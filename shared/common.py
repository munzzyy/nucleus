#!/usr/bin/env python3
"""Nucleus shared server base — stdlib only.

Every console (recon / redcell / bastion) and the hub is a tiny app that
imports this module, registers a handful of routes, and calls `serve()`.
All the security-critical behaviour lives here, once, so the three apps
can never drift apart on it:

  * bind 127.0.0.1 only (never configurable — loopback is structural)
  * Host-header allowlist  (defeats DNS-rebinding)
  * Origin/Referer check on every POST  (defeats CSRF)
  * strict Content-Security-Policy, no external assets anywhere
  * static files served out of a sandboxed directory (no path traversal)
  * one place that knows every console's port, so cross-links + health
    checks are server-side (the browser only ever talks to its own origin)

Handlers are plain functions `f(req) -> Response`. Keep them small.
"""

from __future__ import annotations

import http.client
import io
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import parse_qs, urlparse

BIND_ADDR = "127.0.0.1"  # loopback only — never a config knob
VERSION = "1.0.0"

# Persistent activity logging — the redcell audit trail (var/redcell-scans.jsonl),
# the recon case history (var/recon-scans.jsonl), and saved nmap/nuclei output
# copies (var/redcell-out/). OFF by default: Nucleus runs authorized client
# engagements and the operator generally does not want an on-disk record of what
# was scanned sitting around afterward. Nothing is written to disk unless this is
# explicitly turned back on with NUCLEUS_LOGGING=1. Results still render live in
# the UI for the life of the session — only the disk writes are suppressed.
LOGGING_ENABLED = os.environ.get("NUCLEUS_LOGGING") == "1"

# The whole suite, in one place. Hub + every console read this to draw the
# switcher and to health-check siblings. Ports are fixed so a bookmark or a
# systemd unit never has to guess.
CONSOLES: list[dict] = [
    {"slug": "hub",     "name": "Nucleus",  "port": 8890,
     "tag": "command center", "desc": "The one app — everything connects here."},
    {"slug": "recon",   "name": "Recon",    "port": 8900,
     "tag": "OSINT",          "desc": "Passive recon: username, email, domain, IP, phone."},
    {"slug": "redcell", "name": "Redcell",  "port": 8910,
     "tag": "offensive",      "desc": "The pentest kit — inventory + authorized runners."},
    {"slug": "bastion", "name": "Bastion",  "port": 8920,
     "tag": "defensive",      "desc": "Hardening, opsec posture, metadata scrubbing, and the report engine."},
    {"slug": "devkit",  "name": "Devkit",   "port": 8930,
     "tag": "developer",      "desc": "Encoders, hashes, JWT, JSON, generators, time, regex, CIDR — the everyday dev toolbelt."},
    {"slug": "systems", "name": "Systems",  "port": 8940,
     "tag": "systems",        "desc": "Live local machine health — CPU, memory, disk, network, processes, sensors."},
]
# Other local apps Nucleus knows how to point at (not part of this repo).
EXTERNAL_APPS: list[dict] = [
    {"slug": "coleos-hub", "name": "COLE-OS Hub", "port": 4747,
     "tag": "vault", "desc": "The Obsidian control panel.", "path": "/"},
]

CONSOLE_BY_SLUG = {c["slug"]: c for c in CONSOLES}

MAX_BODY = 256 * 1024           # 256 KiB cap on any POST body
MAX_CONCURRENT_REQUESTS = 64    # per-console cap; excess gets a quick 503, not a hang
DEFAULT_TIMEOUT = 6.0           # seconds, external fetches
_HEALTH_TIMEOUT = 0.7           # loopback ping; a down sibling shouldn't cost more

REPO_ROOT = Path(__file__).resolve().parent.parent
SHARED_STATIC = (REPO_ROOT / "shared" / "static").resolve()


# --------------------------------------------------------------------------
# Request / Response
# --------------------------------------------------------------------------
@dataclass
class Request:
    method: str
    path: str
    query: dict
    headers: dict
    body: bytes
    client: str

    def q(self, key: str, default: str = "") -> str:
        v = self.query.get(key)
        if isinstance(v, list):
            return v[0] if v else default
        return v if v is not None else default

    def json(self) -> dict:
        if not self.body:
            return {}
        try:
            data = json.loads(self.body.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except (ValueError, UnicodeDecodeError):
            return {}


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    content_type: str = "application/json; charset=utf-8"
    headers: dict = field(default_factory=dict)

    @staticmethod
    def json(obj, status: int = 200) -> "Response":
        return Response(status, json.dumps(obj, default=str).encode("utf-8"),
                        "application/json; charset=utf-8")

    @staticmethod
    def text(s: str, status: int = 200,
             content_type: str = "text/plain; charset=utf-8") -> "Response":
        return Response(status, s.encode("utf-8"), content_type)

    @staticmethod
    def error(status: int, msg: str) -> "Response":
        return Response.json({"error": msg, "status": status}, status)

    @staticmethod
    def raw(data: bytes, content_type: str, status: int = 200,
            headers: Optional[dict] = None) -> "Response":
        return Response(status, data, content_type, headers or {})


# --------------------------------------------------------------------------
# App config
# --------------------------------------------------------------------------
@dataclass
class App:
    slug: str
    static_dir: Path
    routes: dict = field(default_factory=dict)   # "GET /api/x" -> handler
    version: str = VERSION
    # Per-route POST body caps: route key ("POST /api/x") -> max bytes. Exists
    # for bastion's file-upload route, which legitimately takes multi-MB files;
    # any route absent from this dict keeps the global MAX_BODY cap.
    body_limits: dict = field(default_factory=dict)

    @property
    def meta(self) -> dict:
        return CONSOLE_BY_SLUG.get(self.slug, {"slug": self.slug, "name": self.slug,
                                               "port": 0, "tag": "", "desc": ""})


# --------------------------------------------------------------------------
# Security helpers
# --------------------------------------------------------------------------
def _allowed_hosts(port: int) -> set[str]:
    return {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}


def _origin_ok(origin: str, port: int) -> bool:
    if not origin:
        return False
    try:
        u = urlparse(origin)
        # .port validates lazily and raises ValueError on a bad port ("8890.evil")
        # — it must be read inside the try, or a crafted Origin crashes the guard.
        oport = u.port
    except ValueError:
        return False
    return (u.hostname in ("127.0.0.1", "localhost", "::1")
            and (oport == port or (oport is None and u.scheme in ("http", "https"))))


def _ip_is_public(ip) -> bool:
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified):
        return False
    # CGNAT 100.64.0.0/10
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return True


def resolve_public_ips(host: str) -> list[str]:
    """Resolve every A/AAAA address for `host` and confirm ALL of them are
    public. Returns the validated public IPs (resolver order, de-duped), or
    [] if `host` is empty/unresolvable. Raises ValueError the moment ANY
    resolved address is private/loopback/link-local/reserved/unspecified — a
    host with even one non-public answer is refused outright, since an
    attacker only needs one rebinding-capable record.

    This is the ONE place that resolves-and-validates a hostname. Both
    `host_is_public()` (the bool convenience used for scope checks) and
    `_resolve_public()` (fetch()'s connect-pinning, below) call this, so the
    two SSRF guards share a single predicate and can never quietly drift
    apart from each other.

    Residual risk: this closes the DNS-rebinding TOCTOU for a caller that
    immediately connects to one of the returned IPs — `fetch()` does exactly
    that. It does NOT close it for a caller that takes the validated
    hostname and hands it to something that re-resolves later (a second
    lookup can return a different, private, answer if the attacker's DNS TTL
    is short enough to flip between the two resolutions — classic DNS
    rebinding). A caller passing a hostname to a third-party tool/subprocess
    that does its own resolution should pin to one of these IPs directly
    wherever the tool supports it; where it can't, only kernel-level egress
    filtering (netns/nftables) fully closes that gap. That tool-side
    mitigation belongs to redcell, not this guard.
    """
    host = (host or "").strip()
    if not host:
        return []
    try:
        ipobj = ipaddress.ip_address(host)
    except ValueError:
        ipobj = None
    if ipobj is not None:
        if not _ip_is_public(ipobj):
            raise ValueError(f"non-public IP: {host}")
        return [host]
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    if not infos:
        return []
    ips: list[str] = []
    seen: set[str] = set()
    for info in infos:
        addr = info[4][0]
        try:
            addr_ip = ipaddress.ip_address(addr)
        except ValueError:
            raise ValueError(f"host resolved to an unparseable address: {host} -> {addr}")
        if not _ip_is_public(addr_ip):
            raise ValueError(f"host resolves to non-public address: {host} -> {addr}")
        if addr not in seen:
            seen.add(addr)
            ips.append(addr)
    return ips


def host_is_public(hostname: str) -> bool:
    """SSRF guard: True only if every resolved address is a normal public IP.

    Blocks loopback, RFC1918, link-local, multicast, reserved, and CGNAT.
    Used before recon ever fetches a user-supplied host. Thin bool wrapper
    around `resolve_public_ips()` — see its docstring for the residual
    DNS-rebinding TOCTOU this does and doesn't cover.
    """
    try:
        return bool(resolve_public_ips(hostname))
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Outbound fetch (SSRF-guarded) — recon's only door to the internet
# --------------------------------------------------------------------------
# Outbound User-Agent. Defaults to a common browser string, NOT a self-identifying
# "nucleus-recon" tool name — during an authorized engagement you don't want your
# scan traffic labelled with your personal tooling in the target's logs. Override
# per-engagement with NUCLEUS_UA (e.g. to match the client's expected UA, or a
# current browser build). This only changes a request header; it does not, and
# cannot, hide your source IP — see the OpSec notes in the README.
_UA = os.environ.get("NUCLEUS_UA") or (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
_MAX_REDIRECTS = 5


def _resolve_public(host: str) -> tuple[str, int]:
    """Resolve `host` and confirm EVERY address is public. Returns (ip, family).

    We resolve once here (via the shared `resolve_public_ips`) and connect to
    exactly this IP, so the address the guard approved is the address we
    actually talk to — no second lookup for an attacker to poison (defeats
    DNS-rebinding TOCTOU for this call). A host that resolves to any
    non-public address at all is refused.
    """
    ips = resolve_public_ips(host)  # raises ValueError with the reason on any non-public hit
    if not ips:
        raise ValueError(f"unresolvable host: {host}")
    ip = ips[0]
    family = socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
    return ip, family


def _arm_deadline(sock: socket.socket, deadline: float) -> None:
    """Set `sock`'s timeout to whatever's left before `deadline`, or raise
    TimeoutError if that's already <= 0. Call this right before every
    blocking op on the socket (see `_bind_deadline`) so the timeout shrinks
    toward the deadline instead of resetting to the full window every time.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("fetch() deadline exceeded")
    sock.settimeout(remaining)


class _DeadlineSocketIO(socket.SocketIO):
    """The raw I/O http.client's buffered reader sits on top of, but with
    every recv_into() re-arming a shared monotonic deadline first instead of
    trusting whatever timeout was on the socket when the reader was built —
    see `_DeadlineSock` for why that matters."""

    def __init__(self, raw_sock, mode: str, deadline: float):
        super().__init__(raw_sock, mode)
        self._deadline = deadline

    def readinto(self, b):
        _arm_deadline(self._sock, self._deadline)
        return super().readinto(b)


class _DeadlineSock:
    """Stand-in for `conn.sock` that bounds the whole conversation — send
    through the final body byte — by one monotonic deadline, not a fixed
    `socket.settimeout()` a slow server can ride well past its budget.

    `socket.settimeout()` only bounds a single blocking call. http.client's
    buffered reader issues many small recv()s under one
    `resp.read(max_bytes)`, and each one gets whatever timeout was last set
    unless something re-arms it — a server that trickles one byte just
    under the timeout on every recv() can keep a single read() blocking for
    many multiples of the configured timeout (measured ~28x against a real
    slow-trickle server in testing). Sockets don't support monkeypatching
    their bound methods (no per-instance __dict__ — confirmed by trying),
    so instead of patching recv/send in place, this wraps `conn.sock`.

    http.client only ever calls sendall()/makefile()/close() on conn.sock in
    the path we use (we assign conn.sock directly and never call
    HTTPConnection.connect() — verified against the stdlib source), so
    that's all this needs to implement: re-arm the deadline before every
    send, and swap in `_DeadlineSocketIO` so the reader built off
    makefile() re-arms it before every read too.

    The `_io_refs` increment in makefile() mirrors what a real
    `socket.makefile()` does — http.client calls `close()` on `Connection:
    close` responses right after reading headers, *before* the body is
    read (`self.close()` inside `getresponse()`); a real socket defers its
    actual fd close until every makefile()-derived reader is also closed
    (`socket.socket.close()` checks `_io_refs`). Skipping this increment
    would let that early close() kill the connection before the body is
    ever read — confirmed against a real Connection:-close response in
    testing before this was added.
    """

    def __init__(self, raw_sock, deadline: float):
        self._sock = raw_sock
        self._deadline = deadline

    def send(self, data):
        _arm_deadline(self._sock, self._deadline)
        return self._sock.send(data)

    def sendall(self, data):
        _arm_deadline(self._sock, self._deadline)
        return self._sock.sendall(data)

    def makefile(self, mode: str = "rb", *a, **kw):
        self._sock._io_refs += 1
        raw = _DeadlineSocketIO(self._sock, mode, self._deadline)
        return io.BufferedReader(raw)

    def close(self):
        self._sock.close()


def fetch(url: str, *, timeout: float = DEFAULT_TIMEOUT, headers: Optional[dict] = None,
          data: Optional[bytes] = None, allow_hosts: Optional[set] = None,
          max_bytes: int = 2_000_000, follow_redirects: bool = True) -> tuple[int, bytes, dict]:
    """GET/POST a URL with a hard SSRF guard. Returns (status, body, headers).

    Redirects are followed manually and the guard runs again on every hop's
    host, so a public URL can't 3xx-bounce into loopback/metadata. Set
    follow_redirects=False to get the first 3xx response back verbatim (status +
    Location header) instead — useful for auditing whether http:// forces https.
    Each hop is
    connected to the exact IP the guard validated (hostname preserved for TLS
    SNI + cert check), which also closes the resolve-then-reconnect race.
    Each hop gets its own fresh `timeout`-second deadline (connect through
    the final read), enforced by a monotonic clock rather than a single
    `socket.settimeout()` call that a slow-trickle server can ride well past
    its budget — see `_DeadlineSock`.
    `allow_hosts` is accepted for call-site compatibility but never relaxes the
    public check. Raises ValueError on a blocked host or non-http scheme.
    """
    method = "POST" if data is not None else "GET"
    current = url
    body_data = data
    origin_host = (urlparse(url).hostname or "").lower()
    for _hop in range(_MAX_REDIRECTS + 1):
        u = urlparse(current)
        if u.scheme not in ("http", "https"):
            raise ValueError(f"scheme not allowed: {u.scheme}")
        host = u.hostname or ""
        if not host:
            raise ValueError("no host in url")
        ip, _family = _resolve_public(host)  # validates + pins
        port = u.port or (443 if u.scheme == "https" else 80)
        path = u.path or "/"
        if u.query:
            path += "?" + u.query

        req_headers = {"User-Agent": _UA, "Accept-Encoding": "identity",
                       "Connection": "close"}
        # Caller headers may carry API keys. Only send them to the ORIGINAL host —
        # if a redirect points anywhere else, drop them so a key can never ride a
        # 3xx to an attacker-chosen host.
        if host.lower() == origin_host:
            for k, v in (headers or {}).items():
                req_headers[k] = v

        deadline = time.monotonic() + timeout  # fresh cumulative budget for this hop
        sock = socket.create_connection((ip, port), timeout=timeout)
        wrapped = None  # set below for https — a DIFFERENT object holding the real fd
        try:
            if u.scheme == "https":
                _arm_deadline(sock, deadline)  # handshake gets whatever's left, not a fresh window
                ctx = ssl.create_default_context()
                conn = http.client.HTTPSConnection(host, port, timeout=timeout)
                wrapped = ctx.wrap_socket(sock, server_hostname=host)
                conn.sock = _DeadlineSock(wrapped, deadline)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
                conn.sock = _DeadlineSock(sock, deadline)
            conn.request(method, path, body=body_data, headers=req_headers)
            resp = conn.getresponse()
            status = resp.status
            loc = resp.getheader("Location")
            if follow_redirects and status in (301, 302, 303, 307, 308) and loc:
                resp.read()  # drain before closing
                conn.close()
                current = urllib.parse.urljoin(current, loc)
                if status in (301, 302, 303):  # browsers demote these to GET
                    method, body_data = "GET", None
                continue
            payload = resp.read(max_bytes)
            resp_headers = {k: v for k, v in resp.getheaders()}
            conn.close()
            return status, payload, resp_headers
        finally:
            # wrap_socket() hands back a NEW object holding the real fd and
            # detaches `sock` — on a mid-handshake/mid-read abort (which our
            # own deadline enforcement now triggers deliberately, instead of
            # the caller just hanging), closing only `sock` would leak that
            # fd. Close both; closing an already-detached socket is a no-op.
            for s in (wrapped, sock):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
    raise ValueError(f"too many redirects (> {_MAX_REDIRECTS})")


_DOH_ENDPOINTS = (
    ("https://dns.google/resolve", None),
    ("https://cloudflare-dns.com/dns-query", "application/dns-json"),
)


def dns_query(name: str, rtype: str = "A", timeout: float = DEFAULT_TIMEOUT) -> list[dict]:
    """Encrypted DNS-over-HTTPS lookup (keyless, zero-dep).

    Returns the raw Answer list. Using DoH JSON here means no dnspython — and so
    no repeat of the shared-Resolver thread-safety bug that bit the old
    osint-console — while still keeping every lookup encrypted in transit.
    Google is primary, Cloudflare the fallback.
    """
    name = (name or "").strip().rstrip(".")
    if not name:
        return []
    for base, accept in _DOH_ENDPOINTS:
        url = f"{base}?name={urllib.parse.quote(name)}&type={urllib.parse.quote(rtype)}"
        headers = {"Accept": accept} if accept else {"Accept": "application/json"}
        try:
            status, body, _ = fetch(url, timeout=timeout, headers=headers)
            if status != 200:
                continue
            ans = json.loads(body.decode("utf-8")).get("Answer") or []
            return ans
        except (ValueError, OSError, json.JSONDecodeError, http.client.HTTPException):
            continue
    return []


# --------------------------------------------------------------------------
# Local tool detection + safe execution (redcell / bastion)
# --------------------------------------------------------------------------
def which(name: str) -> Optional[str]:
    from shutil import which as _which
    return _which(name)


def tool_version(argv: list[str], timeout: float = 4.0) -> str:
    try:
        out = subprocess.run(argv, capture_output=True, text=True,
                             timeout=timeout, check=False)
        blob = (out.stdout or "") + (out.stderr or "")
        return blob.strip().splitlines()[0] if blob.strip() else ""
    except (OSError, subprocess.SubprocessError):
        return ""


@dataclass
class RunResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False
    error: str = ""


def run_tool(argv: list[str], *, timeout: float = 120.0,
             cwd: Optional[str] = None, input_text: Optional[str] = None) -> RunResult:
    """Run a command with NO shell — argv is a list, never a string.

    Callers are responsible for validating argv[0] against an allowlist and
    validating every argument before calling this. This function only
    guarantees the shell is never involved and the process is time-bounded.
    """
    import time
    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            cwd=cwd, input=input_text, check=False, shell=False,
        )
        return RunResult(argv, proc.returncode, proc.stdout or "", proc.stderr or "",
                         round(time.monotonic() - start, 3))
    except subprocess.TimeoutExpired as e:
        return RunResult(argv, -1, (e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or ""),
                         "", round(time.monotonic() - start, 3), timed_out=True,
                         error=f"timed out after {timeout}s")
    except (OSError, ValueError) as e:
        return RunResult(argv, -1, "", "", round(time.monotonic() - start, 3),
                         error=str(e))


# --------------------------------------------------------------------------
# Sibling health (server-side, so the browser stays same-origin)
# --------------------------------------------------------------------------
def _ping(port: int) -> bool:
    """Our own consoles answer /healthz with 200."""
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/healthz", timeout=_HEALTH_TIMEOUT) as r:
            return r.status == 200
    except (OSError, urllib.error.URLError, http.client.HTTPException):
        return False


def _tcp_open(port: int) -> bool:
    """External apps (e.g. coleos-hub) may not expose /healthz — a bound port is
    the honest 'reachable' signal for them."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(_HEALTH_TIMEOUT)
        return s.connect_ex(("127.0.0.1", port)) == 0


def local_get_json(port: int, path: str, timeout: float = 4.0) -> Optional[dict]:
    """GET JSON from one of OUR OWN consoles on loopback.

    Deliberately bypasses the SSRF guard in `fetch` (which correctly blocks
    loopback) because the target is a fixed, trusted Nucleus port on 127.0.0.1.
    Used only by the hub to aggregate console data server-side, so the browser
    never has to make a cross-origin call. Returns None if the console is down.
    """
    if port not in {c["port"] for c in CONSOLES}:
        return None
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}{path}", timeout=timeout) as r:
            if r.status != 200:
                return None
            return json.loads(r.read(4_000_000).decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError, http.client.HTTPException):
        return None


# --------------------------------------------------------------------------
# OpSec / anonymity — "is my real IP exposed right now?"
# One cached network check, shared across every console (same process), so the
# whole app can warn before a scan ever leaves the machine.
# --------------------------------------------------------------------------
_opsec_cache: dict = {"data": None, "ts": 0.0}
_opsec_lock = threading.Lock()
OPSEC_TTL = 25.0


def _vpn_iface_up() -> Optional[str]:
    try:
        for iface in os.listdir("/sys/class/net"):
            if iface.startswith(("wg", "tun", "mullvad", "proton", "nordlynx", "tailscale")):
                try:
                    state = Path(f"/sys/class/net/{iface}/operstate").read_text().strip()
                except OSError:
                    state = ""
                if state in ("up", "unknown"):  # tun devices often read 'unknown' when up
                    return iface
    except OSError:
        pass
    return None


_OPSEC_ORACLES = (
    # (key, url) — each independently answers "what's my public IP", plus
    # whatever extra signal it's authoritative for. All three are HTTPS-only
    # and keyless: the anonymity check itself must never be the thing that
    # leaks the query in the clear — the old ip-api.com fallback did exactly
    # that (plain http://, sent over whatever exit was up).
    ("mullvad", "https://am.i.mullvad.net/json"),
    ("tor", "https://check.torproject.org/api/ip"),
    ("geo", "https://ipapi.co/json/"),
)


def _oracle_fetch(url: str, timeout: float = 5.0) -> Optional[dict]:
    try:
        st, body, _ = fetch(url, timeout=timeout, max_bytes=8192)
        if st == 200:
            j = json.loads(body.decode("utf-8"))
            return j if isinstance(j, dict) else None
    except (ValueError, OSError, json.JSONDecodeError, http.client.HTTPException):
        pass
    return None


def opsec_status(force: bool = False) -> dict:
    """What the internet sees right now + a plain exposed/protected verdict.

    Cross-checks three independent, keyless, HTTPS-only oracles in parallel —
    Mullvad's own check (authoritative for 'am I behind Mullvad'), the Tor
    Project's check, and a plain IP-geolocation echo — instead of trusting
    any single one. Their reported public IP must agree; if they disagree, or
    none of them answer, that's reported as exposed rather than a false
    'protected' (fail-safe). No oracle is ever queried over plaintext HTTP —
    the check itself leaking the query would defeat the point of it.
    Cached ~25s so console polling doesn't hammer the check services.
    """
    now = time.monotonic()
    with _opsec_lock:
        cached = _opsec_cache["data"]
        if not force and cached and (now - _opsec_cache["ts"] < OPSEC_TTL):
            return cached

    results: dict[str, Optional[dict]] = {}
    lock = threading.Lock()

    def worker(key, url):
        r = _oracle_fetch(url)
        with lock:
            results[key] = r

    threads = [threading.Thread(target=worker, args=(k, u)) for k, u in _OPSEC_ORACLES]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=6.0)

    mv, tor, geo = results.get("mullvad"), results.get("tor"), results.get("geo")

    # Every oracle that actually answered contributes the public IP it saw.
    seen_ips: list[tuple[str, str]] = []
    if mv and mv.get("ip"):
        seen_ips.append(("mullvad", str(mv["ip"])))
    if tor and tor.get("IP"):
        seen_ips.append(("tor", str(tor["IP"])))
    if geo and geo.get("ip"):
        seen_ips.append(("geo", str(geo["ip"])))

    reachable = bool(seen_ips)
    disagreement = len({ip for _, ip in seen_ips}) > 1

    iface = _vpn_iface_up()
    mullvad = bool(mv and mv.get("mullvad_exit_ip"))
    tor_exit = bool(tor and tor.get("IsTor"))

    # Prefer Mullvad's own fields (most detailed); fall back to the plain geo
    # echo if Mullvad didn't answer.
    pub_ip = (mv or {}).get("ip") or (geo or {}).get("ip") or (tor or {}).get("IP") or ""
    org = (mv or {}).get("organization") or (geo or {}).get("org") or ""
    city = (mv or {}).get("city") or (geo or {}).get("city") or ""
    country = (mv or {}).get("country") or (geo or {}).get("country_name") or ""

    if disagreement:
        exposed, reason = True, (
            "Anonymity oracles disagree on your public IP ("
            + ", ".join(f"{src}={ip}" for src, ip in seen_ips)
            + ") — treating you as exposed until that's resolved")
    elif mullvad:
        exposed, reason = False, f"Behind Mullvad ({mv.get('mullvad_exit_ip_hostname') or 'exit node'})"
    elif iface and reachable:
        exposed, reason = False, f"VPN interface {iface} is up"
    elif iface and not reachable:
        exposed, reason = False, f"VPN interface {iface} is up (couldn't reach any check oracle to confirm the exit)"
    elif reachable:
        exposed, reason = True, "No VPN detected — your real IP and approximate location are visible to any target you scan"
    else:
        exposed, reason = True, "Couldn't verify your exit and no VPN interface is up — treat yourself as exposed"

    data = {
        "exposed": exposed, "reason": reason, "mullvad": mullvad, "vpn_iface": iface,
        "reachable": reachable, "tor_exit": tor_exit, "oracle_disagreement": disagreement,
        "public_ip": pub_ip, "org": org, "city": city, "country": country,
    }
    with _opsec_lock:
        _opsec_cache.update(data=data, ts=now)
    return data


def siblings_status() -> list[dict]:
    """Health of every console + known external app, checked in parallel."""
    our_ports = {c["port"] for c in CONSOLES}
    items = [dict(c) for c in CONSOLES] + [dict(a) for a in EXTERNAL_APPS]
    results: dict[int, bool] = {}
    lock = threading.Lock()

    def worker(port):
        up = _ping(port) if port in our_ports else _tcp_open(port)
        with lock:
            results[port] = up

    threads = [threading.Thread(target=worker, args=(it["port"],)) for it in items]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=_HEALTH_TIMEOUT + 0.5)
    for it in items:
        it["up"] = results.get(it["port"], False)
    return items


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------
def _safe_static(base: Path, rel: str) -> Optional[Path]:
    """Resolve rel under base, refusing anything that escapes base."""
    rel = rel.lstrip("/")
    if not rel or rel.endswith("/"):
        return None
    candidate = (base / rel).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8", ".json": "application/json",
    ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon",
    ".woff2": "font/woff2", ".map": "application/json", ".txt": "text/plain; charset=utf-8",
}

_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


def _make_handler(app: App, port: int):
    static_dir = app.static_dir.resolve()
    slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)

    class Handler(BaseHTTPRequestHandler):
        server_version = f"nucleus-{app.slug}/{app.version}"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # quiet by default
            if os.environ.get("NUCLEUS_VERBOSE"):
                super().log_message(fmt, *args)

        # -- guards -----------------------------------------------------
        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in _allowed_hosts(port)

        def _send(self, resp: Response):
            body = resp.body
            self.send_response(resp.status)
            self.send_header("Content-Type", resp.content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", _CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            for k, v in resp.headers.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _dispatch(self, method: str):
            if not self._host_ok():
                self._send(Response.error(HTTPStatus.FORBIDDEN, "bad host"))
                return
            parsed = urlparse(self.path)
            path = parsed.path
            query = {k: v for k, v in parse_qs(parsed.query).items()}

            # built-in: health
            if path == "/healthz" and method == "GET":
                self._send(Response.json({
                    "app": app.slug, "name": app.meta["name"], "port": port,
                    "version": app.version, "status": "ok"}))
                return
            # built-in: siblings
            if path == "/api/siblings" and method == "GET":
                self._send(Response.json({"consoles": siblings_status(),
                                          "self": app.slug}))
                return
            # built-in: opsec / anonymity (every console can warn you)
            if path == "/api/opsec" and method == "GET":
                self._send(Response.json(opsec_status()))
                return
            # built-in: static
            if path == "/" and method in ("GET", "HEAD"):
                self._serve_file(static_dir / "index.html")
                return
            if path.startswith("/static/"):
                f = _safe_static(static_dir, path[len("/static/"):])
                self._serve_file(f)
                return
            if path.startswith("/shared/"):
                f = _safe_static(SHARED_STATIC, path[len("/shared/"):])
                self._serve_file(f)
                return

            # registered routes
            key = f"{method} {path}"
            handler = app.routes.get(key)
            if handler is None:
                self._send(Response.error(HTTPStatus.NOT_FOUND, "not found"))
                return

            # CSRF: POST must carry a same-origin Origin (or Referer)
            if method == "POST":
                origin = self.headers.get("Origin") or ""
                referer = self.headers.get("Referer") or ""
                ref_origin = ""
                if referer:
                    ru = urlparse(referer)
                    ref_origin = f"{ru.scheme}://{ru.netloc}"
                if not (_origin_ok(origin, port) or _origin_ok(ref_origin, port)):
                    self._send(Response.error(HTTPStatus.FORBIDDEN, "bad origin"))
                    return

            body = b""
            if method == "POST":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = 0
                limit = app.body_limits.get(key, MAX_BODY)  # per-route override (uploads)
                if length > limit:
                    self._send(Response.error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body too large"))
                    return
                body = self.rfile.read(length) if length > 0 else b""

            req = Request(method, path, query, dict(self.headers), body,
                          self.client_address[0])
            try:
                resp = handler(req)
                if not isinstance(resp, Response):
                    resp = Response.json(resp)
            except Exception as e:  # a handler bug must not take the server down
                resp = Response.error(HTTPStatus.INTERNAL_SERVER_ERROR,
                                      f"handler error: {type(e).__name__}: {e}")
            self._send(resp)

        def _serve_file(self, path: Optional[Path]):
            if path is None or not path.is_file():
                self._send(Response.error(HTTPStatus.NOT_FOUND, "not found"))
                return
            ctype = _CONTENT_TYPES.get(path.suffix, "application/octet-stream")
            try:
                data = path.read_bytes()
            except OSError:
                self._send(Response.error(HTTPStatus.INTERNAL_SERVER_ERROR, "read failed"))
                return
            self._send(Response.raw(data, ctype))

        def _guarded(self, method: str):
            if not slots.acquire(timeout=15):
                self._send(Response.error(HTTPStatus.SERVICE_UNAVAILABLE, "server busy"))
                return
            try:
                self._dispatch(method)
            finally:
                slots.release()

        def do_GET(self):
            self._guarded("GET")

        def do_HEAD(self):
            self._guarded("GET")

        def do_POST(self):
            self._guarded("POST")

    return Handler


def serve(app: App, *, port: Optional[int] = None, block: bool = True):
    """Start the app on 127.0.0.1. Returns the server (for tests) if block=False."""
    port = port or app.meta["port"]
    handler = _make_handler(app, port)
    httpd = ThreadingHTTPServer((BIND_ADDR, port), handler)
    httpd.daemon_threads = True
    if not block:
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        return httpd
    name = app.meta["name"]
    print(f"  {name}  →  http://{BIND_ADDR}:{port}   (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n  {name} stopped.")
    finally:
        httpd.server_close()
    return httpd
