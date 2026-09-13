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
    {"slug": "dork",    "name": "Dork",     "port": 8950,
     "tag": "search",         "desc": "Point it at a website — builds the full professional dork set across every engine + specialist source."},
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
    """True only for an Origin that is exactly this console's own origin.

    The port must match EXACTLY. A port-less Origin ("http://localhost",
    i.e. localhost:80, or "https://127.0.0.1", i.e. :443) used to be accepted
    too, on the theory that it was still loopback — but that made any page
    served from a default-port loopback server a valid CSRF source for every
    console, including POST /api/run and POST /api/settings. Nucleus never
    serves on 80 or 443 (ports are fixed at 8890-8940), so a genuine
    same-origin request from one of our own pages ALWAYS carries the real
    port and nothing legitimate is lost by requiring it.
    """
    if not origin:
        return False
    try:
        u = urlparse(origin)
        # .port validates lazily and raises ValueError on a bad port ("8890.evil")
        # — it must be read inside the try, or a crafted Origin crashes the guard.
        oport = u.port
    except ValueError:
        return False
    return (u.scheme in ("http", "https")
            and u.hostname in ("127.0.0.1", "localhost", "::1")
            and oport == port)


_SIXTOFOUR = ipaddress.ip_network("2002::/16")     # 6to4 tunnel: IPv4 in bits 16-48
_NAT64_WK = ipaddress.ip_network("64:ff9b::/96")   # NAT64 well-known: IPv4 in the low 32


def _embedded_ipv4(ip):
    """Pull the IPv4 destination out of an IPv6 form that actually routes to
    IPv4 — 6to4 (2002::/16) and NAT64 well-known (64:ff9b::/96) — so the SSRF
    check judges where the packet really goes. Returns an IPv4Address or None.
    (ipaddress.ipv4_mapped already covers ::ffff:0:0/96; these two are the ones
    the stdlib has classified inconsistently across interpreter versions.)"""
    if ip.version != 6:
        return None
    packed = ip.packed
    if ip in _SIXTOFOUR:
        return ipaddress.IPv4Address(packed[2:6])
    if ip in _NAT64_WK:
        return ipaddress.IPv4Address(packed[12:16])
    return None


def _ip_is_public(ip) -> bool:
    # Judge an embedded/tunneled IPv4 by its real target first, so the verdict
    # never depends on the interpreter's version-shifting classification of
    # these forms (pre-3.13 CPython read some 6to4 addresses as public — this
    # made the SSRF guard's floor the same on every supported Python).
    if ip.version == 6:
        mapped = ip.ipv4_mapped
        if mapped is not None:
            return _ip_is_public(mapped)
        emb = _embedded_ipv4(ip)
        if emb is not None:
            return _ip_is_public(emb)
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


def _collect_headers(pairs) -> dict:
    """Flatten a response's header list into a dict WITHOUT losing repeats.

    `{k: v for k, v in resp.getheaders()}` keeps only the last value of a
    repeated header, which quietly threw away every Set-Cookie but one — so a
    site that sets a session cookie plus a tracking cookie looked like it set
    one, and redcell's cookie-flag analysis only ever graded the last one.

    Contract for callers:
      * single-valued headers behave exactly as before (a plain string)
      * repeats are joined with ", " (the RFC 9110 rule for list-valued fields)
      * Set-Cookie repeats are joined with "\\n" instead, because cookie values
        legitimately contain commas (Expires=Wed, 09 Jun 2027 ...) and comma
        splitting them is guesswork. Callers that want the individual cookies
        do: `resp_headers.get("Set-Cookie", "").split("\\n")`.

    Header names keep the casing the server sent for the first occurrence; a
    repeat that differs only in case folds into that same entry.
    """
    out: dict = {}
    canon: dict = {}   # lowercased name -> the key actually used in `out`
    for k, v in pairs:
        low = k.lower()
        key = canon.get(low)
        if key is None:
            canon[low] = k
            out[k] = v
            continue
        sep = "\n" if low == "set-cookie" else ", "
        out[key] = out[key] + sep + v
    return out


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


def _ordered_public_ips(host: str) -> list[str]:
    """Every validated public IP for `host`, IPv4 first.

    `resolve_public_ips()` has already confirmed every address is public
    (raising on any that isn't), so this ordering is purely about connecting
    reliably: `fetch()` tries these in turn and stops at the first that
    accepts, so a dual-stack box whose IPv6 route is dead — or a host whose
    first DNS record points at an address that refuses — falls through to a
    working one instead of failing the whole fetch. IPv4 goes first because a
    broken-IPv6 box is the common case; a genuinely IPv6-only host still works
    (its v4 list is simply empty). Whichever address wins, it came from the
    guard's validated set, so the SSRF guarantee is unchanged.
    """
    ips = resolve_public_ips(host)
    v4 = [ip for ip in ips if ipaddress.ip_address(ip).version == 4]
    v6 = [ip for ip in ips if ipaddress.ip_address(ip).version == 6]
    return v4 + v6


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


def _proxy_config() -> Optional[tuple[str, int]]:
    """SOCKS5 proxy from NUCLEUS_SOCKS (host:port or socks5://host:port), so all
    outbound recon can leave through Tor / a VPN's SOCKS port instead of the real
    IP. None = direct. Any host is accepted (the user set it explicitly); the
    usual value is a local Tor at 127.0.0.1:9050."""
    raw = (os.environ.get("NUCLEUS_SOCKS") or "").strip()
    if not raw:
        return None
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.strip().rstrip("/")
    if raw.startswith("[") and "]" in raw:            # [ipv6]:port
        hostpart, _, portpart = raw.partition("]")
        host, port = hostpart[1:], portpart.lstrip(":") or "1080"
    elif ":" in raw:
        host, _, port = raw.rpartition(":")
    else:
        host, port = raw, "1080"
    try:
        return (host, int(port)) if host else None
    except ValueError:
        return None


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("SOCKS5 proxy closed the connection early")
        buf += chunk
    return buf


def _socks5_connect(proxy_host: str, proxy_port: int, dest_host: str, dest_port: int,
                    timeout: float, dest_is_ip: bool) -> "socket.socket":
    """TCP to (dest_host, dest_port) THROUGH a no-auth SOCKS5 proxy. A hostname
    dest is sent as a SOCKS5 domain address (0x03) so the PROXY resolves it —
    DNS travels through the tunnel and never leaks to a local resolver. Returns
    the connected socket, ready for TLS/HTTP; raises OSError on any failure."""
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        s.sendall(b"\x05\x01\x00")                    # VER=5, 1 method, NO-AUTH
        greet = _recv_exact(s, 2)
        if greet[0] != 0x05 or greet[1] != 0x00:
            raise OSError("SOCKS5 proxy rejected the no-auth handshake")
        if dest_is_ip:
            ip = ipaddress.ip_address(dest_host)
            atyp = b"\x01" if ip.version == 4 else b"\x04"
            addr = ip.packed
        else:
            try:
                host_b = dest_host.encode("idna")
            except (UnicodeError, ValueError):
                host_b = dest_host.encode("ascii", "strict")
            if not 1 <= len(host_b) <= 255:
                raise OSError("hostname out of range for SOCKS5")
            atyp, addr = b"\x03", bytes([len(host_b)]) + host_b
        s.sendall(b"\x05\x01\x00" + atyp + addr + int(dest_port).to_bytes(2, "big"))
        rep = _recv_exact(s, 4)                        # VER, REP, RSV, ATYP
        if rep[1] != 0x00:
            raise OSError(f"SOCKS5 CONNECT refused (reply code {rep[1]})")
        bnd = rep[3]                                   # drain the bound address
        if bnd == 0x01:
            _recv_exact(s, 4 + 2)
        elif bnd == 0x04:
            _recv_exact(s, 16 + 2)
        elif bnd == 0x03:
            _recv_exact(s, _recv_exact(s, 1)[0] + 2)
        else:
            raise OSError("SOCKS5 returned an unknown bound-address type")
        return s
    except Exception:
        try:
            s.close()
        except OSError:
            pass
        raise


def _http_conn_over(sock, host: str, port: int, scheme: str, deadline: float, timeout: float):
    """Wrap an already-connected socket into an http.client connection with our
    monotonic-deadline reader — TLS (SNI + cert check on `host`) for https,
    plain otherwise. Returns (conn, wrapped_or_None). Same wiring whether the
    socket came from a direct connect or a SOCKS5 tunnel."""
    if scheme == "https":
        _arm_deadline(sock, deadline)  # handshake gets whatever's left, not a fresh window
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=timeout)
        wrapped = ctx.wrap_socket(sock, server_hostname=host)  # NEW object holding the real fd
        conn.sock = _DeadlineSock(wrapped, deadline)
        return conn, wrapped
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    conn.sock = _DeadlineSock(sock, deadline)
    return conn, None


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
    _origin = urlparse(url)
    origin_host = (_origin.hostname or "").lower()
    origin_scheme = (_origin.scheme or "").lower()
    for _hop in range(_MAX_REDIRECTS + 1):
        u = urlparse(current)
        if u.scheme not in ("http", "https"):
            raise ValueError(f"scheme not allowed: {u.scheme}")
        host = u.hostname or ""
        if not host:
            raise ValueError("no host in url")
        proxy = _proxy_config()
        candidates = None
        if not proxy:
            candidates = _ordered_public_ips(host)  # all validated public, v4 first
            if not candidates:
                raise ValueError(f"unresolvable host: {host}")
        elif _is_ip_literal(host) and not _ip_is_public(ipaddress.ip_address(host)):
            # Through a proxy, a hostname is resolved BY the proxy (DNS in the
            # tunnel, no local leak) so we can't pin an IP we never resolved; a
            # literal private/loopback/reserved IP target is still refused here.
            raise ValueError(f"refusing non-public target through proxy: {host}")
        port = u.port or (443 if u.scheme == "https" else 80)
        path = u.path or "/"
        if u.query:
            path += "?" + u.query

        req_headers = {"User-Agent": _UA, "Accept-Encoding": "identity",
                       "Connection": "close"}
        # Caller headers may carry API keys. Only send them to the ORIGINAL host —
        # if a redirect points anywhere else, drop them so a key can never ride a
        # 3xx to an attacker-chosen host. The SCHEME has to match too: a same-host
        # https -> http redirect would otherwise put the key on the wire in
        # cleartext, which is exactly what an on-path attacker would ask for.
        # (Downgrades are allowed to proceed; they just travel without the key.)
        if host.lower() == origin_host and (u.scheme.lower() == origin_scheme
                                            or origin_scheme != "https"):
            for k, v in (headers or {}).items():
                req_headers[k] = v

        # Connect to the first address that accepts us. Every candidate came
        # from resolve_public_ips() and is confirmed public, so trying them in
        # turn keeps the SSRF guarantee while surviving a dead IPv6 route (or
        # any single dead record) instead of failing the whole fetch on it. A
        # connection that ESTABLISHES then errors later is NOT retried — only
        # connect/handshake failures fall through — so a POST body is never
        # sent twice.
        conn = sock = wrapped = None
        deadline = 0.0
        connect_err = None
        # ONE budget for the whole hop, shared across every attempt. Giving each
        # a fresh `timeout` made an N-address hop cost up to N x timeout of wall
        # clock, so a caller asking for 5s could sit for 20s.
        hop_deadline = time.monotonic() + timeout
        if proxy:
            # One tunneled connection; the proxy resolves a hostname dest so DNS
            # rides the tunnel. (dns_query's own DoH is a fetch(), so it tunnels
            # through here too when a proxy is set.)
            deadline = hop_deadline
            try:
                sock = _socks5_connect(proxy[0], proxy[1], host, port, timeout,
                                       dest_is_ip=_is_ip_literal(host))
                conn, wrapped = _http_conn_over(sock, host, port, u.scheme, deadline, timeout)
            except OSError as e:
                connect_err = e
                for s in (wrapped, sock):
                    if s is not None:
                        try:
                            s.close()
                        except OSError:
                            pass
                conn = sock = wrapped = None
        else:
            for ip in candidates:
                remaining = hop_deadline - time.monotonic()
                if remaining <= 0:
                    break
                deadline = hop_deadline
                try:
                    sock = socket.create_connection((ip, port), timeout=remaining)
                    conn, wrapped = _http_conn_over(sock, host, port, u.scheme, deadline, timeout)
                    break
                except OSError as e:
                    connect_err = e
                    for s in (wrapped, sock):
                        if s is not None:
                            try:
                                s.close()
                            except OSError:
                                pass
                    conn = sock = wrapped = None
                    continue
        if conn is None:
            # Exhausted every validated address — re-raise the last connect
            # error (an OSError, as before) so callers keep catching the same type.
            raise connect_err if connect_err is not None else ValueError(f"unresolvable host: {host}")
        try:
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
            resp_headers = _collect_headers(resp.getheaders())
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
    # Cloudflare before Google on purpose: don't hand Google a log of every
    # domain the operator resolves by default. Both are proven JSON-DoH and, when
    # a proxy is set, these queries ride the tunnel too (dns_query goes via fetch).
    ("https://cloudflare-dns.com/dns-query", "application/dns-json"),
    ("https://dns.google/resolve", None),
)


def _doh_endpoints():
    """DoH resolvers, overridable via NUCLEUS_DOH (comma-separated https base
    URLs) so an operator can point at Quad9, a self-hosted resolver, or anything
    they trust instead of the defaults. A `dns-query` path speaks
    application/dns-json; otherwise the google-style JSON echo."""
    raw = (os.environ.get("NUCLEUS_DOH") or "").strip()
    if not raw:
        return _DOH_ENDPOINTS
    out = [(u.strip(), "application/dns-json" if "dns-query" in u else None)
           for u in raw.split(",") if u.strip().startswith("https://")]
    return tuple(out) or _DOH_ENDPOINTS


class DNSUnavailable(Exception):
    """Every DoH endpoint failed to answer (transport / non-200 / parse error) —
    as opposed to a successful lookup that simply returned no records. Only
    raised by dns_query(strict=True); the default path still returns [] on
    failure so existing callers are unchanged. A grader that scores on record
    presence needs this to tell 'no such record' apart from 'the lookup did not
    run' and avoid reporting an outage as a real finding."""


def dns_query(name: str, rtype: str = "A", timeout: float = DEFAULT_TIMEOUT,
              strict: bool = False) -> list[dict]:
    """Encrypted DNS-over-HTTPS lookup (keyless, zero-dep).

    Returns the raw Answer list. Using DoH JSON here means no dnspython — and so
    no repeat of the shared-Resolver thread-safety bug that bit the old
    osint-console — while still keeping every lookup encrypted in transit.
    Google is primary, Cloudflare the fallback.

    A valid 200 response (even with an empty Answer) is a definitive result and
    returns []. Only when NO endpoint produced one does strict=True raise
    DNSUnavailable; without strict it returns [] as before.
    """
    name = (name or "").strip().rstrip(".")
    if not name:
        return []
    for base, accept in _doh_endpoints():
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
    if strict:
        raise DNSUnavailable(f"no DoH endpoint answered for {name} {rtype}")
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
        def _dec(b):
            return b.decode("utf-8", "replace") if isinstance(b, bytes) else (b or "")
        return RunResult(argv, -1, _dec(e.stdout), _dec(e.stderr),
                         round(time.monotonic() - start, 3), timed_out=True,
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


def local_get_json_status(port: int, path: str,
                          timeout: float = 4.0) -> tuple[Optional[dict], str, str]:
    """`local_get_json` that also says WHY it came back empty.

    Returns (data, status, detail) where status is one of:
      "ok"      — a 200 with a JSON object
      "down"    — nothing listening (connection refused)
      "timeout" — listening but didn't answer inside the budget (cold start,
                  or a probe that's genuinely slow the first time)
      "error"   — answered, but not with something usable

    The hub needs this distinction: "offline" and "still starting up" and
    "broke" are three different things to show an operator, and collapsing
    them into a bare `None` is exactly the kind of dishonest UI this app is
    supposed to avoid.
    """
    if port not in {c["port"] for c in CONSOLES}:
        return None, "error", "not a Nucleus port"
    url = f"http://127.0.0.1:{port}{path}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            if r.status != 200:
                return None, "error", f"HTTP {r.status}"
            data = json.loads(r.read(4_000_000).decode("utf-8"))
            if not isinstance(data, dict):
                return None, "error", "unexpected payload"
            return data, "ok", ""
    except urllib.error.HTTPError as e:          # must precede URLError
        return None, "error", f"HTTP {e.code}"
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", None)
        if isinstance(reason, TimeoutError):
            return None, "timeout", f"no answer in {timeout:g}s"
        if isinstance(reason, ConnectionRefusedError):
            return None, "down", "connection refused"
        return None, "error", str(reason or e)[:120]
    except TimeoutError:                          # socket.timeout is this since 3.10
        return None, "timeout", f"no answer in {timeout:g}s"
    except ConnectionRefusedError:
        return None, "down", "connection refused"
    except (OSError, json.JSONDecodeError, ValueError, http.client.HTTPException) as e:
        return None, "error", f"{type(e).__name__}: {e}"[:120]


def local_get_json(port: int, path: str, timeout: float = 4.0) -> Optional[dict]:
    """GET JSON from one of OUR OWN consoles on loopback.

    Deliberately bypasses the SSRF guard in `fetch` (which correctly blocks
    loopback) because the target is a fixed, trusted Nucleus port on 127.0.0.1.
    Used only by the hub to aggregate console data server-side, so the browser
    never has to make a cross-origin call. Returns None if the console is down.
    Thin wrapper over `local_get_json_status` so there's one implementation.
    """
    data, _status, _detail = local_get_json_status(port, path, timeout)
    return data


# --------------------------------------------------------------------------
# OpSec / anonymity — "is my real IP exposed right now?"
# One cached network check, shared across every console (same process), so the
# whole app can warn before a scan ever leaves the machine.
# --------------------------------------------------------------------------
_opsec_cache: dict = {"data": None, "ts": 0.0}
_opsec_lock = threading.Lock()
OPSEC_TTL = 25.0


_VPN_PREFIXES = ("wg", "tun", "mullvad", "proton", "nordlynx", "tailscale")


def _vpn_iface_up() -> Optional[str]:
    try:
        for iface in os.listdir("/sys/class/net"):
            if iface.startswith(_VPN_PREFIXES):
                try:
                    state = Path(f"/sys/class/net/{iface}/operstate").read_text().strip()
                except OSError:
                    state = ""
                if state in ("up", "unknown"):  # tun devices often read 'unknown' when up
                    return iface
    except OSError:
        pass
    return None


def _default_route_iface() -> Optional[str]:
    """The egress interface for the IPv4 default route, read from
    /proc/net/route (no subprocess). None if it can't be determined."""
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            f = line.split()
            if len(f) >= 4 and f[1] == "00000000":  # destination 0.0.0.0 = default route
                return f[0]
    except OSError:
        pass
    return None


def _local_opsec() -> dict:
    """Exposure verdict from LOCAL signals only — reads the routing table and
    interface list and makes NO outbound call. This is the default for the
    always-on indicator, so opening a console never sends your IP to a third
    party before you ask. Call opsec_status(oracles=True) to actually confirm
    the exit IP against the check services."""
    route_if = _default_route_iface()
    iface = _vpn_iface_up()
    on_vpn = bool(route_if and route_if.startswith(_VPN_PREFIXES))
    if on_vpn:
        exposed, reason = False, (f"Default route is through {route_if} — traffic leaves via the tunnel "
                                  "(local check; use Verify exit to confirm the IP)")
    elif iface:
        exposed, reason = True, (f"VPN interface {iface} is up but the default route is "
                                 f"{route_if or 'unknown'} — your real IP is likely still what targets "
                                 "see (local check)")
    else:
        exposed, reason = True, ("No VPN on the default route — your real IP and rough location are "
                                 "visible to any target you scan (local check)")
    return {"exposed": exposed, "reason": reason, "mode": "local",
            "vpn_iface": iface, "route_iface": route_if,
            "public_ip": "", "org": "", "city": "", "country": "",
            "reachable": None, "mullvad": False, "tor_exit": False, "oracle_disagreement": False}


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


def opsec_status(force: bool = False, oracles: bool = False) -> dict:
    """A plain exposed/protected verdict.

    Default (oracles=False) uses LOCAL signals only — the routing table and
    interface list — and makes NO outbound call, so the always-on indicator
    never sends your IP to a third party before you ask.

    oracles=True runs the full exit check: three independent, keyless,
    HTTPS-only services in parallel (Mullvad's own check, the Tor Project's,
    and a plain IP-geolocation echo) whose reported public IP must agree; if
    they disagree or none answer, that's exposed, not a false 'protected'
    (fail-safe). It's opt-in because it does reveal your IP to those three
    services — trigger it explicitly ("Verify exit"), and it rides whatever
    outbound proxy is configured. Cached ~25s so a verify burst doesn't hammer
    the services.
    """
    if not oracles:
        return _local_opsec()
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
        "public_ip": pub_ip, "org": org, "city": city, "country": country, "mode": "oracles",
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
            # built-in: opsec / anonymity (every console can warn you). The
            # always-on poll is local-only (no outbound); ?verify=1 opts in to
            # the exit-IP oracle check, which does reveal the IP to 3 services.
            if path == "/api/opsec" and method == "GET":
                self._send(Response.json(opsec_status(oracles=(query.get("verify") == ["1"]))))
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
                if self.headers.get("Transfer-Encoding"):
                    # The body is sized by Content-Length; a chunked body would
                    # read as empty and silently drop the request. Refuse it and
                    # close, rather than mis-handling it. (No browser fetch(str)
                    # path sends chunked, so this only trips a raw/hostile client.)
                    self.close_connection = True
                    self._send(Response.error(HTTPStatus.BAD_REQUEST, "chunked request bodies are not supported"))
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = 0
                if length < 0:
                    length = 0  # a negative Content-Length is malformed; treat as no body
                limit = app.body_limits.get(key, MAX_BODY)  # per-route override (uploads)
                if length > limit:
                    # Close instead of leaving the oversized body on a keep-alive
                    # socket for the next request to trip over.
                    self.close_connection = True
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
