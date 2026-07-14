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
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import threading
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
     "tag": "defensive",      "desc": "Hardening, opsec posture, and the report engine."},
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
    except ValueError:
        return False
    return (u.hostname in ("127.0.0.1", "localhost", "::1")
            and (u.port == port or (u.port is None and u.scheme in ("http", "https"))))


def host_is_public(hostname: str) -> bool:
    """SSRF guard: True only if every resolved address is a normal public IP.

    Blocks loopback, RFC1918, link-local, multicast, reserved, and CGNAT.
    Used before recon ever fetches a user-supplied host.
    """
    hostname = (hostname or "").strip()
    if not hostname:
        return False
    # A bare IP literal: check it directly.
    try:
        ip = ipaddress.ip_address(hostname)
        return _ip_is_public(ip)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    if not infos:
        return False
    for info in infos:
        addr = info[4][0]
        try:
            if not _ip_is_public(ipaddress.ip_address(addr)):
                return False
        except ValueError:
            return False
    return True


def _ip_is_public(ip) -> bool:
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified):
        return False
    # CGNAT 100.64.0.0/10
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return True


# --------------------------------------------------------------------------
# Outbound fetch (SSRF-guarded) — recon's only door to the internet
# --------------------------------------------------------------------------
_UA = "nucleus-recon/1.0 (+local osint console)"
_MAX_REDIRECTS = 5


def _resolve_public(host: str) -> tuple[str, int]:
    """Resolve `host` and confirm EVERY address is public. Returns (ip, family).

    We resolve once here and connect to exactly this IP, so the address the
    guard approved is the address we actually talk to — no second lookup for an
    attacker to poison (defeats DNS-rebinding TOCTOU). A host that resolves to
    any non-public address at all is refused.
    """
    try:
        ipobj = ipaddress.ip_address(host)
        if not _ip_is_public(ipobj):
            raise ValueError(f"non-public IP: {host}")
        return host, (socket.AF_INET6 if ipobj.version == 6 else socket.AF_INET)
    except ValueError as e:
        if "non-public" in str(e):
            raise
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        raise ValueError(f"unresolvable host: {host}")
    if not infos:
        raise ValueError(f"unresolvable host: {host}")
    for info in infos:
        addr = info[4][0]
        try:
            if not _ip_is_public(ipaddress.ip_address(addr)):
                raise ValueError(f"host resolves to non-public address: {host} -> {addr}")
        except ValueError:
            raise ValueError(f"host resolves to non-public address: {host} -> {addr}")
    fam, _, _, _, sockaddr = infos[0]
    return sockaddr[0], fam


def fetch(url: str, *, timeout: float = DEFAULT_TIMEOUT, headers: Optional[dict] = None,
          data: Optional[bytes] = None, allow_hosts: Optional[set] = None,
          max_bytes: int = 2_000_000) -> tuple[int, bytes, dict]:
    """GET/POST a URL with a hard SSRF guard. Returns (status, body, headers).

    Redirects are followed manually and the guard runs again on every hop's
    host, so a public URL can't 3xx-bounce into loopback/metadata. Each hop is
    connected to the exact IP the guard validated (hostname preserved for TLS
    SNI + cert check), which also closes the resolve-then-reconnect race.
    `allow_hosts` is accepted for call-site compatibility but never relaxes the
    public check. Raises ValueError on a blocked host or non-http scheme.
    """
    method = "POST" if data is not None else "GET"
    current = url
    body_data = data
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
        for k, v in (headers or {}).items():
            req_headers[k] = v

        sock = socket.create_connection((ip, port), timeout=timeout)
        try:
            if u.scheme == "https":
                ctx = ssl.create_default_context()
                conn = http.client.HTTPSConnection(host, port, timeout=timeout)
                conn.sock = ctx.wrap_socket(sock, server_hostname=host)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
                conn.sock = sock
            conn.request(method, path, body=body_data, headers=req_headers)
            resp = conn.getresponse()
            status = resp.status
            loc = resp.getheader("Location")
            if status in (301, 302, 303, 307, 308) and loc:
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
            try:
                sock.close()
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
        except (ValueError, OSError, json.JSONDecodeError):
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
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/healthz", timeout=_HEALTH_TIMEOUT) as r:
            return r.status == 200
    except (OSError, urllib.error.URLError):
        return False


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
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError):
        return None


def siblings_status() -> list[dict]:
    """Health of every console + known external app, checked in parallel."""
    items = [dict(c) for c in CONSOLES] + [dict(a) for a in EXTERNAL_APPS]
    results: dict[int, bool] = {}
    lock = threading.Lock()

    def worker(port):
        up = _ping(port)
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
                if length > MAX_BODY:
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
