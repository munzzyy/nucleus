"""Native web security analyzer — one passive request, a graded read-out.

Point it at a URL and it tells you, without any external tool installed, what
a browser and an attacker learn from the response: which security headers are
present/missing/weak, whether cookies are set safely, what version/tech the
server leaks, and whether CORS is misconfigured into an actual finding. It's
the thing you run first on every web target — nikto/nuclei are heavier and
need installing; this is instant and always there.

It is passive: at most two HTTP GETs to the target (one plain, one with a
probe Origin to test CORS), through `common.fetch` — the same SSRF-guarded,
connect-pinned, redirect-revalidated path recon uses, so a target that
resolves to loopback/RFC1918 is refused and DNS-rebinding can't turn this
into a probe of the local network. No POST, no auth, no injected payloads.

Gated like every other redcell action: authorized:true required server-side,
and public-scope enforced unless lab:true (your own box). The single request
this makes is strictly less intrusive than the nmap/nikto runners, but it
goes through the same gate so the console has one consistent authorization
story.
"""

from __future__ import annotations

import http.client
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from shared import common
from consoles.redcell import runners

# Everything common.fetch can raise: ValueError (blocked host / bad scheme /
# too many redirects), OSError (socket/TLS/timeout — TimeoutError and SSLError
# are both OSError subclasses), and http.client.HTTPException. Catch exactly
# these — same set common.dns_query() catches — so a real bug still surfaces
# instead of being swallowed by a bare `except Exception`.
_FETCH_ERRORS = (ValueError, OSError, http.client.HTTPException)

# A throwaway Origin used only to see whether the server reflects an arbitrary
# origin back in Access-Control-Allow-Origin (the classic CORS misconfig). It is
# never a real host and nothing is ever sent to it. Kept deliberately neutral (no
# "nucleus" tool name) so the Origin header this leaves in the target's logs
# doesn't identify your tooling. `.example` is a reserved TLD — it can't resolve.
_CORS_PROBE_ORIGIN = "https://web.example"

# Shown when someone points a native fetch tool at a private/lab target: the
# SSRF guard won't fetch it, and that's by design (see the handler).
_LAB_PRIVATE_MSG = (
    "The native web tools (analyzer + secret scanner) fetch through the SSRF guard, "
    "which refuses private/loopback/link-local targets even in lab mode. For an internal "
    "or staging host on a private IP, use the runner tools (nikto / nuclei / whatweb) or "
    "Expert mode — those exec a binary that connects directly, so they reach lab targets.")

def _extract_title(body: bytes) -> str:
    """Linear <title> extraction via bytes.find — never a `.*?</title>` regex,
    which backtracks O(n^2) on a page full of unclosed <title> tags. O(n)."""
    low = body.lower()
    s = low.find(b"<title")
    if s == -1:
        return ""
    gt = low.find(b">", s)
    if gt == -1:
        return ""
    end = low.find(b"</title", gt)
    if end == -1:
        return ""
    return body[gt + 1:end].decode("utf-8", "replace").strip()[:200]


# --------------------------------------------------------------------------
# Security-header catalog. Each entry: how to grade the value that's present,
# points available, and advice when it's missing/weak. Points sum into a
# grade so the read-out has a single headline the way the report engine does.
# --------------------------------------------------------------------------
def _norm_headers(headers: dict) -> dict:
    """Lower-case every header name; last value wins (same as a browser)."""
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


def _check_hsts(v: Optional[str]) -> tuple[int, int, list]:
    if not v:
        return 0, 15, [_f("high", "Missing HSTS (Strict-Transport-Security)",
                          "No HSTS — a downgrade/SSL-strip MITM can force plaintext. "
                          "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")]
    findings = []
    m = re.search(r"max-age=(\d+)", v)
    age = int(m.group(1)) if m else 0
    if age < 15552000:  # < ~180 days
        findings.append(_f("low", "Weak HSTS max-age",
                           f"max-age={age} is short; 31536000 (1 year) is the norm."))
    if "includesubdomains" not in v.lower():
        findings.append(_f("low", "HSTS without includeSubDomains",
                           "Sub-domains aren't covered by HSTS."))
    pts = 15 if not findings else 9
    return pts, 15, findings


def _check_csp(v: Optional[str]) -> tuple[int, int, list]:
    if not v:
        return 0, 15, [_f("medium", "Missing Content-Security-Policy",
                          "No CSP — the main defense-in-depth against XSS/data-injection is absent.")]
    low = v.lower()
    findings = []
    if "unsafe-inline" in low:
        findings.append(_f("medium", "CSP allows 'unsafe-inline'",
                           "'unsafe-inline' in the policy largely defeats CSP's XSS protection."))
    if "unsafe-eval" in low:
        findings.append(_f("low", "CSP allows 'unsafe-eval'", "'unsafe-eval' weakens the policy."))
    if re.search(r"(default|script)-src[^;]*\*", low):
        findings.append(_f("medium", "CSP uses a wildcard source",
                           "A '*' source in default-src/script-src lets scripts load from anywhere."))
    pts = 15 if not findings else 8
    return pts, 15, findings


def _check_simple(v: Optional[str], name: str, want: str, sev: str, pts: int,
                  advice: str) -> tuple[int, int, list]:
    if not v:
        return 0, pts, [_f(sev, f"Missing {name}", advice)]
    if want and want.lower() not in v.lower():
        return pts // 2, pts, [_f("low", f"{name} present but unexpected value",
                                  f"{name}: {v} (expected something like '{want}').")]
    return pts, pts, []


def _f(sev: str, title: str, detail: str) -> dict:
    return {"severity": sev, "title": title, "detail": detail}


# --------------------------------------------------------------------------
# Cookies + information disclosure
# --------------------------------------------------------------------------
_DISCLOSURE_HEADERS = {
    "server": "Server software/version",
    "x-powered-by": "Framework/runtime",
    "x-aspnet-version": "ASP.NET version",
    "x-aspnetmvc-version": "ASP.NET MVC version",
    "x-generator": "CMS/generator",
    "x-drupal-cache": "Drupal",
    "via": "Proxy chain",
}


def _analyze_cookies(set_cookie: Optional[str]) -> tuple[list, list]:
    """Return (cookies, findings). `common.fetch` collapses duplicate
    Set-Cookie into one comma-joined value; split on the boundary between one
    cookie's attributes and the next cookie's name=value (a comma directly
    before `token=`), tolerating the Expires=...GMT comma inside a cookie."""
    if not set_cookie:
        return [], []
    # Split only on ", " that precedes a `name=` (start of a new cookie),
    # never the comma inside `Expires=Wed, 09 Jun 2021 ...`.
    parts = re.split(r",\s*(?=[A-Za-z0-9!#$%&'*+.^_`|~-]+=)", set_cookie)
    cookies, findings = [], []
    for part in parts:
        segs = [s.strip() for s in part.split(";")]
        if not segs or "=" not in segs[0]:
            continue
        name = segs[0].split("=", 1)[0]
        attrs = {s.split("=", 1)[0].lower(): (s.split("=", 1)[1] if "=" in s else "")
                 for s in segs[1:]}
        secure = "secure" in attrs
        httponly = "httponly" in attrs
        samesite = attrs.get("samesite", "")
        cookies.append({"name": name, "secure": secure, "httponly": httponly,
                        "samesite": samesite or "(none)"})
        if not secure:
            findings.append(_f("medium", f"Cookie '{name}' missing Secure",
                               "Can be sent over plaintext HTTP — interceptable."))
        if not httponly:
            findings.append(_f("medium", f"Cookie '{name}' missing HttpOnly",
                               "Readable from JavaScript — stealable via XSS."))
        if not samesite:
            findings.append(_f("low", f"Cookie '{name}' missing SameSite",
                               "No SameSite — weaker CSRF posture."))
    return cookies, findings


# --------------------------------------------------------------------------
# CORS probe
# --------------------------------------------------------------------------
def _analyze_cors(url: str) -> tuple[dict, list]:
    """Second GET with a probe Origin. Reflected origin (or '*') plus
    Allow-Credentials:true is a real, reportable CORS misconfiguration."""
    try:
        status, _body, headers = common.fetch(
            url, timeout=8.0, headers={"Origin": _CORS_PROBE_ORIGIN}, max_bytes=4096)
    except _FETCH_ERRORS:
        return {"tested": False}, []
    h = _norm_headers(headers)
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower() == "true"
    reflected = acao == _CORS_PROBE_ORIGIN
    wildcard = acao == "*"
    findings = []
    if reflected and acac:
        findings.append(_f("high", "CORS reflects arbitrary Origin with credentials",
                           "Access-Control-Allow-Origin echoes any Origin AND Allow-Credentials is true — "
                           "any site can read authenticated responses. Classic account-takeover CORS bug."))
    elif reflected:
        findings.append(_f("medium", "CORS reflects arbitrary Origin",
                           "The server echoes any Origin in Access-Control-Allow-Origin. Risky if any "
                           "endpoint returns sensitive data without credentials."))
    elif wildcard and acac:
        findings.append(_f("medium", "CORS wildcard with credentials",
                           "ACAO '*' together with Allow-Credentials is invalid but some stacks honor it — verify."))
    return {"tested": True, "acao": acao, "allow_credentials": acac,
            "reflected": reflected, "wildcard": wildcard, "status": status}, findings


# --------------------------------------------------------------------------
# Grade
# --------------------------------------------------------------------------
def _grade(pts: int, maxpts: int) -> tuple[str, float]:
    pct = (pts / maxpts * 100) if maxpts else 0.0
    letter = ("A" if pct >= 90 else "B" if pct >= 80 else "C" if pct >= 65
              else "D" if pct >= 50 else "F")
    return letter, round(pct, 1)


def analyze(url: str) -> dict:
    """Fetch `url` and grade its HTTP security posture. Assumes the caller
    already validated the URL and confirmed scope — this only does the passive
    HTTP work. Never raises: a fetch failure becomes an 'unreachable' result."""
    try:
        status, body, headers = common.fetch(url, timeout=10.0, max_bytes=200_000)
    except ValueError as e:
        return {"ok": False, "error": f"blocked: {e}"}
    except (OSError, http.client.HTTPException) as e:
        return {"ok": False, "error": f"unreachable: {type(e).__name__}: {e}"}

    h = _norm_headers(headers)
    findings: list = []
    pts = 0
    maxpts = 0

    checks = [
        _check_hsts(h.get("strict-transport-security")),
        _check_csp(h.get("content-security-policy")),
        _check_simple(h.get("x-frame-options"), "X-Frame-Options", "DENY", "medium", 10,
                      "No clickjacking protection. Add X-Frame-Options: DENY (or a CSP frame-ancestors)."),
        _check_simple(h.get("x-content-type-options"), "X-Content-Type-Options", "nosniff", "low", 8,
                      "Add X-Content-Type-Options: nosniff to stop MIME sniffing."),
        _check_simple(h.get("referrer-policy"), "Referrer-Policy", "", "low", 6,
                      "Add a Referrer-Policy (e.g. no-referrer or strict-origin-when-cross-origin)."),
        _check_simple(h.get("permissions-policy"), "Permissions-Policy", "", "low", 6,
                      "Add a Permissions-Policy to lock down browser features."),
    ]
    for p, mx, fs in checks:
        pts += p
        maxpts += mx
        findings.extend(fs)

    cookies, cookie_findings = _analyze_cookies(headers.get("Set-Cookie") or h.get("set-cookie"))
    findings.extend(cookie_findings)
    # Cookie safety worth up to 10 points if any cookies are set.
    if cookies:
        maxpts += 10
        bad = len(cookie_findings)
        pts += max(0, 10 - min(10, bad * 3))

    disclosures = []
    for hk, label in _DISCLOSURE_HEADERS.items():
        if hk in h and h[hk]:
            disclosures.append({"header": hk, "label": label, "value": h[hk]})
            if re.search(r"\d+\.\d+", h[hk]):
                findings.append(_f("low", f"Version disclosure via {hk}",
                                   f"{hk}: {h[hk]} — reveals exact software/version to attackers."))

    cors, cors_findings = _analyze_cors(url)
    findings.extend(cors_findings)

    title = _extract_title(body or b"")

    # HTTP-vs-HTTPS: flag a plaintext scheme outright.
    if url.lower().startswith("http://"):
        findings.append(_f("medium", "Target served over plaintext HTTP",
                           "This URL is http://. Everything is interceptable; the site should force HTTPS."))

    letter, pct = _grade(pts, maxpts)
    sev_rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: sev_rank.get(f["severity"], 3))

    return {
        "ok": True,
        "url": url,
        "status": status,
        "grade": letter,
        "score_pct": pct,
        "points": pts,
        "max_points": maxpts,
        "title": title,
        "server": h.get("server", ""),
        "content_type": h.get("content-type", ""),
        "body_bytes": len(body or b""),
        "present_headers": sorted(k for k in h if k in _SECURITY_HEADER_KEYS),
        "missing_headers": sorted(k for k in _SECURITY_HEADER_KEYS if k not in h),
        "cookies": cookies,
        "disclosures": disclosures,
        "cors": cors,
        "findings": findings,
        "counts": {sev: sum(1 for f in findings if f["severity"] == sev)
                   for sev in ("high", "medium", "low")},
    }


_SECURITY_HEADER_KEYS = {
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "cross-origin-opener-policy", "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
}


def handle_web_analyze(req) -> "common.Response":
    """POST /api/web-analyze  {url, authorized, lab}  ->  graded analysis.

    Same gate as the runners: authorized:true required, URL validated, public
    scope enforced unless lab. Reuses runners.validate_url / scope_check so it
    can never have a laxer notion of a valid/in-scope target than /api/run.
    """
    body = req.json()
    target_raw = body.get("url") or body.get("target")
    authorized = body.get("authorized") is True
    lab = body.get("lab") is True

    if not authorized:
        return common.Response.error(403,
            "authorized:true is required — confirm you have permission to test this target.")
    if not isinstance(target_raw, str):
        return common.Response.error(400, "url must be a string")

    ok, host_or_reason, cleaned = runners.validate_url(target_raw)
    if not ok:
        return common.Response.error(400, f"invalid target: {host_or_reason}")

    in_scope, reason = runners.scope_check(host_or_reason, lab)
    if not in_scope:
        return common.Response.error(403, reason)

    blocked = runners.opsec_gate(lab, body)
    if blocked is not None:
        return blocked

    # The native fetch tools go through common.fetch's SSRF guard, which
    # refuses private/loopback targets even in lab mode. Say so plainly here
    # instead of letting analyze() return a cryptic 'blocked' from deep in the
    # fetch layer. (The runner tools reach private lab targets fine — they exec
    # a binary that connects directly, no fetch guard.)
    if lab and not common.host_is_public(host_or_reason):
        return common.Response.error(400, _LAB_PRIVATE_MSG)

    # Re-resolve immediately before the fetch (DNS-rebind step 8, recheck
    # tier) unless lab — fetch() itself also pins to a validated IP, so this
    # is belt-and-suspenders consistent with /api/run's web runners.
    if not lab and not runners._resolve_public_ips_safe(host_or_reason):
        return common.Response.error(403,
            "target no longer resolves to a public address (re-checked before fetch) — refusing")

    result = analyze(cleaned)

    # Audit trail, consistent with the runners and the secret scanner: every
    # authorized action that reaches a target leaves a record. Log scheme/host/
    # path only (a querystring can carry a token).
    if result.get("ok"):
        p = urlparse(cleaned)
        runners._append_audit({
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": "web-analyze", "target": f"{p.scheme}://{p.netloc}{p.path}",
            "authorized": authorized, "lab": lab,
            "grade": result.get("grade"), "counts": result.get("counts", {}),
        })
    return common.Response.json(result)
