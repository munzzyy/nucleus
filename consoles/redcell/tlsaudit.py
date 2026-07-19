"""Deep TLS/cipher/chain audit — stdlib `ssl` only, no external tool required.

sslscan/testssl already live in the runner tools (SAFE_RUNNERS), but they're
optional installs and they exec a subprocess. This gives the same "what does
this server's TLS actually look like" answer natively: which protocol
versions the server will complete a handshake on (TLS 1.0 through 1.3, tested
one at a time by pinning an SSLContext's min/max version), the cipher each one
negotiates, and the certificate — read even when the chain doesn't validate,
which is the whole point (an expired/self-signed/hostname-mismatched cert is
exactly the finding you're here for, not something that should vanish behind
a failed handshake).

Certificate handling below is deliberately the same two-phase approach as
`engine/osint_report.py`'s `_tls_cert()` — verify first, and if that fails,
reconnect unverified and decode the leaf by hand via the stdlib's own
`ssl._ssl._test_decode_cert` — reusing that module's exact helpers
(`_decode_cert_pem`, `_parse_cert_time`, `_host_matches_cert`) so a cert never
gets described two different ways by two independently-written decoders. It's
inlined here rather than calling `_tls_cert()` directly because that function
resolves the hostname itself; this one resolves ONCE up front and pins that
same IP for both the cert read and the whole protocol sweep below it, so an
attacker with short-TTL DNS can't hand the cert-check and the protocol-check
two different addresses.

SSRF posture: `common.resolve_public_ips()` gate before any socket opens
(refuses private/loopback/reserved — same guard `common.fetch` uses), connect
to the pinned IP (never re-resolve mid-audit), hard per-connection timeout,
every failure mode caught so a dead/hostile/legacy-TLS-only target degrades
the result instead of crashing the server.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

from shared import common
from consoles.redcell import runners
from engine import osint_report as report

_TLS_PORT = 443
_HANDSHAKE_TIMEOUT = 6.0

# Tested oldest-first so the read-out lists them in the order an auditor
# thinks about them. Built from the ssl module's own TLSVersion enum so this
# quietly stops testing versions a future Python/OpenSSL build drops, instead
# of raising on a missing attribute.
_PROTOCOL_NAMES = ("TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3")
_PROTOCOL_LABELS = {
    "TLSv1": "TLS 1.0", "TLSv1_1": "TLS 1.1",
    "TLSv1_2": "TLS 1.2", "TLSv1_3": "TLS 1.3",
}

# Cipher-suite name fragments that mean "broken regardless of protocol" —
# checked against both the baseline handshake's cipher and every accepted
# protocol's negotiated cipher.
_WEAK_CIPHER_MARKERS = ("RC4", "DES", "3DES", "NULL", "EXPORT", "_MD5", "ADH", "AECDH")


def _f(sev: str, title: str, detail: str) -> dict:
    return {"severity": sev, "title": title, "detail": detail}


def _protocol_versions() -> list[tuple[str, str, "ssl.TLSVersion"]]:
    """(attr_name, label, enum_value) for every protocol this Python's ssl
    module actually knows about — a build that stripped TLSv1/TLSv1_1
    constants entirely just gets fewer rows instead of an AttributeError."""
    out = []
    for name in _PROTOCOL_NAMES:
        version = getattr(ssl.TLSVersion, name, None)
        if version is not None:
            out.append((name, _PROTOCOL_LABELS[name], version))
    return out


def _attempt_protocol(ip: str, hostname: str, version: "ssl.TLSVersion",
                       timeout: float) -> dict:
    """One forced-version handshake attempt. `accepted` is True (server speaks
    this version), False (server actively refused it — the version alert we
    want to see for TLS 1.0/1.1), or None (couldn't tell — connection-level
    failure, not a protocol decision)."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        # A modern OpenSSL's default security level (SECLEVEL=2) silently
        # refuses to even OFFER TLS 1.0/1.1-era ciphers regardless of what
        # minimum/maximum_version says, which would misreport "refused" for a
        # server that actually still speaks the old protocol. Dropping our own
        # client-side floor to 0 tests what THE SERVER accepts, not what our
        # local OpenSSL build still permits.
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        with socket.create_connection((ip, _TLS_PORT), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                c = ssock.cipher()
                return {"accepted": True, "negotiated": ssock.version(),
                        "cipher": c[0] if c else None, "reason": ""}
    except ssl.SSLError as e:
        return {"accepted": False, "negotiated": None, "cipher": None, "reason": str(e)}
    except (ValueError, AttributeError) as e:
        return {"accepted": None, "negotiated": None, "cipher": None,
                 "reason": f"not testable on this OpenSSL build: {e}"}
    except (OSError, socket.timeout) as e:
        return {"accepted": None, "negotiated": None, "cipher": None,
                 "reason": f"connection error: {type(e).__name__}: {e}"}


def _cert_and_baseline(ip: str, host: str, timeout: float) -> dict:
    """Same two-phase read as engine.osint_report._tls_cert (verifying
    handshake first; on failure, reconnect unverified and decode the leaf by
    hand) — against an IP already resolved-and-validated by the caller, so
    the cert read and the protocol sweep in assess() below share one address
    instead of two independent DNS lookups an attacker could answer
    differently."""
    trusted = False
    verify_error = None
    protocol = cipher = None
    cert: Optional[dict] = None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, _TLS_PORT), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                c = ssock.cipher()
                cipher = c[0] if c else None
        trusted = True
    except ssl.SSLCertVerificationError as e:
        verify_error = getattr(e, "verify_message", None) or str(e)
    except ssl.SSLError as e:
        verify_error = str(e)
    except (OSError, socket.timeout) as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    if not cert:
        try:
            uctx = ssl._create_unverified_context()
            with socket.create_connection((ip, _TLS_PORT), timeout=timeout) as sock:
                with uctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    protocol = protocol or ssock.version()
                    c = ssock.cipher()
                    cipher = cipher or (c[0] if c else None)
            cert = report._decode_cert_pem(ssl.DER_cert_to_PEM_cert(der)) if der else {}
        except Exception as e:  # noqa: BLE001 — degrade, never crash the audit
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    cert = cert or {}
    issuer = dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else {}
    subject = dict(x[0] for x in cert.get("subject", [])) if cert.get("subject") else {}
    sans = sorted({v for k, v in cert.get("subjectAltName", []) if k == "DNS"})
    not_after_raw = cert.get("notAfter", "")
    not_after = report._parse_cert_time(not_after_raw)
    days_left = (not_after - datetime.now(timezone.utc)).days if not_after else None
    subject_cn = subject.get("commonName")

    return {
        "ok": True,
        "trusted": trusted,
        "verify_error": verify_error,
        "self_signed": bool(subject) and subject == issuer,
        "hostname_ok": (report._host_matches_cert(host, subject_cn, sans)
                        if (subject_cn or sans) else None),
        "baseline_protocol": protocol,
        "baseline_cipher": cipher,
        "issuer": issuer.get("organizationName") or issuer.get("commonName") or "unknown",
        "subject_cn": subject_cn,
        "not_after": not_after_raw,
        "days_left": days_left,
        "sans": sans[:25],
    }


def _has_weak_cipher(name: Optional[str]) -> bool:
    if not name:
        return False
    upper = name.upper()
    return any(marker in upper for marker in _WEAK_CIPHER_MARKERS)


def grade(cert: dict, protocols: dict) -> tuple[str, float, list[dict]]:
    """Score the assessment and return (letter, pct, findings). Pure function
    over already-collected data — no I/O — so it's independently testable
    with constructed fixtures."""
    findings: list[dict] = []
    pts = 0
    max_pts = 80  # cert health 40 + baseline cipher 10 + no-legacy-protocol 20 + TLS 1.3 offered 10

    if cert.get("self_signed"):
        findings.append(_f("high", "TLS certificate is self-signed",
                            "Browsers reject it with a hard, unskippable warning. Get a cert from a "
                            "public CA — Let's Encrypt is free and automatable."))
    elif cert.get("days_left") is not None and cert["days_left"] < 0:
        findings.append(_f("high", f"TLS certificate expired {-cert['days_left']} day(s) ago",
                            "Renew immediately — every client sees a hard, unskippable warning."))
    elif cert.get("hostname_ok") is False:
        findings.append(_f("high", "TLS certificate does not cover this hostname",
                            "The cert's CN/SANs don't include this host. Reissue with the correct SAN(s)."))
    elif not cert.get("trusted"):
        ve = cert.get("verify_error") or "chain did not validate"
        findings.append(_f("high", "TLS certificate chain does not validate",
                            f"{ve} — install the full chain (leaf + intermediates)."))
    else:
        pts += 30
        days_left = cert.get("days_left")
        if days_left is not None and days_left < 14:
            findings.append(_f("medium", f"TLS certificate expires in {days_left} day(s)",
                                "Renew now — a lapsed cert is a hard outage, not a soft warning."))
            pts += 5
        else:
            pts += 10

    # Weak cipher check covers the modern (baseline) handshake AND every
    # legacy protocol that got accepted below — a server that only offers
    # RC4/3DES on its TLS 1.0 fallback is exactly as broken as one that
    # offers it on its main handshake, so either surfaces the same finding
    # (deduplicated by cipher name) without being double-scored.
    weak_ciphers = {cert.get("baseline_cipher")} if _has_weak_cipher(cert.get("baseline_cipher")) else set()
    for row in protocols.values():
        if row.get("accepted") and _has_weak_cipher(row.get("cipher")):
            weak_ciphers.add(row["cipher"])
    if weak_ciphers:
        for name in sorted(c for c in weak_ciphers if c):
            findings.append(_f("high", f"Weak cipher accepted: {name}",
                                "RC4/DES/3DES/NULL/export/anonymous ciphers are all broken by modern standards."))
    else:
        pts += 10

    accepted_legacy = []
    for name in ("TLSv1", "TLSv1_1"):
        label = _PROTOCOL_LABELS[name]
        row = protocols.get(label)
        if row and row.get("accepted") is True:
            accepted_legacy.append(label)
    if accepted_legacy:
        findings.append(_f("high", f"Server accepts {', '.join(accepted_legacy)}",
                            "TLS 1.0/1.1 are deprecated (RFC 8996) — PCI-DSS and every major browser have "
                            "dropped support. Disable them server-side."))
    else:
        pts += 20

    tls13 = protocols.get(_PROTOCOL_LABELS["TLSv1_3"])
    if tls13 and tls13.get("accepted") is True:
        pts += 10
    elif tls13 and tls13.get("accepted") is False:
        findings.append(_f("low", "Server does not offer TLS 1.3",
                            "TLS 1.3 is faster and drops legacy cipher/handshake weaknesses — worth enabling."))

    pct = round(min(pts, max_pts) / max_pts * 100, 1) if max_pts else 0.0
    letter = ("A" if pct >= 90 else "B" if pct >= 80 else "C" if pct >= 65
              else "D" if pct >= 50 else "F")
    sev_rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: sev_rank.get(f["severity"], 3))
    return letter, pct, findings


def assess(host: str, timeout: float = _HANDSHAKE_TIMEOUT) -> dict:
    """Full TLS assessment of `host`:443. Assumes the caller already validated
    the hostname/scope — this only does the network + cert + grading work.
    Never raises: every failure mode degrades to an {"ok": False, "error"}
    result instead of crashing the request."""
    try:
        ips = common.resolve_public_ips(host)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    if not ips:
        return {"ok": False, "error": "host did not resolve to a public address"}
    ip = ips[0]

    cert = _cert_and_baseline(ip, host, timeout)
    if not cert.get("ok"):
        return cert

    protocols = {}
    for _attr, label, version in _protocol_versions():
        protocols[label] = _attempt_protocol(ip, host, version, timeout)

    letter, pct, findings = grade(cert, protocols)

    return {
        "ok": True,
        "host": host,
        "resolved_ip": ip,
        "cert": {k: v for k, v in cert.items() if k != "ok"},
        "protocols": protocols,
        "grade": letter,
        "score_pct": pct,
        "findings": findings,
        "counts": {sev: sum(1 for f in findings if f["severity"] == sev)
                   for sev in ("high", "medium", "low")},
    }


_LAB_PRIVATE_MSG = (
    "The native TLS audit dials :443 directly (no HTTP fetch to route through the SSRF guard), "
    "which refuses private/loopback/link-local targets even in lab mode. For an internal or "
    "staging host, use sslscan/testssl from the Runners tab instead — those exec a binary that "
    "connects directly and reach lab targets fine.")


def handle_tls_audit(req) -> "common.Response":
    """POST /api/tls-audit  {host, authorized, lab}  ->  full TLS assessment.

    Same authorized/scope/opsec gate as every other target-touching redcell
    action — this opens a raw socket straight to the target, so it gets the
    identical treatment webscan.py's single-fetch analyzer gets, just without
    a URL (there's no path/scheme here, only a host:443 to dial).
    """
    body = req.json()
    target_raw = body.get("host") or body.get("target")
    authorized = body.get("authorized") is True
    lab = body.get("lab") is True

    if not authorized:
        return common.Response.error(403,
            "authorized:true is required — confirm you have permission to test this target.")
    if not isinstance(target_raw, str):
        return common.Response.error(400, "host must be a string")

    ok, host_or_reason = runners.validate_host(target_raw)
    if not ok:
        return common.Response.error(400, f"invalid target: {host_or_reason}")
    host = host_or_reason

    in_scope, reason = runners.scope_check(host, lab)
    if not in_scope:
        return common.Response.error(403, reason)

    blocked = runners.opsec_gate(lab, body)
    if blocked is not None:
        return blocked

    if lab and not common.host_is_public(host):
        return common.Response.error(400, _LAB_PRIVATE_MSG)

    if not lab and not runners._resolve_public_ips_safe(host):
        return common.Response.error(403,
            "target no longer resolves to a public address (re-checked before connecting) — refusing")

    result = assess(host)

    if result.get("ok"):
        runners._append_audit({
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": "tls-audit", "target": host, "authorized": authorized, "lab": lab,
            "grade": result.get("grade"), "counts": result.get("counts", {}),
        })
    return common.Response.json(result)
