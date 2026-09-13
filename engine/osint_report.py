#!/usr/bin/env python3
"""Passive OSINT security-assessment report engine.

Given a domain, produces a graded (A-F) passive security assessment from
public sources only — DNS, HTTP response headers, certificate-transparency
logs, and Shodan's free InternetDB. No active scanning, no exploitation,
nothing touches the target beyond what a normal browser/DNS resolver would.

All outbound traffic goes through shared.common.fetch (SSRF-guarded) and
shared.common.dns_query (encrypted DoH). Every external call is individually
timeout-bounded and wrapped so one dead source degrades the report instead
of crashing it.

Importable:
    from engine.osint_report import assess, render_markdown, render_html

CLI:
    python3 engine/osint_report.py <domain> [--json] [--md] [--html] [--pdf] [--out DIR]
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from shared import common  # noqa: E402

REPORTS_DIR = Path(__file__).resolve().parent / "reports"
_SRC_TIMEOUT = 8.0
_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "smtp", "mx", "s1"]


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def _safe_domain(domain: str) -> str:
    d = (domain or "").strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split(":")[0]
    return d


def _slug(domain: str) -> str:
    return re.sub(r"[^a-z0-9.-]", "-", domain.lower()).strip("-") or "unknown"


def finding(severity: str, title: str, recommendation: str = "") -> dict:
    return {"severity": severity, "title": title, "recommendation": recommendation}


def _dns(name: str, rtype: str) -> list[dict]:
    # strict=True so a DoH outage raises DNSUnavailable (caught per-check below)
    # instead of masquerading as "no such record" and deflating a client's grade.
    return common.dns_query(name, rtype, timeout=_SRC_TIMEOUT, strict=True)


def _txt_values(name: str) -> list[str]:
    vals = []
    for a in _dns(name, "TXT"):
        d = (a.get("data") or "").strip()
        if len(d) >= 2 and d[0] == '"' and d[-1] == '"':
            d = d[1:-1]
        d = d.replace('" "', "")
        if d:
            vals.append(d)
    return vals


def _fetch(url: str, timeout: float = _SRC_TIMEOUT, max_bytes: int = 400_000,
           *, follow_redirects: bool = True) -> dict:
    try:
        status, body, headers = common.fetch(url, timeout=timeout, max_bytes=max_bytes,
                                             follow_redirects=follow_redirects)
        return {"ok": True, "status": status, "headers": {k.lower(): v for k, v in headers.items()},
                "body_len": len(body), "body": body, "url": url}
    except (ValueError, OSError) as e:
        return {"ok": False, "error": str(e), "url": url}
    except Exception as e:  # a source misbehaving must never crash the whole report
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "url": url}


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------
def _collect_dns(domain: str) -> dict:
    # available=False if the DoH lookup itself failed (per record type), so the
    # caller never reads "no MX" as fact when the truth is "couldn't ask".
    out = {"A": [], "AAAA": [], "MX": [], "NS": [], "available": True}
    for rtype in ("A", "AAAA", "MX", "NS"):
        try:
            ans = _dns(domain, rtype)
        except common.DNSUnavailable:
            out["available"] = False
            continue
        out[rtype] = sorted({(a.get("data") or "").rstrip(".") for a in ans if a.get("data")})
    return out


def _apex_ip(dns_section: dict) -> str | None:
    if dns_section.get("A"):
        return dns_section["A"][0]
    if dns_section.get("AAAA"):
        return dns_section["AAAA"][0]
    return None


# --------------------------------------------------------------------------
# Email security — SPF / DMARC / DKIM hint
# --------------------------------------------------------------------------
def _check_spf(domain: str) -> dict:
    try:
        spf_vals = [v for v in _txt_values(domain) if v.lower().startswith("v=spf1")]
    except common.DNSUnavailable:
        return {"present": False, "record": None, "valid": False, "qualifier": None, "available": False}
    if not spf_vals:
        return {"present": False, "record": None, "valid": False, "qualifier": None, "available": True}
    rec = spf_vals[0]
    # The `all` mechanism must be its own token (start-of-record or after
    # whitespace), so an `all` substring inside another mechanism (e.g. a bare
    # `include:example-all`) is NOT read as the policy. A bare trailing `all`
    # with no qualifier defaults to '+' per RFC 7208 — it authorizes every
    # sender exactly like +all, so grade it as '+', not "no qualifier".
    m = re.search(r"(?:^|\s)([-~?+])?all\s*$", rec.strip(), re.I)
    qualifier = (m.group(1) or "+") if m else None
    has_redirect = "redirect=" in rec.lower()
    # "valid" = the record actually asserts a policy that protects the domain.
    # -all (fail) and ~all (softfail) do; a bare redirect= delegates to another
    # policy. ?all (neutral) and +all (pass-all) do NOT — +all in particular
    # tells receivers to accept mail from ANY server as this domain.
    protective = qualifier in ("-", "~") or (has_redirect and qualifier is None)
    return {"present": True, "record": rec, "valid": protective, "qualifier": qualifier, "available": True}


def _check_dmarc(domain: str) -> dict:
    try:
        vals = [v for v in _txt_values(f"_dmarc.{domain}") if v.lower().startswith("v=dmarc1")]
    except common.DNSUnavailable:
        return {"present": False, "record": None, "policy": None, "available": False}
    if not vals:
        return {"present": False, "record": None, "policy": None, "available": True}
    rec = vals[0]
    m = re.search(r"p=(\w+)", rec, re.I)
    return {"present": True, "record": rec, "policy": (m.group(1).lower() if m else "none"), "available": True}


def _check_dkim_hint(domain: str) -> dict:
    for sel in _DKIM_SELECTORS:
        try:
            if _dns(f"{sel}._domainkey.{domain}", "TXT"):
                return {"found": True, "selector": sel}
        except common.DNSUnavailable:
            return {"found": False, "selector": None, "available": False}
    return {"found": False, "selector": None}


def _check_mtasts(domain: str) -> dict:
    """MTA-STS (RFC 8461): a published policy that tells sending mail servers to
    require TLS for inbound mail to this domain, and to refuse to fall back to
    cleartext. The policy lives at a well-known HTTPS path on the mta-sts
    subdomain; we grade presence + mode (enforce/testing/none). Fetched through
    the same SSRF-guarded path as every other web check, so a hostile or dead
    host degrades to {present: False} instead of crashing the report."""
    res = _fetch(f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                 timeout=_SRC_TIMEOUT, max_bytes=20_000)
    if not (res.get("ok") and res.get("status") == 200 and res.get("body")):
        return {"present": False, "mode": None,
                "status": res.get("status") if res.get("ok") else None}
    text = res["body"].decode("utf-8", "replace")
    fields = {}
    for line in text.splitlines():
        key, sep, val = line.partition(":")
        if sep:
            fields[key.strip().lower()] = val.strip()
    # A real policy file starts with `version: STSv1`. Without that marker a 200
    # is just some other page answering on that host, not an MTA-STS policy.
    if fields.get("version", "").lower() != "stsv1":
        return {"present": False, "mode": None, "status": res.get("status")}
    return {"present": True, "mode": (fields.get("mode") or "").lower() or None,
            "status": 200}


def _check_tlsrpt(domain: str) -> dict:
    """TLS-RPT (RFC 8460): a TXT record at _smtp._tls.<domain> naming where to
    send SMTP TLS failure reports. Its presence means the operator is actually
    watching inbound-mail TLS health, which is the signal we grade."""
    try:
        vals = [v for v in _txt_values(f"_smtp._tls.{domain}") if v.lower().startswith("v=tlsrptv1")]
    except common.DNSUnavailable:
        return {"present": False, "record": None, "available": False}
    return {"present": bool(vals), "record": vals[0] if vals else None}


def _score_email(spf: dict, dmarc: dict, dkim: dict, mx_present: bool,
                 mtasts: dict | None = None, tlsrpt: dict | None = None) -> tuple[int, int, list]:
    max_pts, pts, findings = 30, 0, []
    spf_avail = spf.get("available", True)
    dmarc_avail = dmarc.get("available", True)

    if not spf_avail:
        max_pts -= 12   # SPF's full slice: excluded from the grade on a DNS outage, not scored as a failure
    elif spf["present"]:
        q = spf.get("qualifier")
        if q == "-":
            pts += 12
        elif q == "~":
            pts += 11
            findings.append(finding("low", "SPF ends in ~all (soft fail, not hard fail)",
                                     "~all asks receivers to accept-but-mark unlisted senders. Move to "
                                     "-all once every legitimate sender is listed."))
        elif spf["valid"]:  # redirect= delegation, no explicit all qualifier
            pts += 12
        elif q == "?":
            pts += 6
            findings.append(finding("medium", "SPF ends in ?all (neutral — provides no protection)",
                                     "?all makes no assertion, so receivers won't reject spoofed mail. "
                                     "Use -all (or ~all while testing)."))
        elif q == "+":
            pts += 2
            findings.append(finding("high", "SPF ends in +all — it authorizes every sender",
                                     "+all tells receivers to accept mail from ANY server as you, which is "
                                     "worse than having no SPF. Change the qualifier to -all (hard fail) or "
                                     "~all (soft fail)."))
        else:
            pts += 6
            findings.append(finding("medium", "SPF record present but has no 'all' qualifier",
                                     "End the record in a qualifier (-all/~all) so receivers know what to "
                                     "do with senders you didn't list."))
    else:
        sev = "high" if mx_present else "low"
        findings.append(finding(sev, "No SPF record found",
                                 "Publish a TXT record on the apex starting with v=spf1 ... -all "
                                 "to stop mail systems trusting spoofed senders."))

    if not dmarc_avail:
        max_pts -= 18   # DMARC's full slice, likewise excluded when the lookup could not run
    elif dmarc["present"]:
        policy = dmarc.get("policy") or "none"
        if policy == "reject":
            pts += 18
        elif policy == "quarantine":
            pts += 12
            findings.append(finding("low", "DMARC policy is quarantine, not reject",
                                     "Once alignment reports look clean, move p=quarantine to p=reject."))
        else:
            pts += 6
            findings.append(finding("medium", "DMARC policy is p=none (monitor-only)",
                                     "p=none only reports abuse, it doesn't stop it. Tighten to "
                                     "quarantine/reject once reports look clean."))
    else:
        sev = "high" if mx_present else "medium"
        findings.append(finding(sev, "No DMARC record found",
                                 "Publish _dmarc.<domain> TXT starting with v=DMARC1; p=none to "
                                 "start, then tighten."))

    if not dkim["found"]:
        findings.append(finding("info", "No DKIM selector detected among common names",
                                 "Best-effort check against common selectors only "
                                 f"({', '.join(_DKIM_SELECTORS)}) — DKIM may still be configured "
                                 "under a different selector."))

    # MTA-STS + TLS-RPT protect *inbound* mail in transit, so they only apply to
    # a domain that actually receives mail (has MX). Each is graded only when
    # there's an MX AND the check ran — the same variable-max discipline the
    # attack-surface section uses, so a no-mail domain or a source outage neither
    # inflates nor penalizes the grade. The existing four-arg callers (and the
    # unit tests) pass neither, so the email max stays 30 for them.
    if mx_present and mtasts is not None:
        max_pts += 4
        mode = mtasts.get("mode") if mtasts.get("present") else None
        if mode == "enforce":
            pts += 4
        elif mode == "testing":
            pts += 2
            findings.append(finding("low", "MTA-STS policy is in testing mode, not enforce",
                                     "Testing mode reports TLS failures but still allows cleartext "
                                     "delivery. Move to mode: enforce once the reports look clean."))
        elif mtasts.get("present"):
            findings.append(finding("low", "MTA-STS policy present but mode is not enforce",
                                     "A policy with mode: none provides no protection. Set "
                                     "mode: enforce so senders require TLS for mail to you."))
        else:
            findings.append(finding("low", "No MTA-STS policy found",
                                     "Publish an MTA-STS policy (mta-sts.<domain>/.well-known/"
                                     "mta-sts.txt with mode: enforce) so senders require TLS for "
                                     "inbound mail and won't silently fall back to cleartext."))

    if mx_present and tlsrpt is not None:
        max_pts += 2
        if tlsrpt.get("present"):
            pts += 2
        else:
            findings.append(finding("info", "No TLS-RPT (SMTP TLS reporting) record found",
                                     "Publish a _smtp._tls.<domain> TXT record (v=TLSRPTv1) so you "
                                     "get reports when a sender can't establish TLS to your mail "
                                     "servers."))

    return pts, max_pts, findings


# --------------------------------------------------------------------------
# Web / TLS
# --------------------------------------------------------------------------
def _parse_max_age(hsts_value: str) -> int | None:
    m = re.search(r"max-age\s*=\s*(\d+)", hsts_value or "", re.I)
    return int(m.group(1)) if m else None


def _redirects_to_https(http_noredir: dict):
    """Does plaintext :80 force a redirect to HTTPS? Reads the actual 3xx +
    Location from a non-following fetch instead of guessing from page sizes.
    True  = :80 redirects to an https URL.
    False = :80 answers 2xx with content (served in the clear, no redirect).
    None  = nothing answered on :80, so there's nothing to grade (which is fine)."""
    if not http_noredir.get("ok"):
        return None
    status = http_noredir.get("status")
    loc = ((http_noredir.get("headers") or {}).get("location", "") or "").strip().lower()
    if status in (301, 302, 303, 307, 308):
        return loc.startswith("https://")
    if isinstance(status, int) and 200 <= status < 300:
        return False
    return None


def _score_web(https_res: dict, http_res: dict) -> tuple[int, int, list, dict]:
    max_pts, pts, findings = 40, 0, []
    headers = https_res.get("headers", {}) if https_res.get("ok") else {}

    if https_res.get("ok"):
        pts += 6
        hsts = headers.get("strict-transport-security")
        if hsts:
            max_age = _parse_max_age(hsts)
            if max_age and max_age >= 15552000:
                pts += 8
            else:
                pts += 4
                findings.append(finding("low", f"HSTS max-age is short ({max_age or '?'}s)",
                                         "Raise to at least 15552000 (180 days), ideally 31536000 "
                                         "with includeSubDomains; preload."))
        else:
            findings.append(finding("high", "No Strict-Transport-Security (HSTS) header",
                                     "Add Strict-Transport-Security: max-age=31536000; "
                                     "includeSubDomains; preload once every subdomain supports HTTPS."))

        csp = headers.get("content-security-policy")
        if csp:
            pts += 8
        else:
            findings.append(finding("medium", "No Content-Security-Policy header",
                                     "Add a CSP to reduce XSS / data-injection blast radius."))

        if headers.get("x-frame-options") or "frame-ancestors" in (csp or ""):
            pts += 4
        else:
            findings.append(finding("medium", "No clickjacking protection (X-Frame-Options / frame-ancestors)",
                                     "Add X-Frame-Options: DENY or a CSP frame-ancestors directive."))

        if (headers.get("x-content-type-options") or "").lower() == "nosniff":
            pts += 4
        else:
            findings.append(finding("low", "Missing X-Content-Type-Options: nosniff",
                                     "Add it to stop MIME-sniffing based attacks."))

        if headers.get("referrer-policy"):
            pts += 4
        else:
            findings.append(finding("low", "No Referrer-Policy header",
                                     "Add e.g. strict-origin-when-cross-origin to limit referrer leakage."))

        if headers.get("permissions-policy"):
            pts += 3
        else:
            findings.append(finding("info", "No Permissions-Policy header",
                                     "Optional hardening — restrict browser features you don't use "
                                     "(camera, geolocation, etc)."))
    else:
        findings.append(finding("high", "HTTPS not reachable",
                                 https_res.get("error", "site did not respond over HTTPS")))

    redirects = _redirects_to_https(http_res)
    if redirects is True:
        pts += 3
    elif redirects is False:
        findings.append(finding("medium", "HTTP does not appear to redirect to HTTPS",
                                 "Force a redirect from :80 to :443 so plaintext requests aren't served."))
    # redirects is None -> can't tell (e.g. nothing on :80 at all, which is itself fine)

    banner = {
        "server": headers.get("server"),
        "x_powered_by": headers.get("x-powered-by"),
    }
    return pts, max_pts, findings, banner


# --------------------------------------------------------------------------
# TLS certificate — a direct handshake, not an HTTP fetch
#
# common.fetch speaks HTTP over a guarded socket; grabbing the leaf cert needs
# a raw TLS ClientHello with nothing behind it, so we can't route this through
# fetch(). It gets the same SSRF treatment by hand: host_is_public() gate
# before the socket ever opens, hard timeout, and every failure mode (DNS,
# refused, handshake, bad chain) caught so a dead/hostile target degrades the
# report instead of crashing it.
# --------------------------------------------------------------------------
def _parse_cert_time(s: str) -> datetime | None:
    try:
        return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _decode_cert_pem(pem: str) -> dict:
    """Parse a PEM cert into the dict shape getpeercert() returns, without the
    cert having to validate. getpeercert() returns {} on an unverified socket,
    so an expired/self-signed/mismatched cert would otherwise be invisible — we
    decode it ourselves via the stdlib ssl module's own certificate decoder."""
    import os
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return {}
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def _host_matches_cert(domain: str, subject_cn: str | None, sans: list[str]) -> bool:
    names = [n.lower() for n in sans]
    if subject_cn:
        names.append(subject_cn.lower())
    d = domain.lower()
    for n in names:
        if n == d:
            return True
        if n.startswith("*.") and "." in d and d.split(".", 1)[1] == n[2:]:
            return True  # wildcard covers exactly one left-most label
    return False


def _tls_cert(domain: str, timeout: float = 5.0) -> dict:
    # Resolve once and connect to the validated IP literal, not the hostname —
    # otherwise the tool re-resolves and a DNS rebind (short TTL, alternating
    # records) could bounce this raw TLS connection at loopback/RFC1918 after
    # the public check passed. Same pin-the-resolved-IP defense common.fetch()
    # uses; SNI + cert validation still key off the hostname.
    try:
        ips = common.resolve_public_ips(domain)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    if not ips:
        return {"ok": False, "error": "host did not resolve to a public address"}

    trusted = False
    verify_error = None
    protocol = cipher = None
    cert: dict | None = None
    # 1) A verifying handshake first — this is what tells us whether a real
    # browser will trust the chain (and, implicitly, that it isn't expired or
    # name-mismatched).
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ips[0], 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
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
        # Connection-level failure: nothing listening / no TLS at all. No cert.
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    # 2) If it didn't validate, connect again WITHOUT verification so we can
    # still read the leaf and report exactly why it's bad (this is the whole
    # point — an expired/self-signed cert must show up as a finding, not vanish).
    if not cert:
        try:
            uctx = ssl._create_unverified_context()
            with socket.create_connection((ips[0], 443), timeout=timeout) as sock:
                with uctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    protocol = protocol or ssock.version()
                    c = ssock.cipher()
                    cipher = cipher or (c[0] if c else None)
            cert = _decode_cert_pem(ssl.DER_cert_to_PEM_cert(der)) if der else {}
        except Exception as e:  # noqa: BLE001 — degrade instead of crashing the report
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    cert = cert or {}
    issuer = dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else {}
    subject = dict(x[0] for x in cert.get("subject", [])) if cert.get("subject") else {}
    sans = sorted({v for k, v in cert.get("subjectAltName", []) if k == "DNS"})
    not_after_raw = cert.get("notAfter", "")
    not_after = _parse_cert_time(not_after_raw)
    days_left = (not_after - datetime.now(timezone.utc)).days if not_after else None
    subject_cn = subject.get("commonName")

    return {
        "ok": True,
        "trusted": trusted,
        "verify_error": verify_error,
        "self_signed": bool(subject) and subject == issuer,
        "hostname_ok": (_host_matches_cert(domain, subject_cn, sans)
                        if (subject_cn or sans) else None),
        "protocol": protocol,
        "cipher": cipher,
        "issuer": issuer.get("organizationName") or issuer.get("commonName") or "unknown",
        "subject_cn": subject_cn,
        "not_after": not_after_raw,
        "days_left": days_left,
        "sans": sans[:25],
    }


def _score_tls(tls: dict) -> tuple[int, int, list]:
    max_pts, findings = 8, []
    if not tls.get("ok"):
        findings.append(finding("high", "Could not complete a TLS handshake on :443",
                                 f"{tls.get('error', 'connection failed')} — confirm the cert chain is "
                                 "complete and the host isn't blocking automated clients."))
        return 0, max_pts, findings

    days_left = tls.get("days_left")
    expired = days_left is not None and days_left < 0

    # A cert a browser won't accept is broken — name the reason and score it at
    # the floor, regardless of how many days are left on it. Each failure mode
    # is reported once, worst first.
    if tls.get("self_signed"):
        findings.append(finding("high", "TLS certificate is self-signed",
                                 "Browsers reject it with a hard, unskippable warning. Get a cert from a "
                                 "public CA — Let's Encrypt is free and automatable."))
        return 0, max_pts, findings
    if expired:
        findings.append(finding("high", f"TLS certificate expired {-days_left} day(s) ago",
                                 "Renew immediately — an expired cert breaks every browser connection "
                                 "with a hard, unskippable warning."))
        return 0, max_pts, findings
    if tls.get("hostname_ok") is False:
        findings.append(finding("high", "TLS certificate does not cover this hostname",
                                 "The certificate's names don't include this domain, so browsers show a "
                                 "name-mismatch warning. Reissue with the correct SAN(s)."))
        return 0, max_pts, findings
    if not tls.get("trusted"):
        ve = tls.get("verify_error") or "chain did not validate"
        findings.append(finding("high", "TLS certificate chain does not validate",
                                 f"{ve} — install the full chain (leaf + intermediates) so clients don't "
                                 "reject it."))
        return 1, max_pts, findings  # reachable and speaks TLS, but untrusted

    # Trusted, name matches, not expired — grade on remaining lifetime.
    if days_left is None:
        findings.append(finding("info", "Could not read the TLS certificate's expiry date", ""))
        return 6, max_pts, findings
    if days_left < 14:
        findings.append(finding("medium", f"TLS certificate expires in {days_left} day(s)",
                                 "Renew now. If this is unexpected, check ACME/auto-renewal is actually "
                                 "running — it should renew well before this point."))
        return 6, max_pts, findings
    return 8, max_pts, findings


# --------------------------------------------------------------------------
# CAA record — who's allowed to issue certs for this domain
# --------------------------------------------------------------------------
def _check_caa(domain: str) -> dict:
    try:
        recs = _dns(domain, "CAA")
    except common.DNSUnavailable:
        return {"present": False, "records": [], "available": False}
    return {"present": bool(recs), "records": sorted({(r.get("data") or "").strip() for r in recs if r.get("data")})}


def _score_caa(caa: dict) -> tuple[int, int, list]:
    if not caa.get("available", True):
        return 0, 0, []   # DNS outage: excluded from numerator AND denominator (see assess() info finding)
    max_pts, pts, findings = 3, 0, []
    if caa["present"]:
        pts = 3
    else:
        findings.append(finding("low", "No CAA record found",
                                 "Publish a CAA record (e.g. `example.com. CAA 0 issue \"letsencrypt.org\"`) "
                                 "so only your chosen CA(s) can issue certificates for this domain — "
                                 "without one, any public CA can."))
    return pts, max_pts, findings


# --------------------------------------------------------------------------
# /.well-known/security.txt (RFC 9116) — is there an authorized report channel
# --------------------------------------------------------------------------
def _check_security_txt(domain: str) -> dict:
    res = _fetch(f"https://{domain}/.well-known/security.txt", timeout=_SRC_TIMEOUT, max_bytes=20_000)
    present = bool(res.get("ok") and res.get("status") == 200 and res.get("body"))
    return {"present": present, "status": res.get("status") if res.get("ok") else None}


def _score_security_txt(sec: dict) -> tuple[int, int, list]:
    max_pts, pts, findings = 2, 0, []
    if sec["present"]:
        pts = 2
    else:
        findings.append(finding("info", "No /.well-known/security.txt found",
                                 "Publish one per RFC 9116 so researchers have a clear, authorized "
                                 "channel to report vulnerabilities instead of guessing who to email."))
    return pts, max_pts, findings


# --------------------------------------------------------------------------
# DNSSEC — best-effort presence check (DNSKEY/DS), not full chain validation
# --------------------------------------------------------------------------
def _check_dnssec(domain: str) -> dict:
    try:
        dnskey = _dns(domain, "DNSKEY")
        ds = _dns(domain, "DS")
    except common.DNSUnavailable:
        return {"present": False, "available": False}
    return {"present": bool(dnskey or ds)}


def _score_dnssec(dnssec: dict) -> tuple[int, int, list]:
    if not dnssec.get("available", True):
        return 0, 0, []   # DNS outage: excluded from the grade (see assess() info finding)
    max_pts, pts, findings = 5, 0, []
    if dnssec["present"]:
        pts = 5
    else:
        findings.append(finding("info", "No DNSSEC (DNSKEY/DS) records found",
                                 "Consider enabling DNSSEC at your registrar/DNS provider — it stops "
                                 "off-path attackers from forging DNS answers for this domain."))
    return pts, max_pts, findings


# --------------------------------------------------------------------------
# Attack surface — crt.sh + Shodan InternetDB
# --------------------------------------------------------------------------
def _crtsh_subdomains(domain: str) -> dict:
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    res = _fetch(url, timeout=_SRC_TIMEOUT, max_bytes=3_000_000)
    if not res.get("ok") or res.get("status") != 200 or not res.get("body"):
        return {"ok": False, "error": res.get("error") or f"http {res.get('status')}",
                "count": None, "sample": []}
    names = set()
    body_text = res["body"].decode("utf-8", "replace")
    try:
        rows = json.loads(body_text)
    except json.JSONDecodeError:
        rows = []
        for line in body_text.splitlines():
            line = line.strip().strip(",")
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    for row in rows:
        for n in (row.get("name_value") or "").split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n and n.endswith(domain.lower()):
                names.add(n)
    return {"ok": True, "count": len(names), "sample": sorted(names)[:15]}


def _shodan_internetdb(ip: str | None) -> dict:
    if not ip:
        return {"ok": False, "error": "no apex IP resolved", "ports": [], "cves": [], "tags": [], "hostnames": []}
    res = _fetch(f"https://internetdb.shodan.io/{ip}", timeout=_SRC_TIMEOUT)
    if not res.get("ok"):
        return {"ok": False, "error": res.get("error"), "ports": [], "cves": [], "tags": [], "hostnames": []}
    if res.get("status") == 404:
        return {"ok": True, "ports": [], "cves": [], "tags": [], "hostnames": [], "note": "ip not indexed by shodan"}
    if res.get("status") != 200 or not res.get("body"):
        return {"ok": False, "error": f"http {res.get('status')}", "ports": [], "cves": [], "tags": [], "hostnames": []}
    try:
        data = json.loads(res["body"].decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return {"ok": False, "error": "bad json", "ports": [], "cves": [], "tags": [], "hostnames": []}
    return {"ok": True, "ports": data.get("ports", []), "cves": data.get("vulns", []),
            "tags": data.get("tags", []), "hostnames": data.get("hostnames", [])}


def _score_attack_surface(subdomains: dict, shodan: dict) -> tuple[int, int, list]:
    # NB: max_pts is built up from the sources that actually answered. A source
    # outage must NOT read as a clean surface — an unreachable Shodan lookup is
    # excluded from BOTH numerator and denominator rather than scored 20/20.
    findings: list = []
    pts = max_pts = 0

    # crt.sh subdomains — informational only, contributes no points either way.
    if subdomains.get("ok") and subdomains.get("count") is not None:
        c = subdomains["count"]
        if c > 200:
            findings.append(finding("info", f"{c} distinct subdomains seen in certificate-transparency logs",
                                     "Large surface — worth an inventory pass to confirm every "
                                     "subdomain is still owned, needed, and patched."))
    elif not subdomains.get("ok"):
        findings.append(finding("info", "Certificate-transparency lookup (crt.sh) unavailable",
                                 f"{subdomains.get('error', 'source did not respond')} — retry later, "
                                 "crt.sh rate-limits aggressively."))

    # Shodan InternetDB — the graded portion, worth 20, but only when the lookup
    # succeeded (a 404 = indexed-and-clean still counts; an error does not).
    if shodan.get("ok"):
        max_pts += 20
        pts += 20
        cves = shodan.get("cves") or []
        ports = shodan.get("ports") or []
        if cves:
            pts -= min(14, 4 * len(cves))
            findings.append(finding("high", f"{len(cves)} known CVE(s) tagged against the apex IP",
                                     "; ".join(cves[:8])))
        risky_ports = [p for p in ports if p not in (80, 443)]
        if risky_ports:
            pts -= min(6, len(risky_ports))
            findings.append(finding("medium", f"Non-web ports open on the apex IP: {risky_ports}",
                                     "Confirm each is intentional and reachable only from where it "
                                     "needs to be."))
        pts = max(0, pts)
    elif shodan.get("error") == "no apex IP resolved":
        findings.append(finding("info", "Apex has no A/AAAA record, so exposed ports/CVEs couldn't be checked",
                                 "This section is omitted from the grade."))
    elif shodan.get("error"):
        findings.append(finding("info", "Shodan InternetDB lookup unavailable — attack surface not graded",
                                 f"{shodan.get('error')}. Excluded from the score rather than assumed "
                                 "clean, so an outage can't inflate the grade."))

    return pts, max_pts, findings


# --------------------------------------------------------------------------
# grading
# --------------------------------------------------------------------------
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _grade(total: int, max_total: int) -> tuple[str, float]:
    pct = round(100 * total / max_total, 1) if max_total else 0.0
    if pct >= 90:
        g = "A"
    elif pct >= 80:
        g = "B"
    elif pct >= 65:
        g = "C"
    elif pct >= 50:
        g = "D"
    else:
        g = "F"
    return g, pct


# --------------------------------------------------------------------------
# grade-diff — compare against the most recent PRIOR dated report on disk
#
# Reports are written date-stamped (domain-YYYYMMDD.md/.html), one per domain
# per day. diff() looks for the newest one strictly before `before` (default
# today) and pulls grade+score back out of its Markdown — no separate JSON
# index to keep in sync, the .md we already write is the source of truth.
# --------------------------------------------------------------------------
_REPORT_STAMP_RE = re.compile(r"^(?P<slug>.+)-(?P<date>\d{8})\.md$")
_REPORT_GRADE_RE = re.compile(r"Grade \*\*([A-F])\*\* \(([\d.]+)%")


def _prior_report_files(domain: str, out_dir: Path) -> list[tuple[str, Path]]:
    """[(YYYYMMDD, path), ...] ascending, every previously-written .md report
    for this domain (matched by slug, so foo.com and foo-com don't collide)."""
    slug = _slug(domain)
    out = []
    if not out_dir.is_dir():
        return out
    for p in out_dir.glob(f"{slug}-*.md"):
        m = _REPORT_STAMP_RE.match(p.name)
        if m and m.group("slug") == slug:
            out.append((m.group("date"), p))
    out.sort(key=lambda t: t[0])
    return out


def diff(domain: str, out_dir: Path = REPORTS_DIR, *, before: str | None = None) -> dict | None:
    """Grade/score of the most recent report for `domain` dated strictly
    before `before` (default: today, YYYYMMDD). None if there's no prior
    report. Reusable standalone — this is what the dormant fulfillment-rescan
    skill calls to see whether a tracked domain's grade moved since last time.
    """
    domain = _safe_domain(domain)
    if not domain:
        return None
    cutoff = before or datetime.now(timezone.utc).strftime("%Y%m%d")
    priors = [(d, p) for d, p in _prior_report_files(domain, out_dir) if d < cutoff]
    if not priors:
        return None
    date, path = priors[-1]
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = _REPORT_GRADE_RE.search(text)
    if not m:
        return None
    return {"grade": m.group(1), "score_pct": float(m.group(2)),
            "date": f"{date[0:4]}-{date[4:6]}-{date[6:8]}"}


# --------------------------------------------------------------------------
# main entry point
#
# Score weights (kept deliberately small relative to the existing categories so
# an already-good site's grade barely moves and a genuinely absent control still
# shows up as a real, visible deduction):
#   email (30, up to 36): SPF 12, DMARC up to 18, DKIM hint informational only,
#     + MTA-STS 4 + TLS-RPT 2 — but the last two are graded ONLY for a domain
#     with MX (they protect inbound mail), so a no-mail domain's email max stays
#     30 and the two signals never penalize it.
#   web (53 = 40 existing + 13 new): HSTS/CSP/X-Frame/nosniff/Referrer/
#     Permissions-Policy/redirect (40) + TLS cert health (8) + CAA (3) +
#     security.txt (2)
#   attack_surface (up to 25): Shodan InternetDB (20, ONLY when the lookup
#     answered — excluded from the total on an outage so it can't inflate the
#     grade) + DNSSEC presence (5); crt.sh subdomains are informational.
# The max is therefore not fixed — it's the sum of the sections that actually
# ran, so the grade always reflects what was measured, never what was assumed.
# --------------------------------------------------------------------------
def assess(domain: str) -> dict:
    domain = _safe_domain(domain)
    started = datetime.now(timezone.utc)
    if not domain:
        raise ValueError("empty domain")

    # DNS first — apex IP and MX presence gate the Shodan/email logic below.
    dns_section = _collect_dns(domain)
    mx_present = bool(dns_section.get("MX"))
    apex_ip = _apex_ip(dns_section)

    # Every remaining source is an independent network call. Fan them out so an
    # assessment takes about as long as its slowest source, not the sum of all
    # of them. Each collector already degrades to a result dict on failure
    # (never raises), so a dead/slow source can't sink the pool — and the
    # scoring below stays serial + deterministic on the collected results.
    collectors = {
        "spf": lambda: _check_spf(domain),
        "dmarc": lambda: _check_dmarc(domain),
        "dkim": lambda: _check_dkim_hint(domain),
        "https": lambda: _fetch(f"https://{domain}"),
        # Non-following on purpose: we want to SEE whether :80 issues a 3xx to
        # https, not land on the final page and guess.
        "http": lambda: _fetch(f"http://{domain}", follow_redirects=False),
        "tls": lambda: _tls_cert(domain),
        "caa": lambda: _check_caa(domain),
        "sec_txt": lambda: _check_security_txt(domain),
        "dnssec": lambda: _check_dnssec(domain),
        "subdomains": lambda: _crtsh_subdomains(domain),
        "shodan": lambda: _shodan_internetdb(apex_ip),
    }
    # MTA-STS + TLS-RPT only matter for a domain that receives mail, so they're
    # only fetched when there's an MX — no wasted outbound (one HTTPS + one TXT)
    # for a no-mail domain, and `.get(...)` below yields None so scoring skips
    # them cleanly.
    if mx_present:
        collectors["mtasts"] = lambda: _check_mtasts(domain)
        collectors["tlsrpt"] = lambda: _check_tlsrpt(domain)
    with ThreadPoolExecutor(max_workers=len(collectors)) as ex:
        futures = {k: ex.submit(fn) for k, fn in collectors.items()}
        r = {k: f.result() for k, f in futures.items()}

    spf, dmarc, dkim = r["spf"], r["dmarc"], r["dkim"]
    https_res, http_res, tls = r["https"], r["http"], r["tls"]
    caa, sec_txt, dnssec = r["caa"], r["sec_txt"], r["dnssec"]
    subdomains, shodan = r["subdomains"], r["shodan"]
    mtasts, tlsrpt = r.get("mtasts"), r.get("tlsrpt")

    email_pts, email_max, email_findings = _score_email(spf, dmarc, dkim, mx_present, mtasts, tlsrpt)

    web_pts, web_max, web_findings, banner = _score_web(https_res, http_res)
    tls_pts, tls_max, tls_findings = _score_tls(tls)
    caa_pts, caa_max, caa_findings = _score_caa(caa)
    sec_pts, sec_max, sec_findings = _score_security_txt(sec_txt)
    web_pts += tls_pts + caa_pts + sec_pts
    web_max += tls_max + caa_max + sec_max
    web_findings = web_findings + tls_findings + caa_findings + sec_findings

    surf_pts, surf_max, surf_findings = _score_attack_surface(subdomains, shodan)
    dnssec_pts, dnssec_max, dnssec_findings = _score_dnssec(dnssec)
    surf_pts += dnssec_pts
    surf_max += dnssec_max
    surf_findings = surf_findings + dnssec_findings

    total_pts = email_pts + web_pts + surf_pts
    max_pts = email_max + web_max + surf_max
    grade, pct = _grade(total_pts, max_pts)

    all_findings = email_findings + web_findings + surf_findings
    # Any DNS-derived signal whose lookup FAILED (vs genuinely absent) was left
    # out of the grade by the scorers above; say so once, honestly, instead of
    # emitting a deflated grade with fabricated "record missing" findings.
    dns_down = [n for n, chk in (("SPF", spf), ("DMARC", dmarc), ("CAA", caa),
                                 ("DNSSEC", dnssec)) if not chk.get("available", True)]
    if not dns_section.get("available", True):
        dns_down.insert(0, "DNS records")
    if dns_down:
        all_findings.append(finding("info", "Some DNS lookups did not complete",
            f"{', '.join(dns_down)} could not be resolved (the DNS/DoH lookup did not answer). "
            "Those checks were left out of the grade rather than counted as failing — re-run "
            "when DNS is reachable for a complete assessment."))
    all_findings.sort(key=lambda f: _SEV_ORDER.get(f["severity"], 9))

    report = {
        "domain": domain,
        "generated_at": started.isoformat(),
        "grade": grade,
        "score_pct": pct,
        "score_breakdown": {
            "email": {"points": email_pts, "max": email_max},
            "web": {"points": web_pts, "max": web_max},
            "attack_surface": {"points": surf_pts, "max": surf_max},
            "total": {"points": total_pts, "max": max_pts},
        },
        "findings": all_findings,
        "dns": dns_section,
        "email_security": {"spf": spf, "dmarc": dmarc, "dkim_hint": dkim, "mx_present": mx_present,
                           "mtasts": mtasts, "tlsrpt": tlsrpt},
        "web": {
            "https": {"ok": https_res.get("ok"), "status": https_res.get("status"),
                      "error": https_res.get("error"), "headers": https_res.get("headers", {})},
            "http": {"ok": http_res.get("ok"), "status": http_res.get("status"),
                     "error": http_res.get("error")},
            "redirects_to_https": _redirects_to_https(http_res),
            "banner": banner,
            "tls": tls,
            "caa": caa,
            "security_txt": sec_txt,
        },
        "attack_surface": {
            "apex_ip": apex_ip,
            "subdomains": subdomains,
            "shodan_internetdb": shodan,
            "dnssec": dnssec,
        },
    }

    prev = diff(domain, before=started.strftime("%Y%m%d"))
    if prev:
        report["previous"] = prev
        delta_pct = round(pct - prev["score_pct"], 1)
        direction = "up" if delta_pct > 0 else "down" if delta_pct < 0 else "same"
        report["delta"] = {"score_pct": delta_pct, "grade_direction": direction}

    return report


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------
def _md_safe(value) -> str:
    """Neutralize external content before it enters the Markdown report — so a
    hostile DNS/SPF/DMARC record, HTTP banner, TLS issuer/SAN, or security.txt
    value can't inject markup, form a `[text](url)` Markdown link/image, break
    out of a code span, reopen raw HTML, or add lines (which also blocks
    prompt-injection if the .md is later read by an agent that treats file
    text as instructions). `&`/`[`/`]` matter as much as `<`/`>`/`|` here —
    `[label](javascript:...)` is a working link in most Markdown renderers
    even with angle brackets neutralized, so every bracket/entity character
    that can build one has to go too."""
    s = "".join(ch if ch >= " " else " " for ch in str(value))
    return (s.replace("`", "'").replace("<", "(").replace(">", ")").replace("|", "/")
             .replace("&", "+").replace("[", "(").replace("]", ")"))


_DIRECTION_ARROW = {"up": "▲", "down": "▼", "same": "▬"}


def _mtasts_md(mtasts) -> str:
    if mtasts is None:
        return "not applicable (no MX)"
    if not mtasts.get("present"):
        return "absent"
    return "present (mode=" + _md_safe(mtasts.get("mode") or "unspecified") + ")"


def _tlsrpt_md(tlsrpt) -> str:
    if tlsrpt is None:
        return "not applicable (no MX)"
    return "present" if tlsrpt.get("present") else "absent"


def render_markdown(report: dict) -> str:
    d = report["domain"]
    es = report["email_security"]
    lines = [
        f"# Passive security assessment — {d}",
        "",
        f"Generated {report['generated_at']} · Grade **{report['grade']}** "
        f"({report['score_pct']}%, passive sources only)",
    ]
    prev, delta = report.get("previous"), report.get("delta")
    if prev and delta:
        arrow = _DIRECTION_ARROW.get(delta["grade_direction"], "")
        lines.append(f"Previous: grade **{prev['grade']}** ({prev['score_pct']}%) on {prev['date']} "
                     f"— {arrow} {delta['score_pct']:+.1f}%")
    lines += [
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        lines.append("No findings — every checked signal came back clean.")
    for f in report["findings"]:
        # Neutralize like every other external value in this file: some finding
        # text embeds source data (Shodan CVE ids, the OpenSSL verify_error) that
        # must not inject markup/links/newlines into a client-facing .md.
        lines.append(f"- **[{f['severity'].upper()}]** {_md_safe(f['title'])}")
        if f["recommendation"]:
            lines.append(f"  - {_md_safe(f['recommendation'])}")
    lines += [
        "",
        "## DNS",
        "",
        f"- A: {_md_safe(', '.join(report['dns']['A'])) or 'none'}",
        f"- AAAA: {_md_safe(', '.join(report['dns']['AAAA'])) or 'none'}",
        f"- MX: {_md_safe(', '.join(report['dns']['MX'])) or 'none'}",
        f"- NS: {_md_safe(', '.join(report['dns']['NS'])) or 'none'}",
        "",
        "## Email security",
        "",
        f"- SPF: {'present' if es['spf']['present'] else 'absent'}"
        + (f" — `{_md_safe(es['spf']['record'])}`" if es['spf']['present'] else ""),
        f"- DMARC: {'present, policy=' + _md_safe(es['dmarc']['policy']) if es['dmarc']['present'] else 'absent'}",
        f"- DKIM hint: {'found (selector: ' + _md_safe(es['dkim_hint']['selector']) + ')' if es['dkim_hint']['found'] else 'not detected (common selectors only)'}",
        f"- MTA-STS: {_mtasts_md(es.get('mtasts'))}",
        f"- TLS-RPT: {_tlsrpt_md(es.get('tlsrpt'))}",
        "",
        "## Web / TLS",
        "",
        f"- HTTPS reachable: {report['web']['https']['ok']} (status {report['web']['https']['status']})",
        f"- HTTP -> HTTPS redirect (inferred): {report['web']['redirects_to_https']}",
        f"- Server banner: {_md_safe(report['web']['banner'].get('server')) if report['web']['banner'].get('server') else 'not disclosed'}",
        f"- TLS certificate: {('issuer ' + _md_safe(report['web']['tls'].get('issuer')) + ', ' + str(report['web']['tls'].get('days_left')) + ' day(s) left') if report['web']['tls'].get('ok') else 'handshake failed — ' + _md_safe(report['web']['tls'].get('error'))}",
        f"- CAA record: {'present' if report['web']['caa']['present'] else 'absent'}",
        f"- security.txt: {'present' if report['web']['security_txt']['present'] else 'absent'}",
        "",
        "## Attack surface",
        "",
        f"- Apex IP: {report['attack_surface']['apex_ip'] or 'unresolved'}",
        f"- Subdomains seen in CT logs: {report['attack_surface']['subdomains'].get('count', 'unknown')}",
        f"- Shodan InternetDB open ports: {report['attack_surface']['shodan_internetdb'].get('ports') or 'none/unavailable'}",
        f"- Shodan InternetDB CVEs: {report['attack_surface']['shodan_internetdb'].get('cves') or 'none'}",
        f"- DNSSEC (DNSKEY/DS present): {report['attack_surface']['dnssec']['present']}",
        "",
        "---",
        "*Passive assessment only — no active scanning or exploitation was performed.*",
    ]
    return "\n".join(lines)


_HTML_ESCAPE = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}


def _esc(s) -> str:
    return re.sub(r"[&<>\"']", lambda m: _HTML_ESCAPE[m.group(0)], str(s if s is not None else ""))


def _mtasts_html(mtasts) -> str:
    if mtasts is None:
        return "not applicable (no MX)"
    if not mtasts.get("present"):
        return "absent"
    return "present, mode=" + _esc(mtasts.get("mode") or "unspecified")


_GRADE_COLOR = {"A": "#38d39f", "B": "#8fd339", "C": "#ffb454", "D": "#ff8a3d", "F": "#ff5c72"}
_SEV_COLOR = {"high": "#ff5c72", "medium": "#ffb454", "low": "#4db8ff", "info": "#8a97a8"}


def render_html(report: dict) -> str:
    d = _esc(report["domain"])
    grade = report["grade"]
    color = _GRADE_COLOR.get(grade, "#8a97a8")
    findings_html = "".join(
        f'<div class="finding sev-{f["severity"]}">'
        f'<span class="sev">{_esc(f["severity"].upper())}</span>'
        f'<div><div class="title">{_esc(f["title"])}</div>'
        f'{"<div class=rec>" + _esc(f["recommendation"]) + "</div>" if f["recommendation"] else ""}</div>'
        f'</div>'
        for f in report["findings"]
    ) or "<p>No findings — every checked signal came back clean.</p>"

    dns = report["dns"]
    es = report["email_security"]
    web = report["web"]
    asurf = report["attack_surface"]
    tls = web["tls"]

    prev, delta = report.get("previous"), report.get("delta")
    diff_html = ""
    if prev and delta:
        arrow = _DIRECTION_ARROW.get(delta["grade_direction"], "")
        diff_html = (f'<div class="grade-pct">previous: {_esc(prev["grade"])} ({_esc(prev["score_pct"])}%) '
                    f'on {_esc(prev["date"])} &mdash; {arrow} {delta["score_pct"]:+.1f}%</div>')

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security assessment — {d}</title>
<style>
  :root {{ --bg:#0a0e14; --card:#131a24; --line:#232d3b; --txt:#d6dee8; --dim:#8a97a8; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--txt); font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }}
  .wrap {{ max-width: 880px; margin: 0 auto; padding: 40px 24px 80px; }}
  h1 {{ font-size: 24px; margin: 0 0 6px; }}
  .meta {{ color: var(--dim); font-size: 13px; margin-bottom: 28px; }}
  .grade-box {{ display:flex; align-items:center; gap:22px; background:var(--card); border:1px solid var(--line);
                border-radius:12px; padding:22px 26px; margin-bottom:28px; }}
  .grade-letter {{ font-size:56px; font-weight:800; color:{color}; line-height:1; font-family: ui-monospace,monospace; }}
  .grade-pct {{ color: var(--dim); font-size: 14px; }}
  h2 {{ font-size: 15px; text-transform: uppercase; letter-spacing: .06em; color: var(--dim);
        border-bottom: 1px solid var(--line); padding-bottom: 8px; margin: 30px 0 14px; }}
  .finding {{ display:flex; gap:14px; padding:12px 0; border-bottom:1px solid var(--line); }}
  .finding:last-child {{ border-bottom: none; }}
  .sev {{ flex: none; width: 66px; font-size: 11px; font-weight: 700; letter-spacing:.04em; }}
  .sev-high .sev {{ color: {_SEV_COLOR['high']}; }}
  .sev-medium .sev {{ color: {_SEV_COLOR['medium']}; }}
  .sev-low .sev {{ color: {_SEV_COLOR['low']}; }}
  .sev-info .sev {{ color: {_SEV_COLOR['info']}; }}
  .title {{ font-weight: 600; }}
  .rec {{ color: var(--dim); font-size: 13px; margin-top: 3px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  td, th {{ text-align: left; padding: 6px 10px 6px 0; border-bottom: 1px solid var(--line); }}
  th {{ color: var(--dim); font-weight: 600; width: 220px; }}
  code {{ font-family: ui-monospace, monospace; font-size: 12px; word-break: break-all; }}
  footer {{ margin-top: 40px; color: var(--dim); font-size: 12px; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Passive security assessment — {d}</h1>
  <div class="meta">Generated {_esc(report['generated_at'])} · passive sources only, no active scanning</div>

  <div class="grade-box">
    <div class="grade-letter">{_esc(grade)}</div>
    <div>
      <div class="grade-pct">{report['score_pct']}% weighted score</div>
      <div class="grade-pct">email {report['score_breakdown']['email']['points']}/{report['score_breakdown']['email']['max']}
        &middot; web {report['score_breakdown']['web']['points']}/{report['score_breakdown']['web']['max']}
        &middot; attack surface {report['score_breakdown']['attack_surface']['points']}/{report['score_breakdown']['attack_surface']['max']}</div>
      {diff_html}
    </div>
  </div>

  <h2>Findings</h2>
  {findings_html}

  <h2>DNS</h2>
  <table>
    <tr><th>A</th><td>{_esc(', '.join(dns['A']) or 'none')}</td></tr>
    <tr><th>AAAA</th><td>{_esc(', '.join(dns['AAAA']) or 'none')}</td></tr>
    <tr><th>MX</th><td>{_esc(', '.join(dns['MX']) or 'none')}</td></tr>
    <tr><th>NS</th><td>{_esc(', '.join(dns['NS']) or 'none')}</td></tr>
  </table>

  <h2>Email security</h2>
  <table>
    <tr><th>SPF</th><td>{'present' if es['spf']['present'] else 'absent'}{' — <code>' + _esc(es['spf']['record']) + '</code>' if es['spf']['present'] else ''}</td></tr>
    <tr><th>DMARC</th><td>{('present, policy=' + _esc(es['dmarc']['policy'])) if es['dmarc']['present'] else 'absent'}</td></tr>
    <tr><th>DKIM hint</th><td>{('found (selector: ' + _esc(es['dkim_hint']['selector']) + ')') if es['dkim_hint']['found'] else 'not detected (common selectors only)'}</td></tr>
    <tr><th>MTA-STS</th><td>{_mtasts_html(es.get('mtasts'))}</td></tr>
    <tr><th>TLS-RPT</th><td>{_tlsrpt_md(es.get('tlsrpt'))}</td></tr>
  </table>

  <h2>Web / TLS</h2>
  <table>
    <tr><th>HTTPS reachable</th><td>{web['https']['ok']} (status {_esc(web['https']['status'])})</td></tr>
    <tr><th>HTTP&rarr;HTTPS redirect</th><td>{_esc(web['redirects_to_https'])} (inferred)</td></tr>
    <tr><th>Server banner</th><td>{_esc(web['banner'].get('server') or 'not disclosed')}</td></tr>
    <tr><th>TLS certificate</th><td>{(f"issuer {_esc(tls.get('issuer'))}, {_esc(tls.get('days_left'))} day(s) left") if tls.get('ok') else f"handshake failed &mdash; {_esc(tls.get('error'))}"}</td></tr>
    <tr><th>CAA record</th><td>{'present' if web['caa']['present'] else 'absent'}</td></tr>
    <tr><th>security.txt</th><td>{'present' if web['security_txt']['present'] else 'absent'}</td></tr>
  </table>

  <h2>Attack surface</h2>
  <table>
    <tr><th>Apex IP</th><td>{_esc(asurf['apex_ip'] or 'unresolved')}</td></tr>
    <tr><th>Subdomains (CT logs)</th><td>{_esc(asurf['subdomains'].get('count', 'unknown'))}</td></tr>
    <tr><th>Open ports (Shodan)</th><td>{_esc(asurf['shodan_internetdb'].get('ports') or 'none/unavailable')}</td></tr>
    <tr><th>CVEs (Shodan)</th><td>{_esc(asurf['shodan_internetdb'].get('cves') or 'none')}</td></tr>
    <tr><th>DNSSEC (DNSKEY/DS)</th><td>{asurf['dnssec']['present']}</td></tr>
  </table>

  <footer>Passive assessment only &mdash; no active scanning or exploitation was performed.</footer>
</div>
</body>
</html>"""


def render_pdf(report: dict, html: str, out_path: Path) -> bool:
    try:
        import weasyprint  # type: ignore
    except ImportError:
        return False
    try:
        weasyprint.HTML(string=html).write_pdf(str(out_path))
        return True
    except Exception:
        return False


def write_reports(report: dict, out_dir: Path, *, md: bool = True, html: bool = True,
                   pdf: bool = False) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    base = f"{_slug(report['domain'])}-{stamp}"
    paths = {}

    if md:
        md_path = out_dir / f"{base}.md"
        md_path.write_text(render_markdown(report), encoding="utf-8")
        paths["md"] = md_path

    html_text = None
    if html or pdf:
        html_text = render_html(report)
    if html:
        html_path = out_dir / f"{base}.html"
        html_path.write_text(html_text, encoding="utf-8")
        paths["html"] = html_path

    if pdf:
        pdf_path = out_dir / f"{base}.pdf"
        if render_pdf(report, html_text, pdf_path):
            paths["pdf"] = pdf_path
        else:
            paths["pdf_note"] = "weasyprint not available — PDF skipped (optional dependency)"

    return paths


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _print_summary(report: dict) -> None:
    print(f"\n{report['domain']}  —  grade {report['grade']}  ({report['score_pct']}%)")
    print(f"generated {report['generated_at']}\n")
    if not report["findings"]:
        print("  no findings — every checked signal came back clean")
    for f in report["findings"]:
        print(f"  [{f['severity'].upper():6s}] {f['title']}")
        if f["recommendation"]:
            print(f"           -> {f['recommendation']}")
    print()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Passive OSINT security-assessment report engine.")
    ap.add_argument("domain")
    ap.add_argument("--json", action="store_true", help="print the full report dict as JSON")
    ap.add_argument("--md", action="store_true", help="write a Markdown report")
    ap.add_argument("--html", action="store_true", help="write an HTML report")
    ap.add_argument("--pdf", action="store_true", help="also write a PDF (requires weasyprint; skipped if absent)")
    ap.add_argument("--out", default=str(REPORTS_DIR), help="output directory (default: engine/reports)")
    args = ap.parse_args(argv)

    report = assess(args.domain)

    if args.json:
        print(json.dumps(report, default=str, indent=2))
    else:
        _print_summary(report)

    if args.md or args.html or args.pdf:
        paths = write_reports(report, Path(args.out), md=args.md, html=args.html, pdf=args.pdf)
        for kind, p in paths.items():
            print(f"wrote {kind}: {p}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
