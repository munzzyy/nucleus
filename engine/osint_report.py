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
import sys
import urllib.parse
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
    try:
        return common.dns_query(name, rtype, timeout=_SRC_TIMEOUT)
    except Exception:
        return []


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


def _fetch(url: str, timeout: float = _SRC_TIMEOUT, max_bytes: int = 400_000) -> dict:
    try:
        status, body, headers = common.fetch(url, timeout=timeout, max_bytes=max_bytes)
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
    out = {}
    for rtype in ("A", "AAAA", "MX", "NS"):
        ans = _dns(domain, rtype)
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
    spf_vals = [v for v in _txt_values(domain) if v.lower().startswith("v=spf1")]
    if not spf_vals:
        return {"present": False, "record": None, "valid": False}
    rec = spf_vals[0]
    valid = bool(re.search(r"[-~?+]all\s*$", rec.strip(), re.I)) or "redirect=" in rec.lower()
    return {"present": True, "record": rec, "valid": valid}


def _check_dmarc(domain: str) -> dict:
    vals = [v for v in _txt_values(f"_dmarc.{domain}") if v.lower().startswith("v=dmarc1")]
    if not vals:
        return {"present": False, "record": None, "policy": None}
    rec = vals[0]
    m = re.search(r"p=(\w+)", rec, re.I)
    return {"present": True, "record": rec, "policy": (m.group(1).lower() if m else "none")}


def _check_dkim_hint(domain: str) -> dict:
    for sel in _DKIM_SELECTORS:
        if _dns(f"{sel}._domainkey.{domain}", "TXT"):
            return {"found": True, "selector": sel}
    return {"found": False, "selector": None}


def _score_email(spf: dict, dmarc: dict, dkim: dict, mx_present: bool) -> tuple[int, int, list]:
    max_pts, pts, findings = 30, 0, []

    if spf["present"]:
        pts += 12
        if not spf["valid"]:
            findings.append(finding("medium", "SPF record present but looks malformed",
                                     "Must start with v=spf1 and end in a qualifier (-all/~all/?all)."))
    else:
        sev = "high" if mx_present else "low"
        findings.append(finding(sev, "No SPF record found",
                                 "Publish a TXT record on the apex starting with v=spf1 ... -all "
                                 "to stop mail systems trusting spoofed senders."))

    if dmarc["present"]:
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

    return pts, max_pts, findings


# --------------------------------------------------------------------------
# Web / TLS
# --------------------------------------------------------------------------
def _parse_max_age(hsts_value: str) -> int | None:
    m = re.search(r"max-age\s*=\s*(\d+)", hsts_value or "", re.I)
    return int(m.group(1)) if m else None


def _redirects_to_https(http_res: dict, https_res: dict):
    """Best-effort: common.fetch follows redirects transparently (stdlib urllib), so
    we can't see the 301 itself — only infer from whether the http:// fetch landed
    on the same final resource as the https:// fetch."""
    if not http_res.get("ok") or not https_res.get("ok"):
        return None
    return (http_res.get("status") == 200 and https_res.get("status") == 200
            and http_res.get("body_len") == https_res.get("body_len"))


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

    redirects = _redirects_to_https(http_res, https_res)
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
    max_pts, pts, findings = 20, 20, []

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

    if shodan.get("ok"):
        cves = shodan.get("cves") or []
        ports = shodan.get("ports") or []
        if cves:
            pts -= min(10, 3 * len(cves))
            findings.append(finding("high", f"{len(cves)} known CVE(s) tagged against the apex IP",
                                     "; ".join(cves[:8])))
        risky_ports = [p for p in ports if p not in (80, 443)]
        if risky_ports:
            pts -= min(6, len(risky_ports))
            findings.append(finding("medium", f"Non-web ports open on the apex IP: {risky_ports}",
                                     "Confirm each is intentional and reachable only from where it "
                                     "needs to be."))
    elif shodan.get("error") and shodan.get("error") != "no apex IP resolved":
        findings.append(finding("info", "Shodan InternetDB lookup unavailable", shodan.get("error")))

    return max(0, pts), max_pts, findings


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
# main entry point
# --------------------------------------------------------------------------
def assess(domain: str) -> dict:
    domain = _safe_domain(domain)
    started = datetime.now(timezone.utc)
    if not domain:
        raise ValueError("empty domain")

    dns_section = _collect_dns(domain)
    mx_present = bool(dns_section.get("MX"))

    spf = _check_spf(domain)
    dmarc = _check_dmarc(domain)
    dkim = _check_dkim_hint(domain)
    email_pts, email_max, email_findings = _score_email(spf, dmarc, dkim, mx_present)

    https_res = _fetch(f"https://{domain}")
    http_res = _fetch(f"http://{domain}")
    web_pts, web_max, web_findings, banner = _score_web(https_res, http_res)

    apex_ip = _apex_ip(dns_section)
    subdomains = _crtsh_subdomains(domain)
    shodan = _shodan_internetdb(apex_ip)
    surf_pts, surf_max, surf_findings = _score_attack_surface(subdomains, shodan)

    total_pts = email_pts + web_pts + surf_pts
    max_pts = email_max + web_max + surf_max
    grade, pct = _grade(total_pts, max_pts)

    all_findings = email_findings + web_findings + surf_findings
    all_findings.sort(key=lambda f: _SEV_ORDER.get(f["severity"], 9))

    return {
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
        "email_security": {"spf": spf, "dmarc": dmarc, "dkim_hint": dkim, "mx_present": mx_present},
        "web": {
            "https": {"ok": https_res.get("ok"), "status": https_res.get("status"),
                      "error": https_res.get("error"), "headers": https_res.get("headers", {})},
            "http": {"ok": http_res.get("ok"), "status": http_res.get("status"),
                     "error": http_res.get("error")},
            "redirects_to_https": _redirects_to_https(http_res, https_res),
            "banner": banner,
        },
        "attack_surface": {
            "apex_ip": apex_ip,
            "subdomains": subdomains,
            "shodan_internetdb": shodan,
        },
    }


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------
def _md_safe(value) -> str:
    """Neutralize external content before it enters the Markdown report — so a
    hostile DNS/SPF/DMARC record or HTTP banner can't inject markup, break out of
    a code span, or add lines (which also blocks prompt-injection if the .md is
    later read by an agent that treats file text as instructions)."""
    s = "".join(ch if ch >= " " else " " for ch in str(value))
    return s.replace("`", "'").replace("<", "(").replace(">", ")").replace("|", "/")


def render_markdown(report: dict) -> str:
    d = report["domain"]
    lines = [
        f"# Passive security assessment — {d}",
        "",
        f"Generated {report['generated_at']} · Grade **{report['grade']}** "
        f"({report['score_pct']}%, passive sources only)",
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        lines.append("No findings — every checked signal came back clean.")
    for f in report["findings"]:
        lines.append(f"- **[{f['severity'].upper()}]** {f['title']}")
        if f["recommendation"]:
            lines.append(f"  - {f['recommendation']}")
    lines += [
        "",
        "## DNS",
        "",
        f"- A: {', '.join(report['dns']['A']) or 'none'}",
        f"- AAAA: {', '.join(report['dns']['AAAA']) or 'none'}",
        f"- MX: {_md_safe(', '.join(report['dns']['MX'])) or 'none'}",
        f"- NS: {_md_safe(', '.join(report['dns']['NS'])) or 'none'}",
        "",
        "## Email security",
        "",
        f"- SPF: {'present' if report['email_security']['spf']['present'] else 'absent'}"
        + (f" — `{_md_safe(report['email_security']['spf']['record'])}`" if report['email_security']['spf']['present'] else ""),
        f"- DMARC: {'present, policy=' + _md_safe(report['email_security']['dmarc']['policy']) if report['email_security']['dmarc']['present'] else 'absent'}",
        f"- DKIM hint: {'found (selector: ' + _md_safe(report['email_security']['dkim_hint']['selector']) + ')' if report['email_security']['dkim_hint']['found'] else 'not detected (common selectors only)'}",
        "",
        "## Web / TLS",
        "",
        f"- HTTPS reachable: {report['web']['https']['ok']} (status {report['web']['https']['status']})",
        f"- HTTP -> HTTPS redirect (inferred): {report['web']['redirects_to_https']}",
        f"- Server banner: {_md_safe(report['web']['banner'].get('server')) if report['web']['banner'].get('server') else 'not disclosed'}",
        "",
        "## Attack surface",
        "",
        f"- Apex IP: {report['attack_surface']['apex_ip'] or 'unresolved'}",
        f"- Subdomains seen in CT logs: {report['attack_surface']['subdomains'].get('count', 'unknown')}",
        f"- Shodan InternetDB open ports: {report['attack_surface']['shodan_internetdb'].get('ports') or 'none/unavailable'}",
        f"- Shodan InternetDB CVEs: {report['attack_surface']['shodan_internetdb'].get('cves') or 'none'}",
        "",
        "---",
        "*Passive assessment only — no active scanning or exploitation was performed.*",
    ]
    return "\n".join(lines)


_HTML_ESCAPE = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}


def _esc(s) -> str:
    return re.sub(r"[&<>\"']", lambda m: _HTML_ESCAPE[m.group(0)], str(s if s is not None else ""))


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
  </table>

  <h2>Web / TLS</h2>
  <table>
    <tr><th>HTTPS reachable</th><td>{web['https']['ok']} (status {_esc(web['https']['status'])})</td></tr>
    <tr><th>HTTP&rarr;HTTPS redirect</th><td>{_esc(web['redirects_to_https'])} (inferred)</td></tr>
    <tr><th>Server banner</th><td>{_esc(web['banner'].get('server') or 'not disclosed')}</td></tr>
  </table>

  <h2>Attack surface</h2>
  <table>
    <tr><th>Apex IP</th><td>{_esc(asurf['apex_ip'] or 'unresolved')}</td></tr>
    <tr><th>Subdomains (CT logs)</th><td>{_esc(asurf['subdomains'].get('count', 'unknown'))}</td></tr>
    <tr><th>Open ports (Shodan)</th><td>{_esc(asurf['shodan_internetdb'].get('ports') or 'none/unavailable')}</td></tr>
    <tr><th>CVEs (Shodan)</th><td>{_esc(asurf['shodan_internetdb'].get('cves') or 'none')}</td></tr>
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
