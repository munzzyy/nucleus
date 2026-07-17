"""Assessment playbooks — named, ordered recipes over the tools that already
exist here. A playbook is pure DATA: a list of steps, each naming an existing
safe-runner key (or the native web-analyze) plus its options. This module
executes NOTHING. The frontend walks the steps and runs each one through the
same gated endpoint it would use by hand (/api/run, /api/web-analyze), so a
playbook can't do anything a single manual run couldn't, and every step still
passes the full authorization + scope + no-shell gate on its own.

The point is user-friendliness: "assess this website" is one click that runs
the right five tools in the right order and collects the findings, instead of
remembering which tool to run and retyping the target five times.

`target_kind` tells the UI what to ask for (a URL vs a bare domain/host) and
which steps to skip when the target isn't the right shape for them.
"""

from __future__ import annotations

from shared import common


# Each step: kind is "web-analyze" (native, POST /api/web-analyze) or "runner"
# (POST /api/run with `tool`). options is passed straight through to /api/run.
# `optional` steps are ones the UI pre-unchecks because they're slow or need a
# less-common tool installed — the user opts in.
PLAYBOOKS: list[dict] = [
    {
        "key": "web-quick",
        "name": "Website quick assessment",
        "target_kind": "url",
        "desc": "The five-minute first look at a web target: native header/cookie/CORS "
                "grade, tech fingerprint, live HTTP probe, and TLS posture. All passive, "
                "nothing installed-heavy.",
        "steps": [
            {"kind": "web-analyze", "label": "Security headers, cookies & CORS",
             "note": "native — no external tool needed"},
            {"kind": "secret-scan", "label": "Leaked API keys / secrets in page + JS",
             "note": "native — scans the site's own HTML and JS bundles"},
            {"kind": "runner", "tool": "whatweb", "label": "Technology fingerprint"},
            {"kind": "runner", "tool": "httpx", "label": "HTTP probe (status/title/tech)"},
            {"kind": "runner", "tool": "sslscan", "label": "TLS/cipher posture"},
        ],
    },
    {
        "key": "web-deep",
        "name": "Website deep assessment",
        "target_kind": "url",
        "desc": "Everything in the quick pass, then WAF detection and the heavier vuln "
                "scanners. Slower (nuclei + nikto can each take minutes) — run it once the "
                "quick pass says the target is worth it.",
        "steps": [
            {"kind": "web-analyze", "label": "Security headers, cookies & CORS"},
            {"kind": "secret-scan", "label": "Leaked API keys / secrets in page + JS"},
            {"kind": "runner", "tool": "whatweb", "label": "Technology fingerprint"},
            {"kind": "runner", "tool": "wafw00f", "label": "WAF detection"},
            {"kind": "runner", "tool": "sslscan", "label": "TLS/cipher posture"},
            {"kind": "runner", "tool": "nuclei", "label": "Template vuln scan (CVEs + exposures)",
             "options": {"tags": "cves", "rate": "10"}},
            {"kind": "runner", "tool": "nikto", "label": "Web server misconfig scan", "optional": True},
        ],
    },
    {
        "key": "recon-domain",
        "name": "Domain recon",
        "target_kind": "host",
        "desc": "Map a domain's footprint: passive subdomains, DNS records, and a WHOIS "
                "pull. Feed the subdomains you find back into a website assessment.",
        "steps": [
            {"kind": "runner", "tool": "subfinder", "label": "Passive subdomain enumeration"},
            {"kind": "runner", "tool": "dnsenum", "label": "DNS / zone-transfer enum"},
            {"kind": "runner", "tool": "whois", "label": "WHOIS registration"},
        ],
    },
    {
        "key": "tls-audit",
        "name": "TLS/SSL audit",
        "target_kind": "host",
        "desc": "Two independent reads of the certificate and cipher configuration, so a "
                "weak protocol or cipher shows up in at least one.",
        "steps": [
            {"kind": "runner", "tool": "sslscan", "label": "sslscan cipher/cert check"},
            {"kind": "runner", "tool": "testssl", "label": "testssl.sh deep posture"},
        ],
    },
    {
        "key": "content-discovery",
        "name": "Web content discovery",
        "target_kind": "url",
        "desc": "Brute-force hidden directories and files. Needs a wordlist — the UI will "
                "ask; a good default is Discovery/Web-Content/common.txt.",
        "needs_wordlist": True,
        "steps": [
            {"kind": "runner", "tool": "ffuf", "label": "Directory/file fuzz", "needs_wordlist": True},
        ],
    },
]

_BY_KEY = {p["key"]: p for p in PLAYBOOKS}


def catalog() -> list[dict]:
    return PLAYBOOKS


def handle_playbooks(req) -> "common.Response":
    """GET /api/playbooks -> {playbooks:[...]}. Static recipe data; the browser
    executes each step through the already-gated /api/run and /api/web-analyze,
    so there is nothing to gate or execute here."""
    return common.Response.json({"playbooks": catalog()})
