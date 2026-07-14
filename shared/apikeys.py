#!/usr/bin/env python3
"""OSINT API-key catalog + reader — the single source of truth for keys.

Recon works fully keyless, but a handful of free-tier API keys unlock a lot more
data. This module lists the keys Nucleus knows how to use (so the hub Settings
panel can render a slot + signup link for each), and reads them from the
environment or the gitignored `var/.env`. Everything that wants a key calls
`get_key(name)`; every module degrades gracefully when it returns "".

Ranked roughly by value-for-a-free-signup. `free` describes the free tier.
"""
from __future__ import annotations

import os
from pathlib import Path

_VAR_ENV = Path(__file__).resolve().parents[1] / "var" / ".env"

# name(env var) -> spec. `unlocks` is a human list of what turns on.
CATALOG = [
    {"name": "SHODAN_API_KEY", "label": "Shodan", "provider": "shodan.io",
     "get_url": "https://account.shodan.io/register",
     "free": "free account; host lookups",
     "unlocks": "IP: full host data (all ports, banners, vulns, tags) beyond the keyless InternetDB. Domain: DNS + subdomains."},
    {"name": "VT_API_KEY", "label": "VirusTotal", "provider": "virustotal.com",
     "get_url": "https://www.virustotal.com/gui/join-us",
     "free": "free, ~500 lookups/day",
     "unlocks": "Hash/Domain/IP/URL reputation: AV detections, related samples, resolutions, categories. The single highest-value key."},
    {"name": "IPINFO_TOKEN", "label": "IPinfo", "provider": "ipinfo.io",
     "get_url": "https://ipinfo.io/signup",
     "free": "free, 50k/mo",
     "unlocks": "IP: precise geo, ASN/company, privacy detection (VPN/proxy/tor/hosting), abuse contact."},
    {"name": "ABUSEIPDB_API_KEY", "label": "AbuseIPDB", "provider": "abuseipdb.com",
     "get_url": "https://www.abuseipdb.com/register",
     "free": "free, 1k checks/day",
     "unlocks": "IP: abuse confidence score, report count, categories, ISP/usage type."},
    {"name": "HUNTER_API_KEY", "label": "Hunter.io", "provider": "hunter.io",
     "get_url": "https://hunter.io/users/sign_up",
     "free": "free, 25 searches/mo",
     "unlocks": "Email/Domain: find + verify corporate email addresses, catch-all detection, deliverability."},
    {"name": "SECURITYTRAILS_API_KEY", "label": "SecurityTrails", "provider": "securitytrails.com",
     "get_url": "https://securitytrails.com/app/signup",
     "free": "free, 50 queries/mo",
     "unlocks": "Domain: historical DNS, full subdomain list, associated domains, WHOIS history."},
    {"name": "GREYNOISE_API_KEY", "label": "GreyNoise", "provider": "greynoise.io",
     "get_url": "https://viz.greynoise.io/signup",
     "free": "free community API",
     "unlocks": "IP: is it internet-background-noise / known scanner / benign, with classification + name."},
    {"name": "IPQS_API_KEY", "label": "IPQualityScore", "provider": "ipqualityscore.com",
     "get_url": "https://www.ipqualityscore.com/create-account",
     "free": "free, 5k lookups/mo",
     "unlocks": "IP/Email/Phone: fraud + risk score, proxy/VPN/bot detection, disposable-email + leaked checks."},
    {"name": "WHOISXML_API_KEY", "label": "WhoisXML", "provider": "whoisxmlapi.com",
     "get_url": "https://whois.whoisxmlapi.com/signup",
     "free": "free, 500/mo (1000 one-time)",
     "unlocks": "Domain: clean structured WHOIS, DNS, and subdomain discovery."},
    {"name": "URLSCAN_API_KEY", "label": "urlscan.io", "provider": "urlscan.io",
     "get_url": "https://urlscan.io/user/signup",
     "free": "free account",
     "unlocks": "Domain: submit live scans + higher search limits (the keyless search already works)."},
    {"name": "NUMLOOKUP_API_KEY", "label": "NumLookupAPI", "provider": "numlookupapi.com",
     "get_url": "https://numlookupapi.com/",
     "free": "free tier",
     "unlocks": "Phone: carrier, line type, location, validity (Recon's live phone module)."},
    {"name": "HIBP_API_KEY", "label": "Have I Been Pwned", "provider": "haveibeenpwned.com",
     "get_url": "https://haveibeenpwned.com/API/Key",
     "free": "paid, ~$4/mo (worth it)",
     "unlocks": "Email: the authoritative breach list + pastes. Recon already uses keyless XposedOrNot; HIBP is the gold standard."},
]

CATALOG_BY_NAME = {k["name"]: k for k in CATALOG}


def _read_var_env() -> dict:
    out = {}
    try:
        if _VAR_ENV.exists():
            for line in _VAR_ENV.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def get_key(name: str) -> str:
    """Env var first (set live by the Settings panel), then var/.env. '' if unset."""
    v = os.environ.get(name)
    if v:
        return v.strip()
    return _read_var_env().get(name, "").strip()


def is_set(name: str) -> bool:
    return bool(get_key(name))
