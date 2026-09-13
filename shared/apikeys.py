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

import fcntl
import os
import tempfile
from pathlib import Path

_VAR_ENV = Path(__file__).resolve().parents[1] / "var" / ".env"
_LOCK_PATH = _VAR_ENV.parent / ".env.lock"

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
    {"name": "ABUSECH_API_KEY", "label": "abuse.ch", "provider": "abuse.ch",
     "get_url": "https://auth.abuse.ch/",
     "free": "free account",
     "unlocks": "Hash: the MalwareBazaar known-malware lookup (signature, file type, tags). abuse.ch stopped serving anonymous API requests, so this source is off until a key is set."},
    {"name": "WPSCAN_API_TOKEN", "label": "WPScan", "provider": "wpscan.com",
     "get_url": "https://wpscan.com/register",
     "free": "free, 25 requests/day",
     "unlocks": "Redcell: unlocks WPScan's live vulnerability database, so WordPress core/plugin/theme scans return known CVEs. Without it wpscan still enumerates but reports no vuln data."},
]

CATALOG_BY_NAME = {k["name"]: k for k in CATALOG}


def _clean_value(v: str) -> str:
    """Trim whitespace and strip one layer of matching quotes."""
    v = (v or "").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        v = v[1:-1]
    return v.strip()


def _parse_env_text(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        if k:
            out[k] = _clean_value(v)
    return out


def read_env() -> dict:
    """Parse var/.env once: KEY=value, KEY="value", KEY='value', blank lines,
    and '#' comments are all handled, and quotes are stripped so nobody
    downstream ever sees them. Used internally by get_key(); public so the
    hub Settings panel (and anything else that wants the whole file) reads
    it here instead of growing its own parser — this is the one that stays
    correct."""
    try:
        if _VAR_ENV.exists():
            return _parse_env_text(_VAR_ENV.read_text())
    except OSError:
        pass
    return {}


def get_key(name: str) -> str:
    """Env var first (set live by the Settings panel), then var/.env.
    Surrounding single/double quotes are stripped either way — a quoted
    value used to reach callers WITH the quote characters still attached,
    which 401'd every keyed source that sent it on verbatim. '' if unset.
    """
    v = os.environ.get(name)
    if v:
        return _clean_value(v)
    return read_env().get(name, "")


def is_set(name: str) -> bool:
    return bool(get_key(name))


def set_key(name: str, value: str) -> None:
    """Atomically upsert (or, if `value` is '', remove) one key in
    var/.env, and mirror the change into os.environ so it's live
    immediately with no restart.

    The whole read-modify-write is held under an flock() on a sidecar
    `.env.lock`, then written to a temp file in the SAME directory and
    moved into place with os.replace() — a single atomic rename. A reader
    never observes a half-written file, and two saves racing each other
    (two request threads in the hub, or two consoles) serialize on the lock
    instead of corrupting the file or silently dropping each other's key.
    This replaces the hub's old '_write_env_key' (read lines, mutate,
    write_text — no lock, no atomic rename), which had exactly that race.

    The file is rewritten canonically (sorted KEY=value lines, unquoted) —
    it's a machine-managed secrets store, not a hand-edited config, so this
    intentionally doesn't try to preserve stray comments or ordering.
    """
    name = (name or "").strip()
    # A name/value with '=' or an embedded newline would corrupt the
    # KEY=value line format on write (and desync from what read_env() can
    # parse back). The hub's own regex already keeps values to this shape
    # before they get here; this is the belt-and-suspenders for any other
    # caller of this now-shared API.
    if not name or "=" in name or "\n" in name or "\r" in name:
        return
    value = _clean_value(value).replace("\n", "").replace("\r", "")

    _VAR_ENV.parent.mkdir(parents=True, exist_ok=True)
    _LOCK_PATH.touch(exist_ok=True)

    with open(_LOCK_PATH, "r+") as lockf:
        fcntl.flock(lockf, fcntl.LOCK_EX)
        try:
            current = read_env()
            if value:
                current[name] = value
            else:
                current.pop(name, None)

            lines = [f"{k}={v}" for k, v in sorted(current.items())]
            text = ("\n".join(lines) + "\n") if lines else ""

            fd, tmp_path = tempfile.mkstemp(
                dir=str(_VAR_ENV.parent), prefix=".env.", suffix=".tmp")
            try:
                with os.fdopen(fd, "w") as f:
                    f.write(text)
                os.chmod(tmp_path, 0o600)
                os.replace(tmp_path, _VAR_ENV)
            except OSError:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        finally:
            fcntl.flock(lockf, fcntl.LOCK_UN)

    if value:
        os.environ[name] = value
    else:
        os.environ.pop(name, None)
