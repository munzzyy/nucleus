"""Selector classification + pivot-link/dork engine for the Recon console.

`classify()` takes whatever a human pastes in and guesses what it is. For the
types that have a live lookup module (username/email/domain/ip/phone) that
guess drives which module runs. For everything else (name/company/crypto/
image/geo) there's no live module -- we hand back curated pivot links and
Google/Bing dorks instead. This file never makes a network call; it only
builds URLs.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import quote, quote_plus

VALID_TYPES = (
    "username", "email", "domain", "ip", "phone",
    "name", "company", "crypto", "image", "geo",
    "hash", "mac", "asn", "discord",
)

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
_BTC_RE = re.compile(r"^(bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
_ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_GEO_RE = re.compile(r"^-?\d{1,3}(?:\.\d+)?\s*,\s*-?\d{1,3}(?:\.\d+)?$")
# MD5 / SHA1 / SHA256 hex digest, either case.
_HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
# Colon- or dash-separated MAC, one separator style per match (no mixing).
_MAC_RE = re.compile(
    r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$|^(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$"
)
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,39}$")
# Autonomous System number: "AS15169" / "as15169" (the AS prefix disambiguates
# it from a bare integer, which would look like a phone or a Discord ID).
_ASN_RE = re.compile(r"^AS\d{1,10}$", re.I)
# Discord snowflake: a 17-20 digit ID (account / message / server). Longer than
# any phone number, so it can't collide with one.
_DISCORD_RE = re.compile(r"^\d{17,20}$")
_IMAGE_EXT_RE = re.compile(r"\.(jpe?g|png|gif|webp|bmp|svg|tiff?)(?:[?#].*)?$", re.I)
_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z'\-]*(?:\s+[A-Za-z][A-Za-z'\-]*){1,4}$")
_COMPANY_SUFFIXES = (
    "inc", "inc.", "llc", "l.l.c.", "corp", "corp.", "ltd", "ltd.", "co",
    "co.", "gmbh", "plc", "group", "holdings", "technologies", "systems",
    "labs", "llp", "s.a.", "sa", "srl", "s.r.l.",
)


def _strip_scheme(s: str) -> tuple[str, bool]:
    """Return (rest, had_scheme) for an http(s):// prefix."""
    m = re.match(r"^https?://(.+)$", s, re.I)
    return (m.group(1), True) if m else (s, False)


def classify(raw: str) -> tuple[str, str]:
    """Guess the selector type. Returns (kind, normalized_value)."""
    s = (raw or "").strip()
    if not s:
        return "username", s

    # IP literal (v4 or v6), bracketed or bare.
    bare = s[1:-1] if s.startswith("[") and s.endswith("]") else s
    try:
        ipaddress.ip_address(bare)
        return "ip", bare
    except ValueError:
        pass

    # An email can't contain a path or a scheme. Without this, a URL carrying
    # basic-auth credentials ("https://admin:hunter2@intranet.example.com/x")
    # matches _EMAIL_RE and gets scanned AS AN EMAIL, which ships the password
    # off to XposedOrNot, HudsonRock, Gravatar and friends. Check the URL shape
    # first and let the host fall through to the domain branch below.
    if _EMAIL_RE.match(s) and "/" not in s and ":" not in s.split("@", 1)[0]:
        return "email", s.lower()

    # MAC before hash/username: colon form isn't a valid username character
    # set anyway, but the dash form (xx-xx-xx-xx-xx-xx) IS a legal username
    # string, so it must be claimed here or it'll misclassify downstream.
    if _MAC_RE.match(s):
        return "mac", s.lower()

    # Hash before crypto/username: a bare hex digest is also alnum (a legal
    # username), so it has to be claimed before the username fallback. It
    # can't collide with BTC (base58, excludes several hex letters) or ETH
    # (requires a literal "0x" prefix, which isn't a hex digit itself).
    if _HASH_RE.match(s):
        return "hash", s.lower()

    if _BTC_RE.match(s) or _ETH_RE.match(s):
        return "crypto", s

    if _GEO_RE.match(s):
        return "geo", re.sub(r"\s+", "", s)

    # ASN before the username fallback -- "AS15169" is a legal username string,
    # so it has to be claimed here or it'd fall through to a username scan.
    if _ASN_RE.match(s):
        return "asn", "AS" + re.sub(r"\D", "", s)

    # Discord snowflake: 17-20 pure digits. A phone tops out at 15 digits and
    # the phone branch below caps at 15, so this can't steal a real phone; claim
    # it before the username fallback (a bare digit run is a legal username).
    if _DISCORD_RE.match(s):
        return "discord", s

    # URL forms: image if it looks like a media file, otherwise treat the
    # host as a domain target.
    rest, had_scheme = _strip_scheme(s)
    if had_scheme or ("/" in s and _DOMAIN_RE.match(s.split("/", 1)[0])):
        host_and_path = rest if had_scheme else s
        host = host_and_path.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        path = host_and_path[len(host):]
        # Drop userinfo and the port before the host is matched. Keeping them
        # made _DOMAIN_RE fail on perfectly ordinary recon input
        # ("https://example.com:8080/admin"), which then fell through to the
        # username branch and 400'd.
        if "@" in host:
            host = host.rsplit("@", 1)[1]
        host = host.split(":", 1)[0]
        if _IMAGE_EXT_RE.search(path or host_and_path):
            return "image", s if had_scheme else f"https://{s}"
        if _DOMAIN_RE.match(host):
            return "domain", host.lower()

    if _DOMAIN_RE.match(s):
        return "domain", s.lower()

    digits = re.sub(r"[^\d+]", "", s)
    digit_count = len(re.sub(r"\D", "", digits))
    # "." and "-" are legal phone punctuation, which means a dotted quad that
    # ipaddress already rejected above (a zero-padded or out-of-range IPv4 like
    # 192.168.001.1 or 999.1.1.1) otherwise lands here and gets scanned as a
    # phone number. Anything shaped like an IPv4 is not a phone number.
    looks_like_ipv4 = re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", s) is not None
    if 7 <= digit_count <= 15 and re.match(r"^[\d\s()+.\-]+$", s) and not looks_like_ipv4:
        return "phone", digits

    if re.search(r"\s", s):
        words = s.split()
        lowered = [w.strip(".,").lower() for w in words]
        if any(w in _COMPANY_SUFFIXES for w in lowered):
            return "company", s
        if 2 <= len(words) <= 4 and _NAME_RE.match(s):
            return "name", s
        return "company", s

    if _USERNAME_RE.match(s):
        return "username", s

    # "@handle" is how people actually write a username. Strip the sigil so it
    # scans instead of failing validation (which is the same _USERNAME_RE, so
    # anything that doesn't match here is rejected upstream by design).
    if s.startswith("@") and _USERNAME_RE.match(s[1:]):
        return "username", s[1:]

    # Fall through: treat as a username anyway (best-effort single token).
    return "username", s


def normalize_for(kind: str, raw: str) -> str:
    """When a type is forced explicitly (not auto), still do light cleanup."""
    s = (raw or "").strip()
    if kind == "email":
        return s.lower()
    if kind == "domain":
        rest, _ = _strip_scheme(s)
        return rest.split("/", 1)[0].split("?", 1)[0].lower()
    if kind == "ip":
        return s[1:-1] if s.startswith("[") and s.endswith("]") else s
    if kind == "phone":
        return re.sub(r"[^\d+]", "", s)
    if kind == "geo":
        return re.sub(r"\s+", "", s)
    if kind in ("hash", "mac"):
        return s.lower()
    if kind == "asn":
        digits = re.sub(r"\D", "", s)
        return f"AS{digits}" if digits else s.upper()
    if kind == "discord":
        return re.sub(r"\D", "", s)
    if kind == "username":
        return s[1:] if s.startswith("@") else s
    return s


_FORMAT_RE = {
    "email": _EMAIL_RE,
    "domain": _DOMAIN_RE,
    "username": _USERNAME_RE,
    "geo": _GEO_RE,
    "name": _NAME_RE,
    "hash": _HASH_RE,
    "mac": _MAC_RE,
    "asn": _ASN_RE,
    "discord": _DISCORD_RE,
}


def validate(kind: str, value: str) -> bool:
    """Confirm a normalized value actually looks like `kind`.

    Runs for forced types too (not just auto-detect), so `?type=domain` with a
    bogus value is rejected up front instead of relying on a downstream guard.
    Freeform types (company/image) pass a non-empty check.
    """
    v = (value or "").strip()
    if not v:
        return False
    if kind == "ip":
        try:
            ipaddress.ip_address(v)
            return True
        except ValueError:
            return False
    if kind == "phone":
        return 7 <= len(re.sub(r"\D", "", v)) <= 15
    if kind == "crypto":
        return bool(_BTC_RE.match(v) or _ETH_RE.match(v))
    rex = _FORMAT_RE.get(kind)
    if rex is not None:
        return bool(rex.match(v))
    return True  # company / image — freeform


# --------------------------------------------------------------------------
# Search-engine deep links
# --------------------------------------------------------------------------
def _google(q: str) -> str:
    return f"https://www.google.com/search?q={quote_plus(q)}"


def _bing(q: str) -> str:
    return f"https://www.bing.com/search?q={quote_plus(q)}"


def _duck(q: str) -> str:
    return f"https://duckduckgo.com/?q={quote_plus(q)}"


def _dork(label: str, query: str) -> dict:
    return {"label": label, "query": query, "google": _google(query), "bing": _bing(query)}


# --------------------------------------------------------------------------
# Pivot links per type
# --------------------------------------------------------------------------
def pivots_for(kind: str, value: str) -> list[dict]:
    v = value or ""
    qv = quote(v, safe="")
    qpv = quote_plus(v)

    if kind == "username":
        return [
            {"title": "Namechk", "url": f"https://namechk.com/"},
            {"title": "WhatsMyName", "url": "https://whatsmyname.app/"},
            {"title": "KnowEm", "url": f"https://knowem.com/checkusername.php?u={qv}"},
            {"title": "Instant Username Search", "url": f"https://instantusername.com/#/?s={qv}"},
            {"title": f"GitHub — {v}", "url": f"https://github.com/{qv}"},
            {"title": f"X (Twitter) — {v}", "url": f"https://x.com/{qv}"},
        ]

    if kind == "email":
        domain = v.split("@", 1)[1] if "@" in v else ""
        return [
            {"title": "Have I Been Pwned", "url": f"https://haveibeenpwned.com/account/{qv}"},
            {"title": "Epieos email lookup", "url": "https://epieos.com/"},
            {"title": "That'sThem", "url": f"https://thatsthem.com/email/{qv}"},
            {"title": f"Hunter.io — {domain}", "url": f"https://hunter.io/search/{quote(domain, safe='')}"},
        ]

    if kind == "domain":
        return [
            {"title": "crt.sh certificate transparency", "url": f"https://crt.sh/?q=%25.{qv}"},
            {"title": "Wayback Machine", "url": f"https://web.archive.org/web/*/{qv}*"},
            {"title": "BuiltWith tech profile", "url": f"https://builtwith.com/{qv}"},
            {"title": "SecurityTrails DNS history", "url": f"https://securitytrails.com/domain/{qv}/dns"},
            {"title": "Shodan hostname search", "url": f"https://www.shodan.io/search?query=hostname%3A{qv}"},
            {"title": "who.is WHOIS", "url": f"https://who.is/whois/{qv}"},
            {"title": "Bastion — full security report", "url": "http://127.0.0.1:8920/"},
        ]

    if kind == "ip":
        return [
            {"title": "Shodan host", "url": f"https://www.shodan.io/host/{qv}"},
            {"title": "Censys host", "url": f"https://search.censys.io/hosts/{qv}"},
            {"title": "AbuseIPDB", "url": f"https://www.abuseipdb.com/check/{qv}"},
            {"title": "ipinfo.io", "url": f"https://ipinfo.io/{qv}"},
            {"title": "VirusTotal", "url": f"https://www.virustotal.com/gui/ip-address/{qv}"},
        ]

    if kind == "phone":
        return [
            {"title": "Sync.me", "url": f"https://sync.me/search/?number={qpv}"},
            {"title": "WhitePages", "url": f"https://www.whitepages.com/phone/{qv}"},
            {"title": "TrueCaller search", "url": f"https://www.truecaller.com/search/us/{qv}"},
            {"title": "FreeCarrierLookup", "url": "https://www.freecarrierlookup.com/"},
        ]

    if kind == "name":
        return [
            {"title": "LinkedIn people search", "url": f"https://www.linkedin.com/search/results/people/?keywords={qpv}"},
            {"title": "Facebook people search", "url": f"https://www.facebook.com/search/people/?q={qpv}"},
            {"title": "Spokeo", "url": f"https://www.spokeo.com/search?q={qpv}"},
            {"title": "WhitePages name search", "url": f"https://www.whitepages.com/name/{quote(v.replace(' ', '-'), safe='')}"},
        ]

    if kind == "company":
        return [
            {"title": "OpenCorporates", "url": f"https://opencorporates.com/companies?q={qpv}"},
            {"title": "Crunchbase search", "url": f"https://www.crunchbase.com/textsearch?q={qpv}"},
            {"title": "LinkedIn company search", "url": f"https://www.linkedin.com/search/results/companies/?keywords={qpv}"},
            {"title": "SEC EDGAR full-text search", "url": f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company={qpv}"},
            {"title": "Glassdoor", "url": f"https://www.glassdoor.com/Search/results.htm?keyword={qpv}"},
        ]

    if kind == "crypto":
        is_eth = v.lower().startswith("0x")
        if is_eth:
            return [
                {"title": "Etherscan", "url": f"https://etherscan.io/address/{qv}"},
                {"title": "Blockchair (Ethereum)", "url": f"https://blockchair.com/ethereum/address/{qv}"},
                {"title": "Arkham Intel", "url": f"https://intel.arkm.com/explorer/address/{qv}"},
            ]
        return [
            {"title": "Blockchain.com explorer", "url": f"https://www.blockchain.com/explorer/addresses/btc/{qv}"},
            {"title": "Blockchair (Bitcoin)", "url": f"https://blockchair.com/bitcoin/address/{qv}"},
            {"title": "OXT", "url": f"https://oxt.me/address/{qv}"},
        ]

    if kind == "image":
        return [
            {"title": "Google Lens reverse image", "url": f"https://lens.google.com/uploadbyurl?url={qv}"},
            {"title": "TinEye", "url": f"https://tineye.com/search?url={qv}"},
            {"title": "Yandex reverse image", "url": f"https://yandex.com/images/search?rpt=imageview&url={qv}"},
            {"title": "Bing visual search", "url": f"https://www.bing.com/images/search?q=imgurl:{qv}&view=detailv2"},
        ]

    if kind == "hash":
        return [
            {"title": "VirusTotal", "url": f"https://www.virustotal.com/gui/file/{qv}"},
            {"title": "CIRCL hashlookup", "url": "https://hashlookup.circl.lu/"},
            {"title": "MalwareBazaar", "url": f"https://bazaar.abuse.ch/browse.php?search=hash%3A{qv}"},
            {"title": "Hybrid Analysis", "url": f"https://www.hybrid-analysis.com/search?query={qv}"},
        ]

    if kind == "mac":
        return [
            {"title": "macvendors.com", "url": "https://macvendors.com/"},
            {"title": "Wireshark OUI lookup", "url": "https://www.wireshark.org/tools/oui-lookup.html"},
            {"title": "IEEE OUI registry search", "url": "https://standards-oui.ieee.org/"},
        ]

    if kind == "geo":
        try:
            lat, lng = v.split(",", 1)
        except ValueError:
            lat, lng = v, ""
        return [
            {"title": "Google Maps", "url": f"https://www.google.com/maps?q={lat},{lng}"},
            {"title": "OpenStreetMap", "url": f"https://www.openstreetmap.org/#map=17/{lat}/{lng}"},
            {"title": "SunCalc (shadow/sun analysis)", "url": f"https://www.suncalc.org/#/{lat},{lng},15"},
            {"title": "Wikimapia", "url": f"http://wikimapia.org/#lang=en&lat={lat}&lon={lng}&z=16"},
        ]

    if kind == "asn":
        num = re.sub(r"\D", "", v)
        return [
            {"title": f"bgp.he.net — AS{num}", "url": f"https://bgp.he.net/AS{num}"},
            {"title": f"bgp.tools — AS{num}", "url": f"https://bgp.tools/as/{num}"},
            {"title": "RIPEstat", "url": f"https://stat.ripe.net/AS{num}"},
            {"title": "PeeringDB", "url": f"https://www.peeringdb.com/asn/{num}"},
            {"title": "Shodan ASN search", "url": f"https://www.shodan.io/search?query=asn%3AAS{num}"},
        ]

    if kind == "discord":
        return [
            {"title": "DiscordLookup", "url": f"https://discordlookup.com/user/{qv}"},
            {"title": "Snowflake reference (Discord docs)",
             "url": "https://discord.com/developers/docs/reference#snowflakes"},
        ]

    return []


# --------------------------------------------------------------------------
# Dork builder per type — Google + Bing query URLs, never fetched.
# --------------------------------------------------------------------------
def dorks_for(kind: str, value: str) -> list[dict]:
    v = value or ""

    if kind == "username":
        return [
            _dork("Exact mention", f'"{v}"'),
            _dork("Profile pages", f'intext:"{v}" (profile OR account OR bio)'),
            _dork("Pastes / leaks", f'"{v}" site:pastebin.com OR site:github.com'),
            _dork("Docs mentioning it", f'"{v}" filetype:pdf OR filetype:doc OR filetype:xlsx'),
        ]

    if kind == "email":
        domain = v.split("@", 1)[1] if "@" in v else ""
        return [
            _dork("Exact mention", f'"{v}"'),
            _dork("Leaked in docs", f'"{v}" filetype:pdf OR filetype:xlsx OR filetype:csv OR filetype:txt'),
            _dork("Pastes", f'"{v}" site:pastebin.com'),
            _dork("Same domain, other addresses", f'"@{domain}" -"{v}"'),
        ]

    if kind == "domain":
        return [
            _dork("All indexed pages", f"site:{v}"),
            _dork("Login / admin surfaces", f"site:{v} inurl:admin OR inurl:login OR inurl:portal"),
            _dork("Exposed documents", f"site:{v} filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:sql"),
            _dork("Subdomains indexed", f"site:*.{v} -site:www.{v}"),
            _dork("Config / backup files", f"site:{v} (inurl:.env OR inurl:.git OR inurl:backup OR inurl:config)"),
        ]

    if kind == "ip":
        return [
            _dork("Exact mention", f'"{v}"'),
            _dork("Pastes / leaks", f'"{v}" site:pastebin.com'),
            _dork("Server banners / panels", f'"{v}" intitle:"index of" OR intitle:"login"'),
        ]

    if kind == "phone":
        return [
            _dork("Exact mention", f'"{v}"'),
            _dork("Social profiles", f'"{v}" site:facebook.com OR site:linkedin.com'),
            _dork("Classifieds / listings", f'"{v}" site:craigslist.org OR intext:"contact"'),
        ]

    if kind == "name":
        return [
            _dork("Exact name", f'"{v}"'),
            _dork("Resume / CV", f'"{v}" resume OR CV filetype:pdf'),
            _dork("LinkedIn profile", f'"{v}" site:linkedin.com/in'),
            _dork("News mentions", f'"{v}" (news OR article OR press)'),
        ]

    if kind == "company":
        return [
            _dork("Exact name", f'"{v}"'),
            _dork("LinkedIn company", f'"{v}" site:linkedin.com/company'),
            _dork("Financial filings", f'"{v}" (10-K OR 10-Q OR annual report) filetype:pdf'),
            _dork("Exposed spreadsheets", f'"{v}" filetype:xlsx OR filetype:csv'),
        ]

    if kind == "crypto":
        return [
            _dork("Exact address", f'"{v}"'),
            _dork("Pastes / forums", f'"{v}" site:pastebin.com OR site:reddit.com OR site:bitcointalk.org'),
        ]

    if kind == "hash":
        return [
            _dork("Exact hash", f'"{v}"'),
            _dork("Malware writeups", f'"{v}" (malware OR sample OR analysis OR IOC)'),
        ]

    if kind == "mac":
        return [
            _dork("Exact mention", f'"{v}"'),
        ]

    if kind == "asn":
        return [
            _dork("Exact mention", f'"{v}"'),
            _dork("Abuse / netblock references", f'"{v}" (abuse OR netblock OR prefix OR peering)'),
        ]

    if kind == "discord":
        return [
            _dork("Exact ID", f'"{v}"'),
            _dork("Server / invite mentions", f'"{v}" (discord OR invite OR guild)'),
        ]

    return []
