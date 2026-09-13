"""Extra keyless OSINT sources for the Recon console.

This module holds the newer, no-API-key-required sources that plug into the
existing `lookups.py` scan functions, plus two brand-new selector types (ASN
and Discord snowflake). It's split out of `lookups.py` purely so that file
doesn't keep growing without bound -- the contract is identical: stdlib only,
every outbound call goes through `shared.common.fetch` (the same SSRF guard,
redirect re-validation and IP pinning every other request in this app uses),
and every function degrades to a populated dict with an `error`/`note` field
rather than raising, so one dead source never sinks a scan.

Passive/public sources only -- no exploitation, no auth attempts, no active
scanning. Every endpoint here was picked because it works with no key and
answers a question the keyless core couldn't before:

  * CertSpotter / RapidDNS / Wayback CDX  -> far deeper subdomain + historical
    URL coverage than crt.sh alone (which is chronically rate-limited).
  * HudsonRock Cavalier  -> infostealer-infection intel by email / username /
    domain, the single highest-signal free breach source there is right now.
  * Gravatar profile JSON  -> a real name + verified linked social accounts
    from just an email hash.
  * RIPEstat + isc.sans.edu  -> ASN / prefix / network abuse intel for an IP,
    and a first-class ASN lookup.
  * mempool.space + the OFAC sanctioned-address list  -> a more reliable BTC
    balance source and an actual sanctions check on a crypto address.
  * Discord snowflake  -> account-creation timestamp decoded offline, no call.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from shared import common

VAR_DIR = Path(__file__).resolve().parents[2] / "var"

FETCH_TIMEOUT = 6.0
SLOW_TIMEOUT = 12.0  # CertSpotter / RapidDNS return bigger bodies
# The Wayback CDX index is in a class of its own: `matchType=domain` makes the
# server walk the whole domain index before it can emit a row, and measured
# runs swing from 0.6s to well past 20s for the SAME query shape depending on
# how hot that index is. At SLOW_TIMEOUT this call simply never landed, so the
# historical-URL section was permanently empty. It runs concurrently with the
# rest of domain_scan, so a longer budget costs wall clock only when it's
# actually the slowest source.
WAYBACK_TIMEOUT = 25.0

# DNS record type numbers (RFC 1035 / 4034). A DoH Answer section carries
# whatever the resolver put there, including the CNAME chain, so anything that
# cares WHICH record it got has to filter on this.
_DNS_TYPE_CNAME = 5
_DNS_TYPE_DS = 43
_DNS_TYPE_DNSKEY = 48

_UA_BROWSER = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# Same charset guard lookups.py uses -- these functions substitute the caller's
# value straight into a URL, so re-validate here too (defense in depth, never
# trust an upstream caller).
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,39}$")
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _get(url, *, timeout=FETCH_TIMEOUT, headers=None, max_bytes=1_000_000):
    """common.fetch that never raises: (status_or_None, body, headers, error).

    http.client.HTTPException is in the catch list because common.fetch drives
    http.client directly: a hostile or broken provider can hand back a bad
    status line, an over-long header, or a truncated chunked body, and those
    raise HTTPException subclasses that are NOT OSError. Without this, one
    misbehaving third party could take down a scan that had already succeeded.
    """
    try:
        status, body, hdrs = common.fetch(url, timeout=timeout, headers=headers, max_bytes=max_bytes)
        return status, body, hdrs, None
    except (ValueError, OSError, TimeoutError, http.client.HTTPException) as e:
        return None, b"", {}, f"{type(e).__name__}: {e}" if not str(e) else str(e)


def _json(body):
    import json
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def _md5_email(email: str) -> str:
    import hashlib
    return hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()


# ==========================================================================
# Subdomain sources -- each returns (set_of_names, error_or_None) so
# domain_scan can merge them into its existing subdomain set with one shape.
# ==========================================================================
def certspotter_subdomains(d: str) -> tuple[set[str], str | None]:
    """SSLMate's CertSpotter certificate-transparency search. Keyless tier
    covers issuances for a domain + its subdomains; returns clean JSON (unlike
    crt.sh's flaky multi-MB dumps). Every `dns_names` entry under the domain
    becomes a candidate subdomain."""
    if not _HOST_RE.match(d or ""):
        return set(), "invalid domain"
    url = (f"https://api.certspotter.com/v1/issuances?domain={quote(d, safe='')}"
           "&include_subdomains=true&expand=dns_names")
    status, body, _, err = _get(url, timeout=SLOW_TIMEOUT, max_bytes=4_000_000)
    if status != 200:
        # CertSpotter 429s aggressively without a key -- surface it, don't crash.
        return set(), (f"HTTP {status}" if status else err) or "unreachable"
    rows = _json(body)
    if not isinstance(rows, list):
        return set(), "unparseable response"
    names: set[str] = set()
    for row in rows:
        for n in (row.get("dns_names") or []):
            n = (n or "").strip().lstrip("*.").lower()
            if n and (n == d or n.endswith("." + d)):
                names.add(n)
    return names, None


def rapiddns_subdomains(d: str) -> tuple[set[str], str | None]:
    """RapidDNS.io passive subdomain page. It's HTML, not an API, so we pull
    every hostname under the target out of the table with a domain-anchored
    regex and validate each -- a layout change just yields fewer names, never a
    crash. Best-effort supplement to the CT sources."""
    if not _HOST_RE.match(d or ""):
        return set(), "invalid domain"
    status, body, _, err = _get(
        f"https://rapiddns.io/subdomain/{quote(d, safe='')}?full=1",
        timeout=SLOW_TIMEOUT, max_bytes=3_000_000, headers={"User-Agent": _UA_BROWSER})
    if status != 200:
        return set(), (f"HTTP {status}" if status else err) or "unreachable"
    text = body.decode("utf-8", "replace")
    # Flat character class, no nested quantifiers. The obvious hostname pattern
    # (`[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]+)*\.example\.com`)
    # nests two quantifiers over overlapping sets, which backtracks
    # catastrophically on a long run of hostname-legal characters -- and this
    # runs over megabytes of third-party HTML. Grab a permissive label run and
    # validate the shape in Python instead, where it costs linear time.
    pat = re.compile(r"([A-Za-z0-9._-]{1,253}\." + re.escape(d) + r")\b")
    names = set()
    for m in pat.findall(text):
        n = m.lower().strip(".")
        if (n == d or n.endswith("." + d)) and _HOST_RE.match(n) and ".." not in n:
            names.add(n)
    return names, None


def wayback_urls(d: str, limit: int = 40) -> dict:
    """Historical URLs the Internet Archive has crawled for a domain -- great
    for surfacing old endpoints, params and paths that no longer link from the
    live site. Also a side source of subdomains. Uses the CDX API with
    urlkey-collapse so we get distinct URLs, not every snapshot."""
    if not _HOST_RE.match(d or ""):
        return {"ok": False, "count": 0, "urls": [], "subdomains": [], "error": "invalid domain"}
    url = (f"https://web.archive.org/cdx/search/cdx?url={quote(d, safe='')}"
           f"&matchType=domain&fl=original&collapse=urlkey&limit={int(limit)}&output=json")
    status, body, _, err = _get(url, timeout=WAYBACK_TIMEOUT, max_bytes=2_000_000)
    if status != 200:
        return {"ok": False, "count": 0, "urls": [], "subdomains": [],
                "error": (f"HTTP {status}" if status else err) or "unreachable"}
    rows = _json(body)
    if not isinstance(rows, list) or not rows:
        return {"ok": True, "count": 0, "urls": [], "subdomains": [], "error": None}
    urls = [r[0] for r in rows[1:] if isinstance(r, list) and r]  # row 0 is the header
    subs: set[str] = set()
    host_re = re.compile(r"^https?://([^/:?#]+)", re.I)
    for u in urls:
        m = host_re.match(u or "")
        if m:
            h = m.group(1).lower().strip(".")
            if h.endswith("." + d) or h == d:
                subs.add(h)
    return {"ok": True, "count": len(urls), "urls": urls[:limit],
            "subdomains": sorted(subs), "error": None}


def _answers_of_type(name: str, rtype: str, type_num: int) -> tuple[int, bool]:
    """(count of answers ACTUALLY of `type_num`, unreachable). A DoH Answer
    section contains the whole chain the resolver followed, so asking for DS on
    a CNAME'd host comes back with a CNAME (type 5) answer and a naive
    truthiness check reads it as "DS present". Filtering on the numeric type is
    the only way to tell a real record from the chain that led to it."""
    try:
        ans = common.dns_query(name, rtype, timeout=FETCH_TIMEOUT)
    except Exception:
        return 0, True
    return sum(1 for a in ans if a.get("type") == type_num), False


def dnssec_status(d: str, dnskey_records: list | None = None) -> dict:
    """Is the zone DNSSEC-signed?

    A real chain of trust needs BOTH a DNSKEY in the zone and a DS record at
    the parent. Both are queried here with a record-type filter rather than
    trusting the caller's pre-extracted list, because that list is flattened to
    bare strings by domain_scan and loses the type -- and an unfiltered answer
    for a CNAME'd host reports "signed" for a zone that is not signed at all.
    """
    dnskey_count, dnskey_unreachable = _answers_of_type(d, "DNSKEY", _DNS_TYPE_DNSKEY)
    ds_count, ds_unreachable = _answers_of_type(d, "DS", _DNS_TYPE_DS)
    ds_present = ds_count > 0
    note = None
    if dnskey_count and not ds_present and not ds_unreachable:
        note = "DNSKEY published but no DS at the parent -- not a full chain of trust"
    elif dnskey_unreachable or ds_unreachable:
        note = "DNSSEC lookup did not complete -- treat this as unknown, not as unsigned"
    return {
        "signed": bool(dnskey_count) and ds_present,
        "dnskey_present": bool(dnskey_count),
        "dnskey_count": dnskey_count,
        "ds_present": ds_present,
        "ds_count": ds_count,
        "unreachable": dnskey_unreachable or ds_unreachable,
        "note": note,
    }


# ==========================================================================
# HudsonRock Cavalier -- infostealer-infection intel, keyless. Email/username
# share one shape (a `stealers` list); domain returns aggregate counts + the
# URLs where employees'/users' credentials were captured.
# ==========================================================================
_HR_BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"


def _hudsonrock_person(kind: str, value: str) -> dict:
    """Shared parser for the email + username endpoints."""
    status, body, _, err = _get(f"{_HR_BASE}/search-by-{kind}?{kind}={quote(value, safe='')}",
                                timeout=SLOW_TIMEOUT, max_bytes=1_000_000)
    if status is None:
        return {"ok": False, "infected": None, "stealer_count": 0, "stealers": [], "error": err or "unreachable"}
    if status == 429:
        return {"ok": False, "infected": None, "stealer_count": 0, "stealers": [], "error": "rate-limited -- try again shortly"}
    if status != 200:
        return {"ok": False, "infected": None, "stealer_count": 0, "stealers": [], "error": f"HTTP {status}"}
    data = _json(body) or {}
    stealers = data.get("stealers") or []
    trimmed = [{
        "date_compromised": s.get("date_compromised"),
        "computer_name": s.get("computer_name"),
        "operating_system": s.get("operating_system"),
        "malware_path": s.get("malware_path"),
        "antiviruses": s.get("antiviruses") or [],
        "stealer_family": s.get("stealer_family"),
        "total_user_services": s.get("total_user_services"),
        "total_corporate_services": s.get("total_corporate_services"),
        # HudsonRock already masks these on the free tier (e.g. "S******8"),
        # so no new secret is revealed -- they're kept only as an exposure hint.
        "top_logins": (s.get("top_logins") or [])[:5],
        "top_passwords": (s.get("top_passwords") or [])[:5],
    } for s in stealers[:10]]
    return {
        "ok": True,
        "infected": bool(stealers),
        "stealer_count": len(stealers),
        "total_user_services": data.get("total_user_services"),
        "total_corporate_services": data.get("total_corporate_services"),
        "stealers": trimmed,
        "source": "HudsonRock Cavalier (infostealer intel)",
        "error": None,
    }


def hudsonrock_email(email: str) -> dict:
    if not _EMAIL_RE.match(email or ""):
        return {"ok": False, "infected": None, "stealer_count": 0, "stealers": [], "error": "invalid email"}
    return _hudsonrock_person("email", email)


def hudsonrock_username(username: str) -> dict:
    if not _USERNAME_RE.match(username or ""):
        return {"ok": False, "infected": None, "stealer_count": 0, "stealers": [], "error": "invalid username"}
    return _hudsonrock_person("username", username)


def hudsonrock_domain(d: str) -> dict:
    """Domain endpoint: how many employees/users tied to this domain turned up
    in infostealer logs, and the login URLs where their credentials were
    captured -- a direct read on an org's credential-exposure surface."""
    if not _HOST_RE.match(d or ""):
        return {"ok": False, "error": "invalid domain"}
    status, body, _, err = _get(f"{_HR_BASE}/search-by-domain?domain={quote(d, safe='')}",
                                timeout=SLOW_TIMEOUT, max_bytes=1_000_000)
    if status is None:
        return {"ok": False, "error": err or "unreachable"}
    if status == 429:
        return {"ok": False, "error": "rate-limited -- try again shortly"}
    if status != 200:
        return {"ok": False, "error": f"HTTP {status}"}
    data = _json(body) or {}
    inner = data.get("data") or {}
    client_urls = inner.get("clients_urls") or []
    emp_urls = inner.get("employees_urls") or []
    return {
        "ok": True,
        "total": data.get("total", 0),
        "employees": data.get("employees", 0),
        "users": data.get("users", 0),
        "third_parties": data.get("third_parties", 0),
        "total_stealers": data.get("totalStealers"),
        "employee_urls": [{"url": u.get("url"), "occurrence": u.get("occurrence")} for u in emp_urls[:15]],
        "client_urls": [{"url": u.get("url"), "occurrence": u.get("occurrence"), "type": u.get("type")}
                        for u in client_urls[:15]],
        "source": "HudsonRock Cavalier (infostealer intel)",
        "error": None,
    }


# ==========================================================================
# Gravatar profile -- real name + verified linked social accounts from an
# email hash. Upgrades the old existence-only check into an identity pivot.
# ==========================================================================
def gravatar_profile(email: str) -> dict:
    if not _EMAIL_RE.match(email or ""):
        return {"exists": False, "error": "invalid email"}
    h = _md5_email(email)
    status, body, _, err = _get(f"https://gravatar.com/{h}.json", timeout=FETCH_TIMEOUT, max_bytes=200_000,
                                headers={"User-Agent": "nucleus-recon"})
    if status == 404:
        return {"exists": False, "error": None, "note": "no public Gravatar profile for this email"}
    if status != 200:
        return {"exists": None, "error": (f"HTTP {status}" if status else err) or "unreachable"}
    data = _json(body) or {}
    entries = data.get("entry") or []
    if not entries:
        return {"exists": False, "error": None}
    e = entries[0]
    accounts = [{
        "name": a.get("name"), "url": a.get("url"), "username": a.get("username"),
        "verified": a.get("verified"), "shortname": a.get("shortname"),
    } for a in (e.get("accounts") or []) if not a.get("is_hidden")]
    # Deliberately omit raw emails / phone / IM contact blocks (data
    # minimization) -- the display fields + verified account pivots are the
    # signal; the person's other contact details are not ours to surface.
    return {
        "exists": True,
        "display_name": e.get("displayName"),
        "username": e.get("preferredUsername"),
        "location": e.get("currentLocation"),
        "job_title": e.get("job_title"),
        "company": e.get("company"),
        "pronouns": e.get("pronouns"),
        "about": (e.get("aboutMe") or "")[:400] or None,
        "profile_url": e.get("profileUrl"),
        "avatar": e.get("thumbnailUrl"),
        "accounts": accounts,
        "source": "Gravatar public profile",
        "error": None,
    }


# ==========================================================================
# IP / ASN network intel -- RIPEstat (RIPE NCC, keyless, very reliable) and
# isc.sans.edu (SANS ISC, keyless abuse/threat-feed intel).
# ==========================================================================
def _ripestat(call: str, resource: str, timeout: float = FETCH_TIMEOUT) -> dict | None:
    url = f"https://stat.ripe.net/data/{call}/data.json?resource={quote(resource, safe='')}"
    status, body, _, _ = _get(url, timeout=timeout, max_bytes=3_000_000)
    if status != 200:
        return None
    data = _json(body) or {}
    # RIPEstat answers 200 with status "error"/"maintenance" and a useless data
    # block. Returning it anyway produced empty-but-"ok" ASN results.
    if data.get("status") != "ok":
        return None
    return data.get("data")


def ripestat_ip(ip: str) -> dict:
    """IP -> announcing ASN(s) + covering prefix (network-info), then the ASN's
    holder/registry (as-overview). Fills the gap where no IPinfo key is set."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "not a valid IP"}
    ni = _ripestat("network-info", ip)
    if not ni:
        return {"ok": False, "error": "RIPEstat unreachable"}
    asns = ni.get("asns") or []
    prefix = ni.get("prefix")
    holder = None
    if asns:
        ov = _ripestat("as-overview", f"AS{asns[0]}")
        if ov:
            holder = ov.get("holder")
    return {"ok": True, "asns": asns, "prefix": prefix, "holder": holder,
            "source": "RIPEstat", "error": None}


def isc_ip(ip: str) -> dict:
    """SANS Internet Storm Center intel for an IP: how many attacks it's been
    reported for, its network's abuse contact, and which threat feeds list it
    (miner / openresolver / etc)."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "not a valid IP"}
    status, body, _, err = _get(f"https://isc.sans.edu/api/ip/{quote(ip, safe='')}?json",
                                timeout=FETCH_TIMEOUT, max_bytes=100_000)
    if status != 200:
        return {"ok": False, "error": (f"HTTP {status}" if status else err) or "unreachable"}
    data = (_json(body) or {}).get("ip") or {}
    feeds = list((data.get("threatfeeds") or {}).keys())

    def _int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    return {
        "ok": True,
        "attacks": _int(data.get("attacks")),
        "reports": _int(data.get("count")),
        "asname": data.get("asname"),
        "ascountry": data.get("ascountry"),
        "abuse_contact": data.get("asabusecontact"),
        "network": data.get("network"),
        "threatfeeds": feeds,
        "comment": data.get("comment"),
        "source": "SANS ISC",
        "error": None,
    }


def asn_scan(asn: str) -> dict:
    """First-class ASN lookup: holder, allocating registry, and the prefixes
    the AS announces (v4/v6 counts + a sample). RIPEstat, keyless."""
    digits = re.sub(r"\D", "", asn or "")
    if not digits:
        return {"input": asn, "ok": False, "error": "not a valid ASN"}
    resource = f"AS{digits}"
    ov = _ripestat("as-overview", resource)
    if not ov:
        return {"input": resource, "asn": digits, "ok": False, "error": "RIPEstat unreachable or unknown ASN"}
    block = ov.get("block") or {}
    result = {
        "input": resource, "asn": digits, "ok": True,
        "holder": ov.get("holder"),
        "announced": ov.get("announced"),
        "registry": block.get("desc"),
        "prefix_count": None, "prefixes_v4": [], "prefixes_v6": [], "error": None,
        "source": "RIPEstat",
    }
    pfx = _ripestat("announced-prefixes", resource, timeout=SLOW_TIMEOUT)
    if pfx:
        v4, v6 = [], []
        for row in pfx.get("prefixes") or []:
            p = row.get("prefix")
            if not p:
                continue
            (v6 if ":" in p else v4).append(p)
        result["prefix_count"] = len(v4) + len(v6)
        result["prefixes_v4"] = sorted(v4)[:25]
        result["prefixes_v6"] = sorted(v6)[:25]
    return result


# ==========================================================================
# Crypto -- mempool.space (reliable BTC balance) + OFAC sanctions check.
# ==========================================================================
def mempool_btc(addr: str) -> dict:
    """BTC address balance/activity from mempool.space -- steadier than
    blockchain.info under load. Confirmed chain stats + anything pending in the
    mempool."""
    if not re.match(r"^(bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$", addr or ""):
        return {"ok": False, "error": "not a BTC address"}
    status, body, _, err = _get(f"https://mempool.space/api/address/{quote(addr, safe='')}",
                                timeout=FETCH_TIMEOUT, max_bytes=100_000)
    if status != 200:
        return {"ok": False, "error": (f"HTTP {status}" if status else err) or "unreachable"}
    data = _json(body) or {}
    cs = data.get("chain_stats") or {}
    ms = data.get("mempool_stats") or {}
    sat = 100_000_000
    funded = cs.get("funded_txo_sum", 0) or 0
    spent = cs.get("spent_txo_sum", 0) or 0
    return {
        "ok": True,
        "balance_btc": round((funded - spent) / sat, 8),
        "total_received_btc": round(funded / sat, 8),
        "total_sent_btc": round(spent / sat, 8),
        "tx_count": cs.get("tx_count", 0),
        "pending_tx": ms.get("tx_count", 0),
        "source": "mempool.space",
        "error": None,
    }


# OFAC sanctioned-address lists, per chain (0xB10C's mirror of Treasury's SDN
# crypto entries). Cached in-process + on disk so a scan doesn't refetch a list
# every time.
_OFAC_URL = ("https://raw.githubusercontent.com/0xB10C/"
             "ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_{chain}.txt")
_OFAC_TTL = 24 * 3600
_ofac_lock = threading.Lock()
_ofac_mem: dict = {}  # chain -> {"set": set[str], "at": float}


def _load_ofac_list(chain: str) -> tuple[set[str] | None, str | None, str | None]:
    """(addresses, error, staleness_note).

    A sanctions check is only meaningful if the caller knows how current the
    list is. When the live fetch fails we still fall back to the copy on disk,
    but the age of that copy is measured and reported instead of being
    laundered into a fresh-looking result: a months-old list answering
    "not sanctioned" is exactly the answer you must not trust silently.
    """
    now = time.monotonic()
    with _ofac_lock:
        cached = _ofac_mem.get(chain)
        if cached and (now - cached["at"]) < _OFAC_TTL:
            return cached["set"], None, cached.get("stale")
    cache_file = VAR_DIR / f"ofac_{chain}.txt"
    status, body, _, err = _get(_OFAC_URL.format(chain=chain), timeout=FETCH_TIMEOUT, max_bytes=2_000_000)
    stale: str | None = None
    if status == 200:
        text = body.decode("utf-8", "replace")
        try:
            VAR_DIR.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(text, encoding="utf-8")
        except OSError:
            pass
    else:
        try:
            text = cache_file.read_text(encoding="utf-8")
        except OSError:
            return None, (f"HTTP {status}" if status else err) or "list unavailable", None
        try:
            age_days = max(0, int((time.time() - cache_file.stat().st_mtime) // 86400))
            stale = (f"live list unreachable ({(f'HTTP {status}' if status else err) or 'unknown'}); "
                     f"checked against a cached copy {age_days} day(s) old")
        except OSError:
            stale = "live list unreachable; checked against a cached copy of unknown age"
    addrs = {ln.strip().lower() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")}
    with _ofac_lock:
        _ofac_mem[chain] = {"set": addrs, "at": now, "stale": stale}
    return addrs, None, stale


def ofac_sanctioned(addr: str, chain: str) -> dict:
    """Is this address on the US Treasury OFAC sanctions (SDN) list? Membership
    check against 0xB10C's parsed per-chain lists. `chain` is 'ETH' or 'BTC'."""
    chain = (chain or "").upper()
    if chain not in ("ETH", "BTC"):
        return {"checked": False, "sanctioned": None, "error": "unsupported chain"}
    # The upstream list files Bitcoin as "XBT" (the ISO-style ticker), not "BTC".
    addrs, err, stale = _load_ofac_list("XBT" if chain == "BTC" else chain)
    if addrs is None:
        return {"checked": False, "sanctioned": None, "error": err}
    hit = (addr or "").strip().lower() in addrs
    note = "address appears on the OFAC sanctions list" if hit else None
    if stale:
        note = f"{note}. {stale}" if note else stale
    return {
        "checked": True, "sanctioned": hit, "chain": chain,
        "list_size": len(addrs),
        "source": "OFAC SDN (0xB10C mirror)",
        "stale": bool(stale),
        "note": note,
        "error": None,
    }


# ==========================================================================
# Discord snowflake -- decoded entirely offline (no network). A snowflake
# packs a millisecond timestamp (since the 2015 Discord epoch) plus the worker
# / process / per-ms increment that minted it. This tells you exactly when a
# Discord account / message / server was created.
# ==========================================================================
_DISCORD_EPOCH_MS = 1420070400000  # 2015-01-01T00:00:00Z


def discord_snowflake(sid: str) -> dict:
    s = (sid or "").strip()
    if not re.match(r"^\d{17,20}$", s):
        return {"input": sid, "ok": False, "error": "not a Discord snowflake (17-20 digits)"}
    n = int(s)
    ts_ms = (n >> 22) + _DISCORD_EPOCH_MS
    try:
        created = datetime.fromtimestamp(ts_ms / 1000, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return {"input": sid, "ok": False, "error": "snowflake timestamp out of range"}
    # A real Discord ID lands between the 2015 epoch and roughly now; anything
    # decoding to the far future is just an 18-digit number, not a snowflake.
    if created.year > datetime.now(timezone.utc).year + 1:
        return {"input": sid, "ok": False,
                "error": "decodes to an implausible date -- probably not a Discord ID"}
    return {
        "input": s, "ok": True,
        "created_utc": created.isoformat().replace("+00:00", "Z"),
        "created_ts_ms": ts_ms,
        "worker_id": (n >> 17) & 0x1F,
        "process_id": (n >> 12) & 0x1F,
        "increment": n & 0xFFF,
        "note": "decoded offline from the snowflake -- no network call",
        "error": None,
    }
