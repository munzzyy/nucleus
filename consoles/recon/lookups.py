"""Live OSINT lookup modules for the Recon console.

Stdlib only. Every outbound call goes through shared.common.fetch (SSRF-guarded)
or shared.common.dns_query (DNS-over-HTTPS) -- nothing here ever hits a
user-supplied host directly with urllib. Passive/public sources only: no
exploitation, no auth attempts, no active scanning.

Every external call is wrapped so a slow/dead API degrades to a null field
with an error note instead of blowing up the request -- a handler exception
still can't take the server down (common.py catches that too), but we want
partial results, not a wall of 500s when one of a dozen sources is offline.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import ipaddress
import json
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from shared import apikeys, common

FETCH_TIMEOUT = 5.0
KEYED_TIMEOUT = 6.0
DNS_TIMEOUT = 5.0
USERNAME_SITE_TIMEOUT = 6.0
USERNAME_CONCURRENCY = 8
USERNAME_BUDGET = 25.0  # overall wall-clock cap for the whole username scan

VAR_DIR = Path(__file__).resolve().parents[2] / "var"
HISTORY_FILE = VAR_DIR / "recon-scans.jsonl"
HISTORY_MAX = 500  # cap on-disk case history to a sane size

_UA_BROWSER = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# API keys all come from shared.apikeys.get_key() now -- one reader, one
# contract (env var first, else the gitignored var/.env, quotes stripped),
# used by hub Settings and every console alike. No local .env parser here
# anymore -- a second one only meant a quoted key from Settings could get
# sent to a provider verbatim (with the quotes) and 401 silently.


def _safe_fetch(url, **kw):
    """common.fetch() but never raises -- (status_or_None, body, headers, error)."""
    try:
        status, body, headers = common.fetch(url, **kw)
        return status, body, headers, None
    except (ValueError, OSError, TimeoutError) as e:
        return None, b"", {}, str(e)


def _fetch_text(url, headers=None, timeout=USERNAME_SITE_TIMEOUT, max_bytes=300_000):
    status, body, hdrs, err = _safe_fetch(url, timeout=timeout, headers=headers, max_bytes=max_bytes)
    text = body.decode("utf-8", "replace") if body else ""
    return status, text, hdrs, err


def _json_or_none(body: bytes):
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def _dns_query_ex(name: str, rtype: str, timeout: float = DNS_TIMEOUT) -> tuple[list[dict], bool]:
    """Like common.dns_query, but also reports whether the empty result is a
    total outage (BOTH DoH resolvers unreachable) vs. a genuine NXDOMAIN/NODATA
    answer. common.dns_query collapses that on purpose -- a bare [] is the
    right contract for the common case -- but recon wants to tell a caller
    "lookup failed" from "no such record" so the UI doesn't render a DNS
    outage as a clean "none". Walks the same public resolvers common.py uses,
    strictly through common.fetch (never raw urllib/socket).
    """
    name = (name or "").strip().rstrip(".")
    if not name:
        return [], False
    reached = False
    for base, accept in common._DOH_ENDPOINTS:
        url = f"{base}?name={quote(name)}&type={quote(rtype)}"
        headers = {"Accept": accept} if accept else {"Accept": "application/json"}
        try:
            status, body, _ = common.fetch(url, timeout=timeout, headers=headers)
        except (ValueError, OSError, TimeoutError):
            continue
        if status != 200:
            continue
        reached = True
        ans = (_json_or_none(body) or {}).get("Answer") or []
        if ans:
            return ans, False
    return [], not reached


def _keyed_note(status, err) -> str:
    """Human-readable failure note for a keyed source -- a bad/expired key or a
    rate limit must degrade to this, never a crash, never sink the rest of the
    module's scan."""
    if status is None:
        return err or "unreachable or timed out"
    if status in (401, 403):
        return "key invalid or rejected"
    if status == 429:
        return "rate-limited -- try again later"
    if status >= 500:
        return "provider error"
    return err or f"HTTP {status}"


def _geo_lookup(ip: str) -> dict | None:
    status, body, _, _ = _safe_fetch(f"http://ip-api.com/json/{quote(ip, safe='')}", timeout=FETCH_TIMEOUT)
    if status == 200:
        data = _json_or_none(body) or {}
        if data.get("status") == "success":
            return {
                "country": data.get("country"), "region": data.get("regionName"),
                "city": data.get("city"), "lat": data.get("lat"), "lon": data.get("lon"),
                "isp": data.get("isp"), "org": data.get("org"), "asn": data.get("as"),
                "source": "ip-api.com",
            }
    status, body, _, _ = _safe_fetch(f"https://ipwho.is/{quote(ip, safe='')}", timeout=FETCH_TIMEOUT)
    if status == 200:
        data = _json_or_none(body) or {}
        if data.get("success"):
            conn = data.get("connection") or {}
            return {
                "country": data.get("country"), "region": data.get("region"),
                "city": data.get("city"), "lat": data.get("latitude"), "lon": data.get("longitude"),
                "isp": conn.get("isp"), "org": conn.get("org"), "asn": conn.get("asn"),
                "source": "ipwho.is",
            }
    return None


# ==========================================================================
# 1. Username -- ~30 sites, thread-pooled, capped concurrency.
#
# Every checker returns {"found": True/False/None, "url": ..., "note": ...}.
# `None` means "couldn't confirm" -- several major platforms (X, Instagram,
# TikTok, Spotify, Twitch, Reddit) serve an identical client-rendered shell
# or bot-wall to every request regardless of whether the account exists, so
# a confident true/false there would just be a fabricated signal. We say so
# in the note instead of guessing.
# ==========================================================================
_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9-]{1,63}$")


def _c_github(u):
    url = f"https://api.github.com/users/{quote(u, safe='')}"
    status, body, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT,
                                        headers={"Accept": "application/vnd.github+json"},
                                        max_bytes=50_000)
    profile = f"https://github.com/{u}"
    if status == 200:
        data = _json_or_none(body) or {}
        enrich = {
            "name": data.get("name"), "bio": data.get("bio"),
            "public_repos": data.get("public_repos"), "followers": data.get("followers"),
            "created_at": data.get("created_at"), "blog": data.get("blog"),
            "location": data.get("location"),
        }
        return {"found": True, "url": profile, "note": "HTTP 200", "enrich": enrich}
    if status == 404:
        return {"found": False, "url": profile, "note": "HTTP 404"}
    return {"found": None, "url": profile, "note": err or f"HTTP {status}"}


def _c_github_gist(u):
    url = f"https://gist.github.com/{quote(u, safe='')}"
    status, _, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT)
    if status == 200:
        return {"found": True, "url": url, "note": "HTTP 200"}
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    return {"found": None, "url": url, "note": err or f"HTTP {status}"}


def _c_gitlab(u):
    url = f"https://gitlab.com/{quote(u, safe='')}"
    status, text, _, err = _fetch_text(url, headers={"User-Agent": _UA_BROWSER}, max_bytes=2000)
    if status == 200 and "Just a moment" not in text:
        return {"found": True, "url": url, "note": "HTTP 200"}
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    return {"found": None, "url": url, "note": "bot-challenge or unreachable"}


def _c_reddit(u):
    url = f"https://www.reddit.com/user/{quote(u, safe='')}/about.json"
    status, _, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT,
                                     headers={"User-Agent": "web:nucleus-recon:1.0 (by /u/nucleusrecon)"})
    profile = f"https://www.reddit.com/user/{u}/"
    if status == 200:
        return {"found": True, "url": profile, "note": "HTTP 200"}
    if status == 404:
        return {"found": False, "url": profile, "note": "HTTP 404"}
    return {"found": None, "url": profile, "note": "reddit bot-walls scripted requests (403)"}


def _c_youtube(u):
    url = f"https://www.youtube.com/@{quote(u, safe='')}"
    status, _, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT, headers={"User-Agent": _UA_BROWSER})
    if status == 200:
        return {"found": True, "url": url, "note": "HTTP 200"}
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    return {"found": None, "url": url, "note": err or f"HTTP {status}"}


def _c_keybase(u):
    url = f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={quote(u, safe='')}"
    status, body, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT)
    profile = f"https://keybase.io/{u}"
    if status == 200:
        data = _json_or_none(body) or {}
        them = data.get("them") or []
        found = bool(them) and them[0] is not None
        return {"found": found, "url": profile, "note": "Keybase lookup API"}
    return {"found": None, "url": profile, "note": err or f"HTTP {status}"}


def _c_medium(u):
    url = f"https://medium.com/@{quote(u, safe='')}"
    status, text, _, err = _fetch_text(url, headers={"User-Agent": _UA_BROWSER}, max_bytes=5000)
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    if status == 200:
        bare = '<title data-rh="true">Medium</title>' in text
        return {"found": not bare, "url": url,
                "note": "bare shell title = no profile" if bare else "profile title present"}
    return {"found": None, "url": url, "note": err or f"HTTP {status}"}


def _c_devto(u):
    url = f"https://dev.to/api/users/by_username?url={quote(u, safe='')}"
    status, _, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT)
    profile = f"https://dev.to/{u}"
    if status == 200:
        return {"found": True, "url": profile, "note": "dev.to API"}
    if status == 404:
        return {"found": False, "url": profile, "note": "dev.to API"}
    return {"found": None, "url": profile, "note": err or f"HTTP {status}"}


def _c_hackernews(u):
    url = f"https://hacker-news.firebaseio.com/v0/user/{quote(u, safe='')}.json"
    status, body, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT)
    profile = f"https://news.ycombinator.com/user?id={u}"
    if status == 200:
        return {"found": body.strip() != b"null", "url": profile, "note": "Firebase user API"}
    return {"found": None, "url": profile, "note": err or f"HTTP {status}"}


def _c_pastebin(u):
    url = f"https://pastebin.com/u/{quote(u, safe='')}"
    status, _, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT, headers={"User-Agent": _UA_BROWSER})
    if status == 200:
        return {"found": True, "url": url, "note": "HTTP 200"}
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    return {"found": None, "url": url, "note": err or f"HTTP {status}"}


def _c_gravatar(u):
    url = f"https://gravatar.com/{quote(u, safe='')}"
    status, _, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT, headers={"User-Agent": _UA_BROWSER})
    if status == 200:
        return {"found": True, "url": url, "note": "HTTP 200"}
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    return {"found": None, "url": url, "note": err or f"HTTP {status}"}


def _c_wikipedia(u):
    url = f"https://en.wikipedia.org/w/api.php?action=query&list=users&ususers={quote(u, safe='')}&format=json"
    status, body, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT)
    profile = f"https://en.wikipedia.org/wiki/User:{u}"
    if status == 200:
        data = _json_or_none(body) or {}
        users = ((data.get("query") or {}).get("users")) or []
        found = bool(users) and "missing" not in users[0]
        return {"found": found, "url": profile, "note": "Wikipedia user API"}
    return {"found": None, "url": profile, "note": err or f"HTTP {status}"}


def _c_soundcloud(u):
    url = f"https://soundcloud.com/{quote(u, safe='')}"
    status, _, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT, headers={"User-Agent": _UA_BROWSER})
    if status == 200:
        return {"found": True, "url": url, "note": "HTTP 200"}
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    return {"found": None, "url": url, "note": err or f"HTTP {status}"}


def _c_vimeo(u):
    url = f"https://vimeo.com/{quote(u, safe='')}"
    status, _, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT, headers={"User-Agent": _UA_BROWSER})
    if status == 200:
        return {"found": True, "url": url, "note": "HTTP 200"}
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    return {"found": None, "url": url, "note": err or f"HTTP {status}"}


def _c_flickr(u):
    url = f"https://www.flickr.com/people/{quote(u, safe='')}"
    status, _, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT, headers={"User-Agent": _UA_BROWSER})
    if status == 200:
        return {"found": True, "url": url, "note": "HTTP 200"}
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    return {"found": None, "url": url, "note": err or f"HTTP {status}"}


def _c_aboutme(u):
    url = f"https://about.me/{quote(u, safe='')}"
    status, _, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT, headers={"User-Agent": _UA_BROWSER})
    if status == 200:
        return {"found": True, "url": url, "note": "HTTP 200"}
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    return {"found": None, "url": url, "note": err or f"HTTP {status}"}


def _c_behance(u):
    url = f"https://www.behance.net/{quote(u, safe='')}"
    status, _, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT, headers={"User-Agent": _UA_BROWSER})
    if status == 200:
        return {"found": True, "url": url, "note": "HTTP 200"}
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    return {"found": None, "url": url, "note": err or f"HTTP {status}"}


def _c_dribbble(u):
    url = f"https://dribbble.com/{quote(u, safe='')}"
    status, _, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT, headers={"User-Agent": _UA_BROWSER})
    if status == 200:
        return {"found": True, "url": url, "note": "HTTP 200"}
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    return {"found": None, "url": url, "note": err or f"HTTP {status}"}


def _c_steam(u):
    url = f"https://steamcommunity.com/id/{quote(u, safe='')}"
    status, text, _, err = _fetch_text(url, headers={"User-Agent": _UA_BROWSER}, max_bytes=200_000)
    if status == 200:
        notfound = "The specified profile could not be found" in text
        return {"found": not notfound, "url": url, "note": "soft-404 signature check"}
    return {"found": None, "url": url, "note": err or f"HTTP {status}"}


def _c_patreon(u):
    url = f"https://www.patreon.com/{quote(u, safe='')}"
    status, _, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT, headers={"User-Agent": _UA_BROWSER})
    if status == 200:
        return {"found": True, "url": url, "note": "HTTP 200"}
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    return {"found": None, "url": url, "note": err or f"HTTP {status}"}


def _c_npm(u):
    url = f"https://registry.npmjs.org/-/v1/search?text=maintainer:{quote(u, safe='')}&size=1"
    status, body, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT)
    profile = f"https://www.npmjs.com/~{u}"
    if status == 200:
        data = _json_or_none(body) or {}
        found = bool(data.get("objects"))
        return {"found": found, "url": profile,
                "note": "best-effort: has published packages under this name "
                        "(npm's own profile pages are bot-walled, no direct existence check)"}
    return {"found": None, "url": profile, "note": err or f"HTTP {status}"}


def _c_pypi(u):
    url = f"https://pypi.org/user/{quote(u, safe='')}/"
    status, text, _, err = _fetch_text(url, headers={"User-Agent": _UA_BROWSER}, max_bytes=3000)
    if "Client Challenge" in text or "Just a moment" in text:
        return {"found": None, "url": url, "note": "bot-challenge page returned"}
    if status == 200:
        return {"found": True, "url": url, "note": "HTTP 200"}
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    return {"found": None, "url": url, "note": err or f"HTTP {status}"}


def _c_dockerhub(u):
    url = f"https://hub.docker.com/v2/users/{quote(u, safe='')}/"
    status, _, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT)
    profile = f"https://hub.docker.com/u/{u}"
    if status == 200:
        return {"found": True, "url": profile, "note": "Docker Hub API"}
    if status == 404:
        return {"found": False, "url": profile, "note": "Docker Hub API"}
    return {"found": None, "url": profile, "note": err or f"HTTP {status}"}


def _c_trello(u):
    url = f"https://trello.com/1/Members/{quote(u, safe='')}"
    status, _, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT)
    profile = f"https://trello.com/{u}"
    if status == 200:
        return {"found": True, "url": profile, "note": "Trello API"}
    if status == 404:
        return {"found": False, "url": profile, "note": "Trello API"}
    return {"found": None, "url": profile, "note": err or f"HTTP {status}"}


def _c_mastodon(u):
    url = f"https://mastodon.social/api/v1/accounts/lookup?acct={quote(u, safe='')}"
    status, _, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT)
    profile = f"https://mastodon.social/@{u}"
    if status == 200:
        return {"found": True, "url": profile, "note": "Mastodon API (mastodon.social instance only)"}
    if status == 404:
        return {"found": False, "url": profile, "note": "Mastodon API (mastodon.social instance only)"}
    return {"found": None, "url": profile, "note": err or f"HTTP {status}"}


def _c_tumblr(u):
    profile = f"https://{u}.tumblr.com/"
    if not _DNS_LABEL_RE.match(u):
        return {"found": None, "url": profile, "note": "username not usable as a subdomain label"}
    status, _, _, err = _safe_fetch(profile, timeout=USERNAME_SITE_TIMEOUT, headers={"User-Agent": _UA_BROWSER})
    if status is None:
        return {"found": False, "url": profile, "note": "blog subdomain does not resolve"}
    return {"found": True, "url": profile, "note": f"HTTP {status}"}


def _c_twitter(u):
    url = f"https://x.com/{quote(u, safe='')}"
    status, text, _, err = _fetch_text(url, headers={"User-Agent": _UA_BROWSER}, max_bytes=4000)
    if "doesn't exist" in text.lower() or "account doesn" in text.lower():
        return {"found": False, "url": url, "note": "not-found signature"}
    if status == 200:
        return {"found": None, "url": url,
                "note": "X serves an identical client-rendered shell for any handle -- can't confirm without JS"}
    return {"found": None, "url": url, "note": err or f"HTTP {status}"}


def _c_instagram(u):
    url = f"https://www.instagram.com/{quote(u, safe='')}/"
    status, text, _, err = _fetch_text(url, headers={"User-Agent": _UA_BROWSER}, max_bytes=300_000)
    low = text.lower()
    if status == 200 and f'"username":"{u.lower()}"' in low:
        return {"found": True, "url": url, "note": "username present in page data"}
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    return {"found": None, "url": url, "note": "Instagram bot-walls anonymous requests -- can't confirm"}


def _c_tiktok(u):
    url = f"https://www.tiktok.com/@{quote(u, safe='')}"
    status, text, _, err = _fetch_text(url, headers={"User-Agent": _UA_BROWSER}, max_bytes=300_000)
    if status == 200 and f'"uniqueId":"{u}"' in text:
        return {"found": True, "url": url, "note": "uniqueId present in page data"}
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    return {"found": None, "url": url, "note": "TikTok bot-walls anonymous requests -- can't confirm"}


def _c_telegram(u):
    url = f"https://t.me/{quote(u, safe='')}"
    status, text, _, err = _fetch_text(url, headers={"User-Agent": _UA_BROWSER}, max_bytes=8000)
    if status is None:
        return {"found": None, "url": url, "note": err or "unreachable"}
    if 'tgme_page_title' in text and u.lower() in text.lower():
        return {"found": True, "url": url, "note": "channel/user preview present"}
    if "If you have Telegram" in text:
        return {"found": False, "url": url, "note": "generic no-preview page"}
    return {"found": None, "url": url, "note": "ambiguous preview page"}


def _c_twitch(u):
    url = f"https://www.twitch.tv/{quote(u, safe='')}"
    status, text, _, err = _fetch_text(url, headers={"User-Agent": _UA_BROWSER}, max_bytes=250_000)
    if status == 200 and f'"login":"{u.lower()}"' in text.lower():
        return {"found": True, "url": url, "note": "login present in page data"}
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    return {"found": None, "url": url, "note": "Twitch is heavily client-rendered -- can't confirm without JS"}


def _c_spotify(u):
    url = f"https://open.spotify.com/user/{quote(u, safe='')}"
    status, _, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT, headers={"User-Agent": _UA_BROWSER})
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    return {"found": None, "url": url,
            "note": "Spotify serves a client-rendered shell for any user id -- can't confirm without JS"}


def _c_replit(u):
    url = f"https://replit.com/@{quote(u, safe='')}"
    status, _, _, err = _safe_fetch(url, timeout=USERNAME_SITE_TIMEOUT, headers={"User-Agent": _UA_BROWSER})
    if status == 404:
        return {"found": False, "url": url, "note": "HTTP 404"}
    return {"found": None, "url": url, "note": "Replit redirects profile views to login -- can't confirm"}


SITES: list[tuple[str, object]] = [
    ("GitHub", _c_github),
    ("GitHub Gist", _c_github_gist),
    ("GitLab", _c_gitlab),
    ("Reddit", _c_reddit),
    ("Twitter/X", _c_twitter),
    ("Instagram", _c_instagram),
    ("TikTok", _c_tiktok),
    ("YouTube", _c_youtube),
    ("Twitch", _c_twitch),
    ("Steam", _c_steam),
    ("Keybase", _c_keybase),
    ("Telegram", _c_telegram),
    ("Medium", _c_medium),
    ("Dev.to", _c_devto),
    ("Hacker News", _c_hackernews),
    ("Pastebin", _c_pastebin),
    ("Gravatar", _c_gravatar),
    ("Wikipedia", _c_wikipedia),
    ("SoundCloud", _c_soundcloud),
    ("Spotify", _c_spotify),
    ("Vimeo", _c_vimeo),
    ("Flickr", _c_flickr),
    ("About.me", _c_aboutme),
    ("Patreon", _c_patreon),
    ("Behance", _c_behance),
    ("Dribbble", _c_dribbble),
    ("npm", _c_npm),
    ("PyPI", _c_pypi),
    ("Docker Hub", _c_dockerhub),
    ("Replit", _c_replit),
    ("Trello", _c_trello),
    ("Mastodon", _c_mastodon),
    ("Tumblr", _c_tumblr),
]


def username_scan(u: str) -> dict:
    t0 = time.monotonic()
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=USERNAME_CONCURRENCY)
    results = []
    github_enrich = None
    try:
        futures = {ex.submit(fn, u): name for name, fn in SITES}
        done, not_done = concurrent.futures.wait(futures, timeout=USERNAME_BUDGET)
        for fut in done:
            name = futures[fut]
            try:
                r = fut.result()
            except Exception as e:  # a single site bug must not sink the scan
                r = {"found": None, "url": "", "note": f"error: {type(e).__name__}: {e}"}
            entry = {"site": name, "url": r.get("url", ""), "found": r.get("found"),
                      "note": r.get("note", "")}
            results.append(entry)
            if name == "GitHub" and r.get("enrich"):
                github_enrich = r["enrich"]
        for fut in not_done:
            results.append({"site": futures[fut], "url": "", "found": None, "note": "timed out"})
    finally:
        # wait=False + cancel_futures: don't block the response on slow
        # stragglers past the budget above; any still-running fetch just
        # finishes in the background and its result is discarded.
        ex.shutdown(wait=False, cancel_futures=True)

    order = {name: i for i, (name, _) in enumerate(SITES)}
    results.sort(key=lambda r: order.get(r["site"], 999))
    return {
        "input": u,
        "sites": results,
        "github": github_enrich,
        "found_count": sum(1 for r in results if r["found"] is True),
        "not_found_count": sum(1 for r in results if r["found"] is False),
        "unknown_count": sum(1 for r in results if r["found"] is None),
        "checked": len(results),
        "took_ms": round((time.monotonic() - t0) * 1000),
    }


# ==========================================================================
# 2. Email -- keyed source helpers
# ==========================================================================
def _hunter_email_verify(email: str, key: str) -> dict:
    status, body, _, err = _safe_fetch(
        f"https://api.hunter.io/v2/email-verifier?email={quote(email, safe='')}&api_key={quote(key, safe='')}",
        timeout=KEYED_TIMEOUT, max_bytes=100_000)
    if status == 200:
        data = (_json_or_none(body) or {}).get("data") or {}
        return {
            "ok": True, "result": data.get("result"), "score": data.get("score"),
            "disposable": data.get("disposable"), "webmail": data.get("webmail"),
            "mx_records": data.get("mx_records"), "error": None,
        }
    return {"ok": False, "error": _keyed_note(status, err)}


def _ipqs_email_lookup(email: str, key: str) -> dict:
    status, body, _, err = _safe_fetch(
        f"https://ipqualityscore.com/api/json/email/{quote(key, safe='')}/{quote(email, safe='')}",
        timeout=KEYED_TIMEOUT, max_bytes=100_000)
    if status == 200:
        data = _json_or_none(body) or {}
        if data.get("success") is False:
            return {"ok": False, "error": data.get("message") or "lookup failed"}
        return {
            "ok": True, "valid": data.get("valid"), "disposable": data.get("disposable"),
            "recent_abuse": data.get("recent_abuse"), "fraud_score": data.get("fraud_score"),
            "leaked": data.get("leaked"), "error": None,
        }
    return {"ok": False, "error": _keyed_note(status, err)}


def _hibp_lookup(email: str, key: str) -> dict:
    status, body, _, err = _safe_fetch(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='')}?truncateResponse=false",
        timeout=KEYED_TIMEOUT, max_bytes=200_000,
        headers={"hibp-api-key": key, "User-Agent": "nucleus-recon"})
    if status == 200:
        data = _json_or_none(body)
        breaches = [{
            "name": b.get("Name"), "date": b.get("BreachDate"), "data_classes": b.get("DataClasses") or [],
        } for b in (data if isinstance(data, list) else [])]
        return {"ok": True, "breach_count": len(breaches), "breaches": breaches, "error": None}
    if status == 404:
        return {"ok": True, "breach_count": 0, "breaches": [], "note": "no breaches on file", "error": None}
    return {"ok": False, "error": _keyed_note(status, err)}


def _leakcheck_lookup(email: str) -> dict:
    """LeakCheck's keyless public endpoint -- a second free breach oracle
    alongside XposedOrNot, since HIBP's breach-by-email lookup went paid-only
    in 2026. 1 req/sec, no auth. It only ever returns the breach SOURCE list
    (names + dates) and which FIELD CATEGORIES were exposed -- never the
    actual leaked values (password, address, etc) -- that's the entire design
    of the public tier, so the result is labeled that way for whoever reads it.
    """
    status, body, _, err = _safe_fetch(
        f"https://leakcheck.io/api/public?check={quote(email, safe='')}",
        timeout=FETCH_TIMEOUT, max_bytes=500_000)
    if status == 200:
        data = _json_or_none(body) or {}
        if data.get("success"):
            return {
                "ok": True, "found": data.get("found", 0),
                "sources": [{"name": s.get("name"), "date": s.get("date")}
                            for s in (data.get("sources") or [])],
                "fields": data.get("fields") or [],
                "note": "breach source names + exposed-field categories only -- "
                        "never the actual leaked field values (public tier)",
                "error": None,
            }
        # {"success": false, ...} on a 200 is LeakCheck's "no breaches on
        # file" response (it also returns this for a malformed query), not
        # a real error.
        return {"ok": True, "found": 0, "sources": [], "fields": [],
                "note": "no breaches on file", "error": None}
    if status == 429:
        return {"ok": False, "found": 0, "sources": [], "fields": [],
                "note": None, "error": "rate-limited (1 req/sec) -- try again shortly"}
    return {"ok": False, "found": 0, "sources": [], "fields": [],
            "note": None, "error": err or f"HTTP {status}"}


def email_scan(email: str) -> dict:
    domain = email.split("@", 1)[1] if "@" in email else ""
    result: dict = {"input": email, "domain": domain}

    # XposedOrNot -- simple breach list
    status, body, _, err = _safe_fetch(
        f"https://api.xposedornot.com/v1/check-email/{quote(email, safe='')}", timeout=FETCH_TIMEOUT)
    breaches_simple: list[str] = []
    if status in (200, 404):
        data = _json_or_none(body) or {}
        for group in data.get("breaches") or []:
            if isinstance(group, list):
                breaches_simple.extend(group)
        result["breach_check"] = {"ok": True, "breached": bool(breaches_simple),
                                   "breaches": breaches_simple, "error": None}
    else:
        result["breach_check"] = {"ok": False, "breached": False, "breaches": [],
                                   "error": err or f"HTTP {status}"}

    # XposedOrNot -- rich breach analytics
    status, body, _, err = _safe_fetch(
        f"https://api.xposedornot.com/v1/breach-analytics?email={quote(email, safe='')}", timeout=FETCH_TIMEOUT)
    if status == 200:
        data = _json_or_none(body) or {}
        risk_list = (data.get("BreachMetrics") or {}).get("risk") or [{}]
        risk0 = risk_list[0] if risk_list else {}
        details = ((data.get("ExposedBreaches") or {}).get("breaches_details")) or []
        pastes = data.get("ExposedPastes") or []
        result["breach_analytics"] = {
            "ok": True,
            "risk_label": risk0.get("risk_label"),
            "risk_score": risk0.get("risk_score"),
            "breach_count": len(details),
            "breaches": [{
                "name": d.get("breach"), "domain": d.get("domain"), "year": d.get("xposed_date"),
                "records": d.get("xposed_records"), "password_risk": d.get("password_risk"),
                "data_classes": [c for c in (d.get("xposed_data") or "").split(";") if c],
                "verified": d.get("verified"),
            } for d in details[:50]],
            "paste_count": len(pastes) if isinstance(pastes, list) else 0,
            "error": None,
        }
    elif status == 404:
        result["breach_analytics"] = {"ok": True, "risk_label": None, "risk_score": None,
                                       "breach_count": 0, "breaches": [], "paste_count": 0, "error": None}
    else:
        result["breach_analytics"] = {"ok": False, "risk_label": None, "risk_score": None,
                                       "breach_count": 0, "breaches": [], "paste_count": 0,
                                       "error": err or f"HTTP {status}"}

    # LeakCheck -- keyless, second breach oracle (HIBP's email breach lookup
    # is paid-only as of 2026; keep this top-level like the XposedOrNot
    # fields above, no key required, so it's not gated behind "keyed"/"unlock").
    result["leakcheck"] = _leakcheck_lookup(email)

    # Gravatar existence
    md5_hash = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    status, _, _, err = _safe_fetch(
        f"https://www.gravatar.com/avatar/{md5_hash}?d=404&s=200", timeout=FETCH_TIMEOUT)
    result["gravatar"] = {"checked": status is not None, "exists": status == 200,
                           "error": None if status is not None else err}

    # MX records
    try:
        mx, mx_unreachable = _dns_query_ex(domain, "MX", timeout=DNS_TIMEOUT) if domain else ([], False)
    except Exception as e:
        mx, mx_unreachable = [], True
        result.setdefault("mx_error", str(e))
    result["mx"] = [r.get("data") for r in mx if r.get("data")]
    result["has_mx"] = bool(result["mx"])
    # True only when BOTH DoH resolvers were unreachable for this query --
    # lets the UI show "lookup failed" instead of a false "no MX records".
    result["mx_unreachable"] = mx_unreachable

    keyed: dict = {}
    unlock: list[str] = []

    key = apikeys.get_key("HUNTER_API_KEY")
    if key:
        keyed["hunter"] = _hunter_email_verify(email, key)
    else:
        unlock.append("Add a Hunter.io key in Settings to verify deliverability and flag disposable/webmail addresses.")

    key = apikeys.get_key("IPQS_API_KEY")
    if key:
        keyed["ipqs"] = _ipqs_email_lookup(email, key)
    else:
        unlock.append("Add an IPQualityScore key in Settings for fraud score and leak detection on this email.")

    key = apikeys.get_key("HIBP_API_KEY")
    if key:
        keyed["hibp"] = _hibp_lookup(email, key)
    else:
        unlock.append("Add a Have I Been Pwned key in Settings for the authoritative breach list (the gold standard).")

    result["keyed"] = keyed
    result["unlock"] = unlock
    return result


# ==========================================================================
# 3. Domain
# ==========================================================================
_SECURITY_HEADERS = [
    ("Strict-Transport-Security", "hsts"),
    ("Content-Security-Policy", "csp"),
    ("X-Frame-Options", "x_frame_options"),
    ("X-Content-Type-Options", "x_content_type_options"),
    ("Referrer-Policy", "referrer_policy"),
]


# ==========================================================================
# 3. Domain -- keyed source helpers
# ==========================================================================
def _securitytrails_subdomains(d: str, key: str) -> tuple[set[str], str | None]:
    status, body, _, err = _safe_fetch(
        f"https://api.securitytrails.com/v1/domain/{quote(d, safe='')}/subdomains",
        timeout=KEYED_TIMEOUT, max_bytes=200_000, headers={"APIKEY": key})
    if status == 200:
        data = _json_or_none(body) or {}
        names = set()
        for sub in data.get("subdomains") or []:
            sub = (sub or "").strip().lower()
            if sub:
                names.add(f"{sub}.{d}")
        return names, None
    return set(), _keyed_note(status, err)


def _vt_domain_lookup(d: str, key: str) -> dict:
    status, body, _, err = _safe_fetch(
        f"https://www.virustotal.com/api/v3/domains/{quote(d, safe='')}",
        timeout=KEYED_TIMEOUT, max_bytes=300_000, headers={"x-apikey": key})
    if status == 200:
        data = _json_or_none(body) or {}
        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        cats = attrs.get("categories") or {}
        return {
            "ok": True, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0), "reputation": attrs.get("reputation"),
            "categories": list(cats.values())[:10], "error": None,
        }
    return {"ok": False, "error": _keyed_note(status, err)}


def _hunter_domain_search(d: str, key: str) -> dict:
    status, body, _, err = _safe_fetch(
        f"https://api.hunter.io/v2/domain-search?domain={quote(d, safe='')}&api_key={quote(key, safe='')}&limit=10",
        timeout=KEYED_TIMEOUT, max_bytes=200_000)
    if status == 200:
        data = (_json_or_none(body) or {}).get("data") or {}
        emails = data.get("emails") or []
        return {
            "ok": True, "organization": data.get("organization"), "pattern": data.get("pattern"),
            "email_count": len(emails),
            "emails": [{"value": e.get("value"), "type": e.get("type"), "confidence": e.get("confidence")}
                       for e in emails[:10]],
            "error": None,
        }
    return {"ok": False, "error": _keyed_note(status, err)}


def _whoisxml_lookup(d: str, key: str) -> dict:
    status, body, _, err = _safe_fetch(
        f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
        f"?apiKey={quote(key, safe='')}&domainName={quote(d, safe='')}&outputFormat=JSON",
        timeout=KEYED_TIMEOUT, max_bytes=200_000)
    if status == 200:
        data = _json_or_none(body) or {}
        rec = data.get("WhoisRecord") or {}
        err_msg = (rec.get("errorMessage") or {}).get("msg") or (data.get("ErrorMessage") or {}).get("msg")
        if err_msg:
            return {"ok": False, "error": err_msg}
        registrant = rec.get("registrant") or {}
        return {
            "ok": True, "registrar": rec.get("registrarName"), "created": rec.get("createdDate"),
            "updated": rec.get("updatedDate"), "expires": rec.get("expiresDate"),
            "registrant_org": registrant.get("organization"), "error": None,
        }
    return {"ok": False, "error": _keyed_note(status, err)}


def domain_scan(domain: str) -> dict:
    d = domain.lower().strip(".")
    result: dict = {"input": d}

    # DNS
    dns: dict = {}
    dns_unreachable: list[str] = []
    for rtype in ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA", "SOA", "SRV", "DNSKEY"):
        try:
            ans, unreachable = _dns_query_ex(d, rtype, timeout=DNS_TIMEOUT)
        except Exception:
            ans, unreachable = [], True
        dns[rtype] = sorted({a.get("data") for a in ans if a.get("data")})
        if unreachable:
            dns_unreachable.append(rtype)
    result["dns"] = dns
    # Record types where BOTH DoH resolvers were unreachable (vs. a genuine
    # empty/NXDOMAIN answer) -- the UI should render these as "lookup failed",
    # not silently as "none".
    result["dns_unreachable"] = dns_unreachable

    # RDAP whois (rdap.org redirects to the right RIR/registry; urllib follows it)
    status, body, _, err = _safe_fetch(f"https://rdap.org/domain/{quote(d, safe='')}", timeout=FETCH_TIMEOUT)
    if status == 200:
        data = _json_or_none(body) or {}
        registrar_name = None
        for ent in data.get("entities") or []:
            if "registrar" in (ent.get("roles") or []):
                vcard = ent.get("vcardArray")
                if isinstance(vcard, list) and len(vcard) > 1:
                    for field in vcard[1]:
                        if field and field[0] == "fn":
                            registrar_name = field[3]
        result["whois"] = {
            "ok": True, "handle": data.get("handle"), "status": data.get("status"),
            "registrar": registrar_name,
            "events": [{"action": e.get("eventAction"), "date": e.get("eventDate")}
                       for e in data.get("events") or []],
            "error": None,
        }
    else:
        result["whois"] = {"ok": False, "error": err or f"HTTP {status}"}

    # crt.sh certificate-transparency subdomains (notoriously flaky/rate-limited).
    # Busy domains return a multi-MB body; a whole-document json.loads that
    # lands mid-array on a truncated body fails silently and we'd report
    # "unavailable" for a domain that actually has plenty of data. Raise the
    # cap and fall back to parsing row-by-row (NDJSON-style) when the whole
    # body doesn't parse as one JSON list -- mirrors engine/osint_report.py's
    # crt.sh parser so both stay in sync.
    status, body, _, err = _safe_fetch(
        f"https://crt.sh/?q=%25.{quote(d, safe='')}&output=json", timeout=10.0, max_bytes=3_000_000)
    crt_names: set[str] = set()
    if status == 200:
        rows = _json_or_none(body)
        if not isinstance(rows, list):
            rows = []
            for line in body.decode("utf-8", "replace").splitlines():
                line = line.strip().strip(",")
                if not line:
                    continue
                row = _json_or_none(line.encode("utf-8"))
                if isinstance(row, dict):
                    rows.append(row)
        for row in rows:
            for n in (row.get("name_value") or "").split("\n"):
                n = n.strip().lstrip("*.").lower()
                if n and n.endswith(d):
                    crt_names.add(n)
        crt_error = None
    else:
        crt_error = err or f"HTTP {status} (crt.sh is often overloaded -- retry later)"

    # hackertarget hostsearch -- CSV `host,ip`. Free tier rate-limits with a
    # plain-text error body on a 200, so detect that instead of trusting status.
    status, body, _, err = _safe_fetch(
        f"https://api.hackertarget.com/hostsearch/?q={quote(d, safe='')}",
        timeout=FETCH_TIMEOUT, max_bytes=100_000)
    ht_hosts: list[dict] = []
    if status == 200:
        text = body.decode("utf-8", "replace").strip()
        if not text or "error" in text.lower() or "exceeded" in text.lower():
            ht_error = text[:200] or "empty response"
        else:
            ht_error = None
            for line in text.splitlines():
                host, _, ip = line.partition(",")
                host = host.strip().lower()
                if host and host.endswith(d):
                    ht_hosts.append({"host": host, "ip": ip.strip()})
    else:
        ht_error = err or f"HTTP {status}"

    # SecurityTrails full subdomain list (keyed) -- merges into the same set.
    securitytrails_key = apikeys.get_key("SECURITYTRAILS_API_KEY")
    st_names: set[str] = set()
    st_error: str | None = None
    if securitytrails_key:
        st_names, st_error = _securitytrails_subdomains(d, securitytrails_key)

    merged_names = crt_names | {h["host"] for h in ht_hosts} | st_names
    result["subdomains"] = {
        "ok": bool(merged_names) or (crt_error is None and ht_error is None),
        "count": len(merged_names), "names": sorted(merged_names)[:300],
        "crt_sh": {"ok": crt_error is None, "count": len(crt_names), "error": crt_error},
        "hackertarget": {"ok": ht_error is None, "count": len(ht_hosts),
                          "hosts": ht_hosts[:150], "error": ht_error},
        "securitytrails": {"ok": bool(securitytrails_key) and st_error is None,
                            "count": len(st_names),
                            "error": st_error if securitytrails_key else None},
    }

    # urlscan.io recent public scans -- a key (if set) only raises submit/search
    # limits, the keyless search already works, so this stays best-effort.
    urlscan_key = apikeys.get_key("URLSCAN_API_KEY")
    status, body, _, err = _safe_fetch(
        f"https://urlscan.io/api/v1/search/?q=domain:{quote(d, safe='')}&size=5",
        timeout=FETCH_TIMEOUT, max_bytes=300_000,
        headers={"API-Key": urlscan_key} if urlscan_key else None)
    if status == 200:
        data = _json_or_none(body) or {}
        scans = []
        for r in (data.get("results") or [])[:5]:
            page = r.get("page") or {}
            task = r.get("task") or {}
            scans.append({
                "url": page.get("url"), "ip": page.get("ip"),
                "time": task.get("time"), "screenshot": r.get("screenshot"),
            })
        result["urlscan"] = {"ok": True, "count": len(scans), "scans": scans, "error": None}
    else:
        result["urlscan"] = {"ok": False, "count": 0, "scans": [], "error": err or f"HTTP {status}"}

    # AlienVault OTX reputation (community threat-intel pulses mentioning this domain)
    status, body, _, err = _safe_fetch(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(d, safe='')}/general",
        timeout=FETCH_TIMEOUT, max_bytes=300_000)
    if status == 200:
        data = _json_or_none(body) or {}
        pulse_info = data.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        result["otx"] = {"ok": True, "pulse_count": pulse_info.get("count", 0),
                          "pulse_names": [p.get("name") for p in pulses[:5] if p.get("name")],
                          "error": None}
    else:
        result["otx"] = {"ok": False, "pulse_count": 0, "pulse_names": [], "error": err or f"HTTP {status}"}

    # Wayback availability
    status, body, _, err = _safe_fetch(
        f"https://archive.org/wayback/available?url={quote(d, safe='')}", timeout=FETCH_TIMEOUT)
    if status == 200:
        data = _json_or_none(body) or {}
        snap = (data.get("archived_snapshots") or {}).get("closest") or {}
        result["wayback"] = {"ok": True, "archived": bool(snap), "url": snap.get("url"),
                              "timestamp": snap.get("timestamp"), "error": None}
    else:
        result["wayback"] = {"ok": False, "archived": False, "error": err or f"HTTP {status}"}

    # SPF / DMARC posture
    spf_txt = [t for t in dns.get("TXT", []) if "v=spf1" in (t or "").lower()]
    try:
        dmarc_ans, dmarc_unreachable = _dns_query_ex(f"_dmarc.{d}", "TXT", timeout=DNS_TIMEOUT)
    except Exception:
        dmarc_ans, dmarc_unreachable = [], True
    dmarc_txt = [a.get("data") for a in dmarc_ans
                 if a.get("data") and "v=dmarc1" in a.get("data", "").lower()]
    result["email_posture"] = {
        "spf_present": bool(spf_txt), "spf": spf_txt[0] if spf_txt else None,
        "dmarc_present": bool(dmarc_txt), "dmarc": dmarc_txt[0] if dmarc_txt else None,
        "dmarc_unreachable": dmarc_unreachable,
    }

    # Live HTTP fetch: status, server/tech headers, security-header score
    http_info = {"ok": False, "error": "no response on http or https"}
    for scheme in ("https", "http"):
        status, body, hdrs, err = _safe_fetch(f"{scheme}://{d}/", timeout=FETCH_TIMEOUT, max_bytes=100_000)
        if status is not None:
            hdr_lower = {k.lower(): v for k, v in hdrs.items()}
            sec_headers = {key: (hname.lower() in hdr_lower) for hname, key in _SECURITY_HEADERS}
            http_info = {
                "ok": True, "scheme": scheme, "status": status,
                "server": hdr_lower.get("server"), "powered_by": hdr_lower.get("x-powered-by"),
                "security_headers": sec_headers,
                "security_score": f"{sum(sec_headers.values())}/{len(_SECURITY_HEADERS)}",
                "error": None,
            }
            break
        http_info = {"ok": False, "error": err}
    result["http"] = http_info

    # Hosting chain: apex A (falling back to AAAA for an IPv6-only apex) -> IP
    # -> InternetDB (ports/CVEs) + geo
    hosting = {"ip": None, "ports": [], "cves": [], "hostnames": [], "tags": [], "geo": None, "error": None}
    a_records = dns.get("A") or dns.get("AAAA") or []
    if a_records:
        ip = a_records[0]
        hosting["ip"] = ip
        status, body, _, err = _safe_fetch(f"https://internetdb.shodan.io/{ip}", timeout=FETCH_TIMEOUT)
        if status == 200:
            idb = _json_or_none(body) or {}
            hosting["ports"] = idb.get("ports", [])
            hosting["cves"] = idb.get("vulns", [])
            hosting["hostnames"] = idb.get("hostnames", [])
            hosting["tags"] = idb.get("tags", [])
        elif status is not None:
            hosting["error"] = f"internetdb HTTP {status}"
        hosting["geo"] = _geo_lookup(ip)
    else:
        hosting["error"] = "no A or AAAA record to resolve"
    result["hosting"] = hosting

    keyed: dict = {}
    unlock: list[str] = []

    if not urlscan_key:
        unlock.append("Add a urlscan.io key in Settings for higher submit/search limits (keyless search already works).")

    if securitytrails_key:
        keyed["securitytrails"] = {"ok": st_error is None, "count": len(st_names), "error": st_error}
    else:
        unlock.append("Add a SecurityTrails key in Settings for a deeper subdomain list + DNS history.")

    key = apikeys.get_key("VT_API_KEY")
    if key:
        keyed["virustotal"] = _vt_domain_lookup(d, key)
    else:
        unlock.append("Add a VirusTotal key in Settings for domain reputation and AV categorization.")

    key = apikeys.get_key("HUNTER_API_KEY")
    if key:
        keyed["hunter"] = _hunter_domain_search(d, key)
    else:
        unlock.append("Add a Hunter.io key in Settings to find corporate email addresses for this domain.")

    key = apikeys.get_key("WHOISXML_API_KEY")
    if key:
        keyed["whoisxml"] = _whoisxml_lookup(d, key)
    else:
        unlock.append("Add a WhoisXML key in Settings for clean structured WHOIS data.")

    result["keyed"] = keyed
    result["unlock"] = unlock
    return result


# ==========================================================================
# 4. IP -- keyed source helpers (each only ever called when its key is set)
# ==========================================================================
def _ipinfo_lookup(ip: str, key: str) -> dict:
    status, body, _, err = _safe_fetch(
        f"https://ipinfo.io/{quote(ip, safe='')}/json?token={quote(key, safe='')}",
        timeout=KEYED_TIMEOUT, max_bytes=50_000)
    if status == 200:
        data = _json_or_none(body) or {}
        privacy = data.get("privacy") or {}
        org = data.get("org") or ""
        return {
            "ok": True, "org": org or None,
            "asn": org.split(" ", 1)[0] if org.startswith("AS") else None,
            "city": data.get("city"), "region": data.get("region"), "country": data.get("country"),
            "vpn": privacy.get("vpn"), "proxy": privacy.get("proxy"), "tor": privacy.get("tor"),
            "hosting": privacy.get("hosting"),
            "abuse_contact": (data.get("abuse") or {}).get("address"),
            "error": None,
        }
    return {"ok": False, "error": _keyed_note(status, err)}


def _vt_ip_lookup(ip: str, key: str) -> dict:
    status, body, _, err = _safe_fetch(
        f"https://www.virustotal.com/api/v3/ip_addresses/{quote(ip, safe='')}",
        timeout=KEYED_TIMEOUT, max_bytes=300_000, headers={"x-apikey": key})
    if status == 200:
        data = _json_or_none(body) or {}
        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        return {
            "ok": True, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0), "as_owner": attrs.get("as_owner"),
            "country": attrs.get("country"), "reputation": attrs.get("reputation"), "error": None,
        }
    return {"ok": False, "error": _keyed_note(status, err)}


def _abuseipdb_lookup(ip: str, key: str) -> dict:
    status, body, _, err = _safe_fetch(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={quote(ip, safe='')}&maxAgeInDays=90",
        timeout=KEYED_TIMEOUT, max_bytes=100_000,
        headers={"Key": key, "Accept": "application/json"})
    if status == 200:
        data = (_json_or_none(body) or {}).get("data") or {}
        return {
            "ok": True, "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"), "usage_type": data.get("usageType"),
            "isp": data.get("isp"), "domain": data.get("domain"), "error": None,
        }
    return {"ok": False, "error": _keyed_note(status, err)}


def _greynoise_lookup(ip: str, key: str) -> dict:
    status, body, _, err = _safe_fetch(
        f"https://api.greynoise.io/v3/community/{quote(ip, safe='')}",
        timeout=KEYED_TIMEOUT, max_bytes=50_000, headers={"key": key})
    if status == 200:
        data = _json_or_none(body) or {}
        return {
            "ok": True, "noise": data.get("noise"), "riot": data.get("riot"),
            "classification": data.get("classification"), "name": data.get("name"),
            "last_seen": data.get("last_seen"), "note": None, "error": None,
        }
    if status == 404:
        return {"ok": True, "noise": False, "riot": False, "classification": None, "name": None,
                "last_seen": None, "note": "not seen scanning the internet (clean)", "error": None}
    return {"ok": False, "error": _keyed_note(status, err)}


def _shodan_host_lookup(ip: str, key: str) -> dict:
    status, body, _, err = _safe_fetch(
        f"https://api.shodan.io/shodan/host/{quote(ip, safe='')}?key={quote(key, safe='')}",
        timeout=KEYED_TIMEOUT, max_bytes=700_000)
    if status == 200:
        data = _json_or_none(body) or {}
        if data is None:
            return {"ok": False, "error": "response too large to parse -- try again"}
        ports = sorted(set(data.get("ports") or []))
        vulns = sorted(set(data.get("vulns") or []))[:30]
        return {
            "ok": True, "org": data.get("org"), "os": data.get("os"),
            "hostnames": data.get("hostnames") or [], "ports": ports, "vulns": vulns, "error": None,
        }
    if status == 404:
        return {"ok": True, "org": None, "os": None, "hostnames": [], "ports": [], "vulns": [],
                "note": "no data on file for this IP", "error": None}
    return {"ok": False, "error": _keyed_note(status, err)}


def _ipqs_ip_lookup(ip: str, key: str) -> dict:
    status, body, _, err = _safe_fetch(
        f"https://ipqualityscore.com/api/json/ip/{quote(key, safe='')}/{quote(ip, safe='')}",
        timeout=KEYED_TIMEOUT, max_bytes=100_000)
    if status == 200:
        data = _json_or_none(body) or {}
        if data.get("success") is False:
            return {"ok": False, "error": data.get("message") or "lookup failed"}
        return {
            "ok": True, "fraud_score": data.get("fraud_score"), "proxy": data.get("proxy"),
            "vpn": data.get("vpn"), "tor": data.get("tor"), "recent_abuse": data.get("recent_abuse"),
            "error": None,
        }
    return {"ok": False, "error": _keyed_note(status, err)}


def _reverse_dns_name(ipobj) -> str:
    """Build the PTR query name for an IP: x.x.x.x.in-addr.arpa for v4, the
    reversed-nibble form under ip6.arpa for v6."""
    if ipobj.version == 4:
        return ".".join(reversed(str(ipobj).split("."))) + ".in-addr.arpa"
    nibbles = ipobj.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".ip6.arpa"


def ip_scan(ip: str) -> dict:
    try:
        ipobj = ipaddress.ip_address(ip)
    except ValueError:
        return {"input": ip, "error": "not a valid IP address"}

    result: dict = {"input": ip, "version": ipobj.version}

    status, body, _, err = _safe_fetch(f"https://internetdb.shodan.io/{quote(ip, safe='')}", timeout=FETCH_TIMEOUT)
    if status == 200:
        data = _json_or_none(body) or {}
        result["internetdb"] = {"ok": True, "ports": data.get("ports", []), "cves": data.get("vulns", []),
                                 "hostnames": data.get("hostnames", []), "tags": data.get("tags", []),
                                 "cpes": data.get("cpes", []), "error": None}
    elif status == 404:
        result["internetdb"] = {"ok": True, "ports": [], "cves": [], "hostnames": [], "tags": [],
                                 "cpes": [], "error": None, "note": "no data on file for this IP"}
    else:
        result["internetdb"] = {"ok": False, "error": err or f"HTTP {status}"}

    result["geo"] = _geo_lookup(ip)

    # Reverse DNS (PTR) over DoH -- NOT socket.gethostbyaddr(), which hits the
    # system resolver: that leaks the queried IP straight to the ISP/system
    # DNS (defeating the whole encrypted-DoH passive design) and has no
    # timeout of its own, so it can block a worker for the resolver's full
    # timeout. This stays on the same encrypted, timeout-bounded path as
    # every other lookup in this file.
    try:
        ptr_ans, ptr_unreachable = _dns_query_ex(_reverse_dns_name(ipobj), "PTR", timeout=DNS_TIMEOUT)
    except Exception:
        ptr_ans, ptr_unreachable = [], True
    hostnames = [h for h in ((a.get("data") or "").rstrip(".") for a in ptr_ans) if h]
    if ptr_unreachable:
        result["reverse_dns"] = {
            "ok": False, "hostname": None, "hostnames": [], "unreachable": True,
            "error": "PTR lookup failed -- both DoH resolvers unreachable",
        }
    else:
        result["reverse_dns"] = {
            "ok": True, "hostname": hostnames[0] if hostnames else None,
            "hostnames": hostnames, "unreachable": False, "error": None,
        }
        if not hostnames:
            result["reverse_dns"]["note"] = "no PTR record on file"

    status, body, _, err = _safe_fetch(f"https://rdap.org/ip/{quote(ip, safe='')}", timeout=FETCH_TIMEOUT)
    if status == 200:
        data = _json_or_none(body) or {}
        result["rdap"] = {"ok": True, "start": data.get("startAddress"), "end": data.get("endAddress"),
                           "name": data.get("name"), "type": data.get("type"),
                           "country": data.get("country"), "error": None}
    else:
        result["rdap"] = {"ok": False, "error": err or f"HTTP {status}"}

    status, body, _, err = _safe_fetch(
        f"https://onionoo.torproject.org/details?search={quote(ip, safe='')}"
        "&fields=nickname,flags,exit_addresses,running", timeout=FETCH_TIMEOUT)
    if status == 200:
        data = _json_or_none(body) or {}
        relays = data.get("relays") or []  # empty list is a valid "not a relay" answer, not a 404
        is_exit = any("Exit" in (r.get("flags") or []) or r.get("exit_addresses") for r in relays)
        result["tor"] = {
            "ok": True, "is_relay": bool(relays), "is_exit": is_exit,
            "relays": [{"nickname": r.get("nickname"), "flags": r.get("flags"), "running": r.get("running")}
                       for r in relays[:10]],
            "error": None,
        }
    else:
        result["tor"] = {"ok": False, "error": err or f"HTTP {status}"}

    otx_type = "IPv4" if ipobj.version == 4 else "IPv6"
    status, body, _, err = _safe_fetch(
        f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{quote(ip, safe='')}/general",
        timeout=FETCH_TIMEOUT, max_bytes=300_000)
    if status == 200:
        data = _json_or_none(body) or {}
        pulse_info = data.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        result["otx"] = {"ok": True, "pulse_count": pulse_info.get("count", 0),
                          "pulse_names": [p.get("name") for p in pulses[:5] if p.get("name")],
                          "error": None}
    else:
        result["otx"] = {"ok": False, "pulse_count": 0, "pulse_names": [], "error": err or f"HTTP {status}"}

    # Keyed sources -- each only runs when its free API key is present in
    # Settings; otherwise it's skipped and surfaced as an "unlock" hint so
    # Cole knows exactly which key would turn it on.
    keyed: dict = {}
    unlock: list[str] = []

    key = apikeys.get_key("IPINFO_TOKEN")
    if key:
        keyed["ipinfo"] = _ipinfo_lookup(ip, key)
    else:
        unlock.append("Add an IPinfo key in Settings for precise geo, ASN/org, and VPN/proxy/Tor detection.")

    key = apikeys.get_key("VT_API_KEY")
    if key:
        keyed["virustotal"] = _vt_ip_lookup(ip, key)
    else:
        unlock.append("Add a VirusTotal key in Settings for IP reputation and AV detections.")

    key = apikeys.get_key("ABUSEIPDB_API_KEY")
    if key:
        keyed["abuseipdb"] = _abuseipdb_lookup(ip, key)
    else:
        unlock.append("Add an AbuseIPDB key in Settings for abuse confidence score and report count.")

    key = apikeys.get_key("GREYNOISE_API_KEY")
    if key:
        keyed["greynoise"] = _greynoise_lookup(ip, key)
    else:
        unlock.append("Add a GreyNoise key in Settings to see if this IP is known internet background noise.")

    key = apikeys.get_key("SHODAN_API_KEY")
    if key:
        keyed["shodan"] = _shodan_host_lookup(ip, key)
    else:
        unlock.append("Add a Shodan key in Settings for full host data (banners, org, OS, vulns) beyond InternetDB.")

    key = apikeys.get_key("IPQS_API_KEY")
    if key:
        keyed["ipqs"] = _ipqs_ip_lookup(ip, key)
    else:
        unlock.append("Add an IPQualityScore key in Settings for fraud score and proxy/VPN/Tor detection.")

    result["keyed"] = keyed
    result["unlock"] = unlock
    return result


# ==========================================================================
# 5. Phone
# ==========================================================================
_COUNTRY_CODES = {
    "1": "US/Canada", "44": "UK", "33": "France", "49": "Germany", "34": "Spain",
    "39": "Italy", "31": "Netherlands", "32": "Belgium", "41": "Switzerland",
    "46": "Sweden", "47": "Norway", "45": "Denmark", "351": "Portugal",
    "353": "Ireland", "48": "Poland", "420": "Czechia", "43": "Austria",
    "61": "Australia", "64": "New Zealand", "81": "Japan", "82": "South Korea",
    "86": "China", "91": "India", "92": "Pakistan", "234": "Nigeria",
    "27": "South Africa", "20": "Egypt", "971": "UAE", "966": "Saudi Arabia",
    "7": "Russia/Kazakhstan", "55": "Brazil", "52": "Mexico", "54": "Argentina",
    "56": "Chile", "57": "Colombia", "60": "Malaysia", "62": "Indonesia",
    "63": "Philippines", "65": "Singapore", "66": "Thailand", "84": "Vietnam",
    "852": "Hong Kong", "886": "Taiwan", "972": "Israel", "90": "Turkey",
    "380": "Ukraine",
}


def _guess_country(digits_with_plus: str) -> str | None:
    if not digits_with_plus.startswith("+"):
        return None
    digits = digits_with_plus[1:]
    for length in (3, 2, 1):
        code = digits[:length]
        if code in _COUNTRY_CODES:
            return _COUNTRY_CODES[code]
    return None


def _ipqs_phone_lookup(digits: str, key: str) -> dict:
    phone = digits.lstrip("+")
    status, body, _, err = _safe_fetch(
        f"https://ipqualityscore.com/api/json/phone/{quote(key, safe='')}/{quote(phone, safe='')}",
        timeout=KEYED_TIMEOUT, max_bytes=100_000)
    if status == 200:
        data = _json_or_none(body) or {}
        if data.get("success") is False:
            return {"ok": False, "error": data.get("message") or "lookup failed"}
        return {
            "ok": True, "valid": data.get("valid"), "active": data.get("active"),
            "carrier": data.get("carrier"), "line_type": data.get("line_type"),
            "fraud_score": data.get("fraud_score"), "risky": data.get("risky"), "error": None,
        }
    return {"ok": False, "error": _keyed_note(status, err)}


def phone_scan(number: str) -> dict:
    digits = re.sub(r"[^\d+]", "", number)
    result: dict = {
        "input": number, "normalized": digits,
        "country_guess": _guess_country(digits),
        "digit_count": len(re.sub(r"\D", "", digits)),
    }

    api_key = apikeys.get_key("NUMLOOKUP_API_KEY")
    if not api_key:
        result["lookup"] = {
            "ok": False, "configured": False,
            "note": "NUMLOOKUP_API_KEY not set (env var or var/.env) -- "
                    "live carrier/line-type lookup skipped, showing parsed data only",
        }
    else:
        if digits.startswith("+"):
            url = f"https://api.numlookupapi.com/v1/validate/{quote(digits, safe='+')}"
        else:
            url = f"https://api.numlookupapi.com/v1/validate/{quote(digits, safe='')}?country_code=US"
        status, body, _, err = _safe_fetch(url, timeout=FETCH_TIMEOUT, headers={"apikey": api_key})
        if status == 200:
            data = _json_or_none(body) or {}
            result["lookup"] = {
                "ok": True, "configured": True, "valid": data.get("valid"),
                "carrier": data.get("carrier"), "line_type": data.get("line_type"),
                "location": data.get("location"), "country_name": data.get("country_name"),
                "international_format": data.get("international_format"),
                "local_format": data.get("local_format"),
            }
        elif status == 401:
            data = _json_or_none(body) or {}
            result["lookup"] = {"ok": False, "configured": True,
                                 "error": data.get("message") or "unauthorized"}
        else:
            result["lookup"] = {"ok": False, "configured": True, "error": err or f"HTTP {status}"}

    keyed: dict = {}
    unlock: list[str] = []
    key = apikeys.get_key("IPQS_API_KEY")
    if key:
        keyed["ipqs"] = _ipqs_phone_lookup(digits, key)
    else:
        unlock.append("Add an IPQualityScore key in Settings for carrier, line type, and fraud score.")
    result["keyed"] = keyed
    result["unlock"] = unlock
    return result


# ==========================================================================
# 6. Hash -- known-file lookup against CIRCL hashlookup (NSRL + malware sets)
# ==========================================================================
_HASH_ALGO_BY_LEN = {32: "md5", 40: "sha1", 64: "sha256"}


def _vt_hash_lookup(h: str, key: str) -> dict:
    status, body, _, err = _safe_fetch(
        f"https://www.virustotal.com/api/v3/files/{quote(h, safe='')}",
        timeout=KEYED_TIMEOUT, max_bytes=300_000, headers={"x-apikey": key})
    if status == 200:
        data = _json_or_none(body) or {}
        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        ptc = attrs.get("popular_threat_classification") or {}
        return {
            "ok": True, "malicious": stats.get("malicious", 0),
            "total": sum(stats.values()) if stats else 0,
            "meaningful_name": attrs.get("meaningful_name"),
            "type_description": attrs.get("type_description"),
            "threat_label": ptc.get("suggested_threat_label"), "error": None,
        }
    if status == 404:
        return {"ok": True, "malicious": 0, "total": 0, "note": "not found in VirusTotal", "error": None}
    return {"ok": False, "error": _keyed_note(status, err)}


def hash_scan(h: str) -> dict:
    h = h.strip().lower()
    algo = _HASH_ALGO_BY_LEN.get(len(h))
    if not algo:
        return {"input": h, "algo": None, "known": None, "error": "unrecognized hash length"}

    status, body, _, err = _safe_fetch(
        f"https://hashlookup.circl.lu/lookup/{algo}/{quote(h, safe='')}",
        timeout=FETCH_TIMEOUT, max_bytes=50_000)
    if status == 200:
        data = _json_or_none(body) or {}
        result = {
            "input": h, "algo": algo, "known": True,
            "filename": data.get("FileName") or data.get("hashlookup:parent-name"),
            "size": data.get("FileSize"),
            "source": data.get("source") or data.get("hashlookup:source"),
            "trust": data.get("hashlookup:trust"),
            "md5": data.get("MD5"), "sha1": data.get("SHA-1"), "sha256": data.get("SHA-256"),
            "error": None,
        }
    elif status == 404:
        result = {"input": h, "algo": algo, "known": False, "error": None,
                   "note": "not present in CIRCL hashlookup (NSRL known-file + malware corpora)"}
    else:
        result = {"input": h, "algo": algo, "known": None, "error": err or f"HTTP {status}"}

    keyed: dict = {}
    unlock: list[str] = []
    key = apikeys.get_key("VT_API_KEY")
    if key:
        keyed["virustotal"] = _vt_hash_lookup(h, key)
    else:
        unlock.append("Add a VirusTotal key in Settings for AV detection ratio and threat classification.")
    result["keyed"] = keyed
    result["unlock"] = unlock
    return result


def _balanced_json_value(text: str, start: int) -> str | None:
    """From `text[start]` (a '{' or '['), return the balanced substring up to
    its matching close, or None if it's cut off (i.e. a truncated body)."""
    if start >= len(text) or text[start] not in "{[":
        return None
    open_ch = text[start]
    close_ch = "}" if open_ch == "{" else "]"
    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def _partial_ethplorer_parse(text: str) -> tuple[dict, list[dict], bool]:
    """Best-effort recovery when a huge Ethplorer response got cut off by our
    byte cap. `"ETH"` sits near the top of the document so it almost always
    survives intact even when the (potentially enormous) `"tokens"` array
    doesn't; a naive whole-document json.loads would lose both. Walk the
    tokens array element-by-element so a truncated tail just stops early
    instead of poisoning the whole parse. Returns (eth, tokens[:15], any_cut).
    """
    eth: dict = {}
    idx = text.find('"ETH"')
    if idx != -1:
        brace = text.find("{", idx)
        chunk = _balanced_json_value(text, brace) if brace != -1 else None
        if chunk:
            eth = _json_or_none(chunk.encode("utf-8")) or {}

    tokens: list[dict] = []
    cut = True
    idx = text.find('"tokens"')
    if idx != -1:
        bracket = text.find("[", idx)
        if bracket != -1:
            i, n = bracket + 1, len(text)
            while i < n and len(tokens) < 15:
                while i < n and text[i] in " \t\r\n,":
                    i += 1
                if i < n and text[i] == "]":
                    cut = False
                    break
                if i >= n or text[i] != "{":
                    break
                chunk = _balanced_json_value(text, i)
                if chunk is None:
                    break  # element itself got truncated -- stop, don't guess
                tok = _json_or_none(chunk.encode("utf-8"))
                if tok is not None:
                    tokens.append(tok)
                i += len(chunk)
    return eth, tokens, cut


# ==========================================================================
# 7. Crypto address -- BTC via blockchain.info, ETH via Ethplorer
# ==========================================================================
def crypto_scan(addr: str) -> dict:
    if addr.lower().startswith("0x"):
        status, body, _, err = _safe_fetch(
            f"https://api.ethplorer.io/getAddressInfo/{quote(addr, safe='')}?apiKey=freekey",
            timeout=FETCH_TIMEOUT, max_bytes=200_000)
        if status == 200:
            data = _json_or_none(body)
            truncated = False
            if data is not None:
                eth = data.get("ETH") or {}
                tokens = data.get("tokens") or []
                token_count = len(tokens)
            else:
                # Ethplorer can return 400KB+ for busy wallets and our cap
                # can land mid-token-array -- recover balance + a few token
                # names from what we did get instead of losing everything.
                text = body.decode("utf-8", "replace")
                eth, tokens, truncated = _partial_ethplorer_parse(text)
                token_count = len(tokens) if not truncated else None
            token_list = [{
                "name": (t.get("tokenInfo") or {}).get("name"),
                "symbol": (t.get("tokenInfo") or {}).get("symbol"),
                "balance": t.get("balance"),
            } for t in tokens[:15]]
            return {
                "input": addr, "chain": "ETH", "ok": True,
                "balance_eth": eth.get("balance"),
                "total_in_eth": eth.get("totalIn"), "total_out_eth": eth.get("totalOut"),
                "token_count": token_count, "tokens": token_list,
                "note": ("response was larger than our size cap -- showing balance + "
                         f"first {len(token_list)} token(s), count may be incomplete") if truncated else None,
                "error": None,
            }
        if status == 404:
            return {"input": addr, "chain": "ETH", "ok": True, "balance_eth": 0,
                    "total_in_eth": None, "total_out_eth": None, "token_count": 0, "tokens": [],
                    "note": "no on-chain activity on file", "error": None}
        return {"input": addr, "chain": "ETH", "ok": False, "error": err or f"HTTP {status}"}

    status, body, _, err = _safe_fetch(
        f"https://blockchain.info/rawaddr/{quote(addr, safe='')}?limit=0",
        timeout=FETCH_TIMEOUT, max_bytes=300_000)
    if status == 200:
        data = _json_or_none(body) or {}
        sat = 100_000_000
        return {
            "input": addr, "chain": "BTC", "ok": True,
            "balance_btc": round((data.get("final_balance") or 0) / sat, 8),
            "total_received_btc": round((data.get("total_received") or 0) / sat, 8),
            "total_sent_btc": round((data.get("total_sent") or 0) / sat, 8),
            "n_tx": data.get("n_tx"), "note": None, "error": None,
        }
    if status == 404:
        return {"input": addr, "chain": "BTC", "ok": True, "balance_btc": 0, "n_tx": 0,
                "total_received_btc": 0, "total_sent_btc": 0,
                "note": "address not found / no activity", "error": None}
    return {"input": addr, "chain": "BTC", "ok": False, "error": err or f"HTTP {status}"}


# ==========================================================================
# 8. MAC address -- OUI vendor lookup via macvendors.com
# ==========================================================================
def mac_scan(mac: str) -> dict:
    m = mac.strip()
    status, body, _, err = _safe_fetch(
        f"https://api.macvendors.com/{quote(m, safe='')}", timeout=FETCH_TIMEOUT, max_bytes=5_000)
    text = body.decode("utf-8", "replace").strip() if body else ""
    if status == 200:
        return {"input": m, "vendor": text, "known": True, "note": None, "error": None}
    if status == 404:
        return {"input": m, "vendor": None, "known": False, "error": None,
                "note": "OUI not found (unassigned or a locally-administered address)"}
    if status == 429:
        return {"input": m, "vendor": None, "known": None, "error": None,
                "note": "rate-limited by macvendors.com -- try again shortly"}
    return {"input": m, "vendor": None, "known": None, "error": err or f"HTTP {status}"}


# ==========================================================================
# 9. Wikipedia summary -- for name/company/topic selectors
# ==========================================================================
def wikipedia_scan(term: str) -> dict:
    title = term.strip().replace(" ", "_")
    status, body, _, err = _safe_fetch(
        f"https://en.wikipedia.org/api/rest_v1/page/summary/{quote(title, safe='')}",
        timeout=FETCH_TIMEOUT, max_bytes=200_000)
    if status == 200:
        data = _json_or_none(body) or {}
        if data.get("type") == "disambiguation":
            return {"input": term, "found": False,
                    "note": f"“{term}” is ambiguous on Wikipedia (disambiguation page)",
                    "url": (data.get("content_urls") or {}).get("desktop", {}).get("page"), "error": None}
        return {
            "input": term, "found": True,
            "title": data.get("title"), "description": data.get("description"),
            "extract": data.get("extract"),
            "url": (data.get("content_urls") or {}).get("desktop", {}).get("page"),
            "thumbnail": (data.get("thumbnail") or {}).get("source"),
            "error": None,
        }
    if status == 404:
        return {"input": term, "found": False, "note": "no Wikipedia page found", "error": None}
    return {"input": term, "found": False, "note": None, "error": err or f"HTTP {status}"}


# ==========================================================================
# 10. Scan history -- append-only case memory so a finished scan can be
# reopened later from the sidebar. A logging failure here (disk full, bad
# permissions, a JSON-shape surprise) must NEVER turn a good scan into a 500
# -- every function in this section is best-effort and swallows its own
# exceptions.
# ==========================================================================
_history_lock = threading.Lock()


def _summarize_scan(kind: str, scan: dict) -> str:
    """One-line human digest for the history list, e.g. '3 breaches - risk
    high' or '12 subdomains - SPF ok'. Best-effort: an unexpected module
    shape degrades to a generic line instead of raising."""
    try:
        mod = (scan.get("modules") or {}).get(kind) or {}
        if kind == "username":
            return f"{mod.get('found_count', 0)} found / {mod.get('checked', 0)} sites"
        if kind == "email":
            analytics = mod.get("breach_analytics") or {}
            n = analytics.get("breach_count")
            if n is None:
                n = len((mod.get("breach_check") or {}).get("breaches") or [])
            risk = analytics.get("risk_label")
            bit = f"{n} breach{'es' if n != 1 else ''}"
            return f"{bit} - risk {risk.lower()}" if risk else bit
        if kind == "domain":
            subs = (mod.get("subdomains") or {}).get("count", 0)
            spf = "SPF ok" if (mod.get("email_posture") or {}).get("spf_present") else "no SPF"
            return f"{subs} subdomains - {spf}"
        if kind == "ip":
            idb = mod.get("internetdb") or {}
            ports, cves = len(idb.get("ports") or []), len(idb.get("cves") or [])
            bit = f"{ports} open port{'s' if ports != 1 else ''}"
            return f"{bit} - {cves} CVE(s)" if cves else bit
        if kind == "phone":
            return (mod.get("lookup") or {}).get("carrier") or mod.get("country_guess") or "parsed"
        if kind == "hash":
            known = mod.get("known")
            return "known file" if known else ("unrecognized hash" if known is False else "lookup failed")
        if kind == "crypto":
            is_eth = mod.get("chain") == "ETH"
            activity = mod.get("token_count") if is_eth else mod.get("n_tx")
            return f"{mod.get('chain', '')} address - {activity or 0} {'token(s)' if is_eth else 'tx(s)'}"
        if kind == "mac":
            return mod.get("vendor") or "vendor unknown"
        if kind in ("name", "company"):
            return "Wikipedia match" if mod.get("found") else "no Wikipedia match"
    except Exception:
        pass
    return f"{kind} scan"


def _read_history() -> list[dict]:
    try:
        if not HISTORY_FILE.is_file():
            return []
        rows = []
        for line in HISTORY_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            row = _json_or_none(line.encode("utf-8"))
            if isinstance(row, dict):
                rows.append(row)
        return rows
    except OSError:
        return []


def _trim_history_locked() -> None:
    """Keep only the newest HISTORY_MAX lines on disk. Caller must already
    hold _history_lock (runs right after an append)."""
    try:
        lines = HISTORY_FILE.read_text(encoding="utf-8").splitlines()
        if len(lines) > HISTORY_MAX:
            HISTORY_FILE.write_text("\n".join(lines[-HISTORY_MAX:]) + "\n", encoding="utf-8")
    except OSError:
        pass


def log_scan(kind: str, query: str, scan: dict) -> None:
    """Append one finished scan to var/recon-scans.jsonl. Best-effort and
    silent on failure -- case history is a convenience, never a scan
    dependency."""
    try:
        scan_id = secrets.token_hex(4) + format(int(time.time()), "x")
        entry = {
            "id": scan_id,
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "type": kind,
            "q": query,
            "summary": _summarize_scan(kind, scan),
            "scan": scan,
        }
        line = json.dumps(entry, default=str)
        with _history_lock:
            VAR_DIR.mkdir(parents=True, exist_ok=True)
            with HISTORY_FILE.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
            _trim_history_locked()
    except Exception:
        pass


def history_list(limit: int = 50) -> list[dict]:
    """Newest-first summaries for the history sidebar."""
    limit = max(1, min(limit, HISTORY_MAX))
    rows = _read_history()
    rows.reverse()  # file is append order (oldest-first) -- flip for display
    return [{"id": r.get("id"), "ts": r.get("ts"), "type": r.get("type"),
             "q": r.get("q"), "summary": r.get("summary")} for r in rows[:limit]]


def history_get(scan_id: str):
    """The full stored scan JSON for one id (same shape /api/scan returns),
    or None if the id doesn't exist (already trimmed, or never existed)."""
    if not scan_id:
        return None
    for r in _read_history():
        if r.get("id") == scan_id:
            return r.get("scan")
    return None


# ==========================================================================
# Local Arsenal -- installed-tool status + launch commands
# ==========================================================================
ARSENAL_TOOLS = [
    {"name": "theHarvester", "bin": "theHarvester", "usage": "theHarvester -d {target} -b all"},
    {"name": "amass", "bin": "amass", "usage": "amass enum -d {target}"},
    {"name": "subfinder", "bin": "subfinder", "usage": "subfinder -d {target}"},
    {"name": "recon-ng", "bin": "recon-ng", "usage": "recon-ng"},
    {"name": "spiderfoot", "bin": "spiderfoot", "usage": "spiderfoot -s {target} -m all"},
]


def arsenal_status() -> dict:
    tools = []
    for t in ARSENAL_TOOLS:
        path = common.which(t["bin"])
        tools.append({"name": t["name"], "installed": bool(path), "path": path or "", "usage": t["usage"]})
    return {"tools": tools, "bastion_url": "http://127.0.0.1:8920/"}
