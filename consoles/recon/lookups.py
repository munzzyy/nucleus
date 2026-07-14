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
import os
import re
import socket
import time
from pathlib import Path
from urllib.parse import quote

from shared import common

FETCH_TIMEOUT = 5.0
DNS_TIMEOUT = 5.0
USERNAME_SITE_TIMEOUT = 6.0
USERNAME_CONCURRENCY = 8
USERNAME_BUDGET = 25.0  # overall wall-clock cap for the whole username scan

VAR_DIR = Path(__file__).resolve().parents[2] / "var"
ENV_FILE = VAR_DIR / ".env"

_UA_BROWSER = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


def _env(name: str) -> str:
    """Env var first, else a gitignored var/.env (KEY=value, one per line)."""
    val = os.environ.get(name, "")
    if val:
        return val
    try:
        if ENV_FILE.is_file():
            for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                if k.strip() == name:
                    return v.strip().strip('"').strip("'")
    except OSError:
        pass
    return ""


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
# 2. Email
# ==========================================================================
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

    # Gravatar existence
    md5_hash = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    status, _, _, err = _safe_fetch(
        f"https://www.gravatar.com/avatar/{md5_hash}?d=404&s=200", timeout=FETCH_TIMEOUT)
    result["gravatar"] = {"checked": status is not None, "exists": status == 200,
                           "error": None if status is not None else err}

    # MX records
    try:
        mx = common.dns_query(domain, "MX", timeout=DNS_TIMEOUT) if domain else []
    except Exception as e:
        mx = []
        result.setdefault("mx_error", str(e))
    result["mx"] = [r.get("data") for r in mx if r.get("data")]
    result["has_mx"] = bool(result["mx"])

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


def domain_scan(domain: str) -> dict:
    d = domain.lower().strip(".")
    result: dict = {"input": d}

    # DNS
    dns: dict = {}
    for rtype in ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA", "SOA", "SRV", "DNSKEY"):
        try:
            ans = common.dns_query(d, rtype, timeout=DNS_TIMEOUT)
        except Exception:
            ans = []
        dns[rtype] = sorted({a.get("data") for a in ans if a.get("data")})
    result["dns"] = dns

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

    # crt.sh certificate-transparency subdomains (notoriously flaky/rate-limited)
    status, body, _, err = _safe_fetch(
        f"https://crt.sh/?q=%25.{quote(d, safe='')}&output=json", timeout=10.0, max_bytes=800_000)
    crt_names: set[str] = set()
    if status == 200:
        data = _json_or_none(body)
        if isinstance(data, list):
            for row in data:
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

    merged_names = crt_names | {h["host"] for h in ht_hosts}
    result["subdomains"] = {
        "ok": bool(merged_names) or (crt_error is None and ht_error is None),
        "count": len(merged_names), "names": sorted(merged_names)[:300],
        "crt_sh": {"ok": crt_error is None, "count": len(crt_names), "error": crt_error},
        "hackertarget": {"ok": ht_error is None, "count": len(ht_hosts),
                          "hosts": ht_hosts[:150], "error": ht_error},
    }

    # urlscan.io recent public scans
    status, body, _, err = _safe_fetch(
        f"https://urlscan.io/api/v1/search/?q=domain:{quote(d, safe='')}&size=5",
        timeout=FETCH_TIMEOUT, max_bytes=300_000)
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
        dmarc_ans = common.dns_query(f"_dmarc.{d}", "TXT", timeout=DNS_TIMEOUT)
    except Exception:
        dmarc_ans = []
    dmarc_txt = [a.get("data") for a in dmarc_ans
                 if a.get("data") and "v=dmarc1" in a.get("data", "").lower()]
    result["email_posture"] = {
        "spf_present": bool(spf_txt), "spf": spf_txt[0] if spf_txt else None,
        "dmarc_present": bool(dmarc_txt), "dmarc": dmarc_txt[0] if dmarc_txt else None,
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

    # Hosting chain: apex A -> IP -> InternetDB (ports/CVEs) + geo
    hosting = {"ip": None, "ports": [], "cves": [], "hostnames": [], "tags": [], "geo": None, "error": None}
    a_records = dns.get("A") or []
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
        hosting["error"] = "no A record to resolve"
    result["hosting"] = hosting

    return result


# ==========================================================================
# 4. IP
# ==========================================================================
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

    try:
        host, _, _ = socket.gethostbyaddr(ip)
        result["reverse_dns"] = {"ok": True, "hostname": host}
    except (socket.herror, socket.gaierror, OSError) as e:
        result["reverse_dns"] = {"ok": False, "hostname": None, "error": str(e)}

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


def phone_scan(number: str) -> dict:
    digits = re.sub(r"[^\d+]", "", number)
    result: dict = {
        "input": number, "normalized": digits,
        "country_guess": _guess_country(digits),
        "digit_count": len(re.sub(r"\D", "", digits)),
    }

    api_key = _env("NUMLOOKUP_API_KEY")
    if not api_key:
        result["lookup"] = {
            "ok": False, "configured": False,
            "note": "NUMLOOKUP_API_KEY not set (env var or var/.env) -- "
                    "live carrier/line-type lookup skipped, showing parsed data only",
        }
        return result

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
    return result


# ==========================================================================
# 6. Hash -- known-file lookup against CIRCL hashlookup (NSRL + malware sets)
# ==========================================================================
_HASH_ALGO_BY_LEN = {32: "md5", 40: "sha1", 64: "sha256"}


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
        return {
            "input": h, "algo": algo, "known": True,
            "filename": data.get("FileName") or data.get("hashlookup:parent-name"),
            "size": data.get("FileSize"),
            "source": data.get("source") or data.get("hashlookup:source"),
            "trust": data.get("hashlookup:trust"),
            "md5": data.get("MD5"), "sha1": data.get("SHA-1"), "sha256": data.get("SHA-256"),
            "error": None,
        }
    if status == 404:
        return {"input": h, "algo": algo, "known": False, "error": None,
                "note": "not present in CIRCL hashlookup (NSRL known-file + malware corpora)"}
    return {"input": h, "algo": algo, "known": None, "error": err or f"HTTP {status}"}


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
