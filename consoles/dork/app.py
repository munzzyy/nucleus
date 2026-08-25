import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shared import common
from consoles.dork import generator

MAX_DOMAIN_LEN = 255
MAX_KEYWORD_LEN = 64

# Open-in-Firefox limits. The query cap matches what a real search box accepts;
# the URL cap is a tab-bomb guard so one click can't spawn hundreds of windows.
MAX_QUERY_LEN = 512
MAX_OPEN_URLS = 40

# A launched URL must be exactly an http(s) URL with no whitespace or control
# bytes. Because every URL we pass to the browser matches this, none can begin
# with "-" and be mistaken for a command-line flag (argv-injection defense) —
# on top of the fact that engine URLs are rebuilt server-side and source URLs
# are host-allowlisted before they ever reach here.
_SAFE_URL_RE = re.compile(r"^https://[^\s\x00-\x1f\x7f]{1,2000}$")

# Firefox binaries we'll launch, in order of preference. Resolved once per
# process. A flatpak Firefox is handled as a fallback launch form below.
_FIREFOX_BINS = ("firefox", "firefox-esr", "firefox-developer-edition", "firefox-bin")


def _firefox_launcher() -> list[str] | None:
    """Return the argv prefix that launches Firefox, or None if it isn't
    installed. The URLs are appended by the caller."""
    for name in _FIREFOX_BINS:
        path = shutil.which(name)
        if path:
            return [path]
    flatpak = shutil.which("flatpak")
    if flatpak:
        try:
            out = subprocess.run([flatpak, "info", "org.mozilla.firefox"],
                                 capture_output=True, timeout=4, check=False)
            if out.returncode == 0:
                return [flatpak, "run", "org.mozilla.firefox"]
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def _resolve_targets(targets) -> tuple[list[str], list[str]]:
    """Turn the request's target list into (urls, problems).

    Two accepted shapes per target:
      {"engine": "...", "query": "..."}  -> rebuilt server-side from the
          fixed engine template map (the browser never sees a client URL)
      {"url": "https://<allowlisted-source>/..."}  -> a specialist-source
          deep link, accepted ONLY if https and its host is in SOURCE_HOSTS
    Anything else is dropped into `problems` (reported, never launched)."""
    urls: list[str] = []
    problems: list[str] = []
    for t in targets:
        if not isinstance(t, dict):
            problems.append("target is not an object")
            continue
        # engine + query: fully server-constructed, the safe default path
        if t.get("engine") is not None or t.get("query") is not None:
            engine = str(t.get("engine", "")).strip().lower()
            query = str(t.get("query", "")).strip()
            if not query:
                problems.append("empty query")
                continue
            if len(query) > MAX_QUERY_LEN:
                problems.append("query too long")
                continue
            try:
                url = generator.engine_search_url(engine, query)
            except ValueError as e:
                problems.append(str(e))
                continue
            urls.append(url)
            continue
        # source url: allowlisted host only
        url = str(t.get("url", "")).strip()
        if not url:
            problems.append("empty target")
            continue
        if not _SAFE_URL_RE.match(url):
            problems.append("url must be a plain https URL")
            continue
        host = (urlparse(url).hostname or "").lower()
        if host not in generator.SOURCE_HOSTS:
            problems.append(f"host not allowed: {host}")
            continue
        urls.append(url)
    return urls, problems


def _open(req):
    body = req.json()
    targets = body.get("targets")
    if not isinstance(targets, list) or not targets:
        return common.Response.error(400, "no targets")
    if len(targets) > MAX_OPEN_URLS:
        return common.Response.error(400, f"too many targets (max {MAX_OPEN_URLS})")

    urls, problems = _resolve_targets(targets)
    if not urls:
        detail = "; ".join(problems[:5]) or "nothing to open"
        return common.Response.error(400, detail)

    launcher = _firefox_launcher()
    if launcher is None:
        return common.Response.error(
            501, "Firefox not found on PATH — install it or use the link buttons.")

    # Every url matched _SAFE_URL_RE / was built from the engine map, so none can
    # be read as a flag. No shell. Detached so the request returns immediately and
    # Firefox outlives this handler; output is discarded (it would otherwise spam
    # the console log). We do NOT wait — a slow cold start must not block the UI.
    try:
        subprocess.Popen(
            launcher + urls,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as e:
        return common.Response.error(500, f"could not launch Firefox: {e}")

    return common.Response.json({
        "opened": len(urls),
        "browser": "firefox",
        "skipped": problems,
    })


def _generate(req):
    # POST-only for symmetry with recon's /api/scan and so the CSRF origin
    # guard in common.py applies — even though this handler makes no network
    # call and only builds strings.
    body = req.json()
    raw = str(body.get("domain", "")).strip()
    keyword = str(body.get("keyword", "") or "").strip()

    if not raw:
        return common.Response.error(400, "missing domain")
    if len(raw) > MAX_DOMAIN_LEN:
        return common.Response.error(400, "domain too long")
    if len(keyword) > MAX_KEYWORD_LEN:
        return common.Response.error(400, "keyword too long")

    try:
        data = generator.dork_set(raw, keyword or None)
    except ValueError as e:
        return common.Response.error(400, str(e))
    return common.Response.json(data)


ROUTES = {
    "POST /api/dork": _generate,
    "POST /api/open": _open,
}


def build_app() -> "common.App":
    return common.App(slug="dork", static_dir=Path(__file__).resolve().parent / "static", routes=ROUTES)


if __name__ == "__main__":
    common.serve(build_app())
