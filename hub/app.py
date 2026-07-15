#!/usr/bin/env python3
"""Nucleus hub — the one app. Everything connects here.

The hub is deliberately thin: it draws the command center, shows which
consoles + local apps are up, and aggregates a couple of headline numbers
(installed-tool count from Redcell, opsec score from Bastion) by calling
those consoles server-side on loopback. The browser only ever talks to the
hub's own origin, so the strict CSP holds.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from shared import apikeys, common  # noqa: E402

# Reading/writing var/.env is apikeys' job (shared.apikeys.get_key/set_key) —
# it does the atomic tmp+os.replace swap and 0600 perms in one place, so the
# hub, recon, and any future console never race each other read-modify-writing
# the same file. The hub used to hand-roll its own reader/writer here; that
# was a non-atomic read-modify-write (a concurrent write could clobber the
# other's line) and, separately, wrote whatever text the browser sent verbatim
# — see _clean_key_value below for the quote bug that caused.
_QUOTE_CHARS = frozenset("\"'")


def _clean_key_value(value: str) -> str:
    """Strip whitespace and one layer of surrounding quotes. Provider dashboards
    often display a key as "abc123" and it gets pasted quotes-and-all; stored
    literally that extra 2 bytes makes every request using it 401."""
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in _QUOTE_CHARS:
        v = v[1:-1].strip()
    return v


def _valid_key_value(value: str) -> bool:
    # API keys come in many shapes (hex, base64, colon-joined id:secret) so we
    # stay permissive on the character set — but quotes and whitespace have no
    # legitimate place in a token and previously slipped through
    # [\x21-\x7e]{6,256} (0x22/0x27 are inside that printable-ASCII range),
    # which is exactly how a quoted paste made it into var/.env unnoticed.
    return bool(re.fullmatch(r"[\x21-\x7e]{6,256}", value)) and not (_QUOTE_CHARS & set(value))


def _settings_get(req) -> common.Response:
    keys = []
    for spec in apikeys.CATALOG:
        keys.append({
            "name": spec["name"], "label": spec["label"], "provider": spec["provider"],
            "get_url": spec["get_url"], "free": spec["free"], "unlocks": spec["unlocks"],
            "set": apikeys.is_set(spec["name"]),
        })
    return common.Response.json({"keys": keys})


def _settings_post(req) -> common.Response:
    body = req.json()
    key = str(body.get("name", "")).strip()
    value = _clean_key_value(str(body.get("value", "")))
    if key not in apikeys.CATALOG_BY_NAME:
        return common.Response.error(400, "unknown setting")
    if value and not _valid_key_value(value):
        return common.Response.error(400, "that doesn't look like a valid key (no spaces/quotes; 6-256 chars)")
    apikeys.set_key(key, value)  # atomic write + live os.environ update; ""=remove
    return common.Response.json({"ok": True, "name": key, "set": bool(value)})


def _overview(req) -> common.Response:
    # Run the three slow sub-queries concurrently — health pings, the tool
    # inventory, and the live posture probes are independent, so the whole
    # aggregate is bounded by the slowest one, not their sum.
    import concurrent.futures as cf

    out = {"consoles": [], "tools": None, "posture": None,
           "published_tools": PUBLISHED_TOOLS}

    def _tools():
        inv = common.local_get_json(8910, "/api/inventory", timeout=3.5)
        return inv["summary"] if inv and isinstance(inv.get("summary"), dict) else None

    def _posture():
        p = common.local_get_json(8920, "/api/posture", timeout=3.5)
        return p["summary"] if p and isinstance(p.get("summary"), dict) else None

    with cf.ThreadPoolExecutor(max_workers=3) as ex:
        f_sib = ex.submit(common.siblings_status)
        f_tools = ex.submit(_tools)
        f_post = ex.submit(_posture)
        out["consoles"] = f_sib.result()
        up = {c["slug"]: c.get("up") for c in out["consoles"]}
        out["tools"] = f_tools.result() if up.get("redcell") else None
        out["posture"] = f_post.result() if up.get("bastion") else None

    return common.Response.json(out)


# Cole's shipped security tools (github.com/munzzyy). The hub links to them and,
# where the CLI is installed locally, Redcell can run them.
PUBLISHED_TOOLS = [
    {"name": "framewall", "desc": "Detect visual prompt-injection in screenshots.",
     "url": "https://github.com/munzzyy/framewall"},
    {"name": "skillxray", "desc": "Scan an agent skill for injection / hidden unicode / secrets.",
     "url": "https://github.com/munzzyy/skillxray"},
    {"name": "sessionxray", "desc": "Security audit of Claude Code session transcripts.",
     "url": "https://github.com/munzzyy/sessionxray"},
    {"name": "toolsmell", "desc": "Lint an MCP server's tool descriptions for smells.",
     "url": "https://github.com/munzzyy/toolsmell"},
    {"name": "webmcp-lint", "desc": "Security + spec linter for WebMCP tool manifests.",
     "url": "https://github.com/munzzyy/webmcp-lint"},
    {"name": "wouldrun", "desc": "Which GitHub Actions would fire for a diff, without running them.",
     "url": "https://github.com/munzzyy/wouldrun"},
    {"name": "ci-safety-gate", "desc": "noslop + zizmor + skillxray + secrets as one CI gate.",
     "url": "https://github.com/munzzyy/ci-safety-gate"},
    {"name": "injection-fixtures", "desc": "Known visual-injection payloads as pytest fixtures.",
     "url": "https://github.com/munzzyy/injection-fixtures"},
    {"name": "coacheck", "desc": "Parse a peptide CoA, purity + reconstitution math.",
     "url": "https://github.com/munzzyy/coacheck"},
]

ROUTES = {
    "GET /api/overview": _overview,
    "GET /api/settings": _settings_get,
    "POST /api/settings": _settings_post,
}


def build_app() -> common.App:
    return common.App(
        slug="hub",
        static_dir=Path(__file__).resolve().parent / "static",
        routes=ROUTES,
    )


if __name__ == "__main__":
    common.serve(build_app())
