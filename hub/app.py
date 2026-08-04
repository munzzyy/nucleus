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


# Which console owns each headline stat, and how long that probe is allowed to
# take. Posture gets the biggest budget: its first uncached run shells out to
# the arch audit and legitimately takes tens of seconds, after which it's cached
# for 15 minutes. Rather than pretend that's a failure, the probe times out and
# the hub says "starting…".
_SOURCES = {
    "tools":   {"console": "redcell", "port": 8910, "timeout": 4.0},
    "posture": {"console": "bastion", "port": 8920, "timeout": 5.0},
    "devkit":  {"console": "devkit",  "port": 8930, "timeout": 2.0},
    "systems": {"console": "systems", "port": 8940, "timeout": 2.5},
}


def _summary_probe(port: int, path: str, timeout: float):
    """Pull the `summary` block out of a console's endpoint, honestly.

    Returns (value, status, detail) — status is common.local_get_json_status's
    ok/down/timeout/error, so the client can tell "offline" from "still warming
    up" from "answered with something I didn't understand".
    """
    data, status, detail = common.local_get_json_status(port, path, timeout=timeout)
    if status != "ok":
        return None, status, detail
    summary = data.get("summary")
    if not isinstance(summary, dict):
        return None, "error", "no summary in response"
    return summary, "ok", ""


def _devkit_probe():
    """How many tools Devkit is offering, straight from its own manifest."""
    spec = _SOURCES["devkit"]
    data, status, detail = common.local_get_json_status(
        spec["port"], "/api/devkit/manifest", timeout=spec["timeout"])
    if status != "ok":
        return None, status, detail
    sections = data.get("sections")
    if not isinstance(sections, list):
        return None, "error", "no sections in manifest"
    # The manifest is one entry per tool section today. If it ever grows a
    # per-section tool list, count those instead of the sections.
    tools = sum(len(s["tools"]) for s in sections
                if isinstance(s, dict) and isinstance(s.get("tools"), list))
    return {"sections": len(sections), "tools": tools or len(sections)}, "ok", ""


def _systems_probe():
    """One line of machine health: load + memory pressure."""
    spec = _SOURCES["systems"]
    data, status, detail = common.local_get_json_status(
        spec["port"], "/api/systems/overview", timeout=spec["timeout"])
    if status != "ok":
        return None, status, detail
    load = data.get("loadavg")
    out = {
        "hostname": data.get("hostname"),
        "uptime_human": data.get("uptime_human"),
        "cpu_count": data.get("cpu_count"),
        "load1": round(load[0], 2) if isinstance(load, list) and load else None,
        "mem_percent": None,
    }
    # /api/systems/overview reports TOTAL memory, not usage — the percentage
    # this headline wants only exists on /api/systems/memory. Second cheap
    # loopback call rather than a made-up number.
    mem, mem_status, _mem_detail = common.local_get_json_status(
        spec["port"], "/api/systems/memory", timeout=spec["timeout"])
    if mem_status == "ok" and isinstance(mem.get("percent"), (int, float)):
        out["mem_percent"] = mem["percent"]
    return out, "ok", ""


def _overview(req) -> common.Response:
    # Every sub-query runs concurrently — the health pings and the four console
    # probes are independent, so the whole aggregate is bounded by the slowest
    # one, not their sum. A console being down never blocks the rest.
    import concurrent.futures as cf
    import time

    out = {
        "consoles": [], "tools": None, "posture": None, "devkit": None,
        "systems": None, "sources": {}, "published_tools": PUBLISHED_TOOLS,
        "generated_at": round(time.time(), 3),
    }

    with cf.ThreadPoolExecutor(max_workers=5) as ex:
        f_sib = ex.submit(common.siblings_status)
        futures = {
            "tools": ex.submit(_summary_probe, _SOURCES["tools"]["port"],
                               "/api/inventory", _SOURCES["tools"]["timeout"]),
            "posture": ex.submit(_summary_probe, _SOURCES["posture"]["port"],
                                 "/api/posture", _SOURCES["posture"]["timeout"]),
            "devkit": ex.submit(_devkit_probe),
            "systems": ex.submit(_systems_probe),
        }
        out["consoles"] = f_sib.result()
        up = {c["slug"]: bool(c.get("up")) for c in out["consoles"]}
        for name, fut in futures.items():
            value, status, detail = fut.result()
            console = _SOURCES[name]["console"]
            # A successful probe always wins (it may have raced a console that
            # was still starting when the health ping ran). Otherwise the ping
            # is what explains the failure.
            if status != "ok" and not up.get(console):
                status, detail = "down", detail or "console not running"
            out[name] = value
            out["sources"][name] = {"status": status, "detail": detail,
                                    "console": console, "port": _SOURCES[name]["port"]}

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
