#!/usr/bin/env python3
"""Nucleus hub — the one app. Everything connects here.

The hub is deliberately thin: it draws the command center, shows which
consoles + local apps are up, and aggregates a couple of headline numbers
(installed-tool count from Redcell, opsec score from Bastion) by calling
those consoles server-side on loopback. The browser only ever talks to the
hub's own origin, so the strict CSP holds.
"""

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from shared import common  # noqa: E402

ENV_FILE = Path(__file__).resolve().parents[1] / "var" / ".env"
# The keys the settings panel is allowed to manage (name -> label).
MANAGED_KEYS = {"NUMLOOKUP_API_KEY": "NumLookupAPI key (Recon live phone lookups)"}


def _read_env() -> dict:
    out = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


def _write_env_key(key: str, value: str):
    """Upsert one key in var/.env, preserving everything else. 0600."""
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    lines, found = [], False
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if re.match(rf"\s*{re.escape(key)}\s*=", line):
                lines.append(f"{key}={value}")
                found = True
            else:
                lines.append(line)
    if not found:
        lines.append(f"{key}={value}")
    ENV_FILE.write_text("\n".join(lines) + "\n")
    try:
        os.chmod(ENV_FILE, 0o600)
    except OSError:
        pass


def _settings_get(req) -> common.Response:
    env = _read_env()
    return common.Response.json({"keys": [
        {"name": k, "label": lbl,
         "set": bool(env.get(k) or os.environ.get(k))}
        for k, lbl in MANAGED_KEYS.items()]})


def _settings_post(req) -> common.Response:
    body = req.json()
    key = str(body.get("name", "")).strip()
    value = str(body.get("value", "")).strip()
    if key not in MANAGED_KEYS:
        return common.Response.error(400, "unknown setting")
    # keys are opaque tokens; keep it to a sane charset + length, no newlines
    if value and not re.fullmatch(r"[A-Za-z0-9_\-.]{8,128}", value):
        return common.Response.error(400, "that doesn't look like a valid key")
    _write_env_key(key, value)
    if value:
        os.environ[key] = value           # live now, no restart
    else:
        os.environ.pop(key, None)
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
