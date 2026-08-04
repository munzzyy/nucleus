#!/usr/bin/env python3
"""Devkit — the everyday developer toolbelt console.

Every tool is a thin POST route over a pure function in tools.py: parse the
JSON body, check the required fields are present, call the function, wrap the
result. All the real logic (and all the correctness) lives in tools.py so it
stays unit-testable with no server. Nothing here touches the network or the
filesystem — the one subprocess in the whole console is tools.regex_test's
ReDoS-containment worker, which runs our own Python.

Contract for every route: JSON in, JSON out. Success is
{"ok": true, ...<the function's result dict>}; bad input is a clean
Response.error(400, msg). Handlers never raise to the client — a ValueError
from a tool becomes a 400, and common's outer guard would turn anything else
into a 500 rather than dropping the connection.
"""

import functools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shared import common
from consoles.devkit import tools


# The tool groups the UI renders, in page order. Exposed via /api/devkit/manifest
# so the frontend (and the command palette) can discover sections without
# hardcoding them.
TOOL_SECTIONS = [
    {"id": "hashing", "label": "Hashing"},
    {"id": "encode", "label": "Encode / decode"},
    {"id": "jwt", "label": "JWT"},
    {"id": "json", "label": "JSON"},
    {"id": "generators", "label": "Generators"},
    {"id": "time", "label": "Time"},
    {"id": "cron", "label": "Cron"},
    {"id": "numbers", "label": "Numbers & color"},
    {"id": "text", "label": "Text"},
    {"id": "regex", "label": "Regex"},
    {"id": "cidr", "label": "Network (CIDR)"},
]


def _ok(result: dict) -> common.Response:
    return common.Response.json({"ok": True, **result})


def _guard(fn):
    """Turn any bad-input failure into a clean 400, never a 500.

    The tools raise ValueError/TypeError on bad input and each handler already
    catches those around the tool call. But two failure classes slip past that
    inner try: a pathological input can surface OverflowError (float of a
    thousand-digit int) or RecursionError (deeply nested JSON) from inside the
    tool, and Response.json() serialises eagerly, so a value that json.dumps
    refuses (an int past CPython's int->str digit limit) raises a ValueError in
    _ok() — which runs after the inner try has been left. Wrapping the whole
    handler catches all of them in one place, so every /api/devkit/* route
    keeps its contract: JSON in, JSON out, bad input -> 400.
    """
    @functools.wraps(fn)
    def wrapped(req: common.Request) -> common.Response:
        try:
            return fn(req)
        except (ValueError, TypeError, OverflowError, RecursionError) as e:
            return common.Response.error(400, str(e))
    return wrapped


def _flag(v, default: bool = True) -> bool:
    """Coerce a JSON value to a bool. JSON booleans pass straight through; a
    stray string like "false"/"0"/"no" is treated as false so a checkbox that
    got stringified somewhere doesn't silently read as always-on."""
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    if isinstance(v, str):
        return v.strip().lower() not in ("false", "0", "no", "off", "")
    return bool(v)


# --------------------------------------------------------------------------
# handlers
# --------------------------------------------------------------------------
def h_hash(req: common.Request) -> common.Response:
    j = req.json()
    if "text" not in j:
        return common.Response.error(400, "missing text")
    try:
        result = tools.hash_text(str(j["text"]), algos=j.get("algos"), algo=j.get("algo"))
    except (ValueError, TypeError) as e:
        return common.Response.error(400, str(e))
    return _ok(result)


def h_encode(req: common.Request) -> common.Response:
    j = req.json()
    if "text" not in j:
        return common.Response.error(400, "missing text")
    scheme = j.get("scheme")
    if not scheme:
        return common.Response.error(400, "missing scheme")
    try:
        result = tools.encode(j["text"], scheme)
    except (ValueError, TypeError) as e:
        return common.Response.error(400, str(e))
    return _ok(result)


def h_decode(req: common.Request) -> common.Response:
    j = req.json()
    if "text" not in j:
        return common.Response.error(400, "missing text")
    scheme = j.get("scheme")
    if not scheme:
        return common.Response.error(400, "missing scheme")
    try:
        result = tools.decode(j["text"], scheme)
    except (ValueError, TypeError) as e:
        return common.Response.error(400, str(e))
    return _ok(result)


def h_jwt(req: common.Request) -> common.Response:
    j = req.json()
    token = j.get("token")
    if not token:
        return common.Response.error(400, "missing token")
    try:
        result = tools.jwt_decode(token, secret=str(j.get("secret", "")),
                                  verify=_flag(j.get("verify"), False))
    except (ValueError, TypeError) as e:
        return common.Response.error(400, str(e))
    return _ok(result)


def h_json(req: common.Request) -> common.Response:
    j = req.json()
    if "text" not in j:
        return common.Response.error(400, "missing text")
    try:
        result = tools.json_tool(j["text"], mode=str(j.get("mode", "pretty")),
                                 sort_keys=_flag(j.get("sort_keys"), False))
    except (ValueError, TypeError) as e:
        return common.Response.error(400, str(e))
    return _ok(result)


def h_gen(req: common.Request) -> common.Response:
    j = req.json()
    kind = str(j.get("kind", "")).lower()
    try:
        if kind == "uuid":
            result = tools.gen_uuid(version=j.get("version", 4), count=j.get("count", 1))
        elif kind == "password":
            result = tools.gen_password(
                length=j.get("length", 20),
                upper=_flag(j.get("upper"), True), lower=_flag(j.get("lower"), True),
                digits=_flag(j.get("digits"), True), symbols=_flag(j.get("symbols"), True),
                count=j.get("count", 1))
        elif kind == "random":
            result = tools.gen_random(nbytes=j.get("nbytes", 32),
                                      encoding=str(j.get("encoding", "hex")))
        elif kind == "secret":
            result = tools.gen_secret_key(nbytes=j.get("nbytes", 32))
        else:
            return common.Response.error(400, "kind must be one of: uuid, password, random, secret")
    except (ValueError, TypeError) as e:
        return common.Response.error(400, str(e))
    return _ok(result)


def h_time(req: common.Request) -> common.Response:
    j = req.json()
    op = str(j.get("op", "")).lower()
    try:
        if op == "now":
            result = tools.now()
        elif op == "unix_to_iso":
            result = tools.unix_to_iso(j.get("ts"))
        elif op == "iso_to_unix":
            result = tools.iso_to_unix(j.get("iso", ""))
        elif op == "tz_convert":
            result = tools.tz_convert(j.get("iso", ""), j.get("from_tz", ""), j.get("to_tz", ""))
        elif op == "humanize_duration":
            result = tools.humanize_duration(j.get("seconds"))
        else:
            return common.Response.error(
                400, "op must be one of: now, unix_to_iso, iso_to_unix, tz_convert, humanize_duration")
    except (ValueError, TypeError) as e:
        return common.Response.error(400, str(e))
    return _ok(result)


def h_cron(req: common.Request) -> common.Response:
    j = req.json()
    expr = str(j.get("expr", "")).strip()
    if not expr:
        return common.Response.error(400, "missing expr")
    try:
        result = tools.cron_next(expr, count=j.get("count", 5), base_iso=j.get("base_iso"))
    except (ValueError, TypeError) as e:
        return common.Response.error(400, str(e))
    return _ok(result)


def h_base(req: common.Request) -> common.Response:
    j = req.json()
    if "value" not in j:
        return common.Response.error(400, "missing value")
    if "from_base" not in j or "to_base" not in j:
        return common.Response.error(400, "missing from_base / to_base")
    try:
        result = tools.base_convert(j["value"], j["from_base"], j["to_base"])
    except (ValueError, TypeError) as e:
        return common.Response.error(400, str(e))
    return _ok(result)


def h_color(req: common.Request) -> common.Response:
    j = req.json()
    value = j.get("value")
    if not value:
        return common.Response.error(400, "missing value")
    try:
        result = tools.color_convert(value)
    except (ValueError, TypeError) as e:
        return common.Response.error(400, str(e))
    return _ok(result)


def h_bytes(req: common.Request) -> common.Response:
    j = req.json()
    op = str(j.get("op", "")).lower()
    try:
        if op == "humanize":
            if "n" not in j:
                return common.Response.error(400, "missing n")
            result = tools.humanize_bytes(j["n"], binary=_flag(j.get("binary"), True))
        elif op == "parse":
            if "text" not in j:
                return common.Response.error(400, "missing text")
            result = tools.parse_bytes(j["text"])
        else:
            return common.Response.error(400, "op must be one of: humanize, parse")
    except (ValueError, TypeError) as e:
        return common.Response.error(400, str(e))
    return _ok(result)


def h_text(req: common.Request) -> common.Response:
    j = req.json()
    if "text" not in j:
        return common.Response.error(400, "missing text")
    op = str(j.get("op", "")).lower()
    if not op:
        return common.Response.error(400, "missing op")
    opts = {k: _flag(j.get(k), False) for k in ("reverse", "unique", "numeric", "casefold")}
    try:
        result = tools.text_tools(j["text"], op, **opts)
    except (ValueError, TypeError) as e:
        return common.Response.error(400, str(e))
    return _ok(result)


def h_diff(req: common.Request) -> common.Response:
    j = req.json()
    if "a" not in j or "b" not in j:
        return common.Response.error(400, "missing a / b")
    try:
        result = tools.text_diff(j["a"], j["b"], mode=str(j.get("mode", "unified")))
    except (ValueError, TypeError) as e:
        return common.Response.error(400, str(e))
    return _ok(result)


def h_regex(req: common.Request) -> common.Response:
    j = req.json()
    pattern = j.get("pattern")
    if not pattern:
        return common.Response.error(400, "missing pattern")
    result = tools.regex_test(pattern, j.get("text", ""), flags=str(j.get("flags", "")))
    if "error" in result:
        return common.Response.error(400, result["error"])
    return _ok(result)


def h_cidr(req: common.Request) -> common.Response:
    j = req.json()
    cidr = j.get("cidr")
    if not cidr:
        return common.Response.error(400, "missing cidr")
    try:
        if j.get("ip"):
            result = tools.cidr_contains(cidr, j["ip"])
        else:
            result = tools.cidr_info(cidr)
    except (ValueError, TypeError) as e:
        return common.Response.error(400, str(e))
    return _ok(result)


def h_manifest(req: common.Request) -> common.Response:
    return common.Response.json({"sections": TOOL_SECTIONS})


# Every route goes through _guard so no bad input can ever 500 (see _guard).
ROUTES = {key: _guard(fn) for key, fn in {
    "POST /api/devkit/hash": h_hash,
    "POST /api/devkit/encode": h_encode,
    "POST /api/devkit/decode": h_decode,
    "POST /api/devkit/jwt": h_jwt,
    "POST /api/devkit/json": h_json,
    "POST /api/devkit/gen": h_gen,
    "POST /api/devkit/time": h_time,
    "POST /api/devkit/cron": h_cron,
    "POST /api/devkit/base": h_base,
    "POST /api/devkit/color": h_color,
    "POST /api/devkit/bytes": h_bytes,
    "POST /api/devkit/text": h_text,
    "POST /api/devkit/diff": h_diff,
    "POST /api/devkit/regex": h_regex,
    "POST /api/devkit/cidr": h_cidr,
    "GET /api/devkit/manifest": h_manifest,
}.items()}


def build_app() -> common.App:
    return common.App(
        slug="devkit",
        static_dir=Path(__file__).resolve().parent / "static",
        routes=ROUTES,
    )


if __name__ == "__main__":
    common.serve(build_app())
