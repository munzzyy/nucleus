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
import os
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shared import common
from consoles.devkit import tools

# The file-hash route reads the whole upload into memory to hash it, so it needs
# a larger body cap than the global 256 KiB — but a bounded one (default 64 MiB,
# overridable). Applied per-route via App.body_limits so every other POST keeps
# the tight default. The bytes are hashed and dropped; nothing is written.
HASHFILE_MAX = int(os.environ.get("NUCLEUS_DEVKIT_HASHFILE_MAX_MB") or 64) * 1024 * 1024


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


def _header(req: common.Request, name: str) -> str:
    """Case-insensitive header lookup — req.headers is whatever casing the
    client sent, but header names are case-insensitive on the wire (mirrors
    bastion/scrub's upload handling)."""
    want = name.lower()
    for k, v in req.headers.items():
        if k.lower() == want:
            return v
    return ""


def _clean_filename(name: str) -> str:
    """The uploaded name is only echoed back in JSON and shown via textContent —
    it is NEVER used as a filesystem path (nothing in this handler touches disk).
    Still, strip control characters, keep the basename only, and cap the length
    so a hostile X-Filename can't smuggle newlines or bloat the response."""
    name = "".join(ch for ch in str(name) if ch >= " " and ch != "\x7f")
    name = name.replace("\\", "/").rsplit("/", 1)[-1].strip()
    return name[:255]


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


def h_hashfile(req: common.Request) -> common.Response:
    """Hash an uploaded file's bytes IN MEMORY — no disk write, no parsing.

    Mirrors bastion/scrub's upload: the raw request body IS the file bytes and
    the (percent-encoded UTF-8) filename rides in X-Filename. POST-only, so
    common's Origin/CSRF check applies, and the oversized-body cap is enforced
    upstream via App.body_limits BEFORE this handler runs. Devkit's no-I/O rule
    holds here: we read the request body only, feed it to hashlib, and never
    touch the filesystem or interpret the content.
    """
    if not req.body:
        return common.Response.error(400, "empty upload — send the file bytes as the request body")
    raw = _header(req, "X-Filename")
    filename = _clean_filename(urllib.parse.unquote(raw)) if raw.strip() else ""
    result = tools.hash_file_bytes(req.body)
    return _ok({"filename": filename, "size": len(req.body), "hashes": result})


def h_hmac(req: common.Request) -> common.Response:
    j = req.json()
    if "text" not in j:
        return common.Response.error(400, "missing text")
    if "key" not in j:
        return common.Response.error(400, "missing key")
    try:
        result = tools.hmac_digest(str(j["text"]), str(j["key"]), algo=str(j.get("algo", "sha256")))
    except (ValueError, TypeError) as e:
        return common.Response.error(400, str(e))
    return _ok(result)


def h_checksums(req: common.Request) -> common.Response:
    j = req.json()
    if "text" not in j:
        return common.Response.error(400, "missing text")
    try:
        result = tools.checksums(str(j["text"]))
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
            result = tools.gen_uuid(version=j.get("version", 4), count=j.get("count", 1),
                                    namespace=j.get("namespace"), name=j.get("name"))
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
    "POST /api/devkit/hashfile": h_hashfile,
    "POST /api/devkit/hmac": h_hmac,
    "POST /api/devkit/checksums": h_checksums,
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
        # Only the file-hash route takes a big body (it hashes the bytes in
        # memory); every other POST keeps the global 256 KiB MAX_BODY cap.
        body_limits={"POST /api/devkit/hashfile": HASHFILE_MAX},
    )


if __name__ == "__main__":
    common.serve(build_app())
