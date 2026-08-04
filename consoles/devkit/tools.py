"""Devkit — the pure-logic engine behind the developer toolbelt.

Every function here is a small, self-contained transform: text in, a JSON-able
dict out. That is deliberate, and it is the whole design of this console:

  * No network. No filesystem. Devkit never phones home and never reads or
    writes a file — the entire suite's promise ("stdlib-only, loopback-only,
    never phones home") would be worthless if the dev toolbelt quietly opened a
    socket to look up a timezone or fetch a hash. Everything is computed locally
    from what the user typed.

  * ONE subprocess, and it is our own Python. `regex_test` runs the match in a
    separate `sys.executable -c` worker with a hard 3-second timeout. A
    user-supplied pattern like `(a+)+$` against a crafted string is a classic
    ReDoS: `re` has no per-call timeout, so evaluating such a pattern inline
    would peg and hang a server worker thread indefinitely. Isolating the match
    in a killable subprocess is the only way to bound it — see `regex_test`.

  * Bad input raises `ValueError` with a human message; the route layer
    (app.py) catches that and returns a clean 400. This mirrors the rest of the
    house (bastion's scrub/report handlers translate ValueError into a status
    code) and keeps every function trivially unit-testable without a server.
    The single exception is `regex_test`, which RETURNS an error dict rather
    than raising, because its failure modes (a timeout, a re.error surfaced from
    the subprocess) are results of the guard doing its job, not caller mistakes.

These functions back the `POST /api/devkit/*` routes one-to-one.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import difflib
import hashlib
import hmac
import html
import ipaddress
import json
import math
import re
import secrets
import string
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

from shared import common

try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:  # zoneinfo is stdlib on 3.9+, but never assume
    ZoneInfo = None  # type: ignore
    ZoneInfoNotFoundError = Exception  # type: ignore


# --------------------------------------------------------------------------
# small shared helpers
# --------------------------------------------------------------------------
def _to_bytes(text) -> bytes:
    if isinstance(text, bytes):
        return text
    return str(text).encode("utf-8")


def _strip_ws(s: str) -> str:
    return "".join(str(s).split())


# URL percent-encoding, done by hand rather than via urllib.parse. Devkit
# deliberately imports NO urllib/socket/http module anywhere — the whole point
# of the console is that it can't reach the network even by accident — and this
# is pure string work (space -> "+", unreserved chars pass through, everything
# else -> %XX over UTF-8 bytes), matching urllib.parse.quote_plus/unquote_plus.
_URL_SAFE = frozenset(string.ascii_letters + string.digits + "_.-~")


def _url_encode(s: str) -> str:
    out = []
    for ch in s:
        if ch == " ":
            out.append("+")
        elif ch in _URL_SAFE:
            out.append(ch)
        else:
            for byte in ch.encode("utf-8"):
                out.append("%%%02X" % byte)
    return "".join(out)


def _url_decode(s: str) -> str:
    s = s.replace("+", " ")
    out = bytearray()
    i, n = 0, len(s)
    while i < n:
        ch = s[i]
        if ch == "%" and i + 2 < n:
            try:
                out.append(int(s[i + 1:i + 3], 16))
                i += 3
                continue
            except ValueError:
                pass
        out.extend(ch.encode("utf-8"))
        i += 1
    return out.decode("utf-8", "replace")


def _capcount(count, mx: int) -> int:
    count = int(count)
    if count < 1:
        raise ValueError("count must be at least 1")
    return min(count, mx)


# --------------------------------------------------------------------------
# hashing
# --------------------------------------------------------------------------
DEFAULT_HASHES = ("md5", "sha1", "sha256", "sha512", "sha3_256", "blake2b")


def hash_text(text, algos=None, algo=None) -> dict:
    """Hex digests of `text` (UTF-8) for a set of algorithms.

    Returns {algo: hexdigest}. With no `algos`/`algo` it does the default set;
    a single `algo` (or a list in `algos`) narrows it. Unknown names error.
    """
    data = _to_bytes(text)
    if algo:
        wanted = [algo]
    elif isinstance(algos, str):
        wanted = [algos]
    elif algos:
        wanted = list(algos)
    else:
        wanted = list(DEFAULT_HASHES)
    out: dict = {}
    for name in wanted:
        key = str(name).lower()
        try:
            h = hashlib.new(key)
        except (ValueError, TypeError):
            raise ValueError(f"unknown hash algorithm: {name}")
        h.update(data)
        out[key] = h.hexdigest()
    return out


# --------------------------------------------------------------------------
# encode / decode
# --------------------------------------------------------------------------
_ENC_SCHEMES = ("base64", "base64url", "base32", "hex", "url", "html", "rot13")


def encode(text, scheme) -> dict:
    s = "" if text is None else str(text)
    b = s.encode("utf-8")
    scheme = str(scheme or "").lower()
    if scheme == "base64":
        return {"result": base64.b64encode(b).decode("ascii")}
    if scheme == "base64url":
        return {"result": base64.urlsafe_b64encode(b).decode("ascii")}
    if scheme == "base32":
        return {"result": base64.b32encode(b).decode("ascii")}
    if scheme == "hex":
        return {"result": b.hex()}
    if scheme == "url":
        return {"result": _url_encode(s)}
    if scheme == "html":
        return {"result": html.escape(s)}
    if scheme == "rot13":
        return {"result": codecs.encode(s, "rot_13")}
    raise ValueError(f"unknown scheme: {scheme} (pick one of {', '.join(_ENC_SCHEMES)})")


def _b64decode(s: str, urlsafe: bool) -> str:
    s2 = _strip_ws(s)
    if urlsafe:
        s2 = s2.replace("-", "+").replace("_", "/")
    s2 += "=" * ((4 - len(s2) % 4) % 4)  # tolerate missing padding
    raw = base64.b64decode(s2, validate=True)
    return raw.decode("utf-8", "replace")


def decode(text, scheme) -> dict:
    s = "" if text is None else str(text)
    scheme = str(scheme or "").lower()
    try:
        if scheme == "base64":
            return {"result": _b64decode(s, urlsafe=False)}
        if scheme == "base64url":
            return {"result": _b64decode(s, urlsafe=True)}
        if scheme == "base32":
            s2 = _strip_ws(s)
            s2 += "=" * ((8 - len(s2) % 8) % 8)
            return {"result": base64.b32decode(s2, casefold=True).decode("utf-8", "replace")}
        if scheme == "hex":
            return {"result": bytes.fromhex(_strip_ws(s)).decode("utf-8", "replace")}
        if scheme == "url":
            return {"result": _url_decode(s)}
        if scheme == "html":
            return {"result": html.unescape(s)}
        if scheme == "rot13":
            return {"result": codecs.encode(s, "rot_13")}
    except (ValueError, binascii.Error):
        raise ValueError(f"not valid {scheme}")
    raise ValueError(f"unknown scheme: {scheme} (pick one of {', '.join(_ENC_SCHEMES)})")


# --------------------------------------------------------------------------
# JWT (decode + optional HS* verification — never fetches a key)
# --------------------------------------------------------------------------
def _jwt_b64_bytes(seg: str) -> bytes:
    seg = seg.strip()
    seg += "=" * ((4 - len(seg) % 4) % 4)
    return base64.urlsafe_b64decode(seg)


def jwt_decode(token, secret: str = "", verify: bool = False) -> dict:
    """Split + decode a JWT. Optionally verify an HS256/384/512 signature with a
    caller-supplied secret. There is no path here that fetches a key or hits the
    network — verification is HMAC-only and local, and an `alg: none` token is
    flagged loudly rather than silently trusted."""
    token = str(token or "").strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed JWT — expected 3 dot-separated segments")
    h_b64, p_b64, sig_b64 = parts
    try:
        header = json.loads(_jwt_b64_bytes(h_b64).decode("utf-8"))
        payload = json.loads(_jwt_b64_bytes(p_b64).decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise ValueError("malformed JWT — header/payload is not valid base64url JSON")
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("malformed JWT — header/payload is not a JSON object")

    alg = str(header.get("alg", ""))
    typ = header.get("typ")
    warnings: list = []
    if alg.lower() == "none":
        warnings.append('algorithm is "none" — this token is unsigned; never trust it')

    def _human(k):
        v = payload.get(k)
        if v is None:
            return None
        try:
            return datetime.fromtimestamp(int(v), tz=timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError, TypeError):
            return None

    exp_human, iat_human, nbf_human = _human("exp"), _human("iat"), _human("nbf")

    expired = None
    if "exp" in payload:
        try:
            expired = int(payload["exp"]) < int(time.time())
        except (ValueError, TypeError):
            expired = None
    if expired:
        warnings.append("token is expired (exp is in the past)")

    verified = None
    if verify:
        if alg.upper() in ("HS256", "HS384", "HS512") and secret:
            digestmod = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                         "HS512": hashlib.sha512}[alg.upper()]
            signing_input = (h_b64 + "." + p_b64).encode("ascii")
            expected = hmac.new(_to_bytes(secret), signing_input, digestmod).digest()
            try:
                got = _jwt_b64_bytes(sig_b64)
            except (ValueError, binascii.Error):
                got = b""
            verified = hmac.compare_digest(expected, got)
            if not verified:
                warnings.append("signature did NOT verify with the provided secret")
        elif alg.lower() == "none":
            verified = False
            warnings.append('cannot verify an unsigned ("none") token')
        elif not secret:
            warnings.append("verification requested but no secret was provided")
        else:
            warnings.append(f"verification not supported for alg {alg or '?'} (HS256/384/512 only)")

    return {
        "header": header, "payload": payload, "signature_b64": sig_b64,
        "alg": alg, "typ": typ,
        "exp_human": exp_human, "iat_human": iat_human, "nbf_human": nbf_human,
        "expired": expired, "verified": verified, "warnings": warnings,
    }


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------
def json_tool(text, mode: str = "pretty", sort_keys: bool = False) -> dict:
    text = "" if text is None else str(text)
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON at line {e.lineno} col {e.colno}: {e.msg}")
    except RecursionError:
        # A pathologically nested document ([[[[...]]]]) blows Python's parser
        # stack. Turn it into a normal bad-input error instead of letting it
        # bubble to a 500.
        raise ValueError("JSON is nested too deeply to parse")
    mode = str(mode or "pretty").lower()
    if mode == "pretty":
        return {"result": json.dumps(obj, indent=2, sort_keys=bool(sort_keys),
                                     ensure_ascii=False), "valid": True}
    if mode == "minify":
        return {"result": json.dumps(obj, separators=(",", ":"), sort_keys=bool(sort_keys),
                                     ensure_ascii=False), "valid": True}
    if mode == "validate":
        return {"valid": True, "result": json.dumps(obj, separators=(",", ":"),
                                                     ensure_ascii=False)}
    raise ValueError(f"unknown mode: {mode} (pretty, minify, validate)")


# --------------------------------------------------------------------------
# generators (all cryptographically strong via `secrets`)
# --------------------------------------------------------------------------
def gen_uuid(version=4, count=1) -> dict:
    version = int(version)
    count = _capcount(count, 100)
    if version not in (1, 4):
        raise ValueError("uuid version must be 1 or 4")
    make = uuid.uuid4 if version == 4 else uuid.uuid1
    return {"uuids": [str(make()) for _ in range(count)], "version": version}


_PW_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/"


def _one_password(length: int, pools: list, alphabet: str) -> str:
    # Guarantee one char from each selected class, fill the rest from the union,
    # then shuffle with `secrets` so the guaranteed chars aren't positionally
    # predictable (front-loaded).
    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(pools))]
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def gen_password(length=20, upper=True, lower=True, digits=True, symbols=True, count=1) -> dict:
    length = int(length)
    count = _capcount(count, 100)
    if length < 4:
        raise ValueError("password length must be at least 4")
    # Hard upper bound: `length` flows straight into a per-char secrets.choice
    # loop, so an unbounded value is a memory/CPU exhaustion vector from a tiny
    # request. Cap it the way gen_random caps nbytes.
    if length > 4096:
        raise ValueError("password length must be at most 4096")
    pools = []
    if upper:
        pools.append(string.ascii_uppercase)
    if lower:
        pools.append(string.ascii_lowercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(_PW_SYMBOLS)
    if not pools:
        raise ValueError("select at least one character class")
    if length < len(pools):
        raise ValueError(f"length {length} is too short to include all {len(pools)} selected classes")
    alphabet = "".join(pools)
    return {"passwords": [_one_password(length, pools, alphabet) for _ in range(count)]}


def gen_random(nbytes=32, encoding="hex") -> dict:
    nbytes = int(nbytes)
    if not (1 <= nbytes <= 4096):
        raise ValueError("nbytes must be between 1 and 4096")
    raw = secrets.token_bytes(nbytes)
    encoding = str(encoding or "hex").lower()
    if encoding == "hex":
        val = raw.hex()
    elif encoding == "base64":
        val = base64.b64encode(raw).decode("ascii")
    elif encoding == "base64url":
        val = base64.urlsafe_b64encode(raw).decode("ascii")
    else:
        raise ValueError(f"unknown encoding: {encoding} (hex, base64, base64url)")
    return {"result": val, "bytes": nbytes, "encoding": encoding}


def gen_secret_key(nbytes=32) -> dict:
    nbytes = int(nbytes)
    if not (1 <= nbytes <= 4096):
        raise ValueError("nbytes must be between 1 and 4096")
    return {"result": secrets.token_urlsafe(nbytes), "bytes": nbytes}


# --------------------------------------------------------------------------
# time
# --------------------------------------------------------------------------
def _parse_iso(s) -> datetime:
    s = str(s or "").strip()
    if not s:
        raise ValueError("empty timestamp")
    s2 = s
    if s2[-1:] in ("Z", "z"):
        s2 = s2[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s2)
    except ValueError:
        raise ValueError(f"not a valid ISO 8601 datetime: {s}")


def now() -> dict:
    t = time.time()
    return {
        "unix": int(t),
        "unix_ms": int(t * 1000),
        "iso_utc": datetime.now(timezone.utc).isoformat(),
        "iso_local": datetime.now().astimezone().isoformat(),
    }


def unix_to_iso(ts) -> dict:
    try:
        t = float(ts)
    except (ValueError, TypeError):
        raise ValueError("timestamp must be a number")
    if abs(t) >= 1e11:  # looks like milliseconds
        t /= 1000.0
    try:
        dt = datetime.fromtimestamp(t, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        raise ValueError("timestamp out of range")
    return {"iso_utc": dt.isoformat(), "iso_local": dt.astimezone().isoformat(), "unix": t}


def iso_to_unix(s) -> dict:
    dt = _parse_iso(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return {"unix": int(dt.timestamp()), "unix_float": dt.timestamp(),
            "iso_utc": dt.astimezone(timezone.utc).isoformat()}


def tz_convert(iso, from_tz, to_tz) -> dict:
    if ZoneInfo is None:
        raise ValueError("zoneinfo is unavailable on this Python build")
    dt = _parse_iso(iso)
    try:
        src = ZoneInfo(str(from_tz))
        dst = ZoneInfo(str(to_tz))
    except (ZoneInfoNotFoundError, ValueError, KeyError):
        raise ValueError("unknown timezone (use IANA names like America/New_York)")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=src)
    converted = dt.astimezone(dst)
    return {"result": converted.isoformat(), "from": str(from_tz), "to": str(to_tz),
            "source": dt.isoformat()}


def humanize_duration(seconds) -> dict:
    try:
        f = float(seconds)
    except (ValueError, TypeError, OverflowError):
        raise ValueError("seconds must be a number")
    if not math.isfinite(f):
        raise ValueError("seconds must be a finite number")
    total = int(f)
    neg = total < 0
    total = abs(total)
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    mins, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if mins:
        parts.append(f"{mins}m")
    if secs or not parts:
        parts.append(f"{secs}s")
    return {"result": ("-" if neg else "") + " ".join(parts)}


# --------------------------------------------------------------------------
# cron — next fire times for a standard 5-field expression
# --------------------------------------------------------------------------
def _parse_cron_field(field, lo: int, hi: int, name: str) -> set:
    """Expand one cron field into the set of integers it matches.

    Supports `*`, comma lists, `a-b` ranges, `*/n` and `a-b/n` steps, and a bare
    `a/n` (start at a, step to hi). Everything is bounds-checked against
    [lo, hi] so a malformed field (`60` for minutes, `9` for day-of-week) fails
    loudly here instead of silently never matching later.
    """
    field = str(field).strip()
    if field == "":
        raise ValueError(f"empty {name} field")
    values: set = set()
    for part in field.split(","):
        part = part.strip()
        if part == "":
            raise ValueError(f"empty entry in {name} field")
        has_step = "/" in part
        base_part, step = part, 1
        if has_step:
            base_part, _, step_str = part.partition("/")
            base_part = base_part.strip()
            if not step_str.isdigit() or int(step_str) < 1:
                raise ValueError(f"bad step '/{step_str}' in {name} field")
            step = int(step_str)
        if base_part == "*":
            start, end = lo, hi
        elif "-" in base_part:
            a, _, b = base_part.partition("-")
            a, b = a.strip(), b.strip()
            if not (a.isdigit() and b.isdigit()):
                raise ValueError(f"bad range '{base_part}' in {name} field")
            start, end = int(a), int(b)
        else:
            if not base_part.isdigit():
                raise ValueError(f"bad value '{base_part}' in {name} field")
            start = int(base_part)
            end = hi if has_step else start
        if start < lo or end > hi or start > end:
            raise ValueError(f"{name} value out of range [{lo}-{hi}]: {part}")
        values.update(range(start, end + 1, step))
    if not values:
        raise ValueError(f"no values parsed for {name} field")
    return values


def _next_month_start(dt: datetime) -> datetime:
    if dt.month == 12:
        return dt.replace(year=dt.year + 1, month=1, day=1, hour=0, minute=0,
                          second=0, microsecond=0)
    return dt.replace(month=dt.month + 1, day=1, hour=0, minute=0,
                      second=0, microsecond=0)


_DOW_NAMES = {0: "Sunday", 1: "Monday", 2: "Tuesday", 3: "Wednesday",
              4: "Thursday", 5: "Friday", 6: "Saturday"}
_MONTH_NAMES = {1: "January", 2: "February", 3: "March", 4: "April", 5: "May",
                6: "June", 7: "July", 8: "August", 9: "September", 10: "October",
                11: "November", 12: "December"}


def _describe_cron(fields, minutes, hours, dows, dom_r, dow_r) -> str:
    fmin, fhour, fdom, fmon, fdow = fields
    if fmin == "*":
        when = "every minute"
    elif fmin.startswith("*/") and fmin[2:].isdigit():
        when = f"every {fmin[2:]} minutes"
    elif len(minutes) == 1 and len(hours) == 1:
        when = f"at {sorted(hours)[0]:02d}:{sorted(minutes)[0]:02d}"
    elif fhour == "*" and len(minutes) == 1:
        when = f"at minute {sorted(minutes)[0]} past every hour"
    else:
        when = "at the configured times"
    day_bits = []
    if dom_r:
        day_bits.append(f"on day {fdom} of the month" if fdom.isdigit()
                        else f"on days-of-month {fdom}")
    if dow_r:
        try:
            day_bits.append("on " + ", ".join(_DOW_NAMES[d] for d in sorted(dows)))
        except KeyError:
            day_bits.append(f"on weekdays {fdow}")
    joiner = " or " if (dom_r and dow_r) else " "
    day_str = joiner.join(day_bits) if day_bits else "every day"
    month_str = ""
    if fmon != "*":
        if fmon.isdigit() and int(fmon) in _MONTH_NAMES:
            month_str = " in " + _MONTH_NAMES[int(fmon)]
        else:
            month_str = " in months " + fmon
    return f"{when}, {day_str}{month_str}".strip()


def cron_next(expr, count=5, base_iso=None) -> dict:
    """Next `count` fire times of a 5-field cron expression from `base_iso`
    (default: now). Times are naive wall-clock ISO strings.

    The day-of-month / day-of-week fields follow the classic Vixie-cron rule:
    when BOTH are restricted the entry fires if EITHER matches; when only one is
    restricted, only that one is consulted. The search advances by jumping over
    non-matching months / days / hours instead of ticking one minute at a time,
    so even a sparse expression (`0 0 29 2 *` — Feb 29) converges in a handful
    of iterations, and it is hard-bounded to an 8-year horizon so an impossible
    expression can never loop forever.
    """
    count = int(count)
    if count < 1:
        raise ValueError("count must be at least 1")
    count = min(count, 20)  # cap — this is a display convenience, not a scheduler

    fields = str(expr).split()
    if len(fields) != 5:
        raise ValueError("cron needs exactly 5 fields: minute hour day-of-month month day-of-week")
    minutes = _parse_cron_field(fields[0], 0, 59, "minute")
    hours = _parse_cron_field(fields[1], 0, 23, "hour")
    doms = _parse_cron_field(fields[2], 1, 31, "day-of-month")
    months = _parse_cron_field(fields[3], 1, 12, "month")
    dows_raw = _parse_cron_field(fields[4], 0, 7, "day-of-week")
    dows = {d % 7 for d in dows_raw}  # 7 and 0 are both Sunday
    dom_r = fields[2].strip() != "*"
    dow_r = fields[4].strip() != "*"

    if base_iso:
        base = _parse_iso(base_iso)
        if base.tzinfo is not None:
            base = base.replace(tzinfo=None)
    else:
        base = datetime.now().replace(microsecond=0)

    def _day_ok(dt: datetime) -> bool:
        dom_hit = dt.day in doms
        dow_hit = ((dt.weekday() + 1) % 7) in dows  # python Mon=0 -> cron Sun=0
        if dom_r and dow_r:
            return dom_hit or dow_hit
        if dom_r:
            return dom_hit
        if dow_r:
            return dow_hit
        return True

    cur = base.replace(second=0, microsecond=0) + timedelta(minutes=1)
    horizon_year = base.year + 8
    results: list = []
    guard = 0
    while len(results) < count and guard < 5_000_000:
        guard += 1
        if cur.year > horizon_year:
            break
        if cur.month not in months:
            cur = _next_month_start(cur)
            continue
        if not _day_ok(cur):
            cur = (cur + timedelta(days=1)).replace(hour=0, minute=0)
            continue
        if cur.hour not in hours:
            cur = (cur + timedelta(hours=1)).replace(minute=0)
            continue
        if cur.minute not in minutes:
            cur = cur + timedelta(minutes=1)
            continue
        results.append(cur.isoformat())
        cur = cur + timedelta(minutes=1)

    return {
        "description": _describe_cron(fields, minutes, hours, dows, dom_r, dow_r),
        "next": results,
        "count": len(results),
    }


# --------------------------------------------------------------------------
# number base conversion
# --------------------------------------------------------------------------
_BASE_PREFIX = {16: "0x", 8: "0o", 2: "0b"}
_BASE_DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz"


def _to_base(n: int, base: int) -> str:
    if n == 0:
        return "0"
    out = []
    while n > 0:
        n, r = divmod(n, base)
        out.append(_BASE_DIGITS[r])
    return "".join(reversed(out))


def base_convert(value, from_base, to_base) -> dict:
    from_base = int(from_base)
    to_base = int(to_base)
    if not (2 <= from_base <= 36 and 2 <= to_base <= 36):
        raise ValueError("bases must be between 2 and 36")
    s = str(value).strip().lower()
    neg = s.startswith("-")
    if neg:
        s = s[1:]
    prefix = _BASE_PREFIX.get(from_base)
    if prefix and s.startswith(prefix):
        s = s[len(prefix):]
    if s == "":
        raise ValueError("no digits to convert")
    # Bound the work: a huge digit string turns into a bignum whose base
    # conversion (and json.dumps of the decimal field) is expensive and, past
    # CPython's int->str digit limit, would raise at serialize time. Reject it
    # cleanly up front.
    if len(s) > 4096:
        raise ValueError("value too long (max 4096 digits)")
    try:
        n = int(s, from_base)
    except ValueError:
        raise ValueError(f"'{value}' is not a valid base-{from_base} number")
    result = _to_base(n, to_base)
    return {
        "result": ("-" + result) if (neg and n != 0) else result,
        "decimal": (-n if neg else n),
        "from_base": from_base,
        "to_base": to_base,
    }


# --------------------------------------------------------------------------
# color
# --------------------------------------------------------------------------
def _color_nums(s: str) -> list:
    return [float(x) for x in re.findall(r"[-+]?\d*\.?\d+", s)]


def _clamp255(v) -> int:
    return max(0, min(255, int(round(v))))


def _clamp01(v) -> float:
    return max(0.0, min(1.0, float(v)))


def _fmt_alpha(a: float) -> str:
    return ("%.3f" % a).rstrip("0").rstrip(".")


def _rgb_to_hsl(r: int, g: int, b: int):
    rf, gf, bf = r / 255, g / 255, b / 255
    mx, mn = max(rf, gf, bf), min(rf, gf, bf)
    d = mx - mn
    ll = (mx + mn) / 2
    if d == 0:
        h = s = 0.0
    else:
        s = d / (1 - abs(2 * ll - 1))
        if mx == rf:
            h = ((gf - bf) / d) % 6
        elif mx == gf:
            h = (bf - rf) / d + 2
        else:
            h = (rf - gf) / d + 4
        h *= 60
    return round(h) % 360, round(s * 100), round(ll * 100)


def _hsl_to_rgb(h: float, s: float, ll: float):
    h = h % 360
    s = _clamp01(s / 100)
    ll = _clamp01(ll / 100)
    c = (1 - abs(2 * ll - 1)) * s
    x = c * (1 - abs((h / 60) % 2 - 1))
    m = ll - c / 2
    if h < 60:
        rp, gp, bp = c, x, 0
    elif h < 120:
        rp, gp, bp = x, c, 0
    elif h < 180:
        rp, gp, bp = 0, c, x
    elif h < 240:
        rp, gp, bp = 0, x, c
    elif h < 300:
        rp, gp, bp = x, 0, c
    else:
        rp, gp, bp = c, 0, x
    return _clamp255((rp + m) * 255), _clamp255((gp + m) * 255), _clamp255((bp + m) * 255)


def color_convert(value) -> dict:
    """Parse #hex (3/4/6/8), rgb()/rgba(), or hsl()/hsla() and return all three
    representations. Alpha is preserved when present."""
    s = str(value).strip().lower()
    if not s:
        raise ValueError("empty color")
    r = g = b = 0
    a = None
    if s.startswith("#"):
        hx = s[1:]
        try:
            if len(hx) == 3:
                r, g, b = (int(c * 2, 16) for c in hx)
            elif len(hx) == 4:
                r, g, b, al = (int(c * 2, 16) for c in hx)
                a = round(al / 255, 3)
            elif len(hx) == 6:
                r, g, b = (int(hx[i:i + 2], 16) for i in (0, 2, 4))
            elif len(hx) == 8:
                r, g, b = (int(hx[i:i + 2], 16) for i in (0, 2, 4))
                a = round(int(hx[6:8], 16) / 255, 3)
            else:
                raise ValueError
        except ValueError:
            raise ValueError(f"invalid hex color: {value}")
    elif s.startswith("rgb"):
        nums = _color_nums(s)
        if len(nums) < 3:
            raise ValueError(f"rgb needs 3 values: {value}")
        r, g, b = _clamp255(nums[0]), _clamp255(nums[1]), _clamp255(nums[2])
        if len(nums) >= 4:
            a = round(_clamp01(nums[3]), 3)
    elif s.startswith("hsl"):
        nums = _color_nums(s)
        if len(nums) < 3:
            raise ValueError(f"hsl needs 3 values: {value}")
        r, g, b = _hsl_to_rgb(nums[0], nums[1], nums[2])
        if len(nums) >= 4:
            a = round(_clamp01(nums[3]), 3)
    else:
        raise ValueError(f"unrecognized color format: {value}")

    hh, ss, ll = _rgb_to_hsl(r, g, b)
    out = {
        "hex": "#%02x%02x%02x" % (r, g, b),
        "rgb": "rgb(%d,%d,%d)" % (r, g, b),
        "hsl": "hsl(%d,%d%%,%d%%)" % (hh, ss, ll),
        "r": r, "g": g, "b": b,
    }
    if a is not None:
        out["alpha"] = a
        out["hex"] = "#%02x%02x%02x%02x" % (r, g, b, round(a * 255))
        out["rgb"] = "rgba(%d,%d,%d,%s)" % (r, g, b, _fmt_alpha(a))
        out["hsl"] = "hsla(%d,%d%%,%d%%,%s)" % (hh, ss, ll, _fmt_alpha(a))
    return out


# --------------------------------------------------------------------------
# byte sizes
# --------------------------------------------------------------------------
_BIN_UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"]
_DEC_UNITS = ["B", "KB", "MB", "GB", "TB", "PB", "EB"]
_BYTE_MULT = {
    "": 1, "b": 1,
    "k": 1000, "kb": 1000, "kib": 1024,
    "m": 1000 ** 2, "mb": 1000 ** 2, "mib": 1024 ** 2,
    "g": 1000 ** 3, "gb": 1000 ** 3, "gib": 1024 ** 3,
    "t": 1000 ** 4, "tb": 1000 ** 4, "tib": 1024 ** 4,
    "p": 1000 ** 5, "pb": 1000 ** 5, "pib": 1024 ** 5,
    "e": 1000 ** 6, "eb": 1000 ** 6, "eib": 1024 ** 6,
}


def humanize_bytes(n, binary=True) -> dict:
    try:
        n = float(n)
    except (ValueError, TypeError, OverflowError):
        raise ValueError("n must be a number")
    if not math.isfinite(n):
        raise ValueError("n must be a finite number")
    if n < 0:
        raise ValueError("n must be non-negative")
    binary = bool(binary)
    base = 1024 if binary else 1000
    units = _BIN_UNITS if binary else _DEC_UNITS
    v, i = float(n), 0
    while v >= base and i < len(units) - 1:
        v /= base
        i += 1
    if i == 0:
        result = f"{int(v)} {units[0]}"
    else:
        result = f"{v:.2f}".rstrip("0").rstrip(".") + " " + units[i]
    return {"result": result, "bytes": int(n)}


def parse_bytes(text) -> dict:
    s = str(text).strip()
    m = re.match(r"^([-+]?\d*\.?\d+)\s*([a-zA-Z]*)$", s)
    if not m:
        raise ValueError(f"can't parse a byte size from '{text}'")
    num = float(m.group(1))
    unit = m.group(2).lower()
    if unit not in _BYTE_MULT:
        raise ValueError(f"unknown byte unit: {m.group(2)}")
    n = int(round(num * _BYTE_MULT[unit]))
    return {"bytes": n, "human": humanize_bytes(abs(n))["result"]}


# --------------------------------------------------------------------------
# text transforms
# --------------------------------------------------------------------------
def _words(s: str) -> list:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", s)
    return [p for p in re.split(r"[^A-Za-z0-9]+", s) if p]


def _to_snake(s: str) -> str:
    return "_".join(w.lower() for w in _words(s))


def _to_kebab(s: str) -> str:
    return "-".join(w.lower() for w in _words(s))


def _to_camel(s: str) -> str:
    ws = _words(s)
    if not ws:
        return ""
    return ws[0].lower() + "".join(w.capitalize() for w in ws[1:])


def _slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.strip().lower()).strip("-")


def text_tools(text, op, **opts) -> dict:
    text = "" if text is None else str(text)
    op = str(op or "").lower()
    if op == "upper":
        return {"result": text.upper()}
    if op == "lower":
        return {"result": text.lower()}
    if op == "title":
        return {"result": text.title()}
    if op == "camel":
        return {"result": _to_camel(text)}
    if op == "snake":
        return {"result": _to_snake(text)}
    if op == "kebab":
        return {"result": _to_kebab(text)}
    if op == "slugify":
        return {"result": _slugify(text)}
    if op == "reverse_lines":
        return {"result": "\n".join(reversed(text.split("\n")))}
    if op == "trim":
        return {"result": "\n".join(line.strip() for line in text.split("\n"))}
    if op == "dedup":
        seen: set = set()
        kept = []
        for line in text.split("\n"):
            if line not in seen:
                seen.add(line)
                kept.append(line)
        return {"result": "\n".join(kept)}
    if op == "sort":
        lines = text.split("\n")
        reverse = bool(opts.get("reverse"))
        unique = bool(opts.get("unique"))
        numeric = bool(opts.get("numeric"))
        casefold = bool(opts.get("casefold"))
        if numeric:
            def _key(line):
                m = re.search(r"[-+]?\d*\.?\d+", line)
                return (0, float(m.group())) if m else (1, 0.0)
            lines = sorted(lines, key=_key, reverse=reverse)
        else:
            lines = sorted(lines, key=(str.casefold if casefold else None), reverse=reverse)
        if unique:
            seen = set()
            kept = []
            for line in lines:
                k = line.casefold() if casefold else line
                if k not in seen:
                    seen.add(k)
                    kept.append(line)
            lines = kept
        return {"result": "\n".join(lines)}
    if op == "count":
        return {"counts": {
            "chars": len(text),
            "chars_no_spaces": len(re.sub(r"\s", "", text)),
            "words": len(text.split()),
            "lines": text.count("\n") + (1 if text and not text.endswith("\n") else 0) if text else 0,
            "bytes": len(text.encode("utf-8")),
        }}
    raise ValueError(f"unknown text op: {op}")


# --------------------------------------------------------------------------
# diff
# --------------------------------------------------------------------------
def text_diff(a, b, mode="unified") -> dict:
    a = "" if a is None else str(a)
    b = "" if b is None else str(b)
    a_lines = a.splitlines()
    b_lines = b.splitlines()
    mode = str(mode or "unified").lower()
    if mode == "ndiff":
        diff_lines = list(difflib.ndiff(a_lines, b_lines))
        added = sum(1 for line in diff_lines if line.startswith("+ "))
        removed = sum(1 for line in diff_lines if line.startswith("- "))
    else:
        diff_lines = list(difflib.unified_diff(a_lines, b_lines, fromfile="a",
                                               tofile="b", lineterm=""))
        added = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
        removed = sum(1 for line in diff_lines if line.startswith("-") and not line.startswith("---"))
    return {"diff": "\n".join(diff_lines), "changed": a != b,
            "added": added, "removed": removed, "mode": mode}


# --------------------------------------------------------------------------
# regex — the one place devkit spawns a subprocess (ReDoS containment)
# --------------------------------------------------------------------------
# This worker runs in a SEPARATE, killable python process. `re` offers no
# per-call timeout, so a catastrophic-backtracking pattern evaluated inline
# would hang a server worker thread with no way to stop it. Running the match
# here, behind common.run_tool's hard timeout, is the only reliable bound.
_REGEX_WORKER = r'''
import sys, json, re
data = json.loads(sys.stdin.read() or "{}")
pattern = data.get("pattern", "")
text = data.get("text", "")
flags_str = (data.get("flags", "") or "")
fmap = {"i": re.I, "m": re.M, "s": re.S, "x": re.X, "a": re.A}
flags = 0
for ch in flags_str.lower():
    if ch in fmap:
        flags |= fmap[ch]
    elif ch.strip() == "":
        continue
    else:
        print(json.dumps({"error": "unknown flag: " + ch}))
        sys.exit(2)
try:
    rx = re.compile(pattern, flags)
except re.error as e:
    print(json.dumps({"error": "invalid regex: " + str(e)}))
    sys.exit(2)
CAP = 1000
matches = []
for m in rx.finditer(text):
    if len(matches) >= CAP:
        break
    matches.append({
        "match": m.group(0),
        "start": m.start(),
        "end": m.end(),
        "groups": list(m.groups()),
        "named": m.groupdict(),
    })
print(json.dumps({"matches": matches, "count": len(matches), "capped": len(matches) >= CAP}))
'''

_REGEX_MAX_TEXT = 200 * 1024  # 200 KB — cap the work handed to the subprocess


def regex_test(pattern, text, flags="") -> dict:
    """Test `pattern` against `text` in an isolated, time-bounded subprocess.

    Returns {matches, count, capped} on success or {error} on a bad pattern,
    unknown flag, oversized input, or a timeout (catastrophic backtracking).
    Never raises — the guard turning a would-be hang into a clean error is the
    entire point, so the caller always gets a dict.
    """
    if not isinstance(pattern, str):
        return {"error": "pattern must be a string"}
    text = "" if text is None else str(text)
    if len(text.encode("utf-8", "replace")) > _REGEX_MAX_TEXT:
        return {"error": "text too large (max 200 KB)"}
    payload = json.dumps({"pattern": pattern, "text": text, "flags": str(flags or "")})
    res = common.run_tool([sys.executable, "-c", _REGEX_WORKER],
                          input_text=payload, timeout=3.0)
    if res.timed_out:
        return {"error": "pattern timed out (possible catastrophic backtracking)"}
    out = (res.stdout or "").strip()
    if res.returncode != 0:
        try:
            j = json.loads(out)
            if isinstance(j, dict) and j.get("error"):
                return {"error": j["error"]}
        except (ValueError, json.JSONDecodeError):
            pass
        stderr = (res.stderr or res.error or "").strip()
        return {"error": stderr.splitlines()[0] if stderr else "regex worker failed"}
    try:
        j = json.loads(out)
    except (ValueError, json.JSONDecodeError):
        return {"error": "could not parse regex worker output"}
    return j


# --------------------------------------------------------------------------
# CIDR / IP
# --------------------------------------------------------------------------
def cidr_info(cidr) -> dict:
    try:
        net = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except ValueError:
        raise ValueError(f"not a valid CIDR: {cidr}")
    total = net.num_addresses
    prefixlen = net.prefixlen
    version = net.version
    if version == 4:
        broadcast = str(net.broadcast_address)
        if prefixlen <= 30:
            usable = total - 2
            first_host = str(net.network_address + 1)
            last_host = str(net.broadcast_address - 1)
        elif prefixlen == 31:  # RFC 3021 point-to-point link, both usable
            usable = 2
            first_host = str(net.network_address)
            last_host = str(net.broadcast_address)
        else:  # /32
            usable = 1
            first_host = last_host = str(net.network_address)
    else:
        broadcast = None  # IPv6 has no broadcast
        usable = total
        first_host = str(net.network_address)
        last_host = str(net.broadcast_address)  # numerically the last address
    return {
        "network": str(net.network_address),
        "broadcast": broadcast,
        "netmask": str(net.netmask),
        "hostmask": str(net.hostmask),
        "prefixlen": prefixlen,
        "num_addresses": total,
        "num_usable_hosts": usable,
        "first_host": first_host,
        "last_host": last_host,
        "is_private": net.is_private,
        "version": version,
        "cidr": str(net),
    }


def cidr_contains(cidr, ip) -> dict:
    try:
        net = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except ValueError:
        raise ValueError(f"not a valid CIDR: {cidr}")
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        raise ValueError(f"not a valid IP address: {ip}")
    return {"contains": addr in net, "cidr": str(net), "ip": str(addr)}
