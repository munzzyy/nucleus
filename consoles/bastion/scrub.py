"""Bastion scrub — mat2 front-end for stripping metadata before a file is shared.

Everything stays on this machine: files are POSTed over loopback, cleaned in
place under var/scrub/, and downloaded back over the same loopback socket.
Nothing is ever sent anywhere.

The security model, in one place because all of it matters:

  * Untrusted files are ONLY ever parsed by the mat2 subprocess — never
    in-process. A malicious PNG/PDF/docx gets to attack mat2's parsers
    (which sandbox their own exiftool/ffmpeg helpers under bwrap), not this
    server. We treat mat2's text output as data and its exit code as the
    verdict; the file bytes themselves stay opaque to us.
  * mat2 runs via common.run_tool — argv list, shell=False, time-bounded.
    A filename never touches a shell.
  * Each upload lives in its own 0700 session directory named by a random
    urlsafe token; the token is the only handle the browser ever holds.
    Every function that accepts a token goes through _session_dir(), which
    validates it against _TOKEN_RE and then resolve()+relative_to()-guards
    it under SCRUB_DIR (same belt-and-braces as h_report_file), so a
    crafted token can never address anything outside the sandbox.
  * Sessions are disposable: purge_stale() reaps anything older than
    SESSION_TTL so cleaned copies of private files don't quietly
    accumulate on disk. It runs proactively — a background daemon sweeps
    on PURGE_INTERVAL and status() sweeps on the way in — so an idle
    session left open for weeks still expires without any traffic.
  * Deletion is a best-effort SECURE wipe: every file's bytes are
    overwritten with os.urandom before the unlink. HONEST CAVEAT: on a
    copy-on-write / wear-levelled SSD / journalling filesystem the old
    bytes can still survive underneath; full-disk encryption is the only
    real guarantee. The overwrite raises the bar, it doesn't promise
    unrecoverability.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
import unicodedata
from pathlib import Path
from typing import Optional

from shared import common

# Env override exists so tests can point the sandbox at a temp dir and never
# touch the real workspace.
SCRUB_DIR = Path(os.environ.get("NUCLEUS_SCRUB_DIR") or (common.REPO_ROOT / "var" / "scrub"))

try:
    MAX_UPLOAD_MB = int(os.environ.get("NUCLEUS_SCRUB_MAX_MB") or 256)
except ValueError:
    MAX_UPLOAD_MB = 256
MAX_UPLOAD = MAX_UPLOAD_MB * 1024 * 1024

SESSION_TTL = 24 * 3600   # seconds a session survives before purge_stale() reaps it
_last_status_purge = 0.0
_PURGE_MIN_INTERVAL = 300  # status() is polled often; cap its sweep to once per 5 min


def _throttled_purge() -> None:
    """purge_stale() but rate-limited, so a fast status poll can't hammer the
    disk sweeping every session on every request. The background _purge_loop
    handles the long-idle case; this is the belt-and-suspenders on the poll."""
    global _last_status_purge
    now = time.time()
    if now - _last_status_purge >= _PURGE_MIN_INTERVAL:
        _last_status_purge = now
        purge_stale()
PURGE_INTERVAL = 3600     # background sweep cadence — reaps idle sessions with zero traffic
SHOW_TIMEOUT = 60.0       # mat2 --show budget
CLEAN_TIMEOUT = 300.0     # mat2 clean budget — a video re-mux can be legitimately slow

# secrets.token_urlsafe(24) yields 32 chars of [A-Za-z0-9_-]; anything that
# doesn't match this exact shape (no dots, no slashes, no backslashes) is
# rejected before a token ever becomes part of a path.
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")

# Display caps. Metadata comes out of hostile files, so a file that claims ten
# thousand megabyte-sized "entries" must not be able to balloon the JSON
# response (or the DOM that renders it) without bound.
MAX_PAIRS = 500
MAX_VALUE_CHARS = 2000

_META_NAME = "meta.json"  # per-session bookkeeping file — records the original's name/size

# --------------------------------------------------------------------------
# Metadata risk classification
#
# Not all metadata identifies you. A JPEG's GPS coordinates and camera serial
# absolutely do; an MP4's codec id and bitrate do not — and mat2 CANNOT remove
# the latter, because the container format requires those fields to exist (it
# says so itself: "has some mandatory metadata fields; mat2 filled them with
# standard data"). Judging a clean purely by "zero fields remain" therefore
# reports every successfully-scrubbed video as a failure, which is both wrong
# and the kind of wrong that makes someone distrust a working privacy tool.
#
# So we classify each field. `sensitive` categories are the ones that can tie a
# file to a person, a place, a device or a moment; `structural` is the codec /
# geometry / container bookkeeping that is safe to leave. Anything we don't
# recognize is `unknown` — deliberately NOT counted as clean-blocking (that
# would resurrect the false-failure problem) but surfaced for review, so the
# UI can be honest about what it couldn't vouch for.
# --------------------------------------------------------------------------
RISK_LOCATION = "location"
RISK_IDENTITY = "identity"
RISK_DEVICE = "device"
RISK_TIME = "time"
RISK_SOFTWARE = "software"
RISK_STRUCTURAL = "structural"
RISK_UNKNOWN = "unknown"

# Categories that mean "this can identify someone". Ordered most-alarming first.
SENSITIVE_RISKS = (RISK_LOCATION, RISK_IDENTITY, RISK_DEVICE, RISK_TIME, RISK_SOFTWARE)

# Matched against the lowercased key. Structural is checked FIRST so a
# container field like "CompressorID" can't be caught by the device patterns.
_STRUCTURAL_PATTERNS = (
    "imagewidth", "imageheight", "sourceimagewidth", "sourceimageheight",
    "xresolution", "yresolution", "resolutionunit", "bitspersample", "bitdepth",
    "colorcomponents", "colorspace", "encodingprocess", "ycbcr", "jfif",
    "exifbyteorder", "filetype", "mimetype", "megapixels", "aspectratio",
    "compressorid", "compressorname", "graphicsmode", "opcolor", "handlertype",
    "handlerdescription", "handlervendorid", "majorbrand", "minorversion",
    "compatiblebrands", "mediadataoffset", "mediadatasize", "mediaheaderversion",
    "moviedataoffset", "moviedatasize", "movieheaderversion", "trackheaderversion",
    "trackid", "tracklayer", "nexttrackid", "timescale", "duration", "framerate",
    "videoframerate", "audioformat", "audiochannels", "audiobitspersample",
    "audiosamplerate", "samplerate", "channels", "averagebitrate", "maxbitrate",
    "buffersize", "avgbitrate", "matrixstructure", "mediatimescale", "mediaduration",
    "preferredrate", "preferredvolume", "previewtime", "previewduration",
    "postertime", "selectiontime", "selectionduration", "currenttime",
    "rotation", "orientation", "interlace", "planarconfiguration", "photometric",
    "compression", "quality", "progressive", "numberofframes", "pixelformat",
    "chromasubsampling", "videocodec", "audiocodec", "codec", "container",
    "balance", "graphicsmodecolor", "opcolorred", "opcolorgreen", "opcolorblue",
)

# Substring patterns per sensitive category (checked in this order).
_SENSITIVE_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (RISK_LOCATION, (
        "gps", "location", "geo", "coordinate", "latitude", "longitude",
        "altitude", "destbearing", "subjectlocation", "country", "city",
        "province", "state", "sublocation",
    )),
    (RISK_IDENTITY, (
        "artist", "author", "creator", "owner", "copyright", "by-line", "byline",
        "credit", "contact", "email", "url", "website", "rights", "usageterms",
        "personinimage", "lastmodifiedby", "company", "manager", "producer",
        "writer", "director", "publisher", "source", "supplier", "licensor",
        "user", "name", "title", "description", "comment", "keywords", "subject",
        "caption", "headline", "instructions", "note", "album", "performer",
        "composer", "encodedby", "grouping", "lyrics", "identifier",
    )),
    (RISK_DEVICE, (
        "make", "model", "serial", "bodyserial", "lens", "camera", "hostcomputer",
        "devicemanufacturer", "devicemodel", "firmware", "internalserial",
        "ownername", "cameraid", "imei", "deviceid", "scanner",
    )),
    (RISK_TIME, (
        "date", "time", "year", "timestamp", "createdate", "modifydate",
    )),
    (RISK_SOFTWARE, (
        "software", "encoder", "creatortool", "processingsoftware", "application",
        "generator", "producedby", "toolkit", "writername", "encodingtool",
        "historysoftwareagent", "xmptoolkit",
    )),
)


def classify_key(key: str) -> str:
    """Risk category for one metadata key. Structural (harmless container
    bookkeeping) wins over everything so codec/geometry fields are never
    mistaken for device fingerprints; otherwise the first matching sensitive
    category wins; anything unrecognized is `unknown`."""
    k = re.sub(r"[^a-z0-9]", "", str(key or "").lower())
    if not k:
        return RISK_UNKNOWN
    for pat in _STRUCTURAL_PATTERNS:
        if pat in k:
            return RISK_STRUCTURAL
    for risk, patterns in _SENSITIVE_PATTERNS:
        for pat in patterns:
            if pat in k:
                return risk
    return RISK_UNKNOWN


def annotate(pairs: list[dict]) -> list[dict]:
    """Copy of `pairs` with `risk` + `sensitive` on every entry. Pure."""
    out = []
    for p in pairs or []:
        risk = classify_key(p.get("key", ""))
        out.append({**p, "risk": risk, "sensitive": risk in SENSITIVE_RISKS})
    return out


def risk_summary(pairs: list[dict]) -> dict:
    """Counts by category for an annotated (or raw) pair list, plus the
    headline flags the UI leads with."""
    annotated = pairs if (pairs and "risk" in pairs[0]) else annotate(pairs)
    counts: dict = {}
    for p in annotated:
        counts[p["risk"]] = counts.get(p["risk"], 0) + 1
    sensitive = [p for p in annotated if p.get("sensitive")]
    return {
        "counts": counts,
        "sensitive_count": len(sensitive),
        "structural_count": counts.get(RISK_STRUCTURAL, 0),
        "unknown_count": counts.get(RISK_UNKNOWN, 0),
        "has_location": counts.get(RISK_LOCATION, 0) > 0,
        "has_identity": counts.get(RISK_IDENTITY, 0) > 0,
        "has_device": counts.get(RISK_DEVICE, 0) > 0,
        "sensitive_keys": [p["key"] for p in sensitive][:50],
    }

# Cached once per process: the formats list and version string never change
# under us, and status() is polled by the UI.
_exts_cache: Optional[frozenset] = None
_version_cache: Optional[str] = None


def mat2_path() -> Optional[str]:
    return common.which("mat2")


def supported_exts() -> frozenset:
    """Extensions mat2 says it can clean (lowercase, with the dot), parsed from
    `mat2 --list` once and cached. A parse failure degrades to an empty set:
    uploads then get refused with a clear 415 instead of being handed to a
    tool that never claimed to support them."""
    global _exts_cache
    if _exts_cache is None:
        exts: set[str] = set()
        path = mat2_path()
        if path:
            r = common.run_tool([path, "--list"], timeout=SHOW_TIMEOUT)
            if r.returncode == 0:
                # lines look like: "  - image/png (.png)" / "  - image/jpeg (.jpg, .jpeg)"
                for m in re.finditer(r"\(([^)]*)\)", r.stdout):
                    for part in m.group(1).split(","):
                        part = part.strip().lower()
                        if part.startswith(".") and len(part) > 1:
                            exts.add(part)
        _exts_cache = frozenset(exts)
    return _exts_cache


def status() -> dict:
    """Panel status — the fail-loud gate. A missing mat2 binary reports
    available=False with the reason (the UI shows an offline card, no drop
    zone) rather than pretending the panel works: a metadata cleaner that
    silently does nothing is worse than no cleaner at all."""
    global _version_cache
    _throttled_purge()  # proactive but rate-limited so a fast status poll can't hammer disk
    sandbox = common.which("bwrap") is not None
    path = mat2_path()
    if path is None:
        return {"available": False,
                "reason": "mat2 not found on PATH — install it with `sudo pacman -S mat2`",
                "version": "", "sandbox": sandbox,
                "max_upload_bytes": MAX_UPLOAD, "formats": [], "format_count": 0}
    if _version_cache is None:
        _version_cache = common.tool_version([path, "--version"])
    formats = sorted(supported_exts())
    return {"available": True, "version": _version_cache, "sandbox": sandbox,
            "max_upload_bytes": MAX_UPLOAD, "formats": formats,
            "format_count": len(formats)}


def sanitize_name(name: str) -> str:
    """Reduce an attacker-supplied filename to a safe on-disk name.

    The browser sends the original filename in a header; we keep it (people
    want holiday.cleaned.jpg back, not a3f9.bin) but never trust it: path
    segments are dropped (both "/" and "\\", so Windows-origin names can't
    smuggle traversal either), the charset is reduced to [A-Za-z0-9._ -]
    (pure ASCII — which also makes the name safe verbatim inside a quoted
    Content-Disposition header later), leading dots/dashes/spaces go away
    (no hidden files, nothing that parses as a flag), and length is capped
    at 120 keeping the extension — mat2 picks its parser by extension, so
    that part must survive intact. Deterministic, never raises.
    """
    name = str(name or "")
    # Last path segment only — cut at "/" and "\" by hand, then Path().name
    # as a second net (it also collapses "." and ".." to nothing).
    name = name[name.rfind("/") + 1:]
    name = name[name.rfind("\\") + 1:]
    name = Path(name).name if name else ""
    name = unicodedata.normalize("NFC", name)
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name)
    name = re.sub(r"_+", "_", name)
    name = re.sub(r" +", " ", name)
    name = name.lstrip(".- ")
    if not Path(name).stem:
        name = "file" + name
    if len(name) > 120:
        stem, suffix = Path(name).stem, Path(name).suffix
        if len(suffix) >= 120:
            name = name[:120]  # pathological all-extension name — just cut it
        else:
            name = stem[:120 - len(suffix)] + suffix
    return name


def parse_show(text: str) -> tuple[list[dict], list[str]]:
    """Parse `mat2 --show` output into (pairs, notes) without trusting it.

    mat2 prints a `[+] Metadata for FILE:` header, then indented `Key: Value`
    lines; warnings start with `[-]`, and a clean file yields a `No metadata
    found` line. Pairs split on the FIRST ": " so a value containing the
    separator survives whole. The MAX_PAIRS / MAX_VALUE_CHARS caps live here
    because every key and value is attacker-authored content from inside the
    file. Never raises on garbage — unrecognized lines are simply dropped.
    """
    pairs: list[dict] = []
    notes: list[str] = []
    dropped = truncated = 0
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("[+]"):
            continue  # blank, or the "[+] Metadata for FILE:" header
        if stripped.startswith("[-]"):
            notes.append(stripped)
            continue
        if "No metadata found" in stripped:
            notes.append(stripped)
            continue
        if line[:1] not in (" ", "\t") or ": " not in stripped:
            continue  # real pairs are always indented "K: V" — anything else is noise
        key, _, value = stripped.partition(": ")
        if len(pairs) >= MAX_PAIRS:
            dropped += 1
            continue
        if len(key) > MAX_VALUE_CHARS:
            key = key[:MAX_VALUE_CHARS]
            truncated += 1
        if len(value) > MAX_VALUE_CHARS:
            value = value[:MAX_VALUE_CHARS]
            truncated += 1
        pairs.append({"key": key, "value": value})
    if dropped:
        notes.append(f"[-] {dropped} further entries not shown ({MAX_PAIRS}-entry cap)")
    if truncated:
        notes.append(f"[-] {truncated} value(s) truncated to {MAX_VALUE_CHARS} chars")
    return pairs, notes


def _session_dir(token: str) -> Path:
    """Map a token to its session directory — the ONLY place request input
    becomes a filesystem path.

    Two independent guards, either of which kills a traversal on its own:
    the token must match _TOKEN_RE exactly (dots, slashes and backslashes
    can't even appear), and the resolved path must still sit under SCRUB_DIR
    — the same resolve()+relative_to() pattern h_report_file uses for the
    reports sandbox. Raises ValueError on anything else.
    """
    if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
        raise ValueError("bad token")
    base = SCRUB_DIR.resolve()
    candidate = (base / token).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        raise ValueError("token resolves outside the scrub sandbox")
    return candidate


def _write_private(path: Path, data: bytes) -> None:
    """0600 + O_EXCL: these are private files sitting in the workspace, and
    O_EXCL means a (theoretical) name collision fails loudly instead of
    silently overwriting another session's bytes."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]
    finally:
        os.close(fd)


def create_session(name: str, data: bytes) -> dict:
    """Store one upload in a fresh single-use sandbox dir.

    Returns {token, name, size}. Reaps stale sessions first so the sandbox
    never grows without bound, then writes the file (0600) and a meta.json
    (0600) recording the original name/size — later calls read that instead
    of guessing which file in the dir is the original.
    """
    purge_stale()
    safe = sanitize_name(name)
    if safe == _META_NAME:
        safe = "file_" + safe  # an upload must not shadow our bookkeeping file
    SCRUB_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    token = secrets.token_urlsafe(24)  # 32 chars of [A-Za-z0-9_-] — fits _TOKEN_RE by construction
    sdir = _session_dir(token)
    sdir.mkdir(mode=0o700)
    _write_private(sdir / safe, data)
    _write_private(sdir / _META_NAME,
                   json.dumps({"name": safe, "size": len(data)}).encode("utf-8"))
    return {"token": token, "name": safe, "size": len(data)}


def _original(token: str) -> tuple[Path, dict]:
    """The session's original upload path + its meta. Raises ValueError on a
    bad token, FileNotFoundError when the session is gone (expired, purged,
    or deleted)."""
    sdir = _session_dir(token)
    try:
        meta = json.loads((sdir / _META_NAME).read_text("utf-8"))
    except (OSError, ValueError):
        raise FileNotFoundError("no such session")
    # meta.json is ours, but re-sanitizing costs nothing (idempotent) and keeps
    # the no-request-input-becomes-a-path rule airtight.
    name = sanitize_name(str(meta.get("name") or ""))
    fpath = sdir / name
    if not fpath.is_file():
        raise FileNotFoundError("session file missing")
    return fpath, meta


def _run_summary(r: common.RunResult) -> str:
    """First 400 chars of whatever the failed run has to say — mat2's own
    message (e.g. its abort-on-unknown-archive-member complaint) is exactly
    what the user needs to act, so it must survive intact enough to read."""
    blob = (r.stderr or "").strip() or (r.stdout or "").strip() or r.error \
        or f"exit code {r.returncode}"
    return blob[:400]


def inspect(token: str) -> dict:
    """`mat2 --show` on the session's original file.

    Returns {metadata: [{key, value}...], notes: [...]} — an empty metadata
    list is a perfectly valid answer — or {error: ...} when mat2 refused or
    timed out. The file is never opened in-process; mat2 is the only parser.
    """
    path = mat2_path()
    if path is None:
        return {"error": "mat2 is not installed — install it with `sudo pacman -S mat2`"}
    fpath, _meta = _original(token)
    r = common.run_tool([path, "--show", str(fpath)], timeout=SHOW_TIMEOUT)
    if r.timed_out:
        return {"error": f"mat2 --show timed out after {int(SHOW_TIMEOUT)}s"}
    if r.returncode != 0:
        return {"error": "mat2 could not inspect this file: " + _run_summary(r)}
    pairs, notes = parse_show(r.stdout)
    annotated = annotate(pairs)
    return {"metadata": annotated, "notes": notes, "risk": risk_summary(annotated)}


def clean(token: str, lightweight: bool = False, unknown_members: str = "abort") -> dict:
    """Clean the session's file with mat2, then PROVE it by re-inspecting.

    mat2 writes `<stem>.cleaned<suffix>` next to the original (t.jpg ->
    t.cleaned.jpg); we require that file to exist after rc==0 rather than
    trusting the exit code alone, then run --show on the CLEANED copy so the
    "clean" verdict is a measurement, not an assumption. `unknown_members`
    only ever reaches the argv from a fixed three-value allowlist — "abort"
    (mat2's default) is expressed by passing nothing at all.

    Success: {cleaned_name, size_before, size_after, metadata_after, notes,
    clean}. Failure: {error: ...} with mat2's own message. Raises ValueError
    on a bad token/policy, FileNotFoundError when the session is gone.
    """
    if unknown_members not in ("abort", "omit", "keep"):
        raise ValueError("unknown_members must be abort, omit or keep")
    path = mat2_path()
    if path is None:
        return {"error": "mat2 is not installed — install it with `sudo pacman -S mat2`"}
    fpath, meta = _original(token)
    size_before = int(meta.get("size") or fpath.stat().st_size)

    # Snapshot the BEFORE state so the result can show exactly which fields
    # went away. Re-reading here (rather than trusting whatever the upload
    # returned) keeps clean() self-contained and correct even if the caller
    # never inspected, and it's the same one-subprocess cost as --show.
    before_pairs: list[dict] = []
    before = common.run_tool([path, "--show", str(fpath)], timeout=SHOW_TIMEOUT)
    if not before.timed_out and before.returncode == 0:
        before_pairs = annotate(parse_show(before.stdout)[0])

    argv = [path]
    if lightweight:
        argv.append("-L")
    if unknown_members != "abort":
        argv += ["--unknown-members", unknown_members]
    argv.append(str(fpath))
    r = common.run_tool(argv, timeout=CLEAN_TIMEOUT)
    if r.timed_out:
        return {"error": f"mat2 timed out after {int(CLEAN_TIMEOUT)}s"}
    cleaned = fpath.with_name(fpath.stem + ".cleaned" + fpath.suffix)
    if r.returncode != 0 or not cleaned.is_file():
        return {"error": "mat2 could not clean this file: " + _run_summary(r)}
    show = common.run_tool([path, "--show", str(cleaned)], timeout=SHOW_TIMEOUT)
    if show.timed_out or show.returncode != 0:
        return {"error": "cleaned, but the re-check failed: " + _run_summary(show)}
    pairs, notes = parse_show(show.stdout)
    after_pairs = annotate(pairs)

    # What actually went away, by key. This is the reassurance that matters:
    # "GPSLatitude, Make, Model, Artist removed" beats any verdict word.
    after_keys = {p["key"] for p in after_pairs}
    removed = [p for p in before_pairs if p["key"] not in after_keys]
    remaining_sensitive = [p for p in after_pairs if p.get("sensitive")]

    return {
        "cleaned_name": cleaned.name,   # sanitized original with ".cleaned" inserted
        "size_before": size_before,
        "size_after": cleaned.stat().st_size,
        "metadata_after": after_pairs,
        "notes": notes,
        # Strict verdict: nothing at all is left. Kept as-is for callers that
        # already read it.
        "clean": len(after_pairs) == 0,
        # The verdict that's actually correct for formats with mandatory
        # fields: no field that could identify a person, place, device or
        # moment survives. A scrubbed MP4 keeps its codec id and bitrate and
        # is still, in every sense a user cares about, clean.
        "privacy_clean": len(remaining_sensitive) == 0,
        "removed": [{"key": p["key"], "risk": p["risk"]} for p in removed][:MAX_PAIRS],
        "removed_count": len(removed),
        "remaining_sensitive": [{"key": p["key"], "risk": p["risk"]} for p in remaining_sensitive][:MAX_PAIRS],
        "risk_before": risk_summary(before_pairs),
        "risk_after": risk_summary(after_pairs),
    }


def cleaned_file(token: str) -> tuple[Path, str]:
    """(path, download name) of the CLEANED artifact — only ever the cleaned
    one; the original upload is deliberately unreachable through any route,
    so the download endpoint can't reflect a hostile file back out with its
    metadata intact. Raises ValueError on a bad token, FileNotFoundError when
    there's no session or nothing has been cleaned yet."""
    fpath, _meta = _original(token)
    cleaned = fpath.with_name(fpath.stem + ".cleaned" + fpath.suffix)
    if not cleaned.is_file():
        raise FileNotFoundError("no cleaned file yet")
    return cleaned, cleaned.name


_OVERWRITE_CHUNK = 1024 * 1024  # 1 MiB — chunked so a big video doesn't load whole into RAM


def _secure_delete_file(path: Path) -> None:
    """Overwrite a file's bytes with os.urandom, flush+fsync, then unlink.

    Best-effort by design (see the module docstring): a CoW/SSD/journalling
    filesystem can keep the original blocks alive underneath us — the real
    guarantee is full-disk encryption. This just makes the plaintext copy on
    the visible block harder to recover than a bare unlink would. Never
    raises; a file that can't be opened for rewrite is still unlinked."""
    if path.is_symlink():
        # Never follow a symlink — a hostile scrubbed archive can plant one, and
        # overwriting through it would clobber the link's TARGET (e.g. ~/.bashrc).
        # Drop the link itself, never its target.
        try:
            path.unlink()
        except OSError:
            pass
        return
    try:
        size = path.stat().st_size
        with open(path, "r+b", buffering=0) as f:
            remaining = size
            while remaining > 0:
                n = min(_OVERWRITE_CHUNK, remaining)
                f.write(os.urandom(n))
                remaining -= n
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    finally:
        try:
            path.unlink()
        except OSError:
            pass


def _secure_rmtree(path: Path) -> None:
    """rmtree that overwrites every file's bytes first. Best-effort and
    idempotent — a missing tree, or a permission hiccup on one entry, is
    swallowed rather than raised."""
    if not path.exists():
        return
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            _secure_delete_file(Path(root) / name)
        for name in dirs:
            d = Path(root) / name
            try:
                # A symlinked dir (os.walk doesn't descend it): drop the link,
                # never rmdir/recurse into its target.
                d.unlink() if d.is_symlink() else d.rmdir()
            except OSError:
                pass
    try:
        path.rmdir()
    except OSError:
        pass


def delete_session(token: str) -> None:
    """Securely remove a session and everything in it. Idempotent — deleting a
    session that's already gone is fine. Raises ValueError only on a malformed
    token."""
    _secure_rmtree(_session_dir(token))


def purge_stale(now: Optional[float] = None) -> int:
    """Reap every session dir older than SESSION_TTL, securely. Best-effort by
    design — a permission hiccup on one dir must not break an upload — and a
    no-op when SCRUB_DIR doesn't exist yet. Returns how many dirs were removed."""
    now = time.time() if now is None else now
    try:
        children = list(SCRUB_DIR.iterdir())
    except OSError:
        return 0
    removed = 0
    for child in children:
        try:
            if child.is_dir() and now - child.stat().st_mtime > SESSION_TTL:
                _secure_rmtree(child)
                removed += 1
        except OSError:
            continue
    return removed


def _purge_loop() -> None:
    while True:
        time.sleep(PURGE_INTERVAL)
        try:
            purge_stale()
        except Exception:
            pass  # a background sweep must never take the process down


# Start the idle sweeper once, at import. Daemon so it never blocks shutdown;
# opt out with NUCLEUS_NO_PURGE_THREAD=1 (tests, or single-shot CLI use).
if not os.environ.get("NUCLEUS_NO_PURGE_THREAD"):
    threading.Thread(target=_purge_loop, name="scrub-purge", daemon=True).start()
