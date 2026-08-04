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
    accumulate on disk.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
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
    return {"metadata": pairs, "notes": notes}


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
    return {
        "cleaned_name": cleaned.name,   # sanitized original with ".cleaned" inserted
        "size_before": size_before,
        "size_after": cleaned.stat().st_size,
        "metadata_after": pairs,
        "notes": notes,
        "clean": len(pairs) == 0,
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


def delete_session(token: str) -> None:
    """Remove a session and everything in it. Idempotent — deleting a session
    that's already gone is fine. Raises ValueError only on a malformed token."""
    shutil.rmtree(_session_dir(token), ignore_errors=True)


def purge_stale(now: Optional[float] = None) -> int:
    """Reap every session dir older than SESSION_TTL. Best-effort by design —
    a permission hiccup on one dir must not break an upload — and a no-op when
    SCRUB_DIR doesn't exist yet. Returns how many dirs were removed."""
    now = time.time() if now is None else now
    try:
        children = list(SCRUB_DIR.iterdir())
    except OSError:
        return 0
    removed = 0
    for child in children:
        try:
            if child.is_dir() and now - child.stat().st_mtime > SESSION_TTL:
                shutil.rmtree(child, ignore_errors=True)
                removed += 1
        except OSError:
            continue
    return removed
