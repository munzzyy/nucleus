"""Server-side wordlist registry — allowlist, never a path.

Redcell never accepts a wordlist as a filesystem path from the client. At
import time this module walks the two real wordlist roots on this box,
records every `.txt` file it finds under an opaque id, and that's the whole
universe of wordlists a runner will ever touch. A client picks an id; the id
is a dict lookup, never a path join. An id that isn't in the registry is
refused. Even a hit is re-validated against the allowed roots before use
(defense in depth against the registry going stale between startup and a
request — see `resolve()`).

Two independent packages both happen to install a directory named
`seclists` (`wordlists` package ships one under /usr/share/wordlists/seclists,
the standalone `seclists` package installs its own at /usr/share/seclists) —
real files, not a symlink, so both trees are scanned and a given wordlist may
legitimately show up twice under different ids. That's harmless: every id
still resolves through the same allowlist check.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

ROOTS: list[tuple[str, Path]] = [
    ("wordlists", Path("/usr/share/wordlists")),
    ("seclists", Path("/usr/share/seclists")),
]

# Every resolved path must land under one of these — checked again at
# resolve() time, not just trusted from the startup scan.
ALLOWED_ROOTS: list[Path] = []

MAX_FILES = 30_000          # sanity cap so a hostile mount can't stall startup
MAX_FILE_LABEL = 160


@dataclass
class WordlistEntry:
    id: str
    label: str        # relative path, for display
    root: str          # "wordlists" | "seclists"
    path: str          # absolute resolved path
    size: int
    common: bool = False


_REGISTRY: dict[str, WordlistEntry] = {}

# Curated "start here" list — real filenames confirmed present on this box.
# Anything else is still reachable via the search endpoint; this only
# decides what the dropdown shows before the user types a query.
_COMMON_RELPATHS = {
    "wordlists": {
        "dirb/common.txt",
        "dirb/big.txt",
        "dirbuster/directory-list-2.3-medium.txt",
        "dirbuster/directory-list-2.3-small.txt",
    },
    "seclists": {
        "Discovery/Web-Content/common.txt",
        "Discovery/Web-Content/big.txt",
        "Discovery/Web-Content/quickhits.txt",
        "Discovery/Web-Content/raft-small-directories.txt",
        "Discovery/Web-Content/raft-medium-directories.txt",
        "Discovery/DNS/subdomains-top1million-5000.txt",
        "Discovery/DNS/subdomains-top1million-20000.txt",
    },
}


def _scan_root(root_label: str, root: Path, out: dict[str, WordlistEntry]) -> None:
    if not root.is_dir():
        return
    resolved_root = root.resolve()
    ALLOWED_ROOTS.append(resolved_root)
    common_set = _COMMON_RELPATHS.get(root_label, set())
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for fname in sorted(filenames):
            if count >= MAX_FILES:
                return
            if not fname.lower().endswith(".txt"):
                continue
            full = Path(dirpath) / fname
            try:
                rel = full.relative_to(root).as_posix()
            except ValueError:
                continue
            try:
                size = full.stat().st_size
            except OSError:
                continue
            wid = f"{root_label}/{rel}"
            out[wid] = WordlistEntry(
                id=wid, label=rel[:MAX_FILE_LABEL], root=root_label,
                path=str(full), size=size, common=(rel in common_set),
            )
            count += 1


def _build_registry() -> dict[str, WordlistEntry]:
    out: dict[str, WordlistEntry] = {}
    for label, root in ROOTS:
        _scan_root(label, root, out)
    return out


_REGISTRY = _build_registry()


def common_list() -> list[dict]:
    return sorted(
        ({"id": e.id, "label": e.label, "root": e.root, "size": e.size}
         for e in _REGISTRY.values() if e.common),
        key=lambda d: d["label"],
    )


def search(query: str, limit: int = 50) -> list[dict]:
    q = (query or "").strip().lower()
    if not q:
        return common_list()[:limit]
    starts, contains = [], []
    for e in _REGISTRY.values():
        low = e.label.lower()
        if low.startswith(q) or low.split("/")[-1].startswith(q):
            starts.append(e)
        elif q in low:
            contains.append(e)
        if len(starts) >= limit:
            break
    results = (starts + contains)[:limit]
    return [{"id": e.id, "label": e.label, "root": e.root, "size": e.size} for e in results]


def resolve(wordlist_id: str) -> Optional[str]:
    """id -> absolute path, re-validated against the allowed roots. None if
    the id is unknown, the file vanished, or it now resolves outside every
    allowed root (registry staleness / tamper defense-in-depth)."""
    if not isinstance(wordlist_id, str) or not wordlist_id:
        return None
    entry = _REGISTRY.get(wordlist_id)
    if entry is None:
        return None
    try:
        p = Path(entry.path).resolve()
    except (OSError, RuntimeError):
        return None
    if not p.is_file():
        return None
    for allowed in ALLOWED_ROOTS:
        try:
            p.relative_to(allowed)
            return str(p)
        except ValueError:
            continue
    return None


def registry_count() -> int:
    return len(_REGISTRY)
