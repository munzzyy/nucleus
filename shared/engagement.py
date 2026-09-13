"""Engagements — a named case with an explicit authorized scope, its collected
findings, and a timeline. Stdlib JSON under var/engagements/.

The scope is the point. When an engagement is active AND has a scope, the Redcell
gate additionally requires the target to be inside it (see runners.scope_check),
turning the "I am authorized" checkbox into a real allowlist. Matching fails
safe: a target that isn't clearly in scope is refused, and a malformed scope
entry simply never matches.

Creating an engagement is a deliberate act — it writes a case file to disk — so
it's independent of the NUCLEUS_LOGGING switch that gates incidental scan logging.
`nucleus wipe` removes var/engagements along with the other case data.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Optional

_DIR = Path(__file__).resolve().parents[1] / "var" / "engagements"
_ACTIVE = _DIR / "_active"
_SLUG_RE = re.compile(r"[^a-z0-9._-]+")
_MAX = 500  # cap findings/events per case so a runaway loop can't grow a file unbounded


def _slugify(name: str) -> str:
    s = _SLUG_RE.sub("-", (name or "").strip().lower()).strip("-.")
    return s[:60] or "case"


def _path(slug: str) -> Path:
    # slug is already sanitized, but re-clamp so a hand-passed slug can't escape _DIR
    return _DIR / (_slugify(slug) + ".json")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _read(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _save(e: dict) -> None:
    _DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(_DIR), prefix=".eng.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(e, f, indent=2, default=str)
        os.chmod(tmp, 0o600)
        os.replace(tmp, _path(e["slug"]))
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def list_engagements() -> list[dict]:
    if not _DIR.exists():
        return []
    out = []
    for p in sorted(_DIR.glob("*.json")):
        e = _read(p)
        if e and e.get("slug"):
            out.append({"slug": e["slug"], "name": e.get("name", e["slug"]),
                        "created": e.get("created"), "scope": e.get("scope", []),
                        "findings": len(e.get("findings", [])), "events": len(e.get("events", []))})
    return out


def get(slug: str) -> Optional[dict]:
    return _read(_path(slug))


def create(name: str, scope: Optional[list] = None) -> dict:
    slug = _slugify(name)
    e = {"slug": slug, "name": (name or slug).strip(), "created": _now(),
         "scope": [s.strip() for s in (scope or []) if s and s.strip()],
         "notes": "", "findings": [], "events": []}
    _save(e)
    set_active(slug)
    return e


def active() -> Optional[dict]:
    try:
        slug = _ACTIVE.read_text().strip()
    except OSError:
        return None
    return get(slug) if slug else None


def set_active(slug: str) -> None:
    _DIR.mkdir(parents=True, exist_ok=True)
    if slug:
        _ACTIVE.write_text(_slugify(slug))
    elif _ACTIVE.exists():
        _ACTIVE.unlink()


def add_scope(slug: str, entry: str) -> Optional[dict]:
    e = get(slug)
    if e is None:
        return None
    entry = (entry or "").strip()
    if entry and entry not in e["scope"]:
        e["scope"].append(entry)
        _save(e)
    return e


def add_finding(slug: str, finding: dict) -> None:
    e = get(slug)
    if e is None:
        return
    e.setdefault("findings", []).append(finding)
    e["findings"] = e["findings"][-_MAX:]
    _save(e)


def add_event(slug: str, kind: str, target: str, summary: str) -> None:
    e = get(slug)
    if e is None:
        return
    e.setdefault("events", []).append({"ts": _now(), "kind": kind, "target": target, "summary": summary})
    e["events"] = e["events"][-_MAX:]
    _save(e)


def _entry_matches(target: str, entry: str) -> bool:
    entry = (entry or "").strip().lower()
    target = (target or "").strip().lower().rstrip(".")
    if not entry or not target:
        return False
    # IP / CIDR entry: match only an IP target that falls inside it.
    try:
        net = ipaddress.ip_network(entry, strict=False)
        try:
            return ipaddress.ip_address(target) in net
        except ValueError:
            return False  # entry is a network, target is a hostname -> no match
    except ValueError:
        pass
    # Hostname/domain entry: exact, or target is a subdomain of it.
    return target == entry or target.endswith("." + entry)


def in_scope(target: str, scope) -> bool:
    """True only if `target` clearly falls within one scope entry. Fail-safe: an
    empty scope or an unmatched/odd target returns False (the caller enforces
    scope only when it is non-empty, so 'no scope set' never means allow-all)."""
    return any(_entry_matches(target, s) for s in (scope or ()))


def export_markdown(e: dict) -> str:
    from shared import findings as F
    if not e:
        return "# Engagement\n\n_Not found._\n"
    lines = [f"# Engagement — {e.get('name', e.get('slug'))}", "",
             f"Created {e.get('created', '?')}", ""]
    scope = e.get("scope") or []
    lines += ["## Scope", "", *([f"- `{s}`" for s in scope] or ["_No scope set._"]), ""]
    lines.append(F.to_markdown(e.get("findings", []), "Findings"))
    events = e.get("events") or []
    if events:
        lines += ["", "## Timeline", ""]
        lines += [f"- `{ev.get('ts', '')}` **{ev.get('kind', '')}** {ev.get('target', '')} — {ev.get('summary', '')}"
                  for ev in events]
    return "\n".join(lines) + "\n"
