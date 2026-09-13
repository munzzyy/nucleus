"""Normalized findings — one place to roll up, render, and export them.

A Finding is a plain dict: {severity, title, host, evidence, tool}. Recon,
Redcell's native modules, and the external-tool runners all produce findings in
different raw shapes; normalizing through here means a "3 high, 1 medium" rollup
means the same thing everywhere, and Markdown/CSV export works the same way from
every console. Stdlib only, no I/O — pure functions over dicts and strings.
"""
from __future__ import annotations

import csv
import io
import json

SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def _sev(v) -> str:
    s = str(v if v is not None else "info").strip().lower()
    return s if s in _SEV_RANK else "info"


def finding(severity, title, host="", evidence="", tool="") -> dict:
    return {"severity": _sev(severity), "title": str(title or "").strip(),
            "host": str(host or "").strip(), "evidence": str(evidence or "").strip(),
            "tool": str(tool or "").strip()}


def normalize(raw: dict) -> dict:
    """Coerce a loosely-shaped dict (from any producer) into a Finding, tolerant
    of the common alternate field names."""
    raw = raw or {}
    return finding(raw.get("severity"),
                   raw.get("title") or raw.get("name") or raw.get("template") or "",
                   raw.get("host") or raw.get("matched") or raw.get("url") or raw.get("target") or "",
                   raw.get("evidence") or raw.get("detail") or raw.get("recommendation") or "",
                   raw.get("tool") or "")


def sort_key(f: dict):
    return (_SEV_RANK.get(_sev(f.get("severity")), 99), f.get("host", ""), f.get("title", ""))


def roll_up(findings) -> dict:
    """Counts per severity plus a total — the honest source for a 'N critical'
    summary line (parsed severities, not a raw-output guess)."""
    counts = {s: 0 for s in SEVERITIES}
    for f in findings or ():
        counts[_sev((f or {}).get("severity"))] += 1
    counts["total"] = sum(counts[s] for s in SEVERITIES)
    return counts


def summary_line(findings) -> str:
    c = roll_up(findings)
    parts = [f"{c[s]} {s}" for s in SEVERITIES if c[s]]
    return ", ".join(parts) if parts else "no findings"


def to_markdown(findings, title="Findings") -> str:
    fs = sorted(findings or (), key=sort_key)
    lines = [f"## {title}", "", summary_line(fs), ""]
    if not fs:
        lines.append("_No findings._")
        return "\n".join(lines) + "\n"
    for f in fs:
        head = f"- **[{_sev(f.get('severity')).upper()}]** {f.get('title', '')}"
        if f.get("host"):
            head += f" — `{f['host']}`"
        lines.append(head)
        if f.get("evidence"):
            lines.append(f"  - {f['evidence']}")
        if f.get("tool"):
            lines.append(f"  - _{f['tool']}_")
    return "\n".join(lines) + "\n"


def to_csv(findings) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["severity", "title", "host", "evidence", "tool"])
    for f in sorted(findings or (), key=sort_key):
        w.writerow([_sev(f.get("severity")), f.get("title", ""), f.get("host", ""),
                    f.get("evidence", ""), f.get("tool", "")])
    return out.getvalue()


# --------------------------------------------------------------------------
# Parsers for the machine-readable output the runners already ask tools to emit.
# Each is defensive: a malformed/partial line is skipped, never raised.
# --------------------------------------------------------------------------
def parse_nuclei_jsonl(text: str, host: str = "") -> list[dict]:
    """nuclei -jsonl: one JSON object per line."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(j, dict):
            continue
        info = j.get("info") or {}
        out.append(finding(info.get("severity", "info"),
                           info.get("name") or j.get("template-id") or "nuclei match",
                           j.get("matched-at") or j.get("host") or host,
                           j.get("template-id", ""), "nuclei"))
    return out


def parse_httpx_jsonl(text: str) -> list[dict]:
    """httpx -json (one JSON object per probed URL)."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(j, dict):
            continue
        tech = j.get("tech")
        ev = " ".join(str(x) for x in (j.get("status_code"), j.get("webserver"),
                                       ",".join(tech) if isinstance(tech, list) else "") if x)
        out.append(finding("info", j.get("title") or j.get("webserver") or "http service",
                           j.get("url") or j.get("input") or "", ev, "httpx"))
    return out


def parse_nmap_grepable(text: str) -> list[dict]:
    """Open ports from nmap normal (-oN) output lines like '22/tcp open ssh'.
    Info-level (an open port isn't a vuln), one finding per open port."""
    out = []
    import re
    for line in (text or "").splitlines():
        m = re.match(r"\s*(\d{1,5})/(tcp|udp)\s+open\s+(\S+)?", line)
        if m:
            port, proto, svc = m.group(1), m.group(2), (m.group(3) or "").strip()
            out.append(finding("info", f"{port}/{proto} open" + (f" ({svc})" if svc else ""),
                               "", line.strip(), "nmap"))
    return out
