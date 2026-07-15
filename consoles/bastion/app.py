#!/usr/bin/env python3
"""Bastion — defensive/opsec console. Local posture dashboard + the OSINT report engine."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shared import common
from consoles.bastion import posture
from engine import osint_report

REPORTS_DIR = Path(__file__).resolve().parents[2] / "engine" / "reports"


def h_posture(req: common.Request) -> common.Response:
    return common.Response.json(posture.run_all())


def h_hardening(req: common.Request) -> common.Response:
    return common.Response.json(posture.hardening_panel())


def h_hardening_plan(req: common.Request) -> common.Response:
    return common.Response.json(posture.hardening_plan())


def h_anonymity(req: common.Request) -> common.Response:
    return common.Response.json(posture.anonymity_panel())


def h_report(req: common.Request) -> common.Response:
    # POST-only: assessing a domain triggers outbound fetches and writes report
    # files, so it must carry a same-origin Origin (not a bare cross-origin GET).
    domain = str(req.json().get("domain", "")).strip()
    if not domain:
        return common.Response.error(400, "missing domain")
    try:
        report = osint_report.assess(domain)
    except ValueError as e:
        return common.Response.error(400, str(e))
    except Exception as e:
        return common.Response.error(500, f"assessment failed: {type(e).__name__}: {e}")

    try:
        paths = osint_report.write_reports(report, REPORTS_DIR, md=True, html=True, pdf=False)
    except OSError as e:
        paths = {}
        report.setdefault("_write_error", str(e))

    files = {}
    for kind in ("md", "html"):
        p = paths.get(kind)
        if p:
            files[kind] = {"path": str(p), "url": f"/api/report-file?path={p.name}"}

    report["files"] = files
    return common.Response.json(report)


def h_report_file(req: common.Request) -> common.Response:
    rel = req.q("path")
    if not rel:
        return common.Response.error(400, "missing ?path=")
    base = REPORTS_DIR.resolve()
    try:
        candidate = (base / rel).resolve()
        candidate.relative_to(base)  # raises ValueError if it escapes the sandbox
    except (ValueError, OSError):
        return common.Response.error(403, "path outside reports sandbox")
    if not candidate.is_file():
        return common.Response.error(404, "not found")

    ctype = "text/html; charset=utf-8" if candidate.suffix == ".html" else \
            "text/markdown; charset=utf-8" if candidate.suffix == ".md" else \
            "application/pdf" if candidate.suffix == ".pdf" else "application/octet-stream"
    try:
        data = candidate.read_bytes()
    except OSError:
        return common.Response.error(500, "read failed")
    return common.Response.raw(data, ctype)


ROUTES = {
    "GET /api/posture": h_posture,
    "GET /api/anonymity": h_anonymity,
    "GET /api/hardening": h_hardening,
    "GET /api/hardening-plan": h_hardening_plan,
    "POST /api/report": h_report,
    "GET /api/report-file": h_report_file,
}


def build_app() -> common.App:
    return common.App(slug="bastion", static_dir=Path(__file__).resolve().parent / "static", routes=ROUTES)


if __name__ == "__main__":
    common.serve(build_app())
