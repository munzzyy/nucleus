#!/usr/bin/env python3
"""Bastion — defensive/opsec console. Local posture dashboard, the metadata
scrub panel (mat2), and the OSINT report engine."""

import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shared import common
from consoles.bastion import posture, scrub
from engine import osint_report

REPORTS_DIR = Path(__file__).resolve().parents[2] / "engine" / "reports"


def h_posture(req: common.Request) -> common.Response:
    # ?force=1 bypasses the 30s posture cache for a manual "Refresh" from the UI
    # so the panel isn't stale-forever; the default poll stays cached.
    return common.Response.json(posture.run_all(force=bool(req.q("force"))))


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


# --------------------------------------------------------------------------
# Scrub panel (mat2) — the parsing itself lives in scrub.py; these handlers
# only translate HTTP into scrub calls and scrub errors into status codes.
# --------------------------------------------------------------------------
def _header(req: common.Request, name: str) -> str:
    # Header names are case-insensitive on the wire, but req.headers is a
    # plain dict of whatever the client sent — match on the lowercased key.
    want = name.lower()
    for k, v in req.headers.items():
        if k.lower() == want:
            return v
    return ""


def h_scrub_status(req: common.Request) -> common.Response:
    return common.Response.json(scrub.status())


def h_scrub_upload(req: common.Request) -> common.Response:
    # Raw body = the file bytes; the (percent-encoded UTF-8) filename rides in
    # X-Filename. POST-only, so common's Origin check applies; the oversized
    # body cap is enforced upstream via App.body_limits before we ever run.
    #
    # Fail loud, first thing: a missing mat2 must read as "the panel is
    # offline", never as a mysterious per-file failure.
    if scrub.mat2_path() is None:
        return common.Response.error(
            503, "mat2 is not installed — the scrub panel is offline. Install it: sudo pacman -S mat2")
    raw = _header(req, "X-Filename")
    name = scrub.sanitize_name(urllib.parse.unquote(raw)) if raw.strip() else ""
    if not name:
        return common.Response.error(400, "missing X-Filename header")
    if not req.body:
        return common.Response.error(400, "empty upload")
    exts = scrub.supported_exts()
    ext = Path(name).suffix.lower()
    if ext not in exts:
        return common.Response.error(
            415, f"mat2 can't clean {ext or 'extension-less'} files (supported: {len(exts)} formats)")
    sess = scrub.create_session(name, req.body)
    result = scrub.inspect(sess["token"])
    if "error" in result:
        # A file mat2 can't even inspect isn't worth keeping: delete the
        # session so no orphan survives, and 422 with the reason. Simplest UI
        # contract — an upload either yields a live card or a clear error.
        scrub.delete_session(sess["token"])
        return common.Response.error(422, result["error"])
    return common.Response.json({
        "token": sess["token"], "name": sess["name"], "size": sess["size"], "ext": ext,
        "metadata": result["metadata"], "notes": result["notes"],
        "sandbox": common.which("bwrap") is not None,
    })


def h_scrub_clean(req: common.Request) -> common.Response:
    j = req.json()
    token = str(j.get("token") or "")
    try:
        result = scrub.clean(token,
                             lightweight=bool(j.get("lightweight") or False),
                             unknown_members=str(j.get("unknown_members") or "abort"))
    except ValueError as e:
        return common.Response.error(400, str(e))
    except FileNotFoundError:
        return common.Response.error(404, "no such session — it may have hit the 24h auto-purge")
    if "error" in result:
        # 422 carries mat2's own words — e.g. its abort-on-unknown-archive-
        # member message is exactly what the user needs to pick another policy.
        return common.Response.error(422, result["error"])
    result["token"] = token
    result["download"] = f"/api/scrub/file?token={token}"
    return common.Response.json(result)


def h_scrub_file(req: common.Request) -> common.Response:
    # Serves ONLY the cleaned artifact — scrub.cleaned_file() cannot return
    # the original, so this endpoint can't reflect a hostile upload back out
    # with its metadata intact.
    try:
        path, name = scrub.cleaned_file(req.q("token"))
    except ValueError:
        return common.Response.error(400, "bad token")
    except FileNotFoundError:
        return common.Response.error(404, "no cleaned file for that session")
    try:
        data = path.read_bytes()
    except OSError:
        return common.Response.error(500, "read failed")
    # `name` is sanitize_name() output — pure ASCII, no quotes/CR/LF — so it's
    # safe verbatim inside a quoted Content-Disposition.
    return common.Response.raw(
        data, "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{name}"'})


def h_scrub_delete(req: common.Request) -> common.Response:
    token = str(req.json().get("token") or "")
    try:
        scrub.delete_session(token)  # idempotent — a gone session is still ok
    except ValueError:
        return common.Response.error(400, "bad token")
    return common.Response.json({"ok": True})


ROUTES = {
    "GET /api/posture": h_posture,
    "GET /api/anonymity": h_anonymity,
    "GET /api/hardening": h_hardening,
    "GET /api/hardening-plan": h_hardening_plan,
    "POST /api/report": h_report,
    "GET /api/report-file": h_report_file,
    "GET /api/scrub/status": h_scrub_status,
    "POST /api/scrub/upload": h_scrub_upload,
    "POST /api/scrub/clean": h_scrub_clean,
    "GET /api/scrub/file": h_scrub_file,
    "POST /api/scrub/delete": h_scrub_delete,
}


def build_app() -> common.App:
    # Reap expired scrub sessions at startup — cheap, and it means private
    # files never outlive SESSION_TTL just because nobody uploads anything new.
    try:
        scrub.purge_stale()
    except OSError:
        pass
    return common.App(
        slug="bastion",
        static_dir=Path(__file__).resolve().parent / "static",
        routes=ROUTES,
        # Only the upload route takes big bodies; every other POST keeps the
        # global 256 KiB cap from common.MAX_BODY.
        body_limits={"POST /api/scrub/upload": scrub.MAX_UPLOAD},
    )


if __name__ == "__main__":
    common.serve(build_app())
