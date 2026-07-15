import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shared import common
from consoles.recon import detect, lookups, resources

MAX_QUERY_LEN = 512


def _scan(req):
    # POST-only: a scan triggers outbound fetches, so it must not be a plain
    # cross-origin GET. The body carries {q, type}.
    body = req.json()
    raw = str(body.get("q", "")).strip()
    type_param = str(body.get("type", "auto") or "auto").strip().lower()

    if not raw:
        return common.Response.error(400, "missing q")
    if len(raw) > MAX_QUERY_LEN:
        return common.Response.error(400, "q too long")

    t0 = time.monotonic()

    if type_param == "auto":
        kind, normalized = detect.classify(raw)
    else:
        if type_param not in detect.VALID_TYPES:
            return common.Response.error(400, f"unknown type: {type_param}")
        kind = type_param
        normalized = detect.normalize_for(kind, raw)

    # Validate the value against the (possibly forced) type — the format check
    # must run no matter how `type` arrived, not only on auto-detect.
    if not detect.validate(kind, normalized):
        return common.Response.error(400, f"'{raw}' is not a valid {kind}")

    modules: dict = {}
    errors: dict = {}
    try:
        if kind == "username":
            modules["username"] = lookups.username_scan(normalized)
        elif kind == "email":
            modules["email"] = lookups.email_scan(normalized)
        elif kind == "domain":
            modules["domain"] = lookups.domain_scan(normalized)
        elif kind == "ip":
            modules["ip"] = lookups.ip_scan(normalized)
        elif kind == "phone":
            modules["phone"] = lookups.phone_scan(normalized)
        elif kind == "hash":
            modules["hash"] = lookups.hash_scan(normalized)
        elif kind == "crypto":
            modules["crypto"] = lookups.crypto_scan(normalized)
        elif kind == "mac":
            modules["mac"] = lookups.mac_scan(normalized)
        elif kind in ("name", "company"):
            modules[kind] = lookups.wikipedia_scan(normalized)
        # image / geo have no live module -- pivots + dorks below are the
        # whole answer for those.
    except Exception as e:  # a module bug degrades to an error field, not a 500
        errors[kind] = f"{type(e).__name__}: {e}"

    result = {
        "input": raw,
        "detected_type": kind,
        "normalized": normalized,
        "modules": modules,
        "pivots": detect.pivots_for(kind, normalized),
        "dorks": detect.dorks_for(kind, normalized),
        "errors": errors,
        "took_ms": round((time.monotonic() - t0) * 1000),
    }
    lookups.log_scan(kind, raw, result)  # best-effort case history; never fails the response
    return common.Response.json(result)


def _arsenal(req):
    return common.Response.json(lookups.arsenal_status())


def _recon_history(req):
    try:
        limit = int(req.q("limit", "50"))
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 500))
    return common.Response.json({"scans": lookups.history_list(limit)})


def _recon_scan_get(req):
    scan_id = req.q("id", "").strip()
    scan = lookups.history_get(scan_id) if scan_id else None
    if scan is None:
        return common.Response.error(404, "scan not found")
    return common.Response.json(scan)


def _resources(req):
    return common.Response.json({
        "categories": [{"name": cat, "items": items} for cat, items in resources.RESOURCES.items()],
        "count": sum(len(items) for items in resources.RESOURCES.values()),
    })


ROUTES = {
    "POST /api/scan": _scan,
    "GET /api/arsenal": _arsenal,
    "GET /api/resources": _resources,
    "GET /api/recon-history": _recon_history,
    "GET /api/recon-scan": _recon_scan_get,
}


def build_app() -> "common.App":
    return common.App(slug="recon", static_dir=Path(__file__).resolve().parent / "static", routes=ROUTES)


if __name__ == "__main__":
    common.serve(build_app())
