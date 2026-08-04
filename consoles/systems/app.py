#!/usr/bin/env python3
"""Systems — a live, read-only view of this machine's health.

CPU, memory, disks, network, listening ports, processes, sensors, and user
services. Every route is a GET: the data is read straight out of /proc, /sys,
and stdlib, so there's nothing to mutate and no CSRF surface — these are safe,
side-effect-free reads. All the actual collection lives in sysinfo.py; these
handlers only translate an HTTP GET into one collector call and never let a
collector exception reach the client (common's dispatcher already wraps that,
but each collector is itself written to degrade rather than raise).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shared import common
from consoles.systems import sysinfo


def h_overview(req: common.Request) -> common.Response:
    return common.Response.json(sysinfo.overview())


def h_cpu(req: common.Request) -> common.Response:
    return common.Response.json(sysinfo.cpu())


def h_memory(req: common.Request) -> common.Response:
    return common.Response.json(sysinfo.memory())


def h_disks(req: common.Request) -> common.Response:
    return common.Response.json({"disks": sysinfo.disks()})


def h_network(req: common.Request) -> common.Response:
    return common.Response.json({"interfaces": sysinfo.network()})


def h_listening(req: common.Request) -> common.Response:
    return common.Response.json(sysinfo.listening())


def h_processes(req: common.Request) -> common.Response:
    # limit is clamped to a sane window so a crafted ?limit=999999 can't make
    # the response huge; the collector still only sorts what /proc had.
    try:
        limit = int(req.q("limit", "15"))
    except ValueError:
        limit = 15
    limit = max(1, min(50, limit))
    return common.Response.json(sysinfo.processes(limit=limit))


def h_sensors(req: common.Request) -> common.Response:
    return common.Response.json(sysinfo.sensors())


def h_services(req: common.Request) -> common.Response:
    return common.Response.json(sysinfo.services())


def h_all(req: common.Request) -> common.Response:
    """The cheap panels bundled for first paint. Deliberately excludes the two
    collectors that sleep ~200ms to sample a delta (cpu, processes) and the
    /proc/*/fd socket scan (listening) — the UI fetches those on their own so
    the initial load stays snappy."""
    return common.Response.json({
        "overview": sysinfo.overview(),
        "memory": sysinfo.memory(),
        "disks": sysinfo.disks(),
        "network": sysinfo.network(),
        "sensors": sysinfo.sensors(),
    })


ROUTES = {
    "GET /api/systems/overview": h_overview,
    "GET /api/systems/cpu": h_cpu,
    "GET /api/systems/memory": h_memory,
    "GET /api/systems/disks": h_disks,
    "GET /api/systems/network": h_network,
    "GET /api/systems/listening": h_listening,
    "GET /api/systems/processes": h_processes,
    "GET /api/systems/sensors": h_sensors,
    "GET /api/systems/services": h_services,
    "GET /api/systems/all": h_all,
}


def build_app() -> common.App:
    return common.App(
        slug="systems",
        static_dir=Path(__file__).resolve().parent / "static",
        routes=ROUTES,
    )


if __name__ == "__main__":
    common.serve(build_app())
