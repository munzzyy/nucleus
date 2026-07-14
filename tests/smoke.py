#!/usr/bin/env python3
"""End-to-end smoke test for the whole Nucleus suite.

Starts the hub + every console on offset test ports (real ports + 10000) so it
never collides with a running instance, then exercises the universal contract
and each console's key endpoints. Run: python3 tests/smoke.py
Exit 0 = all green.
"""
import importlib
import json
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from shared import common  # noqa: E402

OFFSET = 10000
APPS = {
    "hub": "hub.app",
    "recon": "consoles.recon.app",
    "redcell": "consoles.redcell.app",
    "bastion": "consoles.bastion.app",
}
BASE_PORT = {c["slug"]: c["port"] for c in common.CONSOLES}

passed, failed, skipped = [], [], []


def check(name, cond, detail=""):
    (passed if cond else failed).append(name)
    mark = "ok  " if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f"  — {detail}" if detail and not cond else ""))
    return cond


def skip(name, why):
    skipped.append(name)
    print(f"  [skip] {name}  — {why}")


def req(port, path, method="GET", body=None):
    url = f"http://127.0.0.1:{port}{path}"
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Host": f"127.0.0.1:{port}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
        headers["Origin"] = f"http://127.0.0.1:{port}"
    r = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=40) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def jget(port, path, **kw):
    st, body = req(port, path, **kw)
    try:
        return st, json.loads(body)
    except Exception:
        return st, {"_raw": body[:200].decode("utf-8", "replace")}


def main():
    servers = {}
    print("Starting suite on test ports…")
    for slug, modpath in APPS.items():
        try:
            mod = importlib.import_module(modpath)
            app = mod.build_app()
            port = BASE_PORT[slug] + OFFSET
            servers[slug] = (common.serve(app, port=port, block=False), port)
            print(f"  started {slug} on :{port}")
        except Exception as e:
            print(f"  NOT BUILT: {slug} ({type(e).__name__}: {e})")
    time.sleep(0.8)

    # ---- universal contract, every console that started ----
    print("\nUniversal contract:")
    for slug, (_, port) in servers.items():
        st, j = jget(port, "/healthz")
        check(f"{slug} /healthz 200", st == 200)
        st, _ = req(port, "/")
        check(f"{slug} / serves html", st == 200)
        st, j = jget(port, "/api/siblings")
        check(f"{slug} /api/siblings 200", st == 200 and "consoles" in j)
        st, _ = req(port, "/healthz", method="GET")
        # bad host guard
        bad = urllib.request.Request(f"http://127.0.0.1:{port}/healthz",
                                     headers={"Host": "evil.example:1"})
        try:
            with urllib.request.urlopen(bad, timeout=5) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        check(f"{slug} rejects foreign Host", code == 403)

    # ---- recon ----
    if "recon" in servers:
        print("\nRecon:")
        port = servers["recon"][1]
        st, j = jget(port, "/api/scan", method="POST", body={"type": "domain", "q": "example.com"})
        check("recon scan domain", st == 200, str(j)[:120])
        st, j = jget(port, "/api/scan", method="POST", body={"type": "ip", "q": "8.8.8.8"})
        check("recon scan ip", st == 200, str(j)[:120])
        st, j = jget(port, "/api/scan", method="POST", body={"type": "email", "q": "test@gmail.com"})
        check("recon scan email", st == 200, str(j)[:120])
        # scan must be POST-only now (no cross-origin GET side effects)
        st, _ = req(port, "/api/scan?type=domain&q=example.com", method="GET")
        check("recon scan not GET-reachable", st in (404, 405), f"got {st}")
        # forced-type validation rejects a bogus value
        st, j = jget(port, "/api/scan", method="POST", body={"type": "ip", "q": "not-an-ip"})
        check("recon rejects bad forced-type value", st == 400, str(j)[:120])
        # CSRF: a POST without a same-origin Origin is refused
        noorigin = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/scan", method="POST",
            data=b'{"type":"domain","q":"example.com"}',
            headers={"Host": f"127.0.0.1:{port}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(noorigin, timeout=10) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        check("recon POST without Origin refused", code == 403, f"got {code}")

    # ---- redcell ----
    if "redcell" in servers:
        print("\nRedcell:")
        port = servers["redcell"][1]
        st, j = jget(port, "/api/inventory")
        check("redcell inventory", st == 200 and ("summary" in j or "categories" in j or "tools" in j), str(j)[:120])
        # authorization gate must refuse an unauthorized run
        st, j = jget(port, "/api/run", method="POST",
                     body={"tool": "nmap", "target": "scanme.nmap.org", "authorized": False})
        check("redcell refuses unauthorized run", st != 200 or (isinstance(j, dict) and j.get("error")), str(j)[:120])
        # injection target must be refused
        st, j = jget(port, "/api/run", method="POST",
                     body={"tool": "nmap", "target": "x; rm -rf /", "authorized": True})
        check("redcell refuses injection target", st != 200 or (isinstance(j, dict) and j.get("error")), str(j)[:120])

    # ---- bastion ----
    if "bastion" in servers:
        print("\nBastion:")
        port = servers["bastion"][1]
        st, j = jget(port, "/api/posture")
        check("bastion posture", st == 200 and ("checks" in j or "summary" in j), str(j)[:120])
        st, j = jget(port, "/api/report", method="POST", body={"domain": "github.com"})
        check("bastion report engine", st == 200 and ("grade" in j or "findings" in j or "score" in j), str(j)[:160])
        # report must be POST-only now
        st, _ = req(port, "/api/report?domain=github.com", method="GET")
        check("bastion report not GET-reachable", st in (404, 405), f"got {st}")
        # traversal must be refused
        st, j = jget(port, "/api/report-file?path=../../../../etc/passwd")
        check("bastion report-file blocks traversal", st != 200, str(j)[:120])

    for srv, _ in servers.values():
        try:
            srv.shutdown()
        except Exception:
            pass

    print(f"\n{'='*50}\nPASS {len(passed)}   FAIL {len(failed)}   SKIP {len(skipped)}")
    if failed:
        print("FAILURES: " + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
