#!/usr/bin/env python3
"""End-to-end smoke test for the whole Nucleus suite.

Starts the hub + every console on offset test ports (real ports + 10000) so it
never collides with a running instance, then exercises the universal contract
and each console's key endpoints. Run: python3 tests/smoke.py
Exit 0 = all green.
"""
import importlib
import json
import os
import struct
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from shared import common  # noqa: E402

# Scrub sessions must land in a throwaway tree, never the real var/scrub.
# consoles.bastion.scrub reads NUCLEUS_SCRUB_DIR once at import time, so the
# override has to be in place before main() imports the bastion app below.
_SCRUB_TMP = tempfile.TemporaryDirectory(prefix="nucleus-smoke-scrub-")
os.environ["NUCLEUS_SCRUB_DIR"] = _SCRUB_TMP.name

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


def scrub_png():
    """The scrub-spec fixture: a 1x1 PNG with a tEXt `Author: Jane Doe` chunk
    mat2 can find and strip — built from stdlib so the smoke run carries no
    binary blob."""
    def _chunk(t, d):
        c = t + d
        return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr)
            + _chunk(b"tEXt", b"Author\x00Jane Doe")
            + _chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + _chunk(b"IEND", b""))


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

        # ---- new: hash identifier (pure offline, no gate) ----
        st, j = jget(port, "/api/hash-id", method="POST",
                     body={"hash": "5f4dcc3b5aa765d61d8327deb882cf99"})
        top = (j.get("candidates") or [{}])[0] if isinstance(j, dict) else {}
        check("redcell hash-id identifies md5", st == 200 and top.get("hashcat") == 0, str(j)[:120])
        check("redcell hash-id builds crack command",
              isinstance(top.get("commands"), dict) and bool(top["commands"].get("hashcat")), str(top)[:120])
        # NTLM must appear in the ambiguous set for a bare 32-hex
        st, j = jget(port, "/api/hash-id", method="POST",
                     body={"hash": "b4b9b02e6f09a9bd760f388b67351e2b"})
        names = " ".join(c.get("name", "") for c in (j.get("candidates") or [])) if isinstance(j, dict) else ""
        check("redcell hash-id shows NTLM ambiguity", "NTLM" in names and "MD5" in names, names[:120])
        # hash-id is a mutating POST route -> must still enforce the CSRF Origin check
        noorigin = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/hash-id", method="POST", data=b'{"hash":"x"}',
            headers={"Host": f"127.0.0.1:{port}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(noorigin, timeout=5) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        check("redcell hash-id POST without Origin refused", code == 403, f"got {code}")

        # ---- new: assessment playbooks (catalog only; steps are client-run) ----
        st, j = jget(port, "/api/playbooks")
        pbs = j.get("playbooks") if isinstance(j, dict) else None
        check("redcell playbooks catalog", st == 200 and isinstance(pbs, list) and len(pbs) >= 3, str(j)[:120])

        # ---- new: native web analyzer (same auth + scope gate as runners) ----
        st, j = jget(port, "/api/web-analyze", method="POST",
                     body={"url": "https://example.com"})  # no authorized flag
        check("redcell web-analyze refuses without authorization", st == 403, f"got {st}")
        st, j = jget(port, "/api/web-analyze", method="POST",
                     body={"url": "http://127.0.0.1/", "authorized": True})  # private, no lab
        check("redcell web-analyze refuses loopback out of scope", st == 403, f"got {st}")

        # ---- new: secret / API-key leak scanner (same gate) ----
        st, j = jget(port, "/api/secret-scan", method="POST",
                     body={"url": "https://example.com"})  # no authorized flag
        check("redcell secret-scan refuses without authorization", st == 403, f"got {st}")
        st, j = jget(port, "/api/secret-scan", method="POST",
                     body={"url": "http://169.254.169.254/", "authorized": True})  # link-local metadata
        check("redcell secret-scan refuses non-public target", st == 403, f"got {st}")

        # ---- new: DDoS resilience (bounded probe + load-test builder) ----
        st, j = jget(port, "/api/stress-probe", method="POST",
                     body={"url": "https://example.com"})  # no authorized flag
        check("redcell stress-probe refuses without authorization", st == 403, f"got {st}")
        st, j = jget(port, "/api/stress-probe", method="POST",
                     body={"url": "https://example.com", "authorized": True, "tier": "nuke"})
        check("redcell stress-probe refuses invalid tier", st == 400, f"got {st}")
        st, j = jget(port, "/api/stress-probe", method="POST",
                     body={"url": "http://10.0.0.1", "authorized": True})  # private, no lab
        check("redcell stress-probe refuses private out of scope", st == 403, f"got {st}")
        # Custom tier is accepted by validation (clamps its own params) — it must
        # reach the scope gate, not be rejected as an invalid tier. Private target
        # → 403 scope, proving the tier passed.
        st, j = jget(port, "/api/stress-probe", method="POST",
                     body={"url": "http://10.0.0.1", "authorized": True, "tier": "custom",
                           "requests": 500, "duration": "30s", "concurrency": 20})
        check("redcell stress-probe accepts custom tier (reaches scope gate)", st == 403, f"got {st}")
        st, j = jget(port, "/api/stress-build", method="POST",
                     body={"engine": "k6", "params": {"url": "https://example.com"}})
        check("redcell stress-build assembles a command, unexecuted",
              st == 200 and isinstance(j, dict) and j.get("executed") is False
              and bool(j.get("files") or j.get("command")), str(j)[:120])
        st, j = jget(port, "/api/stress-token", method="POST", body={"target": "example.com"})
        check("redcell stress-token mints a token",
              st == 200 and isinstance(j, dict) and str(j.get("token", "")).startswith("nucleus-loadtest-"), str(j)[:120])
        # CSRF: a POST without a same-origin Origin must be refused like the others
        noorigin = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/stress-probe", method="POST", data=b"{}",
            headers={"Host": f"127.0.0.1:{port}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(noorigin, timeout=5) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        check("redcell stress-probe POST without Origin refused", code == 403, f"got {code}")

        # ---- new: wordlist preview (read-only, registry-gated path) ----
        st, wl = jget(port, "/api/wordlists?q=common&limit=3")
        wid = (wl.get("results") or [{}])[0].get("id") if isinstance(wl, dict) else None
        if wid:
            st, j = jget(port, "/api/wordlist-preview?id=" + urllib.parse.quote(wid))
            check("redcell wordlist-preview reads a registered list",
                  st == 200 and isinstance(j.get("preview"), list) and j.get("line_count", 0) > 0, str(j)[:120])
            # an unregistered / traversal id must be refused
            st, j = jget(port, "/api/wordlist-preview?id=" + urllib.parse.quote("../../../../etc/passwd"))
            check("redcell wordlist-preview blocks unknown/traversal id", st == 400, f"got {st}")
        else:
            skip("redcell wordlist-preview", "no wordlists registered on this box")

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

        # ---- scrub (mat2 metadata cleaner): full upload → clean → download →
        # delete round trip, against the temp NUCLEUS_SCRUB_DIR set at the top ----
        if common.which("mat2"):
            st, j = jget(port, "/api/scrub/status")
            check("bastion scrub status available", st == 200 and j.get("available") is True
                  and bool(j.get("version")), str(j)[:120])

            # upload is a raw-body POST (not JSON), so build it by hand — same
            # Origin discipline as every other POST in this file
            upreq = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/scrub/upload", method="POST", data=scrub_png(),
                headers={"Host": f"127.0.0.1:{port}",
                         "Origin": f"http://127.0.0.1:{port}",
                         "Content-Type": "application/octet-stream",
                         "X-Filename": urllib.parse.quote("smoke.png")})
            try:
                with urllib.request.urlopen(upreq, timeout=60) as r:
                    ust, uj = r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                ust, uj = e.code, {}
            except Exception as e:  # noqa: BLE001 — a smoke check records, never crashes
                ust, uj = 0, {"_err": f"{type(e).__name__}: {e}"}
            token = uj.get("token") or ""
            meta_keys = [p.get("key") for p in (uj.get("metadata") or [])]
            check("bastion scrub upload sees Author", ust == 200 and bool(token)
                  and "Author" in meta_keys, str(uj)[:160])

            st, j = jget(port, "/api/scrub/clean", method="POST", body={"token": token})
            check("bastion scrub clean re-checks clean", st == 200 and j.get("clean") is True
                  and j.get("metadata_after") == [], str(j)[:160])

            dlreq = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/scrub/file?token=" + urllib.parse.quote(token),
                headers={"Host": f"127.0.0.1:{port}"})
            try:
                with urllib.request.urlopen(dlreq, timeout=30) as r:
                    dst = r.status
                    dtype = r.headers.get("Content-Type", "")
                    dispo = r.headers.get("Content-Disposition", "")
                    data = r.read()
            except urllib.error.HTTPError as e:
                dst, dtype, dispo, data = e.code, "", "", b""
            check("bastion scrub download is the clean file",
                  dst == 200 and "octet-stream" in dtype and "attachment" in dispo
                  and data.startswith(b"\x89PNG\r\n\x1a\n") and b"tEXt" not in data,
                  f"status {dst} type {dtype!r} dispo {dispo!r} len {len(data)}")

            st, j = jget(port, "/api/scrub/delete", method="POST", body={"token": token})
            check("bastion scrub delete ok", st == 200 and j.get("ok") is True, str(j)[:120])
        else:
            skip("bastion scrub round-trip", "mat2 not installed")

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
