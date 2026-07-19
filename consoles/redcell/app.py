import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shared import common
from consoles.redcell import (runners, inventory, builder, hashtools, webscan, playbooks,
                               secretscan, stresstest, tlsaudit, techfp, jwtaudit)

ROUTES = {
    "GET /api/inventory": inventory.handle_inventory,
    "POST /api/inventory/refresh": inventory.handle_inventory_refresh,
    "POST /api/run": runners.handle_run,
    "GET /api/history": runners.handle_history,
    "GET /api/wordlists": runners.handle_wordlists,
    "GET /api/wordlist-preview": runners.handle_wordlist_preview,
    "GET /api/outputs": runners.handle_outputs,
    "GET /api/output-file": runners.handle_output_file,
    "POST /api/build": builder.handle_build,
    "POST /api/local-tool": runners.handle_local_tool,
    "GET /api/expert-tools": runners.handle_expert_tools,
    "POST /api/expert": runners.handle_expert,
    # ---- new: password cracking, native web analysis, assessment playbooks ----
    "POST /api/hash-id": hashtools.handle_hash_id,
    "POST /api/web-analyze": webscan.handle_web_analyze,
    "POST /api/secret-scan": secretscan.handle_secret_scan,
    "GET /api/playbooks": playbooks.handle_playbooks,
    # ---- new: DDoS resilience testing (bounded L7 probe + load-test builder) ----
    "POST /api/stress-token": stresstest.handle_stress_token,
    "POST /api/stress-verify": stresstest.handle_stress_verify,
    "POST /api/stress-probe": stresstest.handle_stress_probe,
    "POST /api/stress-build": stresstest.handle_stress_build,
    # ---- new: deep TLS audit, passive tech fingerprinting, offline JWT analysis ----
    "POST /api/tls-audit": tlsaudit.handle_tls_audit,
    "POST /api/tech-fingerprint": techfp.handle_tech_fingerprint,
    "POST /api/jwt-audit": jwtaudit.handle_jwt_audit,
}


def build_app():
    return common.App(slug="redcell", static_dir=Path(__file__).resolve().parent / "static", routes=ROUTES)


if __name__ == "__main__":
    common.serve(build_app())
