import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shared import common
from consoles.redcell import runners, inventory, builder

ROUTES = {
    "GET /api/inventory": inventory.handle_inventory,
    "POST /api/run": runners.handle_run,
    "GET /api/history": runners.handle_history,
    "GET /api/wordlists": runners.handle_wordlists,
    "POST /api/build": builder.handle_build,
    "POST /api/local-tool": runners.handle_local_tool,
}


def build_app():
    return common.App(slug="redcell", static_dir=Path(__file__).resolve().parent / "static", routes=ROUTES)


if __name__ == "__main__":
    common.serve(build_app())
