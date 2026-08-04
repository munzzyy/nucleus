#!/usr/bin/env python3
"""Nucleus desktop app — the whole command center in one real native window.

Double-click and it starts every console (and coleos-hub, if present) in the
background, then opens a single Qt/Chromium window on the hub. The in-page
switcher moves between consoles inside the same window, so it feels like one
app, not four browser tabs. Everything stays on 127.0.0.1.

Uses the system PySide6 + QtWebEngine (already installed) — no pip deps.
Falls back to the default browser if Qt isn't available.

    python3 bin/nucleus_app.py            # launch the app
    python3 bin/nucleus_app.py --selftest # headless: prove it boots + loads
"""
import importlib
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from shared import common  # noqa: E402

HUB_PORT = 8890
SERVERS = [
    ("hub", "hub.app"), ("recon", "consoles.recon.app"),
    ("redcell", "consoles.redcell.app"), ("bastion", "consoles.bastion.app"),
    ("devkit", "consoles.devkit.app"), ("systems", "consoles.systems.app"),
]
_coleos_proc = None


def _busy(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def start_backend():
    """Bring up every console in-process (daemon threads) + coleos-hub."""
    for slug, modpath in SERVERS:
        port = common.CONSOLE_BY_SLUG[slug]["port"]
        if _busy(port):
            continue
        try:
            mod = importlib.import_module(modpath)
            common.serve(mod.build_app(), port=port, block=False)
        except Exception as e:  # one console failing shouldn't stop the app
            print(f"[nucleus] {slug} did not start: {e}", file=sys.stderr)
    _start_coleos_hub()
    # wait until the hub answers so the first page load isn't a connection error
    for _ in range(50):
        if _busy(HUB_PORT):
            return True
        time.sleep(0.1)
    return _busy(HUB_PORT)


def _start_coleos_hub():
    """Start Cole's vault hub too, so 'connected to it all' is literal."""
    global _coleos_proc
    server = Path.home() / "Projects" / "coleos-hub" / "server.py"
    if _busy(4747) or not server.exists():
        return
    try:
        _coleos_proc = subprocess.Popen(
            [sys.executable, str(server)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as e:
        print(f"[nucleus] coleos-hub did not start: {e}", file=sys.stderr)


def _stop_coleos_hub():
    if _coleos_proc:
        try:
            _coleos_proc.terminate()
        except OSError:
            pass


def run_browser_fallback():
    import webbrowser
    print("[nucleus] Qt not available — opening in your browser instead.")
    webbrowser.open(f"http://127.0.0.1:{HUB_PORT}/")
    print("Servers are running. Press Ctrl-C to stop.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


def run_app(selftest: bool = False) -> int:
    if selftest:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtCore import QUrl, Qt, QTimer
        from PySide6.QtGui import QAction, QIcon, QKeySequence
        from PySide6.QtWebEngineWidgets import QWebEngineView
        from PySide6.QtWidgets import QApplication, QMainWindow, QToolBar
    except Exception as e:
        print(f"[nucleus] Qt import failed ({e}).", file=sys.stderr)
        if not selftest:
            run_browser_fallback()
            return 0
        return 3

    app = QApplication(sys.argv[:1])
    app.setApplicationName("Nucleus")
    app.setApplicationDisplayName("Nucleus")
    icon_path = REPO / "bin" / "nucleus.png"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    win = QMainWindow()
    win.setWindowTitle("Nucleus — Security Command Center")
    view = QWebEngineView()

    def go(port):
        return lambda: view.setUrl(QUrl(f"http://127.0.0.1:{port}/"))

    tb = QToolBar()
    tb.setMovable(False)
    win.addToolBar(tb)

    def add(label, fn, shortcut=None, tip=None):
        a = QAction(label, win)
        a.triggered.connect(fn)
        if shortcut:
            a.setShortcut(QKeySequence(shortcut))
        if tip:
            a.setToolTip(tip)
        tb.addAction(a)
        return a

    add("⌂  Hub", go(8890), "Alt+Home", "Back to the command center")
    tb.addSeparator()
    add("Recon", go(8900), tip="OSINT")
    add("Redcell", go(8910), tip="Offensive")
    add("Bastion", go(8920), tip="Defensive / opsec")
    add("Devkit", go(8930), tip="Dev toolbelt")
    add("Systems", go(8940), tip="Local machine health")
    tb.addSeparator()
    add("←", view.back, "Alt+Left", "Back")
    add("↻", view.reload, "F5", "Reload")

    win.setCentralWidget(view)
    win.resize(1440, 920)
    view.setUrl(QUrl(f"http://127.0.0.1:{HUB_PORT}/"))

    if selftest:
        result = {"ok": False}

        def on_load(ok):
            result["ok"] = ok
            app.quit()
        view.loadFinished.connect(on_load)
        QTimer.singleShot(15000, app.quit)  # hard cap
        win.show()
        app.exec()
        print("SELFTEST:", "PASS — hub page loaded in the native window"
              if result["ok"] else "FAIL — page did not load")
        _stop_coleos_hub()
        return 0 if result["ok"] else 4

    win.show()
    rc = app.exec()
    _stop_coleos_hub()
    return rc


def main():
    selftest = "--selftest" in sys.argv[1:]
    if not start_backend():
        print("[nucleus] backend did not come up on :8890", file=sys.stderr)
        return 1
    return run_app(selftest=selftest)


if __name__ == "__main__":
    sys.exit(main())
