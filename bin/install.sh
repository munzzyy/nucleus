#!/usr/bin/env bash
# Install Nucleus as a real app on this machine:
#   - a `nucleus` command on your PATH (~/.local/bin)
#   - an app-menu entry (Nucleus) that launches the hub in your browser
#   - an optional systemd --user service so it can autostart
#
# Nothing here touches the system or needs root. Everything is loopback-only.
# Re-runnable (idempotent). Undo notes at the bottom.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$HOME/.local/bin"
APPS="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons/hicolor/scalable/apps"
UNITS="$HOME/.config/systemd/user"

echo ">> Nucleus install (repo: $REPO)"

mkdir -p "$BIN" "$APPS" "$ICONS" "$UNITS"

# 1) `nucleus` on PATH
ln -sf "$REPO/bin/nucleus" "$BIN/nucleus"
chmod +x "$REPO/bin/nucleus"
echo "   • command:  $BIN/nucleus  (make sure ~/.local/bin is on your PATH)"

# 2) icon (png + svg)
cp -f "$REPO/bin/nucleus.svg" "$ICONS/nucleus.svg"
mkdir -p "$HOME/.local/share/icons/hicolor/256x256/apps"
[ -f "$REPO/bin/nucleus.png" ] && cp -f "$REPO/bin/nucleus.png" "$HOME/.local/share/icons/hicolor/256x256/apps/nucleus.png"

# 3) app-menu launcher — one click opens the native desktop window
cat > "$APPS/nucleus.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Nucleus
GenericName=Security Command Center
Comment=Recon, offense, defense — one local command center
Exec=/usr/bin/env python3 $REPO/bin/nucleus_app.py
Icon=nucleus
Terminal=false
StartupWMClass=Nucleus
Categories=Security;Network;Development;Utility;System;
Keywords=osint;pentest;security;opsec;recon;devtools;encode;hash;jwt;system;monitor;dork;
EOF
echo "   • menu entry: Nucleus (native app, one click)"

update-desktop-database "$APPS" >/dev/null 2>&1 || true
gtk-update-icon-cache "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true

# 4) optional systemd --user service (installed, NOT enabled — your call)
sed "s|%h/Projects/nucleus|$REPO|g" "$REPO/bin/nucleus.service" > "$UNITS/nucleus.service"
systemctl --user daemon-reload 2>/dev/null || true
echo "   • systemd unit installed (not enabled). To autostart on login:"
echo "       systemctl --user enable --now nucleus.service"

echo
echo "Done. Start it now with:  nucleus up --open"
echo
echo "UNDO:"
echo "  rm -f $BIN/nucleus $APPS/nucleus.desktop $ICONS/nucleus.svg"
echo "  systemctl --user disable --now nucleus.service 2>/dev/null; rm -f $UNITS/nucleus.service"
