"""Bastion posture checks — read-only inspection of this box's hardening.

Every probe here is read-only: status commands (`systemctl is-active`,
`sysctl -n`, `resolvectl status`, `wg show`, `arch-audit`) and file reads.
Nothing in this module runs sudo, writes to the filesystem, or touches
system state. Where a probe needs root it just can't (permission denied /
directory unreadable) and we report that honestly as "unknown" rather than
guessing.

Two public entry points:
  run_all()          -> {"checks": [...], "summary": {...}}   for /api/posture
  hardening_panel()  -> {"scripts": [...]}                    for /api/hardening
"""

from __future__ import annotations

import socket
from pathlib import Path

from shared import common

HOME = Path.home()
SETUP_DIR = HOME / "security-setup"

_QUAD9_ADDRS = {"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"}


def _check(id_: str, label: str, category: str, status: str, detail: str,
           fix_hint: str = "") -> dict:
    return {"id": id_, "label": label, "category": category, "status": status,
            "detail": detail, "fix_hint": fix_hint}


def _svc_active(name: str, timeout: float = 3.0) -> tuple[bool, str]:
    """(is_active, raw_state) via `systemctl is-active` — never raises."""
    r = common.run_tool(["systemctl", "is-active", name], timeout=timeout)
    state = (r.stdout or r.error or "unknown").strip() or "unknown"
    return state == "active", state


def _tcp_open(host: str, port: int, timeout: float = 0.6) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# --------------------------------------------------------------------------
# individual checks
# --------------------------------------------------------------------------
_SYSCTL_EXPECT = {
    "kernel.kptr_restrict": "2",
    "kernel.dmesg_restrict": "1",
    "fs.protected_regular": "2",
    "net.ipv4.tcp_syncookies": "1",
}


def check_sysctl() -> dict:
    conf = Path("/etc/sysctl.d/99-cole-hardening.conf")
    conf_exists = conf.is_file()
    live = {}
    for key in _SYSCTL_EXPECT:
        r = common.run_tool(["sysctl", "-n", key], timeout=3)
        live[key] = r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None
    matched = sum(1 for k, v in _SYSCTL_EXPECT.items() if live.get(k) == v)
    total = len(_SYSCTL_EXPECT)
    bits = ", ".join(f"{k}={live.get(k) or '?'} (want {v})" for k, v in _SYSCTL_EXPECT.items())

    if matched == total and conf_exists:
        status, summary = "ok", "conf present, all spot-checked values applied"
    elif matched == total:
        status, summary = "ok", "live values applied (conf file missing at the expected path)"
    elif matched > 0:
        status, summary = "warn", f"partial — {matched}/{total} spot-checked values applied"
    elif conf_exists:
        status, summary = "warn", "conf present but not applied yet (needs `sysctl --system` or a reboot)"
    else:
        status, summary = "bad", "not applied — conf file absent and live defaults in place"

    return _check("sysctl", "Kernel / network hardening (sysctl)", "hardening", status,
                  f"{summary}. {bits}", "sudo ~/security-setup/2-harden.sh")


def check_auditd() -> dict:
    active, state = _svc_active("auditd")
    status = "ok" if active else "bad"
    return _check("auditd", "auditd", "hardening", status,
                  "running" if active else f"inactive ({state})",
                  "sudo systemctl enable --now auditd")


def check_usbguard() -> dict:
    installed = common.which("usbguard") is not None
    if not installed:
        return _check("usbguard", "USBGuard", "hardening", "unknown", "not installed",
                      "sudo ~/security-setup/1-install.sh")
    active, state = _svc_active("usbguard")
    policy = Path("/etc/usbguard/rules.conf").is_file()
    if active:
        status, detail = "ok", "installed, daemon active" + (", policy present" if policy else "")
    else:
        status = "warn"
        detail = ("installed, daemon inactive by design (policy pre-generated, review before enabling)"
                   if policy else f"installed, daemon inactive ({state}), no policy generated yet")
    return _check("usbguard", "USBGuard", "hardening", status, detail,
                  "sudo systemctl enable --now usbguard  # review /etc/usbguard/rules.conf first")


def check_dns() -> dict:
    r = common.run_tool(["resolvectl", "status"], timeout=5)
    if r.returncode != 0 or not r.stdout.strip():
        return _check("dns", "Encrypted DNS (Quad9 DoT)", "opsec", "unknown",
                      "resolvectl status unavailable" + (f": {r.error}" if r.error else ""),
                      "sudo ~/security-setup/3-secure-dns.sh")

    out = r.stdout
    # "Global" section runs from the top of the output to the first "Link N" header.
    global_block = out.split("\nLink ")[0]
    dot_on = "+DNSOverTLS" in global_block
    quad9_active = any(addr in global_block for addr in _QUAD9_ADDRS)

    conf_dot = Path("/etc/systemd/resolved.conf.d/dns-over-tls.conf").is_file()
    conf_handoff = Path("/etc/NetworkManager/conf.d/dns-resolved.conf").is_file()
    conf_force = Path("/etc/NetworkManager/conf.d/10-force-quad9-dns.conf").is_file()

    detail = (f"DNSOverTLS={'on' if dot_on else 'off'}, "
              f"current server is Quad9={'yes' if quad9_active else 'no'}, "
              f"conf files: dot={conf_dot} nm-handoff={conf_handoff} force-quad9={conf_force}")

    if dot_on and quad9_active and conf_dot:
        status = "ok"
    elif dot_on or quad9_active or conf_dot:
        status = "warn"
    else:
        status = "bad"

    fix = "sudo ~/security-setup/3-secure-dns.sh"
    if status == "warn" and not conf_force:
        fix += "  (then sudo ~/security-setup/4-dns-force-quad9.sh to remove leftover ISP/DHCP DNS)"
    return _check("dns", "Encrypted DNS (Quad9 DoT)", "opsec", status, detail, fix)


def check_tor() -> dict:
    installed = common.which("tor") is not None
    if not installed:
        return _check("tor", "Tor", "opsec", "unknown", "not installed",
                      "sudo ~/security-setup/1-install.sh")
    active, state = _svc_active("tor")
    listening = _tcp_open("127.0.0.1", 9050)
    if active and listening:
        status, detail = "ok", "daemon active, SOCKS listening on 127.0.0.1:9050"
    elif active and not listening:
        status, detail = "warn", f"daemon reports active ({state}) but nothing is listening on :9050"
    elif listening:
        status, detail = "warn", "not systemd-managed but something is listening on :9050"
    else:
        status = "unknown"
        detail = "installed, daemon intentionally left off by default — launch Tor Browser for on-demand Tor"
    return _check("tor", "Tor", "opsec", status, detail,
                  "sudo systemctl enable --now tor   # or just launch Tor Browser")


def check_wireguard() -> dict:
    installed = common.which("wg") is not None
    if not installed:
        return _check("wireguard", "WireGuard VPN", "opsec", "unknown", "wireguard-tools not installed",
                      "sudo ~/security-setup/1-install.sh")

    try:
        conf_count = len(list(Path("/etc/wireguard").glob("*.conf")))
        conf_note = f"{conf_count} config(s) in /etc/wireguard"
    except (PermissionError, OSError):
        conf_note = "/etc/wireguard not readable as this user (normal — root-only dir)"

    r = common.run_tool(["wg", "show"], timeout=4)
    if r.returncode != 0:
        return _check("wireguard", "WireGuard VPN", "opsec", "unknown",
                      f"wg show failed: {r.error or r.stderr.strip()}. {conf_note}",
                      "sudo wg-quick up <name>")
    active = bool(r.stdout.strip())
    status = "ok" if active else "unknown"
    detail = ("tunnel currently up — " + r.stdout.strip().splitlines()[0]) if active else \
             f"installed, no tunnel currently up. {conf_note}"
    return _check("wireguard", "WireGuard VPN", "opsec", status, detail,
                  "sudo wg-quick up <name>  (drop a config in /etc/wireguard/ first)")


def check_wifi_mac() -> dict:
    conf = Path("/etc/NetworkManager/conf.d/00-wifi-mac-random.conf")
    if conf.is_file():
        return _check("wifi-mac", "Wi-Fi MAC randomization", "opsec", "ok",
                      "conf present: scan + connection MAC randomized", "")
    return _check("wifi-mac", "Wi-Fi MAC randomization", "opsec", "warn", "not configured",
                  "sudo ~/security-setup/2-harden.sh")


def check_firewall() -> dict:
    for svc in ("firewalld", "ufw", "nftables"):
        active, state = _svc_active(svc)
        if active:
            return _check("firewall", "Firewall", "hardening", "ok", f"{svc} is active", "")
    return _check("firewall", "Firewall", "hardening", "bad",
                  "no active firewall detected (firewalld/ufw/nftables all inactive)",
                  "sudo systemctl enable --now firewalld")


_PRIVACY_TOOLS = [
    ("keepassxc", "KeePassXC (password vault)"),
    ("firejail", "Firejail (sandboxing)"),
    ("mat2", "mat2 (metadata stripping)"),
    ("torbrowser-launcher", "Tor Browser launcher"),
    ("wg", "WireGuard tools"),
]


def check_privacy_tools() -> list[dict]:
    out = []
    for bin_, label in _PRIVACY_TOOLS:
        present = common.which(bin_) is not None
        out.append(_check(f"tool-{bin_}", label, "tools", "ok" if present else "warn",
                          "installed" if present else "not installed",
                          "" if present else "sudo ~/security-setup/1-install.sh"))
    return out


def check_audit_tools() -> list[dict]:
    out = []

    if common.which("arch-audit"):
        r = common.run_tool(["arch-audit"], timeout=20)
        lines = [l.strip() for l in r.stdout.splitlines() if l.strip()]
        count = len(lines)
        sample = [l.split(" is affected")[0] for l in lines[:5]]
        if count == 0:
            status = "ok"
        elif count <= 5:
            status = "warn"
        else:
            status = "bad"
        detail = f"{count} installed package(s) flagged with known CVEs"
        if sample:
            detail += " — e.g. " + ", ".join(sample)
        out.append(_check("arch-audit", "arch-audit (CVE scan)", "audit", status, detail,
                          "arch-audit   # rerun anytime, no sudo needed"))
    else:
        out.append(_check("arch-audit", "arch-audit (CVE scan)", "audit", "unknown", "not installed",
                          "sudo ~/security-setup/1-install.sh"))

    lynis_report = Path("/var/log/lynis-report.dat")
    if lynis_report.is_file():
        try:
            idx = {}
            for line in lynis_report.read_text(errors="replace").splitlines():
                if "=" in line:
                    k, _, v = line.partition("=")
                    idx[k] = v
            score = idx.get("hardening_index", "")
            out.append(_check("lynis", "lynis hardening index", "audit",
                              "ok" if score else "unknown",
                              f"hardening_index={score or '?'} (from {lynis_report})",
                              "sudo lynis audit system   # refresh the report"))
        except OSError:
            out.append(_check("lynis", "lynis hardening index", "audit", "unknown",
                              "report present but unreadable by this user", "sudo lynis audit system"))
    else:
        out.append(_check("lynis", "lynis hardening index", "audit", "unknown",
                          "no report yet — lynis has not been run", "sudo lynis audit system"))

    return out


def check_rkhunter() -> dict:
    installed = common.which("rkhunter") is not None
    return _check("rkhunter", "rkhunter (rootkit hunter)", "audit",
                  "ok" if installed else "unknown",
                  "installed" if installed else "not installed",
                  "" if installed else "sudo pacman -S rkhunter && sudo rkhunter --propupd")


# --------------------------------------------------------------------------
# aggregate
# --------------------------------------------------------------------------
def run_all() -> dict:
    checks: list[dict] = []
    checks.append(check_sysctl())
    checks.append(check_auditd())
    checks.append(check_usbguard())
    checks.append(check_dns())
    checks.append(check_tor())
    checks.append(check_wireguard())
    checks.append(check_wifi_mac())
    checks.append(check_firewall())
    checks.extend(check_privacy_tools())
    checks.extend(check_audit_tools())
    checks.append(check_rkhunter())

    counts = {"ok": 0, "warn": 0, "bad": 0, "unknown": 0}
    for c in checks:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    total = len(checks)
    # headline score: ok counts full, warn counts half, bad/unknown count zero
    score = round(100 * (counts["ok"] + 0.5 * counts["warn"]) / total) if total else 0

    return {"checks": checks, "summary": {"total": total, "counts": counts, "score": score}}


# --------------------------------------------------------------------------
# (A2) hardening scripts control panel
# --------------------------------------------------------------------------
_SCRIPTS = [
    {"file": "1-install.sh", "run": "./1-install.sh",
     "desc": "Full upgrade + install the vetted opsec/pentest toolkit (official repos + ffuf from AUR).",
     "applied": lambda: all(common.which(b) for b in ("keepassxc", "firejail", "mat2", "usbguard"))},
    {"file": "2-harden.sh", "run": "sudo ./2-harden.sh",
     "desc": "Kernel/network sysctl hardening, auditd, Wi-Fi MAC randomization, USBGuard policy pre-gen.",
     "applied": lambda: Path("/etc/sysctl.d/99-cole-hardening.conf").is_file()
                and Path("/etc/NetworkManager/conf.d/00-wifi-mac-random.conf").is_file()},
    {"file": "3-secure-dns.sh", "run": "sudo ./3-secure-dns.sh",
     "desc": "Encrypted DNS-over-TLS via Quad9 (self-tests, auto-rolls-back if resolution breaks).",
     "applied": lambda: Path("/etc/systemd/resolved.conf.d/dns-over-tls.conf").is_file()},
    {"file": "4-dns-force-quad9.sh", "run": "sudo ./4-dns-force-quad9.sh",
     "desc": "Strips leftover DHCP/ISP DNS servers so every physical link is Quad9-only, no cleartext fallback.",
     "applied": lambda: Path("/etc/NetworkManager/conf.d/10-force-quad9-dns.conf").is_file()},
    {"file": "5-pentest-tools.sh", "run": "./5-pentest-tools.sh",
     "desc": "Curated desktop pentest toolkit (~80 tools: recon, web, exploitation, AD, cracking, network, RE).",
     "applied": lambda: all(common.which(b) for b in ("nmap", "sqlmap", "hydra"))},
    {"file": "5b-aur-tools.sh", "run": "./5b-aur-tools.sh",
     "desc": "Resilient one-at-a-time AUR installer for the toolkit stragglers yay's batch install abandons.",
     "applied": lambda: any(common.which(b) for b in ("nuclei", "amass", "feroxbuster"))},
    {"file": "5c-hard-tools.sh", "run": "./5c-hard-tools.sh",
     "desc": "The last two stragglers (BeEF, Autopsy) installed the way upstream actually ships them. Optional.",
     "applied": lambda: (Path.home() / "tools" / "beef").is_dir()},
    {"file": "6-blackarch-repo.sh", "run": "./6-blackarch-repo.sh",
     "desc": "Adds the BlackArch repo (signature-checked) so any of its ~2900 tools is one pacman -S away.",
     "applied": lambda: "blackarch" in _pacman_conf_text()},
]


def _pacman_conf_text() -> str:
    try:
        return Path("/etc/pacman.conf").read_text(errors="replace").lower()
    except OSError:
        return ""


def hardening_panel() -> dict:
    scripts = []
    for s in _SCRIPTS:
        path = SETUP_DIR / s["file"]
        try:
            applied = bool(s["applied"]())
        except Exception:
            applied = None  # can't determine — never let a probe crash the panel
        scripts.append({
            "file": s["file"],
            "exists": path.is_file(),
            "description": s["desc"],
            "command": s["run"],
            "applied": applied,
        })
    return {"setup_dir": str(SETUP_DIR), "scripts": scripts}
