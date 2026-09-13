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
import threading
import time
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


def check_egress_control() -> dict:
    """Per-app OUTBOUND control. check_firewall covers inbound; nothing there
    stops a running app from reaching out. opensnitch is the standard per-app
    egress prompt/deny. Without it (or an explicit per-app nftables egress
    rule), every app on the box — browser, RE tools, anything — can phone out
    unnoticed. This is the systemic gap behind 'is tool X talking to someone'."""
    active, _ = _svc_active("opensnitchd")
    if active:
        return _check("egress-control", "Per-app egress control", "hardening", "ok",
                      "opensnitch active — outbound connections are gated per application", "")
    return _check("egress-control", "Per-app egress control", "hardening", "warn",
                  "no per-app egress control — the firewall only filters inbound, so any app "
                  "can reach out unnoticed. This, not any one tool, is the real phone-home gap.",
                  "sudo pacman -S opensnitch && sudo systemctl enable --now opensnitchd")


_FIREJAIL_PROFILE_DIR = HOME / ".config" / "firejail"


def check_ghidra_containment() -> "dict | None":
    """Ghidra is NSA-authored but open-source with no default phone-home
    ([[ghidra-opsec]]). Full opsec still means it should never be *able* to
    reach out: this surfaces whether it's egress-contained — via a firejail
    net-none profile or system-wide opensnitch — instead of running wide open.
    Only shown when Ghidra is actually installed."""
    if not common.which("ghidra"):
        return None
    profile = _FIREJAIL_PROFILE_DIR / "ghidra.profile"
    opensnitch_active, _ = _svc_active("opensnitchd")
    if profile.is_file() or opensnitch_active:
        how = "firejail net-none profile" if profile.is_file() else "opensnitch (system-wide)"
        return _check("ghidra-egress", "Ghidra egress containment", "opsec", "ok",
                      f"Ghidra installed and egress-contained ({how})", "")
    return _check("ghidra-egress", "Ghidra egress containment", "opsec", "warn",
                  "Ghidra installed with no egress containment. It's open-source with no default "
                  "phone-home, but for full opsec run it with no network path at all.",
                  "firejail --net=none ghidra   # profile lives at ~/.config/firejail/ghidra.profile")


_PRIVACY_TOOLS = [
    ("keepassxc", "KeePassXC (password vault)"),
    ("firejail", "Firejail (sandboxing)"),
    ("opensnitch", "OpenSnitch (per-app egress firewall)"),
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


_arch_audit_cache: dict = {"data": None, "ts": 0.0}
_arch_audit_lock = threading.Lock()
ARCH_AUDIT_TTL = 900.0  # 15 min — the scan itself takes ~20s of subprocess time,
                         # no reason to pay that on every posture refresh


def _arch_audit_check() -> dict:
    """Cached separately (and much longer) than the rest of run_all(): this is
    the one probe expensive enough to matter — everything else here is a sub-
    100ms systemctl/sysctl call, arch-audit alone is ~20s."""
    now = time.monotonic()
    with _arch_audit_lock:
        cached = _arch_audit_cache["data"]
        if cached and (now - _arch_audit_cache["ts"] < ARCH_AUDIT_TTL):
            return cached

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
        result = _check("arch-audit", "arch-audit (CVE scan)", "audit", status, detail,
                        "arch-audit   # rerun anytime, no sudo needed")
    else:
        result = _check("arch-audit", "arch-audit (CVE scan)", "audit", "unknown", "not installed",
                        "sudo ~/security-setup/1-install.sh")

    with _arch_audit_lock:
        _arch_audit_cache.update(data=result, ts=now)
    return result


def check_audit_tools() -> list[dict]:
    out = [_arch_audit_check()]

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
def _ipv6_global() -> list[str]:
    """Global-scope IPv6 addresses on non-VPN interfaces (a classic leak path)."""
    r = common.run_tool(["ip", "-6", "-o", "addr", "show", "scope", "global"], timeout=4)
    out = []
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 4:
            iface, addr = parts[1], parts[3].split("/")[0]
            if not iface.startswith(("wg", "tun", "mullvad", "proton", "nordlynx", "lo")):
                out.append(f"{addr} on {iface}")
    return out


def anonymity_panel() -> dict:
    """The OpSec page: is my real IP/location exposed right now, and what should
    I have on. Read-only; the network verdict comes from shared opsec_status.
    This is a dedicated page the user opened, so it opts in to the exit-IP
    oracle check (which reveals the IP to the check services)."""
    o = common.opsec_status(oracles=True)
    checks = []

    # 1) the headline: VPN / exit exposure
    if o["exposed"]:
        checks.append(_check("vpn", "VPN / anonymity", "anonymity", "bad",
            f"EXPOSED — {o['reason']}. Public IP {o.get('public_ip') or '?'}"
            + (f" ({', '.join(x for x in (o.get('org'), o.get('city'), o.get('country')) if x)})" if o.get("org") else ""),
            "Turn on Mullvad (or another VPN) before any scan. Install: yay -S mullvad-vpn"))
    else:
        checks.append(_check("vpn", "VPN / anonymity", "anonymity", "ok",
            f"Protected — {o['reason']}. Exit IP {o.get('public_ip') or '?'}"
            + (f" ({', '.join(x for x in (o.get('org'), o.get('country')) if x)})" if o.get("org") else ""),
            ""))

    # 2) Mullvad installed?
    mv = common.which("mullvad") or common.which("mullvad-vpn")
    if mv:
        r = common.run_tool(["mullvad", "status"], timeout=4)
        detail = (r.stdout or r.stderr or "").strip().splitlines()[0] if (r.stdout or r.stderr) else "installed"
        checks.append(_check("mullvad", "Mullvad app", "anonymity", "ok" if o["mullvad"] else "warn",
            detail, "" if o["mullvad"] else "mullvad connect"))
    else:
        checks.append(_check("mullvad", "Mullvad app", "anonymity", "warn",
            "not installed", "yay -S mullvad-vpn   (then: mullvad account login, mullvad connect)"))

    # 3) kill switch — traffic must not leak if the VPN drops
    if mv:
        r = common.run_tool(["mullvad", "lockdown-mode", "get"], timeout=4)
        on = "on" in (r.stdout or "").lower()
        checks.append(_check("killswitch", "Kill switch", "anonymity", "ok" if on else "warn",
            "Mullvad lockdown mode " + ("on" if on else "off"),
            "" if on else "mullvad lockdown-mode set on"))
    else:
        checks.append(_check("killswitch", "Kill switch", "anonymity", "warn",
            "no VPN kill switch detected — traffic would leak if the tunnel drops",
            "Use Mullvad's lockdown mode, or a firewall rule that blocks non-VPN egress."))

    # 4) encrypted DNS (reuse the hardening check)
    dns = check_dns()
    dns["category"] = "anonymity"
    checks.append(dns)

    # 5) IPv6 leak
    v6 = _ipv6_global()
    if v6 and o["exposed"]:
        checks.append(_check("ipv6", "IPv6 leak", "anonymity", "bad",
            "Global IPv6 active with no VPN: " + "; ".join(v6[:3])
            + " — IPv6 traffic can bypass an IPv4-only VPN.",
            "Ensure your VPN tunnels IPv6, or disable it: sysctl -w net.ipv6.conf.all.disable_ipv6=1"))
    elif v6:
        checks.append(_check("ipv6", "IPv6", "anonymity", "warn",
            "Global IPv6 present (" + v6[0] + ") — confirm your VPN tunnels it.",
            "Verify with the VPN up: curl -6 https://am.i.mullvad.net/json"))
    else:
        checks.append(_check("ipv6", "IPv6", "anonymity", "ok", "no global IPv6 on physical links", ""))

    # 6) Tor, 7) MAC randomization (reuse)
    for c in (check_tor(), check_wifi_mac()):
        c["category"] = "anonymity"
        checks.append(c)

    recs = [
        "Install + connect Mullvad: yay -S mullvad-vpn, then `mullvad account login` and `mullvad connect`.",
        "Turn on Mullvad's kill switch (lockdown mode) so nothing leaks if the tunnel drops: `mullvad lockdown-mode set on`.",
        "Keep encrypted DNS (Quad9 DoT) on — run ~/security-setup/3-secure-dns.sh if it isn't.",
        "Make sure IPv6 is tunneled by the VPN, or disable it, so it can't bypass the tunnel.",
        "For the most sensitive work, use Tor Browser on top of the VPN.",
        "Keep Wi-Fi MAC randomization on, and strip metadata from any file you share (mat2).",
    ]
    n_bad = sum(1 for c in checks if c["status"] == "bad")
    n_warn = sum(1 for c in checks if c["status"] == "warn")
    return {
        "verdict": {
            "exposed": o["exposed"], "reason": o["reason"],
            "public_ip": o.get("public_ip", ""), "org": o.get("org", ""),
            "city": o.get("city", ""), "country": o.get("country", ""),
            "mullvad": o["mullvad"],
        },
        "checks": checks,
        "recommendations": recs,
        "summary": {"ok": sum(1 for c in checks if c["status"] == "ok"),
                    "warn": n_warn, "bad": n_bad, "total": len(checks)},
    }


def _run_all_uncached() -> dict:
    checks: list[dict] = []
    checks.append(check_sysctl())
    checks.append(check_auditd())
    checks.append(check_usbguard())
    checks.append(check_dns())
    checks.append(check_tor())
    checks.append(check_wireguard())
    checks.append(check_wifi_mac())
    checks.append(check_firewall())
    checks.append(check_egress_control())
    ghidra_check = check_ghidra_containment()
    if ghidra_check is not None:
        checks.append(ghidra_check)
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


_posture_cache: dict = {"data": None, "ts": 0.0}
_posture_lock = threading.Lock()
POSTURE_TTL = 30.0  # seconds


def run_all(force: bool = False) -> dict:
    """Cached wrapper around the real probe sweep.

    Every check here is a subprocess (systemctl/sysctl/wg/resolvectl/etc, ~15
    of them) or a file read, and the hub's dashboard polls /api/overview -> our
    /api/posture every 8s. Uncached that's a subprocess storm on a timer, and
    the hub's own 3.5s budget for the call was shorter than a cold arch-audit
    run, so the posture stat just showed "—" forever. A 30s TTL keeps the
    number fresh to a human glance while cutting the subprocess count by ~4x;
    arch-audit itself is cached separately and far longer (see
    _arch_audit_check). `force=True` bypasses the cache for a manual refresh.
    """
    now = time.monotonic()
    with _posture_lock:
        cached = _posture_cache["data"]
        if not force and cached and (now - _posture_cache["ts"] < POSTURE_TTL):
            return cached
    result = _run_all_uncached()
    with _posture_lock:
        _posture_cache.update(data=result, ts=now)
    return result


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
    {"file": "7-osint-tools.sh", "run": "./7-osint-tools.sh",
     "desc": "Curated OSINT toolkit via pipx/go (maigret, holehe, recon-ng, spiderfoot, dnsrecon, shodan...). Pairs with the Recon console.",
     "applied": lambda: any(common.which(b) for b in ("maigret", "holehe", "recon-ng", "spiderfoot"))},
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


# --------------------------------------------------------------------------
# (A3) fix-everything checklist — every failing/warn check's fix_hint, ordered
# --------------------------------------------------------------------------
_PLAN_ORDER = {"bad": 0, "warn": 1}


def hardening_plan() -> dict:
    """One ordered, copy-pasteable checklist built straight from run_all()'s
    per-check fix_hint — worst-first (bad before warn), skipping checks that
    have nothing to run (ok/unknown, or a warn/bad with no fix_hint at all,
    e.g. Tor's 'off by design'). Strictly read-only: this returns the commands
    a human would run, it never executes anything itself — bastion never
    changes system state."""
    data = run_all()
    candidates = [c for c in data["checks"]
                  if c["status"] in _PLAN_ORDER and c.get("fix_hint")]
    candidates.sort(key=lambda c: _PLAN_ORDER[c["status"]])
    steps = [
        {"label": c["label"], "command": c["fix_hint"], "why": c["detail"]}
        for c in candidates
    ]
    return {"steps": steps}
