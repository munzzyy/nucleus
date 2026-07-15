"""Tool inventory — the categorized registry of Cole's ~80-tool pentest kit.

Read-only. Every entry here is a name + a version-probe argv, nothing that
touches a target. Source of truth for what's in the kit is
~/security-setup/1-install.sh, 5-pentest-tools.sh, 5b-aur-tools.sh and
5c-hard-tools.sh — this list was built by reading those, then confirming
each binary's real invocation on this box, not guessed.
"""

from __future__ import annotations

import concurrent.futures
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from shared import common
from consoles.redcell import runners, builder, wordlists

CATEGORIES: dict[str, str] = {
    "recon": "Recon / OSINT",
    "web": "Web Application",
    "exploitation": "Exploitation",
    "ad": "AD / Internal",
    "cracking": "Cracking / Wordlists",
    "network": "Network / MITM",
    "wireless": "Wireless",
    "forensics": "Forensics",
    "re": "Reverse Engineering / Binary",
    "fuzzing": "Fuzzing",
    "vulnscan": "Vulnerability Scanning",
}


@dataclass
class ToolSpec:
    key: str                       # stable id
    name: str                      # display name
    category: str                  # key into CATEGORIES
    purpose: str                   # one-liner
    install: str                   # human install command/hint
    source: str                    # official | aur | go | manual
    kind: str = "bin"              # bin | pymodule | dataset | manual
    bin: Optional[str] = None      # binary to `which()` / exec (kind=bin)
    probe: Optional[list] = None   # version-probe argv (kind=bin)
    pymodule: Optional[str] = None  # module name (kind=pymodule)
    dataset_path: Optional[str] = None  # path to check exists (kind=dataset)
    manual_check: Optional[Callable[[], tuple]] = None  # () -> (installed, path)
    note: str = ""


# --------------------------------------------------------------------------
# Manual-install checks (beef / autopsy — no pacman/AUR package, installed
# by ~/security-setup/5c-hard-tools.sh per its own comments).
# --------------------------------------------------------------------------
def _check_beef():
    p = Path.home() / "tools" / "beef" / "beef"
    return (p.is_file(), str(p) if p.is_file() else None)


def _check_autopsy():
    base = Path.home() / "tools"
    if not base.is_dir():
        return (False, None)
    matches = sorted(base.glob("autopsy*/bin/autopsy"))
    return (bool(matches), str(matches[0]) if matches else None)


REGISTRY: list[ToolSpec] = [
    # ---- recon / OSINT ----
    ToolSpec("nmap", "nmap", "recon", "Network/port/service scanner", "sudo pacman -S nmap", "official",
             bin="nmap", probe=["nmap", "--version"]),
    ToolSpec("masscan", "masscan", "recon", "Internet-scale async port scanner", "sudo pacman -S masscan", "official",
             bin="masscan", probe=["masscan", "--version"]),
    ToolSpec("theharvester", "theHarvester", "recon", "Email/subdomain/employee OSINT harvester",
             "yay -S theharvester-git (or pipx install theHarvester)", "aur",
             bin="theHarvester", probe=["theHarvester", "--version"]),
    ToolSpec("amass", "amass", "recon", "Passive/active subdomain enum & attack-surface mapping",
             "yay -S amass", "aur", bin="amass", probe=["amass", "-version"]),
    ToolSpec("subfinder", "subfinder", "recon", "Fast passive subdomain enumeration (ProjectDiscovery)",
             "yay -S subfinder", "aur", bin="subfinder", probe=["subfinder", "-version"]),
    ToolSpec("whatweb", "whatweb", "recon", "Web technology / CMS fingerprinting", "yay -S whatweb", "aur",
             bin="whatweb", probe=["whatweb", "--version"]),
    ToolSpec("httpx", "httpx", "recon", "Fast HTTP probing toolkit (ProjectDiscovery)",
             "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", "go",
             bin="httpx", probe=["httpx", "-version"]),
    ToolSpec("dnsenum", "dnsenum2", "recon", "DNS enumeration / zone-transfer / subdomain brute",
             "yay -S dnsenum2", "aur", bin="dnsenum", probe=["dnsenum", "--version"]),
    ToolSpec("gau", "gau", "recon", "Pulls known URLs for a domain from web archives (getallurls)",
             "yay -S gau", "aur", bin="gau", probe=["gau", "--version"]),
    ToolSpec("dig", "dig", "recon", "DNS record lookup", "sudo pacman -S bind", "official",
             bin="dig", probe=["dig", "-v"]),
    ToolSpec("host", "host", "recon", "Simple DNS lookup", "sudo pacman -S bind", "official",
             bin="host", probe=["host"]),
    ToolSpec("whois", "whois", "recon", "WHOIS domain/IP registration lookup", "sudo pacman -S whois", "official",
             bin="whois", probe=["whois", "--version"]),

    # ---- web application ----
    ToolSpec("nikto", "nikto", "web", "Web server vuln / misconfig scanner", "sudo pacman -S nikto", "official",
             bin="nikto", probe=["nikto", "-Version"]),
    ToolSpec("zaproxy", "OWASP ZAP", "web", "Web app intercepting proxy + active/passive scanner",
             "sudo pacman -S zaproxy", "official", bin="zaproxy", probe=["zaproxy", "-version"]),
    ToolSpec("wpscan", "wpscan", "web", "WordPress core/plugin/theme vulnerability scanner",
             "sudo pacman -S wpscan", "official", bin="wpscan", probe=["wpscan", "--version"]),
    ToolSpec("sslscan", "sslscan", "web", "TLS/SSL cipher & config scanner", "sudo pacman -S sslscan", "official",
             bin="sslscan", probe=["sslscan", "--version"]),
    ToolSpec("testssl", "testssl.sh", "web", "Deep read-only TLS/SSL posture testing",
             "sudo pacman -S testssl.sh", "official", bin="testssl", probe=["testssl", "--version"]),
    ToolSpec("gobuster", "gobuster", "web", "Directory / DNS / vhost brute-forcer", "sudo pacman -S gobuster",
             "official", bin="gobuster", probe=["gobuster", "version"]),
    ToolSpec("feroxbuster", "feroxbuster", "web", "Fast recursive content discovery", "yay -S feroxbuster",
             "aur", bin="feroxbuster", probe=["feroxbuster", "--version"]),
    ToolSpec("wfuzz", "wfuzz", "web", "Web application fuzzer (params/dirs/forms)", "yay -S wfuzz", "aur",
             bin="wfuzz", probe=["wfuzz", "--version"]),
    ToolSpec("ffuf", "ffuf", "web", "Fast web fuzzer (Go)", "yay -S ffuf", "aur",
             bin="ffuf", probe=["ffuf", "-V"]),
    ToolSpec("commix", "commix", "web", "Automated command-injection exploitation tool", "yay -S commix", "aur",
             bin="commix", probe=["commix", "--version"]),
    ToolSpec("burpsuite", "Burp Suite", "web", "Web app proxy/scanner (PortSwigger)", "yay -S burpsuite", "aur",
             bin="burpsuite", probe=["burpsuite", "--version"]),

    # ---- exploitation ----
    ToolSpec("metasploit", "Metasploit", "exploitation", "Full exploitation framework", "sudo pacman -S metasploit",
             "official", bin="msfconsole", probe=["msfconsole", "--version"]),
    ToolSpec("exploitdb", "searchsploit", "exploitation", "Offline exploit-db search", "sudo pacman -S exploitdb",
             "official", bin="searchsploit", probe=["searchsploit", "-h"]),
    ToolSpec("setoolkit", "social-engineer-toolkit", "exploitation", "Social-engineering attack toolkit",
             "yay -S social-engineer-toolkit", "aur", bin="setoolkit", probe=["setoolkit", "--version"]),
    ToolSpec("beef", "BeEF", "exploitation", "Browser exploitation framework (XSS hook C2)",
             "~/security-setup/5c-hard-tools.sh  (clones + builds ~/tools/beef)", "manual",
             kind="manual", manual_check=_check_beef),
    ToolSpec("routersploit", "RouterSploit", "exploitation", "Router / embedded / IoT exploitation framework",
             "yay -S routersploit-git", "aur", bin="routersploit", probe=["routersploit", "--version"]),

    # ---- AD / internal ----
    ToolSpec("impacket", "impacket (secretsdump.py)", "ad",
             "Python AD/SMB protocol toolkit — 100+ scripts (secretsdump, psexec, GetUserSPNs...)",
             "sudo pacman -S impacket", "official", bin="secretsdump.py", probe=["secretsdump.py", "-h"],
             note="presence checked via secretsdump.py; the package ships many more /usr/bin/*.py scripts"),
    ToolSpec("netexec", "netexec (nxc)", "ad", "AD/SMB/WinRM pentesting swiss-army-knife (CrackMapExec successor)",
             "yay -S netexec", "aur", bin="nxc", probe=["nxc", "--version"]),
    ToolSpec("responder", "Responder", "ad", "LLMNR/NBT-NS/mDNS poisoner & credential harvester",
             "yay -S responder", "aur", bin="responder", probe=["responder", "--version"]),
    ToolSpec("enum4linux", "enum4linux", "ad", "SMB/Samba enumeration", "yay -S enum4linux", "aur",
             bin="enum4linux", probe=["enum4linux", "-h"]),
    ToolSpec("smbmap", "smbmap", "ad", "SMB share enumeration", "yay -S smbmap", "aur",
             bin="smbmap", probe=["smbmap", "--version"]),
    ToolSpec("evil-winrm", "evil-winrm", "ad", "WinRM shell for AD pentesting", "yay -S ruby-evil-winrm", "aur",
             bin="evil-winrm", probe=["evil-winrm", "--version"]),
    ToolSpec("chisel", "chisel", "ad", "TCP/UDP tunneling & pivoting", "yay -S chisel", "aur",
             bin="chisel", probe=["chisel", "--version"]),

    # ---- cracking / wordlists ----
    ToolSpec("john", "John the Ripper", "cracking", "Offline password hash cracker", "sudo pacman -S john",
             "official", bin="john", probe=["john"]),
    ToolSpec("hashcat", "hashcat", "cracking", "GPU-accelerated hash cracker", "sudo pacman -S hashcat", "official",
             bin="hashcat", probe=["hashcat", "--version"]),
    ToolSpec("hydra", "hydra", "cracking", "Online login brute-forcer (many protocols)", "sudo pacman -S hydra",
             "official", bin="hydra", probe=["hydra", "-h"]),
    ToolSpec("medusa", "medusa", "cracking", "Parallel online login brute-forcer", "sudo pacman -S medusa",
             "official", bin="medusa", probe=["medusa", "-h"]),
    ToolSpec("crunch", "crunch", "cracking", "Wordlist generator by pattern", "yay -S crunch", "aur",
             bin="crunch", probe=["crunch"]),
    ToolSpec("cewl", "CeWL", "cracking", "Custom wordlist generator from website content", "yay -S cewl-git",
             "aur", bin="cewl", probe=["cewl", "--version"]),
    ToolSpec("hashid", "hashid", "cracking", "Identify likely hash types", "yay -S hashid", "aur",
             bin="hashid", probe=["hashid", "--version"]),
    ToolSpec("seclists", "SecLists", "cracking", "Curated wordlist collection (dataset, not a binary)",
             "yay -S seclists", "aur", kind="dataset", dataset_path="/usr/share/seclists"),
    ToolSpec("wordlists", "wordlists (rockyou etc.)", "cracking", "Common password wordlist bundle (dataset)",
             "yay -S wordlists", "aur", kind="dataset", dataset_path="/usr/share/wordlists"),

    # ---- network / MITM ----
    ToolSpec("ettercap", "ettercap", "network", "MITM suite — ARP spoofing, sniffing", "yay -S ettercap", "aur",
             bin="ettercap", probe=["ettercap", "--version"]),
    ToolSpec("bettercap", "bettercap", "network", "Modern MITM / recon swiss-army-knife", "yay -S bettercap",
             "aur", bin="bettercap", probe=["bettercap", "-version"]),
    ToolSpec("mitmproxy", "mitmproxy", "network", "Interactive HTTPS intercepting proxy", "yay -S mitmproxy",
             "aur", bin="mitmproxy", probe=["mitmproxy", "--version"]),
    ToolSpec("tcpdump", "tcpdump", "network", "Packet capture from the CLI", "sudo pacman -S tcpdump", "official",
             bin="tcpdump", probe=["tcpdump", "--version"]),
    ToolSpec("wireshark", "Wireshark", "network", "GUI packet analyzer", "sudo pacman -S wireshark-qt", "official",
             bin="wireshark", probe=["wireshark", "--version"]),
    ToolSpec("tshark", "tshark", "network", "CLI packet analyzer (Wireshark engine)", "yay -S wireshark-cli",
             "aur", bin="tshark", probe=["tshark", "--version"]),
    ToolSpec("netcat", "netcat (OpenBSD)", "network", "Classic read/write TCP/UDP socket tool",
             "yay -S openbsd-netcat", "aur", bin="nc", probe=["nc", "-h"]),
    ToolSpec("socat", "socat", "network", "Bidirectional relay / tunnel utility (netcat++)", "yay -S socat",
             "aur", bin="socat", probe=["socat", "-V"]),
    ToolSpec("proxychains", "proxychains-ng", "network", "Force any TCP app through a proxy chain",
             "yay -S proxychains-ng", "aur", bin="proxychains4", probe=["proxychains4"]),
    ToolSpec("macchanger", "macchanger", "network", "MAC address spoofing", "yay -S macchanger", "aur",
             bin="macchanger", probe=["macchanger", "--version"]),
    ToolSpec("arp-scan", "arp-scan", "network", "ARP-based host discovery on the local network",
             "yay -S arp-scan", "aur", bin="arp-scan", probe=["arp-scan", "--version"]),

    # ---- wireless ----
    ToolSpec("aircrack-ng", "aircrack-ng", "wireless", "WEP/WPA cracking suite", "yay -S aircrack-ng", "aur",
             bin="aircrack-ng", probe=["aircrack-ng"]),
    ToolSpec("wifite", "wifite", "wireless", "Automated wireless auditing wrapper", "yay -S wifite", "aur",
             bin="wifite", probe=["wifite", "--version"]),
    ToolSpec("hcxtools", "hcxtools", "wireless", "WPA handshake/PMKID conversion for hashcat", "yay -S hcxtools",
             "aur", bin="hcxpcapngtool", probe=["hcxpcapngtool", "--version"]),
    ToolSpec("hcxdumptool", "hcxdumptool", "wireless", "WiFi frame capture for hcxtools", "yay -S hcxdumptool",
             "aur", bin="hcxdumptool", probe=["hcxdumptool", "--version"]),
    ToolSpec("reaver", "reaver", "wireless", "WPS PIN brute-force attack", "yay -S reaver", "aur",
             bin="reaver", probe=["reaver", "--version"]),
    ToolSpec("pixiewps", "pixiewps", "wireless", "WPS offline pixie-dust attack", "yay -S pixiewps", "aur",
             bin="pixiewps", probe=["pixiewps", "--version"]),
    ToolSpec("cowpatty", "cowpatty", "wireless", "WPA-PSK dictionary attack tool", "yay -S cowpatty", "aur",
             bin="cowpatty", probe=["cowpatty"]),
    ToolSpec("kismet", "kismet", "wireless", "Wireless network detector / sniffer / IDS", "yay -S kismet", "aur",
             bin="kismet", probe=["kismet", "--version"]),

    # ---- forensics ----
    ToolSpec("sleuthkit", "Sleuth Kit (fls)", "forensics", "Disk / filesystem forensic toolkit",
             "yay -S sleuthkit", "aur", bin="fls", probe=["fls", "-V"]),
    ToolSpec("foremost", "foremost", "forensics", "File carving from disk images", "yay -S foremost", "aur",
             bin="foremost", probe=["foremost", "-V"]),
    ToolSpec("binwalk", "binwalk", "forensics", "Firmware / binary analysis & extraction", "yay -S binwalk",
             "aur", bin="binwalk", probe=["binwalk", "--version"]),
    ToolSpec("volatility3", "volatility3 (vol)", "forensics", "Memory forensics framework", "yay -S volatility3",
             "aur", bin="vol", probe=["vol", "--version"]),
    ToolSpec("yara", "YARA", "forensics", "Pattern-matching malware / IOC scanner", "yay -S yara", "aur",
             bin="yara", probe=["yara", "--version"]),
    ToolSpec("exiftool", "exiftool", "forensics", "File metadata extraction / analysis",
             "yay -S perl-image-exiftool", "aur", bin="exiftool", probe=["exiftool", "-ver"]),
    ToolSpec("autopsy", "Autopsy", "forensics", "GUI case-management forensics front-end for Sleuth Kit",
             "~/security-setup/5c-hard-tools.sh + manual zip (needs jre17, see script notes)", "manual",
             kind="manual", manual_check=_check_autopsy),

    # ---- reverse engineering / binary ----
    ToolSpec("radare2", "radare2", "re", "Reverse engineering framework (disasm/debug)", "yay -S radare2", "aur",
             bin="radare2", probe=["radare2", "-v"]),
    ToolSpec("cutter", "Cutter", "re", "GUI front-end for radare2", "sudo pacman -S cutter", "official",
             bin="cutter", probe=["cutter", "--version"]),
    ToolSpec("ghidra", "Ghidra", "re", "NSA's SRE suite (disassembler/decompiler)", "sudo pacman -S ghidra",
             "official", bin="ghidra"),  # GUI launcher — no probe, presence-only (avoid triggering a GUI launch)
    ToolSpec("pwndbg", "pwndbg", "re", "GDB plugin for exploit development", "sudo pacman -S pwndbg", "official",
             bin="pwndbg", probe=["pwndbg", "--version"]),
    ToolSpec("ropgadget", "ROPgadget", "re", "ROP gadget finder", "sudo pacman -S ropgadget", "official",
             bin="ROPgadget", probe=["ROPgadget", "--version"]),
    ToolSpec("checksec", "checksec", "re", "Binary security mitigation checker (RELRO/PIE/canary...)",
             "sudo pacman -S checksec", "official", bin="checksec", probe=["checksec", "--version"]),
    ToolSpec("angr", "angr", "re", "Python binary analysis / symbolic execution framework",
             "yay -S python-angr  (or ~/venvs/angr per 5c-hard-tools.sh)", "aur", kind="pymodule", pymodule="angr"),

    # ---- fuzzing ----
    ToolSpec("aflplusplus", "AFL++ (afl-fuzz)", "fuzzing", "Coverage-guided binary fuzzer", "sudo pacman -S afl++",
             "official", bin="afl-fuzz", probe=["afl-fuzz", "--help"]),
    ToolSpec("honggfuzz", "honggfuzz", "fuzzing", "Feedback-driven mutation fuzzer", "yay -S honggfuzz-git", "aur",
             bin="honggfuzz", probe=["honggfuzz", "--help"]),

    # ---- vulnerability scanning ----
    ToolSpec("nuclei", "nuclei", "vulnscan", "Template-based vulnerability scanner (ProjectDiscovery)",
             "yay -S nuclei", "aur", bin="nuclei", probe=["nuclei", "-version"]),
    ToolSpec("trivy", "trivy", "vulnscan", "Container / IaC / dependency vulnerability scanner",
             "sudo pacman -S trivy", "official", bin="trivy", probe=["trivy", "--version"]),
]


# --------------------------------------------------------------------------
# Probing
# --------------------------------------------------------------------------
def _probe_pymodule(modname: str) -> tuple:
    venv_py = Path.home() / "venvs" / modname / "bin" / "python"
    candidates = ([str(venv_py)] if venv_py.is_file() else []) + ["python3"]
    for py in candidates:
        r = common.run_tool([py, "-c", f"import {modname}; print(getattr({modname}, '__version__', 'unknown'))"],
                             timeout=10.0)
        if r.returncode == 0:
            return True, py, r.stdout.strip()
    return False, None, ""


def _probe_one(spec: ToolSpec) -> dict:
    if spec.kind == "dataset":
        p = Path(spec.dataset_path)
        installed = p.exists()
        return {"installed": installed, "path": str(p) if installed else None, "version": ""}
    if spec.kind == "manual":
        installed, path = spec.manual_check()
        return {"installed": installed, "path": path, "version": ""}
    if spec.kind == "pymodule":
        installed, path, version = _probe_pymodule(spec.pymodule)
        return {"installed": installed, "path": path, "version": version}
    # default: bin
    path = common.which(spec.bin)
    installed = path is not None
    version = ""
    if installed and spec.probe:
        version = common.tool_version(spec.probe, timeout=4.0)
    return {"installed": installed, "path": path, "version": version}


_CACHE: dict = {"ts": 0.0, "data": None}
_CACHE_TTL = 60.0


def build_inventory(force_refresh: bool = False) -> dict:
    now = time.monotonic()
    if not force_refresh and _CACHE["data"] is not None and (now - _CACHE["ts"]) < _CACHE_TTL:
        return _CACHE["data"]

    results: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        futures = {pool.submit(_probe_one, spec): spec.key for spec in REGISTRY}
        for fut in concurrent.futures.as_completed(futures):
            key = futures[fut]
            try:
                results[key] = fut.result()
            except Exception as e:  # a single tool's probe must never sink the scan
                results[key] = {"installed": False, "path": None, "version": "", "error": str(e)}

    tools = []
    counts: dict[str, dict] = {c: {"installed": 0, "total": 0} for c in CATEGORIES}
    installed_total = 0
    for spec in REGISTRY:
        r = results.get(spec.key, {"installed": False, "path": None, "version": ""})
        tools.append({
            "key": spec.key, "name": spec.name, "category": spec.category,
            "category_label": CATEGORIES.get(spec.category, spec.category),
            "purpose": spec.purpose, "install": spec.install, "source": spec.source,
            "note": spec.note,
            "installed": r["installed"], "path": r.get("path"), "version": r.get("version", ""),
        })
        counts[spec.category]["total"] += 1
        if r["installed"]:
            counts[spec.category]["installed"] += 1
            installed_total += 1

    try:
        local_tools = runners.local_tools_status()
    except Exception:
        local_tools = []

    safe_runners = []
    for key, spec in runners.SAFE_RUNNERS.items():
        options = [{
            "name": name, "label": opt.label, "default": opt.default,
            "choices": sorted(opt.choices),
        } for name, opt in spec.options.items()]
        safe_runners.append({
            "key": key, "desc": spec.desc, "kind": spec.kind, "bin": spec.bin,
            "installed": common.which(spec.bin) is not None, "install": spec.install,
            "timeout": spec.timeout, "options": options,
            "needs_wordlist": spec.needs_wordlist,
            "known_broken": spec.known_broken,
        })

    build_tools = [{"key": k, "desc": v["desc"], "fields": v["fields"], "note": v.get("note", "")}
                   for k, v in builder.BUILDERS.items()]

    try:
        wordlists_common = wordlists.common_list()
        wordlists_total = wordlists.registry_count()
    except Exception:
        wordlists_common, wordlists_total = [], 0

    data = {
        "tools": tools,
        "categories": [{"key": k, "label": v, **counts[k]} for k, v in CATEGORIES.items()],
        "summary": {"total": len(REGISTRY), "installed": installed_total},
        "local_tools": local_tools,
        "safe_runners": safe_runners,
        "build_tools": build_tools,
        "wordlists_common": wordlists_common,
        "wordlists_total": wordlists_total,
        "generated_at": time.time(),
    }
    _CACHE["ts"] = now
    _CACHE["data"] = data
    return data


def handle_inventory(req) -> "common.Response":
    # GET never forces a refresh — GET requests carry no Origin/Referer check
    # anywhere in this app (only POST does, see shared/common.py), so a
    # ?refresh=1 side effect here would let a blind cross-origin <img>/
    # fetch(no-cors) from any page Cole has open repeat-trigger ~80 concurrent
    # subprocess --version probes for free. Use POST /api/inventory/refresh
    # (which DOES get the Origin check, like every other mutating endpoint)
    # to force one; this endpoint stays cached-and-read-only, always.
    return common.Response.json(build_inventory(force_refresh=False))


def handle_inventory_refresh(req) -> "common.Response":
    return common.Response.json(build_inventory(force_refresh=True))
