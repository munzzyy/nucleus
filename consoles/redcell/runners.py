"""The exec layer. Everything in this file that can run a subprocess runs it
through common.run_tool (argv list, shell=False, time-bounded) and nothing
else. There is no os.system, no shell=True, no string-built command anywhere
below. Every gate here is server-side; the UI has no say in whether a run
actually happens.

Order every run passes through, and every one of these can refuse the run:
  1. tool must be a key in SAFE_RUNNERS (a fixed dict — never derived from
     request data)
  2. authorized:true must be present in the POST body
  3. target must pass strict validation for the runner's target kind
  4. target must be in scope (public) unless lab:true is set
  5. every declared option must resolve through a fixed server-side choice
     dict — an unrecognized option key is refused, never passed through
  6. a runner that needs a wordlist gets one ONLY via a registry id
     (see wordlists.py) — never a raw path
  7. the binary must actually be installed
  8. immediately before spawn, the target's public-ness is re-resolved and
     re-checked a SECOND time (see "DNS-rebind, honestly" below) — either
     pinned to the address that check validated, or re-verified in place

Only after all eight does a subprocess get spawned. The user-supplied target
is inserted as exactly one argv element by the runner's `build` callback.
Every other argv element is either a fixed literal baked into this file, or
a value looked up from a server-side dict keyed by a validated enum/id — the
client's raw enum key or wordlist id is NEVER itself placed in argv, only
the looked-up fixed value is.

DNS-rebind, honestly. Step 4's scope_check and step 8's re-check both call
common.resolve_public_ips()/common.host_is_public() — real DNS lookups. Left
alone, that's TWO independent resolutions of the same hostname with nothing
forcing them to agree: an attacker who controls authoritative DNS for a
domain Cole is scanning (TTL=0, alternating A records — routine DNS-rebinding,
not a theoretical race) can answer "public" to step 4 and "127.0.0.1" to
whatever the external tool resolves moments later, turning any runner into a
probe of Cole's own loopback/LAN. Two mitigations, sized to what's actually
achievable in a no-root stdlib app:
  - nmap / sslscan / testssl / enum4linux connect straight to an address and
    don't need the hostname for anything else the tool does, so the address
    step 8 validates is PINNED directly into argv — the tool never resolves
    again, so there's no second lookup left for an attacker to answer
    differently. This closes the gap completely for these four. (dig/host/
    whois are host-kind too but deliberately NOT pinned — they never connect
    to the resolved address, they query a DNS resolver / WHOIS registry ABOUT
    the name, so pinning would just silently change what they report — PTR
    lookup instead of forward lookup, IP WHOIS instead of domain WHOIS —
    without closing any real "connects to a private address" risk. They get
    the re-verify treatment below instead, as cheap defense in depth.)
  - Every other runner needs the real hostname (SNI, vhost routing, or
    subdomain/name enumeration IS the point) — for those, step 8 re-resolves
    and re-confirms "still public" a second time, as late as possible,
    immediately before the subprocess spawns. This SHRINKS the window from
    "the whole scope_check-to-spawn request lifetime" down to the gap between
    that one extra DNS round-trip and the external tool's own lookup — it
    does NOT close it. Nothing in Python can bind a third-party subprocess's
    own resolver to the address we just validated. The only structurally
    complete fix is kernel-level egress filtering (a network namespace or an
    nftables rule scoped to the run_tool subprocess tree, blocking outbound
    to loopback/RFC1918/link-local regardless of what DNS said at any point)
    — out of scope for this app today (no root, no namespace tooling), but
    it's the real hardening path if this ever needs to be airtight instead
    of "much harder to hit."
"""

from __future__ import annotations

import ipaddress
import json
import re
import secrets
import shlex
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

from shared import common, apikeys
from consoles.redcell import wordlists

MAX_OUTPUT = 200_000          # chars kept per stream; degrades gracefully past this
AUDIT_LOG = common.REPO_ROOT / "var" / "redcell-scans.jsonl"
OUT_DIR = common.REPO_ROOT / "var" / "redcell-out"


# --------------------------------------------------------------------------
# Target validation — hostnames / IPs / URLs. Reject anything with shell
# metacharacters, whitespace, or a leading '-' (argument injection) before
# it ever reaches an argv list.
# --------------------------------------------------------------------------
_BAD_CHARS = re.compile(r"[\s;&|`$(){}<>'\"\\\[\]!*?~\x00-\x1f]")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
# The full RFC 3986 URL character set. Safe to allow in a URL target because the
# value only ever becomes ONE argv element (no shell), so '?' '&' '=' etc. are
# just characters passed to the tool — this is what lets sqlmap/nuclei/ffuf test
# real GET-parameter URLs. Whitespace, control chars, quotes, backtick, and
# < > { } | ^ \ are still refused (none belong in a URL, none are needed).
_URL_CHARS = re.compile(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$")


def validate_host(raw: str) -> tuple[bool, str]:
    """Accept a bare hostname or IPv4/IPv6 literal. Returns (ok, reason_or_host)."""
    if not isinstance(raw, str) or not raw or len(raw) > 253:
        return False, "target is empty or too long"
    if raw.startswith("-"):
        return False, "target may not start with '-' (argument injection)"
    if _BAD_CHARS.search(raw):
        return False, "target contains disallowed characters"
    try:
        ipaddress.ip_address(raw)
        return True, raw
    except ValueError:
        pass
    if _HOSTNAME_RE.match(raw):
        return True, raw
    return False, "not a valid hostname or IP literal"


def validate_url(raw: str, allow_any_scheme: bool = False) -> tuple[bool, str, str]:
    """Accept an http(s) URL with a validated host and no embedded credentials.
    Returns (ok, host_or_reason, cleaned_url).

    `allow_any_scheme` drops only the http/https requirement (the stress probe
    passes this — the operator load-tests whatever scheme they aim at). Every
    other check still applies: host validation, no embedded credentials, no
    argument injection, and the caller's own SSRF/scope gate downstream. Leave
    it False for the CLI runners — passing an odd scheme to sqlmap/nuclei/etc.
    has no legitimate use there.

    Query strings ARE allowed (the URL charset is validated against _URL_CHARS,
    not the strict host bad-char set), so real GET-parameter targets like
    http://site/page?id=1 work with sqlmap/nuclei/ffuf/nikto/wpscan. The value
    is passed as a single argv element (never a shell), so URL punctuation is
    inert. The host portion is still validated strictly via validate_host.
    """
    if not isinstance(raw, str) or not raw or len(raw) > 2048:
        return False, "target is empty or too long", ""
    if raw.startswith("-"):
        return False, "target may not start with '-' (argument injection)", ""
    if not _URL_CHARS.match(raw):
        return False, "URL contains disallowed characters (no spaces/quotes/backticks)", ""
    try:
        u = urlparse(raw)
    except ValueError:
        return False, "target is not a parseable URL", ""
    if not allow_any_scheme and u.scheme not in ("http", "https"):
        return False, "only http:// and https:// URLs are allowed", ""
    if not u.hostname:
        return False, "URL has no host", ""
    if u.username or u.password:
        return False, "URLs with embedded credentials are not allowed", ""
    ok, host_or_reason = validate_host(u.hostname)
    if not ok:
        return False, host_or_reason, ""
    return True, u.hostname, raw


def scope_check(host: str, lab: bool) -> tuple[bool, str]:
    """Block private/loopback/link-local/reserved/unresolvable targets unless
    lab=True. Reuses common.host_is_public (the same SSRF-grade check recon
    uses) so redcell never has a laxer notion of 'public' than the rest of
    Nucleus.

    This is the FIRST of two checks, not the only one — see "DNS-rebind,
    honestly" in the module docstring. This result can be stale by the time
    the tool actually runs; handle_run re-resolves a second time immediately
    before spawn (pin or re-verify, depending on the runner) to shrink that
    window as much as a Python-level check can.
    """
    if common.host_is_public(host):
        return True, ""
    if lab:
        return True, "lab-scope override"
    return False, ("target resolves to a private/loopback/link-local/reserved address "
                    "(or doesn't resolve) — set lab:true only to test your own lab or localhost")


def _resolve_public_ips_safe(host: str) -> list[str]:
    """Wrapper around common.resolve_public_ips() tolerant of either a
    raise-on-blocked or return-empty-on-blocked contract (this codebase has
    both styles — host_is_public() swallows and returns a bool,
    _resolve_public() raises ValueError) so a detail of that helper can't
    turn into an unhandled 500 here. Always returns a list; empty means
    "don't trust this host right now"."""
    try:
        ips = common.resolve_public_ips(host)
    except (ValueError, OSError):
        return []
    return list(ips) if ips else []


# Host-kind runners whose tool CONNECTS DIRECTLY to the target address (no
# hostname-dependent behavior — no SNI, no vhost routing) get the validated
# address pinned into argv instead of the hostname, closing the DNS-rebind
# gap completely for them. See "DNS-rebind, honestly" above for why dig/host/
# whois are host-kind but NOT in this set.
_REBIND_IP_PIN = {"nmap", "sslscan", "testssl", "enum4linux"}

# Every other runner needs the real hostname (SNI / vhost / subdomain-enum is
# the point) — these get re-resolved and re-verified "still public" a second
# time immediately before spawn instead of being pinned. dig/host/whois are
# here rather than in the pin set above (see the docstring note).
_REBIND_RECHECK = {
    "nuclei", "gobuster-dns", "gobuster-dir", "wpscan", "nikto", "sqlmap",
    "subfinder", "theharvester", "dnsenum", "dnsrecon", "sublist3r", "ffuf",
    "feroxbuster", "wfuzz", "whatweb", "httpx", "wafw00f",
    "dig", "host", "whois",
}


# --------------------------------------------------------------------------
# Output paths — server-controlled, never a client-supplied path. Used by
# the handful of runners whose findings are worth persisting to disk in
# addition to the stdout we already capture (nmap, nuclei).
# --------------------------------------------------------------------------
def _ensure_out_dir() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        OUT_DIR.chmod(0o700)
    except OSError:
        pass


def _out_path(tool: str, ext: str) -> str:
    _ensure_out_dir()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    fname = f"{tool}-{ts}-{secrets.token_hex(4)}.{ext}"
    return str(OUT_DIR / fname)


# --------------------------------------------------------------------------
# Runner specs. A runner declares its target kind, a fixed timeout, zero or
# more named OPTIONS (each a closed choice-dict — the client's chosen key is
# validated then swapped for the server-side fixed value before it ever
# reaches build()), whether it needs a wordlist (resolved through
# wordlists.resolve(), never a path), and whether it wants a server-picked
# output file. `build(ctx)` only ever sees already-validated/looked-up
# values — it does no validation of its own.
# --------------------------------------------------------------------------
@dataclass
class BuildCtx:
    target: str
    options: dict = field(default_factory=dict)   # name -> resolved fixed value
    wordlist: Optional[str] = None                 # resolved absolute path
    out_path: Optional[str] = None                 # server-picked output path
    apikey: Optional[str] = None                   # resolved secret value, if any
    resolved_ip: Optional[str] = None               # DNS-rebind pin, IP-pin-tier runners only
                                                     # (see _REBIND_IP_PIN) — `target` stays the
                                                     # original hostname so build() can still use
                                                     # it for SNI/display even when pinning argv


@dataclass
class OptionSpec:
    choices: dict                    # client key -> resolved fixed value (str or list[str])
    default: str
    label: str = ""


@dataclass
class RunnerSpec:
    bin: str
    kind: str                      # "host" | "url"
    build: Callable[[BuildCtx], list]
    timeout: float
    install: str
    desc: str
    options: dict = field(default_factory=dict)     # name -> OptionSpec
    needs_wordlist: bool = False
    needs_output: Optional[str] = None               # file extension, or None
    uses_apikey: Optional[str] = None                # env-var name, or None
    known_broken: bool = False                        # installed but confirmed non-functional
                                                       # on this box (see desc for why) — surfaced
                                                       # in /api/inventory so the UI can badge it
                                                       # instead of the state living only in prose


# ---- nmap: fixed scan-profile enum, -Pn -T3 always, persisted -oN copy ----
_NMAP_PROFILES = {
    "quick":   ["-T3", "-Pn", "--top-ports", "100"],
    "service": ["-T3", "-Pn", "-sV", "--top-ports", "100"],
    "scripts": ["-T3", "-Pn", "-sV", "-sC", "--top-ports", "100"],
    "vuln":    ["-T3", "-Pn", "-sV", "--script", "vuln", "--top-ports", "100"],
    "full":    ["-T3", "-Pn", "-sV", "-p-"],
}


def _build_nmap(ctx: BuildCtx) -> list:
    argv = ["nmap"] + ctx.options["profile"]
    if ctx.out_path:
        argv += ["-oN", ctx.out_path]
    # DNS-rebind pin (see _REBIND_IP_PIN): nmap doesn't need the hostname for
    # anything at these scan profiles, so prefer the address we just
    # re-validated over letting nmap resolve the name itself.
    argv.append(ctx.resolved_ip or ctx.target)
    return argv


def _build_enum4linux(ctx: BuildCtx) -> list:
    # DNS-rebind pin: enum4linux's own usage text calls its positional arg
    # "ip" — SMB null-session enum has no SNI/name-routing dependency.
    return ["enum4linux", "-a", ctx.resolved_ip or ctx.target]


def _build_sslscan(ctx: BuildCtx) -> list:
    # DNS-rebind pin, SNI-preserving: connect to the validated IP but tell
    # sslscan the real hostname via --sni-name so a name-based-vhosted TLS
    # server still presents the right certificate.
    argv = ["sslscan", "--no-colour"]
    if ctx.resolved_ip and ctx.resolved_ip != ctx.target:
        argv += [f"--sni-name={ctx.target}"]
        argv.append(ctx.resolved_ip)
    else:
        argv.append(ctx.target)
    return argv


def _build_testssl(ctx: BuildCtx) -> list:
    # DNS-rebind pin via --ip: keeps the hostname as the URI (correct SNI /
    # cert-name matching, same as sslscan above) while forcing the actual TCP
    # connection to the address we already validated — testssl's own --help:
    # "tests the supplied <ip> ... instead of resolving host(s) in URI".
    argv = ["testssl", "--fast", "--quiet", "--color", "0"]
    if ctx.resolved_ip and ctx.resolved_ip != ctx.target:
        argv += ["--ip", ctx.resolved_ip]
    argv.append(ctx.target)
    return argv


def _build_nuclei(ctx: BuildCtx) -> list:
    argv = ["nuclei", "-u", ctx.target, "-rl", ctx.options["rate"],
            "-timeout", "10", "-silent", "-etags", "dos,intrusive,fuzz"]
    tag = ctx.options.get("tags")
    if tag:
        argv += ["-tags", tag]
    else:
        argv += ["-severity", "info,low,medium,high,critical"]
    if ctx.out_path:
        argv += ["-o", ctx.out_path]
    return argv


def _build_gobuster_dir(ctx: BuildCtx) -> list:
    return ["gobuster", "dir", "-u", ctx.target, "-w", ctx.wordlist, "-q", "-t", "10"]


def _build_gobuster_dns(ctx: BuildCtx) -> list:
    return ["gobuster", "dns", "--domain", ctx.target, "-w", ctx.wordlist, "-q", "-t", "10"]


def _build_ffuf(ctx: BuildCtx) -> list:
    url = ctx.target.rstrip("/") + "/FUZZ"
    return ["ffuf", "-u", url, "-w", ctx.wordlist, "-t", "20", "-s",
            "-mc", "200-299,301,302,307,401,403,405"]


def _build_feroxbuster(ctx: BuildCtx) -> list:
    return ["feroxbuster", "-u", ctx.target, "-w", ctx.wordlist, "-d", "2", "-q"]


def _build_wfuzz(ctx: BuildCtx) -> list:
    url = ctx.target.rstrip("/") + "/FUZZ"
    return ["wfuzz", "-w", ctx.wordlist, "-t", "20", "--hc", "404", url]


def _build_wpscan(ctx: BuildCtx) -> list:
    argv = ["wpscan", "--url", ctx.target, "--enumerate", "vp,vt,u",
            "--random-user-agent", "--no-banner"]
    if ctx.apikey:
        argv += ["--api-token", ctx.apikey]
    return argv


SAFE_RUNNERS: dict[str, RunnerSpec] = {
    # ---- recon / enum ----
    "nmap": RunnerSpec(
        bin="nmap", kind="host", timeout=600,
        install="sudo pacman -S nmap",
        desc="Scan-profile enum, always -Pn -T3 (non-aggressive timing, no ping sweep). "
             "'full' scans all 65535 ports and can take several minutes. Also writes a "
             "normal-format copy under var/redcell-out/.",
        options={"profile": OptionSpec(
            choices=_NMAP_PROFILES, default="quick",
            label="quick=top-100 · service=version detect · scripts=-sC · vuln=--script vuln · full=all ports")},
        needs_output="txt",
        build=_build_nmap,
    ),
    "whatweb": RunnerSpec(
        bin="whatweb", kind="url", timeout=60,
        install="yay -S whatweb",
        desc="Web technology fingerprinting at the lowest aggression level.",
        build=lambda ctx: ["whatweb", "--no-errors", "-a", "1", ctx.target],
    ),
    "dnsenum": RunnerSpec(
        bin="dnsenum", kind="host", timeout=180,
        install="yay -S dnsenum2",
        desc="NS/MX/zone-transfer enum + default bundled dictionary brute (--noreverse skips "
             "the netblock reverse-lookup sweep; no google scraping, no -w whois netrange).",
        build=lambda ctx: ["dnsenum", "--noreverse", "--threads", "5", ctx.target],
    ),
    "sslscan": RunnerSpec(
        bin="sslscan", kind="host", timeout=90,
        install="sudo pacman -S sslscan",
        desc="Read-only TLS/cipher posture check.",
        build=_build_sslscan,
    ),
    "testssl": RunnerSpec(
        bin="testssl", kind="host", timeout=120,
        install="sudo pacman -S testssl.sh",
        desc="Read-only TLS/SSL posture check (fast mode).",
        build=_build_testssl,
    ),
    "wafw00f": RunnerSpec(
        bin="wafw00f", kind="url", timeout=30,
        install="pipx install wafw00f",
        desc="WAF fingerprinting — passive/low-volume GET probes, reports every WAF that matches.",
        build=lambda ctx: ["wafw00f", "-a", "-T", "10", ctx.target],
    ),
    "enum4linux": RunnerSpec(
        bin="enum4linux", kind="host", timeout=120,
        install="yay -S enum4linux",
        desc="SMB/Samba null-session enumeration (users, shares, groups, policy, OS info).",
        build=_build_enum4linux,
    ),
    "httpx": RunnerSpec(
        bin="httpx", kind="host", timeout=30,
        install="go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        desc="Fast HTTP probe — status, title, tech-detect, server header.",
        build=lambda ctx: ["httpx", "-u", ctx.target, "-sc", "-title", "-td",
                            "-server", "-timeout", "10", "-silent"],
    ),

    # ---- subdomain / OSINT ----
    "subfinder": RunnerSpec(
        bin="subfinder", kind="host", timeout=90,
        install="yay -S subfinder",
        desc="Passive subdomain enumeration.",
        build=lambda ctx: ["subfinder", "-d", ctx.target, "-silent", "-timeout", "10"],
    ),
    "theharvester": RunnerSpec(
        bin="theHarvester", kind="host", timeout=90,
        install="yay -S theharvester-git",
        desc="Passive OSINT harvesting from certificate-transparency logs (crt.sh). No -c/-p (no active brute/scan flags).",
        build=lambda ctx: ["theHarvester", "-d", ctx.target, "-l", "100", "-b", "crtsh"],
    ),
    "sublist3r": RunnerSpec(
        bin="sublist3r", kind="host", timeout=90,
        install="pipx install sublist3r",
        desc="Passive subdomain enumeration via search-engine aggregation (no -b bruteforce module).",
        build=lambda ctx: ["sublist3r", "-d", ctx.target, "-n"],
    ),
    "dnsrecon": RunnerSpec(
        bin="dnsrecon", kind="host", timeout=60,
        install="pipx install dnsrecon",
        desc="Standard DNS record enumeration (NS/SOA/MX/TXT/A/AAAA/SRV). "
             "Currently broken on this box: the pipx venv's Python 3.14 removed "
             "urllib.request.FancyURLopener, which dnsrecon's bingenum module imports at "
             "load time — every invocation errors before it can run. Not patched here "
             "(third-party site-packages); wired anyway so it fails loud with a real "
             "traceback in stderr instead of silently.",
        known_broken=True,
        build=lambda ctx: ["dnsrecon", "-d", ctx.target, "-t", "std"],
    ),

    # ---- web content discovery (brute — wordlist required) ----
    "gobuster-dir": RunnerSpec(
        bin="gobuster", kind="url", timeout=300,
        install="sudo pacman -S gobuster",
        desc="Directory/file brute-force. Needs a wordlist.",
        needs_wordlist=True,
        build=_build_gobuster_dir,
    ),
    "gobuster-dns": RunnerSpec(
        bin="gobuster", kind="host", timeout=300,
        install="sudo pacman -S gobuster",
        desc="DNS subdomain brute-force. Needs a wordlist.",
        needs_wordlist=True,
        build=_build_gobuster_dns,
    ),
    "ffuf": RunnerSpec(
        bin="ffuf", kind="url", timeout=300,
        install="yay -S ffuf",
        desc="Fast web fuzzer — brutes the target's top-level path with FUZZ auto-appended. Needs a wordlist.",
        needs_wordlist=True,
        build=_build_ffuf,
    ),
    "feroxbuster": RunnerSpec(
        bin="feroxbuster", kind="url", timeout=300,
        install="yay -S feroxbuster",
        desc="Fast recursive content discovery, recursion capped at depth 2. Needs a wordlist.",
        needs_wordlist=True,
        build=_build_feroxbuster,
    ),
    "wfuzz": RunnerSpec(
        bin="wfuzz", kind="url", timeout=300,
        install="yay -S wfuzz",
        desc="Web fuzzer — brutes the target's top-level path with FUZZ auto-appended. Needs a wordlist. "
             "Currently broken on this box: missing the 'pkg_resources' module (setuptools) "
             "in its interpreter — not patched here (system package); wired anyway so it "
             "fails loud instead of silently.",
        needs_wordlist=True,
        known_broken=True,
        build=_build_wfuzz,
    ),

    # ---- vuln scan ----
    "nuclei": RunnerSpec(
        bin="nuclei", kind="url", timeout=180,
        install="yay -S nuclei",
        desc="Template-based scan, rate-limited, dos/intrusive/fuzz tags always excluded. "
             "Also writes a copy of findings under var/redcell-out/.",
        options={
            "rate": OptionSpec(choices={"5": "5", "10": "10", "20": "20"}, default="10",
                                label="requests/sec"),
            "tags": OptionSpec(choices={
                "all": "", "cves": "cve", "exposures": "exposure",
                "misconfig": "misconfig", "default-logins": "default-login",
            }, default="all", label="template focus"),
        },
        needs_output="txt",
        build=_build_nuclei,
    ),
    "nikto": RunnerSpec(
        bin="nikto", kind="url", timeout=300,
        install="sudo pacman -S nikto",
        desc="Web server vuln/misconfig scanner, DoS-tuning-category excluded (-Tuning x6).",
        build=lambda ctx: ["nikto", "-h", ctx.target, "-Tuning", "x6", "-nointeractive", "-ask", "no"],
    ),
    "wpscan": RunnerSpec(
        bin="wpscan", kind="url", timeout=300,
        install="sudo pacman -S wpscan",
        desc="WordPress plugin/theme/user enumeration (-e vp,vt,u). A free WPScan API token "
             "(WPSCAN_API_TOKEN in var/.env) unlocks the live vulnerability database — "
             "without one this still enumerates what's installed, just without CVE matching.",
        uses_apikey="WPSCAN_API_TOKEN",
        build=_build_wpscan,
    ),

    # ---- SQLi detection (safe mode only — see sqlmap builder for anything past detection) ----
    "sqlmap": RunnerSpec(
        bin="sqlmap", kind="url", timeout=180,
        install="sudo pacman -S sqlmap",
        desc="SQLi DETECTION only — --batch --crawl=0 --level=1 --risk=1. Never dumps, never "
             "opens a shell. GET-parameter URLs (e.g. http://site/page?id=1) work fine here — "
             "the target validator allows query strings. For anything beyond detection "
             "(higher level/risk, --dump, --os-shell), use the Build tab instead.",
        build=lambda ctx: ["sqlmap", "-u", ctx.target, "--batch", "--crawl=0", "--level=1", "--risk=1"],
    ),

    # ---- simple lookups ----
    "dig": RunnerSpec(
        bin="dig", kind="host", timeout=20,
        install="sudo pacman -S bind",
        desc="DNS record lookup.",
        build=lambda ctx: ["dig", ctx.target, "+noall", "+answer"],
    ),
    "host": RunnerSpec(
        bin="host", kind="host", timeout=20,
        install="sudo pacman -S bind",
        desc="Simple DNS lookup.",
        build=lambda ctx: ["host", ctx.target],
    ),
    "whois": RunnerSpec(
        bin="whois", kind="host", timeout=20,
        install="sudo pacman -S whois",
        desc="WHOIS registration lookup.",
        build=lambda ctx: ["whois", ctx.target],
    ),
}

# amass is deliberately NOT wired here. OWASP Amass v5's `amass enum` starts a
# local "engine" daemon (client/server split) that — as tested live against
# this exact binary — binds 0.0.0.0:4000 (and 127.0.0.1:6060 for pprof) with
# no authentication, and that process is not a child of the `enum` process
# run_tool's timeout kills, so it can outlive the request that spawned it.
# That's a wildcard-bind, unauthenticated network listener triggered by a web
# button — directly against this whole suite's loopback-only threat model.
# Nothing in amass's CLI (`amass engine -h`) exposes a bind-address flag to
# fix this. subfinder already covers passive subdomain enum without the
# daemon. amass stays in builder.py — Cole runs it himself, on his own
# terminal, when he decides to.


# Every safe runner must sit in exactly one rebind treatment: IP-pinned, or
# rechecked-still-public before spawn. The gate's step-8 fallback now fails
# closed for anything not pinned, but this catches a runner added to neither
# set (or to both) at import time, keeping the two sets an honest map of
# SAFE_RUNNERS instead of silently drifting.
assert set(SAFE_RUNNERS) == _REBIND_IP_PIN | _REBIND_RECHECK, \
    "rebind sets must cover exactly SAFE_RUNNERS"
assert not (_REBIND_IP_PIN & _REBIND_RECHECK), \
    "a runner cannot be both IP-pinned and rechecked"


def _cap(s: str) -> str:
    if s and len(s) > MAX_OUTPUT:
        return s[:MAX_OUTPUT] + f"\n...[truncated, {len(s) - MAX_OUTPUT} more chars]"
    return s or ""


def _append_audit(entry: dict) -> None:
    if not common.LOGGING_ENABLED:   # no on-disk trail by default (NUCLEUS_LOGGING=1 to opt in)
        return
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except OSError:
        pass  # audit logging must never be why a request 500s


def _redact_argv(argv: list, secret: Optional[str]) -> list:
    """Copy of argv with any element exactly equal to `secret` replaced.
    Used so an API key never reaches the audit log or the HTTP response —
    only the literal subprocess call (which never leaves this process) sees it."""
    if not secret:
        return list(argv)
    return [("***REDACTED***" if a == secret else a) for a in argv]


def _redact_str(text: str, secret: Optional[str]) -> str:
    """Scrub a secret out of tool stdout/stderr before it reaches the browser —
    in case a tool echoes its own token in an error/debug line."""
    if not secret or not text:
        return text
    return text.replace(secret, "***REDACTED***")


def _resolve_options(spec: RunnerSpec, body: dict) -> tuple[Optional[dict], Optional["common.Response"]]:
    """Validate every declared option against its fixed choice-dict. Returns
    (resolved, None) or (None, error_response). The client's raw key is
    checked against spec.options[name].choices and then DISCARDED — only the
    looked-up value is kept, so the raw key never reaches build()/argv."""
    resolved: dict = {}
    supplied = body.get("options")
    if not isinstance(supplied, dict):
        supplied = {}
    for name, opt in spec.options.items():
        key = supplied.get(name)
        if key is None:
            resolved[name] = opt.choices[opt.default]
            continue
        key = str(key)
        if key not in opt.choices:
            return None, common.Response.error(
                400, f"invalid {name}: must be one of {sorted(opt.choices)}")
        resolved[name] = opt.choices[key]
    return resolved, None


# --------------------------------------------------------------------------
# OpSec gate — don't let an authorized run leave the box while the real IP is
# exposed. This is the "nothing comes back to me" safety: it turns the passive
# EXPOSED banner into an actual refusal, enforcing VPN-on discipline. It does
# NOT anonymize traffic (only a VPN/Tor/proxy can) — it just refuses to be the
# thing that fires a scan from your real IP by accident.
#
# Applies to every target-touching action (runners, expert, web-analyze,
# secret-scan). Skipped for lab/local targets (no external exposure) and
# overridable per request with proceed_exposed:true for the times you know
# you're clear (or the anonymity oracles are simply unreachable). Reads the
# process-wide opsec cache (~25s TTL, kept warm by the UI's opsec poll), so on
# the hot path it's a dict read, not a network round-trip.
# --------------------------------------------------------------------------
def opsec_gate(lab: bool, body: dict) -> Optional["common.Response"]:
    if lab or body.get("proceed_exposed") is True:
        return None
    try:
        status = common.opsec_status()
    except Exception:
        return None  # a broken opsec check must never be why authorized work is blocked
    if not status.get("exposed"):
        return None
    ip = status.get("public_ip") or "?"
    reason = status.get("reason") or "no VPN detected"
    return common.Response.json({
        "error": (f"OPSEC BLOCK — you're exposed ({reason}). Your real IP {ip} would reach the "
                  "target. Turn on your VPN (Mullvad), or enable 'scan anyway' to override."),
        "status": 403, "opsec_block": True, "public_ip": ip,
    }, status=403)


def handle_run(req) -> "common.Response":
    body = req.json()
    tool = str(body.get("tool") or "")
    target_raw = body.get("target")
    authorized = body.get("authorized") is True
    lab = body.get("lab") is True

    spec = SAFE_RUNNERS.get(tool)
    if spec is None:
        return common.Response.error(400,
            f"'{tool}' is not a runnable tool. Only these run here: {', '.join(sorted(SAFE_RUNNERS))}. "
            "Use /api/build for everything else (it builds the command for you to run yourself).")

    if not authorized:
        return common.Response.error(403,
            "authorized:true is required — confirm you have permission to test this target before it runs.")

    if not isinstance(target_raw, str):
        return common.Response.error(400, "target must be a string")

    if spec.kind == "url":
        ok, host_or_reason, cleaned = validate_url(target_raw)
        if not ok:
            return common.Response.error(400, f"invalid target: {host_or_reason}")
        scope_host, argv_target = host_or_reason, cleaned
    else:
        ok, host_or_reason = validate_host(target_raw)
        if not ok:
            return common.Response.error(400, f"invalid target: {host_or_reason}")
        scope_host, argv_target = host_or_reason, host_or_reason

    in_scope, reason = scope_check(scope_host, lab)
    if not in_scope:
        return common.Response.error(403, reason)

    blocked = opsec_gate(lab, body)
    if blocked is not None:
        return blocked

    resolved_options, err = _resolve_options(spec, body)
    if err is not None:
        return err

    wordlist_path = None
    wordlist_id = None
    if spec.needs_wordlist:
        wordlist_id = body.get("wordlist")
        if not isinstance(wordlist_id, str) or not wordlist_id:
            return common.Response.error(400, f"'{tool}' needs a wordlist — pick one from the list")
        wordlist_path = wordlists.resolve(wordlist_id)
        if wordlist_path is None:
            return common.Response.error(400, f"unknown wordlist id: {wordlist_id!r}")

    path = common.which(spec.bin)
    if not path:
        return common.Response.error(409,
            f"{spec.bin} is not installed — install it with: {spec.install}")

    # DNS-rebind mitigation, step 8 — as late as possible, right before
    # spawn. See "DNS-rebind, honestly" in the module docstring for why this
    # is two different treatments and what it does and doesn't close.
    resolved_ip = None
    if tool in _REBIND_IP_PIN:
        ips = _resolve_public_ips_safe(scope_host)
        if not ips:
            if not lab:
                return common.Response.error(403,
                    "target no longer resolves to a public address (re-checked "
                    "immediately before running) — refusing")
            # lab mode: proceed unpinned — a private lab target won't resolve
            # via resolve_public_ips at all, and lab mode intentionally opts
            # out of the public-only requirement (same as scope_check above).
        else:
            resolved_ip = ips[0]
    elif not lab:
        # Fail CLOSED for every non-IP-pinned runner, not only those we
        # remembered to list in _REBIND_RECHECK: re-verify still-public right
        # before spawn regardless of set membership, so adding a runner to
        # neither set can never silently skip step 8.
        if not _resolve_public_ips_safe(scope_host):
            return common.Response.error(403,
                "target no longer resolves to a public address (re-checked "
                "immediately before running) — refusing; set lab:true only "
                "for your own lab or localhost")

    # Saved output copies are part of the on-disk trail — off unless logging is on.
    out_path = _out_path(tool, spec.needs_output) if (spec.needs_output and common.LOGGING_ENABLED) else None
    apikey = apikeys.get_key(spec.uses_apikey) if spec.uses_apikey else None
    apikey = apikey or None  # "" -> None, so build() can just check truthiness

    ctx = BuildCtx(target=argv_target, options=resolved_options,
                   wordlist=wordlist_path, out_path=out_path, apikey=apikey,
                   resolved_ip=resolved_ip)
    argv = spec.build(ctx)
    result = common.run_tool(argv, timeout=spec.timeout)

    safe_argv = _redact_argv(argv, apikey)

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": tool, "argv": safe_argv, "target": argv_target,
        "authorized": authorized, "lab": lab,
        "wordlist": wordlist_id, "out_path": out_path,
        "returncode": result.returncode, "duration": result.duration,
        "timed_out": result.timed_out,
    }
    _append_audit(entry)

    return common.Response.json({
        "argv": safe_argv,
        "returncode": result.returncode,
        "stdout": _redact_str(_cap(result.stdout), apikey),
        "stderr": _redact_str(_cap(result.stderr), apikey),
        "duration": result.duration,
        "timed_out": result.timed_out,
        "error": result.error,
        "out_path": out_path,
    })


# --------------------------------------------------------------------------
# Expert mode — run any INSTALLED pentest tool from the inventory with your own
# arguments. Safe because: only inventory binaries (never an arbitrary system
# command), args tokenized with shlex to an argv list (NO shell, so metachars
# are inert), the authorization + expert-ack gates, secret redaction, output
# caps, and the same Origin/host guards as everything else. Cole owns the target
# choice here (like his terminal) — the guardrail is 'no shell, no arbitrary
# binary', not 'no dangerous flags'.
# --------------------------------------------------------------------------
# General-purpose / privesc binaries that happen to be in the kit but must NOT
# be reachable as an arbitrary-arg runner (docker is root-equivalent; the rest
# are code-exec shells/interpreters).
#
# Everything below that isn't in the original hand-picked set was added after
# auditing the FULL Expert allowlist (every installed, kind=="bin" entry in
# inventory.REGISTRY not already denied) for tools whose OWN documented
# feature set can spawn an arbitrary process or load arbitrary code,
# independent of run_tool's shell=False guarantee — "no shell ever" is a
# property of THIS file's subprocess call, not of every binary it's allowed
# to invoke. None of this is reachable today (auth + expert_ack gate holds,
# confirmed live in the prior audit); the point is that a FUTURE bug reaching
# /api/expert should cost "ran an allowlisted tool," not "got a shell."
# Two tiers, both denied, documented separately so the reasoning survives:
_EXPERT_DENY = {
    "docker", "python", "python3", "python2", "ruby", "perl", "sh",
    "bash", "zsh", "fish", "tmux", "jq", "pip", "pipx", "go", "gcc",
    "msfconsole", "msfvenom",

    # ---- Tier 1: direct, single-argv arbitrary command/binary execution.
    # Zero extra primitives needed beyond what Expert mode already grants
    # (argv control) — the CLI argument text itself IS the shell command or
    # the binary to exec. Confirmed via man page / --help / the tool's own
    # usage banner this session (not executed live — see the audit note). ----
    "socat",            # EXEC:<cmd> / SYSTEM:<shell-cmd> / SHELL:<cmd>
                         # address types — man socat, ADDRESS TYPES section
    "tcpdump",           # -z postrotate-command forks/execs an arbitrary
                         # command after each -C/-G file rotation — man tcpdump
    "radare2", "r2",     # `-c 'cmd'` / interactive `!` shells out — r2 -h
                         # confirms `-c 'cmd..' execute radare command`; `!`
                         # is one of r2's most basic documented commands
    "gdb", "gdb-multiarch", "pwndbg",  # built-in `shell`/`!` — live-confirmed:
                         # `gdb -batch -ex "help shell"` -> "Execute the rest
                         # of the line as a shell command." pwndbg is a gdb
                         # plugin wrapper, inherits the same command
    "bettercap",         # `-eval '! id'` runs the session's `!` shell-out
                         # straight from ONE CLI flag, no caplet file needed —
                         # confirmed via `bettercap --help` (-eval exists) +
                         # documented `!` session command
    "proxychains", "proxychains4",  # usage is literally `proxychains4 ...
                         # program_name [args]` — it execs whatever you name
                         # as its own argv, unconditionally. `proxychains4 sh`
                         # is a full shell. Confirmed via its own usage banner.
    "aflplusplus", "afl-fuzz",  # usage is `afl-fuzz [opts] -- /path/to/target
                         # [args]` — execs whatever binary follows `--` as the
                         # fuzz target. Confirmed via `afl-fuzz --help`.
    "honggfuzz",         # same shape: `honggfuzz [opts] -- path_to_command
                         # [args]` execs the trailing command. Confirmed via
                         # `honggfuzz --help`.

    # ---- Tier 2: loads an arbitrary LOCAL script/template/plugin FILE that
    # then execs. Needs a second primitive (something to plant that file)
    # that doesn't exist anywhere in this app today — a materially smaller
    # blast radius than Tier 1 above. Denied anyway per the conservative
    # standard here ("can load a script that execs" = deny); each of these
    # loses ONLY its ad-hoc Expert-mode flag access, not its normal use. ----
    "nmap",              # --script <path> loads NSE Lua with an UNSANDBOXED
                         # os.execute() — nmap's own manual states scripts
                         # "are not run in a sandbox... can use os.execute()
                         # to run arbitrary system commands." The fixed-
                         # profile nmap runner in SAFE_RUNNERS is untouched.
    "tshark", "wireshark",  # -X lua_script:<path> loads arbitrary Lua; the
                         # shared Wireshark/tshark Lua engine exposes
                         # io.popen (tshark.dev's own scripting docs show an
                         # io.popen(...) call from a loaded script).
    "ettercap",          # -F <compiled-filter> runs an etterfilter script,
                         # which has a built-in exec(command) function — man
                         # etterfilter: "this function executes a shell
                         # command."
    "mitmproxy",         # -s/--scripts <path> loads an arbitrary Python
                         # addon, executed inside the mitmproxy process —
                         # confirmed via `mitmproxy --help` (--scripts, -s).
    "nuclei",            # -code enables "code protocol" templates, which run
                         # local commands as part of the check — confirmed
                         # via `nuclei -h` (-code flag, off by default for
                         # exactly this reason). SAFE_RUNNERS' nuclei profile
                         # never sets -code, so normal scanning is unaffected.
    "volatility3", "vol",  # -p/--plugin-dirs loads arbitrary Python plugin
                         # modules from a given directory, executed on import
                         # — confirmed via `vol -h`.
    "exiftool",          # -config <file> loads a ExifTool config, which is a
                         # Perl file eval'd on load (man exiftool: config files
                         # are Perl) — arbitrary code once a file can be planted.
                         # Same Tier-2 shape as the loaders above.
    "ghidra", "analyzeHeadless",  # Ghidra headless runs -preScript/-postScript/
                         # -scriptPath GhidraScripts (Java/Jython) that exec
                         # arbitrary code — same shape as nmap --script above.
                         # Not wired into redcell today; denied pre-emptively so
                         # it can never slip in as an Expert arbitrary-arg tool.
}


def _expert_binaries() -> set:
    from consoles.redcell import inventory
    bins = {s.bin for s in inventory.REGISTRY
            if getattr(s, "kind", "bin") == "bin" and s.bin}
    return {b for b in bins if b not in _EXPERT_DENY and common.which(b)}


def _all_secret_env_names() -> set:
    """Every env-var name that holds a secret the app might place in an argv —
    the OSINT catalog PLUS any token a runner declares via uses_apikey (e.g.
    WPSCAN_API_TOKEN, which isn't in the recon catalog). Expert mode redacts all
    of them, so a token passed as a raw Expert argument can't leak in cleartext
    to the audit log or the HTTP response the way it would if only CATALOG were
    scrubbed."""
    names = {s["name"] for s in apikeys.CATALOG}
    names |= {spec.uses_apikey for spec in SAFE_RUNNERS.values() if spec.uses_apikey}
    return names


def _redact_all(text: str) -> str:
    if not text:
        return text
    for name in _all_secret_env_names():
        v = apikeys.get_key(name)
        if v:
            text = text.replace(v, "***REDACTED***")
    return text


def handle_expert_tools(req) -> "common.Response":
    return common.Response.json({"tools": sorted(_expert_binaries())})


def handle_expert(req) -> "common.Response":
    body = req.json()
    if body.get("authorized") is not True:
        return common.Response.error(403, "authorization required — check the box first")
    if body.get("expert_ack") is not True:
        return common.Response.error(403, "expert mode: acknowledge you're running your own arguments on a target you're authorized to test")
    # Expert has no lab flag (arbitrary args), so the opsec gate always applies
    # unless proceed_exposed is set — override it when your target is local.
    blocked = opsec_gate(False, body)
    if blocked is not None:
        return blocked
    tool = str(body.get("tool", "")).strip()
    args_raw = str(body.get("args", ""))
    if tool not in _expert_binaries():
        return common.Response.error(400, "expert mode only runs installed pentest tools from the inventory (not arbitrary commands)")
    try:
        tokens = shlex.split(args_raw, posix=True)
    except ValueError as e:
        return common.Response.error(400, f"couldn't parse arguments: {e}")
    if len(tokens) > 80:
        return common.Response.error(400, "too many arguments (max 80)")
    for t in tokens:
        if len(t) > 4096:
            return common.Response.error(400, "an argument is too long")
        if any((ord(c) < 9 or (13 < ord(c) < 32) or ord(c) == 127) for c in t):
            return common.Response.error(400, "an argument contains control characters")
    argv = [tool] + tokens
    result = common.run_tool(argv, timeout=600)
    safe_argv = [_redact_all(a) for a in argv]
    _append_audit({
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": tool, "argv": safe_argv, "mode": "expert",
        "authorized": True, "returncode": result.returncode,
        "duration": result.duration, "timed_out": result.timed_out,
    })
    return common.Response.json({
        "argv": safe_argv, "returncode": result.returncode,
        "stdout": _redact_all(_cap(result.stdout)),
        "stderr": _redact_all(_cap(result.stderr)),
        "duration": result.duration, "timed_out": result.timed_out,
        "error": result.error,
    })


def handle_history(req) -> "common.Response":
    limit = 50
    try:
        limit = max(1, min(int(req.q("limit", "50")), 200))
    except ValueError:
        pass
    if not AUDIT_LOG.exists():
        return common.Response.json({"runs": [], "total_logged": 0})
    try:
        lines = AUDIT_LOG.read_text(encoding="utf-8").splitlines()
    except OSError:
        return common.Response.json({"runs": [], "total_logged": 0})
    runs = []
    for line in reversed(lines[-limit:]):
        try:
            runs.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return common.Response.json({"runs": runs, "total_logged": len(lines)})


def handle_wordlists(req) -> "common.Response":
    q = req.q("q", "")
    limit = 50
    try:
        limit = max(1, min(int(req.q("limit", "50")), 200))
    except ValueError:
        pass
    return common.Response.json({
        "results": wordlists.search(q, limit=limit),
        "total_registered": wordlists.registry_count(),
    })


# Bounds for the preview: enough lines to eyeball a list, a hard cap on how far
# we'll count into a huge file (rockyou is ~14M lines / 130MB), and a per-read
# byte window so a pathological single-huge-line file can't be buffered whole.
_WL_PREVIEW_LINES = 40
_WL_COUNT_CAP = 2_000_000
_WL_LINE_MAXLEN = 512
_WL_CHUNK = 1 << 20           # 1 MiB read window — bounds memory per iteration
_WL_PREVIEW_BYTE_CAP = 65_536  # never buffer more than this for the preview slice


def handle_wordlist_preview(req) -> "common.Response":
    """GET /api/wordlist-preview?id=...  ->  first lines + a bounded line count.

    Read-only, no exec. The id resolves through wordlists.resolve() — the SAME
    allowlist + allowed-root re-validation a runner uses — so this can only ever
    read a file already in the registry, never an arbitrary path.

    Read in fixed 1 MiB byte chunks (never `for line in f`, which would buffer
    one whole line first — a single-line 130MB file would then be read whole).
    Memory is bounded to the chunk window plus a 64 KiB preview buffer no matter
    how the file is shaped; line counting streams and stops at the 2M cap."""
    wid = req.q("id", "")
    if not wid:
        return common.Response.error(400, "missing ?id=")
    path = wordlists.resolve(wid)
    if path is None:
        return common.Response.error(400, "unknown or out-of-scope wordlist id")

    preview_buf = bytearray()
    newlines = 0
    total_bytes = 0
    last_byte = b""
    capped = False
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(_WL_CHUNK)
                if not chunk:
                    break
                total_bytes += len(chunk)
                last_byte = chunk[-1:]
                newlines += chunk.count(b"\n")
                if len(preview_buf) < _WL_PREVIEW_BYTE_CAP:
                    preview_buf += chunk[:_WL_PREVIEW_BYTE_CAP - len(preview_buf)]
                if newlines >= _WL_COUNT_CAP:
                    capped = True
                    break
    except OSError as e:
        return common.Response.error(500, f"could not read wordlist: {e}")

    # line_count ≈ newline count, +1 for a final line with no trailing newline
    # (only meaningful when we read the whole file, i.e. not capped).
    line_count = newlines
    if not capped and total_bytes > 0 and last_byte != b"\n":
        line_count += 1

    parts = preview_buf.decode("utf-8", "replace").split("\n")
    if parts and parts[-1] == "":     # drop the empty tail from a trailing newline
        parts.pop()
    preview = [ln.rstrip("\r")[:_WL_LINE_MAXLEN] for ln in parts[:_WL_PREVIEW_LINES]]

    try:
        size = Path(path).stat().st_size
    except OSError:
        size = 0

    return common.Response.json({
        "id": wid,
        "preview": preview,
        "line_count": line_count,
        "count_capped": capped,      # True -> real count is "line_count+"
        "size": size,
    })


# --------------------------------------------------------------------------
# Saved outputs — nmap -oN / nuclei -o copies under OUT_DIR. Read-only,
# listing + fetch only; nothing here can write, delete, or escape OUT_DIR.
# Mirrors bastion's report-file pattern (resolve() + relative_to() traversal
# guard) but stricter: a subdirectory path is refused outright, not just a
# path that escapes the sandbox, since OUT_DIR is only ever meant to be flat.
# --------------------------------------------------------------------------
# Matches filenames _out_path() actually produces: "<tool>-<ts>-<hex8>.<ext>".
# `.+` (greedy) correctly recovers `tool` even if a future tool key contains a
# hyphen (e.g. gobuster-dir), since it anchors from the fixed-shape suffix.
_OUT_FNAME_RE = re.compile(
    r"^(?P<tool>.+)-(?P<ts>\d{8}T\d{6}Z)-(?P<rand>[0-9a-f]{8})\.(?P<ext>[A-Za-z0-9]+)$"
)


def handle_outputs(req) -> "common.Response":
    """List files directly under OUT_DIR, newest first. Never recurses —
    OUT_DIR is only ever written to by _out_path() and never contains
    subdirectories, so a browser has no reason to be able to walk into one."""
    _ensure_out_dir()
    files = []
    try:
        entries = list(OUT_DIR.iterdir())
    except OSError:
        entries = []
    for p in entries:
        if not p.is_file():
            continue
        m = _OUT_FNAME_RE.match(p.name)
        tool = m.group("tool") if m else ""
        try:
            st = p.stat()
        except OSError:
            continue
        files.append({
            "name": p.name,
            "tool": tool,
            "size": st.st_size,
            "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
                     .isoformat(timespec="seconds"),
        })
    files.sort(key=lambda f: f["mtime"], reverse=True)
    return common.Response.json({"files": files})


def handle_output_file(req) -> "common.Response":
    """Serve one saved output file as plain text. `name` must be a bare
    filename — no path separators, no '.'/'..' — resolving to a file that
    lives DIRECTLY inside OUT_DIR. The upfront separator check and the
    resolve()+relative_to() guard are redundant with each other on purpose
    (defense in depth): the separator check alone would miss the pathlib
    absolute-path-override gotcha (`base / "/etc/passwd"` silently becomes
    `/etc/passwd`), and relative_to() alone wouldn't stop a value containing
    no '/' from still being interpreted as something other than a flat name."""
    name = req.q("name")
    if not name or "/" in name or "\\" in name or name in (".", ".."):
        return common.Response.error(400, "invalid or missing ?name=")
    base = OUT_DIR.resolve()
    try:
        candidate = (base / name).resolve()
        candidate.relative_to(base)  # raises ValueError if it escapes the sandbox
    except (ValueError, OSError):
        return common.Response.error(403, "path outside output sandbox")
    if candidate.parent != base or not candidate.is_file():
        return common.Response.error(404, "not found")
    try:
        data = candidate.read_bytes()
    except OSError:
        return common.Response.error(500, "read failed")
    return common.Response.raw(data, "text/plain; charset=utf-8")


# --------------------------------------------------------------------------
# Published-tool integration. Cole's own defensive CLIs — still exec, so
# still gated: allowlisted tool keys, validated path argument, no shell.
# --------------------------------------------------------------------------
PROJECTS_DIR = Path.home() / "Projects"

LOCAL_TOOLS: dict[str, dict] = {
    "framewall": {
        "module": "framewall.cli", "bin": "framewall",
        "desc": "Detects visually-embedded prompt injection in images before a vision/computer-use agent reads them.",
        "github": "https://github.com/munzzyy/framewall",
        "argv": lambda p: ["scan", p, "--json"],
    },
    "skillxray": {
        "module": "skillxray.cli", "bin": "skillxray",
        "desc": "Security/hygiene scanner for AI agent skills (SKILL.md, plugins, MCP bundles).",
        "github": "https://github.com/munzzyy/skillxray",
        "argv": lambda p: [p, "--json"],
    },
    "sessionxray": {
        "module": "sessionxray.cli", "bin": "sessionxray",
        "desc": "Audits a Claude Code session transcript for what the agent touched and whether it should worry you.",
        "github": "https://github.com/munzzyy/sessionxray",
        "argv": lambda p: [p, "--json"],
    },
    "toolsmell": {
        "module": "toolsmell.cli", "bin": "toolsmell",
        "desc": "Lints an MCP server's tool descriptions/JSON schemas for smells that make agents misuse tools.",
        "github": "https://github.com/munzzyy/toolsmell",
        "argv": lambda p: [p, "--json"],
    },
    "webmcp-lint": {
        "module": "webmcp_lint.cli", "bin": "webmcp-lint",
        "desc": "Security and spec-correctness linter for WebMCP tool manifests.",
        "github": "https://github.com/munzzyy/webmcp-lint",
        "argv": lambda p: [p, "--json"],
    },
    "wouldrun": {
        "module": "wouldrun.cli", "bin": "wouldrun",
        "desc": "Works out which GitHub Actions workflows/jobs a change would trigger, without pushing or running act.",
        "github": "https://github.com/munzzyy/wouldrun",
        "argv": lambda p: [p, "--json"],
    },
    "coacheck": {
        "module": "coacheck.cli", "bin": "coacheck",
        "desc": "Certificate-of-Analysis parser + purity math (informational, not medical advice).",
        "github": "https://github.com/munzzyy/coacheck",
        "argv": lambda p: ["parse", p, "--json"],
    },
}


def _local_tool_status(key: str, spec: dict) -> dict:
    binpath = shutil.which(spec["bin"])
    if binpath:
        return {"installed": True, "mode": "path", "path": binpath}
    repo_dir = PROJECTS_DIR / key
    pkg_dir_name = spec["module"].split(".")[0]
    cli_file = repo_dir / pkg_dir_name / "cli.py"
    if repo_dir.is_dir() and cli_file.is_file():
        return {"installed": True, "mode": "checkout", "path": str(repo_dir)}
    return {"installed": False, "mode": None, "path": None}


def local_tools_status() -> list[dict]:
    out = []
    for key, spec in LOCAL_TOOLS.items():
        status = _local_tool_status(key, spec)
        out.append({
            "key": key, "desc": spec["desc"], "github": spec["github"],
            "installed": status["installed"], "mode": status["mode"], "path": status["path"],
        })
    return out


def _validate_local_path(raw: str) -> tuple[bool, str]:
    if not isinstance(raw, str) or not raw or len(raw) > 4096:
        return False, "path is empty or too long"
    if "\x00" in raw:
        return False, "path contains a null byte"
    try:
        p = Path(raw).expanduser().resolve()
    except (OSError, RuntimeError):
        return False, "path could not be resolved"
    try:
        p.relative_to(Path.home())
    except ValueError:
        return False, "path must be under the home directory"
    if not p.exists():
        return False, "path does not exist"
    return True, str(p)


def handle_local_tool(req) -> "common.Response":
    body = req.json()
    key = str(body.get("tool") or "")
    path_raw = body.get("path")

    spec = LOCAL_TOOLS.get(key)
    if spec is None:
        return common.Response.error(400,
            f"'{key}' is not a recognized local tool. Known: {', '.join(sorted(LOCAL_TOOLS))}")

    if not isinstance(path_raw, str):
        return common.Response.error(400, "path must be a string")
    ok, resolved_or_reason = _validate_local_path(path_raw)
    if not ok:
        return common.Response.error(400, f"invalid path: {resolved_or_reason}")
    resolved_path = resolved_or_reason

    status = _local_tool_status(key, spec)
    if not status["installed"]:
        return common.Response.error(409,
            f"{key} is not installed locally. Repo: {spec['github']}  "
            f"Install: pipx install \"git+{spec['github']}.git\"")

    extra_argv = spec["argv"](resolved_path)
    if status["mode"] == "path":
        argv = [spec["bin"]] + extra_argv
        cwd = None
    else:
        argv = ["python3", "-m", spec["module"]] + extra_argv
        cwd = status["path"]

    result = common.run_tool(argv, timeout=60.0, cwd=cwd)
    return common.Response.json({
        "argv": argv,
        "returncode": result.returncode,
        "stdout": _cap(result.stdout),
        "stderr": _cap(result.stderr),
        "duration": result.duration,
        "timed_out": result.timed_out,
        "error": result.error,
    })
