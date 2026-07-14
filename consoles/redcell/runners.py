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
  5. the binary must actually be installed

Only after all five does a subprocess get spawned. The user-supplied target
is inserted as exactly one argv element by the runner's `build` callback —
never split, never used to build a flag, never touched by string
interpolation.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

from shared import common

MAX_OUTPUT = 200_000          # chars kept per stream; degrades gracefully past this
AUDIT_LOG = common.REPO_ROOT / "var" / "redcell-scans.jsonl"


# --------------------------------------------------------------------------
# Target validation — hostnames / IPs / URLs. Reject anything with shell
# metacharacters, whitespace, or a leading '-' (argument injection) before
# it ever reaches an argv list.
# --------------------------------------------------------------------------
_BAD_CHARS = re.compile(r"[\s;&|`$(){}<>'\"\\\[\]!*?~\x00-\x1f]")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


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


def validate_url(raw: str) -> tuple[bool, str, str]:
    """Accept an http(s) URL with a validated host and no embedded credentials.
    Returns (ok, host_or_reason, cleaned_url)."""
    if not isinstance(raw, str) or not raw or len(raw) > 2048:
        return False, "target is empty or too long", ""
    if raw.startswith("-"):
        return False, "target may not start with '-' (argument injection)", ""
    if _BAD_CHARS.search(raw):
        return False, "target contains disallowed characters", ""
    try:
        u = urlparse(raw)
    except ValueError:
        return False, "target is not a parseable URL", ""
    if u.scheme not in ("http", "https"):
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
    Nucleus."""
    if common.host_is_public(host):
        return True, ""
    if lab:
        return True, "lab-scope override"
    return False, ("target resolves to a private/loopback/link-local/reserved address "
                    "(or doesn't resolve) — set lab:true only to test your own lab or localhost")


# --------------------------------------------------------------------------
# Safe runner allowlist. Fixed argv templates; TARGET (and, for a couple of
# runners, ONE enum-validated option) are the only variable positions.
# --------------------------------------------------------------------------
@dataclass
class RunnerSpec:
    bin: str
    kind: str                      # "host" | "url"
    build: Callable[[str, str], list]
    timeout: float
    install: str
    desc: str
    option_key: Optional[str] = None
    option_choices: Optional[dict] = None   # allowed-value -> substituted argv value
    option_default: Optional[str] = None


SAFE_RUNNERS: dict[str, RunnerSpec] = {
    "nmap": RunnerSpec(
        bin="nmap", kind="host", timeout=120,
        install="sudo pacman -S nmap",
        desc="Service + version detection, top ports, no ping sweep (-Pn), non-aggressive timing.",
        option_key="top_ports", option_choices={"100": "100", "1000": "1000"}, option_default="100",
        build=lambda t, opt: ["nmap", "-sV", "-T3", "--top-ports", opt, "-Pn", t],
    ),
    "whatweb": RunnerSpec(
        bin="whatweb", kind="url", timeout=60,
        install="yay -S whatweb",
        desc="Web technology fingerprinting at the lowest aggression level.",
        build=lambda t, opt: ["whatweb", "--no-errors", "-a", "1", t],
    ),
    "nuclei": RunnerSpec(
        bin="nuclei", kind="url", timeout=120,
        install="yay -S nuclei",
        desc="Template-based scan, rate-limited, DoS/intrusive/fuzz template tags excluded.",
        option_key="rate", option_choices={"5": "5", "10": "10", "20": "20"}, option_default="10",
        build=lambda t, opt: ["nuclei", "-u", t, "-rl", opt,
                               "-severity", "info,low,medium,high,critical",
                               "-etags", "dos,intrusive,fuzz",
                               "-timeout", "10", "-silent"],
    ),
    "sslscan": RunnerSpec(
        bin="sslscan", kind="host", timeout=90,
        install="sudo pacman -S sslscan",
        desc="Read-only TLS/cipher posture check.",
        build=lambda t, opt: ["sslscan", "--no-colour", t],
    ),
    "testssl": RunnerSpec(
        bin="testssl", kind="host", timeout=120,
        install="sudo pacman -S testssl.sh",
        desc="Read-only TLS/SSL posture check (fast mode).",
        build=lambda t, opt: ["testssl", "--fast", "--quiet", "--color", "0", t],
    ),
    "subfinder": RunnerSpec(
        bin="subfinder", kind="host", timeout=90,
        install="yay -S subfinder",
        desc="Passive subdomain enumeration.",
        build=lambda t, opt: ["subfinder", "-d", t, "-silent", "-timeout", "10"],
    ),
    "amass": RunnerSpec(
        bin="amass", kind="host", timeout=120,
        install="yay -S amass",
        desc="Passive-only subdomain enumeration (-passive, never active).",
        build=lambda t, opt: ["amass", "enum", "-passive", "-d", t, "-timeout", "2"],
    ),
    "theharvester": RunnerSpec(
        bin="theHarvester", kind="host", timeout=90,
        install="yay -S theharvester-git",
        desc="Passive OSINT harvesting from certificate-transparency logs (crt.sh). No -c/-p (no active brute/scan flags).",
        build=lambda t, opt: ["theHarvester", "-d", t, "-l", "100", "-b", "crtsh"],
    ),
    "dig": RunnerSpec(
        bin="dig", kind="host", timeout=20,
        install="sudo pacman -S bind",
        desc="DNS record lookup.",
        build=lambda t, opt: ["dig", t, "+noall", "+answer"],
    ),
    "host": RunnerSpec(
        bin="host", kind="host", timeout=20,
        install="sudo pacman -S bind",
        desc="Simple DNS lookup.",
        build=lambda t, opt: ["host", t],
    ),
    "whois": RunnerSpec(
        bin="whois", kind="host", timeout=20,
        install="sudo pacman -S whois",
        desc="WHOIS registration lookup.",
        build=lambda t, opt: ["whois", t],
    ),
}


def _cap(s: str) -> str:
    if s and len(s) > MAX_OUTPUT:
        return s[:MAX_OUTPUT] + f"\n...[truncated, {len(s) - MAX_OUTPUT} more chars]"
    return s or ""


def _append_audit(entry: dict) -> None:
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except OSError:
        pass  # audit logging must never be why a request 500s


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

    opt_value = spec.option_default
    if spec.option_key:
        options = body.get("options") or {}
        if not isinstance(options, dict):
            options = {}
        supplied = options.get(spec.option_key)
        if supplied is not None:
            supplied = str(supplied)
            if supplied not in (spec.option_choices or {}):
                return common.Response.error(400,
                    f"invalid {spec.option_key}: must be one of {sorted(spec.option_choices)}")
            opt_value = spec.option_choices[supplied]

    path = common.which(spec.bin)
    if not path:
        return common.Response.error(409,
            f"{spec.bin} is not installed — install it with: {spec.install}")

    argv = spec.build(argv_target, opt_value)
    result = common.run_tool(argv, timeout=spec.timeout)

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": tool, "argv": argv, "target": argv_target,
        "authorized": authorized, "lab": lab,
        "returncode": result.returncode, "duration": result.duration,
        "timed_out": result.timed_out,
    }
    _append_audit(entry)

    return common.Response.json({
        "argv": argv,
        "returncode": result.returncode,
        "stdout": _cap(result.stdout),
        "stderr": _cap(result.stderr),
        "duration": result.duration,
        "timed_out": result.timed_out,
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


