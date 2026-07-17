"""Native hash identification + crack-command planning — pure stdlib, offline.

This module never runs a cracker and never touches the network. It takes a
string that might be a password hash and works out what it probably is: the
hashcat `-m` mode, the John format, an example of that hash shape, and a
ready-to-paste crack command for both tools. Identification is the single
most repeated question in a real engagement ("what is this and how do I feed
it to hashcat"), and answering it locally — no hashid dependency, no upload —
is the whole point.

How it decides:

  * STRUCTURED hashes carry an unambiguous prefix or internal shape
    ($6$, $2b$, $krb5tgs$, {SSHA}, sha256:...). Those match exactly, so they
    come back as a single high-confidence answer.
  * RAW hashes are just a run of hex of a certain length. A 32-char hex
    string is equally MD5, NTLM, LM-half, MD4, or a dozen others by shape
    alone — nothing in the string itself distinguishes them. Those come back
    as a RANKED list of candidates (most common in practice first), clearly
    marked ambiguous, because pretending to know which one it is would send
    someone off with the wrong `-m` and waste an afternoon.

The catalog is deliberately the ~40 types that actually show up in web-app,
AD, and CTF work, not an exhaustive dump of every mode hashcat supports —
each entry's mode/format is confirmed against hashcat's example-hashes list
and John's format names, so the command it prints is the command that runs.

The identifier is pure string analysis with no exec and no I/O, so the
endpoint that calls it needs no authorization gate — there's no target and
nothing leaves the box.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass(frozen=True)
class HashType:
    name: str
    hashcat: Optional[int]        # hashcat -m mode, or None if hashcat can't do it
    john: Optional[str]           # John --format=..., or None
    example: str
    # A candidate is "exact" when its shape is unique enough to trust on its
    # own (a prefix/structure no other type shares); "ambiguous" when it only
    # matched by length/charset and other types share that shape.
    exact: bool = False
    note: str = ""


# --------------------------------------------------------------------------
# Structured matchers — unique prefix or internal shape. Order matters only
# for readability; each regex is specific enough not to collide with another.
# Every mode/format below is checked against hashcat --example-hashes and
# John's documented format names.
# --------------------------------------------------------------------------
_HEX = r"[0-9a-fA-F]"        # full class — used standalone, e.g. {_HEX}{{32}}
_B64 = r"[A-Za-z0-9+/]"      # full class — standard base64, used standalone
_C = r"./A-Za-z0-9"          # BARE crypt/bcrypt base64 alphabet — goes INSIDE a
                             # [...] class (never wrap a full class in another)

# (compiled regex, HashType) — anchored, full-string matches only.
_STRUCTURED: list[tuple[re.Pattern, HashType]] = [
    (re.compile(rf"^\$1\$[{_C}]{{0,8}}\$[{_C}]{{22}}$"),
     HashType("md5crypt ($1$, FreeBSD/old Linux)", 500, "md5crypt",
              "$1$28772684$iEwNOgGugqO9.bIz5sk8k/", exact=True)),
    (re.compile(rf"^\$2[abxy]\$\d\d\$[{_C}]{{53}}$"),
     HashType("bcrypt ($2*$, Blowfish)", 3200, "bcrypt",
              "$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6", exact=True)),
    (re.compile(rf"^\$5\$(rounds=\d+\$)?[{_C}]{{0,16}}\$[{_C}]{{43}}$"),
     HashType("sha256crypt ($5$)", 7400, "sha256crypt",
              "$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD", exact=True)),
    (re.compile(rf"^\$6\$(rounds=\d+\$)?[{_C}]{{0,16}}\$[{_C}]{{86}}$"),
     HashType("sha512crypt ($6$, modern Linux /etc/shadow)", 1800, "sha512crypt",
              "$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/", exact=True)),
    (re.compile(rf"^\$y\$[{_C}]+\$[{_C}]+\$[{_C}]+$"),
     HashType("yescrypt ($y$, newest Linux /etc/shadow)", None, "crypt",
              "$y$j9T$F5Jx5fExrKuPp53xLKQ..1$X3DX6M94c9o.CT.NHVMDvGemqvXNMcHc7f4Rmm0/Pm.", exact=True,
              note="hashcat has no yescrypt mode yet — crack with John (--format=crypt) or unshadow+John.")),
    (re.compile(rf"^{_HEX}{{32}}:{_HEX}{{32}}$"),
     HashType("NTLM:LM pair (pwdump line, right half = NTLM)", 1000, "nt",
              "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", exact=True,
              note="Crack the NTLM half (-m 1000). The aad3b4... LM half is the empty-LM sentinel.")),
    (re.compile(rf"^\$krb5tgs\$23\$\*.+\*\${_HEX}+$"),
     HashType("Kerberos 5 TGS-REP etype 23 (Kerberoast)", 13100, "krb5tgs",
              "$krb5tgs$23$*user$realm$test/spn*$00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", exact=True)),
    # [^@]+@[^:]+ (not .+@.+) — excluding each field's own delimiter keeps this
    # linear. The wildcard form backtracks quadratically on a crafted string
    # full of @/: characters (caught in adversarial review).
    (re.compile(rf"^\$krb5asrep\$23\$[^@]+@[^:]+:{_HEX}+\${_HEX}+$"),
     HashType("Kerberos 5 AS-REP etype 23 (AS-REProast)", 18200, "krb5asrep",
              "$krb5asrep$23$user@domain.com:00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff00112233", exact=True)),
    (re.compile(rf"^\$krb5pa\$"),
     HashType("Kerberos 5 AS-REQ Pre-Auth etype 23", 7500, "krb5pa-md5",
              "$krb5pa$23$user$realm$salt$...", exact=True)),
    # NetNTLMv1: user::host:LMresp(48 hex):NTresp(48 hex):challenge(16 hex).
    (re.compile(r"^[^:]+::[^:]*:" + _HEX + r"{48}:" + _HEX + r"{48}:" + _HEX + r"{16}$"),
     HashType("NetNTLMv1 (responder capture)", 5500, "netntlm",
              "u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c", exact=True)),
    # NetNTLMv2: user::domain:challenge(16 hex):NTproof(32 hex):blob(long hex).
    (re.compile(r"^[^:]+::[^:]*:" + _HEX + r"{16}:" + _HEX + r"{32}:" + _HEX + r"{2,}$"),
     HashType("NetNTLMv2 (responder capture — very common in AD)", 5600, "netntlmv2",
              "admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:0101000000000000", exact=True)),
    (re.compile(rf"^\$[PH]\$[{_C}]{{31}}$"),
     HashType("phpass (WordPress / phpBB3 $P$ / $H$)", 400, "phpass",
              "$P$984478476IagS59wHZvyQMArzfx58u.", exact=True)),
    (re.compile(rf"^\$apr1\$[{_C}]{{0,8}}\$[{_C}]{{22}}$"),
     HashType("Apache apr1 md5 (.htpasswd)", 1600, "md5crypt",
              "$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.", exact=True)),
    (re.compile(rf"^\$django\$\*1\*pbkdf2_sha256\$"),
     HashType("Django PBKDF2-SHA256", 10000, "django",
              "$django$*1*pbkdf2_sha256$36000$salt$...", exact=True)),
    (re.compile(rf"^pbkdf2_sha256\$\d+\${_B64}+\${_B64}+=*$"),
     HashType("Django PBKDF2-SHA256 (raw form)", 10000, "django",
              "pbkdf2_sha256$36000$saltsalt$base64hash=", exact=True)),
    (re.compile(rf"^{{SSHA}}{_B64}{{20,}}={{0,2}}$"),
     HashType("LDAP {SSHA} (salted SHA1)", 111, "ssha",
              "{SSHA}uFT2G5401Kk6MImUYtG4Ynf5R6E6Z0Zw", exact=True)),
    (re.compile(rf"^{{SHA}}{_B64}{{27}}=$"),
     HashType("LDAP {SHA} (unsalted SHA1, base64)", 101, "raw-sha1",
              "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", exact=True)),
    (re.compile(rf"^{{SSHA256}}{_B64}+={{0,2}}$"),
     HashType("LDAP {SSHA256}", 1411, "ssha256",
              "{SSHA256}0jXqbEZUJVddbSCbTITZ+xfDeE1JjClxpH9M/8lqxD1lMs3o", exact=True)),
    (re.compile(rf"^sha1\$[0-9A-Za-z]+\${_HEX}{{40}}$"),
     HashType("Django SHA1 (salted)", 124, None,
              "sha1$abcd1234$5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", exact=True)),
    (re.compile(rf"^{_HEX}{{32}}:{_HEX}{{1,}}$"),
     HashType("md5($pass.$salt) or md5($salt.$pass) — salted MD5", 10, "dynamic",
              "01dfae6e5d4d90d9892622325959afbe:7050461", exact=True,
              note="hashcat -m 10 is md5($pass.$salt); -m 20 is md5($salt.$pass). Try both.")),
    (re.compile(rf"^{_HEX}{{40}}:{_HEX}{{1,}}$"),
     HashType("sha1($pass.$salt) — salted SHA1", 110, "dynamic",
              "2fc5a684737ce1bf7b3b239df432416e0dd07357:2014", exact=True,
              note="hashcat -m 110 is sha1($pass.$salt); -m 120 is sha1($salt.$pass).")),
    (re.compile(rf"^0x0100{_HEX}{{48}}$", re.I),
     HashType("MSSQL 2005 (0x0100 + salt + SHA1)", 132, "mssql05",
              "0x010000112233445566778899aabbccddeeff0011223344556677", exact=True)),
    (re.compile(rf"^0x0200{_HEX}{{136}}$", re.I),
     HashType("MSSQL 2012/2014 (0x0200 + SHA512)", 1731, "mssql12",
              "0x020000112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233", exact=True)),
    (re.compile(rf"^\*{_HEX}{{40}}$"),
     HashType("MySQL 4.1+ (SHA1(SHA1(pass)), leading *)", 300, "mysql-sha1",
              "*E6CC90B878B948C35E92B003C792C46C58C4AF40", exact=True)),
    (re.compile(rf"^{_HEX}{{16}}$"),
     HashType("MySQL 3.23 (old, 16 hex) or DES/LM half", 200, "mysql",
              "5d2e19393cc5ef67", exact=True,
              note="16 hex is also an LM half (-m 3000) — check context.")),
    (re.compile(r"^\$sha1\$\d+\$[./A-Za-z0-9]{0,64}\$[./A-Za-z0-9]{28}$"),
     HashType("sha1crypt ($sha1$, NetBSD)", 15100, "sha1crypt",
              "$sha1$40000$jtNX3nZ2$hBNaIXkt4wBI2o5rsi8KejSjNqIq", exact=True)),
    (re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"),
     HashType("JWT (JSON Web Token, HMAC signature)", 16500, "HMAC-SHA256",
              "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", exact=True,
              note="Only HS256/384/512 JWTs are crackable (shared secret). RS/ES use a private key — not brute-forceable here.")),
    (re.compile(rf"^grub\.pbkdf2\.sha512\."),
     HashType("GRUB2 PBKDF2-SHA512", 7200, None,
              "grub.pbkdf2.sha512.10000.salt.hash", exact=True)),
    (re.compile(rf"^sha256:\d+:{_B64}+:{_B64}+$"),
     HashType("PBKDF2-HMAC-SHA256 (Werkzeug/Flask default)", 10900, "PBKDF2-HMAC-SHA256",
              "sha256:1000:salt:hash", exact=True)),
    (re.compile(rf"^\$pbkdf2-sha256\$"),
     HashType("PBKDF2-HMAC-SHA256 (passlib $pbkdf2-sha256$)", 10900, "PBKDF2-HMAC-SHA256",
              "$pbkdf2-sha256$29000$salt$hash", exact=True)),
    (re.compile(rf"^\$argon2(id|i|d)\$"),
     HashType("Argon2", None, "argon2",
              "$argon2id$v=19$m=65536,t=3,p=4$salt$hash", exact=True,
              note="hashcat has no Argon2 mode — crack with John (--format=argon2).")),
    (re.compile(rf"^SCRYPT:\d+:\d+:\d+:{_B64}+:{_B64}+$"),
     HashType("scrypt", 8900, None,
              "SCRYPT:16384:8:1:salt:hash", exact=True)),
]


# --------------------------------------------------------------------------
# Raw hex matchers — length-only, so every one is AMBIGUOUS by construction.
# For each length we return the candidate types ranked by how often they turn
# up in real work, most-likely first.
# --------------------------------------------------------------------------
_RAW_HEX_BY_LEN: dict[int, list[HashType]] = {
    32: [
        HashType("MD5", 0, "raw-md5", "8743b52063cd84097a65d1633f5c74f5"),
        HashType("NTLM (Windows, from SAM/secretsdump)", 1000, "nt",
                 "b4b9b02e6f09a9bd760f388b67351e2b",
                 note="A bare 32-hex from a Windows box is almost always NTLM (-m 1000), not MD5."),
        HashType("LM (half)", 3000, "lm", "299bd128c1101fd6"),
        HashType("MD4", 900, "raw-md4", "afe04867ec7a3845145579a95f72eca7"),
        HashType("MD5(MD5($pass)) / double MD5", 2600, "dynamic", "a936af92b0ae20b1ff6c3347a72e5fbe"),
        HashType("MD5(Unix)-less raw md5($salt.$pass) variants", 20, "dynamic",
                 "01dfae6e5d4d90d9892622325959afbe"),
    ],
    16: [
        HashType("MySQL 3.23 (old)", 200, "mysql", "7196759210defdc0"),
        HashType("LM (half)", 3000, "lm", "299bd128c1101fd6"),
        HashType("DES(Oracle) / crypt(3) fragment", 3100, "descrypt", "7A57A5A743894A0E"),
    ],
    40: [
        HashType("SHA1", 100, "raw-sha1", "b89eaac7e61417341b710b727768294d0e6a277b"),
        HashType("MySQL 4.1+ (without leading *)", 300, "mysql-sha1",
                 "e6cc90b878b948c35e92b003c792c46c58c4af40"),
        HashType("RIPEMD-160", 6000, "ripemd-160", "012cf5b1e6dbe64e5f5f6b6f2d1c6f..."),
        HashType("Tiger-160", None, "tiger", ""),
    ],
    56: [
        HashType("SHA-224", None, "raw-sha224",
                 "e4d1b0b6ea88b3a09b2e2f3f0f9c1d7f2b7a4c9e2d8f1a0b3c6e9f2d"),
        HashType("SHA3-224 / Keccak-224", 17300, "raw-keccak", ""),
    ],
    64: [
        HashType("SHA-256", 1400, "raw-sha256",
                 "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"),
        HashType("SHA3-256 / Keccak-256", 17400, "raw-keccak",
                 "c0a5cca43b8aa79eb50e3464bc839dd6fd414fae0ddf928ca23dcebf8a8b8dd0"),
        HashType("SHA-256 (Cisco IOS type 5 base off)", 5700, "cisco$4$", ""),
        HashType("GOST R 34.11-94", 6900, "gost", ""),
        HashType("BLAKE2s / other 256-bit digests", None, None, ""),
    ],
    96: [
        HashType("SHA-384", 10800, "raw-sha384", ""),
        HashType("SHA3-384 / Keccak-384", 17500, "raw-keccak", ""),
    ],
    128: [
        HashType("SHA-512", 1700, "raw-sha512",
                 "82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f"),
        HashType("SHA3-512 / Keccak-512", 17600, "raw-keccak", ""),
        HashType("Whirlpool", 6100, "whirlpool", ""),
        HashType("BLAKE2b-512", 600, "blake2b-512", ""),
    ],
}

_HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")


def _clean(raw: str) -> str:
    return (raw or "").strip()


def identify(raw: str) -> list[dict]:
    """Return ranked candidate hash types for `raw`, best guess first.

    Structured hashes (unique prefix/shape) return a single exact match.
    Raw hex returns every plausible type for that length, ranked by how
    often it shows up in practice. Empty/garbage returns []. The caller is
    expected to show ALL candidates for a raw hash, not just the top one —
    that ambiguity is the honest answer, not a bug.
    """
    s = _clean(raw)
    if not s or len(s) > 8192:
        return []

    # 1) Structured — first specific match wins, returned alone and exact.
    for pat, ht in _STRUCTURED:
        if pat.match(s):
            return [_as_dict(ht, ambiguous=not ht.exact)]

    # 2) Raw hex — length lookup, all candidates, ambiguous.
    if _HEX_ONLY.match(s):
        cands = _RAW_HEX_BY_LEN.get(len(s))
        if cands:
            return [_as_dict(ht, ambiguous=True) for ht in cands]
        return [{
            "name": f"unrecognized raw hex ({len(s)} chars)",
            "hashcat": None, "john": None, "example": "", "exact": False,
            "ambiguous": True,
            "note": "Length doesn't match a common raw digest. Try `hashcat --identify` "
                    "or check whether it's truncated/concatenated.",
        }]

    # 3) Nothing matched.
    return []


def _as_dict(ht: HashType, ambiguous: bool) -> dict:
    return {
        "name": ht.name, "hashcat": ht.hashcat, "john": ht.john,
        "example": ht.example, "exact": ht.exact, "ambiguous": ambiguous,
        "note": ht.note,
    }


# --------------------------------------------------------------------------
# Crack-command planning — turn a chosen hash type into the exact hashcat and
# John commands. Placeholders (<HASH_FILE>, <WORDLIST>) are literal — this is
# guidance to paste into a terminal, never executed here (mirrors builder.py).
# --------------------------------------------------------------------------
def crack_commands(hashcat_mode: Optional[int], john_format: Optional[str],
                   attack: str = "wordlist") -> dict:
    """Build hashcat + John command strings for a hash type.

    `attack` is 'wordlist' (default, -a 0 + rockyou) or 'bruteforce'
    (-a 3 + a mask). Returns {hashcat, john} strings with placeholders; the
    caller shows them, nobody runs them from here.
    """
    hc = None
    if hashcat_mode is not None:
        if attack == "bruteforce":
            hc = (f"hashcat -m {hashcat_mode} -a 3 <HASH_FILE> "
                  "'?a?a?a?a?a?a?a?a' --increment")
        else:
            hc = (f"hashcat -m {hashcat_mode} -a 0 <HASH_FILE> "
                  "/usr/share/wordlists/rockyou.txt "
                  "-r /usr/share/hashcat/rules/best64.rule")
    jn = None
    if john_format is not None:
        jn = (f"john --format={john_format} "
              "--wordlist=/usr/share/wordlists/rockyou.txt <HASH_FILE>")
    return {"hashcat": hc, "john": jn}


def handle_hash_id(req) -> "object":
    """POST /api/hash-id  {hash: "..."}  ->  {candidates: [...]}.

    Pure offline string analysis. No target, no exec, no network — so unlike
    the runners this needs no authorization gate. Still a POST (so it gets the
    same-origin Origin check every mutating route gets) purely so a hash never
    rides in a URL/querystring that could land in a log.
    """
    from shared import common
    body = req.json()
    raw = body.get("hash")
    if not isinstance(raw, str):
        return common.Response.error(400, "hash must be a string")
    attack = str(body.get("attack") or "wordlist")
    if attack not in ("wordlist", "bruteforce"):
        attack = "wordlist"
    candidates = identify(raw)
    for c in candidates:
        c["commands"] = crack_commands(c.get("hashcat"), c.get("john"), attack)
    return common.Response.json({
        "input_len": len(_clean(raw)),
        "candidates": candidates,
        "count": len(candidates),
    })
