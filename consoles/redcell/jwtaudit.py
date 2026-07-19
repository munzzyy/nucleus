"""JWT weakness analyzer — pure offline string/claim analysis, zero network.

Decodes header + claims through `keyverify.decode_jwt` (the same base64url
decoder everywhere else a JWT gets read in this app, so a token's fields
never come from two independently-written decoders) and then flags the
handful of JWT bugs that actually get exploited in the wild — the same short
list PortSwigger's JWT-attacks material and OWASP's testing guide both walk
through:

  * alg:none                      — signature check bypassed entirely
  * alg embeds a key-fetch URL     — jku / x5u / jwk headers let a client
                                     point the verifier at an attacker-hosted
                                     key
  * kid parameter                 — classic path-traversal / SQLi / key-
                                     confusion injection surface
  * HS*-signed token               — algorithm-confusion risk if the same
                                     server also verifies RS*/ES* tokens
  * exp/nbf hygiene                — missing, expired, or not-yet-valid
  * missing iss/aud/sub            — token can't be scoped to who it's for

For an HS256/384/512 token it also builds the exact hashcat (mode 16500,
which cracks the JWT's HMAC directly — no hash file needed) and John command
to try cracking the signing secret offline. Same stance as keyverify.py:
build the command, never run it — the actual cracking is CPU work Cole runs
on his own box, not something a web handler should spawn a subprocess for.
"""

from __future__ import annotations

import shlex
import time

from shared import common
from consoles.redcell import keyverify

_HS_ALGS = {"hs256", "hs384", "hs512"}
_RS_ALGS = {"rs256", "rs384", "rs512", "ps256", "ps384", "ps512", "es256", "es384", "es512"}
_HASHCAT_MODE = 16500  # hashcat's dedicated JWT mode — cracks HS256/384/512 signatures directly

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _f(sev: str, title: str, detail: str) -> dict:
    return {"severity": sev, "title": title, "detail": detail}


def _alg_findings(header: dict) -> tuple[list[dict], str]:
    alg_raw = header.get("alg")
    alg = str(alg_raw or "").strip()
    alg_low = alg.lower()
    findings = []

    if alg_low in ("none", ""):
        findings.append(_f("critical",
            "alg:none — signature verification can be bypassed entirely",
            "A verifier that honors 'none' accepts ANY payload with an empty signature segment. "
            "Try re-encoding the token with alg set to \"none\" (also try the case variants "
            "\"None\"/\"NONE\"/\"nOnE\" — some libraries only blocklist the exact lowercase string) "
            "and a trailing empty signature (token ending in a bare '.')."))
    elif alg_low in _HS_ALGS:
        findings.append(_f("medium",
            f"HMAC algorithm ({alg}) — algorithm-confusion risk if the server also verifies RS*/ES* tokens",
            "If this server ALSO accepts RS256/ES256 tokens (check for a JWKS endpoint, a .well-known "
            "path, or a public key embedded anywhere else it responds), a library that trusts the "
            "client-supplied 'alg' can be tricked into verifying an HS256-forged token using that RSA/EC "
            "PUBLIC key as the HMAC secret. Confirm the public key is reachable before attempting this."))
    elif alg_low in _RS_ALGS:
        findings.append(_f("info", f"Asymmetric algorithm ({alg})",
            "Signed with a private key you don't have — forging a valid signature needs the key itself, "
            "not a wordlist. The algorithm-confusion angle (above, in reverse) is the usual way in: check "
            "whether the server would ALSO accept an HS256 token signed with its own public key."))
    else:
        findings.append(_f("low", f"Unrecognized or unusual 'alg' value: {alg or '(missing)'}",
            "Not a standard JWS algorithm name — worth confirming the verifying library actually "
            "recognizes it rather than silently falling back to an insecure default."))

    return findings, alg_low


def _header_injection_findings(header: dict) -> list[dict]:
    findings = []
    if "jku" in header:
        findings.append(_f("high", "'jku' header present (JWK Set URL)",
            f"jku={header.get('jku')!r} — if the verifier fetches the key set from this URL without an "
            "allowlist, hosting your own JWKS and pointing jku at it lets you forge a validly-signed token."))
    if "x5u" in header:
        findings.append(_f("high", "'x5u' header present (X.509 URL)",
            f"x5u={header.get('x5u')!r} — same class of bug as jku: if the verifier fetches the cert from "
            "here unchecked, hosting your own cert (or self-signed chain) can forge a trusted signature."))
    if "jwk" in header:
        findings.append(_f("high", "'jwk' header present (embedded public key)",
            "Some verifiers trust whatever public key is embedded in the token itself instead of checking "
            "it's the expected one — re-sign with your own keypair and embed your public key here."))
    if "kid" in header:
        findings.append(_f("info", "'kid' header present (key ID)",
            f"kid={header.get('kid')!r} — classic injection surface if the server looks the key up by this "
            "value from a file or database: try path traversal (../../dev/null paired with alg confusion), "
            "SQL injection, or pointing it at a predictable/attacker-known key."))
    return findings


def _claim_findings(payload: dict, now: float) -> list[dict]:
    findings = []
    exp = payload.get("exp")
    nbf = payload.get("nbf")

    if exp is None:
        findings.append(_f("medium", "No 'exp' claim — token never expires",
            "Add an exp claim; a token with no expiry is a permanent bearer credential once it leaks."))
    else:
        try:
            exp_f = float(exp)
        except (TypeError, ValueError):
            findings.append(_f("low", "'exp' claim is not a number", f"exp={exp!r} — most JWT libraries "
                                                                      "expect a NumericDate (Unix epoch seconds)."))
        else:
            if exp_f < now:
                findings.append(_f("high", "Token is expired",
                    f"exp was {int(now - exp_f)}s ago — a server that still accepts this token isn't "
                    "checking expiry at all."))

    if nbf is not None:
        try:
            nbf_f = float(nbf)
        except (TypeError, ValueError):
            findings.append(_f("low", "'nbf' claim is not a number", f"nbf={nbf!r}"))
        else:
            if nbf_f > now:
                findings.append(_f("info", "Token not valid yet ('nbf' is in the future)",
                    f"nbf is {int(nbf_f - now)}s from now."))

    if not any(k in payload for k in ("iss", "aud", "sub")):
        findings.append(_f("low", "No 'iss', 'aud', or 'sub' claim",
            "Nothing in the payload scopes who issued this token or who it's for — a token like this is "
            "hard to restrict to one service, which makes it more valuable if it leaks."))

    return findings


def _crack_commands(token: str) -> dict:
    """Build (never run) the hashcat + john commands to crack an HS*-signed
    token's secret offline. The token is one shlex-quoted argv element —
    same paste-safety stance as keyverify.build_command: this string came off
    a page you don't trust, so it must land as one inert literal, never a
    shell fragment."""
    hc_argv = ["hashcat", "-a", "0", "-m", str(_HASHCAT_MODE), token,
               "/usr/share/wordlists/rockyou.txt"]
    hc_ruled_argv = hc_argv + ["-r", "/usr/share/hashcat/rules/best64.rule"]
    john_argv = ["john", "--format=HMAC-SHA256",
                 "--wordlist=/usr/share/wordlists/rockyou.txt", "<JWT_FILE>"]
    return {
        "hashcat": " ".join(shlex.quote(t) for t in hc_ruled_argv),
        "hashcat_plain": " ".join(shlex.quote(t) for t in hc_argv),
        "john": " ".join(shlex.quote(t) for t in john_argv),
        "note": "hashcat -m 16500 takes the JWT directly on the command line (no hash file needed) and "
                "cracks the HS256/384/512 HMAC secret. John needs the raw token saved to a file first, one "
                "per line — <JWT_FILE> is a placeholder for that path.",
    }


def analyze_jwt(token: str) -> dict:
    """Pure function, no I/O. Returns {"ok": False, "error": ...} for anything
    that doesn't parse as a JWT, else the decoded header/payload plus every
    weakness finding, sorted worst-first."""
    decoded = keyverify.decode_jwt(token)
    if decoded is None:
        return {"ok": False,
                "error": "not a well-formed JWT (expected base64url header.payload.signature)"}

    header, payload = decoded["header"], decoded["payload"]
    now = time.time()

    findings, alg_low = _alg_findings(header)
    findings += _header_injection_findings(header)
    findings += _claim_findings(payload, now)
    findings.sort(key=lambda f: _SEV_RANK.get(f["severity"], 9))

    crack = _crack_commands(token) if alg_low in _HS_ALGS else None

    return {
        "ok": True,
        "header": header,
        "payload": payload,
        "alg": header.get("alg"),
        "findings": findings,
        "counts": {sev: sum(1 for f in findings if f["severity"] == sev)
                   for sev in ("critical", "high", "medium", "low", "info")},
        "crack": crack,
    }


_MAX_TOKEN_LEN = 8192  # generous for a real JWT; a refusal past this is a sanity cap, not a real limit


def handle_jwt_audit(req) -> "common.Response":
    """POST /api/jwt-audit  {token: "..."}  ->  decoded claims + weakness findings.

    Pure offline analysis — same "no authorization gate" reasoning as
    hashtools.handle_hash_id: nothing here ever touches a network or a
    target, so there's nothing to authorize. Still POST-only so a token
    never rides in a URL/querystring where it could land in an access log.
    """
    body = req.json()
    token = body.get("token")
    if not isinstance(token, str) or not token:
        return common.Response.error(400, "token must be a non-empty string")
    if len(token) > _MAX_TOKEN_LEN:
        return common.Response.error(400, "token too long")
    return common.Response.json(analyze_jwt(token))
