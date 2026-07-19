"""Secret / API-key leak scanner — find credentials exposed in a site's own
client-side code. Point it at a URL; it pulls the page HTML, every inline
<script>, the site's own external JS bundles, any source maps those bundles
reference, and (in deep mode) commonly-exposed config files and the site's
Wayback history — then scans all of it for the credential shapes that get
shipped to the browser by accident: cloud keys, payment keys, source-control
tokens, webhook URLs, private keys, JWTs, and high-entropy secret assignments.

Why this exists: the #1 real-world web leak isn't a clever exploit, it's a
secret key hardcoded into a front-end bundle and served to every visitor. A
scan of the actual delivered HTML/JS catches exactly that.

What it is careful about:
  * SCOPE. It fetches the page, then only the JS hosted on the SAME site
    (same host, or a subdomain of the same *registrable* domain — the apex
    check now understands multi-tenant suffixes like co.uk / github.io /
    s3.amazonaws.com so a scan of one tenant can't wander into another's
    bundles). It does not follow third-party CDNs. Every fetch rides
    `common.fetch`, the same SSRF-guarded, connect-pinned, public-only path
    recon uses, so a page that links an internal/metadata address can't turn
    this into an SSRF probe.
  * COMPLETENESS OVER A CAP. Every fetched script is scanned in full (bounded
    only by a total-byte CPU budget); the findings cap only trims what's
    RETURNED for display, and it trims after a severity sort so a live
    critical is never the thing dropped. (The old code aborted the whole scan
    loop at the cap — a real secret in a later file could vanish silently.
    That's fixed: findings are capped per-rule-per-blob so one noisy pattern
    can't crowd out the rest, and scanning never stops early.)
  * FALSE POSITIVES. Publishable keys that are MEANT to be public (Stripe
    pk_live_, Google/Firebase browser AIza keys) are reported as low/info with
    a note, not screamed about. Placeholder/example values are filtered, the
    generic assignment rule is entropy-gated, JWT matches must actually decode
    to valid claims, and unlabeled high-entropy strings go through a decode-
    and-inspect gate before they're ever reported (low severity only).
  * THE SECRETS THEMSELVES. Findings go back to the browser (loopback, your
    screen) with a masked preview by default; the on-disk audit log records
    only counts and rule names, never the matched secret values.
  * VERIFICATION IS OFFERED, NEVER FIRED. Each finding carries the exact
    safe, read-only command to confirm the key is live against its provider —
    built for the operator to run, never auto-run (see keyverify.py), because
    that call leaves the client's site and hits a third party.

Gated like every other redcell action: authorized:true, public scope unless
lab. Passive — it only GETs pages/files the site already serves to anyone.
"""

from __future__ import annotations

import base64
import binascii
import concurrent.futures
import http.client
import json
import math
import re
from datetime import datetime, timezone
from urllib.parse import quote, urljoin, urlparse

from shared import common
from consoles.redcell import runners, webscan, keyverify

_FETCH_ERRORS = (ValueError, OSError, http.client.HTTPException)

MAX_SCRIPTS = 80            # cap external JS fetches per scan (byte budget is the real valve)
MAX_SCRIPT_BYTES = 2_000_000
MAX_SOURCEMAPS = 15         # cap .map fetches per scan
MAX_FINDINGS = 600         # DISPLAY cap only — trims the returned list after sorting,
                            # never stops the scan (see module docstring)
_PER_RULE_PER_BLOB = 30     # one noisy rule can't crowd out others within one blob
PER_FETCH_TIMEOUT = 8.0
_CTX = 40                    # context chars kept around each match
# Hard cap on total bytes handed to the regex engine across one whole scan
# (page + inline + every external script + maps). Bounded so a single scan
# stays well under a few seconds even against a hostile/huge target.
_TOTAL_SCAN_BUDGET = 12_000_000

# Deep-mode surface (opt-in — noisier scanner signature, more requests).
MAX_DEEP_PROBES = 45
MAX_WAYBACK = 25


# --------------------------------------------------------------------------
# Rule catalog. Each rule: a compiled regex, a severity, a confidence, and
# `public_ok` (the shape is legitimately shipped to browsers — a note, not an
# alarm). Patterns follow the well-known gitleaks/SecretFinder shapes.
#
# `keywords` is a cheap pre-filter: a rule's regex only runs if at least one of
# its keyword literals is present in the (lower-cased) text. A C-level substring
# scan is orders of magnitude faster than a regex pass, so on real code — where
# almost none of these markers appear — nearly every pattern is skipped. This
# is the standard secret-scanner optimization (gitleaks does the same). Use a
# DISTINCTIVE literal (a key prefix), not a 2-letter fragment like "sk" that
# appears in every other word — a non-distinctive keyword just disables the
# speedup without any correctness effect. keywords=None means always run.
#
# `placeholder_check` runs the captured value through _PLACEHOLDER before
# reporting — used on free-form-value rules (basic-auth, bearer) so a doc
# example like user:password@host isn't reported as a real leak.
# `context_any` (lowercased literals) requires one of them to appear somewhere
# in the blob for a structural-shape-only rule (Discord) to fire at all — the
# precision valve for shapes too generic to stand alone.
# --------------------------------------------------------------------------
class Rule:
    __slots__ = ("name", "rx", "severity", "confidence", "public_ok", "note",
                 "group", "keywords", "placeholder_check", "context_any")

    def __init__(self, name, pattern, severity, confidence="high",
                 public_ok=False, note="", group=0, flags=0, keywords=None,
                 placeholder_check=False, context_any=None):
        self.name = name
        self.rx = re.compile(pattern, flags)
        self.severity = severity
        self.confidence = confidence
        self.public_ok = public_ok
        self.note = note
        self.group = group     # capture group holding the secret value
        self.keywords = keywords
        self.placeholder_check = placeholder_check
        self.context_any = context_any


RULES: list[Rule] = [
    # ---- cloud ----
    Rule("AWS Access Key ID", r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16})\b",
         "critical", group=1, keywords=("akia", "asia", "agpa", "aida", "aroa", "anpa"),
         note="An AKIA/ASIA key ID. Confirm the matching secret isn't nearby — the pair grants API access."),
    # Secret half — matched by its OWN key name, not by a nearby literal "aws":
    # Amplify/Cognito/S3-upload configs ship it as secretAccessKey with no "aws"
    # anywhere. This is the half that actually matters.
    Rule("AWS Secret Access Key",
         r"(?i)(?:aws.{0,20}?(?:secret|sk)|secret[_-]?access[_-]?key|secretaccesskey)"
         r"['\"]?\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
         "critical", confidence="medium", group=1, keywords=("secret", "aws")),
    Rule("Google API key", r"\b(AIza[0-9A-Za-z\-_]{35})\b", "medium", public_ok=True, keywords=("aiza",),
         note="Google/Firebase BROWSER keys are often intentionally public — but they must be "
              "referrer/API-restricted server-side. Verify the restriction; an unrestricted one is billable abuse."),
    Rule("Google OAuth access token", r"\b(ya29\.[0-9A-Za-z\-_]{20,})", "high", group=1, keywords=("ya29.",)),
    Rule("GCP service-account private key block", r'("type"\s*:\s*"service_account")',
         "critical", keywords=("service_account",),
         note="A service-account JSON blob in client code is a full server credential leak — the PEM "
              "private_key is usually in the same object (see the Private key block finding).", group=1),
    Rule("Firebase Cloud Messaging legacy server key",
         r"\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})\b", "critical", group=1, keywords=("aaaa",)),
    Rule("Azure AD client secret",
         r"(?:^|[\\'\"`\s>=:(,])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\'\"`\s<),])",
         "critical", confidence="medium", group=1, keywords=("q~",)),
    # ---- payments ----
    Rule("Stripe secret key (LIVE)", r"\b(sk_live_[0-9a-zA-Z]{24,})\b", "critical", group=1, keywords=("sk_live_",)),
    Rule("Stripe restricted key (LIVE)", r"\b(rk_live_[0-9a-zA-Z]{24,})\b", "high", group=1, keywords=("rk_live_",)),
    Rule("Stripe publishable key (LIVE)", r"\b(pk_live_[0-9a-zA-Z]{24,})\b", "info", public_ok=True, keywords=("pk_live_",),
         note="Publishable keys are designed to be public in the browser — expected, not a leak. Noted for completeness."),
    Rule("Stripe test key", r"\b((?:sk|pk|rk)_test_[0-9a-zA-Z]{24,})\b", "low", public_ok=True, keywords=("_test_",),
         note="Test-mode key — no real money/data, but shouldn't ship to production."),
    Rule("Square access token", r"\b(sq0(?:atp|csp|idp)-[0-9A-Za-z\-_]{22,43})\b", "high", group=1, keywords=("sq0",)),
    Rule("PayPal/Braintree access token", r"\b(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})\b",
         "critical", group=1, keywords=("access_token$production$",)),
    Rule("Shopify access token", r"\b(shpat_[a-fA-F0-9]{32})\b", "critical", group=1, keywords=("shpat_",)),
    Rule("Shopify custom-app token", r"\b(shpca_[a-fA-F0-9]{32})\b", "critical", group=1, keywords=("shpca_",)),
    # ---- source control / package ----
    Rule("GitHub token", r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b", "critical", group=1,
         keywords=("ghp_", "gho_", "ghu_", "ghs_", "ghr_")),
    Rule("GitHub fine-grained PAT", r"\b(github_pat_[A-Za-z0-9_]{82})\b", "critical", group=1, keywords=("github_pat_",)),
    Rule("GitLab personal access token", r"\b(glpat-[A-Za-z0-9\-_]{20})\b", "critical", group=1, keywords=("glpat-",)),
    Rule("npm access token", r"\b(npm_[A-Za-z0-9]{36})\b", "high", group=1, keywords=("npm_",)),
    Rule("PyPI upload token", r"\b(pypi-AgEIcHlwaS[A-Za-z0-9\-_]{50,})\b", "critical", group=1, keywords=("pypi-",)),
    Rule("Terraform Cloud/Enterprise API token",
         r"\b([a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70})\b", "critical", group=1, keywords=(".atlasv1.",)),
    Rule("HashiCorp Vault service token", r"\b(hvs\.[A-Za-z0-9_-]{90,120})\b", "critical", group=1, keywords=("hvs.",)),
    # ---- comms / email ----
    Rule("Slack token", r"\b(xox[baprs]-[A-Za-z0-9-]{10,64})\b", "high", group=1, keywords=("xox",)),
    Rule("Slack webhook URL", r"(https://hooks\.slack\.com/services/[A-Za-z0-9+/_-]{40,})",
         "high", group=1, keywords=("hooks.slack.com",)),
    Rule("Discord bot token",
         r"\b([MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38})\b",
         "critical", confidence="medium", group=1, keywords=("discord",), context_any=("discord", "bot"),
         note="Structural token shape confirmed near a discord/bot reference — verify before treating as certain."),
    Rule("Telegram bot token", r"\b([0-9]{5,16}:AA[A-Za-z0-9_-]{33})\b", "critical", group=1, keywords=(":aa",)),
    Rule("SendGrid API key", r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b", "critical", group=1, keywords=("sg.",)),
    Rule("Mailgun API key", r"\b(key-[0-9a-f]{32})\b", "high", confidence="medium", group=1, keywords=("key-",),
         note="Mailgun keys are hex; a key- prefix on non-hex is something else."),
    Rule("Mailchimp API key", r"\b([0-9a-f]{32}-us[0-9]{1,2})\b", "high", confidence="medium", group=1, keywords=("-us",)),
    Rule("Twilio API Key SID", r"\b(SK[0-9a-fA-F]{32})\b", "high", confidence="medium", group=1, keywords=("sk",),
         note="SK+32hex is the Twilio API Key SID shape — confirm it's Twilio (it needs the paired auth token to use)."),
    Rule("Twilio Account SID", r"\b(AC[0-9a-f]{32})\b", "low", confidence="medium", public_ok=True, keywords=("ac",),
         note="An Account SID is an identifier, not a secret on its own — a finding only paired with the auth token."),
    # ---- infra / observability ----
    Rule("DigitalOcean access token", r"\b(doo_v1_[a-f0-9]{64})\b", "critical", group=1, keywords=("doo_v1_",)),
    Rule("Cloudflare API token",
         r"(?i)cloudflare(?:[ \t\w.-]{0,20})['\"]?\s*[:=]\s*['\"]?([a-z0-9_-]{40})\b",
         "critical", confidence="medium", group=1, keywords=("cloudflare",)),
    Rule("Heroku API key",
         r"(?i)heroku(?:[ \t\w.-]{0,20})['\"]?\s*[:=]\s*['\"]?"
         r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
         "critical", confidence="medium", group=1, keywords=("heroku",)),
    Rule("Datadog API key",
         r"(?i)datadog(?:[ \t\w.-]{0,20})['\"]?\s*[:=]\s*['\"]?([a-z0-9]{32})\b",
         "high", confidence="medium", group=1, keywords=("datadog",)),
    Rule("New Relic user API key", r"\b(NRAK-[A-Z0-9]{27})\b", "high", group=1, keywords=("nrak-",)),
    Rule("Grafana service-account token", r"\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})\b",
         "critical", group=1, keywords=("glsa_",)),
    Rule("Grafana legacy API key", r"\b(eyJrIjoi[A-Za-z0-9]{60,400}={0,3})\b",
         "high", confidence="medium", group=1, keywords=("eyjrijoi",)),
    # ---- productivity / SaaS ----
    Rule("Notion integration token (current)", r"\b(ntn_[A-Za-z0-9]{40,50})\b",
         "critical", group=1, keywords=("ntn_",)),
    Rule("Notion integration token (legacy)", r"\b(secret_[A-Za-z0-9]{43})\b",
         "critical", group=1, keywords=("secret_",)),
    Rule("Postman API key", r"\b(PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34})\b", "high", group=1, keywords=("pmak-",)),
    Rule("Airtable personal access token", r"\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b",
         "critical", group=1, keywords=("pat",)),
    Rule("Algolia Admin API key",
         r"(?i)algolia(?:[ \t\w.-]{0,20})['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})\b",
         "high", confidence="medium", group=1, keywords=("algolia",)),
    # ---- AI providers ----
    Rule("OpenAI API key", r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})\b", "critical", confidence="medium", group=1, keywords=("sk-",),
         note="OpenAI 'sk-' key. Verify it isn't a Stripe 'sk_' (underscore) false hit — this rule requires the hyphen form."),
    Rule("Anthropic API key", r"\b(sk-ant-[A-Za-z0-9\-_]{24,})\b", "critical", group=1, keywords=("sk-ant-",)),
    # ---- generic / structural ----
    Rule("Database connection string with inline credentials",
         r"\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s\"'/@]{1,64}:[^@\s\"'/]{1,64}@[A-Za-z0-9.\-]+)",
         "critical", group=1, keywords=("://",), placeholder_check=True,
         note="A database URL with an inline password shipped to the browser — the password is right there in the string."),
    Rule("Private key block",
         r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)",
         "critical", group=1, keywords=("private key",)),
    Rule("JSON Web Token (JWT)",
         r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b",
         "medium", confidence="medium", group=1, keywords=("eyj",),
         note="A JWT shipped in code may be a leaked session/service token — the decoded claims are attached."),
    Rule("Basic-auth credentials in URL",
         r"\b(https?://[^/\s:@\"']{1,64}:[^/\s:@\"']{1,64}@[A-Za-z0-9.-]+)",
         "high", group=1, keywords=("://",), placeholder_check=True),
    Rule("Authorization: Bearer header value",
         r"(?i)authorization['\"]?\s*[:=]\s*['\"]?bearer\s+([A-Za-z0-9_\-\.=]{20,})",
         "high", confidence="medium", group=1, keywords=("bearer",), placeholder_check=True),
]

# Keys that gate the entropy-checked generic assignment rule — if none of these
# literals appear, the generic pattern (the most expensive one) is skipped.
_GENERIC_KEYWORDS = ("api", "key", "secret", "passwd", "password", "token", "auth", "private", "session", "access")

# The noisy one, handled separately so it can be entropy-gated: a
# key/secret/token assignment with a quoted value. The `['"]?` before the
# `[:=]` is what makes JSON work — in `"apiKey":"..."` the char after the key
# is the closing quote, not the colon (the audit's P0 #3). The three-word
# compounds (secret[_-]?access[_-]?key etc.) close the gap where a literal word
# sits between the recognized token and the colon (audit P0 #6).
_GENERIC_ASSIGN = re.compile(
    r"""(?ix)
    (?P<key>(?:api[_-]?key|apikey|secret[_-]?access[_-]?key|secretaccesskey|
             api[_-]?secret[_-]?(?:key|token)|client[_-]?secret|client[_-]?access[_-]?token|
             secret[_-]?key|secret|passwd|password|access[_-]?token|auth[_-]?token|
             private[_-]?key|session[_-]?key|encryption[_-]?key))
    ['"]?\s*[:=]\s*
    ['"](?P<val>[A-Za-z0-9_\-+/=\.]{16,80})['"]
    """
)

# Secrets riding a URL query string — `?api_key=...` / `&token=...`. The value
# is unquoted here, so the quoted generic rule misses it (audit-adjacent gap
# the benchmark caught). Entropy-gated the same way.
_QUERY_SECRET = re.compile(
    r"""(?ix)
    [?&](?P<key>api[_-]?key|apikey|access[_-]?token|auth[_-]?token|api[_-]?secret|
         client[_-]?secret|session[_-]?key|token|secret|key|password|passwd)
    =(?P<val>[A-Za-z0-9._\-+/%]{16,120})
    """
)

# Unlabeled high-entropy strings — a real secret assigned to an innocuous var
# name (`const t="Zx9Kd7..."`) has no key-name to key off. Reported ONLY at low
# severity and ONLY after passing every gate in _looks_like_bare_secret, because
# this is the FP-prone frontier: most high-entropy strings are hashes/ids/blobs.
_QUOTED_TOKEN = re.compile(r"""['"]([A-Za-z0-9_\-+/=]{24,64})['"]""")

# Values that look secret-shaped but are obviously placeholders/examples.
_PLACEHOLDER = re.compile(
    r"(?i)(your[_-]?|example|placeholder|changeme|xxxx|\.\.\.|<[a-z]|test[_-]?key|"
    r"sample|dummy|redacted|insert[_-]?|enter[_-]?|my[_-]?secret|todo|foobar|1234567)")

# Doc-example credential words — a password that IS one of these is a placeholder.
_CRED_PLACEHOLDER = re.compile(r"(?i)^(pass|passwd|password|secret|changeme|admin|test|foo|bar|hunter2|123+)$")


def _is_placeholder_cred(value: str) -> bool:
    """Placeholder gate for URL-credential rules (basic-auth, DB URLs). Checks
    the PASSWORD portion only — never the hostname, so a real credential to a
    host that happens to contain 'example' isn't wrongly suppressed, while a
    textbook user:password@host doc example still is. Non-URL values (a bare
    Bearer token) fall back to a whole-value placeholder check."""
    m = re.search(r"://[^/@\s]*?:([^/@\s]+)@", value)
    if m:
        password = m.group(1)
        return bool(_PLACEHOLDER.search(password)) or _CRED_PLACEHOLDER.match(password) is not None
    return bool(_PLACEHOLDER.search(value))

# Shapes that are high-entropy but NOT credentials — excluded from the bare pass.
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_ALL_HEX = re.compile(r"^[0-9a-f]+$", re.I)         # md5/sha1/sha256/git object ids
_SRI_CTX = re.compile(r"(?i)(integrity|sha256-|sha384-|sha512-)")


def _entropy(s: str) -> float:
    """Shannon entropy in bits/char — high-entropy strings look like real
    secrets, low-entropy ones look like words/placeholders."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((k / n) * math.log2(k / n) for k in counts.values())


def _mostly_printable_text(raw: bytes) -> bool:
    """True if `raw` decodes to mostly printable ASCII with spaces/words — the
    tell that a base64 blob is encoded TEXT (a message, JSON, HTML), not a
    packed binary secret. Used to drop base64-of-text from the bare pass."""
    if not raw:
        return False
    try:
        txt = raw.decode("ascii")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for c in txt if 32 <= ord(c) < 127)
    return printable / len(txt) > 0.9 and (" " in txt or txt.isalnum())


def _looks_like_bare_secret(val: str, before: str) -> bool:
    """Hard gate for the unlabeled-high-entropy pass. Must have real mixed
    entropy AND not match any of the common non-secret high-entropy shapes."""
    if len(val) < 24 or _entropy(val) < 4.0:
        return False
    if _PLACEHOLDER.search(val):
        return False
    has_lower = any(c.islower() for c in val)
    has_upper = any(c.isupper() for c in val)
    has_digit = any(c.isdigit() for c in val)
    # Require mixed case + a digit: rules out hex hashes (single-case), all-caps
    # constants, and lowercase base64 English words in one cheap test.
    if not (has_lower and has_upper and has_digit):
        return False
    if _UUID.match(val) or _ALL_HEX.match(val):
        return False
    if _SRI_CTX.search(before):                 # subresource-integrity digest, not a key
        return False
    # base64-decode-and-inspect: if it cleanly decodes to readable text, it's
    # encoded content, not a packed secret.
    if len(val) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", val):
        try:
            if _mostly_printable_text(base64.b64decode(val, validate=True)):
                return False
        except (binascii.Error, ValueError):
            pass
    return True


def _mask(secret: str) -> str:
    """first4…last4, so a finding is identifiable without fully re-exposing it."""
    s = secret.strip()
    if len(s) <= 12:
        return s[0] + "…" + s[-1] if len(s) > 2 else "…"
    return f"{s[:4]}…{s[-4:]}  ({len(s)} chars)"


def _snippet(text: str, start: int, end: int) -> str:
    a = max(0, start - _CTX)
    b = min(len(text), end + _CTX)
    frag = text[a:b].replace("\n", " ").replace("\r", " ")
    return ("…" if a > 0 else "") + frag + ("…" if b < len(text) else "")


def _finding(rule_name, severity, confidence, public_ok, note, secret, source, text, start, end):
    return {
        "rule": rule_name, "severity": severity, "confidence": confidence,
        "public_ok": public_ok, "note": note,
        "match": secret, "masked": _mask(secret),
        "source": source, "snippet": _snippet(text, start, end),
        "entropy": round(_entropy(secret), 2),
    }


def scan_text(text: str, source: str) -> list[dict]:
    """Run every rule (plus the generic, query-string, and unlabeled-entropy
    passes) over one blob. A rule's regex only runs if one of its keyword
    literals is present (a fast substring pre-filter). Findings are capped
    PER RULE (not globally) so one noisy pattern in this blob can't crowd out
    the others — the whole-scan display cap lives in analyze(), after sorting."""
    if not text:
        return []
    low = text.lower()
    findings: list[dict] = []

    for rule in RULES:
        if rule.keywords and not any(k in low for k in rule.keywords):
            continue
        if rule.context_any and not any(k in low for k in rule.context_any):
            continue
        hits = 0
        for m in rule.rx.finditer(text):
            secret = m.group(rule.group) if rule.group else m.group(0)
            if rule.placeholder_check and _is_placeholder_cred(secret):
                continue
            # JWT precision gate: it must actually decode to valid claims, else
            # it's a base64 lookalike, not a token.
            if rule.name.startswith("JSON Web Token") and keyverify.decode_jwt(secret) is None:
                continue
            findings.append(_finding(rule.name, rule.severity, rule.confidence,
                                     rule.public_ok, rule.note, secret, source, text, m.start(), m.end()))
            hits += 1
            if hits >= _PER_RULE_PER_BLOB:
                break

    # Unlabeled high-entropy strings — runs BEFORE the key-name gate, because a
    # secret assigned to an innocuous var (`const t="..."`) has no key-name to
    # gate on. Low severity, heavily gated by _looks_like_bare_secret.
    hits = 0
    seen_vals = {f["match"] for f in findings}
    for m in _QUOTED_TOKEN.finditer(text):
        val = m.group(1)
        if val in seen_vals:
            continue
        before = text[max(0, m.start() - 20):m.start()]
        if not _looks_like_bare_secret(val, before):
            continue
        seen_vals.add(val)
        f = _finding("High-entropy string (unlabeled)", "low", "low", False,
                     "A high-entropy value with no key-name context — could be a token or an opaque id; worth a look.",
                     val, source, text, m.start(1), m.end(1))
        findings.append(f)
        hits += 1
        if hits >= _PER_RULE_PER_BLOB:
            break

    # The name-keyed passes (generic assignment, URL query params) only make
    # sense when a key-name literal is present — gate them on it for speed.
    if not any(k in low for k in _GENERIC_KEYWORDS):
        return findings

    hits = 0
    for m in _GENERIC_ASSIGN.finditer(text):
        val = m.group("val")
        if _PLACEHOLDER.search(val) or _entropy(val) < 3.0 or len(set(val)) < 8:
            continue
        f = _finding(f"Hardcoded {m.group('key').lower()} assignment", "medium", "low",
                     False, "Generic high-entropy secret assignment — verify it's a real credential, not an id/hash.",
                     val, source, text, m.start("val"), m.end("val"))
        findings.append(f)
        hits += 1
        if hits >= _PER_RULE_PER_BLOB:
            break

    hits = 0
    for m in _QUERY_SECRET.finditer(text):
        val = m.group("val")
        if _PLACEHOLDER.search(val) or _entropy(val) < 3.0 or len(set(val)) < 8:
            continue
        f = _finding(f"Secret in URL query ({m.group('key').lower()})", "high", "medium",
                     False, "A credential passed in a URL query string — it lands in logs, referrers, and history.",
                     val, source, text, m.start("val"), m.end("val"))
        findings.append(f)
        hits += 1
        if hits >= _PER_RULE_PER_BLOB:
            break

    return findings


# --------------------------------------------------------------------------
# Enrichment — attach the safe verify command + decoded JWT claims per finding.
# --------------------------------------------------------------------------
def _enrich(findings: list[dict]) -> None:
    for f in findings:
        rule = f["rule"]
        cmd = keyverify.build_command(rule, f["match"])
        if cmd:
            f["verify"] = cmd
        else:
            reason = keyverify.no_check_reason(rule)
            if reason:
                f["verify_note"] = reason
        if rule.startswith("JSON Web Token"):
            claims = keyverify.decode_jwt(f["match"])
            if claims:
                f["jwt"] = {"header": claims["header"], "payload": claims["payload"], "exp": claims.get("exp")}


# --------------------------------------------------------------------------
# Script harvesting — same-site only.
# --------------------------------------------------------------------------
_SCRIPT_SRC = re.compile(rb"""<script[^>]*\bsrc\s*=\s*["']?([^"'>\s]+)""", re.I)
# modulepreload / prefetch links point at route-adjacent chunks that never
# appear as a literal <script src> in the initial HTML (Next.js et al) — audit
# P1 #7. Match either attribute order.
_LINK_PRELOAD = re.compile(
    rb"""<link[^>]*\b(?:rel\s*=\s*["']?(?:modulepreload|preload|prefetch)["']?[^>]*\bhref|"""
    rb"""href\s*=\s*["']?([^"'>\s]+)[^>]*\brel\s*=\s*["']?(?:modulepreload|preload|prefetch))"""
    rb"""[^>]*""", re.I)
_LINK_HREF = re.compile(rb"""href\s*=\s*["']?([^"'>\s]+)""", re.I)
_SOURCEMAP = re.compile(rb"//[#@]\s*sourceMappingURL=([^\s'\"]+)", re.I)

_MAX_INLINE_SCRIPTS = 100
_MAX_INLINE_LEN = 1_000_000


def _iter_inline_scripts(body: bytes) -> list:
    out, i, count = [], 0, 0
    low = body.lower()
    while count < _MAX_INLINE_SCRIPTS:
        s = low.find(b"<script", i)
        if s == -1:
            break
        gt = low.find(b">", s)
        if gt == -1:
            break
        open_tag = low[s:gt]
        i = gt + 1
        if b"src=" in open_tag:            # external script — fetched + scanned separately
            continue
        end = low.find(b"</script", i)
        if end == -1:                       # unclosed — take a bounded tail and stop
            out.append(body[i:i + _MAX_INLINE_LEN])
            break
        out.append(body[i:end][:_MAX_INLINE_LEN])
        i = end + 8                          # len(b"</script")
        count += 1
    return out


# Registrable-suffix table: suffixes that are themselves >= 2 labels, so the
# "last two labels = apex" shortcut would wrongly call two unrelated tenants the
# same site (audit P1 #5). For a host under one of these, the registrable domain
# is suffix + 1 more label. stdlib-only, so this is a curated short list of the
# multi-tenant suffixes that actually show up hosting app bundles — not a full
# public-suffix list. Anything not covered here falls back to exact-host match
# (the safe default) unless it's a plain apex/subdomain of a 2-label domain.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.au", "com.br", "co.in",
    "co.nz", "co.za", "com.mx", "com.sg", "github.io", "gitlab.io", "s3.amazonaws.com",
    "herokuapp.com", "herokudns.com", "azurewebsites.net", "cloudfront.net",
    "vercel.app", "netlify.app", "netlify.com", "pages.dev", "workers.dev",
    "web.app", "firebaseapp.com", "appspot.com", "cloudfunctions.net",
    "r2.dev", "surge.sh", "fastly.net", "akamaihd.net", "wpengine.com",
}


def _registrable(host: str) -> str:
    """The registrable domain for `host`, honoring multi-label public suffixes.
    Falls back to the last two labels for ordinary domains."""
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) < 2:
        return host
    for n in (3, 2):                       # try longest suffix first (e.g. s3.amazonaws.com)
        if len(parts) > n and ".".join(parts[-n:]) in _MULTI_LABEL_SUFFIXES:
            return ".".join(parts[-(n + 1):])
    if ".".join(parts[-2:]) in _MULTI_LABEL_SUFFIXES:
        # a 2-label suffix (co.uk) with the host EXACTLY equal to it → treat as-is
        return host if len(parts) == 2 else ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _same_site(script_host: str, target_host: str) -> bool:
    """Same host, or a subdomain of the same registrable domain. For a host on a
    multi-tenant suffix (github.io, s3.amazonaws.com), the registrable domain
    includes the tenant label, so one tenant is NOT 'same site' as another."""
    if not script_host:
        return True  # relative URL -> same host
    sh, th = script_host.lower(), target_host.lower()
    if sh == th:
        return True
    rd = _registrable(th)
    # A multi-tenant suffix requires the tenant label to match — exact registrable
    # equality, or a subdomain of that exact registrable domain.
    return sh == rd or sh.endswith("." + rd)


def _collect_script_urls(html: bytes, base_url: str, target_host: str) -> tuple[list[str], int, int]:
    """Absolute, same-site, http(s) script URLs from the page — both <script src>
    and <link modulepreload/prefetch> (js only). Returns
    (urls, skipped_cross_origin, skipped_over_cap)."""
    urls, seen, skipped, over_cap = [], set(), 0, 0

    def consider(raw: str) -> None:
        nonlocal skipped, over_cap
        raw = raw.strip()
        if not raw or raw.startswith("data:"):
            return
        absu = urljoin(base_url, raw)
        pu = urlparse(absu)
        if pu.scheme not in ("http", "https") or not pu.hostname:
            return
        if not _same_site(pu.hostname, target_host):
            skipped += 1
            return
        if absu in seen:
            return
        if len(urls) >= MAX_SCRIPTS:
            over_cap += 1
            return
        seen.add(absu)
        urls.append(absu)

    for m in _SCRIPT_SRC.finditer(html):
        consider(m.group(1).decode("utf-8", "replace"))
    for m in _LINK_PRELOAD.finditer(html):
        raw = m.group(1)
        if raw is None:                     # rel-before-href branch: pull the href out of the tag
            hm = _LINK_HREF.search(m.group(0))
            raw = hm.group(1) if hm else None
        if raw is None:
            continue
        href = raw.decode("utf-8", "replace")
        if href.rsplit("?", 1)[0].endswith((".js", ".mjs", ".map")):
            consider(href)

    return urls, skipped, over_cap


def _fetch_text(url: str) -> tuple[str, str]:
    """(url, text) — text is '' on any fetch failure. Same SSRF-guarded path as
    everything else; a URL that resolves non-public is refused by fetch itself."""
    try:
        status, body, _headers = common.fetch(url, timeout=PER_FETCH_TIMEOUT, max_bytes=MAX_SCRIPT_BYTES)
        if status != 200 or not body:
            return url, ""
        return url, body.decode("utf-8", "replace")
    except _FETCH_ERRORS:
        return url, ""


def _scan_sourcemap(map_url: str) -> list[dict]:
    """Fetch a .map, parse its JSON, and scan every original source in
    sourcesContent — de-minified source has real variable names (secretAccessKey,
    not a mangled `t`) and dev-only branches, the highest-signal artifact a
    minified bundle hides. Returns findings labeled by their original path."""
    _u, text = _fetch_text(map_url)
    if not text:
        return []
    try:
        data = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    findings: list[dict] = []
    for i, content in enumerate(contents):
        if not isinstance(content, str) or not content:
            continue
        origin = sources[i] if i < len(sources) and isinstance(sources[i], str) else f"source[{i}]"
        findings += scan_text(content, source=f"{map_url} → {origin}")
    return findings


def _apex(host: str) -> str:
    """Back-compat shim — the registrable domain of `host`. Kept because tests
    and callers reference it; delegates to the suffix-aware _registrable."""
    return _registrable(host)


# --------------------------------------------------------------------------
# Deep mode — opt-in extra surface. All same-site, all through common.fetch,
# all passive GETs. Noisier scanner signature (more 404s), so it's off unless
# the caller asks. Bounded hard.
# --------------------------------------------------------------------------
# Curated high-signal exposed paths (nuclei exposures/config territory), kept
# short and same-host. A 200 with matching content is itself a finding.
_EXPOSED_FILES = [
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.git/config", "/.git/HEAD", "/config.json", "/config.js", "/env.js",
    "/appsettings.json", "/appsettings.Production.json", "/settings.py",
    "/wp-config.php.bak", "/wp-config.php~", "/.aws/credentials", "/credentials.json",
    "/secrets.json", "/.npmrc", "/.dockercfg", "/docker-compose.yml",
    "/.DS_Store", "/server-status", "/phpinfo.php", "/.well-known/security.txt",
    "/api/config", "/actuator/env", "/debug/vars", "/.vscode/settings.json",
]
# Signatures that mark an exposed file as the real thing (not a 200 SPA fallback).
_EXPOSED_SIGNATURES = {
    "/.env": re.compile(r"(?im)^\s*[A-Z0-9_]{2,40}\s*=.+"),
    "/.git/config": re.compile(r"(?i)\[core\]|\[remote|repositoryformatversion"),
    "/.git/HEAD": re.compile(r"(?i)^ref:\s+refs/"),
    "/.aws/credentials": re.compile(r"(?i)aws_access_key_id|\[default\]"),
    "/.npmrc": re.compile(r"(?i)_authToken|registry="),
}


def _probe_exposed_files(base_url: str, target_host: str) -> tuple[list[dict], list[dict]]:
    """GET a short curated list of commonly-exposed config/dotfiles on the SAME
    host. Returns (findings, probed) — findings include both any secrets inside
    a served file AND the exposure of the file itself."""
    findings: list[dict] = []
    probed: list[dict] = []
    root = f"{urlparse(base_url).scheme}://{target_host}"
    count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futs = {}
        for path in _EXPOSED_FILES[:MAX_DEEP_PROBES]:
            futs[pool.submit(_fetch_status, root + path)] = path
        for fut in concurrent.futures.as_completed(futs):
            path = futs[fut]
            status, text = fut.result()
            hit = status == 200 and bool(text)
            probed.append({"path": path, "status": status, "served": hit})
            count += 1
            if not hit:
                continue
            sig = _EXPOSED_SIGNATURES.get(path)
            looks_real = (sig.search(text) is not None) if sig else True
            if looks_real:
                findings.append({
                    "rule": f"Exposed file served: {path}", "severity": "high",
                    "confidence": "medium" if sig else "low", "public_ok": False,
                    "note": "This path is served publicly and matches its expected sensitive shape — "
                            "confirm it isn't meant to be public, then scan its contents below.",
                    "match": root + path, "masked": root + path,
                    "source": root + path, "snippet": _snippet(text, 0, min(len(text), 60)),
                    "entropy": 0.0,
                })
            findings += scan_text(text, source=root + path)
    return findings, probed


def _fetch_status(url: str) -> tuple[int, str]:
    try:
        status, body, _h = common.fetch(url, timeout=PER_FETCH_TIMEOUT, max_bytes=512_000)
        return status, (body or b"").decode("utf-8", "replace")
    except _FETCH_ERRORS:
        return 0, ""


def _wayback_js_urls(target_host: str) -> list[str]:
    """Query the Wayback CDX API (keyless, public) for historical JS/map URLs on
    the host — catches a key rotated out of the CURRENT bundle but still live.
    web.archive.org is public, so it rides the normal SSRF-guarded fetch."""
    q = ("https://web.archive.org/cdx/search/cdx?url=" + quote(target_host)
         + "/*&output=json&fl=timestamp,original,mimetype&collapse=urlkey&limit=800")
    _u, text = _fetch_text(q)
    if not text:
        return []
    try:
        rows = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return []
    urls, seen = [], set()
    for row in rows[1:] if rows and isinstance(rows[0], list) else []:
        if len(row) < 2:
            continue
        ts, orig = row[0], row[1]
        if not orig.rsplit("?", 1)[0].endswith((".js", ".mjs", ".map")):
            continue
        if orig in seen:
            continue
        seen.add(orig)
        # `<timestamp>id_` fetches the raw, unrewritten archived bytes (no
        # Wayback toolbar/HTML injection), so the scan sees the original JS.
        urls.append(f"https://web.archive.org/web/{ts}id_/{orig}")
        if len(urls) >= MAX_WAYBACK:
            break
    return urls


def analyze(url: str, deep: bool = False) -> dict:
    """Fetch the page + its same-site JS + referenced source maps and scan
    everything; in deep mode also probe common exposed files and Wayback
    history. Assumes the caller already validated the URL and scope. Never raises."""
    target_host = urlparse(url).hostname or ""
    try:
        status, body, headers = common.fetch(url, timeout=PER_FETCH_TIMEOUT, max_bytes=MAX_SCRIPT_BYTES)
    except ValueError as e:
        return {"ok": False, "error": f"blocked: {e}"}
    except (OSError, http.client.HTTPException) as e:
        return {"ok": False, "error": f"unreachable: {type(e).__name__}: {e}"}

    html_text = (body or b"").decode("utf-8", "replace")
    findings: list[dict] = []
    scanned_bytes = 0
    scan_truncated = False

    def budget_ok() -> bool:
        return scanned_bytes < _TOTAL_SCAN_BUDGET

    # 1) the page HTML itself
    findings += scan_text(html_text, source=url)
    scanned_bytes += len(html_text)

    # 2) response headers (already in hand — a token echoed in X-Api-Key / a
    #    Set-Cookie session JWT is a real leak the body scan would miss).
    hdr_blob = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    if hdr_blob:
        findings += scan_text(hdr_blob, source=f"{url} (response headers)")
        scanned_bytes += len(hdr_blob)

    # 3) inline scripts (already in-hand — no extra fetch)
    for inline_b in _iter_inline_scripts(body or b""):
        inline = inline_b.decode("utf-8", "replace")
        findings += scan_text(inline, source=f"{url} (inline <script>)")
        scanned_bytes += len(inline)

    # 4) same-site external JS + their source maps, fetched concurrently and
    #    bounded. EVERY fetched script is scanned (bounded by the byte budget);
    #    the findings cap is display-only and applied later, so a later file's
    #    live secret is never dropped mid-scan (audit P0 #1).
    script_urls, skipped, skipped_over_cap = _collect_script_urls(body or b"", url, target_host)
    scanned_scripts: list[dict] = []
    sourcemap_urls: list[str] = []
    if script_urls:
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            for surl, text in pool.map(_fetch_text, script_urls):
                over_budget = not budget_ok()
                scanned_scripts.append({"url": surl, "bytes": len(text),
                                        "fetched": bool(text), "scanned": bool(text) and not over_budget})
                if over_budget:
                    scan_truncated = True
                    continue
                if text:
                    findings += scan_text(text, source=surl)
                    scanned_bytes += len(text)
                    # collect any source map this bundle references (audit P0 #8:
                    # the marker lives in the JS, not the HTML)
                    mm = _SOURCEMAP.search(text.encode("utf-8", "replace"))
                    if mm and len(sourcemap_urls) < MAX_SOURCEMAPS:
                        map_ref = mm.group(1).decode("utf-8", "replace").strip()
                        if not map_ref.startswith("data:"):
                            map_abs = urljoin(surl, map_ref)
                            if _same_site(urlparse(map_abs).hostname or "", target_host):
                                sourcemap_urls.append(map_abs)

    # 5) source maps — de-minified original source
    maps_scanned = 0
    if sourcemap_urls and budget_ok():
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            for map_findings in pool.map(_scan_sourcemap, sourcemap_urls):
                if not budget_ok():
                    scan_truncated = True
                    break
                findings += map_findings
                maps_scanned += 1
                scanned_bytes += sum(len(f.get("snippet", "")) for f in map_findings) + 50_000

    # 6) deep mode — exposed files + Wayback history (opt-in)
    exposed_probed: list[dict] = []
    wayback_scanned = 0
    if deep:
        ef, exposed_probed = _probe_exposed_files(url, target_host)
        findings += ef
        wb_urls = _wayback_js_urls(target_host)
        if wb_urls and budget_ok():
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                for surl, text in pool.map(_fetch_text, wb_urls):
                    if not budget_ok():
                        scan_truncated = True
                        break
                    if text:
                        findings += scan_text(text, source=f"{surl} (wayback)")
                        scanned_bytes += len(text)
                        wayback_scanned += 1

    # De-dup on (rule, value) and MERGE locations — the full-HTML scan overlaps
    # its own inline scripts, and one key legitimately appears in several files;
    # either way the operator wants ONE finding that lists every place it lives,
    # not a wall of duplicate rows. First occurrence wins; the rest of the
    # distinct sources ride along in `also_in` (capped).
    by_key: dict = {}
    deduped = []
    for f in findings:
        k = (f["rule"], f["match"])
        if k in by_key:
            primary = by_key[k]
            if f["source"] != primary["source"] and len(primary.setdefault("also_in", [])) < 12:
                if f["source"] not in primary["also_in"]:
                    primary["also_in"].append(f["source"])
            continue
        by_key[k] = f
        deduped.append(f)

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    # real leaks (public_ok False) ahead of public-by-design keys within a severity;
    # then higher-confidence first, so the display cap keeps the strongest findings.
    deduped.sort(key=lambda f: (sev_rank.get(f["severity"], 9), f["public_ok"],
                                conf_rank.get(f["confidence"], 3)))

    total_found = len(deduped)
    display_truncated = total_found > MAX_FINDINGS
    if display_truncated:
        deduped = deduped[:MAX_FINDINGS]     # after sort → drops only the weakest

    _enrich(deduped)
    real = [f for f in deduped if not f["public_ok"]]

    return {
        "ok": True,
        "url": url,
        "status": status,
        "deep": deep,
        "scripts_scanned": scanned_scripts,
        "scripts_skipped_cross_origin": skipped,
        "scripts_skipped_over_cap": skipped_over_cap,
        "sourcemaps_scanned": maps_scanned,
        "sourcemap_referenced": bool(sourcemap_urls),
        "exposed_files_probed": exposed_probed,
        "wayback_scripts_scanned": wayback_scanned,
        "findings": deduped,
        "counts": {sev: sum(1 for f in deduped if f["severity"] == sev)
                   for sev in ("critical", "high", "medium", "low", "info")},
        "real_leak_count": len(real),   # excludes public-by-design keys
        "total_findings": total_found,
        "truncated": display_truncated,      # returned list trimmed for display (scan was complete)
        "scan_truncated": scan_truncated,    # hit the total-byte CPU budget — some bytes unscanned
        "bytes_scanned": scanned_bytes,
    }


def handle_secret_scan(req) -> "common.Response":
    """POST /api/secret-scan  {url, authorized, lab, deep}  ->  leak findings.

    Same gate as the runners (authorized + validated URL + public scope unless
    lab + pre-fetch re-resolve). `deep` adds the exposed-file + Wayback surface.
    The audit log records the scan and its COUNTS, never the matched secret
    values — those go only to the browser.
    """
    body = req.json()
    target_raw = body.get("url") or body.get("target")
    authorized = body.get("authorized") is True
    lab = body.get("lab") is True
    deep = body.get("deep") is True

    if not authorized:
        return common.Response.error(403,
            "authorized:true is required — confirm you have permission to test this target.")
    if not isinstance(target_raw, str):
        return common.Response.error(400, "url must be a string")

    ok, host_or_reason, cleaned = runners.validate_url(target_raw)
    if not ok:
        return common.Response.error(400, f"invalid target: {host_or_reason}")

    in_scope, reason = runners.scope_check(host_or_reason, lab)
    if not in_scope:
        return common.Response.error(403, reason)
    blocked = runners.opsec_gate(lab, body)
    if blocked is not None:
        return blocked
    # Native fetch tools can't reach private targets even in lab mode (SSRF
    # guard) — say so clearly. See webscan._LAB_PRIVATE_MSG.
    if lab and not common.host_is_public(host_or_reason):
        return common.Response.error(400, webscan._LAB_PRIVATE_MSG)
    if not lab and not runners._resolve_public_ips_safe(host_or_reason):
        return common.Response.error(403,
            "target no longer resolves to a public address (re-checked before fetch) — refusing")

    result = analyze(cleaned, deep=deep)

    # Audit: record that a scan ran and how much it found — NEVER the secrets.
    # Log the scheme/host/path only; a querystring can itself carry a secret
    # (?api_key=...), and this scanner's whole point is to not persist secrets.
    if result.get("ok"):
        p = urlparse(cleaned)
        runners._append_audit({
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": "secret-scan", "target": f"{p.scheme}://{p.netloc}{p.path}",
            "authorized": authorized, "lab": lab, "deep": deep,
            "findings_total": len(result.get("findings", [])),
            "real_leak_count": result.get("real_leak_count", 0),
            "counts": result.get("counts", {}),
        })
    return common.Response.json(result)
