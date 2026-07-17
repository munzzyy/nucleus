"""Secret / API-key leak scanner — find credentials exposed in a site's own
client-side code. Point it at a URL; it pulls the page HTML, every inline
<script>, and the site's own external JS bundles, and scans all of it for the
credential shapes that get shipped to the browser by accident: cloud keys,
payment keys, source-control tokens, webhook URLs, private keys, JWTs, and
high-entropy `apiKey: "..."` assignments.

Why this exists: the #1 real-world web leak isn't a clever exploit, it's a
secret key hardcoded into a front-end bundle and served to every visitor. A
scan of the actual delivered HTML/JS catches exactly that.

What it is careful about:
  * SCOPE. It fetches the page, then only the JS hosted on the SAME site
    (same host, or a subdomain of the same apex domain) — it does not wander
    off to third-party CDNs. Every fetch rides `common.fetch`, the same
    SSRF-guarded, connect-pinned, public-only path recon uses, so a page that
    links an internal/metadata address can't turn this into an SSRF probe.
  * FALSE POSITIVES. Publishable keys that are MEANT to be public (Stripe
    pk_live_, Google/Firebase browser AIza keys) are reported as low/info
    with a note, not screamed about — that separation is what makes the
    output usable in a real report. The generic `key = "..."` rule is
    entropy-gated so placeholder values don't flood the results.
  * THE SECRETS THEMSELVES. Findings go back to the browser (loopback, your
    screen) with a masked preview by default; the on-disk audit log records
    only counts and rule names, never the matched secret values.

Gated like every other redcell action: authorized:true, public scope unless
lab. Passive — it only GETs pages the site already serves to anyone.
"""

from __future__ import annotations

import concurrent.futures
import http.client
import math
import re
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from shared import common
from consoles.redcell import runners, webscan

_FETCH_ERRORS = (ValueError, OSError, http.client.HTTPException)

MAX_SCRIPTS = 15            # cap external JS fetches per scan
MAX_SCRIPT_BYTES = 2_000_000
MAX_FINDINGS = 400
PER_FETCH_TIMEOUT = 8.0
_CTX = 36                    # context chars kept around each match
# Hard cap on total bytes handed to the regex engine across one whole scan
# (page + inline + every external script). Without it, 15 scripts x 2MB x ~30
# patterns is tens of seconds of CPU pinning a worker — bounded here to keep a
# single scan well under a few seconds even against a hostile/huge target.
_TOTAL_SCAN_BUDGET = 8_000_000


# --------------------------------------------------------------------------
# Rule catalog. Each rule: a compiled regex, a severity, a confidence, and
# `public_ok` (the shape is legitimately shipped to browsers — a note, not an
# alarm). Patterns follow the well-known gitleaks/SecretFinder shapes.
#
# `keywords` is a cheap pre-filter: a rule's regex only runs if at least one of
# its keyword literals is present in the (lower-cased) text. A C-level substring
# scan is orders of magnitude faster than a regex pass, so on real code — where
# almost none of these markers appear — nearly every pattern is skipped. This
# is the standard secret-scanner optimization (gitleaks does the same) and is
# what keeps a scan of multi-MB minified bundles fast. keywords=None means the
# pattern is cheap/structural enough to always run.
# --------------------------------------------------------------------------
class Rule:
    __slots__ = ("name", "rx", "severity", "confidence", "public_ok", "note", "group", "keywords")

    def __init__(self, name, pattern, severity, confidence="high",
                 public_ok=False, note="", group=0, flags=0, keywords=None):
        self.name = name
        self.rx = re.compile(pattern, flags)
        self.severity = severity
        self.confidence = confidence
        self.public_ok = public_ok
        self.note = note
        self.group = group     # capture group holding the secret value
        self.keywords = keywords  # tuple of lower-case literals; any-present gate


RULES: list[Rule] = [
    # ---- cloud ----
    Rule("AWS Access Key ID", r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16})\b",
         "critical", group=1, keywords=("akia", "asia", "agpa", "aida", "aroa", "anpa"),
         note="An AKIA/ASIA key ID. Confirm the matching secret isn't nearby — the pair grants API access."),
    Rule("AWS Secret Access Key (contextual)",
         r"(?i)aws.{0,20}?(?:secret|sk).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]",
         "critical", confidence="medium", group=1, keywords=("aws",)),
    Rule("Google API key", r"\b(AIza[0-9A-Za-z\-_]{35})\b", "medium", public_ok=True, keywords=("aiza",),
         note="Google/Firebase BROWSER keys are often intentionally public — but they must be "
              "referrer/API-restricted server-side. Verify the restriction; an unrestricted one is billable abuse."),
    Rule("Google OAuth access token", r"\b(ya29\.[0-9A-Za-z\-_]{20,})", "high", group=1, keywords=("ya29.",)),
    Rule("GCP service-account private key block", r'("type"\s*:\s*"service_account")',
         "critical", keywords=("service_account",),
         note="A service-account JSON blob in client code is a full server credential leak.", group=1),
    Rule("Firebase Cloud Messaging legacy server key",
         r"\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})\b", "critical", group=1, keywords=("aaaa",)),
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
    # ---- source control / package ----
    Rule("GitHub token", r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b", "critical", group=1,
         keywords=("ghp_", "gho_", "ghu_", "ghs_", "ghr_")),
    Rule("GitHub fine-grained PAT", r"\b(github_pat_[A-Za-z0-9_]{82})\b", "critical", group=1, keywords=("github_pat_",)),
    Rule("GitLab personal access token", r"\b(glpat-[A-Za-z0-9\-_]{20})\b", "critical", group=1, keywords=("glpat-",)),
    Rule("npm access token", r"\b(npm_[A-Za-z0-9]{36})\b", "high", group=1, keywords=("npm_",)),
    Rule("PyPI upload token", r"\b(pypi-AgEIcHlwaS[A-Za-z0-9\-_]{50,})\b", "critical", group=1, keywords=("pypi-",)),
    # ---- comms / email ----
    Rule("Slack token", r"\b(xox[baprs]-[A-Za-z0-9-]{10,64})\b", "high", group=1, keywords=("xox",)),
    Rule("Slack webhook URL", r"(https://hooks\.slack\.com/services/[A-Za-z0-9+/_-]{40,})",
         "high", group=1, keywords=("hooks.slack.com",)),
    Rule("SendGrid API key", r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b", "critical", group=1, keywords=("sg.",)),
    Rule("Mailgun API key", r"\b(key-[0-9a-zA-Z]{32})\b", "high", confidence="medium", group=1, keywords=("key-",)),
    Rule("Mailchimp API key", r"\b([0-9a-f]{32}-us[0-9]{1,2})\b", "high", group=1, keywords=("-us",)),
    Rule("Twilio API Key SID", r"\b(SK[0-9a-fA-F]{32})\b", "high", confidence="medium", group=1, keywords=("sk",)),
    Rule("Twilio Account SID", r"\b(AC[0-9a-f]{32})\b", "low", confidence="medium", public_ok=True, keywords=("ac",),
         note="An Account SID is an identifier, not a secret on its own — a finding only paired with the auth token."),
    # ---- AI providers ----
    Rule("OpenAI API key", r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})\b", "critical", confidence="medium", group=1, keywords=("sk-",),
         note="OpenAI 'sk-' key. Verify it isn't a Stripe 'sk_' (underscore) false hit — this rule requires the hyphen form."),
    Rule("Anthropic API key", r"\b(sk-ant-[A-Za-z0-9\-_]{24,})\b", "critical", group=1, keywords=("sk-ant-",)),
    # ---- generic / structural ----
    Rule("Private key block",
         r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)",
         "critical", group=1, keywords=("private key",)),
    Rule("JSON Web Token (JWT)",
         r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b",
         "medium", confidence="medium", group=1, keywords=("eyj",),
         note="A JWT shipped in code may be a leaked session/service token — decode it to check the claims and expiry."),
    Rule("Basic-auth credentials in URL",
         r"\b(https?://[^/\s:@\"']{1,64}:[^/\s:@\"']{1,64}@[A-Za-z0-9.-]+)",
         "high", group=1, keywords=("://",)),
    Rule("Authorization: Bearer header value",
         r"(?i)authorization['\"]?\s*[:=]\s*['\"]?bearer\s+([A-Za-z0-9_\-\.=]{20,})",
         "high", confidence="medium", group=1, keywords=("bearer",)),
]

# Keys that gate the entropy-checked generic assignment rule — if none of these
# literals appear, the generic pattern (the most expensive one) is skipped.
_GENERIC_KEYWORDS = ("api", "key", "secret", "passwd", "password", "token", "auth", "private", "session")

# The noisy one, handled separately so it can be entropy-gated: a
# key/secret/token assignment with a quoted value.
_GENERIC_ASSIGN = re.compile(
    r"""(?ix)
    (?P<key>(?:api[_-]?key|apikey|secret|secret[_-]?key|client[_-]?secret|
             passwd|password|access[_-]?token|auth[_-]?token|private[_-]?key|
             session[_-]?key|encryption[_-]?key))
    \s*[:=]\s*
    ['"](?P<val>[A-Za-z0-9_\-+/=\.]{16,80})['"]
    """
)

# Values that look secret-shaped but are obviously placeholders/examples.
_PLACEHOLDER = re.compile(
    r"(?i)(your[_-]?|example|placeholder|changeme|xxxx|\.\.\.|<[a-z]|test[_-]?key|"
    r"sample|dummy|redacted|insert[_-]?|enter[_-]?|my[_-]?secret|todo|foobar|1234567)")


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


def scan_text(text: str, source: str) -> list[dict]:
    """Run every rule (plus the entropy-gated generic rule) over one blob.

    A rule's regex only runs if one of its keyword literals is present in the
    text (a fast substring pre-filter) — on real code that skips almost every
    pattern, which is what keeps scanning large minified bundles cheap."""
    if not text:
        return []
    low = text.lower()
    findings: list[dict] = []
    for rule in RULES:
        if rule.keywords and not any(k in low for k in rule.keywords):
            continue
        for m in rule.rx.finditer(text):
            secret = m.group(rule.group) if rule.group else m.group(0)
            findings.append({
                "rule": rule.name, "severity": rule.severity, "confidence": rule.confidence,
                "public_ok": rule.public_ok, "note": rule.note,
                "match": secret, "masked": _mask(secret),
                "source": source, "snippet": _snippet(text, m.start(), m.end()),
                "entropy": round(_entropy(secret), 2),
            })
            if len(findings) >= MAX_FINDINGS:
                return findings

    if not any(k in low for k in _GENERIC_KEYWORDS):
        return findings
    for m in _GENERIC_ASSIGN.finditer(text):
        val = m.group("val")
        # Gate: skip obvious placeholders and low-entropy words.
        if _PLACEHOLDER.search(val) or _entropy(val) < 3.0 or len(set(val)) < 8:
            continue
        findings.append({
            "rule": f"Hardcoded {m.group('key').lower()} assignment",
            "severity": "medium", "confidence": "low", "public_ok": False,
            "note": "Generic high-entropy secret assignment — verify it's a real credential, not an id/hash.",
            "match": val, "masked": _mask(val),
            "source": source, "snippet": _snippet(text, m.start(), m.end()),
            "entropy": round(_entropy(val), 2),
        })
        if len(findings) >= MAX_FINDINGS:
            break
    return findings


# --------------------------------------------------------------------------
# Script harvesting — same-site only.
# --------------------------------------------------------------------------
_SCRIPT_SRC = re.compile(rb"""<script[^>]*\bsrc\s*=\s*["']?([^"'>\s]+)""", re.I)
_SOURCEMAP = re.compile(rb"//[#@]\s*sourceMappingURL=([^\s'\"]+)", re.I)

# Inline scripts are pulled out by a LINEAR find-scan, never a `.*?</script>`
# regex: the lazy regex backtracks O(n^2) — a multi-MINUTE stall — on a hostile
# page full of unclosed <script> tags (each tag re-scans to EOF). bytes.find
# advances monotonically, so this is O(n) regardless of how the page is shaped.
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


def _apex(host: str) -> str:
    """Last two labels — a good-enough 'same site' anchor without a public
    suffix list (stdlib-only). Errs toward NOT following (won't leave the
    obvious apex), which is the safe direction for scope."""
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _same_site(script_host: str, target_host: str) -> bool:
    if not script_host:
        return True  # relative URL -> same host
    sh, th = script_host.lower(), target_host.lower()
    return sh == th or sh.endswith("." + _apex(th)) or sh == _apex(th)


def _collect_script_urls(html: bytes, base_url: str, target_host: str) -> tuple[list[str], int]:
    """Absolute, same-site, http(s) script URLs from the page. Returns
    (urls, skipped_cross_origin_count)."""
    urls, seen, skipped = [], set(), 0
    for m in _SCRIPT_SRC.finditer(html):
        raw = m.group(1).decode("utf-8", "replace").strip()
        if not raw or raw.startswith("data:"):
            continue
        absu = urljoin(base_url, raw)
        pu = urlparse(absu)
        if pu.scheme not in ("http", "https") or not pu.hostname:
            continue
        if not _same_site(pu.hostname, target_host):
            skipped += 1
            continue
        if absu not in seen:
            seen.add(absu)
            urls.append(absu)
        if len(urls) >= MAX_SCRIPTS:
            break
    return urls, skipped


def _fetch_script(url: str) -> tuple[str, str]:
    """(url, text) — text is '' on any fetch failure. Same SSRF-guarded path
    as everything else; a script URL that resolves non-public is refused by
    fetch itself, independent of the same-site check above."""
    try:
        status, body, _headers = common.fetch(url, timeout=PER_FETCH_TIMEOUT,
                                               max_bytes=MAX_SCRIPT_BYTES)
        if status != 200 or not body:
            return url, ""
        return url, body.decode("utf-8", "replace")
    except _FETCH_ERRORS:
        return url, ""


def analyze(url: str) -> dict:
    """Fetch the page + its same-site JS and scan everything. Assumes the
    caller already validated the URL and scope. Never raises."""
    target_host = urlparse(url).hostname or ""
    try:
        status, body, _headers = common.fetch(url, timeout=PER_FETCH_TIMEOUT, max_bytes=MAX_SCRIPT_BYTES)
    except ValueError as e:
        return {"ok": False, "error": f"blocked: {e}"}
    except (OSError, http.client.HTTPException) as e:
        return {"ok": False, "error": f"unreachable: {type(e).__name__}: {e}"}

    html_text = (body or b"").decode("utf-8", "replace")
    findings: list[dict] = []
    scanned_bytes = 0
    scan_truncated = False

    # 1) the page HTML itself
    findings += scan_text(html_text, source=url)
    scanned_bytes += len(html_text)

    # 2) inline scripts (already in-hand — no extra fetch)
    for inline_b in _iter_inline_scripts(body or b""):
        inline = inline_b.decode("utf-8", "replace")
        findings += scan_text(inline, source=f"{url} (inline <script>)")
        scanned_bytes += len(inline)

    # 3) same-site external JS, fetched concurrently and bounded. The fetch
    # count is capped (MAX_SCRIPTS); the SCAN work is capped independently by a
    # total-byte budget, so a page of 15 huge bundles can't pin a worker.
    script_urls, skipped = _collect_script_urls(body or b"", url, target_host)
    scanned_scripts = []
    if script_urls and len(findings) < MAX_FINDINGS:
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            for surl, text in pool.map(_fetch_script, script_urls):
                over_budget = scanned_bytes >= _TOTAL_SCAN_BUDGET
                scanned_scripts.append({"url": surl, "bytes": len(text),
                                        "fetched": bool(text), "scanned": bool(text) and not over_budget})
                if over_budget:
                    scan_truncated = True
                    continue
                if text:
                    findings += scan_text(text, source=surl)
                    scanned_bytes += len(text)
                if len(findings) >= MAX_FINDINGS:
                    break

    # de-dup identical (rule, match, source)
    seen = set()
    deduped = []
    for f in findings:
        k = (f["rule"], f["match"], f["source"])
        if k in seen:
            continue
        seen.add(k)
        deduped.append(f)

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    # real leaks (public_ok False -> 0) ahead of public-by-design keys within a severity
    deduped.sort(key=lambda f: (sev_rank.get(f["severity"], 9), f["public_ok"]))

    sourcemaps = bool(_SOURCEMAP.search(body or b""))
    real = [f for f in deduped if not f["public_ok"]]

    return {
        "ok": True,
        "url": url,
        "status": status,
        "scripts_scanned": scanned_scripts,
        "scripts_skipped_cross_origin": skipped,
        "sourcemap_referenced": sourcemaps,
        "findings": deduped,
        "counts": {sev: sum(1 for f in deduped if f["severity"] == sev)
                   for sev in ("critical", "high", "medium", "low", "info")},
        "real_leak_count": len(real),   # excludes public-by-design keys
        "truncated": len(findings) >= MAX_FINDINGS,
        "scan_truncated": scan_truncated,   # hit the total-byte scan budget
        "bytes_scanned": scanned_bytes,
    }


def handle_secret_scan(req) -> "common.Response":
    """POST /api/secret-scan  {url, authorized, lab}  ->  leak findings.

    Same gate as the runners (authorized + validated URL + public scope unless
    lab + pre-fetch re-resolve). The audit log records the scan and its
    COUNTS, never the matched secret values — those go only to the browser.
    """
    body = req.json()
    target_raw = body.get("url") or body.get("target")
    authorized = body.get("authorized") is True
    lab = body.get("lab") is True

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

    result = analyze(cleaned)

    # Audit: record that a scan ran and how much it found — NEVER the secrets.
    # Log the scheme/host/path only; a querystring can itself carry a secret
    # (?api_key=...), and this scanner's whole point is to not persist secrets.
    if result.get("ok"):
        p = urlparse(cleaned)
        runners._append_audit({
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": "secret-scan", "target": f"{p.scheme}://{p.netloc}{p.path}",
            "authorized": authorized, "lab": lab,
            "findings_total": len(result.get("findings", [])),
            "real_leak_count": result.get("real_leak_count", 0),
            "counts": result.get("counts", {}),
        })
    return common.Response.json(result)
