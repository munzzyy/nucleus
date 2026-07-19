"""DDoS resilience test — a bounded, ramped, auto-aborting Layer-7 probe that
measures whether a target's *defenses* hold under load, plus a command builder
for real capacity testing with the industry-standard load generators.

The point of this module is DEFENSE. You run it against a client's site (with
their authorization) to answer: does rate limiting engage? is there a CDN/WAF
absorbing the edge? does latency stay flat or fall over? where's the knee? —
and then hand them a graded read-out with concrete remediation. It is a
diagnostic, not a weapon, and it is built so it can't be turned into one.

What it is NOT, on purpose:
  * No packet-level flooding. It speaks real HTTP over real TCP from your own
    IP through the same SSRF-guarded fetch the rest of Nucleus uses. There is
    no raw socket, no SYN/UDP/ICMP flood, no IP spoofing, no amplification /
    reflection, and no distributed coordination anywhere in this file.
  * Not unbounded. The native probe is hard-capped in three independent
    dimensions — concurrency, total requests, and wall-clock — enforced
    server-side from constants in THIS file, never from anything the client
    sends, and probes are serialized + per-host cooldown-paced so looping the
    endpoint can't aggregate past those caps. The caps stay under the "ordinary
    authorized load test" line (well below the rates that need a cloud
    provider's sign-off). The higher tiers do deliver real, sustained load —
    enough to actually exercise a target with datacenter capacity, which a few
    hundred requests never would — so you match the tier to the target; the
    ramp-up + circuit breaker are what keep a WEAK target safe (load climbs from
    gentle and aborts the moment it buckles). For volume beyond what one box can
    push — truly saturating a big CDN/datacenter — use the k6/vegeta/hey/wrk/ab
    command builder, which never executes anything here.
  * Not a fire-and-forget hammer. A circuit breaker aborts the ramp the moment
    the target shows sustained distress — the goal is to FIND the point where
    defenses kick in (or don't), not to keep hitting something that's already
    hurting.

Every native run passes the same gate stack the runners use:
  1. authorized:true (you assert permission to test this target)
  2. the target validates and is public (or lab:true for your own box)
  3. the opsec gate — refused while your real IP is exposed (no VPN), unless
     you override or it's a lab target
  4. the hard caps above, applied to whatever tier was requested
  5. the circuit breaker, live, during the run

Ownership verification (verify_ownership) is an OPTIONAL proof-of-scope feature,
not a blocker: place a token in DNS TXT or a well-known file on the target and
the report gets stamped "scope verified", which is worth having on a real
engagement. A claimed verification that fails to check out is refused (so the
stamp can never be faked) — but skipping verification entirely is fine.
"""

from __future__ import annotations

import http.client
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from shared import common
from consoles.redcell import runners

# Everything common.fetch can raise (same set webscan catches): a blocked host
# or bad scheme is ValueError; sockets/TLS/timeouts are OSError (TimeoutError is
# an OSError subclass); protocol errors are http.client.HTTPException.
_FETCH_ERRORS = (ValueError, OSError, http.client.HTTPException)

# --------------------------------------------------------------------------
# HARD CAPS — the ceiling on a single probe. These are literals so no request
# body, tier, or UI toggle can raise them; a run is the MINIMUM of what the tier
# asks for and what these allow. They're sized to be a REAL load test — enough
# to actually exercise a well-provisioned target (a client with real datacenter
# capacity won't even notice a few hundred requests, so the low tiers would
# report "no defenses seen" on a site that's actually fine) — while staying far
# under genuine-weapon territory: the research pins the "ordinary authorized
# load test" line well below ~1000 RPS / 500 connections, and these sit under
# that. The ramp-up + circuit breaker are what protect a WEAK target: load
# climbs from gentle, and the breaker aborts the moment a target buckles, so a
# small origin trips out early instead of getting buried. Match the tier to the
# target — the high tiers deliver sustained load and can stress a small origin.
# --------------------------------------------------------------------------
MAX_CONCURRENCY = 100          # absolute ceiling on simultaneous in-flight requests
MAX_TOTAL_REQUESTS = 50_000    # absolute ceiling on requests across the whole probe
MAX_DURATION_S = 180.0         # absolute wall-clock ceiling; the probe stops here no matter what
REQ_TIMEOUT = 8.0              # per-request timeout (connect through read)
PROBE_MAX_BYTES = 8192         # read just enough to time the server, not to move bandwidth
REQS_PER_WORKER = 10           # requests fired per concurrency-unit per ramp/hold step

# Circuit breaker: if a ramp step's origin-error rate (5xx + connection errors)
# hits CB_ERROR_RATE, OR its timeout rate hits CB_TIMEOUT_RATE, with a
# meaningful sample, the target is visibly distressed — stop the ramp. Protects
# the target and gives a cleaner "defenses failed at concurrency N" read than
# grinding through more load would. 429s and edge challenges do NOT count as
# distress (they're the defense working), so a well-defended target that sheds
# load gracefully is measured, not aborted on.
CB_ERROR_RATE = 0.5
CB_TIMEOUT_RATE = 0.25
CB_MIN_SAMPLE = 8

# Cross-call throttle — the per-run caps above bound ONE probe, but nothing
# stops a script from calling /api/stress-probe in a loop or firing many at
# once, which would aggregate into real sustained load. So probes are
# SERIALIZED (one at a time, process-wide) and a short per-host cooldown paces
# back-to-back runs. Together these bound the delivered load to roughly one
# probe's worth per (probe + cooldown), no matter how the endpoint is driven —
# closing the "caps are per-call only" gap. Single-operator tool, so serializing
# is invisible in normal use and only trips a runaway loop or an accidental fan-out.
_PROBE_LOCK = threading.Lock()          # only one native probe runs at a time
_LAST_PROBE_END: dict = {}              # resolved-IP -> monotonic time the last probe finished
_PROBE_COOLDOWN_S = 10.0                # min gap between probes against the SAME origin (by IP)

# Intensity tiers. Each is a concurrency `ramp` (climb from gentle so a weak
# target's knee is found before the load gets heavy) plus a `hold` count — how
# many extra steps to sustain AT PEAK after the ramp. The hold is what makes a
# higher tier a real load test instead of a quick burst: sustained peak load is
# what surfaces autoscaling and steady-state rate limiting on a well-provisioned
# target. Every step is concurrency * REQS_PER_WORKER requests, and the whole
# run is still clamped by the caps above and ended early by the circuit breaker.
# Pick the tier to match the target: "smoke" for a quick read or a small origin,
# "stress" for a client with real CDN/datacenter capacity.
_TIERS = {
    "smoke":    {"ramp": [2, 5, 10],            "hold": 0,  "desc": "lightest read — a small origin or a quick check"},
    "standard": {"ramp": [2, 5, 10, 25],        "hold": 10, "desc": "modest sustained load"},
    "thorough": {"ramp": [2, 5, 10, 25, 50],    "hold": 30, "desc": "real sustained load"},
    "stress":   {"ramp": [5, 10, 25, 50, 100],  "hold": 80, "desc": "datacenter-scale — sustained peak; can stress a small origin"},
}
DEFAULT_TIER = "smoke"

# CDN / WAF / edge fingerprints. Presence of any of these in the response
# headers means there's an edge in front of the origin absorbing traffic — the
# single biggest DDoS-resilience win a site can have. Maps a header (or a
# header+value marker) to the provider it identifies.
_EDGE_HEADER_KEYS = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-amz-cf-id": "AWS CloudFront",
    "x-amz-cf-pop": "AWS CloudFront",
    "x-served-by": "Fastly/Varnish",
    "x-fastly-request-id": "Fastly",
    "x-akamai-transformed": "Akamai",
    "x-akamai-request-id": "Akamai",
    "x-cache": "CDN cache layer",
    "x-cdn": "CDN",
    "x-azure-ref": "Azure Front Door",
    "x-msedge-ref": "Azure/MS edge",
    "fly-request-id": "Fly.io edge",
}
# Substrings that identify an edge from the Server: header value.
_EDGE_SERVER_MARKERS = {
    "cloudflare": "Cloudflare",
    "akamaighost": "Akamai",
    "varnish": "Varnish/Fastly",
    "ecs": "Edgecast/Verizon",
    "cloudfront": "AWS CloudFront",
    "envoy": "Envoy (edge proxy)",
    "awselb": "AWS ELB",
    "sucuri": "Sucuri",
    "incapsula": "Imperva Incapsula",
    "google frontend": "Google Front End",
    "gws": "Google Front End",
}
# Rate-limit signals in the response stream.
_RATELIMIT_HEADER_MARKERS = (
    "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining",
    "ratelimit-limit", "ratelimit-remaining", "x-rate-limit-limit",
)

# The well-known path an operator drops an ownership token at (HTTP method).
WELLKNOWN_PATH = "/.well-known/nucleus-loadtest.txt"
# The DNS name (prefixed to the target host) an operator sets a TXT record on.
DNS_TXT_PREFIX = "_nucleus-loadtest"


# ==========================================================================
# Percentiles / small stats — no numpy, this is stdlib-only like everything else.
# ==========================================================================
def _pct(sorted_vals: list, q: float) -> float:
    """Nearest-rank percentile of an already-sorted list. q in [0,100]."""
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return round(float(sorted_vals[0]), 1)
    rank = max(0, min(len(sorted_vals) - 1, int(round((q / 100.0) * (len(sorted_vals) - 1)))))
    return round(float(sorted_vals[rank]), 1)


def _summarize_latencies(latencies: list) -> dict:
    s = sorted(latencies)
    return {
        "count": len(s),
        "min": round(s[0], 1) if s else 0.0,
        "p50": _pct(s, 50),
        "p90": _pct(s, 90),
        "p95": _pct(s, 95),
        "p99": _pct(s, 99),
        "max": round(s[-1], 1) if s else 0.0,
    }


# ==========================================================================
# Ownership verification — optional proof of scope
# ==========================================================================
def make_token() -> str:
    """A fresh, unguessable ownership token the operator places on the target."""
    import secrets
    return "nucleus-loadtest-" + secrets.token_hex(16)


def verify_ownership(host: str, token: str, method: str) -> dict:
    """Confirm the operator controls `host` by finding `token` where only
    someone with control could put it. Returns {verified, method, detail}.

    Two methods, both keyless and passive:
      * "dns"  — a TXT record at _nucleus-loadtest.<host> containing the token.
      * "file" — the token inside https://<host>/.well-known/nucleus-loadtest.txt,
                 fetched through the SSRF-guarded path (so it only works for a
                 public host — same limitation the native probe has).

    This never blocks a run on its own; the caller decides. It exists so a
    report can carry an auditable "scope verified" stamp on a real engagement.
    """
    token = (token or "").strip()
    if not token:
        return {"verified": False, "method": method, "detail": "no token supplied"}

    if method == "dns":
        name = f"{DNS_TXT_PREFIX}.{host}"
        try:
            answers = common.dns_query(name, "TXT")
        except _FETCH_ERRORS as e:
            return {"verified": False, "method": "dns", "detail": f"TXT lookup failed: {e}"}
        for a in answers or []:
            if not isinstance(a, dict):
                continue  # tolerate any non-dict answer shape rather than 500
            data = str(a.get("data", "")).strip().strip('"')
            if token in data:
                return {"verified": True, "method": "dns", "detail": f"TXT {name} matched"}
        return {"verified": False, "method": "dns",
                "detail": f"no TXT record at {name} contained the token"}

    if method == "file":
        url = f"https://{host}{WELLKNOWN_PATH}"
        try:
            status, body, _ = common.fetch(url, timeout=8.0, max_bytes=4096)
        except _FETCH_ERRORS as e:
            return {"verified": False, "method": "file", "detail": f"fetch failed: {e}"}
        if status == 200 and token in body.decode("utf-8", "replace"):
            return {"verified": True, "method": "file", "detail": f"{WELLKNOWN_PATH} matched"}
        return {"verified": False, "method": "file",
                "detail": f"token not found at {url} (status {status})"}

    return {"verified": False, "method": method, "detail": f"unknown method '{method}'"}


# ==========================================================================
# The bounded ramp probe
# ==========================================================================
def _one_request(url: str) -> dict:
    """Fire a single timed GET through the SSRF-guarded fetch. Never raises —
    a failure is a sample with ok=False, so one dead request can't abort a step."""
    t0 = time.monotonic()
    try:
        status, _body, headers = common.fetch(url, timeout=REQ_TIMEOUT, max_bytes=PROBE_MAX_BYTES)
        ms = (time.monotonic() - t0) * 1000.0
        return {"ok": True, "status": status, "ms": ms, "headers": headers, "timeout": False}
    except ValueError as e:
        # Blocked host / bad scheme — should be impossible post-validation. Flag
        # it distinctly so the caller can hard-stop rather than counting it as
        # target distress.
        return {"ok": False, "status": 0, "ms": 0.0, "blocked": True, "err": str(e), "timeout": False}
    except (OSError, http.client.HTTPException) as e:
        ms = (time.monotonic() - t0) * 1000.0
        is_to = isinstance(e, TimeoutError) or "timed out" in str(e).lower()
        return {"ok": False, "status": 0, "ms": ms, "err": type(e).__name__, "timeout": is_to}


def _run_step(url: str, concurrency: int, n_requests: int, deadline: float) -> dict:
    """Fire `n_requests` GETs with up to `concurrency` in flight, timed as a
    block, but never past `deadline` (monotonic). Returns the step's aggregate
    sample. The deadline makes MAX_DURATION_S a real wall-clock ceiling *within*
    a step, not just between steps — a slow target (or a long redirect chain,
    each hop getting its own timeout) can't stretch one step past the cap. When
    the deadline hits we stop collecting and cancel anything not yet started;
    in-flight requests are each already bounded by REQ_TIMEOUT."""
    workers = max(1, min(concurrency, MAX_CONCURRENCY))
    t0 = time.monotonic()
    samples: list = []
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = [pool.submit(_one_request, url) for _ in range(n_requests)]
        for fut in as_completed(futures):
            samples.append(fut.result())
            if time.monotonic() >= deadline:
                break
    finally:
        # Don't block on stragglers past the deadline: drop queued work and
        # return; the few in-flight requests drain on their own REQ_TIMEOUT.
        pool.shutdown(wait=False, cancel_futures=True)
    wall = max(1e-6, time.monotonic() - t0)

    ok = [s for s in samples if s["ok"]]
    lat = [s["ms"] for s in ok]
    http_err = sum(1 for s in ok if s["status"] >= 500)
    conn_err = sum(1 for s in samples if not s["ok"] and not s.get("blocked"))
    timeouts = sum(1 for s in samples if s.get("timeout"))
    rate_limited = sum(1 for s in ok if s["status"] == 429)
    blocked = sum(1 for s in samples if s.get("blocked"))

    # Distress = the target failing to serve: 5xx + connection errors/timeouts.
    # 429s are NOT distress — they're the defense working, so they don't trip
    # the breaker. (A 503 that's actually a CDN challenge is conservatively
    # still counted here: stopping early on a wall of 503s is the safe call, and
    # the read-out notes when they carried edge/challenge markers.)
    distress = http_err + conn_err
    n = len(samples)
    distress_rate = distress / n if n else 0.0
    timeout_rate = timeouts / n if n else 0.0

    status_dist: dict = {}
    for s in ok:
        k = str(s["status"])
        status_dist[k] = status_dist.get(k, 0) + 1

    return {
        "concurrency": concurrency,
        "requests": len(samples),
        "ok": len(ok),
        "http_5xx": http_err,
        "conn_errors": conn_err,
        "timeouts": timeouts,
        "rate_limited": rate_limited,
        "blocked": blocked,
        "distress_rate": round(distress_rate, 3),
        "timeout_rate": round(timeout_rate, 3),
        "rps": round(len(samples) / wall, 1),
        "wall_s": round(wall, 2),
        "latency": _summarize_latencies(lat),
        "status_dist": status_dist,
        "_samples": ok,   # kept for header inspection; stripped before serialization
    }


def probe(url: str, tier: str = DEFAULT_TIER) -> dict:
    """Ramp a bounded L7 load probe against `url` and return a defensive
    read-out. Assumes the caller already validated the URL, confirmed scope,
    and passed the opsec gate — this only does the (capped) HTTP work. Never
    raises: an unreachable target becomes a clean 'unreachable' result.
    """
    spec = _TIERS.get(tier, _TIERS[DEFAULT_TIER])
    ramp = spec["ramp"]
    # levels = the ramp-up, then `hold` more steps AT PEAK to sustain the load.
    # The caps + circuit breaker end it; the trailing peak-holds only ever run if
    # the target is still healthy after the ramp.
    levels = list(ramp) + [ramp[-1]] * spec.get("hold", 0)

    # Baseline sanity: one request at concurrency 1. If we can't get a single
    # response, there's nothing to ramp — report unreachable instead of firing
    # hundreds of doomed requests at a host that isn't answering.
    base = _one_request(url)
    if base.get("blocked"):
        return {"ok": False, "error": f"blocked: {base.get('err')}"}
    if not base["ok"]:
        return {"ok": False,
                "error": f"unreachable: {base.get('err', 'no response')} — nothing to measure"}

    steps: list = []
    total = 0
    started = time.monotonic()
    deadline = started + MAX_DURATION_S
    aborted = None
    edge_headers_seen: dict = {}
    ratelimit_headers_seen: list = []
    challenge_seen: list = []
    server_header = ""

    # Fold the baseline response's headers into detection right away.
    _harvest_headers([base], edge_headers_seen, ratelimit_headers_seen, challenge_seen)
    server_header = _norm(base.get("headers", {})).get("server", server_header)

    for concurrency in levels:
        if time.monotonic() - started > MAX_DURATION_S:
            aborted = f"time cap reached ({MAX_DURATION_S:.0f}s) at concurrency {concurrency}"
            break
        n = concurrency * REQS_PER_WORKER
        if total + n > MAX_TOTAL_REQUESTS:
            n = MAX_TOTAL_REQUESTS - total
        if n <= 0:
            aborted = f"request cap reached ({MAX_TOTAL_REQUESTS}) before concurrency {concurrency}"
            break

        step = _run_step(url, concurrency, n, deadline)
        total += step["requests"]

        _harvest_headers(step.pop("_samples"), edge_headers_seen, ratelimit_headers_seen, challenge_seen)
        steps.append(step)

        # Mid-ramp SSRF block: if requests start coming back blocked, the host
        # stopped resolving to a public address (DNS rebind, or it went private)
        # mid-run. No packets reached a private host — the guard did its job —
        # but there's nothing left to measure, so stop instead of hammering a
        # now-blocked target with the rest of the ramp.
        if step["blocked"] > 0:
            aborted = (f"target stopped resolving to a public address at concurrency {concurrency} "
                       "(SSRF guard blocked it mid-ramp) — stopped")
            break

        # Circuit breaker — stop the moment the target is clearly failing.
        # Origin errors OR timeouts sustained past their thresholds both trip it.
        if step["requests"] >= CB_MIN_SAMPLE and (
                step["distress_rate"] >= CB_ERROR_RATE or step["timeout_rate"] >= CB_TIMEOUT_RATE):
            why = (f"{int(step['distress_rate'] * 100)}% 5xx/connection errors"
                   if step["distress_rate"] >= CB_ERROR_RATE
                   else f"{int(step['timeout_rate'] * 100)}% timeouts")
            aborted = (f"circuit breaker: {why} at concurrency {concurrency} "
                       "— stopped to avoid piling on a struggling target")
            break
        if total >= MAX_TOTAL_REQUESTS:
            aborted = f"request cap reached ({MAX_TOTAL_REQUESTS})"
            break

    return _assemble(url, tier, steps, total, aborted, edge_headers_seen,
                     ratelimit_headers_seen, challenge_seen, server_header)


def _norm(headers: dict) -> dict:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


def _harvest_headers(samples: list, edge_seen: dict, ratelimit_seen: list,
                     challenge_seen: list) -> None:
    """Pull edge / rate-limit / challenge signals out of a batch of responses."""
    for s in samples:
        h = _norm(s.get("headers", {}))
        status = s.get("status", 0)
        edge_here = False
        for key, provider in _EDGE_HEADER_KEYS.items():
            if key in h:
                edge_here = True
                if provider not in edge_seen.values():
                    edge_seen[key] = provider
        srv = h.get("server", "").lower()
        for marker, provider in _EDGE_SERVER_MARKERS.items():
            if marker in srv:
                edge_here = True
                if provider not in edge_seen.values():
                    edge_seen["server:" + marker] = provider
        for marker in _RATELIMIT_HEADER_MARKERS:
            if marker in h and marker not in ratelimit_seen:
                ratelimit_seen.append(marker)
        # A CDN challenge: a 403/503/429 that carries an explicit challenge
        # header, or a 403/503 sitting behind a detected edge. This is the edge
        # shedding load — a defense, not origin distress.
        if "cf-mitigated" in h and "cf-mitigated:challenge" not in challenge_seen:
            challenge_seen.append("cf-mitigated:challenge")
        elif status in (403, 503) and edge_here:
            tag = f"edge-{status}"
            if tag not in challenge_seen:
                challenge_seen.append(tag)


# ==========================================================================
# Read-out: detection verdicts + grade + remediation
# ==========================================================================
def _assemble(url, tier, steps, total, aborted, edge_seen, ratelimit_seen,
              challenge_seen, server_header) -> dict:
    all_lat = [v for st in steps for v in _step_latencies(st)]
    overall = _summarize_latencies(all_lat)

    total_ok = sum(st["ok"] for st in steps)
    total_5xx = sum(st["http_5xx"] for st in steps)
    total_conn = sum(st["conn_errors"] for st in steps)
    total_timeouts = sum(st["timeouts"] for st in steps)
    total_429 = sum(st["rate_limited"] for st in steps)
    peak_rps = max((st["rps"] for st in steps), default=0.0)
    distress = total_5xx + total_conn
    distress_rate = round(distress / total, 3) if total else 0.0

    # Degradation: p95 latency at the top completed step vs the first step. A
    # ratio near 1 means the target barely noticed the load (headroom /
    # autoscaling); a large ratio means it's straining.
    baseline_p95 = steps[0]["latency"]["p95"] if steps else 0.0
    peak_p95 = steps[-1]["latency"]["p95"] if steps else 0.0
    degradation = round(peak_p95 / baseline_p95, 2) if baseline_p95 > 0 else None

    rate_limited_detected = total_429 > 0 or bool(ratelimit_seen)
    challenge_detected = bool(challenge_seen)
    # "Active shedding" = the L7 layer refusing/challenging automated load, by
    # either a rate limit (429/headers) or an edge challenge (403/503+CDN). Both
    # are the decisive application-layer DDoS defense doing its job.
    shedding = rate_limited_detected or challenge_detected
    edge = sorted(set(edge_seen.values()))
    edge_present = bool(edge)

    verdicts = _verdicts(rate_limited_detected, challenge_detected, challenge_seen,
                         total_429, ratelimit_seen, edge, edge_present, degradation,
                         distress_rate, total_timeouts, aborted, server_header)
    findings = _findings(shedding, edge_present, degradation,
                         distress_rate, total_timeouts, aborted)
    letter, score = _grade(shedding, edge_present, degradation,
                           distress_rate, total_timeouts, aborted)

    return {
        "ok": True,
        "url": url,
        "tier": tier,
        "grade": letter,
        "score": score,
        "aborted": aborted,
        "totals": {
            "requests": total, "ok": total_ok, "http_5xx": total_5xx,
            "conn_errors": total_conn, "timeouts": total_timeouts,
            "rate_limited_429": total_429, "distress_rate": distress_rate,
            "peak_rps": peak_rps,
        },
        "latency_overall_ms": overall,
        "degradation_p95_ratio": degradation,
        "defenses": {
            "rate_limiting": {
                "detected": rate_limited_detected,
                "http_429_seen": total_429,
                "headers_seen": ratelimit_seen,
            },
            "challenge": {"detected": challenge_detected, "signals": challenge_seen},
            "edge": {"present": edge_present, "providers": edge},
            "server": server_header,
        },
        "steps": steps,
        "verdicts": verdicts,
        "findings": findings,
        "remediation": _remediation(shedding, edge_present, degradation,
                                    distress_rate, total_timeouts),
        "caps": {"max_concurrency": MAX_CONCURRENCY, "max_requests": MAX_TOTAL_REQUESTS,
                 "max_duration_s": MAX_DURATION_S},
        "notes": [
            "Native probe is a bounded diagnostic — a closed concurrency model, hard-capped at "
            f"{MAX_CONCURRENCY} in flight / {MAX_TOTAL_REQUESTS} counted requests / {MAX_DURATION_S:.0f}s wall "
            "clock (enforced during a step, not just between). Probes are serialized and per-host "
            "cooldown-paced so looping the endpoint can't aggregate past this. It locates whether defenses "
            "engage; it cannot and is not meant to overwhelm a healthy target.",
            "Requests follow up to a few redirects through the shared fetch, so a target on a redirect "
            "chain can see somewhat more wire requests than the counted figure — the wall-clock cap bounds "
            "the delivered load regardless of hop count.",
            "Latency is wall-clock per request (connect through full read of up to "
            f"{PROBE_MAX_BYTES} bytes) on a Connection: close client — state it when comparing to other tools.",
            "For true high-rate stress with an open arrival-rate model (correct tail latency, no "
            "coordinated omission) and a sustained hold long enough to observe autoscaling, use the "
            "load-test command builder (k6/vegeta) against a target you're authorized to test.",
        ],
    }


def _step_latencies(step: dict) -> list:
    """Reconstruct a representative latency list for a step from its summary —
    the raw per-request samples are dropped before this point (headers were the
    only reason to keep them), so overall percentiles are computed from the
    per-step percentile points weighted by count. Good enough for a headline;
    the per-step detail carries the exact percentiles."""
    lat = step["latency"]
    if not lat["count"]:
        return []
    # Represent the step by its five percentile points, repeated proportionally
    # so a heavier step weighs more in the overall figure.
    reps = max(1, lat["count"] // 5)
    return ([lat["min"]] * reps + [lat["p50"]] * reps + [lat["p90"]] * reps
            + [lat["p95"]] * reps + [lat["max"]] * reps)


def _verdicts(rate_limited, challenge_detected, challenge_seen, n429, rl_headers, edge,
              edge_present, degradation, distress_rate, timeouts, aborted, server_header) -> list:
    v = []
    if rate_limited:
        how = []
        if n429:
            how.append(f"{n429}×429")
        if rl_headers:
            how.append(", ".join(rl_headers))
        v.append({"area": "Rate limiting", "status": "good",
                  "detail": f"The target rate-limited the probe ({'; '.join(how)}). "
                            "Automated request floods get throttled — the main L7 defense is live."})
    elif challenge_detected:
        v.append({"area": "Rate limiting / challenge", "status": "good",
                  "detail": f"No hard rate limit seen, but the edge challenged the probe "
                            f"({', '.join(challenge_seen)}) — a WAF/CDN is intercepting automated load "
                            "before it reaches the origin."})
    else:
        v.append({"area": "Rate limiting", "status": "gap",
                  "detail": "No rate limiting or challenge observed — the target answered every request in "
                            "the ramp with no 429s, no rate-limit headers, and no edge challenge. An HTTP "
                            "flood would not be throttled."})
    if edge_present:
        v.append({"area": "Edge / CDN / WAF", "status": "good",
                  "detail": f"Traffic is fronted by {', '.join(edge)} — a scrubbing edge that absorbs "
                            "volumetric and L7 load before it reaches the origin."})
    else:
        v.append({"area": "Edge / CDN / WAF", "status": "gap",
                  "detail": "No CDN/WAF edge fingerprint in the responses" +
                            (f" (Server: {server_header})" if server_header else "") +
                            " — the origin appears to answer directly, with no edge to absorb a flood."})
    if degradation is not None:
        if degradation <= 1.5:
            v.append({"area": "Load headroom", "status": "good",
                      "detail": f"p95 latency held steady under the ramp (×{degradation} vs baseline) — "
                                "good headroom / autoscaling."})
        elif degradation <= 4:
            v.append({"area": "Load headroom", "status": "watch",
                      "detail": f"p95 latency rose ×{degradation} across the ramp — some strain, "
                                "limited headroom."})
        else:
            v.append({"area": "Load headroom", "status": "gap",
                      "detail": f"p95 latency blew up ×{degradation} under a light ramp — the origin "
                                "is close to its knee already; real load would tip it over."})
    if distress_rate > 0 or timeouts > 0:
        sev = "gap" if distress_rate >= 0.2 else "watch"
        v.append({"area": "Error behavior", "status": sev,
                  "detail": f"{int(distress_rate * 100)}% of requests failed (5xx/connection) "
                            f"with {timeouts} timeouts — the target dropped requests under a bounded probe."})
    if aborted and "circuit breaker" in aborted:
        v.append({"area": "Resilience", "status": "gap",
                  "detail": "The probe's circuit breaker tripped: the target started failing under a "
                            "diagnostic-level load. That's a resilience finding on its own."})
    return v


def _findings(shedding, edge_present, degradation, distress_rate, timeouts, aborted) -> list:
    f = []
    if not shedding:
        f.append({"severity": "high", "title": "No request rate limiting or edge challenge",
                  "detail": "The application served an automated request ramp with no throttling and no "
                            "WAF/CDN challenge. An HTTP GET/POST flood would consume origin resources unchecked."})
    if not edge_present:
        f.append({"severity": "high", "title": "Origin answers without a CDN/WAF edge",
                  "detail": "No edge provider was detected in the responses. Without a scrubbing layer, "
                            "volumetric and L7 floods hit the origin directly."})
    if degradation is not None and degradation > 4:
        f.append({"severity": "medium", "title": "Latency degrades sharply under light load",
                  "detail": f"p95 rose ×{degradation} across a bounded ramp — little headroom before saturation."})
    if distress_rate >= 0.2:
        f.append({"severity": "high", "title": "Requests dropped under a bounded probe",
                  "detail": f"{int(distress_rate * 100)}% of requests failed. The origin is already at its "
                            "limit under diagnostic load."})
    elif timeouts > 0:
        f.append({"severity": "medium", "title": "Timeouts under load",
                  "detail": f"{timeouts} requests timed out — connection or worker starvation under load."})
    sev_rank = {"high": 0, "medium": 1, "low": 2}
    f.sort(key=lambda x: sev_rank.get(x["severity"], 3))
    return f


def _grade(shedding, edge_present, degradation, distress_rate, timeouts, aborted) -> tuple:
    """Combine defense presence + behavior under load into A–F. Defenses are
    weighted heaviest (they're what stops a real attack); degradation and error
    behavior adjust from there. `shedding` = the L7 layer actively refusing or
    challenging automated load (rate limit OR edge challenge) — the decisive
    application-layer DDoS defense. Grading keys off WHERE errors come from: a
    target that sheds load at a present edge is "found the ceiling", not "broke"."""
    score = 0
    score += 45 if shedding else 0          # the decisive L7 defense (rate limit or challenge)
    score += 35 if edge_present else 0       # scrubbing edge
    # Behavior under load, worth 20.
    if degradation is None:
        score += 10
    elif degradation <= 1.5:
        score += 20
    elif degradation <= 4:
        score += 12
    else:
        score += 2
    # Penalties for actually dropping traffic during a diagnostic-level probe.
    if distress_rate >= 0.2:
        score -= 25
    elif distress_rate > 0 or timeouts > 0:
        score -= 8
    if aborted and "circuit breaker" in aborted:
        score -= 15
    score = max(0, min(100, score))
    letter = ("A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60
              else "D" if score >= 40 else "F")
    return letter, score


def _remediation(shedding, edge_present, degradation, distress_rate, timeouts) -> list:
    """Finding → concrete fix → how to verify. Only the items relevant to what
    this run actually found."""
    r = []
    if not shedding:
        r.append({
            "area": "Add rate limiting",
            "fix": "Throttle automated request floods at the edge and the app. Cloudflare Rate Limiting "
                   "Rules or AWS WAF rate-based rules at the edge; nginx `limit_req_zone` / `limit_conn` "
                   "or an API-gateway throttle at the app. Rate-limit expensive endpoints (login, search, "
                   "export) hardest.",
            "verify": "Re-run this probe — a healthy config returns 429s (with Retry-After) once the "
                      "ramp exceeds the configured rate."})
    if not edge_present:
        r.append({
            "area": "Put a scrubbing edge in front of the origin",
            "fix": "Front the site with a CDN/WAF that absorbs volumetric + L7 floods: Cloudflare (+ its "
                   "managed DDoS rules), Fastly, Akamai, or AWS CloudFront + AWS Shield / Shield Advanced, "
                   "or Google Cloud Armor. Then lock the origin firewall so it only accepts traffic from the "
                   "edge's IP ranges (or via an authenticated origin pull / Cloudflare Tunnel) so the origin "
                   "IP can't be hit directly to bypass the edge.",
            "verify": "Confirm CF-Ray / X-Cache / equivalent edge headers appear, and that the origin IP "
                      "refuses direct connections from off the edge."})
    if degradation is not None and degradation > 4:
        r.append({
            "area": "Add capacity headroom",
            "fix": "Horizontal autoscaling behind a load balancer, plus caching so repeat requests never "
                   "reach the origin (CDN cache + correct Cache-Control). Consider Anycast so load spreads "
                   "across PoPs. Profile and fix the expensive endpoints the ramp stressed.",
            "verify": "Re-run at the same tier and confirm p95 stays within ~1.5× of baseline."})
    if distress_rate > 0 or timeouts > 0:
        r.append({
            "area": "Fix connection / worker exhaustion",
            "fix": "Tune the web server against slow and bursty clients: nginx `client_body_timeout`, "
                   "`client_header_timeout`, `reset_timedout_connection on`, `keepalive_timeout`, and per-IP "
                   "`limit_conn`; Apache `mod_reqtimeout`; enable SYN cookies (`net.ipv4.tcp_syncookies=1`). "
                   "Raise worker/connection pools and put a buffering reverse proxy ahead of the app so a "
                   "slow client can't hold an app worker.",
            "verify": "Re-run and confirm 0% dropped requests / timeouts at the same tier."})
    # HTTP/2 Rapid Reset — always worth flagging; this stdlib HTTP/1.1 probe
    # can't test it, so it's advisory (delegate to a dedicated HTTP/2 check).
    r.append({
        "area": "HTTP/2 Rapid Reset (CVE-2023-44487) — verify separately",
        "fix": "If the origin/edge speaks HTTP/2, make sure it caps per-connection stream churn: patched "
               "nginx/Envoy/Go/nghttp2, and a bound on concurrent + reset streams per connection. This "
               "HTTP/1.1 probe can't exercise it — test it with a dedicated HTTP/2 tool (h2load, or the "
               "vendor's own check) on one or a few real connections, never distributed.",
        "verify": "Confirm the HTTP/2 stack version is past the Oct-2023 fixes and that rapid open+RST_STREAM "
                  "on a single connection gets throttled, not served unbounded."})
    # Always-on scope reminder about what this L7 tool does and doesn't cover.
    r.append({
        "area": "Layer 3/4 volumetric (out of this tool's scope)",
        "fix": "This probe tests application-layer (L7) resilience only. Volumetric floods (UDP/ICMP/"
               "amplification) and protocol attacks (SYN floods) are stopped upstream of the origin: "
               "provider scrubbing (AWS Shield Advanced, Cloudflare Magic Transit, Akamai Prolexic), always-on "
               "Anycast, and network ACLs / BGP Flowspec. Verify the client has an upstream scrubbing story.",
        "verify": "Confirm with the hosting/transit provider that L3/4 scrubbing is enabled — it can't be "
                  "measured safely from a single host, and shouldn't be attempted from one."})
    return r


# ==========================================================================
# Command builder — real capacity/stress testing, delegated, never executed
# ==========================================================================
def _shq(v) -> str:
    import shlex
    s = "" if v is None else str(v).replace("\n", " ").replace("\r", " ").strip()
    return shlex.quote(s[:2048])


def _int_field(v, default: str) -> str:
    """Digits only. Numeric params (rate/concurrency/threads/requests) get
    sanitized to a bare integer before they're embedded — the shell engines
    shlex-quote on top, but the k6 script embeds them RAW into JS, so a stray
    quote/newline in one of these must not be able to inject a second statement."""
    s = "".join(ch for ch in str(v) if ch.isdigit())
    return s or default


def _dur_field(v, default: str) -> str:
    """A load-test duration like 30s / 5m / 1h — digits plus a unit suffix only,
    for the same raw-embed safety reason as _int_field."""
    s = "".join(ch for ch in str(v).lower() if ch.isdigit() or ch in "smh")
    return s or default


def build_loadtest(engine: str, params: dict) -> dict:
    """Assemble a copy-paste command for an industry-standard load generator.
    Never runs anything — mirrors builder.py: every field is shlex-quoted so a
    malformed value can't become a second shell command when pasted.

    These tools do the heavy, high-rate stress testing the native probe
    deliberately won't. Run them yourself, against a target you're authorized
    to test, from infrastructure your engagement allows — and prefer verifying
    target ownership first (the DNS/well-known token above).
    """
    raw_url = params.get("url") or params.get("target") or "<URL>"
    # Strip CR/LF and cap length before the URL goes anywhere — the shell
    # engines get shlex.quote on top (below); k6 embeds it via repr() into a JS
    # string, and cleaning newlines here stops a multi-line break-out of that
    # string even though the builder never executes anything.
    url = str(raw_url).replace("\n", " ").replace("\r", " ").strip()[:2048]
    urlq = _shq(url)
    rate = _int_field(params.get("rate"), "50")
    duration = _dur_field(params.get("duration"), "30s")
    concurrency = _int_field(params.get("concurrency"), "50")

    if engine == "k6":
        vus = concurrency
        # k6 uses a JS script; emit an inline ramped scenario the operator saves.
        script = (
            "import http from 'k6/http';\n"
            "import { check, sleep } from 'k6';\n"
            "export const options = {\n"
            "  stages: [\n"
            f"    {{ duration: '10s', target: {vus} }},   // ramp up\n"
            f"    {{ duration: '{duration}', target: {vus} }}, // steady state\n"
            "    { duration: '10s', target: 0 },    // ramp down\n"
            "  ],\n"
            "  thresholds: { http_req_duration: ['p(95)<800'], http_req_failed: ['rate<0.05'] },\n"
            "};\n"
            "export default function () {\n"
            f"  const res = http.get({url!r});\n"
            "  check(res, { 'status < 500': (r) => r.status < 500 });\n"
            "  sleep(1);\n"
            "}\n"
        )
        return {"engine": "k6",
                "files": [{"name": "loadtest.js", "content": script}],
                "command": "k6 run loadtest.js",
                "note": "Grafana k6 — ramped stages with p95 + error-rate thresholds. Save the script, "
                        "then run it. Adjust target VUs/duration to the intensity your engagement authorizes."}

    if engine == "vegeta":
        # Quote the whole "GET <url>" target line as ONE argument to echo —
        # never `echo 'GET {url}'` with the url pasted between literal quotes,
        # which a single-quote in the url would break straight out of.
        target_line = _shq("GET " + url)
        cmd = (f"echo {target_line} | vegeta attack -rate={_shq(rate)} -duration={_shq(duration)} "
               "| vegeta report")
        return {"engine": "vegeta", "command": cmd,
                "note": "Vegeta — constant-rate attack (requests/sec, not concurrency). `-rate` is the "
                        "sustained RPS; add `| tee results.bin | vegeta report -type='hist[0,100ms,200ms,"
                        "500ms,1s]'` for a latency histogram."}

    if engine == "hey":
        n = _int_field(params.get("requests"), "2000")
        cmd = f"hey -z {_shq(duration)} -c {_shq(concurrency)} {urlq}"
        return {"engine": "hey", "command": cmd,
                "note": f"hey — {concurrency} concurrent workers for {duration}. Use `-n {n}` instead of "
                        "`-z` to bound by request count. `-q` caps per-worker QPS."}

    if engine == "wrk":
        threads = _int_field(params.get("threads"), "4")
        cmd = f"wrk -t{_shq(threads)} -c{_shq(concurrency)} -d{_shq(duration)} --latency {urlq}"
        return {"engine": "wrk", "command": cmd,
                "note": f"wrk — {threads} threads holding {concurrency} connections for {duration}, with a "
                        "latency distribution. High throughput from one box; watch your own NIC/CPU."}

    if engine == "ab":
        n = _int_field(params.get("requests"), "1000")
        cmd = f"ab -n {_shq(n)} -c {_shq(concurrency)} {urlq if url.endswith('/') else _shq(url + '/')}"
        return {"engine": "ab", "command": cmd,
                "note": "ApacheBench — simplest smoke test; note ab needs a trailing slash on a bare host "
                        "and is single-threaded, so it under-loads vs wrk/k6. Good for a quick sanity pass."}

    return {"engine": engine, "command": f"# unknown engine '{engine}'",
            "note": f"Known engines: k6, vegeta, hey, wrk, ab."}


# ==========================================================================
# HTTP handlers
# ==========================================================================
def handle_stress_token(req) -> "common.Response":
    """POST /api/stress-token  ->  a fresh ownership token + placement instructions.
    Touches no target; just mints a token for the operator to place."""
    token = make_token()
    body = req.json()
    host = ""
    raw = body.get("target") or body.get("url")
    if isinstance(raw, str) and raw:
        ok, host_or_reason, _ = runners.validate_url(raw) if "://" in raw else (
            *runners.validate_host(raw), raw)
        if ok:
            host = host_or_reason
    return common.Response.json({
        "token": token,
        "dns": {"name": f"{DNS_TXT_PREFIX}.{host or '<host>'}", "type": "TXT", "value": token},
        "file": {"url": f"https://{host or '<host>'}{WELLKNOWN_PATH}", "content": token},
        "note": "Place EITHER the DNS TXT record or the well-known file, then verify. This proves you "
                "control the target and stamps the report with scope. It's optional — the authorization "
                "checkbox is the actual gate.",
    })


def handle_stress_verify(req) -> "common.Response":
    """POST /api/stress-verify  {url|target, token, method, authorized}  ->  {verified,...}.

    Gated like the rest of the console: verifying ownership is part of an
    engagement's setup and (via the file method) touches the target, so it needs
    the same authorized:true assertion. Minting a token (/api/stress-token)
    touches nothing and stays ungated."""
    body = req.json()
    raw = body.get("url") or body.get("target")
    token = body.get("token")
    method = str(body.get("method") or "dns")
    if body.get("authorized") is not True:
        return common.Response.error(403,
            "authorized:true is required — confirm you have permission to test this target.")
    if not isinstance(raw, str) or not raw:
        return common.Response.error(400, "target is required")
    if "://" in raw:
        ok, host_or_reason, _ = runners.validate_url(raw)
    else:
        ok, host_or_reason = runners.validate_host(raw)
    if not ok:
        return common.Response.error(400, f"invalid target: {host_or_reason}")
    if not isinstance(token, str) or not token:
        return common.Response.error(400, "token is required")
    # The "file" method fetches the target's well-known URL, which touches it from
    # your real IP — apply the opsec gate so verification can't leak your IP while
    # exposed. The "dns" method contacts a resolver, not the target, so it isn't
    # gated. proceed_exposed overrides, same as everywhere else.
    if method == "file":
        blocked = runners.opsec_gate(lab=False, body=body)
        if blocked is not None:
            return blocked
    result = verify_ownership(host_or_reason, token, method)
    return common.Response.json(result)


def handle_stress_build(req) -> "common.Response":
    """POST /api/stress-build  {engine, params}  ->  a copy-paste load-test command.
    Builds only — never executes (mirrors /api/build)."""
    body = req.json()
    engine = str(body.get("engine") or "k6")
    params = body.get("params")
    if not isinstance(params, dict):
        params = {}
    result = build_loadtest(engine, params)
    result["executed"] = False
    return common.Response.json(result)


def handle_stress_probe(req) -> "common.Response":
    """POST /api/stress-probe  {url, authorized, lab, tier, verify?, proceed_exposed}
       ->  a bounded resilience read-out.

    Same gate stack as the runners and the native web tools: authorized:true,
    validated + public target, opsec gate, then the hard caps + circuit breaker
    inside probe(). The native probe only reaches public targets (the SSRF guard
    refuses private/loopback), so opsec ALWAYS applies here — 'lab' doesn't buy a
    bypass the way it does for a private-target runner; only proceed_exposed does.
    Optional `verify:{token,method}` stamps scope; a supplied-but-failing verify
    is refused so the stamp can't be faked.
    """
    body = req.json()
    target_raw = body.get("url") or body.get("target")
    authorized = body.get("authorized") is True
    lab = body.get("lab") is True
    tier = str(body.get("tier") or DEFAULT_TIER)
    if tier not in _TIERS:
        return common.Response.error(400, f"invalid tier: must be one of {sorted(_TIERS)}")

    if not authorized:
        return common.Response.error(403,
            "authorized:true is required — confirm you have permission to load-test this target.")
    if not isinstance(target_raw, str):
        return common.Response.error(400, "url must be a string")

    ok, host_or_reason, cleaned = runners.validate_url(target_raw)
    if not ok:
        return common.Response.error(400, f"invalid target: {host_or_reason}")

    in_scope, reason = runners.scope_check(host_or_reason, lab)
    if not in_scope:
        return common.Response.error(403, reason)

    # The native probe fetches through the SSRF guard — it only ever reaches a
    # PUBLIC target. A private/loopback host (the one way a lab:true target gets
    # this far past scope_check) is refused here; point at the command builder,
    # whose k6/wrk/etc. connect directly and reach internal hosts.
    if not common.host_is_public(host_or_reason):
        return common.Response.error(400,
            "The native probe fetches through the SSRF guard, which refuses private/loopback targets "
            "even in lab mode. For an internal/staging host, use the command builder (k6/vegeta/hey/wrk/ab) "
            "— those connect directly and reach lab targets.")

    # The target is public, so the opsec gate ALWAYS applies — a load test must
    # never fire from an exposed IP just because 'lab' was ticked. 'lab' can't
    # mean "my private network" here (the SSRF guard refused any private target
    # above), so it must not buy an opsec bypass; only the honest proceed_exposed
    # override does. (Passing lab=False forces the gate on regardless of the box.)
    blocked = runners.opsec_gate(lab=False, body=body)
    if blocked is not None:
        return blocked

    # Optional proof-of-scope. If the caller claims a verification, it must hold.
    verify_result = None
    verify_req = body.get("verify")
    if isinstance(verify_req, dict) and verify_req.get("token"):
        verify_result = verify_ownership(host_or_reason, str(verify_req.get("token")),
                                         str(verify_req.get("method") or "dns"))
        if not verify_result.get("verified"):
            return common.Response.json({
                "error": "ownership verification was requested but failed — refusing to stamp an "
                         "unverified scope. Fix the token placement or drop the verify block to run "
                         "on the authorization checkbox alone.",
                "status": 403, "verify": verify_result,
            }, status=403)

    # Re-resolve immediately before firing (DNS-rebind recheck tier). The target
    # is guaranteed public by the check above, so this always runs. Keep the
    # resolved IPs — the cooldown keys on them, not the hostname.
    probe_ips = runners._resolve_public_ips_safe(host_or_reason)
    if not probe_ips:
        return common.Response.error(403,
            "target no longer resolves to a public address (re-checked before the probe) — refusing")

    # SERIALIZE + COOLDOWN. The per-run caps bound one probe; this bounds the
    # aggregate. Only one probe runs at a time (a concurrent fan-out is refused,
    # not queued), and back-to-back runs against the same host wait out a short
    # cooldown — so looping the endpoint can't stack probes into real load.
    if not _PROBE_LOCK.acquire(blocking=False):
        return common.Response.json({
            "error": "a resilience probe is already running — they run one at a time so load can't stack. "
                     "Wait for it to finish.", "status": 409}, status=409)
    try:
        # Cooldown keys on the resolved IP(s), not the hostname — two names behind
        # one origin (shared LB/CDN) must share the cooldown so an alias can't be
        # used to fire back-to-back probes at the same box with no gap.
        cd_keys = probe_ips or [host_or_reason]
        last_end = max((_LAST_PROBE_END[k] for k in cd_keys if k in _LAST_PROBE_END), default=None)
        if last_end is not None:
            since = time.monotonic() - last_end
            if since < _PROBE_COOLDOWN_S:
                wait = round(_PROBE_COOLDOWN_S - since, 1)
                return common.Response.json({
                    "error": f"cooling down after the last probe of this origin — retry in {wait}s. "
                             "(Paces back-to-back runs so a loop can't aggregate into real load.)",
                    "status": 429, "retry_after_s": wait}, status=429)
        result = probe(cleaned, tier)
        stamp = time.monotonic()
        for k in cd_keys:
            _LAST_PROBE_END[k] = stamp
    finally:
        _PROBE_LOCK.release()

    if verify_result:
        result["scope_verified"] = verify_result

    # Audit, consistent with the runners (respects NUCLEUS_LOGGING; off by
    # default). Log host/tier/grade/counts — never a querystring (can carry a token).
    if result.get("ok"):
        p = urlparse(cleaned)
        runners._append_audit({
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": "stress-probe", "target": f"{p.scheme}://{p.netloc}{p.path}",
            "authorized": authorized, "lab": lab, "tier": tier,
            "grade": result.get("grade"), "totals": result.get("totals", {}),
            "scope_verified": bool(verify_result and verify_result.get("verified")),
        })
    return common.Response.json(result)
