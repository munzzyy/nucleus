"""Subdomain takeover checker — 100% passive: a CNAME lookup plus, for
HTTP-fingerprinted services, one GET per subdomain.

Follows each subdomain's CNAME chain (over encrypted DoH, same resolvers
`common.dns_query` uses) to see whether it points at a third-party host that
looks abandoned — the classic dangling-DNS bug: a CNAME still points at
`something.github.io` / `something.s3.amazonaws.com` / etc long after that
resource was deleted, and whoever registers the same name on that service can
now serve content under the victim's own domain.

Every service in the table below is checked two ways:
  * DNS-only (Azure's whole family): the takeover signal IS the CNAME target
    itself failing to resolve (NXDOMAIN) — there's no page to fetch.
  * HTTP-fingerprinted (everyone else): one GET through `common.fetch` (the
    same SSRF-guarded path every other outbound call in this app uses) and a
    substring match against that service's documented "unclaimed resource"
    page text.

Fingerprints and per-service exploitability notes are sourced from
EdOverflow's `can-i-take-over-xyz` project (the community-maintained
reference for this class of bug) — a fingerprint match alone does not always
mean "exploitable right now" (some services since added ownership
verification), so every match carries a verdict of vulnerable / likely / safe
plus the specific caveat for that service, not a blanket "found it."

No authorization gate here — this whole console is passive/public-source
OSINT (same posture as `lookups.py`'s domain_scan/ip_scan), not the
active-tooling gate redcell's runners use.
"""

from __future__ import annotations

import concurrent.futures
import http.client
import json
import re
import urllib.parse
from dataclasses import dataclass
from typing import Optional

from shared import common

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

_MAX_SUBS_PER_REQUEST = 200
_CONCURRENCY = 12
_BUDGET_SECONDS = 45.0
_CNAME_MAX_HOPS = 8
_FETCH_TIMEOUT = 8.0
_DNS_TIMEOUT = 5.0
_DOH_STATUS_NXDOMAIN = 3


@dataclass(frozen=True)
class TakeoverService:
    name: str
    cname_markers: tuple            # substrings identifying this service in a CNAME target (lower)
    fingerprint: str = ""           # substring searched in the response body (lower); "" for DNS-only
    provider_status: str = "vulnerable"   # "vulnerable" | "edge_case" | "not_vulnerable"
    dns_only: bool = False          # True: verdict comes from the CNAME target's own NXDOMAIN, not a fetch
    note: str = ""


# Data sourced from EdOverflow/can-i-take-over-xyz (fingerprints.json), the
# community reference for this bug class. `provider_status` mirrors that
# project's own classification of whether the fingerprint alone still proves
# an exploitable takeover today.
SERVICES: tuple[TakeoverService, ...] = (
    TakeoverService("GitHub Pages", ("github.io",),
        "there isn't a github pages site here.", "edge_case",
        note="The CNAME target repo/org looks unclaimed, but you still need to create a GitHub Pages "
             "site under that exact name yourself to finish the takeover."),
    TakeoverService("Heroku", ("herokuapp.com", "herokudns.com", "herokussl.com"),
        "no such app", "edge_case",
        note="The Heroku app matching this name has been deleted. Claim it by creating an app with "
             "that exact (case-sensitive) name, if it's still free."),
    TakeoverService("Shopify", ("myshopify.com",),
        "sorry, this shop is currently unavailable.", "edge_case",
        note="Store handle looks unclaimed; a new Shopify store using the matching handle can claim it."),
    TakeoverService("Zendesk", ("zendesk.com",),
        "help center closed", "not_vulnerable",
        note="Zendesk added subdomain-ownership verification — this fingerprint alone no longer proves "
             "a takeover is possible."),
    TakeoverService("Surge.sh", ("surge.sh",),
        "project not found", "vulnerable",
        note="The `surge` CLI can claim this domain directly on republish — still exploitable."),
    TakeoverService("Netlify", ("netlify.app", "netlify.com"),
        "not found - request id:", "edge_case",
        note="A generic Netlify 404 can also mean a real, still-owned site with no page at '/' — confirm "
             "the SITE itself (not just the path) is unclaimed before relying on this."),
    TakeoverService("Pantheon", ("pantheon.io", "pantheonsite.io"),
        "404 error unknown site!", "vulnerable"),
    TakeoverService("Tumblr", ("domains.tumblr.com",),
        "whatever you were looking for doesn't currently exist", "edge_case",
        note="The domain needs to be added to a Tumblr blog you control to finish the claim."),
    TakeoverService("Unbounce", ("unbouncepages.com",),
        "the requested url was not found on this server.", "not_vulnerable",
        note="That text is a generic Apache 404, not Unbounce-specific — treat a match here as noise."),
    TakeoverService("WordPress.com", ("wordpress.com",),
        "do you want to register", "vulnerable"),
    TakeoverService("Fastly", ("fastly.net", "fastlylb.net"),
        "fastly error: unknown domain:", "not_vulnerable",
        note="Fastly requires proving TLS control of the domain before it'll serve it — this fingerprint "
             "alone doesn't hand over the service."),
    TakeoverService("AWS S3", ("s3.amazonaws.com", "s3-website", "s3.dualstack"),
        "the specified bucket does not exist", "vulnerable",
        note="Create an S3 bucket with the exact name the CNAME expects (matching region/endpoint) to claim it."),
    TakeoverService("Bitbucket Pages", ("bitbucket.io",),
        "repository not found", "vulnerable"),
    TakeoverService("Ghost(Pro)", ("ghost.io",),
        "site unavailable", "vulnerable"),
    TakeoverService("Cargo Collective", ("cargocollective.com",),
        "404 not found", "vulnerable",
        note="'404 Not Found' is a generic string other stacks share too — corroborate with the CNAME "
             "before trusting this alone."),
    TakeoverService("Fly.io", ("fly.dev",),
        "404 not found", "not_vulnerable",
        note="Fly.io reclaims released app names quickly and requires app-level ownership — this "
             "fingerprint alone doesn't indicate an exploitable takeover."),
    TakeoverService("Statuspage", ("statuspage.io",),
        "", "not_vulnerable",
        note="No reliable public body fingerprint exists for Statuspage's unclaimed state — flagged for "
             "manual review only."),
    TakeoverService("Squarespace", ("squarespace.com", "sqsp.net"),
        "", "not_vulnerable",
        note="No reliable public takeover fingerprint exists for Squarespace — flagged for manual review only."),
    TakeoverService("Azure", ("cloudapp.net", "azurewebsites.net", "azure-api.net",
                              "blob.core.windows.net", "trafficmanager.net",
                              "azureedge.net", "azurefd.net", "cloudapp.azure.com"),
        "", "vulnerable", dns_only=True,
        note="Azure's own takeover signal is an NXDOMAIN on the CNAME target itself, not a page body."),
    TakeoverService("AWS Elastic Beanstalk", ("elasticbeanstalk.com",),
        "", "vulnerable", dns_only=True,
        note="Same DNS-only signal as Azure — an NXDOMAIN on the CNAME target means the environment "
             "behind it has been terminated and the name is free to re-register."),
)


def _doh_lookup_with_status(name: str, rtype: str, timeout: float = _DNS_TIMEOUT) -> tuple[list[dict], Optional[int]]:
    """Like common.dns_query, but keeps the raw DNS response Status code
    (0=NOERROR, 3=NXDOMAIN, ...) instead of discarding it. Needed for the
    Azure family, where the takeover signal IS an NXDOMAIN on the CNAME
    target — common.dns_query collapses that into the same bare [] it
    returns for a healthy-but-empty answer, which is exactly the ambiguity
    this check can't afford. Mirrors lookups.py's `_dns_query_ex` reasoning
    for the same "recon needs the Status code, common.py doesn't" split."""
    name = (name or "").strip().rstrip(".")
    if not name:
        return [], None
    for base, accept in common._DOH_ENDPOINTS:
        url = f"{base}?name={urllib.parse.quote(name)}&type={urllib.parse.quote(rtype)}"
        headers = {"Accept": accept} if accept else {"Accept": "application/json"}
        try:
            status, resp_body, _ = common.fetch(url, timeout=timeout, headers=headers)
        except (ValueError, OSError, TimeoutError, http.client.HTTPException):
            continue
        if status != 200:
            continue
        try:
            data = json.loads(resp_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        return data.get("Answer") or [], data.get("Status")
    return [], None


def _cname_chain(name: str, max_hops: int = _CNAME_MAX_HOPS) -> list[str]:
    """Follow CNAME records to the end (or until max_hops / a loop). Some
    takeover-prone chains go through an intermediate CNAME before reaching
    the vulnerable third-party hostname, so a single-hop lookup can miss it."""
    chain: list[str] = []
    seen: set[str] = set()
    current = name.strip().rstrip(".")
    for _ in range(max_hops):
        if not current or current in seen:
            break
        seen.add(current)
        answers = common.dns_query(current, "CNAME")
        targets = [a.get("data", "").rstrip(".") for a in answers if a.get("data")]
        if not targets:
            break
        target = targets[0]
        chain.append(target)
        current = target
    return chain


def _match_service(cname_target: str) -> Optional[TakeoverService]:
    t = cname_target.lower()
    for svc in SERVICES:
        if any(marker in t for marker in svc.cname_markers):
            return svc
    return None


def _error_result(sub: str, reason: str) -> dict:
    return {"subdomain": sub, "cname_chain": [], "service": None, "verdict": "error",
            "http_status": None, "evidence": [reason], "note": ""}


def check_subdomain(sub: str) -> dict:
    """One subdomain's takeover verdict: 'vulnerable' | 'likely' | 'safe' |
    'error', with the evidence that produced it. Never raises — every
    network failure mode degrades to a result dict."""
    sub = (sub or "").strip().rstrip(".")
    if not sub:
        return _error_result(sub, "empty subdomain")

    result = {"subdomain": sub, "cname_chain": [], "service": None,
              "verdict": "safe", "http_status": None, "evidence": [], "note": ""}

    chain = _cname_chain(sub)
    result["cname_chain"] = chain
    if not chain:
        result["evidence"].append(
            "no CNAME record (direct A/AAAA, or unresolvable) — CNAME-based takeover check doesn't apply")
        return result

    final_target = chain[-1]
    svc = _match_service(final_target)
    if svc is None:
        result["evidence"].append(f"CNAME points to {final_target}, not a recognized takeover-prone service")
        return result

    result["service"] = svc.name
    result["note"] = svc.note

    if svc.dns_only:
        answers, dns_status = _doh_lookup_with_status(final_target, "A")
        if not answers:
            answers6, dns_status6 = _doh_lookup_with_status(final_target, "AAAA")
            if answers6:
                answers, dns_status = answers6, dns_status6
        if not answers and dns_status == _DOH_STATUS_NXDOMAIN:
            result["verdict"] = "vulnerable"
            result["evidence"].append(
                f"{final_target} does not resolve (NXDOMAIN) — the Azure resource behind this CNAME "
                "has been deleted or released")
        elif not answers:
            result["verdict"] = "likely"
            result["evidence"].append(
                f"{final_target} returned no A/AAAA record (DNS status={dns_status}) — inconclusive, "
                "but consistent with a released resource")
        else:
            result["verdict"] = "safe"
            result["evidence"].append(f"{final_target} still resolves — resource appears claimed")
        return result

    url = f"https://{sub}/"
    try:
        status, resp_body, _headers = common.fetch(url, timeout=_FETCH_TIMEOUT, max_bytes=200_000)
    except ValueError as e:
        result["verdict"] = "error"
        result["evidence"].append(f"blocked: {e}")
        return result
    except (OSError, http.client.HTTPException) as e:
        result["verdict"] = "likely"
        result["evidence"].append(
            f"connection failed ({type(e).__name__}: {e}) while the CNAME still points to {svc.name} — "
            "consistent with, but not proof of, an unclaimed resource")
        return result

    result["http_status"] = status
    text = resp_body.decode("utf-8", "replace").lower()

    if svc.fingerprint and svc.fingerprint in text:
        result["evidence"].append(f"response body matches the known {svc.name} 'unclaimed' fingerprint")
        if svc.provider_status == "vulnerable":
            result["verdict"] = "vulnerable"
        elif svc.provider_status == "edge_case":
            result["verdict"] = "likely"
        else:
            result["verdict"] = "safe"
            result["evidence"].append("fingerprint matched, but this provider isn't exploitable via this "
                                       "signal alone — see note")
    else:
        result["verdict"] = "safe"
        result["evidence"].append(f"{svc.name} fingerprint not found — resource appears claimed")
    return result


def _check_many(subs: list[str]) -> list[dict]:
    """Bounded-concurrency batch check with a global wall-clock budget.
    Whatever hasn't finished when the budget runs out gets a timeout
    placeholder instead of blocking the response indefinitely — same
    shutdown(wait=False, cancel_futures=True) shape lookups.py's
    username_scan uses for the same reason."""
    if not subs:
        return []
    results_by_sub: dict[str, dict] = {}
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=min(_CONCURRENCY, len(subs)))
    try:
        futures = {ex.submit(check_subdomain, s): s for s in subs}
        try:
            for fut in concurrent.futures.as_completed(futures, timeout=_BUDGET_SECONDS):
                s = futures[fut]
                try:
                    results_by_sub[s] = fut.result()
                except Exception as e:  # a single subdomain bug must not sink the whole batch
                    results_by_sub[s] = _error_result(s, f"{type(e).__name__}: {e}")
        except concurrent.futures.TimeoutError:
            pass  # budget exhausted -- whatever finished stays; stragglers get a placeholder below
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return [results_by_sub.get(s) or _error_result(s, "timed out before this subdomain could be checked")
            for s in subs]


def handle_takeover(req) -> "common.Response":
    """POST /api/takeover  {domain, subdomains: [...]}  ->  per-subdomain
    CNAME-takeover verdicts. Either field alone is enough (a bare `domain`
    checks just that one name; `subdomains` is meant for a list already
    gathered elsewhere, e.g. recon's own crt.sh subdomain scan)."""
    body = req.json()
    domain = str(body.get("domain") or "").strip().rstrip(".").lower()
    subs_in = body.get("subdomains")

    if not domain and not isinstance(subs_in, list):
        return common.Response.error(400, "provide a domain and/or a subdomains list")

    subs: list[str] = []
    if domain:
        subs.append(domain)
    if isinstance(subs_in, list):
        for s in subs_in:
            if isinstance(s, str) and s.strip():
                subs.append(s.strip().rstrip(".").lower())

    seen: set[str] = set()
    ordered: list[str] = []
    for s in subs:
        if s not in seen:
            seen.add(s)
            ordered.append(s)
    subs = ordered

    if not subs:
        return common.Response.error(400, "no valid subdomains to check")
    if len(subs) > _MAX_SUBS_PER_REQUEST:
        return common.Response.error(400, f"too many subdomains (max {_MAX_SUBS_PER_REQUEST} per request)")
    for s in subs:
        if not _HOSTNAME_RE.match(s):
            return common.Response.error(400, f"'{s}' is not a valid hostname")

    results = _check_many(subs)
    counts: dict[str, int] = {"vulnerable": 0, "likely": 0, "safe": 0, "error": 0}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1

    return common.Response.json({
        "domain": domain, "checked": len(results), "results": results, "counts": counts,
    })
