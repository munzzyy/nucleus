"""Passive tech-stack fingerprinter — hand-rolled, Wappalyzer-style.

Takes one HTTP response (headers + body, whatever `common.fetch` already
pulled back) and runs a table of signatures over it: response headers,
cookie NAMES (never values — a value can carry a session token, a name never
should), the HTML's meta-generator tag, and every `<script src="...">` path.
No JavaScript execution, no DOM, no extra requests: everything here is a
regex/substring pass over bytes that already arrived.

This module makes AT MOST one outbound request of its own (via
`handle_tech_fingerprint`'s own `url` path) — or zero, if the caller already
has a fetched response in hand and passes `headers`/`body` directly instead.
That second shape exists so another tool that already GET'd the page (the web
analyzer, the secret scanner) can hand this module its response instead of
firing a second request at the same target for the same page.

The signature table trades completeness for honesty: every entry is a
publicly documented, stable signal (a header a stack is known to set, a path
its bundler is known to use, a cookie name its session middleware is known to
mint) — not a guess. A hit only ever means "this evidence matched," which is
exactly what the `evidence` field says back.
"""

from __future__ import annotations

import http.client
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from shared import common
from consoles.redcell import runners

_FETCH_ERRORS = (OSError, http.client.HTTPException)  # ValueError ("blocked") is caught separately below

_LAB_PRIVATE_MSG = (
    "The tech fingerprinter fetches through common.fetch's SSRF guard, which refuses "
    "private/loopback/link-local targets even in lab mode. For an internal/staging host, "
    "fetch it yourself and pass {headers, body} directly instead of {url, ...} — this tool "
    "never needs live network access to fingerprint a response you already have.")


@dataclass(frozen=True)
class Sig:
    name: str
    category: str                       # server | cdn-waf | cms | framework | language | js-library | analytics
    confidence: str = "medium"          # bumped to "high" automatically on 2+ independent hits
    header_has: tuple = ()              # header names (lower) whose mere PRESENCE is the signal
    header_contains: tuple = ()         # (header name lower, needle lower) — substring of the header VALUE
    cookie_contains: tuple = ()         # substrings searched against cookie NAMES only (lower)
    html_contains: tuple = ()           # substrings searched in the lowercased HTML body
    script_contains: tuple = ()         # substrings searched against <script src="..."> paths (lower)
    generator_contains: str = ""        # substring searched in the <meta name=generator> content


# --------------------------------------------------------------------------
# Signature table — ~55 common stacks across servers, CDN/WAF, CMS,
# frameworks, JS libraries, and analytics. Every string below is a real,
# documented marker of that technology (not a guess at one).
# --------------------------------------------------------------------------
SIGNATURES: tuple[Sig, ...] = (
    # ---- web servers ----
    Sig("nginx", "server", "high", header_contains=(("server", "nginx"),)),
    Sig("Apache HTTP Server", "server", "high", header_contains=(("server", "apache"),)),
    Sig("Microsoft IIS", "server", "high", header_contains=(("server", "microsoft-iis"),)),
    Sig("LiteSpeed", "server", "high", header_contains=(("server", "litespeed"),)),
    Sig("OpenResty", "server", "high", header_contains=(("server", "openresty"),)),
    Sig("Caddy", "server", "high", header_contains=(("server", "caddy"),)),
    Sig("Gunicorn", "server", "high", header_contains=(("server", "gunicorn"),)),
    Sig("Werkzeug (Flask dev server)", "server", "high", header_contains=(("server", "werkzeug"),)),
    Sig("Kestrel (ASP.NET Core)", "server", "high", header_contains=(("server", "kestrel"),)),
    Sig("Apache Tomcat / Coyote", "server", "high", header_contains=(("server", "apache-coyote"),),
        cookie_contains=("jsessionid",)),
    Sig("Varnish Cache", "server", "medium", header_has=("x-varnish",)),
    Sig("Phusion Passenger", "server", "high", header_contains=(("x-powered-by", "phusion passenger"),)),

    # ---- languages / app frameworks (server-declared) ----
    Sig("PHP", "language", "medium", header_contains=(("x-powered-by", "php"),),
        cookie_contains=("phpsessid",)),
    Sig("ASP.NET", "framework", "high", header_has=("x-aspnet-version",),
        cookie_contains=("asp.net_sessionid", "aspxauth")),
    Sig("Express (Node.js)", "framework", "high", header_contains=(("x-powered-by", "express"),)),
    Sig("Django", "framework", "medium", cookie_contains=("csrftoken",)),
    Sig("Ruby on Rails", "framework", "medium", header_has=("x-runtime",), cookie_contains=("_session_id",)),
    Sig("Laravel", "framework", "medium", cookie_contains=("laravel_session", "xsrf-token")),
    Sig("Symfony", "framework", "low", cookie_contains=("symfony",)),
    Sig("Spring (Actuator)", "framework", "medium", header_has=("x-application-context",)),

    # ---- CDN / WAF ----
    Sig("Cloudflare", "cdn-waf", "high", header_contains=(("server", "cloudflare"),),
        header_has=("cf-ray", "cf-cache-status")),
    Sig("Akamai", "cdn-waf", "medium", header_has=("x-akamai-transformed",),
        header_contains=(("server", "akamaighost"), ("via", "akamai"))),
    Sig("Fastly", "cdn-waf", "medium", header_has=("x-fastly-request-id",),
        header_contains=(("via", "fastly"),)),
    Sig("Amazon CloudFront", "cdn-waf", "high", header_has=("x-amz-cf-id", "x-amz-cf-pop")),
    Sig("Sucuri (WAF)", "cdn-waf", "high", header_has=("x-sucuri-id", "x-sucuri-cache")),
    Sig("Imperva Incapsula", "cdn-waf", "high", header_has=("x-iinfo",),
        header_contains=(("x-cdn", "incapsula"),)),
    Sig("StackPath", "cdn-waf", "medium", header_contains=(("server", "stackpath"),)),
    Sig("KeyCDN", "cdn-waf", "medium", header_contains=(("server", "keycdn"),)),
    Sig("Amazon S3 (static hosting)", "cdn-waf", "high", header_contains=(("server", "amazons3"),)),
    Sig("GitHub Pages", "cdn-waf", "high", header_has=("x-github-request-id",)),
    Sig("Netlify", "cdn-waf", "high", header_has=("x-nf-request-id",),
        header_contains=(("server", "netlify"),)),
    Sig("Vercel", "cdn-waf", "high", header_has=("x-vercel-id",),
        header_contains=(("server", "vercel"),)),
    Sig("Google Frontend (GFE)", "cdn-waf", "medium", header_contains=(("server", "gws"), ("server", "google frontend"))),
    Sig("Heroku (via Vegur)", "cdn-waf", "low", header_contains=(("via", "vegur"),)),

    # ---- CMS ----
    Sig("WordPress", "cms", "high", generator_contains="wordpress",
        html_contains=("/wp-content/", "/wp-includes/"),
        cookie_contains=("wordpress_logged_in", "wp-settings")),
    Sig("Drupal", "cms", "high", header_has=("x-drupal-cache", "x-drupal-dynamic-cache"),
        generator_contains="drupal", html_contains=("/sites/all/", "drupal.settings")),
    Sig("Joomla!", "cms", "high", generator_contains="joomla", html_contains=("/com_content/", "joomla!")),
    Sig("Magento", "cms", "high", html_contains=("mage.cookies.", "/static/frontend/"),
        cookie_contains=("mage-cache-sessid", "mage-cache-storage")),
    Sig("Shopify", "cms", "high", html_contains=("cdn.shopify.com", "shopify.theme"),
        header_has=("x-shopid", "x-shopify-stage")),
    Sig("Wix", "cms", "high", html_contains=("static.parastorage.com",),
        header_contains=(("server", "wixserver"),), header_has=("x-wix-request-id",)),
    Sig("Squarespace", "cms", "high", html_contains=("static1.squarespace.com", "squarespace-cdn.com")),
    Sig("Ghost", "cms", "high", generator_contains="ghost", html_contains=("/ghost/api/",)),
    Sig("TYPO3", "cms", "high", generator_contains="typo3", cookie_contains=("fe_typo_user",)),
    Sig("Webflow", "cms", "high", html_contains=("assets.website-files.com", "webflow.js")),
    Sig("HubSpot CMS", "cms", "medium", html_contains=("hs-scripts.com", "hsforms.net")),
    Sig("PrestaShop", "cms", "medium", generator_contains="prestashop"),
    Sig("BigCommerce", "cms", "high", html_contains=("cdn11.bigcommerce.com",)),

    # ---- JS meta-frameworks ----
    Sig("Next.js", "framework", "high", html_contains=('id="__next"', "/_next/static/", "__next_data__")),
    Sig("Nuxt.js", "framework", "high", html_contains=("/_nuxt/", "__nuxt")),
    Sig("Gatsby", "framework", "high", html_contains=("___gatsby", "/page-data/")),

    # ---- JS libraries ----
    Sig("jQuery", "js-library", "high", script_contains=("jquery.min.js", "jquery.js", "jquery-")),
    Sig("React", "js-library", "medium", html_contains=("data-reactroot", "data-reactid"),
        script_contains=("react.production.min.js", "react-dom")),
    Sig("Vue.js", "js-library", "medium", html_contains=("data-v-", "__vue__"),
        script_contains=("vue.min.js", "vue.global.js")),
    Sig("Angular", "js-library", "high", html_contains=("ng-version",), script_contains=("angular.min.js",)),
    Sig("Bootstrap", "js-library", "medium", script_contains=("bootstrap.min.js",), html_contains=("bootstrap.min.css",)),
    Sig("Font Awesome", "js-library", "medium", script_contains=("font-awesome",), html_contains=("fontawesome",)),
    Sig("Lodash", "js-library", "high", script_contains=("lodash.min.js", "lodash.js")),
    Sig("Moment.js", "js-library", "high", script_contains=("moment.min.js", "moment.js")),
    Sig("D3.js", "js-library", "high", script_contains=("d3.min.js", "d3.v")),
    Sig("Alpine.js", "js-library", "medium", html_contains=("x-data=", "x-init="), script_contains=("alpinejs",)),
    Sig("htmx", "js-library", "high", html_contains=("hx-get=", "hx-post="), script_contains=("htmx.min.js",)),
    Sig("GSAP", "js-library", "high", script_contains=("gsap.min.js", "gsap/gsap")),
    Sig("Swiper", "js-library", "high", script_contains=("swiper-bundle", "swiper.min.js")),
    Sig("Three.js", "js-library", "high", script_contains=("three.min.js", "three.module.js")),

    # ---- analytics / tag managers ----
    Sig("Google Analytics", "analytics", "high", script_contains=("google-analytics.com/analytics.js",
        "googletagmanager.com/gtag/js"), html_contains=("ga('create'",)),
    Sig("Google Tag Manager", "analytics", "high", script_contains=("googletagmanager.com/gtm.js",)),
    Sig("Facebook Pixel", "analytics", "high", script_contains=("connect.facebook.net",),
        html_contains=("fbq(",)),
    Sig("Hotjar", "analytics", "high", script_contains=("static.hotjar.com",)),
    Sig("Segment", "analytics", "high", script_contains=("cdn.segment.com",)),
    Sig("Mixpanel", "analytics", "high", script_contains=("cdn.mxpnl.com",)),
    Sig("Matomo / Piwik", "analytics", "high", html_contains=("matomo.js", "piwik.js")),
    Sig("Intercom", "analytics", "high", script_contains=("widget.intercom.io",)),
    Sig("Crisp Chat", "analytics", "high", script_contains=("client.crisp.chat",)),
    Sig("Zendesk Chat", "analytics", "high", script_contains=("static.zdassets.com",)),
)

_SCRIPT_SRC_RE = re.compile(r'<script\b[^>]*\bsrc=["\']([^"\']*)["\']', re.I)
_GENERATOR_A_RE = re.compile(r'<meta[^>]*\bname=["\']generator["\'][^>]*\bcontent=["\']([^"\']*)["\']', re.I)
_GENERATOR_B_RE = re.compile(r'<meta[^>]*\bcontent=["\']([^"\']*)["\'][^>]*\bname=["\']generator["\']', re.I)


def _norm_headers(headers: dict) -> dict:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


def _cookie_names(set_cookie: str) -> list[str]:
    """Cookie NAMES only, never values — mirrors webscan._analyze_cookies.
    common.fetch newline-joins repeated Set-Cookie headers (see the contract in
    common._collect_headers), so split on that newline first to see every cookie,
    then keep the legacy comma-before-`name=` split per line for any single
    comma-joined value (never the comma inside `Expires=Wed, 09 Jun 2021 ...`)."""
    if not set_cookie:
        return []
    parts = [c for line in set_cookie.split("\n")
             for c in re.split(r",\s*(?=[A-Za-z0-9!#$%&'*+.^_`|~-]+=)", line)]
    names = []
    for part in parts:
        seg = part.split(";", 1)[0]
        if "=" in seg:
            names.append(seg.split("=", 1)[0].strip())
    return names


def _extract_generator(html: str) -> str:
    m = _GENERATOR_A_RE.search(html) or _GENERATOR_B_RE.search(html)
    return m.group(1) if m else ""


def fingerprint(headers: dict, body: bytes, cookie_names: Optional[list[str]] = None) -> dict:
    """Pure function over an already-fetched response — no I/O. Returns the
    detected technologies with per-hit evidence and a confidence."""
    h = _norm_headers(headers)
    html = (body or b"").decode("utf-8", "replace")
    html_lower = html.lower()
    if cookie_names is None:
        cookie_names = _cookie_names(headers.get("Set-Cookie") or h.get("set-cookie", ""))
    cookie_blob = " ".join(cookie_names).lower()
    script_srcs = [s.lower() for s in _SCRIPT_SRC_RE.findall(html)]
    generator = _extract_generator(html)
    generator_lower = generator.lower()

    hits = []
    for sig in SIGNATURES:
        evidence = []
        for hname in sig.header_has:
            if h.get(hname):
                evidence.append(f"header {hname} present")
        for hname, needle in sig.header_contains:
            v = h.get(hname, "")
            if needle in v.lower():
                evidence.append(f"header {hname}: {v[:120]}")
        for needle in sig.cookie_contains:
            if needle in cookie_blob:
                evidence.append(f"cookie name contains '{needle}'")
        for needle in sig.html_contains:
            if needle in html_lower:
                evidence.append(f"HTML contains '{needle}'")
        for needle in sig.script_contains:
            if any(needle in s for s in script_srcs):
                evidence.append(f"script src contains '{needle}'")
        if sig.generator_contains and sig.generator_contains in generator_lower:
            evidence.append(f"generator meta: {generator[:120]}")
        if evidence:
            hits.append({
                "name": sig.name,
                "category": sig.category,
                "confidence": "high" if len(evidence) > 1 else sig.confidence,
                "evidence": evidence,
            })

    hits.sort(key=lambda x: (x["category"], x["name"]))
    return {
        "ok": True,
        "technologies": hits,
        "count": len(hits),
        "meta_generator": generator or None,
    }


def handle_tech_fingerprint(req) -> "common.Response":
    """POST /api/tech-fingerprint

    Two shapes:
      {headers: {...}, body: "...", authorized/lab not needed} -> zero network
        calls, fingerprints the response you already fetched.
      {url, authorized, lab} -> exactly ONE gated fetch (same authorized +
        scope + opsec story as webscan's single-request analyzer), then
        fingerprints that.
    """
    body = req.json()

    if "headers" in body or "body" in body:
        headers = body.get("headers")
        raw_body = body.get("body")
        if not isinstance(headers, dict):
            return common.Response.error(400, "headers must be an object")
        if not isinstance(raw_body, str):
            return common.Response.error(400, "body must be a string")
        result = fingerprint(headers, raw_body.encode("utf-8", "replace"))
        return common.Response.json(result)

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

    if lab and not common.host_is_public(host_or_reason):
        return common.Response.error(400, _LAB_PRIVATE_MSG)

    if not lab and not runners._resolve_public_ips_safe(host_or_reason):
        return common.Response.error(403,
            "target no longer resolves to a public address (re-checked before fetch) — refusing")

    try:
        status, raw_body, headers = common.fetch(cleaned, timeout=10.0, max_bytes=300_000)
    except ValueError as e:
        return common.Response.json({"ok": False, "error": f"blocked: {e}"})
    except _FETCH_ERRORS as e:
        return common.Response.json({"ok": False, "error": f"unreachable: {type(e).__name__}: {e}"})

    result = fingerprint(headers, raw_body)
    result["url"] = cleaned
    result["status"] = status

    runners._append_audit({
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": "tech-fingerprint", "target": cleaned, "authorized": authorized, "lab": lab,
        "count": result.get("count", 0),
    })
    return common.Response.json(result)
