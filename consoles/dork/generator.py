"""Professional search-dork generator for the Dork console.

Give it a website. It returns a full, categorized set of the search-engine
"dorks" a pro would actually run against that target during passive recon —
attack-surface mapping, exposed files, config/secrets, login panels, API docs,
off-domain code/paste leaks, people OSINT, tech fingerprinting, and parameter
hunting — plus a set of direct deep links into the specialist sources
(certificate transparency, Shodan, GitHub code search, the Wayback Machine, …)
that Google operators can't reach.

Like recon/detect.py, this file NEVER makes a network call. It only normalizes
the input and builds query strings + URLs. Everything it surfaces is content a
search engine already crawled; running these against a target you don't own or
aren't authorized to test is on you, not on the URL builder.
"""

from __future__ import annotations

import re
from urllib.parse import quote, quote_plus

# A registrable-domain check that's good enough to reject junk without pulling
# in the Public Suffix List. Same shape recon/detect.py uses.
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

# The common two-label public suffixes, so "foo.co.uk" resolves its brand to
# "foo" (not "co") and its apex to "foo.co.uk" (not "co.uk"). Not exhaustive —
# the brand is editable in the UI for the long tail.
_MULTI_SUFFIX = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au",
    "org.au", "co.nz", "co.za", "co.jp", "or.jp", "ne.jp", "com.br",
    "com.mx", "com.sg", "com.tr", "co.in", "co.kr", "com.cn", "com.hk",
    "com.tw", "co.il", "com.ua", "com.ar", "com.pl", "com.es",
})

# Engine URLs are built client-side (one template map in app.js) so this
# module stays pure string logic; the UI switches the primary engine live.
ENGINES = ("google", "bing", "duckduckgo", "yandex", "brave")

# Server-side copy of the same search-URL templates the client uses. This is the
# ONLY source of truth the "Open in Firefox" launcher trusts: it rebuilds the
# URL from {engine, query} here rather than accepting a full URL from the page,
# so a compromised/altered client can never make the server hand the browser an
# arbitrary URL through the engine path. {q} is replaced with a url-encoded query.
# Keep in sync with the ENGINE map in static/app.js (a unit test asserts parity).
ENGINE_SEARCH_URL = {
    "google":     "https://www.google.com/search?q={q}",
    "bing":       "https://www.bing.com/search?q={q}",
    "duckduckgo": "https://duckduckgo.com/?q={q}",
    "yandex":     "https://yandex.com/search/?text={q}",
    "brave":      "https://search.brave.com/search?q={q}",
}

# The exact set of hosts _sources() ever deep-links into. The launcher validates
# any source URL it's asked to open against this allowlist (scheme must be https
# and host must be in here), so the specialist-source path can only ever open one
# of these known OSINT sites — never an attacker-chosen URL. A unit test asserts
# every host _sources() emits is present here, so the two can't drift apart.
SOURCE_HOSTS = frozenset({
    "crt.sh",
    "search.censys.io",
    "www.shodan.io",
    "github.com",
    "grep.app",
    "web.archive.org",
    "urlscan.io",
    "www.virustotal.com",
    "api.hackertarget.com",
    "rapiddns.io",
    "otx.alienvault.com",
    "viewdns.info",
    "builtwith.com",
    "securitytrails.com",
    "www.exploit-db.com",
})


def engine_search_url(engine: str, query: str) -> str:
    """Build the search URL for `engine` + `query`, server-side. Raises
    ValueError on an unknown engine so the launcher fails closed."""
    tmpl = ENGINE_SEARCH_URL.get((engine or "").strip().lower())
    if tmpl is None:
        raise ValueError(f"unknown engine: {engine!r}")
    return tmpl.replace("{q}", quote_plus(query))


# --------------------------------------------------------------------------
# Per-engine operator translation.
#
# The dorks below are authored in Google syntax — the lingua franca — but NO
# other engine speaks it (verified 2026: Research/dorking-sota-2026.md). Reusing
# one Google string on every engine silently degrades: Bing wants `inbody:` not
# `intext:`, Yandex has no `inurl:` at all and calls filetype `mime:`, and
# DuckDuckGo reliably honors only `site:`. So for each engine we (a) rename the
# operators that have a documented 1:1 equivalent, and (b) flag a dork
# "degraded" on an engine that has no equivalent for one of the operators it
# uses, so the UI can say so honestly instead of handing over a query the engine
# will quietly ignore. site:, "quotes", -term and OR are universal and untouched.
# --------------------------------------------------------------------------

# Operators this generator actually emits, longest-first so a token-boundary
# rewrite never clips a longer operator (e.g. must see "intext:" before "ext:").
_OPS = ("allintitle:", "allintext:", "allinurl:",
        "intitle:", "intext:", "inurl:", "filetype:", "ext:")

# engine -> {google_op: replacement_op} for documented 1:1 renames.
_ENGINE_RENAME = {
    "bing":   {"intext:": "inbody:", "allintext:": "inbody:"},
    "brave":  {"intext:": "inbody:", "allintext:": "inbody:"},
    "yandex": {"filetype:": "mime:", "ext:": "mime:",
               "intitle:": "title:", "allintitle:": "title:"},
}

# engine -> operators it has no equivalent for. A dork that uses one of these on
# that engine is "degraded": we still build a best-effort link (the engine
# treats the unknown operator as loose text) but flag it. Bing's inurl: is a
# membership check rather than a substring match — approximate but useful, so we
# don't flag it. DuckDuckGo reliably honors only site:, so everything else there
# is degraded (per its own help page + 2023 field testing).
_ENGINE_UNSUPPORTED = {
    "google":     frozenset(),
    "bing":       frozenset(),
    "brave":      frozenset({"inurl:", "allinurl:"}),
    "yandex":     frozenset({"inurl:", "allinurl:", "intext:", "allintext:"}),
    "duckduckgo": frozenset({"inurl:", "allinurl:", "intitle:", "allintitle:",
                             "intext:", "allintext:", "filetype:", "ext:"}),
}


def _ops_used(query: str) -> set[str]:
    """Which of _OPS appear in `query` as real operator tokens (start-of-string
    or after a space/paren), so 'ext:' is never matched inside 'intext:'."""
    used = set()
    for op in _OPS:
        # a token boundary before the op: string start, whitespace, or '('
        if re.search(r"(?:^|[\s(])" + re.escape(op), query):
            used.add(op)
    return used


def translate_query(query: str, engine: str) -> tuple[str, str]:
    """(translated_query, level) for one Google-syntax dork on `engine`.

    level is "full" if every operator the dork uses has a native or renamed
    equivalent on the engine, else "degraded". Renames are applied only at a
    token boundary so a longer operator is never clipped."""
    engine = (engine or "").strip().lower()
    used = _ops_used(query)
    out = query
    for op, repl in _ENGINE_RENAME.get(engine, {}).items():
        if op in used:
            out = re.sub(r"(^|[\s(])" + re.escape(op), r"\1" + repl, out)
    level = "degraded" if (used & _ENGINE_UNSUPPORTED.get(engine, frozenset())) else "full"
    return out, level


def _engine_variants(query: str) -> dict:
    """Per-engine {q, level} for a dork, for every engine in ENGINES. The client
    builds its links from this (and hands q straight to the Firefox launcher), so
    the query the user runs on Yandex is Yandex syntax, not Google's."""
    variants = {}
    for e in ENGINES:
        tq, level = translate_query(query, e)
        variants[e] = {"q": tq, "level": level}
    return variants

# risk buckets, only used to colour the row in the UI:
#   info      — enumerates public surface, expected to return hits
#   recon     — probes for a surface that may or may not exist
#   sensitive — if this returns anything, it's likely a real finding to report


def normalize(raw: str) -> tuple[str, str, str]:
    """(host, apex, brand) from whatever the user pasted, or raise ValueError.

    A scheme, path, query, fragment, userinfo, port, and a leading "www." are
    all stripped — `site:example.com` already covers `www.example.com` on every
    engine, so we broaden to the apex by default.
    """
    s = (raw or "").strip()
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", s)      # scheme
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]  # path/query/frag
    s = s.split("@")[-1]                                     # userinfo
    s = s.rsplit(":", 1)[0] if s.count(":") == 1 else s      # :port (not IPv6)
    s = s.strip().strip(".").lower()
    if s.startswith("www."):
        s = s[4:]
    if not s or not _DOMAIN_RE.match(s):
        raise ValueError(f"'{raw}' is not a valid domain")
    labels = s.split(".")
    if len(labels) <= 2:
        apex = s
    else:
        last2 = ".".join(labels[-2:])
        apex = ".".join(labels[-3:]) if last2 in _MULTI_SUFFIX else last2
    brand = apex.split(".")[0]
    return s, apex, brand


# --------------------------------------------------------------------------
# The dork spec. Each entry is (label, query_template, why, risk).
# Templates use {host} (what to dork), {apex} (registrable domain), and
# {brand} (the org name guess). Substitution is a literal replace, so query
# text may contain any characters except those three tokens.
# --------------------------------------------------------------------------
_SPEC: list[dict] = [
    {
        "key": "surface", "name": "Attack surface",
        "why": "Everything the target has let a search engine index. Start here — it maps hosts, sections, and stacks before you probe anything.",
        "dorks": [
            ("All indexed pages", "site:{host}",
             "The whole public footprint on this host.", "info"),
            ("Subdomains", "site:*.{apex} -www.{apex}",
             "Other hosts under the same domain — the app, staging, admin, mail.", "info"),
            ("Drop the marketing noise", "site:{host} -inurl:blog -inurl:news -inurl:tag",
             "Strips SEO/blog pages so real application routes surface.", "info"),
            ("Server-side app pages", "site:{host} (inurl:php OR inurl:aspx OR inurl:jsp OR inurl:cgi)",
             "Dynamic endpoints — where parameters (and bugs) live.", "recon"),
            ("Interesting parameters", "site:{host} (inurl:id= OR inurl:page= OR inurl:cat= OR inurl:item=)",
             "URLs that take an ID/path — IDOR and injection candidates.", "recon"),
        ],
    },
    {
        "key": "auth", "name": "Login, admin & account",
        "why": "The authentication surface — every place a credential is accepted is a place to enumerate, brute-force (with authorization), or find a default.",
        "dorks": [
            ("Login / admin URLs", "site:{host} (inurl:login OR inurl:signin OR inurl:admin OR inurl:dashboard OR inurl:portal OR inurl:account)",
             "The obvious front doors, by path.", "info"),
            ("Login / admin titles", 'site:{host} (intitle:"login" OR intitle:"admin" OR intitle:"sign in" OR intitle:"dashboard")',
             "Catches panels whose URL doesn't say 'login' but whose page does.", "recon"),
            ("SSO / federated auth", "site:{host} (inurl:sso OR inurl:oauth OR inurl:saml OR inurl:auth OR inurl:openid)",
             "Identity endpoints — often misconfigured, often verbose.", "recon"),
            ("Registration & reset", "site:{host} (inurl:register OR inurl:signup OR inurl:password OR inurl:reset OR inurl:forgot)",
             "Account flows worth reviewing for enumeration and token leaks.", "recon"),
        ],
    },
    {
        "key": "api", "name": "API & developer surface",
        "why": "Auto-generated API docs and schemas hand you the entire attack surface in one page — endpoints, parameters, and often auth requirements.",
        "dorks": [
            ("API endpoints", "site:{host} inurl:api",
             "Anything routed under /api.", "info"),
            ("Swagger / OpenAPI docs", 'site:{host} (inurl:swagger OR inurl:openapi OR inurl:api-docs OR inurl:redoc OR intitle:"Swagger UI")',
             "A published API spec is a map of every route and field.", "sensitive"),
            ("Raw OpenAPI schema files", "site:{host} (inurl:swagger.json OR inurl:openapi.json OR inurl:swagger.yaml)",
             "The machine-readable spec — every endpoint, parameter, and auth requirement in one file.", "sensitive"),
            ("GraphQL", "site:{host} (inurl:graphql OR inurl:graphiql OR inurl:playground)",
             "A live GraphQL endpoint often allows introspection of the whole schema.", "sensitive"),
            ("Versioned REST", "site:{host} (inurl:v1 OR inurl:v2 OR inurl:v3 OR inurl:rest)",
             "Older API versions that never got the newer auth checks.", "recon"),
            ("Exposed JSON config", "site:{host} filetype:json (config OR manifest OR firebase OR credentials)",
             "Client config JSON leaks keys, buckets, and backend URLs.", "sensitive"),
        ],
    },
    {
        "key": "files", "name": "Exposed files & directory listings",
        "why": "An open directory listing or a stray backup is the single highest-yield dork category — it turns 'the server' into 'the server's file tree'.",
        "dorks": [
            ("Open directory listings", 'site:{host} intitle:"index of"',
             "Apache/nginx autoindex — browse the raw file tree.", "sensitive"),
            ("Listings of backups", 'site:{host} intitle:"index of" (backup OR bak OR old OR db OR sql OR dump)',
             "An open directory that also contains a backup is a data breach.", "sensitive"),
            ("Backup & archive files", "site:{host} (filetype:bak OR filetype:old OR filetype:backup OR filetype:zip OR filetype:tar OR filetype:gz OR filetype:rar)",
             "site.zip / backup.tar.gz left in web root.", "sensitive"),
            ("Database dumps", "site:{host} (filetype:sql OR filetype:db OR filetype:sqlite OR filetype:dump OR filetype:mdb)",
             "An exported database sitting somewhere crawlable.", "sensitive"),
            ("Exposed .git directory", 'site:{host} inurl:.git intitle:"index of"',
             "A browsable .git dir reconstructs the full source and its history.", "sensitive"),
            ("Off-domain listings", 'intitle:"index of" "{apex}"',
             "Open directories on OTHER hosts that reference this domain.", "recon"),
        ],
    },
    {
        "key": "secrets", "name": "Config, secrets & credentials",
        "why": "The jackpot bucket, and the lowest hit rate. If any of these return content, treat it as a live credential and report it — do not use it.",
        "dorks": [
            ("Config files", "site:{host} (ext:env OR ext:cfg OR ext:conf OR ext:ini OR ext:yaml OR ext:yml OR ext:toml)",
             ".env / config files hold DB strings and API keys.", "sensitive"),
            ("Exposed VCS / server config", "site:{host} (inurl:.env OR inurl:.git OR inurl:.svn OR inurl:.htaccess OR inurl:wp-config OR inurl:web.config)",
             "A readable .git or wp-config is full source + secrets.", "sensitive"),
            ("Keys & tokens in text", 'site:{host} (intext:"api_key" OR intext:"apikey" OR intext:"client_secret" OR intext:"access_token" OR intext:"aws_secret")',
             "Secrets hardcoded into a served page or file.", "sensitive"),
            ("Private keys", 'site:{host} (intext:"BEGIN RSA PRIVATE KEY" OR intext:"BEGIN OPENSSH PRIVATE KEY" OR intext:"BEGIN PRIVATE KEY")',
             "A served private key is game-over for that service.", "sensitive"),
            ("Passwords in files", 'site:{host} (intext:"password" OR intext:"passwd" OR intext:"DB_PASSWORD") (filetype:txt OR filetype:log OR filetype:cfg OR filetype:env)',
             "Plaintext credentials in a downloadable file.", "sensitive"),
        ],
    },
    {
        "key": "errors", "name": "Logs, errors & debug",
        "why": "Verbose errors leak stack traces, absolute paths, framework versions, and sometimes query fragments — the details that make the next step precise.",
        "dorks": [
            ("Log files", "site:{host} (filetype:log OR inurl:log OR inurl:logs OR inurl:debug.log)",
             "Application logs with paths, tokens, and internal hostnames.", "sensitive"),
            ("Stack traces & fatals", 'site:{host} (intext:"stack trace" OR intext:"Fatal error" OR intext:"Uncaught exception" OR intext:"Traceback (most recent call last)")',
             "Uncaught errors expose the framework and file layout.", "recon"),
            ("SQL errors", 'site:{host} (intext:"SQL syntax" OR intext:"mysql_fetch" OR intext:"ORA-01756" OR intext:"Microsoft OLE DB")',
             "A database error in a page is a live SQL-injection signal.", "sensitive"),
            ("phpinfo()", 'site:{host} (inurl:phpinfo OR intitle:"phpinfo()")',
             "A left-over phpinfo dumps the entire server config.", "sensitive"),
            ("Dev / staging / test hosts", "site:{host} (inurl:dev OR inurl:staging OR inurl:test OR inurl:uat OR inurl:qa)",
             "Non-prod environments with weaker controls and real data.", "recon"),
        ],
    },
    {
        "key": "docs", "name": "Documents & metadata",
        "why": "Published documents carry author names, software versions, internal paths, and sometimes data the org never meant to be public.",
        "dorks": [
            ("Office & PDF documents", "site:{host} (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:ppt OR filetype:pptx)",
             "Every doc carries metadata; some carry the actual secret.", "recon"),
            ("Spreadsheets with PII", "site:{host} (filetype:xlsx OR filetype:csv) (email OR phone OR employee OR salary OR budget OR invoice)",
             "Exported data dumps in a crawlable spreadsheet.", "sensitive"),
            ("Marked-confidential docs", 'site:{host} (intext:"confidential" OR intext:"internal use only" OR intext:"not for distribution" OR intext:"proprietary")',
             "Documents that state they weren't meant to be public.", "sensitive"),
        ],
    },
    {
        "key": "leaks", "name": "Off-domain leaks",
        "why": "A small org bleeds most on OTHER people's sites — code hosts, paste sites, project boards, and public cloud buckets. Keyed on the domain and brand, not on the site itself.",
        "dorks": [
            ("Code hosts", '"{apex}" (site:github.com OR site:gitlab.com OR site:bitbucket.org)',
             "Repos and gists that mention the domain — often with URLs and keys.", "recon"),
            ("Paste sites", '"{apex}" (site:pastebin.com OR site:paste.ee OR site:ghostbin.com OR site:controlc.com OR site:rentry.co)',
             "Dumped configs, creds, and logs live on paste sites.", "sensitive"),
            ("Project boards & wikis", '"{apex}" (site:trello.com OR site:notion.so OR site:atlassian.net OR site:sharepoint.com OR site:docs.google.com)',
             "Public boards/docs leak roadmaps, creds, and internal process.", "recon"),
            ("Public cloud buckets", '"{apex}" (site:s3.amazonaws.com OR site:blob.core.windows.net OR site:storage.googleapis.com OR site:digitaloceanspaces.com)',
             "Misconfigured object storage indexed by name.", "sensitive"),
            ("Brand + secret", '("{brand}" OR "{apex}") (password OR secret OR "api_key" OR token) (site:github.com OR site:pastebin.com OR site:gitlab.com)',
             "The narrowest, highest-signal leak query.", "sensitive"),
        ],
    },
    {
        "key": "people", "name": "People & org OSINT",
        "why": "Who works there, how their emails are formatted, and where they post — the raw material for phishing, credential-stuffing, and social pretext (in an authorized test).",
        "dorks": [
            ("Employees on LinkedIn", 'site:linkedin.com/in "{brand}"',
             "Staff list → naming convention → email format.", "info"),
            ("Corporate email addresses", '"@{apex}" -site:{apex}',
             "Addresses on the domain, indexed on other sites.", "recon"),
            ("Contact addresses on-site", 'site:{host} intext:"@{apex}"',
             "Emails the site itself publishes (support, sales, abuse).", "info"),
            ("Brand across communities", '"{brand}" (site:github.com OR site:stackoverflow.com OR site:reddit.com OR site:news.ycombinator.com)',
             "Employee posts that leak stack details and frustrations.", "recon"),
        ],
    },
    {
        "key": "tech", "name": "Technology & known panels",
        "why": "Fingerprint the stack and find the well-known admin panels for it — a matched CMS/tool version maps straight to public exploits.",
        "dorks": [
            ("WordPress", 'site:{host} (inurl:wp-content OR inurl:wp-admin OR inurl:wp-json OR intitle:"wp-login")',
             "WP surface — plugins/themes are the usual way in.", "recon"),
            ("DB admin panels", "site:{host} (inurl:phpmyadmin OR inurl:adminer OR inurl:pma OR inurl:dbadmin)",
             "A web DB admin exposed to the internet.", "sensitive"),
            ("Ops dashboards", 'site:{host} (intitle:"Grafana" OR intitle:"Kibana" OR intitle:"Jenkins" OR intitle:"Prometheus" OR intitle:"Argo CD")',
             "Monitoring/CI dashboards, frequently unauthenticated.", "sensitive"),
            ("Dev tooling", "site:{host} (inurl:jira OR inurl:confluence OR inurl:gitlab OR inurl:jenkins OR inurl:sonar)",
             "Internal tooling reachable from outside.", "recon"),
            (".well-known", "site:{host} inurl:.well-known",
             "security.txt, mta-sts, openid-config — free recon.", "info"),
        ],
    },
    {
        "key": "cloud", "name": "Cloud, DevOps & dashboards",
        "why": "Modern stacks leak through their infra: an open Spring Boot actuator, a Kubernetes dashboard, or a Terraform state file hands over secrets and internal topology. Google indexes these poorly, so anything it *does* surface here is worth a close look — and pivot bare IP:port services to Shodan/Censys below.",
        "dorks": [
            ("Spring Boot actuator", "site:{host} (inurl:actuator/env OR inurl:actuator/health OR inurl:actuator/heapdump OR inurl:actuator/mappings)",
             "An exposed /actuator/env or /heapdump dumps config and in-memory secrets.", "sensitive"),
            ("Firebase backends", 'inurl:firebaseio.com ("{brand}" OR "{apex}")',
             "An open Firebase realtime DB is world-readable by default.", "sensitive"),
            ("Kubernetes dashboards", 'site:{host} (intitle:"Kubernetes Dashboard" OR inurl:/api/v1/namespaces)',
             "An unauthenticated k8s dashboard is cluster-wide control.", "sensitive"),
            ("Container registries", "site:{host} inurl:v2/_catalog",
             "A Docker registry catalog lists every private image name.", "sensitive"),
            ("Elasticsearch / search nodes", "site:{host} (inurl:9200 OR inurl:_cat/indices OR inurl:_search)",
             "An open Elasticsearch node is a browsable copy of the data.", "sensitive"),
            ("Terraform state", "site:{host} (filetype:tfstate OR inurl:terraform.tfstate)",
             "A .tfstate file holds plaintext provider creds and full infra layout.", "sensitive"),
        ],
    },
    {
        "key": "params", "name": "Redirects & parameter hunting",
        "why": "URLs that take a redirect target or a file path are the seeds of open-redirect, SSRF, and LFI — worth collecting up front for an authorized test.",
        "dorks": [
            ("Open-redirect params", "site:{host} (inurl:redirect OR inurl:redir OR inurl:url= OR inurl:next= OR inurl:return= OR inurl:dest= OR inurl:continue=)",
             "Redirect targets that may not validate the destination.", "recon"),
            ("File / path params", "site:{host} (inurl:file= OR inurl:path= OR inurl:doc= OR inurl:folder= OR inurl:download=)",
             "Path-taking params — LFI / path-traversal candidates.", "recon"),
            ("Server-side fetch params", "site:{host} (inurl:url= OR inurl:uri= OR inurl:link= OR inurl:src= OR inurl:proxy=)",
             "Params that fetch a URL — SSRF candidates.", "recon"),
        ],
    },
]


def _sources(apex: str) -> list[dict]:
    """Direct deep links into the specialist sources Google operators can't
    reach — cert transparency, host search, code search, archives, reputation.
    Each is a real, working URL for this target."""
    a = quote(apex, safe="")
    ap = quote_plus(apex)
    return [
        {"name": "crt.sh — certificate transparency",
         "url": f"https://crt.sh/?q=%25.{a}",
         "why": "Every TLS cert the domain ever issued → a free, complete subdomain list."},
        {"name": "Censys — hosts & certs",
         "url": f"https://search.censys.io/search?resource=hosts&q={ap}",
         "why": "Internet-wide host scan data by domain and certificate."},
        {"name": "Shodan — by hostname",
         "url": f"https://www.shodan.io/search?query=hostname%3A{a}",
         "why": "Open ports, banners, and services on hosts under this domain."},
        {"name": "Shodan — by TLS cert",
         "url": f"https://www.shodan.io/search?query=ssl%3A%22{ap}%22",
         "why": "Finds infrastructure by cert even when the hostname is hidden."},
        {"name": "GitHub — code search",
         "url": f"https://github.com/search?q=%22{ap}%22&type=code",
         "why": "Source code across all public repos that mentions the domain."},
        {"name": "GitHub — domain + secrets",
         "url": f"https://github.com/search?q=%22{ap}%22+%28password+OR+secret+OR+api_key%29&type=code",
         "why": "The narrowest code-leak query — domain next to a credential word."},
        {"name": "grep.app — code search",
         "url": f"https://grep.app/search?q={ap}",
         "why": "Fast, regex-capable search across a million public repos."},
        {"name": "Wayback Machine — URL history",
         "url": f"https://web.archive.org/web/*/{a}/*",
         "why": "Old, since-removed pages and endpoints that are still archived."},
        {"name": "Wayback CDX — every captured URL",
         "url": f"https://web.archive.org/cdx/search/cdx?url={a}*&output=text&fl=original&collapse=urlkey",
         "why": "A raw, deduped list of every path the archive has ever seen."},
        {"name": "urlscan.io — submitted scans",
         "url": f"https://urlscan.io/domain/{a}",
         "why": "Screenshots, resources, and redirect chains others have scanned."},
        {"name": "VirusTotal — domain relations",
         "url": f"https://www.virustotal.com/gui/domain/{a}/relations",
         "why": "Subdomains, sibling domains, and resolutions pivoted server-side."},
        {"name": "HackerTarget — subdomain search",
         "url": f"https://api.hackertarget.com/hostsearch/?q={a}",
         "why": "Plain-text subdomain + IP list, no login (rate-limited)."},
        {"name": "RapidDNS — subdomains",
         "url": f"https://rapiddns.io/subdomain/{a}#result",
         "why": "Fast, fully keyless subdomain list from passive DNS."},
        {"name": "AlienVault OTX — domain intel",
         "url": f"https://otx.alienvault.com/indicator/domain/{a}",
         "why": "Passive DNS, URLs, and threat data; effectively keyless."},
        {"name": "ViewDNS — reverse IP",
         "url": f"https://viewdns.info/reverseip/?host={a}&t=1",
         "why": "Other domains sharing this domain's server — neighbour recon."},
        {"name": "BuiltWith — tech profile",
         "url": f"https://builtwith.com/{a}",
         "why": "The site's detected stack, analytics IDs, and vendors."},
        {"name": "SecurityTrails — DNS history",
         "url": f"https://securitytrails.com/domain/{a}/dns",
         "why": "Historical DNS + subdomains (free tier needs an account)."},
        {"name": "Google Hacking Database",
         "url": "https://www.exploit-db.com/google-hacking-database",
         "why": "The curated master list of proven dorks — steal ideas here."},
    ]


def dork_set(raw: str, keyword: str | None = None) -> dict:
    """Build the full dork set for a target. Raises ValueError on a bad domain."""
    host, apex, brand = normalize(raw)
    if keyword:
        # Let the operator override the brand guess (multi-part suffixes, an org
        # name that isn't the domain label, etc.). Kept short and stripped.
        brand = keyword.strip()[:64] or brand

    def fill(t: str) -> str:
        return (t.replace("{host}", host)
                 .replace("{apex}", apex)
                 .replace("{brand}", brand))

    categories = []
    total = 0
    for cat in _SPEC:
        dorks = []
        for label, tmpl, why, risk in cat["dorks"]:
            query = fill(tmpl)
            dorks.append({"label": label, "query": query, "why": why, "risk": risk,
                          "eng": _engine_variants(query)})
            total += 1
        categories.append({"key": cat["key"], "name": cat["name"],
                           "why": cat["why"], "dorks": dorks})

    return {
        "input": raw,
        "host": host,
        "apex": apex,
        "brand": brand,
        "engines": list(ENGINES),
        "categories": categories,
        "sources": _sources(apex),
        "count": total,
    }
