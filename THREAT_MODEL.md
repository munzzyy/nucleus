# Threat model

This is the honest version: what Nucleus is built to withstand, what it deliberately doesn't try
to, and exactly what touches your disk and network. If you handle sensitive investigations or work
in a hostile environment, read the whole thing before you trust it with anything real.

## What you're running

Nucleus is a set of local web servers (a hub plus six consoles) written in pure Python standard
library, each bound to `127.0.0.1`, served to a browser (or a bundled native window) under a strict
Content-Security-Policy. There is no third-party runtime dependency, no build step, and no account.

## Assets worth protecting

1. **What you investigate.** Recon runs on real people and organizations. The targets, the results,
   and the pivot trail are sensitive by nature.
2. **Your own operational security.** The fact that *you* looked something up, and from where.
3. **Credentials.** Optional API keys you add to unlock deeper data.
4. **The machine.** Nucleus can run local security tooling, so it must never become a way to run
   arbitrary code or reach places it shouldn't.

## Adversaries considered

- **The network you're on.** Other hosts on your LAN, and anyone on-path to the internet.
- **A hostile web page or a malicious link** trying to reach the local servers through your browser
  (DNS rebinding, CSRF, cross-origin reads).
- **A hostile lookup target** trying to turn a passive scan into a server-side request forgery, or
  to inject content into results, a saved report, or the audit log.
- **A malicious tool target** trying to escape the run sandbox into shell execution or a
  private/internal address.

Explicitly **out of scope** (see "What this does not defend" below): a machine already running
malware as your user, and other accounts on a shared multi-user box.

## Trust boundaries and what defends each

| Boundary | Defense | Where |
|---|---|---|
| Network to the app | Loopback-only bind; not a config option | `common.serve` |
| A foreign site to the local API (DNS rebinding) | Host-header allowlist on every request | `common._allowed_hosts` |
| A cross-origin page POSTing to the API (CSRF) | Per-POST Origin/Referer check, exact host **and** port | `common._origin_ok` |
| The browser reaching off-origin | Strict CSP: `default-src 'none'`, no inline script/style, `connect-src 'self'` | `common._CSP` |
| A lookup reaching internal/loopback (SSRF) | One guarded fetch: refuses private/loopback/link-local/reserved, re-validates every redirect, pins the connection to the validated IP | `common.fetch` / `common.resolve_public_ips` |
| DNS leaking or being forged | Encrypted DNS-over-HTTPS for app lookups | `common.dns_query` |
| A tool target becoming shell code | No shell ever; allow-listed binary + fixed argv template + validated target as one argument, behind an authorization gate | `redcell/runners.py` |
| Echoed data becoming markup/script | DOM built with `textContent`/`N.el`; report values neutralized before Markdown/HTML | frontend + `engine/osint_report._md_safe` |

## What is written to disk, and where

This matters most for anyone whose threat model includes their own device being seized or searched.

- **Audit and case logs are OFF by default.** With logging disabled (the default), Nucleus writes
  nothing to `var/` during use: not the offensive-tool audit trail (`var/redcell-scans.jsonl`), not
  the recon case history (`var/recon-scans.jsonl`), not saved tool output (`var/redcell-out/`).
  Results render live in the browser for the session and are gone when you close it. You turn
  persistence on deliberately with `NUCLEUS_LOGGING=1`.
- **API keys** you add are stored in `var/.env` in plaintext, readable only by your user. Treat that
  file as a secret. It is git-ignored.
- **Reports** you generate with the report engine are written where you tell the CLI to write them.
- **Browser-side state** (remembered inputs, recent scans, deep-link state) lives in your browser's
  `localStorage`, scoped to the loopback origin, never sent anywhere.

Nothing in `var/` leaves your machine. There is no sync, no upload, no backup phone-home.

## What this does NOT defend against

- **A compromised local machine.** Any code running as your user can reach a loopback port and read
  your files, including `var/.env`. Loopback keeps the network out; it does not sandbox hostile
  local software. Nucleus is not a substitute for not running malware.
- **Another user on a shared machine.** On a multi-user box, another account may reach
  `127.0.0.1:88xx`. Run Nucleus only on a machine you control.
- **Your network-level anonymity, by default.** With no proxy set, passive recon originates from
  your real IP and a source or target can see that a request came from your address. Set
  `NUCLEUS_SOCKS` (below) to route everything, DNS included, through Tor or a proxy; without it,
  assume your IP is exposed to every source a scan touches. The always-on exposure indicator warns
  you which state you're in, using only local signals.
- **Correlation by the sources themselves.** The third-party services a lookup queries (crt.sh,
  Shodan's InternetDB, breach oracles, and so on) see the query. Nucleus can't hide a lookup from
  the service you're asking.
- **Misuse.** The authorization gate stops accidents and cross-site requests. It is not permission.
  Only investigate and only scan what you are authorized to.

## Residual risks we're honest about

- **DNS rebinding against a tool that re-resolves.** The fetch path pins to a validated IP and
  closes the classic rebinding window for the app's own requests. A third-party binary that does
  its own name resolution can still be raced; where a runner can be pinned to an IP it is, and where
  it can't, only kernel-level egress control fully closes it. This is documented per-runner.
- **Plaintext key storage.** `var/.env` is plaintext. An at-rest encryption option for keys is on
  the roadmap.

## Privacy hardening you can turn on

- **Outbound SOCKS5 proxy.** `NUCLEUS_SOCKS=host:port` (e.g. a local Tor at `127.0.0.1:9050`)
  routes all outbound recon through the tunnel, DNS included: a hostname target is handed to the
  proxy to resolve, and `dns_query`'s DoH rides the tunnel too. A literal private/loopback/reserved
  IP target is still refused. `NUCLEUS_DOH` overrides the DoH resolvers (Cloudflare before Google by
  default, so DNS isn't handed to Google first).
- **At-rest key storage.** `NUCLEUS_KEYRING=1` stores API keys in the OS keyring (libsecret) instead
  of plaintext `var/.env`; or export them as environment variables to keep them off disk entirely.
- **Local-first exposure check.** The always-on indicator reads only your routing table and never
  the network; the exit-IP check against third-party services is an explicit, disclosed opt-in.
- **Secure deletion + panic wipe.** Scrub sessions are overwritten before unlink and reaped on a
  timer, and `nucleus wipe` securely purges all on-disk case data (scans, saved tool output,
  reports, scrub sessions) in one gesture. Best-effort by nature: on a copy-on-write or
  wear-leveled disk the real guarantee is still full-disk encryption, and the tool says so.

## On the roadmap (not yet shipped)

- **Reproducible-build** guidance and a verifiable release, so you can confirm the code you run is
  the code that was published.

If you find a gap this document doesn't name, that's a bug in the document as much as the code.
Report it per [SECURITY.md](SECURITY.md).
