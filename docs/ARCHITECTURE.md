# Nucleus — architecture

## The idea

You had three piles of security work that never talked to each other: the OSINT website (lost in a migration), the pentest/opsec kit staged in `~/security-setup/`, and the client-facing OSINT report engine (also lost). Nucleus pulls all of it into one place.

The design constraint was to match how the rest of your stack already works: a small stdlib-only Python server bound to loopback, serving a hardened local web UI, with zero dependencies to audit. Same shape as coleos-hub and the old osint-console. That keeps the security surface tiny and means there's nothing to `pip install` and vet.

"One app, but it can be three" is solved by making one shared server core and three thin consoles on top of it. Run them together on one box and the launcher + switcher make it feel like a single app. Copy the repo to two more machines and run one console on each; they still cross-link over loopback.

## Pieces

```
                       ┌─────────────────────────────┐
                       │  browser (127.0.0.1 only)    │
                       │  strict CSP, same-origin only │
                       └──────────────┬──────────────┘
                                      │ each tab talks ONLY to its own origin
        ┌───────────────┬────────────┼─────────────┬───────────────┐
        │               │            │             │               │
   hub :8890       recon :8900   redcell :8910  bastion :8920   coleos-hub :4747
        │               │            │             │               (external)
        └──── all import shared/common.py ─────────┘
                        (one server core, one set of guards)
```

- **`shared/common.py`** is the whole security-critical surface, written once:
  - loopback bind, Host-header allowlist, per-POST Origin/Referer check, strict CSP, static file sandbox
  - `fetch()` — the single SSRF-guarded outbound HTTP path (recon's only door out)
  - `dns_query()` — encrypted DNS-over-HTTPS (Google→Cloudflare), so no dnspython and no repeat of the old shared-`Resolver` thread-safety bug
  - `run_tool()` — the single no-shell, time-bounded execution primitive (argv list only)
  - `which()` / `tool_version()` — tool detection
  - `siblings_status()` / `local_get_json()` — server-side health + aggregation, so the browser never makes a cross-origin call
  - `CONSOLES` — one table of every console's port, so links, health, and the switcher never guess

- **Consoles** are tiny. Each is a `build_app()` that hands `common.serve()` a `static_dir` and a `routes` dict of `"GET /api/x" -> handler`. All the hard stuff is inherited from the core, so a console can't accidentally weaken a guard.

- **The hub** aggregates. It calls each console on loopback (`local_get_json`) to show headline numbers — tools installed, opsec posture — and draws the status of everything, including external local apps like coleos-hub. It's the "one app" you open.

## Why the browser never talks cross-origin

Three consoles on three ports are three origins. Rather than open CORS (and widen the attack surface), the CSP stays at `connect-src 'self'` and any cross-console data is fetched **server-side**: the hub asks Redcell and Bastion for their summaries over loopback and merges them; each console's switcher gets sibling health from its own `/api/siblings`, which the server fills in. The browser only ever sees same-origin JSON.

## Request lifecycle

1. Handler dispatch checks the `Host` header against the allowlist → 403 if foreign.
2. `/healthz`, `/api/siblings`, and static routes are served by the core.
3. A registered route runs. For POST, the core first checks a same-origin `Origin`/`Referer` and caps the body size.
4. The handler returns a `common.Response`; a handler exception becomes a clean 500, never a crash.

## Recon data flow (OSINT)

Input → type detection (username / email / domain / ip / phone / …) → the matching live module runs its lookups through `fetch()` (SSRF-guarded) and `dns_query()` (encrypted), concurrency-capped, each source time-boxed and allowed to fail without sinking the response → structured JSON back to the UI. Types with no live module return curated pivot links + dorks. Nothing active, nothing authenticated — passive public sources only.

## Redcell safety model (offensive)

This is the only console that can run security tools, so it's built to assume the UI is hostile:

- **Allowlist.** Only a curated set of binaries may be executed, each with a fixed argv template. The validated target is inserted as exactly one argv element — never a flag, never shell-interpolated.
- **Validation.** Targets are checked (hostname / IP / URL) and rejected for shell metacharacters or argument-injection (a leading `-`, spaces, `;`, `|`, backticks…).
- **Scope + authorization gate.** RFC1918/loopback targets are refused unless an explicit `lab` flag is set; every run requires `authorized: true` server-side. The checkbox in the UI is a convenience, not the enforcement.
- **Non-destructive only.** Runners use safe, read-mostly flags with hard timeouts and output caps, and degrade cleanly to "not installed — here's the install command" when a binary is absent.
- **Aggressive tools are never executed.** For hydra/hashcat/sqlmap/metasploit/etc. the console *builds the command string* for you to run yourself.
- **Audit log.** Every run is appended to `var/redcell-scans.jsonl`.

## Bastion (defensive)

Read-only. Posture checks inspect this machine (sysctls, auditd, Quad9 DoT via `resolvectl`, Tor, WireGuard, MAC randomization, firewall, `arch-audit` CVEs) and report ok/warn/bad/unknown with the exact fix command — Bastion never runs sudo or changes anything. The **report engine** (`engine/osint_report.py`) takes a domain and produces a graded passive assessment (DNS, SPF/DMARC, TLS + security headers, crt.sh attack surface, InternetDB ports/CVEs) rendered to Markdown/HTML. It's importable and has a CLI, so the old income-machine skills that shell out to a `report.py` can point at it again.

## Extending it

- **A new live recon module:** add it to `consoles/recon/lookups.py` and route it in the type detector. Use `fetch()`/`dns_query()` — never raw urllib.
- **A new safe runner:** add a template to the Redcell allowlist with a validator. If it isn't obviously safe and non-destructive, make it a command-builder entry instead.
- **A new console:** add a row to `CONSOLES` in `common.py`, create `consoles/<slug>/app.py` with a `build_app()`, and it shows up in the switcher, the hub, and the launcher automatically.

## Deliberate non-goals

- No external dependencies (nothing new to security-audit).
- No cross-origin browser calls (server-side aggregation instead).
- No remote binding, no auth-over-the-network — this is a local tool, and staying loopback-only is the security model, not a limitation to fix later.
