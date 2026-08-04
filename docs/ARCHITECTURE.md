# Nucleus — architecture

## The idea

You had three piles of security work that never talked to each other: the OSINT website (lost in a migration), the pentest/opsec kit staged in `~/security-setup/`, and the client-facing OSINT report engine (also lost). Nucleus pulls all of it into one place.

The design constraint was to match how the rest of your stack already works: a small stdlib-only Python server bound to loopback, serving a hardened local web UI, with zero dependencies to audit. Same shape as coleos-hub and the old osint-console. That keeps the security surface tiny and means there's nothing to `pip install` and vet.

"One app, but it can be many" is solved by making one shared server core and thin consoles on top of it. It started as three security consoles; it's now five — the same two toolbelt consoles most machines want (a developer kit and a live system monitor) ride the exact same core. Run them together on one box and the launcher + switcher make it feel like a single app. Copy the repo to more machines and run one console on each; they still cross-link over loopback.

## Pieces

```
                       ┌─────────────────────────────┐
                       │  browser (127.0.0.1 only)    │
                       │  strict CSP, same-origin only │
                       └──────────────┬──────────────┘
                                      │ each tab talks ONLY to its own origin
   hub :8890   recon :8900   redcell :8910   bastion :8920   devkit :8930   systems :8940   coleos-hub :4747
        │           │             │               │              │              │            (external)
        └──────────── all import shared/common.py ──────────────────────────────┘
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
- **Audit log — off by default.** When persistent logging is enabled (`NUCLEUS_LOGGING=1`) every run is appended to `var/redcell-scans.jsonl`. It ships OFF: an authorized engagement generally shouldn't leave an on-disk record of what was scanned. With it off, nothing is written to `var/` — not the redcell audit trail, not the recon case history (`var/recon-scans.jsonl`), not saved nmap/nuclei output copies (`var/redcell-out/`). Results still render live in the UI for the session; only the disk writes are suppressed. The switch is one flag in `shared/common.py` (`LOGGING_ENABLED`).

### Redcell's native capabilities (no external tool, same guards)

Four things Redcell does itself, so they work on a box with nothing installed. None of them widens the threat model:

- **`hashtools.py` — hash identification (`POST /api/hash-id`).** Pure offline string analysis: a regex catalog of ~40 hash types, each mapped to its hashcat `-m` mode and John `--format`, confirmed against hashcat's own example hashes. No exec, no target, no network — so it needs no authorization gate; it's a POST only so the same-origin check keeps a hash out of a URL/log. Structured hashes (unique prefix) return one confident answer; raw hex returns the honest ambiguous set ranked by real-world frequency, because a bare 32-hex is genuinely MD5 or NTLM and pretending otherwise ships the wrong `-m`.
- **`webscan.py` — native web analyzer (`POST /api/web-analyze`).** At most two `common.fetch()` GETs (one plain, one with a probe Origin for a CORS reflection test) to a user-supplied URL, graded into headers/cookies/CORS/disclosure findings. It reuses `runners.validate_url` + `runners.scope_check` + a pre-fetch re-resolve, so it can never have a laxer notion of a valid/in-scope target than `/api/run`, and every fetch rides the same SSRF guard (connect-pinned to the validated IP, redirect-revalidated) — strictly less intrusive than the nmap/nikto runners, behind the same authorization gate.
- **`secretscan.py` — API-key leak scanner (`POST /api/secret-scan`).** Fetches the page, its inline scripts, and its own same-site JS bundles (same host or a subdomain of the same apex — never third-party CDNs), and regex-scans all of it for exposed credentials. Every fetch is a `common.fetch` through the SSRF guard, so a page that links an internal/metadata address can't turn it into an SSRF probe; the same-site check is a scope narrowing on top, not the security boundary. Publishable-by-design keys are separated from real leaks (`public_ok`) so the output is usable, and the generic `key = "..."` rule is entropy-gated against placeholders. Secrets go back to the browser (masked by default); the audit log records only counts and rule names, never the matched values. Same authorization + scope gate as the analyzer.
- **`playbooks.py` — assessment recipes (`GET /api/playbooks`).** Pure data: an ordered list of steps naming existing runners (or the native analyzer / secret scanner) plus their options. **This module executes nothing.** The browser walks the steps and runs each one through the already-gated `/api/run`, `/api/web-analyze`, and `/api/secret-scan`, so a playbook can't do anything a manual run couldn't, and every step still passes the full 8-step gate on its own. It's a usability layer over the gate, not a hole through it.
- **`handle_wordlist_preview` (`GET /api/wordlist-preview`).** Read-only. The `id` resolves through the same `wordlists.resolve()` allowlist + allowed-root re-check a runner uses, so it can only ever read a file already in the registry — never an arbitrary path. The file is streamed with a 2M line cap and a per-line length clamp so previewing a 130MB rockyou can't stall or blow memory.

## Bastion (defensive)

Read-only. Posture checks inspect this machine (sysctls, auditd, Quad9 DoT via `resolvectl`, Tor, WireGuard, MAC randomization, firewall, `arch-audit` CVEs) and report ok/warn/bad/unknown with the exact fix command — Bastion never runs sudo or changes anything. The **report engine** (`engine/osint_report.py`) takes a domain and produces a graded passive assessment (DNS, SPF/DMARC, TLS + security headers, crt.sh attack surface, InternetDB ports/CVEs) rendered to Markdown/HTML. It's importable and has a CLI, so the old income-machine skills that shell out to a `report.py` can point at it again.

## Devkit (developer toolbelt)

Does no I/O of any kind — no network, no filesystem — which is the whole point: whatever you paste in stays in the process. It follows the same shape as the security consoles but inverts one thing: instead of read-only GETs, every tool is a `POST /api/devkit/<tool>` that takes JSON and returns JSON, so nothing you're encoding or hashing ends up in a URL or a log.

All the real work lives in `consoles/devkit/tools.py` as small pure functions — `hash_text`, `encode`/`decode`, `jwt_decode`, `json_tool`, the `gen_*` generators, `time_convert`, `cron_next`, `base_convert`, `color_convert`, `humanize_bytes`/`parse_bytes`, `text_tools`, `text_diff`, `regex_test`, `cidr_info`/`cidr_contains`. Keeping them pure means each one is unit-testable by import with no server, and `app.py` handlers stay thin: parse the body, validate it's present, call the function, wrap the result in `Response.json` or a clean `Response.error(400, …)`. A tool never raises to the client.

Routes: `POST /api/devkit/{hash, encode, decode, jwt, json, gen, time, cron, base, color, bytes, text, diff, regex, cidr}`, plus a `GET /api/devkit/manifest` so the UI can render its sections without hardcoding them.

The one subprocess in the whole console is the regex tester. A user pattern can catastrophically backtrack, and re has no timeout, so `regex_test` runs the match in a short-lived `sys.executable -c <worker>` through `run_tool` with a hard timeout — our own Python, an argv list, no shell, trusted-shape JSON on stdin. A pathological pattern times out cleanly instead of pinning a server thread forever.

## Systems (live machine health)

Read-only and local-only, in the same spirit as Bastion's posture checks. Collectors live in `consoles/systems/sysinfo.py`; each reads `/proc`, `/sys`, or stdlib (`os`, `platform`, `shutil`, `socket`) and returns a JSON-able dict, wrapping file reads in try/except so a missing path degrades to partial data or `{available: false, reason}` instead of raising. The only subprocess calls are a short allow-list of read-only commands (`ip -o -j addr show`, `systemctl --user list-units …`) run through `run_tool` with an argv list and guarded by `which()` — missing tools fail soft to "n/a", never faked data. No writes, no killing processes, no config changes, nothing off the box.

Collectors: `overview`, `cpu` (per-core + overall by sampling `/proc/stat` twice), `memory`, `disks`, `network`, `listening` (parses `/proc/net/{tcp,tcp6,udp,udp6}` and best-effort maps inode→pid→name), `processes` (top by CPU and by memory, sampled), `sensors` (thermal/hwmon temps + battery), and `services`.

Routes are all GET — reads are safe cross-origin, so no POST or Origin check is needed: `GET /api/systems/{overview, cpu, memory, disks, network, listening, processes, sensors, services}`, plus a combined `GET /api/systems/all` for first paint.

## Shared frontend and the command palette

Every console's UI is a plain IIFE over `window.Nucleus` (`N.el`/`N.get`/`N.post`/`N.esc`/`N.toast`/`N.safeUrl`), styled by the shared design system in `shared/static/`, under the same strict CSP — no inline JS or CSS, DOM built with `N.el`/`textContent` so any echoed value (a JWT payload, a regex input, a process name) renders as inert text, never `innerHTML`.

`shared/static/nucleus.js` also holds the cross-console furniture: the switcher (with live sibling health dots), the keyboard shortcuts (`g` + a letter to jump, `/` to focus a console's main input, `1`–`6` for the six pages), and the **command palette**. Ctrl-K / Cmd-K opens a fuzzy launcher whose entries are computed at open time from two sources: one "Go to <console>" per sibling, and one entry per `.section-title` and card heading on the current page (scroll-into-view). Because it discovers sections from the DOM, it works on every console with zero per-console registration — a new tool that adds a heading is reachable from the palette for free. It's exposed as `N.openCommandPalette()` / `N.closeCommandPalette()`.

## Extending it

- **A new live recon module:** add it to `consoles/recon/lookups.py` and route it in the type detector. Use `fetch()`/`dns_query()` — never raw urllib.
- **A new safe runner:** add a template to the Redcell allowlist with a validator. If it isn't obviously safe and non-destructive, make it a command-builder entry instead.
- **A new console:** add a row to `CONSOLES` in `common.py`, create `consoles/<slug>/app.py` with a `build_app()`, and it shows up in the switcher, the hub, and the launcher automatically.

## Deliberate non-goals

- No external dependencies (nothing new to security-audit).
- No cross-origin browser calls (server-side aggregation instead).
- No remote binding, no auth-over-the-network — this is a local tool, and staying loopback-only is the security model, not a limitation to fix later.
