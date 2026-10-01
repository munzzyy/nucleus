# Changelog

All notable changes to Nucleus are kept here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
for [semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `nucleus --version` prints the running version and exits.
- A static accessibility check in the test suite: every console page must set a
  page language and give every form control and button an accessible name.

### Changed
- Nucleus now needs Python 3.11 or newer, enforced at startup. `doctor` reports
  the shortfall and every other command refuses before it binds a port. CI runs
  the suite on 3.11 through 3.14.
- The `dns_query` docstring and `docs/ARCHITECTURE.md` now say DoH goes to
  Cloudflare first with Google as the fallback, matching the code.

### Fixed
- A closed browser tab mid-response no longer prints a BrokenPipeError or
  ConnectionResetError traceback to the terminal.
- The 12 Redcell form controls whose visible label was not tied to the control
  now carry a real `for=`, so a screen reader announces each one.

## [1.0.0] - 2026-09-25

First public release. Nucleus is a loopback-only, zero-dependency stdlib-Python
security command center: a hub plus six consoles that share one hardened server
core.

### Added
- **The core** (`shared/common.py`): a single stdlib server base with the whole
  security model in one place. Loopback-only bind, a Host-header allowlist
  against DNS-rebinding, an exact-port Origin/Referer check against CSRF, a
  strict `default-src 'none'` CSP, a sandboxed static file server, and one
  SSRF-guarded `fetch()` that pins to a resolved public IP and re-validates
  every redirect hop.
- **Recon** (:8900): passive, keyless OSINT that auto-detects what you paste.
  Username presence across the WhatsMyName set, email breach and Gravatar and
  infostealer checks, domain workup with certificate-transparency subdomains and
  DNSSEC and SPF/DMARC, IP intel with RIPEstat and SANS ISC, ASN lookups, crypto
  balances with an OFAC check, offline phone intel, and file-hash, MAC and
  Discord snowflake decoding. Scans chain into each other and are deep-linkable.
- **Redcell** (:8910): a front end over the local pentest kit. An 8-step no-shell
  gate (allowlist, authorization, validate, scope, resolve options, wordlist id,
  installed check, re-resolve and pin before spawn) runs only allowlisted
  binaries with an argv list, never a shell string. Native tools that need
  nothing installed: a web analyzer, a secret-leak scanner, a hash identifier
  for 32 confirmed types, a wordlist browser, and a DDoS resilience test hard
  capped at 1000 concurrent, 500k requests and 10 minutes. Server-side run
  cancel, command builders for the aggressive tools, and a searchsploit lookup.
- **Bastion** (:8920): a read-only hardening posture dashboard, the graded (A-F)
  OSINT report engine with MTA-STS and TLS-RPT checks, and a metadata scrub
  panel that reads what a file gives away and strips it with mat2 in sandboxed
  parsers, then re-inspects to prove it worked.
- **Devkit** (:8930): the everyday developer toolbelt. Hashes, encoders, a JWT
  decoder, JSON tools, generators built on `secrets`, time and cron, base and
  color conversion, text transforms, a diff, a CIDR calculator, a regex tester
  that runs in a time-bounded subprocess, and an in-memory file hash. No network
  or filesystem I/O.
- **Systems** (:8940): a read-only live view of the machine from `/proc`, `/sys`
  and a short allowlist of read-only commands. CPU, memory, disk, network,
  listening ports mapped to processes, sensors, battery, and `--user` services,
  with sparklines and a downloadable snapshot.
- **Dork** (:8950): paste a website and get 57 professional dorks across 12
  categories, each translated per engine for Google, Bing, DuckDuckGo, Yandex
  and Brave, paired with deep links into the specialist sources operators reach
  for. Optional one-click handoff into real Firefox tabs through an allowlisted
  loopback launcher.
- **The hub** (:8890): the command center. It aggregates each console's status
  over loopback and holds the settings, so the browser never makes a
  cross-origin call.
- **Engagements**: a local case model with an authorized scope that becomes the
  Redcell allowlist, a parsed-findings library, and a one-click Markdown report.
- **Privacy controls**, all off by default: `NUCLEUS_SOCKS` routes the app's own
  recon and DNS through Tor or a SOCKS5 proxy with DNS resolved inside the
  tunnel, `NUCLEUS_DOH` picks the DoH resolvers, `NUCLEUS_KEYRING` stores API
  keys in the OS keyring over libsecret, `NUCLEUS_LOGGING` opts in to on-disk
  history, and `nucleus wipe` securely erases all on-disk case data.
- **A native desktop app**: one Qt/QtWebEngine window over the system PySide6
  with no new Python dependency, a one-click installer with a PATH command and an
  app-menu entry, and a Ctrl-K command palette across every console.
- **Ship docs**: SECURITY, THREAT_MODEL, CONTRIBUTING, a dependency-free CI
  matrix, and issue and PR templates.

### Changed
- Relicensed from MIT to GPL-3.0-or-later, so copies and modified versions stay
  open. Earlier commits remain under MIT.

[Unreleased]: https://github.com/munzzyy/nucleus/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/munzzyy/nucleus/releases/tag/v1.0.0
