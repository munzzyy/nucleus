# Changelog

All notable changes to Nucleus are kept here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims
for [semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- A refused request no longer leaves its body on a keep-alive connection.
  Before this, a page on any site could POST to a console with a body that was
  itself a complete same-origin request. The server refused the outer request
  and then ran the inner one, past the Origin and Host checks. Every refusal
  now closes the connection with `Connection: close`. So does a request with a
  malformed Content-Length.

### Added
- `nucleus --version` prints the running version and exits.
- A static accessibility check in the test suite. Every console page must set a
  page language and give every form control and button an accessible name.

### Changed
- Nucleus now needs Python 3.11 or newer and checks at startup. `doctor` reports
  the shortfall and every other command refuses before it binds a port. CI runs
  the suite on 3.11 through 3.14.
- The hub only lists the external COLE-OS Hub when this machine has it. That
  means its launcher is on disk or its port answers. Everyone else gets the
  empty Apps panel instead of a card that is always offline.
- The `dns_query` docstring and `docs/ARCHITECTURE.md` now say DoH goes to
  Cloudflare first with Google as the fallback. That is what the code does.

### Fixed
- A browser tab closed mid-response no longer prints a BrokenPipeError or
  ConnectionResetError traceback to the terminal.
- The 12 Redcell form controls whose visible label was not tied to the control
  now carry a real `for=`. A screen reader announces each one by name.

## [1.0.0] - 2026-09-25

First public release. Nucleus is a loopback-only security command center in
plain stdlib Python with zero dependencies. A hub and six consoles share one
hardened server core.

### Added
- The core in `shared/common.py` keeps the whole security model in one place.
  It binds to loopback only and checks the Host header against DNS rebinding.
  Every POST needs an exact-port Origin or Referer. Pages get a strict
  `default-src 'none'` CSP. All outbound HTTP goes through one SSRF-guarded
  `fetch()` that pins a resolved public IP and checks every redirect hop.
- Recon (:8900) runs passive and keyless OSINT on whatever you paste, from a
  username or email to a domain, IP, phone number or file hash. Scans chain
  into each other and are deep-linkable.
- Redcell (:8910) fronts the local pentest kit. An 8-step gate runs only
  allowlisted binaries with an argv list and never a shell string. Its native
  tools need nothing installed: a web analyzer, a secret-leak scanner, a hash
  identifier for 32 confirmed types, a wordlist browser and a DDoS resilience
  test. That test is hard capped at 1000 concurrent requests, 500k requests
  and 10 minutes.
- Bastion (:8920) has a read-only hardening dashboard and the graded (A-F)
  OSINT report engine with MTA-STS and TLS-RPT checks. Its scrub panel shows
  what a file gives away and strips it with mat2, then checks the result again.
- Devkit (:8930) is the everyday developer toolbelt, from hashes and encoders
  to a regex tester that runs in a time-bounded subprocess. It does no network
  or filesystem I/O.
- Systems (:8940) is a read-only live view of the machine from `/proc`, `/sys`
  and a short allowlist of read-only commands.
- Dork (:8950) turns a website into 57 dorks across 12 categories. Each one is
  translated per engine for Google, Bing, DuckDuckGo, Yandex and Brave.
- The hub (:8890) gathers each console's status over loopback and holds the
  settings, so the browser never makes a cross-origin call.
- Engagements give a case an authorized scope that becomes the Redcell
  allowlist. Findings collect on the case and export as one Markdown report.
- Privacy controls are all off by default. `NUCLEUS_SOCKS` sends the app's own
  recon and DNS through Tor or a SOCKS5 proxy. `NUCLEUS_DOH` picks the DoH
  resolvers. `NUCLEUS_KEYRING` keeps API keys in the OS keyring.
  `NUCLEUS_LOGGING` opts in to on-disk history. `nucleus wipe` securely erases
  all on-disk case data.
- A native desktop app in one Qt window on the system PySide6. A one-click
  installer adds a PATH command and an app-menu entry. Ctrl-K opens a command
  palette on every console.
- SECURITY, THREAT_MODEL and CONTRIBUTING docs, a dependency-free CI matrix and
  issue and PR templates.

### Changed
- Relicensed from MIT to GPL-3.0-or-later, so copies and modified versions stay
  open. Earlier commits remain under MIT.

[Unreleased]: https://github.com/munzzyy/nucleus/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/munzzyy/nucleus/releases/tag/v1.0.0
