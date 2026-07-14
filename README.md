# Nucleus

One local command center for the whole security kit — recon, offense, and defense — plus the apps you already run and the tools you've shipped. It's **one app** made of **three consoles**, each of which can also run on its own machine.

Everything binds to `127.0.0.1` only. Pure stdlib Python, zero dependencies. Nothing phones home.

```
┌─ Nucleus hub  :8890 ─ the command center. links + live status of everything.
├─ Recon        :8900 ─ OSINT. paste a username / email / domain / IP / phone, get live passive recon.
├─ Redcell      :8910 ─ the pentest kit. tool inventory + authorization-gated safe runners + command builder.
└─ Bastion      :8920 ─ opsec posture of this box + the OSINT report engine (graded domain assessments).
```

## Run it

```bash
cd ~/Projects/nucleus
python3 bin/nucleus up --open      # starts all four, opens the hub in your browser
```

That's the whole thing. `Ctrl-C` stops everything. Other commands:

```bash
python3 bin/nucleus status         # what's online
python3 bin/nucleus up --only recon,bastion
python3 bin/nucleus doctor         # sanity check the environment
python3 bin/nucleus open bastion   # open one console
```

### Install it as a real app

```bash
bash bin/install.sh
```

Puts `nucleus` on your PATH (`~/.local/bin`), adds a **Nucleus** entry to your app menu with an icon, and drops in a systemd `--user` unit you can enable for autostart (`systemctl --user enable --now nucleus.service`). No root, loopback only, fully reversible (undo lines are printed at the end).

### Run a console on its own machine

Each console is standalone. Copy the repo to another box and run just one:

```bash
python3 consoles/recon/app.py     # only Recon, on :8900
```

The switcher at the top of every console lights up whichever siblings it can reach on loopback, so a single machine running all three feels like one app — and three machines each running one still cross-link.

## The three consoles

**Recon (OSINT).** A rebuild of the old osint-console. Auto-detects what you paste and runs live, passive, keyless lookups: username presence across ~30 sites, email breach exposure + Gravatar + MX, full domain workup (DNS, whois, subdomains via crt.sh, SPF/DMARC, security headers, hosting/ports/CVEs), IP intel (open ports, CVEs, geo, reverse DNS, Tor relay check), and phone validation (optional API key). Anything without a live module falls back to curated pivot links and a Google-dork builder. Every outbound request goes through one SSRF-guarded fetch; DNS rides encrypted DNS-over-HTTPS.

**Redcell (offensive).** A front-end over the ~80-tool pentest kit from `~/security-setup/`. It shows which tools are actually installed, runs a small set of **safe, non-destructive** checks behind a hard "I am authorized to test this target" gate (no shell, allow-listed binaries, validated targets, audit-logged), and — for the aggressive tools — builds the command for you to run yourself instead of executing it. Authorized / lab / CTF use only.

**Bastion (defensive).** Two halves. A read-only posture dashboard that tells you whether this machine is actually hardened — kernel sysctls, auditd, encrypted Quad9 DNS, Tor, WireGuard, MAC randomization, firewall, CVE audit — and shows the exact command to fix anything that isn't. And the **OSINT report engine**: give it a domain and it produces a graded (A–F) passive security assessment with prioritized findings, rendered to Markdown and HTML.

## Security model

- **Loopback only.** Every server binds `127.0.0.1`. Not a config knob.
- **Host + Origin guards.** Requests with a foreign `Host` header are refused (anti DNS-rebinding); every POST needs a same-origin `Origin`/`Referer` (anti-CSRF).
- **Strict CSP.** `default-src 'none'`; no external scripts, styles, fonts, or images. The UI only ever calls its own origin — cross-console data is aggregated server-side.
- **SSRF guard.** Recon's only door to the internet is one `fetch()` that refuses loopback, RFC1918, link-local, and reserved addresses.
- **No shell, ever.** Redcell executes only allow-listed binaries with an argv list (never a string), only after the authorization gate, and logs every run. Aggressive tools are never auto-run.
- **Read-only on the system.** Bastion inspects and reports; it never runs sudo or changes system state.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how it all fits together.

## Layout

```
shared/common.py        the server base + every security guard, in one place
shared/static/          the shared design system (one look across all consoles)
hub/                    the command center
consoles/recon/         OSINT
consoles/redcell/       offensive
consoles/bastion/       defensive / opsec
engine/osint_report.py  the graded domain-assessment engine (also a CLI)
bin/                    launcher, installer, desktop + systemd files
```

Authorized, lab, and educational use only.
