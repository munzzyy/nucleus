# Nucleus

One local command center for the whole security kit — recon, offense, and defense — plus the apps you already run and the tools you've shipped. It's **one app** made of **three consoles**, each of which can also run on its own machine.

Everything binds to `127.0.0.1` only. Pure stdlib Python, zero dependencies. Nothing phones home.

```
┌─ Nucleus hub  :8890 ─ the command center. links + live status of everything.
├─ Recon        :8900 ─ OSINT. paste a username / email / domain / IP / phone, get live passive recon.
├─ Redcell      :8910 ─ the pentest kit. safe runners + web analyzer + hash ID + one-click assessments.
└─ Bastion      :8920 ─ opsec posture of this box + the OSINT report engine (graded domain assessments).
```

## Run it

It's a real desktop app. One command opens a single native window with everything inside it:

```bash
cd ~/Projects/nucleus
python3 bin/nucleus            # opens the native app window
```

Or install it and just click the **Nucleus** icon in your app menu:

```bash
bash bin/install.sh           # PATH command + app-menu entry + icon
nucleus                       # from anywhere
```

Install puts `nucleus` on your PATH (`~/.local/bin`), adds a **Nucleus** app-menu entry with an icon (one click, no terminal), and drops in a systemd `--user` unit for optional autostart. No root, loopback only, fully reversible (undo lines print at the end).

The app starts every console — and your coleos-hub, if it's there — in the background, then opens the hub. The switcher at the top moves between consoles inside the same window. Set your API keys from the hub's **Settings** panel; no file editing.

### Headless / power use

```bash
python3 bin/nucleus up             # start everything, no window (Ctrl-C stops all)
python3 bin/nucleus status         # what's online
python3 bin/nucleus up --only recon,bastion
python3 bin/nucleus doctor         # sanity check the environment
python3 bin/nucleus open bastion   # open one console in the browser
```

### Run a console on its own machine

Each console is standalone. Copy the repo to another box and run just one:

```bash
python3 consoles/recon/app.py     # only Recon, on :8900
```

The switcher at the top of every console lights up whichever siblings it can reach on loopback, so a single machine running all three feels like one app — and three machines each running one still cross-link.

## The three consoles

**Recon (OSINT).** A rebuild of the old osint-console. Auto-detects what you paste and runs live, passive, keyless lookups: username presence across ~30 sites, email breach exposure + Gravatar + MX, full domain workup (DNS, whois, subdomains via crt.sh, SPF/DMARC, security headers, hosting/ports/CVEs), IP intel (open ports, CVEs, geo, reverse DNS, Tor relay check), and phone validation (optional API key). Anything without a live module falls back to curated pivot links and a Google-dork builder. Every outbound request goes through one SSRF-guarded fetch; DNS rides encrypted DNS-over-HTTPS.

**Redcell (offensive).** A front-end over the ~80-tool pentest kit from `~/security-setup/`. It shows which tools are actually installed, runs a small set of **safe, non-destructive** checks behind a hard "I am authorized to test this target" gate (no shell, allow-listed binaries, validated targets, audit-logged), and — for the aggressive tools — builds the command for you to run yourself instead of executing it. On top of that it now has four things that don't need any external tool:

- **Website assessment playbooks** — pick a recipe ("Website quick assessment", "Domain recon", "TLS audit"), type the target once, and it runs the right tools in order and collects the findings. One click instead of remembering which five tools to run and retyping the target five times.
- **Native web analyzer** — point it at a URL and get an instant graded read on security headers, cookie flags, CORS, and version disclosure. Pure stdlib through the same SSRF-guarded fetch recon uses, so it works even on a box where nothing else is installed.
- **Secret / API-key leak scanner** — pulls a site's HTML, inline scripts, and its own JS bundles, and flags credentials shipped to the browser by accident: cloud keys, payment keys, source-control tokens, webhook URLs, private keys, JWTs, and high-entropy `apiKey: "..."` assignments. It separates real leaks from keys that are *meant* to be public (Stripe `pk_live_`, Firebase browser keys) so the report is signal, not noise. Only scans the site's own JS (same host / same apex), and the audit log records counts, never the secrets themselves.
- **Hash identifier** — paste a hash, get the type, the hashcat `-m` mode, the John `--format`, and a ready-to-paste crack command. ~40 types confirmed against hashcat's example hashes; raw hex is shown as the honest ambiguous set (a 32-hex string is MD5 *or* NTLM, and it says so) instead of one confident wrong guess.
- **Wordlist browser** — search the installed wordlists and preview any of them (first lines + total count) before you kick off a brute that runs for five minutes.
- **DDoS resilience test** — checks whether a target's DDoS *defenses* hold: does rate limiting kick in, is there a CDN/WAF at the edge, does latency stay flat under load, where's the breaking point. You get a graded A–F read-out with the exact fixes to hand the client. The native probe is a bounded diagnostic on purpose — hard-capped in code at 40 requests in flight / 1500 total / 20s, with a circuit breaker that stops the moment the target shows distress. It speaks real HTTP over real TCP through the same SSRF-guarded fetch; there is no packet flood, no spoofing, no amplification anywhere in it, so it can measure a defense without being able to take anything down. For actual high-volume stress there's a command builder that hands you a proper k6/vegeta/hey/wrk/ab command to run yourself. Optional ownership verification (a DNS TXT record or a well-known file) stamps the report with proof you control the target — good to have on a real engagement.

Authorized / lab / CTF use only.

**Bastion (defensive).** Two halves. A read-only posture dashboard that tells you whether this machine is actually hardened — kernel sysctls, auditd, encrypted Quad9 DNS, Tor, WireGuard, MAC randomization, firewall, CVE audit — and shows the exact command to fix anything that isn't. And the **OSINT report engine**: give it a domain and it produces a graded (A–F) passive security assessment with prioritized findings, rendered to Markdown and HTML.

## Security model

- **Loopback only.** Every server binds `127.0.0.1`. Not a config knob.
- **Host + Origin guards.** Requests with a foreign `Host` header are refused (anti DNS-rebinding); every POST needs a same-origin `Origin`/`Referer` (anti-CSRF).
- **Strict CSP.** `default-src 'none'`; no external scripts, styles, fonts, or images. The UI only ever calls its own origin — cross-console data is aggregated server-side.
- **SSRF guard.** Recon's only door to the internet is one `fetch()` that refuses loopback, RFC1918, link-local, and reserved addresses.
- **No shell, ever.** Redcell executes only allow-listed binaries with an argv list (never a string), only after the authorization gate, and logs every run. Aggressive tools are never auto-run.
- **Read-only on the system.** Bastion inspects and reports; it never runs sudo or changes system state.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how it all fits together.

## OpSec — keeping a scan from leading back to you

Two different things, and it's worth being clear about which is which.

**What the tool does for you:**
- **Neutral fingerprint.** Outbound requests use a normal browser `User-Agent`, not a self-identifying tool name, and the CORS probe sends a neutral `Origin`. Nothing in a request labels the traffic as this tool. Set your own with `NUCLEUS_UA="..."` per engagement (e.g. to match a UA the client expects).
- **Exposure gate.** Every target-touching run is refused while your real IP is exposed — no VPN detected — unless the target is your own lab or you tick "scan anyway". The top bar already shows EXPOSED/protected in real time; the gate turns that warning into an actual block so you don't fire a scan from your home IP by reflex.

**What the tool cannot do — and you have to handle yourself:**
- **It does not anonymize your traffic.** A local tool can change a header and refuse to run; it can't route your packets. Your source IP is whatever your machine is using.
- **The external scanners connect on their own.** nmap, nuclei, nikto, sqlmap, hydra, gobuster and the rest open their own sockets from your real IP regardless of anything here. The command builder and Expert mode run real binaries — same story.

**To actually be covered on an engagement:**
1. Bring up your VPN (Mullvad is what the exposure check looks for) *before* you touch a target. With it up, the gate stops blocking and everything — native tools and external binaries — rides the tunnel.
2. For the external CLI tools specifically, if you want per-tool routing or a chain, run them through `proxychains` (or a SOCKS proxy / your VPN's kill-switch) so a VPN drop can't leak a single packet mid-scan.
3. Use a client-agreed source IP where the scope calls for one, and keep the local audit log (`var/redcell-scans.jsonl`, which stays on your box) as your record of what ran when.

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
