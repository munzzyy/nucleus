# Nucleus

[![tests](https://github.com/munzzyy/nucleus/actions/workflows/ci.yml/badge.svg)](https://github.com/munzzyy/nucleus/actions/workflows/ci.yml)

One local command center for your machine: recon, offense, defense, a developer toolbelt, a search-dork generator, and a live view of the box you're on, all in one loopback app. The whole security kit is still here; now it sits next to the tools you reach for the rest of the day. It's one app made of six consoles, and each console can also run on its own machine.

Everything binds to `127.0.0.1` only. Pure stdlib Python, zero dependencies, and nothing phones home.

```
┌─ Nucleus hub  :8890 ─ the command center. links + live status of everything.
├─ Recon        :8900 ─ OSINT. paste a username / email / domain / IP / ASN / phone / hash / crypto address / Discord ID, get live passive recon (incl. infostealer + sanctions checks).
├─ Redcell      :8910 ─ the pentest kit. safe runners + web analyzer + hash ID + one-click assessments.
├─ Bastion      :8920 ─ opsec posture of this box + the OSINT report engine (graded domain assessments).
├─ Devkit       :8930 ─ dev toolbelt. hashes, encoders, JWT, JSON, generators, time, regex, CIDR.
├─ Systems      :8940 ─ live local machine health: CPU, memory, disk, network, processes, sensors.
└─ Dork         :8950 ─ paste a website, get the full professional dork set across every engine + specialist source.
```

## Run it

It's a real desktop app. One command opens a single native window with everything inside it:

```bash
git clone https://github.com/munzzyy/nucleus
cd nucleus
python3 bin/nucleus            # opens the native app window
```

Or install it and click the **Nucleus** icon in your app menu:

```bash
bash bin/install.sh           # PATH command + app-menu entry + icon
nucleus                       # from anywhere
```

Install puts `nucleus` on your PATH (`~/.local/bin`), adds a Nucleus app-menu entry with an icon (one click, no terminal), and drops in a systemd `--user` unit for optional autostart. The entry lands in your app launcher, so you can pin Nucleus to your dock or taskbar like any other app. No root, loopback only, fully reversible (the undo lines print at the end).

You need Python 3.11 or newer and a browser, nothing else. The one-click install targets Linux desktops; the app itself runs anywhere Python does. Redcell's runners use whatever pentest tools you already have on the box, and the scrub panel uses mat2 when it's present. Both say what's missing and keep working without it.

The app starts every console (and your coleos-hub, if it's there) in the background, then opens the hub. The switcher at the top moves between consoles inside the same window. Set your API keys from the hub's Settings panel, no file editing.

Hit Ctrl-K (Cmd-K on a Mac) anywhere and you get a command palette: type a few letters to jump to another console or straight to any tool section on the page you're on. It reads the page's own headings, so it works the same on every console with nothing to configure, and it shows your most-recently-used commands first when the box is empty. Both the palette and the `?` help overlay trap focus and restore it on close.

Every console shares one small UI kit, so results behave the same everywhere: a Copy / Copy JSON / Download bar on result cards, a screen-reader announcement on every toast, remembered inputs and deep-linkable state, and honest loading, empty, and error blocks. A failure looks like a failure: red, not a muted dash.

### Headless / power use

```bash
python3 bin/nucleus up             # start everything, no window (Ctrl-C stops all)
python3 bin/nucleus status         # what's online
python3 bin/nucleus up --only recon,bastion
python3 bin/nucleus doctor         # sanity check the environment
python3 bin/nucleus open bastion   # open one console in the browser
python3 bin/nucleus wipe           # securely erase all on-disk case data (confirm; --yes to skip)
```

Environment knobs, all optional and all off by default:

```bash
NUCLEUS_SOCKS=127.0.0.1:9050   # route the app's recon + DNS through Tor / a SOCKS5 proxy
NUCLEUS_DOH=https://dns.quad9.net/dns-query   # pick your DoH resolver(s), comma-separated
NUCLEUS_KEYRING=1              # store API keys in the OS keyring, not plaintext var/.env
NUCLEUS_LOGGING=1              # opt IN to on-disk scan/audit history (off = no trace)
NUCLEUS_UA="..."              # set the outbound User-Agent for an engagement
```

### Run a console on its own machine

Each console is standalone. Copy the repo to another box and run just one:

```bash
python3 consoles/recon/app.py     # only Recon, on :8900
```

The switcher at the top of every console lights up whichever siblings it can reach on loopback, so a single machine running all six feels like one app, and six machines each running one still cross-link.

## The consoles

**Recon (OSINT).** A rebuild of the old osint-console. It auto-detects what you paste and runs live, passive, keyless lookups:

- **Username** presence across the full WhatsMyName set (700+ sites) plus a HudsonRock infostealer check on the handle.
- **Email** breach exposure (XposedOrNot + LeakCheck), a full Gravatar profile (real name, job, location, and verified linked social accounts pulled from the email hash), MX/SPF posture, and a HudsonRock infostealer-infection check.
- **Domain** workup: DNS, RDAP whois, subdomains merged from crt.sh, CertSpotter, RapidDNS, HackerTarget and the Wayback CDX (crt.sh alone is chronically rate-limited, so the extra certificate-transparency and passive sources fill the gaps), DNSSEC chain-of-trust status, SPF/DMARC, security headers, hosting/ports/CVEs, historical URLs from the Internet Archive, and org-level infostealer exposure (how many employees and users tied to the domain turned up in stealer logs, and where their credentials were captured).
- **IP** intel: open ports, CVEs, geo, reverse DNS, Tor-relay check, plus RIPEstat (announcing ASN, covering prefix, AS holder) and SANS ISC (attack reports, network abuse contact, threat-feed membership).
- **ASN** (paste `AS15169`): holder, allocating registry, and the prefixes it announces, from RIPEstat.
- **Crypto** address balances (BTC via blockchain.info + mempool.space, ETH via Ethplorer) with an OFAC sanctions-list check on every address.
- **Phone** numbers get a full offline read with no key: country (with flag), clean E.164 / national / international formats, line type (toll-free / premium / geographic), structural validity, and for North American numbers the state, time zone, and the current local time at that number. A NumLookup or IPQualityScore key adds live carrier and fraud data on top.
- **File-hash** reputation (CIRCL + MalwareBazaar), **MAC** vendor lookup, and **Discord snowflake** decoding (account-creation time worked out offline from the ID, no call).

Anything without a live module falls back to curated pivot links and a Google-dork builder. When a domain scan turns up subdomains, one click feeds them straight into the subdomain-takeover check, and any username, verified social account, IP or ASN a scan surfaces is one click from its own deep scan. The username grid filters as you type and can sort found-first or show only hits; scans are deep-linkable and kept in a recent-scans list. Every outbound request goes through one SSRF-guarded fetch, which now tries each resolved address in turn, so a dead IPv6 route no longer kills a lookup, and DNS rides encrypted DNS-over-HTTPS. Every source is keyless; adding a free API key in Settings only opens up deeper data.

**Redcell (offensive).** A front-end over the ~80-tool pentest kit from `~/security-setup/`. It shows which tools are actually installed, runs a small set of safe, non-destructive checks behind a hard "I am authorized to test this target" gate (no shell, allow-listed binaries, validated targets, audit-logged), and for the aggressive tools it builds the command for you to run yourself instead of executing it. On top of that it has a set of built-ins that need no external tool at all:

- **Website assessment playbooks.** Pick a recipe ("Website quick assessment", "Domain recon", "TLS audit"), type the target once, and it runs the right tools in order and collects the findings. One click instead of remembering which five tools to run and retyping the target five times.
- **Native web analyzer.** Point it at a URL and get an instant graded read on security headers, cookie flags, CORS, and version disclosure. Pure stdlib through the same SSRF-guarded fetch recon uses, so it works even on a box where nothing else is installed.
- **Secret / API-key leak scanner.** Pulls a site's HTML, inline scripts, and its own JS bundles, and flags credentials shipped to the browser by accident: cloud keys, payment keys, source-control tokens, webhook URLs, private keys, JWTs, and high-entropy `apiKey: "..."` assignments. It separates real leaks from keys that are meant to be public (Stripe `pk_live_`, Firebase browser keys) so the report is signal, not noise. It only scans the site's own JS (same host / same apex), and the audit log records counts, never the secrets themselves.
- **Hash identifier.** Paste a hash, get the type, the hashcat `-m` mode, the John `--format`, and a ready-to-paste crack command. It knows 32 structured hash types, each confirmed against hashcat's example-hashes list, and shows raw hex as the honest ambiguous set (a bare 32-character digest is MD5 or NTLM, and it says so) instead of one confident wrong guess.
- **Wordlist browser.** Search the installed wordlists and preview any of them (first lines + total count) before you kick off a brute that runs for five minutes.
- **DDoS resilience test.** Checks whether a target's DDoS *defenses* hold: does rate limiting kick in, is there a CDN or WAF at the edge, does latency stay flat under load, where's the breaking point. You get a graded A-F read-out with the exact fixes to hand the client. It runs in tiers, from a light smoke diagnostic a well-provisioned site won't even notice up to a genuine high-fan-out load test, and it's hard-capped in code at 1000 concurrent requests, 500,000 requests total, and 10 minutes. The top of that range is a real stress test that can hurt an under-provisioned target, so it's for authorized engagements only, and the heaviest runs are the kind you get written sign-off for first. It speaks real HTTP over real TCP through the same SSRF-guarded fetch, so there's no packet flood, spoofing, or amplification in it, but at full tilt it is not a toy. Every run is gated: the authorization checkbox, the opsec gate (it won't fire while your own IP is exposed), a per-origin cooldown, and a circuit breaker that backs off the moment the target shows distress. Optional ownership verification (a DNS TXT record or a well-known file) stamps the report with proof you control the target. For load past what this covers, a command builder hands you a proper k6/vegeta/hey/wrk/ab command to run yourself.

Authorized, lab, and CTF use only.

**Bastion (defensive).** Three parts. A read-only posture dashboard tells you whether this machine is actually hardened: kernel sysctls, auditd, encrypted Quad9 DNS, Tor, WireGuard, MAC randomization, firewall, and a CVE audit, each with the exact command to fix what isn't. The OSINT report engine takes a domain and produces a graded (A-F) passive security assessment with prioritized findings, rendered to Markdown and HTML. Its email-security section also checks MTA-STS (it fetches the domain's `.well-known/mta-sts.txt` policy and reads its enforce/testing mode) and TLS-RPT (the `_smtp._tls` reporting record) alongside SPF/DMARC/DKIM, and the report and its fix plan are one-click copyable and downloadable (JSON, findings Markdown, and the hardening commands as a runnable `.sh`). The scrub panel is the opsec workbench for anything you're about to share: drop in a photo, a video, a PDF, a document or an audio file (69 formats) and it tells you in plain words what the file gives away, like "this file reveals where it was taken, what device took it, who made it". Every field is labeled by what it exposes: location (GPS), identity (author, comments), device (camera make, model, serial), time, software, or merely structural. One click strips it with mat2 in sandboxed parsers, then the cleaned copy is re-inspected to prove it worked and you're shown exactly which fields went away. That last distinction matters for video: formats like MP4 require fields such as codec id and bitrate, so mat2 refills them by design. The panel judges the result on whether anything identifying survived rather than on a raw field count, so a properly scrubbed video reads as clean instead of falsely reporting failure. Cleaned files stay on loopback, and uploads auto-purge after 24 hours.

**Devkit (developer toolbelt).** The everyday dev stuff you'd otherwise paste into some sketchy website. Hashing (md5 through blake2b), encoders and decoders (base64/base64url/base32/hex/url/html/rot13), a JWT decoder that can verify an HS256 signature with your own secret, JSON pretty-print/minify/validate with the exact line and column on a syntax error, generators for UUIDs, passwords, random bytes and secret keys built on `secrets`, time and timezone conversion plus a cron "when does this next fire" preview, base and color conversion, byte humanizing, a pile of text transforms, a unified diff, a CIDR calculator, and a regex tester. It also does HMAC (text + key + algorithm to a hex MAC), CRC32 and Adler32 checksums, UUID v5 (a deterministic namespace hash), and hashing a whole file: drop or pick a file and get md5/sha1/sha256/sha512/blake2b of the bytes. The file is hashed in memory only, never written to disk, never parsed, so it's safe to run on anything. Every tool computes in Python on loopback; nothing you paste or drop in leaves the box. The regex tester runs each match in a short-lived subprocess with a hard timeout, so a catastrophic-backtracking pattern times out cleanly instead of hanging the server. Apart from that in-memory file hash reading the request body, Devkit does no network or filesystem I/O at all.

**Dork (search recon).** Paste a website and it builds the full professional dork set a pro runs during passive recon: attack surface, login/admin panels, API & Swagger docs, exposed files and directory listings, config/secrets, logs and errors, documents, cloud & DevOps leaks (Spring Boot actuator, Kubernetes dashboards, Terraform state, Firebase, container registries), off-domain code/paste/bucket leaks, people OSINT, tech fingerprinting, and redirect/parameter hunting. That's 57 queries across 12 categories, each one click away on Google, Bing, DuckDuckGo, Yandex, and Brave. Because no engine actually speaks Google's dialect, every dork is translated per engine before it opens (Bing/Brave want `inbody:` not `intext:`; Yandex uses `mime:`/`title:` and has no `inurl:`; DuckDuckGo reliably honors only `site:`), and an engine that can't run one of a dork's operators is dimmed and marked `~` so the tool never pretends a query runs the same everywhere. With Links → Firefox on, clicking any dork, or a category's Open all, sends the query straight into real Firefox tabs through a loopback launcher that rebuilds the URL server-side and only ever opens a known search engine or an allowlisted OSINT source. It normalizes whatever you paste (scheme, path, port, and `www.` come off; a subdomain still resolves its apex and brand), colors every dork by risk (info / recon / sensitive), and pairs the query set with direct deep links into the specialist sources Google operators can't reach: crt.sh certificate transparency, Censys, Shodan, GitHub and grep.app code search, the Wayback Machine (plus its raw CDX index), urlscan.io, VirusTotal, RapidDNS, AlienVault OTX, ViewDNS, BuiltWith, and more. Copy the whole sheet as Markdown or a plain query list, or grab any single dork. It only builds strings: every query is content a search engine already indexed, and the UI says plainly that running them is for assets you own or are authorized to test.

**Systems (live machine health).** A read-only look at the box you're on: an overview (host, kernel, OS, uptime, load, RAM), per-core and overall CPU use, memory and swap, disk usage per real mount, network interfaces with their traffic counters and addresses, listening TCP/UDP ports mapped back to a process where it's resolvable, the top processes by CPU and memory, temperatures and battery, and your running or failed `--user` systemd services. It only ever reads `/proc`, `/sys`, and a short allow-list of read-only commands, so it can't write, kill a process, or change config, and nothing leaves the machine. CPU and memory carry tiny inline sparklines from a short in-browser history, the process and listening tables sort by any column and filter by text, and a "Download snapshot" button saves the current panels as one JSON. Refresh is under your control: a pause/resume toggle, a cadence selector, an "updated Ns ago" label, and auto-pause when the tab is hidden so it isn't polling in the background.

## Security model

- **Loopback only.** Every server binds `127.0.0.1`. Not a config knob.
- **Host and Origin guards.** Requests with a foreign `Host` header are refused (anti DNS-rebinding); every POST needs a same-origin `Origin`/`Referer` (anti-CSRF). The Origin check matches the console's port exactly, so a port-less Origin (`http://localhost`, i.e. `:80`) no longer slips through and a page on a default-port loopback server can't act as a CSRF source for any console.
- **Set-Cookie preservation.** The internal `fetch()` keeps every `Set-Cookie` a response sends (repeats are joined with a newline, since cookie values carry their own commas) instead of collapsing them to the last one, so redcell's cookie-flag analysis grades all of them, not just one.
- **Strict CSP.** `default-src 'none'`; no external scripts, styles, fonts, or images. The UI only ever calls its own origin, and cross-console data is aggregated server-side.
- **SSRF guard.** Recon's only door to the internet is one `fetch()` that refuses loopback, RFC1918, link-local, and reserved addresses.
- **No shell, ever.** Redcell executes only allow-listed binaries with an argv list (never a string), only after the authorization gate, and it logs every run. Aggressive tools are never auto-run.
- **Read-only on the system.** Bastion and Systems inspect and report; they never run sudo or change system state. Systems reads `/proc` and `/sys` and a short allow-list of read-only commands, nothing more.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how it all fits together, [`THREAT_MODEL.md`](THREAT_MODEL.md) for what it does and doesn't defend (and the privacy hardening you can turn on), [`SECURITY.md`](SECURITY.md) to report a problem, and [`CONTRIBUTING.md`](CONTRIBUTING.md) for the rules a change has to keep.

## OpSec: keeping a scan from leading back to you

Two different things here, and it's worth being clear about which is which.

What the tool does for you:

- It can route its own recon through Tor or a proxy. Set `NUCLEUS_SOCKS=127.0.0.1:9050` (env or the Settings reference) and every request the app makes, Recon lookups, the report engine, and its DNS, goes through a stdlib SOCKS5 client over the tunnel. DNS resolves inside the tunnel (a hostname target is handed to the proxy) so it doesn't leak around it, and a literal private or loopback IP target is still refused. `NUCLEUS_DOH` picks the DoH resolvers (Cloudflare before Google by default).
- A local-first exposure check reads your routing table to tell you exposed vs. protected without sending anything anywhere, and a Verify exit IP button is the explicit, disclosed opt-in that checks your public exit against Mullvad / the Tor Project / a geo echo. The exposure gate refuses a target-touching run while your real IP is exposed, unless it's your own lab or you tick "scan anyway".
- Outbound requests carry a neutral fingerprint: a normal browser `User-Agent` rather than a self-identifying tool name, and a neutral `Origin` on the CORS probe. Set your own with `NUCLEUS_UA="..."`.
- Secrets and case data can stay off disk, or get wiped. `NUCLEUS_KEYRING=1` stores API keys in the OS keyring instead of plaintext `var/.env` (or export them as env vars for nothing on disk); logging is off by default so a session leaves no trail; and `nucleus wipe` securely overwrites and removes all on-disk case data (scans, saved output, reports, scrub sessions, engagements) in one gesture.

What you still handle yourself:

- The external scanners connect on their own. nmap, nuclei, nikto, sqlmap, hydra, gobuster and the rest open their own sockets from your real IP, and the app's SOCKS option routes its traffic, not a separate binary's. Run those through `proxychains` (or your VPN) so they ride the tunnel too.
- A proxy is not a whole opsec plan. `NUCLEUS_SOCKS` covers the app's requests; bring up your VPN before an engagement, use a client-agreed source IP where scope calls for one, and treat full-disk encryption as the real guarantee for anything at rest.

## Make it yours

Everything is a preference, remembered per browser, with no config file to edit. The theme is dark, light, or follow-the-system (`prefers-color-scheme`), set in Settings → Appearance; light mode is a full palette rather than an inversion, and its accents meet WCAG AA. You pick comfortable or compact density and which console opens on launch. Every keyboard shortcut is remappable in Settings → Shortcuts (capture a keypress, save, reset one or all), and the command palette (Ctrl-K) and the `?` help overlay always reflect your live bindings. API keys, appearance, shortcuts, and a privacy reference for the `NUCLEUS_*` env toggles all live on the hub.

## Engagements

Give a case a name and an authorized scope (hosts, domains, CIDRs) from the hub, and it becomes the thing you actually work: every Recon scan and Redcell run tags onto its timeline, parsed findings collect on it, and one click exports a Markdown report. The scope isn't just a label. When a case is active it's the Redcell allowlist, so a target outside it is refused and the "I'm authorized" checkbox becomes a real boundary. It's all local stdlib JSON under `var/`, created only when you make a case, and `nucleus wipe` clears it with everything else.

## Layout

```
shared/common.py        the server base + every security guard, in one place
shared/static/          the shared design system (one look across all consoles)
hub/                    the command center
consoles/recon/         OSINT
consoles/redcell/       offensive
consoles/bastion/       defensive / opsec
consoles/devkit/        developer toolbelt
consoles/systems/       live local machine health
engine/osint_report.py  the graded domain-assessment engine (also a CLI)
bin/                    launcher, installer, desktop + systemd files
```

## License

MIT, see [LICENSE](LICENSE). Authorized, lab, and educational use only.
