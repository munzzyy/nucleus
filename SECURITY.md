# Security

Nucleus is a local security tool. It runs entirely on `127.0.0.1`, ships with zero third-party
runtime dependencies, and makes no network call you didn't ask for. That design is the security
model, not a feature to be relaxed later. This file says what that buys you, where it stops, and
how to report a problem.

## Reporting a vulnerability

Email **Munzzyy1@proton.me** with "Nucleus" in the subject. Include what you found, the steps to
reproduce it, and what an attacker gets out of it. A proof of concept helps.

Please don't open a public issue for a real vulnerability until there's a fix to point at. I'll
confirm I received your report, work the fix, and credit you when it lands unless you'd rather stay
anonymous. This is a personal project, not a funded program, so there's no bounty, but real
findings get a real fix and a thank-you.

## What Nucleus defends

Every console binds `127.0.0.1`, loopback only, so nothing on your network or the internet can
reach it. That's enforced in the server core, not a config knob you can flip.

There's no phone-home: no telemetry, no analytics, no update check, no crash reporter, and no
remote fonts, scripts, or styles pulled in. The only outbound traffic is a lookup you trigger, a
Recon or report-engine query to the source you named, or the optional **Verify exit IP** button
(which you click, and which reveals your IP to three exit-check services). The always-on exposure
indicator is local-only: it reads your routing table, never the network.

The browser surface is tight. A strict Content-Security-Policy (`default-src 'none'`, no inline
script or style, `connect-src 'self'`) means a console page can only talk to its own origin;
cross-console data is merged server-side so the browser never makes a cross-origin call. Every
value echoed back into the page is inserted as text, never as markup.

There's a single guarded door out. All outbound HTTP goes through one SSRF-guarded fetch that
refuses loopback, private, link-local, and reserved ranges, re-validates every redirect hop, and
pins the connection to the address it validated so a rebinding host can't swap IPs mid-request.
DNS rides encrypted DNS-over-HTTPS.

And there's no shell, ever. The offensive console runs only allow-listed binaries with a fixed
argument template and a validated target inserted as exactly one argument, behind an authorization
gate. Aggressive tools are never executed; the command is built for you to run yourself. The
defensive and systems consoles are read-only and never touch `sudo`.

## What Nucleus does not defend

Being honest about the edges matters more than a longer list of wins.

A compromised local machine is out of scope. Anything running as your user can reach a loopback
port and read what's on your disk. Loopback keeps the network out; it does not keep out code
already running as you. Nucleus is not a sandbox for hostile local software. The same goes for
another local user on a shared box: on a multi-user machine, another account may be able to reach
`127.0.0.1:88xx`, so run Nucleus on a machine only you use, or firewall the ports per-user.

Your operational security as an investigator is on you. Passive recon still originates from your
IP and your DNS. The sources and targets you look up can see that a request came from you. Route
your traffic accordingly if that matters for your threat model: set `NUCLEUS_SOCKS=host:port`
(e.g. a local Tor) to route everything, DNS included, through a proxy; without it, assume your
real IP is exposed to every source a scan touches.

And the safety of what you point it at is still your call. The authorization gate is a guard
against accidents and cross-site requests, not a license. Only scan what you are authorized to
scan.

For the full picture of what is trusted, what is written to disk, and where the boundaries are, see
[THREAT_MODEL.md](THREAT_MODEL.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Supported versions

This is a single active line. Fixes land on the latest release; there is no back-porting to old
tags. Run current.
