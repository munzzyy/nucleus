# Contributing

Thanks for looking. Nucleus has a few hard rules that shape every change. They aren't
negotiable, because they're the whole reason the app is safe to run.

## The rules

1. **Standard library only.** No third-party runtime dependencies, ever. If a feature needs a
   `pip install`, it doesn't go in. The payoff is that there's nothing to audit but this repo, and
   the app runs on a fresh Python with no setup. (The optional native window uses system PySide6 if
   it's already installed; the app runs fine without it.)
2. **Loopback only.** Every server binds `127.0.0.1`. Don't add a bind address, a `0.0.0.0`, or a
   "just for the LAN" option. That's not a limitation to fix; it's the security model.
3. **Nothing phones home.** No telemetry, no analytics, no update check, no remote assets. The only
   outbound traffic is a lookup the user explicitly triggered, going to the source it names.
4. **One door out.** All outbound HTTP goes through `common.fetch` (the SSRF guard). Never call
   `urllib` directly. All DNS goes through `common.dns_query`.
5. **No shell.** Anything that runs a binary goes through `common.run_tool` with an argv list. No
   `shell=True`, no string interpolation into a command, no exceptions.
6. **Strict CSP stays strict.** No inline script or style, no `innerHTML` of any value that came
   from the network or the user. Build DOM with `N.el` and `textContent` so echoed values are inert.

If a change can't live inside those rules, it's out of scope, however good the idea.

## Getting set up

```bash
git clone <repo> nucleus && cd nucleus
python3 bin/nucleus doctor     # sanity-check the environment
python3 bin/nucleus            # native window, or `up` for headless
```

No build step, no virtualenv needed. Python 3.11 or newer.

## Before you send a change

- Run the offline suite and keep it green: `python3 -m unittest tests.unit`
- If you touched server plumbing, routing, or a console's endpoints, run the live smoke test too:
  `python3 tests/smoke.py`
- Add a test for what you changed. The suite is offline by design; mock the network, don't call it.
- Match the surrounding style. Small pure functions, thin handlers, no clever one-liners that need
  a comment to survive.

## Where things go

- **A new Recon lookup:** add it to `consoles/recon/lookups.py` (or `sources.py`) and route it in
  `detect.py`. Use `common.fetch` / `common.dns_query`. Degrade to a populated dict with an
  `error`/`note` field on failure; one dead source must never sink a scan.
- **A new safe runner:** add a template + validator to the Redcell allowlist. If it isn't obviously
  read-only and non-destructive, make it a command-*builder* entry instead of a runner.
- **A new console:** add a row to `CONSOLES` in `shared/common.py`, create
  `consoles/<slug>/app.py` with a `build_app()`, and it appears in the switcher, hub, and launcher
  automatically. See `docs/ARCHITECTURE.md`.

## Writing

Write like a person. Plain, direct sentences in code comments, docs, and commit messages. Skip the
buzzwords and the filler. A commit message should say what changed and why, not narrate.
