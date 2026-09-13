## What this changes

<!-- One or two sentences. What and why. -->

## Checklist

- [ ] `python -m unittest tests.unit` is green
- [ ] Ran `python3 tests/smoke.py` if I touched server/routing/endpoints
- [ ] No new third-party runtime dependency
- [ ] Outbound HTTP goes through `common.fetch`; any exec goes through `common.run_tool` (argv, no shell)
- [ ] No `innerHTML` of network/user values; DOM built with `N.el`/`textContent`
- [ ] Added or updated a test for the change
