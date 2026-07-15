# tests/

- `unit.py` — offline unit suite (pure logic, no network, no running server
  except one loopback-only check). Run from the repo root:

      python3 -m unittest tests.unit -v

- `smoke.py` — live end-to-end script. Starts the hub + every console on
  offset test ports and exercises real endpoints. Run:

      python3 tests/smoke.py

Run `unit.py` on every change; `smoke.py` before a release or after touching
routing/server plumbing.
