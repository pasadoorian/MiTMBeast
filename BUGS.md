# MITM Beast — bugs / findings during v2.0 development

Living list of bugs surfaced during Phase 2 manual testing. Each row
links the bug to the commit that fixed it (or "open" if pending).

| # | Date | Reported | Severity | Where | Symptom | Status / fix |
|---|---|---|---|---|---|---|
| 1 | 2026-04-29 | user (`sudo ./mitmbeast`) | major (TUI fails to start) | `core.netif`, called from Textual screens | `RuntimeError: This event loop is already running` from pyroute2's `IPRoute()` constructor when called inside Textual's running asyncio loop | **fixed** — TUI screens now run `snapshot_state()` via `asyncio.to_thread` so pyroute2's internal `run_until_complete` doesn't collide with the foreground loop |

## How to add a finding

When you hit a bug, paste here (or just tell me) with:
- minimal repro (the exact command you ran + what you saw)
- environment (host vs Kali VM, mode, root or not)
- severity guess: trivial / minor / major / critical

I'll triage, log, and either fix in flight (P2.x) or schedule for the
appropriate later phase.
