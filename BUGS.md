# MITM Beast — bugs / findings during v2.0 development

Living list of bugs surfaced during Phase 2 manual testing. Each row
links the bug to the commit that fixed it (or "open" if pending).

| # | Date | Reported | Severity | Where | Symptom | Status / fix |
|---|---|---|---|---|---|---|
| 1 | 2026-04-29 | user (`sudo ./mitmbeast`) | major (TUI fails to start) | `core.netif`, called from Textual screens | `RuntimeError: This event loop is already running` from pyroute2's `IPRoute()` constructor when called inside Textual's running asyncio loop | **fixed** — TUI screens now run `snapshot_state()` via `asyncio.to_thread` so pyroute2's internal `run_until_complete` doesn't collide with the foreground loop |
| 2 | 2026-04-29 | integration test | major (sslstrip mode failed to start) | `core.proxy.fakefw` | `parents[3]` resolved to `<repo>/src` instead of repo root, so `fake-firmware-server.py` lookup failed | **fixed** — bumped to `parents[4]`. fakefw.py is one directory deeper (`core/proxy/`) than other proxy modules. Future modules in `core/proxy/` should also use `parents[4]` |
| 3 | 2026-04-29 | integration test | major (delorean start failed) | `core.delorean.start` | Passed a relative script path to subprocess while also setting cwd to its parent — Python resolved the script as `<cwd>/<relative>` = `delorean/delorean/delorean.py` (doubled) | **fixed** — `Path(...).resolve()` to absolute before subprocess. Lesson: never combine a relative path with a `cwd` change unless you mean it |
| 4 | 2026-04-29 | user feedback | minor (UX) | TUI Dashboard log pane | Pane uses a `Static` widget capped at 12 lines — output during `up`/`down` scrolls past too fast to read | **open** — replace with `RichLog` (persistent scrollable buffer, retains thousands of lines, user can scroll up). |
| 5 | 2026-04-29 | user feedback | minor (UX) | TUI | No way to view or edit `mitm.conf` from inside the TUI; the mode selector lets you start a router but you can't see what Wi-Fi SSID / IPs / proxy ports are about to be used | **open** — add a Settings tab. Read-only first (display all mitm.conf fields), editable later. |

## How to add a finding

When you hit a bug, paste here (or just tell me) with:
- minimal repro (the exact command you ran + what you saw)
- environment (host vs Kali VM, mode, root or not)
- severity guess: trivial / minor / major / critical

I'll triage, log, and either fix in flight (P2.x) or schedule for the
appropriate later phase.
