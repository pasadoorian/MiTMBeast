# MITM Beast — bugs / findings during v2.0 development

Living list of bugs surfaced during Phase 2 manual testing. Each row
links the bug to the commit that fixed it (or "open" if pending).

| # | Date | Reported | Severity | Where | Symptom | Status / fix |
|---|---|---|---|---|---|---|
| 1 | 2026-04-29 | user (`sudo ./mitmbeast`) | major (TUI fails to start) | `core.netif`, called from Textual screens | `RuntimeError: This event loop is already running` from pyroute2's `IPRoute()` constructor when called inside Textual's running asyncio loop | **fixed** — TUI screens now run `snapshot_state()` via `asyncio.to_thread` so pyroute2's internal `run_until_complete` doesn't collide with the foreground loop |
| 2 | 2026-04-29 | integration test | major (sslstrip mode failed to start) | `core.proxy.fakefw` | `parents[3]` resolved to `<repo>/src` instead of repo root, so `fake-firmware-server.py` lookup failed | **fixed** — bumped to `parents[4]`. fakefw.py is one directory deeper (`core/proxy/`) than other proxy modules. Future modules in `core/proxy/` should also use `parents[4]` |
| 3 | 2026-04-29 | integration test | major (delorean start failed) | `core.delorean.start` | Passed a relative script path to subprocess while also setting cwd to its parent — Python resolved the script as `<cwd>/<relative>` = `delorean/delorean/delorean.py` (doubled) | **fixed** — `Path(...).resolve()` to absolute before subprocess. Lesson: never combine a relative path with a `cwd` change unless you mean it |
| 4 | 2026-04-29 | user feedback | minor (UX) | TUI Dashboard log pane | Pane uses a `Static` widget capped at 12 lines — output during `up`/`down` scrolls past too fast to read | **open** — replace with `RichLog` (persistent scrollable buffer, retains thousands of lines, user can scroll up). |
| 5 | 2026-04-29 | user feedback | minor (UX) | TUI | No way to view or edit `mitm.conf` from inside the TUI; the mode selector lets you start a router but you can't see what Wi-Fi SSID / IPs / proxy ports are about to be used | **fixed** (`3513dac`) — Settings tab read-only. Edit support is a follow-up. |
| 6 | 2026-04-29 | integration test | major (intermittent up failure) | `core.dnsmasq.start` | Stale **bash-version** dnsmasq from old `mitm.sh` runs holds port 67. Python `is_running()` only matches its own config path so leaks the older daemon. Symptom: `dnsmasq: failed to bind DHCP server socket: Address already in use` on subsequent `up`. | **fixed** — `core.dnsmasq.start` now probes port 67 first; if held by *any* dnsmasq (regardless of config), kills it before binding. |
| 7 | 2026-04-29 | not yet validated | unknown | `core.proxy.mitmproxy_mode` + flow logger | The mitmproxy-flow-logger.py addon writes one NDJSON line per response and `mitmproxy_flow_source` tails the file. Wired end-to-end but not validated against real traffic in P2.10b commit. | **validated** 2026-04-30 — Victim curl https://example.com / https://www.kali.org → 2 flows captured in `/run/mitmbeast/flows.ndjson` with full structure (ts, method, host, url, status, request_size, response_size, client). MITM_NAT_PRE counter incremented. The TUI Proxy tab consumes these events. |

## How to add a finding

When you hit a bug, paste here (or just tell me) with:
- minimal repro (the exact command you ran + what you saw)
- environment (host vs Kali VM, mode, root or not)
- severity guess: trivial / minor / major / critical

I'll triage, log, and either fix in flight (P2.x) or schedule for the
appropriate later phase.
