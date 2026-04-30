# Changelog

All notable changes to MITM Beast will be recorded here. Versions
prior to 2.0 lived in commit messages; the v1.x series is summarized
under the "Pre-v2.0" entry below.

## [2.0.0-alpha1] — 2026-04-30

First v2.0 alpha. The toolkit is now a Python package (`mitmbeast`)
with a Textual TUI (`./mitmbeast`). All five proxy modes plus
`none` are reachable via `mitmbeast up --python` against a pure
Python stack; the v1.x bash entry points (`mitm.sh`, `dns-spoof.sh`,
`delorean.sh`) remain as compatibility shims.

### Added
- **Python package** at `src/mitmbeast/` with `core/` (router,
  firewall, dnsmasq, hostapd, netif, bridge, restore, fakefw,
  delorean, events, event_sources, proxy/*) and `tui/` (Textual app,
  screens, widgets).
- **`mitmbeast` CLI** — Click-based, with all v1.x subcommands
  (`up`, `down`, `reload`, `restore`, `spoof`, `delorean`, `tui`).
- **`./mitmbeast` wrapper** — top-level script that bootstraps the
  uv-managed venv on first run and execs the click entry point.
  No-subcommand invocation opens the TUI.
- **Textual TUI** with seven tabs:
  - **Dashboard** — status line + mode dropdown + Up/Down/Refresh +
    scrollable RichLog event feed
  - **Clients** — merged DHCP-lease + Wi-Fi-station table
  - **DNS Spoofs** — list + add/remove
  - **Sessions** — past pcap and proxy session directories
  - **Proxy** — live HTTP flow table (method, status, host, URL,
    size) fed by `http_flow` events
  - **Logs** — journalctl tail of dnsmasq / hostapd / mitmweb /
    sslsplit / sslstrip / mitmbeast
  - **Settings** — read-only `mitm.conf` viewer with secret redaction
- **Async event bus** (`core.events.EventBus`) — thread-safe
  publish, sync + async subscribers, used by the TUI for live
  updates.
- **Event sources**: dnsmasq DHCP, hostapd associations, mitmproxy
  flow capture (via NDJSON tail of an addon-written log).
- **`mitmproxy-flow-logger.py`** addon for transparent capture of
  HTTP flows into `/run/mitmbeast/flows.ndjson`.
- **`--python` flag** on `up`, `down`, `restore`, `delorean
  start/stop/status/reload` — opt into the new Python core; without
  it, the CLI dispatches to the v1.x bash scripts.
- **All five proxy modes ported to Python**: `mitmproxy`,
  `sslsplit`, `sslstrip`, `certmitm`, `intercept`. Each has its own
  module under `core/proxy/` with start/stop/session-dir
  bookkeeping.
- **131 unit + integration tests** (host: 131 pass / 23 skip;
  Kali as root: 154 pass / 1 skip). Lint clean (ruff).
- **Documentation**: `RESTORE.md`, `EXECUTIVE_SUMMARY.md`,
  `IMPLEMENTATION_PLAN.md`, `PYTHON_TUI_PLAN.md`, `PHASE1_STATUS.md`,
  `BUGS.md`, this `CHANGELOG.md`.

### Changed
- `iptables --flush` (which wiped *all* host firewall rules) replaced
  with dedicated `MITM_NAT_PRE`, `MITM_NAT_POST`, `MITM_FWD`,
  `MITM_NTP_PRE` chains. Host firewall rules survive.
- `/etc/resolv.conf` is now backed up symlink-aware before overwrite
  and restored cleanly on `down`.
- `dns-spoof.sh add` validates domain + IP (IPv4 + IPv6) and warns on
  passthrough-list collisions (suppressed by `--force`).
- `mitm.sh restore` (bash and Python) re-enables NetworkManager,
  restores resolv.conf, removes leftover MITM iptables chains.
- Fake firmware server (`fake-firmware-server.py`) is now a
  ThreadingHTTPServer — concurrent IoT clients no longer queue.
- Network manager startup detects and kills stale dnsmasq/hostapd
  from prior bash runs (Bug #6 fix).

### Fixed
- **Bug #1**: pyroute2 / Textual asyncio loop conflict in TUI
  (`asyncio.to_thread` for snapshot reads).
- **Bug #2**: `core.proxy.fakefw` REPO_ROOT off-by-one path resolution.
- **Bug #3**: `core.delorean.start` resolved relative script path
  through cwd, doubling the path.
- **Bug #4**: TUI Dashboard log scrolled past too fast (now `RichLog`
  with 5000-line buffer).
- **Bug #5**: no Settings tab in TUI to view `mitm.conf` (added,
  read-only).
- **Bug #6**: stale bash-version dnsmasq/hostapd held ports across
  v2 starts (now killed automatically on `start`).
- **Bug #7**: live mitmproxy flow capture validated end-to-end.

## Pre-v2.0

The v1.x line was a bash toolkit (`mitm.sh`, `dns-spoof.sh`,
`delorean.sh`) that landed all the original interception capabilities.
v1.1 (Phase 1 of the remediation effort) fixed four critical
stability bugs — see `PHASE1_STATUS.md` and the `793be5c` commit for
details. v1.x entry points remain available as compatibility shims
in v2.x.
