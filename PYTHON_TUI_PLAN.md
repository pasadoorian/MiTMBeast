# MITM Beast — Python + Textual TUI Conversion Plan

**Status:** proposed (2026-04-29) · supersedes Phases 2–5 of `IMPLEMENTATION_PLAN.md`
**Effort:** ~8–12 engineering days (one engineer, focused)
**Outcome:** v2.0 — pure Python implementation with Textual TUI replacing the bash CLI

---

## Goals

1. **Eliminate the 1000+ line `mitm.sh`** in favor of a structured Python package with proper modules, types, and tests.
2. **Replace the manual CLI workflow** (`sudo ./mitm.sh up -m mitmproxy`, `./dns-spoof.sh add ...`, `./delorean.sh start +1500`) with a single `mitmbeast tui` interactive interface.
3. **Make features discoverable** — a consultant unfamiliar with the tool should be able to drive an engagement from the TUI without reading bash source.
4. **Make state observable** — live counters, connected clients, DHCP grants, mitmproxy flows, all visible in one screen instead of `tail -f` across five log files.
5. **Keep the same threat model and capabilities.** All v1.1 features (5 proxy modes, NTP spoofing, fake firmware server, packet capture) survive intact.

## Non-goals (explicitly)

- Web UI in this phase. Plan keeps the architecture clean enough to add FastAPI on top later if needed (Phase 3+).
- Multi-user concurrent operation.
- Container/Docker support — same architectural constraint as v1.1 (must own host network).

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│  mitmbeast/cli.py                                │
│   (Click — `up`, `down`, `restore`, `tui`,       │
│    `spoof add`, `proxy mode`, scriptable)        │
├──────────────────────────────────────────────────┤
│  mitmbeast/tui/                                  │
│   (Textual app — Dashboard, Clients, DNS,        │
│    Sessions, Proxy, Logs, Settings screens)      │
├──────────────────────────────────────────────────┤
│  mitmbeast/core/  ←  the heart                   │
│   • config.py        — load + validate mitm.conf │
│   • state.py         — SQLite, sessions/leases   │
│   • events.py        — async pub/sub event bus   │
│   • netif.py         — pyroute2 interface mgmt   │
│   • bridge.py        — bridge + slave mgmt       │
│   • firewall.py      — iptables MITM_* chains    │
│   • dnsmasq.py       — config gen + lifecycle    │
│   • hostapd.py       — config gen + association  │
│   • dhcp.py          — lease tracking            │
│   • proxy/           — mode launchers            │
│       mitmproxy.py   (uses mitmproxy Python API) │
│       sslsplit.py                                │
│       certmitm.py                                │
│       sslstrip.py                                │
│       intercept.py                               │
│   • delorean.py      — NTP spoofing              │
│   • fakefw.py        — fake firmware server      │
│   • restore.py       — host repurpose helper     │
├──────────────────────────────────────────────────┤
│  System layer (libraries used)                   │
│   • pyroute2 — netlink for interfaces / iptables │
│   • python-iptables (iptc) — alt for nf rules    │
│   • mitmproxy (Python API) — direct integration  │
│   • subprocess — for hostapd, dnsmasq, certmitm  │
│   • Textual — TUI framework                      │
│   • Click — CLI                                  │
│   • Pydantic — config / event models             │
│   • SQLAlchemy / aiosqlite — state               │
│   • pytest — testing                             │
└──────────────────────────────────────────────────┘
```

### Why this layering matters

- `core/` has zero UI dependencies. Anyone can import a module and drive it from `cli.py`, `tui/`, a future web layer, or a pytest fixture.
- `events.py` is an async pub/sub. Any module that produces interesting events (DHCP grant, association, mitmproxy flow, iptables counter delta) emits to the bus. Any UI subscribes. Future Web UI just adds another subscriber.
- `state.py` is SQLite — sessions and lease history are persistent across restarts (current bash leaks all of this on `down`).

---

## TUI design (Textual screens)

```
┌─ MITM Beast ─────────────────────────────────────────────────┐
│ Mode: mitmproxy │ WAN: 192.168.1.80 │ LAN: 192.168.200.1     │
│ Clients: 3      │ Up: 12m 34s       │ Wi-Fi: mitmbeast / on  │
├──────────────────────────────────────────────────────────────┤
│ [D]ashboard │ [C]lients │ d[N]S │ [S]essions │ [P]roxy │ ... │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Live event feed                                             │
│  10:42:11  [DHCP]   192.168.200.65  Pixel-9                  │
│  10:42:12  [HOSTAPD] STA assoc  f2:00:dc:cd:96:3a (-37 dBm) │
│  10:42:14  [MITM]   GET https://example.com/  (200, 1.2 KB)  │
│  10:42:15  [DNS]    update.example.com -> 192.168.200.1     │
│  ...                                                         │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│ [m]ode  [s]poof  [r]estore  [q]uit                           │
└──────────────────────────────────────────────────────────────┘
```

| Screen | Content |
|---|---|
| **Dashboard** | Status line · mode selector · live event feed (scrolling) · quick stats (packets, bytes through `MITM_NAT_PRE`) |
| **Clients** | Table: MAC · IP · Hostname · Signal · Connected since · RX/TX bytes · Real-time row updates |
| **DNS Spoofs** | CRUD UI for `dns-spoof.conf` · live DNS query log on right pane · validation feedback inline |
| **Sessions** | Past + current capture sessions · pcap file list with sizes · launch external viewer (mitmweb/wireshark) |
| **Proxy** | Mode-specific view (mitmproxy flows table, sslsplit conn log, certmitm findings, sslstrip events, intercept dispatched URLs) |
| **Logs** | Tailed logs from dnsmasq / hostapd / mitmweb / mitmbeast itself, filterable |
| **Settings** | Wi-Fi creds · WAN/LAN config · auth token rotation · restore subcommand from menu |

---

## Phased milestones

### Phase 2a — Python core foundation (~1.5 days)

| ID | Item | Done when |
|---|---|---|
| P2.1 | Repo restructure: `mitmbeast/` package, `pyproject.toml`, `ruff` + `pytest` config | `pip install -e .` works; `pytest` runs (no tests yet) |
| P2.2 | `mitmbeast.core.config` — Pydantic model for `mitm.conf` | Tests validate good + bad configs |
| P2.3 | `mitmbeast.core.system` — async subprocess helpers, `run_as_root`, structured stdout/stderr capture | Tested against `echo`, `false`, long-running command |
| P2.4 | `mitmbeast.cli` — Click CLI with `up`, `down`, `restore`, `spoof`, `delorean`, `tui` subcommands. Initially calls existing bash via subprocess. | `mitmbeast up -m mitmproxy` produces same result as `./mitm.sh up -m mitmproxy` |

### Phase 2b — Replace bash internals (~3 days)

Each module replaces one piece of `mitm.sh` / `dns-spoof.sh` / `delorean.sh`. Bash scripts stay callable but become thin wrappers that exec `python -m mitmbeast.cli ...`.

| ID | Item | Replaces |
|---|---|---|
| P2.5 | `core.netif` (pyroute2) — interface up/down, IP add/remove, route mgmt | `ifconfig`, `ip` calls in `mitm.sh` |
| P2.6 | `core.bridge` — bridge create/destroy, slave add/remove | `brctl` |
| P2.7 | `core.firewall` — `MITM_*` chain mgmt via `iptc` | iptables sections in `mitm.sh` and `delorean.sh` |
| P2.8 | `core.dnsmasq` — config gen, lifecycle, lease parsing, log monitoring | `dnsmasq` config write + spawn in `mitm.sh` |
| P2.9 | `core.hostapd` — config gen, lifecycle, `hostapd_cli` event monitor | hostapd config + spawn in `mitm.sh` |
| P2.10 | `core.proxy.mitmproxy` — uses mitmproxy's **Python API** instead of subprocess (cleaner integration, direct flow access) | mitmweb subprocess, intercept addon |
| P2.11 | `core.proxy.{sslsplit,certmitm,sslstrip,intercept}` — subprocess wrappers with structured event emission | Mode launchers in `mitm.sh` |
| P2.12 | `core.delorean` — NTP spoofing wrapper, idempotent firewall via `core.firewall` | `delorean.sh` |
| P2.13 | `core.fakefw` — refactor `fake-firmware-server.py` into a proper module with threaded HTTP server | `fake-firmware-server.py` |
| P2.14 | `core.restore` — port the `mitm.sh restore` subcommand | restore branch in `mitm.sh` |

### Phase 2c — State + events (~1.5 days)

| ID | Item | Done when |
|---|---|---|
| P2.15 | `core.state` — SQLite schema for sessions, dhcp_leases, dns_spoofs, events. SQLAlchemy or aiosqlite. | `mitmbeast sessions list` shows past sessions with timestamps |
| P2.16 | `core.events` — asyncio pub/sub event bus (`EventBus.publish`, `subscribe`) | Test: subscriber receives events from publisher |
| P2.17 | Event sources wired in: hostapd_cli STA events, dnsmasq lease changes, iptables counter polling (1 Hz), mitmproxy flow callbacks | Live event stream observable from a test consumer |

### Phase 2d — Textual TUI (~2 days)

**Plan adjustment 2026-04-29:** user asked to bring TUI work forward —
ship a *minimum-viable* TUI on top of the current Python stack
(P2.9b) before completing P2.10–P2.17. The TUI initially polls for
state (no event bus yet); the event-bus refactor in Phase 2c
upgrades the same screens to push-based without changing their
visual contract.

| ID | Item | Done when |
|---|---|---|
| **P2.18** | Top-level `./mitmbeast` wrapper + click group invokes TUI when no subcommand. Textual app skeleton with TabbedContent. | `./mitmbeast` opens the TUI in one keystroke |
| **P2.19** | Dashboard: status header, mode selector (`none` only initially), up/down buttons, recent log tail. Polls state every 2s. | Click Up → router runs (Python stack); Down → tears down |
| **P2.20** | Clients screen: merged DHCP-lease + hostapd-station table. Polls every 3s. | Phone associating shows up as a row |
| **P2.21** | DNS Spoofs screen: list + add/rm modal. Calls `dns-spoof.sh` under the hood for v2.0. | Add `foo.example.com → 192.168.200.1`, see it in the list, remove it |
| P2.22 | Sessions screen — list past pcap dirs and mitmproxy flow exports | Click row → opens external viewer |
| P2.23 | Proxy screen — mode-specific view (start with mitmproxy flow table) | Live flows from victim VM appear in real time |
| P2.24 | Logs + Settings screens | Logs tail; Settings menu launches `restore`, edits Wi-Fi creds |

P2.18–P2.21 are the MVP user-test checkpoint. P2.22–P2.24 land after
the deferred Phase 2b/2c work (proxy modes + event bus).

### Phase 2e — Tests, docs, distribution (~1.5 days)

| ID | Item | Done when |
|---|---|---|
| P2.25 | pytest suite — port the Phase 1b test inventory to Python; uses MCP/SSH to drive Kali + Ubuntu VMs | `pytest tests/` exercises all 5 modes end-to-end and passes |
| P2.26 | README rewrite for Python-only workflow; migration guide from bash CLI to `mitmbeast tui` | New user can install + run a session from the README |
| P2.27 | `pyproject.toml` complete with deps, entry points, console_scripts | `pip install mitmbeast` installs cleanly on a fresh VM |
| P2.28 | systemd unit (optional) — `mitmbeast.service` that launches the TUI in a screen / dispatched mode | `systemctl start mitmbeast` works |
| P2.29 | Tag v2.0 | `git tag` + GitHub release |

---

## Testing strategy

- **Unit tests** for `core/*` modules — pure Python logic, no system calls, mocks for subprocess.
- **Integration tests** that drive the Kali + Ubuntu VMs via SSH/MCP (this is what Phase 1b would have done, now in Python with pytest).
- **Smoke test** matrix in CI: each of the 5 proxy modes exercised against the Ubuntu victim, asserting on iptables counters / mitmproxy flow capture / cert chain seen by the victim.
- **Manual UX tests** for the TUI — there's no good way to automate Textual UI testing today beyond Textual's own `pilot` (snapshot tests), but we'll use that for screen layout regressions.

---

## Distribution

- `pyproject.toml` with `[project]` and `[project.scripts]` for `mitmbeast` entry point.
- Initially: `pip install -e .` from a clone (lab use).
- Eventually: publish to PyPI as `mitmbeast` — single command install on any system with Python 3.10+ and the system deps (`hostapd`, `dnsmasq`, `bridge-utils`).
- System-package alternative: AUR PKGBUILD for Arch / Manjaro, `.deb` for Kali — Phase 6+ work.

---

## Backwards compatibility

| What | What happens |
|---|---|
| `mitm.sh up -m mitmproxy` etc. | Stays callable as a thin shim that execs `mitmbeast up -m mitmproxy`. Removed in v3.0. |
| `dns-spoof.sh`, `delorean.sh` | Same — stay as compatibility shims. |
| `mitm.conf` | Same format, parsed by Pydantic now. New fields added without breaking old configs. |
| Existing test bed (Kali VM) | Works unchanged. Just `git pull` + `pip install -e .` and the CLI command names match. |
| Bash test scripts in `tests/` (if any) | Migrated to pytest in P2.25. |

---

## Locked decisions (confirmed 2026-04-29)

| Q | Decision | Notes |
|---|---|---|
| 1 | Bash scripts become **one-line shims** that exec the Python entry point | `mitm.sh`, `dns-spoof.sh`, `delorean.sh` stay at top level for backwards compatibility; removed in v3.0 |
| 2 | **mitmproxy Python API** for `mitmproxy` and `intercept` modes; subprocess for `sslsplit`/`certmitm`/`sslstrip` | Flow events flow directly into the event bus — no log scraping |
| 3 | **Hybrid state** — daemon-owned files stay authoritative (dnsmasq leases, dns-spoof.conf); SQLite for sessions / findings / event log / DHCP history | No "our DB says X, dnsmasq says Y" race conditions |
| 4 | **Python supervisor via asyncio** subprocess; no systemd dependency | One process owns everything; quitting mitmbeast tears it all down |
| 5 | **`pip install -e .` from clone** for v2.0; PyPI later. **Pinned Python version + dedicated venv + locked dependency versions** — no system Python, no system libraries | Use `uv` for venv + lockfile management. Python 3.12 (LTS-ish, supported through 2028) |
| 6 | **`python-iptables` (`iptc`)** for `MITM_*` chain management | Atomic batch updates; first-class Python objects; no `iptables -S` parsing |

### What "no system libraries" means in practice

- Pinned `.python-version` file — `3.12` exactly. Project refuses to set up against any other interpreter.
- `uv.lock` (or `requirements.lock`) — every transitive dependency pinned to exact versions. Reproducible across host, Kali, future systems.
- Project venv at `.venv/` (gitignored). Bash shims locate and use `.venv/bin/mitmbeast`.
- Activation is implicit — users don't need to remember to `source .venv/bin/activate`. The shims handle it.
- System packages still required for the **non-Python** dependencies: `hostapd`, `dnsmasq`, `bridge-utils`, `iptables`, `sslsplit`, `sslstrip`, `tcpdump`, `mitmproxy` system package (NOT used by us — we use the pip-installed `mitmproxy` library for the API). Documented in README.
