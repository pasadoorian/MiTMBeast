# MITM Beast — Phase 3 plan

Phase 2 shipped v2.0.0-alpha1: a Python core, Textual TUI, all five
proxy modes ported, 160 host tests passing. This plan covers what
comes next — validation under real-client load, targeted bug fixes,
and the highest-value feature work — through to v2.0.0 final.

Out of scope per user direction (2026-04-30): touching the v1.x bash
entry points. They remain frozen as compatibility shims; all forward
work is in the Python tree.

---

## Goals

1. **Validate the alpha** under real client traffic — the integration
   suite covers each mode in isolation, but only mitmproxy and `none`
   have been driven end-to-end with a real client.
2. **Fix bugs surfaced during validation** plus a small carry-over
   list from Phase 2.
3. **Ship the features that change operator workflow**, not the ones
   that are nice-to-haves.
4. **Reach v2.0.0 final** through alpha2 → beta1 → final, gated on
   soak hours.

---

## Phased milestones

### Phase 3a — Real-client soak (~2 days, mostly hands-on)

The integration suite ran each mode in isolation. The soak proves the
modes work against a real device on the AP, end-to-end. Bug #7
validated this for mitmproxy; the other four modes need the same
treatment before we can claim the alpha is real.

| ID | Item | Done when |
|---|---|---|
| M3.1 | Soak: `none` mode | ✅ 2026-04-30 — Ubuntu laptop "gibson" on AP, DHCP lease 192.168.200.63, NAT 16+ packets through eth2, internet reachable |
| M3.2 | Soak: `mitmproxy` mode | Browser on laptop hits 5+ HTTPS sites; flows appear in TUI Proxy tab live; no errors in mitmweb log |
| M3.3 | Soak: `sslsplit` mode | Browser hits 5+ HTTPS sites; PCAP files written under `sslsplit_logs/session_*/`; cert chain visible in `decrypt.log` |
| M3.4 | Soak: `sslstrip` mode | Test page that should arrive over HTTPS arrives over HTTP at the client when its domain is in `dns-spoof.conf` |
| M3.5 | Soak: `certmitm` mode | Test domain hit from client; results written to workdir; client flagged VULNERABLE or SECURE for at least one cert variant |
| M3.6 | Soak: `intercept` mode | Fake firmware server returns custom response when client hits spoofed domain over HTTPS |
| M3.7 | Multi-client soak | Laptop + victim VM both connected, both pass DHCP + NAT traffic concurrently for 10+ minutes |
| M3.8 | Lifecycle stress | 5× up/down cycles back-to-back, no orphaned hostapd/dnsmasq/proxy daemons, no leaked `MITM_*` chains |
| M3.9 | Mode-switch sequence | `up -m none` → `down` → `up -m mitmproxy` → `down` → `up -m sslsplit` → `down`, all clean |
| M3.10 | Crash recovery | After `kill -9` on the running mitmbeast process, `mitmbeast restore --python` returns host to NetworkManager + clean iptables |

The soak is the gate to v2.0.0-alpha2. We do not ship features
(Phase 3c) until M3.2–M3.6 pass.

### Phase 3b — Targeted bug fixes (~1 day, mostly autonomous)

Triaged list. Some came from observation during Phase 2; new ones
will be added as Phase 3a runs.

| ID | Severity | Bug | Fix sketch |
|---|---|---|---|
| B3.1 | trivial | `mitmbeast up --help` still says *"Currently only supports -m none. Proxy modes land in P2.10/P2.11."* | Update the Click docstring on `up` |
| B3.2 | minor (hardening) | `core.hostapd.generate_config` is missing `rsn_pairwise=CCMP`, `ieee80211d=1`, `auth_algs=1` — works on Linux clients but defensive completeness for finicky Wi-Fi stacks | Add the three lines; update `test_hostapd` to pin them |
| B3.3 | unknown | `iptables -t nat -L` prints *"Warning: iptables-legacy tables present, use iptables-legacy to see them"* on Kali — leftover from somewhere | Investigate: is it our chains in legacy and nft simultaneously, or just host-package pollution? Document or fix accordingly |
| B3.4 | trivial | Stale references to *"P2.10"* / *"Phase 2c"* in source comments now that Phase 2 is closed | Sweep + update or remove |
| B3.5–* | TBD | Bugs surfaced by Phase 3a | Logged in `BUGS.md` as they appear |

### Phase 3c — High-value features (~3 days, one feature per commit)

Each independently shippable. Ordered by operator-impact.

| ID | Feature | Why operators care | Done when |
|---|---|---|---|
| F3.1 | **Live mode switch** in TUI Dashboard | Today's flow: select mode → Up → wait → Down → switch dropdown → Up. Should be: change dropdown → automatic transition (down current proxy, install new chains, start new proxy). Cuts ~30 seconds + manual error per switch. | Changing the Select while up triggers the transition; status line and Proxy tab reflect the new mode |
| F3.2 | **Proxy tab filters** | At >100 captured flows the tab becomes hard to read. Need host filter, status filter (200/3xx/4xx/5xx), free-text URL search. | Three filter inputs above the table; rows filter live as the operator types |
| F3.3 | **Mode-aware status bar** | Right now the status line says "mode: down/none/unknown". Should show active mode + relevant URLs — e.g., `mitmproxy mode → http://192.168.1.80:8080`. | Status bar on every screen renders mode + URL when applicable |
| F3.4 | **Per-client byte counters** in Clients tab | Helps operators identify which device is generating traffic. The data is already in hostapd station dump (rx_bytes / tx_bytes); just expose it as deltas, not totals. | Two new columns: "RX/sec" and "TX/sec", updated each refresh tick |
| F3.5 | **DNS spoof presets** | Operators repeat the same spoof patterns (firmware update CDNs, telemetry endpoints). Save sets of patterns + apply with one click. | TUI Spoofs tab gets "Apply preset" dropdown; presets stored in `~/.config/mitmbeast/presets.yaml` |

F3.1 and F3.2 are the two that change the operator's workflow most.
F3.3–F3.5 are quality-of-life. Ship F3.1 first.

### Phase 3d — Docs + release prep (~1 day)

| ID | Item | Done when |
|---|---|---|
| D3.1 | Update project `CLAUDE.md` for v2.0 — currently describes v1.x bash structure as primary | New CLAUDE.md describes Python package layout; bash mentions confined to "compatibility shims" |
| D3.2 | Tag **v2.0.0-alpha2** | After Phase 3a M3.2–M3.6 + Phase 3b B3.1–B3.4 |
| D3.3 | Tag **v2.0.0-beta1** | After Phase 3c F3.1 + at least 2 more features ship |
| D3.4 | Tag **v2.0.0** final | After 1-week soak on beta1 with no major bugs |

---

## Deferred (explicitly NOT in Phase 3)

These were considered and pushed out per user direction:

- **Settings tab edit support** (Bug #5 follow-up) — a v2.x.x or v2.1
  feature. Operators can edit `mitm.conf` outside the TUI for now.
- **SQLite session persistence** (P2.17 from Phase 2) — files-on-disk
  is sufficient for the alpha audience. Revisit when we need
  cross-session queries.
- **FastAPI web UI** — Phase 4+ if the TUI hits operator limits.
- **Eclypsium-specific test profiles** — needs research-team input on
  which devices and what scoring; out of scope for v2.0.
- **Bash → one-line shims** — user direction (2026-04-30): leave the
  legacy scripts alone. They keep working as-is.

---

## Risks

- **Phase 3a needs Paul at the keyboard** with at least the Ubuntu
  laptop, ideally also the phone and a victim VM. Each soak is
  ~10 minutes hands-on; the four remaining proxy modes are ~40 min
  end-to-end. Schedule accordingly.
- **F3.1 (live mode switch)** is the trickiest item — current router
  isn't designed to swap proxies in place; we either restart the
  router under the hood (simple, brief AP outage) or implement a real
  in-place swap (complex, no outage). Recommend simple version first.
- **B3.3 (iptables-legacy warning)** could be a real iptc/nft
  divergence issue (we hit a related one in Phase 2). Worst case it
  unwinds part of the firewall layer — flag early if so.

---

## Success criteria for v2.0.0 final

- All five proxy modes soaked end-to-end with real clients.
- TUI workflow validated by an operator who didn't write the code.
- No major bugs open for 7 days on `main`.
- README + CHANGELOG up to date.
- A clean install from a fresh clone (`git clone && uv sync &&
  sudo ./mitmbeast`) Just Works.
