# MiTM Beast — Implementation Plan

Plan to land all bug fixes and improvements identified in the code review, plus Eclypsium-specific enhancements for research and services use.

**Total estimate:** ~12–17 engineering days across 6 phases. Phases 1–3 (P0/P1/P2) ship a hardened v1.1. Phases 4–6 ship v1.2 with CI, quality engineering, and Eclypsium workflow integration.

---

## Phase 1 — Critical Stability (v1.1-rc1) — **complete (2026-04-28)**

Goal: a single `up`/`down` cycle leaves the host in the same state it started in. No system breakage.

Implementation summary (final, may differ from original spec):

| ID | Item | Status | Notes |
|---|---|---|---|
| M1.1 | RESTORE.md doc + new `mitm.sh restore` subcommand (interactive prompt + `--manager` flag) | **done** | Scope shifted from "auto-restore on down" to explicit `restore` action per design decision: dedicated host, services may stay disabled until user repurposes the box. Top-level destructive sections now gated on `ACTION != restore`. |
| M1.2 | Named `MITM_NAT_PRE`, `MITM_NAT_POST`, `MITM_FWD` chains in `mitm.sh`; separate `MITM_NTP_PRE` in `delorean.sh` | **done** | Hooks installed via idempotent `-C \|\| -I`. `down` and `restore` both tear chains down cleanly. Verified no rule duplication on repeated `up`. |
| M1.3 | `dns-spoof.sh add` validates domain regex + IPv4 *and* IPv6; warns when domain is in `*_PASSTHROUGH_DOMAINS` (suppressed by `--force`) | **done** | Newline / slash injection rejected. `rm` validates domain too. |
| M1.4 | Symlink-aware `/etc/resolv.conf` backup. Regular file → `/etc/resolv.conf.backup`; symlink → target saved to `/run/mitm-beast/resolv_was_symlink_to`. Restore on `down` recreates the original form. | **done** | Idempotent: re-running `up` does not clobber the original backup. Resolv.conf overwrite now action-gated to `up\|reload` only (was previously running on every action including `down`). |

**Exit criteria met:** in-VM test cycle (`up -m none && down -k`) returns NM, resolv.conf, and iptables to baseline state. Smoke test of `up -m mitmproxy` followed by `down -k` and `restore --manager NetworkManager` confirms full round-trip.

See `PHASE1_STATUS.md` for the file-level diff summary and the test cases that were run.

---

## Phase 2 — Reliability & Process Hygiene (v1.1) — **2 days**

Goal: scripts behave predictably under partial failure, repeated invocation, and Ctrl-C.

| ID | Item | File(s) | Effort |
|---|---|---|---|
| M2.1 | Replace `$WAN_STATIC_IP` in printed URLs with the live IP from `ip -4 addr show $WAN_IFACE`. Fixes broken URLs in DHCP mode. | `mitm.sh` | 0.25d |
| M2.2 | Validate `WAN_STATIC_DNS` is non-empty before writing `resolv.conf`. Fall back to `1.1.1.1`. | `mitm.sh` | 0.1d |
| M2.3 | Replace `killall <name>` with PID-file-based shutdown. Track PIDs in `/run/mitm-beast/`. Stops MiTM Beast killing unrelated user dnsmasq/hostapd/mitmweb. | `mitm.sh`, `dns-spoof.sh` | 0.5d |
| M2.4 | Idempotent iptables in `delorean.sh` — `-C` check before `-A`. Track which rules were inserted to a state file; remove only those on `stop`. | `delorean.sh` | 0.25d |
| M2.5 | Add `trap teardown EXIT INT TERM` in `mitm.sh` and `delorean.sh`. Half-failed `up` now self-cleans. | `mitm.sh`, `delorean.sh` | 0.5d |
| M2.6 | DRY: extract duplicated cleanup logic from `reload` and `down` paths into `cleanup_session()`. | `mitm.sh` | 0.25d |
| M2.7 | Source `mitm.conf` from `delorean.sh` and `dns-spoof.sh` instead of redefining `BR_IFACE`/`ROUTER_IP` — eliminates configuration drift. | `delorean.sh`, `dns-spoof.sh` | 0.25d |
| M2.8 | Captive-portal bypass: pass `--ignore-hosts` (or addon equivalent) to mitmproxy/mitmweb for the well-known connectivity-check domains (`connectivitycheck.gstatic.com`, `www.google.com/generate_204`, `clients3.google.com`, `captive.apple.com`, `nmcheck.gnome.org`). Without this, modern Android marks the Wi-Fi "limited" and falls back to mobile data. Discovered during 2026-04-29 Pixel 9 validation. | `mitm.sh`, `mitm.conf.example` | 0.5d |

**Exit criteria:** Ctrl-C at any point in `up` returns the system to baseline. Repeated `delorean.sh start` does not duplicate iptables rules. `dns-spoof.sh reload` does not affect dnsmasq instances outside MiTM Beast. A real Android device joins the Wi-Fi AP and shows full connectivity even with mitmproxy active.

---

## Phase 3 — Correctness & Security Hardening (v1.1) — **1.5 days**

Goal: remove security footguns and behavior that surprises operators.

| ID | Item | File(s) | Effort |
|---|---|---|---|
| M3.1 | certmitm subshell PID issue: launch via `setsid python3 ...` and capture the python3 PID directly via `$!` after the activate is sourced in the parent shell, or write a tiny Python wrapper that handles its own PID file. | `mitm.sh` | 0.25d |
| M3.2 | Subdomain matching in `mitmproxy-intercept.py` — match `host == d` or `host.endswith("." + d)`. | `mitmproxy-intercept.py` | 0.1d |
| M3.3 | Move all PID and state files from `/tmp/mitm_*` to `/run/mitm-beast/` (root-owned, mode 0700). Eliminates predictable-name race attacks on shared hosts. | all `.sh` | 0.5d |
| M3.4 | Default `mitmweb --web-host` to `$LAN_IP` instead of `0.0.0.0`. Add explicit `MITMPROXY_BIND_WAN=true` flag to opt back in. | `mitm.sh`, `mitm.conf` | 0.1d |
| M3.5 | Refuse to start with default credentials (`mypassword`, `mitm`). Print remediation steps. | `mitm.sh` | 0.1d |
| M3.6 | Pass `MITMPROXY_WEB_PASSWORD` via env var, not command line — keeps it out of `ps`. | `mitm.sh` | 0.1d |
| M3.7 | Move sslsplit session CA private key from `/tmp/mitm_certs.*` to `/var/lib/mitm-beast/sessions/<id>/`. | `mitm.sh` | 0.25d |

**Exit criteria:** no MiTM Beast secrets visible in `ps auxf` or world-readable directories. Default-credential install refuses to launch.

---

## Phase 4 — Code Quality & Modernization (v1.2-rc1) — **2 days**

Goal: codebase is shellcheck-clean, lint-clean, and uses modern tooling.

| ID | Item | File(s) | Effort |
|---|---|---|---|
| M4.1 | Add `set -euo pipefail` and `IFS=$'\n\t'` to all bash scripts. Fix the failures it surfaces. | all `.sh` | 0.5d |
| M4.2 | Replace `ifconfig` and `brctl` with `ip` / `ip link` / `ip addr` throughout. Both are deprecated. | `mitm.sh` | 0.5d |
| M4.3 | Quote all variable expansions. Pass shellcheck with no exclusions. | all `.sh` | 0.5d |
| M4.4 | Standardize log/state paths under `./logs/<session_id>/`. Document in README. | `mitm.sh`, `fake-firmware-server.py` | 0.25d |
| M4.5 | `fake-firmware-server.py`: switch to `ThreadingHTTPServer` so a single slow client doesn't block the test. | `fake-firmware-server.py` | 0.1d |
| M4.6 | Resolve global-vs-arg `config` ambiguity in `fake-firmware-server.py`. | `fake-firmware-server.py` | 0.1d |

**Exit criteria:** `shellcheck *.sh` exits 0. `ruff check *.py` exits 0.

---

## Phase 5 — CI, Tests, Reproducibility (v1.2) — **2 days**

Goal: regressions are caught automatically; new contributors can run the toolkit confidently.

| ID | Item | Effort |
|---|---|---|
| M5.1 | GitHub Actions workflow: `shellcheck` + `ruff` on every PR. | 0.25d |
| M5.2 | Network-namespace smoke test: spin up two `ip netns`, run `mitm.sh up -m none` in one, verify DHCP/DNS from the other, run `down`, verify cleanup. CI runs it. | 1d |
| M5.3 | Per-mode smoke tests against a Python "honeypot" client that pretends to be an IoT device making TLS calls — assert each proxy mode produces the expected log artifacts. | 0.5d |
| M5.4 | `pre-commit` hooks: shellcheck, ruff, trailing whitespace. | 0.1d |
| M5.5 | Versioned release process: `git tag v1.2`, GitHub Releases with changelog. | 0.1d |

**Exit criteria:** PRs cannot merge without green CI. A known-good rev is taggable and reproducible.

---

## Phase 6 — Eclypsium Workflow Enhancements (v1.3) — **3–6 days**

Goal: features that make MiTM Beast a first-class research and services tool, beyond the open-source baseline.

| ID | Item | Audience | Effort |
|---|---|---|---|
| M6.1 | **Engagement report generator.** `mitm.sh report <session_dir>` produces a markdown/PDF summary: device-under-test info, modes run, cert fingerprints presented, pass/fail per test, PCAP references. Drops into client deliverables. | Services | 1d |
| M6.2 | **Enterprise device profiles.** Pre-canned configs for common test targets — e.g., `profile=bmc-redfish` (intercepts 443 and 8080, watches Redfish update endpoints), `profile=enterprise-router` (covers vendor telemetry hosts), `profile=iot-generic`. `mitm.sh up --profile bmc-redfish`. | Both | 1d |
| M6.3 | **Firmware-analysis hand-off.** When the fake firmware server captures an upload from the device (e.g., diagnostic blob, certificate enrollment), drop it in a structured `./captures/uploads/` dir with metadata for direct ingestion into Eclypsium's firmware analysis pipeline. | Research | 0.5d |
| M6.4 | **HTTP/2 + QUIC interception evaluation.** Spike to determine which proxy mode best supports modern protocol stacks; document gaps. Some enterprise devices have moved off HTTP/1.1. | Research | 1d |
| M6.5 | **Hostname-substring test as a one-liner.** Today this is a documented multi-step procedure. Wrap in `mitm.sh test substring-hostname --target <domain>` that handles the certbot dance and reports vulnerable/secure. | Both | 1d |
| M6.6 | **Findings-database integration (optional).** Each session writes a JSON summary to a configurable endpoint or local SQLite — feeds Eclypsium's research findings tracker. | Research | 0.5d |
| M6.7 | **Multi-device session tracking.** Many engagements test a fleet (e.g., 12 BMCs). Tag each connecting MAC with a device label and produce per-device subdirectories of logs/PCAPs. | Services | 0.5d |

**Exit criteria:** A services consultant can run `mitm.sh up --profile bmc-redfish --device "Dell iDRAC9 #4"` and finish with a one-command report.

---

## Suggested Sequencing & Releases

| Release | Phases | Calendar (single engineer) |
|---|---|---|
| **v1.1** — hardening | 1, 2, 3 | Week 1 |
| **v1.2** — quality + CI | 4, 5 | Week 2 |
| **v1.3** — Eclypsium features | 6 | Week 3–3.5 |

With two engineers, Phases 1–3 in parallel with Phase 4 brings v1.2 in by end of week 1.5; v1.3 lands end of week 2.5.

---

## Risk & Dependencies

- **Network-namespace tests (M5.2)** require root in CI; GitHub-hosted runners support this with caveats — may need a small self-hosted runner.
- **Phase 6 BMC profiles (M6.2)** benefit from access to representative hardware (Dell iDRAC, HPE iLO, Supermicro BMC). If unavailable, profiles can be authored from publicly available firmware/documentation but should be validated on real hardware before client use.
- **HTTP/2/QUIC (M6.4)** is research-flavored — outcome may be "document gaps and defer" rather than a full implementation. Time-box to 1 day.

---

## Decision Points for Leadership

1. **Phase 6 scope** — confirm which Eclypsium-specific enhancements (M6.1–M6.7) are highest leverage. Report generator (M6.1) and enterprise device profiles (M6.2) likely deliver the most services-team value; firmware hand-off (M6.3) and findings DB (M6.6) deliver the most research-team value.
2. **Open-sourcing posture** — v1.1 hardening is generally useful; v1.3 Eclypsium-specific work may belong in a private fork or internal extension repo. Recommend keeping core open-source-clean and shipping enterprise features as a separate `mitmbeast-enterprise` overlay.
3. **Maintainer ownership** — single named owner needed for the open-source repo to handle community contributions and disclosures, since security tools attract reports.
