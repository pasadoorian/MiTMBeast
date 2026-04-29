# MiTM Beast — Executive Summary

**Audience:** Eclypsium leadership, Research, and Services
**Status:** v1.0 functional · Phase 1 (critical stability remediation) complete · v1.1 pending end-to-end smoke test in the VM bed

---

## What MiTM Beast Is

MiTM Beast is a single-machine network man-in-the-middle platform purpose-built to intercept, manipulate, and impersonate the **network side** of any firmware-based device — IoT endpoints, edge gateways, enterprise switches and routers, BMCs, storage controllers, network security appliances, and any product that talks to a vendor cloud, NTP source, or update server.

It complements firmware-image analysis by attacking the **runtime trust boundary** between the device and its vendor: DNS, TLS, NTP, and OTA update channels. Where Eclypsium's existing tooling tells us *what is in the firmware*, MiTM Beast tells us *what the firmware trusts on the wire and what happens when that trust is abused*.

---

## Why It Matters to Eclypsium

### For the Research Team — accelerating new-bug discovery

Firmware analysis can identify a vulnerable update routine in static analysis, but proving exploitability often requires standing up the full network conditions the device expects. MiTM Beast removes that friction.

**Direct research value:**
- **Surfaces a CVE-rich vulnerability class** — TLS certificate validation flaws, hostname substring matching, expired-cert acceptance, and TLS-to-HTTP downgrade are reliably present in firmware shipped by major vendors. The toolkit tests for each in minutes per device.
- **Closes the loop from firmware to network** — when static analysis flags a hardcoded update host or a weak TLS context, MiTM Beast can immediately confirm exploitability against a live device.
- **Time manipulation as a research lever** — combined NTP spoofing + time-matched certificates bypass certificate expiry, exposing devices that rely on `notAfter` as their primary trust check. This is an underexplored vulnerability class with strong advisory potential.
- **Fake update server enables full exploit chain validation** — researchers can demonstrate end-to-end RCE via firmware injection, not just "the device accepted a bad cert." Advisory weight is materially higher.
- **Capture artifacts (PCAPs, connection logs, certificate fingerprints) drop directly into write-ups and CVE submissions.**

**Where it lives in the research workflow:**
```
Firmware image  -->  Eclypsium static analysis  -->  identifies update/cert logic
                                                              |
                                                              v
       MiTM Beast  <--  bench device under test  <--  hypothesis to validate
              |
              v
     Reproducible exploit + evidence package --> advisory / CVE
```

### For the Services Team — repeatable, evidence-producing engagements

Customer engagements live or die on consistent methodology and defensible evidence. Network MITM testing has historically been bespoke per engagement — every consultant rebuilds the rig.

**Direct services value:**
- **Single-command engagement bring-up.** A laptop with two NICs and a Wi-Fi adapter becomes a full MITM lab. Lower setup overhead per engagement = more billable hours on actual analysis.
- **Five interchangeable proxy modes against the same device, one session** — covers the common firmware-device weakness matrix (cert validation, downgrade, response injection, generic capture) without reconfiguring infrastructure.
- **Per-session evidence artifacts** — timestamped PCAPs, connection logs, certificate fingerprints, and intercepted payloads are produced by default and drop straight into client reports.
- **Selective interception (DNS-spoof + passthrough)** — critical for enterprise devices that make many sequential cloud calls, where breaking the wrong one prevents the device from reaching the test path.
- **Portable to client sites.** Runs on commodity Linux hardware. No cloud dependency, no per-seat licensing, no client network changes required.
- **Standardizes deliverables across consultants.** Two engineers running the same playbook produce comparably structured evidence.

### Scope: not just IoT

The toolkit's architecture is protocol-driven, not device-class-driven. It is equally applicable to:

| Device class | Typical findings MiTM Beast surfaces |
|---|---|
| Consumer IoT | Cert validation, cleartext OTA, hardcoded update hosts |
| Edge gateways / industrial controllers | Downgrade, NTP-bypass cert expiry, weak SAN matching |
| Enterprise routers / switches / firewalls | Update channel hijack, fallback-to-HTTP, BMC management plane interception |
| Server BMCs / IPMI / Redfish endpoints | TLS implementation flaws, update-image acceptance, cert pinning gaps |
| Storage controllers and SAN appliances | Vendor-cloud telemetry channels, license/update servers |
| Network security appliances | Self-update mechanisms, telemetry exfiltration paths |

The fake update server, NTP attack, and substring-hostname-matching test apply identically across these classes — the threat model (a device trusts a remote vendor over TLS) is the same.

---

## Capability Summary

| Capability | Research use | Services use |
|---|---|---|
| Transparent TLS proxy (mitmproxy, sslsplit) | Manual exploration of new protocols | Default capture for any engagement |
| **certmitm** — automated cert validation testing | Bug-class hunting across many devices | Pass/fail evidence per device |
| **sslstrip** — TLS downgrade testing | Surface devices that fall back to HTTP | Compliance/risk reporting |
| **intercept** — fake response injection | End-to-end exploit demonstration | Proof-of-impact for clients |
| **NTP spoofing (Delorean)** | Time-attack research | Comprehensive update-channel coverage |
| **Fake firmware server** | Exploit chain validation | Demonstrable supply-chain impact |
| Selective DNS spoofing with passthrough | Multi-step protocol research | Engagements with chatty enterprise devices |
| Per-session PCAP / log capture | Advisory evidence | Client report artifacts |

---

## Current State

- Functionally complete (v1.0), in active use.
- Code review identified 10 issues across stability, security, and quality.
- **Phase 1 (critical stability) is complete and verified in the VM test bed** (2026-04-28):
  - `mitm.sh restore` subcommand re-enables NetworkManager, restores `/etc/resolv.conf`, and tears down MITM iptables chains
  - `iptables --flush` replaced with dedicated `MITM_*` chains — host firewall rules are no longer wiped
  - `dns-spoof.sh add` validates input (IPv4 + IPv6) and rejects injection attempts
  - `/etc/resolv.conf` is now backed up before overwrite and correctly restored, including the symlink case
- Phases 2–6 (reliability hardening, security hygiene, code quality, CI, and Eclypsium-specific enhancements) remain. See `IMPLEMENTATION_PLAN.md` for milestones and `PHASE1_STATUS.md` for the detailed Phase 1 summary.
