# Phase 1 — Status

**Last updated:** 2026-04-28

## Implementation: complete

| ID | Item | Status | Files touched |
|---|---|---|---|
| M1.1 | RESTORE.md + `mitm.sh restore` subcommand | done | `mitm.sh`, `RESTORE.md` |
| M1.2 | Replace `iptables --flush` with named `MITM_*` chains | done | `mitm.sh`, `delorean.sh` |
| M1.3 | `dns-spoof.sh` input validation (IPv4+IPv6, passthrough warn, `--force`) | done | `dns-spoof.sh` |
| M1.4 | resolv.conf backup with symlink awareness | done | `mitm.sh` |

## Decisions locked during planning

| Q | Item | Decision |
|---|---|---|
| 1 | Restore mechanism | Markdown doc + `mitm.sh restore` subcommand |
| 2 | How `restore` chooses what to re-enable | Interactive prompt; `--manager` flag for non-interactive |
| 3a | dns-spoof IP support | IPv4 **and** IPv6 |
| 3b | Passthrough domain conflict | Warn + allow + `--force` to silence |
| 4 | `down` resolv.conf handling | Detect symlink at `up`, recreate symlink at `down` |
| 5 | Test bed | Kali (MITM Beast) + Ubuntu Server (victim) on libvirt, USB Wi-Fi passthrough |

## Test bed

- Host: Manjaro (paulda's workstation)
- KVM/libvirt — three networks:
  - `default` (NAT, 192.168.122.0/24) — currently inactive, autostart disabled, kept around
  - `mitm-lan` (isolated, no DHCP/NAT) — for VM-to-VM LAN side
  - `nwbridge` (bridge → host's bridge0 → 192.168.1.0/24) — Kali WAN
- **Kali VM** with two virtio NICs and an AR9271 USB Wi-Fi passthrough; `mitm.conf` is configured for the lab's specific WAN interface, static IP, and Wi-Fi credentials (lab values intentionally not committed; see local notes).
- **Ubuntu Server VM** also part of the bed (added 2026-04-29) for victim-side traffic.

## Verified test cases (in Kali VM)

### M1.4
- Regular file `/etc/resolv.conf`: backed up at `up`, restored at `down`
- Symlink `/etc/resolv.conf`: target saved to `/run/mitm-beast/resolv_was_symlink_to`, recreated at `down`
- Re-running `up` without `down`: backup not clobbered (idempotent)

### M1.3
- Valid IPv4 (`192.168.1.50`) → accepted
- Valid IPv6 (`::1`) → accepted
- Slash in domain (`evil/bar`) → rejected, exit 1
- Newline-injection (`foo\naddress=/evil.com/9.9.9.9`) → **rejected**, exit 1
- Bad IPv4 (`999.999.999.999`) → rejected
- Domain in CERTMITM_PASSTHROUGH_DOMAINS → warned, still added
- Same with `--force` → no warning

### M1.1
- `restore --manager NetworkManager` → NM re-enabled, resolv.conf restored
- `restore --manager none` → resolv.conf restored, no service touched
- `restore` with no TTY and no flag → exits with helpful error
- Interactive prompt path uses standard `read -p` (not auto-tested)

### M1.2
- `up -m mitmproxy` → `MITM_FWD`, `MITM_NAT_PRE`, `MITM_NAT_POST` chains created and hooked into built-ins
- `down -k` → all `MITM_*` references removed from iptables-save
- Re-running `up` twice → no rule duplication (idempotent)

## Open items

All Phase 1 closeout items are done:

- **#8** Ubuntu Server 26.04 victim VM built on `mitm-lan` (DHCP from MITM Beast at 192.168.200.X)
- **#4** End-to-end smoke test in mitmproxy mode: victim's `openssl s_client` showed `issuer=CN=mitmproxy`, MITM_NAT_PRE counter incremented, full down → restore round-trip returns the host to baseline
- **#10** Real-hardware Wi-Fi validation: Pixel 9 associated to the AR9271 AP, got DHCP, NAT'd to internet
- Git commit landed as `793be5c`

## Findings discovered during Wi-Fi validation

Modern Android (Pixel 9 / latest) runs an HTTPS-based captive portal check (`https://www.google.com/generate_204`) and falls back to LTE if cert verification fails. With mitmproxy in transparent HTTPS interception mode, the device sees `issuer=CN=mitmproxy` and refuses to mark the network usable. This is captured as a new feature item in `IMPLEMENTATION_PLAN.md` (Phase 2 usability addition) — bypass the well-known captive-check hosts via mitmproxy `--ignore-hosts`.

## Files changed (host repo, uncommitted)

- `mitm.sh` — added `backup_resolv_conf`/`restore_resolv_conf`/`mitm_iptables_install`/`mitm_iptables_uninstall` functions; gated top-level destructive sections on `ACTION != restore`; added `restore` subcommand and `--manager` flag; replaced `iptables --flush` with named chains
- `dns-spoof.sh` — added `validate_domain`/`validate_ip`/`check_passthrough`; added `--force` flag parsing
- `delorean.sh` — moved NTP DNAT rules into dedicated `MITM_NTP_PRE` chain
- `RESTORE.md` — new doc
- `mitm.conf` — **gitignored**; on the test VM the lab values were set (WAN interface name, static IP, Wi-Fi SSID/password) but those are environment-specific and intentionally not in the repo
