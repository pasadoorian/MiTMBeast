"""Polled view of the mitmbeast router state.

The MVP TUI does not yet have an event bus (Phase 2c work). Instead,
each screen calls :func:`snapshot_state` on a ``set_interval`` timer
and re-renders. The function is cheap (a handful of subprocess /
netlink reads, all local) so 1–3 second cadences are fine.

When Phase 2c lands, the TUI screens migrate to subscribing to the
event bus; this module's role shifts to "initial snapshot" only.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from mitmbeast.core import dnsmasq, firewall, hostapd, netif


@dataclass(frozen=True, slots=True)
class RouterSnapshot:
    """Point-in-time view of router state.

    Cheap to compute; safe to call from a TUI timer.
    """

    is_root: bool

    # Bridge / WAN / Wi-Fi addresses — empty list means iface absent / down
    wan_iface: str
    wan_addresses: tuple[str, ...]
    bridge_iface: str
    bridge_addresses: tuple[str, ...]
    wifi_iface: str

    # Daemon state
    dnsmasq_running: bool
    hostapd_running: bool

    # Firewall — chain present + total packets through MASQUERADE
    mitm_chains_present: bool
    masquerade_packets: int

    # Counts (for headers / summaries)
    lease_count: int
    station_count: int

    # Operating mode best-guess: "none" if Python state file but no
    # proxy chains, "unknown" if bash version is up, "down" if all clean.
    mode: str = "unknown"

    # The dnsmasq + hostapd config paths the router writes when up
    dnsmasq_conf: Path = field(default=Path("/run/mitmbeast/dnsmasq.conf"))
    hostapd_conf: Path = field(default=Path("/run/mitmbeast/hostapd.conf"))


def _addresses(iface: str) -> tuple[str, ...]:
    """List of CIDR strings on ``iface`` — empty if iface absent."""
    if not netif.iface_exists(iface):
        return ()
    return tuple(str(a.interface) for a in netif.iface_addresses(iface))


def snapshot_state(
    *,
    wan_iface: str = "eth2",
    bridge_iface: str = "br0",
    wifi_iface: str = "wlan0",
    dnsmasq_conf: Path = Path("/run/mitmbeast/dnsmasq.conf"),
    hostapd_conf: Path = Path("/run/mitmbeast/hostapd.conf"),
) -> RouterSnapshot:
    """Collect a full snapshot of router state."""
    is_root = os.geteuid() == 0

    chains_present = (
        firewall.chain_exists("nat", "MITM_NAT_PRE")
        and firewall.chain_exists("nat", "MITM_NAT_POST")
        and firewall.chain_exists("filter", "MITM_FWD")
    )

    masq_pkts = 0
    if chains_present:
        for pkts, _ in firewall.chain_packet_counts("nat", "MITM_NAT_POST"):
            masq_pkts += pkts

    leases = dnsmasq.read_leases() if is_root else []
    stations = hostapd.list_stations(wifi_iface)

    if not chains_present:
        mode = "down"
    else:
        # If we wrote our own configs, infer "none" (no proxy support yet)
        mode = "none" if dnsmasq_conf.exists() else "unknown"

    return RouterSnapshot(
        is_root=is_root,
        wan_iface=wan_iface,
        wan_addresses=_addresses(wan_iface),
        bridge_iface=bridge_iface,
        bridge_addresses=_addresses(bridge_iface),
        wifi_iface=wifi_iface,
        dnsmasq_running=dnsmasq.is_running(dnsmasq_conf) if dnsmasq_conf.exists() else False,
        hostapd_running=hostapd.is_running(hostapd_conf) if hostapd_conf.exists() else False,
        mitm_chains_present=chains_present,
        masquerade_packets=masq_pkts,
        lease_count=len(leases),
        station_count=len(stations),
        mode=mode,
        dnsmasq_conf=dnsmasq_conf,
        hostapd_conf=hostapd_conf,
    )
