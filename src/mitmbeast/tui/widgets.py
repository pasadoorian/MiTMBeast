"""Shared widgets and helpers for the TUI."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Static

from mitmbeast.tui.state import RouterSnapshot


class StatusBar(Static):
    """Top-of-screen status line summarising router state."""

    DEFAULT_CSS = ""  # rely on app.tcss

    def update_from(self, s: RouterSnapshot) -> None:
        if s.mode == "down":
            mode_part = "[bold red]DOWN[/]"
        else:
            mode_part = f"[bold green]UP[/] · mode={s.mode}"

        wan = s.wan_addresses[0] if s.wan_addresses else "[dim]not configured[/]"
        lan = s.bridge_addresses[0] if s.bridge_addresses else "[dim]no bridge[/]"

        flags = []
        if s.dnsmasq_running:
            flags.append("[green]dnsmasq[/]")
        else:
            flags.append("[dim]dnsmasq[/]")
        if s.hostapd_running:
            flags.append("[green]hostapd[/]")
        else:
            flags.append("[dim]hostapd[/]")

        root = "[green]root[/]" if s.is_root else "[red]non-root[/]"

        self.update(
            f"{mode_part}    "
            f"WAN ({s.wan_iface}): {wan}    "
            f"LAN ({s.bridge_iface}): {lan}    "
            f"{'  '.join(flags)}    "
            f"clients: {s.lease_count} DHCP / {s.station_count} STA    "
            f"masq pkts: {s.masquerade_packets}    "
            f"{root}"
        )


def header_row() -> ComposeResult:
    """Yield a Horizontal containing the StatusBar widget."""
    with Horizontal(id="status_bar"):
        yield StatusBar(id="status_text")
