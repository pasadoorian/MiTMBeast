"""Tab content widgets for the MVP TUI.

Three screens: Dashboard, Clients, DNS Spoofs. Each composes a
:class:`StatusBar` at the top and its own content below. Screens own
the polling timer for their data.
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Input, Static

from mitmbeast.core import dnsmasq, hostapd
from mitmbeast.tui.state import snapshot_state
from mitmbeast.tui.widgets import StatusBar

REPO_ROOT = Path(__file__).resolve().parents[3]


class DashboardScreen(Vertical):
    """Status overview + up/down buttons."""

    def compose(self) -> ComposeResult:
        yield StatusBar(id="status_text")
        with Horizontal(id="dashboard_actions"):
            yield Button("Up (--python -m none)", id="btn_up", variant="success")
            yield Button("Down", id="btn_down", variant="warning")
            yield Button("Refresh", id="btn_refresh")
        yield Static(id="dashboard_log", expand=True)

    def on_mount(self) -> None:
        self._log_lines: list[str] = []
        self._refresh()
        self.set_interval(2.0, self._refresh)

    def _refresh(self) -> None:
        snap = snapshot_state()
        self.query_one("#status_text", StatusBar).update_from(snap)

    def _append_log(self, line: str) -> None:
        ts = datetime.now(UTC).strftime("%H:%M:%S")
        self._log_lines.append(f"{ts}  {line}")
        # Keep last 12 lines
        self._log_lines = self._log_lines[-12:]
        self.query_one("#dashboard_log", Static).update("\n".join(self._log_lines))

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_up":
            await self._invoke_router("up")
        elif event.button.id == "btn_down":
            await self._invoke_router("down")
        elif event.button.id == "btn_refresh":
            self._refresh()

    async def _invoke_router(self, action: str) -> None:
        if os.geteuid() != 0:
            self._append_log("[red]Need root for this action — relaunch with sudo[/]")
            return
        argv = [sys.executable, "-m", "mitmbeast.cli", action, "--python", "-k"]
        if action == "up":
            argv += ["-m", "none"]
        self._append_log(f"$ {' '.join(argv[1:])}")
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=str(REPO_ROOT),
            )
            assert proc.stdout is not None
            async for raw in proc.stdout:
                self._append_log(raw.decode("utf-8", "replace").rstrip("\n"))
            await proc.wait()
            self._append_log(f"[dim]exit {proc.returncode}[/]")
        except Exception as e:  # noqa: BLE001 — surface anything in the UI
            self._append_log(f"[red]error: {e}[/]")
        self._refresh()


class ClientsScreen(Vertical):
    """Merged view: dnsmasq DHCP leases + hostapd Wi-Fi stations."""

    def compose(self) -> ComposeResult:
        yield StatusBar(id="status_text")
        yield DataTable(id="clients_table", zebra_stripes=True)

    def on_mount(self) -> None:
        table = self.query_one("#clients_table", DataTable)
        table.cursor_type = "row"
        table.add_columns("MAC", "IP", "Hostname",
                          "Signal dBm", "Wi-Fi RX", "Wi-Fi TX",
                          "Lease expires")
        self._refresh()
        self.set_interval(3.0, self._refresh)

    def _refresh(self) -> None:
        snap = snapshot_state()
        self.query_one("#status_text", StatusBar).update_from(snap)

        table = self.query_one("#clients_table", DataTable)
        table.clear()

        leases = dnsmasq.read_leases() if snap.is_root else []
        stations = {s.mac: s for s in hostapd.list_stations(snap.wifi_iface)}

        # Index leases by MAC for joining
        lease_by_mac = {ll.mac.lower(): ll for ll in leases}

        # Union of macs across both sources
        macs = set(lease_by_mac) | set(stations)
        for mac in sorted(macs):
            lease = lease_by_mac.get(mac)
            sta = stations.get(mac)
            ip = str(lease.ip) if lease else "-"
            hostname = lease.hostname if lease and lease.hostname else "-"
            signal = (str(sta.signal_dbm) if sta and sta.signal_dbm is not None
                      else "-")
            rx = f"{sta.rx_bytes:,}" if sta else "-"
            tx = f"{sta.tx_bytes:,}" if sta else "-"
            if lease:
                ttl = lease.expires_in_seconds
                if ttl == float("inf"):
                    expires = "infinite"
                elif ttl < 0:
                    expires = "[red]expired[/]"
                else:
                    h = int(ttl // 3600)
                    m = int((ttl % 3600) // 60)
                    expires = f"{h}h{m:02d}m"
            else:
                expires = "-"
            table.add_row(mac, ip, hostname, signal, rx, tx, expires)


class SpoofsScreen(Vertical):
    """List + add/remove DNS spoof entries."""

    def compose(self) -> ComposeResult:
        yield StatusBar(id="status_text")
        with Horizontal(id="spoof_form"):
            yield Input(placeholder="domain (e.g. update.example.com)",
                        id="spoof_domain")
            yield Input(placeholder="IP (v4 or v6)", id="spoof_ip")
            yield Button("Add", id="btn_add_spoof", variant="success")
        yield DataTable(id="spoofs_table", zebra_stripes=True)
        yield Static(id="spoof_message")

    def on_mount(self) -> None:
        table = self.query_one("#spoofs_table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Domain", "IP", "")
        self._refresh()
        self.set_interval(5.0, self._refresh)

    def _refresh(self) -> None:
        snap = snapshot_state()
        self.query_one("#status_text", StatusBar).update_from(snap)
        table = self.query_one("#spoofs_table", DataTable)
        table.clear()
        for domain, ip in self._read_spoofs():
            table.add_row(domain, ip, "[dim](Enter on row → remove)[/]")

    def _read_spoofs(self) -> list[tuple[str, str]]:
        """Parse dns-spoof.conf in the repo root."""
        path = REPO_ROOT / "dns-spoof.conf"
        out: list[tuple[str, str]] = []
        if not path.is_file():
            return out
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("address=/"):
                rest = line[len("address=/"):]
                # rest is "domain/ip"
                slash = rest.rfind("/")
                if slash > 0:
                    out.append((rest[:slash], rest[slash + 1:]))
        return out

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_add_spoof":
            domain = self.query_one("#spoof_domain", Input).value.strip()
            ip = self.query_one("#spoof_ip", Input).value.strip()
            if not domain or not ip:
                self._set_msg("[red]domain and ip required[/]")
                return
            await self._invoke(["spoof", "add", domain, ip])
            self.query_one("#spoof_domain", Input).value = ""
            self.query_one("#spoof_ip", Input).value = ""
            self._refresh()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        table = self.query_one("#spoofs_table", DataTable)
        row = table.get_row(event.row_key)
        if not row:
            return
        domain = str(row[0])
        # Use a worker to avoid blocking the UI
        self.run_worker(self._invoke(["spoof", "rm", domain]))

    async def _invoke(self, args: list[str]) -> None:
        argv = [sys.executable, "-m", "mitmbeast.cli", *args]
        try:
            r = await asyncio.create_subprocess_exec(
                *argv, cwd=str(REPO_ROOT),
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            _, stderr = await r.communicate()
            if r.returncode == 0:
                self._set_msg(f"ok: {' '.join(args)}")
            else:
                self._set_msg(f"[red]exit {r.returncode}: "
                              f"{stderr.decode('utf-8', 'replace').strip()}[/]")
        except Exception as e:  # noqa: BLE001
            self._set_msg(f"[red]error: {e}[/]")
        self._refresh()

    def _set_msg(self, msg: str) -> None:
        self.query_one("#spoof_message", Static).update(msg)
