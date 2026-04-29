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
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, DataTable, Input, RichLog, Select, Static

from mitmbeast.core import dnsmasq, hostapd
from mitmbeast.tui.state import snapshot_state
from mitmbeast.tui.widgets import StatusBar

REPO_ROOT = Path(__file__).resolve().parents[3]


def _clients_snapshot() -> tuple[object, list[object], list[object]]:
    """Combined off-thread fetch for the Clients screen.

    Returns ``(snapshot, leases, stations)``. Touches pyroute2 +
    subprocess; safe to run via :func:`asyncio.to_thread`.
    """
    snap = snapshot_state()
    leases = dnsmasq.read_leases() if snap.is_root else []
    stations = hostapd.list_stations(snap.wifi_iface)
    return snap, leases, stations


def _spoofs_snapshot() -> tuple[object, list[tuple[str, str]]]:
    """Off-thread fetch for the Spoofs screen.

    Reading dns-spoof.conf is just file IO so it would be safe inline,
    but we run it through the same path as the others to keep the
    snapshot model uniform.
    """
    snap = snapshot_state()
    path = REPO_ROOT / "dns-spoof.conf"
    out: list[tuple[str, str]] = []
    if path.is_file():
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("address=/"):
                rest = line[len("address=/"):]
                slash = rest.rfind("/")
                if slash > 0:
                    out.append((rest[:slash], rest[slash + 1:]))
    return snap, out


_MODES: tuple[tuple[str, str], ...] = (
    ("none — router only (Python stack)", "none"),
    ("mitmproxy — transparent HTTPS intercept (bash)", "mitmproxy"),
    ("sslsplit — TLS PCAP capture (bash)", "sslsplit"),
    ("certmitm — TLS validation testing (bash)", "certmitm"),
    ("sslstrip — TLS downgrade testing (bash)", "sslstrip"),
    ("intercept — fake response injection (bash)", "intercept"),
)


class DashboardScreen(Vertical):
    """Status overview + mode selector + up/down buttons."""

    def compose(self) -> ComposeResult:
        yield StatusBar(id="status_text")
        with Horizontal(id="dashboard_actions"):
            yield Select(_MODES, value="none", id="mode_select",
                         allow_blank=False, prompt="Proxy mode")
            yield Button("Up", id="btn_up", variant="success")
            yield Button("Down", id="btn_down", variant="warning")
            yield Button("Refresh", id="btn_refresh")
            yield Button("Clear log", id="btn_clear_log")
        yield RichLog(id="dashboard_log", wrap=True, markup=True,
                      max_lines=5000, auto_scroll=True)

    async def on_mount(self) -> None:
        await self._refresh()
        self.set_interval(2.0, self._refresh)
        # Subscribe to the app's event bus so live events land in the
        # log pane. Unsubscribe is idempotent and runs at unmount.
        self._unsub = self.app.bus.subscribe(self._on_event)  # type: ignore[attr-defined]

    def on_unmount(self) -> None:
        if hasattr(self, "_unsub"):
            self._unsub()

    async def _refresh(self) -> None:
        # snapshot_state() touches pyroute2, which constructs an asyncio
        # event loop internally — run it off the main loop so it doesn't
        # collide with Textual's already-running loop.
        snap = await asyncio.to_thread(snapshot_state)
        self.query_one("#status_text", StatusBar).update_from(snap)

    def _on_event(self, event) -> None:  # type: ignore[no-untyped-def]
        """Render any bus event as a single coloured log line."""
        kind = event.kind.upper()
        # Quick mode-specific formatting; default to k=v dump.
        d = event.data
        if event.kind == "dhcp_lease":
            msg = (f"[green]DHCP[/]    {d.get('ip')} → "
                   f"{d.get('hostname') or d.get('mac')}")
        elif event.kind == "dhcp_request":
            msg = f"[dim]DHCP-REQ[/] {d.get('ip')} ({d.get('mac')})"
        elif event.kind == "dhcp_release":
            msg = f"[yellow]DHCP-REL[/] {d.get('ip')} ({d.get('mac')})"
        elif event.kind == "sta_connected":
            msg = f"[cyan]STA+[/]    {d.get('mac')} on {d.get('iface')}"
        elif event.kind == "sta_disconnected":
            msg = f"[magenta]STA-[/]    {d.get('mac')} on {d.get('iface')}"
        else:
            msg = f"[dim]{kind}[/] " + " ".join(f"{k}={v}" for k, v in d.items())
        self._append_log(msg)

    def _append_log(self, line: str) -> None:
        ts = datetime.now(UTC).strftime("%H:%M:%S")
        self.query_one("#dashboard_log", RichLog).write(f"[dim]{ts}[/]  {line}")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_up":
            await self._invoke_router("up")
        elif event.button.id == "btn_down":
            await self._invoke_router("down")
        elif event.button.id == "btn_refresh":
            await self._refresh()
        elif event.button.id == "btn_clear_log":
            self.query_one("#dashboard_log", RichLog).clear()

    async def _invoke_router(self, action: str) -> None:
        if os.geteuid() != 0:
            self._append_log("[red]Need root for this action — relaunch with sudo[/]")
            return
        # Pick selected mode from the Select widget (default "none").
        mode = "none"
        try:
            mode = str(self.query_one("#mode_select", Select).value)
        except Exception:  # noqa: BLE001, S110 — defensive; default mode OK
            pass

        argv = [sys.executable, "-m", "mitmbeast.cli", action]
        # Use the new Python stack only for mode=none. Other modes still
        # rely on the v1.1 bash dispatch until P2.10/P2.11 land.
        use_python = (action == "down") or (action == "up" and mode == "none")
        if use_python:
            argv.append("--python")
        argv.append("-k")
        if action == "up":
            argv += ["-m", mode]
        self._append_log(f"$ {' '.join(argv[1:])}"
                         + (" [dim](python)[/]" if use_python else " [dim](bash)[/]"))
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
        await self._refresh()


class ClientsScreen(Vertical):
    """Merged view: dnsmasq DHCP leases + hostapd Wi-Fi stations."""

    def compose(self) -> ComposeResult:
        yield StatusBar(id="status_text")
        yield DataTable(id="clients_table", zebra_stripes=True)

    async def on_mount(self) -> None:
        table = self.query_one("#clients_table", DataTable)
        table.cursor_type = "row"
        table.add_columns("MAC", "IP", "Hostname",
                          "Signal dBm", "Wi-Fi RX", "Wi-Fi TX",
                          "Lease expires")
        await self._refresh()
        self.set_interval(3.0, self._refresh)

    async def _refresh(self) -> None:
        # See DashboardScreen._refresh for why we go off-thread.
        snap, leases, stations_list = await asyncio.to_thread(_clients_snapshot)
        self.query_one("#status_text", StatusBar).update_from(snap)

        table = self.query_one("#clients_table", DataTable)
        table.clear()

        stations = {s.mac: s for s in stations_list}

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

    async def on_mount(self) -> None:
        table = self.query_one("#spoofs_table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Domain", "IP", "")
        await self._refresh()
        self.set_interval(5.0, self._refresh)

    async def _refresh(self) -> None:
        snap, spoofs = await asyncio.to_thread(_spoofs_snapshot)
        self.query_one("#status_text", StatusBar).update_from(snap)
        table = self.query_one("#spoofs_table", DataTable)
        table.clear()
        for domain, ip in spoofs:
            table.add_row(domain, ip, "[dim](Enter on row → remove)[/]")

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
            await self._refresh()

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
        await self._refresh()

    def _set_msg(self, msg: str) -> None:
        self.query_one("#spoof_message", Static).update(msg)


# ----------------------------------------------------------------------
# Sessions screen — list pcap + proxy-session directories on disk
# ----------------------------------------------------------------------

# (label_for_kind, dir_relative_to_repo_root)
_SESSION_DIRS: tuple[tuple[str, str], ...] = (
    ("tcpdump",  "captures"),
    ("sslsplit", "sslsplit_logs"),
    ("certmitm", "certmitm_logs"),
    ("sslstrip", "sslstrip_logs"),
    ("intercept","intercept_logs"),
)


def _sessions_snapshot() -> tuple[object, list[tuple[str, str, str, str]]]:
    """Off-thread fetch for the Sessions screen.

    Returns ``(snapshot, rows)`` where each row is
    ``(kind, relative_path, size_human, mtime_human)``.
    """
    from datetime import datetime as _dt
    snap = snapshot_state()
    rows: list[tuple[str, str, str, str]] = []
    for kind, rel in _SESSION_DIRS:
        d = REPO_ROOT / rel
        if not d.is_dir():
            continue
        for child in sorted(d.iterdir(), reverse=True):
            try:
                st = child.stat()
            except OSError:
                continue
            size_h = _human_bytes(_total_size(child))
            mtime_h = _dt.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
            rows.append((kind, str(child.relative_to(REPO_ROOT)), size_h, mtime_h))
    return snap, rows


def _total_size(p: Path) -> int:
    if p.is_file():
        return p.stat().st_size
    total = 0
    for child in p.rglob("*"):
        try:
            if child.is_file():
                total += child.stat().st_size
        except OSError:
            continue
    return total


def _human_bytes(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024.0:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024.0  # type: ignore[assignment]
    return f"{n:.1f} PiB"


class SessionsScreen(Vertical):
    """Past + current capture / proxy session directories on disk."""

    def compose(self) -> ComposeResult:
        yield StatusBar(id="status_text")
        yield DataTable(id="sessions_table", zebra_stripes=True)
        yield Static(id="sessions_hint",
                     content="[dim]Open these in Wireshark / mitmweb / "
                             "your editor for now — in-TUI viewer comes later.[/]")

    async def on_mount(self) -> None:
        table = self.query_one("#sessions_table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Kind", "Path", "Size", "Modified")
        await self._refresh()
        self.set_interval(5.0, self._refresh)

    async def _refresh(self) -> None:
        snap, rows = await asyncio.to_thread(_sessions_snapshot)
        self.query_one("#status_text", StatusBar).update_from(snap)
        table = self.query_one("#sessions_table", DataTable)
        table.clear()
        if not rows:
            table.add_row("[dim]none[/]", "no sessions on disk yet", "", "")
            return
        for kind, path, size, mtime in rows:
            table.add_row(kind, path, size, mtime)


# ----------------------------------------------------------------------
# Logs screen — tail journalctl entries from our daemons
# ----------------------------------------------------------------------

class LogsScreen(Vertical):
    """Recent journalctl entries for our daemons + mitmbeast itself."""

    JOURNAL_UNITS = ("dnsmasq", "hostapd", "mitmweb", "sslsplit",
                     "sslstrip", "mitmbeast")

    def compose(self) -> ComposeResult:
        yield StatusBar(id="status_text")
        yield Static(id="logs_pane")

    async def on_mount(self) -> None:
        await self._refresh()
        # Logs change quickly when traffic flows — poll every 2s.
        self.set_interval(2.0, self._refresh)

    async def _refresh(self) -> None:
        snap, log_text = await asyncio.to_thread(self._gather)
        self.query_one("#status_text", StatusBar).update_from(snap)
        self.query_one("#logs_pane", Static).update(log_text or
            "[dim]No recent entries from dnsmasq / hostapd / mitmweb / "
            "sslsplit / sslstrip. Bring the router up and traffic will "
            "appear here.[/]")

    def _gather(self) -> tuple[object, str]:
        """Collect last ~80 lines from any of our daemon units."""
        snap = snapshot_state()
        # Match by syslog-identifier; one journalctl call covers all.
        cmd = ["journalctl", "-n", "80", "--no-pager", "-q"]
        for unit in self.JOURNAL_UNITS:
            cmd += ["-t", unit]
        try:
            r = subprocess.run(cmd, check=False, capture_output=True,
                               text=True, timeout=3.0)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return snap, ""
        return snap, r.stdout


# ----------------------------------------------------------------------
# Settings screen — read-only display of mitm.conf
# ----------------------------------------------------------------------

# Logical grouping of mitm.conf fields for readable display
_SETTINGS_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Network interfaces", ("WAN_IFACE", "LAN_IFACE", "WIFI_IFACE", "BR_IFACE")),
    ("LAN bridge",         ("LAN_IP", "LAN_SUBNET",
                            "LAN_DHCP_START", "LAN_DHCP_END")),
    ("WAN",                ("WAN_STATIC_IP", "WAN_STATIC_NETMASK",
                            "WAN_STATIC_GATEWAY", "WAN_STATIC_DNS")),
    ("Wi-Fi AP",           ("WIFI_SSID", "WIFI_PASSWORD")),
    ("Default proxy",      ("PROXY_MODE",)),
    ("mitmproxy",          ("MITMPROXY_PORT", "MITMPROXY_WEB_PORT",
                            "MITMPROXY_WEB_HOST", "MITMPROXY_WEB_PASSWORD")),
    ("sslsplit",           ("SSLSPLIT_PORT", "SSLSPLIT_PCAP_DIR")),
    ("certmitm",           ("CERTMITM_PATH", "CERTMITM_PORT",
                            "CERTMITM_WORKDIR", "CERTMITM_VERBOSE",
                            "CERTMITM_SHOW_DATA", "CERTMITM_TEST_DOMAINS",
                            "CERTMITM_PASSTHROUGH_DOMAINS")),
    ("sslstrip",           ("SSLSTRIP_PORT", "SSLSTRIP_FAKE_SERVER_PORT",
                            "SSLSTRIP_FAKE_SERVER_SCRIPT",
                            "SSLSTRIP_TEST_DOMAINS",
                            "SSLSTRIP_PASSTHROUGH_DOMAINS")),
    ("intercept",          ("INTERCEPT_PORT", "INTERCEPT_FAKE_SERVER_PORT",
                            "INTERCEPT_FAKE_SERVER_SCRIPT",
                            "INTERCEPT_DOMAINS",
                            "INTERCEPT_PASSTHROUGH_DOMAINS")),
    ("delorean",           ("DELOREAN_PATH",)),
    ("Packet capture",     ("TCPDUMP_IFACE", "TCPDUMP_OPTIONS", "TCPDUMP_DIR")),
)

_SECRETS = frozenset({"WIFI_PASSWORD", "MITMPROXY_WEB_PASSWORD"})


def _settings_snapshot() -> tuple[object, str]:
    """Off-thread fetch — load + render mitm.conf as Rich markup."""
    snap = snapshot_state()
    conf_path = REPO_ROOT / "mitm.conf"
    if not conf_path.is_file():
        return snap, (f"[red]mitm.conf not found at {conf_path}[/]\n"
                      "Copy mitm.conf.example and edit, then restart "
                      "mitmbeast.")
    try:
        from mitmbeast.core.config import load_config
        cfg = load_config(conf_path)
    except Exception as e:  # noqa: BLE001 — surface load errors verbatim
        return snap, f"[red]mitm.conf failed validation:[/]\n{e}"

    lines: list[str] = [f"[dim]Path: {conf_path}[/]", ""]
    for group_name, keys in _SETTINGS_GROUPS:
        lines.append(f"[bold cyan]{group_name}[/]")
        for key in keys:
            value = getattr(cfg, key, "(missing)")
            display = "[dim]●●●●●●●●[/]" if key in _SECRETS and value else str(value)
            lines.append(f"  [yellow]{key:<35}[/] {display}")
        lines.append("")
    lines.append("[dim]To edit: stop mitmbeast, edit mitm.conf, restart. "
                 "(In-TUI editing comes later.)[/]")
    return snap, "\n".join(lines)


class SettingsScreen(Vertical):
    """Read-only mitm.conf viewer."""

    def compose(self) -> ComposeResult:
        yield StatusBar(id="status_text")
        with VerticalScroll(id="settings_pane"):
            yield Static(id="settings_text", markup=True)

    async def on_mount(self) -> None:
        await self._refresh()
        # Settings rarely change while running; poll slowly.
        self.set_interval(10.0, self._refresh)

    async def _refresh(self) -> None:
        snap, text = await asyncio.to_thread(_settings_snapshot)
        self.query_one("#status_text", StatusBar).update_from(snap)
        self.query_one("#settings_text", Static).update(text)


# ----------------------------------------------------------------------
# Proxy screen — live HTTP flows from mitmproxy mode (P2.10b/P2.23)
# ----------------------------------------------------------------------

class ProxyScreen(Vertical):
    """Live HTTP flow table fed by ``http_flow`` events.

    Active when ``mitmbeast up -m mitmproxy`` is running — the
    mitmproxy-flow-logger.py addon writes one NDJSON line per
    response, and ``core.event_sources.mitmproxy_flow_source`` tails
    that file, publishing ``http_flow`` events. We subscribe and
    insert rows.
    """

    MAX_ROWS = 500   # keep the table bounded so the TUI stays snappy

    def compose(self) -> ComposeResult:
        yield StatusBar(id="status_text")
        with Horizontal(id="dashboard_actions"):
            yield Button("Clear", id="btn_proxy_clear")
            yield Static(id="proxy_count", expand=True)
        yield DataTable(id="proxy_table", zebra_stripes=True)

    async def on_mount(self) -> None:
        table = self.query_one("#proxy_table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Time", "Client", "Method", "Status",
                          "Host", "URL", "Size")
        await self._refresh()
        self.set_interval(2.0, self._refresh)
        self._unsub = self.app.bus.subscribe(self._on_event)  # type: ignore[attr-defined]
        self._count = 0

    def on_unmount(self) -> None:
        if hasattr(self, "_unsub"):
            self._unsub()

    async def _refresh(self) -> None:
        snap = await asyncio.to_thread(snapshot_state)
        self.query_one("#status_text", StatusBar).update_from(snap)

    def _on_event(self, event) -> None:  # type: ignore[no-untyped-def]
        if event.kind != "http_flow":
            return
        d = event.data
        # Keep rows bounded — prune from the top once we hit MAX_ROWS.
        table = self.query_one("#proxy_table", DataTable)
        if table.row_count >= self.MAX_ROWS:
            keys = list(table.rows)
            if keys:
                table.remove_row(keys[0])
        ts = d.get("ts", "")[-12:-3]  # take HH:MM:SS.fff portion
        status = d.get("status")
        if isinstance(status, int):
            color = ("[green]" if 200 <= status < 300
                     else "[yellow]" if 300 <= status < 400
                     else "[red]" if status >= 400
                     else "")
            status_str = f"{color}{status}[/]" if color else str(status)
        else:
            status_str = "-"
        size = int(d.get("response_size") or 0)
        size_str = (f"{size}B" if size < 1024
                    else f"{size / 1024:.1f}KB" if size < 1024 * 1024
                    else f"{size / 1024 / 1024:.1f}MB")
        url = d.get("url", "")
        if len(url) > 70:
            url = url[:67] + "…"
        table.add_row(
            ts,
            d.get("client") or "-",
            d.get("method", "?"),
            status_str,
            d.get("host", "-"),
            url,
            size_str,
        )
        self._count += 1
        self.query_one("#proxy_count", Static).update(
            f"[dim]flows captured: {self._count}[/]"
        )

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_proxy_clear":
            self.query_one("#proxy_table", DataTable).clear()
            self._count = 0
            self.query_one("#proxy_count", Static).update(
                "[dim]flows captured: 0[/]"
            )
