"""Functional pilot tests for the Textual TUI.

These tests don't compare visual snapshots — they pin down the app's
structural invariants: every tab mounts without crashing, expected
widget IDs are present, key bindings switch tabs. That catches the
regressions that matter most for a TUI (broken ``compose()``, missing
widget IDs, dead bindings) without introducing a snapshot baseline
that needs human re-verification each time the layout changes.

System-touching probes (``snapshot_state``, ``start_event_sources``,
journalctl, dnsmasq/hostapd readers) are stubbed so the tests run on
any host without root.
"""
from __future__ import annotations

from typing import Any

import pytest
from textual.widgets import (
    Button,
    DataTable,
    Input,
    RichLog,
    Select,
    Static,
    Switch,
    TabbedContent,
)

from mitmbeast.tui.app import MitmBeastApp
from mitmbeast.tui.state import RouterSnapshot

_FAKE_SNAPSHOT = RouterSnapshot(
    is_root=False,
    wan_iface="eth0",
    wan_addresses=(),
    bridge_iface="br0",
    bridge_addresses=(),
    wifi_iface="wlan0",
    dnsmasq_running=False,
    hostapd_running=False,
    mitm_chains_present=False,
    masquerade_packets=0,
    lease_count=0,
    station_count=0,
    mode="down",
)


@pytest.fixture(autouse=True)
def _stub_system(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace every system-touching call the TUI makes on mount."""
    monkeypatch.setattr(
        "mitmbeast.tui.screens.snapshot_state", lambda: _FAKE_SNAPSHOT,
    )
    monkeypatch.setattr(
        "mitmbeast.tui.state.snapshot_state", lambda: _FAKE_SNAPSHOT,
    )
    # No-op event sources — would otherwise tail journalctl forever.
    monkeypatch.setattr(
        "mitmbeast.tui.app.start_event_sources",
        lambda bus, stop: [],
    )
    # Daemon readers.
    monkeypatch.setattr(
        "mitmbeast.tui.screens.dnsmasq.read_leases", lambda: [],
    )
    monkeypatch.setattr(
        "mitmbeast.tui.screens.hostapd.list_stations", lambda iface: [],
    )

    # LogsScreen runs ``journalctl`` via subprocess. Stub the whole call
    # so tests don't depend on systemd / journalctl being present.
    class _StubProc:
        stdout = ""
        returncode = 0

    monkeypatch.setattr(
        "mitmbeast.tui.screens.subprocess.run",
        lambda *a, **kw: _StubProc(),
    )


# ----- helpers --------------------------------------------------------

async def _switch_tab(pilot: Any, key: str, expected_tab_id: str) -> None:
    """Press the binding key and assert the active tab changed."""
    await pilot.press(key)
    await pilot.pause()
    tabs = pilot.app.query_one(TabbedContent)
    assert tabs.active == expected_tab_id, (
        f"after pressing {key!r}: expected active tab {expected_tab_id!r}, "
        f"got {tabs.active!r}"
    )


# ----- tests ----------------------------------------------------------

async def test_app_starts_and_compose_succeeds() -> None:
    """The app must mount cleanly with all 7 tabs in the expected order."""
    app = MitmBeastApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        tabs = pilot.app.query_one(TabbedContent)
        # Default tab is dashboard
        assert tabs.active == "dashboard"
        # All 7 tab IDs are present
        ids = {p.id for p in tabs.query("TabPane")}
        assert ids == {
            "dashboard", "clients", "spoofs",
            "sessions", "proxy", "logs", "settings",
        }


async def test_dashboard_widgets_present() -> None:
    """Dashboard must expose mode select, up/down/refresh/clear buttons,
    capture toggle, and the RichLog event feed (Bug #4 fix)."""
    app = MitmBeastApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        # Mode dropdown
        select = pilot.app.query_one("#mode_select", Select)
        # Should default to "none"
        assert str(select.value) == "none"
        # Buttons
        for btn_id in ("btn_up", "btn_down", "btn_refresh", "btn_clear_log"):
            pilot.app.query_one(f"#{btn_id}", Button)
        # Capture toggle (B3.6 follow-up — packet capture from the TUI)
        toggle = pilot.app.query_one("#capture_toggle", Switch)
        assert toggle.value is False    # off by default
        # RichLog (Bug #4 fix — replaces 12-line Static)
        log = pilot.app.query_one("#dashboard_log", RichLog)
        assert log.max_lines == 5000


async def test_tab_bindings_switch_tabs() -> None:
    """Each single-letter binding must switch to its tab."""
    app = MitmBeastApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        for key, tab_id in [
            ("c", "clients"),
            ("n", "spoofs"),
            ("s", "sessions"),
            ("p", "proxy"),
            ("l", "logs"),
            ("t", "settings"),
            ("d", "dashboard"),
        ]:
            await _switch_tab(pilot, key, tab_id)


async def test_clients_screen_table_columns() -> None:
    """Clients screen DataTable carries the documented columns."""
    app = MitmBeastApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("c")
        await pilot.pause()
        table = pilot.app.query_one("#clients_table", DataTable)
        labels = [str(c.label) for c in table.columns.values()]
        assert labels == [
            "MAC", "IP", "Hostname",
            "Signal dBm", "Wi-Fi RX", "Wi-Fi TX",
            "Lease expires",
        ]


async def test_spoofs_screen_form_present() -> None:
    """Spoofs screen exposes the add-entry form + table."""
    app = MitmBeastApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("n")
        await pilot.pause()
        pilot.app.query_one("#spoof_domain", Input)
        pilot.app.query_one("#spoof_ip", Input)
        pilot.app.query_one("#btn_add_spoof", Button)
        pilot.app.query_one("#spoofs_table", DataTable)


async def test_proxy_screen_table_columns() -> None:
    """Proxy screen DataTable carries the live-flow columns."""
    app = MitmBeastApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("p")
        await pilot.pause()
        table = pilot.app.query_one("#proxy_table", DataTable)
        labels = [str(c.label) for c in table.columns.values()]
        assert labels == [
            "Time", "Client", "Method", "Status", "Host", "URL", "Size",
        ]


async def test_settings_screen_renders_text() -> None:
    """Settings screen has the read-only viewer Static."""
    app = MitmBeastApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("t")
        await pilot.pause()
        pilot.app.query_one("#settings_text", Static)


async def test_sessions_screen_table_columns() -> None:
    """Sessions screen DataTable carries the documented columns."""
    app = MitmBeastApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("s")
        await pilot.pause()
        table = pilot.app.query_one("#sessions_table", DataTable)
        labels = [str(c.label) for c in table.columns.values()]
        assert labels == ["Kind", "Path", "Size", "Modified"]
