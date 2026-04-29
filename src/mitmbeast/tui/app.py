"""Top-level Textual application.

Tabs: Dashboard, Clients, DNS Spoofs, Sessions, Logs, Settings.

The App owns one :class:`mitmbeast.core.events.EventBus` and starts
the default event sources (dnsmasq DHCP, hostapd associations) on
mount. Screens that want live updates ``subscribe`` on mount and
unsubscribe on unmount; the bus is exposed via ``self.app.bus`` from
inside any screen / widget.
"""
from __future__ import annotations

import asyncio

from textual.app import App, ComposeResult
from textual.widgets import Footer, Header, TabbedContent, TabPane

from mitmbeast import __version__
from mitmbeast.core.event_sources import start_event_sources
from mitmbeast.core.events import EventBus
from mitmbeast.tui.screens import (
    ClientsScreen,
    DashboardScreen,
    LogsScreen,
    SessionsScreen,
    SettingsScreen,
    SpoofsScreen,
)


class MitmBeastApp(App):
    """MITM Beast TUI — v2.0-alpha minimum-viable interface."""

    CSS_PATH = "app.tcss"
    TITLE = "MITM Beast"
    SUB_TITLE = f"v{__version__}"

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("d", "show_tab('dashboard')", "Dashboard"),
        ("c", "show_tab('clients')", "Clients"),
        ("n", "show_tab('spoofs')", "DNS"),
        ("s", "show_tab('sessions')", "Sessions"),
        ("l", "show_tab('logs')", "Logs"),
        ("t", "show_tab('settings')", "Settings"),
    ]

    bus: EventBus

    def __init__(self) -> None:
        super().__init__()
        self.bus = EventBus()
        self._event_source_stop = asyncio.Event()
        self._event_source_tasks: list[asyncio.Task] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial="dashboard"):
            with TabPane("Dashboard", id="dashboard"):
                yield DashboardScreen()
            with TabPane("Clients", id="clients"):
                yield ClientsScreen()
            with TabPane("DNS Spoofs", id="spoofs"):
                yield SpoofsScreen()
            with TabPane("Sessions", id="sessions"):
                yield SessionsScreen()
            with TabPane("Logs", id="logs"):
                yield LogsScreen()
            with TabPane("Settings", id="settings"):
                yield SettingsScreen()
        yield Footer()

    async def on_mount(self) -> None:
        # Bind the bus to the app's loop so cross-thread publishers
        # marshal correctly.
        self.bus.attach_loop(asyncio.get_running_loop())
        # Start the journalctl-tailing event sources in the background.
        self._event_source_tasks = list(
            start_event_sources(self.bus, self._event_source_stop)
        )

    async def on_unmount(self) -> None:
        self._event_source_stop.set()
        # Give sources up to a second to wrap up
        for t in self._event_source_tasks:
            try:
                await asyncio.wait_for(t, timeout=1.0)
            except (TimeoutError, asyncio.CancelledError):
                t.cancel()

    def action_show_tab(self, tab_id: str) -> None:
        self.query_one(TabbedContent).active = tab_id


if __name__ == "__main__":
    MitmBeastApp().run()
