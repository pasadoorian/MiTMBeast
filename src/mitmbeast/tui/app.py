"""Top-level Textual application.

The MVP exposes three tabs (Dashboard, Clients, DNS Spoofs). All
update by polling — Phase 2c will replace the polling with an event
bus subscription. Screens themselves don't know which strategy is in
use; the swap is internal.
"""
from __future__ import annotations

from textual.app import App, ComposeResult
from textual.widgets import Footer, Header, TabbedContent, TabPane

from mitmbeast import __version__
from mitmbeast.tui.screens import (
    ClientsScreen,
    DashboardScreen,
    LogsScreen,
    SessionsScreen,
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
    ]

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
        yield Footer()

    def action_show_tab(self, tab_id: str) -> None:
        self.query_one(TabbedContent).active = tab_id


if __name__ == "__main__":
    MitmBeastApp().run()
