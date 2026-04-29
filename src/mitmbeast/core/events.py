"""Async pub/sub event bus.

Designed for the case the TUI lives in: one asyncio loop on the main
thread (Textual), and one or more event sources that may publish from
worker threads (e.g. mitmproxy's in-process DumpMaster, journalctl
tailers, periodic poll tasks).

Usage::

    bus = EventBus()
    bus.attach_loop(asyncio.get_running_loop())

    async def handler(ev: Event) -> None:
        print(ev.kind, ev.data)

    unsub = bus.subscribe(handler)
    bus.publish(Event.now(kind="dhcp_lease",
                          data={"mac": "aa:bb:...", "ip": "192.168.200.65"}))
    # ... later
    unsub()

:meth:`publish` is **thread-safe** — workers can call it from any
thread; the bus marshals dispatch back onto the attached loop via
``loop.call_soon_threadsafe``. Handlers run on the loop, so they can
update Textual widgets directly.

Sync handlers run inline; async (``coroutine`` returning) handlers
get scheduled via :func:`asyncio.ensure_future`. Handler exceptions
are logged and swallowed so a misbehaving subscriber can't take down
the rest of the system.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

__all__ = [
    "Event",
    "EventBus",
    "EventHandler",
    "Subscription",
]

logger = logging.getLogger("mitmbeast.events")

EventHandler = Callable[["Event"], "None | Awaitable[None]"]
Subscription = Callable[[], None]   # call to unsubscribe


@dataclass(frozen=True, slots=True)
class Event:
    """One event flowing through the bus.

    ``kind`` is a short string ("dhcp_lease", "sta_connected", "http_request",
    "http_response", "iptables_counters", …) used by subscribers to filter.
    ``data`` is a free-form dict; we intentionally don't sub-class per-kind
    so adding a new event source doesn't require touching consumers that
    don't care.
    """

    kind: str
    timestamp: datetime
    data: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def now(cls, *, kind: str, data: dict[str, Any] | None = None) -> Event:
        return cls(kind=kind, timestamp=datetime.now(UTC),
                   data=dict(data) if data else {})


class EventBus:
    """Thread-safe pub/sub backed by an asyncio loop."""

    def __init__(self) -> None:
        self._subscribers: list[EventHandler] = []
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    # ----- lifecycle -----

    def attach_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Bind the bus to a running asyncio loop.

        Must be called once before publishing from non-loop threads
        (otherwise we have nowhere to dispatch to).
        """
        self._loop = loop

    @property
    def loop(self) -> asyncio.AbstractEventLoop | None:
        return self._loop

    # ----- subscribers -----

    def subscribe(self, handler: EventHandler) -> Subscription:
        """Register ``handler`` to receive every event. Returns an unsubscribe fn."""
        with self._lock:
            self._subscribers.append(handler)

        def _unsubscribe() -> None:
            with self._lock:
                if handler in self._subscribers:
                    self._subscribers.remove(handler)

        return _unsubscribe

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    # ----- publish -----

    def publish(self, event: Event) -> None:
        """Publish ``event``. Safe from any thread.

        If a loop is attached and we're not on it, marshal the dispatch
        via ``call_soon_threadsafe``. Otherwise dispatch immediately
        (suitable for tests with no loop, or publishers already on the
        loop's thread).
        """
        loop = self._loop
        if loop is not None and loop.is_running() and not _on_loop(loop):
            loop.call_soon_threadsafe(self._dispatch, event)
        else:
            self._dispatch(event)

    def _dispatch(self, event: Event) -> None:
        with self._lock:
            handlers = list(self._subscribers)
        for handler in handlers:
            try:
                result = handler(event)
            except Exception:  # noqa: BLE001 — never let one handler kill the rest
                logger.exception("event handler raised on %r", event.kind)
                continue
            if asyncio.iscoroutine(result):
                # We are guaranteed to be on the loop here (publish() routed
                # us via call_soon_threadsafe); ensure_future schedules it.
                asyncio.ensure_future(result)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _on_loop(loop: asyncio.AbstractEventLoop) -> bool:
    """True if the calling thread is the one running ``loop``."""
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        return False
    return running is loop
