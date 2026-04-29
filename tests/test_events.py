"""Tests for ``mitmbeast.core.events``."""
from __future__ import annotations

import asyncio
import threading

import pytest

from mitmbeast.core.events import Event, EventBus


def test_event_now_sets_kind_and_data() -> None:
    ev = Event.now(kind="x", data={"a": 1})
    assert ev.kind == "x"
    assert ev.data == {"a": 1}


def test_event_is_frozen() -> None:
    ev = Event.now(kind="x")
    with pytest.raises((AttributeError, Exception)):
        ev.kind = "y"  # type: ignore[misc]


def test_subscribe_and_publish_sync_handler() -> None:
    bus = EventBus()
    received: list[Event] = []
    bus.subscribe(lambda ev: received.append(ev))
    bus.publish(Event.now(kind="hello"))
    assert len(received) == 1
    assert received[0].kind == "hello"


def test_unsubscribe_stops_delivery() -> None:
    bus = EventBus()
    received: list[Event] = []
    unsub = bus.subscribe(lambda ev: received.append(ev))
    bus.publish(Event.now(kind="a"))
    unsub()
    bus.publish(Event.now(kind="b"))
    assert [ev.kind for ev in received] == ["a"]


def test_handler_exception_does_not_kill_others() -> None:
    bus = EventBus()
    seen: list[str] = []

    def bad(_ev: Event) -> None:
        raise RuntimeError("boom")

    bus.subscribe(bad)
    bus.subscribe(lambda ev: seen.append(ev.kind))
    bus.publish(Event.now(kind="zzz"))
    assert seen == ["zzz"]  # the second handler still ran


def test_subscriber_count() -> None:
    bus = EventBus()
    assert bus.subscriber_count == 0
    u1 = bus.subscribe(lambda _e: None)
    u2 = bus.subscribe(lambda _e: None)
    assert bus.subscriber_count == 2
    u1()
    assert bus.subscriber_count == 1
    u2()
    assert bus.subscriber_count == 0


@pytest.mark.asyncio
async def test_async_handler_scheduled() -> None:
    bus = EventBus()
    bus.attach_loop(asyncio.get_running_loop())
    received: list[Event] = []

    async def async_handler(ev: Event) -> None:
        received.append(ev)

    bus.subscribe(async_handler)
    bus.publish(Event.now(kind="async-ev"))
    # Yield twice so the ensure_future-scheduled coroutine actually runs
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert len(received) == 1


@pytest.mark.asyncio
async def test_publish_from_thread_dispatches_on_loop() -> None:
    bus = EventBus()
    loop = asyncio.get_running_loop()
    bus.attach_loop(loop)
    received: list[tuple[str, int]] = []

    def handler(ev: Event) -> None:
        # Record which thread we ran on so the test can assert.
        received.append((ev.kind, threading.get_ident()))

    bus.subscribe(handler)
    main_thread_id = threading.get_ident()

    def worker() -> None:
        bus.publish(Event.now(kind="from-thread"))

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    # Drain the loop so call_soon_threadsafe completes.
    await asyncio.sleep(0)
    assert len(received) == 1
    kind, dispatched_thread = received[0]
    assert kind == "from-thread"
    # Handler must have run on the *main* thread (the one running the loop)
    assert dispatched_thread == main_thread_id
