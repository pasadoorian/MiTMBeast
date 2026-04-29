"""Event sources — async tasks that publish to the :class:`EventBus`.

Each source is an async function that runs as a background task for
the lifetime of the TUI / daemon and publishes events as they
happen. The TUI's :class:`MitmBeastApp` owns one of each.

Currently shipping:

* :func:`dnsmasq_dhcp_source` — tails ``journalctl -f -t dnsmasq-dhcp``
  and emits ``dhcp_lease`` / ``dhcp_request`` / ``dhcp_release`` events
* :func:`hostapd_event_source` — tails ``journalctl -f -t hostapd`` and
  emits ``sta_connected`` / ``sta_disconnected`` events

Sources are best-effort: if journalctl isn't available, or its child
exits, the task simply returns without raising. Lets the TUI continue
to function on systems without systemd-journald.

Each source accepts a ``stop: asyncio.Event``. Setting the event
causes the source to terminate its child subprocess and exit.
"""
from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Iterable

from mitmbeast.core.events import Event, EventBus

__all__ = [
    "dnsmasq_dhcp_source",
    "hostapd_event_source",
    "start_event_sources",
]

logger = logging.getLogger("mitmbeast.events")


# ----------------------------------------------------------------------
# dnsmasq DHCP
# ----------------------------------------------------------------------

# dnsmasq logs to syslog with identifier "dnsmasq-dhcp". Sample lines:
#   "1916534182 DHCPREQUEST(br0) 192.168.200.65 f2:00:dc:cd:96:3a"
#   "1916534182 DHCPACK(br0) 192.168.200.65 f2:00:dc:cd:96:3a Paul-s-iPhone-16"
#   "1916534182 DHCPRELEASE(br0) 192.168.200.65 ..."
_DHCP_RE = re.compile(
    r"DHCP(?P<op>ACK|REQUEST|RELEASE|NAK|OFFER)"
    r"\((?P<iface>[^)]+)\)\s+"
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<mac>[0-9a-fA-F:]{17})"
    r"(?:\s+(?P<hostname>\S+))?"
)


async def dnsmasq_dhcp_source(bus: EventBus, stop: asyncio.Event) -> None:
    """Background task: tail dnsmasq's DHCP logs, publish events."""
    await _journalctl_source(
        bus, stop,
        identifier="dnsmasq-dhcp",
        parser=_parse_dhcp_line,
    )


def _parse_dhcp_line(line: str) -> Event | None:
    m = _DHCP_RE.search(line)
    if not m:
        return None
    op = m.group("op").lower()
    kind = {
        "ack":     "dhcp_lease",
        "request": "dhcp_request",
        "release": "dhcp_release",
        "nak":     "dhcp_nak",
        "offer":   "dhcp_offer",
    }.get(op, f"dhcp_{op}")
    return Event.now(kind=kind, data={
        "iface":    m.group("iface"),
        "ip":       m.group("ip"),
        "mac":      m.group("mac").lower(),
        "hostname": m.group("hostname"),
    })


# ----------------------------------------------------------------------
# hostapd association events
# ----------------------------------------------------------------------

# hostapd logs e.g.
#   "wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated (aid 1)"
#   "wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: deauthenticated due to local deauth request"
_HOSTAPD_RE = re.compile(
    r"(?P<iface>\S+):\s+STA\s+(?P<mac>[0-9a-fA-F:]{17})\s+IEEE 802\.11:\s+"
    r"(?P<event>associated|deauthenticated|disassociated)"
)


async def hostapd_event_source(bus: EventBus, stop: asyncio.Event) -> None:
    """Background task: tail hostapd logs, publish association events."""
    await _journalctl_source(
        bus, stop,
        identifier="hostapd",
        parser=_parse_hostapd_line,
    )


def _parse_hostapd_line(line: str) -> Event | None:
    m = _HOSTAPD_RE.search(line)
    if not m:
        return None
    ev = m.group("event")
    kind = "sta_connected" if ev == "associated" else "sta_disconnected"
    return Event.now(kind=kind, data={
        "iface":    m.group("iface"),
        "mac":      m.group("mac").lower(),
        "raw":      line,
    })


# ----------------------------------------------------------------------
# Common journalctl plumbing
# ----------------------------------------------------------------------

async def _journalctl_source(
    bus: EventBus,
    stop: asyncio.Event,
    *,
    identifier: str,
    parser,  # type: ignore[no-untyped-def]
) -> None:
    """Run ``journalctl -f -t <identifier>``, parse each line, publish events.

    ``parser`` is a function ``(str) -> Event | None``; lines that
    don't match are silently dropped. Exits cleanly when ``stop`` is
    set or journalctl exits.
    """
    cmd = [
        "journalctl", "-f", "-q", "--no-pager",
        "-n", "0",            # don't replay history; only new lines
        "-t", identifier,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except FileNotFoundError:
        logger.warning("journalctl not found; %s event source disabled", identifier)
        return

    assert proc.stdout is not None
    try:
        while not stop.is_set():
            try:
                raw = await asyncio.wait_for(proc.stdout.readline(), timeout=0.5)
            except TimeoutError:
                continue
            if not raw:
                break  # EOF — journalctl exited
            line = raw.decode("utf-8", errors="replace").rstrip()
            try:
                event = parser(line)
            except Exception:  # noqa: BLE001 — malformed line, keep going
                logger.exception("event parser raised on line: %r", line)
                continue
            if event is not None:
                bus.publish(event)
    finally:
        if proc.returncode is None:
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except TimeoutError:
                proc.kill()
                await proc.wait()


# ----------------------------------------------------------------------
# Convenience: spawn all sources for the TUI
# ----------------------------------------------------------------------

def start_event_sources(bus: EventBus, stop: asyncio.Event) -> Iterable[asyncio.Task]:
    """Spawn every default event source as a background task.

    Returns the list of tasks so the caller can await them on shutdown.
    """
    return [
        asyncio.create_task(dnsmasq_dhcp_source(bus, stop),
                            name="event-source:dnsmasq-dhcp"),
        asyncio.create_task(hostapd_event_source(bus, stop),
                            name="event-source:hostapd"),
    ]
