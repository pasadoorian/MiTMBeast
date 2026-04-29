"""Integration tests for ``mitmbeast.core.netif`` write operations.

These tests need ``CAP_NET_ADMIN`` and a kernel that supports the
``dummy`` link type (any modern Linux). They are skipped automatically
when running as a non-root user, so the unit-test suite can be run on
any developer machine. CI runs the privileged tests inside the Kali VM.

Each test creates and tears down its own dummy interface so the host's
real network is never touched.
"""
from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError

from mitmbeast.core.netif import (
    iface_add_address,
    iface_addresses,
    iface_exists,
    iface_flush_addresses,
    iface_is_up,
    iface_set_down,
    iface_set_up,
)

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="netif write ops require root; run inside the Kali VM",
)


@pytest.fixture
def dummy_iface() -> Iterator[str]:
    """Create a unique dummy interface, yield its name, remove it after."""
    name = f"mitmt{uuid.uuid4().hex[:6]}"  # max 15 chars per IFNAMSIZ
    with IPRoute() as ipr:
        ipr.link("add", ifname=name, kind="dummy")
    try:
        yield name
    finally:
        with IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=name)
            if idx:
                try:
                    ipr.link("del", index=idx[0])
                except NetlinkError:  # noqa: S110 — best-effort cleanup
                    pass


def test_create_and_query_dummy(dummy_iface: str) -> None:
    assert iface_exists(dummy_iface)
    assert not iface_is_up(dummy_iface)


def test_set_up_then_down(dummy_iface: str) -> None:
    iface_set_up(dummy_iface)
    assert iface_is_up(dummy_iface)
    iface_set_down(dummy_iface)
    assert not iface_is_up(dummy_iface)


def test_add_and_flush_addresses(dummy_iface: str) -> None:
    iface_set_up(dummy_iface)

    # Empty to start
    assert iface_addresses(dummy_iface) == []

    iface_add_address(dummy_iface, "10.255.0.1/24")
    addrs = iface_addresses(dummy_iface)
    ips = {str(a.ip) for a in addrs}
    assert "10.255.0.1" in ips

    # Idempotent re-add
    iface_add_address(dummy_iface, "10.255.0.1/24")
    assert {str(a.ip) for a in iface_addresses(dummy_iface)} == ips

    iface_flush_addresses(dummy_iface)
    assert iface_addresses(dummy_iface) == []


def test_multiple_addresses(dummy_iface: str) -> None:
    iface_set_up(dummy_iface)
    iface_add_address(dummy_iface, "10.255.1.1/24")
    iface_add_address(dummy_iface, "10.255.2.1/24")

    ips = {str(a.ip) for a in iface_addresses(dummy_iface)}
    assert {"10.255.1.1", "10.255.2.1"} <= ips

    iface_flush_addresses(dummy_iface)
    assert iface_addresses(dummy_iface) == []


def test_set_down_on_missing_iface_is_noop() -> None:
    # Should not raise — matches mitm.sh's `ifconfig X down 2>/dev/null || true`
    iface_set_down("nope-not-here-zzz")
