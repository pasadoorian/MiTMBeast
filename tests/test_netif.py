"""Tests for ``mitmbeast.core.netif``.

Read-only paths are exercised against the loopback interface (``lo``)
which exists on every Linux box and answers our queries without root.
Write operations are not unit-tested here — they need root and a real
interface; integration testing for those happens on the Kali VM.
"""
from __future__ import annotations

from ipaddress import IPv4Interface

import pytest

from mitmbeast.core.netif import (
    AddressInfo,
    iface_addresses,
    iface_exists,
    iface_index,
    iface_is_up,
)


def test_loopback_exists() -> None:
    assert iface_exists("lo")


def test_loopback_index_is_one() -> None:
    # lo is always interface 1 on Linux. If this ever fails, something
    # truly weird is happening (or we're in a netns without lo).
    assert iface_index("lo") == 1


def test_missing_iface_returns_none() -> None:
    assert iface_index("definitely-not-an-interface-zzz") is None
    assert not iface_exists("definitely-not-an-interface-zzz")


def test_loopback_is_up() -> None:
    # Every Linux system has lo up. If it isn't, you have bigger problems.
    assert iface_is_up("lo")


def test_missing_iface_is_not_up() -> None:
    assert not iface_is_up("definitely-not-an-interface-zzz")


def test_loopback_has_127_0_0_1() -> None:
    addrs = iface_addresses("lo")
    ips = {str(a.ip) for a in addrs}
    assert "127.0.0.1" in ips


def test_address_info_immutable() -> None:
    a = AddressInfo(interface=IPv4Interface("10.0.0.1/24"))
    assert a.ip == IPv4Interface("10.0.0.1/24").ip
    assert a.prefixlen == 24
    with pytest.raises((AttributeError, Exception)):
        a.interface = IPv4Interface("1.2.3.4/8")  # type: ignore[misc]


def test_addresses_for_missing_iface_is_empty() -> None:
    assert iface_addresses("definitely-not-an-interface-zzz") == []
