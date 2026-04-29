"""Integration tests for ``mitmbeast.core.bridge``.

Need root + dummy/bridge link types. Skip otherwise.
"""
from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError

from mitmbeast.core.bridge import (
    bridge_add_slave,
    bridge_create,
    bridge_destroy,
    bridge_remove_slave,
    bridge_slaves,
)
from mitmbeast.core.netif import iface_exists

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="bridge ops require root; run inside the Kali VM",
)


def _short_name(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:6]}"


@pytest.fixture
def bridge_name() -> Iterator[str]:
    name = _short_name("mb")
    bridge_create(name)
    try:
        yield name
    finally:
        bridge_destroy(name)


@pytest.fixture
def dummy_iface() -> Iterator[str]:
    name = _short_name("md")
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


def test_create_and_destroy_idempotent(bridge_name: str) -> None:
    assert iface_exists(bridge_name)
    # Re-create is a no-op
    bridge_create(bridge_name)
    assert iface_exists(bridge_name)
    # Destroy then re-destroy
    bridge_destroy(bridge_name)
    assert not iface_exists(bridge_name)
    bridge_destroy(bridge_name)  # no-op


def test_destroy_missing_bridge_is_noop() -> None:
    bridge_destroy("definitely-not-a-bridge-zzz")  # must not raise


def test_attach_and_detach_slave(bridge_name: str, dummy_iface: str) -> None:
    assert bridge_slaves(bridge_name) == []

    bridge_add_slave(bridge_name, dummy_iface)
    assert bridge_slaves(bridge_name) == [dummy_iface]

    # Idempotent re-attach
    bridge_add_slave(bridge_name, dummy_iface)
    assert bridge_slaves(bridge_name) == [dummy_iface]

    bridge_remove_slave(dummy_iface)
    assert bridge_slaves(bridge_name) == []

    # Idempotent re-detach
    bridge_remove_slave(dummy_iface)
    assert bridge_slaves(bridge_name) == []


def test_attach_to_missing_bridge_raises(dummy_iface: str) -> None:
    from mitmbeast.core.netif import NetifError
    with pytest.raises(NetifError, match="bridge add_slave"):
        bridge_add_slave("nope-zzz", dummy_iface)
