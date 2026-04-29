"""Linux bridge management via pyroute2 netlink.

Replaces the ``brctl`` shell-outs in ``mitm.sh``. ``brctl`` itself is
deprecated upstream (``bridge`` from iproute2 is the modern user-space
tool); we skip both and talk to the kernel directly via netlink.

Operations are all idempotent — creating an already-existing bridge,
adding a slave that's already attached, or destroying a bridge that
doesn't exist all silently succeed. This matches the v1.1 bash
behavior of ``brctl ... 2>/dev/null || true``.
"""
from __future__ import annotations

from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError

from mitmbeast.core.netif import NetifError, iface_index

__all__ = [
    "bridge_add_slave",
    "bridge_create",
    "bridge_destroy",
    "bridge_remove_slave",
    "bridge_slaves",
]


def bridge_create(name: str) -> None:
    """Create a Linux bridge. No-op if it already exists."""
    if iface_index(name) is not None:
        return
    with IPRoute() as ipr:
        try:
            ipr.link("add", ifname=name, kind="bridge")
        except NetlinkError as e:
            # 17 = EEXIST (race)
            if e.code == 17:
                return
            raise NetifError("bridge create", ifname=name, cause=e) from e


def bridge_destroy(name: str) -> None:
    """Destroy a Linux bridge. No-op if missing."""
    idx = iface_index(name)
    if idx is None:
        return
    with IPRoute() as ipr:
        try:
            ipr.link("del", index=idx)
        except NetlinkError as e:
            # 19 = ENODEV (race: someone else removed it)
            if e.code == 19:
                return
            raise NetifError("bridge destroy", ifname=name, cause=e) from e


def bridge_add_slave(bridge: str, slave: str) -> None:
    """Attach ``slave`` to ``bridge``. Idempotent."""
    bridge_idx = iface_index(bridge)
    slave_idx = iface_index(slave)
    if bridge_idx is None:
        raise NetifError("bridge add_slave", ifname=bridge,
                         cause=FileNotFoundError(bridge))
    if slave_idx is None:
        raise NetifError("bridge add_slave", ifname=slave,
                         cause=FileNotFoundError(slave))
    # Already attached?
    if _link_master(slave_idx) == bridge_idx:
        return
    with IPRoute() as ipr:
        try:
            ipr.link("set", index=slave_idx, master=bridge_idx)
        except NetlinkError as e:
            raise NetifError("bridge add_slave", ifname=slave, cause=e) from e


def bridge_remove_slave(slave: str) -> None:
    """Detach ``slave`` from whatever bridge it's currently part of."""
    slave_idx = iface_index(slave)
    if slave_idx is None:
        return
    if _link_master(slave_idx) is None:
        return
    with IPRoute() as ipr:
        try:
            # master=0 means "no master"
            ipr.link("set", index=slave_idx, master=0)
        except NetlinkError as e:
            raise NetifError("bridge remove_slave", ifname=slave, cause=e) from e


def bridge_slaves(bridge: str) -> list[str]:
    """Return the names of interfaces enslaved to ``bridge``."""
    bridge_idx = iface_index(bridge)
    if bridge_idx is None:
        return []
    with IPRoute() as ipr:
        try:
            links = ipr.get_links()
        except NetlinkError as e:
            raise NetifError("bridge slaves", ifname=bridge, cause=e) from e
    out: list[str] = []
    for link in links:
        if link.get_attr("IFLA_MASTER") == bridge_idx:
            name = link.get_attr("IFLA_IFNAME")
            if name is not None:
                out.append(name)
    return out


# ----------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------

def _link_master(idx: int) -> int | None:
    """Return the master ifindex for a link, or ``None`` if standalone."""
    with IPRoute() as ipr:
        links = ipr.get_links(idx)
        if not links:
            return None
        return links[0].get_attr("IFLA_MASTER")
