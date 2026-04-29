"""Interface and route management via pyroute2 netlink.

Replaces the ``ifconfig`` and ``ip`` shell-outs in ``mitm.sh``. The
surface area is intentionally narrow — only the operations the v1.1
bash actually uses:

* check whether an interface exists and is up
* enumerate IPv4 addresses on an interface
* bring an interface up or down
* add or flush IPv4 addresses
* add a default route via a gateway
* flush routes attached to a specific device

All write operations require ``CAP_NET_ADMIN`` (effectively root).
Functions raise :class:`NetifError` on netlink errors with the
operation context attached, never bare pyroute2 ``NetlinkError``.

These helpers run synchronously — netlink RTTs are microseconds and
the supervisor only calls them at startup/teardown, not in the hot
path. If we ever need streaming netlink events (link-state changes
for the TUI Clients screen) we'll add an :class:`AsyncIPRoute` wrapper
beside this module.
"""
from __future__ import annotations

import socket
from contextlib import contextmanager
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface
from typing import TYPE_CHECKING

from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError

if TYPE_CHECKING:
    from collections.abc import Iterator

__all__ = [
    "AddressInfo",
    "NetifError",
    "iface_addresses",
    "iface_add_address",
    "iface_exists",
    "iface_flush_addresses",
    "iface_index",
    "iface_is_up",
    "iface_set_down",
    "iface_set_up",
    "route_add_default",
    "route_flush_dev",
]


class NetifError(RuntimeError):
    """Raised when a netlink operation fails."""

    def __init__(self, op: str, *, ifname: str | None = None,
                 cause: Exception | None = None) -> None:
        msg = f"netlink {op} failed"
        if ifname is not None:
            msg += f" for {ifname!r}"
        if cause is not None:
            msg += f": {cause}"
        super().__init__(msg)
        self.op = op
        self.ifname = ifname
        self.cause = cause


@dataclass(frozen=True, slots=True)
class AddressInfo:
    """One IPv4 address bound to an interface."""

    interface: IPv4Interface  # address + prefix length, e.g. 192.168.1.80/24

    @property
    def ip(self) -> IPv4Address:
        return self.interface.ip

    @property
    def prefixlen(self) -> int:
        return self.interface.network.prefixlen


# pyroute2 expects integer family constants — alias for clarity
_AF_INET = socket.AF_INET


@contextmanager
def _ipr() -> Iterator[IPRoute]:
    """Context manager that yields an open IPRoute and closes it cleanly."""
    ipr = IPRoute()
    try:
        yield ipr
    finally:
        ipr.close()


def iface_index(name: str) -> int | None:
    """Return the kernel ifindex for ``name``, or ``None`` if missing."""
    with _ipr() as ipr:
        idxs = ipr.link_lookup(ifname=name)
        return idxs[0] if idxs else None


def iface_exists(name: str) -> bool:
    """True if an interface named ``name`` exists in this netns."""
    return iface_index(name) is not None


def iface_is_up(name: str) -> bool:
    """True if the interface exists and is administratively up.

    Does **not** check carrier state — `ip link set up` succeeds before
    a cable is plugged in. Use ``iface_is_up`` to know whether *we* set
    it up.
    """
    with _ipr() as ipr:
        idxs = ipr.link_lookup(ifname=name)
        if not idxs:
            return False
        link = ipr.get_links(idxs[0])[0]
        # IFF_UP is bit 0 of the flags. pyroute2 also exposes 'state' but
        # the flag is the canonical "admin up" answer.
        return bool(link["flags"] & 0x1)


def iface_addresses(name: str) -> list[AddressInfo]:
    """Return all IPv4 addresses currently bound to ``name``."""
    with _ipr() as ipr:
        idxs = ipr.link_lookup(ifname=name)
        if not idxs:
            return []
        try:
            raw = ipr.get_addr(index=idxs[0], family=_AF_INET)
        except NetlinkError as e:
            raise NetifError("get_addr", ifname=name, cause=e) from e
    out: list[AddressInfo] = []
    for entry in raw:
        addr = entry.get_attr("IFA_ADDRESS")
        if addr is None:
            continue
        out.append(AddressInfo(interface=IPv4Interface(f"{addr}/{entry['prefixlen']}")))
    return out


def iface_set_up(name: str) -> None:
    """``ip link set <name> up`` — bring interface administratively up."""
    with _ipr() as ipr:
        idxs = ipr.link_lookup(ifname=name)
        if not idxs:
            raise NetifError("link_lookup", ifname=name,
                             cause=FileNotFoundError(name))
        try:
            ipr.link("set", index=idxs[0], state="up")
        except NetlinkError as e:
            raise NetifError("link set up", ifname=name, cause=e) from e


def iface_set_down(name: str) -> None:
    """``ip link set <name> down``."""
    with _ipr() as ipr:
        idxs = ipr.link_lookup(ifname=name)
        if not idxs:
            return  # already gone — nothing to do
        try:
            ipr.link("set", index=idxs[0], state="down")
        except NetlinkError as e:
            raise NetifError("link set down", ifname=name, cause=e) from e


def iface_add_address(name: str, addr: str | IPv4Interface) -> None:
    """``ip addr add <addr> dev <name>``.

    ``addr`` may be a CIDR string (``"192.168.1.80/24"``) or an
    :class:`IPv4Interface`. Idempotent — adding an existing address
    silently succeeds.
    """
    iface = addr if isinstance(addr, IPv4Interface) else IPv4Interface(addr)
    with _ipr() as ipr:
        idxs = ipr.link_lookup(ifname=name)
        if not idxs:
            raise NetifError("link_lookup", ifname=name,
                             cause=FileNotFoundError(name))
        try:
            ipr.addr("add", index=idxs[0],
                     address=str(iface.ip),
                     prefixlen=iface.network.prefixlen)
        except NetlinkError as e:
            # 17 = EEXIST: address already configured. That's fine.
            if e.code == 17:
                return
            raise NetifError("addr add", ifname=name, cause=e) from e


def iface_flush_addresses(name: str) -> None:
    """``ip addr flush dev <name>`` — remove every IPv4 address on iface."""
    with _ipr() as ipr:
        idxs = ipr.link_lookup(ifname=name)
        if not idxs:
            return
        try:
            current = ipr.get_addr(index=idxs[0], family=_AF_INET)
            for entry in current:
                addr = entry.get_attr("IFA_ADDRESS")
                if addr is None:
                    continue
                try:
                    ipr.addr("del", index=idxs[0], address=addr,
                             prefixlen=entry["prefixlen"])
                except NetlinkError as e:
                    # 99 = EADDRNOTAVAIL: addr is gone already; benign
                    if e.code == 99:
                        continue
                    raise
        except NetlinkError as e:
            raise NetifError("addr flush", ifname=name, cause=e) from e


def route_add_default(gateway: str, *, dev: str | None = None) -> None:
    """``ip route replace default via <gateway> [dev <dev>]``.

    Uses ``replace`` semantics so calling twice is idempotent — matches
    ``mitm.sh``'s use of ``ip route replace default ...``.
    """
    kwargs: dict[str, object] = {"dst": "default", "gateway": gateway}
    if dev is not None:
        with _ipr() as ipr:
            idxs = ipr.link_lookup(ifname=dev)
            if not idxs:
                raise NetifError("link_lookup", ifname=dev,
                                 cause=FileNotFoundError(dev))
            kwargs["oif"] = idxs[0]
            try:
                ipr.route("replace", **kwargs)
            except NetlinkError as e:
                raise NetifError("route replace default", cause=e) from e
        return
    with _ipr() as ipr:
        try:
            ipr.route("replace", **kwargs)
        except NetlinkError as e:
            raise NetifError("route replace default", cause=e) from e


def route_flush_dev(name: str) -> None:
    """``ip route flush dev <name>`` — remove every route via this iface."""
    with _ipr() as ipr:
        idxs = ipr.link_lookup(ifname=name)
        if not idxs:
            return
        try:
            routes = ipr.get_routes(oif=idxs[0])
            for r in routes:
                # Skip kernel-installed connected routes (proto=2 = kernel);
                # they get cleaned up automatically when the address is removed.
                if r.get("proto", 0) == 2:
                    continue
                try:
                    ipr.route("del", **{
                        k: r[k] for k in ("dst_len", "src_len", "tos",
                                          "scope", "type", "family")
                        if k in r
                    }, oif=idxs[0])
                except NetlinkError:
                    # Best-effort: a route may already be gone or non-deletable.
                    continue
        except NetlinkError as e:
            raise NetifError("route flush", ifname=name, cause=e) from e
