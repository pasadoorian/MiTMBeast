"""dnsmasq configuration, lifecycle, and lease parsing.

Replaces the dnsmasq config generation and spawn in ``mitm.sh``:

    echo "interface=${BR_IFACE}" > tmp_dnsmasq.conf
    echo "dhcp-range=..." >> tmp_dnsmasq.conf
    ...
    dnsmasq -C tmp_dnsmasq.conf

The lease file (``/var/lib/misc/dnsmasq.leases`` by default) carries
the live DHCP state we surface in the TUI Clients screen and in the
``mitmbeast spoof dump`` debug output. We treat it as the source of
truth — dnsmasq writes it, we read it, no separate persistence in our
SQLite (see Q3 of PYTHON_TUI_PLAN: hybrid state).

Real-time DHCP/DNS event tailing is **not** in this module — it belongs
to the event-bus layer (P2.16). Here we only do start/stop and
point-in-time lease reads.
"""
from __future__ import annotations

import os
import signal
import subprocess
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path

from mitmbeast.core.config import MitmConfig

__all__ = [
    "DEFAULT_LEASES_PATH",
    "DnsmasqError",
    "Lease",
    "generate_config",
    "is_running",
    "read_leases",
    "start",
    "stop",
    "write_config",
]


DEFAULT_LEASES_PATH = Path("/var/lib/misc/dnsmasq.leases")


class DnsmasqError(RuntimeError):
    """Raised when a dnsmasq lifecycle operation fails."""


@dataclass(frozen=True, slots=True)
class Lease:
    """One DHCP lease as recorded by dnsmasq.

    Attributes mirror the lease file format:
    ``<expiry> <mac> <ip> <hostname> <client-id>``
    """

    expiry: datetime           # UTC; sentinel value 0 → "never expires"
    mac: str                   # lowercase ``aa:bb:cc:dd:ee:ff``
    ip: IPv4Address
    hostname: str | None       # ``*`` in the file → ``None``
    client_id: str | None      # ``*`` in the file → ``None``

    @property
    def expires_in_seconds(self) -> float:
        """Seconds until expiry. Negative if already expired.

        Returns ``+inf`` for the special "infinite lease" sentinel
        (expiry == epoch 0).
        """
        if self.expiry.timestamp() == 0:
            return float("inf")
        return (self.expiry - datetime.now(UTC)).total_seconds()


# ----------------------------------------------------------------------
# Config generation
# ----------------------------------------------------------------------

def generate_config(
    cfg: MitmConfig,
    *,
    spoof_conf_path: str | Path,
    log_queries: bool = True,
    log_dhcp: bool = True,
) -> str:
    """Build the dnsmasq config text from a :class:`MitmConfig`.

    Mirrors the layout produced by ``mitm.sh``. The DHCP DNS option
    points at ``LAN_IP`` so clients use mitmbeast's dnsmasq for both
    DHCP and DNS (which is how the spoofs land).
    """
    lines = [
        f"interface={cfg.BR_IFACE}",
        f"dhcp-range={cfg.LAN_DHCP_START},{cfg.LAN_DHCP_END},{cfg.LAN_SUBNET},12h",
        # DNS server option served to DHCP clients = our LAN IP
        f"dhcp-option=6,{cfg.LAN_IP}",
        f"conf-file={Path(spoof_conf_path)}",
    ]
    if log_queries:
        lines.append("log-queries")
    if log_dhcp:
        lines.append("log-dhcp")
    return "\n".join(lines) + "\n"


def write_config(
    cfg: MitmConfig,
    *,
    output_path: str | Path,
    spoof_conf_path: str | Path,
    log_queries: bool = True,
    log_dhcp: bool = True,
) -> Path:
    """Render the config and write it to ``output_path``. Returns the path."""
    p = Path(output_path)
    p.write_text(generate_config(
        cfg,
        spoof_conf_path=spoof_conf_path,
        log_queries=log_queries,
        log_dhcp=log_dhcp,
    ))
    return p


# ----------------------------------------------------------------------
# Lifecycle
# ----------------------------------------------------------------------

def start(config_path: str | Path, *, dnsmasq_binary: str = "dnsmasq") -> int:
    """Spawn dnsmasq with ``config_path`` and return its PID.

    dnsmasq daemonises itself by default — we run it that way (no
    foreground flag) so the parent shell can exit. We then locate the
    daemon's PID via ``pgrep`` matching this exact config path. This
    is the same approach ``mitm.sh`` used.
    """
    cfg = Path(config_path)
    if not cfg.is_file():
        raise DnsmasqError(f"config not found: {cfg}")
    try:
        subprocess.run(
            [dnsmasq_binary, "-C", str(cfg)],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as e:
        raise DnsmasqError(
            f"dnsmasq -C {cfg} failed: {e.stderr.strip() or e}"
        ) from e
    # Give it a moment to register, then resolve PID.
    for _ in range(20):
        pid = _pid_for_config(cfg)
        if pid is not None:
            return pid
        time.sleep(0.05)
    raise DnsmasqError(f"dnsmasq spawned but no PID found for {cfg}")


def stop(pid: int, *, timeout: float = 3.0) -> None:
    """Send SIGTERM and wait up to ``timeout`` for clean exit.

    Falls back to SIGKILL if the daemon hasn't exited in time. No-op
    when the PID is already gone.
    """
    if not _pid_alive(pid):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return
        time.sleep(0.05)
    # Hard kill
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def is_running(config_path: str | Path) -> bool:
    """True if a dnsmasq process is running with our exact config."""
    return _pid_for_config(Path(config_path)) is not None


def _pid_for_config(config_path: Path) -> int | None:
    """Return the PID of a dnsmasq running ``-C config_path``, else ``None``.

    We use the absolute path so two configs that happen to share a
    basename can't be confused.
    """
    abs_path = str(config_path.resolve())
    try:
        out = subprocess.run(
            ["pgrep", "-fa", "dnsmasq"],
            check=False, capture_output=True, text=True,
        ).stdout
    except FileNotFoundError:
        return None
    for line in out.splitlines():
        # "<pid> dnsmasq -C /path/to/conf"
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        pid_str, cmdline = parts
        if abs_path in cmdline or str(config_path) in cmdline:
            try:
                return int(pid_str)
            except ValueError:
                continue
    return None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


# ----------------------------------------------------------------------
# Lease parsing
# ----------------------------------------------------------------------

def read_leases(path: str | Path = DEFAULT_LEASES_PATH) -> list[Lease]:
    """Parse the dnsmasq lease file. Empty list if file is missing.

    File format (one lease per line, space-separated):

        <expiry-epoch> <mac> <ip> <hostname-or-*> <client-id-or-*>

    A handful of lines may be IPv6 leases (DUID instead of MAC). We
    skip those silently — IPv4 is all v1.x of mitmbeast cares about.
    """
    p = Path(path)
    if not p.is_file():
        return []
    return list(_parse_leases(p.read_text().splitlines()))


def _parse_leases(lines: Iterable[str]) -> Iterable[Lease]:
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            expiry_epoch = int(parts[0])
        except ValueError:
            continue
        mac_or_duid = parts[1]
        # IPv6 leases use a DUID-style identifier (long colon-string,
        # not 6 octets). Skip them.
        if mac_or_duid.count(":") != 5:
            continue
        try:
            ip = IPv4Address(parts[2])
        except ValueError:
            continue
        hostname = None if parts[3] == "*" else parts[3]
        client_id = None if parts[4] == "*" else parts[4]
        yield Lease(
            expiry=datetime.fromtimestamp(expiry_epoch, tz=UTC),
            mac=mac_or_duid.lower(),
            ip=ip,
            hostname=hostname,
            client_id=client_id,
        )
