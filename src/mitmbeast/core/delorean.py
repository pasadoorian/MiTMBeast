"""Delorean NTP-spoofing lifecycle.

Python port of ``delorean.sh``. Spawns the Delorean tool
(https://github.com/jselvi/Delorean), which serves spoofed NTP
responses, and installs iptables DNAT rules so any NTP traffic from
the LAN gets redirected to it.

Configuration values from :class:`MitmConfig`:

* ``DELOREAN_PATH``  — path to ``delorean.py`` (must be installed)
* ``BR_IFACE``       — bridge to redirect on
* ``LAN_IP``         — DNAT destination

Two iptables modes match the bash version:

1. **Generic catch-all** for any UDP/123 traffic on the bridge.
2. **Targeted** rules for hard-coded NTP server IPs that some IoT
   devices use (Cloudflare, Google).

The chain ``MITM_NTP_PRE`` (created by :mod:`mitmbeast.core.firewall`)
holds the rules. ``stop`` only tears down ``MITM_NTP_PRE`` so the
proxy chains owned by ``mitm.sh up`` remain intact.

Time-offset arithmetic lives in :func:`calculate_date` so the CLI
and tests can reuse it.
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from mitmbeast.core import firewall
from mitmbeast.core.config import MitmConfig
from mitmbeast.core.system import require_root

__all__ = [
    "DEFAULT_OFFSET",
    "DeloreanError",
    "DeloreanState",
    "calculate_date",
    "is_running",
    "load_state",
    "start",
    "status",
    "stop",
]


DEFAULT_OFFSET = "+1000"

# Hard-coded NTP server IPs that some IoT devices use directly,
# bypassing DNS. Mirrors the list from delorean.sh.
KNOWN_NTP_IPS: tuple[str, ...] = (
    "162.159.200.1", "162.159.200.123",
    "216.239.35.0", "216.239.35.4",
    "216.239.35.8", "216.239.35.12",
)

# Persistent state files
STATE_DIR = Path("/run/mitmbeast")
PID_FILE = STATE_DIR / "delorean.pid"
TIME_FILE = STATE_DIR / "delorean.offset"


class DeloreanError(RuntimeError):
    """Raised when a Delorean lifecycle operation fails."""


@dataclass(frozen=True, slots=True)
class DeloreanState:
    """Reflected snapshot of the Delorean lifecycle."""

    running: bool
    pid: int | None
    offset: str | None       # last user-supplied offset (+1000, -365, "2030-06-15")
    target_date: str | None  # offset rendered to a concrete date string
    iptables_active: bool


# ----------------------------------------------------------------------
# Time arithmetic
# ----------------------------------------------------------------------

_OFFSET_RE = re.compile(r"^[+\-]\d+$")


def calculate_date(offset: str) -> str:
    """Render ``+1500`` / ``-365`` / ``"2030-06-15"`` to a date string.

    Numeric offsets are interpreted as days relative to ``datetime.now()``
    in local time (matches what the bash version does via ``date -d``).
    """
    if _OFFSET_RE.match(offset):
        days = int(offset)
        target = datetime.now() + timedelta(days=days)  # noqa: DTZ005
        return target.strftime("%Y-%m-%d %H:%M:%S")
    # Already a date string — pass through. Delorean parses "YYYY-MM-DD"
    # and "YYYY-MM-DD HH:MM:SS" itself.
    return offset


# ----------------------------------------------------------------------
# Lifecycle
# ----------------------------------------------------------------------

def start(cfg: MitmConfig, *, offset: str = DEFAULT_OFFSET) -> DeloreanState:
    """Spawn Delorean and install the iptables NTP redirect chain."""
    require_root()
    if is_running():
        raise DeloreanError(
            f"Delorean is already running (PID {load_state().pid}). "
            "Stop it first or use reload."
        )

    script_rel = Path(cfg.DELOREAN_PATH)
    if not script_rel.is_file():
        raise DeloreanError(
            f"Delorean script not found: {script_rel}\n"
            "Install with:\n"
            f"  git clone https://github.com/jselvi/Delorean.git "
            f"{script_rel.parent}"
        )
    # Resolve to absolute so a cwd change inside subprocess doesn't break
    # the script lookup. Matches the bash version's behavior, which
    # invokes from the repo root with a relative path that just happens
    # to resolve there.
    script = script_rel.resolve()

    target_date = calculate_date(offset)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    TIME_FILE.write_text(offset + "\n")

    log_path = STATE_DIR / "delorean.log"
    log_fh = log_path.open("ab")
    proc = subprocess.Popen(  # noqa: S603 — argv list, no shell
        ["python3", str(script), "-d", target_date],
        stdout=log_fh, stderr=subprocess.STDOUT,
        cwd=str(script.parent), start_new_session=True,
    )
    time.sleep(0.3)
    if proc.poll() is not None:
        tail = log_path.read_text(errors="replace").splitlines()[-15:]
        raise DeloreanError(
            f"Delorean exited {proc.returncode} on startup. Last log:\n"
            + "\n".join(tail)
        )
    PID_FILE.write_text(f"{proc.pid}\n")

    # iptables: catch-all + per-known-IP rules
    firewall.install_ntp_chain()
    firewall.add_dnat_ntp(in_iface=cfg.BR_IFACE, router_ip=str(cfg.LAN_IP))
    for known in KNOWN_NTP_IPS:
        firewall.add_dnat_ntp(in_iface=cfg.BR_IFACE,
                              router_ip=str(cfg.LAN_IP), dst=known)

    return DeloreanState(
        running=True, pid=proc.pid,
        offset=offset, target_date=target_date,
        iptables_active=True,
    )


def stop(*, timeout: float = 3.0) -> None:
    """Stop Delorean and remove its iptables chain. Idempotent."""
    require_root()
    pid = _read_pid()
    if pid is not None and _alive(pid):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + timeout
        while _alive(pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        if _alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    PID_FILE.unlink(missing_ok=True)
    firewall.uninstall_ntp_chain()


def is_running() -> bool:
    pid = _read_pid()
    return pid is not None and _alive(pid)


def status() -> DeloreanState:
    return load_state()


def load_state() -> DeloreanState:
    """Read the persisted PID + offset and probe iptables."""
    pid = _read_pid()
    running = pid is not None and _alive(pid)
    offset = TIME_FILE.read_text().strip() if TIME_FILE.is_file() else None
    target = calculate_date(offset) if offset else None
    iptables_active = firewall.chain_exists("nat", "MITM_NTP_PRE")
    return DeloreanState(
        running=running,
        pid=pid if running else None,
        offset=offset,
        target_date=target,
        iptables_active=iptables_active,
    )


# ----------------------------------------------------------------------
# Internals
# ----------------------------------------------------------------------

def _read_pid() -> int | None:
    if not PID_FILE.is_file():
        return None
    try:
        return int(PID_FILE.read_text().strip())
    except (ValueError, OSError):
        return None


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False
