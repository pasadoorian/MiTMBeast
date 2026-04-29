"""hostapd configuration, lifecycle, and station enumeration.

Replaces the hostapd portion of ``mitm.sh``:

    cat > tmp_hostapd.conf <<EOF
    interface=wlan0
    bridge=br0
    ssid=...
    wpa=2
    wpa_passphrase=...
    ...
    EOF
    hostapd -B tmp_hostapd.conf

We talk to ``iw`` (not ``hostapd_cli``) to list stations because
``iw dev <iface> station dump`` works without depending on hostapd's
control socket — robust if hostapd's socket isn't writable by us, or
if we attach to a managed-mode iface for one-off testing.

Real-time STA-CONNECTED / STA-DISCONNECTED tailing belongs to the
event-bus layer (P2.16); here we only do start/stop and point-in-time
station reads.
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from mitmbeast.core.config import MitmConfig

__all__ = [
    "HostapdError",
    "Station",
    "generate_config",
    "is_running",
    "list_stations",
    "start",
    "stop",
    "write_config",
]


class HostapdError(RuntimeError):
    """Raised when a hostapd lifecycle operation fails."""


@dataclass(frozen=True, slots=True)
class Station:
    """One Wi-Fi station (client) currently associated with the AP."""

    mac: str                  # lowercase ``aa:bb:cc:dd:ee:ff``
    signal_dbm: int | None    # last RX signal, e.g. -37 (None if missing)
    rx_bytes: int             # cumulative since association
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    inactive_ms: int | None   # ms since last frame received from station


# ----------------------------------------------------------------------
# Config generation
# ----------------------------------------------------------------------

def generate_config(
    cfg: MitmConfig,
    *,
    country_code: str = "US",
    channel: int = 11,
    hw_mode: str = "g",
    enable_11n: bool = True,
) -> str:
    """Build a hostapd config from a :class:`MitmConfig`.

    Mirrors the layout produced by ``mitm.sh`` line-for-line. The bridge
    parameter is required so hostapd attaches the station interface to
    our LAN bridge — the AP and the wired LAN see one shared L2.
    """
    lines = [
        f"interface={cfg.WIFI_IFACE}",
        f"bridge={cfg.BR_IFACE}",
        f"ssid={cfg.WIFI_SSID}",
        f"country_code={country_code}",
        f"hw_mode={hw_mode}",
        f"channel={channel}",
        "wpa=2",
        f"wpa_passphrase={cfg.WIFI_PASSWORD}",
        "wpa_key_mgmt=WPA-PSK",
        "wpa_pairwise=CCMP",
    ]
    if enable_11n:
        lines.append("ieee80211n=1")
    return "\n".join(lines) + "\n"


def write_config(
    cfg: MitmConfig,
    *,
    output_path: str | Path,
    country_code: str = "US",
    channel: int = 11,
    hw_mode: str = "g",
    enable_11n: bool = True,
) -> Path:
    """Render the config and write it to ``output_path``. Returns the path."""
    p = Path(output_path)
    p.write_text(generate_config(
        cfg,
        country_code=country_code,
        channel=channel,
        hw_mode=hw_mode,
        enable_11n=enable_11n,
    ))
    return p


# ----------------------------------------------------------------------
# Lifecycle
# ----------------------------------------------------------------------

def start(config_path: str | Path, *, hostapd_binary: str = "hostapd") -> int:
    """Spawn ``hostapd -B config_path`` and return its PID.

    ``-B`` daemonises hostapd, similar to dnsmasq's behavior. We then
    resolve the PID via ``pgrep -fa hostapd``. Errors at startup
    (interface busy, channel disallowed, bad passphrase) surface as
    :class:`HostapdError` with hostapd's stderr attached.
    """
    cfg = Path(config_path)
    if not cfg.is_file():
        raise HostapdError(f"config not found: {cfg}")
    try:
        subprocess.run(
            [hostapd_binary, "-B", str(cfg)],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as e:
        raise HostapdError(
            f"hostapd -B {cfg} failed: {e.stderr.strip() or e}"
        ) from e
    for _ in range(40):  # up to ~2s — hostapd takes longer than dnsmasq
        pid = _pid_for_config(cfg)
        if pid is not None:
            return pid
        time.sleep(0.05)
    raise HostapdError(f"hostapd spawned but no PID found for {cfg}")


def stop(pid: int, *, timeout: float = 3.0) -> None:
    """Send SIGTERM and wait up to ``timeout`` for clean exit."""
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
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def is_running(config_path: str | Path) -> bool:
    return _pid_for_config(Path(config_path)) is not None


def _pid_for_config(config_path: Path) -> int | None:
    abs_path = str(config_path.resolve())
    try:
        out = subprocess.run(
            ["pgrep", "-fa", "hostapd"],
            check=False, capture_output=True, text=True,
        ).stdout
    except FileNotFoundError:
        return None
    for line in out.splitlines():
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
# Station enumeration via `iw`
# ----------------------------------------------------------------------

# Sample `iw dev wlan0 station dump` output (one block per station):
#
#   Station f2:00:dc:cd:96:3a (on wlan0)
#       inactive time:  0 ms
#       rx bytes:       32374
#       rx packets:     476
#       tx bytes:       17210
#       tx packets:     88
#       signal:         -37 [-37] dBm
#       ...
#
# We parse the header line to start a new Station, then accumulate
# numeric fields until the next header or EOF.

_STA_HEADER_RE = re.compile(r"^Station\s+([0-9a-fA-F:]{17})\s")
_KV_RE = re.compile(r"^\s*([^:]+?):\s*(.+?)\s*$")


def list_stations(iface: str) -> list[Station]:
    """Run ``iw dev <iface> station dump`` and return parsed stations.

    Returns an empty list if the interface isn't an AP, isn't up, or
    has no associated stations.
    """
    try:
        r = subprocess.run(
            ["iw", "dev", iface, "station", "dump"],
            check=False, capture_output=True, text=True,
        )
    except FileNotFoundError:
        return []
    if r.returncode != 0:
        return []
    return list(_parse_stations(r.stdout))


def _parse_stations(text: str) -> list[Station]:
    blocks: list[dict[str, str]] = []
    cur: dict[str, str] | None = None
    for raw in text.splitlines():
        m_header = _STA_HEADER_RE.match(raw)
        if m_header:
            if cur is not None:
                blocks.append(cur)
            cur = {"mac": m_header.group(1).lower()}
            continue
        if cur is None:
            continue
        m_kv = _KV_RE.match(raw)
        if m_kv:
            cur[m_kv.group(1).strip()] = m_kv.group(2)
    if cur is not None:
        blocks.append(cur)

    out: list[Station] = []
    for b in blocks:
        out.append(Station(
            mac=b["mac"],
            signal_dbm=_first_int(b.get("signal")),
            rx_bytes=_first_int(b.get("rx bytes")) or 0,
            tx_bytes=_first_int(b.get("tx bytes")) or 0,
            rx_packets=_first_int(b.get("rx packets")) or 0,
            tx_packets=_first_int(b.get("tx packets")) or 0,
            inactive_ms=_first_int(b.get("inactive time")),
        ))
    return out


def _first_int(value: str | None) -> int | None:
    """Return the first integer found in ``value``. ``None`` if absent.

    Accepts forms like ``"-37 [-37] dBm"`` (signal) or ``"32374"`` (counts).
    """
    if value is None:
        return None
    m = re.search(r"-?\d+", value)
    if m is None:
        return None
    return int(m.group())
