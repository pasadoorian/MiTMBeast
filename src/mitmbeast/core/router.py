"""Router orchestration — stitches the core modules into ``up``/``down``.

This is the Python equivalent of the v1.1 bash ``mitm.sh up`` and
``mitm.sh down`` flows, mode = ``none`` only. Proxy modes (mitmproxy,
sslsplit, certmitm, sslstrip, intercept) are added in P2.10–P2.11
when their respective :mod:`mitmbeast.core.proxy.*` modules land.

Behavior intentionally matches v1.1:

* on ``up``: stop NetworkManager / systemd-networkd / systemd-resolved,
  back up ``/etc/resolv.conf``, reset LAN/Wi-Fi interfaces, configure
  WAN (static IP if ``WAN_STATIC_IP`` set, otherwise DHCP), create
  the bridge, install MITM iptables chains, start dnsmasq + hostapd.
* on ``down``: stop daemons, tear down chains and bridge, restore
  resolv.conf. Network managers are **not** re-enabled — that's the
  job of ``mitmbeast restore`` (M1.1 in Phase 1).

State files live under ``/run/mitmbeast/``:

* ``resolv_was_symlink_to`` — original symlink target if applicable
* ``dnsmasq.conf`` — generated dnsmasq config
* ``hostapd.conf`` — generated hostapd config
* ``dnsmasq.pid`` / ``hostapd.pid`` — PIDs of the daemons we started

These supersede the v1.1 ``tmp_*.conf`` files in the repo directory.

All operations require root.
"""
from __future__ import annotations

import subprocess
from ipaddress import IPv4Network
from pathlib import Path

from mitmbeast.core import bridge, dnsmasq, firewall, hostapd, netif
from mitmbeast.core.config import MitmConfig
from mitmbeast.core.proxy import sslsplit as proxy_sslsplit
from mitmbeast.core.proxy import sslstrip as proxy_sslstrip
from mitmbeast.core.system import require_root

__all__ = [
    "RouterError",
    "STATE_DIR",
    "router_down",
    "router_up",
]


class RouterError(RuntimeError):
    """Raised when an orchestration step fails."""


STATE_DIR = Path("/run/mitmbeast")
_DNSMASQ_CONF = STATE_DIR / "dnsmasq.conf"
_HOSTAPD_CONF = STATE_DIR / "hostapd.conf"
_DNSMASQ_PID = STATE_DIR / "dnsmasq.pid"
_HOSTAPD_PID = STATE_DIR / "hostapd.pid"
_SSLSPLIT_PID = STATE_DIR / "sslsplit.pid"
_SSLSPLIT_SESSION = STATE_DIR / "sslsplit.session"  # JSON for cert_dir/etc
_SSLSTRIP_PID = STATE_DIR / "sslstrip.pid"
_SSLSTRIP_FAKEFW_PID = STATE_DIR / "sslstrip-fakefw.pid"
_SSLSTRIP_SESSION = STATE_DIR / "sslstrip.session"
_RESOLV_BACKUP = Path("/etc/resolv.conf.backup")
_RESOLV_SYMLINK_MARK = STATE_DIR / "resolv_was_symlink_to"

# Modes natively supported by the Python core. Anything else still
# falls through to the legacy bash via the click CLI's non-`--python`
# path (see :mod:`mitmbeast.cli`).
_SUPPORTED_MODES = ("none", "sslsplit", "sslstrip")


# ----------------------------------------------------------------------
# Public entry points
# ----------------------------------------------------------------------

def router_up(cfg: MitmConfig, *, mode: str = "none",
              keep_wan: bool = False) -> None:
    """Bring the MITM router up.

    Equivalent to ``mitm.sh up -m none`` in v1.1. Proxy modes raise
    ``RouterError`` until P2.10/P2.11.
    """
    require_root()
    if mode not in _SUPPORTED_MODES:
        raise RouterError(
            f"mode {mode!r} not supported in P2.9b — only "
            f"{_SUPPORTED_MODES}; proxy modes land in P2.10/P2.11. "
            "Use the bash fallback (`mitmbeast up` without --python)."
        )
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    print(">> stopping host network managers")
    _stop_network_managers()

    print(">> backing up /etc/resolv.conf and writing spoofed nameserver")
    _backup_resolv_conf()
    _write_resolv_conf(cfg.WAN_STATIC_DNS or "1.1.1.1")

    print(">> resetting LAN and Wi-Fi interfaces")
    netif.iface_flush_addresses(cfg.LAN_IFACE)
    netif.iface_set_down(cfg.LAN_IFACE)
    netif.iface_flush_addresses(cfg.WIFI_IFACE)
    netif.iface_set_down(cfg.WIFI_IFACE)
    if netif.iface_exists(cfg.BR_IFACE):
        netif.iface_set_down(cfg.BR_IFACE)
        bridge.bridge_destroy(cfg.BR_IFACE)

    print(">> configuring WAN")
    if keep_wan and _wan_is_static(cfg):
        print(f"   preserving {cfg.WAN_IFACE} (static {cfg.WAN_STATIC_IP})")
    else:
        _configure_wan(cfg)

    print(f">> creating bridge {cfg.BR_IFACE} and attaching {cfg.LAN_IFACE}")
    netif.iface_set_up(cfg.LAN_IFACE)
    bridge.bridge_create(cfg.BR_IFACE)
    bridge.bridge_add_slave(cfg.BR_IFACE, cfg.LAN_IFACE)
    netif.iface_set_up(cfg.BR_IFACE)
    bridge_cidr = _ipv4_with_cidr(str(cfg.LAN_IP), cfg.LAN_SUBNET)
    netif.iface_add_address(cfg.BR_IFACE, bridge_cidr)

    print(">> enabling IPv4 forwarding")
    Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")

    print(">> installing MITM_* iptables chains")
    firewall.install_mitm_chains()
    firewall.add_masquerade(cfg.WAN_IFACE)
    firewall.add_forward_established()
    firewall.add_forward_lan_to_wan(cfg.BR_IFACE, cfg.WAN_IFACE)

    print(">> starting dnsmasq")
    spoof_conf = Path(__file__).resolve().parents[3] / "dns-spoof.conf"
    dnsmasq.write_config(cfg, output_path=_DNSMASQ_CONF,
                         spoof_conf_path=spoof_conf)
    dnsmasq_pid = dnsmasq.start(_DNSMASQ_CONF)
    _DNSMASQ_PID.write_text(f"{dnsmasq_pid}\n")
    print(f"   dnsmasq pid {dnsmasq_pid}")

    print(">> starting hostapd")
    hostapd.write_config(cfg, output_path=_HOSTAPD_CONF)
    hostapd_pid = hostapd.start(_HOSTAPD_CONF)
    _HOSTAPD_PID.write_text(f"{hostapd_pid}\n")
    print(f"   hostapd pid {hostapd_pid}")

    if mode == "sslsplit":
        print(">> starting sslsplit")
        session = proxy_sslsplit.start(cfg)
        _SSLSPLIT_PID.write_text(f"{session.pid}\n")
        _SSLSPLIT_SESSION.write_text(
            f"{session.cert_dir}\n{session.session_dir}\n"
        )
        firewall.add_redirect(
            in_iface=cfg.BR_IFACE, dst=None,
            dport=443, to_port=cfg.SSLSPLIT_PORT,
        )
        print(f"   sslsplit pid {session.pid}")
        print(f"   session dir: {session.session_dir}")
        print(f"   CA fingerprint: {session.ca_fingerprint}")

    elif mode == "sslstrip":
        print(">> starting sslstrip + fake firmware server")
        ss = proxy_sslstrip.start(cfg)
        _SSLSTRIP_PID.write_text(f"{ss.sslstrip_pid}\n")
        _SSLSTRIP_FAKEFW_PID.write_text(f"{ss.fakefw_pid}\n")
        _SSLSTRIP_SESSION.write_text(f"{ss.session_dir}\n")
        # Only redirect traffic destined to *us* (the LAN_IP), to match
        # mitm.sh — passthrough domains resolve to real IPs and bypass.
        firewall.add_redirect(
            in_iface=cfg.BR_IFACE, dst=str(cfg.LAN_IP),
            dport=443, to_port=cfg.SSLSTRIP_PORT,
        )
        firewall.add_redirect(
            in_iface=cfg.BR_IFACE, dst=str(cfg.LAN_IP),
            dport=80, to_port=cfg.SSLSTRIP_FAKE_SERVER_PORT,
        )
        print(f"   sslstrip pid {ss.sslstrip_pid}")
        print(f"   fakefw pid   {ss.fakefw_pid}")
        print(f"   session dir: {ss.session_dir}")

    print()
    print(f"== MITM router is up (mode: {mode}, Python stack)")
    print(f"   WAN: {cfg.WAN_IFACE} ({cfg.WAN_STATIC_IP or 'DHCP'})")
    print(f"   LAN: {cfg.BR_IFACE} ({cfg.LAN_IP})")
    print(f"   WiFi SSID: {cfg.WIFI_SSID}")


def router_down(cfg: MitmConfig, *, keep_wan: bool = False) -> None:
    """Bring the MITM router down.

    Equivalent to ``mitm.sh down`` in v1.1. Network managers are
    intentionally **not** restarted; use ``mitmbeast restore`` for that
    (the Phase 1 design — dedicated host).
    """
    require_root()
    print(">> stopping daemons")
    _stop_sslsplit()
    _stop_sslstrip()
    _stop_pid_file(_HOSTAPD_PID, hostapd.stop)
    _stop_pid_file(_DNSMASQ_PID, dnsmasq.stop)

    print(">> removing MITM iptables chains")
    firewall.uninstall_mitm_chains()

    print(">> restoring /etc/resolv.conf")
    _restore_resolv_conf()

    if keep_wan:
        print(f">> preserving WAN {cfg.WAN_IFACE}")
    else:
        print(f">> tearing down WAN {cfg.WAN_IFACE}")
        netif.route_flush_dev(cfg.WAN_IFACE)
        netif.iface_flush_addresses(cfg.WAN_IFACE)
        netif.iface_set_down(cfg.WAN_IFACE)

    print(">> tearing down bridge")
    if netif.iface_exists(cfg.BR_IFACE):
        netif.iface_set_down(cfg.BR_IFACE)
        netif.iface_flush_addresses(cfg.BR_IFACE)
        bridge.bridge_destroy(cfg.BR_IFACE)

    print()
    print("== MITM router is down")


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _stop_network_managers() -> None:
    """Stop NM / systemd-networkd / systemd-resolved if running."""
    for unit in ("NetworkManager", "systemd-networkd", "systemd-resolved"):
        subprocess.run(["systemctl", "stop", unit],
                       check=False, capture_output=True)


def _backup_resolv_conf() -> None:
    """M1.4 logic: detect symlink vs regular file, back up appropriately."""
    if _RESOLV_SYMLINK_MARK.exists() or _RESOLV_BACKUP.exists():
        return  # already backed up
    target = Path("/etc/resolv.conf")
    if target.is_symlink():
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        _RESOLV_SYMLINK_MARK.write_text(str(target.readlink()) + "\n")
        target.unlink()
    elif target.is_file():
        target.replace(_RESOLV_BACKUP)


def _write_resolv_conf(nameserver: str) -> None:
    Path("/etc/resolv.conf").write_text(
        "# Static resolv.conf managed by mitmbeast\n"
        f"nameserver {nameserver}\n"
    )


def _restore_resolv_conf() -> None:
    target = Path("/etc/resolv.conf")
    if _RESOLV_SYMLINK_MARK.exists():
        link_target = _RESOLV_SYMLINK_MARK.read_text().strip()
        if target.exists() or target.is_symlink():
            target.unlink()
        target.symlink_to(link_target)
        _RESOLV_SYMLINK_MARK.unlink()
        return
    if _RESOLV_BACKUP.is_file():
        _RESOLV_BACKUP.replace(target)


def _wan_is_static(cfg: MitmConfig) -> bool:
    if not cfg.WAN_STATIC_IP:
        return False
    addrs = {str(a.ip) for a in netif.iface_addresses(cfg.WAN_IFACE)}
    return cfg.WAN_STATIC_IP in addrs


def _configure_wan(cfg: MitmConfig) -> None:
    if cfg.WAN_STATIC_IP:
        netif.iface_flush_addresses(cfg.WAN_IFACE)
        cidr = _ipv4_with_cidr(cfg.WAN_STATIC_IP, cfg.WAN_STATIC_NETMASK)
        netif.iface_add_address(cfg.WAN_IFACE, cidr)
        netif.iface_set_up(cfg.WAN_IFACE)
        if cfg.WAN_STATIC_GATEWAY:
            netif.route_add_default(cfg.WAN_STATIC_GATEWAY, dev=cfg.WAN_IFACE)
    else:
        netif.iface_set_up(cfg.WAN_IFACE)
        # DHCP — shell out to dhclient. No clean Python alternative
        # outside very heavy DHCP libraries.
        subprocess.run(
            ["dhclient", "-v", cfg.WAN_IFACE],
            check=False, capture_output=True,
        )


def _ipv4_with_cidr(ip: str, dotted_mask: str) -> str:
    """Convert ``"192.168.1.80"`` + ``"255.255.255.0"`` → ``"192.168.1.80/24"``."""
    network = IPv4Network(f"0.0.0.0/{dotted_mask}", strict=False)
    return f"{ip}/{network.prefixlen}"


def _stop_pid_file(pid_file: Path, stopper) -> None:  # type: ignore[no-untyped-def]
    if not pid_file.is_file():
        return
    try:
        pid = int(pid_file.read_text().strip())
    except (ValueError, OSError):
        pid_file.unlink(missing_ok=True)
        return
    stopper(pid)
    pid_file.unlink(missing_ok=True)


def _stop_sslsplit() -> None:
    """Tear down sslsplit if a previous ``up`` started it."""
    if not _SSLSPLIT_PID.is_file():
        return
    try:
        pid = int(_SSLSPLIT_PID.read_text().strip())
    except (ValueError, OSError):
        _SSLSPLIT_PID.unlink(missing_ok=True)
        _SSLSPLIT_SESSION.unlink(missing_ok=True)
        return
    cert_dir = Path(STATE_DIR / "no-such-dir")
    session_dir = Path(STATE_DIR / "no-such-dir")
    if _SSLSPLIT_SESSION.is_file():
        try:
            lines = _SSLSPLIT_SESSION.read_text().splitlines()
            if len(lines) >= 2:
                cert_dir, session_dir = Path(lines[0]), Path(lines[1])
        except OSError:
            pass
    proxy_sslsplit.stop(proxy_sslsplit.SslsplitSession(
        pid=pid, cert_dir=cert_dir, session_dir=session_dir,
        ca_fingerprint="(unknown)",
    ))
    _SSLSPLIT_PID.unlink(missing_ok=True)
    _SSLSPLIT_SESSION.unlink(missing_ok=True)


def _stop_sslstrip() -> None:
    """Tear down sslstrip + fakefw if a previous ``up`` started them."""
    if not _SSLSTRIP_PID.is_file() and not _SSLSTRIP_FAKEFW_PID.is_file():
        return
    sslstrip_pid = _read_int(_SSLSTRIP_PID)
    fakefw_pid = _read_int(_SSLSTRIP_FAKEFW_PID)
    session_dir = STATE_DIR / "no-such"
    if _SSLSTRIP_SESSION.is_file():
        try:
            session_dir = Path(_SSLSTRIP_SESSION.read_text().strip())
        except OSError:
            pass
    if sslstrip_pid is not None and fakefw_pid is not None:
        proxy_sslstrip.stop(proxy_sslstrip.SslstripSession(
            sslstrip_pid=sslstrip_pid,
            fakefw_pid=fakefw_pid,
            session_dir=session_dir,
        ))
    _SSLSTRIP_PID.unlink(missing_ok=True)
    _SSLSTRIP_FAKEFW_PID.unlink(missing_ok=True)
    _SSLSTRIP_SESSION.unlink(missing_ok=True)


def _read_int(path: Path) -> int | None:
    if not path.is_file():
        return None
    try:
        return int(path.read_text().strip())
    except (ValueError, OSError):
        return None
