"""Unit tests for ``mitmbeast.core.dnsmasq``."""
from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from mitmbeast.core.config import load_config
from mitmbeast.core.dnsmasq import (
    Lease,
    generate_config,
    is_running,
    read_leases,
    write_config,
)


@pytest.fixture
def cfg(tmp_path: Path):
    minimal = """\
WIFI_SSID="lab"
WIFI_PASSWORD="passw0rd"
LAN_IP="192.168.200.1"
LAN_SUBNET="255.255.255.0"
LAN_DHCP_START="192.168.200.10"
LAN_DHCP_END="192.168.200.100"
MITMPROXY_WEB_PASSWORD="mitm"
"""
    p = tmp_path / "mitm.conf"
    p.write_text(minimal)
    return load_config(p)


# ----- generate_config -----

def test_generate_config_produces_required_lines(cfg, tmp_path: Path) -> None:
    text = generate_config(cfg, spoof_conf_path=tmp_path / "dns-spoof.conf")
    assert "interface=br0" in text
    assert "dhcp-range=192.168.200.10,192.168.200.100,255.255.255.0,12h" in text
    assert "dhcp-option=6,192.168.200.1" in text
    assert f"conf-file={tmp_path / 'dns-spoof.conf'}" in text
    assert "log-queries" in text
    assert "log-dhcp" in text


def test_generate_config_log_flags_optional(cfg, tmp_path: Path) -> None:
    text = generate_config(cfg, spoof_conf_path=tmp_path / "x",
                           log_queries=False, log_dhcp=False)
    assert "log-queries" not in text
    assert "log-dhcp" not in text


def test_write_config_writes_to_disk(cfg, tmp_path: Path) -> None:
    out = tmp_path / "tmp_dnsmasq.conf"
    spoof = tmp_path / "dns-spoof.conf"
    written = write_config(cfg, output_path=out, spoof_conf_path=spoof)
    assert written == out
    text = out.read_text()
    assert "interface=br0" in text


# ----- read_leases -----

def test_read_leases_missing_file_returns_empty(tmp_path: Path) -> None:
    assert read_leases(tmp_path / "no-such-file") == []


def test_read_leases_parses_typical_entries(tmp_path: Path) -> None:
    leases_file = tmp_path / "dnsmasq.leases"
    leases_file.write_text(
        "1777510546 f2:00:dc:cd:96:3a 192.168.200.65 Pixel-9 01:f2:00:dc:cd:96:3a\n"
        "1777510600 aa:bb:cc:dd:ee:ff 192.168.200.10 * *\n"
    )
    leases = read_leases(leases_file)
    assert len(leases) == 2

    pixel = leases[0]
    assert pixel.mac == "f2:00:dc:cd:96:3a"
    assert pixel.ip == IPv4Address("192.168.200.65")
    assert pixel.hostname == "Pixel-9"
    assert pixel.client_id == "01:f2:00:dc:cd:96:3a"
    assert pixel.expiry == datetime.fromtimestamp(1777510546, tz=UTC)

    star = leases[1]
    assert star.hostname is None
    assert star.client_id is None


def test_read_leases_skips_comments_and_blanks(tmp_path: Path) -> None:
    f = tmp_path / "leases"
    f.write_text(
        "\n"
        "# a comment\n"
        "1777510546 aa:bb:cc:dd:ee:ff 192.168.200.10 host *\n"
    )
    assert len(read_leases(f)) == 1


def test_read_leases_skips_ipv6(tmp_path: Path) -> None:
    f = tmp_path / "leases"
    # IPv6 lease line has DUID (many colons) instead of 6-octet MAC
    f.write_text(
        "1777510546 ff:56:50:4d:98:00:02:00:00:ab:11:af:75:19:7f:fb:c9:00:e6 "
        "::1 hostname *\n"
        "1777510600 aa:bb:cc:dd:ee:ff 192.168.200.10 host *\n"
    )
    leases = read_leases(f)
    assert len(leases) == 1
    assert leases[0].ip == IPv4Address("192.168.200.10")


def test_read_leases_skips_malformed_lines(tmp_path: Path) -> None:
    f = tmp_path / "leases"
    f.write_text(
        "not a lease\n"
        "1777510546 aa:bb:cc:dd:ee:ff 192.168.200.10 host *\n"
        "abc def 192.168.200.20 host *\n"
        "1777510700 aa:bb:cc:dd:ee:01 not-an-ip host *\n"
    )
    leases = read_leases(f)
    assert len(leases) == 1


def test_lease_immutable() -> None:
    lease = Lease(
        expiry=datetime.now(UTC),
        mac="aa:bb:cc:dd:ee:ff",
        ip=IPv4Address("192.168.1.1"),
        hostname=None,
        client_id=None,
    )
    with pytest.raises((AttributeError, Exception)):
        lease.mac = "00:00:00:00:00:00"  # type: ignore[misc]


def test_lease_expires_in_seconds_negative_when_past() -> None:
    past = Lease(
        expiry=datetime(2020, 1, 1, tzinfo=UTC),
        mac="aa:bb:cc:dd:ee:ff",
        ip=IPv4Address("192.168.1.1"),
        hostname=None,
        client_id=None,
    )
    assert past.expires_in_seconds < 0


def test_lease_infinite_when_epoch_zero() -> None:
    forever = Lease(
        expiry=datetime.fromtimestamp(0, tz=UTC),
        mac="aa:bb:cc:dd:ee:ff",
        ip=IPv4Address("192.168.1.1"),
        hostname=None,
        client_id=None,
    )
    assert forever.expires_in_seconds == float("inf")


# ----- is_running (smoke; we don't actually fork dnsmasq in unit tests) -----

def test_is_running_false_for_nonexistent_config(tmp_path: Path) -> None:
    # No dnsmasq is running with a config at this path.
    assert not is_running(tmp_path / "definitely-not-running.conf")
