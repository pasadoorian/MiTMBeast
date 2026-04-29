"""Unit tests for ``mitmbeast.core.hostapd``."""
from __future__ import annotations

from pathlib import Path

import pytest

from mitmbeast.core.config import load_config
from mitmbeast.core.hostapd import (
    Station,
    _parse_stations,
    generate_config,
    is_running,
    write_config,
)


@pytest.fixture
def cfg(tmp_path: Path):
    minimal = """\
WIFI_SSID="lab-ssid"
WIFI_PASSWORD="passw0rd!"
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

def test_generate_config_required_lines(cfg) -> None:
    text = generate_config(cfg)
    assert "interface=wlan0" in text
    assert "bridge=br0" in text
    assert "ssid=lab-ssid" in text
    assert "wpa=2" in text
    assert "wpa_passphrase=passw0rd!" in text
    assert "wpa_key_mgmt=WPA-PSK" in text
    assert "wpa_pairwise=CCMP" in text


def test_generate_config_defaults(cfg) -> None:
    text = generate_config(cfg)
    assert "country_code=US" in text
    assert "hw_mode=g" in text
    assert "channel=11" in text
    assert "ieee80211n=1" in text


def test_generate_config_overrides(cfg) -> None:
    text = generate_config(cfg, country_code="GB", channel=6,
                           hw_mode="a", enable_11n=False)
    assert "country_code=GB" in text
    assert "hw_mode=a" in text
    assert "channel=6" in text
    assert "ieee80211n=1" not in text


def test_write_config_writes_to_disk(cfg, tmp_path: Path) -> None:
    out = tmp_path / "tmp_hostapd.conf"
    written = write_config(cfg, output_path=out)
    assert written == out
    assert "ssid=lab-ssid" in out.read_text()


# ----- station parsing -----

SAMPLE_STA_DUMP = """\
Station f2:00:dc:cd:96:3a (on wlan0)
\tinactive time:\t100 ms
\trx bytes:\t32374
\trx packets:\t476
\ttx bytes:\t17210
\ttx packets:\t88
\tsignal:  \t-37 [-37] dBm
\tsignal avg:\t-37 [-37] dBm
\ttx bitrate:\t65.0 MBit/s MCS 7
Station aa:bb:cc:dd:ee:ff (on wlan0)
\tinactive time:\t5000 ms
\trx bytes:\t1024
\trx packets:\t10
\ttx bytes:\t512
\ttx packets:\t4
\tsignal:  \t-65 dBm
"""


def test_parse_two_stations() -> None:
    stations = _parse_stations(SAMPLE_STA_DUMP)
    assert len(stations) == 2

    pixel = stations[0]
    assert pixel.mac == "f2:00:dc:cd:96:3a"
    assert pixel.signal_dbm == -37
    assert pixel.rx_bytes == 32374
    assert pixel.tx_bytes == 17210
    assert pixel.rx_packets == 476
    assert pixel.tx_packets == 88
    assert pixel.inactive_ms == 100

    other = stations[1]
    assert other.mac == "aa:bb:cc:dd:ee:ff"
    assert other.signal_dbm == -65


def test_parse_empty_dump_returns_empty_list() -> None:
    assert _parse_stations("") == []


def test_parse_garbled_lines_skipped() -> None:
    text = "Station ab:cd:ef:01:02:03 (on wlan0)\nthis line is junk\n"
    stations = _parse_stations(text)
    assert len(stations) == 1
    assert stations[0].mac == "ab:cd:ef:01:02:03"
    # All numeric fields default to None/0 since the body was garbage
    assert stations[0].signal_dbm is None
    assert stations[0].rx_bytes == 0


def test_station_immutable() -> None:
    s = Station(mac="aa:bb:cc:dd:ee:ff", signal_dbm=-50,
                rx_bytes=0, tx_bytes=0, rx_packets=0, tx_packets=0,
                inactive_ms=None)
    with pytest.raises((AttributeError, Exception)):
        s.mac = "00:00:00:00:00:00"  # type: ignore[misc]


# ----- is_running -----

def test_is_running_false_for_nonexistent_config(tmp_path: Path) -> None:
    assert not is_running(tmp_path / "definitely-not-running.conf")
