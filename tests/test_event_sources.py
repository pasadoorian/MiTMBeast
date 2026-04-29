"""Tests for ``mitmbeast.core.event_sources`` parsers."""
from __future__ import annotations

from mitmbeast.core.event_sources import (
    _parse_dhcp_line,
    _parse_hostapd_line,
)

# ----- DHCP parser -----

def test_parse_dhcp_ack_with_hostname() -> None:
    line = "Apr 29 16:55:42 host dnsmasq-dhcp[123]: 1916534182 " \
           "DHCPACK(br0) 192.168.200.65 f2:00:dc:cd:96:3a Paul-s-iPhone-16"
    ev = _parse_dhcp_line(line)
    assert ev is not None
    assert ev.kind == "dhcp_lease"
    assert ev.data["iface"] == "br0"
    assert ev.data["ip"] == "192.168.200.65"
    assert ev.data["mac"] == "f2:00:dc:cd:96:3a"
    assert ev.data["hostname"] == "Paul-s-iPhone-16"


def test_parse_dhcp_request_no_hostname() -> None:
    line = "1916534182 DHCPREQUEST(br0) 192.168.200.65 aa:bb:cc:dd:ee:ff"
    ev = _parse_dhcp_line(line)
    assert ev is not None
    assert ev.kind == "dhcp_request"
    assert ev.data["hostname"] is None


def test_parse_dhcp_release() -> None:
    line = "1916534182 DHCPRELEASE(br0) 192.168.200.10 aa:bb:cc:dd:ee:ff"
    assert _parse_dhcp_line(line).kind == "dhcp_release"


def test_parse_dhcp_nak() -> None:
    line = "DHCPNAK(br0) 192.168.200.10 aa:bb:cc:dd:ee:ff"
    assert _parse_dhcp_line(line).kind == "dhcp_nak"


def test_parse_dhcp_offer() -> None:
    line = "DHCPOFFER(br0) 192.168.200.10 aa:bb:cc:dd:ee:ff"
    assert _parse_dhcp_line(line).kind == "dhcp_offer"


def test_parse_dhcp_unrelated_line_returns_none() -> None:
    assert _parse_dhcp_line("totally unrelated journal output") is None
    assert _parse_dhcp_line("") is None


# ----- hostapd parser -----

def test_parse_hostapd_associated() -> None:
    line = ("Apr 29 17:00:00 host hostapd: wlan0: STA aa:bb:cc:dd:ee:ff "
            "IEEE 802.11: associated (aid 1)")
    ev = _parse_hostapd_line(line)
    assert ev is not None
    assert ev.kind == "sta_connected"
    assert ev.data["iface"] == "wlan0"
    assert ev.data["mac"] == "aa:bb:cc:dd:ee:ff"


def test_parse_hostapd_deauthenticated() -> None:
    line = ("hostapd: wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: "
            "deauthenticated due to local deauth request")
    ev = _parse_hostapd_line(line)
    assert ev is not None
    assert ev.kind == "sta_disconnected"


def test_parse_hostapd_disassociated() -> None:
    line = "wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: disassociated"
    ev = _parse_hostapd_line(line)
    assert ev is not None
    assert ev.kind == "sta_disconnected"


def test_parse_hostapd_unrelated_line_returns_none() -> None:
    assert _parse_hostapd_line("AP-ENABLED") is None
    assert _parse_hostapd_line("") is None
