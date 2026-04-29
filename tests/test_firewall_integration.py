"""Integration tests for ``mitmbeast.core.firewall``.

Need root + iptables. Run on the Kali VM. Tests use a fixture that
removes any leftover MITM_* chains before *and* after each test, so
a botched test doesn't poison the next run.

Rule assertions inspect the text returned by ``chain_rules_text``,
which is what ``iptables -S`` would print — robust across iptables
backends (legacy and nft) and immune to the iptc/legacy mismatch
that bit P2.7's first cut.
"""
from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from mitmbeast.core.firewall import (
    add_dnat_ntp,
    add_forward_established,
    add_forward_lan_to_wan,
    add_masquerade,
    add_redirect,
    chain_exists,
    chain_packet_counts,
    chain_rules_text,
    install_mitm_chains,
    install_ntp_chain,
    uninstall_mitm_chains,
    uninstall_ntp_chain,
)

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="firewall ops require root; run inside the Kali VM",
)


@pytest.fixture
def clean_chains() -> Iterator[None]:
    uninstall_mitm_chains()
    uninstall_ntp_chain()
    yield
    uninstall_mitm_chains()
    uninstall_ntp_chain()


# ----- chain install / uninstall -----

def test_install_creates_all_chains(clean_chains: None) -> None:
    install_mitm_chains()
    assert chain_exists("nat", "MITM_NAT_PRE")
    assert chain_exists("nat", "MITM_NAT_POST")
    assert chain_exists("filter", "MITM_FWD")


def test_uninstall_removes_all(clean_chains: None) -> None:
    install_mitm_chains()
    uninstall_mitm_chains()
    assert not chain_exists("nat", "MITM_NAT_PRE")
    assert not chain_exists("nat", "MITM_NAT_POST")
    assert not chain_exists("filter", "MITM_FWD")


def test_install_is_idempotent(clean_chains: None) -> None:
    install_mitm_chains()
    install_mitm_chains()
    install_mitm_chains()
    # Hook rules should not duplicate. After uninstall, no MITM_* refs.
    uninstall_mitm_chains()
    assert not chain_exists("nat", "MITM_NAT_PRE")


def test_uninstall_idempotent(clean_chains: None) -> None:
    uninstall_mitm_chains()
    uninstall_mitm_chains()


def test_ntp_chain_independent_of_main(clean_chains: None) -> None:
    install_mitm_chains()
    install_ntp_chain()
    assert chain_exists("nat", "MITM_NTP_PRE")
    uninstall_ntp_chain()
    assert not chain_exists("nat", "MITM_NTP_PRE")
    assert chain_exists("nat", "MITM_NAT_PRE")  # untouched


# ----- rule helpers -----

def _has_rule(rules: list[str], *fragments: str) -> bool:
    """True if any line in ``rules`` contains every fragment."""
    return any(all(f in line for f in fragments) for line in rules)


def test_add_masquerade(clean_chains: None) -> None:
    install_mitm_chains()
    add_masquerade("eth0")
    rules = chain_rules_text("nat", "MITM_NAT_POST")
    assert _has_rule(rules, "-A MITM_NAT_POST", "-o eth0", "MASQUERADE")


def test_add_forward_established(clean_chains: None) -> None:
    install_mitm_chains()
    add_forward_established()
    rules = chain_rules_text("filter", "MITM_FWD")
    assert _has_rule(rules, "-A MITM_FWD",
                     "RELATED,ESTABLISHED", "-j ACCEPT")


def test_add_forward_lan_to_wan(clean_chains: None) -> None:
    install_mitm_chains()
    add_forward_lan_to_wan("br0", "eth0")
    rules = chain_rules_text("filter", "MITM_FWD")
    assert _has_rule(rules, "-A MITM_FWD",
                     "-i br0", "-o eth0", "-j ACCEPT")


def test_add_redirect_no_dst(clean_chains: None) -> None:
    install_mitm_chains()
    add_redirect(in_iface="br0", dst=None, dport=443, to_port=8081)
    rules = chain_rules_text("nat", "MITM_NAT_PRE")
    assert _has_rule(rules, "-A MITM_NAT_PRE",
                     "-i br0", "-p tcp", "--dport 443",
                     "REDIRECT", "--to-ports 8081")


def test_add_redirect_with_dst(clean_chains: None) -> None:
    install_mitm_chains()
    add_redirect(in_iface="br0", dst="192.168.200.1",
                 dport=443, to_port=8081)
    rules = chain_rules_text("nat", "MITM_NAT_PRE")
    assert _has_rule(rules, "-A MITM_NAT_PRE",
                     "-d 192.168.200.1",
                     "-i br0", "-p tcp", "--dport 443",
                     "REDIRECT", "--to-ports 8081")


def test_add_dnat_ntp_no_dst(clean_chains: None) -> None:
    install_ntp_chain()
    add_dnat_ntp(in_iface="br0", router_ip="192.168.200.1")
    rules = chain_rules_text("nat", "MITM_NTP_PRE")
    assert _has_rule(rules, "-A MITM_NTP_PRE",
                     "-i br0", "-p udp", "--dport 123",
                     "DNAT", "192.168.200.1:123")


def test_add_dnat_ntp_with_dst(clean_chains: None) -> None:
    install_ntp_chain()
    add_dnat_ntp(in_iface="br0", router_ip="192.168.200.1",
                 dst="162.159.200.1")
    rules = chain_rules_text("nat", "MITM_NTP_PRE")
    assert _has_rule(rules, "-A MITM_NTP_PRE",
                     "-d 162.159.200.1",
                     "-i br0", "-p udp", "--dport 123",
                     "DNAT", "192.168.200.1:123")


# ----- counters -----

def test_chain_packet_counts(clean_chains: None) -> None:
    install_mitm_chains()
    add_masquerade("eth0")
    counts = chain_packet_counts("nat", "MITM_NAT_POST")
    assert counts == [(0, 0)]


def test_packet_counts_for_missing_chain_is_empty() -> None:
    assert chain_packet_counts("nat", "DEFINITELY_NOT_A_CHAIN_ZZZ") == []
