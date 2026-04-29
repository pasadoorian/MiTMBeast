"""Unit tests for ``mitmbeast.core.firewall`` — pure-data only.

Read/write iptables ops require root; those live in
``test_firewall_integration.py`` and run on the Kali VM.
"""
from __future__ import annotations

import pytest

from mitmbeast.core.firewall import (
    MITM_HOOKS,
    MITM_NTP_HOOK,
    FirewallError,
    Hook,
    _table_check,
)


def test_mitm_hooks_layout() -> None:
    """Locked-in chain layout — changing this is a major migration."""
    by_target = {h.target: h for h in MITM_HOOKS}
    assert set(by_target) == {"MITM_NAT_PRE", "MITM_NAT_POST", "MITM_FWD"}
    assert by_target["MITM_NAT_PRE"].table == "nat"
    assert by_target["MITM_NAT_PRE"].builtin == "PREROUTING"
    assert by_target["MITM_NAT_POST"].builtin == "POSTROUTING"
    assert by_target["MITM_FWD"].table == "filter"
    assert by_target["MITM_FWD"].builtin == "FORWARD"


def test_mitm_ntp_hook_layout() -> None:
    assert MITM_NTP_HOOK.table == "nat"
    assert MITM_NTP_HOOK.builtin == "PREROUTING"
    assert MITM_NTP_HOOK.target == "MITM_NTP_PRE"


def test_hook_is_frozen() -> None:
    h = Hook(table="nat", builtin="PREROUTING", target="X")
    with pytest.raises((AttributeError, Exception)):
        h.table = "filter"  # type: ignore[misc]


def test_unknown_table_raises() -> None:
    with pytest.raises(FirewallError, match="unknown table"):
        _table_check("mangle")  # we only support nat + filter for now
