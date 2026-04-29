"""Tests for ``mitmbeast.core.restore`` — interactive and headless paths."""
from __future__ import annotations

import pytest

from mitmbeast.core.restore import RestoreError, _resolve_manager


def _stub_prompt(answer: str):
    return lambda _msg: answer


def test_explicit_manager_skips_prompt() -> None:
    chosen = _resolve_manager("NetworkManager",
                              ["NetworkManager", "systemd-networkd"], None)
    assert chosen == "NetworkManager"


def test_explicit_none() -> None:
    chosen = _resolve_manager("none", ["NetworkManager"], None)
    assert chosen == "none"


def test_invalid_explicit_value_rejected() -> None:
    with pytest.raises(RestoreError, match="must be"):
        _resolve_manager("bogus", ["NetworkManager"], None)  # type: ignore[arg-type]


def test_interactive_numeric_choice() -> None:
    chosen = _resolve_manager(None,
                              ["NetworkManager", "systemd-networkd"],
                              _stub_prompt("2"))
    assert chosen == "systemd-networkd"


def test_interactive_letter_choice_n() -> None:
    chosen = _resolve_manager(None, ["NetworkManager"], _stub_prompt("n"))
    assert chosen == "none"


def test_interactive_empty_choice_means_none() -> None:
    chosen = _resolve_manager(None, ["NetworkManager"], _stub_prompt(""))
    assert chosen == "none"


def test_interactive_out_of_range_choice_raises() -> None:
    with pytest.raises(RestoreError, match="invalid"):
        _resolve_manager(None, ["NetworkManager"], _stub_prompt("9"))


def test_interactive_garbage_choice_raises() -> None:
    with pytest.raises(RestoreError, match="invalid"):
        _resolve_manager(None, ["NetworkManager"], _stub_prompt("hello"))
