"""Tests for ``mitmbeast.core.delorean`` — pure-data only.

Lifecycle tests need root + the Delorean tool installed; they live
in the integration suite once a Kali image with Delorean is built.
"""
from __future__ import annotations

import re
from datetime import datetime

import pytest

from mitmbeast.core.delorean import (
    DEFAULT_OFFSET,
    DeloreanState,
    calculate_date,
)


def test_default_offset_is_plus_1000() -> None:
    assert DEFAULT_OFFSET == "+1000"


def test_calculate_date_positive_offset() -> None:
    out = calculate_date("+10")
    # YYYY-MM-DD HH:MM:SS
    assert re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$", out)
    parsed = datetime.strptime(out, "%Y-%m-%d %H:%M:%S")
    delta = (parsed - datetime.now()).days
    # Within ±1 day to absorb clock drift around the day boundary
    assert 9 <= delta <= 10


def test_calculate_date_negative_offset() -> None:
    out = calculate_date("-365")
    parsed = datetime.strptime(out, "%Y-%m-%d %H:%M:%S")
    delta = (parsed - datetime.now()).days
    assert -366 <= delta <= -364


def test_calculate_date_passes_through_explicit_date() -> None:
    assert calculate_date("2030-06-15") == "2030-06-15"
    assert calculate_date("2030-06-15 12:00:00") == "2030-06-15 12:00:00"


def test_calculate_date_treats_unparseable_as_passthrough() -> None:
    # Junk that's not numeric and not a recognised date format —
    # we don't try to validate, we hand to delorean.py and let it
    # complain. Match bash behavior (`date -d "<arg>"` decides).
    assert calculate_date("tomorrow") == "tomorrow"


def test_state_is_frozen() -> None:
    s = DeloreanState(running=False, pid=None, offset=None,
                      target_date=None, iptables_active=False)
    with pytest.raises((AttributeError, Exception)):
        s.running = True  # type: ignore[misc]
