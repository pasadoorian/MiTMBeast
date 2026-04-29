"""Unit tests for ``mitmbeast.core.bridge`` — read-only paths."""
from __future__ import annotations

from mitmbeast.core.bridge import bridge_slaves


def test_bridge_slaves_for_missing_bridge_is_empty() -> None:
    assert bridge_slaves("definitely-not-a-bridge-zzz") == []


def test_bridge_slaves_for_loopback_is_empty() -> None:
    # lo isn't a bridge, so the helper finds no slaves.
    assert bridge_slaves("lo") == []
