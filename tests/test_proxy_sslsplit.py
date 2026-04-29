"""Unit tests for ``mitmbeast.core.proxy.sslsplit`` — pure-data only.

The cert-generation and lifecycle paths shell out to ``openssl`` /
``sslsplit`` and need root + a real network interface; they live in
the integration suite (Phase 2e). Here we just verify the data
classes and helpers.
"""
from __future__ import annotations

from mitmbeast.core.proxy import sslsplit


def test_session_is_frozen() -> None:
    s = sslsplit.SslsplitSession(
        pid=1234,
        session_dir=sslsplit.SESSION_BASE_DIR,
        cert_dir=sslsplit.SESSION_BASE_DIR,
        ca_fingerprint="AA:BB:CC",
    )
    import pytest
    with pytest.raises((AttributeError, Exception)):
        s.pid = 5678  # type: ignore[misc]


def test_pid_alive_returns_false_for_unlikely_pid() -> None:
    # PID 99,999,999 is well outside any normal Linux PID range.
    assert sslsplit._pid_alive(99_999_999) is False


def test_session_base_dir_under_var_lib() -> None:
    """Session CA private keys must not live under /tmp."""
    assert str(sslsplit.SESSION_BASE_DIR).startswith("/var/lib/")
