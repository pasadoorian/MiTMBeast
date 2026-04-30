"""Unit tests for ``mitmbeast.core.proxy.sslstrip`` — pure-data only.

The lifecycle paths spawn ``sslstrip`` + the fake-firmware-server and
need root + a network interface; they live in the integration suite.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mitmbeast.core.proxy import sslstrip


def test_session_is_frozen(tmp_path: Path) -> None:
    s = sslstrip.SslstripSession(
        sslstrip_pid=1234,
        fakefw_pid=5678,
        session_dir=tmp_path,
    )
    with pytest.raises((AttributeError, Exception)):
        s.sslstrip_pid = 9999  # type: ignore[misc]


def test_alive_returns_false_for_unlikely_pid() -> None:
    assert sslstrip._alive(99_999_999) is False


def test_log_dir_is_relative() -> None:
    """SSLSTRIP_LOG_DIR is a relative path under the repo, like the
    other proxy-mode log dirs (e.g. MITMPROXY_LOG_DIR)."""
    assert not sslstrip.SSLSTRIP_LOG_DIR.is_absolute()
    assert sslstrip.SSLSTRIP_LOG_DIR.name == "sslstrip_logs"


def test_error_is_runtime_error_subclass() -> None:
    assert issubclass(sslstrip.SslstripError, RuntimeError)
