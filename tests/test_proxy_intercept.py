"""Unit tests for ``mitmbeast.core.proxy.intercept`` — pure-data only.

The lifecycle paths spawn ``mitmweb`` + the fake-firmware-server and
need root + a network interface; they live in the integration suite.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mitmbeast.core.proxy import intercept


def test_session_is_frozen(tmp_path: Path) -> None:
    s = intercept.InterceptSession(
        mitmweb_pid=1234,
        fakefw_pid=5678,
        session_dir=tmp_path,
    )
    with pytest.raises((AttributeError, Exception)):
        s.mitmweb_pid = 9999  # type: ignore[misc]


def test_alive_returns_false_for_unlikely_pid() -> None:
    assert intercept._alive(99_999_999) is False


def test_repo_root_resolves_to_repo() -> None:
    """REPO_ROOT must point at the repo (contains pyproject.toml).
    Catches Bug #2-style off-by-one path resolution if intercept.py
    ever moves under core/proxy/ to a deeper level."""
    assert (intercept.REPO_ROOT / "pyproject.toml").is_file()


def test_intercept_addon_ships_at_repo_root() -> None:
    """The mitmproxy-intercept.py addon must live at the repo root —
    intercept.start() resolves it via REPO_ROOT and bails early if
    it's missing."""
    assert (intercept.REPO_ROOT / "mitmproxy-intercept.py").is_file()


def test_log_dir_is_relative() -> None:
    assert not intercept.INTERCEPT_LOG_DIR.is_absolute()
    assert intercept.INTERCEPT_LOG_DIR.name == "intercept_logs"


def test_error_is_runtime_error_subclass() -> None:
    assert issubclass(intercept.InterceptError, RuntimeError)
