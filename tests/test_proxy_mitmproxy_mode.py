"""Unit tests for ``mitmbeast.core.proxy.mitmproxy_mode`` — pure-data only.

The lifecycle paths shell out to ``mitmweb`` and need a real network
interface; they live in the integration suite. Here we verify the
data classes, helpers, and module-level path constants.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mitmbeast.core.proxy import mitmproxy_mode


def test_session_is_frozen(tmp_path: Path) -> None:
    s = mitmproxy_mode.MitmproxySession(
        pid=1234,
        session_dir=tmp_path,
        web_url="http://127.0.0.1:8081",
    )
    with pytest.raises((AttributeError, Exception)):
        s.pid = 5678  # type: ignore[misc]


def test_alive_returns_false_for_unlikely_pid() -> None:
    assert mitmproxy_mode._alive(99_999_999) is False


def test_repo_root_resolves_to_repo() -> None:
    """REPO_ROOT must point at the repo (contains pyproject.toml)."""
    assert (mitmproxy_mode.REPO_ROOT / "pyproject.toml").is_file()


def test_flow_logger_addon_path_exists() -> None:
    """The mitmproxy flow-logger addon ships at the repo root."""
    assert mitmproxy_mode.FLOW_LOGGER_ADDON.is_file()
    assert mitmproxy_mode.FLOW_LOGGER_ADDON.name == "mitmproxy-flow-logger.py"


def test_default_flow_log_under_run_mitmbeast() -> None:
    """Flow log lives under /run/mitmbeast — wiped on reboot, no /tmp."""
    assert str(mitmproxy_mode.DEFAULT_FLOW_LOG).startswith("/run/mitmbeast/")


def test_error_is_runtime_error_subclass() -> None:
    assert issubclass(mitmproxy_mode.MitmproxyError, RuntimeError)
