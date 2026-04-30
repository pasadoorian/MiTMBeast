"""Unit tests for ``mitmbeast.core.proxy.certmitm`` — pure-data only.

certmitm is a third-party tool with its own venv. The lifecycle paths
require it to be installed and a real network interface; they live in
the integration suite.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mitmbeast.core.config import load_config
from mitmbeast.core.proxy import certmitm

_MINIMAL_CONF = """\
WIFI_SSID="lab"
WIFI_PASSWORD="passw0rd"
LAN_IP="192.168.200.1"
LAN_SUBNET="255.255.255.0"
LAN_DHCP_START="192.168.200.10"
LAN_DHCP_END="192.168.200.100"
MITMPROXY_WEB_PASSWORD="mitm"
"""


@pytest.fixture
def cfg(tmp_path: Path):
    p = tmp_path / "mitm.conf"
    p.write_text(_MINIMAL_CONF)
    return load_config(p)


def test_session_is_frozen(tmp_path: Path) -> None:
    s = certmitm.CertmitmSession(
        pid=1234,
        session_dir=tmp_path,
        log_path=tmp_path / "certmitm.log",
    )
    with pytest.raises((AttributeError, Exception)):
        s.pid = 5678  # type: ignore[misc]


def test_alive_returns_false_for_unlikely_pid() -> None:
    assert certmitm._alive(99_999_999) is False


def test_error_is_runtime_error_subclass() -> None:
    assert issubclass(certmitm.CertmitmError, RuntimeError)


def test_start_raises_when_certmitm_path_missing(cfg, tmp_path: Path) -> None:
    """If ``cfg.CERTMITM_PATH`` doesn't exist, start() raises a clear
    error before ever reaching subprocess.Popen — operator gets a
    helpful message instead of a generic FileNotFoundError."""
    bad = cfg.model_copy(update={"CERTMITM_PATH": str(tmp_path / "nope.py")})
    with pytest.raises(certmitm.CertmitmError, match="not found"):
        certmitm.start(bad)


def test_start_raises_when_venv_python_missing(cfg, tmp_path: Path) -> None:
    """If certmitm.py exists but ``venv/bin/python3`` is missing,
    start() raises with setup instructions rather than launching a
    broken subprocess."""
    fake_script = tmp_path / "certmitm.py"
    fake_script.write_text("# stub\n")
    bad = cfg.model_copy(update={"CERTMITM_PATH": str(fake_script)})
    with pytest.raises(certmitm.CertmitmError, match="venv"):
        certmitm.start(bad)
