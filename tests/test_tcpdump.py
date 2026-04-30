"""Unit tests for ``mitmbeast.core.tcpdump``.

Pure-data only. The ``start`` lifecycle path spawns ``tcpdump`` and
needs root + a real network interface; that lives in the integration
suite.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from mitmbeast.core import tcpdump
from mitmbeast.core.config import load_config

_HAS_TCPDUMP = shutil.which("tcpdump") is not None

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
    s = tcpdump.TcpdumpSession(pid=1234, pcap_path=tmp_path / "x.pcap")
    with pytest.raises((AttributeError, Exception)):
        s.pid = 5678  # type: ignore[misc]


def test_alive_returns_false_for_unlikely_pid() -> None:
    assert tcpdump._alive(99_999_999) is False


def test_error_is_runtime_error_subclass() -> None:
    assert issubclass(tcpdump.TcpdumpError, RuntimeError)


@pytest.mark.skipif(not _HAS_TCPDUMP, reason="tcpdump binary not installed")
def test_start_raises_for_nonexistent_interface(cfg, tmp_path: Path) -> None:
    """If the iface doesn't exist, tcpdump exits ~immediately and we
    surface a TcpdumpError with a helpful hint instead of leaking the
    dead subprocess."""
    bad = cfg.model_copy(update={
        "TCPDUMP_IFACE": "nope-not-a-real-iface-xyz",
        "TCPDUMP_DIR": str(tmp_path / "captures"),
    })
    with pytest.raises(tcpdump.TcpdumpError, match="exited"):
        tcpdump.start(bad)


def test_start_raises_when_tcpdump_binary_missing(cfg, tmp_path: Path) -> None:
    """If the tcpdump binary isn't on PATH, surface a clear error with
    install hints — operators shouldn't have to read a Python traceback."""
    target_dir = tmp_path / "captures-missing-bin"
    bad = cfg.model_copy(update={"TCPDUMP_DIR": str(target_dir)})
    with pytest.raises(tcpdump.TcpdumpError, match="not found"):
        tcpdump.start(bad, tcpdump_binary="/no/such/tcpdump-binary")
    # The directory was still created before Popen tried to launch.
    assert target_dir.is_dir()


def test_stop_is_noop_for_dead_pid() -> None:
    """stop() must never raise for an already-dead PID."""
    tcpdump.stop(99_999_999)  # no exception


def test_options_are_split_safely(cfg, tmp_path: Path, monkeypatch) -> None:
    """``TCPDUMP_OPTIONS`` is shlex-split, not shell-evaluated. Multi-flag
    strings like ``"-s 0 -U"`` must become a clean argv list — no shell
    injection surface and no quoting accidents."""
    captured: dict[str, list[str]] = {}

    class _DummyProc:
        returncode = 1
        pid = 12345

        def poll(self):
            return 1   # pretend it died, so start() raises and we
                       # don't actually leave a tcpdump running

    def fake_popen(cmd, *a, **kw):
        captured["cmd"] = list(cmd)
        return _DummyProc()

    monkeypatch.setattr(tcpdump.subprocess, "Popen", fake_popen)
    cfg2 = cfg.model_copy(update={
        "TCPDUMP_IFACE": "br0",
        "TCPDUMP_OPTIONS": "-s 0 -U",
        "TCPDUMP_DIR": str(tmp_path / "caps"),
    })
    with pytest.raises(tcpdump.TcpdumpError):
        tcpdump.start(cfg2)

    cmd = captured["cmd"]
    assert cmd[0] == "tcpdump"
    assert cmd[1:3] == ["-i", "br0"]
    # The options were split into separate argv elements.
    assert "-s" in cmd
    assert "0" in cmd
    assert "-U" in cmd
    # Last two args: -w <path>
    assert cmd[-2] == "-w"
    assert cmd[-1].endswith(".pcap")
    assert "br0_" in cmd[-1]
