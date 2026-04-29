"""Tests for ``mitmbeast.core.config``."""
from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from mitmbeast.core.config import (
    ConfigParseError,
    MitmConfig,
    load_config,
    parse_conf,
)

MINIMAL_VALID = """\
# minimal valid config
WIFI_SSID="lab"
WIFI_PASSWORD="passw0rd"
LAN_IP="192.168.200.1"
LAN_SUBNET="255.255.255.0"
LAN_DHCP_START="192.168.200.10"
LAN_DHCP_END="192.168.200.100"
MITMPROXY_WEB_PASSWORD="mitm"
"""


def write(tmp_path: Path, contents: str) -> Path:
    p = tmp_path / "mitm.conf"
    p.write_text(contents)
    return p


# ----- raw parser -----

def test_parse_simple_assignments(tmp_path: Path) -> None:
    p = write(tmp_path, """
        FOO="hello"
        BAR='world'
        BAZ=plain
    """)
    out = parse_conf(p)
    assert out == {"FOO": "hello", "BAR": "world", "BAZ": "plain"}


def test_parse_strips_comments(tmp_path: Path) -> None:
    p = write(tmp_path, """
        # full-line comment
        FOO="x"   # inline comment
    """)
    assert parse_conf(p) == {"FOO": "x"}


def test_parse_var_references(tmp_path: Path) -> None:
    p = write(tmp_path, 'A="br0"\nB="$A"\nC="${A}-iface"\n')
    assert parse_conf(p) == {"A": "br0", "B": "br0", "C": "br0-iface"}


def test_parse_unknown_var_ref_raises(tmp_path: Path) -> None:
    p = write(tmp_path, 'X="$UNDEFINED"\n')
    with pytest.raises(ConfigParseError, match="UNDEFINED"):
        parse_conf(p)


def test_parse_invalid_line_raises(tmp_path: Path) -> None:
    p = write(tmp_path, "this is not a config line\n")
    with pytest.raises(ConfigParseError, match="cannot parse"):
        parse_conf(p)


# ----- Pydantic model -----

def test_load_minimal_valid(tmp_path: Path) -> None:
    cfg = load_config(write(tmp_path, MINIMAL_VALID))
    assert cfg.WIFI_SSID == "lab"
    assert str(cfg.LAN_IP) == "192.168.200.1"
    assert cfg.PROXY_MODE == "mitmproxy"  # default


def test_missing_required_fails(tmp_path: Path) -> None:
    # WIFI_PASSWORD missing
    bad = MINIMAL_VALID.replace('WIFI_PASSWORD="passw0rd"\n', "")
    with pytest.raises(ValidationError):
        load_config(write(tmp_path, bad))


def test_short_wifi_password_fails(tmp_path: Path) -> None:
    bad = MINIMAL_VALID.replace('WIFI_PASSWORD="passw0rd"', 'WIFI_PASSWORD="short"')
    with pytest.raises(ValidationError, match="at least 8"):
        load_config(write(tmp_path, bad))


def test_invalid_ip_fails(tmp_path: Path) -> None:
    bad = MINIMAL_VALID.replace('LAN_IP="192.168.200.1"', 'LAN_IP="not.an.ip.address"')
    with pytest.raises(ValidationError):
        load_config(write(tmp_path, bad))


def test_invalid_proxy_mode_fails(tmp_path: Path) -> None:
    bad = MINIMAL_VALID + 'PROXY_MODE="bogus"\n'
    with pytest.raises(ValidationError):
        load_config(write(tmp_path, bad))


def test_invalid_port_fails(tmp_path: Path) -> None:
    bad = MINIMAL_VALID + "MITMPROXY_PORT=99999\n"
    with pytest.raises(ValidationError, match="65535"):
        load_config(write(tmp_path, bad))


def test_unknown_key_fails(tmp_path: Path) -> None:
    bad = MINIMAL_VALID + 'WAN_TYPO="oops"\n'
    with pytest.raises(ValidationError, match="WAN_TYPO"):
        load_config(write(tmp_path, bad))


def test_empty_wan_static_ip_means_dhcp(tmp_path: Path) -> None:
    cfg = load_config(write(tmp_path, MINIMAL_VALID + 'WAN_STATIC_IP=""\n'))
    assert cfg.WAN_STATIC_IP == ""


def test_loads_real_example_file() -> None:
    """The shipped mitm.conf.example must parse and validate cleanly."""
    example = Path(__file__).parent.parent / "mitm.conf.example"
    assert example.is_file()
    cfg = load_config(example)
    assert isinstance(cfg, MitmConfig)
    assert cfg.PROXY_MODE in {
        "mitmproxy", "sslsplit", "certmitm", "sslstrip", "intercept", "none"
    }
