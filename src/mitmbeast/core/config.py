"""Typed config model for ``mitm.conf``.

The legacy ``mitm.conf`` is a shell file that ``mitm.sh`` sources at
startup. We don't want to invoke bash to read it (security + portability),
so we parse it ourselves. The format is a strict subset of POSIX shell:

    # comment
    KEY="value"     # inline comment
    KEY='value'
    KEY=value       # bare
    OTHER="$KEY"    # reference an earlier-defined variable

This module exposes :func:`load_config` which returns a validated
:class:`MitmConfig`. Pydantic validates types and rejects unknown keys
(strict mode) so typos surface fast.
"""
from __future__ import annotations

import re
from ipaddress import IPv4Address
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Module-level: lines we recognise from a sourced shell file.
# Anchored: KEY=VALUE with optional surrounding whitespace and trailing comment.
_ASSIGN_RE = re.compile(
    r"""
    ^\s*
    (?P<key>[A-Z_][A-Z0-9_]*)       # SHOUTY_SNAKE assignment target
    \s*=\s*
    (?P<value>
        "(?:[^"\\]|\\.)*"           # double-quoted
        | '(?:[^'\\]|\\.)*'         # single-quoted
        | [^#\s]*                   # bare (no spaces, no comment)
    )
    \s*(?:\#.*)?$                   # optional inline comment
    """,
    re.VERBOSE,
)

_VAR_REF_RE = re.compile(r"\$\{?([A-Z_][A-Z0-9_]*)\}?")


class ConfigParseError(Exception):
    """Raised when ``mitm.conf`` cannot be parsed."""


def _strip_quotes(s: str) -> str:
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


def _expand_vars(value: str, scope: dict[str, str]) -> str:
    """Replace ``$VAR`` / ``${VAR}`` with values from ``scope``.

    Mirrors bash's behavior of forward-only references — variables
    must be defined before they are used. Unknown references raise.
    """
    def repl(m: re.Match[str]) -> str:
        name = m.group(1)
        if name not in scope:
            raise ConfigParseError(
                f"reference to undefined variable {name!r} in config"
            )
        return scope[name]
    return _VAR_REF_RE.sub(repl, value)


def parse_conf(path: Path) -> dict[str, str]:
    """Parse a ``mitm.conf`` shell file into a flat ``{KEY: value}`` dict.

    Raises :class:`ConfigParseError` on syntactically invalid lines.
    """
    scope: dict[str, str] = {}
    for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _ASSIGN_RE.match(line)
        if not m:
            raise ConfigParseError(f"{path}:{lineno}: cannot parse line: {raw!r}")
        key = m.group("key")
        raw_val = _strip_quotes(m.group("value"))
        try:
            value = _expand_vars(raw_val, scope)
        except ConfigParseError as e:
            raise ConfigParseError(f"{path}:{lineno}: {e}") from None
        scope[key] = value
    return scope


# Pydantic model. Fields use SHOUTY_SNAKE_CASE to match mitm.conf 1:1
# (no aliasing dance) — this is a config DTO, not a public API.
ProxyMode = Literal["mitmproxy", "sslsplit", "certmitm", "sslstrip", "intercept", "none"]


class MitmConfig(BaseModel):
    """Validated MITM Beast configuration.

    Field names match the keys in ``mitm.conf``. Unknown keys raise on
    load — typos in the config file surface as validation errors.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    # ----- Internal / runtime
    DNSMASQ_CONF: str = "tmp_dnsmasq.conf"
    HOSTAPD_CONF: str = "tmp_hostapd.conf"
    TCPDUMP_ENABLED: bool = False

    # ----- Network interfaces
    BR_IFACE: str = "br0"
    WAN_IFACE: str = "eth0"
    LAN_IFACE: str = "eth1"
    WIFI_IFACE: str = "wlan0"

    # ----- WiFi AP
    WIFI_SSID: str
    WIFI_PASSWORD: Annotated[str, Field(min_length=8, max_length=63)]

    # ----- LAN
    LAN_IP: IPv4Address
    LAN_SUBNET: str
    LAN_DHCP_START: IPv4Address
    LAN_DHCP_END: IPv4Address

    # ----- WAN (empty WAN_STATIC_IP = DHCP)
    WAN_STATIC_IP: str = ""
    WAN_STATIC_NETMASK: str = "255.255.255.0"
    WAN_STATIC_GATEWAY: str = ""
    WAN_STATIC_DNS: str = ""

    # ----- Default proxy
    PROXY_MODE: ProxyMode = "mitmproxy"

    # ----- mitmproxy
    MITMPROXY_PORT: int = 8081
    MITMPROXY_WEB_PORT: int = 8080
    MITMPROXY_WEB_HOST: str = "0.0.0.0"   # noqa: S104 — intentional bind-all default
    MITMPROXY_WEB_PASSWORD: str

    # ----- sslsplit
    SSLSPLIT_PORT: int = 8081
    SSLSPLIT_PCAP_DIR: str = "./sslsplit_logs"

    # ----- certmitm
    CERTMITM_PATH: str = "/opt/certmitm/certmitm.py"
    CERTMITM_PORT: int = 8081
    CERTMITM_WORKDIR: str = "./certmitm_logs"
    CERTMITM_VERBOSE: bool = True
    CERTMITM_SHOW_DATA: bool = True
    CERTMITM_TEST_DOMAINS: str = ""
    CERTMITM_PASSTHROUGH_DOMAINS: str = ""

    # ----- sslstrip
    SSLSTRIP_PORT: int = 10000
    SSLSTRIP_FAKE_SERVER_PORT: int = 80
    SSLSTRIP_FAKE_SERVER_SCRIPT: str = "./fake-firmware-server.py"
    SSLSTRIP_LOG_FILE: str = "tmp_sslstrip.log"
    SSLSTRIP_TEST_DOMAINS: str = ""
    SSLSTRIP_PASSTHROUGH_DOMAINS: str = ""

    # ----- intercept
    INTERCEPT_PORT: int = 8081
    INTERCEPT_FAKE_SERVER_PORT: int = 8443
    INTERCEPT_FAKE_SERVER_SCRIPT: str = "./fake-firmware-server.py"
    INTERCEPT_DOMAINS: str = ""
    INTERCEPT_PASSTHROUGH_DOMAINS: str = ""

    # ----- Delorean NTP spoofing
    DELOREAN_PATH: str = "./delorean/delorean.py"

    # ----- tcpdump
    TCPDUMP_IFACE: str = "br0"
    TCPDUMP_OPTIONS: str = "-s 0"
    TCPDUMP_DIR: str = "./captures"

    @field_validator("WAN_STATIC_IP")
    @classmethod
    def _wan_static_ip_optional(cls, v: str) -> str:
        # Empty = DHCP. Non-empty must be a valid IPv4.
        if v:
            IPv4Address(v)  # raises ValueError if malformed
        return v

    @field_validator("LAN_SUBNET", "WAN_STATIC_NETMASK")
    @classmethod
    def _validate_netmask(cls, v: str) -> str:
        # Dotted-quad. Don't enforce contiguous bits — some labs use weird masks.
        IPv4Address(v)
        return v

    @field_validator("MITMPROXY_PORT", "MITMPROXY_WEB_PORT", "SSLSPLIT_PORT",
                      "CERTMITM_PORT", "SSLSTRIP_PORT", "SSLSTRIP_FAKE_SERVER_PORT",
                      "INTERCEPT_PORT", "INTERCEPT_FAKE_SERVER_PORT")
    @classmethod
    def _port_range(cls, v: int) -> int:
        if not 1 <= v <= 65535:
            raise ValueError(f"port {v} out of range 1-65535")
        return v


def load_config(path: str | Path) -> MitmConfig:
    """Parse and validate ``mitm.conf`` at ``path``."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"config not found: {p}")
    raw = parse_conf(p)
    return MitmConfig(**raw)
