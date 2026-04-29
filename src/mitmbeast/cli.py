"""Click-based CLI entry point.

Subcommands map 1:1 to the bash scripts they are replacing:
    mitmbeast up         <- mitm.sh up
    mitmbeast down       <- mitm.sh down
    mitmbeast restore    <- mitm.sh restore
    mitmbeast spoof      <- dns-spoof.sh
    mitmbeast delorean   <- delorean.sh
    mitmbeast tui        <- (new)

During Phase 2a the implementations shell out to the existing bash
scripts. Phase 2b replaces each one with a pure-Python module.
"""
from __future__ import annotations

import sys

import click

from mitmbeast import __version__


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version")
def main() -> None:
    """MITM Beast — Wi-Fi MITM lab for firmware-device security testing."""


@main.command()
@click.option("-m", "--mode",
              type=click.Choice(["mitmproxy", "sslsplit", "certmitm",
                                 "sslstrip", "intercept", "none"]),
              help="Proxy mode")
@click.option("-k", "--keep-wan", is_flag=True,
              help="Preserve WAN interface (keeps SSH alive)")
@click.option("-c", "--capture", is_flag=True,
              help="Enable packet capture on bridge")
def up(mode: str | None, keep_wan: bool, capture: bool) -> None:
    """Start the MITM router."""
    click.echo(f"[stub] up: mode={mode} keep_wan={keep_wan} capture={capture}")
    sys.exit(0)


@main.command()
@click.option("-k", "--keep-wan", is_flag=True,
              help="Preserve WAN interface (keeps SSH alive)")
def down(keep_wan: bool) -> None:
    """Stop the MITM router."""
    click.echo(f"[stub] down: keep_wan={keep_wan}")
    sys.exit(0)


@main.command()
@click.option("-m", "--mode",
              type=click.Choice(["mitmproxy", "sslsplit", "certmitm",
                                 "sslstrip", "intercept", "none"]),
              help="Proxy mode")
@click.option("-k", "--keep-wan", is_flag=True)
@click.option("-c", "--capture", is_flag=True)
def reload(mode: str | None, keep_wan: bool, capture: bool) -> None:
    """Stop then start (down + up)."""
    click.echo(f"[stub] reload: mode={mode}")


@main.command()
@click.option("--manager",
              type=click.Choice(["NetworkManager", "systemd-networkd", "none"]),
              help="Non-interactive choice of network manager to re-enable")
def restore(manager: str | None) -> None:
    """Restore the host to a normal Linux configuration."""
    click.echo(f"[stub] restore: manager={manager}")


@main.group()
def spoof() -> None:
    """Manage dnsmasq DNS-spoof entries."""


@spoof.command("add")
@click.argument("domain")
@click.argument("ip")
@click.option("--force", is_flag=True,
              help="Suppress passthrough-domain warning")
def spoof_add(domain: str, ip: str, force: bool) -> None:
    click.echo(f"[stub] spoof add: {domain} -> {ip}  force={force}")


@spoof.command("rm")
@click.argument("domain")
def spoof_rm(domain: str) -> None:
    click.echo(f"[stub] spoof rm: {domain}")


@spoof.command("list")
def spoof_list() -> None:
    click.echo("[stub] spoof list")


@main.group()
def delorean() -> None:
    """Delorean NTP-spoofing controls."""


@delorean.command("start")
@click.argument("offset", required=False, default="+1000")
def delorean_start(offset: str) -> None:
    click.echo(f"[stub] delorean start: {offset}")


@delorean.command("stop")
def delorean_stop() -> None:
    click.echo("[stub] delorean stop")


@delorean.command("status")
def delorean_status() -> None:
    click.echo("[stub] delorean status")


@main.command()
def tui() -> None:
    """Launch the Textual TUI."""
    click.echo("[stub] tui — Textual interface lands in Phase 2d.")


if __name__ == "__main__":
    main()
