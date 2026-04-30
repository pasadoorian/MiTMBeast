"""Click-based CLI entry point.

Subcommands map 1:1 to the bash scripts they are replacing:

    mitmbeast up         <-> mitm.sh up
    mitmbeast down       <-> mitm.sh down
    mitmbeast reload     <-> mitm.sh reload
    mitmbeast restore    <-> mitm.sh restore
    mitmbeast spoof ...  <-> dns-spoof.sh
    mitmbeast delorean ...  <-> delorean.sh
    mitmbeast tui        <-> (new in Phase 2d)

Phase 2a wires every command to its corresponding bash script via
:func:`_run_legacy` so external behavior matches v1.1 exactly. Phases
2b–2d replace each underlying script with a pure-Python implementation;
the click commands' user-facing surface stays the same.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import click

from mitmbeast import __version__

# Repo root contains the legacy bash scripts. cli.py lives at
# <root>/src/mitmbeast/cli.py — three parents up.
REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_legacy(script: str, *args: str) -> int:
    """Run a legacy bash script, inheriting stdio. Returns its exit code.

    Tests monkeypatch this function to capture argv without forking.
    """
    argv = [str(REPO_ROOT / script), *args]
    return subprocess.call(argv)


# ----------------------------------------------------------------------
# Top-level group
# ----------------------------------------------------------------------

@click.group(context_settings={"help_option_names": ["-h", "--help"]},
             invoke_without_command=True)
@click.version_option(__version__, "-V", "--version")
@click.pass_context
def main(ctx: click.Context) -> None:
    """MITM Beast — Wi-Fi MITM lab for firmware-device security testing.

    Run with no subcommand to open the Textual TUI. Pass a subcommand
    (up, down, spoof, …) to run that command directly.
    """
    if ctx.invoked_subcommand is None:
        ctx.invoke(tui)


# ----------------------------------------------------------------------
# Router lifecycle: up / down / reload / restore
# ----------------------------------------------------------------------

_MODES = ["mitmproxy", "sslsplit", "certmitm", "sslstrip", "intercept", "none"]


def _router_args(
    mode: str | None, keep_wan: bool, capture: bool, action: str,
) -> list[str]:
    args = [action]
    if mode:
        args += ["-m", mode]
    if keep_wan:
        args.append("-k")
    if capture:
        args.append("-c")
    return args


@main.command()
@click.option("-m", "--mode", type=click.Choice(_MODES), help="Proxy mode")
@click.option("-k", "--keep-wan", is_flag=True,
              help="Preserve WAN interface (keeps SSH alive)")
@click.option("-c", "--capture", is_flag=True,
              help="Enable packet capture on bridge")
@click.option("--python", "use_python", is_flag=True,
              help="Use the Python core instead of the legacy bash dispatch. "
                   "All six modes (none, mitmproxy, sslsplit, sslstrip, "
                   "certmitm, intercept) are supported natively.")
def up(mode: str | None, keep_wan: bool, capture: bool, use_python: bool) -> None:
    """Start the MITM router."""
    if use_python:
        sys.exit(_python_up(mode, keep_wan, capture))
    sys.exit(_run_legacy("mitm.sh", *_router_args(mode, keep_wan, capture, "up")))


@main.command()
@click.option("-k", "--keep-wan", is_flag=True,
              help="Preserve WAN interface (keeps SSH alive)")
@click.option("--python", "use_python", is_flag=True,
              help="Use the Python core (P2.9b+) instead of the legacy bash.")
def down(keep_wan: bool, use_python: bool) -> None:
    """Stop the MITM router."""
    if use_python:
        sys.exit(_python_down(keep_wan))
    args = ["down"]
    if keep_wan:
        args.append("-k")
    sys.exit(_run_legacy("mitm.sh", *args))


# ---- Python-stack dispatch -------------------------------------------

def _python_up(mode: str | None, keep_wan: bool, capture: bool) -> int:
    """Drive ``core.router.router_up`` from the CLI."""
    from mitmbeast.core.config import load_config
    from mitmbeast.core.router import RouterError, router_up
    cfg_path = REPO_ROOT / "mitm.conf"
    if not cfg_path.is_file():
        click.echo(f"Error: {cfg_path} not found", err=True)
        return 1
    cfg = load_config(cfg_path)
    try:
        router_up(cfg, mode=mode or "none", keep_wan=keep_wan,
                  capture=capture)
    except RouterError as e:
        click.echo(f"Error: {e}", err=True)
        return 1
    except PermissionError as e:
        click.echo(f"Error: {e}", err=True)
        return 1
    return 0


def _python_down(keep_wan: bool) -> int:
    """Drive ``core.router.router_down`` from the CLI."""
    from mitmbeast.core.config import load_config
    from mitmbeast.core.router import router_down
    cfg_path = REPO_ROOT / "mitm.conf"
    if not cfg_path.is_file():
        click.echo(f"Error: {cfg_path} not found", err=True)
        return 1
    cfg = load_config(cfg_path)
    try:
        router_down(cfg, keep_wan=keep_wan)
    except PermissionError as e:
        click.echo(f"Error: {e}", err=True)
        return 1
    return 0


@main.command()
@click.option("-m", "--mode", type=click.Choice(_MODES), help="Proxy mode")
@click.option("-k", "--keep-wan", is_flag=True)
@click.option("-c", "--capture", is_flag=True)
def reload(mode: str | None, keep_wan: bool, capture: bool) -> None:
    """Stop then start (down + up)."""
    sys.exit(_run_legacy("mitm.sh", *_router_args(mode, keep_wan, capture, "reload")))


@main.command()
@click.option("--manager",
              type=click.Choice(["NetworkManager", "systemd-networkd", "none"]),
              help="Non-interactive choice of network manager to re-enable")
@click.option("--python", "use_python", is_flag=True,
              help="Use the Python core (P2.14+) instead of the legacy bash.")
def restore(manager: str | None, use_python: bool) -> None:
    """Restore the host to a normal Linux configuration."""
    if use_python:
        sys.exit(_python_restore(manager))
    args = ["restore"]
    if manager:
        args += ["--manager", manager]
    sys.exit(_run_legacy("mitm.sh", *args))


def _python_restore(manager: str | None) -> int:
    from mitmbeast.core.restore import RestoreError, restore_host
    try:
        restore_host(manager=manager)  # type: ignore[arg-type]
    except (RestoreError, PermissionError) as e:
        click.echo(f"Error: {e}", err=True)
        return 1
    return 0


# ----------------------------------------------------------------------
# DNS spoofing
# ----------------------------------------------------------------------

@main.group()
def spoof() -> None:
    """Manage dnsmasq DNS-spoof entries."""


@spoof.command("add")
@click.argument("domain")
@click.argument("ip")
@click.option("--force", is_flag=True,
              help="Suppress passthrough-domain warning")
def spoof_add(domain: str, ip: str, force: bool) -> None:
    """Add a DNS spoof: domain -> ip (IPv4 or IPv6)."""
    args = ["add", domain, ip]
    if force:
        args.append("--force")
    sys.exit(_run_legacy("dns-spoof.sh", *args))


@spoof.command("rm")
@click.argument("domain")
def spoof_rm(domain: str) -> None:
    """Remove a DNS spoof for the given domain."""
    sys.exit(_run_legacy("dns-spoof.sh", "rm", domain))


@spoof.command("list")
def spoof_list() -> None:
    """List active DNS spoof entries."""
    sys.exit(_run_legacy("dns-spoof.sh", "list"))


@spoof.command("reload")
def spoof_reload() -> None:
    """Restart dnsmasq to apply config changes."""
    sys.exit(_run_legacy("dns-spoof.sh", "reload"))


@spoof.command("flush")
def spoof_flush() -> None:
    """Clear dnsmasq cache (SIGHUP)."""
    sys.exit(_run_legacy("dns-spoof.sh", "flush"))


@spoof.command("dump")
@click.argument("domain", required=False)
def spoof_dump(domain: str | None) -> None:
    """Dump cache stats; optionally test a domain."""
    args = ["dump"]
    if domain:
        args.append(domain)
    sys.exit(_run_legacy("dns-spoof.sh", *args))


@spoof.command("logs")
@click.argument("count", required=False, default="50")
def spoof_logs(count: str) -> None:
    """Show last N DNS queries from syslog (default 50)."""
    sys.exit(_run_legacy("dns-spoof.sh", "logs", count))


# ----------------------------------------------------------------------
# Delorean NTP spoofing
# ----------------------------------------------------------------------

@main.group()
def delorean() -> None:
    """Delorean NTP-spoofing controls."""


@delorean.command("start")
@click.argument("offset", required=False, default="+1000")
@click.option("--python", "use_python", is_flag=True,
              help="Use the Python core (P2.12+) instead of legacy bash.")
def delorean_start(offset: str, use_python: bool) -> None:
    """Start Delorean. OFFSET is +DAYS / -DAYS / 'YYYY-MM-DD'."""
    if use_python:
        sys.exit(_python_delorean_start(offset))
    sys.exit(_run_legacy("delorean.sh", "start", offset))


@delorean.command("stop")
@click.option("--python", "use_python", is_flag=True,
              help="Use the Python core (P2.12+) instead of legacy bash.")
def delorean_stop(use_python: bool) -> None:
    """Stop Delorean and remove iptables NTP redirects."""
    if use_python:
        sys.exit(_python_delorean_stop())
    sys.exit(_run_legacy("delorean.sh", "stop"))


@delorean.command("status")
@click.option("--python", "use_python", is_flag=True,
              help="Use the Python core (P2.12+) instead of legacy bash.")
def delorean_status(use_python: bool) -> None:
    """Show Delorean status."""
    if use_python:
        sys.exit(_python_delorean_status())
    sys.exit(_run_legacy("delorean.sh", "status"))


@delorean.command("reload")
@click.argument("offset", required=False)
@click.option("--python", "use_python", is_flag=True,
              help="Use the Python core (P2.12+) instead of legacy bash.")
def delorean_reload(offset: str | None, use_python: bool) -> None:
    """Restart Delorean."""
    if use_python:
        rc = _python_delorean_stop()
        if rc != 0:
            sys.exit(rc)
        sys.exit(_python_delorean_start(offset or "+1000"))
    args = ["reload"]
    if offset:
        args.append(offset)
    sys.exit(_run_legacy("delorean.sh", *args))


@delorean.command("set")
@click.argument("offset")
def delorean_set(offset: str) -> None:
    """Change time offset (restarts if running)."""
    sys.exit(_run_legacy("delorean.sh", "set", offset))


def _load_cfg_for_delorean():  # type: ignore[no-untyped-def]
    from mitmbeast.core.config import load_config
    cfg_path = REPO_ROOT / "mitm.conf"
    if not cfg_path.is_file():
        click.echo(f"Error: {cfg_path} not found", err=True)
        sys.exit(1)
    return load_config(cfg_path)


def _python_delorean_start(offset: str) -> int:
    from mitmbeast.core import delorean as _del
    cfg = _load_cfg_for_delorean()
    try:
        state = _del.start(cfg, offset=offset)
    except (_del.DeloreanError, PermissionError) as e:
        click.echo(f"Error: {e}", err=True)
        return 1
    click.echo(f"Delorean started (PID {state.pid})")
    click.echo(f"  offset: {state.offset}")
    click.echo(f"  target date: {state.target_date}")
    click.echo("  iptables: MITM_NTP_PRE chain installed")
    return 0


def _python_delorean_stop() -> int:
    from mitmbeast.core import delorean as _del
    try:
        _del.stop()
    except (_del.DeloreanError, PermissionError) as e:
        click.echo(f"Error: {e}", err=True)
        return 1
    click.echo("Delorean stopped; MITM_NTP_PRE removed.")
    return 0


def _python_delorean_status() -> int:
    from mitmbeast.core import delorean as _del
    s = _del.status()
    click.echo(f"running:         {s.running}")
    if s.pid is not None:
        click.echo(f"pid:             {s.pid}")
    click.echo(f"offset:          {s.offset or '(unset)'}")
    click.echo(f"target date:     {s.target_date or '(unset)'}")
    click.echo(f"iptables active: {s.iptables_active}")
    return 0


# ----------------------------------------------------------------------
# Textual TUI — placeholder until Phase 2d
# ----------------------------------------------------------------------

@main.command()
def tui() -> None:
    """Launch the Textual TUI."""
    from mitmbeast.tui.app import MitmBeastApp
    MitmBeastApp().run()


if __name__ == "__main__":
    main()
