"""Restore the host to a normal Linux configuration.

Python port of the v1.1 ``mitm.sh restore`` subcommand (Phase 1 M1.1).

The router intentionally **disables** ``NetworkManager`` /
``systemd-networkd`` / ``systemd-resolved`` on ``up`` and does not
re-enable them on ``down`` — the design is "dedicated machine" with
an explicit repurpose step. ``restore_host`` is that step:

* re-enable a chosen network manager (``NetworkManager`` or
  ``systemd-networkd``)
* if NM is chosen, also enable ``systemd-resolved`` (NM uses it for
  DNS by default on most modern distros)
* restore ``/etc/resolv.conf`` from the backup made at ``up`` time
* remove any leftover ``MITM_*`` iptables chains (proxy + NTP)

This is callable both interactively and headlessly. The CLI's
``--python`` path uses :func:`restore_host` directly.
"""
from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from mitmbeast.core import firewall
from mitmbeast.core.system import require_root

__all__ = [
    "RestoreError",
    "Manager",
    "available_managers",
    "restore_host",
]


Manager = Literal["NetworkManager", "systemd-networkd", "none"]
_ALL_MANAGERS: tuple[str, ...] = ("NetworkManager", "systemd-networkd",
                                  "systemd-resolved")
_RESOLV_BACKUP = Path("/etc/resolv.conf.backup")
_RESOLV_SYMLINK_MARK = Path("/run/mitmbeast/resolv_was_symlink_to")


class RestoreError(RuntimeError):
    """Raised when an explicit user input is required but absent."""


def available_managers() -> list[str]:
    """Return the subset of recognised units that have unit files installed."""
    out = []
    for unit in _ALL_MANAGERS:
        try:
            r = subprocess.run(
                ["systemctl", "list-unit-files", "--no-pager", "--no-legend",
                 f"{unit}.service"],
                check=False, capture_output=True, text=True,
            )
        except FileNotFoundError:
            return []
        if any(line.strip().startswith(f"{unit}.service")
               for line in r.stdout.splitlines()):
            out.append(unit)
    return out


def restore_host(
    *,
    manager: Manager | None = None,
    prompt: Callable[[str], str] | None = None,
) -> None:
    """Bring the host back to a normal Linux configuration.

    :param manager: explicit choice. When ``None`` we ask via
        :func:`prompt` (which defaults to ``input``). Passing
        ``"none"`` skips the service-enable step.
    :param prompt: function to call when interactive input is needed.
        Tests inject a stub; the CLI uses :func:`input`.
    """
    require_root()
    print("== Restoring host to a normal Linux configuration")

    available = available_managers()
    if not available:
        raise RestoreError(
            "no recognized network manager installed (looked for "
            "NetworkManager, systemd-networkd, systemd-resolved)"
        )

    chosen = _resolve_manager(manager, available, prompt)

    if chosen != "none":
        print(f"   Enabling and starting {chosen}...")
        _enable_unit(chosen)
        if chosen == "NetworkManager" and "systemd-resolved" in available:
            print("   Also enabling systemd-resolved (NM uses it for DNS)...")
            _enable_unit("systemd-resolved")
    else:
        print("   (skipping service enable — chose 'none')")

    print("   Restoring /etc/resolv.conf...")
    _restore_resolv_conf()

    print("   Removing MITM iptables chains...")
    firewall.uninstall_mitm_chains()
    firewall.uninstall_ntp_chain()

    print()
    print("== restore complete")
    print()
    print("Sanity checks:")
    print("  ip -br addr")
    print("  cat /etc/resolv.conf")
    print("  ping 1.1.1.1")


# ----------------------------------------------------------------------
# Internals
# ----------------------------------------------------------------------

def _resolve_manager(
    manager: Manager | None,
    available: list[str],
    prompt: Callable[[str], str] | None,
) -> str:
    """Resolve to a concrete manager name (or 'none')."""
    if manager is not None:
        if manager not in ("NetworkManager", "systemd-networkd", "none"):
            raise RestoreError(
                f"--manager must be NetworkManager, systemd-networkd, or none "
                f"(got {manager!r})"
            )
        return manager

    # Interactive path — only works if we have a TTY (or a custom prompt
    # function from tests).
    if prompt is None:
        if not sys.stdin.isatty():
            raise RestoreError(
                "not running in a TTY and --manager was not provided.\n"
                "Use: mitmbeast restore --python --manager "
                "<NetworkManager|systemd-networkd|none>"
            )
        prompt = input

    print()
    print("Network managers installed on this host:")
    for i, unit in enumerate(available, start=1):
        print(f"  [{i}] {unit}")
    print("  [n] none — skip enabling any network manager")
    print()
    answer = prompt(f"Pick the one to re-enable [1-{len(available)} or n]: ")
    answer = answer.strip().lower()
    if answer in ("n", "none", ""):
        return "none"
    if answer.isdigit():
        idx = int(answer)
        if 1 <= idx <= len(available):
            return available[idx - 1]
    raise RestoreError(f"invalid choice {answer!r}")


def _enable_unit(unit: str) -> None:
    """``systemctl enable --now <unit>``."""
    try:
        subprocess.run(
            ["systemctl", "enable", "--now", unit],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as e:
        raise RestoreError(
            f"systemctl enable --now {unit} failed: "
            f"{e.stderr.strip() or e}"
        ) from e


def _restore_resolv_conf() -> None:
    """Inverse of router._backup_resolv_conf — see core.router."""
    target = Path("/etc/resolv.conf")
    if _RESOLV_SYMLINK_MARK.is_file():
        link_target = _RESOLV_SYMLINK_MARK.read_text().strip()
        if target.exists() or target.is_symlink():
            target.unlink()
        target.symlink_to(link_target)
        _RESOLV_SYMLINK_MARK.unlink()
        return
    if _RESOLV_BACKUP.is_file():
        _RESOLV_BACKUP.replace(target)
