"""iptables ``MITM_*`` chain management — subprocess-based.

**Design note (April 2026):** Q6 of PYTHON_TUI_PLAN locked in
``python-iptables`` (``iptc``) as the iptables library. During P2.7
integration testing on Kali we discovered that ``iptc`` only talks to
the **legacy** iptables backend (``iptables-legacy``) but Kali — and
modern Debian/Ubuntu — default ``iptables`` to ``iptables-nft``.
Rules created via iptc end up in a completely separate kernel
namespace from rules created by the bash scripts (and from anything
else running on the host). That divergence is unworkable.

We therefore shell out to the ``iptables`` binary directly. The system
``update-alternatives`` choice (legacy vs nft) is honoured, and we end
up in the same namespace as ``mitm.sh``'s legacy bash invocations
during the v1.x → v2.x transition. Per-call overhead is tens of
milliseconds; we add rules at most a few times per ``up`` and never in
the hot path, so the cost is irrelevant.

The public API matches what was originally drafted with iptc — only
the implementation changed. The ``python-iptables`` dependency in
``pyproject.toml`` is no longer used and will be removed in a
follow-up commit.

Operations require root (CAP_NET_ADMIN).
"""
from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass

__all__ = [
    "FirewallError",
    "Hook",
    "MITM_HOOKS",
    "MITM_NTP_HOOK",
    "add_dnat_ntp",
    "add_forward_established",
    "add_forward_lan_to_wan",
    "add_masquerade",
    "add_redirect",
    "chain_exists",
    "chain_packet_counts",
    "chain_rules_text",
    "create_chain",
    "delete_chain",
    "flush_chain",
    "hook_chain",
    "install_mitm_chains",
    "install_ntp_chain",
    "uninstall_mitm_chains",
    "uninstall_ntp_chain",
    "unhook_chain",
]


class FirewallError(RuntimeError):
    """Raised when an iptables operation fails."""


@dataclass(frozen=True, slots=True)
class Hook:
    """A jump from a built-in chain into one of our MITM chains."""

    table: str       # "nat" or "filter"
    builtin: str     # "PREROUTING", "POSTROUTING", "FORWARD"
    target: str      # "MITM_NAT_PRE", etc.


MITM_HOOKS: tuple[Hook, ...] = (
    Hook(table="nat",    builtin="PREROUTING",  target="MITM_NAT_PRE"),
    Hook(table="nat",    builtin="POSTROUTING", target="MITM_NAT_POST"),
    Hook(table="filter", builtin="FORWARD",     target="MITM_FWD"),
)

MITM_NTP_HOOK: Hook = Hook(table="nat", builtin="PREROUTING", target="MITM_NTP_PRE")


# ----------------------------------------------------------------------
# Subprocess plumbing
# ----------------------------------------------------------------------

def _run(argv: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Invoke ``iptables`` (or another shell command) and return the result.

    Uses ``check=True`` by default — non-zero exit raises FirewallError
    with the captured stderr. The caller can pass ``check=False`` for
    operations where a non-zero exit is benign (chain already exists,
    rule not found, etc.) and inspect the return code itself.
    """
    try:
        return subprocess.run(
            list(argv),
            check=check,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        raise FirewallError(
            f"{' '.join(argv)} -> exit {e.returncode}: {e.stderr.strip() or '(no stderr)'}"
        ) from e


def _ipt(*args: str, table: str | None = None,
         check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run ``iptables`` with optional ``-t TABLE`` prefix."""
    argv: list[str] = ["iptables"]
    if table is not None:
        argv += ["-t", table]
    argv.extend(args)
    return _run(argv, check=check)


def _table_check(table: str) -> str:
    if table not in ("nat", "filter"):
        raise FirewallError(f"unknown table {table!r}")
    return table


# ----------------------------------------------------------------------
# Low-level chain operations
# ----------------------------------------------------------------------

def chain_exists(table: str, chain: str) -> bool:
    """``iptables -t table -L chain`` returns 0 if the chain exists."""
    _table_check(table)
    r = _ipt("-L", chain, "-n", table=table, check=False)
    return r.returncode == 0


def create_chain(table: str, chain: str) -> None:
    """Create ``chain``. Idempotent — re-creating an existing chain is a no-op."""
    _table_check(table)
    if chain_exists(table, chain):
        return
    _ipt("-N", chain, table=table)


def flush_chain(table: str, chain: str) -> None:
    """Empty ``chain``. No-op if the chain doesn't exist."""
    _table_check(table)
    if not chain_exists(table, chain):
        return
    _ipt("-F", chain, table=table)


def delete_chain(table: str, chain: str) -> None:
    """Delete ``chain``. No-op if missing.

    iptables refuses to delete a chain that's still referenced; the
    caller must :func:`unhook_chain` first.
    """
    _table_check(table)
    if not chain_exists(table, chain):
        return
    _ipt("-X", chain, table=table)


def chain_rules_text(table: str, chain: str) -> list[str]:
    """Return the chain's rules as ``-A`` lines from ``iptables-save``.

    Each entry is the line as iptables-save would print it (one per
    rule). Empty list if the chain doesn't exist or is empty.
    """
    _table_check(table)
    if not chain_exists(table, chain):
        return []
    r = _ipt("-S", chain, table=table)
    out: list[str] = []
    for line in r.stdout.splitlines():
        line = line.strip()
        # First line of -S output is `-N CHAIN`; we want the rule lines.
        if line.startswith("-A "):
            out.append(line)
    return out


def chain_packet_counts(table: str, chain: str) -> list[tuple[int, int]]:
    """Return ``[(packets, bytes), …]`` per rule in ``chain``.

    Counters surface in the TUI Dashboard for live observability.
    """
    _table_check(table)
    if not chain_exists(table, chain):
        return []
    r = _ipt("-L", chain, "-n", "-v", "-x", table=table)
    counts: list[tuple[int, int]] = []
    for line in r.stdout.splitlines():
        parts = line.split()
        # iptables -L -n -v -x output:
        #   pkts bytes target prot opt in out source destination ...
        # First two columns are integers when the line is a rule.
        if len(parts) < 2:
            continue
        try:
            counts.append((int(parts[0]), int(parts[1])))
        except ValueError:
            # Header lines ("Chain X (...)", "pkts bytes ...") — skip.
            continue
    return counts


# ----------------------------------------------------------------------
# Hook management
# ----------------------------------------------------------------------

def hook_chain(table: str, builtin: str, target: str) -> None:
    """Insert ``-j target`` at the top of ``builtin``. Idempotent.

    Uses ``-C`` to check first; only inserts if the rule is not already
    present.
    """
    _table_check(table)
    check = _ipt("-C", builtin, "-j", target, table=table, check=False)
    if check.returncode == 0:
        return  # already hooked
    _ipt("-I", builtin, "-j", target, table=table)


def unhook_chain(table: str, builtin: str, target: str) -> None:
    """Remove every ``-j target`` rule from ``builtin``. Idempotent.

    iptables exits non-zero when the rule isn't present, which we
    treat as success — the goal state is "no such rule".
    """
    _table_check(table)
    # There may be multiple copies (shouldn't happen with our
    # idempotent install, but be defensive). Loop until -D fails.
    while True:
        r = _ipt("-D", builtin, "-j", target, table=table, check=False)
        if r.returncode != 0:
            return


# ----------------------------------------------------------------------
# High-level: install / uninstall the MITM chain set
# ----------------------------------------------------------------------

def install_mitm_chains() -> None:
    """Create + hook all MITM_* chains. Idempotent."""
    for h in MITM_HOOKS:
        create_chain(h.table, h.target)
        flush_chain(h.table, h.target)
        hook_chain(h.table, h.builtin, h.target)


def uninstall_mitm_chains() -> None:
    """Unhook + flush + delete all MITM_* chains. Idempotent."""
    for h in MITM_HOOKS:
        unhook_chain(h.table, h.builtin, h.target)
    for h in MITM_HOOKS:
        flush_chain(h.table, h.target)
        delete_chain(h.table, h.target)


def install_ntp_chain() -> None:
    """Create + hook the Delorean MITM_NTP_PRE chain. Idempotent."""
    h = MITM_NTP_HOOK
    create_chain(h.table, h.target)
    flush_chain(h.table, h.target)
    hook_chain(h.table, h.builtin, h.target)


def uninstall_ntp_chain() -> None:
    """Unhook + flush + delete MITM_NTP_PRE. Idempotent."""
    h = MITM_NTP_HOOK
    unhook_chain(h.table, h.builtin, h.target)
    flush_chain(h.table, h.target)
    delete_chain(h.table, h.target)


# ----------------------------------------------------------------------
# Mode-specific rule helpers
# ----------------------------------------------------------------------

def add_masquerade(wan_iface: str) -> None:
    """``-A MITM_NAT_POST -o WAN_IFACE -j MASQUERADE``."""
    _ipt("-A", "MITM_NAT_POST", "-o", wan_iface, "-j", "MASQUERADE",
         table="nat")


def add_forward_established() -> None:
    """``-A MITM_FWD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT``."""
    _ipt("-A", "MITM_FWD",
         "-m", "conntrack",
         "--ctstate", "RELATED,ESTABLISHED",
         "-j", "ACCEPT")


def add_forward_lan_to_wan(bridge: str, wan_iface: str) -> None:
    """``-A MITM_FWD -i bridge -o wan_iface -j ACCEPT``."""
    _ipt("-A", "MITM_FWD",
         "-i", bridge, "-o", wan_iface,
         "-j", "ACCEPT")


def add_redirect(
    *,
    in_iface: str,
    dst: str | None,
    dport: int,
    to_port: int,
    protocol: str = "tcp",
    chain: str = "MITM_NAT_PRE",
) -> None:
    """``-A chain -i in -p protocol [-d dst] --dport dport -j REDIRECT --to-ports to_port``."""
    args = ["-A", chain, "-i", in_iface, "-p", protocol]
    if dst is not None:
        args += ["-d", dst]
    args += ["--dport", str(dport),
             "-j", "REDIRECT",
             "--to-ports", str(to_port)]
    _ipt(*args, table="nat")


def add_dnat_ntp(*, in_iface: str, router_ip: str, dst: str | None = None) -> None:
    """Delorean NTP DNAT: redirect UDP/123 to local NTP spoofer."""
    args = ["-A", "MITM_NTP_PRE", "-i", in_iface, "-p", "udp"]
    if dst is not None:
        args += ["-d", dst]
    args += ["--dport", "123",
             "-j", "DNAT",
             "--to-destination", f"{router_ip}:123"]
    _ipt(*args, table="nat")
