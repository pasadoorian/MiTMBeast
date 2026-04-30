"""tcpdump packet-capture lifecycle.

Starts ``tcpdump`` on the bridge interface (``cfg.TCPDUMP_IFACE``,
default ``br0``) and writes a unique-named pcap under ``cfg.TCPDUMP_DIR``
(default ``./captures``). Mirrors the v1.1 ``mitm.sh`` capture flow but
runs as a managed subprocess like the other Python-core daemons.

Public surface:

* :func:`start` — spawn tcpdump, return a :class:`TcpdumpSession`.
* :func:`stop`  — SIGTERM with SIGKILL fallback, no-op if dead.

The orchestrator (``core.router``) is responsible for persisting PID
and pcap path under ``/run/mitmbeast/`` so ``down`` can clean up.
"""
from __future__ import annotations

import os
import secrets
import shlex
import signal
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from mitmbeast.core.config import MitmConfig

__all__ = [
    "TcpdumpError",
    "TcpdumpSession",
    "start",
    "stop",
]


class TcpdumpError(RuntimeError):
    """Raised when tcpdump fails to start."""


@dataclass(frozen=True, slots=True)
class TcpdumpSession:
    pid: int
    pcap_path: Path


def start(
    cfg: MitmConfig,
    *,
    output_dir: Path | None = None,
    tcpdump_binary: str = "tcpdump",
) -> TcpdumpSession:
    """Spawn tcpdump on ``cfg.TCPDUMP_IFACE`` writing to a fresh pcap.

    Output directory: ``output_dir`` if given, else ``cfg.TCPDUMP_DIR``.
    The orchestrator (``core.router``) passes an absolute path so the
    pcap doesn't land relative to whatever CWD ``sudo`` happened to
    have. The pcap filename mirrors the bash convention:
    ``<iface>_<YYYYMMDD_HHMMSS>_<4-hex>.pcap`` so multiple captures
    in the same second don't collide.
    """
    out_dir = output_dir if output_dir is not None else Path(cfg.TCPDUMP_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")  # noqa: DTZ005
    session_id = secrets.token_hex(2)
    pcap_path = out_dir / f"{cfg.TCPDUMP_IFACE}_{timestamp}_{session_id}.pcap"

    cmd = [tcpdump_binary, "-i", cfg.TCPDUMP_IFACE]
    if cfg.TCPDUMP_OPTIONS.strip():
        cmd += shlex.split(cfg.TCPDUMP_OPTIONS)
    cmd += ["-w", str(pcap_path)]

    try:
        proc = subprocess.Popen(  # noqa: S603 — argv list, no shell
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except FileNotFoundError as e:
        raise TcpdumpError(
            f"{tcpdump_binary!r} binary not found. Install it "
            "(`sudo apt install tcpdump` / `sudo pacman -S tcpdump`)."
        ) from e
    # tcpdump opens the capture file and prints "listening on …" to stderr
    # almost immediately. A short wait is enough to detect early exit
    # (e.g. interface doesn't exist, no permission).
    time.sleep(0.3)
    if proc.poll() is not None:
        raise TcpdumpError(
            f"tcpdump exited {proc.returncode} on startup "
            f"(iface={cfg.TCPDUMP_IFACE!r}). Is the interface up?"
        )
    return TcpdumpSession(pid=proc.pid, pcap_path=pcap_path)


def stop(pid: int, *, timeout: float = 3.0) -> None:
    """SIGTERM with SIGKILL fallback. No-op if already gone."""
    if not _alive(pid):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + timeout
    while _alive(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    if _alive(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False
