"""Subprocess wrapper around the legacy ``fake-firmware-server.py``.

P2.11b/P2.11d both need a fake firmware server alongside their proxy
process. P2.13 will refactor ``fake-firmware-server.py`` into a proper
``mitmbeast.core.fakefw`` module with a threaded HTTP server; for now
we spawn the existing script and track its PID.

Public API:
* :func:`start_http(port, firmware_dir)` — return PID
* :func:`start_https(port, cert, key, firmware_dir)` — return PID
* :func:`stop(pid)` — SIGTERM + SIGKILL fallback
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
LEGACY_SCRIPT = REPO_ROOT / "fake-firmware-server.py"


__all__ = [
    "FakefwError",
    "start_http",
    "start_https",
    "stop",
]


class FakefwError(RuntimeError):
    """Raised when the fake firmware server fails to start."""


def start_http(*, port: int, firmware_dir: str | Path,
               log_path: str | Path) -> int:
    """Start the fake server on HTTP only. Return its PID."""
    return _spawn(
        ["--http", "--http-port", str(port),
         "--firmware-dir", str(firmware_dir)],
        log_path=Path(log_path),
    )


def start_https(*, port: int, cert: str | Path, key: str | Path,
                firmware_dir: str | Path, log_path: str | Path) -> int:
    """Start the fake server on HTTPS. Return its PID."""
    return _spawn(
        ["--https-port", str(port),
         "--cert", str(cert), "--key", str(key),
         "--firmware-dir", str(firmware_dir)],
        log_path=Path(log_path),
    )


def stop(pid: int, *, timeout: float = 3.0) -> None:
    """Stop the server process. No-op if already gone."""
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


def _spawn(extra_args: list[str], *, log_path: Path) -> int:
    if not LEGACY_SCRIPT.is_file():
        raise FakefwError(f"fake firmware server script not found: {LEGACY_SCRIPT}")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fh = log_path.open("ab")
    cmd = [sys.executable, str(LEGACY_SCRIPT), *extra_args]
    proc = subprocess.Popen(  # noqa: S603 — argv list, no shell
        cmd, stdout=log_fh, stderr=subprocess.STDOUT,
        cwd=str(REPO_ROOT), start_new_session=True,
    )
    time.sleep(0.3)
    if proc.poll() is not None:
        tail = log_path.read_text(errors="replace").splitlines()[-10:]
        raise FakefwError(
            f"fake firmware server exited {proc.returncode} on startup. "
            "Last log lines:\n" + "\n".join(tail)
        )
    return proc.pid


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False
