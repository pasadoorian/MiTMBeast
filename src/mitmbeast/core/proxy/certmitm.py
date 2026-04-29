"""certmitm lifecycle — TLS certificate validation testing.

certmitm is a third-party tool (https://github.com/aapooksman/certmitm)
that presents a battery of malformed TLS certificates to the client and
records which ones were accepted (= the device has a TLS validation
flaw). It ships its own venv with its own dependencies; the operator
installs it once and points :data:`MitmConfig.CERTMITM_PATH` at the
``certmitm.py`` script.

We run it via ``<install_dir>/venv/bin/python3 certmitm.py …`` (no
``source venv/bin/activate`` dance — we hand the venv interpreter
directly, which is exactly what the activate script ends up doing).
``cwd`` is set to the install dir so certmitm's relative imports and
output paths resolve as it expects.
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

__all__ = [
    "CertmitmError",
    "CertmitmSession",
    "start",
    "stop",
]


class CertmitmError(RuntimeError):
    """Raised when certmitm fails to launch."""


@dataclass(frozen=True, slots=True)
class CertmitmSession:
    pid: int
    session_dir: Path     # certmitm's --workdir; findings + raw data
    log_path: Path        # mitmbeast's redirect of stdout/stderr


def start(cfg: MitmConfig) -> CertmitmSession:
    """Start certmitm; return the session info."""
    script = Path(cfg.CERTMITM_PATH)
    if not script.is_file():
        raise CertmitmError(
            f"certmitm script not found: {script}\n"
            "Install from https://github.com/aapooksman/certmitm "
            "and update CERTMITM_PATH in mitm.conf."
        )
    install_dir = script.parent
    venv_python = install_dir / "venv" / "bin" / "python3"
    if not venv_python.is_file():
        raise CertmitmError(
            f"certmitm venv interpreter not found: {venv_python}\n"
            f"Create it with:\n"
            f"  cd {install_dir}\n"
            f"  python3 -m venv venv\n"
            f"  source venv/bin/activate\n"
            f"  pip install -r requirements.txt"
        )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")  # noqa: DTZ005
    workdir_root = Path(cfg.CERTMITM_WORKDIR)
    workdir_root.mkdir(parents=True, exist_ok=True)
    session_dir = workdir_root / f"session_{timestamp}"
    session_dir.mkdir(parents=True, exist_ok=True)
    log_path = session_dir / "certmitm.log"

    cmd: list[str] = [
        str(venv_python), str(script),
        "--listen", str(cfg.CERTMITM_PORT),
        "--workdir", str(session_dir),
    ]
    if cfg.CERTMITM_VERBOSE:
        cmd.append("--verbose")
    if cfg.CERTMITM_SHOW_DATA:
        cmd.append("--show-data")

    log_fh = log_path.open("ab")
    proc = subprocess.Popen(  # noqa: S603 — argv list, no shell
        cmd, stdout=log_fh, stderr=subprocess.STDOUT,
        cwd=str(install_dir), start_new_session=True,
    )
    time.sleep(0.5)  # certmitm imports take a beat
    if proc.poll() is not None:
        tail = log_path.read_text(errors="replace").splitlines()[-15:]
        raise CertmitmError(
            f"certmitm exited {proc.returncode} on startup. Last log lines:\n"
            + "\n".join(tail)
        )
    return CertmitmSession(pid=proc.pid, session_dir=session_dir,
                           log_path=log_path)


def stop(session: CertmitmSession, *, timeout: float = 3.0) -> None:
    """SIGTERM with SIGKILL fallback. No-op if already gone."""
    if not _alive(session.pid):
        return
    try:
        os.kill(session.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + timeout
    while _alive(session.pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    if _alive(session.pid):
        try:
            os.kill(session.pid, signal.SIGKILL)
        except ProcessLookupError:
            return


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False
