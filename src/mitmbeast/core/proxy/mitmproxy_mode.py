"""mitmproxy mode — subprocess wrapper around ``mitmweb``.

Phase 2.10a (subprocess version): spawn ``mitmweb`` as a managed
subprocess and install the iptables redirect, mirroring the other
proxy-mode modules. The router_up flow gains ``mode=mitmproxy``
support without the in-process API integration.

Phase 2.10b (event bus phase): replace this with ``DumpMaster``
running in-process so flow events fire callbacks that hit the
mitmbeast event bus directly, powering the live-flow Proxy TUI tab.
The public surface (``start``/``stop``) stays the same so the
router doesn't need to change.

Module name is ``mitmproxy_mode`` to avoid colliding with the
``mitmproxy`` PyPI package which we'll import in P2.10b.
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

REPO_ROOT = Path(__file__).resolve().parents[4]


__all__ = [
    "MITMPROXY_LOG_DIR",
    "MitmproxyError",
    "MitmproxySession",
    "start",
    "stop",
]


MITMPROXY_LOG_DIR = Path("./mitmproxy_logs")


class MitmproxyError(RuntimeError):
    """Raised when mitmweb fails to start."""


@dataclass(frozen=True, slots=True)
class MitmproxySession:
    pid: int
    session_dir: Path
    web_url: str       # http://<wan>:<web-port> for the operator


def start(cfg: MitmConfig) -> MitmproxySession:
    """Spawn mitmweb in transparent mode."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")  # noqa: DTZ005
    MITMPROXY_LOG_DIR.mkdir(parents=True, exist_ok=True)
    session_dir = MITMPROXY_LOG_DIR / f"session_{timestamp}"
    session_dir.mkdir(parents=True, exist_ok=True)
    log_path = session_dir / "mitmweb.log"

    cmd = [
        "mitmweb", "--mode", "transparent", "--showhost",
        "-p", str(cfg.MITMPROXY_PORT),
        "--web-host", cfg.MITMPROXY_WEB_HOST,
        "--web-port", str(cfg.MITMPROXY_WEB_PORT),
        "--set", f"web_password={cfg.MITMPROXY_WEB_PASSWORD}",
        "-k",
    ]
    log_fh = log_path.open("ab")
    proc = subprocess.Popen(  # noqa: S603 — argv list, no shell
        cmd, stdout=log_fh, stderr=subprocess.STDOUT,
        cwd=str(REPO_ROOT), start_new_session=True,
    )
    time.sleep(0.5)
    if proc.poll() is not None:
        tail = log_path.read_text(errors="replace").splitlines()[-15:]
        raise MitmproxyError(
            f"mitmweb exited {proc.returncode} on startup. Last log:\n"
            + "\n".join(tail)
        )

    web_host = cfg.WAN_STATIC_IP or cfg.MITMPROXY_WEB_HOST
    web_url = f"http://{web_host}:{cfg.MITMPROXY_WEB_PORT}"
    return MitmproxySession(
        pid=proc.pid, session_dir=session_dir, web_url=web_url,
    )


def stop(session: MitmproxySession, *, timeout: float = 3.0) -> None:
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
