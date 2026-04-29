"""intercept lifecycle — mitmweb + addon + fake firmware server.

Replaces the v1.1 ``mitm.sh`` flow for ``-m intercept``. The mode
exploits missing certificate pinning: ``mitmweb`` terminates TLS for
DNS-spoofed domains, then the included ``mitmproxy-intercept.py``
addon rewrites the upstream destination to a local HTTP fake server
that returns whatever firmware/responses we want.

Three pieces:

  1. ``fake-firmware-server.py`` on ``cfg.INTERCEPT_FAKE_SERVER_PORT``
  2. ``mitmweb --mode transparent -s mitmproxy-intercept.py`` listening
     on ``cfg.INTERCEPT_PORT``
  3. iptables redirect ``LAN_IP:443 → mitmweb`` (router-level)

The intercept addon reads ``FAKE_SERVER_HOST``, ``FAKE_SERVER_PORT``,
and ``INTERCEPT_DOMAINS`` from its environment — we inject those when
spawning mitmweb.

Note: this module spawns mitmweb as a subprocess (mitmweb's web UI
remains the primary flow viewer for now). P2.10 will introduce a
parallel ``proxy.mitmproxy_mode`` that uses mitmproxy's Python API
in-process so flow events can hit our event bus directly.
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

REPO_ROOT = Path(__file__).resolve().parents[4]


__all__ = [
    "INTERCEPT_LOG_DIR",
    "InterceptError",
    "InterceptSession",
    "start",
    "stop",
]


INTERCEPT_LOG_DIR = Path("./intercept_logs")


class InterceptError(RuntimeError):
    """Raised when the intercept stack fails to start."""


@dataclass(frozen=True, slots=True)
class InterceptSession:
    mitmweb_pid: int
    fakefw_pid: int
    session_dir: Path


def start(cfg: MitmConfig) -> InterceptSession:
    """Start mitmweb + fakefw, return the session info."""
    addon = REPO_ROOT / "mitmproxy-intercept.py"
    if not addon.is_file():
        raise InterceptError(
            f"intercept addon script not found: {addon}"
        )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")  # noqa: DTZ005
    INTERCEPT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    session_dir = INTERCEPT_LOG_DIR / f"session_{timestamp}"
    session_dir.mkdir(parents=True, exist_ok=True)

    # 1. fake firmware server (HTTP) — INTERCEPT_FAKE_SERVER_PORT
    fakefw_pid = fakefw.start_http(
        port=cfg.INTERCEPT_FAKE_SERVER_PORT,
        firmware_dir="./firmware",
        log_path=session_dir / "fake_server.log",
    )

    # 2. mitmweb in transparent mode with the intercept addon
    log_path = session_dir / "mitmweb.log"
    env = os.environ.copy()
    env.update({
        "FAKE_SERVER_HOST": "127.0.0.1",
        "FAKE_SERVER_PORT": str(cfg.INTERCEPT_FAKE_SERVER_PORT),
        "INTERCEPT_DOMAINS": cfg.INTERCEPT_DOMAINS,
    })
    cmd = [
        "mitmweb", "--mode", "transparent", "--showhost",
        "-p", str(cfg.INTERCEPT_PORT),
        "-s", str(addon),
        "--web-host", cfg.MITMPROXY_WEB_HOST,
        "--web-port", str(cfg.MITMPROXY_WEB_PORT),
        "--set", f"web_password={cfg.MITMPROXY_WEB_PASSWORD}",
        "-k",
    ]
    log_fh = log_path.open("ab")
    proc = subprocess.Popen(  # noqa: S603 — argv list, no shell
        cmd, env=env, stdout=log_fh, stderr=subprocess.STDOUT,
        cwd=str(REPO_ROOT), start_new_session=True,
    )
    time.sleep(0.5)
    if proc.poll() is not None:
        tail = log_path.read_text(errors="replace").splitlines()[-15:]
        fakefw.stop(fakefw_pid)
        raise InterceptError(
            f"mitmweb exited {proc.returncode} on startup. Last log lines:\n"
            + "\n".join(tail)
        )
    return InterceptSession(
        mitmweb_pid=proc.pid,
        fakefw_pid=fakefw_pid,
        session_dir=session_dir,
    )


def stop(session: InterceptSession, *, timeout: float = 3.0) -> None:
    """Stop mitmweb + fake server."""
    if _alive(session.mitmweb_pid):
        try:
            os.kill(session.mitmweb_pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + timeout
        while _alive(session.mitmweb_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        if _alive(session.mitmweb_pid):
            try:
                os.kill(session.mitmweb_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    fakefw.stop(session.fakefw_pid, timeout=timeout)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False
