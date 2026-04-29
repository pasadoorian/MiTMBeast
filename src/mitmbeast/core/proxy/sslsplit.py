"""sslsplit lifecycle and session-cert management.

Replaces the v1.1 ``mitm.sh`` flow for ``-m sslsplit``:

  1. ``mktemp -d`` for the session CA cert + key
  2. ``openssl req -x509 -newkey rsa:4096 ...`` to generate a self-signed CA
  3. Spawn ``sslsplit -D -Y <pcapdir> -l <connlog> -k ca.key -c ca.crt
                     ssl 127.0.0.1 <port> sni 443``
  4. Add iptables redirect ``443 -> SSLSPLIT_PORT`` (handled by
     :mod:`mitmbeast.core.firewall`)

The session CA private key lives under ``/var/lib/mitmbeast/sessions/``
(M3.7 from the original IMPLEMENTATION_PLAN — moved out of ``/tmp``).

``stop`` SIGTERMs the daemon and securely deletes the private key
(``shred`` if present, ``rm`` otherwise).
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from mitmbeast.core.config import MitmConfig

__all__ = [
    "SESSION_BASE_DIR",
    "SslsplitError",
    "SslsplitSession",
    "start",
    "stop",
]


SESSION_BASE_DIR = Path("/var/lib/mitmbeast/sessions")


class SslsplitError(RuntimeError):
    """Raised when an sslsplit lifecycle operation fails."""


@dataclass(frozen=True, slots=True)
class SslsplitSession:
    pid: int
    session_dir: Path        # holds pcap files + connections.log
    cert_dir: Path           # holds ca.key + ca.crt
    ca_fingerprint: str      # SHA-256, for printing to the user


# ----------------------------------------------------------------------
# Cert generation
# ----------------------------------------------------------------------

def _generate_session_ca(cert_dir: Path) -> str:
    """Run ``openssl req -x509 ...`` to mint a 1-day self-signed CA.

    Returns the SHA-256 fingerprint as ``"AA:BB:CC:..."``.
    """
    cert_dir.mkdir(parents=True, exist_ok=True)
    key = cert_dir / "ca.key"
    crt = cert_dir / "ca.crt"
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:4096",
        "-keyout", str(key),
        "-out", str(crt),
        "-sha256", "-days", "1", "-nodes",
        "-subj", "/CN=MITM Session CA/O=MITM Router",
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise SslsplitError(
            f"openssl req failed: {e.stderr.strip() or e}"
        ) from e
    key.chmod(0o600)
    return _fingerprint(crt)


def _fingerprint(crt: Path) -> str:
    """Return the SHA-256 fingerprint of ``crt`` as ``AA:BB:CC...``."""
    try:
        r = subprocess.run(
            ["openssl", "x509", "-fingerprint", "-sha256",
             "-noout", "-in", str(crt)],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError:
        return "(unknown)"
    # Output: "sha256 Fingerprint=AA:BB:..."
    line = r.stdout.strip()
    if "=" in line:
        return line.split("=", 1)[1]
    return line


# ----------------------------------------------------------------------
# Lifecycle
# ----------------------------------------------------------------------

def start(cfg: MitmConfig) -> SslsplitSession:
    """Generate certs, launch sslsplit, return a :class:`SslsplitSession`.

    Honours :pep:`Q3` (hybrid state) — pcap files land where the
    user expects (``cfg.SSLSPLIT_PCAP_DIR/session_<ts>``); the cert
    private key is moved out of ``/tmp`` to ``/var/lib/mitmbeast/``.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")  # noqa: DTZ005
    SESSION_BASE_DIR.mkdir(parents=True, exist_ok=True)
    cert_dir = SESSION_BASE_DIR / f"sslsplit_{timestamp}"

    # The user-facing pcap dir from mitm.conf is repo-relative — keep it
    # that way for compat with v1.1 docs.
    pcap_root = Path(cfg.SSLSPLIT_PCAP_DIR)
    pcap_root.mkdir(parents=True, exist_ok=True)
    session_dir = pcap_root / f"session_{timestamp}"
    session_dir.mkdir(parents=True, exist_ok=True)

    fp = _generate_session_ca(cert_dir)

    log_path = session_dir / "sslsplit.log"
    conn_log = session_dir / "connections.log"

    cmd = [
        "sslsplit", "-D",
        "-Y", str(session_dir),
        "-l", str(conn_log),
        "-k", str(cert_dir / "ca.key"),
        "-c", str(cert_dir / "ca.crt"),
        "ssl", "127.0.0.1", str(cfg.SSLSPLIT_PORT),
        "sni", "443",
    ]
    log_fh = log_path.open("ab")
    proc = subprocess.Popen(  # noqa: S603 — argv list, no shell
        cmd, stdout=log_fh, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    # Give the daemon a moment to bind. If it's going to crash, it
    # almost always does so within ~200ms (port already in use, cert
    # path wrong, etc.).
    time.sleep(0.3)
    if proc.poll() is not None:
        log_tail = log_path.read_text(errors="replace").splitlines()[-10:]
        _shred(cert_dir / "ca.key")
        try:
            cert_dir.rmdir()
        except OSError:
            pass
        raise SslsplitError(
            f"sslsplit exited {proc.returncode} on startup. Last log lines:\n"
            + "\n".join(log_tail)
        )

    return SslsplitSession(
        pid=proc.pid,
        session_dir=session_dir,
        cert_dir=cert_dir,
        ca_fingerprint=fp,
    )


def stop(session: SslsplitSession, *, timeout: float = 3.0) -> None:
    """SIGTERM the sslsplit daemon and securely wipe the session CA key."""
    if _pid_alive(session.pid):
        try:
            os.kill(session.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + timeout
        while _pid_alive(session.pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        if _pid_alive(session.pid):
            try:
                os.kill(session.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    _shred(session.cert_dir / "ca.key")
    crt = session.cert_dir / "ca.crt"
    if crt.exists():
        crt.unlink()
    try:
        session.cert_dir.rmdir()
    except OSError:
        pass


# ----------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------

def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _shred(path: Path) -> None:
    """Securely delete ``path`` if possible; fallback to ``unlink``."""
    if not path.exists():
        return
    if shutil.which("shred"):
        subprocess.run(  # noqa: S603
            ["shred", "-u", str(path)],
            check=False, capture_output=True,
        )
        if path.exists():
            path.unlink()
    else:
        path.unlink()
