"""Fake firmware server — in-process refactor of fake-firmware-server.py.

Impersonates a vendor's update endpoint. Used by ``-m sslstrip`` and
``-m intercept`` modes to serve fake firmware downloads to the device
under test.

This module is the canonical implementation; the top-level
``fake-firmware-server.py`` script is now a thin shim that imports
:func:`main` here. That preserves backwards compatibility for any
external automation that invokes the script directly while letting
new code import :class:`FirmwareConfig`, :class:`FirmwareRequestHandler`,
and :func:`serve_in_thread` for in-process use.

Concrete improvements over the original script:

* :class:`http.server.ThreadingHTTPServer` instead of single-threaded
  :class:`HTTPServer` — multiple simultaneous IoT clients no longer
  queue. Fixes the original v1.0 bug "one slow client blocks the test."
* :func:`serve_in_thread` exposes the server as a Python-callable
  function returning a session handle, so future TUI / supervisor
  code can run it inside mitmbeast without subprocess overhead.

Endpoint contract (unchanged from v1.0):

* ``GET /releases?deviceId=XXX`` → JSON with appUrl / systemUrl
* ``GET /app/<ver>/<APP_FILENAME>`` → firmware binary
* ``GET /system/<ver>/system.tar`` → system update tarball
* ``GET /`` → metadata (service banner, endpoint list)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import socket
import ssl
import sys
import threading
import traceback
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger("mitmbeast.fakefw")
__all__ = [
    "FirmwareConfig",
    "FirmwareRequestHandler",
    "ServerSession",
    "calculate_sha256",
    "main",
    "run_server",
    "serve_in_thread",
]


# ----------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------

@dataclass
class FirmwareConfig:
    """Per-server config. Mutable so tests / supervisor can tweak."""

    firmware_dir: str = "./firmware"
    server_host: str = "0.0.0.0"  # noqa: S104 — bind-all is the v1.0 default
    http_port: int | None = None  # None = HTTP disabled
    https_port: int = 443
    cert_file: str | None = None
    key_file: str | None = None
    firmware_version: str = "99.0.0"      # high to force update
    update_host: str = "update.example.com"
    app_filename: str = "firmware_app"
    allowed_files: list[str] = field(default_factory=list)


# Process-wide config object so the request handler (which is
# instantiated per-request by the stdlib HTTPServer) can read it
# without us subclassing the server.
config = FirmwareConfig()


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def calculate_sha256(filepath: str | Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ----------------------------------------------------------------------
# Request handler — unchanged contract from v1.0
# ----------------------------------------------------------------------

class FirmwareRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the fake firmware server."""

    def log_message(self, format: str, *args) -> None:  # noqa: A002 — stdlib name
        logger.info("%s - %s", self.address_string(), format % args)

    def send_json_response(self, data: dict, status: int = 200) -> None:
        content = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def send_file_response(self, filepath: Path,
                           content_type: str = "application/octet-stream") -> None:
        try:
            file_size = os.path.getsize(filepath)
            sha256 = calculate_sha256(filepath)
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(file_size))
            self.send_header("X-SHA256", sha256)
            self.end_headers()
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    self.wfile.write(chunk)
            logger.info("Served file: %s (%d bytes)", filepath, file_size)
        except FileNotFoundError:
            self.send_error(404, f"File not found: {filepath}")
        except OSError as e:
            logger.error("Error serving file %s: %s", filepath, e)
            self.send_error(500, str(e))

    def handle_firmware_download(self, filename: str) -> None:
        if filename not in config.allowed_files:
            logger.warning("Attempted to download disallowed file: %s", filename)
            self.send_error(403, "Forbidden")
            return
        filepath = Path(config.firmware_dir) / filename
        if not filepath.exists():
            logger.error("Firmware file not found: %s", filepath)
            self.send_error(404, f"Firmware not found: {filename}")
            return
        logger.info("=== FIRMWARE DOWNLOAD === file=%s client=%s",
                    filename, self.address_string())
        content_type = ("application/x-tar" if filename.endswith(".tar")
                        else "application/octet-stream")
        self.send_file_response(filepath, content_type)

    def handle_releases_api(self, query_params: dict) -> None:
        device_id = query_params.get("deviceId", ["unknown"])[0]
        prerelease = query_params.get("prerelease", ["false"])[0]
        logger.info("=== /releases (vendor API spoof) === device=%s prerelease=%s client=%s",
                    device_id, prerelease, self.address_string())
        version = config.firmware_version
        response = {
            "appVersion": version,
            "appUrl": f"https://{config.update_host}/app/{version}/{config.app_filename}",
            "systemVersion": version,
            "systemUrl": f"https://{config.update_host}/system/{version}/system.tar",
        }
        logger.info("→ appUrl: %s", response["appUrl"])
        logger.info("→ systemUrl: %s", response["systemUrl"])
        self.send_json_response(response)

    def do_GET(self) -> None:  # noqa: N802 — stdlib name
        parsed = urlparse(self.path)
        path = parsed.path
        query_params = parse_qs(parsed.query)
        logger.info("GET %s from %s", self.path, self.address_string())
        if path == "/releases":
            self.handle_releases_api(query_params)
        elif path.startswith("/app/") and path.endswith(f"/{config.app_filename}"):
            self.handle_firmware_download(config.app_filename)
        elif path.startswith("/system/") and path.endswith("/system.tar"):
            self.handle_firmware_download("system.tar")
        elif path == "/":
            self.send_json_response({
                "service": "Fake Firmware Server",
                "endpoints": [
                    "/releases?deviceId=XXX",
                    f"/app/<version>/{config.app_filename}",
                    "/system/<version>/system.tar",
                ],
            })
        else:
            logger.warning("Unknown path requested: %s", path)
            self.send_error(404, "Not found")

    def do_POST(self) -> None:  # noqa: N802 — stdlib name
        logger.warning("POST %s not implemented", self.path)
        self.send_error(405, "Method not allowed")


# ----------------------------------------------------------------------
# Threaded server with SSL diagnostics
# ----------------------------------------------------------------------

class SSLLoggingThreadingHTTPServer(ThreadingHTTPServer):
    """Threaded HTTPServer that logs SSL handshake failures clearly.

    Multi-threaded: each connection handled in its own thread, so a
    slow client doesn't block the rest. Was single-threaded in v1.0;
    fixes a real cause of false negatives during IoT testing where
    a hung TLS handshake would queue subsequent legitimate connections.
    """

    daemon_threads = True   # don't block process exit on stuck client

    def get_request(self):  # type: ignore[no-untyped-def]
        newsocket, fromaddr = self.socket.accept()
        logger.info(">>> connection from %s:%d", fromaddr[0], fromaddr[1])
        return newsocket, fromaddr

    def handle_error(self, request, client_address) -> None:  # type: ignore[no-untyped-def]
        exc_type, exc_value, _ = sys.exc_info()
        if exc_type is ssl.SSLError:
            err = str(exc_value)
            logger.error("SSL handshake error from %s:%d — %s",
                         client_address[0], client_address[1], err)
            for needle, hint in (
                ("CERTIFICATE_VERIFY_FAILED",     "client rejected our cert"),
                ("WRONG_VERSION_NUMBER",          "TLS version mismatch"),
                ("UNKNOWN_CA",                    "client doesn't trust our CA"),
                ("CERTIFICATE_UNKNOWN",           "client rejected our cert"),
                ("HANDSHAKE_FAILURE",             "cipher/protocol mismatch"),
                ("EOF occurred",                  "client closed during handshake"),
            ):
                if needle in err:
                    logger.error("    → %s", hint)
                    break
        elif exc_type is ConnectionResetError:
            logger.error("connection reset by %s:%d",
                         client_address[0], client_address[1])
        elif exc_type is BrokenPipeError:
            logger.error("broken pipe from %s:%d",
                         client_address[0], client_address[1])
        elif exc_type is socket.timeout:
            logger.error("connection timeout from %s:%d",
                         client_address[0], client_address[1])
        else:
            logger.error("unhandled error from %s:%d: %s: %s",
                         client_address[0], client_address[1],
                         exc_type.__name__ if exc_type else "?", exc_value)
            traceback.print_exc()

    def finish_request(self, request, client_address) -> None:  # type: ignore[no-untyped-def]
        try:
            super().finish_request(request, client_address)
        except ssl.SSLError as e:
            logger.error("SSL error during request from %s:%d — %s",
                         client_address[0], client_address[1], e)
        except (ConnectionResetError, BrokenPipeError) as e:
            logger.error("connection error from %s:%d: %s",
                         client_address[0], client_address[1], e)


# ----------------------------------------------------------------------
# Lifecycle
# ----------------------------------------------------------------------

@dataclass
class ServerSession:
    """Handle returned by :func:`serve_in_thread`."""

    threads: list[threading.Thread]
    servers: list[SSLLoggingThreadingHTTPServer]

    def shutdown(self) -> None:
        for s in self.servers:
            try:
                s.shutdown()
                s.server_close()
            except Exception:  # noqa: BLE001, S110 — best-effort, never raise here
                pass
        for t in self.threads:
            t.join(timeout=2.0)


def _build_servers(cfg: FirmwareConfig) -> list[tuple[str, SSLLoggingThreadingHTTPServer, int]]:
    out: list[tuple[str, SSLLoggingThreadingHTTPServer, int]] = []
    if cfg.http_port is not None:
        out.append((
            "HTTP",
            SSLLoggingThreadingHTTPServer((cfg.server_host, cfg.http_port),
                                          FirmwareRequestHandler),
            cfg.http_port,
        ))
    if cfg.cert_file and cfg.key_file:
        srv = SSLLoggingThreadingHTTPServer(
            (cfg.server_host, cfg.https_port), FirmwareRequestHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cfg.cert_file, cfg.key_file)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        out.append(("HTTPS", srv, cfg.https_port))
    return out


def serve_in_thread(cfg: FirmwareConfig) -> ServerSession:
    """Start the configured servers in background threads. Returns a session.

    The caller can shutdown via ``session.shutdown()``.
    """
    if cfg.http_port is None and not (cfg.cert_file and cfg.key_file):
        raise ValueError("must enable HTTP and/or supply cert/key for HTTPS")
    if not cfg.allowed_files:
        cfg.allowed_files = [cfg.app_filename, "system.tar"]
    Path(cfg.firmware_dir).mkdir(parents=True, exist_ok=True)
    # The handler reads from the module-level config object — make sure
    # callers' cfg becomes that object.
    global config
    config = cfg
    servers = _build_servers(cfg)
    threads = []
    for proto, srv, port in servers:
        t = threading.Thread(target=srv.serve_forever, name=f"fakefw-{proto.lower()}",
                             daemon=True)
        t.start()
        threads.append(t)
        logger.info("fakefw %s listening on %s:%d", proto, cfg.server_host, port)
    return ServerSession(threads=threads, servers=[s for _, s, _ in servers])


def run_server(cfg: FirmwareConfig) -> None:
    """Foreground entry point used by the legacy script.

    Starts servers via :func:`serve_in_thread` and then blocks on a
    sentinel until SIGINT.
    """
    session = serve_in_thread(cfg)
    logger.info("=" * 60)
    logger.info("Fake Firmware Server Started (threaded)")
    logger.info("  firmware dir:    %s", cfg.firmware_dir)
    logger.info("  firmware_version: %s", cfg.firmware_version)
    logger.info("  update_host:     %s", cfg.update_host)
    logger.info("  app_filename:    %s", cfg.app_filename)
    logger.info("=" * 60)
    try:
        # Block until interrupted
        while any(t.is_alive() for t in session.threads):
            for t in session.threads:
                t.join(timeout=1.0)
    except KeyboardInterrupt:
        logger.info("\nShutting down servers...")
        session.shutdown()


# ----------------------------------------------------------------------
# CLI (used by fake-firmware-server.py shim)
# ----------------------------------------------------------------------

def main() -> None:
    """CLI entry point — argparse + run_server."""
    parser = argparse.ArgumentParser(
        description="Fake firmware server for IoT devices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--http", action="store_true",
                        help="Enable HTTP server on --http-port")
    parser.add_argument("--http-port", type=int, default=80)
    parser.add_argument("--cert", help="SSL certificate file (enables HTTPS)")
    parser.add_argument("--key", help="SSL private key file")
    parser.add_argument("--https-port", type=int, default=443)
    parser.add_argument("--firmware-dir", default="./firmware")
    parser.add_argument("--firmware-version", default="99.0.0")
    parser.add_argument("--update-host", default="update.example.com")
    parser.add_argument("--app-filename", default="firmware_app")
    parser.add_argument("--firmware-files", nargs="+", default=None)
    parser.add_argument("--host", default="0.0.0.0")  # noqa: S104

    args = parser.parse_args()
    if not args.http and not (args.cert and args.key):
        parser.error("must specify --http and/or --cert/--key")
    if (args.cert or args.key) and not (args.cert and args.key):
        parser.error("--cert and --key must be supplied together")

    cfg = FirmwareConfig(
        firmware_dir=args.firmware_dir,
        server_host=args.host,
        http_port=args.http_port if args.http else None,
        https_port=args.https_port,
        cert_file=args.cert,
        key_file=args.key,
        firmware_version=args.firmware_version,
        update_host=args.update_host,
        app_filename=args.app_filename,
        allowed_files=(args.firmware_files
                       if args.firmware_files else [args.app_filename, "system.tar"]),
    )

    needs_root = ((args.http and args.http_port < 1024) or
                  (args.cert and args.https_port < 1024))
    if needs_root and os.geteuid() != 0:
        logger.error("ports below 1024 require root; re-run with sudo")
        sys.exit(1)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s - %(levelname)s - %(message)s")
    run_server(cfg)


if __name__ == "__main__":
    main()
