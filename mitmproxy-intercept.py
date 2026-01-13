"""
mitmproxy addon for intercept mode.

This addon routes intercepted traffic to a fake server for serving
fake responses (e.g., malicious firmware updates).

Only domains listed in INTERCEPT_DOMAINS will reach mitmproxy.
Passthrough domains are NOT DNS-spoofed and connect directly to
real servers, bypassing mitmproxy entirely.

Usage:
    mitmweb --mode transparent -s mitmproxy-intercept.py

Environment variables:
    FAKE_SERVER_HOST    - Fake server hostname (default: 127.0.0.1)
    FAKE_SERVER_PORT    - Fake server port (default: 8443)
    INTERCEPT_DOMAINS   - Domains to intercept (comma-separated)

Example:
    export INTERCEPT_DOMAINS="update.example.com"
    mitmweb --mode transparent -s mitmproxy-intercept.py
"""

from mitmproxy import http, ctx
import os

# Configuration from environment variables
FAKE_SERVER_HOST = os.environ.get("FAKE_SERVER_HOST", "127.0.0.1")
FAKE_SERVER_PORT = int(os.environ.get("FAKE_SERVER_PORT", "8443"))
INTERCEPT_DOMAINS = [d.strip() for d in os.environ.get("INTERCEPT_DOMAINS", "").split(",") if d.strip()]


def load(loader):
    """Called when the addon is loaded."""
    ctx.log.info("=" * 60)
    ctx.log.info("Intercept addon loaded")
    ctx.log.info("=" * 60)
    ctx.log.info(f"  Fake server: {FAKE_SERVER_HOST}:{FAKE_SERVER_PORT}")
    ctx.log.info(f"  Intercept domains: {INTERCEPT_DOMAINS}")
    ctx.log.info("=" * 60)


def server_connect(data):
    """
    Redirect upstream connection to fake server BEFORE mitmproxy connects.

    This hook runs before mitmproxy attempts to connect to the original
    destination (192.168.200.1:443). Without this, mitmproxy would try
    to connect to the router itself, which would fail.

    By redirecting here, we ensure mitmproxy connects to the fake server
    instead of the original destination.
    """
    # Access the actual server connection from the hook data
    server = data.server
    original_host = server.address[0]
    original_port = server.address[1]

    ctx.log.info(f"SERVER_CONNECT: {original_host}:{original_port}")

    # Redirect all connections to fake server
    server.address = (FAKE_SERVER_HOST, FAKE_SERVER_PORT)

    ctx.log.info(f"  -> Redirected to: {FAKE_SERVER_HOST}:{FAKE_SERVER_PORT}")


def request(flow: http.HTTPFlow) -> None:
    """
    Route requests to fake server.

    All traffic reaching mitmproxy in intercept mode should be
    redirected to the fake server. Passthrough domains never
    reach mitmproxy (they're not DNS-spoofed).
    """
    original_host = flow.request.pretty_host

    # Check if this is an intercept domain
    should_intercept = False
    if INTERCEPT_DOMAINS:
        should_intercept = original_host in INTERCEPT_DOMAINS
    else:
        # No intercept domains specified - intercept everything
        should_intercept = True

    if should_intercept:
        ctx.log.info(f"INTERCEPT: {flow.request.method} {flow.request.pretty_url}")

        # Store original host for fake server
        flow.request.headers["X-Original-Host"] = original_host
        flow.request.headers["X-Original-Scheme"] = flow.request.scheme
        flow.request.headers["X-Intercepted"] = "true"

        # Change scheme to HTTP for fake server (it's plaintext)
        flow.request.scheme = "http"
        flow.request.host = FAKE_SERVER_HOST
        flow.request.port = FAKE_SERVER_PORT

        ctx.log.info(f"  -> Forwarding to fake server: {FAKE_SERVER_HOST}:{FAKE_SERVER_PORT}")
    else:
        # Domain not in intercept list - log and pass through
        # (This shouldn't normally happen since only intercept domains are DNS-spoofed)
        ctx.log.warn(f"UNEXPECTED: {flow.request.method} {flow.request.pretty_url}")
        ctx.log.warn(f"  Domain '{original_host}' not in INTERCEPT_DOMAINS, passing through")


def response(flow: http.HTTPFlow) -> None:
    """Log responses."""
    original_host = flow.request.headers.get("X-Original-Host", flow.request.pretty_host)
    status = flow.response.status_code

    if flow.request.headers.get("X-Intercepted"):
        ctx.log.info(f"RESPONSE [INTERCEPTED] {original_host}: {status}")
    else:
        ctx.log.info(f"RESPONSE {original_host}: {status}")
