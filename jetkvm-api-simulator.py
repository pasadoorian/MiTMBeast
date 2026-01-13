#!/usr/bin/env python3
"""
JetKVM API Request Simulator

Simulates a JetKVM device querying api.jetkvm.com for firmware updates.
Logs all requests and responses in JSON format for analysis.

Usage:
    python3 jetkvm-api-simulator.py --device-id JK12345
    python3 jetkvm-api-simulator.py --device-id JK12345 --output logs/session.json
    python3 jetkvm-api-simulator.py --device-id JK12345 --download --verbose
"""

import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("Error: 'requests' library required. Install with: pip install requests")
    sys.exit(1)


# JetKVM API endpoints
API_BASE_URL = "https://api.jetkvm.com"
RELEASES_ENDPOINT = "/releases"


def get_timestamp():
    """Return ISO 8601 timestamp in UTC."""
    return datetime.now(timezone.utc).isoformat()


def create_session_id():
    """Generate a unique session ID."""
    return str(uuid.uuid4())[:8]


def log_message(message, verbose=True):
    """Print message to console if verbose mode enabled."""
    if verbose:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")


def analyze_firmware_urls(response_body):
    """Analyze firmware URLs from API response."""
    analysis = {
        "app_update_available": False,
        "system_update_available": False,
        "warnings": []
    }

    if "appUrl" in response_body:
        analysis["app_update_available"] = True
        app_url = response_body["appUrl"]
        parsed = urlparse(app_url)
        analysis["app_protocol"] = parsed.scheme.upper()
        analysis["app_download_host"] = parsed.netloc
        analysis["app_download_path"] = parsed.path
        analysis["app_version"] = response_body.get("appVersion", "unknown")

        if parsed.scheme == "http":
            analysis["warnings"].append(f"App firmware served over HTTP (insecure): {app_url}")

    if "systemUrl" in response_body:
        analysis["system_update_available"] = True
        sys_url = response_body["systemUrl"]
        parsed = urlparse(sys_url)
        analysis["system_protocol"] = parsed.scheme.upper()
        analysis["system_download_host"] = parsed.netloc
        analysis["system_download_path"] = parsed.path
        analysis["system_version"] = response_body.get("systemVersion", "unknown")

        if parsed.scheme == "http":
            analysis["warnings"].append(f"System firmware served over HTTP (insecure): {sys_url}")

    return analysis


def query_releases(device_id, prerelease=False, verbose=False):
    """
    Query the JetKVM releases API endpoint.

    Returns a dict with full request/response details.
    """
    url = f"{API_BASE_URL}{RELEASES_ENDPOINT}"
    params = {
        "deviceId": device_id,
        "prerelease": str(prerelease).lower()
    }
    headers = {
        "User-Agent": "jetkvm-api-simulator/1.0",
        "Accept": "application/json"
    }

    log_message(f"Querying: {url}", verbose)
    log_message(f"Device ID: {device_id}, Prerelease: {prerelease}", verbose)

    result = {
        "timestamp": get_timestamp(),
        "endpoint": "releases",
        "request": {
            "method": "GET",
            "url": url,
            "params": params,
            "headers": headers
        },
        "response": None,
        "error": None,
        "analysis": None
    }

    start_time = time.time()

    try:
        response = requests.get(url, params=params, headers=headers, timeout=30)
        elapsed_ms = int((time.time() - start_time) * 1000)

        # Try to parse JSON body
        try:
            body = response.json()
        except json.JSONDecodeError:
            body = response.text

        result["response"] = {
            "status_code": response.status_code,
            "reason": response.reason,
            "headers": dict(response.headers),
            "body": body,
            "elapsed_ms": elapsed_ms,
            "url_final": response.url  # Capture any redirects
        }

        log_message(f"Response: {response.status_code} {response.reason} ({elapsed_ms}ms)", verbose)

        # Analyze firmware URLs if successful response
        if response.status_code == 200 and isinstance(body, dict):
            result["analysis"] = analyze_firmware_urls(body)

            if verbose and result["analysis"]["warnings"]:
                for warning in result["analysis"]["warnings"]:
                    log_message(f"WARNING: {warning}", verbose)

    except requests.exceptions.Timeout:
        result["error"] = {"type": "timeout", "message": "Request timed out after 30 seconds"}
        log_message("ERROR: Request timed out", verbose)
    except requests.exceptions.ConnectionError as e:
        result["error"] = {"type": "connection_error", "message": str(e)}
        log_message(f"ERROR: Connection failed: {e}", verbose)
    except requests.exceptions.RequestException as e:
        result["error"] = {"type": "request_error", "message": str(e)}
        log_message(f"ERROR: Request failed: {e}", verbose)

    return result


def download_firmware(url, save_path=None, headers_only=False, verbose=False):
    """
    Download firmware from a URL and log the transaction.

    Returns a dict with request/response details.
    """
    log_message(f"Downloading: {url}", verbose)

    result = {
        "timestamp": get_timestamp(),
        "endpoint": "firmware_download",
        "request": {
            "method": "GET",
            "url": url,
            "headers": {
                "User-Agent": "jetkvm-api-simulator/1.0"
            }
        },
        "response": None,
        "error": None,
        "file_saved": None
    }

    start_time = time.time()

    try:
        if headers_only:
            response = requests.head(url, timeout=30, allow_redirects=True)
        else:
            response = requests.get(url, timeout=120, stream=True)

        elapsed_ms = int((time.time() - start_time) * 1000)

        result["response"] = {
            "status_code": response.status_code,
            "reason": response.reason,
            "headers": dict(response.headers),
            "elapsed_ms": elapsed_ms,
            "url_final": response.url,
            "content_length": response.headers.get("Content-Length"),
            "content_type": response.headers.get("Content-Type"),
            "sha256_header": response.headers.get("X-SHA256")
        }

        log_message(f"Response: {response.status_code} ({elapsed_ms}ms)", verbose)

        if response.headers.get("Content-Length"):
            size_mb = int(response.headers["Content-Length"]) / (1024 * 1024)
            log_message(f"Content-Length: {size_mb:.2f} MB", verbose)

        # Save file if requested
        if save_path and not headers_only and response.status_code == 200:
            parsed = urlparse(url)
            filename = Path(parsed.path).name
            filepath = Path(save_path) / filename
            filepath.parent.mkdir(parents=True, exist_ok=True)

            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            result["file_saved"] = str(filepath)
            log_message(f"Saved to: {filepath}", verbose)

    except requests.exceptions.Timeout:
        result["error"] = {"type": "timeout", "message": "Download timed out"}
        log_message("ERROR: Download timed out", verbose)
    except requests.exceptions.RequestException as e:
        result["error"] = {"type": "request_error", "message": str(e)}
        log_message(f"ERROR: Download failed: {e}", verbose)

    return result


def run_simulation(args):
    """Run the API simulation and return results."""
    session_id = create_session_id()
    results = {
        "session_id": session_id,
        "started_at": get_timestamp(),
        "config": {
            "device_id": args.device_id,
            "prerelease": args.prerelease,
            "download_firmware": args.download
        },
        "transactions": []
    }

    log_message(f"Session started: {session_id}", args.verbose)
    log_message("=" * 50, args.verbose)

    # Query releases endpoint
    releases_result = query_releases(
        device_id=args.device_id,
        prerelease=args.prerelease,
        verbose=args.verbose
    )
    results["transactions"].append(releases_result)

    # Download firmware if requested and URLs are available
    if args.download and releases_result.get("response"):
        body = releases_result["response"].get("body", {})

        if isinstance(body, dict):
            log_message("=" * 50, args.verbose)

            # Download app firmware
            if "appUrl" in body:
                log_message("Fetching app firmware...", args.verbose)
                app_result = download_firmware(
                    url=body["appUrl"],
                    save_path=args.save_firmware,
                    headers_only=args.headers_only,
                    verbose=args.verbose
                )
                results["transactions"].append(app_result)

            # Download system firmware
            if "systemUrl" in body:
                log_message("Fetching system firmware...", args.verbose)
                sys_result = download_firmware(
                    url=body["systemUrl"],
                    save_path=args.save_firmware,
                    headers_only=args.headers_only,
                    verbose=args.verbose
                )
                results["transactions"].append(sys_result)

    results["completed_at"] = get_timestamp()
    log_message("=" * 50, args.verbose)
    log_message(f"Session completed: {session_id}", args.verbose)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Simulate JetKVM device querying api.jetkvm.com for updates",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic query with device ID
  python3 %(prog)s --device-id JK12345

  # Save logs to file
  python3 %(prog)s --device-id JK12345 --output logs/session.json

  # Include pre-release versions
  python3 %(prog)s --device-id JK12345 --prerelease

  # Download firmware and log transactions
  python3 %(prog)s --device-id JK12345 --download --verbose

  # Just fetch headers (don't download full files)
  python3 %(prog)s --device-id JK12345 --download --headers-only

  # Save downloaded firmware to directory
  python3 %(prog)s --device-id JK12345 --download --save-firmware ./downloads/
        """
    )

    parser.add_argument("--device-id", required=True,
                        help="JetKVM device ID/serial number")
    parser.add_argument("--prerelease", action="store_true",
                        help="Include pre-release versions in check")
    parser.add_argument("--download", action="store_true",
                        help="Also fetch firmware URLs from response")
    parser.add_argument("--headers-only", action="store_true",
                        help="Only fetch headers for firmware (no download)")
    parser.add_argument("--save-firmware", metavar="DIR",
                        help="Directory to save downloaded firmware")
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="Output JSON log file (default: stdout)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print progress to console")
    parser.add_argument("--pretty", action="store_true",
                        help="Pretty-print JSON output")

    args = parser.parse_args()

    # Run simulation
    results = run_simulation(args)

    # Format output
    if args.pretty:
        output = json.dumps(results, indent=2)
    else:
        output = json.dumps(results)

    # Write output
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(output)
            f.write('\n')
        if args.verbose:
            log_message(f"Logs saved to: {args.output}", True)
    else:
        print(output)


if __name__ == "__main__":
    main()
