"""mitmproxy addon: append one JSON line per HTTP flow to a log file.

Loaded by ``mitmweb`` when launched in mitmproxy mode (P2.10b). The
flow log is tailed by mitmbeast's TUI Proxy tab and surfaced as live
events. Path defaults to ``/run/mitmbeast/flows.ndjson`` and is
overridable via ``MITMBEAST_FLOW_LOG``.

One line per response (we ignore in-flight requests so the log lines
have stable shape — every entry has both request and response data).

The format is deliberately small + flat so the TUI parser stays simple:

  {"ts": "...", "method": "GET", "host": "example.com",
   "url": "https://example.com/", "status": 200,
   "request_size": 0, "response_size": 1256, "client": "192.168.200.65"}
"""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime

from mitmproxy import http

LOG_PATH = os.environ.get("MITMBEAST_FLOW_LOG", "/run/mitmbeast/flows.ndjson")


class FlowJsonLogger:
    """Append-only NDJSON sink for completed HTTP flows."""

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        record = {
            "ts": datetime.now(UTC).isoformat(),
            "method": flow.request.method,
            "host": flow.request.pretty_host,
            "url": flow.request.pretty_url,
            "status": flow.response.status_code,
            "request_size": len(flow.request.content or b""),
            "response_size": len(flow.response.content or b""),
            "client": (flow.client_conn.peername[0]
                       if flow.client_conn and flow.client_conn.peername
                       else None),
        }
        try:
            with open(LOG_PATH, "a") as f:
                f.write(json.dumps(record) + "\n")
        except OSError:
            # Logging failure mustn't break the proxy; swallow.
            pass


addons = [FlowJsonLogger()]
