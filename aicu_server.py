"""
AICU Agent API Server

Run aicu-agent as an HTTP service for CI/CD integration.

Usage:
    python aicu_server.py --port 9000

Endpoints:
    POST /scan          Full adaptive scan
    POST /enum          Enumerate MCP server
    POST /honeypot      Honeypot detection
    GET  /health        Health check
    GET  /results/:id   Get scan results

Requires: Python 3.12+
"""
from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs


# Store scan results in memory
SCANS: dict[str, dict] = {}


def run_scan_async(scan_id: str, url: str, scan_type: str):
    """Run a scan in background thread."""
    SCANS[scan_id]["status"] = "running"
    SCANS[scan_id]["started"] = datetime.now().isoformat()

    try:
        match scan_type:
            case "full":
                from mcp_agent_v3 import run_intelligent_agent
                findings = run_intelligent_agent([url], stealth_enabled=True, deep=True)
            case "enum":
                from mcp_enum import enumerate_server, leak_secrets
                info = enumerate_server(url)
                findings = leak_secrets(url, info.tools) if info.tools else []
            case "honeypot":
                from mcp_tester import test_fingerprint, test_injection, test_evasion
                results = test_fingerprint(url) + test_injection(url) + test_evasion(url)
                findings = results
            case _:
                findings = []

        SCANS[scan_id]["status"] = "complete"
        SCANS[scan_id]["findings"] = len(findings) if isinstance(findings, list) else 0
        SCANS[scan_id]["completed"] = datetime.now().isoformat()
        SCANS[scan_id]["results"] = [
            {"severity": getattr(f, "severity", "info"), "title": getattr(f, "title", getattr(f, "name", str(f))), "category": getattr(f, "category", "")}
            for f in (findings if isinstance(findings, list) else [])
        ][:50]

    except Exception as e:
        SCANS[scan_id]["status"] = "error"
        SCANS[scan_id]["error"] = str(e)


class APIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _json_response(self, data: dict, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._json_response({"status": "ok", "scans_active": sum(1 for s in SCANS.values() if s["status"] == "running")})

        elif parsed.path.startswith("/results/"):
            scan_id = parsed.path.split("/")[-1]
            if scan_id in SCANS:
                self._json_response(SCANS[scan_id])
            else:
                self._json_response({"error": "Scan not found"}, 404)

        elif parsed.path == "/scans":
            self._json_response({"scans": [{k: v for k, v in s.items() if k != "results"} for s in SCANS.values()]})

        else:
            self._json_response({"error": "Not found"}, 404)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_length).decode()) if content_length else {}

        url = body.get("url", "")
        if not url and self.path != "/health":
            self._json_response({"error": "Missing 'url' in request body"}, 400)
            return

        scan_id = str(uuid.uuid4())[:8]

        match self.path:
            case "/scan":
                scan_type = "full"
            case "/enum":
                scan_type = "enum"
            case "/honeypot":
                scan_type = "honeypot"
            case _:
                self._json_response({"error": "Unknown endpoint"}, 404)
                return

        SCANS[scan_id] = {"id": scan_id, "url": url, "type": scan_type, "status": "queued", "created": datetime.now().isoformat()}

        thread = threading.Thread(target=run_scan_async, args=(scan_id, url, scan_type), daemon=True)
        thread.start()

        self._json_response({"id": scan_id, "status": "queued", "results_url": f"/results/{scan_id}"}, 202)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="AICU Agent API Server")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), APIHandler)
    print(f"AICU Agent API running on http://{args.host}:{args.port}")
    print(f"  POST /scan     {{\"url\": \"...\"}}")
    print(f"  POST /enum     {{\"url\": \"...\"}}")
    print(f"  POST /honeypot {{\"url\": \"...\"}}")
    print(f"  GET  /health")
    print(f"  GET  /results/{{id}}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
