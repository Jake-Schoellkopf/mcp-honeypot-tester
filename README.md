# MCP Honeypot Tester

Security testing tool for Model Context Protocol (MCP) servers. Enumerates capabilities, tests access controls, and probes for vulnerabilities including SSRF, injection, and IDOR.

## What It Tests

| Phase | Tests |
|-------|-------|
| 1. Initialization | Handshake, capability discovery, unauthenticated access |
| 2. Enumeration | Tools, resources, prompts listing (with and without auth) |
| 3. Access | Tool invocation, resource reading, unauthenticated calls |
| 4. Injection | Command injection, SSRF via args, path traversal, template injection |
| 5. IDOR | Resource access with manipulated URIs, privilege escalation |

## Installation

```bash
git clone https://github.com/Jake-Schoellkopf/mcp-honeypot-tester.git
cd mcp-honeypot-tester
pip install httpx
```

## Usage

```bash
# Basic scan against an MCP server
python mcp_tester.py --target http://localhost:3000/mcp

# With authentication
python mcp_tester.py --target http://localhost:3000/mcp --auth "Bearer your-token"

# Through Burp proxy
python mcp_tester.py --target http://localhost:3000/mcp --proxy http://127.0.0.1:8080

# With custom delay (avoid rate limiting)
python mcp_tester.py --target https://api.example.com/mcp --delay 3
```

## What It Finds

- **Unauthenticated enumeration** — Can tools/resources be listed without credentials?
- **Unauthenticated invocation** — Can tools be called without auth?
- **SSRF** — Can resource URIs or tool arguments reach internal services (IMDS, Redis, etc.)?
- **Injection** — Are tool arguments sanitized? (command injection, path traversal, template injection)
- **IDOR** — Can resources belonging to other users/contexts be accessed?
- **Information disclosure** — Does the server leak sensitive data in error messages?

## Output

Results are saved to `runs/mcp_scan_<timestamp>/`:
- `results.json` — All test results with findings
- `server_info.json` — Server capabilities and version
- `tools.json` — Enumerated tools
- `resources.json` — Enumerated resources

## Requirements

- Python 3.8+
- httpx

## License

MIT
