# MCP Security Tester

The first open-source security agent purpose-built for MCP (Model Context Protocol) server testing. Adaptive schema-aware probing, exploit chaining, stealth mode, LLM-based extraction, and honeypot detection.

**Requires Python 3.12+**

## Install

```bash
git clone https://github.com/Jake-Schoellkopf/aicu-agent.git
cd aicu-agent
pip install httpx
```

## Quick Start

```bash
# Full adaptive scan (recommended)
python mcp_test.py scan --url https://target-mcp-server.com

# Discover MCP servers from local configs
python mcp_test.py discover

# Test if a server is a honeypot
python mcp_test.py honeypot --url https://suspicious-server.com

# Extract MCP info through an LLM
python mcp_test.py llm --llm https://chat-api.com/v1/chat

# Interactive mode (LLM-guided)
python mcp_test.py agent --url https://target.com --interactive
```

## Commands

| Command | What it does |
|---------|-------------|
| `scan` | Full adaptive security scan with reasoning, chaining, evasion |
| `enum` | Enumerate tools/resources/prompts and probe for leaks |
| `llm` | Trick an AI agent into revealing its MCP server details |
| `honeypot` | Detect if a server is a decoy (fingerprint, inject, evade) |
| `agent` | Interactive mode — pauses for LLM reasoning between phases |
| `discover` | Find MCP servers in local config files |

## Architecture

```
mcp_test.py              ← Unified CLI entry point
├── mcp_agent_v3.py      ← Intelligent agent (reasoning loop, persistence, correlation)
├── mcp_agent_v2.py      ← Adaptive agent (schema probing, stealth, chaining, reports)
├── mcp_interactive.py   ← Interactive/LLM-guided mode
├── mcp_enum.py          ← Direct MCP server enumeration + leak testing
├── mcp_llm.py           ← LLM-based extraction (21 advanced prompts + response chaining)
├── mcp_tester.py        ← Honeypot detection (fingerprint, inject, evade)
├── mcp_agent.py         ← Original agent (auto-detect honeypot vs real)
├── fp_filter.py         ← Strict false positive elimination
└── knowledge_base.json  ← Persistent memory (auto-generated)
```

## Features

### Adaptive Probing
Reads each tool's `inputSchema` and generates targeted probes per parameter type:
- Path parameters → path traversal (`../../etc/passwd`)
- URL parameters → SSRF (`http://169.254.169.254/`)
- Command parameters → injection (`id; cat /etc/passwd`)
- SQL parameters → SQLi (`' OR '1'='1`)
- Key parameters → enumeration (`AWS_SECRET_ACCESS_KEY`, `admin`)

### Exploit Chaining
Uses findings from one tool to attack others:
- Leaked credential from Tool A → tried as auth on Tool B
- Leaked endpoint from Tool A → SSRF'd through Tool B

### Stealth Mode
- Random 0.5-3s jitter between requests
- User-Agent rotation (8 real MCP client UAs)
- Randomized probe ordering
- Disable with `--no-stealth`

### Evasion Adaptation
When a probe is blocked, automatically retries with:
1. URL encoding
2. Double encoding
3. Unicode substitution
4. Case variation
5. Null byte injection
6. Path normalization tricks
7. Whitespace manipulation

### Multi-Server Correlation
Scan multiple targets and cross-reference:
```bash
python mcp_test.py scan --url https://server-a.com --url https://server-b.com
```
Credentials leaked from Server A are tested against Server B.

### LLM Extraction (21 Advanced Prompts)
Tricks AI agents into revealing MCP details through:
- Incident response framing
- Terraform/Docker export requests
- SDK generation requests
- Least privilege audit framing
- Negative space mapping

With **response chaining**: if the LLM partially discloses, the tool automatically follows up.

### Persistence
`knowledge_base.json` remembers between runs:
- Which probes succeeded (replayed on next scan)
- Which probes were blocked (skipped or adapted)
- Leaked credentials and endpoints (used for chaining)

### False Positive Filtering
Strict validation before any finding is reported:
- Credential format validation (full regex, not partial)
- Echo detection (discards responses that repeat input)
- Denial detection (discards error messages with keywords)
- Category-specific rules (SSRF must return real metadata, not just 200)

### Full MCP Protocol Coverage
- `tools/list` + `tools/call`
- `resources/list` + `resources/read`
- `prompts/list` + `prompts/get`
- `sampling/createMessage`
- `initialize` / `notifications/initialized`

### HTML Reports
Auto-generated after each scan at `reports/mcp_scan_<timestamp>.html`:
- Severity stats with color-coded cards
- Expandable evidence (full request + response)
- Chain indicators showing exploit paths
- Dark theme, responsive, print-friendly

## Output Formats

```bash
# HTML report (default, auto-generated)
reports/mcp_scan_2026-05-26_21-00-00.html

# JSON findings (knowledge_base.json contains structured data)
knowledge_base.json

# Console output with severity indicators
🔴 [CRITICAL] Credential leaked via secrets_vault/aws
🟠 [HIGH] System file via file_read/etc_passwd
🟡 [MEDIUM] Resource readable: config.yaml
🔵 [LOW] Non-trivial response from generic_tool
```

## Honeypot Detection

Identifies known MCP honeypots (Zeltser template, Kadam's deception server):
- Server version string fingerprinting
- Known tool name matching
- Minimal implementation detection
- Alert injection testing (Slack XSS, SIEM log injection)
- Evasion testing (skip initialize, spoof UA, batch requests)

## Interactive Mode

Pauses after enumeration and outputs state for LLM reasoning:
```
═══ PHASE 1 COMPLETE ═══
Tools (3):
  - secrets_vault (params: [key])
  - db_query (params: [sql])
  - file_read (params: [path])

═══ DECISION NEEDED ═══
What should I probe next?
```

Paste to your LLM, get a plan back, paste it in. The tool executes the plan.

## Disclaimer

Only test systems you own or have explicit authorization to test. This tool is for security research and authorized penetration testing only.

## License

MIT
