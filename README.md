# AICU Agent

The first open-source AI security agent for MCP (Model Context Protocol) infrastructure testing. Adaptive probing, exploit chaining, LLM extraction, honeypot detection, and multi-model comparison.

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

# Run as API service for CI/CD
python aicu_server.py --port 9000
```

## Commands

```bash
python mcp_test.py scan --url URL          # Full adaptive scan
python mcp_test.py enum --url URL          # Enumerate + probe
python mcp_test.py llm --llm URL           # Extract MCP info through LLM
python mcp_test.py honeypot --url URL      # Honeypot detection
python mcp_test.py agent --url URL --interactive  # LLM-guided mode
python mcp_test.py discover                # Find local MCP configs
```

## Features

### Intelligent Agent (v3)
- **Reasoning loop** — re-plans after each phase based on discoveries
- **Persistence** — remembers between runs (knowledge_base.json)
- **Evasion adaptation** — 7 encoding retries when probes are blocked
- **Multi-server correlation** — leaked creds from Server A tested on Server B
- **Stealth mode** — jitter, UA rotation, randomized probe order

### Adaptive Probing
- Schema-aware: reads `inputSchema` and generates per-parameter attacks
- Path traversal, SSRF, SQLi, command injection, key enumeration
- Prioritizes tools based on what resources/prompts reveal

### LLM Extraction (21 Advanced Prompts)
- Incident response framing, Terraform export, SDK generation
- Response chaining: follows up on partial disclosures automatically
- No obvious keywords that trigger guardrails

### Full MCP Protocol Coverage
- `tools/list` + `tools/call`
- `resources/list` + `resources/read`
- `prompts/list` + `prompts/get`
- `sampling/createMessage`

### Context Overflow Testing
- Progressively fills context window to find safety rule breakpoints
- Tests multiple padding styles (docs, code, data, noise)
- Multiple injection techniques per size level

### Attack Graph Visualization
- Interactive force-directed HTML/SVG diagram
- Nodes = findings, edges = exploit chains
- Hover for details, auto-layout

### Multi-Model Comparison Matrix
- Same payloads against multiple LLMs
- Color-coded HTML table (PASS/FAIL per model)
- Per-model fail rate statistics

### API Server (CI/CD Integration)
```bash
python aicu_server.py --port 9000

# Trigger scans via HTTP
curl -X POST http://localhost:9000/scan -d '{"url":"https://target.com"}'
curl http://localhost:9000/results/<id>
curl http://localhost:9000/health
```

### Before/After Comparison
```bash
python compare.py --save baseline --results findings.json
# ... target gets patched ...
python compare.py --compare baseline --results findings_after.json
# Output: "3 fixed, 1 new, 2 unchanged"
```

### Honeypot Detection
- Fingerprints known honeypots (Zeltser, Kadam)
- Alert injection testing (Slack XSS, SIEM injection)
- Evasion testing (skip initialize, spoof UA, batch)

### False Positive Filtering
- Credential format validation (full regex)
- Echo detection, denial filtering
- Category-specific rules per finding type

### Output Formats
- **HTML** — polished interactive reports
- **JSON** — structured findings for automation
- **SARIF** — GitHub/Azure DevOps/SIEM integration
- **Attack Graph** — visual exploit chain diagram
- **Comparison** — before/after diff reports

## Architecture

```
mcp_test.py              ← Unified CLI
├── mcp_agent_v3.py      ← Intelligent agent (reasoning, persistence, correlation)
├── mcp_agent_v2.py      ← Adaptive agent (schema probing, stealth, reports)
├── mcp_interactive.py   ← LLM-guided interactive mode
├── mcp_enum.py          ← Direct MCP enumeration + leak testing
├── mcp_llm.py           ← LLM-based extraction (21 prompts + chaining)
├── mcp_tester.py        ← Honeypot detection
├── mcp_agent.py         ← Original agent (honeypot vs real)
├── context_overflow.py  ← Context window overflow testing
├── attack_graph.py      ← Exploit chain visualization
├── model_matrix.py      ← Multi-model comparison
├── aicu_server.py       ← HTTP API server for CI/CD
├── compare.py           ← Before/after comparison
├── fp_filter.py         ← False positive elimination
├── output_formats.py    ← JSON + SARIF exporters
├── demo.py              ← Terminal demo for recording
└── knowledge_base.json  ← Persistent memory (auto-generated)
```

## Companion Tool

For LLM application security testing (prompt injection, file upload attacks, safety bypass), see [**AICU**](https://github.com/Jake-Schoellkopf/aicu).

| Tool | What it tests |
|------|--------------|
| **AICU** | LLM applications (prompt injection, file upload, safety bypass) |
| **AICU Agent** | MCP infrastructure (server probing, credential extraction, protocol attacks) |

## Disclaimer

Only test systems you own or have explicit authorization to test.

## License

MIT
