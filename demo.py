"""
Demo Script — Simulated scan output for terminal recording.

Run this to generate a GIF-ready terminal demo showing:
1. Scan starting
2. Findings appearing in real-time
3. Exploit chain forming
4. Report generated

Usage:
    python demo.py

Record with: asciinema rec demo.cast && asciinema-agg demo.cast demo.gif
Or use: terminalizer record demo
"""
from __future__ import annotations

import time
import sys
import random


def typewrite(text: str, delay: float = 0.02):
    """Simulate typing."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def slow_print(text: str, delay: float = 0.05):
    """Print with slight delay for readability."""
    print(text)
    time.sleep(delay)


def main():
    print()
    typewrite("$ python mcp_test.py scan --url https://target-mcp.example.com", 0.04)
    time.sleep(0.5)

    print()
    slow_print("=" * 60)
    slow_print("  MCP INTELLIGENT AGENT v3")
    slow_print("  Reasoning | Persistence | Chaining | Correlation | Evasion")
    slow_print("=" * 60)
    time.sleep(0.3)

    slow_print("\n  Knowledge base: 12 past successes, 3 known creds")
    time.sleep(0.5)

    slow_print(f"\n\n  {'═' * 60}")
    slow_print("  TARGET: https://target-mcp.example.com")
    slow_print(f"  {'═' * 60}")
    time.sleep(0.3)

    slow_print("\n  [PHASE 1] Initialize & Enumerate")
    slow_print("  " + "─" * 50)
    time.sleep(0.8)
    slow_print("    Server: internal-tools v2.1.0")
    slow_print("    Tools: 4")
    slow_print("      - secrets_vault: Read secrets from production vault")
    slow_print("      - db_query: Run SQL queries against replica")
    slow_print("      - file_read: Read files from workspace")
    slow_print("      - http_fetch: Fetch external URLs")
    time.sleep(0.5)

    slow_print("\n  [PLAN] ['Found 2 resources — often less protected', 'Check sampling']")
    time.sleep(0.3)

    slow_print("\n  [PHASE 2] Resources / Prompts / Sampling")
    slow_print("  " + "─" * 50)
    time.sleep(0.6)
    slow_print("    Resources findings: 1")
    slow_print("    \U0001f7e1 [MEDIUM] Resource readable: config.yaml")
    time.sleep(0.3)
    slow_print("    Prompts findings: 0")
    slow_print("    Sampling findings: 0")
    time.sleep(0.5)

    slow_print("\n  [PLAN] ['Database discovered — prioritizing SQL tools', 'Secrets discovered — prioritizing vault tools']")
    time.sleep(0.3)

    slow_print("\n  [PHASE 3] Adaptive Tool Probing")
    slow_print("  " + "─" * 50)
    time.sleep(0.4)
    slow_print("    [PRIORITY] secrets_vault (18 probes)...")
    time.sleep(1.5)
    slow_print("    \U0001f534 [CRITICAL] Credentials from secrets_vault/AWS_SECRET_ACCESS_KEY")
    slow_print("       AKIA4EXAMPLE7KEYID...")
    time.sleep(0.8)

    slow_print("    [PRIORITY] db_query (7 probes)...")
    time.sleep(1.0)
    slow_print("    \U0001f7e0 [HIGH] Database schema exposed via db_query/information_schema")
    time.sleep(0.5)

    slow_print("    [standard] file_read (12 probes)...")
    time.sleep(1.2)
    slow_print("    \U0001f7e0 [HIGH] System file via file_read/etc_passwd")
    slow_print("    \U0001f7e0 [HIGH] Env vars via file_read/.env")
    time.sleep(0.5)

    slow_print("    [standard] http_fetch (6 probes)...")
    time.sleep(0.8)
    slow_print("    \U0001f534 [CRITICAL] Cloud metadata via http_fetch/169.254.169.254")
    time.sleep(0.8)

    slow_print("\n  [PHASE 4] Exploit Chaining")
    slow_print("  " + "─" * 50)
    time.sleep(0.5)
    slow_print("    Using leaked AWS key against http_fetch...")
    time.sleep(1.0)
    slow_print("    \U0001f534 [CRITICAL] Chained: AWS credential works on http_fetch → S3 access")
    time.sleep(0.5)

    slow_print("\n  [FP FILTER] Removed 2 false positives, 6 validated findings remain")
    time.sleep(0.3)

    slow_print("\n  [KB] Saved: 15 successes, 4 creds, 2 endpoints")
    slow_print("  [REPORT] reports/mcp_scan_2026-05-26_21-50-00.html")
    slow_print("  [JSON]   reports/findings_2026-05-26_21-50-00.json")
    slow_print("  [SARIF]  reports/findings_2026-05-26_21-50-00.sarif")
    slow_print("  [GRAPH]  reports/attack_graph.html")
    time.sleep(0.3)

    slow_print(f"\n  {'═' * 60}")
    slow_print("  FINDINGS: 6")
    slow_print("    CRITICAL: 3")
    slow_print("    HIGH: 3")
    slow_print(f"  {'═' * 60}")
    print()
    time.sleep(1)


if __name__ == "__main__":
    main()
