#!/usr/bin/env python3
"""
mcp-test — Unified CLI for MCP security testing.

Usage:
    python mcp_test.py scan --url URL          # Full adaptive scan (agent v3)
    python mcp_test.py enum --url URL          # Enumerate + leak
    python mcp_test.py llm --llm URL           # Extract MCP info through LLM
    python mcp_test.py honeypot --url URL      # Test if target is a honeypot
    python mcp_test.py agent --url URL         # Interactive LLM-guided mode
    python mcp_test.py discover                # Find MCP servers in local configs

Requires: Python 3.12+
"""
from __future__ import annotations

import argparse
import sys


def cmd_scan(args):
    from mcp_agent_v3 import run_intelligent_agent
    run_intelligent_agent(args.url, stealth_enabled=not args.no_stealth, deep=not args.shallow)


def cmd_enum(args):
    from mcp_enum import main as enum_main
    sys.argv = ["mcp_enum", "--url", args.url[0]]
    if args.discover:
        sys.argv.append("--discover")
    enum_main()


def cmd_llm(args):
    from mcp_llm import main as llm_main
    argv = ["mcp_llm", "--llm", args.llm]
    if args.direct:
        argv.extend(["--direct", args.direct])
    for h in args.header or []:
        argv.extend(["--header", h])
    sys.argv = argv
    llm_main()


def cmd_honeypot(args):
    from mcp_tester import main as tester_main
    sys.argv = ["mcp_tester", "--url", args.url[0], "--test", args.test]
    tester_main()


def cmd_agent(args):
    from mcp_interactive import run_interactive, run_auto
    if args.interactive:
        run_interactive(args.url[0], stealth_enabled=not args.no_stealth)
    else:
        run_auto(args.url[0], stealth_enabled=not args.no_stealth)


def cmd_discover(args):
    from mcp_enum import discover_local_configs
    configs = discover_local_configs()
    if configs:
        print(f"Found {len(configs)} MCP servers:")
        for c in configs:
            print(f"  {c['name']} -> {c.get('url', c.get('type', '?'))} ({c['source']})")
    else:
        print("No MCP configs found in standard locations.")


def main():
    parser = argparse.ArgumentParser(
        prog="mcp-test",
        description="MCP Security Testing Tool — Enumerate, probe, and exploit MCP servers",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p = sub.add_parser("scan", help="Full adaptive security scan (recommended)")
    p.add_argument("--url", action="append", required=True, help="Target MCP server URL (repeatable)")
    p.add_argument("--no-stealth", action="store_true", help="Disable stealth mode")
    p.add_argument("--shallow", action="store_true", help="Skip exploit chaining")
    p.set_defaults(func=cmd_scan)

    # enum
    p = sub.add_parser("enum", help="Enumerate and probe MCP server directly")
    p.add_argument("--url", action="append", required=True, help="Target MCP server URL")
    p.add_argument("--discover", action="store_true", help="Also scan local configs")
    p.set_defaults(func=cmd_enum)

    # llm
    p = sub.add_parser("llm", help="Extract MCP info through an LLM/AI agent")
    p.add_argument("--llm", required=True, help="LLM chat endpoint URL")
    p.add_argument("--direct", help="Also test MCP server directly")
    p.add_argument("--header", action="append", help="HTTP header (key:value)")
    p.set_defaults(func=cmd_llm)

    # honeypot
    p = sub.add_parser("honeypot", help="Test if target is a honeypot")
    p.add_argument("--url", action="append", required=True, help="Target MCP server URL")
    p.add_argument("--test", choices=["all", "fingerprint", "inject", "evade"], default="all")
    p.set_defaults(func=cmd_honeypot)

    # agent
    p = sub.add_parser("agent", help="Interactive LLM-guided agent mode")
    p.add_argument("--url", action="append", required=True, help="Target MCP server URL")
    p.add_argument("--interactive", action="store_true", help="Pause for LLM input between phases")
    p.add_argument("--no-stealth", action="store_true", help="Disable stealth")
    p.set_defaults(func=cmd_agent)

    # discover
    p = sub.add_parser("discover", help="Find MCP servers in local config files")
    p.set_defaults(func=cmd_discover)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
