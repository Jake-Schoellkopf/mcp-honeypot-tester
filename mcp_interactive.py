"""
MCP Agent Interactive Mode

Runs the agent phase-by-phase, outputting state after each phase.
Accepts a plan (from an LLM or human) to guide the next phase.

Two modes:
  --interactive    Pauses after each phase, waits for plan input
  --auto           Runs autonomously (uses built-in reasoning)

The output between phases is designed to be pasted to an LLM for reasoning.

Requires: Python 3.12+
"""
from __future__ import annotations

import argparse
import json
import sys
import random
import time
from pathlib import Path
from datetime import datetime
from typing import Any

import httpx

from mcp_agent_v2 import (
    send, jsonrpc, StealthConfig, Finding, Evidence,
    generate_adaptive_probes, test_resources, test_prompts, test_sampling,
    generate_report, chain_findings,
)
from mcp_agent_v3 import (
    KnowledgeBase, probe_with_evasion, correlate_across_servers,
)


def phase_enumerate(url: str, stealth: StealthConfig) -> dict:
    """Phase 1: Connect and enumerate everything."""
    state = {"url": url, "server_info": {}, "tools": [], "resources": [], "prompts": [], "capabilities": []}

    code, resp, _ = send(url, jsonrpc("initialize", {
        "protocolVersion": "2025-06-18",
        "capabilities": {"tools": {}, "resources": {}, "prompts": {}, "sampling": {}},
        "clientInfo": {"name": stealth.get_ua().split("/")[0], "version": "1.0.0"},
    }), stealth)

    if code != 200:
        state["error"] = f"Connection failed: {code}"
        return state

    match resp:
        case {"result": {"serverInfo": dict(si), "capabilities": dict(caps)}}:
            state["server_info"] = si
            state["capabilities"] = list(caps.keys())
        case {"result": {"serverInfo": dict(si)}}:
            state["server_info"] = si

    send(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, stealth)

    _, resp, _ = send(url, jsonrpc("tools/list"), stealth)
    match resp:
        case {"result": {"tools": list(t)}}:
            state["tools"] = [{"name": tool["name"], "description": tool.get("description", ""), "params": list(tool.get("inputSchema", {}).get("properties", {}).keys())} for tool in t]

    _, resp, _ = send(url, jsonrpc("resources/list"), stealth)
    match resp:
        case {"result": {"resources": list(r)}}:
            state["resources"] = [{"uri": res.get("uri", ""), "name": res.get("name", ""), "type": res.get("mimeType", "")} for res in r]

    _, resp, _ = send(url, jsonrpc("prompts/list"), stealth)
    match resp:
        case {"result": {"prompts": list(p)}}:
            state["prompts"] = [{"name": pr.get("name", ""), "description": pr.get("description", "")} for pr in p]

    return state


def phase_probe_tool(url: str, tool_name: str, tools_full: list[dict], stealth: StealthConfig, kb: KnowledgeBase, custom_probes: list[dict] | None = None) -> list[Finding]:
    """Probe a specific tool with adaptive or custom probes."""
    findings: list[Finding] = []

    # Find the full tool definition
    tool = next((t for t in tools_full if t["name"] == tool_name), None)
    if not tool:
        return findings

    if custom_probes:
        probes = [(p.get("name", "custom"), p.get("args", {})) for p in custom_probes]
    else:
        probes = generate_adaptive_probes(tool)

    if stealth.randomize_order:
        random.shuffle(probes)

    for probe_name, args in probes:
        success, text, ev = probe_with_evasion(url, tool_name, probe_name, args, stealth, kb)
        if success and text:
            if any(p in text for p in ["AKIA", "sk-", "ghp_", "-----BEGIN", "postgres://", "mysql://"]):
                findings.append(Finding("critical", "credential_leak", f"{tool_name}/{probe_name}", text[:150], ev))
            elif any(p in text for p in ["root:x:0", "/bin/bash"]):
                findings.append(Finding("high", "system_file", f"{tool_name}/{probe_name}", text[:100], ev))
            elif any(p in text for p in ["ami-id", "instance-id"]):
                findings.append(Finding("critical", "ssrf_cloud", f"{tool_name}/{probe_name}", text[:100], ev))
            elif any(p in text for p in ["AWS_", "OPENAI_", "DATABASE_URL"]):
                findings.append(Finding("high", "env_leak", f"{tool_name}/{probe_name}", text[:100], ev))
            elif len(text) > 80:
                findings.append(Finding("low", "info_disclosure", f"{tool_name}/{probe_name}", text[:80], ev))

    return findings


def format_state_for_llm(state: dict, findings: list[Finding], phase: int) -> str:
    """Format current state as a prompt for LLM reasoning."""
    output = []
    output.append(f"═══ PHASE {phase} COMPLETE ═══")
    output.append(f"Target: {state['url']}")
    output.append(f"Server: {state.get('server_info', {}).get('name', '?')} v{state.get('server_info', {}).get('version', '?')}")
    output.append(f"\nTools ({len(state.get('tools', []))}):")
    for t in state.get("tools", []):
        output.append(f"  - {t['name']} (params: {t.get('params', [])}) — {t.get('description', '')[:60]}")
    if state.get("resources"):
        output.append(f"\nResources ({len(state['resources'])}):")
        for r in state["resources"]:
            output.append(f"  - {r.get('uri', r.get('name', '?'))} [{r.get('type', '')}]")
    if state.get("prompts"):
        output.append(f"\nPrompts ({len(state['prompts'])}):")
        for p in state["prompts"]:
            output.append(f"  - {p['name']}: {p.get('description', '')[:50]}")
    if findings:
        output.append(f"\nFindings so far ({len(findings)}):")
        for f in findings:
            output.append(f"  [{f.severity.upper()}] {f.title}: {f.details[:60]}")
    output.append(f"\n═══ DECISION NEEDED ═══")
    output.append("What should I probe next? Respond with JSON:")
    output.append('{"probe_order": ["tool_name1", "tool_name2"], "custom_probes": {"tool_name": [{"name": "probe_id", "args": {"param": "value"}}]}, "skip": ["tool_to_skip"], "reason": "why"}')
    return "\n".join(output)


def parse_plan(plan_text: str) -> dict:
    """Parse an LLM-generated plan (JSON or freeform)."""
    # Try JSON first
    try:
        # Find JSON in the response
        start = plan_text.find("{")
        end = plan_text.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(plan_text[start:end])
    except json.JSONDecodeError:
        pass

    # Freeform: extract tool names mentioned
    import re
    tools_mentioned = re.findall(r'["`]([a-z_]+(?:_[a-z]+)*)["`]', plan_text)
    if tools_mentioned:
        return {"probe_order": tools_mentioned, "reason": "Extracted from freeform response"}

    return {"probe_order": [], "reason": "Could not parse plan"}


def run_interactive(url: str, *, stealth_enabled: bool = True):
    """Run agent in interactive mode — pauses for LLM input between phases."""
    stealth = StealthConfig(enabled=stealth_enabled)
    kb = KnowledgeBase.load()
    all_findings: list[Finding] = []

    print("=" * 60)
    print("  MCP AGENT — INTERACTIVE MODE")
    print("  Paste state to your LLM, paste plan back here")
    print("=" * 60)

    # Phase 1: Enumerate
    print("\n  [PHASE 1] Enumerating...")
    state = phase_enumerate(url, stealth)

    if "error" in state:
        print(f"  ERROR: {state['error']}")
        return

    # Also get full tool definitions for probing
    _, resp, _ = send(url, jsonrpc("tools/list"), stealth)
    tools_full = []
    match resp:
        case {"result": {"tools": list(t)}}:
            tools_full = t

    # Test resources/prompts/sampling
    print("  [PHASE 1b] Testing resources/prompts/sampling...")
    all_findings.extend(test_resources(url, stealth))
    all_findings.extend(test_prompts(url, stealth))
    all_findings.extend(test_sampling(url, stealth))

    # Output state for LLM
    llm_prompt = format_state_for_llm(state, all_findings, 1)
    print(f"\n{'─' * 60}")
    print(llm_prompt)
    print(f"{'─' * 60}")

    # Wait for plan
    try:
        print("\n  Paste your LLM's plan (JSON or freeform), then press Enter twice:")
        lines = []
        while True:
            line = input()
            if line == "" and lines and lines[-1] == "":
                break
            lines.append(line)
        plan_text = "\n".join(lines)
    except EOFError:
        # Non-interactive — use built-in reasoning
        plan_text = json.dumps({"probe_order": [t["name"] for t in state.get("tools", [])], "reason": "auto: probe all tools"})

    plan = parse_plan(plan_text)
    print(f"\n  [PLAN RECEIVED] {plan.get('reason', 'No reason given')}")
    print(f"  Probe order: {plan.get('probe_order', [])}")

    # Phase 2: Execute plan
    print("\n  [PHASE 2] Executing plan...")
    probe_order = plan.get("probe_order", [t["name"] for t in state.get("tools", [])])
    custom_probes = plan.get("custom_probes", {})
    skip = set(plan.get("skip", []))

    for tool_name in probe_order:
        if tool_name in skip:
            print(f"    Skipping {tool_name} (per plan)")
            continue

        custom = custom_probes.get(tool_name)
        print(f"    Probing {tool_name}...")
        findings = phase_probe_tool(url, tool_name, tools_full, stealth, kb, custom)
        all_findings.extend(findings)
        for f in findings:
            print(f"      [{f.severity.upper()}] {f.title}")

    # Phase 3: Chain if we have findings
    if kb.leaked_credentials or kb.leaked_endpoints:
        print("\n  [PHASE 3] Exploit chaining...")
        chained = chain_findings(url, all_findings, tools_full, stealth)
        all_findings.extend(chained)
        for f in chained:
            print(f"    [CHAIN] [{f.severity.upper()}] {f.title}")

    # Save and report
    kb.save()
    server_info = {"url": url, "name": state.get("server_info", {}).get("name", "")}
    report_path = generate_report(all_findings, server_info)

    print(f"\n  {'═' * 60}")
    print(f"  COMPLETE — {len(all_findings)} findings")
    print(f"  Report: {report_path}")
    print(f"  {'═' * 60}")


def run_auto(url: str, *, stealth_enabled: bool = True):
    """Run agent autonomously (no human input needed)."""
    from mcp_agent_v3 import run_intelligent_agent
    run_intelligent_agent([url], stealth_enabled=stealth_enabled, deep=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MCP Agent Interactive/Auto Mode")
    parser.add_argument("--url", required=True, help="Target MCP server URL")
    parser.add_argument("--interactive", action="store_true", help="Pause for LLM input between phases")
    parser.add_argument("--no-stealth", action="store_true", help="Disable stealth")
    args = parser.parse_args()

    if args.interactive:
        run_interactive(args.url, stealth_enabled=not args.no_stealth)
    else:
        run_auto(args.url, stealth_enabled=not args.no_stealth)
