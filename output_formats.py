"""
Output formatters — JSON and SARIF for CI/SIEM integration.

Generates:
  - findings.json (simple JSON array)
  - findings.sarif (SARIF 2.1.0 for GitHub/Azure DevOps/SIEM)
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp_agent_v2 import Finding


def export_json(findings: list[Finding], output_dir: str = "reports") -> Path:
    """Export findings as a simple JSON array."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = Path(output_dir) / f"findings_{timestamp}.json"

    data = [{
        "severity": f.severity,
        "category": f.category,
        "title": f.title,
        "details": f.details,
        "chained_from": f.chained_from,
        "evidence": {
            "request": f.evidence.request_body if f.evidence else None,
            "response_code": f.evidence.response_code if f.evidence else None,
            "response": f.evidence.response_body[:1000] if f.evidence else None,
            "timestamp": f.evidence.timestamp if f.evidence else None,
        } if f.evidence else None,
    } for f in findings]

    path.write_text(json.dumps({"findings": data, "count": len(data), "generated": datetime.now().isoformat()}, indent=2), encoding="utf-8")
    return path


def export_sarif(findings: list[Finding], target_url: str = "", output_dir: str = "reports") -> Path:
    """Export findings in SARIF 2.1.0 format for CI integration."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = Path(output_dir) / f"findings_{timestamp}.sarif"

    severity_to_level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}

    rules = []
    results = []
    rule_ids: dict[str, int] = {}

    for f in findings:
        # Create rule if new category
        if f.category not in rule_ids:
            rule_ids[f.category] = len(rules)
            rules.append({
                "id": f.category,
                "name": f.category.replace("_", " ").title(),
                "shortDescription": {"text": f.category},
                "defaultConfiguration": {"level": severity_to_level.get(f.severity, "warning")},
            })

        results.append({
            "ruleId": f.category,
            "level": severity_to_level.get(f.severity, "warning"),
            "message": {"text": f"{f.title}\n{f.details}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": target_url or "mcp-server"},
                }
            }],
            "properties": {
                "severity": f.severity,
                "chained_from": f.chained_from,
                "evidence_response_code": f.evidence.response_code if f.evidence else None,
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "aicu-agent",
                    "version": "3.0.0",
                    "informationUri": "https://github.com/Jake-Schoellkopf/aicu-agent",
                    "rules": rules,
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.now().isoformat() + "Z",
            }],
        }],
    }

    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return path
