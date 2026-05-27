"""
False Positive Filter

Strict validation layer that eliminates false positives before reporting.
A finding only counts if it passes ALL validation checks.

Rules:
- Response must contain ACTUAL sensitive data (not just keywords in error messages)
- Response must NOT be an error/denial/refusal
- Response must differ from a baseline "denied" response
- Credential patterns must be full-length valid formats (not partial matches)
- SSRF must return actual metadata content (not just a 200 status)
- Path traversal must return file content (not just the path echoed back)

Requires: Python 3.12+
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from mcp_agent_v2 import Finding


# ============================================================
# VALIDATION RULES
# ============================================================

DENIAL_PATTERNS = [
    "access denied", "permission denied", "unauthorized", "forbidden",
    "not allowed", "blocked", "rejected", "invalid", "error",
    "not found", "does not exist", "no such", "cannot",
    "incident logged", "security", "restricted",
]

# Real credential formats (must match full pattern, not just prefix)
CREDENTIAL_VALIDATORS = {
    "AWS_ACCESS_KEY": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS_SECRET_KEY": re.compile(r"[A-Za-z0-9/+=]{40}"),
    "OPENAI_KEY": re.compile(r"sk-[A-Za-z0-9]{32,}"),
    "GITHUB_TOKEN": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "GITLAB_TOKEN": re.compile(r"glpat-[A-Za-z0-9\-]{20}"),
    "SLACK_TOKEN": re.compile(r"xox[bpras]-[A-Za-z0-9\-]+"),
    "PRIVATE_KEY": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "CONNECTION_STRING": re.compile(r"(postgres|mysql|mongodb|redis|amqp)://[^\s\"']+:[^\s\"']+@[^\s\"']+"),
}

# System file content validators (must contain actual file content, not just path)
SYSTEM_FILE_VALIDATORS = [
    re.compile(r"root:[x*]:0:0:"),  # /etc/passwd
    re.compile(r"daemon:[x*]:\d+:\d+:"),  # /etc/passwd continued
    re.compile(r"-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----"),  # SSH key
    re.compile(r"(export\s+)?[A-Z_]+=.+", re.MULTILINE),  # env file
]

# Cloud metadata validators (must contain actual metadata, not just URL echo)
CLOUD_METADATA_VALIDATORS = [
    re.compile(r"ami-[a-f0-9]+"),
    re.compile(r"i-[a-f0-9]+"),
    re.compile(r"\"(AccessKeyId|SecretAccessKey|Token)\""),
    re.compile(r"arn:aws:[a-z]+:[a-z0-9-]*:\d+:"),
]


def is_denial(text: str) -> bool:
    """Check if response is actually a denial/error, not real data."""
    lower = text.lower().strip()
    # Short responses that are just errors
    if len(lower) < 100 and any(d in lower for d in DENIAL_PATTERNS):
        return True
    # Response is ONLY an error message (no other content)
    if all(d in lower for d in ["error"]) and len(lower) < 200:
        return True
    return False


def is_echo(probe_args: dict, response: str) -> bool:
    """Check if response just echoes back our input (not real data)."""
    for value in probe_args.values():
        if isinstance(value, str) and len(value) > 5:
            # If >60% of our input appears verbatim in the response, it's an echo
            if value in response:
                return True
    return False


def validate_credential(text: str) -> str | None:
    """Validate that a credential pattern is a real, full-format credential."""
    for cred_type, pattern in CREDENTIAL_VALIDATORS.items():
        if match := pattern.search(text):
            # Additional check: not a placeholder/example
            value = match.group(0)
            if any(p in value.lower() for p in ["example", "placeholder", "xxx", "your-", "replace"]):
                return None
            return cred_type
    return None


def validate_system_file(text: str) -> bool:
    """Validate that response contains actual system file content."""
    return any(v.search(text) for v in SYSTEM_FILE_VALIDATORS)


def validate_cloud_metadata(text: str) -> bool:
    """Validate that response contains actual cloud metadata."""
    return any(v.search(text) for v in CLOUD_METADATA_VALIDATORS)


def validate_env_vars(text: str) -> bool:
    """Validate that response contains real environment variables (not just names)."""
    # Must have KEY=VALUE format with actual values
    env_pattern = re.compile(r"^[A-Z][A-Z0-9_]+=.{3,}", re.MULTILINE)
    matches = env_pattern.findall(text)
    # Need at least 2 real env vars to count
    return len(matches) >= 2


# ============================================================
# MAIN FILTER
# ============================================================

def validate_finding(finding: Finding, probe_args: dict | None = None) -> bool:
    """
    Returns True if the finding is VALID (not a false positive).
    Returns False if it should be discarded.
    """
    # No evidence = can't validate = discard
    if not finding.evidence:
        return False

    response = finding.evidence.response_body

    # Rule 1: Must not be a denial/error
    if is_denial(response):
        return False

    # Rule 2: Must not be an echo of our input
    if probe_args and is_echo(probe_args, response):
        return False

    # Rule 3: Must have substantial content (not empty/trivial)
    if len(response.strip()) < 20:
        return False

    # Rule 4: Category-specific validation
    match finding.category:
        case "credential_leak":
            # Must contain a real, full-format credential
            return validate_credential(response) is not None

        case "system_file":
            # Must contain actual file content, not just path
            return validate_system_file(response)

        case "ssrf_cloud" | "ssrf":
            # Must contain actual metadata, not just a 200 response
            return validate_cloud_metadata(response)

        case "env_leak":
            # Must contain real KEY=VALUE pairs
            return validate_env_vars(response)

        case "info_disclosure":
            # For low-severity info disclosure, require longer meaningful content
            if len(response) < 100:
                return False
            # Must not be a generic help/usage message
            if any(k in response.lower() for k in ("usage:", "help:", "available commands", "syntax")):
                return False
            return True

        case "resource_read" | "prompt_leak":
            # Must contain something beyond just the resource name
            return len(response) > 50 and not is_denial(response)

        case "sampling_abuse":
            # Must show the LLM actually processed our injection
            return len(response) > 30 and not is_denial(response)

        case "cross_server_access" | "chained_access":
            # Must return real data, not just a non-error status
            return len(response) > 50 and not is_denial(response)

        case _:
            # Unknown category — require substantial non-error response
            return len(response) > 50 and not is_denial(response)


def filter_findings(findings: list[Finding], probe_log: dict[str, dict] | None = None) -> list[Finding]:
    """
    Filter a list of findings, removing false positives.
    
    Args:
        findings: Raw findings from scanning
        probe_log: Optional dict mapping finding titles to their probe args
    
    Returns:
        Validated findings only
    """
    validated = []
    removed = 0

    for f in findings:
        args = probe_log.get(f.title, {}) if probe_log else None
        if validate_finding(f, args):
            validated.append(f)
        else:
            removed += 1

    if removed:
        print(f"    [FP FILTER] Removed {removed} false positives, {len(validated)} validated findings remain")

    return validated
