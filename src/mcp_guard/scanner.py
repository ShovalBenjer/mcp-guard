"""Core scanner for MCP tool security analysis."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ScanResult:
    rule_id: str
    severity: Severity
    message: str
    tool_name: str
    remediation: str = ""


_SHELL_KEYWORDS = frozenset({
    "bash", "shell", "command", "exec", "execute", "powershell",
    "terminal", "cmd", "script", "run_command", "subprocess",
})

_URL_KEYWORDS = frozenset({
    "url", "uri", "endpoint", "link", "href", "webhook", "callback_url",
})

_ENV_KEYWORDS = frozenset({
    "env", "environment", "secret", "token", "password", "apikey", "api_key",
})


class Scanner:
    def scan_tool(self, tool: dict) -> list[ScanResult]:
        findings: list[ScanResult] = []
        name = tool.get("name", "").lower()
        desc = tool.get("description", "").lower()
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})

        findings.extend(self._check_shell_injection(name, desc, properties))
        findings.extend(self._check_ssrf(name, desc, properties))
        findings.extend(self._check_missing_schema(schema))

        return findings

    def _check_shell_injection(
        self, name: str, desc: str, properties: dict
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        tool_ref = name or "unknown"

        # Check name + description
        text = f"{name} {desc}"
        if any(kw in text for kw in _SHELL_KEYWORDS):
            results.append(ScanResult(
                rule_id="shell-injection",
                severity=Severity.CRITICAL,
                message=f"Tool '{tool_ref}' may accept shell commands — risk of command injection",
                tool_name=tool_ref,
                remediation="Restrict to predefined commands. Never pass raw user input to shell.",
            ))
            return results

        # Check property names and descriptions
        for prop_name, prop_def in properties.items():
            prop_desc = prop_def.get("description", "").lower()
            prop_text = f"{prop_name} {prop_desc}"
            if any(kw in prop_text for kw in _SHELL_KEYWORDS):
                results.append(ScanResult(
                    rule_id="shell-injection",
                    severity=Severity.CRITICAL,
                    message=f"Parameter '{prop_name}' may accept shell commands",
                    tool_name=tool_ref,
                    remediation="Use enum constraints or allowlists for command parameters.",
                ))
                break

        return results

    def _check_ssrf(
        self, name: str, desc: str, properties: dict
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        tool_ref = name or "unknown"

        for prop_name, prop_def in properties.items():
            fmt = prop_def.get("format", "").lower()
            prop_desc = prop_def.get("description", "").lower()
            prop_text = f"{prop_name} {prop_desc}"

            is_url = (
                fmt == "uri"
                or any(kw in prop_text for kw in _URL_KEYWORDS)
            )
            if is_url:
                has_enum = "enum" in prop_def
                severity = Severity.WARNING if has_enum else Severity.CRITICAL
                results.append(ScanResult(
                    rule_id="ssrf-risk",
                    severity=severity,
                    message=f"Parameter '{prop_name}' accepts URL input — potential SSRF vector",
                    tool_name=tool_ref,
                    remediation="Validate URL scheme (https only). Block private IP ranges. Use an allowlist.",
                ))
                break

        return results

    def _check_missing_schema(self, schema: dict) -> list[ScanResult]:
        if not schema or "properties" not in schema:
            return [ScanResult(
                rule_id="missing-schema",
                severity=Severity.WARNING,
                message="Tool has no input schema — no validation on inputs",
                tool_name="unknown",
                remediation="Define an inputSchema with type constraints for all parameters.",
            )]
        return []
