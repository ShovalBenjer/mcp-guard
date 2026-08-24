"""Core scanner for MCP tool security analysis."""
from __future__ import annotations

from dataclasses import dataclass

from .types import Severity


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
    """Static security scanner for MCP tool schemas."""

    def scan_tool(self, tool: dict) -> list[ScanResult]:
        """Scan a single MCP tool definition for security issues.

        Args:
            tool: The tool definition dictionary from the MCP server.

        Returns:
            A list of ScanResult entries for each issue found.
        """
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
        """Check for parameters that may accept shell commands.

        Args:
            name: Lowercase tool name.
            desc: Lowercase tool description.
            properties: Input schema properties dictionary.

        Returns:
            A list of ScanResult entries for shell injection risks.
        """
        results: list[ScanResult] = []
        tool_ref = name or "unknown"

        text = f"{name} {desc}"
        if any(kw in text for kw in _SHELL_KEYWORDS):
            results.append(ScanResult(
                rule_id="shell-injection",
                severity=Severity.CRITICAL,
                message=f"Tool '{tool_ref}' may accept shell commands — risk of command injection",
                tool_name=tool_ref,
                remediation="Restrict to predefined commands. Never pass raw user input to shell.",
            ))

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

        return results

    def _check_ssrf(
        self, name: str, desc: str, properties: dict
    ) -> list[ScanResult]:
        """Check for parameters that accept URL input and may enable SSRF.

        Args:
            name: Lowercase tool name.
            desc: Lowercase tool description.
            properties: Input schema properties dictionary.

        Returns:
            A list of ScanResult entries for SSRF risks.
        """
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

        return results

    def _check_missing_schema(self, schema: dict) -> list[ScanResult]:
        """Check if the tool has a missing or empty input schema.

        Args:
            schema: The input schema dictionary from the tool definition.

        Returns:
            A list containing a single ScanResult if schema is missing.
        """
        if not schema or "properties" not in schema:
            return [ScanResult(
                rule_id="missing-schema",
                severity=Severity.WARNING,
                message="Tool has no input schema — no validation on inputs",
                tool_name="unknown",
                remediation="Define an inputSchema with type constraints for all parameters.",
            )]
        return []
