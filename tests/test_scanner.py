"""Tests for the static schema scanner."""
from __future__ import annotations

from mcp_guard.scanner import Scanner, ScanResult, Severity


def test_scanner_flags_tool_with_shell_command():
    """A tool that accepts shell commands must be flagged as CRITICAL."""
    fake_tool = {
        "name": "run_bash",
        "description": "Execute a bash command on the server",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to run"}
            },
            "required": ["command"],
        },
    }

    scanner = Scanner()
    results = scanner.scan_tool(fake_tool)

    assert len(results) > 0, "Scanner must return at least one finding"

    shell_findings = [r for r in results if "shell" in r.rule_id or "command" in r.rule_id]
    assert len(shell_findings) > 0, "Must flag shell/command injection"
    assert shell_findings[0].severity == Severity.CRITICAL
    assert isinstance(shell_findings[0], ScanResult)


def test_scanner_passes_safe_tool():
    """A read-only tool with constrained input must pass cleanly."""
    safe_tool = {
        "name": "get_weather",
        "description": "Get current weather for a city",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string", "enum": ["tel-aviv", "london", "nyc"]}
            },
            "required": ["city"],
        },
    }

    scanner = Scanner()
    results = scanner.scan_tool(safe_tool)

    criticals = [r for r in results if r.severity == Severity.CRITICAL]
    assert len(criticals) == 0, "Safe tool must not have critical findings"


def test_scanner_flags_url_parameter_as_ssrf():
    """A tool that accepts a URL parameter must be flagged for SSRF risk."""
    url_tool = {
        "name": "fetch_url",
        "description": "Fetch content from a URL",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "format": "uri"}
            },
            "required": ["url"],
        },
    }

    scanner = Scanner()
    results = scanner.scan_tool(url_tool)

    ssrf_findings = [r for r in results if "ssrf" in r.rule_id]
    assert len(ssrf_findings) > 0, "Must flag SSRF risk on URL parameter"
    assert ssrf_findings[0].severity in (Severity.CRITICAL, Severity.WARNING)


def test_scanner_detects_missing_schema():
    """A tool without an input schema must be flagged with missing-schema."""
    scanner = Scanner()
    no_schema = {"name": "loose", "description": "no schema here"}
    empty_props = {
        "name": "empty",
        "description": "empty schema",
        "inputSchema": {"type": "object"},
    }

    for tool in (no_schema, empty_props):
        results = scanner.scan_tool(tool)
        missing = [r for r in results if r.rule_id == "missing-schema"]
        assert missing, f"Must flag missing-schema for {tool['name']}"
        assert missing[0].severity == Severity.WARNING


def test_scanner_ssrf_with_enum_constraint_downgrades_to_warning():
    """An SSRF-capable URL param constrained by an enum must be WARNING, not CRITICAL."""
    tool = {
        "name": "proxy",
        "description": "Proxy a request",
        "inputSchema": {
            "type": "object",
            "properties": {
                "endpoint": {
                    "type": "string",
                    "format": "uri",
                    "enum": ["https://a.test", "https://b.test"],
                }
            },
            "required": ["endpoint"],
        },
    }

    scanner = Scanner()
    results = scanner.scan_tool(tool)
    ssrf = [r for r in results if r.rule_id == "ssrf-risk"]
    assert ssrf, "Must flag SSRF"
    assert ssrf[0].severity == Severity.WARNING


def test_scanner_detects_url_without_format_uri_by_keyword():
    """A URL-like parameter with no format:uri must still be flagged via keyword."""
    tool = {
        "name": "webhook",
        "description": "Register a callback",
        "inputSchema": {
            "type": "object",
            "properties": {
                "callback_url": {"type": "string"}
            },
            "required": ["callback_url"],
        },
    }

    scanner = Scanner()
    results = scanner.scan_tool(tool)
    ssrf = [r for r in results if r.rule_id == "ssrf-risk"]
    assert ssrf, "Must flag SSRF via keyword detection"
    assert ssrf[0].severity == Severity.CRITICAL


def test_scanner_flags_multiple_dangerous_properties():
    """A tool with both shell and URL params must produce multiple findings."""
    tool = {
        "name": "swiss_army",
        "description": "Does everything",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command"},
                "target_url": {"type": "string", "format": "uri"},
            },
            "required": ["command", "target_url"],
        },
    }

    scanner = Scanner()
    results = scanner.scan_tool(tool)
    rule_ids = {r.rule_id for r in results}
    assert "shell-injection" in rule_ids
    assert "ssrf-risk" in rule_ids
    assert len(results) >= 2


def test_scanner_is_case_insensitive():
    """Tool name/description casing must not affect detection."""
    tool = {
        "name": "Run_BASH",
        "description": "EXECUTE A SHELL COMMAND",
        "inputSchema": {
            "type": "object",
            "properties": {
                "COMMAND": {"type": "string", "description": "BASH COMMAND"},
            },
            "required": ["COMMAND"],
        },
    }

    scanner = Scanner()
    results = scanner.scan_tool(tool)
    shell = [r for r in results if r.rule_id == "shell-injection"]
    assert shell, "Must detect shell injection regardless of casing"


def test_scanner_handles_empty_tool_description():
    """A tool with an empty description must still scan its properties."""
    tool = {
        "name": "runner",
        "description": "",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cmd": {"type": "string", "description": "command"},
            },
            "required": ["cmd"],
        },
    }

    scanner = Scanner()
    results = scanner.scan_tool(tool)
    assert any(r.rule_id == "shell-injection" for r in results)
