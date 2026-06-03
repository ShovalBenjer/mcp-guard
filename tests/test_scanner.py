"""RED: First failing test for mcp-guard core scanner."""
from mcp_guard.scanner import ScanResult, Scanner, Severity


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
