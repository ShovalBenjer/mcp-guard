"""Tests for the mcp-guard CLI entry point."""
from __future__ import annotations

import pytest

import mcp_guard.cli as cli
from mcp_guard.fuzzer import FuzzResult, ResultCategory
from mcp_guard.scanner import ScanResult, Severity


class FakeTransport:
    """Stand-in for StdioTransport that never spawns a subprocess."""

    def __init__(self, command, timeout=30.0):
        self.command = command
        self.timeout = timeout
        self.entered = False
        self.exited = False
        self.tools = [
            {
                "name": "run_bash",
                "description": "Execute a bash command on the server",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "Shell command to run"}
                    },
                    "required": ["command"],
                },
            },
            {
                "name": "get_weather",
                "description": "Get weather for a city",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "city": {"type": "string", "enum": ["tel-aviv", "london"]}
                    },
                    "required": ["city"],
                },
            },
        ]
        self.crashed = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, *exc):
        self.exited = True
        return False

    def list_tools(self):
        return self.tools

    def call_tool(self, tool_name, arguments):
        if self.crashed:
            raise ConnectionError("Server crashed")
        return {"content": [{"type": "text", "text": "ok"}]}


@pytest.fixture
def fake_transport(monkeypatch):
    inst = FakeTransport(["fake", "server"])
    monkeypatch.setattr(cli, "StdioTransport", lambda command, timeout=30.0: inst)
    return inst


def test_no_subcommand_prints_help():
    """With no subcommand, main prints help and returns None."""
    assert cli.main([]) is None


def test_fuzz_table_format_runs(fake_transport, capsys):
    cli.main(["fuzz", "--", "fake", "server"])
    out = capsys.readouterr().out
    assert "mcp-guard fuzz report" in out
    assert "Tools fuzzed" in out
    assert fake_transport.entered and fake_transport.exited


def test_fuzz_json_format_runs(fake_transport, capsys):
    cli.main(["fuzz", "--format", "json", "--", "fake", "server"])
    out = capsys.readouterr().out
    assert out.strip().startswith("{")
    import json

    data = json.loads(out)
    assert "summary" in data
    assert data["server"] == "fake server"


def test_fuzz_sarif_format_runs(fake_transport, capsys):
    cli.main(["fuzz", "--format", "sarif", "--", "fake", "server"])
    out = capsys.readouterr().out
    import json

    sarif = json.loads(out)
    assert sarif["version"] == "2.1.0"


def test_fuzz_crashes_exit_code_2(fake_transport):
    fake_transport.crashed = True
    with pytest.raises(SystemExit) as exc:
        cli.main(["fuzz", "--", "fake", "server"])
    assert exc.value.code == 2


def test_fuzz_without_server_command_exits_1():
    with pytest.raises(SystemExit) as exc:
        cli.main(["fuzz"])
    assert exc.value.code == 1


def test_scan_reports_findings_and_passes(fake_transport, capsys):
    cli.main(["scan", "--", "fake", "server"])
    out = capsys.readouterr().out
    assert "run_bash" in out
    assert "get_weather" in out
    assert "PASS" in out
    assert "SHELL" in out.upper() or "shell-injection".upper() in out.upper()


def test_scan_json_format_runs(fake_transport, capsys):
    cli.main(["scan", "--format", "json", "--", "fake", "server"])
    out = capsys.readouterr().out
    assert "run_bash" in out
    assert "get_weather" in out


def test_scan_output_file_written(fake_transport, tmp_path):
    out_file = tmp_path / "scan.txt"
    cli.main(["--output-file", str(out_file), "scan", "--", "fake", "server"])
    assert out_file.exists()
    content = out_file.read_text()
    assert "run_bash" in content
    assert "get_weather" in content


def test_invalid_format_choice_exits(fake_transport):
    with pytest.raises(SystemExit):
        cli.main(["fuzz", "--format", "xml", "--", "fake", "server"])


def test_verbose_and_quiet_flags_do_not_crash(fake_transport, capsys):
    cli.main(["--verbose", "fuzz", "--", "fake", "server"])
    capsys.readouterr()
    cli.main(["--quiet", "fuzz", "--", "fake", "server"])
    capsys.readouterr()
