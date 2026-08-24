"""Tests for the fuzz engine core."""
from __future__ import annotations

from mcp_guard.fuzzer import FuzzEngine, FuzzResult, ResultCategory


class FakeTransport:
    """Simulates an MCP server for testing the fuzz engine."""

    def __init__(self, responses=None, reject_all=False):
        self.calls: list[dict] = []
        self.responses = responses or {}
        self.crashed = False
        self.reject_all = reject_all

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        self.calls.append({"tool": tool_name, "arguments": arguments})
        if self.crashed:
            raise ConnectionError("Server crashed")
        if self.reject_all:
            return {
                "isError": True,
                "content": [{"type": "text", "text": "Invalid input rejected"}],
            }
        key = f"{tool_name}:{sorted(arguments.items())}"
        return self.responses.get(key, {"content": [{"type": "text", "text": "ok"}]})


STRING_TOOL = {
    "name": "execute",
    "description": "Run a command",
    "inputSchema": {
        "type": "object",
        "properties": {"cmd": {"type": "string"}},
        "required": ["cmd"],
    },
}


def test_fuzzer_enumerates_and_fuzzes_single_tool():
    """FuzzEngine should accept a tool schema, generate payloads, fire them."""
    transport = FakeTransport()
    engine = FuzzEngine(transport=transport)

    results = engine.fuzz_tool(STRING_TOOL)
    assert len(results) > 0, "Fuzzer must produce results"
    assert all(isinstance(r, FuzzResult) for r in results)
    assert len(transport.calls) > 0, "Fuzzer must have called the tool"


def test_fuzzer_detects_crash():
    """When server crashes mid-fuzz, fuzzer must detect it."""
    transport = FakeTransport()
    transport.crashed = True
    engine = FuzzEngine(transport=transport)

    results = engine.fuzz_tool(STRING_TOOL)
    crash_results = [r for r in results if r.category == ResultCategory.CRASH]
    assert len(crash_results) > 0, "Must detect server crash"


def test_fuzzer_classifies_expected_errors_as_safe():
    """A clean error response (e.g. validation rejection) should be SAFE, not a finding."""
    transport = FakeTransport(reject_all=True)
    engine = FuzzEngine(transport=transport)

    results = engine.fuzz_tool(STRING_TOOL)
    findings = [r for r in results if r.category != ResultCategory.SAFE]
    assert len(findings) == 0, "Expected errors should be classified as SAFE"


def test_fuzz_result_has_reproduction_info():
    """Every FuzzResult must include enough info to reproduce."""
    transport = FakeTransport()
    engine = FuzzEngine(transport=transport)

    results = engine.fuzz_tool(STRING_TOOL)
    for r in results:
        assert r.tool_name == "execute"
        assert hasattr(r, "payload_value")
        assert r.probe_name != ""


def test_fuzzer_handles_no_schema_tools():
    """A tool with no input schema must be fuzzed with generic payloads."""
    transport = FakeTransport()
    engine = FuzzEngine(transport=transport)

    tool = {"name": "loose", "description": "No schema"}
    results = engine.fuzz_tool(tool)

    assert len(results) > 0, "No-schema tool must still be fuzzed"
    assert all(isinstance(r, FuzzResult) for r in results)
    assert len(transport.calls) > 0


def test_fuzzer_fires_type_confusion_payloads():
    """Type-confusion payloads (int/bool/null/array/object) must be sent."""
    transport = FakeTransport()
    engine = FuzzEngine(transport=transport)

    engine.fuzz_tool(STRING_TOOL)
    sent_values = [call["arguments"]["cmd"] for call in transport.calls]
    assert any(v is None for v in sent_values)
    assert any(isinstance(v, bool) for v in sent_values)
    assert any(isinstance(v, (int, list, dict)) for v in sent_values)


def test_fuzzer_fires_overflow_payloads():
    """Overflow payloads must be sent as oversized strings."""
    transport = FakeTransport()
    engine = FuzzEngine(transport=transport)

    results = engine.fuzz_tool(STRING_TOOL)
    overflow = [r for r in results if r.rule_id == "overflow"]
    assert overflow, "Must have overflow results"
    assert any(isinstance(r.payload_value, str) and len(r.payload_value) > 10_000 for r in overflow)


def test_fuzzer_classifies_info_leak():
    """A response leaking internal info must be a high-severity info-leak finding."""
    transport = FakeTransport(
        responses={
            "execute:[('cmd', '; rm -rf /')]": {
                "content": [{"type": "text", "text": "traceback: api_key=supersecret"}]
            }
        }
    )
    engine = FuzzEngine(transport=transport)

    results = engine.fuzz_tool(STRING_TOOL)
    leaks = [r for r in results if r.rule_id.endswith("-info-leak")]
    assert leaks, "Must detect info-leak"
    assert leaks[0].severity == "high"
    assert leaks[0].category == ResultCategory.FINDING


def test_fuzzer_delay_ms_is_stored_and_does_not_break():
    """The engine must accept a delay_ms and continue fuzzing normally."""
    transport = FakeTransport()
    engine = FuzzEngine(transport=transport, delay_ms=50)
    assert engine._delay_ms == 50

    results = engine.fuzz_tool(STRING_TOOL)
    assert len(results) == len(transport.calls)
    assert len(results) > 0


def test_fuzzer_handles_multiple_tools():
    """Fuzzing multiple tools must keep their results separated by tool name."""
    transport = FakeTransport()
    engine = FuzzEngine(transport=transport)

    tools = [
        STRING_TOOL,
        {
            "name": "fetch",
            "description": "Fetch a url",
            "inputSchema": {
                "type": "object",
                "properties": {"url": {"type": "string", "format": "uri"}},
                "required": ["url"],
            },
        },
    ]
    all_results: list[FuzzResult] = []
    for tool in tools:
        all_results.extend(engine.fuzz_tool(tool))

    names = {r.tool_name for r in all_results}
    assert names == {"execute", "fetch"}


def test_fuzzer_handles_empty_required_set():
    """A tool with an empty required list must still be fuzzed without error."""
    transport = FakeTransport()
    engine = FuzzEngine(transport=transport)

    tool = {
        "name": "optional",
        "description": "All params optional",
        "inputSchema": {
            "type": "object",
            "properties": {"q": {"type": "string"}},
            "required": [],
        },
    }
    results = engine.fuzz_tool(tool)
    assert len(results) > 0
    assert len(transport.calls) > 0
