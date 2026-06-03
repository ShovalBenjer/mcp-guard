"""RED: Failing tests for fuzz engine core."""
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
            return {"isError": True, "content": [{"type": "text", "text": "Invalid input rejected"}]}
        key = f"{tool_name}:{sorted(arguments.items())}"
        return self.responses.get(key, {"content": [{"type": "text", "text": "ok"}]})


def test_fuzzer_enumerates_and_fuzzes_single_tool():
    """FuzzEngine should accept a tool schema, generate payloads, fire them."""
    transport = FakeTransport()
    engine = FuzzEngine(transport=transport)

    tool = {
        "name": "execute",
        "description": "Run a command",
        "inputSchema": {
            "type": "object",
            "properties": {"cmd": {"type": "string"}},
            "required": ["cmd"],
        },
    }

    results = engine.fuzz_tool(tool)
    assert len(results) > 0, "Fuzzer must produce results"
    assert all(isinstance(r, FuzzResult) for r in results)
    assert len(transport.calls) > 0, "Fuzzer must have called the tool"


def test_fuzzer_detects_crash():
    """When server crashes mid-fuzz, fuzzer must detect it."""
    transport = FakeTransport()
    transport.crashed = True
    engine = FuzzEngine(transport=transport)

    tool = {
        "name": "fragile",
        "description": "Crashes easily",
        "inputSchema": {
            "type": "object",
            "properties": {"input": {"type": "string"}},
            "required": ["input"],
        },
    }

    results = engine.fuzz_tool(tool)
    crash_results = [r for r in results if r.category == ResultCategory.CRASH]
    assert len(crash_results) > 0, "Must detect server crash"


def test_fuzzer_classifies_expected_errors_as_safe():
    """A clean error response (e.g. validation rejection) should be SAFE, not a finding."""
    transport = FakeTransport(reject_all=True)
    engine = FuzzEngine(transport=transport)

    tool = {
        "name": "safe_tool",
        "description": "Safely rejects bad input",
        "inputSchema": {
            "type": "object",
            "properties": {"input": {"type": "string"}},
            "required": ["input"],
        },
    }

    results = engine.fuzz_tool(tool)
    findings = [r for r in results if r.category != ResultCategory.SAFE]
    assert len(findings) == 0, "Expected errors should be classified as SAFE"


def test_fuzz_result_has_reproduction_info():
    """Every FuzzResult must include enough info to reproduce."""
    transport = FakeTransport()
    engine = FuzzEngine(transport=transport)

    tool = {
        "name": "test",
        "description": "Test tool",
        "inputSchema": {
            "type": "object",
            "properties": {"x": {"type": "string"}},
            "required": ["x"],
        },
    }

    results = engine.fuzz_tool(tool)
    for r in results:
        assert r.tool_name == "test"
        assert hasattr(r, "payload_value")
        assert r.probe_name != ""
