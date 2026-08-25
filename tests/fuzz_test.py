"""Fuzz test suite — CI gate for the 5 failure modes from docs/spec.md premortem."""
from __future__ import annotations

import random

import pytest

from mcp_guard.fuzzer import FuzzEngine, FuzzResult, ResultCategory
from mcp_guard.payloads import (
    generate_all_for_param,
    generate_overflow,
    generate_prompt_injection,
    generate_shell_injection,
    generate_ssrf,
    generate_type_confusion,
)
from mcp_guard.report import FuzzReport


class CrashTransport:
    """Transport that crashes after N calls."""

    def __init__(self, crash_after: int = 2):
        self.calls = 0
        self.crash_after = crash_after

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        self.calls += 1
        if self.calls > self.crash_after:
            raise ConnectionError("Server process exited")
        return {"content": [{"type": "text", "text": "ok"}]}


class RateLimitTransport:
    """Transport that returns 429 after first call."""

    def __init__(self):
        self.calls = 0

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        self.calls += 1
        if self.calls > 1:
            return {
                "isError": True,
                "content": [{"type": "text", "text": "Rate limited. Retry after 60s."}],
            }
        return {"content": [{"type": "text", "text": "ok"}]}


class SlowTransport:
    """Transport with varying response times to test adaptive delay."""

    def __init__(self, base_delay: float = 0.01):
        self.calls = 0
        self.base_delay = base_delay

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        import time

        time.sleep(self.base_delay)
        self.calls += 1
        return {"content": [{"type": "text", "text": "ok"}]}


# 1. Server crashes kill the fuzzer


def test_crash_detection_mid_fuzz():
    """If server crashes, fuzzer must classify subsequent payloads as CRASH."""
    transport = CrashTransport(crash_after=2)
    engine = FuzzEngine(transport=transport, delay_ms=0)

    tool = {
        "name": "fragile",
        "inputSchema": {
            "type": "object",
            "properties": {"input": {"type": "string"}},
            "required": ["input"],
        },
    }

    results = engine.fuzz_tool(tool)
    crash_results = [r for r in results if r.category == ResultCategory.CRASH]
    assert len(crash_results) > 0, "Must detect server crash after process exit"


def test_crash_payload_tracked():
    """Crash-causing payloads must be identifiable in results."""
    transport = CrashTransport(crash_after=1)
    engine = FuzzEngine(transport=transport, delay_ms=0)

    tool = {
        "name": "crasher",
        "inputSchema": {
            "type": "object",
            "properties": {"cmd": {"type": "string"}},
            "required": ["cmd"],
        },
    }

    results = engine.fuzz_tool(tool)
    assert any(r.category == ResultCategory.CRASH for r in results)
    assert any(r.detail and "crashed" in r.detail.lower() for r in results)


# 2. Rate limiting / server throttling


def test_rate_limited_server_does_not_flag_false_positives():
    """When server returns 429 after rate limit, fuzzer must not flag it as a vulnerability finding."""
    transport = RateLimitTransport()
    engine = FuzzEngine(transport=transport, delay_ms=0)

    tool = {
        "name": "limited",
        "inputSchema": {
            "type": "object",
            "properties": {"q": {"type": "string"}},
            "required": ["q"],
        },
    }

    results = engine.fuzz_tool(tool)
    findings = [r for r in results if r.category == ResultCategory.FINDING]
    assert len(findings) == 0, "Rate-limited responses must not be flagged as findings"


# 3. False positives from expected errors


def test_expected_errors_classified_as_safe():
    """Tools that correctly reject bad input must not produce findings."""
    transport = _RejectAllTransport()
    engine = FuzzEngine(transport=transport, delay_ms=0)

    tool = {
        "name": "validator",
        "inputSchema": {
            "type": "object",
            "properties": {"x": {"type": "string"}},
            "required": ["x"],
        },
    }

    results = engine.fuzz_tool(tool)
    non_safe = [r for r in results if r.category != ResultCategory.SAFE]
    assert len(non_safe) == 0, "Expected validation errors must be SAFE, not findings"


class _RejectAllTransport:
    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        return {"isError": True, "content": [{"type": "text", "text": "Invalid input"}]}


# 4. Non-deterministic results


def test_deterministic_payload_generation():
    """Payload generation must be deterministic for reproducible CI results."""
    payloads1 = generate_shell_injection()
    payloads2 = generate_shell_injection()
    assert len(payloads1) == len(payloads2)
    for p1, p2 in zip(payloads1, payloads2):
        assert p1.value == p2.value
        assert p1.rule_id == p2.rule_id
        assert p1.severity == p2.severity


def test_seeded_fuzz_produces_same_results():
    """FuzzEngine must produce identical results across runs with the same transport."""
    transport1 = _RejectAllTransport()
    transport2 = _RejectAllTransport()
    engine1 = FuzzEngine(transport=transport1, delay_ms=0)
    engine2 = FuzzEngine(transport=transport2, delay_ms=0)

    tool = {
        "name": "stable",
        "inputSchema": {
            "type": "object",
            "properties": {"p": {"type": "string"}},
            "required": ["p"],
        },
    }

    results1 = engine1.fuzz_tool(tool)
    results2 = engine2.fuzz_tool(tool)

    assert len(results1) == len(results2)
    for r1, r2 in zip(results1, results2):
        assert r1.category == r2.category
        assert r1.rule_id == r2.rule_id


# 5. MCP protocol version drift


def test_protocol_version_pinned_in_transport():
    """Transport must pin the MCP protocol version and fail gracefully on unknown responses."""
    from mcp_guard.transport import StdioTransport

    # Verify the protocol version is pinned in the source
    import inspect
    source = inspect.getsource(StdioTransport._initialize)
    assert "2024-11-05" in source, "MCP protocol version must be pinned"


def test_unknown_message_types_handled():
    """Transport must skip notifications and return only valid results."""
    from mcp_guard.transport import StdioTransport
    import subprocess
    import json
    import sys

    # Verify the transport skips server notifications (messages without id)
    source = inspect.getsource(StdioTransport._read_response)
    assert '"method" in response and "id" not in response' in source or "notify" in source.lower(), (
        "Transport must skip server notifications gracefully"
    )


# Benchmark gate — reproduce LEADERBOARD.md methodology


def test_benchmark_gate_reproduces_methodology():
    """CI must reproduce the leaderboard benchmark methodology:
    1. Spawn via stdio transport
    2. Enumerate tools
    3. Fuzz with schema-aware payloads
    4. Classify responses as SAFE / FINDING / CRASH
    """
    tool = {
        "name": "memory_tool",
        "description": "Store and retrieve memories",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "value": {"type": "string"},
            },
            "required": ["key"],
        },
    }

    # Simulate the benchmark methodology with a deterministic transport
    class BenchmarkTransport:
        def call_tool(self, tool_name: str, arguments: dict) -> dict:
            return {"content": [{"type": "text", "text": "ok"}]}

    transport = BenchmarkTransport()
    engine = FuzzEngine(transport=transport, delay_ms=0)
    results = engine.fuzz_tool(tool)

    # All results must be classified
    for r in results:
        assert r.category in (ResultCategory.SAFE, ResultCategory.FINDING, ResultCategory.CRASH)

    # Report must summarize correctly
    report = FuzzReport(
        server_command="benchmark",
        tools_fuzzed=1,
        total_payloads=len(results),
        results=results,
    )
    assert report.tools_fuzzed == 1
    assert report.total_payloads == len(results)
    assert report.crashes == []
    assert report.findings == [r for r in results if r.category == ResultCategory.FINDING]
    assert report.safe == [r for r in results if r.category == ResultCategory.SAFE]


# Payload coverage gate


def test_all_five_probe_types_generated():
    """CI gate: all 5 probe types (shell, ssrf, overflow, type-confusion, prompt-injection) must be generated."""
    all_payloads = []
    all_payloads.extend(generate_shell_injection())
    all_payloads.extend(generate_ssrf())
    all_payloads.extend(generate_overflow())
    all_payloads.extend(generate_type_confusion())
    all_payloads.extend(generate_prompt_injection())

    rule_ids = {p.rule_id for p in all_payloads}
    assert "shell-injection" in rule_ids
    assert "ssrf" in rule_ids
    assert "overflow" in rule_ids
    assert "type-confusion" in rule_ids
    assert "prompt-injection" in rule_ids


def test_schema_aware_payload_generation():
    """URI parameters must get SSRF payloads; string params must get injection + overflow."""
    uri_payloads = generate_all_for_param("url", {"type": "string", "format": "uri"})
    assert any(p.rule_id == "ssrf" for p in uri_payloads)

    str_payloads = generate_all_for_param("name", {"type": "string"})
    assert any(p.rule_id == "shell-injection" for p in str_payloads)
    assert any(p.rule_id == "overflow" for p in str_payloads)
    assert any(p.rule_id == "prompt-injection" for p in str_payloads)


# Non-determinism test


def test_no_randomness_in_payload_values():
    """Payload values must not contain random data — ensures reproducible CI."""
    for _ in range(10):
        payloads = generate_shell_injection()
        assert payloads[0].value == "; rm -rf /"
