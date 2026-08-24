"""Tests for the stdio MCP transport layer."""
from __future__ import annotations

import os
import sys

import pytest

from mcp_guard.transport import StdioTransport

SERVER = os.path.join(os.path.dirname(__file__), "fakeserver.py")


def _cmd(mode: str) -> list[str]:
    return [sys.executable, SERVER, mode]


def test_transport_context_manager_starts_and_stops():
    """Entering the context manager starts the server; exiting stops it."""
    transport = StdioTransport(_cmd("normal"), timeout=5.0)
    assert not transport.is_alive

    with transport as t:
        assert t is transport
        assert transport.is_alive
        tools = transport.list_tools()
        assert any(tool.get("name") == "echo" for tool in tools)

    assert not transport.is_alive


def test_transport_context_manager_does_not_suppress_exceptions():
    """__exit__ must return False so exceptions propagate out of the block."""
    transport = StdioTransport(_cmd("normal"), timeout=5.0)
    with transport:
        pass
    assert transport.__exit__(ValueError, ValueError("boom"), None) is False


def test_transport_start_and_stop_explicit():
    """start()/stop() can be used without a with block."""
    transport = StdioTransport(_cmd("normal"), timeout=5.0)
    transport.start()
    try:
        assert transport.is_alive
        tools = transport.list_tools()
        assert len(tools) == 1
    finally:
        transport.stop()
    assert not transport.is_alive


def test_transport_timeout_raises():
    """A server that never replies must raise TimeoutError within the timeout."""
    transport = StdioTransport(_cmd("silent"), timeout=0.5)
    with pytest.raises(TimeoutError):
        transport.start()
    transport.stop()
    assert not transport.is_alive


def test_transport_non_mcp_server_raises():
    """A process that does not speak JSON-RPC must raise ConnectionError."""
    transport = StdioTransport(_cmd("garbage"), timeout=5.0)
    with pytest.raises(ConnectionError):
        transport.start()
    transport.stop()
    assert not transport.is_alive


def test_transport_json_rpc_error_response_raises():
    """A JSON-RPC error response from the server must surface as RuntimeError."""
    transport = StdioTransport(_cmd("error"), timeout=5.0)
    with pytest.raises(RuntimeError):
        transport.start()
    transport.stop()
    assert not transport.is_alive


def test_transport_send_before_start_raises():
    """Sending on an unstarted transport must raise ConnectionError."""
    transport = StdioTransport(_cmd("normal"), timeout=5.0)
    with pytest.raises(ConnectionError):
        transport.call_tool("echo", {"msg": "hi"})


def test_transport_call_tool_returns_result():
    """call_tool should return the inner result of a tools/call response."""
    with StdioTransport(_cmd("normal"), timeout=5.0) as transport:
        result = transport.call_tool("echo", {"msg": "hi"})
        assert result.get("content") == [{"type": "text", "text": "ok"}]


def test_transport_resources_and_prompts_list():
    """list_resources/list_prompts should return empty lists from the fake."""
    with StdioTransport(_cmd("normal"), timeout=5.0) as transport:
        assert transport.list_resources() == []
        assert transport.list_prompts() == []
