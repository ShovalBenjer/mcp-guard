"""Stdio MCP transport — spawns server subprocess and communicates via JSON-RPC."""
from __future__ import annotations

import json
import select
import subprocess
from typing import Any


class StdioTransport:
    """Transport layer for MCP servers communicating over stdio."""

    def __init__(self, command: list[str], timeout: float = 30.0):
        """Initialize the transport with a server command and read timeout.

        Args:
            command: The command and arguments to start the MCP server.
            timeout: Timeout in seconds for reading responses from the server.
        """
        self._command = command
        self._timeout = timeout
        self._proc: subprocess.Popen | None = None
        self._request_id = 0

    def start(self) -> None:
        """Start the MCP server subprocess and perform initialization handshake."""
        self._proc = subprocess.Popen(
            self._command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._initialize()

    def stop(self) -> None:
        """Stop the MCP server subprocess gracefully, with forced kill fallback."""
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def __enter__(self):
        """Enter context manager, starting the transport."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager, stopping the transport and not suppressing exceptions."""
        self.stop()
        return False

    @property
    def is_alive(self) -> bool:
        """Check if the server subprocess is still running."""
        return self._proc is not None and self._proc.poll() is None

    def _send(self, method: str, params: dict | None = None) -> dict:
        """Send a JSON-RPC request and return the response result.

        Args:
            method: The JSON-RPC method name.
            params: Optional parameters for the method.

        Returns:
            The result field from the JSON-RPC response.

        Raises:
            ConnectionError: If the server is not running.
            TimeoutError: If the response exceeds the read timeout.
        """
        if not self._proc or not self.is_alive:
            raise ConnectionError("Server not running")
        proc = self._proc
        assert proc is not None
        assert proc.stdin is not None
        assert proc.stdout is not None

        self._request_id += 1
        request: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
        }
        if params is not None:
            request["params"] = params

        line = json.dumps(request) + "\n"
        proc.stdin.write(line)
        proc.stdin.flush()

        return self._read_response()

    def _notify(self, method: str, params: dict | None = None) -> None:
        """Send a JSON-RPC notification (no response expected).

        Args:
            method: The JSON-RPC method name.
            params: Optional parameters for the method.

        Raises:
            ConnectionError: If the server is not running.
        """
        if not self._proc or not self.is_alive:
            raise ConnectionError("Server not running")
        proc = self._proc
        assert proc is not None
        assert proc.stdin is not None

        notification: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params is not None:
            notification["params"] = params

        line = json.dumps(notification) + "\n"
        proc.stdin.write(line)
        proc.stdin.flush()

    def _read_response(self) -> dict:
        """Read and parse a JSON-RPC response from the server.

        Uses select.select() to enforce the configured timeout. If the timeout
        expires, kills the server process and raises TimeoutError.

        Returns:
            The result field from the JSON-RPC response.

        Raises:
            ConnectionError: If the server closes the connection.
            TimeoutError: If no response arrives within the configured timeout.
        """
        proc = self._proc
        assert proc is not None
        assert proc.stdout is not None
        while True:
            ready, _, _ = select.select([proc.stdout], [], [], self._timeout)
            if not ready:
                if self._proc and self._proc.poll() is None:
                    self._proc.kill()
                raise TimeoutError(
                    f"No response from server within {self._timeout}s timeout"
                )
            response_line = proc.stdout.readline()
            if not response_line:
                raise ConnectionError("Server closed connection")
            try:
                response = json.loads(response_line)
            except json.JSONDecodeError:
                continue
            if "method" in response and "id" not in response:
                continue
            if "error" in response:
                raise RuntimeError(f"MCP error: {response['error']}")
            return response.get("result", {})

    def _initialize(self) -> dict:
        """Perform the MCP initialization handshake with the server.

        Returns:
            The initialize result from the server.
        """
        result = self._send("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp-guard", "version": "0.1.0"},
        })
        self._notify("notifications/initialized")
        return result

    def list_tools(self) -> list[dict]:
        """List all tools available on the MCP server.

        Returns:
            A list of tool definition dictionaries.
        """
        result = self._send("tools/list")
        return result.get("tools", [])

    def list_resources(self) -> list[dict]:
        """List all resources available on the MCP server.

        Returns:
            A list of resource definition dictionaries.
        """
        result = self._send("resources/list")
        return result.get("resources", [])

    def list_prompts(self) -> list[dict]:
        """List all prompts available on the MCP server.

        Returns:
            A list of prompt definition dictionaries.
        """
        result = self._send("prompts/list")
        return result.get("prompts", [])

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """Call a tool on the MCP server with the given arguments.

        Args:
            tool_name: The name of the tool to call.
            arguments: The arguments to pass to the tool.

        Returns:
            The result of the tool call.
        """
        return self._send("tools/call", {
            "name": tool_name,
            "arguments": arguments,
        })
