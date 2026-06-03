"""Stdio MCP transport — spawns server subprocess and communicates via JSON-RPC."""
from __future__ import annotations

import json
import subprocess
from typing import Any


class StdioTransport:
    def __init__(self, command: list[str], timeout: float = 10.0):
        self._command = command
        self._timeout = timeout
        self._proc: subprocess.Popen | None = None
        self._request_id = 0

    def start(self) -> None:
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
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()

    @property
    def is_alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def _send(self, method: str, params: dict | None = None) -> dict:
        if not self._proc or not self.is_alive:
            raise ConnectionError("Server not running")

        self._request_id += 1
        request: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
        }
        if params is not None:
            request["params"] = params

        line = json.dumps(request) + "\n"
        self._proc.stdin.write(line)
        self._proc.stdin.flush()

        response_line = self._proc.stdout.readline()
        if not response_line:
            raise ConnectionError("Server closed connection")

        response = json.loads(response_line)
        if "error" in response:
            raise RuntimeError(f"MCP error: {response['error']}")
        return response.get("result", {})

    def _initialize(self) -> dict:
        result = self._send("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp-guard", "version": "0.2.0"},
        })
        self._send("notifications/initialized")
        return result

    def list_tools(self) -> list[dict]:
        result = self._send("tools/list")
        return result.get("tools", [])

    def list_resources(self) -> list[dict]:
        result = self._send("resources/list")
        return result.get("resources", [])

    def list_prompts(self) -> list[dict]:
        result = self._send("prompts/list")
        return result.get("prompts", [])

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        return self._send("tools/call", {
            "name": tool_name,
            "arguments": arguments,
        })
