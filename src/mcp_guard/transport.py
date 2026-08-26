"""Stdio MCP transport — spawns server subprocess and communicates via JSON-RPC."""
from __future__ import annotations

import json
import queue
import subprocess
import threading
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
        proc = self._proc
        assert proc is not None
        assert proc.stdout is not None

        q: queue.Queue[str | None] = queue.Queue()

        def _read_line() -> None:
            try:
                q.put(proc.stdout.readline())
            except Exception:
                q.put(None)

        thread = threading.Thread(target=_read_line, daemon=True)
        thread.start()
        thread.join(timeout=self._timeout)

        if thread.is_alive():
            if self._proc and self._proc.poll() is None:
                self._proc.kill()
            raise TimeoutError(
                f"No response from server within {self._timeout}s timeout"
            )

        response_line = q.get()
        if not response_line:
            raise ConnectionError("Server closed connection")
        try:
            response = json.loads(response_line)
        except json.JSONDecodeError:
            raise ConnectionError("Invalid JSON response from server")
        if "method" in response and "id" not in response:
            raise ConnectionError("Invalid JSON response from server")
        if "error" in response:
            raise RuntimeError(f"MCP error: {response['error']}")
        return response.get("result", {})

    def _initialize(self) -> dict:
        result = self._send("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp-guard", "version": "0.2.1"},
        })
        self._notify("notifications/initialized")
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
