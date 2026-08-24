"""Fake MCP servers for transport tests.

Run as a subprocess: ``python fakeserver.py <mode>`` where ``mode`` is one of
``normal`` (speaks JSON-RPC), ``silent`` (reads but never replies -> timeout),
``garbage`` (writes non-JSON then exits -> non-MCP server), or ``error``
(always replies with a JSON-RPC error).
"""
from __future__ import annotations

import json
import sys

TOOLS = [
    {
        "name": "echo",
        "description": "Echo a message back to the caller",
        "inputSchema": {
            "type": "object",
            "properties": {"msg": {"type": "string"}},
            "required": ["msg"],
        },
    }
]


def _respond(req: dict) -> dict | None:
    if "id" not in req:
        return None
    method = req.get("method", "")
    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": {"name": "fake", "version": "0.1"},
        }
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "resources/list":
        result = {"resources": []}
    elif method == "prompts/list":
        result = {"prompts": []}
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "ok"}]}
    else:
        result = {}
    return {"jsonrpc": "2.0", "id": req["id"], "result": result}


def _respond_error(req: dict) -> dict | None:
    if "id" not in req:
        return None
    return {
        "jsonrpc": "2.0",
        "id": req["id"],
        "error": {"code": -32000, "message": "internal error"},
    }


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "normal"

    if mode == "silent":
        for _ in sys.stdin:
            pass
        return 0

    if mode == "garbage":
        sys.stdout.write("this is not json-rpc\n")
        sys.stdout.flush()
        return 0

    handler = _respond_error if mode == "error" else _respond
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        resp = handler(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
