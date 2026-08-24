"""Fuzz engine — orchestrates adversarial payload delivery to MCP tools."""
from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from .payloads import (
    Payload,
    generate_all_for_param,
    generate_overflow,
    generate_prompt_injection,
    generate_shell_injection,
    generate_ssrf,
)


class ResultCategory(Enum):
    SAFE = "safe"
    FINDING = "finding"
    CRASH = "crash"
    ERROR = "error"


@dataclass
class FuzzResult:
    tool_name: str
    probe_name: str
    payload_value: object
    category: ResultCategory
    rule_id: str
    severity: str
    detail: str = ""
    response_preview: str = ""


class Transport(Protocol):
    def call_tool(self, tool_name: str, arguments: dict) -> dict: ...


class FuzzEngine:
    def __init__(self, transport: Transport, delay_ms: int = 0):
        """Initialize the fuzz engine with a transport and optional delay.

        Args:
            transport: The transport to use for calling tools.
            delay_ms: Delay in milliseconds between payload deliveries.
        """
        self._transport = transport
        self._delay_ms = delay_ms

    def fuzz_tool(self, tool: dict) -> list[FuzzResult]:
        """Fuzz a single tool using its schema to generate targeted payloads.

        Args:
            tool: The tool definition dictionary from the MCP server.

        Returns:
            A list of FuzzResult entries for each payload tested.
        """
        tool_name = tool.get("name", "unknown")
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))

        if not properties:
            return self._fuzz_no_schema(tool_name)

        results: list[FuzzResult] = []
        for param_name, param_schema in properties.items():
            payloads = generate_all_for_param(param_name, param_schema)
            for payload in payloads:
                result = self._fire_payload(tool_name, param_name, payload, required)
                results.append(result)

        return results

    def _fuzz_no_schema(self, tool_name: str) -> list[FuzzResult]:
        """Fuzz a tool that has no input schema using generic payloads.

        Args:
            tool_name: The name of the tool being fuzzed.

        Returns:
            A list of FuzzResult entries for generic payloads.
        """
        all_payloads = (
            generate_shell_injection()
            + generate_ssrf()
            + generate_overflow()[:2]
            + generate_prompt_injection()
        )
        results: list[FuzzResult] = []
        for payload in all_payloads:
            result = self._fire_payload(tool_name, payload.rule_id, payload, set())
            results.append(result)
        return results

    def _fire_payload(
        self, tool_name: str, param_name: str, payload: Payload, required: set[str]
    ) -> FuzzResult:
        """Send a single payload to a tool and classify the response.

        Args:
            tool_name: The name of the tool being targeted.
            param_name: The parameter name the payload targets.
            payload: The payload to send.
            required: Set of required parameter names for the tool.

        Returns:
            A FuzzResult describing the outcome.
        """
        args: dict[str, Any] = {param_name: payload.value}
        try:
            response = self._transport.call_tool(tool_name, args)
        except ConnectionError:
            return FuzzResult(
                tool_name=tool_name,
                probe_name=param_name,
                payload_value=payload.value,
                category=ResultCategory.CRASH,
                rule_id=payload.rule_id,
                severity=payload.severity.value,
                detail="Server crashed or connection lost after payload",
            )
        except (OSError, json.JSONDecodeError, RuntimeError) as exc:
            return FuzzResult(
                tool_name=tool_name,
                probe_name=param_name,
                payload_value=payload.value,
                category=ResultCategory.ERROR,
                rule_id=payload.rule_id,
                severity=payload.severity.value,
                detail=f"Unexpected exception: {exc}",
            )

        return self._classify_response(tool_name, param_name, payload, response)

    def _classify_response(
        self, tool_name: str, param_name: str, payload: Payload, response: dict
    ) -> FuzzResult:
        """Classify the server's response to a payload as safe, finding, or crash.

        Args:
            tool_name: The name of the tool being targeted.
            param_name: The parameter name the payload targets.
            payload: The payload that was sent.
            response: The JSON-RPC response from the server.

        Returns:
            A FuzzResult describing the outcome.
        """
        is_error = response.get("isError", False)
        content = response.get("content", [])
        text = ""
        if content and isinstance(content, list):
            text = " ".join(
                c.get("text", "") for c in content if isinstance(c, dict)
            )

        if is_error:
            return FuzzResult(
                tool_name=tool_name,
                probe_name=param_name,
                payload_value=payload.value,
                category=ResultCategory.SAFE,
                rule_id=payload.rule_id,
                severity=payload.severity.value,
                detail="Server rejected payload (expected error)",
                response_preview=text[:200],
            )

        text_lower = text.lower()
        leaked = any(
            kw in text_lower
            for kw in (
                "traceback",
                "exception",
                "stack trace",
                "error:",
                "internal",
                "password",
                "secret",
                "api_key",
                "api-key",
                "secret_key",
                "private_key",
                "database_url",
                "connection_string",
            )
        )
        if leaked:
            return FuzzResult(
                tool_name=tool_name,
                probe_name=param_name,
                payload_value=payload.value,
                category=ResultCategory.FINDING,
                rule_id=f"{payload.rule_id}-info-leak",
                severity="high",
                detail=f"Payload accepted, response leaks internal info: {text[:100]}",
                response_preview=text[:200],
            )

        return FuzzResult(
            tool_name=tool_name,
            probe_name=param_name,
            payload_value=payload.value,
            category=ResultCategory.FINDING,
            rule_id=payload.rule_id,
            severity=payload.severity.value,
            detail="Payload accepted without error — potential vulnerability",
            response_preview=text[:200],
        )
