"""Fuzz engine — orchestrates adversarial payload delivery to MCP tools."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from .payloads import Payload, generate_all_for_param


class ResultCategory(Enum):
    SAFE = "safe"          # server rejected the payload (isError) — expected, good
    ACCEPTED = "accepted"  # accepted without error, no evidence of harm — informational
    FINDING = "finding"    # accepted AND concrete evidence of a problem (leak/reflection)
    CRASH = "crash"        # server died / connection lost after the payload
    ERROR = "error"        # client-side error talking to the server


# Patterns that are real evidence a payload did something it should not have.
# Deliberately conservative: a normal non-error response is NOT a vulnerability.
_LEAK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("stack-trace", re.compile(r"traceback \(most recent call last\)", re.I)),
    ("stack-trace", re.compile(r"\n\s+at\s+[\w.$]+\s*\(.*:\d+:\d+\)")),  # JS stack frame
    ("etc-passwd", re.compile(r"root:.*:0:0:")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws-metadata", re.compile(r"ami-id|instance-id|iam/security-credentials")),
    ("aws-secret", re.compile(r"AKIA[0-9A-Z]{16}")),
)


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
        self._transport = transport
        self._delay_ms = delay_ms

    def fuzz_tool(self, tool: dict) -> list[FuzzResult]:
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
        from .payloads import (
            generate_shell_injection,
            generate_ssrf,
            generate_overflow,
            generate_prompt_injection,
        )
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
        if self._delay_ms:
            time.sleep(self._delay_ms / 1000.0)
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
        except Exception as exc:
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

        # The response did NOT error. That alone is not a vulnerability — many
        # tools legitimately accept arbitrary strings (a note body, a search
        # query) or ignore parameters they don't use. Only escalate to FINDING
        # when there is concrete evidence the payload did something it should not.
        leak = self._detect_leak(text)
        if leak is not None:
            return FuzzResult(
                tool_name=tool_name,
                probe_name=param_name,
                payload_value=payload.value,
                category=ResultCategory.FINDING,
                rule_id=f"{payload.rule_id}-{leak}",
                severity="high",
                detail=f"Payload accepted and response leaks sensitive data ({leak})",
                response_preview=text[:200],
            )

        return FuzzResult(
            tool_name=tool_name,
            probe_name=param_name,
            payload_value=payload.value,
            category=ResultCategory.ACCEPTED,
            rule_id=payload.rule_id,
            severity="info",
            detail="Payload accepted without error — input not rejected (no evidence of harm)",
            response_preview=text[:200],
        )

    @staticmethod
    def _detect_leak(text: str) -> str | None:
        """Return a leak label if the response contains real evidence of a leak."""
        for label, pattern in _LEAK_PATTERNS:
            if pattern.search(text):
                return label
        return None
