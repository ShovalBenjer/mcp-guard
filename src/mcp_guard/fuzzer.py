"""Fuzz engine — orchestrates adversarial payload delivery to MCP tools."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from .payloads import INDIRECT_CANARY, Payload, Severity, generate_all_for_param

# Markdown image pointing at an external URL inside a tool *output*: the
# exfiltration channel of the EchoLeak (CVE-2025-32711) pattern.
_EXFIL_MD_RE = re.compile(r"!\[[^\]]*\]\(\s*https?://", re.IGNORECASE)


def _payload_reflected(payload_value: object, text: str) -> bool:
    """Did attacker-controlled bytes reach the tool output?

    Checks the payload verbatim and quote-stripped (servers often echo
    inside their own quoting). The stripped form needs >= 6 chars to avoid
    matching common substrings.
    """
    s = str(payload_value)
    if not s:
        return False
    if s in text:
        return True
    stripped = s.strip("'\"")
    return len(stripped) >= 6 and stripped in text


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
            generate_overflow,
            generate_prompt_injection,
            generate_shell_injection,
            generate_ssrf,
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
        except Exception as exc:  # noqa: BLE001
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

        text_lower = text.lower()

        # Indirect prompt injection (OWASP ASI01): the server reflected our
        # canary-bearing probe into its tool *output*. A downstream agent
        # reading that output receives attacker-shaped "instructions" on the
        # data channel — the seed of goal hijack. Checked only for
        # indirect-injection probes so normal input echo is not flagged.
        if payload.rule_id == "indirect-injection" and INDIRECT_CANARY in text:
            return FuzzResult(
                tool_name=tool_name,
                probe_name=param_name,
                payload_value=payload.value,
                category=ResultCategory.FINDING,
                rule_id="reflection-untrusted-echo",
                severity="high",
                detail=(
                    "Server reflected attacker-controlled input into tool output — "
                    "seed for indirect prompt injection (OWASP ASI01)"
                ),
                response_preview=text[:200],
            )

        # Exfil-shaped channel in tool output (EchoLeak pattern): a markdown
        # image to an external URL gives injected content a way to phone home.
        if payload.rule_id == "indirect-injection" and _EXFIL_MD_RE.search(text):
            return FuzzResult(
                tool_name=tool_name,
                probe_name=param_name,
                payload_value=payload.value,
                category=ResultCategory.FINDING,
                rule_id="indirect-injection-exfil-channel",
                severity="critical",
                detail="Tool output contains markdown image to external URL — exfil channel",
                response_preview=text[:200],
            )

        leaked = any(
            kw in text_lower
            for kw in ("traceback", "exception", "stack trace", "error:", "internal", "password", "secret", "token")
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

        # Evidence-graded default (mcp-guard#107): severity follows what we
        # OBSERVED, not the payload's potential. Cross-repo evidence
        # (mcp-guard vs agentgate demo server, 2026-10-02): a pure dict lookup
        # that echoes input in a "not found" message drew 20 CRITICAL
        # shell-injection findings — there is no shell. A fuzzer that cries
        # critical on zero evidence drowns real findings in noise.
        if _payload_reflected(payload.value, text):
            if payload.rule_id in ("prompt-injection", "indirect-injection"):
                # The reflection IS the attack: a downstream agent reads
                # these instructions on the data channel.
                severity = payload.severity.value
            else:
                # Execution-class payload (shell/sqli/...): reflection is
                # not execution. Unconfirmed — medium, never critical.
                severity = Severity.MEDIUM.value
            return FuzzResult(
                tool_name=tool_name,
                probe_name=param_name,
                payload_value=payload.value,
                category=ResultCategory.FINDING,
                rule_id=f"{payload.rule_id}-unconfirmed-reflection",
                severity=severity,
                detail=(
                    "Payload reflected in tool output without execution "
                    "evidence. For prompt-injection payloads the reflection "
                    "itself reaches a downstream agent; for execution-class "
                    "payloads this is unconfirmed."
                ),
                response_preview=text[:200],
            )
        # Deliberately FINDING (not SAFE) at INFO: for a pre-deployment
        # security fuzzer the safe direction of error is non-negotiable. A
        # silently-executed payload is observationally identical to a
        # neutralized one; resolving that ambiguity as SAFE would let the
        # CLI's CLEAN verdict assert safety it cannot verify. INFO keeps it
        # visible and filterable without crying wolf.
        return FuzzResult(
            tool_name=tool_name,
            probe_name=param_name,
            payload_value=payload.value,
            category=ResultCategory.FINDING,
            rule_id=f"{payload.rule_id}-no-observable-effect",
            severity=Severity.INFO.value,
            detail=(
                "Payload produced no observable effect: not reflected, no "
                "error, no leak. Silent execution cannot be ruled out by "
                "black-box probing alone — informational, not a clean bill."
            ),
            response_preview=text[:200],
        )
