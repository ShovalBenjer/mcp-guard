"""Canary smuggling — runtime detection of indirect prompt injection (OWASP ASI01).

The fuzzer's red-team battery (see ``payloads.generate_indirect_injection``)
proves a server *can* reflect attacker-controlled input into tool outputs.
This module answers the next question at agent runtime: did the agent *act on*
smuggled data?

Mechanism: before a tool output is handed to the agent, :meth:`CanaryTrap.smuggle`
embeds a fresh, unique canary token in the text. Every canary is registered
with the tool whose output carried it. The harness later scans the agent's
subsequent actions — tool-call arguments and outbound messages — for those
tokens. Detection is purely deterministic string matching; no model judges
anything.

Verdict rules:
- a canary from tool A's output appears in a call to tool B (B != A):
  ``goal_drift`` (high) — untrusted data crossed into another tool's
  invocation, the deterministic signature of data promoted to instruction
  context (ASI01 Agent Goal Hijack).
- a canary appears in the agent's outbound message, or looped back into its
  source tool's arguments: ``echo`` (medium) — reflection of untrusted data.
- no canary anywhere unexpected: ``clean``.

Honest limits (see also the PR's adversarial review): canaries catch
reflection/echo and cross-tool smuggling of *marked* data. They do NOT catch
an attacker who paraphrases instructions without the canary, unmarked
outputs, or goal drift that never touches tool data. An agent legitimately
quoting a tool output (e.g. "here is the file you asked for") produces an
``echo`` hit — treat ``echo`` as review-grade, ``goal_drift`` as
high-confidence.
"""
from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass, field

CANARY_PREFIX = "mcpguard-canary-"


def _default_token_factory() -> str:
    return CANARY_PREFIX + secrets.token_hex(6)


@dataclass(frozen=True)
class Canary:
    """One smuggled token and where it was planted."""

    token: str
    source: str  # tool whose output carried this canary
    seq: int  # issuance order; makes reports reproducible


@dataclass(frozen=True)
class AgentAction:
    """One downstream thing the agent did, as plain text to scan."""

    kind: str  # "tool_call" | "message"
    name: str  # tool name for tool_call; channel/recipient for message
    text: str  # serialized arguments, or the message body


@dataclass(frozen=True)
class CanaryHit:
    canary: Canary
    sink_kind: str
    sink_name: str
    excerpt: str  # surrounding context of the token in the sink


@dataclass(frozen=True)
class CanaryVerdict:
    status: str  # "clean" | "echo" | "goal_drift"
    severity: str  # "info" | "medium" | "high"
    hits: tuple[CanaryHit, ...]
    summary: str


class CanaryTrap:
    """Issues canaries, smuggles them into tool outputs, scans agent actions."""

    def __init__(self, token_factory: Callable[[], str] = _default_token_factory) -> None:
        self._token_factory = token_factory
        self._registry: dict[str, Canary] = {}
        self._seq = 0

    def __len__(self) -> int:
        return len(self._registry)

    def smuggle(self, text: str, source: str) -> tuple[str, Canary]:
        """Embed a fresh canary at the end of tool-output text.

        Returns the marked text and the registered Canary. The marker is
        appended (never prepended) so it cannot shadow the tool's own content.
        """
        self._seq += 1
        canary = Canary(token=self._token_factory(), source=source, seq=self._seq)
        self._registry[canary.token] = canary
        marked = text + f"\n[{canary.token}]"
        return marked, canary

    def smuggle_tool_result(
        self, result: dict, source: str
    ) -> tuple[dict, list[Canary]]:
        """Mark every text block of an MCP tool result with its own canary.

        Non-text blocks are left untouched. Returns the marked result (a
        shallow copy; the input dict is not mutated) and the canaries issued.
        """
        marked_blocks: list[Canary] = []
        content = result.get("content")
        new_content = content
        if isinstance(content, list):
            new_content = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    marked_text, canary = self.smuggle(str(block.get("text", "")), source)
                    marked_blocks.append(canary)
                    new_content.append({**block, "text": marked_text})
                else:
                    new_content.append(block)
        marked_result = {**result, "content": new_content}
        return marked_result, marked_blocks

    def scan(self, action: AgentAction) -> list[CanaryHit]:
        """Find registered canaries in one agent action. Deterministic."""
        hits: list[CanaryHit] = []
        for token, canary in self._registry.items():
            idx = action.text.find(token)
            if idx == -1:
                continue
            start = max(0, idx - 40)
            end = min(len(action.text), idx + len(token) + 40)
            hits.append(
                CanaryHit(
                    canary=canary,
                    sink_kind=action.kind,
                    sink_name=action.name,
                    excerpt=action.text[start:end],
                )
            )
        return hits

    def assess(self, action: AgentAction) -> CanaryVerdict:
        """Scan one action and reduce hits to a deterministic verdict."""
        hits = self.scan(action)
        if not hits:
            return CanaryVerdict(
                status="clean", severity="info", hits=(), summary="no canary in action"
            )
        drift = [
            h
            for h in hits
            if h.sink_kind == "tool_call" and h.sink_name != h.canary.source
        ]
        if drift:
            sources = sorted({h.canary.source for h in drift})
            sinks = sorted({h.sink_name for h in drift})
            return CanaryVerdict(
                status="goal_drift",
                severity="high",
                hits=tuple(hits),
                summary=(
                    "canary crossed from tool output(s) "
                    f"{', '.join(sources)} into tool call(s) {', '.join(sinks)} — "
                    "untrusted data reached another tool's arguments (OWASP ASI01)"
                ),
            )
        return CanaryVerdict(
            status="echo",
            severity="medium",
            hits=tuple(hits),
            summary="canary reflected in agent output without crossing tools",
        )


@dataclass
class DriftLedger:
    """Append-only record of non-clean verdicts, for audit trails."""

    entries: list[CanaryVerdict] = field(default_factory=list)

    def record(self, verdict: CanaryVerdict) -> None:
        if verdict.status != "clean":
            self.entries.append(verdict)

    def goal_drifts(self) -> list[CanaryVerdict]:
        return [e for e in self.entries if e.status == "goal_drift"]
