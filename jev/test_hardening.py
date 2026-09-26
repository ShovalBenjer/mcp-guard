"""Hardening tests for the jev router (ADR-0009).

- every routing decision is logged, append-only, with no raw task text
- uncertainty escalation threshold is configurable and honored
- local model outputs are schema-checked
- the router routes but never judges/gates: decisions carry routing facts only

No network model calls; only availability probes (monkeypatched here).
"""
import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from jev import router
from jev.decisions import DecisionsLog
from jev.router import SchemaViolation, check_output_schema, escalate

ROUTING_KEYS = {
    "ts", "task_sha256", "task_len", "route", "route_kind",
    "complexity", "threshold", "escalated", "reason",
}


@pytest.fixture()
def ledger(tmp_path, monkeypatch):
    path = str(tmp_path / "decisions.jsonl")
    monkeypatch.setenv("JEV_DECISIONS_PATH", path)
    return path


@pytest.fixture()
def local_up(monkeypatch):
    monkeypatch.setattr(router, "_ollama_alive", lambda url, timeout=1.5: True)


@pytest.fixture()
def nothing_up(monkeypatch):
    monkeypatch.setattr(router, "_ollama_alive", lambda url, timeout=1.5: False)
    monkeypatch.setenv("JEV_MODEL_TOKEN", "test-token")


def test_escalate_logs_every_decision(ledger, local_up):
    before = DecisionsLog().verify() if os.path.exists(ledger) else 0
    escalate("summarize this log")
    escalate("prove the distributed refactor is free of concurrency bugs")
    assert DecisionsLog().verify() == before + 2


def test_kept_local_decision_is_logged(ledger, local_up):
    _, decision = escalate("hi")
    assert decision["escalated"] is False
    assert "kept local" in decision["reason"]
    assert decision["route"] == "ollama-local"


def test_uncertain_task_escalates(ledger, nothing_up, monkeypatch):
    monkeypatch.setenv("JEV_ESCALATE_THRESHOLD", "0.10")
    chosen, decision = escalate("prove the distributed refactor is free of concurrency bugs",
                               budget="balanced")
    assert decision["escalated"] is True
    assert chosen.name == "github-models"
    assert "escalated" in decision["reason"]


def test_threshold_env_is_honored(ledger, nothing_up, monkeypatch):
    monkeypatch.setenv("JEV_ESCALATE_THRESHOLD", "0.99")
    _, decision = escalate("prove the distributed refactor is free of concurrency bugs",
                           budget="balanced")
    # complexity below the raised threshold... but no local route is up, so it
    # still escalates to the only available route — logged either way.
    assert set(decision) == ROUTING_KEYS
    assert decision["threshold"] == 0.99


def test_task_text_never_logged(ledger, local_up):
    task = "summarize my secret plan hunter2"
    escalate(task)
    with open(ledger, encoding="utf-8") as f:
        raw = f.read()
    assert "hunter2" not in raw
    assert "secret plan" not in raw
    entry = json.loads(raw.strip().splitlines()[-1])
    assert entry["task_sha256"] == hashlib.sha256(task.encode()).hexdigest()
    assert entry["task_len"] == len(task)


def test_router_never_judges_or_gates(ledger, local_up):
    chosen, decision = escalate("summarize this log")
    assert isinstance(chosen, router.Route)  # a route, not a verdict
    assert set(decision) == ROUTING_KEYS  # routing facts only
    for forbidden in ("approved", "verdict", "allowed", "denied", "blocked"):
        assert forbidden not in decision


def test_check_output_schema_accepts_valid():
    check_output_schema(
        {"summary": "ok", "score": 3},
        {"required": ["summary"], "properties": {"score": {"type": "integer"}}},
    )


def test_check_output_schema_rejects_missing_required():
    with pytest.raises(SchemaViolation, match="missing required field"):
        check_output_schema({}, {"required": ["summary"]})


def test_check_output_schema_rejects_wrong_type():
    with pytest.raises(SchemaViolation, match="expected integer"):
        check_output_schema({"score": "three"}, {"properties": {"score": {"type": "integer"}}})


def test_check_output_schema_rejects_non_object():
    with pytest.raises(SchemaViolation, match="expected object"):
        check_output_schema(["not", "a", "dict"], {})
