"""Tests for the adversarial payload generators."""
from __future__ import annotations

import pytest

from mcp_guard.payloads import (
    Payload,
    generate_all_for_param,
    generate_overflow,
    generate_prompt_injection,
    generate_shell_injection,
    generate_ssrf,
    generate_type_confusion,
)


def test_shell_injection_generates_command_payloads():
    payloads = generate_shell_injection()
    assert len(payloads) > 5, "Need multiple shell injection variants"
    sample = payloads[0]
    assert hasattr(sample, "value")
    assert hasattr(sample, "severity")
    assert "shell" in sample.rule_id or "injection" in sample.rule_id


def test_ssrf_generates_internal_network_payloads():
    payloads = generate_ssrf()
    assert len(payloads) > 3
    values = [p.value for p in payloads]
    assert any("169.254" in v or "localhost" in v or "file://" in v for v in values)


def test_overflow_generates_large_strings():
    payloads = generate_overflow()
    assert len(payloads) > 2
    assert any(len(p.value) > 10_000 for p in payloads), "Need payloads >10KB"


def test_type_confusion_generates_wrong_types():
    payloads = generate_type_confusion(param_type="string")
    assert len(payloads) > 2
    values = [p.value for p in payloads]
    assert any(isinstance(v, (int, list)) or v is None for v in values)


def test_prompt_injection_generates_override_payloads():
    payloads = generate_prompt_injection()
    assert len(payloads) > 3
    values = [p.value for p in payloads]
    assert any("ignore" in str(v).lower() for v in values)


def test_generate_all_for_param_dispatches_string():
    """A string param pulls in shell, prompt, overflow and type-confusion probes."""
    payloads = generate_all_for_param("cmd", {"type": "string"})
    rule_ids = {p.rule_id for p in payloads}
    assert "shell-injection" in rule_ids
    assert "prompt-injection" in rule_ids
    assert "overflow" in rule_ids
    assert "type-confusion" in rule_ids


def test_generate_all_for_param_dispatches_integer_and_number():
    """Integer and number params get type-confusion plus a max-int64 overflow probe."""
    for ptype in ("integer", "number"):
        payloads = generate_all_for_param("count", {"type": ptype})
        rule_ids = {p.rule_id for p in payloads}
        assert "type-confusion" in rule_ids
        assert "overflow" in rule_ids
        assert any(p.value == 2**63 for p in payloads)


def test_generate_all_for_param_dispatches_uri():
    """A URI param must include SSRF payloads (per README: 8 SSRF probes)."""
    payloads = generate_all_for_param("url", {"type": "string", "format": "uri"})
    ssrf = [p for p in payloads if p.rule_id == "ssrf"]
    assert len(ssrf) == 8


def test_generate_all_for_param_unknown_type():
    """An unknown param type falls back to base type-confusion payloads only."""
    payloads = generate_all_for_param("weird", {"type": "weird"})
    assert len(payloads) == 6
    assert all(p.rule_id == "type-confusion" for p in payloads)


def test_payloads_are_immutable():
    """Payload is a frozen dataclass; attributes must not be reassignable."""
    p = Payload("x", "r", __import__("mcp_guard.types", fromlist=["Severity"]).Severity.HIGH, "d")
    with pytest.raises(AttributeError):
        p.value = "mutated"


def test_payload_counts_match_readme():
    """Documented payload counts must hold."""
    assert len(generate_shell_injection()) == 8
    assert len(generate_ssrf()) == 8
    assert len(generate_overflow()) == 5
    assert len(generate_prompt_injection()) == 6
    assert len(generate_type_confusion("string")) == 8
    assert len(generate_type_confusion("integer")) == 8
    assert len(generate_all_for_param("x", {"type": "string"})) == 25
    assert len(generate_all_for_param("x", {"type": "integer"})) == 9


def test_generated_payloads_are_independent():
    """Repeated calls return independent Payload objects, not shared state."""
    a = generate_shell_injection()
    b = generate_shell_injection()
    assert a is not b
    assert [p.value for p in a] == [p.value for p in b]
