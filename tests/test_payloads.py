"""RED: Failing tests for adversarial payload generators."""
from mcp_guard.payloads import (
    generate_shell_injection,
    generate_ssrf,
    generate_overflow,
    generate_type_confusion,
    generate_prompt_injection,
)


def test_shell_injection_generates_command_payloads():
    payloads = generate_shell_injection()
    assert len(payloads) > 5, "Need multiple shell injection variants"
    sample = payloads[0]
    assert hasattr(sample, "value")
    assert hasattr(sample, "rule_id")
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
    assert any(isinstance(v, int) or isinstance(v, list) or v is None for v in values)


def test_prompt_injection_generates_override_payloads():
    payloads = generate_prompt_injection()
    assert len(payloads) > 3
    values = [p.value for p in payloads]
    assert any("ignore" in str(v).lower() for v in values)
