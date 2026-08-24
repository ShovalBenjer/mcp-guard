"""Tests for the report formatters (table, JSON, SARIF)."""
from __future__ import annotations

import json
import tempfile
from dataclasses import replace
from io import StringIO

from mcp_guard.fuzzer import FuzzResult, ResultCategory
from mcp_guard.report import FuzzReport


def _result(category, rule_id="shell-injection", severity="critical", tool="echo", detail=""):
    return FuzzResult(
        tool_name=tool,
        probe_name="msg",
        payload_value="; rm -rf /",
        category=category,
        rule_id=rule_id,
        severity=severity,
        detail=detail or f"{category.value} detail",
        response_preview="",
    )


def _report(results):
    return FuzzReport(
        server_command="fake -- server",
        tools_fuzzed=1,
        total_payloads=len(results),
        results=results,
    )


def test_empty_results_table_renders_clean_verdict():
    """An empty report must render the CLEAN verdict and no finding sections."""
    out = StringIO()
    _report([]).to_table(out=out)
    text = out.getvalue()
    assert "CLEAN" in text
    assert "CRASHES" not in text
    assert "FINDINGS" not in text


def test_empty_results_json_has_no_results():
    out = StringIO()
    _report([]).to_json(out=out)
    data = json.loads(out.getvalue())
    assert data["summary"]["crashes"] == 0
    assert data["summary"]["findings"] == 0
    assert data["results"] == []


def test_empty_results_sarif_has_no_results():
    out = StringIO()
    _report([]).to_sarif(out=out)
    sarif = json.loads(out.getvalue())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []


def test_severity_distribution_counts():
    results = [
        _result(ResultCategory.CRASH, severity="critical"),
        _result(ResultCategory.CRASH, severity="high"),
        _result(ResultCategory.FINDING, severity="high"),
        _result(ResultCategory.FINDING, severity="high"),
        _result(ResultCategory.SAFE, severity="low"),
        _result(ResultCategory.SAFE, severity="low"),
    ]
    report = _report(results)
    assert len(report.crashes) == 2
    assert len(report.findings) == 2
    assert len(report.safe) == 2

    out = StringIO()
    report.to_table(out=out)
    text = out.getvalue()
    assert "Crashes:       2" in text
    assert "Findings:      2" in text
    assert "Safe:          2" in text
    assert "VULNERABLE" in text


def test_json_file_output_is_valid_and_persisted():
    with tempfile.NamedTemporaryFile("r+", suffix=".json", delete=False) as f:
        path = f.name
    try:
        with open(path, "w", encoding="utf-8") as fh:
            _report([_result(ResultCategory.FINDING)]).to_json(out=fh)
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        assert data["server"] == "fake -- server"
        assert data["results"][0]["rule_id"] == "shell-injection"
    finally:
        import os

        os.unlink(path)


def test_sarif_file_output_is_valid_and_persisted():
    with tempfile.NamedTemporaryFile("r+", suffix=".sarif", delete=False) as f:
        path = f.name
    try:
        with open(path, "w", encoding="utf-8") as fh:
            report = _report([
                _result(ResultCategory.CRASH),
                _result(ResultCategory.FINDING),
            ])
            report.to_sarif(out=fh)
        with open(path, encoding="utf-8") as fh:
            sarif = json.load(fh)

        runs = sarif["runs"][0]
        assert len(runs["results"]) == 2
        levels = {r["level"] for r in runs["results"]}
        assert levels == {"error", "warning"}
        assert runs["tool"]["driver"]["name"] == "mcp-guard"
        assert len(runs["tool"]["driver"]["rules"]) >= 1

        crash_result = next(r for r in runs["results"] if r["level"] == "error")
        assert crash_result["ruleId"] == "shell-injection"
    finally:
        import os

        os.unlink(path)


def test_json_excludes_safe_results():
    """SAFE results must be omitted from the JSON/SARIF output."""
    results = [
        _result(ResultCategory.SAFE, severity="low"),
        _result(ResultCategory.FINDING, severity="high"),
    ]
    out = StringIO()
    _report(results).to_json(out=out)
    data = json.loads(out.getvalue())
    assert len(data["results"]) == 1

    out2 = StringIO()
    _report(results).to_sarif(out=out2)
    sarif = json.loads(out2.getvalue())
    assert len(sarif["runs"][0]["results"]) == 1


def test_info_leak_finding_carries_high_severity():
    """An info-leak finding must be reported as high severity with a -info-leak rule."""
    leak = replace(
        _result(ResultCategory.FINDING, rule_id="shell-injection-info-leak"),
        severity="high",
        detail="Payload accepted, response leaks internal info: api_key=secret",
    )
    out = StringIO()
    _report([leak]).to_json(out=out)
    data = json.loads(out.getvalue())
    assert data["results"][0]["severity"] == "high"
    assert data["results"][0]["rule_id"].endswith("-info-leak")
