"""Tests for report provenance (Finding A) and deterministic numeric validation (Finding B)."""
import io
import json

import pytest

from mcp_guard.fuzzer import FuzzResult, ResultCategory
from mcp_guard.report import FuzzReport, scanner_version


def _result(tool="t", category=ResultCategory.FINDING, severity="high"):
    return FuzzResult(
        tool_name=tool, probe_name="p", payload_value="x",
        category=category, rule_id="r", severity=severity,
    )


def _report():
    results = [
        _result(tool="a", category=ResultCategory.FINDING, severity="high"),
        _result(tool="a", category=ResultCategory.SAFE, severity="info"),
        _result(tool="b", category=ResultCategory.CRASH, severity="critical"),
    ]
    return FuzzReport(
        server_command="npx some-server", tools_fuzzed=2,
        total_payloads=3, results=results,
    )


def test_provenance_block_present_and_never_empty():
    buf = io.StringIO()
    _report().to_json(buf)
    prov = json.loads(buf.getvalue())["_provenance"]
    for key in ("scanner", "scanner_version", "run_id", "run_at",
                "data_source", "payload_ruleset_version", "report_schema"):
        assert prov.get(key), f"provenance missing/empty: {key}"
    assert prov["scanner"] == "mcp-guard"
    assert prov["data_source"] == "npx some-server"


def test_provenance_run_ids_unique():
    assert _report().run_id != _report().run_id


def test_summary_numbers_recomputed_in_code():
    buf = io.StringIO()
    _report().to_json(buf)
    summary = json.loads(buf.getvalue())["summary"]
    assert summary["crashes"] == 1
    assert summary["findings"] == 1
    assert summary["safe"] == 1
    assert summary["total_payloads"] == 3
    assert summary["by_severity"] == {"high": 1, "critical": 1}


def test_verify_counts_rejects_drifted_total():
    rep = _report()
    rep.total_payloads = 99
    with pytest.raises(ValueError, match="total_payloads"):
        rep.verify_counts()


def test_verify_counts_rejects_mutated_results():
    rep = _report()
    rep.results.append(_result(tool="c", category=ResultCategory.FINDING))
    with pytest.raises(ValueError):
        rep.to_json(io.StringIO())


def test_verify_counts_rejects_wrong_tool_count():
    rep = _report()
    rep.tools_fuzzed = 7
    with pytest.raises(ValueError, match="tools_fuzzed"):
        rep.verify_counts()


def test_sarif_carries_real_version_and_provenance():
    buf = io.StringIO()
    _report().to_sarif(buf)
    run = json.loads(buf.getvalue())["runs"][0]
    # Version must be resolved dynamically, never a hardcoded literal.
    assert run["tool"]["driver"]["version"] == scanner_version()
    props = run["properties"]
    assert props["mcp-guard.run_id"]
    assert props["mcp-guard.data_source"] == "npx some-server"


def test_table_carries_provenance_footer():
    buf = io.StringIO()
    _report().to_table(buf)
    assert "provenance:" in buf.getvalue()
