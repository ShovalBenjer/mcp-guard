"""RED: LEADERBOARD.md methodology must match the payload generators.

mcp-guard#12 stayed open for six weeks because the documented payload counts
drifted from the code: generate_indirect_injection() added 4 probes per string
parameter (2026-09-26) and nobody updated the methodology section. These tests
fail CI on any generator change that is not carried into LEADERBOARD.md, and
on any leaderboard edit that is not true of the code — the doc is verified in
both directions.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from mcp_guard.fuzzer import FuzzEngine
from mcp_guard.payloads import (
    Severity,
    generate_all_for_param,
    generate_indirect_injection,
    generate_overflow,
    generate_prompt_injection,
    generate_shell_injection,
    generate_ssrf,
    generate_type_confusion,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
LEADERBOARD = REPO_ROOT / "LEADERBOARD.md"


def _two_col_rows(text: str) -> dict[str, int]:
    """Map label -> count for exactly-two-column markdown table rows."""
    rows: dict[str, int] = {}
    for m in re.finditer(r"^\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|\s*$", text, re.MULTILINE):
        rows[m.group(1).strip()] = int(m.group(2))
    return rows


def _severity_table(text: str) -> dict[str, int]:
    """Map severity -> weight from the three-column severity table."""
    rows: dict[str, int] = {}
    for m in re.finditer(r"^\|\s*([A-Z]+)\s*\|\s*(\d+)\s*\|[^|]*\|\s*$", text, re.MULTILINE):
        rows[m.group(1).strip()] = int(m.group(2))
    return rows


@pytest.fixture(scope="module")
def doc() -> str:
    assert LEADERBOARD.exists(), "LEADERBOARD.md missing at repo root"
    return LEADERBOARD.read_text(encoding="utf-8")


class TestPayloadCountsMatchGenerators:
    """The §1 table is derived from payloads.py, not hand-written."""

    def test_string_parameter_count(self, doc: str) -> None:
        documented = _two_col_rows(doc)["String parameter"]
        actual = len(generate_all_for_param("name", {"type": "string"}))
        assert actual == documented, (
            f"LEADERBOARD.md says {documented} payloads per string parameter, "
            f"generators produce {actual} — update the doc or the generators"
        )

    def test_string_breakdown_sums(self) -> None:
        """Names which payload class drifted, not just that something did."""
        parts = {
            "shell injection": len(generate_shell_injection()),
            "prompt injection": len(generate_prompt_injection()),
            "indirect injection": len(generate_indirect_injection()),
            "overflow subset": len(generate_overflow()[:3]),
            "type confusion": len(generate_type_confusion("string")),
        }
        assert parts == {
            "shell injection": 8,
            "prompt injection": 6,
            "indirect injection": 4,
            "overflow subset": 3,
            "type confusion": 8,
        }, f"payload class counts drifted: {parts}"
        assert sum(parts.values()) == len(
            generate_all_for_param("name", {"type": "string"})
        )

    def test_uri_string_parameter_count(self, doc: str) -> None:
        documented = _two_col_rows(doc)["URI-typed string parameter"]
        actual = len(generate_all_for_param("url", {"type": "string", "format": "uri"}))
        assert actual == documented
        assert actual == len(generate_ssrf()) + len(
            generate_all_for_param("name", {"type": "string"})
        )

    def test_integer_parameter_count(self, doc: str) -> None:
        documented = _two_col_rows(doc)["Integer / number parameter"]
        actual = len(generate_all_for_param("count", {"type": "integer"}))
        assert actual == documented == 9

    def test_no_schema_count(self, doc: str) -> None:
        """Drive the real FuzzEngine path so the count can't be hand-rolled."""

        class StubTransport:
            def call_tool(self, tool_name: str, arguments: dict) -> dict:
                return {"isError": True, "content": []}

        engine = FuzzEngine(transport=StubTransport())
        results = engine.fuzz_tool({"name": "no_schema_tool", "inputSchema": {}})
        documented = _two_col_rows(doc)["No input schema"]
        assert len(results) == documented == 24


class TestSeverityTableMatchesEnum:
    """Every Severity enum member — including INFO — has a documented weight."""

    def test_all_enum_members_documented(self, doc: str) -> None:
        documented = _severity_table(doc)
        enum_members = {s.name for s in Severity}
        assert set(documented) == enum_members, (
            f"doc severities {set(documented)} != code enum {enum_members}"
        )

    def test_info_weight_is_zero(self, doc: str) -> None:
        assert _severity_table(doc)["INFO"] == 0

    def test_weights_monotone(self, doc: str) -> None:
        w = _severity_table(doc)
        assert w["CRITICAL"] > w["HIGH"] > w["MEDIUM"] > w["LOW"] > w["INFO"]


class TestVersionAlignment:
    """mcp-guard#12: the leaderboard header version must equal pyproject's."""

    def test_header_version_matches_pyproject(self, doc: str) -> None:
        import tomllib

        with open(REPO_ROOT / "pyproject.toml", "rb") as f:
            pyproject = tomllib.load(f)
        expected = pyproject["project"]["version"]
        m = re.search(r"\*\*mcp-guard version:\s*([\d.]+)\*\*", doc)
        assert m, "leaderboard header has no mcp-guard version line"
        assert m.group(1) == expected, (
            f"leaderboard says {m.group(1)}, pyproject.toml says {expected}"
        )

    def test_payload_ruleset_version_matches_code(self, doc: str) -> None:
        from mcp_guard.payloads import PAYLOAD_SET_VERSION

        m = re.search(r"\*\*Payload ruleset version:\s*(\d+)\*\*", doc)
        assert m, "leaderboard header has no payload ruleset version line"
        assert m.group(1) == PAYLOAD_SET_VERSION
