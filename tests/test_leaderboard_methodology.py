"""RED: LEADERBOARD.md methodology must match the payload generators.

mcp-guard#12 stayed open for six weeks because the documented payload counts
drifted from the code: generate_indirect_injection() added 4 probes per string
parameter (2026-09-26) and nobody updated the methodology section. These tests
fail CI on any generator change that is not carried into LEADERBOARD.md, and
on any leaderboard edit that is not true of the code — the doc is verified in
both directions. Code and doc are the only two sources of numbers here; the
tests themselves assert equality between them and hold no independent
literals.
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


def _section(text: str, start: str, end: str) -> str:
    """Extract the markdown between two section headings (end exclusive)."""
    i = text.index(start)
    j = text.index(end, i)
    return text[i:j]


def _two_col_rows(section: str) -> dict[str, int]:
    """Map label -> count for exactly-two-column markdown table rows."""
    rows: dict[str, int] = {}
    for m in re.finditer(
        r"^\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|\s*$", section, re.MULTILINE
    ):
        rows[m.group(1).strip()] = int(m.group(2))
    return rows


def _severity_table(section: str) -> dict[str, int]:
    """Map severity -> weight from the three-column severity table."""
    rows: dict[str, int] = {}
    for m in re.finditer(
        r"^\|\s*([A-Z]+)\s*\|\s*(\d+)\s*\|[^|]*\|\s*$", section, re.MULTILINE
    ):
        rows[m.group(1).strip()] = int(m.group(2))
    return rows


def _bullet_class_counts(section: str) -> dict[str, int]:
    """Map payload class label -> documented count from the §1 string bullet.

    Parses only the string-parameter breakdown line:
      - String parameters receive shell injection (8), prompt injection (6), ...
    """
    counts: dict[str, int] = {}
    for line in section.splitlines():
        if not line.startswith("- String parameters receive"):
            continue
        items = line.removeprefix("- String parameters receive ").strip()
        for item in re.split(r",\s*(?:and\s+)?", items):
            m = re.fullmatch(r"(.+?)\s*\((\d+)\)\.?", item.strip())
            if m:
                counts[m.group(1).strip()] = int(m.group(2))
    return counts


@pytest.fixture(scope="module")
def doc() -> str:
    assert LEADERBOARD.exists(), "LEADERBOARD.md missing at repo root"
    return LEADERBOARD.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def counts_section(doc: str) -> str:
    return _section(doc, "### 1. Payload Counting", "### 2. Severity Levels")


@pytest.fixture(scope="module")
def severity_section(doc: str) -> str:
    return _section(doc, "### 2. Severity Levels", "### 3. Benchmarking")


# label -> generator expression for the §1 string-parameter breakdown bullets
STRING_CLASS_GENERATORS = {
    "shell injection": lambda: len(generate_shell_injection()),
    "prompt injection": lambda: len(generate_prompt_injection()),
    "indirect-injection probes": lambda: len(generate_indirect_injection()),
    "overflow subset": lambda: len(generate_overflow()[:3]),
    "type confusion": lambda: len(generate_type_confusion("string")),
}


class TestPayloadCountsMatchGenerators:
    """The §1 table is derived from payloads.py, not hand-written."""

    def test_string_parameter_count(self, counts_section: str) -> None:
        documented = _two_col_rows(counts_section)["String parameter"]
        actual = len(generate_all_for_param("name", {"type": "string"}))
        assert actual == documented, (
            f"LEADERBOARD.md says {documented} payloads per string parameter, "
            f"generators produce {actual} — update the doc or the generators"
        )

    def test_string_breakdown_classes_match_generators(
        self, counts_section: str
    ) -> None:
        """Each documented payload class equals its live generator.

        Names which class drifted, without hard-coding any count in the test:
        both sides of every comparison come from code (generator) or doc.
        """
        bullets = _bullet_class_counts(counts_section)
        for label, count_of in STRING_CLASS_GENERATORS.items():
            assert label in bullets, (
                f"§1 breakdown no longer documents '{label}' — "
                "doc and generators have drifted"
            )
            actual = count_of()
            assert bullets[label] == actual, (
                f"doc says {label} contributes {bullets[label]} payloads, "
                f"generator produces {actual}"
            )
        assert sum(
            count_of() for count_of in STRING_CLASS_GENERATORS.values()
        ) == len(generate_all_for_param("name", {"type": "string"}))

    def test_uri_string_parameter_count(self, counts_section: str) -> None:
        documented = _two_col_rows(counts_section)["URI-typed string parameter"]
        actual = len(generate_all_for_param("url", {"type": "string", "format": "uri"}))
        assert actual == documented
        assert actual == len(generate_ssrf()) + len(
            generate_all_for_param("name", {"type": "string"})
        )

    def test_integer_parameter_count(self, counts_section: str) -> None:
        documented = _two_col_rows(counts_section)["Integer / number parameter"]
        actual = len(generate_all_for_param("count", {"type": "integer"}))
        assert actual == documented

    def test_no_schema_count(self, counts_section: str) -> None:
        """Drive the real FuzzEngine path so the count can't be hand-rolled."""

        class StubTransport:
            def call_tool(self, tool_name: str, arguments: dict) -> dict:
                return {"isError": True, "content": []}

        engine = FuzzEngine(transport=StubTransport())
        results = engine.fuzz_tool({"name": "no_schema_tool", "inputSchema": {}})
        documented = _two_col_rows(counts_section)["No input schema"]
        assert len(results) == documented


class TestSeverityTableMatchesEnum:
    """Every Severity enum member — including INFO — has a documented weight."""

    def test_all_enum_members_documented(self, severity_section: str) -> None:
        documented = _severity_table(severity_section)
        enum_members = {s.name for s in Severity}
        assert set(documented) == enum_members, (
            f"doc severities {set(documented)} != code enum {enum_members}"
        )

    def test_info_weight_is_zero(self, severity_section: str) -> None:
        # mcp-guard#12 names INFO=0 explicitly as a requirement.
        assert _severity_table(severity_section)["INFO"] == 0

    def test_weights_monotone(self, severity_section: str) -> None:
        w = _severity_table(severity_section)
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


class TestLegacyRowsAnnotated:
    """The pre-verification rankings rows must not ride under the stamp."""

    def test_rankings_carry_provenance_caveat(self, doc: str) -> None:
        rankings = _section(doc, "## Rankings", "## Key Findings")
        assert "2026-06-03" in rankings, "rankings lost their production date"
        assert "re-run" in rankings, (
            "rankings rows lack the not-re-run caveat — the methodology stamp "
            "would overclaim coverage of legacy rows"
        )
