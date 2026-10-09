"""Enforce valid YAML for every GitHub Actions workflow (mcp-guard#48).

Regression: ``coffee-break.yml`` shipped with an unquoted ``${{ }}``
expression containing a colon-space inside a single-quoted fragment:

    TOPIC: ${{ inputs.topic || github.event.issue.title || 'open brainstorm: current blockers' }}

In a YAML plain scalar the quotes carry no meaning, so the colon-space
after "brainstorm" was parsed as a mapping indicator and the whole
workflow file became invalid YAML. Every run then failed before any job
started (zero check runs), and the surface never worked once. These tests
pin the invariant so the class can never recur.
"""

from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"


def _names() -> list[str]:
    return sorted(p.name for p in WORKFLOWS.glob("*.yml"))


def _load(name: str) -> dict:
    raw = (WORKFLOWS / name).read_text(encoding="utf-8")
    doc = yaml.safe_load(raw)
    assert isinstance(doc, dict), f"{name}: top-level YAML must be a mapping"
    return doc


def test_at_least_one_workflow() -> None:
    assert _names(), "no workflow files found under .github/workflows"


@pytest.mark.parametrize("name", _names())
def test_workflow_parses_as_yaml(name: str) -> None:
    _load(name)


@pytest.mark.parametrize("name", _names())
def test_workflow_has_jobs_mapping(name: str) -> None:
    doc = _load(name)
    assert isinstance(doc.get("jobs"), dict), f"{name}: must define a jobs mapping"


def test_coffee_break_topic_expression_quoted() -> None:
    """Pin the exact shipped bug: the TOPIC default fragment must survive parsing."""
    text = (WORKFLOWS / "coffee-break.yml").read_text(encoding="utf-8")
    assert "'open brainstorm: current blockers'" in text
    doc = _load("coffee-break.yml")
    steps = doc["jobs"]["deliberate"]["steps"]
    env = next(s for s in steps if s.get("name") == "Run coffee-break deliberation")["env"]
    assert "open brainstorm: current blockers" in str(env["TOPIC"])
