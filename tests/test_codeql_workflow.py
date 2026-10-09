"""Enforce the acceptance criteria of mcp-guard#44 (CodeQL workflow) in CI.

The workflow file is the deliverable; these tests pin every acceptance
criterion so a regression (e.g. a dropped permission or schedule line)
fails the build instead of silently weakening the analysis.
"""

from pathlib import Path

import pytest
import yaml

WORKFLOW = (
    Path(__file__).resolve().parent.parent / ".github" / "workflows" / "codeql.yml"
)


@pytest.fixture(scope="module")
def doc() -> dict:
    assert WORKFLOW.exists(), f"codeql.yml missing: {WORKFLOW}"
    raw = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    # YAML 1.1 quirk: a bare `on:` key parses as boolean True.
    if "on" not in raw and True in raw:
        raw["on"] = raw.pop(True)
    return raw


@pytest.fixture(scope="module")
def analyze(doc: dict) -> dict:
    jobs = doc["jobs"]
    assert "analyze" in jobs, "codeql.yml must define an 'analyze' job"
    return jobs["analyze"]


def test_workflow_file_exists() -> None:
    assert WORKFLOW.exists()


def test_languages_python_and_actions(analyze: dict) -> None:
    languages = analyze["strategy"]["matrix"]["language"]
    assert "python" in languages, "CodeQL must analyze Python"
    assert "actions" in languages, "CodeQL must analyze GitHub Actions workflows"


def test_autobuild_step_present(analyze: dict) -> None:
    uses = [str(s.get("uses", "")) for s in analyze["steps"]]
    assert any(u.startswith("github/codeql-action/autobuild@") for u in uses), (
        "CodeQL workflow must run autobuild for Python"
    )


def test_security_events_write_permission(doc: dict) -> None:
    perms = doc.get("permissions", {})
    assert perms.get("security-events") == "write", (
        "security-events: write is required to upload results to the Security tab"
    )


def test_weekly_schedule_mondays(doc: dict) -> None:
    schedules = doc["on"]["schedule"]
    crons = [s["cron"] for s in schedules]
    assert "0 0 * * 1" in crons, "CodeQL must run on a weekly Monday schedule"


def test_push_and_pull_request_triggers(doc: dict) -> None:
    on = doc["on"]
    assert "push" in on and "pull_request" in on, (
        "CodeQL must run on push and pull_request"
    )


def test_codeql_init_uses_matrix_language(analyze: dict) -> None:
    init_steps = [
        s
        for s in analyze["steps"]
        if str(s.get("uses", "")).startswith("github/codeql-action/init@")
    ]
    assert init_steps, "CodeQL init step missing"
    langs = init_steps[0]["with"]["languages"]
    assert "matrix.language" in langs, (
        "init must analyze the matrix language, not a hardcoded value"
    )


def test_fail_fast_false_so_both_languages_report(analyze: dict) -> None:
    # If python fails, the actions run must still report (and vice versa).
    assert analyze["strategy"].get("fail-fast") is False
