"""Adversarial tests for the release tooling (mcp-guard#37).

The release pipeline's two safety-critical behaviors are fail-closed:
(1) a mismatched/malformed tag must NEVER publish, and (2) release notes
must cover exactly the commits in the tag range — no more, no less.
Every test here pins a failure mode, not a happy path.
"""

import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from release_check_version import VersionMismatch, check, normalize_tag
from release_notes import (
    _version_key,
    escape_md,
    format_notes,
    generate,
    previous_tag,
)

# --- version guard -------------------------------------------------------


class TestNormalizeTag:
    def test_ok(self):
        assert normalize_tag("v0.2.1") == "0.2.1"

    def test_rejects_missing_v(self):
        with pytest.raises(VersionMismatch):
            normalize_tag("0.2.1")

    def test_rejects_empty_after_v(self):
        with pytest.raises(VersionMismatch):
            normalize_tag("v")

    def test_rejects_two_part(self):
        with pytest.raises(VersionMismatch):
            normalize_tag("v1.2")

    def test_rejects_prefix_garbage(self):
        with pytest.raises(VersionMismatch):
            normalize_tag("release-1.2.3")

    def test_rejects_embedded_space(self):
        with pytest.raises(VersionMismatch):
            normalize_tag("v 1.2.3")

    def test_accepts_prerelease(self):
        assert normalize_tag("v1.0.0-rc.1") == "1.0.0-rc.1"


class TestCheck:
    def test_match(self):
        assert check("v0.2.1", "0.2.1") == "0.2.1"

    def test_mismatch_refused(self):
        with pytest.raises(VersionMismatch):
            check("v0.3.0", "0.2.1")

    def test_patch_drift_refused(self):
        # the classic footgun: tag pushed before the version bump
        with pytest.raises(VersionMismatch):
            check("v0.2.1", "0.2.2")

    def test_malformed_project_version_refused(self):
        with pytest.raises(VersionMismatch):
            check("v0.2.1", "latest")

    def test_whitespace_tolerated_not_silenced(self):
        assert check("v0.2.1", "  0.2.1\n") == "0.2.1"

    def test_no_coercion_of_close_tags(self):
        # "v0.2.10" must not match project "0.2.1" by prefix tricks
        with pytest.raises(VersionMismatch):
            check("v0.2.10", "0.2.1")


# --- tag ordering --------------------------------------------------------


class TestPreviousTag:
    def test_picks_immediate_predecessor(self):
        tags = ["v0.1.0", "v0.2.0", "v0.2.1"]
        assert previous_tag(tags, "v0.2.1") == "v0.2.0"

    def test_numeric_not_lexicographic(self):
        # string sort would put v0.2.10 before v0.2.9 — the wrong range
        tags = ["v0.2.9", "v0.2.10"]
        assert previous_tag(tags, "v0.2.10") == "v0.2.9"

    def test_none_when_first_release(self):
        assert previous_tag(["v0.1.0"], "v0.1.0") is None

    def test_none_when_no_tags(self):
        assert previous_tag([], "v0.1.0") is None

    def test_ignores_later_tags(self):
        tags = ["v0.1.0", "v0.9.9", "v0.2.0"]
        assert previous_tag(tags, "v0.2.0") == "v0.1.0"

    def test_version_key_orders_prerelease_below_release(self):
        assert _version_key("v1.0.0") > _version_key("v1.0.0-rc.1")


# --- notes formatting ----------------------------------------------------


class TestFormatNotes:
    def test_compare_link_present(self):
        notes = format_notes("v0.2.1", "v0.2.0", [("abc1234", "fix: thing")])
        assert "compare/v0.2.0...v0.2.1" in notes
        assert "fix: thing (abc1234)" in notes

    def test_first_release_has_no_compare_link(self):
        notes = format_notes("v0.1.0", None, [("abc1234", "init")])
        assert "compare" not in notes

    def test_empty_range_renders_without_commits(self):
        notes = format_notes("v0.2.1", "v0.2.0", [])
        assert "v0.2.0" in notes  # still names the range


# --- end-to-end against throwaway git repos ------------------------------


def _init_repo(path: str) -> None:
    subprocess.run(["git", "init", "-q", path], check=True)
    subprocess.run(["git", "-C", path, "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", path, "config", "user.name", "t"], check=True)


def _commit(path: str, name: str, msg: str) -> None:
    with open(os.path.join(path, name), "w") as fh:
        fh.write(msg)
    subprocess.run(["git", "-C", path, "add", name], check=True)
    subprocess.run(["git", "-C", path, "commit", "-q", "-m", msg], check=True)


def _tag(path: str, tag: str) -> None:
    subprocess.run(["git", "-C", path, "tag", tag], check=True)


def test_generate_covers_exactly_the_range(tmp_path):
    repo = str(tmp_path)
    _init_repo(repo)
    _commit(repo, "a", "old work")
    _tag(repo, "v0.1.0")
    _commit(repo, "b", "new feature")
    _commit(repo, "c", "new fix")
    _tag(repo, "v0.2.0")

    notes = generate(repo, "v0.2.0")
    assert "new feature" in notes
    assert "new fix" in notes
    assert "old work" not in notes  # outside the range — must not leak in
    assert "compare/v0.1.0...v0.2.0" in notes


def test_generate_first_release_uses_full_history(tmp_path):
    repo = str(tmp_path)
    _init_repo(repo)
    _commit(repo, "a", "first")
    _commit(repo, "b", "second")
    _tag(repo, "v0.1.0")

    notes = generate(repo, "v0.1.0")
    assert "first" in notes and "second" in notes
    assert "compare" not in notes


def test_generate_excludes_merges(tmp_path):
    repo = str(tmp_path)
    _init_repo(repo)
    _commit(repo, "a", "base")
    _tag(repo, "v0.1.0")
    subprocess.run(["git", "-C", repo, "checkout", "-q", "-b", "feat"], check=True)
    _commit(repo, "b", "side work")
    subprocess.run(["git", "-C", repo, "checkout", "-q", "master"], check=True)
    subprocess.run(
        ["git", "-C", repo, "merge", "-q", "--no-ff", "feat", "-m", "Merge branch 'feat'"],
        check=True,
    )
    _tag(repo, "v0.2.0")

    notes = generate(repo, "v0.2.0")
    assert "side work" in notes
    assert "Merge branch" not in notes


# --- untrusted-subject markdown escaping (F1) ----------------------------


class TestEscapeMd:
    def test_link_neutralized(self):
        evil = "[critical security fix](https://evil.example/pwn)"
        notes = format_notes("v0.2.1", "v0.2.0", [("abc1234", evil)])
        assert evil not in notes  # raw link must never reach the release body
        assert r"\[critical security fix\]\(https://evil.example/pwn\)" in notes

    def test_image_neutralized(self):
        evil = "![x](https://evil.example/t.png)"
        notes = format_notes("v0.2.1", "v0.2.0", [("abc1234", evil)])
        assert evil not in notes
        assert r"\!\[x\]\(https://evil.example/t.png\)" in notes

    def test_backslash_escaped_first(self):
        # a pre-escaped subject must not become an active link
        assert escape_md("[a](b)") == "\\[a\\]\\(b\\)"
        assert escape_md("a\\[b]") == "a\\\\\\[b\\]"

    def test_cr_stripped(self):
        assert escape_md("line one\r\nsmuggled line") == "line one\nsmuggled line"

    def test_benign_subject_untouched(self):
        assert escape_md("fix: handle timeouts in canary") == "fix: handle timeouts in canary"

    def test_first_release_path_also_escaped(self):
        evil = "[x](https://evil.example)"
        notes = format_notes("v0.1.0", None, [("abc1234", evil)])
        assert evil not in notes

    def test_angle_autolink_neutralized(self):
        # CommonMark autolink syntax must not survive into the release body
        evil = "<https://evil.example/pwn>"
        notes = format_notes("v0.2.1", "v0.2.0", [("abc1234", evil)])
        assert evil not in notes
        assert r"\<https://evil.example/pwn\>" in notes

    def test_raw_html_neutralized(self):
        evil = "<script>alert(1)</script>"
        notes = format_notes("v0.2.1", "v0.2.0", [("abc1234", evil)])
        assert evil not in notes

    def test_bare_url_is_accepted_residual(self):
        # bare URLs (no markup chars) are autolinked by GFM's extension and
        # cannot be neutralized by escaping; they render as the raw URL
        # itself (no disguised link text) — documented accepted residual.
        benign = "fix: see https://github.com/ShovalBenjer/mcp-guard/issues/37"
        assert escape_md(benign) == benign
