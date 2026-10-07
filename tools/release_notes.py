"""Release-notes generator for the release workflow (mcp-guard#37).

Generates Markdown release notes from git history: commits on
<previous-tag>..<current-tag> (merge commits excluded), plus a compare
link. First release (no previous tag) uses the full history and omits
the compare link. Prints to stdout; the workflow redirects to a file
consumed by the GitHub Release step.

Usage:
    python3 tools/release_notes.py [--repo PATH]
Reads GITHUB_REF_NAME for the current tag.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

REPO_URL = "https://github.com/ShovalBenjer/mcp-guard"
_MERGE_SUBJECT = re.compile(r"^Merge (branch|pull request|remote)", re.IGNORECASE)
_MD_ESCAPE = re.compile(r"([\\\[\]()!])")


def escape_md(text: str) -> str:
    """Escape Markdown metacharacters in an untrusted commit subject.

    Commit subjects are fully attacker-influenced (a PR title becomes the
    commit subject on squash-merge) and are rendered into the GitHub Release
    body as Markdown; interpolated raw, a subject like
    ``[critical security fix](https://evil.example/pwn)`` would render as a
    live link or image on the project's trusted release surface. Backslash
    escaping makes every metacharacter render literally. Also strips ``\\r``
    so a crafted carriage return cannot hide a second line.
    """
    text = text.replace("\r", "")
    return _MD_ESCAPE.sub(r"\\\1", text)


def _git(repo: str, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", repo, *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _version_key(tag: str) -> tuple:
    """Numeric version sort key so v0.2.10 sorts after v0.2.9.

    A bare release sorts above any prerelease of the same numbers
    (v1.0.0 > v1.0.0-rc.1); that is the only suffix ordering the
    release-range logic needs.
    """
    stem = tag.removeprefix("v")
    main, _, suffix = stem.partition("-")
    nums = tuple(int(p) for p in main.split(".") if p.isdigit())
    suffix_key: tuple = (1,) if not suffix else (0, suffix)
    return (nums, suffix_key)


def previous_tag(tags: list[str], current: str) -> str | None:
    """The greatest release tag strictly below *current*, or None."""
    current_key = _version_key(current)
    candidates = [
        t for t in tags
        if t != current and _version_key(t) < current_key
    ]
    if not candidates:
        return None
    return max(candidates, key=_version_key)


def commits_in_range(repo: str, rev_range: str) -> list[tuple[str, str]]:
    """[(short_sha, subject)] for non-merge commits in *rev_range*."""
    out = _git(repo, "log", rev_range, "--format=%h%x00%s", "--no-merges")
    commits: list[tuple[str, str]] = []
    for line in out.splitlines():
        sha, _, subject = line.partition("\x00")
        if _MERGE_SUBJECT.match(subject):
            continue  # belt-and-suspenders: --no-merges plus subject filter
        commits.append((sha, subject))
    return commits


def format_notes(current: str, prev: str | None,
                 commits: list[tuple[str, str]]) -> str:
    """Render the release-notes Markdown."""
    lines = [f"## mcp-guard {current}", ""]
    if prev is None:
        lines.append("Initial release notes generated from full git history.")
    else:
        lines += [f"Changes since `{prev}`:", ""]
        for sha, subject in commits:
            lines.append(f"- {escape_md(subject)} ({sha})")
        lines += [
            "",
            f"**Full changelog:** {REPO_URL}/compare/{prev}...{current}",
        ]
    if prev is None:
        lines += ["", "### Changes", ""]
        for sha, subject in commits:
            lines.append(f"- {escape_md(subject)} ({sha})")
    return "\n".join(lines) + "\n"


def generate(repo: str, current: str) -> str:
    tags = _git(repo, "tag", "--list", "v*").splitlines()
    prev = previous_tag(tags, current)
    rev_range = current if prev is None else f"{prev}..{current}"
    commits = commits_in_range(repo, rev_range)
    return format_notes(current, prev, commits)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    args = ap.parse_args()
    current = os.environ.get("GITHUB_REF_NAME", "")
    if not current:
        print("release_notes: GITHUB_REF_NAME is not set", file=sys.stderr)
        return 1
    try:
        sys.stdout.write(generate(args.repo, current))
    except subprocess.CalledProcessError as exc:
        print(f"release_notes: git failed: {exc.stderr.strip()}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

