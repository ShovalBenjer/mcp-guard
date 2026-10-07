"""Fail-closed version guard for the release workflow (mcp-guard#37).

The release pipeline must never publish an artifact whose PyPI version
disagrees with the tag that triggered it. A tag vX.Y.Z with pyproject
[project].version == X.Y.Z passes; anything else exits non-zero with a
loud message. No silent default, no coercion of malformed tags.

Usage (in release.yml):
    python3 tools/release_check_version.py
Reads GITHUB_REF_NAME from the environment and [project].version from
pyproject.toml at the repo root.
"""

from __future__ import annotations

import os
import re
import sys
import tomllib

_SEMVER = re.compile(r"^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$")


class VersionMismatch(Exception):
    """Raised when the tag and the project version disagree."""


def normalize_tag(ref_name: str) -> str:
    """'v1.2.3' -> '1.2.3'. Anything else is a hard failure, never coerced."""
    if not ref_name.startswith("v"):
        raise VersionMismatch(
            f"ref '{ref_name}' does not look like a release tag (expected vX.Y.Z)"
        )
    version = ref_name[1:]
    if not _SEMVER.match(version):
        raise VersionMismatch(
            f"tag version '{version}' is not valid semver (expected vX.Y.Z)"
        )
    return version


def check(ref_name: str, project_version: str) -> str:
    """Return the release version if tag and project version agree exactly.

    Raises VersionMismatch on any disagreement or malformed input.
    """
    tag_version = normalize_tag(ref_name)
    project_version = project_version.strip()
    if not _SEMVER.match(project_version):
        raise VersionMismatch(
            f"pyproject [project].version '{project_version}' is not valid semver"
        )
    if tag_version != project_version:
        raise VersionMismatch(
            f"tag v{tag_version} != pyproject version {project_version}: "
            "bump [project].version first, then push the matching tag"
        )
    return tag_version


def main() -> int:
    ref_name = os.environ.get("GITHUB_REF_NAME", "")
    if not ref_name:
        print("release_check_version: GITHUB_REF_NAME is not set", file=sys.stderr)
        return 1
    try:
        with open("pyproject.toml", "rb") as fh:
            project_version = tomllib.load(fh)["project"]["version"]
    except (OSError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        # fail-closed on unreadable/unparseable metadata
        print(f"release_check_version: cannot read [project].version: {exc}",
              file=sys.stderr)
        return 1
    try:
        version = check(ref_name, str(project_version))
    except VersionMismatch as exc:
        print(f"release_check_version: REFUSED: {exc}", file=sys.stderr)
        return 1
    print(f"release_check_version: OK — releasing {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
