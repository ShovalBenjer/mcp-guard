"""Adversarial coverage test for .gitignore: every artifact class enumerated in
issue #15 must actually be ignored, and tracked source files must NOT be
silenced by an over-broad pattern. Enforcement is `git check-ignore`,
not prose.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Representative paths for every artifact class enumerated in issue #15.
MUST_BE_IGNORED = [
    # Python
    "__pycache__/scanner.cpython-311.pyc",
    "mcp_guard.cpython-311.pyc",
    "legacy.pyo",
    "legacy.pyd",
    "native.so",
    "pkg.egg",
    "pkg.egg-info/PKG-INFO",
    "dist/mcp-guard-0.2.1.tar.gz",
    "build/lib/mcp_guard/scanner.py",
    ".eggs/setuptools-68",
    "lib/site.py",
    "lib64/site.py",
    ".venv/bin/activate",
    "venv/bin/activate",
    "env/bin/activate",
    ".env",
    ".mypy_cache/3.11/scanner.data.json",
    ".pytest_cache/CACHEDIR.TAG",
    ".ruff_cache/0.5.0/CACHEDIR.TAG",
    "htmlcov/index.html",
    ".coverage",
    ".coverage.localhost.1234.5678",
    ".hypothesis/examples/x",
    ".tox/py311/bin/pytest",
    ".nox/lint/bin/ruff",
    ".pytype/py3.11/imports/x",
    "pip-log.txt",
    "pip-delete-this-directory.txt",
    ".python-version",
    "__pypackages__/3.11/lib/x.py",
    # Node.js
    "node_modules/.bin/eslint",
    "npm-debug.log",
    "yarn-error.log",
    "pnpm-debug.log",
    ".npm/_cacache/x",
    ".yarn/releases/yarn-4.js",
    ".pnp.js",
    ".pnp.cache",
    ".cache/vite/x",
    # OS
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    "shortcut.lnk",
    # IDE
    ".idea/workspace.xml",
    ".vscode/settings.json",
    ".history/scanner_20261009.py",
    # CI
    "junit.xml",
    "reports/junit.xml",
    "test-results/report.xml",
    "coverage/lcov.info",
]

# Real source files that must never be swallowed by an over-broad pattern.
MUST_NOT_BE_IGNORED = [
    "src/mcp_guard/scanner.py",
    "src/mcp_guard/__init__.py",
    "pyproject.toml",
    "README.md",
    "tests/test_scanner.py",
    ".github/workflows/ci.yml",
    "docs/spec.md",
    ".gitignore",
]


def _check_ignore(paths: list[str]) -> set[str]:
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "check-ignore", "--", *paths],
        capture_output=True,
        text=True,
        check=False,
    )
    return {line for line in proc.stdout.splitlines() if line}


def test_all_issue15_artifact_classes_are_ignored() -> None:
    ignored = _check_ignore(MUST_BE_IGNORED)
    missing = [p for p in MUST_BE_IGNORED if p not in ignored]
    assert not missing, f"paths NOT ignored by .gitignore: {missing}"


def test_no_overbroad_pattern_swallows_sources() -> None:
    ignored = _check_ignore(MUST_NOT_BE_IGNORED)
    assert not ignored, f"source files wrongly ignored: {sorted(ignored)}"
