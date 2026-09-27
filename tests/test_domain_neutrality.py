"""Domain-neutrality lint: fintech/fraud/credit/risk-domain language must never
appear in mcp-guard source, tests, or docs. Threat scenarios use neutral
tool-call/API domains only. See issue #63 (neutralized 2026-09-28).

Security-risk language (command injection, SSRF risk, ...) is this repo's own
domain and is explicitly allowed.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

BANNED_PATTERNS = [
    r"\bfraud\b",
    r"\bfintech\b",
    r"synthetic[\s_-]?identity",
    r"social[\s_-]?engineering",
    r"money[\s_-]?launder",
    r"credit[\s_-]?scor",
    r"\bdavies\b",
    r"lying for money",
]

SCANNED_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".json", ".toml", ".html"}
SKIPPED_DIRS = {".git", "__pycache__", ".venv", "node_modules"}
# This lint file names the banned terms by design; it is the enforcement
# mechanism, not a domain fixture.
SELF = Path(__file__).resolve()


def _iter_files():
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if path.resolve() == SELF:
            continue
        if path.suffix.lower() not in SCANNED_SUFFIXES:
            continue
        if any(part in SKIPPED_DIRS for part in path.parts):
            continue
        yield path


def test_no_fintech_fraud_domain_language():
    compiled = [(p, re.compile(p, re.IGNORECASE)) for p in BANNED_PATTERNS]
    violations = []
    for path in _iter_files():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern, rx in compiled:
                if rx.search(line):
                    rel = path.relative_to(REPO_ROOT)
                    violations.append(f"{rel}:{lineno}: matches {pattern!r}")
    assert not violations, (
        "Fintech/fraud-domain language detected "
        "(use neutral tool-call/API domains instead):\n" + "\n".join(violations)
    )
