"""jev decisions ledger — append-only log of every routing decision.

Per ADR-0009: the escalation threshold must be calibrated and audited, and
every "kept local" decision is logged. The log is also the raw material for
the NVIDIA flywheel (log calls -> curate -> distill specialists).

The raw task text is NEVER logged — only its SHA-256 hash and length, because
tasks may contain secrets or PII. The ledger is append-only: this module
exposes no method that rewrites, truncates, or deletes entries.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime

# Routing facts only. If a key appears here it describes WHERE a task runs,
# never a judgment about the task (no approved/verdict/allowed/denied).
_DECISION_KEYS = frozenset({
    "ts", "task_sha256", "task_len", "route", "route_kind",
    "complexity", "threshold", "escalated", "reason",
})


def default_ledger_path() -> str:
    """Ledger location; override with JEV_DECISIONS_PATH (tests do this)."""
    return os.getenv("JEV_DECISIONS_PATH") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "decisions.jsonl"
    )


class DecisionsLog:
    """Append-only JSONL ledger of routing decisions."""

    def __init__(self, path: str | None = None):
        self.path = path or default_ledger_path()

    def record(
        self,
        *,
        task: str,
        route_name: str,
        route_kind: str,
        complexity: float,
        threshold: float,
        escalated: bool,
        reason: str,
    ) -> dict:
        entry = {
            "ts": datetime.now(UTC).isoformat(),
            "task_sha256": hashlib.sha256(task.encode("utf-8")).hexdigest(),
            "task_len": len(task),
            "route": route_name,
            "route_kind": route_kind,
            "complexity": round(complexity, 4),
            "threshold": threshold,
            "escalated": escalated,
            "reason": reason,
        }
        assert set(entry) == _DECISION_KEYS, "decision record carries non-routing fields"
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        return entry

    def verify(self) -> int:
        """Check the ledger is well-formed JSONL. Returns the row count."""
        rows = 0
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entry = json.loads(line)
                    assert set(entry) == _DECISION_KEYS, f"foreign keys in ledger: {set(entry)}"
                    rows += 1
        return rows
