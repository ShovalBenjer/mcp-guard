"""Report formatters — table, JSON, SARIF.

Every emitted report carries a ``_provenance`` block (Finding A: citation and
provenance are the load-bearing trust feature): scanner identity, version, run
id, UTC timestamp, target server id, and payload-ruleset version, so a
downstream agent or human can answer "where did this number come from?" without
trusting the channel the report arrived on.

All summary numbers are recomputed from the raw results list by
``verify_counts()`` (Finding B: never let the LLM do math, never show false
precision). The formatters refuse to emit a report whose summary disagrees with
its results — numbers are derived in code, never narrated.
"""
from __future__ import annotations

import json
import sys
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TextIO

from .fuzzer import FuzzResult, ResultCategory
from .payloads import PAYLOAD_SET_VERSION


def scanner_version() -> str:
    """Best-effort installed version; never lies, never empty."""
    try:
        from importlib.metadata import version

        return version("mcp-guard")
    except Exception:  # noqa: BLE001 — metadata absent in a bare checkout
        return "0.0.0+unknown"


@dataclass
class FuzzReport:
    server_command: str
    tools_fuzzed: int
    total_payloads: int
    results: list[FuzzResult]
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    run_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def crashes(self) -> list[FuzzResult]:
        return [r for r in self.results if r.category == ResultCategory.CRASH]

    @property
    def findings(self) -> list[FuzzResult]:
        return [r for r in self.results if r.category == ResultCategory.FINDING]

    @property
    def safe(self) -> list[FuzzResult]:
        return [r for r in self.results if r.category == ResultCategory.SAFE]

    @property
    def errors(self) -> list[FuzzResult]:
        return [r for r in self.results if r.category == ResultCategory.ERROR]

    def _category_counts(self) -> dict[str, int]:
        counts = {"crash": 0, "finding": 0, "safe": 0, "error": 0}
        for r in self.results:
            counts[r.category.value] += 1
        return counts

    def _severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in self.results:
            if r.category != ResultCategory.SAFE:
                counts[r.severity] = counts.get(r.severity, 0) + 1
        return counts

    def verify_counts(self) -> None:
        """Recompute every summary number from the raw results (Finding B).

        Raises ValueError if any caller-supplied or derived number disagrees
        with the results list. A report must never emit numbers that cannot be
        re-derived deterministically in code.
        """
        counts = self._category_counts()
        problems: list[str] = []
        if self.total_payloads != len(self.results):
            problems.append(
                f"total_payloads={self.total_payloads} != len(results)={len(self.results)}"
            )
        if len(self.crashes) != counts["crash"]:
            problems.append("crash count drifted from results")
        if len(self.findings) != counts["finding"]:
            problems.append("finding count drifted from results")
        if len(self.safe) != counts["safe"]:
            problems.append("safe count drifted from results")
        distinct_tools = {r.tool_name for r in self.results}
        if self.results and self.tools_fuzzed != len(distinct_tools):
            problems.append(
                f"tools_fuzzed={self.tools_fuzzed} != distinct tools in results={len(distinct_tools)}"
            )
        if problems:
            raise ValueError("report summary inconsistent with results: " + "; ".join(problems))

    def _provenance(self) -> dict[str, str]:
        """Machine-readable provenance block (Finding A). Never empty."""
        return {
            "scanner": "mcp-guard",
            "scanner_version": scanner_version(),
            "run_id": self.run_id,
            "run_at": self.run_at,
            "data_source": self.server_command,
            "payload_ruleset_version": PAYLOAD_SET_VERSION,
            "report_schema": "1",
        }

    def to_table(self, out: TextIO | None = None) -> None:
        self.verify_counts()
        out = out or sys.stdout
        out.write(f"\n{'='*72}\n")
        out.write(f"  mcp-guard fuzz report: {self.server_command}\n")
        out.write(f"{'='*72}\n\n")
        out.write(f"  Tools fuzzed:  {self.tools_fuzzed}\n")
        out.write(f"  Payloads sent: {self.total_payloads}\n")
        out.write(f"  Crashes:       {len(self.crashes)}\n")
        out.write(f"  Findings:      {len(self.findings)}\n")
        out.write(f"  Safe:          {len(self.safe)}\n\n")

        if self.crashes:
            out.write(f"  {'CRASHES':^68}\n")
            out.write(f"  {'-'*68}\n")
            for r in self.crashes:
                out.write(f"  [{r.severity.upper()}] {r.tool_name} :: {r.rule_id}\n")
                out.write(f"         payload: {str(r.payload_value)[:60]}\n")
                out.write(f"         {r.detail}\n\n")

        if self.findings:
            out.write(f"  {'FINDINGS':^68}\n")
            out.write(f"  {'-'*68}\n")
            for r in self.findings[:20]:
                out.write(f"  [{r.severity.upper()}] {r.tool_name} :: {r.rule_id}\n")
                out.write(f"         payload: {str(r.payload_value)[:60]}\n")
                if r.response_preview:
                    out.write(f"         response: {r.response_preview[:60]}\n")
                out.write("")

        remaining = len(self.findings) - 20
        if remaining > 0:
            out.write(f"  ... and {remaining} more findings\n")

        out.write(f"\n{'='*72}\n")
        if self.crashes:
            out.write("  VERDICT: VULNERABLE — crashes detected\n")
        elif self.findings:
            out.write(f"  VERDICT: {len(self.findings)} findings require investigation\n")
        else:
            out.write("  VERDICT: CLEAN — all payloads handled safely\n")
        out.write(f"{'='*72}\n")
        prov = self._provenance()
        out.write(
            f"  provenance: {prov['scanner']} {prov['scanner_version']} | "
            f"run {prov['run_id'][:12]} at {prov['run_at']} | "
            f"ruleset v{prov['payload_ruleset_version']}\n\n"
        )

    def to_json(self, out: TextIO | None = None) -> None:
        self.verify_counts()
        out = out or sys.stdout
        data = {
            "_provenance": self._provenance(),
            "server": self.server_command,
            "summary": {
                "tools_fuzzed": self.tools_fuzzed,
                "total_payloads": self.total_payloads,
                "crashes": len(self.crashes),
                "findings": len(self.findings),
                "safe": len(self.safe),
                "by_severity": self._severity_counts(),
            },
            "results": [
                {
                    "tool": r.tool_name,
                    "probe": r.probe_name,
                    "payload": repr(r.payload_value),
                    "category": r.category.value,
                    "rule_id": r.rule_id,
                    "severity": r.severity,
                    "detail": r.detail,
                    "response_preview": r.response_preview,
                }
                for r in self.results
                if r.category != ResultCategory.SAFE
            ],
        }
        out.write(json.dumps(data, indent=2, ensure_ascii=False))

    def to_sarif(self, out: TextIO | None = None) -> None:
        self.verify_counts()
        out = out or sys.stdout
        rules_map: dict[str, int] = {}
        rules_list: list[dict] = []
        results_sarif: list[dict] = []

        for r in self.results:
            if r.category == ResultCategory.SAFE:
                continue
            if r.rule_id not in rules_map:
                idx = len(rules_list) + 1
                rules_map[r.rule_id] = idx
                rules_list.append({"id": r.rule_id, "shortDescription": {"text": r.rule_id}})

            sarif_level = "error" if r.category == ResultCategory.CRASH else "warning"
            results_sarif.append({
                "ruleId": r.rule_id,
                "ruleIndex": rules_map[r.rule_id] - 1,
                "level": sarif_level,
                "message": {"text": r.detail},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"mcp://{r.tool_name}"}}}],
            })

        prov = self._provenance()
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "mcp-guard",
                    "version": prov["scanner_version"],
                    "rules": rules_list,
                }},
                "properties": {
                    "mcp-guard.run_id": prov["run_id"],
                    "mcp-guard.run_at": prov["run_at"],
                    "mcp-guard.data_source": prov["data_source"],
                    "mcp-guard.payload_ruleset_version": prov["payload_ruleset_version"],
                },
                "results": results_sarif,
            }],
        }
        out.write(json.dumps(sarif, indent=2, ensure_ascii=False))
