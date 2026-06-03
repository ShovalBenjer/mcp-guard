"""Report formatters — table, JSON, SARIF."""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import TextIO

from .fuzzer import FuzzResult, ResultCategory


@dataclass
class FuzzReport:
    server_command: str
    tools_fuzzed: int
    total_payloads: int
    results: list[FuzzResult]

    @property
    def crashes(self) -> list[FuzzResult]:
        return [r for r in self.results if r.category == ResultCategory.CRASH]

    @property
    def findings(self) -> list[FuzzResult]:
        return [r for r in self.results if r.category == ResultCategory.FINDING]

    @property
    def safe(self) -> list[FuzzResult]:
        return [r for r in self.results if r.category == ResultCategory.SAFE]

    def to_table(self, out: TextIO | None = None) -> None:
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
        out.write(f"{'='*72}\n\n")

    def to_json(self, out: TextIO | None = None) -> None:
        out = out or sys.stdout
        data = {
            "server": self.server_command,
            "summary": {
                "tools_fuzzed": self.tools_fuzzed,
                "total_payloads": self.total_payloads,
                "crashes": len(self.crashes),
                "findings": len(self.findings),
                "safe": len(self.safe),
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

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "mcp-guard", "version": "0.2.0", "rules": rules_list}},
                "results": results_sarif,
            }],
        }
        out.write(json.dumps(sarif, indent=2, ensure_ascii=False))
