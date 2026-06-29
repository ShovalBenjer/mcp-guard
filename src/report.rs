//! Output formatters: human-readable table, JSON, and SARIF.

use std::io::{self, Write};

use serde_json::{Value, json};

use crate::fuzzer::{FuzzResult, ResultCategory};

/// A complete fuzz run, ready to be rendered.
pub struct FuzzReport {
    /// The server command that was fuzzed.
    pub server_command: String,
    /// Number of tools fuzzed.
    pub tools_fuzzed: usize,
    /// Total payloads sent.
    pub total_payloads: usize,
    /// All per-payload results.
    pub results: Vec<FuzzResult>,
}

impl FuzzReport {
    /// Results in the given category.
    fn by_category(&self, category: ResultCategory) -> impl Iterator<Item = &FuzzResult> {
        self.results.iter().filter(move |r| r.category == category)
    }

    /// Count of crash results.
    #[must_use]
    pub fn crashes(&self) -> usize {
        self.by_category(ResultCategory::Crash).count()
    }

    /// Count of evidence-backed findings.
    #[must_use]
    pub fn findings(&self) -> usize {
        self.by_category(ResultCategory::Finding).count()
    }

    /// Count of accepted-without-validation results.
    #[must_use]
    pub fn accepted(&self) -> usize {
        self.by_category(ResultCategory::Accepted).count()
    }

    /// Count of rejected (safe) results.
    #[must_use]
    pub fn rejected(&self) -> usize {
        self.by_category(ResultCategory::Safe).count()
    }

    /// Render the human-readable table.
    pub fn to_table(&self, out: &mut impl Write) -> io::Result<()> {
        let bar = "=".repeat(72);
        writeln!(out, "\n{bar}")?;
        writeln!(out, "  mcp-guard fuzz report: {}", self.server_command)?;
        writeln!(out, "{bar}\n")?;
        self.write_summary(out)?;
        self.write_section(out, "CRASHES", ResultCategory::Crash, usize::MAX)?;
        self.write_section(out, "FINDINGS", ResultCategory::Finding, 20)?;
        writeln!(out, "\n{bar}")?;
        self.write_verdict(out)?;
        writeln!(out, "{bar}\n")
    }

    fn write_summary(&self, out: &mut impl Write) -> io::Result<()> {
        writeln!(out, "  Tools fuzzed:  {}", self.tools_fuzzed)?;
        writeln!(out, "  Payloads sent: {}", self.total_payloads)?;
        writeln!(out, "  Crashes:       {}", self.crashes())?;
        writeln!(
            out,
            "  Findings:      {}   (accepted + concrete evidence of harm)",
            self.findings()
        )?;
        writeln!(
            out,
            "  Accepted:      {}   (no validation, no evidence of harm)",
            self.accepted()
        )?;
        writeln!(
            out,
            "  Rejected:      {}   (server returned an error)\n",
            self.rejected()
        )
    }

    fn write_section(
        &self,
        out: &mut impl Write,
        title: &str,
        category: ResultCategory,
        limit: usize,
    ) -> io::Result<()> {
        let rows: Vec<_> = self.by_category(category).collect();
        if rows.is_empty() {
            return Ok(());
        }
        writeln!(out, "  {title:^68}")?;
        writeln!(out, "  {}", "-".repeat(68))?;
        for r in rows.iter().take(limit) {
            writeln!(
                out,
                "  [{}] {} :: {}",
                r.severity.to_uppercase(),
                r.tool_name,
                r.rule_id
            )?;
            writeln!(
                out,
                "         payload: {}",
                truncate(&r.payload_value.to_string(), 60)
            )?;
            if !r.response_preview.is_empty() {
                writeln!(
                    out,
                    "         response: {}",
                    truncate(&r.response_preview, 60)
                )?;
            }
            writeln!(out)?;
        }
        if rows.len() > limit {
            writeln!(out, "  ... and {} more", rows.len() - limit)?;
        }
        Ok(())
    }

    fn write_verdict(&self, out: &mut impl Write) -> io::Result<()> {
        if self.crashes() > 0 {
            writeln!(
                out,
                "  VERDICT: VULNERABLE — server crashed on adversarial input"
            )
        } else if self.findings() > 0 {
            writeln!(
                out,
                "  VERDICT: {} finding(s) with concrete evidence — investigate",
                self.findings()
            )
        } else if self.accepted() > 0 {
            writeln!(
                out,
                "  VERDICT: no confirmed vulnerabilities. {} payload(s) accepted",
                self.accepted()
            )?;
            writeln!(
                out,
                "           without validation — review input handling."
            )
        } else {
            writeln!(
                out,
                "  VERDICT: CLEAN — every adversarial payload was rejected"
            )
        }
    }

    /// Render machine-readable JSON (omitting the noisy `safe` results).
    pub fn to_json(&self, out: &mut impl Write) -> io::Result<()> {
        let results: Vec<Value> = self
            .results
            .iter()
            .filter(|r| r.category != ResultCategory::Safe)
            .map(|r| {
                json!({
                    "tool": r.tool_name,
                    "probe": r.probe_name,
                    "payload": r.payload_value,
                    "category": r.category.as_str(),
                    "rule_id": r.rule_id,
                    "severity": r.severity,
                    "detail": r.detail,
                    "response_preview": r.response_preview,
                })
            })
            .collect();

        let doc = json!({
            "server": self.server_command,
            "summary": {
                "tools_fuzzed": self.tools_fuzzed,
                "total_payloads": self.total_payloads,
                "crashes": self.crashes(),
                "findings": self.findings(),
                "accepted": self.accepted(),
                "safe": self.rejected(),
            },
            "results": results,
        });
        writeln!(out, "{}", serde_json::to_string_pretty(&doc)?)
    }

    /// Render SARIF 2.1.0 for the GitHub Security tab.
    pub fn to_sarif(&self, out: &mut impl Write) -> io::Result<()> {
        let mut rule_index: Vec<String> = Vec::new();
        let mut sarif_results = Vec::new();

        for r in self
            .results
            .iter()
            .filter(|r| r.category != ResultCategory::Safe)
        {
            let idx = rule_index
                .iter()
                .position(|id| id == &r.rule_id)
                .unwrap_or_else(|| {
                    rule_index.push(r.rule_id.clone());
                    rule_index.len() - 1
                });
            let level = match r.category {
                ResultCategory::Crash => "error",
                ResultCategory::Finding => "warning",
                _ => "note",
            };
            sarif_results.push(json!({
                "ruleId": r.rule_id,
                "ruleIndex": idx,
                "level": level,
                "message": { "text": r.detail },
                "locations": [{
                    "physicalLocation": { "artifactLocation": { "uri": format!("mcp://{}", r.tool_name) } }
                }],
            }));
        }

        let rules: Vec<Value> = rule_index
            .iter()
            .map(|id| json!({ "id": id, "shortDescription": { "text": id } }))
            .collect();

        let sarif = json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": { "name": "mcp-guard", "version": crate::VERSION, "rules": rules } },
                "results": sarif_results,
            }],
        });
        writeln!(out, "{}", serde_json::to_string_pretty(&sarif)?)
    }
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn report_with(category: ResultCategory) -> FuzzReport {
        FuzzReport {
            server_command: "test".to_owned(),
            tools_fuzzed: 1,
            total_payloads: 1,
            results: vec![FuzzResult {
                tool_name: "t".to_owned(),
                probe_name: "p".to_owned(),
                payload_value: json!("x"),
                category,
                rule_id: "shell-injection".to_owned(),
                severity: "info".to_owned(),
                detail: "d".to_owned(),
                response_preview: String::new(),
            }],
        }
    }

    #[test]
    fn json_is_valid_and_has_accepted_bucket() {
        let mut buf = Vec::new();
        report_with(ResultCategory::Accepted)
            .to_json(&mut buf)
            .unwrap();
        let parsed: Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(parsed["summary"]["accepted"], 1);
        assert_eq!(parsed["summary"]["findings"], 0);
    }

    #[test]
    fn sarif_maps_accepted_to_note() {
        let mut buf = Vec::new();
        report_with(ResultCategory::Accepted)
            .to_sarif(&mut buf)
            .unwrap();
        let parsed: Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["results"][0]["level"], "note");
    }

    #[test]
    fn table_renders_clean_verdict() {
        let mut buf = Vec::new();
        report_with(ResultCategory::Safe)
            .to_table(&mut buf)
            .unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("CLEAN"));
    }
}
