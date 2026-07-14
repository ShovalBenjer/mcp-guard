//! Diff two fuzz JSON reports to surface newly-introduced and resolved results.
//!
//! A "new" result is present in the current report but not the baseline (e.g. a payload the
//! server used to reject is now accepted); a "resolved" result is the reverse. Because the JSON
//! report omits rejected (safe) results, a `REJECTED → ACCEPTED` regression naturally shows up
//! as a new accepted entry, and a fix shows up as resolved.

use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{self, Write};

use serde_json::{Value, json};

/// One non-safe result parsed from a fuzz JSON report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Tool name.
    pub tool: String,
    /// Parameter / probe name.
    pub probe: String,
    /// Rule id.
    pub rule_id: String,
    /// Result category (`crash` / `finding` / `accepted` / `error`).
    pub category: String,
    /// The payload, rendered for display and identity.
    pub payload: String,
}

impl Entry {
    /// A stable identity for the result. Payloads are hashed so a 1&nbsp;MB overflow string
    /// doesn't bloat the key while still distinguishing sizes.
    fn key(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.payload.hash(&mut hasher);
        format!(
            "{}|{}|{}|{}|{:x}",
            self.tool,
            self.probe,
            self.rule_id,
            self.category,
            hasher.finish()
        )
    }
}

/// Parse the `results` array of a fuzz JSON report into entries.
#[must_use]
pub fn parse_report(report: &Value) -> Vec<Entry> {
    report
        .get("results")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|r| Entry {
                    tool: str_field(r, "tool"),
                    probe: str_field(r, "probe"),
                    rule_id: str_field(r, "rule_id"),
                    category: str_field(r, "category"),
                    payload: r
                        .get("payload")
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// New and resolved results between a baseline and a current report.
#[derive(Debug, Default)]
pub struct Diff {
    /// Present in current, absent from baseline.
    pub new: Vec<Entry>,
    /// Present in baseline, absent from current.
    pub resolved: Vec<Entry>,
}

impl Diff {
    /// Count of new results in the given category.
    #[must_use]
    pub fn new_in(&self, category: &str) -> usize {
        self.new.iter().filter(|e| e.category == category).count()
    }

    /// Render a human-readable table.
    pub fn to_table(&self, out: &mut impl Write) -> io::Result<()> {
        writeln!(
            out,
            "\nmcp-guard diff: {} new, {} resolved",
            self.new.len(),
            self.resolved.len()
        )?;
        writeln!(
            out,
            "  new — crashes: {}, findings: {}, accepted: {}",
            self.new_in("crash"),
            self.new_in("finding"),
            self.new_in("accepted")
        )?;
        write_entries_table(out, "NEW", &self.new)?;
        write_entries_table(out, "RESOLVED", &self.resolved)
    }

    /// Render Markdown suitable for a PR comment.
    pub fn to_markdown(&self, out: &mut impl Write) -> io::Result<()> {
        writeln!(out, "## mcp-guard diff\n")?;
        writeln!(
            out,
            "**{} new** (crashes {}, findings {}, accepted {}) · **{} resolved**\n",
            self.new.len(),
            self.new_in("crash"),
            self.new_in("finding"),
            self.new_in("accepted"),
            self.resolved.len()
        )?;
        write_entries_md(out, "New", &self.new)?;
        write_entries_md(out, "Resolved", &self.resolved)
    }

    /// Render machine-readable JSON.
    pub fn to_json(&self, out: &mut impl Write) -> io::Result<()> {
        let doc = json!({
            "summary": {
                "new": self.new.len(),
                "resolved": self.resolved.len(),
                "new_crashes": self.new_in("crash"),
                "new_findings": self.new_in("finding"),
                "new_accepted": self.new_in("accepted"),
            },
            "new": self.new.iter().map(entry_json).collect::<Vec<_>>(),
            "resolved": self.resolved.iter().map(entry_json).collect::<Vec<_>>(),
        });
        writeln!(out, "{}", serde_json::to_string_pretty(&doc)?)
    }
}

fn entry_json(e: &Entry) -> Value {
    json!({ "tool": e.tool, "probe": e.probe, "rule_id": e.rule_id, "category": e.category })
}

fn write_entries_table(out: &mut impl Write, title: &str, entries: &[Entry]) -> io::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    writeln!(out, "\n  {title}:")?;
    for e in entries {
        writeln!(
            out,
            "    [{}] {} :: {} ({})",
            e.category.to_uppercase(),
            e.tool,
            e.rule_id,
            e.probe
        )?;
    }
    Ok(())
}

fn write_entries_md(out: &mut impl Write, title: &str, entries: &[Entry]) -> io::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    writeln!(out, "### {title}\n")?;
    writeln!(out, "| Category | Tool | Rule | Probe |")?;
    writeln!(out, "|---|---|---|---|")?;
    for e in entries {
        writeln!(
            out,
            "| {} | `{}` | {} | {} |",
            e.category.to_uppercase(),
            e.tool,
            e.rule_id,
            e.probe
        )?;
    }
    writeln!(out)
}

/// Compute the new/resolved diff between baseline and current entries.
#[must_use]
pub fn diff(baseline: &[Entry], current: &[Entry]) -> Diff {
    let base_keys: HashSet<String> = baseline.iter().map(Entry::key).collect();
    let cur_keys: HashSet<String> = current.iter().map(Entry::key).collect();
    Diff {
        new: current
            .iter()
            .filter(|e| !base_keys.contains(&e.key()))
            .cloned()
            .collect(),
        resolved: baseline
            .iter()
            .filter(|e| !cur_keys.contains(&e.key()))
            .cloned()
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(rows: &Value) -> Value {
        json!({ "results": rows })
    }

    #[test]
    fn detects_new_and_resolved() {
        let baseline = parse_report(&report(&json!([
            {"tool":"a","probe":"x","rule_id":"shell-injection","category":"finding","payload":"p1"}
        ])));
        let current = parse_report(&report(&json!([
            {"tool":"a","probe":"x","rule_id":"shell-injection","category":"finding","payload":"p1"},
            {"tool":"b","probe":"y","rule_id":"overflow","category":"crash","payload":"p2"}
        ])));

        let d = diff(&baseline, &current);
        assert_eq!(d.new.len(), 1, "the crash on tool b is new");
        assert_eq!(d.new_in("crash"), 1);
        assert!(d.resolved.is_empty(), "the shared finding is unchanged");
    }

    #[test]
    fn rejected_to_accepted_is_a_new_entry() {
        // Baseline had no entry (the payload was rejected → absent from JSON).
        let baseline = parse_report(&report(&json!([])));
        let current = parse_report(&report(&json!([
            {"tool":"a","probe":"x","rule_id":"ssrf","category":"accepted","payload":"p"}
        ])));
        let d = diff(&baseline, &current);
        assert_eq!(d.new_in("accepted"), 1);
    }

    #[test]
    fn resolved_when_current_drops_a_result() {
        let baseline = parse_report(&report(&json!([
            {"tool":"a","probe":"x","rule_id":"ssrf","category":"finding","payload":"p"}
        ])));
        let current = parse_report(&report(&json!([])));
        let d = diff(&baseline, &current);
        assert_eq!(d.resolved.len(), 1);
        assert_eq!(d.new.len(), 0);
    }
}
