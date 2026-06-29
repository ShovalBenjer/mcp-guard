//! Static schema analysis: lightweight heuristics over a tool's declaration, with no payloads
//! sent.

use serde_json::Value;

/// Severity of a static scan finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Likely-dangerous capability.
    Critical,
    /// Worth review.
    Warning,
    /// Informational.
    Info,
}

impl Severity {
    /// Uppercase label used in output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::Warning => "WARNING",
            Self::Info => "INFO",
        }
    }
}

/// A single static finding.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Rule id.
    pub rule_id: String,
    /// Severity.
    pub severity: Severity,
    /// Human-readable message.
    pub message: String,
    /// Tool the finding refers to.
    pub tool_name: String,
    /// Suggested remediation.
    pub remediation: String,
}

const SHELL_KEYWORDS: [&str; 12] = [
    "bash",
    "shell",
    "command",
    "exec",
    "execute",
    "powershell",
    "terminal",
    "cmd",
    "script",
    "run_command",
    "subprocess",
    "eval",
];
const URL_KEYWORDS: [&str; 7] = [
    "url",
    "uri",
    "endpoint",
    "link",
    "href",
    "webhook",
    "callback_url",
];

/// Run all static checks against one tool.
#[must_use]
pub fn scan_tool(tool: &Value) -> Vec<ScanResult> {
    let name = tool
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let desc = tool
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let schema = tool.get("inputSchema");
    let properties = schema
        .and_then(|s| s.get("properties"))
        .and_then(Value::as_object);

    let mut findings = Vec::new();
    findings.extend(check_shell(name, desc, properties));
    findings.extend(check_ssrf(name, properties));
    findings.extend(check_missing_schema(name, schema));
    findings
}

fn check_shell(
    name: &str,
    desc: &str,
    properties: Option<&serde_json::Map<String, Value>>,
) -> Vec<ScanResult> {
    let haystack = format!("{name} {desc}").to_ascii_lowercase();
    if SHELL_KEYWORDS.iter().any(|kw| haystack.contains(kw)) {
        return vec![ScanResult {
            rule_id: "shell-injection".to_owned(),
            severity: Severity::Critical,
            message: format!("Tool '{name}' may accept shell commands — risk of command injection"),
            tool_name: name.to_owned(),
            remediation: "Restrict to predefined commands. Never pass raw user input to a shell."
                .to_owned(),
        }];
    }

    if let Some(props) = properties {
        for (prop_name, prop) in props {
            let prop_desc = prop
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let text = format!("{prop_name} {prop_desc}").to_ascii_lowercase();
            if SHELL_KEYWORDS.iter().any(|kw| text.contains(kw)) {
                return vec![ScanResult {
                    rule_id: "shell-injection".to_owned(),
                    severity: Severity::Critical,
                    message: format!("Parameter '{prop_name}' may accept shell commands"),
                    tool_name: name.to_owned(),
                    remediation: "Use enum constraints or allowlists for command parameters."
                        .to_owned(),
                }];
            }
        }
    }
    Vec::new()
}

fn check_ssrf(name: &str, properties: Option<&serde_json::Map<String, Value>>) -> Vec<ScanResult> {
    let Some(props) = properties else {
        return Vec::new();
    };
    for (prop_name, prop) in props {
        let fmt = prop
            .get("format")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let prop_desc = prop
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let text = format!("{prop_name} {prop_desc}").to_ascii_lowercase();
        let is_url = fmt == "uri" || URL_KEYWORDS.iter().any(|kw| text.contains(kw));
        if is_url {
            let severity = if prop.get("enum").is_some() {
                Severity::Warning
            } else {
                Severity::Critical
            };
            return vec![ScanResult {
                rule_id: "ssrf-risk".to_owned(),
                severity,
                message: format!("Parameter '{prop_name}' accepts URL input — potential SSRF vector"),
                tool_name: name.to_owned(),
                remediation: "Validate the URL scheme (https only). Block private IP ranges. Use an allowlist."
                    .to_owned(),
            }];
        }
    }
    Vec::new()
}

fn check_missing_schema(name: &str, schema: Option<&Value>) -> Vec<ScanResult> {
    let has_properties = schema.and_then(|s| s.get("properties")).is_some();
    if has_properties {
        return Vec::new();
    }
    vec![ScanResult {
        rule_id: "missing-schema".to_owned(),
        severity: Severity::Warning,
        message: "Tool has no input schema — no validation on inputs".to_owned(),
        tool_name: name.to_owned(),
        remediation: "Define an inputSchema with type constraints for all parameters.".to_owned(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn flags_shell_tool_as_critical() {
        let tool = json!({
            "name": "run_bash",
            "description": "Execute a bash command on the server",
            "inputSchema": {"type":"object","properties":{"command":{"type":"string"}}}
        });
        let results = scan_tool(&tool);
        let shell: Vec<_> = results
            .iter()
            .filter(|r| r.rule_id == "shell-injection")
            .collect();
        assert!(!shell.is_empty());
        assert_eq!(shell[0].severity, Severity::Critical);
    }

    #[test]
    fn safe_enum_tool_has_no_critical() {
        let tool = json!({
            "name": "get_weather",
            "description": "Get current weather for a city",
            "inputSchema": {"type":"object","properties":{"city":{"type":"string","enum":["london","nyc"]}}}
        });
        let results = scan_tool(&tool);
        assert!(results.iter().all(|r| r.severity != Severity::Critical));
    }

    #[test]
    fn flags_url_param_as_ssrf() {
        let tool = json!({
            "name": "fetch_url",
            "description": "Fetch content from a URL",
            "inputSchema": {"type":"object","properties":{"url":{"type":"string","format":"uri"}}}
        });
        let results = scan_tool(&tool);
        assert!(results.iter().any(|r| r.rule_id == "ssrf-risk"));
    }
}
