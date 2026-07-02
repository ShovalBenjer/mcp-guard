//! The fuzz engine: payload delivery and honest response classification.

use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

use crate::config::PayloadConfig;
use crate::payloads::{self, Payload, param_type};

/// How talking to the server can fail.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The connection to the server was lost (treated as a crash).
    #[error("connection to server lost")]
    ConnectionLost,
    /// The server returned a protocol-level error, or a malformed message.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// An I/O error occurred while spawning or talking to the server.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// A connection to an MCP server that can enumerate and invoke its tools.
pub trait Transport {
    /// Invoke `tool_name` with `arguments` and return the JSON-RPC `result`.
    fn call_tool(&mut self, tool_name: &str, arguments: Value) -> Result<Value, TransportError>;

    /// List the tools the server exposes. The default returns an empty list (used by test
    /// doubles); real transports override it.
    fn list_tools(&mut self) -> Result<Vec<Value>, TransportError> {
        Ok(Vec::new())
    }

    /// Re-establish the connection after a crash so fuzzing can continue.
    ///
    /// The default implementation reports that reconnection is unsupported; transports that can
    /// respawn their server (e.g. [`crate::transport::StdioTransport`]) override it.
    fn reconnect(&mut self) -> Result<(), TransportError> {
        Err(TransportError::Protocol(
            "reconnect not supported".to_owned(),
        ))
    }
}

/// The outcome bucket for a single payload.
///
/// The distinction between [`Self::Accepted`] and [`Self::Finding`] is the heart of the tool:
/// a normal, non-error response is *not* a vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultCategory {
    /// Server returned an error for the payload — the desired behavior.
    Safe,
    /// Server accepted the payload with no evidence of harm — informational.
    Accepted,
    /// Server accepted the payload *and* the response shows concrete evidence of harm.
    Finding,
    /// Server crashed or dropped the connection after the payload.
    Crash,
    /// A client-side error occurred talking to the server.
    Error,
}

impl ResultCategory {
    /// The lowercase string form used in reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Accepted => "accepted",
            Self::Finding => "finding",
            Self::Crash => "crash",
            Self::Error => "error",
        }
    }
}

/// The result of firing one payload at one parameter.
#[derive(Debug, Clone)]
pub struct FuzzResult {
    /// Tool that was fuzzed.
    pub tool_name: String,
    /// Parameter (or probe name for no-schema tools).
    pub probe_name: String,
    /// The payload value sent.
    pub payload_value: Value,
    /// Classification of the response.
    pub category: ResultCategory,
    /// Rule id (probe category, possibly suffixed with the evidence kind).
    pub rule_id: String,
    /// Severity string.
    pub severity: String,
    /// Human-readable detail.
    pub detail: String,
    /// Truncated preview of the response body.
    pub response_preview: String,
}

/// The outcome of fuzzing a whole server with [`FuzzEngine::fuzz_server`].
#[derive(Debug)]
pub struct ServerFuzzOutcome {
    /// One entry per payload fired across all tools reached.
    pub results: Vec<FuzzResult>,
    /// Number of tools actually fuzzed (may be fewer than requested if the run aborted).
    pub tools_fuzzed: usize,
    /// Whether the run stopped early because the server crashed and could not be reconnected.
    pub aborted: bool,
}

/// Drives payloads at a server's tools and classifies the responses.
///
/// The engine is a stateless holder of configuration; [`Self::fuzz_tool`] borrows the
/// transport so the caller retains ownership (e.g. to enumerate tools first).
pub struct FuzzEngine {
    delay: Duration,
    config: PayloadConfig,
    safe: bool,
}

impl FuzzEngine {
    /// Create an engine with the given inter-payload delay (milliseconds) and default config.
    #[must_use]
    pub fn new(delay_ms: u64) -> Self {
        Self {
            delay: Duration::from_millis(delay_ms),
            config: PayloadConfig::default(),
            safe: false,
        }
    }

    /// Attach a custom payload configuration.
    #[must_use]
    pub fn with_config(mut self, config: PayloadConfig) -> Self {
        self.config = config;
        self
    }

    /// Enable safe mode (caps destructive/oversized payloads).
    #[must_use]
    pub const fn with_safe_mode(mut self, safe: bool) -> Self {
        self.safe = safe;
        self
    }

    /// Fuzz every tool, recovering from crashes so one crashing tool does not abort the run.
    ///
    /// When a tool crashes the server, the transport is reconnected before the next tool. If
    /// reconnection fails, fuzzing stops and [`ServerFuzzOutcome::aborted`] is set — the results
    /// gathered so far are still returned.
    ///
    /// `on_tool` is invoked with each tool's name just before it is fuzzed, for progress reporting.
    pub fn fuzz_server(
        &self,
        transport: &mut dyn Transport,
        tools: &[Value],
        mut on_tool: impl FnMut(&str),
    ) -> ServerFuzzOutcome {
        let mut results = Vec::new();
        let mut tools_fuzzed = 0;
        for tool in tools {
            let name = tool
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            on_tool(name);
            let tool_results = self.fuzz_tool(transport, tool);
            let crashed = tool_results
                .iter()
                .any(|r| r.category == ResultCategory::Crash);
            results.extend(tool_results);
            tools_fuzzed += 1;

            if crashed && transport.reconnect().is_err() {
                return ServerFuzzOutcome {
                    results,
                    tools_fuzzed,
                    aborted: true,
                };
            }
        }
        ServerFuzzOutcome {
            results,
            tools_fuzzed,
            aborted: false,
        }
    }

    /// Fuzz a single tool, returning one result per payload fired.
    pub fn fuzz_tool(&self, transport: &mut dyn Transport, tool: &Value) -> Vec<FuzzResult> {
        let tool_name = tool
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        let properties = tool
            .get("inputSchema")
            .and_then(|s| s.get("properties"))
            .and_then(Value::as_object);

        match properties {
            Some(props) if !props.is_empty() => {
                let mut results = Vec::new();
                for (param_name, param_schema) in props {
                    for payload in self.payloads_for(param_name, param_schema) {
                        results.push(self.fire(transport, &tool_name, param_name, &payload));
                    }
                }
                results
            }
            _ => self
                .payloads_no_schema()
                .iter()
                .map(|p| {
                    let probe = p.rule_id.clone();
                    self.fire(transport, &tool_name, &probe, p)
                })
                .collect(),
        }
    }

    fn payloads_for(&self, name: &str, schema: &Value) -> Vec<Payload> {
        let mut payloads: Vec<Payload> = payloads::generate_for_param(name, schema, self.safe)
            .into_iter()
            .filter(|p| !self.config.is_disabled(&p.rule_id))
            .collect();
        payloads.extend(self.config.custom_for(Some(&param_type(schema))));
        payloads
    }

    fn payloads_no_schema(&self) -> Vec<Payload> {
        let mut payloads: Vec<Payload> = payloads::generate_no_schema(self.safe)
            .into_iter()
            .filter(|p| !self.config.is_disabled(&p.rule_id))
            .collect();
        payloads.extend(self.config.custom_for(None));
        payloads
    }

    fn fire(
        &self,
        transport: &mut dyn Transport,
        tool_name: &str,
        probe_name: &str,
        payload: &Payload,
    ) -> FuzzResult {
        if !self.delay.is_zero() {
            thread::sleep(self.delay);
        }
        let args = json!({ probe_name: payload.value });
        match transport.call_tool(tool_name, args) {
            Ok(response) => classify(tool_name, probe_name, payload, &response, &self.config),
            Err(TransportError::ConnectionLost) => FuzzResult {
                tool_name: tool_name.to_owned(),
                probe_name: probe_name.to_owned(),
                payload_value: payload.value.clone(),
                category: ResultCategory::Crash,
                rule_id: payload.rule_id.clone(),
                severity: payload.severity.as_str().to_owned(),
                detail: "Server crashed or connection lost after payload".to_owned(),
                response_preview: String::new(),
            },
            Err(err) => FuzzResult {
                tool_name: tool_name.to_owned(),
                probe_name: probe_name.to_owned(),
                payload_value: payload.value.clone(),
                category: ResultCategory::Error,
                rule_id: payload.rule_id.clone(),
                severity: payload.severity.as_str().to_owned(),
                detail: format!("Unexpected error: {err}"),
                response_preview: String::new(),
            },
        }
    }
}

/// Classify a non-failing response.
fn classify(
    tool_name: &str,
    probe_name: &str,
    payload: &Payload,
    response: &Value,
    config: &PayloadConfig,
) -> FuzzResult {
    let is_error = response
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let text = response_text(response);
    let preview: String = text.chars().take(200).collect();

    let base =
        |category: ResultCategory, rule_id: String, severity: &str, detail: String| FuzzResult {
            tool_name: tool_name.to_owned(),
            probe_name: probe_name.to_owned(),
            payload_value: payload.value.clone(),
            category,
            rule_id,
            severity: severity.to_owned(),
            detail,
            response_preview: preview.clone(),
        };

    if is_error {
        return base(
            ResultCategory::Safe,
            payload.rule_id.clone(),
            payload.severity.as_str(),
            "Server rejected payload (expected error)".to_owned(),
        );
    }

    // A non-error response is not a vulnerability on its own. Escalate only with evidence.
    if let Some(kind) = detect_leak(&text) {
        return base(
            ResultCategory::Finding,
            format!("{}-{kind}", payload.rule_id),
            "high",
            format!("Payload accepted and response leaks sensitive data ({kind})"),
        );
    }

    // A user-supplied evidence matcher can also promote to a finding.
    if let Some(spec) = config
        .payloads
        .iter()
        .find(|s| s.rule_id == payload.rule_id && s.evidence.is_some())
    {
        if let Some(ev) = &spec.evidence {
            if text.contains(&ev.contains) {
                return base(
                    ResultCategory::Finding,
                    format!("{}-evidence", payload.rule_id),
                    payload.severity.as_str(),
                    format!(
                        "Payload accepted and response matched evidence \"{}\"",
                        ev.contains
                    ),
                );
            }
        }
    }

    base(
        ResultCategory::Accepted,
        payload.rule_id.clone(),
        "info",
        "Payload accepted without error — input not rejected (no evidence of harm)".to_owned(),
    )
}

fn response_text(response: &Value) -> String {
    response
        .get("content")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|c| c.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

/// Return a leak label if `text` contains concrete evidence of a leak. Deliberately
/// conservative: a normal response is never a leak.
fn detect_leak(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("traceback (most recent call last)") {
        return Some("stack-trace");
    }
    if text.contains("    at ")
        && text.contains('(')
        && text.contains(": ")
        && lower.contains("error")
    {
        return Some("stack-trace");
    }
    if text.contains("root:") && text.contains(":0:0:") {
        return Some("etc-passwd");
    }
    if text.contains("-----BEGIN") && text.contains("PRIVATE KEY-----") {
        return Some("private-key");
    }
    if lower.contains("iam/security-credentials")
        || lower.contains("ami-id")
        || lower.contains("instance-id")
    {
        return Some("aws-metadata");
    }
    if contains_aws_key(text) {
        return Some("aws-secret");
    }
    None
}

/// Detect an `AKIA` access-key id (`AKIA` + 16 uppercase alphanumerics) without a regex dep.
fn contains_aws_key(text: &str) -> bool {
    text.match_indices("AKIA").any(|(i, _)| {
        let tail = &text[i + 4..];
        tail.chars()
            .take(16)
            .filter(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            .count()
            == 16
            && tail
                .chars()
                .nth(16)
                .is_none_or(|c| !(c.is_ascii_uppercase() || c.is_ascii_digit()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake transport that returns a fixed response (or simulates a crash).
    struct FakeTransport {
        crashed: bool,
        reject_all: bool,
        leak: Option<String>,
        calls: usize,
    }

    impl FakeTransport {
        const fn new() -> Self {
            Self {
                crashed: false,
                reject_all: false,
                leak: None,
                calls: 0,
            }
        }
    }

    impl Transport for FakeTransport {
        fn call_tool(&mut self, _t: &str, _a: Value) -> Result<Value, TransportError> {
            self.calls += 1;
            if self.crashed {
                return Err(TransportError::ConnectionLost);
            }
            if self.reject_all {
                return Ok(
                    json!({"isError": true, "content": [{"type":"text","text":"rejected"}]}),
                );
            }
            let text = self.leak.clone().unwrap_or_else(|| "ok".to_owned());
            Ok(json!({"content": [{"type":"text","text": text}]}))
        }
    }

    fn string_tool() -> Value {
        json!({
            "name": "t",
            "inputSchema": {"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}
        })
    }

    #[test]
    fn fuzzes_and_calls_the_tool() {
        let mut t = FakeTransport::new();
        let results = FuzzEngine::new(0).fuzz_tool(&mut t, &string_tool());
        assert!(!results.is_empty());
        assert!(t.calls > 0);
    }

    #[test]
    fn normal_response_is_accepted_not_finding() {
        let mut t = FakeTransport::new();
        let results = FuzzEngine::new(0).fuzz_tool(&mut t, &string_tool());
        assert!(
            results
                .iter()
                .all(|r| r.category != ResultCategory::Finding)
        );
        assert!(
            results
                .iter()
                .any(|r| r.category == ResultCategory::Accepted)
        );
    }

    #[test]
    fn rejected_payloads_are_safe() {
        let mut t = FakeTransport::new();
        t.reject_all = true;
        let results = FuzzEngine::new(0).fuzz_tool(&mut t, &string_tool());
        assert!(results.iter().all(|r| r.category == ResultCategory::Safe));
    }

    #[test]
    fn crash_is_detected() {
        let mut t = FakeTransport::new();
        t.crashed = true;
        let results = FuzzEngine::new(0).fuzz_tool(&mut t, &string_tool());
        assert!(results.iter().any(|r| r.category == ResultCategory::Crash));
    }

    #[test]
    fn leaked_etc_passwd_is_a_finding() {
        let mut t = FakeTransport::new();
        t.leak = Some("root:x:0:0:root:/root:/bin/bash".to_owned());
        let results = FuzzEngine::new(0).fuzz_tool(&mut t, &string_tool());
        let findings: Vec<_> = results
            .iter()
            .filter(|r| r.category == ResultCategory::Finding)
            .collect();
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|r| r.severity == "high"));
    }

    #[test]
    fn detect_leak_ignores_benign_text() {
        assert!(detect_leak("here is your token and a secret internal value").is_none());
        assert!(detect_leak("AKIAIOSFODNN7EXAMPLE").is_some());
    }

    /// A transport that crashes on the first call, then heals after a reconnect.
    struct CrashOnceTransport {
        alive: bool,
        reconnects: usize,
    }

    impl Transport for CrashOnceTransport {
        fn call_tool(&mut self, _t: &str, _a: Value) -> Result<Value, TransportError> {
            if self.alive {
                Ok(json!({"content": [{"type":"text","text":"ok"}]}))
            } else {
                Err(TransportError::ConnectionLost)
            }
        }
        fn reconnect(&mut self) -> Result<(), TransportError> {
            self.reconnects += 1;
            self.alive = true;
            Ok(())
        }
    }

    #[test]
    fn fuzz_server_recovers_from_a_crash_and_continues() {
        let mut t = CrashOnceTransport {
            alive: false,
            reconnects: 0,
        };
        let tools = vec![string_tool(), string_tool()];
        let outcome = FuzzEngine::new(0).fuzz_server(&mut t, &tools, |_| {});

        assert!(
            !outcome.aborted,
            "reconnect succeeded, so the run should not abort"
        );
        assert_eq!(outcome.tools_fuzzed, 2, "both tools should be reached");
        assert_eq!(
            t.reconnects, 1,
            "the crash should trigger exactly one reconnect"
        );
        // First tool crashed; second tool (post-reconnect) was accepted.
        assert!(
            outcome
                .results
                .iter()
                .any(|r| r.category == ResultCategory::Crash)
        );
        assert!(
            outcome
                .results
                .iter()
                .any(|r| r.category == ResultCategory::Accepted)
        );
    }

    /// A transport that stays dead and cannot reconnect.
    struct DeadTransport;

    impl Transport for DeadTransport {
        fn call_tool(&mut self, _t: &str, _a: Value) -> Result<Value, TransportError> {
            Err(TransportError::ConnectionLost)
        }
    }

    #[test]
    fn fuzz_server_aborts_when_reconnect_is_unsupported() {
        let mut t = DeadTransport;
        let tools = vec![string_tool(), string_tool(), string_tool()];
        let outcome = FuzzEngine::new(0).fuzz_server(&mut t, &tools, |_| {});

        assert!(
            outcome.aborted,
            "an unrecoverable crash should abort the run"
        );
        assert_eq!(
            outcome.tools_fuzzed, 1,
            "the run should stop after the first crashing tool"
        );
    }
}
