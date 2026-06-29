//! User-supplied payload configuration.
//!
//! Custom payloads and probe toggles can be loaded from a config file. JSON is supported in
//! the default build (it reuses the `serde_json` dependency, so the core install stays lean);
//! YAML is available when the crate is built with the `yaml` feature.
//!
//! ```json
//! {
//!   "payloads": [
//!     { "value": "{{7*7}}", "rule_id": "template-injection", "severity": "high",
//!       "applies_to": ["string"], "evidence": { "contains": "49" } }
//!   ],
//!   "probes": { "disable": ["overflow"] }
//! }
//! ```

use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

use crate::payloads::{Payload, Severity};

/// Errors raised while loading a [`PayloadConfig`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("could not read config {path}: {source}")]
    Read {
        /// Path that failed to load.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The file contents could not be parsed.
    #[error("could not parse config {path}: {message}")]
    Parse {
        /// Path that failed to parse.
        path: String,
        /// Parser message.
        message: String,
    },
    /// The file extension is not a supported format.
    #[error("unsupported config format for {path}: expected .json{}", yaml_hint())]
    UnsupportedFormat {
        /// Path with the unsupported extension.
        path: String,
    },
}

const fn yaml_hint() -> &'static str {
    if cfg!(feature = "yaml") {
        " or .yml/.yaml"
    } else {
        " (build with --features yaml for .yml)"
    }
}

/// A user-defined payload and how to recognize evidence it caused harm.
#[derive(Debug, Clone, Deserialize)]
pub struct PayloadSpec {
    /// The value to send.
    pub value: Value,
    /// Rule id reported for this payload.
    pub rule_id: String,
    /// Severity if the payload yields a finding.
    #[serde(default = "default_severity")]
    pub severity: Severity,
    /// Parameter types this payload applies to (empty = all, including no-schema tools).
    #[serde(default)]
    pub applies_to: Vec<String>,
    /// Optional evidence matcher that promotes an accepted response to a finding.
    #[serde(default)]
    pub evidence: Option<Evidence>,
}

const fn default_severity() -> Severity {
    Severity::High
}

/// A simple substring matcher used to recognize a leak in a response body.
#[derive(Debug, Clone, Deserialize)]
pub struct Evidence {
    /// If the response contains this substring, the result is a finding.
    pub contains: String,
}

/// Probe-selection toggles.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProbeConfig {
    /// Built-in probe categories to disable (e.g. `["overflow"]`).
    #[serde(default)]
    pub disable: Vec<String>,
}

/// A loaded payload configuration. The default value adds nothing to the built-in set.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PayloadConfig {
    /// User-defined payloads.
    #[serde(default)]
    pub payloads: Vec<PayloadSpec>,
    /// Probe toggles.
    #[serde(default)]
    pub probes: ProbeConfig,
}

impl PayloadConfig {
    /// Load a config from a file, dispatching on the extension.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let display = path.display().to_string();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: display.clone(),
            source,
        })?;
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        match ext.as_str() {
            "json" => Self::from_json(&text, &display),
            #[cfg(feature = "yaml")]
            "yml" | "yaml" => serde_yaml::from_str(&text).map_err(|e| ConfigError::Parse {
                path: display,
                message: e.to_string(),
            }),
            _ => Err(ConfigError::UnsupportedFormat { path: display }),
        }
    }

    fn from_json(text: &str, path: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(text).map_err(|e| ConfigError::Parse {
            path: path.to_owned(),
            message: e.to_string(),
        })
    }

    /// Whether a built-in probe category is disabled by this config.
    #[must_use]
    pub fn is_disabled(&self, rule_id: &str) -> bool {
        self.probes.disable.iter().any(|d| d == rule_id)
    }

    /// Custom payloads that apply to a parameter of the given type. `param_type` is `None`
    /// for no-schema tools; specs with an empty `applies_to` always apply.
    #[must_use]
    pub fn custom_for(&self, param_type: Option<&str>) -> Vec<Payload> {
        self.payloads
            .iter()
            .filter(|spec| {
                spec.applies_to.is_empty()
                    || param_type.is_some_and(|t| spec.applies_to.iter().any(|a| a == t))
            })
            .map(|spec| Payload {
                value: spec.value.clone(),
                rule_id: spec.rule_id.clone(),
                severity: spec.severity,
                description: "custom payload".to_owned(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_and_filters_by_type() {
        let cfg = PayloadConfig::from_json(
            r#"{"payloads":[
                {"value":"{{7*7}}","rule_id":"tmpl","severity":"high","applies_to":["string"]},
                {"value":1,"rule_id":"any","severity":"low"}
            ],"probes":{"disable":["overflow"]}}"#,
            "<test>",
        )
        .expect("valid config");

        assert!(cfg.is_disabled("overflow"));
        assert!(!cfg.is_disabled("ssrf"));

        let for_string = cfg.custom_for(Some("string"));
        assert_eq!(
            for_string.len(),
            2,
            "string param gets the typed and the untyped payload"
        );

        let for_integer = cfg.custom_for(Some("integer"));
        assert_eq!(
            for_integer.len(),
            1,
            "integer param gets only the untyped payload"
        );

        let no_schema = cfg.custom_for(None);
        assert_eq!(
            no_schema.len(),
            1,
            "no-schema tools get untyped payloads only"
        );
    }

    #[test]
    fn empty_config_adds_nothing() {
        let cfg = PayloadConfig::default();
        assert!(cfg.custom_for(Some("string")).is_empty());
        assert!(!cfg.is_disabled("shell-injection"));
    }
}
