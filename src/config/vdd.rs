use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

use super::default_true;

const MAX_VDD_ITERATIONS: u32 = 8;
const MAX_VDD_MODEL_OUTPUT_TOKENS: u32 = 32 * 1024;
const MAX_VDD_REVIEW_TIMEOUT_SECONDS: u64 = 10 * 60;
const MAX_VDD_STATIC_COMMANDS: usize = 16;
const MAX_VDD_STATIC_COMMAND_BYTES: usize = 4 * 1024;
const MAX_VDD_STATIC_TIMEOUT_SECONDS: u64 = 10 * 60;
const MAX_VDD_EVIDENCE_RETENTION_DAYS: u64 = 10 * 365;

/// VDD operating mode
#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VddMode {
    /// Adversary findings injected as context for next turn
    #[default]
    Advisory,
    /// Response held until adversary passes or loop converges
    Blocking,
}

impl fmt::Display for VddMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Advisory => write!(f, "advisory"),
            Self::Blocking => write!(f, "blocking"),
        }
    }
}

/// Top-level VDD configuration
#[derive(Debug, Deserialize, Clone)]
pub struct VddConfig {
    /// Enable VDD adversarial loop (default: false)
    #[serde(default)]
    pub enabled: bool,
    /// Operating mode: advisory or blocking
    #[serde(default)]
    pub mode: VddMode,
    /// Adversary model configuration (must be different provider than builder)
    #[serde(default)]
    pub adversary: VddAdversaryConfig,
    /// Convergence thresholds
    #[serde(default)]
    pub thresholds: VddThresholds,
    /// Static analysis commands to run as part of the loop
    #[serde(default)]
    pub static_analysis: VddStaticAnalysis,
    /// Persistence and logging
    #[serde(default)]
    pub tracking: VddTracking,
}

impl Default for VddConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: VddMode::Advisory,
            adversary: VddAdversaryConfig::default(),
            thresholds: VddThresholds::default(),
            static_analysis: VddStaticAnalysis::default(),
            tracking: VddTracking::default(),
        }
    }
}

/// Adversary model configuration
#[derive(Debug, Deserialize, Clone)]
pub struct VddAdversaryConfig {
    /// Provider name (must differ from proxy.target)
    #[serde(default = "default_adversary_provider")]
    pub provider: String,
    /// Model override for adversary (uses provider default if None)
    #[serde(default)]
    pub model: Option<String>,
    /// Separate API key for adversary (falls back to provider's key if None).
    /// Uses the [`crate::providers::ApiKey`] newtype so Debug/Display redact
    /// and CRLF-injection is rejected at config load — see crosslink #256.
    #[serde(default)]
    pub api_key: Option<crate::providers::ApiKey>,
    /// Temperature for adversary responses (lower = more deterministic critique)
    #[serde(default = "default_adversary_temperature")]
    pub temperature: f32,
    /// Max output tokens for adversary responses
    #[serde(default = "default_adversary_max_tokens")]
    pub max_tokens: u32,
    /// Aggregate timeout for the complete VDD review, in seconds.
    ///
    /// Guards against a hung or slow adversary provider blocking the
    /// entire VDD loop (blocking mode holds the user's request
    /// hostage). Default: 120 s — generous enough for reasoning-heavy
    /// models, short enough to fail fast when the provider is down.
    /// See crosslink #496.
    #[serde(default = "default_adversary_request_timeout_seconds")]
    pub request_timeout_seconds: u64,
}

fn default_adversary_provider() -> String {
    "google".to_string()
}

const fn default_adversary_temperature() -> f32 {
    0.3
}

const fn default_adversary_max_tokens() -> u32 {
    4096
}

const fn default_adversary_request_timeout_seconds() -> u64 {
    120
}

impl Default for VddAdversaryConfig {
    fn default() -> Self {
        Self {
            provider: default_adversary_provider(),
            model: None,
            api_key: None,
            temperature: default_adversary_temperature(),
            max_tokens: default_adversary_max_tokens(),
            request_timeout_seconds: default_adversary_request_timeout_seconds(),
        }
    }
}

/// Convergence and termination thresholds
#[derive(Debug, Deserialize, Clone)]
pub struct VddThresholds {
    /// Maximum adversarial loop iterations before forced termination
    #[serde(default = "default_max_iterations")]
    pub max_iterations: u32,
    /// False positive rate threshold for confabulation detection (0.0-1.0)
    #[serde(default = "default_fp_threshold")]
    pub false_positive_rate: f32,
    /// Minimum iterations before checking confabulation threshold
    #[serde(default = "default_min_iterations")]
    pub min_iterations: u32,
}

const fn default_max_iterations() -> u32 {
    5
}

const fn default_fp_threshold() -> f32 {
    0.75
}

const fn default_min_iterations() -> u32 {
    2
}

impl Default for VddThresholds {
    fn default() -> Self {
        Self {
            max_iterations: default_max_iterations(),
            false_positive_rate: default_fp_threshold(),
            min_iterations: default_min_iterations(),
        }
    }
}

/// Static analysis commands run as part of the adversarial loop
#[derive(Debug, Deserialize, Clone)]
pub struct VddStaticAnalysis {
    /// Enable static analysis in the loop
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Auto-detect project language and use default analysis commands
    /// Only used when `commands` is empty. Default: true.
    #[serde(default = "default_true")]
    pub auto_detect: bool,
    /// Shell commands to run (exit code 0 = pass)
    /// If empty and `auto_detect` is true, commands are auto-detected from project type.
    #[serde(default)]
    pub commands: Vec<String>,
    /// Timeout per command in seconds
    #[serde(default = "default_analysis_timeout")]
    pub timeout_seconds: u64,
}

const fn default_analysis_timeout() -> u64 {
    120
}

impl Default for VddStaticAnalysis {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_detect: true,
            commands: Vec::new(),
            timeout_seconds: default_analysis_timeout(),
        }
    }
}

impl VddStaticAnalysis {
    pub(crate) const MAX_COMMANDS: usize = MAX_VDD_STATIC_COMMANDS;
}

/// VDD evidence persistence, issue projection, and diagnostic logging.
#[derive(Debug, Deserialize, Clone)]
pub struct VddTracking {
    /// Persist redacted, resumable VDD evidence to disk.
    #[serde(default = "default_true")]
    pub persist: bool,
    /// Directory for the descriptor-safe evidence ledger.
    #[serde(default = "default_vdd_path")]
    pub path: PathBuf,
    /// Project checked unresolved findings into Crosslink issues.
    ///
    /// This is host configuration, never a model-selected action. Promotion
    /// requires persistence so retries can reconcile partial external state.
    #[serde(default = "default_true")]
    pub promote_verified_findings: bool,
    /// Days before retained prose is redacted while bindings and status
    /// history remain as tombstone evidence.
    #[serde(default = "default_evidence_retention_days")]
    pub retention_days: u64,
    /// Log a bounded adversary response preview (verbose and sensitive).
    #[serde(default)]
    pub log_adversary_responses: bool,
}

fn default_vdd_path() -> PathBuf {
    PathBuf::from(".openclaudia/vdd")
}

const fn default_evidence_retention_days() -> u64 {
    30
}

impl Default for VddTracking {
    fn default() -> Self {
        Self {
            persist: true,
            path: default_vdd_path(),
            promote_verified_findings: true,
            retention_days: default_evidence_retention_days(),
            log_adversary_responses: false,
        }
    }
}

impl VddConfig {
    /// Validate VDD settings that do not depend on the active builder provider.
    ///
    /// # Errors
    ///
    /// Returns an error if thresholds or adversary request parameters are invalid.
    pub fn validate_settings(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        self.validate_non_provider_settings()
    }

    /// Validate VDD configuration. Returns error message if invalid.
    ///
    /// # Errors
    ///
    /// Returns an error if the adversary provider is the same as the builder,
    /// or if required configuration fields are missing.
    pub fn validate(&self, builder_provider: &str) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        // Adversary must use different provider than builder
        if self.adversary.provider.to_lowercase() == builder_provider.to_lowercase() {
            return Err(format!(
                "VDD adversary provider '{}' must differ from builder provider '{}'. \
                 Using the same model to review its own output defeats the purpose of adversarial review.",
                self.adversary.provider, builder_provider
            ));
        }

        self.validate_non_provider_settings()
    }

    fn validate_non_provider_settings(&self) -> Result<(), String> {
        if self.tracking.persist && self.tracking.path.as_os_str().is_empty() {
            return Err("VDD evidence persistence path cannot be empty".to_string());
        }
        if self.tracking.promote_verified_findings && !self.tracking.persist {
            return Err(
                "VDD Crosslink promotion requires evidence persistence for retry-safe reconciliation"
                    .to_string(),
            );
        }
        if self.tracking.retention_days > MAX_VDD_EVIDENCE_RETENTION_DAYS {
            return Err(format!(
                "VDD evidence retention cannot exceed {MAX_VDD_EVIDENCE_RETENTION_DAYS} days, got {}",
                self.tracking.retention_days
            ));
        }
        if !self.thresholds.false_positive_rate.is_finite()
            || self.thresholds.false_positive_rate < 0.0
            || self.thresholds.false_positive_rate > 1.0
        {
            return Err(format!(
                "VDD false_positive_rate must be between 0.0 and 1.0, got {}",
                self.thresholds.false_positive_rate
            ));
        }

        if self.thresholds.min_iterations > self.thresholds.max_iterations {
            return Err(format!(
                "VDD min_iterations ({}) cannot exceed max_iterations ({})",
                self.thresholds.min_iterations, self.thresholds.max_iterations
            ));
        }

        if self.thresholds.max_iterations == 0 {
            return Err("VDD max_iterations must be at least 1".to_string());
        }

        if self.thresholds.max_iterations > MAX_VDD_ITERATIONS {
            return Err(format!(
                "VDD max_iterations cannot exceed {MAX_VDD_ITERATIONS}, got {}",
                self.thresholds.max_iterations
            ));
        }

        // Temperature validation
        if !self.adversary.temperature.is_finite()
            || self.adversary.temperature < 0.0
            || self.adversary.temperature > 2.0
        {
            return Err(format!(
                "VDD adversary temperature must be between 0.0 and 2.0, got {}",
                self.adversary.temperature
            ));
        }

        if self.adversary.max_tokens == 0 || self.adversary.max_tokens > MAX_VDD_MODEL_OUTPUT_TOKENS
        {
            return Err(format!(
                "VDD adversary max_tokens must be between 1 and {MAX_VDD_MODEL_OUTPUT_TOKENS}, got {}",
                self.adversary.max_tokens
            ));
        }

        if self.adversary.request_timeout_seconds == 0
            || self.adversary.request_timeout_seconds > MAX_VDD_REVIEW_TIMEOUT_SECONDS
        {
            return Err(format!(
                "VDD review timeout must be between 1 and {MAX_VDD_REVIEW_TIMEOUT_SECONDS} seconds, got {}",
                self.adversary.request_timeout_seconds
            ));
        }

        if self.static_analysis.timeout_seconds == 0
            || self.static_analysis.timeout_seconds > MAX_VDD_STATIC_TIMEOUT_SECONDS
        {
            return Err(format!(
                "VDD static-analysis timeout must be between 1 and {MAX_VDD_STATIC_TIMEOUT_SECONDS} seconds, got {}",
                self.static_analysis.timeout_seconds
            ));
        }

        if self.static_analysis.commands.len() > MAX_VDD_STATIC_COMMANDS {
            return Err(format!(
                "VDD static analysis accepts at most {MAX_VDD_STATIC_COMMANDS} commands, got {}",
                self.static_analysis.commands.len()
            ));
        }
        for command in &self.static_analysis.commands {
            if command.trim().is_empty() || command.len() > MAX_VDD_STATIC_COMMAND_BYTES {
                return Err(format!(
                    "VDD static-analysis commands must be non-empty and at most {MAX_VDD_STATIC_COMMAND_BYTES} bytes"
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdd_config_default_disabled() {
        let config = VddConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.mode, VddMode::Advisory);
        assert_eq!(config.adversary.provider, "google");
        assert!(config.adversary.model.is_none());
        assert!((config.adversary.temperature - 0.3_f32).abs() < f32::EPSILON);
        assert_eq!(config.adversary.max_tokens, 4096);
        assert_eq!(config.thresholds.max_iterations, 5);
        assert!((config.thresholds.false_positive_rate - 0.75_f32).abs() < f32::EPSILON);
        assert_eq!(config.thresholds.min_iterations, 2);
        assert!(config.static_analysis.enabled);
        assert!(config.static_analysis.commands.is_empty());
        assert_eq!(config.static_analysis.timeout_seconds, 120);
        assert!(config.tracking.persist);
        assert_eq!(config.tracking.path, PathBuf::from(".openclaudia/vdd"));
    }

    #[test]
    fn test_vdd_config_serde_full() {
        let json = r#"{
            "enabled": true,
            "mode": "blocking",
            "adversary": {
                "provider": "google",
                "model": "gemini-2.5-pro",
                "temperature": 0.2,
                "max_tokens": 8192
            },
            "thresholds": {
                "max_iterations": 8,
                "false_positive_rate": 0.80,
                "min_iterations": 3
            },
            "static_analysis": {
                "enabled": true,
                "commands": ["cargo clippy -- -D warnings", "cargo test"],
                "timeout_seconds": 180
            },
            "tracking": {
                "persist": true,
                "path": "/custom/vdd",
                "promote_verified_findings": false,
                "retention_days": 90,
                "log_adversary_responses": false
            }
        }"#;

        let config: VddConfig = serde_json::from_str(json).unwrap();
        assert!(config.enabled);
        assert_eq!(config.mode, VddMode::Blocking);
        assert_eq!(config.adversary.provider, "google");
        assert_eq!(config.adversary.model, Some("gemini-2.5-pro".to_string()));
        assert!((config.adversary.temperature - 0.2_f32).abs() < f32::EPSILON);
        assert_eq!(config.adversary.max_tokens, 8192);
        assert_eq!(config.thresholds.max_iterations, 8);
        assert!((config.thresholds.false_positive_rate - 0.80_f32).abs() < f32::EPSILON);
        assert_eq!(config.thresholds.min_iterations, 3);
        assert_eq!(config.static_analysis.commands.len(), 2);
        assert_eq!(config.static_analysis.timeout_seconds, 180);
        assert!(!config.tracking.promote_verified_findings);
        assert_eq!(config.tracking.retention_days, 90);
        assert!(!config.tracking.log_adversary_responses);
    }

    #[test]
    fn test_vdd_mode_display() {
        assert_eq!(format!("{}", VddMode::Advisory), "advisory");
        assert_eq!(format!("{}", VddMode::Blocking), "blocking");
    }

    #[test]
    fn test_vdd_validate_same_provider_rejected() {
        let config = VddConfig {
            enabled: true,
            adversary: VddAdversaryConfig {
                provider: "anthropic".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let result = config.validate("anthropic");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must differ"));
    }

    #[test]
    fn test_vdd_settings_validation_allows_runtime_provider_choice() {
        let config = VddConfig {
            enabled: true,
            adversary: VddAdversaryConfig {
                provider: "anthropic".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(config.validate_settings().is_ok());
        assert!(config.validate("anthropic").is_err());
    }

    #[test]
    fn test_vdd_validate_same_provider_case_insensitive() {
        let config = VddConfig {
            enabled: true,
            adversary: VddAdversaryConfig {
                provider: "Anthropic".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let result = config.validate("anthropic");
        assert!(result.is_err());
    }

    #[test]
    fn test_vdd_validate_different_provider_ok() {
        let config = VddConfig {
            enabled: true,
            adversary: VddAdversaryConfig {
                provider: "google".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate("anthropic").is_ok());
    }

    #[test]
    fn test_vdd_validate_rejects_empty_evidence_path() {
        let mut config = VddConfig {
            enabled: true,
            ..Default::default()
        };
        config.tracking.path = PathBuf::new();
        assert!(config
            .validate("anthropic")
            .expect_err("empty evidence root must fail")
            .contains("cannot be empty"));
    }

    #[test]
    fn test_vdd_validate_disabled_skips_checks() {
        // Even with same provider, disabled VDD passes validation
        let config = VddConfig {
            enabled: false,
            adversary: VddAdversaryConfig {
                provider: "anthropic".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate("anthropic").is_ok());
    }

    #[test]
    fn test_vdd_validate_bad_fp_rate() {
        let config = VddConfig {
            enabled: true,
            thresholds: VddThresholds {
                false_positive_rate: 1.5,
                ..Default::default()
            },
            ..Default::default()
        };
        let result = config.validate("anthropic");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("between 0.0 and 1.0"));
    }

    #[test]
    fn test_vdd_validate_min_exceeds_max() {
        let config = VddConfig {
            enabled: true,
            thresholds: VddThresholds {
                min_iterations: 10,
                max_iterations: 5,
                ..Default::default()
            },
            ..Default::default()
        };
        let result = config.validate("anthropic");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot exceed"));
    }

    #[test]
    fn test_vdd_validate_zero_max_iterations() {
        let config = VddConfig {
            enabled: true,
            thresholds: VddThresholds {
                max_iterations: 0,
                min_iterations: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        let result = config.validate("anthropic");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least 1"));
    }

    #[test]
    fn test_vdd_validate_bad_temperature() {
        let config = VddConfig {
            enabled: true,
            adversary: VddAdversaryConfig {
                temperature: 3.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let result = config.validate("anthropic");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("temperature"));
    }

    #[test]
    fn test_vdd_validate_rejects_non_finite_thresholds() {
        for false_positive_rate in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let config = VddConfig {
                enabled: true,
                thresholds: VddThresholds {
                    false_positive_rate,
                    ..Default::default()
                },
                ..Default::default()
            };
            assert!(config.validate_settings().is_err());
        }
    }

    #[test]
    fn test_vdd_validate_rejects_non_finite_temperature() {
        for temperature in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let config = VddConfig {
                enabled: true,
                adversary: VddAdversaryConfig {
                    temperature,
                    ..Default::default()
                },
                ..Default::default()
            };
            assert!(config.validate_settings().is_err());
        }
    }

    #[test]
    fn test_vdd_validate_rejects_zero_and_excessive_resource_limits() {
        let mut config = VddConfig {
            enabled: true,
            ..Default::default()
        };
        config.adversary.max_tokens = 0;
        assert!(config.validate_settings().is_err());

        config.adversary.max_tokens = default_adversary_max_tokens();
        config.adversary.request_timeout_seconds = 0;
        assert!(config.validate_settings().is_err());

        config.adversary.request_timeout_seconds = default_adversary_request_timeout_seconds();
        config.static_analysis.timeout_seconds = 0;
        assert!(config.validate_settings().is_err());

        config.static_analysis.timeout_seconds = default_analysis_timeout();
        config.thresholds.max_iterations = MAX_VDD_ITERATIONS + 1;
        assert!(config.validate_settings().is_err());
    }

    #[test]
    fn test_vdd_validate_rejects_unbounded_static_command_lists() {
        let config = VddConfig {
            enabled: true,
            static_analysis: VddStaticAnalysis {
                commands: vec!["true".to_string(); MAX_VDD_STATIC_COMMANDS + 1],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate_settings().is_err());
    }
}
