use serde::Deserialize;
use std::fmt;
use std::num::NonZeroU32;

use super::default_true;

/// Top-level guardrails configuration
#[derive(Debug, Deserialize, Clone, Default)]
pub struct GuardrailsConfig {
    /// Blast radius limiting: constrain file access per request
    #[serde(default)]
    pub blast_radius: Option<BlastRadiusConfig>,
    /// Diff size monitoring: flag oversized changes
    #[serde(default)]
    pub diff_monitor: Option<DiffMonitorConfig>,
    /// Automated code quality gates
    #[serde(default)]
    pub quality_gates: Option<QualityGatesConfig>,
}

/// Guardrail enforcement mode
#[derive(Debug, Default, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GuardrailMode {
    /// Block operations that violate the guardrail
    Strict,
    /// Warn but allow operations
    #[default]
    Advisory,
}

impl fmt::Display for GuardrailMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Strict => write!(f, "strict"),
            Self::Advisory => write!(f, "advisory"),
        }
    }
}

/// Action to take when a guardrail threshold is exceeded
#[derive(Debug, Default, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailAction {
    /// Log a warning
    #[default]
    Warn,
    /// Block the operation
    Block,
    /// Inject findings into context for the model to address
    InjectFindings,
}

impl fmt::Display for GuardrailAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Warn => write!(f, "warn"),
            Self::Block => write!(f, "block"),
            Self::InjectFindings => write!(f, "inject_findings"),
        }
    }
}

/// When to run quality gate checks
#[derive(Debug, Default, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunAfter {
    /// After every file edit
    EveryEdit,
    /// After every tool-use turn
    #[default]
    EveryTurn,
    /// Only before git commit
    OnCommit,
}

impl fmt::Display for RunAfter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EveryEdit => write!(f, "every_edit"),
            Self::EveryTurn => write!(f, "every_turn"),
            Self::OnCommit => write!(f, "on_commit"),
        }
    }
}

/// Blast radius limiting configuration
#[derive(Debug, Deserialize, Clone)]
pub struct BlastRadiusConfig {
    /// Enable blast radius limiting
    #[serde(default)]
    pub enabled: bool,
    /// Enforcement mode: strict (block) or advisory (warn)
    #[serde(default)]
    pub mode: GuardrailMode,
    /// Glob patterns for allowed file paths (empty = all allowed)
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    /// Glob patterns for denied file paths (takes priority over allowed)
    #[serde(default)]
    pub denied_paths: Vec<String>,
    /// Maximum distinct capability-resolved paths admitted during one run.
    ///
    /// `max_files_per_turn` remains a deserialization alias so existing
    /// non-zero configurations migrate without silently changing which value
    /// wins. Supplying both names is a duplicate-field error, and zero is
    /// rejected by [`NonZeroU32`] instead of ambiguously meaning "unlimited".
    #[serde(default, alias = "max_files_per_turn")]
    pub max_files_per_run: Option<NonZeroU32>,
    /// Maximum changed lines committed by file mutations during one run.
    #[serde(default)]
    pub max_lines_per_run: Option<NonZeroU32>,
    /// Maximum classified tool calls committed during one run.
    #[serde(default)]
    pub max_tool_calls_per_run: Option<NonZeroU32>,
    /// Maximum state-mutating tool calls committed during one run.
    #[serde(default)]
    pub max_mutations_per_run: Option<NonZeroU32>,
}

impl Default for BlastRadiusConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: GuardrailMode::Advisory,
            allowed_paths: Vec::new(),
            denied_paths: Vec::new(),
            max_files_per_run: None,
            max_lines_per_run: None,
            max_tool_calls_per_run: None,
            max_mutations_per_run: None,
        }
    }
}

/// Diff size monitoring configuration
#[derive(Debug, Deserialize, Clone)]
pub struct DiffMonitorConfig {
    /// Enable diff monitoring
    #[serde(default)]
    pub enabled: bool,
    /// Maximum total lines changed before warning (0 = unlimited)
    #[serde(default = "default_max_lines")]
    pub max_lines_changed: u32,
    /// Maximum files changed before warning (0 = unlimited)
    #[serde(default = "default_max_files")]
    pub max_files_changed: u32,
    /// Action when thresholds exceeded
    #[serde(default)]
    pub action: GuardrailAction,
}

const fn default_max_lines() -> u32 {
    500
}

const fn default_max_files() -> u32 {
    10
}

impl Default for DiffMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_lines_changed: default_max_lines(),
            max_files_changed: default_max_files(),
            action: GuardrailAction::Warn,
        }
    }
}

/// Quality gates configuration
#[derive(Debug, Deserialize, Clone)]
pub struct QualityGatesConfig {
    /// Enable quality gates
    #[serde(default)]
    pub enabled: bool,
    /// When to run checks
    #[serde(default)]
    pub run_after: RunAfter,
    /// Action when required checks fail
    #[serde(default)]
    pub fail_action: GuardrailAction,
    /// List of quality checks to run
    #[serde(default)]
    pub checks: Vec<QualityCheck>,
    /// Timeout per command in seconds
    #[serde(default = "default_quality_timeout")]
    pub timeout_seconds: u64,
}

const fn default_quality_timeout() -> u64 {
    120
}

impl Default for QualityGatesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            run_after: RunAfter::EveryTurn,
            fail_action: GuardrailAction::Warn,
            checks: Vec::new(),
            timeout_seconds: default_quality_timeout(),
        }
    }
}

/// A single quality check definition
#[derive(Debug, Deserialize, Clone)]
pub struct QualityCheck {
    /// Human-readable name for the check
    pub name: String,
    /// Shell command to run (exit code 0 = pass)
    pub command: String,
    /// Whether failure should be treated as an error
    #[serde(default = "default_true")]
    pub required: bool,
}
