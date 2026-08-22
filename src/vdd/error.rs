//! VDD error type and result enums.

use serde_json::Value;
use thiserror::Error;

use crate::session::TokenUsage;

use crate::vdd::finding::Finding;
use crate::vdd::review::VddSession;
use crate::vdd::static_analysis::StaticAnalysisResult;

#[derive(Error, Debug)]
pub enum VddError {
    #[error(transparent)]
    Capability(#[from] crate::tools::ToolCapabilityError),

    #[error("Adversary provider request failed: {0}")]
    AdversaryRequestFailed(String),

    #[error("Builder revision request failed: {0}")]
    BuilderRevisionFailed(String),

    #[error("Failed to parse adversary response as findings: {0}")]
    ParseError(String),

    #[error("VDD HTTP request to provider '{provider}' timed out after {elapsed_secs}s")]
    Timeout { provider: String, elapsed_secs: u64 },

    #[error("Static analysis command failed: {command} (timeout: {timeout}s)")]
    StaticAnalysisTimeout { command: String, timeout: u64 },

    #[error("Crosslink issue creation failed: {0}")]
    CrosslinkError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("HTTP client error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Top-level result from VDD processing
pub enum VddResult {
    /// Advisory mode: single pass, findings for context injection
    Advisory(VddAdvisoryResult),
    /// Blocking mode: full loop, revised response
    Blocking(VddBlockingResult),
    /// VDD was skipped (disabled, not applicable, etc.)
    Skipped(String),
}

/// Advisory mode result
pub struct VddAdvisoryResult {
    pub findings: Vec<Finding>,
    pub context_observation: Option<crate::context::ContextItem>,
    pub static_analysis: Vec<StaticAnalysisResult>,
    pub tokens_used: TokenUsage,
}

/// Blocking mode result
pub struct VddBlockingResult {
    pub final_response: Value,
    pub session: VddSession,
    pub crosslink_issues: Vec<String>,
}
