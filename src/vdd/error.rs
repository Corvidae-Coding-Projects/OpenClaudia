//! VDD error type and result enums.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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

/// Host-side failures while binding a candidate to the VDD finalization gate.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum VddFinalizationError {
    #[error("invalid VDD finalization policy: {0}")]
    InvalidPolicy(String),

    #[error("invalid VDD candidate binding: {0}")]
    InvalidCandidate(String),
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

/// Terminal disposition of one provider call owned by a VDD review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VddProviderCallOutcome {
    Completed,
    FailedOrUnknown,
}

/// Transport-observed identity and accounting receipt for one VDD model call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VddProviderCallReceipt {
    pub provider: String,
    pub requested_model: String,
    pub resolved_model: Option<String>,
    pub outcome: VddProviderCallOutcome,
    pub usage_known: bool,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub response_bytes: u64,
    pub completed_at: DateTime<Utc>,
}

/// Advisory mode result
pub struct VddAdvisoryResult {
    pub findings: Vec<Finding>,
    pub context_observation: Option<crate::context::ContextItem>,
    pub static_analysis: Vec<StaticAnalysisResult>,
    pub tokens_used: TokenUsage,
    pub provider_receipts: Vec<VddProviderCallReceipt>,
}

/// Blocking mode result
pub struct VddBlockingResult {
    pub final_response: Value,
    pub session: VddSession,
    pub crosslink_issues: Vec<String>,
    pub provider_receipts: Vec<VddProviderCallReceipt>,
}

/// Blocking VDD result for frontends whose provider turn is already decoded
/// to text rather than retained as a provider-native JSON envelope.
pub struct VddBlockingTextResult {
    pub final_text: String,
    pub session: VddSession,
    pub crosslink_issues: Vec<String>,
    pub provider_receipts: Vec<VddProviderCallReceipt>,
}
