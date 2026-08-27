//! Verification-Driven Development (VDD) Engine
//!
//! Implements the adversarial loop methodology where a Builder AI's output is reviewed
//! by a separate Adversary AI on a different provider with fresh context. The loop
//! continues until the adversary reaches the confabulation threshold (producing mostly
//! false positives), indicating exhaustion of genuine findings.
//!
//! Two modes:
//! - Advisory: Single adversary pass, findings injected into next turn context
//! - Blocking: Full adversarial loop until convergence, response held until clean
//!
//! Based on the VDD methodology: <https://github.com/dollspace-gay/Tesseract-Vault>
//!
//! ## Internal layout
//!
//! - [`engine`] — orchestration state machine (`VddEngine`, advisory + blocking loops)
//! - [`transport`] — HTTP plumbing to adversary + builder providers
//! - [`prompts`] — system prompts and request-template builders
//! - [`triage`] — three-layer finding triage (duplicate, pattern, AI verification)
//! - [`sink`] — crosslink issue creation + on-disk session persistence
//! - [`helpers`] — small utilities (truncation, task extraction, advisory formatting)
//! - [`error`] — `VddError` and result enums
//! - [`finding`], [`review`], [`parsing`], [`static_analysis`], [`confabulation`] —
//!   domain types and pre-existing parsing/analysis support

mod canonical;
pub mod confabulation;
mod engine;
mod error;
pub mod finding;
mod helpers;
pub mod parsing;
mod prompts;
pub mod review;
mod sink;
pub mod static_analysis;
mod transport;
mod triage;

// Re-exports for public API
pub(crate) use canonical::validate_canonical_verifier_model_output;
pub use canonical::{
    CanonicalAcceptanceCriterion, CanonicalCriterionOutcome, CanonicalCriterionReport,
    CanonicalDeterministicReceipt, CanonicalFindingSeverity, CanonicalModelVerdict,
    CanonicalSourceSnapshot, CanonicalVddPreflightError, CanonicalVddReceipt, CanonicalVddRequest,
    CanonicalVddRequestParts, CanonicalVddTerminalReason, CanonicalVddVerdict,
    CanonicalVerifierFinding, CanonicalVerifierReport, DeterministicCheckOutcome, VddModelIdentity,
    VddPromotionAuthority,
};
pub use engine::{BuilderProvider, VddEngine};
pub use error::{VddAdvisoryResult, VddBlockingResult, VddError, VddResult};
pub use finding::{Finding, FindingStatus, Severity};
pub use helpers::findings_context_observation;
pub use review::{AdversaryReview, VddIteration, VddSession};
pub use static_analysis::StaticAnalysisResult;
pub use transport::VddProviderAuth;

/// Triage entry points re-exported for the VDD-pipeline E2E test
/// suite (`tests/vdd_triage_e2e.rs`, sprint 54). Curated to avoid
/// surfacing the internal `RawFinding` / `AdversaryResponse` types
/// that the parser uses internally.
pub use triage::{parse_findings, parse_findings_detailed, ParseErrorKind, ParseFindingsOutcome};
