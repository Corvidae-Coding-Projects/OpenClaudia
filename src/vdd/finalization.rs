//! Host-owned VDD finalization decisions.
//!
//! Review engines produce evidence. This module is the only VDD surface that
//! decides whether an exact candidate may leave a frontend as ordinary
//! success. Required review fails closed; advisory review and an explicit
//! host-selected fail-open policy remain visible, distinct outcomes.

use std::collections::BTreeSet;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::{VddConfig, VddMode};
use crate::context::ContextItem;
use crate::coordinator::WorkerSliceResult;
use crate::coordinator::WorkerTerminalState;
use crate::runtime::{ContentDigest, RunDescriptor};
use crate::tools::ToolRunContext;

use super::{
    BuilderProvider, CanonicalCriterionOutcome, CanonicalModelVerdict, CanonicalVddPreflightError,
    CanonicalVddReceipt, CanonicalVddRequest, CanonicalVddTerminalReason, CanonicalVddVerdict,
    DeterministicCheckOutcome, FindingStatus, VddEngine, VddError, VddFinalizationError,
    VddPromotionAuthority, VddResult,
};

const MAX_FAIL_OPEN_REASON_BYTES: usize = 4 * 1024;
const MAX_CANDIDATE_GENERATION_BYTES: usize = 4 * 1024;

/// Whether review is disabled, advisory, or required before success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VddFinalizationRequirement {
    Disabled,
    Advisory,
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VddFailurePolicy {
    Withhold,
    HostSelectedFailOpen { reason: String },
}

/// Immutable host policy applied to one finalization attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VddFinalizationPolicy {
    requirement: VddFinalizationRequirement,
    failure_policy: VddFailurePolicy,
}

impl VddFinalizationPolicy {
    /// Derive the normal frontend policy from configuration.
    #[must_use]
    pub const fn from_config(config: &VddConfig) -> Self {
        let requirement = if config.enabled {
            match &config.mode {
                VddMode::Advisory => VddFinalizationRequirement::Advisory,
                VddMode::Blocking => VddFinalizationRequirement::Required,
            }
        } else {
            VddFinalizationRequirement::Disabled
        };
        Self {
            requirement,
            failure_policy: VddFailurePolicy::Withhold,
        }
    }

    /// Construct a required, fail-closed publication policy.
    #[must_use]
    pub const fn required() -> Self {
        Self {
            requirement: VddFinalizationRequirement::Required,
            failure_policy: VddFailurePolicy::Withhold,
        }
    }

    /// Explicitly permit the host to publish a non-pass candidate.
    ///
    /// This cannot be selected by planner or worker model output. Callers must
    /// supply a bounded, non-empty host reason, and the resulting publication
    /// is labeled [`VddFinalizationOutcome::FailOpen`].
    ///
    /// # Errors
    ///
    /// Returns [`VddFinalizationError::InvalidPolicy`] for disabled/advisory
    /// policies or an empty/oversized reason.
    pub fn with_host_fail_open(
        mut self,
        reason: impl Into<String>,
    ) -> Result<Self, VddFinalizationError> {
        if self.requirement != VddFinalizationRequirement::Required {
            return Err(VddFinalizationError::InvalidPolicy(
                "fail-open is meaningful only for required VDD review".to_string(),
            ));
        }
        let reason = reason.into();
        if reason.trim().is_empty() || reason.len() > MAX_FAIL_OPEN_REASON_BYTES {
            return Err(VddFinalizationError::InvalidPolicy(format!(
                "host fail-open reason must contain 1..={MAX_FAIL_OPEN_REASON_BYTES} bytes"
            )));
        }
        self.failure_policy = VddFailurePolicy::HostSelectedFailOpen { reason };
        Ok(self)
    }

    #[must_use]
    pub const fn requirement(&self) -> VddFinalizationRequirement {
        self.requirement
    }
}

/// Exact response or worker-output identity reviewed for publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VddCandidateBinding {
    digest: ContentDigest,
    generation: String,
}

impl VddCandidateBinding {
    /// Bind response bytes to the immutable run plus a caller-selected turn
    /// scope (normally the exact user task or session turn identity).
    ///
    /// # Errors
    ///
    /// Returns [`VddFinalizationError`] if the immutable run descriptor cannot
    /// be serialized into the generation seed.
    pub fn for_response(
        run: &ToolRunContext,
        scope: &str,
        candidate: &[u8],
    ) -> Result<Self, VddFinalizationError> {
        let digest = ContentDigest::sha256(candidate);
        let seed = ResponseGenerationSeed {
            schema_version: 1,
            run: run.runtime().descriptor(),
            scope_sha256: ContentDigest::sha256(scope.as_bytes()),
            candidate_sha256: digest,
        };
        let seed = serde_json::to_vec(&seed).map_err(|error| {
            VddFinalizationError::InvalidCandidate(format!(
                "response generation seed could not be serialized: {error}"
            ))
        })?;
        Ok(Self {
            digest,
            generation: format!("response-v1:{}", ContentDigest::sha256(seed)),
        })
    }

    fn for_worker(request: &CanonicalVddRequest, candidate: &[u8]) -> Self {
        Self::for_worker_result(request.worker_result(), candidate)
    }

    fn for_worker_result(result: &WorkerSliceResult, candidate: &[u8]) -> Self {
        Self {
            digest: ContentDigest::sha256(candidate),
            generation: result.artifact.generation.clone(),
        }
    }

    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    #[must_use]
    pub fn generation(&self) -> &str {
        &self.generation
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ResponseGenerationSeed<'a> {
    schema_version: u16,
    run: &'a RunDescriptor,
    scope_sha256: ContentDigest,
    candidate_sha256: ContentDigest,
}

/// A required-review reason that normally withholds success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VddNonPassOutcome {
    Fail,
    Inconclusive,
    VerifierError,
    Unavailable,
    Stale,
    Unconverged,
    Cancelled,
}

/// Final, caller-visible disposition of one review attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VddFinalizationOutcome {
    Pass,
    Advisory,
    SkippedByPolicy,
    Fail,
    Inconclusive,
    VerifierError,
    Unavailable,
    Stale,
    Unconverged,
    Cancelled,
    FailOpen,
}

impl From<VddNonPassOutcome> for VddFinalizationOutcome {
    fn from(value: VddNonPassOutcome) -> Self {
        match value {
            VddNonPassOutcome::Fail => Self::Fail,
            VddNonPassOutcome::Inconclusive => Self::Inconclusive,
            VddNonPassOutcome::VerifierError => Self::VerifierError,
            VddNonPassOutcome::Unavailable => Self::Unavailable,
            VddNonPassOutcome::Stale => Self::Stale,
            VddNonPassOutcome::Unconverged => Self::Unconverged,
            VddNonPassOutcome::Cancelled => Self::Cancelled,
        }
    }
}

/// A candidate that the host finalization gate permits to publish.
#[derive(Debug)]
pub struct VddPublishedCandidate<T> {
    candidate: T,
    binding: VddCandidateBinding,
    outcome: VddFinalizationOutcome,
    blocked_outcome: Option<VddNonPassOutcome>,
    detail: String,
}

impl<T> VddPublishedCandidate<T> {
    #[must_use]
    pub fn into_candidate(self) -> T {
        self.candidate
    }

    #[must_use]
    pub const fn binding(&self) -> &VddCandidateBinding {
        &self.binding
    }

    #[must_use]
    pub const fn outcome(&self) -> VddFinalizationOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn blocked_outcome(&self) -> Option<VddNonPassOutcome> {
        self.blocked_outcome
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Metadata retained when required review withholds the candidate bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VddWithheldCandidate {
    binding: VddCandidateBinding,
    outcome: VddNonPassOutcome,
    detail: String,
}

impl VddWithheldCandidate {
    #[must_use]
    pub const fn binding(&self) -> &VddCandidateBinding {
        &self.binding
    }

    #[must_use]
    pub const fn outcome(&self) -> VddNonPassOutcome {
        self.outcome
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Publication is an explicit sum type: blocked candidates are consumed and
/// are not returned in the `Withhold` arm.
#[derive(Debug)]
pub enum VddPublication<T> {
    Publish(VddPublishedCandidate<T>),
    Withhold(VddWithheldCandidate),
}

impl<T> VddPublication<T> {
    #[must_use]
    pub const fn outcome(&self) -> VddFinalizationOutcome {
        match self {
            Self::Publish(candidate) => candidate.outcome(),
            Self::Withhold(candidate) => match candidate.outcome() {
                VddNonPassOutcome::Fail => VddFinalizationOutcome::Fail,
                VddNonPassOutcome::Inconclusive => VddFinalizationOutcome::Inconclusive,
                VddNonPassOutcome::VerifierError => VddFinalizationOutcome::VerifierError,
                VddNonPassOutcome::Unavailable => VddFinalizationOutcome::Unavailable,
                VddNonPassOutcome::Stale => VddFinalizationOutcome::Stale,
                VddNonPassOutcome::Unconverged => VddFinalizationOutcome::Unconverged,
                VddNonPassOutcome::Cancelled => VddFinalizationOutcome::Cancelled,
            },
        }
    }

    #[must_use]
    pub const fn is_publishable(&self) -> bool {
        matches!(self, Self::Publish(_))
    }
}

/// Finalization plus advisory context that a frontend may project into a later
/// turn. The context never affects the current publication decision.
#[derive(Debug)]
pub struct VddResponseFinalization<T> {
    publication: VddPublication<T>,
    context_observation: Option<ContextItem>,
    provider_receipts: Vec<super::VddProviderCallReceipt>,
}

/// Durable host record attached to one exact worker-attempt finalization.
///
/// The canonical receipt is retained as its exact serialized value because
/// the strict receipt type is intentionally output-only. Its digest prevents a
/// planner checkpoint from silently substituting another receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VddWorkerFinalizationRecord {
    binding: VddCandidateBinding,
    outcome: VddFinalizationOutcome,
    blocked_outcome: Option<VddNonPassOutcome>,
    detail_sha256: ContentDigest,
    canonical_receipt_sha256: Option<ContentDigest>,
    canonical_receipt: Option<serde_json::Value>,
    finalized_at: DateTime<Utc>,
}

impl VddWorkerFinalizationRecord {
    #[must_use]
    pub const fn binding(&self) -> &VddCandidateBinding {
        &self.binding
    }

    #[must_use]
    pub const fn outcome(&self) -> VddFinalizationOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn blocked_outcome(&self) -> Option<VddNonPassOutcome> {
        self.blocked_outcome
    }

    #[must_use]
    pub const fn canonical_receipt_sha256(&self) -> Option<ContentDigest> {
        self.canonical_receipt_sha256
    }

    #[must_use]
    pub const fn canonical_receipt(&self) -> Option<&serde_json::Value> {
        self.canonical_receipt.as_ref()
    }

    #[must_use]
    pub const fn finalized_at(&self) -> DateTime<Utc> {
        self.finalized_at
    }

    /// Recompute the retained receipt digest after checkpoint load.
    #[must_use]
    pub fn receipt_digest_is_valid(&self) -> bool {
        match (&self.canonical_receipt, self.canonical_receipt_sha256) {
            (None, None) => true,
            (Some(receipt), Some(expected)) => serde_json::to_vec(receipt)
                .is_ok_and(|bytes| ContentDigest::sha256(bytes) == expected),
            _ => false,
        }
    }
}

/// Worker publication plus the immutable record the planner must checkpoint.
#[derive(Debug)]
pub struct VddWorkerFinalization<T> {
    publication: VddPublication<T>,
    record: VddWorkerFinalizationRecord,
}

impl<T> VddWorkerFinalization<T> {
    #[must_use]
    pub fn into_parts(self) -> (VddPublication<T>, VddWorkerFinalizationRecord) {
        (self.publication, self.record)
    }

    #[must_use]
    pub const fn publication(&self) -> &VddPublication<T> {
        &self.publication
    }

    #[must_use]
    pub const fn record(&self) -> &VddWorkerFinalizationRecord {
        &self.record
    }
}

impl<T> VddResponseFinalization<T> {
    #[must_use]
    pub fn into_parts(self) -> (VddPublication<T>, Option<ContextItem>) {
        (self.publication, self.context_observation)
    }

    #[must_use]
    pub fn into_parts_with_receipts(
        self,
    ) -> (
        VddPublication<T>,
        Option<ContextItem>,
        Vec<super::VddProviderCallReceipt>,
    ) {
        (
            self.publication,
            self.context_observation,
            self.provider_receipts,
        )
    }

    #[must_use]
    pub const fn publication(&self) -> &VddPublication<T> {
        &self.publication
    }
}

/// Review and finalize plain text through the existing frontend review API.
///
/// Required mode runs the full revision/convergence loop. A required pass
/// needs a clean final iteration with no failed deterministic evidence.
#[allow(clippy::too_many_lines)] // Every policy/review arm consumes the candidate into one terminal publication decision.
pub async fn finalize_text_candidate(
    engine: Option<&VddEngine>,
    run: &Arc<ToolRunContext>,
    policy: &VddFinalizationPolicy,
    content: String,
    scope: &str,
    user_task: &str,
    builder: BuilderProvider<'_>,
) -> VddResponseFinalization<String> {
    let binding = match VddCandidateBinding::for_response(run, scope, content.as_bytes()) {
        Ok(binding) => binding,
        Err(error) => {
            return VddResponseFinalization {
                publication: unavailable_binding_publication(policy, content, error.to_string()),
                context_observation: None,
                provider_receipts: Vec::new(),
            };
        }
    };
    if policy.requirement == VddFinalizationRequirement::Disabled {
        return VddResponseFinalization {
            publication: publish(
                content,
                binding,
                VddFinalizationOutcome::SkippedByPolicy,
                "VDD review is disabled by host policy".to_string(),
            ),
            context_observation: None,
            provider_receipts: Vec::new(),
        };
    }
    if run.runtime().cancellation().is_cancelled() {
        return VddResponseFinalization {
            publication: non_pass(
                policy,
                content,
                binding,
                VddNonPassOutcome::Cancelled,
                "candidate finalization was cancelled before VDD review".to_string(),
            ),
            context_observation: None,
            provider_receipts: Vec::new(),
        };
    }
    let Some(engine) = engine else {
        return VddResponseFinalization {
            publication: non_pass(
                policy,
                content,
                binding,
                VddNonPassOutcome::Unavailable,
                "configured VDD engine is unavailable".to_string(),
            ),
            context_observation: None,
            provider_receipts: Vec::new(),
        };
    };

    match policy.requirement {
        VddFinalizationRequirement::Advisory => {
            let review = engine.review_text(run, &content, user_task, builder).await;
            if run.runtime().cancellation().is_cancelled() {
                return VddResponseFinalization {
                    publication: non_pass(
                        policy,
                        content,
                        binding,
                        VddNonPassOutcome::Cancelled,
                        "candidate finalization was cancelled during VDD review".to_string(),
                    ),
                    context_observation: None,
                    provider_receipts: Vec::new(),
                };
            }
            match review {
                Ok(review) => {
                    let context_observation = review.context_observation;
                    let publication = finalize_advisory_review(
                        policy,
                        content,
                        binding,
                        &review.findings,
                        &review.static_analysis,
                    );
                    VddResponseFinalization {
                        publication,
                        context_observation,
                        provider_receipts: review.provider_receipts,
                    }
                }
                Err(error) => VddResponseFinalization {
                    publication: non_pass(
                        policy,
                        content,
                        binding,
                        classify_legacy_error(&error),
                        error.to_string(),
                    ),
                    context_observation: None,
                    provider_receipts: Vec::new(),
                },
            }
        }
        VddFinalizationRequirement::Required => {
            let review = engine
                .review_text_blocking(run, &content, user_task, builder)
                .await;
            if run.runtime().cancellation().is_cancelled() {
                return VddResponseFinalization {
                    publication: non_pass(
                        policy,
                        content,
                        binding,
                        VddNonPassOutcome::Cancelled,
                        "candidate finalization was cancelled during blocking VDD review"
                            .to_string(),
                    ),
                    context_observation: None,
                    provider_receipts: Vec::new(),
                };
            }
            match review {
                Ok(review) => finalize_blocking_text_review(run, policy, scope, content, review),
                Err(error) => VddResponseFinalization {
                    publication: non_pass(
                        policy,
                        content,
                        binding,
                        classify_legacy_error(&error),
                        error.to_string(),
                    ),
                    context_observation: None,
                    provider_receipts: Vec::new(),
                },
            }
        }
        VddFinalizationRequirement::Disabled => unreachable!("disabled policy returned above"),
    }
}

fn finalize_blocking_text_review(
    run: &ToolRunContext,
    policy: &VddFinalizationPolicy,
    scope: &str,
    fallback_candidate: String,
    review: super::VddBlockingTextResult,
) -> VddResponseFinalization<String> {
    let super::VddBlockingTextResult {
        final_text,
        session,
        crosslink_issues: _,
        provider_receipts,
    } = review;
    let binding = match VddCandidateBinding::for_response(run, scope, final_text.as_bytes()) {
        Ok(binding) => binding,
        Err(error) => {
            return VddResponseFinalization {
                publication: unavailable_binding_publication(
                    policy,
                    fallback_candidate,
                    error.to_string(),
                ),
                context_observation: None,
                provider_receipts,
            };
        }
    };
    let publication = if !session.converged {
        non_pass(
            policy,
            final_text,
            binding,
            VddNonPassOutcome::Unconverged,
            session
                .termination_reason
                .unwrap_or_else(|| "blocking VDD review ended without convergence".to_string()),
        )
    } else if !blocking_session_has_clean_final_iteration(&session) {
        non_pass(
            policy,
            final_text,
            binding,
            VddNonPassOutcome::Fail,
            "blocking VDD convergence lacked a clean final evidence iteration".to_string(),
        )
    } else {
        publish(
            final_text,
            binding,
            VddFinalizationOutcome::Pass,
            "blocking VDD review converged on a clean final iteration".to_string(),
        )
    };
    VddResponseFinalization {
        publication,
        context_observation: None,
        provider_receipts,
    }
}

pub fn blocking_session_has_clean_final_iteration(session: &super::VddSession) -> bool {
    session.iterations.last().is_some_and(|iteration| {
        iteration.genuine_count == 0
            && iteration
                .adversary_review
                .findings
                .iter()
                .all(|finding| finding.status == FindingStatus::FalsePositive)
            && iteration.static_analysis.iter().all(|result| result.passed)
    })
}

/// Finalize the result of `VddEngine::process_response` without rerunning it.
///
/// This compatibility adapter lets buffered frontends retain their transport
/// flow while sharing the same publication semantics.
#[allow(clippy::too_many_lines)] // Every legacy result arm consumes the candidate into one publication decision.
pub fn finalize_review_result(
    run: &ToolRunContext,
    policy: &VddFinalizationPolicy,
    original_candidate: Vec<u8>,
    scope: &str,
    result: Result<VddResult, VddError>,
) -> VddResponseFinalization<Vec<u8>> {
    let binding = match VddCandidateBinding::for_response(run, scope, &original_candidate) {
        Ok(binding) => binding,
        Err(error) => {
            return VddResponseFinalization {
                publication: unavailable_binding_publication(
                    policy,
                    original_candidate,
                    error.to_string(),
                ),
                context_observation: None,
                provider_receipts: Vec::new(),
            };
        }
    };
    if policy.requirement == VddFinalizationRequirement::Disabled {
        return VddResponseFinalization {
            publication: publish(
                original_candidate,
                binding,
                VddFinalizationOutcome::SkippedByPolicy,
                "VDD review is disabled by host policy".to_string(),
            ),
            context_observation: None,
            provider_receipts: Vec::new(),
        };
    }
    if run.runtime().cancellation().is_cancelled() {
        return VddResponseFinalization {
            publication: non_pass(
                policy,
                original_candidate,
                binding,
                VddNonPassOutcome::Cancelled,
                "candidate finalization was cancelled".to_string(),
            ),
            context_observation: None,
            provider_receipts: Vec::new(),
        };
    }

    match result {
        Ok(VddResult::Advisory(review)) => {
            let context_observation = review.context_observation;
            let provider_receipts = review.provider_receipts;
            let publication = finalize_advisory_review(
                policy,
                original_candidate,
                binding,
                &review.findings,
                &review.static_analysis,
            );
            VddResponseFinalization {
                publication,
                context_observation,
                provider_receipts,
            }
        }
        Ok(VddResult::Blocking(blocking)) => {
            let provider_receipts = blocking.provider_receipts;
            if !blocking.session.converged {
                return VddResponseFinalization {
                    publication: non_pass(
                        policy,
                        original_candidate,
                        binding,
                        VddNonPassOutcome::Unconverged,
                        blocking.session.termination_reason.unwrap_or_else(|| {
                            "blocking VDD review ended without convergence".to_string()
                        }),
                    ),
                    context_observation: None,
                    provider_receipts,
                };
            }
            if !blocking_session_has_clean_final_iteration(&blocking.session) {
                return VddResponseFinalization {
                    publication: non_pass(
                        policy,
                        original_candidate,
                        binding,
                        VddNonPassOutcome::Fail,
                        "blocking VDD convergence lacked a clean final evidence iteration"
                            .to_string(),
                    ),
                    context_observation: None,
                    provider_receipts,
                };
            }
            match serde_json::to_vec(&blocking.final_response) {
                Ok(candidate) => {
                    let reviewed_binding =
                        VddCandidateBinding::for_response(run, scope, &candidate)
                            .unwrap_or_else(|_| binding.clone());
                    VddResponseFinalization {
                        publication: publish(
                            candidate,
                            reviewed_binding,
                            VddFinalizationOutcome::Pass,
                            "blocking VDD review converged on a clean final iteration".to_string(),
                        ),
                        context_observation: None,
                        provider_receipts,
                    }
                }
                Err(error) => VddResponseFinalization {
                    publication: non_pass(
                        policy,
                        original_candidate,
                        binding,
                        VddNonPassOutcome::VerifierError,
                        format!("reviewed response could not be serialized: {error}"),
                    ),
                    context_observation: None,
                    provider_receipts,
                },
            }
        }
        Ok(VddResult::Skipped(reason)) => VddResponseFinalization {
            publication: non_pass(
                policy,
                original_candidate,
                binding,
                VddNonPassOutcome::Unavailable,
                reason,
            ),
            context_observation: None,
            provider_receipts: Vec::new(),
        },
        Err(error) => VddResponseFinalization {
            publication: non_pass(
                policy,
                original_candidate,
                binding,
                classify_legacy_error(&error),
                error.to_string(),
            ),
            context_observation: None,
            provider_receipts: Vec::new(),
        },
    }
}

/// Run and consume a canonical worker verifier receipt, then re-observe the
/// artifact immediately before returning a publication decision.
pub async fn finalize_worker_candidate(
    engine: Option<&VddEngine>,
    run: &Arc<ToolRunContext>,
    policy: &VddFinalizationPolicy,
    request: &CanonicalVddRequest,
    candidate: Vec<u8>,
) -> VddPublication<Vec<u8>> {
    finalize_worker_candidate_with_receipt(engine, run, policy, request, candidate)
        .await
        .into_parts()
        .0
}

/// Finalize a canonical worker candidate and retain the exact verifier receipt
/// for the planner's durable acceptance checkpoint.
#[allow(clippy::too_many_lines)] // Canonical receipt validation and candidate consumption form one authority boundary.
pub async fn finalize_worker_candidate_with_receipt(
    engine: Option<&VddEngine>,
    run: &Arc<ToolRunContext>,
    policy: &VddFinalizationPolicy,
    request: &CanonicalVddRequest,
    candidate: Vec<u8>,
) -> VddWorkerFinalization<Vec<u8>> {
    let binding = VddCandidateBinding::for_worker(request, &candidate);
    if policy.requirement == VddFinalizationRequirement::Disabled {
        return worker_finalization(
            publish(
                candidate,
                binding,
                VddFinalizationOutcome::SkippedByPolicy,
                "VDD review is disabled by host policy".to_string(),
            ),
            None,
        );
    }
    if binding.digest != request.worker_result().output_digest {
        return worker_finalization(
            non_pass(
                policy,
                candidate,
                binding,
                VddNonPassOutcome::Stale,
                "publication bytes differ from the exact worker output digest".to_string(),
            ),
            None,
        );
    }
    if run.runtime().cancellation().is_cancelled() {
        return worker_finalization(
            non_pass(
                policy,
                candidate,
                binding,
                VddNonPassOutcome::Cancelled,
                "worker finalization was cancelled before VDD review".to_string(),
            ),
            None,
        );
    }
    let Some(engine) = engine else {
        return worker_finalization(
            non_pass(
                policy,
                candidate,
                binding,
                VddNonPassOutcome::Unavailable,
                "canonical worker verifier is unavailable".to_string(),
            ),
            None,
        );
    };
    let receipt = engine.verify_worker_artifact(run, request).await;
    let receipt_json = match serde_json::to_value(&receipt) {
        Ok(receipt) => receipt,
        Err(error) => {
            return worker_finalization(
                non_pass(
                    policy,
                    candidate,
                    binding,
                    VddNonPassOutcome::VerifierError,
                    format!("canonical VDD receipt could not be retained: {error}"),
                ),
                None,
            );
        }
    };
    if run.runtime().cancellation().is_cancelled() {
        return worker_finalization(
            non_pass(
                policy,
                candidate,
                binding,
                VddNonPassOutcome::Cancelled,
                "worker finalization was cancelled during VDD review".to_string(),
            ),
            Some(receipt_json),
        );
    }
    let live_generation = request
        .worker_result()
        .artifact
        .locator
        .as_deref()
        .ok_or_else(|| "canonical worker artifact locator is unavailable".to_string())
        .and_then(|locator| {
            crate::tools::worktree::inspect_worker_artifacts(run, std::path::Path::new(locator))
                .map(|observation| observation.generation)
        });
    let live_generation = match live_generation {
        Ok(generation) => generation,
        Err(detail) => {
            return worker_finalization(
                non_pass(
                    policy,
                    candidate,
                    binding,
                    VddNonPassOutcome::Unavailable,
                    detail,
                ),
                Some(receipt_json),
            );
        }
    };
    let publication =
        match classify_canonical_receipt(request, &binding, &live_generation, &receipt) {
            Ok(detail) => publish(candidate, binding, VddFinalizationOutcome::Pass, detail),
            Err((outcome, detail)) => non_pass(policy, candidate, binding, outcome, detail),
        };
    worker_finalization(publication, Some(receipt_json))
}

/// Consume a candidate when its host-built canonical request failed preflight.
/// No model receipt exists in this case, and required policy remains closed.
#[must_use]
pub fn finalize_worker_preflight_failure(
    policy: &VddFinalizationPolicy,
    result: &WorkerSliceResult,
    candidate: Vec<u8>,
    error: &CanonicalVddPreflightError,
) -> VddWorkerFinalization<Vec<u8>> {
    let binding = VddCandidateBinding::for_worker_result(result, &candidate);
    let outcome = match error {
        CanonicalVddPreflightError::ArtifactStale(_) => VddNonPassOutcome::Stale,
        CanonicalVddPreflightError::ModelUnavailable(_)
        | CanonicalVddPreflightError::DeterministicEvidenceUnavailable(_) => {
            VddNonPassOutcome::Unavailable
        }
        CanonicalVddPreflightError::ModelCollision(_) => VddNonPassOutcome::Inconclusive,
        CanonicalVddPreflightError::InvalidContract(_) => VddNonPassOutcome::VerifierError,
    };
    worker_finalization(
        non_pass(policy, candidate, binding, outcome, error.to_string()),
        None,
    )
}

fn finalize_advisory_review<T>(
    policy: &VddFinalizationPolicy,
    candidate: T,
    binding: VddCandidateBinding,
    findings: &[super::Finding],
    static_analysis: &[super::StaticAnalysisResult],
) -> VddPublication<T> {
    let has_unresolved_finding = findings
        .iter()
        .any(|finding| finding.status != FindingStatus::FalsePositive);
    let deterministic_failed = static_analysis.iter().any(|result| !result.passed);
    if policy.requirement == VddFinalizationRequirement::Advisory {
        let detail = format!(
            "advisory VDD completed with {} finding(s) and {} failed static check(s)",
            findings.len(),
            static_analysis
                .iter()
                .filter(|result| !result.passed)
                .count()
        );
        return publish(candidate, binding, VddFinalizationOutcome::Advisory, detail);
    }
    if has_unresolved_finding || deterministic_failed {
        return non_pass(
            policy,
            candidate,
            binding,
            VddNonPassOutcome::Fail,
            "required VDD review found unresolved findings or failed deterministic evidence"
                .to_string(),
        );
    }
    publish(
        candidate,
        binding,
        VddFinalizationOutcome::Pass,
        "required VDD review passed without unresolved findings".to_string(),
    )
}

#[allow(clippy::too_many_lines)] // Keep the complete pass-receipt invariant visible in one verifier.
fn classify_canonical_receipt(
    request: &CanonicalVddRequest,
    binding: &VddCandidateBinding,
    live_generation: &str,
    receipt: &CanonicalVddReceipt,
) -> Result<String, (VddNonPassOutcome, String)> {
    match request.worker_result().terminal {
        WorkerTerminalState::Succeeded => {}
        WorkerTerminalState::Cancelled => {
            return Err((
                VddNonPassOutcome::Cancelled,
                "cancelled worker output cannot be published as success".to_string(),
            ));
        }
        WorkerTerminalState::Failed | WorkerTerminalState::Orphaned => {
            return Err((
                VddNonPassOutcome::Fail,
                "non-successful worker output cannot be published as success".to_string(),
            ));
        }
    }
    if binding.generation.is_empty()
        || binding.generation.len() > MAX_CANDIDATE_GENERATION_BYTES
        || live_generation != binding.generation.as_str()
    {
        return Err((
            VddNonPassOutcome::Stale,
            "live artifact generation differs from the reviewed candidate".to_string(),
        ));
    }
    if receipt.task_id != request.worker_result().task_id
        || receipt.task_revision != request.worker_result().task_revision
        || receipt.artifact_generation_before != binding.generation
        || receipt.artifact_generation_after.as_deref() != Some(binding.generation.as_str())
        || &receipt.worker_identity != request.worker_identity()
        || receipt.completed_at < request.worker_result().recorded_at
    {
        return Err((
            VddNonPassOutcome::Stale,
            "VDD receipt does not bind the exact task, worker, and artifact generation".to_string(),
        ));
    }
    let mapped = map_canonical_non_pass(receipt);
    if let Some(outcome) = mapped {
        return Err((outcome, receipt.detail.clone()));
    }
    if receipt.verdict != CanonicalVddVerdict::Pass
        || receipt.reason != CanonicalVddTerminalReason::Passed
        || receipt.promotion_authority != VddPromotionAuthority::ProposedOnly
        || receipt.verifier_identity.is_none()
        || receipt.verifier_identity.as_ref() == Some(request.worker_identity())
        || receipt
            .verifier_agent_id
            .as_deref()
            .is_none_or(str::is_empty)
        || receipt.verifier_turns.is_none_or(|turns| turns == 0)
        || receipt.verifier_run.is_none()
        || receipt.verifier_budget.is_none()
        || receipt.cancellation_receipt.is_some()
        || receipt.report_sha256.is_none()
    {
        return Err((
            VddNonPassOutcome::VerifierError,
            "passing VDD receipt lacks required independent-run evidence".to_string(),
        ));
    }
    if request
        .deterministic_receipts()
        .iter()
        .any(|receipt| receipt.outcome != DeterministicCheckOutcome::Passed)
        || !request.unresolved_uncertainties().is_empty()
    {
        return Err((
            VddNonPassOutcome::Inconclusive,
            "deterministic evidence or worker uncertainty is not resolved".to_string(),
        ));
    }
    let Some(report) = receipt.report.as_ref() else {
        return Err((
            VddNonPassOutcome::VerifierError,
            "passing VDD receipt omitted its strict verifier report".to_string(),
        ));
    };
    let expected = request
        .acceptance_criteria()
        .iter()
        .map(|criterion| criterion.digest)
        .collect::<BTreeSet<_>>();
    let reported = report
        .criteria
        .iter()
        .map(|criterion| criterion.criterion_sha256)
        .collect::<BTreeSet<_>>();
    if report.verdict != CanonicalModelVerdict::Pass
        || report.criteria.iter().any(|criterion| {
            criterion.outcome != CanonicalCriterionOutcome::Pass || criterion.evidence.is_empty()
        })
        || expected != reported
        || !report.findings.is_empty()
        || !report.uncertainties.is_empty()
    {
        return Err((
            VddNonPassOutcome::VerifierError,
            "passing VDD receipt contains a contradictory or incomplete report".to_string(),
        ));
    }
    Ok("canonical VDD receipt passed for the exact live worker artifact".to_string())
}

fn map_canonical_non_pass(receipt: &CanonicalVddReceipt) -> Option<VddNonPassOutcome> {
    if receipt.verdict == CanonicalVddVerdict::Pass
        && receipt.reason == CanonicalVddTerminalReason::Passed
    {
        return None;
    }
    Some(match receipt.reason {
        CanonicalVddTerminalReason::ArtifactStale => VddNonPassOutcome::Stale,
        CanonicalVddTerminalReason::Cancelled => VddNonPassOutcome::Cancelled,
        CanonicalVddTerminalReason::Disabled
        | CanonicalVddTerminalReason::ModelUnavailable
        | CanonicalVddTerminalReason::DeterministicEvidenceUnavailable => {
            VddNonPassOutcome::Unavailable
        }
        CanonicalVddTerminalReason::IncompleteEvidence => VddNonPassOutcome::Inconclusive,
        CanonicalVddTerminalReason::Findings => VddNonPassOutcome::Fail,
        CanonicalVddTerminalReason::Passed
        | CanonicalVddTerminalReason::InvalidContract
        | CanonicalVddTerminalReason::ModelCollision
        | CanonicalVddTerminalReason::TimedOut
        | CanonicalVddTerminalReason::BudgetExhausted
        | CanonicalVddTerminalReason::Truncated
        | CanonicalVddTerminalReason::ParseFailure
        | CanonicalVddTerminalReason::TransportFailure => VddNonPassOutcome::VerifierError,
    })
}

const fn classify_legacy_error(error: &VddError) -> VddNonPassOutcome {
    match error {
        VddError::Capability(_) | VddError::ConfigError(_) => VddNonPassOutcome::Unavailable,
        VddError::AdversaryRequestFailed(_)
        | VddError::BuilderRevisionFailed(_)
        | VddError::ParseError(_)
        | VddError::Timeout { .. }
        | VddError::StaticAnalysisTimeout { .. }
        | VddError::CrosslinkError(_)
        | VddError::HttpError(_)
        | VddError::JsonError(_)
        | VddError::IoError(_) => VddNonPassOutcome::VerifierError,
    }
}

fn unavailable_binding_publication<T>(
    policy: &VddFinalizationPolicy,
    candidate: T,
    detail: String,
) -> VddPublication<T> {
    let binding = VddCandidateBinding {
        digest: ContentDigest::sha256(b"invalid-vdd-candidate-binding"),
        generation: "invalid".to_string(),
    };
    non_pass(
        policy,
        candidate,
        binding,
        VddNonPassOutcome::Unavailable,
        detail,
    )
}

const fn publish<T>(
    candidate: T,
    binding: VddCandidateBinding,
    outcome: VddFinalizationOutcome,
    detail: String,
) -> VddPublication<T> {
    VddPublication::Publish(VddPublishedCandidate {
        candidate,
        binding,
        outcome,
        blocked_outcome: None,
        detail,
    })
}

fn worker_finalization<T>(
    publication: VddPublication<T>,
    canonical_receipt: Option<serde_json::Value>,
) -> VddWorkerFinalization<T> {
    let (binding, outcome, blocked_outcome, detail_sha256) = match &publication {
        VddPublication::Publish(candidate) => (
            candidate.binding.clone(),
            candidate.outcome,
            candidate.blocked_outcome,
            ContentDigest::sha256(candidate.detail.as_bytes()),
        ),
        VddPublication::Withhold(candidate) => (
            candidate.binding.clone(),
            candidate.outcome.into(),
            Some(candidate.outcome),
            ContentDigest::sha256(candidate.detail.as_bytes()),
        ),
    };
    let canonical_receipt_sha256 = canonical_receipt
        .as_ref()
        .and_then(|receipt| serde_json::to_vec(receipt).ok().map(ContentDigest::sha256));
    VddWorkerFinalization {
        publication,
        record: VddWorkerFinalizationRecord {
            binding,
            outcome,
            blocked_outcome,
            detail_sha256,
            canonical_receipt_sha256,
            canonical_receipt,
            finalized_at: Utc::now(),
        },
    }
}

fn non_pass<T>(
    policy: &VddFinalizationPolicy,
    candidate: T,
    binding: VddCandidateBinding,
    outcome: VddNonPassOutcome,
    detail: String,
) -> VddPublication<T> {
    if policy.requirement == VddFinalizationRequirement::Advisory {
        return VddPublication::Publish(VddPublishedCandidate {
            candidate,
            binding,
            outcome: VddFinalizationOutcome::Advisory,
            blocked_outcome: Some(outcome),
            detail,
        });
    }
    match &policy.failure_policy {
        VddFailurePolicy::Withhold => VddPublication::Withhold(VddWithheldCandidate {
            binding,
            outcome,
            detail,
        }),
        VddFailurePolicy::HostSelectedFailOpen { reason } => {
            VddPublication::Publish(VddPublishedCandidate {
                candidate,
                binding,
                outcome: VddFinalizationOutcome::FailOpen,
                blocked_outcome: Some(outcome),
                detail: format!("{detail}; host fail-open: {reason}"),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::TokenUsage;
    use crate::vdd::{
        AdversaryReview, Finding, Severity, StaticAnalysisResult, VddAdvisoryResult,
        VddBlockingTextResult, VddIteration, VddSession,
    };

    fn binding() -> VddCandidateBinding {
        VddCandidateBinding {
            digest: ContentDigest::sha256(b"candidate"),
            generation: "response-v1:test".to_string(),
        }
    }

    fn finding(status: FindingStatus) -> Finding {
        Finding {
            id: "finding-1".to_string(),
            severity: Severity::High,
            cwe: Some("CWE-20".to_string()),
            description: "checked defect".to_string(),
            file_path: Some("src/lib.rs".to_string()),
            line_range: Some((1, 1)),
            status,
            adversary_reasoning: "current source evidence".to_string(),
            iteration: 1,
        }
    }

    fn static_result(passed: bool) -> StaticAnalysisResult {
        StaticAnalysisResult {
            command: "check".to_string(),
            exit_code: i32::from(!passed),
            stdout: String::new(),
            stderr: String::new(),
            passed,
        }
    }

    fn blocking_session(
        findings: Vec<Finding>,
        static_analysis: Vec<StaticAnalysisResult>,
    ) -> VddSession {
        let genuine_count = u32::try_from(
            findings
                .iter()
                .filter(|finding| finding.status == FindingStatus::Genuine)
                .count(),
        )
        .expect("test finding count");
        let false_positive_count = u32::try_from(
            findings
                .iter()
                .filter(|finding| finding.status == FindingStatus::FalsePositive)
                .count(),
        )
        .expect("test finding count");
        let mut session = VddSession::new(VddMode::Blocking);
        session.record_iteration(VddIteration {
            number: 1,
            builder_response: "reviewed candidate".to_string(),
            static_analysis,
            adversary_review: AdversaryReview {
                iteration: 1,
                findings,
                raw_response: "{}".to_string(),
                tokens_used: TokenUsage::default(),
                timestamp: Utc::now(),
            },
            genuine_count,
            false_positive_count,
        });
        session.finalize(true, "review loop terminated");
        session
    }

    #[test]
    fn required_review_withholds_findings_and_failed_static_evidence() {
        for (findings, static_analysis) in [
            (vec![finding(FindingStatus::Genuine)], vec![]),
            (vec![finding(FindingStatus::Disputed)], vec![]),
            (vec![], vec![static_result(false)]),
        ] {
            let publication = finalize_advisory_review(
                &VddFinalizationPolicy::required(),
                "candidate".to_string(),
                binding(),
                &findings,
                &static_analysis,
            );
            assert!(matches!(
                publication,
                VddPublication::Withhold(VddWithheldCandidate {
                    outcome: VddNonPassOutcome::Fail,
                    ..
                })
            ));
        }
    }

    #[test]
    fn advisory_review_preserves_publication_and_labels_non_pass() {
        let policy = VddFinalizationPolicy {
            requirement: VddFinalizationRequirement::Advisory,
            failure_policy: VddFailurePolicy::Withhold,
        };
        let publication = finalize_advisory_review(
            &policy,
            "candidate".to_string(),
            binding(),
            &[finding(FindingStatus::Genuine)],
            &[static_result(false)],
        );
        assert_eq!(publication.outcome(), VddFinalizationOutcome::Advisory);
        assert!(publication.is_publishable());
    }

    #[test]
    fn fail_open_requires_an_explicit_bounded_host_reason() {
        assert!(VddFinalizationPolicy::required()
            .with_host_fail_open(" ")
            .is_err());
        assert!(VddFinalizationPolicy::from_config(&VddConfig::default())
            .with_host_fail_open("operator accepted degraded review")
            .is_err());

        let policy = VddFinalizationPolicy::required()
            .with_host_fail_open("operator accepted degraded review")
            .expect("explicit host fail-open policy");
        let publication = non_pass(
            &policy,
            "candidate".to_string(),
            binding(),
            VddNonPassOutcome::VerifierError,
            "verifier transport failed".to_string(),
        );
        let VddPublication::Publish(published) = publication else {
            panic!("explicit host fail-open must publish");
        };
        assert_eq!(published.outcome(), VddFinalizationOutcome::FailOpen);
        assert_eq!(
            published.blocked_outcome(),
            Some(VddNonPassOutcome::VerifierError)
        );
        assert!(published.detail().contains("operator accepted"));
    }

    #[test]
    fn withheld_publication_does_not_return_candidate_bytes() {
        let publication = non_pass(
            &VddFinalizationPolicy::required(),
            vec![1_u8, 2, 3],
            binding(),
            VddNonPassOutcome::Stale,
            "generation changed".to_string(),
        );
        let VddPublication::Withhold(withheld) = publication else {
            panic!("stale required review must withhold");
        };
        assert_eq!(withheld.outcome(), VddNonPassOutcome::Stale);
        assert_eq!(withheld.binding(), &binding());
    }

    #[test]
    fn advisory_result_shape_can_be_consumed_without_conferring_authority() {
        let result = VddAdvisoryResult {
            findings: vec![finding(FindingStatus::FalsePositive)],
            context_observation: None,
            static_analysis: vec![static_result(true)],
            tokens_used: TokenUsage::default(),
            provider_receipts: Vec::new(),
        };
        let publication = finalize_advisory_review(
            &VddFinalizationPolicy::required(),
            "candidate".to_string(),
            binding(),
            &result.findings,
            &result.static_analysis,
        );
        assert_eq!(publication.outcome(), VddFinalizationOutcome::Pass);
    }

    #[test]
    fn blocking_publication_requires_clean_terminal_evidence() {
        assert!(blocking_session_has_clean_final_iteration(
            &blocking_session(
                vec![finding(FindingStatus::FalsePositive)],
                vec![static_result(true)],
            )
        ));
        assert!(!blocking_session_has_clean_final_iteration(
            &blocking_session(
                vec![finding(FindingStatus::Genuine)],
                vec![static_result(true)],
            )
        ));
        assert!(!blocking_session_has_clean_final_iteration(
            &blocking_session(Vec::new(), vec![static_result(false)],)
        ));
    }

    #[test]
    fn blocking_text_publication_binds_and_returns_the_reviewed_revision() {
        let directory = tempfile::tempdir().expect("run directory");
        let run = crate::tools::security::test_run_context_for(directory.path());
        let result = finalize_blocking_text_review(
            &run,
            &VddFinalizationPolicy::required(),
            "test-scope",
            "unreviewed candidate".to_string(),
            VddBlockingTextResult {
                final_text: "reviewed candidate".to_string(),
                session: blocking_session(Vec::new(), vec![static_result(true)]),
                crosslink_issues: Vec::new(),
                provider_receipts: Vec::new(),
            },
        );
        let VddPublication::Publish(published) = result.publication else {
            panic!("clean blocking result must publish");
        };
        assert_eq!(published.candidate.as_str(), "reviewed candidate");
        assert_eq!(
            published.binding().digest(),
            ContentDigest::sha256(b"reviewed candidate")
        );
        assert_eq!(published.outcome(), VddFinalizationOutcome::Pass);
    }

    #[test]
    fn worker_finalization_record_detects_receipt_substitution() {
        let finalized = worker_finalization(
            publish(
                b"candidate".to_vec(),
                binding(),
                VddFinalizationOutcome::Pass,
                "verified".to_string(),
            ),
            Some(serde_json::json!({"verdict": "pass", "generation": 7})),
        );
        let (_, record) = finalized.into_parts();
        assert!(record.receipt_digest_is_valid());

        let mut substituted = record;
        substituted.canonical_receipt =
            Some(serde_json::json!({"verdict": "pass", "generation": 8}));
        assert!(!substituted.receipt_digest_is_valid());
    }
}
