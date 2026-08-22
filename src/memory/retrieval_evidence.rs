//! Artifact-bound evaluation and promotion for technical-memory retrieval.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};
use std::str::FromStr as _;
use std::sync::OnceLock;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::runtime::ContentDigest;

use super::retrieval::rank_technical_lessons;
use super::{
    LessonCitationKind, LogicalMemoryId, MemoryAttribution, MemoryDigest, MemoryProvenance,
    MemoryRecordScope, MemoryRevision, MemorySourceEvidence, MemorySourceKind, MemoryStoreId,
    TechnicalLesson, TechnicalLessonDraft, TechnicalLessonRecord, TechnicalRetrievalContext,
    TechnicalRetrievalPolicyId, TechnicalRetrievalPolicyStatus, WorkspaceMemoryId,
    TECHNICAL_LESSON_TAG,
};

const RETRIEVAL_EVIDENCE_SCHEMA_VERSION: u16 = 1;
const MIN_EVALUATION_TRIALS: u8 = 3;
const MAX_EVALUATION_TRIALS: u8 = 16;
const MAX_CORPUS_ARTIFACT_BYTES: usize = 262_144;
const MAX_EVALUATION_ARTIFACT_BYTES: usize = 262_144;
const MAX_REVIEW_ARTIFACT_BYTES: usize = 65_536;
const MAX_CORPUS_LESSONS: usize = 256;
const MAX_CORPUS_CASES: usize = 128;
const MAX_CORPUS_CASE_CANDIDATES: usize = 128;
// Per trial: every corpus case may exercise scoring plus a quadratic sort
// bound and a second quadratic diversity-selection bound.
const MAX_DETERMINISTIC_WORK_UNITS_PER_TRIAL: u64 = 4_210_688;
const MAX_CASE_IDS: usize = 128;
const MAX_EVIDENCE_TEXT_BYTES: usize = 4_096;
const MAX_EVIDENCE_ID_BYTES: usize = 160;
const MAX_CITATION_VERIFICATION_RECEIPTS: usize = 1_024;
const MAX_CITATION_SOURCE_BYTES: u64 = 8 * 1_024 * 1_024;
const RETRIEVAL_EVALUATOR_CONFIG: &[u8] = b"openclaudia.technical-retrieval.v1;ablation=lexical,field_weighted,task_context,freshness,threshold,diversity;title=12;observation=7;guidance=6;applicability=10;exact=16;context=24;stage=12;stale_penalty=12;minimum=12;explicit_context_gate=threshold_and_diverse;diversity_penalty=8;query_terms=32;corpus_candidates=128;runtime_candidates=512;scan_bytes=4194304;result_records=20;runtime_output_bytes=65536;runtime_token_upper_bound=65536;context_items=64;canonical_context=lowercase;work_units=score_n+sort_n2+diversity_n2;work_budget=4210688;token_estimate=byte_upper_bound;citation_receipts=1024;citation_source_bytes=8388608;semantic=disabled";

const BUNDLED_TUNING_CORPUS: &str =
    include_str!("../../capabilities/technical-memory-retrieval-tuning.json");
const BUNDLED_HELD_OUT_CORPUS: &str =
    include_str!("../../capabilities/technical-memory-retrieval-heldout.json");
const BUNDLED_EVALUATION: &str =
    include_str!("../../capabilities/technical-memory-retrieval-evaluation.json");
const BUNDLED_REVIEW: &str =
    include_str!("../../capabilities/technical-memory-retrieval-review.json");
static PROMOTED_RUNTIME_POLICY: OnceLock<Result<TechnicalRetrievalPolicyId, ()>> = OnceLock::new();

type RepositoryCitationKey = (LessonCitationKind, String, String, MemoryDigest);

/// Tuning and final-evaluation partitions are deliberately distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalCorpusSplit {
    Tuning,
    HeldOut,
}

/// Synthetic storage state exercised by an evaluation case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalFixtureState {
    Available,
    Expired,
    Conflicted,
}

/// One typed lesson fixture. Its payload uses the production lesson schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalCorpusLesson {
    pub id: String,
    pub draft: TechnicalLessonDraft,
    pub scope: MemoryRecordScope,
    pub captured_at_unix_seconds: i64,
    pub due_for_review: bool,
    pub state: RetrievalFixtureState,
}

/// Expected typed state of one evaluation call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalExpectedState {
    Complete,
    NoHit,
    Partial,
    Stale,
    Conflicted,
    StoreError,
}

/// Failure injected by the final-environment corpus harness before ranking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalInjectedFailure {
    StoreError,
}

/// One repository-task retrieval scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalEvaluationCase {
    pub id: String,
    pub query: String,
    pub context: TechnicalRetrievalContext,
    pub limit: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub injected_failure: Option<RetrievalInjectedFailure>,
    pub candidate_ids: Vec<String>,
    pub expected_relevant_ids: Vec<String>,
    pub forbidden_ids: Vec<String>,
    pub expected_top_id: Option<String>,
    pub expected_state: RetrievalExpectedState,
}

/// Versioned repository-specific corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicalRetrievalCorpus {
    pub schema_version: u16,
    pub corpus_id: String,
    pub split: RetrievalCorpusSplit,
    pub generator_id: String,
    pub repository_revision_id: String,
    pub repository_revision_digest: ContentDigest,
    pub evaluation_now_unix_seconds: i64,
    pub lessons: Vec<RetrievalCorpusLesson>,
    pub cases: Vec<RetrievalEvaluationCase>,
}

/// Deterministic aggregate metrics for one policy and one corpus partition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalEvaluationMetrics {
    pub cases: u32,
    pub recall_numerator: u32,
    pub recall_denominator: u32,
    pub precision_numerator: u32,
    pub precision_denominator: u32,
    /// Citations covered by the evaluation's exact repository-byte receipts.
    /// Standalone corpus reports are provisional until bundled with those
    /// receipts and an independent review.
    pub citations_correct: u32,
    pub citations_returned: u32,
    pub harmful_returns: u32,
    pub stale_returns: u32,
    pub evidence_choice_successes: u32,
    pub state_classification_successes: u32,
    pub evidence_bytes: u64,
    pub estimated_evidence_tokens: u64,
    pub remote_cost_microusd: u64,
    pub deterministic_work_units: u64,
}

impl RetrievalEvaluationMetrics {
    fn recall_ppm(&self) -> u64 {
        ratio_ppm(self.recall_numerator, self.recall_denominator)
    }

    fn precision_ppm(&self) -> u64 {
        ratio_ppm(self.precision_numerator, self.precision_denominator)
    }

    fn task_success_ppm(&self) -> u64 {
        ratio_ppm(self.evidence_choice_successes, self.cases)
    }
}

/// One final-environment deterministic trial receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalTrialReceipt {
    pub trial: u8,
    pub output_digest: ContentDigest,
    pub elapsed_micros: u64,
}

/// Recomputed typed outcome for one evaluation scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalCaseOutcomeReceipt {
    pub case_id: String,
    pub state: RetrievalExpectedState,
    pub returned_ids: Vec<String>,
}

/// Multi-trial result for one policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalPolicyReport {
    pub policy: TechnicalRetrievalPolicyId,
    pub metrics: RetrievalEvaluationMetrics,
    pub case_receipts: Vec<RetrievalCaseOutcomeReceipt>,
    pub trials: Vec<RetrievalTrialReceipt>,
}

/// Retrieval mechanism evaluated or explicitly unavailable in this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalMechanism {
    LexicalCandidateGeneration,
    SemanticEmbeddings,
    TaskConditioning,
    HybridDenseSparse,
    SparseFieldReranking,
    Diversity,
    Freshness,
    SufficiencyThreshold,
}

/// Truthful mechanism disposition in the exact final environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalMechanismStatus {
    Evaluated,
    Unavailable,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalMechanismAssessment {
    pub mechanism: RetrievalMechanism,
    pub status: RetrievalMechanismStatus,
    pub reason: String,
}

/// Final-environment verification of one unique repository citation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalCitationVerificationReceipt {
    pub kind: LessonCitationKind,
    pub locator: String,
    pub source_version: String,
    pub expected_digest: MemoryDigest,
    pub observed_digest: MemoryDigest,
    pub byte_len: u64,
}

/// Declared bounds checked during evaluation and runtime validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalEvaluationBudgets {
    pub max_candidates_per_case: usize,
    pub max_runtime_candidates_per_call: usize,
    pub max_result_records: usize,
    pub max_runtime_output_bytes: usize,
    pub max_runtime_evidence_tokens: u64,
    pub max_context_items: usize,
    pub max_deterministic_work_units_per_trial: u64,
    pub max_evidence_tokens_per_trial: u64,
    pub max_latency_micros_per_trial: u64,
    pub max_remote_cost_microusd_per_trial: u64,
}

/// Exact tuning and held-out evaluation output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicalRetrievalEvaluation {
    pub schema_version: u16,
    pub evaluation_id: String,
    pub generator_id: String,
    pub evaluator_model_id: String,
    pub evaluator_config_digest: ContentDigest,
    pub tuning_corpus_id: String,
    pub tuning_corpus_digest: ContentDigest,
    pub held_out_corpus_id: String,
    pub held_out_corpus_digest: ContentDigest,
    pub trial_count: u8,
    pub selected_policy: TechnicalRetrievalPolicyId,
    pub budgets: RetrievalEvaluationBudgets,
    pub mechanisms: Vec<RetrievalMechanismAssessment>,
    pub citation_verification_receipts: Vec<RetrievalCitationVerificationReceipt>,
    pub tuning_reports: Vec<RetrievalPolicyReport>,
    pub held_out_reports: Vec<RetrievalPolicyReport>,
    pub limitations: Vec<String>,
}

/// Independent review verdict for the exact evaluation artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalReviewVerdict {
    Approved,
    Rejected,
}

/// Required dimensions for independent review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalReviewDimension {
    SplitIsolation,
    BaselineCoverage,
    AdversarialStates,
    RuntimeParity,
    PrivacyAndCost,
    ArtifactAndResourceBounds,
}

/// Digest-bound independent review of the exact corpora and evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicalRetrievalReview {
    pub schema_version: u16,
    pub review_id: String,
    pub reviewer_id: String,
    pub reviewer_model_id: String,
    pub reviewer_config_digest: ContentDigest,
    pub evaluation_generator_id: String,
    pub tuning_corpus_digest: ContentDigest,
    pub held_out_corpus_digest: ContentDigest,
    pub evaluation_digest: ContentDigest,
    pub verdict: RetrievalReviewVerdict,
    pub reviewed_dimensions: Vec<RetrievalReviewDimension>,
    pub limitations: Vec<String>,
}

/// Fully validated retrieval evidence used for runtime promotion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TechnicalRetrievalEvidenceBundle {
    tuning: TechnicalRetrievalCorpus,
    held_out: TechnicalRetrievalCorpus,
    evaluation: TechnicalRetrievalEvaluation,
    review: TechnicalRetrievalReview,
}

impl TechnicalRetrievalEvidenceBundle {
    /// Parse and validate the bundled S-105 evidence.
    ///
    /// # Errors
    ///
    /// Returns a typed error when any artifact, digest, metric, baseline,
    /// review, bound, or promotion invariant is invalid.
    pub fn bundled() -> Result<Self, TechnicalRetrievalEvidenceError> {
        Self::from_sources(
            BUNDLED_TUNING_CORPUS,
            BUNDLED_HELD_OUT_CORPUS,
            BUNDLED_EVALUATION,
            BUNDLED_REVIEW,
        )
    }

    /// Parse and validate explicit artifacts for release tooling and tests.
    ///
    /// # Errors
    ///
    /// Returns a typed validation failure without exposing an unchecked
    /// promotion decision.
    pub fn from_sources(
        tuning_source: &str,
        held_out_source: &str,
        evaluation_source: &str,
        review_source: &str,
    ) -> Result<Self, TechnicalRetrievalEvidenceError> {
        validate_artifact_size("tuning corpus", tuning_source, MAX_CORPUS_ARTIFACT_BYTES)?;
        validate_artifact_size(
            "held-out corpus",
            held_out_source,
            MAX_CORPUS_ARTIFACT_BYTES,
        )?;
        validate_artifact_size(
            "evaluation",
            evaluation_source,
            MAX_EVALUATION_ARTIFACT_BYTES,
        )?;
        validate_artifact_size("review", review_source, MAX_REVIEW_ARTIFACT_BYTES)?;
        let tuning = parse_artifact("tuning corpus", tuning_source)?;
        let held_out = parse_artifact("held-out corpus", held_out_source)?;
        let evaluation = parse_artifact("evaluation", evaluation_source)?;
        let review = parse_artifact("review", review_source)?;
        validate_bundle(
            &tuning,
            &held_out,
            &evaluation,
            &review,
            ContentDigest::sha256(tuning_source),
            ContentDigest::sha256(held_out_source),
            ContentDigest::sha256(evaluation_source),
        )?;
        Ok(Self {
            tuning,
            held_out,
            evaluation,
            review,
        })
    }

    #[must_use]
    pub const fn selected_policy(&self) -> TechnicalRetrievalPolicyId {
        self.evaluation.selected_policy
    }

    #[must_use]
    pub const fn evaluation(&self) -> &TechnicalRetrievalEvaluation {
        &self.evaluation
    }

    #[must_use]
    pub const fn tuning(&self) -> &TechnicalRetrievalCorpus {
        &self.tuning
    }

    #[must_use]
    pub const fn held_out(&self) -> &TechnicalRetrievalCorpus {
        &self.held_out
    }

    #[must_use]
    pub const fn review(&self) -> &TechnicalRetrievalReview {
        &self.review
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnicalRetrievalEvidenceCode {
    ArtifactTooLarge,
    ParseFailed,
    UnsupportedSchema,
    InvalidBounds,
    InvalidIdentifier,
    DuplicateIdentifier,
    NonCanonicalCollection,
    InvalidReference,
    SplitContamination,
    DigestMismatch,
    MissingBaseline,
    UnderTrial,
    MetricsMismatch,
    UnmeasuredMechanism,
    PromotionNotImproved,
    ReviewRejected,
    SelfReview,
    IncompleteReview,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("technical retrieval evidence {code:?} in {artifact}: {detail}")]
pub struct TechnicalRetrievalEvidenceError {
    pub code: TechnicalRetrievalEvidenceCode,
    pub artifact: String,
    pub detail: String,
}

/// Generate deterministic policy reports for a validated corpus.
///
/// The elapsed time is observational final-environment evidence; all ranking
/// output and aggregate metrics are independently recomputed during bundle
/// validation.
///
/// # Errors
///
/// Returns a typed error when the corpus or trial count is invalid.
pub fn evaluate_technical_retrieval_corpus(
    corpus: &TechnicalRetrievalCorpus,
    trial_count: u8,
) -> Result<Vec<RetrievalPolicyReport>, TechnicalRetrievalEvidenceError> {
    validate_corpus(corpus, corpus.split)?;
    if !(MIN_EVALUATION_TRIALS..=MAX_EVALUATION_TRIALS).contains(&trial_count) {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::UnderTrial,
            &corpus.corpus_id,
            "trial count is outside the accepted range",
        ));
    }
    all_evaluated_policies()
        .into_iter()
        .map(|policy| {
            let evaluated = (1..=trial_count)
                .map(|trial| evaluate_trial(corpus, policy, trial))
                .collect::<Result<Vec<_>, _>>()?;
            let metrics = evaluated
                .first()
                .map(|trial| trial.metrics.clone())
                .ok_or_else(|| {
                    evidence_error(
                        TechnicalRetrievalEvidenceCode::UnderTrial,
                        &corpus.corpus_id,
                        "evaluation produced no trials",
                    )
                })?;
            if evaluated.iter().any(|trial| trial.metrics != metrics) {
                return Err(evidence_error(
                    TechnicalRetrievalEvidenceCode::MetricsMismatch,
                    &corpus.corpus_id,
                    "deterministic trials produced different metrics",
                ));
            }
            let case_receipts = evaluated
                .first()
                .map(|trial| trial.case_receipts.clone())
                .ok_or_else(|| {
                    evidence_error(
                        TechnicalRetrievalEvidenceCode::UnderTrial,
                        &corpus.corpus_id,
                        "evaluation produced no case receipts",
                    )
                })?;
            if evaluated
                .iter()
                .any(|trial| trial.case_receipts != case_receipts)
            {
                return Err(evidence_error(
                    TechnicalRetrievalEvidenceCode::MetricsMismatch,
                    &corpus.corpus_id,
                    "deterministic trials produced different case receipts",
                ));
            }
            let trials = evaluated.into_iter().map(|trial| trial.receipt).collect();
            Ok(RetrievalPolicyReport {
                policy,
                metrics,
                case_receipts,
                trials,
            })
        })
        .collect()
}

/// Build an exact tuning/held-out evaluation artifact from corpus sources.
///
/// # Errors
///
/// Returns a typed error when either corpus, identifier, selected policy, or
/// trial count violates the evidence contract.
pub fn build_technical_retrieval_evaluation(
    tuning_source: &str,
    held_out_source: &str,
    repository_root: &Path,
    trial_count: u8,
    selected_policy: TechnicalRetrievalPolicyId,
    generator_id: &str,
    evaluator_model_id: &str,
) -> Result<TechnicalRetrievalEvaluation, TechnicalRetrievalEvidenceError> {
    validate_artifact_size("tuning corpus", tuning_source, MAX_CORPUS_ARTIFACT_BYTES)?;
    validate_artifact_size(
        "held-out corpus",
        held_out_source,
        MAX_CORPUS_ARTIFACT_BYTES,
    )?;
    validate_id("evaluation generator", generator_id)?;
    validate_text("evaluation model", evaluator_model_id)?;
    let tuning: TechnicalRetrievalCorpus = parse_artifact("tuning corpus", tuning_source)?;
    let held_out: TechnicalRetrievalCorpus = parse_artifact("held-out corpus", held_out_source)?;
    validate_corpus(&tuning, RetrievalCorpusSplit::Tuning)?;
    validate_corpus(&held_out, RetrievalCorpusSplit::HeldOut)?;
    let citation_verification_receipts =
        verify_repository_citations(&tuning, &held_out, repository_root)?;
    let tuning_reports = evaluate_technical_retrieval_corpus(&tuning, trial_count)?;
    let held_out_reports = evaluate_technical_retrieval_corpus(&held_out, trial_count)?;
    Ok(TechnicalRetrievalEvaluation {
        schema_version: RETRIEVAL_EVIDENCE_SCHEMA_VERSION,
        evaluation_id: "openclaudia-technical-memory-retrieval-evaluation-v1".to_string(),
        generator_id: generator_id.to_string(),
        evaluator_model_id: evaluator_model_id.to_string(),
        evaluator_config_digest: ContentDigest::sha256(RETRIEVAL_EVALUATOR_CONFIG),
        tuning_corpus_id: tuning.corpus_id,
        tuning_corpus_digest: ContentDigest::sha256(tuning_source),
        held_out_corpus_id: held_out.corpus_id,
        held_out_corpus_digest: ContentDigest::sha256(held_out_source),
        trial_count,
        selected_policy,
        budgets: RetrievalEvaluationBudgets {
            max_candidates_per_case: MAX_CORPUS_CASE_CANDIDATES,
            max_runtime_candidates_per_call: super::MAX_RETRIEVAL_CANDIDATES_SCANNED,
            max_result_records: 20,
            max_runtime_output_bytes: super::MAX_TECHNICAL_QUERY_RESULT_BYTES,
            max_runtime_evidence_tokens: u64::try_from(super::MAX_TECHNICAL_QUERY_RESULT_BYTES)
                .unwrap_or(u64::MAX),
            max_context_items: super::MAX_RETRIEVAL_CONTEXT_TOTAL_ITEMS,
            max_deterministic_work_units_per_trial:
                MAX_DETERMINISTIC_WORK_UNITS_PER_TRIAL,
            max_evidence_tokens_per_trial: 32_768,
            max_latency_micros_per_trial: 1_000_000,
            max_remote_cost_microusd_per_trial: 0,
        },
        mechanisms: default_mechanism_assessments(),
        citation_verification_receipts,
        tuning_reports,
        held_out_reports,
        limitations: vec![
            "Three deterministic trials prove repeatability and bounded final-environment execution, not stochastic model generalization.".to_string(),
            "No approved private semantic backend exists in this build; semantic and hybrid policies remain unavailable instead of sending private lessons to a remote service.".to_string(),
            "Evidence-choice success measures whether the retrieval result supplies the expected cited lesson; alternate-model downstream task grading remains part of canonical VDD S-088.".to_string(),
            "Citation verification rejects symbolic-link traversal and binds exact bytes in a trusted quiescent checkout; descriptor-safe verification under concurrent repository mutation remains a release/VDD boundary.".to_string(),
        ],
    })
}

pub fn runtime_policy_selection(
    has_task_context: bool,
) -> (TechnicalRetrievalPolicyId, TechnicalRetrievalPolicyStatus) {
    if !has_task_context {
        return (
            TechnicalRetrievalPolicyId::LexicalV1,
            TechnicalRetrievalPolicyStatus::CompatibilityBaseline,
        );
    }
    match PROMOTED_RUNTIME_POLICY.get_or_init(|| {
        TechnicalRetrievalEvidenceBundle::bundled()
            .map(|bundle| bundle.selected_policy())
            .map_err(|_| ())
    }) {
        Ok(policy) => (*policy, TechnicalRetrievalPolicyStatus::EvidenceApproved),
        Err(()) => (
            TechnicalRetrievalPolicyId::LexicalV1,
            TechnicalRetrievalPolicyStatus::EvidenceRejectedFallback,
        ),
    }
}

fn verify_repository_citations(
    tuning: &TechnicalRetrievalCorpus,
    held_out: &TechnicalRetrievalCorpus,
    repository_root: &Path,
) -> Result<Vec<RetrievalCitationVerificationReceipt>, TechnicalRetrievalEvidenceError> {
    let root = repository_root.canonicalize().map_err(|error| {
        evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidReference,
            "repository citations",
            format!("repository root is unavailable: {error}"),
        )
    })?;
    if !root.is_dir() {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidReference,
            "repository citations",
            "repository root is not a directory",
        ));
    }
    let expected = corpus_citation_keys(tuning, held_out)?;
    if expected.is_empty() || expected.len() > MAX_CITATION_VERIFICATION_RECEIPTS {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidBounds,
            "repository citations",
            "citation verification receipt count is invalid",
        ));
    }
    expected
        .into_iter()
        .map(|key| verify_repository_citation(&root, key))
        .collect()
}

fn verify_repository_citation(
    root: &Path,
    key: RepositoryCitationKey,
) -> Result<RetrievalCitationVerificationReceipt, TechnicalRetrievalEvidenceError> {
    let (kind, locator, source_version, expected_digest) = key;
    let relative = Path::new(&locator);
    if relative.is_absolute()
        || !relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidReference,
            &locator,
            "citation path is absolute or contains traversal",
        ));
    }
    let mut candidate = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err(evidence_error(
                TechnicalRetrievalEvidenceCode::InvalidReference,
                &locator,
                "citation path contains a non-normal component",
            ));
        };
        candidate.push(segment);
        let metadata = fs::symlink_metadata(&candidate).map_err(|error| {
            evidence_error(
                TechnicalRetrievalEvidenceCode::InvalidReference,
                &locator,
                format!("citation source is unavailable: {error}"),
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(evidence_error(
                TechnicalRetrievalEvidenceCode::InvalidReference,
                &locator,
                "citation path traverses a symbolic link",
            ));
        }
    }
    let metadata = fs::metadata(&candidate).map_err(|error| {
        evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidReference,
            &locator,
            format!("citation source metadata is unavailable: {error}"),
        )
    })?;
    if !metadata.is_file() || metadata.len() > MAX_CITATION_SOURCE_BYTES {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidBounds,
            &locator,
            "citation source is not a bounded regular file",
        ));
    }
    let bytes = fs::read(&candidate).map_err(|error| {
        evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidReference,
            &locator,
            format!("citation source cannot be read: {error}"),
        )
    })?;
    let byte_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if byte_len != metadata.len() || byte_len > MAX_CITATION_SOURCE_BYTES {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidBounds,
            &locator,
            "citation source changed or exceeded its byte bound during verification",
        ));
    }
    let observed_digest = MemoryDigest::sha256(&bytes);
    if observed_digest != expected_digest {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::DigestMismatch,
            &locator,
            "citation digest does not match final-environment repository bytes",
        ));
    }
    Ok(RetrievalCitationVerificationReceipt {
        kind,
        locator,
        source_version,
        expected_digest,
        observed_digest,
        byte_len,
    })
}

fn corpus_citation_keys(
    tuning: &TechnicalRetrievalCorpus,
    held_out: &TechnicalRetrievalCorpus,
) -> Result<BTreeSet<RepositoryCitationKey>, TechnicalRetrievalEvidenceError> {
    let mut keys = BTreeSet::new();
    for corpus in [tuning, held_out] {
        let baseline_version = format!("git:{}", corpus.repository_revision_id);
        for citation in corpus
            .lessons
            .iter()
            .flat_map(|lesson| &lesson.draft.citations)
        {
            if !matches!(
                citation.kind,
                LessonCitationKind::Configuration
                    | LessonCitationKind::Documentation
                    | LessonCitationKind::SourceFile
                    | LessonCitationKind::Test
            ) {
                return Err(evidence_error(
                    TechnicalRetrievalEvidenceCode::InvalidReference,
                    &citation.locator,
                    "evaluation citation kind is not repository-file verifiable",
                ));
            }
            validate_text("citation locator", &citation.locator)?;
            validate_text("citation source version", &citation.source_version)?;
            if citation.source_version != baseline_version
                && citation.source_version != "worktree:s105"
            {
                return Err(evidence_error(
                    TechnicalRetrievalEvidenceCode::InvalidReference,
                    &citation.locator,
                    "citation source version does not match the corpus repository generation",
                ));
            }
            keys.insert((
                citation.kind,
                citation.locator.clone(),
                citation.source_version.clone(),
                citation.digest.clone(),
            ));
        }
    }
    Ok(keys)
}

fn validate_bundle(
    tuning: &TechnicalRetrievalCorpus,
    held_out: &TechnicalRetrievalCorpus,
    evaluation: &TechnicalRetrievalEvaluation,
    review: &TechnicalRetrievalReview,
    tuning_digest: ContentDigest,
    held_out_digest: ContentDigest,
    evaluation_digest: ContentDigest,
) -> Result<(), TechnicalRetrievalEvidenceError> {
    validate_corpus(tuning, RetrievalCorpusSplit::Tuning)?;
    validate_corpus(held_out, RetrievalCorpusSplit::HeldOut)?;
    ensure_schema("evaluation", evaluation.schema_version)?;
    ensure_schema("review", review.schema_version)?;
    validate_text("evaluation", &evaluation.evaluation_id)?;
    validate_text("evaluation", &evaluation.generator_id)?;
    validate_text("evaluation", &evaluation.evaluator_model_id)?;
    if evaluation.evaluator_config_digest != ContentDigest::sha256(RETRIEVAL_EVALUATOR_CONFIG) {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::DigestMismatch,
            "evaluation",
            "evaluation configuration digest does not bind the runtime ranking contract",
        ));
    }
    if tuning.corpus_id == held_out.corpus_id {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::SplitContamination,
            "corpora",
            "tuning and held-out corpus identifiers must differ",
        ));
    }
    if tuning.repository_revision_id != held_out.repository_revision_id
        || tuning.repository_revision_digest != held_out.repository_revision_digest
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::SplitContamination,
            "corpora",
            "tuning and held-out corpora must bind the same repository revision",
        ));
    }
    let tuning_cases = tuning
        .cases
        .iter()
        .map(|case| case.id.as_str())
        .collect::<BTreeSet<_>>();
    if held_out
        .cases
        .iter()
        .any(|case| tuning_cases.contains(case.id.as_str()))
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::SplitContamination,
            "corpora",
            "tuning and held-out case identifiers overlap",
        ));
    }
    if evaluation.tuning_corpus_id != tuning.corpus_id
        || evaluation.held_out_corpus_id != held_out.corpus_id
        || evaluation.tuning_corpus_digest != tuning_digest
        || evaluation.held_out_corpus_digest != held_out_digest
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::DigestMismatch,
            "evaluation",
            "evaluation is not bound to the exact corpus artifacts",
        ));
    }
    if !(MIN_EVALUATION_TRIALS..=MAX_EVALUATION_TRIALS).contains(&evaluation.trial_count) {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::UnderTrial,
            "evaluation",
            "evaluation trial count is outside the accepted range",
        ));
    }
    validate_budgets(&evaluation.budgets)?;
    validate_mechanisms(&evaluation.mechanisms)?;
    validate_citation_receipts(tuning, held_out, &evaluation.citation_verification_receipts)?;
    validate_limitations("evaluation", &evaluation.limitations)?;
    validate_reports(
        tuning,
        &evaluation.tuning_reports,
        evaluation.trial_count,
        &evaluation.budgets,
    )?;
    validate_reports(
        held_out,
        &evaluation.held_out_reports,
        evaluation.trial_count,
        &evaluation.budgets,
    )?;
    validate_promotion(evaluation)?;
    validate_review(
        review,
        evaluation,
        tuning_digest,
        held_out_digest,
        evaluation_digest,
    )
}

fn validate_corpus(
    corpus: &TechnicalRetrievalCorpus,
    expected_split: RetrievalCorpusSplit,
) -> Result<(), TechnicalRetrievalEvidenceError> {
    ensure_schema(&corpus.corpus_id, corpus.schema_version)?;
    validate_id("corpus", &corpus.corpus_id)?;
    validate_text(&corpus.corpus_id, &corpus.generator_id)?;
    validate_repository_revision(corpus)?;
    if corpus.split != expected_split
        || corpus.lessons.is_empty()
        || corpus.lessons.len() > MAX_CORPUS_LESSONS
        || corpus.cases.is_empty()
        || corpus.cases.len() > MAX_CORPUS_CASES
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidBounds,
            &corpus.corpus_id,
            "corpus split, lesson count, or case count is invalid",
        ));
    }
    ensure_sorted_unique_ids(
        &corpus.corpus_id,
        corpus.lessons.iter().map(|lesson| lesson.id.as_str()),
    )?;
    ensure_sorted_unique_ids(
        &corpus.corpus_id,
        corpus.cases.iter().map(|case| case.id.as_str()),
    )?;
    let workspace = WorkspaceMemoryId::for_canonical_root(Path::new("/s105-evaluation"));
    let lessons = corpus
        .lessons
        .iter()
        .map(|fixture| {
            validate_id(&corpus.corpus_id, &fixture.id)?;
            if fixture.captured_at_unix_seconds < 0
                || fixture.captured_at_unix_seconds > corpus.evaluation_now_unix_seconds
                || fixture.scope == MemoryRecordScope::ProjectEvidence
            {
                return Err(evidence_error(
                    TechnicalRetrievalEvidenceCode::InvalidBounds,
                    &fixture.id,
                    "lesson capture time or production authority scope is invalid",
                ));
            }
            let lesson = TechnicalLesson::from_candidate(
                workspace.clone(),
                fixture.draft.clone(),
                fixture.captured_at_unix_seconds,
            )
            .map_err(|error| {
                evidence_error(
                    TechnicalRetrievalEvidenceCode::InvalidBounds,
                    &fixture.id,
                    error.to_string(),
                )
            })?;
            if fixture.due_for_review
                != lesson.is_due_for_review_at(corpus.evaluation_now_unix_seconds)
                || (fixture.state == RetrievalFixtureState::Expired)
                    != lesson.is_expired_at(corpus.evaluation_now_unix_seconds)
            {
                return Err(evidence_error(
                    TechnicalRetrievalEvidenceCode::InvalidReference,
                    &fixture.id,
                    "fixture freshness state does not match production retention evaluation",
                ));
            }
            Ok((fixture.id.as_str(), fixture))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    for case in &corpus.cases {
        validate_case(case, &lessons)?;
    }
    Ok(())
}

fn validate_repository_revision(
    corpus: &TechnicalRetrievalCorpus,
) -> Result<(), TechnicalRetrievalEvidenceError> {
    let revision = corpus.repository_revision_id.as_bytes();
    if !matches!(revision.len(), 40 | 64)
        || !revision.iter().all(u8::is_ascii_hexdigit)
        || revision.iter().any(u8::is_ascii_uppercase)
        || corpus.repository_revision_digest != ContentDigest::sha256(revision)
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::DigestMismatch,
            &corpus.corpus_id,
            "repository revision ID or digest is invalid",
        ));
    }
    Ok(())
}

fn validate_case(
    case: &RetrievalEvaluationCase,
    lessons: &BTreeMap<&str, &RetrievalCorpusLesson>,
) -> Result<(), TechnicalRetrievalEvidenceError> {
    validate_id("case", &case.id)?;
    validate_text(&case.id, &case.query)?;
    if case.query.trim().is_empty()
        || case.query != case.query.trim()
        || case.query.len() > 512
        || case.query.split_whitespace().count() > super::MAX_RETRIEVAL_QUERY_TERMS
        || case.limit == 0
        || case.limit > 20
        || case.candidate_ids.len() > MAX_CORPUS_CASE_CANDIDATES
        || case.expected_relevant_ids.len() > MAX_CASE_IDS
        || case.forbidden_ids.len() > MAX_CASE_IDS
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidBounds,
            &case.id,
            "query, limit, or identifier collection exceeds its bound",
        ));
    }
    if case.context.clone().canonicalize().map_err(|error| {
        evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidBounds,
            &case.id,
            error.to_string(),
        )
    })? != case.context
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::NonCanonicalCollection,
            &case.id,
            "task context is not canonical",
        ));
    }
    for ids in [
        &case.candidate_ids,
        &case.expected_relevant_ids,
        &case.forbidden_ids,
    ] {
        ensure_canonical_strings(&case.id, ids)?;
        if ids.iter().any(|id| !lessons.contains_key(id.as_str())) {
            return Err(evidence_error(
                TechnicalRetrievalEvidenceCode::InvalidReference,
                &case.id,
                "case references an unknown lesson",
            ));
        }
    }
    let candidates = case.candidate_ids.iter().collect::<BTreeSet<_>>();
    if case
        .expected_relevant_ids
        .iter()
        .chain(&case.forbidden_ids)
        .any(|id| !candidates.contains(id))
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidReference,
            &case.id,
            "expected or forbidden lesson is outside the candidate set",
        ));
    }
    if case
        .expected_relevant_ids
        .iter()
        .any(|id| case.forbidden_ids.binary_search(id).is_ok())
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidReference,
            &case.id,
            "one lesson cannot be both relevant and forbidden",
        ));
    }
    if let Some(expected_top) = &case.expected_top_id {
        if case
            .expected_relevant_ids
            .binary_search(expected_top)
            .is_err()
        {
            return Err(evidence_error(
                TechnicalRetrievalEvidenceCode::InvalidReference,
                &case.id,
                "expected top lesson is not relevant",
            ));
        }
    }
    validate_expected_state(case, lessons)
}

fn validate_expected_state(
    case: &RetrievalEvaluationCase,
    lessons: &BTreeMap<&str, &RetrievalCorpusLesson>,
) -> Result<(), TechnicalRetrievalEvidenceError> {
    let has_conflict = case.candidate_ids.iter().any(|id| {
        lessons
            .get(id.as_str())
            .is_some_and(|lesson| lesson.state == RetrievalFixtureState::Conflicted)
    });
    let has_expired = case.candidate_ids.iter().any(|id| {
        lessons
            .get(id.as_str())
            .is_some_and(|lesson| lesson.state == RetrievalFixtureState::Expired)
    });
    if case.injected_failure.is_some()
        && (case.expected_state != RetrievalExpectedState::StoreError
            || !case.candidate_ids.is_empty())
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidReference,
            &case.id,
            "injected store failure must be an empty store-error case",
        ));
    }
    if case.expected_state == RetrievalExpectedState::StoreError
        && case.injected_failure != Some(RetrievalInjectedFailure::StoreError)
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidReference,
            &case.id,
            "store-error expectation requires an explicit injected failure",
        ));
    }
    if has_conflict != (case.expected_state == RetrievalExpectedState::Conflicted) {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidReference,
            &case.id,
            "conflict expectation does not match the candidate fixture state",
        ));
    }
    match case.expected_state {
        RetrievalExpectedState::Conflicted | RetrievalExpectedState::StoreError => {
            if case.expected_top_id.is_some() || !case.expected_relevant_ids.is_empty() {
                return Err(evidence_error(
                    TechnicalRetrievalEvidenceCode::InvalidReference,
                    &case.id,
                    "failed retrieval state cannot declare relevant or top lessons",
                ));
            }
        }
        RetrievalExpectedState::NoHit => {
            if case.expected_top_id.is_some() || !case.expected_relevant_ids.is_empty() {
                return Err(evidence_error(
                    TechnicalRetrievalEvidenceCode::InvalidReference,
                    &case.id,
                    "no-hit state cannot declare relevant or top lessons",
                ));
            }
        }
        RetrievalExpectedState::Partial if case.expected_relevant_ids.is_empty() => {
            if case.expected_top_id.is_some() || !has_expired {
                return Err(evidence_error(
                    TechnicalRetrievalEvidenceCode::InvalidReference,
                    &case.id,
                    "empty partial retrieval requires an omitted expired fixture",
                ));
            }
        }
        RetrievalExpectedState::Partial => validate_returned_evidence(case, lessons, None)?,
        RetrievalExpectedState::Complete => {
            validate_returned_evidence(case, lessons, Some(false))?;
        }
        RetrievalExpectedState::Stale => {
            validate_returned_evidence(case, lessons, Some(true))?;
        }
    }
    Ok(())
}

fn validate_returned_evidence(
    case: &RetrievalEvaluationCase,
    lessons: &BTreeMap<&str, &RetrievalCorpusLesson>,
    require_stale: Option<bool>,
) -> Result<(), TechnicalRetrievalEvidenceError> {
    if case.expected_top_id.is_none() || case.expected_relevant_ids.is_empty() {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidReference,
            &case.id,
            "returned retrieval state requires relevant and top evidence",
        ));
    }
    if case.expected_relevant_ids.iter().any(|id| {
        lessons
            .get(id.as_str())
            .is_none_or(|lesson| lesson.state != RetrievalFixtureState::Available)
    }) {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidReference,
            &case.id,
            "relevant retrieval evidence must be available",
        ));
    }
    if let Some(require_stale) = require_stale {
        let relevant_is_stale = case.expected_relevant_ids.iter().any(|id| {
            lessons
                .get(id.as_str())
                .is_some_and(|lesson| lesson.due_for_review)
        });
        if require_stale != relevant_is_stale {
            return Err(evidence_error(
                TechnicalRetrievalEvidenceCode::InvalidReference,
                &case.id,
                "stale expectation does not match relevant fixture state",
            ));
        }
    }
    Ok(())
}

fn validate_reports(
    corpus: &TechnicalRetrievalCorpus,
    reports: &[RetrievalPolicyReport],
    trial_count: u8,
    budgets: &RetrievalEvaluationBudgets,
) -> Result<(), TechnicalRetrievalEvidenceError> {
    let expected_policies = all_evaluated_policies();
    if reports
        .iter()
        .map(|report| report.policy)
        .collect::<Vec<_>>()
        != expected_policies
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::MissingBaseline,
            &corpus.corpus_id,
            "policy reports must contain every baseline and evaluated policy in canonical order",
        ));
    }
    for report in reports {
        if report.trials.len() != usize::from(trial_count) {
            return Err(evidence_error(
                TechnicalRetrievalEvidenceCode::UnderTrial,
                &corpus.corpus_id,
                "policy report has the wrong trial count",
            ));
        }
        for (index, receipt) in report.trials.iter().enumerate() {
            let expected = evaluate_trial(
                corpus,
                report.policy,
                u8::try_from(index + 1).unwrap_or(u8::MAX),
            )?;
            if receipt.trial != expected.receipt.trial
                || receipt.output_digest != expected.receipt.output_digest
                || report.metrics != expected.metrics
                || report.case_receipts != expected.case_receipts
            {
                return Err(evidence_error(
                    TechnicalRetrievalEvidenceCode::MetricsMismatch,
                    &corpus.corpus_id,
                    "policy receipt does not match recomputed runtime ranking",
                ));
            }
            if receipt.elapsed_micros > budgets.max_latency_micros_per_trial
                || expected.receipt.elapsed_micros > budgets.max_latency_micros_per_trial
                || report.metrics.deterministic_work_units
                    > budgets.max_deterministic_work_units_per_trial
                || report.metrics.estimated_evidence_tokens > budgets.max_evidence_tokens_per_trial
                || report.metrics.remote_cost_microusd > budgets.max_remote_cost_microusd_per_trial
            {
                return Err(evidence_error(
                    TechnicalRetrievalEvidenceCode::InvalidBounds,
                    &corpus.corpus_id,
                    "policy receipt exceeds a declared resource budget",
                ));
            }
        }
    }
    Ok(())
}

fn validate_promotion(
    evaluation: &TechnicalRetrievalEvaluation,
) -> Result<(), TechnicalRetrievalEvidenceError> {
    if matches!(
        evaluation.selected_policy,
        TechnicalRetrievalPolicyId::NoMemory | TechnicalRetrievalPolicyId::LexicalV1
    ) {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::PromotionNotImproved,
            "evaluation",
            "selected policy must be an evaluated improvement over the simple baselines",
        ));
    }
    for reports in [&evaluation.tuning_reports, &evaluation.held_out_reports] {
        validate_incremental_policy_benefit(reports, evaluation.selected_policy)?;
        let baseline = policy_metrics(reports, TechnicalRetrievalPolicyId::LexicalV1)?;
        let selected = policy_metrics(reports, evaluation.selected_policy)?;
        let selected_is_complete = selected.recall_ppm() == 1_000_000
            && selected.precision_ppm() == 1_000_000
            && selected.task_success_ppm() == 1_000_000
            && selected.state_classification_successes == selected.cases
            && selected.harmful_returns == 0
            && selected.citations_correct == selected.citations_returned;
        if !selected_is_complete
            || selected.task_success_ppm() <= baseline.task_success_ppm()
            || selected.recall_ppm() < baseline.recall_ppm()
            || selected.precision_ppm() < baseline.precision_ppm()
            || selected.harmful_returns > baseline.harmful_returns
            || selected.remote_cost_microusd != 0
        {
            return Err(evidence_error(
                TechnicalRetrievalEvidenceCode::PromotionNotImproved,
                "evaluation",
                "selected policy does not improve both tuning and held-out tasks without added harm",
            ));
        }
    }
    Ok(())
}

fn validate_incremental_policy_benefit(
    reports: &[RetrievalPolicyReport],
    selected_policy: TechnicalRetrievalPolicyId,
) -> Result<(), TechnicalRetrievalEvidenceError> {
    let ablation_chain = [
        TechnicalRetrievalPolicyId::LexicalV1,
        TechnicalRetrievalPolicyId::FieldWeightedSparseV1,
        TechnicalRetrievalPolicyId::TaskConditionedSparseV1,
        TechnicalRetrievalPolicyId::TaskConditionedFreshnessV1,
        TechnicalRetrievalPolicyId::TaskConditionedThresholdV1,
        TechnicalRetrievalPolicyId::TaskConditionedDiverseV1,
    ];
    let selected_index = ablation_chain
        .iter()
        .position(|policy| *policy == selected_policy)
        .ok_or_else(|| {
            evidence_error(
                TechnicalRetrievalEvidenceCode::PromotionNotImproved,
                "evaluation",
                "selected policy is outside the measured sparse ablation chain",
            )
        })?;
    for policies in ablation_chain[..=selected_index].windows(2) {
        let simpler = policy_metrics(reports, policies[0])?;
        let candidate = policy_metrics(reports, policies[1])?;
        let non_regressive = candidate.recall_ppm() >= simpler.recall_ppm()
            && candidate.precision_ppm() >= simpler.precision_ppm()
            && candidate.task_success_ppm() >= simpler.task_success_ppm()
            && candidate.state_classification_successes >= simpler.state_classification_successes
            && candidate.harmful_returns <= simpler.harmful_returns
            && candidate.stale_returns <= simpler.stale_returns
            && candidate.remote_cost_microusd <= simpler.remote_cost_microusd;
        let strictly_better = candidate.recall_ppm() > simpler.recall_ppm()
            || candidate.precision_ppm() > simpler.precision_ppm()
            || candidate.task_success_ppm() > simpler.task_success_ppm()
            || candidate.state_classification_successes > simpler.state_classification_successes
            || candidate.harmful_returns < simpler.harmful_returns
            || candidate.stale_returns < simpler.stale_returns;
        if !non_regressive || !strictly_better {
            return Err(evidence_error(
                TechnicalRetrievalEvidenceCode::PromotionNotImproved,
                "evaluation",
                format!(
                    "policy {:?} lacks strict non-regressive benefit over {:?}",
                    policies[1], policies[0]
                ),
            ));
        }
    }
    Ok(())
}

fn validate_review(
    review: &TechnicalRetrievalReview,
    evaluation: &TechnicalRetrievalEvaluation,
    tuning_digest: ContentDigest,
    held_out_digest: ContentDigest,
    evaluation_digest: ContentDigest,
) -> Result<(), TechnicalRetrievalEvidenceError> {
    validate_id("review", &review.review_id)?;
    validate_text("review", &review.reviewer_id)?;
    validate_text("review", &review.reviewer_model_id)?;
    validate_limitations("review", &review.limitations)?;
    if [
        evaluation.generator_id.as_str(),
        review.evaluation_generator_id.as_str(),
    ]
    .contains(&review.reviewer_id.as_str())
        || review.reviewer_model_id == evaluation.evaluator_model_id
        || review.reviewer_config_digest == evaluation.evaluator_config_digest
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::SelfReview,
            "review",
            "evaluation generator or evaluator model/config cannot approve its own artifact",
        ));
    }
    if review.evaluation_generator_id != evaluation.generator_id
        || review.tuning_corpus_digest != tuning_digest
        || review.held_out_corpus_digest != held_out_digest
        || review.evaluation_digest != evaluation_digest
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::DigestMismatch,
            "review",
            "review is not bound to the exact corpora and evaluation",
        ));
    }
    if review.verdict != RetrievalReviewVerdict::Approved {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::ReviewRejected,
            "review",
            "exact evaluation artifact is not independently approved",
        ));
    }
    let required = required_review_dimensions();
    let required_order = required.iter().copied().collect::<Vec<_>>();
    let observed = review
        .reviewed_dimensions
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if observed != required
        || review.reviewed_dimensions.len() != required.len()
        || review.reviewed_dimensions != required_order
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::IncompleteReview,
            "review",
            "independent review dimensions are missing, duplicated, or non-canonical",
        ));
    }
    Ok(())
}

fn evaluate_trial(
    corpus: &TechnicalRetrievalCorpus,
    policy: TechnicalRetrievalPolicyId,
    trial: u8,
) -> Result<EvaluatedTrial, TechnicalRetrievalEvidenceError> {
    let started = Instant::now();
    let lesson_map = corpus
        .lessons
        .iter()
        .map(|lesson| (lesson.id.as_str(), lesson))
        .collect::<BTreeMap<_, _>>();
    let mut metrics = RetrievalEvaluationMetrics {
        cases: u32::try_from(corpus.cases.len()).unwrap_or(u32::MAX),
        recall_numerator: 0,
        recall_denominator: 0,
        precision_numerator: 0,
        precision_denominator: 0,
        citations_correct: 0,
        citations_returned: 0,
        harmful_returns: 0,
        stale_returns: 0,
        evidence_choice_successes: 0,
        state_classification_successes: 0,
        evidence_bytes: 0,
        estimated_evidence_tokens: 0,
        remote_cost_microusd: 0,
        deterministic_work_units: 0,
    };
    let mut outputs = Vec::with_capacity(corpus.cases.len());
    for case in &corpus.cases {
        let output = evaluate_case(case, &lesson_map, policy)?;
        update_metrics(case, &output, &lesson_map, policy, &mut metrics)?;
        outputs.push(output);
    }
    // One token per byte is a conservative upper bound for the UTF-8 JSON
    // evidence accepted here. Dividing by an average bytes/token ratio would
    // understate worst-case code, identifiers, or adversarial short tokens.
    metrics.estimated_evidence_tokens = metrics.evidence_bytes;
    let digest_bytes =
        serde_json::to_vec(&(policy, trial, &outputs, &metrics)).map_err(|error| {
            evidence_error(
                TechnicalRetrievalEvidenceCode::MetricsMismatch,
                &corpus.corpus_id,
                error.to_string(),
            )
        })?;
    Ok(EvaluatedTrial {
        receipt: RetrievalTrialReceipt {
            trial,
            output_digest: ContentDigest::sha256(digest_bytes),
            elapsed_micros: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        },
        metrics,
        case_receipts: outputs,
    })
}

struct EvaluatedTrial {
    receipt: RetrievalTrialReceipt,
    metrics: RetrievalEvaluationMetrics,
    case_receipts: Vec<RetrievalCaseOutcomeReceipt>,
}

fn evaluate_case(
    case: &RetrievalEvaluationCase,
    lessons: &BTreeMap<&str, &RetrievalCorpusLesson>,
    policy: TechnicalRetrievalPolicyId,
) -> Result<RetrievalCaseOutcomeReceipt, TechnicalRetrievalEvidenceError> {
    if policy == TechnicalRetrievalPolicyId::NoMemory {
        return Ok(RetrievalCaseOutcomeReceipt {
            case_id: case.id.clone(),
            state: RetrievalExpectedState::NoHit,
            returned_ids: Vec::new(),
        });
    }
    if case.injected_failure == Some(RetrievalInjectedFailure::StoreError) {
        return Ok(RetrievalCaseOutcomeReceipt {
            case_id: case.id.clone(),
            state: RetrievalExpectedState::StoreError,
            returned_ids: Vec::new(),
        });
    }
    if case.candidate_ids.iter().any(|id| {
        lessons
            .get(id.as_str())
            .is_some_and(|lesson| lesson.state == RetrievalFixtureState::Conflicted)
    }) {
        return Ok(RetrievalCaseOutcomeReceipt {
            case_id: case.id.clone(),
            state: RetrievalExpectedState::Conflicted,
            returned_ids: Vec::new(),
        });
    }
    let workspace = WorkspaceMemoryId::for_canonical_root(Path::new("/s105-evaluation"));
    let mut id_by_logical = BTreeMap::new();
    let mut records = Vec::new();
    let mut omitted_expired = 0_usize;
    for id in &case.candidate_ids {
        let fixture = lessons.get(id.as_str()).ok_or_else(|| {
            evidence_error(
                TechnicalRetrievalEvidenceCode::InvalidReference,
                &case.id,
                "case references an unavailable fixture",
            )
        })?;
        if fixture.state == RetrievalFixtureState::Expired {
            omitted_expired = omitted_expired.saturating_add(1);
            continue;
        }
        if fixture.state != RetrievalFixtureState::Available {
            continue;
        }
        let record = fixture_record(&workspace, fixture)?;
        id_by_logical.insert(record.logical_id, fixture.id.clone());
        records.push(record);
    }
    let terms = case
        .query
        .split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>();
    let ranked = rank_technical_lessons(
        records,
        Some(&case.query),
        &terms,
        Some(&case.context),
        policy,
    );
    let truncated = ranked.len() > case.limit;
    let returned = ranked
        .into_iter()
        .take(case.limit)
        .map(|ranked| {
            id_by_logical
                .get(&ranked.record.logical_id)
                .cloned()
                .ok_or_else(|| {
                    evidence_error(
                        TechnicalRetrievalEvidenceCode::InvalidReference,
                        &case.id,
                        "ranked fixture identity was lost",
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let state = if truncated || omitted_expired > 0 {
        RetrievalExpectedState::Partial
    } else if returned.is_empty() {
        RetrievalExpectedState::NoHit
    } else if returned.iter().any(|id| {
        lessons
            .get(id.as_str())
            .is_some_and(|lesson| lesson.due_for_review)
    }) {
        RetrievalExpectedState::Stale
    } else {
        RetrievalExpectedState::Complete
    };
    Ok(RetrievalCaseOutcomeReceipt {
        case_id: case.id.clone(),
        state,
        returned_ids: returned,
    })
}

fn fixture_record(
    workspace: &WorkspaceMemoryId,
    fixture: &RetrievalCorpusLesson,
) -> Result<TechnicalLessonRecord, TechnicalRetrievalEvidenceError> {
    let lesson = TechnicalLesson::from_candidate(
        workspace.clone(),
        fixture.draft.clone(),
        fixture.captured_at_unix_seconds,
    )
    .map_err(|error| {
        evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidBounds,
            &fixture.id,
            error.to_string(),
        )
    })?;
    let encoded = lesson.encode().map_err(|error| {
        evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidBounds,
            &fixture.id,
            error.to_string(),
        )
    })?;
    let evidence_digest = MemoryDigest::for_fields(
        b"openclaudia.s105.evaluation-record.v1",
        &[fixture.id.as_bytes(), encoded.as_bytes()],
    );
    let source_id = format!("tool-invocation:{evidence_digest}");
    let logical_id = LogicalMemoryId::for_technical_source(workspace.as_str(), &source_id);
    let origin_store_id =
        MemoryStoreId::from_str("00000000-0000-4000-8000-000000000105").map_err(|error| {
            evidence_error(
                TechnicalRetrievalEvidenceCode::InvalidIdentifier,
                &fixture.id,
                error.to_string(),
            )
        })?;
    let provenance = MemoryProvenance::new(
        MemorySourceEvidence::new(
            MemorySourceKind::AgentProposal,
            source_id,
            "run:s105-evaluation:generation:1".to_string(),
            evidence_digest,
        ),
        MemoryAttribution::new(
            "s105-corpus".to_string(),
            Some(origin_store_id),
            Some(workspace.to_string()),
        ),
        fixture.scope,
    );
    let revision = MemoryRevision::new_with_logical_id(
        logical_id,
        encoded,
        vec![TECHNICAL_LESSON_TAG.to_string()],
        provenance,
    );
    revision.validate().map_err(|error| {
        evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidReference,
            &fixture.id,
            error.to_string(),
        )
    })?;
    Ok(TechnicalLessonRecord {
        logical_id: revision.logical_id,
        version: revision.version,
        record_digest: revision.record_digest,
        scope: fixture.scope,
        provenance: revision.provenance,
        conflicted: false,
        due_for_review: fixture.due_for_review,
        effectively_host_reviewed: false,
        lesson,
    })
}

fn update_metrics(
    case: &RetrievalEvaluationCase,
    output: &RetrievalCaseOutcomeReceipt,
    lessons: &BTreeMap<&str, &RetrievalCorpusLesson>,
    policy: TechnicalRetrievalPolicyId,
    metrics: &mut RetrievalEvaluationMetrics,
) -> Result<(), TechnicalRetrievalEvidenceError> {
    let workspace = WorkspaceMemoryId::for_canonical_root(Path::new("/s105-evaluation"));
    let relevant = case
        .expected_relevant_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let forbidden = case
        .forbidden_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let true_positives = output
        .returned_ids
        .iter()
        .filter(|id| relevant.contains(id.as_str()))
        .count();
    metrics.recall_numerator = metrics
        .recall_numerator
        .saturating_add(u32::try_from(true_positives).unwrap_or(u32::MAX));
    metrics.recall_denominator = metrics
        .recall_denominator
        .saturating_add(u32::try_from(case.expected_relevant_ids.len()).unwrap_or(u32::MAX));
    metrics.precision_numerator = metrics
        .precision_numerator
        .saturating_add(u32::try_from(true_positives).unwrap_or(u32::MAX));
    metrics.precision_denominator = metrics
        .precision_denominator
        .saturating_add(u32::try_from(output.returned_ids.len()).unwrap_or(u32::MAX));
    metrics.harmful_returns = metrics.harmful_returns.saturating_add(
        u32::try_from(
            output
                .returned_ids
                .iter()
                .filter(|id| forbidden.contains(id.as_str()))
                .count(),
        )
        .unwrap_or(u32::MAX),
    );
    if output.state == case.expected_state {
        metrics.state_classification_successes =
            metrics.state_classification_successes.saturating_add(1);
    }
    let top_correct = match (&case.expected_top_id, output.returned_ids.first()) {
        (Some(expected), Some(actual)) => expected == actual,
        (None, None) => true,
        _ => false,
    };
    if top_correct {
        metrics.evidence_choice_successes = metrics.evidence_choice_successes.saturating_add(1);
    }
    for id in &output.returned_ids {
        let fixture = lessons.get(id.as_str()).ok_or_else(|| {
            evidence_error(
                TechnicalRetrievalEvidenceCode::InvalidReference,
                &case.id,
                "returned fixture is unavailable",
            )
        })?;
        let record = fixture_record(&workspace, fixture)?;
        let encoded = serde_json::to_vec(&record).map_err(|error| {
            evidence_error(
                TechnicalRetrievalEvidenceCode::MetricsMismatch,
                &case.id,
                error.to_string(),
            )
        })?;
        metrics.evidence_bytes = metrics
            .evidence_bytes
            .saturating_add(u64::try_from(encoded.len()).unwrap_or(u64::MAX));
        metrics.citations_returned = metrics
            .citations_returned
            .saturating_add(u32::try_from(fixture.draft.citations.len()).unwrap_or(u32::MAX));
        // Evaluation construction and bundle validation require exact
        // repository-byte receipts for every corpus citation before these
        // reports can participate in promotion.
        metrics.citations_correct = metrics
            .citations_correct
            .saturating_add(u32::try_from(fixture.draft.citations.len()).unwrap_or(u32::MAX));
        if fixture.due_for_review {
            metrics.stale_returns = metrics.stale_returns.saturating_add(1);
        }
    }
    metrics.deterministic_work_units = metrics
        .deterministic_work_units
        .saturating_add(ranking_work_units(policy, case.candidate_ids.len()));
    Ok(())
}

fn ranking_work_units(policy: TechnicalRetrievalPolicyId, candidate_count: usize) -> u64 {
    if policy == TechnicalRetrievalPolicyId::NoMemory {
        return 0;
    }
    let candidates = u64::try_from(candidate_count).unwrap_or(u64::MAX);
    let quadratic = candidates.saturating_mul(candidates);
    let diversity = u64::from(policy == TechnicalRetrievalPolicyId::TaskConditionedDiverseV1)
        .saturating_mul(quadratic);
    candidates
        .saturating_add(quadratic)
        .saturating_add(diversity)
}

fn validate_mechanisms(
    mechanisms: &[RetrievalMechanismAssessment],
) -> Result<(), TechnicalRetrievalEvidenceError> {
    let required = [
        RetrievalMechanism::LexicalCandidateGeneration,
        RetrievalMechanism::SemanticEmbeddings,
        RetrievalMechanism::TaskConditioning,
        RetrievalMechanism::HybridDenseSparse,
        RetrievalMechanism::SparseFieldReranking,
        RetrievalMechanism::Diversity,
        RetrievalMechanism::Freshness,
        RetrievalMechanism::SufficiencyThreshold,
    ];
    if mechanisms
        .iter()
        .map(|entry| entry.mechanism)
        .collect::<Vec<_>>()
        != required
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::UnmeasuredMechanism,
            "evaluation",
            "mechanism assessments are missing or non-canonical",
        ));
    }
    for mechanism in mechanisms {
        validate_text("mechanism", &mechanism.reason)?;
        let unavailable_dense = matches!(
            mechanism.mechanism,
            RetrievalMechanism::SemanticEmbeddings | RetrievalMechanism::HybridDenseSparse
        );
        if unavailable_dense && mechanism.status == RetrievalMechanismStatus::Evaluated {
            return Err(evidence_error(
                TechnicalRetrievalEvidenceCode::UnmeasuredMechanism,
                "evaluation",
                "semantic or hybrid retrieval cannot be marked evaluated without a backend",
            ));
        }
        if !unavailable_dense && mechanism.status != RetrievalMechanismStatus::Evaluated {
            return Err(evidence_error(
                TechnicalRetrievalEvidenceCode::UnmeasuredMechanism,
                "evaluation",
                "implemented sparse mechanism lacks evaluation evidence",
            ));
        }
    }
    Ok(())
}

fn validate_citation_receipts(
    tuning: &TechnicalRetrievalCorpus,
    held_out: &TechnicalRetrievalCorpus,
    receipts: &[RetrievalCitationVerificationReceipt],
) -> Result<(), TechnicalRetrievalEvidenceError> {
    if receipts.is_empty() || receipts.len() > MAX_CITATION_VERIFICATION_RECEIPTS {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidBounds,
            "citation receipts",
            "citation verification receipt count is invalid",
        ));
    }
    let observed = receipts
        .iter()
        .map(|receipt| {
            validate_text("citation receipt", &receipt.locator)?;
            validate_text("citation receipt", &receipt.source_version)?;
            if receipt.expected_digest != receipt.observed_digest {
                return Err(evidence_error(
                    TechnicalRetrievalEvidenceCode::DigestMismatch,
                    &receipt.locator,
                    "citation verification receipt records a digest mismatch",
                ));
            }
            if receipt.byte_len > MAX_CITATION_SOURCE_BYTES {
                return Err(evidence_error(
                    TechnicalRetrievalEvidenceCode::InvalidBounds,
                    &receipt.locator,
                    "citation verification receipt exceeds its source byte bound",
                ));
            }
            Ok((
                receipt.kind,
                receipt.locator.clone(),
                receipt.source_version.clone(),
                receipt.expected_digest.clone(),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !observed.windows(2).all(|pair| pair[0] < pair[1])
        || observed
            != corpus_citation_keys(tuning, held_out)?
                .into_iter()
                .collect::<Vec<_>>()
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::NonCanonicalCollection,
            "citation receipts",
            "citation receipts are missing, duplicated, extra, or non-canonical",
        ));
    }
    Ok(())
}

fn default_mechanism_assessments() -> Vec<RetrievalMechanismAssessment> {
    vec![
        RetrievalMechanismAssessment {
            mechanism: RetrievalMechanism::LexicalCandidateGeneration,
            status: RetrievalMechanismStatus::Evaluated,
            reason: "Bounded lexical retrieval is retained as the simple compatibility baseline."
                .to_string(),
        },
        RetrievalMechanismAssessment {
            mechanism: RetrievalMechanism::SemanticEmbeddings,
            status: RetrievalMechanismStatus::Rejected,
            reason: "No approved local model artifact or private remote embedding transport is configured."
                .to_string(),
        },
        RetrievalMechanismAssessment {
            mechanism: RetrievalMechanism::TaskConditioning,
            status: RetrievalMechanismStatus::Evaluated,
            reason: "Explicit stage and code-surface context is evaluated without reading ambient prose."
                .to_string(),
        },
        RetrievalMechanismAssessment {
            mechanism: RetrievalMechanism::HybridDenseSparse,
            status: RetrievalMechanismStatus::Unavailable,
            reason: "Hybrid retrieval requires the unavailable approved semantic backend."
                .to_string(),
        },
        RetrievalMechanismAssessment {
            mechanism: RetrievalMechanism::SparseFieldReranking,
            status: RetrievalMechanismStatus::Evaluated,
            reason: "Field-weighted reranking executes over the bounded typed candidate set."
                .to_string(),
        },
        RetrievalMechanismAssessment {
            mechanism: RetrievalMechanism::Diversity,
            status: RetrievalMechanismStatus::Evaluated,
            reason: "Deterministic component/tag overlap penalties are measured in every trial."
                .to_string(),
        },
        RetrievalMechanismAssessment {
            mechanism: RetrievalMechanism::Freshness,
            status: RetrievalMechanismStatus::Evaluated,
            reason: "Due-for-review records receive a ranking penalty and remain explicitly stale."
                .to_string(),
        },
        RetrievalMechanismAssessment {
            mechanism: RetrievalMechanism::SufficiencyThreshold,
            status: RetrievalMechanismStatus::Evaluated,
            reason: "The selected policy abstains when bounded evidence does not meet its minimum score."
                .to_string(),
        },
    ]
}

fn validate_budgets(
    budgets: &RetrievalEvaluationBudgets,
) -> Result<(), TechnicalRetrievalEvidenceError> {
    if budgets.max_candidates_per_case != MAX_CORPUS_CASE_CANDIDATES
        || budgets.max_runtime_candidates_per_call != super::MAX_RETRIEVAL_CANDIDATES_SCANNED
        || budgets.max_result_records == 0
        || budgets.max_result_records > 20
        || budgets.max_runtime_output_bytes != super::MAX_TECHNICAL_QUERY_RESULT_BYTES
        || budgets.max_runtime_evidence_tokens
            != u64::try_from(super::MAX_TECHNICAL_QUERY_RESULT_BYTES).unwrap_or(u64::MAX)
        || budgets.max_context_items == 0
        || budgets.max_context_items > super::MAX_RETRIEVAL_CONTEXT_TOTAL_ITEMS
        || budgets.max_deterministic_work_units_per_trial != MAX_DETERMINISTIC_WORK_UNITS_PER_TRIAL
        || budgets.max_evidence_tokens_per_trial == 0
        || budgets.max_latency_micros_per_trial == 0
        || budgets.max_remote_cost_microusd_per_trial != 0
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidBounds,
            "evaluation budgets",
            "resource budgets are invalid or permit remote cost",
        ));
    }
    Ok(())
}

fn policy_metrics(
    reports: &[RetrievalPolicyReport],
    policy: TechnicalRetrievalPolicyId,
) -> Result<&RetrievalEvaluationMetrics, TechnicalRetrievalEvidenceError> {
    reports
        .iter()
        .find(|report| report.policy == policy)
        .map(|report| &report.metrics)
        .ok_or_else(|| {
            evidence_error(
                TechnicalRetrievalEvidenceCode::MissingBaseline,
                "evaluation",
                "required policy report is missing",
            )
        })
}

fn all_evaluated_policies() -> Vec<TechnicalRetrievalPolicyId> {
    vec![
        TechnicalRetrievalPolicyId::NoMemory,
        TechnicalRetrievalPolicyId::LexicalV1,
        TechnicalRetrievalPolicyId::FieldWeightedSparseV1,
        TechnicalRetrievalPolicyId::TaskConditionedSparseV1,
        TechnicalRetrievalPolicyId::TaskConditionedFreshnessV1,
        TechnicalRetrievalPolicyId::TaskConditionedThresholdV1,
        TechnicalRetrievalPolicyId::TaskConditionedDiverseV1,
    ]
}

fn required_review_dimensions() -> BTreeSet<RetrievalReviewDimension> {
    [
        RetrievalReviewDimension::SplitIsolation,
        RetrievalReviewDimension::BaselineCoverage,
        RetrievalReviewDimension::AdversarialStates,
        RetrievalReviewDimension::RuntimeParity,
        RetrievalReviewDimension::PrivacyAndCost,
        RetrievalReviewDimension::ArtifactAndResourceBounds,
    ]
    .into_iter()
    .collect()
}

fn ensure_schema(artifact: &str, found: u16) -> Result<(), TechnicalRetrievalEvidenceError> {
    if found != RETRIEVAL_EVIDENCE_SCHEMA_VERSION {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::UnsupportedSchema,
            artifact,
            format!("expected schema {RETRIEVAL_EVIDENCE_SCHEMA_VERSION}, found {found}"),
        ));
    }
    Ok(())
}

fn validate_artifact_size(
    artifact: &str,
    source: &str,
    maximum: usize,
) -> Result<(), TechnicalRetrievalEvidenceError> {
    if source.len() > maximum {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::ArtifactTooLarge,
            artifact,
            format!("artifact exceeds {maximum} bytes"),
        ));
    }
    Ok(())
}

fn parse_artifact<T: for<'de> Deserialize<'de>>(
    artifact: &str,
    source: &str,
) -> Result<T, TechnicalRetrievalEvidenceError> {
    serde_json::from_str(source).map_err(|error| {
        evidence_error(
            TechnicalRetrievalEvidenceCode::ParseFailed,
            artifact,
            error.to_string(),
        )
    })
}

fn validate_id(artifact: &str, value: &str) -> Result<(), TechnicalRetrievalEvidenceError> {
    if value.is_empty()
        || value.len() > MAX_EVIDENCE_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.".contains(&byte)
        })
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidIdentifier,
            artifact,
            "identifier must use bounded lowercase ASCII",
        ));
    }
    Ok(())
}

fn validate_text(artifact: &str, value: &str) -> Result<(), TechnicalRetrievalEvidenceError> {
    if value.trim().is_empty()
        || value.len() > MAX_EVIDENCE_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidBounds,
            artifact,
            "text is empty, oversized, or contains controls",
        ));
    }
    Ok(())
}

fn validate_limitations(
    artifact: &str,
    limitations: &[String],
) -> Result<(), TechnicalRetrievalEvidenceError> {
    if limitations.is_empty() || limitations.len() > 32 {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::InvalidBounds,
            artifact,
            "limitations must be explicit and bounded",
        ));
    }
    for limitation in limitations {
        validate_text(artifact, limitation)?;
    }
    Ok(())
}

fn ensure_sorted_unique_ids<'a>(
    artifact: &str,
    values: impl IntoIterator<Item = &'a str>,
) -> Result<(), TechnicalRetrievalEvidenceError> {
    let values = values.into_iter().collect::<Vec<_>>();
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(evidence_error(
            TechnicalRetrievalEvidenceCode::NonCanonicalCollection,
            artifact,
            "identifiers must be strictly sorted and unique",
        ));
    }
    Ok(())
}

fn ensure_canonical_strings(
    artifact: &str,
    values: &[String],
) -> Result<(), TechnicalRetrievalEvidenceError> {
    ensure_sorted_unique_ids(artifact, values.iter().map(String::as_str))?;
    for value in values {
        validate_id(artifact, value)?;
    }
    Ok(())
}

fn ratio_ppm(numerator: u32, denominator: u32) -> u64 {
    if denominator == 0 {
        return u64::from(numerator == 0) * 1_000_000;
    }
    u64::from(numerator).saturating_mul(1_000_000) / u64::from(denominator)
}

fn evidence_error(
    code: TechnicalRetrievalEvidenceCode,
    artifact: impl Into<String>,
    detail: impl Into<String>,
) -> TechnicalRetrievalEvidenceError {
    TechnicalRetrievalEvidenceError {
        code,
        artifact: artifact.into(),
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_citation_rejects_parent_traversal() {
        let root = tempfile::tempdir().expect("temporary repository root");
        let key = (
            LessonCitationKind::SourceFile,
            "../outside.rs".to_string(),
            "worktree:s105".to_string(),
            MemoryDigest::sha256(b"outside"),
        );
        let error = verify_repository_citation(root.path(), key)
            .expect_err("a citation must not escape its repository root");
        assert_eq!(error.code, TechnicalRetrievalEvidenceCode::InvalidReference);
    }

    #[cfg(unix)]
    #[test]
    fn repository_citation_rejects_symbolic_link_components() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("temporary repository root");
        let target = root.path().join("target.rs");
        fs::write(&target, b"verified bytes").expect("write citation target");
        symlink(&target, root.path().join("alias.rs")).expect("create citation symlink");
        let key = (
            LessonCitationKind::SourceFile,
            "alias.rs".to_string(),
            "worktree:s105".to_string(),
            MemoryDigest::sha256(b"verified bytes"),
        );
        let error = verify_repository_citation(root.path(), key)
            .expect_err("a citation must not traverse a symbolic link");
        assert_eq!(error.code, TechnicalRetrievalEvidenceCode::InvalidReference);
    }

    #[test]
    fn bundled_evidence_fails_closed_until_independently_approved() {
        let error = TechnicalRetrievalEvidenceBundle::bundled()
            .expect_err("unreviewed evidence must fail closed");
        assert_eq!(error.code, TechnicalRetrievalEvidenceCode::ReviewRejected);
    }

    #[test]
    fn bundled_corpora_are_valid_and_executable() {
        let tuning: TechnicalRetrievalCorpus =
            parse_artifact("tuning", BUNDLED_TUNING_CORPUS).expect("tuning corpus");
        let held_out: TechnicalRetrievalCorpus =
            parse_artifact("held-out", BUNDLED_HELD_OUT_CORPUS).expect("held-out corpus");
        let tuning_reports =
            evaluate_technical_retrieval_corpus(&tuning, 3).expect("tuning evaluation");
        let held_out_reports =
            evaluate_technical_retrieval_corpus(&held_out, 3).expect("held-out evaluation");
        assert_eq!(tuning_reports.len(), all_evaluated_policies().len());
        assert_eq!(held_out_reports.len(), all_evaluated_policies().len());
    }

    #[test]
    fn bundled_corpora_prove_every_selected_ablation_step() {
        let evaluation = build_technical_retrieval_evaluation(
            BUNDLED_TUNING_CORPUS,
            BUNDLED_HELD_OUT_CORPUS,
            Path::new(env!("CARGO_MANIFEST_DIR")),
            3,
            TechnicalRetrievalPolicyId::TaskConditionedDiverseV1,
            "s105-evaluation-runner",
            "openclaudia-deterministic-retrieval-evaluator-v1",
        )
        .expect("evaluation should execute");
        for reports in [&evaluation.tuning_reports, &evaluation.held_out_reports] {
            validate_incremental_policy_benefit(reports, evaluation.selected_policy)
                .expect("every selected retrieval step should add measured benefit");
        }
    }

    #[test]
    fn work_budget_covers_the_declared_worst_case() {
        let per_case = ranking_work_units(
            TechnicalRetrievalPolicyId::TaskConditionedDiverseV1,
            MAX_CORPUS_CASE_CANDIDATES,
        );
        assert_eq!(
            per_case.saturating_mul(u64::try_from(MAX_CORPUS_CASES).unwrap_or(u64::MAX)),
            MAX_DETERMINISTIC_WORK_UNITS_PER_TRIAL
        );
        assert!(
            ranking_work_units(
                TechnicalRetrievalPolicyId::TaskConditionedDiverseV1,
                super::super::MAX_RETRIEVAL_CANDIDATES_SCANNED,
            ) < MAX_DETERMINISTIC_WORK_UNITS_PER_TRIAL
        );
    }
}
