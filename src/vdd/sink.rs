//! Transactional, redacted VDD evidence and Crosslink reconciliation.
//!
//! Review engines only produce evidence. This module persists the host-owned
//! finalization result first, applies each external issue mutation inside one
//! SQLite transaction, and finally records the reconciliation receipt with a
//! generation-checked commit. Deterministic markers make the middle step safe
//! to recover when a process stops after Crosslink commits but before the
//! evidence receipt is published.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{VddConfig, VddMode};
use crate::persistence::{
    CommitReceipt, FileClass, PersistenceError, PersistentStorage, StorageGeneration,
};
use crate::runtime::ContentDigest;
use crate::tools::{ToolResource, ToolRunContext};

use super::finalization::{
    VddCandidateBinding, VddFinalizationOutcome, VddFinalizationRequirement,
};
use super::finding::{Finding, FindingStatus, Severity};
use super::prompts::{ADVERSARY_SYSTEM_PROMPT, VERIFIER_SYSTEM_PROMPT};
use super::review::VddSession;
use super::static_analysis::StaticAnalysisResult;
use super::{
    CanonicalFindingSeverity, CanonicalVddReceipt, CanonicalVddRequest, DeterministicCheckOutcome,
    VddProviderCallOutcome, VddProviderCallReceipt,
};

const EVIDENCE_SCHEMA_VERSION: u16 = 1;
const MAX_ATTEMPTS: usize = 512;
const MAX_FINDINGS_PER_ATTEMPT: usize = 512;
const MAX_FINDING_HISTORY: usize = 64;
const MAX_ISSUE_ACTIONS: usize = 2_048;
const MAX_RECONCILE_RETRIES: usize = 8;
const MAX_LEDGER_ID_BYTES: usize = 512;
const MAX_SUMMARY_BYTES: usize = 4 * 1024;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_CODE_BYTES: usize = 128;
const MAX_CITATIONS: usize = 64;
const MAX_OBSERVATION_IDS: usize = 256;
const MAX_OBSERVATION_ID_BYTES: usize = 512;
const MAX_MODEL_CALLS: usize = 128;
const MAX_DETERMINISTIC_CHECKS: usize = 256;
const ISSUE_MARKER_PREFIX: &str = "openclaudia-vdd:v1";
const RECONCILE_MARKER_PREFIX: &str = "openclaudia-vdd-reconcile:v1";

/// Failure at the durable VDD evidence or external reconciliation boundary.
#[derive(Debug, Error)]
pub enum VddEvidenceError {
    #[error(transparent)]
    Capability(#[from] crate::tools::ToolCapabilityError),
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("VDD evidence root is unavailable or unsafe")]
    UnsafeStorageRoot,
    #[error("VDD evidence ledger is invalid: {0}")]
    InvalidLedger(&'static str),
    #[error("VDD evidence capacity exceeded for {resource} (limit {limit})")]
    Capacity {
        resource: &'static str,
        limit: usize,
    },
    #[error("VDD evidence generation remained contended after bounded retries")]
    Contended,
    #[error("Crosslink reconciliation failed: {0}")]
    Crosslink(String),
    #[error("VDD evidence worker failed: {0}")]
    Worker(String),
}

/// Sensitivity state retained for one review attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VddEvidenceSensitivity {
    /// Bounded, secret-sanitized prose is still retained.
    PrivateRedacted,
    /// Only identities, digests, and lifecycle facts remain.
    Tombstone,
}

/// Host-derived lifecycle state for a finding on an exact artifact revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VddFindingState {
    Genuine,
    FalsePositive,
    Disputed,
    Resolved,
}

/// One artifact-bound finding state transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VddFindingEvent {
    pub state: VddFindingState,
    pub iteration: u32,
    pub artifact_sha256: ContentDigest,
    pub observed_at: DateTime<Utc>,
}

/// Redacted source citation. Paths are normalized observations, never write
/// authority and never used to open a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VddEvidenceCitation {
    pub artifact_sha256: ContentDigest,
    pub path: Option<String>,
    pub line_range: Option<(usize, usize)>,
    pub observation_ids: Vec<String>,
}

/// Stable redacted evidence for one logical finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VddFindingEvidence {
    pub finding_sha256: ContentDigest,
    pub severity: Severity,
    pub code: Option<String>,
    pub summary: Option<String>,
    pub description_sha256: ContentDigest,
    pub reasoning_sha256: ContentDigest,
    pub citations: Vec<VddEvidenceCitation>,
    pub history: Vec<VddFindingEvent>,
}

/// Bounded model-call identity and accounting retained without prompt or
/// response bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VddModelEvidence {
    pub provider: String,
    pub requested_model: String,
    pub resolved_model: Option<String>,
    pub endpoint_sha256: Option<ContentDigest>,
    pub identity_sha256: Option<ContentDigest>,
    pub policy_generation: Option<u64>,
    pub outcome: super::VddProviderCallOutcome,
    pub usage_known: bool,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub response_bytes: u64,
    pub completed_at: DateTime<Utc>,
}

/// Digest-only deterministic analyzer receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VddDeterministicEvidence {
    pub command_sha256: ContentDigest,
    pub output_sha256: ContentDigest,
    pub exit_code: i32,
    pub passed: bool,
}

/// One host-finalized review attempt. Raw builder, adversary, analyzer, and
/// user-task content is deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VddEvidenceAttempt {
    pub attempt_id: String,
    pub attempt_sha256: ContentDigest,
    pub scope_sha256: ContentDigest,
    pub session_sha256: ContentDigest,
    pub candidate: VddCandidateBinding,
    pub mode: VddMode,
    pub requirement: VddFinalizationRequirement,
    pub outcome: VddFinalizationOutcome,
    pub policy_sha256: ContentDigest,
    pub prompt_sha256: ContentDigest,
    pub canonical_receipt_sha256: Option<ContentDigest>,
    pub review_session_sha256: Option<ContentDigest>,
    pub model_calls: Vec<VddModelEvidence>,
    pub deterministic_checks: Vec<VddDeterministicEvidence>,
    pub findings: BTreeMap<String, VddFindingEvidence>,
    pub unresolved_finding_ids: BTreeSet<String>,
    pub started_at: DateTime<Utc>,
    pub finalized_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub sensitivity: VddEvidenceSensitivity,
    pub redacted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IssueDesiredState {
    Open,
    Resolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IssueReconciliationState {
    Pending,
    Applied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueReconciliation {
    operation_id: String,
    attempt_id: String,
    finding_key: String,
    finding_sha256: ContentDigest,
    marker: String,
    desired: IssueDesiredState,
    revision_micros: i64,
    severity: Severity,
    code: Option<String>,
    summary: Option<String>,
    citation: Option<VddEvidenceCitation>,
    state: IssueReconciliationState,
    issue_id: Option<i64>,
    applied_at: Option<DateTime<Utc>>,
}

/// Versioned canonical evidence document for one frontend session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VddEvidenceLedger {
    schema_version: u16,
    ledger_id: String,
    revision: u64,
    attempts: BTreeMap<String, VddEvidenceAttempt>,
    issue_reconciliations: BTreeMap<String, IssueReconciliation>,
}

impl VddEvidenceLedger {
    const fn new(ledger_id: String) -> Self {
        Self {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            ledger_id,
            revision: 0,
            attempts: BTreeMap::new(),
            issue_reconciliations: BTreeMap::new(),
        }
    }

    /// Exact retained attempt, if present.
    #[must_use]
    pub fn attempt(&self, attempt_id: &str) -> Option<&VddEvidenceAttempt> {
        self.attempts.get(attempt_id)
    }

    /// Monotonic ledger revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[allow(clippy::too_many_lines)] // Keep the complete tamper-validation invariant visible together.
    fn validate(&self, expected_id: &str) -> Result<(), VddEvidenceError> {
        if self.schema_version != EVIDENCE_SCHEMA_VERSION {
            return Err(VddEvidenceError::InvalidLedger(
                "unsupported schema version",
            ));
        }
        if self.ledger_id != expected_id {
            return Err(VddEvidenceError::InvalidLedger("ledger identity mismatch"));
        }
        validate_identifier(&self.ledger_id)?;
        if self.attempts.len() > MAX_ATTEMPTS {
            return Err(VddEvidenceError::Capacity {
                resource: "attempts",
                limit: MAX_ATTEMPTS,
            });
        }
        if self.issue_reconciliations.len() > MAX_ISSUE_ACTIONS {
            return Err(VddEvidenceError::Capacity {
                resource: "issue reconciliations",
                limit: MAX_ISSUE_ACTIONS,
            });
        }
        for (id, attempt) in &self.attempts {
            if id != &attempt.attempt_id || attempt.attempt_sha256 != digest_attempt(attempt)? {
                return Err(VddEvidenceError::InvalidLedger(
                    "attempt identity or digest mismatch",
                ));
            }
            if attempt.findings.len() > MAX_FINDINGS_PER_ATTEMPT {
                return Err(VddEvidenceError::Capacity {
                    resource: "findings per attempt",
                    limit: MAX_FINDINGS_PER_ATTEMPT,
                });
            }
            if attempt.model_calls.len() > MAX_MODEL_CALLS
                || attempt.deterministic_checks.len() > MAX_DETERMINISTIC_CHECKS
                || !attempt
                    .unresolved_finding_ids
                    .iter()
                    .all(|finding_id| attempt.findings.contains_key(finding_id))
            {
                return Err(VddEvidenceError::InvalidLedger(
                    "attempt evidence bounds or unresolved identities are invalid",
                ));
            }
            if attempt.model_calls.iter().any(|call| {
                call.provider.len() > MAX_OBSERVATION_ID_BYTES
                    || call.requested_model.len() > MAX_OBSERVATION_ID_BYTES
                    || call
                        .resolved_model
                        .as_ref()
                        .is_some_and(|model| model.len() > MAX_OBSERVATION_ID_BYTES)
            }) {
                return Err(VddEvidenceError::InvalidLedger(
                    "model-call identities are invalid",
                ));
            }
            for (finding_id, finding) in &attempt.findings {
                if finding_id != &finding.finding_sha256.to_string()
                    || finding.history.len() > MAX_FINDING_HISTORY
                    || finding.citations.len() > MAX_CITATIONS
                    || finding
                        .summary
                        .as_ref()
                        .is_some_and(|summary| summary.len() > MAX_SUMMARY_BYTES)
                    || finding.history.is_empty()
                    || finding.citations.iter().any(|citation| {
                        citation.path.as_ref().is_some_and(|path| {
                            normalize_observed_path(Some(path)) != Some(path.clone())
                        }) || citation.line_range.is_some()
                            && normalize_line_range(citation.path.as_deref(), citation.line_range)
                                != citation.line_range
                            || citation.observation_ids.len() > MAX_OBSERVATION_IDS
                            || citation
                                .observation_ids
                                .iter()
                                .any(|id| id.len() > MAX_OBSERVATION_ID_BYTES)
                    })
                {
                    return Err(VddEvidenceError::InvalidLedger(
                        "finding identity or bounds are invalid",
                    ));
                }
            }
        }
        for (operation_id, action) in &self.issue_reconciliations {
            let attempt =
                self.attempts
                    .get(&action.attempt_id)
                    .ok_or(VddEvidenceError::InvalidLedger(
                        "issue reconciliation attempt is missing",
                    ))?;
            let finding_id = action.finding_sha256.to_string();
            let finding =
                attempt
                    .findings
                    .get(&finding_id)
                    .ok_or(VddEvidenceError::InvalidLedger(
                        "issue reconciliation finding is missing",
                    ))?;
            let expected_key = format!("{}:{finding_id}", attempt.scope_sha256);
            let last = finding
                .history
                .last()
                .ok_or(VddEvidenceError::InvalidLedger(
                    "issue reconciliation finding history is empty",
                ))?;
            if operation_id != &action.operation_id
                || action.finding_key != expected_key
                || action.marker != issue_marker(&expected_key)
                || desired_issue_state(attempt, &finding_id, finding) != Some(action.desired)
                || action.revision_micros != last.observed_at.timestamp_micros()
                || action.operation_id
                    != derive_operation_id(&expected_key, action.desired, action.revision_micros)
                || action.severity != finding.severity
                || action.code != finding.code
                || action.summary != finding.summary
                || action.citation != finding.citations.last().cloned()
                || action
                    .summary
                    .as_ref()
                    .is_some_and(|summary| summary.len() > MAX_SUMMARY_BYTES)
                || match action.state {
                    IssueReconciliationState::Pending => {
                        action.issue_id.is_some() || action.applied_at.is_some()
                    }
                    IssueReconciliationState::Applied => {
                        action.issue_id.is_none() || action.applied_at.is_none()
                    }
                }
            {
                return Err(VddEvidenceError::InvalidLedger(
                    "issue reconciliation receipt is inconsistent",
                ));
            }
        }
        Ok(())
    }

    fn redact_expired(&mut self, now: DateTime<Utc>) {
        let mut redacted_attempts = BTreeSet::new();
        for attempt in self.attempts.values_mut() {
            if attempt.expires_at <= now {
                redact_attempt(attempt, now);
                redacted_attempts.insert(attempt.attempt_id.clone());
            }
        }
        for action in self.issue_reconciliations.values_mut() {
            if redacted_attempts.contains(&action.attempt_id) {
                action.summary = None;
            }
        }
    }
}

/// Loaded ledger plus the exact descriptor-safe storage generation.
#[derive(Debug)]
struct StoredVddEvidenceLedger {
    ledger: VddEvidenceLedger,
    storage_generation: StorageGeneration,
}

/// Descriptor-safe store for one frontend session's VDD evidence.
#[derive(Debug, Clone)]
pub struct VddEvidenceStore {
    storage: PersistentStorage,
    target: PathBuf,
    ledger_id: String,
}

impl VddEvidenceStore {
    /// Bind an existing private evidence root and a root-relative document.
    ///
    /// # Errors
    /// Returns an error for an unsafe root, target, or ledger identity.
    pub fn open(
        root: impl AsRef<Path>,
        target: impl Into<PathBuf>,
        ledger_id: impl Into<String>,
    ) -> Result<Self, VddEvidenceError> {
        let ledger_id = ledger_id.into();
        validate_identifier(&ledger_id)?;
        Ok(Self {
            storage: PersistentStorage::open(root)?,
            target: target.into(),
            ledger_id,
        })
    }

    /// Open the configured private ledger for one immutable run.
    ///
    /// # Errors
    /// Requires workspace-write authority and a safe configured persistence
    /// root.
    pub fn open_for_run(
        run: &ToolRunContext,
        config: &VddConfig,
    ) -> Result<Self, VddEvidenceError> {
        run.require(ToolResource::WorkspaceWrite)?;
        let root = resolve_evidence_root(run, &config.tracking.path)?;
        prepare_private_evidence_root(run, &root)?;
        Self::open(
            root,
            format!("vdd-evidence-{}.json", run.session_id()),
            format!("session:{}", run.session_id()),
        )
    }

    /// Load and strictly validate the current ledger. A missing document is a
    /// valid empty generation-zero ledger.
    ///
    /// # Errors
    /// Returns malformed, oversized, unsafe, or identity-mismatched state.
    fn load(&self) -> Result<StoredVddEvidenceLedger, VddEvidenceError> {
        let read = self.storage.read(&self.target, FileClass::Evidence)?;
        let storage_generation = read.generation();
        let ledger = read.expose_bytes(|bytes| {
            bytes.map_or_else(
                || Ok(VddEvidenceLedger::new(self.ledger_id.clone())),
                |bytes| serde_json::from_slice(bytes).map_err(VddEvidenceError::from),
            )
        })?;
        ledger.validate(&self.ledger_id)?;
        Ok(StoredVddEvidenceLedger {
            ledger,
            storage_generation,
        })
    }

    fn commit(
        &self,
        expected: StorageGeneration,
        ledger: &VddEvidenceLedger,
    ) -> Result<CommitReceipt, VddEvidenceError> {
        ledger.validate(&self.ledger_id)?;
        let bytes = serde_json::to_vec(ledger)?;
        Ok(self
            .storage
            .commit(&self.target, FileClass::Evidence, expected, bytes)?)
    }

    /// Export one already-redacted attempt without exposing other session
    /// records.
    ///
    /// # Errors
    /// Returns an error when the ledger is unavailable or the attempt is not
    /// present.
    pub fn export_attempt(&self, attempt_id: &str) -> Result<VddEvidenceAttempt, VddEvidenceError> {
        self.mutate(|ledger, _now| {
            ledger
                .attempts
                .get(attempt_id)
                .cloned()
                .ok_or(VddEvidenceError::InvalidLedger("attempt does not exist"))
        })
        .map(|(attempt, _ledger)| attempt)
    }

    /// List retained attempt identities after applying the configured
    /// retention redaction boundary.
    ///
    /// # Errors
    /// Returns an error when the ledger cannot be validated or committed.
    pub fn attempt_ids(&self) -> Result<Vec<String>, VddEvidenceError> {
        self.mutate(|ledger, _now| Ok(ledger.attempts.keys().cloned().collect()))
            .map(|(attempts, _ledger)| attempts)
    }

    /// Delete retained prose for one attempt while preserving its exact
    /// bindings, digests, findings, and status history as a tombstone.
    ///
    /// # Errors
    /// Returns an error for a missing attempt or persistent contention.
    pub fn delete_attempt(&self, attempt_id: &str) -> Result<(), VddEvidenceError> {
        self.mutate(|ledger, now| {
            let attempt = ledger
                .attempts
                .get_mut(attempt_id)
                .ok_or(VddEvidenceError::InvalidLedger("attempt does not exist"))?;
            redact_attempt(attempt, now);
            for action in ledger.issue_reconciliations.values_mut() {
                if action.attempt_id == attempt_id {
                    action.summary = None;
                }
            }
            Ok(())
        })
        .map(|_| ())
    }

    fn mutate<T>(
        &self,
        mut mutation: impl FnMut(&mut VddEvidenceLedger, DateTime<Utc>) -> Result<T, VddEvidenceError>,
    ) -> Result<(T, VddEvidenceLedger), VddEvidenceError> {
        for _ in 0..MAX_RECONCILE_RETRIES {
            let stored = self.load()?;
            let mut proposal = stored.ledger;
            let now = Utc::now();
            proposal.redact_expired(now);
            let output = mutation(&mut proposal, now)?;
            proposal.revision = proposal
                .revision
                .checked_add(1)
                .ok_or(VddEvidenceError::InvalidLedger("revision space exhausted"))?;
            match self.commit(stored.storage_generation, &proposal) {
                Ok(_) => return Ok((output, proposal)),
                Err(VddEvidenceError::Persistence(PersistenceError::Conflict { .. })) => {}
                Err(error) => return Err(error),
            }
        }
        Err(VddEvidenceError::Contended)
    }
}

/// Output-only receipt for a persisted and reconciled finalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VddEvidenceReceipt {
    pub attempt_id: String,
    pub ledger_revision: u64,
    pub issue_ids: Vec<i64>,
}

/// Persist and reconcile one legacy advisory or blocking review after the host
/// has selected its terminal publication outcome.
#[allow(clippy::too_many_arguments)]
pub(super) async fn persist_legacy_finalization(
    run: &Arc<ToolRunContext>,
    config: &VddConfig,
    requirement: VddFinalizationRequirement,
    policy_sha256: ContentDigest,
    scope: &str,
    candidate: &VddCandidateBinding,
    outcome: VddFinalizationOutcome,
    session: Option<&VddSession>,
    advisory_findings: &[Finding],
    advisory_static: &[StaticAnalysisResult],
    provider_receipts: &[VddProviderCallReceipt],
) -> Result<Option<VddEvidenceReceipt>, VddEvidenceError> {
    if !config.tracking.persist {
        return Ok(None);
    }
    let run = Arc::clone(run);
    let config = config.clone();
    let scope = scope.to_string();
    let candidate = candidate.clone();
    let session = session.cloned();
    let advisory_findings = advisory_findings.to_vec();
    let advisory_static = advisory_static.to_vec();
    let provider_receipts = provider_receipts.to_vec();
    tokio::task::spawn_blocking(move || {
        persist_legacy_finalization_blocking(
            &run,
            &config,
            requirement,
            policy_sha256,
            &scope,
            candidate,
            outcome,
            session.as_ref(),
            &advisory_findings,
            &advisory_static,
            &provider_receipts,
        )
    })
    .await
    .map_err(|error| VddEvidenceError::Worker(error.to_string()))?
}

/// Persist and reconcile one strict artifact-bound worker verification after
/// host finalization. The canonical receipt itself remains in the planner
/// checkpoint; this ledger retains its digest and typed redacted projection.
#[allow(clippy::too_many_arguments)]
pub(super) async fn persist_worker_finalization(
    run: &Arc<ToolRunContext>,
    config: &VddConfig,
    requirement: VddFinalizationRequirement,
    policy_sha256: ContentDigest,
    request: &CanonicalVddRequest,
    candidate: &VddCandidateBinding,
    outcome: VddFinalizationOutcome,
    receipt: &CanonicalVddReceipt,
) -> Result<Option<VddEvidenceReceipt>, VddEvidenceError> {
    if !config.tracking.persist {
        return Ok(None);
    }
    let run = Arc::clone(run);
    let config = config.clone();
    let request = request.clone();
    let candidate = candidate.clone();
    let receipt = receipt.clone();
    tokio::task::spawn_blocking(move || {
        let store = VddEvidenceStore::open_for_run(&run, &config)?;
        let attempt = build_worker_attempt(
            &run,
            &config,
            requirement,
            policy_sha256,
            &request,
            candidate,
            outcome,
            &receipt,
        )?;
        let attempt_id = attempt.attempt_id.clone();
        let promote = config.tracking.promote_verified_findings
            && requirement == VddFinalizationRequirement::Required;
        let ((), mut ledger) =
            store.mutate(|ledger, _now| insert_attempt_and_actions(ledger, &attempt, promote))?;
        let mut issue_ids = Vec::new();
        if promote && has_pending_issue_actions(&ledger) {
            let receipts = reconcile_pending_crosslink(&run, &ledger)?;
            if !receipts.is_empty() {
                let ((), updated) = store.mutate(|ledger, now| {
                    apply_issue_receipts(ledger, &receipts, now);
                    Ok(())
                })?;
                ledger = updated;
            }
        }
        issue_ids.extend(issue_ids_for_attempt(&ledger, &attempt_id));
        issue_ids.sort_unstable();
        issue_ids.dedup();
        Ok(Some(VddEvidenceReceipt {
            attempt_id,
            ledger_revision: ledger.revision,
            issue_ids,
        }))
    })
    .await
    .map_err(|error| VddEvidenceError::Worker(error.to_string()))?
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn build_worker_attempt(
    run: &ToolRunContext,
    config: &VddConfig,
    requirement: VddFinalizationRequirement,
    policy_sha256: ContentDigest,
    request: &CanonicalVddRequest,
    candidate: VddCandidateBinding,
    outcome: VddFinalizationOutcome,
    receipt: &CanonicalVddReceipt,
) -> Result<VddEvidenceAttempt, VddEvidenceError> {
    let scope = format!(
        "worker:{}:{}",
        request.worker_result().task_id,
        request.worker_result().task_revision
    );
    let scope_sha256 = ContentDigest::sha256(scope.as_bytes());
    let session_sha256 = ContentDigest::sha256(run.session_id().as_bytes());
    let request_bytes = serde_json::to_vec(request)?;
    let mut prompt_material = b"canonical-vdd-prompt-v2".to_vec();
    prompt_material.extend_from_slice(&request_bytes);
    let prompt_sha256 = ContentDigest::sha256(prompt_material);
    let receipt_sha256 = ContentDigest::sha256(serde_json::to_vec(receipt)?);
    let started_at = request
        .deterministic_receipts()
        .iter()
        .map(|evidence| evidence.observed_at)
        .min()
        .unwrap_or(receipt.completed_at);
    let expires_at = receipt
        .completed_at
        .checked_add_signed(Duration::days(
            i64::try_from(config.tracking.retention_days).unwrap_or(i64::MAX),
        ))
        .unwrap_or(DateTime::<Utc>::MAX_UTC);
    let mut model_calls = vec![model_evidence_from_identity(
        request.worker_identity(),
        VddProviderCallOutcome::Completed,
        receipt.completed_at,
    )];
    if let Some(verifier) = &receipt.verifier_identity {
        model_calls.push(model_evidence_from_identity(
            verifier,
            if receipt.verifier_run.is_some() {
                VddProviderCallOutcome::Completed
            } else {
                VddProviderCallOutcome::FailedOrUnknown
            },
            receipt.completed_at,
        ));
    }
    let deterministic_checks = request
        .deterministic_receipts()
        .iter()
        .map(|evidence| VddDeterministicEvidence {
            command_sha256: ContentDigest::sha256(evidence.check.as_bytes()),
            output_sha256: evidence.evidence_sha256,
            exit_code: match evidence.outcome {
                DeterministicCheckOutcome::Passed => 0,
                DeterministicCheckOutcome::Failed => 1,
                DeterministicCheckOutcome::Unavailable => -1,
            },
            passed: evidence.outcome == DeterministicCheckOutcome::Passed,
        })
        .collect();
    let mut findings = BTreeMap::new();
    if let Some(report) = &receipt.report {
        for finding in &report.findings {
            let id = finding.finding_sha256.to_string();
            let summary = run.sanitize_diagnostic(&finding.message).to_string();
            let summary = (!summary.is_empty())
                .then(|| truncate_utf8(&summary, MAX_SUMMARY_BYTES).to_string());
            let line_range = finding.range.and_then(|range| {
                Some((
                    usize::try_from(range.start_line).ok()?,
                    usize::try_from(range.end_line).ok()?,
                ))
            });
            let citation = VddEvidenceCitation {
                artifact_sha256: candidate.digest(),
                path: normalize_observed_path(finding.path.as_deref()),
                line_range: normalize_line_range(finding.path.as_deref(), line_range),
                observation_ids: finding.evidence.iter().map(ToString::to_string).collect(),
            };
            findings.insert(
                id,
                VddFindingEvidence {
                    finding_sha256: finding.finding_sha256,
                    severity: match finding.severity {
                        CanonicalFindingSeverity::Critical => Severity::Critical,
                        CanonicalFindingSeverity::High => Severity::High,
                        CanonicalFindingSeverity::Medium => Severity::Medium,
                        CanonicalFindingSeverity::Low => Severity::Low,
                    },
                    code: normalize_code(Some(&finding.code)),
                    summary,
                    description_sha256: ContentDigest::sha256(finding.message.as_bytes()),
                    reasoning_sha256: ContentDigest::sha256(report.summary.as_bytes()),
                    citations: vec![citation],
                    history: vec![VddFindingEvent {
                        state: VddFindingState::Genuine,
                        iteration: 1,
                        artifact_sha256: candidate.digest(),
                        observed_at: receipt.completed_at,
                    }],
                },
            );
        }
    }
    let unresolved_finding_ids = findings.keys().cloned().collect();
    let review_session_sha256 = receipt
        .verifier_run
        .as_ref()
        .and_then(|run| serde_json::to_vec(run).ok())
        .map(ContentDigest::sha256);
    let attempt_id = derive_attempt_id(
        session_sha256,
        scope_sha256,
        &candidate,
        outcome,
        review_session_sha256,
        receipt_sha256,
    );
    let mut attempt = VddEvidenceAttempt {
        attempt_id,
        attempt_sha256: ContentDigest::sha256([]),
        scope_sha256,
        session_sha256,
        candidate,
        mode: VddMode::Blocking,
        requirement,
        outcome,
        policy_sha256,
        prompt_sha256,
        canonical_receipt_sha256: Some(receipt_sha256),
        review_session_sha256,
        model_calls,
        deterministic_checks,
        findings,
        unresolved_finding_ids,
        started_at,
        finalized_at: receipt.completed_at,
        expires_at,
        sensitivity: VddEvidenceSensitivity::PrivateRedacted,
        redacted_at: None,
    };
    attempt.attempt_sha256 = digest_attempt(&attempt)?;
    Ok(attempt)
}

fn model_evidence_from_identity(
    identity: &super::VddModelIdentity,
    outcome: VddProviderCallOutcome,
    completed_at: DateTime<Utc>,
) -> VddModelEvidence {
    VddModelEvidence {
        provider: bounded_identity(identity.provider()),
        requested_model: bounded_identity(identity.model()),
        resolved_model: Some(bounded_identity(identity.model())),
        endpoint_sha256: Some(identity.endpoint_sha256()),
        identity_sha256: Some(identity.identity_sha256()),
        policy_generation: Some(identity.policy_generation()),
        outcome,
        usage_known: false,
        input_tokens: 0,
        output_tokens: 0,
        response_bytes: 0,
        completed_at,
    }
}

#[allow(clippy::too_many_arguments)]
fn persist_legacy_finalization_blocking(
    run: &ToolRunContext,
    config: &VddConfig,
    requirement: VddFinalizationRequirement,
    policy_sha256: ContentDigest,
    scope: &str,
    candidate: VddCandidateBinding,
    outcome: VddFinalizationOutcome,
    session: Option<&VddSession>,
    advisory_findings: &[Finding],
    advisory_static: &[StaticAnalysisResult],
    provider_receipts: &[VddProviderCallReceipt],
) -> Result<Option<VddEvidenceReceipt>, VddEvidenceError> {
    let store = VddEvidenceStore::open_for_run(run, config)?;
    let attempt = build_legacy_attempt(
        run,
        config,
        requirement,
        policy_sha256,
        scope,
        candidate,
        outcome,
        session,
        advisory_findings,
        advisory_static,
        provider_receipts,
    )?;
    let attempt_id = attempt.attempt_id.clone();
    let promote = config.tracking.promote_verified_findings
        && requirement == VddFinalizationRequirement::Required;
    let ((), mut ledger) =
        store.mutate(|ledger, _now| insert_attempt_and_actions(ledger, &attempt, promote))?;

    let mut issue_ids = Vec::new();
    if promote && has_pending_issue_actions(&ledger) {
        let receipts = reconcile_pending_crosslink(run, &ledger)?;
        if !receipts.is_empty() {
            let ((), updated) = store.mutate(|ledger, now| {
                apply_issue_receipts(ledger, &receipts, now);
                Ok(())
            })?;
            ledger = updated;
        }
    }
    issue_ids.extend(issue_ids_for_attempt(&ledger, &attempt_id));
    issue_ids.sort_unstable();
    issue_ids.dedup();
    Ok(Some(VddEvidenceReceipt {
        attempt_id,
        ledger_revision: ledger.revision,
        issue_ids,
    }))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn build_legacy_attempt(
    run: &ToolRunContext,
    config: &VddConfig,
    requirement: VddFinalizationRequirement,
    policy_sha256: ContentDigest,
    scope: &str,
    candidate: VddCandidateBinding,
    outcome: VddFinalizationOutcome,
    session: Option<&VddSession>,
    advisory_findings: &[Finding],
    advisory_static: &[StaticAnalysisResult],
    provider_receipts: &[VddProviderCallReceipt],
) -> Result<VddEvidenceAttempt, VddEvidenceError> {
    let scope_sha256 = ContentDigest::sha256(scope.as_bytes());
    let session_sha256 = ContentDigest::sha256(run.session_id().as_bytes());
    let prompt_material = [
        b"legacy-vdd-prompts-v1".as_slice(),
        ADVERSARY_SYSTEM_PROMPT.as_bytes(),
        VERIFIER_SYSTEM_PROMPT.as_bytes(),
    ]
    .concat();
    let prompt_sha256 = ContentDigest::sha256(prompt_material);
    let finalized_at = session
        .and_then(|review| review.ended_at)
        .unwrap_or_else(Utc::now);
    let started_at = session.map_or(finalized_at, |review| review.started_at);
    let expires_at = finalized_at
        .checked_add_signed(Duration::days(
            i64::try_from(config.tracking.retention_days).unwrap_or(i64::MAX),
        ))
        .unwrap_or(DateTime::<Utc>::MAX_UTC);
    let (review_session_sha256, findings, unresolved_finding_ids, checks) = if let Some(review) =
        session
    {
        let (findings, unresolved) = findings_from_session(run, review)?;
        let checks = review
            .iterations
            .iter()
            .flat_map(|iteration| deterministic_evidence(&iteration.static_analysis))
            .collect();
        (
            Some(ContentDigest::sha256(review.id.as_bytes())),
            findings,
            unresolved,
            checks,
        )
    } else {
        let artifact_sha256 = candidate.digest();
        let findings =
            findings_from_one_iteration(run, advisory_findings, artifact_sha256, 1, finalized_at)?;
        let unresolved = findings
            .iter()
            .filter(|(_, finding)| {
                finding
                    .history
                    .last()
                    .is_some_and(|event| event.state == VddFindingState::Genuine)
            })
            .map(|(id, _)| id.clone())
            .collect();
        (
            None,
            findings,
            unresolved,
            deterministic_evidence(advisory_static),
        )
    };
    let model_calls = provider_receipts
        .iter()
        .map(|receipt| VddModelEvidence {
            provider: bounded_identity(&receipt.provider),
            requested_model: bounded_identity(&receipt.requested_model),
            resolved_model: receipt.resolved_model.as_deref().map(bounded_identity),
            endpoint_sha256: None,
            identity_sha256: None,
            policy_generation: None,
            outcome: receipt.outcome,
            usage_known: receipt.usage_known,
            input_tokens: receipt.input_tokens,
            output_tokens: receipt.output_tokens,
            response_bytes: receipt.response_bytes,
            completed_at: receipt.completed_at,
        })
        .collect();
    let evidence_sha256 = ContentDigest::sha256(serde_json::to_vec(&serde_json::json!({
        "review_session": review_session_sha256,
        "model_calls": &model_calls,
        "deterministic_checks": &checks,
        "findings": &findings,
        "unresolved_findings": &unresolved_finding_ids,
        "finalized_at": finalized_at,
    }))?);
    let attempt_id = derive_attempt_id(
        session_sha256,
        scope_sha256,
        &candidate,
        outcome,
        review_session_sha256,
        evidence_sha256,
    );
    let mut attempt = VddEvidenceAttempt {
        attempt_id,
        attempt_sha256: ContentDigest::sha256([]),
        scope_sha256,
        session_sha256,
        candidate,
        mode: config.mode.clone(),
        requirement,
        outcome,
        policy_sha256,
        prompt_sha256,
        canonical_receipt_sha256: None,
        review_session_sha256,
        model_calls,
        deterministic_checks: checks,
        findings,
        unresolved_finding_ids,
        started_at,
        finalized_at,
        expires_at,
        sensitivity: VddEvidenceSensitivity::PrivateRedacted,
        redacted_at: None,
    };
    attempt.attempt_sha256 = digest_attempt(&attempt)?;
    Ok(attempt)
}

fn findings_from_session(
    run: &ToolRunContext,
    session: &VddSession,
) -> Result<(BTreeMap<String, VddFindingEvidence>, BTreeSet<String>), VddEvidenceError> {
    let mut findings = BTreeMap::new();
    let mut previous_genuine = BTreeSet::new();
    for iteration in &session.iterations {
        let artifact_sha256 = ContentDigest::sha256(iteration.builder_response.as_bytes());
        let observed = findings_from_one_iteration(
            run,
            &iteration.adversary_review.findings,
            artifact_sha256,
            iteration.number,
            iteration.adversary_review.timestamp,
        )?;
        let current_genuine = observed
            .iter()
            .filter(|(_, finding)| {
                finding
                    .history
                    .last()
                    .is_some_and(|event| event.state == VddFindingState::Genuine)
            })
            .map(|(id, _)| id.clone())
            .collect::<BTreeSet<_>>();
        for resolved in previous_genuine.difference(&current_genuine) {
            if let Some(finding) = findings.get_mut(resolved) {
                push_finding_event(
                    finding,
                    VddFindingEvent {
                        state: VddFindingState::Resolved,
                        iteration: iteration.number,
                        artifact_sha256,
                        observed_at: iteration.adversary_review.timestamp,
                    },
                )?;
            }
        }
        for (id, observed_finding) in observed {
            if let Some(existing) = findings.get_mut(&id) {
                for event in observed_finding.history {
                    push_finding_event(existing, event)?;
                }
                if existing.summary.is_none() {
                    existing.summary = observed_finding.summary;
                }
                for citation in observed_finding.citations {
                    if !existing.citations.contains(&citation) {
                        if existing.citations.len() >= MAX_CITATIONS {
                            return Err(VddEvidenceError::Capacity {
                                resource: "finding citations",
                                limit: MAX_CITATIONS,
                            });
                        }
                        existing.citations.push(citation);
                    }
                }
            } else {
                findings.insert(id, observed_finding);
            }
        }
        previous_genuine = current_genuine;
    }
    let unresolved = session
        .iterations
        .last()
        .map(|iteration| {
            let artifact_sha256 = ContentDigest::sha256(iteration.builder_response.as_bytes());
            iteration
                .adversary_review
                .findings
                .iter()
                .filter(|finding| finding.status == FindingStatus::Genuine)
                .filter_map(|finding| finding_identity(finding, artifact_sha256).ok())
                .map(|digest| digest.to_string())
                .collect()
        })
        .unwrap_or_default();
    Ok((findings, unresolved))
}

fn findings_from_one_iteration(
    run: &ToolRunContext,
    source: &[Finding],
    artifact_sha256: ContentDigest,
    iteration: u32,
    observed_at: DateTime<Utc>,
) -> Result<BTreeMap<String, VddFindingEvidence>, VddEvidenceError> {
    if source.len() > MAX_FINDINGS_PER_ATTEMPT {
        return Err(VddEvidenceError::Capacity {
            resource: "findings per attempt",
            limit: MAX_FINDINGS_PER_ATTEMPT,
        });
    }
    let mut findings = BTreeMap::new();
    for finding in source {
        let finding_sha256 = finding_identity(finding, artifact_sha256)?;
        let id = finding_sha256.to_string();
        let summary = run.sanitize_diagnostic(&finding.description).to_string();
        let summary = if summary.is_empty() {
            None
        } else {
            Some(truncate_utf8(&summary, MAX_SUMMARY_BYTES).to_string())
        };
        let citation = VddEvidenceCitation {
            artifact_sha256,
            path: normalize_observed_path(finding.file_path.as_deref()),
            line_range: normalize_line_range(finding.file_path.as_deref(), finding.line_range),
            observation_ids: Vec::new(),
        };
        let evidence = VddFindingEvidence {
            finding_sha256,
            severity: finding.severity.clone(),
            code: normalize_code(finding.cwe.as_deref()),
            summary,
            description_sha256: ContentDigest::sha256(finding.description.as_bytes()),
            reasoning_sha256: ContentDigest::sha256(finding.adversary_reasoning.as_bytes()),
            citations: vec![citation],
            history: vec![VddFindingEvent {
                state: match finding.status {
                    FindingStatus::Genuine => VddFindingState::Genuine,
                    FindingStatus::FalsePositive => VddFindingState::FalsePositive,
                    FindingStatus::Disputed => VddFindingState::Disputed,
                },
                iteration,
                artifact_sha256,
                observed_at,
            }],
        };
        findings.insert(id, evidence);
    }
    Ok(findings)
}

fn deterministic_evidence(results: &[StaticAnalysisResult]) -> Vec<VddDeterministicEvidence> {
    results
        .iter()
        .map(|result| {
            let mut output = Vec::with_capacity(result.stdout.len() + result.stderr.len() + 1);
            output.extend_from_slice(result.stdout.as_bytes());
            output.push(0);
            output.extend_from_slice(result.stderr.as_bytes());
            VddDeterministicEvidence {
                command_sha256: ContentDigest::sha256(result.command.as_bytes()),
                output_sha256: ContentDigest::sha256(output),
                exit_code: result.exit_code,
                passed: result.passed,
            }
        })
        .collect()
}

fn desired_issue_state(
    attempt: &VddEvidenceAttempt,
    finding_id: &str,
    finding: &VddFindingEvidence,
) -> Option<IssueDesiredState> {
    let last = finding.history.last()?;
    if attempt.unresolved_finding_ids.contains(finding_id)
        && last.state == VddFindingState::Genuine
        && matches!(
            attempt.outcome,
            VddFinalizationOutcome::Fail
                | VddFinalizationOutcome::Unconverged
                | VddFinalizationOutcome::FailOpen
        )
    {
        Some(IssueDesiredState::Open)
    } else if matches!(
        last.state,
        VddFindingState::Resolved | VddFindingState::FalsePositive
    ) {
        Some(IssueDesiredState::Resolved)
    } else {
        None
    }
}

fn insert_attempt_and_actions(
    ledger: &mut VddEvidenceLedger,
    attempt: &VddEvidenceAttempt,
    promote: bool,
) -> Result<(), VddEvidenceError> {
    if let Some(existing) = ledger.attempts.get(&attempt.attempt_id) {
        if existing != attempt {
            return Err(VddEvidenceError::InvalidLedger(
                "attempt identity collided with different evidence",
            ));
        }
    } else {
        if ledger.attempts.len() >= MAX_ATTEMPTS {
            return Err(VddEvidenceError::Capacity {
                resource: "attempts",
                limit: MAX_ATTEMPTS,
            });
        }
        ledger
            .attempts
            .insert(attempt.attempt_id.clone(), attempt.clone());
    }
    if !promote {
        return Ok(());
    }

    for (id, finding) in &attempt.findings {
        let Some(last) = finding.history.last() else {
            continue;
        };
        let desired = desired_issue_state(attempt, id, finding);
        let Some(desired) = desired else {
            continue;
        };
        let finding_key = format!("{}:{id}", attempt.scope_sha256);
        if desired == IssueDesiredState::Resolved
            && !ledger
                .issue_reconciliations
                .values()
                .any(|action| action.finding_key == finding_key)
        {
            continue;
        }
        let revision_micros = last.observed_at.timestamp_micros();
        let operation_id = derive_operation_id(&finding_key, desired, revision_micros);
        if ledger.issue_reconciliations.contains_key(&operation_id) {
            continue;
        }
        if ledger.issue_reconciliations.len() >= MAX_ISSUE_ACTIONS {
            return Err(VddEvidenceError::Capacity {
                resource: "issue reconciliations",
                limit: MAX_ISSUE_ACTIONS,
            });
        }
        ledger.issue_reconciliations.insert(
            operation_id.clone(),
            IssueReconciliation {
                operation_id,
                attempt_id: attempt.attempt_id.clone(),
                marker: issue_marker(&finding_key),
                finding_key,
                finding_sha256: finding.finding_sha256,
                desired,
                revision_micros,
                severity: finding.severity.clone(),
                code: finding.code.clone(),
                summary: finding.summary.clone(),
                citation: finding.citations.last().cloned(),
                state: IssueReconciliationState::Pending,
                issue_id: None,
                applied_at: None,
            },
        );
    }
    Ok(())
}

fn issue_ids_for_attempt(ledger: &VddEvidenceLedger, attempt_id: &str) -> Vec<i64> {
    ledger
        .issue_reconciliations
        .values()
        .filter(|action| action.attempt_id == attempt_id)
        .filter_map(|action| action.issue_id)
        .collect()
}

fn has_pending_issue_actions(ledger: &VddEvidenceLedger) -> bool {
    ledger
        .issue_reconciliations
        .values()
        .any(|action| action.state == IssueReconciliationState::Pending)
}

fn reconcile_pending_crosslink(
    run: &ToolRunContext,
    ledger: &VddEvidenceLedger,
) -> Result<BTreeMap<String, i64>, VddEvidenceError> {
    run.require(ToolResource::WorkspaceWrite)?;
    let dir = run.working_directory().join(".crosslink");
    fs::create_dir_all(&dir).map_err(|error| VddEvidenceError::Crosslink(error.to_string()))?;
    let db = crosslink::db::Database::open(&dir.join("issues.db"))
        .map_err(|error| VddEvidenceError::Crosslink(error.to_string()))?;
    let mut receipts = BTreeMap::new();
    for action in ledger
        .issue_reconciliations
        .values()
        .filter(|action| action.state == IssueReconciliationState::Pending)
    {
        let mut reconciled = None;
        let mut last_error = None;
        for attempt in 0..MAX_RECONCILE_RETRIES {
            match reconcile_crosslink_action(&db, action) {
                Ok(issue_id) => {
                    reconciled = Some(issue_id);
                    break;
                }
                Err(error) if attempt + 1 < MAX_RECONCILE_RETRIES => {
                    last_error = Some(error);
                    std::thread::yield_now();
                }
                Err(error) => last_error = Some(error),
            }
        }
        let issue_id = reconciled.ok_or_else(|| {
            last_error.unwrap_or_else(|| {
                VddEvidenceError::Crosslink("bounded reconciliation made no attempt".to_string())
            })
        })?;
        receipts.insert(action.operation_id.clone(), issue_id);
    }
    Ok(receipts)
}

fn reconcile_crosslink_action(
    db: &crosslink::db::Database,
    action: &IssueReconciliation,
) -> Result<i64, VddEvidenceError> {
    db.transaction(|| {
        let matches = db.search_issues(&action.marker)?;
        if matches.len() > 1 {
            anyhow::bail!("multiple Crosslink issues carry marker {}", action.marker);
        }
        let issue_id = if let Some(issue) = matches.first() {
            issue.id
        } else if action.desired == IssueDesiredState::Open {
            let title = format!(
                "VDD {} finding {}",
                action.severity,
                digest_prefix(action.finding_sha256)
            );
            let description = issue_description(action);
            let priority = match action.severity {
                Severity::Critical | Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low | Severity::Info => "low",
            };
            let issue_id = db.create_issue(&title, Some(&description), priority)?;
            db.add_label(
                issue_id,
                if action
                    .code
                    .as_deref()
                    .is_some_and(|code| code.starts_with("CWE-"))
                {
                    "security"
                } else {
                    "bug"
                },
            )?;
            issue_id
        } else {
            anyhow::bail!("cannot resolve a VDD issue whose marker has never been projected");
        };

        let comments = db.get_comments(issue_id)?;
        let newest_applied = comments
            .iter()
            .filter_map(|comment| parse_reconcile_revision(&comment.content))
            .max();
        if newest_applied.is_some_and(|(revision, desired)| {
            revision > action.revision_micros
                || revision == action.revision_micros
                    && desired == IssueDesiredState::Resolved
                    && action.desired == IssueDesiredState::Open
        }) {
            return Ok(issue_id);
        }
        let reconcile_marker = reconcile_marker(action);
        if !comments
            .iter()
            .any(|comment| comment.content.contains(&reconcile_marker))
        {
            let verb = match action.desired {
                IssueDesiredState::Open => "verified unresolved",
                IssueDesiredState::Resolved => "verified resolved",
            };
            db.add_comment(
                issue_id,
                &format!("VDD reconciliation: {verb}. {reconcile_marker}"),
                "note",
            )?;
        }
        match action.desired {
            IssueDesiredState::Open => {
                if let Some(issue) = db.get_issue(issue_id)? {
                    match issue.status {
                        crosslink::models::IssueStatus::Open => {}
                        crosslink::models::IssueStatus::Closed => {
                            db.reopen_issue(issue_id)?;
                        }
                        crosslink::models::IssueStatus::Archived => {
                            db.unarchive_issue(issue_id)?;
                            db.reopen_issue(issue_id)?;
                        }
                    }
                }
            }
            IssueDesiredState::Resolved => {
                db.close_issue(issue_id)?;
            }
        }
        Ok(issue_id)
    })
    .map_err(|error| VddEvidenceError::Crosslink(error.to_string()))
}

fn apply_issue_receipts(
    ledger: &mut VddEvidenceLedger,
    receipts: &BTreeMap<String, i64>,
    now: DateTime<Utc>,
) {
    for (operation_id, issue_id) in receipts {
        if let Some(action) = ledger.issue_reconciliations.get_mut(operation_id) {
            action.state = IssueReconciliationState::Applied;
            action.issue_id = Some(*issue_id);
            action.applied_at = Some(now);
        }
    }
}

fn issue_description(action: &IssueReconciliation) -> String {
    let mut description = String::from(
        "Checked VDD evidence found an unresolved defect. Descriptive text and paths below are redacted observations, not filesystem authority.\n\n",
    );
    if let Some(summary) = &action.summary {
        description.push_str("Summary: ");
        description.push_str(summary);
        description.push('\n');
    }
    if let Some(citation) = &action.citation {
        if let Some(path) = &citation.path {
            description.push_str("Observed location: ");
            description.push_str(path);
            if let Some((start, end)) = citation.line_range {
                let _ = write!(description, ":{start}-{end}");
            }
            description.push('\n');
        }
        let _ = writeln!(description, "Artifact: {}", citation.artifact_sha256);
    }
    let _ = writeln!(description, "Finding: {}", action.finding_sha256);
    description.push_str(&action.marker);
    truncate_utf8(&description, 32 * 1024).to_string()
}

fn finding_identity(
    finding: &Finding,
    artifact_sha256: ContentDigest,
) -> Result<ContentDigest, VddEvidenceError> {
    let path = normalize_observed_path(finding.file_path.as_deref());
    let range = normalize_line_range(finding.file_path.as_deref(), finding.line_range);
    let code = normalize_code(finding.cwe.as_deref());
    let description_sha256 = ContentDigest::sha256(finding.description.as_bytes());
    let seed = serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "code": code,
        "path": path,
        "range": range,
        "description_fallback": if code.is_none() && path.is_none() {
            Some(description_sha256)
        } else {
            None
        },
        "artifact_fallback": if code.is_none() && path.is_none() {
            Some(artifact_sha256)
        } else {
            None
        },
    }))?;
    Ok(ContentDigest::sha256(seed))
}

fn derive_attempt_id(
    session_sha256: ContentDigest,
    scope_sha256: ContentDigest,
    candidate: &VddCandidateBinding,
    outcome: VddFinalizationOutcome,
    review_session_sha256: Option<ContentDigest>,
    evidence_sha256: ContentDigest,
) -> String {
    ContentDigest::sha256(
        serde_json::to_vec(&serde_json::json!({
            "schema": 1,
            "session": session_sha256,
            "scope": scope_sha256,
            "candidate": candidate,
            "outcome": outcome,
            "review_session": review_session_sha256,
            "evidence": evidence_sha256,
        }))
        .unwrap_or_default(),
    )
    .to_string()
}

fn derive_operation_id(
    finding_key: &str,
    desired: IssueDesiredState,
    revision_micros: i64,
) -> String {
    ContentDigest::sha256(format!(
        "vdd-issue-operation-v1\0{finding_key}\0{desired:?}\0{revision_micros}"
    ))
    .to_string()
}

#[derive(Serialize)]
struct AttemptDigestSeed<'a> {
    attempt_id: &'a str,
    scope_sha256: ContentDigest,
    session_sha256: ContentDigest,
    candidate: &'a VddCandidateBinding,
    mode: &'a VddMode,
    requirement: VddFinalizationRequirement,
    outcome: VddFinalizationOutcome,
    policy_sha256: ContentDigest,
    prompt_sha256: ContentDigest,
    canonical_receipt_sha256: Option<ContentDigest>,
    review_session_sha256: Option<ContentDigest>,
    model_calls: &'a [VddModelEvidence],
    deterministic_checks: &'a [VddDeterministicEvidence],
    findings: &'a BTreeMap<String, VddFindingEvidence>,
    unresolved_finding_ids: &'a BTreeSet<String>,
    started_at: DateTime<Utc>,
    finalized_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    sensitivity: VddEvidenceSensitivity,
    redacted_at: Option<DateTime<Utc>>,
}

fn digest_attempt(attempt: &VddEvidenceAttempt) -> Result<ContentDigest, VddEvidenceError> {
    let seed = AttemptDigestSeed {
        attempt_id: &attempt.attempt_id,
        scope_sha256: attempt.scope_sha256,
        session_sha256: attempt.session_sha256,
        candidate: &attempt.candidate,
        mode: &attempt.mode,
        requirement: attempt.requirement,
        outcome: attempt.outcome,
        policy_sha256: attempt.policy_sha256,
        prompt_sha256: attempt.prompt_sha256,
        canonical_receipt_sha256: attempt.canonical_receipt_sha256,
        review_session_sha256: attempt.review_session_sha256,
        model_calls: &attempt.model_calls,
        deterministic_checks: &attempt.deterministic_checks,
        findings: &attempt.findings,
        unresolved_finding_ids: &attempt.unresolved_finding_ids,
        started_at: attempt.started_at,
        finalized_at: attempt.finalized_at,
        expires_at: attempt.expires_at,
        sensitivity: attempt.sensitivity,
        redacted_at: attempt.redacted_at,
    };
    Ok(ContentDigest::sha256(serde_json::to_vec(&seed)?))
}

fn redact_attempt(attempt: &mut VddEvidenceAttempt, now: DateTime<Utc>) {
    if attempt.sensitivity == VddEvidenceSensitivity::Tombstone {
        return;
    }
    for finding in attempt.findings.values_mut() {
        finding.summary = None;
    }
    attempt.sensitivity = VddEvidenceSensitivity::Tombstone;
    attempt.redacted_at = Some(now);
    attempt.attempt_sha256 = digest_attempt(attempt).unwrap_or(attempt.attempt_sha256);
}

fn push_finding_event(
    finding: &mut VddFindingEvidence,
    event: VddFindingEvent,
) -> Result<(), VddEvidenceError> {
    if finding.history.last() == Some(&event) {
        return Ok(());
    }
    if finding.history.len() >= MAX_FINDING_HISTORY {
        return Err(VddEvidenceError::Capacity {
            resource: "finding status history",
            limit: MAX_FINDING_HISTORY,
        });
    }
    finding.history.push(event);
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), VddEvidenceError> {
    if value.is_empty()
        || value.len() > MAX_LEDGER_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(VddEvidenceError::InvalidLedger("invalid ledger identity"));
    }
    Ok(())
}

fn normalize_code(raw: Option<&str>) -> Option<String> {
    let value = raw?.trim().to_ascii_uppercase();
    if value.is_empty()
        || value.len() > MAX_CODE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return None;
    }
    Some(value)
}

fn normalize_observed_path(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    if raw.is_empty() || raw.len() > MAX_PATH_BYTES || raw.contains(['\\', '\0']) {
        return None;
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        return None;
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?),
            _ => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn normalize_line_range(
    raw_path: Option<&str>,
    range: Option<(usize, usize)>,
) -> Option<(usize, usize)> {
    normalize_observed_path(raw_path)?;
    let (start, end) = range?;
    (start > 0 && end >= start && end.saturating_sub(start) <= 100_000).then_some((start, end))
}

fn bounded_identity(value: &str) -> String {
    truncate_utf8(value.trim(), 512).to_string()
}

fn truncate_utf8(value: &str, max: usize) -> &str {
    if value.len() <= max {
        return value;
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn issue_marker(finding_key: &str) -> String {
    format!(
        "[{ISSUE_MARKER_PREFIX}:{}]",
        ContentDigest::sha256(finding_key.as_bytes())
    )
}

fn reconcile_marker(action: &IssueReconciliation) -> String {
    let desired = match action.desired {
        IssueDesiredState::Open => "open",
        IssueDesiredState::Resolved => "resolved",
    };
    format!(
        "[{RECONCILE_MARKER_PREFIX}:{}:{desired}:{}]",
        action.revision_micros, action.operation_id,
    )
}

fn parse_reconcile_revision(comment: &str) -> Option<(i64, IssueDesiredState)> {
    let prefix = format!("[{RECONCILE_MARKER_PREFIX}:");
    let start = comment.find(&prefix)? + prefix.len();
    let remainder = &comment[start..];
    let revision_end = remainder.find(':')?;
    let revision = remainder[..revision_end].parse().ok()?;
    let remainder = &remainder[revision_end + 1..];
    let desired_end = remainder.find(':')?;
    let desired = match &remainder[..desired_end] {
        "open" => IssueDesiredState::Open,
        "resolved" => IssueDesiredState::Resolved,
        _ => return None,
    };
    Some((revision, desired))
}

fn digest_prefix(digest: ContentDigest) -> String {
    digest.to_string().chars().skip(7).take(12).collect()
}

fn resolve_evidence_root(
    run: &ToolRunContext,
    configured: &Path,
) -> Result<PathBuf, VddEvidenceError> {
    let candidate = if configured.is_absolute() {
        configured.to_path_buf()
    } else {
        run.working_directory().join(configured)
    };
    let mut normalized = PathBuf::new();
    for component in candidate.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => return Err(VddEvidenceError::UnsafeStorageRoot),
        }
    }
    if !normalized.is_absolute() {
        return Err(VddEvidenceError::UnsafeStorageRoot);
    }
    #[cfg(any(unix, windows))]
    if run.is_denied_path(&normalized) {
        run.host_control_root_handle_for(&normalized, true)
            .map_err(|_| VddEvidenceError::UnsafeStorageRoot)?;
    } else if !run.permits_write(&normalized) {
        return Err(VddEvidenceError::UnsafeStorageRoot);
    }
    #[cfg(not(any(unix, windows)))]
    if !run.permits_write(&normalized) {
        return Err(VddEvidenceError::UnsafeStorageRoot);
    }
    Ok(normalized)
}

fn prepare_private_evidence_root(
    run: &ToolRunContext,
    root: &Path,
) -> Result<(), VddEvidenceError> {
    #[cfg(not(unix))]
    let _ = run;
    if !root.is_absolute() {
        return Err(VddEvidenceError::UnsafeStorageRoot);
    }
    #[cfg(unix)]
    if run.is_denied_path(root) {
        crate::tools::file::secure_fs::prepare_private_host_control_directory(run, root)
            .map_err(|_| VddEvidenceError::UnsafeStorageRoot)?;
        return Ok(());
    }
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(VddEvidenceError::UnsafeStorageRoot);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                let mut builder = fs::DirBuilder::new();
                builder.recursive(true).mode(0o700);
                builder
                    .create(root)
                    .map_err(|_| VddEvidenceError::UnsafeStorageRoot)?;
            }
            #[cfg(not(unix))]
            fs::create_dir_all(root).map_err(|_| VddEvidenceError::UnsafeStorageRoot)?;
        }
        Err(_) => return Err(VddEvidenceError::UnsafeStorageRoot),
    }
    let metadata = fs::symlink_metadata(root).map_err(|_| VddEvidenceError::UnsafeStorageRoot)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(VddEvidenceError::UnsafeStorageRoot);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        // SAFETY: `geteuid` has no preconditions and retains no pointer.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid || metadata.permissions().mode() & 0o077 != 0 {
            return Err(VddEvidenceError::UnsafeStorageRoot);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracking_config(root: &Path, promote: bool) -> VddConfig {
        let mut config = VddConfig {
            enabled: true,
            mode: VddMode::Blocking,
            ..VddConfig::default()
        };
        config.tracking.path = root.join("evidence");
        config.tracking.promote_verified_findings = promote;
        config
    }

    fn finding(status: FindingStatus, description: &str) -> Finding {
        Finding {
            id: "model-supplied-id".to_string(),
            severity: Severity::High,
            cwe: Some("CWE-20".to_string()),
            description: description.to_string(),
            file_path: Some("src/lib.rs".to_string()),
            line_range: Some((10, 12)),
            status,
            adversary_reasoning: "checked by verifier".to_string(),
            iteration: 1,
        }
    }

    fn iteration(
        number: u32,
        builder_response: &str,
        findings: Vec<Finding>,
        observed_at: DateTime<Utc>,
    ) -> super::super::VddIteration {
        let genuine_count = u32::try_from(
            findings
                .iter()
                .filter(|finding| finding.status == FindingStatus::Genuine)
                .count(),
        )
        .expect("bounded test finding count");
        let false_positive_count = u32::try_from(
            findings
                .iter()
                .filter(|finding| finding.status == FindingStatus::FalsePositive)
                .count(),
        )
        .expect("bounded test finding count");
        super::super::VddIteration {
            number,
            builder_response: builder_response.to_string(),
            static_analysis: vec![StaticAnalysisResult {
                command: "deterministic-check".to_string(),
                exit_code: 0,
                stdout: "passed".to_string(),
                stderr: String::new(),
                passed: true,
            }],
            adversary_review: super::super::AdversaryReview {
                iteration: number,
                findings,
                raw_response: "raw provider body must not persist".to_string(),
                tokens_used: crate::session::TokenUsage::default(),
                timestamp: observed_at,
            },
            genuine_count,
            false_positive_count,
        }
    }

    fn review_session(iterations: Vec<super::super::VddIteration>, converged: bool) -> VddSession {
        let mut session = VddSession::new(VddMode::Blocking);
        for iteration in iterations {
            session.record_iteration(iteration);
        }
        session.finalize(
            converged,
            if converged {
                "verified convergence"
            } else {
                "bounded review remained unresolved"
            },
        );
        session
    }

    #[cfg(unix)]
    fn private_tempdir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
        root
    }

    #[cfg(unix)]
    #[test]
    fn default_relative_evidence_root_resolves_inside_the_run_workspace() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = private_tempdir();
        let run = crate::tools::security::test_run_context_for(root.path());
        let mut config = VddConfig {
            enabled: true,
            ..VddConfig::default()
        };
        let legacy_root = root.path().join(".openclaudia/vdd");
        fs::create_dir_all(&legacy_root).expect("legacy evidence root");
        fs::set_permissions(&legacy_root, fs::Permissions::from_mode(0o755))
            .expect("legacy evidence permissions");
        let store = VddEvidenceStore::open_for_run(&run, &config).expect("default store");
        assert_eq!(
            store.storage.root_path(),
            root.path().join(".openclaudia/vdd")
        );
        assert_eq!(
            fs::metadata(&legacy_root)
                .expect("private evidence metadata")
                .permissions()
                .mode()
                & 0o077,
            0
        );
        config.tracking.path = PathBuf::from("../outside");
        assert!(matches!(
            VddEvidenceStore::open_for_run(&run, &config),
            Err(VddEvidenceError::UnsafeStorageRoot)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn store_rejects_stale_generation_without_losing_first_attempt() {
        let root = private_tempdir();
        let store =
            VddEvidenceStore::open(root.path(), "ledger.json", "session:test").expect("open store");
        let first = store.load().expect("first load");
        let second = store.load().expect("second load");
        let mut first_ledger = first.ledger;
        first_ledger.revision = 1;
        store
            .commit(first.storage_generation, &first_ledger)
            .expect("first commit");
        let mut stale = second.ledger;
        stale.revision = 2;
        assert!(matches!(
            store.commit(second.storage_generation, &stale),
            Err(VddEvidenceError::Persistence(
                PersistenceError::Conflict { .. }
            ))
        ));
        assert_eq!(store.load().expect("reload").ledger.revision(), 1);
    }

    #[test]
    fn untrusted_paths_are_observations_not_authority() {
        assert_eq!(
            normalize_observed_path(Some("src/lib.rs")),
            Some("src/lib.rs".to_string())
        );
        assert_eq!(normalize_observed_path(Some("../../etc/passwd")), None);
        assert_eq!(normalize_observed_path(Some("/etc/passwd")), None);
        assert_eq!(normalize_line_range(Some("src/lib.rs"), Some((9, 4))), None);
    }

    #[test]
    fn reconcile_marker_exposes_monotonic_revision() {
        let action = IssueReconciliation {
            operation_id: "operation".to_string(),
            attempt_id: "attempt".to_string(),
            finding_key: "finding".to_string(),
            finding_sha256: ContentDigest::sha256(b"finding"),
            marker: issue_marker("finding"),
            desired: IssueDesiredState::Open,
            revision_micros: 42,
            severity: Severity::High,
            code: None,
            summary: None,
            citation: None,
            state: IssueReconciliationState::Pending,
            issue_id: None,
            applied_at: None,
        };
        let marker = reconcile_marker(&action);
        assert_eq!(
            parse_reconcile_revision(&marker),
            Some((42, IssueDesiredState::Open))
        );
    }

    #[cfg(unix)]
    #[test]
    fn crash_window_retry_reuses_one_crosslink_issue() {
        let root = private_tempdir();
        let run = crate::tools::security::test_run_context_for(root.path());
        let config = tracking_config(root.path(), true);
        let observed_at = Utc::now();
        let session = review_session(
            vec![iteration(
                1,
                "candidate-v1",
                vec![finding(FindingStatus::Genuine, "reachable defect")],
                observed_at,
            )],
            false,
        );
        let binding = VddCandidateBinding::for_response(&run, "scope", b"candidate-v1")
            .expect("candidate binding");
        let store = VddEvidenceStore::open_for_run(&run, &config).expect("evidence store");
        let attempt = build_legacy_attempt(
            &run,
            &config,
            VddFinalizationRequirement::Required,
            ContentDigest::sha256(b"policy"),
            "scope",
            binding.clone(),
            VddFinalizationOutcome::Unconverged,
            Some(&session),
            &[],
            &[],
            &[],
        )
        .expect("attempt");
        let ((), ledger) = store
            .mutate(|ledger, _| insert_attempt_and_actions(ledger, &attempt, true))
            .expect("journal intent");
        let first = reconcile_pending_crosslink(&run, &ledger).expect("external commit");
        assert_eq!(first.len(), 1);

        // Simulate a process stop before `apply_issue_receipts`, then retry the
        // complete finalization against the still-pending journal.
        let receipt = persist_legacy_finalization_blocking(
            &run,
            &config,
            VddFinalizationRequirement::Required,
            ContentDigest::sha256(b"policy"),
            "scope",
            binding.clone(),
            VddFinalizationOutcome::Unconverged,
            Some(&session),
            &[],
            &[],
            &[],
        )
        .expect("recovered finalization")
        .expect("persistence enabled");
        let db = crosslink::db::Database::open(&root.path().join(".crosslink/issues.db"))
            .expect("crosslink database");
        assert_eq!(
            db.list_issues(Some("all"), None, None)
                .expect("issues")
                .len(),
            1
        );
        assert_eq!(receipt.issue_ids.len(), 1);
        assert_eq!(store.load().expect("ledger").ledger.attempts.len(), 1);
        let retry = persist_legacy_finalization_blocking(
            &run,
            &config,
            VddFinalizationRequirement::Required,
            ContentDigest::sha256(b"policy"),
            "scope",
            binding,
            VddFinalizationOutcome::Unconverged,
            Some(&session),
            &[],
            &[],
            &[],
        )
        .expect("ordinary retry")
        .expect("persistence enabled");
        assert_eq!(retry.issue_ids, receipt.issue_ids);
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_retry_keeps_one_attempt_and_one_issue() {
        let root = private_tempdir();
        let run = crate::tools::security::test_run_context_for(root.path());
        let config = tracking_config(root.path(), true);
        let session = review_session(
            vec![iteration(
                1,
                "candidate-v1",
                vec![finding(FindingStatus::Genuine, "concurrent defect")],
                Utc::now(),
            )],
            false,
        );
        let binding = VddCandidateBinding::for_response(&run, "scope", b"candidate-v1")
            .expect("candidate binding");
        std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                persist_legacy_finalization_blocking(
                    &run,
                    &config,
                    VddFinalizationRequirement::Required,
                    ContentDigest::sha256(b"policy"),
                    "scope",
                    binding.clone(),
                    VddFinalizationOutcome::Unconverged,
                    Some(&session),
                    &[],
                    &[],
                    &[],
                )
            });
            let second = scope.spawn(|| {
                persist_legacy_finalization_blocking(
                    &run,
                    &config,
                    VddFinalizationRequirement::Required,
                    ContentDigest::sha256(b"policy"),
                    "scope",
                    binding.clone(),
                    VddFinalizationOutcome::Unconverged,
                    Some(&session),
                    &[],
                    &[],
                    &[],
                )
            });
            first.join().expect("first thread").expect("first retry");
            second.join().expect("second thread").expect("second retry");
        });
        let store = VddEvidenceStore::open_for_run(&run, &config).expect("store");
        assert_eq!(store.load().expect("ledger").ledger.attempts.len(), 1);
        let db = crosslink::db::Database::open(&root.path().join(".crosslink/issues.db"))
            .expect("crosslink database");
        assert_eq!(
            db.list_issues(Some("all"), None, None)
                .expect("issues")
                .len(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn identical_findings_in_distinct_scopes_keep_distinct_issue_state() {
        let root = private_tempdir();
        let run = crate::tools::security::test_run_context_for(root.path());
        let config = tracking_config(root.path(), true);
        let session = review_session(
            vec![iteration(
                1,
                "candidate-v1",
                vec![finding(FindingStatus::Genuine, "shared-looking defect")],
                Utc::now(),
            )],
            false,
        );
        for scope in ["task-a", "task-b"] {
            let binding = VddCandidateBinding::for_response(&run, scope, b"candidate-v1")
                .expect("candidate binding");
            let receipt = persist_legacy_finalization_blocking(
                &run,
                &config,
                VddFinalizationRequirement::Required,
                ContentDigest::sha256(b"policy"),
                scope,
                binding,
                VddFinalizationOutcome::Unconverged,
                Some(&session),
                &[],
                &[],
                &[],
            )
            .expect("persist")
            .expect("receipt");
            assert_eq!(receipt.issue_ids.len(), 1);
        }
        let db = crosslink::db::Database::open(&root.path().join(".crosslink/issues.db"))
            .expect("crosslink database");
        assert_eq!(
            db.list_issues(Some("all"), None, None)
                .expect("issues")
                .len(),
            2
        );
    }

    #[cfg(unix)]
    #[test]
    fn fixed_revision_preserves_history_without_creating_stale_issue() {
        let root = private_tempdir();
        let run = crate::tools::security::test_run_context_for(root.path());
        let config = tracking_config(root.path(), true);
        let first_at = Utc::now();
        let second_at = first_at + Duration::seconds(1);
        let session = review_session(
            vec![
                iteration(
                    1,
                    "candidate-v1",
                    vec![finding(FindingStatus::Genuine, "reachable defect")],
                    first_at,
                ),
                iteration(
                    2,
                    "candidate-v2",
                    vec![finding(FindingStatus::FalsePositive, "reachable defect")],
                    second_at,
                ),
            ],
            true,
        );
        let binding = VddCandidateBinding::for_response(&run, "scope", b"candidate-v2")
            .expect("candidate binding");
        let receipt = persist_legacy_finalization_blocking(
            &run,
            &config,
            VddFinalizationRequirement::Required,
            ContentDigest::sha256(b"policy"),
            "scope",
            binding,
            VddFinalizationOutcome::Pass,
            Some(&session),
            &[],
            &[],
            &[],
        )
        .expect("persist")
        .expect("receipt");
        assert!(receipt.issue_ids.is_empty());
        let store = VddEvidenceStore::open_for_run(&run, &config).expect("store");
        let attempt = store.export_attempt(&receipt.attempt_id).expect("attempt");
        let evidence = attempt.findings.values().next().expect("finding history");
        assert!(evidence
            .history
            .iter()
            .any(|event| event.state == VddFindingState::Resolved));
        assert_eq!(
            evidence
                .citations
                .first()
                .expect("first citation")
                .artifact_sha256,
            ContentDigest::sha256(b"candidate-v1")
        );
        assert!(!root.path().join(".crosslink/issues.db").exists());
    }

    #[cfg(unix)]
    #[test]
    fn stale_finalization_cannot_promote_review_findings() {
        let root = private_tempdir();
        let run = crate::tools::security::test_run_context_for(root.path());
        let config = tracking_config(root.path(), true);
        let session = review_session(
            vec![iteration(
                1,
                "candidate-v1",
                vec![finding(FindingStatus::Genuine, "obsolete defect")],
                Utc::now(),
            )],
            false,
        );
        let binding = VddCandidateBinding::for_response(&run, "scope", b"candidate-v2")
            .expect("candidate binding");
        let receipt = persist_legacy_finalization_blocking(
            &run,
            &config,
            VddFinalizationRequirement::Required,
            ContentDigest::sha256(b"policy"),
            "scope",
            binding,
            VddFinalizationOutcome::Stale,
            Some(&session),
            &[],
            &[],
            &[],
        )
        .expect("persist")
        .expect("receipt");
        assert!(receipt.issue_ids.is_empty());
        let store = VddEvidenceStore::open_for_run(&run, &config).expect("store");
        let attempt = store.export_attempt(&receipt.attempt_id).expect("attempt");
        assert!(!attempt.unresolved_finding_ids.is_empty());
        assert!(!root.path().join(".crosslink/issues.db").exists());
    }

    #[cfg(unix)]
    #[test]
    fn export_and_delete_never_retain_raw_provider_or_secret_text() {
        let root = private_tempdir();
        let run = crate::tools::security::test_run_context_for(root.path());
        let config = tracking_config(root.path(), false);
        let session = review_session(
            vec![iteration(
                1,
                "private builder body",
                vec![finding(
                    FindingStatus::Genuine,
                    "api_key=super-secret-value reachable defect",
                )],
                Utc::now(),
            )],
            false,
        );
        let binding = VddCandidateBinding::for_response(&run, "scope", b"private builder body")
            .expect("candidate binding");
        let receipt = persist_legacy_finalization_blocking(
            &run,
            &config,
            VddFinalizationRequirement::Required,
            ContentDigest::sha256(b"policy"),
            "scope",
            binding.clone(),
            VddFinalizationOutcome::Unconverged,
            Some(&session),
            &[],
            &[],
            &[],
        )
        .expect("persist")
        .expect("receipt");
        let store = VddEvidenceStore::open_for_run(&run, &config).expect("store");
        assert_eq!(
            store.attempt_ids().expect("attempt identities"),
            vec![receipt.attempt_id.clone()]
        );
        let exported = store.export_attempt(&receipt.attempt_id).expect("export");
        let encoded = serde_json::to_string(&exported).expect("encode export");
        assert!(!encoded.contains("super-secret-value"));
        assert!(!encoded.contains("private builder body"));
        assert!(!encoded.contains("raw provider body"));
        store
            .delete_attempt(&receipt.attempt_id)
            .expect("delete prose");
        let tombstone = store
            .export_attempt(&receipt.attempt_id)
            .expect("tombstone");
        assert_eq!(tombstone.sensitivity, VddEvidenceSensitivity::Tombstone);
        assert_eq!(tombstone.candidate, binding);
        assert!(tombstone
            .findings
            .values()
            .all(|finding| finding.summary.is_none() && !finding.history.is_empty()));
    }

    #[cfg(unix)]
    #[test]
    fn export_enforces_expired_prose_retention() {
        let root = private_tempdir();
        let run = crate::tools::security::test_run_context_for(root.path());
        let mut config = tracking_config(root.path(), false);
        config.tracking.retention_days = 0;
        let session = review_session(
            vec![iteration(
                1,
                "candidate-v1",
                vec![finding(
                    FindingStatus::Genuine,
                    "retained only until export",
                )],
                Utc::now(),
            )],
            false,
        );
        let binding = VddCandidateBinding::for_response(&run, "scope", b"candidate-v1")
            .expect("candidate binding");
        let receipt = persist_legacy_finalization_blocking(
            &run,
            &config,
            VddFinalizationRequirement::Required,
            ContentDigest::sha256(b"policy"),
            "scope",
            binding,
            VddFinalizationOutcome::Unconverged,
            Some(&session),
            &[],
            &[],
            &[],
        )
        .expect("persist")
        .expect("receipt");
        let store = VddEvidenceStore::open_for_run(&run, &config).expect("store");
        let exported = store.export_attempt(&receipt.attempt_id).expect("export");
        assert_eq!(exported.sensitivity, VddEvidenceSensitivity::Tombstone);
        assert!(exported
            .findings
            .values()
            .all(|finding| finding.summary.is_none()));
    }

    #[cfg(unix)]
    #[test]
    fn older_reconciliation_cannot_reopen_newer_resolution() {
        let root = private_tempdir();
        let db = crosslink::db::Database::open(&root.path().join("issues.db")).expect("database");
        let finding_sha256 = ContentDigest::sha256(b"stable-finding");
        let mut open = IssueReconciliation {
            operation_id: "open-operation".to_string(),
            attempt_id: "attempt-open".to_string(),
            finding_key: "scope:finding".to_string(),
            finding_sha256,
            marker: issue_marker("scope:finding"),
            desired: IssueDesiredState::Open,
            revision_micros: 10,
            severity: Severity::High,
            code: Some("CWE-20".to_string()),
            summary: Some("reachable defect".to_string()),
            citation: None,
            state: IssueReconciliationState::Pending,
            issue_id: None,
            applied_at: None,
        };
        let issue_id = reconcile_crosslink_action(&db, &open).expect("open issue");
        let mut resolved = open.clone();
        resolved.operation_id = "resolved-operation".to_string();
        resolved.attempt_id = "attempt-resolved".to_string();
        resolved.desired = IssueDesiredState::Resolved;
        resolved.revision_micros = 20;
        reconcile_crosslink_action(&db, &resolved).expect("resolve issue");
        open.operation_id = "late-old-open".to_string();
        reconcile_crosslink_action(&db, &open).expect("ignore stale open");
        assert_eq!(
            db.require_issue(issue_id).expect("issue").status,
            crosslink::models::IssueStatus::Closed
        );
        assert_eq!(
            db.list_issues(Some("all"), None, None)
                .expect("issues")
                .len(),
            1
        );
    }
}
