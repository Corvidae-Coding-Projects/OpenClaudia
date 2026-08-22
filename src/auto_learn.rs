//! Evidence-bound automatic learning for codebase-specific technical lessons.
//!
//! This module deliberately does not inspect user prose, assistant prose, or
//! prompt-expanded repository text. The canonical tool executor supplies typed
//! post-authorization results. A bounded run-local state machine can turn one
//! narrow causal sequence into a private technical-lesson *candidate*:
//!
//! 1. an allowlisted verification command fails;
//! 2. one or more successful file mutations occur in the same exact task;
//! 3. the exact command and arguments later succeed in that same task.
//!
//! The resulting lesson says only that recovery was observed. It remains
//! untrusted, carries exact tool-result citations, expires into review, and
//! never claims that correlation proves the edits were the cause. A later
//! failure of the same command creates a causal correction that contradicts
//! the earlier candidate. Unrelated success, task changes, prose, generic edit
//! failures, and co-edit frequency cannot create a lesson.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::str::FromStr as _;
use std::sync::{LazyLock, Mutex, MutexGuard};

use serde::Serialize;

use crate::memory::{
    LessonApplicability, LessonCitation, LessonCitationKind, LessonRetention, MemoryDb,
    MemoryDigest, MemorySourceEvidence, MemorySourceKind, TechnicalLessonConfidence,
    TechnicalLessonCorrectionRequest, TechnicalLessonDraft, TechnicalLessonKind,
    TechnicalLessonRecord, TechnicalLessonSensitivity,
};
use crate::runtime::{CapabilityGeneration, RunId};
use crate::session::{TaskManager, TaskStatus};
use crate::tools::{ToolFailureCode, ToolObservation, ToolOutcome, ToolResult, ToolRunContext};

pub const AUTOMATIC_LEARNING_SCHEMA_VERSION: u32 = 1;
const MAX_ACTIVE_RUNS: usize = 128;
const MAX_PENDING_CHECKS_PER_RUN: usize = 32;
const MAX_MUTATIONS_PER_CHECK: usize = 16;
const MAX_LEARNED_CHECKS_PER_RUN: usize = 32;
const MAX_RETAINED_COMMAND_BYTES: usize = 512;
const REVIEW_AFTER_SECONDS: i64 = 30 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RunKey {
    run_id: RunId,
    capability_generation: CapabilityGeneration,
}

impl RunKey {
    fn from_run(run: &ToolRunContext) -> Self {
        Self {
            run_id: run.run_id(),
            capability_generation: run.generation(),
        }
    }
}

/// Exact task context attached to every eligible learning observation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
pub enum LearningTaskBinding {
    CanonicalTask {
        graph_id: String,
        graph_generation: u64,
        task_id: String,
        task_revision: u64,
    },
    RunTask {
        run_id: String,
        task_generation: u64,
        task_sha256: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
enum VerificationClass {
    Build,
    Format,
    Lint,
    Test,
    TypeCheck,
}

impl VerificationClass {
    const fn lesson_kind(self) -> TechnicalLessonKind {
        match self {
            Self::Build | Self::TypeCheck => TechnicalLessonKind::Build,
            Self::Format | Self::Lint => TechnicalLessonKind::Tooling,
            Self::Test => TechnicalLessonKind::Testing,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Format => "format",
            Self::Lint => "lint",
            Self::Test => "test",
            Self::TypeCheck => "type-check",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CheckKey {
    workspace_id: String,
    task: LearningTaskBinding,
    arguments_digest: MemoryDigest,
}

#[derive(Debug, Clone)]
struct EvidenceRef {
    call_id_digest: MemoryDigest,
    result_digest: MemoryDigest,
    workspace_generation: u64,
}

#[derive(Debug, Clone)]
struct MutationRef {
    path: String,
    evidence: EvidenceRef,
}

#[derive(Debug, Clone)]
struct PendingFailure {
    class: VerificationClass,
    command: String,
    failure_code: &'static str,
    evidence: EvidenceRef,
    mutations: Vec<MutationRef>,
    mutation_evidence_complete: bool,
}

#[derive(Debug, Clone)]
struct LearnedCandidate {
    record: TechnicalLessonRecord,
    class: VerificationClass,
    command: String,
    applicability: LessonApplicability,
    citations: Vec<LessonCitation>,
}

#[derive(Debug, Default)]
struct RunLearningState {
    pending: HashMap<CheckKey, PendingFailure>,
    pending_order: VecDeque<CheckKey>,
    learned: HashMap<CheckKey, LearnedCandidate>,
    learned_order: VecDeque<CheckKey>,
    observations: u64,
    candidates: u64,
    contradictions: u64,
    degraded: u64,
}

#[derive(Debug, Default)]
struct LearningRegistry {
    runs: HashMap<RunKey, RunLearningState>,
    run_order: VecDeque<RunKey>,
}

static LEARNING: LazyLock<Mutex<LearningRegistry>> =
    LazyLock::new(|| Mutex::new(LearningRegistry::default()));

/// Bounded, non-sensitive health projection for one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutomaticLearningStatus {
    pub schema_version: u32,
    pub run_id: String,
    pub capability_generation: u64,
    pub pending_checks: usize,
    pub learned_candidates: usize,
    pub observations: u64,
    pub candidates_stored: u64,
    pub contradictions_stored: u64,
    pub degraded_events: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LearningEvidenceDisposition {
    FailurePending,
    MutationLinked,
    SuccessUnmatched,
    SuccessWithoutMutation,
}

/// Typed model-visible receipt attached to an eligible tool result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum LearningCaptureStatus {
    EvidenceRecorded {
        disposition: LearningEvidenceDisposition,
        linked_mutations: usize,
    },
    CandidateStored {
        logical_id: String,
        version: u64,
        record_digest: String,
    },
    ContradictionStored {
        logical_id: String,
        version: u64,
        record_digest: String,
    },
    Degraded {
        stage: &'static str,
        code: &'static str,
    },
}

/// Complete capture result bound to the source tool receipt and task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LearningCaptureReceipt {
    pub schema_version: u32,
    pub run_id: String,
    pub capability_generation: u64,
    pub workspace_generation: u64,
    pub task: LearningTaskBinding,
    pub tool: String,
    pub call_id_digest: String,
    pub result_digest: String,
    pub status: LearningCaptureStatus,
}

impl LearningCaptureReceipt {
    /// Project this receipt into the canonical tool result without granting it
    /// authority over the result or the model.
    #[must_use]
    pub fn into_tool_observation(self) -> ToolObservation {
        let data = serde_json::to_value(self).unwrap_or_else(|_| {
            serde_json::json!({
                "schema_version": AUTOMATIC_LEARNING_SCHEMA_VERSION,
                "status": "degraded",
                "stage": "receipt_encoding",
                "code": "serialization_failed"
            })
        });
        ToolObservation {
            kind: crate::tools::TECHNICAL_LEARNING_CAPTURE_OBSERVATION_KIND.to_string(),
            authoritative: false,
            data,
        }
    }
}

/// Observe one canonical post-authorization tool result.
///
/// Only eligible verification and file-mutation tools return a receipt. The
/// caller attaches it to the tool result so CLI, TUI, ACP, and subagents see
/// the same success/degraded state.
#[must_use]
pub fn observe_tool_result(
    run: &ToolRunContext,
    db: &MemoryDb,
    task_manager: Option<&TaskManager>,
    result: &ToolResult,
) -> Option<LearningCaptureReceipt> {
    match result.handler() {
        "bash" => observe_bash(run, db, task_manager, result),
        "edit_file" | "write_file" if !result.is_error() && !result.is_partial() => {
            observe_mutation(run, db, task_manager, result)
        }
        _ => None,
    }
}

/// Remove all process-local causal state for one retired run generation.
pub fn retire_run(run: &ToolRunContext) {
    let Ok(mut registry) = registry_guard("retire_run") else {
        return;
    };
    let key = RunKey::from_run(run);
    registry.runs.remove(&key);
    registry.run_order.retain(|candidate| *candidate != key);
}

/// Return a bounded health projection for a canonical run.
#[must_use]
pub fn status_for_run(run: &ToolRunContext) -> AutomaticLearningStatus {
    let key = RunKey::from_run(run);
    let Ok(registry) = registry_guard("status_for_run") else {
        return AutomaticLearningStatus {
            schema_version: AUTOMATIC_LEARNING_SCHEMA_VERSION,
            run_id: run.run_id().to_string(),
            capability_generation: run.generation().get(),
            pending_checks: 0,
            learned_candidates: 0,
            observations: 0,
            candidates_stored: 0,
            contradictions_stored: 0,
            degraded_events: 1,
        };
    };
    let state = registry.runs.get(&key);
    AutomaticLearningStatus {
        schema_version: AUTOMATIC_LEARNING_SCHEMA_VERSION,
        run_id: run.run_id().to_string(),
        capability_generation: run.generation().get(),
        pending_checks: state.map_or(0, |state| state.pending.len()),
        learned_candidates: state.map_or(0, |state| state.learned.len()),
        observations: state.map_or(0, |state| state.observations),
        candidates_stored: state.map_or(0, |state| state.candidates),
        contradictions_stored: state.map_or(0, |state| state.contradictions),
        degraded_events: state.map_or(0, |state| state.degraded),
    }
}

fn observe_bash(
    run: &ToolRunContext,
    db: &MemoryDb,
    task_manager: Option<&TaskManager>,
    result: &ToolResult,
) -> Option<LearningCaptureReceipt> {
    let arguments = result.invocation().arguments.as_ref()?;
    if arguments
        .get("run_in_background")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return None;
    }
    let command = arguments.get("command")?.as_str()?;
    let class = classify_verification_command(command)?;
    let context = match observation_context(run, db, task_manager, result) {
        Ok(context) => context,
        Err(failure) => {
            let ContextFailure {
                task,
                evidence,
                stage,
                code,
            } = *failure;
            increment_degraded(run);
            return Some(receipt(
                run,
                task,
                result,
                &evidence,
                LearningCaptureStatus::Degraded { stage, code },
            ));
        }
    };
    let key = CheckKey {
        workspace_id: context.workspace_id.clone(),
        task: context.task.clone(),
        arguments_digest: MemoryDigest::sha256(result.invocation().raw_arguments.as_bytes()),
    };
    if result.is_error() || result.is_partial() {
        Some(observe_verification_failure(
            run, db, result, key, class, command, context,
        ))
    } else {
        Some(observe_verification_success(run, db, result, key, context))
    }
}

fn observe_mutation(
    run: &ToolRunContext,
    db: &MemoryDb,
    task_manager: Option<&TaskManager>,
    result: &ToolResult,
) -> Option<LearningCaptureReceipt> {
    let path = mutation_path(run, result)?;
    let context = match observation_context(run, db, task_manager, result) {
        Ok(context) => context,
        Err(failure) => {
            let ContextFailure {
                task,
                evidence,
                stage,
                code,
            } = *failure;
            increment_degraded(run);
            return Some(receipt(
                run,
                task,
                result,
                &evidence,
                LearningCaptureStatus::Degraded { stage, code },
            ));
        }
    };
    let mutation = MutationRef {
        path,
        evidence: context.evidence.clone(),
    };
    let (linked, overflowed) = if let Ok(mut registry) = registry_guard("observe_mutation") {
        let state = state_for_run(&mut registry, run);
        state.observations = state.observations.saturating_add(1);
        let mut linked = 0_usize;
        let mut overflowed = false;
        for (key, pending) in &mut state.pending {
            if key.workspace_id == context.workspace_id && key.task == context.task {
                if !pending.mutations.iter().any(|existing| {
                    existing.evidence.result_digest == mutation.evidence.result_digest
                }) {
                    if pending.mutations.len() < MAX_MUTATIONS_PER_CHECK {
                        pending.mutations.push(mutation.clone());
                    } else {
                        pending.mutation_evidence_complete = false;
                        overflowed = true;
                    }
                }
                linked = linked.saturating_add(1);
            }
        }
        if overflowed {
            state.degraded = state.degraded.saturating_add(1);
        }
        (linked, overflowed)
    } else {
        increment_degraded(run);
        return Some(receipt(
            run,
            context.task,
            result,
            &context.evidence,
            LearningCaptureStatus::Degraded {
                stage: "state",
                code: "registry_unavailable",
            },
        ));
    };
    let status = if overflowed {
        LearningCaptureStatus::Degraded {
            stage: "evidence_bounds",
            code: "mutation_limit_exceeded",
        }
    } else {
        LearningCaptureStatus::EvidenceRecorded {
            disposition: LearningEvidenceDisposition::MutationLinked,
            linked_mutations: linked,
        }
    };
    Some(receipt(
        run,
        context.task,
        result,
        &context.evidence,
        status,
    ))
}

fn observe_verification_failure(
    run: &ToolRunContext,
    db: &MemoryDb,
    result: &ToolResult,
    key: CheckKey,
    class: VerificationClass,
    command: &str,
    context: ObservationContext,
) -> LearningCaptureReceipt {
    let pending = PendingFailure {
        class,
        command: retained_command(run, command),
        failure_code: failure_code_label(result),
        evidence: context.evidence.clone(),
        mutations: Vec::new(),
        mutation_evidence_complete: true,
    };
    let (prior, capacity_evicted) =
        if let Ok(mut registry) = registry_guard("observe_verification_failure") {
            let state = state_for_run(&mut registry, run);
            state.observations = state.observations.saturating_add(1);
            let prior = state.learned.get(&key).cloned();
            let capacity_evicted = insert_pending(state, key.clone(), pending.clone());
            (prior, capacity_evicted)
        } else {
            increment_degraded(run);
            return receipt(
                run,
                context.task,
                result,
                &context.evidence,
                LearningCaptureStatus::Degraded {
                    stage: "state",
                    code: "registry_unavailable",
                },
            );
        };

    let Some(prior) = prior else {
        let status = if capacity_evicted {
            LearningCaptureStatus::Degraded {
                stage: "evidence_bounds",
                code: "pending_capacity_eviction",
            }
        } else {
            LearningCaptureStatus::EvidenceRecorded {
                disposition: LearningEvidenceDisposition::FailurePending,
                linked_mutations: 0,
            }
        };
        return receipt(run, context.task, result, &context.evidence, status);
    };
    match store_contradiction(run, db, &prior, &pending, &context) {
        Ok(record) => {
            update_learned(
                run,
                key,
                LearnedCandidate {
                    record: record.clone(),
                    class: prior.class,
                    command: prior.command,
                    applicability: prior.applicability,
                    citations: record.lesson.citations.clone(),
                },
            );
            increment_counter(run, Counter::Contradiction);
            receipt(
                run,
                context.task,
                result,
                &context.evidence,
                LearningCaptureStatus::ContradictionStored {
                    logical_id: record.logical_id.to_string(),
                    version: record.version.get(),
                    record_digest: record.record_digest.to_string(),
                },
            )
        }
        Err(error) => {
            trace_store_error(run, "contradiction", &error);
            increment_degraded(run);
            receipt(
                run,
                context.task,
                result,
                &context.evidence,
                LearningCaptureStatus::Degraded {
                    stage: "contradiction_store",
                    code: "persistence_failed",
                },
            )
        }
    }
}

fn observe_verification_success(
    run: &ToolRunContext,
    db: &MemoryDb,
    result: &ToolResult,
    key: CheckKey,
    context: ObservationContext,
) -> LearningCaptureReceipt {
    let pending = if let Ok(mut registry) = registry_guard("observe_verification_success") {
        let state = state_for_run(&mut registry, run);
        state.observations = state.observations.saturating_add(1);
        let pending = state.pending.remove(&key);
        state.pending_order.retain(|candidate| candidate != &key);
        pending
    } else {
        increment_degraded(run);
        return receipt(
            run,
            context.task,
            result,
            &context.evidence,
            LearningCaptureStatus::Degraded {
                stage: "state",
                code: "registry_unavailable",
            },
        );
    };
    let Some(pending) = pending else {
        return receipt(
            run,
            context.task,
            result,
            &context.evidence,
            LearningCaptureStatus::EvidenceRecorded {
                disposition: LearningEvidenceDisposition::SuccessUnmatched,
                linked_mutations: 0,
            },
        );
    };
    if pending.mutations.is_empty() {
        return receipt(
            run,
            context.task,
            result,
            &context.evidence,
            LearningCaptureStatus::EvidenceRecorded {
                disposition: LearningEvidenceDisposition::SuccessWithoutMutation,
                linked_mutations: 0,
            },
        );
    }
    if !pending.mutation_evidence_complete {
        return receipt(
            run,
            context.task,
            result,
            &context.evidence,
            LearningCaptureStatus::Degraded {
                stage: "evidence_bounds",
                code: "mutation_evidence_incomplete",
            },
        );
    }

    match store_recovery_candidate(run, db, &pending, &context) {
        Ok(record) => {
            let learned = LearnedCandidate {
                record: record.clone(),
                class: pending.class,
                command: pending.command,
                applicability: record.lesson.applicability.clone(),
                citations: record.lesson.citations.clone(),
            };
            update_learned(run, key, learned);
            increment_counter(run, Counter::Candidate);
            receipt(
                run,
                context.task,
                result,
                &context.evidence,
                LearningCaptureStatus::CandidateStored {
                    logical_id: record.logical_id.to_string(),
                    version: record.version.get(),
                    record_digest: record.record_digest.to_string(),
                },
            )
        }
        Err(error) => {
            trace_store_error(run, "candidate", &error);
            increment_degraded(run);
            if let Ok(mut registry) = registry_guard("restore_pending_after_store_failure") {
                insert_pending(state_for_run(&mut registry, run), key, pending);
            }
            receipt(
                run,
                context.task,
                result,
                &context.evidence,
                LearningCaptureStatus::Degraded {
                    stage: "candidate_store",
                    code: "persistence_failed",
                },
            )
        }
    }
}

#[derive(Debug)]
struct ObservationContext {
    workspace_id: String,
    task: LearningTaskBinding,
    evidence: EvidenceRef,
}

struct ContextFailure {
    task: LearningTaskBinding,
    evidence: EvidenceRef,
    stage: &'static str,
    code: &'static str,
}

fn observation_context(
    run: &ToolRunContext,
    db: &MemoryDb,
    task_manager: Option<&TaskManager>,
    result: &ToolResult,
) -> Result<ObservationContext, Box<ContextFailure>> {
    let descriptor = run.runtime().descriptor();
    let fallback_task = LearningTaskBinding::RunTask {
        run_id: run.run_id().to_string(),
        task_generation: 0,
        task_sha256: None,
    };
    let result_digest = MemoryDigest::from_str(&result.evidence_digest())
        .expect("canonical tool evidence digest must be a valid memory digest");
    let fallback_evidence = EvidenceRef {
        call_id_digest: MemoryDigest::sha256(result.tool_call_id().as_bytes()),
        result_digest,
        workspace_generation: descriptor.workspace.generation.get(),
    };
    let Some(workspace_id) = db.workspace_id().map(ToString::to_string) else {
        return Err(Box::new(ContextFailure {
            task: fallback_task,
            evidence: fallback_evidence,
            stage: "workspace_binding",
            code: "memory_store_unbound",
        }));
    };
    let Ok(freshness) = crate::evidence_freshness::current_stamp(run) else {
        return Err(Box::new(ContextFailure {
            task: fallback_task,
            evidence: fallback_evidence,
            stage: "freshness_binding",
            code: "freshness_unavailable",
        }));
    };
    let task = task_binding(run, task_manager, &freshness);
    Ok(ObservationContext {
        workspace_id,
        task,
        evidence: EvidenceRef {
            call_id_digest: fallback_evidence.call_id_digest,
            result_digest: fallback_evidence.result_digest,
            workspace_generation: freshness.workspace_generation,
        },
    })
}

fn task_binding(
    run: &ToolRunContext,
    task_manager: Option<&TaskManager>,
    freshness: &crate::ledger::FreshnessStamp,
) -> LearningTaskBinding {
    if let Some((manager, task)) = task_manager.and_then(|manager| {
        manager
            .current_task_for_actor_lane()
            .map(|task| (manager, task))
    }) {
        debug_assert_eq!(task.status, TaskStatus::InProgress);
        LearningTaskBinding::CanonicalTask {
            graph_id: manager.graph().graph_id().to_string(),
            graph_generation: manager.generation().get(),
            task_id: task.id.clone(),
            task_revision: task.revision,
        }
    } else {
        LearningTaskBinding::RunTask {
            run_id: run.run_id().to_string(),
            task_generation: freshness.task_generation,
            task_sha256: freshness.task_sha256.clone(),
        }
    }
}

fn store_recovery_candidate(
    run: &ToolRunContext,
    db: &MemoryDb,
    pending: &PendingFailure,
    success: &ObservationContext,
) -> anyhow::Result<TechnicalLessonRecord> {
    let draft = recovery_draft(pending, success);
    let source = learning_source(
        b"openclaudia.automatic-learning.recovery.v1",
        &success.task,
        &draft.citations,
        success.evidence.workspace_generation,
    )?;
    db.save_technical_lesson_candidate(
        &draft,
        source,
        run.runtime().descriptor().actor.id.to_string(),
        chrono::Utc::now().timestamp(),
    )
}

fn store_contradiction(
    run: &ToolRunContext,
    db: &MemoryDb,
    prior: &LearnedCandidate,
    failure: &PendingFailure,
    context: &ObservationContext,
) -> anyhow::Result<TechnicalLessonRecord> {
    let mut citations = prior.citations.clone();
    let current_failure = citation(&failure.evidence);
    citations.sort_by(citation_order);
    citations.dedup();
    if citations.len() >= crate::memory::MAX_LESSON_CITATIONS {
        citations.truncate(crate::memory::MAX_LESSON_CITATIONS.saturating_sub(1));
    }
    citations.push(current_failure);
    citations.sort_by(citation_order);
    citations.dedup();
    let now = chrono::Utc::now().timestamp();
    let replacement = TechnicalLessonDraft {
        title: bounded_single_line(
            &format!(
                "Contradicted automatic {} recovery candidate",
                prior.class.label()
            ),
            crate::memory::MAX_LESSON_TITLE_BYTES,
        ),
        kind: prior.class.lesson_kind(),
        observation: bounded_text(
            &format!(
                "The exact verification command `{}` failed again in the same task with typed failure class `{}` after an earlier observed recovery. This contradicts treating the intervening edits as a reusable resolution; inspect the cited result rather than trusting stored output prose.",
                prior.command, failure.failure_code
            ),
            crate::memory::MAX_LESSON_OBSERVATION_BYTES,
        ),
        guidance: "Do not reuse the earlier correlated edits as a fix without a fresh diagnosis and deterministic reproduction. Inspect the cited current failure and correct or delete this candidate after review."
            .to_string(),
        applicability: prior.applicability.clone(),
        citations: citations.clone(),
        confidence: TechnicalLessonConfidence::ObservedOnce,
        sensitivity: TechnicalLessonSensitivity::Internal,
        retention: LessonRetention::ReviewAfter {
            unix_seconds: now.saturating_add(REVIEW_AFTER_SECONDS),
        },
    };
    let source = learning_source(
        b"openclaudia.automatic-learning.contradiction.v1",
        &context.task,
        &citations,
        context.evidence.workspace_generation,
    )?;
    db.correct_technical_lesson(TechnicalLessonCorrectionRequest {
        logical_id: prior.record.logical_id,
        expected_record_digest: prior.record.record_digest.clone(),
        replacement,
        correction_reason:
            "exact task-bound verification failed after the earlier correlated recovery"
                .to_string(),
        source,
        author_id: run.runtime().descriptor().actor.id.to_string(),
        captured_at_unix_seconds: now,
    })
}

fn recovery_draft(pending: &PendingFailure, success: &ObservationContext) -> TechnicalLessonDraft {
    let mut paths = pending
        .mutations
        .iter()
        .map(|mutation| mutation.path.clone())
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    let mut components = paths
        .iter()
        .filter_map(|path| Path::new(path).extension().and_then(|value| value.to_str()))
        .filter(|extension| crate::file_types::is_known_extension(extension))
        .map(|extension| format!("file-type:{}", extension.to_ascii_lowercase()))
        .collect::<Vec<_>>();
    components.sort();
    components.dedup();
    let mut citations = Vec::with_capacity(pending.mutations.len().saturating_add(2));
    citations.push(citation(&pending.evidence));
    citations.extend(
        pending
            .mutations
            .iter()
            .map(|mutation| citation(&mutation.evidence)),
    );
    citations.push(citation(&success.evidence));
    citations.sort_by(citation_order);
    citations.dedup();
    let now = chrono::Utc::now().timestamp();
    TechnicalLessonDraft {
        title: bounded_single_line(
            &format!(
                "Observed {} recovery after task-bound edits",
                pending.class.label()
            ),
            crate::memory::MAX_LESSON_TITLE_BYTES,
        ),
        kind: pending.class.lesson_kind(),
        observation: bounded_text(
            &format!(
                "Within one exact task, verification command `{}` failed with typed failure class `{}` and the exact command later succeeded after successful mutations to {}. This is a correlated recovery observation, not proof that those edits caused the success; arbitrary command-output prose was not retained.",
                pending.command,
                pending.failure_code,
                paths.join(", ")
            ),
            crate::memory::MAX_LESSON_OBSERVATION_BYTES,
        ),
        guidance: "If the same diagnostic recurs in this workspace, inspect the cited tool results and changed paths, then reproduce the behavior before applying a similar fix. Host review or additional deterministic evidence is required before treating this candidate as reliable."
            .to_string(),
        applicability: LessonApplicability {
            paths,
            components,
            tags: vec![
                "causal-candidate".to_string(),
                format!("verification-{}", pending.class.label()),
            ],
            ..LessonApplicability::default()
        },
        citations,
        confidence: TechnicalLessonConfidence::ObservedOnce,
        sensitivity: TechnicalLessonSensitivity::Internal,
        retention: LessonRetention::ReviewAfter {
            unix_seconds: now.saturating_add(REVIEW_AFTER_SECONDS),
        },
    }
}

fn learning_source(
    domain: &[u8],
    task: &LearningTaskBinding,
    citations: &[LessonCitation],
    workspace_generation: u64,
) -> anyhow::Result<MemorySourceEvidence> {
    let task_bytes = serde_json::to_vec(task)?;
    let citation_bytes = serde_json::to_vec(citations)?;
    let generation = workspace_generation.to_be_bytes();
    let digest = MemoryDigest::for_fields(domain, &[&task_bytes, &citation_bytes, &generation]);
    let source_id = format!(
        "automatic-learning:{}",
        digest.as_str().trim_start_matches("sha256:")
    );
    Ok(MemorySourceEvidence::new(
        MemorySourceKind::ToolOutcome,
        source_id,
        format!("s055-v1-workspace-{workspace_generation}"),
        digest,
    ))
}

fn citation(evidence: &EvidenceRef) -> LessonCitation {
    LessonCitation {
        kind: LessonCitationKind::ToolResult,
        locator: format!("tool-call-digest:{}", evidence.call_id_digest),
        source_version: format!("workspace-generation:{}", evidence.workspace_generation),
        digest: evidence.result_digest.clone(),
        line_start: None,
        line_end: None,
    }
}

fn citation_order(left: &LessonCitation, right: &LessonCitation) -> std::cmp::Ordering {
    left.kind
        .cmp(&right.kind)
        .then_with(|| left.locator.cmp(&right.locator))
        .then_with(|| left.source_version.cmp(&right.source_version))
        .then_with(|| left.digest.cmp(&right.digest))
        .then_with(|| left.line_start.cmp(&right.line_start))
        .then_with(|| left.line_end.cmp(&right.line_end))
}

fn mutation_path(run: &ToolRunContext, result: &ToolResult) -> Option<String> {
    let raw = result
        .invocation()
        .arguments
        .as_ref()?
        .get("path")?
        .as_str()?;
    let resolved = crate::tools::resolve_capability_path(run, raw).ok()?;
    let relative = resolved.strip_prefix(run.project_root()).ok()?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return None;
    }
    Some(relative.to_string_lossy().replace('\\', "/"))
}

fn classify_verification_command(command: &str) -> Option<VerificationClass> {
    if command.contains(['\n', '\r', ';', '|', '&', '>', '<', '`'])
        || command.contains("&&")
        || command.contains("$(")
    {
        return None;
    }
    let words = shlex::split(command)?;
    let mut index = 0_usize;
    while words
        .get(index)
        .is_some_and(|word| word.contains('=') && !word.starts_with(['/', '.']))
    {
        index = index.saturating_add(1);
    }
    if words.get(index).is_some_and(|word| word == "env") {
        index = index.saturating_add(1);
        while words
            .get(index)
            .is_some_and(|word| word.contains('=') && !word.starts_with(['/', '.']))
        {
            index = index.saturating_add(1);
        }
    }
    let executable = Path::new(words.get(index)?)
        .file_name()?
        .to_string_lossy()
        .to_ascii_lowercase();
    let mut remainder = &words[index.saturating_add(1)..];
    if executable == "cargo" {
        while remainder.first().is_some_and(|word| word.starts_with('+')) {
            remainder = &remainder[1..];
        }
        return match remainder.first().map(String::as_str) {
            Some("test" | "nextest") => Some(VerificationClass::Test),
            Some("clippy") => Some(VerificationClass::Lint),
            Some("fmt") => Some(VerificationClass::Format),
            Some("check") => Some(VerificationClass::TypeCheck),
            Some("build") => Some(VerificationClass::Build),
            _ => None,
        };
    }
    match executable.as_str() {
        "rustc" | "tsc" | "mypy" => Some(VerificationClass::TypeCheck),
        "pytest" | "py.test" => Some(VerificationClass::Test),
        "ruff" | "eslint" | "golangci-lint" => Some(VerificationClass::Lint),
        "rustfmt" | "prettier" => Some(VerificationClass::Format),
        "go" => match remainder.first().map(String::as_str) {
            Some("test") => Some(VerificationClass::Test),
            Some("vet") => Some(VerificationClass::Lint),
            Some("build") => Some(VerificationClass::Build),
            _ => None,
        },
        "npm" | "pnpm" | "yarn" | "bun" => match remainder.first().map(String::as_str) {
            Some("test") => Some(VerificationClass::Test),
            Some("lint") => Some(VerificationClass::Lint),
            Some("build") => Some(VerificationClass::Build),
            Some("typecheck" | "type-check") => Some(VerificationClass::TypeCheck),
            _ => None,
        },
        "dotnet" => match remainder.first().map(String::as_str) {
            Some("test") => Some(VerificationClass::Test),
            Some("build") => Some(VerificationClass::Build),
            _ => None,
        },
        "mvn" | "mvnw" | "gradle" | "gradlew" => remainder
            .iter()
            .any(|word| matches!(word.as_str(), "test" | "check" | "verify"))
            .then_some(VerificationClass::Test),
        "make" => remainder.iter().find_map(|word| match word.as_str() {
            "test" | "check" => Some(VerificationClass::Test),
            "lint" => Some(VerificationClass::Lint),
            "build" | "all" => Some(VerificationClass::Build),
            _ => None,
        }),
        _ => None,
    }
}

fn retained_command(run: &ToolRunContext, command: &str) -> String {
    let diagnostic = run.sanitize_diagnostic(command);
    let sanitized = redact_sensitive_command_words(diagnostic.as_str());
    bounded_single_line(&sanitized, MAX_RETAINED_COMMAND_BYTES)
}

fn redact_sensitive_command_words(command: &str) -> String {
    let Some(mut words) = shlex::split(command) else {
        return "[unparseable verification command]".to_string();
    };
    let mut redact_next = false;
    for word in &mut words {
        if redact_next {
            *word = "[REDACTED]".to_string();
            redact_next = false;
            continue;
        }
        if let Some((name, _)) = word.split_once('=') {
            if is_sensitive_command_field(name) {
                *word = format!("{name}=[REDACTED]");
            }
            continue;
        }
        if word.starts_with('-') && is_sensitive_command_field(word) {
            redact_next = true;
        }
    }
    shlex::try_join(words.iter().map(String::as_str))
        .unwrap_or_else(|_| "[unrenderable verification command]".to_string())
}

fn is_sensitive_command_field(name: &str) -> bool {
    let normalized = name
        .trim_start_matches('-')
        .to_ascii_uppercase()
        .replace('-', "_");
    crate::tools::is_sensitive_env(&normalized)
        || matches!(
            normalized.as_str(),
            "AUTHORIZATION"
                | "COOKIE"
                | "CREDENTIAL"
                | "PASSWORD"
                | "PASSPHRASE"
                | "PRIVATE_KEY"
                | "SECRET"
                | "TOKEN"
        )
        || normalized.ends_with("_CREDENTIAL")
        || normalized.ends_with("_CREDENTIALS")
}

fn failure_code_label(result: &ToolResult) -> &'static str {
    let code = match result.outcome() {
        ToolOutcome::Error { failure } => Some(failure.code),
        ToolOutcome::Partial { failures, .. } => failures.first().map(|failure| failure.code),
        ToolOutcome::Success { .. } => None,
    };
    match code {
        Some(ToolFailureCode::InvalidArguments) => "invalid_arguments",
        Some(ToolFailureCode::InvalidInput) => "invalid_input",
        Some(ToolFailureCode::PermissionDenied) => "permission_denied",
        Some(ToolFailureCode::PolicyDenied) => "policy_denied",
        Some(ToolFailureCode::Unavailable) => "unavailable",
        Some(ToolFailureCode::Cancelled) => "cancelled",
        Some(ToolFailureCode::DeadlineExceeded) => "deadline_exceeded",
        Some(ToolFailureCode::Conflict) => "conflict",
        Some(ToolFailureCode::External) => "external",
        Some(ToolFailureCode::Internal) => "internal",
        Some(ToolFailureCode::Legacy) => "legacy",
        None => "partial_without_failure",
    }
}

fn bounded_single_line(value: &str, max_bytes: usize) -> String {
    let normalized = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    bounded_text(normalized.trim(), max_bytes)
}

fn bounded_text(value: &str, max_bytes: usize) -> String {
    let value = value.trim();
    if value.len() <= max_bytes {
        return value.to_string();
    }
    crate::tools::safe_truncate(value, max_bytes)
        .trim()
        .to_string()
}

fn receipt(
    run: &ToolRunContext,
    task: LearningTaskBinding,
    result: &ToolResult,
    evidence: &EvidenceRef,
    status: LearningCaptureStatus,
) -> LearningCaptureReceipt {
    LearningCaptureReceipt {
        schema_version: AUTOMATIC_LEARNING_SCHEMA_VERSION,
        run_id: run.run_id().to_string(),
        capability_generation: run.generation().get(),
        workspace_generation: evidence.workspace_generation,
        task,
        tool: result.handler().to_string(),
        call_id_digest: evidence.call_id_digest.to_string(),
        result_digest: evidence.result_digest.to_string(),
        status,
    }
}

fn registry_guard(operation: &'static str) -> Result<MutexGuard<'static, LearningRegistry>, ()> {
    LEARNING.lock().map_err(|error| {
        tracing::error!(
            target: "openclaudia::auto_learn",
            operation,
            error = %error,
            "Automatic-learning registry is unavailable"
        );
    })
}

fn state_for_run<'a>(
    registry: &'a mut LearningRegistry,
    run: &ToolRunContext,
) -> &'a mut RunLearningState {
    let key = RunKey::from_run(run);
    if !registry.runs.contains_key(&key) {
        let mut capacity_evicted = false;
        while registry.runs.len() >= MAX_ACTIVE_RUNS {
            let Some(oldest) = registry.run_order.pop_front() else {
                break;
            };
            capacity_evicted |= registry.runs.remove(&oldest).is_some();
        }
        registry.run_order.push_back(key);
        let mut state = RunLearningState::default();
        if capacity_evicted {
            state.degraded = state.degraded.saturating_add(1);
        }
        registry.runs.insert(key, state);
    }
    registry
        .runs
        .get_mut(&key)
        .expect("automatic-learning run was inserted")
}

fn insert_pending(state: &mut RunLearningState, key: CheckKey, pending: PendingFailure) -> bool {
    let mut capacity_evicted = false;
    if !state.pending.contains_key(&key) {
        while state.pending.len() >= MAX_PENDING_CHECKS_PER_RUN {
            let Some(oldest) = state.pending_order.pop_front() else {
                break;
            };
            capacity_evicted |= state.pending.remove(&oldest).is_some();
        }
        state.pending_order.push_back(key.clone());
    }
    state.pending.insert(key, pending);
    if capacity_evicted {
        state.degraded = state.degraded.saturating_add(1);
    }
    capacity_evicted
}

fn update_learned(run: &ToolRunContext, key: CheckKey, candidate: LearnedCandidate) {
    let Ok(mut registry) = registry_guard("update_learned") else {
        return;
    };
    let state = state_for_run(&mut registry, run);
    if !state.learned.contains_key(&key) {
        let mut capacity_evicted = false;
        while state.learned.len() >= MAX_LEARNED_CHECKS_PER_RUN {
            let Some(oldest) = state.learned_order.pop_front() else {
                break;
            };
            capacity_evicted |= state.learned.remove(&oldest).is_some();
        }
        state.learned_order.push_back(key.clone());
        if capacity_evicted {
            state.degraded = state.degraded.saturating_add(1);
        }
    }
    state.learned.insert(key, candidate);
}

#[derive(Clone, Copy)]
enum Counter {
    Candidate,
    Contradiction,
}

fn increment_counter(run: &ToolRunContext, counter: Counter) {
    let Ok(mut registry) = registry_guard("increment_counter") else {
        return;
    };
    let state = state_for_run(&mut registry, run);
    match counter {
        Counter::Candidate => state.candidates = state.candidates.saturating_add(1),
        Counter::Contradiction => {
            state.contradictions = state.contradictions.saturating_add(1);
        }
    }
}

fn increment_degraded(run: &ToolRunContext) {
    let Ok(mut registry) = registry_guard("increment_degraded") else {
        return;
    };
    let state = state_for_run(&mut registry, run);
    state.degraded = state.degraded.saturating_add(1);
}

fn trace_store_error(run: &ToolRunContext, operation: &'static str, error: &anyhow::Error) {
    tracing::warn!(
        target: "openclaudia::auto_learn",
        event = "automatic_learning_degraded",
        run_id = %run.run_id(),
        operation,
        error = %run.sanitize_diagnostic(&error.to_string()),
        "Automatic learning retained the tool outcome but could not persist its lesson transition"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::{Hash as _, Hasher as _};

    #[test]
    fn verification_classifier_is_narrow_and_rejects_compound_commands() {
        assert_eq!(
            classify_verification_command("CARGO_BUILD_JOBS=4 cargo +1.98.0 test --lib"),
            Some(VerificationClass::Test)
        );
        assert_eq!(
            classify_verification_command("cargo clippy --all-targets"),
            Some(VerificationClass::Lint)
        );
        assert_eq!(classify_verification_command("cargo test && echo ok"), None);
        assert_eq!(classify_verification_command("cargo test &"), None);
        assert_eq!(classify_verification_command("echo cargo test"), None);
        assert_eq!(classify_verification_command("git status"), None);
    }

    #[test]
    fn retained_text_is_bounded_on_utf8_boundaries_and_single_line() {
        let value = "é\n".repeat(600);
        let retained = bounded_single_line(&value, 127);
        assert!(retained.len() <= 127);
        assert!(!retained.contains('\n'));
        assert!(retained.is_char_boundary(retained.len()));
    }

    #[test]
    fn retained_command_redacts_sensitive_assignments_and_option_values() {
        let command = concat!(
            "CARGO_REGISTRY_TOKEN=registry-secret cargo test ",
            "--api-key=inline-secret --password separated-secret --lib"
        );
        let retained = redact_sensitive_command_words(command);
        assert!(!retained.contains("registry-secret"));
        assert!(!retained.contains("inline-secret"));
        assert!(!retained.contains("separated-secret"));
        assert!(retained.contains("CARGO_REGISTRY_TOKEN=[REDACTED]"));
        assert!(retained.contains("--api-key=[REDACTED]"));
        assert!(retained.contains("--password '[REDACTED]'"));
        assert!(retained.contains("--lib"));
    }

    #[test]
    fn task_binding_hash_distinguishes_task_revision_and_run_scope() {
        let first = LearningTaskBinding::CanonicalTask {
            graph_id: "session:test".to_string(),
            graph_generation: 2,
            task_id: "task-1".to_string(),
            task_revision: 1,
        };
        let second = LearningTaskBinding::CanonicalTask {
            graph_id: "session:test".to_string(),
            graph_generation: 2,
            task_id: "task-1".to_string(),
            task_revision: 2,
        };
        let mut first_hash = std::collections::hash_map::DefaultHasher::new();
        first.hash(&mut first_hash);
        let mut second_hash = std::collections::hash_map::DefaultHasher::new();
        second.hash(&mut second_hash);
        assert_ne!(first_hash.finish(), second_hash.finish());
        assert_ne!(
            first,
            LearningTaskBinding::RunTask {
                run_id: "run".to_string(),
                task_generation: 1,
                task_sha256: None,
            }
        );
    }
}
