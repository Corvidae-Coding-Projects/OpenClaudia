//! Run-owned, artifact-bound speculative reads.
//!
//! The only production prediction supported here is the final page of a
//! `read_file` continuation already returned by the harness. The opaque cursor
//! binds the content generation and exact line limit; the coordinator adds the
//! exact path and immutable run generations. Capture uses the descriptor-pinned
//! project filesystem capability but publishes no read observation, approval,
//! tracker entry, attachment, network access, process, secret, or write.
//!
//! A prediction is started before the next provider turn completes. The later
//! tool call still traverses normal policy, hook, and permission admission.
//! Only then may an exact tool/argument/run/generation match join the owned
//! worker, revalidate the live descriptor snapshot, and commit the
//! complete successful receipt. Every other outcome cancels, joins, and drops
//! the disposable snapshot.

use crate::runtime::{
    BudgetAmounts, BudgetGeneration, BudgetReservation, CapabilityGeneration, ContentDigest, RunId,
    StateGeneration, WorkspaceGeneration,
};
use crate::tools::effect::ToolEffect;
use crate::tools::{ToolCall, ToolResult};
use serde_json::{Map, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const SPECULATIVE_TOOL: &str = "read_file";
const MAX_ARGUMENT_BYTES: usize = 4 * 1024;
const MAX_INPUT_BYTES: u64 = 256 * 1024;
const MAX_RESULT_BYTES: u64 = 96 * 1024;
const MAX_MEASUREMENT_SAMPLES: usize = 16;
const MIN_ADMISSION_SAMPLES: usize = 4;
const CONFIDENCE_SCALE: u16 = 10_000;
const PREDICTION_CONFIDENCE: u16 = 9_000;
const MIN_CONFIDENCE: u16 = 8_000;
const OPERATION_DEADLINE: Duration = Duration::from_millis(1_500);
const RESULT_DEADLINE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RunBinding {
    run_id: RunId,
    workspace: WorkspaceGeneration,
    capability: CapabilityGeneration,
    budget: BudgetGeneration,
    state: StateGeneration,
    provider: ContentDigest,
    host_safety_policy: u32,
    runtime_mode: u64,
}

impl RunBinding {
    fn from_run(run: &crate::tools::ToolRunContext) -> Self {
        let descriptor = run.runtime().descriptor();
        Self {
            run_id: descriptor.run_id,
            workspace: descriptor.workspace.generation,
            capability: descriptor.capabilities.generation,
            budget: descriptor.budget.generation,
            state: descriptor.initial_state.generation,
            provider: ContentDigest::sha256(run.provider_id().as_bytes()),
            host_safety_policy: crate::tools::HOST_SAFETY_POLICY_GENERATION,
            runtime_mode: run.runtime_mode().generation,
        }
    }

    fn matches(self, run: &crate::tools::ToolRunContext) -> bool {
        self == Self::from_run(run)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadPrediction {
    id: u64,
    binding: RunBinding,
    arguments: Value,
    input_generation: ContentDigest,
    confidence: u16,
}

impl ReadPrediction {
    fn matches(&self, run: &crate::tools::ToolRunContext, tool_call: &ToolCall) -> bool {
        self.binding.matches(run)
            && tool_call.function.name == SPECULATIVE_TOOL
            && tool_call.function.arguments.len() <= MAX_ARGUMENT_BYTES
            && serde_json::from_str::<Value>(&tool_call.function.arguments)
                .is_ok_and(|arguments| arguments == self.arguments)
    }

    fn argument_map(&self) -> Option<HashMap<String, Value>> {
        self.arguments
            .as_object()
            .map(|arguments| arguments.clone().into_iter().collect())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// A bounded trial is still gathering comparisons against demand reads.
    Evaluating,
    /// Every deterministic admission threshold has been met.
    Enabled,
    /// Speculation did not beat the demand baseline and is disabled for the run.
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EvaluationSample {
    correct: bool,
    hit: bool,
    wasted: bool,
    baseline_latency_micros: u64,
    speculative_latency_micros: u64,
    baseline_cost_units: u64,
    speculative_cost_units: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpeculationMetrics {
    pub(crate) samples: usize,
    pub(crate) correct: usize,
    pub(crate) hits: usize,
    pub(crate) wasted: usize,
    pub(crate) baseline_latency_micros: u64,
    pub(crate) speculative_latency_micros: u64,
    pub(crate) baseline_cost_units: u64,
    pub(crate) speculative_cost_units: u64,
}

#[derive(Debug, Default)]
struct EvaluationWindow {
    samples: VecDeque<EvaluationSample>,
}

impl EvaluationWindow {
    fn record(&mut self, sample: EvaluationSample) {
        if self.samples.len() == MAX_MEASUREMENT_SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    fn metrics(&self) -> SpeculationMetrics {
        self.samples
            .iter()
            .fold(SpeculationMetrics::default(), |mut metrics, sample| {
                metrics.samples = metrics.samples.saturating_add(1);
                metrics.correct = metrics.correct.saturating_add(usize::from(sample.correct));
                metrics.hits = metrics.hits.saturating_add(usize::from(sample.hit));
                metrics.wasted = metrics.wasted.saturating_add(usize::from(sample.wasted));
                metrics.baseline_latency_micros = metrics
                    .baseline_latency_micros
                    .saturating_add(sample.baseline_latency_micros);
                metrics.speculative_latency_micros = metrics
                    .speculative_latency_micros
                    .saturating_add(sample.speculative_latency_micros);
                metrics.baseline_cost_units = metrics
                    .baseline_cost_units
                    .saturating_add(sample.baseline_cost_units);
                metrics.speculative_cost_units = metrics
                    .speculative_cost_units
                    .saturating_add(sample.speculative_cost_units);
                metrics
            })
    }

    fn decision(&self) -> AdmissionDecision {
        let metrics = self.metrics();
        if metrics.samples < MIN_ADMISSION_SAMPLES {
            return AdmissionDecision::Evaluating;
        }
        let all_correct = metrics.correct == metrics.samples;
        let hit_threshold = metrics.hits.saturating_mul(usize::from(CONFIDENCE_SCALE))
            >= metrics
                .samples
                .saturating_mul(usize::from(PREDICTION_CONFIDENCE));
        let waste_threshold =
            metrics.wasted.saturating_mul(100) <= metrics.samples.saturating_mul(25);
        let latency_better = metrics.speculative_latency_micros < metrics.baseline_latency_micros;
        let cost_not_worse = metrics.speculative_cost_units <= metrics.baseline_cost_units;
        if all_correct && hit_threshold && waste_threshold && latency_better && cost_not_worse {
            AdmissionDecision::Enabled
        } else {
            AdmissionDecision::Disabled
        }
    }
}

/// Exact run-owned coordinator for one bounded speculative-read experiment.
///
/// The coordinator is carried through immediate TUI follow-up turns alongside
/// the same `ToolRunContext`. A workspace transition creates a new coordinator;
/// no worker or prediction crosses that generation boundary.
pub struct SpeculationCoordinator {
    binding: RunBinding,
    next_prediction_id: AtomicU64,
    pending: Mutex<Option<ReadPrediction>>,
    measurements: Arc<Mutex<EvaluationWindow>>,
    in_flight: Arc<AtomicBool>,
}

impl std::fmt::Debug for SpeculationCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SpeculationCoordinator")
            .field("binding", &self.binding)
            .field("decision", &self.admission_decision())
            .field("metrics", &self.metrics())
            .field("in_flight", &self.in_flight.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl SpeculationCoordinator {
    #[must_use]
    pub(crate) fn for_run(run: &crate::tools::ToolRunContext) -> Self {
        Self {
            binding: RunBinding::from_run(run),
            next_prediction_id: AtomicU64::new(1),
            pending: Mutex::new(None),
            measurements: Arc::new(Mutex::new(EvaluationWindow::default())),
            in_flight: Arc::new(AtomicBool::new(false)),
        }
    }

    #[must_use]
    pub(crate) fn is_bound_to(&self, run: &crate::tools::ToolRunContext) -> bool {
        self.binding.matches(run)
    }

    /// Retain one next-page prediction from a trusted typed `read_file`
    /// result. Only partial results with an opaque continuation and immutable
    /// artifact generation can seed work; errors, complete reads, and every
    /// other tool clear the pending candidate.
    pub(crate) fn observe_result(&self, tool_call: &ToolCall, result: &ToolResult) {
        let prediction_id = self.next_prediction_id.fetch_add(1, Ordering::Relaxed);
        let prediction = prediction_from_result(self.binding, prediction_id, tool_call, result);
        let mut pending = lock_or_recover(&self.pending);
        if pending.as_ref().is_some_and(|current| {
            prediction.as_ref().is_some_and(|next| {
                current.arguments == next.arguments
                    && current.input_generation == next.input_generation
            })
        }) {
            return;
        }
        *pending = prediction;
    }

    /// Start the retained prediction before provider completion. The caller
    /// owns the returned handle and must either consume it after normal tool
    /// admission or discard it; `Drop` is a cancellation-and-join backstop.
    #[must_use]
    #[allow(clippy::too_many_lines)] // Admission, reservation, and worker ownership are one transaction.
    pub(crate) fn start(
        &self,
        run: &Arc<crate::tools::ToolRunContext>,
    ) -> Option<SpeculationHandle> {
        if !self.is_bound_to(run)
            || run.runtime().cancellation().is_cancelled()
            || self.admission_decision() == AdmissionDecision::Disabled
            || self
                .in_flight
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return None;
        }
        let prediction = lock_or_recover(&self.pending).take();
        let Some(prediction) = prediction else {
            self.in_flight.store(false, Ordering::Release);
            return None;
        };
        if prediction.confidence < MIN_CONFIDENCE
            || prediction.confidence > CONFIDENCE_SCALE
            || serde_json::to_vec(&prediction.arguments)
                .map_or(true, |bytes| bytes.len() > MAX_ARGUMENT_BYTES)
        {
            self.in_flight.store(false, Ordering::Release);
            return None;
        }
        let Ok(effect) = crate::tools::host_safety::HostSafetyPolicy::enforce(
            SPECULATIVE_TOOL,
            &prediction.arguments,
        ) else {
            self.in_flight.store(false, Ordering::Release);
            return None;
        };
        if effect.effect != ToolEffect::ReadOnly {
            self.in_flight.store(false, Ordering::Release);
            return None;
        }
        if run
            .admit_runtime_mode_resolved(SPECULATIVE_TOOL, &effect, &prediction.arguments)
            .is_err()
            || run
                .tool_catalog()
                .admit_tool_call(run, SPECULATIVE_TOOL)
                .is_err()
        {
            self.in_flight.store(false, Ordering::Release);
            return None;
        }
        let Some(arguments) = prediction.argument_map() else {
            self.in_flight.store(false, Ordering::Release);
            return None;
        };
        let budget_reservation = match run.budget().reserve(BudgetAmounts {
            concurrent_calls: 1,
            ..BudgetAmounts::default()
        }) {
            Ok(reservation) => reservation,
            Err(error) => {
                self.in_flight.store(false, Ordering::Release);
                tracing::debug!(%error, "run budget denied speculative read");
                return None;
            }
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let started = Instant::now();
        let deadline = started + RESULT_DEADLINE;
        let worker_deadline = started + OPERATION_DEADLINE;
        let worker_run = Arc::clone(run);
        let worker = match std::thread::Builder::new()
            .name(format!("speculative-read-{}", prediction.id))
            .spawn(move || {
                if worker_run.runtime().cancellation().is_cancelled() {
                    return Err("owning run was cancelled before speculative capture".to_string());
                }
                let artifact = crate::tools::file::capture_speculative_read(
                    &worker_run,
                    &arguments,
                    &worker_cancelled,
                    worker_deadline,
                )?;
                if artifact.input_bytes() > MAX_INPUT_BYTES
                    || artifact.output_bytes() > MAX_RESULT_BYTES
                {
                    return Err("speculative read exceeded its reserved byte budget".to_string());
                }
                Ok(artifact)
            }) {
            Ok(worker) => worker,
            Err(error) => {
                self.in_flight.store(false, Ordering::Release);
                tracing::debug!(%error, "could not start bounded speculative read worker");
                return None;
            }
        };
        Some(SpeculationHandle {
            prediction,
            started,
            deadline,
            cancelled,
            worker: Some(worker),
            budget_reservation: Some(budget_reservation),
            measurements: Arc::clone(&self.measurements),
            in_flight: Arc::clone(&self.in_flight),
        })
    }

    #[must_use]
    pub(crate) fn admission_decision(&self) -> AdmissionDecision {
        lock_or_recover(&self.measurements).decision()
    }

    #[must_use]
    pub(crate) fn metrics(&self) -> SpeculationMetrics {
        lock_or_recover(&self.measurements).metrics()
    }
}

/// Owned result handle for one bounded prediction. It is intentionally not
/// cloneable: exactly one caller decides reuse or discard and observes the
/// worker's terminal result.
pub struct SpeculationHandle {
    prediction: ReadPrediction,
    started: Instant,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<crate::tools::file::SpeculativeReadArtifact, String>>>,
    budget_reservation: Option<BudgetReservation>,
    measurements: Arc<Mutex<EvaluationWindow>>,
    in_flight: Arc<AtomicBool>,
}

impl std::fmt::Debug for SpeculationHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SpeculationHandle")
            .field("prediction_id", &self.prediction.id)
            .field("binding", &self.prediction.binding)
            .field("input_generation", &self.prediction.input_generation)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl SpeculationHandle {
    #[must_use]
    pub(crate) fn matches(&self, run: &crate::tools::ToolRunContext, tool_call: &ToolCall) -> bool {
        self.prediction.matches(run, tool_call)
    }

    /// Join, validate, and commit a matching prediction after the actual tool
    /// call has passed ordinary admission. `None` directs the caller to the
    /// demand path.
    pub(crate) fn consume(
        mut self,
        run: &crate::tools::ToolRunContext,
        tool_call: &ToolCall,
    ) -> Option<crate::tools::file::SpeculativeReadArtifact> {
        if !self.matches(run, tool_call) {
            self.discard_inner("actual tool call did not exactly match prediction");
            return None;
        }
        let consume_started = Instant::now();
        let joined = self.join_worker();
        let speculative_latency = micros(consume_started.elapsed());
        let mut sample = EvaluationSample {
            correct: true,
            hit: false,
            wasted: true,
            baseline_latency_micros: 0,
            speculative_latency_micros: speculative_latency,
            baseline_cost_units: 0,
            speculative_cost_units: 0,
        };
        let artifact = match joined {
            Ok(artifact)
                if Instant::now() < self.deadline
                    && artifact.generation() == self.prediction.input_generation =>
            {
                artifact
            }
            Ok(artifact) => {
                sample.correct = artifact.generation() == self.prediction.input_generation;
                sample.speculative_cost_units = artifact.input_bytes().saturating_mul(2);
                self.record(sample);
                return None;
            }
            Err(error) => {
                tracing::debug!(prediction_id = self.prediction.id, %error, "speculative read discarded");
                self.record(sample);
                return None;
            }
        };
        sample.speculative_cost_units = artifact.input_bytes().saturating_mul(2);
        sample.baseline_latency_micros = artifact.capture_latency_micros();
        sample.baseline_cost_units = artifact.input_bytes().saturating_mul(2);
        match crate::tools::file::validate_speculative_read(
            run,
            &artifact,
            &self.cancelled,
            self.deadline,
        ) {
            Ok(()) => {
                sample.correct = true;
                sample.hit = true;
                sample.wasted = false;
                sample.speculative_latency_micros = micros(consume_started.elapsed());
                self.record(sample);
                Some(artifact)
            }
            Err(error) => {
                sample.correct = false;
                sample.speculative_latency_micros = micros(consume_started.elapsed());
                tracing::debug!(prediction_id = self.prediction.id, %error, "speculative read failed live-generation validation");
                self.record(sample);
                None
            }
        }
    }

    /// Cancel and synchronously join an unused prediction. The worker is
    /// bounded to one small local project read, so this cannot leave a detached
    /// task behind the owning run.
    pub(crate) fn discard(mut self, reason: &'static str) {
        self.discard_inner(reason);
    }

    fn discard_inner(&mut self, reason: &'static str) {
        self.cancelled.store(true, Ordering::Release);
        let cost = self
            .join_worker()
            .ok()
            .map_or(0, |artifact| artifact.input_bytes().saturating_mul(2));
        tracing::debug!(
            prediction_id = self.prediction.id,
            reason,
            "speculative read cancelled and joined"
        );
        self.record(EvaluationSample {
            correct: true,
            hit: false,
            wasted: true,
            baseline_latency_micros: 0,
            speculative_latency_micros: micros(self.started.elapsed()),
            baseline_cost_units: 0,
            speculative_cost_units: cost,
        });
    }

    fn join_worker(&mut self) -> Result<crate::tools::file::SpeculativeReadArtifact, String> {
        let worker = self
            .worker
            .take()
            .ok_or_else(|| "speculative read worker was already observed".to_string())?;
        let result = worker
            .join()
            .map_err(|_| "speculative read worker panicked".to_string())?;
        if let Some(reservation) = self.budget_reservation.take() {
            reservation
                .commit()
                .map_err(|error| format!("speculative read budget settlement failed: {error}"))?;
        }
        result
    }

    fn record(&self, sample: EvaluationSample) {
        let mut measurements = lock_or_recover(&self.measurements);
        measurements.record(sample);
        let metrics = measurements.metrics();
        let decision = measurements.decision();
        drop(measurements);
        tracing::debug!(
            prediction_id = self.prediction.id,
            samples = metrics.samples,
            correct = metrics.correct,
            hits = metrics.hits,
            wasted = metrics.wasted,
            baseline_latency_micros = metrics.baseline_latency_micros,
            speculative_latency_micros = metrics.speculative_latency_micros,
            baseline_cost_units = metrics.baseline_cost_units,
            speculative_cost_units = metrics.speculative_cost_units,
            admission = ?decision,
            "recorded bounded speculation comparison"
        );
    }
}

impl Drop for SpeculationHandle {
    fn drop(&mut self) {
        if self.worker.is_some() {
            self.discard_inner("owned speculation handle dropped before reuse");
        }
        self.in_flight.store(false, Ordering::Release);
    }
}

fn prediction_from_result(
    binding: RunBinding,
    id: u64,
    tool_call: &ToolCall,
    result: &ToolResult,
) -> Option<ReadPrediction> {
    if tool_call.function.name != SPECULATIVE_TOOL
        || result.handler() != SPECULATIVE_TOOL
        || result.is_error()
        || !result.is_partial()
    {
        return None;
    }
    let arguments = serde_json::from_str::<Value>(&tool_call.function.arguments)
        .ok()?
        .as_object()?
        .clone();
    let path = arguments.get("path")?.as_str()?.to_string();
    let structured = result.structured()?;
    if structured.get("kind").and_then(Value::as_str) != Some("text")
        || structured.get("sensitivity").and_then(Value::as_str) != Some("workspace")
    {
        return None;
    }
    let cursor = structured
        .get("continuation")?
        .get("cursor")?
        .as_str()?
        .to_string();
    let input_generation = structured
        .get("artifact")?
        .get("generation")?
        .as_str()?
        .parse()
        .ok()?;
    let mut next = Map::new();
    next.insert("path".to_string(), Value::String(path));
    next.insert("cursor".to_string(), Value::String(cursor));
    if let Some(limit) = arguments.get("limit") {
        if limit.as_u64().is_none_or(|limit| limit == 0) {
            return None;
        }
        next.insert("limit".to_string(), limit.clone());
    }
    let arguments = Value::Object(next);
    if serde_json::to_vec(&arguments).is_ok_and(|encoded| encoded.len() <= MAX_ARGUMENT_BYTES) {
        Some(ReadPrediction {
            id,
            binding,
            arguments,
            input_generation,
            confidence: PREDICTION_CONFIDENCE,
        })
    } else {
        None
    }
}

fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| {
        tracing::error!("speculation state lock poisoned; recovering inner state");
        error.into_inner()
    })
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{
        FunctionCall, ToolFailure, ToolFailureCode, ToolHandlerResult, ToolRetryability,
    };
    use serde_json::json;

    fn binding() -> RunBinding {
        RunBinding {
            run_id: RunId::new(),
            workspace: WorkspaceGeneration::new(1).expect("workspace generation"),
            capability: CapabilityGeneration::new(2).expect("capability generation"),
            budget: BudgetGeneration::new(3).expect("budget generation"),
            state: StateGeneration::new(4).expect("state generation"),
            provider: ContentDigest::sha256(b"test-provider"),
            host_safety_policy: crate::tools::HOST_SAFETY_POLICY_GENERATION,
            runtime_mode: 1,
        }
    }

    fn call(arguments: &Value) -> ToolCall {
        ToolCall {
            id: "call-1".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: SPECULATIVE_TOOL.to_string(),
                arguments: serde_json::to_string(&arguments).expect("arguments encode"),
            },
        }
    }

    fn partial_read_result(call: &ToolCall) -> ToolResult {
        ToolResult::bind(
            call,
            SPECULATIVE_TOOL,
            ToolHandlerResult::partial_truncated_structured(
                "page",
                json!({
                    "kind": "text",
                    "sensitivity": "workspace",
                    "artifact": {
                        "generation": ContentDigest::sha256(b"artifact"),
                        "byte_len": 100,
                    },
                    "continuation": {"cursor": "opaque-cursor"},
                    "partial": true,
                    "eof": false,
                }),
                50,
                Some(json!({"cursor": "opaque-cursor"})),
            ),
        )
    }

    #[test]
    fn trusted_partial_read_predicts_exact_cursor_call() {
        let call = call(&json!({"path": "src/lib.rs", "limit": 20}));
        let result = partial_read_result(&call);
        let prediction = prediction_from_result(binding(), 7, &call, &result)
            .expect("trusted continuation predicts final page");

        assert_eq!(prediction.id, 7);
        assert_eq!(prediction.arguments["path"], "src/lib.rs");
        assert_eq!(prediction.arguments["cursor"], "opaque-cursor");
        assert_eq!(prediction.arguments["limit"], 20);
        assert_eq!(
            prediction.input_generation,
            ContentDigest::sha256(b"artifact")
        );
    }

    #[test]
    fn complete_error_and_non_read_results_cannot_seed_predictions() {
        let read = call(&json!({"path": "src/lib.rs"}));
        let complete = ToolResult::bind(
            &read,
            SPECULATIVE_TOOL,
            ToolHandlerResult::success_text("complete"),
        );
        assert!(prediction_from_result(binding(), 1, &read, &complete).is_none());

        let error = ToolResult::bind(
            &read,
            SPECULATIVE_TOOL,
            ToolHandlerResult::error(ToolFailure::new(
                ToolFailureCode::External,
                "failed".to_string(),
                ToolRetryability::Safe,
            )),
        );
        assert!(prediction_from_result(binding(), 2, &read, &error).is_none());

        let mut other = read;
        other.function.name = "grep".to_string();
        let result = partial_read_result(&other);
        assert!(prediction_from_result(binding(), 3, &other, &result).is_none());
    }

    #[test]
    fn exact_arguments_do_not_accept_a_near_match() {
        let read = call(&json!({"path": "src/lib.rs"}));
        let result = partial_read_result(&read);
        let prediction = prediction_from_result(binding(), 1, &read, &result).expect("prediction");
        assert_eq!(
            prediction.arguments,
            json!({"path": "src/lib.rs", "cursor": "opaque-cursor"})
        );
        assert_ne!(
            prediction.arguments,
            json!({"path": "src/lib.rs", "cursor": "other-cursor"})
        );
    }

    #[test]
    fn exact_cursor_receipt_commits_and_enables_when_it_moves_latency_off_path() {
        let workspace = tempfile::tempdir().expect("speculation workspace");
        std::fs::write(workspace.path().join("source.txt"), "one\ntwo\n")
            .expect("write source fixture");
        let run = crate::tools::security::test_run_context_for(workspace.path());
        let first_call = call(&json!({"path": "source.txt", "limit": 1}));
        let first_args = HashMap::from([
            ("path".to_string(), json!("source.txt")),
            ("limit".to_string(), json!(1)),
        ]);
        let first_result = ToolResult::bind(
            &first_call,
            SPECULATIVE_TOOL,
            crate::tools::file::execute_read_file_typed(&run, &first_args),
        );
        assert!(first_result.is_partial());
        let cursor = first_result.structured().expect("typed first page")["continuation"]["cursor"]
            .as_str()
            .expect("continuation cursor")
            .to_string();
        let continuation = call(&json!({
            "path": "source.txt",
            "cursor": cursor,
            "limit": 1,
        }));
        let coordinator = SpeculationCoordinator::for_run(&run);
        let permissions = crate::permissions::PermissionManager::unrestricted_for_run(&run);

        for _ in 0..MIN_ADMISSION_SAMPLES {
            coordinator.observe_result(&first_call, &first_result);
            let handle = coordinator
                .start(&run)
                .expect("evaluation prediction starts");
            assert!(handle.matches(&run, &continuation));
            let committed = crate::services::tool_executor::ToolExecutor::execute_precomputed_read(
                crate::services::tool_executor::PrecomputedReadRequest {
                    run_context: &run,
                    tool_call: &continuation,
                    handle,
                    memory_db: None,
                    app_config: None,
                    permission_mgr: &permissions,
                    authorization: None,
                    session_id: Some(run.session_id()),
                    policy_enforcer: None,
                },
            );
            assert!(!committed.is_partial());
            assert_eq!(
                committed.structured().expect("typed final page")["eof"],
                true
            );
        }

        let metrics = coordinator.metrics();
        assert_eq!(metrics.samples, MIN_ADMISSION_SAMPLES);
        assert_eq!(metrics.correct, MIN_ADMISSION_SAMPLES);
        assert_eq!(metrics.hits, MIN_ADMISSION_SAMPLES);
        assert_eq!(metrics.wasted, 0);
        assert_eq!(metrics.speculative_cost_units, metrics.baseline_cost_units);
        assert!(metrics.speculative_latency_micros < metrics.baseline_latency_micros);
        assert_eq!(coordinator.admission_decision(), AdmissionDecision::Enabled);
        crate::tools::retire_run(&run);
    }

    #[test]
    fn changed_artifact_is_rejected_without_a_second_full_read() {
        let workspace = tempfile::tempdir().expect("speculation workspace");
        let path = workspace.path().join("source.txt");
        std::fs::write(&path, "one\ntwo\n").expect("write source fixture");
        let run = crate::tools::security::test_run_context_for(workspace.path());
        let first_call = call(&json!({"path": "source.txt", "limit": 1}));
        let first_args = HashMap::from([
            ("path".to_string(), json!("source.txt")),
            ("limit".to_string(), json!(1)),
        ]);
        let first_result = ToolResult::bind(
            &first_call,
            SPECULATIVE_TOOL,
            crate::tools::file::execute_read_file_typed(&run, &first_args),
        );
        let cursor = first_result.structured().expect("typed first page")["continuation"]["cursor"]
            .as_str()
            .expect("continuation cursor")
            .to_string();
        let continuation_args = HashMap::from([
            ("path".to_string(), json!("source.txt")),
            ("cursor".to_string(), json!(cursor)),
            ("limit".to_string(), json!(1)),
        ]);
        let cancelled = AtomicBool::new(false);
        let artifact = crate::tools::file::capture_speculative_read(
            &run,
            &continuation_args,
            &cancelled,
            Instant::now() + Duration::from_secs(1),
        )
        .expect("capture speculative continuation");

        std::fs::write(&path, "one\ntwo changed\n").expect("mutate source fixture");
        let error = crate::tools::file::validate_speculative_read(
            &run,
            &artifact,
            &cancelled,
            Instant::now() + Duration::from_secs(1),
        )
        .expect_err("changed artifact must invalidate speculation");
        assert!(error.contains("no longer matches"));
        crate::tools::retire_run(&run);
    }

    #[test]
    fn admission_requires_correct_hits_with_lower_latency_and_cost() {
        let mut window = EvaluationWindow::default();
        for _ in 0..MIN_ADMISSION_SAMPLES {
            window.record(EvaluationSample {
                correct: true,
                hit: true,
                wasted: false,
                baseline_latency_micros: 100,
                speculative_latency_micros: 20,
                baseline_cost_units: 100,
                speculative_cost_units: 40,
            });
        }
        assert_eq!(window.decision(), AdmissionDecision::Enabled);
    }

    #[test]
    fn admission_disables_on_wrong_result_waste_or_non_improvement() {
        let failing_samples = [
            EvaluationSample {
                correct: false,
                hit: true,
                wasted: false,
                baseline_latency_micros: 100,
                speculative_latency_micros: 20,
                baseline_cost_units: 100,
                speculative_cost_units: 40,
            },
            EvaluationSample {
                correct: true,
                hit: false,
                wasted: true,
                baseline_latency_micros: 100,
                speculative_latency_micros: 20,
                baseline_cost_units: 100,
                speculative_cost_units: 40,
            },
            EvaluationSample {
                correct: true,
                hit: true,
                wasted: false,
                baseline_latency_micros: 100,
                speculative_latency_micros: 100,
                baseline_cost_units: 100,
                speculative_cost_units: 100,
            },
        ];
        for failing in failing_samples {
            let mut window = EvaluationWindow::default();
            for _ in 0..MIN_ADMISSION_SAMPLES {
                window.record(failing);
            }
            assert_eq!(window.decision(), AdmissionDecision::Disabled);
        }
    }

    #[test]
    fn measurement_window_stays_bounded() {
        let mut window = EvaluationWindow::default();
        for _ in 0..(MAX_MEASUREMENT_SAMPLES + 5) {
            window.record(EvaluationSample {
                correct: true,
                hit: true,
                wasted: false,
                baseline_latency_micros: 2,
                speculative_latency_micros: 1,
                baseline_cost_units: 2,
                speculative_cost_units: 1,
            });
        }
        assert_eq!(window.metrics().samples, MAX_MEASUREMENT_SAMPLES);
    }
}
