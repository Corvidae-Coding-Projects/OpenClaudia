//! Typed capability maturity, executable evidence, and generated documentation.
//!
//! The checked-in JSON artifacts are data to validate, never authority by
//! themselves. [`CapabilityEvidenceBundle::bundled`] parses them with strict
//! schemas, binds the evaluation corpus to an independent review digest, and
//! refuses to expose an operational capability unless executable multi-trial
//! receipts cover every reachable entrypoint, declared failure mode, and
//! required effect.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read as _};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::runtime::ContentDigest;

const REGISTRY_SCHEMA_VERSION: u16 = 1;
const CORPUS_SCHEMA_VERSION: u16 = 1;
const REVIEW_SCHEMA_VERSION: u16 = 1;
const TRACE_SCHEMA_VERSION: u16 = 1;
const MIN_EVALUATION_TRIALS: u8 = 3;
const MAX_EVALUATION_TRIALS: u8 = 16;
const MAX_REGISTRY_ARTIFACT_BYTES: usize = 524_288;
const MAX_CORPUS_ARTIFACT_BYTES: usize = 262_144;
const MAX_REVIEW_ARTIFACT_BYTES: usize = 65_536;
const MAX_CAPABILITIES: usize = 128;
const MAX_EVIDENCE_RECORDS: usize = 512;
const MAX_ENTRYPOINTS_PER_CAPABILITY: usize = 64;
const MAX_EFFECTS_PER_CAPABILITY: usize = 64;
const MAX_LINKS_PER_RECORD: usize = 128;
const MAX_FAILURE_MODES_PER_ENTRYPOINT: usize = 16;
const MAX_SCENARIOS: usize = 128;
const MAX_EFFECT_OBSERVATIONS: usize = 64;
const MAX_REVIEW_LIMITATIONS: usize = 32;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_INVOCATION_BYTES: usize = 1_024;
const MAX_TEST_FIELD_BYTES: usize = 256;
const MAX_GRADER_PATHS: usize = 32;
const MAX_GRADED_FILE_BYTES: u64 = 1_048_576;

const BUNDLED_REGISTRY: &str = include_str!("../capabilities/registry.json");
const BUNDLED_CORPUS: &str = include_str!("../capabilities/evaluation-corpus.json");
const BUNDLED_REVIEW: &str = include_str!("../capabilities/evaluation-corpus-review.json");

/// Capability release maturity.
///
/// These states deliberately distinguish unavailable and experiment-only
/// surfaces from partial implementations. Only `Operational` is a release
/// claim and therefore activates executable-evidence validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityMaturity {
    Unsupported,
    Experimental,
    SchemaOnly,
    Unreachable,
    Partial,
    Operational,
}

impl CapabilityMaturity {
    /// Stable label used by generated documentation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::Experimental => "experimental",
            Self::SchemaOnly => "schema-only",
            Self::Unreachable => "unreachable",
            Self::Partial => "partial",
            Self::Operational => "operational",
        }
    }
}

/// Kind of public or internal entrypoint that reaches a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntrypointKind {
    DefaultTui,
    LegacyRepl,
    Print,
    Init,
    Auth,
    Proxy,
    Acp,
    Loop,
    Config,
    Doctor,
    Hooks,
    TeamCli,
    AgentTool,
    LibraryApi,
}

impl EntrypointKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DefaultTui => "default_tui",
            Self::LegacyRepl => "legacy_repl",
            Self::Print => "print",
            Self::Init => "init",
            Self::Auth => "auth",
            Self::Proxy => "proxy",
            Self::Acp => "acp",
            Self::Loop => "loop",
            Self::Config => "config",
            Self::Doctor => "doctor",
            Self::Hooks => "hooks",
            Self::TeamCli => "team_cli",
            Self::AgentTool => "agent_tool",
            Self::LibraryApi => "library_api",
        }
    }
}

/// Audited reachability of an entrypoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntrypointReachability {
    Reachable,
    Unreachable,
    TestOnly,
    Unverified,
}

impl EntrypointReachability {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::Unreachable => "unreachable",
            Self::TestOnly => "test-only",
            Self::Unverified => "unverified",
        }
    }
}

/// Failure modes an operational entrypoint must exercise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    InvalidInput,
    ProviderFailure,
    Timeout,
    Cancellation,
    PartialState,
    DocumentationOnlyClaim,
    MissingFailureEvidence,
}

/// Host or environment effect required by a capability contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredEffectKind {
    FilesystemRead,
    FilesystemWrite,
    ProcessExecution,
    NetworkRequest,
    CredentialRead,
    SessionMutation,
    ExternalMutation,
    DocumentationProjection,
    FinalEnvironmentObservation,
    TraceEmission,
}

impl RequiredEffectKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::FilesystemRead => "filesystem read",
            Self::FilesystemWrite => "filesystem write",
            Self::ProcessExecution => "process execution",
            Self::NetworkRequest => "network request",
            Self::CredentialRead => "credential read",
            Self::SessionMutation => "session mutation",
            Self::ExternalMutation => "external mutation",
            Self::DocumentationProjection => "documentation projection",
            Self::FinalEnvironmentObservation => "final-environment observation",
            Self::TraceEmission => "trace emission",
        }
    }
}

/// Whether an effect must occur or must remain absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectExpectation {
    MustOccur,
    MustNotOccur,
    MayOccur,
}

/// State established by an executable grader for one declared effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectObservationState {
    Occurred,
    DidNotOccur,
}

/// Runtime fact from which an effect observation is derived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "proof", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectObservationProof {
    FinalFile { path: String },
    ForbiddenPathAbsent { path: String },
    TraceEvent { kind: EvaluationTraceEventKind },
    GraderExecution,
}

/// Typed effect observation checked against final state or the causal trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectObservationRecord {
    effect_id: String,
    kind: RequiredEffectKind,
    state: EffectObservationState,
    proof: EffectObservationProof,
}

impl EffectObservationRecord {
    /// Required-effect identifier established by this observation.
    #[must_use]
    pub fn effect_id(&self) -> &str {
        &self.effect_id
    }

    /// Typed effect classification established by the grader.
    #[must_use]
    pub const fn kind(&self) -> RequiredEffectKind {
        self.kind
    }

    /// Whether the effect occurred or remained absent.
    #[must_use]
    pub const fn state(&self) -> EffectObservationState {
        self.state
    }
}

/// One required effect in a capability contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredEffectRecord {
    id: String,
    kind: RequiredEffectKind,
    expectation: EffectExpectation,
    description: String,
}

impl RequiredEffectRecord {
    /// Stable record identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Typed effect classification.
    #[must_use]
    pub const fn kind(&self) -> RequiredEffectKind {
        self.kind
    }

    /// Required presence or absence of the effect.
    #[must_use]
    pub const fn expectation(&self) -> EffectExpectation {
        self.expectation
    }

    /// Human explanation; never executable evidence.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
}

/// One concrete route into a capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntrypointRecord {
    id: String,
    kind: EntrypointKind,
    invocation: String,
    reachability: EntrypointReachability,
    required_failure_modes: Vec<FailureMode>,
}

impl EntrypointRecord {
    /// Stable entrypoint identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Entrypoint family.
    #[must_use]
    pub const fn kind(&self) -> EntrypointKind {
        self.kind
    }

    /// User-visible invocation or API name.
    #[must_use]
    pub fn invocation(&self) -> &str {
        &self.invocation
    }

    /// Audited reachability state.
    #[must_use]
    pub const fn reachability(&self) -> EntrypointReachability {
        self.reachability
    }

    /// Failure modes required before an operational claim is valid.
    #[must_use]
    pub fn required_failure_modes(&self) -> &[FailureMode] {
        &self.required_failure_modes
    }
}

/// Whether a registry record is projected into user documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityVisibility {
    UserFacing,
    Internal,
}

/// One capability and all data that determine its maturity claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRecord {
    id: String,
    display_name: String,
    visibility: CapabilityVisibility,
    maturity: CapabilityMaturity,
    summary: String,
    limitation: String,
    entrypoints: Vec<EntrypointRecord>,
    required_effects: Vec<RequiredEffectRecord>,
    evidence_ids: Vec<String>,
}

impl CapabilityRecord {
    /// Stable capability identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// User-facing capability name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Whether this record belongs in generated user documentation.
    #[must_use]
    pub const fn visibility(&self) -> CapabilityVisibility {
        self.visibility
    }

    /// Audited maturity.
    #[must_use]
    pub const fn maturity(&self) -> CapabilityMaturity {
        self.maturity
    }

    /// Concise behavior description; never evidence.
    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// Known limitation shown beside the maturity state.
    #[must_use]
    pub fn limitation(&self) -> &str {
        &self.limitation
    }

    /// Concrete entrypoints.
    #[must_use]
    pub fn entrypoints(&self) -> &[EntrypointRecord] {
        &self.entrypoints
    }

    /// Effects that executable evidence must cover.
    #[must_use]
    pub fn required_effects(&self) -> &[RequiredEffectRecord] {
        &self.required_effects
    }

    /// Linked executable evidence identifiers.
    #[must_use]
    pub fn evidence_ids(&self) -> &[String] {
        &self.evidence_ids
    }
}

/// Success or one exact failure behavior covered by evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceCoverage {
    Success,
    Failure { failure_mode: FailureMode },
}

/// Outcome of one executable trial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialOutcome {
    Passed,
    Failed,
}

/// Source class for capability evidence provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSourceKind {
    ExecutableScenario,
}

/// Authority granted to an evidence record after validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAuthority {
    CapabilityRelease,
}

/// Explicit provenance for an executable evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProvenanceRecord {
    source: EvidenceSourceKind,
    authority: EvidenceAuthority,
    test_target: String,
}

impl EvidenceProvenanceRecord {
    /// Evidence source class.
    #[must_use]
    pub const fn source(&self) -> EvidenceSourceKind {
        self.source
    }

    /// Narrow authority granted by this evidence.
    #[must_use]
    pub const fn authority(&self) -> EvidenceAuthority {
        self.authority
    }

    /// Executable target that produces the receipts.
    #[must_use]
    pub fn test_target(&self) -> &str {
        &self.test_target
    }
}

/// Artifact-bound result from one execution of a corpus scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableReceipt {
    trial: u8,
    outcome: TrialOutcome,
    final_environment_sha256: ContentDigest,
    trace_sha256: ContentDigest,
    effect_observations_sha256: ContentDigest,
}

impl ExecutableReceipt {
    /// One-based trial number.
    #[must_use]
    pub const fn trial(&self) -> u8 {
        self.trial
    }

    /// Trial verdict.
    #[must_use]
    pub const fn outcome(&self) -> TrialOutcome {
        self.outcome
    }

    /// Digest of state read back from the disposable final environment.
    #[must_use]
    pub const fn final_environment_sha256(&self) -> ContentDigest {
        self.final_environment_sha256
    }

    /// Digest of the typed causal trace.
    #[must_use]
    pub const fn trace_sha256(&self) -> ContentDigest {
        self.trace_sha256
    }

    /// Digest of grader-derived typed effect observations.
    #[must_use]
    pub const fn effect_observations_sha256(&self) -> ContentDigest {
        self.effect_observations_sha256
    }
}

/// Executable evidence linked to a capability, entrypoint, corpus, and review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    id: String,
    capability_id: String,
    entrypoint_id: String,
    scenario_id: String,
    coverage: EvidenceCoverage,
    corpus_sha256: ContentDigest,
    quality_review_id: String,
    provenance: EvidenceProvenanceRecord,
    trace: TraceRecord,
    receipts: Vec<ExecutableReceipt>,
}

impl EvidenceRecord {
    /// Stable evidence identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Capability this evidence supports.
    #[must_use]
    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    /// Entrypoint this evidence exercises.
    #[must_use]
    pub fn entrypoint_id(&self) -> &str {
        &self.entrypoint_id
    }

    /// Executable corpus scenario.
    #[must_use]
    pub fn scenario_id(&self) -> &str {
        &self.scenario_id
    }

    /// Success or exact failure behavior exercised.
    #[must_use]
    pub const fn coverage(&self) -> EvidenceCoverage {
        self.coverage
    }

    /// Explicit executable source and release authority.
    #[must_use]
    pub const fn provenance(&self) -> &EvidenceProvenanceRecord {
        &self.provenance
    }

    /// Reviewed typed trace contract.
    #[must_use]
    pub const fn trace(&self) -> &TraceRecord {
        &self.trace
    }

    /// Individual multi-trial receipts.
    #[must_use]
    pub fn receipts(&self) -> &[ExecutableReceipt] {
        &self.receipts
    }
}

/// Versioned capability registry artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRegistry {
    schema_version: u16,
    generation: u64,
    capabilities: Vec<CapabilityRecord>,
    evidence: Vec<EvidenceRecord>,
}

impl CapabilityRegistry {
    /// Monotonic registry generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Capability records in deterministic documentation order.
    #[must_use]
    pub fn capabilities(&self) -> &[CapabilityRecord] {
        &self.capabilities
    }

    /// Executable evidence records.
    #[must_use]
    pub fn evidence(&self) -> &[EvidenceRecord] {
        &self.evidence
    }

    /// Find one capability by stable identifier.
    #[must_use]
    pub fn capability(&self, id: &str) -> Option<&CapabilityRecord> {
        self.capabilities.iter().find(|record| record.id == id)
    }
}

/// Kind of executable evaluation scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScenarioCoverage {
    Success,
    Failure { failure_mode: FailureMode },
}

/// Named executable action implemented by the acceptance harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioAction {
    RenderCapabilityDocumentation,
    RejectDocumentationOnlyOperationalClaim,
    RejectOperationalClaimMissingFailureEvidence,
}

/// Typed events retained by a capability evaluation trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationTraceEventKind {
    ScenarioStarted,
    RegistryLoaded,
    RegistryValidated,
    DocumentationRendered,
    RegistryRejected,
    FinalEnvironmentInspected,
}

/// Actual terminal outcome captured by an executable scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvaluationTraceOutcome {
    Success,
    Rejected { code: RegistryValidationCode },
}

/// One ordered evaluation trace event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationTraceEvent {
    sequence: u16,
    kind: EvaluationTraceEventKind,
}

impl EvaluationTraceEvent {
    /// Construct a typed event for an executable evaluation trace.
    #[must_use]
    pub const fn new(sequence: u16, kind: EvaluationTraceEventKind) -> Self {
        Self { sequence, kind }
    }

    /// Causal sequence number.
    #[must_use]
    pub const fn sequence(self) -> u16 {
        self.sequence
    }

    /// Typed event payload.
    #[must_use]
    pub const fn kind(self) -> EvaluationTraceEventKind {
        self.kind
    }
}

/// Versioned trace envelope bound to one exact scenario and outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationTraceEnvelope {
    schema_version: u16,
    scenario_id: String,
    outcome: EvaluationTraceOutcome,
    events: Vec<EvaluationTraceEvent>,
}

impl EvaluationTraceEnvelope {
    /// Capture a successful scenario outcome and its observed events.
    #[must_use]
    pub fn success(scenario_id: impl Into<String>, events: Vec<EvaluationTraceEvent>) -> Self {
        Self {
            schema_version: TRACE_SCHEMA_VERSION,
            scenario_id: scenario_id.into(),
            outcome: EvaluationTraceOutcome::Success,
            events,
        }
    }

    /// Capture an observed typed rejection and its events.
    #[must_use]
    pub fn rejected(
        scenario_id: impl Into<String>,
        code: RegistryValidationCode,
        events: Vec<EvaluationTraceEvent>,
    ) -> Self {
        Self {
            schema_version: TRACE_SCHEMA_VERSION,
            scenario_id: scenario_id.into(),
            outcome: EvaluationTraceOutcome::Rejected { code },
            events,
        }
    }

    /// Exact scenario identity included in the trace digest.
    #[must_use]
    pub fn scenario_id(&self) -> &str {
        &self.scenario_id
    }

    /// Actual terminal outcome included in the trace digest.
    #[must_use]
    pub const fn outcome(&self) -> EvaluationTraceOutcome {
        self.outcome
    }

    /// Ordered typed events included in the trace digest.
    #[must_use]
    pub fn events(&self) -> &[EvaluationTraceEvent] {
        &self.events
    }
}

/// Reviewed trace contract linked to executable evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceRecord {
    envelope: EvaluationTraceEnvelope,
    trace_sha256: ContentDigest,
}

impl TraceRecord {
    /// Executable scenario that owns this trace contract.
    #[must_use]
    pub fn scenario_id(&self) -> &str {
        &self.envelope.scenario_id
    }

    /// Exact versioned trace required by the reviewed grader.
    #[must_use]
    pub const fn envelope(&self) -> &EvaluationTraceEnvelope {
        &self.envelope
    }

    /// Digest bound into every trial receipt.
    #[must_use]
    pub const fn trace_sha256(&self) -> ContentDigest {
        self.trace_sha256
    }
}

/// Required state of one file after an evaluation trial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedFileState {
    path: String,
    content_sha256: ContentDigest,
    max_bytes: u64,
}

impl ExpectedFileState {
    /// Relative path below the disposable evaluation root.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Grader that reads final files and a typed trace after execution finishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalEnvironmentGrader {
    expected_files: Vec<ExpectedFileState>,
    absent_paths: Vec<String>,
    expected_environment_sha256: ContentDigest,
    expected_trace: EvaluationTraceEnvelope,
    expected_trace_sha256: ContentDigest,
    effect_observations: Vec<EffectObservationRecord>,
    expected_effect_observations_sha256: ContentDigest,
}

/// Process isolation assumed by the path-based final-environment grader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationExecutionIsolation {
    InProcessNoChild,
}

/// One reviewed, repeated executable scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationScenario {
    id: String,
    capability_id: String,
    entrypoint_id: String,
    coverage: ScenarioCoverage,
    action: ScenarioAction,
    trials: u8,
    test_target: String,
    test_name: String,
    execution_isolation: EvaluationExecutionIsolation,
    grader: FinalEnvironmentGrader,
}

impl EvaluationScenario {
    /// Stable scenario identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Action the acceptance harness must execute.
    #[must_use]
    pub const fn action(&self) -> ScenarioAction {
        self.action
    }

    /// Required independent trials.
    #[must_use]
    pub const fn trials(&self) -> u8 {
        self.trials
    }

    /// Cargo integration-test target that executes the scenario.
    #[must_use]
    pub fn test_target(&self) -> &str {
        &self.test_target
    }

    /// Exact test function that executes the scenario.
    #[must_use]
    pub fn test_name(&self) -> &str {
        &self.test_name
    }

    /// Isolation boundary under which path grading is authoritative.
    #[must_use]
    pub const fn execution_isolation(&self) -> EvaluationExecutionIsolation {
        self.execution_isolation
    }

    /// Grade a completed trial by reading final environment state and the
    /// typed trace. Model output and documentation prose are not inputs.
    ///
    /// # Errors
    ///
    /// Returns a typed error for unsafe paths, unbounded/non-regular files,
    /// missing or unexpected state, trace mismatch, or I/O failure.
    pub fn grade_trial(
        &self,
        root: &Path,
        trial: u8,
        trace: &EvaluationTraceEnvelope,
    ) -> Result<ExecutableReceipt, CapabilityEvidenceError> {
        if !(1..=self.trials).contains(&trial) {
            return Err(CapabilityEvidenceError::InvalidTrial {
                scenario_id: self.id.clone(),
                trial,
            });
        }
        let observations = self.inspect_final_environment(root)?;
        let environment_digest = digest_json(&observations)?;
        if environment_digest != self.grader.expected_environment_sha256 {
            return Err(CapabilityEvidenceError::EnvironmentDigestMismatch {
                scenario_id: self.id.clone(),
            });
        }
        let mut completed_trace = trace.clone();
        let sequence = u16::try_from(completed_trace.events.len() + 1).map_err(|_| {
            CapabilityEvidenceError::TraceMismatch {
                scenario_id: self.id.clone(),
            }
        })?;
        completed_trace.events.push(EvaluationTraceEvent::new(
            sequence,
            EvaluationTraceEventKind::FinalEnvironmentInspected,
        ));
        let trace_digest = digest_json(&completed_trace)?;
        if completed_trace != self.grader.expected_trace
            || trace_digest != self.grader.expected_trace_sha256
        {
            return Err(CapabilityEvidenceError::TraceMismatch {
                scenario_id: self.id.clone(),
            });
        }
        self.verify_effect_observations(&observations, &completed_trace)?;
        let effect_observations_digest = digest_json(&self.grader.effect_observations)?;
        if effect_observations_digest != self.grader.expected_effect_observations_sha256 {
            return Err(CapabilityEvidenceError::EffectObservationMismatch {
                scenario_id: self.id.clone(),
                effect_id: "effect-observation-set".to_string(),
            });
        }
        Ok(ExecutableReceipt {
            trial,
            outcome: TrialOutcome::Passed,
            final_environment_sha256: environment_digest,
            trace_sha256: trace_digest,
            effect_observations_sha256: effect_observations_digest,
        })
    }

    fn verify_effect_observations(
        &self,
        environment: &[EnvironmentObservation],
        trace: &EvaluationTraceEnvelope,
    ) -> Result<(), CapabilityEvidenceError> {
        for observation in &self.grader.effect_observations {
            let proven = match &observation.proof {
                EffectObservationProof::FinalFile { path } => environment.iter().any(
                    |item| matches!(item, EnvironmentObservation::Present { path: actual, .. } if actual == path),
                ),
                EffectObservationProof::ForbiddenPathAbsent { path } => environment.iter().any(
                    |item| matches!(item, EnvironmentObservation::Absent { path: actual } if actual == path),
                ),
                EffectObservationProof::TraceEvent { kind } => {
                    trace.events.iter().any(|event| event.kind == *kind)
                }
                EffectObservationProof::GraderExecution => !environment.is_empty(),
            };
            if !proven || !effect_proof_supports(observation) {
                return Err(CapabilityEvidenceError::EffectObservationMismatch {
                    scenario_id: self.id.clone(),
                    effect_id: observation.effect_id.clone(),
                });
            }
        }
        Ok(())
    }

    fn inspect_final_environment(
        &self,
        root: &Path,
    ) -> Result<Vec<EnvironmentObservation>, CapabilityEvidenceError> {
        let canonical_root = fs::canonicalize(root)
            .map_err(|source| self.environment_io(root.to_path_buf(), source))?;
        let mut observations =
            Vec::with_capacity(self.grader.expected_files.len() + self.grader.absent_paths.len());
        for expected in &self.grader.expected_files {
            let relative = PathBuf::from(&expected.path);
            let path = resolve_beneath(&canonical_root, &expected.path, false)
                .map_err(|source| self.environment_io(relative.clone(), source))?;
            let bytes = read_regular_bounded(&path, expected.max_bytes)
                .map_err(|source| self.environment_io(relative, source))?;
            let actual = ContentDigest::sha256(&bytes);
            if actual != expected.content_sha256 {
                return Err(CapabilityEvidenceError::FinalStateMismatch {
                    scenario_id: self.id.clone(),
                    path: expected.path.clone(),
                });
            }
            observations.push(EnvironmentObservation::Present {
                path: expected.path.clone(),
                content_sha256: actual,
            });
        }
        for absent in &self.grader.absent_paths {
            let relative = PathBuf::from(absent);
            let path = resolve_beneath(&canonical_root, absent, true)
                .map_err(|source| self.environment_io(relative, source))?;
            if fs::symlink_metadata(&path).is_ok() {
                return Err(CapabilityEvidenceError::UnexpectedFinalState {
                    scenario_id: self.id.clone(),
                    path: absent.clone(),
                });
            }
            observations.push(EnvironmentObservation::Absent {
                path: absent.clone(),
            });
        }
        observations.sort_by(|left, right| left.path().cmp(right.path()));
        Ok(observations)
    }

    fn environment_io(&self, path: PathBuf, source: io::Error) -> CapabilityEvidenceError {
        CapabilityEvidenceError::EnvironmentIo {
            scenario_id: self.id.clone(),
            path,
            source,
        }
    }
}

/// Versioned multi-trial evaluation corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationCorpus {
    schema_version: u16,
    corpus_id: String,
    author_id: String,
    scenarios: Vec<EvaluationScenario>,
}

impl EvaluationCorpus {
    /// Stable corpus identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.corpus_id
    }

    /// Reviewed executable scenarios.
    #[must_use]
    pub fn scenarios(&self) -> &[EvaluationScenario] {
        &self.scenarios
    }

    /// Find a scenario by stable identifier.
    #[must_use]
    pub fn scenario(&self, id: &str) -> Option<&EvaluationScenario> {
        self.scenarios.iter().find(|scenario| scenario.id == id)
    }
}

/// Independent review verdict for an evaluation corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityReviewVerdict {
    Approved,
    Rejected,
}

/// Required independent quality-review dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityReviewDimension {
    FinalEnvironmentGraders,
    SuccessAndFailureCoverage,
    MultiTrialDesign,
    TraceAssertions,
    EffectObservationAssertions,
    ArtifactBoundsAndIsolation,
}

/// Digest-bound independent review of the exact corpus artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationCorpusReview {
    schema_version: u16,
    review_id: String,
    reviewer_id: String,
    corpus_id: String,
    corpus_sha256: ContentDigest,
    verdict: QualityReviewVerdict,
    reviewed_scenario_ids: Vec<String>,
    reviewed_dimensions: Vec<QualityReviewDimension>,
    limitations: Vec<String>,
}

impl EvaluationCorpusReview {
    /// Stable review identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.review_id
    }

    /// Exact corpus artifact digest reviewed.
    #[must_use]
    pub const fn corpus_sha256(&self) -> ContentDigest {
        self.corpus_sha256
    }

    /// Review limitations retained with the approval.
    #[must_use]
    pub fn limitations(&self) -> &[String] {
        &self.limitations
    }
}

/// Registry, corpus, and independent review after all cross-artifact checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityEvidenceBundle {
    registry: CapabilityRegistry,
    corpus: EvaluationCorpus,
    review: EvaluationCorpusReview,
}

impl CapabilityEvidenceBundle {
    /// Parse and validate the exact bundled release artifacts.
    ///
    /// # Errors
    ///
    /// Returns a parse or typed validation error. Invalid evidence fails
    /// closed; no unchecked registry is returned.
    pub fn bundled() -> Result<Self, CapabilityEvidenceError> {
        Self::from_sources(BUNDLED_REGISTRY, BUNDLED_CORPUS, BUNDLED_REVIEW)
    }

    /// Parse and validate explicit artifacts. This supports downstream release
    /// tooling and adversarial tests without granting an unchecked constructor.
    ///
    /// # Errors
    ///
    /// Returns a parse or typed validation error.
    pub fn from_sources(
        registry_source: &str,
        corpus_source: &str,
        review_source: &str,
    ) -> Result<Self, CapabilityEvidenceError> {
        validate_artifact_size("registry", registry_source, MAX_REGISTRY_ARTIFACT_BYTES)?;
        validate_artifact_size(
            "evaluation-corpus",
            corpus_source,
            MAX_CORPUS_ARTIFACT_BYTES,
        )?;
        validate_artifact_size(
            "evaluation-corpus-review",
            review_source,
            MAX_REVIEW_ARTIFACT_BYTES,
        )?;
        let registry: CapabilityRegistry = parse_artifact("registry", registry_source)?;
        let corpus: EvaluationCorpus = parse_artifact("evaluation corpus", corpus_source)?;
        let review: EvaluationCorpusReview = parse_artifact("corpus review", review_source)?;
        validate_bundle(
            &registry,
            &corpus,
            &review,
            ContentDigest::sha256(corpus_source.as_bytes()),
        )?;
        Ok(Self {
            registry,
            corpus,
            review,
        })
    }

    /// Validated capability registry.
    #[must_use]
    pub const fn registry(&self) -> &CapabilityRegistry {
        &self.registry
    }

    /// Validated evaluation corpus.
    #[must_use]
    pub const fn corpus(&self) -> &EvaluationCorpus {
        &self.corpus
    }

    /// Independent review bound to the corpus digest.
    #[must_use]
    pub const fn review(&self) -> &EvaluationCorpusReview {
        &self.review
    }

    /// Render the user-facing matrix from validated registry data.
    ///
    /// Documentation prose is only a projection. Editing the rendered file
    /// cannot change capability maturity or produce an evidence receipt.
    #[must_use]
    pub fn render_user_facing_markdown(&self) -> String {
        let mut output = format!(
            "# Binary Capability Matrix — Registry Generation {}\n\n",
            self.registry.generation
        );
        output.push_str(
            "Generated from `capabilities/registry.json` after typed evidence validation. \
Do not edit this table by hand: prose is not readiness evidence. `operational` \
requires reviewed executable success and failure receipts for every reachable \
entrypoint; other maturity labels retain their stated limitations.\n\n",
        );
        output.push_str(
            "| Capability | Invocation | Entrypoint | Reachability | Maturity | Required effects | Acceptance evidence | Limitation |\n",
        );
        output.push_str("|---|---|---|---|---|---|---|---|\n");
        for capability in self
            .registry
            .capabilities
            .iter()
            .filter(|record| record.visibility == CapabilityVisibility::UserFacing)
        {
            let effects = if capability.required_effects.is_empty() {
                "none declared".to_string()
            } else {
                capability
                    .required_effects
                    .iter()
                    .map(|effect| effect.kind.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let evidence = if capability.evidence_ids.is_empty() {
                "none — not operational".to_string()
            } else {
                capability
                    .evidence_ids
                    .iter()
                    .filter_map(|id| self.registry.evidence.iter().find(|item| item.id == *id))
                    .map(|item| item.scenario_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            for entrypoint in &capability.entrypoints {
                output.push_str("| ");
                push_markdown_cell(&mut output, &capability.display_name);
                output.push('`');
                output.push_str(&escape_markdown(&entrypoint.invocation));
                output.push('`');
                output.push_str(" | ");
                push_markdown_cell(&mut output, entrypoint.kind.as_str());
                push_markdown_cell(&mut output, entrypoint.reachability.as_str());
                push_markdown_cell(&mut output, capability.maturity.as_str());
                push_markdown_cell(&mut output, &effects);
                push_markdown_cell(&mut output, &evidence);
                output.push_str(&escape_markdown(&capability.limitation));
                output.push_str(" |\n");
            }
        }
        output.push_str(
            "\nThe registry intentionally publishes `unsupported`, `experimental`, \
`schema-only`, `unreachable`, and `partial` states. Reachability proves only \
that an invocation reaches code; it does not promote maturity. The full audit \
remains the evidence source for limitations outside this initial registry.\n",
        );
        output
    }
}

/// Stable validation failure class used by negative evaluation scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryValidationCode {
    UnsupportedSchema,
    InvalidIdentifier,
    EmptyCollection,
    DuplicateIdentifier,
    InvalidEntrypoint,
    InvalidEffect,
    InvalidEvidenceLink,
    CorpusReviewInvalid,
    ReceiptMismatch,
    OperationalMissingSuccessEvidence,
    OperationalMissingFailureEvidence,
    OperationalMissingEffectEvidence,
    EvaluationBoundsInvalid,
}

impl RegistryValidationCode {
    /// Stable machine-readable label for end-state denial receipts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedSchema => "unsupported_schema",
            Self::InvalidIdentifier => "invalid_identifier",
            Self::EmptyCollection => "empty_collection",
            Self::DuplicateIdentifier => "duplicate_identifier",
            Self::InvalidEntrypoint => "invalid_entrypoint",
            Self::InvalidEffect => "invalid_effect",
            Self::InvalidEvidenceLink => "invalid_evidence_link",
            Self::CorpusReviewInvalid => "corpus_review_invalid",
            Self::ReceiptMismatch => "receipt_mismatch",
            Self::OperationalMissingSuccessEvidence => "operational_missing_success_evidence",
            Self::OperationalMissingFailureEvidence => "operational_missing_failure_evidence",
            Self::OperationalMissingEffectEvidence => "operational_missing_effect_evidence",
            Self::EvaluationBoundsInvalid => "evaluation_bounds_invalid",
        }
    }
}

/// Typed registry validation error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("capability evidence validation failed ({code:?}) for {record_id}: {detail}")]
pub struct RegistryValidationError {
    code: RegistryValidationCode,
    record_id: String,
    detail: String,
}

impl RegistryValidationError {
    fn new(
        code: RegistryValidationCode,
        record_id: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            code,
            record_id: record_id.into(),
            detail: detail.into(),
        }
    }

    /// Machine-readable failure class.
    #[must_use]
    pub const fn code(&self) -> RegistryValidationCode {
        self.code
    }

    /// Record that failed validation.
    #[must_use]
    pub fn record_id(&self) -> &str {
        &self.record_id
    }
}

/// Parse, validation, or executable final-state grading error.
#[derive(Debug, Error)]
pub enum CapabilityEvidenceError {
    #[error("cannot parse {artifact}: {source}")]
    Parse {
        artifact: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error(transparent)]
    Validation(#[from] RegistryValidationError),
    #[error("scenario {scenario_id} has no trial {trial}")]
    InvalidTrial { scenario_id: String, trial: u8 },
    #[error("cannot inspect final environment for scenario {scenario_id} at {path}: {source}")]
    EnvironmentIo {
        scenario_id: String,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("scenario {scenario_id} final file {path} does not match its reviewed digest")]
    FinalStateMismatch { scenario_id: String, path: String },
    #[error("scenario {scenario_id} unexpectedly created {path}")]
    UnexpectedFinalState { scenario_id: String, path: String },
    #[error("scenario {scenario_id} final-environment digest does not match its grader")]
    EnvironmentDigestMismatch { scenario_id: String },
    #[error("scenario {scenario_id} typed trace does not match its reviewed trace")]
    TraceMismatch { scenario_id: String },
    #[error("scenario {scenario_id} cannot prove typed effect observation {effect_id}")]
    EffectObservationMismatch {
        scenario_id: String,
        effect_id: String,
    },
    #[error("cannot serialize deterministic capability evidence: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum EnvironmentObservation {
    Present {
        path: String,
        content_sha256: ContentDigest,
    },
    Absent {
        path: String,
    },
}

impl EnvironmentObservation {
    fn path(&self) -> &str {
        match self {
            Self::Present { path, .. } | Self::Absent { path } => path,
        }
    }
}

fn parse_artifact<T>(artifact: &'static str, source: &str) -> Result<T, CapabilityEvidenceError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_str(source)
        .map_err(|source| CapabilityEvidenceError::Parse { artifact, source })
}

fn validate_artifact_size(
    artifact: &'static str,
    source: &str,
    max_bytes: usize,
) -> Result<(), CapabilityEvidenceError> {
    if source.len() > max_bytes {
        return Err(validation(
            RegistryValidationCode::EvaluationBoundsInvalid,
            artifact,
            format!("artifact exceeds its {max_bytes}-byte input limit"),
        )
        .into());
    }
    Ok(())
}

fn validate_bundle(
    registry: &CapabilityRegistry,
    corpus: &EvaluationCorpus,
    review: &EvaluationCorpusReview,
    corpus_digest: ContentDigest,
) -> Result<(), RegistryValidationError> {
    validate_schema("registry", registry.schema_version, REGISTRY_SCHEMA_VERSION)?;
    validate_schema(
        "evaluation-corpus",
        corpus.schema_version,
        CORPUS_SCHEMA_VERSION,
    )?;
    validate_schema(
        "evaluation-corpus-review",
        review.schema_version,
        REVIEW_SCHEMA_VERSION,
    )?;
    if registry.generation == 0 {
        return Err(validation(
            RegistryValidationCode::UnsupportedSchema,
            "registry",
            "generation must be non-zero",
        ));
    }
    validate_id("corpus", &corpus.corpus_id)?;
    validate_id("corpus-author", &corpus.author_id)?;
    validate_id("review", &review.review_id)?;
    validate_id("reviewer", &review.reviewer_id)?;
    if review.reviewed_scenario_ids.len() > MAX_SCENARIOS
        || review.reviewed_dimensions.len() > required_review_dimensions().len()
        || review.limitations.len() > MAX_REVIEW_LIMITATIONS
    {
        return Err(validation(
            RegistryValidationCode::EvaluationBoundsInvalid,
            &review.review_id,
            "corpus review collections exceed their configured bounds",
        ));
    }
    for limitation in &review.limitations {
        validate_text(&review.review_id, "limitation", limitation, MAX_TEXT_BYTES)?;
    }
    if review.corpus_id != corpus.corpus_id
        || review.corpus_sha256 != corpus_digest
        || review.verdict != QualityReviewVerdict::Approved
        || review
            .reviewed_dimensions
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            != required_review_dimensions()
        || review.reviewed_dimensions.len() != required_review_dimensions().len()
        || review.reviewer_id == corpus.author_id
    {
        return Err(validation(
            RegistryValidationCode::CorpusReviewInvalid,
            &review.review_id,
            "review must approve the exact corpus digest, pass every quality check, and use an author-independent reviewer",
        ));
    }

    let scenarios = validate_corpus(corpus)?;
    let reviewed = unique_ids(
        &review.review_id,
        &review.reviewed_scenario_ids,
        RegistryValidationCode::CorpusReviewInvalid,
    )?;
    let scenario_ids = scenarios.keys().copied().collect::<BTreeSet<_>>();
    if reviewed != scenario_ids {
        return Err(validation(
            RegistryValidationCode::CorpusReviewInvalid,
            &review.review_id,
            "reviewed scenario ids must exactly cover the corpus",
        ));
    }

    validate_registry_records(registry, &scenarios, review, corpus_digest, &scenario_ids)
}

fn validate_registry_records(
    registry: &CapabilityRegistry,
    scenarios: &BTreeMap<&str, &EvaluationScenario>,
    review: &EvaluationCorpusReview,
    corpus_digest: ContentDigest,
    scenario_ids: &BTreeSet<&str>,
) -> Result<(), RegistryValidationError> {
    if registry.capabilities.is_empty() || registry.capabilities.len() > MAX_CAPABILITIES {
        return Err(validation(
            RegistryValidationCode::EvaluationBoundsInvalid,
            "registry",
            format!("registry must contain between 1 and {MAX_CAPABILITIES} capabilities"),
        ));
    }
    if registry.evidence.len() > MAX_EVIDENCE_RECORDS {
        return Err(validation(
            RegistryValidationCode::EvaluationBoundsInvalid,
            "registry",
            format!("registry may contain at most {MAX_EVIDENCE_RECORDS} evidence records"),
        ));
    }
    let mut capabilities = BTreeMap::new();
    for capability in &registry.capabilities {
        validate_id("capability", &capability.id)?;
        validate_text(
            &capability.id,
            "display_name",
            &capability.display_name,
            MAX_TEST_FIELD_BYTES,
        )?;
        validate_text(
            &capability.id,
            "summary",
            &capability.summary,
            MAX_TEXT_BYTES,
        )?;
        validate_text(
            &capability.id,
            "limitation",
            &capability.limitation,
            MAX_TEXT_BYTES,
        )?;
        if capabilities
            .insert(capability.id.as_str(), capability)
            .is_some()
        {
            return Err(validation(
                RegistryValidationCode::DuplicateIdentifier,
                &capability.id,
                "duplicate capability id",
            ));
        }
        validate_capability_shape(capability)?;
    }

    let mut evidence = BTreeMap::new();
    for record in &registry.evidence {
        validate_id("evidence", &record.id)?;
        if evidence.insert(record.id.as_str(), record).is_some() {
            return Err(validation(
                RegistryValidationCode::DuplicateIdentifier,
                &record.id,
                "duplicate evidence id",
            ));
        }
        validate_evidence_record(record, &capabilities, scenarios, review, corpus_digest)?;
    }
    let linked_scenarios = evidence
        .values()
        .map(|record| record.scenario_id.as_str())
        .collect::<BTreeSet<_>>();
    if &linked_scenarios != scenario_ids {
        return Err(validation(
            RegistryValidationCode::InvalidEvidenceLink,
            "registry",
            "reviewed corpus scenarios and linked evidence scenarios must match exactly",
        ));
    }
    for capability in registry.capabilities() {
        validate_capability_evidence(capability, &evidence, scenarios)?;
    }
    Ok(())
}

fn validate_schema(
    artifact: &str,
    found: u16,
    expected: u16,
) -> Result<(), RegistryValidationError> {
    if found != expected {
        return Err(validation(
            RegistryValidationCode::UnsupportedSchema,
            artifact,
            format!("expected schema {expected}, found {found}"),
        ));
    }
    Ok(())
}

fn required_review_dimensions() -> BTreeSet<QualityReviewDimension> {
    [
        QualityReviewDimension::FinalEnvironmentGraders,
        QualityReviewDimension::SuccessAndFailureCoverage,
        QualityReviewDimension::MultiTrialDesign,
        QualityReviewDimension::TraceAssertions,
        QualityReviewDimension::EffectObservationAssertions,
        QualityReviewDimension::ArtifactBoundsAndIsolation,
    ]
    .into_iter()
    .collect()
}

fn validate_corpus(
    corpus: &EvaluationCorpus,
) -> Result<BTreeMap<&str, &EvaluationScenario>, RegistryValidationError> {
    if corpus.scenarios.is_empty() || corpus.scenarios.len() > MAX_SCENARIOS {
        return Err(validation(
            RegistryValidationCode::EvaluationBoundsInvalid,
            &corpus.corpus_id,
            format!("evaluation corpus must contain between 1 and {MAX_SCENARIOS} scenarios"),
        ));
    }
    let mut scenarios = BTreeMap::new();
    for scenario in &corpus.scenarios {
        validate_id("scenario", &scenario.id)?;
        validate_id("scenario-capability", &scenario.capability_id)?;
        validate_id("scenario-entrypoint", &scenario.entrypoint_id)?;
        validate_text(
            &scenario.id,
            "test_target",
            &scenario.test_target,
            MAX_TEST_FIELD_BYTES,
        )?;
        validate_text(
            &scenario.id,
            "test_name",
            &scenario.test_name,
            MAX_TEST_FIELD_BYTES,
        )?;
        if !(MIN_EVALUATION_TRIALS..=MAX_EVALUATION_TRIALS).contains(&scenario.trials) {
            return Err(validation(
                RegistryValidationCode::EvaluationBoundsInvalid,
                &scenario.id,
                format!(
                    "trial count must be between {MIN_EVALUATION_TRIALS} and {MAX_EVALUATION_TRIALS}"
                ),
            ));
        }
        validate_grader(scenario)?;
        if scenarios.insert(scenario.id.as_str(), scenario).is_some() {
            return Err(validation(
                RegistryValidationCode::DuplicateIdentifier,
                &scenario.id,
                "duplicate scenario id",
            ));
        }
    }
    Ok(scenarios)
}

fn validate_grader(scenario: &EvaluationScenario) -> Result<(), RegistryValidationError> {
    validate_environment_grader(scenario)?;
    validate_trace_grader(scenario)?;
    validate_effect_grader(scenario)
}

fn validate_environment_grader(
    scenario: &EvaluationScenario,
) -> Result<(), RegistryValidationError> {
    let grader = &scenario.grader;
    let path_count = grader
        .expected_files
        .len()
        .checked_add(grader.absent_paths.len())
        .ok_or_else(|| {
            validation(
                RegistryValidationCode::EvaluationBoundsInvalid,
                &scenario.id,
                "grader path count overflowed",
            )
        })?;
    if path_count == 0 || path_count > MAX_GRADER_PATHS {
        return Err(validation(
            RegistryValidationCode::EvaluationBoundsInvalid,
            &scenario.id,
            format!("grader must inspect between 1 and {MAX_GRADER_PATHS} paths"),
        ));
    }
    let mut paths = BTreeSet::new();
    let mut expected_observations = Vec::with_capacity(path_count);
    for expected in &grader.expected_files {
        validate_relative_path(&scenario.id, &expected.path)?;
        if expected.max_bytes == 0 || expected.max_bytes > MAX_GRADED_FILE_BYTES {
            return Err(validation(
                RegistryValidationCode::EvaluationBoundsInvalid,
                &scenario.id,
                format!(
                    "{} must use a byte limit between 1 and {MAX_GRADED_FILE_BYTES}",
                    expected.path
                ),
            ));
        }
        if !paths.insert(expected.path.as_str()) {
            return Err(validation(
                RegistryValidationCode::DuplicateIdentifier,
                &scenario.id,
                format!("duplicate grader path {}", expected.path),
            ));
        }
        expected_observations.push(EnvironmentObservation::Present {
            path: expected.path.clone(),
            content_sha256: expected.content_sha256,
        });
    }
    for absent in &grader.absent_paths {
        validate_relative_path(&scenario.id, absent)?;
        if !paths.insert(absent) {
            return Err(validation(
                RegistryValidationCode::DuplicateIdentifier,
                &scenario.id,
                format!("duplicate grader path {absent}"),
            ));
        }
        expected_observations.push(EnvironmentObservation::Absent {
            path: absent.clone(),
        });
    }
    expected_observations.sort_by(|left, right| left.path().cmp(right.path()));
    if digest_json_validation(&scenario.id, &expected_observations)?
        != grader.expected_environment_sha256
    {
        return Err(validation(
            RegistryValidationCode::ReceiptMismatch,
            &scenario.id,
            "reviewed final-environment digest does not match grader expectations",
        ));
    }
    Ok(())
}

fn validate_trace_grader(scenario: &EvaluationScenario) -> Result<(), RegistryValidationError> {
    let trace = &scenario.grader.expected_trace;
    if trace.schema_version != TRACE_SCHEMA_VERSION
        || trace.scenario_id != scenario.id
        || trace.events.is_empty()
        || trace.events.len() > MAX_GRADER_PATHS
        || trace
            .events
            .iter()
            .enumerate()
            .any(|(index, event)| usize::from(event.sequence) != index + 1)
        || trace.events.last().map(|event| event.kind())
            != Some(EvaluationTraceEventKind::FinalEnvironmentInspected)
        || !trace_outcome_matches_action(scenario.action, trace.outcome)
    {
        return Err(validation(
            RegistryValidationCode::EvaluationBoundsInvalid,
            &scenario.id,
            "trace must bind the exact schema, scenario, action outcome, and ordered final-environment inspection",
        ));
    }
    if digest_json_validation(&scenario.id, trace)? != scenario.grader.expected_trace_sha256 {
        return Err(validation(
            RegistryValidationCode::ReceiptMismatch,
            &scenario.id,
            "reviewed trace digest does not match typed trace events",
        ));
    }
    Ok(())
}

fn validate_effect_grader(scenario: &EvaluationScenario) -> Result<(), RegistryValidationError> {
    let observations = &scenario.grader.effect_observations;
    if observations.is_empty() || observations.len() > MAX_EFFECT_OBSERVATIONS {
        return Err(validation(
            RegistryValidationCode::EvaluationBoundsInvalid,
            &scenario.id,
            format!(
                "grader must declare between 1 and {MAX_EFFECT_OBSERVATIONS} effect observations"
            ),
        ));
    }
    let mut effect_ids = BTreeSet::new();
    for observation in observations {
        validate_id("observed-effect", &observation.effect_id)?;
        if !effect_ids.insert(observation.effect_id.as_str()) {
            return Err(validation(
                RegistryValidationCode::DuplicateIdentifier,
                &scenario.id,
                format!("duplicate effect observation {}", observation.effect_id),
            ));
        }
        validate_effect_proof_shape(scenario, observation)?;
    }
    if digest_json_validation(&scenario.id, observations)?
        != scenario.grader.expected_effect_observations_sha256
    {
        return Err(validation(
            RegistryValidationCode::ReceiptMismatch,
            &scenario.id,
            "reviewed effect-observation digest does not match typed observations",
        ));
    }
    Ok(())
}

const fn trace_outcome_matches_action(
    action: ScenarioAction,
    outcome: EvaluationTraceOutcome,
) -> bool {
    matches!(
        (action, outcome),
        (
            ScenarioAction::RenderCapabilityDocumentation,
            EvaluationTraceOutcome::Success
        ) | (
            ScenarioAction::RejectDocumentationOnlyOperationalClaim,
            EvaluationTraceOutcome::Rejected {
                code: RegistryValidationCode::OperationalMissingSuccessEvidence
            }
        ) | (
            ScenarioAction::RejectOperationalClaimMissingFailureEvidence,
            EvaluationTraceOutcome::Rejected {
                code: RegistryValidationCode::OperationalMissingFailureEvidence
            }
        )
    )
}

fn validate_effect_proof_shape(
    scenario: &EvaluationScenario,
    observation: &EffectObservationRecord,
) -> Result<(), RegistryValidationError> {
    let referenced_path = match &observation.proof {
        EffectObservationProof::FinalFile { path } => {
            if !scenario
                .grader
                .expected_files
                .iter()
                .any(|expected| expected.path == path.as_str())
            {
                return Err(validation(
                    RegistryValidationCode::InvalidEffect,
                    &observation.effect_id,
                    "final-file effect proof is not an expected final file",
                ));
            }
            Some(path.as_str())
        }
        EffectObservationProof::ForbiddenPathAbsent { path } => {
            if !scenario
                .grader
                .absent_paths
                .iter()
                .any(|absent| absent == path)
            {
                return Err(validation(
                    RegistryValidationCode::InvalidEffect,
                    &observation.effect_id,
                    "forbidden-path proof is not an inspected absent path",
                ));
            }
            Some(path.as_str())
        }
        EffectObservationProof::TraceEvent { kind } => {
            if !scenario
                .grader
                .expected_trace
                .events
                .iter()
                .any(|event| event.kind == *kind)
            {
                return Err(validation(
                    RegistryValidationCode::InvalidEffect,
                    &observation.effect_id,
                    "trace-event effect proof is absent from the reviewed trace",
                ));
            }
            None
        }
        EffectObservationProof::GraderExecution => None,
    };
    if let Some(path) = referenced_path {
        validate_relative_path(&scenario.id, path)?;
    }
    if !effect_proof_supports(observation) {
        return Err(validation(
            RegistryValidationCode::InvalidEffect,
            &observation.effect_id,
            "effect kind and state are incompatible with the selected runtime proof",
        ));
    }
    Ok(())
}

const fn effect_proof_supports(observation: &EffectObservationRecord) -> bool {
    matches!(
        (&observation.proof, observation.kind, observation.state),
        (
            EffectObservationProof::FinalFile { .. },
            RequiredEffectKind::FilesystemWrite | RequiredEffectKind::DocumentationProjection,
            EffectObservationState::Occurred,
        ) | (
            EffectObservationProof::ForbiddenPathAbsent { .. },
            RequiredEffectKind::FilesystemWrite
                | RequiredEffectKind::SessionMutation
                | RequiredEffectKind::ExternalMutation
                | RequiredEffectKind::DocumentationProjection,
            EffectObservationState::DidNotOccur,
        ) | (
            EffectObservationProof::TraceEvent { .. },
            RequiredEffectKind::TraceEmission,
            EffectObservationState::Occurred,
        ) | (
            EffectObservationProof::GraderExecution,
            RequiredEffectKind::FinalEnvironmentObservation,
            EffectObservationState::Occurred,
        )
    )
}

fn validate_capability_shape(capability: &CapabilityRecord) -> Result<(), RegistryValidationError> {
    if capability.entrypoints.is_empty()
        || capability.entrypoints.len() > MAX_ENTRYPOINTS_PER_CAPABILITY
        || capability.required_effects.len() > MAX_EFFECTS_PER_CAPABILITY
        || capability.evidence_ids.len() > MAX_LINKS_PER_RECORD
    {
        return Err(validation(
            RegistryValidationCode::EvaluationBoundsInvalid,
            &capability.id,
            "capability entrypoint, effect, or evidence-link collection exceeds its bound",
        ));
    }
    let mut entrypoints = BTreeSet::new();
    for entrypoint in &capability.entrypoints {
        validate_id("entrypoint", &entrypoint.id)?;
        validate_text(
            &entrypoint.id,
            "invocation",
            &entrypoint.invocation,
            MAX_INVOCATION_BYTES,
        )?;
        if entrypoint.required_failure_modes.len() > MAX_FAILURE_MODES_PER_ENTRYPOINT {
            return Err(validation(
                RegistryValidationCode::EvaluationBoundsInvalid,
                &entrypoint.id,
                format!(
                    "entrypoint may declare at most {MAX_FAILURE_MODES_PER_ENTRYPOINT} failure modes"
                ),
            ));
        }
        if !entrypoints.insert(entrypoint.id.as_str()) {
            return Err(validation(
                RegistryValidationCode::DuplicateIdentifier,
                &entrypoint.id,
                "duplicate entrypoint id within capability",
            ));
        }
        let failures = entrypoint
            .required_failure_modes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if failures.len() != entrypoint.required_failure_modes.len() {
            return Err(validation(
                RegistryValidationCode::InvalidEntrypoint,
                &entrypoint.id,
                "required failure modes must be unique",
            ));
        }
    }
    let mut effects = BTreeSet::new();
    for effect in &capability.required_effects {
        validate_id("required-effect", &effect.id)?;
        validate_text(
            &effect.id,
            "description",
            &effect.description,
            MAX_TEXT_BYTES,
        )?;
        if !effects.insert(effect.id.as_str()) {
            return Err(validation(
                RegistryValidationCode::DuplicateIdentifier,
                &effect.id,
                "duplicate effect id within capability",
            ));
        }
    }
    unique_ids(
        &capability.id,
        &capability.evidence_ids,
        RegistryValidationCode::InvalidEvidenceLink,
    )?;
    Ok(())
}

fn validate_evidence_record(
    evidence: &EvidenceRecord,
    capabilities: &BTreeMap<&str, &CapabilityRecord>,
    scenarios: &BTreeMap<&str, &EvaluationScenario>,
    review: &EvaluationCorpusReview,
    corpus_digest: ContentDigest,
) -> Result<(), RegistryValidationError> {
    let capability = capabilities
        .get(evidence.capability_id.as_str())
        .ok_or_else(|| {
            validation(
                RegistryValidationCode::InvalidEvidenceLink,
                &evidence.id,
                "evidence references an unknown capability",
            )
        })?;
    let entrypoint = capability
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.id == evidence.entrypoint_id)
        .ok_or_else(|| {
            validation(
                RegistryValidationCode::InvalidEvidenceLink,
                &evidence.id,
                "evidence references an unknown capability entrypoint",
            )
        })?;
    let scenario = scenarios
        .get(evidence.scenario_id.as_str())
        .ok_or_else(|| {
            validation(
                RegistryValidationCode::InvalidEvidenceLink,
                &evidence.id,
                "evidence references an unknown executable scenario",
            )
        })?;
    let coverage_matches = matches!(
        (evidence.coverage, scenario.coverage),
        (EvidenceCoverage::Success, ScenarioCoverage::Success)
    ) || matches!(
        (evidence.coverage, scenario.coverage),
        (
            EvidenceCoverage::Failure { failure_mode: left },
            ScenarioCoverage::Failure { failure_mode: right }
        ) if left == right
    );
    if scenario.capability_id != capability.id
        || scenario.entrypoint_id != entrypoint.id
        || !coverage_matches
        || evidence.corpus_sha256 != corpus_digest
        || evidence.quality_review_id != review.review_id
        || evidence.provenance.source != EvidenceSourceKind::ExecutableScenario
        || evidence.provenance.authority != EvidenceAuthority::CapabilityRelease
        || evidence.provenance.test_target != scenario.test_target
        || evidence.trace.envelope != scenario.grader.expected_trace
        || evidence.trace.trace_sha256 != scenario.grader.expected_trace_sha256
    {
        return Err(validation(
            RegistryValidationCode::InvalidEvidenceLink,
            &evidence.id,
            "evidence capability, entrypoint, coverage, corpus digest, or review binding does not match its scenario",
        ));
    }
    validate_text(
        &evidence.id,
        "provenance.test_target",
        &evidence.provenance.test_target,
        MAX_TEST_FIELD_BYTES,
    )?;
    validate_effect_observation_contract(evidence, capability, scenario)?;
    if evidence.receipts.len() != usize::from(scenario.trials) {
        return Err(validation(
            RegistryValidationCode::ReceiptMismatch,
            &evidence.id,
            "receipt count must equal the reviewed scenario trial count",
        ));
    }
    let mut trials = BTreeSet::new();
    for receipt in &evidence.receipts {
        if receipt.outcome != TrialOutcome::Passed
            || !(1..=scenario.trials).contains(&receipt.trial)
            || !trials.insert(receipt.trial)
            || receipt.final_environment_sha256 != scenario.grader.expected_environment_sha256
            || receipt.trace_sha256 != scenario.grader.expected_trace_sha256
            || receipt.effect_observations_sha256
                != scenario.grader.expected_effect_observations_sha256
        {
            return Err(validation(
                RegistryValidationCode::ReceiptMismatch,
                &evidence.id,
                "every reviewed trial must have one passing final-state, trace, and effect-bound receipt",
            ));
        }
    }
    Ok(())
}

fn validate_effect_observation_contract(
    evidence: &EvidenceRecord,
    capability: &CapabilityRecord,
    scenario: &EvaluationScenario,
) -> Result<(), RegistryValidationError> {
    for observation in &scenario.grader.effect_observations {
        let required = capability
            .required_effects
            .iter()
            .find(|effect| effect.id == observation.effect_id)
            .ok_or_else(|| {
                validation(
                    RegistryValidationCode::InvalidEffect,
                    &evidence.id,
                    format!(
                        "scenario observes undeclared effect {}",
                        observation.effect_id
                    ),
                )
            })?;
        let expectation_matches = match required.expectation {
            EffectExpectation::MustOccur => observation.state == EffectObservationState::Occurred,
            EffectExpectation::MustNotOccur => {
                observation.state == EffectObservationState::DidNotOccur
            }
            EffectExpectation::MayOccur => true,
        };
        if required.kind != observation.kind || !expectation_matches {
            return Err(validation(
                RegistryValidationCode::InvalidEffect,
                &evidence.id,
                format!(
                    "effect observation {} contradicts its declared kind or expectation",
                    observation.effect_id
                ),
            ));
        }
    }
    Ok(())
}

fn validate_capability_evidence(
    capability: &CapabilityRecord,
    evidence: &BTreeMap<&str, &EvidenceRecord>,
    scenarios: &BTreeMap<&str, &EvaluationScenario>,
) -> Result<(), RegistryValidationError> {
    let linked = capability
        .evidence_ids
        .iter()
        .map(|id| {
            evidence.get(id.as_str()).copied().ok_or_else(|| {
                validation(
                    RegistryValidationCode::InvalidEvidenceLink,
                    &capability.id,
                    format!("unknown evidence id {id}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if linked
        .iter()
        .any(|record| record.capability_id != capability.id)
    {
        return Err(validation(
            RegistryValidationCode::InvalidEvidenceLink,
            &capability.id,
            "capability links evidence owned by another capability",
        ));
    }
    let reverse_links = evidence
        .values()
        .filter(|record| record.capability_id == capability.id)
        .map(|record| record.id.as_str())
        .collect::<BTreeSet<_>>();
    let forward_links = capability
        .evidence_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if reverse_links != forward_links {
        return Err(validation(
            RegistryValidationCode::InvalidEvidenceLink,
            &capability.id,
            "capability and evidence links must be bidirectionally exact",
        ));
    }
    if capability.maturity != CapabilityMaturity::Operational {
        return Ok(());
    }
    validate_operational_entrypoints(capability, &linked)?;
    validate_operational_effects(capability, &linked, scenarios)
}

fn validate_operational_entrypoints(
    capability: &CapabilityRecord,
    linked: &[&EvidenceRecord],
) -> Result<(), RegistryValidationError> {
    if capability.required_effects.is_empty() {
        return Err(validation(
            RegistryValidationCode::OperationalMissingEffectEvidence,
            &capability.id,
            "operational capability must declare at least one required effect",
        ));
    }
    let mut found_reachable = false;
    for entrypoint in capability
        .entrypoints
        .iter()
        .filter(|entrypoint| entrypoint.reachability == EntrypointReachability::Reachable)
    {
        found_reachable = true;
        if entrypoint.required_failure_modes.is_empty() {
            return Err(validation(
                RegistryValidationCode::OperationalMissingFailureEvidence,
                &entrypoint.id,
                "reachable operational entrypoint must declare failure modes",
            ));
        }
        if !linked.iter().any(|record| {
            record.entrypoint_id == entrypoint.id && record.coverage == EvidenceCoverage::Success
        }) {
            return Err(validation(
                RegistryValidationCode::OperationalMissingSuccessEvidence,
                &entrypoint.id,
                "reachable operational entrypoint lacks executable success receipts",
            ));
        }
        for failure_mode in &entrypoint.required_failure_modes {
            if !linked.iter().any(|record| {
                record.entrypoint_id == entrypoint.id
                    && record.coverage
                        == EvidenceCoverage::Failure {
                            failure_mode: *failure_mode,
                        }
            }) {
                return Err(validation(
                    RegistryValidationCode::OperationalMissingFailureEvidence,
                    &entrypoint.id,
                    format!(
                        "reachable operational entrypoint lacks executable receipts for {failure_mode:?}"
                    ),
                ));
            }
        }
    }
    if !found_reachable {
        return Err(validation(
            RegistryValidationCode::OperationalMissingSuccessEvidence,
            &capability.id,
            "operational capability must have a reachable entrypoint",
        ));
    }
    Ok(())
}

fn validate_operational_effects(
    capability: &CapabilityRecord,
    linked: &[&EvidenceRecord],
    scenarios: &BTreeMap<&str, &EvaluationScenario>,
) -> Result<(), RegistryValidationError> {
    for required in &capability.required_effects {
        if required.expectation == EffectExpectation::MayOccur {
            continue;
        }
        let proven = match required.expectation {
            EffectExpectation::MustOccur => linked.iter().any(|record| {
                observed_effect_state(record, required, scenarios)
                    == Some(EffectObservationState::Occurred)
            }),
            EffectExpectation::MustNotOccur => linked.iter().all(|record| {
                observed_effect_state(record, required, scenarios)
                    == Some(EffectObservationState::DidNotOccur)
            }),
            EffectExpectation::MayOccur => true,
        };
        if !proven {
            let detail = if required.expectation == EffectExpectation::MustNotOccur {
                "every executable scenario must prove the forbidden effect remained absent"
            } else {
                "operational capability lacks an executable occurrence proof"
            };
            return Err(validation(
                RegistryValidationCode::OperationalMissingEffectEvidence,
                &required.id,
                detail,
            ));
        }
    }
    Ok(())
}

fn observed_effect_state(
    evidence: &EvidenceRecord,
    required: &RequiredEffectRecord,
    scenarios: &BTreeMap<&str, &EvaluationScenario>,
) -> Option<EffectObservationState> {
    scenarios
        .get(evidence.scenario_id.as_str())?
        .grader
        .effect_observations
        .iter()
        .find(|observation| observation.effect_id == required.id)
        .map(|observation| observation.state)
}

fn validate_id(kind: &str, id: &str) -> Result<(), RegistryValidationError> {
    if id.is_empty()
        || id.len() > 96
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-.".contains(&byte))
    {
        return Err(validation(
            RegistryValidationCode::InvalidIdentifier,
            id,
            format!("{kind} id must be 1-96 lowercase ASCII letters, digits, dots, or hyphens"),
        ));
    }
    Ok(())
}

fn validate_text(
    record_id: &str,
    field: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), RegistryValidationError> {
    if value.trim().is_empty() {
        return Err(validation(
            RegistryValidationCode::EmptyCollection,
            record_id,
            format!("{field} must not be empty"),
        ));
    }
    if value.len() > max_bytes || value.contains('\0') {
        return Err(validation(
            RegistryValidationCode::EvaluationBoundsInvalid,
            record_id,
            format!("{field} must be at most {max_bytes} bytes and contain no NUL"),
        ));
    }
    Ok(())
}

fn unique_ids<'a>(
    record_id: &str,
    ids: &'a [String],
    code: RegistryValidationCode,
) -> Result<BTreeSet<&'a str>, RegistryValidationError> {
    let mut unique = BTreeSet::new();
    for id in ids {
        validate_id("linked", id)?;
        if !unique.insert(id.as_str()) {
            return Err(validation(
                code,
                record_id,
                format!("duplicate linked id {id}"),
            ));
        }
    }
    Ok(unique)
}

fn validate_relative_path(scenario_id: &str, path: &str) -> Result<(), RegistryValidationError> {
    let parsed = Path::new(path);
    if path.is_empty()
        || path.len() > 240
        || parsed.is_absolute()
        || parsed
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(validation(
            RegistryValidationCode::EvaluationBoundsInvalid,
            scenario_id,
            format!("grader path {path:?} must be a bounded normal relative path"),
        ));
    }
    Ok(())
}

fn validation(
    code: RegistryValidationCode,
    record_id: impl Into<String>,
    detail: impl Into<String>,
) -> RegistryValidationError {
    RegistryValidationError::new(code, record_id, detail)
}

fn digest_json<T: Serialize>(value: &T) -> Result<ContentDigest, CapabilityEvidenceError> {
    Ok(ContentDigest::sha256(serde_json::to_vec(value)?))
}

fn digest_json_validation<T: Serialize>(
    record_id: &str,
    value: &T,
) -> Result<ContentDigest, RegistryValidationError> {
    serde_json::to_vec(value)
        .map(ContentDigest::sha256)
        .map_err(|error| {
            validation(
                RegistryValidationCode::ReceiptMismatch,
                record_id,
                format!("cannot serialize deterministic grader state: {error}"),
            )
        })
}

fn escape_markdown(value: &str) -> String {
    value.replace('|', "\\|").replace(['\n', '\r'], " ")
}

fn push_markdown_cell(output: &mut String, value: &str) {
    output.push_str(&escape_markdown(value));
    output.push_str(" | ");
}

fn resolve_beneath(root: &Path, relative: &str, allow_missing: bool) -> io::Result<PathBuf> {
    let mut current = root.to_path_buf();
    let components = Path::new(relative).components().collect::<Vec<_>>();
    for (index, component) in components.iter().copied().enumerate() {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "evaluation path is not normal and relative",
            ));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "evaluation path contains a symlink",
                    ));
                }
                if index + 1 < components.len() && !metadata.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotADirectory,
                        "evaluation path parent is not a directory",
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && allow_missing => {
                for remaining in components[index + 1..].iter().copied() {
                    let Component::Normal(name) = remaining else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "evaluation path is not normal and relative",
                        ));
                    };
                    current.push(name);
                }
                return Ok(current);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(current)
}

fn read_regular_bounded(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "graded path must be a non-symlink regular file",
        ));
    }
    if metadata.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "graded file exceeds its byte limit",
        ));
    }
    let max_len = usize::try_from(max_bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "graded file byte limit does not fit this platform",
        )
    })?;
    let mut bytes = Vec::with_capacity(max_len.min(64 * 1024));
    File::open(path)?
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "graded file exceeded its byte limit while reading",
        ));
    }
    Ok(bytes)
}
