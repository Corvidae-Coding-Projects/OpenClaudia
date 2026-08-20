//! Provenance-bound observation ledger for grounded agent decisions.
//!
//! Chat history, memory, and compaction summaries are useful navigation
//! aids, but they are not facts. `RealityLedger` stores observations issued by
//! typed runtime producers. The decision gate evaluates the provenance and
//! claim applicability of those records; presence in this ledger is not, by
//! itself, proof.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use thiserror::Error;
use uuid::Uuid;

use crate::runtime::{CapabilityGeneration, RunId};

const SCHEMA_VERSION: i64 = 1;
const SESSION_LEDGER_DIR: &str = ".openclaudia/reality-ledgers";
const MAX_RUNTIME_ISSUED_RECEIPTS: usize = 65_536;

pub type SharedRealityLedger = Arc<Mutex<RealityLedger>>;

static ACTIVE_REALITY_LEDGERS: LazyLock<Mutex<HashMap<String, SharedRealityLedger>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static RUNTIME_ISSUED_RECEIPTS: LazyLock<Mutex<IssuedReceiptRegistry>> =
    LazyLock::new(|| Mutex::new(IssuedReceiptRegistry::default()));

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObsId(Uuid);

impl ObsId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for ObsId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ObsId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for ObsId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(Self)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Observation {
    pub id: ObsId,
    pub ts: DateTime<Utc>,
    pub kind: ObservationKind,
    pub provenance: EvidenceProvenance,
}

impl Observation {
    fn new(provenance: EvidenceProvenance, kind: ObservationKind) -> Self {
        Self {
            id: ObsId::new(),
            ts: Utc::now(),
            kind,
            provenance,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceTrust {
    UserInput,
    RuntimeObserved,
    UntrustedContent,
    HostPolicy,
    TrustedVerifier,
    DerivedSummary,
    /// Typed provenance loaded from mutable persistence without a matching
    /// process-issued receipt remains useful for navigation, never proof.
    UnverifiedPersisted,
    /// Rows written before the provenance schema cannot authorize decisions.
    LegacyUnbound,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EvidenceSource {
    UserInput,
    FilesystemRead,
    CommandExecution,
    WorkspaceDiff,
    ToolResult,
    HostPolicy { policy: String },
    QualityGate { check: String },
    ModelSummary,
    Legacy { claimed_authority: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RunBinding {
    pub run_id: RunId,
    pub capability_generation: CapabilityGeneration,
}

impl RunBinding {
    #[must_use]
    pub(crate) fn from_run(run: &crate::tools::ToolRunContext) -> Self {
        Self {
            run_id: run.run_id(),
            capability_generation: run.generation(),
        }
    }

    #[must_use]
    pub fn matches(&self, run: &crate::tools::ToolRunContext) -> bool {
        self.run_id == run.run_id() && self.capability_generation == run.generation()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ToolCallBinding {
    pub call_id: String,
    pub handler: String,
    pub arguments_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ArtifactBinding {
    File {
        path: String,
        sha256: String,
    },
    Diff {
        files: Vec<String>,
        patch_sha256: String,
    },
    Command {
        cwd: String,
        argv_sha256: String,
    },
    Executable {
        path: String,
        sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VerificationMethod {
    GuardrailsQualityGateDirectExec {
        normalized_argv: Vec<String>,
        resolved_executable: Option<String>,
        executable_sha256: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EvidenceProvenance {
    pub trust: EvidenceTrust,
    pub source: EvidenceSource,
    pub run: Option<RunBinding>,
    pub tool_call: Option<ToolCallBinding>,
    pub artifact: Option<ArtifactBinding>,
    pub verification_method: Option<VerificationMethod>,
}

impl EvidenceProvenance {
    fn for_run(
        run: &crate::tools::ToolRunContext,
        trust: EvidenceTrust,
        source: EvidenceSource,
    ) -> Self {
        Self::for_binding(RunBinding::from_run(run), trust, source)
    }

    const fn for_binding(run: RunBinding, trust: EvidenceTrust, source: EvidenceSource) -> Self {
        Self {
            trust,
            source,
            run: Some(run),
            tool_call: None,
            artifact: None,
            verification_method: None,
        }
    }

    fn legacy_unbound(authority: LegacyAuthority) -> Self {
        Self::legacy_unbound_label(authority.as_str())
    }

    fn legacy_unbound_label(claimed_authority: &str) -> Self {
        Self {
            trust: EvidenceTrust::LegacyUnbound,
            source: EvidenceSource::Legacy {
                claimed_authority: claimed_authority.to_string(),
            },
            run: None,
            tool_call: None,
            artifact: None,
            verification_method: None,
        }
    }

    #[must_use]
    pub fn is_bound_to(&self, run: &crate::tools::ToolRunContext) -> bool {
        self.run
            .as_ref()
            .is_some_and(|binding| binding.matches(run))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LegacyAuthority {
    User,
    Tool,
    Filesystem,
    Command,
    Git,
    Policy,
    Verifier,
    ModelSummary,
}

impl LegacyAuthority {
    const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Tool => "tool",
            Self::Filesystem => "filesystem",
            Self::Command => "command",
            Self::Git => "git",
            Self::Policy => "policy",
            Self::Verifier => "verifier",
            Self::ModelSummary => "model_summary",
        }
    }
}

#[derive(Deserialize)]
struct ObservationWire {
    id: ObsId,
    ts: DateTime<Utc>,
    kind: ObservationKind,
    #[serde(default)]
    provenance: Option<EvidenceProvenance>,
    #[serde(default)]
    authority: Option<LegacyAuthority>,
}

impl<'de> Deserialize<'de> for Observation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ObservationWire::deserialize(deserializer)?;
        let provenance = match (wire.provenance, wire.authority) {
            (Some(provenance), _) => provenance,
            (None, Some(authority)) => EvidenceProvenance::legacy_unbound(authority),
            (None, None) => {
                return Err(serde::de::Error::missing_field(
                    "provenance (or legacy authority)",
                ))
            }
        };
        Ok(Self {
            id: wire.id,
            ts: wire.ts,
            kind: wire.kind,
            provenance,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ObservationKind {
    UserTask {
        content: String,
    },
    FileRead {
        path: String,
        sha256: String,
        start_line: usize,
        end_line: usize,
        excerpt: String,
    },
    CommandRun {
        cwd: String,
        argv: Vec<String>,
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    DiffObserved {
        files: Vec<String>,
        patch: String,
    },
    ToolResult {
        tool: String,
        result: serde_json::Value,
    },
    PolicyDecision {
        allowed: bool,
        reason: String,
    },
    Verification {
        passed: bool,
        command: Option<String>,
        findings: Vec<String>,
    },
    Summary {
        text: String,
        source_obs: Vec<ObsId>,
    },
}

impl ObservationKind {
    #[must_use]
    pub fn compact_label(&self) -> String {
        match self {
            Self::UserTask { content } => format!("user_task {}", first_line(content)),
            Self::FileRead {
                path,
                sha256,
                start_line,
                end_line,
                ..
            } => {
                format!("file {path} sha256={sha256} lines {start_line}-{end_line}")
            }
            Self::CommandRun {
                argv, exit_code, ..
            } => {
                format!("command {argv:?} exit={exit_code}")
            }
            Self::DiffObserved { files, patch } => {
                format!("diff {} files {} bytes", files.len(), patch.len())
            }
            Self::ToolResult { tool, .. } => format!("tool_result {tool}"),
            Self::PolicyDecision { allowed, reason } => {
                format!("policy allowed={allowed} {}", first_line(reason))
            }
            Self::Verification {
                passed,
                command,
                findings,
            } => {
                let command = command.as_deref().unwrap_or("<none>");
                format!(
                    "verification passed={passed} command={command} findings={}",
                    findings.len()
                )
            }
            Self::Summary { text, source_obs } => {
                format!("summary sources={} {}", source_obs.len(), first_line(text))
            }
        }
    }

    #[must_use]
    pub fn touched_files(&self) -> Vec<&str> {
        match self {
            Self::FileRead { path, .. } => vec![path.as_str()],
            Self::DiffObserved { files, .. } => files.iter().map(String::as_str).collect(),
            _ => Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationIndexEntry {
    pub id: ObsId,
    pub ts: DateTime<Utc>,
    pub trust: EvidenceTrust,
    pub source: EvidenceSource,
    pub stale: bool,
    pub label: String,
}

#[derive(Debug, Clone)]
struct ObservationRecord {
    observation: Observation,
    stale: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IssuedReceiptState {
    observation_sha256: [u8; 32],
    stale: bool,
}

#[derive(Default)]
struct IssuedReceiptRegistry {
    states: HashMap<ObsId, IssuedReceiptState>,
    issuance_order: VecDeque<ObsId>,
}

impl IssuedReceiptRegistry {
    fn insert(&mut self, id: ObsId, state: IssuedReceiptState) {
        if !self.states.contains_key(&id) {
            while self.states.len() >= MAX_RUNTIME_ISSUED_RECEIPTS {
                let Some(evicted) = self.issuance_order.pop_front() else {
                    break;
                };
                self.states.remove(&evicted);
            }
            self.issuance_order.push_back(id);
        }
        self.states.insert(id, state);
    }

    fn mark_stale(&mut self, id: ObsId) {
        if let Some(state) = self.states.get_mut(&id) {
            state.stale = true;
        }
    }
}

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("sqlite ledger operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("ledger observation serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("duplicate observation id {0}")]
    DuplicateObservation(ObsId),
    #[error("invalid ledger session key {session_key:?}: {reason}")]
    InvalidSessionKey {
        session_key: String,
        reason: &'static str,
    },
    #[error("session ledger not found at {path}")]
    MissingSessionLedger { path: PathBuf },
    #[error("failed to create ledger directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid evidence provenance: {0}")]
    InvalidEvidenceProvenance(String),
}

#[must_use = "dropping the guard restores the previous active ledger"]
pub struct ActiveRealityLedgerGuard {
    session_key: String,
    previous: Option<SharedRealityLedger>,
}

impl Drop for ActiveRealityLedgerGuard {
    fn drop(&mut self) {
        let mut ledgers = active_ledgers_guard("drop_active_ledger_guard");
        if let Some(previous) = self.previous.take() {
            ledgers.insert(self.session_key.clone(), previous);
        } else {
            ledgers.remove(&self.session_key);
        }
    }
}

pub struct RealityLedger {
    records: HashMap<ObsId, ObservationRecord>,
    conn: Option<Connection>,
}

impl Default for RealityLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl RealityLedger {
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            conn: None,
        }
    }

    /// Open a `SQLite`-backed ledger and load existing observations into memory.
    ///
    /// The full observation JSON is retained in `SQLite`. Compact prompt packets
    /// should pass indexes or selected hydrated observations to the model, but
    /// compaction must not delete rows from this table.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot be opened, schema initialization
    /// fails, or any existing observation row cannot be deserialized.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let conn = Connection::open(path)?;
        initialize_schema(&conn)?;
        let records = load_records(&conn)?;

        Ok(Self {
            records,
            conn: Some(conn),
        })
    }

    /// Open an existing `SQLite` ledger without creating or migrating it.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be opened read-only, the expected
    /// schema is absent, or any observation row cannot be deserialized.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let records = load_records(&conn)?;
        Ok(Self {
            records,
            conn: Some(conn),
        })
    }

    /// Open the project-local `SQLite` ledger for a session.
    ///
    /// Session keys are constrained to ASCII alphanumeric plus `-`, matching
    /// session/audit filename rules, so the key can safely become a filename.
    ///
    /// # Errors
    ///
    /// Returns an error when the session key is not filename-safe, the ledger
    /// directory cannot be created, or `SQLite` cannot be opened.
    pub fn open_project_session(session_key: &str) -> Result<Self, LedgerError> {
        let path = project_session_ledger_path(session_key)?;
        if let Some(parent) = path.parent() {
            if let Err(source) = std::fs::create_dir_all(parent) {
                // The project directory can be read-only (an external
                // supervisor can mount the workspace read-only for a
                // sandboxed agent). The reality ledger must not block the
                // session in that case: fall back to the per-user data
                // directory, keyed the same way, and only fail when
                // neither location is writable.
                let Some(fallback_dir) = dirs::data_local_dir()
                    .map(|data_dir| data_dir.join("openclaudia").join("reality-ledgers"))
                else {
                    return Err(LedgerError::CreateDir {
                        path: parent.to_path_buf(),
                        source,
                    });
                };
                let project_error = LedgerError::CreateDir {
                    path: parent.to_path_buf(),
                    source,
                };
                if std::fs::create_dir_all(&fallback_dir).is_err() {
                    return Err(project_error);
                }
                let file_name = path.file_name().ok_or(project_error)?.to_os_string();
                return Self::open(fallback_dir.join(file_name));
            }
        }
        Self::open(path)
    }

    /// Open an existing project-local session ledger in read-only mode.
    ///
    /// # Errors
    ///
    /// Returns an error when the session key is invalid, the ledger file is
    /// absent, or the existing database cannot be opened/read.
    pub fn open_existing_project_session(session_key: &str) -> Result<Self, LedgerError> {
        let path = project_session_ledger_path(session_key)?;
        if path.is_file() {
            return Self::open_read_only(path);
        }
        // Mirror open_project_session's read-only-workspace fallback: a
        // ledger created under the per-user data directory must stay
        // readable through the same key.
        if let Some(file_name) = path.file_name() {
            if let Some(fallback) = dirs::data_local_dir().map(|data_dir| {
                data_dir
                    .join("openclaudia")
                    .join("reality-ledgers")
                    .join(file_name)
            }) {
                if fallback.is_file() {
                    return Self::open_read_only(fallback);
                }
            }
        }
        Err(LedgerError::MissingSessionLedger { path })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    #[must_use]
    pub fn get(&self, id: ObsId) -> Option<&Observation> {
        self.records.get(&id).map(|record| &record.observation)
    }

    #[must_use]
    pub fn is_stale(&self, id: ObsId) -> bool {
        self.records.get(&id).is_some_and(|record| record.stale)
    }

    /// Return all observations in chronological order.
    ///
    /// This hydrates the in-memory cache, not the `SQLite` connection directly.
    /// Callers that need compact prompt context should prefer
    /// [`Self::observation_index`]; this method is for policy/packet builders
    /// that need to inspect typed observation variants.
    #[must_use]
    pub fn observations_chronological(&self) -> Vec<&Observation> {
        let mut observations = self
            .records
            .values()
            .map(|record| &record.observation)
            .collect::<Vec<_>>();
        observations.sort_by_key(|observation| observation.ts);
        observations
    }

    fn append_observation(&mut self, observation: Observation) -> Result<ObsId, LedgerError> {
        let id = observation.id;
        if self.records.contains_key(&id) {
            return Err(LedgerError::DuplicateObservation(id));
        }
        let record = ObservationRecord {
            observation,
            stale: false,
        };
        self.persist_record(&record)?;
        register_runtime_issued(&record)?;
        self.records.insert(id, record);
        Ok(id)
    }

    fn append(
        &mut self,
        provenance: EvidenceProvenance,
        kind: ObservationKind,
    ) -> Result<ObsId, LedgerError> {
        self.append_observation(Observation::new(provenance, kind))
    }

    /// Record the user's task as the root task specification evidence.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    pub fn observe_user_task(
        &mut self,
        run: &crate::tools::ToolRunContext,
        content: impl Into<String>,
    ) -> Result<ObsId, LedgerError> {
        self.append(
            EvidenceProvenance::for_run(run, EvidenceTrust::UserInput, EvidenceSource::UserInput),
            ObservationKind::UserTask {
                content: content.into(),
            },
        )
    }

    /// Record a file read. `sha256` is computed over `full_contents`, while
    /// `excerpt` is the slice that was actually shown to the model.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    pub fn observe_file_read(
        &mut self,
        run: &crate::tools::ToolRunContext,
        path: impl Into<String>,
        full_contents: &str,
        start_line: usize,
        end_line: usize,
        excerpt: impl Into<String>,
    ) -> Result<ObsId, LedgerError> {
        self.observe_file_read_bytes(
            run,
            path,
            full_contents.as_bytes(),
            start_line,
            end_line,
            excerpt,
        )
    }

    /// Record a file read using raw bytes for the content hash.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    pub fn observe_file_read_bytes(
        &mut self,
        run: &crate::tools::ToolRunContext,
        path: impl Into<String>,
        full_contents: &[u8],
        start_line: usize,
        end_line: usize,
        excerpt: impl Into<String>,
    ) -> Result<ObsId, LedgerError> {
        let path = path.into();
        let sha256 = sha256_hex(full_contents);
        let mut provenance = EvidenceProvenance::for_run(
            run,
            EvidenceTrust::RuntimeObserved,
            EvidenceSource::FilesystemRead,
        );
        provenance.artifact = Some(ArtifactBinding::File {
            path: path.clone(),
            sha256: sha256.clone(),
        });
        self.append(
            provenance,
            ObservationKind::FileRead {
                path,
                sha256,
                start_line,
                end_line,
                excerpt: excerpt.into(),
            },
        )
    }

    /// Record a command result.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    pub fn observe_command_run(
        &mut self,
        run: &crate::tools::ToolRunContext,
        cwd: impl Into<String>,
        argv: Vec<String>,
        exit_code: i32,
        stdout: impl Into<String>,
        stderr: impl Into<String>,
    ) -> Result<ObsId, LedgerError> {
        self.observe_command_run_for_binding(
            RunBinding::from_run(run),
            cwd,
            argv,
            exit_code,
            stdout,
            stderr,
        )
    }

    pub(crate) fn observe_command_run_for_binding(
        &mut self,
        run: RunBinding,
        cwd: impl Into<String>,
        argv: Vec<String>,
        exit_code: i32,
        stdout: impl Into<String>,
        stderr: impl Into<String>,
    ) -> Result<ObsId, LedgerError> {
        let cwd = cwd.into();
        let mut provenance = EvidenceProvenance::for_binding(
            run,
            EvidenceTrust::RuntimeObserved,
            EvidenceSource::CommandExecution,
        );
        provenance.artifact = Some(ArtifactBinding::Command {
            cwd: cwd.clone(),
            argv_sha256: sha256_hex(
                &serde_json::to_vec(&argv).expect("command argv serialization cannot fail"),
            ),
        });
        self.append(
            provenance,
            ObservationKind::CommandRun {
                cwd,
                argv,
                exit_code,
                stdout: stdout.into(),
                stderr: stderr.into(),
            },
        )
    }

    /// Record a tool result envelope.
    ///
    /// Tool-specific observers such as file reads and command runs remain the
    /// typed source for detailed filesystem/command facts. This
    /// generic observation records that a model-visible tool result was
    /// produced, including bounded result metadata for later grounding.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    pub fn observe_tool_result(
        &mut self,
        run: &crate::tools::ToolRunContext,
        tool_result: &crate::tools::ToolResult,
        result_payload: serde_json::Value,
    ) -> Result<ObsId, LedgerError> {
        let invocation = tool_result.invocation();
        let tool = invocation.handler.clone();
        let mut provenance = EvidenceProvenance::for_run(
            run,
            EvidenceTrust::UntrustedContent,
            EvidenceSource::ToolResult,
        );
        provenance.tool_call = Some(ToolCallBinding {
            call_id: invocation.call_id.clone(),
            handler: invocation.handler.clone(),
            arguments_sha256: sha256_hex(invocation.raw_arguments.as_bytes()),
        });
        self.append(
            provenance,
            ObservationKind::ToolResult {
                tool,
                result: result_payload,
            },
        )
    }

    pub(crate) fn observe_policy_decision(
        &mut self,
        run: &crate::tools::ToolRunContext,
        policy: impl Into<String>,
        allowed: bool,
        reason: impl Into<String>,
    ) -> Result<ObsId, LedgerError> {
        self.append(
            EvidenceProvenance::for_run(
                run,
                EvidenceTrust::HostPolicy,
                EvidenceSource::HostPolicy {
                    policy: policy.into(),
                },
            ),
            ObservationKind::PolicyDecision {
                allowed,
                reason: reason.into(),
            },
        )
    }

    pub(crate) fn observe_model_summary(
        &mut self,
        run: &crate::tools::ToolRunContext,
        text: impl Into<String>,
        source_obs: Vec<ObsId>,
    ) -> Result<ObsId, LedgerError> {
        self.append(
            EvidenceProvenance::for_run(
                run,
                EvidenceTrust::DerivedSummary,
                EvidenceSource::ModelSummary,
            ),
            ObservationKind::Summary {
                text: text.into(),
                source_obs,
            },
        )
    }

    pub(crate) fn observe_quality_gate(
        &mut self,
        run: &crate::tools::ToolRunContext,
        gate: &crate::guardrails::QualityCheckResult,
        findings: Vec<String>,
    ) -> Result<ObsId, LedgerError> {
        Self::validate_quality_gate_result(run, gate)?;
        let proof = gate.evidence();

        let mut provenance = EvidenceProvenance::for_run(
            run,
            EvidenceTrust::TrustedVerifier,
            EvidenceSource::QualityGate {
                check: gate.name().to_string(),
            },
        );
        provenance.artifact = proof
            .resolved_executable
            .as_ref()
            .zip(proof.executable_sha256.as_ref())
            .map(|(path, sha256)| ArtifactBinding::Executable {
                path: path.clone(),
                sha256: sha256.clone(),
            });
        provenance.verification_method =
            Some(VerificationMethod::GuardrailsQualityGateDirectExec {
                normalized_argv: proof.normalized_argv.clone(),
                resolved_executable: proof.resolved_executable.clone(),
                executable_sha256: proof.executable_sha256.clone(),
            });
        self.append(
            provenance,
            ObservationKind::Verification {
                passed: gate.passed(),
                command: Some(gate.command().to_string()),
                findings,
            },
        )
    }

    pub(crate) fn validate_quality_gate_result(
        run: &crate::tools::ToolRunContext,
        gate: &crate::guardrails::QualityCheckResult,
    ) -> Result<(), LedgerError> {
        let proof = gate.evidence();
        if proof.run_id != run.run_id() || proof.capability_generation != run.generation() {
            return Err(LedgerError::InvalidEvidenceProvenance(
                "quality-gate result belongs to a different run generation".to_string(),
            ));
        }
        let normalized = shlex::split(gate.command())
            .filter(|argv| !argv.is_empty())
            .unwrap_or_default();
        if normalized != proof.normalized_argv {
            return Err(LedgerError::InvalidEvidenceProvenance(
                "quality-gate command does not match its runner-minted argv".to_string(),
            ));
        }
        if gate.passed() != (gate.exit_code() == 0) {
            return Err(LedgerError::InvalidEvidenceProvenance(
                "quality-gate pass state does not match its exit code".to_string(),
            ));
        }
        if gate.passed()
            && (proof.resolved_executable.is_none() || proof.executable_sha256.is_none())
        {
            return Err(LedgerError::InvalidEvidenceProvenance(
                "passing quality gate lacks a resolved executable artifact".to_string(),
            ));
        }

        Ok(())
    }

    /// Record a diff and stale prior file reads for every touched path.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    pub fn observe_diff(
        &mut self,
        run: &crate::tools::ToolRunContext,
        files: Vec<String>,
        patch: impl Into<String>,
    ) -> Result<ObsId, LedgerError> {
        let patch = patch.into();
        let mut provenance = EvidenceProvenance::for_run(
            run,
            EvidenceTrust::RuntimeObserved,
            EvidenceSource::WorkspaceDiff,
        );
        provenance.artifact = Some(ArtifactBinding::Diff {
            files: files.clone(),
            patch_sha256: sha256_hex(patch.as_bytes()),
        });
        let observation =
            Observation::new(provenance, ObservationKind::DiffObserved { files, patch });
        let id = observation.id;
        if self.records.contains_key(&id) {
            return Err(LedgerError::DuplicateObservation(id));
        }

        let touched = observation.kind.touched_files();
        let stale_ids = self
            .records
            .iter()
            .filter_map(|(existing_id, record)| match &record.observation.kind {
                ObservationKind::FileRead { path, .. }
                    if !record.stale
                        && touched
                            .iter()
                            .any(|touched| ledger_paths_match(path, touched)) =>
                {
                    Some(*existing_id)
                }
                ObservationKind::DiffObserved { files, .. }
                    if !record.stale
                        && files.iter().any(|path| {
                            touched
                                .iter()
                                .any(|touched| ledger_paths_match(path, touched))
                        }) =>
                {
                    Some(*existing_id)
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        let record = ObservationRecord {
            observation,
            stale: false,
        };

        if let Some(conn) = self.conn.as_mut() {
            let tx = conn.transaction()?;
            insert_record(&tx, &record)?;
            for stale_id in &stale_ids {
                tx.execute(
                    "UPDATE reality_observations SET stale = 1 WHERE id = ?1",
                    params![stale_id.to_string()],
                )?;
            }
            tx.commit()?;
        }

        register_runtime_issued(&record)?;
        mark_runtime_receipts_stale(&stale_ids);
        self.records.insert(id, record);
        for stale_id in stale_ids {
            if let Some(record) = self.records.get_mut(&stale_id) {
                record.stale = true;
            }
        }
        Ok(id)
    }

    /// Mark file-read observations for `path` stale.
    ///
    /// This is the primitive write/edit paths should call after mutating a
    /// file. A stale read can still be inspected for history, but cannot be
    /// used as fresh evidence for a new decision.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` persistence fails.
    pub fn mark_file_observations_stale(&mut self, path: &str) -> Result<Vec<ObsId>, LedgerError> {
        let stale_ids = self
            .records
            .iter()
            .filter_map(|(id, record)| match &record.observation.kind {
                ObservationKind::FileRead {
                    path: observed_path,
                    ..
                } if ledger_paths_match(observed_path, path) && !record.stale => Some(*id),
                _ => None,
            })
            .collect::<Vec<_>>();

        if let Some(conn) = self.conn.as_mut() {
            let tx = conn.transaction()?;
            for id in &stale_ids {
                tx.execute(
                    "UPDATE reality_observations SET stale = 1 WHERE id = ?1",
                    params![id.to_string()],
                )?;
            }
            tx.commit()?;
        }

        mark_runtime_receipts_stale(&stale_ids);
        for id in &stale_ids {
            if let Some(record) = self.records.get_mut(id) {
                record.stale = true;
            }
        }
        Ok(stale_ids)
    }

    /// Return a compact, chronological observation index for prompt packets.
    #[must_use]
    pub fn observation_index(&self, limit: usize) -> Vec<ObservationIndexEntry> {
        let mut records = self.records.values().collect::<Vec<_>>();
        records.sort_by_key(|record| record.observation.ts);
        if limit > 0 && records.len() > limit {
            records.drain(0..records.len() - limit);
        }
        records
            .into_iter()
            .map(|record| ObservationIndexEntry {
                id: record.observation.id,
                ts: record.observation.ts,
                trust: record.observation.provenance.trust,
                source: record.observation.provenance.source.clone(),
                stale: record.stale,
                label: record.observation.kind.compact_label(),
            })
            .collect()
    }

    fn persist_record(&self, record: &ObservationRecord) -> Result<(), LedgerError> {
        if let Some(conn) = self.conn.as_ref() {
            insert_record(conn, record)?;
        }
        Ok(())
    }
}

pub fn install_active_ledger_for_session(
    session_key: impl Into<String>,
    ledger: SharedRealityLedger,
) -> ActiveRealityLedgerGuard {
    let session_key = session_key.into();
    let previous =
        active_ledgers_guard("install_active_ledger").insert(session_key.clone(), ledger);
    ActiveRealityLedgerGuard {
        session_key,
        previous,
    }
}

#[must_use]
pub fn active_ledger_for_session(session_key: &str) -> Option<SharedRealityLedger> {
    active_ledgers_guard("active_ledger_for_session")
        .get(session_key)
        .cloned()
}

/// Return the project-local ledger path for a session key.
///
/// # Errors
///
/// Returns [`LedgerError::InvalidSessionKey`] when the key is not safe for use
/// as a ledger filename.
pub fn project_session_ledger_path(session_key: &str) -> Result<PathBuf, LedgerError> {
    validate_session_key(session_key).map_err(|reason| LedgerError::InvalidSessionKey {
        session_key: session_key.to_string(),
        reason,
    })?;
    Ok(Path::new(SESSION_LEDGER_DIR).join(format!("{session_key}.sqlite3")))
}

fn initialize_schema(conn: &Connection) -> Result<(), LedgerError> {
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS reality_observations (
            id TEXT PRIMARY KEY NOT NULL,
            ts TEXT NOT NULL,
            authority TEXT NOT NULL,
            stale INTEGER NOT NULL DEFAULT 0 CHECK (stale IN (0, 1)),
            observation_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_reality_observations_ts
            ON reality_observations(ts);
        CREATE INDEX IF NOT EXISTS idx_reality_observations_authority
            ON reality_observations(authority);",
    )?;
    Ok(())
}

fn load_records(conn: &Connection) -> Result<HashMap<ObsId, ObservationRecord>, LedgerError> {
    let mut stmt =
        conn.prepare("SELECT observation_json, stale FROM reality_observations ORDER BY ts ASC")?;
    let mut rows = stmt.query([])?;
    let mut records = HashMap::new();
    while let Some(row) = rows.next()? {
        let json: String = row.get(0)?;
        let stale: i64 = row.get(1)?;
        let mut observation: Observation = serde_json::from_str(&json)?;
        let record = ObservationRecord {
            observation: observation.clone(),
            stale: stale != 0,
        };
        if !was_issued_by_this_runtime(&record)?
            && observation.provenance.trust != EvidenceTrust::LegacyUnbound
        {
            observation.provenance.trust = EvidenceTrust::UnverifiedPersisted;
        }
        records.insert(
            observation.id,
            ObservationRecord {
                observation,
                stale: stale != 0,
            },
        );
    }
    Ok(records)
}

fn register_runtime_issued(record: &ObservationRecord) -> Result<(), LedgerError> {
    let state = IssuedReceiptState {
        observation_sha256: observation_digest(&record.observation)?,
        stale: record.stale,
    };
    issued_receipts_guard("register_runtime_issued").insert(record.observation.id, state);
    Ok(())
}

fn was_issued_by_this_runtime(record: &ObservationRecord) -> Result<bool, LedgerError> {
    let state = IssuedReceiptState {
        observation_sha256: observation_digest(&record.observation)?,
        stale: record.stale,
    };
    Ok(issued_receipts_guard("validate_runtime_issued")
        .states
        .get(&record.observation.id)
        .is_some_and(|issued| *issued == state))
}

fn mark_runtime_receipts_stale(ids: &[ObsId]) {
    let mut issued = issued_receipts_guard("mark_runtime_receipts_stale");
    for id in ids {
        issued.mark_stale(*id);
    }
}

fn observation_digest(observation: &Observation) -> Result<[u8; 32], LedgerError> {
    let bytes = serde_json::to_vec(observation)?;
    Ok(Sha256::digest(bytes).into())
}

fn insert_record(conn: &Connection, record: &ObservationRecord) -> Result<(), LedgerError> {
    let observation = &record.observation;
    let json = serde_json::to_string(observation)?;
    conn.execute(
        "INSERT INTO reality_observations (id, ts, authority, stale, observation_json)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            observation.id.to_string(),
            observation.ts.to_rfc3339(),
            format!("{:?}", observation.provenance.trust),
            i64::from(record.stale),
            json
        ],
    )?;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn first_line(text: &str) -> String {
    const MAX: usize = 120;
    let line = text.lines().next().unwrap_or_default();
    if line.chars().count() <= MAX {
        return line.to_string();
    }
    format!("{}...", line.chars().take(MAX).collect::<String>())
}

fn ledger_paths_match(observed: &str, touched: &str) -> bool {
    let observed = observed.trim_start_matches("./");
    let touched = touched.trim_start_matches("./");
    observed == touched
        || observed.ends_with(&format!("/{touched}"))
        || touched.ends_with(&format!("/{observed}"))
}

fn validate_session_key(key: &str) -> Result<(), &'static str> {
    if key.is_empty() {
        return Err("session key must not be empty");
    }
    if key.len() > 128 {
        return Err("session key must be 128 bytes or fewer");
    }
    if key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        Ok(())
    } else {
        Err("session key must contain only ASCII letters, numbers, or '-'")
    }
}

fn active_ledgers_guard(
    operation: &'static str,
) -> MutexGuard<'static, HashMap<String, SharedRealityLedger>> {
    ACTIVE_REALITY_LEDGERS.lock().unwrap_or_else(|err| {
        tracing::error!(
            operation,
            "active reality ledger registry lock poisoned; recovering inner state"
        );
        err.into_inner()
    })
}

fn issued_receipts_guard(operation: &'static str) -> MutexGuard<'static, IssuedReceiptRegistry> {
    RUNTIME_ISSUED_RECEIPTS.lock().unwrap_or_else(|err| {
        tracing::error!(
            operation,
            "runtime-issued receipt registry lock poisoned; recovering inner state"
        );
        err.into_inner()
    })
}
