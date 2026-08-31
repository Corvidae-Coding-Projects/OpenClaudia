//! Immutable bindings carried by every canonical run.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::state::SessionId;

use super::ids::{
    ActorId, BudgetGeneration, BudgetId, CancellationId, CapabilityGeneration,
    ContinuationGeneration, RunId, StateGeneration, WorkspaceGeneration, WorkspaceHandleId,
};

/// SHA-256 digest used to bind mutable resources to an exact generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentDigest([u8; 32]);

impl ContentDigest {
    /// Digest arbitrary bytes.
    #[must_use]
    pub fn sha256(bytes: impl AsRef<[u8]>) -> Self {
        Self(Sha256::digest(bytes.as_ref()).into())
    }

    /// Construct a digest from the output of an already-streaming SHA-256
    /// computation without hashing the digest a second time.
    #[must_use]
    pub const fn from_sha256_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sha256:")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for ContentDigest {
    type Err = DigestParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let hexadecimal = value
            .strip_prefix("sha256:")
            .ok_or(DigestParseError::MissingPrefix)?;
        if hexadecimal.len() != 64 {
            return Err(DigestParseError::InvalidLength(hexadecimal.len()));
        }

        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            *byte = u8::from_str_radix(&hexadecimal[offset..offset + 2], 16)
                .map_err(|_| DigestParseError::InvalidHex)?;
        }
        Ok(Self(bytes))
    }
}

impl Serialize for ContentDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ContentDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

/// Failure to parse a generation-binding digest.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DigestParseError {
    #[error("digest must start with sha256:")]
    MissingPrefix,
    #[error("SHA-256 digest must contain 64 hexadecimal characters, got {0}")]
    InvalidLength(usize),
    #[error("SHA-256 digest contains a non-hexadecimal character")]
    InvalidHex,
}

/// Runtime role of an actor. Role is data, never a prompt marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorRole {
    Frontend,
    Runtime,
    Planner,
    Worker,
    Verifier,
    Provider,
    Tool,
    Hook,
    Persistence,
}

/// Stable actor identity and its declared runtime role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub id: ActorId,
    pub role: ActorRole,
}

/// Explicit workspace snapshot. No runtime API consults the process CWD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceBinding {
    root: PathBuf,
    pub generation: WorkspaceGeneration,
    pub digest: ContentDigest,
}

impl WorkspaceBinding {
    /// Bind an absolute, lexically normalized workspace root.
    ///
    /// Use [`Self::from_existing_root`] when accepting a path from outside the
    /// host composition root; it resolves symlinks before constructing this
    /// binding.
    ///
    /// # Errors
    ///
    /// Returns an error for relative paths or paths containing `.` or `..`.
    pub fn new(
        root: PathBuf,
        generation: WorkspaceGeneration,
        digest: ContentDigest,
    ) -> Result<Self, RunContextError> {
        validate_workspace_root(&root)?;
        Ok(Self {
            root,
            generation,
            digest,
        })
    }

    /// Canonicalize and bind an existing workspace directory.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the path cannot be resolved, an error when it
    /// is not a directory, or a lexical validation error for the resolved path.
    pub fn from_existing_root(
        root: impl AsRef<Path>,
        generation: WorkspaceGeneration,
        digest: ContentDigest,
    ) -> Result<Self, RunContextError> {
        let canonical = std::fs::canonicalize(root).map_err(RunContextError::WorkspaceIo)?;
        if !canonical.is_dir() {
            return Err(RunContextError::WorkspaceNotDirectory(canonical));
        }
        Self::new(canonical, generation, digest)
    }

    /// Return the canonical workspace root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn validate(&self) -> Result<(), RunContextError> {
        validate_workspace_root(&self.root)
    }
}

/// Durable identity of one isolated Git workspace.
///
/// The model receives only [`Self::handle_id`] and [`Self::generation`]. The
/// remaining fields are host-validated resume data: they are never accepted as
/// authority merely because they deserialize successfully.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolatedWorkspaceDescriptor {
    schema_version: u16,
    handle_id: WorkspaceHandleId,
    repository_id: ContentDigest,
    worktree_id: ContentDigest,
    repository_root_id: crate::persistence::StorageRootId,
    workspace_root_id: crate::persistence::StorageRootId,
    repository_root: PathBuf,
    workspace_root: PathBuf,
    base_commit: String,
    target_commit: String,
    branch: String,
    owner_session: SessionId,
    owner_label: String,
    owner_run: RunId,
    owner_actor: ActorId,
    generation: WorkspaceGeneration,
}

impl IsolatedWorkspaceDescriptor {
    pub const SCHEMA_VERSION: u16 = 1;

    /// Construct a validated isolated-workspace identity.
    ///
    /// # Errors
    ///
    /// Returns an error when roots, Git identities, branch, or owner data are
    /// malformed. Filesystem and repository identity are revalidated again
    /// when a run acquires or resumes this descriptor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        handle_id: WorkspaceHandleId,
        repository_id: ContentDigest,
        worktree_id: ContentDigest,
        repository_root_id: crate::persistence::StorageRootId,
        workspace_root_id: crate::persistence::StorageRootId,
        repository_root: PathBuf,
        workspace_root: PathBuf,
        base_commit: String,
        target_commit: String,
        branch: String,
        owner_session: SessionId,
        owner_label: String,
        owner_run: RunId,
        owner_actor: ActorId,
        generation: WorkspaceGeneration,
    ) -> Result<Self, RunContextError> {
        let descriptor = Self {
            schema_version: Self::SCHEMA_VERSION,
            handle_id,
            repository_id,
            worktree_id,
            repository_root_id,
            workspace_root_id,
            repository_root,
            workspace_root,
            base_commit,
            target_commit,
            branch,
            owner_session,
            owner_label,
            owner_run,
            owner_actor,
            generation,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Revalidate persisted descriptor structure before repository inspection.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported schema, unsafe roots, malformed Git
    /// object names, or malformed owner/branch values.
    pub fn validate(&self) -> Result<(), RunContextError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(RunContextError::InvalidWorkspaceDescriptor(
                "unsupported isolated-workspace schema".to_string(),
            ));
        }
        validate_workspace_root(&self.repository_root)?;
        validate_workspace_root(&self.workspace_root)?;
        if self.repository_root == self.workspace_root
            || !self.workspace_root.starts_with(&self.repository_root)
        {
            return Err(RunContextError::InvalidWorkspaceDescriptor(
                "isolated root must be a distinct descendant of its repository root".to_string(),
            ));
        }
        for (label, commit) in [
            ("base commit", self.base_commit.as_str()),
            ("target commit", self.target_commit.as_str()),
        ] {
            if !(40..=64).contains(&commit.len())
                || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(RunContextError::InvalidWorkspaceDescriptor(format!(
                    "{label} is not a full Git object identity"
                )));
            }
        }
        if self.branch.is_empty()
            || self.branch.len() > 255
            || self.branch.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(RunContextError::InvalidWorkspaceDescriptor(
                "isolated-workspace branch is malformed".to_string(),
            ));
        }
        uuid::Uuid::parse_str(self.owner_session.as_str()).map_err(|_| {
            RunContextError::InvalidWorkspaceDescriptor(
                "isolated-workspace owner session is not a UUID".to_string(),
            )
        })?;
        if self.owner_label.is_empty()
            || self.owner_label.len() > 128
            || !self
                .owner_label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(RunContextError::InvalidWorkspaceDescriptor(
                "isolated-workspace owner label is malformed".to_string(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub const fn handle_id(&self) -> WorkspaceHandleId {
        self.handle_id
    }

    #[must_use]
    pub const fn repository_id(&self) -> ContentDigest {
        self.repository_id
    }

    #[must_use]
    pub const fn worktree_id(&self) -> ContentDigest {
        self.worktree_id
    }

    #[must_use]
    pub const fn repository_root_id(&self) -> crate::persistence::StorageRootId {
        self.repository_root_id
    }

    #[must_use]
    pub const fn workspace_root_id(&self) -> crate::persistence::StorageRootId {
        self.workspace_root_id
    }

    #[must_use]
    pub fn repository_root(&self) -> &Path {
        &self.repository_root
    }

    #[must_use]
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    #[must_use]
    pub fn base_commit(&self) -> &str {
        &self.base_commit
    }

    #[must_use]
    pub fn target_commit(&self) -> &str {
        &self.target_commit
    }

    #[must_use]
    pub fn branch(&self) -> &str {
        &self.branch
    }

    #[must_use]
    pub const fn owner_session(&self) -> &SessionId {
        &self.owner_session
    }

    #[must_use]
    pub fn owner_label(&self) -> &str {
        &self.owner_label
    }

    #[must_use]
    pub const fn owner_run(&self) -> RunId {
        self.owner_run
    }

    #[must_use]
    pub const fn owner_actor(&self) -> ActorId {
        self.owner_actor
    }

    #[must_use]
    pub const fn generation(&self) -> WorkspaceGeneration {
        self.generation
    }
}

fn validate_workspace_root(root: &Path) -> Result<(), RunContextError> {
    if !root.is_absolute() {
        return Err(RunContextError::WorkspaceNotAbsolute(root.to_path_buf()));
    }
    if root
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(RunContextError::WorkspaceNotNormalized(root.to_path_buf()));
    }
    Ok(())
}

/// Coarse capability classes bound to an immutable manifest generation.
///
/// S-019 will replace these manifest claims with concrete filesystem,
/// process, network, and secret handles. An empty set is an explicit deny-all
/// manifest rather than a missing security object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    ContextAssembly,
    Provider,
    WorkspaceRead,
    WorkspaceWrite,
    Process,
    Network,
    Secrets,
    Hooks,
    Memory,
    Mcp,
    Trace,
}

/// Exact capability manifest visible to this run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityBinding {
    pub generation: CapabilityGeneration,
    pub manifest_digest: ContentDigest,
    pub grants: BTreeSet<CapabilityKind>,
}

/// Concrete finite limits attached to a run.
///
/// This slice records the immutable budget contract. S-051 owns hierarchical
/// reservation, concurrency, reconciliation, and usage accounting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetLimits {
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Combined input plus output token spend.
    #[serde(default = "default_total_token_limit")]
    pub total_tokens: u64,
    pub turns: u64,
    pub provider_calls: u64,
    pub tool_calls: u64,
    pub elapsed_millis: u64,
    pub retries: u64,
    pub concurrent_calls: u64,
    pub child_runs: u64,
    pub cost_microusd: u64,
    pub trace_bytes: u64,
}

impl Default for BudgetLimits {
    fn default() -> Self {
        Self {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            total_tokens: default_total_token_limit(),
            turns: 1_000,
            provider_calls: 1_000,
            tool_calls: 10_000,
            elapsed_millis: 86_400_000,
            retries: 100,
            concurrent_calls: 64,
            child_runs: 64,
            cost_microusd: 1_000_000_000,
            trace_bytes: 64 * 1024 * 1024,
        }
    }
}

const fn default_total_token_limit() -> u64 {
    1_500_000
}

/// Budget identity, policy generation, and limits bound to a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunBudget {
    pub id: BudgetId,
    pub generation: BudgetGeneration,
    pub limits: BudgetLimits,
}

/// Validated provider identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProviderId(String);

impl ProviderId {
    /// Validate and construct a provider identifier.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, or non-identifier value.
    pub fn new(value: impl Into<String>) -> Result<Self, RunContextError> {
        let value = value.into();
        validate_provider_id(&value)?;
        Ok(Self(value))
    }

    /// Borrow the provider identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), RunContextError> {
        validate_provider_id(&self.0)
    }
}

fn validate_provider_id(value: &str) -> Result<(), RunContextError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(RunContextError::InvalidProviderId(value.to_string()));
    }
    Ok(())
}

/// Provider-owned continuation binding without flattening native state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderContinuation {
    Fresh {
        provider: ProviderId,
    },
    Resume {
        provider: ProviderId,
        generation: ContinuationGeneration,
        state_digest: ContentDigest,
    },
}

impl ProviderContinuation {
    fn validate(&self) -> Result<(), RunContextError> {
        match self {
            Self::Fresh { provider } | Self::Resume { provider, .. } => provider.validate(),
        }
    }
}

/// Exact committed state generation and digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateSnapshot {
    pub generation: StateGeneration,
    pub digest: ContentDigest,
}

/// Input parts for a [`RunDescriptor`]. A named struct keeps construction
/// legible and prevents positional confusion between security generations.
#[derive(Debug, Clone)]
pub struct RunDescriptorParts {
    pub run_id: RunId,
    pub session_id: SessionId,
    pub actor: Actor,
    pub workspace: WorkspaceBinding,
    pub capabilities: CapabilityBinding,
    pub budget: RunBudget,
    pub provider_continuation: ProviderContinuation,
    pub cancellation_root: CancellationId,
    pub initial_state: StateSnapshot,
}

/// Serializable, immutable identity and authority bindings for one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunDescriptor {
    pub run_id: RunId,
    pub session_id: SessionId,
    pub actor: Actor,
    pub workspace: WorkspaceBinding,
    pub capabilities: CapabilityBinding,
    pub budget: RunBudget,
    pub provider_continuation: ProviderContinuation,
    pub cancellation_root: CancellationId,
    pub initial_state: StateSnapshot,
}

impl RunDescriptor {
    /// Validate and construct an immutable run descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error when a persisted identifier or binding is invalid.
    pub fn new(parts: RunDescriptorParts) -> Result<Self, RunContextError> {
        let descriptor = Self {
            run_id: parts.run_id,
            session_id: parts.session_id,
            actor: parts.actor,
            workspace: parts.workspace,
            capabilities: parts.capabilities,
            budget: parts.budget,
            provider_continuation: parts.provider_continuation,
            cancellation_root: parts.cancellation_root,
            initial_state: parts.initial_state,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Revalidate a descriptor reconstructed from serialized events.
    ///
    /// # Errors
    ///
    /// Returns an error when persisted data violates a descriptor invariant.
    pub fn validate(&self) -> Result<(), RunContextError> {
        uuid::Uuid::parse_str(self.session_id.as_str())
            .map_err(|_| RunContextError::InvalidSessionId(self.session_id.to_string()))?;
        self.workspace.validate()?;
        self.provider_continuation.validate()
    }
}

/// Invalid immutable run binding.
#[derive(Debug, Error)]
pub enum RunContextError {
    #[error("workspace root must be absolute: {0}")]
    WorkspaceNotAbsolute(PathBuf),
    #[error("workspace root must be lexically normalized: {0}")]
    WorkspaceNotNormalized(PathBuf),
    #[error("workspace root is not a directory: {0}")]
    WorkspaceNotDirectory(PathBuf),
    #[error("could not resolve workspace root: {0}")]
    WorkspaceIo(std::io::Error),
    #[error("invalid isolated workspace descriptor: {0}")]
    InvalidWorkspaceDescriptor(String),
    #[error("session id is not a UUID: {0}")]
    InvalidSessionId(String),
    #[error("provider id must be 1-64 ASCII identifier characters: {0:?}")]
    InvalidProviderId(String),
    #[error("run descriptor cancellation root does not match the supplied tree")]
    CancellationRootMismatch,
}
