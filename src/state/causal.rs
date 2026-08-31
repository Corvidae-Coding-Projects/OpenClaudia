//! Causal identity and validation for resumable sessions and branch proposals.
//!
//! The host-owned session document is the authority. Project-owned branch
//! files are only proposals: a proposal becomes selectable after its exact
//! digest is recorded in the session's bounded branch-anchor ledger.

use std::collections::HashSet;
use std::fmt;
use std::ops::Deref;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::runtime::{
    CapabilityGeneration, ContentDigest, ContinuationGeneration, ProviderNativeState, RunId,
    WorkspaceGeneration,
};
use crate::tools::ToolRunContext;

use super::SessionId;

/// Schema emitted for causal session envelopes.
pub const SESSION_CAUSAL_SCHEMA_VERSION: u16 = 1;
/// Schema emitted for project-owned branch proposals.
pub const BRANCH_PROPOSAL_SCHEMA_VERSION: u16 = 1;
/// Maximum encoded size accepted for one branch proposal.
pub const MAX_BRANCH_PROPOSAL_BYTES: usize = 16 * 1_024 * 1_024;
/// Maximum number of conversation messages accepted in one branch proposal.
pub const MAX_BRANCH_MESSAGES: usize = 50_000;

const MAX_CAUSAL_EVENTS: usize = 256;
const MAX_BRANCH_ANCHORS: usize = 256;
const MAX_BRANCH_SELECTIONS: usize = 256;
const MAX_BRANCH_JSON_NODES: usize = 200_000;
const MAX_BRANCH_JSON_DEPTH: usize = 64;
const MAX_BRANCH_NAME_BYTES: usize = 128;
const MAX_PROVIDER_ID_BYTES: usize = 64;
const MAX_MODEL_ID_BYTES: usize = 256;

/// Immutable UUID identity shared by causal session and branch events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LogicalStateId(uuid::Uuid);

impl LogicalStateId {
    /// Create a fresh logical identity.
    #[must_use]
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    fn from_session_id(session_id: &SessionId) -> Result<Self, CausalStateError> {
        super::session::validate_session_id(session_id.as_str()).map_err(|detail| {
            CausalStateError::InvalidIdentity {
                detail: detail.to_string(),
            }
        })?;
        if let Ok(id) = uuid::Uuid::parse_str(session_id.as_str()) {
            return Ok(Self(id));
        }
        let digest = ContentDigest::sha256(
            [
                b"openclaudia.legacy-session-logical-id.v1:".as_slice(),
                session_id.as_str().as_bytes(),
            ]
            .concat(),
        );
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest.as_bytes()[..16]);
        Ok(Self(uuid::Uuid::from_bytes(bytes)))
    }
}

impl Default for LogicalStateId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for LogicalStateId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Exact immutable runtime bindings captured with a causal event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalRuntimeBinding {
    run_id: RunId,
    provider: String,
    model: String,
    provider_generation: Option<ContinuationGeneration>,
    provider_state_digest: Option<ContentDigest>,
    workspace_root: PathBuf,
    workspace_generation: WorkspaceGeneration,
    workspace_digest: ContentDigest,
    capability_generation: CapabilityGeneration,
    capability_digest: ContentDigest,
}

impl CausalRuntimeBinding {
    fn capture(
        run: &ToolRunContext,
        model: &str,
        provider_state: Option<&ProviderNativeState>,
    ) -> Result<Self, CausalStateError> {
        let descriptor = run.runtime().descriptor();
        let binding = Self {
            run_id: run.run_id(),
            provider: run.provider_id().to_ascii_lowercase(),
            model: model.to_string(),
            provider_generation: provider_state.map(ProviderNativeState::generation),
            provider_state_digest: provider_state.map(ProviderNativeState::digest),
            workspace_root: descriptor.workspace.root().to_path_buf(),
            workspace_generation: descriptor.workspace.generation,
            workspace_digest: descriptor.workspace.digest,
            capability_generation: descriptor.capabilities.generation,
            capability_digest: descriptor.capabilities.manifest_digest,
        };
        binding.validate(provider_state)?;
        Ok(binding)
    }

    fn validate(
        &self,
        provider_state: Option<&ProviderNativeState>,
    ) -> Result<(), CausalStateError> {
        validate_provider_and_model(&self.provider, &self.model)?;
        if !self.workspace_root.is_absolute() {
            return Err(CausalStateError::InvalidIdentity {
                detail: "causal workspace root is not absolute".to_string(),
            });
        }
        match (
            self.provider_generation,
            self.provider_state_digest,
            provider_state,
        ) {
            (None, None, None) => Ok(()),
            (Some(generation), Some(digest), Some(state))
                if generation == state.generation() && digest == state.digest() =>
            {
                Ok(())
            }
            (Some(_), Some(_), None) => Err(CausalStateError::Unavailable {
                detail: "causal binding requires provider-native state that is unavailable"
                    .to_string(),
            }),
            _ => Err(CausalStateError::ProviderConflict {
                detail: "provider continuation generation or digest differs from causal binding"
                    .to_string(),
            }),
        }
    }

    fn validate_session_identity(
        &self,
        provider: &str,
        model: &str,
    ) -> Result<(), CausalStateError> {
        if !self.provider.eq_ignore_ascii_case(provider.trim()) || self.model != model {
            return Err(CausalStateError::ProviderConflict {
                detail: format!(
                    "causal provider/model '{}/{}' differs from session provider/model '{}/{}'",
                    self.provider, self.model, provider, model
                ),
            });
        }
        Ok(())
    }

    fn with_provider_state(
        mut self,
        provider: &str,
        model: &str,
        provider_state: Option<&ProviderNativeState>,
    ) -> Result<Self, CausalStateError> {
        self.validate_session_identity(provider, model)?;
        self.provider_generation = provider_state.map(ProviderNativeState::generation);
        self.provider_state_digest = provider_state.map(ProviderNativeState::digest);
        self.validate(provider_state)?;
        Ok(self)
    }

    fn validate_resume_run(&self, run: &ToolRunContext) -> Result<(), CausalStateError> {
        if !self.provider.eq_ignore_ascii_case(run.provider_id()) {
            return Err(CausalStateError::ProviderConflict {
                detail: format!(
                    "persisted provider '{}' differs from active provider '{}'",
                    self.provider,
                    run.provider_id()
                ),
            });
        }
        let workspace = &run.runtime().descriptor().workspace;
        if self.workspace_root != workspace.root() || self.workspace_digest != workspace.digest {
            return Err(CausalStateError::WorkspaceConflict {
                detail: "persisted workspace identity differs from the active workspace"
                    .to_string(),
            });
        }
        Ok(())
    }

    fn validate_branch_run(&self, run: &ToolRunContext) -> Result<(), CausalStateError> {
        self.validate_resume_run(run)?;
        let descriptor = run.runtime().descriptor();
        if self.workspace_generation != descriptor.workspace.generation {
            return Err(CausalStateError::Stale {
                detail: "branch workspace generation is stale".to_string(),
            });
        }
        if self.capability_generation != descriptor.capabilities.generation
            || self.capability_digest != descriptor.capabilities.manifest_digest
        {
            return Err(CausalStateError::CapabilityConflict {
                detail: "branch capability generation differs from the active run".to_string(),
            });
        }
        Ok(())
    }
}

/// Immutable reference to one committed causal event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalEventRef {
    logical_id: LogicalStateId,
    generation: u64,
    digest: ContentDigest,
}

impl CausalEventRef {
    /// Monotonic generation of the referenced committed event.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Digest of the exact committed event payload.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    pub(crate) fn validate(&self) -> Result<(), CausalStateError> {
        if self.generation == 0 {
            return Err(CausalStateError::InvalidIdentity {
                detail: "causal event generation must be non-zero".to_string(),
            });
        }
        Ok(())
    }
}

/// Provenance of the currently committed session event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionProvenance {
    /// Session state was created by the host runtime.
    HostCreated,
    /// State was selected from one explicitly anchored branch proposal.
    BranchSelection {
        branch_id: LogicalStateId,
        proposal_digest: ContentDigest,
    },
    /// State was admitted by the explicit legacy migration path.
    MigratedLegacy,
}

/// Host-owned authorization record for one project-owned branch proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchAnchor {
    name: String,
    branch_id: LogicalStateId,
    proposal_digest: ContentDigest,
    parent: CausalEventRef,
}

/// Versioned causal envelope persisted with canonical session state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCausalState {
    schema_version: u16,
    logical_id: LogicalStateId,
    generation: u64,
    parent: Option<CausalEventRef>,
    binding: Option<CausalRuntimeBinding>,
    previous_events: Vec<CausalEventRef>,
    branch_anchors: Vec<BranchAnchor>,
    selected_branches: Vec<LogicalStateId>,
    provenance: SessionProvenance,
    event_digest: ContentDigest,
    initialized: bool,
}

impl Default for SessionCausalState {
    fn default() -> Self {
        Self {
            schema_version: SESSION_CAUSAL_SCHEMA_VERSION,
            logical_id: LogicalStateId(uuid::Uuid::nil()),
            generation: 1,
            parent: None,
            binding: None,
            previous_events: Vec::new(),
            branch_anchors: Vec::new(),
            selected_branches: Vec::new(),
            provenance: SessionProvenance::MigratedLegacy,
            event_digest: ContentDigest::sha256(b"openclaudia-legacy-causal-placeholder"),
            initialized: false,
        }
    }
}

impl SessionCausalState {
    pub(crate) const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Construct an uninitialized envelope for a newly allocated state group.
    /// [`crate::state::Session`] initializes it with provider identity before
    /// the state can be persisted as a resumable session.
    #[must_use]
    pub fn uninitialized(session_id: &SessionId) -> Self {
        let logical_id = LogicalStateId::from_session_id(session_id).unwrap_or_default();
        Self {
            schema_version: SESSION_CAUSAL_SCHEMA_VERSION,
            logical_id,
            generation: 1,
            parent: None,
            binding: None,
            previous_events: Vec::new(),
            branch_anchors: Vec::new(),
            selected_branches: Vec::new(),
            provenance: SessionProvenance::HostCreated,
            event_digest: ContentDigest::sha256(b"openclaudia-uninitialized-causal-session"),
            initialized: false,
        }
    }

    pub(crate) fn initialize(
        session_id: &SessionId,
        provider: &str,
        model: &str,
        messages: &[Value],
        provider_state: Option<&ProviderNativeState>,
        provenance: SessionProvenance,
    ) -> Result<Self, CausalStateError> {
        validate_provider_and_model(provider, model)?;
        let logical_id = LogicalStateId::from_session_id(session_id)?;
        let mut causal = Self {
            schema_version: SESSION_CAUSAL_SCHEMA_VERSION,
            logical_id,
            generation: 1,
            parent: None,
            binding: None,
            previous_events: Vec::new(),
            branch_anchors: Vec::new(),
            selected_branches: Vec::new(),
            provenance,
            event_digest: ContentDigest::sha256([]),
            initialized: true,
        };
        causal.event_digest =
            causal.calculate_event_digest(provider, model, messages, provider_state)?;
        Ok(causal)
    }

    pub(crate) fn reinitialize_identity(
        &mut self,
        session_id: &SessionId,
        provider: &str,
        model: &str,
        messages: &[Value],
        provider_state: Option<&ProviderNativeState>,
    ) -> Result<(), CausalStateError> {
        *self = Self::initialize(
            session_id,
            provider,
            model,
            messages,
            provider_state,
            SessionProvenance::HostCreated,
        )?;
        Ok(())
    }

    pub(crate) fn refresh(
        &mut self,
        session_id: &SessionId,
        provider: &str,
        model: &str,
        messages: &[Value],
        provider_state: Option<&ProviderNativeState>,
        run: Option<&ToolRunContext>,
    ) -> Result<(), CausalStateError> {
        if !self.initialized {
            *self = Self::initialize(
                session_id,
                provider,
                model,
                messages,
                provider_state,
                SessionProvenance::HostCreated,
            )?;
        }
        let expected_id = LogicalStateId::from_session_id(session_id)?;
        if self.logical_id != expected_id {
            return Err(CausalStateError::IdentityConflict {
                detail: "session id differs from immutable causal identity".to_string(),
            });
        }
        let next_binding = match run {
            Some(run) => Some(CausalRuntimeBinding::capture(run, model, provider_state)?),
            None => self
                .binding
                .clone()
                .map(|binding| binding.with_provider_state(provider, model, provider_state))
                .transpose()?,
        };
        let unchanged = self.binding == next_binding
            && self.calculate_event_digest(provider, model, messages, provider_state)?
                == self.event_digest;
        if unchanged {
            return Ok(());
        }
        self.advance_generation()?;
        self.binding = next_binding;
        self.event_digest =
            self.calculate_event_digest(provider, model, messages, provider_state)?;
        Ok(())
    }

    pub(crate) fn validate_document(
        &self,
        session_id: &SessionId,
        provider: &str,
        model: &str,
        messages: &[Value],
        provider_state: Option<&ProviderNativeState>,
    ) -> Result<(), CausalStateError> {
        if self.schema_version != SESSION_CAUSAL_SCHEMA_VERSION {
            return Err(CausalStateError::UnsupportedSchema {
                found: self.schema_version,
                supported: SESSION_CAUSAL_SCHEMA_VERSION,
            });
        }
        if !self.initialized || self.generation == 0 {
            return Err(CausalStateError::Unavailable {
                detail: "session has no initialized causal envelope".to_string(),
            });
        }
        let expected_id = LogicalStateId::from_session_id(session_id)?;
        if self.logical_id != expected_id {
            return Err(CausalStateError::IdentityConflict {
                detail: "session id differs from immutable causal identity".to_string(),
            });
        }
        validate_provider_and_model(provider, model)?;
        if let Some(binding) = &self.binding {
            binding.validate(provider_state)?;
            binding.validate_session_identity(provider, model)?;
        }
        if self.previous_events.len() > MAX_CAUSAL_EVENTS
            || self.branch_anchors.len() > MAX_BRANCH_ANCHORS
            || self.selected_branches.len() > MAX_BRANCH_SELECTIONS
        {
            return Err(CausalStateError::ResourceLimit {
                detail: "causal session history exceeds its bounded limit".to_string(),
            });
        }
        if self
            .parent
            .as_ref()
            .is_some_and(|parent| parent.logical_id == self.logical_id || parent.generation == 0)
        {
            return Err(CausalStateError::Cycle {
                detail: "session causal parent is self-referential".to_string(),
            });
        }
        for event in &self.previous_events {
            event.validate()?;
            if event.logical_id != self.logical_id || event.generation >= self.generation {
                return Err(CausalStateError::Stale {
                    detail: "session causal history is non-monotonic".to_string(),
                });
            }
        }
        validate_unique_history(self)?;
        let actual = self.calculate_event_digest(provider, model, messages, provider_state)?;
        if actual != self.event_digest {
            return Err(CausalStateError::DigestMismatch {
                expected: self.event_digest,
                actual,
            });
        }
        Ok(())
    }

    pub(crate) fn validate_resume(
        &self,
        session_id: &SessionId,
        provider: &str,
        model: &str,
        messages: &[Value],
        provider_state: Option<&ProviderNativeState>,
        run: &ToolRunContext,
    ) -> Result<(), CausalStateError> {
        self.validate_document(session_id, provider, model, messages, provider_state)?;
        if run.session_id() != session_id.as_str() {
            return Err(CausalStateError::IdentityConflict {
                detail: "resume run belongs to another logical session".to_string(),
            });
        }
        self.binding
            .as_ref()
            .ok_or_else(|| CausalStateError::Unavailable {
                detail: "session was never bound to a complete tool/provider run".to_string(),
            })?
            .validate_resume_run(run)
    }

    pub(crate) fn prepare_resume(
        &mut self,
        session_id: &SessionId,
        provider: &str,
        model: &str,
        messages: &[Value],
        provider_state: Option<&ProviderNativeState>,
        run: &ToolRunContext,
    ) -> Result<(), CausalStateError> {
        self.validate_document(session_id, provider, model, messages, provider_state)?;
        if run.session_id() != session_id.as_str() {
            return Err(CausalStateError::IdentityConflict {
                detail: "resume run belongs to another logical session".to_string(),
            });
        }
        if let Some(binding) = &self.binding {
            return binding.validate_resume_run(run);
        }
        if !matches!(
            self.provenance,
            SessionProvenance::HostCreated | SessionProvenance::MigratedLegacy
        ) {
            return Err(CausalStateError::Unavailable {
                detail: "session was never bound to a complete tool/provider run".to_string(),
            });
        }
        if !run.provider_id().eq_ignore_ascii_case(provider) {
            return Err(CausalStateError::ProviderConflict {
                detail: format!(
                    "persisted provider '{}' differs from active provider '{}'",
                    provider,
                    run.provider_id()
                ),
            });
        }

        self.advance_generation()?;
        self.binding = Some(CausalRuntimeBinding::capture(run, model, provider_state)?);
        self.event_digest =
            self.calculate_event_digest(provider, model, messages, provider_state)?;
        Ok(())
    }

    pub(crate) const fn current_event(&self) -> CausalEventRef {
        CausalEventRef {
            logical_id: self.logical_id,
            generation: self.generation,
            digest: self.event_digest,
        }
    }

    fn contains_event(&self, event: &CausalEventRef) -> bool {
        self.current_event() == *event || self.previous_events.contains(event)
    }

    fn advance_generation(&mut self) -> Result<(), CausalStateError> {
        let previous = self.current_event();
        if self.previous_events.last() != Some(&previous) {
            self.previous_events.push(previous);
        }
        if self.previous_events.len() > MAX_CAUSAL_EVENTS {
            let excess = self.previous_events.len() - MAX_CAUSAL_EVENTS;
            self.previous_events.drain(..excess);
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(CausalStateError::GenerationExhausted)?;
        Ok(())
    }

    fn calculate_event_digest(
        &self,
        provider: &str,
        model: &str,
        messages: &[Value],
        provider_state: Option<&ProviderNativeState>,
    ) -> Result<ContentDigest, CausalStateError> {
        #[derive(Serialize)]
        struct DigestMaterial<'a> {
            domain: &'static str,
            schema_version: u16,
            logical_id: LogicalStateId,
            generation: u64,
            parent: &'a Option<CausalEventRef>,
            binding: &'a Option<CausalRuntimeBinding>,
            previous_events: &'a [CausalEventRef],
            branch_anchors: &'a [BranchAnchor],
            selected_branches: &'a [LogicalStateId],
            provenance: &'a SessionProvenance,
            provider: &'a str,
            model: &'a str,
            messages: &'a [Value],
            provider_state: Option<&'a ProviderNativeState>,
        }

        let material = DigestMaterial {
            domain: "openclaudia.session-causal-event.v1",
            schema_version: self.schema_version,
            logical_id: self.logical_id,
            generation: self.generation,
            parent: &self.parent,
            binding: &self.binding,
            previous_events: &self.previous_events,
            branch_anchors: &self.branch_anchors,
            selected_branches: &self.selected_branches,
            provenance: &self.provenance,
            provider,
            model,
            messages,
            provider_state,
        };
        serde_json::to_vec(&material)
            .map(ContentDigest::sha256)
            .map_err(CausalStateError::Serialization)
    }
}

fn validate_unique_history(causal: &SessionCausalState) -> Result<(), CausalStateError> {
    let mut events = HashSet::with_capacity(causal.previous_events.len());
    for event in &causal.previous_events {
        if !events.insert((event.logical_id, event.generation, event.digest)) {
            return Err(CausalStateError::Cycle {
                detail: "causal event history contains a duplicate event".to_string(),
            });
        }
    }
    let mut anchor_names = HashSet::with_capacity(causal.branch_anchors.len());
    let mut anchor_ids = HashSet::with_capacity(causal.branch_anchors.len());
    for anchor in &causal.branch_anchors {
        validate_branch_name(&anchor.name)?;
        anchor.parent.validate()?;
        if anchor.parent.logical_id != causal.logical_id
            || anchor.branch_id == causal.logical_id
            || !anchor_names.insert(anchor.name.as_str())
            || !anchor_ids.insert(anchor.branch_id)
        {
            return Err(CausalStateError::Cycle {
                detail: "branch anchor identity is duplicated or self-referential".to_string(),
            });
        }
    }
    let mut selections = HashSet::with_capacity(causal.selected_branches.len());
    if causal
        .selected_branches
        .iter()
        .any(|id| *id == causal.logical_id || !selections.insert(*id))
    {
        return Err(CausalStateError::Cycle {
            detail: "branch selection ancestry contains a cycle".to_string(),
        });
    }
    Ok(())
}

/// Immutable source captured from a canonical session for `/branch`.
#[derive(Debug, Clone)]
pub struct BranchSource {
    session_id: SessionId,
    parent: CausalEventRef,
    binding: CausalRuntimeBinding,
    messages: Vec<Value>,
    provider_state: Option<ProviderNativeState>,
    source_run: RunId,
}

impl BranchSource {
    pub(crate) fn from_session(
        session_id: SessionId,
        causal: &SessionCausalState,
        messages: Vec<Value>,
        provider_state: Option<ProviderNativeState>,
        run: &ToolRunContext,
    ) -> Result<Self, CausalStateError> {
        let binding = causal
            .binding
            .clone()
            .ok_or_else(|| CausalStateError::Unavailable {
                detail: "cannot branch a session without a complete runtime binding".to_string(),
            })?;
        binding.validate_branch_run(run)?;
        Ok(Self {
            session_id,
            parent: causal.current_event(),
            binding,
            messages,
            provider_state,
            source_run: run.run_id(),
        })
    }

    /// Capture a bounded branch source for compatibility frontends that do not
    /// expose a canonical [`crate::state::Session`] handle to command parsing.
    /// Such proposals remain unselectable until explicitly anchored by the
    /// host-owned session state.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal for an invalid session/provider identity or an
    /// inconsistent runtime binding.
    pub fn from_untracked_messages(
        messages: &[Value],
        provider: &str,
        model: &str,
        run: &ToolRunContext,
    ) -> Result<Self, CausalStateError> {
        let session_id = SessionId::from_raw(run.session_id()).map_err(|_| {
            CausalStateError::InvalidIdentity {
                detail: "run session identity is not a UUID".to_string(),
            }
        })?;
        let mut causal = SessionCausalState::initialize(
            &session_id,
            provider,
            model,
            messages,
            None,
            SessionProvenance::HostCreated,
        )?;
        causal.refresh(&session_id, provider, model, messages, None, Some(run))?;
        Self::from_session(session_id, &causal, messages.to_vec(), None, run)
    }

    /// Build one digest-bound proposal from this immutable source.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal when the name or captured state exceeds bounds.
    pub fn prepare(&self, name: &str) -> Result<PreparedBranch, CausalStateError> {
        PreparedBranch::new(BranchProposal::new(name, self)?)
    }
}

/// Provenance retained by a project-owned branch proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchProvenance {
    source_session: SessionId,
    source_run: RunId,
    source: String,
}

/// Bounded, digest-bound project-owned proposal for a branch selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchProposal {
    schema_version: u16,
    logical_id: LogicalStateId,
    name: String,
    created_at: DateTime<Utc>,
    parent: CausalEventRef,
    binding: CausalRuntimeBinding,
    messages: Vec<Value>,
    provider_native_state: Option<ProviderNativeState>,
    provenance: BranchProvenance,
    digest: ContentDigest,
}

impl BranchProposal {
    fn new(name: &str, source: &BranchSource) -> Result<Self, CausalStateError> {
        validate_branch_name(name)?;
        if source.messages.len() > MAX_BRANCH_MESSAGES {
            return Err(CausalStateError::ResourceLimit {
                detail: "branch proposal contains too many messages".to_string(),
            });
        }
        let mut proposal = Self {
            schema_version: BRANCH_PROPOSAL_SCHEMA_VERSION,
            logical_id: LogicalStateId::new(),
            name: name.to_string(),
            created_at: Utc::now(),
            parent: source.parent.clone(),
            binding: source.binding.clone(),
            messages: source.messages.clone(),
            provider_native_state: source.provider_state.clone(),
            provenance: BranchProvenance {
                source_session: source.session_id.clone(),
                source_run: source.source_run,
                source: "host_branch_command".to_string(),
            },
            digest: ContentDigest::sha256([]),
        };
        proposal.digest = proposal.calculate_digest()?;
        proposal.validate()?;
        Ok(proposal)
    }

    /// Proposal name selected by the user.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Portable messages carried by the proposal.
    #[must_use]
    pub fn messages(&self) -> &[Value] {
        &self.messages
    }

    /// Exact digest recorded by the host-owned branch anchor.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Revalidate the complete proposal without granting it authority.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal for invalid shape, bounds, identity, or digest.
    pub fn validate(&self) -> Result<(), CausalStateError> {
        if self.schema_version != BRANCH_PROPOSAL_SCHEMA_VERSION {
            return Err(CausalStateError::UnsupportedSchema {
                found: self.schema_version,
                supported: BRANCH_PROPOSAL_SCHEMA_VERSION,
            });
        }
        validate_branch_name(&self.name)?;
        self.parent.validate()?;
        if self.logical_id == self.parent.logical_id {
            return Err(CausalStateError::Cycle {
                detail: "branch proposal is its own causal parent".to_string(),
            });
        }
        if LogicalStateId::from_session_id(&self.provenance.source_session)?
            != self.parent.logical_id
        {
            return Err(CausalStateError::IdentityConflict {
                detail: "branch provenance session differs from its causal parent".to_string(),
            });
        }
        if self.provenance.source != "host_branch_command" {
            return Err(CausalStateError::InvalidIdentity {
                detail: "branch proposal provenance is unsupported".to_string(),
            });
        }
        if self.messages.len() > MAX_BRANCH_MESSAGES {
            return Err(CausalStateError::ResourceLimit {
                detail: "branch proposal contains too many messages".to_string(),
            });
        }
        self.binding.validate(self.provider_native_state.as_ref())?;
        if let Some(native) = &self.provider_native_state {
            native
                .validate()
                .map_err(|error| CausalStateError::ProviderConflict {
                    detail: error.to_string(),
                })?;
            native
                .validate_identity(&self.binding.provider, &self.binding.model)
                .map_err(|error| CausalStateError::ProviderConflict {
                    detail: error.to_string(),
                })?;
        }
        let actual = self.calculate_digest()?;
        if actual != self.digest {
            return Err(CausalStateError::DigestMismatch {
                expected: self.digest,
                actual,
            });
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<ContentDigest, CausalStateError> {
        #[derive(Serialize)]
        struct DigestMaterial<'a> {
            domain: &'static str,
            schema_version: u16,
            logical_id: LogicalStateId,
            name: &'a str,
            created_at: &'a DateTime<Utc>,
            parent: &'a CausalEventRef,
            binding: &'a CausalRuntimeBinding,
            messages: &'a [Value],
            provider_native_state: Option<&'a ProviderNativeState>,
            provenance: &'a BranchProvenance,
        }

        serde_json::to_vec(&DigestMaterial {
            domain: "openclaudia.branch-proposal.v1",
            schema_version: self.schema_version,
            logical_id: self.logical_id,
            name: &self.name,
            created_at: &self.created_at,
            parent: &self.parent,
            binding: &self.binding,
            messages: &self.messages,
            provider_native_state: self.provider_native_state.as_ref(),
            provenance: &self.provenance,
        })
        .map(ContentDigest::sha256)
        .map_err(CausalStateError::Serialization)
    }
}

/// Branch proposal prepared for persistence and later host anchoring.
#[derive(Debug, Clone)]
pub struct PreparedBranch {
    proposal: Box<BranchProposal>,
}

impl PreparedBranch {
    fn new(proposal: BranchProposal) -> Result<Self, CausalStateError> {
        proposal.validate()?;
        Ok(Self {
            proposal: Box::new(proposal),
        })
    }

    /// Borrow the validated proposal.
    #[must_use]
    pub fn proposal(&self) -> &BranchProposal {
        &self.proposal
    }
}

impl Deref for PreparedBranch {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.proposal.name()
    }
}

impl fmt::Display for PreparedBranch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.proposal.name())
    }
}

impl PartialEq<String> for PreparedBranch {
    fn eq(&self, other: &String) -> bool {
        self.proposal.name() == other
    }
}

/// Decode and structurally validate an untrusted project-owned proposal.
///
/// # Errors
///
/// Returns a typed refusal for malformed, oversized, unsupported, or
/// digest-inconsistent input.
pub fn decode_branch_proposal(raw: &str) -> Result<BranchProposal, CausalStateError> {
    if raw.len() > MAX_BRANCH_PROPOSAL_BYTES {
        return Err(CausalStateError::ResourceLimit {
            detail: "branch proposal exceeds the supported byte limit".to_string(),
        });
    }
    let value: Value = serde_json::from_str(raw).map_err(CausalStateError::Serialization)?;
    validate_json_bounds(&value)?;
    let proposal: BranchProposal =
        serde_json::from_value(value).map_err(CausalStateError::Serialization)?;
    proposal.validate()?;
    Ok(proposal)
}

pub(crate) fn register_branch(
    causal: &mut SessionCausalState,
    prepared: &PreparedBranch,
    provider: &str,
    model: &str,
    messages: &[Value],
    provider_state: Option<&ProviderNativeState>,
    run: &ToolRunContext,
) -> Result<(), CausalStateError> {
    causal.refresh(
        &prepared.proposal.provenance.source_session,
        provider,
        model,
        messages,
        provider_state,
        Some(run),
    )?;
    let proposal = prepared.proposal();
    proposal.validate()?;
    proposal.binding.validate_branch_run(run)?;
    if proposal.parent != causal.current_event() {
        return Err(CausalStateError::Stale {
            detail: "branch source changed before its proposal was anchored".to_string(),
        });
    }
    if causal.branch_anchors.iter().any(|anchor| {
        [
            anchor.name == proposal.name,
            anchor.branch_id == proposal.logical_id,
            anchor.proposal_digest == proposal.digest,
        ]
        .into_iter()
        .any(std::convert::identity)
    }) {
        return Err(CausalStateError::Conflict {
            detail: "branch name, identity, or digest is already anchored".to_string(),
        });
    }
    causal.advance_generation()?;
    causal.branch_anchors.push(BranchAnchor {
        name: proposal.name.clone(),
        branch_id: proposal.logical_id,
        proposal_digest: proposal.digest,
        parent: proposal.parent.clone(),
    });
    if causal.branch_anchors.len() > MAX_BRANCH_ANCHORS {
        let _expired = causal.branch_anchors.remove(0);
    }
    causal.event_digest =
        causal.calculate_event_digest(provider, model, messages, provider_state)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)] // All fields participate in one atomic selection boundary.
pub(crate) fn select_branch(
    causal: &mut SessionCausalState,
    session_id: &SessionId,
    provider: &str,
    model: &str,
    current_messages: &[Value],
    current_provider_state: Option<&ProviderNativeState>,
    proposal: &BranchProposal,
    run: &ToolRunContext,
) -> Result<(), CausalStateError> {
    causal.refresh(
        session_id,
        provider,
        model,
        current_messages,
        current_provider_state,
        Some(run),
    )?;
    proposal.validate()?;
    proposal
        .binding
        .validate_session_identity(provider, model)?;
    if proposal.binding.workspace_root != run.runtime().descriptor().workspace.root()
        || proposal.binding.workspace_digest != run.runtime().descriptor().workspace.digest
    {
        return Err(CausalStateError::WorkspaceConflict {
            detail: "branch belongs to another workspace".to_string(),
        });
    }
    if &proposal.provenance.source_session != session_id {
        return Err(CausalStateError::IdentityConflict {
            detail: "branch belongs to another logical session".to_string(),
        });
    }
    let Some(anchor) = causal.branch_anchors.iter().find(|anchor| {
        [
            anchor.name == proposal.name,
            anchor.branch_id == proposal.logical_id,
            anchor.proposal_digest == proposal.digest,
            anchor.parent == proposal.parent,
        ]
        .into_iter()
        .all(std::convert::identity)
    }) else {
        return Err(CausalStateError::Unavailable {
            detail: "branch proposal has no matching host-owned anchor".to_string(),
        });
    };
    if !causal.contains_event(&anchor.parent) {
        return Err(CausalStateError::Stale {
            detail: "branch parent event is outside the retained causal history".to_string(),
        });
    }
    if causal.selected_branches.contains(&proposal.logical_id) {
        return Err(CausalStateError::Cycle {
            detail: "branch was already selected in this causal lineage".to_string(),
        });
    }
    if causal.selected_branches.len() >= MAX_BRANCH_SELECTIONS {
        return Err(CausalStateError::ResourceLimit {
            detail: "branch selection ancestry reached its bounded limit".to_string(),
        });
    }

    causal.advance_generation()?;
    causal.parent = Some(CausalEventRef {
        logical_id: proposal.logical_id,
        generation: 1,
        digest: proposal.digest,
    });
    causal.binding = Some(CausalRuntimeBinding::capture(
        run,
        model,
        proposal.provider_native_state.as_ref(),
    )?);
    causal.selected_branches.push(proposal.logical_id);
    causal.provenance = SessionProvenance::BranchSelection {
        branch_id: proposal.logical_id,
        proposal_digest: proposal.digest,
    };
    causal.event_digest = causal.calculate_event_digest(
        provider,
        model,
        &proposal.messages,
        proposal.provider_native_state.as_ref(),
    )?;
    Ok(())
}

pub(crate) fn proposal_state(
    proposal: &BranchProposal,
) -> (Vec<Value>, Option<ProviderNativeState>) {
    (
        proposal.messages.clone(),
        proposal.provider_native_state.clone(),
    )
}

fn validate_branch_name(name: &str) -> Result<(), CausalStateError> {
    if name.is_empty()
        || name.len() > MAX_BRANCH_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(CausalStateError::InvalidIdentity {
            detail: "branch name must be 1-128 ASCII letters, numbers, '-' or '_'".to_string(),
        });
    }
    Ok(())
}

fn validate_provider_and_model(provider: &str, model: &str) -> Result<(), CausalStateError> {
    if provider.trim().is_empty()
        || provider.len() > MAX_PROVIDER_ID_BYTES
        || model.trim().is_empty()
        || model.len() > MAX_MODEL_ID_BYTES
        || provider.bytes().any(|byte| byte.is_ascii_control())
        || model.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(CausalStateError::InvalidIdentity {
            detail: "provider or model identity is empty, excessive, or contains controls"
                .to_string(),
        });
    }
    Ok(())
}

fn validate_json_bounds(value: &Value) -> Result<(), CausalStateError> {
    let mut nodes = 0_usize;
    let mut pending = vec![(value, 0_usize)];
    while let Some((node, depth)) = pending.pop() {
        if depth > MAX_BRANCH_JSON_DEPTH {
            return Err(CausalStateError::ResourceLimit {
                detail: "branch JSON nesting exceeds the supported limit".to_string(),
            });
        }
        nodes = nodes
            .checked_add(1)
            .ok_or_else(|| CausalStateError::ResourceLimit {
                detail: "branch JSON node count overflowed".to_string(),
            })?;
        if nodes > MAX_BRANCH_JSON_NODES {
            return Err(CausalStateError::ResourceLimit {
                detail: "branch JSON node count exceeds the supported limit".to_string(),
            });
        }
        match node {
            Value::Array(items) => pending.extend(items.iter().map(|item| (item, depth + 1))),
            Value::Object(fields) => {
                pending.extend(fields.values().map(|item| (item, depth + 1)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

/// Typed refusal from causal resume or branch selection.
#[derive(Debug, Error)]
pub enum CausalStateError {
    #[error("unsupported causal schema {found}; supported schema is {supported}")]
    UnsupportedSchema { found: u16, supported: u16 },
    #[error("invalid causal identity: {detail}")]
    InvalidIdentity { detail: String },
    #[error("causal identity conflict: {detail}")]
    IdentityConflict { detail: String },
    #[error("causal state conflict: {detail}")]
    Conflict { detail: String },
    #[error("causal state is unavailable: {detail}")]
    Unavailable { detail: String },
    #[error("stale causal state: {detail}")]
    Stale { detail: String },
    #[error("provider causal conflict: {detail}")]
    ProviderConflict { detail: String },
    #[error("workspace causal conflict: {detail}")]
    WorkspaceConflict { detail: String },
    #[error("capability causal conflict: {detail}")]
    CapabilityConflict { detail: String },
    #[error("causal cycle rejected: {detail}")]
    Cycle { detail: String },
    #[error("causal digest mismatch: expected {expected}, calculated {actual}")]
    DigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    #[error("causal resource limit: {detail}")]
    ResourceLimit { detail: String },
    #[error("causal generation space exhausted")]
    GenerationExhausted,
    #[error("could not serialize causal state: {0}")]
    Serialization(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn causal_run(root: &std::path::Path) -> std::sync::Arc<ToolRunContext> {
        ToolRunContext::builder(SessionId::new(), root)
            .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(std::collections::HashMap::new())
            .process(false)
            .network(false)
            .secrets(false)
            .provider("provider")
            .build()
            .expect("causal run")
    }

    #[test]
    fn tampered_branch_proposal_is_rejected_before_selection() {
        let root = tempfile::tempdir().expect("workspace");
        let run = causal_run(root.path());
        let messages = vec![serde_json::json!({"role": "user", "content": "original"})];
        let prepared = BranchSource::from_untracked_messages(&messages, "provider", "model", &run)
            .expect("source")
            .prepare("snapshot")
            .expect("proposal");
        let mut value = serde_json::to_value(prepared.proposal()).expect("proposal JSON");
        value["messages"][0]["content"] = serde_json::json!("forged");

        assert!(matches!(
            decode_branch_proposal(&serde_json::to_string(&value).expect("encoded proposal")),
            Err(CausalStateError::DigestMismatch { .. })
        ));
    }
}
