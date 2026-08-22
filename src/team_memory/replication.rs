//! Encrypted, authenticated, bounded team technical-memory replicas.
//!
//! The replica is deliberately distinct from the user-private [`MemoryDb`].
//! Only immutable `TeamShared` technical-lesson revisions enter this state.
//! Every local operation consumes an S-103 authorization grant before content
//! is read or changed, and every wire exchange is bound to fresh grants over
//! exact protocol payload digests.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use anyhow::Context as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use rand::rngs::SysRng;
use rand::TryRng as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

use super::authority::{
    PrincipalId, ReplicaAuthorityRole, TeamAuthorityError, TeamAuthorityStatus, TeamAuthorityStore,
    TeamAuthorizationOutcome, TeamId, TeamMemoryOperation, TeamOperationGrant, TeamOperationPermit,
    TeamRole, MAX_TEAM_GRANT_TTL_SECONDS,
};
use super::MemoryScope;
use crate::memory::{
    LogicalMemoryId, MemoryConflictHead, MemoryDb, MemoryDigest, MemoryRecordScope, MemoryRevision,
    MemoryRevisionState, MemorySourceEvidence, TechnicalLessonCorrectionRequest,
    TechnicalLessonDraft, TechnicalLessonError, TechnicalLessonQueryResult,
    TechnicalLessonQueryStatus, TechnicalLessonRecord, TechnicalLessonStoreError,
    WorkspaceMemoryId, MAX_TECHNICAL_QUERY_RESULT_BYTES, TECHNICAL_LESSON_SCHEMA_VERSION,
    TECHNICAL_LESSON_TAG,
};
use crate::persistence::{
    CommitState, FileClass, PersistenceError, PersistentStorage, StorageGeneration,
};
use crate::runtime::ContentDigest;

/// Wire and encrypted-state format understood by this build.
pub const TEAM_REPLICATION_SCHEMA_VERSION: u32 = 1;
/// Maximum immutable revisions retained by one local replica or service.
pub const MAX_TEAM_REPLICA_REVISIONS: usize = 8_192;
/// Maximum local mutations waiting for a remote acknowledgement.
pub const MAX_TEAM_REPLICA_OUTBOX: usize = 1_024;
/// Maximum idempotency receipts retained by a service.
pub const MAX_TEAM_REPLICA_INBOX: usize = 4_096;
/// Maximum revisions sent in one parent-before-child protocol batch.
pub const MAX_TEAM_REPLICATION_BATCH: usize = 64;
/// Maximum encoded request or response accepted by the protocol.
pub const MAX_TEAM_REPLICATION_MESSAGE_BYTES: usize = 2 * 1_024 * 1_024;
/// Maximum DER certificate pinned for one service.
pub const MAX_TEAM_REPLICATION_CERTIFICATE_BYTES: usize = 128 * 1_024;
/// Maximum endpoint string retained in host-owned state.
pub const MAX_TEAM_REPLICATION_ENDPOINT_BYTES: usize = 2_048;
const MAX_REPLICA_PLAINTEXT_BYTES: usize = 48 * 1_024 * 1_024;
const MAX_REPLICA_CIPHERTEXT_BASE64_BYTES: usize = 64 * 1_024 * 1_024;
const MAX_REPLICA_ID_BYTES: usize = 40;
const MAX_OPERATION_ID_BYTES: usize = 128;
const MAX_ENCODED_OPERATION_GRANT_BYTES: usize = 4 * 1_024;
const MAX_WIRE_ENVELOPE_MARGIN_BYTES: usize = 1_024;
const LOCAL_GRANT_TTL_SECONDS: i64 = 60;
const SERVICE_DESCRIPTOR_GRANT_TTL_SECONDS: i64 = MAX_TEAM_GRANT_TTL_SECONDS;

/// Stable opaque identity of one replica instance.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TeamReplicaId(String);

impl TeamReplicaId {
    fn random() -> Result<Self, TeamReplicationError> {
        let mut bytes = [0_u8; 16];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| TeamReplicationError::RecoveryRequired {
                reason: "operating-system randomness is unavailable",
            })?;
        let mut value = String::with_capacity(40);
        value.push_str("replica-");
        for byte in bytes {
            use fmt::Write as _;
            let _ = write!(value, "{byte:02x}");
        }
        Ok(Self(value))
    }

    /// Stable printable identity; never a credential.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TeamReplicaId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Debug for TeamReplicaId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TeamReplicaId")
            .field(&self.0)
            .finish()
    }
}

impl FromStr for TeamReplicaId {
    type Err = TeamReplicationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some(hex) = value.strip_prefix("replica-") else {
            return Err(TeamReplicationError::InvalidProtocol);
        };
        if value.len() > MAX_REPLICA_ID_BYTES
            || hex.len() != 32
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(TeamReplicationError::InvalidProtocol);
        }
        Ok(Self(value.to_string()))
    }
}

impl TryFrom<String> for TeamReplicaId {
    type Error = TeamReplicationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<TeamReplicaId> for String {
    fn from(value: TeamReplicaId) -> Self {
        value.0
    }
}

/// Stable typed failures at the replica boundary.
#[derive(Debug, Error)]
pub enum TeamReplicationError {
    #[error("team memory is not configured")]
    Unconfigured,
    #[error("team memory authorization was denied")]
    Unauthorized,
    #[error("team replication protocol is malformed, mismatched, or unsupported")]
    InvalidProtocol,
    #[error("team replica state is corrupt or cannot be decrypted")]
    CorruptReplica,
    #[error("team replica reached its bounded {resource} capacity")]
    CapacityExceeded { resource: &'static str },
    #[error("team replica update conflicted with another process")]
    ConcurrentUpdate,
    #[error("team replication service is unavailable")]
    ServiceUnavailable,
    #[error("team replication service identity changed")]
    ServiceIdentityMismatch,
    #[error("team replication requires host recovery: {reason}")]
    RecoveryRequired { reason: &'static str },
    #[error("team authority failed: {0}")]
    Authority(#[from] TeamAuthorityError),
    #[error("team memory store failed")]
    Store(#[source] anyhow::Error),
}

/// Stable internal disposition shared by the replica, transport, and tool
/// adapters. Keeping this classification at the typed error boundary prevents
/// a persistence or integrity failure from being misreported as an authority
/// denial merely because it originated in [`TeamAuthorityStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TeamReplicationFailureClass {
    Unconfigured,
    AuthorizationDenied,
    InvalidRequest,
    IntegrityFailure,
    CapacityExceeded,
    ConcurrentUpdate,
    Unavailable,
}

impl TeamReplicationError {
    #[must_use]
    pub(crate) fn failure_class(&self) -> TeamReplicationFailureClass {
        match self {
            Self::Unconfigured => TeamReplicationFailureClass::Unconfigured,
            Self::Unauthorized => TeamReplicationFailureClass::AuthorizationDenied,
            Self::InvalidProtocol => TeamReplicationFailureClass::InvalidRequest,
            Self::CorruptReplica
            | Self::ServiceIdentityMismatch
            | Self::RecoveryRequired { .. } => TeamReplicationFailureClass::IntegrityFailure,
            Self::CapacityExceeded { .. } => TeamReplicationFailureClass::CapacityExceeded,
            Self::ConcurrentUpdate => TeamReplicationFailureClass::ConcurrentUpdate,
            Self::Store(source) if source.downcast_ref::<TechnicalLessonStoreError>().is_some() => {
                TeamReplicationFailureClass::ConcurrentUpdate
            }
            Self::Store(source) if source.downcast_ref::<TechnicalLessonError>().is_some() => {
                TeamReplicationFailureClass::InvalidRequest
            }
            Self::ServiceUnavailable | Self::Store(_) => TeamReplicationFailureClass::Unavailable,
            Self::Authority(error) => authority_failure_class(error),
        }
    }
}

const fn authority_failure_class(error: &TeamAuthorityError) -> TeamReplicationFailureClass {
    match error {
        TeamAuthorityError::Unenrolled
        | TeamAuthorityError::EnrollmentPending
        | TeamAuthorityError::InvalidSignature
        | TeamAuthorityError::ScopeMismatch
        | TeamAuthorityError::Expired
        | TeamAuthorityError::MembershipInvalid
        | TeamAuthorityError::RoleDenied { .. }
        | TeamAuthorityError::GrantReplay
        | TeamAuthorityError::GrantMismatch
        | TeamAuthorityError::OwnerRequired => TeamReplicationFailureClass::AuthorizationDenied,
        TeamAuthorityError::CapacityExceeded { .. } => {
            TeamReplicationFailureClass::CapacityExceeded
        }
        TeamAuthorityError::ConcurrentUpdate
        | TeamAuthorityError::Persistence(PersistenceError::Conflict { .. }) => {
            TeamReplicationFailureClass::ConcurrentUpdate
        }
        TeamAuthorityError::RecoveryRequired { .. }
        | TeamAuthorityError::InvalidIdentity { .. }
        | TeamAuthorityError::InvalidArtifact
        | TeamAuthorityError::ClockRollback
        | TeamAuthorityError::Secret(_) => TeamReplicationFailureClass::IntegrityFailure,
        TeamAuthorityError::AlreadyEnrolled
        | TeamAuthorityError::CredentialUnavailable
        | TeamAuthorityError::Persistence(_)
        | TeamAuthorityError::Workspace(_) => TeamReplicationFailureClass::Unavailable,
    }
}

impl From<PersistenceError> for TeamReplicationError {
    fn from(error: PersistenceError) -> Self {
        match error {
            PersistenceError::Conflict { .. } => Self::ConcurrentUpdate,
            _ => Self::Store(anyhow::Error::new(error)),
        }
    }
}

/// Observable freshness of a local encrypted team replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamReplicaFreshness {
    Unconfigured,
    NeverSynchronized,
    Current,
    Stale,
    Partial,
    Unauthorized,
    Corrupt,
}

/// Bounded conflict metadata. Lesson content remains available only after an
/// explicit head-specific resolution operation is introduced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TeamLessonConflict {
    pub logical_id: LogicalMemoryId,
    pub heads: Vec<MemoryConflictHead>,
}

/// Team-scoped retrieval result returned to the canonical memory tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TeamTechnicalLessonQueryResult {
    pub schema_version: u32,
    pub team_id: TeamId,
    pub replica_id: TeamReplicaId,
    pub freshness: TeamReplicaFreshness,
    pub result: TechnicalLessonQueryResult,
    pub conflicts: Vec<TeamLessonConflict>,
    /// True when bounded output omitted additional conflict metadata.
    pub conflicts_truncated: bool,
    pub pull_cursor: u64,
    pub queued_mutations: usize,
    pub last_successful_sync_unix_seconds: Option<i64>,
}

/// Truthful status for a private/team/both retrieval operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopedTechnicalLessonQueryStatus {
    Complete,
    NoHit,
    Partial,
    Stale,
    Conflicted,
    Unavailable,
}

/// Canonical merged result for the private/team/both technical-memory tools.
/// Records keep their original scope and provenance; a `both` read does not
/// copy either store into the other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedTechnicalLessonQueryResult {
    pub schema_version: u32,
    pub workspace_id: WorkspaceMemoryId,
    pub authority: &'static str,
    pub scope: MemoryScope,
    pub status: ScopedTechnicalLessonQueryStatus,
    pub query: Option<String>,
    pub records: Vec<TechnicalLessonRecord>,
    pub private_status: Option<TechnicalLessonQueryStatus>,
    pub team_freshness: Option<TeamReplicaFreshness>,
    pub team_conflicts: Vec<TeamLessonConflict>,
    pub team_conflicts_truncated: bool,
    pub omitted_expired: usize,
    pub omitted_conflicted: usize,
    pub truncated_by_budget: bool,
}

/// Redacted replica status safe for CLI and tool output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TeamReplicaStatus {
    pub schema_version: u32,
    pub team_id: TeamId,
    pub workspace_id: WorkspaceMemoryId,
    pub replica_id: TeamReplicaId,
    pub freshness: TeamReplicaFreshness,
    pub revisions: usize,
    pub queued_mutations: usize,
    pub pull_cursor: u64,
    pub service_configured: bool,
    pub last_successful_sync_unix_seconds: Option<i64>,
}

/// Authenticated public descriptor imported explicitly by a host before a
/// client may contact a team service.
///
/// The certificate and service replica are pinned together; repository
/// configuration cannot replace either.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamServiceDescriptor {
    schema_version: u32,
    team_id: TeamId,
    workspace_id: WorkspaceMemoryId,
    service_replica_id: TeamReplicaId,
    service_principal_id: PrincipalId,
    endpoint: String,
    certificate_der_base64: String,
    certificate_digest: ContentDigest,
    grant: TeamOperationGrant,
}

impl TeamServiceDescriptor {
    /// Encode one bounded public descriptor.
    ///
    /// # Errors
    ///
    /// Returns a typed capacity or serialization error when the descriptor
    /// cannot be represented within the protocol limit.
    pub fn encode(&self) -> Result<Vec<u8>, TeamReplicationError> {
        let encoded = serde_json::to_vec_pretty(self)
            .context("encoding team service descriptor")
            .map_err(TeamReplicationError::Store)?;
        if encoded.len() > MAX_TEAM_REPLICATION_MESSAGE_BYTES {
            return Err(TeamReplicationError::CapacityExceeded {
                resource: "service descriptor bytes",
            });
        }
        Ok(encoded)
    }

    /// Decode one bounded public descriptor without contacting or trusting it.
    ///
    /// # Errors
    ///
    /// Returns a typed protocol or capacity error for malformed, unsupported,
    /// or oversized input.
    pub fn decode(encoded: &[u8]) -> Result<Self, TeamReplicationError> {
        if encoded.len() > MAX_TEAM_REPLICATION_MESSAGE_BYTES {
            return Err(TeamReplicationError::CapacityExceeded {
                resource: "service descriptor bytes",
            });
        }
        serde_json::from_slice(encoded).map_err(|_| TeamReplicationError::InvalidProtocol)
    }

    #[must_use]
    pub const fn team_id(&self) -> &TeamId {
        &self.team_id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceMemoryId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn service_replica_id(&self) -> &TeamReplicaId {
        &self.service_replica_id
    }
}

/// One bounded synchronization cycle result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TeamSyncReport {
    pub schema_version: u32,
    pub pushed_revisions: usize,
    pub pulled_revisions: usize,
    pub remaining_outbox: usize,
    pub pull_cursor: u64,
    pub server_cursor: u64,
    pub more_available: bool,
    pub freshness: TeamReplicaFreshness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReplicaRole {
    Client,
    Service,
}

impl ReplicaRole {
    const fn target_prefix(self) -> &'static str {
        match self {
            Self::Client => "team-replica-client",
            Self::Service => "team-replica-service",
        }
    }

    const fn authority_role(self) -> ReplicaAuthorityRole {
        match self {
            Self::Client => ReplicaAuthorityRole::Client,
            Self::Service => ReplicaAuthorityRole::Service,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PinnedTeamService {
    pub endpoint: String,
    pub service_replica_id: TeamReplicaId,
    pub service_principal_id: PrincipalId,
    pub certificate_der_base64: String,
    pub certificate_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutboxMutation {
    operation_id: String,
    operation: TeamMemoryOperation,
    revision_digest: MemoryDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SequencedRevision {
    pub sequence: u64,
    pub revision: MemoryRevision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceInboxReceipt {
    client_replica_id: TeamReplicaId,
    retry_key: String,
    payload_digest: ContentDigest,
    accepted_revision_digests: Vec<MemoryDigest>,
    server_cursor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplicaFileState {
    schema_version: u32,
    role: ReplicaRole,
    team_id: TeamId,
    workspace_id: WorkspaceMemoryId,
    replica_id: TeamReplicaId,
    store_id: crate::memory::MemoryStoreId,
    revisions: Vec<MemoryRevision>,
    next_operation_sequence: u64,
    outbox: Vec<OutboxMutation>,
    pull_cursor: u64,
    pinned_service: Option<PinnedTeamService>,
    freshness: TeamReplicaFreshness,
    last_successful_sync_unix_seconds: Option<i64>,
    next_service_sequence: u64,
    sequenced_revisions: Vec<SequencedRevision>,
    service_inbox: Vec<ServiceInboxReceipt>,
}

impl ReplicaFileState {
    fn new(
        role: ReplicaRole,
        team_id: TeamId,
        workspace_id: WorkspaceMemoryId,
    ) -> Result<Self, TeamReplicationError> {
        Ok(Self {
            schema_version: TEAM_REPLICATION_SCHEMA_VERSION,
            role,
            team_id,
            workspace_id,
            replica_id: TeamReplicaId::random()?,
            store_id: crate::memory::MemoryStoreId::new(),
            revisions: Vec::new(),
            next_operation_sequence: 1,
            outbox: Vec::new(),
            pull_cursor: 0,
            pinned_service: None,
            freshness: TeamReplicaFreshness::Unconfigured,
            last_successful_sync_unix_seconds: None,
            next_service_sequence: 1,
            sequenced_revisions: Vec::new(),
            service_inbox: Vec::new(),
        })
    }

    fn validate(
        &self,
        role: ReplicaRole,
        team_id: &TeamId,
        workspace_id: &WorkspaceMemoryId,
    ) -> Result<(), TeamReplicationError> {
        if self.schema_version != TEAM_REPLICATION_SCHEMA_VERSION
            || self.role != role
            || &self.team_id != team_id
            || &self.workspace_id != workspace_id
            || self.next_operation_sequence == 0
            || self.next_service_sequence == 0
            || self.revisions.len() > MAX_TEAM_REPLICA_REVISIONS
            || self.outbox.len() > MAX_TEAM_REPLICA_OUTBOX
            || self.service_inbox.len() > MAX_TEAM_REPLICA_INBOX
            || self.pull_cursor > MAX_TEAM_REPLICA_REVISIONS as u64
            || self
                .last_successful_sync_unix_seconds
                .is_some_and(|timestamp| timestamp < 0)
        {
            return Err(TeamReplicationError::CorruptReplica);
        }

        let mut revision_digests = BTreeSet::new();
        let mut revision_bytes = 0_usize;
        for revision in &self.revisions {
            revision
                .validate()
                .map_err(|_| TeamReplicationError::CorruptReplica)?;
            if revision.provenance.scope != MemoryRecordScope::TeamShared
                || revision.provenance.workspace_id.as_deref() != Some(workspace_id.as_str())
                || (revision.state == MemoryRevisionState::Active
                    && !revision.tags.iter().any(|tag| tag == TECHNICAL_LESSON_TAG))
                || !revision_digests.insert(revision.record_digest.clone())
            {
                return Err(TeamReplicationError::CorruptReplica);
            }
            revision_bytes = revision_bytes
                .checked_add(revision.content.len())
                .ok_or(TeamReplicationError::CorruptReplica)?;
            if revision_bytes > MAX_REPLICA_PLAINTEXT_BYTES {
                return Err(TeamReplicationError::CapacityExceeded {
                    resource: "revision bytes",
                });
            }
        }

        let mut operation_ids = BTreeSet::new();
        let mut outbox_revision_digests = BTreeSet::new();
        for mutation in &self.outbox {
            if mutation.operation_id.is_empty()
                || mutation.operation_id.len() > MAX_OPERATION_ID_BYTES
                || !operation_ids.insert(mutation.operation_id.as_str())
                || !outbox_revision_digests.insert(&mutation.revision_digest)
                || !revision_digests.contains(&mutation.revision_digest)
            {
                return Err(TeamReplicationError::CorruptReplica);
            }
            let revision = self
                .revisions
                .iter()
                .find(|revision| revision.record_digest == mutation.revision_digest)
                .ok_or(TeamReplicationError::CorruptReplica)?;
            validate_mutation_shape(mutation.operation, revision)?;
        }

        validate_pinned_service(self.pinned_service.as_ref())?;
        self.validate_role_state(role)
    }

    fn validate_role_state(&self, role: ReplicaRole) -> Result<(), TeamReplicationError> {
        match role {
            ReplicaRole::Client => {
                if !self.sequenced_revisions.is_empty() || !self.service_inbox.is_empty() {
                    return Err(TeamReplicationError::CorruptReplica);
                }
                let client_state_is_valid = match self.freshness {
                    TeamReplicaFreshness::Unconfigured => {
                        self.pinned_service.is_none()
                            && self.last_successful_sync_unix_seconds.is_none()
                            && self.pull_cursor == 0
                    }
                    TeamReplicaFreshness::NeverSynchronized => {
                        self.pinned_service.is_some()
                            && self.last_successful_sync_unix_seconds.is_none()
                            && self.pull_cursor == 0
                    }
                    TeamReplicaFreshness::Current => {
                        self.pinned_service.is_some()
                            && self.last_successful_sync_unix_seconds.is_some()
                            && self.outbox.is_empty()
                    }
                    TeamReplicaFreshness::Stale
                    | TeamReplicaFreshness::Partial
                    | TeamReplicaFreshness::Unauthorized
                    | TeamReplicaFreshness::Corrupt => self.pinned_service.is_some(),
                };
                if !client_state_is_valid {
                    return Err(TeamReplicationError::CorruptReplica);
                }
            }
            ReplicaRole::Service => {
                if !self.outbox.is_empty()
                    || self.pinned_service.is_some()
                    || self.pull_cursor != 0
                    || self.last_successful_sync_unix_seconds.is_some()
                    || !matches!(
                        self.freshness,
                        TeamReplicaFreshness::Unconfigured | TeamReplicaFreshness::Current
                    )
                {
                    return Err(TeamReplicationError::CorruptReplica);
                }
                validate_service_sequences(self)?;
                validate_service_inbox(self)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptedReplicaEnvelope {
    schema_version: u32,
    role: ReplicaRole,
    team_id: TeamId,
    workspace_id: WorkspaceMemoryId,
    nonce_base64: String,
    ciphertext_base64: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ReplicaAad<'a> {
    schema_version: u32,
    role: ReplicaRole,
    team_id: &'a TeamId,
    workspace_id: &'a WorkspaceMemoryId,
}

struct ReplicaRuntime {
    generation: StorageGeneration,
    state: ReplicaFileState,
    database: MemoryDb,
}

struct AuthorizedMutation {
    operation: TeamMemoryOperation,
    request_digest: ContentDigest,
    permit: TeamOperationPermit,
}

struct AuthorizedPush {
    transport_permit: TeamOperationPermit,
    mutations: Vec<AuthorizedMutation>,
}

/// Host-owned encrypted replica. Network synchronization is supervised by the
/// transport owner; this type owns all durable local state and cached reads.
pub struct TeamReplica {
    authority: TeamAuthorityStore,
    storage: PersistentStorage,
    target: PathBuf,
    role: ReplicaRole,
    runtime: Mutex<ReplicaRuntime>,
}

impl fmt::Debug for TeamReplica {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("TeamReplica");
        debug
            .field("team_id", self.authority.team_id())
            .field("workspace_id", self.authority.workspace_id())
            .field("role", &self.role);
        match self.runtime.lock() {
            Ok(runtime) => debug.field("replica_id", &runtime.state.replica_id),
            Err(_) => debug.field("replica_id", &"[poisoned]"),
        };
        debug.finish_non_exhaustive()
    }
}

impl TeamReplica {
    /// Open or create the client-side encrypted replica for an enrolled team.
    /// Opening never starts network I/O.
    ///
    /// # Errors
    ///
    /// Returns a typed authority, persistence, integrity, or capacity error if
    /// the enrolled replica cannot be opened safely.
    pub fn open_client(authority: TeamAuthorityStore) -> Result<Self, TeamReplicationError> {
        require_active_replica_authority(&authority, ReplicaRole::Client)?;
        Self::open(authority, ReplicaRole::Client)
    }

    /// Open or create the service-side encrypted authoritative replica.
    /// Opening never starts a listener.
    ///
    /// # Errors
    ///
    /// Returns a typed authority, persistence, integrity, or capacity error if
    /// the service replica cannot be opened safely.
    pub fn open_service(authority: TeamAuthorityStore) -> Result<Self, TeamReplicationError> {
        require_active_replica_authority(&authority, ReplicaRole::Service)?;
        Self::open(authority, ReplicaRole::Service)
    }

    fn open(
        authority: TeamAuthorityStore,
        role: ReplicaRole,
    ) -> Result<Self, TeamReplicationError> {
        let anchored_identity = authority.replica_identity(role.authority_role())?;
        let storage = authority.replica_storage();
        let target = PathBuf::from(format!(
            "{}-{}.json",
            role.target_prefix(),
            authority.team_id().as_str()
        ));
        let read = storage.read(&target, FileClass::Evidence)?;
        let generation = read.generation();
        if generation == StorageGeneration::Missing && anchored_identity.is_some() {
            return Err(TeamReplicationError::RecoveryRequired {
                reason: "encrypted team replica is missing after its identity was pinned",
            });
        }
        let state = read.expose_bytes(|bytes| {
            bytes.map_or_else(
                || {
                    ReplicaFileState::new(
                        role,
                        authority.team_id().clone(),
                        authority.workspace_id().clone(),
                    )
                },
                |bytes| decrypt_state(&authority, role, bytes),
            )
        })?;
        state.validate(role, authority.team_id(), authority.workspace_id())?;
        if anchored_identity
            .as_ref()
            .is_some_and(|(replica_id, store_id)| {
                replica_id != state.replica_id.as_str() || *store_id != state.store_id
            })
        {
            return Err(TeamReplicationError::RecoveryRequired {
                reason: "encrypted team replica identity changed",
            });
        }
        let database = materialize_database(&state)?;
        let replica = Self {
            authority,
            storage,
            target,
            role,
            runtime: Mutex::new(ReplicaRuntime {
                generation,
                state,
                database,
            }),
        };
        if generation == StorageGeneration::Missing {
            let mut runtime = replica.lock_runtime()?;
            replica.commit_runtime(&mut runtime)?;
        }
        let status = replica.status()?;
        replica.authority.pin_replica_identity(
            role.authority_role(),
            status.replica_id.as_str(),
            replica.lock_current_runtime()?.state.store_id,
        )?;
        Ok(replica)
    }

    fn lock_runtime(&self) -> Result<MutexGuard<'_, ReplicaRuntime>, TeamReplicationError> {
        self.runtime
            .lock()
            .map_err(|_| TeamReplicationError::RecoveryRequired {
                reason: "replica state lock is poisoned",
            })
    }

    fn lock_current_runtime(&self) -> Result<MutexGuard<'_, ReplicaRuntime>, TeamReplicationError> {
        let mut runtime = self.lock_runtime()?;
        let read = self.storage.read(&self.target, FileClass::Evidence)?;
        if read.generation() == runtime.generation {
            return Ok(runtime);
        }
        if read.generation() == StorageGeneration::Missing {
            return Err(TeamReplicationError::RecoveryRequired {
                reason: "encrypted team replica disappeared while in use",
            });
        }
        let replacement = read.expose_bytes(|bytes| {
            let bytes = bytes.ok_or(TeamReplicationError::CorruptReplica)?;
            decrypt_state(&self.authority, self.role, bytes)
        })?;
        replacement.validate(
            self.role,
            self.authority.team_id(),
            self.authority.workspace_id(),
        )?;
        validate_forward_refresh(&runtime.state, &replacement)?;
        let database = materialize_database(&replacement)?;
        runtime.generation = read.generation();
        runtime.state = replacement;
        runtime.database = database;
        Ok(runtime)
    }

    /// Return redacted durable state without reading lesson content.
    ///
    /// # Errors
    ///
    /// Returns a typed persistence or integrity error if current replica state
    /// cannot be read and validated.
    pub fn status(&self) -> Result<TeamReplicaStatus, TeamReplicationError> {
        let runtime = self.lock_current_runtime()?;
        Ok(TeamReplicaStatus {
            schema_version: TEAM_REPLICATION_SCHEMA_VERSION,
            team_id: runtime.state.team_id.clone(),
            workspace_id: runtime.state.workspace_id.clone(),
            replica_id: runtime.state.replica_id.clone(),
            freshness: runtime.state.freshness,
            revisions: runtime.state.revisions.len(),
            queued_mutations: runtime.state.outbox.len(),
            pull_cursor: runtime.state.pull_cursor,
            service_configured: runtime.state.pinned_service.is_some(),
            last_successful_sync_unix_seconds: runtime.state.last_successful_sync_unix_seconds,
        })
    }

    /// Produce a signed public descriptor for this service replica. The caller
    /// supplies the externally reachable HTTPS origin and exact DER leaf
    /// certificate that clients must pin.
    ///
    /// # Errors
    ///
    /// Returns a typed protocol, authority, persistence, or capacity error if
    /// the descriptor cannot be validated and signed.
    pub fn service_descriptor(
        &self,
        endpoint: &str,
        certificate_der: &[u8],
    ) -> Result<TeamServiceDescriptor, TeamReplicationError> {
        if self.role != ReplicaRole::Service {
            return Err(TeamReplicationError::InvalidProtocol);
        }
        validate_service_endpoint(endpoint)?;
        validate_certificate(certificate_der)?;
        let (team_id, workspace_id, service_replica_id) = {
            let runtime = self.lock_current_runtime()?;
            (
                runtime.state.team_id.clone(),
                runtime.state.workspace_id.clone(),
                runtime.state.replica_id.clone(),
            )
        };
        let service_principal_id = self.authority.local_principal_id()?;
        let unsigned = UnsignedServiceDescriptor {
            schema_version: TEAM_REPLICATION_SCHEMA_VERSION,
            team_id: &team_id,
            workspace_id: &workspace_id,
            service_replica_id: &service_replica_id,
            service_principal_id: &service_principal_id,
            endpoint,
            certificate_der_base64: BASE64_STANDARD.encode(certificate_der),
            certificate_digest: ContentDigest::sha256(certificate_der),
        };
        let request_digest = canonical_digest(&unsigned)?;
        let grant = self.authority.issue_grant(
            TeamMemoryOperation::Admin,
            request_digest,
            SERVICE_DESCRIPTOR_GRANT_TTL_SECONDS,
        )?;
        Ok(TeamServiceDescriptor {
            schema_version: unsigned.schema_version,
            team_id: unsigned.team_id.clone(),
            workspace_id: unsigned.workspace_id.clone(),
            service_replica_id: unsigned.service_replica_id.clone(),
            service_principal_id: unsigned.service_principal_id.clone(),
            endpoint: unsigned.endpoint.to_string(),
            certificate_der_base64: unsigned.certificate_der_base64,
            certificate_digest: unsigned.certificate_digest,
            grant,
        })
    }

    /// Authenticate and pin one service descriptor in encrypted host-owned
    /// state. Replica or principal replacement is always rejected; the host
    /// may explicitly rotate only the endpoint and certificate for the same
    /// pinned service identity.
    ///
    /// # Errors
    ///
    /// Returns a typed protocol, authorization, identity, persistence, or
    /// concurrency error if the descriptor cannot be pinned atomically.
    pub fn configure_service(
        &self,
        descriptor: &TeamServiceDescriptor,
        allow_transport_rotation: bool,
    ) -> Result<TeamReplicaStatus, TeamReplicationError> {
        if self.role != ReplicaRole::Client {
            return Err(TeamReplicationError::InvalidProtocol);
        }
        validate_service_descriptor(
            descriptor,
            self.authority.team_id(),
            self.authority.workspace_id(),
        )?;
        let request_digest = descriptor_unsigned_digest(descriptor)?;
        if descriptor.grant.principal_id() != &descriptor.service_principal_id
            || descriptor.grant.operation() != TeamMemoryOperation::Admin
            || descriptor.grant.request_digest() != request_digest
        {
            return Err(TeamReplicationError::InvalidProtocol);
        }
        let pinned = PinnedTeamService {
            endpoint: descriptor.endpoint.clone(),
            service_replica_id: descriptor.service_replica_id.clone(),
            service_principal_id: descriptor.service_principal_id.clone(),
            certificate_der_base64: descriptor.certificate_der_base64.clone(),
            certificate_digest: descriptor.certificate_digest,
        };
        validate_pinned_service(Some(&pinned))?;
        {
            let runtime = self.lock_current_runtime()?;
            ensure_client_runtime(&runtime)?;
            if let Some(existing) = &runtime.state.pinned_service {
                if existing != &pinned
                    && (existing.service_replica_id != pinned.service_replica_id
                        || existing.service_principal_id != pinned.service_principal_id
                        || !allow_transport_rotation)
                {
                    return Err(TeamReplicationError::ServiceIdentityMismatch);
                }
            }
        }
        let permit = match self.authority.authorize_grant(
            &descriptor.grant,
            TeamMemoryOperation::Admin,
            request_digest,
        )? {
            TeamAuthorizationOutcome::Authorized(permit) => permit,
            TeamAuthorizationOutcome::Denied { .. } => {
                return Err(TeamReplicationError::Unauthorized);
            }
        };
        let mut runtime = self.lock_current_runtime()?;
        ensure_client_runtime(&runtime)?;
        self.authority
            .validate_permit(&permit, TeamMemoryOperation::Admin, request_digest)?;
        let replacing_transport = if let Some(existing) = &runtime.state.pinned_service {
            if existing == &pinned {
                return Ok(Self::status_from_runtime(&runtime));
            }
            if existing.service_replica_id != pinned.service_replica_id
                || existing.service_principal_id != pinned.service_principal_id
                || !allow_transport_rotation
            {
                return Err(TeamReplicationError::ServiceIdentityMismatch);
            }
            true
        } else {
            false
        };
        let previous = runtime.state.clone();
        runtime.state.pinned_service = Some(pinned);
        runtime.state.freshness = if replacing_transport {
            TeamReplicaFreshness::Stale
        } else {
            TeamReplicaFreshness::NeverSynchronized
        };
        if let Err(error) = self.commit_runtime(&mut runtime) {
            restore_runtime(&mut runtime, previous)?;
            return Err(error);
        }
        Ok(Self::status_from_runtime(&runtime))
    }

    fn status_from_runtime(runtime: &ReplicaRuntime) -> TeamReplicaStatus {
        TeamReplicaStatus {
            schema_version: TEAM_REPLICATION_SCHEMA_VERSION,
            team_id: runtime.state.team_id.clone(),
            workspace_id: runtime.state.workspace_id.clone(),
            replica_id: runtime.state.replica_id.clone(),
            freshness: runtime.state.freshness,
            revisions: runtime.state.revisions.len(),
            queued_mutations: runtime.state.outbox.len(),
            pull_cursor: runtime.state.pull_cursor,
            service_configured: runtime.state.pinned_service.is_some(),
            last_successful_sync_unix_seconds: runtime.state.last_successful_sync_unix_seconds,
        }
    }

    pub(crate) fn pinned_service(&self) -> Result<PinnedTeamService, TeamReplicationError> {
        let runtime = self.lock_current_runtime()?;
        ensure_client_runtime(&runtime)?;
        runtime
            .state
            .pinned_service
            .clone()
            .ok_or(TeamReplicationError::Unconfigured)
    }

    pub(crate) fn mark_sync_failure(
        &self,
        error: &TeamReplicationError,
    ) -> Result<(), TeamReplicationError> {
        let mut runtime = self.lock_current_runtime()?;
        ensure_client_runtime(&runtime)?;
        let next_freshness = match error.failure_class() {
            TeamReplicationFailureClass::AuthorizationDenied => TeamReplicaFreshness::Unauthorized,
            TeamReplicationFailureClass::InvalidRequest
            | TeamReplicationFailureClass::IntegrityFailure => TeamReplicaFreshness::Corrupt,
            TeamReplicationFailureClass::Unconfigured => TeamReplicaFreshness::Unconfigured,
            TeamReplicationFailureClass::CapacityExceeded
            | TeamReplicationFailureClass::ConcurrentUpdate
            | TeamReplicationFailureClass::Unavailable => TeamReplicaFreshness::Stale,
        };
        if runtime.state.freshness == next_freshness {
            return Ok(());
        }
        let previous = runtime.state.clone();
        runtime.state.freshness = next_freshness;
        if let Err(commit_error) = self.commit_runtime(&mut runtime) {
            restore_runtime(&mut runtime, previous)?;
            return Err(commit_error);
        }
        drop(runtime);
        Ok(())
    }

    pub(crate) fn synchronization_progress(
        &self,
    ) -> Result<(usize, u64, TeamReplicaFreshness), TeamReplicationError> {
        let runtime = self.lock_current_runtime()?;
        ensure_client_runtime(&runtime)?;
        Ok((
            runtime.state.outbox.len(),
            runtime.state.pull_cursor,
            runtime.state.freshness,
        ))
    }

    pub(crate) fn prepare_push(&self) -> Result<Option<PushRequest>, TeamReplicationError> {
        let (client_replica_id, mut mutations) = {
            let runtime = self.lock_current_runtime()?;
            ensure_client_runtime(&runtime)?;
            if runtime.state.pinned_service.is_none() {
                return Err(TeamReplicationError::Unconfigured);
            }
            let mut mutations =
                Vec::with_capacity(runtime.state.outbox.len().min(MAX_TEAM_REPLICATION_BATCH));
            for queued in runtime.state.outbox.iter().take(MAX_TEAM_REPLICATION_BATCH) {
                let revision = runtime
                    .state
                    .revisions
                    .iter()
                    .find(|revision| revision.record_digest == queued.revision_digest)
                    .cloned()
                    .ok_or(TeamReplicationError::CorruptReplica)?;
                mutations.push(MutationPayload {
                    operation_id: queued.operation_id.clone(),
                    operation: queued.operation,
                    revision,
                });
            }
            (runtime.state.replica_id.clone(), mutations)
        };
        if mutations.is_empty() {
            return Ok(None);
        }
        let payload = loop {
            let retry_key = push_retry_key(&client_replica_id, &mutations)?;
            let candidate = PushPayload {
                schema_version: TEAM_REPLICATION_SCHEMA_VERSION,
                team_id: self.authority.team_id().clone(),
                workspace_id: self.authority.workspace_id().clone(),
                client_replica_id: client_replica_id.clone(),
                retry_key,
                mutations: mutations.clone(),
            };
            if wire_value_fits_with_grants(&candidate, candidate.mutations.len() + 1)? {
                break candidate;
            }
            mutations.pop();
            if mutations.is_empty() {
                return Err(TeamReplicationError::CapacityExceeded {
                    resource: "single replication mutation bytes",
                });
            }
        };
        validate_push_payload(&payload)?;
        let mut mutation_grants = Vec::with_capacity(payload.mutations.len());
        for mutation in &payload.mutations {
            let grant = self.authority.issue_grant(
                mutation.operation,
                canonical_digest(mutation)?,
                LOCAL_GRANT_TTL_SECONDS,
            )?;
            ensure_operation_grant_wire_size(&grant)?;
            mutation_grants.push(grant);
        }
        let payload_digest = canonical_digest(&payload)?;
        let transport_grant = self.authority.issue_grant(
            TeamMemoryOperation::ReplicatePush,
            payload_digest,
            LOCAL_GRANT_TTL_SECONDS,
        )?;
        ensure_operation_grant_wire_size(&transport_grant)?;
        let request = PushRequest {
            payload,
            transport_grant,
            mutation_grants,
        };
        ensure_wire_message_size(&request, "push request bytes")?;
        Ok(Some(request))
    }

    pub(crate) fn apply_push_ack(
        &self,
        request: &PushRequest,
        response: &PushResponse,
    ) -> Result<usize, TeamReplicationError> {
        validate_push_request(
            request,
            self.authority.team_id(),
            self.authority.workspace_id(),
        )?;
        validate_push_response(
            response,
            request,
            self.authority.team_id(),
            self.authority.workspace_id(),
            &self.pinned_service()?,
        )?;
        let response_digest = canonical_digest(&response.ack)?;
        if response.grant.principal_id() != &self.pinned_service()?.service_principal_id
            || response.grant.operation() != TeamMemoryOperation::ReplicatePush
            || response.grant.request_digest() != response_digest
        {
            return Err(TeamReplicationError::ServiceIdentityMismatch);
        }
        let permit = match self.authority.authorize_grant(
            &response.grant,
            TeamMemoryOperation::ReplicatePush,
            response_digest,
        )? {
            TeamAuthorizationOutcome::Authorized(permit) => permit,
            TeamAuthorizationOutcome::Denied { .. } => {
                return Err(TeamReplicationError::Unauthorized);
            }
        };
        let local_authorization = self.authorize_current_local_push(request)?;
        let accepted = response
            .ack
            .accepted_revision_digests
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let expected = request
            .payload
            .mutations
            .iter()
            .map(|mutation| mutation.revision.record_digest.clone())
            .collect::<BTreeSet<_>>();
        if accepted != expected {
            return Err(TeamReplicationError::InvalidProtocol);
        }
        let mut runtime = self.lock_current_runtime()?;
        ensure_client_runtime(&runtime)?;
        if runtime.state.replica_id != request.payload.client_replica_id {
            return Err(TeamReplicationError::RecoveryRequired {
                reason: "push acknowledgement targets a replaced client replica",
            });
        }
        self.authority.validate_permit(
            &permit,
            TeamMemoryOperation::ReplicatePush,
            response_digest,
        )?;
        let request_digest = canonical_digest(&request.payload)?;
        self.authority.validate_permit(
            &local_authorization.transport_permit,
            TeamMemoryOperation::ReplicatePush,
            request_digest,
        )?;
        for authorized in &local_authorization.mutations {
            self.authority.validate_permit(
                &authorized.permit,
                authorized.operation,
                authorized.request_digest,
            )?;
        }
        let previous = runtime.state.clone();
        runtime
            .state
            .outbox
            .retain(|mutation| !accepted.contains(&mutation.revision_digest));
        runtime.state.freshness = TeamReplicaFreshness::Partial;
        if let Err(error) = self.commit_runtime(&mut runtime) {
            restore_runtime(&mut runtime, previous)?;
            return Err(error);
        }
        drop(runtime);
        // Another handle may already have consumed some or all of this exact
        // acknowledgement. The request itself proves every accepted digest
        // was queued; retaining/removing against the refreshed state makes the
        // acknowledgement idempotent without losing newer outbox entries.
        Ok(accepted.len())
    }

    pub(crate) fn prepare_pull(&self) -> Result<PullRequest, TeamReplicationError> {
        let (client_replica_id, after_cursor) = {
            let runtime = self.lock_current_runtime()?;
            ensure_client_runtime(&runtime)?;
            if runtime.state.pinned_service.is_none() {
                return Err(TeamReplicationError::Unconfigured);
            }
            (runtime.state.replica_id.clone(), runtime.state.pull_cursor)
        };
        let payload = PullPayload {
            schema_version: TEAM_REPLICATION_SCHEMA_VERSION,
            team_id: self.authority.team_id().clone(),
            workspace_id: self.authority.workspace_id().clone(),
            client_replica_id,
            after_cursor,
            limit: MAX_TEAM_REPLICATION_BATCH,
        };
        let payload_digest = canonical_digest(&payload)?;
        let grant = self.authority.issue_grant(
            TeamMemoryOperation::ReplicatePull,
            payload_digest,
            LOCAL_GRANT_TTL_SECONDS,
        )?;
        Ok(PullRequest { payload, grant })
    }

    pub(crate) fn apply_pull_ack(
        &self,
        request: &PullRequest,
        response: &PullResponse,
        synchronized_at_unix_seconds: i64,
    ) -> Result<TeamSyncReport, TeamReplicationError> {
        validate_pull_request(
            request,
            self.authority.team_id(),
            self.authority.workspace_id(),
        )?;
        let pinned = self.pinned_service()?;
        validate_pull_response(
            response,
            request,
            self.authority.team_id(),
            self.authority.workspace_id(),
            &pinned,
        )?;
        let response_digest = canonical_digest(&response.ack)?;
        if response.grant.principal_id() != &pinned.service_principal_id
            || response.grant.operation() != TeamMemoryOperation::ReplicatePull
            || response.grant.request_digest() != response_digest
        {
            return Err(TeamReplicationError::ServiceIdentityMismatch);
        }
        let permit = match self.authority.authorize_grant(
            &response.grant,
            TeamMemoryOperation::ReplicatePull,
            response_digest,
        )? {
            TeamAuthorizationOutcome::Authorized(permit) => permit,
            TeamAuthorizationOutcome::Denied { .. } => {
                return Err(TeamReplicationError::Unauthorized);
            }
        };
        let local_request_digest = canonical_digest(&request.payload)?;
        let local_permit =
            self.authorize_local(TeamMemoryOperation::ReplicatePull, local_request_digest)?;

        let mut runtime = self.lock_current_runtime()?;
        ensure_client_runtime(&runtime)?;
        if runtime.state.replica_id != request.payload.client_replica_id {
            return Err(TeamReplicationError::RecoveryRequired {
                reason: "pull acknowledgement targets a replaced client replica",
            });
        }
        self.authority.validate_permit(
            &permit,
            TeamMemoryOperation::ReplicatePull,
            response_digest,
        )?;
        self.authority.validate_permit(
            &local_permit,
            TeamMemoryOperation::ReplicatePull,
            local_request_digest,
        )?;
        if runtime.state.pull_cursor != request.payload.after_cursor {
            return Err(TeamReplicationError::ConcurrentUpdate);
        }
        let previous = runtime.state.clone();
        for entry in &response.ack.revisions {
            if !runtime
                .state
                .revisions
                .iter()
                .any(|revision| revision.record_digest == entry.revision.record_digest)
            {
                if runtime.state.revisions.len() >= MAX_TEAM_REPLICA_REVISIONS {
                    restore_runtime(&mut runtime, previous)?;
                    return Err(TeamReplicationError::CapacityExceeded {
                        resource: "revisions",
                    });
                }
                if let Err(error) = runtime.database.apply_revision(&entry.revision) {
                    restore_runtime(&mut runtime, previous)?;
                    return Err(TeamReplicationError::Store(error));
                }
                runtime.state.revisions.push(entry.revision.clone());
            }
        }
        runtime.state.pull_cursor = response.ack.next_cursor;
        runtime.state.last_successful_sync_unix_seconds = Some(synchronized_at_unix_seconds);
        runtime.state.freshness = if response.ack.more_available || !runtime.state.outbox.is_empty()
        {
            TeamReplicaFreshness::Partial
        } else {
            TeamReplicaFreshness::Current
        };
        if let Err(error) = self.commit_runtime(&mut runtime) {
            restore_runtime(&mut runtime, previous)?;
            return Err(error);
        }
        Ok(TeamSyncReport {
            schema_version: TEAM_REPLICATION_SCHEMA_VERSION,
            pushed_revisions: 0,
            pulled_revisions: response.ack.revisions.len(),
            remaining_outbox: runtime.state.outbox.len(),
            pull_cursor: runtime.state.pull_cursor,
            server_cursor: response.ack.server_cursor,
            more_available: response.ack.more_available,
            freshness: runtime.state.freshness,
        })
    }

    pub(crate) fn handle_push(
        &self,
        request: &PushRequest,
    ) -> Result<PushResponse, TeamReplicationError> {
        if self.role != ReplicaRole::Service {
            return Err(TeamReplicationError::InvalidProtocol);
        }
        validate_push_request(
            request,
            self.authority.team_id(),
            self.authority.workspace_id(),
        )?;
        let payload_digest = canonical_digest(&request.payload)?;
        let transport_permit = match self.authority.authorize_grant(
            &request.transport_grant,
            TeamMemoryOperation::ReplicatePush,
            payload_digest,
        )? {
            TeamAuthorizationOutcome::Authorized(permit) => permit,
            TeamAuthorizationOutcome::Denied { .. } => {
                return Err(TeamReplicationError::Unauthorized);
            }
        };
        let service_permit = self.authorize_local(TeamMemoryOperation::Admin, payload_digest)?;

        if let Some(ack) = self.existing_push_ack(
            &request.payload,
            payload_digest,
            &transport_permit,
            &service_permit,
        )? {
            return self.sign_push_ack(ack);
        }
        let mutation_permits = self.authorize_push_mutations(request)?;
        let ack = self.apply_authorized_push(
            request,
            payload_digest,
            &transport_permit,
            &service_permit,
            &mutation_permits,
        )?;
        self.sign_push_ack(ack)
    }

    fn authorize_push_mutations(
        &self,
        request: &PushRequest,
    ) -> Result<Vec<AuthorizedMutation>, TeamReplicationError> {
        let mut mutation_permits = Vec::with_capacity(request.payload.mutations.len());
        for (mutation, grant) in request
            .payload
            .mutations
            .iter()
            .zip(&request.mutation_grants)
        {
            let mutation_digest = canonical_digest(mutation)?;
            if grant.principal_id() != request.transport_grant.principal_id()
                || grant.operation() != mutation.operation
                || grant.request_digest() != mutation_digest
            {
                return Err(TeamReplicationError::InvalidProtocol);
            }
            let permit =
                match self
                    .authority
                    .authorize_grant(grant, mutation.operation, mutation_digest)?
                {
                    TeamAuthorizationOutcome::Authorized(permit) => permit,
                    TeamAuthorizationOutcome::Denied { .. } => {
                        return Err(TeamReplicationError::Unauthorized);
                    }
                };
            mutation_permits.push(AuthorizedMutation {
                operation: mutation.operation,
                request_digest: mutation_digest,
                permit,
            });
        }
        Ok(mutation_permits)
    }

    fn authorize_current_local_push(
        &self,
        request: &PushRequest,
    ) -> Result<AuthorizedPush, TeamReplicationError> {
        let payload_digest = canonical_digest(&request.payload)?;
        let transport_permit =
            self.authorize_local(TeamMemoryOperation::ReplicatePush, payload_digest)?;
        let mut mutation_permits = Vec::with_capacity(request.payload.mutations.len());
        for mutation in &request.payload.mutations {
            let mutation_digest = canonical_digest(mutation)?;
            let permit = self.authorize_local(mutation.operation, mutation_digest)?;
            mutation_permits.push(AuthorizedMutation {
                operation: mutation.operation,
                request_digest: mutation_digest,
                permit,
            });
        }
        Ok(AuthorizedPush {
            transport_permit,
            mutations: mutation_permits,
        })
    }

    fn apply_authorized_push(
        &self,
        request: &PushRequest,
        payload_digest: ContentDigest,
        transport_permit: &TeamOperationPermit,
        service_permit: &TeamOperationPermit,
        mutation_permits: &[AuthorizedMutation],
    ) -> Result<PushAckPayload, TeamReplicationError> {
        let mut runtime = self.lock_current_runtime()?;
        if runtime.state.role != ReplicaRole::Service {
            return Err(TeamReplicationError::InvalidProtocol);
        }
        self.authority.validate_permit(
            transport_permit,
            TeamMemoryOperation::ReplicatePush,
            payload_digest,
        )?;
        self.authority.validate_permit(
            service_permit,
            TeamMemoryOperation::Admin,
            payload_digest,
        )?;
        for authorized in mutation_permits {
            self.authority.validate_permit(
                &authorized.permit,
                authorized.operation,
                authorized.request_digest,
            )?;
        }
        let previous = runtime.state.clone();
        let mut accepted = Vec::with_capacity(request.payload.mutations.len());
        for mutation in &request.payload.mutations {
            let already_present = runtime
                .state
                .revisions
                .iter()
                .any(|revision| revision.record_digest == mutation.revision.record_digest);
            if !already_present {
                if runtime.state.revisions.len() >= MAX_TEAM_REPLICA_REVISIONS {
                    restore_runtime(&mut runtime, previous)?;
                    return Err(TeamReplicationError::CapacityExceeded {
                        resource: "service revisions",
                    });
                }
                if let Err(error) = runtime.database.apply_revision(&mutation.revision) {
                    restore_runtime(&mut runtime, previous)?;
                    return Err(TeamReplicationError::Store(error));
                }
                let sequence = runtime.state.next_service_sequence;
                let Some(next_sequence) = sequence.checked_add(1) else {
                    restore_runtime(&mut runtime, previous)?;
                    return Err(TeamReplicationError::CapacityExceeded {
                        resource: "service sequence",
                    });
                };
                runtime.state.next_service_sequence = next_sequence;
                runtime.state.revisions.push(mutation.revision.clone());
                runtime.state.sequenced_revisions.push(SequencedRevision {
                    sequence,
                    revision: mutation.revision.clone(),
                });
            }
            accepted.push(mutation.revision.record_digest.clone());
        }
        let server_cursor = runtime.state.next_service_sequence.saturating_sub(1);
        if runtime.state.service_inbox.len() >= MAX_TEAM_REPLICA_INBOX {
            runtime.state.service_inbox.remove(0);
        }
        runtime.state.service_inbox.push(ServiceInboxReceipt {
            client_replica_id: request.payload.client_replica_id.clone(),
            retry_key: request.payload.retry_key.clone(),
            payload_digest,
            accepted_revision_digests: accepted.clone(),
            server_cursor,
        });
        runtime.state.freshness = TeamReplicaFreshness::Current;
        if let Err(error) = self.commit_runtime(&mut runtime) {
            restore_runtime(&mut runtime, previous)?;
            return Err(error);
        }
        let service_replica_id = runtime.state.replica_id.clone();
        drop(runtime);
        Ok(PushAckPayload {
            schema_version: TEAM_REPLICATION_SCHEMA_VERSION,
            team_id: request.payload.team_id.clone(),
            workspace_id: request.payload.workspace_id.clone(),
            service_replica_id,
            client_replica_id: request.payload.client_replica_id.clone(),
            retry_key: request.payload.retry_key.clone(),
            request_digest: payload_digest,
            accepted_revision_digests: accepted,
            server_cursor,
        })
    }

    fn existing_push_ack(
        &self,
        payload: &PushPayload,
        payload_digest: ContentDigest,
        permit: &TeamOperationPermit,
        service_permit: &TeamOperationPermit,
    ) -> Result<Option<PushAckPayload>, TeamReplicationError> {
        let runtime = self.lock_current_runtime()?;
        self.authority.validate_permit(
            permit,
            TeamMemoryOperation::ReplicatePush,
            payload_digest,
        )?;
        self.authority.validate_permit(
            service_permit,
            TeamMemoryOperation::Admin,
            payload_digest,
        )?;
        let existing = runtime.state.service_inbox.iter().find(|receipt| {
            receipt.client_replica_id == payload.client_replica_id
                && receipt.retry_key == payload.retry_key
        });
        let Some(existing) = existing else {
            return Ok(None);
        };
        if existing.payload_digest != payload_digest {
            return Err(TeamReplicationError::InvalidProtocol);
        }
        Ok(Some(PushAckPayload {
            schema_version: TEAM_REPLICATION_SCHEMA_VERSION,
            team_id: payload.team_id.clone(),
            workspace_id: payload.workspace_id.clone(),
            service_replica_id: runtime.state.replica_id.clone(),
            client_replica_id: payload.client_replica_id.clone(),
            retry_key: payload.retry_key.clone(),
            request_digest: payload_digest,
            accepted_revision_digests: existing.accepted_revision_digests.clone(),
            server_cursor: existing.server_cursor,
        }))
    }

    fn sign_push_ack(&self, ack: PushAckPayload) -> Result<PushResponse, TeamReplicationError> {
        let digest = canonical_digest(&ack)?;
        let grant = self.authority.issue_grant(
            TeamMemoryOperation::ReplicatePush,
            digest,
            LOCAL_GRANT_TTL_SECONDS,
        )?;
        ensure_operation_grant_wire_size(&grant)?;
        let response = PushResponse { ack, grant };
        ensure_wire_message_size(&response, "push response bytes")?;
        Ok(response)
    }

    pub(crate) fn handle_pull(
        &self,
        request: &PullRequest,
    ) -> Result<PullResponse, TeamReplicationError> {
        if self.role != ReplicaRole::Service {
            return Err(TeamReplicationError::InvalidProtocol);
        }
        validate_pull_request(
            request,
            self.authority.team_id(),
            self.authority.workspace_id(),
        )?;
        let payload_digest = canonical_digest(&request.payload)?;
        let permit = match self.authority.authorize_grant(
            &request.grant,
            TeamMemoryOperation::ReplicatePull,
            payload_digest,
        )? {
            TeamAuthorizationOutcome::Authorized(permit) => permit,
            TeamAuthorizationOutcome::Denied { .. } => {
                return Err(TeamReplicationError::Unauthorized);
            }
        };
        let service_permit = self.authorize_local(TeamMemoryOperation::Admin, payload_digest)?;
        let runtime = self.lock_current_runtime()?;
        self.authority.validate_permit(
            &permit,
            TeamMemoryOperation::ReplicatePull,
            payload_digest,
        )?;
        self.authority.validate_permit(
            &service_permit,
            TeamMemoryOperation::Admin,
            payload_digest,
        )?;
        let server_cursor = runtime.state.next_service_sequence.saturating_sub(1);
        if request.payload.after_cursor > server_cursor {
            return Err(TeamReplicationError::InvalidProtocol);
        }
        let mut revisions = runtime
            .state
            .sequenced_revisions
            .iter()
            .filter(|entry| entry.sequence > request.payload.after_cursor)
            .take(request.payload.limit)
            .cloned()
            .collect::<Vec<_>>();
        revisions.sort_by_key(|entry| entry.sequence);
        let next_cursor = revisions
            .last()
            .map_or(request.payload.after_cursor, |entry| entry.sequence);
        let mut ack = PullAckPayload {
            schema_version: TEAM_REPLICATION_SCHEMA_VERSION,
            team_id: request.payload.team_id.clone(),
            workspace_id: request.payload.workspace_id.clone(),
            service_replica_id: runtime.state.replica_id.clone(),
            client_replica_id: request.payload.client_replica_id.clone(),
            request_digest: payload_digest,
            after_cursor: request.payload.after_cursor,
            next_cursor,
            server_cursor,
            more_available: next_cursor < server_cursor,
            revisions,
        };
        fit_pull_ack_to_wire_budget(&mut ack)?;
        drop(runtime);
        let digest = canonical_digest(&ack)?;
        let grant = self.authority.issue_grant(
            TeamMemoryOperation::ReplicatePull,
            digest,
            LOCAL_GRANT_TTL_SECONDS,
        )?;
        ensure_operation_grant_wire_size(&grant)?;
        let response = PullResponse { ack, grant };
        ensure_wire_message_size(&response, "pull response bytes")?;
        Ok(response)
    }

    /// Save one explicitly scoped team candidate after consuming local S-103
    /// authorization. The encrypted revision and durable outbox entry commit
    /// before success is returned.
    ///
    /// # Errors
    ///
    /// Returns a typed authorization, validation, persistence, concurrency, or
    /// capacity error if the candidate cannot be committed and queued.
    pub fn save_technical_lesson_candidate(
        &self,
        draft: &TechnicalLessonDraft,
        source: MemorySourceEvidence,
        author_id: String,
        captured_at_unix_seconds: i64,
    ) -> Result<TechnicalLessonRecord, TeamReplicationError> {
        let request_digest = canonical_digest(&LocalSaveRequest {
            draft,
            source: &source,
            author_id: &author_id,
            captured_at_unix_seconds,
        })?;
        let permit = self.authorize_local(TeamMemoryOperation::Propose, request_digest)?;
        let mut runtime = self.lock_current_runtime()?;
        ensure_client_runtime(&runtime)?;
        self.authority
            .validate_permit(&permit, TeamMemoryOperation::Propose, request_digest)?;
        ensure_outbox_capacity(&runtime.state)?;
        let previous = runtime.state.clone();
        let record = runtime
            .database
            .save_technical_lesson_candidate(draft, source, author_id, captured_at_unix_seconds)
            .map_err(TeamReplicationError::Store)?;
        let revision = runtime
            .database
            .revision_by_digest(&record.record_digest)
            .map_err(TeamReplicationError::Store)?
            .context("new team lesson revision is unavailable")
            .map_err(TeamReplicationError::Store)?;
        if let Err(error) =
            self.record_local_mutation(&mut runtime, TeamMemoryOperation::Propose, revision)
        {
            restore_runtime(&mut runtime, previous)?;
            return Err(error);
        }
        drop(runtime);
        Ok(record)
    }

    /// Query the encrypted local team replica after consuming local S-103
    /// authorization. Cached records are explicitly marked stale when the
    /// remote service has not completed a current synchronization.
    ///
    /// # Errors
    ///
    /// Returns a typed authorization, integrity, persistence, or output-budget
    /// error if the bounded query cannot be completed truthfully.
    pub fn query_technical_lessons(
        &self,
        query: Option<&str>,
        limit: usize,
        now_unix_seconds: i64,
    ) -> Result<TeamTechnicalLessonQueryResult, TeamReplicationError> {
        let operation = if query.is_some() {
            TeamMemoryOperation::Search
        } else {
            TeamMemoryOperation::List
        };
        let request_digest = canonical_digest(&LocalQueryRequest {
            query,
            limit,
            now_unix_seconds,
        })?;
        let permit = self.authorize_local(operation, request_digest)?;
        let runtime = self.lock_current_runtime()?;
        ensure_client_runtime(&runtime)?;
        self.authority
            .validate_permit(&permit, operation, request_digest)?;
        if runtime.state.freshness == TeamReplicaFreshness::Unauthorized {
            return Err(TeamReplicationError::Unauthorized);
        }
        if runtime.state.freshness == TeamReplicaFreshness::Corrupt {
            return Err(TeamReplicationError::CorruptReplica);
        }
        let mut result = runtime
            .database
            .query_technical_lessons(query, limit, now_unix_seconds)
            .map_err(TeamReplicationError::Store)?;
        let conflicts = collect_conflicts(&runtime.database)?;
        result.omitted_conflicted = conflicts.len();
        let freshness =
            effective_read_freshness(runtime.state.freshness, &result, conflicts.is_empty());
        let mut output = TeamTechnicalLessonQueryResult {
            schema_version: TECHNICAL_LESSON_SCHEMA_VERSION,
            team_id: runtime.state.team_id.clone(),
            replica_id: runtime.state.replica_id.clone(),
            freshness,
            result,
            conflicts,
            conflicts_truncated: false,
            pull_cursor: runtime.state.pull_cursor,
            queued_mutations: runtime.state.outbox.len(),
            last_successful_sync_unix_seconds: runtime.state.last_successful_sync_unix_seconds,
        };
        drop(runtime);
        bound_team_query_result(&mut output)?;
        Ok(output)
    }

    /// Create one causal team correction and queue it durably for replication.
    ///
    /// # Errors
    ///
    /// Returns a typed authorization, conflict, validation, persistence, or
    /// capacity error if the correction cannot be committed and queued.
    pub fn correct_technical_lesson(
        &self,
        request: TechnicalLessonCorrectionRequest,
    ) -> Result<TechnicalLessonRecord, TeamReplicationError> {
        let request_digest = canonical_digest(&LocalCorrectionRequest::from(&request))?;
        let permit = self.authorize_local(TeamMemoryOperation::Correct, request_digest)?;
        let mut runtime = self.lock_current_runtime()?;
        ensure_client_runtime(&runtime)?;
        self.authority
            .validate_permit(&permit, TeamMemoryOperation::Correct, request_digest)?;
        ensure_outbox_capacity(&runtime.state)?;
        let previous = runtime.state.clone();
        let record = runtime
            .database
            .correct_technical_lesson(request)
            .map_err(TeamReplicationError::Store)?;
        let revision = runtime
            .database
            .revision_by_digest(&record.record_digest)
            .map_err(TeamReplicationError::Store)?
            .context("new team correction revision is unavailable")
            .map_err(TeamReplicationError::Store)?;
        if let Err(error) =
            self.record_local_mutation(&mut runtime, TeamMemoryOperation::Correct, revision)
        {
            restore_runtime(&mut runtime, previous)?;
            return Err(error);
        }
        drop(runtime);
        Ok(record)
    }

    /// Write one team tombstone and queue it durably for replication.
    ///
    /// # Errors
    ///
    /// Returns a typed authorization, conflict, validation, persistence, or
    /// capacity error if the tombstone cannot be committed and queued.
    pub fn delete_technical_lesson(
        &self,
        logical_id: LogicalMemoryId,
        expected_record_digest: &MemoryDigest,
        source: MemorySourceEvidence,
        author_id: String,
    ) -> Result<MemoryDigest, TeamReplicationError> {
        let request_digest = canonical_digest(&LocalDeleteRequest {
            logical_id,
            expected_record_digest,
            source: &source,
            author_id: &author_id,
        })?;
        let permit = self.authorize_local(TeamMemoryOperation::Delete, request_digest)?;
        let mut runtime = self.lock_current_runtime()?;
        ensure_client_runtime(&runtime)?;
        self.authority
            .validate_permit(&permit, TeamMemoryOperation::Delete, request_digest)?;
        ensure_outbox_capacity(&runtime.state)?;
        let previous = runtime.state.clone();
        let tombstone_digest = runtime
            .database
            .delete_technical_lesson(logical_id, expected_record_digest, source, author_id)
            .map_err(TeamReplicationError::Store)?;
        let revision = runtime
            .database
            .revision_by_digest(&tombstone_digest)
            .map_err(TeamReplicationError::Store)?
            .context("new team tombstone revision is unavailable")
            .map_err(TeamReplicationError::Store)?;
        if let Err(error) =
            self.record_local_mutation(&mut runtime, TeamMemoryOperation::Delete, revision)
        {
            restore_runtime(&mut runtime, previous)?;
            return Err(error);
        }
        drop(runtime);
        Ok(tombstone_digest)
    }

    fn authorize_local(
        &self,
        operation: TeamMemoryOperation,
        request_digest: ContentDigest,
    ) -> Result<TeamOperationPermit, TeamReplicationError> {
        let grant =
            self.authority
                .issue_grant(operation, request_digest, LOCAL_GRANT_TTL_SECONDS)?;
        match self
            .authority
            .authorize_grant(&grant, operation, request_digest)?
        {
            TeamAuthorizationOutcome::Authorized(permit) => Ok(permit),
            TeamAuthorizationOutcome::Denied { .. } => Err(TeamReplicationError::Unauthorized),
        }
    }

    fn record_local_mutation(
        &self,
        runtime: &mut ReplicaRuntime,
        operation: TeamMemoryOperation,
        revision: MemoryRevision,
    ) -> Result<(), TeamReplicationError> {
        validate_mutation_shape(operation, &revision)?;
        if runtime
            .state
            .revisions
            .iter()
            .any(|existing| existing.record_digest == revision.record_digest)
        {
            return Ok(());
        }
        if runtime.state.revisions.len() >= MAX_TEAM_REPLICA_REVISIONS {
            return Err(TeamReplicationError::CapacityExceeded {
                resource: "revisions",
            });
        }
        let operation_id = format!(
            "{}:{}",
            runtime.state.replica_id, runtime.state.next_operation_sequence
        );
        if operation_id.len() > MAX_OPERATION_ID_BYTES {
            return Err(TeamReplicationError::CapacityExceeded {
                resource: "operation identity",
            });
        }
        runtime.state.next_operation_sequence =
            runtime.state.next_operation_sequence.checked_add(1).ok_or(
                TeamReplicationError::CapacityExceeded {
                    resource: "operation sequence",
                },
            )?;
        runtime.state.outbox.push(OutboxMutation {
            operation_id,
            operation,
            revision_digest: revision.record_digest.clone(),
        });
        runtime.state.revisions.push(revision);
        runtime.state.freshness = if runtime.state.pinned_service.is_some() {
            TeamReplicaFreshness::Stale
        } else {
            TeamReplicaFreshness::Unconfigured
        };
        self.commit_runtime(runtime)
    }

    fn commit_runtime(&self, runtime: &mut ReplicaRuntime) -> Result<(), TeamReplicationError> {
        runtime.state.validate(
            self.role,
            self.authority.team_id(),
            self.authority.workspace_id(),
        )?;
        let encoded = encrypt_state(&self.authority, self.role, &runtime.state)?;
        let receipt = self.storage.commit(
            &self.target,
            FileClass::Evidence,
            runtime.generation,
            &*encoded,
        )?;
        if receipt.state() == CommitState::PublishedDurabilityUncertain {
            let retry = self.storage.commit(
                &self.target,
                FileClass::Evidence,
                runtime.generation,
                &*encoded,
            )?;
            if retry.state() == CommitState::PublishedDurabilityUncertain {
                return Err(TeamReplicationError::RecoveryRequired {
                    reason: "replica publication durability is uncertain",
                });
            }
            runtime.generation = retry.generation();
        } else {
            runtime.generation = receipt.generation();
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct LocalSaveRequest<'a> {
    draft: &'a TechnicalLessonDraft,
    source: &'a MemorySourceEvidence,
    author_id: &'a str,
    captured_at_unix_seconds: i64,
}

#[derive(Serialize)]
struct LocalQueryRequest<'a> {
    query: Option<&'a str>,
    limit: usize,
    now_unix_seconds: i64,
}

#[derive(Serialize)]
struct LocalCorrectionRequest<'a> {
    logical_id: LogicalMemoryId,
    expected_record_digest: &'a MemoryDigest,
    replacement: &'a TechnicalLessonDraft,
    correction_reason: &'a str,
    source: &'a MemorySourceEvidence,
    author_id: &'a str,
    captured_at_unix_seconds: i64,
}

impl<'a> From<&'a TechnicalLessonCorrectionRequest> for LocalCorrectionRequest<'a> {
    fn from(request: &'a TechnicalLessonCorrectionRequest) -> Self {
        Self {
            logical_id: request.logical_id,
            expected_record_digest: &request.expected_record_digest,
            replacement: &request.replacement,
            correction_reason: &request.correction_reason,
            source: &request.source,
            author_id: &request.author_id,
            captured_at_unix_seconds: request.captured_at_unix_seconds,
        }
    }
}

#[derive(Serialize)]
struct LocalDeleteRequest<'a> {
    logical_id: LogicalMemoryId,
    expected_record_digest: &'a MemoryDigest,
    source: &'a MemorySourceEvidence,
    author_id: &'a str,
}

fn canonical_digest(value: &impl Serialize) -> Result<ContentDigest, TeamReplicationError> {
    let encoded = serde_json::to_vec(value)
        .context("encoding bounded team-memory request")
        .map_err(TeamReplicationError::Store)?;
    if encoded.len() > MAX_TEAM_REPLICATION_MESSAGE_BYTES {
        return Err(TeamReplicationError::CapacityExceeded {
            resource: "request bytes",
        });
    }
    Ok(ContentDigest::sha256(encoded))
}

fn encoded_wire_len(value: &impl Serialize) -> Result<usize, TeamReplicationError> {
    serde_json::to_vec(value)
        .map(|encoded| encoded.len())
        .context("encoding bounded team-memory wire value")
        .map_err(TeamReplicationError::Store)
}

fn wire_value_fits_with_grants(
    value: &impl Serialize,
    grant_count: usize,
) -> Result<bool, TeamReplicationError> {
    let grant_reserve = grant_count
        .checked_mul(MAX_ENCODED_OPERATION_GRANT_BYTES)
        .and_then(|bytes| bytes.checked_add(MAX_WIRE_ENVELOPE_MARGIN_BYTES))
        .ok_or(TeamReplicationError::CapacityExceeded {
            resource: "wire size accounting",
        })?;
    let total = encoded_wire_len(value)?.checked_add(grant_reserve).ok_or(
        TeamReplicationError::CapacityExceeded {
            resource: "wire size accounting",
        },
    )?;
    Ok(total <= MAX_TEAM_REPLICATION_MESSAGE_BYTES)
}

fn ensure_operation_grant_wire_size(
    grant: &TeamOperationGrant,
) -> Result<(), TeamReplicationError> {
    if encoded_wire_len(grant)? > MAX_ENCODED_OPERATION_GRANT_BYTES {
        return Err(TeamReplicationError::CapacityExceeded {
            resource: "operation grant bytes",
        });
    }
    Ok(())
}

fn ensure_wire_message_size(
    value: &impl Serialize,
    resource: &'static str,
) -> Result<(), TeamReplicationError> {
    if encoded_wire_len(value)? > MAX_TEAM_REPLICATION_MESSAGE_BYTES {
        return Err(TeamReplicationError::CapacityExceeded { resource });
    }
    Ok(())
}

fn fit_pull_ack_to_wire_budget(ack: &mut PullAckPayload) -> Result<(), TeamReplicationError> {
    while !wire_value_fits_with_grants(ack, 1)? {
        if ack.revisions.pop().is_none() {
            return Err(TeamReplicationError::CapacityExceeded {
                resource: "single replication revision bytes",
            });
        }
        ack.next_cursor = ack
            .revisions
            .last()
            .map_or(ack.after_cursor, |entry| entry.sequence);
        ack.more_available = ack.next_cursor < ack.server_cursor;
    }
    Ok(())
}

fn materialize_database(state: &ReplicaFileState) -> Result<MemoryDb, TeamReplicationError> {
    let database = MemoryDb::open_ephemeral_team_replica(&state.workspace_id, state.store_id)
        .map_err(TeamReplicationError::Store)?;
    let mut revisions = state.revisions.clone();
    revisions.sort_by(|left, right| {
        left.version
            .cmp(&right.version)
            .then_with(|| left.record_digest.cmp(&right.record_digest))
    });
    for revision in &revisions {
        database
            .apply_revision(revision)
            .map_err(|_| TeamReplicationError::CorruptReplica)?;
    }
    Ok(database)
}

fn restore_runtime(
    runtime: &mut ReplicaRuntime,
    state: ReplicaFileState,
) -> Result<(), TeamReplicationError> {
    let database = materialize_database(&state)?;
    runtime.state = state;
    runtime.database = database;
    Ok(())
}

fn validate_forward_refresh(
    current: &ReplicaFileState,
    replacement: &ReplicaFileState,
) -> Result<(), TeamReplicationError> {
    let last_sync_regressed = match (
        current.last_successful_sync_unix_seconds,
        replacement.last_successful_sync_unix_seconds,
    ) {
        (Some(_), None) => true,
        (Some(current), Some(replacement)) => replacement < current,
        (None, None | Some(_)) => false,
    };
    let pinned_service_was_removed =
        current.pinned_service.is_some() && replacement.pinned_service.is_none();
    if replacement.replica_id != current.replica_id
        || replacement.store_id != current.store_id
        || replacement.next_operation_sequence < current.next_operation_sequence
        || replacement.next_service_sequence < current.next_service_sequence
        || replacement.pull_cursor < current.pull_cursor
        || pinned_service_was_removed
        || last_sync_regressed
    {
        return Err(TeamReplicationError::RecoveryRequired {
            reason: "encrypted team replica moved backward or was replaced",
        });
    }

    let replacement_revisions = replacement
        .revisions
        .iter()
        .map(|revision| &revision.record_digest)
        .collect::<BTreeSet<_>>();
    if current
        .revisions
        .iter()
        .any(|revision| !replacement_revisions.contains(&revision.record_digest))
    {
        return Err(TeamReplicationError::RecoveryRequired {
            reason: "encrypted team replica lost a previously observed revision",
        });
    }
    Ok(())
}

fn ensure_client_runtime(runtime: &ReplicaRuntime) -> Result<(), TeamReplicationError> {
    if runtime.state.role != ReplicaRole::Client {
        return Err(TeamReplicationError::InvalidProtocol);
    }
    Ok(())
}

fn require_active_replica_authority(
    authority: &TeamAuthorityStore,
    role: ReplicaRole,
) -> Result<(), TeamReplicationError> {
    match authority.status()? {
        TeamAuthorityStatus::Active {
            role: member_role, ..
        } if role == ReplicaRole::Client || member_role == TeamRole::Owner => Ok(()),
        _ => Err(TeamReplicationError::Unauthorized),
    }
}

const fn ensure_outbox_capacity(state: &ReplicaFileState) -> Result<(), TeamReplicationError> {
    if state.outbox.len() >= MAX_TEAM_REPLICA_OUTBOX {
        return Err(TeamReplicationError::CapacityExceeded { resource: "outbox" });
    }
    Ok(())
}

fn validate_mutation_shape(
    operation: TeamMemoryOperation,
    revision: &MemoryRevision,
) -> Result<(), TeamReplicationError> {
    let valid = match operation {
        TeamMemoryOperation::Propose => {
            revision.version.get() == 1
                && revision.parent_digest.is_none()
                && revision.state == MemoryRevisionState::Active
                && revision.tags.iter().any(|tag| tag == TECHNICAL_LESSON_TAG)
        }
        TeamMemoryOperation::Correct => {
            revision.version.get() > 1
                && revision.parent_digest.is_some()
                && revision.state == MemoryRevisionState::Active
                && revision.tags.iter().any(|tag| tag == TECHNICAL_LESSON_TAG)
        }
        TeamMemoryOperation::Delete => {
            revision.parent_digest.is_some()
                && revision.state == MemoryRevisionState::Tombstone
                && revision.content.is_empty()
                && revision.tags.is_empty()
        }
        _ => false,
    };
    if !valid || revision.provenance.scope != MemoryRecordScope::TeamShared {
        return Err(TeamReplicationError::InvalidProtocol);
    }
    Ok(())
}

fn collect_conflicts(database: &MemoryDb) -> Result<Vec<TeamLessonConflict>, TeamReplicationError> {
    let rows = database
        .memory_list(MAX_TEAM_REPLICA_REVISIONS + 1)
        .map_err(TeamReplicationError::Store)?;
    if rows.len() > MAX_TEAM_REPLICA_REVISIONS {
        return Err(TeamReplicationError::CapacityExceeded {
            resource: "conflict scan",
        });
    }
    let mut conflicts = rows
        .into_iter()
        .filter(|row| !row.conflict_heads.is_empty())
        .map(|row| TeamLessonConflict {
            logical_id: row.logical_id,
            heads: row.conflict_heads,
        })
        .collect::<Vec<_>>();
    conflicts.sort_by_key(|conflict| conflict.logical_id);
    Ok(conflicts)
}

fn bound_team_query_result(
    result: &mut TeamTechnicalLessonQueryResult,
) -> Result<(), TeamReplicationError> {
    if encoded_query_result_len(result)? <= MAX_TECHNICAL_QUERY_RESULT_BYTES {
        return Ok(());
    }

    let conflicts = std::mem::take(&mut result.conflicts);
    let conflict_count = conflicts.len();
    result.conflicts_truncated = conflict_count > 0;
    let records_only_len = encoded_query_result_len(result)?;
    if records_only_len <= MAX_TECHNICAL_QUERY_RESULT_BYTES {
        let retained = serialized_prefix_count(
            &conflicts,
            MAX_TECHNICAL_QUERY_RESULT_BYTES - records_only_len,
        )?;
        result
            .conflicts
            .extend(conflicts.into_iter().take(retained));
        result.conflicts_truncated = retained < conflict_count;
        if result.conflicts_truncated {
            result.freshness = TeamReplicaFreshness::Partial;
        }
        return ensure_bounded_query_result(result);
    }

    let records = std::mem::take(&mut result.result.records);
    result.freshness = TeamReplicaFreshness::Partial;
    result.result.status = TechnicalLessonQueryStatus::Partial;
    result.result.truncated_by_budget = true;
    let metadata_len = encoded_query_result_len(result)?;
    if metadata_len > MAX_TECHNICAL_QUERY_RESULT_BYTES {
        return Err(TeamReplicationError::CapacityExceeded {
            resource: "query result metadata",
        });
    }
    let retained =
        serialized_prefix_count(&records, MAX_TECHNICAL_QUERY_RESULT_BYTES - metadata_len)?;
    result
        .result
        .records
        .extend(records.into_iter().take(retained));
    ensure_bounded_query_result(result)
}

fn encoded_query_result_len(
    result: &TeamTechnicalLessonQueryResult,
) -> Result<usize, TeamReplicationError> {
    serde_json::to_vec(result)
        .map(|encoded| encoded.len())
        .context("encoding bounded team-memory query result")
        .map_err(TeamReplicationError::Store)
}

fn serialized_prefix_count<T: Serialize>(
    items: &[T],
    available_bytes: usize,
) -> Result<usize, TeamReplicationError> {
    let mut used = 0_usize;
    let mut retained = 0_usize;
    for item in items {
        let item_bytes = serde_json::to_vec(item)
            .context("encoding bounded team-memory query member")
            .map_err(TeamReplicationError::Store)?
            .len();
        let addition = item_bytes.checked_add(usize::from(retained > 0)).ok_or(
            TeamReplicationError::CapacityExceeded {
                resource: "query result bytes",
            },
        )?;
        let Some(next) = used.checked_add(addition) else {
            break;
        };
        if next > available_bytes {
            break;
        }
        used = next;
        retained += 1;
    }
    Ok(retained)
}

fn ensure_bounded_query_result(
    result: &TeamTechnicalLessonQueryResult,
) -> Result<(), TeamReplicationError> {
    if encoded_query_result_len(result)? > MAX_TECHNICAL_QUERY_RESULT_BYTES {
        return Err(TeamReplicationError::CapacityExceeded {
            resource: "query result bytes",
        });
    }
    Ok(())
}

fn effective_read_freshness(
    stored: TeamReplicaFreshness,
    result: &TechnicalLessonQueryResult,
    conflict_free: bool,
) -> TeamReplicaFreshness {
    if !conflict_free {
        return TeamReplicaFreshness::Partial;
    }
    if result.status == TechnicalLessonQueryStatus::Partial {
        return TeamReplicaFreshness::Partial;
    }
    stored
}

fn validate_pinned_service(
    service: Option<&PinnedTeamService>,
) -> Result<(), TeamReplicationError> {
    let Some(service) = service else {
        return Ok(());
    };
    if validate_service_endpoint(&service.endpoint).is_err()
        || service.certificate_der_base64.len() > MAX_TEAM_REPLICATION_CERTIFICATE_BYTES * 2
    {
        return Err(TeamReplicationError::CorruptReplica);
    }
    let certificate = BASE64_STANDARD
        .decode(&service.certificate_der_base64)
        .map_err(|_| TeamReplicationError::CorruptReplica)?;
    if certificate.is_empty()
        || certificate.len() > MAX_TEAM_REPLICATION_CERTIFICATE_BYTES
        || ContentDigest::sha256(&certificate) != service.certificate_digest
    {
        return Err(TeamReplicationError::CorruptReplica);
    }
    validate_certificate(&certificate).map_err(|_| TeamReplicationError::CorruptReplica)?;
    Ok(())
}

fn validate_service_sequences(state: &ReplicaFileState) -> Result<(), TeamReplicationError> {
    if state.sequenced_revisions.len() != state.revisions.len() {
        return Err(TeamReplicationError::CorruptReplica);
    }
    let mut sequences = BTreeSet::new();
    let revisions = state
        .revisions
        .iter()
        .map(|revision| (revision.record_digest.clone(), revision))
        .collect::<BTreeMap<_, _>>();
    let mut sequenced_digests = BTreeSet::new();
    for entry in &state.sequenced_revisions {
        entry
            .revision
            .validate()
            .map_err(|_| TeamReplicationError::CorruptReplica)?;
        if entry.sequence == 0
            || !sequences.insert(entry.sequence)
            || !sequenced_digests.insert(entry.revision.record_digest.clone())
            || revisions.get(&entry.revision.record_digest).copied() != Some(&entry.revision)
        {
            return Err(TeamReplicationError::CorruptReplica);
        }
    }
    let maximum = sequences.last().copied().unwrap_or(0);
    if maximum.checked_add(1) != Some(state.next_service_sequence)
        || sequences.len() != usize::try_from(maximum).unwrap_or(usize::MAX)
    {
        return Err(TeamReplicationError::CorruptReplica);
    }
    Ok(())
}

fn validate_service_inbox(state: &ReplicaFileState) -> Result<(), TeamReplicationError> {
    let revision_digests = state
        .revisions
        .iter()
        .map(|revision| &revision.record_digest)
        .collect::<BTreeSet<_>>();
    let mut keys = BTreeMap::new();
    for receipt in &state.service_inbox {
        let accepted = receipt
            .accepted_revision_digests
            .iter()
            .collect::<BTreeSet<_>>();
        if receipt.retry_key.is_empty()
            || receipt.retry_key.len() > MAX_OPERATION_ID_BYTES
            || receipt.server_cursor >= state.next_service_sequence
            || accepted.is_empty()
            || accepted.len() != receipt.accepted_revision_digests.len()
            || accepted.len() > MAX_TEAM_REPLICATION_BATCH
            || accepted
                .iter()
                .any(|digest| !revision_digests.contains(digest))
            || keys
                .insert(
                    (
                        receipt.client_replica_id.clone(),
                        receipt.retry_key.as_str(),
                    ),
                    receipt.payload_digest,
                )
                .is_some()
        {
            return Err(TeamReplicationError::CorruptReplica);
        }
    }
    Ok(())
}

fn replica_aad(
    role: ReplicaRole,
    team_id: &TeamId,
    workspace_id: &WorkspaceMemoryId,
) -> Result<Vec<u8>, TeamReplicationError> {
    serde_json::to_vec(&ReplicaAad {
        schema_version: TEAM_REPLICATION_SCHEMA_VERSION,
        role,
        team_id,
        workspace_id,
    })
    .context("encoding team replica associated data")
    .map_err(TeamReplicationError::Store)
}

fn encrypt_state(
    authority: &TeamAuthorityStore,
    role: ReplicaRole,
    state: &ReplicaFileState,
) -> Result<Zeroizing<Vec<u8>>, TeamReplicationError> {
    let mut plaintext = Zeroizing::new(
        serde_json::to_vec(state)
            .context("encoding team replica")
            .map_err(TeamReplicationError::Store)?,
    );
    if plaintext.len() > MAX_REPLICA_PLAINTEXT_BYTES {
        return Err(TeamReplicationError::CapacityExceeded {
            resource: "encrypted state bytes",
        });
    }
    let key = authority.replica_storage_key()?;
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| {
        TeamReplicationError::RecoveryRequired {
            reason: "replica encryption key is invalid",
        }
    })?;
    let mut nonce = [0_u8; 12];
    SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| TeamReplicationError::RecoveryRequired {
            reason: "operating-system randomness is unavailable",
        })?;
    let aad = replica_aad(role, authority.team_id(), authority.workspace_id())?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| TeamReplicationError::CorruptReplica)?;
    plaintext.zeroize();
    let envelope = EncryptedReplicaEnvelope {
        schema_version: TEAM_REPLICATION_SCHEMA_VERSION,
        role,
        team_id: authority.team_id().clone(),
        workspace_id: authority.workspace_id().clone(),
        nonce_base64: BASE64_STANDARD.encode(nonce),
        ciphertext_base64: BASE64_STANDARD.encode(ciphertext),
    };
    let encoded = serde_json::to_vec(&envelope)
        .context("encoding encrypted team replica envelope")
        .map_err(TeamReplicationError::Store)?;
    let encoded_len =
        u64::try_from(encoded.len()).map_err(|_| TeamReplicationError::CapacityExceeded {
            resource: "encrypted state file",
        })?;
    if encoded_len > FileClass::Evidence.max_bytes() {
        return Err(TeamReplicationError::CapacityExceeded {
            resource: "encrypted state file",
        });
    }
    Ok(Zeroizing::new(encoded))
}

fn decrypt_state(
    authority: &TeamAuthorityStore,
    role: ReplicaRole,
    encoded: &[u8],
) -> Result<ReplicaFileState, TeamReplicationError> {
    let envelope: EncryptedReplicaEnvelope =
        serde_json::from_slice(encoded).map_err(|_| TeamReplicationError::CorruptReplica)?;
    if envelope.schema_version != TEAM_REPLICATION_SCHEMA_VERSION
        || envelope.role != role
        || envelope.team_id != *authority.team_id()
        || envelope.workspace_id != *authority.workspace_id()
        || envelope.nonce_base64.len() > 24
        || envelope.ciphertext_base64.len() > MAX_REPLICA_CIPHERTEXT_BASE64_BYTES
    {
        return Err(TeamReplicationError::CorruptReplica);
    }
    let nonce = BASE64_STANDARD
        .decode(&envelope.nonce_base64)
        .map_err(|_| TeamReplicationError::CorruptReplica)?;
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| TeamReplicationError::CorruptReplica)?;
    let ciphertext = BASE64_STANDARD
        .decode(&envelope.ciphertext_base64)
        .map_err(|_| TeamReplicationError::CorruptReplica)?;
    if ciphertext.len() > MAX_REPLICA_PLAINTEXT_BYTES + 32 {
        return Err(TeamReplicationError::CorruptReplica);
    }
    let key = authority.replica_storage_key()?;
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| {
        TeamReplicationError::RecoveryRequired {
            reason: "replica encryption key is invalid",
        }
    })?;
    let aad = replica_aad(role, authority.team_id(), authority.workspace_id())?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| TeamReplicationError::CorruptReplica)?;
    if plaintext.len() > MAX_REPLICA_PLAINTEXT_BYTES {
        return Err(TeamReplicationError::CorruptReplica);
    }
    let plaintext = Zeroizing::new(plaintext);
    serde_json::from_slice(&plaintext).map_err(|_| TeamReplicationError::CorruptReplica)
}

/// Exact stable payload of one queued mutation. A fresh semantic grant can be
/// issued after a restart without changing this digest or retry identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MutationPayload {
    pub operation_id: String,
    pub operation: TeamMemoryOperation,
    pub revision: MemoryRevision,
}

#[derive(Serialize)]
struct UnsignedServiceDescriptor<'a> {
    schema_version: u32,
    team_id: &'a TeamId,
    workspace_id: &'a WorkspaceMemoryId,
    service_replica_id: &'a TeamReplicaId,
    service_principal_id: &'a PrincipalId,
    endpoint: &'a str,
    certificate_der_base64: String,
    certificate_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PushPayload {
    schema_version: u32,
    team_id: TeamId,
    workspace_id: WorkspaceMemoryId,
    client_replica_id: TeamReplicaId,
    retry_key: String,
    mutations: Vec<MutationPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PushRequest {
    pub payload: PushPayload,
    pub transport_grant: TeamOperationGrant,
    pub mutation_grants: Vec<TeamOperationGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PushAckPayload {
    schema_version: u32,
    team_id: TeamId,
    workspace_id: WorkspaceMemoryId,
    service_replica_id: TeamReplicaId,
    client_replica_id: TeamReplicaId,
    retry_key: String,
    request_digest: ContentDigest,
    accepted_revision_digests: Vec<MemoryDigest>,
    server_cursor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PushResponse {
    pub ack: PushAckPayload,
    pub grant: TeamOperationGrant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PullPayload {
    schema_version: u32,
    team_id: TeamId,
    workspace_id: WorkspaceMemoryId,
    client_replica_id: TeamReplicaId,
    after_cursor: u64,
    limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PullRequest {
    pub payload: PullPayload,
    pub grant: TeamOperationGrant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PullAckPayload {
    schema_version: u32,
    team_id: TeamId,
    workspace_id: WorkspaceMemoryId,
    service_replica_id: TeamReplicaId,
    client_replica_id: TeamReplicaId,
    request_digest: ContentDigest,
    after_cursor: u64,
    next_cursor: u64,
    server_cursor: u64,
    more_available: bool,
    revisions: Vec<SequencedRevision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PullResponse {
    pub ack: PullAckPayload,
    pub grant: TeamOperationGrant,
}

fn validate_service_endpoint(endpoint: &str) -> Result<(), TeamReplicationError> {
    if endpoint.is_empty()
        || endpoint.len() > MAX_TEAM_REPLICATION_ENDPOINT_BYTES
        || endpoint.chars().any(char::is_control)
    {
        return Err(TeamReplicationError::InvalidProtocol);
    }
    let parsed = url::Url::parse(endpoint).map_err(|_| TeamReplicationError::InvalidProtocol)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        return Err(TeamReplicationError::InvalidProtocol);
    }
    Ok(())
}

fn validate_certificate(certificate_der: &[u8]) -> Result<(), TeamReplicationError> {
    if certificate_der.is_empty() || certificate_der.len() > MAX_TEAM_REPLICATION_CERTIFICATE_BYTES
    {
        return Err(TeamReplicationError::InvalidProtocol);
    }
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(
            certificate_der.to_vec(),
        ))
        .map_err(|_| TeamReplicationError::InvalidProtocol)?;
    Ok(())
}

fn validate_service_descriptor(
    descriptor: &TeamServiceDescriptor,
    team_id: &TeamId,
    workspace_id: &WorkspaceMemoryId,
) -> Result<(), TeamReplicationError> {
    if descriptor.schema_version != TEAM_REPLICATION_SCHEMA_VERSION
        || &descriptor.team_id != team_id
        || &descriptor.workspace_id != workspace_id
    {
        return Err(TeamReplicationError::InvalidProtocol);
    }
    validate_service_endpoint(&descriptor.endpoint)?;
    if descriptor.certificate_der_base64.len() > MAX_TEAM_REPLICATION_CERTIFICATE_BYTES * 2 {
        return Err(TeamReplicationError::InvalidProtocol);
    }
    let certificate = BASE64_STANDARD
        .decode(&descriptor.certificate_der_base64)
        .map_err(|_| TeamReplicationError::InvalidProtocol)?;
    validate_certificate(&certificate)?;
    if ContentDigest::sha256(&certificate) != descriptor.certificate_digest {
        return Err(TeamReplicationError::InvalidProtocol);
    }
    Ok(())
}

fn descriptor_unsigned_digest(
    descriptor: &TeamServiceDescriptor,
) -> Result<ContentDigest, TeamReplicationError> {
    canonical_digest(&UnsignedServiceDescriptor {
        schema_version: descriptor.schema_version,
        team_id: &descriptor.team_id,
        workspace_id: &descriptor.workspace_id,
        service_replica_id: &descriptor.service_replica_id,
        service_principal_id: &descriptor.service_principal_id,
        endpoint: &descriptor.endpoint,
        certificate_der_base64: descriptor.certificate_der_base64.clone(),
        certificate_digest: descriptor.certificate_digest,
    })
}

fn push_retry_key(
    client_replica_id: &TeamReplicaId,
    mutations: &[MutationPayload],
) -> Result<String, TeamReplicationError> {
    #[derive(Serialize)]
    struct RetryIdentity<'a> {
        schema_version: u32,
        client_replica_id: &'a TeamReplicaId,
        operation_ids: Vec<&'a str>,
        revision_digests: Vec<&'a MemoryDigest>,
    }
    let digest = canonical_digest(&RetryIdentity {
        schema_version: TEAM_REPLICATION_SCHEMA_VERSION,
        client_replica_id,
        operation_ids: mutations
            .iter()
            .map(|mutation| mutation.operation_id.as_str())
            .collect(),
        revision_digests: mutations
            .iter()
            .map(|mutation| &mutation.revision.record_digest)
            .collect(),
    })?;
    Ok(digest.to_string())
}

fn validate_push_payload(payload: &PushPayload) -> Result<(), TeamReplicationError> {
    if payload.schema_version != TEAM_REPLICATION_SCHEMA_VERSION
        || payload.retry_key.is_empty()
        || payload.retry_key.len() > MAX_OPERATION_ID_BYTES
        || payload.mutations.is_empty()
        || payload.mutations.len() > MAX_TEAM_REPLICATION_BATCH
    {
        return Err(TeamReplicationError::InvalidProtocol);
    }
    let mut operation_ids = BTreeSet::new();
    let mut revision_digests = BTreeSet::new();
    for mutation in &payload.mutations {
        if mutation.operation_id.is_empty()
            || mutation.operation_id.len() > MAX_OPERATION_ID_BYTES
            || !operation_ids.insert(mutation.operation_id.as_str())
            || !revision_digests.insert(mutation.revision.record_digest.clone())
            || mutation.revision.provenance.workspace_id.as_deref()
                != Some(payload.workspace_id.as_str())
        {
            return Err(TeamReplicationError::InvalidProtocol);
        }
        mutation
            .revision
            .validate()
            .map_err(|_| TeamReplicationError::InvalidProtocol)?;
        validate_mutation_shape(mutation.operation, &mutation.revision)?;
    }
    if push_retry_key(&payload.client_replica_id, &payload.mutations)? != payload.retry_key {
        return Err(TeamReplicationError::InvalidProtocol);
    }
    Ok(())
}

fn validate_push_request(
    request: &PushRequest,
    team_id: &TeamId,
    workspace_id: &WorkspaceMemoryId,
) -> Result<(), TeamReplicationError> {
    validate_push_payload(&request.payload)?;
    if &request.payload.team_id != team_id
        || &request.payload.workspace_id != workspace_id
        || request.mutation_grants.len() != request.payload.mutations.len()
    {
        return Err(TeamReplicationError::InvalidProtocol);
    }
    let payload_digest = canonical_digest(&request.payload)?;
    if request.transport_grant.operation() != TeamMemoryOperation::ReplicatePush
        || request.transport_grant.request_digest() != payload_digest
    {
        return Err(TeamReplicationError::InvalidProtocol);
    }
    Ok(())
}

fn validate_push_response(
    response: &PushResponse,
    request: &PushRequest,
    team_id: &TeamId,
    workspace_id: &WorkspaceMemoryId,
    service: &PinnedTeamService,
) -> Result<(), TeamReplicationError> {
    let ack = &response.ack;
    if ack.schema_version != TEAM_REPLICATION_SCHEMA_VERSION
        || &ack.team_id != team_id
        || &ack.workspace_id != workspace_id
        || ack.service_replica_id != service.service_replica_id
        || ack.client_replica_id != request.payload.client_replica_id
        || ack.retry_key != request.payload.retry_key
        || ack.request_digest != canonical_digest(&request.payload)?
        || ack.accepted_revision_digests.len() != request.payload.mutations.len()
    {
        return Err(TeamReplicationError::InvalidProtocol);
    }
    Ok(())
}

fn validate_pull_request(
    request: &PullRequest,
    team_id: &TeamId,
    workspace_id: &WorkspaceMemoryId,
) -> Result<(), TeamReplicationError> {
    if request.payload.schema_version != TEAM_REPLICATION_SCHEMA_VERSION
        || &request.payload.team_id != team_id
        || &request.payload.workspace_id != workspace_id
        || request.payload.after_cursor > MAX_TEAM_REPLICA_REVISIONS as u64
        || request.payload.limit == 0
        || request.payload.limit > MAX_TEAM_REPLICATION_BATCH
    {
        return Err(TeamReplicationError::InvalidProtocol);
    }
    let payload_digest = canonical_digest(&request.payload)?;
    if request.grant.operation() != TeamMemoryOperation::ReplicatePull
        || request.grant.request_digest() != payload_digest
    {
        return Err(TeamReplicationError::InvalidProtocol);
    }
    Ok(())
}

fn validate_pull_response(
    response: &PullResponse,
    request: &PullRequest,
    team_id: &TeamId,
    workspace_id: &WorkspaceMemoryId,
    service: &PinnedTeamService,
) -> Result<(), TeamReplicationError> {
    let ack = &response.ack;
    if ack.schema_version != TEAM_REPLICATION_SCHEMA_VERSION
        || &ack.team_id != team_id
        || &ack.workspace_id != workspace_id
        || ack.service_replica_id != service.service_replica_id
        || ack.client_replica_id != request.payload.client_replica_id
        || ack.request_digest != canonical_digest(&request.payload)?
        || ack.after_cursor != request.payload.after_cursor
        || ack.revisions.len() > request.payload.limit
        || ack.next_cursor < ack.after_cursor
        || ack.server_cursor < ack.next_cursor
        || ack.server_cursor > MAX_TEAM_REPLICA_REVISIONS as u64
        || ack.more_available != (ack.next_cursor < ack.server_cursor)
        || (ack.revisions.is_empty() && ack.server_cursor != ack.after_cursor)
    {
        return Err(TeamReplicationError::InvalidProtocol);
    }
    let mut expected_sequence = ack.after_cursor;
    let mut revision_digests = BTreeSet::new();
    for entry in &ack.revisions {
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(TeamReplicationError::InvalidProtocol)?;
        if entry.sequence != expected_sequence
            || entry.revision.provenance.scope != MemoryRecordScope::TeamShared
            || entry.revision.provenance.workspace_id.as_deref() != Some(workspace_id.as_str())
            || !revision_digests.insert(entry.revision.record_digest.clone())
        {
            return Err(TeamReplicationError::InvalidProtocol);
        }
        entry
            .revision
            .validate()
            .map_err(|_| TeamReplicationError::InvalidProtocol)?;
        if entry.revision.state == MemoryRevisionState::Active
            && !entry
                .revision
                .tags
                .iter()
                .any(|tag| tag == TECHNICAL_LESSON_TAG)
        {
            return Err(TeamReplicationError::InvalidProtocol);
        }
    }
    if ack.next_cursor != expected_sequence {
        return Err(TeamReplicationError::InvalidProtocol);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::missing_panics_doc)]

    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::memory::{
        LessonApplicability, LessonCitation, LessonCitationKind, LessonRetention, MemorySourceKind,
        TechnicalLessonConfidence, TechnicalLessonDraft, TechnicalLessonKind,
        TechnicalLessonSensitivity,
    };
    use crate::team_memory::{PrincipalId, TeamRole};

    const MEMBERSHIP_TTL_SECONDS: i64 = 31_536_000;
    const CERTIFICATE_DER_BASE64: &str = "MIIBvTCCAWOgAwIBAgIUfUWeyDgo5yP5nWXotTF/TOMi/OEwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgyMjAxMDYwNFoXDTM2MDgxOTAxMDYwNFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXGgdHsWaQlfJxe8pg6dK0IdFetzHDo/SwISNqf7oammUDXRmMWSdBbpeNHNoN10ICpWELUjCycVlyEEx+eo7CaOBkjCBjzAdBgNVHQ4EFgQUxTjb982X3PKPSoxPLX0WtOGedIcwHwYDVR0jBBgwFoAUxTjb982X3PKPSoxPLX0WtOGedIcwGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAoGCCqGSM49BAMCA0gAMEUCIF8+FLOhGMMka9yLeQcqHBeDxiaECrfSphs96q/nauA5AiEA9Z9m0FsKG7+5c2B/TF+NJGmHAmJU35o4Tn+KYZPiM8g=";

    struct OwnerFixture {
        home: TempDir,
        workspace: TempDir,
        authority: TeamAuthorityStore,
    }

    fn owner_fixture() -> OwnerFixture {
        let home = tempfile::tempdir().expect("host home");
        let workspace = tempfile::tempdir().expect("workspace");
        let principal: PrincipalId = "owner".parse().expect("principal");
        let authority = TeamAuthorityStore::bootstrap(
            home.path(),
            workspace.path(),
            principal,
            MEMBERSHIP_TTL_SECONDS,
        )
        .expect("team authority");
        OwnerFixture {
            home,
            workspace,
            authority,
        }
    }

    fn test_certificate() -> Vec<u8> {
        BASE64_STANDARD
            .decode(CERTIFICATE_DER_BASE64)
            .expect("certificate fixture")
    }

    fn enroll_member(
        owner: &TeamAuthorityStore,
        member_home: &TempDir,
        workspace: &TempDir,
        role: TeamRole,
    ) -> TeamAuthorityStore {
        let invitation = owner
            .create_enrollment_invitation(3_600)
            .expect("invitation");
        let principal: PrincipalId = "member".parse().expect("principal");
        let (member, request) = TeamAuthorityStore::begin_enrollment(
            member_home.path(),
            workspace.path(),
            principal,
            invitation.clone(),
        )
        .expect("begin enrollment");
        let approval = owner
            .approve_enrollment(&invitation, &request, role, MEMBERSHIP_TTL_SECONDS)
            .expect("approval");
        member
            .accept_enrollment(&approval)
            .expect("accept enrollment");
        member
    }

    fn source(label: &str) -> MemorySourceEvidence {
        MemorySourceEvidence::new(
            MemorySourceKind::ToolOutcome,
            format!("test:{label}"),
            "generation:test".to_string(),
            MemoryDigest::for_fields(b"openclaudia.s104.test-source.v1", &[label.as_bytes()]),
        )
    }

    fn draft(label: &str) -> TechnicalLessonDraft {
        TechnicalLessonDraft {
            title: format!("{label} repository invariant"),
            kind: TechnicalLessonKind::Compatibility,
            observation: format!("The {label} implementation requires a causal revision."),
            guidance: "Inspect the cited code generation before changing this invariant."
                .to_string(),
            applicability: LessonApplicability {
                paths: vec!["src/team_memory/replication.rs".to_string()],
                symbols: vec!["TeamReplica".to_string()],
                ..LessonApplicability::default()
            },
            citations: vec![LessonCitation {
                kind: LessonCitationKind::Test,
                locator: "src/team_memory/replication.rs".to_string(),
                source_version: "git:s104-test".to_string(),
                digest: MemoryDigest::for_fields(
                    b"openclaudia.s104.test-citation.v1",
                    &[label.as_bytes()],
                ),
                line_start: Some(1),
                line_end: Some(1),
            }],
            confidence: TechnicalLessonConfidence::VerifiedByTest,
            sensitivity: TechnicalLessonSensitivity::Internal,
            retention: LessonRetention::Indefinite,
        }
    }

    fn large_wire_draft(label: &str) -> TechnicalLessonDraft {
        let mut draft = draft(label);
        draft.observation = "o".repeat(2_048);
        draft.guidance = "g".repeat(2_048);
        draft.applicability.paths = (0..16)
            .map(|index| format!("src/wire/{index:02}-{}", "p".repeat(100)))
            .collect();
        draft.applicability.symbols = (0..16)
            .map(|index| format!("WireSymbol{index:02}{}", "s".repeat(100)))
            .collect();
        draft.citations = (0_usize..32)
            .map(|index| LessonCitation {
                kind: LessonCitationKind::Test,
                locator: format!("tests/wire/{index:02}-{}", "l".repeat(470)),
                source_version: format!("generation:{index:02}:{}", "v".repeat(60)),
                digest: MemoryDigest::for_fields(
                    b"openclaudia.s104.large-wire-citation.v1",
                    &[label.as_bytes(), &index.to_le_bytes()],
                ),
                line_start: Some(1),
                line_end: Some(1),
            })
            .collect();
        draft
    }

    fn configured_replicas(
        authority: &TeamAuthorityStore,
    ) -> (TeamReplica, TeamReplica, TeamServiceDescriptor) {
        let client = TeamReplica::open_client(authority.clone()).expect("client replica");
        let service = TeamReplica::open_service(authority.clone()).expect("service replica");
        let descriptor = service
            .service_descriptor("https://localhost:7443", &test_certificate())
            .expect("service descriptor");
        client
            .configure_service(&descriptor, false)
            .expect("pin service");
        (client, service, descriptor)
    }

    fn push_once(client: &TeamReplica, service: &TeamReplica) -> usize {
        let request = client
            .prepare_push()
            .expect("prepare push")
            .expect("queued push");
        let response = service.handle_push(&request).expect("service push");
        client
            .apply_push_ack(&request, &response)
            .expect("push ack")
    }

    fn pull_once(client: &TeamReplica, service: &TeamReplica) -> TeamSyncReport {
        let request = client.prepare_pull().expect("prepare pull");
        let response = service.handle_pull(&request).expect("service pull");
        client
            .apply_pull_ack(&request, &response, chrono::Utc::now().timestamp())
            .expect("pull ack")
    }

    fn replica_path(fixture: &OwnerFixture, role: ReplicaRole, team_id: &TeamId) -> PathBuf {
        let canonical_workspace = fixture.workspace.path().canonicalize().expect("workspace");
        let workspace_id = WorkspaceMemoryId::for_canonical_root(&canonical_workspace);
        fixture
            .home
            .path()
            .join(".openclaudia")
            .join("memory")
            .join("workspaces")
            .join(workspace_id.path_component())
            .join(format!("{}-{team_id}.json", role.target_prefix()))
    }

    #[test]
    fn encrypted_replica_contains_no_lesson_text_and_missing_store_fails_closed() {
        let fixture = owner_fixture();
        let client = TeamReplica::open_client(fixture.authority.clone()).expect("client");
        let lesson = draft("plaintext sentinel");
        client
            .save_technical_lesson_candidate(
                &lesson,
                source("encrypted"),
                "agent:test".to_string(),
                chrono::Utc::now().timestamp(),
            )
            .expect("save encrypted lesson");
        let path = replica_path(&fixture, ReplicaRole::Client, fixture.authority.team_id());
        let encrypted = fs::read(&path).expect("encrypted file");
        assert!(!encrypted
            .windows(lesson.title.len())
            .any(|window| window == lesson.title.as_bytes()));
        assert!(!encrypted
            .windows(lesson.observation.len())
            .any(|window| window == lesson.observation.as_bytes()));
        drop(client);

        fs::remove_file(&path).expect("remove temporary replica");
        assert!(matches!(
            TeamReplica::open_client(fixture.authority),
            Err(TeamReplicationError::RecoveryRequired { .. })
        ));
    }

    #[test]
    fn validly_encrypted_nontechnical_content_is_rejected_as_corrupt() {
        let fixture = owner_fixture();
        let authority = fixture.authority.clone();
        let client = TeamReplica::open_client(authority.clone()).expect("client");
        let path = replica_path(&fixture, ReplicaRole::Client, authority.team_id());
        let mut state = client.lock_runtime().expect("runtime").state.clone();
        let provenance = crate::memory::MemoryProvenance::new(
            source("nontechnical injection"),
            crate::memory::MemoryAttribution::new(
                "agent:test".to_string(),
                Some(state.store_id),
                Some(state.workspace_id.to_string()),
            ),
            MemoryRecordScope::TeamShared,
        );
        state.revisions = vec![MemoryRevision::new(
            "arbitrary prose is not a codebase technical lesson".to_string(),
            vec!["arbitrary".to_string()],
            provenance,
        )];
        let encoded = encrypt_state(&authority, ReplicaRole::Client, &state)
            .expect("validly encrypted hostile state");
        fs::write(path, encoded.as_slice()).expect("replace encrypted state");
        drop(client);

        assert!(matches!(
            TeamReplica::open_client(authority),
            Err(TeamReplicationError::CorruptReplica)
        ));
    }

    #[test]
    fn independently_opened_handles_refresh_forward_without_losing_mutations() {
        let fixture = owner_fixture();
        let first = TeamReplica::open_client(fixture.authority.clone()).expect("first client");
        let second = TeamReplica::open_client(fixture.authority).expect("second client");

        first
            .save_technical_lesson_candidate(
                &draft("first handle"),
                source("first handle"),
                "agent:first".to_string(),
                chrono::Utc::now().timestamp(),
            )
            .expect("first mutation");
        assert_eq!(second.status().expect("refreshed status").revisions, 1);
        second
            .save_technical_lesson_candidate(
                &draft("second handle"),
                source("second handle"),
                "agent:second".to_string(),
                chrono::Utc::now().timestamp(),
            )
            .expect("second mutation");

        let refreshed = first
            .query_technical_lessons(None, 5, chrono::Utc::now().timestamp())
            .expect("first handle refresh");
        assert_eq!(refreshed.result.records.len(), 2);
        assert_eq!(refreshed.queued_mutations, 2);
    }

    #[test]
    fn same_identity_snapshot_rollback_is_rejected_while_handle_is_live() {
        let fixture = owner_fixture();
        let client = TeamReplica::open_client(fixture.authority.clone()).expect("client");
        let path = replica_path(&fixture, ReplicaRole::Client, fixture.authority.team_id());
        let empty_snapshot = fs::read(&path).expect("empty encrypted snapshot");
        client
            .save_technical_lesson_candidate(
                &draft("rollback sentinel"),
                source("rollback sentinel"),
                "agent:test".to_string(),
                chrono::Utc::now().timestamp(),
            )
            .expect("newer mutation");

        fs::write(&path, empty_snapshot).expect("restore older encrypted snapshot");
        assert!(matches!(
            client.status(),
            Err(TeamReplicationError::RecoveryRequired { .. })
        ));
    }

    #[test]
    fn encrypted_replica_copied_to_a_different_member_key_is_rejected() {
        let fixture = owner_fixture();
        let owner_client =
            TeamReplica::open_client(fixture.authority.clone()).expect("owner client");
        owner_client
            .save_technical_lesson_candidate(
                &draft("wrong key sentinel"),
                source("wrong key sentinel"),
                "agent:owner".to_string(),
                chrono::Utc::now().timestamp(),
            )
            .expect("encrypted owner lesson");
        let member_home = tempfile::tempdir().expect("member home");
        let member = enroll_member(
            &fixture.authority,
            &member_home,
            &fixture.workspace,
            TeamRole::Reader,
        );
        let owner_path = replica_path(&fixture, ReplicaRole::Client, fixture.authority.team_id());
        let workspace_id = WorkspaceMemoryId::for_canonical_root(
            &fixture.workspace.path().canonicalize().expect("workspace"),
        );
        let member_path = member_home
            .path()
            .join(".openclaudia")
            .join("memory")
            .join("workspaces")
            .join(workspace_id.path_component())
            .join(format!(
                "{}-{}.json",
                ReplicaRole::Client.target_prefix(),
                fixture.authority.team_id()
            ));
        fs::copy(owner_path, member_path).expect("copy encrypted replica");

        assert!(matches!(
            TeamReplica::open_client(member),
            Err(TeamReplicationError::CorruptReplica)
        ));
    }

    #[test]
    fn transport_rotation_requires_host_approval_and_replica_replacement_is_rejected() {
        let fixture = owner_fixture();
        let client = TeamReplica::open_client(fixture.authority.clone()).expect("client");
        let first_service =
            TeamReplica::open_service(fixture.authority.clone()).expect("first service");
        assert!(matches!(
            first_service.service_descriptor("https://localhost:7443", b"not-a-certificate"),
            Err(TeamReplicationError::InvalidProtocol)
        ));
        let first_descriptor = first_service
            .service_descriptor("https://localhost:7443", &test_certificate())
            .expect("first descriptor");
        client
            .configure_service(&first_descriptor, false)
            .expect("first service pin");
        assert!(matches!(
            client.configure_service(&first_descriptor, false),
            Err(TeamReplicationError::Unauthorized)
        ));

        let rotated_transport = first_service
            .service_descriptor("https://localhost:8443", &test_certificate())
            .expect("rotated transport descriptor");
        assert!(matches!(
            client.configure_service(&rotated_transport, false),
            Err(TeamReplicationError::ServiceIdentityMismatch)
        ));
        let rotated = client
            .configure_service(&rotated_transport, true)
            .expect("explicit transport rotation");
        assert!(rotated.service_configured);
        assert_eq!(rotated.freshness, TeamReplicaFreshness::Stale);

        let second_home = tempfile::tempdir().expect("second service home");
        let second_authority = enroll_member(
            &fixture.authority,
            &second_home,
            &fixture.workspace,
            TeamRole::Owner,
        );
        let second_service =
            TeamReplica::open_service(second_authority).expect("second service replica");
        let second_descriptor = second_service
            .service_descriptor("https://localhost:8443", &test_certificate())
            .expect("second descriptor");

        assert!(matches!(
            client.configure_service(&second_descriptor, false),
            Err(TeamReplicationError::ServiceIdentityMismatch)
        ));
        assert!(matches!(
            client.configure_service(&second_descriptor, true),
            Err(TeamReplicationError::ServiceIdentityMismatch)
        ));
    }

    #[test]
    fn replica_physical_store_identity_survives_materialization_and_restart() {
        let fixture = owner_fixture();
        let client = TeamReplica::open_client(fixture.authority.clone()).expect("client");
        let initial_store_id = client
            .lock_runtime()
            .expect("runtime")
            .database
            .store_id()
            .expect("replica store ID");
        let saved = client
            .save_technical_lesson_candidate(
                &draft("stable physical store"),
                source("stable physical store"),
                "agent:test".to_string(),
                chrono::Utc::now().timestamp(),
            )
            .expect("team lesson");
        assert_eq!(saved.provenance.origin_store_id, Some(initial_store_id));
        drop(client);

        let reopened = TeamReplica::open_client(fixture.authority).expect("reopened client");
        let reopened_store_id = reopened
            .lock_runtime()
            .expect("runtime")
            .database
            .store_id()
            .expect("reopened replica store ID");
        assert_eq!(reopened_store_id, initial_store_id);
        let queried = reopened
            .query_technical_lessons(None, 5, chrono::Utc::now().timestamp())
            .expect("reopened query");
        assert_eq!(queried.result.records.len(), 1);
        assert_eq!(
            queried.result.records[0].provenance.origin_store_id,
            Some(initial_store_id)
        );
    }

    #[test]
    fn validly_encrypted_store_replacement_is_rejected_across_restart() {
        let fixture = owner_fixture();
        let authority = fixture.authority.clone();
        let client = TeamReplica::open_client(authority.clone()).expect("client");
        let path = replica_path(&fixture, ReplicaRole::Client, authority.team_id());
        let mut replacement = client.lock_runtime().expect("runtime").state.clone();
        let original_store_id = replacement.store_id;
        replacement.store_id = crate::memory::MemoryStoreId::new();
        assert_ne!(replacement.store_id, original_store_id);
        let encoded = encrypt_state(&authority, ReplicaRole::Client, &replacement)
            .expect("valid replacement envelope");
        fs::write(path, encoded.as_slice()).expect("replace encrypted state");
        drop(client);

        assert!(matches!(
            TeamReplica::open_client(authority),
            Err(TeamReplicationError::RecoveryRequired { .. })
        ));
    }

    #[test]
    fn validly_encrypted_invalid_service_endpoint_is_rejected_on_reopen() {
        let fixture = owner_fixture();
        let (client, _service, _) = configured_replicas(&fixture.authority);
        let path = replica_path(&fixture, ReplicaRole::Client, fixture.authority.team_id());
        let mut replacement = client.lock_runtime().expect("runtime").state.clone();
        replacement
            .pinned_service
            .as_mut()
            .expect("pinned service")
            .endpoint = "http://untrusted.invalid".to_string();
        let encoded = encrypt_state(&fixture.authority, ReplicaRole::Client, &replacement)
            .expect("valid encrypted envelope");
        fs::write(path, encoded.as_slice()).expect("replace encrypted state");
        drop(client);

        assert!(matches!(
            TeamReplica::open_client(fixture.authority),
            Err(TeamReplicationError::CorruptReplica)
        ));
    }

    #[test]
    fn concurrent_push_acknowledgements_are_idempotent_after_outbox_refresh() {
        let fixture = owner_fixture();
        let first = TeamReplica::open_client(fixture.authority.clone()).expect("first client");
        let second = TeamReplica::open_client(fixture.authority.clone()).expect("second client");
        let service = TeamReplica::open_service(fixture.authority).expect("service");
        let descriptor = service
            .service_descriptor("https://localhost:7443", &test_certificate())
            .expect("descriptor");
        first
            .configure_service(&descriptor, false)
            .expect("configure service");
        second.status().expect("refresh service configuration");
        first
            .save_technical_lesson_candidate(
                &draft("concurrent acknowledgement"),
                source("concurrent acknowledgement"),
                "agent:test".to_string(),
                chrono::Utc::now().timestamp(),
            )
            .expect("queue mutation");
        let first_request = first
            .prepare_push()
            .expect("first prepare")
            .expect("first request");
        let second_request = second
            .prepare_push()
            .expect("second prepare")
            .expect("second request");
        assert_eq!(first_request.payload, second_request.payload);

        let first_response = service.handle_push(&first_request).expect("first push");
        assert_eq!(
            first
                .apply_push_ack(&first_request, &first_response)
                .expect("first acknowledgement"),
            1
        );
        let second_response = service.handle_push(&second_request).expect("replayed push");
        assert_eq!(
            second
                .apply_push_ack(&second_request, &second_response)
                .expect("idempotent concurrent acknowledgement"),
            1
        );
        assert_eq!(second.status().expect("status").queued_mutations, 0);
    }

    #[test]
    fn lost_push_response_replays_idempotently_after_both_processes_restart() {
        let fixture = owner_fixture();
        let (client, service, _descriptor) = configured_replicas(&fixture.authority);
        client
            .save_technical_lesson_candidate(
                &draft("restart"),
                source("restart"),
                "agent:test".to_string(),
                chrono::Utc::now().timestamp(),
            )
            .expect("queued lesson");
        let first_request = client
            .prepare_push()
            .expect("prepare first push")
            .expect("first push");
        let _lost_response = service
            .handle_push(&first_request)
            .expect("durable service accept");
        drop(client);
        drop(service);

        let reopened_client =
            TeamReplica::open_client(fixture.authority.clone()).expect("reopen client");
        assert!(
            reopened_client
                .status()
                .expect("reopened pinned client status")
                .service_configured
        );
        let reopened_service =
            TeamReplica::open_service(fixture.authority).expect("reopen service");
        let retry_request = reopened_client
            .prepare_push()
            .expect("prepare retry")
            .expect("retry push");
        assert_eq!(retry_request.payload, first_request.payload);
        let retry_response = reopened_service
            .handle_push(&retry_request)
            .expect("idempotent service retry");
        assert_eq!(
            reopened_client
                .apply_push_ack(&retry_request, &retry_response)
                .expect("consume retry ack"),
            1
        );
        let report = pull_once(&reopened_client, &reopened_service);
        assert_eq!(report.pulled_revisions, 1);
        assert_eq!(report.remaining_outbox, 0);
        assert_eq!(report.freshness, TeamReplicaFreshness::Current);
        let query = reopened_client
            .query_technical_lessons(Some("restart"), 5, chrono::Utc::now().timestamp())
            .expect("query synchronized lesson");
        assert_eq!(query.result.records.len(), 1);
        assert!(query.conflicts.is_empty());
        assert_eq!(reopened_service.status().expect("status").revisions, 1);
    }

    #[test]
    fn actual_push_and_pull_batches_shrink_to_the_exact_wire_budget() {
        let fixture = owner_fixture();
        let (client, service, _) = configured_replicas(&fixture.authority);
        for index in 0..MAX_TEAM_REPLICATION_BATCH {
            let label = format!("wire-{index:02}");
            client
                .save_technical_lesson_candidate(
                    &large_wire_draft(&label),
                    source(&label),
                    "agent:wire-budget".to_string(),
                    chrono::Utc::now().timestamp(),
                )
                .expect("queue large valid lesson");
        }

        let first_push = client
            .prepare_push()
            .expect("prepare bounded push")
            .expect("non-empty push");
        assert!(first_push.payload.mutations.len() < MAX_TEAM_REPLICATION_BATCH);
        assert!(
            encoded_wire_len(&first_push).expect("push size") <= MAX_TEAM_REPLICATION_MESSAGE_BYTES
        );

        let mut pushed = 0;
        while let Some(request) = client.prepare_push().expect("prepare remaining push") {
            let response = service.handle_push(&request).expect("accept bounded push");
            pushed += client
                .apply_push_ack(&request, &response)
                .expect("acknowledge bounded push");
        }
        assert_eq!(pushed, MAX_TEAM_REPLICATION_BATCH);

        let pull_request = client.prepare_pull().expect("prepare pull");
        let pull_response = service.handle_pull(&pull_request).expect("bounded pull");
        assert!(
            pull_response.ack.revisions.len() < MAX_TEAM_REPLICATION_BATCH,
            "lesson bytes={}, pull bytes={}",
            first_push.payload.mutations[0].revision.content.len(),
            encoded_wire_len(&pull_response).expect("measured pull size")
        );
        assert!(
            encoded_wire_len(&pull_response).expect("pull size")
                <= MAX_TEAM_REPLICATION_MESSAGE_BYTES
        );
        assert!(pull_response.ack.more_available);
        assert_eq!(
            pull_response.ack.next_cursor,
            u64::try_from(pull_response.ack.revisions.len()).expect("bounded cursor")
        );
    }

    #[test]
    fn concurrent_offline_corrections_remain_visible_and_revocation_hides_cached_content() {
        let fixture = owner_fixture();
        let member_home = tempfile::tempdir().expect("member home");
        let member = enroll_member(
            &fixture.authority,
            &member_home,
            &fixture.workspace,
            TeamRole::Maintainer,
        );
        let owner_client =
            TeamReplica::open_client(fixture.authority.clone()).expect("owner client");
        let member_client = TeamReplica::open_client(member.clone()).expect("member client");
        let service = TeamReplica::open_service(fixture.authority.clone()).expect("team service");
        let descriptor = service
            .service_descriptor("https://localhost:7443", &test_certificate())
            .expect("descriptor");
        owner_client
            .configure_service(&descriptor, false)
            .expect("owner pin");
        member_client
            .configure_service(&descriptor, false)
            .expect("member pin");

        let root = owner_client
            .save_technical_lesson_candidate(
                &draft("conflict root"),
                source("root"),
                "owner-agent".to_string(),
                chrono::Utc::now().timestamp(),
            )
            .expect("root");
        assert_eq!(push_once(&owner_client, &service), 1);
        pull_once(&owner_client, &service);
        pull_once(&member_client, &service);
        let owner_left = owner_client
            .correct_technical_lesson(TechnicalLessonCorrectionRequest {
                logical_id: root.logical_id,
                expected_record_digest: root.record_digest.clone(),
                replacement: draft("owner branch"),
                correction_reason: "owner observed a platform-specific invariant".to_string(),
                source: source("owner branch"),
                author_id: "owner-agent".to_string(),
                captured_at_unix_seconds: chrono::Utc::now().timestamp(),
            })
            .expect("owner correction");
        let member_right = member_client
            .correct_technical_lesson(TechnicalLessonCorrectionRequest {
                logical_id: root.logical_id,
                expected_record_digest: root.record_digest,
                replacement: draft("member branch"),
                correction_reason: "member observed a different tested invariant".to_string(),
                source: source("member branch"),
                author_id: "member-agent".to_string(),
                captured_at_unix_seconds: chrono::Utc::now().timestamp(),
            })
            .expect("member correction");
        assert_ne!(owner_left.record_digest, member_right.record_digest);
        assert_eq!(push_once(&owner_client, &service), 1);
        assert_eq!(push_once(&member_client, &service), 1);
        pull_once(&owner_client, &service);
        pull_once(&member_client, &service);

        let conflicted = member_client
            .query_technical_lessons(None, 5, chrono::Utc::now().timestamp())
            .expect("conflicted query");
        assert!(conflicted.result.records.is_empty());
        assert_eq!(conflicted.conflicts.len(), 1);
        assert_eq!(conflicted.conflicts[0].heads.len(), 2);
        assert_eq!(conflicted.freshness, TeamReplicaFreshness::Partial);

        let conflict = conflicted.conflicts[0].clone();
        let mut oversized = conflicted;
        oversized.conflicts = vec![conflict; 2_048];
        oversized.conflicts_truncated = false;
        bound_team_query_result(&mut oversized).expect("bound conflict metadata");
        assert!(oversized.conflicts_truncated);
        assert!(
            serde_json::to_vec(&oversized)
                .expect("bounded result")
                .len()
                <= MAX_TECHNICAL_QUERY_RESULT_BYTES
        );

        let member_id = member.local_principal_id().expect("member ID");
        let revoked_bundle = fixture
            .authority
            .revoke_member(&member_id)
            .expect("revoke member");
        member
            .apply_authority_bundle(&revoked_bundle)
            .expect("apply revocation");
        assert!(matches!(
            member_client.query_technical_lessons(None, 5, chrono::Utc::now().timestamp()),
            Err(TeamReplicationError::Authority(_) | TeamReplicationError::Unauthorized)
        ));
    }

    #[test]
    fn concurrent_tombstone_heads_remain_visible_as_a_typed_conflict() {
        let fixture = owner_fixture();
        let member_home = tempfile::tempdir().expect("member home");
        let member = enroll_member(
            &fixture.authority,
            &member_home,
            &fixture.workspace,
            TeamRole::Maintainer,
        );
        let owner_client =
            TeamReplica::open_client(fixture.authority.clone()).expect("owner client");
        let member_client = TeamReplica::open_client(member).expect("member client");
        let service = TeamReplica::open_service(fixture.authority).expect("service");
        let descriptor = service
            .service_descriptor("https://localhost:7443", &test_certificate())
            .expect("descriptor");
        owner_client
            .configure_service(&descriptor, false)
            .expect("owner pin");
        member_client
            .configure_service(&descriptor, false)
            .expect("member pin");
        let root = owner_client
            .save_technical_lesson_candidate(
                &draft("concurrent deletion root"),
                source("concurrent deletion root"),
                "agent:owner".to_string(),
                chrono::Utc::now().timestamp(),
            )
            .expect("root");
        push_once(&owner_client, &service);
        pull_once(&owner_client, &service);
        pull_once(&member_client, &service);

        owner_client
            .delete_technical_lesson(
                root.logical_id,
                &root.record_digest,
                source("owner tombstone"),
                "agent:owner".to_string(),
            )
            .expect("owner tombstone");
        member_client
            .delete_technical_lesson(
                root.logical_id,
                &root.record_digest,
                source("member tombstone"),
                "agent:member".to_string(),
            )
            .expect("member tombstone");
        push_once(&owner_client, &service);
        push_once(&member_client, &service);
        pull_once(&member_client, &service);

        let result = member_client
            .query_technical_lessons(None, 5, chrono::Utc::now().timestamp())
            .expect("conflicted query");
        assert!(result.result.records.is_empty());
        assert_eq!(result.result.omitted_conflicted, 1);
        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.conflicts[0].heads.len(), 2);
        assert!(result.conflicts[0]
            .heads
            .iter()
            .all(|head| head.state == MemoryRevisionState::Tombstone));
        assert_eq!(result.freshness, TeamReplicaFreshness::Partial);
    }

    #[test]
    fn client_revoked_after_request_cannot_apply_an_inflight_acknowledgement() {
        let fixture = owner_fixture();
        let service_home = tempfile::tempdir().expect("service home");
        let service_authority = enroll_member(
            &fixture.authority,
            &service_home,
            &fixture.workspace,
            TeamRole::Owner,
        );
        let client = TeamReplica::open_client(fixture.authority.clone()).expect("client");
        let service = TeamReplica::open_service(service_authority).expect("service");
        let descriptor = service
            .service_descriptor("https://localhost:7443", &test_certificate())
            .expect("descriptor");
        client
            .configure_service(&descriptor, false)
            .expect("configure service");
        client
            .save_technical_lesson_candidate(
                &draft("client revocation race"),
                source("client revocation race"),
                "agent:owner".to_string(),
                chrono::Utc::now().timestamp(),
            )
            .expect("queued lesson");
        let request = client
            .prepare_push()
            .expect("prepare push")
            .expect("queued request");
        let response = service.handle_push(&request).expect("service response");

        fixture
            .authority
            .revoke_member(&"owner".parse().expect("owner principal"))
            .expect("revoke client principal");
        assert!(client.apply_push_ack(&request, &response).is_err());
        assert_eq!(client.status().expect("local status").queued_mutations, 1);
        assert!(matches!(
            TeamReplica::open_client(fixture.authority),
            Err(TeamReplicationError::Unauthorized)
        ));
    }

    #[test]
    fn revoked_service_cannot_mutate_the_replica_before_signing_a_response() {
        let fixture = owner_fixture();
        let service_home = tempfile::tempdir().expect("service home");
        let service_authority = enroll_member(
            &fixture.authority,
            &service_home,
            &fixture.workspace,
            TeamRole::Owner,
        );
        let service_principal = service_authority
            .local_principal_id()
            .expect("service principal");
        let client = TeamReplica::open_client(fixture.authority.clone()).expect("client");
        let service = TeamReplica::open_service(service_authority.clone()).expect("service");
        let descriptor = service
            .service_descriptor("https://localhost:7443", &test_certificate())
            .expect("descriptor");
        client
            .configure_service(&descriptor, false)
            .expect("configure service");
        client
            .save_technical_lesson_candidate(
                &draft("service revocation race"),
                source("service revocation race"),
                "agent:owner".to_string(),
                chrono::Utc::now().timestamp(),
            )
            .expect("queued lesson");
        let request = client
            .prepare_push()
            .expect("prepare push")
            .expect("queued request");
        let revoked = fixture
            .authority
            .revoke_member(&service_principal)
            .expect("revoke service");
        service_authority
            .apply_authority_bundle(&revoked)
            .expect("apply service revocation");

        assert!(service.handle_push(&request).is_err());
        assert_eq!(service.status().expect("service status").revisions, 0);
        assert!(matches!(
            TeamReplica::open_service(service_authority),
            Err(TeamReplicationError::Unauthorized)
        ));
    }

    #[test]
    fn cross_team_tampering_and_exact_grant_replay_are_rejected() {
        let fixture = owner_fixture();
        let (client, service, _) = configured_replicas(&fixture.authority);
        client
            .save_technical_lesson_candidate(
                &draft("tamper"),
                source("tamper"),
                "agent:test".to_string(),
                chrono::Utc::now().timestamp(),
            )
            .expect("lesson");
        let request = client
            .prepare_push()
            .expect("prepare")
            .expect("queued push");
        let mut wrong_team = request.clone();
        wrong_team.payload.team_id = "team-0123456789abcdef0123456789abcdef"
            .parse()
            .expect("other team");
        assert!(matches!(
            service.handle_push(&wrong_team),
            Err(TeamReplicationError::InvalidProtocol)
        ));

        service.handle_push(&request).expect("first exact grant");
        assert!(matches!(
            service.handle_push(&request),
            Err(TeamReplicationError::Unauthorized)
        ));
    }

    #[test]
    fn pull_response_cannot_schedule_unbounded_cycles_without_progress() {
        let fixture = owner_fixture();
        let (client, service, _) = configured_replicas(&fixture.authority);
        let request = client.prepare_pull().expect("pull request");
        let response = service.handle_pull(&request).expect("empty pull response");
        let pinned = client.pinned_service().expect("pinned service");

        let mut no_progress = response.clone();
        no_progress.ack.server_cursor = 1;
        no_progress.ack.more_available = true;
        assert!(matches!(
            validate_pull_response(
                &no_progress,
                &request,
                fixture.authority.team_id(),
                fixture.authority.workspace_id(),
                &pinned,
            ),
            Err(TeamReplicationError::InvalidProtocol)
        ));

        let mut unbounded = response;
        unbounded.ack.server_cursor = MAX_TEAM_REPLICA_REVISIONS as u64 + 1;
        unbounded.ack.more_available = true;
        assert!(matches!(
            validate_pull_response(
                &unbounded,
                &request,
                fixture.authority.team_id(),
                fixture.authority.workspace_id(),
                &pinned,
            ),
            Err(TeamReplicationError::InvalidProtocol)
        ));

        let mut oversized_cursor_request = request;
        oversized_cursor_request.payload.after_cursor = MAX_TEAM_REPLICA_REVISIONS as u64 + 1;
        assert!(matches!(
            validate_pull_request(
                &oversized_cursor_request,
                fixture.authority.team_id(),
                fixture.authority.workspace_id(),
            ),
            Err(TeamReplicationError::InvalidProtocol)
        ));

        let mut ahead_of_service = oversized_cursor_request;
        ahead_of_service.payload.after_cursor = 1;
        let digest = canonical_digest(&ahead_of_service.payload).expect("request digest");
        ahead_of_service.grant = fixture
            .authority
            .issue_grant(
                TeamMemoryOperation::ReplicatePull,
                digest,
                LOCAL_GRANT_TTL_SECONDS,
            )
            .expect("fresh pull grant");
        assert!(matches!(
            service.handle_pull(&ahead_of_service),
            Err(TeamReplicationError::InvalidProtocol)
        ));
    }

    #[test]
    fn pull_response_rejects_duplicate_revision_digests_at_distinct_sequences() {
        let fixture = owner_fixture();
        let (client, service, _) = configured_replicas(&fixture.authority);
        client
            .save_technical_lesson_candidate(
                &draft("duplicate pull"),
                source("duplicate pull"),
                "agent:test".to_string(),
                chrono::Utc::now().timestamp(),
            )
            .expect("lesson");
        push_once(&client, &service);
        let request = client.prepare_pull().expect("pull request");
        let response = service.handle_pull(&request).expect("pull response");
        let pinned = client.pinned_service().expect("pinned service");
        let mut duplicate = response;
        let mut repeated = duplicate.ack.revisions[0].clone();
        repeated.sequence = 2;
        duplicate.ack.revisions.push(repeated);
        duplicate.ack.next_cursor = 2;
        duplicate.ack.server_cursor = 2;
        duplicate.ack.more_available = false;

        assert!(matches!(
            validate_pull_response(
                &duplicate,
                &request,
                fixture.authority.team_id(),
                fixture.authority.workspace_id(),
                &pinned,
            ),
            Err(TeamReplicationError::InvalidProtocol)
        ));
    }

    #[test]
    fn outbox_capacity_check_is_exact_and_never_silently_drops_work() {
        let fixture = owner_fixture();
        let client = TeamReplica::open_client(fixture.authority).expect("client");
        client
            .save_technical_lesson_candidate(
                &draft("capacity"),
                source("capacity"),
                "agent:test".to_string(),
                chrono::Utc::now().timestamp(),
            )
            .expect("seed mutation");
        let mut runtime = client.lock_runtime().expect("runtime");
        let seed = runtime.state.outbox[0].clone();
        runtime.state.outbox = (0..MAX_TEAM_REPLICA_OUTBOX)
            .map(|index| OutboxMutation {
                operation_id: format!("capacity-{index}"),
                ..seed.clone()
            })
            .collect();
        assert!(matches!(
            ensure_outbox_capacity(&runtime.state),
            Err(TeamReplicationError::CapacityExceeded { resource: "outbox" })
        ));
        assert_eq!(runtime.state.outbox.len(), MAX_TEAM_REPLICA_OUTBOX);
    }

    #[test]
    fn nested_authority_and_store_failures_keep_their_actual_disposition() {
        let cases = [
            (
                TeamReplicationError::Authority(TeamAuthorityError::MembershipInvalid),
                TeamReplicationFailureClass::AuthorizationDenied,
            ),
            (
                TeamReplicationError::Authority(TeamAuthorityError::CapacityExceeded {
                    resource: "audit receipts",
                }),
                TeamReplicationFailureClass::CapacityExceeded,
            ),
            (
                TeamReplicationError::Authority(TeamAuthorityError::ConcurrentUpdate),
                TeamReplicationFailureClass::ConcurrentUpdate,
            ),
            (
                TeamReplicationError::Authority(TeamAuthorityError::ClockRollback),
                TeamReplicationFailureClass::IntegrityFailure,
            ),
            (
                TeamReplicationError::Authority(TeamAuthorityError::CredentialUnavailable),
                TeamReplicationFailureClass::Unavailable,
            ),
            (
                TeamReplicationError::Store(anyhow::Error::new(
                    TechnicalLessonStoreError::UnresolvedConflict,
                )),
                TeamReplicationFailureClass::ConcurrentUpdate,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.failure_class(), expected, "{error}");
        }
    }
}
