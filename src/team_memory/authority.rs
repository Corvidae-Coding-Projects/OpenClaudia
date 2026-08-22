//! Host-owned authenticated authority for team technical memory.
//!
//! This module deliberately does not move lesson content. It establishes the
//! identity, membership, role, credential, grant, revocation, and audit
//! boundary consumed by the bounded replication service. A
//! repository may name a [`TeamId`], but neither a repository file nor a
//! filesystem path can create membership or grant access.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand::rngs::SysRng;
use rand::TryRng as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

use crate::memory::{MemoryDb, MemoryStoreId, WorkspaceMemoryId};
use crate::persistence::{
    CommitState, FileClass, PersistenceError, PersistentStorage, StorageGeneration,
};
use crate::runtime::ContentDigest;
use crate::secrets::{SecretString, SecretValueError};

/// Persisted authority format understood by this build.
pub const TEAM_AUTHORITY_SCHEMA_VERSION: u32 = 1;
/// Signed public artifact format understood by this build.
pub const TEAM_AUTHORITY_ARTIFACT_SCHEMA_VERSION: u32 = 1;
/// Maximum lifetime of an operation grant.
pub const MAX_TEAM_GRANT_TTL_SECONDS: i64 = 5 * 60;
/// Maximum lifetime of a public enrollment invitation or request.
pub const MAX_TEAM_ENROLLMENT_TTL_SECONDS: i64 = 24 * 60 * 60;
/// Maximum members retained in one authority document.
pub const MAX_TEAM_MEMBERS: usize = 512;
/// Maximum unexpired consumed grants retained for replay defense.
pub const MAX_CONSUMED_TEAM_GRANTS: usize = 1_024;
/// Maximum causally linked audit entries retained locally.
pub const MAX_TEAM_AUDIT_EVENTS: usize = 512;
/// Maximum accepted bytes for one public signed authority artifact.
pub const MAX_TEAM_AUTHORITY_ARTIFACT_BYTES: usize = 256 * 1_024;
const MAX_AUTHORITY_RETRIES: usize = 8;
const MAX_PRINCIPAL_ID_BYTES: usize = 64;
const MAX_KEY_EPOCHS: usize = 64;

/// Typed failures at the team-memory authority boundary.
#[derive(Debug, Error)]
pub enum TeamAuthorityError {
    #[error("team authority is not enrolled on this host")]
    Unenrolled,
    #[error("team authority enrollment is still pending")]
    EnrollmentPending,
    #[error("team authority is already enrolled on this host")]
    AlreadyEnrolled,
    #[error("team authority requires host recovery: {reason}")]
    RecoveryRequired { reason: &'static str },
    #[error("invalid {kind} identity")]
    InvalidIdentity { kind: &'static str },
    #[error("team authority artifact is malformed or unsupported")]
    InvalidArtifact,
    #[error("team authority signature validation failed")]
    InvalidSignature,
    #[error("team authority artifact does not belong to this team or workspace")]
    ScopeMismatch,
    #[error("team authority artifact is expired or not yet valid")]
    Expired,
    #[error("team authority clock moved backwards")]
    ClockRollback,
    #[error("team membership is missing, revoked, expired, or stale")]
    MembershipInvalid,
    #[error("team role does not permit {operation}")]
    RoleDenied { operation: TeamMemoryOperation },
    #[error("team operation grant has already been consumed")]
    GrantReplay,
    #[error("team operation grant does not match the requested operation")]
    GrantMismatch,
    #[error("team authority state reached its bounded {resource} capacity")]
    CapacityExceeded { resource: &'static str },
    #[error("team authority update conflicted repeatedly; retry the operation")]
    ConcurrentUpdate,
    #[error("team authority private credential is unavailable for this operation")]
    CredentialUnavailable,
    #[error("team authority operation requires the owner role")]
    OwnerRequired,
    #[error("team authority persistence failed: {0}")]
    Persistence(#[from] PersistenceError),
    #[error("team authority secret could not be protected: {0}")]
    Secret(#[from] SecretValueError),
    #[error("team authority workspace storage failed: {0}")]
    Workspace(String),
}

macro_rules! opaque_random_id {
    ($name:ident, $prefix:literal, $kind:literal) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            fn random() -> Result<Self, TeamAuthorityError> {
                let mut bytes = [0_u8; 16];
                SysRng.try_fill_bytes(&mut bytes).map_err(|_| {
                    TeamAuthorityError::RecoveryRequired {
                        reason: "operating-system randomness is unavailable",
                    }
                })?;
                let mut value = String::with_capacity($prefix.len() + 32);
                value.push_str($prefix);
                for byte in bytes {
                    use fmt::Write as _;
                    let _ = write!(value, "{byte:02x}");
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl FromStr for $name {
            type Err = TeamAuthorityError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let Some(hex) = value.strip_prefix($prefix) else {
                    return Err(TeamAuthorityError::InvalidIdentity { kind: $kind });
                };
                if hex.len() != 32
                    || !hex
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(TeamAuthorityError::InvalidIdentity { kind: $kind });
                }
                Ok(Self(value.to_string()))
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                String::deserialize(deserializer)?
                    .parse()
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

opaque_random_id!(TeamId, "team-", "team");
opaque_random_id!(MembershipId, "membership-", "membership");
opaque_random_id!(TeamGrantId, "grant-", "grant");
opaque_random_id!(EnrollmentInvitationId, "invitation-", "invitation");
opaque_random_id!(EnrollmentRequestId, "request-", "enrollment request");

/// Stable, human-selected principal name. It is identity metadata, never a
/// credential or an authorization decision by itself.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalId(String);

impl PrincipalId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Debug for PrincipalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("PrincipalId").field(&self.0).finish()
    }
}

impl FromStr for PrincipalId {
    type Err = TeamAuthorityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let valid = !value.is_empty()
            && value.len() <= MAX_PRINCIPAL_ID_BYTES
            && value.bytes().enumerate().all(|(index, byte)| match byte {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => true,
                b'.' | b'_' | b'-' => index > 0,
                _ => false,
            });
        if !valid {
            return Err(TeamAuthorityError::InvalidIdentity { kind: "principal" });
        }
        Ok(Self(value.to_string()))
    }
}

impl Serialize for PrincipalId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PrincipalId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Member role enforced for every exact team-memory operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamRole {
    Reader,
    Contributor,
    Maintainer,
    Owner,
}

impl TeamRole {
    /// Whether this role permits one canonical operation.
    #[must_use]
    pub const fn permits(self, operation: TeamMemoryOperation) -> bool {
        match operation {
            TeamMemoryOperation::List
            | TeamMemoryOperation::Search
            | TeamMemoryOperation::ReplicatePull
            | TeamMemoryOperation::ManageOwnCredential => true,
            TeamMemoryOperation::Propose | TeamMemoryOperation::ReplicatePush => {
                !matches!(self, Self::Reader)
            }
            TeamMemoryOperation::Correct
            | TeamMemoryOperation::Resolve
            | TeamMemoryOperation::Delete
            | TeamMemoryOperation::Review
            | TeamMemoryOperation::Export
            | TeamMemoryOperation::Import => {
                matches!(self, Self::Maintainer | Self::Owner)
            }
            TeamMemoryOperation::Admin => matches!(self, Self::Owner),
        }
    }
}

impl fmt::Display for TeamRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Reader => "reader",
            Self::Contributor => "contributor",
            Self::Maintainer => "maintainer",
            Self::Owner => "owner",
        })
    }
}

impl FromStr for TeamRole {
    type Err = TeamAuthorityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "reader" => Ok(Self::Reader),
            "contributor" => Ok(Self::Contributor),
            "maintainer" => Ok(Self::Maintainer),
            "owner" => Ok(Self::Owner),
            _ => Err(TeamAuthorityError::InvalidArtifact),
        }
    }
}

/// Exact operation bound into a one-use signed grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamMemoryOperation {
    List,
    Search,
    Propose,
    Correct,
    Resolve,
    Delete,
    Review,
    Export,
    Import,
    Admin,
    ReplicatePull,
    ReplicatePush,
    /// Local credential rotation only; never grants access to lesson data.
    ManageOwnCredential,
}

impl fmt::Display for TeamMemoryOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::List => "list",
            Self::Search => "search",
            Self::Propose => "propose",
            Self::Correct => "correct",
            Self::Resolve => "resolve",
            Self::Delete => "delete",
            Self::Review => "review",
            Self::Export => "export",
            Self::Import => "import",
            Self::Admin => "admin",
            Self::ReplicatePull => "replicate_pull",
            Self::ReplicatePush => "replicate_push",
            Self::ManageOwnCredential => "manage_own_credential",
        })
    }
}

/// Fixed-size encoded Ed25519 public key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TeamPublicKey(String);

impl fmt::Debug for TeamPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TeamPublicKey")
            .field(&self.0)
            .finish()
    }
}

impl TeamPublicKey {
    fn from_key(key: &VerifyingKey) -> Self {
        Self(BASE64_STANDARD.encode(key.to_bytes()))
    }

    fn decode(&self) -> Result<VerifyingKey, TeamAuthorityError> {
        let bytes = BASE64_STANDARD
            .decode(&self.0)
            .map_err(|_| TeamAuthorityError::InvalidArtifact)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| TeamAuthorityError::InvalidArtifact)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| TeamAuthorityError::InvalidArtifact)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Fixed-size encoded Ed25519 signature.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TeamSignature(String);

impl fmt::Debug for TeamSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TeamSignature")
            .field(&self.0)
            .finish()
    }
}

impl TeamSignature {
    fn sign(key: &SigningKey, message: &[u8]) -> Self {
        Self(BASE64_STANDARD.encode(key.sign(message).to_bytes()))
    }

    fn verify(&self, key: &VerifyingKey, message: &[u8]) -> Result<(), TeamAuthorityError> {
        let bytes = BASE64_STANDARD
            .decode(&self.0)
            .map_err(|_| TeamAuthorityError::InvalidArtifact)?;
        let bytes: [u8; 64] = bytes
            .try_into()
            .map_err(|_| TeamAuthorityError::InvalidArtifact)?;
        key.verify(message, &Signature::from_bytes(&bytes))
            .map_err(|_| TeamAuthorityError::InvalidSignature)
    }
}

/// One public member record signed by the current team authority key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamMembership {
    membership_id: MembershipId,
    principal_id: PrincipalId,
    role: TeamRole,
    expires_at_unix_seconds: i64,
    membership_generation: u64,
    principal_key_generation: u64,
    principal_public_key: TeamPublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revoked_at_unix_seconds: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    enrollment_request_digest: Option<ContentDigest>,
}

impl TeamMembership {
    #[must_use]
    pub const fn role(&self) -> TeamRole {
        self.role
    }

    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    #[must_use]
    pub const fn membership_id(&self) -> &MembershipId {
        &self.membership_id
    }

    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> i64 {
        self.expires_at_unix_seconds
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked_at_unix_seconds.is_some()
    }
}

/// Signed current membership and policy document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamAuthorityDocument {
    schema_version: u32,
    team_id: TeamId,
    workspace_id: WorkspaceMemoryId,
    authority_generation: u64,
    authority_key_generation: u64,
    members: Vec<TeamMembership>,
}

impl TeamAuthorityDocument {
    #[must_use]
    pub const fn team_id(&self) -> &TeamId {
        &self.team_id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceMemoryId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn authority_generation(&self) -> u64 {
        self.authority_generation
    }

    #[must_use]
    pub fn members(&self) -> &[TeamMembership] {
        &self.members
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityKeyTransition {
    schema_version: u32,
    team_id: TeamId,
    workspace_id: WorkspaceMemoryId,
    previous_generation: u64,
    next_generation: u64,
    next_public_key: TeamPublicKey,
}

/// One authority-key epoch. Every epoch after the trust anchor is signed by
/// the immediately preceding key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityKeyEpoch {
    generation: u64,
    public_key: TeamPublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_signature: Option<TeamSignature>,
}

/// Public trust bundle distributed during enrollment and authority updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamAuthorityBundle {
    schema_version: u32,
    trust_anchor: TeamPublicKey,
    key_epochs: Vec<AuthorityKeyEpoch>,
    document: TeamAuthorityDocument,
    document_signature: TeamSignature,
}

impl TeamAuthorityBundle {
    #[must_use]
    pub const fn document(&self) -> &TeamAuthorityDocument {
        &self.document
    }

    #[must_use]
    pub const fn team_id(&self) -> &TeamId {
        self.document.team_id()
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceMemoryId {
        self.document.workspace_id()
    }
}

/// Public, authority-signed invitation to begin enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamEnrollmentInvitation {
    schema_version: u32,
    invitation_id: EnrollmentInvitationId,
    issued_at_unix_seconds: i64,
    expires_at_unix_seconds: i64,
    bundle: TeamAuthorityBundle,
    signature: TeamSignature,
}

impl TeamEnrollmentInvitation {
    #[must_use]
    pub const fn team_id(&self) -> &TeamId {
        self.bundle.document.team_id()
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceMemoryId {
        self.bundle.document.workspace_id()
    }
}

/// Public proof-of-possession request created by the enrolling principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamEnrollmentRequest {
    schema_version: u32,
    request_id: EnrollmentRequestId,
    invitation_id: EnrollmentInvitationId,
    invitation_digest: ContentDigest,
    team_id: TeamId,
    workspace_id: WorkspaceMemoryId,
    principal_id: PrincipalId,
    principal_public_key: TeamPublicKey,
    principal_key_generation: u64,
    issued_at_unix_seconds: i64,
    expires_at_unix_seconds: i64,
    proof_signature: TeamSignature,
}

impl TeamEnrollmentRequest {
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }
}

/// Public approval binding one enrollment request to a signed membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamEnrollmentApproval {
    schema_version: u32,
    request_digest: ContentDigest,
    bundle: TeamAuthorityBundle,
}

impl TeamEnrollmentApproval {
    #[must_use]
    pub const fn team_id(&self) -> &TeamId {
        self.bundle.team_id()
    }
}

/// Public request to replace one principal key while proving possession of
/// both the currently authorized key and the proposed successor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamCredentialRotationRequest {
    schema_version: u32,
    team_id: TeamId,
    workspace_id: WorkspaceMemoryId,
    principal_id: PrincipalId,
    membership_id: MembershipId,
    current_key_generation: u64,
    next_key_generation: u64,
    next_public_key: TeamPublicKey,
    authority_generation: u64,
    issued_at_unix_seconds: i64,
    expires_at_unix_seconds: i64,
    current_key_signature: TeamSignature,
    next_key_signature: TeamSignature,
}

impl TeamCredentialRotationRequest {
    #[must_use]
    pub const fn team_id(&self) -> &TeamId {
        &self.team_id
    }
}

/// One signed, short-lived, exact-operation authorization request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamOperationGrant {
    schema_version: u32,
    grant_id: TeamGrantId,
    team_id: TeamId,
    workspace_id: WorkspaceMemoryId,
    principal_id: PrincipalId,
    membership_id: MembershipId,
    role: TeamRole,
    operation: TeamMemoryOperation,
    request_digest: ContentDigest,
    authority_generation: u64,
    authority_key_generation: u64,
    membership_generation: u64,
    principal_key_generation: u64,
    issued_at_unix_seconds: i64,
    expires_at_unix_seconds: i64,
    signature: TeamSignature,
}

impl TeamOperationGrant {
    #[must_use]
    pub const fn grant_id(&self) -> &TeamGrantId {
        &self.grant_id
    }

    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    #[must_use]
    pub const fn operation(&self) -> TeamMemoryOperation {
        self.operation
    }

    #[must_use]
    pub const fn request_digest(&self) -> ContentDigest {
        self.request_digest
    }
}

/// Redacted authorization decision emitted only after its audit event is
/// durably committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamAuditReceipt {
    pub sequence: u64,
    pub operation: TeamMemoryOperation,
    pub allowed: bool,
    pub decision_code: TeamAuditDecisionCode,
    pub event_digest: ContentDigest,
}

/// Public result of an explicit host recovery authorized by possession of the
/// current team authority signing credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamOwnerRecovery {
    pub bundle: TeamAuthorityBundle,
    pub receipt: TeamAuditReceipt,
}

/// Stable reason recorded for an allowed or denied authorization attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamAuditDecisionCode {
    Allowed,
    RecoveryAllowed,
    ScopeMismatch,
    Expired,
    ClockRollback,
    MembershipInvalid,
    RoleDenied,
    GrantReplay,
    GrantMismatch,
    InvalidSignature,
    CapacityExceeded,
}

/// Typed denial paired with a durably published redacted audit receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamAuthorizationDenial {
    ScopeMismatch,
    Expired,
    ClockRollback,
    MembershipInvalid,
    RoleDenied,
    GrantReplay,
    GrantMismatch,
    InvalidSignature,
    CapacityExceeded,
}

/// Authorization cannot be mistaken for execution: only the authorized
/// variant contains the opaque downstream permit.
#[derive(Debug)]
pub enum TeamAuthorizationOutcome {
    Authorized(TeamOperationPermit),
    Denied {
        receipt: TeamAuditReceipt,
        reason: TeamAuthorizationDenial,
    },
}

/// Opaque, single-operation capability returned only after durable grant
/// consumption and audit publication.
pub struct TeamOperationPermit {
    team_id: TeamId,
    workspace_id: WorkspaceMemoryId,
    principal_id: PrincipalId,
    membership_id: MembershipId,
    role: TeamRole,
    operation: TeamMemoryOperation,
    request_digest: ContentDigest,
    authority_generation: u64,
    authority_key_generation: u64,
    membership_generation: u64,
    principal_key_generation: u64,
    expires_at_unix_seconds: i64,
    receipt: TeamAuditReceipt,
}

impl fmt::Debug for TeamOperationPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TeamOperationPermit")
            .field("operation", &self.operation)
            .field("receipt", &self.receipt)
            .finish_non_exhaustive()
    }
}

impl TeamOperationPermit {
    #[must_use]
    pub const fn receipt(&self) -> &TeamAuditReceipt {
        &self.receipt
    }

    /// Verify that a downstream operation is using the exact capability it
    /// requested. No constructor exists outside this module.
    ///
    /// # Errors
    /// Returns [`TeamAuthorityError::GrantMismatch`] when any exact operation
    /// scope or request binding differs.
    pub fn require(
        &self,
        team_id: &TeamId,
        workspace_id: &WorkspaceMemoryId,
        operation: TeamMemoryOperation,
        request_digest: ContentDigest,
    ) -> Result<(), TeamAuthorityError> {
        if &self.team_id != team_id
            || &self.workspace_id != workspace_id
            || self.operation != operation
            || self.request_digest != request_digest
        {
            return Err(TeamAuthorityError::GrantMismatch);
        }
        Ok(())
    }

    fn require_current(
        &self,
        bundle: &TeamAuthorityBundle,
        now: i64,
    ) -> Result<(), TeamAuthorityError> {
        if bundle.document.authority_generation != self.authority_generation
            || bundle.document.authority_key_generation != self.authority_key_generation
            || now >= self.expires_at_unix_seconds
        {
            return Err(TeamAuthorityError::MembershipInvalid);
        }
        let member = member_for_principal(&bundle.document, &self.principal_id)
            .ok_or(TeamAuthorityError::MembershipInvalid)?;
        if member.membership_id != self.membership_id
            || member.role != self.role
            || member.membership_generation != self.membership_generation
            || member.principal_key_generation != self.principal_key_generation
            || !member.role.permits(self.operation)
        {
            return Err(TeamAuthorityError::MembershipInvalid);
        }
        require_active_member(member, now)
    }
}

/// Host-local authority lifecycle state safe for display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum TeamAuthorityStatus {
    Unenrolled,
    Pending {
        team_id: TeamId,
        workspace_id: WorkspaceMemoryId,
        principal_id: PrincipalId,
    },
    Active {
        team_id: TeamId,
        workspace_id: WorkspaceMemoryId,
        principal_id: PrincipalId,
        role: TeamRole,
        authority_generation: u64,
        authority_key_generation: u64,
        membership_generation: u64,
        principal_key_generation: u64,
        expires_at_unix_seconds: i64,
        audit_events: usize,
    },
    Revoked {
        team_id: TeamId,
        workspace_id: WorkspaceMemoryId,
        principal_id: PrincipalId,
    },
    Expired {
        team_id: TeamId,
        workspace_id: WorkspaceMemoryId,
        principal_id: PrincipalId,
        expires_at_unix_seconds: i64,
    },
    RecoveryRequired,
}

fn now_unix_seconds() -> Result<i64, TeamAuthorityError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TeamAuthorityError::RecoveryRequired {
            reason: "system clock is before the Unix epoch",
        })?
        .as_secs();
    i64::try_from(seconds).map_err(|_| TeamAuthorityError::RecoveryRequired {
        reason: "system clock cannot be represented",
    })
}

fn generate_signing_key() -> Result<SigningKey, TeamAuthorityError> {
    let mut secret = [0_u8; 32];
    SysRng
        .try_fill_bytes(&mut secret)
        .map_err(|_| TeamAuthorityError::RecoveryRequired {
            reason: "operating-system randomness is unavailable",
        })?;
    let key = SigningKey::from_bytes(&secret);
    secret.zeroize();
    Ok(key)
}

fn generate_replica_storage_secret() -> Result<SecretString, TeamAuthorityError> {
    let mut secret = [0_u8; 32];
    SysRng
        .try_fill_bytes(&mut secret)
        .map_err(|_| TeamAuthorityError::RecoveryRequired {
            reason: "operating-system randomness is unavailable",
        })?;
    let encoded = BASE64_STANDARD.encode(secret);
    secret.zeroize();
    SecretString::try_from_string(encoded).map_err(Into::into)
}

fn decode_replica_storage_secret(
    secret: &SecretString,
) -> Result<Zeroizing<[u8; 32]>, TeamAuthorityError> {
    secret.expose(|encoded| {
        let mut bytes =
            BASE64_STANDARD
                .decode(encoded)
                .map_err(|_| TeamAuthorityError::RecoveryRequired {
                    reason: "replica encryption credential encoding is corrupt",
                })?;
        let key =
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| TeamAuthorityError::RecoveryRequired {
                    reason: "replica encryption credential length is corrupt",
                })?;
        bytes.zeroize();
        Ok(Zeroizing::new(key))
    })
}

fn random_authorization_attempt_digest() -> Result<ContentDigest, TeamAuthorityError> {
    let mut random = [0_u8; 32];
    SysRng
        .try_fill_bytes(&mut random)
        .map_err(|_| TeamAuthorityError::RecoveryRequired {
            reason: "operating-system randomness is unavailable",
        })?;
    let mut material = Zeroizing::new(Vec::with_capacity(69));
    material.extend_from_slice(b"openclaudia.team-authority.authorization-attempt.v1\0");
    material.extend_from_slice(&random);
    random.zeroize();
    Ok(ContentDigest::sha256(&*material))
}

fn signing_key_to_secret(key: &SigningKey) -> Result<SecretString, TeamAuthorityError> {
    SecretString::try_from_string(BASE64_STANDARD.encode(key.to_bytes())).map_err(Into::into)
}

fn secret_to_signing_key(secret: &SecretString) -> Result<SigningKey, TeamAuthorityError> {
    secret.expose(|encoded| {
        let mut bytes =
            BASE64_STANDARD
                .decode(encoded)
                .map_err(|_| TeamAuthorityError::RecoveryRequired {
                    reason: "private credential encoding is corrupt",
                })?;
        let key_bytes: [u8; 32] =
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| TeamAuthorityError::RecoveryRequired {
                    reason: "private credential length is corrupt",
                })?;
        let key = SigningKey::from_bytes(&key_bytes);
        bytes.zeroize();
        Ok(key)
    })
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, TeamAuthorityError> {
    serde_json::to_vec(value).map_err(|_| TeamAuthorityError::InvalidArtifact)
}

fn digest_serialized(value: &impl Serialize) -> Result<ContentDigest, TeamAuthorityError> {
    Ok(ContentDigest::sha256(canonical_bytes(value)?))
}

const fn validate_time_window(
    issued_at: i64,
    expires_at: i64,
    now: i64,
    max_ttl: i64,
) -> Result<(), TeamAuthorityError> {
    if issued_at < 0
        || expires_at <= issued_at
        || expires_at - issued_at > max_ttl
        || now < issued_at
        || now >= expires_at
    {
        return Err(TeamAuthorityError::Expired);
    }
    Ok(())
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAuthorityState {
    schema_version: u32,
    team_id: TeamId,
    workspace_id: WorkspaceMemoryId,
    last_observed_unix_seconds: i64,
    local: StoredLocalAuthority,
    consumed_grants: Vec<ConsumedGrant>,
    audit_anchor: ContentDigest,
    audit_events: Vec<TeamAuditEvent>,
    next_audit_sequence: u64,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "snake_case", tag = "lifecycle", deny_unknown_fields)]
enum StoredLocalAuthority {
    Pending {
        principal_id: PrincipalId,
        principal_secret_key: SecretString,
        invitation: TeamEnrollmentInvitation,
        request: TeamEnrollmentRequest,
    },
    Active {
        principal_id: PrincipalId,
        principal_secret_key: SecretString,
        #[serde(default)]
        authority_secret_key: Option<SecretString>,
        #[serde(default)]
        replica_storage_secret_key: Option<SecretString>,
        #[serde(default)]
        replica_identities: ReplicaIdentityAnchors,
        bundle: TeamAuthorityBundle,
        #[serde(default)]
        pending_rotation: Option<PendingCredentialRotation>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplicaIdentityAnchors {
    client: Option<ReplicaIdentityAnchor>,
    service: Option<ReplicaIdentityAnchor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplicaIdentityAnchor {
    replica_id: String,
    store_id: MemoryStoreId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplicaAuthorityRole {
    Client,
    Service,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingCredentialRotation {
    request: TeamCredentialRotationRequest,
    next_secret_key: SecretString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumedGrant {
    grant_id: TeamGrantId,
    expires_at_unix_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TeamAuditEvent {
    sequence: u64,
    timestamp_unix_seconds: i64,
    operation: TeamMemoryOperation,
    allowed: bool,
    decision_code: TeamAuditDecisionCode,
    grant_digest: ContentDigest,
    principal_digest: ContentDigest,
    request_digest: ContentDigest,
    authorization_attempt_digest: ContentDigest,
    previous_event_digest: ContentDigest,
    event_digest: ContentDigest,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedAuditEvent {
    sequence: u64,
    timestamp_unix_seconds: i64,
    operation: TeamMemoryOperation,
    allowed: bool,
    decision_code: TeamAuditDecisionCode,
    grant_digest: ContentDigest,
    principal_digest: ContentDigest,
    request_digest: ContentDigest,
    authorization_attempt_digest: ContentDigest,
    previous_event_digest: ContentDigest,
}

struct RawSecret<'a>(&'a SecretString);

impl Serialize for RawSecret<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.expose(|raw| serializer.serialize_str(raw))
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct StoredAuthorityStateRef<'a> {
    schema_version: u32,
    team_id: &'a TeamId,
    workspace_id: &'a WorkspaceMemoryId,
    last_observed_unix_seconds: i64,
    local: StoredLocalAuthorityRef<'a>,
    consumed_grants: &'a [ConsumedGrant],
    audit_anchor: ContentDigest,
    audit_events: &'a [TeamAuditEvent],
    next_audit_sequence: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case", tag = "lifecycle", deny_unknown_fields)]
enum StoredLocalAuthorityRef<'a> {
    Pending {
        principal_id: &'a PrincipalId,
        principal_secret_key: RawSecret<'a>,
        invitation: &'a TeamEnrollmentInvitation,
        request: &'a TeamEnrollmentRequest,
    },
    Active {
        principal_id: &'a PrincipalId,
        principal_secret_key: RawSecret<'a>,
        authority_secret_key: Option<RawSecret<'a>>,
        replica_storage_secret_key: Option<RawSecret<'a>>,
        replica_identities: &'a ReplicaIdentityAnchors,
        bundle: &'a TeamAuthorityBundle,
        pending_rotation: Option<PendingCredentialRotationRef<'a>>,
    },
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PendingCredentialRotationRef<'a> {
    request: &'a TeamCredentialRotationRequest,
    next_secret_key: RawSecret<'a>,
}

impl StoredAuthorityState {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, TeamAuthorityError> {
        let local = match &self.local {
            StoredLocalAuthority::Pending {
                principal_id,
                principal_secret_key,
                invitation,
                request,
            } => StoredLocalAuthorityRef::Pending {
                principal_id,
                principal_secret_key: RawSecret(principal_secret_key),
                invitation,
                request,
            },
            StoredLocalAuthority::Active {
                principal_id,
                principal_secret_key,
                authority_secret_key,
                replica_storage_secret_key,
                replica_identities,
                bundle,
                pending_rotation,
            } => StoredLocalAuthorityRef::Active {
                principal_id,
                principal_secret_key: RawSecret(principal_secret_key),
                authority_secret_key: authority_secret_key.as_ref().map(RawSecret),
                replica_storage_secret_key: replica_storage_secret_key.as_ref().map(RawSecret),
                replica_identities,
                bundle,
                pending_rotation: pending_rotation.as_ref().map(|pending| {
                    PendingCredentialRotationRef {
                        request: &pending.request,
                        next_secret_key: RawSecret(&pending.next_secret_key),
                    }
                }),
            },
        };
        let encoded = serde_json::to_vec(&StoredAuthorityStateRef {
            schema_version: self.schema_version,
            team_id: &self.team_id,
            workspace_id: &self.workspace_id,
            last_observed_unix_seconds: self.last_observed_unix_seconds,
            local,
            consumed_grants: &self.consumed_grants,
            audit_anchor: self.audit_anchor,
            audit_events: &self.audit_events,
            next_audit_sequence: self.next_audit_sequence,
        })
        .map_err(|_| TeamAuthorityError::RecoveryRequired {
            reason: "credential state could not be encoded",
        })?;
        if encoded.len() as u64 > FileClass::Credentials.max_bytes() {
            return Err(TeamAuthorityError::CapacityExceeded {
                resource: "credential file",
            });
        }
        Ok(Zeroizing::new(encoded))
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedInvitation<'a> {
    schema_version: u32,
    invitation_id: &'a EnrollmentInvitationId,
    issued_at_unix_seconds: i64,
    expires_at_unix_seconds: i64,
    bundle: &'a TeamAuthorityBundle,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedEnrollmentRequest<'a> {
    schema_version: u32,
    request_id: &'a EnrollmentRequestId,
    invitation_id: &'a EnrollmentInvitationId,
    invitation_digest: ContentDigest,
    team_id: &'a TeamId,
    workspace_id: &'a WorkspaceMemoryId,
    principal_id: &'a PrincipalId,
    principal_public_key: &'a TeamPublicKey,
    principal_key_generation: u64,
    issued_at_unix_seconds: i64,
    expires_at_unix_seconds: i64,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedCredentialRotationRequest<'a> {
    schema_version: u32,
    team_id: &'a TeamId,
    workspace_id: &'a WorkspaceMemoryId,
    principal_id: &'a PrincipalId,
    membership_id: &'a MembershipId,
    current_key_generation: u64,
    next_key_generation: u64,
    next_public_key: &'a TeamPublicKey,
    authority_generation: u64,
    issued_at_unix_seconds: i64,
    expires_at_unix_seconds: i64,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedOperationGrant<'a> {
    schema_version: u32,
    grant_id: &'a TeamGrantId,
    team_id: &'a TeamId,
    workspace_id: &'a WorkspaceMemoryId,
    principal_id: &'a PrincipalId,
    membership_id: &'a MembershipId,
    role: TeamRole,
    operation: TeamMemoryOperation,
    request_digest: ContentDigest,
    authority_generation: u64,
    authority_key_generation: u64,
    membership_generation: u64,
    principal_key_generation: u64,
    issued_at_unix_seconds: i64,
    expires_at_unix_seconds: i64,
}

fn authority_document_bytes(
    document: &TeamAuthorityDocument,
) -> Result<Vec<u8>, TeamAuthorityError> {
    canonical_bytes(document)
}

fn current_authority_key(bundle: &TeamAuthorityBundle) -> Result<VerifyingKey, TeamAuthorityError> {
    bundle
        .key_epochs
        .last()
        .ok_or(TeamAuthorityError::InvalidArtifact)?
        .public_key
        .decode()
}

fn validate_authority_bundle(
    bundle: &TeamAuthorityBundle,
    expected_team_id: &TeamId,
    expected_workspace_id: &WorkspaceMemoryId,
) -> Result<(), TeamAuthorityError> {
    if bundle.schema_version != TEAM_AUTHORITY_ARTIFACT_SCHEMA_VERSION
        || bundle.document.schema_version != TEAM_AUTHORITY_ARTIFACT_SCHEMA_VERSION
    {
        return Err(TeamAuthorityError::InvalidArtifact);
    }
    if &bundle.document.team_id != expected_team_id
        || &bundle.document.workspace_id != expected_workspace_id
    {
        return Err(TeamAuthorityError::ScopeMismatch);
    }
    if bundle.key_epochs.is_empty() || bundle.key_epochs.len() > MAX_KEY_EPOCHS {
        return Err(TeamAuthorityError::InvalidArtifact);
    }
    let first = &bundle.key_epochs[0];
    if first.generation != 1
        || first.previous_signature.is_some()
        || first.public_key != bundle.trust_anchor
    {
        return Err(TeamAuthorityError::InvalidArtifact);
    }
    let mut previous_key = first.public_key.decode()?;
    let mut previous_generation = first.generation;
    for epoch in bundle.key_epochs.iter().skip(1) {
        if epoch.generation != previous_generation.saturating_add(1) {
            return Err(TeamAuthorityError::InvalidArtifact);
        }
        let transition = AuthorityKeyTransition {
            schema_version: TEAM_AUTHORITY_ARTIFACT_SCHEMA_VERSION,
            team_id: expected_team_id.clone(),
            workspace_id: expected_workspace_id.clone(),
            previous_generation,
            next_generation: epoch.generation,
            next_public_key: epoch.public_key.clone(),
        };
        epoch
            .previous_signature
            .as_ref()
            .ok_or(TeamAuthorityError::InvalidArtifact)?
            .verify(&previous_key, &canonical_bytes(&transition)?)?;
        previous_key = epoch.public_key.decode()?;
        previous_generation = epoch.generation;
    }
    if bundle.document.authority_key_generation != previous_generation
        || bundle.document.authority_generation == 0
    {
        return Err(TeamAuthorityError::InvalidArtifact);
    }
    bundle
        .document_signature
        .verify(&previous_key, &authority_document_bytes(&bundle.document)?)?;
    validate_members(&bundle.document.members)?;
    Ok(())
}

fn validate_members(members: &[TeamMembership]) -> Result<(), TeamAuthorityError> {
    if members.is_empty() || members.len() > MAX_TEAM_MEMBERS {
        return Err(TeamAuthorityError::InvalidArtifact);
    }
    let mut principal_ids = BTreeSet::new();
    let mut membership_ids = BTreeSet::new();
    let mut previous_principal: Option<&PrincipalId> = None;
    let mut active_owner = false;
    for member in members {
        if previous_principal.is_some_and(|previous| previous >= &member.principal_id)
            || !principal_ids.insert(member.principal_id.clone())
            || !membership_ids.insert(member.membership_id.clone())
            || member.expires_at_unix_seconds <= 0
            || member.membership_generation == 0
            || member.principal_key_generation == 0
            || member
                .revoked_at_unix_seconds
                .is_some_and(|revoked| revoked < 0)
        {
            return Err(TeamAuthorityError::InvalidArtifact);
        }
        member.principal_public_key.decode()?;
        if member.role == TeamRole::Owner && member.revoked_at_unix_seconds.is_none() {
            active_owner = true;
        }
        previous_principal = Some(&member.principal_id);
    }
    if !active_owner {
        return Err(TeamAuthorityError::InvalidArtifact);
    }
    Ok(())
}

fn validate_invitation_signature(
    invitation: &TeamEnrollmentInvitation,
) -> Result<(), TeamAuthorityError> {
    validate_authority_bundle(
        &invitation.bundle,
        invitation.bundle.document.team_id(),
        invitation.bundle.document.workspace_id(),
    )?;
    let unsigned = UnsignedInvitation {
        schema_version: invitation.schema_version,
        invitation_id: &invitation.invitation_id,
        issued_at_unix_seconds: invitation.issued_at_unix_seconds,
        expires_at_unix_seconds: invitation.expires_at_unix_seconds,
        bundle: &invitation.bundle,
    };
    if invitation.schema_version != TEAM_AUTHORITY_ARTIFACT_SCHEMA_VERSION {
        return Err(TeamAuthorityError::InvalidArtifact);
    }
    invitation.signature.verify(
        &current_authority_key(&invitation.bundle)?,
        &canonical_bytes(&unsigned)?,
    )
}

fn validate_invitation(
    invitation: &TeamEnrollmentInvitation,
    expected_workspace_id: &WorkspaceMemoryId,
    now: i64,
) -> Result<(), TeamAuthorityError> {
    validate_invitation_signature(invitation)?;
    if invitation.workspace_id() != expected_workspace_id {
        return Err(TeamAuthorityError::ScopeMismatch);
    }
    validate_time_window(
        invitation.issued_at_unix_seconds,
        invitation.expires_at_unix_seconds,
        now,
        MAX_TEAM_ENROLLMENT_TTL_SECONDS,
    )
}

fn validate_enrollment_request_signature(
    request: &TeamEnrollmentRequest,
) -> Result<(), TeamAuthorityError> {
    if request.schema_version != TEAM_AUTHORITY_ARTIFACT_SCHEMA_VERSION
        || request.principal_key_generation != 1
    {
        return Err(TeamAuthorityError::InvalidArtifact);
    }
    let unsigned = UnsignedEnrollmentRequest {
        schema_version: request.schema_version,
        request_id: &request.request_id,
        invitation_id: &request.invitation_id,
        invitation_digest: request.invitation_digest,
        team_id: &request.team_id,
        workspace_id: &request.workspace_id,
        principal_id: &request.principal_id,
        principal_public_key: &request.principal_public_key,
        principal_key_generation: request.principal_key_generation,
        issued_at_unix_seconds: request.issued_at_unix_seconds,
        expires_at_unix_seconds: request.expires_at_unix_seconds,
    };
    request.proof_signature.verify(
        &request.principal_public_key.decode()?,
        &canonical_bytes(&unsigned)?,
    )
}

fn validate_enrollment_request(
    invitation: &TeamEnrollmentInvitation,
    request: &TeamEnrollmentRequest,
    now: i64,
) -> Result<(), TeamAuthorityError> {
    validate_invitation(invitation, invitation.workspace_id(), now)?;
    validate_enrollment_request_signature(request)?;
    if request.team_id != *invitation.team_id()
        || request.workspace_id != *invitation.workspace_id()
        || request.invitation_id != invitation.invitation_id
        || request.invitation_digest != digest_serialized(invitation)?
    {
        return Err(TeamAuthorityError::ScopeMismatch);
    }
    validate_time_window(
        request.issued_at_unix_seconds,
        request.expires_at_unix_seconds,
        now,
        MAX_TEAM_ENROLLMENT_TTL_SECONDS,
    )
}

fn validate_rotation_request(
    request: &TeamCredentialRotationRequest,
    member: &TeamMembership,
    now: i64,
) -> Result<(), TeamAuthorityError> {
    if request.schema_version != TEAM_AUTHORITY_ARTIFACT_SCHEMA_VERSION
        || request.principal_id != member.principal_id
        || request.membership_id != member.membership_id
        || request.current_key_generation != member.principal_key_generation
        || request.next_key_generation != member.principal_key_generation.saturating_add(1)
    {
        return Err(TeamAuthorityError::MembershipInvalid);
    }
    validate_time_window(
        request.issued_at_unix_seconds,
        request.expires_at_unix_seconds,
        now,
        MAX_TEAM_ENROLLMENT_TTL_SECONDS,
    )?;
    let unsigned = UnsignedCredentialRotationRequest {
        schema_version: request.schema_version,
        team_id: &request.team_id,
        workspace_id: &request.workspace_id,
        principal_id: &request.principal_id,
        membership_id: &request.membership_id,
        current_key_generation: request.current_key_generation,
        next_key_generation: request.next_key_generation,
        next_public_key: &request.next_public_key,
        authority_generation: request.authority_generation,
        issued_at_unix_seconds: request.issued_at_unix_seconds,
        expires_at_unix_seconds: request.expires_at_unix_seconds,
    };
    let bytes = canonical_bytes(&unsigned)?;
    request
        .current_key_signature
        .verify(&member.principal_public_key.decode()?, &bytes)?;
    request
        .next_key_signature
        .verify(&request.next_public_key.decode()?, &bytes)
}

fn validate_operation_grant_signature(
    grant: &TeamOperationGrant,
    key: &TeamPublicKey,
) -> Result<(), TeamAuthorityError> {
    if grant.schema_version != TEAM_AUTHORITY_ARTIFACT_SCHEMA_VERSION {
        return Err(TeamAuthorityError::InvalidArtifact);
    }
    let unsigned = UnsignedOperationGrant {
        schema_version: grant.schema_version,
        grant_id: &grant.grant_id,
        team_id: &grant.team_id,
        workspace_id: &grant.workspace_id,
        principal_id: &grant.principal_id,
        membership_id: &grant.membership_id,
        role: grant.role,
        operation: grant.operation,
        request_digest: grant.request_digest,
        authority_generation: grant.authority_generation,
        authority_key_generation: grant.authority_key_generation,
        membership_generation: grant.membership_generation,
        principal_key_generation: grant.principal_key_generation,
        issued_at_unix_seconds: grant.issued_at_unix_seconds,
        expires_at_unix_seconds: grant.expires_at_unix_seconds,
    };
    grant
        .signature
        .verify(&key.decode()?, &canonical_bytes(&unsigned)?)
}

fn member_for_principal<'a>(
    document: &'a TeamAuthorityDocument,
    principal_id: &PrincipalId,
) -> Option<&'a TeamMembership> {
    document
        .members
        .binary_search_by(|member| member.principal_id.cmp(principal_id))
        .ok()
        .map(|index| &document.members[index])
}

fn initial_audit_anchor() -> ContentDigest {
    ContentDigest::sha256(b"openclaudia.team-authority.audit.v1\0")
}

fn redacted_identity_digest(kind: &[u8], value: &str) -> ContentDigest {
    let mut bytes = Vec::with_capacity(kind.len() + value.len() + 1);
    bytes.extend_from_slice(kind);
    bytes.push(0);
    bytes.extend_from_slice(value.as_bytes());
    ContentDigest::sha256(bytes)
}

fn validate_audit_chain(state: &StoredAuthorityState) -> Result<(), TeamAuthorityError> {
    if state.audit_events.len() > MAX_TEAM_AUDIT_EVENTS
        || state.consumed_grants.len() > MAX_CONSUMED_TEAM_GRANTS
        || state.next_audit_sequence == 0
        || state.last_observed_unix_seconds < 0
    {
        return Err(TeamAuthorityError::RecoveryRequired {
            reason: "bounded audit or replay state is invalid",
        });
    }
    let mut previous = state.audit_anchor;
    let mut previous_sequence = None;
    for event in &state.audit_events {
        if event.previous_event_digest != previous
            || previous_sequence
                .is_some_and(|sequence: u64| event.sequence != sequence.saturating_add(1))
        {
            return Err(TeamAuthorityError::RecoveryRequired {
                reason: "audit chain is discontinuous",
            });
        }
        let unsigned = UnsignedAuditEvent {
            sequence: event.sequence,
            timestamp_unix_seconds: event.timestamp_unix_seconds,
            operation: event.operation,
            allowed: event.allowed,
            decision_code: event.decision_code,
            grant_digest: event.grant_digest,
            principal_digest: event.principal_digest,
            request_digest: event.request_digest,
            authorization_attempt_digest: event.authorization_attempt_digest,
            previous_event_digest: event.previous_event_digest,
        };
        if digest_serialized(&unsigned)? != event.event_digest {
            return Err(TeamAuthorityError::RecoveryRequired {
                reason: "audit event digest is invalid",
            });
        }
        previous = event.event_digest;
        previous_sequence = Some(event.sequence);
    }
    if previous_sequence
        .is_some_and(|sequence| state.next_audit_sequence != sequence.saturating_add(1))
    {
        return Err(TeamAuthorityError::RecoveryRequired {
            reason: "audit sequence is invalid",
        });
    }
    let mut grant_ids = BTreeSet::new();
    if state
        .consumed_grants
        .iter()
        .any(|grant| grant.expires_at_unix_seconds <= 0 || !grant_ids.insert(&grant.grant_id))
    {
        return Err(TeamAuthorityError::RecoveryRequired {
            reason: "grant replay ledger is invalid",
        });
    }
    Ok(())
}

fn validate_stored_state(
    state: &StoredAuthorityState,
    expected_team_id: &TeamId,
    expected_workspace_id: &WorkspaceMemoryId,
) -> Result<(), TeamAuthorityError> {
    if state.schema_version != TEAM_AUTHORITY_SCHEMA_VERSION {
        return Err(TeamAuthorityError::RecoveryRequired {
            reason: "credential schema is unsupported",
        });
    }
    if &state.team_id != expected_team_id || &state.workspace_id != expected_workspace_id {
        return Err(TeamAuthorityError::RecoveryRequired {
            reason: "credential file is bound to a different team or workspace",
        });
    }
    validate_audit_chain(state)?;
    match &state.local {
        StoredLocalAuthority::Pending {
            principal_id,
            principal_secret_key,
            invitation,
            request,
        } => {
            validate_invitation_signature(invitation)?;
            validate_enrollment_request_signature(request)?;
            if request.team_id != state.team_id
                || request.workspace_id != state.workspace_id
                || request.principal_id != *principal_id
                || request.invitation_id != invitation.invitation_id
                || request.invitation_digest != digest_serialized(invitation)?
            {
                return Err(TeamAuthorityError::RecoveryRequired {
                    reason: "pending enrollment binding is invalid",
                });
            }
            let secret_key = secret_to_signing_key(principal_secret_key)?;
            if TeamPublicKey::from_key(&secret_key.verifying_key()) != request.principal_public_key
            {
                return Err(TeamAuthorityError::RecoveryRequired {
                    reason: "pending principal credential does not match its request",
                });
            }
        }
        StoredLocalAuthority::Active {
            principal_id,
            principal_secret_key,
            authority_secret_key,
            replica_storage_secret_key,
            replica_identities,
            bundle,
            pending_rotation,
        } => {
            validate_authority_bundle(bundle, &state.team_id, &state.workspace_id)?;
            let member = member_for_principal(&bundle.document, principal_id).ok_or(
                TeamAuthorityError::RecoveryRequired {
                    reason: "local principal has no signed membership",
                },
            )?;
            let principal_key = secret_to_signing_key(principal_secret_key)?;
            if TeamPublicKey::from_key(&principal_key.verifying_key())
                != member.principal_public_key
            {
                return Err(TeamAuthorityError::RecoveryRequired {
                    reason: "local principal credential does not match signed membership",
                });
            }
            if let Some(secret) = authority_secret_key {
                let key = secret_to_signing_key(secret)?;
                if TeamPublicKey::from_key(&key.verifying_key())
                    != bundle
                        .key_epochs
                        .last()
                        .ok_or(TeamAuthorityError::InvalidArtifact)?
                        .public_key
                {
                    return Err(TeamAuthorityError::RecoveryRequired {
                        reason: "local authority credential does not match the current key epoch",
                    });
                }
            }
            validate_replica_credentials(replica_storage_secret_key.as_ref(), replica_identities)?;
            if let Some(pending) = pending_rotation {
                validate_rotation_request(
                    &pending.request,
                    member,
                    pending.request.issued_at_unix_seconds,
                )?;
                let next_key = secret_to_signing_key(&pending.next_secret_key)?;
                if TeamPublicKey::from_key(&next_key.verifying_key())
                    != pending.request.next_public_key
                {
                    return Err(TeamAuthorityError::RecoveryRequired {
                        reason: "pending successor credential does not match its rotation request",
                    });
                }
            }
        }
    }
    Ok(())
}

fn validate_replica_credentials(
    replica_storage_secret_key: Option<&SecretString>,
    replica_identities: &ReplicaIdentityAnchors,
) -> Result<(), TeamAuthorityError> {
    if replica_storage_secret_key.is_none()
        && (replica_identities.client.is_some() || replica_identities.service.is_some())
    {
        return Err(TeamAuthorityError::RecoveryRequired {
            reason: "replica identity is pinned but its encryption credential is missing",
        });
    }
    if let Some(secret) = replica_storage_secret_key {
        let _ = decode_replica_storage_secret(secret)?;
    }
    for anchor in [
        replica_identities.client.as_ref(),
        replica_identities.service.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        let replica_id = &anchor.replica_id;
        if replica_id.is_empty()
            || replica_id.len() > 64
            || replica_id.chars().any(char::is_control)
        {
            return Err(TeamAuthorityError::RecoveryRequired {
                reason: "replica identity anchor is invalid",
            });
        }
    }
    Ok(())
}

fn append_audit_event(
    state: &mut StoredAuthorityState,
    timestamp: i64,
    operation: TeamMemoryOperation,
    allowed: bool,
    decision_code: TeamAuditDecisionCode,
    grant: &TeamOperationGrant,
    authorization_attempt_digest: ContentDigest,
) -> Result<TeamAuditReceipt, TeamAuthorityError> {
    append_audit_event_fields(
        state,
        &AuditEventFields {
            timestamp,
            operation,
            allowed,
            decision_code,
            grant_digest: digest_serialized(grant)?,
            principal_digest: redacted_identity_digest(
                b"openclaudia.team-authority.principal.v1",
                grant.principal_id.as_str(),
            ),
            request_digest: grant.request_digest,
            authorization_attempt_digest,
        },
    )
}

struct AuditEventFields {
    timestamp: i64,
    operation: TeamMemoryOperation,
    allowed: bool,
    decision_code: TeamAuditDecisionCode,
    grant_digest: ContentDigest,
    principal_digest: ContentDigest,
    request_digest: ContentDigest,
    authorization_attempt_digest: ContentDigest,
}

fn append_audit_event_fields(
    state: &mut StoredAuthorityState,
    fields: &AuditEventFields,
) -> Result<TeamAuditReceipt, TeamAuthorityError> {
    let previous_event_digest = state
        .audit_events
        .last()
        .map_or(state.audit_anchor, |event| event.event_digest);
    let unsigned = UnsignedAuditEvent {
        sequence: state.next_audit_sequence,
        timestamp_unix_seconds: fields.timestamp,
        operation: fields.operation,
        allowed: fields.allowed,
        decision_code: fields.decision_code,
        grant_digest: fields.grant_digest,
        principal_digest: fields.principal_digest,
        request_digest: fields.request_digest,
        authorization_attempt_digest: fields.authorization_attempt_digest,
        previous_event_digest,
    };
    let event_digest = digest_serialized(&unsigned)?;
    let event = TeamAuditEvent {
        sequence: unsigned.sequence,
        timestamp_unix_seconds: unsigned.timestamp_unix_seconds,
        operation: unsigned.operation,
        allowed: unsigned.allowed,
        decision_code: unsigned.decision_code,
        grant_digest: unsigned.grant_digest,
        principal_digest: unsigned.principal_digest,
        request_digest: unsigned.request_digest,
        authorization_attempt_digest: unsigned.authorization_attempt_digest,
        previous_event_digest: unsigned.previous_event_digest,
        event_digest,
    };
    state.audit_events.push(event);
    state.next_audit_sequence = state.next_audit_sequence.saturating_add(1);
    if state.audit_events.len() > MAX_TEAM_AUDIT_EVENTS {
        let removed = state.audit_events.remove(0);
        state.audit_anchor = removed.event_digest;
    }
    Ok(TeamAuditReceipt {
        sequence: unsigned.sequence,
        operation: fields.operation,
        allowed: fields.allowed,
        decision_code: fields.decision_code,
        event_digest,
    })
}

macro_rules! impl_public_artifact_codec {
    ($type:ty) => {
        impl $type {
            /// Decode one bounded public artifact. Signature and scope checks
            /// occur when the artifact is consumed by an authority store.
            ///
            /// # Errors
            /// Returns a typed artifact or capacity error for malformed,
            /// unsupported, or oversized input.
            pub fn decode(bytes: &[u8]) -> Result<Self, TeamAuthorityError> {
                if bytes.len() > MAX_TEAM_AUTHORITY_ARTIFACT_BYTES {
                    return Err(TeamAuthorityError::CapacityExceeded {
                        resource: "public artifact",
                    });
                }
                serde_json::from_slice(bytes).map_err(|_| TeamAuthorityError::InvalidArtifact)
            }

            /// Encode one public artifact for manual transfer. No private key
            /// material is part of these types.
            ///
            /// # Errors
            /// Returns a typed artifact or capacity error when the value
            /// cannot be encoded within the public artifact bound.
            pub fn encode_pretty(&self) -> Result<Vec<u8>, TeamAuthorityError> {
                let bytes = serde_json::to_vec_pretty(self)
                    .map_err(|_| TeamAuthorityError::InvalidArtifact)?;
                if bytes.len() > MAX_TEAM_AUTHORITY_ARTIFACT_BYTES {
                    return Err(TeamAuthorityError::CapacityExceeded {
                        resource: "public artifact",
                    });
                }
                Ok(bytes)
            }
        }
    };
}

impl_public_artifact_codec!(TeamAuthorityBundle);
impl_public_artifact_codec!(TeamEnrollmentInvitation);
impl_public_artifact_codec!(TeamEnrollmentRequest);
impl_public_artifact_codec!(TeamEnrollmentApproval);
impl_public_artifact_codec!(TeamCredentialRotationRequest);
impl_public_artifact_codec!(TeamOperationGrant);

/// Host-owned authority capability for one exact team and workspace.
///
/// The handle contains only a descriptor-pinned storage capability and public
/// scope identities. Private keys are loaded into zeroizing allocations for
/// the duration of an operation and are never exposed by `Debug`.
#[derive(Clone)]
pub struct TeamAuthorityStore {
    storage: PersistentStorage,
    target: PathBuf,
    team_id: TeamId,
    workspace_id: WorkspaceMemoryId,
}

impl fmt::Debug for TeamAuthorityStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TeamAuthorityStore")
            .field("team_id", &self.team_id)
            .field("workspace_id", &self.workspace_id)
            .finish_non_exhaustive()
    }
}

impl TeamAuthorityStore {
    /// Open the host-owned authority file for one repository-selected team.
    /// Opening does not create membership and succeeds even when the file is
    /// absent so [`Self::status`] can report `Unenrolled`.
    ///
    /// # Errors
    /// Returns a typed error when the workspace/root cannot be canonicalized
    /// or the host cannot provide descriptor-safe private storage.
    pub fn open_for_workspace(
        host_home: &Path,
        project_dir: &Path,
        team_id: TeamId,
    ) -> Result<Self, TeamAuthorityError> {
        let memory = MemoryDb::open_for_workspace(host_home, project_dir)
            .map_err(|error| TeamAuthorityError::Workspace(error.to_string()))?;
        let workspace_id =
            memory
                .workspace_id()
                .cloned()
                .ok_or(TeamAuthorityError::RecoveryRequired {
                    reason: "workspace memory has no host authority binding",
                })?;
        let root = memory
            .path()
            .parent()
            .ok_or(TeamAuthorityError::RecoveryRequired {
                reason: "workspace memory has no private state root",
            })?;
        let storage = PersistentStorage::open(root)?;
        let target = PathBuf::from(format!("team-authority-{}.json", team_id.as_str()));
        Ok(Self {
            storage,
            target,
            team_id,
            workspace_id,
        })
    }

    /// Bootstrap a new team with this host principal as its first owner.
    ///
    /// # Errors
    /// Fails if the TTL is invalid, secure randomness/private persistence is
    /// unavailable, or a generated identity unexpectedly collides.
    pub fn bootstrap(
        host_home: &Path,
        project_dir: &Path,
        principal_id: PrincipalId,
        membership_ttl_seconds: i64,
    ) -> Result<Self, TeamAuthorityError> {
        Self::bootstrap_at(
            host_home,
            project_dir,
            principal_id,
            membership_ttl_seconds,
            now_unix_seconds()?,
        )
    }

    #[doc(hidden)]
    pub fn bootstrap_at(
        host_home: &Path,
        project_dir: &Path,
        principal_id: PrincipalId,
        membership_ttl_seconds: i64,
        now: i64,
    ) -> Result<Self, TeamAuthorityError> {
        validate_membership_ttl(membership_ttl_seconds)?;
        let team_id = TeamId::random()?;
        let store = Self::open_for_workspace(host_home, project_dir, team_id.clone())?;
        if store.read_state_optional()?.is_some() {
            return Err(TeamAuthorityError::ConcurrentUpdate);
        }

        let authority_key = generate_signing_key()?;
        let principal_key = generate_signing_key()?;
        let authority_public_key = TeamPublicKey::from_key(&authority_key.verifying_key());
        let member = TeamMembership {
            membership_id: MembershipId::random()?,
            principal_id: principal_id.clone(),
            role: TeamRole::Owner,
            expires_at_unix_seconds: now.saturating_add(membership_ttl_seconds),
            membership_generation: 1,
            principal_key_generation: 1,
            principal_public_key: TeamPublicKey::from_key(&principal_key.verifying_key()),
            revoked_at_unix_seconds: None,
            enrollment_request_digest: None,
        };
        let document = TeamAuthorityDocument {
            schema_version: TEAM_AUTHORITY_ARTIFACT_SCHEMA_VERSION,
            team_id: team_id.clone(),
            workspace_id: store.workspace_id.clone(),
            authority_generation: 1,
            authority_key_generation: 1,
            members: vec![member],
        };
        let bundle = TeamAuthorityBundle {
            schema_version: TEAM_AUTHORITY_ARTIFACT_SCHEMA_VERSION,
            trust_anchor: authority_public_key.clone(),
            key_epochs: vec![AuthorityKeyEpoch {
                generation: 1,
                public_key: authority_public_key,
                previous_signature: None,
            }],
            document_signature: TeamSignature::sign(
                &authority_key,
                &authority_document_bytes(&document)?,
            ),
            document,
        };
        let state = StoredAuthorityState {
            schema_version: TEAM_AUTHORITY_SCHEMA_VERSION,
            team_id,
            workspace_id: store.workspace_id.clone(),
            last_observed_unix_seconds: now,
            local: StoredLocalAuthority::Active {
                principal_id,
                principal_secret_key: signing_key_to_secret(&principal_key)?,
                authority_secret_key: Some(signing_key_to_secret(&authority_key)?),
                replica_storage_secret_key: Some(generate_replica_storage_secret()?),
                replica_identities: ReplicaIdentityAnchors::default(),
                bundle,
                pending_rotation: None,
            },
            consumed_grants: Vec::new(),
            audit_anchor: initial_audit_anchor(),
            audit_events: Vec::new(),
            next_audit_sequence: 1,
        };
        validate_stored_state(&state, &store.team_id, &store.workspace_id)?;
        store.commit_state(StorageGeneration::Missing, &state)?;
        Ok(store)
    }

    #[must_use]
    pub const fn team_id(&self) -> &TeamId {
        &self.team_id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceMemoryId {
        &self.workspace_id
    }

    pub(crate) fn replica_storage(&self) -> PersistentStorage {
        self.storage.clone()
    }

    /// Return the currently enrolled local principal without exposing any
    /// credential material.
    ///
    /// # Errors
    /// Returns a typed lifecycle or recovery error for missing, pending, or
    /// corrupt state.
    pub fn local_principal_id(&self) -> Result<PrincipalId, TeamAuthorityError> {
        let (_, state) = self.read_required_state()?;
        let StoredLocalAuthority::Active { principal_id, .. } = state.local else {
            return Err(TeamAuthorityError::EnrollmentPending);
        };
        Ok(principal_id)
    }

    pub(crate) fn replica_storage_key(&self) -> Result<Zeroizing<[u8; 32]>, TeamAuthorityError> {
        let (_, state) = self.read_required_state()?;
        let StoredLocalAuthority::Active {
            replica_storage_secret_key,
            ..
        } = state.local
        else {
            return Err(TeamAuthorityError::EnrollmentPending);
        };
        if let Some(secret) = replica_storage_secret_key {
            return decode_replica_storage_secret(&secret);
        }

        let generated = generate_replica_storage_secret()?;
        self.update_state(|state| {
            let StoredLocalAuthority::Active {
                replica_storage_secret_key,
                ..
            } = &mut state.local
            else {
                return Err(TeamAuthorityError::EnrollmentPending);
            };
            if replica_storage_secret_key.is_none() {
                *replica_storage_secret_key = Some(generated.clone());
            }
            Ok(())
        })?;
        let (_, state) = self.read_required_state()?;
        let StoredLocalAuthority::Active {
            replica_storage_secret_key: Some(secret),
            ..
        } = state.local
        else {
            return Err(TeamAuthorityError::RecoveryRequired {
                reason: "replica encryption credential was not published",
            });
        };
        decode_replica_storage_secret(&secret)
    }

    pub(crate) fn replica_identity(
        &self,
        role: ReplicaAuthorityRole,
    ) -> Result<Option<(String, MemoryStoreId)>, TeamAuthorityError> {
        let (_, state) = self.read_required_state()?;
        let StoredLocalAuthority::Active {
            replica_identities, ..
        } = state.local
        else {
            return Err(TeamAuthorityError::EnrollmentPending);
        };
        Ok(match role {
            ReplicaAuthorityRole::Client => replica_identities.client,
            ReplicaAuthorityRole::Service => replica_identities.service,
        }
        .map(|anchor| (anchor.replica_id, anchor.store_id)))
    }

    pub(crate) fn pin_replica_identity(
        &self,
        role: ReplicaAuthorityRole,
        replica_id: &str,
        store_id: MemoryStoreId,
    ) -> Result<(), TeamAuthorityError> {
        if replica_id.is_empty()
            || replica_id.len() > 64
            || replica_id.chars().any(char::is_control)
        {
            return Err(TeamAuthorityError::RecoveryRequired {
                reason: "replica identity anchor is invalid",
            });
        }
        if self
            .replica_identity(role)?
            .as_ref()
            .is_some_and(|(current_id, current_store)| {
                current_id == replica_id && *current_store == store_id
            })
        {
            return Ok(());
        }
        self.update_state(|state| {
            let StoredLocalAuthority::Active {
                replica_identities, ..
            } = &mut state.local
            else {
                return Err(TeamAuthorityError::EnrollmentPending);
            };
            let anchor = match role {
                ReplicaAuthorityRole::Client => &mut replica_identities.client,
                ReplicaAuthorityRole::Service => &mut replica_identities.service,
            };
            if anchor.as_ref().is_some_and(|current| {
                current.replica_id != replica_id || current.store_id != store_id
            }) {
                return Err(TeamAuthorityError::RecoveryRequired {
                    reason: "encrypted team replica identity changed",
                });
            }
            *anchor = Some(ReplicaIdentityAnchor {
                replica_id: replica_id.to_string(),
                store_id,
            });
            Ok(())
        })
    }

    /// Report lifecycle state without revealing credentials or host paths.
    ///
    /// # Errors
    /// Corrupt, insecure, or unreadable persisted authority is returned as a
    /// typed recovery failure and never interpreted as unenrolled.
    pub fn status(&self) -> Result<TeamAuthorityStatus, TeamAuthorityError> {
        self.status_at(now_unix_seconds()?)
    }

    #[doc(hidden)]
    pub fn status_at(&self, now: i64) -> Result<TeamAuthorityStatus, TeamAuthorityError> {
        let Some((_, state)) = self.read_state_optional()? else {
            return Ok(TeamAuthorityStatus::Unenrolled);
        };
        if now < state.last_observed_unix_seconds {
            return Err(TeamAuthorityError::ClockRollback);
        }
        match state.local {
            StoredLocalAuthority::Pending { principal_id, .. } => {
                Ok(TeamAuthorityStatus::Pending {
                    team_id: state.team_id,
                    workspace_id: state.workspace_id,
                    principal_id,
                })
            }
            StoredLocalAuthority::Active {
                principal_id,
                bundle,
                ..
            } => {
                let member = member_for_principal(&bundle.document, &principal_id).ok_or(
                    TeamAuthorityError::RecoveryRequired {
                        reason: "local principal has no signed membership",
                    },
                )?;
                if member.revoked_at_unix_seconds.is_some() {
                    return Ok(TeamAuthorityStatus::Revoked {
                        team_id: state.team_id,
                        workspace_id: state.workspace_id,
                        principal_id,
                    });
                }
                if now >= member.expires_at_unix_seconds {
                    return Ok(TeamAuthorityStatus::Expired {
                        team_id: state.team_id,
                        workspace_id: state.workspace_id,
                        principal_id,
                        expires_at_unix_seconds: member.expires_at_unix_seconds,
                    });
                }
                Ok(TeamAuthorityStatus::Active {
                    team_id: state.team_id,
                    workspace_id: state.workspace_id,
                    principal_id,
                    role: member.role,
                    authority_generation: bundle.document.authority_generation,
                    authority_key_generation: bundle.document.authority_key_generation,
                    membership_generation: member.membership_generation,
                    principal_key_generation: member.principal_key_generation,
                    expires_at_unix_seconds: member.expires_at_unix_seconds,
                    audit_events: state.audit_events.len(),
                })
            }
        }
    }

    /// Export current public authority state. This contains no private key.
    ///
    /// # Errors
    /// Returns a typed lifecycle or recovery error for missing/corrupt state.
    pub fn public_bundle(&self) -> Result<TeamAuthorityBundle, TeamAuthorityError> {
        self.public_bundle_at(now_unix_seconds()?)
    }

    #[doc(hidden)]
    pub fn public_bundle_at(&self, now: i64) -> Result<TeamAuthorityBundle, TeamAuthorityError> {
        let (_, state) = self.read_required_state()?;
        require_local_active_state(&state, now)?;
        let StoredLocalAuthority::Active { bundle, .. } = state.local else {
            return Err(TeamAuthorityError::EnrollmentPending);
        };
        Ok(bundle)
    }

    /// Return bounded redacted audit receipts. Grant/principal identifiers,
    /// keys, lesson payloads, and host paths are intentionally absent.
    ///
    /// # Errors
    /// Returns a typed lifecycle or recovery error for missing/corrupt state.
    pub fn audit_receipts(&self) -> Result<Vec<TeamAuditReceipt>, TeamAuthorityError> {
        self.audit_receipts_at(now_unix_seconds()?)
    }

    #[doc(hidden)]
    pub fn audit_receipts_at(&self, now: i64) -> Result<Vec<TeamAuditReceipt>, TeamAuthorityError> {
        let (_, state) = self.read_required_state()?;
        require_local_active_state(&state, now)?;
        Ok(state
            .audit_events
            .iter()
            .map(|event| TeamAuditReceipt {
                sequence: event.sequence,
                operation: event.operation,
                allowed: event.allowed,
                decision_code: event.decision_code,
                event_digest: event.event_digest,
            })
            .collect())
    }

    /// Revalidate an already audited permit against the current signed
    /// authority document at the downstream operation boundary.
    ///
    /// The replication boundary calls this immediately before reading or
    /// changing replicated lesson state. A concurrent role, revocation, membership, principal-key,
    /// or authority-key generation change invalidates the permit.
    ///
    /// # Errors
    /// Fails when the permit has the wrong scope/request, has expired, or no
    /// longer matches current authenticated membership.
    pub fn validate_permit(
        &self,
        permit: &TeamOperationPermit,
        operation: TeamMemoryOperation,
        request_digest: ContentDigest,
    ) -> Result<(), TeamAuthorityError> {
        self.validate_permit_at(permit, operation, request_digest, now_unix_seconds()?)
    }

    #[doc(hidden)]
    pub fn validate_permit_at(
        &self,
        permit: &TeamOperationPermit,
        operation: TeamMemoryOperation,
        request_digest: ContentDigest,
        now: i64,
    ) -> Result<(), TeamAuthorityError> {
        let (_, state) = self.read_required_state()?;
        if now < state.last_observed_unix_seconds {
            return Err(TeamAuthorityError::ClockRollback);
        }
        let StoredLocalAuthority::Active { bundle, .. } = state.local else {
            return Err(TeamAuthorityError::MembershipInvalid);
        };
        permit.require(&self.team_id, &self.workspace_id, operation, request_digest)?;
        permit.require_current(&bundle, now)
    }

    /// Issue a signed, short-lived grant for one exact operation and request
    /// digest. Issuance alone does not grant access; the recipient must call
    /// [`Self::authorize_grant`], which consumes and audits it durably.
    ///
    /// # Errors
    /// Fails for stale/revoked/expired membership, role denial, clock
    /// rollback, invalid TTL, or unavailable local credentials.
    pub fn issue_grant(
        &self,
        operation: TeamMemoryOperation,
        request_digest: ContentDigest,
        ttl_seconds: i64,
    ) -> Result<TeamOperationGrant, TeamAuthorityError> {
        self.issue_grant_at(operation, request_digest, ttl_seconds, now_unix_seconds()?)
    }

    #[doc(hidden)]
    pub fn issue_grant_at(
        &self,
        operation: TeamMemoryOperation,
        request_digest: ContentDigest,
        ttl_seconds: i64,
        now: i64,
    ) -> Result<TeamOperationGrant, TeamAuthorityError> {
        if ttl_seconds <= 0 || ttl_seconds > MAX_TEAM_GRANT_TTL_SECONDS {
            return Err(TeamAuthorityError::Expired);
        }
        let (_, state) = self.read_required_state()?;
        if now < state.last_observed_unix_seconds {
            return Err(TeamAuthorityError::ClockRollback);
        }
        let StoredLocalAuthority::Active {
            principal_id,
            principal_secret_key,
            bundle,
            ..
        } = state.local
        else {
            return Err(TeamAuthorityError::EnrollmentPending);
        };
        let member = member_for_principal(&bundle.document, &principal_id)
            .ok_or(TeamAuthorityError::MembershipInvalid)?;
        require_active_member(member, now)?;
        let mut grant = TeamOperationGrant {
            schema_version: TEAM_AUTHORITY_ARTIFACT_SCHEMA_VERSION,
            grant_id: TeamGrantId::random()?,
            team_id: self.team_id.clone(),
            workspace_id: self.workspace_id.clone(),
            principal_id,
            membership_id: member.membership_id.clone(),
            role: member.role,
            operation,
            request_digest,
            authority_generation: bundle.document.authority_generation,
            authority_key_generation: bundle.document.authority_key_generation,
            membership_generation: member.membership_generation,
            principal_key_generation: member.principal_key_generation,
            issued_at_unix_seconds: now,
            expires_at_unix_seconds: now.saturating_add(ttl_seconds),
            signature: TeamSignature(String::new()),
        };
        let unsigned = unsigned_grant(&grant);
        let key = secret_to_signing_key(&principal_secret_key)?;
        grant.signature = TeamSignature::sign(&key, &canonical_bytes(&unsigned)?);
        Ok(grant)
    }

    /// Validate, consume, and audit one exact grant before returning an opaque
    /// downstream permit. Denials are also committed before they are returned.
    ///
    /// # Errors
    /// Returns only storage/recovery failures. Policy denials are represented
    /// by [`TeamAuthorizationOutcome::Denied`] with their durable receipt.
    pub fn authorize_grant(
        &self,
        grant: &TeamOperationGrant,
        expected_operation: TeamMemoryOperation,
        expected_request_digest: ContentDigest,
    ) -> Result<TeamAuthorizationOutcome, TeamAuthorityError> {
        self.authorize_grant_at(
            grant,
            expected_operation,
            expected_request_digest,
            now_unix_seconds()?,
        )
    }

    #[doc(hidden)]
    pub fn authorize_grant_at(
        &self,
        grant: &TeamOperationGrant,
        expected_operation: TeamMemoryOperation,
        expected_request_digest: ContentDigest,
        now: i64,
    ) -> Result<TeamAuthorizationOutcome, TeamAuthorityError> {
        let authorization_attempt_digest = random_authorization_attempt_digest()?;
        for _ in 0..MAX_AUTHORITY_RETRIES {
            let (generation, mut state) = self.read_required_state()?;
            let timestamp = now.max(state.last_observed_unix_seconds);
            let (decision, signed_by_current_member) = evaluate_grant(
                &state,
                grant,
                expected_operation,
                expected_request_digest,
                now,
            );
            state.last_observed_unix_seconds = timestamp;
            state
                .consumed_grants
                .retain(|entry| entry.expires_at_unix_seconds > timestamp);
            let mut effective_decision = decision;
            if signed_by_current_member
                && !matches!(
                    effective_decision,
                    GrantDecision::Denied(
                        TeamAuthorizationDenial::GrantReplay
                            | TeamAuthorizationDenial::InvalidSignature
                    )
                )
            {
                if state.consumed_grants.len() >= MAX_CONSUMED_TEAM_GRANTS {
                    effective_decision =
                        GrantDecision::Denied(TeamAuthorizationDenial::CapacityExceeded);
                } else {
                    state.consumed_grants.push(ConsumedGrant {
                        grant_id: grant.grant_id.clone(),
                        expires_at_unix_seconds: grant.expires_at_unix_seconds.max(timestamp + 1),
                    });
                    state
                        .consumed_grants
                        .sort_by(|left, right| left.grant_id.cmp(&right.grant_id));
                }
            }
            let allowed = matches!(effective_decision, GrantDecision::Allowed);
            let decision_code = match effective_decision {
                GrantDecision::Allowed => TeamAuditDecisionCode::Allowed,
                GrantDecision::Denied(denial) => denial_to_audit_code(denial),
            };
            let receipt = append_audit_event(
                &mut state,
                timestamp,
                expected_operation,
                allowed,
                decision_code,
                grant,
                authorization_attempt_digest,
            )?;
            match self.commit_state(generation, &state) {
                Ok(()) => {
                    if allowed {
                        return Ok(TeamAuthorizationOutcome::Authorized(TeamOperationPermit {
                            team_id: self.team_id.clone(),
                            workspace_id: self.workspace_id.clone(),
                            principal_id: grant.principal_id.clone(),
                            membership_id: grant.membership_id.clone(),
                            role: grant.role,
                            operation: expected_operation,
                            request_digest: expected_request_digest,
                            authority_generation: grant.authority_generation,
                            authority_key_generation: grant.authority_key_generation,
                            membership_generation: grant.membership_generation,
                            principal_key_generation: grant.principal_key_generation,
                            expires_at_unix_seconds: grant.expires_at_unix_seconds,
                            receipt,
                        }));
                    }
                    let GrantDecision::Denied(reason) = effective_decision else {
                        unreachable!("allowed authorization returned above")
                    };
                    return Ok(TeamAuthorizationOutcome::Denied { receipt, reason });
                }
                Err(TeamAuthorityError::Persistence(PersistenceError::Conflict { .. })) => {}
                Err(error) => return Err(error),
            }
        }
        Err(TeamAuthorityError::ConcurrentUpdate)
    }

    fn read_state_optional(
        &self,
    ) -> Result<Option<(StorageGeneration, StoredAuthorityState)>, TeamAuthorityError> {
        let read = self.storage.read(&self.target, FileClass::Credentials)?;
        let generation = read.generation();
        read.expose_bytes(|bytes| {
            let Some(bytes) = bytes else {
                return Ok(None);
            };
            let state: StoredAuthorityState = serde_json::from_slice(bytes).map_err(|_| {
                TeamAuthorityError::RecoveryRequired {
                    reason: "credential state is malformed",
                }
            })?;
            validate_stored_state(&state, &self.team_id, &self.workspace_id)?;
            Ok(Some((generation, state)))
        })
    }

    fn read_required_state(
        &self,
    ) -> Result<(StorageGeneration, StoredAuthorityState), TeamAuthorityError> {
        self.read_state_optional()?
            .ok_or(TeamAuthorityError::Unenrolled)
    }

    fn commit_state(
        &self,
        expected: StorageGeneration,
        state: &StoredAuthorityState,
    ) -> Result<(), TeamAuthorityError> {
        validate_stored_state(state, &self.team_id, &self.workspace_id)?;
        let encoded = state.encode()?;
        let receipt =
            self.storage
                .commit(&self.target, FileClass::Credentials, expected, &*encoded)?;
        if receipt.state() == CommitState::PublishedDurabilityUncertain {
            let recovery =
                self.storage
                    .commit(&self.target, FileClass::Credentials, expected, &*encoded)?;
            if recovery.state() == CommitState::PublishedDurabilityUncertain {
                return Err(TeamAuthorityError::RecoveryRequired {
                    reason: "credential publication durability is uncertain",
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantDecision {
    Allowed,
    Denied(TeamAuthorizationDenial),
}

fn evaluate_grant(
    state: &StoredAuthorityState,
    grant: &TeamOperationGrant,
    expected_operation: TeamMemoryOperation,
    expected_request_digest: ContentDigest,
    now: i64,
) -> (GrantDecision, bool) {
    let StoredLocalAuthority::Active { bundle, .. } = &state.local else {
        return (
            GrantDecision::Denied(TeamAuthorizationDenial::MembershipInvalid),
            false,
        );
    };
    let member = member_for_principal(&bundle.document, &grant.principal_id);
    if now < state.last_observed_unix_seconds {
        return (
            GrantDecision::Denied(TeamAuthorizationDenial::ClockRollback),
            false,
        );
    }
    if grant.team_id != state.team_id || grant.workspace_id != state.workspace_id {
        return (
            GrantDecision::Denied(TeamAuthorizationDenial::ScopeMismatch),
            false,
        );
    }
    if grant.operation != expected_operation || grant.request_digest != expected_request_digest {
        return (
            GrantDecision::Denied(TeamAuthorizationDenial::GrantMismatch),
            false,
        );
    }
    let Some(member) = member else {
        return (
            GrantDecision::Denied(TeamAuthorizationDenial::MembershipInvalid),
            false,
        );
    };
    if member.membership_id != grant.membership_id
        || member.role != grant.role
        || member.membership_generation != grant.membership_generation
        || member.principal_key_generation != grant.principal_key_generation
        || bundle.document.authority_generation != grant.authority_generation
        || bundle.document.authority_key_generation != grant.authority_key_generation
    {
        return (
            GrantDecision::Denied(TeamAuthorizationDenial::MembershipInvalid),
            false,
        );
    }
    if validate_operation_grant_signature(grant, &member.principal_public_key).is_err() {
        return (
            GrantDecision::Denied(TeamAuthorizationDenial::InvalidSignature),
            false,
        );
    }
    if validate_time_window(
        grant.issued_at_unix_seconds,
        grant.expires_at_unix_seconds,
        now,
        MAX_TEAM_GRANT_TTL_SECONDS,
    )
    .is_err()
    {
        return (
            GrantDecision::Denied(TeamAuthorizationDenial::Expired),
            true,
        );
    }
    if require_active_member(member, now).is_err() {
        return (
            GrantDecision::Denied(TeamAuthorizationDenial::MembershipInvalid),
            true,
        );
    }
    if !member.role.permits(expected_operation) {
        return (
            GrantDecision::Denied(TeamAuthorizationDenial::RoleDenied),
            true,
        );
    }
    if state
        .consumed_grants
        .iter()
        .any(|entry| entry.grant_id == grant.grant_id)
    {
        return (
            GrantDecision::Denied(TeamAuthorizationDenial::GrantReplay),
            true,
        );
    }
    (GrantDecision::Allowed, true)
}

const fn denial_to_audit_code(denial: TeamAuthorizationDenial) -> TeamAuditDecisionCode {
    match denial {
        TeamAuthorizationDenial::ScopeMismatch => TeamAuditDecisionCode::ScopeMismatch,
        TeamAuthorizationDenial::Expired => TeamAuditDecisionCode::Expired,
        TeamAuthorizationDenial::ClockRollback => TeamAuditDecisionCode::ClockRollback,
        TeamAuthorizationDenial::MembershipInvalid => TeamAuditDecisionCode::MembershipInvalid,
        TeamAuthorizationDenial::RoleDenied => TeamAuditDecisionCode::RoleDenied,
        TeamAuthorizationDenial::GrantReplay => TeamAuditDecisionCode::GrantReplay,
        TeamAuthorizationDenial::GrantMismatch => TeamAuditDecisionCode::GrantMismatch,
        TeamAuthorizationDenial::InvalidSignature => TeamAuditDecisionCode::InvalidSignature,
        TeamAuthorizationDenial::CapacityExceeded => TeamAuditDecisionCode::CapacityExceeded,
    }
}

const fn unsigned_grant(grant: &TeamOperationGrant) -> UnsignedOperationGrant<'_> {
    UnsignedOperationGrant {
        schema_version: grant.schema_version,
        grant_id: &grant.grant_id,
        team_id: &grant.team_id,
        workspace_id: &grant.workspace_id,
        principal_id: &grant.principal_id,
        membership_id: &grant.membership_id,
        role: grant.role,
        operation: grant.operation,
        request_digest: grant.request_digest,
        authority_generation: grant.authority_generation,
        authority_key_generation: grant.authority_key_generation,
        membership_generation: grant.membership_generation,
        principal_key_generation: grant.principal_key_generation,
        issued_at_unix_seconds: grant.issued_at_unix_seconds,
        expires_at_unix_seconds: grant.expires_at_unix_seconds,
    }
}

const fn validate_membership_ttl(ttl_seconds: i64) -> Result<(), TeamAuthorityError> {
    const MAX_MEMBERSHIP_TTL_SECONDS: i64 = 5 * 366 * 24 * 60 * 60;
    if ttl_seconds <= 0 || ttl_seconds > MAX_MEMBERSHIP_TTL_SECONDS {
        return Err(TeamAuthorityError::Expired);
    }
    Ok(())
}

const fn require_active_member(
    member: &TeamMembership,
    now: i64,
) -> Result<(), TeamAuthorityError> {
    if member.revoked_at_unix_seconds.is_some() || now >= member.expires_at_unix_seconds {
        return Err(TeamAuthorityError::MembershipInvalid);
    }
    Ok(())
}

fn require_active_owner(members: &[TeamMembership], now: i64) -> Result<(), TeamAuthorityError> {
    if members.iter().any(|member| {
        member.role == TeamRole::Owner
            && member.revoked_at_unix_seconds.is_none()
            && now < member.expires_at_unix_seconds
    }) {
        Ok(())
    } else {
        Err(TeamAuthorityError::OwnerRequired)
    }
}

fn require_local_active_state(
    state: &StoredAuthorityState,
    now: i64,
) -> Result<(), TeamAuthorityError> {
    if now < state.last_observed_unix_seconds {
        return Err(TeamAuthorityError::ClockRollback);
    }
    let StoredLocalAuthority::Active {
        principal_id,
        bundle,
        ..
    } = &state.local
    else {
        return Err(TeamAuthorityError::EnrollmentPending);
    };
    let member = member_for_principal(&bundle.document, principal_id)
        .ok_or(TeamAuthorityError::MembershipInvalid)?;
    require_active_member(member, now)
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AuthorityAction<'a> {
    schema_version: u32,
    team_id: &'a TeamId,
    workspace_id: &'a WorkspaceMemoryId,
    action: &'static str,
    payload_digest: ContentDigest,
}

impl TeamAuthorityStore {
    /// Create an authority-signed invitation. The invitation carries only
    /// public trust material and remains useless without proof of possession
    /// from a newly generated principal key.
    ///
    /// # Errors
    /// Requires an active local owner credential and a valid bounded TTL.
    pub fn create_enrollment_invitation(
        &self,
        ttl_seconds: i64,
    ) -> Result<TeamEnrollmentInvitation, TeamAuthorityError> {
        self.create_enrollment_invitation_at(ttl_seconds, now_unix_seconds()?)
    }

    #[doc(hidden)]
    pub fn create_enrollment_invitation_at(
        &self,
        ttl_seconds: i64,
        now: i64,
    ) -> Result<TeamEnrollmentInvitation, TeamAuthorityError> {
        if ttl_seconds <= 0 || ttl_seconds > MAX_TEAM_ENROLLMENT_TTL_SECONDS {
            return Err(TeamAuthorityError::Expired);
        }
        let invitation_id = EnrollmentInvitationId::random()?;
        let payload_digest = digest_serialized(&(invitation_id.clone(), ttl_seconds, now))?;
        let request_digest = self.authority_action_digest("create_invitation", payload_digest)?;
        let permit = self.authorize_local_admin(request_digest, now)?;
        let (_, state) = self.read_required_state()?;
        let StoredLocalAuthority::Active {
            authority_secret_key,
            bundle,
            ..
        } = state.local
        else {
            return Err(TeamAuthorityError::EnrollmentPending);
        };
        permit.require(
            &self.team_id,
            &self.workspace_id,
            TeamMemoryOperation::Admin,
            request_digest,
        )?;
        permit.require_current(&bundle, now)?;
        let authority_key = authority_secret_key
            .as_ref()
            .ok_or(TeamAuthorityError::CredentialUnavailable)
            .and_then(secret_to_signing_key)?;
        let mut invitation = TeamEnrollmentInvitation {
            schema_version: TEAM_AUTHORITY_ARTIFACT_SCHEMA_VERSION,
            invitation_id,
            issued_at_unix_seconds: now,
            expires_at_unix_seconds: now.saturating_add(ttl_seconds),
            bundle,
            signature: TeamSignature(String::new()),
        };
        let unsigned = UnsignedInvitation {
            schema_version: invitation.schema_version,
            invitation_id: &invitation.invitation_id,
            issued_at_unix_seconds: invitation.issued_at_unix_seconds,
            expires_at_unix_seconds: invitation.expires_at_unix_seconds,
            bundle: &invitation.bundle,
        };
        invitation.signature = TeamSignature::sign(&authority_key, &canonical_bytes(&unsigned)?);
        Ok(invitation)
    }

    /// Begin enrollment on a new host using a manually transferred public
    /// invitation. The generated principal key is persisted only in the
    /// private host store; the returned request contains its public key and
    /// proof of possession.
    ///
    /// # Errors
    /// Rejects expired/foreign/forged invitations and a currently authorized
    /// local enrollment. A pending enrollment may be replaced atomically, and
    /// a locally observed revoked identity may re-enroll with a fresh key and
    /// owner-issued invitation, so lost responses and revocation recovery do
    /// not require reusing an invalid credential.
    pub fn begin_enrollment(
        host_home: &Path,
        project_dir: &Path,
        principal_id: PrincipalId,
        invitation: TeamEnrollmentInvitation,
    ) -> Result<(Self, TeamEnrollmentRequest), TeamAuthorityError> {
        Self::begin_enrollment_at(
            host_home,
            project_dir,
            principal_id,
            invitation,
            now_unix_seconds()?,
        )
    }

    #[doc(hidden)]
    pub fn begin_enrollment_at(
        host_home: &Path,
        project_dir: &Path,
        principal_id: PrincipalId,
        invitation: TeamEnrollmentInvitation,
        now: i64,
    ) -> Result<(Self, TeamEnrollmentRequest), TeamAuthorityError> {
        let team_id = invitation.team_id().clone();
        let store = Self::open_for_workspace(host_home, project_dir, team_id.clone())?;
        validate_invitation(&invitation, &store.workspace_id, now)?;
        let expected_generation = match store.read_state_optional()? {
            None => StorageGeneration::Missing,
            Some((generation, state)) => {
                if now < state.last_observed_unix_seconds {
                    return Err(TeamAuthorityError::ClockRollback);
                }
                match &state.local {
                    StoredLocalAuthority::Pending { .. } => generation,
                    StoredLocalAuthority::Active {
                        principal_id: current_principal,
                        bundle,
                        ..
                    } if current_principal == &principal_id
                        && member_for_principal(&bundle.document, current_principal)
                            .is_some_and(TeamMembership::is_revoked) =>
                    {
                        generation
                    }
                    StoredLocalAuthority::Active { .. } => {
                        return Err(TeamAuthorityError::AlreadyEnrolled);
                    }
                }
            }
        };
        let principal_key = generate_signing_key()?;
        let request_id = EnrollmentRequestId::random()?;
        let invitation_digest = digest_serialized(&invitation)?;
        let expires_at = invitation
            .expires_at_unix_seconds
            .min(now.saturating_add(MAX_TEAM_ENROLLMENT_TTL_SECONDS));
        let mut request = TeamEnrollmentRequest {
            schema_version: TEAM_AUTHORITY_ARTIFACT_SCHEMA_VERSION,
            request_id,
            invitation_id: invitation.invitation_id.clone(),
            invitation_digest,
            team_id: team_id.clone(),
            workspace_id: store.workspace_id.clone(),
            principal_id: principal_id.clone(),
            principal_public_key: TeamPublicKey::from_key(&principal_key.verifying_key()),
            principal_key_generation: 1,
            issued_at_unix_seconds: now,
            expires_at_unix_seconds: expires_at,
            proof_signature: TeamSignature(String::new()),
        };
        let unsigned = unsigned_enrollment_request(&request);
        request.proof_signature = TeamSignature::sign(&principal_key, &canonical_bytes(&unsigned)?);
        let state = StoredAuthorityState {
            schema_version: TEAM_AUTHORITY_SCHEMA_VERSION,
            team_id,
            workspace_id: store.workspace_id.clone(),
            last_observed_unix_seconds: now,
            local: StoredLocalAuthority::Pending {
                principal_id,
                principal_secret_key: signing_key_to_secret(&principal_key)?,
                invitation,
                request: request.clone(),
            },
            consumed_grants: Vec::new(),
            audit_anchor: initial_audit_anchor(),
            audit_events: Vec::new(),
            next_audit_sequence: 1,
        };
        store.commit_state(expected_generation, &state)?;
        Ok((store, request))
    }

    /// Approve one exact proof-of-possession enrollment request and publish a
    /// successor signed authority document.
    ///
    /// # Errors
    /// Requires the active local authority private key and owner role. The
    /// invitation must bind the exact current authority bundle.
    pub fn approve_enrollment(
        &self,
        invitation: &TeamEnrollmentInvitation,
        request: &TeamEnrollmentRequest,
        role: TeamRole,
        membership_ttl_seconds: i64,
    ) -> Result<TeamEnrollmentApproval, TeamAuthorityError> {
        self.approve_enrollment_at(
            invitation,
            request,
            role,
            membership_ttl_seconds,
            now_unix_seconds()?,
        )
    }

    #[doc(hidden)]
    pub fn approve_enrollment_at(
        &self,
        invitation: &TeamEnrollmentInvitation,
        request: &TeamEnrollmentRequest,
        role: TeamRole,
        membership_ttl_seconds: i64,
        now: i64,
    ) -> Result<TeamEnrollmentApproval, TeamAuthorityError> {
        validate_membership_ttl(membership_ttl_seconds)?;
        validate_enrollment_request(invitation, request, now)?;
        if invitation.team_id() != &self.team_id || invitation.workspace_id() != &self.workspace_id
        {
            return Err(TeamAuthorityError::ScopeMismatch);
        }
        let payload_digest =
            digest_serialized(&(invitation, request, role, membership_ttl_seconds))?;
        let request_digest = self.authority_action_digest("approve_enrollment", payload_digest)?;
        let permit = self.authorize_local_admin(request_digest, now)?;
        self.update_state(|state| {
            let StoredLocalAuthority::Active {
                authority_secret_key,
                bundle,
                ..
            } = &mut state.local
            else {
                return Err(TeamAuthorityError::EnrollmentPending);
            };
            permit.require(
                &self.team_id,
                &self.workspace_id,
                TeamMemoryOperation::Admin,
                request_digest,
            )?;
            permit.require_current(bundle, now)?;
            if bundle != &invitation.bundle {
                return Err(TeamAuthorityError::MembershipInvalid);
            }
            let existing_index = bundle
                .document
                .members
                .binary_search_by(|member| member.principal_id.cmp(&request.principal_id))
                .ok();
            if existing_index.is_none() && bundle.document.members.len() >= MAX_TEAM_MEMBERS {
                return Err(TeamAuthorityError::CapacityExceeded {
                    resource: "members",
                });
            }
            if existing_index.is_some_and(|index| {
                bundle.document.members[index]
                    .revoked_at_unix_seconds
                    .is_none()
            }) {
                return Err(TeamAuthorityError::AlreadyEnrolled);
            }
            let authority_key = authority_secret_key
                .as_ref()
                .ok_or(TeamAuthorityError::CredentialUnavailable)
                .and_then(secret_to_signing_key)?;
            let replacement = TeamMembership {
                membership_id: MembershipId::random()?,
                principal_id: request.principal_id.clone(),
                role,
                expires_at_unix_seconds: now.saturating_add(membership_ttl_seconds),
                membership_generation: 1,
                principal_key_generation: request.principal_key_generation,
                principal_public_key: request.principal_public_key.clone(),
                revoked_at_unix_seconds: None,
                enrollment_request_digest: Some(digest_serialized(request)?),
            };
            if let Some(index) = existing_index {
                bundle.document.members[index] = replacement;
            } else {
                bundle.document.members.push(replacement);
            }
            bundle
                .document
                .members
                .sort_by(|left, right| left.principal_id.cmp(&right.principal_id));
            advance_and_sign_document(bundle, &authority_key)?;
            state.last_observed_unix_seconds = state.last_observed_unix_seconds.max(now);
            Ok(TeamEnrollmentApproval {
                schema_version: TEAM_AUTHORITY_ARTIFACT_SCHEMA_VERSION,
                request_digest: digest_serialized(request)?,
                bundle: bundle.clone(),
            })
        })
    }

    /// Complete enrollment after receiving the public signed approval.
    ///
    /// # Errors
    /// Rejects a different trust anchor, request, principal key, workspace,
    /// team, expired membership, or invalid authority chain.
    pub fn accept_enrollment(
        &self,
        approval: &TeamEnrollmentApproval,
    ) -> Result<(), TeamAuthorityError> {
        self.accept_enrollment_at(approval, now_unix_seconds()?)
    }

    #[doc(hidden)]
    pub fn accept_enrollment_at(
        &self,
        approval: &TeamEnrollmentApproval,
        now: i64,
    ) -> Result<(), TeamAuthorityError> {
        if approval.schema_version != TEAM_AUTHORITY_ARTIFACT_SCHEMA_VERSION {
            return Err(TeamAuthorityError::InvalidArtifact);
        }
        validate_authority_bundle(&approval.bundle, &self.team_id, &self.workspace_id)?;
        let replica_storage_secret_key = generate_replica_storage_secret()?;
        self.update_state(|state| {
            let StoredLocalAuthority::Pending {
                principal_id,
                principal_secret_key,
                invitation,
                request,
            } = &state.local
            else {
                return Err(TeamAuthorityError::MembershipInvalid);
            };
            if approval.bundle.trust_anchor != invitation.bundle.trust_anchor
                || approval.request_digest != digest_serialized(request)?
            {
                return Err(TeamAuthorityError::ScopeMismatch);
            }
            let member = member_for_principal(&approval.bundle.document, principal_id)
                .ok_or(TeamAuthorityError::MembershipInvalid)?;
            if member.principal_public_key != request.principal_public_key
                || member.principal_key_generation != request.principal_key_generation
                || member.enrollment_request_digest != Some(approval.request_digest)
            {
                return Err(TeamAuthorityError::MembershipInvalid);
            }
            require_active_member(member, now)?;
            let active = StoredLocalAuthority::Active {
                principal_id: principal_id.clone(),
                principal_secret_key: principal_secret_key.clone(),
                authority_secret_key: None,
                replica_storage_secret_key: Some(replica_storage_secret_key.clone()),
                replica_identities: ReplicaIdentityAnchors::default(),
                bundle: approval.bundle.clone(),
                pending_rotation: None,
            };
            state.local = active;
            state.last_observed_unix_seconds = state.last_observed_unix_seconds.max(now);
            Ok(())
        })
    }

    /// Change one member's role through an owner-authorized successor
    /// document. Downgrading the last active owner fails validation.
    ///
    /// # Errors
    /// Fails for missing owner authority, stale or revoked membership,
    /// invalid target identity, persistence conflict, or recovery state.
    pub fn set_member_role(
        &self,
        principal_id: &PrincipalId,
        role: TeamRole,
    ) -> Result<TeamAuthorityBundle, TeamAuthorityError> {
        self.set_member_role_at(principal_id, role, now_unix_seconds()?)
    }

    #[doc(hidden)]
    pub fn set_member_role_at(
        &self,
        principal_id: &PrincipalId,
        role: TeamRole,
        now: i64,
    ) -> Result<TeamAuthorityBundle, TeamAuthorityError> {
        let payload_digest = digest_serialized(&(principal_id, role))?;
        self.mutate_member_document(
            "set_member_role",
            payload_digest,
            principal_id,
            now,
            |member| {
                member.role = role;
                member.membership_generation = member.membership_generation.saturating_add(1);
                Ok(())
            },
        )
    }

    /// Revoke one member immediately. Revoking the last active owner fails
    /// closed so the authority cannot silently become unmaintainable.
    ///
    /// # Errors
    /// Fails for missing owner authority, stale membership, an invalid target,
    /// persistence conflict, or an invalid successor document.
    pub fn revoke_member(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<TeamAuthorityBundle, TeamAuthorityError> {
        self.revoke_member_at(principal_id, now_unix_seconds()?)
    }

    #[doc(hidden)]
    pub fn revoke_member_at(
        &self,
        principal_id: &PrincipalId,
        now: i64,
    ) -> Result<TeamAuthorityBundle, TeamAuthorityError> {
        let payload_digest = digest_serialized(principal_id)?;
        self.mutate_member_document(
            "revoke_member",
            payload_digest,
            principal_id,
            now,
            |member| {
                member.revoked_at_unix_seconds = Some(now);
                member.membership_generation = member.membership_generation.saturating_add(1);
                Ok(())
            },
        )
    }

    /// Renew one active membership with a bounded host-approved TTL.
    ///
    /// # Errors
    /// Fails for an invalid TTL, missing owner authority, revoked or unknown
    /// membership, persistence conflict, or recovery state.
    pub fn renew_member(
        &self,
        principal_id: &PrincipalId,
        membership_ttl_seconds: i64,
    ) -> Result<TeamAuthorityBundle, TeamAuthorityError> {
        self.renew_member_at(principal_id, membership_ttl_seconds, now_unix_seconds()?)
    }

    #[doc(hidden)]
    pub fn renew_member_at(
        &self,
        principal_id: &PrincipalId,
        membership_ttl_seconds: i64,
        now: i64,
    ) -> Result<TeamAuthorityBundle, TeamAuthorityError> {
        validate_membership_ttl(membership_ttl_seconds)?;
        let payload_digest = digest_serialized(&(principal_id, membership_ttl_seconds))?;
        self.mutate_member_document(
            "renew_member",
            payload_digest,
            principal_id,
            now,
            |member| {
                if member.revoked_at_unix_seconds.is_some() {
                    return Err(TeamAuthorityError::MembershipInvalid);
                }
                member.expires_at_unix_seconds = now.saturating_add(membership_ttl_seconds);
                member.membership_generation = member.membership_generation.saturating_add(1);
                Ok(())
            },
        )
    }

    /// Recover the expired local owner on the host that retains the current
    /// team authority signing credential.
    ///
    /// This is a deliberately narrow break-glass path: it cannot recover a
    /// revoked member, change a role, name another principal, or run on an
    /// enrolled host that lacks the current authority key. The successor
    /// membership document and a causally linked redacted recovery receipt are
    /// committed atomically.
    ///
    /// # Errors
    /// Fails closed unless the local membership is an expired, non-revoked
    /// owner and the host retains the current authority signing credential.
    pub fn recover_expired_local_owner(
        &self,
        membership_ttl_seconds: i64,
    ) -> Result<TeamOwnerRecovery, TeamAuthorityError> {
        self.recover_expired_local_owner_at(membership_ttl_seconds, now_unix_seconds()?)
    }

    #[doc(hidden)]
    pub fn recover_expired_local_owner_at(
        &self,
        membership_ttl_seconds: i64,
        now: i64,
    ) -> Result<TeamOwnerRecovery, TeamAuthorityError> {
        validate_membership_ttl(membership_ttl_seconds)?;
        let request_digest = self.authority_action_digest(
            "recover_expired_local_owner",
            digest_serialized(&membership_ttl_seconds)?,
        )?;
        let authorization_attempt_digest = random_authorization_attempt_digest()?;
        self.update_state(|state| {
            if now < state.last_observed_unix_seconds {
                return Err(TeamAuthorityError::ClockRollback);
            }
            let (bundle_result, principal_id, authority_key_generation) = {
                let StoredLocalAuthority::Active {
                    principal_id,
                    authority_secret_key,
                    bundle,
                    ..
                } = &mut state.local
                else {
                    return Err(TeamAuthorityError::EnrollmentPending);
                };
                let index = bundle
                    .document
                    .members
                    .binary_search_by(|member| member.principal_id.cmp(principal_id))
                    .map_err(|_| TeamAuthorityError::MembershipInvalid)?;
                let member = &mut bundle.document.members[index];
                if member.revoked_at_unix_seconds.is_some() || now < member.expires_at_unix_seconds
                {
                    return Err(TeamAuthorityError::MembershipInvalid);
                }
                if member.role != TeamRole::Owner {
                    return Err(TeamAuthorityError::OwnerRequired);
                }
                let authority_key = authority_secret_key
                    .as_ref()
                    .ok_or(TeamAuthorityError::CredentialUnavailable)
                    .and_then(secret_to_signing_key)?;
                member.expires_at_unix_seconds = now.saturating_add(membership_ttl_seconds);
                member.membership_generation = member.membership_generation.saturating_add(1);
                advance_and_sign_document(bundle, &authority_key)?;
                (
                    bundle.clone(),
                    principal_id.clone(),
                    bundle.document.authority_key_generation,
                )
            };
            state.last_observed_unix_seconds = now;
            let receipt = append_audit_event_fields(
                state,
                &AuditEventFields {
                    timestamp: now,
                    operation: TeamMemoryOperation::Admin,
                    allowed: true,
                    decision_code: TeamAuditDecisionCode::RecoveryAllowed,
                    grant_digest: digest_serialized(&(
                        "authority_key_possession",
                        authority_key_generation,
                        request_digest,
                    ))?,
                    principal_digest: redacted_identity_digest(
                        b"openclaudia.team-authority.principal.v1",
                        principal_id.as_str(),
                    ),
                    request_digest,
                    authorization_attempt_digest,
                },
            )?;
            Ok(TeamOwnerRecovery {
                bundle: bundle_result,
                receipt,
            })
        })
    }

    /// Rotate the team authority key and append an old-key-signed epoch
    /// transition. Every grant bound to the previous key generation becomes
    /// stale immediately.
    ///
    /// # Errors
    /// Fails for missing owner or authority-key credentials, epoch capacity,
    /// persistence conflict, clock failure, or invalid stored state.
    pub fn rotate_authority_key(&self) -> Result<TeamAuthorityBundle, TeamAuthorityError> {
        self.rotate_authority_key_at(now_unix_seconds()?)
    }

    #[doc(hidden)]
    pub fn rotate_authority_key_at(
        &self,
        now: i64,
    ) -> Result<TeamAuthorityBundle, TeamAuthorityError> {
        let next_key = generate_signing_key()?;
        let next_public_key = TeamPublicKey::from_key(&next_key.verifying_key());
        let payload_digest = digest_serialized(&next_public_key)?;
        let request_digest =
            self.authority_action_digest("rotate_authority_key", payload_digest)?;
        let permit = self.authorize_local_admin(request_digest, now)?;
        self.update_state(|state| {
            let StoredLocalAuthority::Active {
                authority_secret_key,
                bundle,
                ..
            } = &mut state.local
            else {
                return Err(TeamAuthorityError::EnrollmentPending);
            };
            permit.require(
                &self.team_id,
                &self.workspace_id,
                TeamMemoryOperation::Admin,
                request_digest,
            )?;
            permit.require_current(bundle, now)?;
            let current_secret = authority_secret_key
                .as_ref()
                .ok_or(TeamAuthorityError::CredentialUnavailable)?;
            let current_key = secret_to_signing_key(current_secret)?;
            if bundle.key_epochs.len() >= MAX_KEY_EPOCHS {
                return Err(TeamAuthorityError::CapacityExceeded {
                    resource: "authority key epochs",
                });
            }
            let previous_generation = bundle.document.authority_key_generation;
            let next_generation = previous_generation.saturating_add(1);
            let transition = AuthorityKeyTransition {
                schema_version: TEAM_AUTHORITY_ARTIFACT_SCHEMA_VERSION,
                team_id: self.team_id.clone(),
                workspace_id: self.workspace_id.clone(),
                previous_generation,
                next_generation,
                next_public_key: next_public_key.clone(),
            };
            bundle.key_epochs.push(AuthorityKeyEpoch {
                generation: next_generation,
                public_key: next_public_key.clone(),
                previous_signature: Some(TeamSignature::sign(
                    &current_key,
                    &canonical_bytes(&transition)?,
                )),
            });
            bundle.document.authority_key_generation = next_generation;
            bundle.document.authority_generation =
                bundle.document.authority_generation.saturating_add(1);
            bundle.document_signature =
                TeamSignature::sign(&next_key, &authority_document_bytes(&bundle.document)?);
            *authority_secret_key = Some(signing_key_to_secret(&next_key)?);
            state.last_observed_unix_seconds = state.last_observed_unix_seconds.max(now);
            Ok(bundle.clone())
        })
    }

    /// Begin rotation of the local principal credential. The successor secret
    /// remains host-private; the returned public request proves possession of
    /// both old and new keys.
    ///
    /// # Errors
    /// Fails for inactive membership, an existing pending rotation, unavailable
    /// randomness, persistence conflict, or invalid credential state.
    pub fn begin_principal_key_rotation(
        &self,
    ) -> Result<TeamCredentialRotationRequest, TeamAuthorityError> {
        self.begin_principal_key_rotation_at(now_unix_seconds()?)
    }

    #[doc(hidden)]
    pub fn begin_principal_key_rotation_at(
        &self,
        now: i64,
    ) -> Result<TeamCredentialRotationRequest, TeamAuthorityError> {
        let (_, state) = self.read_required_state()?;
        let StoredLocalAuthority::Active {
            principal_id,
            principal_secret_key,
            bundle,
            pending_rotation,
            ..
        } = state.local
        else {
            return Err(TeamAuthorityError::EnrollmentPending);
        };
        if pending_rotation.is_some() {
            return Err(TeamAuthorityError::ConcurrentUpdate);
        }
        let member = member_for_principal(&bundle.document, &principal_id)
            .ok_or(TeamAuthorityError::MembershipInvalid)?;
        require_active_member(member, now)?;
        let current_key = secret_to_signing_key(&principal_secret_key)?;
        let next_key = generate_signing_key()?;
        let mut request = TeamCredentialRotationRequest {
            schema_version: TEAM_AUTHORITY_ARTIFACT_SCHEMA_VERSION,
            team_id: self.team_id.clone(),
            workspace_id: self.workspace_id.clone(),
            principal_id: principal_id.clone(),
            membership_id: member.membership_id.clone(),
            current_key_generation: member.principal_key_generation,
            next_key_generation: member.principal_key_generation.saturating_add(1),
            next_public_key: TeamPublicKey::from_key(&next_key.verifying_key()),
            authority_generation: bundle.document.authority_generation,
            issued_at_unix_seconds: now,
            expires_at_unix_seconds: now.saturating_add(MAX_TEAM_ENROLLMENT_TTL_SECONDS),
            current_key_signature: TeamSignature(String::new()),
            next_key_signature: TeamSignature(String::new()),
        };
        let unsigned = unsigned_rotation_request(&request);
        let bytes = canonical_bytes(&unsigned)?;
        request.current_key_signature = TeamSignature::sign(&current_key, &bytes);
        request.next_key_signature = TeamSignature::sign(&next_key, &bytes);
        let payload_digest = digest_serialized(&request)?;
        let request_digest =
            self.authority_action_digest("begin_principal_key_rotation", payload_digest)?;
        let permit = self.authorize_local_operation(
            TeamMemoryOperation::ManageOwnCredential,
            request_digest,
            now,
        )?;
        let next_secret_key = signing_key_to_secret(&next_key)?;
        self.update_state(|state| {
            let StoredLocalAuthority::Active {
                principal_id,
                bundle,
                pending_rotation,
                ..
            } = &mut state.local
            else {
                return Err(TeamAuthorityError::EnrollmentPending);
            };
            permit.require(
                &self.team_id,
                &self.workspace_id,
                TeamMemoryOperation::ManageOwnCredential,
                request_digest,
            )?;
            permit.require_current(bundle, now)?;
            if principal_id != &request.principal_id
                || bundle.document.authority_generation != request.authority_generation
                || pending_rotation.is_some()
            {
                return Err(TeamAuthorityError::MembershipInvalid);
            }
            *pending_rotation = Some(PendingCredentialRotation {
                request: request.clone(),
                next_secret_key: next_secret_key.clone(),
            });
            state.last_observed_unix_seconds = state.last_observed_unix_seconds.max(now);
            Ok(request.clone())
        })
    }

    /// Approve a principal-key rotation and return the successor public
    /// authority bundle. A local self-rotation switches to the pending secret
    /// atomically with the signed membership update.
    ///
    /// # Errors
    /// Fails for a forged, expired, stale, or foreign request; missing owner or
    /// authority-key credentials; persistence conflict; or recovery state.
    pub fn approve_principal_key_rotation(
        &self,
        request: &TeamCredentialRotationRequest,
    ) -> Result<TeamAuthorityBundle, TeamAuthorityError> {
        self.approve_principal_key_rotation_at(request, now_unix_seconds()?)
    }

    #[doc(hidden)]
    pub fn approve_principal_key_rotation_at(
        &self,
        request: &TeamCredentialRotationRequest,
        now: i64,
    ) -> Result<TeamAuthorityBundle, TeamAuthorityError> {
        if request.team_id != self.team_id || request.workspace_id != self.workspace_id {
            return Err(TeamAuthorityError::ScopeMismatch);
        }
        let payload_digest = digest_serialized(request)?;
        let request_digest =
            self.authority_action_digest("approve_principal_key_rotation", payload_digest)?;
        let permit = self.authorize_local_admin(request_digest, now)?;
        self.update_state(|state| {
            let StoredLocalAuthority::Active {
                principal_id,
                principal_secret_key,
                authority_secret_key,
                bundle,
                pending_rotation,
                ..
            } = &mut state.local
            else {
                return Err(TeamAuthorityError::EnrollmentPending);
            };
            permit.require(
                &self.team_id,
                &self.workspace_id,
                TeamMemoryOperation::Admin,
                request_digest,
            )?;
            permit.require_current(bundle, now)?;
            if bundle.document.authority_generation != request.authority_generation {
                return Err(TeamAuthorityError::MembershipInvalid);
            }
            let index = bundle
                .document
                .members
                .binary_search_by(|member| member.principal_id.cmp(&request.principal_id))
                .map_err(|_| TeamAuthorityError::MembershipInvalid)?;
            validate_rotation_request(request, &bundle.document.members[index], now)?;
            let authority_key = authority_secret_key
                .as_ref()
                .ok_or(TeamAuthorityError::CredentialUnavailable)
                .and_then(secret_to_signing_key)?;
            let member = &mut bundle.document.members[index];
            member.principal_public_key = request.next_public_key.clone();
            member.principal_key_generation = request.next_key_generation;
            member.membership_generation = member.membership_generation.saturating_add(1);
            if principal_id == &request.principal_id {
                let pending = pending_rotation
                    .take()
                    .ok_or(TeamAuthorityError::CredentialUnavailable)?;
                if pending.request != *request {
                    return Err(TeamAuthorityError::GrantMismatch);
                }
                *principal_secret_key = pending.next_secret_key;
            }
            advance_and_sign_document(bundle, &authority_key)?;
            state.last_observed_unix_seconds = state.last_observed_unix_seconds.max(now);
            Ok(bundle.clone())
        })
    }

    /// Import a newer signed public authority bundle. This is a manual
    /// authority update, not lesson replication. A pending principal rotation
    /// is completed only when the signed successor key exactly matches it.
    ///
    /// # Errors
    /// Fails for a forged, stale, foreign, or divergent authority chain,
    /// incompatible local credential, persistence conflict, or recovery state.
    pub fn apply_authority_bundle(
        &self,
        successor: &TeamAuthorityBundle,
    ) -> Result<(), TeamAuthorityError> {
        self.apply_authority_bundle_at(successor, now_unix_seconds()?)
    }

    #[doc(hidden)]
    pub fn apply_authority_bundle_at(
        &self,
        successor: &TeamAuthorityBundle,
        now: i64,
    ) -> Result<(), TeamAuthorityError> {
        validate_authority_bundle(successor, &self.team_id, &self.workspace_id)?;
        self.update_state(|state| {
            let StoredLocalAuthority::Active {
                principal_id,
                principal_secret_key,
                authority_secret_key,
                bundle,
                pending_rotation,
                ..
            } = &mut state.local
            else {
                return Err(TeamAuthorityError::EnrollmentPending);
            };
            if successor.trust_anchor != bundle.trust_anchor
                || successor.document.authority_generation < bundle.document.authority_generation
                || successor.key_epochs.len() < bundle.key_epochs.len()
                || successor.key_epochs[..bundle.key_epochs.len()] != bundle.key_epochs
            {
                return Err(TeamAuthorityError::MembershipInvalid);
            }
            if successor.document.authority_generation == bundle.document.authority_generation {
                if successor != bundle {
                    return Err(TeamAuthorityError::MembershipInvalid);
                }
                return Ok(());
            }
            let member = member_for_principal(&successor.document, principal_id)
                .ok_or(TeamAuthorityError::MembershipInvalid)?;
            let current_key = secret_to_signing_key(principal_secret_key)?;
            if TeamPublicKey::from_key(&current_key.verifying_key()) != member.principal_public_key
            {
                let pending = pending_rotation
                    .take()
                    .ok_or(TeamAuthorityError::CredentialUnavailable)?;
                if pending.request.next_public_key != member.principal_public_key
                    || pending.request.next_key_generation != member.principal_key_generation
                {
                    return Err(TeamAuthorityError::MembershipInvalid);
                }
                *principal_secret_key = pending.next_secret_key;
            }
            if let Some(secret) = authority_secret_key {
                let local_authority_key = secret_to_signing_key(secret)?;
                let current_public = successor
                    .key_epochs
                    .last()
                    .ok_or(TeamAuthorityError::InvalidArtifact)?
                    .public_key
                    .clone();
                if TeamPublicKey::from_key(&local_authority_key.verifying_key()) != current_public {
                    *authority_secret_key = None;
                }
            }
            *bundle = successor.clone();
            state.last_observed_unix_seconds = state.last_observed_unix_seconds.max(now);
            Ok(())
        })
    }

    fn mutate_member_document(
        &self,
        action: &'static str,
        payload_digest: ContentDigest,
        principal_id: &PrincipalId,
        now: i64,
        mutation: impl Fn(&mut TeamMembership) -> Result<(), TeamAuthorityError>,
    ) -> Result<TeamAuthorityBundle, TeamAuthorityError> {
        let request_digest = self.authority_action_digest(action, payload_digest)?;
        let permit = self.authorize_local_admin(request_digest, now)?;
        self.update_state(|state| {
            let StoredLocalAuthority::Active {
                authority_secret_key,
                bundle,
                ..
            } = &mut state.local
            else {
                return Err(TeamAuthorityError::EnrollmentPending);
            };
            permit.require(
                &self.team_id,
                &self.workspace_id,
                TeamMemoryOperation::Admin,
                request_digest,
            )?;
            permit.require_current(bundle, now)?;
            let authority_key = authority_secret_key
                .as_ref()
                .ok_or(TeamAuthorityError::CredentialUnavailable)
                .and_then(secret_to_signing_key)?;
            let index = bundle
                .document
                .members
                .binary_search_by(|member| member.principal_id.cmp(principal_id))
                .map_err(|_| TeamAuthorityError::MembershipInvalid)?;
            mutation(&mut bundle.document.members[index])?;
            require_active_owner(&bundle.document.members, now)?;
            advance_and_sign_document(bundle, &authority_key)?;
            state.last_observed_unix_seconds = state.last_observed_unix_seconds.max(now);
            Ok(bundle.clone())
        })
    }

    fn authority_action_digest(
        &self,
        action: &'static str,
        payload_digest: ContentDigest,
    ) -> Result<ContentDigest, TeamAuthorityError> {
        digest_serialized(&AuthorityAction {
            schema_version: TEAM_AUTHORITY_ARTIFACT_SCHEMA_VERSION,
            team_id: &self.team_id,
            workspace_id: &self.workspace_id,
            action,
            payload_digest,
        })
    }

    fn authorize_local_admin(
        &self,
        request_digest: ContentDigest,
        now: i64,
    ) -> Result<TeamOperationPermit, TeamAuthorityError> {
        self.authorize_local_operation(TeamMemoryOperation::Admin, request_digest, now)
    }

    fn authorize_local_operation(
        &self,
        operation: TeamMemoryOperation,
        request_digest: ContentDigest,
        now: i64,
    ) -> Result<TeamOperationPermit, TeamAuthorityError> {
        let grant =
            self.issue_grant_at(operation, request_digest, MAX_TEAM_GRANT_TTL_SECONDS, now)?;
        match self.authorize_grant_at(&grant, operation, request_digest, now)? {
            TeamAuthorizationOutcome::Authorized(permit) => Ok(permit),
            TeamAuthorizationOutcome::Denied { reason, .. } => {
                Err(denial_to_error(reason, operation))
            }
        }
    }

    fn update_state<R>(
        &self,
        mut update: impl FnMut(&mut StoredAuthorityState) -> Result<R, TeamAuthorityError>,
    ) -> Result<R, TeamAuthorityError> {
        for _ in 0..MAX_AUTHORITY_RETRIES {
            let (generation, mut state) = self.read_required_state()?;
            let output = update(&mut state)?;
            match self.commit_state(generation, &state) {
                Ok(()) => return Ok(output),
                Err(TeamAuthorityError::Persistence(PersistenceError::Conflict { .. })) => {}
                Err(error) => return Err(error),
            }
        }
        Err(TeamAuthorityError::ConcurrentUpdate)
    }
}

const fn unsigned_enrollment_request(
    request: &TeamEnrollmentRequest,
) -> UnsignedEnrollmentRequest<'_> {
    UnsignedEnrollmentRequest {
        schema_version: request.schema_version,
        request_id: &request.request_id,
        invitation_id: &request.invitation_id,
        invitation_digest: request.invitation_digest,
        team_id: &request.team_id,
        workspace_id: &request.workspace_id,
        principal_id: &request.principal_id,
        principal_public_key: &request.principal_public_key,
        principal_key_generation: request.principal_key_generation,
        issued_at_unix_seconds: request.issued_at_unix_seconds,
        expires_at_unix_seconds: request.expires_at_unix_seconds,
    }
}

const fn unsigned_rotation_request(
    request: &TeamCredentialRotationRequest,
) -> UnsignedCredentialRotationRequest<'_> {
    UnsignedCredentialRotationRequest {
        schema_version: request.schema_version,
        team_id: &request.team_id,
        workspace_id: &request.workspace_id,
        principal_id: &request.principal_id,
        membership_id: &request.membership_id,
        current_key_generation: request.current_key_generation,
        next_key_generation: request.next_key_generation,
        next_public_key: &request.next_public_key,
        authority_generation: request.authority_generation,
        issued_at_unix_seconds: request.issued_at_unix_seconds,
        expires_at_unix_seconds: request.expires_at_unix_seconds,
    }
}

fn advance_and_sign_document(
    bundle: &mut TeamAuthorityBundle,
    authority_key: &SigningKey,
) -> Result<(), TeamAuthorityError> {
    bundle.document.authority_generation = bundle.document.authority_generation.saturating_add(1);
    bundle.document_signature =
        TeamSignature::sign(authority_key, &authority_document_bytes(&bundle.document)?);
    validate_authority_bundle(
        bundle,
        &bundle.document.team_id,
        &bundle.document.workspace_id,
    )
}

const fn denial_to_error(
    denial: TeamAuthorizationDenial,
    operation: TeamMemoryOperation,
) -> TeamAuthorityError {
    match denial {
        TeamAuthorizationDenial::ScopeMismatch => TeamAuthorityError::ScopeMismatch,
        TeamAuthorizationDenial::Expired => TeamAuthorityError::Expired,
        TeamAuthorizationDenial::ClockRollback => TeamAuthorityError::ClockRollback,
        TeamAuthorizationDenial::MembershipInvalid => TeamAuthorityError::MembershipInvalid,
        TeamAuthorizationDenial::RoleDenied => TeamAuthorityError::RoleDenied { operation },
        TeamAuthorizationDenial::GrantReplay => TeamAuthorityError::GrantReplay,
        TeamAuthorizationDenial::GrantMismatch => TeamAuthorityError::GrantMismatch,
        TeamAuthorizationDenial::InvalidSignature => TeamAuthorityError::InvalidSignature,
        TeamAuthorizationDenial::CapacityExceeded => TeamAuthorityError::CapacityExceeded {
            resource: "grant replay ledger",
        },
    }
}
