//! Stable identity and causal revision records for durable memory.
//!
//! Physical SQLite row IDs are deliberately absent from this module. A memory
//! keeps the same [`LogicalMemoryId`] when it is copied between stores, while
//! every mutation creates an immutable [`MemoryRevision`] whose digest binds
//! its parent, content, tags, provenance, author, scope, and state.

use std::fmt;
use std::num::NonZeroU64;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

/// Schema version of the JSON provenance envelope stored with every revision.
pub const MEMORY_PROVENANCE_SCHEMA_VERSION: u32 = 1;

/// Persistent identity of one physical memory store.
///
/// This is deliberately distinct from [`LogicalMemoryId`]: a logical memory
/// may be replicated into many stores, while replacing a store must allocate a
/// new ID so stale overlays and replication logs cannot silently attach to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MemoryStoreId(Uuid);

impl MemoryStoreId {
    /// Allocate a new physical-store identity.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Return the underlying UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for MemoryStoreId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MemoryStoreId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for MemoryStoreId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

/// Store-independent identity of one logical memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LogicalMemoryId(Uuid);

impl LogicalMemoryId {
    /// Allocate a new globally unique identity.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Build the deterministic identity used only for a legacy row migration.
    ///
    /// The caller supplies the complete canonical legacy record. Equal prose
    /// alone is intentionally insufficient to produce equal identities.
    #[must_use]
    pub(crate) fn for_legacy_record(canonical_record: &[u8]) -> Self {
        let digest = digest_bytes_fields(b"openclaudia.memory.legacy-id.v1", &[canonical_record]);
        Self::from_deterministic_digest(digest)
    }

    /// Build the stable identity for one exact workspace/source invocation.
    /// Replaying that invocation therefore addresses the same root revision.
    #[must_use]
    pub(crate) fn for_technical_source(workspace_id: &str, source_id: &str) -> Self {
        let digest = digest_bytes_fields(
            b"openclaudia.memory.technical-source-id.v1",
            &[workspace_id.as_bytes(), source_id.as_bytes()],
        );
        Self::from_deterministic_digest(digest)
    }

    fn from_deterministic_digest(digest: [u8; 32]) -> Self {
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        // Mark this as a standards-shaped, deterministic UUID without claiming
        // UUIDv5 (which uses SHA-1). The variant is RFC 4122 and the version
        // nibble is reserved for implementation-specific use (8).
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Self(Uuid::from_bytes(bytes))
    }

    /// Return the underlying UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for LogicalMemoryId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for LogicalMemoryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for LogicalMemoryId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

/// Monotonic, non-zero version within one logical memory's revision graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MemoryVersion(NonZeroU64);

impl MemoryVersion {
    /// Initial memory version.
    pub const INITIAL: Self = Self(NonZeroU64::MIN);

    /// Validate a persisted version.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    fn next(self) -> Result<Self, MemoryRecordError> {
        self.get()
            .checked_add(1)
            .and_then(Self::new)
            .ok_or(MemoryRecordError::VersionExhausted)
    }
}

impl fmt::Display for MemoryVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// SHA-256 digest with an explicit algorithm prefix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryDigest(String);

impl MemoryDigest {
    /// Hash one exact byte sequence without adding a domain envelope.
    ///
    /// This is reserved for artifact identity, where the interoperable
    /// `SHA-256(file-bytes)` value is the contract. Semantic record digests
    /// should continue to use [`Self::for_fields`] so their type and fields
    /// remain domain separated.
    #[must_use]
    pub fn sha256(bytes: &[u8]) -> Self {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        digest_from_bytes(digest)
    }

    /// Hash a domain-separated sequence of length-prefixed fields.
    #[must_use]
    pub fn for_fields(domain: &[u8], fields: &[&[u8]]) -> Self {
        digest_fields(domain, fields)
    }

    /// Return the canonical `sha256:<hex>` representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MemoryDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for MemoryDigest {
    type Err = MemoryRecordError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err(MemoryRecordError::InvalidDigest);
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(MemoryRecordError::InvalidDigest);
        }
        Ok(Self(value.to_string()))
    }
}

impl Serialize for MemoryDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for MemoryDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Where a revision is allowed to be replicated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryRecordScope {
    /// Host/user-private memory; never copied to the team store.
    UserPrivate,
    /// A record deliberately shared with an authenticated team store.
    TeamShared,
    /// Repository material imported as non-authoritative evidence.
    ProjectEvidence,
}

/// Kind of source observation that led to a revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySourceKind {
    /// Explicit host/user action.
    Explicit,
    /// Model-proposed capture or correction made through a canonical tool
    /// invocation. The proposal remains untrusted until separately reviewed.
    AgentProposal,
    /// Typed tool or task outcome.
    ToolOutcome,
    /// Imported repository or external artifact.
    Imported,
    /// Legacy row whose original source cannot be recovered.
    LegacyUnattributed,
}

/// Typed source observation from which a memory revision was derived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySourceEvidence {
    /// Evidence category; never an authority level.
    pub kind: MemorySourceKind,
    /// Stable source observation/artifact/call identifier.
    pub id: String,
    /// Exact source generation or version label.
    pub version: String,
    /// Digest of the source material or typed receipt.
    pub digest: MemoryDigest,
}

impl MemorySourceEvidence {
    /// Build one exact source observation.
    #[must_use]
    pub const fn new(
        kind: MemorySourceKind,
        id: String,
        version: String,
        digest: MemoryDigest,
    ) -> Self {
        Self {
            kind,
            id,
            version,
            digest,
        }
    }
}

/// Actor, physical store, and workspace attribution for a revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryAttribution {
    /// Attributed actor; use an explicit unknown marker when unavailable.
    pub author_id: String,
    /// Physical origin store, when known.
    pub origin_store_id: Option<MemoryStoreId>,
    /// Workspace/repository identity, when known.
    pub workspace_id: Option<String>,
}

impl MemoryAttribution {
    /// Build explicit revision attribution.
    #[must_use]
    pub const fn new(
        author_id: String,
        origin_store_id: Option<MemoryStoreId>,
        workspace_id: Option<String>,
    ) -> Self {
        Self {
            author_id,
            origin_store_id,
            workspace_id,
        }
    }
}

/// Attribution carried by every immutable revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryProvenance {
    /// Version of this envelope.
    pub schema_version: u32,
    /// Source category; it is evidence classification, not authority.
    pub source_kind: MemorySourceKind,
    /// Stable source observation/artifact/call identifier.
    pub source_id: String,
    /// Exact source generation or version label.
    pub source_version: String,
    /// Digest of the source material or typed receipt.
    pub source_digest: MemoryDigest,
    /// Attributed actor; legacy data uses an explicit unknown marker.
    pub author_id: String,
    /// Physical store where this observation/revision originated, when known.
    /// Replication preserves this value rather than rewriting provenance.
    pub origin_store_id: Option<MemoryStoreId>,
    /// Workspace/repository identity when known.
    pub workspace_id: Option<String>,
    /// Replication scope selected at capture time.
    pub scope: MemoryRecordScope,
}

impl MemoryProvenance {
    /// Build explicit provenance for a new record.
    #[must_use]
    pub fn new(
        source: MemorySourceEvidence,
        attribution: MemoryAttribution,
        scope: MemoryRecordScope,
    ) -> Self {
        Self {
            schema_version: MEMORY_PROVENANCE_SCHEMA_VERSION,
            source_kind: source.kind,
            source_id: source.id,
            source_version: source.version,
            source_digest: source.digest,
            author_id: attribution.author_id,
            origin_store_id: attribution.origin_store_id,
            workspace_id: attribution.workspace_id,
            scope,
        }
    }

    /// Explicitly mark data for which legacy source attribution was absent.
    #[must_use]
    pub(crate) fn legacy(logical_id: LogicalMemoryId, content_digest: MemoryDigest) -> Self {
        Self::new(
            MemorySourceEvidence::new(
                MemorySourceKind::LegacyUnattributed,
                format!("legacy-row:{logical_id}"),
                "pre-s053".to_string(),
                content_digest,
            ),
            MemoryAttribution::new("legacy-unattributed".to_string(), None, None),
            MemoryRecordScope::ProjectEvidence,
        )
    }
}

/// Whether a revision contains live content or records a versioned deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryRevisionState {
    /// A live record revision.
    Active,
    /// A deletion that names and causally follows an exact prior revision.
    Tombstone,
}

/// One immutable node in a logical memory's causal revision graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryRevision {
    /// Logical identity shared by every replica/revision.
    pub logical_id: LogicalMemoryId,
    /// Monotonic version. Concurrent branches may share a version.
    pub version: MemoryVersion,
    /// Exact predecessor digest (`None` only at version one).
    pub parent_digest: Option<MemoryDigest>,
    /// Digest binding every semantic field of this revision.
    pub record_digest: MemoryDigest,
    /// Digest of the exact content bytes.
    pub content_digest: MemoryDigest,
    /// Content retained for active records; tombstones carry an empty string.
    pub content: String,
    /// Canonical sorted, de-duplicated tags.
    pub tags: Vec<String>,
    /// Source and author attribution.
    pub provenance: MemoryProvenance,
    /// Live or deleted state.
    pub state: MemoryRevisionState,
}

impl MemoryRevision {
    /// Create a new root revision.
    #[must_use]
    pub fn new(content: String, tags: Vec<String>, provenance: MemoryProvenance) -> Self {
        Self::build(
            LogicalMemoryId::new(),
            MemoryVersion::INITIAL,
            None,
            content,
            tags,
            provenance,
            MemoryRevisionState::Active,
        )
    }

    /// Create an idempotent root at a host-derived logical identity.
    #[must_use]
    pub(crate) fn new_with_logical_id(
        logical_id: LogicalMemoryId,
        content: String,
        tags: Vec<String>,
        provenance: MemoryProvenance,
    ) -> Self {
        Self::build(
            logical_id,
            MemoryVersion::INITIAL,
            None,
            content,
            tags,
            provenance,
            MemoryRevisionState::Active,
        )
    }

    /// Create the next active revision.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryRecordError::VersionExhausted`] at the numeric limit.
    pub fn successor(
        &self,
        content: String,
        tags: Vec<String>,
        provenance: MemoryProvenance,
    ) -> Result<Self, MemoryRecordError> {
        if provenance.scope != self.provenance.scope {
            return Err(MemoryRecordError::ScopeChange);
        }
        Ok(Self::build(
            self.logical_id,
            self.version.next()?,
            Some(self.record_digest.clone()),
            content,
            tags,
            provenance,
            MemoryRevisionState::Active,
        ))
    }

    /// Create a version-bound tombstone.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryRecordError::VersionExhausted`] at the numeric limit.
    pub fn tombstone(&self, provenance: MemoryProvenance) -> Result<Self, MemoryRecordError> {
        if provenance.scope != self.provenance.scope {
            return Err(MemoryRecordError::ScopeChange);
        }
        Ok(Self::build(
            self.logical_id,
            self.version.next()?,
            Some(self.record_digest.clone()),
            String::new(),
            Vec::new(),
            provenance,
            MemoryRevisionState::Tombstone,
        ))
    }

    /// Rebuild the deterministic legacy root used by migration tests and SQL.
    pub(crate) fn legacy(logical_id: LogicalMemoryId, content: String, tags: Vec<String>) -> Self {
        let content_digest = content_digest(&content);
        let provenance = MemoryProvenance::legacy(logical_id, content_digest);
        Self::build(
            logical_id,
            MemoryVersion::INITIAL,
            None,
            content,
            tags,
            provenance,
            MemoryRevisionState::Active,
        )
    }

    #[cfg(test)]
    pub(crate) fn successor_with_unchecked_scope_for_storage_test(
        &self,
        provenance: MemoryProvenance,
    ) -> Result<Self, MemoryRecordError> {
        Ok(Self::build(
            self.logical_id,
            self.version.next()?,
            Some(self.record_digest.clone()),
            self.content.clone(),
            self.tags.clone(),
            provenance,
            MemoryRevisionState::Active,
        ))
    }

    fn build(
        logical_id: LogicalMemoryId,
        version: MemoryVersion,
        parent_digest: Option<MemoryDigest>,
        content: String,
        mut tags: Vec<String>,
        provenance: MemoryProvenance,
        state: MemoryRevisionState,
    ) -> Self {
        tags.sort();
        tags.dedup();
        let content_digest = content_digest(&content);
        let record_digest = revision_digest(
            logical_id,
            version,
            parent_digest.as_ref(),
            &content_digest,
            &tags,
            &provenance,
            state,
        );
        Self {
            logical_id,
            version,
            parent_digest,
            record_digest,
            content_digest,
            content,
            tags,
            provenance,
            state,
        }
    }

    /// Recompute the revision digest and reject tampered/inconsistent input.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for unsupported provenance, invalid
    /// parent/state shape, non-canonical tags, or digest mismatch.
    pub fn validate(&self) -> Result<(), MemoryRecordError> {
        if self.provenance.schema_version != MEMORY_PROVENANCE_SCHEMA_VERSION {
            return Err(MemoryRecordError::UnsupportedProvenanceSchema);
        }
        if (self.version == MemoryVersion::INITIAL) != self.parent_digest.is_none() {
            return Err(MemoryRecordError::InvalidParent);
        }
        if self.state == MemoryRevisionState::Tombstone
            && (!self.content.is_empty() || !self.tags.is_empty())
        {
            return Err(MemoryRecordError::InvalidTombstone);
        }
        let rebuilt = Self::build(
            self.logical_id,
            self.version,
            self.parent_digest.clone(),
            self.content.clone(),
            self.tags.clone(),
            self.provenance.clone(),
            self.state,
        );
        if rebuilt.content_digest != self.content_digest
            || rebuilt.record_digest != self.record_digest
            || rebuilt.tags != self.tags
        {
            return Err(MemoryRecordError::DigestMismatch);
        }
        Ok(())
    }
}

/// Validation failures for persisted or replicated revisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MemoryRecordError {
    /// A digest was not canonical SHA-256 text.
    #[error("invalid memory digest")]
    InvalidDigest,
    /// The record/content digest does not match the fields.
    #[error("memory revision digest mismatch")]
    DigestMismatch,
    /// Root and successor parent constraints were violated.
    #[error("invalid memory revision parent")]
    InvalidParent,
    /// Tombstones must not carry content or tags.
    #[error("invalid memory tombstone payload")]
    InvalidTombstone,
    /// No higher non-zero version can be represented.
    #[error("memory revision version exhausted")]
    VersionExhausted,
    /// The provenance envelope is not the supported exact schema.
    #[error("unsupported memory provenance schema")]
    UnsupportedProvenanceSchema,
    /// Replication authority cannot change within one logical lineage.
    #[error("memory revision cannot change replication scope")]
    ScopeChange,
}

fn revision_digest(
    logical_id: LogicalMemoryId,
    version: MemoryVersion,
    parent_digest: Option<&MemoryDigest>,
    content_digest: &MemoryDigest,
    tags: &[String],
    provenance: &MemoryProvenance,
    state: MemoryRevisionState,
) -> MemoryDigest {
    let mut hasher = Sha256::new();
    append_field(&mut hasher, b"openclaudia.memory.revision.v1");
    append_field(&mut hasher, logical_id.to_string().as_bytes());
    append_field(&mut hasher, &version.get().to_be_bytes());
    append_field(
        &mut hasher,
        parent_digest.map_or(&[][..], |digest| digest.as_str().as_bytes()),
    );
    append_field(&mut hasher, content_digest.as_str().as_bytes());
    append_field(
        &mut hasher,
        &u64::try_from(tags.len()).unwrap_or(u64::MAX).to_be_bytes(),
    );
    for tag in tags {
        append_field(&mut hasher, tag.as_bytes());
    }
    append_field(&mut hasher, &provenance.schema_version.to_be_bytes());
    append_field(
        &mut hasher,
        match provenance.source_kind {
            MemorySourceKind::Explicit => b"explicit",
            MemorySourceKind::AgentProposal => b"agent_proposal",
            MemorySourceKind::ToolOutcome => b"tool_outcome",
            MemorySourceKind::Imported => b"imported",
            MemorySourceKind::LegacyUnattributed => b"legacy_unattributed",
        },
    );
    append_field(&mut hasher, provenance.source_id.as_bytes());
    append_field(&mut hasher, provenance.source_version.as_bytes());
    append_field(&mut hasher, provenance.source_digest.as_str().as_bytes());
    append_field(&mut hasher, provenance.author_id.as_bytes());
    append_field(
        &mut hasher,
        provenance
            .origin_store_id
            .map(|store_id| store_id.to_string())
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    append_field(
        &mut hasher,
        provenance
            .workspace_id
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    append_field(
        &mut hasher,
        match provenance.scope {
            MemoryRecordScope::UserPrivate => b"user_private",
            MemoryRecordScope::TeamShared => b"team_shared",
            MemoryRecordScope::ProjectEvidence => b"project_evidence",
        },
    );
    append_field(
        &mut hasher,
        match state {
            MemoryRevisionState::Active => b"active",
            MemoryRevisionState::Tombstone => b"tombstone",
        },
    );
    digest_from_bytes(hasher.finalize().into())
}

fn content_digest(content: &str) -> MemoryDigest {
    digest_fields(b"openclaudia.memory.content.v1", &[content.as_bytes()])
}

fn digest_fields(domain: &[u8], fields: &[&[u8]]) -> MemoryDigest {
    digest_from_bytes(digest_bytes_fields(domain, fields))
}

fn digest_from_bytes(bytes: [u8; 32]) -> MemoryDigest {
    let mut hex = String::with_capacity(64);
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    MemoryDigest(format!("sha256:{hex}"))
}

fn digest_bytes_fields(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    append_field(&mut hasher, domain);
    for field in fields {
        append_field(&mut hasher, field);
    }
    hasher.finalize().into()
}

fn append_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance(scope: MemoryRecordScope) -> MemoryProvenance {
        MemoryProvenance::new(
            MemorySourceEvidence::new(
                MemorySourceKind::Explicit,
                "receipt-1".to_string(),
                "generation-7".to_string(),
                MemoryDigest::for_fields(b"test-source", &[b"source"]),
            ),
            MemoryAttribution::new("actor-1".to_string(), None, Some("workspace-1".to_string())),
            scope,
        )
    }

    #[test]
    fn interoperable_sha256_matches_the_standard_empty_vector() {
        assert_eq!(
            MemoryDigest::sha256(b"").as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn equal_content_does_not_assign_equal_identity() {
        let left = MemoryRevision::new(
            "use descriptor-relative opens".to_string(),
            Vec::new(),
            provenance(MemoryRecordScope::UserPrivate),
        );
        let right = MemoryRevision::new(
            "use descriptor-relative opens".to_string(),
            Vec::new(),
            provenance(MemoryRecordScope::UserPrivate),
        );
        assert_ne!(left.logical_id, right.logical_id);
        assert_eq!(left.content_digest, right.content_digest);
    }

    #[test]
    fn successors_bind_parent_and_detect_concurrent_branches() {
        let root = MemoryRevision::new(
            "old lesson".to_string(),
            vec!["rust".to_string()],
            provenance(MemoryRecordScope::TeamShared),
        );
        let left = root
            .successor(
                "left correction".to_string(),
                vec!["rust".to_string()],
                provenance(MemoryRecordScope::TeamShared),
            )
            .unwrap();
        let right = root
            .successor(
                "right correction".to_string(),
                vec!["rust".to_string()],
                provenance(MemoryRecordScope::TeamShared),
            )
            .unwrap();
        assert_eq!(left.version, right.version);
        assert_eq!(left.parent_digest, right.parent_digest);
        assert_ne!(left.record_digest, right.record_digest);
        left.validate().unwrap();
        right.validate().unwrap();
    }

    #[test]
    fn successor_and_tombstone_reject_replication_scope_changes() {
        let root = MemoryRevision::new(
            "private lesson".to_string(),
            Vec::new(),
            provenance(MemoryRecordScope::UserPrivate),
        );
        assert_eq!(
            root.successor(
                "attempted shared lesson".to_string(),
                Vec::new(),
                provenance(MemoryRecordScope::TeamShared),
            )
            .unwrap_err(),
            MemoryRecordError::ScopeChange
        );
        assert_eq!(
            root.tombstone(provenance(MemoryRecordScope::TeamShared))
                .unwrap_err(),
            MemoryRecordError::ScopeChange
        );
    }

    #[test]
    fn tampered_revision_is_rejected() {
        let mut revision = MemoryRevision::new(
            "verified command".to_string(),
            Vec::new(),
            provenance(MemoryRecordScope::UserPrivate),
        );
        revision.content.push_str(" --force");
        assert_eq!(revision.validate(), Err(MemoryRecordError::DigestMismatch));
    }

    #[test]
    fn noncanonical_tag_order_is_rejected_even_when_digest_was_valid() {
        let mut revision = MemoryRevision::new(
            "lesson".to_string(),
            vec!["alpha".to_string(), "beta".to_string()],
            provenance(MemoryRecordScope::UserPrivate),
        );
        revision.tags.reverse();
        assert_eq!(revision.validate(), Err(MemoryRecordError::DigestMismatch));
    }

    #[test]
    fn tombstone_is_version_bound_and_empty() {
        let root = MemoryRevision::new(
            "obsolete lesson".to_string(),
            vec!["old".to_string()],
            provenance(MemoryRecordScope::UserPrivate),
        );
        let tombstone = root
            .tombstone(provenance(MemoryRecordScope::UserPrivate))
            .unwrap();
        assert_eq!(tombstone.version.get(), 2);
        assert_eq!(tombstone.parent_digest, Some(root.record_digest));
        assert_eq!(tombstone.state, MemoryRevisionState::Tombstone);
        assert!(tombstone.content.is_empty());
        assert!(tombstone.tags.is_empty());
        tombstone.validate().unwrap();
    }
}
