//! Bounded, integrity-checked portable packages for technical memory.
//!
//! The package contains only the typed technical-lesson causal graph, source
//! lifecycle state, and host-review audit roots. Legacy memory, transcripts,
//! prompts, and free-form compatibility tables are deliberately absent.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;
use std::str::FromStr as _;
use std::time::{Duration, Instant};

use rusqlite::{params, Connection, TransactionBehavior};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use super::review::TechnicalLessonReviewAudit;
use super::{
    LogicalMemoryId, MemoryDb, MemoryDigest, MemoryRecordScope, MemoryRevision,
    MemoryRevisionState, MemoryStoreId, TechnicalMemorySourceState,
    TechnicalMemorySourceStoreStatus, WorkspaceMemoryId, MAX_MEMORY_MIGRATION_ROWS,
    MEMORY_PROVENANCE_SCHEMA_VERSION, TECHNICAL_LESSON_SCHEMA_VERSION, TECHNICAL_LESSON_TAG,
    TECHNICAL_MEMORY_REVIEW_AUDIT_SCHEMA_VERSION, TECHNICAL_MEMORY_REVIEW_AUDIT_TAG,
    TECHNICAL_MEMORY_SOURCE_STATE_SCHEMA_VERSION, TECHNICAL_MEMORY_SOURCE_TAG,
};
use crate::permissions::HostApprovalEvidence;
use crate::persistence::{
    CommitState, FileClass, PersistenceError, PersistentStorage, StorageGeneration, StorageRootId,
};
use crate::runtime::CancellationHandle;

/// Exact portable package schema emitted and accepted by this build.
pub const TECHNICAL_MEMORY_PACKAGE_SCHEMA_VERSION: u32 = 1;
/// The only file whose presence marks a package complete.
pub const TECHNICAL_MEMORY_PACKAGE_MANIFEST_NAME: &str =
    "openclaudia-technical-memory-manifest.json";
/// Mutable resumable progress state. It never marks a package complete.
pub const TECHNICAL_MEMORY_PACKAGE_CHECKPOINT_NAME: &str =
    "openclaudia-technical-memory-checkpoint.json";

const MAX_PACKAGE_PART_BYTES: usize = 4 * 1024 * 1024;
const TARGET_PACKAGE_PART_PAYLOAD_BYTES: usize = 3 * 1024 * 1024;
const MAX_PACKAGE_ENTRY_BYTES: usize = 96 * 1024;
const MAX_PACKAGE_PARTS: usize = 512;
const MAX_PACKAGE_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_PACKAGE_ENTRIES: u64 = 2_000_000;
const PACKAGE_FILE_CLASS: FileClass = FileClass::PortableMemoryPackage;
const MAX_PORTABLE_CALL_DURATION: Duration = Duration::from_secs(60);
// Package schema v1 began with typed memory objects from store schema v6.
// Multi-parent revisions require the additive store-v7 reader. Keep accepting
// truthful v6 packages while every package emitted by this build declares v7.
const MINIMUM_PORTABLE_MEMORY_STORE_SCHEMA_VERSION: u32 = 7;
const OLDEST_SUPPORTED_PORTABLE_MEMORY_STORE_SCHEMA_VERSION: u32 = 6;
const MULTI_PARENT_PORTABLE_MEMORY_STORE_SCHEMA_VERSION: u32 = 7;

const PORTABLE_HISTORY_CTE: &str = r"WITH RECURSIVE portable_history(record_digest) AS (
    SELECT revision.record_digest
      FROM memory_revisions revision
     WHERE EXISTS (
         SELECT 1 FROM json_each(revision.tags_json) AS tag
          WHERE tag.value IN (?1, ?2, ?3)
     )
    UNION
    SELECT child.record_digest
      FROM memory_revisions child
      JOIN portable_history parent ON child.parent_digest = parent.record_digest
)";

/// One exact immutable package part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicalMemoryPackagePartDescriptor {
    pub index: u32,
    pub file_name: String,
    pub byte_len: u64,
    pub entry_count: u32,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub previous_part_digest: Option<MemoryDigest>,
    pub part_digest: MemoryDigest,
}

/// Durable package declaration. Parts without this exact final manifest are
/// intentionally incomplete and are never imported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicalMemoryPackageManifest {
    pub schema_version: u32,
    pub store_schema_version: u32,
    pub minimum_reader_version: u32,
    pub lesson_schema_version: u32,
    pub provenance_schema_version: u32,
    pub source_state_schema_version: u32,
    pub review_audit_schema_version: u32,
    pub workspace_id: WorkspaceMemoryId,
    pub source_store_id: MemoryStoreId,
    pub package_id: MemoryDigest,
    pub snapshot_digest: MemoryDigest,
    pub revision_count: u64,
    pub head_count: u64,
    pub entry_count: u64,
    pub total_part_bytes: u64,
    pub parts: Vec<TechnicalMemoryPackagePartDescriptor>,
}

/// Truthful terminal or resumable export state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PortableMemoryExportStatus {
    Completed,
    Idempotent,
    Cancelled,
    DeadlineExceeded,
    DurabilityUncertain,
}

/// Bounded export receipt. Lesson content and filesystem paths are absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortableMemoryExportResult {
    pub schema_version: u32,
    pub status: PortableMemoryExportStatus,
    /// Absent only when cancellation or the fixed deadline stopped work before
    /// a complete snapshot was observed, so the receipt never fabricates
    /// content identity.
    pub package_id: Option<MemoryDigest>,
    /// Absent only when work stopped before snapshot validation.
    pub snapshot_digest: Option<MemoryDigest>,
    pub manifest_digest: Option<MemoryDigest>,
    pub checkpoint_digest: Option<MemoryDigest>,
    pub revision_count: u64,
    pub head_count: u64,
    pub completed_parts: usize,
    pub total_part_bytes: u64,
}

/// Truthful atomic import state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PortableMemoryImportStatus {
    Imported,
    Idempotent,
    Cancelled,
    DeadlineExceeded,
}

/// Bounded import receipt. No lesson content is reflected to the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortableMemoryImportResult {
    pub schema_version: u32,
    pub status: PortableMemoryImportStatus,
    pub package_id: MemoryDigest,
    pub snapshot_digest: MemoryDigest,
    pub manifest_digest: MemoryDigest,
    pub revision_count: u64,
    pub head_count: u64,
}

/// Typed package rejection. Messages deliberately avoid lesson bytes and host
/// paths so callers can safely render them as recovery diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum PortableMemoryError {
    #[error("portable technical-memory operation lacks exact fresh host approval")]
    ApprovalInvalid,
    #[error("portable technical-memory checkpoint exists; supply expected digest {observed}")]
    CheckpointRequired { observed: MemoryDigest },
    #[error("portable technical-memory checkpoint generation is stale")]
    StaleCheckpoint,
    #[error("portable technical-memory destination contains conflicting package state")]
    DestinationConflict,
    #[error("portable technical-memory package is incomplete, corrupt, or noncanonical")]
    InvalidPackage,
    #[error("portable technical-memory package uses an unsupported schema")]
    UnsupportedSchema,
    #[error("portable technical-memory package exceeds a fixed budget")]
    BudgetExceeded,
    #[error("portable technical-memory package belongs to a different workspace")]
    WrongWorkspace,
    #[error("portable technical-memory target store has divergent causal state")]
    CausalConflict,
    #[error("portable technical-memory snapshot changed during publication")]
    SnapshotChanged,
    #[error("portable technical-memory operation was cancelled")]
    Cancelled,
    #[error("portable technical-memory operation reached its fixed work deadline")]
    DeadlineExceeded,
    #[error("portable technical-memory persistence failed")]
    Persistence(#[source] PersistenceError),
    #[error("portable technical-memory store validation failed")]
    Store(#[source] anyhow::Error),
}

impl From<PersistenceError> for PortableMemoryError {
    fn from(error: PersistenceError) -> Self {
        match error {
            PersistenceError::TooLarge { .. } => Self::BudgetExceeded,
            PersistenceError::InvalidTarget { .. } => Self::InvalidPackage,
            PersistenceError::Conflict { .. } => Self::DestinationConflict,
            other => Self::Persistence(other),
        }
    }
}

impl PortableMemoryError {
    fn store(error: impl Into<anyhow::Error>) -> Self {
        Self::Store(error.into())
    }
}

pub struct PortableMemoryExportRequest<'a> {
    pub storage: &'a PersistentStorage,
    pub expected_checkpoint_digest: Option<MemoryDigest>,
    pub approval: &'a HostApprovalEvidence,
    pub arguments: &'a Value,
    pub control: PortableOperationControl,
}

pub struct PortableMemoryImportRequest<'a> {
    pub storage: &'a PersistentStorage,
    pub approval: &'a HostApprovalEvidence,
    pub arguments: &'a Value,
    pub control: PortableOperationControl,
}

/// Per-invocation stop authority shared by snapshot, publication, validation,
/// and atomic import phases.
pub struct PortableOperationControl {
    cancellation: CancellationHandle,
    deadline: Instant,
}

impl PortableOperationControl {
    /// Bind one package call to run cancellation and the fixed wall-clock
    /// work budget. An incomplete export publishes only a resumable checkpoint.
    #[must_use]
    pub fn new(cancellation: CancellationHandle) -> Self {
        Self {
            cancellation,
            deadline: Instant::now() + MAX_PORTABLE_CALL_DURATION,
        }
    }

    #[cfg(test)]
    fn with_duration(cancellation: CancellationHandle, duration: Duration) -> Self {
        Self {
            cancellation,
            deadline: Instant::now() + duration,
        }
    }

    fn check(&self) -> Result<(), PortableMemoryError> {
        if self.cancellation.is_cancelled() {
            return Err(PortableMemoryError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(PortableMemoryError::DeadlineExceeded);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PortableEntry {
    Revision {
        revision: Box<MemoryRevision>,
    },
    Head {
        logical_id: LogicalMemoryId,
        record_digest: MemoryDigest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortableEntryEnvelope {
    sequence: u64,
    entry: PortableEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TechnicalMemoryPackagePart {
    schema_version: u32,
    package_id: MemoryDigest,
    index: u32,
    first_sequence: u64,
    last_sequence: u64,
    previous_part_digest: Option<MemoryDigest>,
    entries_digest: MemoryDigest,
    entries: Vec<PortableEntryEnvelope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CheckpointStatus {
    InProgress,
    Cancelled,
    DeadlineExceeded,
    PartsComplete,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TechnicalMemoryPackageCheckpoint {
    schema_version: u32,
    package_id: MemoryDigest,
    snapshot_digest: MemoryDigest,
    workspace_id: WorkspaceMemoryId,
    source_store_id: MemoryStoreId,
    destination_root: StorageRootId,
    status: CheckpointStatus,
    revision_count: u64,
    head_count: u64,
    entry_count: u64,
    next_sequence: u64,
    completed_parts: Vec<TechnicalMemoryPackagePartDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotSummary {
    snapshot_digest: MemoryDigest,
    revision_count: u64,
    head_count: u64,
    entry_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineageKind {
    TechnicalLesson,
    SourceState,
    ReviewAudit,
}

struct LineageCursor {
    logical_id: LogicalMemoryId,
    kind: LineageKind,
    revisions: BTreeMap<MemoryDigest, super::MemoryVersion>,
    superseded: BTreeSet<MemoryDigest>,
}

impl LineageCursor {
    fn from_root(root: &MemoryRevision, kind: LineageKind) -> Self {
        Self {
            logical_id: root.logical_id,
            kind,
            revisions: BTreeMap::from([(root.record_digest.clone(), root.version)]),
            superseded: BTreeSet::new(),
        }
    }

    fn sole_unsuperseded_head(&self) -> Option<&MemoryDigest> {
        let mut heads = self
            .revisions
            .keys()
            .filter(|digest| !self.superseded.contains(*digest));
        let head = heads.next()?;
        heads.next().is_none().then_some(head)
    }
}

fn package_id(
    workspace_id: &WorkspaceMemoryId,
    source_store_id: MemoryStoreId,
    snapshot_digest: &MemoryDigest,
) -> MemoryDigest {
    MemoryDigest::for_fields(
        b"openclaudia.technical-memory.package-id.v1",
        &[
            workspace_id.as_str().as_bytes(),
            source_store_id.to_string().as_bytes(),
            snapshot_digest.as_str().as_bytes(),
        ],
    )
}

fn package_part_name(package_id: &MemoryDigest, index: u32) -> Result<String, PortableMemoryError> {
    let digest = package_id
        .as_str()
        .strip_prefix("sha256:")
        .ok_or(PortableMemoryError::InvalidPackage)?;
    Ok(format!(
        "openclaudia-technical-memory-{digest}-part-{index:06}.json"
    ))
}

fn canonical_root_target(storage: &PersistentStorage) -> Result<String, PortableMemoryError> {
    let root = storage
        .root_path()
        .canonicalize()
        .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;
    if root != storage.root_path() {
        return Err(PortableMemoryError::DestinationConflict);
    }
    Ok(root.to_string_lossy().into_owned())
}

fn append_digest_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

fn new_snapshot_hasher(workspace_id: &WorkspaceMemoryId) -> Sha256 {
    let mut hasher = Sha256::new();
    append_digest_field(&mut hasher, b"openclaudia.technical-memory.snapshot.v1");
    append_digest_field(
        &mut hasher,
        &TECHNICAL_MEMORY_PACKAGE_SCHEMA_VERSION.to_be_bytes(),
    );
    append_digest_field(&mut hasher, workspace_id.as_str().as_bytes());
    append_digest_field(&mut hasher, &TECHNICAL_LESSON_SCHEMA_VERSION.to_be_bytes());
    append_digest_field(&mut hasher, &MEMORY_PROVENANCE_SCHEMA_VERSION.to_be_bytes());
    append_digest_field(
        &mut hasher,
        &TECHNICAL_MEMORY_SOURCE_STATE_SCHEMA_VERSION.to_be_bytes(),
    );
    append_digest_field(
        &mut hasher,
        &TECHNICAL_MEMORY_REVIEW_AUDIT_SCHEMA_VERSION.to_be_bytes(),
    );
    hasher
}

fn finish_snapshot_digest(hasher: Sha256) -> MemoryDigest {
    let digest: [u8; 32] = hasher.finalize().into();
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        let _ = write!(encoded, "{byte:02x}");
    }
    MemoryDigest::from_str(&format!("sha256:{encoded}"))
        .expect("SHA-256 formatter always emits a canonical memory digest")
}

impl MemoryDb {
    fn portable_snapshot_on(
        conn: &Connection,
        workspace_id: &WorkspaceMemoryId,
        control: &PortableOperationControl,
    ) -> Result<SnapshotSummary, PortableMemoryError> {
        let mut hasher = new_snapshot_hasher(workspace_id);
        let mut revision_count = 0_u64;
        let mut head_count = 0_u64;
        let mut entry_count = 0_u64;
        Self::visit_portable_entries_on(conn, workspace_id, control, |envelope| {
            let encoded = serde_json::to_vec(&envelope)
                .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;
            if encoded.len() > MAX_PACKAGE_ENTRY_BYTES {
                return Err(PortableMemoryError::BudgetExceeded);
            }
            append_digest_field(&mut hasher, &encoded);
            match envelope.entry {
                PortableEntry::Revision { .. } => {
                    revision_count = revision_count
                        .checked_add(1)
                        .ok_or(PortableMemoryError::BudgetExceeded)?;
                }
                PortableEntry::Head { .. } => {
                    head_count = head_count
                        .checked_add(1)
                        .ok_or(PortableMemoryError::BudgetExceeded)?;
                }
            }
            entry_count = entry_count
                .checked_add(1)
                .ok_or(PortableMemoryError::BudgetExceeded)?;
            if entry_count > MAX_PACKAGE_ENTRIES {
                return Err(PortableMemoryError::BudgetExceeded);
            }
            Ok(())
        })?;
        Ok(SnapshotSummary {
            snapshot_digest: finish_snapshot_digest(hasher),
            revision_count,
            head_count,
            entry_count,
        })
    }

    fn visit_portable_entries_on(
        conn: &Connection,
        workspace_id: &WorkspaceMemoryId,
        control: &PortableOperationControl,
        mut visitor: impl FnMut(PortableEntryEnvelope) -> Result<(), PortableMemoryError>,
    ) -> Result<(), PortableMemoryError> {
        let sql = format!(
            "{PORTABLE_HISTORY_CTE}\n\
             SELECT revision.logical_id, revision.version,\n\
                    revision.parent_digest, revision.record_digest,\n\
                    revision.content_digest, revision.content,\n\
                    revision.tags_json, revision.provenance_json,\n\
                    revision.record_state,\n\
                    revision.additional_parent_digests_json\n\
               FROM memory_revisions revision\n\
               JOIN portable_history history\n\
                 ON history.record_digest = revision.record_digest\n\
              ORDER BY revision.logical_id, revision.version, revision.record_digest\n\
              LIMIT ?4"
        );
        let mut statement = conn
            .prepare(&sql)
            .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;
        let mut rows = statement
            .query(params![
                TECHNICAL_LESSON_TAG,
                TECHNICAL_MEMORY_SOURCE_TAG,
                TECHNICAL_MEMORY_REVIEW_AUDIT_TAG,
                MAX_MEMORY_MIGRATION_ROWS.saturating_add(1),
            ])
            .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;
        let mut sequence = 0_u64;
        let mut revisions_seen = 0_i64;
        let mut lineage: Option<LineageCursor> = None;

        while let Some(row) = rows
            .next()
            .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?
        {
            control.check()?;
            revisions_seen = revisions_seen
                .checked_add(1)
                .ok_or(PortableMemoryError::BudgetExceeded)?;
            if revisions_seen > MAX_MEMORY_MIGRATION_ROWS {
                return Err(PortableMemoryError::BudgetExceeded);
            }
            let revision = Self::revision_from_row(row)
                .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;

            if lineage
                .as_ref()
                .is_some_and(|cursor| cursor.logical_id != revision.logical_id)
            {
                let completed = lineage.take().ok_or(PortableMemoryError::InvalidPackage)?;
                Self::emit_portable_head_on(conn, &completed, &mut sequence, &mut visitor)?;
            }

            match &mut lineage {
                None => {
                    let kind = classify_portable_root(&revision, workspace_id)?;
                    lineage = Some(LineageCursor::from_root(&revision, kind));
                }
                Some(cursor) => {
                    validate_portable_successor(cursor, &revision, workspace_id)?;
                    cursor
                        .superseded
                        .extend(revision.causal_parent_digests().cloned());
                    cursor
                        .revisions
                        .insert(revision.record_digest.clone(), revision.version);
                }
            }

            visitor(PortableEntryEnvelope {
                sequence,
                entry: PortableEntry::Revision {
                    revision: Box::new(revision),
                },
            })?;
            sequence = sequence
                .checked_add(1)
                .ok_or(PortableMemoryError::BudgetExceeded)?;
        }

        if let Some(completed) = lineage {
            Self::emit_portable_head_on(conn, &completed, &mut sequence, &mut visitor)?;
        }

        control.check()?;
        Self::validate_current_technical_lesson_projections(
            conn,
            Some(workspace_id),
            Some(MemoryRecordScope::UserPrivate),
        )
        .map_err(PortableMemoryError::store)?;
        control.check()?;
        match Self::technical_memory_source_status_on(conn, workspace_id)
            .map_err(PortableMemoryError::store)?
        {
            TechnicalMemorySourceStoreStatus::Unconfigured
            | TechnicalMemorySourceStoreStatus::Ready { .. } => {}
            TechnicalMemorySourceStoreStatus::Conflict { .. } => {
                return Err(PortableMemoryError::CausalConflict);
            }
        }
        control.check()?;
        Self::validate_all_host_review_audits_on(conn, workspace_id)
            .map_err(PortableMemoryError::store)?;
        control.check()?;
        Ok(())
    }

    fn emit_portable_head_on(
        conn: &Connection,
        lineage: &LineageCursor,
        sequence: &mut u64,
        visitor: &mut impl FnMut(PortableEntryEnvelope) -> Result<(), PortableMemoryError>,
    ) -> Result<(), PortableMemoryError> {
        let heads =
            Self::head_digests(conn, lineage.logical_id).map_err(PortableMemoryError::store)?;
        if heads.len() != 1 || lineage.sole_unsuperseded_head() != heads.first() {
            return Err(PortableMemoryError::CausalConflict);
        }
        visitor(PortableEntryEnvelope {
            sequence: *sequence,
            entry: PortableEntry::Head {
                logical_id: lineage.logical_id,
                record_digest: heads[0].clone(),
            },
        })?;
        *sequence = sequence
            .checked_add(1)
            .ok_or(PortableMemoryError::BudgetExceeded)?;
        Ok(())
    }
}

fn classify_portable_root(
    revision: &MemoryRevision,
    workspace_id: &WorkspaceMemoryId,
) -> Result<LineageKind, PortableMemoryError> {
    if revision.version != super::MemoryVersion::INITIAL
        || revision.parent_digest.is_some()
        || !revision.additional_parent_digests.is_empty()
    {
        return Err(PortableMemoryError::CausalConflict);
    }
    let kind = if revision.tags.iter().any(|tag| tag == TECHNICAL_LESSON_TAG) {
        LineageKind::TechnicalLesson
    } else if revision.tags == [TECHNICAL_MEMORY_SOURCE_TAG.to_string()] {
        LineageKind::SourceState
    } else if revision.tags == [TECHNICAL_MEMORY_REVIEW_AUDIT_TAG.to_string()] {
        LineageKind::ReviewAudit
    } else {
        return Err(PortableMemoryError::InvalidPackage);
    };
    validate_portable_revision(kind, revision, workspace_id, true)?;
    Ok(kind)
}

fn validate_portable_successor(
    lineage: &LineageCursor,
    revision: &MemoryRevision,
    workspace_id: &WorkspaceMemoryId,
) -> Result<(), PortableMemoryError> {
    if revision.logical_id != lineage.logical_id
        || (lineage.kind != LineageKind::TechnicalLesson
            && !revision.additional_parent_digests.is_empty())
    {
        return Err(PortableMemoryError::CausalConflict);
    }
    let parent_versions = revision
        .causal_parent_digests()
        .map(|digest| {
            lineage
                .revisions
                .get(digest)
                .copied()
                .ok_or(PortableMemoryError::CausalConflict)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let newest_parent = parent_versions
        .into_iter()
        .max()
        .ok_or(PortableMemoryError::CausalConflict)?;
    if newest_parent.get().checked_add(1) != Some(revision.version.get())
        || lineage.revisions.contains_key(&revision.record_digest)
    {
        return Err(PortableMemoryError::CausalConflict);
    }
    validate_portable_revision(lineage.kind, revision, workspace_id, false)
}

fn validate_portable_revision(
    kind: LineageKind,
    revision: &MemoryRevision,
    workspace_id: &WorkspaceMemoryId,
    is_root: bool,
) -> Result<(), PortableMemoryError> {
    revision
        .validate()
        .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;
    if revision.provenance.workspace_id.as_deref() != Some(workspace_id.as_str())
        || revision.provenance.scope != MemoryRecordScope::UserPrivate
    {
        return Err(PortableMemoryError::WrongWorkspace);
    }
    match kind {
        LineageKind::TechnicalLesson => {
            MemoryDb::validate_technical_lesson_lineage_revision(
                revision,
                workspace_id,
                MemoryRecordScope::UserPrivate,
            )
            .map_err(PortableMemoryError::store)?;
        }
        LineageKind::SourceState => {
            if revision.state != MemoryRevisionState::Active
                || revision.tags != [TECHNICAL_MEMORY_SOURCE_TAG.to_string()]
            {
                return Err(PortableMemoryError::InvalidPackage);
            }
            let state = TechnicalMemorySourceState::decode(&revision.content)
                .map_err(PortableMemoryError::store)?;
            state
                .validate_for_workspace(workspace_id)
                .map_err(PortableMemoryError::store)?;
            MemoryDb::validate_source_state_revision(revision, &state)
                .map_err(PortableMemoryError::store)?;
        }
        LineageKind::ReviewAudit => {
            if !is_root
                || revision.state != MemoryRevisionState::Active
                || revision.tags != [TECHNICAL_MEMORY_REVIEW_AUDIT_TAG.to_string()]
            {
                return Err(PortableMemoryError::InvalidPackage);
            }
            TechnicalLessonReviewAudit::decode(&revision.content)
                .map_err(PortableMemoryError::store)?;
        }
    }
    Ok(())
}

fn read_owned_bytes(
    storage: &PersistentStorage,
    target: &Path,
    class: FileClass,
) -> Result<(StorageGeneration, Option<Vec<u8>>), PortableMemoryError> {
    let state = storage.read(target, class)?;
    let bytes = state.expose_bytes(|bytes| bytes.map(<[u8]>::to_vec));
    Ok((state.generation(), bytes))
}

fn manifest_digest(bytes: &[u8]) -> MemoryDigest {
    MemoryDigest::sha256(bytes)
}

fn snapshot_matches_manifest(
    summary: &SnapshotSummary,
    manifest: &TechnicalMemoryPackageManifest,
) -> bool {
    summary.snapshot_digest == manifest.snapshot_digest
        && summary.revision_count == manifest.revision_count
        && summary.head_count == manifest.head_count
        && summary.entry_count == manifest.entry_count
}

fn decode_canonical_json<T>(bytes: &[u8]) -> Result<T, PortableMemoryError>
where
    T: DeserializeOwned + Serialize,
{
    let value =
        serde_json::from_slice::<T>(bytes).map_err(|_| PortableMemoryError::InvalidPackage)?;
    let canonical = serde_json::to_vec(&value).map_err(|_| PortableMemoryError::InvalidPackage)?;
    if canonical != bytes {
        return Err(PortableMemoryError::InvalidPackage);
    }
    Ok(value)
}

fn load_manifest(
    storage: &PersistentStorage,
) -> Result<Option<(TechnicalMemoryPackageManifest, Vec<u8>)>, PortableMemoryError> {
    let (_, bytes) = read_owned_bytes(
        storage,
        Path::new(TECHNICAL_MEMORY_PACKAGE_MANIFEST_NAME),
        PACKAGE_FILE_CLASS,
    )?;
    bytes
        .map(|bytes| {
            let manifest = decode_canonical_json::<TechnicalMemoryPackageManifest>(&bytes)?;
            validate_manifest(&manifest)?;
            Ok((manifest, bytes))
        })
        .transpose()
}

fn load_checkpoint(
    storage: &PersistentStorage,
    expected_digest: Option<&MemoryDigest>,
) -> Result<
    Option<(
        TechnicalMemoryPackageCheckpoint,
        StorageGeneration,
        MemoryDigest,
    )>,
    PortableMemoryError,
> {
    let (generation, bytes) = read_owned_bytes(
        storage,
        Path::new(TECHNICAL_MEMORY_PACKAGE_CHECKPOINT_NAME),
        PACKAGE_FILE_CLASS,
    )?;
    let Some(bytes) = bytes else {
        if expected_digest.is_some() {
            return Err(PortableMemoryError::StaleCheckpoint);
        }
        return Ok(None);
    };
    let observed = manifest_digest(&bytes);
    match expected_digest {
        None => {
            return Err(PortableMemoryError::CheckpointRequired { observed });
        }
        Some(expected) if expected != &observed => {
            return Err(PortableMemoryError::StaleCheckpoint);
        }
        Some(_) => {}
    }
    let checkpoint = decode_canonical_json::<TechnicalMemoryPackageCheckpoint>(&bytes)?;
    Ok(Some((checkpoint, generation, observed)))
}

fn validate_manifest(manifest: &TechnicalMemoryPackageManifest) -> Result<(), PortableMemoryError> {
    let supported_store_schema =
        u32::try_from(super::SCHEMA_VERSION).map_err(|_| PortableMemoryError::UnsupportedSchema)?;
    if manifest.schema_version != TECHNICAL_MEMORY_PACKAGE_SCHEMA_VERSION
        || !(OLDEST_SUPPORTED_PORTABLE_MEMORY_STORE_SCHEMA_VERSION
            ..=MINIMUM_PORTABLE_MEMORY_STORE_SCHEMA_VERSION)
            .contains(&manifest.minimum_reader_version)
        || manifest.minimum_reader_version > supported_store_schema
        || manifest.store_schema_version < manifest.minimum_reader_version
        || manifest.lesson_schema_version != TECHNICAL_LESSON_SCHEMA_VERSION
        || manifest.provenance_schema_version != MEMORY_PROVENANCE_SCHEMA_VERSION
        || manifest.source_state_schema_version != TECHNICAL_MEMORY_SOURCE_STATE_SCHEMA_VERSION
        || manifest.review_audit_schema_version != TECHNICAL_MEMORY_REVIEW_AUDIT_SCHEMA_VERSION
    {
        return Err(PortableMemoryError::UnsupportedSchema);
    }
    if manifest.entry_count
        != manifest
            .revision_count
            .checked_add(manifest.head_count)
            .ok_or(PortableMemoryError::BudgetExceeded)?
        || manifest.entry_count > MAX_PACKAGE_ENTRIES
        || manifest.parts.len() > MAX_PACKAGE_PARTS
        || manifest.total_part_bytes > MAX_PACKAGE_TOTAL_BYTES
        || manifest.package_id
            != package_id(
                &manifest.workspace_id,
                manifest.source_store_id,
                &manifest.snapshot_digest,
            )
    {
        return Err(PortableMemoryError::InvalidPackage);
    }

    let mut next_sequence = 0_u64;
    let mut previous_digest: Option<&MemoryDigest> = None;
    let mut total_bytes = 0_u64;
    let mut total_entries = 0_u64;
    for (position, part) in manifest.parts.iter().enumerate() {
        let index = u32::try_from(position).map_err(|_| PortableMemoryError::BudgetExceeded)?;
        if part.index != index
            || part.file_name != package_part_name(&manifest.package_id, index)?
            || part.byte_len == 0
            || part.byte_len > u64::try_from(MAX_PACKAGE_PART_BYTES).unwrap_or(u64::MAX)
            || part.entry_count == 0
            || part.first_sequence != next_sequence
            || part.last_sequence
                != part
                    .first_sequence
                    .checked_add(
                        u64::from(part.entry_count)
                            .checked_sub(1)
                            .ok_or(PortableMemoryError::InvalidPackage)?,
                    )
                    .ok_or(PortableMemoryError::BudgetExceeded)?
            || part.previous_part_digest.as_ref() != previous_digest
        {
            return Err(PortableMemoryError::InvalidPackage);
        }
        next_sequence = part
            .last_sequence
            .checked_add(1)
            .ok_or(PortableMemoryError::BudgetExceeded)?;
        total_bytes = total_bytes
            .checked_add(part.byte_len)
            .ok_or(PortableMemoryError::BudgetExceeded)?;
        total_entries = total_entries
            .checked_add(u64::from(part.entry_count))
            .ok_or(PortableMemoryError::BudgetExceeded)?;
        previous_digest = Some(&part.part_digest);
    }
    if total_entries != manifest.entry_count
        || total_bytes != manifest.total_part_bytes
        || next_sequence != manifest.entry_count
    {
        return Err(PortableMemoryError::InvalidPackage);
    }
    Ok(())
}

fn validate_checkpoint(
    checkpoint: &TechnicalMemoryPackageCheckpoint,
    summary: &SnapshotSummary,
    workspace_id: &WorkspaceMemoryId,
    source_store_id: MemoryStoreId,
    storage: &PersistentStorage,
) -> Result<(), PortableMemoryError> {
    if checkpoint.schema_version != TECHNICAL_MEMORY_PACKAGE_SCHEMA_VERSION
        || checkpoint.package_id
            != package_id(workspace_id, source_store_id, &summary.snapshot_digest)
        || checkpoint.snapshot_digest != summary.snapshot_digest
        || checkpoint.workspace_id != *workspace_id
        || checkpoint.source_store_id != source_store_id
        || checkpoint.destination_root != storage.root_id()
        || checkpoint.revision_count != summary.revision_count
        || checkpoint.head_count != summary.head_count
        || checkpoint.entry_count != summary.entry_count
        || checkpoint.next_sequence
            != checkpoint
                .completed_parts
                .last()
                .map_or(0, |part| part.last_sequence.saturating_add(1))
        || checkpoint.completed_parts.len() > MAX_PACKAGE_PARTS
    {
        return Err(PortableMemoryError::InvalidPackage);
    }
    Ok(())
}

fn commit_checkpoint(
    storage: &PersistentStorage,
    checkpoint: &TechnicalMemoryPackageCheckpoint,
) -> Result<(MemoryDigest, bool), PortableMemoryError> {
    let (generation, existing) = read_owned_bytes(
        storage,
        Path::new(TECHNICAL_MEMORY_PACKAGE_CHECKPOINT_NAME),
        PACKAGE_FILE_CLASS,
    )?;
    if let Some(existing) = existing {
        let prior = decode_canonical_json::<TechnicalMemoryPackageCheckpoint>(&existing)?;
        if prior.package_id != checkpoint.package_id
            || prior.destination_root != checkpoint.destination_root
            || prior.completed_parts.len() > checkpoint.completed_parts.len()
            || prior.completed_parts != checkpoint.completed_parts[..prior.completed_parts.len()]
        {
            return Err(PortableMemoryError::DestinationConflict);
        }
    }
    let encoded = serde_json::to_vec(checkpoint)
        .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;
    let receipt = storage.commit(
        Path::new(TECHNICAL_MEMORY_PACKAGE_CHECKPOINT_NAME),
        PACKAGE_FILE_CLASS,
        generation,
        &encoded,
    )?;
    Ok((
        manifest_digest(&encoded),
        receipt.state() == CommitState::PublishedDurabilityUncertain,
    ))
}

struct PartPublisher<'a> {
    storage: &'a PersistentStorage,
    checkpoint: TechnicalMemoryPackageCheckpoint,
    prior_checkpoint: Option<TechnicalMemoryPackageCheckpoint>,
    entries: Vec<PortableEntryEnvelope>,
    approximate_payload_bytes: usize,
    checkpoint_digest: Option<MemoryDigest>,
    total_part_bytes: u64,
    durability_uncertain: bool,
}

struct PreparedPart {
    descriptor: TechnicalMemoryPackagePartDescriptor,
    bytes: Vec<u8>,
}

impl<'a> PartPublisher<'a> {
    fn new(
        storage: &'a PersistentStorage,
        summary: &SnapshotSummary,
        workspace_id: WorkspaceMemoryId,
        source_store_id: MemoryStoreId,
        prior_checkpoint: Option<TechnicalMemoryPackageCheckpoint>,
    ) -> Self {
        Self {
            storage,
            checkpoint: TechnicalMemoryPackageCheckpoint {
                schema_version: TECHNICAL_MEMORY_PACKAGE_SCHEMA_VERSION,
                package_id: package_id(&workspace_id, source_store_id, &summary.snapshot_digest),
                snapshot_digest: summary.snapshot_digest.clone(),
                workspace_id,
                source_store_id,
                destination_root: storage.root_id(),
                status: CheckpointStatus::InProgress,
                revision_count: summary.revision_count,
                head_count: summary.head_count,
                entry_count: summary.entry_count,
                next_sequence: 0,
                completed_parts: Vec::new(),
            },
            prior_checkpoint,
            entries: Vec::new(),
            approximate_payload_bytes: 0,
            checkpoint_digest: None,
            total_part_bytes: 0,
            durability_uncertain: false,
        }
    }

    fn push(&mut self, entry: PortableEntryEnvelope) -> Result<(), PortableMemoryError> {
        let encoded_len = serde_json::to_vec(&entry)
            .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?
            .len();
        if encoded_len > MAX_PACKAGE_ENTRY_BYTES {
            return Err(PortableMemoryError::BudgetExceeded);
        }
        if !self.entries.is_empty()
            && self.approximate_payload_bytes.saturating_add(encoded_len)
                > TARGET_PACKAGE_PART_PAYLOAD_BYTES
        {
            self.flush()?;
        }
        self.approximate_payload_bytes = self
            .approximate_payload_bytes
            .checked_add(encoded_len)
            .ok_or(PortableMemoryError::BudgetExceeded)?;
        self.entries.push(entry);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), PortableMemoryError> {
        let Some(part) = self.prepare_part()? else {
            return Ok(());
        };
        self.publish_part(part)
    }

    fn prepare_part(&mut self) -> Result<Option<PreparedPart>, PortableMemoryError> {
        if self.entries.is_empty() {
            return Ok(None);
        }
        if self.checkpoint.completed_parts.len() >= MAX_PACKAGE_PARTS {
            return Err(PortableMemoryError::BudgetExceeded);
        }
        let index = u32::try_from(self.checkpoint.completed_parts.len())
            .map_err(|_| PortableMemoryError::BudgetExceeded)?;
        let first_sequence = self
            .entries
            .first()
            .map(|entry| entry.sequence)
            .ok_or(PortableMemoryError::InvalidPackage)?;
        let last_sequence = self
            .entries
            .last()
            .map(|entry| entry.sequence)
            .ok_or(PortableMemoryError::InvalidPackage)?;
        let entries_bytes = serde_json::to_vec(&self.entries)
            .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;
        let previous_part_digest = self
            .checkpoint
            .completed_parts
            .last()
            .map(|part| part.part_digest.clone());
        let part = TechnicalMemoryPackagePart {
            schema_version: TECHNICAL_MEMORY_PACKAGE_SCHEMA_VERSION,
            package_id: self.checkpoint.package_id.clone(),
            index,
            first_sequence,
            last_sequence,
            previous_part_digest: previous_part_digest.clone(),
            entries_digest: MemoryDigest::sha256(&entries_bytes),
            entries: std::mem::take(&mut self.entries),
        };
        self.approximate_payload_bytes = 0;
        let bytes = serde_json::to_vec(&part)
            .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;
        if bytes.len() > MAX_PACKAGE_PART_BYTES {
            return Err(PortableMemoryError::BudgetExceeded);
        }
        let descriptor = TechnicalMemoryPackagePartDescriptor {
            index,
            file_name: package_part_name(&self.checkpoint.package_id, index)?,
            byte_len: u64::try_from(bytes.len())
                .map_err(|_| PortableMemoryError::BudgetExceeded)?,
            entry_count: u32::try_from(part.entries.len())
                .map_err(|_| PortableMemoryError::BudgetExceeded)?,
            first_sequence,
            last_sequence,
            previous_part_digest,
            part_digest: MemoryDigest::sha256(&bytes),
        };
        Ok(Some(PreparedPart { descriptor, bytes }))
    }

    fn publish_part(&mut self, part: PreparedPart) -> Result<(), PortableMemoryError> {
        let PreparedPart { descriptor, bytes } = part;
        let prior_descriptor = self.prior_checkpoint.as_ref().and_then(|checkpoint| {
            usize::try_from(descriptor.index)
                .ok()
                .and_then(|index| checkpoint.completed_parts.get(index))
        });
        if let Some(expected) = prior_descriptor {
            if expected != &descriptor {
                return Err(PortableMemoryError::DestinationConflict);
            }
        }
        let (observed, existing) = read_owned_bytes(
            self.storage,
            Path::new(&descriptor.file_name),
            PACKAGE_FILE_CLASS,
        )?;
        if existing
            .as_deref()
            .is_some_and(|existing| existing != bytes)
        {
            return Err(PortableMemoryError::DestinationConflict);
        }
        if prior_descriptor.is_some() && existing.is_some() {
            return self.record_published_part(descriptor, None);
        }
        let expected_generation = if existing.is_some() {
            StorageGeneration::Missing
        } else {
            observed
        };
        let receipt = self.storage.commit(
            Path::new(&descriptor.file_name),
            PACKAGE_FILE_CLASS,
            expected_generation,
            &bytes,
        )?;
        self.record_published_part(descriptor, Some(receipt.state()))
    }

    fn record_published_part(
        &mut self,
        descriptor: TechnicalMemoryPackagePartDescriptor,
        commit_state: Option<CommitState>,
    ) -> Result<(), PortableMemoryError> {
        self.total_part_bytes = self
            .total_part_bytes
            .checked_add(descriptor.byte_len)
            .ok_or(PortableMemoryError::BudgetExceeded)?;
        if self.total_part_bytes > MAX_PACKAGE_TOTAL_BYTES {
            return Err(PortableMemoryError::BudgetExceeded);
        }
        self.checkpoint.next_sequence = descriptor
            .last_sequence
            .checked_add(1)
            .ok_or(PortableMemoryError::BudgetExceeded)?;
        self.checkpoint.completed_parts.push(descriptor);
        if commit_state == Some(CommitState::PublishedDurabilityUncertain) {
            self.durability_uncertain = true;
            return Ok(());
        }
        if self.prior_checkpoint.as_ref().is_some_and(|checkpoint| {
            self.checkpoint.completed_parts.len() <= checkpoint.completed_parts.len()
        }) {
            return Ok(());
        }
        let (digest, uncertain) = commit_checkpoint(self.storage, &self.checkpoint)?;
        self.checkpoint_digest = Some(digest);
        self.durability_uncertain |= uncertain;
        Ok(())
    }

    fn checkpoint_with_status(
        &mut self,
        status: CheckpointStatus,
    ) -> Result<(), PortableMemoryError> {
        self.checkpoint.status = status;
        let (digest, uncertain) = commit_checkpoint(self.storage, &self.checkpoint)?;
        self.checkpoint_digest = Some(digest);
        self.durability_uncertain |= uncertain;
        Ok(())
    }
}

const fn stopped_export_before_snapshot(
    status: PortableMemoryExportStatus,
) -> PortableMemoryExportResult {
    PortableMemoryExportResult {
        schema_version: TECHNICAL_MEMORY_PACKAGE_SCHEMA_VERSION,
        status,
        package_id: None,
        snapshot_digest: None,
        manifest_digest: None,
        checkpoint_digest: None,
        revision_count: 0,
        head_count: 0,
        completed_parts: 0,
        total_part_bytes: 0,
    }
}

fn existing_export_result(
    storage: &PersistentStorage,
    workspace_id: &WorkspaceMemoryId,
    source_store_id: MemoryStoreId,
    summary: &SnapshotSummary,
    control: &PortableOperationControl,
) -> Result<Option<PortableMemoryExportResult>, PortableMemoryError> {
    let Some((manifest, manifest_bytes)) = load_manifest(storage)? else {
        return Ok(None);
    };
    if manifest.workspace_id != *workspace_id
        || manifest.source_store_id != source_store_id
        || manifest.package_id
            != package_id(workspace_id, source_store_id, &summary.snapshot_digest)
        || manifest.snapshot_digest != summary.snapshot_digest
        || manifest.revision_count != summary.revision_count
        || manifest.head_count != summary.head_count
        || manifest.entry_count != summary.entry_count
    {
        return Err(PortableMemoryError::DestinationConflict);
    }
    let status = match validate_package_entries(storage, &manifest, control) {
        Err(PortableMemoryError::Cancelled) => PortableMemoryExportStatus::Cancelled,
        Err(PortableMemoryError::DeadlineExceeded) => PortableMemoryExportStatus::DeadlineExceeded,
        other => {
            let _ = other?;
            PortableMemoryExportStatus::Idempotent
        }
    };
    Ok(Some(export_result(
        status,
        &manifest,
        Some(manifest_digest(&manifest_bytes)),
        None,
    )))
}

fn publisher_for_snapshot<'a>(
    storage: &'a PersistentStorage,
    expected_checkpoint_digest: Option<&MemoryDigest>,
    summary: &SnapshotSummary,
    workspace_id: &WorkspaceMemoryId,
    source_store_id: MemoryStoreId,
) -> Result<PartPublisher<'a>, PortableMemoryError> {
    let checkpoint = load_checkpoint(storage, expected_checkpoint_digest)?;
    let (prior_checkpoint, prior_checkpoint_digest) = match checkpoint {
        Some((checkpoint, _, digest)) => {
            validate_checkpoint(&checkpoint, summary, workspace_id, source_store_id, storage)?;
            (Some(checkpoint), Some(digest))
        }
        None => (None, None),
    };
    let mut publisher = PartPublisher::new(
        storage,
        summary,
        workspace_id.clone(),
        source_store_id,
        prior_checkpoint,
    );
    publisher.checkpoint_digest = prior_checkpoint_digest;
    Ok(publisher)
}

fn publish_snapshot_parts(
    conn: &Connection,
    workspace_id: &WorkspaceMemoryId,
    control: &PortableOperationControl,
    summary: &SnapshotSummary,
    publisher: &mut PartPublisher<'_>,
) -> Result<Option<PortableMemoryExportResult>, PortableMemoryError> {
    let visit_result = MemoryDb::visit_portable_entries_on(conn, workspace_id, control, |entry| {
        if publisher.durability_uncertain {
            return Err(PortableMemoryError::SnapshotChanged);
        }
        publisher.push(entry)
    });
    if matches!(visit_result, Err(PortableMemoryError::Cancelled)) {
        publisher.entries.clear();
        publisher.approximate_payload_bytes = 0;
        publisher.checkpoint_with_status(CheckpointStatus::Cancelled)?;
        return Ok(Some(export_progress_result(
            PortableMemoryExportStatus::Cancelled,
            publisher,
        )));
    }
    if matches!(visit_result, Err(PortableMemoryError::DeadlineExceeded)) {
        publisher.entries.clear();
        publisher.approximate_payload_bytes = 0;
        publisher.checkpoint_with_status(CheckpointStatus::DeadlineExceeded)?;
        return Ok(Some(export_progress_result(
            PortableMemoryExportStatus::DeadlineExceeded,
            publisher,
        )));
    }
    if matches!(visit_result, Err(PortableMemoryError::SnapshotChanged))
        && publisher.durability_uncertain
    {
        return Ok(Some(export_progress_result(
            PortableMemoryExportStatus::DurabilityUncertain,
            publisher,
        )));
    }
    visit_result?;
    publisher.flush()?;
    if publisher.durability_uncertain {
        return Ok(Some(export_progress_result(
            PortableMemoryExportStatus::DurabilityUncertain,
            publisher,
        )));
    }
    if publisher.checkpoint.next_sequence != summary.entry_count
        || publisher.prior_checkpoint.as_ref().is_some_and(|prior| {
            prior.completed_parts.len() != publisher.checkpoint.completed_parts.len()
        })
    {
        return Err(PortableMemoryError::SnapshotChanged);
    }
    Ok(None)
}

fn package_manifest(
    workspace_id: WorkspaceMemoryId,
    source_store_id: MemoryStoreId,
    summary: SnapshotSummary,
    publisher: &PartPublisher<'_>,
) -> Result<TechnicalMemoryPackageManifest, PortableMemoryError> {
    let manifest = TechnicalMemoryPackageManifest {
        schema_version: TECHNICAL_MEMORY_PACKAGE_SCHEMA_VERSION,
        store_schema_version: u32::try_from(super::SCHEMA_VERSION)
            .map_err(|_| PortableMemoryError::UnsupportedSchema)?,
        minimum_reader_version: MINIMUM_PORTABLE_MEMORY_STORE_SCHEMA_VERSION,
        lesson_schema_version: TECHNICAL_LESSON_SCHEMA_VERSION,
        provenance_schema_version: MEMORY_PROVENANCE_SCHEMA_VERSION,
        source_state_schema_version: TECHNICAL_MEMORY_SOURCE_STATE_SCHEMA_VERSION,
        review_audit_schema_version: TECHNICAL_MEMORY_REVIEW_AUDIT_SCHEMA_VERSION,
        package_id: package_id(&workspace_id, source_store_id, &summary.snapshot_digest),
        workspace_id,
        source_store_id,
        snapshot_digest: summary.snapshot_digest,
        revision_count: summary.revision_count,
        head_count: summary.head_count,
        entry_count: summary.entry_count,
        total_part_bytes: publisher.total_part_bytes,
        parts: publisher.checkpoint.completed_parts.clone(),
    };
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn import_result(
    status: PortableMemoryImportStatus,
    manifest: &TechnicalMemoryPackageManifest,
    manifest_digest: MemoryDigest,
) -> PortableMemoryImportResult {
    let (revision_count, head_count) = if matches!(
        status,
        PortableMemoryImportStatus::Cancelled | PortableMemoryImportStatus::DeadlineExceeded
    ) {
        (0, 0)
    } else {
        (manifest.revision_count, manifest.head_count)
    };
    PortableMemoryImportResult {
        schema_version: TECHNICAL_MEMORY_PACKAGE_SCHEMA_VERSION,
        status,
        package_id: manifest.package_id.clone(),
        snapshot_digest: manifest.snapshot_digest.clone(),
        manifest_digest,
        revision_count,
        head_count,
    }
}

impl MemoryDb {
    pub(crate) fn export_technical_memory_package(
        &self,
        request: &PortableMemoryExportRequest<'_>,
    ) -> Result<PortableMemoryExportResult, PortableMemoryError> {
        let workspace_id = self
            .workspace_id
            .clone()
            .ok_or(PortableMemoryError::WrongWorkspace)?;
        let target = canonical_root_target(request.storage)?;
        self.validate_portable_approval(
            request.approval,
            "MemoryExport",
            &target,
            request.arguments,
        )?;

        let source_store_id = self.store_id().map_err(PortableMemoryError::store)?;
        let mut conn = self.lock_conn().map_err(PortableMemoryError::store)?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;
        let summary =
            match Self::portable_snapshot_on(&transaction, &workspace_id, &request.control) {
                Err(PortableMemoryError::Cancelled) => {
                    return Ok(stopped_export_before_snapshot(
                        PortableMemoryExportStatus::Cancelled,
                    ));
                }
                Err(PortableMemoryError::DeadlineExceeded) => {
                    return Ok(stopped_export_before_snapshot(
                        PortableMemoryExportStatus::DeadlineExceeded,
                    ));
                }
                other => other?,
            };
        if let Some(result) = existing_export_result(
            request.storage,
            &workspace_id,
            source_store_id,
            &summary,
            &request.control,
        )? {
            return Ok(result);
        }
        let mut publisher = publisher_for_snapshot(
            request.storage,
            request.expected_checkpoint_digest.as_ref(),
            &summary,
            &workspace_id,
            source_store_id,
        )?;
        if let Some(result) = publish_snapshot_parts(
            &transaction,
            &workspace_id,
            &request.control,
            &summary,
            &mut publisher,
        )? {
            return Ok(result);
        }
        transaction
            .commit()
            .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;
        drop(conn);
        self.finalize_portable_export(request, workspace_id, source_store_id, summary, publisher)
    }

    fn finalize_portable_export(
        &self,
        request: &PortableMemoryExportRequest<'_>,
        workspace_id: WorkspaceMemoryId,
        source_store_id: MemoryStoreId,
        summary: SnapshotSummary,
        mut publisher: PartPublisher<'_>,
    ) -> Result<PortableMemoryExportResult, PortableMemoryError> {
        // The immediate reservation fences another WAL writer between the
        // full snapshot comparison and final-manifest publication.
        let mut final_conn = self.lock_conn().map_err(PortableMemoryError::store)?;
        let final_transaction = final_conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;
        let final_summary =
            match Self::portable_snapshot_on(&final_transaction, &workspace_id, &request.control) {
                Err(PortableMemoryError::Cancelled) => {
                    publisher.checkpoint_with_status(CheckpointStatus::Cancelled)?;
                    return Ok(export_progress_result(
                        PortableMemoryExportStatus::Cancelled,
                        &publisher,
                    ));
                }
                Err(PortableMemoryError::DeadlineExceeded) => {
                    publisher.checkpoint_with_status(CheckpointStatus::DeadlineExceeded)?;
                    return Ok(export_progress_result(
                        PortableMemoryExportStatus::DeadlineExceeded,
                        &publisher,
                    ));
                }
                other => other?,
            };
        if final_summary != summary {
            return Err(PortableMemoryError::SnapshotChanged);
        }
        publisher.checkpoint_with_status(CheckpointStatus::PartsComplete)?;
        if publisher.durability_uncertain {
            return Ok(export_progress_result(
                PortableMemoryExportStatus::DurabilityUncertain,
                &publisher,
            ));
        }
        let manifest = package_manifest(workspace_id, source_store_id, summary, &publisher)?;
        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;
        match request.control.check() {
            Err(PortableMemoryError::Cancelled) => {
                publisher.checkpoint_with_status(CheckpointStatus::Cancelled)?;
                return Ok(export_progress_result(
                    PortableMemoryExportStatus::Cancelled,
                    &publisher,
                ));
            }
            Err(PortableMemoryError::DeadlineExceeded) => {
                publisher.checkpoint_with_status(CheckpointStatus::DeadlineExceeded)?;
                return Ok(export_progress_result(
                    PortableMemoryExportStatus::DeadlineExceeded,
                    &publisher,
                ));
            }
            other => other?,
        }
        let receipt = request.storage.commit(
            Path::new(TECHNICAL_MEMORY_PACKAGE_MANIFEST_NAME),
            PACKAGE_FILE_CLASS,
            StorageGeneration::Missing,
            &manifest_bytes,
        )?;
        if receipt.state() == CommitState::PublishedDurabilityUncertain {
            return Ok(export_result(
                PortableMemoryExportStatus::DurabilityUncertain,
                &manifest,
                Some(manifest_digest(&manifest_bytes)),
                publisher.checkpoint_digest,
            ));
        }
        publisher.checkpoint_with_status(CheckpointStatus::Complete)?;
        let status = if publisher.durability_uncertain {
            PortableMemoryExportStatus::DurabilityUncertain
        } else {
            PortableMemoryExportStatus::Completed
        };
        final_transaction
            .commit()
            .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;
        drop(final_conn);
        Ok(export_result(
            status,
            &manifest,
            Some(manifest_digest(&manifest_bytes)),
            publisher.checkpoint_digest,
        ))
    }

    pub(crate) fn import_technical_memory_package(
        &self,
        request: &PortableMemoryImportRequest<'_>,
    ) -> Result<PortableMemoryImportResult, PortableMemoryError> {
        let workspace_id = self
            .workspace_id
            .clone()
            .ok_or(PortableMemoryError::WrongWorkspace)?;
        let target = canonical_root_target(request.storage)?;
        self.validate_portable_approval(
            request.approval,
            "MemoryImport",
            &target,
            request.arguments,
        )?;
        let (manifest, manifest_bytes) =
            load_manifest(request.storage)?.ok_or(PortableMemoryError::InvalidPackage)?;
        if manifest.workspace_id != workspace_id {
            return Err(PortableMemoryError::WrongWorkspace);
        }
        let manifest_digest = manifest_digest(&manifest_bytes);
        let _ = match validate_package_entries(request.storage, &manifest, &request.control) {
            Err(PortableMemoryError::Cancelled) => {
                return Ok(import_result(
                    PortableMemoryImportStatus::Cancelled,
                    &manifest,
                    manifest_digest,
                ));
            }
            Err(PortableMemoryError::DeadlineExceeded) => {
                return Ok(import_result(
                    PortableMemoryImportStatus::DeadlineExceeded,
                    &manifest,
                    manifest_digest,
                ));
            }
            other => other?,
        };

        let mut conn = self.lock_conn().map_err(PortableMemoryError::store)?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;
        let current = Self::portable_snapshot_on(&transaction, &workspace_id, &request.control);
        let current = match current {
            Err(PortableMemoryError::Cancelled) => {
                return Ok(import_result(
                    PortableMemoryImportStatus::Cancelled,
                    &manifest,
                    manifest_digest,
                ));
            }
            Err(PortableMemoryError::DeadlineExceeded) => {
                return Ok(import_result(
                    PortableMemoryImportStatus::DeadlineExceeded,
                    &manifest,
                    manifest_digest,
                ));
            }
            other => other?,
        };
        if snapshot_matches_manifest(&current, &manifest) {
            return Ok(import_result(
                PortableMemoryImportStatus::Idempotent,
                &manifest,
                manifest_digest,
            ));
        }
        if current.entry_count != 0 {
            return Err(PortableMemoryError::CausalConflict);
        }

        let applied =
            apply_package_entries_on(&transaction, request.storage, &manifest, &request.control);
        if matches!(applied, Err(PortableMemoryError::Cancelled)) {
            return Ok(import_result(
                PortableMemoryImportStatus::Cancelled,
                &manifest,
                manifest_digest,
            ));
        }
        if matches!(applied, Err(PortableMemoryError::DeadlineExceeded)) {
            return Ok(import_result(
                PortableMemoryImportStatus::DeadlineExceeded,
                &manifest,
                manifest_digest,
            ));
        }
        applied?;
        let imported = Self::portable_snapshot_on(&transaction, &workspace_id, &request.control)?;
        if !snapshot_matches_manifest(&imported, &manifest) {
            return Err(PortableMemoryError::SnapshotChanged);
        }
        transaction
            .commit()
            .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;
        drop(conn);
        Ok(import_result(
            PortableMemoryImportStatus::Imported,
            &manifest,
            manifest_digest,
        ))
    }

    fn validate_portable_approval(
        &self,
        approval: &HostApprovalEvidence,
        canonical_tool: &str,
        target: &str,
        arguments: &Value,
    ) -> Result<(), PortableMemoryError> {
        let workspace_digest = self
            .approval_workspace_digest
            .as_deref()
            .ok_or(PortableMemoryError::ApprovalInvalid)?;
        if approval.workspace_digest != workspace_digest
            || !approval.authorizes_exact_host_call(
                canonical_tool,
                "external_mutation",
                None,
                target,
                arguments,
            )
        {
            return Err(PortableMemoryError::ApprovalInvalid);
        }
        Ok(())
    }
}

fn export_progress_result(
    status: PortableMemoryExportStatus,
    publisher: &PartPublisher<'_>,
) -> PortableMemoryExportResult {
    PortableMemoryExportResult {
        schema_version: TECHNICAL_MEMORY_PACKAGE_SCHEMA_VERSION,
        status,
        package_id: Some(publisher.checkpoint.package_id.clone()),
        snapshot_digest: Some(publisher.checkpoint.snapshot_digest.clone()),
        manifest_digest: None,
        checkpoint_digest: publisher.checkpoint_digest.clone(),
        revision_count: publisher.checkpoint.revision_count,
        head_count: publisher.checkpoint.head_count,
        completed_parts: publisher.checkpoint.completed_parts.len(),
        total_part_bytes: publisher.total_part_bytes,
    }
}

fn export_result(
    status: PortableMemoryExportStatus,
    manifest: &TechnicalMemoryPackageManifest,
    manifest_digest: Option<MemoryDigest>,
    checkpoint_digest: Option<MemoryDigest>,
) -> PortableMemoryExportResult {
    PortableMemoryExportResult {
        schema_version: TECHNICAL_MEMORY_PACKAGE_SCHEMA_VERSION,
        status,
        package_id: Some(manifest.package_id.clone()),
        snapshot_digest: Some(manifest.snapshot_digest.clone()),
        manifest_digest,
        checkpoint_digest,
        revision_count: manifest.revision_count,
        head_count: manifest.head_count,
        completed_parts: manifest.parts.len(),
        total_part_bytes: manifest.total_part_bytes,
    }
}

struct PackageStreamValidator<'a> {
    workspace_id: &'a WorkspaceMemoryId,
    permits_multi_parent_revisions: bool,
    lineage: Option<LineageCursor>,
    last_completed_logical_id: Option<LogicalMemoryId>,
    next_sequence: u64,
    revision_count: u64,
    head_count: u64,
    hasher: Sha256,
}

impl<'a> PackageStreamValidator<'a> {
    fn new(workspace_id: &'a WorkspaceMemoryId, minimum_reader_version: u32) -> Self {
        Self {
            workspace_id,
            permits_multi_parent_revisions: minimum_reader_version
                >= MULTI_PARENT_PORTABLE_MEMORY_STORE_SCHEMA_VERSION,
            lineage: None,
            last_completed_logical_id: None,
            next_sequence: 0,
            revision_count: 0,
            head_count: 0,
            hasher: new_snapshot_hasher(workspace_id),
        }
    }

    fn accept(&mut self, envelope: &PortableEntryEnvelope) -> Result<(), PortableMemoryError> {
        if envelope.sequence != self.next_sequence {
            return Err(PortableMemoryError::InvalidPackage);
        }
        let encoded = serde_json::to_vec(envelope)
            .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;
        if encoded.len() > MAX_PACKAGE_ENTRY_BYTES {
            return Err(PortableMemoryError::BudgetExceeded);
        }
        append_digest_field(&mut self.hasher, &encoded);
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(PortableMemoryError::BudgetExceeded)?;

        match &envelope.entry {
            PortableEntry::Revision { revision } => {
                if !self.permits_multi_parent_revisions
                    && !revision.additional_parent_digests.is_empty()
                {
                    return Err(PortableMemoryError::InvalidPackage);
                }
                match &mut self.lineage {
                    None => {
                        if self
                            .last_completed_logical_id
                            .is_some_and(|prior| prior >= revision.logical_id)
                        {
                            return Err(PortableMemoryError::InvalidPackage);
                        }
                        let kind = classify_portable_root(revision, self.workspace_id)?;
                        self.lineage = Some(LineageCursor::from_root(revision, kind));
                    }
                    Some(lineage) if lineage.logical_id == revision.logical_id => {
                        validate_portable_successor(lineage, revision, self.workspace_id)?;
                        lineage
                            .superseded
                            .extend(revision.causal_parent_digests().cloned());
                        lineage
                            .revisions
                            .insert(revision.record_digest.clone(), revision.version);
                    }
                    Some(_) => return Err(PortableMemoryError::InvalidPackage),
                }
                self.revision_count = self
                    .revision_count
                    .checked_add(1)
                    .ok_or(PortableMemoryError::BudgetExceeded)?;
            }
            PortableEntry::Head {
                logical_id,
                record_digest,
            } => {
                let lineage = self
                    .lineage
                    .take()
                    .ok_or(PortableMemoryError::InvalidPackage)?;
                if lineage.logical_id != *logical_id
                    || lineage.sole_unsuperseded_head() != Some(record_digest)
                {
                    return Err(PortableMemoryError::CausalConflict);
                }
                self.last_completed_logical_id = Some(*logical_id);
                self.head_count = self
                    .head_count
                    .checked_add(1)
                    .ok_or(PortableMemoryError::BudgetExceeded)?;
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<SnapshotSummary, PortableMemoryError> {
        if self.lineage.is_some() {
            return Err(PortableMemoryError::InvalidPackage);
        }
        let entry_count = self
            .revision_count
            .checked_add(self.head_count)
            .ok_or(PortableMemoryError::BudgetExceeded)?;
        if entry_count != self.next_sequence || entry_count > MAX_PACKAGE_ENTRIES {
            return Err(PortableMemoryError::InvalidPackage);
        }
        Ok(SnapshotSummary {
            snapshot_digest: finish_snapshot_digest(self.hasher),
            revision_count: self.revision_count,
            head_count: self.head_count,
            entry_count,
        })
    }
}

fn read_validated_part(
    storage: &PersistentStorage,
    manifest: &TechnicalMemoryPackageManifest,
    descriptor: &TechnicalMemoryPackagePartDescriptor,
) -> Result<TechnicalMemoryPackagePart, PortableMemoryError> {
    let (_, bytes) = read_owned_bytes(
        storage,
        Path::new(&descriptor.file_name),
        PACKAGE_FILE_CLASS,
    )?;
    let bytes = bytes.ok_or(PortableMemoryError::InvalidPackage)?;
    if bytes.len() > MAX_PACKAGE_PART_BYTES
        || u64::try_from(bytes.len()).ok() != Some(descriptor.byte_len)
        || MemoryDigest::sha256(&bytes) != descriptor.part_digest
    {
        return Err(PortableMemoryError::InvalidPackage);
    }
    let part = decode_canonical_json::<TechnicalMemoryPackagePart>(&bytes)?;
    let entries_bytes = serde_json::to_vec(&part.entries)
        .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;
    if part.schema_version != TECHNICAL_MEMORY_PACKAGE_SCHEMA_VERSION
        || part.package_id != manifest.package_id
        || part.index != descriptor.index
        || part.first_sequence != descriptor.first_sequence
        || part.last_sequence != descriptor.last_sequence
        || part.previous_part_digest != descriptor.previous_part_digest
        || part.entries_digest != MemoryDigest::sha256(&entries_bytes)
        || u32::try_from(part.entries.len()).ok() != Some(descriptor.entry_count)
        || part.entries.first().map(|entry| entry.sequence) != Some(part.first_sequence)
        || part.entries.last().map(|entry| entry.sequence) != Some(part.last_sequence)
    {
        return Err(PortableMemoryError::InvalidPackage);
    }
    Ok(part)
}

fn validate_package_entries(
    storage: &PersistentStorage,
    manifest: &TechnicalMemoryPackageManifest,
    control: &PortableOperationControl,
) -> Result<SnapshotSummary, PortableMemoryError> {
    validate_manifest(manifest)?;
    let mut validator =
        PackageStreamValidator::new(&manifest.workspace_id, manifest.minimum_reader_version);
    for descriptor in &manifest.parts {
        control.check()?;
        let part = read_validated_part(storage, manifest, descriptor)?;
        for entry in &part.entries {
            control.check()?;
            validator.accept(entry)?;
        }
    }
    let summary = validator.finish()?;
    if summary.snapshot_digest != manifest.snapshot_digest
        || summary.revision_count != manifest.revision_count
        || summary.head_count != manifest.head_count
        || summary.entry_count != manifest.entry_count
    {
        return Err(PortableMemoryError::InvalidPackage);
    }
    Ok(summary)
}

fn apply_package_entries_on(
    conn: &Connection,
    storage: &PersistentStorage,
    manifest: &TechnicalMemoryPackageManifest,
    control: &PortableOperationControl,
) -> Result<(), PortableMemoryError> {
    let mut validator =
        PackageStreamValidator::new(&manifest.workspace_id, manifest.minimum_reader_version);
    for descriptor in &manifest.parts {
        control.check()?;
        let part = read_validated_part(storage, manifest, descriptor)?;
        for envelope in &part.entries {
            control.check()?;
            validator.accept(envelope)?;
            match &envelope.entry {
                PortableEntry::Revision { revision } => {
                    MemoryDb::validate_revision_parent(conn, revision)
                        .map_err(PortableMemoryError::store)?;
                    if !MemoryDb::insert_revision_row(conn, revision)
                        .map_err(PortableMemoryError::store)?
                    {
                        return Err(PortableMemoryError::CausalConflict);
                    }
                }
                PortableEntry::Head {
                    logical_id,
                    record_digest,
                } => {
                    let rows = conn
                        .execute(
                            "INSERT INTO memory_heads (logical_id, record_digest) VALUES (?1, ?2)",
                            params![logical_id.to_string(), record_digest.as_str()],
                        )
                        .map_err(|error| PortableMemoryError::store(anyhow::Error::new(error)))?;
                    if rows != 1
                        || MemoryDb::refresh_projection(conn, *logical_id)
                            .map_err(PortableMemoryError::store)?
                            != 1
                    {
                        return Err(PortableMemoryError::CausalConflict);
                    }
                }
            }
        }
    }
    let summary = validator.finish()?;
    if summary.snapshot_digest != manifest.snapshot_digest
        || summary.revision_count != manifest.revision_count
        || summary.head_count != manifest.head_count
        || summary.entry_count != manifest.entry_count
    {
        return Err(PortableMemoryError::InvalidPackage);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::missing_panics_doc)]
mod tests {
    use super::*;
    use crate::memory::{
        MemoryAttribution, MemoryProvenance, MemorySourceEvidence, MemorySourceKind, MemoryVersion,
        TechnicalLessonDraft,
    };

    fn fixture() -> (tempfile::TempDir, PersistentStorage) {
        let root = tempfile::tempdir().expect("portable package root");
        let canonical = root.path().canonicalize().expect("canonical package root");
        let storage = PersistentStorage::open(canonical).expect("portable package storage");
        (root, storage)
    }

    fn workspace() -> WorkspaceMemoryId {
        serde_json::from_str(
            "\"workspace-sha256:0000000000000000000000000000000000000000000000000000000000000000\"",
        )
        .expect("fixed workspace identity")
    }

    fn store_id() -> MemoryStoreId {
        MemoryStoreId::from_str("00000000-0000-4000-8000-000000000107")
            .expect("fixed store identity")
    }

    fn digest(label: &[u8]) -> MemoryDigest {
        MemoryDigest::for_fields(b"openclaudia.s107.portable-test.v1", &[label])
    }

    fn head(sequence: u64, logical_id: &str, record: &[u8]) -> PortableEntryEnvelope {
        PortableEntryEnvelope {
            sequence,
            entry: PortableEntry::Head {
                logical_id: LogicalMemoryId::from_str(logical_id).expect("fixed logical identity"),
                record_digest: digest(record),
            },
        }
    }

    fn save_lesson(db: &MemoryDb, title: &str, source_id: &str, timestamp: i64) {
        let draft: TechnicalLessonDraft = serde_json::from_value(serde_json::json!({
            "title": title,
            "kind": "compatibility",
            "observation": "A final generation fence rejects a stale portable snapshot.",
            "guidance": "Recompute the typed snapshot under an immediate transaction before publishing the manifest.",
            "applicability": {"paths": ["src/memory/portable.rs"]},
            "citations": [{
                "kind": "test",
                "locator": "src/memory/portable.rs",
                "source_version": "unit:fence",
                "digest": digest(source_id.as_bytes()),
                "line_start": 1,
                "line_end": 1
            }],
            "confidence": "verified_by_test",
            "sensitivity": "internal",
            "retention": {"policy": "indefinite"}
        }))
        .expect("technical lesson draft");
        db.save_technical_lesson_candidate(
            &draft,
            MemorySourceEvidence::new(
                MemorySourceKind::Explicit,
                source_id.to_string(),
                "unit:v1".to_string(),
                digest(source_id.as_bytes()),
            ),
            "s107-test".to_string(),
            timestamp,
        )
        .expect("technical lesson candidate");
    }

    #[test]
    fn checkpoint_resume_republishes_exact_prefix_then_extends_it() {
        let (_root, storage) = fixture();
        let workspace = workspace();
        let store = store_id();
        let summary = SnapshotSummary {
            snapshot_digest: digest(b"snapshot"),
            revision_count: 0,
            head_count: 2,
            entry_count: 2,
        };
        let first_entry = head(0, "00000000-0000-4000-8000-000000000001", b"first");
        let second_entry = head(1, "00000000-0000-4000-8000-000000000002", b"second");

        let mut interrupted =
            PartPublisher::new(&storage, &summary, workspace.clone(), store, None);
        interrupted.push(first_entry.clone()).expect("first entry");
        interrupted.flush().expect("first durable part");
        interrupted
            .checkpoint_with_status(CheckpointStatus::Cancelled)
            .expect("cancelled checkpoint");
        let expected_digest = interrupted
            .checkpoint_digest
            .clone()
            .expect("checkpoint digest");
        let first_descriptor = interrupted.checkpoint.completed_parts[0].clone();
        drop(interrupted);

        let (prior, _, observed) = load_checkpoint(&storage, Some(&expected_digest))
            .expect("load exact checkpoint")
            .expect("checkpoint exists");
        assert_eq!(observed, expected_digest);
        validate_checkpoint(&prior, &summary, &workspace, store, &storage)
            .expect("valid interrupted checkpoint");

        let mut resumed = PartPublisher::new(&storage, &summary, workspace, store, Some(prior));
        resumed.checkpoint_digest = Some(expected_digest.clone());
        resumed.push(first_entry).expect("replayed first entry");
        resumed.flush().expect("reconcile exact first part");
        assert_eq!(resumed.checkpoint.completed_parts, [first_descriptor]);
        assert_eq!(resumed.checkpoint_digest, Some(expected_digest));

        resumed.push(second_entry).expect("new second entry");
        resumed.flush().expect("publish second part");
        assert_eq!(resumed.checkpoint.completed_parts.len(), 2);
        assert_ne!(resumed.checkpoint_digest, None);
        resumed
            .checkpoint_with_status(CheckpointStatus::PartsComplete)
            .expect("parts-complete checkpoint");
        assert_eq!(resumed.checkpoint.next_sequence, summary.entry_count);
        for descriptor in &resumed.checkpoint.completed_parts {
            assert!(descriptor.byte_len <= FileClass::PortableMemoryPackage.max_bytes());
        }
    }

    #[test]
    fn manifest_budgets_and_canonical_json_are_strict() {
        let workspace = workspace();
        let store = store_id();
        let snapshot = digest(b"empty-snapshot");
        let manifest = TechnicalMemoryPackageManifest {
            schema_version: TECHNICAL_MEMORY_PACKAGE_SCHEMA_VERSION,
            store_schema_version: MINIMUM_PORTABLE_MEMORY_STORE_SCHEMA_VERSION,
            minimum_reader_version: MINIMUM_PORTABLE_MEMORY_STORE_SCHEMA_VERSION,
            lesson_schema_version: TECHNICAL_LESSON_SCHEMA_VERSION,
            provenance_schema_version: MEMORY_PROVENANCE_SCHEMA_VERSION,
            source_state_schema_version: TECHNICAL_MEMORY_SOURCE_STATE_SCHEMA_VERSION,
            review_audit_schema_version: TECHNICAL_MEMORY_REVIEW_AUDIT_SCHEMA_VERSION,
            workspace_id: workspace.clone(),
            source_store_id: store,
            package_id: package_id(&workspace, store, &snapshot),
            snapshot_digest: snapshot,
            revision_count: 0,
            head_count: 0,
            entry_count: 0,
            total_part_bytes: 0,
            parts: Vec::new(),
        };
        validate_manifest(&manifest).expect("empty manifest is valid");
        let mut previous_reader = manifest.clone();
        previous_reader.store_schema_version =
            OLDEST_SUPPORTED_PORTABLE_MEMORY_STORE_SCHEMA_VERSION;
        previous_reader.minimum_reader_version =
            OLDEST_SUPPORTED_PORTABLE_MEMORY_STORE_SCHEMA_VERSION;
        validate_manifest(&previous_reader).expect("schema-v6 portable package remains readable");
        let canonical = serde_json::to_vec(&manifest).expect("canonical manifest");
        assert_eq!(
            manifest_digest(&canonical).as_str(),
            "sha256:402f53d475bb34e2ef4b24ac47a0588a6f47614a612cc670af285e0be0817b10"
        );
        assert_eq!(
            u64::try_from(MAX_PACKAGE_PART_BYTES).expect("part budget"),
            FileClass::PortableMemoryPackage.max_bytes()
        );
        assert_eq!(
            decode_canonical_json::<TechnicalMemoryPackageManifest>(&canonical)
                .expect("canonical decode"),
            manifest
        );
        let mut newer_source_store = manifest.clone();
        newer_source_store.store_schema_version = newer_source_store
            .store_schema_version
            .checked_add(1)
            .expect("newer source schema");
        validate_manifest(&newer_source_store)
            .expect("unchanged portable schema is independent of newer internal tables");
        let mut future_reader = newer_source_store;
        future_reader.minimum_reader_version = future_reader.store_schema_version;
        assert!(matches!(
            validate_manifest(&future_reader),
            Err(PortableMemoryError::UnsupportedSchema)
        ));
        let pretty = serde_json::to_vec_pretty(&manifest).expect("pretty manifest");
        assert!(matches!(
            decode_canonical_json::<TechnicalMemoryPackageManifest>(&pretty),
            Err(PortableMemoryError::InvalidPackage)
        ));

        let descriptor = TechnicalMemoryPackagePartDescriptor {
            index: 0,
            file_name: package_part_name(&manifest.package_id, 0).expect("part name"),
            byte_len: 1,
            entry_count: 1,
            first_sequence: 0,
            last_sequence: 0,
            previous_part_digest: None,
            part_digest: digest(b"part"),
        };
        let mut too_many = manifest.clone();
        too_many.revision_count = u64::try_from(MAX_PACKAGE_PARTS + 1).expect("count");
        too_many.entry_count = too_many.revision_count;
        too_many.parts = vec![descriptor.clone(); MAX_PACKAGE_PARTS + 1];
        assert!(matches!(
            validate_manifest(&too_many),
            Err(PortableMemoryError::InvalidPackage)
        ));

        let mut oversized = manifest;
        let mut descriptor = descriptor;
        descriptor.byte_len = FileClass::PortableMemoryPackage.max_bytes() + 1;
        oversized.revision_count = 1;
        oversized.entry_count = 1;
        oversized.total_part_bytes = descriptor.byte_len;
        oversized.parts.push(descriptor);
        assert!(matches!(
            validate_manifest(&oversized),
            Err(PortableMemoryError::InvalidPackage)
        ));
    }

    #[test]
    fn schema_v6_reader_claim_rejects_a_multi_parent_revision() {
        let workspace = workspace();
        let provenance = |label: &str| {
            MemoryProvenance::new(
                MemorySourceEvidence::new(
                    MemorySourceKind::Explicit,
                    format!("portable-reader:{label}"),
                    "unit:v1".to_string(),
                    digest(label.as_bytes()),
                ),
                MemoryAttribution::new(
                    "portable-reader-test".to_string(),
                    Some(store_id()),
                    Some(workspace.to_string()),
                ),
                MemoryRecordScope::UserPrivate,
            )
        };
        let root = MemoryRevision::new("root".to_string(), Vec::new(), provenance("root"));
        let left = root
            .successor("left".to_string(), Vec::new(), provenance("left"))
            .expect("left branch");
        let right = root
            .successor("right".to_string(), Vec::new(), provenance("right"))
            .expect("right branch");
        let merge = MemoryRevision::merge_successor(
            &[left, right],
            "merge".to_string(),
            Vec::new(),
            provenance("merge"),
        )
        .expect("multi-parent revision");
        let entry = PortableEntryEnvelope {
            sequence: 0,
            entry: PortableEntry::Revision {
                revision: Box::new(merge),
            },
        };

        let mut legacy_claim = PackageStreamValidator::new(
            &workspace,
            OLDEST_SUPPORTED_PORTABLE_MEMORY_STORE_SCHEMA_VERSION,
        );
        assert!(matches!(
            legacy_claim.accept(&entry),
            Err(PortableMemoryError::InvalidPackage)
        ));
    }

    #[test]
    fn branching_lineage_requires_one_graph_derived_head() {
        let root = digest(b"root");
        let left = digest(b"left");
        let right = digest(b"right");
        let merge = digest(b"merge");
        let mut lineage = LineageCursor {
            logical_id: LogicalMemoryId::from_str("00000000-0000-4000-8000-000000000108")
                .expect("logical identity"),
            kind: LineageKind::TechnicalLesson,
            revisions: BTreeMap::from([
                (root.clone(), MemoryVersion::INITIAL),
                (left.clone(), MemoryVersion::new(2).expect("version")),
                (right.clone(), MemoryVersion::new(2).expect("version")),
            ]),
            superseded: BTreeSet::from([root]),
        };
        assert!(lineage.sole_unsuperseded_head().is_none());

        lineage
            .revisions
            .insert(merge.clone(), MemoryVersion::new(3).expect("version"));
        lineage.superseded.extend([left, right]);
        assert_eq!(lineage.sole_unsuperseded_head(), Some(&merge));
    }

    #[test]
    fn final_generation_fence_detects_a_writer_after_the_read_snapshot() {
        let host = tempfile::tempdir().expect("host home");
        let workspace_root = tempfile::tempdir().expect("workspace root");
        let first = MemoryDb::open_for_workspace(host.path(), workspace_root.path())
            .expect("first memory handle");
        let second = MemoryDb::open_for_workspace(host.path(), workspace_root.path())
            .expect("second memory handle");
        save_lesson(&first, "Initial portable state", "initial", 1);
        let workspace_id = first.workspace_id().expect("workspace identity").clone();
        let control = PortableOperationControl::new(crate::runtime::CancellationTree::new().root());

        let mut initial_conn = first.lock_conn().expect("initial connection");
        let initial_transaction = initial_conn
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .expect("initial read transaction");
        let initial = MemoryDb::portable_snapshot_on(&initial_transaction, &workspace_id, &control)
            .expect("initial snapshot");
        initial_transaction.commit().expect("finish read snapshot");
        drop(initial_conn);
        save_lesson(&second, "Concurrent portable state", "concurrent", 2);

        let mut final_conn = first.lock_conn().expect("final connection");
        let final_transaction = final_conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("generation-fenced transaction");
        let final_summary =
            MemoryDb::portable_snapshot_on(&final_transaction, &workspace_id, &control)
                .expect("final snapshot");
        final_transaction.commit().expect("finish final snapshot");
        drop(final_conn);
        assert_ne!(initial, final_summary);
    }

    #[test]
    fn expired_work_budget_stops_before_snapshot_identity_is_claimed() {
        let host = tempfile::tempdir().expect("host home");
        let workspace_root = tempfile::tempdir().expect("workspace root");
        let db =
            MemoryDb::open_for_workspace(host.path(), workspace_root.path()).expect("memory store");
        save_lesson(&db, "Deadline-bounded export", "deadline", 1);
        let workspace_id = db.workspace_id().expect("workspace identity").clone();
        let control = PortableOperationControl::with_duration(
            crate::runtime::CancellationTree::new().root(),
            Duration::ZERO,
        );
        let conn = db.lock_conn().expect("memory connection");
        assert!(matches!(
            MemoryDb::portable_snapshot_on(&conn, &workspace_id, &control),
            Err(PortableMemoryError::DeadlineExceeded)
        ));
        let result = stopped_export_before_snapshot(PortableMemoryExportStatus::DeadlineExceeded);
        assert_eq!(result.status, PortableMemoryExportStatus::DeadlineExceeded);
        assert!(result.package_id.is_none() && result.snapshot_digest.is_none());
    }
}
