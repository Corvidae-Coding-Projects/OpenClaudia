//! Causal state and atomic publication for repository technical-memory sources.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::memdir::{EntrypointFile, TechnicalMemoryManifestEntry, MAX_ENTRYPOINT_LESSONS};

use super::{
    technical_lesson_kind_name, ApplyRevisionOutcome, LogicalMemoryId, MemoryAttribution, MemoryDb,
    MemoryDigest, MemoryProvenance, MemoryRecordScope, MemoryRevision, MemoryRevisionState,
    MemorySourceEvidence, MemorySourceKind, MemoryStoreId, TechnicalLesson,
    TechnicalLessonStoreError, WorkspaceMemoryId, MAX_TECHNICAL_LESSONS_PER_STORE,
    TECHNICAL_LESSON_TAG,
};

/// Exact tag for the non-model-facing source lifecycle record.
pub const TECHNICAL_MEMORY_SOURCE_TAG: &str = "openclaudia:technical-memory-source:v1";
/// Exact source-state payload schema.
pub const TECHNICAL_MEMORY_SOURCE_STATE_SCHEMA_VERSION: u32 = 1;
// The lifecycle can retain 512 maximally sized 96-byte lesson identities. Keep
// the encoded-state ceiling large enough for that advertised identity budget
// while remaining below the manifest's own 512 KiB admission ceiling.
const MAX_SOURCE_STATE_BYTES: usize = 256 * 1024;
const MAX_SOURCE_LIFECYCLE_MEMBERS: usize = 512;
const MAX_SOURCE_REVIEW_LINEAGE_REVISIONS: usize = 4_096;

/// Whether the tracked manifest currently exists in the workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnicalMemorySourcePresence {
    Active,
    Missing,
}

/// Exact current lesson head owned by one active source generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicalMemorySourceMember {
    pub lesson_id: String,
    pub logical_id: LogicalMemoryId,
    pub record_digest: MemoryDigest,
}

/// Strict persisted source projection. Removed lesson identities remain in the
/// immutable revision graph but are absent from this current membership set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicalMemorySourceState {
    pub schema_version: u32,
    pub workspace_id: WorkspaceMemoryId,
    pub source_id: String,
    pub relative_path: String,
    pub source_generation: u64,
    pub source_digest: MemoryDigest,
    pub presence: TechnicalMemorySourcePresence,
    pub members: Vec<TechnicalMemorySourceMember>,
    /// Exact tombstone heads retained so status and later restoration can
    /// verify deleted source-owned identities rather than forgetting them.
    pub retired_members: Vec<TechnicalMemorySourceMember>,
    pub published_at_unix_seconds: i64,
}

/// Read-only store view returned by `memory_source_status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TechnicalMemorySourceStoreStatus {
    Unconfigured,
    Ready {
        state_record_digest: MemoryDigest,
        state: TechnicalMemorySourceState,
    },
    Conflict {
        source_records: usize,
        causal_heads: usize,
    },
}

/// Successful atomic refresh outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnicalMemoryRefreshStatus {
    Imported,
    Updated,
    Renamed,
    Pruned,
    Unchanged,
    Missing,
    PruneRequired,
}

/// Bounded structured result of one refresh request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicalMemoryRefreshResult {
    pub schema_version: u32,
    pub status: TechnicalMemoryRefreshStatus,
    pub source_id: Option<String>,
    pub relative_path: Option<String>,
    pub source_generation: Option<u64>,
    pub source_digest: Option<MemoryDigest>,
    pub state_record_digest: Option<MemoryDigest>,
    pub created: usize,
    pub updated: usize,
    pub restored: usize,
    pub deleted: usize,
    pub unchanged: usize,
    pub removals_requiring_confirmation: Vec<String>,
}

impl TechnicalMemoryRefreshResult {
    const fn without_source(status: TechnicalMemoryRefreshStatus) -> Self {
        Self {
            schema_version: TECHNICAL_MEMORY_SOURCE_STATE_SCHEMA_VERSION,
            status,
            source_id: None,
            relative_path: None,
            source_generation: None,
            source_digest: None,
            state_record_digest: None,
            created: 0,
            updated: 0,
            restored: 0,
            deleted: 0,
            unchanged: 0,
            removals_requiring_confirmation: Vec::new(),
        }
    }
}

/// Inputs already admitted by the tool/capability boundary.
pub struct TechnicalMemoryRefreshRequest<'a> {
    pub source: Option<&'a EntrypointFile>,
    pub expected_source_digest: Option<MemoryDigest>,
    pub prune_missing: bool,
    pub author_id: String,
    pub captured_at_unix_seconds: i64,
}

/// Typed optimistic-concurrency and ownership failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TechnicalMemorySourceStoreError {
    #[error("technical-memory source refresh requires the current expected digest")]
    ExpectedDigestRequired,
    #[error("technical-memory source expected digest is stale")]
    StaleSource,
    #[error("technical-memory source identity conflicts with the tracked source")]
    SourceIdentityConflict,
    #[error("technical-memory source generation regressed")]
    GenerationRegression,
    #[error("technical-memory source bytes changed without a generation increment")]
    GenerationCollision,
    #[error("technical-memory source or member has conflicting causal state")]
    CausalConflict,
    #[error("technical-memory source supplied an expected digest before initial import")]
    UnexpectedExpectedDigest,
}

struct StoredSource {
    state: TechnicalMemorySourceState,
    revision: MemoryRevision,
}

/// Coherent source membership captured before a host-review transaction moves
/// the member head. Keeping this opaque outside the source module prevents the
/// review path from constructing or partially updating source state itself.
pub(super) struct PreparedSourceMemberReview {
    source: StoredSource,
    member_index: usize,
}

#[derive(Clone, Copy, Default)]
struct RefreshCounts {
    created: usize,
    updated: usize,
    restored: usize,
    deleted: usize,
    unchanged: usize,
}

struct SourceMemberSets {
    active: BTreeMap<String, TechnicalMemorySourceMember>,
    retired: BTreeMap<String, TechnicalMemorySourceMember>,
}

struct ReconciledSourceMembers {
    active: Vec<TechnicalMemorySourceMember>,
    retired: Vec<TechnicalMemorySourceMember>,
    counts: RefreshCounts,
}

impl MemoryDb {
    /// Inspect the exact persisted technical-memory source state.
    ///
    /// # Errors
    ///
    /// Returns an error for corrupt source payloads, wrong-workspace data, or
    /// database failures. Concurrent source/member heads are represented by
    /// the typed [`TechnicalMemorySourceStoreStatus::Conflict`] outcome.
    pub fn technical_memory_source_status(&self) -> Result<TechnicalMemorySourceStoreStatus> {
        let workspace_id = self
            .workspace_id
            .as_ref()
            .context("technical-memory sources require a workspace-bound store")?;
        Self::technical_memory_source_status_on(&*self.lock_conn()?, workspace_id)
    }

    pub(super) fn technical_memory_source_status_on(
        conn: &Connection,
        workspace_id: &WorkspaceMemoryId,
    ) -> Result<TechnicalMemorySourceStoreStatus> {
        let rows = Self::memory_search_by_tag_on(conn, TECHNICAL_MEMORY_SOURCE_TAG, 2)?;
        if rows.is_empty() {
            return Ok(TechnicalMemorySourceStoreStatus::Unconfigured);
        }
        if rows.len() != 1 {
            return Ok(TechnicalMemorySourceStoreStatus::Conflict {
                source_records: rows.len(),
                causal_heads: rows.iter().map(|row| row.conflict_heads.len().max(1)).sum(),
            });
        }
        let row = &rows[0];
        if !row.conflict_heads.is_empty() {
            return Ok(TechnicalMemorySourceStoreStatus::Conflict {
                source_records: 1,
                causal_heads: row.conflict_heads.len(),
            });
        }
        let stored = Self::decode_stored_source_on(conn, row, workspace_id)?;
        if !Self::source_members_match_heads_on(conn, &stored.state, workspace_id)? {
            return Ok(TechnicalMemorySourceStoreStatus::Conflict {
                source_records: 1,
                causal_heads: 1,
            });
        }
        Ok(TechnicalMemorySourceStoreStatus::Ready {
            state_record_digest: stored.revision.record_digest,
            state: stored.state,
        })
    }

    /// Publish a verified source snapshot and every linked lesson mutation in
    /// one immediate transaction.
    pub(crate) fn refresh_technical_memory_source(
        &self,
        request: &TechnicalMemoryRefreshRequest<'_>,
    ) -> Result<TechnicalMemoryRefreshResult> {
        anyhow::ensure!(
            request.captured_at_unix_seconds >= 0,
            "technical-memory refresh timestamp is invalid"
        );
        let workspace_id = self
            .workspace_id
            .clone()
            .context("technical-memory sources require a workspace-bound store")?;
        Self::refresh_technical_memory_source_on(&mut *self.lock_conn()?, &workspace_id, request)
    }

    fn refresh_technical_memory_source_on(
        conn: &mut Connection,
        workspace_id: &WorkspaceMemoryId,
        request: &TechnicalMemoryRefreshRequest<'_>,
    ) -> Result<TechnicalMemoryRefreshResult> {
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .context("technical-memory source: failed to begin refresh transaction")?;
        let current = Self::load_single_stored_source_on(&tx, workspace_id)?;
        let outcome = match request.source {
            Some(source) => Self::refresh_present_source_on(
                &tx,
                workspace_id,
                current.as_ref(),
                source,
                request,
            )?,
            None => Self::refresh_missing_source_on(&tx, workspace_id, current.as_ref(), request)?,
        };
        if matches!(
            outcome.status,
            TechnicalMemoryRefreshStatus::Missing
                | TechnicalMemoryRefreshStatus::PruneRequired
                | TechnicalMemoryRefreshStatus::Unchanged
        ) {
            return Ok(outcome);
        }
        tx.commit()
            .context("technical-memory source: committing atomic refresh")?;
        Ok(outcome)
    }

    fn refresh_present_source_on(
        conn: &Connection,
        workspace_id: &WorkspaceMemoryId,
        current: Option<&StoredSource>,
        source: &EntrypointFile,
        request: &TechnicalMemoryRefreshRequest<'_>,
    ) -> Result<TechnicalMemoryRefreshResult> {
        Self::validate_refresh_precondition(
            current,
            source,
            request.expected_source_digest.as_ref(),
        )?;
        let store_id = Self::store_id_on(conn)?;
        let member_sets = Self::source_member_sets(current);
        let removals = Self::validate_source_member_budget(&member_sets, source)?;
        Self::validate_store_capacity_for_source_on(conn, current, source)?;
        if !removals.is_empty() && !request.prune_missing {
            return Ok(Self::source_prune_required_result(
                source, current, removals,
            ));
        }
        let reconciled = Self::reconcile_present_source_members_on(
            conn,
            workspace_id,
            store_id,
            source,
            request,
            member_sets,
        )?;
        if Self::present_refresh_is_unchanged(current, source, &reconciled) {
            return Ok(Self::result_for_stored(
                TechnicalMemoryRefreshStatus::Unchanged,
                current.context("unchanged source has no stored state")?,
                reconciled.counts,
            ));
        }
        Self::publish_present_source_on(
            conn,
            workspace_id,
            current,
            source,
            request,
            store_id,
            reconciled,
        )
    }

    fn source_member_sets(current: Option<&StoredSource>) -> SourceMemberSets {
        let active = current.map_or_else(BTreeMap::new, |stored| {
            stored
                .state
                .members
                .iter()
                .map(|member| (member.lesson_id.clone(), member.clone()))
                .collect()
        });
        let retired = current.map_or_else(BTreeMap::new, |stored| {
            stored
                .state
                .retired_members
                .iter()
                .map(|member| (member.lesson_id.clone(), member.clone()))
                .collect()
        });
        SourceMemberSets { active, retired }
    }

    fn validate_source_member_budget(
        member_sets: &SourceMemberSets,
        source: &EntrypointFile,
    ) -> Result<Vec<String>> {
        let desired_ids = source
            .manifest
            .lessons
            .iter()
            .map(|entry| entry.lesson_id.as_str())
            .collect::<BTreeSet<_>>();
        let known_identity_count = member_sets
            .active
            .keys()
            .chain(member_sets.retired.keys())
            .map(String::as_str)
            .chain(desired_ids.iter().copied())
            .collect::<BTreeSet<_>>()
            .len();
        anyhow::ensure!(
            known_identity_count <= MAX_SOURCE_LIFECYCLE_MEMBERS,
            "technical-memory source lifecycle exceeds its identity budget"
        );
        Ok(member_sets
            .active
            .keys()
            .filter(|lesson_id| !desired_ids.contains(lesson_id.as_str()))
            .cloned()
            .collect())
    }

    fn validate_store_capacity_for_source_on(
        conn: &Connection,
        current: Option<&StoredSource>,
        source: &EntrypointFile,
    ) -> Result<()> {
        let active_count: i64 = conn.query_row(
            r"SELECT COUNT(*)
                FROM archival_memory am
                JOIN archival_memory_tags amt ON amt.memory_id = am.id
               WHERE amt.tag = ?1
                 AND am.record_state != 'tombstone'",
            params![TECHNICAL_LESSON_TAG],
            |row| row.get(0),
        )?;
        let active_count = usize::try_from(active_count)
            .context("technical-memory source: active lesson count is invalid")?;
        let tracked_active = current.map_or(0, |stored| stored.state.members.len());
        let projected = projected_active_lesson_count(
            active_count,
            tracked_active,
            source.manifest.lessons.len(),
        )
        .context("technical-memory source: active lesson count is inconsistent")?;
        anyhow::ensure!(
            projected <= MAX_TECHNICAL_LESSONS_PER_STORE,
            "technical-memory source refresh exceeds the active lesson store budget"
        );
        Ok(())
    }

    fn reconcile_present_source_members_on(
        conn: &Connection,
        workspace_id: &WorkspaceMemoryId,
        store_id: MemoryStoreId,
        source: &EntrypointFile,
        request: &TechnicalMemoryRefreshRequest<'_>,
        member_sets: SourceMemberSets,
    ) -> Result<ReconciledSourceMembers> {
        let SourceMemberSets {
            active: mut prior_members,
            retired: mut retired_members,
        } = member_sets;
        let mut counts = RefreshCounts::default();
        let mut next_members = Vec::with_capacity(source.manifest.lessons.len());
        for entry in &source.manifest.lessons {
            let prior = prior_members
                .remove(&entry.lesson_id)
                .or_else(|| retired_members.remove(&entry.lesson_id));
            let member = Self::upsert_source_member_on(
                conn,
                workspace_id,
                store_id,
                source,
                entry,
                prior.as_ref(),
                request,
                &mut counts,
            )?;
            next_members.push(member);
        }
        for (lesson_id, prior) in prior_members {
            let retired = Self::delete_source_member_on(
                conn,
                workspace_id,
                store_id,
                source,
                &lesson_id,
                &prior,
                request,
            )?;
            retired_members.insert(lesson_id, retired);
            counts.deleted += 1;
        }
        Ok(ReconciledSourceMembers {
            active: next_members,
            retired: retired_members.into_values().collect(),
            counts,
        })
    }

    fn present_refresh_is_unchanged(
        current: Option<&StoredSource>,
        source: &EntrypointFile,
        reconciled: &ReconciledSourceMembers,
    ) -> bool {
        current.is_some_and(|current| {
            let exactly_current = current.state.presence == TechnicalMemorySourcePresence::Active
                && current.state.source_digest == source.source_digest
                && current.state.source_generation == source.manifest.generation
                && current.state.relative_path == source.relative_path;
            let counts = reconciled.counts;
            exactly_current
                && counts.created == 0
                && counts.updated == 0
                && counts.restored == 0
                && counts.deleted == 0
                && counts.unchanged == source.manifest.lessons.len()
        })
    }

    fn publish_present_source_on(
        conn: &Connection,
        workspace_id: &WorkspaceMemoryId,
        current: Option<&StoredSource>,
        source: &EntrypointFile,
        request: &TechnicalMemoryRefreshRequest<'_>,
        store_id: MemoryStoreId,
        reconciled: ReconciledSourceMembers,
    ) -> Result<TechnicalMemoryRefreshResult> {
        let counts = reconciled.counts;
        let state = TechnicalMemorySourceState {
            schema_version: TECHNICAL_MEMORY_SOURCE_STATE_SCHEMA_VERSION,
            workspace_id: workspace_id.clone(),
            source_id: source.manifest.source_id.clone(),
            relative_path: source.relative_path.clone(),
            source_generation: source.manifest.generation,
            source_digest: source.source_digest.clone(),
            presence: TechnicalMemorySourcePresence::Active,
            members: reconciled.active,
            retired_members: reconciled.retired,
            published_at_unix_seconds: request.captured_at_unix_seconds,
        };
        let state_revision = Self::publish_source_state_on(
            conn,
            current,
            &state,
            store_id,
            request.author_id.clone(),
            source.source_digest.clone(),
            format!("generation:{}", source.manifest.generation),
        )?;
        let status = Self::present_refresh_status(current, source, counts);
        Ok(Self::result_for_source(
            status,
            source,
            Some(state_revision.record_digest),
            counts,
        ))
    }

    fn present_refresh_status(
        current: Option<&StoredSource>,
        source: &EntrypointFile,
        counts: RefreshCounts,
    ) -> TechnicalMemoryRefreshStatus {
        if current.is_none() {
            TechnicalMemoryRefreshStatus::Imported
        } else if current.is_some_and(|stored| stored.state.relative_path != source.relative_path)
            && counts.created == 0
            && counts.updated == 0
            && counts.restored == 0
            && counts.deleted == 0
        {
            TechnicalMemoryRefreshStatus::Renamed
        } else if counts.deleted > 0 {
            TechnicalMemoryRefreshStatus::Pruned
        } else {
            TechnicalMemoryRefreshStatus::Updated
        }
    }

    fn source_prune_required_result(
        source: &EntrypointFile,
        current: Option<&StoredSource>,
        removals: Vec<String>,
    ) -> TechnicalMemoryRefreshResult {
        let mut result = Self::result_for_source(
            TechnicalMemoryRefreshStatus::PruneRequired,
            source,
            current.map(|stored| stored.revision.record_digest.clone()),
            RefreshCounts::default(),
        );
        result.removals_requiring_confirmation = removals;
        result
    }

    fn refresh_missing_source_on(
        conn: &Connection,
        workspace_id: &WorkspaceMemoryId,
        current: Option<&StoredSource>,
        request: &TechnicalMemoryRefreshRequest<'_>,
    ) -> Result<TechnicalMemoryRefreshResult> {
        let Some(current) = current else {
            if request.expected_source_digest.is_some() {
                return Err(TechnicalMemorySourceStoreError::UnexpectedExpectedDigest.into());
            }
            return Ok(TechnicalMemoryRefreshResult::without_source(
                TechnicalMemoryRefreshStatus::Missing,
            ));
        };
        Self::require_expected_digest(current, request.expected_source_digest.as_ref())?;
        if current.state.presence == TechnicalMemorySourcePresence::Missing {
            return Ok(Self::result_for_stored(
                TechnicalMemoryRefreshStatus::Unchanged,
                current,
                RefreshCounts::default(),
            ));
        }
        if !request.prune_missing {
            let mut result = Self::result_for_stored(
                TechnicalMemoryRefreshStatus::PruneRequired,
                current,
                RefreshCounts::default(),
            );
            result.removals_requiring_confirmation = current
                .state
                .members
                .iter()
                .map(|member| member.lesson_id.clone())
                .collect();
            return Ok(result);
        }
        Self::prune_missing_source_on(conn, workspace_id, current, request)
    }

    fn prune_missing_source_on(
        conn: &Connection,
        workspace_id: &WorkspaceMemoryId,
        current: &StoredSource,
        request: &TechnicalMemoryRefreshRequest<'_>,
    ) -> Result<TechnicalMemoryRefreshResult> {
        let store_id = Self::store_id_on(conn)?;
        let missing_digest = MemoryDigest::for_fields(
            b"openclaudia.technical-memory.source-missing.v1",
            &[current.state.source_digest.as_str().as_bytes()],
        );
        let mut retired_members = current
            .state
            .retired_members
            .iter()
            .map(|member| (member.lesson_id.clone(), member.clone()))
            .collect::<BTreeMap<_, _>>();
        for member in &current.state.members {
            let retired = Self::delete_member_with_evidence_on(
                conn,
                workspace_id,
                store_id,
                &current.state.source_id,
                &member.lesson_id,
                member,
                request,
                missing_digest.clone(),
                format!("missing:generation:{}", current.state.source_generation),
            )?;
            retired_members.insert(member.lesson_id.clone(), retired);
        }
        let state = TechnicalMemorySourceState {
            schema_version: TECHNICAL_MEMORY_SOURCE_STATE_SCHEMA_VERSION,
            workspace_id: workspace_id.clone(),
            source_id: current.state.source_id.clone(),
            relative_path: current.state.relative_path.clone(),
            source_generation: current.state.source_generation,
            source_digest: current.state.source_digest.clone(),
            presence: TechnicalMemorySourcePresence::Missing,
            members: Vec::new(),
            retired_members: retired_members.into_values().collect(),
            published_at_unix_seconds: request.captured_at_unix_seconds,
        };
        let state_revision = Self::publish_source_state_on(
            conn,
            Some(current),
            &state,
            store_id,
            request.author_id.clone(),
            missing_digest,
            format!("missing:generation:{}", current.state.source_generation),
        )?;
        Ok(TechnicalMemoryRefreshResult {
            schema_version: TECHNICAL_MEMORY_SOURCE_STATE_SCHEMA_VERSION,
            status: TechnicalMemoryRefreshStatus::Pruned,
            source_id: Some(current.state.source_id.clone()),
            relative_path: Some(current.state.relative_path.clone()),
            source_generation: Some(current.state.source_generation),
            source_digest: Some(current.state.source_digest.clone()),
            state_record_digest: Some(state_revision.record_digest),
            created: 0,
            updated: 0,
            restored: 0,
            deleted: current.state.members.len(),
            unchanged: 0,
            removals_requiring_confirmation: Vec::new(),
        })
    }

    fn validate_refresh_precondition(
        current: Option<&StoredSource>,
        source: &EntrypointFile,
        expected: Option<&MemoryDigest>,
    ) -> Result<()> {
        let Some(current) = current else {
            if expected.is_some() {
                return Err(TechnicalMemorySourceStoreError::UnexpectedExpectedDigest.into());
            }
            return Ok(());
        };
        if current.state.source_id != source.manifest.source_id {
            return Err(TechnicalMemorySourceStoreError::SourceIdentityConflict.into());
        }
        let exactly_current = current.state.presence == TechnicalMemorySourcePresence::Active
            && current.state.source_digest == source.source_digest
            && current.state.source_generation == source.manifest.generation
            && current.state.relative_path == source.relative_path;
        // Replaying an already-published snapshot is read-only and therefore
        // remains idempotent even when the caller carries the predecessor's
        // compare-and-swap token from a concurrent identical request.
        if exactly_current {
            return Ok(());
        }
        Self::require_expected_digest(current, expected)?;
        if source.manifest.generation < current.state.source_generation {
            return Err(TechnicalMemorySourceStoreError::GenerationRegression.into());
        }
        if source.manifest.generation == current.state.source_generation
            && source.source_digest != current.state.source_digest
        {
            return Err(TechnicalMemorySourceStoreError::GenerationCollision.into());
        }
        if current.state.presence == TechnicalMemorySourcePresence::Missing
            && source.manifest.generation <= current.state.source_generation
        {
            return Err(TechnicalMemorySourceStoreError::GenerationRegression.into());
        }
        Ok(())
    }

    fn require_expected_digest(
        current: &StoredSource,
        expected: Option<&MemoryDigest>,
    ) -> Result<()> {
        let expected = expected.ok_or(TechnicalMemorySourceStoreError::ExpectedDigestRequired)?;
        if expected != &current.state.source_digest {
            return Err(TechnicalMemorySourceStoreError::StaleSource.into());
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn upsert_source_member_on(
        conn: &Connection,
        workspace_id: &WorkspaceMemoryId,
        store_id: MemoryStoreId,
        source: &EntrypointFile,
        entry: &TechnicalMemoryManifestEntry,
        prior: Option<&TechnicalMemorySourceMember>,
        request: &TechnicalMemoryRefreshRequest<'_>,
        counts: &mut RefreshCounts,
    ) -> Result<TechnicalMemorySourceMember> {
        let logical_id =
            source_member_logical_id(workspace_id, &source.manifest.source_id, &entry.lesson_id);
        if prior.is_some_and(|member| member.logical_id != logical_id) {
            return Err(TechnicalMemorySourceStoreError::CausalConflict.into());
        }
        let heads = Self::head_digests(conn, logical_id)?;
        if heads.len() > 1 {
            return Err(TechnicalMemorySourceStoreError::CausalConflict.into());
        }
        let current = heads
            .first()
            .map(|digest| {
                Self::load_revision_by_digest(conn, digest)?
                    .context("technical-memory member head is missing")
            })
            .transpose()?;
        if let Some(prior) = prior {
            if heads.as_slice() != [prior.record_digest.clone()] {
                return Err(TechnicalMemorySourceStoreError::CausalConflict.into());
            }
        }
        let evidence = source_member_evidence(source, entry)?;
        let provenance =
            imported_provenance(evidence, store_id, workspace_id, request.author_id.clone());
        if prior.is_none() && current.is_some() {
            return Err(TechnicalMemorySourceStoreError::CausalConflict.into());
        }
        let record_digest = match current {
            None => {
                let lesson = TechnicalLesson::from_candidate(
                    workspace_id.clone(),
                    entry.lesson.clone(),
                    request.captured_at_unix_seconds,
                )?;
                let revision = MemoryRevision::new_with_logical_id(
                    logical_id,
                    lesson.encode()?,
                    lesson_tags(lesson.kind),
                    provenance,
                );
                Self::apply_root_revision_in_transaction(conn, &revision)?;
                counts.created += 1;
                revision.record_digest
            }
            Some(current) if current.state == MemoryRevisionState::Tombstone => {
                let lesson = TechnicalLesson::restored(
                    workspace_id.clone(),
                    entry.lesson.clone(),
                    current.record_digest.clone(),
                    "restored by a newer technical-memory source generation".to_string(),
                    request.captured_at_unix_seconds,
                )?;
                let revision =
                    current.successor(lesson.encode()?, lesson_tags(lesson.kind), provenance)?;
                Self::apply_linear_revision_in_transaction(
                    conn,
                    &revision,
                    &current.record_digest,
                )?;
                counts.restored += 1;
                revision.record_digest
            }
            Some(current) => {
                Self::validate_technical_lesson_revision(&current, workspace_id)?;
                let previous = TechnicalLesson::decode(&current.content)?;
                if previous.draft() == entry.lesson {
                    counts.unchanged += 1;
                    current.record_digest
                } else {
                    let lesson = previous.corrected(
                        entry.lesson.clone(),
                        current.record_digest.clone(),
                        "refreshed from a newer technical-memory source generation".to_string(),
                        request.captured_at_unix_seconds,
                    )?;
                    let revision = current.successor(
                        lesson.encode()?,
                        lesson_tags(lesson.kind),
                        provenance,
                    )?;
                    Self::apply_linear_revision_in_transaction(
                        conn,
                        &revision,
                        &current.record_digest,
                    )?;
                    counts.updated += 1;
                    revision.record_digest
                }
            }
        };
        Ok(TechnicalMemorySourceMember {
            lesson_id: entry.lesson_id.clone(),
            logical_id,
            record_digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn delete_source_member_on(
        conn: &Connection,
        workspace_id: &WorkspaceMemoryId,
        store_id: MemoryStoreId,
        source: &EntrypointFile,
        lesson_id: &str,
        prior: &TechnicalMemorySourceMember,
        request: &TechnicalMemoryRefreshRequest<'_>,
    ) -> Result<TechnicalMemorySourceMember> {
        Self::delete_member_with_evidence_on(
            conn,
            workspace_id,
            store_id,
            &source.manifest.source_id,
            lesson_id,
            prior,
            request,
            source.source_digest.clone(),
            format!("generation:{}:removed", source.manifest.generation),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn delete_member_with_evidence_on(
        conn: &Connection,
        workspace_id: &WorkspaceMemoryId,
        store_id: MemoryStoreId,
        source_id: &str,
        lesson_id: &str,
        prior: &TechnicalMemorySourceMember,
        request: &TechnicalMemoryRefreshRequest<'_>,
        source_digest: MemoryDigest,
        source_version: String,
    ) -> Result<TechnicalMemorySourceMember> {
        let expected_id = source_member_logical_id(workspace_id, source_id, lesson_id);
        if prior.logical_id != expected_id {
            return Err(TechnicalMemorySourceStoreError::CausalConflict.into());
        }
        let heads = Self::head_digests(conn, prior.logical_id)?;
        if heads.as_slice() != [prior.record_digest.clone()] {
            return Err(TechnicalMemorySourceStoreError::CausalConflict.into());
        }
        let current = Self::load_revision_by_digest(conn, &prior.record_digest)?
            .context("technical-memory member head is missing")?;
        Self::validate_technical_lesson_revision(&current, workspace_id)?;
        let provenance = imported_provenance(
            MemorySourceEvidence::new(
                MemorySourceKind::Imported,
                source_member_source_id(source_id, lesson_id),
                source_version,
                source_digest,
            ),
            store_id,
            workspace_id,
            request.author_id.clone(),
        );
        let tombstone = current.tombstone(provenance)?;
        let outcome =
            Self::apply_linear_revision_in_transaction(conn, &tombstone, &current.record_digest)?;
        if !matches!(
            outcome,
            ApplyRevisionOutcome::Advanced | ApplyRevisionOutcome::Idempotent
        ) {
            return Err(TechnicalLessonStoreError::ConcurrentMutation.into());
        }
        Ok(TechnicalMemorySourceMember {
            lesson_id: lesson_id.to_string(),
            logical_id: prior.logical_id,
            record_digest: tombstone.record_digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_source_state_on(
        conn: &Connection,
        current: Option<&StoredSource>,
        state: &TechnicalMemorySourceState,
        store_id: MemoryStoreId,
        author_id: String,
        evidence_digest: MemoryDigest,
        evidence_version: String,
    ) -> Result<MemoryRevision> {
        state.validate()?;
        let content = serde_json::to_string(state)?;
        anyhow::ensure!(
            content.len() <= MAX_SOURCE_STATE_BYTES,
            "technical-memory source state exceeds its byte budget"
        );
        let provenance = imported_provenance(
            MemorySourceEvidence::new(
                MemorySourceKind::Imported,
                source_state_source_id(&state.source_id),
                evidence_version,
                evidence_digest,
            ),
            store_id,
            &state.workspace_id,
            author_id,
        );
        let tags = vec![TECHNICAL_MEMORY_SOURCE_TAG.to_string()];
        let revision = match current {
            Some(current) => current.revision.successor(content, tags, provenance)?,
            None => MemoryRevision::new_with_logical_id(
                source_state_logical_id(&state.workspace_id, &state.source_id),
                content,
                tags,
                provenance,
            ),
        };
        match current {
            Some(current) => {
                Self::apply_linear_revision_in_transaction(
                    conn,
                    &revision,
                    &current.revision.record_digest,
                )?;
            }
            None => Self::apply_root_revision_in_transaction(conn, &revision)?,
        }
        Ok(revision)
    }

    pub(super) fn apply_root_revision_in_transaction(
        conn: &Connection,
        revision: &MemoryRevision,
    ) -> Result<()> {
        revision.validate()?;
        if !Self::head_digests(conn, revision.logical_id)?.is_empty()
            || Self::load_revision_by_digest(conn, &revision.record_digest)?.is_some()
        {
            return Err(TechnicalMemorySourceStoreError::CausalConflict.into());
        }
        anyhow::ensure!(
            Self::insert_revision_row(conn, revision)?,
            "technical-memory root revision was not inserted"
        );
        conn.execute(
            "INSERT INTO memory_heads (logical_id, record_digest) VALUES (?1, ?2)",
            params![
                revision.logical_id.to_string(),
                revision.record_digest.as_str()
            ],
        )?;
        anyhow::ensure!(
            Self::refresh_projection(conn, revision.logical_id)? == 1,
            "technical-memory root did not retain one causal head"
        );
        Ok(())
    }

    fn load_single_stored_source_on(
        conn: &Connection,
        workspace_id: &WorkspaceMemoryId,
    ) -> Result<Option<StoredSource>> {
        let rows = Self::memory_search_by_tag_on(conn, TECHNICAL_MEMORY_SOURCE_TAG, 2)?;
        if rows.len() > 1
            || rows
                .first()
                .is_some_and(|row| !row.conflict_heads.is_empty())
        {
            return Err(TechnicalMemorySourceStoreError::CausalConflict.into());
        }
        let stored = rows
            .first()
            .map(|row| Self::decode_stored_source_on(conn, row, workspace_id))
            .transpose()?;
        if let Some(stored) = &stored {
            if !Self::source_members_match_heads_on(conn, &stored.state, workspace_id)? {
                return Err(TechnicalMemorySourceStoreError::CausalConflict.into());
            }
        }
        Ok(stored)
    }

    /// Capture the exact source membership, if any, before a host review moves
    /// the lesson head. A conflicting source projection rejects the review
    /// before any lesson or audit record is written.
    pub(super) fn prepare_source_member_review_on(
        conn: &Connection,
        workspace_id: &WorkspaceMemoryId,
        current: &MemoryRevision,
    ) -> Result<Option<PreparedSourceMemberReview>> {
        let rows = Self::memory_search_by_tag_on(conn, TECHNICAL_MEMORY_SOURCE_TAG, 2)?;
        if rows.is_empty() {
            return Ok(None);
        }
        if rows.len() != 1 || !rows[0].conflict_heads.is_empty() {
            return Err(TechnicalMemorySourceStoreError::CausalConflict.into());
        }
        let source = Self::decode_stored_source_on(conn, &rows[0], workspace_id)?;
        let member_index = source
            .state
            .members
            .iter()
            .position(|member| member.logical_id == current.logical_id);
        let Some(member_index) = member_index else {
            return Ok(None);
        };
        if !Self::source_members_match_heads_on(conn, &source.state, workspace_id)? {
            return Err(TechnicalMemorySourceStoreError::CausalConflict.into());
        }
        let member = &source.state.members[member_index];
        if member.record_digest != current.record_digest
            || source.state.presence != TechnicalMemorySourcePresence::Active
        {
            return Err(TechnicalMemorySourceStoreError::CausalConflict.into());
        }
        Ok(Some(PreparedSourceMemberReview {
            source,
            member_index,
        }))
    }

    /// Advance one prepared source member to an audit-validated host-review
    /// successor. The caller owns the surrounding immediate transaction, so a
    /// source-state publication failure rolls back the lesson and audit too.
    pub(super) fn publish_source_member_review_on(
        conn: &Connection,
        workspace_id: &WorkspaceMemoryId,
        prepared: PreparedSourceMemberReview,
        reviewed_revision: &MemoryRevision,
        author_id: String,
    ) -> Result<()> {
        let current = prepared.source;
        let mut state = current.state.clone();
        let member = state
            .members
            .get_mut(prepared.member_index)
            .context("prepared technical-memory source member is unavailable")?;
        if member.logical_id != reviewed_revision.logical_id
            || reviewed_revision.parent_digest.as_ref() != Some(&member.record_digest)
        {
            return Err(TechnicalMemorySourceStoreError::CausalConflict.into());
        }
        Self::validate_technical_lesson_revision(reviewed_revision, workspace_id)?;
        Self::validate_host_review_transition_on(conn, reviewed_revision, workspace_id)?;
        member
            .record_digest
            .clone_from(&reviewed_revision.record_digest);

        let source_digest = state.source_digest.clone();
        let source_version = format!("generation:{}", state.source_generation);
        let store_id = Self::store_id_on(conn)?;
        Self::publish_source_state_on(
            conn,
            Some(&current),
            &state,
            store_id,
            author_id,
            source_digest,
            source_version,
        )?;
        anyhow::ensure!(
            Self::source_members_match_heads_on(conn, &state, workspace_id)?,
            "host-reviewed technical-memory source member is incoherent"
        );
        Ok(())
    }

    fn decode_stored_source_on(
        conn: &Connection,
        row: &super::ArchivalMemory,
        workspace_id: &WorkspaceMemoryId,
    ) -> Result<StoredSource> {
        anyhow::ensure!(
            row.tags == [TECHNICAL_MEMORY_SOURCE_TAG.to_string()],
            "technical-memory source projection has noncanonical tags"
        );
        let state = TechnicalMemorySourceState::decode(&row.content)?;
        state.validate_for_workspace(workspace_id)?;
        let revision = Self::load_revision_by_digest(conn, &row.record_digest)?
            .context("technical-memory source projection references a missing revision")?;
        anyhow::ensure!(
            revision.content == row.content,
            "technical-memory source projection diverges from its immutable revision"
        );
        Self::validate_source_state_revision(&revision, &state)?;
        Ok(StoredSource { state, revision })
    }

    pub(super) fn validate_source_state_revision(
        revision: &MemoryRevision,
        state: &TechnicalMemorySourceState,
    ) -> Result<()> {
        revision.validate()?;
        let expected_evidence_digest = match state.presence {
            TechnicalMemorySourcePresence::Active => state.source_digest.clone(),
            TechnicalMemorySourcePresence::Missing => MemoryDigest::for_fields(
                b"openclaudia.technical-memory.source-missing.v1",
                &[state.source_digest.as_str().as_bytes()],
            ),
        };
        let expected_evidence_version = match state.presence {
            TechnicalMemorySourcePresence::Active => {
                format!("generation:{}", state.source_generation)
            }
            TechnicalMemorySourcePresence::Missing => {
                format!("missing:generation:{}", state.source_generation)
            }
        };
        anyhow::ensure!(
            revision.logical_id == source_state_logical_id(&state.workspace_id, &state.source_id)
                && revision.state == MemoryRevisionState::Active
                && revision.tags == [TECHNICAL_MEMORY_SOURCE_TAG.to_string()]
                && revision.provenance.source_kind == MemorySourceKind::Imported
                && revision.provenance.source_id == source_state_source_id(&state.source_id)
                && revision.provenance.source_version == expected_evidence_version
                && revision.provenance.source_digest == expected_evidence_digest
                && revision.provenance.origin_store_id.is_some()
                && revision.provenance.scope == MemoryRecordScope::UserPrivate
                && revision.provenance.workspace_id.as_deref() == Some(state.workspace_id.as_str()),
            "technical-memory source revision authority is invalid"
        );
        Ok(())
    }

    fn source_members_match_heads_on(
        conn: &Connection,
        state: &TechnicalMemorySourceState,
        workspace_id: &WorkspaceMemoryId,
    ) -> Result<bool> {
        let mut review_lineage_budget = MAX_SOURCE_REVIEW_LINEAGE_REVISIONS;
        for member in &state.members {
            let heads = Self::head_digests(conn, member.logical_id)?;
            if heads.as_slice() != [member.record_digest.clone()] {
                return Ok(false);
            }
            let Some(revision) = Self::load_revision_by_digest(conn, &member.record_digest)? else {
                return Ok(false);
            };
            if !Self::active_source_member_has_owned_lineage_on(
                conn,
                state,
                member,
                revision,
                workspace_id,
                &mut review_lineage_budget,
            )? {
                return Ok(false);
            }
        }
        for member in &state.retired_members {
            let heads = Self::head_digests(conn, member.logical_id)?;
            if heads.as_slice() != [member.record_digest.clone()] {
                return Ok(false);
            }
            let Some(revision) = Self::load_revision_by_digest(conn, &member.record_digest)? else {
                return Ok(false);
            };
            if revision.validate().is_err()
                || revision.state != MemoryRevisionState::Tombstone
                || revision.logical_id != member.logical_id
                || revision.provenance.source_kind != MemorySourceKind::Imported
                || revision.provenance.source_id
                    != source_member_source_id(&state.source_id, &member.lesson_id)
                || revision.provenance.origin_store_id.is_none()
                || revision.provenance.scope != MemoryRecordScope::UserPrivate
                || revision.provenance.workspace_id.as_deref() != Some(workspace_id.as_str())
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn active_source_member_has_owned_lineage_on(
        conn: &Connection,
        state: &TechnicalMemorySourceState,
        member: &TechnicalMemorySourceMember,
        mut revision: MemoryRevision,
        workspace_id: &WorkspaceMemoryId,
        review_lineage_budget: &mut usize,
    ) -> Result<bool> {
        loop {
            if Self::validate_technical_lesson_revision(&revision, workspace_id).is_err()
                || revision.logical_id != member.logical_id
            {
                return Ok(false);
            }
            let source_import = revision.provenance.source_kind == MemorySourceKind::Imported
                && revision.provenance.source_id
                    == source_member_source_id(&state.source_id, &member.lesson_id)
                && revision.provenance.origin_store_id.is_some()
                && revision.provenance.scope == MemoryRecordScope::UserPrivate
                && revision.provenance.workspace_id.as_deref() == Some(workspace_id.as_str());
            if source_import {
                return Ok(true);
            }
            if *review_lineage_budget == 0
                || Self::validate_host_review_transition_on(conn, &revision, workspace_id).is_err()
            {
                return Ok(false);
            }
            *review_lineage_budget -= 1;
            let Some(parent_digest) = revision.parent_digest else {
                return Ok(false);
            };
            let Some(parent) = Self::load_revision_by_digest(conn, &parent_digest)? else {
                return Ok(false);
            };
            revision = parent;
        }
    }

    pub(super) fn store_id_on(conn: &Connection) -> Result<MemoryStoreId> {
        let encoded: String = conn.query_row(
            "SELECT store_id FROM memory_store_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        encoded.parse().context("invalid physical memory store ID")
    }

    fn result_for_source(
        status: TechnicalMemoryRefreshStatus,
        source: &EntrypointFile,
        state_record_digest: Option<MemoryDigest>,
        counts: RefreshCounts,
    ) -> TechnicalMemoryRefreshResult {
        TechnicalMemoryRefreshResult {
            schema_version: TECHNICAL_MEMORY_SOURCE_STATE_SCHEMA_VERSION,
            status,
            source_id: Some(source.manifest.source_id.clone()),
            relative_path: Some(source.relative_path.clone()),
            source_generation: Some(source.manifest.generation),
            source_digest: Some(source.source_digest.clone()),
            state_record_digest,
            created: counts.created,
            updated: counts.updated,
            restored: counts.restored,
            deleted: counts.deleted,
            unchanged: counts.unchanged,
            removals_requiring_confirmation: Vec::new(),
        }
    }

    fn result_for_stored(
        status: TechnicalMemoryRefreshStatus,
        current: &StoredSource,
        counts: RefreshCounts,
    ) -> TechnicalMemoryRefreshResult {
        TechnicalMemoryRefreshResult {
            schema_version: TECHNICAL_MEMORY_SOURCE_STATE_SCHEMA_VERSION,
            status,
            source_id: Some(current.state.source_id.clone()),
            relative_path: Some(current.state.relative_path.clone()),
            source_generation: Some(current.state.source_generation),
            source_digest: Some(current.state.source_digest.clone()),
            state_record_digest: Some(current.revision.record_digest.clone()),
            created: counts.created,
            updated: counts.updated,
            restored: counts.restored,
            deleted: counts.deleted,
            unchanged: counts.unchanged,
            removals_requiring_confirmation: Vec::new(),
        }
    }
}

impl TechnicalMemorySourceState {
    pub(super) fn decode(encoded: &str) -> Result<Self> {
        anyhow::ensure!(
            encoded.len() <= MAX_SOURCE_STATE_BYTES,
            "technical-memory source state exceeds its byte budget"
        );
        let state: Self = serde_json::from_str(encoded)
            .context("technical-memory source state has invalid encoding")?;
        state.validate()?;
        Ok(state)
    }

    pub(super) fn validate_for_workspace(&self, workspace_id: &WorkspaceMemoryId) -> Result<()> {
        self.validate()?;
        anyhow::ensure!(
            &self.workspace_id == workspace_id,
            "technical-memory source belongs to another workspace"
        );
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.schema_version == TECHNICAL_MEMORY_SOURCE_STATE_SCHEMA_VERSION
                && self.source_generation > 0
                && self.published_at_unix_seconds >= 0
                && valid_identifier(&self.source_id)
                && matches!(
                    self.relative_path.as_str(),
                    "MEMORY.md" | ".openclaudia/MEMORY.md"
                )
                && self.members.len() <= MAX_ENTRYPOINT_LESSONS
                && self
                    .members
                    .len()
                    .checked_add(self.retired_members.len())
                    .is_some_and(|count| count <= MAX_SOURCE_LIFECYCLE_MEMBERS),
            "technical-memory source state is invalid"
        );
        if self.presence == TechnicalMemorySourcePresence::Missing {
            anyhow::ensure!(
                self.members.is_empty(),
                "missing technical-memory source retains active members"
            );
        }
        let mut previous: Option<&str> = None;
        let mut logical_ids = BTreeSet::new();
        for member in &self.members {
            anyhow::ensure!(
                valid_identifier(&member.lesson_id)
                    && previous.is_none_or(|value| value < member.lesson_id.as_str())
                    && logical_ids.insert(member.logical_id)
                    && member.logical_id
                        == source_member_logical_id(
                            &self.workspace_id,
                            &self.source_id,
                            &member.lesson_id,
                        ),
                "technical-memory source membership is invalid"
            );
            previous = Some(&member.lesson_id);
        }
        previous = None;
        for member in &self.retired_members {
            anyhow::ensure!(
                valid_identifier(&member.lesson_id)
                    && previous.is_none_or(|value| value < member.lesson_id.as_str())
                    && logical_ids.insert(member.logical_id)
                    && member.logical_id
                        == source_member_logical_id(
                            &self.workspace_id,
                            &self.source_id,
                            &member.lesson_id,
                        ),
                "technical-memory retired source membership is invalid"
            );
            previous = Some(&member.lesson_id);
        }
        Ok(())
    }
}

fn source_state_logical_id(workspace_id: &WorkspaceMemoryId, source_id: &str) -> LogicalMemoryId {
    LogicalMemoryId::for_technical_source(workspace_id.as_str(), &source_state_source_id(source_id))
}

fn source_member_logical_id(
    workspace_id: &WorkspaceMemoryId,
    source_id: &str,
    lesson_id: &str,
) -> LogicalMemoryId {
    LogicalMemoryId::for_technical_source(
        workspace_id.as_str(),
        &source_member_source_id(source_id, lesson_id),
    )
}

fn source_state_source_id(source_id: &str) -> String {
    format!("memdir-source:{source_id}")
}

fn source_member_source_id(source_id: &str, lesson_id: &str) -> String {
    format!("memdir:{source_id}:lesson:{lesson_id}")
}

fn source_member_evidence(
    source: &EntrypointFile,
    entry: &TechnicalMemoryManifestEntry,
) -> Result<MemorySourceEvidence> {
    let encoded = serde_json::to_vec(entry)?;
    let digest = MemoryDigest::for_fields(
        b"openclaudia.technical-memory.source-lesson.v1",
        &[
            source.source_digest.as_str().as_bytes(),
            entry.lesson_id.as_bytes(),
            &encoded,
        ],
    );
    Ok(MemorySourceEvidence::new(
        MemorySourceKind::Imported,
        source_member_source_id(&source.manifest.source_id, &entry.lesson_id),
        format!("generation:{}", source.manifest.generation),
        digest,
    ))
}

fn imported_provenance(
    evidence: MemorySourceEvidence,
    store_id: MemoryStoreId,
    workspace_id: &WorkspaceMemoryId,
    author_id: String,
) -> MemoryProvenance {
    MemoryProvenance::new(
        evidence,
        MemoryAttribution::new(author_id, Some(store_id), Some(workspace_id.to_string())),
        MemoryRecordScope::UserPrivate,
    )
}

fn lesson_tags(kind: super::TechnicalLessonKind) -> Vec<String> {
    vec![
        TECHNICAL_LESSON_TAG.to_string(),
        format!("technical-kind:{}", technical_lesson_kind_name(kind)),
    ]
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn projected_active_lesson_count(
    active_count: usize,
    tracked_active: usize,
    desired_source_count: usize,
) -> Option<usize> {
    active_count
        .checked_sub(tracked_active)?
        .checked_add(desired_source_count)
}

#[cfg(test)]
mod tests {
    use super::projected_active_lesson_count;

    #[test]
    fn projected_store_capacity_replaces_tracked_members_before_adding_desired_members() {
        assert_eq!(projected_active_lesson_count(4_096, 256, 256), Some(4_096));
        assert_eq!(projected_active_lesson_count(4_096, 1, 2), Some(4_097));
        assert_eq!(projected_active_lesson_count(0, 1, 0), None);
        assert_eq!(projected_active_lesson_count(usize::MAX, 0, 1), None);
    }
}
