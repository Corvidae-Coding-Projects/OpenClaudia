//! Team memory store — per-user + optional shared team scope.
//!
//! S-053 gives this store stable logical identity, immutable causal revisions,
//! explicit conflicts, version-bound tombstones, and durable idempotent
//! cross-store reconciliation. Production [`crate::config::load_config`] still
//! rejects a configured team path until S-054 supplies authenticated authority,
//! host-owned storage, schema recovery, and retrieval policy. A shared path
//! alone is not a team authorization model.
//!
//! Crosslink #604. Parity with Claude Code's `teamMemPaths.ts`: a project
//! may carry an additional *shared* memory directory that several users on
//! the same project read and write together. The shared store sits **next
//! to** the per-user store. Only explicitly `Both`-scoped logical memories are
//! enrolled for idempotent replica exchange; private user records are never
//! mirrored automatically.
//!
//! # Scope model
//!
//! [`MemoryScope`] selects which underlying store a single operation
//! participates against:
//!
//! * [`MemoryScope::User`] — operate on the per-user store only.
//! * [`MemoryScope::Team`] — operate on the shared team store only.
//!   Returns [`TeamMemoryError::TeamUnavailable`] when no team path is
//!   configured.
//! * [`MemoryScope::Both`] — reads merge by logical identity; writes first
//!   persist an operation and then idempotently apply one exact revision to
//!   both stores.
//!
//! # Merge semantics
//!
//! Equal immutable revisions collapse to one `Both` result. A causally newer
//! descendant supersedes its ancestor. Concurrent branches remain explicit
//! conflict heads and neither branch is deleted. Equal prose with different
//! logical IDs remains distinct. Core sections retain their stable section key
//! and user overlay precedence pending the broader authority work in S-054.
//!
//! # Tombstones
//!
//! A user-side hide of a team-origin entry records the physical team-store ID,
//! logical ID, exact source version, and record digest in a sidecar. The
//! sidecar itself is bound to the exact user/team store pair, so replacing a
//! database fails closed instead of inheriting replay authority. A later team
//! revision is therefore not silently hidden by a stale row-number tombstone.
//! A `Both` deletion is a replicated immutable tombstone revision.

use crate::config::MemoryConfig;
use crate::memory::{
    ArchivalMemory, CoreMemory, LogicalMemoryId, MemoryAttribution, MemoryDb, MemoryDigest,
    MemoryProvenance, MemoryRecordScope, MemoryRevision, MemoryRevisionState, MemorySourceEvidence,
    MemorySourceKind, MemoryStoreId,
};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

const MAX_PENDING_REPLICATION_OPERATIONS: usize = 4_096;
const MAX_REPLICATED_LOGICAL_IDS: usize = 4_096;
const MAX_REVISIONS_PER_LOGICAL_ID: usize = 4_096;
const MAX_MERGED_CONFLICT_HEADS: usize = 64;
const MAX_ARCHIVAL_TOMBSTONES: usize = 4_096;
const MAX_REPLICATION_REVISION_BYTES: usize = 1_048_576;

/// Selects which underlying store an operation participates against.
///
/// See module documentation for the read/write semantics of each
/// variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryScope {
    /// Per-user store only.
    User,
    /// Shared team store only. Operations error with
    /// [`TeamMemoryError::TeamUnavailable`] if no team path was
    /// configured.
    Team,
    /// Both stores. Reads causally merge by logical identity; writes target
    /// both stores through a durable idempotent operation.
    Both,
}

/// Errors that can arise from team-memory operations.
#[derive(Debug, thiserror::Error)]
pub enum TeamMemoryError {
    /// A scoped operation requested the team store but no team path is
    /// configured.
    #[error("team memory not configured")]
    TeamUnavailable,
    /// The sidecar belongs to a different physical user or team database.
    #[error("team-memory sync state is bound to a different {role} store")]
    StoreBindingMismatch {
        /// Which physical store changed.
        role: &'static str,
    },
    /// User and team roles must not alias the same physical database.
    #[error("user and team memory cannot use the same physical store")]
    SamePhysicalStore,
    /// Pre-S-053 sidecar state cannot be attached to a store without evidence.
    #[error("legacy team-memory sync state has no physical store binding")]
    UnboundSyncState,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VersionBoundTombstone {
    team_store_id: String,
    logical_id: String,
    source_version: i64,
    source_digest: String,
}

impl VersionBoundTombstone {
    fn matches(&self, team_store_id: MemoryStoreId, entry: &ArchivalMemory) -> bool {
        self.team_store_id == team_store_id.to_string()
            && self.logical_id == entry.logical_id.to_string()
            && u64::try_from(self.source_version) == Ok(entry.version.get())
            && self.source_digest == entry.record_digest.as_str()
    }
}

/// The team-memory store: a per-user database plus an optional shared
/// team database, mediated through a [`MemoryScope`] selector.
///
/// Construct via [`TeamMemoryStore::open`]. Clone-friendly via internal
/// [`Arc`]s.
pub struct TeamMemoryStore {
    user: Arc<MemoryDb>,
    team: Option<Arc<MemoryDb>>,
    user_store_id: MemoryStoreId,
    team_store_id: Option<MemoryStoreId>,
    /// Version-bound overlay tombstones and durable cross-store operation log.
    /// `None` when no team store is configured.
    sync: Option<Mutex<Connection>>,
}

impl TeamMemoryStore {
    /// Open a team-memory store given a user database path and the
    /// project-wide memory configuration. When
    /// [`MemoryConfig::team_memory_path`] is `Some(dir)`, the team
    /// database is opened at `dir/memory.db` (the directory is created
    /// if missing); when `None`, the store behaves as a per-user-only
    /// wrapper.
    ///
    /// # Errors
    ///
    /// Returns an error if the user or team database cannot be opened,
    /// or if the team directory cannot be created.
    pub fn open(user_db_path: &Path, cfg: &MemoryConfig) -> Result<Self> {
        let user = Arc::new(MemoryDb::open(user_db_path).context("opening user memory db")?);
        let user_store_id = user
            .store_id()
            .context("reading user memory store identity")?;

        let team = match cfg.team_memory_path.as_deref() {
            Some(dir) => {
                if !dir.exists() {
                    std::fs::create_dir_all(dir).with_context(|| {
                        format!("creating team memory directory {}", dir.display())
                    })?;
                }
                let team_db =
                    MemoryDb::open(&dir.join("memory.db")).context("opening team memory db")?;
                Some(Arc::new(team_db))
            }
            None => None,
        };
        let team_store_id = team
            .as_ref()
            .map(|store| {
                store
                    .store_id()
                    .context("reading team memory store identity")
            })
            .transpose()?;
        if team_store_id == Some(user_store_id) {
            return Err(TeamMemoryError::SamePhysicalStore.into());
        }

        let sync = match &team {
            Some(_) => {
                let parent = user_db_path
                    .parent()
                    .filter(|path| !path.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
                let sync_path = parent.join("team_memory_sync.db");
                let mut conn = Connection::open(&sync_path)
                    .with_context(|| format!("opening team sync db at {}", sync_path.display()))?;
                conn.execute_batch(
                    r"
                    PRAGMA foreign_keys = ON;
                    PRAGMA journal_mode = WAL;
                    PRAGMA synchronous = FULL;
                    PRAGMA busy_timeout = 5000;
                    CREATE TABLE IF NOT EXISTS archival_tombstones (
                        team_store_id TEXT NOT NULL,
                        logical_id TEXT NOT NULL,
                        source_version INTEGER NOT NULL CHECK(source_version > 0),
                        source_digest TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT (datetime('now')),
                        PRIMARY KEY (team_store_id, logical_id, source_version, source_digest)
                    );
                    CREATE TABLE IF NOT EXISTS core_tombstones (
                        section TEXT PRIMARY KEY
                    );
                    CREATE TABLE IF NOT EXISTS replica_binding (
                        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                        user_store_id TEXT NOT NULL,
                        team_store_id TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS replicated_memories (
                        logical_id TEXT PRIMARY KEY,
                        enrolled_at TEXT NOT NULL DEFAULT (datetime('now'))
                    );
                    CREATE TABLE IF NOT EXISTS replication_operations (
                        operation_id TEXT PRIMARY KEY,
                        revision_json TEXT NOT NULL,
                        user_applied INTEGER NOT NULL DEFAULT 0 CHECK(user_applied IN (0, 1)),
                        team_applied INTEGER NOT NULL DEFAULT 0 CHECK(team_applied IN (0, 1)),
                        created_at TEXT NOT NULL DEFAULT (datetime('now')),
                        completed_at TEXT
                    );
                    ",
                )
                .context("initialising team-memory sync schema")?;
                Self::bind_sync_database(
                    &mut conn,
                    user_store_id,
                    team_store_id.ok_or(TeamMemoryError::TeamUnavailable)?,
                )?;
                Some(Mutex::new(conn))
            }
            None => None,
        };

        let store = Self {
            user,
            team,
            user_store_id,
            team_store_id,
            sync,
        };
        store.reconcile_replica_histories()?;
        store.reconcile_pending_operations()?;
        store.reconcile_replica_histories()?;
        Ok(store)
    }

    /// `true` when the store has a configured team database.
    #[must_use]
    pub const fn has_team(&self) -> bool {
        self.team.is_some()
    }

    /// Access the per-user store directly. Useful for code paths that
    /// only need user-scoped operations and do not yet model
    /// [`MemoryScope`].
    #[must_use]
    pub const fn user(&self) -> &Arc<MemoryDb> {
        &self.user
    }

    /// Access the team store directly when configured.
    #[must_use]
    pub const fn team(&self) -> Option<&Arc<MemoryDb>> {
        self.team.as_ref()
    }

    /// Persistent identity of the physical user database.
    #[must_use]
    pub const fn user_store_id(&self) -> MemoryStoreId {
        self.user_store_id
    }

    /// Persistent identity of the physical team database, when configured.
    #[must_use]
    pub const fn team_store_id(&self) -> Option<MemoryStoreId> {
        self.team_store_id
    }

    fn lock_sync(&self) -> Option<Result<MutexGuard<'_, Connection>>> {
        self.sync.as_ref().map(|m| {
            m.lock()
                .map_err(|_| anyhow::anyhow!("team-memory sync mutex poisoned"))
        })
    }

    fn bind_sync_database(
        conn: &mut Connection,
        user_store_id: MemoryStoreId,
        team_store_id: MemoryStoreId,
    ) -> Result<()> {
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .context("binding team-memory sync database")?;
        let binding = tx
            .query_row(
                "SELECT user_store_id, team_store_id FROM replica_binding WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        if let Some((stored_user, stored_team)) = binding {
            let stored_user: MemoryStoreId = stored_user
                .parse()
                .context("invalid bound user memory store ID")?;
            let stored_team: MemoryStoreId = stored_team
                .parse()
                .context("invalid bound team memory store ID")?;
            if stored_user != user_store_id {
                return Err(TeamMemoryError::StoreBindingMismatch { role: "user" }.into());
            }
            if stored_team != team_store_id {
                return Err(TeamMemoryError::StoreBindingMismatch { role: "team" }.into());
            }
        } else {
            let existing_state: i64 = tx.query_row(
                r"SELECT
                        (SELECT COUNT(*) FROM archival_tombstones) +
                        (SELECT COUNT(*) FROM core_tombstones) +
                        (SELECT COUNT(*) FROM replicated_memories) +
                        (SELECT COUNT(*) FROM replication_operations)",
                [],
                |row| row.get(0),
            )?;
            if existing_state != 0 {
                return Err(TeamMemoryError::UnboundSyncState.into());
            }
            tx.execute(
                r"INSERT INTO replica_binding
                       (singleton, user_store_id, team_store_id) VALUES (1, ?1, ?2)",
                params![user_store_id.to_string(), team_store_id.to_string()],
            )?;
        }
        tx.commit()
            .context("committing team-memory store binding")?;
        Ok(())
    }

    /// Returns version-bound team records shadowed by a user-side hide.
    /// Empty when no team store / sync database exists.
    fn archival_tombstones(&self) -> Result<HashSet<VersionBoundTombstone>> {
        let Some(guard) = self.lock_sync() else {
            return Ok(HashSet::new());
        };
        let conn = guard?;
        let mut stmt = conn.prepare(
            "SELECT team_store_id, logical_id, source_version, source_digest \
             FROM archival_tombstones ORDER BY rowid LIMIT 4097",
        )?;
        let rows: HashSet<VersionBoundTombstone> = stmt
            .query_map([], |row| {
                Ok(VersionBoundTombstone {
                    team_store_id: row.get(0)?,
                    logical_id: row.get(1)?,
                    source_version: row.get(2)?,
                    source_digest: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<HashSet<_>>>()?;
        anyhow::ensure!(
            rows.len() <= MAX_ARCHIVAL_TOMBSTONES,
            "team-memory archival tombstone budget exceeded"
        );
        drop(stmt);
        drop(conn);
        Ok(rows)
    }

    fn core_tombstones(&self) -> Result<HashSet<String>> {
        let Some(guard) = self.lock_sync() else {
            return Ok(HashSet::new());
        };
        let conn = guard?;
        let mut stmt = conn.prepare("SELECT section FROM core_tombstones")?;
        let rows: HashSet<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<HashSet<_>>>()?;
        drop(stmt);
        drop(conn);
        Ok(rows)
    }

    fn insert_archival_tombstone(&self, entry: &ArchivalMemory) -> Result<()> {
        let Some(guard) = self.lock_sync() else {
            return Ok(());
        };
        let mut conn = guard?;
        let team_store_id = self.team_store_id.ok_or(TeamMemoryError::TeamUnavailable)?;
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .context("persisting team-memory archival tombstone")?;
        let exists: bool = tx.query_row(
            r"SELECT EXISTS(
                   SELECT 1 FROM archival_tombstones
                    WHERE team_store_id = ?1 AND logical_id = ?2
                      AND source_version = ?3 AND source_digest = ?4
               )",
            params![
                team_store_id.to_string(),
                entry.logical_id.to_string(),
                i64::try_from(entry.version.get())?,
                entry.record_digest.as_str(),
            ],
            |row| row.get(0),
        )?;
        if !exists {
            let count: i64 =
                tx.query_row("SELECT COUNT(*) FROM archival_tombstones", [], |row| {
                    row.get(0)
                })?;
            anyhow::ensure!(
                count < i64::try_from(MAX_ARCHIVAL_TOMBSTONES)?,
                "team-memory archival tombstone budget exceeded"
            );
        }
        tx.execute(
            r"INSERT OR IGNORE INTO archival_tombstones
               (team_store_id, logical_id, source_version, source_digest)
               VALUES (?1, ?2, ?3, ?4)",
            params![
                team_store_id.to_string(),
                entry.logical_id.to_string(),
                i64::try_from(entry.version.get())?,
                entry.record_digest.as_str(),
            ],
        )?;
        tx.commit()
            .context("committing team-memory archival tombstone")?;
        drop(conn);
        Ok(())
    }

    fn insert_core_tombstone(&self, section: &str) -> Result<()> {
        let Some(guard) = self.lock_sync() else {
            return Ok(());
        };
        let conn = guard?;
        conn.execute(
            "INSERT OR IGNORE INTO core_tombstones (section) VALUES (?1)",
            params![section],
        )?;
        drop(conn);
        Ok(())
    }

    fn memory_provenance(
        &self,
        scope: MemoryScope,
        operation: &str,
        content: &str,
        tags: &[String],
    ) -> Result<MemoryProvenance> {
        let tags_json = serde_json::to_vec(tags)?;
        let record_scope = match scope {
            MemoryScope::User => MemoryRecordScope::UserPrivate,
            MemoryScope::Team | MemoryScope::Both => MemoryRecordScope::TeamShared,
        };
        let origin_store_id = match scope {
            MemoryScope::User | MemoryScope::Both => self.user_store_id,
            MemoryScope::Team => self.team_store_id.ok_or(TeamMemoryError::TeamUnavailable)?,
        };
        Ok(MemoryProvenance::new(
            MemorySourceEvidence::new(
                MemorySourceKind::Explicit,
                format!("team-memory:{operation}:{}", uuid::Uuid::new_v4()),
                "s053-v1".to_string(),
                MemoryDigest::for_fields(
                    b"openclaudia.team-memory.operation.v1",
                    &[operation.as_bytes(), content.as_bytes(), &tags_json],
                ),
            ),
            MemoryAttribution::new(
                "team-memory-api-unattributed".to_string(),
                Some(origin_store_id),
                None,
            ),
            record_scope,
        ))
    }

    fn persist_replication_operation(&self, revision: &MemoryRevision) -> Result<String> {
        anyhow::ensure!(
            revision.provenance.scope == MemoryRecordScope::TeamShared,
            "only team-shared revisions may enter the replication log"
        );
        revision.validate()?;
        let operation_id = format!("replicate:{}", revision.record_digest);
        let encoded = serde_json::to_string(revision)?;
        anyhow::ensure!(
            encoded.len() <= MAX_REPLICATION_REVISION_BYTES,
            "team-memory replication revision exceeds byte budget"
        );
        let Some(guard) = self.lock_sync() else {
            return Err(TeamMemoryError::TeamUnavailable.into());
        };
        let mut conn = guard?;
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .context("persisting team-memory replication operation")?;
        let enrollment_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM replicated_memories WHERE logical_id = ?1)",
            params![revision.logical_id.to_string()],
            |row| row.get(0),
        )?;
        if !enrollment_exists {
            let enrollment_count: i64 =
                tx.query_row("SELECT COUNT(*) FROM replicated_memories", [], |row| {
                    row.get(0)
                })?;
            anyhow::ensure!(
                enrollment_count < i64::try_from(MAX_REPLICATED_LOGICAL_IDS)?,
                "team-memory replica identity budget exceeded"
            );
        }
        let existing_operation: Option<String> = tx
            .query_row(
                "SELECT revision_json FROM replication_operations WHERE operation_id = ?1",
                params![operation_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing_operation {
            anyhow::ensure!(
                existing == encoded,
                "team-memory replication operation identity collision"
            );
        } else {
            let operation_count: i64 =
                tx.query_row("SELECT COUNT(*) FROM replication_operations", [], |row| {
                    row.get(0)
                })?;
            anyhow::ensure!(
                operation_count < i64::try_from(MAX_PENDING_REPLICATION_OPERATIONS)?,
                "team-memory operation log exceeds reconciliation budget"
            );
        }
        tx.execute(
            "INSERT OR IGNORE INTO replicated_memories (logical_id) VALUES (?1)",
            params![revision.logical_id.to_string()],
        )?;
        tx.execute(
            r"INSERT OR IGNORE INTO replication_operations
               (operation_id, revision_json) VALUES (?1, ?2)",
            params![operation_id, encoded],
        )?;
        tx.commit()
            .context("committing team-memory replication operation")?;
        drop(conn);
        Ok(operation_id)
    }

    fn apply_replication_operation(
        &self,
        operation_id: &str,
        revision: &MemoryRevision,
        user_applied: bool,
        team_applied: bool,
    ) -> Result<()> {
        if !user_applied {
            let _ = self.user.apply_revision(revision)?;
            let guard = self.lock_sync().ok_or(TeamMemoryError::TeamUnavailable)??;
            guard.execute(
                "UPDATE replication_operations SET user_applied = 1 WHERE operation_id = ?1",
                params![operation_id],
            )?;
        }
        if team_applied {
            let guard = self.lock_sync().ok_or(TeamMemoryError::TeamUnavailable)??;
            guard.execute(
                r"UPDATE replication_operations SET completed_at = COALESCE(completed_at, datetime('now'))
                  WHERE operation_id = ?1 AND user_applied = 1 AND team_applied = 1",
                params![operation_id],
            )?;
        } else {
            let team = self.team.as_ref().ok_or(TeamMemoryError::TeamUnavailable)?;
            let _ = team.apply_revision(revision)?;
            let guard = self.lock_sync().ok_or(TeamMemoryError::TeamUnavailable)??;
            guard.execute(
                r"UPDATE replication_operations
                    SET team_applied = 1, completed_at = datetime('now')
                  WHERE operation_id = ?1",
                params![operation_id],
            )?;
        }
        let guard = self.lock_sync().ok_or(TeamMemoryError::TeamUnavailable)??;
        guard.execute(
            r"DELETE FROM replication_operations
              WHERE operation_id = ?1 AND user_applied = 1 AND team_applied = 1",
            params![operation_id],
        )?;
        drop(guard);
        Ok(())
    }

    /// Replay incomplete cross-store writes. Applying an already-written
    /// immutable revision is idempotent, so every crash boundary is retryable.
    ///
    /// # Errors
    ///
    /// Returns an error for a corrupt/oversized operation log or when either
    /// store cannot accept the next causal revision.
    pub fn reconcile_pending_operations(&self) -> Result<usize> {
        let Some(guard) = self.lock_sync() else {
            return Ok(0);
        };
        let conn = guard?;
        conn.execute(
            "DELETE FROM replication_operations WHERE user_applied = 1 AND team_applied = 1",
            [],
        )?;
        let oversized: bool = conn.query_row(
            r"SELECT EXISTS(
                SELECT 1 FROM replication_operations
                 WHERE (user_applied = 0 OR team_applied = 0)
                   AND length(CAST(revision_json AS BLOB)) > ?1
            )",
            params![i64::try_from(MAX_REPLICATION_REVISION_BYTES)?],
            |row| row.get(0),
        )?;
        anyhow::ensure!(
            !oversized,
            "team-memory replication revision exceeds byte budget"
        );
        let mut stmt = conn.prepare(
            r"SELECT operation_id, revision_json, user_applied, team_applied
                 FROM replication_operations
                WHERE user_applied = 0 OR team_applied = 0
                ORDER BY rowid LIMIT ?1",
        )?;
        let pending = stmt
            .query_map(
                params![i64::try_from(MAX_PENDING_REPLICATION_OPERATIONS + 1)?],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, bool>(3)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        drop(conn);
        anyhow::ensure!(
            pending.len() <= MAX_PENDING_REPLICATION_OPERATIONS,
            "team-memory operation log exceeds reconciliation budget"
        );
        for (operation_id, revision_json, user_applied, team_applied) in &pending {
            let revision: MemoryRevision = serde_json::from_str(revision_json)
                .context("invalid team-memory replication operation")?;
            revision.validate()?;
            self.apply_replication_operation(
                operation_id,
                &revision,
                *user_applied,
                *team_applied,
            )?;
        }
        Ok(pending.len())
    }

    fn replicated_logical_ids(&self) -> Result<Vec<LogicalMemoryId>> {
        let Some(guard) = self.lock_sync() else {
            return Ok(Vec::new());
        };
        let conn = guard?;
        let mut stmt = conn
            .prepare("SELECT logical_id FROM replicated_memories ORDER BY logical_id LIMIT ?1")?;
        let encoded = stmt
            .query_map(
                params![i64::try_from(MAX_REPLICATED_LOGICAL_IDS + 1)?],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        drop(conn);
        anyhow::ensure!(
            encoded.len() <= MAX_REPLICATED_LOGICAL_IDS,
            "team-memory replica identity budget exceeded"
        );
        let mut ids = encoded
            .into_iter()
            .map(|encoded| {
                encoded
                    .parse()
                    .context("invalid replicated logical memory ID")
            })
            .collect::<Result<Vec<_>>>()?;
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    /// Exchange immutable team-shared revision histories for every logical ID
    /// introduced by a durable `Both` operation. Parent-before-child import
    /// makes retries deterministic, while concurrent heads remain conflicts in
    /// both stores rather than being overwritten.
    ///
    /// # Errors
    ///
    /// Returns an error for corrupt/oversized histories or a failed store
    /// transaction. A partial exchange is safe to retry.
    pub fn reconcile_replica_histories(&self) -> Result<usize> {
        let Some(team) = &self.team else {
            return Ok(0);
        };
        let mut applied = 0_usize;
        for logical_id in self.replicated_logical_ids()? {
            let mut revisions = self
                .user
                .revisions_for_logical_bounded(logical_id, MAX_REVISIONS_PER_LOGICAL_ID)?;
            revisions.extend(
                team.revisions_for_logical_bounded(logical_id, MAX_REVISIONS_PER_LOGICAL_ID)?,
            );
            revisions.retain(|revision| revision.provenance.scope == MemoryRecordScope::TeamShared);
            revisions.sort_by(|left, right| {
                left.version
                    .cmp(&right.version)
                    .then_with(|| left.record_digest.cmp(&right.record_digest))
            });
            revisions.dedup_by(|left, right| left.record_digest == right.record_digest);
            anyhow::ensure!(
                revisions.len() <= MAX_REVISIONS_PER_LOGICAL_ID,
                "team-memory revision history exceeds reconciliation budget"
            );
            for revision in revisions {
                let user_outcome = self.user.apply_revision(&revision)?;
                let team_outcome = team.apply_revision(&revision)?;
                applied +=
                    usize::from(user_outcome != crate::memory::ApplyRevisionOutcome::Idempotent);
                applied +=
                    usize::from(team_outcome != crate::memory::ApplyRevisionOutcome::Idempotent);
            }
        }
        Ok(applied)
    }

    fn replicate_revision(&self, revision: &MemoryRevision) -> Result<i64> {
        // A successor/tombstone may have been created while one replica was
        // offline. Exchange already-enrolled history first so the exact parent
        // exists in both stores before the durable child operation is applied.
        self.reconcile_replica_histories()?;
        self.persist_replication_operation(revision)?;
        self.reconcile_pending_operations()?;
        self.user
            .row_id_for_logical(revision.logical_id)?
            .ok_or_else(|| anyhow::anyhow!("replicated user projection is unavailable"))
    }

    /// Save an archival memory entry into the selected scope(s).
    ///
    /// * `User`  → writes only to the user db.
    /// * `Team`  → writes only to the team db (error if unavailable).
    /// * `Both`  → durably records one immutable revision, then applies it
    ///   idempotently to user and team stores. The returned ID is only the
    ///   user store's compatibility locator.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying database write fails or if
    /// `Team` / `Both` is requested without a configured team store.
    pub fn save_archival(&self, scope: MemoryScope, content: &str, tags: &[String]) -> Result<i64> {
        let provenance = self.memory_provenance(scope, "save", content, tags)?;
        let revision = MemoryRevision::new(content.to_string(), tags.to_vec(), provenance);
        match scope {
            MemoryScope::User => self.user.memory_save_revision(&revision),
            MemoryScope::Team => {
                let team = self.team.as_ref().ok_or(TeamMemoryError::TeamUnavailable)?;
                team.memory_save_revision(&revision)
            }
            MemoryScope::Both => self.replicate_revision(&revision),
        }
    }

    /// List archival memories from the selected scope.
    ///
    /// With [`MemoryScope::Both`] the returned vector is merged by logical
    /// identity, then globally ordered and limited. Identical revisions
    /// collapse; descendants supersede ancestors; concurrent heads remain
    /// explicit conflicts.
    ///
    /// # Errors
    ///
    /// Returns an error if any underlying read fails.
    pub fn list_archival(&self, scope: MemoryScope, limit: usize) -> Result<Vec<ScopedArchival>> {
        match scope {
            MemoryScope::User => {
                let rows = self.user.memory_list(limit)?;
                Ok(rows.into_iter().map(ScopedArchival::user).collect())
            }
            MemoryScope::Team => {
                let team = self.team.as_ref().ok_or(TeamMemoryError::TeamUnavailable)?;
                let tombstoned = self.archival_tombstones()?;
                let team_store_id = self.team_store_id.ok_or(TeamMemoryError::TeamUnavailable)?;
                let rows = team.memory_list(limit.saturating_add(tombstoned.len()))?;
                Ok(rows
                    .into_iter()
                    .filter(|entry| {
                        !tombstoned
                            .iter()
                            .any(|item| item.matches(team_store_id, entry))
                    })
                    .take(limit)
                    .map(ScopedArchival::team)
                    .collect())
            }
            MemoryScope::Both => {
                let user_rows = self.user.memory_list(limit)?;
                let tombstoned = self.archival_tombstones()?;
                let team_rows = match &self.team {
                    Some(team) => team.memory_list(limit.saturating_add(tombstoned.len()))?,
                    None => Vec::new(),
                };
                let mut merged: HashMap<LogicalMemoryId, ScopedArchival> = user_rows
                    .into_iter()
                    .map(|entry| (entry.logical_id, ScopedArchival::user(entry)))
                    .collect();
                for entry in team_rows {
                    if self.team_store_id.is_some_and(|team_store_id| {
                        tombstoned
                            .iter()
                            .any(|item| item.matches(team_store_id, &entry))
                    }) {
                        continue;
                    }
                    match merged.remove(&entry.logical_id) {
                        Some(user_entry) => {
                            let combined = self.merge_replica_entries(user_entry.entry, entry)?;
                            merged.insert(combined.entry.logical_id, combined);
                        }
                        None => {
                            merged.insert(entry.logical_id, ScopedArchival::team(entry));
                        }
                    }
                }
                let mut out = merged.into_values().collect::<Vec<_>>();
                out.sort_by(|left, right| {
                    right
                        .entry
                        .updated_at
                        .cmp(&left.entry.updated_at)
                        .then_with(|| left.entry.logical_id.cmp(&right.entry.logical_id))
                });
                out.truncate(limit);
                Ok(out)
            }
        }
    }

    fn merge_replica_entries(
        &self,
        user: ArchivalMemory,
        team: ArchivalMemory,
    ) -> Result<ScopedArchival> {
        let conflict_heads = self.maximal_entry_heads(&user, &team)?;
        if conflict_heads.len() == 1 {
            let sole_digest = &conflict_heads[0].record_digest;
            if &user.record_digest == sole_digest {
                return Ok(ScopedArchival::both(user));
            }
            if &team.record_digest == sole_digest {
                return Ok(ScopedArchival::both(team));
            }
            anyhow::bail!("merged memory head has no visible projection");
        }
        let mut chosen = if user.version > team.version
            || (user.version == team.version && user.record_digest < team.record_digest)
        {
            user
        } else {
            team
        };
        chosen.conflict_heads = conflict_heads;
        Ok(ScopedArchival::both(chosen))
    }

    fn maximal_entry_heads(
        &self,
        user: &ArchivalMemory,
        team: &ArchivalMemory,
    ) -> Result<Vec<crate::memory::MemoryConflictHead>> {
        let mut heads = Self::entry_heads(user);
        heads.extend(Self::entry_heads(team));
        heads.sort_by(|left, right| left.record_digest.cmp(&right.record_digest));
        heads.dedup_by(|left, right| left.record_digest == right.record_digest);
        anyhow::ensure!(
            heads.len() <= MAX_MERGED_CONFLICT_HEADS,
            "merged memory conflict-head budget exceeded"
        );

        let mut maximal = Vec::with_capacity(heads.len());
        for (index, candidate) in heads.iter().enumerate() {
            let mut superseded = false;
            for (other_index, other) in heads.iter().enumerate() {
                if index != other_index
                    && self.revision_descends_in_either_store(
                        &other.record_digest,
                        &candidate.record_digest,
                    )?
                {
                    superseded = true;
                    break;
                }
            }
            if !superseded {
                maximal.push(candidate.clone());
            }
        }
        maximal.sort_by(|left, right| {
            right
                .version
                .cmp(&left.version)
                .then_with(|| left.record_digest.cmp(&right.record_digest))
        });
        anyhow::ensure!(!maximal.is_empty(), "merged memory has no causal head");
        Ok(maximal)
    }

    fn revision_descends_in_either_store(
        &self,
        descendant: &MemoryDigest,
        ancestor: &MemoryDigest,
    ) -> Result<bool> {
        if descendant == ancestor {
            return Ok(true);
        }
        if self.user.revision_descends_from(descendant, ancestor)? {
            return Ok(true);
        }
        self.team.as_ref().map_or(Ok(false), |team| {
            team.revision_descends_from(descendant, ancestor)
        })
    }

    fn entry_heads(entry: &ArchivalMemory) -> Vec<crate::memory::MemoryConflictHead> {
        if !entry.conflict_heads.is_empty() {
            return entry.conflict_heads.clone();
        }
        vec![crate::memory::MemoryConflictHead {
            version: entry.version,
            record_digest: entry.record_digest.clone(),
            parent_digest: entry.parent_digest.clone(),
            content_digest: entry.content_digest.clone(),
            state: MemoryRevisionState::Active,
        }]
    }

    /// Delete an archival entry by `(scope, local compatibility id)`.
    /// Store deletes create immutable tombstone revisions. `Both` persists and
    /// replays the same tombstone across stores; hiding a team-origin record
    /// from one user remains the separate [`Self::tombstone_team_archival`]
    /// overlay operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying write fails or if `Team` is
    /// requested without a configured team store.
    pub fn delete_archival(&self, scope: MemoryScope, id: i64) -> Result<bool> {
        match scope {
            MemoryScope::User => self.user.memory_delete(id),
            MemoryScope::Team => {
                let team = self.team.as_ref().ok_or(TeamMemoryError::TeamUnavailable)?;
                team.memory_delete(id)
            }
            MemoryScope::Both => {
                let Some(current) = self.user.revision_for_row(id)? else {
                    return Ok(false);
                };
                if current.state == MemoryRevisionState::Tombstone {
                    return Ok(false);
                }
                anyhow::ensure!(
                    current.provenance.scope == MemoryRecordScope::TeamShared,
                    "Both deletion requires a team-shared memory revision"
                );
                let provenance = self.memory_provenance(
                    MemoryScope::Both,
                    "delete",
                    current.record_digest.as_str(),
                    &[],
                )?;
                let tombstone = current.tombstone(provenance)?;
                let _ = self.replicate_revision(&tombstone)?;
                Ok(true)
            }
        }
    }

    /// Tombstone a team-origin archival id from the user perspective.
    /// The team row remains; merged reads stop returning it for this
    /// user. Idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error if the team row or sync database is unavailable/corrupt.
    pub fn tombstone_team_archival(&self, team_id: i64) -> Result<()> {
        let team = self.team.as_ref().ok_or(TeamMemoryError::TeamUnavailable)?;
        let entry = team
            .memory_get(team_id)?
            .ok_or_else(|| anyhow::anyhow!("team memory row is unavailable"))?;
        self.insert_archival_tombstone(&entry)
    }

    /// Update a core memory section in the selected scope.
    ///
    /// # Errors
    ///
    /// Returns an error if any underlying write fails.
    pub fn update_core(&self, scope: MemoryScope, section: &str, content: &str) -> Result<()> {
        match scope {
            MemoryScope::User => self.user.update_core_memory(section, content),
            MemoryScope::Team => {
                let team = self.team.as_ref().ok_or(TeamMemoryError::TeamUnavailable)?;
                team.update_core_memory(section, content)
            }
            MemoryScope::Both => {
                let team = self.team.as_ref().ok_or(TeamMemoryError::TeamUnavailable)?;
                self.user.update_core_memory(section, content)?;
                team.update_core_memory(section, content)
            }
        }
    }

    /// Get a core memory section. With [`MemoryScope::Both`] the user
    /// entry shadows the team entry; a user tombstone hides the team
    /// entry entirely and yields `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if any underlying read fails.
    pub fn get_core_section(
        &self,
        scope: MemoryScope,
        section: &str,
    ) -> Result<Option<CoreMemory>> {
        match scope {
            MemoryScope::User => self.user.get_core_memory_section(section),
            MemoryScope::Team => {
                let team = self.team.as_ref().ok_or(TeamMemoryError::TeamUnavailable)?;
                let tombstoned = self.core_tombstones()?;
                if tombstoned.contains(section) {
                    return Ok(None);
                }
                team.get_core_memory_section(section)
            }
            MemoryScope::Both => {
                if let Some(user) = self.user.get_core_memory_section(section)? {
                    return Ok(Some(user));
                }
                if let Some(team) = &self.team {
                    let tombstoned = self.core_tombstones()?;
                    if tombstoned.contains(section) {
                        return Ok(None);
                    }
                    return team.get_core_memory_section(section);
                }
                Ok(None)
            }
        }
    }

    /// Tombstone a team-origin core section from the user perspective.
    /// Idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error if the tombstone db is unavailable / corrupt.
    pub fn tombstone_team_core(&self, section: &str) -> Result<()> {
        self.insert_core_tombstone(section)
    }

    /// Where the team store lives (if configured). For logging /
    /// diagnostics.
    #[must_use]
    pub fn team_path(&self) -> Option<PathBuf> {
        self.team.as_ref().map(|db| db.path().to_path_buf())
    }
}

/// An archival memory tagged with the scope it originated from. The
/// merged-read view uses this so callers can attribute each entry.
#[derive(Debug, Clone)]
pub struct ScopedArchival {
    pub scope: MemoryScope,
    pub entry: ArchivalMemory,
}

impl ScopedArchival {
    const fn user(entry: ArchivalMemory) -> Self {
        Self {
            scope: MemoryScope::User,
            entry,
        }
    }
    const fn team(entry: ArchivalMemory) -> Self {
        Self {
            scope: MemoryScope::Team,
            entry,
        }
    }

    const fn both(entry: ArchivalMemory) -> Self {
        Self {
            scope: MemoryScope::Both,
            entry,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_store(team: bool) -> (TempDir, TeamMemoryStore) {
        let tmp = TempDir::new().expect("tempdir");
        let user_path = tmp.path().join("user").join("memory.db");
        std::fs::create_dir_all(user_path.parent().unwrap()).unwrap();
        let team_path = if team {
            Some(tmp.path().join("team"))
        } else {
            None
        };
        let cfg = MemoryConfig {
            team_memory_path: team_path,
        };
        let store = TeamMemoryStore::open(&user_path, &cfg).expect("open store");
        (tmp, store)
    }

    /// #604 — With no team path configured, memory ops only touch the
    /// user store. The team accessor returns `None` and team-scoped
    /// operations error.
    #[test]
    fn issue_604_no_team_path_user_only() {
        let (_tmp, store) = make_store(false);
        assert!(!store.has_team());
        assert!(store.team().is_none());
        assert!(store.team_path().is_none());

        // Writes to User scope succeed and are visible.
        let id = store
            .save_archival(MemoryScope::User, "user-only", &[])
            .expect("save user");
        let listed = store
            .list_archival(MemoryScope::User, 10)
            .expect("list user");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].entry.id, id);
        assert_eq!(listed[0].scope, MemoryScope::User);

        // Team-scoped ops without a team store error out.
        let res = store.save_archival(MemoryScope::Team, "x", &[]);
        assert!(res.is_err(), "Team write must error without team path");
        let res = store.save_archival(MemoryScope::Both, "x", &[]);
        assert!(res.is_err(), "Both write must error without team path");
    }

    #[test]
    fn s053_user_and_team_roles_cannot_alias_one_physical_store() {
        let tmp = TempDir::new().unwrap();
        let user_path = tmp.path().join("memory.db");
        let cfg = MemoryConfig {
            team_memory_path: Some(tmp.path().to_path_buf()),
        };

        let error = TeamMemoryStore::open(&user_path, &cfg)
            .err()
            .expect("same physical database must fail closed");
        assert!(error.to_string().contains("same physical store"));
        assert!(!tmp.path().join("team_memory_sync.db").exists());
    }

    /// #604 — With `team_memory_path` set, a `Both` write places the
    /// content in both stores; a merged read returns it from both
    /// scopes.
    #[test]
    fn issue_604_both_write_visible_in_user_and_team() {
        let (_tmp, store) = make_store(true);
        assert!(store.has_team());

        store
            .save_archival(MemoryScope::Both, "shared note", &[])
            .expect("save both");

        let user_view = store
            .list_archival(MemoryScope::User, 10)
            .expect("list user");
        let team_view = store
            .list_archival(MemoryScope::Team, 10)
            .expect("list team");
        assert_eq!(user_view.len(), 1);
        assert_eq!(team_view.len(), 1);
        assert_eq!(user_view[0].entry.content, "shared note");
        assert_eq!(team_view[0].entry.content, "shared note");

        let merged = store
            .list_archival(MemoryScope::Both, 10)
            .expect("list merged");
        assert_eq!(
            merged.len(),
            1,
            "one logical revision must not be duplicated"
        );
        assert_eq!(merged[0].scope, MemoryScope::Both);
        assert_eq!(user_view[0].entry.logical_id, team_view[0].entry.logical_id);
        assert_eq!(
            user_view[0].entry.record_digest,
            team_view[0].entry.record_digest
        );
    }

    #[test]
    fn s053_completed_replication_operations_are_retired() {
        let (_tmp, store) = make_store(true);
        for index in 0..32 {
            store
                .save_archival(MemoryScope::Both, &format!("lesson {index}"), &[])
                .unwrap();
        }
        let conn = store.lock_sync().unwrap().unwrap();
        let operations: i64 = conn
            .query_row("SELECT COUNT(*) FROM replication_operations", [], |row| {
                row.get(0)
            })
            .unwrap();
        let enrolled: i64 = conn
            .query_row("SELECT COUNT(*) FROM replicated_memories", [], |row| {
                row.get(0)
            })
            .unwrap();
        drop(conn);
        assert_eq!(
            operations, 0,
            "completed operations must not consume a lifetime cap"
        );
        assert_eq!(
            enrolled, 32,
            "logical replica enrollment must remain durable"
        );
    }

    #[test]
    fn s053_replica_enrollment_cap_rejects_before_inserting_state() {
        let (_tmp, store) = make_store(true);
        let conn = store.lock_sync().unwrap().unwrap();
        conn.execute(
            r"WITH digits(d) AS (
                   VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9)
               ), numbers(n) AS (
                   SELECT 1 + a.d + 10*b.d + 100*c.d + 1000*d.d
                     FROM digits a, digits b, digits c, digits d
               )
               INSERT INTO replicated_memories(logical_id)
               SELECT printf('00000000-0000-4000-8000-%012x', n)
                 FROM numbers WHERE n <= ?1",
            params![i64::try_from(MAX_REPLICATED_LOGICAL_IDS).unwrap()],
        )
        .unwrap();
        drop(conn);
        let revision = MemoryRevision::new(
            "one enrollment beyond the budget".to_string(),
            Vec::new(),
            store
                .memory_provenance(MemoryScope::Both, "cap-test", "new", &[])
                .unwrap(),
        );

        let error = store
            .persist_replication_operation(&revision)
            .unwrap_err()
            .to_string();
        assert!(error.contains("replica identity budget exceeded"));
        let conn = store.lock_sync().unwrap().unwrap();
        let enrolled: i64 = conn
            .query_row("SELECT COUNT(*) FROM replicated_memories", [], |row| {
                row.get(0)
            })
            .unwrap();
        let operations: i64 = conn
            .query_row("SELECT COUNT(*) FROM replication_operations", [], |row| {
                row.get(0)
            })
            .unwrap();
        drop(conn);
        assert_eq!(enrolled, i64::try_from(MAX_REPLICATED_LOGICAL_IDS).unwrap());
        assert_eq!(operations, 0);
    }

    #[test]
    fn s053_operation_cap_rejects_before_enrolling_memory() {
        let (_tmp, store) = make_store(true);
        let conn = store.lock_sync().unwrap().unwrap();
        conn.execute(
            r"WITH digits(d) AS (
                   VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9)
               ), numbers(n) AS (
                   SELECT 1 + a.d + 10*b.d + 100*c.d + 1000*d.d
                     FROM digits a, digits b, digits c, digits d
               )
               INSERT INTO replication_operations(operation_id, revision_json)
               SELECT printf('pending-%04x', n), '{}'
                 FROM numbers WHERE n <= ?1",
            params![i64::try_from(MAX_PENDING_REPLICATION_OPERATIONS).unwrap()],
        )
        .unwrap();
        drop(conn);
        let revision = MemoryRevision::new(
            "one operation beyond the budget".to_string(),
            Vec::new(),
            store
                .memory_provenance(MemoryScope::Both, "cap-test", "new", &[])
                .unwrap(),
        );

        let error = store
            .persist_replication_operation(&revision)
            .unwrap_err()
            .to_string();
        assert!(error.contains("operation log exceeds reconciliation budget"));
        let conn = store.lock_sync().unwrap().unwrap();
        let enrolled: i64 = conn
            .query_row("SELECT COUNT(*) FROM replicated_memories", [], |row| {
                row.get(0)
            })
            .unwrap();
        let operations: i64 = conn
            .query_row("SELECT COUNT(*) FROM replication_operations", [], |row| {
                row.get(0)
            })
            .unwrap();
        drop(conn);
        assert_eq!(enrolled, 0);
        assert_eq!(
            operations,
            i64::try_from(MAX_PENDING_REPLICATION_OPERATIONS).unwrap()
        );
    }

    #[test]
    fn s053_tombstone_cap_rejects_before_hiding_another_memory() {
        let (_tmp, store) = make_store(true);
        let team_id = store
            .save_archival(MemoryScope::Team, "must remain visible", &[])
            .unwrap();
        let entry = store.team().unwrap().memory_get(team_id).unwrap().unwrap();
        let team_store_id = store.team_store_id().unwrap();
        let conn = store.lock_sync().unwrap().unwrap();
        conn.execute(
            r"WITH digits(d) AS (
                   VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9)
               ), numbers(n) AS (
                   SELECT 1 + a.d + 10*b.d + 100*c.d + 1000*d.d
                     FROM digits a, digits b, digits c, digits d
               )
               INSERT INTO archival_tombstones
                   (team_store_id, logical_id, source_version, source_digest)
               SELECT ?1, printf('00000000-0000-4000-8000-%012x', n), 1,
                      printf('sha256:%064x', n)
                 FROM numbers WHERE n <= ?2",
            params![
                team_store_id.to_string(),
                i64::try_from(MAX_ARCHIVAL_TOMBSTONES).unwrap()
            ],
        )
        .unwrap();
        drop(conn);

        let error = store
            .insert_archival_tombstone(&entry)
            .unwrap_err()
            .to_string();
        assert!(error.contains("archival tombstone budget exceeded"));
        let conn = store.lock_sync().unwrap().unwrap();
        let tombstones: i64 = conn
            .query_row("SELECT COUNT(*) FROM archival_tombstones", [], |row| {
                row.get(0)
            })
            .unwrap();
        drop(conn);
        assert_eq!(tombstones, i64::try_from(MAX_ARCHIVAL_TOMBSTONES).unwrap());
        assert!(store.team().unwrap().memory_get(team_id).unwrap().is_some());
    }

    #[test]
    fn s053_replaced_team_store_is_rejected_before_replay() {
        let tmp = TempDir::new().unwrap();
        let user_path = tmp.path().join("user").join("memory.db");
        std::fs::create_dir_all(user_path.parent().unwrap()).unwrap();
        let team_path = tmp.path().join("team");
        let cfg = MemoryConfig {
            team_memory_path: Some(team_path.clone()),
        };
        let store = TeamMemoryStore::open(&user_path, &cfg).unwrap();
        let original_team_id = store.team_store_id().unwrap();
        store
            .save_archival(MemoryScope::Both, "must not cross team replacement", &[])
            .unwrap();
        drop(store);

        std::fs::rename(&team_path, tmp.path().join("retired-team")).unwrap();
        let Err(error) = TeamMemoryStore::open(&user_path, &cfg) else {
            panic!("replacement store must not inherit sync authority");
        };
        assert!(error.to_string().contains("different team store"));

        let replacement = MemoryDb::open(&team_path.join("memory.db")).unwrap();
        assert_ne!(replacement.store_id().unwrap(), original_team_id);
        assert!(replacement.memory_list(10).unwrap().is_empty());
        assert_eq!(
            MemoryDb::open(&user_path)
                .unwrap()
                .memory_list(10)
                .unwrap()
                .len(),
            1
        );
    }

    /// #604 — A concurrent / merged read returns the union of user and
    /// team rows, with each scope-tagged. User and team rows that
    /// happen to share content are both returned because equal prose does not
    /// establish shared logical identity.
    #[test]
    fn issue_604_concurrent_read_returns_merged_view() {
        let (_tmp, store) = make_store(true);

        store
            .save_archival(MemoryScope::User, "alpha", &[])
            .expect("user save");
        store
            .save_archival(MemoryScope::Team, "beta", &[])
            .expect("team save");
        store
            .save_archival(MemoryScope::Team, "gamma", &[])
            .expect("team save");

        let merged = store
            .list_archival(MemoryScope::Both, 10)
            .expect("list both");
        let by_scope: Vec<(MemoryScope, String)> = merged
            .iter()
            .map(|m| (m.scope, m.entry.content.clone()))
            .collect();
        assert!(by_scope.contains(&(MemoryScope::User, "alpha".to_string())));
        assert!(by_scope.contains(&(MemoryScope::Team, "beta".to_string())));
        assert!(by_scope.contains(&(MemoryScope::Team, "gamma".to_string())));
        assert_eq!(merged.len(), 3);
    }

    /// #604 — A user tombstone shadows the team row on merged reads.
    /// The team row itself remains intact (Team-scoped read still
    /// sees it filtered, but a fresh `TeamMemoryStore` with a
    /// different user db would see it).
    #[test]
    fn issue_604_user_tombstone_overrides_team_entry() {
        let (_tmp, store) = make_store(true);

        let team_id = store
            .save_archival(MemoryScope::Team, "team-only", &[])
            .expect("team save");

        // Pre-condition: visible in merged view.
        let pre = store
            .list_archival(MemoryScope::Both, 10)
            .expect("list pre");
        assert_eq!(pre.len(), 1);

        // User tombstones the team id.
        store.tombstone_team_archival(team_id).expect("tombstone");

        let post = store
            .list_archival(MemoryScope::Both, 10)
            .expect("list post");
        assert!(
            post.is_empty(),
            "tombstoned team entry must not appear in merged view, got {post:?}"
        );

        // Same for explicit Team scope on this user's store: tombstone
        // applies to *this user's* view of the team store.
        let team_view = store
            .list_archival(MemoryScope::Team, 10)
            .expect("list team");
        assert!(
            team_view.is_empty(),
            "tombstone filters Team-scoped read too"
        );
    }

    #[test]
    fn s053_overlay_tombstone_does_not_hide_a_later_team_revision() {
        let (_tmp, store) = make_store(true);
        let team_id = store
            .save_archival(MemoryScope::Team, "old lesson", &[])
            .unwrap();
        store.tombstone_team_archival(team_id).unwrap();
        let team = store.team.as_ref().unwrap();
        assert!(team.memory_update(team_id, "corrected lesson").unwrap());

        let team_view = store.list_archival(MemoryScope::Team, 10).unwrap();
        assert_eq!(team_view.len(), 1);
        assert_eq!(team_view[0].entry.content, "corrected lesson");
        assert_eq!(team_view[0].entry.version.get(), 2);
        let both_view = store.list_archival(MemoryScope::Both, 10).unwrap();
        assert_eq!(both_view.len(), 1);
        assert_eq!(both_view[0].entry.content, "corrected lesson");
    }

    #[test]
    fn s053_concurrent_replica_branches_are_visible_conflicts() {
        let (_tmp, store) = make_store(true);
        let user_id = store
            .save_archival(MemoryScope::Both, "original lesson", &[])
            .unwrap();
        let root = store.user.revision_for_row(user_id).unwrap().unwrap();
        let left = root
            .successor(
                "user correction".to_string(),
                Vec::new(),
                store
                    .memory_provenance(MemoryScope::Both, "update", "user correction", &[])
                    .unwrap(),
            )
            .unwrap();
        let right = root
            .successor(
                "team correction".to_string(),
                Vec::new(),
                store
                    .memory_provenance(MemoryScope::Team, "update", "team correction", &[])
                    .unwrap(),
            )
            .unwrap();
        store.user.apply_revision(&left).unwrap();
        store.team.as_ref().unwrap().apply_revision(&right).unwrap();
        assert_eq!(store.reconcile_replica_histories().unwrap(), 2);
        assert_eq!(store.user.revision_heads(root.logical_id).unwrap().len(), 2);
        assert_eq!(
            store
                .team
                .as_ref()
                .unwrap()
                .revision_heads(root.logical_id)
                .unwrap()
                .len(),
            2
        );

        let merged = store.list_archival(MemoryScope::Both, 10).unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].scope, MemoryScope::Both);
        assert_eq!(merged[0].entry.logical_id, root.logical_id);
        assert_eq!(merged[0].entry.conflict_heads.len(), 2);
        assert!(merged[0]
            .entry
            .conflict_heads
            .iter()
            .any(|head| head.record_digest == left.record_digest));
        assert!(merged[0]
            .entry
            .conflict_heads
            .iter()
            .any(|head| head.record_digest == right.record_digest));
    }

    #[test]
    fn s053_equal_selected_revision_does_not_hide_a_remote_conflict_head() {
        let (_tmp, store) = make_store(true);
        let user_id = store.save_archival(MemoryScope::Both, "root", &[]).unwrap();
        let root = store.user.revision_for_row(user_id).unwrap().unwrap();
        let left = root
            .successor(
                "left".to_string(),
                Vec::new(),
                store
                    .memory_provenance(MemoryScope::Team, "left", "left", &[])
                    .unwrap(),
            )
            .unwrap();
        let right = root
            .successor(
                "right".to_string(),
                Vec::new(),
                store
                    .memory_provenance(MemoryScope::Team, "right", "right", &[])
                    .unwrap(),
            )
            .unwrap();
        let team = store.team.as_ref().unwrap();
        team.apply_revision(&left).unwrap();
        team.apply_revision(&right).unwrap();
        let team_projection = team.memory_list(10).unwrap().pop().unwrap();
        let selected = team
            .revision_by_digest(&team_projection.record_digest)
            .unwrap()
            .unwrap();
        store.user.apply_revision(&selected).unwrap();

        let merged = store.list_archival(MemoryScope::Both, 10).unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].entry.record_digest, team_projection.record_digest);
        assert_eq!(merged[0].entry.conflict_heads.len(), 2);
        assert!(merged[0]
            .entry
            .conflict_heads
            .iter()
            .any(|head| head.record_digest == left.record_digest));
        assert!(merged[0]
            .entry
            .conflict_heads
            .iter()
            .any(|head| head.record_digest == right.record_digest));
    }

    #[test]
    fn s053_both_delete_reconciles_an_offline_parent_before_tombstone() {
        let (_tmp, store) = make_store(true);
        let user_id = store.save_archival(MemoryScope::Both, "root", &[]).unwrap();
        let root = store.user.revision_for_row(user_id).unwrap().unwrap();
        let offline = root
            .successor(
                "offline correction".to_string(),
                Vec::new(),
                store
                    .memory_provenance(
                        MemoryScope::Both,
                        "offline-update",
                        "offline correction",
                        &[],
                    )
                    .unwrap(),
            )
            .unwrap();
        store.user.apply_revision(&offline).unwrap();
        assert!(store
            .team
            .as_ref()
            .unwrap()
            .revision_by_digest(&offline.record_digest)
            .unwrap()
            .is_none());

        assert!(store.delete_archival(MemoryScope::Both, user_id).unwrap());
        let team = store.team.as_ref().unwrap();
        assert!(team
            .revision_by_digest(&offline.record_digest)
            .unwrap()
            .is_some());
        assert_eq!(store.user.revision_heads(root.logical_id).unwrap().len(), 1);
        assert_eq!(team.revision_heads(root.logical_id).unwrap().len(), 1);
        assert_eq!(
            store.user.revision_heads(root.logical_id).unwrap()[0].state,
            MemoryRevisionState::Tombstone
        );
        assert_eq!(
            team.revision_heads(root.logical_id).unwrap()[0].state,
            MemoryRevisionState::Tombstone
        );
    }

    #[test]
    fn s053_both_delete_refuses_to_replicate_private_user_memory() {
        let (_tmp, store) = make_store(true);
        let user_id = store
            .save_archival(MemoryScope::User, "private", &[])
            .unwrap();
        let error = store
            .delete_archival(MemoryScope::Both, user_id)
            .unwrap_err()
            .to_string();
        assert!(error.contains("requires a team-shared"));
        assert!(store.user.memory_get(user_id).unwrap().is_some());
        assert!(store
            .team
            .as_ref()
            .unwrap()
            .memory_list(10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn s053_pending_both_write_replays_after_team_failure() {
        let tmp = TempDir::new().expect("tempdir");
        let user_path = tmp.path().join("user").join("memory.db");
        std::fs::create_dir_all(user_path.parent().unwrap()).unwrap();
        let team_path = tmp.path().join("team");
        let cfg = MemoryConfig {
            team_memory_path: Some(team_path.clone()),
        };
        let store = TeamMemoryStore::open(&user_path, &cfg).unwrap();
        store
            .team
            .as_ref()
            .unwrap()
            .execute_raw(
                "CREATE TRIGGER reject_replication BEFORE INSERT ON memory_revisions \
                 BEGIN SELECT RAISE(ABORT, 'injected team failure'); END;",
            )
            .unwrap();
        assert!(store
            .save_archival(MemoryScope::Both, "retryable lesson", &[])
            .is_err());
        assert_eq!(store.user.memory_list(10).unwrap().len(), 1);
        assert!(store
            .team
            .as_ref()
            .unwrap()
            .memory_list(10)
            .unwrap()
            .is_empty());
        drop(store);

        Connection::open(team_path.join("memory.db"))
            .unwrap()
            .execute_batch("DROP TRIGGER reject_replication;")
            .unwrap();
        let reopened = TeamMemoryStore::open(&user_path, &cfg).unwrap();
        assert_eq!(reopened.reconcile_pending_operations().unwrap(), 0);
        let user_rows = reopened.user.memory_list(10).unwrap();
        let team_rows = reopened.team.as_ref().unwrap().memory_list(10).unwrap();
        assert_eq!(user_rows.len(), 1);
        assert_eq!(team_rows.len(), 1);
        assert_eq!(user_rows[0].logical_id, team_rows[0].logical_id);
        assert_eq!(user_rows[0].record_digest, team_rows[0].record_digest);
    }

    /// Core memory: User-scope update is invisible to the team and
    /// vice-versa.
    #[test]
    fn issue_604_core_memory_scoping() {
        let (_tmp, store) = make_store(true);
        store
            .update_core(MemoryScope::User, "persona", "user persona")
            .unwrap();
        store
            .update_core(MemoryScope::Team, "persona", "team persona")
            .unwrap();

        let user = store
            .get_core_section(MemoryScope::User, "persona")
            .unwrap()
            .unwrap();
        let team = store
            .get_core_section(MemoryScope::Team, "persona")
            .unwrap()
            .unwrap();
        assert_eq!(user.content, "user persona");
        assert_eq!(team.content, "team persona");

        // Merged: user overrides team.
        let merged = store
            .get_core_section(MemoryScope::Both, "persona")
            .unwrap()
            .unwrap();
        assert_eq!(
            merged.content, "user persona",
            "Both must return user content (user overrides team)"
        );
    }

    /// `Both` core-memory write reflects last-write-wins on each
    /// physical store independently.
    #[test]
    fn issue_604_both_write_to_core_writes_both_stores() {
        let (_tmp, store) = make_store(true);
        store
            .update_core(MemoryScope::Both, "project_info", "v1")
            .unwrap();

        let u = store
            .get_core_section(MemoryScope::User, "project_info")
            .unwrap()
            .unwrap();
        let t = store
            .get_core_section(MemoryScope::Team, "project_info")
            .unwrap()
            .unwrap();
        assert_eq!(u.content, "v1");
        assert_eq!(t.content, "v1");

        // Subsequent User-only write — team copy stays at v1.
        store
            .update_core(MemoryScope::User, "project_info", "v2")
            .unwrap();
        let u2 = store
            .get_core_section(MemoryScope::User, "project_info")
            .unwrap()
            .unwrap();
        let t2 = store
            .get_core_section(MemoryScope::Team, "project_info")
            .unwrap()
            .unwrap();
        assert_eq!(u2.content, "v2");
        assert_eq!(t2.content, "v1");

        // Merged read returns the user value (last write to *user* wins
        // for the merged perspective).
        let m = store
            .get_core_section(MemoryScope::Both, "project_info")
            .unwrap()
            .unwrap();
        assert_eq!(m.content, "v2");
    }
}
