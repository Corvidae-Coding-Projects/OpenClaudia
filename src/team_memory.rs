//! Team memory store — per-user + optional shared team scope.
//!
//! This prototype is preserved for S-053/S-054, but production
//! [`crate::config::load_config`] rejects a configured team path. A shared
//! filesystem path alone does not establish membership, logical identity, or
//! atomic cross-store reconciliation, so frontends must not construct this as
//! an active service yet.
//!
//! Crosslink #604. Parity with Claude Code's `teamMemPaths.ts`: a project
//! may carry an additional *shared* memory directory that several users on
//! the same project read and write together. The shared store sits **next
//! to** the per-user store; nothing is mirrored automatically.
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
//! * [`MemoryScope::Both`] — *reads* return a merged view (user entries
//!   override team entries by id); *writes* go to both stores.
//!
//! # Precedence (user overrides team, last-write-wins)
//!
//! When the same logical key (`archival id`, `core section`) exists in
//! both stores, the merged read returns the **user** entry. Writes are
//! independent — a caller that writes to `Both` produces two physical
//! rows; if the caller subsequently writes to `User` only, the merged
//! read reflects the user row (the team row is unchanged but masked).
//!
//! # Tombstones
//!
//! A user-side delete of a team-origin entry is recorded in a sidecar
//! `tombstones.db` next to the user database. The tombstone shadows the
//! team row on subsequent merged reads. The team row is never touched.
//! This satisfies "User overrides Team" without giving every user write
//! access to the shared store.

use crate::config::MemoryConfig;
use crate::memory::{ArchivalMemory, CoreMemory, MemoryDb};
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

/// Selects which underlying store an operation participates against.
///
/// See module documentation for the read/write semantics of each
/// variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryScope {
    /// Per-user store only.
    User,
    /// Shared team store only. Operations error with
    /// [`TeamMemoryError::TeamUnavailable`] if no team path was
    /// configured.
    Team,
    /// Both stores. Reads merge (user overrides team, last-write-wins);
    /// writes target both physical stores.
    Both,
}

/// Errors that can arise from team-memory operations.
#[derive(Debug, thiserror::Error)]
pub enum TeamMemoryError {
    /// A scoped operation requested the team store but no team path is
    /// configured.
    #[error("team memory not configured")]
    TeamUnavailable,
}

/// The team-memory store: a per-user database plus an optional shared
/// team database, mediated through a [`MemoryScope`] selector.
///
/// Construct via [`TeamMemoryStore::open`]. Clone-friendly via internal
/// [`Arc`]s.
pub struct TeamMemoryStore {
    user: Arc<MemoryDb>,
    team: Option<Arc<MemoryDb>>,
    /// Tombstones for team-origin entries shadowed by user deletes. Held
    /// in a sidecar database alongside the user store. `None` when no
    /// team store is configured — tombstones only make sense relative
    /// to a team store.
    tombstones: Option<Mutex<Connection>>,
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

        let tombstones = match (&team, user_db_path.parent()) {
            (Some(_), Some(parent)) => {
                let tomb_path = parent.join("team_tombstones.db");
                let conn = Connection::open(&tomb_path)
                    .with_context(|| format!("opening tombstone db at {}", tomb_path.display()))?;
                conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS archival_tombstones (team_id INTEGER PRIMARY KEY);
                     CREATE TABLE IF NOT EXISTS core_tombstones (section TEXT PRIMARY KEY);",
                )
                .context("initialising tombstone schema")?;
                Some(Mutex::new(conn))
            }
            _ => None,
        };

        Ok(Self {
            user,
            team,
            tombstones,
        })
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

    fn lock_tombstones(&self) -> Option<Result<MutexGuard<'_, Connection>>> {
        self.tombstones.as_ref().map(|m| {
            m.lock()
                .map_err(|_| anyhow::anyhow!("tombstone mutex poisoned"))
        })
    }

    /// Returns the set of team archival IDs shadowed by a user-side
    /// delete. Empty when no team store / no tombstone db exists.
    fn archival_tombstones(&self) -> Result<HashSet<i64>> {
        let Some(guard) = self.lock_tombstones() else {
            return Ok(HashSet::new());
        };
        let conn = guard?;
        let mut stmt = conn.prepare("SELECT team_id FROM archival_tombstones")?;
        let rows: HashSet<i64> = stmt
            .query_map([], |row| row.get::<_, i64>(0))?
            .collect::<rusqlite::Result<HashSet<_>>>()?;
        drop(stmt);
        drop(conn);
        Ok(rows)
    }

    fn core_tombstones(&self) -> Result<HashSet<String>> {
        let Some(guard) = self.lock_tombstones() else {
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

    fn insert_archival_tombstone(&self, team_id: i64) -> Result<()> {
        let Some(guard) = self.lock_tombstones() else {
            return Ok(());
        };
        let conn = guard?;
        conn.execute(
            "INSERT OR IGNORE INTO archival_tombstones (team_id) VALUES (?1)",
            params![team_id],
        )?;
        drop(conn);
        Ok(())
    }

    fn insert_core_tombstone(&self, section: &str) -> Result<()> {
        let Some(guard) = self.lock_tombstones() else {
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

    /// Save an archival memory entry into the selected scope(s).
    ///
    /// * `User`  → writes only to the user db.
    /// * `Team`  → writes only to the team db (error if unavailable).
    /// * `Both`  → writes to user then team. The returned id is the
    ///   **user** rowid; team-side rowid is independent and not exposed
    ///   directly (callers re-read via [`Self::list_archival`] to see
    ///   the merged view).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying database write fails or if
    /// `Team` / `Both` is requested without a configured team store.
    pub fn save_archival(&self, scope: MemoryScope, content: &str, tags: &[String]) -> Result<i64> {
        match scope {
            MemoryScope::User => self.user.memory_save(content, tags),
            MemoryScope::Team => {
                let team = self.team.as_ref().ok_or(TeamMemoryError::TeamUnavailable)?;
                team.memory_save(content, tags)
            }
            MemoryScope::Both => {
                let team = self.team.as_ref().ok_or(TeamMemoryError::TeamUnavailable)?;
                let id = self.user.memory_save(content, tags)?;
                // Last-write-wins: the team copy is independent. We
                // intentionally ignore its rowid — the merged read
                // returns the user entry on collision anyway.
                let _ = team.memory_save(content, tags)?;
                Ok(id)
            }
        }
    }

    /// List archival memories from the selected scope.
    ///
    /// With [`MemoryScope::Both`] the returned vector is the union of
    /// user and team rows with team rows shadowed by tombstones removed
    /// first. Order: user rows in their natural list order, then
    /// surviving team rows.
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
                let rows = team.memory_list(limit)?;
                let tombstoned = self.archival_tombstones()?;
                Ok(rows
                    .into_iter()
                    .filter(|m| !tombstoned.contains(&m.id))
                    .map(ScopedArchival::team)
                    .collect())
            }
            MemoryScope::Both => {
                let user_rows = self.user.memory_list(limit)?;
                let team_rows = match &self.team {
                    Some(team) => team.memory_list(limit)?,
                    None => Vec::new(),
                };
                let tombstoned = self.archival_tombstones()?;
                let mut out: Vec<ScopedArchival> =
                    user_rows.into_iter().map(ScopedArchival::user).collect();
                for m in team_rows {
                    if tombstoned.contains(&m.id) {
                        continue;
                    }
                    out.push(ScopedArchival::team(m));
                }
                Ok(out)
            }
        }
    }

    /// Delete an archival entry by `(scope, id)`. Deleting a team
    /// entry from the `User` perspective inserts a *tombstone* —
    /// the team row itself is untouched. To physically remove a team
    /// row the caller must pass [`MemoryScope::Team`].
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
                // From the user's perspective, "delete from Both" means
                // delete the user row and tombstone the team-origin id.
                let user_removed = self.user.memory_delete(id)?;
                self.insert_archival_tombstone(id)?;
                Ok(user_removed)
            }
        }
    }

    /// Tombstone a team-origin archival id from the user perspective.
    /// The team row remains; merged reads stop returning it for this
    /// user. Idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error if the tombstone db is unavailable / corrupt.
    pub fn tombstone_team_archival(&self, team_id: i64) -> Result<()> {
        self.insert_archival_tombstone(team_id)
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
    }

    /// #604 — A concurrent / merged read returns the union of user and
    /// team rows, with each scope-tagged. User and team rows that
    /// happen to share content are both returned (the merge dedupes
    /// only by tombstone, not by content equality, since rowids are
    /// independent).
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
