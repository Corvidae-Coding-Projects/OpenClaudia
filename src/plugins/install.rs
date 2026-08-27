//! Installation tracking types for `installed_plugins.json` (V2 format).
//!
//! Persistence is scope-aware (crosslink #380): `Managed` and `User` entries
//! live in `~/.openclaudia/plugins/installed_plugins.json`, while `Project`
//! and `Local` entries live in `<project_root>/.openclaudia/plugins/installed_plugins.json`.
//! [`InstalledPlugins::load`] merges both files into one in-memory view; the
//! companion [`InstalledPlugins::save`] dispatches each entry back to the file
//! that owns its scope.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, error, warn};

use super::PluginError;

// ---------------------------------------------------------------------------
// Installation tracking (installed_plugins.json V2)
// ---------------------------------------------------------------------------

/// Installation scope for a plugin
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InstallScope {
    Managed,
    User,
    Project,
    Local,
}

impl InstallScope {
    /// Returns `true` for scopes that persist to the global (per-user) file:
    /// `Managed` and `User`. Returns `false` for `Project` and `Local`, which
    /// live in the per-project file under `<project_root>/.openclaudia/`.
    #[must_use]
    pub const fn is_global(&self) -> bool {
        matches!(self, Self::Managed | Self::User)
    }
}

impl std::fmt::Display for InstallScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Managed => write!(f, "managed"),
            Self::User => write!(f, "user"),
            Self::Project => write!(f, "project"),
            Self::Local => write!(f, "local"),
        }
    }
}

impl std::str::FromStr for InstallScope {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "managed" => Ok(Self::Managed),
            "user" => Ok(Self::User),
            "project" => Ok(Self::Project),
            "local" => Ok(Self::Local),
            _ => Err(format!(
                "Invalid scope '{s}'. Must be: managed, user, project, local"
            )),
        }
    }
}

/// A single installation entry for a plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInstallEntry {
    /// Installation scope
    pub scope: InstallScope,
    /// Project path (required for project/local scopes)
    #[serde(
        default,
        rename = "projectPath",
        skip_serializing_if = "Option::is_none"
    )]
    pub project_path: Option<String>,
    /// Absolute path to the installed plugin directory
    #[serde(rename = "installPath")]
    pub install_path: String,
    /// Currently installed version
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// ISO 8601 timestamp of installation
    #[serde(
        default,
        rename = "installedAt",
        skip_serializing_if = "Option::is_none"
    )]
    pub installed_at: Option<String>,
    /// ISO 8601 timestamp of last update
    #[serde(
        default,
        rename = "lastUpdated",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_updated: Option<String>,
    /// Git commit SHA for git-based plugins
    #[serde(
        default,
        rename = "gitCommitSha",
        skip_serializing_if = "Option::is_none"
    )]
    pub git_commit_sha: Option<String>,
}

/// Installed plugins tracking file (V2 format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPlugins {
    /// Schema version (always 2)
    pub version: u32,
    /// Map of plugin IDs (plugin@marketplace) to installation entries
    pub plugins: HashMap<String, Vec<PluginInstallEntry>>,
}

impl Default for InstalledPlugins {
    fn default() -> Self {
        Self {
            version: 2,
            plugins: HashMap::new(),
        }
    }
}

impl InstalledPlugins {
    /// Load both the global and per-project tracking files and merge them
    /// into a single in-memory view (crosslink #380).
    ///
    /// - Global file: `~/.openclaudia/plugins/installed_plugins.json` — owns
    ///   `Managed` and `User` entries.
    /// - Project file:
    ///   `<project_root>/.openclaudia/plugins/installed_plugins.json` — owns
    ///   `Project` and `Local` entries.
    ///
    /// Missing files are treated as empty (the common first-run case).
    /// Parse / read errors on either file degrade gracefully to "empty for
    /// that file" with a `warn!` log, matching the pre-#380 behavior so a
    /// corrupt project tracker can never wedge the entire install command.
    ///
    /// `project_root` should be the project's root directory (the same
    /// directory whose `.openclaudia/` subtree holds project-scoped state).
    pub fn load(project_root: &Path) -> Self {
        let mut merged = Self::default();

        // Global (User + Managed). If home_dir is unavailable there is no
        // global file to load — leave the global half empty.
        if let Some(global) = Self::global_file_path() {
            Self::merge_file_into(&global, &mut merged);
        } else {
            debug!("home_dir() is None; skipping global installed_plugins.json load");
        }

        // Project (Project + Local).
        let project = Self::project_file_path(project_root);
        Self::merge_file_into(&project, &mut merged);

        debug!(
            count = merged.plugins.len(),
            "Loaded installed plugins tracking (merged global + project)"
        );
        merged
    }

    /// Read a single tracking file (if it exists) and append its entries
    /// into `target`. Missing files are skipped silently; parse / read
    /// errors are logged and skipped.
    fn merge_file_into(path: &Path, target: &mut Self) {
        if !path.exists() {
            return;
        }
        match std::fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str::<Self>(&content) {
                Ok(data) => {
                    for (plugin_id, entries) in data.plugins {
                        let bucket = target.plugins.entry(plugin_id).or_default();
                        for entry in entries {
                            // Preserve existing dedup semantics from `upsert`
                            // (match by scope + project_path).
                            if let Some(existing) = bucket.iter_mut().find(|e| {
                                e.scope == entry.scope && e.project_path == entry.project_path
                            }) {
                                *existing = entry;
                            } else {
                                bucket.push(entry);
                            }
                        }
                    }
                }
                Err(e) => {
                    // Data-loss-on-corruption defense (crosslink #804): a
                    // parse failure used to silently degrade to "treat this
                    // file as empty", which the next `save()` would then
                    // happily overwrite with the empty in-memory view —
                    // erasing every prior install record.
                    //
                    // Preserve the bytes-on-disk as
                    // `<file>.corrupt-<unix_ts>.bak` BEFORE returning so the
                    // operator can inspect / restore them. We still degrade
                    // to "empty for this file" so the install command stays
                    // usable, but the surfaced `error!` line tells operators
                    // there's a backup to look at.
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs());
                    let backup = Self::corrupt_backup_path_resolve(path, ts);
                    match std::fs::rename(path, &backup) {
                        Ok(()) => {
                            error!(
                                path = ?path,
                                backup = ?backup,
                                error = %e,
                                "installed_plugins.json failed to parse; preserved corrupt copy as backup and starting with an empty view for this file"
                            );
                        }
                        Err(rename_err) => {
                            error!(
                                path = ?path,
                                backup = ?backup,
                                parse_error = %e,
                                rename_error = %rename_err,
                                "installed_plugins.json failed to parse; could not move corrupt copy aside — leaving original in place to avoid data loss and skipping this file"
                            );
                        }
                    }
                }
            },
            Err(e) => {
                warn!(path = ?path, error = %e, "Failed to read installed_plugins.json");
            }
        }
    }

    /// Build the backup path used when [`Self::merge_file_into`] finds a
    /// corrupt tracking file. The backup lives next to the original file as
    /// `<filename>.corrupt-<unix_seconds>.bak`. We never overwrite an
    /// existing backup — collisions just append `.dup` so the operator can
    /// see multiple corruption events without losing earlier evidence.
    fn corrupt_backup_path_resolve(path: &Path, ts: u64) -> PathBuf {
        let file_name = path.file_name().map_or_else(
            || "installed_plugins.json".to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut candidate = parent.join(format!("{file_name}.corrupt-{ts}.bak"));
        while candidate.exists() {
            let next = format!("{}.dup", candidate.display());
            candidate = PathBuf::from(next);
        }
        candidate
    }

    /// Persist this in-memory view back to disk by dispatching each entry to
    /// the file that owns its scope (crosslink #380).
    ///
    /// `Managed` / `User` entries are written to the global file, `Project` /
    /// `Local` entries to `<project_root>/.openclaudia/plugins/installed_plugins.json`.
    /// Each file is written atomically (write-temp + fsync + rename) and on
    /// Unix the resulting file is mode `0o600`.
    ///
    /// If at least one `Managed` / `User` entry exists and
    /// [`dirs::home_dir`] returns `None`, this function returns
    /// [`PluginError::IoError`] **without** falling back to a relative path —
    /// a relative fallback would silently fragment install state across
    /// different cwds.
    ///
    /// Either file is omitted entirely when it would contain no entries (so a
    /// project that only has `User`-scoped installs never creates a stray
    /// `.openclaudia/plugins/installed_plugins.json`).
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::IoError`] if serialization, write, fsync, or
    /// rename fails for either file, or if a User/Managed entry exists but
    /// `home_dir()` is `None`.
    pub fn save(&self, project_root: &Path) -> Result<(), PluginError> {
        let (global_view, project_view) = self.split_by_scope();

        // Global save — User / Managed scopes.
        if global_view.plugins.is_empty() {
            // Nothing to save globally. If the global file already exists
            // and is now empty (the last User/Managed entry was removed),
            // we still want it to reflect that. We only rewrite when the
            // file already exists — never create an empty file on demand.
            if let Some(path) = Self::global_file_path() {
                if path.exists() {
                    atomic_save_to(&global_view, &path)?;
                }
            }
        } else {
            let path = Self::global_file_path().ok_or_else(|| {
                PluginError::IoError(
                    "Cannot save User/Managed plugin entries: dirs::home_dir() returned None \
                     (refusing to write a relative-path fallback that would fragment install state)"
                        .to_string(),
                )
            })?;
            atomic_save_to(&global_view, &path)?;
        }

        // Project save — Project / Local scopes.
        // We rewrite the project file in both cases (non-empty view, or
        // empty view but file already exists) so the on-disk state stays
        // consistent with the in-memory view; the dedicated branches are
        // retained for explicit "create on demand only when needed" intent.
        let project_path = Self::project_file_path(project_root);
        if !project_view.plugins.is_empty() || project_path.exists() {
            atomic_save_to(&project_view, &project_path)?;
        }

        Ok(())
    }

    /// Split this in-memory view into (global, project) halves by scope.
    /// Entries are cloned into whichever half corresponds to their scope so
    /// each half is itself a valid [`InstalledPlugins`] that can be
    /// serialized standalone.
    fn split_by_scope(&self) -> (Self, Self) {
        let mut global = Self::default();
        let mut project = Self::default();
        for (plugin_id, entries) in &self.plugins {
            for entry in entries {
                let bucket = if entry.scope.is_global() {
                    global.plugins.entry(plugin_id.clone()).or_default()
                } else {
                    project.plugins.entry(plugin_id.clone()).or_default()
                };
                bucket.push(entry.clone());
            }
        }
        (global, project)
    }

    /// Add or update an installation entry.
    ///
    /// Existing entries with the same scope + `project_path` are replaced;
    /// otherwise the entry is appended.
    pub fn upsert(&mut self, plugin_id: &str, entry: PluginInstallEntry) {
        let entries = self.plugins.entry(plugin_id.to_string()).or_default();
        if let Some(existing) = entries
            .iter_mut()
            .find(|e| e.scope == entry.scope && e.project_path == entry.project_path)
        {
            *existing = entry;
        } else {
            entries.push(entry);
        }
    }

    /// Remove a plugin by ID
    pub fn remove(&mut self, plugin_id: &str) -> bool {
        self.plugins.remove(plugin_id).is_some()
    }

    /// Drop every entry whose `install_path` no longer exists on disk
    /// (crosslink #380). Plugin IDs whose entry vector becomes empty are
    /// removed entirely so the tracking file does not grow stale keys.
    ///
    /// Returns the number of entries that were removed.
    pub fn prune_stale(&mut self) -> usize {
        let mut removed = 0_usize;
        self.plugins.retain(|_plugin_id, entries| {
            let before = entries.len();
            entries.retain(|e| Path::new(&e.install_path).exists());
            removed += before - entries.len();
            !entries.is_empty()
        });
        removed
    }

    /// File path for the per-user / managed tracking file.
    ///
    /// Returns `None` when [`dirs::home_dir`] returns `None`. Callers must
    /// treat `None` as a hard error for `User` / `Managed` entries (no
    /// relative-path fallback — that path would silently follow the
    /// process cwd and fragment install state, crosslink #380).
    fn global_file_path() -> Option<PathBuf> {
        dirs::home_dir().map(|home| {
            home.join(".openclaudia")
                .join("plugins")
                .join("installed_plugins.json")
        })
    }

    /// File path for the per-project tracking file, rooted at `project_root`.
    fn project_file_path(project_root: &Path) -> PathBuf {
        project_root
            .join(".openclaudia")
            .join("plugins")
            .join("installed_plugins.json")
    }

    /// Get all plugin IDs
    #[must_use]
    pub fn plugin_ids(&self) -> Vec<&str> {
        self.plugins
            .keys()
            .map(std::string::String::as_str)
            .collect()
    }
}

/// Atomically write `view` to `path` (write-tmp + fsync + rename + mode 0o600).
///
/// Shared implementation behind [`InstalledPlugins::save`] so the global and
/// per-project halves go through the exact same write discipline.
fn atomic_save_to(view: &InstalledPlugins, path: &Path) -> Result<(), PluginError> {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| PluginError::IoError(e.to_string()))?;

        // Restrict the parent directory so only the owner can list it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let meta =
                std::fs::metadata(parent).map_err(|e| PluginError::IoError(e.to_string()))?;
            let mut perms = meta.permissions();
            perms.set_mode(0o700);
            std::fs::set_permissions(parent, perms)
                .map_err(|e| PluginError::IoError(e.to_string()))?;
        }
    }

    let json =
        serde_json::to_string_pretty(view).map_err(|e| PluginError::IoError(e.to_string()))?;

    // Collision-resistant tmp path (PID + monotonic counter) on the same
    // filesystem as the target — required for `rename(2)` to be atomic.
    let nonce = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp.{pid}.{nonce}", pid = std::process::id()));

    std::fs::write(&tmp, &json).map_err(|e| PluginError::IoError(e.to_string()))?;

    // Restrict permissions BEFORE the rename so the file is never
    // world-readable even momentarily.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| PluginError::IoError(e.to_string()))?;
    }

    {
        let f = std::fs::File::open(&tmp).map_err(|e| PluginError::IoError(e.to_string()))?;
        f.sync_all()
            .map_err(|e| PluginError::IoError(e.to_string()))?;
    }

    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        PluginError::IoError(e.to_string())
    })?;

    // The tracker is the active-generation pointer. Synchronize its parent
    // after rename so a power loss cannot expose the new filename without the
    // directory entry being durable.
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| PluginError::IoError(e.to_string()))?;
    }

    debug!(path = ?path, count = view.plugins.len(), "Saved installed plugins");
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod save_tests {
    use super::*;
    use tempfile::TempDir;

    fn user_entry(install_path: &str) -> PluginInstallEntry {
        PluginInstallEntry {
            scope: InstallScope::User,
            project_path: None,
            install_path: install_path.to_string(),
            version: Some("1.0.0".to_string()),
            installed_at: Some("2026-01-01T00:00:00Z".to_string()),
            last_updated: None,
            git_commit_sha: None,
        }
    }

    fn project_entry(project_path: &str, install_path: &str) -> PluginInstallEntry {
        PluginInstallEntry {
            scope: InstallScope::Project,
            project_path: Some(project_path.to_string()),
            install_path: install_path.to_string(),
            version: Some("1.0.0".to_string()),
            installed_at: Some("2026-01-01T00:00:00Z".to_string()),
            last_updated: None,
            git_commit_sha: None,
        }
    }

    fn managed_entry(install_path: &str) -> PluginInstallEntry {
        PluginInstallEntry {
            scope: InstallScope::Managed,
            project_path: None,
            install_path: install_path.to_string(),
            version: Some("1.0.0".to_string()),
            installed_at: None,
            last_updated: None,
            git_commit_sha: None,
        }
    }

    fn local_entry(project_path: &str, install_path: &str) -> PluginInstallEntry {
        PluginInstallEntry {
            scope: InstallScope::Local,
            project_path: Some(project_path.to_string()),
            install_path: install_path.to_string(),
            version: Some("0.1.0".to_string()),
            installed_at: None,
            last_updated: None,
            git_commit_sha: None,
        }
    }

    /// HOME-isolation harness for `save` / `load` — overrides `$HOME` (and
    /// `$USERPROFILE` on Windows) so that `dirs::home_dir()` resolves into a
    /// `TempDir` for the lifetime of the closure. Restored on drop, even on
    /// panic, so the suite-global env is never poisoned.
    ///
    /// All `save` / `load` tests in this module are serialized via [`HOME_LOCK`]
    /// because `std::env::set_var` mutates process-wide state.
    struct HomeGuard {
        prev_home: Option<std::ffi::OsString>,
        #[cfg(windows)]
        prev_userprofile: Option<std::ffi::OsString>,
    }

    impl HomeGuard {
        fn set(home: &Path) -> Self {
            let prev_home = std::env::var_os("HOME");
            std::env::set_var("HOME", home);
            #[cfg(windows)]
            let prev_userprofile = {
                let prev = std::env::var_os("USERPROFILE");
                std::env::set_var("USERPROFILE", home);
                prev
            };
            Self {
                prev_home,
                #[cfg(windows)]
                prev_userprofile,
            }
        }

        fn unset() -> Self {
            let prev_home = std::env::var_os("HOME");
            std::env::remove_var("HOME");
            #[cfg(windows)]
            let prev_userprofile = {
                let prev = std::env::var_os("USERPROFILE");
                std::env::remove_var("USERPROFILE");
                prev
            };
            Self {
                prev_home,
                #[cfg(windows)]
                prev_userprofile,
            }
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            match self.prev_home.take() {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            #[cfg(windows)]
            match self.prev_userprofile.take() {
                Some(v) => std::env::set_var("USERPROFILE", v),
                None => std::env::remove_var("USERPROFILE"),
            }
        }
    }

    /// Serializes all tests that touch `$HOME` so they don't trample each
    /// other when the suite is run with multiple threads.
    static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // -----------------------------------------------------------------
    // (1) Save with User-scope entry writes only to global file.
    // -----------------------------------------------------------------
    #[test]
    fn save_user_scope_writes_only_to_global_file() {
        let _guard = HOME_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let _h = HomeGuard::set(home.path());

        let mut ip = InstalledPlugins::default();
        ip.upsert("user-plugin@market", user_entry("/opt/user-plugin"));
        ip.save(project.path()).expect("save must succeed");

        let global = home
            .path()
            .join(".openclaudia/plugins/installed_plugins.json");
        let project_file = project
            .path()
            .join(".openclaudia/plugins/installed_plugins.json");

        assert!(global.exists(), "global file must exist");
        assert!(
            !project_file.exists(),
            "project file must NOT exist for user-only save"
        );

        let parsed: InstalledPlugins =
            serde_json::from_str(&std::fs::read_to_string(&global).unwrap()).unwrap();
        assert_eq!(parsed.plugins.len(), 1);
        assert_eq!(
            parsed.plugins["user-plugin@market"][0].scope,
            InstallScope::User
        );
    }

    // -----------------------------------------------------------------
    // (2) Save with Project-scope entry writes only to project file.
    // -----------------------------------------------------------------
    #[test]
    fn save_project_scope_writes_only_to_project_file() {
        let _guard = HOME_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let _h = HomeGuard::set(home.path());

        let mut ip = InstalledPlugins::default();
        ip.upsert(
            "proj-plugin@market",
            project_entry(
                project.path().to_str().unwrap(),
                "/opt/projects/x/.openclaudia/plugins/proj-plugin",
            ),
        );
        ip.save(project.path()).expect("save must succeed");

        let global = home
            .path()
            .join(".openclaudia/plugins/installed_plugins.json");
        let project_file = project
            .path()
            .join(".openclaudia/plugins/installed_plugins.json");

        assert!(
            !global.exists(),
            "global file must NOT exist for project-only save"
        );
        assert!(project_file.exists(), "project file must exist");

        let parsed: InstalledPlugins =
            serde_json::from_str(&std::fs::read_to_string(&project_file).unwrap()).unwrap();
        assert_eq!(parsed.plugins.len(), 1);
        assert_eq!(
            parsed.plugins["proj-plugin@market"][0].scope,
            InstallScope::Project
        );
    }

    // -----------------------------------------------------------------
    // (3) Save with mix writes both files correctly.
    // -----------------------------------------------------------------
    #[test]
    fn save_mixed_scopes_writes_to_correct_files() {
        let _guard = HOME_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let _h = HomeGuard::set(home.path());

        let mut ip = InstalledPlugins::default();
        ip.upsert("u@m", user_entry("/opt/u"));
        ip.upsert("mgr@m", managed_entry("/opt/mgr"));
        ip.upsert(
            "p@m",
            project_entry(project.path().to_str().unwrap(), "/proj/p"),
        );
        ip.upsert(
            "l@m",
            local_entry(project.path().to_str().unwrap(), "/proj/l"),
        );

        ip.save(project.path()).expect("save must succeed");

        let global_path = home
            .path()
            .join(".openclaudia/plugins/installed_plugins.json");
        let project_path = project
            .path()
            .join(".openclaudia/plugins/installed_plugins.json");

        let global: InstalledPlugins =
            serde_json::from_str(&std::fs::read_to_string(&global_path).unwrap()).unwrap();
        let project_file: InstalledPlugins =
            serde_json::from_str(&std::fs::read_to_string(&project_path).unwrap()).unwrap();

        // Global owns User + Managed only.
        let mut global_ids: Vec<&str> = global.plugins.keys().map(String::as_str).collect();
        global_ids.sort_unstable();
        assert_eq!(global_ids, vec!["mgr@m", "u@m"]);

        // Project owns Project + Local only.
        let mut project_ids: Vec<&str> = project_file.plugins.keys().map(String::as_str).collect();
        project_ids.sort_unstable();
        assert_eq!(project_ids, vec!["l@m", "p@m"]);

        // No leakage: a global-scoped id must NOT appear in the project
        // file and vice versa.
        assert!(!global.plugins.contains_key("p@m"));
        assert!(!global.plugins.contains_key("l@m"));
        assert!(!project_file.plugins.contains_key("u@m"));
        assert!(!project_file.plugins.contains_key("mgr@m"));
    }

    // -----------------------------------------------------------------
    // (4) Load merges both files; entries from each scope appear.
    // -----------------------------------------------------------------
    #[test]
    fn load_merges_global_and_project_files() {
        let _guard = HOME_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let _h = HomeGuard::set(home.path());

        // Round-trip via save so the on-disk layout is exactly what the
        // real save path produces.
        let mut writer = InstalledPlugins::default();
        writer.upsert("user-side@m", user_entry("/opt/user-side"));
        writer.upsert(
            "proj-side@m",
            project_entry(project.path().to_str().unwrap(), "/proj/proj-side"),
        );
        writer.save(project.path()).expect("save must succeed");

        let loaded = InstalledPlugins::load(project.path());
        assert_eq!(
            loaded.plugins.len(),
            2,
            "load must merge both files into one view"
        );
        assert_eq!(
            loaded.plugins["user-side@m"][0].scope,
            InstallScope::User,
            "user entry must be present after merge"
        );
        assert_eq!(
            loaded.plugins["proj-side@m"][0].scope,
            InstallScope::Project,
            "project entry must be present after merge"
        );
    }

    // -----------------------------------------------------------------
    // (5) prune_stale drops entries with nonexistent install_path.
    // -----------------------------------------------------------------
    #[test]
    fn prune_stale_drops_missing_install_paths() {
        let dir = TempDir::new().unwrap();
        let live_path = dir.path().join("live-plugin");
        std::fs::create_dir_all(&live_path).unwrap();
        let dead_path = dir.path().join("dead-plugin"); // never created

        let mut ip = InstalledPlugins::default();
        ip.upsert(
            "live@m",
            PluginInstallEntry {
                scope: InstallScope::User,
                project_path: None,
                install_path: live_path.to_string_lossy().to_string(),
                version: None,
                installed_at: None,
                last_updated: None,
                git_commit_sha: None,
            },
        );
        ip.upsert(
            "dead@m",
            PluginInstallEntry {
                scope: InstallScope::User,
                project_path: None,
                install_path: dead_path.to_string_lossy().to_string(),
                version: None,
                installed_at: None,
                last_updated: None,
                git_commit_sha: None,
            },
        );
        // A plugin id with one live and one dead entry — the live one must
        // survive and the dead one must go, plus the id must remain.
        ip.upsert(
            "mixed@m",
            PluginInstallEntry {
                scope: InstallScope::Project,
                project_path: Some("/proj/a".to_string()),
                install_path: live_path.to_string_lossy().to_string(),
                version: None,
                installed_at: None,
                last_updated: None,
                git_commit_sha: None,
            },
        );
        ip.upsert(
            "mixed@m",
            PluginInstallEntry {
                scope: InstallScope::Project,
                project_path: Some("/proj/b".to_string()),
                install_path: dead_path.to_string_lossy().to_string(),
                version: None,
                installed_at: None,
                last_updated: None,
                git_commit_sha: None,
            },
        );

        let removed = ip.prune_stale();
        assert_eq!(removed, 2, "two stale entries should have been removed");
        assert!(ip.plugins.contains_key("live@m"));
        assert!(
            !ip.plugins.contains_key("dead@m"),
            "ids whose entries all vanish must be dropped"
        );
        assert_eq!(
            ip.plugins["mixed@m"].len(),
            1,
            "live half of mixed id survives"
        );
        assert_eq!(
            ip.plugins["mixed@m"][0].project_path.as_deref(),
            Some("/proj/a")
        );
    }

    // -----------------------------------------------------------------
    // (6) home_dir=None + User-scope entry => save returns Err
    //     (no relative-path fallback).
    // -----------------------------------------------------------------
    #[test]
    fn save_errors_when_home_missing_and_user_entry_present() {
        let _guard = HOME_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let project = TempDir::new().unwrap();
        let _h = HomeGuard::unset();

        // Environmental gate: dirs::home_dir() ALSO consults getpwuid_r on
        // Linux when HOME is unset, so on developer machines (and most CI
        // runners) it still resolves to /etc/passwd's entry. Skip the body
        // when that happens — the precondition the test exercises only
        // holds in sandboxed environments where getpwuid_r is unavailable.
        // The save() code path is still covered indirectly by the other
        // save_* tests; this test is the explicit canary for the
        // home-dir-is-None branch in environments that produce that state.
        if dirs::home_dir().is_some() {
            eprintln!(
                "save_errors_when_home_missing_and_user_entry_present: \
                 skipping — dirs::home_dir() resolved via getpwuid_r even \
                 with HOME unset (typical on Linux dev machines / CI)"
            );
            return;
        }

        let mut ip = InstalledPlugins::default();
        ip.upsert("u@m", user_entry("/opt/u"));

        let result = ip.save(project.path());
        assert!(
            result.is_err(),
            "save must return Err when home_dir is None and a User entry exists"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("home_dir"),
            "error must mention home_dir, got: {err}"
        );

        // Critical invariant: NO relative-path file was created as a
        // fallback. Scan the cwd subtree we care about and confirm it.
        let relative_fallback = Path::new(".openclaudia/plugins/installed_plugins.json");
        assert!(
            !relative_fallback.exists(),
            "save must NOT create a relative-path fallback file"
        );
    }

    // -----------------------------------------------------------------
    // Pre-existing security + atomicity tests (mode 0o600 + concurrent
    // reads), rewritten to drive the new public `save` API.
    // -----------------------------------------------------------------

    /// On Unix, the saved file must be mode 0o600 (owner-rw only).
    #[test]
    #[cfg(unix)]
    fn save_creates_file_with_mode_0o600() {
        use std::os::unix::fs::PermissionsExt as _;

        let _guard = HOME_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let _h = HomeGuard::set(home.path());

        let mut ip = InstalledPlugins::default();
        ip.upsert("user-plugin@m", user_entry("/opt/user-plugin"));
        ip.save(project.path()).expect("save must succeed");

        let path = home
            .path()
            .join(".openclaudia/plugins/installed_plugins.json");
        assert!(path.exists(), "file must exist after save");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "file mode must be 0o600 (owner-rw only), got 0o{mode:o}"
        );
    }

    /// Concurrent readers always see complete, valid JSON — never a
    /// half-written file. Drives the per-project file, which is what
    /// `atomic_save_to` writes via the same code path as the global file.
    #[test]
    fn save_is_atomic_concurrent_reads_see_complete_content() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let _guard = HOME_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let _h = HomeGuard::set(home.path());

        let path = project
            .path()
            .join(".openclaudia/plugins/installed_plugins.json");

        // Pre-populate so the reader has something to open immediately.
        let mut seed = InstalledPlugins::default();
        seed.upsert(
            "seed@m",
            project_entry(project.path().to_str().unwrap(), "/proj/seed"),
        );
        seed.save(project.path()).unwrap();

        let done = Arc::new(AtomicBool::new(false));
        let done_reader = Arc::clone(&done);
        let path_reader = path;

        let reader = std::thread::spawn(move || {
            let mut snapshots: Vec<String> = Vec::new();
            while !done_reader.load(Ordering::Relaxed) {
                if let Ok(content) = std::fs::read_to_string(&path_reader) {
                    if !content.is_empty() {
                        snapshots.push(content);
                    }
                }
                std::hint::spin_loop();
            }
            snapshots
        });

        for i in 0_u32..50 {
            let mut ip = InstalledPlugins::default();
            ip.upsert(
                &format!("plugin-{i}@market"),
                project_entry(
                    project.path().to_str().unwrap(),
                    &format!("/proj/plugin-{i}"),
                ),
            );
            ip.save(project.path())
                .expect("concurrent save must succeed");
        }

        done.store(true, Ordering::Relaxed);
        let snapshots = reader.join().unwrap();

        for (idx, snap) in snapshots.iter().enumerate() {
            serde_json::from_str::<InstalledPlugins>(snap).unwrap_or_else(|e| {
                panic!(
                    "snapshot #{idx} is not valid JSON (atomicity violated): {e}\n\
                     Content: {snap}"
                )
            });
        }
    }
}
