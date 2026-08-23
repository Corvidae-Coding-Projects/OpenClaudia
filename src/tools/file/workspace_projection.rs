//! Transactional writable-project projection for sandboxed subprocesses.
//!
//! A writable Bubblewrap bind must never name the host project directly. On
//! Linux this module snapshots the project into harness-owned control state,
//! gives the sandbox a writable candidate, records which top-level entries the
//! child changed, and publishes only a validated candidate generation. The
//! host tree is therefore unchanged until a successful child has exited and
//! reconciliation has proved that the corresponding host entries still match
//! the immutable baseline.

#[cfg(not(target_os = "linux"))]
use crate::tools::security::ToolRunContext;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceProjectionReceipt {
    pub(crate) generation: String,
    pub(crate) proposal_digest: String,
    pub(crate) reconciled_digest: Option<String>,
    pub(crate) changed_entries: usize,
    pub(crate) published: bool,
}

#[derive(Debug)]
pub struct WorkspaceProjectionError {
    message: String,
    recovery_path: Option<PathBuf>,
}

impl WorkspaceProjectionError {
    fn rejected(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            recovery_path: None,
        }
    }

    fn recoverable(message: impl Into<String>, recovery_path: PathBuf) -> Self {
        Self {
            message: message.into(),
            recovery_path: Some(recovery_path),
        }
    }

    pub(crate) fn recovery_path(&self) -> Option<&Path> {
        self.recovery_path.as_deref()
    }
}

impl std::fmt::Display for WorkspaceProjectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)?;
        if let Some(path) = &self.recovery_path {
            write!(
                formatter,
                "; recoverable transaction retained at '{}'",
                path.display()
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for WorkspaceProjectionError {}

#[cfg(target_os = "linux")]
mod linux {
    use super::{WorkspaceProjectionError, WorkspaceProjectionReceipt};
    use crate::tools::security::ToolRunContext;
    use sha2::{Digest as _, Sha256};
    use std::collections::{BTreeSet, HashMap};
    use std::ffi::{CStr, CString, OsStr, OsString};
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    use std::path::{Component, Path, PathBuf};

    const MAX_SNAPSHOT_ENTRIES: usize = 1_000_000;
    const MAX_SNAPSHOT_LOGICAL_BYTES: u64 = 64 * 1024 * 1024 * 1024;
    const INOTIFY_MASK: u32 = libc::IN_ATTRIB
        | libc::IN_CLOSE_WRITE
        | libc::IN_CREATE
        | libc::IN_DELETE
        | libc::IN_DELETE_SELF
        | libc::IN_MODIFY
        | libc::IN_MOVE_SELF
        | libc::IN_MOVED_FROM
        | libc::IN_MOVED_TO;

    #[derive(Default)]
    struct SnapshotBudget {
        entries: usize,
        logical_bytes: u64,
    }

    impl SnapshotBudget {
        fn record(&mut self, bytes: u64) -> Result<(), String> {
            self.entries = self.entries.saturating_add(1);
            self.logical_bytes = self.logical_bytes.saturating_add(bytes);
            if self.entries > MAX_SNAPSHOT_ENTRIES {
                return Err(format!(
                    "Writable workspace snapshot exceeds {MAX_SNAPSHOT_ENTRIES} entries"
                ));
            }
            if self.logical_bytes > MAX_SNAPSHOT_LOGICAL_BYTES {
                return Err(format!(
                    "Writable workspace snapshot exceeds {MAX_SNAPSHOT_LOGICAL_BYTES} logical bytes"
                ));
            }
            Ok(())
        }
    }

    struct Directory(*mut libc::DIR);

    impl Drop for Directory {
        fn drop(&mut self) {
            // SAFETY: this guard uniquely owns the live DIR pointer.
            unsafe {
                libc::closedir(self.0);
            }
        }
    }

    struct ChangeWatcher {
        descriptor: OwnedFd,
        top_levels: HashMap<i32, Option<OsString>>,
    }

    impl ChangeWatcher {
        fn install(root: &Path) -> Result<Self, String> {
            // SAFETY: inotify_init1 has no pointer arguments and returns a new
            // descriptor on success.
            let raw = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
            if raw < 0 {
                return Err(format!(
                    "Cannot initialize workspace change monitor: {}",
                    std::io::Error::last_os_error()
                ));
            }
            // SAFETY: inotify_init1 returned a fresh owned descriptor.
            let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
            let mut watcher = Self {
                descriptor,
                top_levels: HashMap::new(),
            };
            watcher.install_directory_tree(root, None)?;
            Ok(watcher)
        }

        fn install_directory_tree(
            &mut self,
            directory: &Path,
            top_level: Option<&OsStr>,
        ) -> Result<(), String> {
            let entries = sorted_entries(directory)?;
            for entry in entries {
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).map_err(|error| {
                    format!(
                        "Cannot inspect projected workspace entry '{}': {error}",
                        path.display()
                    )
                })?;
                if metadata.is_dir() {
                    let child_top =
                        top_level.map_or_else(|| entry.file_name(), OsStr::to_os_string);
                    self.install_directory_tree(&path, Some(&child_top))?;
                }
            }
            let directory_c = path_cstring(directory)?;
            // SAFETY: the descriptor and NUL-terminated path remain live for
            // the call; the kernel copies the watch path.
            let watch = unsafe {
                libc::inotify_add_watch(
                    self.descriptor.as_raw_fd(),
                    directory_c.as_ptr(),
                    INOTIFY_MASK,
                )
            };
            if watch < 0 {
                return Err(format!(
                    "Cannot monitor projected workspace directory '{}': {}",
                    directory.display(),
                    std::io::Error::last_os_error()
                ));
            }
            self.top_levels
                .insert(watch, top_level.map(OsStr::to_os_string));
            Ok(())
        }

        fn changed_top_levels(&self) -> Result<BTreeSet<OsString>, String> {
            let mut changed = BTreeSet::new();
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                // SAFETY: buffer is writable for its complete length.
                let read = unsafe {
                    libc::read(
                        self.descriptor.as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                    )
                };
                if read < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::WouldBlock {
                        break;
                    }
                    return Err(format!("Cannot read workspace change monitor: {error}"));
                }
                if read == 0 {
                    break;
                }
                let read = usize::try_from(read)
                    .map_err(|_| "Invalid negative inotify byte count".to_string())?;
                let mut offset = 0usize;
                while offset < read {
                    let header_size = std::mem::size_of::<libc::inotify_event>();
                    if read - offset < header_size {
                        return Err("Truncated workspace change event".to_string());
                    }
                    // SAFETY: the length check above proves a full event
                    // header is present. read_unaligned handles buffer
                    // alignment.
                    let event = unsafe {
                        std::ptr::read_unaligned(
                            buffer.as_ptr().add(offset).cast::<libc::inotify_event>(),
                        )
                    };
                    if event.mask & libc::IN_Q_OVERFLOW != 0 {
                        return Err(
                            "Workspace change monitor overflowed; refusing reconciliation"
                                .to_string(),
                        );
                    }
                    let event_len = header_size.saturating_add(event.len as usize);
                    if event_len > read - offset {
                        return Err("Truncated workspace change event name".to_string());
                    }
                    match self.top_levels.get(&event.wd) {
                        Some(Some(top_level)) => {
                            changed.insert(top_level.clone());
                        }
                        Some(None) if event.len > 0 => {
                            let name_bytes = &buffer[offset + header_size..offset + event_len];
                            let name_len = name_bytes
                                .iter()
                                .position(|byte| *byte == 0)
                                .unwrap_or(name_bytes.len());
                            if name_len > 0 {
                                changed.insert(OsString::from_vec(name_bytes[..name_len].to_vec()));
                            }
                        }
                        _ => {}
                    }
                    offset = offset.saturating_add(event_len);
                }
            }
            Ok(changed)
        }
    }

    struct AppliedEntry {
        name: OsString,
        had_host_entry: bool,
        installed_candidate: bool,
    }

    #[derive(Clone, Copy)]
    struct CreatedControlDirectories {
        transaction_parent: bool,
        control_root: bool,
    }

    struct PreparationCleanup {
        transaction_root: PathBuf,
        transaction_parent: PathBuf,
        control_root: PathBuf,
        created: CreatedControlDirectories,
        armed: bool,
    }

    impl Drop for PreparationCleanup {
        fn drop(&mut self) {
            if self.armed {
                let removed = match fs::remove_dir_all(&self.transaction_root) {
                    Ok(()) => true,
                    Err(error) => error.kind() == std::io::ErrorKind::NotFound,
                };
                if removed {
                    cleanup_empty_control_parents(
                        &self.transaction_parent,
                        &self.control_root,
                        self.created,
                    );
                }
            }
        }
    }

    pub struct WorkspaceProjection {
        generation: String,
        project_root: PathBuf,
        transaction_root: PathBuf,
        baseline_root: PathBuf,
        candidate_root: PathBuf,
        backup_root: PathBuf,
        project_directory: File,
        candidate_directory: File,
        backup_directory: File,
        watcher: ChangeWatcher,
        hardlink_groups: Vec<BTreeSet<OsString>>,
        protected_paths: Vec<PathBuf>,
        private_cargo_target: bool,
        transaction_parent: PathBuf,
        control_root: PathBuf,
        created: CreatedControlDirectories,
        settled: bool,
    }

    impl WorkspaceProjection {
        #[allow(clippy::too_many_lines)]
        pub(crate) fn prepare(
            run: &ToolRunContext,
            permits_git_metadata: bool,
        ) -> Result<Option<Self>, String> {
            let project_root = run.project_root();
            if !run.permits_write(project_root) {
                return Ok(None);
            }

            let generation = uuid::Uuid::new_v4().to_string();
            let control_root = project_root.join(".openclaudia");
            let transaction_parent = control_root.join("sandbox-transactions");
            let created_control_root = symlink_metadata_optional(&control_root)?.is_none();
            let created_transaction_parent =
                symlink_metadata_optional(&transaction_parent)?.is_none();
            let created = CreatedControlDirectories {
                transaction_parent: created_transaction_parent,
                control_root: created_control_root,
            };
            let transaction_root = transaction_parent.join(&generation);
            let baseline_root = transaction_root.join("baseline");
            let candidate_root = transaction_root.join("candidate");
            let backup_root = transaction_root.join("backup");
            let mut preparation_cleanup = PreparationCleanup {
                transaction_root: transaction_root.clone(),
                transaction_parent: transaction_parent.clone(),
                control_root: control_root.clone(),
                created,
                armed: true,
            };
            for path in [
                &transaction_parent,
                &transaction_root,
                &baseline_root,
                &candidate_root,
                &backup_root,
            ] {
                crate::tools::file::create_run_control_directory(run, &path.to_string_lossy())?;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
                    format!(
                        "Cannot secure workspace transaction directory '{}': {error}",
                        path.display()
                    )
                })?;
            }

            let (_, project_handle) = run.root_handle_for(project_root, false)?;
            let project_directory = reopen_pinned_directory(project_handle)?;
            let root_entries = descriptor_entries(&project_directory)?;
            let has_cargo_manifest = root_entries.iter().any(|(name, stat)| {
                name == OsStr::new("Cargo.toml") && stat.st_mode & libc::S_IFMT == libc::S_IFREG
            });
            let cargo_target_is_mountable = root_entries
                .iter()
                .find(|(name, _)| name == OsStr::new("target"))
                .is_none_or(|(_, stat)| stat.st_mode & libc::S_IFMT == libc::S_IFDIR);
            let private_cargo_target = has_cargo_manifest && cargo_target_is_mountable;
            let mut budget = SnapshotBudget::default();
            let mut baseline_hardlinks = HashMap::new();
            clone_descriptor_tree(
                &project_directory,
                &baseline_root,
                0,
                permits_git_metadata,
                true,
                &mut budget,
                &mut baseline_hardlinks,
            )?;
            if private_cargo_target && !baseline_root.join("target").exists() {
                fs::create_dir(baseline_root.join("target")).map_err(|error| {
                    format!("Cannot create private Cargo target mountpoint: {error}")
                })?;
            }
            let baseline_directory = open_directory_nofollow(&baseline_root)?;
            let mut candidate_budget = SnapshotBudget::default();
            let mut candidate_hardlinks = HashMap::new();
            clone_descriptor_tree(
                &baseline_directory,
                &candidate_root,
                1,
                true,
                false,
                &mut candidate_budget,
                &mut candidate_hardlinks,
            )?;
            let hardlink_groups = internal_hardlink_top_levels(&candidate_root)?;
            let candidate_directory = open_directory_nofollow(&candidate_root)?;
            let backup_directory = open_directory_nofollow(&backup_root)?;
            let watcher = ChangeWatcher::install(&candidate_root)?;

            let mut protected_paths = run
                .denied_paths()
                .iter()
                .filter_map(|path| path.strip_prefix(project_root).ok())
                .filter(|path| !path.as_os_str().is_empty())
                .map(Path::to_path_buf)
                .collect::<Vec<_>>();
            for path in [PathBuf::from(".openclaudia"), PathBuf::from(".claude")] {
                if !protected_paths.contains(&path) {
                    protected_paths.push(path);
                }
            }
            if !permits_git_metadata {
                protected_paths.push(PathBuf::from(".git"));
            }
            protected_paths.sort();
            protected_paths.dedup();

            let projection = Self {
                generation,
                project_root: project_root.to_path_buf(),
                transaction_root,
                baseline_root,
                candidate_root,
                backup_root,
                project_directory,
                candidate_directory,
                backup_directory,
                watcher,
                hardlink_groups,
                protected_paths,
                private_cargo_target,
                transaction_parent,
                control_root,
                created,
                settled: false,
            };
            projection.write_journal("prepared", &[])?;
            preparation_cleanup.armed = false;
            tracing::info!(
                target: "openclaudia::workspace_projection",
                event = "workspace_projection_prepared",
                generation = %projection.generation,
                entries = budget.entries,
                logical_bytes = budget.logical_bytes,
                "Prepared isolated writable workspace generation"
            );
            Ok(Some(projection))
        }

        pub(crate) fn generation(&self) -> &str {
            &self.generation
        }

        pub(crate) fn transaction_parent(&self) -> &Path {
            &self.transaction_parent
        }

        pub(crate) const fn uses_private_cargo_target(&self) -> bool {
            self.private_cargo_target
        }

        pub(crate) fn duplicate_candidate_bind_fd(&self) -> Result<OwnedFd, String> {
            // SAFETY: fcntl duplicates the live candidate directory descriptor.
            let duplicated = unsafe {
                libc::fcntl(
                    self.candidate_directory.as_raw_fd(),
                    libc::F_DUPFD_CLOEXEC,
                    200,
                )
            };
            if duplicated < 0 {
                return Err(format!(
                    "Cannot duplicate projected workspace descriptor: {}",
                    std::io::Error::last_os_error()
                ));
            }
            // SAFETY: fcntl returned a fresh owned descriptor.
            Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
        }

        pub(crate) fn settle(
            &mut self,
            publish: bool,
        ) -> Result<WorkspaceProjectionReceipt, WorkspaceProjectionError> {
            self.reconcile(publish, true)
        }

        /// Reconcile one request made by a long-lived sandbox process while
        /// keeping its projected root usable for the next request.
        pub(crate) fn checkpoint(
            &mut self,
            publish: bool,
        ) -> Result<WorkspaceProjectionReceipt, WorkspaceProjectionError> {
            self.reconcile(publish, false)
        }

        #[allow(clippy::too_many_lines)]
        fn reconcile(
            &mut self,
            publish: bool,
            final_settlement: bool,
        ) -> Result<WorkspaceProjectionReceipt, WorkspaceProjectionError> {
            if self.settled {
                return Err(WorkspaceProjectionError::rejected(
                    "Workspace projection was already settled",
                ));
            }
            let mut changed = match self.watcher.changed_top_levels() {
                Ok(changed) => changed,
                Err(error) if !publish && !final_settlement => {
                    tracing::warn!(
                        target: "openclaudia::workspace_projection",
                        generation = %self.generation,
                        %error,
                        "Workspace change monitor failed during rollback; resetting the complete candidate"
                    );
                    union_entry_names(&self.baseline_root, &self.candidate_root)
                        .map_err(WorkspaceProjectionError::rejected)?
                }
                Err(error) if !publish => {
                    tracing::warn!(
                        target: "openclaudia::workspace_projection",
                        generation = %self.generation,
                        %error,
                        "Workspace change monitor failed after terminated process; discarding the transaction"
                    );
                    BTreeSet::new()
                }
                Err(error) => return Err(WorkspaceProjectionError::rejected(error)),
            };
            for group in &self.hardlink_groups {
                if group.iter().any(|name| changed.contains(name)) {
                    changed.extend(group.iter().cloned());
                }
            }

            if !publish {
                let changed = changed.into_iter().collect::<Vec<_>>();
                let proposal_digest = empty_or_digest(&changed);
                if final_settlement {
                    self.write_journal("rolled_back", &changed)
                        .map_err(WorkspaceProjectionError::rejected)?;
                    self.settled = true;
                    self.cleanup();
                } else {
                    self.reset_candidate(&changed)
                        .map_err(WorkspaceProjectionError::rejected)?;
                    self.write_journal("checkpoint_rolled_back", &changed)
                        .map_err(WorkspaceProjectionError::rejected)?;
                }
                return Ok(WorkspaceProjectionReceipt {
                    generation: self.generation.clone(),
                    proposal_digest,
                    reconciled_digest: None,
                    changed_entries: changed.len(),
                    published: false,
                });
            }

            let mut actual_changes = Vec::new();
            for name in changed {
                validate_component(&name).map_err(WorkspaceProjectionError::rejected)?;
                let relative = PathBuf::from(&name);
                let baseline = self.baseline_root.join(&relative);
                let candidate = self.candidate_root.join(&relative);
                validate_projected_difference(
                    &baseline,
                    &candidate,
                    &relative,
                    &self.protected_paths,
                )?;
                if !trees_equal(&baseline, &candidate)
                    .map_err(WorkspaceProjectionError::rejected)?
                {
                    actual_changes.push(name);
                }
            }
            let proposal_digest =
                proposal_digest(&self.baseline_root, &self.candidate_root, &actual_changes)
                    .map_err(WorkspaceProjectionError::rejected)?;

            if actual_changes.is_empty() {
                self.write_journal(
                    if final_settlement {
                        "no_changes"
                    } else {
                        "checkpoint_no_changes"
                    },
                    &actual_changes,
                )
                .map_err(WorkspaceProjectionError::rejected)?;
                if final_settlement {
                    self.settled = true;
                    self.cleanup();
                }
                return Ok(WorkspaceProjectionReceipt {
                    generation: self.generation.clone(),
                    proposal_digest,
                    reconciled_digest: Some(empty_or_digest(&actual_changes)),
                    changed_entries: actual_changes.len(),
                    published: true,
                });
            }

            for name in &actual_changes {
                let baseline = self.baseline_root.join(name);
                let host = self.project_root.join(name);
                if !trees_equal(&baseline, &host).map_err(WorkspaceProjectionError::rejected)? {
                    self.write_journal("conflict", &actual_changes)
                        .map_err(WorkspaceProjectionError::rejected)?;
                    self.settled = true;
                    self.cleanup();
                    return Err(WorkspaceProjectionError::rejected(format!(
                        "Workspace generation conflict at '{}'; the host changed after the sandbox snapshot",
                        host.display()
                    )));
                }
            }

            self.write_journal("applying", &actual_changes)
                .map_err(WorkspaceProjectionError::rejected)?;
            let mut applied = Vec::new();
            for name in &actual_changes {
                match self.apply_entry(name) {
                    Ok(entry) => applied.push(entry),
                    Err(error) => {
                        let rollback = self.rollback_entries(&applied);
                        if let Err(rollback_error) = rollback {
                            let _ = self.write_journal("recovery_required", &actual_changes);
                            self.settled = true;
                            return Err(WorkspaceProjectionError::recoverable(
                                format!(
                                    "Workspace reconciliation failed: {error}; rollback also failed: {rollback_error}"
                                ),
                                self.transaction_root.clone(),
                            ));
                        }
                        let _ = self.write_journal("rolled_back", &actual_changes);
                        self.settled = true;
                        self.cleanup();
                        return Err(WorkspaceProjectionError::rejected(format!(
                            "Workspace reconciliation failed and was rolled back: {error}"
                        )));
                    }
                }
            }

            if let Err(error) = self.project_directory.sync_all() {
                let _ = self.write_journal("durability_uncertain", &actual_changes);
                self.settled = true;
                return Err(WorkspaceProjectionError::recoverable(
                    format!(
                        "Workspace entries were published but project-directory durability is uncertain: {error}"
                    ),
                    self.transaction_root.clone(),
                ));
            }
            if let Err(error) = self.write_journal(
                if final_settlement {
                    "committed"
                } else {
                    "checkpoint_published"
                },
                &actual_changes,
            ) {
                self.settled = true;
                return Err(WorkspaceProjectionError::recoverable(
                    format!(
                        "Workspace entries were published but the durable commit receipt failed: {error}"
                    ),
                    self.transaction_root.clone(),
                ));
            }
            let reconciled_digest = proposal_digest.clone();
            if final_settlement {
                self.settled = true;
                self.cleanup();
            } else if let Err(error) = self.rebase_after_commit(&applied) {
                let _ = self.write_journal("recovery_required", &actual_changes);
                self.settled = true;
                return Err(WorkspaceProjectionError::recoverable(
                    format!(
                        "Workspace entries were published but the long-lived sandbox could not be rebased: {error}"
                    ),
                    self.transaction_root.clone(),
                ));
            }
            tracing::info!(
                target: "openclaudia::workspace_projection",
                event = if final_settlement {
                    "workspace_projection_committed"
                } else {
                    "workspace_projection_checkpointed"
                },
                generation = %self.generation,
                proposal_digest,
                changed_entries = actual_changes.len(),
                "Committed isolated writable workspace generation"
            );
            Ok(WorkspaceProjectionReceipt {
                generation: self.generation.clone(),
                proposal_digest: reconciled_digest.clone(),
                reconciled_digest: Some(reconciled_digest),
                changed_entries: actual_changes.len(),
                published: true,
            })
        }

        fn reset_candidate(&mut self, names: &[OsString]) -> Result<(), String> {
            let baseline_directory = open_directory_nofollow(&self.baseline_root)?;
            let mut hardlinks = HashMap::new();
            for name in names {
                validate_component(name)?;
                remove_staged_entry(&self.candidate_root.join(name))?;
                if entry_exists(&self.baseline_root, name)? {
                    let mut budget = SnapshotBudget::default();
                    clone_descriptor_entry(
                        &baseline_directory,
                        name,
                        &self.candidate_root,
                        1,
                        true,
                        true,
                        false,
                        &mut budget,
                        &mut hardlinks,
                    )?;
                }
            }
            self.watcher = ChangeWatcher::install(&self.candidate_root)?;
            Ok(())
        }

        fn rebase_after_commit(&mut self, applied: &[AppliedEntry]) -> Result<(), String> {
            let mut baseline_hardlinks = HashMap::new();
            for entry in applied {
                let name = &entry.name;
                remove_staged_entry(&self.baseline_root.join(name))?;
                if entry.installed_candidate {
                    let mut budget = SnapshotBudget::default();
                    clone_descriptor_entry(
                        &self.project_directory,
                        name,
                        &self.baseline_root,
                        0,
                        true,
                        true,
                        false,
                        &mut budget,
                        &mut baseline_hardlinks,
                    )?;
                }
            }

            let baseline_directory = open_directory_nofollow(&self.baseline_root)?;
            let mut candidate_hardlinks = HashMap::new();
            for entry in applied {
                let name = &entry.name;
                remove_staged_entry(&self.candidate_root.join(name))?;
                if entry.installed_candidate {
                    let mut budget = SnapshotBudget::default();
                    clone_descriptor_entry(
                        &baseline_directory,
                        name,
                        &self.candidate_root,
                        1,
                        true,
                        true,
                        false,
                        &mut budget,
                        &mut candidate_hardlinks,
                    )?;
                }
                if entry.had_host_entry {
                    remove_staged_entry(&self.backup_root.join(name))?;
                }
            }
            self.watcher = ChangeWatcher::install(&self.candidate_root)?;
            self.write_journal(
                "checkpointed",
                &applied
                    .iter()
                    .map(|entry| entry.name.clone())
                    .collect::<Vec<_>>(),
            )?;
            Ok(())
        }

        fn apply_entry(&self, name: &OsStr) -> Result<AppliedEntry, String> {
            let name_c = component_cstring(name)?;
            let baseline_exists = entry_exists(self.baseline_root.as_path(), name)?;
            let candidate_exists = entry_exists(self.candidate_root.as_path(), name)?;
            let host_exists = entry_exists(self.project_root.as_path(), name)?;
            if baseline_exists != host_exists {
                return Err(format!(
                    "Host entry '{}' changed existence before reconciliation",
                    self.project_root.join(name).display()
                ));
            }

            if host_exists {
                rename_noreplace(
                    self.project_directory.as_raw_fd(),
                    &name_c,
                    self.backup_directory.as_raw_fd(),
                    &name_c,
                )?;
                let backup = self.backup_root.join(name);
                let baseline = self.baseline_root.join(name);
                if !trees_equal(&backup, &baseline)? {
                    let _ = rename_noreplace(
                        self.backup_directory.as_raw_fd(),
                        &name_c,
                        self.project_directory.as_raw_fd(),
                        &name_c,
                    );
                    return Err(format!(
                        "Host entry '{}' raced reconciliation",
                        self.project_root.join(name).display()
                    ));
                }
            }

            if candidate_exists {
                if let Err(error) = rename_noreplace(
                    self.candidate_directory.as_raw_fd(),
                    &name_c,
                    self.project_directory.as_raw_fd(),
                    &name_c,
                ) {
                    if host_exists {
                        let _ = rename_noreplace(
                            self.backup_directory.as_raw_fd(),
                            &name_c,
                            self.project_directory.as_raw_fd(),
                            &name_c,
                        );
                    }
                    return Err(error);
                }
            }
            Ok(AppliedEntry {
                name: name.to_os_string(),
                had_host_entry: host_exists,
                installed_candidate: candidate_exists,
            })
        }

        fn rollback_entries(&self, applied: &[AppliedEntry]) -> Result<(), String> {
            for entry in applied.iter().rev() {
                let name_c = component_cstring(&entry.name)?;
                if entry.installed_candidate {
                    rename_noreplace(
                        self.project_directory.as_raw_fd(),
                        &name_c,
                        self.candidate_directory.as_raw_fd(),
                        &name_c,
                    )?;
                }
                if entry.had_host_entry {
                    rename_noreplace(
                        self.backup_directory.as_raw_fd(),
                        &name_c,
                        self.project_directory.as_raw_fd(),
                        &name_c,
                    )?;
                }
            }
            self.project_directory
                .sync_all()
                .map_err(|error| format!("Cannot sync rolled-back project directory: {error}"))
        }

        fn write_journal(&self, phase: &str, names: &[OsString]) -> Result<(), String> {
            let encoded_names = names
                .iter()
                .map(|name| hex_bytes(name.as_bytes()))
                .collect::<Vec<_>>();
            let document = serde_json::to_vec_pretty(&serde_json::json!({
                "schema_version": 1,
                "generation": self.generation,
                "project_root": self.project_root,
                "phase": phase,
                "top_level_names_hex": encoded_names,
            }))
            .map_err(|error| format!("Cannot encode workspace transaction journal: {error}"))?;
            let temporary = self.transaction_root.join("journal.json.tmp");
            let final_path = self.transaction_root.join("journal.json");
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|error| {
                    format!(
                        "Cannot open workspace transaction journal '{}': {error}",
                        temporary.display()
                    )
                })?;
            file.write_all(&document)
                .map_err(|error| format!("Cannot write workspace transaction journal: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("Cannot sync workspace transaction journal: {error}"))?;
            fs::rename(&temporary, &final_path).map_err(|error| {
                format!("Cannot publish workspace transaction journal: {error}")
            })?;
            File::open(&self.transaction_root)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("Cannot sync workspace transaction directory: {error}"))
        }

        fn cleanup(&self) {
            match fs::remove_dir_all(&self.transaction_root) {
                Ok(()) => cleanup_empty_control_parents(
                    &self.transaction_parent,
                    &self.control_root,
                    self.created,
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    cleanup_empty_control_parents(
                        &self.transaction_parent,
                        &self.control_root,
                        self.created,
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        target: "openclaudia::workspace_projection",
                        generation = %self.generation,
                        path = %self.transaction_root.display(),
                        %error,
                        "Workspace transaction cleanup was deferred"
                    );
                }
            }
        }
    }

    impl Drop for WorkspaceProjection {
        fn drop(&mut self) {
            if !self.settled {
                let _ = self.write_journal("abandoned", &[]);
                self.cleanup();
                self.settled = true;
            }
        }
    }

    fn cleanup_empty_control_parents(
        transaction_parent: &Path,
        control_root: &Path,
        created: CreatedControlDirectories,
    ) {
        if created.transaction_parent {
            let _ = fs::remove_dir(transaction_parent);
        }
        if created.control_root {
            let _ = fs::remove_dir(control_root);
        }
    }

    fn internal_hardlink_top_levels(root: &Path) -> Result<Vec<BTreeSet<OsString>>, String> {
        let mut groups: HashMap<(u64, u64), BTreeSet<OsString>> = HashMap::new();
        let mut stack = vec![(root.to_path_buf(), None::<OsString>)];
        while let Some((directory, top_level)) = stack.pop() {
            for entry in sorted_entries(&directory)? {
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).map_err(|error| {
                    format!(
                        "Cannot inspect projected workspace entry '{}': {error}",
                        path.display()
                    )
                })?;
                let entry_top = top_level.clone().unwrap_or_else(|| entry.file_name());
                if metadata.is_dir() {
                    stack.push((path, Some(entry_top)));
                } else if metadata.is_file() && metadata.nlink() > 1 {
                    groups
                        .entry((metadata.dev(), metadata.ino()))
                        .or_default()
                        .insert(entry_top);
                }
            }
        }
        Ok(groups.into_values().collect())
    }

    fn clone_descriptor_tree(
        source: &File,
        destination: &Path,
        depth: usize,
        include_git_metadata: bool,
        mask_cargo_targets: bool,
        budget: &mut SnapshotBudget,
        hardlinks: &mut HashMap<(u64, u64), PathBuf>,
    ) -> Result<(), String> {
        let before = source
            .metadata()
            .map_err(|error| format!("Cannot inspect snapshot source directory: {error}"))?;
        let entries = descriptor_entries(source)?;
        let mask_cargo_target_here = mask_cargo_targets
            && entries.iter().any(|(name, stat)| {
                name == OsStr::new("Cargo.toml") && stat.st_mode & libc::S_IFMT == libc::S_IFREG
            })
            && entries.iter().any(|(name, stat)| {
                name == OsStr::new("target") && stat.st_mode & libc::S_IFMT == libc::S_IFDIR
            });
        for (name, _) in entries {
            clone_descriptor_entry(
                source,
                &name,
                destination,
                depth,
                include_git_metadata,
                mask_cargo_targets,
                mask_cargo_target_here,
                budget,
                hardlinks,
            )?;
        }
        let after = source
            .metadata()
            .map_err(|error| format!("Cannot reinspect snapshot source directory: {error}"))?;
        if !same_directory_metadata(&before, &after) {
            return Err(
                "Workspace directory changed while its baseline snapshot was created; retry the command"
                    .to_string(),
            );
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn clone_descriptor_entry(
        source: &File,
        name: &OsStr,
        destination: &Path,
        depth: usize,
        include_git_metadata: bool,
        mask_cargo_targets: bool,
        mask_cargo_target_here: bool,
        budget: &mut SnapshotBudget,
        hardlinks: &mut HashMap<(u64, u64), PathBuf>,
    ) -> Result<(), String> {
        let stat = fstatat_child(source, name)?;
        budget.record(u64::try_from(stat.st_size).unwrap_or(u64::MAX))?;
        let destination_path = destination.join(name);
        let kind = stat.st_mode & libc::S_IFMT;
        let is_masked_control_entry = depth == 0
            && (name == OsStr::new(".openclaudia")
                || name == OsStr::new(".claude")
                || (!include_git_metadata && name == OsStr::new(".git")));
        let is_masked_cargo_target = mask_cargo_target_here && name == OsStr::new("target");
        if is_masked_control_entry || is_masked_cargo_target {
            create_placeholder(&destination_path, kind, stat.st_mode)?;
        } else if kind == libc::S_IFDIR {
            fs::create_dir(&destination_path).map_err(|error| {
                format!(
                    "Cannot create projected directory '{}': {error}",
                    destination_path.display()
                )
            })?;
            let child = openat_child(source, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
            clone_descriptor_tree(
                &child,
                &destination_path,
                depth.saturating_add(1),
                include_git_metadata,
                mask_cargo_targets,
                budget,
                hardlinks,
            )?;
            apply_directory_metadata(&destination_path, &stat)?;
        } else if kind == libc::S_IFREG {
            let key = (stat.st_dev, stat.st_ino);
            if stat.st_nlink > 1 {
                if let Some(existing) = hardlinks.get(&key) {
                    fs::hard_link(existing, &destination_path).map_err(|error| {
                        format!(
                            "Cannot preserve internal hardlink '{}': {error}",
                            destination_path.display()
                        )
                    })?;
                } else {
                    let child = openat_child(source, name, libc::O_RDONLY)?;
                    clone_regular_file(&child, &destination_path, &stat)?;
                    hardlinks.insert(key, destination_path.clone());
                }
            } else {
                let child = openat_child(source, name, libc::O_RDONLY)?;
                clone_regular_file(&child, &destination_path, &stat)?;
            }
        } else if kind == libc::S_IFLNK {
            let target = readlinkat_child(source, name)?;
            std::os::unix::fs::symlink(&target, &destination_path).map_err(|error| {
                format!(
                    "Cannot clone projected symlink '{}': {error}",
                    destination_path.display()
                )
            })?;
        } else {
            return Err(format!(
                "Refusing socket, FIFO, or device entry '{}' in writable workspace projection",
                destination_path.display()
            ));
        }
        let after = fstatat_child(source, name)?;
        if !same_source_stat(&stat, &after) {
            return Err(format!(
                "Workspace entry '{}' changed while its baseline snapshot was created",
                destination_path.display()
            ));
        }
        Ok(())
    }

    fn remove_staged_entry(path: &Path) -> Result<(), String> {
        let Some(metadata) = symlink_metadata_optional(path)? else {
            return Ok(());
        };
        let result = if metadata.is_dir() && !metadata.file_type().is_symlink() {
            fs::remove_dir_all(path)
        } else {
            fs::remove_file(path)
        };
        result.map_err(|error| {
            format!(
                "Cannot reset projected workspace entry '{}': {error}",
                path.display()
            )
        })
    }

    fn descriptor_entries(source: &File) -> Result<Vec<(OsString, libc::stat)>, String> {
        // SAFETY: fcntl duplicates the live directory descriptor.
        let duplicate = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(format!(
                "Cannot duplicate workspace directory descriptor: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: fdopendir takes ownership of the duplicate on success.
        let raw_directory = unsafe { libc::fdopendir(duplicate) };
        if raw_directory.is_null() {
            // SAFETY: fdopendir failed and retained no ownership.
            unsafe {
                libc::close(duplicate);
            }
            return Err(format!(
                "Cannot enumerate workspace directory descriptor: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: fdopendir returned a live DIR pointer. Duplicated directory
        // descriptors share an open-file-description cursor, so every bounded
        // enumeration must rewind explicitly before reading.
        unsafe {
            libc::rewinddir(raw_directory);
        }
        let directory = Directory(raw_directory);
        let mut entries = Vec::new();
        loop {
            // SAFETY: errno is thread-local on Linux.
            unsafe {
                *libc::__errno_location() = 0;
            }
            // SAFETY: directory owns a live DIR pointer.
            let entry = unsafe { libc::readdir(directory.0) };
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(0) {
                    break;
                }
                return Err(format!("Cannot enumerate workspace directory: {error}"));
            }
            // SAFETY: readdir returned a valid NUL-terminated name.
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            let name = OsString::from_vec(bytes.to_vec());
            let stat = fstatat_child(source, &name)?;
            entries.push((name, stat));
        }
        entries.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        Ok(entries)
    }

    fn openat_child(parent: &File, name: &OsStr, flags: i32) -> Result<File, String> {
        let name_c = component_cstring(name)?;
        // SAFETY: parent and name are valid; O_NOFOLLOW prevents redirection.
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name_c.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(format!(
                "Cannot open workspace snapshot entry '{}': {}",
                name.to_string_lossy(),
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: openat returned a fresh owned descriptor.
        Ok(unsafe { File::from_raw_fd(raw) })
    }

    fn fstatat_child(parent: &File, name: &OsStr) -> Result<libc::stat, String> {
        let name_c = component_cstring(name)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: arguments are valid and AT_SYMLINK_NOFOLLOW inspects the
        // named object itself.
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name_c.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(format!(
                "Cannot inspect workspace snapshot entry '{}': {}",
                name.to_string_lossy(),
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: fstatat initialized stat on success.
        Ok(unsafe { stat.assume_init() })
    }

    fn readlinkat_child(parent: &File, name: &OsStr) -> Result<OsString, String> {
        let name_c = component_cstring(name)?;
        let mut capacity = 256usize;
        loop {
            let mut bytes = vec![0u8; capacity];
            // SAFETY: the buffer is writable and name is NUL-terminated.
            let read = unsafe {
                libc::readlinkat(
                    parent.as_raw_fd(),
                    name_c.as_ptr(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            };
            if read < 0 {
                return Err(format!(
                    "Cannot read workspace symlink '{}': {}",
                    name.to_string_lossy(),
                    std::io::Error::last_os_error()
                ));
            }
            let read =
                usize::try_from(read).map_err(|_| "Invalid symlink byte count".to_string())?;
            if read < bytes.len() {
                bytes.truncate(read);
                return Ok(OsString::from_vec(bytes));
            }
            capacity = capacity
                .checked_mul(2)
                .filter(|value| *value <= 1024 * 1024)
                .ok_or_else(|| "Workspace symlink target exceeds 1 MiB".to_string())?;
        }
    }

    fn clone_regular_file(
        source: &File,
        destination: &Path,
        stat: &libc::stat,
    ) -> Result<(), String> {
        let mut target = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(destination)
            .map_err(|error| {
                format!(
                    "Cannot create projected file '{}': {error}",
                    destination.display()
                )
            })?;
        // SAFETY: both descriptors are regular files. FICLONE either creates
        // an independent copy-on-write extent mapping or fails without
        // changing the source.
        let cloned =
            unsafe { libc::ioctl(target.as_raw_fd(), 0x4004_9409, source.as_raw_fd()) } == 0;
        if !cloned {
            let clone_error = std::io::Error::last_os_error();
            if !matches!(
                clone_error.raw_os_error(),
                Some(libc::EOPNOTSUPP | libc::EXDEV | libc::EINVAL | libc::ENOTTY)
            ) {
                return Err(format!(
                    "Cannot reflink projected file '{}': {clone_error}",
                    destination.display()
                ));
            }
            let mut source = source
                .try_clone()
                .map_err(|error| format!("Cannot duplicate workspace source file: {error}"))?;
            source
                .seek(SeekFrom::Start(0))
                .map_err(|error| format!("Cannot seek workspace source file: {error}"))?;
            target.set_len(0).map_err(|error| {
                format!(
                    "Cannot reset projected file '{}': {error}",
                    destination.display()
                )
            })?;
            std::io::copy(&mut source, &mut target).map_err(|error| {
                format!(
                    "Cannot copy projected file '{}': {error}",
                    destination.display()
                )
            })?;
        }
        set_file_metadata(&target, stat, destination)
    }

    fn set_file_metadata(file: &File, stat: &libc::stat, path: &Path) -> Result<(), String> {
        // SAFETY: file is live and mode is masked to permission bits.
        if unsafe { libc::fchmod(file.as_raw_fd(), stat.st_mode & 0o7777) } != 0 {
            return Err(format!(
                "Cannot preserve projected permissions for '{}': {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        let times = [
            libc::timespec {
                tv_sec: stat.st_atime,
                tv_nsec: stat.st_atime_nsec,
            },
            libc::timespec {
                tv_sec: stat.st_mtime,
                tv_nsec: stat.st_mtime_nsec,
            },
        ];
        // SAFETY: times points to exactly two valid timespec values.
        if unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) } != 0 {
            return Err(format!(
                "Cannot preserve projected timestamps for '{}': {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn apply_directory_metadata(path: &Path, stat: &libc::stat) -> Result<(), String> {
        fs::set_permissions(path, fs::Permissions::from_mode(stat.st_mode & 0o7777)).map_err(
            |error| {
                format!(
                    "Cannot preserve projected directory permissions '{}': {error}",
                    path.display()
                )
            },
        )?;
        let directory = open_directory_nofollow(path)?;
        set_file_metadata(&directory, stat, path)
    }

    fn create_placeholder(
        path: &Path,
        kind: libc::mode_t,
        mode: libc::mode_t,
    ) -> Result<(), String> {
        if kind == libc::S_IFDIR {
            fs::create_dir(path).map_err(|error| {
                format!(
                    "Cannot create protected directory placeholder '{}': {error}",
                    path.display()
                )
            })?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777)).map_err(|error| {
                format!(
                    "Cannot secure protected directory placeholder '{}': {error}",
                    path.display()
                )
            })
        } else if kind == libc::S_IFREG {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode & 0o7777)
                .open(path)
                .map(|_| ())
                .map_err(|error| {
                    format!(
                        "Cannot create protected file placeholder '{}': {error}",
                        path.display()
                    )
                })
        } else {
            Err(format!(
                "Protected control entry '{}' is neither a regular file nor a directory",
                path.display()
            ))
        }
    }

    fn validate_projected_difference(
        baseline: &Path,
        candidate: &Path,
        relative: &Path,
        protected_paths: &[PathBuf],
    ) -> Result<(), WorkspaceProjectionError> {
        let equal = trees_equal(baseline, candidate).map_err(WorkspaceProjectionError::rejected)?;
        if equal {
            return Ok(());
        }
        if protected_paths
            .iter()
            .any(|protected| relative == protected || relative.starts_with(protected))
        {
            return Err(WorkspaceProjectionError::rejected(format!(
                "Sandbox attempted to change protected workspace path '{}'",
                relative.display()
            )));
        }

        let baseline_metadata =
            symlink_metadata_optional(baseline).map_err(WorkspaceProjectionError::rejected)?;
        let candidate_metadata =
            symlink_metadata_optional(candidate).map_err(WorkspaceProjectionError::rejected)?;
        if candidate_metadata
            .as_ref()
            .is_some_and(|metadata| metadata.file_type().is_symlink())
        {
            let unchanged_link = baseline_metadata
                .as_ref()
                .is_some_and(|metadata| metadata.file_type().is_symlink())
                && fs::read_link(baseline).ok() == fs::read_link(candidate).ok();
            if !unchanged_link {
                let target = fs::read_link(candidate).map_err(|error| {
                    WorkspaceProjectionError::rejected(format!(
                        "Cannot inspect projected symlink '{}': {error}",
                        relative.display()
                    ))
                })?;
                validate_symlink_target(relative, &target)?;
            }
            return Ok(());
        }
        if candidate_metadata
            .as_ref()
            .is_some_and(|metadata| metadata.is_file() && metadata.nlink() > 1)
            && !baseline_metadata.as_ref().is_some_and(|metadata| {
                metadata.is_file()
                    && metadata.nlink()
                        == candidate_metadata
                            .as_ref()
                            .map_or(0, std::os::unix::fs::MetadataExt::nlink)
            })
        {
            return Err(WorkspaceProjectionError::rejected(format!(
                "Sandbox changed a hardlinked workspace file at '{}'",
                relative.display()
            )));
        }
        if candidate_metadata.as_ref().is_some_and(|metadata| {
            let kind = metadata.file_type();
            !(kind.is_dir() || kind.is_file() || kind.is_symlink())
        }) {
            return Err(WorkspaceProjectionError::rejected(format!(
                "Sandbox created unsupported special entry '{}'",
                relative.display()
            )));
        }

        let baseline_is_dir = baseline_metadata.as_ref().is_some_and(fs::Metadata::is_dir);
        let candidate_is_dir = candidate_metadata
            .as_ref()
            .is_some_and(fs::Metadata::is_dir);
        if baseline_is_dir || candidate_is_dir {
            let names = union_entry_names(baseline, candidate)
                .map_err(WorkspaceProjectionError::rejected)?;
            for name in names {
                validate_component(&name).map_err(WorkspaceProjectionError::rejected)?;
                validate_projected_difference(
                    &baseline.join(&name),
                    &candidate.join(&name),
                    &relative.join(&name),
                    protected_paths,
                )?;
            }
        }
        Ok(())
    }

    fn validate_symlink_target(
        relative: &Path,
        target: &Path,
    ) -> Result<(), WorkspaceProjectionError> {
        if target.is_absolute() {
            return Err(WorkspaceProjectionError::rejected(format!(
                "Sandbox created absolute symlink '{}' -> '{}'",
                relative.display(),
                target.display()
            )));
        }
        let parent = relative.parent().unwrap_or_else(|| Path::new(""));
        let mut depth = parent
            .components()
            .filter(|component| matches!(component, Component::Normal(_)))
            .count();
        for component in target.components() {
            match component {
                Component::Normal(_) => depth = depth.saturating_add(1),
                Component::CurDir => {}
                Component::ParentDir if depth > 0 => depth -= 1,
                Component::ParentDir => {
                    return Err(WorkspaceProjectionError::rejected(format!(
                        "Sandbox symlink '{}' escapes the workspace",
                        relative.display()
                    )))
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(WorkspaceProjectionError::rejected(format!(
                        "Sandbox symlink '{}' has a non-relative target",
                        relative.display()
                    )))
                }
            }
        }
        Ok(())
    }

    fn trees_equal(left: &Path, right: &Path) -> Result<bool, String> {
        let (left_metadata, right_metadata) = match (
            symlink_metadata_optional(left)?,
            symlink_metadata_optional(right)?,
        ) {
            (None, None) => return Ok(true),
            (Some(left_metadata), Some(right_metadata)) => (left_metadata, right_metadata),
            (None, Some(_)) | (Some(_), None) => return Ok(false),
        };
        let left_kind = left_metadata.file_type();
        let right_kind = right_metadata.file_type();
        if left_kind.is_file() != right_kind.is_file()
            || left_kind.is_dir() != right_kind.is_dir()
            || left_kind.is_symlink() != right_kind.is_symlink()
            || (left_metadata.mode() & 0o7777) != (right_metadata.mode() & 0o7777)
            || left_metadata.mtime() != right_metadata.mtime()
            || left_metadata.mtime_nsec() != right_metadata.mtime_nsec()
        {
            return Ok(false);
        }
        if left_kind.is_symlink() {
            return Ok(fs::read_link(left).ok() == fs::read_link(right).ok());
        }
        if left_kind.is_file() {
            if left_metadata.len() != right_metadata.len() {
                return Ok(false);
            }
            return files_equal(left, right);
        }
        if left_kind.is_dir() {
            let names = union_entry_names(left, right)?;
            for name in names {
                if !trees_equal(&left.join(&name), &right.join(&name))? {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn files_equal(left: &Path, right: &Path) -> Result<bool, String> {
        let mut left = File::open(left)
            .map_err(|error| format!("Cannot open baseline file '{}': {error}", left.display()))?;
        let mut right = File::open(right).map_err(|error| {
            format!("Cannot open candidate file '{}': {error}", right.display())
        })?;
        let mut left_buffer = vec![0u8; 64 * 1024].into_boxed_slice();
        let mut right_buffer = vec![0u8; 64 * 1024].into_boxed_slice();
        loop {
            let left_read = left
                .read(&mut left_buffer)
                .map_err(|error| format!("Cannot read baseline file: {error}"))?;
            let right_read = right
                .read(&mut right_buffer)
                .map_err(|error| format!("Cannot read candidate file: {error}"))?;
            if left_read != right_read {
                return Ok(false);
            }
            if left_buffer[..left_read] != right_buffer[..left_read] {
                return Ok(false);
            }
            if left_read == 0 {
                return Ok(true);
            }
        }
    }

    fn proposal_digest(
        baseline_root: &Path,
        candidate_root: &Path,
        names: &[OsString],
    ) -> Result<String, String> {
        let mut digest = Sha256::new();
        for name in names {
            digest.update((name.as_bytes().len() as u64).to_le_bytes());
            digest.update(name.as_bytes());
            digest_tree(&mut digest, &baseline_root.join(name))?;
            digest_tree(&mut digest, &candidate_root.join(name))?;
        }
        let finalized = digest.finalize();
        Ok(format!("sha256:{}", hex_bytes(finalized.as_ref())))
    }

    fn digest_tree(digest: &mut Sha256, path: &Path) -> Result<(), String> {
        let Some(metadata) = symlink_metadata_optional(path)? else {
            digest.update(b"missing");
            return Ok(());
        };
        digest.update((metadata.mode() & 0o7777).to_le_bytes());
        digest.update(metadata.mtime().to_le_bytes());
        digest.update(metadata.mtime_nsec().to_le_bytes());
        if metadata.file_type().is_symlink() {
            digest.update(b"link");
            digest.update(
                fs::read_link(path)
                    .map_err(|error| {
                        format!("Cannot digest symlink '{}': {error}", path.display())
                    })?
                    .as_os_str()
                    .as_bytes(),
            );
        } else if metadata.is_file() {
            digest.update(b"file");
            let mut file = File::open(path)
                .map_err(|error| format!("Cannot digest file '{}': {error}", path.display()))?;
            let mut buffer = vec![0u8; 64 * 1024].into_boxed_slice();
            loop {
                let read = file
                    .read(&mut buffer)
                    .map_err(|error| format!("Cannot digest file '{}': {error}", path.display()))?;
                if read == 0 {
                    break;
                }
                digest.update(&buffer[..read]);
            }
        } else if metadata.is_dir() {
            digest.update(b"dir");
            for entry in sorted_entries(path)? {
                let name = entry.file_name();
                digest.update((name.as_bytes().len() as u64).to_le_bytes());
                digest.update(name.as_bytes());
                digest_tree(digest, &entry.path())?;
            }
        } else {
            return Err(format!("Cannot digest special entry '{}'", path.display()));
        }
        Ok(())
    }

    fn empty_or_digest(names: &[OsString]) -> String {
        let mut digest = Sha256::new();
        for name in names {
            digest.update(name.as_bytes());
        }
        let finalized = digest.finalize();
        format!("sha256:{}", hex_bytes(finalized.as_ref()))
    }

    fn union_entry_names(left: &Path, right: &Path) -> Result<BTreeSet<OsString>, String> {
        let mut names = BTreeSet::new();
        for directory in [left, right] {
            match fs::read_dir(directory) {
                Ok(entries) => {
                    for entry in entries {
                        names.insert(
                            entry
                                .map_err(|error| {
                                    format!(
                                        "Cannot enumerate transaction directory '{}': {error}",
                                        directory.display()
                                    )
                                })?
                                .file_name(),
                        );
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) => {}
                Err(error) => {
                    return Err(format!(
                        "Cannot enumerate transaction directory '{}': {error}",
                        directory.display()
                    ))
                }
            }
        }
        Ok(names)
    }

    fn sorted_entries(path: &Path) -> Result<Vec<fs::DirEntry>, String> {
        let mut entries = fs::read_dir(path)
            .map_err(|error| format!("Cannot enumerate '{}': {error}", path.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("Cannot enumerate '{}': {error}", path.display()))?;
        entries.sort_by(|left, right| {
            left.file_name()
                .as_bytes()
                .cmp(right.file_name().as_bytes())
        });
        Ok(entries)
    }

    fn symlink_metadata_optional(path: &Path) -> Result<Option<fs::Metadata>, String> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(format!("Cannot inspect '{}': {error}", path.display())),
        }
    }

    fn entry_exists(parent: &Path, name: &OsStr) -> Result<bool, String> {
        symlink_metadata_optional(&parent.join(name)).map(|metadata| metadata.is_some())
    }

    fn open_directory_nofollow(path: &Path) -> Result<File, String> {
        let path_c = path_cstring(path)?;
        // SAFETY: path is NUL-terminated and open returns a new descriptor.
        let raw = unsafe {
            libc::open(
                path_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(format!(
                "Cannot pin transaction directory '{}': {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: open returned a fresh owned descriptor.
        Ok(unsafe { File::from_raw_fd(raw) })
    }

    fn reopen_pinned_directory(path_handle: &File) -> Result<File, String> {
        let current = CString::new(".").expect("static component has no NUL");
        // SAFETY: path_handle names the already-pinned capability root and
        // `.` cannot redirect resolution to another object.
        let raw = unsafe {
            libc::openat(
                path_handle.as_raw_fd(),
                current.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(format!(
                "Cannot reopen pinned project descriptor for traversal: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: openat returned a fresh owned descriptor.
        Ok(unsafe { File::from_raw_fd(raw) })
    }

    fn rename_noreplace(
        source_directory: i32,
        source: &CStr,
        destination_directory: i32,
        destination: &CStr,
    ) -> Result<(), String> {
        // SAFETY: descriptors and NUL-terminated single-component names are
        // valid. RENAME_NOREPLACE prevents accidental overwrite after races.
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                source_directory,
                source.as_ptr(),
                destination_directory,
                destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result != 0 {
            return Err(format!(
                "Atomic workspace rename failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    const fn same_source_stat(left: &libc::stat, right: &libc::stat) -> bool {
        left.st_dev == right.st_dev
            && left.st_ino == right.st_ino
            && left.st_mode == right.st_mode
            && left.st_size == right.st_size
            && left.st_mtime == right.st_mtime
            && left.st_mtime_nsec == right.st_mtime_nsec
            && left.st_ctime == right.st_ctime
            && left.st_ctime_nsec == right.st_ctime_nsec
    }

    fn same_directory_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.mode() == right.mode()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }

    fn validate_component(name: &OsStr) -> Result<(), String> {
        if name.as_bytes().is_empty()
            || name.as_bytes().contains(&0)
            || name == OsStr::new(".")
            || name == OsStr::new("..")
            || name.as_bytes().contains(&b'/')
        {
            Err(format!(
                "Refusing invalid top-level workspace name '{}'",
                name.to_string_lossy()
            ))
        } else {
            Ok(())
        }
    }

    fn component_cstring(name: &OsStr) -> Result<CString, String> {
        validate_component(name)?;
        CString::new(name.as_bytes()).map_err(|_| {
            format!(
                "Workspace entry name contains NUL: '{}'",
                name.to_string_lossy()
            )
        })
    }

    fn path_cstring(path: &Path) -> Result<CString, String> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| format!("Path contains NUL: '{}'", path.display()))
    }

    fn hex_bytes(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            encoded.push(char::from(HEX[(byte >> 4) as usize]));
            encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
        encoded
    }

    pub use WorkspaceProjection as PlatformWorkspaceProjection;
}

#[cfg(target_os = "linux")]
pub use linux::PlatformWorkspaceProjection as WorkspaceProjection;

#[cfg(not(target_os = "linux"))]
pub struct WorkspaceProjection;

#[cfg(not(target_os = "linux"))]
impl WorkspaceProjection {
    pub(crate) fn prepare(
        _run: &ToolRunContext,
        _permits_git_metadata: bool,
    ) -> Result<Option<Self>, String> {
        Err(
            "Writable sandbox workspace projection is unavailable on this platform; refusing host writes"
                .to_string(),
        )
    }

    pub(crate) const fn uses_private_cargo_target(&self) -> bool {
        false
    }

    pub(crate) fn settle(
        &mut self,
        _publish: bool,
    ) -> Result<WorkspaceProjectionReceipt, WorkspaceProjectionError> {
        Err(WorkspaceProjectionError::rejected(
            "Writable workspace projection cannot settle on this platform",
        ))
    }

    pub(crate) fn checkpoint(
        &mut self,
        _publish: bool,
    ) -> Result<WorkspaceProjectionReceipt, WorkspaceProjectionError> {
        Err(WorkspaceProjectionError::rejected(
            "Writable workspace projection cannot checkpoint on this platform",
        ))
    }
}
