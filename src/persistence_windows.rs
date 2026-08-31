//! Windows backend for descriptor-safe persistent storage.

use super::{
    checkpoint, ActiveCheckpointControl, Checkpoint, CommitReceipt, CommitState, ContentDigest,
    DiagnosticGeneration, DurabilityFailure, FileClass, PersistenceError, PersistentStorage,
    ReadState, StorageGeneration, StorageRoot, StorageRootId, UnchangedPhase, LOCK_RETRY_DELAY,
    LOCK_WAIT_TIMEOUT, MAX_TARGET_BYTES, MAX_TARGET_COMPONENTS,
};
use std::io;
use std::io::{Read as _, Seek as _, Write as _};
use std::os::windows::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(test)]
use super::TestAction;

use crate::windows_fs::{self, FileIdentity, FileVersion, ObjectKind, OpenAccess, OpenDisposition};

struct ParentHandle {
    directory: std::fs::File,
    relative: PathBuf,
    leaf: std::ffi::OsString,
    identity: FileIdentity,
    writable: bool,
}

struct TargetLock {
    file: std::fs::File,
    name: std::ffi::OsString,
    identity: FileIdentity,
}

impl Drop for TargetLock {
    fn drop(&mut self) {
        windows_fs::unlock(&self.file);
    }
}

struct StageFile<'a> {
    parent: &'a std::fs::File,
    name: std::ffi::OsString,
    file: std::fs::File,
    identity: FileIdentity,
    synced_version: Option<FileVersion>,
    active: bool,
}

struct PublishContext<'a> {
    storage: &'a PersistentStorage,
    parent: &'a ParentHandle,
    lock: &'a TargetLock,
    target: PathBuf,
    class: FileClass,
    observed: StorageGeneration,
    desired: StorageGeneration,
}

impl StageFile<'_> {
    fn mark_synced(&mut self) -> io::Result<()> {
        self.synced_version = Some(windows_fs::file_version(&self.file)?);
        Ok(())
    }

    fn validate_for_publish(&self, class: FileClass, desired: StorageGeneration) -> io::Result<()> {
        use sha2::Digest as _;

        validate_private_sidecar(&self.file)?;
        let version = windows_fs::file_version(&self.file)?;
        if self.synced_version != Some(version) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "persistence stage metadata changed after it was synchronized",
            ));
        }
        if version.length > class.max_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "persistence stage grew beyond its file-class bound",
            ));
        }
        let mut reader = self.file.try_clone()?;
        reader.seek(io::SeekFrom::Start(0))?;
        let mut digest = sha2::Sha256::new();
        let mut buffer = [0_u8; 16 * 1_024];
        let mut total = 0_u64;
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total = total.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
            if total > class.max_bytes() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "persistence stage changed beyond its file-class bound",
                ));
            }
            digest.update(&buffer[..count]);
        }
        let actual: [u8; 32] = digest.finalize().into();
        let StorageGeneration::Present(expected_digest) = desired else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a staged publication must have a present generation",
            ));
        };
        if total != version.length || actual != *expected_digest.as_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "persistence stage changed after it was synchronized",
            ));
        }
        Ok(())
    }

    fn binding_matches(&self) -> io::Result<bool> {
        let bound = match windows_fs::open_relative(
            self.parent,
            Path::new(&self.name),
            ObjectKind::Regular,
            OpenAccess::Read,
            OpenDisposition::Open,
            None,
        ) {
            Ok(opened) => opened.file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        validate_private_sidecar(&bound)?;
        Ok(windows_fs::file_identity(&bound)? == self.identity)
    }

    fn publish(&mut self, leaf: &std::ffi::OsStr, replace: bool) -> io::Result<()> {
        windows_fs::rename_relative(&self.file, self.parent, leaf, replace)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for StageFile<'_> {
    fn drop(&mut self) {
        if self.active && self.binding_matches().unwrap_or(false) {
            if let Err(error) = windows_fs::delete_handle(&self.file) {
                tracing::warn!(
                    stage = %self.name.to_string_lossy(),
                    %error,
                    "failed to clean an interrupted Windows persistence stage"
                );
            }
        }
    }
}

pub(super) fn open_storage(path: &Path) -> Result<PersistentStorage, PersistenceError> {
    if !path.is_absolute() {
        return Err(PersistenceError::InvalidRoot {
            path: path.to_path_buf(),
            reason: "root must be absolute; ambient CWD is not an authority".to_string(),
        });
    }
    let directory = windows_fs::open_absolute_directory_for_write(path).map_err(|source| {
        PersistenceError::InvalidRoot {
            path: path.to_path_buf(),
            reason: format!("Windows handle-relative open failed: {source}"),
        }
    })?;
    validate_directory(&directory, path).map_err(|reason| PersistenceError::InvalidRoot {
        path: path.to_path_buf(),
        reason,
    })?;
    let identity =
        windows_fs::file_identity(&directory).map_err(|source| PersistenceError::Io {
            operation: "inspect root identity",
            target: path.to_path_buf(),
            source,
        })?;
    Ok(PersistentStorage {
        root: Arc::new(StorageRoot {
            path: path.to_path_buf(),
            id: storage_root_id(identity),
            directory,
            control: ActiveCheckpointControl::default(),
        }),
    })
}

pub(super) fn read_storage(
    storage: &PersistentStorage,
    target: &Path,
    class: FileClass,
) -> Result<ReadState, PersistenceError> {
    let target = validate_target(target)?;
    validate_directory(&storage.root.directory, &storage.root.path).map_err(|reason| {
        PersistenceError::InvalidRoot {
            path: storage.root.path.clone(),
            reason,
        }
    })?;
    let parent = open_parent(storage, &target, false)?;
    checkpoint(storage, Checkpoint::ParentOpened).map_err(|source| PersistenceError::Io {
        operation: "pause after read parent open",
        target: target.clone(),
        source,
    })?;
    let state = observe(&parent, &target, class)?;
    if !parent_binding_matches(storage, &parent).map_err(|source| PersistenceError::Io {
        operation: "revalidate parent namespace",
        target: target.clone(),
        source,
    })? {
        return Err(PersistenceError::InvalidTarget {
            target,
            reason: "parent directory changed identity while the file was read".to_string(),
        });
    }
    tracing::debug!(
        target: "openclaudia::persistence",
        event = "persistent_read",
        root_device = storage.root.id.device,
        root_inode = storage.root.id.inode,
        file_class = ?class,
        generation = %DiagnosticGeneration::new(state.generation(), class),
        relative_target = %target.display(),
        "observed Windows handle-relative persistent state"
    );
    Ok(state)
}

pub(super) fn commit_storage(
    storage: &PersistentStorage,
    target: &Path,
    class: FileClass,
    expected: StorageGeneration,
    contents: &[u8],
) -> Result<CommitReceipt, PersistenceError> {
    let target = validate_target(target)?;
    let actual_bytes = u64::try_from(contents.len()).unwrap_or(u64::MAX);
    if actual_bytes > class.max_bytes() {
        return Err(PersistenceError::TooLarge {
            target,
            class,
            actual_bytes,
            max_bytes: class.max_bytes(),
        });
    }
    validate_directory(&storage.root.directory, &storage.root.path).map_err(|reason| {
        PersistenceError::InvalidRoot {
            path: storage.root.path.clone(),
            reason,
        }
    })?;

    let parent = open_parent(storage, &target, true)?;
    checkpoint(storage, Checkpoint::ParentOpened).map_err(|source| PersistenceError::Io {
        operation: "pause after parent open",
        target: target.clone(),
        source,
    })?;
    let lock = acquire_lock(&parent, &target).map_err(|source| PersistenceError::Io {
        operation: "acquire target lock",
        target: target.clone(),
        source,
    })?;
    let observed_state = observe(&parent, &target, class)?;
    let observed = observed_state.generation();
    ensure_parent_binding(storage, &parent, &target, observed)?;

    let desired = StorageGeneration::for_bytes(contents);
    if observed == desired {
        cleanup_staging(&parent, &target).map_err(|source| PersistenceError::Unchanged {
            target: target.clone(),
            phase: UnchangedPhase::Cleanup,
            observed,
            source,
        })?;
        return reconcile_visible(storage, &parent, target, class, expected, observed);
    }
    if observed != expected {
        return Err(PersistenceError::Conflict {
            target,
            expected,
            observed,
        });
    }
    cleanup_staging(&parent, &target).map_err(|source| PersistenceError::Unchanged {
        target: target.clone(),
        phase: UnchangedPhase::Cleanup,
        observed,
        source,
    })?;
    let stage = write_synced_stage(storage, &parent, &target, observed, contents)?;
    if let Some(reconciled) = verify_publish_preconditions(
        storage, &parent, &target, class, expected, observed, desired,
    )? {
        return Ok(reconciled);
    }
    publish_stage(
        PublishContext {
            storage,
            parent: &parent,
            lock: &lock,
            target,
            class,
            observed,
            desired,
        },
        stage,
    )
}

fn write_synced_stage<'a>(
    storage: &PersistentStorage,
    parent: &'a ParentHandle,
    target: &Path,
    observed: StorageGeneration,
    contents: &[u8],
) -> Result<StageFile<'a>, PersistenceError> {
    let mut stage = create_stage(parent, target).map_err(|source| PersistenceError::Unchanged {
        target: target.to_path_buf(),
        phase: UnchangedPhase::StageCreate,
        observed,
        source,
    })?;
    checkpoint(storage, Checkpoint::BeforeStageWrite).map_err(|source| {
        PersistenceError::Unchanged {
            target: target.to_path_buf(),
            phase: UnchangedPhase::StageWrite,
            observed,
            source,
        }
    })?;
    stage
        .file
        .write_all(contents)
        .map_err(|source| PersistenceError::Unchanged {
            target: target.to_path_buf(),
            phase: UnchangedPhase::StageWrite,
            observed,
            source,
        })?;
    checkpoint(storage, Checkpoint::AfterStageWrite).map_err(|source| {
        PersistenceError::Unchanged {
            target: target.to_path_buf(),
            phase: UnchangedPhase::StageWrite,
            observed,
            source,
        }
    })?;
    checkpoint(storage, Checkpoint::BeforeStageSync).map_err(|source| {
        PersistenceError::Unchanged {
            target: target.to_path_buf(),
            phase: UnchangedPhase::StageSync,
            observed,
            source,
        }
    })?;
    windows_fs::flush(&stage.file).map_err(|source| PersistenceError::Unchanged {
        target: target.to_path_buf(),
        phase: UnchangedPhase::StageSync,
        observed,
        source,
    })?;
    stage
        .mark_synced()
        .map_err(|source| PersistenceError::Unchanged {
            target: target.to_path_buf(),
            phase: UnchangedPhase::StageSync,
            observed,
            source,
        })?;
    Ok(stage)
}

fn verify_publish_preconditions(
    storage: &PersistentStorage,
    parent: &ParentHandle,
    target: &Path,
    class: FileClass,
    expected: StorageGeneration,
    observed: StorageGeneration,
    desired: StorageGeneration,
) -> Result<Option<CommitReceipt>, PersistenceError> {
    let before_publish = observe(parent, target, class)?.generation();
    ensure_parent_binding(storage, parent, target, observed)?;
    if before_publish == desired {
        return Ok(Some(reconcile_visible(
            storage,
            parent,
            target.to_path_buf(),
            class,
            expected,
            before_publish,
        )?));
    }
    if before_publish != observed {
        return Err(PersistenceError::Conflict {
            target: target.to_path_buf(),
            expected,
            observed: before_publish,
        });
    }
    Ok(None)
}

fn publish_stage(
    context: PublishContext<'_>,
    mut stage: StageFile<'_>,
) -> Result<CommitReceipt, PersistenceError> {
    let PublishContext {
        storage,
        parent,
        lock,
        target,
        class,
        observed,
        desired,
    } = context;
    checkpoint(storage, Checkpoint::BeforeRename).map_err(|source| {
        PersistenceError::Unchanged {
            target: target.clone(),
            phase: UnchangedPhase::Rename,
            observed,
            source,
        }
    })?;
    if !parent_binding_matches(storage, parent).map_err(|source| PersistenceError::Unchanged {
        target: target.clone(),
        phase: UnchangedPhase::NamespaceCheck,
        observed,
        source,
    })? {
        return Err(PersistenceError::Unchanged {
            target,
            phase: UnchangedPhase::NamespaceCheck,
            observed,
            source: io::Error::other(
                "parent directory identity changed at the publication boundary",
            ),
        });
    }
    if !lock
        .binding_matches(parent)
        .map_err(|source| PersistenceError::Unchanged {
            target: target.clone(),
            phase: UnchangedPhase::NamespaceCheck,
            observed,
            source,
        })?
    {
        return Err(PersistenceError::Unchanged {
            target,
            phase: UnchangedPhase::NamespaceCheck,
            observed,
            source: io::Error::other("target lock identity changed before publication"),
        });
    }
    ensure_stage_binding(&stage, &target, observed)?;
    stage
        .validate_for_publish(class, desired)
        .map_err(|source| PersistenceError::Unchanged {
            target: target.clone(),
            phase: UnchangedPhase::StageSync,
            observed,
            source,
        })?;
    stage
        .publish(&parent.leaf, observed != StorageGeneration::Missing)
        .map_err(|source| PersistenceError::Unchanged {
            target: target.clone(),
            phase: UnchangedPhase::Rename,
            observed,
            source,
        })?;

    let after_rename = checkpoint(storage, Checkpoint::AfterRename)
        .and_then(|()| checkpoint(storage, Checkpoint::BeforeDirectorySync))
        .and_then(|()| windows_fs::flush(&parent.directory));
    let namespace_stable = parent_binding_matches(storage, parent);
    let durability_error = after_rename
        .err()
        .or_else(|| namespace_stable.as_ref().err().map(clone_io_error))
        .or_else(|| {
            namespace_stable
                .ok()
                .filter(|stable| !stable)
                .map(|_| io::Error::other("parent directory identity changed after publication"))
        });
    if let Some(source) = durability_error {
        return Ok(receipt(
            storage,
            target,
            class,
            observed,
            desired,
            CommitState::PublishedDurabilityUncertain,
            Some(DurabilityFailure::from_io(&source)),
        ));
    }
    Ok(receipt(
        storage,
        target,
        class,
        observed,
        desired,
        CommitState::CommittedDurable,
        None,
    ))
}

fn reconcile_visible(
    storage: &PersistentStorage,
    parent: &ParentHandle,
    target: PathBuf,
    class: FileClass,
    expected: StorageGeneration,
    visible: StorageGeneration,
) -> Result<CommitReceipt, PersistenceError> {
    ensure_parent_binding(storage, parent, &target, visible)?;
    if visible == expected {
        return Ok(receipt(
            storage,
            target,
            class,
            expected,
            visible,
            CommitState::Unchanged,
            None,
        ));
    }
    let durability = checkpoint(storage, Checkpoint::BeforeDirectorySync)
        .and_then(|()| windows_fs::flush(&parent.directory));
    let binding = parent_binding_matches(storage, parent);
    match binding {
        Ok(false) => Err(PersistenceError::Unchanged {
            target,
            phase: UnchangedPhase::NamespaceCheck,
            observed: visible,
            source: io::Error::other("parent directory identity changed during reconciliation"),
        }),
        Err(source) => Err(PersistenceError::Unchanged {
            target,
            phase: UnchangedPhase::NamespaceCheck,
            observed: visible,
            source,
        }),
        Ok(true) => match durability {
            Ok(()) => Ok(receipt(
                storage,
                target,
                class,
                expected,
                visible,
                CommitState::Recovered,
                None,
            )),
            Err(source) => Ok(receipt(
                storage,
                target,
                class,
                expected,
                visible,
                CommitState::PublishedDurabilityUncertain,
                Some(DurabilityFailure::from_io(&source)),
            )),
        },
    }
}

fn ensure_parent_binding(
    storage: &PersistentStorage,
    parent: &ParentHandle,
    target: &Path,
    observed: StorageGeneration,
) -> Result<(), PersistenceError> {
    if parent_binding_matches(storage, parent).map_err(|source| PersistenceError::Unchanged {
        target: target.to_path_buf(),
        phase: UnchangedPhase::NamespaceCheck,
        observed,
        source,
    })? {
        Ok(())
    } else {
        Err(PersistenceError::Unchanged {
            target: target.to_path_buf(),
            phase: UnchangedPhase::NamespaceCheck,
            observed,
            source: io::Error::other("parent directory identity changed before publication"),
        })
    }
}

fn ensure_stage_binding(
    stage: &StageFile<'_>,
    target: &Path,
    observed: StorageGeneration,
) -> Result<(), PersistenceError> {
    if stage
        .binding_matches()
        .map_err(|source| PersistenceError::Unchanged {
            target: target.to_path_buf(),
            phase: UnchangedPhase::NamespaceCheck,
            observed,
            source,
        })?
    {
        Ok(())
    } else {
        Err(PersistenceError::Unchanged {
            target: target.to_path_buf(),
            phase: UnchangedPhase::NamespaceCheck,
            observed,
            source: io::Error::other("staging file identity changed before publication"),
        })
    }
}

fn receipt(
    storage: &PersistentStorage,
    target: PathBuf,
    class: FileClass,
    previous: StorageGeneration,
    generation: StorageGeneration,
    state: CommitState,
    durability_failure: Option<DurabilityFailure>,
) -> CommitReceipt {
    let result = CommitReceipt {
        root: storage.root.id,
        target,
        class,
        previous,
        generation,
        state,
        durability_failure,
    };
    tracing::info!(
        target: "openclaudia::persistence",
        event = "persistent_commit",
        root_device = result.root.device,
        root_inode = result.root.inode,
        file_class = ?result.class,
        previous_generation = %DiagnosticGeneration::new(result.previous, result.class),
        generation = %DiagnosticGeneration::new(result.generation, result.class),
        commit_state = ?result.state,
        relative_target = %result.target.display(),
        durability_error_kind = result.durability_failure.as_ref().map(DurabilityFailure::kind),
        "completed Windows handle-relative persistence operation"
    );
    result
}

fn validate_target(target: &Path) -> Result<PathBuf, PersistenceError> {
    let total_bytes = target.as_os_str().encode_wide().count().saturating_mul(2);
    if target.as_os_str().is_empty() || total_bytes > MAX_TARGET_BYTES {
        return Err(PersistenceError::InvalidTarget {
            target: target.to_path_buf(),
            reason: format!("target must contain 1..={MAX_TARGET_BYTES} UTF-16 bytes"),
        });
    }
    let mut canonical = PathBuf::new();
    let mut count = 0_usize;
    for component in target.components() {
        match component {
            std::path::Component::Normal(name) => {
                windows_fs::validate_component(name).map_err(|error| {
                    PersistenceError::InvalidTarget {
                        target: target.to_path_buf(),
                        reason: error.to_string(),
                    }
                })?;
                if name
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .starts_with(".openclaudia-persistence-")
                {
                    return Err(PersistenceError::InvalidTarget {
                        target: target.to_path_buf(),
                        reason: "target collides with the reserved persistence sidecar namespace"
                            .to_string(),
                    });
                }
                canonical.push(name);
                count += 1;
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                return Err(PersistenceError::InvalidTarget {
                    target: target.to_path_buf(),
                    reason: "target must be root-relative without parent traversal".to_string(),
                });
            }
        }
    }
    if count == 0 || count > MAX_TARGET_COMPONENTS {
        return Err(PersistenceError::InvalidTarget {
            target: target.to_path_buf(),
            reason: format!("target must contain 1..={MAX_TARGET_COMPONENTS} components"),
        });
    }
    Ok(canonical)
}

fn validate_directory(directory: &std::fs::File, display: &Path) -> Result<(), String> {
    let version = windows_fs::file_version(directory)
        .map_err(|error| format!("cannot inspect directory: {error}"))?;
    if !version.is_directory() || version.is_reparse_point() {
        return Err("handle does not name a non-reparse directory".to_string());
    }
    windows_fs::validate_owned_acl(directory, false).map_err(|error| {
        format!(
            "directory ACL/owner is not private enough at {}: {error}",
            display.display()
        )
    })
}

fn open_parent(
    storage: &PersistentStorage,
    target: &Path,
    writable: bool,
) -> Result<ParentHandle, PersistenceError> {
    let components = target
        .components()
        .map(|component| match component {
            std::path::Component::Normal(name) => name.to_os_string(),
            _ => unreachable!("validated target contains only normal components"),
        })
        .collect::<Vec<_>>();
    let (leaf, parents) = components
        .split_last()
        .expect("validated target has at least one component");
    let mut directory =
        storage
            .root
            .directory
            .try_clone()
            .map_err(|source| PersistenceError::Io {
                operation: "duplicate root handle",
                target: target.to_path_buf(),
                source,
            })?;
    let mut relative = PathBuf::new();
    for component in parents {
        relative.push(component);
        directory = windows_fs::open_relative(
            &directory,
            Path::new(component),
            ObjectKind::Directory,
            if writable {
                OpenAccess::Write
            } else {
                OpenAccess::Read
            },
            OpenDisposition::Open,
            None,
        )
        .map_err(|source| PersistenceError::InvalidTarget {
            target: target.to_path_buf(),
            reason: format!(
                "cannot enter parent {} without following reparse points: {source}",
                relative.display()
            ),
        })?
        .file;
        validate_directory(&directory, &relative).map_err(|reason| {
            PersistenceError::InvalidTarget {
                target: target.to_path_buf(),
                reason: format!("parent {} is not trusted: {reason}", relative.display()),
            }
        })?;
    }
    let identity =
        windows_fs::file_identity(&directory).map_err(|source| PersistenceError::Io {
            operation: "inspect parent handle",
            target: target.to_path_buf(),
            source,
        })?;
    Ok(ParentHandle {
        directory,
        relative,
        leaf: leaf.clone(),
        identity,
        writable,
    })
}

fn parent_binding_matches(storage: &PersistentStorage, parent: &ParentHandle) -> io::Result<bool> {
    let directory = windows_fs::open_relative(
        &storage.root.directory,
        if parent.relative.as_os_str().is_empty() {
            Path::new(".")
        } else {
            &parent.relative
        },
        ObjectKind::Directory,
        if parent.writable {
            OpenAccess::Write
        } else {
            OpenAccess::Read
        },
        OpenDisposition::Open,
        None,
    )?
    .file;
    validate_directory(&directory, &parent.relative)
        .map_err(|reason| io::Error::new(io::ErrorKind::PermissionDenied, reason))?;
    Ok(windows_fs::file_identity(&directory)? == parent.identity)
}

fn observe(
    parent: &ParentHandle,
    target: &Path,
    class: FileClass,
) -> Result<ReadState, PersistenceError> {
    let mut file = match windows_fs::open_relative(
        &parent.directory,
        Path::new(&parent.leaf),
        ObjectKind::Regular,
        OpenAccess::Read,
        OpenDisposition::Open,
        None,
    ) {
        Ok(opened) => opened.file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(ReadState::missing(class));
        }
        Err(source) => {
            return Err(PersistenceError::InvalidTarget {
                target: target.to_path_buf(),
                reason: format!("leaf cannot be opened without following reparse points: {source}"),
            });
        }
    };
    let before = validate_regular_file(&file, target, class)?;
    if before.length > class.max_bytes() {
        return Err(PersistenceError::TooLarge {
            target: target.to_path_buf(),
            class,
            actual_bytes: before.length,
            max_bytes: class.max_bytes(),
        });
    }
    let capacity = usize::try_from(before.length).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    std::io::Read::by_ref(&mut file)
        .take(class.max_bytes().saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| PersistenceError::Io {
            operation: "read bounded file",
            target: target.to_path_buf(),
            source,
        })?;
    let actual_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual_bytes > class.max_bytes() {
        return Err(PersistenceError::TooLarge {
            target: target.to_path_buf(),
            class,
            actual_bytes,
            max_bytes: class.max_bytes(),
        });
    }
    let after = windows_fs::file_version(&file).map_err(|source| PersistenceError::Io {
        operation: "reinspect bounded file",
        target: target.to_path_buf(),
        source,
    })?;
    if before != after {
        return Err(PersistenceError::InvalidTarget {
            target: target.to_path_buf(),
            reason: "file changed while its bounded generation was read".to_string(),
        });
    }
    Ok(ReadState::present(class, bytes))
}

fn validate_regular_file(
    file: &std::fs::File,
    target: &Path,
    class: FileClass,
) -> Result<FileVersion, PersistenceError> {
    let version = windows_fs::file_version(file).map_err(|source| PersistenceError::Io {
        operation: "inspect regular file",
        target: target.to_path_buf(),
        source,
    })?;
    if version.is_directory() || version.is_reparse_point() {
        return Err(PersistenceError::InvalidTarget {
            target: target.to_path_buf(),
            reason: "leaf is not a non-reparse regular file".to_string(),
        });
    }
    if version.links != 1 {
        return Err(PersistenceError::InvalidTarget {
            target: target.to_path_buf(),
            reason: format!(
                "leaf has {} hard links; exactly one is required",
                version.links
            ),
        });
    }
    let allow_legacy_read = matches!(
        class,
        FileClass::Configuration | FileClass::Session | FileClass::Artifact
    );
    windows_fs::validate_owned_acl(file, !allow_legacy_read).map_err(|source| {
        PersistenceError::InvalidTarget {
            target: target.to_path_buf(),
            reason: format!("leaf ACL/owner failed {class:?} policy: {source}"),
        }
    })?;
    Ok(version)
}

fn target_sidecar_name(prefix: &str, target: &Path) -> std::ffi::OsString {
    let mut bytes = Vec::new();
    for unit in target.as_os_str().encode_wide() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let digest = ContentDigest::sha256(bytes).to_string();
    let hexadecimal = digest.strip_prefix("sha256:").unwrap_or(digest.as_str());
    std::ffi::OsString::from(format!(".openclaudia-persistence-{prefix}-{hexadecimal}"))
}

fn acquire_lock(parent: &ParentHandle, target: &Path) -> io::Result<TargetLock> {
    let name = target_sidecar_name("lock", target);
    let security = windows_fs::private_security_descriptor()?;
    let opened = windows_fs::open_relative(
        &parent.directory,
        Path::new(&name),
        ObjectKind::Regular,
        OpenAccess::Write,
        OpenDisposition::OpenOrCreate,
        Some(&security),
    )?;
    validate_private_sidecar(&opened.file)?;
    let identity = windows_fs::file_identity(&opened.file)?;
    let started = std::time::Instant::now();
    loop {
        match windows_fs::lock_exclusive(&opened.file) {
            Ok(()) => {
                return Ok(TargetLock {
                    file: opened.file,
                    name,
                    identity,
                });
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.raw_os_error()
                        == Some(
                            windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION.cast_signed(),
                        ) =>
            {
                if started.elapsed() >= LOCK_WAIT_TIMEOUT {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "persistence target lock deadline exceeded",
                    ));
                }
                std::thread::sleep(LOCK_RETRY_DELAY);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

impl TargetLock {
    fn binding_matches(&self, parent: &ParentHandle) -> io::Result<bool> {
        validate_private_sidecar(&self.file)?;
        let bound = match windows_fs::open_relative(
            &parent.directory,
            Path::new(&self.name),
            ObjectKind::Regular,
            OpenAccess::Read,
            OpenDisposition::Open,
            None,
        ) {
            Ok(opened) => opened.file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        validate_private_sidecar(&bound)?;
        Ok(windows_fs::file_identity(&bound)? == self.identity)
    }
}

fn validate_private_sidecar(file: &std::fs::File) -> io::Result<()> {
    let version = windows_fs::file_version(file)?;
    if version.is_directory() || version.is_reparse_point() || version.links != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "persistence sidecar failed type/link checks",
        ));
    }
    windows_fs::validate_owned_acl(file, true)
}

fn cleanup_staging(parent: &ParentHandle, target: &Path) -> io::Result<()> {
    let name = target_sidecar_name("stage", target);
    let opened = match windows_fs::open_relative(
        &parent.directory,
        Path::new(&name),
        ObjectKind::Regular,
        OpenAccess::Read,
        OpenDisposition::Open,
        None,
    ) {
        Ok(opened) => opened,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    validate_private_sidecar(&opened.file)?;
    windows_fs::delete_handle(&opened.file)
}

fn create_stage<'a>(parent: &'a ParentHandle, target: &Path) -> io::Result<StageFile<'a>> {
    let name = target_sidecar_name("stage", target);
    let security = windows_fs::private_security_descriptor()?;
    let opened = windows_fs::open_relative(
        &parent.directory,
        Path::new(&name),
        ObjectKind::Regular,
        OpenAccess::ExclusiveWrite,
        OpenDisposition::Create,
        Some(&security),
    )?;
    validate_private_sidecar(&opened.file)?;
    let identity = windows_fs::file_identity(&opened.file)?;
    Ok(StageFile {
        parent: &parent.directory,
        name,
        file: opened.file,
        identity,
        synced_version: None,
        active: true,
    })
}

fn storage_root_id(identity: FileIdentity) -> StorageRootId {
    let inode = u64::from_le_bytes(identity.id[..8].try_into().expect("eight-byte file id"));
    let file_id_high = u64::from_le_bytes(identity.id[8..].try_into().expect("eight-byte file id"));
    StorageRootId {
        device: identity.volume,
        inode,
        file_id_high,
    }
}

fn clone_io_error(error: &io::Error) -> io::Error {
    error.raw_os_error().map_or_else(
        || io::Error::new(error.kind(), error.to_string()),
        io::Error::from_raw_os_error,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_validation_rejects_windows_aliases_and_sidecars() {
        let root = tempfile::tempdir().expect("root");
        let storage = PersistentStorage::open(root.path()).expect("Windows storage root");
        for target in [
            "..\\escape",
            "CON",
            "file:stream",
            "bad?.json",
            "trailing.",
            ".openclaudia-persistence-lock-x",
        ] {
            assert!(matches!(
                storage.read(target, FileClass::State),
                Err(PersistenceError::InvalidTarget { .. })
            ));
        }
    }

    #[test]
    fn interruption_before_publish_removes_stage_and_preserves_target() {
        let root = tempfile::tempdir().expect("root");
        let storage = PersistentStorage::open(root.path()).expect("Windows storage root");
        let initial = storage
            .commit(
                "state.json",
                FileClass::State,
                StorageGeneration::Missing,
                b"old",
            )
            .expect("initial commit");
        storage.set_test_action(
            Checkpoint::BeforeRename,
            TestAction::Error(
                windows_sys::Win32::Foundation::ERROR_OPERATION_ABORTED.cast_signed(),
            ),
        );
        let error = storage
            .commit("state.json", FileClass::State, initial.generation(), b"new")
            .expect_err("injected interruption");
        assert_eq!(error.commit_state(), Some(CommitState::Unchanged));
        storage
            .read("state.json", FileClass::State)
            .expect("preserved target")
            .expose_bytes(|bytes| assert_eq!(bytes, Some(b"old".as_slice())));
        assert!(std::fs::read_dir(root.path())
            .expect("root entries")
            .all(|entry| !entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .contains("-stage-")));
    }

    #[test]
    fn directory_flush_failure_is_uncertain_then_retry_recovers() {
        let root = tempfile::tempdir().expect("root");
        let storage = PersistentStorage::open(root.path()).expect("Windows storage root");
        let initial = storage
            .commit(
                "state.json",
                FileClass::State,
                StorageGeneration::Missing,
                b"old",
            )
            .expect("initial commit");
        storage.set_test_action(
            Checkpoint::BeforeDirectorySync,
            TestAction::Error(windows_sys::Win32::Foundation::ERROR_WRITE_FAULT.cast_signed()),
        );
        let uncertain = storage
            .commit("state.json", FileClass::State, initial.generation(), b"new")
            .expect("published receipt");
        assert_eq!(uncertain.state(), CommitState::PublishedDurabilityUncertain);
        storage
            .read("state.json", FileClass::State)
            .expect("published target")
            .expose_bytes(|bytes| assert_eq!(bytes, Some(b"new".as_slice())));

        let recovered = storage
            .commit("state.json", FileClass::State, initial.generation(), b"new")
            .expect("idempotent recovery");
        assert_eq!(recovered.state(), CommitState::Recovered);
        assert_eq!(recovered.generation(), uncertain.generation());
    }
}
