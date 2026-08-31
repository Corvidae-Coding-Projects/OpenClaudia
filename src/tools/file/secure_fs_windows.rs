//! Windows backend for agent file capabilities.

use super::*;
use std::hash::{Hash as _, Hasher as _};
use std::io::Write as _;
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::windows_fs::{self, DirectoryEntryKind, ObjectKind, OpenAccess, OpenDisposition};

const WINDOWS_ATOMIC_WRITE_LOCK_STRIPES: usize = 64;

pub(in crate::tools::file) fn open_directory(
    context: &Arc<ToolRunContext>,
    path: &Path,
) -> Result<SecureDirectory, String> {
    context
        .require(ToolResource::WorkspaceRead)
        .map_err(|error| error.to_string())?;
    let file = open_beneath(
        context,
        path,
        false,
        libc_flags::O_RDONLY | libc_flags::O_DIRECTORY,
        0,
        CapabilityDomain::Agent,
    )?;
    require_directory(&file, path)?;
    Ok(SecureDirectory {
        context: Arc::clone(context),
        file,
        display_path: path.to_path_buf(),
    })
}

impl SecureDirectory {
    pub(in crate::tools::file) fn entries_bounded(
        &self,
        maximum_entries: usize,
        maximum_name_bytes: usize,
    ) -> Result<SecureDirectoryEntries, SecureDirectoryEntriesError> {
        let mut entries = Vec::new();
        let mut retained_name_bytes = 0_usize;
        let mut limit_error = None;
        windows_fs::enumerate_directory(&self.file, |entry| {
            if entries.len() >= maximum_entries {
                limit_error = Some(SecureDirectoryEntriesError::EntryLimit {
                    limit: maximum_entries,
                });
                return false;
            }
            let name_bytes = entry.name.encode_wide().count().saturating_mul(2);
            let Some(next_name_bytes) = retained_name_bytes.checked_add(name_bytes) else {
                limit_error = Some(SecureDirectoryEntriesError::NameByteLimit {
                    limit: maximum_name_bytes,
                });
                return false;
            };
            if next_name_bytes > maximum_name_bytes {
                limit_error = Some(SecureDirectoryEntriesError::NameByteLimit {
                    limit: maximum_name_bytes,
                });
                return false;
            }
            let entry_path = self.display_path.join(&entry.name);
            if self.context.is_denied_path(&entry_path) {
                tracing::debug!(
                    target: "openclaudia::filesystem",
                    event = "masked_path_hidden",
                    path = %entry_path.display(),
                    "Omitted masked path from agent directory enumeration"
                );
                return true;
            }
            let kind = match entry.kind {
                DirectoryEntryKind::Directory => SecureFileType::Directory,
                DirectoryEntryKind::Regular => SecureFileType::Regular,
                DirectoryEntryKind::Other => SecureFileType::Other,
            };
            retained_name_bytes = next_name_bytes;
            entries.push(SecureDirEntry {
                name: entry.name,
                kind,
            });
            true
        })
        .map_err(|error| {
            format!(
                "Failed to enumerate Windows directory '{}': {error}",
                self.display_path.display()
            )
        })?;
        if let Some(error) = limit_error {
            return Err(error);
        }
        Ok(SecureDirectoryEntries {
            entries,
            skipped_changed_entries: 0,
        })
    }

    pub(in crate::tools::file) fn identity(&self) -> Result<SecureDirectoryIdentity, String> {
        let identity = windows_fs::file_identity(&self.file).map_err(|error| {
            format!(
                "Failed to inspect Windows directory '{}': {error}",
                self.display_path.display()
            )
        })?;
        Ok(SecureDirectoryIdentity {
            volume: identity.volume,
            file_id: identity.id,
        })
    }

    pub(in crate::tools::file) fn open_child_directory(
        &self,
        name: &std::ffi::OsStr,
    ) -> Result<Self, String> {
        let opened = windows_fs::open_relative(
            &self.file,
            Path::new(name),
            ObjectKind::Directory,
            OpenAccess::Read,
            OpenDisposition::Open,
            None,
        )
        .map_err(|error| {
            format!(
                "Failed to securely enter '{}' below '{}': {error}",
                name.to_string_lossy(),
                self.display_path.display()
            )
        })?;
        Ok(Self {
            context: Arc::clone(&self.context),
            file: opened.file,
            display_path: self.display_path.join(name),
        })
    }

    pub(in crate::tools::file) fn open_child_regular(
        &self,
        name: &std::ffi::OsStr,
    ) -> Result<File, String> {
        let path = self.display_path.join(name);
        let file = windows_fs::open_relative(
            &self.file,
            Path::new(name),
            ObjectKind::Regular,
            OpenAccess::Read,
            OpenDisposition::Open,
            None,
        )
        .map_err(|error| {
            format!(
                "Failed to securely open '{}' below '{}': {error}",
                name.to_string_lossy(),
                self.display_path.display()
            )
        })?
        .file;
        require_regular(&file, &path)?;
        reject_readable_hardlink(&file, &path)?;
        Ok(file)
    }
}

pub(super) fn open_beneath(
    context: &ToolRunContext,
    path: &Path,
    write: bool,
    flags: i32,
    _mode: u32,
    domain: CapabilityDomain,
) -> Result<File, String> {
    let (root, root_handle) = match domain {
        CapabilityDomain::Agent => context.root_handle_for(path, write)?,
        CapabilityDomain::HostControl => context.host_control_root_handle_for(path, write)?,
    };
    let relative = relative_to_root(path, root)?;
    let kind = if flags & libc_flags::O_DIRECTORY != 0 {
        ObjectKind::Directory
    } else {
        ObjectKind::Regular
    };
    let access = if flags & libc_flags::O_RDWR != 0 {
        OpenAccess::Write
    } else {
        OpenAccess::Read
    };
    let disposition = if flags & libc_flags::O_CREAT != 0 {
        if flags & libc_flags::O_EXCL != 0 {
            OpenDisposition::Create
        } else {
            OpenDisposition::OpenOrCreate
        }
    } else {
        OpenDisposition::Open
    };
    windows_fs::open_relative(root_handle, &relative, kind, access, disposition, None)
        .map(|opened| opened.file)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                format!("NOT_FOUND: '{}' does not exist", path.display())
            } else {
                format!(
                    "Secure Windows handle-relative open of '{}' below '{}' failed: {error}",
                    path.display(),
                    root.display()
                )
            }
        })
}

pub(super) fn create_parent_directories(
    context: &ToolRunContext,
    path: &Path,
    domain: CapabilityDomain,
) -> Result<(), String> {
    let (root, root_handle) = match domain {
        CapabilityDomain::Agent => context.root_handle_for(path, true)?,
        CapabilityDomain::HostControl => context.host_control_root_handle_for(path, true)?,
    };
    let parent = path
        .parent()
        .ok_or_else(|| format!("Path '{}' has no parent", path.display()))?;
    let relative = relative_to_root(parent, root)?;
    windows_fs::create_directories(root_handle, &relative).map_err(|error| {
        format!(
            "Failed to create Windows directories below '{}': {error}",
            root.display()
        )
    })
}

pub(super) fn reject_readable_hardlink(file: &File, path: &Path) -> Result<(), String> {
    let version = windows_fs::file_version(file)
        .map_err(|error| format!("Failed to inspect '{}': {error}", path.display()))?;
    if version.links > 1 {
        return Err(format!(
            "Refusing to read '{}' because it has {} hardlinks; another name may be a masked control or secret path",
            path.display(),
            version.links
        ));
    }
    Ok(())
}

pub(super) fn reject_writable_hardlink(file: &File, path: &Path) -> Result<(), String> {
    let version = windows_fs::file_version(file)
        .map_err(|error| format!("Failed to inspect '{}': {error}", path.display()))?;
    if version.links > 1 {
        return Err(format!(
            "Refusing to modify '{}' because it has {} hardlinks; another name may be outside the session capability roots",
            path.display(),
            version.links
        ));
    }
    Ok(())
}

struct ObservedGeneration {
    digest: crate::runtime::ContentDigest,
    security: windows_fs::OwnedSecurityDescriptor,
}

fn observe_writable_generation(
    context: &ToolRunContext,
    path: &Path,
    maximum_bytes: usize,
) -> Result<Option<ObservedGeneration>, AtomicWriteError> {
    let mut file = match open_beneath(
        context,
        path,
        true,
        libc_flags::O_RDONLY,
        0,
        CapabilityDomain::Agent,
    ) {
        Ok(file) => file,
        Err(error) if is_not_found_message(&error) => return Ok(None),
        Err(error) => return Err(AtomicWriteError::Failed(error)),
    };
    require_regular(&file, path).map_err(AtomicWriteError::Failed)?;
    reject_writable_hardlink(&file, path).map_err(AtomicWriteError::Failed)?;
    let bytes = read_stable_bounded_bytes(&mut file, path, maximum_bytes)
        .map_err(AtomicWriteError::Failed)?;
    let security = windows_fs::security_descriptor(&file).map_err(|error| {
        AtomicWriteError::Failed(format!(
            "Failed to preserve Windows permissions for '{}': {error}",
            path.display()
        ))
    })?;
    Ok(Some(ObservedGeneration {
        digest: crate::runtime::ContentDigest::sha256(bytes),
        security,
    }))
}

struct AtomicStage<'a> {
    parent: &'a File,
    name: std::ffi::OsString,
    file: File,
    identity: windows_fs::FileIdentity,
    synced_version: Option<windows_fs::FileVersion>,
    active: bool,
}

impl AtomicStage<'_> {
    fn binding_matches(&self) -> bool {
        windows_fs::open_relative(
            self.parent,
            Path::new(&self.name),
            ObjectKind::Regular,
            OpenAccess::Read,
            OpenDisposition::Open,
            None,
        )
        .and_then(|opened| windows_fs::file_identity(&opened.file))
        .is_ok_and(|identity| identity == self.identity)
    }

    fn mark_synced(&mut self) -> Result<(), String> {
        self.synced_version = Some(windows_fs::file_version(&self.file).map_err(|error| {
            format!("Failed to inspect synchronized Windows atomic-write stage: {error}")
        })?);
        Ok(())
    }

    fn validate_for_publish(&self, contents: &[u8], maximum_bytes: usize) -> Result<(), String> {
        use sha2::Digest as _;

        let version = windows_fs::file_version(&self.file)
            .map_err(|error| format!("Failed to revalidate Windows atomic-write stage: {error}"))?;
        if self.synced_version != Some(version) {
            return Err(
                "Windows atomic-write stage metadata changed after synchronization".to_string(),
            );
        }
        if version.links != 1 {
            return Err(format!(
                "Windows atomic-write stage acquired {} hard links before publication",
                version.links
            ));
        }
        let maximum_bytes = u64::try_from(maximum_bytes).unwrap_or(u64::MAX);
        if version.length > maximum_bytes {
            return Err("Windows atomic-write stage exceeded its write budget".to_string());
        }
        let mut reader = self
            .file
            .try_clone()
            .map_err(|error| format!("Failed to duplicate Windows atomic-write stage: {error}"))?;
        std::io::Seek::seek(&mut reader, std::io::SeekFrom::Start(0))
            .map_err(|error| format!("Failed to rewind Windows atomic-write stage: {error}"))?;
        let mut digest = sha2::Sha256::new();
        let mut buffer = [0_u8; 16 * 1_024];
        let mut total = 0_u64;
        loop {
            let count = std::io::Read::read(&mut reader, &mut buffer)
                .map_err(|error| format!("Failed to verify Windows atomic-write stage: {error}"))?;
            if count == 0 {
                break;
            }
            total = total.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
            if total > maximum_bytes {
                return Err("Windows atomic-write stage exceeded its write budget".to_string());
            }
            digest.update(&buffer[..count]);
        }
        let expected = crate::runtime::ContentDigest::sha256(contents);
        let actual: [u8; 32] = digest.finalize().into();
        if total != version.length || actual != *expected.as_bytes() {
            return Err(
                "Windows atomic-write stage contents changed before publication".to_string(),
            );
        }
        Ok(())
    }
}

impl Drop for AtomicStage<'_> {
    fn drop(&mut self) {
        if self.active && self.binding_matches() {
            if let Err(error) = windows_fs::delete_handle(&self.file) {
                tracing::warn!(
                    stage = %self.name.to_string_lossy(),
                    %error,
                    "failed to remove interrupted Windows atomic-write stage"
                );
            }
        }
    }
}

#[allow(clippy::too_many_lines)] // Keep the ordered Windows atomic-publication protocol visible.
pub(in crate::tools::file) fn write_atomic_generation(
    context: &ToolRunContext,
    path: &Path,
    expected: Option<crate::runtime::ContentDigest>,
    contents: &[u8],
    maximum_bytes: usize,
) -> Result<crate::runtime::ContentDigest, AtomicWriteError> {
    if contents.len() > maximum_bytes {
        return Err(AtomicWriteError::Failed(format!(
            "File '{}' would exceed the {maximum_bytes}-byte write budget",
            path.display()
        )));
    }
    context
        .require(ToolResource::WorkspaceWrite)
        .map_err(|error| AtomicWriteError::Failed(error.to_string()))?;

    let _write_guard = atomic_write_guard(path);
    let initial = observe_writable_generation(context, path, maximum_bytes)?;
    if initial.as_ref().map(|observed| observed.digest) != expected {
        return Err(AtomicWriteError::Conflict {
            expected,
            observed: initial.map(|observed| observed.digest),
        });
    }
    if expected.is_none() {
        create_parent_directories(context, path, CapabilityDomain::Agent)
            .map_err(AtomicWriteError::Failed)?;
    }

    let (root, root_handle) = context
        .root_handle_for(path, true)
        .map_err(AtomicWriteError::Failed)?;
    let relative = relative_to_root(path, root).map_err(AtomicWriteError::Failed)?;
    let leaf = relative.file_name().ok_or_else(|| {
        AtomicWriteError::Failed(format!("File '{}' has no leaf name", path.display()))
    })?;
    let parent_relative = relative
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = windows_fs::open_relative(
        root_handle,
        parent_relative,
        ObjectKind::Directory,
        OpenAccess::Write,
        OpenDisposition::Open,
        None,
    )
    .map_err(|error| {
        AtomicWriteError::Failed(format!(
            "Failed to pin Windows parent directory for '{}': {error}",
            path.display()
        ))
    })?
    .file;
    let stage_name = std::ffi::OsString::from(format!(
        ".openclaudia-edit-{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let opened = windows_fs::open_relative(
        &parent,
        Path::new(&stage_name),
        ObjectKind::Regular,
        OpenAccess::ExclusiveWrite,
        OpenDisposition::Create,
        initial.as_ref().map(|observed| &observed.security),
    )
    .map_err(|error| {
        AtomicWriteError::Failed(format!(
            "Failed to stage Windows atomic write for '{}': {error}",
            path.display()
        ))
    })?;
    let identity = windows_fs::file_identity(&opened.file).map_err(|error| {
        AtomicWriteError::Failed(format!(
            "Failed to identify Windows atomic-write stage for '{}': {error}",
            path.display()
        ))
    })?;
    let mut stage = AtomicStage {
        parent: &parent,
        name: stage_name,
        file: opened.file,
        identity,
        synced_version: None,
        active: true,
    };
    stage.file.write_all(contents).map_err(|error| {
        AtomicWriteError::Failed(format!("Failed to stage '{}': {error}", path.display()))
    })?;
    windows_fs::flush(&stage.file).map_err(|error| {
        AtomicWriteError::Failed(format!(
            "Failed to synchronize staged bytes for '{}': {error}",
            path.display()
        ))
    })?;
    stage.mark_synced().map_err(AtomicWriteError::Failed)?;

    #[cfg(test)]
    if take_fail_before_atomic_publish() {
        return Err(AtomicWriteError::Failed(
            "injected interruption before atomic publication".to_string(),
        ));
    }

    let before_publish = observe_writable_generation(context, path, maximum_bytes)?;
    if before_publish.as_ref().map(|observed| observed.digest) != expected {
        return Err(AtomicWriteError::Conflict {
            expected,
            observed: before_publish.map(|observed| observed.digest),
        });
    }
    if !stage.binding_matches() {
        return Err(AtomicWriteError::Failed(format!(
            "Atomic-write stage for '{}' changed identity before publication",
            path.display()
        )));
    }
    stage
        .validate_for_publish(contents, maximum_bytes)
        .map_err(AtomicWriteError::Failed)?;
    windows_fs::rename_relative(&stage.file, &parent, leaf, expected.is_some()).map_err(
        |error| {
            if expected.is_none() && error.kind() == std::io::ErrorKind::AlreadyExists {
                AtomicWriteError::Conflict {
                    expected: None,
                    observed: observe_writable_generation(context, path, maximum_bytes)
                        .ok()
                        .flatten()
                        .map(|observed| observed.digest),
                }
            } else {
                AtomicWriteError::Failed(format!(
                    "Failed to atomically publish Windows file '{}': {error}",
                    path.display()
                ))
            }
        },
    )?;
    stage.active = false;
    if let Err(error) = windows_fs::flush(&parent) {
        tracing::warn!(
            path = %path.display(),
            %error,
            "Windows atomic file bytes are visible but parent-directory durability is uncertain"
        );
    }
    Ok(crate::runtime::ContentDigest::sha256(contents))
}

fn atomic_write_guard(path: &Path) -> MutexGuard<'static, ()> {
    static LOCKS: OnceLock<Vec<Mutex<()>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| {
        std::iter::repeat_with(|| Mutex::new(()))
            .take(WINDOWS_ATOMIC_WRITE_LOCK_STRIPES)
            .collect()
    });
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.to_string_lossy().to_lowercase().hash(&mut hasher);
    let index = usize::try_from(hasher.finish()).unwrap_or(0) % locks.len();
    locks[index]
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
