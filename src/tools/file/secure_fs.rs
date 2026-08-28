//! Handle-relative filesystem access for agent file tools.
//!
//! Path canonicalization is useful for diagnostics but is not an authorization
//! primitive: an attacker can replace an intermediate directory after the
//! check. On Linux these helpers anchor resolution at an open capability-root
//! descriptor and use `openat2(2)` with `RESOLVE_BENEATH`,
//! `RESOLVE_NO_MAGICLINKS`, and `RESOLVE_NO_SYMLINKS`.

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::Path;
#[cfg(any(unix, windows))]
use std::path::PathBuf;
use std::sync::Arc;

use crate::tools::security::{ToolResource, ToolRunContext};

#[derive(Debug)]
pub(super) enum AtomicWriteError {
    Conflict {
        expected: Option<crate::runtime::ContentDigest>,
        observed: Option<crate::runtime::ContentDigest>,
    },
    Failed(String),
}

impl std::fmt::Display for AtomicWriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict { expected, observed } => write!(
                formatter,
                "file snapshot conflict (expected {}, observed {})",
                expected.map_or_else(|| "missing".to_string(), |value| value.to_string()),
                observed.map_or_else(|| "missing".to_string(), |value| value.to_string())
            ),
            Self::Failed(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for AtomicWriteError {}

#[cfg(all(test, any(unix, windows)))]
std::thread_local! {
    static FAIL_BEFORE_ATOMIC_PUBLISH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Arm one deterministic, current-thread failure after staged bytes are
/// synchronized but before the target generation is published.
#[cfg(all(test, any(unix, windows)))]
pub(super) fn fail_next_atomic_write_before_publish() {
    FAIL_BEFORE_ATOMIC_PUBLISH.set(true);
}

#[cfg(all(test, any(unix, windows)))]
fn take_fail_before_atomic_publish() -> bool {
    FAIL_BEFORE_ATOMIC_PUBLISH.replace(false)
}

#[derive(Clone, Copy)]
enum CapabilityDomain {
    Agent,
    HostControl,
}

/// Open an existing regular file for reading without following any symlink
/// during the authoritative kernel lookup.
pub fn open_regular_read(context: &ToolRunContext, path: &Path) -> Result<File, String> {
    context
        .require(ToolResource::WorkspaceRead)
        .map_err(|error| error.to_string())?;
    let file = open_beneath(
        context,
        path,
        false,
        libc_flags::O_RDONLY,
        0,
        CapabilityDomain::Agent,
    )?;
    require_regular(&file, path)?;
    reject_readable_hardlink(&file, path)?;
    Ok(file)
}

/// Open an existing file for update, or securely create it and any missing
/// parent directories. Returns `(file, existed_before_open)`.
pub(super) fn open_regular_update_or_create(
    context: &ToolRunContext,
    path: &Path,
) -> Result<(File, bool), String> {
    context
        .require(ToolResource::WorkspaceWrite)
        .map_err(|error| error.to_string())?;
    match open_beneath(
        context,
        path,
        true,
        libc_flags::O_RDWR,
        0,
        CapabilityDomain::Agent,
    ) {
        Ok(file) => {
            require_regular(&file, path)?;
            reject_writable_hardlink(&file, path)?;
            Ok((file, true))
        }
        Err(error) if is_not_found_message(&error) => {
            create_parent_directories(context, path, CapabilityDomain::Agent)?;
            let file = open_beneath(
                context,
                path,
                true,
                libc_flags::O_RDWR | libc_flags::O_CREAT | libc_flags::O_EXCL,
                0o666,
                CapabilityDomain::Agent,
            )?;
            require_regular(&file, path)?;
            Ok((file, false))
        }
        Err(error) => Err(error),
    }
}

/// Open host-owned control state below the exact run project for reading.
pub fn open_host_control_regular_read(
    context: &ToolRunContext,
    path: &Path,
) -> Result<File, String> {
    context
        .require(ToolResource::WorkspaceRead)
        .map_err(|error| error.to_string())?;
    let file = open_beneath(
        context,
        path,
        false,
        libc_flags::O_RDONLY,
        0,
        CapabilityDomain::HostControl,
    )?;
    require_regular(&file, path)?;
    reject_readable_hardlink(&file, path)?;
    Ok(file)
}

/// Open or securely create host-owned control state below the run project.
pub(super) fn open_host_control_regular_update_or_create(
    context: &ToolRunContext,
    path: &Path,
) -> Result<(File, bool), String> {
    context
        .require(ToolResource::WorkspaceWrite)
        .map_err(|error| error.to_string())?;
    match open_beneath(
        context,
        path,
        true,
        libc_flags::O_RDWR,
        0,
        CapabilityDomain::HostControl,
    ) {
        Ok(file) => {
            require_regular(&file, path)?;
            reject_writable_hardlink(&file, path)?;
            Ok((file, true))
        }
        Err(error) if is_not_found_message(&error) => {
            create_parent_directories(context, path, CapabilityDomain::HostControl)?;
            let file = open_beneath(
                context,
                path,
                true,
                libc_flags::O_RDWR | libc_flags::O_CREAT | libc_flags::O_EXCL,
                0o600,
                CapabilityDomain::HostControl,
            )?;
            require_regular(&file, path)?;
            Ok((file, false))
        }
        Err(error) => Err(error),
    }
}

/// Securely create a host-owned control directory and any missing parents.
pub(super) fn create_host_control_directories(
    context: &ToolRunContext,
    path: &Path,
) -> Result<(), String> {
    context
        .require(ToolResource::WorkspaceWrite)
        .map_err(|error| error.to_string())?;
    // The shared parent creator walks exactly the parent of its input. A
    // synthetic leaf lets it create `path` itself without creating any file.
    let synthetic_leaf = path.join(".openclaudia-directory-capability-leaf");
    create_parent_directories(context, &synthetic_leaf, CapabilityDomain::HostControl)
}

/// Create or open one host-control directory through the pinned project
/// capability, then make the exact directory owner-private.
#[cfg(unix)]
pub fn prepare_private_host_control_directory(
    context: &ToolRunContext,
    path: &Path,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    create_host_control_directories(context, path)?;
    let directory = open_beneath(
        context,
        path,
        true,
        libc_flags::O_RDONLY | libc_flags::O_DIRECTORY,
        0,
        CapabilityDomain::HostControl,
    )?;
    require_directory(&directory, path)?;
    let metadata = directory
        .metadata()
        .map_err(|error| format!("Failed to inspect '{}': {error}", path.display()))?;
    // SAFETY: `geteuid` has no preconditions and retains no pointer.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid {
        return Err(format!(
            "Host-control directory '{}' is not owned by the current user",
            path.display()
        ));
    }
    directory
        .set_permissions(std::fs::Permissions::from_mode(0o700))
        .map_err(|error| {
            format!(
                "Failed to make host-control directory '{}' private: {error}",
                path.display()
            )
        })?;
    Ok(())
}

/// A directory pinned to the kernel object reached through a capability root.
pub(super) struct SecureDirectory {
    context: Arc<ToolRunContext>,
    #[cfg(any(unix, windows))]
    file: File,
    #[cfg(any(unix, windows))]
    display_path: PathBuf,
}

pub(super) struct SecureDirEntry {
    pub(super) name: OsString,
    pub(super) kind: SecureFileType,
}

pub(super) struct SecureDirectoryEntries {
    pub(super) entries: Vec<SecureDirEntry>,
    pub(super) skipped_changed_entries: usize,
}

#[derive(Debug)]
pub(super) enum SecureDirectoryEntriesError {
    EntryLimit { limit: usize },
    NameByteLimit { limit: usize },
    Read(String),
}

impl std::fmt::Display for SecureDirectoryEntriesError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EntryLimit { limit } => {
                write!(formatter, "directory contains more than {limit} entries")
            }
            Self::NameByteLimit { limit } => write!(
                formatter,
                "directory entry names exceed the {limit}-byte enumeration budget"
            ),
            Self::Read(message) => formatter.write_str(message),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SecureFileType {
    Directory,
    Regular,
    Other,
}

#[cfg(unix)]
struct Directory(*mut libc::DIR);

#[cfg(unix)]
impl Drop for Directory {
    fn drop(&mut self) {
        // SAFETY: the guard uniquely owns the DIR pointer.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

/// Open a directory without following symlinks in any path component.
#[cfg(unix)]
pub(super) fn open_directory(
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

#[cfg(not(any(unix, windows)))]
pub(super) fn open_directory(
    _context: &Arc<ToolRunContext>,
    _path: &Path,
) -> Result<SecureDirectory, String> {
    Err(
        "Directory operation is blocked: this platform lacks a race-safe handle-relative filesystem backend"
            .to_string(),
    )
}

#[cfg(unix)]
impl SecureDirectory {
    /// Enumerate names relative to this pinned directory descriptor. Entry
    /// types are inspected with `fstatat(..., AT_SYMLINK_NOFOLLOW)`. Both
    /// limits are checked before retaining the next name, so a hostile or
    /// generated directory cannot make a discovery tool allocate its entire
    /// namespace before applying a page limit.
    pub(super) fn entries_bounded(
        &self,
        maximum_entries: usize,
        maximum_name_bytes: usize,
    ) -> Result<SecureDirectoryEntries, SecureDirectoryEntriesError> {
        read_directory_entries(
            &self.context,
            &self.file,
            &self.display_path,
            maximum_entries,
            maximum_name_bytes,
        )
    }

    pub(super) fn identity(&self) -> Result<SecureDirectoryIdentity, String> {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = self.file.metadata().map_err(|error| {
            format!(
                "Failed to inspect directory '{}': {error}",
                self.display_path.display()
            )
        })?;
        Ok(SecureDirectoryIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    /// Securely enter one direct child directory.
    pub(super) fn open_child_directory(&self, name: &std::ffi::OsStr) -> Result<Self, String> {
        let relative = single_component(name)?;
        let file = openat2_relative(
            &self.file,
            &relative,
            libc_flags::O_RDONLY | libc::O_DIRECTORY,
            0,
        )
        .map_err(|error| {
            format!(
                "Failed to securely enter '{}' below '{}': {error}",
                name.to_string_lossy(),
                self.display_path.display()
            )
        })?;
        let display_path = self.display_path.join(name);
        require_directory(&file, &display_path)?;
        Ok(Self {
            context: Arc::clone(&self.context),
            file,
            display_path,
        })
    }

    /// Securely open one direct regular-file child for reading.
    pub(super) fn open_child_regular(&self, name: &std::ffi::OsStr) -> Result<File, String> {
        let relative = single_component(name)?;
        let file =
            openat2_relative(&self.file, &relative, libc_flags::O_RDONLY, 0).map_err(|error| {
                format!(
                    "Failed to securely open '{}' below '{}': {error}",
                    name.to_string_lossy(),
                    self.display_path.display()
                )
            })?;
        require_regular(&file, &self.display_path.join(name))?;
        reject_readable_hardlink(&file, &self.display_path.join(name))?;
        Ok(file)
    }
}

#[cfg(not(any(unix, windows)))]
impl SecureDirectory {
    pub(super) fn entries_bounded(
        &self,
        _maximum_entries: usize,
        _maximum_name_bytes: usize,
    ) -> Result<SecureDirectoryEntries, SecureDirectoryEntriesError> {
        Err(
            "Directory operation is blocked: this platform lacks a race-safe handle-relative filesystem backend"
                .to_string()
                .into(),
        )
    }

    pub(super) fn identity(&self) -> Result<SecureDirectoryIdentity, String> {
        Err(
            "Directory identity is unavailable: this platform lacks a race-safe handle-relative filesystem backend"
                .to_string(),
        )
    }

    pub(super) fn open_child_directory(&self, _name: &std::ffi::OsStr) -> Result<Self, String> {
        Err(
            "Directory traversal is blocked: this platform lacks a race-safe handle-relative filesystem backend"
                .to_string(),
        )
    }

    pub(super) fn open_child_regular(&self, _name: &std::ffi::OsStr) -> Result<File, String> {
        Err(
            "File operation is blocked: this platform lacks a race-safe handle-relative filesystem backend"
                .to_string(),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct SecureDirectoryIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume: u64,
    #[cfg(windows)]
    file_id: [u8; 16],
}

impl From<String> for SecureDirectoryEntriesError {
    fn from(message: String) -> Self {
        Self::Read(message)
    }
}

/// Read a UTF-8 file from its already confined handle.
pub(super) fn read_to_string(file: &mut File, path: &Path) -> Result<String, String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("Failed to seek '{}': {error}", path.display()))?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|error| format!("Failed to read '{}': {error}", path.display()))?;
    Ok(content)
}

/// Read one descriptor-pinned file twice under a hard byte ceiling.
///
/// The repeated read prevents a concurrently rewritten source from being
/// accepted as a mixed snapshot. Both reads use the same already-confined
/// descriptor; no path is resolved again after admission.
pub fn read_stable_bounded_bytes(
    file: &mut File,
    path: &Path,
    maximum_bytes: usize,
) -> Result<Vec<u8>, String> {
    let before = file
        .metadata()
        .map_err(|error| format!("Failed to inspect '{}': {error}", path.display()))?;
    if before.len() > u64::try_from(maximum_bytes).unwrap_or(u64::MAX) {
        return Err(format!(
            "File '{}' exceeds the {maximum_bytes}-byte read budget",
            path.display()
        ));
    }
    let first = read_bounded_once(file, path, maximum_bytes)?;
    let middle = file
        .metadata()
        .map_err(|error| format!("Failed to inspect '{}': {error}", path.display()))?;
    let second = read_bounded_once(file, path, maximum_bytes)?;
    let after = file
        .metadata()
        .map_err(|error| format!("Failed to inspect '{}': {error}", path.display()))?;
    if !same_file_snapshot(&before, &middle)
        || !same_file_snapshot(&middle, &after)
        || first != second
    {
        return Err(format!(
            "File '{}' changed while its bounded snapshot was read",
            path.display()
        ));
    }
    Ok(first)
}

fn read_bounded_once(
    file: &mut File,
    path: &Path,
    maximum_bytes: usize,
) -> Result<Vec<u8>, String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("Failed to seek '{}': {error}", path.display()))?;
    let limit = u64::try_from(maximum_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(maximum_bytes.min(64 * 1024));
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Failed to read '{}': {error}", path.display()))?;
    if bytes.len() > maximum_bytes {
        return Err(format!(
            "File '{}' exceeds the {maximum_bytes}-byte read budget",
            path.display()
        ));
    }
    Ok(bytes)
}

/// Publish a complete file generation without exposing a truncated target.
///
/// `expected = Some(digest)` replaces only that generation. `None` is a
/// create-only operation and never overwrites a concurrently created leaf.
/// The staged file is synchronized before one descriptor-relative namespace
/// operation publishes it.
#[cfg(unix)]
#[allow(clippy::too_many_lines)] // Keep the ordered atomic-publication protocol visible as one transaction.
pub(super) fn write_atomic_generation(
    context: &ToolRunContext,
    path: &Path,
    expected: Option<crate::runtime::ContentDigest>,
    contents: &[u8],
    maximum_bytes: usize,
) -> Result<crate::runtime::ContentDigest, AtomicWriteError> {
    use std::ffi::CString;
    use std::io::Write as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    if contents.len() > maximum_bytes {
        return Err(AtomicWriteError::Failed(format!(
            "File '{}' would exceed the {maximum_bytes}-byte write budget",
            path.display()
        )));
    }
    context
        .require(ToolResource::WorkspaceWrite)
        .map_err(|error| AtomicWriteError::Failed(error.to_string()))?;

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
    let parent = openat2_relative(
        root_handle,
        parent_relative,
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )
    .map_err(|error| {
        AtomicWriteError::Failed(format!(
            "Failed to pin parent directory for '{}': {error}",
            path.display()
        ))
    })?;
    let leaf = CString::new(leaf.as_bytes()).map_err(|_| {
        AtomicWriteError::Failed(format!("File '{}' has a NUL leaf name", path.display()))
    })?;

    let stage_name = CString::new(format!(
        ".openclaudia-edit-{}.tmp",
        uuid::Uuid::new_v4().simple()
    ))
    .expect("generated stage name contains no NUL");
    // SAFETY: `parent` is a live directory descriptor and `stage_name` is a
    // generated single component. O_EXCL prevents collision or substitution.
    let raw_stage = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            stage_name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o666,
        )
    };
    if raw_stage < 0 {
        return Err(AtomicWriteError::Failed(format!(
            "Failed to stage atomic write for '{}': {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: openat returned a fresh owned descriptor.
    let stage_file = unsafe { File::from_raw_fd(raw_stage) };
    let mut stage = AtomicStage {
        parent: &parent,
        name: stage_name,
        file: stage_file,
        active: true,
    };

    if let Some(observed) = &initial {
        stage
            .file
            .set_permissions(std::fs::Permissions::from_mode(observed.mode))
            .map_err(|error| {
                AtomicWriteError::Failed(format!(
                    "Failed to preserve mode for '{}': {error}",
                    path.display()
                ))
            })?;
    }
    stage.file.write_all(contents).map_err(|error| {
        AtomicWriteError::Failed(format!("Failed to stage '{}': {error}", path.display()))
    })?;
    stage.file.sync_all().map_err(|error| {
        AtomicWriteError::Failed(format!(
            "Failed to synchronize staged bytes for '{}': {error}",
            path.display()
        ))
    })?;

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

    if let Some(expected_generation) = expected {
        publish_replacement(
            &parent,
            &mut stage,
            &leaf,
            expected_generation,
            maximum_bytes,
            path,
        )?;
    } else {
        publish_new(&parent, &mut stage, &leaf).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                AtomicWriteError::Conflict {
                    expected: None,
                    observed: observe_writable_generation(context, path, maximum_bytes)
                        .ok()
                        .flatten()
                        .map(|observed| observed.digest),
                }
            } else {
                AtomicWriteError::Failed(format!(
                    "Failed to publish new file '{}': {error}",
                    path.display()
                ))
            }
        })?;
    }

    if let Err(error) = parent.sync_all() {
        tracing::warn!(
            path = %path.display(),
            error = %error,
            "atomic file bytes are visible but parent-directory durability is uncertain"
        );
    }
    Ok(crate::runtime::ContentDigest::sha256(contents))
}

#[cfg(not(any(unix, windows)))]
pub(super) fn write_atomic_generation(
    _context: &ToolRunContext,
    path: &Path,
    _expected: Option<crate::runtime::ContentDigest>,
    _contents: &[u8],
    _maximum_bytes: usize,
) -> Result<crate::runtime::ContentDigest, AtomicWriteError> {
    Err(AtomicWriteError::Failed(format!(
        "Atomic file write for '{}' is unavailable: this platform lacks a race-safe handle-relative filesystem backend",
        path.display()
    )))
}

#[cfg(unix)]
struct ObservedGeneration {
    digest: crate::runtime::ContentDigest,
    mode: u32,
}

#[cfg(unix)]
fn observe_writable_generation(
    context: &ToolRunContext,
    path: &Path,
    maximum_bytes: usize,
) -> Result<Option<ObservedGeneration>, AtomicWriteError> {
    use std::os::unix::fs::MetadataExt as _;

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
    let metadata = file.metadata().map_err(|error| {
        AtomicWriteError::Failed(format!("Failed to inspect '{}': {error}", path.display()))
    })?;
    let bytes = read_stable_bounded_bytes(&mut file, path, maximum_bytes)
        .map_err(AtomicWriteError::Failed)?;
    Ok(Some(ObservedGeneration {
        digest: crate::runtime::ContentDigest::sha256(bytes),
        mode: metadata.mode() & 0o7777,
    }))
}

#[cfg(unix)]
struct AtomicStage<'a> {
    parent: &'a File,
    name: std::ffi::CString,
    file: File,
    active: bool,
}

#[cfg(unix)]
impl Drop for AtomicStage<'_> {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd as _;
        if self.active {
            // SAFETY: the parent outlives this guard and the generated name is
            // a single NUL-terminated component.
            unsafe {
                libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn publish_new(
    parent: &File,
    stage: &mut AtomicStage<'_>,
    leaf: &std::ffi::CStr,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    // SAFETY: descriptors and names are valid. RENAME_NOREPLACE makes file
    // creation atomic with respect to a concurrent creator.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            stage.name.as_ptr(),
            parent.as_raw_fd(),
            leaf.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    stage.active = false;
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn publish_new(
    parent: &File,
    stage: &mut AtomicStage<'_>,
    leaf: &std::ffi::CStr,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    // linkat is a no-replace publication. Removing the staging name leaves the
    // completed inode visible at the requested leaf.
    let linked = unsafe {
        libc::linkat(
            parent.as_raw_fd(),
            stage.name.as_ptr(),
            parent.as_raw_fd(),
            leaf.as_ptr(),
            0,
        )
    };
    if linked != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let unlinked = unsafe { libc::unlinkat(parent.as_raw_fd(), stage.name.as_ptr(), 0) };
    if unlinked != 0 {
        return Err(std::io::Error::last_os_error());
    }
    stage.active = false;
    Ok(())
}

#[cfg(target_os = "linux")]
fn publish_replacement(
    parent: &File,
    stage: &mut AtomicStage<'_>,
    leaf: &std::ffi::CStr,
    expected: crate::runtime::ContentDigest,
    maximum_bytes: usize,
    path: &Path,
) -> Result<(), AtomicWriteError> {
    use std::os::fd::AsRawFd as _;
    let exchange = |left: &std::ffi::CStr, right: &std::ffi::CStr| {
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parent.as_raw_fd(),
                left.as_ptr(),
                parent.as_raw_fd(),
                right.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    };
    publish_replacement_with_exchange(parent, stage, leaf, expected, maximum_bytes, path, exchange)
}

#[cfg(target_os = "macos")]
fn publish_replacement(
    parent: &File,
    stage: &mut AtomicStage<'_>,
    leaf: &std::ffi::CStr,
    expected: crate::runtime::ContentDigest,
    maximum_bytes: usize,
    path: &Path,
) -> Result<(), AtomicWriteError> {
    use std::os::fd::AsRawFd as _;
    let exchange = |left: &std::ffi::CStr, right: &std::ffi::CStr| {
        // SAFETY: both names are single components below the pinned parent.
        // RENAME_SWAP atomically retains the displaced generation for review.
        let result = unsafe {
            libc::renameatx_np(
                parent.as_raw_fd(),
                left.as_ptr(),
                parent.as_raw_fd(),
                right.as_ptr(),
                libc::RENAME_SWAP,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    };
    publish_replacement_with_exchange(parent, stage, leaf, expected, maximum_bytes, path, exchange)
}

/// Exchange gives us the exact displaced inode under the private staging
/// name. Verifying that inode after the atomic swap closes the final pathname
/// race; a mismatch is exchanged back before returning conflict.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn publish_replacement_with_exchange(
    parent: &File,
    stage: &mut AtomicStage<'_>,
    leaf: &std::ffi::CStr,
    expected: crate::runtime::ContentDigest,
    maximum_bytes: usize,
    path: &Path,
    exchange: impl Fn(&std::ffi::CStr, &std::ffi::CStr) -> std::io::Result<()>,
) -> Result<(), AtomicWriteError> {
    use std::os::fd::AsRawFd as _;
    exchange(&stage.name, leaf).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AtomicWriteError::Conflict {
                expected: Some(expected),
                observed: None,
            }
        } else {
            AtomicWriteError::Failed(format!(
                "Failed to atomically replace '{}': {error}",
                path.display()
            ))
        }
    })?;

    let displaced = openat2_relative(
        parent,
        Path::new(stage.name.to_str().unwrap_or_default()),
        libc::O_RDONLY,
        0,
    )
    .and_then(|mut file| {
        read_stable_bounded_bytes(&mut file, path, maximum_bytes).map_err(std::io::Error::other)
    });
    let observed = displaced
        .as_ref()
        .ok()
        .map(crate::runtime::ContentDigest::sha256);
    if observed != Some(expected) {
        exchange(&stage.name, leaf).map_err(|error| {
            AtomicWriteError::Failed(format!(
                "Snapshot conflict for '{}' could not restore the displaced generation: {error}",
                path.display()
            ))
        })?;
        return Err(AtomicWriteError::Conflict {
            expected: Some(expected),
            observed,
        });
    }
    let unlinked = unsafe { libc::unlinkat(parent.as_raw_fd(), stage.name.as_ptr(), 0) };
    if unlinked != 0 {
        tracing::warn!(
            path = %path.display(),
            error = %std::io::Error::last_os_error(),
            "atomic replacement succeeded but displaced-file cleanup must be retried"
        );
        return Ok(());
    }
    stage.active = false;
    Ok(())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn publish_replacement(
    parent: &File,
    stage: &mut AtomicStage<'_>,
    leaf: &std::ffi::CStr,
    _expected: crate::runtime::ContentDigest,
    _maximum_bytes: usize,
    path: &Path,
) -> Result<(), AtomicWriteError> {
    use std::os::fd::AsRawFd as _;
    let result = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            stage.name.as_ptr(),
            parent.as_raw_fd(),
            leaf.as_ptr(),
        )
    };
    if result != 0 {
        return Err(AtomicWriteError::Failed(format!(
            "Failed to atomically replace '{}': {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    stage.active = false;
    Ok(())
}

#[cfg(unix)]
pub(super) fn same_file_snapshot(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(windows)]
pub(super) fn same_file_snapshot(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    left.file_size() == right.file_size()
        && left.last_write_time() == right.last_write_time()
        && left.creation_time() == right.creation_time()
        && left.file_attributes() == right.file_attributes()
}

#[cfg(not(any(unix, windows)))]
pub(super) fn same_file_snapshot(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

fn require_regular(file: &File, path: &Path) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("Failed to inspect '{}': {error}", path.display()))?;
    if metadata.file_type().is_file() {
        Ok(())
    } else {
        Err(format!(
            "Refusing non-regular file '{}': directories, sockets, FIFOs, and devices are not file-tool capabilities",
            path.display()
        ))
    }
}

#[cfg(any(unix, windows))]
fn require_directory(file: &File, path: &Path) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("Failed to inspect '{}': {error}", path.display()))?;
    if metadata.file_type().is_dir() {
        Ok(())
    } else {
        Err(format!("'{}' is not a directory", path.display()))
    }
}

#[cfg(unix)]
fn reject_writable_hardlink(file: &File, path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = file
        .metadata()
        .map_err(|error| format!("Failed to inspect '{}': {error}", path.display()))?;
    if metadata.nlink() > 1 {
        return Err(format!(
            "Refusing to modify '{}' because it has {} hardlinks; another name may be outside the session capability roots",
            path.display(),
            metadata.nlink()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn reject_readable_hardlink(file: &File, path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = file
        .metadata()
        .map_err(|error| format!("Failed to inspect '{}': {error}", path.display()))?;
    if metadata.nlink() > 1 {
        return Err(format!(
            "Refusing to read '{}' because it has {} hardlinks; another name may be a masked control or secret path",
            path.display(),
            metadata.nlink()
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn reject_readable_hardlink(_file: &File, _path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn reject_writable_hardlink(_file: &File, _path: &Path) -> Result<(), String> {
    Ok(())
}

pub fn is_not_found_message(error: &str) -> bool {
    error.starts_with("NOT_FOUND:")
}

#[cfg(target_os = "linux")]
fn open_beneath(
    context: &ToolRunContext,
    path: &Path,
    write: bool,
    flags: i32,
    mode: u32,
    domain: CapabilityDomain,
) -> Result<File, String> {
    let (root, root_fd) = match domain {
        CapabilityDomain::Agent => context.root_handle_for(path, write)?,
        CapabilityDomain::HostControl => context.host_control_root_handle_for(path, write)?,
    };
    let relative = relative_to_root(path, root)?;
    openat2_relative(root_fd, &relative, flags, mode).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            format!("NOT_FOUND: '{}' does not exist", path.display())
        } else {
            format!(
                "Secure open of '{}' below '{}' failed: {error}",
                path.display(),
                root.display()
            )
        }
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn open_beneath(
    context: &ToolRunContext,
    path: &Path,
    write: bool,
    flags: i32,
    mode: u32,
    domain: CapabilityDomain,
) -> Result<File, String> {
    let (root, root_fd) = match domain {
        CapabilityDomain::Agent => context.root_handle_for(path, write)?,
        CapabilityDomain::HostControl => context.host_control_root_handle_for(path, write)?,
    };
    let relative = relative_to_root(path, root)?;
    openat_walk(root_fd, &relative, flags, mode).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            format!("NOT_FOUND: '{}' does not exist", path.display())
        } else {
            format!(
                "Secure descriptor-relative open of '{}' below '{}' failed: {error}",
                path.display(),
                root.display()
            )
        }
    })
}

#[cfg(not(any(unix, windows)))]
fn open_beneath(
    _context: &ToolRunContext,
    _path: &Path,
    _write: bool,
    _flags: i32,
    _mode: u32,
    _domain: CapabilityDomain,
) -> Result<File, String> {
    Err(
        "File operation is blocked: this platform does not yet provide a race-safe handle-relative filesystem backend"
            .to_string(),
    )
}

/// Descriptor-relative component walk for Unix platforms without `openat2`
/// (notably macOS). Every intermediate descriptor is opened with
/// `O_NOFOLLOW`; `..`, roots, and prefixes are rejected before any syscall.
#[cfg(all(unix, not(target_os = "linux")))]
fn openat_walk(root_fd: &File, relative: &Path, flags: i32, mode: u32) -> std::io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::ffi::OsStrExt as _;

    let duplicated = unsafe { libc::fcntl(root_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut current = unsafe { OwnedFd::from_raw_fd(duplicated) };
    let components: Vec<_> = relative.components().collect();
    if components.is_empty() {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(name) = component else {
            if matches!(component, std::path::Component::CurDir) && components.len() == 1 {
                let duplicate =
                    unsafe { libc::fcntl(current.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
                if duplicate < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                return Ok(unsafe { File::from_raw_fd(duplicate) });
            }
            return Err(std::io::Error::from_raw_os_error(libc::EPERM));
        };
        let name = CString::new(name.as_bytes())
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        let is_last = index + 1 == components.len();
        let open_flags = if is_last {
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW
        };
        let fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), open_flags, mode) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if is_last {
            return Ok(unsafe { File::from_raw_fd(fd) });
        }
        current = unsafe { OwnedFd::from_raw_fd(fd) };
    }
    Err(std::io::Error::from_raw_os_error(libc::EINVAL))
}

#[cfg(target_os = "linux")]
fn openat2_relative(
    root_fd: &File,
    relative: &Path,
    flags: i32,
    mode: u32,
) -> std::io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;

    let relative_c = CString::new(relative.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let how = OpenHow {
        flags: u64::try_from(flags | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?,
        mode: u64::from(mode),
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    };
    // SAFETY: arguments match the Linux openat2 ABI; `how` and `relative_c`
    // remain alive for the syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd.as_raw_fd(),
            relative_c.as_ptr(),
            &raw const how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = i32::try_from(fd).map_err(|_| std::io::Error::from_raw_os_error(libc::EOVERFLOW))?;
    // SAFETY: the successful syscall returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn create_parent_directories(
    context: &ToolRunContext,
    path: &Path,
    domain: CapabilityDomain,
) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::ffi::OsStrExt as _;

    let (root, root_handle) = match domain {
        CapabilityDomain::Agent => context.root_handle_for(path, true)?,
        CapabilityDomain::HostControl => context.host_control_root_handle_for(path, true)?,
    };
    let parent = path
        .parent()
        .ok_or_else(|| format!("Path '{}' has no parent", path.display()))?;
    let relative_parent = relative_to_root(parent, root)?;
    let duplicated = unsafe { libc::fcntl(root_handle.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(format!(
            "Failed to duplicate capability root '{}': {}",
            root.display(),
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `fcntl(F_DUPFD_CLOEXEC)` returned a new owned descriptor.
    let mut current = unsafe { OwnedFd::from_raw_fd(duplicated) };

    for component in relative_parent.components() {
        let std::path::Component::Normal(name) = component else {
            continue;
        };
        let name = CString::new(name.as_bytes()).map_err(|_| {
            format!(
                "Directory component contains NUL below '{}'",
                root.display()
            )
        })?;
        // SAFETY: `current` is an open directory and `name` is NUL-terminated.
        let mkdir_result = unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o777) };
        if mkdir_result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(format!(
                    "Failed to create a directory below '{}': {error}",
                    root.display()
                ));
            }
        }
        // SAFETY: descriptor-relative lookup with O_NOFOLLOW prevents a
        // concurrently substituted symlink from becoming the next anchor.
        #[cfg(target_os = "linux")]
        let directory_flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        #[cfg(not(target_os = "linux"))]
        let directory_flags =
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        let next = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), directory_flags) };
        if next < 0 {
            return Err(format!(
                "Failed to securely enter a directory below '{}': {}",
                root.display(),
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: `next` is newly owned; assignment drops the prior anchor.
        current = unsafe { OwnedFd::from_raw_fd(next) };
    }
    Ok(())
}

#[cfg(unix)]
fn single_component(name: &std::ffi::OsStr) -> Result<PathBuf, String> {
    let path = Path::new(name);
    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(_)), None) => Ok(path.to_path_buf()),
        _ => Err(format!(
            "Refusing non-component directory entry '{}'",
            name.to_string_lossy()
        )),
    }
}

#[cfg(unix)]
#[allow(clippy::too_many_lines)] // Keep descriptor-relative enumeration and its pre-allocation limits together.
fn read_directory_entries(
    context: &ToolRunContext,
    file: &File,
    path: &Path,
    maximum_entries: usize,
    maximum_name_bytes: usize,
) -> Result<SecureDirectoryEntries, SecureDirectoryEntriesError> {
    use std::ffi::CStr;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStringExt as _;

    // `fdopendir` owns its descriptor, so duplicate the pinned handle.
    // SAFETY: `file` is live for this call.
    let duplicate = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(SecureDirectoryEntriesError::Read(format!(
            "Failed to duplicate directory '{}': {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: `duplicate` is an open directory descriptor and ownership is
    // transferred to `fdopendir` on success.
    let dir = unsafe { libc::fdopendir(duplicate) };
    if dir.is_null() {
        // SAFETY: fdopendir failed and did not take ownership.
        unsafe {
            libc::close(duplicate);
        }
        return Err(SecureDirectoryEntriesError::Read(format!(
            "Failed to enumerate directory '{}': {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    let directory = Directory(dir);
    let mut entries = Vec::new();
    let mut retained_name_bytes = 0usize;
    let mut skipped_changed_entries = 0usize;
    loop {
        clear_errno();
        // SAFETY: the DIR pointer remains live under `directory`.
        let entry = unsafe { libc::readdir(directory.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(0) {
                break;
            }
            return Err(SecureDirectoryEntriesError::Read(format!(
                "Failed while enumerating directory '{}': {error}",
                path.display()
            )));
        }
        // SAFETY: `readdir` returned a valid dirent with NUL-terminated name.
        let name_bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }
        if entries.len() >= maximum_entries {
            return Err(SecureDirectoryEntriesError::EntryLimit {
                limit: maximum_entries,
            });
        }
        let Some(next_name_bytes) = retained_name_bytes.checked_add(name_bytes.len()) else {
            return Err(SecureDirectoryEntriesError::NameByteLimit {
                limit: maximum_name_bytes,
            });
        };
        if next_name_bytes > maximum_name_bytes {
            return Err(SecureDirectoryEntriesError::NameByteLimit {
                limit: maximum_name_bytes,
            });
        }
        let name = OsString::from_vec(name_bytes.to_vec());
        let name_c = std::ffi::CString::new(name_bytes).map_err(|_| {
            format!(
                "Directory '{}' contains an entry name with NUL",
                path.display()
            )
        })?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: arguments are valid; AT_SYMLINK_NOFOLLOW inspects the entry
        // itself and cannot redirect the lookup outside this pinned directory.
        let result = unsafe {
            libc::fstatat(
                file.as_raw_fd(),
                name_c.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            skipped_changed_entries = skipped_changed_entries.saturating_add(1);
            tracing::warn!(
                dir = %path.display(),
                entry = %name.to_string_lossy(),
                error = %std::io::Error::last_os_error(),
                "secure directory entry disappeared before inspection"
            );
            continue;
        }
        // SAFETY: fstatat initialized `stat` on success.
        let stat = unsafe { stat.assume_init() };
        let file_kind = stat.st_mode & libc::S_IFMT;
        let kind = if file_kind == libc::S_IFDIR {
            SecureFileType::Directory
        } else if file_kind == libc::S_IFREG {
            SecureFileType::Regular
        } else {
            SecureFileType::Other
        };
        let entry_path = path.join(&name);
        if context.is_denied_path(&entry_path) {
            tracing::debug!(
                target: "openclaudia::filesystem",
                event = "masked_path_hidden",
                path = %entry_path.display(),
                "Omitted masked path from agent directory enumeration"
            );
            continue;
        }
        retained_name_bytes = next_name_bytes;
        entries.push(SecureDirEntry { name, kind });
    }
    Ok(SecureDirectoryEntries {
        entries,
        skipped_changed_entries,
    })
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    // SAFETY: Linux exposes thread-local errno through this pointer.
    unsafe {
        *libc::__errno_location() = 0;
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn clear_errno() {
    // SAFETY: Darwin and the supported BSD libc expose thread-local errno
    // through `__error`.
    unsafe {
        *libc::__error() = 0;
    }
}

#[cfg(not(any(unix, windows)))]
fn create_parent_directories(
    _context: &ToolRunContext,
    _path: &Path,
    _domain: CapabilityDomain,
) -> Result<(), String> {
    Err(
        "Directory creation is blocked: this platform lacks a race-safe handle-relative filesystem backend"
            .to_string(),
    )
}

#[cfg(unix)]
fn relative_to_root(path: &Path, root: &Path) -> Result<PathBuf, String> {
    let relative = path.strip_prefix(root).map_err(|error| {
        format!(
            "Path '{}' is not below capability root '{}': {error}",
            path.display(),
            root.display()
        )
    })?;
    if relative.as_os_str().is_empty() {
        Ok(PathBuf::from("."))
    } else {
        Ok(relative.to_path_buf())
    }
}

#[cfg(windows)]
fn relative_to_root(path: &Path, root: &Path) -> Result<PathBuf, String> {
    crate::windows_fs::relative_to_root(path, root).map_err(|error| {
        format!(
            "Path '{}' is not below capability root '{}': {error}",
            path.display(),
            root.display()
        )
    })
}

#[cfg(unix)]
mod libc_flags {
    pub(super) const O_RDONLY: i32 = libc::O_RDONLY;
    pub(super) const O_RDWR: i32 = libc::O_RDWR;
    pub(super) const O_CREAT: i32 = libc::O_CREAT;
    pub(super) const O_EXCL: i32 = libc::O_EXCL;
    pub(super) const O_DIRECTORY: i32 = libc::O_DIRECTORY;
}

#[cfg(all(unix, not(target_os = "linux")))]
fn openat2_relative(
    root_fd: &File,
    relative: &Path,
    flags: i32,
    mode: u32,
) -> std::io::Result<File> {
    openat_walk(root_fd, relative, flags, mode)
}

#[cfg(windows)]
mod libc_flags {
    pub(super) const O_RDONLY: i32 = 0;
    pub(super) const O_RDWR: i32 = 1 << 0;
    pub(super) const O_CREAT: i32 = 1 << 1;
    pub(super) const O_EXCL: i32 = 1 << 2;
    pub(super) const O_DIRECTORY: i32 = 1 << 3;
}

#[cfg(not(any(unix, windows)))]
mod libc_flags {
    pub(super) const O_RDONLY: i32 = 0;
    pub(super) const O_RDWR: i32 = 0;
    pub(super) const O_CREAT: i32 = 0;
    pub(super) const O_EXCL: i32 = 0;
}

#[cfg(windows)]
#[path = "secure_fs_windows.rs"]
mod windows_backend;

#[cfg(windows)]
use windows_backend::{
    create_parent_directories, open_beneath, reject_readable_hardlink, reject_writable_hardlink,
};

#[cfg(windows)]
pub(super) use windows_backend::{open_directory, write_atomic_generation};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn control_paths_are_hidden_from_direct_reads_and_directory_enumeration() {
        let root = tempfile::tempdir().expect("project root");
        let control = root.path().join(".openclaudia");
        std::fs::create_dir(&control).expect("control dir");
        std::fs::write(control.join("canary"), "secret").expect("control canary");
        std::fs::write(root.path().join("visible"), "public").expect("visible file");
        let context = crate::tools::security::ToolRunContext::builder(
            crate::state::SessionId::new(),
            root.path(),
        )
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(std::collections::HashMap::new())
        .workspace_access(crate::tools::WorkspaceAccess::ReadOnly)
        .process(false)
        .network(false)
        .secrets(false)
        .build()
        .expect("security context");

        let error = open_regular_read(&context, &control.join("canary"))
            .expect_err("control-plane file must not be readable");
        assert!(error.contains("masked"), "unexpected denial: {error}");
        let names: Vec<_> = open_directory(&context, root.path())
            .expect("project directory")
            .entries_bounded(1_000, 64 * 1024)
            .expect("secure entries")
            .entries
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert!(names.contains(&OsString::from("visible")));
        assert!(!names.contains(&OsString::from(".openclaudia")));
    }
}
