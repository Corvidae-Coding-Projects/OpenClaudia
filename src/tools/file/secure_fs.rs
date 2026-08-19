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
#[cfg(unix)]
use std::path::PathBuf;

/// Open an existing regular file for reading without following any symlink
/// during the authoritative kernel lookup.
pub(super) fn open_regular_read(path: &Path) -> Result<File, String> {
    let file = open_beneath(path, false, libc_flags::O_RDONLY, 0)?;
    require_regular(&file, path)?;
    reject_readable_hardlink(&file, path)?;
    Ok(file)
}

/// Open a regular file for an in-place edit.
pub(super) fn open_regular_edit(path: &Path) -> Result<File, String> {
    let file = open_beneath(path, true, libc_flags::O_RDWR, 0)?;
    require_regular(&file, path)?;
    reject_writable_hardlink(&file, path)?;
    Ok(file)
}

/// Open an existing file for update, or securely create it and any missing
/// parent directories. Returns `(file, existed_before_open)`.
pub(super) fn open_regular_update_or_create(path: &Path) -> Result<(File, bool), String> {
    match open_beneath(path, true, libc_flags::O_RDWR, 0) {
        Ok(file) => {
            require_regular(&file, path)?;
            reject_writable_hardlink(&file, path)?;
            Ok((file, true))
        }
        Err(error) if is_not_found_message(&error) => {
            create_parent_directories(path)?;
            let file = open_beneath(
                path,
                true,
                libc_flags::O_RDWR | libc_flags::O_CREAT | libc_flags::O_EXCL,
                0o666,
            )?;
            require_regular(&file, path)?;
            Ok((file, false))
        }
        Err(error) => Err(error),
    }
}

/// A directory pinned to the kernel object reached through a capability root.
pub(super) struct SecureDirectory {
    #[cfg(unix)]
    file: File,
    #[cfg(unix)]
    display_path: PathBuf,
}

pub(super) struct SecureDirEntry {
    pub(super) name: OsString,
    pub(super) kind: SecureFileType,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SecureFileType {
    Directory,
    Regular,
    #[cfg(unix)]
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
pub(super) fn open_directory(path: &Path) -> Result<SecureDirectory, String> {
    let file = open_beneath(
        path,
        false,
        libc_flags::O_RDONLY | libc_flags::O_DIRECTORY,
        0,
    )?;
    require_directory(&file, path)?;
    Ok(SecureDirectory {
        file,
        display_path: path.to_path_buf(),
    })
}

#[cfg(not(unix))]
pub(super) fn open_directory(_path: &Path) -> Result<SecureDirectory, String> {
    Err(
        "Directory operation is blocked: this platform lacks a race-safe handle-relative filesystem backend"
            .to_string(),
    )
}

#[cfg(unix)]
impl SecureDirectory {
    /// Enumerate names relative to this pinned directory descriptor. Entry
    /// types are inspected with `fstatat(..., AT_SYMLINK_NOFOLLOW)`.
    pub(super) fn entries(&self) -> Result<Vec<SecureDirEntry>, String> {
        read_directory_entries(&self.file, &self.display_path)
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
        Ok(Self { file, display_path })
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

#[cfg(not(unix))]
impl SecureDirectory {
    pub(super) fn entries(&self) -> Result<Vec<SecureDirEntry>, String> {
        Err(
            "Directory operation is blocked: this platform lacks a race-safe handle-relative filesystem backend"
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

/// Read a UTF-8 file from its already confined handle.
pub(super) fn read_to_string(file: &mut File, path: &Path) -> Result<String, String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("Failed to seek '{}': {error}", path.display()))?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|error| format!("Failed to read '{}': {error}", path.display()))?;
    Ok(content)
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

#[cfg(unix)]
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

#[cfg(not(unix))]
fn reject_readable_hardlink(_file: &File, _path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(not(unix))]
fn reject_writable_hardlink(_file: &File, _path: &Path) -> Result<(), String> {
    Ok(())
}

fn is_not_found_message(error: &str) -> bool {
    error.starts_with("NOT_FOUND:")
}

#[cfg(target_os = "linux")]
fn open_beneath(path: &Path, write: bool, flags: i32, mode: u32) -> Result<File, String> {
    let context = crate::tools::security::current_context()?;
    let (root, root_fd) = context.root_handle_for(path, write)?;
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
fn open_beneath(path: &Path, write: bool, flags: i32, mode: u32) -> Result<File, String> {
    let context = crate::tools::security::current_context()?;
    let (root, root_fd) = context.root_handle_for(path, write)?;
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

#[cfg(not(unix))]
fn open_beneath(_path: &Path, _write: bool, _flags: i32, _mode: u32) -> Result<File, String> {
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
fn create_parent_directories(path: &Path) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::ffi::OsStrExt as _;

    let context = crate::tools::security::current_context()?;
    let (root, root_handle) = context.root_handle_for(path, true)?;
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
fn read_directory_entries(file: &File, path: &Path) -> Result<Vec<SecureDirEntry>, String> {
    use std::ffi::CStr;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStringExt as _;

    // `fdopendir` owns its descriptor, so duplicate the pinned handle.
    // SAFETY: `file` is live for this call.
    let duplicate = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(format!(
            "Failed to duplicate directory '{}': {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `duplicate` is an open directory descriptor and ownership is
    // transferred to `fdopendir` on success.
    let dir = unsafe { libc::fdopendir(duplicate) };
    if dir.is_null() {
        // SAFETY: fdopendir failed and did not take ownership.
        unsafe {
            libc::close(duplicate);
        }
        return Err(format!(
            "Failed to enumerate directory '{}': {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let directory = Directory(dir);
    let mut entries = Vec::new();
    loop {
        clear_errno();
        // SAFETY: the DIR pointer remains live under `directory`.
        let entry = unsafe { libc::readdir(directory.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(0) {
                break;
            }
            return Err(format!(
                "Failed while enumerating directory '{}': {error}",
                path.display()
            ));
        }
        // SAFETY: `readdir` returned a valid dirent with NUL-terminated name.
        let name_bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name_bytes == b"." || name_bytes == b".." {
            continue;
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
        if crate::tools::security::current_context()?.is_denied_path(&entry_path) {
            tracing::debug!(
                target: "openclaudia::filesystem",
                event = "masked_path_hidden",
                path = %entry_path.display(),
                "Omitted masked path from agent directory enumeration"
            );
            continue;
        }
        entries.push(SecureDirEntry { name, kind });
    }
    Ok(entries)
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

#[cfg(not(unix))]
fn create_parent_directories(_path: &Path) -> Result<(), String> {
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

#[cfg(not(unix))]
mod libc_flags {
    pub(super) const O_RDONLY: i32 = 0;
    pub(super) const O_RDWR: i32 = 0;
    pub(super) const O_CREAT: i32 = 0;
    pub(super) const O_EXCL: i32 = 0;
}

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
        let session = format!("secure-fs-control-mask-{}", uuid::Uuid::new_v4());
        crate::tools::security::register_session_context(
            &session,
            root.path(),
            root.path(),
            &[],
            &[],
        )
        .expect("security context");
        let _guard = crate::tools::SessionIdGuard::set(&session);

        let error = open_regular_read(&control.join("canary"))
            .expect_err("control-plane file must not be readable");
        assert!(error.contains("masked"), "unexpected denial: {error}");
        let names: Vec<_> = open_directory(root.path())
            .expect("project directory")
            .entries()
            .expect("secure entries")
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert!(names.contains(&OsString::from("visible")));
        assert!(!names.contains(&OsString::from(".openclaudia")));
        crate::tools::security::release_session_context(&session);
    }
}
