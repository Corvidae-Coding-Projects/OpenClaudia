//! Immutable security capabilities for one agent/tool session.
//!
//! Security-sensitive tools must resolve paths and subprocess working
//! directories from this context rather than ambient process state. Contexts
//! are pinned on first use for a session and cannot later be replaced with a
//! different project root.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

const DEFAULT_SESSION_KEY: &str = "__default__";

/// Filesystem capabilities pinned to one session.
#[derive(Debug)]
pub struct ToolSecurityContext {
    session_id: String,
    project_root: PathBuf,
    working_directory: PathBuf,
    private_temp: PrivateTempDir,
    read_only_roots: Vec<PathBuf>,
    read_write_roots: Vec<PathBuf>,
    denied_paths: Vec<PathBuf>,
    environment_grants: HashMap<String, String>,
    network_policy: AgentNetworkPolicy,
    #[cfg(unix)]
    root_handles: Vec<CapabilityRootHandle>,
}

/// Network authority carried by an agent session.
///
/// Only the fail-closed default is currently implemented; unsupported grants
/// are rejected during context creation rather than silently restoring the
/// host namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentNetworkPolicy {
    Denied,
}

#[cfg(unix)]
#[derive(Debug)]
struct CapabilityRootHandle {
    path: PathBuf,
    writable: bool,
    directory: std::fs::File,
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxBindRoot {
    pub(crate) path: PathBuf,
    pub(crate) writable: bool,
    pub(crate) directory: std::os::fd::OwnedFd,
}

impl ToolSecurityContext {
    fn new(
        session_id: &str,
        project_root: &Path,
        working_directory: &Path,
        read_only_roots: &[PathBuf],
        read_write_roots: &[PathBuf],
    ) -> Result<Self, String> {
        let project_root = canonical_directory(project_root, "project root")?;
        let working_directory = canonical_directory(working_directory, "working directory")?;
        if !path_is_within(&working_directory, &project_root)
            && !read_only_roots
                .iter()
                .chain(read_write_roots)
                .any(|root| working_directory.starts_with(root))
        {
            return Err(format!(
                "Working directory '{}' is outside the session project root '{}'",
                working_directory.display(),
                project_root.display()
            ));
        }
        if is_unsafe_broad_root(&project_root) {
            return Err(format!(
                "Refusing to create an agent security context for broad project root '{}'",
                project_root.display()
            ));
        }

        let canonical_read_only = canonical_roots(read_only_roots, "read-only")?;
        let mut canonical_read_write = canonical_roots(read_write_roots, "read-write")?;
        if !canonical_read_write.contains(&project_root) {
            canonical_read_write.push(project_root.clone());
        }
        let private_temp = PrivateTempDir::create()?;
        canonical_read_write.push(private_temp.path().to_path_buf());
        let denied_paths = restricted_project_paths(&project_root)?;
        let environment_grants = startup_environment_grants()?;
        let network_policy = startup_network_policy()?;
        #[cfg(unix)]
        let root_handles = open_capability_roots(&canonical_read_only, &canonical_read_write)?;

        Ok(Self {
            session_id: session_id.to_string(),
            project_root,
            working_directory,
            private_temp,
            read_only_roots: canonical_read_only,
            read_write_roots: canonical_read_write,
            denied_paths,
            environment_grants,
            network_policy,
            #[cfg(unix)]
            root_handles,
        })
    }

    /// Session identifier that owns these capabilities.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Canonical immutable project root.
    #[must_use]
    pub fn project_root(&self) -> &Path {
        &self.project_root
    }

    /// Canonical immutable working directory.
    #[must_use]
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    /// Private temporary directory granted only to this session.
    #[must_use]
    pub fn private_temp_root(&self) -> &Path {
        self.private_temp.path()
    }

    /// Whether a canonical path is readable by this session.
    #[must_use]
    pub fn permits_read(&self, path: &Path) -> bool {
        !self.is_denied_path(path)
            && self
                .read_write_roots
                .iter()
                .chain(&self.read_only_roots)
                .any(|root| path_is_within(path, root))
    }

    /// Whether a canonical path is writable by this session.
    #[must_use]
    pub fn permits_write(&self, path: &Path) -> bool {
        !self.is_denied_path(path)
            && self
                .read_write_roots
                .iter()
                .any(|root| path_is_within(path, root))
    }

    /// Canonical roots visible to diagnostic and sandbox profile builders.
    #[must_use]
    pub fn read_only_roots(&self) -> &[PathBuf] {
        &self.read_only_roots
    }

    /// Canonical writable roots visible to diagnostic and sandbox builders.
    #[must_use]
    pub fn read_write_roots(&self) -> &[PathBuf] {
        &self.read_write_roots
    }

    /// Project subtrees excluded from otherwise broad project capabilities.
    #[must_use]
    pub fn denied_paths(&self) -> &[PathBuf] {
        &self.denied_paths
    }

    /// Exact host-approved environment values inherited by agent processes.
    #[must_use]
    pub const fn environment_grants(&self) -> &HashMap<String, String> {
        &self.environment_grants
    }

    /// Immutable session network policy.
    #[must_use]
    pub const fn network_policy(&self) -> AgentNetworkPolicy {
        self.network_policy
    }

    /// Whether a path names or descends from a masked control/secret subtree.
    #[must_use]
    pub fn is_denied_path(&self, path: &Path) -> bool {
        self.denied_paths
            .iter()
            .any(|denied| path == denied || path.starts_with(denied))
    }

    /// Return the longest matching pre-opened Linux capability-root handle.
    ///
    /// Root descriptors are pinned when the session is created. File tools
    /// must anchor authoritative lookups to these descriptors rather than
    /// reopening a root by pathname after policy validation.
    #[cfg(unix)]
    pub(crate) fn root_handle_for(
        &self,
        path: &Path,
        write: bool,
    ) -> Result<(&Path, &std::fs::File), String> {
        if self.is_denied_path(path) {
            return Err(format!(
                "Path '{}' is masked from agent filesystem capabilities",
                path.display()
            ));
        }
        self.root_handles
            .iter()
            .filter(|root| {
                (!write || root.writable)
                    && (path == root.path.as_path() || path.starts_with(&root.path))
            })
            .max_by_key(|root| root.path.components().count())
            .map(|root| (root.path.as_path(), &root.directory))
            .ok_or_else(|| {
                let access = if write { "writable" } else { "readable" };
                format!(
                    "Path '{}' is outside the session's {access} capability roots",
                    path.display()
                )
            })
    }

    /// Duplicate the pinned capability roots onto descriptors reserved above
    /// the seccomp descriptor. The launcher clears `FD_CLOEXEC` only in the
    /// forked child, so concurrent host spawns never inherit them.
    #[cfg(target_os = "linux")]
    pub(crate) fn duplicate_linux_bind_roots(&self) -> Result<Vec<LinuxBindRoot>, String> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};

        let mut roots = Vec::with_capacity(self.root_handles.len());
        for root in &self.root_handles {
            let duplicated =
                unsafe { libc::fcntl(root.directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 200) };
            if duplicated < 0 {
                return Err(format!(
                    "Cannot duplicate pinned capability root for sandbox mounting: {}",
                    std::io::Error::last_os_error()
                ));
            }
            roots.push(LinuxBindRoot {
                path: root.path.clone(),
                writable: root.writable,
                // SAFETY: fcntl returned a fresh owned descriptor.
                directory: unsafe { std::os::fd::OwnedFd::from_raw_fd(duplicated) },
            });
        }
        Ok(roots)
    }
}

fn restricted_project_paths(project_root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut denied = vec![
        project_root.join(".openclaudia"),
        project_root.join(".claude"),
    ];
    let Some(raw) = std::env::var_os("OPENCLAUDIA_PROJECT_SECRET_MASKS") else {
        return Ok(denied);
    };
    let raw = raw.to_str().ok_or_else(|| {
        "OPENCLAUDIA_PROJECT_SECRET_MASKS contains non-Unicode data; refusing to create session capabilities"
            .to_string()
    })?;
    for entry in raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let path = Path::new(entry);
        if path.is_absolute()
            || !path
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
        {
            return Err(format!(
                "Invalid project secret mask '{entry}': use a non-empty relative path without '.' or '..'"
            ));
        }
        let path = project_root.join(path);
        if !denied.contains(&path) {
            denied.push(path);
        }
    }
    Ok(denied)
}

fn startup_environment_grants() -> Result<HashMap<String, String>, String> {
    let Some(raw) = std::env::var_os("OPENCLAUDIA_AGENT_ENV_GRANTS") else {
        return Ok(HashMap::new());
    };
    let raw = raw.to_str().ok_or_else(|| {
        "OPENCLAUDIA_AGENT_ENV_GRANTS contains non-Unicode data; refusing session startup"
            .to_string()
    })?;
    let mut grants = HashMap::new();
    for name in raw
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        let mut chars = name.chars();
        let valid = chars
            .next()
            .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
            && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric());
        let upper = name.to_ascii_uppercase();
        let reserved = matches!(
            upper.as_str(),
            "HOME"
                | "PATH"
                | "TMP"
                | "TEMP"
                | "TMPDIR"
                | "SSH_AUTH_SOCK"
                | "DBUS_SESSION_BUS_ADDRESS"
                | "DISPLAY"
                | "WAYLAND_DISPLAY"
                | "XDG_RUNTIME_DIR"
                | "LD_PRELOAD"
                | "DYLD_INSERT_LIBRARIES"
                | "GCONV_PATH"
                | "GLIBC_TUNABLES"
                | "LOCPATH"
                | "NLSPATH"
        ) || upper.starts_with("LD_")
            || upper.starts_with("DYLD_")
            || upper.starts_with("OPENCLAUDIA_");
        if !valid || reserved {
            return Err(format!(
                "Invalid or policy-reserved agent environment grant '{name}'"
            ));
        }
        if let Some(value) = std::env::var_os(name) {
            let value = value.to_str().ok_or_else(|| {
                format!("Granted environment variable '{name}' is not valid UTF-8")
            })?;
            grants.insert(name.to_string(), value.to_string());
        }
    }
    Ok(grants)
}

fn startup_network_policy() -> Result<AgentNetworkPolicy, String> {
    match std::env::var("OPENCLAUDIA_AGENT_NETWORK") {
        Ok(value) if !value.trim().is_empty() && !value.eq_ignore_ascii_case("denied") => Err(
            "Only OPENCLAUDIA_AGENT_NETWORK=denied is supported; loopback and destination grants require a broker and will not fall back to the host network"
                .to_string(),
        ),
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(AgentNetworkPolicy::Denied),
        Err(std::env::VarError::NotUnicode(_)) => Err(
            "OPENCLAUDIA_AGENT_NETWORK contains non-Unicode data; refusing session startup"
                .to_string(),
        ),
    }
}

#[cfg(unix)]
fn open_capability_roots(
    read_only_roots: &[PathBuf],
    read_write_roots: &[PathBuf],
) -> Result<Vec<CapabilityRootHandle>, String> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    let mut handles = Vec::with_capacity(read_only_roots.len() + read_write_roots.len());
    for (path, writable) in read_only_roots
        .iter()
        .map(|path| (path, false))
        .chain(read_write_roots.iter().map(|path| (path, true)))
    {
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| format!("Capability root contains NUL: '{}'", path.display()))?;
        // SAFETY: `path_c` is stable and NUL-terminated. A successful call
        // returns one uniquely owned descriptor.
        #[cfg(target_os = "linux")]
        let directory_flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        #[cfg(not(target_os = "linux"))]
        let directory_flags =
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        let fd = unsafe { libc::open(path_c.as_ptr(), directory_flags) };
        if fd < 0 {
            return Err(format!(
                "Cannot pin capability root '{}': {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: the successful `open` returned a new owned descriptor.
        let directory = unsafe { std::fs::File::from_raw_fd(fd) };
        handles.push(CapabilityRootHandle {
            path: path.clone(),
            writable,
            directory,
        });
    }
    Ok(handles)
}

#[derive(Debug)]
struct PrivateTempDir {
    path: PathBuf,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl PrivateTempDir {
    fn create() -> Result<Self, String> {
        let parent = std::env::temp_dir();
        for _ in 0..16 {
            let path = parent.join(format!("openclaudia-agent-{}", uuid::Uuid::new_v4()));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt as _;
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                            .map_err(|error| {
                                let _ = std::fs::remove_dir(&path);
                                format!(
                                    "Cannot secure private session temp directory '{}': {error}",
                                    path.display()
                                )
                            })?;
                    }
                    let canonical = path.canonicalize().map_err(|error| {
                        let _ = std::fs::remove_dir(&path);
                        format!(
                            "Cannot resolve private session temp directory '{}': {error}",
                            path.display()
                        )
                    })?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt as _;
                        let metadata = std::fs::symlink_metadata(&canonical).map_err(|error| {
                            let _ = std::fs::remove_dir(&canonical);
                            format!(
                                "Cannot pin private session temp identity '{}': {error}",
                                canonical.display()
                            )
                        })?;
                        return Ok(Self {
                            path: canonical,
                            device: metadata.dev(),
                            inode: metadata.ino(),
                        });
                    }
                    #[cfg(not(unix))]
                    return Ok(Self { path: canonical });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!(
                        "Cannot create private session temp directory below '{}': {error}",
                        parent.display()
                    ));
                }
            }
        }
        Err("Cannot allocate a unique private session temp directory".to_string())
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        let tombstone = self
            .path
            .with_file_name(format!(".openclaudia-cleanup-{}", uuid::Uuid::new_v4()));
        if let Err(error) = std::fs::rename(&self.path, &tombstone) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %self.path.display(),
                    %error,
                    "Failed to atomically detach private session temp directory for cleanup"
                );
            }
            return;
        }
        match std::fs::symlink_metadata(&tombstone) {
            Ok(metadata)
                if metadata.file_type().is_dir()
                    && !metadata.file_type().is_symlink()
                    && private_temp_identity_matches(self, &metadata) =>
            {
                // `remove_dir_all` uses descriptor-relative, no-follow
                // traversal on supported Unix platforms. The unpredictable
                // tombstone name also prevents reuse of the original
                // capability path while cleanup proceeds.
                if let Err(error) = std::fs::remove_dir_all(&tombstone) {
                    tracing::warn!(
                        path = %tombstone.display(),
                        %error,
                        "Failed to remove private session temp directory"
                    );
                }
            }
            Ok(_) => {
                tracing::error!(
                    path = %tombstone.display(),
                    "Private session temp root changed identity or type; refusing recursive cleanup"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(
                    path = %self.path.display(),
                    %error,
                    "Failed to inspect private session temp directory during cleanup"
                );
            }
        }
    }
}

#[cfg(unix)]
fn private_temp_identity_matches(temp: &PrivateTempDir, metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    metadata.dev() == temp.device && metadata.ino() == temp.inode
}

#[cfg(not(unix))]
const fn private_temp_identity_matches(
    _temp: &PrivateTempDir,
    _metadata: &std::fs::Metadata,
) -> bool {
    true
}

type ContextMap = HashMap<String, Result<Arc<ToolSecurityContext>, String>>;

static SESSION_CONTEXTS: LazyLock<Mutex<ContextMap>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn contexts(operation: &'static str) -> Result<MutexGuard<'static, ContextMap>, String> {
    SESSION_CONTEXTS.lock().map_err(|error| {
        tracing::error!(operation, %error, "Tool security-context lock poisoned");
        "Tool security contexts are unavailable because their lock is poisoned".to_string()
    })
}

/// Pin a default context for `session_id`, using the current directory only at
/// this explicit session-boundary call.
pub(crate) fn ensure_session_context(session_id: &str) -> Result<Arc<ToolSecurityContext>, String> {
    let existing = contexts("lookup")?.get(session_id).cloned();
    if let Some(existing) = existing {
        return existing;
    }
    let cwd = std::env::current_dir()
        .map_err(|error| format!("Cannot resolve session working directory: {error}"))?;
    let read_only = startup_root_grants("OPENCLAUDIA_AGENT_READ_ONLY_ROOTS")?;
    let read_write = startup_root_grants("OPENCLAUDIA_AGENT_READ_WRITE_ROOTS")?;
    register_session_context(session_id, &cwd, &cwd, &read_only, &read_write)
}

fn startup_root_grants(name: &str) -> Result<Vec<PathBuf>, String> {
    let Some(raw) = std::env::var_os(name) else {
        return Ok(Vec::new());
    };
    std::env::split_paths(&raw)
        .map(|path| {
            if path.as_os_str().is_empty() {
                Err(format!("{name} contains an empty path"))
            } else {
                Ok(path)
            }
        })
        .collect()
}

/// Register explicit immutable capabilities for a session.
pub(crate) fn register_session_context(
    session_id: &str,
    project_root: &Path,
    working_directory: &Path,
    read_only_roots: &[PathBuf],
    read_write_roots: &[PathBuf],
) -> Result<Arc<ToolSecurityContext>, String> {
    let mut map = contexts("register")?;
    if let Some(existing) = map.get(session_id) {
        let existing = existing.as_ref().map_err(Clone::clone)?;
        let requested_root = project_root
            .canonicalize()
            .map_err(|error| format!("Cannot resolve requested project root: {error}"))?;
        if existing.project_root() != requested_root {
            return Err(format!(
                "Session '{session_id}' is already pinned to project root '{}'; refusing replacement with '{}'",
                existing.project_root().display(),
                requested_root.display()
            ));
        }
        return Ok(Arc::clone(existing));
    }

    let created = ToolSecurityContext::new(
        session_id,
        project_root,
        working_directory,
        read_only_roots,
        read_write_roots,
    )
    .map(Arc::new);
    if let Ok(context) = &created {
        tracing::info!(
            target: "openclaudia::sandbox",
            event = "session_capabilities_registered",
            session_id = context.session_id(),
            read_only_roots = context.read_only_roots().len(),
            read_write_roots = context.read_write_roots().len(),
            denied_paths = context.denied_paths().len(),
            environment_grants = context.environment_grants().len(),
            network = "denied",
            "Registered immutable agent session capabilities"
        );
    }
    map.insert(session_id.to_string(), created.clone());
    created
}

/// Resolve the context for the thread's active session.
///
/// # Errors
///
/// Returns an error when the session context cannot be initialized or the
/// immutable capability registry is unavailable.
pub fn current_context() -> Result<Arc<ToolSecurityContext>, String> {
    let session_id = super::todo::current_session_key();
    if session_id == DEFAULT_SESSION_KEY {
        return ensure_session_context(DEFAULT_SESSION_KEY);
    }
    ensure_session_context(&session_id)
}

/// Validate an IDE/client buffer path against the active immutable
/// capability without opening the file. Existing symlink components are
/// rejected so a client cannot label an outside buffer as project-local.
pub(crate) fn validate_client_buffer_path(path: &Path) -> Result<PathBuf, String> {
    let context = current_context()?;
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        context.working_directory().join(path)
    };
    let mut normalized = PathBuf::new();
    for component in candidate.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                normalized.push(component.as_os_str());
            }
            std::path::Component::Normal(name) => normalized.push(name),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err("IDE buffer path contains '..' traversal".to_string())
            }
        }
    }
    if !context.permits_read(&normalized) {
        return Err("IDE buffer path is outside or masked from the session capability".to_string());
    }
    #[cfg(unix)]
    {
        let (root, _) = context.root_handle_for(&normalized, false)?;
        let relative = normalized
            .strip_prefix(root)
            .map_err(|_| "IDE buffer path escaped its capability root".to_string())?;
        let mut walked = root.to_path_buf();
        for component in relative.components() {
            let std::path::Component::Normal(name) = component else {
                continue;
            };
            walked.push(name);
            match std::fs::symlink_metadata(&walked) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err("IDE buffer path traverses a symbolic link".to_string())
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => return Err(format!("Cannot inspect IDE buffer path: {error}")),
            }
        }
        Ok(normalized)
    }
    #[cfg(not(unix))]
    {
        let _ = normalized;
        Err(
            "IDE buffer access is blocked because this platform lacks a handle-relative backend"
                .to_string(),
        )
    }
}

/// Drop the registry's ownership at session end. The private temp directory is
/// removed when no in-flight tool still holds the context.
pub(crate) fn release_session_context(session_id: &str) {
    match contexts("release") {
        Ok(mut map) => {
            map.remove(session_id);
        }
        Err(error) => {
            tracing::error!(session_id, %error, "Failed to release tool security context");
        }
    }
}

fn canonical_roots(roots: &[PathBuf], kind: &str) -> Result<Vec<PathBuf>, String> {
    let mut canonical = Vec::with_capacity(roots.len());
    for root in roots {
        let root = canonical_directory(root, kind)?;
        if is_unsafe_broad_root(&root) {
            return Err(format!(
                "Refusing broad {kind} capability root '{}'",
                root.display()
            ));
        }
        if !canonical.contains(&root) {
            canonical.push(root);
        }
    }
    Ok(canonical)
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("Cannot resolve {label} '{}': {error}", path.display()))?;
    if !canonical.is_dir() {
        return Err(format!(
            "{label} '{}' is not a directory",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn path_is_within(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

fn is_unsafe_broad_root(path: &Path) -> bool {
    #[cfg(unix)]
    const BROAD_ROOTS: &[&str] = &[
        "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/media", "/mnt", "/opt",
        "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var",
    ];
    #[cfg(unix)]
    if BROAD_ROOTS.iter().any(|root| path == Path::new(root)) {
        return true;
    }
    #[cfg(windows)]
    if path.parent().is_none() {
        return true;
    }
    false
}

#[cfg(test)]
pub(crate) fn clear_contexts_for_test() {
    if let Ok(mut map) = SESSION_CONTEXTS.lock() {
        map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_receive_distinct_private_temp_roots() {
        clear_contexts_for_test();
        let root = tempfile::tempdir().expect("project root");
        let first = register_session_context("security-a", root.path(), root.path(), &[], &[])
            .expect("first context");
        let second = register_session_context("security-b", root.path(), root.path(), &[], &[])
            .expect("second context");
        assert_ne!(first.private_temp_root(), second.private_temp_root());
        assert!(first.permits_write(first.private_temp_root()));
        assert!(!first.permits_read(second.private_temp_root()));
        release_session_context("security-a");
        release_session_context("security-b");
    }

    #[test]
    fn session_root_cannot_be_replaced() {
        clear_contexts_for_test();
        let first = tempfile::tempdir().expect("first root");
        let second = tempfile::tempdir().expect("second root");
        register_session_context("security-pinned", first.path(), first.path(), &[], &[])
            .expect("register");
        let error =
            register_session_context("security-pinned", second.path(), second.path(), &[], &[])
                .expect_err("replacement must fail");
        assert!(error.contains("already pinned"));
        release_session_context("security-pinned");
    }
}
