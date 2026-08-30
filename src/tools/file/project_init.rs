use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

use crate::runtime::{CapabilityGeneration, ContentDigest, RunId};
use crate::tools::security::{ToolResource, ToolRunContext};

const SCAFFOLD_SCHEMA_VERSION: u32 = 1;
const CONFIG_PATH: &str = ".openclaudia/config.yaml";
const CONTROL_PATH: &str = ".openclaudia";
const SKILLS_PATH: &str = ".openclaudia/skills";
const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// Minimal inert project configuration emitted by initialization.
///
/// Comments are documentation only. The document contains no hook, rule,
/// remote-action, credential, or external-listener authority.
pub const DEFAULT_PROJECT_CONFIG: &str = r#"# OpenClaudia project configuration
# Provider credentials are supplied by the host environment, not this file.
proxy:
  host: "127.0.0.1"
  port: 8080
  target: anthropic

providers:
  anthropic:
    base_url: https://api.anthropic.com
"#;

/// Collision policy selected before an initialization plan is constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectInitPolicy {
    /// Refuse every incompatible pre-existing destination.
    RefuseCollisions,
    /// Replace only incompatible scaffold destinations and retain the exact
    /// displaced objects in a generation-specific recovery directory.
    ForceWithBackup,
}

/// Descriptor-observed filesystem object at a planned destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectInitEntryKind {
    Missing,
    Directory,
    RegularFile,
    SymbolicLink,
    Other,
}

/// Exact action planned for one scaffold destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectInitAction {
    CreateDirectory,
    CreateFile,
    Preserve,
    RefuseCollision,
    ReplaceWithBackup,
}

impl fmt::Display for ProjectInitAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::CreateDirectory => "create directory",
            Self::CreateFile => "create file",
            Self::Preserve => "preserve existing",
            Self::RefuseCollision => "refuse collision",
            Self::ReplaceWithBackup => "replace with backup",
        };
        formatter.write_str(value)
    }
}

/// One bounded, previewable initialization effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProjectInitEffect {
    path: PathBuf,
    action: ProjectInitAction,
    observed: ProjectInitEntryKind,
    byte_len: Option<u64>,
    content_digest: Option<ContentDigest>,
    backup_path: Option<PathBuf>,
}

impl ProjectInitEffect {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn action(&self) -> ProjectInitAction {
        self.action
    }

    #[must_use]
    pub const fn observed(&self) -> ProjectInitEntryKind {
        self.observed
    }

    #[must_use]
    pub const fn byte_len(&self) -> Option<u64> {
        self.byte_len
    }

    #[must_use]
    pub const fn content_digest(&self) -> Option<ContentDigest> {
        self.content_digest
    }

    #[must_use]
    pub fn backup_path(&self) -> Option<&Path> {
        self.backup_path.as_deref()
    }
}

/// One incompatible destination discovered while building a plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProjectInitCollision {
    path: PathBuf,
    observed: ProjectInitEntryKind,
}

impl ProjectInitCollision {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn observed(&self) -> ProjectInitEntryKind {
        self.observed
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ObservedEntry {
    Missing,
    Directory,
    RegularFile(ContentDigest),
    SymbolicLink,
    Other,
}

impl ObservedEntry {
    const fn kind(&self) -> ProjectInitEntryKind {
        match self {
            Self::Missing => ProjectInitEntryKind::Missing,
            Self::Directory => ProjectInitEntryKind::Directory,
            Self::RegularFile(_) => ProjectInitEntryKind::RegularFile,
            Self::SymbolicLink => ProjectInitEntryKind::SymbolicLink,
            Self::Other => ProjectInitEntryKind::Other,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProjectInitSnapshot {
    control: ObservedEntry,
    config: ObservedEntry,
    skills: ObservedEntry,
}

/// Run-bound, bounded project-initialization plan.
#[derive(Clone, Debug, Serialize)]
pub struct ProjectInitPlan {
    schema_version: u32,
    generation: String,
    project_root: PathBuf,
    run_id: RunId,
    capability_generation: CapabilityGeneration,
    policy: ProjectInitPolicy,
    effects: Vec<ProjectInitEffect>,
    collisions: Vec<ProjectInitCollision>,
    backup_root: PathBuf,
    #[serde(skip)]
    snapshot: ProjectInitSnapshot,
}

impl ProjectInitPlan {
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    #[must_use]
    pub fn generation(&self) -> &str {
        &self.generation
    }

    #[must_use]
    pub fn project_root(&self) -> &Path {
        &self.project_root
    }

    #[must_use]
    pub const fn policy(&self) -> ProjectInitPolicy {
        self.policy
    }

    #[must_use]
    pub fn effects(&self) -> &[ProjectInitEffect] {
        &self.effects
    }

    #[must_use]
    pub fn collisions(&self) -> &[ProjectInitCollision] {
        &self.collisions
    }

    #[must_use]
    pub fn backup_root(&self) -> &Path {
        &self.backup_root
    }

    #[must_use]
    pub fn changes_project(&self) -> bool {
        self.effects.iter().any(|effect| {
            !matches!(
                effect.action,
                ProjectInitAction::Preserve | ProjectInitAction::RefuseCollision
            )
        })
    }

    /// Render the complete bounded effect list for a terminal frontend.
    #[must_use]
    pub fn preview_lines(&self) -> Vec<String> {
        self.effects
            .iter()
            .map(|effect| {
                effect.backup_path.as_ref().map_or_else(
                    || {
                        format!(
                            "{} {} (observed {:?})",
                            effect.action,
                            effect.path.display(),
                            effect.observed
                        )
                    },
                    |backup| {
                        format!(
                            "{} {} (observed {:?}; backup {})",
                            effect.action,
                            effect.path.display(),
                            effect.observed,
                            backup.display()
                        )
                    },
                )
            })
            .collect()
    }
}

/// Terminal state of a committed project-initialization plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectInitCommitState {
    AlreadyCurrent,
    Created,
    ReplacedWithBackup,
}

/// Typed receipt for a successfully committed initialization generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProjectInitReceipt {
    schema_version: u32,
    generation: String,
    state: ProjectInitCommitState,
    backup_root: Option<PathBuf>,
}

/// Compatibility outcome used by interactive frontends that do not expose
/// force replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectInitOutcome {
    Created,
    AlreadyExists,
}

impl ProjectInitReceipt {
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    #[must_use]
    pub fn generation(&self) -> &str {
        &self.generation
    }

    #[must_use]
    pub const fn state(&self) -> ProjectInitCommitState {
        self.state
    }

    #[must_use]
    pub fn backup_root(&self) -> Option<&Path> {
        self.backup_root.as_deref()
    }
}

/// Typed failures from planning or committing a project scaffold.
#[derive(Debug, Error)]
pub enum ProjectInitError {
    #[error("project initialization capability failed: {0}")]
    Capability(String),
    #[error("generated project configuration is invalid under the current schema: {0}")]
    InvalidGeneratedConfiguration(String),
    #[error(
        "project initialization cannot continue because an incompatible destination already exists: {paths:?}; rerun with --force to replace it with a recovery backup"
    )]
    Collisions { paths: Vec<PathBuf> },
    #[error("project initialization plan no longer matches the pinned workspace")]
    StalePlan,
    #[error("project initialization {operation} failed for {}: {source}", path.display())]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("project initialization is unavailable on this platform: {0}")]
    UnsupportedPlatform(&'static str),
    #[error("project initialization requires recovery at {}: {detail}", transaction_root.display())]
    RecoveryRequired {
        transaction_root: PathBuf,
        detail: String,
    },
}

fn io_error(
    operation: &'static str,
    path: impl Into<PathBuf>,
    source: io::Error,
) -> ProjectInitError {
    ProjectInitError::Io {
        operation,
        path: path.into(),
        source,
    }
}

/// Inspect the exact run project and construct the complete bounded plan.
///
/// # Errors
///
/// Returns a typed capability, schema, or descriptor-relative inspection
/// error. This function performs no filesystem mutation.
#[allow(clippy::too_many_lines)] // The preview must enumerate one complete immutable plan.
pub fn plan_project_initialization(
    run: &ToolRunContext,
    policy: ProjectInitPolicy,
) -> Result<ProjectInitPlan, ProjectInitError> {
    run.require(ToolResource::WorkspaceRead)
        .map_err(|error| ProjectInitError::Capability(error.to_string()))?;
    run.require(ToolResource::WorkspaceWrite)
        .map_err(|error| ProjectInitError::Capability(error.to_string()))?;
    serde_yaml::from_str::<crate::config::AppConfig>(DEFAULT_PROJECT_CONFIG)
        .map_err(|error| ProjectInitError::InvalidGeneratedConfiguration(error.to_string()))?;

    let generation = uuid::Uuid::new_v4().simple().to_string();
    let backup_root = run
        .project_root()
        .join(format!(".openclaudia-init-backup-{generation}"));
    let snapshot = inspect_project(run)?;
    let config_digest = ContentDigest::sha256(DEFAULT_PROJECT_CONFIG.as_bytes());
    let mut collisions = Vec::with_capacity(2);
    let mut effects = Vec::with_capacity(3);

    let control_action = match &snapshot.control {
        ObservedEntry::Missing => ProjectInitAction::CreateDirectory,
        ObservedEntry::Directory => ProjectInitAction::Preserve,
        _ => collision_action(
            policy,
            Path::new(CONTROL_PATH),
            &snapshot.control,
            &mut collisions,
        ),
    };
    effects.push(effect(
        CONTROL_PATH,
        control_action,
        &snapshot.control,
        None,
        None,
        backup_target(&backup_root, CONTROL_PATH, control_action),
    ));

    if snapshot.control == ObservedEntry::Directory {
        let config_action = match &snapshot.config {
            ObservedEntry::Missing => ProjectInitAction::CreateFile,
            ObservedEntry::RegularFile(digest) if *digest == config_digest => {
                ProjectInitAction::Preserve
            }
            _ => collision_action(
                policy,
                Path::new(CONFIG_PATH),
                &snapshot.config,
                &mut collisions,
            ),
        };
        effects.push(effect(
            CONFIG_PATH,
            config_action,
            &snapshot.config,
            Some(u64::try_from(DEFAULT_PROJECT_CONFIG.len()).unwrap_or(u64::MAX)),
            Some(config_digest),
            backup_target(&backup_root, CONFIG_PATH, config_action),
        ));

        let skills_action = match &snapshot.skills {
            ObservedEntry::Missing => ProjectInitAction::CreateDirectory,
            ObservedEntry::Directory => ProjectInitAction::Preserve,
            _ => collision_action(
                policy,
                Path::new(SKILLS_PATH),
                &snapshot.skills,
                &mut collisions,
            ),
        };
        effects.push(effect(
            SKILLS_PATH,
            skills_action,
            &snapshot.skills,
            None,
            None,
            backup_target(&backup_root, SKILLS_PATH, skills_action),
        ));
    } else {
        effects.push(effect(
            CONFIG_PATH,
            ProjectInitAction::CreateFile,
            &ObservedEntry::Missing,
            Some(u64::try_from(DEFAULT_PROJECT_CONFIG.len()).unwrap_or(u64::MAX)),
            Some(config_digest),
            None,
        ));
        effects.push(effect(
            SKILLS_PATH,
            ProjectInitAction::CreateDirectory,
            &ObservedEntry::Missing,
            None,
            None,
            None,
        ));
    }

    Ok(ProjectInitPlan {
        schema_version: SCAFFOLD_SCHEMA_VERSION,
        generation,
        project_root: run.project_root().to_path_buf(),
        run_id: run.run_id(),
        capability_generation: run.generation(),
        policy,
        effects,
        collisions,
        backup_root,
        snapshot,
    })
}

fn collision_action(
    policy: ProjectInitPolicy,
    path: &Path,
    observed: &ObservedEntry,
    collisions: &mut Vec<ProjectInitCollision>,
) -> ProjectInitAction {
    collisions.push(ProjectInitCollision {
        path: path.to_path_buf(),
        observed: observed.kind(),
    });
    match policy {
        ProjectInitPolicy::RefuseCollisions => ProjectInitAction::RefuseCollision,
        ProjectInitPolicy::ForceWithBackup => ProjectInitAction::ReplaceWithBackup,
    }
}

fn effect(
    path: &str,
    action: ProjectInitAction,
    observed: &ObservedEntry,
    byte_len: Option<u64>,
    content_digest: Option<ContentDigest>,
    backup_path: Option<PathBuf>,
) -> ProjectInitEffect {
    ProjectInitEffect {
        path: PathBuf::from(path),
        action,
        observed: observed.kind(),
        byte_len,
        content_digest,
        backup_path,
    }
}

fn backup_target(backup_root: &Path, target: &str, action: ProjectInitAction) -> Option<PathBuf> {
    (action == ProjectInitAction::ReplaceWithBackup)
        .then(|| backup_root.join("candidate").join(target))
}

/// Commit a previously previewed plan through a private same-filesystem stage.
///
/// # Errors
///
/// Returns [`ProjectInitError::StalePlan`] if the run or any destination
/// changed after preview. Pre-publication failures are rolled back. A failure
/// that cannot be rolled back returns [`ProjectInitError::RecoveryRequired`]
/// with the exact retained transaction directory.
pub fn commit_project_initialization(
    run: &ToolRunContext,
    plan: &ProjectInitPlan,
) -> Result<ProjectInitReceipt, ProjectInitError> {
    if plan.project_root != run.project_root()
        || plan.run_id != run.run_id()
        || plan.capability_generation != run.generation()
        || inspect_project(run)? != plan.snapshot
    {
        return Err(ProjectInitError::StalePlan);
    }
    if plan.policy == ProjectInitPolicy::RefuseCollisions && !plan.collisions.is_empty() {
        return Err(ProjectInitError::Collisions {
            paths: plan
                .collisions
                .iter()
                .map(|collision| collision.path.clone())
                .collect(),
        });
    }
    if !plan.changes_project() {
        sync_current_project(run)?;
        return Ok(ProjectInitReceipt {
            schema_version: SCAFFOLD_SCHEMA_VERSION,
            generation: plan.generation.clone(),
            state: ProjectInitCommitState::AlreadyCurrent,
            backup_root: None,
        });
    }
    commit_platform(run, plan)
}

/// Initialize through a run capability while refusing all collisions.
///
/// New frontends should preview [`ProjectInitPlan::effects`] directly. This
/// compatibility adapter preserves the existing `/init` outcome contract.
///
/// # Errors
///
/// Returns a diagnostic string when planning or transactional publication
/// fails.
pub fn initialize_project_for_run(run: &ToolRunContext) -> Result<ProjectInitOutcome, String> {
    let plan = plan_project_initialization(run, ProjectInitPolicy::RefuseCollisions)
        .map_err(|error| error.to_string())?;
    if !plan.collisions().is_empty() || !plan.changes_project() {
        return Ok(ProjectInitOutcome::AlreadyExists);
    }
    commit_project_initialization(run, &plan)
        .map(|_| ProjectInitOutcome::Created)
        .map_err(|error| error.to_string())
}

#[cfg(unix)]
fn inspect_project(run: &ToolRunContext) -> Result<ProjectInitSnapshot, ProjectInitError> {
    use std::ffi::CString;
    use std::io::Read as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let config_path = run.project_root().join(CONFIG_PATH);
    let (_, project) = run
        .host_control_root_handle_for(&config_path, false)
        .map_err(ProjectInitError::Capability)?;
    let control_name = CString::new(CONTROL_PATH).map_err(|error| {
        io_error(
            "encode control path",
            run.project_root(),
            io::Error::new(io::ErrorKind::InvalidInput, error),
        )
    })?;
    let control = stat_entry(project, &control_name)
        .map_err(|source| io_error("inspect control directory", &config_path, source))?;
    if control != ObservedEntry::Directory {
        return Ok(ProjectInitSnapshot {
            control,
            config: ObservedEntry::Missing,
            skills: ObservedEntry::Missing,
        });
    }

    // SAFETY: `project` is the pinned project directory and `control_name` is
    // a live NUL-terminated single component. O_NOFOLLOW rejects links.
    let raw_control = unsafe {
        libc::openat(
            project.as_raw_fd(),
            control_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw_control < 0 {
        return Err(io_error(
            "pin control directory",
            run.project_root().join(CONTROL_PATH),
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: the successful openat returned a fresh owned descriptor.
    let control_directory = unsafe { std::fs::File::from_raw_fd(raw_control) };
    let config_name = CString::new("config.yaml").map_err(|error| {
        io_error(
            "encode config name",
            &config_path,
            io::Error::new(io::ErrorKind::InvalidInput, error),
        )
    })?;
    let mut config = stat_entry(&control_directory, &config_name)
        .map_err(|source| io_error("inspect configuration", &config_path, source))?;
    if config == ObservedEntry::RegularFile(ContentDigest::sha256([])) {
        // SAFETY: `control_directory` is pinned and `config_name` is a live
        // NUL-terminated component. O_NOFOLLOW rejects a substituted link.
        let raw_config = unsafe {
            libc::openat(
                control_directory.as_raw_fd(),
                config_name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw_config < 0 {
            return Err(io_error(
                "open configuration",
                &config_path,
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: the successful openat returned a fresh owned descriptor.
        let mut file = unsafe { std::fs::File::from_raw_fd(raw_config) };
        let mut bytes = Vec::with_capacity(DEFAULT_PROJECT_CONFIG.len());
        file.by_ref()
            .take(u64::try_from(MAX_CONFIG_BYTES + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut bytes)
            .map_err(|source| io_error("read configuration", &config_path, source))?;
        if bytes.len() > MAX_CONFIG_BYTES {
            config = ObservedEntry::Other;
        } else {
            config = ObservedEntry::RegularFile(ContentDigest::sha256(&bytes));
        }
    }
    let skills_name = CString::new("skills").map_err(|error| {
        io_error(
            "encode skills name",
            run.project_root().join(SKILLS_PATH),
            io::Error::new(io::ErrorKind::InvalidInput, error),
        )
    })?;
    let skills = stat_entry(&control_directory, &skills_name).map_err(|source| {
        io_error(
            "inspect skills directory",
            run.project_root().join(SKILLS_PATH),
            source,
        )
    })?;
    Ok(ProjectInitSnapshot {
        control,
        config,
        skills,
    })
}

#[cfg(unix)]
fn stat_entry(parent: &std::fs::File, name: &std::ffi::CStr) -> io::Result<ObservedEntry> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd as _;

    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the parent descriptor and name pointer are live; fstatat writes
    // exactly one `libc::stat` on success.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(ObservedEntry::Missing)
        } else {
            Err(error)
        };
    }
    // SAFETY: fstatat returned success and therefore initialized `stat`.
    let stat = unsafe { stat.assume_init() };
    Ok(match stat.st_mode & libc::S_IFMT {
        libc::S_IFDIR => ObservedEntry::Directory,
        libc::S_IFREG => ObservedEntry::RegularFile(ContentDigest::sha256([])),
        libc::S_IFLNK => ObservedEntry::SymbolicLink,
        _ => ObservedEntry::Other,
    })
}

#[cfg(not(unix))]
fn inspect_project(_run: &ToolRunContext) -> Result<ProjectInitSnapshot, ProjectInitError> {
    Err(ProjectInitError::UnsupportedPlatform(
        "atomic staged directory publication currently requires Unix descriptor-relative rename support",
    ))
}

#[cfg(unix)]
fn sync_current_project(run: &ToolRunContext) -> Result<(), ProjectInitError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let config_path = run.project_root().join(CONFIG_PATH);
    let (_, project_handle) = run
        .host_control_root_handle_for(&config_path, false)
        .map_err(ProjectInitError::Capability)?;
    let dot = CString::new(".").map_err(|error| {
        io_error(
            "encode project directory",
            run.project_root(),
            io::Error::new(io::ErrorKind::InvalidInput, error),
        )
    })?;
    // SAFETY: `project_handle` pins the run root and `dot` resolves that same
    // directory. A readable directory descriptor is required because O_PATH
    // capability descriptors cannot be synchronized.
    let raw_project = unsafe {
        libc::openat(
            project_handle.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw_project < 0 {
        return Err(io_error(
            "open project directory for synchronization",
            run.project_root(),
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: the successful openat returned a fresh owned descriptor.
    let project = unsafe { std::fs::File::from_raw_fd(raw_project) };
    let name = CString::new(CONTROL_PATH).map_err(|error| {
        io_error(
            "encode control path",
            run.project_root(),
            io::Error::new(io::ErrorKind::InvalidInput, error),
        )
    })?;
    // SAFETY: `project` is pinned and `name` is a live NUL-terminated single
    // component. O_NOFOLLOW rejects links.
    let raw = unsafe {
        libc::openat(
            project.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io_error(
            "pin current control directory",
            run.project_root().join(CONTROL_PATH),
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: the successful openat returned a fresh owned descriptor.
    let control = unsafe { std::fs::File::from_raw_fd(raw) };
    control.sync_all().map_err(|source| {
        io_error(
            "synchronize current control directory",
            run.project_root().join(CONTROL_PATH),
            source,
        )
    })?;
    project.sync_all().map_err(|source| {
        io_error(
            "synchronize current project directory",
            run.project_root(),
            source,
        )
    })
}

#[cfg(not(unix))]
fn sync_current_project(_run: &ToolRunContext) -> Result<(), ProjectInitError> {
    Err(ProjectInitError::UnsupportedPlatform(
        "directory durability currently requires Unix descriptor support",
    ))
}

#[cfg(unix)]
fn commit_platform(
    run: &ToolRunContext,
    plan: &ProjectInitPlan,
) -> Result<ProjectInitReceipt, ProjectInitError> {
    unix::commit(run, plan)
}

#[cfg(not(unix))]
fn commit_platform(
    _run: &ToolRunContext,
    _plan: &ProjectInitPlan,
) -> Result<ProjectInitReceipt, ProjectInitError> {
    Err(ProjectInitError::UnsupportedPlatform(
        "atomic staged directory publication currently requires Unix descriptor-relative rename support",
    ))
}

#[cfg(unix)]
mod unix {
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io::{self, Write as _};
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::path::{Path, PathBuf};

    use super::{
        io_error, ProjectInitCommitState, ProjectInitError, ProjectInitPlan, ProjectInitPolicy,
        ProjectInitReceipt, ToolRunContext, CONFIG_PATH, CONTROL_PATH, DEFAULT_PROJECT_CONFIG,
        SCAFFOLD_SCHEMA_VERSION,
    };

    #[derive(Clone, Copy)]
    enum AppliedEntry {
        Created(&'static str),
        Exchanged(&'static str),
    }

    struct StagedTransaction<'a> {
        project_root: &'a Path,
        project: File,
        transaction: File,
        candidate: File,
        candidate_control: File,
        transaction_name: CString,
        transaction_path: PathBuf,
        backup_name: CString,
        backup_path: PathBuf,
        candidate_published: bool,
        retain: bool,
    }

    struct PreparationGuard {
        project: File,
        transaction_name: CString,
        active: bool,
    }

    impl Drop for PreparationGuard {
        fn drop(&mut self) {
            if self.active {
                if let Err(error) = cleanup_named_transaction(&self.project, &self.transaction_name)
                {
                    tracing::warn!(
                        transaction = %self.transaction_name.to_string_lossy(),
                        %error,
                        "failed project initialization preparation cleanup remains inert"
                    );
                }
            }
        }
    }

    impl StagedTransaction<'_> {
        const fn retain_for_recovery(&mut self) {
            self.retain = true;
        }

        fn cleanup(&self) -> io::Result<()> {
            if self.retain {
                return Ok(());
            }
            if !self.candidate_published {
                remove_if_present(&self.candidate_control, c_io("config.yaml")?, false)?;
                remove_if_present(&self.candidate_control, c_io("skills")?, true)?;
                remove_if_present(&self.candidate, c_io(CONTROL_PATH)?, true)?;
            }
            remove_if_present(&self.transaction, c_io("candidate")?, true)?;
            remove_if_present(&self.transaction, c_io("manifest.json")?, false)?;
            remove_if_present(&self.project, &self.transaction_name, true)
        }

        fn publish_backup(&mut self) -> Result<(), ProjectInitError> {
            if let Err(source) = rename_noreplace(
                &self.project,
                &self.transaction_name,
                &self.project,
                &self.backup_name,
            ) {
                self.retain_for_recovery();
                return Err(ProjectInitError::RecoveryRequired {
                    transaction_root: self.transaction_path.clone(),
                    detail: format!(
                        "new scaffold is visible but its recovery backup could not be published at '{}': {source}",
                        self.backup_path.display()
                    ),
                });
            }
            if let Err(source) = self.project.sync_all() {
                self.retain = true;
                return Err(ProjectInitError::RecoveryRequired {
                    transaction_root: self.backup_path.clone(),
                    detail: format!(
                        "recovery backup is visible but project-directory durability is uncertain: {source}"
                    ),
                });
            }
            self.retain = true;
            Ok(())
        }
    }

    impl Drop for StagedTransaction<'_> {
        fn drop(&mut self) {
            if let Err(error) = self.cleanup() {
                tracing::warn!(
                    path = %self.transaction_path.display(),
                    %error,
                    "project initialization staging cleanup remains pending"
                );
            }
        }
    }

    pub(super) fn commit(
        run: &ToolRunContext,
        plan: &ProjectInitPlan,
    ) -> Result<ProjectInitReceipt, ProjectInitError> {
        let mut transaction = stage(run, plan)?;
        let result = if plan.snapshot.control == super::ObservedEntry::Directory {
            apply_below_existing_control(&mut transaction, plan)
        } else {
            apply_control_generation(&mut transaction, plan)
        };
        match result {
            Ok(replaced) => {
                transaction.project.sync_all().map_err(|source| {
                    transaction.retain_for_recovery();
                    ProjectInitError::RecoveryRequired {
                        transaction_root: transaction.transaction_path.clone(),
                        detail: format!(
                            "new scaffold is visible but project-directory durability is uncertain: {source}"
                        ),
                    }
                })?;
                let backup_root = if replaced {
                    transaction.publish_backup()?;
                    Some(plan.backup_root.clone())
                } else {
                    None
                };
                Ok(ProjectInitReceipt {
                    schema_version: SCAFFOLD_SCHEMA_VERSION,
                    generation: plan.generation.clone(),
                    state: if replaced {
                        ProjectInitCommitState::ReplacedWithBackup
                    } else {
                        ProjectInitCommitState::Created
                    },
                    backup_root,
                })
            }
            Err(error) => Err(error),
        }
    }

    #[allow(clippy::too_many_lines)] // Ordered descriptor-relative staging is one rollback unit.
    fn stage<'a>(
        run: &'a ToolRunContext,
        plan: &ProjectInitPlan,
    ) -> Result<StagedTransaction<'a>, ProjectInitError> {
        let config_path = run.project_root().join(CONFIG_PATH);
        let (_, project_handle) = run
            .host_control_root_handle_for(&config_path, true)
            .map_err(ProjectInitError::Capability)?;
        let project = open_directory(project_handle, c(".")?).map_err(|source| {
            io_error(
                "open project directory for transaction",
                run.project_root(),
                source,
            )
        })?;
        let transaction_name = c(&format!(".openclaudia-init-txn-{}", plan.generation))?;
        let backup_name = c(plan
            .backup_root
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| {
                ProjectInitError::Capability("backup path has no UTF-8 leaf".to_string())
            })?)?;
        let mut preparation = PreparationGuard {
            project: project.try_clone().map_err(|source| {
                io_error(
                    "duplicate transaction cleanup descriptor",
                    run.project_root(),
                    source,
                )
            })?,
            transaction_name: transaction_name.clone(),
            active: false,
        };
        mkdir_new(&project, &transaction_name, 0o700).map_err(|source| {
            io_error(
                "create private transaction directory",
                run.project_root()
                    .join(transaction_name.to_string_lossy().as_ref()),
                source,
            )
        })?;
        preparation.active = true;
        let transaction = open_directory(&project, &transaction_name).map_err(|source| {
            io_error(
                "pin private transaction directory",
                run.project_root()
                    .join(transaction_name.to_string_lossy().as_ref()),
                source,
            )
        })?;
        mkdir_new(&transaction, c("candidate")?, 0o700)
            .map_err(|source| io_error("create candidate directory", run.project_root(), source))?;
        let candidate = open_directory(&transaction, c("candidate")?)
            .map_err(|source| io_error("pin candidate directory", run.project_root(), source))?;
        mkdir_new(&candidate, c(CONTROL_PATH)?, 0o700).map_err(|source| {
            io_error(
                "create staged control directory",
                run.project_root(),
                source,
            )
        })?;
        let candidate_control = open_directory(&candidate, c(CONTROL_PATH)?).map_err(|source| {
            io_error("pin staged control directory", run.project_root(), source)
        })?;
        write_new_file(
            &candidate_control,
            c("config.yaml")?,
            DEFAULT_PROJECT_CONFIG.as_bytes(),
        )
        .map_err(|source| io_error("stage configuration", &config_path, source))?;
        mkdir_new(&candidate_control, c("skills")?, 0o700).map_err(|source| {
            io_error(
                "stage skills directory",
                run.project_root().join(".openclaudia/skills"),
                source,
            )
        })?;
        let manifest = serde_json::to_vec_pretty(plan).map_err(|error| {
            ProjectInitError::Capability(format!("cannot encode transaction manifest: {error}"))
        })?;
        write_new_file(&transaction, c("manifest.json")?, &manifest)
            .map_err(|source| io_error("write transaction manifest", run.project_root(), source))?;
        candidate_control.sync_all().map_err(|source| {
            io_error(
                "synchronize staged control tree",
                run.project_root(),
                source,
            )
        })?;
        candidate.sync_all().map_err(|source| {
            io_error("synchronize staged candidate", run.project_root(), source)
        })?;
        transaction.sync_all().map_err(|source| {
            io_error(
                "synchronize transaction directory",
                run.project_root(),
                source,
            )
        })?;
        project.sync_all().map_err(|source| {
            io_error(
                "synchronize transaction publication",
                run.project_root(),
                source,
            )
        })?;

        let staged = StagedTransaction {
            project_root: run.project_root(),
            project,
            transaction,
            candidate,
            candidate_control,
            transaction_path: run
                .project_root()
                .join(transaction_name.to_string_lossy().as_ref()),
            transaction_name,
            backup_path: plan.backup_root.clone(),
            backup_name,
            candidate_published: false,
            retain: false,
        };
        preparation.active = false;
        Ok(staged)
    }

    fn apply_control_generation(
        transaction: &mut StagedTransaction<'_>,
        plan: &ProjectInitPlan,
    ) -> Result<bool, ProjectInitError> {
        let control = c(CONTROL_PATH)?;
        match &plan.snapshot.control {
            super::ObservedEntry::Missing => {
                rename_noreplace(
                    &transaction.candidate,
                    &control,
                    &transaction.project,
                    &control,
                )
                .map_err(|source| {
                    io_error(
                        "publish new control tree",
                        transaction.project_root.join(CONTROL_PATH),
                        source,
                    )
                })?;
                transaction.candidate_published = true;
                Ok(false)
            }
            _ if plan.policy == ProjectInitPolicy::ForceWithBackup => {
                exchange(
                    &transaction.candidate,
                    &control,
                    &transaction.project,
                    &control,
                )
                .map_err(|source| {
                    io_error(
                        "atomically replace control tree",
                        transaction.project_root.join(CONTROL_PATH),
                        source,
                    )
                })?;
                Ok(true)
            }
            _ => Err(ProjectInitError::Collisions {
                paths: vec![PathBuf::from(CONTROL_PATH)],
            }),
        }
    }

    fn apply_below_existing_control(
        transaction: &mut StagedTransaction<'_>,
        plan: &ProjectInitPlan,
    ) -> Result<bool, ProjectInitError> {
        let control = open_directory(&transaction.project, c(CONTROL_PATH)?).map_err(|source| {
            io_error(
                "pin existing control directory",
                transaction.project_root.join(CONTROL_PATH),
                source,
            )
        })?;
        let mut applied = Vec::with_capacity(2);
        if let Err(error) = apply_entry(
            transaction,
            &control,
            "skills",
            ".openclaudia/skills",
            &plan.snapshot.skills,
            plan.policy,
            &mut applied,
        )
        .and_then(|()| {
            apply_entry(
                transaction,
                &control,
                "config.yaml",
                CONFIG_PATH,
                &plan.snapshot.config,
                plan.policy,
                &mut applied,
            )
        }) {
            if let Err(rollback) = rollback_entries(transaction, &control, &applied) {
                transaction.retain_for_recovery();
                return Err(ProjectInitError::RecoveryRequired {
                    transaction_root: transaction.transaction_path.clone(),
                    detail: format!("{error}; rollback failed: {rollback}"),
                });
            }
            return Err(error);
        }
        if let Err(source) = control.sync_all() {
            transaction.retain_for_recovery();
            return Err(ProjectInitError::RecoveryRequired {
                transaction_root: transaction.transaction_path.clone(),
                detail: format!(
                    "scaffold entries are visible but control-directory durability is uncertain: {source}"
                ),
            });
        }
        Ok(applied
            .iter()
            .any(|entry| matches!(entry, AppliedEntry::Exchanged(_))))
    }

    fn apply_entry(
        transaction: &StagedTransaction<'_>,
        control: &File,
        name: &'static str,
        display_path: &'static str,
        observed: &super::ObservedEntry,
        policy: ProjectInitPolicy,
        applied: &mut Vec<AppliedEntry>,
    ) -> Result<(), ProjectInitError> {
        let name_c = c(name)?;
        match observed {
            super::ObservedEntry::Missing => {
                rename_noreplace(&transaction.candidate_control, &name_c, control, &name_c)
                    .map_err(|source| {
                        io_error(
                            "publish scaffold entry",
                            transaction.project_root.join(display_path),
                            source,
                        )
                    })?;
                applied.push(AppliedEntry::Created(name));
            }
            super::ObservedEntry::Directory if name == "skills" => {}
            super::ObservedEntry::RegularFile(digest)
                if name == "config.yaml"
                    && *digest
                        == crate::runtime::ContentDigest::sha256(
                            DEFAULT_PROJECT_CONFIG.as_bytes(),
                        ) => {}
            _ if policy == ProjectInitPolicy::ForceWithBackup => {
                exchange(&transaction.candidate_control, &name_c, control, &name_c).map_err(
                    |source| {
                        io_error(
                            "replace scaffold entry",
                            transaction.project_root.join(display_path),
                            source,
                        )
                    },
                )?;
                applied.push(AppliedEntry::Exchanged(name));
            }
            _ => {
                return Err(ProjectInitError::Collisions {
                    paths: vec![PathBuf::from(display_path)],
                });
            }
        }
        Ok(())
    }

    fn rollback_entries(
        transaction: &StagedTransaction<'_>,
        control: &File,
        applied: &[AppliedEntry],
    ) -> Result<(), String> {
        for entry in applied.iter().rev() {
            match entry {
                AppliedEntry::Created(name) => rename_noreplace(
                    control,
                    c(name).map_err(|error| error.to_string())?,
                    &transaction.candidate_control,
                    c(name).map_err(|error| error.to_string())?,
                ),
                AppliedEntry::Exchanged(name) => exchange(
                    &transaction.candidate_control,
                    c(name).map_err(|error| error.to_string())?,
                    control,
                    c(name).map_err(|error| error.to_string())?,
                ),
            }
            .map_err(|error| error.to_string())?;
        }
        control.sync_all().map_err(|error| error.to_string())
    }

    fn c(value: &str) -> Result<CString, ProjectInitError> {
        CString::new(value).map_err(|_| {
            ProjectInitError::Capability("generated filesystem name contains NUL".to_string())
        })
    }

    fn c_io(value: &str) -> io::Result<CString> {
        CString::new(value).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "generated filesystem name contains NUL",
            )
        })
    }

    fn mkdir_new(parent: &File, name: impl AsRef<CStr>, mode: libc::mode_t) -> io::Result<()> {
        let name = name.as_ref();
        // SAFETY: `parent` is a live directory and `name` is NUL-terminated.
        let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn open_directory(parent: &File, name: impl AsRef<CStr>) -> io::Result<File> {
        let name = name.as_ref();
        // SAFETY: `parent` is pinned and `name` is a live NUL-terminated
        // component. O_NOFOLLOW rejects links.
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: the successful openat returned a fresh owned descriptor.
            Ok(unsafe { File::from_raw_fd(raw) })
        }
    }

    fn write_new_file(parent: &File, name: impl AsRef<CStr>, bytes: &[u8]) -> io::Result<()> {
        let name = name.as_ref();
        // SAFETY: `parent` is pinned and `name` is a live NUL-terminated
        // component. O_EXCL and O_NOFOLLOW prevent overwrite/substitution.
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful openat returned a fresh owned descriptor.
        let mut file = unsafe { File::from_raw_fd(raw) };
        file.write_all(bytes)?;
        file.sync_all()
    }

    fn remove_if_present(parent: &File, name: impl AsRef<CStr>, directory: bool) -> io::Result<()> {
        let name = name.as_ref();
        let flags = if directory { libc::AT_REMOVEDIR } else { 0 };
        // SAFETY: `parent` is a live directory and `name` is a NUL-terminated
        // single component. unlinkat never follows the named leaf.
        let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if result == 0 {
            Ok(())
        } else {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error)
            }
        }
    }

    fn cleanup_named_transaction(project: &File, name: &CStr) -> io::Result<()> {
        let transaction = match open_directory(project, name) {
            Ok(transaction) => transaction,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if let Ok(candidate) = open_directory(&transaction, c_io("candidate")?) {
            if let Ok(control) = open_directory(&candidate, c_io(CONTROL_PATH)?) {
                remove_if_present(&control, c_io("config.yaml")?, false)?;
                remove_if_present(&control, c_io("skills")?, true)?;
                remove_if_present(&candidate, c_io(CONTROL_PATH)?, true)?;
            }
            remove_if_present(&transaction, c_io("candidate")?, true)?;
        }
        remove_if_present(&transaction, c_io("manifest.json")?, false)?;
        remove_if_present(project, name, true)
    }

    #[cfg(target_os = "linux")]
    fn rename_noreplace(
        source_parent: &File,
        source: impl AsRef<CStr>,
        target_parent: &File,
        target: impl AsRef<CStr>,
    ) -> io::Result<()> {
        let source = source.as_ref();
        let target = target.as_ref();
        // SAFETY: both directory descriptors and both NUL-terminated names
        // remain live for the descriptor-relative rename.
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                source_parent.as_raw_fd(),
                source.as_ptr(),
                target_parent.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(target_os = "macos")]
    fn rename_noreplace(
        source_parent: &File,
        source: impl AsRef<CStr>,
        target_parent: &File,
        target: impl AsRef<CStr>,
    ) -> io::Result<()> {
        let source = source.as_ref();
        let target = target.as_ref();
        // SAFETY: both directory descriptors and both NUL-terminated names
        // remain live for the descriptor-relative exclusive rename.
        let result = unsafe {
            libc::renameatx_np(
                source_parent.as_raw_fd(),
                source.as_ptr(),
                target_parent.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    fn rename_noreplace(
        _source_parent: &File,
        _source: impl AsRef<CStr>,
        _target_parent: &File,
        _target: impl AsRef<CStr>,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic no-replace directory rename is unavailable",
        ))
    }

    #[cfg(target_os = "linux")]
    fn exchange(
        left_parent: &File,
        left: impl AsRef<CStr>,
        right_parent: &File,
        right: impl AsRef<CStr>,
    ) -> io::Result<()> {
        let left = left.as_ref();
        let right = right.as_ref();
        // SAFETY: both directory descriptors and both NUL-terminated names
        // remain live for the atomic exchange.
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                left_parent.as_raw_fd(),
                left.as_ptr(),
                right_parent.as_raw_fd(),
                right.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(target_os = "macos")]
    fn exchange(
        left_parent: &File,
        left: impl AsRef<CStr>,
        right_parent: &File,
        right: impl AsRef<CStr>,
    ) -> io::Result<()> {
        let left = left.as_ref();
        let right = right.as_ref();
        // SAFETY: both directory descriptors and both NUL-terminated names
        // remain live for the atomic swap.
        let result = unsafe {
            libc::renameatx_np(
                left_parent.as_raw_fd(),
                left.as_ptr(),
                right_parent.as_raw_fd(),
                right.as_ptr(),
                libc::RENAME_SWAP,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    fn exchange(
        _left_parent: &File,
        _left: impl AsRef<CStr>,
        _right_parent: &File,
        _right: impl AsRef<CStr>,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic directory exchange is unavailable",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_configuration_is_schema_valid_and_inert() {
        serde_yaml::from_str::<crate::config::AppConfig>(DEFAULT_PROJECT_CONFIG)
            .expect("generated configuration must match the current schema");
        let document: serde_yaml::Value =
            serde_yaml::from_str(DEFAULT_PROJECT_CONFIG).expect("generated YAML");

        assert!(document.get("proxy").is_some());
        assert!(document.get("providers").is_some());
        assert!(document.get("hooks").is_none());
        assert!(document.get("rules").is_none());
        assert!(document.get("plugins").is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fresh_initialization_commits_the_complete_minimal_tree() {
        let project = tempfile::tempdir().expect("temporary project");
        let run = crate::tools::security::test_run_context_for(project.path());
        let plan = plan_project_initialization(&run, ProjectInitPolicy::RefuseCollisions)
            .expect("fresh project plan");

        assert_eq!(plan.effects().len(), 3);
        assert!(plan.collisions().is_empty());
        let receipt = commit_project_initialization(&run, &plan).expect("fresh init commit");

        assert_eq!(receipt.state(), ProjectInitCommitState::Created);
        assert_eq!(
            std::fs::read_to_string(project.path().join(CONFIG_PATH)).expect("generated config"),
            DEFAULT_PROJECT_CONFIG
        );
        assert!(project.path().join(SKILLS_PATH).is_dir());
        assert!(!project.path().join(CONTROL_PATH).join("hooks").exists());
        assert!(!project.path().join(CONTROL_PATH).join("rules").exists());
        assert!(transaction_artifacts(project.path()).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collision_refusal_leaves_existing_state_untouched() {
        let project = tempfile::tempdir().expect("temporary project");
        let control = project.path().join(CONTROL_PATH);
        std::fs::create_dir(&control).expect("control directory");
        std::fs::write(control.join("config.yaml"), "owned: true\n").expect("existing config");
        std::fs::write(control.join("keep.txt"), "keep").expect("existing unrelated file");
        let run = crate::tools::security::test_run_context_for(project.path());
        let plan = plan_project_initialization(&run, ProjectInitPolicy::RefuseCollisions)
            .expect("collision plan");

        assert_eq!(plan.collisions().len(), 1);
        assert!(matches!(
            commit_project_initialization(&run, &plan),
            Err(ProjectInitError::Collisions { .. })
        ));
        assert_eq!(
            std::fs::read_to_string(control.join("config.yaml")).expect("existing config"),
            "owned: true\n"
        );
        assert_eq!(
            std::fs::read_to_string(control.join("keep.txt")).expect("unrelated file"),
            "keep"
        );
        assert!(transaction_artifacts(project.path()).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn force_replacement_retains_exact_displaced_state() {
        let project = tempfile::tempdir().expect("temporary project");
        let control = project.path().join(CONTROL_PATH);
        std::fs::create_dir(&control).expect("control directory");
        std::fs::create_dir(control.join("skills")).expect("existing skills");
        std::fs::write(control.join("config.yaml"), "owned: true\n").expect("existing config");
        std::fs::write(control.join("keep.txt"), "keep").expect("unrelated file");
        let run = crate::tools::security::test_run_context_for(project.path());
        let plan = plan_project_initialization(&run, ProjectInitPolicy::ForceWithBackup)
            .expect("force plan");
        let receipt = commit_project_initialization(&run, &plan).expect("force commit");

        assert_eq!(receipt.state(), ProjectInitCommitState::ReplacedWithBackup);
        assert_eq!(
            std::fs::read_to_string(control.join("config.yaml")).expect("replacement config"),
            DEFAULT_PROJECT_CONFIG
        );
        assert_eq!(
            std::fs::read_to_string(control.join("keep.txt")).expect("unrelated file"),
            "keep"
        );
        let backup = receipt.backup_root().expect("force backup receipt");
        assert_eq!(
            std::fs::read_to_string(backup.join("candidate/.openclaudia/config.yaml"))
                .expect("backed-up config"),
            "owned: true\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn changed_destination_invalidates_the_preview() {
        let project = tempfile::tempdir().expect("temporary project");
        let run = crate::tools::security::test_run_context_for(project.path());
        let plan = plan_project_initialization(&run, ProjectInitPolicy::RefuseCollisions)
            .expect("fresh project plan");
        std::fs::create_dir(project.path().join(CONTROL_PATH)).expect("concurrent control path");

        assert!(matches!(
            commit_project_initialization(&run, &plan),
            Err(ProjectInitError::StalePlan)
        ));
        assert!(!project.path().join(CONFIG_PATH).exists());
        assert!(transaction_artifacts(project.path()).is_empty());
    }

    #[cfg(target_os = "linux")]
    fn transaction_artifacts(root: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(root)
            .expect("read project root")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .is_some_and(|name| name.starts_with(".openclaudia-init-txn-"))
            })
            .collect()
    }
}
