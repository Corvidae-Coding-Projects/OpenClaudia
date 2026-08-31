//! Host-owned trust receipts for repository skills.
//!
//! A checkout can propose skill packages by placing files below
//! `.openclaudia/skills`, but it cannot authorize those packages.  Trust is
//! recorded in a private host store and captured into each immutable run.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use thiserror::Error;

const TRUST_SCHEMA_VERSION: u16 = 1;
const MAX_TRUST_STORE_BYTES: u64 = 1024 * 1024;
const MAX_TRUSTED_PROJECTS: usize = 256;
const MAX_ALLOWED_TOOL_SPECS: usize = 128;
const MAX_ALLOWED_TOOL_SPEC_BYTES: usize = 512;
const TRUST_STORE_OVERRIDE_ENV: &str = "OPENCLAUDIA_SKILL_TRUST_STORE";

/// Capability ceiling chosen by the host for one trusted repository.
///
/// Skill files may request these effects, but activation intersects requests
/// with this ceiling.  Merely trusting skill text grants no tool, hook, model,
/// or effort authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "these independent host capability ceilings are serialized policy fields, not state-machine phases"
)]
pub struct SkillCapabilityPolicy {
    #[serde(default)]
    allowed_tools: BTreeSet<String>,
    #[serde(default)]
    allow_model: bool,
    #[serde(default)]
    allow_effort: bool,
    #[serde(default)]
    allow_hooks: bool,
    #[serde(skip)]
    allow_all_declared_tools: bool,
}

impl SkillCapabilityPolicy {
    /// Host-owned user and managed skills retain their declared behavior.
    #[must_use]
    pub(crate) const fn host_owned() -> Self {
        Self {
            allowed_tools: BTreeSet::new(),
            allow_model: true,
            allow_effort: true,
            allow_hooks: true,
            allow_all_declared_tools: true,
        }
    }

    /// Build an explicit repository capability ceiling.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate, empty, oversized, or unbounded tool
    /// specifications.
    pub fn project(
        allowed_tools: Vec<String>,
        allow_model: bool,
        allow_effort: bool,
        allow_hooks: bool,
    ) -> Result<Self, SkillTrustError> {
        if allowed_tools.len() > MAX_ALLOWED_TOOL_SPECS {
            return Err(SkillTrustError::InvalidPolicy(format!(
                "at most {MAX_ALLOWED_TOOL_SPECS} allowed-tool specifications may be trusted"
            )));
        }
        let mut normalized = BTreeSet::new();
        for spec in allowed_tools {
            let spec = spec.trim();
            if spec.is_empty() || spec.len() > MAX_ALLOWED_TOOL_SPEC_BYTES {
                return Err(SkillTrustError::InvalidPolicy(format!(
                    "allowed-tool specifications must contain 1..={MAX_ALLOWED_TOOL_SPEC_BYTES} bytes"
                )));
            }
            if matches!(spec, "*" | "**" | "Bash(*)" | "Bash(**)") {
                return Err(SkillTrustError::InvalidPolicy(format!(
                    "unbounded project skill tool grant '{spec}' is not allowed"
                )));
            }
            if crate::permissions::allowed_tool_spec_to_permission_rule(spec)
                .is_some_and(|rule| matches!(rule.pattern.trim(), "*" | "**"))
            {
                return Err(SkillTrustError::InvalidPolicy(format!(
                    "unbounded project skill tool grant '{spec}' is not allowed"
                )));
            }
            if !normalized.insert(spec.to_string()) {
                return Err(SkillTrustError::InvalidPolicy(format!(
                    "duplicate project skill tool grant '{spec}'"
                )));
            }
        }
        Ok(Self {
            allowed_tools: normalized,
            allow_model,
            allow_effort,
            allow_hooks,
            allow_all_declared_tools: false,
        })
    }

    pub fn allowed_tools(&self) -> impl Iterator<Item = &str> {
        self.allowed_tools.iter().map(String::as_str)
    }

    #[must_use]
    pub const fn allows_model(&self) -> bool {
        self.allow_model
    }

    #[must_use]
    pub const fn allows_effort(&self) -> bool {
        self.allow_effort
    }

    #[must_use]
    pub const fn allows_hooks(&self) -> bool {
        self.allow_hooks
    }

    #[must_use]
    pub(crate) fn allows_tool(&self, requested: &str) -> bool {
        self.allow_all_declared_tools || self.allowed_tools.contains(requested)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectSkillGrant {
    schema_version: u16,
    workspace: PathBuf,
    policy: SkillCapabilityPolicy,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillTrustStore {
    schema_version: u16,
    grants: Vec<ProjectSkillGrant>,
}

impl Default for SkillTrustStore {
    fn default() -> Self {
        Self {
            schema_version: TRUST_SCHEMA_VERSION,
            grants: Vec::new(),
        }
    }
}

/// Immutable repository-skill authority captured by one run.
#[derive(Debug, Clone, Default)]
pub enum ProjectSkillAccess {
    #[default]
    Denied,
    Approved {
        workspace: PathBuf,
        store_path: PathBuf,
        grant_digest: String,
        policy: SkillCapabilityPolicy,
    },
    /// Explicit authority supplied by an embedding host composition root.
    /// This is never constructed from repository data or session persistence.
    HostGranted {
        workspace: PathBuf,
        policy: SkillCapabilityPolicy,
    },
}

impl ProjectSkillAccess {
    fn host_granted(workspace: &Path, policy: SkillCapabilityPolicy) -> Self {
        Self::HostGranted {
            workspace: workspace.to_path_buf(),
            policy,
        }
    }

    /// Return the still-current capability ceiling for `project_root`.
    ///
    /// The host store is rechecked on every catalog refresh, so revocation or
    /// policy narrowing applies to an already-running frontend before another
    /// project skill reaches model context.
    #[must_use]
    pub(crate) fn current_policy(&self, project_root: &Path) -> Option<SkillCapabilityPolicy> {
        match self {
            Self::Denied => None,
            Self::Approved {
                workspace,
                store_path,
                grant_digest,
                policy,
            } => {
                if project_root != workspace {
                    return None;
                }
                let store = load_store(store_path).ok()?;
                store.grants.into_iter().find_map(|grant| {
                    (grant.workspace == *workspace
                        && digest_grant(&grant).ok().as_deref() == Some(grant_digest))
                    .then(|| policy.clone())
                })
            }
            Self::HostGranted { workspace, policy } => {
                (project_root == workspace).then(|| policy.clone())
            }
        }
    }
}

/// Host-owned roots and repository trust captured into an immutable run.
#[derive(Debug, Clone, Default)]
pub struct SkillRunAccess {
    managed_root: Option<PathBuf>,
    user_root: Option<PathBuf>,
    project: ProjectSkillAccess,
}

impl SkillRunAccess {
    /// Capture host skill roots and the exact current project trust receipt.
    #[must_use]
    pub fn capture(project_root: &Path, host_home: Option<&Path>) -> Self {
        let managed_root = capture_managed_root();
        let user_root = host_home.map(|home| home.join(".openclaudia/skills"));
        let project = resolve_project_access(project_root).unwrap_or_else(|error| {
            tracing::warn!(
                target: "openclaudia::skills",
                event = "project_skill_trust_unavailable",
                %error,
                "Repository skills remain inert"
            );
            ProjectSkillAccess::Denied
        });
        Self {
            managed_root,
            user_root,
            project,
        }
    }

    /// Capture only host-managed and user-owned roots.
    #[must_use]
    pub(crate) fn global(host_home: Option<&Path>) -> Self {
        Self {
            managed_root: capture_managed_root(),
            user_root: host_home.map(|home| home.join(".openclaudia/skills")),
            project: ProjectSkillAccess::Denied,
        }
    }

    /// Build an explicit embedding-host grant without consulting ambient
    /// configuration. The caller is the trust authority and must pass a
    /// canonical repository root selected outside repository-controlled data.
    ///
    /// # Errors
    ///
    /// Returns an error when the supplied project root is unavailable or is
    /// not a directory.
    pub fn host_granted_project(
        project_root: &Path,
        policy: SkillCapabilityPolicy,
    ) -> Result<Self, SkillTrustError> {
        Self::from_host_grants(None, None, Some((project_root, policy)))
    }

    /// Compose explicit skill roots and repository authority at an embedding
    /// host boundary without consulting process-global configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when any supplied root cannot be canonicalized to an
    /// existing directory.
    pub fn from_host_grants(
        managed_root: Option<&Path>,
        user_root: Option<&Path>,
        project: Option<(&Path, SkillCapabilityPolicy)>,
    ) -> Result<Self, SkillTrustError> {
        let managed_root = managed_root.map(canonical_skill_root).transpose()?;
        let user_root = user_root.map(canonical_skill_root).transpose()?;
        let project = project.map_or(Ok(ProjectSkillAccess::Denied), |(root, policy)| {
            canonical_workspace(root).map(|root| ProjectSkillAccess::host_granted(&root, policy))
        })?;
        Ok(Self {
            managed_root,
            user_root,
            project,
        })
    }

    /// Capture one repository trust receipt from an explicit host-owned store.
    /// This avoids ambient environment selection in embedding hosts and tests.
    ///
    /// # Errors
    ///
    /// Returns an error when the workspace or trust store is unavailable,
    /// malformed, or does not satisfy the bounded trust schema.
    pub fn capture_project_from_trust_store(
        project_root: &Path,
        store_path: &Path,
    ) -> Result<Self, SkillTrustError> {
        Ok(Self {
            managed_root: None,
            user_root: None,
            project: resolve_project_access_at(project_root, store_path)?,
        })
    }

    #[must_use]
    pub(crate) fn managed_root(&self) -> Option<&Path> {
        self.managed_root.as_deref()
    }

    #[must_use]
    pub(crate) fn user_root(&self) -> Option<&Path> {
        self.user_root.as_deref()
    }

    #[must_use]
    pub(crate) const fn project(&self) -> &ProjectSkillAccess {
        &self.project
    }
}

/// User-visible status of repository skill trust for one workspace.
#[derive(Debug, Clone)]
pub struct SkillTrustStatus {
    pub workspace: PathBuf,
    pub store_path: PathBuf,
    pub policy: Option<SkillCapabilityPolicy>,
}

#[derive(Debug, Error)]
pub enum SkillTrustError {
    #[error("repository skill trust store is unavailable: {0}")]
    StoreUnavailable(String),
    #[error("invalid repository skill trust policy: {0}")]
    InvalidPolicy(String),
    #[error("invalid repository skill trust store {}: {reason}", path.display())]
    InvalidStore { path: PathBuf, reason: String },
    #[error("repository skill trust I/O failed for {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Resolve the host-owned trust-store path.
///
/// # Errors
///
/// Returns an error when the configured override is empty or non-absolute, or
/// when the operating system provides no user data directory.
pub fn skill_trust_store_path() -> Result<PathBuf, SkillTrustError> {
    if let Some(value) = std::env::var_os(TRUST_STORE_OVERRIDE_ENV) {
        if value.is_empty() {
            return Err(SkillTrustError::StoreUnavailable(format!(
                "{TRUST_STORE_OVERRIDE_ENV} is empty"
            )));
        }
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(SkillTrustError::StoreUnavailable(format!(
                "{TRUST_STORE_OVERRIDE_ENV} must be absolute"
            )));
        }
        return Ok(path);
    }
    dirs::data_dir()
        .map(|root| root.join("openclaudia/project-skill-trust.json"))
        .ok_or_else(|| {
            SkillTrustError::StoreUnavailable(
                "the operating system did not provide a user data directory".to_string(),
            )
        })
}

/// Inspect current trust for the process working directory.
///
/// # Errors
///
/// Returns an error when the workspace cannot be canonicalized or the trust
/// store cannot be read and validated.
pub fn inspect_project_skill_trust() -> Result<SkillTrustStatus, SkillTrustError> {
    let workspace = canonical_workspace(Path::new("."))?;
    let store_path = skill_trust_store_path()?;
    inspect_project_skill_trust_at(&workspace, &store_path)
}

/// Explicit-path status seam for frontends and deterministic tests.
///
/// # Errors
///
/// Returns an error when the workspace cannot be canonicalized or the trust
/// store cannot be read and validated.
pub fn inspect_project_skill_trust_at(
    workspace: &Path,
    store_path: &Path,
) -> Result<SkillTrustStatus, SkillTrustError> {
    let workspace = canonical_workspace(workspace)?;
    let policy = match load_store(store_path) {
        Ok(store) => store
            .grants
            .into_iter()
            .find(|grant| grant.workspace == workspace)
            .map(|grant| grant.policy),
        Err(SkillTrustError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    Ok(SkillTrustStatus {
        workspace,
        store_path: store_path.to_path_buf(),
        policy,
    })
}

/// Trust repository skill text and the explicitly selected capability ceiling.
///
/// # Errors
///
/// Returns an error when the workspace or trust store is unavailable, invalid,
/// or cannot be updated atomically.
pub fn trust_project_skills(
    policy: SkillCapabilityPolicy,
) -> Result<SkillTrustStatus, SkillTrustError> {
    let workspace = canonical_workspace(Path::new("."))?;
    let store_path = skill_trust_store_path()?;
    trust_project_skills_at(&workspace, &store_path, policy)
}

/// Trust repository skills using explicit workspace and store paths.
///
/// # Errors
///
/// Returns an error when the workspace or trust store is unavailable, invalid,
/// or cannot be updated atomically.
pub fn trust_project_skills_at(
    workspace: &Path,
    store_path: &Path,
    policy: SkillCapabilityPolicy,
) -> Result<SkillTrustStatus, SkillTrustError> {
    let workspace = canonical_workspace(workspace)?;
    let mut store = load_store_or_default(store_path)?;
    store.grants.retain(|grant| grant.workspace != workspace);
    store.grants.push(ProjectSkillGrant {
        schema_version: TRUST_SCHEMA_VERSION,
        workspace: workspace.clone(),
        policy: policy.clone(),
    });
    store
        .grants
        .sort_by(|left, right| left.workspace.cmp(&right.workspace));
    if store.grants.len() > MAX_TRUSTED_PROJECTS {
        return Err(SkillTrustError::InvalidPolicy(format!(
            "trust store may contain at most {MAX_TRUSTED_PROJECTS} projects"
        )));
    }
    write_store(store_path, &store)?;
    Ok(SkillTrustStatus {
        workspace,
        store_path: store_path.to_path_buf(),
        policy: Some(policy),
    })
}

/// Revoke project skill authority for the current workspace.
///
/// # Errors
///
/// Returns an error when the workspace or trust store is unavailable, invalid,
/// or cannot be updated atomically.
pub fn revoke_project_skills() -> Result<SkillTrustStatus, SkillTrustError> {
    let workspace = canonical_workspace(Path::new("."))?;
    let store_path = skill_trust_store_path()?;
    revoke_project_skills_at(&workspace, &store_path)
}

/// Revoke repository skill authority using explicit workspace and store paths.
///
/// # Errors
///
/// Returns an error when the workspace or trust store is unavailable, invalid,
/// or cannot be updated atomically.
pub fn revoke_project_skills_at(
    workspace: &Path,
    store_path: &Path,
) -> Result<SkillTrustStatus, SkillTrustError> {
    let workspace = canonical_workspace(workspace)?;
    let mut store = load_store_or_default(store_path)?;
    store.grants.retain(|grant| grant.workspace != workspace);
    write_store(store_path, &store)?;
    Ok(SkillTrustStatus {
        workspace,
        store_path: store_path.to_path_buf(),
        policy: None,
    })
}

fn resolve_project_access(project_root: &Path) -> Result<ProjectSkillAccess, SkillTrustError> {
    let store_path = skill_trust_store_path()?;
    resolve_project_access_at(project_root, &store_path)
}

fn resolve_project_access_at(
    project_root: &Path,
    store_path: &Path,
) -> Result<ProjectSkillAccess, SkillTrustError> {
    let workspace = canonical_workspace(project_root)?;
    let store = match load_store(store_path) {
        Ok(store) => store,
        Err(SkillTrustError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(ProjectSkillAccess::Denied);
        }
        Err(error) => return Err(error),
    };
    let Some(grant) = store
        .grants
        .into_iter()
        .find(|grant| grant.workspace == workspace)
    else {
        return Ok(ProjectSkillAccess::Denied);
    };
    let grant_digest = digest_grant(&grant)?;
    Ok(ProjectSkillAccess::Approved {
        workspace,
        store_path: store_path.to_path_buf(),
        grant_digest,
        policy: grant.policy,
    })
}

fn capture_managed_root() -> Option<PathBuf> {
    if std::env::var(super::DISABLE_POLICY_SKILLS_ENV).is_ok_and(|value| !value.is_empty()) {
        return None;
    }
    let root = std::env::var_os(super::MANAGED_PATH_ENV).map(PathBuf::from)?;
    if !root.is_absolute() {
        tracing::warn!(
            target: "openclaudia::skills",
            path = %root.display(),
            "Ignoring relative managed skills root"
        );
        return None;
    }
    Some(root.join("skills"))
}

fn canonical_workspace(path: &Path) -> Result<PathBuf, SkillTrustError> {
    let workspace = fs::canonicalize(path).map_err(|source| SkillTrustError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = fs::metadata(&workspace).map_err(|source| SkillTrustError::Io {
        path: workspace.clone(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(SkillTrustError::InvalidPolicy(format!(
            "workspace '{}' is not a directory",
            workspace.display()
        )));
    }
    Ok(workspace)
}

fn canonical_skill_root(path: &Path) -> Result<PathBuf, SkillTrustError> {
    canonical_workspace(path).map_err(|error| {
        SkillTrustError::InvalidPolicy(format!(
            "host skill root '{}' is unavailable: {error}",
            path.display()
        ))
    })
}

fn digest_grant(grant: &ProjectSkillGrant) -> Result<String, SkillTrustError> {
    let bytes = serde_json::to_vec(grant).map_err(|error| SkillTrustError::InvalidStore {
        path: grant.workspace.clone(),
        reason: error.to_string(),
    })?;
    Ok(digest_bytes(&bytes))
}

fn digest_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(71);
    output.push_str("sha256:");
    for byte in digest {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn load_store(path: &Path) -> Result<SkillTrustStore, SkillTrustError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| SkillTrustError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SkillTrustError::InvalidStore {
            path: path.to_path_buf(),
            reason: "trust store must be a regular non-symlink file".to_string(),
        });
    }
    if metadata.len() > MAX_TRUST_STORE_BYTES {
        return Err(SkillTrustError::InvalidStore {
            path: path.to_path_buf(),
            reason: format!("trust store exceeds {MAX_TRUST_STORE_BYTES} bytes"),
        });
    }
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|source| SkillTrustError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(MAX_TRUST_STORE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| SkillTrustError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_TRUST_STORE_BYTES {
        return Err(SkillTrustError::InvalidStore {
            path: path.to_path_buf(),
            reason: format!("trust store exceeds {MAX_TRUST_STORE_BYTES} bytes"),
        });
    }
    let store: SkillTrustStore =
        serde_json::from_slice(&bytes).map_err(|error| SkillTrustError::InvalidStore {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    validate_store(path, &store)?;
    Ok(store)
}

fn validate_store(path: &Path, store: &SkillTrustStore) -> Result<(), SkillTrustError> {
    if store.schema_version != TRUST_SCHEMA_VERSION {
        return Err(SkillTrustError::InvalidStore {
            path: path.to_path_buf(),
            reason: format!("expected schema version {TRUST_SCHEMA_VERSION}"),
        });
    }
    if store.grants.len() > MAX_TRUSTED_PROJECTS {
        return Err(SkillTrustError::InvalidStore {
            path: path.to_path_buf(),
            reason: format!("more than {MAX_TRUSTED_PROJECTS} projects are trusted"),
        });
    }
    let mut workspaces = BTreeSet::new();
    for grant in &store.grants {
        if grant.schema_version != TRUST_SCHEMA_VERSION
            || !grant.workspace.is_absolute()
            || !workspaces.insert(grant.workspace.clone())
        {
            return Err(SkillTrustError::InvalidStore {
                path: path.to_path_buf(),
                reason: "grant schema, workspace, or uniqueness is invalid".to_string(),
            });
        }
        SkillCapabilityPolicy::project(
            grant.policy.allowed_tools.iter().cloned().collect(),
            grant.policy.allow_model,
            grant.policy.allow_effort,
            grant.policy.allow_hooks,
        )?;
    }
    Ok(())
}

fn load_store_or_default(path: &Path) -> Result<SkillTrustStore, SkillTrustError> {
    match load_store(path) {
        Ok(store) => Ok(store),
        Err(SkillTrustError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(SkillTrustStore::default())
        }
        Err(error) => Err(error),
    }
}

fn write_store(path: &Path, store: &SkillTrustStore) -> Result<(), SkillTrustError> {
    validate_store(path, store)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(SkillTrustError::InvalidStore {
                path: path.to_path_buf(),
                reason: "trust store must be a regular non-symlink file".to_string(),
            });
        }
    }
    let parent = path.parent().ok_or_else(|| {
        SkillTrustError::StoreUnavailable(format!(
            "trust-store path '{}' has no parent",
            path.display()
        ))
    })?;
    fs::create_dir_all(parent).map_err(|source| SkillTrustError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let bytes =
        serde_json::to_vec_pretty(store).map_err(|error| SkillTrustError::InvalidStore {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    let temporary = parent.join(format!(".project-skill-trust.{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|source| SkillTrustError::Io {
            path: temporary.clone(),
            source,
        })?;
    let result = (|| -> Result<(), std::io::Error> {
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()
    })();
    if let Err(source) = result {
        let _ = fs::remove_file(&temporary);
        return Err(SkillTrustError::Io {
            path: temporary,
            source,
        });
    }
    fs::rename(&temporary, path).map_err(|source| {
        let _ = fs::remove_file(&temporary);
        SkillTrustError::Io {
            path: path.to_path_buf(),
            source,
        }
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
            SkillTrustError::Io {
                path: path.to_path_buf(),
                source,
            }
        })?;
    }
    Ok(())
}
