//! Explicit, host-approved imports for repository-owned hook configuration.
//!
//! Recognized repository files are parsed into inert proposals. They become
//! runtime hooks only when an exact proposal receipt exists in the host data
//! directory. The proposal digest binds the canonical workspace and source
//! paths, source bytes, requested events/effects, and command text, so changing
//! any of those properties requires a new approval.

use crate::config::{Hook, HookPolicy, HooksConfig, SandboxMode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{info, warn};

use super::claude_compat::ClaudeCodeSettings;
use super::merge::{merge_claude_hooks, merge_hooks_config};
use super::HookEvent;

const IMPORT_SCHEMA_VERSION: u32 = 1;
const MAX_IMPORT_BYTES: u64 = 256 * 1024;
const MAX_APPROVAL_STORE_BYTES: u64 = 1024 * 1024;
const MAX_IMPORTED_HOOKS: usize = 128;
const MAX_IMPORTED_COMMAND_BYTES: usize = 4096;
const MAX_IMPORTED_TIMEOUT_SECONDS: u64 = 300;
const MAX_BOUND_FILES: usize = 128;
const MAX_BOUND_FILE_BYTES: u64 = 1024 * 1024;
const MAX_BOUND_FILES_TOTAL_BYTES: u64 = 4 * 1024 * 1024;
const APPROVAL_STORE_OVERRIDE_ENV: &str = "OPENCLAUDIA_HOOK_APPROVALS_PATH";

/// Repository hook format recognized by the compatibility importer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookImportKind {
    /// The `hooks:` block of `.openclaudia/config.yaml`.
    OpenClaudiaProject,
    /// Claude-compatible `.claude/settings.json`.
    ClaudeProject,
    /// Claude-compatible `.claude/settings.local.json`.
    ClaudeProjectLocal,
}

impl std::fmt::Display for HookImportKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::OpenClaudiaProject => "openclaudia_project",
            Self::ClaudeProject => "claude_project",
            Self::ClaudeProjectLocal => "claude_project_local",
        };
        formatter.write_str(name)
    }
}

/// Whether a discovered proposal has an exact host-owned approval receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookImportState {
    /// No receipt has ever been stored for this source in this workspace.
    Pending,
    /// A prior receipt exists, but the current proposal no longer matches it.
    Changed,
    /// The current proposal exactly matches a host-owned receipt.
    Approved,
}

/// User-visible, inert description of a repository hook import request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HookImportProposal {
    pub schema_version: u32,
    pub kind: HookImportKind,
    pub workspace: PathBuf,
    pub source: PathBuf,
    pub source_digest: String,
    pub proposal_digest: String,
    pub requested_events: Vec<String>,
    pub requested_effects: Vec<String>,
    pub commands: Vec<String>,
    pub bound_files: Vec<HookImportBoundFile>,
    pub hook_count: usize,
    pub state: HookImportState,
}

/// Repository-resident program or helper content bound into an import receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookImportBoundFile {
    pub path: PathBuf,
    pub digest: String,
    pub bytes: u64,
}

/// Visible discovery or approval failure. Invalid files never activate a
/// partial hook set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HookImportDiagnostic {
    pub source: Option<PathBuf>,
    pub message: String,
}

/// Complete repository hook-import inspection result.
#[derive(Debug, Clone, Default, Serialize)]
pub struct HookImportReport {
    pub proposals: Vec<HookImportProposal>,
    pub diagnostics: Vec<HookImportDiagnostic>,
}

/// Errors returned by explicit approve/revoke operations.
#[derive(Debug, Error)]
pub enum HookImportError {
    #[error("hook import path `{path}` is invalid: {reason}")]
    InvalidPath { path: PathBuf, reason: String },
    #[error("failed to read hook import `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse hook import `{path}`: {reason}")]
    Parse { path: PathBuf, reason: String },
    #[error("hook import `{path}` is unsupported: {reason}")]
    Unsupported { path: PathBuf, reason: String },
    #[error("host hook approval store is unavailable: {0}")]
    ApprovalStoreUnavailable(String),
    #[error("hook import proposal `{0}` is not present in the current workspace")]
    ProposalNotFound(String),
    #[error("hook import approval `{0}` is not present")]
    ApprovalNotFound(String),
    #[error("failed to write host hook approval store `{path}`: {source}")]
    WriteApproval {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug)]
struct ImportCandidate {
    proposal: HookImportProposal,
    hooks: HooksConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HookImportApproval {
    schema_version: u32,
    kind: HookImportKind,
    workspace: PathBuf,
    source: PathBuf,
    source_digest: String,
    proposal_digest: String,
    requested_events: Vec<String>,
    requested_effects: Vec<String>,
    commands: Vec<String>,
    bound_files: Vec<HookImportBoundFile>,
    hook_count: usize,
}

impl From<&HookImportProposal> for HookImportApproval {
    fn from(proposal: &HookImportProposal) -> Self {
        Self {
            schema_version: proposal.schema_version,
            kind: proposal.kind,
            workspace: proposal.workspace.clone(),
            source: proposal.source.clone(),
            source_digest: proposal.source_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            requested_events: proposal.requested_events.clone(),
            requested_effects: proposal.requested_effects.clone(),
            commands: proposal.commands.clone(),
            bound_files: proposal.bound_files.clone(),
            hook_count: proposal.hook_count,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HookImportApprovalStore {
    schema_version: u32,
    approvals: Vec<HookImportApproval>,
}

impl Default for HookImportApprovalStore {
    fn default() -> Self {
        Self {
            schema_version: IMPORT_SCHEMA_VERSION,
            approvals: Vec::new(),
        }
    }
}

#[derive(Serialize)]
struct ProposalFingerprint<'a> {
    schema_version: u32,
    kind: HookImportKind,
    workspace: &'a Path,
    source: &'a Path,
    source_digest: &'a str,
    requested_events: &'a [String],
    requested_effects: &'a [String],
    commands: &'a [String],
    bound_files: &'a [HookImportBoundFile],
    hook_count: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryClaudeSettings {
    #[serde(default)]
    hooks: std::collections::HashMap<String, Vec<super::claude_compat::ClaudeCodeHookEntry>>,
}

/// Return the host-owned approval-store path. There is deliberately no
/// repository-relative fallback: inability to locate a host data directory
/// leaves every repository proposal inert.
///
/// # Errors
///
/// Returns an error when the explicit override is empty or the operating
/// system cannot provide a user data directory.
pub fn hook_import_approval_store_path() -> Result<PathBuf, HookImportError> {
    if let Some(path) = std::env::var_os(APPROVAL_STORE_OVERRIDE_ENV) {
        if path.is_empty() {
            return Err(HookImportError::ApprovalStoreUnavailable(format!(
                "{APPROVAL_STORE_OVERRIDE_ENV} is empty"
            )));
        }
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(HookImportError::ApprovalStoreUnavailable(format!(
                "{APPROVAL_STORE_OVERRIDE_ENV} must be an absolute host path"
            )));
        }
        return Ok(path);
    }
    dirs::data_dir()
        .map(|directory| {
            directory
                .join("openclaudia")
                .join("hook-import-approvals.json")
        })
        .ok_or_else(|| {
            HookImportError::ApprovalStoreUnavailable(
                "the operating system did not provide a user data directory".to_string(),
            )
        })
}

/// Inspect repository hook proposals in the current workspace.
#[must_use]
pub fn inspect_repository_hook_imports() -> HookImportReport {
    let workspace = match canonical_workspace(Path::new(".")) {
        Ok(workspace) => workspace,
        Err(error) => {
            return HookImportReport {
                proposals: Vec::new(),
                diagnostics: vec![diagnostic_from_error(&error)],
            };
        }
    };
    let approval_path = match hook_import_approval_store_path() {
        Ok(path) => path,
        Err(error) => {
            let (candidates, mut diagnostics) = discover_candidates(&workspace);
            diagnostics.push(diagnostic_from_error(&error));
            return HookImportReport {
                proposals: candidates
                    .into_iter()
                    .map(|candidate| candidate.proposal)
                    .collect(),
                diagnostics,
            };
        }
    };
    inspect_repository_hook_imports_at(&workspace, &approval_path)
}

/// Inspect repository proposals using explicit paths. This is also the
/// deterministic test seam for trust-boundary tests.
#[must_use]
pub fn inspect_repository_hook_imports_at(
    workspace: &Path,
    approval_path: &Path,
) -> HookImportReport {
    load_approved_repository_hooks_at(workspace, approval_path).1
}

/// Resolve exact approved repository hooks and their typed report.
///
/// Supplying an explicit approval path is intended for host integrations and
/// deterministic trust-boundary tests.
#[must_use]
pub fn load_approved_repository_hooks_at(
    workspace: &Path,
    approval_path: &Path,
) -> (HooksConfig, HookImportReport) {
    resolve_repository_hook_imports_at(workspace, approval_path)
}

/// Approve one currently discovered proposal and persist the exact receipt in
/// the host store. A digest copied from an old or different workspace cannot
/// be approved.
///
/// # Errors
///
/// Returns an error when the current workspace, approval store, proposal, or
/// atomic store write cannot be validated.
pub fn approve_repository_hook_import(
    proposal_digest: &str,
) -> Result<HookImportProposal, HookImportError> {
    let workspace = canonical_workspace(Path::new("."))?;
    let approval_path = hook_import_approval_store_path()?;
    approve_repository_hook_import_at(&workspace, &approval_path, proposal_digest)
}

/// Explicit-path form of [`approve_repository_hook_import`].
///
/// # Errors
///
/// Returns an error when the workspace cannot be canonicalized, the digest is
/// not a current proposal, the existing store is invalid, or persistence fails.
pub fn approve_repository_hook_import_at(
    workspace: &Path,
    approval_path: &Path,
    proposal_digest: &str,
) -> Result<HookImportProposal, HookImportError> {
    let workspace = canonical_workspace(workspace)?;
    let candidates = discover_candidates(&workspace).0;
    let candidate = candidates
        .into_iter()
        .find(|candidate| candidate.proposal.proposal_digest == proposal_digest)
        .ok_or_else(|| HookImportError::ProposalNotFound(proposal_digest.to_string()))?;
    let mut store = load_approval_store_or_default(approval_path)?;
    store.approvals.retain(|approval| {
        approval.workspace != candidate.proposal.workspace
            || approval.source != candidate.proposal.source
    });
    store
        .approvals
        .push(HookImportApproval::from(&candidate.proposal));
    store
        .approvals
        .sort_by(|left, right| left.proposal_digest.cmp(&right.proposal_digest));
    write_approval_store(approval_path, &store)?;
    let mut proposal = candidate.proposal;
    proposal.state = HookImportState::Approved;
    Ok(proposal)
}

/// Remove an approval receipt. Revocation is effective on the next hook-engine
/// construction and never modifies repository content.
///
/// # Errors
///
/// Returns an error when the host store is unavailable, invalid, or does not
/// contain the exact digest, or when the updated store cannot be persisted.
pub fn revoke_repository_hook_import(proposal_digest: &str) -> Result<(), HookImportError> {
    let approval_path = hook_import_approval_store_path()?;
    revoke_repository_hook_import_at(&approval_path, proposal_digest)
}

/// Explicit-path form of [`revoke_repository_hook_import`].
///
/// # Errors
///
/// Returns an error when the store is unavailable or invalid, the exact digest
/// is absent, or the updated store cannot be persisted.
pub fn revoke_repository_hook_import_at(
    approval_path: &Path,
    proposal_digest: &str,
) -> Result<(), HookImportError> {
    let mut store = load_approval_store(approval_path)?;
    let original_len = store.approvals.len();
    store
        .approvals
        .retain(|approval| approval.proposal_digest != proposal_digest);
    if store.approvals.len() == original_len {
        return Err(HookImportError::ApprovalNotFound(
            proposal_digest.to_string(),
        ));
    }
    write_approval_store(approval_path, &store)
}

/// Load only repository hooks carrying an exact current host approval.
/// Diagnostics are logged with the proposal digest needed by the CLI review
/// command; unapproved and invalid candidates remain inert.
#[must_use]
pub(crate) fn load_approved_repository_hooks() -> HooksConfig {
    let workspace = match canonical_workspace(Path::new(".")) {
        Ok(workspace) => workspace,
        Err(error) => {
            warn!(error = %error, "repository hook imports unavailable");
            return HooksConfig::default();
        }
    };
    let approval_path = match hook_import_approval_store_path() {
        Ok(path) => path,
        Err(error) => {
            warn!(error = %error, "repository hook imports remain inert");
            return HooksConfig::default();
        }
    };
    let (hooks, report) = resolve_repository_hook_imports_at(&workspace, &approval_path);
    log_report(&report);
    hooks
}

fn resolve_repository_hook_imports_at(
    workspace: &Path,
    approval_path: &Path,
) -> (HooksConfig, HookImportReport) {
    let workspace = match canonical_workspace(workspace) {
        Ok(workspace) => workspace,
        Err(error) => {
            return (
                HooksConfig::default(),
                HookImportReport {
                    proposals: Vec::new(),
                    diagnostics: vec![diagnostic_from_error(&error)],
                },
            );
        }
    };
    let (mut candidates, mut diagnostics) = discover_candidates(&workspace);
    let store = match load_approval_store(approval_path) {
        Ok(store) => store,
        Err(HookImportError::Read { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            HookImportApprovalStore::default()
        }
        Err(error) => {
            diagnostics.push(diagnostic_from_error(&error));
            HookImportApprovalStore::default()
        }
    };

    let mut active = HooksConfig::default();
    let mut proposals = Vec::with_capacity(candidates.len());
    for candidate in &mut candidates {
        let exact = store.approvals.iter().any(|approval| {
            approval.proposal_digest == candidate.proposal.proposal_digest
                && approval.workspace == candidate.proposal.workspace
                && approval.source == candidate.proposal.source
                && approval.source_digest == candidate.proposal.source_digest
        });
        let prior = store.approvals.iter().any(|approval| {
            approval.workspace == candidate.proposal.workspace
                && approval.source == candidate.proposal.source
        });
        candidate.proposal.state = if exact {
            HookImportState::Approved
        } else if prior {
            HookImportState::Changed
        } else {
            HookImportState::Pending
        };
        if exact {
            active = merge_hooks_config(active, candidate.hooks.clone());
        }
        proposals.push(candidate.proposal.clone());
    }

    if !active.is_empty() {
        active.policy = Some(import_policy(&active));
    }
    (
        active,
        HookImportReport {
            proposals,
            diagnostics,
        },
    )
}

fn discover_candidates(workspace: &Path) -> (Vec<ImportCandidate>, Vec<HookImportDiagnostic>) {
    let sources = [
        (
            HookImportKind::OpenClaudiaProject,
            workspace.join(".openclaudia/config.yaml"),
        ),
        (
            HookImportKind::ClaudeProject,
            workspace.join(".claude/settings.json"),
        ),
        (
            HookImportKind::ClaudeProjectLocal,
            workspace.join(".claude/settings.local.json"),
        ),
    ];
    let mut candidates = Vec::new();
    let mut diagnostics = Vec::new();
    for (kind, path) in sources {
        match discover_candidate(workspace, &path, kind) {
            Ok(Some(candidate)) => candidates.push(candidate),
            Ok(None) => {}
            Err(error) => diagnostics.push(diagnostic_from_error(&error)),
        }
    }
    (candidates, diagnostics)
}

fn discover_candidate(
    workspace: &Path,
    path: &Path,
    kind: HookImportKind,
) -> Result<Option<ImportCandidate>, HookImportError> {
    let Some(bytes) = read_bounded_file(path, MAX_IMPORT_BYTES)? else {
        return Ok(None);
    };
    let source = path
        .canonicalize()
        .map_err(|source| HookImportError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if !source.starts_with(workspace) {
        return Err(HookImportError::InvalidPath {
            path: path.to_path_buf(),
            reason: format!(
                "canonical source `{}` escapes canonical workspace `{}`",
                source.display(),
                workspace.display()
            ),
        });
    }

    let hooks = match kind {
        HookImportKind::OpenClaudiaProject => parse_native_project_hooks(&source, &bytes)?,
        HookImportKind::ClaudeProject | HookImportKind::ClaudeProjectLocal => {
            parse_repository_claude_hooks(&source, &bytes)?
        }
    };
    if hooks.is_empty() {
        return Ok(None);
    }
    if hooks.policy.is_some() {
        return Err(HookImportError::Unsupported {
            path: source,
            reason: "repository imports cannot define or weaken host hook policy".to_string(),
        });
    }
    let metadata = validate_and_describe_hooks(&source, &hooks)?;
    let bound_files = discover_bound_files(workspace, kind, &metadata.commands)?;
    let source_digest = digest_bytes(&bytes);
    let fingerprint = ProposalFingerprint {
        schema_version: IMPORT_SCHEMA_VERSION,
        kind,
        workspace,
        source: &source,
        source_digest: &source_digest,
        requested_events: &metadata.events,
        requested_effects: &metadata.effects,
        commands: &metadata.commands,
        bound_files: &bound_files,
        hook_count: metadata.hook_count,
    };
    let fingerprint_bytes =
        serde_json::to_vec(&fingerprint).map_err(|error| HookImportError::Parse {
            path: source.clone(),
            reason: format!("failed to construct deterministic proposal: {error}"),
        })?;
    let proposal = HookImportProposal {
        schema_version: IMPORT_SCHEMA_VERSION,
        kind,
        workspace: workspace.to_path_buf(),
        source,
        source_digest,
        proposal_digest: digest_bytes(&fingerprint_bytes),
        requested_events: metadata.events,
        requested_effects: metadata.effects,
        commands: metadata.commands,
        bound_files,
        hook_count: metadata.hook_count,
        state: HookImportState::Pending,
    };
    Ok(Some(ImportCandidate { proposal, hooks }))
}

fn canonical_workspace(workspace: &Path) -> Result<PathBuf, HookImportError> {
    workspace
        .canonicalize()
        .map_err(|source| HookImportError::Read {
            path: workspace.to_path_buf(),
            source,
        })
}

fn read_bounded_file(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, HookImportError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(HookImportError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(HookImportError::InvalidPath {
            path: path.to_path_buf(),
            reason: "source must be a regular, non-symlink file".to_string(),
        });
    }
    if metadata.len() > limit {
        return Err(HookImportError::InvalidPath {
            path: path.to_path_buf(),
            reason: format!("file is {} bytes; limit is {limit} bytes", metadata.len()),
        });
    }
    let mut file = File::open(path).map_err(|source| HookImportError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let capacity = usize::try_from(metadata.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    std::io::Read::by_ref(&mut file)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| HookImportError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(HookImportError::InvalidPath {
            path: path.to_path_buf(),
            reason: format!("file changed while reading and exceeded {limit} bytes"),
        });
    }
    Ok(Some(bytes))
}

fn parse_native_project_hooks(path: &Path, bytes: &[u8]) -> Result<HooksConfig, HookImportError> {
    let document: serde_yaml::Value =
        serde_yaml::from_slice(bytes).map_err(|error| HookImportError::Parse {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    let Some(mapping) = document.as_mapping() else {
        return Err(HookImportError::Parse {
            path: path.to_path_buf(),
            reason: "top-level OpenClaudia config must be a mapping".to_string(),
        });
    };
    let key = serde_yaml::Value::String("hooks".to_string());
    let Some(hooks) = mapping.get(&key) else {
        return Ok(HooksConfig::default());
    };
    serde_yaml::from_value(hooks.clone()).map_err(|error| HookImportError::Parse {
        path: path.to_path_buf(),
        reason: format!("invalid hooks block: {error}"),
    })
}

fn parse_repository_claude_hooks(
    path: &Path,
    bytes: &[u8],
) -> Result<HooksConfig, HookImportError> {
    let document: RepositoryClaudeSettings =
        serde_json::from_slice(bytes).map_err(|error| HookImportError::Parse {
            path: path.to_path_buf(),
            reason: format!(
                "repository Claude settings imports accept only an exact hooks schema: {error}"
            ),
        })?;
    if let Some(event) = document
        .hooks
        .keys()
        .find(|event| HookEvent::from_claude_code_name(event).is_none())
    {
        return Err(HookImportError::Unsupported {
            path: path.to_path_buf(),
            reason: format!("unknown hook event `{event}`; refusing partial import"),
        });
    }
    let settings = ClaudeCodeSettings {
        hooks: document.hooks,
    };
    let mut config = HooksConfig::default();
    merge_claude_hooks(&mut config, &settings);
    Ok(config)
}

fn discover_bound_files(
    workspace: &Path,
    kind: HookImportKind,
    commands: &[String],
) -> Result<Vec<HookImportBoundFile>, HookImportError> {
    let mut files = BTreeMap::new();
    let mut total_bytes = 0u64;
    for command in commands {
        let tokens = shlex::split(command).ok_or_else(|| HookImportError::Unsupported {
            path: workspace.to_path_buf(),
            reason: format!("command is not valid direct-spawn syntax: {command}"),
        })?;
        for token in tokens {
            let token_path = token
                .split_once('=')
                .map_or(token.as_str(), |(_, value)| value);
            if !looks_like_repository_path(token_path) {
                continue;
            }
            let candidate = Path::new(token_path);
            let candidate = if candidate.is_absolute() {
                candidate.to_path_buf()
            } else {
                workspace.join(candidate)
            };
            if !candidate.exists() {
                return Err(HookImportError::InvalidPath {
                    path: candidate,
                    reason: "repository-resident command file does not exist".to_string(),
                });
            }
            add_bound_path(workspace, &candidate, &mut files, &mut total_bytes)?;
        }
    }

    if matches!(
        kind,
        HookImportKind::ClaudeProject | HookImportKind::ClaudeProjectLocal
    ) {
        let package = workspace.join(".claude/hooks");
        if package.exists() {
            add_bound_path(workspace, &package, &mut files, &mut total_bytes)?;
        }
    }
    Ok(files.into_values().collect())
}

fn looks_like_repository_path(token: &str) -> bool {
    let path = Path::new(token);
    path.is_absolute()
        || token.starts_with('.')
        || token.contains('/')
        || token.contains('\\')
        || [".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bash"]
            .iter()
            .any(|extension| token.ends_with(extension))
}

fn add_bound_path(
    workspace: &Path,
    path: &Path,
    files: &mut BTreeMap<PathBuf, HookImportBoundFile>,
    total_bytes: &mut u64,
) -> Result<(), HookImportError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| HookImportError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(HookImportError::InvalidPath {
            path: path.to_path_buf(),
            reason: "bound command content cannot be a symlink".to_string(),
        });
    }
    let canonical = path
        .canonicalize()
        .map_err(|source| HookImportError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if !canonical.starts_with(workspace) {
        return Err(HookImportError::InvalidPath {
            path: path.to_path_buf(),
            reason: format!(
                "bound command content `{}` escapes canonical workspace `{}`",
                canonical.display(),
                workspace.display()
            ),
        });
    }
    if metadata.is_dir() {
        let mut children = fs::read_dir(&canonical)
            .map_err(|source| HookImportError::Read {
                path: canonical.clone(),
                source,
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| HookImportError::Read {
                path: canonical.clone(),
                source,
            })?;
        children.sort_by_key(std::fs::DirEntry::file_name);
        for child in children {
            if generated_cache_entry(&child.path()) {
                continue;
            }
            add_bound_path(workspace, &child.path(), files, total_bytes)?;
        }
        return Ok(());
    }
    if !metadata.is_file() {
        return Err(HookImportError::InvalidPath {
            path: canonical,
            reason: "bound command content must be a regular file or directory".to_string(),
        });
    }
    if files.contains_key(&canonical) {
        return Ok(());
    }
    if files.len() >= MAX_BOUND_FILES {
        return Err(HookImportError::Unsupported {
            path: canonical,
            reason: format!("more than {MAX_BOUND_FILES} repository command files requested"),
        });
    }
    let Some(bytes) = read_bounded_file(&canonical, MAX_BOUND_FILE_BYTES)? else {
        return Err(HookImportError::InvalidPath {
            path: canonical,
            reason: "bound command file disappeared while reading".to_string(),
        });
    };
    let byte_count = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    *total_bytes = total_bytes.saturating_add(byte_count);
    if *total_bytes > MAX_BOUND_FILES_TOTAL_BYTES {
        return Err(HookImportError::Unsupported {
            path: canonical,
            reason: format!(
                "repository command files exceed {MAX_BOUND_FILES_TOTAL_BYTES} total bytes"
            ),
        });
    }
    files.insert(
        canonical.clone(),
        HookImportBoundFile {
            path: canonical,
            digest: digest_bytes(&bytes),
            bytes: byte_count,
        },
    );
    Ok(())
}

fn generated_cache_entry(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "__pycache__")
        || path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| matches!(extension, "pyc" | "pyo"))
}

struct HookMetadata {
    events: Vec<String>,
    effects: Vec<String>,
    commands: Vec<String>,
    hook_count: usize,
}

fn validate_and_describe_hooks(
    path: &Path,
    config: &HooksConfig,
) -> Result<HookMetadata, HookImportError> {
    let mut events = BTreeSet::new();
    let mut effects = BTreeSet::new();
    let mut commands = BTreeSet::new();
    let mut hook_count = 0usize;
    for (event, entries) in hook_slots(config) {
        if entries.is_empty() {
            continue;
        }
        events.insert(event.to_string());
        if matches!(event, "pre_tool_use" | "permission_request") {
            effects.insert("block_action".to_string());
        }
        for entry in entries {
            for hook in &entry.hooks {
                hook_count = hook_count.saturating_add(1);
                if hook_count > MAX_IMPORTED_HOOKS {
                    return Err(HookImportError::Unsupported {
                        path: path.to_path_buf(),
                        reason: format!("requested more than {MAX_IMPORTED_HOOKS} hook actions"),
                    });
                }
                match hook {
                    Hook::Command {
                        command,
                        shell,
                        timeout,
                    } => {
                        if *shell {
                            return Err(HookImportError::Unsupported {
                                path: path.to_path_buf(),
                                reason: "repository imports cannot request shell:true".to_string(),
                            });
                        }
                        if command.is_empty() || command.len() > MAX_IMPORTED_COMMAND_BYTES {
                            return Err(HookImportError::Unsupported {
                                path: path.to_path_buf(),
                                reason: format!(
                                    "command length must be 1..={MAX_IMPORTED_COMMAND_BYTES} bytes"
                                ),
                            });
                        }
                        if *timeout == 0 || *timeout > MAX_IMPORTED_TIMEOUT_SECONDS {
                            return Err(HookImportError::Unsupported {
                                path: path.to_path_buf(),
                                reason: format!(
                                    "command timeout must be 1..={MAX_IMPORTED_TIMEOUT_SECONDS} seconds"
                                ),
                            });
                        }
                        let tokens =
                            shlex::split(command).ok_or_else(|| HookImportError::Unsupported {
                                path: path.to_path_buf(),
                                reason: format!(
                                    "command is not valid direct-spawn syntax: {command}"
                                ),
                            })?;
                        if tokens.is_empty() {
                            return Err(HookImportError::Unsupported {
                                path: path.to_path_buf(),
                                reason: "command has no executable".to_string(),
                            });
                        }
                        commands.insert(command.clone());
                        effects.insert("execute_process".to_string());
                        effects.insert("read_workspace".to_string());
                        effects.insert("write_workspace_sandboxed".to_string());
                        effects.insert("emit_decision".to_string());
                        effects.insert("emit_reference_context".to_string());
                    }
                    Hook::Prompt { .. } => {
                        effects.insert("emit_reference_context".to_string());
                    }
                    Hook::Model { .. } => {
                        return Err(HookImportError::Unsupported {
                            path: path.to_path_buf(),
                            reason: "repository model hooks are unavailable until the canonical provider path is wired"
                                .to_string(),
                        });
                    }
                }
            }
        }
    }
    Ok(HookMetadata {
        events: events.into_iter().collect(),
        effects: effects.into_iter().collect(),
        commands: commands.into_iter().collect(),
        hook_count,
    })
}

fn hook_slots(config: &HooksConfig) -> [(&'static str, &[crate::config::HookEntry]); 16] {
    [
        ("session_start", &config.session_start),
        ("session_end", &config.session_end),
        ("pre_tool_use", &config.pre_tool_use),
        ("post_tool_use", &config.post_tool_use),
        ("post_tool_use_failure", &config.post_tool_use_failure),
        ("user_prompt_submit", &config.user_prompt_submit),
        ("stop", &config.stop),
        ("subagent_start", &config.subagent_start),
        ("subagent_stop", &config.subagent_stop),
        ("pre_compact", &config.pre_compact),
        ("permission_request", &config.permission_request),
        ("notification", &config.notification),
        ("pre_adversary_review", &config.pre_adversary_review),
        ("post_adversary_review", &config.post_adversary_review),
        ("vdd_conflict", &config.vdd_conflict),
        ("vdd_converged", &config.vdd_converged),
    ]
}

fn import_policy(config: &HooksConfig) -> HookPolicy {
    let mut allowed_commands = HashSet::new();
    for (_, entries) in hook_slots(config) {
        for entry in entries {
            for hook in &entry.hooks {
                let Hook::Command { command, .. } = hook else {
                    continue;
                };
                if let Some(executable) = shlex::split(command).and_then(|tokens| {
                    tokens.first().and_then(|token| {
                        Path::new(token)
                            .file_name()
                            .and_then(|name| name.to_str())
                            .map(str::to_string)
                    })
                }) {
                    allowed_commands.insert(executable);
                }
            }
        }
    }
    HookPolicy {
        allowed_commands: Some(allowed_commands),
        sandbox: SandboxMode::FullSandbox,
    }
}

fn load_approval_store(path: &Path) -> Result<HookImportApprovalStore, HookImportError> {
    let Some(bytes) = read_bounded_file(path, MAX_APPROVAL_STORE_BYTES)? else {
        return Err(HookImportError::Read {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "approval store does not exist",
            ),
        });
    };
    let store: HookImportApprovalStore =
        serde_json::from_slice(&bytes).map_err(|error| HookImportError::Parse {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    if store.schema_version != IMPORT_SCHEMA_VERSION
        || store
            .approvals
            .iter()
            .any(|approval| approval.schema_version != IMPORT_SCHEMA_VERSION)
    {
        return Err(HookImportError::Parse {
            path: path.to_path_buf(),
            reason: format!(
                "unsupported approval schema; expected version {IMPORT_SCHEMA_VERSION}"
            ),
        });
    }
    Ok(store)
}

fn load_approval_store_or_default(path: &Path) -> Result<HookImportApprovalStore, HookImportError> {
    match load_approval_store(path) {
        Ok(store) => Ok(store),
        Err(HookImportError::Read { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(HookImportApprovalStore::default())
        }
        Err(error) => Err(error),
    }
}

fn write_approval_store(
    path: &Path,
    store: &HookImportApprovalStore,
) -> Result<(), HookImportError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(HookImportError::InvalidPath {
                path: path.to_path_buf(),
                reason: "approval store must be a regular, non-symlink file".to_string(),
            });
        }
    }
    let parent = path.parent().ok_or_else(|| {
        HookImportError::ApprovalStoreUnavailable(format!(
            "approval path `{}` has no parent directory",
            path.display()
        ))
    })?;
    fs::create_dir_all(parent).map_err(|source| HookImportError::WriteApproval {
        path: path.to_path_buf(),
        source,
    })?;
    let bytes = serde_json::to_vec_pretty(store).map_err(|error| {
        HookImportError::ApprovalStoreUnavailable(format!(
            "failed to serialize approval store: {error}"
        ))
    })?;
    let temp_path = parent.join(format!(
        ".hook-import-approvals.{}.tmp",
        uuid::Uuid::new_v4()
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp_path)
        .map_err(|source| HookImportError::WriteApproval {
            path: temp_path.clone(),
            source,
        })?;
    let write_result = (|| -> Result<(), std::io::Error> {
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()
    })();
    if let Err(source) = write_result {
        let _ = fs::remove_file(&temp_path);
        return Err(HookImportError::WriteApproval {
            path: temp_path,
            source,
        });
    }
    fs::rename(&temp_path, path).map_err(|source| {
        let _ = fs::remove_file(&temp_path);
        HookImportError::WriteApproval {
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(())
}

fn digest_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(7 + digest.len() * 2);
    encoded.push_str("sha256:");
    for byte in digest {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn diagnostic_from_error(error: &HookImportError) -> HookImportDiagnostic {
    let source = match error {
        HookImportError::InvalidPath { path, .. }
        | HookImportError::Read { path, .. }
        | HookImportError::Parse { path, .. }
        | HookImportError::Unsupported { path, .. }
        | HookImportError::WriteApproval { path, .. } => Some(path.clone()),
        HookImportError::ApprovalStoreUnavailable(_)
        | HookImportError::ProposalNotFound(_)
        | HookImportError::ApprovalNotFound(_) => None,
    };
    HookImportDiagnostic {
        source,
        message: error.to_string(),
    }
}

fn log_report(report: &HookImportReport) {
    for diagnostic in &report.diagnostics {
        warn!(
            source = ?diagnostic.source,
            message = %diagnostic.message,
            "repository hook import rejected"
        );
    }
    for proposal in &report.proposals {
        match proposal.state {
            HookImportState::Approved => info!(
                source = %proposal.source.display(),
                source_digest = %proposal.source_digest,
                proposal_digest = %proposal.proposal_digest,
                events = ?proposal.requested_events,
                effects = ?proposal.requested_effects,
                "activated explicitly approved repository hook import"
            ),
            HookImportState::Pending | HookImportState::Changed => warn!(
                state = ?proposal.state,
                source = %proposal.source.display(),
                source_digest = %proposal.source_digest,
                proposal_digest = %proposal.proposal_digest,
                events = ?proposal.requested_events,
                effects = ?proposal.requested_effects,
                "repository hooks remain inert; review with `openclaudia hooks status` and approve the exact proposal digest"
            ),
        }
    }
}
