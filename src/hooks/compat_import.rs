//! Explicit, host-approved imports for repository-owned hook configuration.
//!
//! Recognized repository files are parsed into inert proposals. They become
//! runtime hooks only when an exact proposal receipt exists in the host data
//! directory. The proposal digest binds the canonical workspace and source
//! paths, filesystem owners, source bytes, requested events/capabilities,
//! output authority, and exact executable argv/identity, so changing any of
//! those properties requires a new approval.

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

const IMPORT_SCHEMA_VERSION: u32 = 2;
const MAX_IMPORT_BYTES: u64 = 256 * 1024;
const MAX_APPROVAL_STORE_BYTES: u64 = 1024 * 1024;
const MAX_STORED_APPROVALS: usize = 1024;
const MAX_IMPORTED_HOOKS: usize = 128;
const MAX_IMPORTED_COMMAND_BYTES: usize = 4096;
const MAX_IMPORTED_TIMEOUT_SECONDS: u64 = 300;
const MAX_BOUND_FILES: usize = 128;
const MAX_BOUND_FILE_BYTES: u64 = 1024 * 1024;
const MAX_BOUND_FILES_TOTAL_BYTES: u64 = 4 * 1024 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_EXECUTABLES_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const APPROVAL_STORE_OVERRIDE_ENV: &str = "OPENCLAUDIA_HOOK_APPROVALS_PATH";

/// Repository authority scope represented by a compatibility source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookImportSourceScope {
    /// User-global foreign compatibility configuration.
    User,
    /// Shared project configuration.
    Project,
    /// Machine-local project configuration.
    ProjectLocal,
}

impl std::fmt::Display for HookImportSourceScope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::User => "user",
            Self::Project => "project",
            Self::ProjectLocal => "project_local",
        })
    }
}

/// Stable filesystem owner identity included in proposal and approval digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HookImportOwner {
    /// Unix numeric file owner.
    Unix { uid: u32 },
    /// Windows security identifier string.
    Windows { sid: String },
}

impl std::fmt::Display for HookImportOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unix { uid } => write!(formatter, "unix uid {uid}"),
            Self::Windows { sid } => write!(formatter, "windows SID {sid}"),
        }
    }
}

/// Host capabilities requested by an imported hook set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookImportCapability {
    /// Spawn an exact direct-process argv.
    Process,
    /// Read repository content through the full hook sandbox.
    WorkspaceRead,
    /// Publish sandboxed workspace changes.
    WorkspaceWriteSandboxed,
}

impl std::fmt::Display for HookImportCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Process => "process",
            Self::WorkspaceRead => "workspace_read",
            Self::WorkspaceWriteSandboxed => "workspace_write_sandboxed",
        })
    }
}

/// Model- or control-visible fields a hook may emit for one lifecycle event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookImportOutputField {
    /// A typed allow/ask/deny decision for a blocking lifecycle event.
    Decision,
    /// A reference-only prompt suggestion.
    PromptSuggestion,
    /// Reference-only context, including legacy `systemMessage` output.
    ReferenceContext,
}

impl std::fmt::Display for HookImportOutputField {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Decision => "decision",
            Self::PromptSuggestion => "prompt_suggestion",
            Self::ReferenceContext => "reference_context",
        })
    }
}

/// Exact output authority requested for one lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookImportOutputAuthority {
    pub event: String,
    pub fields: Vec<HookImportOutputField>,
}

/// Direct-spawn identity and argv bound by one host approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookImportExecutable {
    pub command: String,
    pub executable_token: String,
    pub resolved_path: PathBuf,
    pub digest: String,
    pub owner: HookImportOwner,
    pub bytes: u64,
    pub argv: Vec<String>,
}

/// Repository hook format recognized by the compatibility importer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookImportKind {
    /// Claude-compatible user-global `~/.claude/settings.json`.
    ClaudeUser,
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
            Self::ClaudeUser => "claude_user",
            Self::OpenClaudiaProject => "openclaudia_project",
            Self::ClaudeProject => "claude_project",
            Self::ClaudeProjectLocal => "claude_project_local",
        };
        formatter.write_str(name)
    }
}

impl HookImportKind {
    const fn scope(self) -> HookImportSourceScope {
        match self {
            Self::ClaudeUser => HookImportSourceScope::User,
            Self::OpenClaudiaProject | Self::ClaudeProject => HookImportSourceScope::Project,
            Self::ClaudeProjectLocal => HookImportSourceScope::ProjectLocal,
        }
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
    /// An exact receipt exists, but another source or the host store failed
    /// validation, so the entire repository import set remains inert.
    Rejected,
    /// The current proposal exactly matches a host-owned receipt.
    Approved,
}

/// User-visible, inert description of a repository hook import request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HookImportProposal {
    pub schema_version: u32,
    pub kind: HookImportKind,
    pub source_scope: HookImportSourceScope,
    pub workspace: PathBuf,
    pub workspace_owner: HookImportOwner,
    pub source_root: PathBuf,
    pub source_root_owner: HookImportOwner,
    pub source: PathBuf,
    pub source_owner: HookImportOwner,
    pub source_digest: String,
    pub proposal_digest: String,
    pub requested_events: Vec<String>,
    pub requested_effects: Vec<String>,
    pub requested_capabilities: Vec<HookImportCapability>,
    pub output_authority: Vec<HookImportOutputAuthority>,
    pub commands: Vec<String>,
    pub executables: Vec<HookImportExecutable>,
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
    pub owner: HookImportOwner,
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
    #[error(
        "host hook approval store uses schema version {found}; expected {expected}; explicit reapproval is required"
    )]
    ApprovalSchema { found: u32, expected: u32 },
    #[error(
        "repository hook discovery rejected {failures} source(s); resolve status diagnostics before approving any import"
    )]
    DiscoveryRejected { failures: usize },
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
    source_scope: HookImportSourceScope,
    workspace: PathBuf,
    workspace_owner: HookImportOwner,
    source_root: PathBuf,
    source_root_owner: HookImportOwner,
    source: PathBuf,
    source_owner: HookImportOwner,
    source_digest: String,
    proposal_digest: String,
    requested_events: Vec<String>,
    requested_effects: Vec<String>,
    requested_capabilities: Vec<HookImportCapability>,
    output_authority: Vec<HookImportOutputAuthority>,
    commands: Vec<String>,
    executables: Vec<HookImportExecutable>,
    bound_files: Vec<HookImportBoundFile>,
    hook_count: usize,
}

impl From<&HookImportProposal> for HookImportApproval {
    fn from(proposal: &HookImportProposal) -> Self {
        Self {
            schema_version: proposal.schema_version,
            kind: proposal.kind,
            source_scope: proposal.source_scope,
            workspace: proposal.workspace.clone(),
            workspace_owner: proposal.workspace_owner.clone(),
            source_root: proposal.source_root.clone(),
            source_root_owner: proposal.source_root_owner.clone(),
            source: proposal.source.clone(),
            source_owner: proposal.source_owner.clone(),
            source_digest: proposal.source_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            requested_events: proposal.requested_events.clone(),
            requested_effects: proposal.requested_effects.clone(),
            requested_capabilities: proposal.requested_capabilities.clone(),
            output_authority: proposal.output_authority.clone(),
            commands: proposal.commands.clone(),
            executables: proposal.executables.clone(),
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
    source_scope: HookImportSourceScope,
    workspace: &'a Path,
    workspace_owner: &'a HookImportOwner,
    source_root: &'a Path,
    source_root_owner: &'a HookImportOwner,
    source: &'a Path,
    source_owner: &'a HookImportOwner,
    source_digest: &'a str,
    requested_events: &'a [String],
    requested_effects: &'a [String],
    requested_capabilities: &'a [HookImportCapability],
    output_authority: &'a [HookImportOutputAuthority],
    commands: &'a [String],
    executables: &'a [HookImportExecutable],
    bound_files: &'a [HookImportBoundFile],
    hook_count: usize,
}

#[derive(Deserialize)]
struct RepositoryClaudeSettings {
    // Claude settings contain many unrelated product preferences. They are
    // deliberately ignored here: only the typed `hooks` subtree is proposed
    // for authority, and every field inside that subtree remains strict.
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
            let (candidates, mut diagnostics) = discover_candidates(&workspace, true);
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
    resolve_hook_imports_at(&workspace, &approval_path, true).1
}

/// Inspect repository proposals using explicit paths. This is also the
/// deterministic test seam for trust-boundary tests.
#[must_use]
pub fn inspect_repository_hook_imports_at(
    workspace: &Path,
    approval_path: &Path,
) -> HookImportReport {
    resolve_hook_imports_at(workspace, approval_path, false).1
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
    resolve_hook_imports_at(workspace, approval_path, false)
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
    approve_hook_import_at(&workspace, &approval_path, proposal_digest, true)
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
    approve_hook_import_at(workspace, approval_path, proposal_digest, false)
}

fn approve_hook_import_at(
    workspace: &Path,
    approval_path: &Path,
    proposal_digest: &str,
    include_user_source: bool,
) -> Result<HookImportProposal, HookImportError> {
    let workspace = canonical_workspace(workspace)?;
    validate_approval_store_location(&workspace, approval_path)?;
    let (candidates, diagnostics) = discover_candidates(&workspace, include_user_source);
    if !diagnostics.is_empty() {
        return Err(HookImportError::DiscoveryRejected {
            failures: diagnostics.len(),
        });
    }
    let mut matching = candidates
        .into_iter()
        .filter(|candidate| candidate.proposal.proposal_digest == proposal_digest);
    let candidate = matching
        .next()
        .ok_or_else(|| HookImportError::ProposalNotFound(proposal_digest.to_string()))?;
    if matching.next().is_some() {
        return Err(HookImportError::DiscoveryRejected { failures: 1 });
    }
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
    let (hooks, report) = resolve_hook_imports_at(&workspace, &approval_path, true);
    log_report(&report);
    hooks
}

fn resolve_hook_imports_at(
    workspace: &Path,
    approval_path: &Path,
    include_user_source: bool,
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
    let (mut candidates, mut diagnostics) = discover_candidates(&workspace, include_user_source);
    let approval_location_valid = match validate_approval_store_location(&workspace, approval_path)
    {
        Ok(()) => true,
        Err(error) => {
            diagnostics.push(diagnostic_from_error(&error));
            false
        }
    };
    let (store, store_valid) = match load_approval_store(approval_path) {
        Ok(store) => (store, true),
        Err(HookImportError::Read { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            (HookImportApprovalStore::default(), true)
        }
        Err(error) => {
            diagnostics.push(diagnostic_from_error(&error));
            (HookImportApprovalStore::default(), false)
        }
    };
    let activation_allowed = diagnostics.is_empty() && approval_location_valid && store_valid;

    let mut active = HooksConfig::default();
    let mut proposals = Vec::with_capacity(candidates.len());
    for candidate in &mut candidates {
        let expected_approval = HookImportApproval::from(&candidate.proposal);
        let exact = store
            .approvals
            .iter()
            .any(|approval| approval == &expected_approval);
        let prior = store.approvals.iter().any(|approval| {
            approval.workspace == candidate.proposal.workspace
                && approval.source == candidate.proposal.source
        });
        candidate.proposal.state = if exact && activation_allowed {
            HookImportState::Approved
        } else if exact {
            HookImportState::Rejected
        } else if prior {
            HookImportState::Changed
        } else {
            HookImportState::Pending
        };
        if exact && activation_allowed {
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

fn discover_candidates(
    workspace: &Path,
    include_user_source: bool,
) -> (Vec<ImportCandidate>, Vec<HookImportDiagnostic>) {
    let mut diagnostics = Vec::new();
    let mut sources = vec![
        (
            HookImportKind::OpenClaudiaProject,
            workspace.to_path_buf(),
            workspace.join(".openclaudia/config.yaml"),
        ),
        (
            HookImportKind::ClaudeProject,
            workspace.to_path_buf(),
            workspace.join(".claude/settings.json"),
        ),
        (
            HookImportKind::ClaudeProjectLocal,
            workspace.to_path_buf(),
            workspace.join(".claude/settings.local.json"),
        ),
    ];
    if include_user_source {
        if let Some(home) = dirs::home_dir() {
            match home.canonicalize() {
                Ok(home) => sources.insert(
                    0,
                    (
                        HookImportKind::ClaudeUser,
                        home.clone(),
                        home.join(".claude/settings.json"),
                    ),
                ),
                Err(source) => {
                    diagnostics.push(diagnostic_from_error(&HookImportError::Read {
                        path: home,
                        source,
                    }));
                }
            }
        }
    }
    let mut candidates = Vec::new();
    for (kind, source_root, path) in sources {
        match discover_candidate(workspace, &source_root, &path, kind) {
            Ok(Some(candidate)) => candidates.push(candidate),
            Ok(None) => {}
            Err(error) => diagnostics.push(diagnostic_from_error(&error)),
        }
    }
    (candidates, diagnostics)
}

// Keeping discovery in one linear validation sequence makes the fail-closed
// ordering auditable; splitting it would obscure which checks precede parsing.
#[allow(clippy::too_many_lines)]
fn discover_candidate(
    workspace: &Path,
    source_root: &Path,
    path: &Path,
    kind: HookImportKind,
) -> Result<Option<ImportCandidate>, HookImportError> {
    let Some(bytes) = read_bounded_file(path, MAX_IMPORT_BYTES)? else {
        return Ok(None);
    };
    reject_symlinked_scoped_path(source_root, path)?;
    let source = path
        .canonicalize()
        .map_err(|source| HookImportError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if !source.starts_with(source_root) {
        return Err(HookImportError::InvalidPath {
            path: path.to_path_buf(),
            reason: format!(
                "canonical source `{}` escapes canonical source root `{}`",
                source.display(),
                source_root.display()
            ),
        });
    }

    let workspace_owner = owner_identity(workspace)?;
    let source_root_owner = owner_identity(source_root)?;
    let source_owner = owner_identity(&source)?;
    if source_owner != source_root_owner {
        return Err(HookImportError::InvalidPath {
            path: source,
            reason: format!(
                "source owner {source_owner} differs from source-root owner {source_root_owner}"
            ),
        });
    }

    let mut hooks = match kind {
        HookImportKind::OpenClaudiaProject => parse_native_project_hooks(&source, &bytes)?,
        HookImportKind::ClaudeUser
        | HookImportKind::ClaudeProject
        | HookImportKind::ClaudeProjectLocal => parse_repository_claude_hooks(&source, &bytes)?,
    };
    if hooks.policy.is_some() {
        return Err(HookImportError::Unsupported {
            path: source,
            reason: "compatibility imports cannot define or weaken host hook policy".to_string(),
        });
    }
    if hooks.is_empty() {
        return Ok(None);
    }
    let metadata = validate_and_describe_hooks(&source, workspace, &hooks)?;
    pin_executable_commands(&source, &mut hooks, &metadata.executables)?;
    let bound_files = discover_bound_files(
        workspace,
        &workspace_owner,
        source_root,
        &source_root_owner,
        kind,
        &metadata.commands,
    )?;
    let source_digest = digest_bytes(&bytes);
    let fingerprint = ProposalFingerprint {
        schema_version: IMPORT_SCHEMA_VERSION,
        kind,
        source_scope: kind.scope(),
        workspace,
        workspace_owner: &workspace_owner,
        source_root,
        source_root_owner: &source_root_owner,
        source: &source,
        source_owner: &source_owner,
        source_digest: &source_digest,
        requested_events: &metadata.events,
        requested_effects: &metadata.effects,
        requested_capabilities: &metadata.capabilities,
        output_authority: &metadata.output_authority,
        commands: &metadata.commands,
        executables: &metadata.executables,
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
        source_scope: kind.scope(),
        workspace: workspace.to_path_buf(),
        workspace_owner,
        source_root: source_root.to_path_buf(),
        source_root_owner,
        source,
        source_owner,
        source_digest,
        proposal_digest: digest_bytes(&fingerprint_bytes),
        requested_events: metadata.events,
        requested_effects: metadata.effects,
        requested_capabilities: metadata.capabilities,
        output_authority: metadata.output_authority,
        commands: metadata.commands,
        executables: metadata.executables,
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

fn validate_approval_store_location(
    workspace: &Path,
    approval_path: &Path,
) -> Result<(), HookImportError> {
    if !approval_path.is_absolute() {
        return Err(HookImportError::ApprovalStoreUnavailable(format!(
            "approval path `{}` must be absolute",
            approval_path.display()
        )));
    }
    if approval_path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return Err(HookImportError::ApprovalStoreUnavailable(format!(
            "approval path `{}` must not contain relative traversal components",
            approval_path.display()
        )));
    }
    let canonical_target = canonicalize_with_missing_leaf(approval_path)?;
    if canonical_target == workspace || canonical_target.starts_with(workspace) {
        return Err(HookImportError::InvalidPath {
            path: approval_path.to_path_buf(),
            reason: "host hook approvals must be stored outside the repository workspace"
                .to_string(),
        });
    }
    Ok(())
}

fn canonicalize_with_missing_leaf(path: &Path) -> Result<PathBuf, HookImportError> {
    let mut cursor = path;
    let mut missing = Vec::new();
    loop {
        match fs::symlink_metadata(cursor) {
            Ok(_) => {
                let mut canonical =
                    cursor
                        .canonicalize()
                        .map_err(|source| HookImportError::Read {
                            path: cursor.to_path_buf(),
                            source,
                        })?;
                for component in missing.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = cursor.file_name().ok_or_else(|| {
                    HookImportError::ApprovalStoreUnavailable(format!(
                        "cannot resolve approval path `{}`",
                        path.display()
                    ))
                })?;
                missing.push(name.to_os_string());
                cursor = cursor.parent().ok_or_else(|| {
                    HookImportError::ApprovalStoreUnavailable(format!(
                        "cannot resolve approval path `{}`",
                        path.display()
                    ))
                })?;
            }
            Err(source) => {
                return Err(HookImportError::Read {
                    path: cursor.to_path_buf(),
                    source,
                });
            }
        }
    }
}

#[cfg(unix)]
fn owner_identity(path: &Path) -> Result<HookImportOwner, HookImportError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = fs::metadata(path).map_err(|source| HookImportError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(HookImportOwner::Unix {
        uid: metadata.uid(),
    })
}

#[cfg(windows)]
fn owner_identity(path: &Path) -> Result<HookImportOwner, HookImportError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::{LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};

    let file = if path.is_dir() {
        crate::windows_fs::open_absolute_directory(path)
    } else {
        File::open(path)
    }
    .map_err(|source| HookImportError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the file handle remains live, output pointers are valid, and the
    // returned descriptor is released with LocalFree below.
    let error = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if error != 0 || descriptor.is_null() || owner.is_null() {
        if !descriptor.is_null() {
            // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
            unsafe { LocalFree(descriptor.cast()) };
        }
        let source = if error == 0 {
            std::io::Error::other("owner security descriptor is incomplete")
        } else {
            std::io::Error::from_raw_os_error(error.cast_signed())
        };
        return Err(HookImportError::Read {
            path: path.to_path_buf(),
            source,
        });
    }
    let mut sid_string = std::ptr::null_mut();
    // SAFETY: GetSecurityInfo returned a valid owner SID and output receives a
    // LocalAlloc-owned NUL-terminated UTF-16 string.
    if unsafe { ConvertSidToStringSidW(owner, &raw mut sid_string) } == 0 || sid_string.is_null() {
        // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
        unsafe { LocalFree(descriptor.cast()) };
        return Err(HookImportError::Read {
            path: path.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: the conversion returned a valid NUL-terminated UTF-16 string.
    let sid_units = unsafe {
        let mut length = 0usize;
        while *sid_string.add(length) != 0 {
            length += 1;
        }
        std::slice::from_raw_parts(sid_string, length).to_vec()
    };
    // SAFETY: both values were allocated by Windows security APIs with LocalAlloc.
    unsafe {
        LocalFree(sid_string.cast());
        LocalFree(descriptor.cast());
    }
    let sid = String::from_utf16(&sid_units).map_err(|_| HookImportError::InvalidPath {
        path: path.to_path_buf(),
        reason: "filesystem owner SID is not valid UTF-16".to_string(),
    })?;
    Ok(HookImportOwner::Windows { sid })
}

#[cfg(not(any(unix, windows)))]
fn owner_identity(path: &Path) -> Result<HookImportOwner, HookImportError> {
    Err(HookImportError::Unsupported {
        path: path.to_path_buf(),
        reason: "filesystem owner identity is unavailable on this platform".to_string(),
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

fn reject_symlinked_scoped_path(scope_root: &Path, path: &Path) -> Result<(), HookImportError> {
    let relative = path
        .strip_prefix(scope_root)
        .map_err(|_| HookImportError::InvalidPath {
            path: path.to_path_buf(),
            reason: "hook import path is not lexically contained by its source root".to_string(),
        })?;
    let mut current = scope_root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(HookImportError::InvalidPath {
                path: path.to_path_buf(),
                reason: "repository import paths cannot contain traversal components".to_string(),
            });
        };
        current.push(name);
        let metadata = fs::symlink_metadata(&current).map_err(|source| HookImportError::Read {
            path: current.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(HookImportError::InvalidPath {
                path: current,
                reason: "repository import paths cannot traverse symlinks".to_string(),
            });
        }
    }
    Ok(())
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
            reason: format!("invalid Claude hooks configuration: {error}"),
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
    workspace_owner: &HookImportOwner,
    source_root: &Path,
    source_root_owner: &HookImportOwner,
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
            let (binding_root, binding_owner) = if candidate.is_absolute()
                && !candidate.starts_with(workspace)
                && matches!(kind, HookImportKind::ClaudeUser)
            {
                (source_root, source_root_owner)
            } else {
                (workspace, workspace_owner)
            };
            add_bound_path(
                binding_root,
                binding_owner,
                &candidate,
                &mut files,
                &mut total_bytes,
            )?;
        }
    }

    if matches!(
        kind,
        HookImportKind::ClaudeProject | HookImportKind::ClaudeProjectLocal
    ) {
        let package = workspace.join(".claude/hooks");
        if package.exists() {
            add_bound_path(
                workspace,
                workspace_owner,
                &package,
                &mut files,
                &mut total_bytes,
            )?;
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

// Binding a path is one atomic validation sequence over identity, ownership,
// size, and digest; keep those checks adjacent for security review.
#[allow(clippy::too_many_lines)]
fn add_bound_path(
    workspace: &Path,
    workspace_owner: &HookImportOwner,
    path: &Path,
    files: &mut BTreeMap<PathBuf, HookImportBoundFile>,
    total_bytes: &mut u64,
) -> Result<(), HookImportError> {
    reject_symlinked_scoped_path(workspace, path)?;
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
            add_bound_path(
                workspace,
                workspace_owner,
                &child.path(),
                files,
                total_bytes,
            )?;
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
    let owner = owner_identity(&canonical)?;
    if &owner != workspace_owner {
        return Err(HookImportError::InvalidPath {
            path: canonical,
            reason: format!(
                "bound command owner {owner} differs from canonical workspace owner {workspace_owner}"
            ),
        });
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
            owner,
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
    capabilities: Vec<HookImportCapability>,
    output_authority: Vec<HookImportOutputAuthority>,
    commands: Vec<String>,
    executables: Vec<HookImportExecutable>,
    hook_count: usize,
}

#[derive(Default)]
struct HookMetadataBuilder {
    events: BTreeSet<String>,
    effects: BTreeSet<String>,
    capabilities: BTreeSet<HookImportCapability>,
    output_authority: BTreeMap<String, BTreeSet<HookImportOutputField>>,
    commands: BTreeSet<String>,
    hook_count: usize,
}

fn validate_and_describe_hooks(
    path: &Path,
    workspace: &Path,
    config: &HooksConfig,
) -> Result<HookMetadata, HookImportError> {
    let mut builder = HookMetadataBuilder::default();
    for (event, entries) in hook_slots(config) {
        if entries.is_empty() {
            continue;
        }
        let event_name = event.config_key().to_string();
        builder.events.insert(event_name.clone());
        for entry in entries {
            validate_hook_entry(path, &event_name, entry)?;
            for hook in &entry.hooks {
                builder.record_hook(path, event, &event_name, hook)?;
            }
        }
    }
    builder.finish(path, workspace)
}

fn validate_hook_entry(
    path: &Path,
    event_name: &str,
    entry: &crate::config::HookEntry,
) -> Result<(), HookImportError> {
    if entry.hooks.is_empty() {
        return Err(HookImportError::Parse {
            path: path.to_path_buf(),
            reason: format!("hook entry for `{event_name}` contains no hook actions"),
        });
    }
    if let Some(matcher) = entry.matcher.as_deref() {
        super::validate_hook_matcher(matcher, "").map_err(|error| HookImportError::Parse {
            path: path.to_path_buf(),
            reason: format!("invalid matcher for `{event_name}`: {error}"),
        })?;
    }
    Ok(())
}

impl HookMetadataBuilder {
    fn record_hook(
        &mut self,
        path: &Path,
        event: HookEvent,
        event_name: &str,
        hook: &Hook,
    ) -> Result<(), HookImportError> {
        self.hook_count = self.hook_count.saturating_add(1);
        if self.hook_count > MAX_IMPORTED_HOOKS {
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
                validate_command_hook(path, command, *shell, *timeout)?;
                self.record_command_authority(event, event_name, command);
                Ok(())
            }
            Hook::Prompt { prompt, timeout } => {
                validate_prompt_hook(path, event_name, prompt, *timeout)?;
                self.effects.insert("emit_reference_context".to_string());
                self.output_authority
                    .entry(event_name.to_string())
                    .or_default()
                    .insert(HookImportOutputField::ReferenceContext);
                Ok(())
            }
            Hook::Model { .. } => Err(HookImportError::Unsupported {
                path: path.to_path_buf(),
                reason: "repository model hooks are unavailable until the canonical provider path is wired"
                    .to_string(),
            }),
        }
    }

    fn record_command_authority(&mut self, event: HookEvent, event_name: &str, command: &str) {
        self.commands.insert(command.to_string());
        self.capabilities.insert(HookImportCapability::Process);
        self.capabilities
            .insert(HookImportCapability::WorkspaceRead);
        self.capabilities
            .insert(HookImportCapability::WorkspaceWriteSandboxed);
        self.effects.insert("execute_process".to_string());
        self.effects.insert("read_workspace".to_string());
        self.effects.insert("write_workspace_sandboxed".to_string());
        self.effects.insert("emit_reference_context".to_string());
        let fields = self
            .output_authority
            .entry(event_name.to_string())
            .or_default();
        fields.insert(HookImportOutputField::ReferenceContext);
        let contract = event.contract();
        if contract.accepts_decision {
            fields.insert(HookImportOutputField::Decision);
            self.effects.insert("emit_decision".to_string());
            if matches!(contract.failure_mode, super::HookFailureMode::Block) {
                self.effects.insert("block_action".to_string());
            }
        }
        if contract.accepts_prompt_suggestion {
            fields.insert(HookImportOutputField::PromptSuggestion);
            self.effects.insert("emit_prompt_suggestion".to_string());
        }
    }

    fn finish(self, path: &Path, workspace: &Path) -> Result<HookMetadata, HookImportError> {
        let commands = self.commands.into_iter().collect::<Vec<_>>();
        let executables = describe_executables(path, workspace, &commands)?;
        Ok(HookMetadata {
            events: self.events.into_iter().collect(),
            effects: self.effects.into_iter().collect(),
            capabilities: self.capabilities.into_iter().collect(),
            output_authority: self
                .output_authority
                .into_iter()
                .map(|(event, fields)| HookImportOutputAuthority {
                    event,
                    fields: fields.into_iter().collect(),
                })
                .collect(),
            commands,
            executables,
            hook_count: self.hook_count,
        })
    }
}

fn validate_command_hook(
    path: &Path,
    command: &str,
    shell: bool,
    timeout: u64,
) -> Result<(), HookImportError> {
    if shell {
        return Err(HookImportError::Unsupported {
            path: path.to_path_buf(),
            reason: "repository imports cannot request shell:true".to_string(),
        });
    }
    if command.is_empty() || command.len() > MAX_IMPORTED_COMMAND_BYTES {
        return Err(HookImportError::Unsupported {
            path: path.to_path_buf(),
            reason: format!("command length must be 1..={MAX_IMPORTED_COMMAND_BYTES} bytes"),
        });
    }
    validate_import_timeout(path, "command", timeout)?;
    let tokens = shlex::split(command).ok_or_else(|| HookImportError::Unsupported {
        path: path.to_path_buf(),
        reason: format!("command is not valid direct-spawn syntax: {command}"),
    })?;
    if tokens.is_empty() {
        return Err(HookImportError::Unsupported {
            path: path.to_path_buf(),
            reason: "command has no executable".to_string(),
        });
    }
    if tokens[0].contains('=') {
        return Err(HookImportError::Unsupported {
            path: path.to_path_buf(),
            reason: "repository commands cannot use an environment assignment as argv[0]"
                .to_string(),
        });
    }
    if tokens.iter().any(|token| token.contains('\0')) {
        return Err(HookImportError::Unsupported {
            path: path.to_path_buf(),
            reason: "repository command argv cannot contain NUL bytes".to_string(),
        });
    }
    Ok(())
}

fn validate_prompt_hook(
    path: &Path,
    event_name: &str,
    prompt: &str,
    timeout: u64,
) -> Result<(), HookImportError> {
    if prompt.trim().is_empty() {
        return Err(HookImportError::Parse {
            path: path.to_path_buf(),
            reason: format!("prompt hook for `{event_name}` must not be empty"),
        });
    }
    validate_import_timeout(path, "prompt", timeout)
}

fn validate_import_timeout(
    path: &Path,
    hook_kind: &str,
    timeout: u64,
) -> Result<(), HookImportError> {
    if timeout == 0 || timeout > MAX_IMPORTED_TIMEOUT_SECONDS {
        return Err(HookImportError::Unsupported {
            path: path.to_path_buf(),
            reason: format!(
                "{hook_kind} timeout must be 1..={MAX_IMPORTED_TIMEOUT_SECONDS} seconds"
            ),
        });
    }
    Ok(())
}

#[derive(Clone)]
struct ExecutableFileIdentity {
    digest: String,
    owner: HookImportOwner,
    bytes: u64,
}

fn describe_executables(
    source: &Path,
    workspace: &Path,
    commands: &[String],
) -> Result<Vec<HookImportExecutable>, HookImportError> {
    let mut files = BTreeMap::<PathBuf, ExecutableFileIdentity>::new();
    let mut total_bytes = 0u64;
    let mut executables = Vec::with_capacity(commands.len());
    for command in commands {
        let argv = shlex::split(command).ok_or_else(|| HookImportError::Unsupported {
            path: source.to_path_buf(),
            reason: format!("command is not valid direct-spawn syntax: {command}"),
        })?;
        let executable_token =
            argv.first()
                .cloned()
                .ok_or_else(|| HookImportError::Unsupported {
                    path: source.to_path_buf(),
                    reason: "command has no executable".to_string(),
                })?;
        let resolved = which::which_in(&executable_token, std::env::var_os("PATH"), workspace)
            .map_err(|error| HookImportError::Unsupported {
                path: source.to_path_buf(),
                reason: format!(
                    "cannot resolve executable `{executable_token}` for explicit approval: {error}"
                ),
            })?
            .canonicalize()
            .map_err(|error| HookImportError::Read {
                path: PathBuf::from(&executable_token),
                source: error,
            })?;
        let identity = if let Some(identity) = files.get(&resolved) {
            identity.clone()
        } else {
            if files.len() >= MAX_IMPORTED_HOOKS {
                return Err(HookImportError::Unsupported {
                    path: source.to_path_buf(),
                    reason: format!(
                        "more than {MAX_IMPORTED_HOOKS} executable identities requested"
                    ),
                });
            }
            let metadata =
                fs::symlink_metadata(&resolved).map_err(|error| HookImportError::Read {
                    path: resolved.clone(),
                    source: error,
                })?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(HookImportError::InvalidPath {
                    path: resolved,
                    reason: "resolved executable must be a regular, canonical file".to_string(),
                });
            }
            if metadata.len() > MAX_EXECUTABLE_BYTES {
                return Err(HookImportError::Unsupported {
                    path: resolved,
                    reason: format!(
                        "executable is {} bytes; per-file limit is {MAX_EXECUTABLE_BYTES} bytes",
                        metadata.len()
                    ),
                });
            }
            total_bytes = total_bytes.saturating_add(metadata.len());
            if total_bytes > MAX_EXECUTABLES_TOTAL_BYTES {
                return Err(HookImportError::Unsupported {
                    path: resolved,
                    reason: format!(
                        "resolved executables exceed {MAX_EXECUTABLES_TOTAL_BYTES} total bytes"
                    ),
                });
            }
            let identity = ExecutableFileIdentity {
                digest: digest_file_bounded(&resolved, MAX_EXECUTABLE_BYTES)?,
                owner: owner_identity(&resolved)?,
                bytes: metadata.len(),
            };
            files.insert(resolved.clone(), identity.clone());
            identity
        };
        executables.push(HookImportExecutable {
            command: command.clone(),
            executable_token,
            resolved_path: resolved,
            digest: identity.digest,
            owner: identity.owner,
            bytes: identity.bytes,
            argv,
        });
    }
    Ok(executables)
}

fn pin_executable_commands(
    source: &Path,
    config: &mut HooksConfig,
    executables: &[HookImportExecutable],
) -> Result<(), HookImportError> {
    let identities = executables
        .iter()
        .map(|executable| (executable.command.as_str(), executable))
        .collect::<BTreeMap<_, _>>();
    for entries in [
        &mut config.session_start,
        &mut config.session_end,
        &mut config.pre_tool_use,
        &mut config.post_tool_use,
        &mut config.post_tool_use_failure,
        &mut config.user_prompt_submit,
        &mut config.stop,
        &mut config.subagent_start,
        &mut config.subagent_stop,
        &mut config.pre_compact,
        &mut config.permission_request,
        &mut config.notification,
        &mut config.pre_adversary_review,
        &mut config.post_adversary_review,
        &mut config.vdd_conflict,
        &mut config.vdd_converged,
    ] {
        for entry in entries {
            for hook in &mut entry.hooks {
                let Hook::Command { command, .. } = hook else {
                    continue;
                };
                let executable = identities.get(command.as_str()).ok_or_else(|| {
                    HookImportError::Unsupported {
                        path: source.to_path_buf(),
                        reason: format!("command lost its executable identity: {command}"),
                    }
                })?;
                let resolved = executable.resolved_path.to_str().ok_or_else(|| {
                    HookImportError::Unsupported {
                        path: executable.resolved_path.clone(),
                        reason: "resolved executable path is not valid Unicode".to_string(),
                    }
                })?;
                let mut argv = executable.argv.clone();
                argv[0] = resolved.to_string();
                let pinned = shlex::try_join(argv.iter().map(String::as_str)).map_err(|error| {
                    HookImportError::Unsupported {
                        path: source.to_path_buf(),
                        reason: format!("cannot encode exact executable argv: {error}"),
                    }
                })?;
                if pinned.len() > MAX_IMPORTED_COMMAND_BYTES {
                    return Err(HookImportError::Unsupported {
                        path: source.to_path_buf(),
                        reason: format!(
                            "resolved command length exceeds {MAX_IMPORTED_COMMAND_BYTES} bytes"
                        ),
                    });
                }
                *command = pinned;
            }
        }
    }
    Ok(())
}

fn hook_slots(config: &HooksConfig) -> [(HookEvent, &[crate::config::HookEntry]); 16] {
    [
        (HookEvent::SessionStart, &config.session_start),
        (HookEvent::SessionEnd, &config.session_end),
        (HookEvent::PreToolUse, &config.pre_tool_use),
        (HookEvent::PostToolUse, &config.post_tool_use),
        (HookEvent::PostToolUseFailure, &config.post_tool_use_failure),
        (HookEvent::UserPromptSubmit, &config.user_prompt_submit),
        (HookEvent::Stop, &config.stop),
        (HookEvent::SubagentStart, &config.subagent_start),
        (HookEvent::SubagentStop, &config.subagent_stop),
        (HookEvent::PreCompact, &config.pre_compact),
        (HookEvent::PermissionRequest, &config.permission_request),
        (HookEvent::Notification, &config.notification),
        (HookEvent::PreAdversaryReview, &config.pre_adversary_review),
        (
            HookEvent::PostAdversaryReview,
            &config.post_adversary_review,
        ),
        (HookEvent::VddConflict, &config.vdd_conflict),
        (HookEvent::VddConverged, &config.vdd_converged),
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
    validate_approval_store_file(path)?;
    let document: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| HookImportError::Parse {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    let found_version = document
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|version| u32::try_from(version).ok())
        .ok_or_else(|| HookImportError::Parse {
            path: path.to_path_buf(),
            reason: "approval store schema_version must be a u32".to_string(),
        })?;
    if found_version != IMPORT_SCHEMA_VERSION {
        return Err(HookImportError::ApprovalSchema {
            found: found_version,
            expected: IMPORT_SCHEMA_VERSION,
        });
    }
    let store: HookImportApprovalStore =
        serde_json::from_value(document).map_err(|error| HookImportError::Parse {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    validate_approval_store(path, &store)?;
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
        Err(HookImportError::ApprovalSchema { found, expected }) if found < expected => {
            Ok(HookImportApprovalStore::default())
        }
        Err(error) => Err(error),
    }
}

fn validate_approval_store(
    path: &Path,
    store: &HookImportApprovalStore,
) -> Result<(), HookImportError> {
    if store.approvals.len() > MAX_STORED_APPROVALS {
        return Err(approval_parse_error(
            path,
            format!("approval store contains more than {MAX_STORED_APPROVALS} receipts"),
        ));
    }
    let mut sources = HashSet::new();
    let mut digests = HashSet::new();
    for approval in &store.approvals {
        validate_approval(path, approval)?;
        if !sources.insert((approval.workspace.clone(), approval.source.clone())) {
            return Err(approval_parse_error(
                path,
                format!(
                    "ambiguous duplicate approval for workspace `{}` source `{}`",
                    approval.workspace.display(),
                    approval.source.display()
                ),
            ));
        }
        if !digests.insert(approval.proposal_digest.clone()) {
            return Err(approval_parse_error(
                path,
                format!(
                    "ambiguous duplicate proposal digest `{}`",
                    approval.proposal_digest
                ),
            ));
        }
    }
    Ok(())
}

fn validate_approval(path: &Path, approval: &HookImportApproval) -> Result<(), HookImportError> {
    validate_approval_identity(path, approval)?;
    validate_approval_authority(path, approval)?;
    validate_approval_artifacts(path, approval)?;
    validate_approval_digest(path, approval)
}

fn validate_approval_identity(
    path: &Path,
    approval: &HookImportApproval,
) -> Result<(), HookImportError> {
    if approval.schema_version != IMPORT_SCHEMA_VERSION {
        return Err(HookImportError::ApprovalSchema {
            found: approval.schema_version,
            expected: IMPORT_SCHEMA_VERSION,
        });
    }
    if approval.source_scope != approval.kind.scope() {
        return Err(approval_parse_error(
            path,
            "approval source scope does not match its import kind",
        ));
    }
    if !approval.workspace.is_absolute()
        || !approval.source_root.is_absolute()
        || !approval.source.is_absolute()
        || !approval.source.starts_with(&approval.source_root)
    {
        return Err(approval_parse_error(
            path,
            "approval workspace/source-root/source paths are not an absolute contained set",
        ));
    }
    if !matches!(approval.source_scope, HookImportSourceScope::User)
        && approval.source_root != approval.workspace
    {
        return Err(approval_parse_error(
            path,
            "repository approval source root must equal its canonical workspace",
        ));
    }
    if approval.source_owner != approval.source_root_owner {
        return Err(approval_parse_error(
            path,
            "approval source owner differs from its source-root owner",
        ));
    }
    if !valid_digest(&approval.source_digest) || !valid_digest(&approval.proposal_digest) {
        return Err(approval_parse_error(
            path,
            "approval contains a malformed SHA-256 digest",
        ));
    }
    if approval.hook_count == 0 || approval.hook_count > MAX_IMPORTED_HOOKS {
        return Err(approval_parse_error(
            path,
            "approval hook_count is outside the supported range",
        ));
    }
    if !owner_identity_is_valid(&approval.workspace_owner)
        || !owner_identity_is_valid(&approval.source_root_owner)
        || !owner_identity_is_valid(&approval.source_owner)
        || approval
            .requested_events
            .iter()
            .any(|event| hook_event_from_config_key(event).is_none())
    {
        return Err(approval_parse_error(
            path,
            "approval contains an invalid owner or lifecycle-event identity",
        ));
    }
    if !strictly_sorted(&approval.requested_events)
        || !strictly_sorted(&approval.requested_effects)
        || !strictly_sorted(&approval.requested_capabilities)
        || !strictly_sorted(&approval.commands)
    {
        return Err(approval_parse_error(
            path,
            "approval lists must be strictly sorted and duplicate-free",
        ));
    }
    Ok(())
}

fn validate_approval_authority(
    path: &Path,
    approval: &HookImportApproval,
) -> Result<(), HookImportError> {
    if approval
        .output_authority
        .windows(2)
        .any(|pair| pair[0].event >= pair[1].event)
        || approval.output_authority.iter().any(|authority| {
            let event = hook_event_from_config_key(&authority.event);
            event.is_none()
                || !approval.requested_events.contains(&authority.event)
                || authority.fields.is_empty()
                || !strictly_sorted(&authority.fields)
                || authority.fields.iter().any(|field| match field {
                    HookImportOutputField::Decision => {
                        !event.is_some_and(|event| event.contract().accepts_decision)
                    }
                    HookImportOutputField::PromptSuggestion => {
                        !event.is_some_and(|event| event.contract().accepts_prompt_suggestion)
                    }
                    HookImportOutputField::ReferenceContext => false,
                })
        })
    {
        return Err(approval_parse_error(
            path,
            "approval output authority is ambiguous or not bound to a requested event",
        ));
    }
    Ok(())
}

fn validate_approval_artifacts(
    path: &Path,
    approval: &HookImportApproval,
) -> Result<(), HookImportError> {
    if approval.commands.len() != approval.executables.len() {
        return Err(approval_parse_error(
            path,
            "every approved command must have exactly one executable identity",
        ));
    }
    for (command, executable) in approval.commands.iter().zip(&approval.executables) {
        if command != &executable.command
            || executable.argv.first() != Some(&executable.executable_token)
            || shlex::split(command).as_ref() != Some(&executable.argv)
            || !executable.resolved_path.is_absolute()
            || executable.bytes > MAX_EXECUTABLE_BYTES
            || !valid_digest(&executable.digest)
            || !owner_identity_is_valid(&executable.owner)
        {
            return Err(approval_parse_error(
                path,
                format!("malformed executable identity for command `{command}`"),
            ));
        }
    }
    let executable_bytes = approval
        .executables
        .iter()
        .try_fold(0u64, |total, executable| {
            total.checked_add(executable.bytes)
        });
    if executable_bytes.is_none_or(|bytes| bytes > MAX_EXECUTABLES_TOTAL_BYTES) {
        return Err(approval_parse_error(
            path,
            "approved executable identities exceed the total byte limit",
        ));
    }
    if !approval
        .bound_files
        .windows(2)
        .all(|pair| pair[0].path < pair[1].path)
        || approval.bound_files.iter().any(|file| {
            let expected_owner = if file.path.starts_with(&approval.workspace) {
                Some(&approval.workspace_owner)
            } else if matches!(approval.source_scope, HookImportSourceScope::User)
                && file.path.starts_with(&approval.source_root)
            {
                Some(&approval.source_root_owner)
            } else {
                None
            };
            !file.path.is_absolute()
                || expected_owner != Some(&file.owner)
                || file.bytes > MAX_BOUND_FILE_BYTES
                || !valid_digest(&file.digest)
        })
    {
        return Err(approval_parse_error(
            path,
            "approval contains a malformed repository file binding",
        ));
    }
    let bound_bytes = approval
        .bound_files
        .iter()
        .try_fold(0u64, |total, file| total.checked_add(file.bytes));
    if approval.bound_files.len() > MAX_BOUND_FILES
        || bound_bytes.is_none_or(|bytes| bytes > MAX_BOUND_FILES_TOTAL_BYTES)
    {
        return Err(approval_parse_error(
            path,
            "approved file bindings exceed the count or total byte limit",
        ));
    }
    Ok(())
}

fn validate_approval_digest(
    path: &Path,
    approval: &HookImportApproval,
) -> Result<(), HookImportError> {
    let fingerprint = ProposalFingerprint {
        schema_version: approval.schema_version,
        kind: approval.kind,
        source_scope: approval.source_scope,
        workspace: &approval.workspace,
        workspace_owner: &approval.workspace_owner,
        source_root: &approval.source_root,
        source_root_owner: &approval.source_root_owner,
        source: &approval.source,
        source_owner: &approval.source_owner,
        source_digest: &approval.source_digest,
        requested_events: &approval.requested_events,
        requested_effects: &approval.requested_effects,
        requested_capabilities: &approval.requested_capabilities,
        output_authority: &approval.output_authority,
        commands: &approval.commands,
        executables: &approval.executables,
        bound_files: &approval.bound_files,
        hook_count: approval.hook_count,
    };
    let fingerprint_bytes = serde_json::to_vec(&fingerprint).map_err(|error| {
        approval_parse_error(path, format!("cannot reconstruct approval digest: {error}"))
    })?;
    if digest_bytes(&fingerprint_bytes) != approval.proposal_digest {
        return Err(approval_parse_error(
            path,
            "approval proposal digest does not match its authority fields",
        ));
    }
    Ok(())
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

const fn owner_identity_is_valid(owner: &HookImportOwner) -> bool {
    match owner {
        HookImportOwner::Unix { .. } => true,
        HookImportOwner::Windows { sid } => !sid.is_empty(),
    }
}

fn hook_event_from_config_key(key: &str) -> Option<HookEvent> {
    match key {
        "session_start" => Some(HookEvent::SessionStart),
        "session_end" => Some(HookEvent::SessionEnd),
        "pre_tool_use" => Some(HookEvent::PreToolUse),
        "post_tool_use" => Some(HookEvent::PostToolUse),
        "post_tool_use_failure" => Some(HookEvent::PostToolUseFailure),
        "user_prompt_submit" => Some(HookEvent::UserPromptSubmit),
        "stop" => Some(HookEvent::Stop),
        "subagent_start" => Some(HookEvent::SubagentStart),
        "subagent_stop" => Some(HookEvent::SubagentStop),
        "pre_compact" => Some(HookEvent::PreCompact),
        "permission_request" => Some(HookEvent::PermissionRequest),
        "notification" => Some(HookEvent::Notification),
        "pre_adversary_review" => Some(HookEvent::PreAdversaryReview),
        "post_adversary_review" => Some(HookEvent::PostAdversaryReview),
        "vdd_conflict" => Some(HookEvent::VddConflict),
        "vdd_converged" => Some(HookEvent::VddConverged),
        _ => None,
    }
}

fn approval_parse_error(path: &Path, reason: impl Into<String>) -> HookImportError {
    HookImportError::Parse {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

#[cfg(unix)]
fn validate_approval_store_file(path: &Path) -> Result<(), HookImportError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = fs::symlink_metadata(path).map_err(|source| HookImportError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    // SAFETY: geteuid has no preconditions and retains no pointers.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid || metadata.mode() & 0o022 != 0 {
        return Err(HookImportError::InvalidPath {
            path: path.to_path_buf(),
            reason: format!(
                "approval store must be owned by effective uid {effective_uid} and not group/world writable"
            ),
        });
    }
    Ok(())
}

#[cfg(windows)]
fn validate_approval_store_file(path: &Path) -> Result<(), HookImportError> {
    let file = File::open(path).map_err(|source| HookImportError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    crate::windows_fs::validate_owned_acl(&file, true).map_err(|source| HookImportError::Read {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(any(unix, windows)))]
fn validate_approval_store_file(path: &Path) -> Result<(), HookImportError> {
    Err(HookImportError::Unsupported {
        path: path.to_path_buf(),
        reason: "host approval-store ownership checks are unavailable on this platform".to_string(),
    })
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
        validate_approval_store_file(path)?;
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
    validate_approval_store_parent(parent)?;
    validate_approval_store(path, store)?;
    let bytes = serde_json::to_vec_pretty(store).map_err(|error| {
        HookImportError::ApprovalStoreUnavailable(format!(
            "failed to serialize approval store: {error}"
        ))
    })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_APPROVAL_STORE_BYTES {
        return Err(HookImportError::ApprovalStoreUnavailable(format!(
            "serialized approval store exceeds {MAX_APPROVAL_STORE_BYTES} bytes"
        )));
    }
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

#[cfg(unix)]
fn validate_approval_store_parent(path: &Path) -> Result<(), HookImportError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = fs::symlink_metadata(path).map_err(|source| HookImportError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    // SAFETY: geteuid has no preconditions and retains no pointers.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(HookImportError::InvalidPath {
            path: path.to_path_buf(),
            reason: format!(
                "approval-store parent must be a non-symlink directory owned by effective uid {effective_uid} and not group/world writable"
            ),
        });
    }
    Ok(())
}

#[cfg(windows)]
fn validate_approval_store_parent(path: &Path) -> Result<(), HookImportError> {
    let directory = crate::windows_fs::open_absolute_directory(path).map_err(|source| {
        HookImportError::Read {
            path: path.to_path_buf(),
            source,
        }
    })?;
    crate::windows_fs::validate_owned_acl(&directory, false).map_err(|source| {
        HookImportError::Read {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(any(unix, windows)))]
fn validate_approval_store_parent(path: &Path) -> Result<(), HookImportError> {
    Err(HookImportError::Unsupported {
        path: path.to_path_buf(),
        reason: "host approval-directory ownership checks are unavailable on this platform"
            .to_string(),
    })
}

fn digest_file_bounded(path: &Path, limit: u64) -> Result<String, HookImportError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| HookImportError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(HookImportError::InvalidPath {
            path: path.to_path_buf(),
            reason: "digest target must be a regular, non-symlink file".to_string(),
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
    let mut digest = Sha256::new();
    let mut observed = 0u64;
    let mut buffer = vec![0u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file
            .read(buffer.as_mut())
            .map_err(|source| HookImportError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        observed = observed.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if observed > limit {
            return Err(HookImportError::InvalidPath {
                path: path.to_path_buf(),
                reason: format!("file changed while hashing and exceeded {limit} bytes"),
            });
        }
        digest.update(&buffer[..read]);
    }
    Ok(encode_digest(digest.finalize()))
}

fn digest_bytes(bytes: &[u8]) -> String {
    encode_digest(Sha256::digest(bytes))
}

fn encode_digest(digest: impl AsRef<[u8]>) -> String {
    let digest = digest.as_ref();
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
        | HookImportError::ApprovalSchema { .. }
        | HookImportError::DiscoveryRejected { .. }
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
            HookImportState::Pending | HookImportState::Changed | HookImportState::Rejected => {
                warn!(
                    state = ?proposal.state,
                    source = %proposal.source.display(),
                    source_digest = %proposal.source_digest,
                    proposal_digest = %proposal.proposal_digest,
                    events = ?proposal.requested_events,
                    effects = ?proposal.requested_effects,
                    "repository hooks remain inert; review with `openclaudia hooks status` and approve the exact proposal digest"
                );
            }
        }
    }
}
