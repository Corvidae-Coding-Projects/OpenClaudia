//! Run- and workspace-scoped freshness plus immutable artifact snapshots for
//! trusted evidence.
//!
//! The ledger is an index; this module owns the process-local state that makes
//! a verification receipt current. Workspace-capable effects reserve a
//! mutation before execution, while quality gates and finalization compare a
//! bounded, deterministic source-tree snapshot under the same coordinator.

use crate::runtime::{CapabilityGeneration, RunId};
use crate::tools::effect::ToolEffect;
use crate::tools::ToolRunContext;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, MutexGuard};

pub const VERIFICATION_POLICY_VERSION: u32 = 3;
const MAX_SNAPSHOT_ENTRIES: u64 = 100_000;
const MAX_SNAPSHOT_BYTES: u64 = 1_073_741_824;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RunKey {
    run_id: RunId,
    generation: CapabilityGeneration,
}

impl RunKey {
    fn from_run(run: &ToolRunContext) -> Self {
        Self {
            run_id: run.run_id(),
            generation: run.generation(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FreshnessStamp {
    pub workspace_generation: u64,
    pub task_generation: u64,
    pub model_generation: u64,
    pub policy_generation: u64,
    pub import_generation: u64,
    pub policy_version: u32,
    pub task_sha256: Option<String>,
    pub model_sha256: Option<String>,
    pub policy_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceDependencyPolicy {
    /// Hash every regular file and symlink in the project except the root
    /// `.git`, `target`, `.openclaudia/reality-ledgers`, and Crosslink's
    /// `.crosslink/.cache` and `.crosslink/.hub-cache` subtrees. Those
    /// exclusions are VCS metadata or runtime/build caches, not source inputs
    /// asserted by the final gate.
    ProjectSourceTreeV1,
    /// Extends [`Self::ProjectSourceTreeV1`] by excluding the repository-local
    /// `.worktrees` control subtree. Linked worktrees contain independent build
    /// caches and Git metadata rather than source owned by the current run.
    /// Only the root subtree is excluded; a nested `src/.worktrees` directory
    /// remains part of the verified source artifact set.
    ProjectSourceTreeV2,
    /// Extends [`Self::ProjectSourceTreeV2`] with the exact runtime/build
    /// outputs owned by the repository's fuzz package. The `fuzz/target`,
    /// `fuzz/artifacts`, and `fuzz/coverage` subtrees plus non-seed corpus
    /// discoveries are excluded. Reviewed `fuzz/corpus/*/seed-*` inputs remain
    /// verified source artifacts.
    ProjectSourceTreeV3,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactSetBinding {
    pub dependency_policy: WorkspaceDependencyPolicy,
    pub workspace_root: String,
    pub workspace_sha256: String,
    pub entry_count: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VerificationFreshnessBinding {
    pub freshness: FreshnessStamp,
    pub artifacts: ArtifactSetBinding,
    pub environment_sha256: String,
    pub verifier_identity_sha256: String,
}

#[derive(Debug)]
struct FreshnessState {
    workspace: PathBuf,
    task_generation: u64,
    model_generation: u64,
    policy_generation: u64,
    import_generation: u64,
    task_sha256: Option<String>,
    model_sha256: Option<String>,
    policy_sha256: Option<String>,
    pending_workspace_mutations: u64,
    pending_task_mutations: u64,
}

impl FreshnessState {
    const fn new(import_generation: u64, workspace: PathBuf) -> Self {
        Self {
            workspace,
            task_generation: 0,
            model_generation: 0,
            policy_generation: 0,
            import_generation,
            task_sha256: None,
            model_sha256: None,
            policy_sha256: None,
            pending_workspace_mutations: 0,
            pending_task_mutations: 0,
        }
    }

    fn stamp(&self, workspace_generation: u64) -> FreshnessStamp {
        FreshnessStamp {
            workspace_generation,
            task_generation: self.task_generation,
            model_generation: self.model_generation,
            policy_generation: self.policy_generation,
            import_generation: self.import_generation,
            policy_version: VERIFICATION_POLICY_VERSION,
            task_sha256: self.task_sha256.clone(),
            model_sha256: self.model_sha256.clone(),
            policy_sha256: self.policy_sha256.clone(),
        }
    }
}

#[derive(Debug)]
struct WorkspaceFreshnessState {
    generation: u64,
    pending_mutations: u64,
    active_runs: u64,
}

impl WorkspaceFreshnessState {
    const fn new() -> Self {
        Self {
            generation: 1,
            pending_mutations: 0,
            active_runs: 0,
        }
    }
}

#[derive(Default)]
struct FreshnessRegistry {
    runs: HashMap<RunKey, FreshnessState>,
    workspaces: HashMap<PathBuf, WorkspaceFreshnessState>,
}

static FRESHNESS: LazyLock<Mutex<FreshnessRegistry>> =
    LazyLock::new(|| Mutex::new(FreshnessRegistry::default()));

fn freshness_guard(
    operation: &'static str,
) -> Result<MutexGuard<'static, FreshnessRegistry>, String> {
    FRESHNESS.lock().map_err(|error| {
        tracing::error!(
            operation,
            error = %error,
            "evidence freshness registry lock poisoned; refusing authoritative evidence"
        );
        "evidence freshness registry is unavailable".to_string()
    })
}

fn ensure_run_state(registry: &mut FreshnessRegistry, run: &ToolRunContext) {
    let key = RunKey::from_run(run);
    if registry.runs.contains_key(&key) {
        return;
    }
    let workspace = run.project_root().to_path_buf();
    let workspace_state = registry
        .workspaces
        .entry(workspace.clone())
        .or_insert_with(WorkspaceFreshnessState::new);
    workspace_state.active_runs = workspace_state.active_runs.saturating_add(1);
    registry
        .runs
        .insert(key, FreshnessState::new(run.generation().get(), workspace));
}

fn state_for_run<'a>(
    registry: &'a mut FreshnessRegistry,
    run: &ToolRunContext,
) -> &'a mut FreshnessState {
    ensure_run_state(registry, run);
    registry
        .runs
        .get_mut(&RunKey::from_run(run))
        .expect("ensured run freshness state must exist")
}

fn stamp_for_key(registry: &FreshnessRegistry, key: RunKey) -> Result<FreshnessStamp, String> {
    let state = registry
        .runs
        .get(&key)
        .ok_or_else(|| "cannot issue evidence for a released run generation".to_string())?;
    let workspace_generation = registry
        .workspaces
        .get(&state.workspace)
        .ok_or_else(|| "workspace freshness state is unavailable".to_string())?
        .generation;
    Ok(state.stamp(workspace_generation))
}

pub fn current_stamp(run: &ToolRunContext) -> Result<FreshnessStamp, String> {
    let mut registry = freshness_guard("current_stamp")?;
    ensure_run_state(&mut registry, run);
    let stamp = stamp_for_key(&registry, RunKey::from_run(run))?;
    drop(registry);
    Ok(stamp)
}

pub fn current_stamp_for_binding(
    run_id: RunId,
    generation: CapabilityGeneration,
) -> Result<FreshnessStamp, String> {
    let registry = freshness_guard("current_stamp_for_binding")?;
    let stamp = stamp_for_key(&registry, RunKey { run_id, generation })?;
    drop(registry);
    Ok(stamp)
}

/// Bind the immutable guardrail/finalization policy for one run.
///
/// Returns `true` only when an already-bound policy changed and existing
/// verification receipts therefore need invalidation.
pub fn bind_policy(run: &ToolRunContext, policy_sha256: String) -> Result<bool, String> {
    let mut registry = freshness_guard("bind_policy")?;
    let state = state_for_run(&mut registry, run);
    let changed = state
        .policy_sha256
        .as_ref()
        .is_some_and(|existing| existing != &policy_sha256);
    if state.policy_sha256.as_ref() != Some(&policy_sha256) {
        state.policy_generation = state.policy_generation.saturating_add(1);
        state.policy_sha256 = Some(policy_sha256);
    }
    drop(registry);
    Ok(changed)
}

/// Advance the user task and synchronize the model that will act on it.
pub fn advance_task(run: &ToolRunContext, task: &str, model_identity: &str) -> Result<(), String> {
    let model_sha256 = model_identity_digest(model_identity)?;
    let mut registry = freshness_guard("advance_task")?;
    let state = state_for_run(&mut registry, run);
    state.task_generation = state.task_generation.saturating_add(1);
    state.task_sha256 = Some(sha256_hex(task.as_bytes()));
    if state.model_sha256.as_ref() != Some(&model_sha256) {
        state.model_generation = state.model_generation.saturating_add(1);
        state.model_sha256 = Some(model_sha256);
    }
    drop(registry);
    Ok(())
}

/// Synchronize the currently selected model before verification/finalization.
///
/// Returns `true` when a prior model binding changed.
pub fn sync_model(run: &ToolRunContext, model_identity: &str) -> Result<bool, String> {
    let model_sha256 = model_identity_digest(model_identity)?;
    let mut registry = freshness_guard("sync_model")?;
    let state = state_for_run(&mut registry, run);
    let changed = state
        .model_sha256
        .as_ref()
        .is_some_and(|existing| existing != &model_sha256);
    if state.model_sha256.as_ref() != Some(&model_sha256) {
        state.model_generation = state.model_generation.saturating_add(1);
        state.model_sha256 = Some(model_sha256);
    }
    drop(registry);
    Ok(changed)
}

fn model_identity_digest(model_identity: &str) -> Result<String, String> {
    let model_identity = model_identity.trim();
    if model_identity.is_empty() {
        return Err("verification model identity must not be empty".to_string());
    }
    Ok(sha256_hex(model_identity.as_bytes()))
}

#[derive(Debug, Clone, Copy)]
struct MutationDomains {
    workspace: bool,
    task: bool,
}

impl MutationDomains {
    const fn for_effect(effect: ToolEffect) -> Self {
        match effect {
            ToolEffect::ReadOnly | ToolEffect::NetworkRead => Self {
                workspace: false,
                task: false,
            },
            ToolEffect::SessionMutation => Self {
                workspace: false,
                task: true,
            },
            ToolEffect::WorkspaceMutation
            | ToolEffect::ExternalMutation
            | ToolEffect::Destructive => Self {
                workspace: true,
                task: false,
            },
        }
    }

    const fn any(self) -> bool {
        self.workspace || self.task
    }
}

/// RAII token that prevents a verifier snapshot while a managed mutation is
/// in flight. Dropping an uncommitted token releases it without changing a
/// generation; success and typed-partial outcomes commit through guardrails.
pub struct MutationReservation {
    key: RunKey,
    workspace: Option<PathBuf>,
    domains: MutationDomains,
    pending: bool,
}

impl MutationReservation {
    pub fn commit(&mut self) -> Result<(), String> {
        if !self.pending {
            return Ok(());
        }
        let mut registry = freshness_guard("commit_mutation")?;
        let mut failure = None;
        if let Some(state) = registry.runs.get_mut(&self.key) {
            release_run_pending(state, self.domains);
        } else {
            failure = Some("evidence freshness state disappeared during mutation".to_string());
        }
        if let Some(workspace) = self.workspace.as_ref() {
            if let Some(state) = registry.workspaces.get_mut(workspace) {
                state.pending_mutations = state.pending_mutations.saturating_sub(1);
                state.generation = state.generation.saturating_add(1);
            } else {
                failure = Some("workspace freshness state disappeared during mutation".to_string());
            }
        }
        if self.domains.task {
            if let Some(state) = registry.runs.get_mut(&self.key) {
                state.task_generation = state.task_generation.saturating_add(1);
                state.task_sha256 = None;
            }
        }
        self.pending = false;
        if let Some(workspace) = self.workspace.as_ref() {
            remove_unused_workspace(&mut registry, workspace);
        }
        drop(registry);
        failure.map_or(Ok(()), Err)
    }
}

impl Drop for MutationReservation {
    fn drop(&mut self) {
        if !self.pending {
            return;
        }
        match freshness_guard("release_mutation") {
            Ok(mut registry) => {
                if let Some(state) = registry.runs.get_mut(&self.key) {
                    release_run_pending(state, self.domains);
                }
                if let Some(workspace) = self.workspace.as_ref() {
                    if let Some(state) = registry.workspaces.get_mut(workspace) {
                        state.pending_mutations = state.pending_mutations.saturating_sub(1);
                    }
                    remove_unused_workspace(&mut registry, workspace);
                }
            }
            Err(error) => tracing::error!(%error, "failed to release evidence mutation token"),
        }
        self.pending = false;
    }
}

const fn release_run_pending(state: &mut FreshnessState, domains: MutationDomains) {
    if domains.workspace {
        state.pending_workspace_mutations = state.pending_workspace_mutations.saturating_sub(1);
    }
    if domains.task {
        state.pending_task_mutations = state.pending_task_mutations.saturating_sub(1);
    }
}

fn remove_unused_workspace(registry: &mut FreshnessRegistry, workspace: &Path) {
    let removable = registry
        .workspaces
        .get(workspace)
        .is_some_and(|state| state.active_runs == 0 && state.pending_mutations == 0);
    if removable {
        registry.workspaces.remove(workspace);
    }
}

pub fn reserve_mutation(
    run: &ToolRunContext,
    effect: ToolEffect,
) -> Result<Option<MutationReservation>, String> {
    let domains = MutationDomains::for_effect(effect);
    if !domains.any() {
        return Ok(None);
    }
    let key = RunKey::from_run(run);
    let mut registry = freshness_guard("reserve_mutation")?;
    ensure_run_state(&mut registry, run);
    let workspace = registry
        .runs
        .get(&key)
        .expect("ensured run freshness state must exist")
        .workspace
        .clone();
    if domains.workspace {
        let run_pending = registry
            .runs
            .get(&key)
            .expect("ensured run freshness state must exist")
            .pending_workspace_mutations
            .checked_add(1)
            .ok_or_else(|| "workspace mutation reservation count exhausted".to_string())?;
        let workspace_pending = registry
            .workspaces
            .get(&workspace)
            .expect("ensured workspace freshness state must exist")
            .pending_mutations
            .checked_add(1)
            .ok_or_else(|| "shared workspace mutation reservation count exhausted".to_string())?;
        registry
            .runs
            .get_mut(&key)
            .expect("ensured run freshness state must exist")
            .pending_workspace_mutations = run_pending;
        registry
            .workspaces
            .get_mut(&workspace)
            .expect("ensured workspace freshness state must exist")
            .pending_mutations = workspace_pending;
    }
    if domains.task {
        let state = registry
            .runs
            .get_mut(&key)
            .expect("ensured run freshness state must exist");
        state.pending_task_mutations = state
            .pending_task_mutations
            .checked_add(1)
            .ok_or_else(|| "task mutation reservation count exhausted".to_string())?;
    }
    drop(registry);
    Ok(Some(MutationReservation {
        key,
        workspace: domains.workspace.then_some(workspace),
        domains,
        pending: true,
    }))
}

/// Record a workspace change observed outside the canonical effect
/// reservation (primarily direct ledger/API callers). When a managed mutation
/// is already pending, its eventual commit owns the generation change.
pub fn observe_workspace_change(run: &ToolRunContext) -> Result<bool, String> {
    let mut registry = freshness_guard("observe_workspace_change")?;
    ensure_run_state(&mut registry, run);
    let state = registry
        .runs
        .get(&RunKey::from_run(run))
        .expect("ensured run freshness state must exist");
    if state.pending_workspace_mutations > 0 {
        return Ok(false);
    }
    let workspace = state.workspace.clone();
    let state = registry
        .workspaces
        .get_mut(&workspace)
        .expect("ensured workspace freshness state must exist");
    state.generation = state.generation.saturating_add(1);
    drop(registry);
    Ok(true)
}

// Keep the coordinator locked across the double snapshot: this is the
// serialization point that prevents a canonical mutation from starting
// between generation capture and artifact hashing.
#[allow(clippy::significant_drop_tightening)]
pub fn capture_verification_binding(
    run: &ToolRunContext,
    verifier_identity_sha256: String,
) -> Result<VerificationFreshnessBinding, String> {
    let mut registry = freshness_guard("capture_verification_binding")?;
    ensure_run_state(&mut registry, run);
    let state = registry
        .runs
        .get(&RunKey::from_run(run))
        .expect("ensured run freshness state must exist");
    let workspace = registry
        .workspaces
        .get(&state.workspace)
        .expect("ensured workspace freshness state must exist");
    require_stable_state(state, workspace)?;
    if state.model_sha256.is_none() {
        return Err("quality-gate evidence lacks a bound model identity".to_string());
    }
    if state.policy_sha256.is_none() {
        return Err("quality-gate evidence lacks a bound policy identity".to_string());
    }
    let freshness = state.stamp(workspace.generation);
    let artifacts = stable_artifact_set(run)?;
    Ok(VerificationFreshnessBinding {
        freshness,
        artifacts,
        environment_sha256: environment_sha256(run),
        verifier_identity_sha256,
    })
}

// Validation needs the same serialization point as capture; releasing the
// lock before hashing would reopen the verify/mutate race this module closes.
#[allow(clippy::significant_drop_tightening)]
pub fn validate_verification_binding(
    run: &ToolRunContext,
    binding: &VerificationFreshnessBinding,
) -> Result<(), String> {
    let mut registry = freshness_guard("validate_verification_binding")?;
    ensure_run_state(&mut registry, run);
    let state = registry
        .runs
        .get(&RunKey::from_run(run))
        .expect("ensured run freshness state must exist");
    let workspace = registry
        .workspaces
        .get(&state.workspace)
        .expect("ensured workspace freshness state must exist");
    require_stable_state(state, workspace)?;
    if state.stamp(workspace.generation) != binding.freshness {
        return Err("verification context generation changed after the quality gate".to_string());
    }
    if binding.freshness.policy_version != VERIFICATION_POLICY_VERSION {
        return Err("verification policy version is no longer current".to_string());
    }
    if environment_sha256(run) != binding.environment_sha256 {
        return Err("verification environment changed after the quality gate".to_string());
    }
    let current = stable_artifact_set(run)?;
    if current != binding.artifacts {
        return Err("verified workspace artifact set changed after the quality gate".to_string());
    }
    Ok(())
}

fn require_stable_state(
    state: &FreshnessState,
    workspace: &WorkspaceFreshnessState,
) -> Result<(), String> {
    if workspace.pending_mutations > 0 || state.pending_task_mutations > 0 {
        return Err(
            "cannot issue or validate verification while a mutation is in progress".to_string(),
        );
    }
    Ok(())
}

pub fn verifier_identity_sha256(
    check: &str,
    normalized_argv: &[String],
    resolved_executable: Option<&str>,
    executable_sha256: Option<&str>,
) -> String {
    let mut digest = Sha256::new();
    update_field(&mut digest, check.as_bytes());
    for arg in normalized_argv {
        update_field(&mut digest, arg.as_bytes());
    }
    update_field(
        &mut digest,
        resolved_executable.unwrap_or_default().as_bytes(),
    );
    update_field(
        &mut digest,
        executable_sha256.unwrap_or_default().as_bytes(),
    );
    digest_hex(digest.finalize().as_slice())
}

fn environment_sha256(run: &ToolRunContext) -> String {
    let mut digest = Sha256::new();
    update_field(
        &mut digest,
        run.runtime()
            .descriptor()
            .capabilities
            .manifest_digest
            .to_string()
            .as_bytes(),
    );
    update_field(&mut digest, std::env::consts::OS.as_bytes());
    update_field(&mut digest, std::env::consts::ARCH.as_bytes());
    update_field(
        &mut digest,
        run.working_directory().as_os_str().as_encoded_bytes(),
    );
    let mut names = run.environment_grants().keys().collect::<Vec<_>>();
    names.sort_unstable();
    for name in names {
        update_field(&mut digest, name.as_bytes());
        run.environment_grants()
            .with_value(name, |value| update_field(&mut digest, value.as_bytes()))
            .expect("name came from environment capability");
    }
    update_field(&mut digest, run.executable_search_path().as_encoded_bytes());
    digest_hex(digest.finalize().as_slice())
}

fn stable_artifact_set(run: &ToolRunContext) -> Result<ArtifactSetBinding, String> {
    let first = artifact_set(run.project_root())?;
    let second = artifact_set(run.project_root())?;
    if first != second {
        return Err(
            "workspace changed while its verification snapshot was being captured".to_string(),
        );
    }
    Ok(first)
}

fn artifact_set(root: &Path) -> Result<ArtifactSetBinding, String> {
    let mut digest = Sha256::new();
    let mut queue = VecDeque::from([root.to_path_buf()]);
    let mut entry_count = 0_u64;
    let mut total_bytes = 0_u64;

    while let Some(directory) = queue.pop_front() {
        let mut entries = std::fs::read_dir(&directory)
            .map_err(|error| format!("cannot enumerate verification artifact set: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot enumerate verification artifact set: {error}"))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|error| format!("verification artifact escaped project root: {error}"))?;
            if artifact_path_is_excluded(relative) {
                continue;
            }
            entry_count = entry_count
                .checked_add(1)
                .ok_or_else(|| "verification artifact entry count exhausted".to_string())?;
            if entry_count > MAX_SNAPSHOT_ENTRIES {
                return Err(format!(
                    "verification artifact set exceeds {MAX_SNAPSHOT_ENTRIES} entries"
                ));
            }
            let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
                format!(
                    "cannot inspect verification artifact '{}': {error}",
                    path.display()
                )
            })?;
            if metadata.file_type().is_dir() {
                update_artifact_header(&mut digest, b'd', relative, &metadata);
                queue.push_back(path);
            } else if metadata.file_type().is_symlink() {
                update_artifact_header(&mut digest, b'l', relative, &metadata);
                let target = std::fs::read_link(&path).map_err(|error| {
                    format!(
                        "cannot read verification symlink '{}': {error}",
                        path.display()
                    )
                })?;
                update_field(&mut digest, target.as_os_str().as_encoded_bytes());
                let resolved_target = path
                    .parent()
                    .unwrap_or(root)
                    .join(&target)
                    .canonicalize()
                    .map_err(|error| {
                        format!(
                            "verification symlink '{}' has an unresolved target: {error}",
                            path.display()
                        )
                    })?;
                let target_relative = resolved_target.strip_prefix(root).map_err(|_| {
                    format!(
                        "verification symlink '{}' targets an artifact outside the project",
                        path.display()
                    )
                })?;
                if artifact_path_is_excluded(target_relative) {
                    return Err(format!(
                        "verification symlink '{}' targets an excluded artifact subtree",
                        path.display()
                    ));
                }
            } else if metadata.file_type().is_file() {
                update_artifact_header(&mut digest, b'f', relative, &metadata);
                total_bytes = total_bytes
                    .checked_add(metadata.len())
                    .ok_or_else(|| "verification artifact byte count exhausted".to_string())?;
                if total_bytes > MAX_SNAPSHOT_BYTES {
                    return Err(format!(
                        "verification artifact set exceeds {MAX_SNAPSHOT_BYTES} bytes"
                    ));
                }
                hash_regular_file(&mut digest, &path, &metadata)?;
            } else {
                return Err(format!(
                    "verification artifact set contains unsupported special file '{}'",
                    path.display()
                ));
            }
        }
    }

    Ok(ArtifactSetBinding {
        dependency_policy: WorkspaceDependencyPolicy::ProjectSourceTreeV3,
        workspace_root: root.to_string_lossy().to_string(),
        workspace_sha256: digest_hex(digest.finalize().as_slice()),
        entry_count,
        total_bytes,
    })
}

fn artifact_path_is_excluded(relative: &Path) -> bool {
    let components = relative
        .components()
        .map(std::path::Component::as_os_str)
        .collect::<Vec<_>>();
    matches!(
        components.first().and_then(|part| part.to_str()),
        Some(".git" | "target" | ".worktrees")
    ) || matches!(
        components.as_slice(),
        [first, second, ..]
            if *first == std::ffi::OsStr::new("fuzz")
                && matches!(second.to_str(), Some("target" | "artifacts" | "coverage"))
    ) || matches!(
        components.as_slice(),
        [first, second, _target, discovered, ..]
            if *first == std::ffi::OsStr::new("fuzz")
                && *second == std::ffi::OsStr::new("corpus")
                && !discovered.to_string_lossy().starts_with("seed-")
    ) || matches!(
        components.as_slice(),
        [first, second, ..]
            if *first == std::ffi::OsStr::new(".openclaudia")
                && *second == std::ffi::OsStr::new("reality-ledgers")
    ) || matches!(
        components.as_slice(),
        [first, second, ..]
            if *first == std::ffi::OsStr::new(".crosslink")
                && matches!(second.to_str(), Some(".cache" | ".hub-cache"))
    )
}

fn update_artifact_header(
    digest: &mut Sha256,
    kind: u8,
    relative: &Path,
    metadata: &std::fs::Metadata,
) {
    digest.update([kind]);
    update_field(digest, relative.as_os_str().as_encoded_bytes());
    digest.update([u8::from(metadata.permissions().readonly())]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        digest.update(metadata.mode().to_le_bytes());
    }
}

fn hash_regular_file(
    digest: &mut Sha256,
    path: &Path,
    metadata_before: &std::fs::Metadata,
) -> Result<(), String> {
    let mut file = std::fs::File::open(path).map_err(|error| {
        format!(
            "cannot open verification artifact '{}': {error}",
            path.display()
        )
    })?;
    let mut buffer = [0_u8; 16 * 1024];
    digest.update(metadata_before.len().to_le_bytes());
    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            format!(
                "cannot read verification artifact '{}': {error}",
                path.display()
            )
        })?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let metadata_after = file.metadata().map_err(|error| {
        format!(
            "cannot re-inspect verification artifact '{}': {error}",
            path.display()
        )
    })?;
    if metadata_before.len() != metadata_after.len()
        || metadata_before.modified().ok() != metadata_after.modified().ok()
    {
        return Err(format!(
            "verification artifact changed while being read: '{}'",
            path.display()
        ));
    }
    Ok(())
}

fn update_field(digest: &mut Sha256, bytes: &[u8]) {
    digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    digest.update(bytes);
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest_hex(Sha256::digest(bytes).as_slice())
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

pub fn release_run(run: &ToolRunContext) {
    match freshness_guard("release_run") {
        Ok(mut registry) => {
            if let Some(state) = registry.runs.remove(&RunKey::from_run(run)) {
                if let Some(workspace) = registry.workspaces.get_mut(&state.workspace) {
                    workspace.active_runs = workspace.active_runs.saturating_sub(1);
                }
                remove_unused_workspace(&mut registry, &state.workspace);
            }
        }
        Err(error) => tracing::error!(%error, "failed to release evidence freshness state"),
    }
}
