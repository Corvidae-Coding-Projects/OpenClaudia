//! Exact, expiring approval records and opaque execution permits.
//!
//! Approval records are data: they may be persisted in trusted host state and
//! reused only while every normalized binding still matches. Execution
//! permits are process-local capabilities: they are deliberately not
//! serializable or constructible outside this module, and the dispatcher
//! consumes them exactly once.

use std::fmt;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::{PermissionDecision, PermissionRule};
use crate::tools::effect::ResolvedEffect;
use crate::tools::ToolCall;

/// Current on-disk and in-memory approval schema.
pub const APPROVAL_RECEIPT_SCHEMA_VERSION: u32 = 1;

const MAX_PERMISSION_STORE_BYTES: u64 = 1024 * 1024;
const MAX_PERSISTED_APPROVALS: usize = 1024;
const MAX_PERSISTED_DENIALS: usize = 1024;
const MAX_SESSION_APPROVALS: usize = 1024;
const MAX_SESSION_DENIALS: usize = 1024;
const MAX_LOCAL_APPROVALS: usize = 1024;
const MAX_STRING_BYTES: usize = 512;
const SESSION_APPROVAL_USES: u32 = 128;
const PERSISTED_APPROVAL_USES: u32 = 64;
const SESSION_APPROVAL_HOURS: i64 = 8;
const PERSISTED_APPROVAL_DAYS: i64 = 30;

/// Trusted origin of an approval or denial decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalProvenance {
    /// A local interactive user answered the harness permission prompt.
    InteractiveUser,
    /// An authenticated ACP client made the decision.
    AcpClient,
    /// A coordinator leader approved a worker's exact request.
    CoordinatorLeader,
    /// A trusted host administrator provisioned the decision.
    HostAdministrator,
    /// The current host policy allowed the invocation without a user grant.
    PolicyEvaluation,
}

impl ApprovalProvenance {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::InteractiveUser => "interactive_user",
            Self::AcpClient => "acp_client",
            Self::CoordinatorLeader => "coordinator_leader",
            Self::HostAdministrator => "host_administrator",
            Self::PolicyEvaluation => "policy_evaluation",
        }
    }
}

/// Stable host/user/workspace identity used to scope approvals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalBinding {
    actor_id: String,
    workspace_digest: String,
    workspace_root: PathBuf,
    workspace_generation_base: u64,
    follows_process_cwd_generation: bool,
}

impl ApprovalBinding {
    /// Construct an explicit binding for composition roots and deterministic
    /// tests. Values are digested before persistence and traces.
    #[must_use]
    pub fn new(actor_id: impl AsRef<str>, workspace: impl AsRef<Path>, generation: u64) -> Self {
        let workspace_root = normalized_workspace(workspace.as_ref());
        Self {
            actor_id: digest_text(actor_id.as_ref()),
            workspace_digest: digest_text(&workspace_root.to_string_lossy()),
            workspace_root,
            workspace_generation_base: generation.max(1),
            follows_process_cwd_generation: false,
        }
    }

    /// Discover a binding for the current authenticated host invocation.
    #[must_use]
    pub fn current() -> Self {
        let actor = current_actor_identity();
        let workspace = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let mut binding = Self::new(actor, workspace, 1);
        binding.follows_process_cwd_generation = true;
        binding
    }

    /// Bind approvals to the current host actor and one exact run generation.
    #[must_use]
    pub fn for_run(run: &crate::tools::ToolRunContext) -> Self {
        Self::new(
            current_actor_identity(),
            run.project_root(),
            run.generation().get(),
        )
    }

    fn workspace_generation(&self) -> u64 {
        if self.follows_process_cwd_generation {
            self.workspace_generation_base
                .saturating_add(crate::tools::cwd_cache_generation())
        } else {
            self.workspace_generation_base
        }
    }
}

#[cfg(unix)]
fn current_actor_identity() -> String {
    // SAFETY: geteuid has no preconditions and no memory-safety contract.
    let effective_uid = unsafe { libc::geteuid() };
    format!("unix-euid:{effective_uid}")
}

#[cfg(not(unix))]
fn current_actor_identity() -> String {
    // The per-user configuration directory is provided by the OS and is a
    // more trustworthy stable identity input than USER/USERNAME environment
    // variables. The value is digested before it enters a receipt.
    dirs::config_dir().map_or_else(
        || "host-user:unavailable".to_string(),
        |path| format!("host-config:{}", path.display()),
    )
}

fn normalized_workspace(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| lexical_normalize(path))
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApprovalScope {
    actor_id: String,
    workspace_digest: String,
    workspace_generation: u64,
    capability_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    tool: String,
    effect: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operation: Option<String>,
    target_digest: String,
    arguments_digest: String,
}

impl ApprovalScope {
    fn for_call(
        binding: &ApprovalBinding,
        capability_generation: u64,
        resolved: &ResolvedEffect,
        arguments: &Value,
        session_id: Option<&str>,
    ) -> Self {
        Self {
            actor_id: binding.actor_id.clone(),
            workspace_digest: binding.workspace_digest.clone(),
            workspace_generation: binding.workspace_generation(),
            capability_generation,
            session_id: session_id.map(str::to_string),
            tool: resolved.canonical.clone(),
            effect: resolved.effect.as_str().to_string(),
            operation: resolved.operation.clone(),
            target_digest: digest_text(&normalize_target(resolved, binding)),
            arguments_digest: digest_text(&canonical_json(arguments)),
        }
    }

    fn without_session(&self) -> Self {
        let mut scope = self.clone();
        scope.session_id = None;
        scope
    }

    fn trace_id(&self) -> String {
        digest_text(&format!(
            "{}:{}:{}:{}:{}:{}",
            self.actor_id,
            self.workspace_digest,
            self.workspace_generation,
            self.capability_generation,
            self.tool,
            self.arguments_digest
        ))
    }
}

fn normalize_target(resolved: &ResolvedEffect, binding: &ApprovalBinding) -> String {
    if matches!(
        resolved.canonical.as_str(),
        "Read" | "Write" | "Edit" | "Lsp"
    ) {
        let path = Path::new(&resolved.target);
        let rooted = if path.is_absolute() {
            path.to_path_buf()
        } else {
            binding.workspace_root.join(path)
        };
        return canonicalize_existing_ancestor(&rooted)
            .to_string_lossy()
            .into_owned();
    }

    if matches!(
        resolved.canonical.as_str(),
        "WebFetch" | "WebSearch" | "WebBrowser"
    ) {
        if let Ok(mut url) = url::Url::parse(&resolved.target) {
            url.set_fragment(None);
            return url.to_string();
        }
    }

    resolved.target.clone()
}

/// Resolve symlinks in the longest existing prefix while preserving a
/// not-yet-created leaf. This keeps approvals for write targets bound to the
/// actual parent resource instead of to a replaceable symlink spelling.
fn canonicalize_existing_ancestor(path: &Path) -> PathBuf {
    if let Ok(canonical) = fs::canonicalize(path) {
        return canonical;
    }

    let mut cursor = path.to_path_buf();
    let mut suffix = Vec::new();
    while !cursor.exists() {
        let Some(name) = cursor.file_name().map(std::ffi::OsStr::to_os_string) else {
            return lexical_normalize(path);
        };
        suffix.push(name);
        if !cursor.pop() {
            return lexical_normalize(path);
        }
    }

    let mut canonical = fs::canonicalize(&cursor).unwrap_or_else(|_| lexical_normalize(&cursor));
    for component in suffix.into_iter().rev() {
        canonical.push(component);
    }
    lexical_normalize(&canonical)
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string()),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => {
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_unstable_by_key(|(key, _)| *key);
            let encoded = entries
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_string()),
                        canonical_json(value)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{encoded}}}")
        }
    }
}

pub(super) fn digest_text(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut hexadecimal = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(hexadecimal, "{byte:02x}").expect("writing to a String cannot fail");
    }
    format!("sha256:{hexadecimal}")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalRecord {
    receipt_id: Uuid,
    scope: ApprovalScope,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    remaining_uses: u32,
    provenance: ApprovalProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactDenialRecord {
    denial_id: Uuid,
    scope: ApprovalScope,
    issued_at: DateTime<Utc>,
    provenance: ApprovalProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedPermissionState {
    schema_version: u32,
    capability_generation: u64,
    #[serde(default)]
    approvals: Vec<ApprovalRecord>,
    #[serde(default)]
    denials: Vec<PermissionRule>,
    #[serde(default)]
    exact_denials: Vec<ExactDenialRecord>,
}

impl Default for PersistedPermissionState {
    fn default() -> Self {
        Self {
            schema_version: APPROVAL_RECEIPT_SCHEMA_VERSION,
            capability_generation: 1,
            approvals: Vec::new(),
            denials: Vec::new(),
            exact_denials: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
struct RuntimeApprovalState {
    persisted: PersistedPermissionState,
    session_approvals: Vec<ApprovalRecord>,
    session_denials: Vec<ExactDenialRecord>,
}

/// Bounded versioned approval storage owned by a permission manager.
pub(super) struct ApprovalStore {
    path: PathBuf,
    binding: ApprovalBinding,
    capability_generation: AtomicU64,
    state: Mutex<RuntimeApprovalState>,
}

impl ApprovalStore {
    pub(super) fn load(path: PathBuf, binding: ApprovalBinding) -> Self {
        let persisted = load_state(&path).unwrap_or_else(|error| {
            tracing::warn!(
                path_digest = %digest_text(&path.to_string_lossy()),
                error = %error,
                "Permission approval store rejected; continuing with no persisted authority"
            );
            PersistedPermissionState::default()
        });
        let generation = persisted.capability_generation.max(1);
        Self {
            path,
            binding,
            capability_generation: AtomicU64::new(generation),
            state: Mutex::new(RuntimeApprovalState {
                persisted,
                ..RuntimeApprovalState::default()
            }),
        }
    }

    pub(super) fn empty(binding: ApprovalBinding) -> Self {
        Self {
            path: PathBuf::new(),
            binding,
            capability_generation: AtomicU64::new(1),
            state: Mutex::new(RuntimeApprovalState::default()),
        }
    }

    pub(super) fn persisted_denials(&self) -> Vec<PermissionRule> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .persisted
            .denials
            .clone()
    }

    pub(super) fn capability_generation(&self) -> u64 {
        self.capability_generation.load(Ordering::Acquire)
    }

    pub(super) fn bump_generation(&self) -> Result<u64, String> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = self
            .capability_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                generation.checked_add(1)
            })
            .map_err(|_| "permission capability generation is exhausted".to_string())?;
        let candidate = previous + 1;
        state.session_approvals.clear();
        if self.path.as_os_str().is_empty() {
            return Ok(candidate);
        }
        let result = with_store_lock(&self.path, || {
            let mut persisted = load_state(&self.path)?;
            let generation = candidate.max(persisted.capability_generation.saturating_add(1));
            self.capability_generation
                .store(generation, Ordering::Release);
            persisted.capability_generation = generation;
            persisted.approvals.clear();
            save_state(&self.path, &persisted).map_err(|error| {
                format!(
                    "capability generation rotated in memory but could not be persisted: {error}"
                )
            })?;
            state.persisted = persisted;
            Ok(generation)
        });
        drop(state);
        result
    }

    pub(super) fn scope_for(
        &self,
        resolved: &ResolvedEffect,
        arguments: &Value,
        session_id: Option<&str>,
    ) -> ApprovalScope {
        ApprovalScope::for_call(
            &self.binding,
            self.capability_generation(),
            resolved,
            arguments,
            session_id,
        )
    }

    pub(super) fn sync_generation(&self) -> Result<u64, String> {
        let local_generation = self.capability_generation();
        if self.path.as_os_str().is_empty() {
            return Ok(local_generation);
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        with_store_lock(&self.path, || {
            let mut persisted = load_state(&self.path)?;
            let local_generation = self.capability_generation();
            if persisted.capability_generation > local_generation {
                self.capability_generation
                    .store(persisted.capability_generation, Ordering::Release);
                state.session_approvals.clear();
            } else if local_generation > persisted.capability_generation {
                persisted.capability_generation = local_generation;
                persisted.approvals.clear();
                save_state(&self.path, &persisted)?;
            }
            let generation = self.capability_generation();
            state.persisted = persisted;
            Ok(generation)
        })
    }

    pub(super) fn exact_denial_matches(&self, scope: &ApprovalScope) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .session_denials
            .iter()
            .chain(state.persisted.exact_denials.iter())
            .any(|denial| exact_denial_scope_matches(&denial.scope, scope))
    }

    pub(super) fn add_session_denial(
        &self,
        scope: ApprovalScope,
        provenance: ApprovalProvenance,
    ) -> Result<(), String> {
        let rotation = self.bump_generation();
        let mut scope = scope;
        scope.capability_generation = self.capability_generation();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .session_denials
            .retain(|existing| !exact_denial_scope_matches(&existing.scope, &scope));
        if state.session_denials.len() >= MAX_SESSION_DENIALS {
            state.session_denials.remove(0);
        }
        state.session_denials.push(ExactDenialRecord {
            denial_id: Uuid::new_v4(),
            scope,
            issued_at: Utc::now(),
            provenance,
        });
        drop(state);
        rotation.map(|_| ())
    }

    pub(super) fn mint_once(
        scope: ApprovalScope,
        tool_call_id: &str,
        provenance: ApprovalProvenance,
    ) -> ExecutionPermit {
        ExecutionPermit::new(
            scope,
            tool_call_id,
            Utc::now() + Duration::minutes(5),
            Uuid::new_v4(),
            provenance,
        )
    }

    pub(super) fn approve_for_session(
        &self,
        scope: ApprovalScope,
        tool_call_id: &str,
        provenance: ApprovalProvenance,
    ) -> ExecutionPermit {
        let now = Utc::now();
        let receipt_id = Uuid::new_v4();
        let record = ApprovalRecord {
            receipt_id,
            scope: scope.clone(),
            issued_at: now,
            expires_at: now + Duration::hours(SESSION_APPROVAL_HOURS),
            remaining_uses: SESSION_APPROVAL_USES.saturating_sub(1),
            provenance,
        };
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .session_approvals
            .retain(|existing| existing.scope != record.scope);
        if state.session_approvals.len() >= MAX_SESSION_APPROVALS {
            state.session_approvals.remove(0);
        }
        state.session_approvals.push(record);
        drop(state);
        ExecutionPermit::new(
            scope,
            tool_call_id,
            now + Duration::minutes(5),
            receipt_id,
            provenance,
        )
    }

    pub(super) fn approve_persisted(
        &self,
        scope: ApprovalScope,
        tool_call_id: &str,
        provenance: ApprovalProvenance,
    ) -> Result<ExecutionPermit, String> {
        if self.path.as_os_str().is_empty() {
            return Err("permission manager has no trusted persistence path".to_string());
        }
        let now = Utc::now();
        let receipt_id = Uuid::new_v4();
        let record = ApprovalRecord {
            receipt_id,
            scope: scope.without_session(),
            issued_at: now,
            expires_at: now + Duration::days(PERSISTED_APPROVAL_DAYS),
            remaining_uses: PERSISTED_APPROVAL_USES.saturating_sub(1),
            provenance,
        };
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        with_store_lock(&self.path, || {
            let mut persisted = load_state(&self.path)?;
            let local_generation = self.capability_generation();
            if persisted.capability_generation > local_generation {
                self.capability_generation
                    .store(persisted.capability_generation, Ordering::Release);
                return Err(
                    "permission capability generation changed; retry the exact approval"
                        .to_string(),
                );
            }
            if local_generation > persisted.capability_generation {
                persisted.capability_generation = local_generation;
                persisted.approvals.clear();
            }
            if record.scope.capability_generation != local_generation {
                return Err("approval scope belongs to a stale capability generation".to_string());
            }
            persisted
                .approvals
                .retain(|existing| existing.scope != record.scope);
            persisted
                .approvals
                .retain(|existing| existing.scope.capability_generation == local_generation);
            persisted.approvals.push(record.clone());
            save_state(&self.path, &persisted)?;
            state.persisted = persisted;
            Ok(())
        })?;
        Ok(ExecutionPermit::new(
            scope,
            tool_call_id,
            now + Duration::minutes(5),
            receipt_id,
            provenance,
        ))
    }

    pub(super) fn take_approval(
        &self,
        scope: &ApprovalScope,
        tool_call_id: &str,
    ) -> Result<Option<ExecutionPermit>, String> {
        let now = Utc::now();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if self.path.as_os_str().is_empty() {
            return Ok(take_session_approval(&mut state, scope, tool_call_id, now));
        }
        let persisted_scope = scope.without_session();
        with_store_lock(&self.path, || {
            let mut persisted = load_state(&self.path)?;
            let local_generation = self.capability_generation();
            let mut dirty = false;
            if persisted.capability_generation > local_generation {
                self.capability_generation
                    .store(persisted.capability_generation, Ordering::Release);
                state.session_approvals.clear();
                state.persisted = persisted;
                return Ok(None);
            }
            if local_generation > persisted.capability_generation {
                persisted.capability_generation = local_generation;
                persisted.approvals.clear();
                dirty = true;
            }
            if scope.capability_generation != local_generation {
                if dirty {
                    save_state(&self.path, &persisted)?;
                }
                state.persisted = persisted;
                return Ok(None);
            }

            if let Some(permit) = take_session_approval(&mut state, scope, tool_call_id, now) {
                if dirty {
                    save_state(&self.path, &persisted)?;
                }
                state.persisted = persisted;
                return Ok(Some(permit));
            }

            let before_len = persisted.approvals.len();
            persisted
                .approvals
                .retain(|record| record.expires_at > now && record.remaining_uses > 0);
            dirty |= persisted.approvals.len() != before_len;
            let Some(index) = persisted
                .approvals
                .iter()
                .position(|record| record.scope == persisted_scope)
            else {
                if dirty {
                    save_state(&self.path, &persisted)?;
                }
                state.persisted = persisted;
                return Ok(None);
            };

            let (receipt_id, provenance, exhausted) = {
                let record = &mut persisted.approvals[index];
                record.remaining_uses = record.remaining_uses.saturating_sub(1);
                (
                    record.receipt_id,
                    record.provenance,
                    record.remaining_uses == 0,
                )
            };
            let permit = ExecutionPermit::new(
                scope.clone(),
                tool_call_id,
                now + Duration::minutes(5),
                receipt_id,
                provenance,
            );
            if exhausted {
                persisted.approvals.remove(index);
            }
            save_state(&self.path, &persisted)?;
            state.persisted = persisted;
            Ok(Some(permit))
        })
    }

    pub(super) fn validate_permit_scope(
        &self,
        permit: &ExecutionPermit,
        resolved: &ResolvedEffect,
        arguments: &Value,
        session_id: Option<&str>,
    ) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.path.as_os_str().is_empty() {
            let expected = self.scope_for(resolved, arguments, session_id);
            let denied = state
                .session_denials
                .iter()
                .any(|denial| exact_denial_scope_matches(&denial.scope, &expected));
            let outcome = if denied {
                Err("execution permit is blocked by an exact denial".to_string())
            } else {
                permit.consume_for(&expected)
            };
            drop(state);
            return outcome;
        }

        let outcome = with_store_lock(&self.path, || {
            let mut persisted = load_state(&self.path)?;
            let local_generation = self.capability_generation();
            if persisted.capability_generation > local_generation {
                self.capability_generation
                    .store(persisted.capability_generation, Ordering::Release);
                state.session_approvals.clear();
            } else if local_generation > persisted.capability_generation {
                persisted.capability_generation = local_generation;
                persisted.approvals.clear();
                save_state(&self.path, &persisted)?;
            }

            let expected = self.scope_for(resolved, arguments, session_id);
            let denied = state
                .session_denials
                .iter()
                .chain(persisted.exact_denials.iter())
                .any(|denial| exact_denial_scope_matches(&denial.scope, &expected));
            state.persisted = persisted;
            if denied {
                return Err("execution permit is blocked by an exact denial".to_string());
            }
            permit.consume_for(&expected)
        });
        drop(state);
        outcome
    }
}

fn take_session_approval(
    state: &mut RuntimeApprovalState,
    scope: &ApprovalScope,
    tool_call_id: &str,
    now: DateTime<Utc>,
) -> Option<ExecutionPermit> {
    state
        .session_approvals
        .retain(|record| record.expires_at > now && record.remaining_uses > 0);
    let record = state
        .session_approvals
        .iter_mut()
        .find(|record| record.scope == *scope)?;
    record.remaining_uses = record.remaining_uses.saturating_sub(1);
    Some(ExecutionPermit::new(
        scope.clone(),
        tool_call_id,
        now + Duration::minutes(5),
        record.receipt_id,
        record.provenance,
    ))
}

fn exact_denial_scope_matches(denial: &ApprovalScope, request: &ApprovalScope) -> bool {
    denial.actor_id == request.actor_id
        && denial.workspace_digest == request.workspace_digest
        && denial.workspace_generation == request.workspace_generation
        && (denial.session_id.is_none() || denial.session_id == request.session_id)
        && denial.tool == request.tool
        && denial.effect == request.effect
        && denial.operation == request.operation
        && denial.target_digest == request.target_digest
        && denial.arguments_digest == request.arguments_digest
}

/// Opaque one-use authority for one exact tool call.
pub struct ExecutionPermit {
    schema_version: u32,
    receipt_id: Uuid,
    scope: Box<ApprovalScope>,
    tool_call_id: Box<str>,
    expires_at: DateTime<Utc>,
    provenance: ApprovalProvenance,
    consumed: AtomicBool,
}

/// Decision returned by a bounded local-operation cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalApprovalDecision {
    Allowed,
    Denied,
}

#[derive(Debug, Clone)]
struct LocalApprovalRecord {
    operation_digest: String,
    details_digest: String,
    workspace_generation: u64,
    capability_generation: u64,
    expires_at: DateTime<Utc>,
    remaining_uses: u32,
    decision: LocalApprovalDecision,
    provenance: ApprovalProvenance,
}

/// Exact, expiring cache for host-side operations that do not enter the tool
/// registry (for example a user-entered legacy REPL shell command).
#[derive(Debug)]
pub struct LocalApprovalCache {
    binding: ApprovalBinding,
    capability_generation: u64,
    records: Vec<LocalApprovalRecord>,
}

impl Default for LocalApprovalCache {
    fn default() -> Self {
        Self::new(ApprovalBinding::current())
    }
}

impl LocalApprovalCache {
    #[must_use]
    pub const fn new(binding: ApprovalBinding) -> Self {
        Self {
            binding,
            capability_generation: 1,
            records: Vec::new(),
        }
    }

    /// Construct a cache bound to one exact run's workspace generation.
    #[must_use]
    pub fn for_run(run: &crate::tools::ToolRunContext) -> Self {
        Self::new(ApprovalBinding::for_run(run))
    }

    /// Consume one matching allow use or return the matching exact denial.
    pub fn decision(&mut self, operation: &str, details: &str) -> Option<LocalApprovalDecision> {
        let now = Utc::now();
        let operation_digest = digest_text(operation);
        let details_digest = digest_text(&normalize_local_details(details));
        let workspace_generation = self.binding.workspace_generation();
        self.records.retain(|record| {
            record.expires_at > now
                && (record.decision == LocalApprovalDecision::Denied || record.remaining_uses > 0)
        });
        let record = self.records.iter_mut().find(|record| {
            record.operation_digest == operation_digest
                && record.details_digest == details_digest
                && record.workspace_generation == workspace_generation
                && (record.decision == LocalApprovalDecision::Denied
                    || record.capability_generation == self.capability_generation)
        })?;
        if record.decision == LocalApprovalDecision::Allowed {
            record.remaining_uses = record.remaining_uses.saturating_sub(1);
        }
        tracing::info!(
            target: "openclaudia::permissions",
            event = "local_approval_cache_decision",
            operation_digest = %operation_digest,
            details_digest = %details_digest,
            decision = ?record.decision,
            provenance = record.provenance.as_str(),
            "Bounded exact local approval cache matched"
        );
        Some(record.decision)
    }

    pub fn remember_allowed(
        &mut self,
        operation: &str,
        details: &str,
        provenance: ApprovalProvenance,
    ) {
        self.remember(
            operation,
            details,
            LocalApprovalDecision::Allowed,
            SESSION_APPROVAL_USES.saturating_sub(1),
            provenance,
        );
    }

    pub fn remember_denied(
        &mut self,
        operation: &str,
        details: &str,
        provenance: ApprovalProvenance,
    ) {
        self.capability_generation = self.capability_generation.saturating_add(1);
        self.remember(
            operation,
            details,
            LocalApprovalDecision::Denied,
            0,
            provenance,
        );
    }

    fn remember(
        &mut self,
        operation: &str,
        details: &str,
        decision: LocalApprovalDecision,
        remaining_uses: u32,
        provenance: ApprovalProvenance,
    ) {
        let operation_digest = digest_text(operation);
        let details_digest = digest_text(&normalize_local_details(details));
        let workspace_generation = self.binding.workspace_generation();
        self.records.retain(|record| {
            record.operation_digest != operation_digest
                || record.details_digest != details_digest
                || record.workspace_generation != workspace_generation
        });
        if self.records.len() >= MAX_LOCAL_APPROVALS {
            let evict = self
                .records
                .iter()
                .position(|record| record.decision == LocalApprovalDecision::Allowed)
                .unwrap_or(0);
            self.records.remove(evict);
        }
        self.records.push(LocalApprovalRecord {
            operation_digest,
            details_digest,
            workspace_generation,
            capability_generation: self.capability_generation,
            expires_at: Utc::now() + Duration::hours(SESSION_APPROVAL_HOURS),
            remaining_uses,
            decision,
            provenance,
        });
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

fn normalize_local_details(details: &str) -> String {
    serde_json::from_str::<Value>(details)
        .map_or_else(|_| details.to_string(), |value| canonical_json(&value))
}

impl ExecutionPermit {
    fn new(
        scope: ApprovalScope,
        tool_call_id: &str,
        expires_at: DateTime<Utc>,
        receipt_id: Uuid,
        provenance: ApprovalProvenance,
    ) -> Self {
        Self {
            schema_version: APPROVAL_RECEIPT_SCHEMA_VERSION,
            receipt_id,
            scope: Box::new(scope),
            tool_call_id: tool_call_id.into(),
            expires_at,
            provenance,
            consumed: AtomicBool::new(false),
        }
    }

    fn consume_for(&self, expected: &ApprovalScope) -> Result<(), String> {
        if self.schema_version != APPROVAL_RECEIPT_SCHEMA_VERSION {
            return Err("execution permit schema is unsupported".to_string());
        }
        if self.expires_at <= Utc::now() {
            return Err("execution permit expired".to_string());
        }
        if self.scope.as_ref() != expected {
            return Err(
                "execution permit does not match this actor/workspace/tool invocation".to_string(),
            );
        }
        if self.consumed.swap(true, Ordering::AcqRel) {
            return Err("execution permit was already consumed".to_string());
        }
        tracing::info!(
            target: "openclaudia::permissions",
            event = "approval_permit_consumed",
            receipt_id = %self.receipt_id,
            scope_digest = %self.scope.trace_id(),
            tool = %self.scope.tool,
            effect = %self.scope.effect,
            provenance = self.provenance.as_str(),
            "Exact approval permit consumed"
        );
        Ok(())
    }

    pub(super) fn matches_call_id(&self, call: &ToolCall) -> bool {
        self.tool_call_id.as_ref() == call.id
    }

    /// Redacted stable identifier for tests and audit correlation.
    #[must_use]
    pub const fn receipt_id(&self) -> Uuid {
        self.receipt_id
    }
}

impl fmt::Debug for ExecutionPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionPermit")
            .field("schema_version", &self.schema_version)
            .field("receipt_id", &self.receipt_id)
            .field("scope_digest", &self.scope.trace_id())
            .field("expires_at", &self.expires_at)
            .field("provenance", &self.provenance)
            .field("consumed", &self.consumed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

fn load_state(path: &Path) -> Result<PersistedPermissionState, String> {
    if !path.exists() {
        return Ok(PersistedPermissionState::default());
    }
    let file = open_no_follow(path)?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("permission store is not a regular file".to_string());
    }
    if metadata.len() > MAX_PERMISSION_STORE_BYTES {
        return Err(format!(
            "permission store exceeds {MAX_PERMISSION_STORE_BYTES} bytes"
        ));
    }
    let mut content = String::new();
    file.take(MAX_PERMISSION_STORE_BYTES.saturating_add(1))
        .read_to_string(&mut content)
        .map_err(|error| error.to_string())?;
    if content.len() as u64 > MAX_PERMISSION_STORE_BYTES {
        return Err("permission store exceeded the bounded read limit".to_string());
    }

    if let Ok(legacy) = serde_json::from_str::<Vec<PermissionRule>>(&content) {
        let denied = legacy
            .into_iter()
            .filter(|rule| rule.decision == PermissionDecision::Deny)
            .collect();
        tracing::warn!(
            path_digest = %digest_text(&path.to_string_lossy()),
            "Legacy broad permission allows were ignored during safe migration"
        );
        return Ok(PersistedPermissionState {
            denials: denied,
            ..PersistedPermissionState::default()
        });
    }

    let state: PersistedPermissionState =
        serde_json::from_str(&content).map_err(|error| error.to_string())?;
    validate_state(&state)?;
    Ok(state)
}

fn validate_state(state: &PersistedPermissionState) -> Result<(), String> {
    if state.schema_version != APPROVAL_RECEIPT_SCHEMA_VERSION {
        return Err(format!(
            "unsupported approval schema {}; expected {APPROVAL_RECEIPT_SCHEMA_VERSION}",
            state.schema_version
        ));
    }
    if state.capability_generation == 0 {
        return Err("capability generation must be non-zero".to_string());
    }
    if state.approvals.len() > MAX_PERSISTED_APPROVALS
        || state.denials.len() > MAX_PERSISTED_DENIALS
        || state.exact_denials.len() > MAX_PERSISTED_DENIALS
    {
        return Err("permission store contains too many records".to_string());
    }
    let now = Utc::now();
    for approval in &state.approvals {
        validate_scope(&approval.scope)?;
        if approval.remaining_uses == 0
            || approval.remaining_uses > PERSISTED_APPROVAL_USES
            || approval.issued_at > now
            || approval.expires_at <= approval.issued_at
            || approval.expires_at - approval.issued_at > Duration::days(PERSISTED_APPROVAL_DAYS)
        {
            return Err("approval has invalid expiry/use bounds".to_string());
        }
    }
    for denial in &state.exact_denials {
        validate_scope(&denial.scope)?;
    }
    for denial in &state.denials {
        if denial.decision != PermissionDecision::Deny
            || denial.tool.len() > MAX_STRING_BYTES
            || denial.pattern.len() > MAX_STRING_BYTES
        {
            return Err("persisted denial record is invalid or overlong".to_string());
        }
    }
    Ok(())
}

fn validate_scope(scope: &ApprovalScope) -> Result<(), String> {
    let strings = [
        &scope.actor_id,
        &scope.workspace_digest,
        &scope.tool,
        &scope.effect,
        &scope.target_digest,
        &scope.arguments_digest,
    ];
    if strings
        .into_iter()
        .any(|value| value.is_empty() || value.len() > MAX_STRING_BYTES)
        || scope
            .session_id
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_STRING_BYTES)
        || scope
            .operation
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_STRING_BYTES)
        || scope.workspace_generation == 0
        || scope.capability_generation == 0
    {
        return Err("approval scope contains an invalid binding".to_string());
    }
    Ok(())
}

fn open_no_follow(path: &Path) -> Result<File, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err("permission store symlinks are not accepted".to_string());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        // A persisted authority file writable by another OS principal is not
        // trusted input, even when its pathname is under the user config dir.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err(
                "permission store must be owned by the effective user and not group/world writable"
                    .to_string(),
            );
        }
    }
    Ok(file)
}

fn with_store_lock<T>(
    path: &Path,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let parent = path
        .parent()
        .ok_or_else(|| "permission store has no parent directory".to_string())?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    prepare_store_parent(parent)?;

    let file_name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| "permission store file name is not valid UTF-8".to_string())?;
    let lock_path = parent.join(format!(".{file_name}.lock"));
    if let Ok(metadata) = fs::symlink_metadata(&lock_path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("permission store lock is not a regular non-symlink file".to_string());
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = options
        .open(&lock_path)
        .map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let metadata = lock.metadata().map_err(|error| error.to_string())?;
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err("permission store lock is not owned by the effective user".to_string());
        }
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    lock.lock().map_err(|error| error.to_string())?;
    let result = operation();
    let unlock = lock.unlock().map_err(|error| error.to_string());
    match (result, unlock) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(format!("permission store lock release failed: {error}")),
    }
}

fn save_state(path: &Path, state: &PersistedPermissionState) -> Result<(), String> {
    validate_state(state)?;
    let parent = path
        .parent()
        .ok_or_else(|| "permission store has no parent directory".to_string())?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    prepare_store_parent(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("permission store target is not a regular non-symlink file".to_string());
        }
    }

    let file_name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| "permission store file name is not valid UTF-8".to_string())?;
    let temp = parent.join(format!(".{file_name}.{}.tmp", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temp).map_err(|error| error.to_string())?;
    let result = (|| {
        let encoded = serde_json::to_vec_pretty(state).map_err(|error| error.to_string())?;
        if encoded.len() as u64 > MAX_PERMISSION_STORE_BYTES {
            return Err("permission store serialization exceeds its size limit".to_string());
        }
        file.write_all(&encoded)
            .map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        crate::file_error::replace_file_atomic(&temp, path).map_err(|error| error.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|error| error.to_string())?;
        }
        sync_parent_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> Result<(), String> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
const fn sync_parent_directory(_parent: &Path) -> Result<(), String> {
    // Rust's portable File API cannot open directories on every supported
    // platform (notably Windows). The file itself was synced before the
    // atomic rename, so unsupported hosts stop at that portable durability
    // boundary instead of reporting a false write failure after success.
    Ok(())
}

fn prepare_store_parent(parent: &Path) -> Result<(), String> {
    #[cfg(unix)]
    let existed = parent.exists();
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    reject_symlink_path(parent)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if !existed {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
        }
        let metadata = fs::metadata(parent).map_err(|error| error.to_string())?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err(
                "permission store parent must be owned by the effective user and not group/world writable"
                    .to_string(),
            );
        }
    }

    Ok(())
}

fn reject_symlink_path(path: &Path) -> Result<(), String> {
    let mut walked = PathBuf::new();
    for component in path.components() {
        walked.push(component.as_os_str());
        if walked.as_os_str().is_empty() {
            continue;
        }
        let metadata = fs::symlink_metadata(&walked).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "permission store parent contains symlink component: {}",
                walked.display()
            ));
        }
    }
    Ok(())
}

/// Canonical trusted approval path for production composition roots.
#[must_use]
pub fn trusted_permission_store_path() -> PathBuf {
    dirs::config_dir()
        .or_else(|| dirs::home_dir().map(|home| home.join(".config")))
        .map(|base| base.join("openclaudia").join("permissions-v1.json"))
        .unwrap_or_default()
}

/// Redacted bounded summary for `/permissions` and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermissionStoreSummary {
    pub approval_count: usize,
    pub denial_count: usize,
    pub capability_generation: u64,
}

/// Inspect a permission store without exposing raw commands, paths, URLs, or
/// glob patterns.
///
/// # Errors
///
/// Returns an error when the store is untrusted, malformed, oversized, or
/// uses an unsupported schema version.
pub fn inspect_permission_store(path: &Path) -> Result<Option<PermissionStoreSummary>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let state = load_state(path)?;
    let now = Utc::now();
    Ok(Some(PermissionStoreSummary {
        approval_count: state
            .approvals
            .iter()
            .filter(|record| record.expires_at > now && record.remaining_uses > 0)
            .count(),
        denial_count: state.denials.len() + state.exact_denials.len(),
        capability_generation: state.capability_generation,
    }))
}
