//! Session state types: token usage, turn metrics, plan mode.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;
use std::fs::File;
use std::path::{Path, PathBuf};

use super::Session;
use super::SessionMode;

/// Token usage from a single API response
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    /// Input tokens billed
    pub input_tokens: u64,
    /// Output tokens billed
    pub output_tokens: u64,
    /// Tokens read from cache (reduced cost)
    pub cache_read_tokens: u64,
    /// Tokens written to cache
    pub cache_write_tokens: u64,
}

impl TokenUsage {
    /// Total tokens (input + output)
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.input_tokens + self.output_tokens
    }

    /// Accumulate usage from another `TokenUsage`
    pub const fn accumulate(&mut self, other: &Self) {
        self.input_tokens += other.input_tokens;
        self.output_tokens += other.output_tokens;
        self.cache_read_tokens += other.cache_read_tokens;
        self.cache_write_tokens += other.cache_write_tokens;
    }
}

/// Extra provider usage metadata not measured in tokens.
///
/// Threaded **alongside** [`TokenUsage`] so the token struct, which is
/// constructed at many call sites including those locked against
/// modification (e.g. `pipeline.rs`), stays binary-compatible.
///
/// Defaults to all-zero so callers that have nothing to report can
/// pass `&UsageExtras::default()` (or use the
/// [`UsageExtras::ZERO`] constant).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageExtras {}

impl UsageExtras {
    /// All-zero extras — handy when a call site has no extra metadata
    /// to report but [`crate::session::pricing::calculate_cost_full`]
    /// still requires an extras argument.
    pub const ZERO: Self = Self {};

    /// Accumulate one set of extras into another.
    pub const fn accumulate(&mut self, _other: &Self) {
        // Reserved for future non-token metadata. Browser-backed web
        // search is intentionally free and is not accounted here.
    }
}

/// Metrics for a single API turn (round-trip)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnMetrics {
    /// Turn number within the session
    pub turn_number: u64,
    /// Pre-request estimated input tokens (from our estimator)
    pub estimated_input_tokens: usize,
    /// Actual usage reported by the provider (if available)
    pub actual_usage: Option<TokenUsage>,
    /// Tokens consumed by injected context (hooks, session, MCP tools, plugins)
    pub injected_context_tokens: usize,
    /// Tokens consumed by system prompt
    pub system_prompt_tokens: usize,
    /// Tokens consumed by tool definitions
    pub tool_def_tokens: usize,
    /// When this turn occurred
    pub timestamp: DateTime<Utc>,
    /// VDD: number of adversarial iterations this turn (if VDD active)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vdd_iterations: Option<u32>,
    /// VDD: genuine findings count
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vdd_genuine_findings: Option<u32>,
    /// VDD: false positive count
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vdd_false_positives: Option<u32>,
    /// VDD: tokens used by adversary model
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vdd_adversary_tokens: Option<TokenUsage>,
    /// VDD: whether the loop converged
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vdd_converged: Option<bool>,
}

/// Plan mode state for the agent session.
///
/// # Security: TOCTOU-safe plan-file identity (crosslink #334)
///
/// `plan_realpath` is the **canonical** absolute path of the plan file,
/// computed **once** at plan-mode entry via [`PlanModeState::enter`]. All
/// subsequent allow-checks compare against this stored realpath -- the
/// path is never re-resolved against the current working directory or
/// filesystem state at check time, which closes the cwd-swap and
/// symlink-swap TOCTOU windows the previous implementation suffered from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanModeState {
    /// Whether plan mode is currently active
    pub active: bool,
    /// Path the user/agent originally requested for the plan file.
    /// Kept for display / editor invocation; **not** used for security
    /// comparisons -- use [`Self::plan_realpath`] for that.
    pub plan_file: PathBuf,
    /// Canonical absolute path of the plan file, resolved exactly once at
    /// plan-mode entry. Allow-checks for `write_file` compare the
    /// canonical target against this value. Must point to a regular file
    /// (not a symlink, directory, or special file).
    pub plan_realpath: PathBuf,
    /// Allowed prompts when exiting plan mode
    pub allowed_prompts: Vec<AllowedPrompt>,
    /// Snapshot of the agent mode active when plan mode was entered, so
    /// `exit_plan_mode` can restore the prior mode instead of unconditionally
    /// falling back to `Build` (crosslink #618).
    ///
    /// Encoded as a lowercase token (`"build"`, `"extend"`, `"refactor"`,
    /// `"plan"`) so this module stays free of a dependency on the binary-side
    /// `AgentMode` enum. `None` means "the caller did not capture a prior
    /// mode" and the legacy `Build` fallback applies, preserving the on-disk
    /// shape of sessions written before #618.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_mode: Option<String>,
}

/// Error returned when plan-mode entry fails to pin a safe plan-file
/// identity. Each variant carries the path that triggered the failure so
/// the REPL can surface an actionable error message.
#[derive(Debug, thiserror::Error)]
pub enum PlanModeEntryError {
    /// The plan file does not exist on disk.
    #[error("plan file does not exist: {path}")]
    PlanFileMissing {
        /// The path that was checked.
        path: PathBuf,
    },
    /// The plan file path resolves through a symlink.
    #[error("plan file path is a symlink (not allowed): {path}")]
    PlanFileIsSymlink {
        /// The path that resolved to a symlink.
        path: PathBuf,
    },
    /// The plan file is not a regular file (directory, FIFO, socket, etc).
    #[error("plan file is not a regular file: {path}")]
    PlanFileNotRegular {
        /// The path that pointed at a non-regular file.
        path: PathBuf,
    },
    /// The plan file could not be canonicalized.
    #[error("failed to canonicalize plan file {path}: {source}")]
    CanonicalizeFailed {
        /// The path that failed to canonicalize.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The plan file could not be opened for the FD-based identity check.
    #[error("failed to open plan file {path}: {source}")]
    OpenFailed {
        /// The path that failed to open.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

impl PlanModeState {
    /// Enter plan mode by pinning a TOCTOU-safe identity for `plan_file`.
    ///
    /// Performs symlink-metadata + `File::open` + FD-based metadata +
    /// canonicalize. Refuses on any failure -- the previous fallback to
    /// string-based path comparison after a `current_dir()` lookup is
    /// the exact bypass crosslink #334 closes.
    ///
    /// # Errors
    ///
    /// Returns [`PlanModeEntryError`] if any of the four steps fails.
    pub fn enter(plan_file: PathBuf) -> Result<Self, PlanModeEntryError> {
        Self::enter_with_previous_mode(plan_file, None)
    }

    /// Enter plan mode while snapshotting the caller's prior agent mode
    /// (crosslink #618).
    ///
    /// `previous_mode` is the lowercase token form of the mode that was
    /// active before the call (e.g. `"build"`, `"extend"`, `"refactor"`).
    /// Pass `None` to preserve the pre-#618 behaviour of unconditionally
    /// restoring to `Build` on exit.
    ///
    /// # Errors
    ///
    /// Same as [`Self::enter`].
    pub fn enter_with_previous_mode(
        plan_file: PathBuf,
        previous_mode: Option<String>,
    ) -> Result<Self, PlanModeEntryError> {
        let lmeta = match std::fs::symlink_metadata(&plan_file) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(PlanModeEntryError::PlanFileMissing { path: plan_file });
            }
            Err(e) => {
                return Err(PlanModeEntryError::OpenFailed {
                    path: plan_file,
                    source: e,
                });
            }
        };
        if lmeta.file_type().is_symlink() {
            return Err(PlanModeEntryError::PlanFileIsSymlink { path: plan_file });
        }

        let f = File::open(&plan_file).map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                PlanModeEntryError::PlanFileMissing {
                    path: plan_file.clone(),
                }
            } else {
                PlanModeEntryError::OpenFailed {
                    path: plan_file.clone(),
                    source,
                }
            }
        })?;

        let fmeta = f
            .metadata()
            .map_err(|source| PlanModeEntryError::OpenFailed {
                path: plan_file.clone(),
                source,
            })?;
        if !fmeta.file_type().is_file() {
            return Err(PlanModeEntryError::PlanFileNotRegular { path: plan_file });
        }

        let plan_realpath = std::fs::canonicalize(&plan_file).map_err(|source| {
            PlanModeEntryError::CanonicalizeFailed {
                path: plan_file.clone(),
                source,
            }
        })?;

        drop(f);

        Ok(Self {
            active: true,
            plan_file,
            plan_realpath,
            allowed_prompts: Vec::new(),
            previous_mode,
        })
    }
}

/// Install the canonical interactive plan state and runtime capability.
///
/// CLI and TUI entrypoints share this host-owned transition so neither can
/// display a Plan label without a pinned plan artifact and enforced mode.
///
/// # Errors
///
/// Returns an error when the run cannot create or pin its exact plan file, or
/// when the runtime mode transition cannot be installed.
pub fn install_interactive_plan_mode(
    run: &crate::tools::ToolRunContext,
    chat_session: &crate::state::Session,
) -> Result<PathBuf, String> {
    run.require(crate::tools::ToolResource::WorkspaceWrite)
        .map_err(|error| format!("plan mode requires workspace write capability: {error}"))?;
    let plan_file = run.agent_plan_file().to_path_buf();
    if chat_session.agent_mode() == crate::state::AgentMode::Plan {
        if let Some(existing) = chat_session.inspect_state(|state| {
            state
                .conversation
                .plan_mode
                .as_ref()
                .filter(|plan| plan.active)
                .cloned()
        }) {
            if existing.plan_realpath != plan_file {
                return Err("active plan state belongs to a different run capability".to_string());
            }
            if run.runtime_mode().class != crate::modes::RuntimeModeClass::Plan {
                run.transition_runtime_mode(crate::modes::RuntimeMode::Plan)?;
            }
            return Ok(plan_file);
        }
    }
    if !plan_file.exists() {
        let header = format!(
            "# Implementation Plan\n\nSession: {}\nCreated: {}\n\n## Plan\n\n",
            chat_session.id(),
            chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")
        );
        crate::tools::create_capability_text_file(run, &plan_file.to_string_lossy(), &header)
            .map_err(|error| format!("failed to create plan file: {error}"))?;
    }

    let current_mode = chat_session.agent_mode();
    let previous_mode = (current_mode != crate::state::AgentMode::Plan)
        .then(|| current_mode.as_token().to_string());
    let plan_state = PlanModeState::enter_with_previous_mode(plan_file.clone(), previous_mode)
        .map_err(|error| format!("plan file identity pin failed: {error}"))?;

    run.transition_runtime_mode(crate::modes::RuntimeMode::Plan)?;
    chat_session.update_state(|state, _| state.conversation.plan_mode = Some(plan_state));
    chat_session.set_agent_mode(crate::state::AgentMode::Plan);
    Ok(plan_file)
}

/// Exact plan bytes displayed to a user before an approval decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedPlanApproval {
    plan_content: String,
    plan_digest: String,
    plan_realpath: PathBuf,
    previous_mode: Option<String>,
    runtime_mode_generation: u64,
}

impl PreparedPlanApproval {
    /// Plan text the frontend must display for approval.
    #[must_use]
    pub fn plan_content(&self) -> &str {
        &self.plan_content
    }

    /// SHA-256 digest of the exact displayed bytes.
    #[must_use]
    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }

    /// Runtime mode generation under which the proposal was prepared.
    #[must_use]
    pub const fn runtime_mode_generation(&self) -> u64 {
        self.runtime_mode_generation
    }
}

/// Durable task-graph binding created by an approved plan transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedPlanReceipt {
    /// Stable task representing this plan lifecycle.
    pub task_id: String,
    /// Canonical task-graph generation containing the binding.
    pub task_graph_generation: u64,
    /// Digest of the exact approved plan bytes.
    pub plan_digest: String,
    /// Runtime capability generation restored after approval.
    pub runtime_mode_generation: u64,
    /// Exact approved-plan context message to append after the resolving tool
    /// result. Frontends own transcript ordering at that protocol boundary.
    pub context_message: serde_json::Value,
}

fn approved_plan_digest(plan_content: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = Sha256::digest(plan_content.as_bytes());
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn restored_plan_agent_mode(previous_mode: Option<&str>) -> crate::state::AgentMode {
    previous_mode.map_or(
        crate::state::AgentMode::Build,
        crate::state::AgentMode::from_token,
    )
}

/// Read and bind the exact plan bytes a frontend will present to the user.
///
/// # Errors
///
/// Returns an error unless the session and run are in the same active plan
/// generation and the pinned plan artifact can be read through the run.
pub fn prepare_interactive_plan_approval(
    run: &crate::tools::ToolRunContext,
    chat_session: &crate::state::Session,
) -> Result<PreparedPlanApproval, String> {
    let runtime_mode = run.runtime_mode();
    if runtime_mode.class != crate::modes::RuntimeModeClass::Plan {
        return Err("runtime capability is not in plan mode".to_string());
    }
    let plan_state = chat_session
        .inspect_state(|state| state.conversation.plan_mode.clone())
        .filter(|state| state.active)
        .ok_or_else(|| "session is not in active plan mode".to_string())?;
    if plan_state.plan_realpath != run.agent_plan_file() {
        return Err("active plan artifact belongs to a different run capability".to_string());
    }
    let (_, plan_content) = crate::tools::read_capability_text_attachment(
        run,
        &plan_state.plan_realpath.to_string_lossy(),
    )
    .map_err(|error| format!("failed to read the pinned plan artifact: {error}"))?;
    Ok(PreparedPlanApproval {
        plan_digest: approved_plan_digest(&plan_content),
        plan_content,
        plan_realpath: plan_state.plan_realpath,
        previous_mode: plan_state.previous_mode,
        runtime_mode_generation: runtime_mode.generation,
    })
}

/// Commit a user decision for exactly one prepared plan artifact.
///
/// The plan is re-read before publication. A changed plan, replaced session
/// state, or changed runtime generation leaves plan mode active and grants no
/// wider capability. The canonical task binding is published before runtime
/// capabilities are restored; session state is then updated in one closure.
///
/// # Errors
///
/// Returns an error on stale plan bytes/state, task-graph publication failure,
/// or an invalid runtime restoration profile.
pub fn commit_interactive_plan_approval(
    run: &crate::tools::ToolRunContext,
    chat_session: &crate::state::Session,
    task_manager: &std::sync::Mutex<crate::session::TaskManager>,
    prepared: &PreparedPlanApproval,
    allowed_prompts: &[crate::tools::ToolAllowedPrompt],
    restore_mode: crate::modes::RuntimeMode,
) -> Result<ApprovedPlanReceipt, String> {
    let runtime_mode = run.runtime_mode();
    if runtime_mode.class != crate::modes::RuntimeModeClass::Plan
        || runtime_mode.generation != prepared.runtime_mode_generation
    {
        return Err("plan approval is stale for the current runtime mode generation".to_string());
    }
    let current_plan_state = chat_session
        .inspect_state(|state| state.conversation.plan_mode.clone())
        .filter(|state| state.active)
        .ok_or_else(|| "session is no longer in active plan mode".to_string())?;
    if current_plan_state.plan_realpath != prepared.plan_realpath
        || current_plan_state.previous_mode != prepared.previous_mode
    {
        return Err("plan approval is stale for the current session plan state".to_string());
    }
    let (_, current_content) = crate::tools::read_capability_text_attachment(
        run,
        &prepared.plan_realpath.to_string_lossy(),
    )
    .map_err(|error| format!("failed to re-read the pinned plan artifact: {error}"))?;
    if approved_plan_digest(&current_content) != prepared.plan_digest
        || current_content != prepared.plan_content
    {
        return Err("plan artifact changed after it was displayed for approval".to_string());
    }

    // Validate before publishing the durable task binding. The subsequent
    // transition can then fail only if the u64 generation space is exhausted.
    run.validate_runtime_mode_transition(&restore_mode)?;
    let plan_id = format!("plan-{}", chat_session.id());
    let mut manager = task_manager
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let task_id = manager
        .reconcile_approved_plan(&plan_id, prepared.plan_digest.clone())?
        .id
        .clone();
    let task_graph_generation = manager.generation().get();
    drop(manager);

    let restored_runtime = run.transition_runtime_mode(restore_mode)?;
    let restored_agent_mode = restored_plan_agent_mode(prepared.previous_mode.as_deref());
    let allowed_operations = if allowed_prompts.is_empty() {
        String::new()
    } else {
        format!(
            "Allowed operations:\n{}",
            allowed_prompts
                .iter()
                .map(|prompt| format!("- {}: {}", prompt.tool, prompt.prompt))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };
    let plan_content = prepared.plan_content.clone();
    let plan_digest = prepared.plan_digest.clone();
    let context_message = serde_json::json!({
        "role": "system",
        "content": format!(
            "[Approved Implementation Plan]\nThe user has approved the following plan. Execute it step by step.\n\n{}\n\n{}",
            plan_content,
            allowed_operations
        ),
        "metadata": {
            "openclaudia_context_source": "user_approved_plan",
            "canonical_task_id": task_id,
            "canonical_task_graph_generation": task_graph_generation,
            "approved_plan_digest": plan_digest
        }
    });
    chat_session.update_state(|state, _| {
        state.modes.agent_mode = restored_agent_mode;
        state.conversation.plan_mode = None;
        state.conversation.approved_plan = Some(plan_content.clone());
    });

    Ok(ApprovedPlanReceipt {
        task_id,
        task_graph_generation,
        plan_digest: prepared.plan_digest.clone(),
        runtime_mode_generation: restored_runtime.generation,
        context_message,
    })
}

/// An allowed prompt constraint for plan mode exit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedPrompt {
    /// Tool name this prompt applies to
    pub tool: String,
    /// Prompt/description for the allowed operation
    pub prompt: String,
}

/// Common tools displayed when plan mode starts.
///
/// This is explanatory UI, not the authorization source of truth. Runtime
/// admission uses the mandatory effect declaration for the concrete call so
/// newly registered read-only tools do not require a second hand-maintained
/// list. Opaque, networked, orchestration, and mutating families remain denied.
///
/// `enter_plan_mode` / `exit_plan_mode` are special and handled inline in
/// [`is_tool_allowed_in_plan_mode`]; they are not in this list because they
/// affect plan-mode state itself rather than executing under plan-mode
/// restrictions.
pub const PLAN_MODE_ALLOWED_TOOLS: &[&str] = &[
    "read_file",
    "grounding_context",
    "list_files",
    "glob",
    "grep",
    "tool_search",
    "ask_user_question",
    "memory_search",
    "memory_list",
    "memory_learning_status",
    "memory_conflicts",
    "memory_source_status",
];

/// MCP tool name prefix.
///
/// MCP servers register tools as `mcp__<server>__<tool>` (see `src/mcp.rs`).
/// MCP tools are hard-denied in plan mode by default -- their side-effects
/// are opaque to the harness and cannot be statically classified as
/// read-only.
pub const MCP_TOOL_PREFIX: &str = "mcp__";

/// Plugin tool name prefix.
///
/// Plugin-contributed tools follow `plugin__<plugin>__<tool>`. Hard-denied
/// in plan mode by default for the same reason as MCP tools.
pub const PLUGIN_TOOL_PREFIX: &str = "plugin__";

/// Compatibility policy for plan-mode tool gating.
///
/// MCP and plugin tools remain denied by the compiled runtime profile. The
/// fields are retained for configuration compatibility; setting them does not
/// widen the mode's capabilities.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlanModePolicy {
    /// Retained legacy setting; the runtime profile still denies MCP tools.
    pub allow_mcp_tools: bool,
    /// Retained legacy setting; the runtime profile still denies plugin tools.
    pub allow_plugin_tools: bool,
}

/// Check if a concrete tool call is allowed in plan mode.
///
/// Thin wrapper over [`is_tool_allowed_in_plan_mode_with_policy`] using
/// the default policy ([`PlanModePolicy::default`]), which denies all MCP
/// and plugin tools. Existing callers keep their behaviour after the
/// crosslink #341 refactor.
///
/// # Effect-based default-deny
///
/// The previous implementation used a "not in allowlist *and* not in
/// blocklist → fall through" pattern that silently passed any name not in
/// either list (e.g. newly registered MCP tools, plugin tools) to the
/// `write_file` / `enter_plan_mode` / `exit_plan_mode` special cases and
/// only then returned `false`. While the final return was `false`, the
/// architecture invited bypass-by-shadowing and made it easy to add a new
/// branch that fails open. The new implementation collapses the decision
/// to a single explicit flow:
///
/// 1. `mcp__*` / `plugin__*` prefixes → hard-deny.
/// 2. `enter_plan_mode` / `exit_plan_mode` → allow (plan-mode markers).
/// 3. `write_file` → allow **only** if target canonicalizes to `plan_realpath`.
/// 4. Resolve the call through the mandatory effect registry.
/// 5. Allow only local observation tools admitted by the runtime profile.
///
/// # Security: TOCTOU-safe `write_file` gate (crosslink #334)
///
/// `plan_realpath` is assumed to already be canonical and is **never**
/// re-canonicalized here -- re-resolving would re-introduce the cwd-swap
/// race the entry-time pin closes.
///
/// The target is validated with the same FD-pinned pattern used at entry:
/// `symlink_metadata` (reject symlinks) then `File::open` (pin the inode)
/// then FD-based `File::metadata` (reject non-regular) then `canonicalize`
/// (compare to `plan_realpath`). Any failure is a hard refusal -- the old
/// string-comparison and `current_dir`-join fallbacks are removed.
#[must_use]
pub fn is_tool_allowed_in_plan_mode(
    tool_name: &str,
    plan_realpath: &Path,
    args: &serde_json::Value,
) -> bool {
    is_tool_allowed_in_plan_mode_with_policy(
        tool_name,
        plan_realpath,
        args,
        PlanModePolicy::default(),
    )
}

/// Policy-aware compatibility entry point. See
/// [`is_tool_allowed_in_plan_mode`] for the authoritative decision flow.
#[must_use]
pub fn is_tool_allowed_in_plan_mode_with_policy(
    tool_name: &str,
    plan_realpath: &Path,
    args: &serde_json::Value,
    policy: PlanModePolicy,
) -> bool {
    // Preserve the old configuration shape without allowing it to widen the
    // compiled mode profile. This also rejects shadow names before lookup.
    if tool_name.starts_with(MCP_TOOL_PREFIX) {
        return false;
    }
    if tool_name.starts_with(PLUGIN_TOOL_PREFIX) {
        return false;
    }
    let _ = policy;

    // Step 2: Plan-mode marker tools (always allowed -- they manage
    // plan-mode state itself, not user-facing side effects).
    if tool_name == "enter_plan_mode" || tool_name == "exit_plan_mode" {
        return true;
    }

    // Step 3: write_file special case -- only allowed when targeting the
    // pre-pinned plan file (TOCTOU-safe; see crosslink #334).
    if tool_name == "write_file" {
        let Some(path_str) = args.get("path").and_then(|v| v.as_str()) else {
            return false;
        };
        let target = Path::new(path_str);

        let Ok(lmeta) = std::fs::symlink_metadata(target) else {
            return false;
        };
        if lmeta.file_type().is_symlink() {
            return false;
        }

        let Ok(f) = File::open(target) else {
            return false;
        };

        let Ok(fmeta) = f.metadata() else {
            return false;
        };
        if !fmeta.file_type().is_file() {
            return false;
        }

        let Ok(target_canonical) = std::fs::canonicalize(target) else {
            return false;
        };

        drop(f);

        return target_canonical == plan_realpath;
    }

    // Step 4/5: mandatory effect resolution with no permissive fallback.
    crate::tools::effect::resolve_for_call(tool_name, args)
        .is_ok_and(|resolved| crate::modes::observation_tool_allowed(tool_name, resolved.effect))
}

/// Context to inject at session start based on mode
#[must_use]
pub fn get_session_context(session: &Session) -> String {
    match session.mode {
        SessionMode::Initializer => "## Session Context: Initializer Agent\n\
            \n\
            You are the first agent working on this task. Your responsibilities:\n\
            1. Understand the full scope of the work\n\
            2. Create a clear plan with actionable steps\n\
            3. Document key decisions and rationale\n\
            4. Set up any necessary project structure\n\
            5. Prepare detailed handoff notes for subsequent sessions\n\
            \n\
            Focus on establishing a solid foundation that future agents can build upon."
            .to_string(),
        SessionMode::Coding => {
            let mut context = "## Session Context: Coding Agent\n\
                \n\
                You are continuing work from a previous session. Your responsibilities:\n\
                1. Review the handoff notes from the previous session\n\
                2. Continue from where the last agent left off\n\
                3. Track your progress and decisions\n\
                4. Prepare handoff notes if you won't complete the task\n\
                \n"
            .to_string();

            if let Some(parent_id) = &session.parent_session_id {
                let _ = writeln!(context, "Previous session ID: {parent_id}");
            }

            context
        }
    }
}

#[cfg(test)]
mod plan_mode_tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn plan_agent_mode_restore_preserves_known_modes_and_defaults_unknown_tokens() {
        for mode in [
            crate::state::AgentMode::Build,
            crate::state::AgentMode::Extend,
            crate::state::AgentMode::Refactor,
        ] {
            assert_eq!(restored_plan_agent_mode(Some(mode.as_token())), mode);
        }
        assert_eq!(
            restored_plan_agent_mode(None),
            crate::state::AgentMode::Build
        );
        assert_eq!(
            restored_plan_agent_mode(Some("some_future_mode")),
            crate::state::AgentMode::Build
        );
    }

    /// Entry refuses when the plan file does not exist (#334).
    #[test]
    fn enter_refuses_nonexistent_plan_file() {
        let dir = TempDir::new().unwrap();
        let nonexistent = dir.path().join("does_not_exist.md");
        let err = PlanModeState::enter(nonexistent.clone())
            .expect_err("must refuse non-existent plan file");
        assert!(
            matches!(err, PlanModeEntryError::PlanFileMissing { ref path } if path == &nonexistent),
            "expected PlanFileMissing, got {err:?}"
        );
    }

    /// Entry refuses when the plan-file path is a symlink (#334).
    #[cfg(unix)]
    #[test]
    fn enter_refuses_symlink_at_plan_file_path() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("real.md");
        std::fs::write(&target, "# real plan\n").unwrap();
        let link = dir.path().join("plan.md");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = PlanModeState::enter(link.clone()).expect_err("must refuse symlink as plan file");
        assert!(
            matches!(err, PlanModeEntryError::PlanFileIsSymlink { ref path } if path == &link),
            "expected PlanFileIsSymlink, got {err:?}"
        );
    }

    /// Entry refuses when the plan-file path points at a directory (#334).
    #[test]
    fn enter_refuses_directory_at_plan_file_path() {
        let dir = TempDir::new().unwrap();
        let subdir = dir.path().join("plans");
        std::fs::create_dir(&subdir).unwrap();
        let err =
            PlanModeState::enter(subdir.clone()).expect_err("must refuse directory as plan file");
        match err {
            PlanModeEntryError::PlanFileNotRegular { path }
            | PlanModeEntryError::OpenFailed { path, .. } => {
                assert_eq!(path, subdir);
            }
            other => panic!("expected NotRegular or OpenFailed, got {other:?}"),
        }
    }

    /// `write_file` allow-check rejects a symlink target even when the
    /// link points at the canonical plan file (TOCTOU defence, #334).
    #[cfg(unix)]
    #[test]
    fn allow_check_rejects_symlink_target_even_pointing_at_plan_file() {
        let dir = TempDir::new().unwrap();
        let plan = dir.path().join("plan.md");
        std::fs::write(&plan, "# plan\n").unwrap();
        let state = PlanModeState::enter(plan.clone()).expect("enter must succeed");
        let evil_link = dir.path().join("evil_link.md");
        std::os::unix::fs::symlink(&plan, &evil_link).unwrap();
        let args = json!({ "path": evil_link.to_string_lossy() });
        assert!(
            !is_tool_allowed_in_plan_mode("write_file", &state.plan_realpath, &args),
            "symlink to plan file must NOT pass the allow-check (TOCTOU)"
        );
        let ok_args = json!({ "path": plan.to_string_lossy() });
        assert!(
            is_tool_allowed_in_plan_mode("write_file", &state.plan_realpath, &ok_args),
            "the real plan-file path must still be allowed after the fix"
        );
    }

    /// `write_file` allow-check refuses non-existent target paths
    /// (the documented #334 bypass): no string fallback.
    #[test]
    fn allow_check_refuses_nonexistent_target_no_string_fallback() {
        let dir = TempDir::new().unwrap();
        let plan = dir.path().join("plan.md");
        std::fs::write(&plan, "# plan\n").unwrap();
        let state = PlanModeState::enter(plan).expect("enter must succeed");
        let nonexistent = dir.path().join("ghost.md");
        let args = json!({ "path": nonexistent.to_string_lossy() });
        assert!(
            !is_tool_allowed_in_plan_mode("write_file", &state.plan_realpath, &args),
            "non-existent target must NOT silently pass (#334)"
        );
        let sibling_dir = TempDir::new().unwrap();
        let sibling_plan = sibling_dir.path().join("plan.md");
        std::fs::write(&sibling_plan, "# decoy\n").unwrap();
        let args2 = json!({ "path": sibling_plan.to_string_lossy() });
        assert!(
            !is_tool_allowed_in_plan_mode("write_file", &state.plan_realpath, &args2),
            "different file with same basename must NOT pass (#334)"
        );
    }

    /// `write_file` allow-check ignores the current working directory (#334).
    #[test]
    fn allow_check_relative_target_refused_when_not_resolvable() {
        let dir = TempDir::new().unwrap();
        let plan = dir.path().join("plan.md");
        std::fs::write(&plan, "# plan\n").unwrap();
        let state = PlanModeState::enter(plan).expect("enter must succeed");
        let args = json!({
            "path": "this_relative_path_does_not_exist_anywhere_334.md"
        });
        assert!(
            !is_tool_allowed_in_plan_mode("write_file", &state.plan_realpath, &args),
            "relative path that does not resolve must be refused without consulting cwd"
        );
    }

    /// Documented observation tools remain visible while concrete malformed
    /// calls and mutation families are refused.
    #[test]
    fn plan_profile_preserves_documented_observations_and_denies_mutations() {
        let dir = TempDir::new().unwrap();
        let plan = dir.path().join("plan.md");
        std::fs::write(&plan, "# plan\n").unwrap();
        let state = PlanModeState::enter(plan).expect("enter must succeed");
        let no_args = json!({});
        let authority = crate::modes::RuntimeModeAuthority::new(crate::modes::RuntimeMode::Plan)
            .expect("plan profile");
        for allowed in PLAN_MODE_ALLOWED_TOOLS {
            let (_, spec) = crate::tools::effect::lookup(allowed)
                .unwrap_or_else(|| panic!("documented tool {allowed} must be classified"));
            assert!(
                authority.definition_denial(allowed, spec.effect).is_none(),
                "{allowed} must remain visible in the compiled plan profile"
            );
        }
        // Previously-blocklisted write/mutate tools: each must be refused
        // by the hard default-deny path now that PLAN_MODE_BLOCKED_TOOLS
        // is gone (crosslink #341).
        for blocked in &[
            "bash",
            "bash_output",
            "edit_file",
            "kill_shell",
            "kill_shells_for_agent",
            "crosslink",
            "task",
            "agent_output",
            "task_get",
            "task_list",
            "todo_write",
            "todo_read",
            "web_fetch",
            "web_search",
            "web_browser",
            "enter_worktree",
            "exit_worktree",
            "list_worktrees",
        ] {
            assert!(
                !is_tool_allowed_in_plan_mode(blocked, &state.plan_realpath, &no_args),
                "{blocked} must be refused by hard default-deny after #341"
            );
        }
        assert!(is_tool_allowed_in_plan_mode(
            "enter_plan_mode",
            &state.plan_realpath,
            &no_args
        ));
        assert!(is_tool_allowed_in_plan_mode(
            "exit_plan_mode",
            &state.plan_realpath,
            &no_args
        ));
        assert!(!is_tool_allowed_in_plan_mode(
            "unknown_tool_xyz",
            &state.plan_realpath,
            &no_args
        ));
    }

    // ─── Crosslink #341: Hard default-deny for unknown / MCP / plugin tools ──

    /// Concrete, well-formed observation calls are admitted by their effect.
    #[test]
    fn known_tool_allowed_in_plan_mode_341() {
        let dir = TempDir::new().unwrap();
        let plan = dir.path().join("plan.md");
        std::fs::write(&plan, "# plan\n").unwrap();
        let state = PlanModeState::enter(plan).expect("enter must succeed");
        let read_args = json!({"path": state.plan_realpath});
        assert!(
            is_tool_allowed_in_plan_mode("read_file", &state.plan_realpath, &read_args),
            "well-formed read_file call must be permitted"
        );
        assert!(
            is_tool_allowed_in_plan_mode("grounding_context", &state.plan_realpath, &json!({})),
            "grounding_context must be permitted as a read-only plan-mode tool"
        );
        assert!(
            is_tool_allowed_in_plan_mode(
                "grep",
                &state.plan_realpath,
                &json!({"pattern": "plan", "path": state.plan_realpath})
            ),
            "well-formed grep call must be permitted"
        );
    }

    /// #341 — an unknown tool name (no MCP / plugin prefix, not in the
    /// allowlist, not a plan-mode marker) is HARD-denied. Previously the
    /// not-in-allowlist & not-in-blocklist case fell through to the
    /// `write_file` / marker checks before returning false; the new
    /// implementation rejects it via the explicit step 5 default-deny.
    #[test]
    fn unknown_tool_denied_by_hard_default_deny_341() {
        let dir = TempDir::new().unwrap();
        let plan = dir.path().join("plan.md");
        std::fs::write(&plan, "# plan\n").unwrap();
        let state = PlanModeState::enter(plan).expect("enter must succeed");
        let no_args = json!({});
        assert!(
            !is_tool_allowed_in_plan_mode(
                "totally_made_up_tool_341",
                &state.plan_realpath,
                &no_args
            ),
            "unknown tool must be refused by hard default-deny (#341)"
        );
        assert!(
            !is_tool_allowed_in_plan_mode("memory_save", &state.plan_realpath, &no_args),
            "technical-memory mutation must be refused in plan mode (#341)"
        );
    }

    /// #341 — an MCP-registered tool (`mcp__*`) is HARD-denied by default
    /// even when its suffix would have matched an allow-listed name. The
    /// prefix gate fires before the allowlist is consulted, so a hostile
    /// MCP server cannot register `mcp__evil__read_file` and ride the
    /// allowlist match for `read_file`.
    #[test]
    fn mcp_prefixed_tool_denied_by_default_341() {
        let dir = TempDir::new().unwrap();
        let plan = dir.path().join("plan.md");
        std::fs::write(&plan, "# plan\n").unwrap();
        let state = PlanModeState::enter(plan).expect("enter must succeed");
        let no_args = json!({});
        assert!(
            !is_tool_allowed_in_plan_mode(
                "mcp__some_server__exec_shell",
                &state.plan_realpath,
                &no_args
            ),
            "MCP-prefixed tool must be denied by default in plan mode (#341)"
        );
        assert!(
            !is_tool_allowed_in_plan_mode("mcp__evil__read_file", &state.plan_realpath, &no_args),
            "MCP tool whose suffix matches an allow-listed name must \
             STILL be denied -- the prefix gate fires first (#341)"
        );
        // Explicit policy opt-in still requires the bare name to be in
        // the allowlist: arbitrary MCP names remain denied even with
        // allow_mcp_tools = true.
        let permissive = PlanModePolicy {
            allow_mcp_tools: true,
            allow_plugin_tools: false,
        };
        assert!(
            !is_tool_allowed_in_plan_mode_with_policy(
                "mcp__some_server__exec_shell",
                &state.plan_realpath,
                &no_args,
                permissive,
            ),
            "even with allow_mcp_tools=true, an MCP tool not in the \
             allowlist remains denied (#341 belt-and-braces)"
        );
    }

    // ─── #618: previous_mode snapshot on plan-mode entry ──────────────────

    /// Default `enter` keeps the legacy on-disk shape — no `previous_mode`
    /// field — so sessions saved before #618 still load correctly.
    #[test]
    fn enter_default_has_no_previous_mode_snapshot_618() {
        let dir = TempDir::new().unwrap();
        let plan = dir.path().join("plan.md");
        std::fs::write(&plan, "# plan\n").unwrap();
        let state = PlanModeState::enter(plan).expect("enter must succeed");
        assert_eq!(
            state.previous_mode, None,
            "legacy enter() must not snapshot a mode"
        );
    }

    /// The new `enter_with_previous_mode` constructor stores the token
    /// verbatim — the binary-side `AgentMode::from_token` decodes it.
    #[test]
    fn enter_with_previous_mode_records_token_618() {
        let dir = TempDir::new().unwrap();
        let plan = dir.path().join("plan.md");
        std::fs::write(&plan, "# plan\n").unwrap();
        let state =
            PlanModeState::enter_with_previous_mode(plan.clone(), Some("refactor".to_string()))
                .expect("enter must succeed");
        assert_eq!(state.previous_mode.as_deref(), Some("refactor"));
        // Sanity: the other fields still satisfy their #334 invariants.
        assert!(state.active);
        assert_eq!(state.plan_file, plan);
        assert!(state.plan_realpath.is_absolute());
    }

    /// `previous_mode` round-trips through serde (so a paused-then-resumed
    /// session restores to the same mode after `exit_plan_mode`).
    #[test]
    fn previous_mode_round_trips_through_serde_618() {
        let dir = TempDir::new().unwrap();
        let plan = dir.path().join("plan.md");
        std::fs::write(&plan, "# plan\n").unwrap();
        let state = PlanModeState::enter_with_previous_mode(plan, Some("extend".to_string()))
            .expect("enter must succeed");
        let json = serde_json::to_string(&state).expect("serialise");
        assert!(
            json.contains("\"previous_mode\":\"extend\""),
            "JSON must carry the snapshot; got: {json}"
        );
        let round: PlanModeState = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(round.previous_mode.as_deref(), Some("extend"));
    }

    /// #341 — a plugin-contributed tool (`plugin__*`) is HARD-denied by
    /// default. Same architecture as the MCP case: prefix gate first,
    /// allowlist second, default-deny third.
    #[test]
    fn plugin_prefixed_tool_denied_by_default_341() {
        let dir = TempDir::new().unwrap();
        let plan = dir.path().join("plan.md");
        std::fs::write(&plan, "# plan\n").unwrap();
        let state = PlanModeState::enter(plan).expect("enter must succeed");
        let no_args = json!({});
        assert!(
            !is_tool_allowed_in_plan_mode(
                "plugin__my_plugin__do_thing",
                &state.plan_realpath,
                &no_args
            ),
            "plugin-prefixed tool must be denied by default in plan mode (#341)"
        );
        assert!(
            !is_tool_allowed_in_plan_mode(
                "plugin__evil__list_files",
                &state.plan_realpath,
                &no_args
            ),
            "plugin tool whose suffix matches an allow-listed name must \
             STILL be denied (#341)"
        );
        let permissive = PlanModePolicy {
            allow_mcp_tools: false,
            allow_plugin_tools: true,
        };
        assert!(
            !is_tool_allowed_in_plan_mode_with_policy(
                "plugin__my_plugin__do_thing",
                &state.plan_realpath,
                &no_args,
                permissive,
            ),
            "even with allow_plugin_tools=true, a plugin tool not in the \
             allowlist remains denied (#341)"
        );
    }
}
