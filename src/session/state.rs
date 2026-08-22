//! Session state types: token usage, turn metrics, plan mode.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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

/// An allowed prompt constraint for plan mode exit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedPrompt {
    /// Tool name this prompt applies to
    pub tool: String,
    /// Prompt/description for the allowed operation
    pub prompt: String,
}

/// Tools that are allowed in plan mode (read-only + user interaction).
///
/// Single source of truth for "known plan-mode-safe tools".
///
/// `is_tool_allowed_in_plan_mode` enforces hard default-deny: any tool name
/// not in this list (and not the `write_file`-to-plan-file special case nor
/// the plan-mode marker tools below) is **rejected** regardless of whether
/// it is a built-in, MCP-registered, or plugin-contributed tool.
///
/// `enter_plan_mode` / `exit_plan_mode` are special and handled inline in
/// [`is_tool_allowed_in_plan_mode`]; they are not in this list because they
/// affect plan-mode state itself rather than executing under plan-mode
/// restrictions.
pub const PLAN_MODE_ALLOWED_TOOLS: &[&str] = &[
    "read_file",
    "grounding_context",
    "list_files",
    "grep",
    "web_fetch",
    #[cfg(feature = "browser")]
    "web_search",
    #[cfg(feature = "browser")]
    "web_browser",
    "ask_user_question",
    "task",
    "agent_output",
    "task_get",
    "task_list",
    "todo_read",
    "memory_search",
    "memory_list",
    "memory_learning_status",
    "memory_source_status",
    "crosslink",
    "bash_output",
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

/// Policy for plan-mode tool gating.
///
/// Default is *hard* default-deny: every tool not in
/// [`PLAN_MODE_ALLOWED_TOOLS`] is refused, including any MCP or plugin
/// tool that happens to be named like a built-in. Operators may opt into
/// MCP/plugin tools in plan mode by setting `allow_mcp_tools` /
/// `allow_plugin_tools` to `true`, but doing so still requires the tool
/// name to appear in [`PLAN_MODE_ALLOWED_TOOLS`] -- the prefix flags only
/// _lift the prefix-based hard refusal_, they do **not** bypass the
/// allowlist (crosslink #341).
#[derive(Debug, Clone, Copy, Default)]
pub struct PlanModePolicy {
    /// Permit `mcp__*` tools to be considered by the allowlist. Default `false`.
    pub allow_mcp_tools: bool,
    /// Permit `plugin__*` tools to be considered by the allowlist. Default `false`.
    pub allow_plugin_tools: bool,
}

/// Check if a tool is allowed in plan mode (hard default-deny).
///
/// Thin wrapper over [`is_tool_allowed_in_plan_mode_with_policy`] using
/// the default policy ([`PlanModePolicy::default`]), which denies all MCP
/// and plugin tools. Existing callers keep their behaviour after the
/// crosslink #341 refactor.
///
/// # Hard default-deny (crosslink #341)
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
/// 1. `mcp__*` / `plugin__*` prefixes → hard-deny by default (configurable).
/// 2. `enter_plan_mode` / `exit_plan_mode` → allow (plan-mode markers).
/// 3. `write_file` → allow **only** if target canonicalizes to `plan_realpath`.
/// 4. Name in [`PLAN_MODE_ALLOWED_TOOLS`] → allow.
/// 5. Anything else → **deny**.
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

/// Policy-aware plan-mode allow check.
///
/// See [`is_tool_allowed_in_plan_mode`] for the decision flow. This entry
/// point exists so the harness can opt into MCP/plugin tools when an
/// operator has explicitly configured `plan_mode.allow_mcp_tools = true`
/// (or the plugin equivalent) in the project config. Even with those
/// flags lifted, the tool name still has to appear in
/// [`PLAN_MODE_ALLOWED_TOOLS`] -- there is no path to "fall through"
/// into allowed.
#[must_use]
pub fn is_tool_allowed_in_plan_mode_with_policy(
    tool_name: &str,
    plan_realpath: &Path,
    args: &serde_json::Value,
    policy: PlanModePolicy,
) -> bool {
    // Step 1: Prefix-based hard refusal for opaque tool sources.
    //
    // MCP / plugin tools are denied by default. We refuse *before* the
    // allowlist check because a malicious MCP server could otherwise
    // register a tool whose suffix shadows an allow-listed built-in
    // (e.g. `mcp__evil__read_file`). The prefix gate forces such tools
    // to keep their `mcp__` / `plugin__` prefix in the dispatcher, so
    // the refusal here applies before the name-based allowlist is even
    // consulted.
    if tool_name.starts_with(MCP_TOOL_PREFIX) && !policy.allow_mcp_tools {
        return false;
    }
    if tool_name.starts_with(PLUGIN_TOOL_PREFIX) && !policy.allow_plugin_tools {
        return false;
    }

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

    // Step 4: Explicit allowlist.
    if PLAN_MODE_ALLOWED_TOOLS.contains(&tool_name) {
        return true;
    }

    // Step 5: Hard default-deny. Any tool name not handled above --
    // unknown built-ins, typo'd names, late-registered MCP/plugin tools
    // that somehow lost their prefix, etc. -- is refused.
    false
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

    /// Static allow-list preserved, and explicit write/mutate tools refused
    /// after the #334 / #341 refactor (block-list is now redundant; the
    /// hard default-deny in [`is_tool_allowed_in_plan_mode`] subsumes it).
    #[test]
    fn allow_check_preserves_static_allow_and_block_lists() {
        let dir = TempDir::new().unwrap();
        let plan = dir.path().join("plan.md");
        std::fs::write(&plan, "# plan\n").unwrap();
        let state = PlanModeState::enter(plan).expect("enter must succeed");
        let no_args = json!({});
        for allowed in PLAN_MODE_ALLOWED_TOOLS {
            assert!(
                is_tool_allowed_in_plan_mode(allowed, &state.plan_realpath, &no_args),
                "{allowed} must remain in the allow-list after the #334 refactor"
            );
        }
        // Previously-blocklisted write/mutate tools: each must be refused
        // by the hard default-deny path now that PLAN_MODE_BLOCKED_TOOLS
        // is gone (crosslink #341).
        for blocked in &[
            "bash",
            "edit_file",
            "kill_shell",
            "kill_shells_for_agent",
            "todo_write",
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

    /// #341 — every name in [`PLAN_MODE_ALLOWED_TOOLS`] is permitted under
    /// the new explicit-allowlist gate. Positive control: if this fails,
    /// the hard default-deny has collapsed onto legitimate known tools
    /// and the harness is unusable in plan mode.
    #[test]
    fn known_tool_allowed_in_plan_mode_341() {
        let dir = TempDir::new().unwrap();
        let plan = dir.path().join("plan.md");
        std::fs::write(&plan, "# plan\n").unwrap();
        let state = PlanModeState::enter(plan).expect("enter must succeed");
        let no_args = json!({});
        assert!(
            is_tool_allowed_in_plan_mode("read_file", &state.plan_realpath, &no_args),
            "known allow-listed tool must be permitted (#341 positive control)"
        );
        assert!(
            is_tool_allowed_in_plan_mode("grounding_context", &state.plan_realpath, &no_args),
            "grounding_context must be permitted as a read-only plan-mode tool"
        );
        assert!(
            is_tool_allowed_in_plan_mode("grep", &state.plan_realpath, &no_args),
            "known allow-listed tool must be permitted (#341 positive control)"
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
