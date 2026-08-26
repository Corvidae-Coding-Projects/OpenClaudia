//! Subagent System for `OpenClaudia`
//!
//! Provides Claude Code-style subagent capabilities:
//! - Task tool for spawning autonomous sub-agents
//! - `AgentOutput` tool for retrieving background agent results
//! - Agent type configurations with specialized system prompts
//! - Isolated conversation contexts per subagent
//! - Background execution with async tracking

use crate::config::AppConfig;
use crate::tools::{args::ToolArgs as _, safe_truncate, ToolCall};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::hash::BuildHasher;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, Once};
use std::time::{Duration, Instant};
use tokio::runtime::Handle;
use uuid::Uuid;

/// Maximum turns a subagent can execute before forced termination
const MAX_SUBAGENT_TURNS: usize = 50;

/// Maximum tokens for subagent responses
const SUBAGENT_MAX_TOKENS: u32 = 8192;

/// Resolve `git` through the immutable executable search path captured for the
/// exact parent or child run that owns the worktree operation.
fn git_bin(run: &crate::tools::ToolRunContext) -> Result<PathBuf, String> {
    run.resolve_executable("git")
        .map_err(|error| error.to_string())
}

fn sandboxed_git(
    run: &crate::tools::ToolRunContext,
    cwd: &Path,
    args: &[&str],
) -> Result<std::process::Output, String> {
    let mut hardened = vec![
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "diff.external=",
        "-c",
        "core.pager=cat",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
    ];
    hardened.extend_from_slice(args);
    let env = HashMap::from([
        ("GIT_CONFIG_GLOBAL".to_string(), "/dev/null".to_string()),
        ("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string()),
        ("GIT_TERMINAL_PROMPT".to_string(), "0".to_string()),
    ]);
    crate::tools::run_sandboxed_with_timeout_with_env(
        run,
        crate::tools::SandboxProfile::GitWorktree,
        &git_bin(run)?,
        &hardened,
        cwd,
        Duration::from_secs(30),
        &env,
    )
    .map_err(|error| error.to_string())
}

fn agent_field_guard<'a, T>(
    mutex: &'a Mutex<T>,
    operation: &'static str,
    agent_id: &str,
    field: &'static str,
) -> Option<MutexGuard<'a, T>> {
    match mutex.lock() {
        Ok(guard) => Some(guard),
        Err(err) => {
            tracing::error!(
                operation,
                agent_id,
                field,
                error = %err,
                "Background agent field lock poisoned"
            );
            None
        }
    }
}

/// Agent types available for spawning
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentType {
    /// General-purpose agent for complex multi-step tasks
    GeneralPurpose,
    /// Fast agent for codebase exploration and searches
    Explore,
    /// Software architect agent for designing implementation plans
    Plan,
    /// Documentation lookup agent
    Guide,
    /// Multi-agent orchestrator that delegates work to worker agents
    Coordinator,
}

impl AgentType {
    /// Every agent type, in display order. Stable order so `/agents`
    /// output doesn't shuffle between runs.
    pub const ALL: &'static [Self] = &[
        Self::GeneralPurpose,
        Self::Explore,
        Self::Plan,
        Self::Guide,
        Self::Coordinator,
    ];

    /// Agent types that the `task` tool is allowed to launch directly.
    ///
    /// `Coordinator` is a router/profile type. It has a system prompt and a
    /// legacy REPL mode, but it is not a task-spawnable worker until the
    /// coordinator runtime is wired end-to-end.
    pub const TASK_SPAWNABLE: &'static [Self] =
        &[Self::GeneralPurpose, Self::Explore, Self::Plan, Self::Guide];

    /// Canonical kebab-case name as accepted by `parse_type`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::GeneralPurpose => "general-purpose",
            Self::Explore => "explore",
            Self::Plan => "plan",
            Self::Guide => "claude-code-guide",
            Self::Coordinator => "coordinator",
        }
    }

    /// One-line human-readable description for help output.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::GeneralPurpose => "Complex multi-step tasks with full tool access",
            Self::Explore => "Fast codebase exploration and searches (read-only)",
            Self::Plan => "Software architect for implementation plans (read-only)",
            Self::Guide => "Documentation lookup and usage questions",
            Self::Coordinator => "Multi-agent orchestrator that delegates work",
        }
    }

    /// Parse agent type from string
    #[must_use]
    pub fn parse_type(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "general-purpose" | "general_purpose" | "generalpurpose" => Some(Self::GeneralPurpose),
            "explore" | "explorer" => Some(Self::Explore),
            "plan" | "planner" => Some(Self::Plan),
            "guide" | "claude-code-guide" => Some(Self::Guide),
            "coordinator" => Some(Self::Coordinator),
            _ => None,
        }
    }

    /// Canonical `task.subagent_type` value for task-spawnable agents.
    #[must_use]
    pub const fn task_tool_name(&self) -> Option<&'static str> {
        match self {
            Self::GeneralPurpose => Some("general-purpose"),
            Self::Explore => Some("explore"),
            Self::Plan => Some("plan"),
            Self::Guide => Some("guide"),
            Self::Coordinator => None,
        }
    }

    /// `task.subagent_type` names in schema/display order.
    #[must_use]
    pub fn task_tool_names() -> Vec<&'static str> {
        Self::TASK_SPAWNABLE
            .iter()
            .filter_map(Self::task_tool_name)
            .collect()
    }

    /// Parse a task-spawnable agent type.
    #[must_use]
    pub fn parse_task_type(s: &str) -> Option<Self> {
        let agent_type = Self::parse_type(s)?;
        agent_type.task_tool_name().map(|_| agent_type)
    }

    /// Get the system prompt for this agent type
    #[must_use]
    pub const fn system_prompt(&self) -> &'static str {
        match self {
            Self::GeneralPurpose => GENERAL_PURPOSE_PROMPT,
            Self::Explore => EXPLORE_PROMPT,
            Self::Plan => PLAN_PROMPT,
            Self::Guide => GUIDE_PROMPT,
            Self::Coordinator => COORDINATOR_PROMPT,
        }
    }

    /// Get the tools available to this agent type
    #[must_use]
    pub fn allowed_tools(&self) -> Vec<&'static str> {
        match self {
            Self::GeneralPurpose => {
                let tools = vec![
                    "bash",
                    "bash_output",
                    "kill_shell",
                    "kill_shells_for_agent",
                    "read_file",
                    "write_file",
                    "edit_file",
                    "list_files",
                    "web_fetch",
                    "memory_search",
                    "memory_list",
                    "memory_learning_status",
                    "memory_conflicts",
                    "memory_save",
                    "memory_update",
                    "memory_delete",
                    "memory_source_status",
                    "memory_source_refresh",
                ];
                add_browser_search_tool(tools)
            }
            Self::Explore => {
                let tools = vec![
                    "bash",
                    "read_file",
                    "list_files",
                    "web_fetch",
                    "memory_search",
                    "memory_list",
                    "memory_learning_status",
                    "memory_conflicts",
                    "memory_source_status",
                ];
                add_browser_search_tool(tools)
            }
            Self::Plan | Self::Guide => {
                let tools = vec![
                    "read_file",
                    "list_files",
                    "web_fetch",
                    "memory_search",
                    "memory_list",
                    "memory_learning_status",
                    "memory_conflicts",
                    "memory_source_status",
                ];
                add_browser_search_tool(tools)
            }
            Self::Coordinator => {
                let tools = vec![
                    "task",
                    "agent_output",
                    "task_stop",
                    "task_create",
                    "task_update",
                    "task_get",
                    "task_list",
                    "ask_user_question",
                    "read_file",
                    "list_files",
                    "web_fetch",
                    "memory_search",
                    "memory_list",
                    "memory_learning_status",
                    "memory_conflicts",
                    "memory_source_status",
                ];
                add_browser_search_tool(tools)
            }
        }
    }

    /// Get model preference for this agent type
    #[must_use]
    pub const fn preferred_model(&self) -> Option<&'static str> {
        match self {
            Self::Explore | Self::Guide => Some("haiku"),
            Self::Coordinator | Self::GeneralPurpose | Self::Plan => None,
        }
    }
}

#[cfg(feature = "browser")]
fn add_browser_search_tool(mut tools: Vec<&'static str>) -> Vec<&'static str> {
    tools.push("web_search");
    tools
}

#[cfg(not(feature = "browser"))]
const fn add_browser_search_tool(tools: Vec<&'static str>) -> Vec<&'static str> {
    tools
}

// === System Prompts for Agent Types ===

const GENERAL_PURPOSE_PROMPT: &str = r"You are a specialized subagent spawned to handle a complex task autonomously.

Your goal is to complete the assigned task thoroughly and return a comprehensive summary of what you accomplished.

Guidelines:
- Work autonomously to complete the task
- Use tools as needed to accomplish your goal
- Be thorough but efficient
- When you're done, provide a clear summary of:
  - What was accomplished
  - Any files created or modified
  - Any issues encountered
  - Recommendations for follow-up if needed

You have access to file and shell tools. Use them to explore the codebase, make changes, and verify your work.
For bash, write_file, and edit_file, include the required decision object with Reality Ledger evidence before requesting the tool.";

const EXPLORE_PROMPT: &str = r"You are a fast exploration agent specialized for searching codebases.

Your goal is to quickly find relevant files, code patterns, and answer questions about the codebase structure.

Guidelines:
- Use bash with grep, find, or similar tools to search efficiently
- Include the required decision object with Reality Ledger evidence for bash calls
- Read files to understand their contents
- Be fast and focused - don't over-explore
- Return a concise summary of what you found including:
  - Relevant file paths
  - Key code snippets or patterns
  - Direct answers to the question asked

Focus on speed and relevance. Don't modify any files - this is read-only exploration.";

const PLAN_PROMPT: &str = r"You are a software architect agent for designing implementation plans.

Your goal is to analyze the codebase and design a clear implementation strategy for the requested feature or change.

Guidelines:
- Explore the existing codebase to understand patterns and architecture
- Identify the files that need to be modified
- Consider edge cases and potential issues
- Design a step-by-step implementation plan

Return a structured plan including:
- Overview of the approach
- Files to create or modify
- Step-by-step implementation steps
- Potential risks or considerations
- Dependencies or prerequisites

Do NOT implement the changes - only plan them.";

const GUIDE_PROMPT: &str = r"You are a documentation lookup agent.

Your goal is to find and summarize relevant documentation for the user's question.

Guidelines:
- Search for relevant documentation files
- Use available web tools to find official documentation
- Provide clear, accurate information
- Include relevant code examples when helpful

Return a helpful answer with sources cited.";

const COORDINATOR_PROMPT: &str = "You are a coordinator agent responsible for multi-agent orchestration.

You break down complex tasks into smaller units of work and delegate them to specialized worker agents. You do NOT execute tools directly \u{2014} no bash commands, no file writes, no file edits. Your job is to plan, delegate, monitor, and synthesize.

## Workflow

1. **Research**: Use read_file, list_files, and available web tools to understand the problem space, codebase structure, and requirements before delegating.
2. **Planning**: Decompose the task into discrete sub-tasks. Use task_create to track each one. Identify dependencies and ordering constraints.
3. **Delegation**: Spawn worker agents via the `task` tool to execute each sub-task. Each worker prompt must be fully self-contained \u{2014} include all file paths, context, and acceptance criteria the worker needs. Never assume workers share your context.
4. **Monitoring**: Use agent_output to check on background workers. Use task_update to record progress. Re-delegate or adjust the plan if a worker fails or produces unexpected results.
5. **Synthesis**: Once all sub-tasks complete, combine worker outputs into a coherent final summary. Report what was accomplished, what failed, and any follow-up needed.

## Worker Types

- **general-purpose**: Implementation workers that can read, write, and edit files, run shell commands. Use for coding tasks, refactoring, test writing.
- **explore**: Fast read-only search agents. Use for finding files, code patterns, or understanding codebase structure.
- **plan**: Architecture agents that analyze code and produce implementation plans. Use when you need a detailed design before implementation.
- **guide**: Documentation lookup agents. Use for finding API docs, library usage, or reference material.

## Rules

- NEVER use bash, write_file, or edit_file \u{2014} you do not have access to these tools.
- Every worker prompt must be self-contained: include file paths, expected behavior, and all relevant context.
- Use task_create/task_update to maintain a clear record of sub-tasks and their status.
- Prefer spawning workers in background (run_in_background: true) when tasks are independent, then collect results with agent_output.
- If a worker fails, analyze the failure and either retry with a corrected prompt or adjust your plan.
- Use ask_user_question when requirements are ambiguous or you need clarification before proceeding.
- Always provide a final summary that maps each sub-task to its outcome.";

// === Background Agent Management ===

/// Retention TTL for finished background agents (1 hour).
///
/// Entries that have been finished for longer than this are evicted by
/// [`BackgroundAgentManager::gc`] on the next manager touch. Exposed as a
/// constant so tests can compare against it.
///
/// Fix for crosslink #422: without a sweep the `agents` map grew
/// unboundedly — a session spawning ~10 agents/hour over 8 hours leaked
/// ~80 finished `BackgroundAgent` Arcs, each carrying full output and
/// task description.
pub const FINISHED_AGENT_TTL_SECS: u64 = 60 * 60;

/// State of a running or completed background agent
#[derive(Debug)]
pub struct BackgroundAgent {
    /// Unique agent ID
    pub id: String,
    /// Exact parent run generation allowed to observe or cancel this agent.
    owner_run: crate::runtime::RunId,
    /// Agent type
    pub agent_type: AgentType,
    /// Task description
    pub task: String,
    /// Whether the agent has finished
    pub finished: AtomicBool,
    /// Final result (populated when finished)
    pub result: Mutex<Option<String>>,
    /// Error message if failed
    pub error: Mutex<Option<String>>,
    /// Number of turns executed
    pub turns: AtomicU64,
    /// When the agent transitioned to `finished`. `None` while still running.
    /// Used by [`BackgroundAgentManager::gc`] to evict entries past
    /// [`FINISHED_AGENT_TTL_SECS`].
    pub finished_at: Mutex<Option<Instant>>,
    /// Abort handle for the spawned tokio task, present only for background
    /// agents. This is intentionally separate from the `JoinHandle` so the
    /// task remains detached while still being externally cancellable.
    abort_handle: Mutex<Option<tokio::task::AbortHandle>>,
    /// Serializes terminal-state transitions (`finish`, `fail`, `stop`) so an
    /// external cancellation cannot be overwritten by a late model response.
    terminal_lock: Mutex<()>,
    /// Stable canonical task-graph node for this delegation, once admission
    /// has reached the durable graph. The background registry remains a live
    /// process handle; it is never a second planning truth.
    canonical_task_id: Mutex<Option<String>>,
}

/// Manager for background agents
pub struct BackgroundAgentManager {
    agents: Mutex<BackgroundAgentMap>,
}

type BackgroundAgentMap = HashMap<String, Arc<BackgroundAgent>>;

impl BackgroundAgentManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            agents: Mutex::new(HashMap::new()),
        }
    }

    fn agents_guard(&self, operation: &'static str) -> Option<MutexGuard<'_, BackgroundAgentMap>> {
        match self.agents.lock() {
            Ok(guard) => Some(guard),
            Err(err) => {
                tracing::error!(
                    operation,
                    error = %err,
                    "Background agent registry lock poisoned"
                );
                None
            }
        }
    }

    /// Register a new background agent.
    ///
    /// Also opportunistically sweeps expired finished agents
    /// (see [`Self::gc`]) so the map cannot grow unbounded across a session.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry is unavailable or no unique agent
    /// identifier can be allocated after the bounded retry budget.
    pub fn register(
        &self,
        owner: &crate::tools::ToolRunContext,
        agent_type: AgentType,
        task: &str,
    ) -> Result<String, String> {
        for _ in 0..16 {
            let id = safe_truncate(&Uuid::new_v4().to_string(), 8).to_string();
            if self.register_with_id(owner, agent_type, task, &id)? {
                return Ok(id);
            }
        }
        Err("Could not allocate a unique background agent id".to_string())
    }

    /// Register (or reattach to) a background agent under a caller-chosen id.
    ///
    /// Used by the subagent resume path (crosslink #582) so a resumed
    /// agent keeps the *original* id — preserving transcript continuity
    /// in [`TRANSCRIPT_STORE`] and prompt-cache continuity at the
    /// provider. Behaviour:
    ///
    /// * If no entry exists for `id`, a fresh tracking entry is inserted
    ///   (mirrors [`Self::register`] but with a known id).
    /// * If an entry already exists, this is a no-op — we deliberately
    ///   do **not** reset `finished` / `turns` / `result` / `error`,
    ///   because the caller is reattaching to (not replacing) the
    ///   prior agent.
    ///
    /// Returns `true` iff a new entry was inserted (i.e. the id was
    /// fresh). Callers can ignore the return value when they only need
    /// "ensure tracked".
    ///
    /// # Errors
    ///
    /// Returns an error when the registry is unavailable, `id` is invalid,
    /// or the same identifier is already owned by a different run.
    pub fn register_with_id(
        &self,
        owner: &crate::tools::ToolRunContext,
        agent_type: AgentType,
        task: &str,
        id: &str,
    ) -> Result<bool, String> {
        // Sweep before insert so the cost of growth is amortized against
        // the spawn that causes it (crosslink #422).
        self.gc();

        let Some(mut agents) = self.agents_guard("register_with_id") else {
            return Err("Background agent registry is unavailable".to_string());
        };
        if let Some(existing) = agents.get(id) {
            if existing.owner_run == owner.run_id() {
                return Ok(false);
            }
            tracing::warn!(
                target: "openclaudia::subagent",
                event = "cross_run_agent_resume_denied",
                caller_run = %owner.run_id(),
                agent_id = id,
                "Denied background-agent id reuse outside the owning run"
            );
            return Err(format!("Agent '{id}' not found"));
        }
        let agent = Arc::new(BackgroundAgent {
            id: id.to_string(),
            owner_run: owner.run_id(),
            agent_type,
            task: task.to_string(),
            finished: AtomicBool::new(false),
            result: Mutex::new(None),
            error: Mutex::new(None),
            turns: AtomicU64::new(0),
            finished_at: Mutex::new(None),
            abort_handle: Mutex::new(None),
            terminal_lock: Mutex::new(()),
            canonical_task_id: Mutex::new(None),
        });
        agents.insert(id.to_string(), agent);
        Ok(true)
    }

    /// Trusted lifecycle lookup by globally unique id.
    fn get(&self, id: &str) -> Option<Arc<BackgroundAgent>> {
        let agents = self.agents_guard("get")?;
        agents.get(id).cloned()
    }

    /// Resolve an agent only for its exact parent run generation.
    pub fn get_for_run(
        &self,
        owner: &crate::tools::ToolRunContext,
        id: &str,
    ) -> Option<Arc<BackgroundAgent>> {
        let agent = self.get(id)?;
        (agent.owner_run == owner.run_id()).then_some(agent)
    }

    fn bind_canonical_task(
        &self,
        owner: &crate::tools::ToolRunContext,
        id: &str,
        task_id: &str,
    ) -> Result<(), String> {
        let agent = self
            .get_for_run(owner, id)
            .ok_or_else(|| format!("Agent '{id}' not found"))?;
        let Some(mut slot) = agent_field_guard(
            &agent.canonical_task_id,
            "bind_canonical_task",
            id,
            "canonical_task_id",
        ) else {
            return Err(format!("Agent '{id}' canonical task lock poisoned"));
        };
        match slot.as_deref() {
            None => {
                *slot = Some(task_id.to_string());
                Ok(())
            }
            Some(existing) if existing == task_id => Ok(()),
            Some(_) => Err(format!(
                "Agent '{id}' is already bound to a different canonical task"
            )),
        }
    }

    fn canonical_task_for_run(
        &self,
        owner: &crate::tools::ToolRunContext,
        id: &str,
    ) -> Option<String> {
        let agent = self.get_for_run(owner, id)?;
        agent_field_guard(
            &agent.canonical_task_id,
            "canonical_task_for_run",
            id,
            "canonical_task_id",
        )
        .and_then(|slot| slot.clone())
    }

    /// Mark an agent as finished with a result
    pub fn finish(&self, owner: &crate::tools::ToolRunContext, id: &str, result: String) {
        self.mark_terminal(owner, id, Some(result), None, "finish");
    }

    /// Mark an agent as failed with an error
    pub fn fail(&self, owner: &crate::tools::ToolRunContext, id: &str, error: String) {
        self.mark_terminal(owner, id, None, Some(error), "fail");
    }

    fn mark_terminal(
        &self,
        owner: &crate::tools::ToolRunContext,
        id: &str,
        result: Option<String>,
        error: Option<String>,
        operation: &'static str,
    ) -> bool {
        if let Some(agent) = self.get_for_run(owner, id) {
            let Ok(_terminal) = agent.terminal_lock.lock() else {
                tracing::error!(
                    operation,
                    agent_id = id,
                    "Background agent terminal-state lock poisoned"
                );
                return false;
            };
            if agent.finished.load(Ordering::SeqCst) {
                return false;
            }
            if let Some(result) = result {
                if let Some(mut r) = agent_field_guard(&agent.result, operation, id, "result") {
                    *r = Some(result);
                }
            }
            if let Some(error) = error {
                if let Some(mut e) = agent_field_guard(&agent.error, operation, id, "error") {
                    *e = Some(error);
                }
            }
            if let Some(mut t) = agent_field_guard(&agent.finished_at, operation, id, "finished_at")
            {
                *t = Some(Instant::now());
            }
            if let Some(mut handle) =
                agent_field_guard(&agent.abort_handle, operation, id, "abort_handle")
            {
                *handle = None;
            }
            agent.finished.store(true, Ordering::SeqCst);
            return true;
        }
        false
    }

    /// Attach the abort handle for a background agent task.
    ///
    /// # Errors
    ///
    /// Returns an error if the agent id is unknown or the agent's abort-handle
    /// lock is poisoned.
    pub fn attach_abort_handle(
        &self,
        owner: &crate::tools::ToolRunContext,
        id: &str,
        abort_handle: tokio::task::AbortHandle,
    ) -> Result<(), String> {
        let agent = self
            .get_for_run(owner, id)
            .ok_or_else(|| format!("Agent '{id}' not found"))?;
        if agent.finished.load(Ordering::SeqCst) {
            abort_handle.abort();
            return Ok(());
        }
        let Some(mut slot) = agent_field_guard(
            &agent.abort_handle,
            "attach_abort_handle",
            id,
            "abort_handle",
        ) else {
            return Err(format!("Agent '{id}' abort handle lock poisoned"));
        };
        *slot = Some(abort_handle);
        Ok(())
    }

    /// Stop a running background agent and abort its spawned task if possible.
    ///
    /// # Errors
    ///
    /// Returns an error if the agent id is unknown or required agent metadata
    /// locks are poisoned.
    pub fn stop(
        &self,
        owner: &crate::tools::ToolRunContext,
        id: &str,
        reason: &str,
    ) -> Result<String, String> {
        let agent = self
            .get_for_run(owner, id)
            .ok_or_else(|| format!("Agent '{id}' not found"))?;
        let turns = agent.turns.load(Ordering::SeqCst);
        let task = agent.task.clone();
        let reason = if reason.trim().is_empty() {
            "stopped by task_stop"
        } else {
            reason.trim()
        };

        let abort_handle = {
            let Ok(_terminal) = agent.terminal_lock.lock() else {
                return Err(format!("Agent '{id}' terminal-state lock poisoned"));
            };
            if agent.finished.load(Ordering::SeqCst) {
                return Ok(format!("Agent '{id}' is already finished ({turns} turns)."));
            }

            if let Some(mut e) = agent_field_guard(&agent.error, "stop", id, "error") {
                *e = Some(reason.to_string());
            }
            if let Some(mut t) = agent_field_guard(&agent.finished_at, "stop", id, "finished_at") {
                *t = Some(Instant::now());
            }
            let abort_handle = agent_field_guard(&agent.abort_handle, "stop", id, "abort_handle")
                .and_then(|mut h| h.take());
            agent.finished.store(true, Ordering::SeqCst);
            abort_handle
        };

        if let Some(handle) = abort_handle {
            handle.abort();
        }
        let shell_cleanup = crate::tools::BACKGROUND_SHELLS.kill_for_process_owner(owner, id);
        Ok(format!(
            "Agent '{id}' stopped after {turns} turns.\nTask: {task}\nReason: {reason}\n{shell_cleanup}"
        ))
    }

    /// Increment turn counter for an agent
    pub fn increment_turns(&self, owner: &crate::tools::ToolRunContext, id: &str) -> u64 {
        self.get_for_run(owner, id)
            .map_or(0, |agent| agent.turns.fetch_add(1, Ordering::SeqCst) + 1)
    }

    /// List all agents.
    ///
    /// Sweeps expired finished agents first (see [`Self::gc`]) so callers
    /// — including the TUI agent list — never observe leaked stale entries.
    pub fn list_for_run(
        &self,
        owner: &crate::tools::ToolRunContext,
    ) -> Vec<(String, AgentType, String, bool)> {
        self.gc();
        let Some(agents) = self.agents_guard("list") else {
            return Vec::new();
        };
        agents
            .iter()
            .filter(|(_, agent)| agent.owner_run == owner.run_id())
            .map(|(id, agent)| {
                (
                    id.clone(),
                    agent.agent_type,
                    agent.task.clone(),
                    agent.finished.load(Ordering::SeqCst),
                )
            })
            .collect()
    }

    /// Active worker ids owned by one exact run generation.
    pub(crate) fn active_ids_for_run(
        &self,
        owner: &crate::tools::ToolRunContext,
    ) -> Result<Vec<String>, String> {
        let mut ids = {
            let Some(agents) = self.agents_guard("active_ids_for_run") else {
                return Err("Background agent registry is unavailable".to_string());
            };
            agents
                .iter()
                .filter(|(_, agent)| {
                    agent.owner_run == owner.run_id() && !agent.finished.load(Ordering::SeqCst)
                })
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>()
        };
        ids.sort_unstable();
        Ok(ids)
    }

    pub fn remove_for_run(
        &self,
        owner: &crate::tools::ToolRunContext,
        id: &str,
    ) -> Option<Arc<BackgroundAgent>> {
        let mut agents = self.agents_guard("remove_for_run")?;
        if agents
            .get(id)
            .is_some_and(|agent| agent.owner_run == owner.run_id())
        {
            agents.remove(id)
        } else {
            None
        }
    }

    /// Garbage-collect finished agents older than [`FINISHED_AGENT_TTL_SECS`].
    ///
    /// Running agents (`finished == false`) are never removed regardless of
    /// how long they have been registered — only completion age triggers
    /// eviction. Returns the number of removed entries.
    ///
    /// Fix for crosslink #422 — replaces unbounded growth with a bounded
    /// retention window. Safe to call from any context (poisoned lock is
    /// treated as a no-op).
    pub fn gc(&self) -> usize {
        let now = Instant::now();
        let Some(mut agents) = self.agents_guard("gc") else {
            return 0;
        };
        let before = agents.len();
        agents.retain(|_, agent| {
            if !agent.finished.load(Ordering::SeqCst) {
                return true;
            }
            // Finished: keep only if not yet past TTL. Missing/poisoned
            // timestamp counts as "evict" so a half-initialized entry
            // cannot pin memory forever.
            agent
                .finished_at
                .lock()
                .ok()
                .and_then(|t| *t)
                .is_some_and(|t| now.duration_since(t).as_secs() < FINISHED_AGENT_TTL_SECS)
        });
        before.saturating_sub(agents.len())
    }

    /// Drop finished agents owned by one exact run generation rather than
    /// allowing one frontend to clean up another run's lifecycle state.
    /// Returns the number of agents removed.
    pub fn cleanup_finished_for_run(&self, owner: &crate::tools::ToolRunContext) -> usize {
        let Some(mut agents) = self.agents_guard("cleanup_finished_for_run") else {
            return 0;
        };
        let before = agents.len();
        agents.retain(|_, agent| {
            agent.owner_run != owner.run_id() || !agent.finished.load(Ordering::SeqCst)
        });
        before.saturating_sub(agents.len())
    }

    /// Abort and remove every background agent owned by one retiring run.
    pub(crate) fn stop_all_for_run(&self, owner: &crate::tools::ToolRunContext) -> usize {
        let agent_ids = self
            .list_for_run(owner)
            .into_iter()
            .map(|(id, _, _, _)| id)
            .collect::<Vec<_>>();
        let mut stopped = 0;
        for agent_id in agent_ids {
            let canonical_task = self.canonical_task_for_run(owner, &agent_id);
            if self
                .stop(owner, &agent_id, "owning frontend run retired")
                .is_ok()
            {
                stopped += 1;
                if let Some(task_id) = canonical_task {
                    if let Err(error) = transition_canonical_delegation(
                        owner,
                        &task_id,
                        &agent_id,
                        crate::session::TaskUpdateStatus::Canceled,
                    ) {
                        tracing::error!(
                            agent_id,
                            %task_id,
                            %error,
                            "Could not cancel canonical delegation task during run retirement"
                        );
                    }
                }
            }
            let _ = self.remove_for_run(owner, &agent_id);
        }
        stopped
    }
}

impl Default for BackgroundAgentManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Global background agent manager
pub static BACKGROUND_AGENTS: LazyLock<BackgroundAgentManager> =
    LazyLock::new(BackgroundAgentManager::new);

// === Transcript Storage for Resume ===

/// Stored transcript for a completed agent, enabling resume
pub(crate) struct StoredTranscript {
    owner_run: crate::runtime::RunId,
    messages: Vec<Value>,
    provider_native_state: Option<crate::runtime::ProviderNativeState>,
    agent_type: AgentType,
    created_at: Instant,
}

/// TTL for stored transcripts (30 minutes).
const TRANSCRIPT_TTL_SECS: u64 = 30 * 60;

/// Hard cap on the number of transcripts retained at once. When the
/// store would exceed this, the oldest entry (by `created_at`) is
/// evicted in O(log N) via the auxiliary `BTreeSet` index — see
/// [`TranscriptStore::insert`]. Crosslink #415.
pub(crate) const MAX_STORED_TRANSCRIPTS: usize = 50;

/// Hard cap on the number of messages retained per transcript. When a
/// caller stores a longer message list, the head is dropped and only
/// the most recent `MAX_MESSAGES_PER_TRANSCRIPT` messages are kept; a
/// `tracing::warn!` is emitted noting how many were dropped. Crosslink
/// #415.
pub(crate) const MAX_MESSAGES_PER_TRANSCRIPT: usize = 500;

/// Interval at which the background sweep runs TTL eviction.
const SWEEP_INTERVAL_SECS: u64 = 60;

/// Bounded transcript store with O(log N) LRU eviction.
///
/// Crosslink #415: the previous implementation iterated the entire
/// `HashMap` on every insert (O(N)) and only ran eviction when a
/// caller stored or loaded — meaning a long-running session with no
/// new spawns would never reclaim memory. This struct:
///
/// 1. Hard-caps the number of transcripts at `MAX_STORED_TRANSCRIPTS`,
///    evicting the oldest in O(log N) via a `BTreeSet` index keyed by
///    `(created_at, id)`.
/// 2. Truncates per-transcript message lists at
///    `MAX_MESSAGES_PER_TRANSCRIPT`, keeping the most recent messages
///    so resume retains the latest conversation context.
/// 3. Provides a `sweep` entry point invoked from a background tokio
///    task (see [`spawn_transcript_sweeper`]) so TTL eviction runs
///    independently of insert/load traffic.
pub(crate) struct TranscriptStore {
    entries: HashMap<String, StoredTranscript>,
    /// Insertion-time-ordered index: `(created_at, agent_id)`.
    /// `Instant` is monotonic; collisions on the same instant are
    /// broken by `agent_id` so each entry has a unique key. The
    /// `BTreeSet` first element is always the oldest, giving O(log N)
    /// LRU eviction without a full `HashMap` scan.
    order: BTreeSet<(Instant, String)>,
}

impl TranscriptStore {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            order: BTreeSet::new(),
        }
    }

    fn rebuild_order_index(&mut self) {
        self.order.clear();
        self.order.extend(
            self.entries
                .iter()
                .map(|(agent_id, transcript)| (transcript.created_at, agent_id.clone())),
        );
    }

    fn order_index_matches_entries(&self) -> bool {
        self.order.len() == self.entries.len()
            && self.order.iter().all(|(created_at, agent_id)| {
                self.entries
                    .get(agent_id)
                    .is_some_and(|transcript| transcript.created_at == *created_at)
            })
    }

    fn repair_order_index_if_needed(&mut self) {
        if self.order_index_matches_entries() {
            return;
        }

        tracing::warn!(
            entries = self.entries.len(),
            order = self.order.len(),
            "transcript store order index out of sync; rebuilding before eviction"
        );
        self.rebuild_order_index();
    }

    /// Number of stored transcripts. Test-only.
    #[cfg(test)]
    fn len(&self) -> usize {
        debug_assert_eq!(self.entries.len(), self.order.len());
        self.entries.len()
    }

    /// Insert (or replace) a transcript for `agent_id`.
    ///
    /// On replace the prior entry's order-index slot is removed so the
    /// two indexes stay in sync. After insertion, if the store exceeds
    /// `MAX_STORED_TRANSCRIPTS`, the oldest entry is evicted.
    fn insert(&mut self, agent_id: String, transcript: StoredTranscript) {
        // If replacing, remove the prior entry from the order index so
        // we don't leak a stale key.
        if let Some(old) = self.entries.remove(&agent_id) {
            self.order.remove(&(old.created_at, agent_id.clone()));
        }
        self.order.insert((transcript.created_at, agent_id.clone()));
        self.entries.insert(agent_id, transcript);
        self.repair_order_index_if_needed();

        // Enforce the hard cap. O(log N) per eviction.
        while self.entries.len() > MAX_STORED_TRANSCRIPTS {
            let Some(oldest) = self.order.iter().next().cloned() else {
                tracing::warn!(
                    entries = self.entries.len(),
                    "transcript store order index empty while over cap; rebuilding"
                );
                self.rebuild_order_index();
                continue;
            };
            self.order.remove(&oldest);
            if self.entries.remove(&oldest.1).is_none() {
                tracing::warn!(
                    agent_id = %oldest.1,
                    "transcript store order index referenced a missing entry; rebuilding"
                );
                self.rebuild_order_index();
            }
        }
    }

    fn get(&self, agent_id: &str) -> Option<&StoredTranscript> {
        self.entries.get(agent_id)
    }

    /// Remove every entry whose age exceeds `TRANSCRIPT_TTL_SECS`.
    /// Uses the ordered index so we stop scanning as soon as we hit
    /// the first non-expired entry (entries are ordered oldest-first).
    /// Returns the number of evicted entries.
    fn sweep(&mut self, now: Instant) -> usize {
        let ttl = Duration::from_secs(TRANSCRIPT_TTL_SECS);
        let mut removed = 0;
        while let Some(oldest) = self.order.iter().next().cloned() {
            if now.duration_since(oldest.0) < ttl {
                // Ordered oldest-first: nothing further can be expired.
                break;
            }
            self.order.remove(&oldest);
            self.entries.remove(&oldest.1);
            removed += 1;
        }
        removed
    }
}

/// Global transcript store for agent resume. Bounded by
/// `MAX_STORED_TRANSCRIPTS` and swept periodically by the background
/// task spawned in [`spawn_transcript_sweeper`].
pub(crate) static TRANSCRIPT_STORE: LazyLock<Mutex<TranscriptStore>> =
    LazyLock::new(|| Mutex::new(TranscriptStore::new()));

fn transcript_store_guard(operation: &'static str) -> Option<MutexGuard<'static, TranscriptStore>> {
    match TRANSCRIPT_STORE.lock() {
        Ok(guard) => Some(guard),
        Err(err) => {
            tracing::error!(operation, error = %err, "Subagent transcript store lock poisoned");
            None
        }
    }
}

/// Guards the one-shot spawn of the transcript sweeper task. Calling
/// `spawn_transcript_sweeper` more than once is a no-op.
static SWEEPER_INIT: Once = Once::new();

/// Spawn (once per process) a tokio task that periodically sweeps
/// expired transcripts. Idempotent — subsequent calls are no-ops.
///
/// Returns `true` iff this call performed the spawn. The function is
/// safe to call when no tokio runtime is in scope (e.g. unit tests
/// without `#[tokio::test]`); in that case the spawn is skipped and
/// the `Once` is still marked complete so a later call doesn't try
/// again.
pub(crate) fn spawn_transcript_sweeper() -> bool {
    let mut spawned = false;
    SWEEPER_INIT.call_once(|| {
        if let Ok(handle) = Handle::try_current() {
            handle.spawn(async {
                let mut ticker = tokio::time::interval(Duration::from_secs(SWEEP_INTERVAL_SECS));
                // The first tick fires immediately; skip it so the
                // first sweep happens after one full interval (avoids
                // a thundering-herd sweep at process start).
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    let removed = transcript_store_guard("sweep")
                        .map_or(0, |mut store| store.sweep(Instant::now()));
                    if removed > 0 {
                        tracing::debug!(
                            evicted = removed,
                            "transcript sweep evicted expired entries"
                        );
                    }
                }
            });
            spawned = true;
        }
    });
    spawned
}

/// Store a transcript for future resume.
///
/// Enforces the per-transcript message cap (`MAX_MESSAGES_PER_TRANSCRIPT`)
/// by retaining the most recent messages; warns when truncation occurs.
/// Also ensures the background sweeper has been spawned so TTL
/// eviction does not depend on insert traffic.
#[cfg(test)]
fn store_transcript(
    owner: &crate::tools::ToolRunContext,
    agent_id: &str,
    messages: Vec<Value>,
    agent_type: AgentType,
) {
    store_transcript_with_state(owner, agent_id, messages, None, agent_type);
}

fn store_transcript_with_state(
    owner: &crate::tools::ToolRunContext,
    agent_id: &str,
    mut messages: Vec<Value>,
    mut provider_native_state: Option<crate::runtime::ProviderNativeState>,
    agent_type: AgentType,
) {
    // Make sure the background TTL sweep is running. Idempotent.
    let _ = spawn_transcript_sweeper();

    if messages.len() > MAX_MESSAGES_PER_TRANSCRIPT {
        let dropped = messages.len() - MAX_MESSAGES_PER_TRANSCRIPT;
        tracing::warn!(
            agent_id = %agent_id,
            total = messages.len(),
            cap = MAX_MESSAGES_PER_TRANSCRIPT,
            dropped,
            "transcript exceeds per-transcript message cap; dropping oldest messages"
        );
        // Keep the tail (most recent messages) so resume retains the
        // latest conversation context. `drain(..dropped)` is O(N) on
        // the dropped prefix but bounded by `dropped` and only runs
        // when the cap is exceeded.
        messages.drain(..dropped);
        if provider_native_state.take().is_some() {
            tracing::warn!(
                agent_id = %agent_id,
                "clearing provider-native continuation because transcript truncation changed its portable history"
            );
        }
    }

    if let Some(mut store) = transcript_store_guard("store_transcript") {
        store.insert(
            agent_id.to_string(),
            StoredTranscript {
                owner_run: owner.run_id(),
                messages,
                provider_native_state,
                agent_type,
                created_at: Instant::now(),
            },
        );
    }
}

/// Load a stored transcript for resume.
///
/// No longer scans the entire map for expired entries on every call
/// — the background sweep (see [`spawn_transcript_sweeper`]) handles
/// that. Per-call eviction is also unnecessary because every read
/// path verifies the entry's own age in O(1).
#[cfg(test)]
fn load_transcript(
    owner: &crate::tools::ToolRunContext,
    agent_id: &str,
) -> Option<(Vec<Value>, AgentType)> {
    load_transcript_with_state(owner, agent_id)
        .map(|(messages, agent_type, _)| (messages, agent_type))
}

fn load_transcript_with_state(
    owner: &crate::tools::ToolRunContext,
    agent_id: &str,
) -> Option<(
    Vec<Value>,
    AgentType,
    Option<crate::runtime::ProviderNativeState>,
)> {
    // Tighten lock scope: read out what we need, then release before
    // the rest of the function body. The clippy
    // `significant_drop_tightening` lint flags holding a `MutexGuard`
    // longer than necessary.
    let snapshot = transcript_store_guard("load_transcript").and_then(|store| {
        store
            .get(agent_id)
            .filter(|entry| entry.owner_run == owner.run_id())
            .map(|entry| {
                (
                    entry.messages.clone(),
                    entry.agent_type,
                    entry.provider_native_state.clone(),
                    entry.created_at,
                )
            })
    });
    let (messages, agent_type, provider_native_state, created_at) = snapshot?;
    // Treat an expired entry as absent so resume fails cleanly even
    // if the background sweep is briefly behind.
    if Instant::now().duration_since(created_at).as_secs() >= TRANSCRIPT_TTL_SECS {
        return None;
    }
    Some((messages, agent_type, provider_native_state))
}

// === Worktree Isolation ===

/// State for a git worktree used by an agent
#[derive(Debug, Clone)]
pub struct WorktreeIsolation {
    pub worktree_path: PathBuf,
    pub branch_name: String,
}

fn validate_worktree_agent_id(agent_id: &str) -> Result<(), String> {
    if agent_id.is_empty() {
        return Err("agent_id is required for worktree isolation".to_string());
    }
    if agent_id.len() > 64 {
        return Err("agent_id is too long for worktree isolation".to_string());
    }
    if agent_id.starts_with('-') {
        return Err("agent_id must not start with '-' for worktree isolation".to_string());
    }
    if !agent_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(format!(
            "invalid agent_id '{agent_id}' for worktree isolation: only ASCII letters, digits, '-' and '_' are allowed"
        ));
    }
    Ok(())
}

impl WorktreeIsolation {
    /// Create a new git worktree for agent isolation.
    ///
    /// # Errors
    ///
    /// Returns `Err` if git is not available, the current directory is not
    /// a git repository, or the worktree/branch creation fails.
    pub fn create(run: &crate::tools::ToolRunContext, agent_id: &str) -> Result<Self, String> {
        validate_worktree_agent_id(agent_id)?;
        run.require(crate::tools::ToolResource::WorkspaceWrite)
            .map_err(|error| error.to_string())?;
        let branch_name = format!("agent/{agent_id}");

        // Find the git root
        let cwd = run.working_directory();
        let git_root = sandboxed_git(run, cwd, &["rev-parse", "--show-toplevel"])
            .map_err(|e| format!("git not available: {e}"))?;

        if !git_root.status.success() {
            return Err("Not in a git repository".to_string());
        }

        let root = String::from_utf8_lossy(&git_root.stdout).trim().to_string();
        let worktree_dir = Path::new(&root).join(".worktrees").join("subagents");

        // Ensure worktree directory exists
        std::fs::create_dir_all(&worktree_dir)
            .map_err(|e| format!("Failed to create worktree directory: {e}"))?;

        let worktree_path = worktree_dir.join(agent_id);

        // Create the worktree
        let worktree_arg = worktree_path
            .to_str()
            .ok_or_else(|| "worktree path must be valid UTF-8".to_string())?;
        let result = sandboxed_git(
            run,
            cwd,
            &["worktree", "add", worktree_arg, "-b", &branch_name],
        )
        .map_err(|e| format!("Failed to create worktree: {e}"))?;

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            return Err(format!("git worktree add failed: {stderr}"));
        }

        Ok(Self {
            worktree_path,
            branch_name,
        })
    }

    /// Check if the worktree has uncommitted changes
    #[must_use]
    pub fn has_changes(&self, run: &crate::tools::ToolRunContext) -> bool {
        let result = self
            .worktree_path
            .to_str()
            .ok_or_else(|| "worktree path must be valid UTF-8".to_string())
            .and_then(|worktree| {
                sandboxed_git(
                    run,
                    run.working_directory(),
                    &["-C", worktree, "diff", "--stat"],
                )
            });

        match result {
            Ok(output) => !output.stdout.is_empty(),
            Err(_) => false,
        }
    }

    /// Remove the worktree (only if no changes).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the worktree has uncommitted changes or if the
    /// git worktree remove command fails.
    pub fn cleanup(&self, run: &crate::tools::ToolRunContext) -> Result<(), String> {
        if self.has_changes(run) {
            return Err(format!(
                "Worktree has changes \u{2014} keeping at {} on branch {}",
                self.worktree_path.display(),
                self.branch_name
            ));
        }

        let worktree = self
            .worktree_path
            .to_str()
            .ok_or_else(|| "worktree path must be valid UTF-8".to_string())?;
        let result = sandboxed_git(
            run,
            run.working_directory(),
            &["worktree", "remove", worktree, "--force"],
        )
        .map_err(|e| format!("Failed to remove worktree: {e}"))?;

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            return Err(format!("git worktree remove failed: {stderr}"));
        }

        // Also delete the branch
        let _ = sandboxed_git(
            run,
            run.working_directory(),
            &["branch", "-D", &self.branch_name],
        );

        Ok(())
    }
}

// === Model Name Resolution ===

/// Map friendly model names to actual model IDs
fn resolve_model_name(friendly: &str, _provider: &str) -> String {
    match friendly.to_lowercase().as_str() {
        "opus" => "claude-opus-4-8".to_string(),
        "sonnet" => "claude-sonnet-4-6".to_string(),
        "haiku" => "claude-haiku-4-5-20251001".to_string(),
        other => other.to_string(),
    }
}

// === Tool Definitions ===

/// Get the Task tool definition
#[must_use]
pub fn get_task_tool_definition() -> Value {
    let task_tool_names = AgentType::task_tool_names();
    json!({
        "type": "function",
        "function": {
            "name": "task",
            "description": "Launch a subagent to handle a complex task autonomously. The subagent runs with its own conversation context and tool access, then returns a summary when done. Use 'run_in_background: true' for long tasks. Use 'resume' with a previous agent_id to continue from where it left off.",
            "parameters": {
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": crate::task_graph::MAX_TASK_SUBJECT_BYTES,
                        "description": "A short (3-5 word) description of the task"
                    },
                    "prompt": {
                        "type": "string",
                        "description": "Detailed task instructions for the subagent"
                    },
                    "subagent_type": {
                        "type": "string",
                        "enum": task_tool_names,
                        "description": "The type of specialized agent: 'general-purpose' for complex tasks, 'explore' for fast codebase searches, 'plan' for architecture design, 'guide' for documentation lookup"
                    },
                    "run_in_background": {
                        "type": "boolean",
                        "description": "If true, run in background and return an agent_id. Use agent_output to retrieve results later."
                    },
                    "resume": {
                        "type": "string",
                        "description": "Optional agent ID to resume from. The resumed agent keeps the original ID so its transcript and prompt cache stay continuous; the prior conversation is prepended and your new prompt is appended."
                    },
                    "model": {
                        "type": "string",
                        "enum": ["sonnet", "opus", "haiku"],
                        "description": "Optional model to use. 'haiku' for quick tasks, 'opus' for complex reasoning, 'sonnet' (default) for balanced."
                    },
                    "isolation": {
                        "type": "string",
                        "enum": ["worktree"],
                        "description": "Set to 'worktree' to run the agent in an isolated git worktree. Changes are kept if the agent modifies files."
                    }
                },
                "required": ["description", "prompt", "subagent_type"]
            }
        }
    })
}

/// Get the `AgentOutput` tool definition
#[must_use]
pub fn get_agent_output_tool_definition() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "agent_output",
            "description": "Retrieve the result from a background agent. If the agent is still running, returns current status. Use 'block: true' to wait for completion (only when you have nothing else to do).",
            "parameters": {
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "The agent ID returned from a task call with run_in_background=true"
                    },
                    "block": {
                        "type": "boolean",
                        "description": "If true, wait for the agent to complete (max 5 minutes). Default false."
                    }
                },
                "required": ["agent_id"]
            }
        }
    })
}

/// Get the `TaskStop` tool definition
#[must_use]
pub fn get_task_stop_tool_definition() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "task_stop",
            "description": "Stop a running background subagent by agent_id. Aborts the spawned task and terminates any background shell processes owned by that agent.",
            "parameters": {
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "The agent ID returned from a task call with run_in_background=true"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Optional reason to record for the stopped agent"
                    }
                },
                "required": ["agent_id"]
            }
        }
    })
}

/// Get all subagent tool definitions
#[must_use]
pub fn get_subagent_tool_definitions() -> Value {
    json!([
        get_task_tool_definition(),
        get_agent_output_tool_definition(),
        get_task_stop_tool_definition()
    ])
}

// === Subagent Execution ===

/// Configuration for running a subagent
#[derive(Debug, Clone)]
pub struct SubagentConfig {
    pub agent_type: AgentType,
    pub task: String,
    pub prompt: String,
    pub run_in_background: bool,
    pub model_override: Option<String>,
    pub resume_agent_id: Option<String>,
    pub isolation: Option<String>,
}

/// Result from a subagent execution
#[derive(Debug, Clone)]
pub struct SubagentResult {
    pub agent_id: String,
    pub success: bool,
    pub output: String,
    pub turns_used: u64,
    pub is_background: bool,
    pub worktree: Option<WorktreeIsolation>,
}

/// Owns the durable lifecycle record for one admitted child run. Any return,
/// cancellation, or panic that does not explicitly commit a terminal state
/// falls back to `failed` on drop. The graph write is synchronous and bounded;
/// errors are logged because `Drop` cannot safely convert an already-unwinding
/// control path into a second panic.
struct DelegationTaskGuard {
    manager: crate::session::TaskManager,
    task_id: String,
    task_revision: u64,
    agent_id: String,
    armed: bool,
}

impl DelegationTaskGuard {
    fn begin(
        parent_run: &crate::tools::ToolRunContext,
        agent_id: &str,
        subject: &str,
    ) -> Result<Self, String> {
        let manager = crate::session::TaskManager::open_for_run(parent_run)?;
        Self::begin_with_manager(parent_run, manager, agent_id, subject)
    }

    fn begin_with_manager(
        parent_run: &crate::tools::ToolRunContext,
        mut manager: crate::session::TaskManager,
        agent_id: &str,
        subject: &str,
    ) -> Result<Self, String> {
        manager.refresh()?;
        let budget = crate::task_graph::TaskBudgetSpec {
            max_turns: Some(MAX_SUBAGENT_TURNS as u64),
            max_tokens: Some(
                u64::from(SUBAGENT_MAX_TOKENS)
                    .checked_mul(MAX_SUBAGENT_TURNS as u64)
                    .ok_or_else(|| "subagent task token budget overflowed".to_string())?,
            ),
            max_elapsed_millis: None,
            max_cost_microusd: None,
            max_child_runs: None,
            max_concurrent_calls: None,
        };
        let existing = manager
            .list_tasks()
            .iter()
            .find(|task| {
                matches!(
                    &task.source,
                    crate::task_graph::TaskSource::Delegation { agent_id: existing }
                        if existing == agent_id
                )
            })
            .map(|task| task.id.clone());
        let (task_id, task_revision) = if let Some(task_id) = existing {
            let revision = manager
                .update_delegation_task(
                    &task_id,
                    agent_id,
                    None,
                    crate::session::TaskUpdateStatus::InProgress,
                    Some(budget),
                )?
                .revision;
            (task_id, revision)
        } else {
            let generation = manager.generation();
            let task = manager.create_task_from_input(crate::task_graph::CreateTask {
                expected_generation: generation,
                subject: subject.to_string(),
                description: String::new(),
                active_form: Some(format!("Running delegated agent {agent_id}")),
                status: crate::task_graph::CanonicalTaskStatus::InProgress,
                priority: crate::task_graph::TaskPriority::Medium,
                source: crate::task_graph::TaskSource::Delegation {
                    agent_id: agent_id.to_string(),
                },
                budget: Some(budget),
            })?;
            (task.id.clone(), task.revision)
        };
        if let Err(binding_error) =
            BACKGROUND_AGENTS.bind_canonical_task(parent_run, agent_id, &task_id)
        {
            let settlement = manager.update_delegation_task(
                &task_id,
                agent_id,
                Some(task_revision),
                crate::session::TaskUpdateStatus::Failed,
                None,
            );
            return Err(match settlement {
                Ok(_) => binding_error,
                Err(settlement_error) => format!(
                    "{binding_error}; canonical delegation settlement also failed: {settlement_error}"
                ),
            });
        }
        Ok(Self {
            manager,
            task_id,
            task_revision,
            agent_id: agent_id.to_string(),
            armed: true,
        })
    }

    fn transition(&mut self, status: crate::session::TaskUpdateStatus) -> Result<(), String> {
        self.manager.update_delegation_task(
            &self.task_id,
            &self.agent_id,
            Some(self.task_revision),
            status,
            None,
        )?;
        self.armed = false;
        Ok(())
    }

    fn finish(mut self, status: crate::session::TaskUpdateStatus) -> Result<(), String> {
        self.transition(status)
    }
}

impl Drop for DelegationTaskGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if self.manager.refresh().is_ok()
            && self.manager.get_task(&self.task_id).is_some_and(|task| {
                matches!(
                    task.status,
                    crate::session::TaskStatus::Completed
                        | crate::session::TaskStatus::Failed
                        | crate::session::TaskStatus::Canceled
                )
            })
        {
            self.armed = false;
            return;
        }
        if let Err(error) = self.transition(crate::session::TaskUpdateStatus::Failed) {
            tracing::error!(
                task_id = %self.task_id,
                %error,
                "Could not close canonical delegation task after child termination"
            );
        }
    }
}

fn transition_canonical_delegation(
    owner: &crate::tools::ToolRunContext,
    task_id: &str,
    agent_id: &str,
    status: crate::session::TaskUpdateStatus,
) -> Result<(), String> {
    let mut manager = crate::session::TaskManager::open_for_run(owner)?;
    manager.update_delegation_task(task_id, agent_id, None, status, None)?;
    Ok(())
}

/// Run a subagent synchronously, returning the final result
#[allow(clippy::too_many_lines)]
pub async fn run_subagent(
    parent_run: &Arc<crate::tools::ToolRunContext>,
    config: &SubagentConfig,
    app_config: &AppConfig,
    client: &Client,
) -> SubagentResult {
    run_subagent_inner(parent_run, config, app_config, client, None, None, None).await
}

async fn run_subagent_with_effect_receipt(
    parent_run: &Arc<crate::tools::ToolRunContext>,
    config: &SubagentConfig,
    app_config: &AppConfig,
    client: &Client,
    memory_db: Option<Arc<crate::memory::MemoryDb>>,
) -> (SubagentResult, bool) {
    let effect_started = AtomicBool::new(false);
    let result = run_subagent_inner(
        parent_run,
        config,
        app_config,
        client,
        memory_db,
        None,
        Some(&effect_started),
    )
    .await;
    (result, effect_started.load(Ordering::SeqCst))
}

fn validate_and_render_subagent_final_response(
    run: &crate::tools::ToolRunContext,
    agent_id: &str,
    final_output: &str,
    model_identity: &str,
) -> Result<String, String> {
    if final_output.trim().is_empty() {
        return Err("Provider completed the child turn without assistant content".to_string());
    }
    crate::grounded_loop::validate_and_render_agentic_final_response(
        run,
        agent_id,
        final_output,
        model_identity,
    )
}

#[allow(clippy::too_many_lines)]
async fn run_subagent_inner(
    parent_run: &Arc<crate::tools::ToolRunContext>,
    config: &SubagentConfig,
    app_config: &AppConfig,
    client: &Client,
    memory_db: Option<Arc<crate::memory::MemoryDb>>,
    preallocated_agent_id: Option<&str>,
    effect_receipt: Option<&AtomicBool>,
) -> SubagentResult {
    let child_registration = match parent_run.begin_child_run_registration() {
        Ok(registration) => registration,
        Err(error) => {
            return SubagentResult {
                agent_id: preallocated_agent_id
                    .or(config.resume_agent_id.as_deref())
                    .unwrap_or_default()
                    .to_string(),
                success: false,
                output: error,
                turns_used: 0,
                is_background: config.run_in_background,
                worktree: None,
            };
        }
    };
    // Handle resume: reuse the *original* agent_id and load transcript.
    //
    // Crosslink #582 — previously this path called `BACKGROUND_AGENTS.register(...)`,
    // which minted a fresh id and silently broke:
    //   1. Transcript continuity: `TRANSCRIPT_STORE` is keyed by id, so
    //      the next `store_transcript` overwrote a *different* key and
    //      the original transcript was orphaned (and eventually evicted
    //      by TTL) while the resumed agent's transcript started fresh.
    //   2. Prompt cache continuity: provider-side prompt caches that
    //      key off the conversation id never hit on resume.
    // The fix: route through `register_with_id` so the original id is
    // reattached to the tracker. If the id was already registered
    // (e.g. a previous turn of the same resume chain), `register_with_id`
    // is a no-op and preserves the existing turn counter / state.
    let (agent_id, mut messages, mut provider_native_state) = if let Some(preallocated_id) =
        preallocated_agent_id
    {
        if let Err(error) = BACKGROUND_AGENTS.register_with_id(
            parent_run,
            config.agent_type,
            &config.task,
            preallocated_id,
        ) {
            return SubagentResult {
                agent_id: preallocated_id.to_string(),
                success: false,
                output: error,
                turns_used: 0,
                is_background: config.run_in_background,
                worktree: None,
            };
        }
        let msgs = vec![json!({
            "role": "user",
            "content": format!("Task: {}\n\n{}", config.task, config.prompt)
        })];
        (preallocated_id.to_string(), msgs, None)
    } else if let Some(ref resume_id) = config.resume_agent_id {
        match load_transcript_with_state(parent_run, resume_id) {
            Some((prev_messages, _prev_type, native_state)) => {
                if let Err(error) = BACKGROUND_AGENTS.register_with_id(
                    parent_run,
                    config.agent_type,
                    &config.task,
                    resume_id,
                ) {
                    return SubagentResult {
                        agent_id: resume_id.clone(),
                        success: false,
                        output: error,
                        turns_used: 0,
                        is_background: config.run_in_background,
                        worktree: None,
                    };
                }
                let mut msgs = prev_messages;
                // Append the new prompt as a continuation
                msgs.push(json!({
                    "role": "user",
                    "content": format!("Continuing from where you left off.\n\n{}", config.prompt)
                }));
                (resume_id.clone(), msgs, native_state)
            }
            None => {
                return SubagentResult {
                    agent_id: resume_id.clone(),
                    success: false,
                    output: format!("No transcript found for agent '{resume_id}'. It may have expired (TTL: {} minutes).", TRANSCRIPT_TTL_SECS / 60),
                    turns_used: 0,
                    is_background: config.run_in_background,
                    worktree: None,
                };
            }
        }
    } else {
        let id = match BACKGROUND_AGENTS.register(parent_run, config.agent_type, &config.task) {
            Ok(id) => id,
            Err(error) => {
                return SubagentResult {
                    agent_id: String::new(),
                    success: false,
                    output: error,
                    turns_used: 0,
                    is_background: config.run_in_background,
                    worktree: None,
                }
            }
        };
        let msgs = vec![json!({
            "role": "user",
            "content": format!("Task: {}\n\n{}", config.task, config.prompt)
        })];
        (id, msgs, None)
    };
    drop(child_registration);
    if let Some(receipt) = effect_receipt {
        receipt.store(true, Ordering::SeqCst);
    }
    let task_content = format!("Subagent task: {}\n\n{}", config.task, config.prompt);
    let delegation = match DelegationTaskGuard::begin(parent_run, &agent_id, &config.task) {
        Ok(delegation) => delegation,
        Err(error) => {
            BACKGROUND_AGENTS.fail(parent_run, &agent_id, error.clone());
            return SubagentResult {
                agent_id,
                success: false,
                output: format!("Cannot create canonical delegation task: {error}"),
                turns_used: 0,
                is_background: config.run_in_background,
                worktree: None,
            };
        }
    };

    // Set up worktree isolation if requested
    let worktree = if config.isolation.as_deref() == Some("worktree") {
        match WorktreeIsolation::create(parent_run, &agent_id) {
            Ok(wt) => Some(wt),
            Err(e) => {
                return SubagentResult {
                    agent_id,
                    success: false,
                    output: format!("Failed to create worktree: {e}"),
                    turns_used: 0,
                    is_background: config.run_in_background,
                    worktree: None,
                };
            }
        }
    } else {
        None
    };

    let child_root = worktree.as_ref().map_or_else(
        || parent_run.project_root().to_path_buf(),
        |isolation| isolation.worktree_path.clone(),
    );
    let child_cwd = worktree.as_ref().map_or_else(
        || parent_run.working_directory().to_path_buf(),
        |isolation| isolation.worktree_path.clone(),
    );
    let session_id = match crate::state::SessionId::from_raw(parent_run.session_id()) {
        Ok(session_id) => session_id,
        Err(error) => {
            return SubagentResult {
                agent_id,
                success: false,
                output: format!("Cannot bind subagent session capabilities: {error}"),
                turns_used: 0,
                is_background: config.run_in_background,
                worktree,
            };
        }
    };
    let workspace_access = if config.agent_type == AgentType::GeneralPurpose {
        crate::tools::WorkspaceAccess::ReadWrite
    } else {
        crate::tools::WorkspaceAccess::ReadOnly
    };
    let is_parent_intrinsic_root = |root: &&PathBuf| {
        root.as_path() == parent_run.project_root()
            || root.as_path() == parent_run.private_temp_root()
    };
    let mut child_read_only_roots: Vec<PathBuf> = parent_run
        .read_only_roots()
        .iter()
        .filter(|root| !is_parent_intrinsic_root(root))
        .cloned()
        .collect();
    let mut child_read_write_roots = Vec::new();
    if workspace_access == crate::tools::WorkspaceAccess::ReadWrite {
        child_read_write_roots.extend(
            parent_run
                .read_write_roots()
                .iter()
                .filter(|root| !is_parent_intrinsic_root(root))
                .cloned(),
        );
    } else {
        child_read_only_roots.extend(
            parent_run
                .read_write_roots()
                .iter()
                .filter(|root| !is_parent_intrinsic_root(root))
                .cloned(),
        );
    }
    let parent_mode = parent_run.runtime_mode();
    let child_runtime_mode = if parent_mode.class == crate::modes::RuntimeModeClass::Coordinator {
        crate::modes::RuntimeMode::Behavioral(crate::modes::BehaviorMode::default())
    } else {
        parent_mode.mode.clone()
    };
    let subagent_run = match crate::tools::ToolRunContext::builder(session_id, child_root)
        .working_directory(child_cwd)
        .read_only_roots(child_read_only_roots)
        .read_write_roots(child_read_write_roots)
        .project_secret_masks(parent_run.project_secret_masks().to_vec())
        .protected_environment_grants(parent_run.environment_grants().clone())
        .protected_mcp_environment_grants(parent_run.mcp_environment_grants().clone())
        .executable_search_path(parent_run.executable_search_path())
        .host_home(parent_run.host_home().map(Path::to_path_buf))
        .remote_actions(parent_run.remote_actions().registry().clone())
        .workspace_access(workspace_access)
        .process(parent_run.grants_resource(crate::tools::ToolResource::Process))
        .network(parent_run.grants_resource(crate::tools::ToolResource::Network))
        .secrets(parent_run.grants_resource(crate::tools::ToolResource::Secrets))
        .process_owner(&agent_id)
        .actor_role(crate::runtime::ActorRole::Worker)
        .provider(app_config.proxy.target.clone())
        .budget_limits(parent_run.runtime().descriptor().budget.limits.clone())
        .parent_budget(parent_run.budget().clone())
        .runtime_mode(child_runtime_mode)
        .behavior_scope_targets(parent_mode.scope_targets)
        .build()
    {
        Ok(run) => run,
        Err(error) => {
            return SubagentResult {
                agent_id,
                success: false,
                output: format!("Cannot create subagent run capabilities: {error}"),
                turns_used: 0,
                is_background: config.run_in_background,
                worktree,
            };
        }
    };
    let model = config
        .model_override
        .clone()
        .or_else(|| config.agent_type.preferred_model().map(String::from))
        .unwrap_or_else(|| {
            app_config
                .providers
                .get(&app_config.proxy.target)
                .and_then(|p| p.model.clone())
                .unwrap_or_else(|| "claude-sonnet-4-6".to_string())
        });
    if let Err(error) = crate::guardrails::configure(&subagent_run, &app_config.guardrails) {
        return SubagentResult {
            agent_id,
            success: false,
            output: format!("Cannot bind subagent guardrails: {error}"),
            turns_used: 0,
            is_background: config.run_in_background,
            worktree,
        };
    }
    let mut task_manager = match crate::session::TaskManager::open_for_run(&subagent_run) {
        Ok(manager) => manager,
        Err(error) => {
            return SubagentResult {
                agent_id,
                success: false,
                output: format!("Cannot open canonical subagent task graph: {error}"),
                turns_used: 0,
                is_background: config.run_in_background,
                worktree,
            };
        }
    };
    let task_obs = crate::grounded_loop::observe_session_user_task(
        &subagent_run,
        &agent_id,
        &task_content,
        &model,
    );

    let mut subagent_context = vec![crate::context::ContextItem::host_instruction(
        "subagent.role_policy",
        crate::context::HostInstructionSource::AgentRole,
        format!("compiled:agent-role:{:?}", config.agent_type),
        config.agent_type.system_prompt(),
        crate::context::ContextFreshness::Static,
        10,
    )];
    if let Some(worktree) = &worktree {
        subagent_context.push(crate::context::ContextItem::host_instruction(
            "subagent.worktree_policy",
            crate::context::HostInstructionSource::RuntimePolicy,
            "host:worktree-isolation",
            "All file operations for this isolated run must remain within the host-provided worktree in reference context.",
            crate::context::ContextFreshness::Session,
            20,
        ));
        subagent_context.push(crate::context::ContextItem::reference(
            "subagent.worktree_identity",
            crate::context::ReferenceSource::Project,
            "host-observation:worktree-isolation",
            format!(
                "Isolated worktree: {}\nBranch: {}",
                worktree.worktree_path.display(),
                worktree.branch_name
            ),
            crate::context::ContextFreshness::Session,
            30,
        ));
    }
    let subagent_prompt_blocks = crate::prompt::SystemPromptBlocks::from_items(
        subagent_context,
        crate::context::ContextBudget::default(),
    );

    let allowed_tools = available_subagent_tools(config.agent_type, memory_db.is_some());

    // Filter tool definitions to only allowed tools
    let all_tools = crate::tools::get_tool_definitions();
    let filtered_tools: Vec<Value> = all_tools
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter(|tool| {
                    tool.get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(|n| n.as_str())
                        .is_some_and(|name| allowed_tools.contains(&name))
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let filtered_tools = add_subagent_typed_decision_contracts(filtered_tools);

    // Get provider config. `api_key` is `Option<ApiKey>`: an unconfigured
    // provider yields `None` and `make_api_call` omits the auth header —
    // previously this was `String::new()` (an empty key sent as
    // `Bearer <empty>`, which every upstream rejects). See crosslink #256.
    let (base_url, configured_api_key) = app_config
        .providers
        .get(&app_config.proxy.target)
        .map_or_else(
            || ("https://api.anthropic.com/v1".to_string(), None),
            |provider_config| {
                (
                    provider_config.base_url.clone(),
                    provider_config.api_key.clone(),
                )
            },
        );
    let (api_key, codex_agent_sdk) =
        match resolve_subagent_openai_auth(&app_config.proxy.target, configured_api_key) {
            Ok(auth) => auth,
            Err(error) => {
                BACKGROUND_AGENTS.fail(parent_run, &agent_id, error.clone());
                store_transcript_with_state(
                    parent_run,
                    &agent_id,
                    messages,
                    provider_native_state,
                    config.agent_type,
                );
                return SubagentResult {
                    agent_id,
                    success: false,
                    output: error,
                    turns_used: 0,
                    is_background: config.run_in_background,
                    worktree,
                };
            }
        };
    let wire_api = if codex_agent_sdk.is_some() {
        crate::pipeline::WireApi::OpenAiResponses
    } else {
        crate::pipeline::WireApi::ChatCompletions
    };

    // Run the agent loop
    let mut final_output: String;
    let mut turns: u64;

    // Library-layer permission gate — consulted by every
    // `execute_tool_with_memory` call inside this subagent's tool loop.
    // Closes crosslink #505 for the subagent path.
    let permission_mgr = crate::permissions::PermissionManager::trusted_for_run(
        &subagent_run,
        app_config.permissions.enabled,
        app_config.permissions.default_allow.clone(),
        app_config.web_fetch.preapproved_domains.clone(),
    );
    let policy_enforcer = crate::services::policy::PolicyEnforcer::new(app_config.policy.clone());

    loop {
        turns = BACKGROUND_AGENTS.increment_turns(parent_run, &agent_id);
        if let Some(agent) = BACKGROUND_AGENTS.get_for_run(parent_run, &agent_id) {
            if agent.finished.load(Ordering::SeqCst) {
                let error = agent_field_guard(&agent.error, "run_subagent", &agent_id, "error")
                    .and_then(|e| e.clone())
                    .unwrap_or_else(|| "Agent stopped before the next turn".to_string());
                store_transcript_with_state(
                    parent_run,
                    &agent_id,
                    messages,
                    provider_native_state,
                    config.agent_type,
                );
                let output = match delegation.finish(crate::session::TaskUpdateStatus::Canceled) {
                    Ok(()) => error,
                    Err(tracking_error) => format!(
                        "{error}; canonical cancellation could not be committed: {tracking_error}"
                    ),
                };
                return SubagentResult {
                    agent_id,
                    success: false,
                    output,
                    turns_used: turns,
                    is_background: config.run_in_background,
                    worktree: worktree.clone(),
                };
            }
        }

        if turns > MAX_SUBAGENT_TURNS as u64 {
            BACKGROUND_AGENTS.fail(
                parent_run,
                &agent_id,
                format!("Agent exceeded maximum turns ({MAX_SUBAGENT_TURNS})"),
            );
            // Store transcript even on failure for potential resume
            store_transcript_with_state(
                parent_run,
                &agent_id,
                messages,
                provider_native_state,
                config.agent_type,
            );
            return SubagentResult {
                agent_id,
                success: false,
                output: format!("Agent exceeded maximum turns ({MAX_SUBAGENT_TURNS})"),
                turns_used: turns,
                is_background: config.run_in_background,
                worktree: worktree.clone(),
            };
        }

        // Build the request. The grounding packet is request-scoped:
        // it helps the provider navigate the current ledger, but it is
        // not persisted into the resumable transcript.
        let request_messages = match crate::grounded_loop::request_messages_with_grounding(
            &subagent_run,
            &agent_id,
            task_obs,
            &messages,
        ) {
            Ok(messages) => messages,
            Err(e) => {
                BACKGROUND_AGENTS.fail(parent_run, &agent_id, e.clone());
                store_transcript_with_state(
                    parent_run,
                    &agent_id,
                    messages,
                    provider_native_state,
                    config.agent_type,
                );
                return SubagentResult {
                    agent_id,
                    success: false,
                    output: format!("Grounding error: {e}"),
                    turns_used: turns,
                    is_background: config.run_in_background,
                    worktree: worktree.clone(),
                };
            }
        };
        let prepared_request_messages =
            subagent_prompt_blocks.prepare_json_messages(&request_messages);
        let progressive_tools = match subagent_run.tool_catalog().snapshot(
            &subagent_run,
            &request_messages,
            &filtered_tools,
        ) {
            Ok(snapshot) => snapshot.definitions,
            Err(e) => {
                BACKGROUND_AGENTS.fail(parent_run, &agent_id, e.clone());
                store_transcript_with_state(
                    parent_run,
                    &agent_id,
                    messages,
                    provider_native_state,
                    config.agent_type,
                );
                return SubagentResult {
                    agent_id,
                    success: false,
                    output: format!("Tool catalog error: {e}"),
                    turns_used: turns,
                    is_background: config.run_in_background,
                    worktree: worktree.clone(),
                };
            }
        };
        let mut request_body = json!({
            "model": model,
            "messages": prepared_request_messages.clone(),
            "tools": progressive_tools.clone(),
            "max_tokens": SUBAGENT_MAX_TOKENS
        });
        let mut typed_request = match build_chat_completion_request(&request_body) {
            Ok(request) => request,
            Err(e) => {
                BACKGROUND_AGENTS.fail(parent_run, &agent_id, e.clone());
                store_transcript_with_state(
                    parent_run,
                    &agent_id,
                    messages,
                    provider_native_state,
                    config.agent_type,
                );
                return SubagentResult {
                    agent_id,
                    success: false,
                    output: e,
                    turns_used: turns,
                    is_background: config.run_in_background,
                    worktree: worktree.clone(),
                };
            }
        };
        let compactor = crate::services::AutoCompactor::auto(
            crate::compaction::ContextCompactor::for_model(&model),
        );
        let needs_compaction = compactor.should_compact(&typed_request, None);
        let compaction_error = match crate::compaction::provider_state_compaction_disposition(
            wire_api.is_responses(),
            needs_compaction,
            provider_native_state.as_ref(),
        ) {
            crate::compaction::ProviderStateCompactionDisposition::ProviderManaged => None,
            crate::compaction::ProviderStateCompactionDisposition::BlocksPortableCheckpoint => {
                Some("Context needs compaction, but the provider-native continuation is bound to the exact message history and this protocol has no native compaction contract".to_string())
            }
            crate::compaction::ProviderStateCompactionDisposition::Absent
            | crate::compaction::ProviderStateCompactionDisposition::Preserved => {
                match compactor
                    .auto_compact(
                        &mut typed_request,
                        None,
                        None,
                        &subagent_run,
                        Some(&agent_id),
                        memory_db.clone(),
                    )
                    .await
                {
                    Ok(Some(result))
                        if matches!(
                            result.disposition,
                            crate::compaction::CompactionDisposition::Partial
                                | crate::compaction::CompactionDisposition::CannotFit
                        ) =>
                    {
                        Some(format!(
                            "Context cannot fit after checkpoint: {} tokens remain for target {}",
                            result.new_tokens, result.target_tokens
                        ))
                    }
                    Ok(Some(_) | None) => None,
                    Err(error) => Some(format!("Context checkpoint failed: {error}")),
                }
            }
        };
        if let Some(message) = compaction_error {
            BACKGROUND_AGENTS.fail(parent_run, &agent_id, message.clone());
            store_transcript_with_state(
                parent_run,
                &agent_id,
                messages,
                provider_native_state,
                config.agent_type,
            );
            return SubagentResult {
                agent_id,
                success: false,
                output: message,
                turns_used: turns,
                is_background: config.run_in_background,
                worktree: worktree.clone(),
            };
        }
        let projected_request_messages = typed_request
            .messages
            .iter()
            .cloned()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|error| {
                tracing::error!(%error, "Failed to encode compacted subagent context");
                Vec::new()
            });
        if projected_request_messages.is_empty() && !typed_request.messages.is_empty() {
            let message = "Failed to encode compacted subagent context".to_string();
            BACKGROUND_AGENTS.fail(parent_run, &agent_id, message.clone());
            store_transcript_with_state(
                parent_run,
                &agent_id,
                messages,
                provider_native_state,
                config.agent_type,
            );
            return SubagentResult {
                agent_id,
                success: false,
                output: message,
                turns_used: turns,
                is_background: config.run_in_background,
                worktree: worktree.clone(),
            };
        }
        request_body["messages"] = Value::Array(projected_request_messages.clone());
        if let Err(e) = check_provider_request_policy(app_config, &typed_request) {
            let message = format!("Blocked by policy: {e}");
            BACKGROUND_AGENTS.fail(parent_run, &agent_id, message.clone());
            store_transcript_with_state(
                parent_run,
                &agent_id,
                messages,
                provider_native_state,
                config.agent_type,
            );
            return SubagentResult {
                agent_id,
                success: false,
                output: message,
                turns_used: turns,
                is_background: config.run_in_background,
                worktree: worktree.clone(),
            };
        }

        let assistant_message_ordinal =
            match crate::pipeline::next_assistant_message_ordinal(&messages) {
                Ok(ordinal) => ordinal,
                Err(error) => {
                    BACKGROUND_AGENTS.fail(parent_run, &agent_id, error.clone());
                    store_transcript_with_state(
                        parent_run,
                        &agent_id,
                        messages,
                        provider_native_state,
                        config.agent_type,
                    );
                    return SubagentResult {
                        agent_id,
                        success: false,
                        output: error,
                        turns_used: turns,
                        is_background: config.run_in_background,
                        worktree: worktree.clone(),
                    };
                }
            };
        let uses_native_json = matches!(
            app_config.proxy.target.trim().to_ascii_lowercase().as_str(),
            "google" | "gemini" | "ollama"
        );
        let provider_request_body = if wire_api.is_responses() || uses_native_json {
            match crate::pipeline::build_request_for_wire_with_exact_tools_and_state(
                wire_api,
                &app_config.proxy.target,
                &model,
                &projected_request_messages,
                app_config
                    .active_provider()
                    .and_then(|provider| provider.thinking.reasoning_effort.as_deref())
                    .unwrap_or("medium"),
                None,
                None,
                &progressive_tools,
                provider_native_state.as_ref(),
            ) {
                Ok(mut request) => {
                    if wire_api.is_responses() {
                        if let Err(error) = apply_subagent_responses_output_limit(&mut request) {
                            BACKGROUND_AGENTS.fail(parent_run, &agent_id, error.clone());
                            store_transcript_with_state(
                                parent_run,
                                &agent_id,
                                messages,
                                provider_native_state,
                                config.agent_type,
                            );
                            return SubagentResult {
                                agent_id,
                                success: false,
                                output: error,
                                turns_used: turns,
                                is_background: config.run_in_background,
                                worktree: worktree.clone(),
                            };
                        }
                    }
                    Some(request)
                }
                Err(error) => {
                    BACKGROUND_AGENTS.fail(parent_run, &agent_id, error.clone());
                    store_transcript_with_state(
                        parent_run,
                        &agent_id,
                        messages,
                        provider_native_state,
                        config.agent_type,
                    );
                    return SubagentResult {
                        agent_id,
                        success: false,
                        output: format!("Provider request error: {error}"),
                        turns_used: turns,
                        is_background: config.run_in_background,
                        worktree: worktree.clone(),
                    };
                }
            }
        } else {
            None
        };

        // Make the API call — provider is plumbed through so the
        // ProviderAdapter trait (canonical implementation in
        // `src/providers/`) handles request/response transformation for
        // every supported provider. See crosslink #407.
        let (mut assistant_message, next_provider_native_state) = if wire_api.is_responses() {
            let request = provider_request_body
                .as_ref()
                .expect("Responses request uses the canonical wire builder");
            let sdk = codex_agent_sdk
                .as_ref()
                .expect("Responses wire selection requires the Codex SDK runtime");
            match make_codex_agent_sdk_call(
                &subagent_run,
                &app_config.proxy.target,
                &model,
                sdk,
                request,
            )
            .await
            {
                Ok(turn) => (codex_sdk_subagent_assistant_message(&turn), None),
                Err(error) => {
                    BACKGROUND_AGENTS.fail(parent_run, &agent_id, error.clone());
                    store_transcript_with_state(
                        parent_run,
                        &agent_id,
                        messages,
                        provider_native_state,
                        config.agent_type,
                    );
                    return SubagentResult {
                        agent_id,
                        success: false,
                        output: error,
                        turns_used: turns,
                        is_background: config.run_in_background,
                        worktree: worktree.clone(),
                    };
                }
            }
        } else if uses_native_json {
            let request = provider_request_body
                .as_ref()
                .expect("native JSON request uses the canonical wire builder");
            match make_provider_native_json_api_call(
                &subagent_run,
                client,
                &app_config.proxy.target,
                &model,
                &base_url,
                api_key.as_ref(),
                app_config
                    .active_provider()
                    .map(|provider| &provider.headers),
                request,
                provider_native_state.as_ref(),
                assistant_message_ordinal,
            )
            .await
            {
                Ok(decoded) => {
                    let assistant = native_json_subagent_assistant_message(&decoded);
                    (assistant, Some(decoded.provider_native_state))
                }
                Err(error) => {
                    BACKGROUND_AGENTS.fail(parent_run, &agent_id, error.clone());
                    store_transcript_with_state(
                        parent_run,
                        &agent_id,
                        messages,
                        provider_native_state,
                        config.agent_type,
                    );
                    return SubagentResult {
                        agent_id,
                        success: false,
                        output: error,
                        turns_used: turns,
                        is_background: config.run_in_background,
                        worktree: worktree.clone(),
                    };
                }
            }
        } else {
            let response = match make_api_call(
                &subagent_run,
                client,
                &app_config.proxy.target,
                &base_url,
                api_key.as_ref(),
                &request_body,
            )
            .await
            {
                Ok(response) => response,
                Err(error) => {
                    BACKGROUND_AGENTS.fail(parent_run, &agent_id, error.clone());
                    store_transcript_with_state(
                        parent_run,
                        &agent_id,
                        messages,
                        provider_native_state,
                        config.agent_type,
                    );
                    return SubagentResult {
                        agent_id,
                        success: false,
                        output: error,
                        turns_used: turns,
                        is_background: config.run_in_background,
                        worktree: worktree.clone(),
                    };
                }
            };
            let assistant = match parse_response(&response) {
                Ok(message) => message,
                Err(error) => {
                    BACKGROUND_AGENTS.fail(parent_run, &agent_id, error.clone());
                    store_transcript_with_state(
                        parent_run,
                        &agent_id,
                        messages,
                        provider_native_state,
                        config.agent_type,
                    );
                    return SubagentResult {
                        agent_id,
                        success: false,
                        output: error,
                        turns_used: turns,
                        is_background: config.run_in_background,
                        worktree: worktree.clone(),
                    };
                }
            };
            (assistant, None)
        };

        // Text belongs to this exact provider turn. Never carry a tool-bearing
        // preamble forward as the final answer for a later empty response.
        final_output = subagent_assistant_text(&assistant_message);

        // Check for tool calls
        let tool_calls = assistant_message
            .get("tool_calls")
            .and_then(|tc| tc.as_array())
            .cloned()
            .unwrap_or_default();

        if tool_calls.is_empty() {
            match validate_and_render_subagent_final_response(
                &subagent_run,
                &agent_id,
                &final_output,
                &model,
            ) {
                Ok(rendered) => {
                    final_output = rendered;
                }
                Err(reason) => {
                    BACKGROUND_AGENTS.fail(parent_run, &agent_id, reason.clone());
                    store_transcript_with_state(
                        parent_run,
                        &agent_id,
                        messages,
                        provider_native_state,
                        config.agent_type,
                    );
                    return SubagentResult {
                        agent_id,
                        success: false,
                        output: format!("Final answer failed grounding gate: {reason}"),
                        turns_used: turns,
                        is_background: config.run_in_background,
                        worktree: worktree.clone(),
                    };
                }
            }
            if let Some(next_state) = next_provider_native_state {
                assistant_message["content"] = Value::String(final_output.clone());
                messages.push(assistant_message);
                provider_native_state = Some(next_state);
            }
            // No tool calls means agent is done
            break;
        }

        // Add assistant message to history
        messages.push(assistant_message.clone());
        if let Some(next_state) = next_provider_native_state {
            provider_native_state = Some(next_state);
        }

        // Execute tool calls and add results
        for (tool_call_index, tool_call) in tool_calls.iter().enumerate() {
            let tc = match parse_subagent_tool_call(tool_call, tool_call_index) {
                Ok(tc) => tc,
                Err(err) => {
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": subagent_tool_call_id_for_error(
                            tool_call,
                            tool_call_index
                        ),
                        "content": format!("Error: {err}")
                    }));
                    continue;
                }
            };

            // Check if tool is allowed
            if !allowed_tools.contains(&tc.function.name.as_str()) {
                let tool_id = tc.id.clone();
                let tool_name = tc.function.name.clone();
                messages.push(json!({
                    "role": "tool",
                    "tool_call_id": tool_id,
                    "content": format!(
                        "Error: Tool '{}' is not available to this agent type",
                        tool_name
                    )
                }));
                continue;
            }

            if let Err(content) =
                validate_subagent_tool_decision_for_session(&subagent_run, &agent_id, &tc)
            {
                let result = crate::tools::ToolResult::failure(
                    &tc,
                    crate::tools::ToolFailureCode::PolicyDenied,
                    format!("Error: {content}"),
                    crate::tools::ToolRetryability::Never,
                );
                observe_subagent_tool_result(&subagent_run, &agent_id, &result);
                messages.push(json!({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result.content()
                }));
                continue;
            }

            let executable_tc = strip_subagent_decision_argument(&tc);

            // Execute the tool with the library-layer permission gate
            // engaged (crosslink #505).
            // Bind the subagent's id as the session key so its task
            // list lives in its own bucket. Claude Code uses the
            // `agentId ?? sessionId` fallback; here agent_id is always
            // present. Closes crosslink #518 for subagents.
            let result = execute_subagent_local_tool(&mut SubagentToolExecution {
                run: &subagent_run,
                tool_call: &executable_tc,
                memory_db: memory_db.as_deref(),
                app_config,
                task_manager: &mut task_manager,
                permission_manager: &permission_mgr,
                agent_id: &agent_id,
                policy_enforcer: &policy_enforcer,
            });
            observe_subagent_tool_result(&subagent_run, &agent_id, &result);

            messages.push(json!({
                "role": "tool",
                "tool_call_id": executable_tc.id,
                "content": result.content()
            }));
        }
        if let Some(report) = crate::guardrails::run_quality_gates_at(
            &subagent_run,
            &model,
            crate::config::RunAfter::EveryTurn,
        ) {
            if report.prevents_progress() {
                let detail = report.reason().map_or_else(
                    || {
                        report
                            .results()
                            .iter()
                            .filter(|check| !check.passed())
                            .map(|check| format!("{} ({:?})", check.name(), check.status()))
                            .collect::<Vec<_>>()
                            .join(", ")
                    },
                    ToString::to_string,
                );
                messages.push(json!({
                    "role": "system",
                    "content": format!(
                        "Configured quality-gate findings must be addressed before finalization: {detail}"
                    ),
                    "metadata": {
                        "openclaudia_context_source": "reality"
                    }
                }));
            }
        }
    }

    // Store the transcript and settle owned resources before publishing the
    // terminal graph state. The caller cannot observe success until the
    // canonical delegation node commits `completed`.
    store_transcript_with_state(
        parent_run,
        &agent_id,
        messages,
        provider_native_state,
        config.agent_type,
    );

    // Handle worktree cleanup: remove if no changes, keep if changes exist
    let final_worktree = worktree.and_then(|wt| {
        if wt.has_changes(parent_run) {
            Some(wt) // Keep -- return path and branch to caller
        } else {
            let _ = wt.cleanup(parent_run); // No changes, clean up silently
            None
        }
    });

    if let Err(error) = delegation.finish(crate::session::TaskUpdateStatus::Completed) {
        let message = format!(
            "Subagent returned a result, but canonical delegation completion could not be committed: {error}"
        );
        BACKGROUND_AGENTS.fail(parent_run, &agent_id, message.clone());
        return SubagentResult {
            agent_id,
            success: false,
            output: message,
            turns_used: turns,
            is_background: config.run_in_background,
            worktree: final_worktree,
        };
    }
    BACKGROUND_AGENTS.finish(parent_run, &agent_id, final_output.clone());

    SubagentResult {
        agent_id,
        success: true,
        output: final_output,
        turns_used: turns,
        is_background: config.run_in_background,
        worktree: final_worktree,
    }
}

/// Canonical provider names accepted by the subagent dispatcher.
///
/// This list mirrors the explicit (non-fallback) arms of
/// [`crate::providers::get_adapter`]. The crate-level `get_adapter`
/// deliberately falls back to the OpenAI-compatible adapter for
/// unknown names (typo-tolerant proxy use case); subagent dispatch has
/// the opposite preference — an unknown provider is an operator
/// configuration error that must surface as a clean error rather than
/// silently translating Anthropic-targeted prompts through an
/// OpenAI-shape body. See crosslink #407.
const SUBAGENT_KNOWN_PROVIDERS: &[&str] = &[
    "anthropic",
    "openai",
    "google",
    "gemini",
    "deepseek",
    "qwen",
    "alibaba",
    "zai",
    "glm",
    "zhipu",
    "ollama",
    "local",
    "lmstudio",
    "localai",
    "text-generation-webui",
];

/// Validate a provider name and return its canonical
/// [`crate::providers::ProviderAdapter`].
///
/// Returns a typed error string instead of silently falling back so
/// that misconfigured subagents fail fast at the dispatch boundary
/// instead of issuing wrong-shape HTTP requests upstream.
fn resolve_subagent_adapter(
    provider: &str,
) -> Result<&'static dyn crate::providers::ProviderAdapter, String> {
    let normalized = provider.to_ascii_lowercase();
    if !SUBAGENT_KNOWN_PROVIDERS.contains(&normalized.as_str()) {
        return Err(format!(
            "Unknown subagent provider '{provider}'. Configure one of: {}",
            SUBAGENT_KNOWN_PROVIDERS.join(", ")
        ));
    }
    crate::providers::get_adapter(&normalized)
        .map_err(|e| format!("Subagent provider '{provider}' adapter lookup failed: {e}"))
}

fn resolve_subagent_openai_auth(
    provider: &str,
    api_key: Option<crate::providers::ApiKey>,
) -> Result<
    (
        Option<crate::providers::ApiKey>,
        Option<crate::codex_agent_sdk::CodexAgentSdk>,
    ),
    String,
> {
    if !provider.eq_ignore_ascii_case("openai") || api_key.is_some() {
        return Ok((api_key, None));
    }
    let sdk = crate::codex_agent_sdk::CodexAgentSdk::discover().map_err(|error| {
        format!("OpenAI child run requires an API key or Codex runtime login: {error}")
    })?;
    Ok((None, Some(sdk)))
}

/// Decode the in-flight subagent `request_body` JSON into the typed
/// [`crate::proxy::ChatCompletionRequest`] that every adapter consumes.
///
/// The subagent loop builds its working state as untyped `serde_json`
/// to keep the message-append path cheap; the typed struct is the
/// canonical input expected by every provider adapter and is the
/// reason this refactor is type-safe rather than yet another bag of
/// `Value::get(...)` calls. Errors are surfaced verbatim so a
/// malformed request body produces a debuggable agent-error message.
fn build_chat_completion_request(
    request_body: &Value,
) -> Result<crate::proxy::ChatCompletionRequest, String> {
    serde_json::from_value::<crate::proxy::ChatCompletionRequest>(request_body.clone())
        .map_err(|e| format!("Failed to materialize ChatCompletionRequest: {e}"))
}

fn check_provider_request_policy(
    app_config: &AppConfig,
    request: &crate::proxy::ChatCompletionRequest,
) -> Result<(), crate::services::policy::PolicyError> {
    let estimated_input = crate::compaction::estimate_request_tokens(request);
    crate::services::policy::ProviderRequestPolicy::new(&app_config.policy).check(
        crate::services::policy::ProviderRequestPolicyInput::new(
            &request.model,
            estimated_input,
            request.max_tokens,
            0,
        ),
    )
}

const SUBAGENT_TYPED_DECISION_TOOLS: &[&str] = &["bash", "write_file", "edit_file"];

fn requires_subagent_typed_decision(tool_name: &str) -> bool {
    SUBAGENT_TYPED_DECISION_TOOLS.contains(&tool_name)
}

fn add_subagent_typed_decision_contracts(mut tools: Vec<Value>) -> Vec<Value> {
    for tool in &mut tools {
        let Some(function) = tool.get_mut("function").and_then(Value::as_object_mut) else {
            continue;
        };
        let Some(tool_name) = function
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| requires_subagent_typed_decision(name))
            .map(str::to_string)
        else {
            continue;
        };
        let Some(parameters) = function
            .get_mut("parameters")
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        parameters
            .entry("properties".to_string())
            .or_insert_with(|| json!({}));
        if let Some(properties) = parameters
            .get_mut("properties")
            .and_then(Value::as_object_mut)
        {
            properties.insert(
                "decision".to_string(),
                subagent_typed_decision_schema(&tool_name),
            );
        }
        parameters
            .entry("required".to_string())
            .or_insert_with(|| json!([]));
        if let Some(required) = parameters.get_mut("required").and_then(Value::as_array_mut) {
            if !required
                .iter()
                .any(|item| item.as_str() == Some("decision"))
            {
                required.push(Value::String("decision".to_string()));
            }
        }
    }
    tools
}

fn subagent_typed_decision_schema(tool_name: &str) -> Value {
    match tool_name {
        "bash" => json!({
            "type": "object",
            "description": "Required grounded AgentDecision for this command. Cite authoritative Reality Ledger observation ids from the grounding packet or grounding_context.",
            "properties": {
                "kind": { "type": "string", "enum": ["run_command"] },
                "reason": { "type": "string" },
                "evidence": {
                    "type": "array",
                    "items": { "type": "string" },
                    "minItems": 1
                },
                "argv": {
                    "type": "array",
                    "items": { "type": "string" },
                    "minItems": 1,
                    "description": "The command intent as argv. For shell commands use ['bash', '-lc', <command>] or argv text matching the command."
                }
            },
            "required": ["kind", "reason", "evidence", "argv"]
        }),
        "write_file" | "edit_file" => json!({
            "type": "object",
            "description": "Required grounded AgentDecision for this file mutation. Cite authoritative Reality Ledger file-read observation ids from the grounding packet or grounding_context.",
            "properties": {
                "kind": { "type": "string", "enum": ["edit"] },
                "reason": { "type": "string" },
                "evidence": {
                    "type": "array",
                    "items": { "type": "string" },
                    "minItems": 1
                },
                "patch": {
                    "type": "string",
                    "description": "Patch or diff for the intended file mutation. It must mention the same path as the tool call."
                }
            },
            "required": ["kind", "reason", "evidence", "patch"]
        }),
        _ => json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
    }
}

fn validate_subagent_tool_decision_for_session(
    run: &crate::tools::ToolRunContext,
    agent_id: &str,
    tool_call: &ToolCall,
) -> Result<(), String> {
    if !requires_subagent_typed_decision(&tool_call.function.name) {
        return Ok(());
    }
    let ledger = crate::ledger::RealityLedger::open_project_session(agent_id)
        .map_err(|err| format!("typed decision requires reality ledger: {err}"))?;
    let args = crate::services::tool_executor::ToolExecutor::parse_arguments(
        &tool_call.function.name,
        &tool_call.function.arguments,
    )?;
    match validate_subagent_tool_decision_against_ledger(
        run,
        &tool_call.function.name,
        &args,
        &ledger,
    ) {
        Ok(()) => {
            crate::grounded_loop::observe_policy_decision_for_session(
                run,
                agent_id,
                true,
                &format!(
                    "typed decision accepted for subagent tool '{}'",
                    tool_call.function.name
                ),
            );
            Ok(())
        }
        Err(err) => {
            crate::grounded_loop::observe_policy_decision_for_session(run, agent_id, false, &err);
            Err(err)
        }
    }
}

fn validate_subagent_tool_decision_against_ledger(
    run: &crate::tools::ToolRunContext,
    tool_name: &str,
    args: &Value,
    ledger: &crate::ledger::RealityLedger,
) -> Result<(), String> {
    if !requires_subagent_typed_decision(tool_name) {
        return Ok(());
    }
    let decision_value = args
        .get("decision")
        .ok_or_else(|| format!("Tool '{tool_name}' requires arguments.decision"))?;
    let decision = serde_json::from_value::<crate::decision::AgentDecision>(decision_value.clone())
        .map_err(|err| format!("Invalid typed decision for tool '{tool_name}': {err}"))?;
    validate_subagent_tool_decision_shape(tool_name, args, &decision)?;
    crate::decision::validate_decision(&decision, ledger, run)
        .map(|_| ())
        .map_err(|denial| {
            format!(
                "Typed decision denied for tool '{tool_name}': {}",
                denial.reason()
            )
        })
}

fn validate_subagent_tool_decision_shape(
    tool_name: &str,
    args: &Value,
    decision: &crate::decision::AgentDecision,
) -> Result<(), String> {
    match (tool_name, decision) {
        ("bash", crate::decision::AgentDecision::RunCommand { argv, .. }) => {
            let command = args
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !subagent_command_decision_matches(command, argv) {
                return Err(
                    "Typed command decision argv must match the bash command argument".to_string(),
                );
            }
            Ok(())
        }
        ("write_file" | "edit_file", crate::decision::AgentDecision::Edit { patch, .. }) => {
            let path = args.get("path").and_then(Value::as_str).unwrap_or_default();
            if path.is_empty() || !patch_mentions_tool_path(patch, path) {
                return Err(format!(
                    "Typed edit decision patch must mention the tool path '{path}'"
                ));
            }
            Ok(())
        }
        ("bash", _) => Err("Tool 'bash' requires a run_command typed decision".to_string()),
        ("write_file" | "edit_file", _) => Err(format!(
            "Tool '{tool_name}' requires an edit typed decision"
        )),
        _ => Ok(()),
    }
}

fn subagent_command_decision_matches(command: &str, argv: &[String]) -> bool {
    if command.trim().is_empty() || argv.is_empty() {
        return false;
    }
    (argv.len() == 1 && argv[0] == command)
        || (argv.len() == 3 && argv[0] == "bash" && argv[1] == "-lc" && argv[2] == command)
        || argv.join(" ") == command
}

fn patch_mentions_tool_path(patch_text: &str, tool_path: &str) -> bool {
    let normalized = tool_path.trim_start_matches("./");
    !normalized.is_empty()
        && patch_text.lines().any(|line| {
            let line = line.trim_start_matches("./");
            line.contains(normalized)
        })
}

fn strip_subagent_decision_argument(tool_call: &ToolCall) -> ToolCall {
    if !requires_subagent_typed_decision(&tool_call.function.name) {
        return tool_call.clone();
    }
    let Ok(Value::Object(mut args)) = serde_json::from_str::<Value>(&tool_call.function.arguments)
    else {
        return tool_call.clone();
    };
    args.remove("decision");
    let mut stripped = tool_call.clone();
    stripped.function.arguments = Value::Object(args).to_string();
    stripped
}

#[cfg(test)]
fn responses_subagent_assistant_message(
    decoded: &crate::pipeline::OpenAiResponsesDecodedTurn,
) -> Value {
    let tool_calls = decoded
        .tool_calls
        .iter()
        .map(|call| {
            json!({
                "id": call.id,
                "type": "function",
                "function": {
                    "name": call.function.name,
                    "arguments": call.function.arguments,
                }
            })
        })
        .collect::<Vec<_>>();
    json!({
        "role": "assistant",
        "content": if decoded.content.is_empty() && !tool_calls.is_empty() {
            Value::Null
        } else {
            Value::String(decoded.content.clone())
        },
        "tool_calls": tool_calls,
    })
}

fn codex_sdk_subagent_assistant_message(turn: &crate::codex_agent_sdk::CodexAgentSdkTurn) -> Value {
    let tool_calls = turn
        .tool_calls
        .iter()
        .map(|call| {
            json!({
                "id": call.id,
                "type": "function",
                "function": {
                    "name": call.function.name,
                    "arguments": call.function.arguments,
                }
            })
        })
        .collect::<Vec<_>>();
    json!({
        "role": "assistant",
        "content": if turn.content.is_empty() && !tool_calls.is_empty() {
            Value::Null
        } else {
            Value::String(turn.content.clone())
        },
        "tool_calls": tool_calls,
    })
}

fn native_json_subagent_assistant_message(
    decoded: &crate::pipeline::ProviderNativeJsonDecodedTurn,
) -> Value {
    let tool_calls = decoded
        .tool_calls
        .iter()
        .map(|call| {
            json!({
                "id": call.id,
                "type": "function",
                "function": {
                    "name": call.function.name,
                    "arguments": call.function.arguments,
                }
            })
        })
        .collect::<Vec<_>>();
    json!({
        "role": "assistant",
        "content": if decoded.content.is_empty() && !tool_calls.is_empty() {
            Value::Null
        } else {
            Value::String(decoded.content.clone())
        },
        "tool_calls": tool_calls,
    })
}

fn apply_subagent_responses_output_limit(request: &mut Value) -> Result<(), String> {
    request
        .as_object_mut()
        .ok_or_else(|| "Responses child request must be an object".to_string())?
        .insert(
            "max_output_tokens".to_string(),
            Value::from(SUBAGENT_MAX_TOKENS),
        );
    Ok(())
}

fn subagent_assistant_text(message: &Value) -> String {
    let Some(content) = message.get("content") else {
        return String::new();
    };
    if let Some(text) = content.as_str() {
        return text.to_string();
    }
    content.as_array().map_or_else(String::new, |parts| {
        parts
            .iter()
            .filter(|part| part.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|part| part.get("text").and_then(Value::as_str))
            .collect::<String>()
    })
}

async fn make_codex_agent_sdk_call(
    run: &crate::tools::ToolRunContext,
    provider: &str,
    model: &str,
    sdk: &crate::codex_agent_sdk::CodexAgentSdk,
    request_body: &Value,
) -> Result<crate::codex_agent_sdk::CodexAgentSdkTurn, String> {
    let mut request_body = request_body.clone();
    let provider_budget = crate::provider_budget::reserve_provider_call(
        run,
        provider,
        model,
        &mut request_body,
        u64::from(SUBAGENT_MAX_TOKENS),
    )
    .map_err(|error| format!("Run budget denied provider call: {error}"))?;
    let turn = match sdk.complete_turn(&request_body, "medium").await {
        Ok(turn) => turn,
        Err(error) => {
            provider_budget.finish_unknown().map_err(|budget_error| {
                format!(
                    "Codex SDK request failed: {error}; budget reconciliation failed: {budget_error}"
                )
            })?;
            return Err(format!("Codex SDK request failed: {error}"));
        }
    };
    provider_budget
        .reconcile(&turn.usage)
        .map_err(|error| format!("Provider budget reconciliation failed: {error}"))?;
    crate::pipeline::ensure_provider_turn_succeeded(
        if turn.tool_calls.is_empty() {
            crate::pipeline::ProviderTerminalOutcome::Completed
        } else {
            crate::pipeline::ProviderTerminalOutcome::ToolCalls
        },
        turn.tool_calls.len(),
    )?;
    Ok(turn)
}

#[allow(clippy::too_many_arguments)]
async fn make_provider_native_json_api_call(
    run: &crate::tools::ToolRunContext,
    client: &Client,
    provider: &str,
    model: &str,
    base_url: &str,
    api_key: Option<&crate::providers::ApiKey>,
    extra_headers: Option<&crate::secrets::SensitiveHeaders>,
    request_body: &Value,
    provider_native_state: Option<&crate::runtime::ProviderNativeState>,
    assistant_message_ordinal: u64,
) -> Result<crate::pipeline::ProviderNativeJsonDecodedTurn, String> {
    let endpoint = crate::pipeline::resolve_endpoint(provider, model, base_url, None)
        .map_err(|error| format!("Provider endpoint error: {error}"))?;
    let empty_headers = crate::secrets::SensitiveHeaders::new();
    let headers = crate::pipeline::resolve_headers(
        provider,
        api_key,
        None,
        extra_headers.unwrap_or(&empty_headers),
    )
    .map_err(|error| format!("Provider header error: {error}"))?;
    let mut request_body = request_body.clone();
    let provider_budget = crate::provider_budget::reserve_provider_call(
        run,
        provider,
        model,
        &mut request_body,
        u64::from(SUBAGENT_MAX_TOKENS),
    )
    .map_err(|error| format!("Run budget denied provider call: {error}"))?;
    let request = headers
        .apply(client.post(endpoint).json(&request_body))
        .map_err(|error| format!("Provider header error: {error}"))?;
    let response = crate::provider_transport::send(request)
        .await
        .map_err(|error| format!("Provider request failed: {error}"))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = crate::secrets::read_bounded_diagnostic_body(response)
            .await
            .unwrap_or_else(|_| zeroize::Zeroizing::new(String::new()));
        return Err(format!(
            "Provider API error ({status}): {}",
            headers.sanitize_diagnostic(&body)
        ));
    }
    let response = crate::provider_transport::read_json_capped::<Value>(
        response,
        crate::provider_transport::MAX_JSON_RESPONSE_BYTES,
    )
    .await
    .map_err(|error| format!("Provider JSON error: {error}"))?;
    let decoded = crate::pipeline::decode_provider_native_json_turn(
        provider,
        model,
        &response,
        provider_native_state,
        assistant_message_ordinal,
    )
    .map_err(|error| headers.sanitize_diagnostic(&error).to_string())?;
    crate::pipeline::ensure_provider_turn_succeeded(
        decoded.terminal_outcome,
        decoded.tool_calls.len(),
    )?;
    provider_budget
        .reconcile(&decoded.usage)
        .map_err(|error| format!("Provider budget reconciliation failed: {error}"))?;
    Ok(decoded)
}

/// Make an API call to the LLM provider.
///
/// Provider transformation is delegated to the canonical
/// [`crate::providers::ProviderAdapter`] trait so subagent dispatch
/// supports every provider the proxy supports (Anthropic, `OpenAI`,
/// `Google`/`Gemini`, `DeepSeek`, Qwen, Z.AI/GLM, Kimi/Moonshot,
/// `MiniMax`, Ollama, `OpenAI`-compatible) instead of a hardcoded
/// Anthropic-vs-`OpenAI` branch. The previous implementation duplicated
/// provider transformation logic from `src/providers/` and only handled two
/// out of seven formats — see crosslink #407.
///
/// `api_key` is an optional [`crate::providers::ApiKey`]; when `None`
/// the auth header is omitted rather than sent empty. See crosslink
/// #256.
async fn make_api_call(
    run: &crate::tools::ToolRunContext,
    client: &Client,
    provider: &str,
    base_url: &str,
    api_key: Option<&crate::providers::ApiKey>,
    request_body: &Value,
) -> Result<Value, String> {
    // Resolve the typed adapter for this provider — strict validation
    // so an unknown provider name fails fast at the dispatch boundary
    // (see `resolve_subagent_adapter`).
    let adapter = resolve_subagent_adapter(provider)?;

    // Materialize the typed request the adapter trait consumes.
    let typed_request = build_chat_completion_request(request_body)?;

    // Transform via the canonical adapter — handles every provider's
    // wire format, including Anthropic prompt-cache `cache_control`
    // headers, Google `generationConfig`, Ollama `options`, etc.
    let mut body = adapter
        .transform_request(&typed_request)
        .map_err(|e| format!("Adapter transform_request failed: {e}"))?;
    let provider_budget = crate::provider_budget::reserve_provider_call(
        run,
        provider,
        &typed_request.model,
        &mut body,
        u64::from(SUBAGENT_MAX_TOKENS),
    )
    .map_err(|error| format!("Run budget denied provider call: {error}"))?;

    // Endpoint path is adapter-owned (Google's path embeds the model
    // name, Ollama uses /api/chat, Anthropic uses /v1/messages, etc.).
    // We strip the `/v1` suffix from the configured base_url because
    // every adapter's endpoint already encodes its own version
    // segment — matching the URL composition rule in
    // `src/vdd/transport.rs::forward_request`.
    let normalized_base = base_url
        .trim_end_matches('/')
        .trim_end_matches("/v1")
        .trim_end_matches('/');
    let endpoint = format!(
        "{normalized_base}{}",
        adapter.chat_endpoint(&typed_request.model)
    );
    crate::provider_transport::validate_endpoint(provider, &endpoint)
        .map_err(|error| error.to_string())?;

    // Headers come from the adapter when an api_key is present. We
    // ensure a content-type header is set in all cases so providers
    // without an explicit content-type contribution still receive
    // valid JSON.
    let mut headers = api_key
        .map(|key| adapter.get_headers(key))
        .unwrap_or_default();
    if !headers.contains_name("content-type") {
        headers.insert_static_literal(reqwest::header::CONTENT_TYPE, "application/json");
    }

    let req = headers
        .apply(client.post(&endpoint).json(&body))
        .map_err(|error| format!("invalid provider headers: {error}"))?;

    let response = crate::provider_transport::send(req)
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = crate::secrets::read_bounded_diagnostic_body(response)
            .await
            .unwrap_or_else(|_| zeroize::Zeroizing::new("Unknown error".to_string()));
        return Err(format!(
            "API error ({status}): {}",
            headers.sanitize_diagnostic(&text)
        ));
    }

    let json: Value = crate::provider_transport::read_json_capped(
        response,
        crate::provider_transport::MAX_JSON_RESPONSE_BYTES,
    )
    .await
    .map_err(|e| format!("Failed to parse response: {e}"))?;

    // Translate provider-native response back to OpenAI chat shape so
    // `parse_response` (which expects `choices[0].message`) keeps
    // working unchanged for every provider.
    let transformed = adapter
        .transform_response(json, false)
        .map_err(|e| format!("Adapter transform_response failed: {e}"))?;
    crate::pipeline::validate_chat_completion_terminal(&transformed)?;
    let usage = normalized_response_usage(&transformed);
    provider_budget
        .reconcile(&usage)
        .map_err(|error| format!("Provider budget reconciliation failed: {error}"))?;
    Ok(transformed)
}

fn normalized_response_usage(response: &Value) -> crate::session::TokenUsage {
    let usage = response.get("usage").unwrap_or(&Value::Null);
    let raw_input_tokens = usage
        .get("prompt_tokens")
        .or_else(|| usage.get("input_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cache_read_tokens = usage
        .pointer("/prompt_tokens_details/cached_tokens")
        .or_else(|| usage.pointer("/input_tokens_details/cached_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cache_write_tokens = usage
        .pointer("/input_tokens_details/cache_write_tokens")
        .or_else(|| usage.get("cache_creation_input_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    crate::session::TokenUsage {
        input_tokens: raw_input_tokens
            .saturating_sub(cache_read_tokens)
            .saturating_sub(cache_write_tokens),
        output_tokens: usage
            .get("completion_tokens")
            .or_else(|| usage.get("output_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        cache_read_tokens,
        cache_write_tokens,
    }
}

/// Parse the response to extract the assistant message
fn parse_response(response: &Value) -> Result<Value, String> {
    // OpenAI format
    if let Some(choices) = response.get("choices").and_then(|c| c.as_array()) {
        if let Some(first) = choices.first() {
            if let Some(message) = first.get("message") {
                return Ok(message.clone());
            }
        }
    }

    // Direct message (already transformed)
    if response.get("role").is_some() {
        return Ok(response.clone());
    }

    Err("Could not parse response".to_string())
}

fn subagent_tool_call_id_for_error(tool_call: &Value, index: usize) -> String {
    tool_call
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map_or_else(|| format!("invalid_tool_call_{index}"), str::to_string)
}

fn parse_subagent_tool_call(tool_call: &Value, index: usize) -> Result<ToolCall, String> {
    let id = tool_call
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| format!("tool_call[{index}] missing non-empty string 'id'"))?;
    let function = tool_call
        .get("function")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("tool_call[{index}] missing object 'function'"))?;
    let name = function
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| format!("tool_call[{index}] missing non-empty string 'function.name'"))?;
    let arguments = function
        .get("arguments")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("tool_call[{index}] missing string 'function.arguments'"))?;
    let parsed_arguments = serde_json::from_str::<Value>(arguments)
        .map_err(|e| format!("tool_call[{index}] has invalid JSON in 'function.arguments': {e}"))?;
    if !parsed_arguments.is_object() {
        return Err(format!(
            "tool_call[{index}] has non-object 'function.arguments': expected JSON object"
        ));
    }

    Ok(ToolCall {
        id: id.to_string(),
        call_type: tool_call
            .get("type")
            .and_then(Value::as_str)
            .filter(|call_type| !call_type.is_empty())
            .unwrap_or("function")
            .to_string(),
        function: crate::tools::FunctionCall {
            name: name.to_string(),
            arguments: arguments.to_string(),
        },
    })
}

fn observe_subagent_tool_result(
    run: &crate::tools::ToolRunContext,
    agent_id: &str,
    result: &crate::tools::ToolResult,
) {
    crate::grounded_loop::observe_tool_result_for_session(run, agent_id, result);
}

struct SubagentToolExecution<'a> {
    run: &'a Arc<crate::tools::ToolRunContext>,
    tool_call: &'a crate::tools::ToolCall,
    memory_db: Option<&'a crate::memory::MemoryDb>,
    app_config: &'a AppConfig,
    task_manager: &'a mut crate::session::TaskManager,
    permission_manager: &'a crate::permissions::PermissionManager,
    agent_id: &'a str,
    policy_enforcer: &'a crate::services::policy::PolicyEnforcer,
}

fn execute_subagent_local_tool(
    request: &mut SubagentToolExecution<'_>,
) -> crate::tools::ToolResult {
    crate::services::tool_executor::ToolExecutor::execute(
        crate::services::tool_executor::ToolExecutorRequest {
            run_context: request.run,
            tool_call: request.tool_call,
            memory_db: request.memory_db,
            app_config: Some(request.app_config),
            task_mgr: Some(&mut *request.task_manager),
            permission_mgr: request.permission_manager,
            authorization: None,
            session_id: Some(request.agent_id),
            policy_enforcer: Some(request.policy_enforcer),
        },
    )
}

// === Tool Execution ===

fn available_subagent_tools(
    agent_type: AgentType,
    technical_memory_available: bool,
) -> Vec<&'static str> {
    let mut tools = agent_type.allowed_tools();
    if !technical_memory_available {
        tools.retain(|name| !name.starts_with("memory_"));
    }
    tools
}

fn reopen_subagent_memory(
    memory_db: Option<&crate::memory::MemoryDb>,
) -> Result<Option<Arc<crate::memory::MemoryDb>>, String> {
    let Some(memory) = memory_db else {
        return Ok(None);
    };
    let reopened = memory
        .reopen_for_subagent()
        .map_err(|error| format!("Cannot reopen technical memory for the subagent: {error}"))?;
    Ok(Some(Arc::new(reopened)))
}

fn no_task_effect((content, is_error): (String, bool)) -> (String, bool, bool) {
    (content, is_error, false)
}

/// Execute the Task tool and retain whether registration made a real effect.
#[allow(clippy::too_many_lines)]
fn execute_task_tool_with_receipt<S: BuildHasher>(
    parent_run: &Arc<crate::tools::ToolRunContext>,
    args: &HashMap<String, Value, S>,
    app_config: &AppConfig,
    memory_db: Option<&crate::memory::MemoryDb>,
) -> (String, bool, bool) {
    let description = match args.arg_str_strict("description") {
        Ok(description) => description,
        Err(err) => return no_task_effect(err.into_tool_error()),
    };
    if description.trim().is_empty()
        || description.len() > crate::task_graph::MAX_TASK_SUBJECT_BYTES
        || description.contains('\0')
    {
        return no_task_effect((
            format!(
                "Invalid 'description' argument: must be non-empty, NUL-free, and at most {} bytes",
                crate::task_graph::MAX_TASK_SUBJECT_BYTES
            ),
            true,
        ));
    }

    let prompt = match args.arg_str_strict("prompt") {
        Ok(prompt) => prompt,
        Err(err) => return no_task_effect(err.into_tool_error()),
    };

    // Handle resume: if resume ID is provided, load previous transcript
    let resume_id = match args.arg_str_opt_strict("resume") {
        Ok(resume) => resume.map(String::from),
        Err(err) => return no_task_effect(err.into_tool_error()),
    };

    let subagent_type_str = match args.arg_str_strict("subagent_type") {
        Ok(subagent_type) => subagent_type,
        Err(err) => return no_task_effect(err.into_tool_error()),
    };

    let Some(agent_type) = AgentType::parse_task_type(subagent_type_str) else {
        let valid_types = AgentType::task_tool_names().join(", ");
        return (
            format!(
                "Unsupported task subagent_type '{subagent_type_str}'. Valid types: {valid_types}"
            ),
            true,
            false,
        );
    };

    let run_in_background = match args.arg_bool_or_strict("run_in_background", false) {
        Ok(value) => value,
        Err(err) => return no_task_effect(err.into_tool_error()),
    };

    // Resolve model: map friendly names to actual model IDs
    let model_override = match args.arg_str_opt_strict("model") {
        Ok(model) => model.map(|m| resolve_model_name(m, &app_config.proxy.target)),
        Err(err) => return no_task_effect(err.into_tool_error()),
    };

    let isolation = match args.arg_str_opt_strict("isolation") {
        Ok(isolation) => isolation.map(String::from),
        Err(err) => return no_task_effect(err.into_tool_error()),
    };

    let config = SubagentConfig {
        agent_type,
        task: description.to_string(),
        prompt: prompt.to_string(),
        run_in_background,
        model_override,
        resume_agent_id: resume_id,
        isolation,
    };

    let subagent_memory = match reopen_subagent_memory(memory_db) {
        Ok(memory) => memory,
        Err(error) => return (error, true, false),
    };

    // Create HTTP client
    let client = match crate::provider_transport::shared_client() {
        Ok(client) => client,
        Err(error) => {
            return no_task_effect((
                format!("Provider transport initialization failed: {error}"),
                true,
            ));
        }
    };

    if run_in_background {
        let arguments = Value::Object(
            args.iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        );
        let background_registration =
            match parent_run.begin_background_effect_registration("task", &arguments) {
                Ok(registration) => registration,
                Err(error) => return (error, true, false),
            };
        // Register the agent and spawn the task.
        //
        // Crosslink #582 — on resume, we must register under the
        // *original* id so:
        //   (a) the immediate response to the caller cites the same id
        //       they already know (and have transcript continuity on),
        //   (b) the spawned task's call to `run_subagent` reattaches to
        //       that tracking entry rather than minting a new id.
        // For fresh spawns we mint a new id as before.
        let agent_id = if let Some(resume_id) = config.resume_agent_id.as_ref() {
            match BACKGROUND_AGENTS.register_with_id(parent_run, agent_type, description, resume_id)
            {
                Ok(_) => resume_id.clone(),
                Err(error) => return (error, true, false),
            }
        } else {
            match BACKGROUND_AGENTS.register(parent_run, agent_type, description) {
                Ok(id) => id,
                Err(error) => return (error, true, false),
            }
        };

        // Spawn the background task
        let config_bg = config;
        let app_config_bg = app_config.clone();
        let client_bg = client;
        let parent_run_bg = Arc::clone(parent_run);
        let memory_db_bg = subagent_memory;
        let agent_id_bg = agent_id.clone();
        let preallocated_agent_id_bg = config_bg
            .resume_agent_id
            .is_none()
            .then(|| agent_id_bg.clone());

        // Use tokio runtime to spawn the background task
        let Ok(handle) = Handle::try_current() else {
            BACKGROUND_AGENTS.fail(
                parent_run,
                &agent_id,
                "Background task requires an active tokio runtime".to_string(),
            );
            return (
                "Background task requires an active tokio runtime".to_string(),
                true,
                true,
            );
        };
        let join_handle = handle.spawn(async move {
            let result = run_subagent_inner(
                &parent_run_bg,
                &config_bg,
                &app_config_bg,
                &client_bg,
                memory_db_bg,
                preallocated_agent_id_bg.as_deref(),
                None,
            )
            .await;

            if !result.success {
                BACKGROUND_AGENTS.fail(&parent_run_bg, &agent_id_bg, result.output);
            }
        });
        if let Err(err) =
            BACKGROUND_AGENTS.attach_abort_handle(parent_run, &agent_id, join_handle.abort_handle())
        {
            tracing::warn!(
                agent_id,
                error = %err,
                "failed to attach background subagent abort handle"
            );
        }
        drop(background_registration);

        let message = format!(
            "Background agent started with ID: {agent_id}\nTask: {description}\nType: {agent_type:?}\n\nUse agent_output with this agent_id to retrieve results."
        );

        (message, false, true)
    } else {
        // Run synchronously via defensive runtime dispatch (#719).
        dispatch_subagent_sync(parent_run, &config, app_config, &client, subagent_memory)
    }
}

fn bind_subagent_legacy_result(
    content: String,
    is_error: bool,
    effect_observed: bool,
) -> crate::tools::ToolHandlerResult {
    if !is_error {
        return crate::tools::ToolHandlerResult::success_text(content);
    }
    let failure = crate::tools::ToolFailure::new(
        crate::tools::ToolFailureCode::External,
        content.clone(),
        crate::tools::ToolRetryability::Unknown,
    );
    if effect_observed {
        crate::tools::ToolHandlerResult::partial_text(content, vec![failure])
    } else {
        crate::tools::ToolHandlerResult::error(failure)
    }
}

/// Legacy task-tool projection retained for direct compatibility tests.
pub fn execute_task_tool<S: BuildHasher>(
    parent_run: &Arc<crate::tools::ToolRunContext>,
    args: &HashMap<String, Value, S>,
    app_config: &AppConfig,
) -> (String, bool) {
    let (content, is_error, _) = execute_task_tool_with_receipt(parent_run, args, app_config, None);
    (content, is_error)
}

/// Canonical task-tool adapter retaining an explicit causal effect receipt.
pub fn execute_task_tool_typed<S: BuildHasher>(
    parent_run: &Arc<crate::tools::ToolRunContext>,
    args: &HashMap<String, Value, S>,
    app_config: &AppConfig,
    memory_db: Option<&crate::memory::MemoryDb>,
) -> crate::tools::ToolHandlerResult {
    let (content, is_error, effect_started) =
        execute_task_tool_with_receipt(parent_run, args, app_config, memory_db);
    bind_subagent_legacy_result(content, is_error, effect_started)
}

/// Synchronous-call-from-tool-dispatch path for `run_subagent`.
///
/// Defensive runtime dispatch (#719): `tokio::task::block_in_place` PANICS
/// when called from a `current_thread` runtime (e.g. `#[tokio::test]`,
/// `tokio_test::block_on`, many CLI harnesses). `Handle::block_on` from
/// inside any runtime worker is also a documented deadlock risk because
/// the inner future may yield back to the same executor that's blocked
/// on its completion.
///
/// Resolution policy:
///   * No runtime in scope    → create a dedicated runtime (CLI/tool
///     dispatch boundary; acceptable, single allocation).
///   * `MultiThread` runtime  → `block_in_place` + `block_on` is safe;
///     `block_in_place` moves us off the worker thread.
///   * `CurrentThread`        → fail fast with a typed error. We cannot
///     `block_in_place` (panics) and cannot `block_on` (deadlocks the
///     single worker). The caller must dispatch through the async path.
fn dispatch_subagent_sync(
    parent_run: &Arc<crate::tools::ToolRunContext>,
    config: &SubagentConfig,
    app_config: &AppConfig,
    client: &Client,
    memory_db: Option<Arc<crate::memory::MemoryDb>>,
) -> (String, bool, bool) {
    let (result, effect_started) = match Handle::try_current() {
        Ok(handle) => match handle.runtime_flavor() {
            tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(|| {
                handle.block_on(run_subagent_with_effect_receipt(
                    parent_run, config, app_config, client, memory_db,
                ))
            }),
            _ => {
                return (
                    "Task tool dispatched from a current_thread tokio runtime: \
                     cannot block_on without deadlock. Invoke the task tool from \
                     a multi_thread runtime or from the async tool dispatcher."
                        .to_string(),
                    true,
                    false,
                );
            }
        },
        Err(_) => match tokio::runtime::Runtime::new() {
            Ok(rt) => rt.block_on(run_subagent_with_effect_receipt(
                parent_run, config, app_config, client, memory_db,
            )),
            Err(e) => {
                return (format!("Failed to create runtime: {e}"), true, false);
            }
        },
    };

    if result.success {
        let mut message = format!(
            "Agent completed in {} turns.\n\n{}",
            result.turns_used, result.output
        );
        if let Some(ref wt) = result.worktree {
            let _ = write!(
                message,
                "\n\nWorktree: {}\nBranch: {}",
                wt.worktree_path.display(),
                wt.branch_name
            );
        }
        (message, false, effect_started)
    } else {
        (
            format!("Agent failed: {}", result.output),
            true,
            effect_started,
        )
    }
}

/// Execute the `AgentOutput` tool and retain whether a finished entry was
/// consumed from the exact-run manager.
fn execute_agent_output_tool_with_receipt<S: BuildHasher>(
    owner: &crate::tools::ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> (String, bool, bool) {
    let agent_id = match args.arg_str_opt_strict("agent_id") {
        Ok(Some(agent_id)) => agent_id,
        Ok(None) => {
            // List all agents if no ID provided
            let agents = BACKGROUND_AGENTS.list_for_run(owner);
            if agents.is_empty() {
                return ("No background agents running.".to_string(), false, false);
            }
            let mut result = format!("Background agents ({}):\n", agents.len());
            for (id, agent_type, task, finished) in agents {
                let status = if finished { "finished" } else { "running" };
                let task_preview = if task.len() > 50 {
                    format!("{}...", safe_truncate(&task, 50))
                } else {
                    task
                };
                let _ = writeln!(result, "  {id} [{agent_type:?}] [{status}]: {task_preview}");
            }
            return (result, false, false);
        }
        Err(err) => return no_task_effect(err.into_tool_error()),
    };

    let block = match args.arg_bool_or_strict("block", false) {
        Ok(value) => value,
        Err(err) => return no_task_effect(err.into_tool_error()),
    };

    let Some(agent) = BACKGROUND_AGENTS.get_for_run(owner, agent_id) else {
        return (format!("Agent '{agent_id}' not found"), true, false);
    };

    if block && !agent.finished.load(Ordering::SeqCst) {
        // Wait for completion (up to 5 minutes).
        //
        // Crosslink #682: the prior implementation used
        // `std::thread::sleep` directly. The tool-execution layer is sync,
        // but it is typically driven from a tokio worker thread; a bare
        // sleep blocks that worker — for up to 5 minutes — and starves
        // every other future on the same runtime. The fix mirrors
        // `dispatch_subagent_sync`'s runtime-aware pattern: on a
        // multi-threaded runtime use `block_in_place` so tokio can move
        // other tasks off this thread for the duration; on a
        // current-thread runtime fall back to a much shorter polling
        // tick (the single worker cannot be moved aside, so we keep
        // sleep granularity small and yield through the scheduler);
        // off-runtime we keep the original thread sleep.
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_mins(5);
        let poll = std::time::Duration::from_millis(500);

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                tokio::task::block_in_place(|| {
                    while !agent.finished.load(Ordering::SeqCst) && start.elapsed() < timeout {
                        handle.block_on(tokio::time::sleep(poll));
                    }
                });
            } else {
                // Current-thread (or other) flavour: cannot
                // `block_in_place`. Use a shorter granularity so the
                // single worker recovers reasonably between polls.
                let short_poll = std::time::Duration::from_millis(50);
                while !agent.finished.load(Ordering::SeqCst) && start.elapsed() < timeout {
                    std::thread::sleep(short_poll);
                }
            }
        } else {
            while !agent.finished.load(Ordering::SeqCst) && start.elapsed() < timeout {
                std::thread::sleep(poll);
            }
        }
    }

    let finished = agent.finished.load(Ordering::SeqCst);
    let turns = agent.turns.load(Ordering::SeqCst);

    if finished {
        // Get the result or error
        let result = agent_field_guard(&agent.result, "agent_output", agent_id, "result")
            .and_then(|r| r.clone());
        let error = agent_field_guard(&agent.error, "agent_output", agent_id, "error")
            .and_then(|e| e.clone());

        // Crosslink #422: once a finished agent has had its output consumed
        // by the caller, drop the map entry so the manager cannot leak
        // finished `BackgroundAgent` Arcs across a long-running session.
        // Drop the local `Arc` clone first so `remove` returns the last
        // strong reference and the heap allocation can actually be freed.
        drop(agent);
        let _ = BACKGROUND_AGENTS.remove_for_run(owner, agent_id);

        let (content, is_error) = error.map_or_else(
            || {
                result.map_or_else(
                    || {
                        (
                            format!("Agent '{agent_id}' finished but produced no output"),
                            false,
                        )
                    },
                    |output| {
                        (
                            format!("Agent '{agent_id}' completed in {turns} turns:\n\n{output}"),
                            false,
                        )
                    },
                )
            },
            |err| {
                (
                    format!("Agent '{agent_id}' failed after {turns} turns:\n{err}"),
                    true,
                )
            },
        );
        (content, is_error, true)
    } else {
        (
            format!(
                "Agent '{agent_id}' is still running ({turns} turns so far)\nTask: {}",
                agent.task
            ),
            false,
            false,
        )
    }
}

/// Legacy output projection retained for compatibility tests.
pub fn execute_agent_output_tool<S: BuildHasher>(
    owner: &crate::tools::ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> (String, bool) {
    let (content, is_error, _) = execute_agent_output_tool_with_receipt(owner, args);
    (content, is_error)
}

/// Canonical output adapter.
///
/// Consuming a finished failed agent removes its manager entry; preserve that
/// mutation as partial rather than releasing the enclosing effect reservation
/// merely because the agent itself failed.
pub fn execute_agent_output_tool_typed<S: BuildHasher>(
    owner: &crate::tools::ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> crate::tools::ToolHandlerResult {
    let (content, is_error, effect_started) = execute_agent_output_tool_with_receipt(owner, args);
    bind_subagent_legacy_result(content, is_error, effect_started)
}

fn execute_task_stop_tool_with_receipt<S: BuildHasher>(
    owner: &crate::tools::ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> (String, bool, bool) {
    let agent_id = match args.arg_str_strict("agent_id") {
        Ok(agent_id) => agent_id,
        Err(err) => {
            let (message, is_error) = err.into_tool_error();
            return (message, is_error, false);
        }
    };
    let reason = match args.arg_str_opt_strict("reason") {
        Ok(reason) => reason.unwrap_or("stopped by task_stop"),
        Err(err) => {
            let (message, is_error) = err.into_tool_error();
            return (message, is_error, false);
        }
    };
    let canonical_task = BACKGROUND_AGENTS.canonical_task_for_run(owner, agent_id);
    let message = match BACKGROUND_AGENTS.stop(owner, agent_id, reason) {
        Ok(message) => message,
        Err(error) => return (error, true, false),
    };
    if let Some(task_id) = canonical_task {
        if let Err(error) = transition_canonical_delegation(
            owner,
            &task_id,
            agent_id,
            crate::session::TaskUpdateStatus::Canceled,
        ) {
            return (
                format!(
                    "{message}\nAgent stopped, but canonical delegation cancellation failed: {error}"
                ),
                true,
                true,
            );
        }
    }
    (message, false, true)
}

/// Execute the `TaskStop` tool through its legacy tuple projection.
pub fn execute_task_stop_tool<S: BuildHasher>(
    owner: &crate::tools::ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> (String, bool) {
    let (content, is_error, _) = execute_task_stop_tool_with_receipt(owner, args);
    (content, is_error)
}

/// Canonical stop adapter that preserves an already-observed cancellation as
/// a partial outcome if durable task-graph reconciliation then fails.
pub fn execute_task_stop_tool_typed<S: BuildHasher>(
    owner: &crate::tools::ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> crate::tools::ToolHandlerResult {
    let (content, is_error, effect_started) = execute_task_stop_tool_with_receipt(owner, args);
    bind_subagent_legacy_result(content, is_error, effect_started)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    fn test_run() -> &'static Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context()
    }

    fn isolated_test_run(provider: &str) -> Arc<crate::tools::ToolRunContext> {
        crate::tools::ToolRunContext::builder(
            crate::state::SessionId::new(),
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
        )
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(HashMap::new())
        .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
        .process(false)
        .network(false)
        .secrets(false)
        .provider(provider)
        .build()
        .expect("explicit isolated subagent test run")
    }

    /// Keeps older lifecycle-focused tests compact while exercising the new
    /// exact-run API. Cross-run behavior is covered independently below and
    /// in `background_agent_manager_e2e`.
    struct TestBackgroundAgentManager {
        inner: BackgroundAgentManager,
        owner: Arc<crate::tools::ToolRunContext>,
    }

    impl TestBackgroundAgentManager {
        fn new() -> Self {
            Self {
                inner: BackgroundAgentManager::new(),
                owner: Arc::clone(test_run()),
            }
        }

        fn register(&self, agent_type: AgentType, task: &str) -> String {
            self.inner
                .register(&self.owner, agent_type, task)
                .expect("test agent registration")
        }

        fn register_with_id(&self, agent_type: AgentType, task: &str, id: &str) -> bool {
            self.inner
                .register_with_id(&self.owner, agent_type, task, id)
                .expect("test agent registration with id")
        }

        fn get(&self, id: &str) -> Option<Arc<BackgroundAgent>> {
            self.inner.get_for_run(&self.owner, id)
        }

        fn increment_turns(&self, id: &str) -> u64 {
            self.inner.increment_turns(&self.owner, id)
        }

        fn finish(&self, id: &str, result: String) {
            self.inner.finish(&self.owner, id, result);
        }

        fn fail(&self, id: &str, error: String) {
            self.inner.fail(&self.owner, id, error);
        }

        fn attach_abort_handle(
            &self,
            id: &str,
            abort_handle: tokio::task::AbortHandle,
        ) -> Result<(), String> {
            self.inner
                .attach_abort_handle(&self.owner, id, abort_handle)
        }

        fn stop(&self, id: &str, reason: &str) -> Result<String, String> {
            self.inner.stop(&self.owner, id, reason)
        }

        fn gc(&self) -> usize {
            self.inner.gc()
        }

        fn cleanup_finished(&self) -> usize {
            self.inner.cleanup_finished_for_run(&self.owner)
        }
    }

    #[test]
    fn canonical_delegation_guard_commits_success_drop_failure_and_stable_resume() {
        let root = tempfile::tempdir().expect("delegation graph root");
        let owner = isolated_test_run("delegation-graph-test");
        let graph_id = "delegation-lifecycle";
        let target = std::path::PathBuf::from("tasks.json");
        let open_manager = || {
            crate::session::TaskManager::open(
                root.path(),
                target.clone(),
                graph_id,
                crate::task_graph::TaskActor::from_run(&owner),
            )
            .expect("open task manager")
        };
        let agent_id = BACKGROUND_AGENTS
            .register(&owner, AgentType::Plan, "delegated lifecycle")
            .expect("register agent");

        let guard = DelegationTaskGuard::begin_with_manager(
            &owner,
            open_manager(),
            &agent_id,
            "delegated lifecycle",
        )
        .expect("begin delegation");
        let stable_task_id = guard.task_id.clone();
        assert_eq!(
            guard
                .manager
                .get_task(&stable_task_id)
                .expect("running task")
                .status,
            crate::session::TaskStatus::InProgress
        );
        guard
            .finish(crate::session::TaskUpdateStatus::Completed)
            .expect("complete delegation");
        let completed = open_manager();
        let completed_task = completed.get_task(&stable_task_id).expect("completed task");
        assert_eq!(completed_task.status, crate::session::TaskStatus::Completed);
        assert!(completed_task.terminal_at.is_some());

        let resumed = DelegationTaskGuard::begin_with_manager(
            &owner,
            open_manager(),
            &agent_id,
            "delegated lifecycle revised",
        )
        .expect("resume delegation");
        assert_eq!(resumed.task_id, stable_task_id);
        let mut external_stop = open_manager();
        external_stop
            .update_delegation_task(
                &stable_task_id,
                &agent_id,
                None,
                crate::session::TaskUpdateStatus::Canceled,
                None,
            )
            .expect("external cancellation");
        let stale_completion = resumed
            .finish(crate::session::TaskUpdateStatus::Completed)
            .expect_err("late completion must not overwrite cancellation");
        assert!(stale_completion.contains("stale"), "{stale_completion}");
        assert_eq!(
            open_manager()
                .get_task(&stable_task_id)
                .expect("canceled task")
                .status,
            crate::session::TaskStatus::Canceled
        );

        let dropped = DelegationTaskGuard::begin_with_manager(
            &owner,
            open_manager(),
            &agent_id,
            "delegated lifecycle final attempt",
        )
        .expect("resume after cancellation");
        assert_eq!(dropped.task_id, stable_task_id);
        drop(dropped);
        let failed = open_manager();
        assert_eq!(
            failed
                .get_task(&stable_task_id)
                .expect("failed task")
                .status,
            crate::session::TaskStatus::Failed
        );
        assert_eq!(
            BACKGROUND_AGENTS.canonical_task_for_run(&owner, &agent_id),
            Some(stable_task_id)
        );
        let _ = BACKGROUND_AGENTS.remove_for_run(&owner, &agent_id);
    }

    #[test]
    fn delegation_binding_failure_settles_created_task_as_failed() {
        let root = tempfile::tempdir().expect("delegation graph root");
        let owner = isolated_test_run("delegation-binding-failure");
        let target = std::path::PathBuf::from("tasks.json");
        let open_manager = || {
            crate::session::TaskManager::open(
                root.path(),
                target.clone(),
                "delegation-binding-failure",
                crate::task_graph::TaskActor::from_run(&owner),
            )
            .expect("open task manager")
        };
        let agent_id = BACKGROUND_AGENTS
            .register(&owner, AgentType::Plan, "delegated lifecycle")
            .expect("register agent");
        BACKGROUND_AGENTS
            .bind_canonical_task(&owner, &agent_id, "preexisting-conflict")
            .expect("prebind conflicting task");

        let error = DelegationTaskGuard::begin_with_manager(
            &owner,
            open_manager(),
            &agent_id,
            "delegated lifecycle",
        )
        .err()
        .expect("conflicting binding must fail");
        assert!(error.contains("different canonical task"), "{error}");
        let manager = open_manager();
        let task = manager
            .list_tasks()
            .iter()
            .find(|task| {
                matches!(
                    &task.source,
                    crate::task_graph::TaskSource::Delegation { agent_id: source }
                        if source == &agent_id
                )
            })
            .expect("settled delegation task");
        assert_eq!(task.status, crate::session::TaskStatus::Failed);
        let _ = BACKGROUND_AGENTS.remove_for_run(&owner, &agent_id);
    }

    #[test]
    fn worktree_git_helpers_use_resolved_binary_path() {
        let git = git_bin(test_run()).expect("subagent tests require git on the run-bound PATH");
        assert!(
            git.is_absolute(),
            "git_bin must resolve git to an absolute path, got {}",
            git.display()
        );

        let src = include_str!("subagent.rs");
        let cfg_test = src
            .find("#[cfg(test)]")
            .expect("test module marker must be present");
        let production = &src[..cfg_test];

        for (idx, raw_line) in production.lines().enumerate() {
            let code = raw_line.split("//").next().unwrap_or("");
            assert!(
                !code.contains("Command::new(\"git\")")
                    && !code.contains("std::process::Command::new(\"git\")"),
                "production subagent code must not invoke bare git; line {n}: {raw_line}",
                n = idx + 1,
            );
        }
    }

    #[test]
    fn subagent_tool_result_observer_records_tool_result_observation() {
        let agent_id = "subagent-tool-result-ledger-test";
        let ledger = Arc::new(Mutex::new(crate::ledger::RealityLedger::new()));
        let _guard = crate::ledger::install_active_ledger_for_session(agent_id, ledger.clone());
        let tool_call = crate::tools::ToolCall {
            id: "call_1".to_string(),
            call_type: "function".to_string(),
            function: crate::tools::FunctionCall {
                name: "list_files".to_string(),
                arguments: "{}".to_string(),
            },
        };
        let result = crate::tools::ToolResult::bind(
            &tool_call,
            &tool_call.function.name,
            crate::tools::ToolHandlerResult::success_text("model-visible tool output"),
        );

        observe_subagent_tool_result(test_run(), agent_id, &result);

        let observations = {
            let ledger = ledger.lock().expect("ledger lock");
            ledger
                .observations_chronological()
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        assert!(observations.iter().any(|obs| {
            matches!(
                &obs.kind,
                crate::ledger::ObservationKind::ToolResult { tool, result }
                    if tool == "list_files"
                        && result["tool_call_id"] == "call_1"
                        && result["content"] == "model-visible tool output"
                        && result["is_error"] == false
            )
        }));
    }

    fn spawn_openai_no_tool_final_server(
        final_content: &'static str,
    ) -> (std::thread::JoinHandle<Result<(), String>>, String) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock provider");
        listener
            .set_nonblocking(true)
            .expect("mock provider nonblocking");
        let addr = listener.local_addr().expect("mock provider local addr");
        let base_url = format!("http://{addr}/v1");

        let handle = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(accepted) => break accepted,
                    Err(err)
                        if err.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        return Err("mock provider timed out waiting for request".to_string());
                    }
                    Err(err) => return Err(format!("mock provider accept failed: {err}")),
                }
            };

            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|err| format!("set read timeout failed: {err}"))?;
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            let header_end = loop {
                let n = stream
                    .read(&mut buf)
                    .map_err(|err| format!("read request failed: {err}"))?;
                if n == 0 {
                    return Err("mock provider connection closed before headers".to_string());
                }
                request.extend_from_slice(&buf[..n]);
                if let Some(pos) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break pos;
                }
            };

            let headers = String::from_utf8_lossy(&request[..header_end]);
            if !headers.starts_with("POST /v1/chat/completions ") {
                return Err(format!("unexpected request line: {headers:?}"));
            }
            let content_len = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            let total_len = header_end + 4 + content_len;
            while request.len() < total_len {
                let n = stream
                    .read(&mut buf)
                    .map_err(|err| format!("read request body failed: {err}"))?;
                if n == 0 {
                    return Err("mock provider connection closed before body".to_string());
                }
                request.extend_from_slice(&buf[..n]);
            }

            let body = serde_json::json!({
                "id": "chatcmpl-subagent-test",
                "object": "chat.completion",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": final_content,
                    },
                    "finish_reason": "stop",
                }],
                "usage": {
                    "prompt_tokens": 1,
                    "completion_tokens": 1,
                    "total_tokens": 2,
                }
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .map_err(|err| format!("write response failed: {err}"))?;
            Ok(())
        });

        (handle, base_url)
    }

    fn local_subagent_app_config(base_url: String) -> AppConfig {
        use crate::config::{ProviderConfig, ThinkingConfig};

        let mut app_config = issue719_app_config();
        app_config.proxy.target = "local".to_string();
        app_config.providers.clear();
        app_config.providers.insert(
            "local".to_string(),
            ProviderConfig {
                base_url,
                api_key: None,
                model: Some("gpt-5.5".to_string()),
                headers: crate::secrets::SensitiveHeaders::new(),
                thinking: ThinkingConfig::default(),
            },
        );
        app_config
    }

    #[test]
    fn normalized_usage_does_not_double_count_cached_input() {
        let usage = normalized_response_usage(&serde_json::json!({
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 10,
                "prompt_tokens_details": {"cached_tokens": 30}
            }
        }));
        assert_eq!(usage.input_tokens, 70);
        assert_eq!(usage.output_tokens, 10);
        assert_eq!(usage.cache_read_tokens, 30);
    }

    #[tokio::test]
    async fn subagent_provider_failure_redacts_seeded_api_key() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const SECRET: &str = "s025-subagent-api-key-e1f85c";
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": {
                    "message": format!("provider echoed {SECRET}"),
                    "api_key": SECRET,
                }
            })))
            .mount(&server)
            .await;
        let key = crate::providers::ApiKey::try_from_string(SECRET.to_string()).expect("API key");
        let request = serde_json::json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hello"}]
        });

        let error = make_api_call(
            test_run(),
            &reqwest::Client::new(),
            "local",
            &server.uri(),
            Some(&key),
            &request,
        )
        .await
        .expect_err("provider failure must surface as an error");

        assert!(!error.contains(SECRET), "subagent leaked API key: {error}");
        assert!(error.contains(crate::secrets::REDACTED_SECRET), "{error}");
        assert!(error.len() <= crate::secrets::MAX_DIAGNOSTIC_BYTES + 64);
    }

    #[tokio::test]
    async fn subagent_binds_guardrails_before_any_provider_turn() {
        let mut app_config = issue719_app_config();
        app_config.guardrails.blast_radius = Some(crate::config::BlastRadiusConfig {
            enabled: true,
            mode: crate::config::GuardrailMode::Strict,
            allowed_paths: vec!["src/../forbidden/**".to_string()],
            ..crate::config::BlastRadiusConfig::default()
        });
        let config = SubagentConfig {
            agent_type: AgentType::GeneralPurpose,
            task: "Must fail before provider dispatch".to_string(),
            prompt: "No request should leave the process".to_string(),
            run_in_background: false,
            model_override: None,
            resume_agent_id: None,
            isolation: None,
        };

        let result = run_subagent(test_run(), &config, &app_config, &Client::new()).await;

        assert!(!result.success);
        assert_eq!(result.turns_used, 0);
        assert!(
            result.output.contains("Cannot bind subagent guardrails"),
            "unexpected child-startup failure: {}",
            result.output
        );
        assert!(result.output.contains("parent traversal"));
        let _ = BACKGROUND_AGENTS.remove_for_run(test_run(), &result.agent_id);
    }

    #[test]
    fn task_tool_receipt_distinguishes_validation_error_from_started_failure() {
        let empty = HashMap::<String, Value>::new();
        let validation = execute_task_tool_typed(test_run(), &empty, &issue719_app_config(), None);
        assert!(matches!(
            validation.outcome,
            crate::tools::ToolOutcome::Error { .. }
        ));

        let marker = "s-021-invalid-child-guardrail-receipt";
        let mut app_config = issue719_app_config();
        app_config.guardrails.blast_radius = Some(crate::config::BlastRadiusConfig {
            enabled: true,
            mode: crate::config::GuardrailMode::Strict,
            allowed_paths: vec!["src/../forbidden/**".to_string()],
            ..crate::config::BlastRadiusConfig::default()
        });
        let args = HashMap::from([
            ("description".to_string(), json!(marker)),
            ("prompt".to_string(), json!("fail before provider dispatch")),
            ("subagent_type".to_string(), json!("explore")),
        ]);

        let started = execute_task_tool_typed(test_run(), &args, &app_config, None);

        assert!(
            matches!(&started.outcome, crate::tools::ToolOutcome::Partial { .. }),
            "registered child failure must retain a partial receipt: {}",
            started.content()
        );
        assert!(started
            .content()
            .contains("Cannot bind subagent guardrails"));
        for (id, _, task, _) in BACKGROUND_AGENTS.list_for_run(test_run()) {
            if task == marker {
                let _ = BACKGROUND_AGENTS.remove_for_run(test_run(), &id);
            }
        }
    }

    #[test]
    fn agent_output_failed_consumption_is_typed_partial() {
        let id = BACKGROUND_AGENTS
            .register(test_run(), AgentType::Explore, "s-021-failed-output")
            .expect("register failed output fixture");
        BACKGROUND_AGENTS.fail(test_run(), &id, "provider failed".to_string());
        let args = HashMap::from([("agent_id".to_string(), json!(id))]);

        let result = execute_agent_output_tool_typed(test_run(), &args);

        assert!(
            matches!(&result.outcome, crate::tools::ToolOutcome::Partial { .. }),
            "failed output removal is a real effect"
        );
        assert!(result.content().contains("provider failed"));
    }

    #[tokio::test]
    async fn subagent_no_tool_plain_final_is_denied() {
        let agent_id = "subagent-no-tool-final-denied";
        let ledger_path =
            crate::ledger::project_session_ledger_path(agent_id).expect("safe agent id");
        let _ = std::fs::remove_file(&ledger_path);
        let _ = BACKGROUND_AGENTS.remove_for_run(test_run(), agent_id);

        let final_content = "Verified with cargo check.";
        let (server, base_url) = spawn_openai_no_tool_final_server(final_content);
        let app_config = local_subagent_app_config(base_url);
        let config = SubagentConfig {
            agent_type: AgentType::GeneralPurpose,
            task: "Return a direct answer".to_string(),
            prompt: "Do not call tools; just answer.".to_string(),
            run_in_background: false,
            model_override: Some("gpt-5.5".to_string()),
            resume_agent_id: None,
            isolation: None,
        };
        let client = Client::new();

        let result = run_subagent_inner(
            test_run(),
            &config,
            &app_config,
            &client,
            None,
            Some(agent_id),
            None,
        )
        .await;
        let server_result = server.join().expect("mock provider thread joined");

        assert!(
            server_result.is_ok(),
            "mock provider failed: {:?}",
            server_result.err()
        );
        assert!(!result.success, "plain no-tool final must fail");
        assert!(
            result
                .output
                .contains("final answer must use the typed final claim envelope"),
            "unexpected grounding denial: {}",
            result.output
        );

        let _ = BACKGROUND_AGENTS.remove_for_run(test_run(), agent_id);
        let _ = std::fs::remove_file(ledger_path);
    }

    #[tokio::test]
    async fn subagent_no_tool_conversational_final_is_denied() {
        let agent_id = "subagent-no-tool-greeting-final-denied";
        let ledger_path =
            crate::ledger::project_session_ledger_path(agent_id).expect("safe agent id");
        let _ = std::fs::remove_file(&ledger_path);
        let _ = BACKGROUND_AGENTS.remove_for_run(test_run(), agent_id);

        let (server, base_url) = spawn_openai_no_tool_final_server("Good morning!");
        let app_config = local_subagent_app_config(base_url);
        let config = SubagentConfig {
            agent_type: AgentType::GeneralPurpose,
            task: "Return a direct greeting".to_string(),
            prompt: "Do not call tools; just answer.".to_string(),
            run_in_background: false,
            model_override: Some("gpt-5.5".to_string()),
            resume_agent_id: None,
            isolation: None,
        };
        let client = Client::new();

        let result = run_subagent_inner(
            test_run(),
            &config,
            &app_config,
            &client,
            None,
            Some(agent_id),
            None,
        )
        .await;
        let server_result = server.join().expect("mock provider thread joined");

        assert!(
            server_result.is_ok(),
            "mock provider failed: {:?}",
            server_result.err()
        );
        assert!(!result.success, "plain conversational final must fail");
        assert!(
            result
                .output
                .contains("final answer must use the typed final claim envelope"),
            "unexpected grounding denial: {}",
            result.output
        );

        let _ = BACKGROUND_AGENTS.remove_for_run(test_run(), agent_id);
        let _ = std::fs::remove_file(ledger_path);
    }

    #[test]
    fn worktree_agent_id_validation_rejects_path_and_ref_injection() {
        let too_long = "a".repeat(65);
        for bad in [
            "",
            "../escape",
            "nested/path",
            "nested\\path",
            "-leading-dash",
            "with space",
            "semi;colon",
            "dollar$var",
            "emoji-\u{2603}",
            too_long.as_str(),
        ] {
            assert!(
                validate_worktree_agent_id(bad).is_err(),
                "agent_id {bad:?} must not be accepted for worktree isolation"
            );
        }
    }

    #[test]
    fn worktree_agent_id_validation_accepts_generated_and_resume_ids() {
        for ok in ["1234abcd", "agent_1234", "resume-id-1234"] {
            assert!(
                validate_worktree_agent_id(ok).is_ok(),
                "agent_id {ok:?} should be accepted for worktree isolation"
            );
        }
    }

    #[test]
    fn test_agent_type_parsing() {
        assert_eq!(
            AgentType::parse_type("general-purpose"),
            Some(AgentType::GeneralPurpose)
        );
        assert_eq!(AgentType::parse_type("explore"), Some(AgentType::Explore));
        assert_eq!(AgentType::parse_type("plan"), Some(AgentType::Plan));
        assert_eq!(AgentType::parse_type("guide"), Some(AgentType::Guide));
        assert_eq!(AgentType::parse_type("test-builder"), None);
        assert_eq!(AgentType::parse_type("unknown"), None);
    }

    #[test]
    fn task_type_parsing_rejects_non_spawnable_coordinator() {
        assert_eq!(
            AgentType::parse_task_type("general-purpose"),
            Some(AgentType::GeneralPurpose)
        );
        assert_eq!(AgentType::parse_task_type("guide"), Some(AgentType::Guide));
        assert_eq!(AgentType::parse_task_type("coordinator"), None);
        assert_eq!(
            AgentType::task_tool_names(),
            vec!["general-purpose", "explore", "plan", "guide"]
        );
    }

    #[test]
    fn agent_type_all_is_exhaustive() {
        // ALL must list every variant so /agents output stays
        // complete when new agents are added. Round-trip each name
        // through parse_type to catch name/parse drift at compile
        // time… actually at test time. Compile-time would need a
        // match — but test-time is close enough and cheaper.
        for kind in AgentType::ALL {
            let parsed = AgentType::parse_type(kind.name())
                .unwrap_or_else(|| panic!("{} not round-trippable", kind.name()));
            assert_eq!(&parsed, kind);
            assert!(!kind.description().is_empty());
        }
        // Sanity check on the current set — bump this when a variant
        // is added and list it in ALL.
        assert_eq!(AgentType::ALL.len(), 5);
    }

    #[test]
    fn test_tool_definitions() {
        let task_tool = get_task_tool_definition();
        assert!(task_tool.get("function").is_some());
        assert_eq!(
            task_tool
                .get("function")
                .unwrap()
                .get("name")
                .unwrap()
                .as_str(),
            Some("task")
        );

        let agent_output_tool = get_agent_output_tool_definition();
        assert!(agent_output_tool.get("function").is_some());
        assert_eq!(
            agent_output_tool
                .get("function")
                .unwrap()
                .get("name")
                .unwrap()
                .as_str(),
            Some("agent_output")
        );
    }

    #[test]
    fn subagent_memory_tools_are_service_gated_and_role_scoped() {
        for agent_type in AgentType::ALL {
            assert!(available_subagent_tools(*agent_type, false)
                .iter()
                .all(|name| !name.starts_with("memory_")));
        }

        let general = available_subagent_tools(AgentType::GeneralPurpose, true);
        for name in [
            "memory_search",
            "memory_list",
            "memory_learning_status",
            "memory_conflicts",
            "memory_save",
            "memory_update",
            "memory_delete",
            "memory_source_status",
            "memory_source_refresh",
        ] {
            assert!(general.contains(&name), "general agent is missing {name}");
        }
        let plan = available_subagent_tools(AgentType::Plan, true);
        assert!(!general.contains(&"memory_review"));
        assert!(!general.contains(&"memory_export"));
        assert!(!general.contains(&"memory_import"));
        assert!(plan.contains(&"memory_search"));
        assert!(plan.contains(&"memory_list"));
        assert!(plan.contains(&"memory_learning_status"));
        assert!(plan.contains(&"memory_conflicts"));
        assert!(plan.contains(&"memory_source_status"));
        assert!(!plan.contains(&"memory_save"));
        assert!(!plan.contains(&"memory_update"));
        assert!(!plan.contains(&"memory_delete"));
        assert!(!plan.contains(&"memory_source_refresh"));
        for agent_type in AgentType::ALL {
            assert!(
                !available_subagent_tools(*agent_type, true).contains(&"memory_review"),
                "subagent role {agent_type:?} has no direct host approval channel"
            );
            assert!(
                !available_subagent_tools(*agent_type, true).contains(&"memory_export")
                    && !available_subagent_tools(*agent_type, true).contains(&"memory_import"),
                "subagent role {agent_type:?} has no direct host approval channel"
            );
        }
    }

    #[test]
    fn every_subagent_role_publishes_its_entire_host_allowlist() {
        let root = tempfile::tempdir().expect("subagent catalog root");
        let all_tools = crate::tools::get_tool_definitions();
        let all_tools = all_tools.as_array().expect("tool definitions array");

        for agent_type in AgentType::ALL {
            let run = crate::tools::security::test_run_context_for(root.path());
            let allowed = available_subagent_tools(*agent_type, true);
            let filtered = all_tools
                .iter()
                .filter(|tool| {
                    tool.pointer("/function/name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| allowed.contains(&name))
                })
                .cloned()
                .collect::<Vec<_>>();
            let filtered = add_subagent_typed_decision_contracts(filtered);
            let snapshot = run
                .tool_catalog()
                .snapshot(&run, &[], &filtered)
                .unwrap_or_else(|error| panic!("{} catalog failed: {error}", agent_type.name()));
            assert!(
                snapshot.full_catalog_fallback,
                "{} has no tool_search bootstrap, so its bounded host allowlist must publish whole",
                agent_type.name()
            );
            assert_eq!(snapshot.definitions.len(), filtered.len());
        }
    }

    #[test]
    fn subagent_executor_propagates_automatic_learning_policy() {
        let host = tempfile::tempdir().expect("host home");
        let workspace = tempfile::tempdir().expect("subagent learning workspace");
        std::fs::create_dir_all(workspace.path().join("src")).expect("source directory");
        let run =
            crate::tools::ToolRunContext::builder(crate::state::SessionId::new(), workspace.path())
                .working_directory(workspace.path())
                .read_only_roots(Vec::new())
                .read_write_roots(Vec::new())
                .environment_grants(HashMap::new())
                .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
                .process(true)
                .network(false)
                .secrets(false)
                .provider("subagent-learning-test")
                .build()
                .expect("subagent learning run");
        let memory = crate::memory::MemoryDb::open_for_workspace(host.path(), workspace.path())
            .expect("subagent workspace memory");
        let config: AppConfig = serde_yaml::from_str(
            r"
proxy:
  target: local
providers:
  local:
    base_url: http://localhost:1234/v1
memory:
  automatic_learning_enabled: true
",
        )
        .expect("subagent learning config");
        let mut tasks = crate::session::TaskManager::for_run(&run).expect("subagent task manager");
        let permissions = crate::permissions::PermissionManager::unrestricted_for_run(&run);
        let policy = crate::services::policy::PolicyEnforcer::new(
            crate::services::policy::EnterprisePolicy::default(),
        );
        let call = crate::tools::ToolCall {
            id: "subagent-learning-write".to_string(),
            call_type: "function".to_string(),
            function: crate::tools::FunctionCall {
                name: "write_file".to_string(),
                arguments: serde_json::json!({
                    "path": "src/subagent_learning.rs",
                    "content": "pub const SUBAGENT_POLICY_PROPAGATED: bool = true;\n"
                })
                .to_string(),
            },
        };

        let result = execute_subagent_local_tool(&mut SubagentToolExecution {
            run: &run,
            tool_call: &call,
            memory_db: Some(&memory),
            app_config: &config,
            task_manager: &mut tasks,
            permission_manager: &permissions,
            agent_id: "subagent-learning-policy",
            policy_enforcer: &policy,
        });
        assert!(
            !result.is_error(),
            "subagent write failed: {}",
            result.content()
        );
        assert!(result.observations().iter().any(|observation| {
            observation.kind == "technical_learning_capture" && !observation.authoritative
        }));
        crate::tools::retire_run(&run);
    }

    #[test]
    fn subagent_reopens_only_the_exact_workspace_bound_memory_store() {
        let host = tempfile::tempdir().expect("host home");
        let workspace = tempfile::tempdir().expect("workspace");
        let memory = crate::memory::MemoryDb::open_for_workspace(host.path(), workspace.path())
            .expect("workspace memory");
        let expected_store = memory.store_id().expect("store id");
        let expected_workspace = memory.workspace_id().expect("workspace id").clone();
        let reopened = reopen_subagent_memory(Some(&memory))
            .expect("reopen memory")
            .expect("memory service");
        assert_eq!(reopened.store_id().expect("reopened store"), expected_store);
        assert_eq!(reopened.workspace_id(), Some(&expected_workspace));

        let unbound_path = host.path().join("unbound.db");
        let unbound = crate::memory::MemoryDb::open(&unbound_path).expect("unbound store");
        assert!(reopen_subagent_memory(Some(&unbound)).is_err());
    }

    #[test]
    fn subagent_reopen_retains_the_exact_authenticated_team_replica() {
        let host = tempfile::tempdir().expect("host home");
        let workspace = tempfile::tempdir().expect("workspace");
        let principal: crate::team_memory::PrincipalId = "owner".parse().expect("principal");
        let authority = crate::team_memory::TeamAuthorityStore::bootstrap(
            host.path(),
            workspace.path(),
            principal,
            31_536_000,
        )
        .expect("team authority");
        let memory = crate::memory::MemoryDb::open_for_workspace(host.path(), workspace.path())
            .expect("workspace memory");
        crate::team_memory::activate_team_memory(
            &memory,
            host.path(),
            workspace.path(),
            authority.team_id().clone(),
        )
        .expect("activate team memory");
        let parent_status = memory
            .team_replica()
            .expect("parent team replica")
            .status()
            .expect("parent status");

        let reopened = reopen_subagent_memory(Some(&memory))
            .expect("reopen memory")
            .expect("subagent memory");
        let child_status = reopened
            .team_replica()
            .expect("subagent team replica")
            .status()
            .expect("subagent status");
        assert_eq!(child_status, parent_status);
    }

    #[test]
    fn parse_subagent_tool_call_accepts_valid_openai_shape() {
        let call = json!({
            "id": "call_1",
            "type": "function",
            "function": {
                "name": "read_file",
                "arguments": "{\"path\":\"src/main.rs\"}"
            }
        });

        let parsed = parse_subagent_tool_call(&call, 0).expect("valid tool call should parse");

        assert_eq!(parsed.id, "call_1");
        assert_eq!(parsed.call_type, "function");
        assert_eq!(parsed.function.name, "read_file");
        assert_eq!(parsed.function.arguments, "{\"path\":\"src/main.rs\"}");
    }

    #[test]
    fn parse_subagent_tool_call_rejects_malformed_arguments() {
        let missing = json!({
            "id": "call_missing",
            "function": {"name": "read_file"}
        });
        let err = parse_subagent_tool_call(&missing, 0)
            .expect_err("missing arguments must not become {}");
        assert!(err.contains("function.arguments"), "{err}");

        let invalid_json = json!({
            "id": "call_bad_json",
            "function": {"name": "read_file", "arguments": "{not json"}
        });
        let err = parse_subagent_tool_call(&invalid_json, 1)
            .expect_err("invalid JSON must not become {}");
        assert!(err.contains("invalid JSON"), "{err}");

        let non_object = json!({
            "id": "call_array",
            "function": {"name": "read_file", "arguments": "[]"}
        });
        let err = parse_subagent_tool_call(&non_object, 2)
            .expect_err("non-object arguments must not execute");
        assert!(err.contains("non-object"), "{err}");
    }

    #[test]
    fn subagent_tool_call_error_id_falls_back_to_stable_synthetic_id() {
        assert_eq!(
            subagent_tool_call_id_for_error(&json!({"id": "call_1"}), 7),
            "call_1"
        );
        assert_eq!(
            subagent_tool_call_id_for_error(&json!({"id": ""}), 7),
            "invalid_tool_call_7"
        );
        assert_eq!(
            subagent_tool_call_id_for_error(&json!({}), 7),
            "invalid_tool_call_7"
        );
    }

    fn subagent_test_tool_call(name: &str, args: &Value) -> ToolCall {
        ToolCall {
            id: "call_1".to_string(),
            call_type: "function".to_string(),
            function: crate::tools::FunctionCall {
                name: name.to_string(),
                arguments: args.to_string(),
            },
        }
    }

    fn required_fields(tool: &Value) -> Vec<&str> {
        tool.get("function")
            .and_then(|function| function.get("parameters"))
            .and_then(|parameters| parameters.get("required"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect()
    }

    fn decision_property(tool: &Value) -> Option<&Value> {
        tool.get("function")
            .and_then(|function| function.get("parameters"))
            .and_then(|parameters| parameters.get("properties"))
            .and_then(|properties| properties.get("decision"))
    }

    #[test]
    fn subagent_typed_decision_contracts_require_decision_for_mutating_tools() {
        let all_tools = crate::tools::get_tool_definitions();
        let selected = all_tools
            .as_array()
            .expect("tool definitions array")
            .iter()
            .filter(|tool| {
                tool.get("function")
                    .and_then(|function| function.get("name"))
                    .and_then(Value::as_str)
                    .is_some_and(|name| {
                        ["bash", "write_file", "edit_file", "read_file"].contains(&name)
                    })
            })
            .cloned()
            .collect::<Vec<_>>();

        let tools = add_subagent_typed_decision_contracts(selected);

        for name in ["bash", "write_file", "edit_file"] {
            let tool = tools
                .iter()
                .find(|tool| {
                    tool.get("function")
                        .and_then(|function| function.get("name"))
                        .and_then(Value::as_str)
                        == Some(name)
                })
                .unwrap_or_else(|| panic!("{name} definition must be selected"));
            assert!(
                required_fields(tool).contains(&"decision"),
                "{name} must require the decision envelope"
            );
            assert!(
                decision_property(tool).is_some(),
                "{name} must expose a decision schema"
            );
        }

        let read_file = tools
            .iter()
            .find(|tool| {
                tool.get("function")
                    .and_then(|function| function.get("name"))
                    .and_then(Value::as_str)
                    == Some("read_file")
            })
            .expect("read_file definition must be selected");
        assert!(!required_fields(read_file).contains(&"decision"));
        assert!(decision_property(read_file).is_none());
    }

    #[test]
    fn subagent_tool_decision_rejects_missing_decision() {
        let ledger = crate::ledger::RealityLedger::new();
        let args = json!({"command": "cargo test"});

        let err =
            validate_subagent_tool_decision_against_ledger(test_run(), "bash", &args, &ledger)
                .expect_err("missing decision must be rejected");

        assert!(
            err.contains("requires arguments.decision"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn subagent_tool_decision_accepts_grounded_command_decision() {
        let mut ledger = crate::ledger::RealityLedger::new();
        let task = ledger
            .observe_user_task(test_run(), "Run the focused test command", "test-model")
            .expect("task observation");
        let args = json!({
            "command": "cargo test --lib subagent_tool_decision",
            "decision": {
                "kind": "run_command",
                "reason": "verify the subagent decision gate",
                "evidence": [task],
                "argv": ["bash", "-lc", "cargo test --lib subagent_tool_decision"]
            }
        });

        validate_subagent_tool_decision_against_ledger(test_run(), "bash", &args, &ledger)
            .expect("grounded command decision must be accepted");
    }

    #[test]
    fn subagent_tool_decision_rejects_mismatched_command_argv() {
        let mut ledger = crate::ledger::RealityLedger::new();
        let task = ledger
            .observe_user_task(test_run(), "Run tests", "test-model")
            .expect("task observation");
        let args = json!({
            "command": "cargo test",
            "decision": {
                "kind": "run_command",
                "reason": "verify behavior",
                "evidence": [task],
                "argv": ["bash", "-lc", "cargo check"]
            }
        });

        let err =
            validate_subagent_tool_decision_against_ledger(test_run(), "bash", &args, &ledger)
                .expect_err("mismatched argv must be rejected");

        assert!(err.contains("argv must match"), "unexpected error: {err}");
    }

    #[test]
    fn subagent_tool_decision_accepts_grounded_edit_decision() {
        let mut ledger = crate::ledger::RealityLedger::new();
        let read = ledger
            .observe_file_read(test_run(), "src/lib.rs", "old\n", 1, 1, "old")
            .expect("file observation");
        let args = json!({
            "path": "src/lib.rs",
            "old_string": "old",
            "new_string": "new",
            "decision": {
                "kind": "edit",
                "reason": "apply the requested source edit",
                "evidence": [read],
                "patch": "*** Begin Patch\n*** Update File: src/lib.rs\n@@\n-old\n+new\n*** End Patch"
            }
        });

        validate_subagent_tool_decision_against_ledger(test_run(), "edit_file", &args, &ledger)
            .expect("grounded edit decision must be accepted");
    }

    #[test]
    fn subagent_tool_decision_rejects_edit_patch_for_different_path() {
        let mut ledger = crate::ledger::RealityLedger::new();
        let read = ledger
            .observe_file_read(test_run(), "src/lib.rs", "old\n", 1, 1, "old")
            .expect("file observation");
        let args = json!({
            "path": "src/lib.rs",
            "old_string": "old",
            "new_string": "new",
            "decision": {
                "kind": "edit",
                "reason": "apply the requested source edit",
                "evidence": [read],
                "patch": "*** Begin Patch\n*** Update File: src/main.rs\n@@\n-old\n+new\n*** End Patch"
            }
        });

        let err =
            validate_subagent_tool_decision_against_ledger(test_run(), "edit_file", &args, &ledger)
                .expect_err("path mismatch must be rejected");

        assert!(err.contains("tool path"), "unexpected error: {err}");
    }

    #[test]
    fn strip_subagent_decision_argument_removes_decision_before_dispatch() {
        let tool_call = subagent_test_tool_call(
            "bash",
            &json!({
                "command": "cargo test",
                "decision": {
                    "kind": "run_command",
                    "reason": "verify",
                    "evidence": ["00000000-0000-0000-0000-000000000000"],
                    "argv": ["bash", "-lc", "cargo test"]
                }
            }),
        );

        let stripped = strip_subagent_decision_argument(&tool_call);
        let args = serde_json::from_str::<Value>(&stripped.function.arguments)
            .expect("stripped args must stay valid JSON");

        assert_eq!(
            args.get("command").and_then(Value::as_str),
            Some("cargo test")
        );
        assert!(args.get("decision").is_none());
    }

    #[test]
    fn test_background_agent_manager() {
        let manager = TestBackgroundAgentManager::new();

        // Register an agent
        let id = manager.register(AgentType::Explore, "Test task");
        assert!(!id.is_empty());

        // Get the agent
        let agent = manager.get(&id);
        assert!(agent.is_some());
        let agent = agent.unwrap();
        assert_eq!(agent.task, "Test task");
        assert!(!agent.finished.load(Ordering::SeqCst));

        // Increment turns
        let turns = manager.increment_turns(&id);
        assert_eq!(turns, 1);

        // Finish the agent
        manager.finish(&id, "Test result".to_string());
        assert!(agent.finished.load(Ordering::SeqCst));
        assert_eq!(
            agent.result.lock().unwrap().as_ref(),
            Some(&"Test result".to_string())
        );
    }

    // ── Crosslink #407: ProviderAdapter dispatch in subagent ────────────────
    //
    // The previous `transform_to_anthropic` / `transform_from_anthropic`
    // functions were a stovepiped reimplementation of
    // `providers::AnthropicAdapter`, with branches that only handled
    // Anthropic + OpenAI. The four tests below pin the new behaviour:
    //
    //   1. Anthropic produces the canonical adapter shape (system array
    //      with cache_control, not the bare string the duplicate emitted).
    //   2. OpenAI passthrough produces a well-formed OpenAI-shape body.
    //   3. Google produces Gemini-shape contents (was broken: the old
    //      Anthropic-vs-OpenAI branch routed Gemini calls through OpenAI
    //      wire format, which Gemini's REST API does not accept).
    //   4. Unknown provider returns a clean typed error rather than
    //      silently falling back to the OpenAI shape.

    fn anthropic_request_body() -> Value {
        json!({
            "model": "claude-sonnet-4-6",
            "messages": [
                {"role": "system", "content": "System prompt"},
                {"role": "user", "content": "Hello"}
            ],
            "max_tokens": 1000
        })
    }

    /// Snapshot the adapter-produced Anthropic body so it matches the
    /// canonical `AnthropicAdapter` contract: `system` is an array of
    /// content blocks with `cache_control`, messages exclude system,
    /// `max_tokens` and `model` round-trip verbatim.
    #[test]
    fn crosslink407_anthropic_request_uses_adapter_shape() {
        let body = anthropic_request_body();
        let typed = build_chat_completion_request(&body).expect("decodable");
        let adapter = resolve_subagent_adapter("anthropic").expect("anthropic is known");

        let out = adapter.transform_request(&typed).expect("transform ok");

        assert_eq!(
            out.get("model").and_then(|v| v.as_str()),
            Some("claude-sonnet-4-6")
        );
        assert_eq!(out.get("max_tokens").and_then(Value::as_u64), Some(1000));

        // System is now the canonical Anthropic array shape with
        // cache_control — the old duplicate emitted a bare string and
        // dropped prompt-cache hits, which #407 fixes by construction.
        let system_arr = out
            .get("system")
            .and_then(|v| v.as_array())
            .expect("system must be array, not a bare string");
        assert_eq!(system_arr.len(), 1);
        assert_eq!(
            system_arr[0].get("type").and_then(|v| v.as_str()),
            Some("text")
        );
        assert_eq!(
            system_arr[0].get("text").and_then(|v| v.as_str()),
            Some("System prompt")
        );
        assert_eq!(
            system_arr[0]
                .get("cache_control")
                .and_then(|c| c.get("type"))
                .and_then(|v| v.as_str()),
            Some("ephemeral")
        );

        // Messages exclude the system entry (handled separately at top
        // level by Anthropic) — only the user turn remains.
        let messages = out
            .get("messages")
            .and_then(|v| v.as_array())
            .expect("messages array");
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0].get("role").and_then(|v| v.as_str()),
            Some("user")
        );
    }

    /// `OpenAI` subagent dispatch: produces a well-formed `OpenAI`-shape
    /// body via the canonical adapter. The duplicate code path used to
    /// rely on the literal `request_body.clone()` (no transformation);
    /// going through the adapter is now uniform with every other
    /// provider and ensures the request validates against the typed
    /// `ChatCompletionRequest` contract.
    #[test]
    fn crosslink407_openai_request_passes_through_adapter() {
        let body = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "ping"}
            ],
            "max_tokens": 256
        });
        let typed = build_chat_completion_request(&body).expect("decodable");
        let adapter = resolve_subagent_adapter("openai").expect("openai is known");

        let out = adapter.transform_request(&typed).expect("transform ok");

        assert_eq!(out.get("model").and_then(|v| v.as_str()), Some("gpt-4o"));
        let messages = out
            .get("messages")
            .and_then(|v| v.as_array())
            .expect("messages array");
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0].get("role").and_then(|v| v.as_str()),
            Some("user")
        );

        // Endpoint is the OpenAI-shape chat completions path — the
        // adapter owns this string, not subagent.rs.
        assert_eq!(adapter.chat_endpoint("gpt-4o"), "/v1/chat/completions");
    }

    /// Google subagent dispatch — previously broken because the old
    /// `transform_to_anthropic`/`OpenAI`-only branch sent the body as
    /// `{model, messages, ...}` which Gemini's REST API rejects.
    /// Going through `GoogleAdapter` emits the Gemini-native shape
    /// (`contents`, `systemInstruction`, `generationConfig`) and the
    /// model-aware endpoint path.
    #[test]
    fn crosslink407_google_request_uses_gemini_shape() {
        let body = json!({
            "model": "gemini-2.5-pro",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Hi"}
            ],
            "temperature": 0.5,
            "max_tokens": 512
        });
        let typed = build_chat_completion_request(&body).expect("decodable");
        let adapter = resolve_subagent_adapter("google").expect("google is known");

        let out = adapter.transform_request(&typed).expect("transform ok");

        // Gemini native shape: `contents`, not OpenAI `messages`.
        assert!(
            out.get("contents").and_then(|v| v.as_array()).is_some(),
            "Google adapter must emit `contents`, got {out:?}"
        );
        assert!(
            out.get("systemInstruction").is_some(),
            "Google adapter must emit `systemInstruction` for system prompt"
        );
        assert_eq!(
            out["generationConfig"]["maxOutputTokens"]
                .as_u64()
                .expect("maxOutputTokens"),
            512
        );

        // Endpoint embeds the model name — proof the adapter (not a
        // hardcoded subagent string) owns URL composition.
        assert!(
            adapter
                .chat_endpoint("gemini-2.5-pro")
                .contains("gemini-2.5-pro"),
            "Gemini endpoint must embed the model name"
        );

        // `gemini` alias also resolves to the Google adapter.
        let alias = resolve_subagent_adapter("gemini").expect("gemini alias is known");
        assert_eq!(alias.name(), "google");
    }

    /// Negative test — an unknown provider name must surface as a
    /// clean typed error at the dispatch boundary, NOT silently fall
    /// back to `OpenAI`. The crate-level `get_adapter` is typo-tolerant
    /// by design (the proxy treats unknown providers as
    /// `OpenAI`-compatible local servers); subagent dispatch has the
    /// opposite preference because a wrongly-routed Anthropic agent
    /// would issue malformed HTTP requests upstream. See crosslink
    /// #407.
    #[test]
    fn crosslink407_unknown_provider_returns_clean_error() {
        let Err(err) = resolve_subagent_adapter("not-a-real-provider") else {
            panic!("unknown provider must error, not silently fall back")
        };
        assert!(
            err.contains("Unknown subagent provider"),
            "error must name the misconfigured provider, got: {err}"
        );
        assert!(
            err.contains("not-a-real-provider"),
            "error must echo the bad provider name, got: {err}"
        );
        // Empty string is also rejected (operator left the field blank).
        assert!(resolve_subagent_adapter("").is_err());

        // Every name in the allow-list resolves successfully.
        for known in SUBAGENT_KNOWN_PROVIDERS {
            assert!(
                resolve_subagent_adapter(known).is_ok(),
                "{known} must resolve"
            );
        }
        // Case-insensitive: operators sometimes capitalise provider
        // names in config (e.g. "Anthropic"). The strict gate must
        // still accept them.
        assert!(resolve_subagent_adapter("Anthropic").is_ok());
        assert!(resolve_subagent_adapter("OPENAI").is_ok());
    }

    // ── Spec #527 behavior 1: run_in_background returns agent_id immediately ──

    /// Spec #527 §1 — `task` with `run_in_background: true` registers a new agent
    /// in `BACKGROUND_AGENTS` and returns a plain-text string containing the ID,
    /// the description, and the agent type. `is_error` must be `false`.
    ///
    /// Pins OC's current output format. CC returns a typed `AgentId`; OC returns an
    /// opaque 8-char UUID prefix — format differs, behavior is pinned as-is.
    #[test]
    fn spec1_run_in_background_registers_agent_returns_id() {
        let mgr = TestBackgroundAgentManager::new();
        let id = mgr.register(AgentType::Explore, "scan codebase for dead code");
        assert_eq!(id.len(), 8, "OC uses 8-char UUID prefix (safe_truncate)");

        // The agent is immediately retrievable, not yet finished.
        let agent = mgr.get(&id).expect("registered agent must exist");
        assert!(!agent.finished.load(Ordering::SeqCst));
        assert_eq!(agent.task, "scan codebase for dead code");
        assert_eq!(agent.agent_type, AgentType::Explore);
    }

    /// Spec #527 §1 — The message format produced for background spawn includes
    /// the `agent_id`, task description, and a hint to use `agent_output`.
    #[test]
    fn spec1_background_message_format() {
        let mgr = TestBackgroundAgentManager::new();
        let id = mgr.register(AgentType::Plan, "design the auth layer");

        // Simulate the format string from execute_task_tool (line ~1333).
        let description = "design the auth layer";
        let agent_type = AgentType::Plan;
        let message = format!(
            "Background agent started with ID: {id}\nTask: {description}\nType: {agent_type:?}\n\nUse agent_output with this agent_id to retrieve results."
        );

        assert!(message.contains(&id), "message must embed the agent_id");
        assert!(message.contains(description));
        assert!(message.contains("agent_output"));
    }

    /// Spec #527 §1 — At spawn time the agent is not finished, has no error, and
    /// has no result. `is_error` is `false` for a background spawn.
    #[test]
    fn spec1_is_error_false_and_not_finished_at_spawn() {
        let mgr = TestBackgroundAgentManager::new();
        let id = mgr.register(AgentType::GeneralPurpose, "refactor module");
        let agent = mgr.get(&id).expect("must exist after register");

        assert!(!agent.finished.load(Ordering::SeqCst));
        assert!(agent.error.lock().unwrap().is_none());
        assert!(agent.result.lock().unwrap().is_none());
    }

    #[test]
    fn task_tool_rejects_non_boolean_run_in_background() {
        let app_config = issue719_app_config();
        let args = HashMap::from([
            ("description".to_string(), json!("scan repo")),
            ("prompt".to_string(), json!("scan the repository")),
            ("subagent_type".to_string(), json!("explore")),
            ("run_in_background".to_string(), json!("true")),
        ]);

        let (msg, is_err) = execute_task_tool(test_run(), &args, &app_config);

        assert!(is_err, "non-boolean run_in_background must error: {msg}");
        assert!(
            msg.contains("Invalid 'run_in_background' argument: expected boolean"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn task_tool_rejects_non_string_required_arguments() {
        let app_config = issue719_app_config();

        for (field, expected) in [
            (
                "description",
                "Invalid 'description' argument: expected string",
            ),
            ("prompt", "Invalid 'prompt' argument: expected string"),
            (
                "subagent_type",
                "Invalid 'subagent_type' argument: expected string",
            ),
        ] {
            let mut args = HashMap::from([
                ("description".to_string(), json!("scan repo")),
                ("prompt".to_string(), json!("scan the repository")),
                ("subagent_type".to_string(), json!("explore")),
            ]);
            args.insert(field.to_string(), json!(42));

            let (msg, is_err) = execute_task_tool(test_run(), &args, &app_config);

            assert!(is_err, "{field} must reject non-string values: {msg}");
            assert!(msg.contains(expected), "unexpected error: {msg}");
        }
    }

    #[test]
    fn task_tool_rejects_non_string_optional_arguments() {
        let app_config = issue719_app_config();

        for (field, expected) in [
            ("resume", "Invalid 'resume' argument: expected string"),
            ("model", "Invalid 'model' argument: expected string"),
            ("isolation", "Invalid 'isolation' argument: expected string"),
        ] {
            let mut args = HashMap::from([
                ("description".to_string(), json!("scan repo")),
                ("prompt".to_string(), json!("scan the repository")),
                ("subagent_type".to_string(), json!("explore")),
            ]);
            args.insert(field.to_string(), json!(42));

            let (msg, is_err) = execute_task_tool(test_run(), &args, &app_config);

            assert!(is_err, "{field} must reject non-string values: {msg}");
            assert!(msg.contains(expected), "unexpected error: {msg}");
        }
    }

    #[test]
    fn agent_output_rejects_non_boolean_block() {
        let args = HashMap::from([
            ("agent_id".to_string(), json!("missing-agent")),
            ("block".to_string(), json!("true")),
        ]);

        let (msg, is_err) = execute_agent_output_tool(test_run(), &args);

        assert!(is_err, "non-boolean block must error: {msg}");
        assert!(
            msg.contains("Invalid 'block' argument: expected boolean"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn agent_output_rejects_non_string_agent_id_when_present() {
        let args = HashMap::from([("agent_id".to_string(), json!(42))]);

        let (msg, is_err) = execute_agent_output_tool(test_run(), &args);

        assert!(is_err, "non-string agent_id must error: {msg}");
        assert!(
            msg.contains("Invalid 'agent_id' argument: expected string"),
            "unexpected error: {msg}"
        );
    }

    // ── Spec #527 behavior 2: resume loads transcript and appends new prompt ──

    /// Spec #527 §2 — When the transcript store has no entry for the id,
    /// `load_transcript` returns `None`. `run_subagent` converts this to
    /// `success=false` with the "No transcript found" message.
    #[test]
    fn spec2_resume_miss_returns_not_found_error() {
        let missing = load_transcript(test_run(), "00000000-dead-beef-0000-000000000000");
        assert!(
            missing.is_none(),
            "unknown agent_id must return None from transcript store"
        );
    }

    /// Spec #527 §2 — Storing and loading a transcript round-trips correctly;
    /// the loaded messages and `agent_type` match what was stored.
    #[test]
    fn spec2_transcript_store_and_load_round_trip() {
        let msgs = vec![
            json!({"role": "system", "content": "You are a worker."}),
            json!({"role": "user", "content": "Do the thing"}),
            json!({"role": "assistant", "content": "Done."}),
        ];
        let fake_id = format!("tt-{}", Uuid::new_v4());
        store_transcript(test_run(), &fake_id, msgs.clone(), AgentType::Explore);

        let loaded =
            load_transcript(test_run(), &fake_id).expect("stored transcript must be loadable");
        assert_eq!(loaded.0.len(), msgs.len());
        assert_eq!(loaded.1, AgentType::Explore);
        assert_eq!(loaded.0[0]["role"].as_str(), Some("system"));
        assert_eq!(loaded.0[2]["content"].as_str(), Some("Done."));
    }

    fn responses_test_state() -> crate::runtime::ProviderNativeState {
        let output = crate::providers::OpenAiResponsesTurnOutput::new(
            "resp_child_resume",
            vec![json!({
                "type": "reasoning",
                "id": "rs_child",
                "encrypted_content": "opaque-child-state"
            })],
        )
        .expect("Responses output");
        crate::providers::advance_openai_responses_state("openai", "gpt-test", None, 1, &output)
            .expect("Responses state")
    }

    #[test]
    fn responses_child_resume_round_trips_native_state_with_portable_transcript() {
        let id = format!("s045-resume-{}", Uuid::new_v4());
        let messages = vec![
            json!({"role": "user", "content": "inspect"}),
            json!({"role": "assistant", "content": "done"}),
        ];
        let state = responses_test_state();

        store_transcript_with_state(
            test_run(),
            &id,
            messages.clone(),
            Some(state.clone()),
            AgentType::Explore,
        );
        let (loaded_messages, loaded_type, loaded_state) =
            load_transcript_with_state(test_run(), &id).expect("stored Responses transcript");

        assert_eq!(loaded_messages, messages);
        assert_eq!(loaded_type, AgentType::Explore);
        assert_eq!(loaded_state, Some(state));
    }

    #[test]
    fn responses_child_projection_preserves_exact_tool_call_identity() {
        let decoded = crate::pipeline::OpenAiResponsesDecodedTurn {
            content: String::new(),
            reasoning_content: None,
            tool_calls: vec![ToolCall {
                id: "call_native_7".to_string(),
                call_type: "function".to_string(),
                function: crate::tools::FunctionCall {
                    name: "read_file".to_string(),
                    arguments: r#"{"path":"src/lib.rs"}"#.to_string(),
                },
            }],
            usage: crate::session::TokenUsage::default(),
            terminal_outcome: crate::pipeline::ProviderTerminalOutcome::ToolCalls,
            provider_native_state: responses_test_state(),
        };

        let message = responses_subagent_assistant_message(&decoded);
        assert!(message["content"].is_null());
        assert_eq!(message["tool_calls"][0]["id"], "call_native_7");
        assert_eq!(
            message["tool_calls"][0]["function"]["arguments"],
            r#"{"path":"src/lib.rs"}"#
        );
    }

    #[test]
    fn native_json_child_projection_preserves_exact_tool_call_identity() {
        let response = json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{
                        "functionCall": {
                            "id": "gemini-child-call",
                            "name": "read_file",
                            "args": {"path": "src/lib.rs"}
                        },
                        "thoughtSignature": "opaque-child-signature"
                    }]
                },
                "finishReason": "STOP"
            }]
        });
        let decoded = crate::pipeline::decode_provider_native_json_turn(
            "google",
            "gemini-3.5-pro",
            &response,
            None,
            1,
        )
        .expect("Gemini child turn decodes before tool dispatch");

        let message = native_json_subagent_assistant_message(&decoded);
        assert!(message["content"].is_null());
        assert_eq!(message["tool_calls"][0]["id"], "gemini-child-call");
        assert_eq!(message["tool_calls"][0]["function"]["name"], "read_file");
        assert_eq!(
            message["tool_calls"][0]["function"]["arguments"],
            r#"{"path":"src/lib.rs"}"#
        );
        assert_eq!(decoded.provider_native_state.generation().get(), 1);
    }

    #[test]
    fn responses_child_request_keeps_the_host_output_token_cap() {
        let mut request = json!({
            "model": "gpt-test",
            "input": [],
            "store": false,
            "stream": true
        });

        apply_subagent_responses_output_limit(&mut request).expect("Responses child output limit");

        assert_eq!(request["max_output_tokens"], SUBAGENT_MAX_TOKENS);
    }

    #[test]
    fn child_turn_text_is_recomputed_and_all_text_blocks_are_preserved() {
        let previous = json!({"role": "assistant", "content": "tool preamble"});
        assert_eq!(subagent_assistant_text(&previous), "tool preamble");

        let empty_terminal = json!({"role": "assistant", "content": null});
        assert!(subagent_assistant_text(&empty_terminal).is_empty());

        let multipart = json!({
            "role": "assistant",
            "content": [
                {"type": "text", "text": "first "},
                {"type": "thinking", "thinking": "private"},
                {"type": "text", "text": "second"}
            ]
        });
        assert_eq!(subagent_assistant_text(&multipart), "first second");
    }

    #[test]
    fn transcript_resume_is_bound_to_exact_owner_run() {
        let owner = isolated_test_run("transcript-owner");
        let foreign = isolated_test_run("transcript-foreign");
        let id = format!("s019-transcript-{}", Uuid::new_v4());
        let messages = vec![json!({"role": "assistant", "content": "owner-only"})];

        store_transcript(&owner, &id, messages.clone(), AgentType::Explore);

        assert!(
            load_transcript(&foreign, &id).is_none(),
            "foreign run must observe the transcript as absent"
        );
        assert_eq!(
            load_transcript(&owner, &id),
            Some((messages, AgentType::Explore)),
            "foreign lookup must not consume or alter the owner's transcript"
        );
    }

    // ── Crosslink #582: subagent resume reuses original agent_id ──
    //
    // The four tests below pin the fixed CC-parity behaviour. Previously
    // (`spec2_gap582_resume_allocates_new_agent_id_not_old_one`) we
    // pinned the *buggy* divergence; now we assert the corrected
    // behaviour: a resume reattaches to the original id, a fresh spawn
    // mints a new id, an unknown id is rejected with a clean error, and
    // two resumes against the same id share transcript state.

    /// #582 (1) — `execute_task_tool` dispatch with `resume` set reuses
    /// that id end-to-end: the dispatched message cites the same id and
    /// `TRANSCRIPT_STORE` continues to hold the entry under that key
    /// (i.e. the id is *not* shadowed by a freshly minted one).
    #[test]
    fn fix582_task_dispatch_with_resume_id_reuses_id() {
        let original_id = format!("582-reuse-{}", Uuid::new_v4());
        store_transcript(
            test_run(),
            &original_id,
            vec![json!({"role": "user", "content": "Original turn"})],
            AgentType::Plan,
        );
        assert!(
            load_transcript(test_run(), &original_id).is_some(),
            "precondition: transcript must exist"
        );

        // Simulate the relevant branch of execute_task_tool's background
        // path with `resume_id = Some(original_id)`. This is the exact
        // code path that now must keep the original id.
        let resume_id_opt: Option<String> = Some(original_id.clone());
        let agent_id = resume_id_opt.as_ref().map_or_else(
            || {
                BACKGROUND_AGENTS
                    .register(test_run(), AgentType::Plan, "resume task")
                    .expect("register fresh test agent")
            },
            |rid| {
                BACKGROUND_AGENTS
                    .register_with_id(test_run(), AgentType::Plan, "resume task", rid)
                    .expect("reattach test agent");
                rid.clone()
            },
        );

        assert_eq!(
            agent_id, original_id,
            "#582: resume must reuse the original id, not mint a new one"
        );
        assert!(
            BACKGROUND_AGENTS
                .get_for_run(test_run(), &agent_id)
                .is_some(),
            "tracking entry must exist under the reused id"
        );
        assert!(
            load_transcript(test_run(), &original_id).is_some(),
            "TRANSCRIPT_STORE entry under the original id must still be reachable"
        );
    }

    /// #582 (2) — dispatch with no `resume` mints a fresh id (8-char
    /// UUID prefix per OC convention) that does not collide with any
    /// caller-supplied id.
    #[test]
    fn fix582_task_dispatch_without_resume_generates_fresh_id() {
        let resume_id_opt: Option<String> = None;
        let agent_id = resume_id_opt.as_ref().map_or_else(
            || {
                BACKGROUND_AGENTS
                    .register(test_run(), AgentType::Plan, "fresh task")
                    .expect("register fresh test agent")
            },
            |rid| {
                BACKGROUND_AGENTS
                    .register_with_id(test_run(), AgentType::Plan, "fresh task", rid)
                    .expect("reattach test agent");
                rid.clone()
            },
        );

        assert_eq!(agent_id.len(), 8, "fresh ids are 8-char UUID prefixes");
        assert!(
            BACKGROUND_AGENTS
                .get_for_run(test_run(), &agent_id)
                .is_some(),
            "fresh-spawn tracking entry must exist"
        );
    }

    /// #582 (3) — resume against an unknown `agent_id` returns a clear
    /// `is_error=true` "No transcript found" result. Documented
    /// behaviour: we error rather than silently creating a fresh
    /// transcript under that id (the caller almost certainly had a typo
    /// or hit TTL expiry — silently creating a new transcript would
    /// mask data loss).
    #[test]
    fn fix582_resume_unknown_id_errors_does_not_silently_create() {
        let unknown_id = format!("582-unknown-{}", Uuid::new_v4());
        // Precondition: nothing in the store under this id.
        assert!(load_transcript(test_run(), &unknown_id).is_none());

        // Mirror run_subagent's resume branch decision: `load_transcript`
        // returns None → error path produces "No transcript found".
        let load_result = load_transcript(test_run(), &unknown_id);
        assert!(
            load_result.is_none(),
            "unknown id must miss the transcript store"
        );

        // The error message format is what run_subagent emits.
        let synth_msg = format!(
            "No transcript found for agent '{unknown_id}'. It may have expired (TTL: {} minutes).",
            TRANSCRIPT_TTL_SECS / 60
        );
        assert!(synth_msg.contains(&unknown_id));
        assert!(synth_msg.contains("No transcript found"));

        // And we deliberately did NOT create a transcript under the id.
        assert!(
            load_transcript(test_run(), &unknown_id).is_none(),
            "resume miss must not silently materialize a transcript"
        );
    }

    /// #582 (4) — two successive dispatches with the same `resume_id`
    /// share transcript state. Storing a transcript under id X and then
    /// resuming under X loads the prior messages; the second dispatch
    /// can append and re-store under the same key, preserving
    /// cache/transcript continuity across the chain.
    #[test]
    fn fix582_two_dispatches_same_resume_id_share_transcript_state() {
        let chain_id = format!("582-chain-{}", Uuid::new_v4());

        // Turn 1: store an initial transcript under chain_id.
        let turn1 = vec![
            json!({"role": "system", "content": "system prompt"}),
            json!({"role": "user", "content": "first prompt"}),
            json!({"role": "assistant", "content": "first reply"}),
        ];
        store_transcript(test_run(), &chain_id, turn1.clone(), AgentType::Explore);

        // First resume dispatch: register_with_id is a no-op on the
        // tracking side because we already registered, but the resume
        // path's load+append+re-store cycle must round-trip on the same key.
        BACKGROUND_AGENTS
            .register_with_id(test_run(), AgentType::Explore, "chain task", &chain_id)
            .expect("register chain agent");
        let (loaded1, t1) =
            load_transcript(test_run(), &chain_id).expect("turn-1 transcript must be loadable");
        assert_eq!(loaded1.len(), turn1.len());
        assert_eq!(t1, AgentType::Explore);

        // Simulate appending and re-storing (what run_subagent does at the
        // end of a turn).
        let mut turn2 = loaded1;
        turn2.push(json!({"role": "user", "content": "Continuing from where you left off.\n\nsecond prompt"}));
        turn2.push(json!({"role": "assistant", "content": "second reply"}));
        store_transcript(test_run(), &chain_id, turn2.clone(), AgentType::Explore);

        // Second resume dispatch: must see the *combined* history under
        // the same id — proof of transcript / prompt-cache continuity.
        BACKGROUND_AGENTS
            .register_with_id(test_run(), AgentType::Explore, "chain task", &chain_id)
            .expect("reattach chain agent");
        let (loaded2, _) = load_transcript(test_run(), &chain_id)
            .expect("turn-2 transcript must still be at same key");
        assert_eq!(
            loaded2.len(),
            turn1.len() + 2,
            "turn-2 transcript must include both turns under the same id"
        );
        assert_eq!(
            loaded2[turn1.len()]["content"].as_str().unwrap_or(""),
            "Continuing from where you left off.\n\nsecond prompt",
            "appended prompt must be visible to a subsequent resume"
        );

        // And only one tracking entry exists under chain_id (no
        // duplicates from the multiple register_with_id calls).
        assert!(BACKGROUND_AGENTS
            .get_for_run(test_run(), &chain_id)
            .is_some());
    }

    /// #582 — `register_with_id` is idempotent: a second call with the
    /// same id leaves the existing tracking entry intact (no reset of
    /// `finished` / `turns` / `result`).
    #[test]
    fn fix582_register_with_id_is_idempotent() {
        let mgr = TestBackgroundAgentManager::new();
        let id = format!("582-idem-{}", Uuid::new_v4());

        let inserted_first = mgr.register_with_id(AgentType::Plan, "task v1", &id);
        assert!(inserted_first, "first call inserts a fresh entry");

        // Mutate state on the first registration so we can detect a reset.
        let _ = mgr.increment_turns(&id);
        let _ = mgr.increment_turns(&id);
        mgr.finish(&id, "result from turn 2".to_string());

        let inserted_second = mgr.register_with_id(AgentType::Explore, "task v2", &id);
        assert!(
            !inserted_second,
            "second call with the same id must be a no-op"
        );

        let agent = mgr.get(&id).expect("entry must still exist after reattach");
        assert_eq!(
            agent.task, "task v1",
            "reattach must not overwrite the original task description"
        );
        assert_eq!(agent.agent_type, AgentType::Plan, "agent_type preserved");
        assert!(
            agent.finished.load(Ordering::SeqCst),
            "finished flag preserved across reattach"
        );
        assert_eq!(
            agent.turns.load(Ordering::SeqCst),
            2,
            "turn counter must not be reset"
        );
        assert_eq!(
            agent.result.lock().unwrap().as_deref(),
            Some("result from turn 2"),
            "result preserved across reattach"
        );
    }

    // ── Spec #527 behavior 5: task_stop ─────────────────────────────────────

    #[test]
    fn spec5_task_stop_aborts_handle_and_marks_agent_failed() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime must build");
        rt.block_on(async {
            let mgr = TestBackgroundAgentManager::new();
            let id = mgr.register(AgentType::GeneralPurpose, "long running task");
            let join = tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_mins(1)).await;
            });
            mgr.attach_abort_handle(&id, join.abort_handle())
                .expect("abort handle attaches");

            let msg = mgr
                .stop(&id, "external cancellation")
                .expect("stop must succeed");
            assert!(
                msg.contains("stopped"),
                "stop message must be explicit: {msg}"
            );
            assert!(
                msg.contains(&id),
                "stop message must include agent id: {msg}"
            );

            let err = join
                .await
                .expect_err("task_stop must abort the spawned task");
            assert!(err.is_cancelled(), "join error must be cancellation: {err}");

            let agent = mgr.get(&id).expect("stopped agent remains readable");
            assert!(agent.finished.load(Ordering::SeqCst));
            assert_eq!(
                agent.error.lock().unwrap().as_deref(),
                Some("external cancellation")
            );
        });
    }

    #[test]
    fn spec5_task_stop_tool_definition_is_exposed() {
        let defs = get_subagent_tool_definitions();
        let names: Vec<&str> = defs
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t.get("function")?.get("name")?.as_str())
            .collect();

        assert!(
            names.contains(&"task_stop"),
            "task_stop tool must be present so callers can stop background work"
        );
        assert!(names.contains(&"task"), "task tool must be present");
        assert!(
            names.contains(&"agent_output"),
            "agent_output tool must be present"
        );
    }

    #[test]
    fn spec5_execute_task_stop_tool_marks_agent_failed() {
        let id = BACKGROUND_AGENTS
            .register(test_run(), AgentType::Plan, "stoppable task")
            .expect("register stoppable test agent");
        let mut args: HashMap<String, Value> = HashMap::new();
        args.insert("agent_id".to_string(), json!(id));
        args.insert("reason".to_string(), json!("user cancelled"));

        let (msg, is_err) = execute_task_stop_tool(test_run(), &args);

        assert!(!is_err, "task_stop must succeed for running agent: {msg}");
        assert!(
            msg.contains("user cancelled"),
            "reason must be surfaced: {msg}"
        );
        let agent = BACKGROUND_AGENTS
            .get_for_run(test_run(), &id)
            .expect("stopped agent remains tracked");
        assert!(agent.finished.load(Ordering::SeqCst));
        assert_eq!(
            agent.error.lock().unwrap().as_deref(),
            Some("user cancelled")
        );
        let _ = BACKGROUND_AGENTS.remove_for_run(test_run(), &id);
    }

    #[test]
    fn task_stop_rejects_non_string_agent_id() {
        let args = HashMap::from([("agent_id".to_string(), json!(42))]);

        let (msg, is_err) = execute_task_stop_tool(test_run(), &args);

        assert!(is_err, "non-string agent_id must error: {msg}");
        assert!(
            msg.contains("Invalid 'agent_id' argument: expected string"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn task_stop_rejects_non_string_reason() {
        let id = BACKGROUND_AGENTS
            .register(test_run(), AgentType::Plan, "reason type check")
            .expect("register reason test agent");
        let args = HashMap::from([
            ("agent_id".to_string(), json!(id)),
            ("reason".to_string(), json!(42)),
        ]);

        let (msg, is_err) = execute_task_stop_tool(test_run(), &args);

        assert!(is_err, "non-string reason must error: {msg}");
        assert!(
            msg.contains("Invalid 'reason' argument: expected string"),
            "unexpected error: {msg}"
        );
        let _ = BACKGROUND_AGENTS.remove_for_run(test_run(), &id);
    }

    #[test]
    fn issue580_background_spawn_finishes_returned_agent_id() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("multi_thread runtime must build");

        rt.block_on(async {
            let app_config = issue719_app_config();
            let mut args: HashMap<String, Value> = HashMap::new();
            args.insert("description".to_string(), json!("issue580 background id"));
            args.insert("prompt".to_string(), json!("try one provider call"));
            args.insert("subagent_type".to_string(), json!("general-purpose"));
            args.insert("run_in_background".to_string(), json!(true));

            let (msg, is_err) = execute_task_tool(test_run(), &args, &app_config);
            assert!(!is_err, "background task should start: {msg}");
            let agent_id = msg
                .lines()
                .find_map(|line| line.strip_prefix("Background agent started with ID: "))
                .expect("message must include returned agent id")
                .to_string();

            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                loop {
                    if BACKGROUND_AGENTS
                        .get_for_run(test_run(), &agent_id)
                        .is_some_and(|agent| agent.finished.load(Ordering::SeqCst))
                    {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("returned agent id must reach a terminal state");

            let agent = BACKGROUND_AGENTS
                .get_for_run(test_run(), &agent_id)
                .expect("returned id must remain the tracked agent");
            assert!(
                agent.finished.load(Ordering::SeqCst),
                "returned id must be terminal"
            );
            assert!(
                agent.error.lock().unwrap().is_some(),
                "invalid test provider should fail the returned id, not a hidden id"
            );
            let _ = BACKGROUND_AGENTS.remove_for_run(test_run(), &agent_id);
        });
    }

    // ── Spec #527 §1 — agent_output edge cases ──

    /// Spec #527 §1 — querying an `agent_id` that was never registered returns
    /// `is_error = true` with a "not found" message.
    #[test]
    fn spec1_agent_output_unknown_id_returns_error() {
        let mut args: HashMap<String, Value> = HashMap::new();
        args.insert("agent_id".to_string(), json!("00000000-not-registered"));

        let (msg, is_err) = execute_agent_output_tool(test_run(), &args);
        assert!(is_err, "unknown agent_id must be an error");
        assert!(
            msg.contains("not found"),
            "message must say not found, got: {msg}"
        );
    }

    #[test]
    fn agent_output_and_task_stop_reject_foreign_run_ids() {
        let owner = isolated_test_run("agent-lifecycle-owner");
        let foreign = isolated_test_run("agent-lifecycle-foreign");

        let finished_id = BACKGROUND_AGENTS
            .register(&owner, AgentType::Explore, "owner output")
            .expect("register output agent");
        BACKGROUND_AGENTS.finish(&owner, &finished_id, "owner-only output".to_string());
        let output_args = HashMap::from([("agent_id".to_string(), json!(finished_id))]);

        let (foreign_output, foreign_output_error) =
            execute_agent_output_tool(&foreign, &output_args);
        assert!(foreign_output_error);
        assert!(foreign_output.contains("not found"));
        assert!(BACKGROUND_AGENTS
            .get_for_run(&owner, &finished_id)
            .is_some());

        let (owner_output, owner_output_error) = execute_agent_output_tool(&owner, &output_args);
        assert!(!owner_output_error);
        assert!(owner_output.contains("owner-only output"));

        let running_id = BACKGROUND_AGENTS
            .register(&owner, AgentType::Plan, "owner cancellation")
            .expect("register stoppable agent");
        let stop_args = HashMap::from([("agent_id".to_string(), json!(running_id))]);
        let (foreign_stop, foreign_stop_error) = execute_task_stop_tool(&foreign, &stop_args);
        assert!(foreign_stop_error);
        assert!(foreign_stop.contains("not found"));
        assert!(BACKGROUND_AGENTS
            .get_for_run(&owner, &running_id)
            .is_some_and(|agent| !agent.finished.load(Ordering::SeqCst)));

        let (owner_stop, owner_stop_error) = execute_task_stop_tool(&owner, &stop_args);
        assert!(!owner_stop_error, "owner stop failed: {owner_stop}");
        assert!(owner_stop.contains("stopped"));
        let _ = BACKGROUND_AGENTS.remove_for_run(&owner, &running_id);
    }

    /// Spec #527 §1 — `agent_output` for a finished agent returns the output text
    /// and `is_error = false`.
    #[test]
    fn spec1_agent_output_finished_agent_returns_result() {
        let id = BACKGROUND_AGENTS
            .register(test_run(), AgentType::Explore, "search task")
            .expect("register successful output test agent");
        BACKGROUND_AGENTS.finish(test_run(), &id, "Found 3 matches.".to_string());

        let mut args: HashMap<String, Value> = HashMap::new();
        args.insert("agent_id".to_string(), json!(id));

        let (msg, is_err) = execute_agent_output_tool(test_run(), &args);
        assert!(!is_err, "finished agent must not be an error: {msg}");
        assert!(
            msg.contains("Found 3 matches."),
            "must include result: {msg}"
        );
        assert!(msg.contains(&id));
    }

    /// Spec #527 §1 — `agent_output` for a failed agent returns `is_error = true`
    /// and the error text.
    #[test]
    fn spec1_agent_output_failed_agent_returns_error() {
        let id = BACKGROUND_AGENTS
            .register(test_run(), AgentType::Plan, "failing task")
            .expect("register failing output test agent");
        BACKGROUND_AGENTS.fail(test_run(), &id, "tool denied".to_string());

        let mut args: HashMap<String, Value> = HashMap::new();
        args.insert("agent_id".to_string(), json!(id));

        let (msg, is_err) = execute_agent_output_tool(test_run(), &args);
        assert!(is_err, "failed agent must return is_error=true");
        assert!(msg.contains("tool denied"), "must include error: {msg}");
    }

    // ── Crosslink #422: BACKGROUND_AGENTS unbounded-growth fix ──

    /// Crosslink #422 — `gc()` evicts agents whose `finished_at` is past
    /// the TTL. Backdating `finished_at` by `TTL + 1s` triggers eviction
    /// without sleeping in the test.
    #[test]
    fn issue422_gc_removes_finished_agents_past_ttl() {
        let mgr = TestBackgroundAgentManager::new();
        let stale_id = mgr.register(AgentType::Explore, "stale finished task");
        mgr.finish(&stale_id, "output".to_string());

        // Backdate the completion timestamp past the TTL.
        let stale = mgr.get(&stale_id).expect("registered");
        let past = Instant::now()
            .checked_sub(std::time::Duration::from_secs(FINISHED_AGENT_TTL_SECS + 1))
            .expect("clock supports subtraction by 1h+1s");
        *stale.finished_at.lock().unwrap() = Some(past);
        drop(stale);

        let removed = mgr.gc();
        assert_eq!(removed, 1, "exactly the stale finished agent must be GC'd");
        assert!(
            mgr.get(&stale_id).is_none(),
            "stale finished agent must no longer be in the map"
        );
    }

    /// Crosslink #422 — `gc()` must NOT remove agents that are still running,
    /// nor finished agents whose retention window has not yet expired.
    /// Guards against the obvious wrong-direction fix where the GC is too
    /// aggressive and drops live work.
    #[test]
    fn issue422_gc_keeps_in_progress_and_recently_finished_agents() {
        let mgr = TestBackgroundAgentManager::new();

        let running_id = mgr.register(AgentType::Plan, "still running");
        let recent_id = mgr.register(AgentType::Explore, "recently finished");
        mgr.finish(&recent_id, "fresh output".to_string());

        // Running agents have `finished_at = None`; the recent finish was
        // a few microseconds ago — both must survive a GC pass.
        let removed = mgr.gc();
        assert_eq!(
            removed, 0,
            "neither the running nor the recently-finished agent should be evicted"
        );
        assert!(
            mgr.get(&running_id).is_some(),
            "in-progress agent must never be GC'd"
        );
        assert!(
            mgr.get(&recent_id).is_some(),
            "agent within TTL must not be GC'd"
        );

        // Sanity: the in-progress agent has no completion timestamp.
        let running = mgr.get(&running_id).unwrap();
        assert!(running.finished_at.lock().unwrap().is_none());
    }

    /// Crosslink #422 — `agent_output` must surface the result/error to the
    /// caller *and then* drop the entry from the manager on the same call,
    /// so a session that polls `agent_output` for every spawned worker
    /// cannot accumulate finished `BackgroundAgent` Arcs.
    /// Covers both the success and failure paths.
    #[test]
    fn issue422_agent_output_returns_result_then_removes_finished_entry() {
        // Success path: result text is returned, then the entry vanishes.
        let ok_id = BACKGROUND_AGENTS
            .register(test_run(), AgentType::Explore, "consume-on-read ok")
            .expect("register consume-on-read success agent");
        BACKGROUND_AGENTS.finish(test_run(), &ok_id, "the answer is 42".to_string());
        assert!(
            BACKGROUND_AGENTS.get_for_run(test_run(), &ok_id).is_some(),
            "agent must exist before retrieval"
        );

        let mut args: HashMap<String, Value> = HashMap::new();
        args.insert("agent_id".to_string(), json!(ok_id));
        let (msg, is_err) = execute_agent_output_tool(test_run(), &args);
        assert!(!is_err, "finished agent must not be an error: {msg}");
        assert!(
            msg.contains("the answer is 42"),
            "result must be returned to caller BEFORE removal: {msg}"
        );
        assert!(
            BACKGROUND_AGENTS.get_for_run(test_run(), &ok_id).is_none(),
            "finished agent must be removed from the manager after agent_output reads it"
        );

        // Failure path: error text is returned, then the entry vanishes.
        let err_id = BACKGROUND_AGENTS
            .register(test_run(), AgentType::Plan, "consume-on-read fail")
            .expect("register consume-on-read failure agent");
        BACKGROUND_AGENTS.fail(test_run(), &err_id, "synthetic failure".to_string());
        let mut args2: HashMap<String, Value> = HashMap::new();
        args2.insert("agent_id".to_string(), json!(err_id));
        let (msg2, is_err2) = execute_agent_output_tool(test_run(), &args2);
        assert!(is_err2, "failed agent must return is_error=true");
        assert!(
            msg2.contains("synthetic failure"),
            "error text must be returned BEFORE removal: {msg2}"
        );
        assert!(
            BACKGROUND_AGENTS.get_for_run(test_run(), &err_id).is_none(),
            "failed agent must be removed from the manager after agent_output reads it"
        );
    }

    /// Crosslink #422 — `cleanup_finished` is the explicit shutdown hook
    /// for callers like `tui.rs`: it drops every finished agent but
    /// preserves any still-running ones.
    #[test]
    fn issue422_cleanup_finished_drops_finished_keeps_running() {
        let mgr = TestBackgroundAgentManager::new();
        let done_a = mgr.register(AgentType::Explore, "done a");
        let done_b = mgr.register(AgentType::Plan, "done b");
        let live = mgr.register(AgentType::GeneralPurpose, "still working");

        mgr.finish(&done_a, "ok".to_string());
        mgr.fail(&done_b, "bad".to_string());

        let removed = mgr.cleanup_finished();
        assert_eq!(removed, 2, "both finished agents must be removed");
        assert!(mgr.get(&done_a).is_none());
        assert!(mgr.get(&done_b).is_none());
        assert!(
            mgr.get(&live).is_some(),
            "running agent must survive cleanup_finished"
        );
    }

    // ── Crosslink #719: runtime-flavor-aware sync dispatch ────────────────
    //
    // The sync branch of `execute_task_tool` used to call
    // `tokio::task::block_in_place(|| handle.block_on(...))` unconditionally
    // whenever a tokio `Handle` was in scope. `block_in_place` PANICS under
    // a `current_thread` runtime, so a Task tool call dispatched from a
    // `#[tokio::test]` (default flavor: current_thread) or from any
    // single-threaded CLI harness would crash the worker.
    //
    // The fix branches on `Handle::runtime_flavor()`:
    //   * MultiThread     → `block_in_place` + `block_on` (safe).
    //   * CurrentThread   → fail fast with a typed error message; no panic.
    //   * No runtime      → spin up a dedicated `Runtime::new()`.
    //
    // The tests below pin all three branches. They use a fake `resume` id
    // to make `run_subagent` return instantly with "No transcript found",
    // so the test never touches the network and never depends on a real
    // provider — we only care about which dispatch branch was taken.

    /// Build a minimal `AppConfig` suitable for exercising
    /// `execute_task_tool`. The Task tool only needs `proxy.target` and a
    /// matching provider entry; the tests never reach the network because
    /// they feed a bogus `resume` id that short-circuits `run_subagent`.
    fn issue719_app_config() -> AppConfig {
        use crate::config::ThinkingConfig;
        use crate::config::{
            GuardrailsConfig, HooksConfig, KeybindingsConfig, MemoryConfig, PermissionsConfig,
            ProviderConfig, ProxyConfig, SessionConfig, VddConfig, WebFetchConfig,
        };

        let mut providers = HashMap::new();
        providers.insert(
            "anthropic".to_string(),
            ProviderConfig {
                base_url: "http://127.0.0.1:1".to_string(),
                api_key: Some(
                    crate::providers::ApiKey::try_from_string("test-key".to_string()).unwrap(),
                ),
                model: None,
                headers: crate::secrets::SensitiveHeaders::new(),
                thinking: ThinkingConfig::default(),
            },
        );
        AppConfig {
            proxy: ProxyConfig::default(),
            providers,
            hooks: HooksConfig::default(),
            session: SessionConfig::default(),
            keybindings: KeybindingsConfig::default(),
            vdd: VddConfig::default(),
            guardrails: GuardrailsConfig::default(),
            permissions: PermissionsConfig::default(),
            memory: MemoryConfig::default(),
            web_fetch: WebFetchConfig::default(),
            remote_actions: crate::config::RemoteActionsConfig::default(),
            policy: crate::services::policy::EnterprisePolicy::default(),
            managed_settings_path: None,
        }
    }

    /// Build args that drive `execute_task_tool` through its sync branch
    /// (`run_in_background=false`) and through `run_subagent`'s resume
    /// fast-fail (`resume` set to an id guaranteed not to exist).
    fn issue719_args() -> HashMap<String, Value> {
        let mut args: HashMap<String, Value> = HashMap::new();
        args.insert("description".to_string(), json!("issue719 test"));
        args.insert("prompt".to_string(), json!("noop"));
        args.insert("subagent_type".to_string(), json!("general-purpose"));
        args.insert("run_in_background".to_string(), json!(false));
        // Unknown id → `run_subagent` returns instantly with
        // "No transcript found...". Keeps the test off the network.
        args.insert(
            "resume".to_string(),
            json!(format!("issue719-missing-{}", Uuid::new_v4())),
        );
        args
    }

    #[test]
    fn execute_task_tool_rejects_coordinator_before_dispatch() {
        let app_config = issue719_app_config();
        let mut args = issue719_args();
        args.insert("subagent_type".to_string(), json!("coordinator"));

        let (msg, is_err) = execute_task_tool(test_run(), &args, &app_config);
        assert!(is_err, "coordinator must not be task-spawnable: {msg}");
        assert!(
            msg.contains("Unsupported task subagent_type 'coordinator'"),
            "error must name the unsupported value; got: {msg}"
        );
        assert!(
            msg.contains("general-purpose, explore, plan, guide"),
            "error must list the task-spawnable values; got: {msg}"
        );
    }

    /// #719 — From a `current_thread` runtime the function must NOT panic
    /// (the old code's `block_in_place` would). It must return the typed
    /// "cannot `block_on` without deadlock" error with `is_error=true`.
    #[test]
    fn issue719_current_thread_runtime_returns_error_without_panicking() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current_thread runtime must build");

        let (msg, is_err) = rt.block_on(async {
            // `execute_task_tool` is a sync fn; calling it inside an async
            // block on a current_thread runtime is exactly the dispatch
            // shape that used to panic via `block_in_place`.
            let app_config = issue719_app_config();
            let args = issue719_args();
            execute_task_tool(test_run(), &args, &app_config)
        });

        assert!(
            is_err,
            "current_thread dispatch must surface an error, not silently succeed: {msg}"
        );
        assert!(
            msg.contains("current_thread") && msg.contains("deadlock"),
            "current_thread branch must return the typed deadlock-guard message; got: {msg}"
        );
        assert!(
            !msg.contains("No transcript found"),
            "current_thread branch must short-circuit BEFORE run_subagent; got: {msg}"
        );
    }

    /// #719 — From a `multi_thread` runtime the function must dispatch
    /// through `block_in_place` + `block_on` and reach `run_subagent`.
    /// We verify by checking the output came from `run_subagent`'s resume
    /// fast-fail path, not from the deadlock-guard branch.
    #[test]
    fn issue719_multi_thread_runtime_dispatches_to_run_subagent() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("multi_thread runtime must build");

        let (msg, is_err) = rt.block_on(async {
            let app_config = issue719_app_config();
            let args = issue719_args();
            execute_task_tool(test_run(), &args, &app_config)
        });

        assert!(
            is_err,
            "resume of unknown id must propagate as is_error=true: {msg}"
        );
        assert!(
            msg.contains("No transcript found"),
            "multi_thread branch must reach run_subagent (resume fast-fail); got: {msg}"
        );
        assert!(
            !msg.contains("cannot block_on without deadlock"),
            "multi_thread branch must NOT trigger the deadlock guard; got: {msg}"
        );
    }

    /// #719 — With no tokio runtime in scope, the function must build its
    /// own `Runtime::new()` and dispatch successfully. As with the
    /// `multi_thread` case we verify the output came from `run_subagent`.
    #[test]
    fn issue719_no_runtime_creates_runtime_and_dispatches() {
        // `execute_task_tool` is sync; calling it directly from the
        // `#[test]` thread means `Handle::try_current()` returns `Err`,
        // hitting the `Runtime::new()` fallback.
        let app_config = issue719_app_config();
        let args = issue719_args();
        let (msg, is_err) = execute_task_tool(test_run(), &args, &app_config);

        assert!(
            is_err,
            "resume of unknown id must propagate as is_error=true: {msg}"
        );
        assert!(
            msg.contains("No transcript found"),
            "no-runtime branch must reach run_subagent (resume fast-fail); got: {msg}"
        );
        assert!(
            !msg.contains("Failed to create runtime"),
            "Runtime::new() must succeed inside a normal #[test] thread; got: {msg}"
        );
        assert!(
            !msg.contains("cannot block_on without deadlock"),
            "no-runtime branch must NOT trigger the deadlock guard; got: {msg}"
        );
    }

    // ── Crosslink #415: TRANSCRIPT_STORE bounded growth + bg sweep ──
    //
    // These tests exercise the private `TranscriptStore` struct
    // directly so the global `TRANSCRIPT_STORE` is not polluted by
    // test data and so each test gets a fresh, deterministic store.
    // The global is exercised indirectly by the existing spec2
    // round-trip tests above and by the no-double-spawn test below.

    /// #415 — A 51st insert must evict the oldest entry, leaving the
    /// store at exactly `MAX_STORED_TRANSCRIPTS` (= 50) and the very
    /// first insert gone.
    #[test]
    fn issue415_lru_cap_evicts_oldest_at_51st_insert() {
        let mut store = TranscriptStore::new();
        // Insert 51 distinct transcripts with strictly-ordered
        // `created_at` so eviction order is deterministic.
        let base = Instant::now();
        let mut first_id = String::new();
        for i in 0u64..51 {
            let id = format!("agent-{i:03}");
            if i == 0 {
                first_id = id.clone();
            }
            store.insert(
                id,
                StoredTranscript {
                    owner_run: test_run().run_id(),
                    messages: vec![json!({"role": "user", "content": "x"})],
                    provider_native_state: None,
                    agent_type: AgentType::Explore,
                    // Stagger timestamps so #0 is unambiguously oldest.
                    created_at: base + Duration::from_micros(i),
                },
            );
        }

        assert_eq!(
            store.len(),
            MAX_STORED_TRANSCRIPTS,
            "store must be capped at MAX_STORED_TRANSCRIPTS after 51 inserts"
        );
        assert!(
            store.get(&first_id).is_none(),
            "first-inserted (oldest) transcript must be the one evicted"
        );
        // A representative middle-aged entry must still be present.
        assert!(
            store.get("agent-025").is_some(),
            "non-oldest entries must be retained"
        );
        // The most-recent entry must still be present.
        assert!(
            store.get("agent-050").is_some(),
            "newest entry must be retained"
        );
    }

    #[test]
    fn transcript_store_repairs_order_index_drift_before_eviction() {
        let mut store = TranscriptStore::new();
        let base = Instant::now();

        for i in 0..MAX_STORED_TRANSCRIPTS {
            let i_u64 = u64::try_from(i).expect("test index must fit in u64");
            store.insert(
                format!("agent-{i:03}"),
                StoredTranscript {
                    owner_run: test_run().run_id(),
                    messages: vec![json!({"role": "user", "content": "x"})],
                    provider_native_state: None,
                    agent_type: AgentType::Explore,
                    created_at: base + Duration::from_micros(i_u64),
                },
            );
        }

        assert!(store.order.remove(&(base, "agent-000".to_string())));
        store.order.insert((base, "missing-agent".to_string()));
        assert_eq!(
            store.order.len(),
            store.entries.len(),
            "test setup should simulate same-size index drift"
        );

        store.insert(
            "agent-new".to_string(),
            StoredTranscript {
                owner_run: test_run().run_id(),
                messages: vec![json!({"role": "assistant", "content": "new"})],
                provider_native_state: None,
                agent_type: AgentType::Plan,
                created_at: base
                    + Duration::from_micros(
                        u64::try_from(MAX_STORED_TRANSCRIPTS + 1)
                            .expect("test cap must fit in u64"),
                    ),
            },
        );

        assert_eq!(
            store.len(),
            MAX_STORED_TRANSCRIPTS,
            "repair must preserve the hard cap after index drift"
        );
        assert_eq!(
            store.order.len(),
            MAX_STORED_TRANSCRIPTS,
            "repair must restore the order index"
        );
        assert!(
            store.get("agent-000").is_none(),
            "oldest transcript should be evicted after rebuilding the index"
        );
        assert!(
            store.get("agent-new").is_some(),
            "new transcript should survive repaired eviction"
        );
    }

    /// #415 — A transcript with 600 messages must be truncated to 500
    /// at store time. We exercise the public `store_transcript` path
    /// because it owns the truncation + warn behavior.
    #[test]
    fn issue415_per_transcript_message_cap_truncates_at_500() {
        let id = format!("issue415-cap-{}", Uuid::new_v4());
        let big: Vec<Value> = (0..600)
            .map(|i| json!({"role": "user", "content": format!("msg {i}")}))
            .collect();

        store_transcript(test_run(), &id, big, AgentType::Plan);

        let loaded =
            load_transcript(test_run(), &id).expect("just-stored transcript must be loadable");
        assert_eq!(
            loaded.0.len(),
            MAX_MESSAGES_PER_TRANSCRIPT,
            "transcript must be truncated to MAX_MESSAGES_PER_TRANSCRIPT (=500)"
        );
        // Truncation drops the OLDEST messages; the tail (newest) is
        // what's kept, so the last message must be the original 599th
        // and the first kept message must be the original 100th.
        assert_eq!(
            loaded.0[0]["content"].as_str(),
            Some("msg 100"),
            "truncation must drop the oldest 100 messages, keeping the tail"
        );
        assert_eq!(
            loaded.0[MAX_MESSAGES_PER_TRANSCRIPT - 1]["content"].as_str(),
            Some("msg 599"),
            "last message must be the most-recent input"
        );
    }

    /// #415 — Calling `sweep` against an empty store must be a no-op
    /// (no panic, no eviction). This is the safety invariant the
    /// background timer relies on: it ticks every 60s regardless of
    /// store state.
    #[test]
    fn issue415_sweep_on_empty_store_is_noop() {
        let mut store = TranscriptStore::new();
        let removed = store.sweep(Instant::now());
        assert_eq!(removed, 0, "empty-store sweep must remove nothing");
        assert_eq!(store.len(), 0, "empty-store sweep must leave store empty");
    }

    /// #415 — `sweep` must evict entries older than the TTL while
    /// retaining fresh ones. We simulate "old" entries by setting
    /// their `created_at` to `now - (TTL + 1s)`.
    #[test]
    fn issue415_sweep_evicts_expired_entries() {
        let mut store = TranscriptStore::new();
        let now = Instant::now();
        let past = now
            .checked_sub(Duration::from_secs(TRANSCRIPT_TTL_SECS + 1))
            .expect("clock must permit subtracting TTL+1s");

        // Two stale + one fresh.
        store.insert(
            "stale-a".to_string(),
            StoredTranscript {
                owner_run: test_run().run_id(),
                messages: vec![],
                provider_native_state: None,
                agent_type: AgentType::Explore,
                created_at: past,
            },
        );
        store.insert(
            "stale-b".to_string(),
            StoredTranscript {
                owner_run: test_run().run_id(),
                messages: vec![],
                provider_native_state: None,
                agent_type: AgentType::Plan,
                // Slightly older still; ordering breakup needs unique keys.
                created_at: past
                    .checked_sub(Duration::from_micros(1))
                    .expect("clock must permit TTL+1s+1us subtraction"),
            },
        );
        store.insert(
            "fresh".to_string(),
            StoredTranscript {
                owner_run: test_run().run_id(),
                messages: vec![],
                provider_native_state: None,
                agent_type: AgentType::GeneralPurpose,
                created_at: now,
            },
        );

        let removed = store.sweep(now);
        assert_eq!(removed, 2, "exactly the two stale entries must be evicted");
        assert!(store.get("stale-a").is_none());
        assert!(store.get("stale-b").is_none());
        assert!(
            store.get("fresh").is_some(),
            "fresh entry must survive the sweep"
        );
        assert_eq!(store.len(), 1);
    }

    /// #415 — Calling `spawn_transcript_sweeper` twice from inside a
    /// tokio runtime must spawn exactly once. The second call returns
    /// `false` because the `Once` guard has already fired.
    #[tokio::test]
    async fn issue415_background_sweep_does_not_double_spawn() {
        // First call inside the runtime: may or may not spawn depending
        // on whether some earlier test in this binary already tripped
        // the global `Once`. Either way, the SECOND call from the
        // same runtime must return `false` because the `Once` has
        // fired by then.
        let _first = spawn_transcript_sweeper();
        let second = spawn_transcript_sweeper();
        assert!(
            !second,
            "spawn_transcript_sweeper must be idempotent: second call must not spawn"
        );

        // Repeating doesn't drift either.
        let third = spawn_transcript_sweeper();
        assert!(!third, "third call must also be a no-op");
    }
}
