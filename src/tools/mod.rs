//! Tool definitions and execution for `OpenClaudia`
//!
//! Implements the core tools that make `OpenClaudia` an agent:
//! - Bash: Execute shell commands
//! - Read: Read file contents
//! - Write: Write/create files
//! - Edit: Make targeted edits to files
//!
//! Stateful mode adds memory tools:
//! - `memory_save`: Store information in archival memory
//! - `memory_search`: Search archival memory
//! - `memory_update`: Update existing memory
//! - `core_memory_update`: Update core memory sections
//!

mod accumulator;
pub(crate) mod args;
mod ask_user;
mod bash;
pub(crate) use bash::record_command_observation_for_session;
pub use bash::sandbox::{
    sandbox_diagnostics, sandbox_diagnostics_for_run, sandbox_preflight, SandboxDiagnostics,
};
pub(crate) use bash::sandbox::{sandboxed_hook_command, sandboxed_process_command, SandboxProfile};
pub(crate) mod command;
mod continuation;
mod cron;
pub mod crosslink;
pub mod effect;
/// Re-export the cron command entry points so the E2E test suite
/// (`tests/cron_e2e.rs`) can drive create/list/delete + the
/// validator perimeter directly. Internal call sites continue to
/// reach these via the module path.
pub use cron::{
    execute_cron_create, execute_cron_delete, execute_cron_list, validate_cron_expression,
};
mod file;
pub(crate) use file::open_capability_regular_read;
pub use file::{
    create_capability_text_file, create_run_control_directory, create_run_control_text_file,
    initialize_project_for_run, read_capability_text_attachment, read_run_control_text,
    resolve_path as resolve_capability_path, ProjectInitOutcome,
};
mod grounding;
pub(crate) mod host_safety;
pub use host_safety::HOST_SAFETY_POLICY_GENERATION;
pub mod security;
/// Re-export the notebook-source-to-line-array helper so the
/// E2E test suite (`tests/notebook_edit_e2e.rs`) can construct
/// nbformat-compatible test fixtures without re-implementing
/// the splitting convention. Internal call sites reach this via
/// the module path.
pub use file::source_to_line_array;
pub mod file_index;
pub mod lsp;
mod plan_mode;
pub mod registry;
pub mod remote_trigger;
mod result;
pub mod skill;
// `task` is exposed so the end-to-end test suite (`tests/tools_e2e.rs`)
// can drive `execute_task_create` / `_update` / `_get` / `_list` against
// a live `TaskManager`. Internal call sites use the same path.
pub mod task;
#[cfg(test)]
pub(crate) mod testutil;
mod todo;
pub mod tool_search;
mod web;
pub mod worktree;

// Re-exports
pub use accumulator::{
    AnthropicContentBlock, AnthropicToolAccumulator, PartialToolCall, ToolCallAccumulator,
    MAX_PARALLEL_TOOL_CALL_SLOTS,
};
/// Credential-sensitivity classifier re-exported for use outside the tools
/// module (e.g. `hooks::mod` env-scrub logic). Avoids making `bash` public.
pub(crate) use bash::is_sensitive_env;
/// Bash command-policy gates re-exported for the security E2E test suite.
/// Attack-catalog tests drive the deny-only defence-in-depth checks without
/// spawning the payloads. Effect classification and auto-approval come only
/// from the typed registry, never from these string scanners.
pub use bash::policy::{
    dangerous_shell_construct, is_sensitive_env as is_sensitive_env_pub, validate_command,
    MAX_COMMAND_LEN,
};
/// Process-wide background shell registry, re-exported so the
/// coordinator's [`crate::coordinator::tasks::LocalShellTask`]
/// (crosslink #611) can query running shells without taking a
/// dependency on the private `bash` submodule.
pub(crate) use bash::BACKGROUND_SHELLS;
pub(crate) use bash::{terminate_process_tree, terminate_session_background_jobs};
pub(crate) use command::run_sandboxed_with_timeout_with_env;
pub(crate) use command::{
    cancel_all_sandbox_processes, cancel_run_sandbox_processes, cancel_session_sandbox_processes,
};
pub(crate) use command::{run_prepared_sandboxed_with_timeout, CommandError};
pub use continuation::{
    ToolContinuation, ToolContinuationError, ToolExchange, TOOL_CONTINUATION_SCHEMA_VERSION,
};
pub use registry::{ToolContext, ToolHandler, ToolRegistry};
pub use result::{
    ToolAllowedPrompt, ToolArtifact, ToolAttachment, ToolCompleteness, ToolContent, ToolDiff,
    ToolDisplay, ToolExecutionResult, ToolFailure, ToolFailureCode, ToolFollowUp,
    ToolFollowUpState, ToolHandlerResult, ToolInvocation, ToolObservation, ToolOutcome,
    ToolQuestion, ToolQuestionOption, ToolResult, ToolResultError, ToolRetryability,
    ToolSensitivity, ToolUsage, TOOL_RESULT_SCHEMA_VERSION,
};
pub use security::{
    ToolCapabilityError, ToolExecutableError, ToolResource, ToolRunContext, ToolRunContextBuilder,
    WorkspaceAccess,
};
pub use todo::{clear_all_todo_lists, clear_todo_list, get_todo_list, TodoItem, TodoStatus};
/// Web-fetch output formatter + cap constant. Curated re-export so the
/// content-extraction E2E tests (`tests/web_content_extraction_e2e.rs`,
/// sprint 41) can drive `format_fetch_output` directly without spawning
/// real HTTP traffic. The full `web` submodule stays private to avoid
/// surfacing internal request-construction helpers.
pub use web::{format_fetch_output, MAX_FETCH_OUTPUT_BYTES};
pub use worktree::cwd_cache_generation;

use crate::config::AppConfig;
use crate::memory::MemoryDb;
use crate::permissions::{AuthorizationResult, CheckResult, ExecutionPermit, PermissionManager};
use crate::session::TaskManager;
use crate::subagent;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Safely truncate a string at a byte boundary without splitting multi-byte UTF-8 characters.
/// Returns the longest prefix of `s` that is at most `max_bytes` bytes and ends on a char boundary.
#[must_use]
pub fn safe_truncate(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Reset the read tracker. Used by tests and at session-start.
///
/// Clears only the exact run bucket; no ambient session identity participates.
#[doc(hidden)]
pub fn reset_read_tracker(run: &ToolRunContext) {
    file::READ_TRACKER.clear_run(run);
}

/// Retire one exact frontend run before replacing its session generation.
///
/// This host lifecycle boundary cancels the run tree and terminates only the
/// synchronous processes, background shells, and background agents owned by
/// that run. Concurrent runs and later generations are unaffected.
pub fn retire_run(run: &ToolRunContext) {
    let _ = run
        .runtime()
        .cancellation()
        .cancel(crate::runtime::CancellationReason::FrontendDisconnected);
    let sandbox_processes = cancel_run_sandbox_processes(run);
    let background_shells = BACKGROUND_SHELLS.kill_for_run(run);
    let background_agents = crate::subagent::BACKGROUND_AGENTS.stop_all_for_run(run);
    tracing::info!(
        target: "openclaudia::capabilities",
        event = "run_retired",
        run_id = %run.run_id(),
        generation = %run.generation(),
        sandbox_processes,
        background_agents,
        background_shells,
        "Retired exact frontend run resources"
    );
}

/// Tool call from the model
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub call_type: String,
    pub function: FunctionCall,
}

/// Function call details
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: String,
}

/// Get all tool definitions for the API request (`OpenAI` function format).
///
/// Each entry is sourced from the corresponding [`ToolHandler::definition`]
/// implementation, so a tool's schema lives next to its execute logic. The
/// emission order is fixed by `registry::iter_handlers()` (the canonical
/// `HANDLERS` slice) which preserves byte-for-byte equivalence with the
/// pre-#463 hand-maintained JSON literal.
#[must_use]
pub fn get_tool_definitions() -> Value {
    Value::Array(
        registry::iter_handlers()
            .map(ToolHandler::definition)
            .collect(),
    )
}

/// Execute a tool call with an explicit host-owned unrestricted prompt policy.
///
/// This convenience entry point never means "no policy object". It constructs
/// an explicit unrestricted [`PermissionManager`], which suppresses approval
/// prompts while retaining mandatory effect classification, the non-bypassable
/// host ceiling, exact dispatch authorization, and the sandbox/capability
/// boundary.
#[must_use]
pub fn execute_tool(run: &std::sync::Arc<ToolRunContext>, tool_call: &ToolCall) -> ToolResult {
    let permission_manager = PermissionManager::unrestricted_for_run(run);
    execute_tool_with_memory(run, tool_call, None, &permission_manager)
}

/// Fail-closed compatibility probe for callers that have no run capability.
///
/// This function never dispatches a handler. It exists so adapters can turn a
/// missing composition-root binding into a typed tool result without deriving
/// authority from process CWD or thread-local state.
#[must_use]
pub fn execute_tool_without_context(tool_call: &ToolCall) -> ToolResult {
    ToolResult::failure(
        tool_call,
        ToolFailureCode::Unavailable,
        "Tool execution is unavailable because no explicit run capability was supplied".to_string(),
        ToolRetryability::Never,
    )
}

fn invalid_tool_arguments_result(
    tool_call: &ToolCall,
    detail: impl std::fmt::Display,
) -> ToolResult {
    ToolResult::failure(
        tool_call,
        ToolFailureCode::InvalidArguments,
        format!(
            "Invalid tool arguments JSON for '{}': {detail}",
            tool_call.function.name
        ),
        ToolRetryability::Never,
    )
}

fn parse_tool_arguments_value(tool_call: &ToolCall) -> Result<Value, Box<ToolResult>> {
    let value = serde_json::from_str::<Value>(&tool_call.function.arguments)
        .map_err(|err| Box::new(invalid_tool_arguments_result(tool_call, err)))?;
    if !value.is_object() {
        return Err(Box::new(invalid_tool_arguments_result(
            tool_call,
            format_args!("expected a JSON object, got {}", value_type_name(&value)),
        )));
    }
    Ok(value)
}

fn parse_tool_arguments_map(
    tool_call: &ToolCall,
) -> Result<HashMap<String, Value>, Box<ToolResult>> {
    let value = parse_tool_arguments_value(tool_call)?;
    let Value::Object(map) = value else {
        return Err(Box::new(invalid_tool_arguments_result(
            tool_call,
            format_args!("expected a JSON object, got {}", value_type_name(&value)),
        )));
    };
    Ok(map.into_iter().collect())
}

const fn value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn host_safety_dispatch_permit(
    tool_call: &ToolCall,
    args: &HashMap<String, Value>,
) -> Result<registry::ToolDispatchPermit, Box<ToolResult>> {
    let arguments = Value::Object(
        args.iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    );
    host_safety::HostSafetyPolicy::enforce(&tool_call.function.name, &arguments).map_err(
        |reason| {
            Box::new(ToolResult::failure(
                tool_call,
                ToolFailureCode::PolicyDenied,
                format!("Blocked by non-bypassable host safety: {reason}"),
                ToolRetryability::Never,
            ))
        },
    )?;
    Ok(registry::ToolDispatchPermit::new(
        &tool_call.function.name,
        args,
    ))
}

fn dispatch_registered_with_permit(
    tool_call: &ToolCall,
    args: &HashMap<String, Value>,
    ctx: &mut ToolContext<'_>,
    permit: &registry::ToolDispatchPermit,
) -> ToolResult {
    let resolved = match effect::resolve_for_call(
        &tool_call.function.name,
        &Value::Object(
            args.iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        ),
    ) {
        Ok(resolved) => resolved,
        Err(error) => {
            return ToolResult::failure(
                tool_call,
                ToolFailureCode::PolicyDenied,
                error.reason(),
                ToolRetryability::Never,
            );
        }
    };
    let mut guardrail_reservation = match crate::guardrails::reserve_tool_effect(ctx.run, &resolved)
    {
        Ok(reservation) => reservation,
        Err(reason) => {
            return ToolResult::failure(
                tool_call,
                ToolFailureCode::PolicyDenied,
                format!("Blocked by blast radius guardrails: {reason}"),
                ToolRetryability::Never,
            );
        }
    };
    let handler_result = registry::registry()
        .dispatch(tool_call.function.name.as_str(), args, ctx, permit)
        .unwrap_or_else(|| {
            ToolHandlerResult::error(ToolFailure::new(
                ToolFailureCode::Unavailable,
                format!("Unknown tool: {}", tool_call.function.name),
                ToolRetryability::Never,
            ))
        });
    let result = ToolResult::bind(tool_call, &tool_call.function.name, handler_result);
    if !result.is_error() {
        guardrail_reservation.commit();
    }
    result
}

fn dispatch_registered_after_authorization(
    tool_call: &ToolCall,
    args: &HashMap<String, Value>,
    ctx: &mut ToolContext<'_>,
) -> ToolResult {
    let permit = match host_safety_dispatch_permit(tool_call, args) {
        Ok(permit) => permit,
        Err(result) => return *result,
    };
    dispatch_registered_with_permit(tool_call, args, ctx, &permit)
}

/// Describe the effective authority behind an interactive tool permission.
///
/// This is deliberately about the enforced boundary, not the command text:
/// prompts must not imply that approving one string grants ambient host
/// filesystem or network access.
#[must_use]
pub const fn permission_scope_summary(tool: &str) -> &'static str {
    if tool.eq_ignore_ascii_case("bash") {
        "project/explicit roots; controls masked; subprocess network denied"
    } else if tool.eq_ignore_ascii_case("write")
        || tool.eq_ignore_ascii_case("write_file")
        || tool.eq_ignore_ascii_case("edit")
        || tool.eq_ignore_ascii_case("edit_file")
        || tool.eq_ignore_ascii_case("notebook_edit")
    {
        "named path within session write roots; control paths masked"
    } else if tool.eq_ignore_ascii_case("webfetch") || tool.eq_ignore_ascii_case("web_fetch") {
        "brokered URL only; redirects and resolved IPs pass SSRF policy"
    } else {
        "active session capabilities; no ambient host authority"
    }
}

fn legacy_permission_prompt(tool: &str, target: &str) -> String {
    format!(
        "PERMISSION_PROMPT: Allow {tool} on '{target}'? [y/n/a(lways)]\nScope: {}",
        permission_scope_summary(tool)
    )
}

/// Execute a tool call with optional memory and a required permission manager.
#[must_use]
pub fn execute_tool_with_memory(
    run: &std::sync::Arc<ToolRunContext>,
    tool_call: &ToolCall,
    memory_db: Option<&MemoryDb>,
    permission_mgr: &PermissionManager,
) -> ToolResult {
    let permit = match authorization_or_legacy_prompt(tool_call, permission_mgr) {
        Ok(permit) => permit,
        Err(result) => return *result,
    };
    if let Err(result) = consume_for_execution(tool_call, permission_mgr, &permit) {
        return *result;
    }
    execute_tool_with_memory_after_authorization(run, tool_call, memory_db)
}

fn execute_tool_with_memory_after_authorization(
    run: &std::sync::Arc<ToolRunContext>,
    tool_call: &ToolCall,
    memory_db: Option<&MemoryDb>,
) -> ToolResult {
    let args = match parse_tool_arguments_map(tool_call) {
        Ok(args) => args,
        Err(result) => return *result,
    };

    // Subagent tools require full config context; surface a clear error here
    // so callers know to use execute_tool_full() instead.
    if matches!(
        tool_call.function.name.as_str(),
        "task" | "agent_output" | "task_stop"
    ) {
        return ToolResult::failure(
            tool_call,
            ToolFailureCode::Unavailable,
            "Subagent tools require configuration context. Use execute_tool_full() instead."
                .to_string(),
            ToolRetryability::Never,
        );
    }

    let mut ctx = ToolContext {
        run,
        memory_db,
        app_config: None,
        task_mgr: None,
    };
    dispatch_registered_after_authorization(tool_call, &args, &mut ctx)
}

/// Execute a tool call with full context (memory + config for subagents).
#[must_use]
pub fn execute_tool_full(
    run: &std::sync::Arc<ToolRunContext>,
    tool_call: &ToolCall,
    memory_db: Option<&MemoryDb>,
    app_config: Option<&AppConfig>,
    permission_mgr: &PermissionManager,
) -> ToolResult {
    let permit = match authorization_or_legacy_prompt(tool_call, permission_mgr) {
        Ok(permit) => permit,
        Err(result) => return *result,
    };
    if let Err(result) = consume_for_execution(tool_call, permission_mgr, &permit) {
        return *result;
    }
    execute_tool_full_after_authorization(run, tool_call, memory_db, app_config)
}

fn execute_tool_full_after_authorization(
    run: &std::sync::Arc<ToolRunContext>,
    tool_call: &ToolCall,
    memory_db: Option<&MemoryDb>,
    app_config: Option<&AppConfig>,
) -> ToolResult {
    let args = match parse_tool_arguments_map(tool_call) {
        Ok(args) => args,
        Err(result) => return *result,
    };
    let dispatch_permit = match host_safety_dispatch_permit(tool_call, &args) {
        Ok(permit) => permit,
        Err(result) => return *result,
    };

    let resolved = match effect::resolve_for_call(
        &tool_call.function.name,
        &Value::Object(
            args.iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        ),
    ) {
        Ok(resolved) => resolved,
        Err(error) => {
            return ToolResult::failure(
                tool_call,
                ToolFailureCode::PolicyDenied,
                error.reason(),
                ToolRetryability::Never,
            );
        }
    };

    // Check for subagent tools first (they need config). Each match arm
    // produces the inner `(content, is_error)` pair; the `ToolResult`
    // wrapping happens *after* the match so there is a single return point
    // (crosslink #491 — previously the default arm returned mid-match,
    // bypassing the wrapper and creating asymmetric control flow).
    let mut guardrail_reservation = if matches!(
        tool_call.function.name.as_str(),
        "task" | "agent_output" | "task_stop"
    ) {
        match crate::guardrails::reserve_tool_effect(run, &resolved) {
            Ok(reservation) => Some(reservation),
            Err(reason) => {
                return ToolResult::failure(
                    tool_call,
                    ToolFailureCode::PolicyDenied,
                    format!("Blocked by blast radius guardrails: {reason}"),
                    ToolRetryability::Never,
                );
            }
        }
    } else {
        None
    };

    let handler_result = match tool_call.function.name.as_str() {
        "task" => run
            .require(ToolResource::Network)
            .and_then(|()| run.require(ToolResource::Secrets))
            .map_or_else(
                |error| {
                    ToolHandlerResult::error(ToolFailure::new(
                        ToolFailureCode::Unavailable,
                        format!("Task execution is unavailable: {error}"),
                        ToolRetryability::Never,
                    ))
                },
                |()| {
                    app_config.map_or_else(
                        || {
                            ToolHandlerResult::error(ToolFailure::new(
                                ToolFailureCode::Unavailable,
                                "Task tool requires application configuration".to_string(),
                                ToolRetryability::Never,
                            ))
                        },
                        |config| subagent::execute_task_tool_typed(run, &args, config),
                    )
                },
            ),
        "agent_output" => subagent::execute_agent_output_tool_typed(run, &args),
        "task_stop" => {
            let (content, is_error) = subagent::execute_task_stop_tool(run, &args);
            ToolHandlerResult::legacy(content, is_error)
        }
        _ => {
            let mut ctx = ToolContext {
                run,
                memory_db,
                app_config,
                task_mgr: None,
            };
            return dispatch_registered_with_permit(tool_call, &args, &mut ctx, &dispatch_permit);
        }
    };

    let result = ToolResult::bind(tool_call, &tool_call.function.name, handler_result);
    if !result.is_error() {
        if let Some(reservation) = guardrail_reservation.as_mut() {
            reservation.commit();
        }
    }
    result
}

/// Get all tool definitions, optionally including subagent tools
#[must_use]
pub fn get_all_tool_definitions(subagents: bool) -> Value {
    let mut tools = get_tool_definitions();

    if subagents {
        if let (Some(base_arr), Some(subagent_arr)) = (
            tools.as_array_mut(),
            subagent::get_subagent_tool_definitions()
                .as_array()
                .cloned(),
        ) {
            base_arr.extend(subagent_arr);
        }
    }

    tools
}

// =========================================================================
// Permission-Checked Tool Execution
// =========================================================================

/// Structured outcome of a permission check, suitable for typed dispatch at the caller.
///
/// Replaces the previous stringly-typed `PERMISSION_PROMPT: ...` signal that required
/// callers to regex-parse a tool result's content string to know a user prompt was
/// required. See crosslink #460.
#[derive(Debug, Clone)]
pub enum PermissionOutcome {
    /// Tool may proceed.
    Allowed,
    /// Tool is denied; `ToolResult` is ready to return to the model.
    Denied(Box<ToolResult>),
    /// Caller must interactively prompt the user before proceeding.
    /// `tool_call_id` is preserved so the final result can be stitched back
    /// onto the originating call.
    NeedsPrompt {
        tool_call_id: String,
        tool: String,
        target: String,
    },
}

/// Check permissions before executing a tool and return a structured outcome.
///
/// Emits a structured tracing event at every decision point (allowed,
/// denied, or needs-prompt) so the audit trail is queryable without re-running
/// the session.
#[must_use]
pub fn check_tool_permission_outcome(
    tool_call: &ToolCall,
    permission_mgr: &PermissionManager,
) -> PermissionOutcome {
    let tool_name = tool_call.function.name.as_str();
    let args = match parse_tool_arguments_value(tool_call) {
        Ok(args) => args,
        Err(result) => return PermissionOutcome::Denied(result),
    };

    match permission_mgr.check(tool_name, &args) {
        CheckResult::Allowed => {
            tracing::debug!(tool = %tool_name, "permission allowed");
            PermissionOutcome::Allowed
        }
        CheckResult::Denied(reason) => {
            tracing::warn!(
                tool = %tool_name,
                reason = %reason,
                "permission DENIED"
            );
            PermissionOutcome::Denied(Box::new(ToolResult::failure(
                tool_call,
                ToolFailureCode::PermissionDenied,
                format!("Permission denied: {reason}"),
                ToolRetryability::Never,
            )))
        }
        CheckResult::NeedsPrompt { tool, target } => {
            tracing::info!(
                tool = %tool,
                target = %target,
                "permission needs user prompt"
            );
            PermissionOutcome::NeedsPrompt {
                tool_call_id: tool_call.id.clone(),
                tool,
                target,
            }
        }
    }
}

/// Back-compat wrapper: returns `None` on Allowed, `Some(ToolResult)` on Denied.
///
/// Returns a `PERMISSION_PROMPT:` stringly-typed result on `NeedsPrompt`. New
/// code should call [`check_tool_permission_outcome`] and switch on the enum
/// instead.
#[must_use]
pub fn check_tool_permission(
    tool_call: &ToolCall,
    permission_mgr: &PermissionManager,
) -> Option<ToolResult> {
    match check_tool_permission_outcome(tool_call, permission_mgr) {
        PermissionOutcome::Allowed => None,
        PermissionOutcome::Denied(result) => Some(*result),
        PermissionOutcome::NeedsPrompt {
            tool_call_id: _,
            tool,
            target,
        } => Some(ToolResult::failure(
            tool_call,
            ToolFailureCode::PermissionDenied,
            legacy_permission_prompt(&tool, &target),
            ToolRetryability::Never,
        )),
    }
}

fn authorize_for_execution(
    tool_call: &ToolCall,
    permission_mgr: &PermissionManager,
) -> Result<ExecutionPermit, PermissionOutcome> {
    // Preserve the public executor's validation contract before asking the
    // permission layer to classify the invocation. `PermissionManager` also
    // parses defensively, but its string denial cannot carry the typed
    // `InvalidArguments` outcome expected at the tool boundary.
    if let Err(result) = parse_tool_arguments_value(tool_call) {
        return Err(PermissionOutcome::Denied(result));
    }
    match permission_mgr.authorize_tool_call(tool_call, None) {
        AuthorizationResult::Allowed(permit) => Ok(permit),
        AuthorizationResult::Denied(reason) => {
            Err(PermissionOutcome::Denied(Box::new(ToolResult::failure(
                tool_call,
                ToolFailureCode::PermissionDenied,
                format!("Permission denied: {reason}"),
                ToolRetryability::Never,
            ))))
        }
        AuthorizationResult::NeedsPrompt { tool, target } => Err(PermissionOutcome::NeedsPrompt {
            tool_call_id: tool_call.id.clone(),
            tool,
            target,
        }),
    }
}

fn authorization_or_legacy_prompt(
    tool_call: &ToolCall,
    permission_mgr: &PermissionManager,
) -> Result<ExecutionPermit, Box<ToolResult>> {
    match authorize_for_execution(tool_call, permission_mgr) {
        Ok(permit) => Ok(permit),
        Err(PermissionOutcome::Denied(result)) => Err(result),
        Err(PermissionOutcome::NeedsPrompt { tool, target, .. }) => {
            Err(Box::new(ToolResult::failure(
                tool_call,
                ToolFailureCode::PermissionDenied,
                legacy_permission_prompt(&tool, &target),
                ToolRetryability::Never,
            )))
        }
        Err(PermissionOutcome::Allowed) => unreachable!("authorization cannot return bare allow"),
    }
}

fn consume_for_execution(
    tool_call: &ToolCall,
    permission_mgr: &PermissionManager,
    permit: &ExecutionPermit,
) -> Result<(), Box<ToolResult>> {
    permission_mgr
        .consume_execution_permit(permit, tool_call, None)
        .map_err(|reason| {
            Box::new(ToolResult::failure(
                tool_call,
                ToolFailureCode::PermissionDenied,
                format!("Permission denied: execution permit rejected: {reason}"),
                ToolRetryability::Never,
            ))
        })
}

/// Execute a tool call with task manager support.
///
/// This is the highest-level execution function that handles:
/// - Permission checking (internal; runs BEFORE any tool body)
/// - Task management tools (`task_create`, `task_update`, `task_get`, `task_list`)
/// - Subagent tools (via config)
/// - Memory tools (via `memory_db`)
/// - All standard tools
///
#[must_use]
pub fn execute_tool_with_tasks(
    run: &std::sync::Arc<ToolRunContext>,
    tool_call: &ToolCall,
    memory_db: Option<&MemoryDb>,
    app_config: Option<&AppConfig>,
    task_mgr: Option<&mut TaskManager>,
    permission_mgr: &PermissionManager,
) -> ToolResult {
    let permit = match authorization_or_legacy_prompt(tool_call, permission_mgr) {
        Ok(permit) => permit,
        Err(result) => return *result,
    };
    if let Err(result) = consume_for_execution(tool_call, permission_mgr, &permit) {
        return *result;
    }

    execute_tool_after_authorization(run, tool_call, memory_db, app_config, task_mgr)
}

/// Execute a tool after the caller has already made the approval decision.
///
/// This is crate-visible for the shared executor only. It still applies the
/// non-bypassable host ceiling and mints an opaque exact registry permit, so
/// "after authorization" never means "unchecked".
#[must_use]
pub(crate) fn execute_tool_after_authorization(
    run: &std::sync::Arc<ToolRunContext>,
    tool_call: &ToolCall,
    memory_db: Option<&MemoryDb>,
    app_config: Option<&AppConfig>,
    task_mgr: Option<&mut TaskManager>,
) -> ToolResult {
    let args = match parse_tool_arguments_map(tool_call) {
        Ok(args) => args,
        Err(result) => return *result,
    };

    // Subagent tools (task / agent_output / task_stop) need app_config and are handled
    // inside execute_tool_full before the registry is consulted.
    if matches!(
        tool_call.function.name.as_str(),
        "task" | "agent_output" | "task_stop"
    ) {
        return execute_tool_full_after_authorization(run, tool_call, memory_db, app_config);
    }

    // All other tools — including task_create/task_update/task_get/task_list —
    // go through the registry with the full context bundle.
    let mut ctx = ToolContext {
        run,
        memory_db,
        app_config,
        task_mgr,
    };

    dispatch_registered_after_authorization(tool_call, &args, &mut ctx)
}

/// New canonical dispatch: requires a [`PermissionManager`] and uses the strict fail-closed check.
///
/// Prefer this in all new code. If you explicitly want "allow every tool call",
/// construct [`PermissionManager::unrestricted`] at the call site — the intent
/// is then documented in source, not smuggled via a missing argument. See
/// crosslink #460 mandated point 1.
#[must_use]
pub fn execute_tool_with_permission_required(
    run: &std::sync::Arc<ToolRunContext>,
    tool_call: &ToolCall,
    memory_db: Option<&MemoryDb>,
    app_config: Option<&AppConfig>,
    task_mgr: Option<&mut TaskManager>,
    permission_mgr: &PermissionManager,
) -> ToolResult {
    let permit = match authorize_for_execution(tool_call, permission_mgr) {
        Err(PermissionOutcome::Denied(result)) => return *result,
        Err(PermissionOutcome::NeedsPrompt { tool, target, .. }) => {
            return ToolResult::failure(
                tool_call,
                ToolFailureCode::PermissionDenied,
                legacy_permission_prompt(&tool, &target),
                ToolRetryability::Never,
            );
        }
        Ok(permit) => permit,
        Err(PermissionOutcome::Allowed) => unreachable!("authorization cannot return bare allow"),
    };
    if let Err(result) = consume_for_execution(tool_call, permission_mgr, &permit) {
        return *result;
    }
    execute_tool_after_authorization(run, tool_call, memory_db, app_config, task_mgr)
}

/// Typed-outcome dispatch: runs the permission gate and returns a structured [`ExecutionOutcome`].
///
/// Executes the tool body on `Allowed` and returns `ExecutionOutcome::NeedsPrompt`
/// instead of a stringly-typed `PERMISSION_PROMPT:` message. New call sites that
/// want to interactively handle the prompt path should use this. See crosslink
/// #460 mandated point 3.
#[must_use]
pub fn execute_tool_gated(
    run: &std::sync::Arc<ToolRunContext>,
    tool_call: &ToolCall,
    memory_db: Option<&MemoryDb>,
    app_config: Option<&AppConfig>,
    task_mgr: Option<&mut TaskManager>,
    permission_mgr: &PermissionManager,
) -> ExecutionOutcome {
    let permit = match authorize_for_execution(tool_call, permission_mgr) {
        Ok(permit) => permit,
        Err(PermissionOutcome::Denied(result)) => return ExecutionOutcome::Result(result),
        Err(PermissionOutcome::NeedsPrompt {
            tool_call_id,
            tool,
            target,
        }) => {
            return ExecutionOutcome::NeedsPrompt {
                tool_call_id,
                tool,
                target,
            };
        }
        Err(PermissionOutcome::Allowed) => unreachable!("authorization cannot return bare allow"),
    };
    if let Err(result) = consume_for_execution(tool_call, permission_mgr, &permit) {
        return ExecutionOutcome::Result(result);
    }
    ExecutionOutcome::Result(Box::new(execute_tool_after_authorization(
        run, tool_call, memory_db, app_config, task_mgr,
    )))
}

/// Structured outcome of a gated dispatch. Either the tool ran (or was
/// denied and the denial `ToolResult` is returned to the model), or the
/// caller must prompt the user interactively and retry.
///
/// Replaces the stringly-typed `PERMISSION_PROMPT:` content signal.
/// See crosslink #460 mandated point 3.
#[derive(Debug, Clone)]
pub enum ExecutionOutcome {
    /// Tool completed (allowed path) or was denied (rule-denied path).
    /// In both cases the `ToolResult` is ready to hand back to the model.
    Result(Box<ToolResult>),
    /// No rule matched; the caller must interactively prompt the user and
    /// then retry the dispatch (typically after recording the user's
    /// decision on the `PermissionManager`).
    NeedsPrompt {
        tool_call_id: String,
        tool: String,
        target: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::TaskManager;
    use base64::Engine;
    use serde_json::json;

    fn test_run() -> &'static std::sync::Arc<ToolRunContext> {
        security::test_run_context()
    }

    #[test]
    fn post_authorization_boundary_still_denies_catastrophic_bash() {
        let tool_call = ToolCall {
            id: "host-safety-after-authorization-bash".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "bash".to_string(),
                arguments: json!({"command": "rm -rf /"}).to_string(),
            },
        };

        let result = execute_tool_after_authorization(test_run(), &tool_call, None, None, None);
        assert!(result.is_error());
        assert!(matches!(
            result.outcome(),
            ToolOutcome::Error { failure }
                if failure.code == ToolFailureCode::PolicyDenied
                    && failure.retryability == ToolRetryability::Never
        ));
        assert!(result.content().contains("non-bypassable host safety"));
    }

    #[test]
    fn post_authorization_boundary_still_denies_protected_write() {
        let tool_call = ToolCall {
            id: "host-safety-after-authorization-write".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "write_file".to_string(),
                arguments: json!({
                    "path": ".claude/settings.json",
                    "content": "must not be written"
                })
                .to_string(),
            },
        };

        let result = execute_tool_after_authorization(test_run(), &tool_call, None, None, None);
        assert!(result.is_error());
        assert!(matches!(
            result.outcome(),
            ToolOutcome::Error { failure }
                if failure.code == ToolFailureCode::PolicyDenied
                    && failure.retryability == ToolRetryability::Never
        ));
        assert!(result.content().contains("non-bypassable host safety"));
    }

    /// Temporary forensic dump used to verify byte-for-byte equivalence of
    /// `get_tool_definitions()` against the pre-#463 baseline. Writes to a
    /// path supplied via `OPENCLAUDIA_DUMP_TOOLS_PATH` (default `/tmp/...`).
    /// Skipped unless the env var is set.
    #[test]
    fn forensic_dump_tool_definitions_when_env_set() {
        let Ok(path) = std::env::var("OPENCLAUDIA_DUMP_TOOLS_PATH") else {
            return;
        };
        let s = serde_json::to_string(&get_tool_definitions()).unwrap();
        std::fs::write(&path, s).unwrap();
    }

    /// Regression test for crosslink #463 — every handler in the registry
    /// must expose a `definition()` whose `function.name` matches
    /// `handler.name()`. Catches the schema/handler drift that the original
    /// 684-line `json!` literal made silently possible.
    #[test]
    fn handler_definition_name_matches_handler_name() {
        for handler in registry::iter_handlers() {
            let def = handler.definition();
            let schema_name = def
                .pointer("/function/name")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| {
                    panic!(
                        "handler {} returned definition without function.name",
                        handler.name()
                    )
                });
            assert_eq!(
                schema_name,
                handler.name(),
                "definition().function.name disagrees with handler.name() for {}",
                handler.name()
            );
        }
    }

    /// Regression test for crosslink #463 — the composed `get_tool_definitions`
    /// must contain exactly one entry per registered handler, in handler
    /// registration order. This pins the JSON shape so future handlers can't
    /// silently desync the tool list emitted to the model from the dispatch
    /// table.
    #[test]
    fn get_tool_definitions_matches_handler_registry_order() {
        let json = get_tool_definitions();
        let arr = json.as_array().expect("tool definitions must be an array");
        let handler_names: Vec<&str> = registry::iter_handlers().map(ToolHandler::name).collect();
        let json_names: Vec<&str> = arr
            .iter()
            .map(|t| {
                t.pointer("/function/name")
                    .and_then(|v| v.as_str())
                    .expect("every tool entry must have function.name")
            })
            .collect();
        assert_eq!(
            handler_names, json_names,
            "get_tool_definitions() emission order must mirror registry::HANDLERS"
        );
    }

    use file::{
        detect_file_type, parse_page_range, read_image_file, read_notebook_file,
        source_to_line_array, FileType, READ_TRACKER,
    };
    use std::fs;

    #[test]
    fn test_tool_definitions() {
        let tools = get_tool_definitions();
        assert!(tools.is_array());
        let arr = tools.as_array().unwrap();

        // Extract tool names for specific checks
        let tool_names: Vec<&str> = arr
            .iter()
            .filter_map(|t| t["function"]["name"].as_str())
            .collect();

        // Verify all core tools are present
        let required = vec![
            "bash",
            "bash_output",
            "kill_shell",
            "kill_shells_for_agent",
            "read_file",
            "write_file",
            "edit_file",
            "list_files",
            "glob",
            "grep",
            "crosslink",
            "web_fetch",
            "todo_write",
            "todo_read",
            "notebook_edit",
            "ask_user_question",
            "enter_plan_mode",
            "exit_plan_mode",
            "task_create",
            "task_update",
            "task_get",
            "task_list",
        ];
        #[cfg(feature = "browser")]
        let required = {
            let mut required = required;
            required.push("web_search");
            required
        };
        for name in &required {
            assert!(
                tool_names.contains(name),
                "Missing required tool '{name}'. Found: {tool_names:?}"
            );
        }

        // Each tool must have valid structure
        for tool in arr {
            let func = tool.get("function").expect("Tool missing 'function'");
            assert!(
                func.get("name").and_then(|n| n.as_str()).is_some(),
                "Tool missing name"
            );
            assert!(
                func.get("description").and_then(|d| d.as_str()).is_some(),
                "Tool missing description"
            );
            assert!(func.get("parameters").is_some(), "Tool missing parameters");
        }
    }

    #[test]
    fn test_bash_execution() {
        let mut args = HashMap::new();
        args.insert("command".to_string(), json!("echo hello"));
        let (output, is_error) = bash::execute_bash(test_run(), &args);
        assert!(!is_error);
        assert!(output.contains("hello"));
    }

    /// Regression test for crosslink #491.
    ///
    /// Previously, `execute_tool_full` had two arms (`task`, `agent_output`)
    /// that fell through to a shared `ToolResult` wrapper at the bottom, and
    /// a third (default) arm that `return`ed mid-match — bypassing the
    /// wrapper. The refactor unifies the control flow so every arm produces
    /// `(content, is_error)` and the wrapper runs once. This test pins the
    /// invariant that the default arm's `tool_call_id` propagates through
    /// the wrapper (it would still pass under the old code, but any future
    /// refactor that drops the wrapper for the default arm — e.g. by
    /// reintroducing the early return without setting `tool_call_id` —
    /// will fail here).
    #[test]
    fn execute_tool_full_default_arm_wraps_with_tool_call_id() {
        let call = ToolCall {
            id: "call-#491-test".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "bash".to_string(),
                arguments: json!({ "command": "echo hello" }).to_string(),
            },
        };
        let permission_manager = PermissionManager::unrestricted();
        let result = execute_tool_full(test_run(), &call, None, None, &permission_manager);
        assert_eq!(
            result.tool_call_id(),
            "call-#491-test",
            "default match arm must round-trip the tool_call_id through the single wrapper"
        );
        // Subagent arms behave the same — drive `agent_output` with no
        // session so it produces a `(content, is_error=true)` pair and
        // verify the wrapper attaches the id identically.
        let agent_call = ToolCall {
            id: "call-#491-agent".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "agent_output".to_string(),
                arguments: "{}".to_string(),
            },
        };
        let agent_result =
            execute_tool_full(test_run(), &agent_call, None, None, &permission_manager);
        assert_eq!(
            agent_result.tool_call_id(),
            "call-#491-agent",
            "subagent match arm must round-trip the tool_call_id through the single wrapper"
        );
    }

    #[test]
    fn test_list_files() {
        let _cwd_lock = testutil::process_cwd_lock();
        let dir = tempfile::tempdir_in(".").expect("tempdir");
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"fixture\"\n",
        )
        .expect("write fixture Cargo.toml");

        let mut args = HashMap::new();
        args.insert("path".to_string(), json!(dir.path().to_str().unwrap()));
        let (output, is_error) = file::execute_list_files(test_run(), &args);
        assert!(!is_error, "list_files should succeed for temp fixture");
        assert!(!output.is_empty(), "temp fixture should contain files");
        assert!(
            output.contains("Cargo.toml"),
            "temp fixture should contain Cargo.toml, got: {output}"
        );
    }

    #[test]
    fn test_tool_call_accumulator() {
        let mut acc = ToolCallAccumulator::new();

        // Simulate streaming deltas
        acc.process_delta(&json!({
            "tool_calls": [{
                "index": 0,
                "id": "call_123",
                "type": "function",
                "function": {
                    "name": "bash",
                    "arguments": "{\"com"
                }
            }]
        }));

        acc.process_delta(&json!({
            "tool_calls": [{
                "index": 0,
                "function": {
                    "arguments": "mand\": \"ls\"}"
                }
            }]
        }));

        assert!(
            acc.has_tool_calls(),
            "id + function name should be treated as a finalizable tool call"
        );
        let calls = acc.finalize();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "bash");
        assert_eq!(calls[0].function.arguments, "{\"command\": \"ls\"}");
    }

    #[test]
    fn tool_call_accumulator_incomplete_slots_are_not_pending_work() {
        let mut id_only = ToolCallAccumulator::new();
        id_only.process_delta(&json!({
            "tool_calls": [{
                "index": 0,
                "id": "call_missing_name",
                "type": "function"
            }]
        }));
        assert!(
            !id_only.has_tool_calls(),
            "id-only partials cannot finalize into executable tool calls"
        );
        assert!(id_only.finalize().is_empty());

        let mut name_only = ToolCallAccumulator::new();
        name_only.process_delta(&json!({
            "tool_calls": [{
                "index": 0,
                "function": {"name": "bash", "arguments": "{\"command\":\"ls\"}"}
            }]
        }));
        assert!(
            !name_only.has_tool_calls(),
            "name-only partials cannot finalize without a tool_call id"
        );
        assert!(name_only.finalize().is_empty());
    }

    #[test]
    fn test_anthropic_accumulator_text_only() {
        let mut acc = AnthropicToolAccumulator::new();

        acc.process_event(
            &json!({"type": "content_block_start", "content_block": {"type": "text"}}),
        );
        let text1 = acc.process_event(&json!({"type": "content_block_delta", "delta": {"type": "text_delta", "text": "Hello "}}));
        let text2 = acc.process_event(&json!({"type": "content_block_delta", "delta": {"type": "text_delta", "text": "world"}}));
        acc.process_event(&json!({"type": "content_block_stop"}));
        acc.process_event(&json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}}));

        assert_eq!(text1, Some("Hello ".to_string()));
        assert_eq!(text2, Some("world".to_string()));
        assert!(!acc.has_tool_use());
        assert_eq!(acc.get_text(), "Hello world");
        assert_eq!(acc.stop_reason.as_deref(), Some("end_turn"));
    }

    #[test]
    fn test_anthropic_accumulator_tool_use() {
        let mut acc = AnthropicToolAccumulator::new();

        // Text block
        acc.process_event(
            &json!({"type": "content_block_start", "content_block": {"type": "text"}}),
        );
        acc.process_event(&json!({"type": "content_block_delta", "delta": {"type": "text_delta", "text": "Reading file..."}}));
        acc.process_event(&json!({"type": "content_block_stop"}));

        // Tool use block
        acc.process_event(&json!({
            "type": "content_block_start",
            "content_block": {"type": "tool_use", "id": "toolu_abc123", "name": "read_file"}
        }));
        acc.process_event(&json!({"type": "content_block_delta", "delta": {"type": "input_json_delta", "partial_json": "{\"path\":"}}));
        acc.process_event(&json!({"type": "content_block_delta", "delta": {"type": "input_json_delta", "partial_json": " \"test.txt\"}"}}));
        acc.process_event(&json!({"type": "content_block_stop"}));

        // Stop with tool_use
        acc.process_event(&json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}}));

        assert!(acc.has_tool_use());
        assert_eq!(acc.get_text(), "Reading file...");

        let tools = acc.finalize_tool_calls();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].id, "toolu_abc123");
        assert_eq!(tools[0].function.name, "read_file");
        assert_eq!(tools[0].function.arguments, "{\"path\": \"test.txt\"}");
    }

    #[test]
    fn test_anthropic_accumulator_multiple_tools() {
        let mut acc = AnthropicToolAccumulator::new();

        // First tool
        acc.process_event(&json!({
            "type": "content_block_start",
            "content_block": {"type": "tool_use", "id": "toolu_001", "name": "bash"}
        }));
        acc.process_event(&json!({"type": "content_block_delta", "delta": {"type": "input_json_delta", "partial_json": "{\"command\": \"ls\"}"}}));
        acc.process_event(&json!({"type": "content_block_stop"}));

        // Second tool
        acc.process_event(&json!({
            "type": "content_block_start",
            "content_block": {"type": "tool_use", "id": "toolu_002", "name": "read_file"}
        }));
        acc.process_event(&json!({"type": "content_block_delta", "delta": {"type": "input_json_delta", "partial_json": "{\"path\": \"Cargo.toml\"}"}}));
        acc.process_event(&json!({"type": "content_block_stop"}));

        acc.process_event(&json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}}));

        assert!(acc.has_tool_use());
        let tools = acc.finalize_tool_calls();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].function.name, "bash");
        assert_eq!(tools[1].function.name, "read_file");
    }

    #[test]
    fn test_anthropic_accumulator_openai_conversion() {
        let mut acc = AnthropicToolAccumulator::new();

        acc.process_event(&json!({
            "type": "content_block_start",
            "content_block": {"type": "tool_use", "id": "toolu_xyz", "name": "edit_file"}
        }));
        acc.process_event(&json!({"type": "content_block_delta", "delta": {"type": "input_json_delta", "partial_json": "{\"path\": \"a.rs\"}"}}));
        acc.process_event(&json!({"type": "content_block_stop"}));
        acc.process_event(&json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}}));

        let openai_calls = acc.to_openai_tool_calls_json();
        assert_eq!(openai_calls.len(), 1);
        assert_eq!(openai_calls[0]["id"], "toolu_xyz");
        assert_eq!(openai_calls[0]["function"]["name"], "edit_file");
        assert_eq!(
            openai_calls[0]["function"]["arguments"],
            "{\"path\": \"a.rs\"}"
        );
    }

    #[test]
    fn test_anthropic_accumulator_clear() {
        let mut acc = AnthropicToolAccumulator::new();

        acc.process_event(
            &json!({"type": "content_block_start", "content_block": {"type": "text"}}),
        );
        acc.process_event(&json!({"type": "content_block_delta", "delta": {"type": "text_delta", "text": "hello"}}));
        acc.process_event(&json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}}));

        assert_eq!(acc.blocks.len(), 1);
        assert!(acc.stop_reason.is_some());

        acc.clear();
        assert!(acc.blocks.is_empty());
        assert!(acc.stop_reason.is_none());
    }

    // === File type detection tests ===

    #[test]
    fn test_detect_file_type_images() {
        use super::file::ImageKind;
        assert!(matches!(
            detect_file_type("photo.png"),
            FileType::Image(ImageKind::Png)
        ));
        assert!(matches!(
            detect_file_type("photo.PNG"),
            FileType::Image(ImageKind::Png)
        ));
        assert!(matches!(
            detect_file_type("photo.jpg"),
            FileType::Image(ImageKind::Jpeg)
        ));
        assert!(matches!(
            detect_file_type("photo.jpeg"),
            FileType::Image(ImageKind::Jpeg)
        ));
        assert!(matches!(
            detect_file_type("photo.JPEG"),
            FileType::Image(ImageKind::Jpeg)
        ));
        assert!(matches!(
            detect_file_type("anim.gif"),
            FileType::Image(ImageKind::Gif)
        ));
        assert!(matches!(
            detect_file_type("modern.webp"),
            FileType::Image(ImageKind::Webp)
        ));
    }

    #[test]
    fn test_detect_file_type_pdf() {
        assert!(matches!(detect_file_type("document.pdf"), FileType::Pdf));
        assert!(matches!(detect_file_type("DOCUMENT.PDF"), FileType::Pdf));
    }

    #[test]
    fn test_detect_file_type_notebook() {
        assert!(matches!(
            detect_file_type("analysis.ipynb"),
            FileType::Notebook
        ));
        assert!(matches!(detect_file_type("test.IPYNB"), FileType::Notebook));
    }

    #[test]
    fn test_detect_file_type_text() {
        assert!(matches!(detect_file_type("main.rs"), FileType::Text));
        assert!(matches!(detect_file_type("README.md"), FileType::Text));
        assert!(matches!(detect_file_type("config.yaml"), FileType::Text));
        assert!(matches!(detect_file_type("data.csv"), FileType::Text));
    }

    // === Page range parsing tests ===

    #[test]
    fn test_parse_page_range_single() {
        assert_eq!(parse_page_range("3").unwrap(), (3, 3));
        assert_eq!(parse_page_range("1").unwrap(), (1, 1));
        assert_eq!(parse_page_range("100").unwrap(), (100, 100));
    }

    #[test]
    fn test_parse_page_range_range() {
        assert_eq!(parse_page_range("1-5").unwrap(), (1, 5));
        assert_eq!(parse_page_range("10-20").unwrap(), (10, 20));
        assert_eq!(parse_page_range(" 3 - 7 ").unwrap(), (3, 7));
    }

    #[test]
    fn test_parse_page_range_invalid() {
        assert!(parse_page_range("0").is_err());
        assert!(parse_page_range("5-3").is_err());
        assert!(parse_page_range("abc").is_err());
        assert!(parse_page_range("1-abc").is_err());
        assert!(parse_page_range("0-5").is_err());
    }

    // === Notebook source formatting tests ===

    #[test]
    fn test_source_to_line_array_multiline() {
        let result = source_to_line_array("line1\nline2\nline3");
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], json!("line1\n"));
        assert_eq!(arr[1], json!("line2\n"));
        assert_eq!(arr[2], json!("line3"));
    }

    #[test]
    fn test_source_to_line_array_single_line() {
        let result = source_to_line_array("hello world");
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0], json!("hello world"));
    }

    #[test]
    fn test_source_to_line_array_empty() {
        let result = source_to_line_array("");
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 0);
    }

    #[test]
    fn test_source_to_line_array_trailing_newline() {
        let result = source_to_line_array("line1\nline2\n");
        let arr = result.as_array().unwrap();
        // "line1\nline2\n" splits into ["line1", "line2", ""]
        // line1 -> "line1\n", line2 -> "line2\n", "" -> skipped (empty last)
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], json!("line1\n"));
        assert_eq!(arr[1], json!("line2\n"));
    }

    // === Notebook reading tests ===

    #[test]
    fn test_read_notebook_file() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let nb_path = dir.path().join("test.ipynb");
        let notebook = json!({
            "cells": [
                {
                    "cell_type": "markdown",
                    "metadata": {},
                    "source": ["# Title\n", "Some text"]
                },
                {
                    "cell_type": "code",
                    "metadata": {},
                    "source": ["print('hello')"],
                    "outputs": [
                        {
                            "output_type": "stream",
                            "name": "stdout",
                            "text": ["hello\n"]
                        }
                    ],
                    "execution_count": 1
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5
        });
        fs::write(&nb_path, serde_json::to_string_pretty(&notebook).unwrap()).unwrap();

        let (output, is_error) = read_notebook_file(test_run(), nb_path.to_str().unwrap());
        assert!(!is_error, "read_notebook_file should succeed: {output}");
        assert!(output.contains("Cell 0 (markdown)"));
        assert!(output.contains("# Title"));
        assert!(output.contains("Cell 1 (code)"));
        assert!(output.contains("print('hello')"));
        assert!(output.contains("Output:"));
        assert!(output.contains("hello"));
    }

    // === Notebook edit tests ===

    #[test]
    fn test_notebook_edit_replace() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let nb_path = dir.path().join("test.ipynb");
        let notebook = json!({
            "cells": [
                {
                    "cell_type": "code",
                    "metadata": {},
                    "source": ["old code"],
                    "outputs": [],
                    "execution_count": null
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5
        });
        fs::write(&nb_path, serde_json::to_string_pretty(&notebook).unwrap()).unwrap();

        // Mark as read first
        READ_TRACKER.mark_read(test_run(), &nb_path);

        let mut args = HashMap::new();
        args.insert(
            "notebook_path".to_string(),
            json!(nb_path.to_str().unwrap()),
        );
        args.insert("cell_number".to_string(), json!(0));
        args.insert("new_source".to_string(), json!("new code\nline 2"));

        let (output, is_error) = file::execute_notebook_edit(test_run(), &args);
        assert!(!is_error, "notebook_edit replace should succeed: {output}");
        assert!(output.contains("Replaced cell 0"));

        // Verify the file was updated
        let content = fs::read_to_string(&nb_path).unwrap();
        let updated: Value = serde_json::from_str(&content).unwrap();
        let source = updated["cells"][0]["source"].as_array().unwrap();
        assert_eq!(source[0], json!("new code\n"));
        assert_eq!(source[1], json!("line 2"));
    }

    #[test]
    fn test_notebook_edit_insert() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let nb_path = dir.path().join("test.ipynb");
        let notebook = json!({
            "cells": [
                {
                    "cell_type": "code",
                    "metadata": {},
                    "source": ["existing"],
                    "outputs": [],
                    "execution_count": null
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5
        });
        fs::write(&nb_path, serde_json::to_string_pretty(&notebook).unwrap()).unwrap();

        READ_TRACKER.mark_read(test_run(), &nb_path);

        let mut args = HashMap::new();
        args.insert(
            "notebook_path".to_string(),
            json!(nb_path.to_str().unwrap()),
        );
        args.insert("cell_number".to_string(), json!(0));
        args.insert("new_source".to_string(), json!("# New markdown cell"));
        args.insert("cell_type".to_string(), json!("markdown"));
        args.insert("edit_mode".to_string(), json!("insert"));

        let (output, is_error) = file::execute_notebook_edit(test_run(), &args);
        assert!(!is_error, "notebook_edit insert should succeed: {output}");
        assert!(output.contains("Inserted new markdown cell"));

        // Verify - should now have 2 cells
        let content = fs::read_to_string(&nb_path).unwrap();
        let updated: Value = serde_json::from_str(&content).unwrap();
        let cells = updated["cells"].as_array().unwrap();
        assert_eq!(cells.len(), 2);
        assert_eq!(cells[0]["cell_type"], json!("markdown"));
        assert_eq!(cells[1]["cell_type"], json!("code"));
    }

    #[test]
    fn test_notebook_edit_delete() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let nb_path = dir.path().join("test.ipynb");
        let notebook = json!({
            "cells": [
                {
                    "cell_type": "code",
                    "metadata": {},
                    "source": ["cell 0"],
                    "outputs": [],
                    "execution_count": null
                },
                {
                    "cell_type": "code",
                    "metadata": {},
                    "source": ["cell 1"],
                    "outputs": [],
                    "execution_count": null
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5
        });
        fs::write(&nb_path, serde_json::to_string_pretty(&notebook).unwrap()).unwrap();

        READ_TRACKER.mark_read(test_run(), &nb_path);

        let mut args = HashMap::new();
        args.insert(
            "notebook_path".to_string(),
            json!(nb_path.to_str().unwrap()),
        );
        args.insert("cell_number".to_string(), json!(0));
        args.insert("new_source".to_string(), json!(""));
        args.insert("edit_mode".to_string(), json!("delete"));

        let (output, is_error) = file::execute_notebook_edit(test_run(), &args);
        assert!(!is_error, "notebook_edit delete should succeed: {output}");
        assert!(output.contains("Deleted cell 0"));

        // Verify - should now have 1 cell
        let content = fs::read_to_string(&nb_path).unwrap();
        let updated: Value = serde_json::from_str(&content).unwrap();
        let cells = updated["cells"].as_array().unwrap();
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0]["source"].as_array().unwrap()[0], json!("cell 1"));
    }

    #[test]
    fn test_notebook_edit_requires_read_first() {
        let mut args = HashMap::new();
        args.insert(
            "notebook_path".to_string(),
            json!(std::env::current_dir()
                .unwrap()
                .join(".tmp-nonexistent-unread-notebook.ipynb")),
        );
        args.insert("cell_number".to_string(), json!(0));
        args.insert("new_source".to_string(), json!("test"));

        let (output, is_error) = file::execute_notebook_edit(test_run(), &args);
        assert!(is_error, "Should fail without reading first");
        assert!(output.contains("must read"));
    }

    #[test]
    fn test_notebook_edit_out_of_bounds() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let nb_path = dir.path().join("test.ipynb");
        let notebook = json!({
            "cells": [
                {
                    "cell_type": "code",
                    "metadata": {},
                    "source": ["only cell"],
                    "outputs": [],
                    "execution_count": null
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5
        });
        fs::write(&nb_path, serde_json::to_string_pretty(&notebook).unwrap()).unwrap();

        READ_TRACKER.mark_read(test_run(), &nb_path);

        let mut args = HashMap::new();
        args.insert(
            "notebook_path".to_string(),
            json!(nb_path.to_str().unwrap()),
        );
        args.insert("cell_number".to_string(), json!(5));
        args.insert("new_source".to_string(), json!("test"));

        let (output, is_error) = file::execute_notebook_edit(test_run(), &args);
        assert!(is_error, "Should fail for out-of-bounds cell");
        assert!(output.contains("out of bounds"));
    }

    #[test]
    fn test_notebook_edit_insert_requires_cell_type() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let nb_path = dir.path().join("test.ipynb");
        let notebook = json!({
            "cells": [],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5
        });
        fs::write(&nb_path, serde_json::to_string_pretty(&notebook).unwrap()).unwrap();

        READ_TRACKER.mark_read(test_run(), &nb_path);

        let mut args = HashMap::new();
        args.insert(
            "notebook_path".to_string(),
            json!(nb_path.to_str().unwrap()),
        );
        args.insert("cell_number".to_string(), json!(0));
        args.insert("new_source".to_string(), json!("test"));
        args.insert("edit_mode".to_string(), json!("insert"));
        // No cell_type provided

        let (output, is_error) = file::execute_notebook_edit(test_run(), &args);
        assert!(is_error, "Should fail without cell_type for insert");
        assert!(output.contains("cell_type is required"));
    }

    // === Image reading test ===

    #[test]
    fn test_read_image_file() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let img_path = dir.path().join("test.png");
        // Write some fake PNG bytes
        let fake_png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        fs::write(&img_path, &fake_png).unwrap();

        let (output, is_error) = read_image_file(
            test_run(),
            img_path.to_str().unwrap(),
            super::file::ImageKind::Png,
        );
        assert!(!is_error, "read_image_file should succeed");
        assert!(output.contains("[Image: test.png"));
        assert!(output.contains("image/png"));
        assert!(output.contains("8 bytes"));
        // Check that base64 data is present
        let b64 = base64::engine::general_purpose::STANDARD.encode(&fake_png);
        assert!(output.contains(&b64));
    }

    // === Insert code cell has outputs field ===

    #[test]
    fn test_notebook_edit_insert_code_cell_has_outputs() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let nb_path = dir.path().join("test.ipynb");
        let notebook = json!({
            "cells": [],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5
        });
        fs::write(&nb_path, serde_json::to_string_pretty(&notebook).unwrap()).unwrap();

        READ_TRACKER.mark_read(test_run(), &nb_path);

        let mut args = HashMap::new();
        args.insert(
            "notebook_path".to_string(),
            json!(nb_path.to_str().unwrap()),
        );
        args.insert("cell_number".to_string(), json!(0));
        args.insert("new_source".to_string(), json!("x = 1"));
        args.insert("cell_type".to_string(), json!("code"));
        args.insert("edit_mode".to_string(), json!("insert"));

        let (output, is_error) = file::execute_notebook_edit(test_run(), &args);
        assert!(!is_error, "insert code cell should succeed: {output}");

        let content = fs::read_to_string(&nb_path).unwrap();
        let updated: Value = serde_json::from_str(&content).unwrap();
        let cell = &updated["cells"][0];
        assert_eq!(cell["cell_type"], json!("code"));
        assert!(
            cell.get("outputs").is_some(),
            "Code cell should have outputs field"
        );
        assert!(cell["outputs"].as_array().unwrap().is_empty());
        assert!(
            cell.get("execution_count").is_some(),
            "Code cell should have execution_count"
        );
    }

    // === cell_id path (Claude Code parity) ===

    #[test]
    fn test_notebook_edit_resolves_by_cell_id() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let nb_path = dir.path().join("by-id.ipynb");
        let notebook = json!({
            "cells": [
                {"id": "cell-a", "cell_type": "code", "metadata": {}, "source": ["a"], "outputs": [], "execution_count": null},
                {"id": "cell-b", "cell_type": "code", "metadata": {}, "source": ["b"], "outputs": [], "execution_count": null},
            ],
            "metadata": {}, "nbformat": 4, "nbformat_minor": 5
        });
        fs::write(&nb_path, serde_json::to_string_pretty(&notebook).unwrap()).unwrap();
        READ_TRACKER.mark_read(test_run(), &nb_path);

        // Replace by cell_id — no cell_number supplied.
        let mut args = HashMap::new();
        args.insert(
            "notebook_path".to_string(),
            json!(nb_path.to_str().unwrap()),
        );
        args.insert("cell_id".to_string(), json!("cell-b"));
        args.insert("new_source".to_string(), json!("replaced-b"));
        let (output, is_error) = file::execute_notebook_edit(test_run(), &args);
        assert!(!is_error, "replace by cell_id should succeed: {output}");

        let updated: Value = serde_json::from_str(&fs::read_to_string(&nb_path).unwrap()).unwrap();
        assert_eq!(updated["cells"][1]["source"][0], json!("replaced-b"));
        // cell-a was left alone.
        assert_eq!(updated["cells"][0]["source"][0], json!("a"));
    }

    #[test]
    fn test_notebook_edit_insert_after_cell_id() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let nb_path = dir.path().join("insert-after.ipynb");
        let notebook = json!({
            "cells": [
                {"id": "one", "cell_type": "code", "metadata": {}, "source": ["1"], "outputs": [], "execution_count": null},
                {"id": "two", "cell_type": "code", "metadata": {}, "source": ["2"], "outputs": [], "execution_count": null},
            ],
            "metadata": {}, "nbformat": 4, "nbformat_minor": 5
        });
        fs::write(&nb_path, serde_json::to_string_pretty(&notebook).unwrap()).unwrap();
        READ_TRACKER.mark_read(test_run(), &nb_path);

        // Insert AFTER "one" — should land at position 1, pushing "two" to position 2.
        let mut args = HashMap::new();
        args.insert(
            "notebook_path".to_string(),
            json!(nb_path.to_str().unwrap()),
        );
        args.insert("cell_id".to_string(), json!("one"));
        args.insert("edit_mode".to_string(), json!("insert"));
        args.insert("cell_type".to_string(), json!("markdown"));
        args.insert("new_source".to_string(), json!("inserted"));
        let (output, is_error) = file::execute_notebook_edit(test_run(), &args);
        assert!(!is_error, "insert after cell_id should succeed: {output}");

        let updated: Value = serde_json::from_str(&fs::read_to_string(&nb_path).unwrap()).unwrap();
        let cells = updated["cells"].as_array().unwrap();
        assert_eq!(cells.len(), 3);
        assert_eq!(cells[0]["source"][0], json!("1"));
        assert_eq!(cells[1]["source"][0], json!("inserted"));
        assert_eq!(cells[1]["cell_type"], json!("markdown"));
        assert_eq!(cells[2]["source"][0], json!("2"));
    }

    #[test]
    fn test_notebook_edit_unknown_cell_id_errors() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let nb_path = dir.path().join("unknown.ipynb");
        let notebook = json!({
            "cells": [
                {"id": "a", "cell_type": "code", "metadata": {}, "source": ["x"], "outputs": [], "execution_count": null},
            ],
            "metadata": {}, "nbformat": 4, "nbformat_minor": 5
        });
        fs::write(&nb_path, serde_json::to_string_pretty(&notebook).unwrap()).unwrap();
        READ_TRACKER.mark_read(test_run(), &nb_path);

        let mut args = HashMap::new();
        args.insert(
            "notebook_path".to_string(),
            json!(nb_path.to_str().unwrap()),
        );
        args.insert("cell_id".to_string(), json!("does-not-exist"));
        args.insert("new_source".to_string(), json!("x"));
        let (output, is_error) = file::execute_notebook_edit(test_run(), &args);
        assert!(is_error);
        assert!(output.contains("does-not-exist"));
    }

    // ====================================================================
    // Task Management Tool Tests
    // ====================================================================

    #[test]
    fn test_task_create() {
        let mut task_mgr = TaskManager::new();
        let mut args = HashMap::new();
        args.insert("subject".to_string(), json!("Fix the bug"));
        args.insert(
            "description".to_string(),
            json!("There is a null pointer dereference in main"),
        );
        args.insert("active_form".to_string(), json!("Fixing the bug"));

        let (output, is_error) = task::execute_task_create(&args, &mut task_mgr);
        assert!(!is_error, "task_create should succeed: {output}");
        assert!(output.contains("task-1"));
        assert!(output.contains("Fix the bug"));

        // Verify the task was stored
        let tasks = task_mgr.list_tasks();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].subject, "Fix the bug");
    }

    #[test]
    fn test_task_update_status() {
        let mut task_mgr = TaskManager::new();
        task_mgr.create_task("Task A".to_string(), "Desc A".to_string(), None);

        let mut args = HashMap::new();
        args.insert("task_id".to_string(), json!("task-1"));
        args.insert("status".to_string(), json!("in_progress"));

        let (output, is_error) = task::execute_task_update(&args, &mut task_mgr);
        assert!(!is_error, "task_update should succeed: {output}");
        assert!(output.contains("in_progress"));
    }

    #[test]
    fn test_task_only_one_in_progress() {
        let mut task_mgr = TaskManager::new();
        task_mgr.create_task("Task A".to_string(), "Desc A".to_string(), None);
        task_mgr.create_task("Task B".to_string(), "Desc B".to_string(), None);

        // Set task-1 to in_progress
        let mut args = HashMap::new();
        args.insert("task_id".to_string(), json!("task-1"));
        args.insert("status".to_string(), json!("in_progress"));
        task::execute_task_update(&args, &mut task_mgr);

        // Set task-2 to in_progress -- task-1 should be demoted to pending
        args.insert("task_id".to_string(), json!("task-2"));
        task::execute_task_update(&args, &mut task_mgr);

        let task1 = task_mgr.get_task("task-1").unwrap();
        let task2 = task_mgr.get_task("task-2").unwrap();
        assert_eq!(task1.status, crate::session::TaskStatus::Pending);
        assert_eq!(task2.status, crate::session::TaskStatus::InProgress);
    }

    #[test]
    fn test_task_list_empty() {
        let task_mgr = TaskManager::new();
        let (output, is_error) = task::execute_task_list(&task_mgr);
        assert!(!is_error);
        assert_eq!(output, "No tasks.");
    }

    #[test]
    fn fix588_task_get_not_found_returns_success_with_null() {
        // crosslink #588: a not-found `task_get` matches CC's TaskGetTool,
        // which resolves with `null` (success) rather than throwing. The
        // earlier OC behaviour returned `is_error=true` with a "not found"
        // string, which forced the model into a recovery path for what is
        // a legitimate outcome (e.g. polling a deleted task).
        let task_mgr = TaskManager::new();
        let mut args = HashMap::new();
        args.insert("task_id".to_string(), json!("task-999"));
        let (output, is_error) = task::execute_task_get(&args, &task_mgr);
        assert!(
            !is_error,
            "task_get for missing id must be a successful lookup, not an error: {output}"
        );
        // Payload is the JSON literal `null` so structured consumers can
        // distinguish "no task" from "tool failure" without parsing prose.
        assert_eq!(output, "null", "not-found payload must be JSON null");
        let parsed: serde_json::Value =
            serde_json::from_str(&output).expect("payload must parse as JSON");
        assert!(parsed.is_null(), "parsed payload must be JSON null");
    }

    #[test]
    fn fix588_task_get_found_still_returns_full_detail() {
        // crosslink #588 regression guard: the success path for an existing
        // task must still emit the human-readable detail block, not null.
        let mut task_mgr = TaskManager::new();
        task_mgr.create_task("Real task".to_string(), "Desc".to_string(), None);
        let mut args = HashMap::new();
        args.insert("task_id".to_string(), json!("task-1"));
        let (output, is_error) = task::execute_task_get(&args, &task_mgr);
        assert!(!is_error, "found task must succeed: {output}");
        assert_ne!(
            output, "null",
            "found task must not be the not-found sentinel"
        );
        assert!(
            output.contains("Real task"),
            "detail must include subject: {output}"
        );
    }

    #[test]
    fn test_task_delete() {
        let mut task_mgr = TaskManager::new();
        task_mgr.create_task("Task to delete".to_string(), "Desc".to_string(), None);

        let mut args = HashMap::new();
        args.insert("task_id".to_string(), json!("task-1"));
        args.insert("status".to_string(), json!("deleted"));
        let (output, is_error) = task::execute_task_update(&args, &mut task_mgr);
        assert!(!is_error, "delete should not be an error: {output}");
        assert!(output.contains("deleted"));
        assert!(task_mgr.list_tasks().is_empty());
    }

    #[test]
    fn test_task_dependencies() {
        let mut task_mgr = TaskManager::new();
        task_mgr.create_task("Setup DB".to_string(), "Create schema".to_string(), None);
        task_mgr.create_task("Add API".to_string(), "REST endpoints".to_string(), None);

        // task-2 is blocked by task-1
        let mut args = HashMap::new();
        args.insert("task_id".to_string(), json!("task-2"));
        args.insert("add_blocked_by".to_string(), json!(["task-1"]));
        let (_, is_error) = task::execute_task_update(&args, &mut task_mgr);
        assert!(!is_error);

        let task1 = task_mgr.get_task("task-1").unwrap();
        let task2 = task_mgr.get_task("task-2").unwrap();
        // task-2 should have task-1 in blocked_by
        assert!(task2.blocked_by.contains(&"task-1".to_string()));
        // task-1 should have task-2 in blocks (reverse relationship)
        assert!(task1.blocks.contains(&"task-2".to_string()));
    }

    // ====================================================================
    // Permission Checking Tests
    // ====================================================================

    #[test]
    fn test_check_tool_permission_explicit_unrestricted_manager() {
        let tool_call = ToolCall {
            id: "call_1".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "bash".to_string(),
                arguments: r#"{"command": "ls"}"#.to_string(),
            },
        };
        let manager = PermissionManager::unrestricted();
        assert!(check_tool_permission(&tool_call, &manager).is_none());
    }

    #[test]
    fn outcome_permission_allows_safe_call_when_prompts_are_explicitly_disabled() {
        let tool_call = ToolCall {
            id: "call_1".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "bash".to_string(),
                arguments: r#"{"command": "ls"}"#.to_string(),
            },
        };
        let tmp = tempfile::tempdir().expect("tempdir");
        let mgr = PermissionManager::new(tmp.path().join("p.json"), false, vec![]);
        match check_tool_permission_outcome(&tool_call, &mgr) {
            PermissionOutcome::Allowed => {}
            other => {
                panic!("expected Allowed for explicitly-disabled (unrestricted) mgr, got {other:?}")
            }
        }
    }

    #[test]
    fn outcome_enum_allowed_for_enabled_manager_matching_rule() {
        let tool_call = ToolCall {
            id: "call_1".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "bash".to_string(),
                arguments: r#"{"command": "echo hi"}"#.to_string(),
            },
        };
        let tmp = tempfile::tempdir().expect("tempdir");
        let mgr =
            PermissionManager::new(tmp.path().join("p.json"), true, vec!["echo *".to_string()]);
        match check_tool_permission_outcome(&tool_call, &mgr) {
            PermissionOutcome::Allowed => {}
            other => panic!("expected Allowed, got {other:?}"),
        }
    }

    #[test]
    fn outcome_enum_needs_prompt_when_no_rule_matches() {
        let tool_call = ToolCall {
            id: "call_1".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "bash".to_string(),
                arguments: r#"{"command": "rm -rf ./foo"}"#.to_string(),
            },
        };
        let tmp = tempfile::tempdir().expect("tempdir");
        let mgr = PermissionManager::new(tmp.path().join("p.json"), true, vec![]);
        match check_tool_permission_outcome(&tool_call, &mgr) {
            PermissionOutcome::NeedsPrompt {
                tool_call_id, tool, ..
            } => {
                assert_eq!(tool_call_id, "call_1");
                assert_eq!(tool, "Bash");
            }
            other => panic!("expected NeedsPrompt, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Gated-dispatch tests — crosslink #460 mandated point 2.
    // ------------------------------------------------------------------

    /// Build a permission manager with a session rule that denies every
    /// bash invocation. Used to prove the gated dispatch short-circuits
    /// before the tool body runs.
    fn deny_all_bash_manager() -> (PermissionManager, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut mgr = PermissionManager::new(tmp.path().join("p.json"), true, vec![]);
        mgr.add_session_rule(crate::permissions::PermissionRule {
            tool: "Bash".to_string(),
            pattern: "*".to_string(),
            decision: crate::permissions::PermissionDecision::Deny,
        });
        (mgr, tmp)
    }

    #[test]
    fn execute_tool_gated_denies_when_rule_denies() {
        // A bash command that WOULD have side-effects if it ran; the rule
        // denies it, and we assert no ToolResult from the body leaks out.
        let tool_call = ToolCall {
            id: "gated_deny_1".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "bash".to_string(),
                arguments: r#"{"command": "echo SHOULD_NOT_RUN"}"#.to_string(),
            },
        };
        let (mgr, _tmp) = deny_all_bash_manager();
        match execute_tool_gated(test_run(), &tool_call, None, None, None, &mgr) {
            ExecutionOutcome::Result(r) => {
                assert!(r.is_error(), "denial should mark the result as error");
                assert!(
                    r.content().to_lowercase().contains("denied"),
                    "expected 'denied' in content, got: {}",
                    r.content()
                );
                assert!(
                    !r.content().contains("SHOULD_NOT_RUN"),
                    "tool body ran despite denial — gate bypassed: {}",
                    r.content()
                );
            }
            other @ ExecutionOutcome::NeedsPrompt { .. } => {
                panic!("expected Result(Denied), got {other:?}")
            }
        }
    }

    #[test]
    fn execute_tool_gated_allows_when_rule_allows() {
        let tool_call = ToolCall {
            id: "gated_allow_1".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "bash".to_string(),
                arguments: r#"{"command": "echo HELLO_GATED"}"#.to_string(),
            },
        };
        let tmp = tempfile::tempdir().expect("tempdir");
        let mgr =
            PermissionManager::new(tmp.path().join("p.json"), true, vec!["echo *".to_string()]);
        match execute_tool_gated(test_run(), &tool_call, None, None, None, &mgr) {
            ExecutionOutcome::Result(r) => {
                assert!(
                    !r.is_error(),
                    "allowed bash echo should not error; content={}",
                    r.content()
                );
                assert!(
                    r.content().contains("HELLO_GATED"),
                    "expected tool body to have run; got: {}",
                    r.content()
                );
            }
            other @ ExecutionOutcome::NeedsPrompt { .. } => {
                panic!("expected Result(Allowed-executed), got {other:?}")
            }
        }
    }

    #[test]
    fn execute_tool_gated_needs_prompt_returns_structured_outcome() {
        let tool_call = ToolCall {
            id: "gated_prompt_1".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "bash".to_string(),
                arguments: r#"{"command": "rm -rf ./foo"}"#.to_string(),
            },
        };
        let tmp = tempfile::tempdir().expect("tempdir");
        // enabled manager, no matching rule -> NeedsPrompt
        let mgr = PermissionManager::new(tmp.path().join("p.json"), true, vec![]);
        match execute_tool_gated(test_run(), &tool_call, None, None, None, &mgr) {
            ExecutionOutcome::NeedsPrompt {
                tool_call_id,
                tool,
                target,
            } => {
                assert_eq!(tool_call_id, "gated_prompt_1");
                assert_eq!(tool, "Bash");
                assert!(
                    target.contains("rm"),
                    "target should carry the command, got: {target}"
                );
            }
            ExecutionOutcome::Result(r) => {
                panic!("expected structured NeedsPrompt, got Result({r:?})");
            }
        }
    }

    #[test]
    fn required_manager_dispatch_accepts_explicit_unrestricted_policy() {
        let tool_call = ToolCall {
            id: "gated_strict_1".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "bash".to_string(),
                arguments: r#"{"command": "echo strict"}"#.to_string(),
            },
        };
        let mgr = PermissionManager::unrestricted();
        let result =
            execute_tool_with_permission_required(test_run(), &tool_call, None, None, None, &mgr);
        assert!(
            !result.is_error(),
            "unrestricted manager should pass through; got: {}",
            result.content()
        );
        assert!(result.content().contains("strict"));
    }
}
