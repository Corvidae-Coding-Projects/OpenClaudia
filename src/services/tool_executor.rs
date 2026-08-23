//! Shared local tool execution service.
//!
//! This centralizes the common "run an `OpenClaudia` tool locally" mechanics
//! that were duplicated across TUI, legacy REPL, ACP local tools, and subagents:
//! optional enterprise tool cap, session id guard,
//! active ledger installation, exact permission authorization, and
//! task-manager-aware execution.

use crate::config::AppConfig;
use crate::file_types::extensions_from_tool_input;
use crate::hooks::{HookEngine, HookError, HookEvent, HookInput};
use crate::memory::MemoryDb;
use crate::permissions::{AuthorizationResult, ExecutionPermit, PermissionManager};
use crate::runtime::BudgetAmounts;
use crate::services::policy::{PolicyEnforcer, ToolExecutionPolicy};
use crate::session::TaskManager;
use crate::tools::{self, ToolCall, ToolFailureCode, ToolResult, ToolRetryability};
use serde_json::Value;
use std::collections::HashMap;

/// A lifecycle gate blocked a tool before dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionBlock {
    /// User/model visible block reason.
    pub content: String,
}

impl ToolExecutionBlock {
    /// Convert this block into a standard tool result.
    #[must_use]
    pub fn into_tool_result(self, tool_call: &ToolCall) -> ToolResult {
        ToolResult::failure(
            tool_call,
            ToolFailureCode::PolicyDenied,
            self.content,
            ToolRetryability::Never,
        )
    }
}

/// Inputs for one local tool execution.
pub struct ToolExecutorRequest<'a> {
    /// Mandatory immutable run capability. This is the only source of host
    /// workspace, process, network, secret, cancellation, and session identity.
    pub run_context: &'a std::sync::Arc<tools::ToolRunContext>,
    /// Tool call to execute.
    pub tool_call: &'a ToolCall,
    /// Optional memory database for memory tools.
    pub memory_db: Option<&'a MemoryDb>,
    /// Optional app config for subagent tools.
    pub app_config: Option<&'a AppConfig>,
    /// Optional task manager for task_* tools.
    pub task_mgr: Option<&'a mut TaskManager>,
    /// Permission manager used for normal checks and permit revalidation.
    /// A concrete manager is mandatory; explicit prompt bypass is represented
    /// by [`PermissionManager::unrestricted`], never by an absent argument.
    pub permission_mgr: &'a PermissionManager,
    /// Opaque exact-call permit minted by an outer interactive decision.
    /// Absence means the executor performs the normal permission check.
    pub authorization: Option<ExecutionPermit>,
    /// Session id to bind for session-scoped tools and ledger observations.
    pub session_id: Option<&'a str>,
    /// Optional enterprise policy enforcer. When supplied with `session_id`,
    /// the tool cap is checked and recorded before dispatch.
    pub policy_enforcer: Option<&'a PolicyEnforcer>,
}

/// Shared local tool executor.
pub struct ToolExecutor;

impl ToolExecutor {
    /// Parse tool arguments as a JSON object.
    ///
    /// # Errors
    ///
    /// Returns a user/model visible validation error when the argument string
    /// is malformed JSON or does not decode to an object.
    pub fn parse_arguments(tool_name: &str, arguments: &str) -> Result<Value, String> {
        let value = serde_json::from_str::<Value>(arguments)
            .map_err(|e| format!("Invalid tool arguments JSON for '{tool_name}': {e}"))?;
        if !value.is_object() {
            return Err(format!(
                "Invalid tool arguments JSON for '{tool_name}': expected a JSON object, got {}",
                json_value_type_name(&value)
            ));
        }
        Ok(value)
    }

    /// Parse tool arguments as both a map and the original object value.
    ///
    /// # Errors
    ///
    /// Returns the same validation text as [`Self::parse_arguments`].
    pub fn parse_arguments_map(
        tool_name: &str,
        arguments: &str,
    ) -> Result<(HashMap<String, Value>, Value), String> {
        let value = Self::parse_arguments(tool_name, arguments)?;
        let Value::Object(map) = value else {
            unreachable!("parse_arguments only returns object values");
        };
        let args = map.clone().into_iter().collect();
        Ok((args, Value::Object(map)))
    }

    /// Dry-run enterprise policy before user-facing gates such as permission
    /// prompts. Actual cap recording happens in [`Self::execute`] immediately
    /// before dispatch.
    ///
    /// # Errors
    ///
    /// Returns the policy error if the tool is already capped for the session.
    pub fn check_policy_before_prompt(
        policy_enforcer: Option<&PolicyEnforcer>,
        session_id: Option<&str>,
        tool_name: &str,
    ) -> Result<(), crate::services::policy::PolicyError> {
        ToolExecutionPolicy::new(policy_enforcer, session_id).check_tool(tool_name)
    }

    /// Run the shared `PreToolUse` hook gate for one tool dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`ToolExecutionBlock`] when a deny-intent hook blocks dispatch.
    pub async fn run_pre_tool_use(
        run_context: &std::sync::Arc<tools::ToolRunContext>,
        hook_engine: &HookEngine,
        session_id: Option<&str>,
        tool_name: &str,
        tool_input: &Value,
    ) -> Result<(), ToolExecutionBlock> {
        let extensions = extensions_from_tool_input(tool_name, tool_input);

        let mut hook_input = HookInput::for_run(run_context, HookEvent::PreToolUse)
            .with_tool(tool_name, tool_input.clone());
        if let Some(session_id) = session_id {
            hook_input = hook_input.with_session_id(session_id);
        }
        if !extensions.is_empty() {
            hook_input = hook_input.with_extra("extensions", serde_json::json!(extensions));
        }

        let hook_result = hook_engine.run(HookEvent::PreToolUse, &hook_input).await;
        if let Err(hook_err) = HookEngine::check_blocked(&hook_result) {
            let reason = match hook_err {
                HookError::Blocked(reason) => reason,
                other => other.to_string(),
            };
            tracing::warn!(
                tool = %tool_name,
                session_id = ?session_id,
                reason = %reason,
                "PreToolUse hook blocked tool dispatch"
            );
            return Err(ToolExecutionBlock {
                content: format!("Tool '{tool_name}' blocked by PreToolUse hook: {reason}"),
            });
        }

        Ok(())
    }

    /// Fire the shared post-tool hook lifecycle event.
    pub async fn fire_post_tool(
        run_context: &std::sync::Arc<tools::ToolRunContext>,
        hook_engine: &HookEngine,
        success: bool,
        tool_name: &str,
        tool_input: Value,
        tool_output: &str,
        session_id: Option<&str>,
    ) {
        hook_engine
            .fire_post_tool(
                run_context,
                success,
                tool_name,
                tool_input,
                tool_output,
                session_id,
            )
            .await;
    }

    /// Append a bounded tool-result observation to the active session ledger.
    pub fn observe_tool_result(
        run: &crate::tools::ToolRunContext,
        session_id: Option<&str>,
        result: &ToolResult,
    ) {
        if let Some(session_id) = session_id {
            crate::grounded_loop::observe_tool_result_for_session(run, session_id, result);
        }
    }

    /// Execute a local tool call.
    ///
    /// # Errors
    ///
    /// Tool failures are returned inside [`ToolResult::is_error`], matching the
    /// historical dispatcher contract.
    #[must_use]
    #[allow(clippy::too_many_lines)] // Policy, budget admission, dispatch, and settlement are one auditable boundary.
    pub fn execute(request: ToolExecutorRequest<'_>) -> ToolResult {
        let ToolExecutorRequest {
            run_context,
            tool_call,
            memory_db,
            app_config,
            task_mgr,
            permission_mgr,
            authorization,
            session_id,
            policy_enforcer,
        } = request;

        // `session_id` is a logical state/ledger bucket (subagents use their
        // stable agent id). Host authority comes only from `run_context` and
        // must never be inferred from this caller-controlled label.
        let session_id = session_id.or_else(|| Some(run_context.session_id()));

        if let Err(reason) = run_context
            .tool_catalog()
            .admit_tool_call(&tool_call.function.name)
        {
            return ToolResult::failure(
                tool_call,
                ToolFailureCode::Unavailable,
                reason,
                ToolRetryability::Safe,
            );
        }

        let arguments =
            match Self::parse_arguments(&tool_call.function.name, &tool_call.function.arguments) {
                Ok(arguments) => arguments,
                Err(reason) => {
                    return ToolResult::failure(
                        tool_call,
                        ToolFailureCode::InvalidArguments,
                        reason,
                        ToolRetryability::Never,
                    )
                }
            };
        if let Err(reason) =
            run_context.admit_runtime_mode_tool(&tool_call.function.name, &arguments)
        {
            return ToolResult::failure(
                tool_call,
                ToolFailureCode::PolicyDenied,
                reason,
                ToolRetryability::Never,
            );
        }

        let tool_policy = ToolExecutionPolicy::new(policy_enforcer, session_id);
        if let Err(err) = tool_policy.check_tool(&tool_call.function.name) {
            return ToolResult::failure(
                tool_call,
                ToolFailureCode::PolicyDenied,
                format!("Blocked by policy: {err}"),
                ToolRetryability::Never,
            );
        }

        let _ledger_guard =
            session_id.and_then(crate::grounded_loop::install_active_project_ledger_for_session);

        let authorization = match authorization {
            Some(permit) => permit,
            None => match permission_mgr.authorize_tool_call(tool_call, session_id) {
                AuthorizationResult::Allowed(permit) => permit,
                AuthorizationResult::Denied(reason) => {
                    return ToolResult::failure(
                        tool_call,
                        ToolFailureCode::PermissionDenied,
                        format!("Permission denied: {reason}"),
                        ToolRetryability::Never,
                    );
                }
                AuthorizationResult::NeedsPrompt { tool, target } => {
                    return ToolResult::failure(
                        tool_call,
                        ToolFailureCode::PermissionDenied,
                        format!(
                            "Permission denied: no interactive prompt is available for {tool} on '{target}'"
                        ),
                        ToolRetryability::Never,
                    );
                }
            },
        };

        let consumed_authorization =
            match permission_mgr.consume_execution_permit(&authorization, tool_call, session_id) {
                Ok(consumed) => consumed,
                Err(reason) => {
                    return ToolResult::failure(
                        tool_call,
                        ToolFailureCode::PermissionDenied,
                        format!("Permission denied: execution permit rejected: {reason}"),
                        ToolRetryability::Never,
                    );
                }
            };

        if let Err(err) = tool_policy.check_and_record_tool(&tool_call.function.name) {
            return ToolResult::failure(
                tool_call,
                ToolFailureCode::PolicyDenied,
                format!("Blocked by policy: {err}"),
                ToolRetryability::Never,
            );
        }

        let budget_reservation = match run_context.budget().reserve(BudgetAmounts {
            tool_calls: 1,
            concurrent_calls: 1,
            ..BudgetAmounts::default()
        }) {
            Ok(reservation) => Some(reservation),
            Err(crate::runtime::BudgetError::Cancelled { .. })
                if handler_reports_cancellation(&tool_call.function.name) =>
            {
                None
            }
            Err(error) => return budget_denied_tool_result(tool_call, &error),
        };
        let result = tools::execute_tool_after_authorization(
            run_context,
            tool_call,
            memory_db,
            app_config,
            task_mgr,
            Some(&consumed_authorization),
        );
        if let Some(budget_reservation) = budget_reservation {
            if let Err(error) = budget_reservation.commit() {
                return budget_accounting_failure(tool_call, &error);
            }
        }
        result
    }

    /// Execute one dynamically registered MCP tool through the same catalog,
    /// enterprise-policy, permission, host-safety, capability, guardrail and
    /// typed-result boundaries used by static handlers.
    ///
    /// # Errors
    ///
    /// Failures are represented inside the returned [`ToolResult`]. Calls
    /// that may have reached a remote handler before transport failure are
    /// conservatively reported as typed partial outcomes.
    pub async fn execute_mcp(request: ToolExecutorRequest<'_>) -> ToolResult {
        let ToolExecutorRequest {
            run_context,
            tool_call,
            memory_db,
            app_config,
            task_mgr: _,
            permission_mgr,
            authorization,
            session_id,
            policy_enforcer,
        } = request;
        let session_id = session_id.or_else(|| Some(run_context.session_id()));
        let Some(manager) = crate::mcp::registered_manager(run_context) else {
            return ToolResult::failure(
                tool_call,
                ToolFailureCode::Unavailable,
                "MCP manager is unavailable for this exact run generation",
                ToolRetryability::Safe,
            );
        };
        let manager = manager.read().await;
        if !manager.matches_run(run_context) {
            return ToolResult::failure(
                tool_call,
                ToolFailureCode::Unavailable,
                "MCP manager belongs to a different run generation",
                ToolRetryability::Never,
            );
        }
        let preflight = match prepare_mcp_dispatch(McpPreflightRequest {
            run_context,
            tool_call,
            permission_mgr,
            authorization,
            session_id,
            policy_enforcer,
        }) {
            Ok(preflight) => preflight,
            Err(result) => return *result,
        };
        let budget_reservation = match run_context.budget().reserve(BudgetAmounts {
            tool_calls: 1,
            concurrent_calls: 1,
            ..BudgetAmounts::default()
        }) {
            Ok(reservation) => reservation,
            Err(error) => return budget_denied_tool_result(tool_call, &error),
        };
        let remotely_dispatched = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dispatch_evidence = std::sync::Arc::clone(&remotely_dispatched);
        let outcome = manager
            .call_tool_registered_with_dispatch(
                &tool_call.function.name,
                preflight.arguments,
                preflight.source_digest,
                move || {
                    dispatch_evidence.store(true, std::sync::atomic::Ordering::Release);
                    preflight.reservation.commit();
                },
            )
            .await;
        drop(manager);

        let handler_result = match outcome {
            Ok(value) => {
                tools::ToolHandlerResult::success_structured(mcp_result_text(&value), value)
            }
            Err(error) => mcp_error_result(
                &error,
                remotely_dispatched.load(std::sync::atomic::Ordering::Acquire),
            ),
        };
        let result = ToolResult::bind(tool_call, &tool_call.function.name, handler_result);
        let result =
            tools::attach_automatic_learning(run_context, memory_db, app_config, None, result);
        if let Err(error) = budget_reservation.commit() {
            return budget_accounting_failure(tool_call, &error);
        }
        result
    }

    /// Convert a missing run binding into a typed unavailable result without
    /// evaluating permission policy or dispatching any handler.
    #[must_use]
    pub fn execute_unbound(tool_call: &ToolCall) -> ToolResult {
        tools::execute_tool_without_context(tool_call)
    }
}

fn handler_reports_cancellation(tool_name: &str) -> bool {
    matches!(tool_name, "memory_export" | "memory_import")
}

fn budget_denied_tool_result(
    tool_call: &ToolCall,
    error: &crate::runtime::BudgetError,
) -> ToolResult {
    ToolResult::failure(
        tool_call,
        ToolFailureCode::PolicyDenied,
        format!("Run budget denied tool dispatch: {error}"),
        ToolRetryability::Never,
    )
}

fn budget_accounting_failure(
    tool_call: &ToolCall,
    error: &crate::runtime::BudgetError,
) -> ToolResult {
    ToolResult::failure(
        tool_call,
        ToolFailureCode::Internal,
        format!("Tool completed, but run budget accounting failed: {error}"),
        ToolRetryability::Never,
    )
}

struct McpPreflightRequest<'a> {
    run_context: &'a std::sync::Arc<tools::ToolRunContext>,
    tool_call: &'a ToolCall,
    permission_mgr: &'a PermissionManager,
    authorization: Option<ExecutionPermit>,
    session_id: Option<&'a str>,
    policy_enforcer: Option<&'a PolicyEnforcer>,
}

struct McpDispatchPreflight {
    arguments: Value,
    source_digest: crate::runtime::ContentDigest,
    reservation: tools::DynamicToolEffectReservation,
}

fn prepare_mcp_dispatch(
    mut request: McpPreflightRequest<'_>,
) -> Result<McpDispatchPreflight, Box<ToolResult>> {
    let admission = match request
        .run_context
        .tool_catalog()
        .admit_tool_call_with_receipt(&request.tool_call.function.name)
    {
        Ok(admission) if admission.is_mcp() => admission,
        Ok(_) => {
            return Err(Box::new(ToolResult::failure(
                request.tool_call,
                ToolFailureCode::Unavailable,
                format!(
                    "Tool '{}' is not registered as a dynamic MCP capability",
                    request.tool_call.function.name
                ),
                ToolRetryability::Never,
            )));
        }
        Err(reason) => {
            return Err(Box::new(ToolResult::failure(
                request.tool_call,
                ToolFailureCode::Unavailable,
                reason,
                ToolRetryability::Safe,
            )));
        }
    };
    let arguments = ToolExecutor::parse_arguments(
        &request.tool_call.function.name,
        &request.tool_call.function.arguments,
    )
    .map_err(|reason| {
        Box::new(ToolResult::failure(
            request.tool_call,
            ToolFailureCode::InvalidArguments,
            reason,
            ToolRetryability::Never,
        ))
    })?;
    let Value::Object(argument_object) = &arguments else {
        unreachable!("parse_arguments only returns JSON objects");
    };
    let argument_map: HashMap<String, Value> = argument_object.clone().into_iter().collect();
    request
        .run_context
        .admit_runtime_mode_tool(&request.tool_call.function.name, &arguments)
        .map_err(|reason| {
            Box::new(ToolResult::failure(
                request.tool_call,
                ToolFailureCode::PolicyDenied,
                reason,
                ToolRetryability::Never,
            ))
        })?;

    let tool_policy = ToolExecutionPolicy::new(request.policy_enforcer, request.session_id);
    tool_policy
        .check_tool(&request.tool_call.function.name)
        .map_err(|error| {
            Box::new(ToolResult::failure(
                request.tool_call,
                ToolFailureCode::PolicyDenied,
                format!("Blocked by policy: {error}"),
                ToolRetryability::Never,
            ))
        })?;
    let authorization = authorize_mcp_dispatch(&mut request)?;
    let consumed = request
        .permission_mgr
        .consume_execution_permit(&authorization, request.tool_call, request.session_id)
        .map_err(|reason| {
            Box::new(ToolResult::failure(
                request.tool_call,
                ToolFailureCode::PermissionDenied,
                format!("Permission denied: execution permit rejected: {reason}"),
                ToolRetryability::Never,
            ))
        })?;
    tool_policy
        .check_and_record_tool(&request.tool_call.function.name)
        .map_err(|error| {
            Box::new(ToolResult::failure(
                request.tool_call,
                ToolFailureCode::PolicyDenied,
                format!("Blocked by policy: {error}"),
                ToolRetryability::Never,
            ))
        })?;
    let reservation = tools::reserve_dynamic_tool_effect(
        request.run_context,
        request.tool_call,
        &argument_map,
        &consumed,
    )?;
    Ok(McpDispatchPreflight {
        arguments,
        source_digest: admission.source_digest,
        reservation,
    })
}

fn authorize_mcp_dispatch(
    request: &mut McpPreflightRequest<'_>,
) -> Result<ExecutionPermit, Box<ToolResult>> {
    if let Some(permit) = request.authorization.take() {
        return Ok(permit);
    }
    match request
        .permission_mgr
        .authorize_tool_call(request.tool_call, request.session_id)
    {
        AuthorizationResult::Allowed(permit) => Ok(permit),
        AuthorizationResult::Denied(reason) => Err(Box::new(ToolResult::failure(
            request.tool_call,
            ToolFailureCode::PermissionDenied,
            format!("Permission denied: {reason}"),
            ToolRetryability::Never,
        ))),
        AuthorizationResult::NeedsPrompt { tool, target } => Err(Box::new(ToolResult::failure(
            request.tool_call,
            ToolFailureCode::PermissionDenied,
            format!(
                "Permission denied: no interactive prompt is available for {tool} on '{target}'"
            ),
            ToolRetryability::Never,
        ))),
    }
}

const fn json_value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn mcp_result_text(value: &Value) -> String {
    let text = value
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n");
    if text.is_empty() {
        "MCP tool completed with structured output.".to_string()
    } else {
        text
    }
}

fn mcp_error_result(
    error: &crate::mcp::McpError,
    remotely_dispatched: bool,
) -> tools::ToolHandlerResult {
    let (code, retryability) = match error {
        crate::mcp::McpError::InvalidToolArguments { .. } => {
            (ToolFailureCode::InvalidArguments, ToolRetryability::Never)
        }
        crate::mcp::McpError::ToolNotAllowed { .. } => {
            (ToolFailureCode::PolicyDenied, ToolRetryability::Never)
        }
        crate::mcp::McpError::Timeout { .. } => (
            ToolFailureCode::DeadlineExceeded,
            ToolRetryability::AfterBackoff,
        ),
        crate::mcp::McpError::ToolReportedError { .. }
        | crate::mcp::McpError::Transport(_)
        | crate::mcp::McpError::Protocol(_)
        | crate::mcp::McpError::ResponseIdMismatch { .. }
        | crate::mcp::McpError::Io(_) => (ToolFailureCode::External, ToolRetryability::Unknown),
        crate::mcp::McpError::ServerUnreachable(_) => {
            (ToolFailureCode::Unavailable, ToolRetryability::AfterBackoff)
        }
        crate::mcp::McpError::ToolNotFound(_)
        | crate::mcp::McpError::NotConnected(_)
        | crate::mcp::McpError::StaleToolRegistration(_)
        | crate::mcp::McpError::InvalidToolSchema { .. } => {
            (ToolFailureCode::Unavailable, ToolRetryability::Safe)
        }
    };
    let failure = tools::ToolFailure::new(code, error.to_string(), retryability);
    if remotely_dispatched {
        let (message, structured) = match error {
            crate::mcp::McpError::ToolReportedError { result, .. } => (
                "MCP tool reported a typed failure after remote dispatch.",
                result.clone(),
            ),
            _ => (
                "MCP call may have produced a remote effect before failing.",
                serde_json::json!({"state": "remote_outcome_unknown"}),
            ),
        };
        tools::ToolHandlerResult::partial_structured(message, structured, vec![failure], None)
    } else {
        tools::ToolHandlerResult::error(failure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::policy::{EnterprisePolicy, PolicyEnforcer, ToolCaps};
    use crate::tools::{FunctionCall, ToolCall};

    fn test_run() -> &'static std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context()
    }

    fn bash_call(command: &str) -> ToolCall {
        ToolCall {
            id: "call_bash".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "bash".to_string(),
                arguments: serde_json::json!({ "command": command }).to_string(),
            },
        }
    }

    fn one_tool_run() -> std::sync::Arc<crate::tools::ToolRunContext> {
        let root = tempfile::tempdir().expect("root").keep();
        crate::tools::ToolRunContext::builder(crate::state::SessionId::new(), &root)
            .working_directory(&root)
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(std::collections::HashMap::new())
            .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
            .process(true)
            .network(false)
            .secrets(false)
            .provider("test")
            .budget_limits(crate::runtime::BudgetLimits {
                tool_calls: 1,
                ..crate::runtime::BudgetLimits::default()
            })
            .build()
            .expect("run")
    }

    #[test]
    fn tool_executor_enforces_policy_before_dispatch() {
        let mut caps = ToolCaps::new();
        caps.insert("bash".to_string(), 0);
        let enforcer = PolicyEnforcer::new(EnterprisePolicy {
            tool_caps: caps,
            ..Default::default()
        });
        let call = bash_call("printf tool-executor-should-not-run");
        let permission_manager = PermissionManager::unrestricted();

        let result = ToolExecutor::execute(ToolExecutorRequest {
            run_context: test_run(),
            tool_call: &call,
            memory_db: None,
            app_config: None,
            task_mgr: None,
            permission_mgr: &permission_manager,
            authorization: None,
            session_id: Some("s1"),
            policy_enforcer: Some(&enforcer),
        });

        assert!(result.is_error());
        assert!(result.content().contains("Blocked by policy"));
        assert!(!result.content().contains("tool-executor-should-not-run"));
    }

    #[test]
    fn runtime_mode_denial_cannot_be_widened_by_unrestricted_permissions() {
        let run = one_tool_run();
        run.transition_runtime_mode(crate::modes::RuntimeMode::Behavioral(
            crate::modes::BehaviorMode::from_preset(crate::modes::Preset::Explore),
        ))
        .expect("install explore mode");
        let call = bash_call("printf runtime-mode-should-not-run");
        let permission_manager = PermissionManager::unrestricted();

        let result = ToolExecutor::execute(ToolExecutorRequest {
            run_context: &run,
            tool_call: &call,
            memory_db: None,
            app_config: None,
            task_mgr: None,
            permission_mgr: &permission_manager,
            authorization: None,
            session_id: Some("readonly-session"),
            policy_enforcer: None,
        });

        assert!(result.is_error());
        assert!(matches!(
            result.outcome(),
            crate::tools::ToolOutcome::Error { failure }
                if failure.code == ToolFailureCode::PolicyDenied
        ));
        assert!(result.content().contains("denies tool 'bash'"));
        assert!(!result.content().contains("runtime-mode-should-not-run"));
    }

    #[test]
    fn tool_executor_consumes_exact_permit_without_nested_permission() {
        let call = bash_call("printf tool-executor-ok");
        let manager = PermissionManager::unrestricted();
        let permit = manager
            .approve_tool_call_once(
                &call,
                Some("s2"),
                crate::permissions::ApprovalProvenance::InteractiveUser,
            )
            .expect("mint permit");

        let result = ToolExecutor::execute(ToolExecutorRequest {
            run_context: test_run(),
            tool_call: &call,
            memory_db: None,
            app_config: None,
            task_mgr: None,
            permission_mgr: &manager,
            authorization: Some(permit),
            session_id: Some("s2"),
            policy_enforcer: None,
        });

        assert!(!result.is_error(), "unexpected error: {}", result.content());
        assert!(result.content().contains("tool-executor-ok"));
    }

    #[test]
    fn permission_denial_does_not_consume_enterprise_tool_cap() {
        let mut caps = ToolCaps::new();
        caps.insert("bash".to_string(), 1);
        let enforcer = PolicyEnforcer::new(EnterprisePolicy {
            tool_caps: caps,
            ..Default::default()
        });
        let dir = tempfile::tempdir().expect("tempdir");
        let strict = PermissionManager::new(dir.path().join("permissions.json"), true, Vec::new());
        let call = bash_call("printf permission-cap-order");

        let denied = ToolExecutor::execute(ToolExecutorRequest {
            run_context: test_run(),
            tool_call: &call,
            memory_db: None,
            app_config: None,
            task_mgr: None,
            permission_mgr: &strict,
            authorization: None,
            session_id: Some("cap-session"),
            policy_enforcer: Some(&enforcer),
        });
        assert!(denied.is_error());
        assert!(denied.content().contains("Permission denied"));
        assert!(
            enforcer.check_tool("cap-session", "bash").is_ok(),
            "a permission denial must leave the execution cap available"
        );

        let unrestricted = PermissionManager::unrestricted();
        let allowed = ToolExecutor::execute(ToolExecutorRequest {
            run_context: test_run(),
            tool_call: &call,
            memory_db: None,
            app_config: None,
            task_mgr: None,
            permission_mgr: &unrestricted,
            authorization: None,
            session_id: Some("cap-session"),
            policy_enforcer: Some(&enforcer),
        });
        assert!(
            !allowed.is_error(),
            "unexpected result: {}",
            allowed.content()
        );
        assert!(enforcer.check_tool("cap-session", "bash").is_err());
    }

    #[test]
    fn tool_executor_rejects_permit_when_exact_arguments_change() {
        let dir = tempfile::tempdir().expect("tempdir");
        let approved_path = dir.path().join("approved.txt");
        let changed_path = dir.path().join("changed.txt");
        let approved = ToolCall {
            id: "same-call-id".to_string(),
            call_type: "function".to_string(),
            function: crate::tools::FunctionCall {
                name: "write_file".to_string(),
                arguments: serde_json::json!({
                    "path": approved_path,
                    "content": "approved"
                })
                .to_string(),
            },
        };
        let changed = ToolCall {
            id: approved.id.clone(),
            call_type: "function".to_string(),
            function: crate::tools::FunctionCall {
                name: "write_file".to_string(),
                arguments: serde_json::json!({
                    "path": changed_path,
                    "content": "changed"
                })
                .to_string(),
            },
        };
        let manager = PermissionManager::unrestricted();
        let permit = manager
            .approve_tool_call_once(
                &approved,
                Some("s3"),
                crate::permissions::ApprovalProvenance::InteractiveUser,
            )
            .expect("mint permit");

        let result = ToolExecutor::execute(ToolExecutorRequest {
            run_context: test_run(),
            tool_call: &changed,
            memory_db: None,
            app_config: None,
            task_mgr: None,
            permission_mgr: &manager,
            authorization: Some(permit),
            session_id: Some("s3"),
            policy_enforcer: None,
        });

        assert!(result.is_error());
        assert!(result.content().contains("execution permit rejected"));
        assert!(!dir.path().join("approved.txt").exists());
        assert!(!dir.path().join("changed.txt").exists());
    }

    #[test]
    fn tool_executor_preserves_typed_invalid_arguments_before_permission_classification() {
        let call = ToolCall {
            id: "invalid-array".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "list_files".to_string(),
                arguments: "[]".to_string(),
            },
        };
        let manager = PermissionManager::unrestricted();

        let result = ToolExecutor::execute(ToolExecutorRequest {
            run_context: test_run(),
            tool_call: &call,
            memory_db: None,
            app_config: None,
            task_mgr: None,
            permission_mgr: &manager,
            authorization: None,
            session_id: None,
            policy_enforcer: None,
        });

        assert!(result.is_error());
        assert!(matches!(
            result.outcome(),
            crate::tools::ToolOutcome::Error { failure }
                if failure.code == ToolFailureCode::InvalidArguments
                    && failure.retryability == ToolRetryability::Never
        ));
        assert!(result.content().contains("expected a JSON object"));
    }

    #[test]
    fn tool_executor_reserves_the_shared_run_budget_before_dispatch() {
        let run = one_tool_run();
        let manager = PermissionManager::unrestricted_for_run(&run);
        let first = bash_call("printf first");
        let first_result = ToolExecutor::execute(ToolExecutorRequest {
            run_context: &run,
            tool_call: &first,
            memory_db: None,
            app_config: None,
            task_mgr: None,
            permission_mgr: &manager,
            authorization: None,
            session_id: None,
            policy_enforcer: None,
        });
        assert!(!first_result.is_error(), "{}", first_result.content());

        let second = bash_call("printf second-should-not-run");
        let second_result = ToolExecutor::execute(ToolExecutorRequest {
            run_context: &run,
            tool_call: &second,
            memory_db: None,
            app_config: None,
            task_mgr: None,
            permission_mgr: &manager,
            authorization: None,
            session_id: None,
            policy_enforcer: None,
        });
        assert!(second_result.is_error());
        assert!(second_result
            .content()
            .contains("Run budget denied tool dispatch"));
        assert!(!second_result.content().contains("second-should-not-run"));
    }
}
