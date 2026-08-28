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

/// Inputs for admitting an owned speculative read through the same policy,
/// authorization, accounting, and typed-result boundary as an ordinary local
/// tool invocation before its receipt may be joined and validated.
pub(crate) struct PrecomputedReadRequest<'a> {
    pub(crate) run_context: &'a std::sync::Arc<tools::ToolRunContext>,
    pub(crate) tool_call: &'a ToolCall,
    pub(crate) handle: crate::speculation::SpeculationHandle,
    pub(crate) memory_db: Option<&'a MemoryDb>,
    pub(crate) app_config: Option<&'a AppConfig>,
    pub(crate) permission_mgr: &'a PermissionManager,
    pub(crate) authorization: Option<ExecutionPermit>,
    pub(crate) session_id: Option<&'a str>,
    pub(crate) policy_enforcer: Option<&'a PolicyEnforcer>,
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
        let _workspace_operation = match run_context.begin_workspace_operation() {
            Ok(guard) => guard,
            Err(error) => {
                return ToolResult::failure(
                    tool_call,
                    ToolFailureCode::Unavailable,
                    format!("Workspace generation is unavailable: {error}"),
                    ToolRetryability::Safe,
                )
            }
        };

        if let Err(reason) = run_context
            .tool_catalog()
            .admit_tool_call(run_context, &tool_call.function.name)
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

        let _ledger_guard = crate::grounded_loop::install_active_project_ledger_for_session(
            run_context,
            run_context.evidence_session_key(),
        );

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

        let pre_commit_report = if tool_requests_git_commit(&tool_call.function.name, &arguments) {
            crate::guardrails::run_bound_quality_gates_at(
                run_context,
                crate::config::RunAfter::OnCommit,
            )
        } else {
            None
        };
        if let Some(report) = &pre_commit_report {
            record_quality_gate_report(run_context, session_id, report);
            if report.prevents_progress() {
                return ToolResult::failure(
                    tool_call,
                    ToolFailureCode::PolicyDenied,
                    quality_gate_report_message(report, "Git commit blocked"),
                    ToolRetryability::Safe,
                );
            }
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
        let diff_revision_before = crate::guardrails::diff_revision(run_context);
        let mut result = tools::execute_tool_after_authorization(
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
        if let Some(report) = pre_commit_report {
            result = attach_quality_gate_report(result, &report);
        }
        if crate::guardrails::diff_revision(run_context) != diff_revision_before {
            if let Some(report) = crate::guardrails::run_bound_quality_gates_at(
                run_context,
                crate::config::RunAfter::EveryEdit,
            ) {
                record_quality_gate_report(run_context, session_id, &report);
                result = attach_quality_gate_report(result, &report);
            }
        }
        result
    }

    /// Admit, validate, and conditionally commit a `read_file` snapshot without
    /// repeating its render, while preserving every ordinary dispatch gate and
    /// accounting effect. Invalid receipts fall back to the demand handler.
    #[must_use]
    #[allow(clippy::too_many_lines)] // Mirrors the canonical admission transaction before receipt reuse.
    pub(crate) fn execute_precomputed_read(request: PrecomputedReadRequest<'_>) -> ToolResult {
        let PrecomputedReadRequest {
            run_context,
            tool_call,
            handle,
            memory_db,
            app_config,
            permission_mgr,
            authorization,
            session_id,
            policy_enforcer,
        } = request;
        let session_id = session_id.or_else(|| Some(run_context.session_id()));
        let _workspace_operation = match run_context.begin_workspace_operation() {
            Ok(guard) => guard,
            Err(error) => {
                return ToolResult::failure(
                    tool_call,
                    ToolFailureCode::Unavailable,
                    format!("Workspace generation is unavailable: {error}"),
                    ToolRetryability::Safe,
                );
            }
        };
        if tool_call.function.name != "read_file" {
            return ToolResult::failure(
                tool_call,
                ToolFailureCode::Internal,
                "A speculative read receipt cannot execute another tool".to_string(),
                ToolRetryability::Never,
            );
        }
        if let Err(reason) = run_context
            .tool_catalog()
            .admit_tool_call(run_context, &tool_call.function.name)
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
                    );
                }
            };
        let resolved = match tools::host_safety::HostSafetyPolicy::enforce(
            &tool_call.function.name,
            &arguments,
        ) {
            Ok(resolved) if resolved.effect == tools::effect::ToolEffect::ReadOnly => resolved,
            Ok(_) => {
                return ToolResult::failure(
                    tool_call,
                    ToolFailureCode::PolicyDenied,
                    "Speculation requires an explicitly classified read-only invocation"
                        .to_string(),
                    ToolRetryability::Never,
                );
            }
            Err(reason) => {
                return ToolResult::failure(
                    tool_call,
                    ToolFailureCode::PolicyDenied,
                    format!("Blocked by non-bypassable host safety: {reason}"),
                    ToolRetryability::Never,
                );
            }
        };
        if let Err(reason) =
            run_context.admit_runtime_mode_resolved(&tool_call.function.name, &resolved, &arguments)
        {
            return ToolResult::failure(
                tool_call,
                ToolFailureCode::PolicyDenied,
                reason,
                ToolRetryability::Never,
            );
        }
        let tool_policy = ToolExecutionPolicy::new(policy_enforcer, session_id);
        if let Err(error) = tool_policy.check_tool(&tool_call.function.name) {
            return ToolResult::failure(
                tool_call,
                ToolFailureCode::PolicyDenied,
                format!("Blocked by policy: {error}"),
                ToolRetryability::Never,
            );
        }
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
        if let Err(error) = tool_policy.check_and_record_tool(&tool_call.function.name) {
            return ToolResult::failure(
                tool_call,
                ToolFailureCode::PolicyDenied,
                format!("Blocked by policy: {error}"),
                ToolRetryability::Never,
            );
        }
        let budget_reservation = match run_context.budget().reserve(BudgetAmounts {
            tool_calls: 1,
            concurrent_calls: 1,
            ..BudgetAmounts::default()
        }) {
            Ok(reservation) => reservation,
            Err(error) => return budget_denied_tool_result(tool_call, &error),
        };
        let _ledger_guard = crate::grounded_loop::install_active_project_ledger_for_session(
            run_context,
            run_context.evidence_session_key(),
        );
        let result = handle.consume(run_context, tool_call).map_or_else(
            || {
                tools::execute_tool_after_authorization(
                    run_context,
                    tool_call,
                    memory_db,
                    app_config,
                    None,
                    Some(&consumed_authorization),
                )
            },
            |artifact| {
                let handler_result =
                    match tools::file::commit_speculative_read(run_context, artifact) {
                        Ok(result) => result,
                        Err(error) => tools::ToolHandlerResult::error(tools::ToolFailure::new(
                            ToolFailureCode::Conflict,
                            error,
                            ToolRetryability::Safe,
                        )),
                    };
                let result = ToolResult::bind(tool_call, "read_file", handler_result);
                tools::attach_automatic_learning(run_context, memory_db, app_config, None, result)
            },
        );
        if let Err(error) = budget_reservation.commit() {
            return budget_accounting_failure(tool_call, &error);
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
        let _workspace_operation = match run_context.begin_workspace_operation() {
            Ok(guard) => guard,
            Err(error) => {
                return ToolResult::failure(
                    tool_call,
                    ToolFailureCode::Unavailable,
                    format!("Workspace generation is unavailable: {error}"),
                    ToolRetryability::Safe,
                )
            }
        };
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
        let diff_revision_before = crate::guardrails::diff_revision(run_context);
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
            Ok(value) => mcp_handler_result(value),
            Err(error) => mcp_error_result(
                &error,
                remotely_dispatched.load(std::sync::atomic::Ordering::Acquire),
            ),
        };
        let result = ToolResult::bind(tool_call, &tool_call.function.name, handler_result);
        let mut result =
            tools::attach_automatic_learning(run_context, memory_db, app_config, None, result);
        if let Err(error) = budget_reservation.commit() {
            return budget_accounting_failure(tool_call, &error);
        }
        if crate::guardrails::diff_revision(run_context) != diff_revision_before {
            if let Some(report) = crate::guardrails::run_bound_quality_gates_at(
                run_context,
                crate::config::RunAfter::EveryEdit,
            ) {
                record_quality_gate_report(run_context, session_id, &report);
                result = attach_quality_gate_report(result, &report);
            }
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

fn tool_requests_git_commit(tool_name: &str, arguments: &Value) -> bool {
    if tool_name == "exit_worktree" {
        return arguments
            .get("operation")
            .and_then(Value::as_str)
            .is_some_and(|operation| operation == "commit")
            || arguments
                .get("apply_changes")
                .and_then(Value::as_bool)
                .unwrap_or(false);
    }
    if tool_name != "bash" {
        return false;
    }
    let Some(command) = arguments.get("command").and_then(Value::as_str) else {
        return false;
    };
    let Some(argv) = shlex::split(command) else {
        return false;
    };
    argv.iter().enumerate().any(|(index, token)| {
        std::path::Path::new(token)
            .file_name()
            .is_some_and(|name| name == "git")
            && argv[index.saturating_add(1)..]
                .iter()
                .any(|candidate| candidate == "commit")
    })
}

fn quality_gate_report_message(
    report: &crate::guardrails::QualityGateReport,
    prefix: &str,
) -> String {
    let failures = report
        .results()
        .iter()
        .filter(|result| !result.passed())
        .map(|result| format!("{} ({:?})", result.name(), result.status()))
        .collect::<Vec<_>>();
    let detail = report
        .reason()
        .map_or_else(|| failures.join(", "), ToString::to_string);
    format!("{prefix} by configured quality gates: {detail}")
}

fn record_quality_gate_report(
    run: &crate::tools::ToolRunContext,
    session_id: Option<&str>,
    report: &crate::guardrails::QualityGateReport,
) {
    let Some(session_id) = session_id else {
        return;
    };
    let mut ledger =
        match crate::ledger::RealityLedger::open_project_session_for_run(run, session_id) {
            Ok(ledger) => ledger,
            Err(error) => {
                tracing::warn!(session_id, %error, "failed to open quality-gate ledger");
                return;
            }
        };
    for gate in report.results() {
        if let Err(error) =
            crate::grounded_loop::append_quality_gate_observations(run, &mut ledger, gate)
        {
            tracing::warn!(session_id, gate = %gate.name(), %error, "failed to record quality gate");
        }
    }
}

fn attach_quality_gate_report(
    result: ToolResult,
    report: &crate::guardrails::QualityGateReport,
) -> ToolResult {
    if report.disposition() == crate::guardrails::QualityGateDisposition::Skipped {
        return result;
    }
    let message = quality_gate_report_message(report, "Quality gate outcome");
    let mut result = result.with_observation(tools::ToolObservation {
        kind: "quality_gate".to_string(),
        authoritative: true,
        data: serde_json::json!({
            "cadence": report.cadence().to_string(),
            "action": report.action().to_string(),
            "disposition": format!("{:?}", report.disposition()).to_ascii_lowercase(),
            "message": message,
        }),
    });
    if report.disposition() == crate::guardrails::QualityGateDisposition::Blocked {
        result = result.with_postcondition_failure(tools::ToolFailure::new(
            ToolFailureCode::PolicyDenied,
            message,
            ToolRetryability::Safe,
        ));
    }
    result
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
        .admit_tool_call_with_receipt(request.run_context, &request.tool_call.function.name)
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

fn mcp_handler_result(value: Value) -> tools::ToolHandlerResult {
    let Ok(typed) = serde_json::from_value::<crate::mcp::McpCallToolResult>(value.clone()) else {
        return tools::ToolHandlerResult::success_structured(
            "MCP tool completed with structured output.",
            value,
        );
    };
    let text = typed
        .content
        .iter()
        .filter_map(|block| match block {
            crate::mcp::McpContentBlock::Text { text, .. }
            | crate::mcp::McpContentBlock::Resource {
                resource: crate::mcp::McpResourceContents::Text { text, .. },
                ..
            } => Some(text.clone()),
            crate::mcp::McpContentBlock::ResourceLink { uri, name, .. } => {
                Some(format!("MCP resource {name}: {uri}"))
            }
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");
    if text.is_empty() {
        let result = tools::ToolHandlerResult::success_structured(
            "MCP tool completed with structured output.",
            value,
        );
        attach_mcp_media(result, &typed)
    } else {
        let result = tools::ToolHandlerResult::success_structured(text, value);
        attach_mcp_media(result, &typed)
    }
}

fn attach_mcp_media(
    mut result: tools::ToolHandlerResult,
    typed: &crate::mcp::McpCallToolResult,
) -> tools::ToolHandlerResult {
    use base64::Engine as _;

    for block in &typed.content {
        let Some((encoded, media_type)) = block.encoded_media() else {
            continue;
        };
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            continue;
        };
        if let Ok(attachment) = tools::register_transient_attachment(
            media_type,
            bytes,
            tools::ToolSensitivity::Workspace,
        ) {
            result = result.with_attachment(attachment);
        }
    }
    result
}

fn mcp_error_result(
    error: &crate::mcp::McpError,
    remotely_dispatched: bool,
) -> tools::ToolHandlerResult {
    let (code, retryability) = match error {
        crate::mcp::McpError::InvalidToolArguments { .. }
        | crate::mcp::McpError::RequestTooLarge { .. } => {
            (ToolFailureCode::InvalidArguments, ToolRetryability::Never)
        }
        crate::mcp::McpError::ToolNotAllowed { .. } | crate::mcp::McpError::Capability(_) => {
            (ToolFailureCode::PolicyDenied, ToolRetryability::Never)
        }
        crate::mcp::McpError::Timeout { .. } | crate::mcp::McpError::Cancelled { .. } => (
            ToolFailureCode::DeadlineExceeded,
            ToolRetryability::AfterBackoff,
        ),
        crate::mcp::McpError::ToolReportedError { .. }
        | crate::mcp::McpError::Transport(_)
        | crate::mcp::McpError::Protocol(_)
        | crate::mcp::McpError::Rpc { .. }
        | crate::mcp::McpError::HttpStatus { .. }
        | crate::mcp::McpError::OAuth(_)
        | crate::mcp::McpError::ResponseTooLarge { .. }
        | crate::mcp::McpError::ResponseIdMismatch { .. }
        | crate::mcp::McpError::Io(_) => (ToolFailureCode::External, ToolRetryability::Unknown),
        crate::mcp::McpError::ServerUnreachable(_)
        | crate::mcp::McpError::Backpressure { .. }
        | crate::mcp::McpError::ConnectionClosed(_) => {
            (ToolFailureCode::Unavailable, ToolRetryability::AfterBackoff)
        }
        crate::mcp::McpError::ToolNotFound(_)
        | crate::mcp::McpError::NotConnected(_)
        | crate::mcp::McpError::StaleToolRegistration(_)
        | crate::mcp::McpError::StaleConnectionGeneration { .. }
        | crate::mcp::McpError::StaleRunGeneration { .. }
        | crate::mcp::McpError::UnsupportedProtocolVersion { .. }
        | crate::mcp::McpError::UnsupportedCapability(_)
        | crate::mcp::McpError::AuthorizationRequired(_)
        | crate::mcp::McpError::InvalidToolSchema { .. } => {
            (ToolFailureCode::Unavailable, ToolRetryability::Safe)
        }
    };
    let mut failure = tools::ToolFailure::new(code, error.to_string(), retryability);
    if let crate::mcp::McpError::Rpc {
        code,
        message,
        data,
        http_status,
    } = error
    {
        failure.recovery = Some(serde_json::json!({
            "protocol": "mcp-json-rpc-2.0",
            "code": code,
            "message": message,
            "data": data,
            "http_status": http_status,
        }));
    }
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
    use crate::config::{
        DiffMonitorConfig, GuardrailAction, GuardrailsConfig, QualityCheck, QualityGatesConfig,
        RunAfter,
    };
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

    fn write_call(path: &std::path::Path, content: &str) -> ToolCall {
        ToolCall {
            id: "call_write".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "write_file".to_string(),
                arguments: serde_json::json!({ "path": path, "content": content }).to_string(),
            },
        }
    }

    fn isolated_run() -> (
        tempfile::TempDir,
        std::sync::Arc<crate::tools::ToolRunContext>,
    ) {
        let root = tempfile::tempdir().expect("root");
        let run = crate::tools::security::test_run_context_for(root.path());
        (root, run)
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
    fn authoritative_tool_observations_use_the_run_evidence_bucket() {
        let root = tempfile::tempdir().expect("root");
        let artifact = root.path().join("artifact.txt");
        std::fs::write(&artifact, "reviewed artifact\n").expect("artifact fixture");
        let evidence_key = "verifier-evidence-bucket";
        let run =
            crate::tools::ToolRunContext::builder(crate::state::SessionId::new(), root.path())
                .working_directory(root.path())
                .read_only_roots(Vec::new())
                .read_write_roots(Vec::new())
                .environment_grants(std::collections::HashMap::new())
                .workspace_access(crate::tools::WorkspaceAccess::ReadOnly)
                .process(false)
                .network(false)
                .secrets(false)
                .provider("test")
                .evidence_session_key(evidence_key)
                .build()
                .expect("run");
        let call = ToolCall {
            id: "call_read".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "read_file".to_string(),
                arguments: serde_json::json!({ "path": artifact }).to_string(),
            },
        };
        let manager = PermissionManager::unrestricted();

        let result = ToolExecutor::execute(ToolExecutorRequest {
            run_context: &run,
            tool_call: &call,
            memory_db: None,
            app_config: None,
            task_mgr: None,
            permission_mgr: &manager,
            authorization: None,
            session_id: Some("different-logical-session"),
            policy_enforcer: None,
        });

        assert!(
            !result.is_error(),
            "unexpected result: {}",
            result.content()
        );
        let ledger = crate::ledger::RealityLedger::open_project_session_for_run(&run, evidence_key)
            .expect("evidence ledger");
        assert!(ledger
            .observations_chronological()
            .iter()
            .any(|observation| {
                matches!(
                    &observation.kind,
                    crate::ledger::ObservationKind::FileRead { path, .. }
                        if path == &artifact.display().to_string()
                )
            }));
    }

    #[test]
    fn s065_mcp_result_keeps_structured_content_and_native_media() {
        let wire = serde_json::json!({
            "resultType": "complete",
            "content": [
                {"type": "text", "text": "visible text"},
                {"type": "image", "data": "aGVsbG8=", "mimeType": "image/png"},
                {"type": "audio", "data": "d29ybGQ=", "mimeType": "audio/wav"},
                {
                    "type": "resource",
                    "resource": {"uri": "fixture://note", "text": "embedded text"}
                },
                {
                    "type": "resource_link",
                    "uri": "fixture://more",
                    "name": "more"
                }
            ],
            "structuredContent": {"answer": 42}
        });

        let result = mcp_handler_result(wire.clone());
        assert_eq!(
            result.content(),
            "visible text\nembedded text\nMCP resource more: fixture://more"
        );
        assert!(matches!(
            &result.outcome,
            crate::tools::ToolOutcome::Success { content }
                if content.structured.as_ref() == Some(&wire)
        ));
        assert_eq!(result.attachments.len(), 2);

        let metadata = serde_json::to_value(&result.attachments).expect("attachment metadata");
        let resolved = crate::tools::resolve_tool_attachments(Some(&metadata))
            .expect("provider-ready MCP media");
        assert_eq!(resolved[0].media_type, "image/png");
        assert_eq!(&*resolved[0].bytes, b"hello");
        assert_eq!(resolved[1].media_type, "audio/wav");
        assert_eq!(&*resolved[1].bytes, b"world");
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
        let targets = crate::modes::BehaviorScopeTargets::from_user_values(
            run.project_root(),
            run.working_directory(),
            &[".".to_string()],
        )
        .expect("explicit explore target");
        run.transition_runtime_mode_scoped(
            crate::modes::RuntimeMode::Behavioral(crate::modes::BehaviorMode::from_preset(
                crate::modes::Preset::Explore,
            )),
            targets,
        )
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
        let run = test_run();
        let dir = tempfile::Builder::new()
            .prefix("permit-mismatch-")
            .tempdir_in(run.project_root())
            .expect("workspace tempdir");
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
            run_context: run,
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

    #[test]
    fn diff_block_rejects_write_before_publication() {
        let (_root, run) = isolated_run();
        crate::guardrails::configure(
            &run,
            &GuardrailsConfig {
                diff_monitor: Some(DiffMonitorConfig {
                    enabled: true,
                    max_lines_changed: 1,
                    max_files_changed: 0,
                    action: GuardrailAction::Block,
                }),
                ..GuardrailsConfig::default()
            },
        )
        .expect("configure diff block");
        let path = run.project_root().join("blocked.txt");
        let call = write_call(&path, "one\ntwo\n");
        let manager = PermissionManager::unrestricted_for_run(&run);

        let result = ToolExecutor::execute(ToolExecutorRequest {
            run_context: &run,
            tool_call: &call,
            memory_db: None,
            app_config: None,
            task_mgr: None,
            permission_mgr: &manager,
            authorization: None,
            session_id: None,
            policy_enforcer: None,
        });

        assert!(result.is_error(), "unexpected result: {}", result.content());
        assert!(result.content().contains("Diff size threshold exceeded"));
        assert!(!path.exists(), "blocked bytes must never be published");
    }

    #[test]
    fn every_edit_quality_gate_runs_without_diff_monitor() {
        let (_root, run) = isolated_run();
        crate::guardrails::configure(
            &run,
            &GuardrailsConfig {
                quality_gates: Some(QualityGatesConfig {
                    enabled: true,
                    run_after: RunAfter::EveryEdit,
                    fail_action: GuardrailAction::Block,
                    checks: vec![QualityCheck {
                        name: "reject-edit".to_string(),
                        command: "false".to_string(),
                        required: true,
                    }],
                    timeout_seconds: 30,
                }),
                ..GuardrailsConfig::default()
            },
        )
        .expect("configure every-edit quality gate");
        crate::guardrails::bind_quality_gate_model(&run, "test-model").expect("bind model");
        let path = run.project_root().join("edited.txt");
        let call = write_call(&path, "published\n");
        let manager = PermissionManager::unrestricted_for_run(&run);

        let result = ToolExecutor::execute(ToolExecutorRequest {
            run_context: &run,
            tool_call: &call,
            memory_db: None,
            app_config: None,
            task_mgr: None,
            permission_mgr: &manager,
            authorization: None,
            session_id: None,
            policy_enforcer: None,
        });

        assert!(path.exists(), "the gate runs after successful publication");
        assert!(result.is_partial(), "unexpected result: {result:?}");
        assert!(result
            .observations()
            .iter()
            .any(|observation| observation.kind == "quality_gate"));
        assert_eq!(crate::guardrails::diff_revision(&run), 1);
    }

    #[test]
    fn on_commit_quality_gate_blocks_before_command_dispatch() {
        let (_root, run) = isolated_run();
        crate::guardrails::configure(
            &run,
            &GuardrailsConfig {
                quality_gates: Some(QualityGatesConfig {
                    enabled: true,
                    run_after: RunAfter::OnCommit,
                    fail_action: GuardrailAction::Block,
                    checks: vec![QualityCheck {
                        name: "reject-commit".to_string(),
                        command: "false".to_string(),
                        required: true,
                    }],
                    timeout_seconds: 30,
                }),
                ..GuardrailsConfig::default()
            },
        )
        .expect("configure on-commit quality gate");
        crate::guardrails::bind_quality_gate_model(&run, "test-model").expect("bind model");
        let call = bash_call("git commit");
        let manager = PermissionManager::unrestricted_for_run(&run);

        let result = ToolExecutor::execute(ToolExecutorRequest {
            run_context: &run,
            tool_call: &call,
            memory_db: None,
            app_config: None,
            task_mgr: None,
            permission_mgr: &manager,
            authorization: None,
            session_id: None,
            policy_enforcer: None,
        });

        assert!(result.is_error(), "unexpected result: {}", result.content());
        assert!(result.content().contains("Git commit blocked"));
        assert!(!result.content().contains("not a git repository"));
    }

    #[test]
    fn worktree_apply_changes_is_a_commit_boundary() {
        assert!(tool_requests_git_commit(
            "exit_worktree",
            &serde_json::json!({
                "path": "/tmp/worktree",
                "operation": "commit",
                "expected_generation": format!("sha256:{}", "0".repeat(64)),
                "message": "reviewed change"
            })
        ));
        assert!(tool_requests_git_commit(
            "exit_worktree",
            &serde_json::json!({ "path": "/tmp/worktree", "apply_changes": true })
        ));
        assert!(!tool_requests_git_commit(
            "exit_worktree",
            &serde_json::json!({ "path": "/tmp/worktree", "operation": "discard" })
        ));
    }
}
