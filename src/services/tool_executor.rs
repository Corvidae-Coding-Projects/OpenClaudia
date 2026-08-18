//! Shared local tool execution service.
//!
//! This centralizes the common "run an `OpenClaudia` tool locally" mechanics
//! that were duplicated across TUI, legacy REPL, ACP local tools, and subagents:
//! optional enterprise tool cap, session id guard,
//! active ledger installation, permission checked-vs-unchecked dispatch, and
//! task-manager-aware execution.

use crate::config::AppConfig;
use crate::file_types::extensions_from_tool_input;
use crate::hooks::{HookEngine, HookError, HookEvent, HookInput};
use crate::memory::MemoryDb;
use crate::permissions::PermissionManager;
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
    /// Tool call to execute.
    pub tool_call: &'a ToolCall,
    /// Optional memory database for memory tools.
    pub memory_db: Option<&'a MemoryDb>,
    /// Optional app config for subagent tools.
    pub app_config: Option<&'a AppConfig>,
    /// Optional task manager for task_* tools.
    pub task_mgr: Option<&'a mut TaskManager>,
    /// Permission manager to consult when `permission_already_checked` is false.
    pub permission_mgr: Option<&'a PermissionManager>,
    /// Set true when an outer interactive prompt already made the permission
    /// decision and the dispatcher should not prompt/check again.
    pub permission_already_checked: bool,
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
        hook_engine: &HookEngine,
        session_id: Option<&str>,
        tool_name: &str,
        tool_input: &Value,
    ) -> Result<(), ToolExecutionBlock> {
        let extensions = extensions_from_tool_input(tool_name, tool_input);

        let mut hook_input =
            HookInput::new(HookEvent::PreToolUse).with_tool(tool_name, tool_input.clone());
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
        hook_engine: &HookEngine,
        success: bool,
        tool_name: &str,
        tool_input: Value,
        tool_output: &str,
        session_id: Option<&str>,
    ) {
        hook_engine
            .fire_post_tool(success, tool_name, tool_input, tool_output, session_id)
            .await;
    }

    /// Append a bounded tool-result observation to the active session ledger.
    pub fn observe_tool_result(session_id: Option<&str>, tool_name: &str, result: &ToolResult) {
        if let Some(session_id) = session_id {
            crate::grounded_loop::observe_tool_result_for_session(session_id, tool_name, result);
        }
    }

    /// Execute a local tool call.
    ///
    /// # Errors
    ///
    /// Tool failures are returned inside [`ToolResult::is_error`], matching the
    /// historical dispatcher contract.
    #[must_use]
    pub fn execute(request: ToolExecutorRequest<'_>) -> ToolResult {
        let ToolExecutorRequest {
            tool_call,
            memory_db,
            app_config,
            task_mgr,
            permission_mgr,
            permission_already_checked,
            session_id,
            policy_enforcer,
        } = request;

        let tool_policy = ToolExecutionPolicy::new(policy_enforcer, session_id);
        if let Err(err) = tool_policy.check_and_record_tool(&tool_call.function.name) {
            return ToolResult::failure(
                tool_call,
                ToolFailureCode::PolicyDenied,
                format!("Blocked by policy: {err}"),
                ToolRetryability::Never,
            );
        }

        let _session_guard = session_id.map(tools::SessionIdGuard::set);
        let _ledger_guard =
            session_id.and_then(crate::grounded_loop::install_active_project_ledger_for_session);

        if permission_already_checked {
            tools::execute_tool_with_tasks_unchecked(tool_call, memory_db, app_config, task_mgr)
        } else {
            tools::execute_tool_with_tasks(
                tool_call,
                memory_db,
                app_config,
                task_mgr,
                permission_mgr,
            )
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::policy::{EnterprisePolicy, PolicyEnforcer, ToolCaps};
    use crate::tools::{FunctionCall, ToolCall};

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

    #[test]
    fn tool_executor_enforces_policy_before_dispatch() {
        let mut caps = ToolCaps::new();
        caps.insert("bash".to_string(), 0);
        let enforcer = PolicyEnforcer::new(EnterprisePolicy {
            tool_caps: caps,
            ..Default::default()
        });
        let call = bash_call("printf tool-executor-should-not-run");

        let result = ToolExecutor::execute(ToolExecutorRequest {
            tool_call: &call,
            memory_db: None,
            app_config: None,
            task_mgr: None,
            permission_mgr: None,
            permission_already_checked: false,
            session_id: Some("s1"),
            policy_enforcer: Some(&enforcer),
        });

        assert!(result.is_error());
        assert!(result.content().contains("Blocked by policy"));
        assert!(!result.content().contains("tool-executor-should-not-run"));
    }

    #[test]
    fn tool_executor_uses_checked_dispatch_without_nested_permission() {
        let call = bash_call("printf tool-executor-ok");

        let result = ToolExecutor::execute(ToolExecutorRequest {
            tool_call: &call,
            memory_db: None,
            app_config: None,
            task_mgr: None,
            permission_mgr: None,
            permission_already_checked: true,
            session_id: Some("s2"),
            policy_enforcer: None,
        });

        assert!(!result.is_error(), "unexpected error: {}", result.content());
        assert!(result.content().contains("tool-executor-ok"));
    }
}
