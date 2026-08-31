use serde_json::Value;
use std::collections::HashMap;

use super::{
    ToolAllowedPrompt, ToolFailure, ToolFailureCode, ToolFollowUp, ToolFollowUpState,
    ToolHandlerResult, ToolRetryability,
};

/// Execute the `enter_plan_mode` tool.
///
/// Returns a trusted typed follow-up requesting activation only for a
/// top-level frontend run. Worker and other non-frontend actors receive a
/// typed failure. The decision comes from the immutable run descriptor rather
/// than thread-local execution state (crosslink #620, S-019).
pub fn execute_enter_plan_mode(run: &crate::tools::security::ToolRunContext) -> ToolHandlerResult {
    if run.runtime().descriptor().actor.role != crate::runtime::ActorRole::Frontend {
        return ToolHandlerResult::error(ToolFailure::new(
            ToolFailureCode::InvalidInput,
            "plan mode cannot be entered from inside an agent task".to_string(),
            ToolRetryability::Never,
        ));
    }
    ToolHandlerResult::success_text("Plan mode entry requested".to_string()).with_follow_up(
        ToolFollowUp::EnterPlanMode {
            state: ToolFollowUpState::Pending,
        },
    )
}

/// Execute the `exit_plan_mode` tool.
/// Returns a trusted typed follow-up that frontends use to show the plan for
/// approval.
///
/// Perimeter defense: `allowed_prompts`, when present, MUST be a JSON array.
/// Earlier versions used `as_array().cloned().unwrap_or_default()` which
/// silently swallowed type errors — passing `allowed_prompts: "Bash"` would
/// be treated identically to an absent field, masking model mistakes
/// (crosslink #933). Now the wrong container shape is a hard error.
pub fn execute_exit_plan_mode(args: &HashMap<String, Value>) -> ToolHandlerResult {
    let allowed_prompts: Vec<Value> = match args.get("allowed_prompts") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(arr)) => arr.clone(),
        Some(other) => {
            let kind = match other {
                Value::String(_) => "string",
                Value::Bool(_) => "boolean",
                Value::Number(_) => "number",
                Value::Object(_) => "object",
                Value::Array(_) | Value::Null => unreachable!(),
            };
            return invalid_exit(format!("allowed_prompts must be an array, got {kind}"));
        }
    };

    // Validate allowed_prompts structure
    for (i, prompt) in allowed_prompts.iter().enumerate() {
        if !prompt.is_object() {
            return invalid_exit(format!(
                "allowed_prompts[{i}] must be an object with 'tool' and 'prompt' fields"
            ));
        }
        if prompt.get("tool").and_then(|v| v.as_str()).is_none() {
            return invalid_exit(format!("allowed_prompts[{i}] missing 'tool' field"));
        }
        if prompt.get("prompt").and_then(|v| v.as_str()).is_none() {
            return invalid_exit(format!("allowed_prompts[{i}] missing 'prompt' field"));
        }
    }

    let allowed_prompts = allowed_prompts
        .into_iter()
        .map(|prompt| ToolAllowedPrompt {
            tool: prompt["tool"]
                .as_str()
                .expect("validated allowed prompt tool")
                .to_string(),
            prompt: prompt["prompt"]
                .as_str()
                .expect("validated allowed prompt description")
                .to_string(),
        })
        .collect();
    ToolHandlerResult::success_text("Plan mode exit requested".to_string()).with_follow_up(
        ToolFollowUp::ExitPlanMode {
            allowed_prompts,
            state: ToolFollowUpState::Pending,
        },
    )
}

fn invalid_exit(message: String) -> ToolHandlerResult {
    ToolHandlerResult::error(ToolFailure::new(
        ToolFailureCode::InvalidArguments,
        message,
        ToolRetryability::Never,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn frontend_run() -> &'static crate::tools::security::ToolRunContext {
        crate::tools::security::test_run_context().as_ref()
    }

    fn worker_run() -> &'static crate::tools::security::ToolRunContext {
        static RUN: std::sync::OnceLock<std::sync::Arc<crate::tools::security::ToolRunContext>> =
            std::sync::OnceLock::new();
        RUN.get_or_init(|| {
            crate::tools::security::ToolRunContext::builder(
                crate::state::SessionId::new(),
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
            )
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .workspace_access(crate::tools::WorkspaceAccess::ReadOnly)
            .process(false)
            .network(false)
            .secrets(false)
            .actor_role(crate::runtime::ActorRole::Worker)
            .provider("plan-mode-worker-test")
            .build()
            .expect("worker test run")
        })
        .as_ref()
    }

    // ─── Spec §1: Plan-mode enforcement — entering blocks write/edit/bash ──────

    /// Contract: `enter_plan_mode` returns trusted typed follow-up state.
    #[test]
    fn enter_plan_mode_returns_typed_follow_up() {
        let result = execute_enter_plan_mode(frontend_run());
        assert!(matches!(
            result.follow_up,
            ToolFollowUp::EnterPlanMode {
                state: ToolFollowUpState::Pending
            }
        ));
    }

    /// Contract: calling `enter_plan_mode` again (no args) still returns the
    /// same follow-up — the tool is stateless; the REPL layer is responsible for
    /// the no-op-if-already-in-plan-mode behaviour.
    #[test]
    fn enter_plan_mode_is_idempotent_at_tool_level() {
        let first = execute_enter_plan_mode(frontend_run());
        let second = execute_enter_plan_mode(frontend_run());
        assert_eq!(first.follow_up, second.follow_up);
    }

    // ─── Spec §2: Plan-mode exit — restores permissions ────────────────────────

    /// Contract: `exit_plan_mode` with no args returns a typed exit follow-up.
    #[test]
    fn exit_plan_mode_returns_typed_follow_up() {
        let args = HashMap::new();
        let result = execute_exit_plan_mode(&args);
        assert!(matches!(
            result.follow_up,
            ToolFollowUp::ExitPlanMode {
                state: ToolFollowUpState::Pending,
                ..
            }
        ));
    }

    /// Contract: `exit_plan_mode` propagates typed `allowed_prompts`.
    #[test]
    fn exit_plan_mode_includes_typed_allowed_prompts() {
        let mut args = HashMap::new();
        args.insert(
            "allowed_prompts".to_string(),
            json!([{"tool": "Bash", "prompt": "run tests"}]),
        );
        let result = execute_exit_plan_mode(&args);
        let ToolFollowUp::ExitPlanMode {
            allowed_prompts, ..
        } = result.follow_up
        else {
            panic!("expected typed exit follow-up");
        };
        assert_eq!(allowed_prompts.len(), 1);
        assert_eq!(allowed_prompts[0].tool, "Bash");
    }

    /// Contract: an `allowed_prompts` entry missing the `tool` field returns an
    /// error response (`is_error` = true).
    #[test]
    fn exit_plan_mode_rejects_allowed_prompt_missing_tool() {
        let mut args = HashMap::new();
        args.insert(
            "allowed_prompts".to_string(),
            json!([{"prompt": "do something"}]),
        );
        let (msg, is_err) = execute_exit_plan_mode(&args).into_legacy();
        assert!(is_err, "missing 'tool' field must produce is_error=true");
        assert!(
            msg.contains("missing 'tool'"),
            "error message must name the missing field; got: {msg}"
        );
    }

    /// Contract: an `allowed_prompts` entry missing the `prompt` field also
    /// returns `is_error=true`.
    #[test]
    fn exit_plan_mode_rejects_allowed_prompt_missing_prompt_field() {
        let mut args = HashMap::new();
        args.insert("allowed_prompts".to_string(), json!([{"tool": "Bash"}]));
        let (msg, is_err) = execute_exit_plan_mode(&args).into_legacy();
        assert!(is_err);
        assert!(
            msg.contains("missing 'prompt'"),
            "error message must name the missing field; got: {msg}"
        );
    }

    /// #933: when `allowed_prompts` is present but is not an array, the tool
    /// rejects the call rather than silently treating it as empty. The
    /// previous behaviour (`as_array().cloned().unwrap_or_default()`) masked
    /// model mistakes by collapsing "wrong type" and "absent" into the same
    /// successful empty-array path.
    #[test]
    fn exit_plan_mode_rejects_non_array_allowed_prompts_933() {
        for bad in [
            json!("Bash"),
            json!(42),
            json!({"tool": "Bash"}),
            json!(true),
        ] {
            let mut args = HashMap::new();
            args.insert("allowed_prompts".to_string(), bad.clone());
            let (msg, is_err) = execute_exit_plan_mode(&args).into_legacy();
            assert!(is_err, "non-array value {bad} must be rejected; got: {msg}");
            assert!(
                msg.contains("allowed_prompts must be an array"),
                "error must name the shape violation; got: {msg}"
            );
        }
    }

    /// Contract: absent `allowed_prompts` key behaves the same as an empty
    /// array — the typed follow-up contains an empty prompt list.
    #[test]
    fn exit_plan_mode_absent_allowed_prompts_defaults_to_empty() {
        let args = HashMap::new();
        let result = execute_exit_plan_mode(&args);
        let ToolFollowUp::ExitPlanMode {
            allowed_prompts, ..
        } = result.follow_up
        else {
            panic!("expected typed exit follow-up");
        };
        assert!(allowed_prompts.is_empty());
    }

    /// #618 fix: the typed EXIT follow-up does not carry `prePlanMode` state
    /// (that is a session-level concern handled by the REPL via
    /// `PlanModeState::previous_mode`). The tool layer remains stateless —
    /// regression test pinning the contract.
    #[test]
    fn exit_plan_mode_follow_up_has_no_pre_plan_mode_field_618() {
        let args = HashMap::new();
        let result = execute_exit_plan_mode(&args);
        let v = serde_json::to_value(&result.follow_up).expect("serialize follow-up");
        assert!(
            v.get("prePlanMode").is_none(),
            "#618: tool-level follow-up stays stateless"
        );
    }

    // ─── #620 / S-019: immutable actor-role gate for enter_plan_mode ───────────

    /// Outside a subagent task `enter_plan_mode` succeeds. Sanity test so a
    /// regression in the gate is observable as the *positive* case flipping
    /// to an error (crosslink #620).
    #[test]
    fn enter_plan_mode_outside_agent_task_succeeds_620() {
        let result = execute_enter_plan_mode(frontend_run());
        assert!(matches!(
            result.follow_up,
            ToolFollowUp::EnterPlanMode {
                state: ToolFollowUpState::Pending
            }
        ));
    }

    /// A worker descriptor returns an error matching the CC message family.
    #[test]
    fn enter_plan_mode_inside_agent_task_is_refused_620() {
        let (msg, is_err) = execute_enter_plan_mode(worker_run()).into_legacy();
        assert!(is_err, "must produce is_error=true inside an agent task");
        assert!(
            msg.contains("plan mode cannot be entered from inside an agent task"),
            "error must name the gap; got: {msg}"
        );
    }

    /// Interleaving a worker decision cannot contaminate a frontend run.
    #[test]
    fn enter_plan_mode_actor_decisions_do_not_cross_runs_620() {
        let (_, worker_error) = execute_enter_plan_mode(worker_run()).into_legacy();
        let (_, frontend_error) = execute_enter_plan_mode(frontend_run()).into_legacy();
        assert!(worker_error);
        assert!(!frontend_error);
    }
}
