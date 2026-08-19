//! S-018 acceptance coverage for the non-bypassable host-safety ceiling.
//!
//! Approval prompts may be explicitly disabled by a trusted host source, but
//! catastrophic commands, model-requested sandbox weakening, and protected
//! control-file writes must still fail through every executable public entry.

#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};

use openclaudia::permissions::{CheckResult, PermissionManager};
use openclaudia::services::tool_executor::{ToolExecutor, ToolExecutorRequest};
use openclaudia::tools::{
    execute_tool, execute_tool_full, execute_tool_gated, execute_tool_with_memory,
    execute_tool_with_permission_required, execute_tool_with_tasks, ExecutionOutcome, FunctionCall,
    ToolCall, ToolFailureCode, ToolOutcome, ToolResult, HOST_SAFETY_POLICY_GENERATION,
};
use serde_json::json;

#[derive(Clone, Default)]
struct TraceWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for TraceWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("trace buffer")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for TraceWriter {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

fn call(id: &str, tool: &str, arguments: &serde_json::Value) -> ToolCall {
    ToolCall {
        id: id.to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: tool.to_string(),
            arguments: arguments.to_string(),
        },
    }
}

fn assert_host_denial(label: &str, result: &ToolResult) {
    assert!(
        result.is_error(),
        "{label} unexpectedly executed: {result:?}"
    );
    assert!(
        result.content().contains("Host safety")
            || result.content().contains("non-bypassable host safety"),
        "{label} returned a generic failure instead of host-safety evidence: {}",
        result.content()
    );
    assert!(
        matches!(
            result.outcome(),
            ToolOutcome::Error { failure }
                if matches!(
                    failure.code,
                    ToolFailureCode::PermissionDenied | ToolFailureCode::PolicyDenied
                ) && failure.retryability == openclaudia::tools::ToolRetryability::Never
        ),
        "{label} must return a typed, non-retryable policy denial: {:?}",
        result.outcome()
    );
}

fn exercise_public_dispatch_paths(tool_call: &ToolCall, manager: &PermissionManager) {
    let results = [
        ("execute_tool", execute_tool(tool_call)),
        (
            "execute_tool_with_memory",
            execute_tool_with_memory(tool_call, None, manager),
        ),
        (
            "execute_tool_full",
            execute_tool_full(tool_call, None, None, manager),
        ),
        (
            "execute_tool_with_tasks",
            execute_tool_with_tasks(tool_call, None, None, None, manager),
        ),
        (
            "execute_tool_with_permission_required",
            execute_tool_with_permission_required(tool_call, None, None, None, manager),
        ),
        (
            "ToolExecutor::execute",
            ToolExecutor::execute(ToolExecutorRequest {
                tool_call,
                memory_db: None,
                app_config: None,
                task_mgr: None,
                permission_mgr: manager,
                authorization: None,
                session_id: Some("s018-host-safety"),
                policy_enforcer: None,
            }),
        ),
    ];

    for (label, result) in &results {
        assert_host_denial(label, result);
    }

    match execute_tool_gated(tool_call, None, None, None, manager) {
        ExecutionOutcome::Result(result) => assert_host_denial("execute_tool_gated", &result),
        ExecutionOutcome::NeedsPrompt { .. } => {
            panic!("host safety must deny before a user-approvable prompt")
        }
    }
}

#[test]
fn catastrophic_command_is_denied_by_every_public_dispatch_under_bypass_modes() {
    let directory = tempfile::tempdir().expect("tempdir");
    let disabled = PermissionManager::new(
        directory.path().join("disabled-permissions.json"),
        false,
        Vec::new(),
    );
    let unrestricted = PermissionManager::unrestricted();
    let tool_call = call("catastrophic", "bash", &json!({"command": "rm -rf /"}));

    exercise_public_dispatch_paths(&tool_call, &disabled);
    exercise_public_dispatch_paths(&tool_call, &unrestricted);
}

#[test]
fn protected_control_write_is_denied_by_every_public_dispatch_under_bypass_modes() {
    let directory = tempfile::tempdir().expect("tempdir");
    let disabled = PermissionManager::new(
        directory.path().join("disabled-permissions.json"),
        false,
        Vec::new(),
    );
    let unrestricted = PermissionManager::unrestricted();

    for (id, protected, normalized) in [
        (
            "protected-git-write",
            directory
                .path()
                .join("nested")
                .join("..")
                .join(".git/s018-must-not-exist"),
            directory.path().join(".git/s018-must-not-exist"),
        ),
        (
            "protected-settings-write",
            directory.path().join(".claude/./settings.json"),
            directory.path().join(".claude/settings.json"),
        ),
    ] {
        let protected = protected.to_string_lossy().into_owned();
        for (surface, arguments) in [
            (
                "write_file",
                json!({"path": protected, "content": "must not be written"}),
            ),
            (
                "edit_file",
                json!({
                    "path": protected,
                    "old_string": "before",
                    "new_string": "after"
                }),
            ),
            (
                "notebook_edit",
                json!({
                    "notebook_path": protected,
                    "new_source": "must not be written"
                }),
            ),
        ] {
            let tool_call = call(&format!("{id}-{surface}"), surface, &arguments);
            exercise_public_dispatch_paths(&tool_call, &disabled);
            exercise_public_dispatch_paths(&tool_call, &unrestricted);
            assert!(
                !normalized.exists(),
                "{surface} unexpectedly modified protected target {normalized:?}"
            );
        }
    }
}

#[test]
fn model_supplied_sandbox_disable_flag_is_never_treated_as_user_authority() {
    let manager = PermissionManager::unrestricted();
    let tool_call = call(
        "sandbox-escalation",
        "bash",
        &json!({
            "command": "printf sandbox-escalation-must-not-run",
            "dangerously_disable_sandbox": true
        }),
    );
    exercise_public_dispatch_paths(&tool_call, &manager);
}

#[test]
fn host_safety_trace_is_generation_bound_and_does_not_expose_raw_target() {
    let writer = TraceWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .without_time()
        .finish();
    let manager = PermissionManager::unrestricted();
    let secret_target = "/secret-marker/.git/config";

    let outcome = tracing::subscriber::with_default(subscriber, || {
        manager.check(
            "write_file",
            &json!({"path": secret_target, "content": "x"}),
        )
    });
    assert!(matches!(outcome, CheckResult::Denied(_)));

    let captured = String::from_utf8(writer.0.lock().expect("trace buffer").clone())
        .expect("trace output is UTF-8");
    let decision = captured
        .lines()
        .find(|line| line.contains("host_safety_decision") && line.contains("decision=\"denied\""))
        .unwrap_or_else(|| panic!("missing host-safety denial event: {captured}"));
    for field in [
        "event=\"host_safety_decision\"",
        "source=\"protected_control_resource\"",
        "canonical_tool=\"Write\"",
        "effect=\"workspace_mutation\"",
        &format!("policy_generation={HOST_SAFETY_POLICY_GENERATION}"),
        "target_digest=sha256:",
    ] {
        assert!(decision.contains(field), "missing {field:?}: {decision}");
    }
    assert!(!decision.contains(secret_target));
}
