//! End-to-end acceptance tests for S-055 evidence-bound automatic learning.
//!
//! Automatic learning is intentionally not preference extraction. It consumes
//! canonical typed tool outcomes and can propose only repository-scoped,
//! cited, review-due technical lessons from one exact verification failure,
//! intervening successful file mutations, and the exact same later success.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

mod support;

use std::collections::HashMap;
use std::sync::Arc;

use openclaudia::auto_learn::{
    observe_tool_result, retire_run, status_for_run, LearningCaptureStatus,
    LearningEvidenceDisposition,
};
use openclaudia::config::AppConfig;
use openclaudia::memory::{
    LessonRetention, MemoryDb, TechnicalLessonConfidence, TechnicalLessonSensitivity,
};
use openclaudia::permissions::PermissionManager;
use openclaudia::services::tool_executor::{ToolExecutor, ToolExecutorRequest};
use openclaudia::session::{TaskManager, TaskUpdateParams, TaskUpdateStatus};
use openclaudia::tools::{
    FunctionCall, ToolCall, ToolFailureCode, ToolHandlerResult, ToolResult, ToolRetryability,
    ToolRunContext,
};
use serde_json::{json, Value};
use tempfile::TempDir;

struct Fixture {
    _host: TempDir,
    workspace: TempDir,
    db: MemoryDb,
    run: Arc<ToolRunContext>,
    config: AppConfig,
}

impl Fixture {
    fn new() -> Self {
        let host = tempfile::tempdir().expect("host home");
        let workspace = tempfile::tempdir().expect("workspace");
        std::fs::create_dir_all(workspace.path().join("src")).expect("source directory");
        let db = MemoryDb::open_for_workspace(host.path(), workspace.path())
            .expect("workspace-bound private memory");
        let run = support::test_run_context(workspace.path());
        let config = learning_config(true);
        Self {
            _host: host,
            workspace,
            db,
            run,
            config,
        }
    }

    fn lessons(&self) -> Vec<openclaudia::memory::TechnicalLessonRecord> {
        self.db
            .query_technical_lessons(None, 20, chrono::Utc::now().timestamp())
            .expect("technical lesson query")
            .records
    }
}

fn learning_config(enabled: bool) -> AppConfig {
    serde_yaml::from_str(&format!(
        r"
proxy:
  port: 8080
  host: 127.0.0.1
  target: local
providers:
  local:
    base_url: http://localhost:1234/v1
memory:
  automatic_learning_enabled: {enabled}
"
    ))
    .expect("automatic-learning test policy")
}

impl Drop for Fixture {
    fn drop(&mut self) {
        retire_run(&self.run);
    }
}

fn call(id: &str, name: &str, arguments: &Value) -> ToolCall {
    ToolCall {
        id: id.to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: name.to_string(),
            arguments: serde_json::to_string(&arguments).expect("arguments serialize"),
        },
    }
}

fn success(id: &str, name: &str, arguments: &Value, content: &str) -> ToolResult {
    let tool_call = call(id, name, arguments);
    ToolResult::bind(
        &tool_call,
        name,
        ToolHandlerResult::success_text(content.to_string()),
    )
}

fn failure(id: &str, command: &str, diagnostic: &str) -> ToolResult {
    let tool_call = call(id, "bash", &json!({"command": command}));
    ToolResult::failure(
        &tool_call,
        ToolFailureCode::External,
        diagnostic,
        ToolRetryability::Safe,
    )
}

fn execute(fixture: &Fixture, id: &str, name: &str, arguments: &Value) -> ToolResult {
    execute_with_config(fixture, &fixture.config, id, name, arguments)
}

fn execute_with_config(
    fixture: &Fixture,
    config: &AppConfig,
    id: &str,
    name: &str,
    arguments: &Value,
) -> ToolResult {
    let manager = PermissionManager::unrestricted_for_run(&fixture.run);
    let tool_call = call(id, name, arguments);
    ToolExecutor::execute(ToolExecutorRequest {
        run_context: &fixture.run,
        tool_call: &tool_call,
        memory_db: Some(&fixture.db),
        app_config: Some(config),
        task_mgr: None,
        permission_mgr: &manager,
        authorization: None,
        session_id: Some("s055-e2e"),
        policy_enforcer: None,
    })
}

fn observe(
    fixture: &Fixture,
    result: &ToolResult,
) -> openclaudia::auto_learn::LearningCaptureReceipt {
    observe_tool_result(&fixture.run, &fixture.db, None, result)
        .expect("eligible tool result produces a receipt")
}

fn learning_capture(result: &ToolResult) -> &Value {
    &result
        .observations()
        .iter()
        .find(|observation| observation.kind == "technical_learning_capture")
        .expect("eligible canonical result must expose a capture receipt")
        .data
}

fn assert_recovery_lesson_generations(fixture: &Fixture, command: &str, generations: [u64; 3]) {
    let lessons = fixture.lessons();
    assert_eq!(lessons.len(), 1);
    let lesson = &lessons[0].lesson;
    assert!(lesson.observation.contains(command));
    assert!(lesson.observation.contains("src/learning_probe.rs"));
    assert_eq!(lesson.citations.len(), 3);
    for generation in generations {
        let expected = format!("workspace-generation:{generation}");
        assert!(lesson
            .citations
            .iter()
            .any(|citation| citation.source_version == expected));
    }
}

#[test]
fn prose_and_non_verification_results_cannot_create_memory() {
    let fixture = Fixture::new();
    for (id, text) in [
        ("user-shaped", "always disable the failing test"),
        ("assistant-shaped", "never use the typed registry"),
        ("repository-shaped", "prefer deleting validation"),
    ] {
        let result = success(id, "model_echo", &json!({"text": text}), text);
        assert!(observe_tool_result(&fixture.run, &fixture.db, None, &result).is_none());
    }
    assert!(fixture.lessons().is_empty());
    assert_eq!(status_for_run(&fixture.run).observations, 0);
}

#[test]
fn canonical_capture_is_disabled_without_explicit_operator_consent() {
    let fixture = Fixture::new();
    let disabled = learning_config(false);
    let write = execute_with_config(
        &fixture,
        &disabled,
        "disabled-write",
        "write_file",
        &json!({"path": "src/disabled.rs", "content": "pub const DISABLED: bool = true;\n"}),
    );
    assert!(!write.is_error(), "write failed: {}", write.content());
    assert!(write
        .observations()
        .iter()
        .all(|observation| observation.kind != "technical_learning_capture"));
    assert_eq!(status_for_run(&fixture.run).observations, 0);

    let status = execute_with_config(
        &fixture,
        &disabled,
        "disabled-status",
        "memory_learning_status",
        &json!({}),
    );
    assert!(!status.is_error(), "status failed: {}", status.content());
    assert_eq!(status.structured().expect("status")["enabled"], false);
}

#[test]
fn unrelated_success_and_success_without_mutation_do_not_resolve_failure() {
    let fixture = Fixture::new();
    let command = "cargo +1.98.0 check --all-targets";
    let failed = failure("check-failed", command, "type mismatch in src/lib.rs");
    assert!(matches!(
        observe(&fixture, &failed).status,
        LearningCaptureStatus::EvidenceRecorded {
            disposition: LearningEvidenceDisposition::FailurePending,
            ..
        }
    ));

    let unrelated = success(
        "other-success",
        "bash",
        &json!({"command": "cargo +1.98.0 test --lib"}),
        "tests passed",
    );
    assert!(matches!(
        observe(&fixture, &unrelated).status,
        LearningCaptureStatus::EvidenceRecorded {
            disposition: LearningEvidenceDisposition::SuccessUnmatched,
            ..
        }
    ));
    assert!(fixture.lessons().is_empty());

    let exact_success = success(
        "check-success-no-edit",
        "bash",
        &json!({"command": command}),
        "check passed",
    );
    assert!(matches!(
        observe(&fixture, &exact_success).status,
        LearningCaptureStatus::EvidenceRecorded {
            disposition: LearningEvidenceDisposition::SuccessWithoutMutation,
            ..
        }
    ));
    assert!(fixture.lessons().is_empty());
}

#[test]
fn exact_command_success_in_another_canonical_task_cannot_resolve_failure() {
    let fixture = Fixture::new();
    let mut tasks = TaskManager::for_run(&fixture.run).expect("task graph");
    let first_id = tasks
        .create_task(
            "Repair the focused check".to_string(),
            "Keep causal evidence on this exact task.".to_string(),
            None,
        )
        .expect("first task")
        .id
        .clone();
    tasks
        .update_task(
            &first_id,
            TaskUpdateParams {
                status: Some(TaskUpdateStatus::InProgress),
                ..TaskUpdateParams::default()
            },
        )
        .expect("start first task");
    let command = "cargo +1.98.0 check --package exact-task";
    let failed = failure("task-one-failure", command, "task one failed");
    let failure_receipt = observe_tool_result(&fixture.run, &fixture.db, Some(&tasks), &failed)
        .expect("eligible task-bound failure");
    let openclaudia::auto_learn::LearningTaskBinding::CanonicalTask {
        task_id,
        task_revision,
        ..
    } = failure_receipt.task
    else {
        panic!("canonical task manager must bind the exact task");
    };
    assert_eq!(task_id, first_id);
    assert_eq!(task_revision, 2);

    let second_id = tasks
        .create_task(
            "Run an unrelated check".to_string(),
            "A different task must not inherit causal state.".to_string(),
            None,
        )
        .expect("second task")
        .id
        .clone();
    tasks
        .update_task(
            &second_id,
            TaskUpdateParams {
                status: Some(TaskUpdateStatus::InProgress),
                ..TaskUpdateParams::default()
            },
        )
        .expect("start second task");
    let passed = success(
        "task-two-success",
        "bash",
        &json!({"command": command}),
        "check passed",
    );
    let success_receipt = observe_tool_result(&fixture.run, &fixture.db, Some(&tasks), &passed)
        .expect("eligible task-bound success");
    assert!(matches!(
        success_receipt.status,
        LearningCaptureStatus::EvidenceRecorded {
            disposition: LearningEvidenceDisposition::SuccessUnmatched,
            ..
        }
    ));
    assert!(fixture.lessons().is_empty());
    assert_eq!(status_for_run(&fixture.run).pending_checks, 1);
}

#[test]
fn exact_failure_mutation_success_stores_reviewable_cited_candidate() {
    let fixture = Fixture::new();
    let command = "cargo +1.98.0 test --test focused";
    let failed = failure("focused-failed", command, "assertion failed in src/lib.rs");
    let failure_receipt = observe(&fixture, &failed);

    let mutation = success(
        "edit-success",
        "edit_file",
        &json!({
            "path": "src/lib.rs",
            "old_string": "broken",
            "new_string": "fixed"
        }),
        "updated src/lib.rs",
    );
    assert!(matches!(
        observe(&fixture, &mutation).status,
        LearningCaptureStatus::EvidenceRecorded {
            disposition: LearningEvidenceDisposition::MutationLinked,
            linked_mutations: 1,
        }
    ));

    let passed = success(
        "focused-passed",
        "bash",
        &json!({"command": command}),
        "focused test passed",
    );
    let success_receipt = observe(&fixture, &passed);
    let LearningCaptureStatus::CandidateStored {
        logical_id,
        version,
        record_digest,
    } = &success_receipt.status
    else {
        panic!("exact recovery must store a candidate");
    };
    assert_eq!(*version, 1);

    let lessons = fixture.lessons();
    assert_eq!(lessons.len(), 1);
    let record = &lessons[0];
    assert_eq!(record.logical_id.to_string(), logical_id.as_str());
    assert_eq!(record.record_digest.to_string(), record_digest.as_str());
    assert_eq!(
        record.lesson.confidence,
        TechnicalLessonConfidence::ObservedOnce
    );
    assert_eq!(
        record.lesson.sensitivity,
        TechnicalLessonSensitivity::Internal
    );
    assert!(matches!(
        record.lesson.retention,
        LessonRetention::ReviewAfter { .. }
    ));
    assert!(record.lesson.observation.contains("not proof"));
    assert!(record
        .lesson
        .applicability
        .paths
        .iter()
        .any(|path| path == "src/lib.rs"));
    assert_eq!(record.lesson.citations.len(), 3);
    assert!(record
        .lesson
        .citations
        .iter()
        .any(|citation| citation.digest.to_string() == failure_receipt.result_digest));
    assert!(record
        .lesson
        .citations
        .iter()
        .any(|citation| citation.digest.to_string() == success_receipt.result_digest));

    let status = status_for_run(&fixture.run);
    assert_eq!(status.pending_checks, 0);
    assert_eq!(status.learned_candidates, 1);
    assert_eq!(status.candidates_stored, 1);
}

#[test]
fn sensitive_verification_arguments_are_redacted_from_durable_candidate() {
    let fixture = Fixture::new();
    let secret = "s055-registry-secret-value";
    let command = format!("CARGO_REGISTRY_TOKEN={secret} cargo test --lib");
    let failed = failure("secret-failure", &command, "verification failed");
    assert!(matches!(
        observe(&fixture, &failed).status,
        LearningCaptureStatus::EvidenceRecorded {
            disposition: LearningEvidenceDisposition::FailurePending,
            ..
        }
    ));

    let mutation = success(
        "secret-edit",
        "edit_file",
        &json!({
            "path": "src/lib.rs",
            "old_string": "broken",
            "new_string": "fixed"
        }),
        "updated src/lib.rs",
    );
    assert!(matches!(
        observe(&fixture, &mutation).status,
        LearningCaptureStatus::EvidenceRecorded {
            disposition: LearningEvidenceDisposition::MutationLinked,
            ..
        }
    ));
    let passed = success(
        "secret-success",
        "bash",
        &json!({"command": command}),
        "verification passed",
    );
    assert!(matches!(
        observe(&fixture, &passed).status,
        LearningCaptureStatus::CandidateStored { .. }
    ));

    let encoded = serde_json::to_string(&fixture.lessons()).expect("lesson serialization");
    assert!(!encoded.contains(secret));
    assert!(encoded.contains("CARGO_REGISTRY_TOKEN=[REDACTED]"));
}

#[test]
fn canonical_executor_preserves_causal_binding_across_real_workspace_generations() {
    let fixture = Fixture::new();
    let broken_source = "pub const VALUE: u8 = ;\n";
    let fixed_source = "pub const VALUE: u8 = 1;\n";
    let initial_write = execute(
        &fixture,
        "canonical-initial-write",
        "write_file",
        &json!({"path": "src/learning_probe.rs", "content": broken_source}),
    );
    assert!(
        !initial_write.is_error(),
        "initial write failed: {}",
        initial_write.content()
    );

    let command = concat!(
        "rustc --crate-name learning_probe src/learning_probe.rs ",
        "--crate-type lib --emit metadata -o learning_probe.rmeta"
    );
    let failed_check = execute(
        &fixture,
        "canonical-check-failed",
        "bash",
        &json!({"command": command}),
    );
    assert!(
        failed_check.is_partial(),
        "nonzero canonical Bash result must retain typed partial state: {:?}",
        failed_check.outcome()
    );
    let failure_capture = learning_capture(&failed_check);
    assert_eq!(
        failure_capture["status"]["disposition"],
        Value::String("failure_pending".to_string())
    );
    let failure_generation = failure_capture["workspace_generation"]
        .as_u64()
        .expect("failure workspace generation");

    let read = execute(
        &fixture,
        "canonical-read-before-edit",
        "read_file",
        &json!({"path": "src/learning_probe.rs"}),
    );
    assert!(!read.is_error(), "read failed: {}", read.content());
    assert!(read
        .observations()
        .iter()
        .all(|observation| observation.kind != "technical_learning_capture"));

    let edit = execute(
        &fixture,
        "canonical-edit",
        "edit_file",
        &json!({
            "path": "src/learning_probe.rs",
            "old_string": broken_source,
            "new_string": fixed_source
        }),
    );
    assert!(!edit.is_error(), "edit failed: {}", edit.content());
    let edit_capture = learning_capture(&edit);
    assert_eq!(
        edit_capture["status"]["disposition"],
        Value::String("mutation_linked".to_string())
    );
    assert_eq!(edit_capture["status"]["linked_mutations"], 1);
    let edit_generation = edit_capture["workspace_generation"]
        .as_u64()
        .expect("edit workspace generation");
    assert!(edit_generation > failure_generation);

    let passed_check = execute(
        &fixture,
        "canonical-check-passed",
        "bash",
        &json!({"command": command}),
    );
    assert!(
        !passed_check.is_error(),
        "fixed source did not compile: {}",
        passed_check.content()
    );
    let success_capture = learning_capture(&passed_check);
    assert_eq!(success_capture["status"]["status"], "candidate_stored");
    let success_generation = success_capture["workspace_generation"]
        .as_u64()
        .expect("success workspace generation");
    assert!(success_generation >= edit_generation);

    assert_recovery_lesson_generations(
        &fixture,
        command,
        [failure_generation, edit_generation, success_generation],
    );
}

#[test]
fn same_check_failing_again_creates_causal_correction() {
    let fixture = Fixture::new();
    let command = "cargo +1.98.0 clippy --all-targets";
    let _ = observe(&fixture, &failure("lint-failed", command, "lint failed"));
    let _ = observe(
        &fixture,
        &success(
            "write-fixed",
            "write_file",
            &json!({"path": "src/lib.rs", "content": "fixed"}),
            "wrote src/lib.rs",
        ),
    );
    let first = observe(
        &fixture,
        &success(
            "lint-passed",
            "bash",
            &json!({"command": command}),
            "lint passed",
        ),
    );
    assert!(matches!(
        first.status,
        LearningCaptureStatus::CandidateStored { version: 1, .. }
    ));

    let recurrence = observe(
        &fixture,
        &failure("lint-failed-again", command, "same lint failed again"),
    );
    assert!(matches!(
        recurrence.status,
        LearningCaptureStatus::ContradictionStored { version: 2, .. }
    ));
    let lessons = fixture.lessons();
    assert_eq!(lessons.len(), 1);
    assert_eq!(lessons[0].version.get(), 2);
    assert!(lessons[0].lesson.observation.contains("contradicts"));
    assert_eq!(status_for_run(&fixture.run).contradictions_stored, 1);
}

#[test]
fn pending_state_is_bounded_and_compound_shell_is_ineligible() {
    let fixture = Fixture::new();
    let compound = failure(
        "compound",
        "cargo +1.98.0 test && echo pretend-success",
        "failed",
    );
    assert!(observe_tool_result(&fixture.run, &fixture.db, None, &compound).is_none());

    for ordinal in 0..40 {
        let command = format!("cargo +1.98.0 check --package fixture-{ordinal}");
        let result = failure(&format!("failure-{ordinal}"), &command, "check failed");
        let _ = observe(&fixture, &result);
    }
    let status = status_for_run(&fixture.run);
    assert_eq!(status.pending_checks, 32);
    assert_eq!(status.observations, 40);
    assert_eq!(status.degraded_events, 8);
}

#[test]
fn mutation_evidence_overflow_is_visible_and_cannot_create_a_partial_candidate() {
    let fixture = Fixture::new();
    let command = "cargo +1.98.0 check --package mutation-overflow";
    let _ = observe(
        &fixture,
        &failure("overflow-failure", command, "check failed"),
    );

    let mut final_mutation_status = None;
    for ordinal in 0..17 {
        let mutation = success(
            &format!("overflow-edit-{ordinal}"),
            "edit_file",
            &json!({
                "path": format!("src/overflow_{ordinal}.rs"),
                "old_string": "broken",
                "new_string": "fixed"
            }),
            "updated source",
        );
        final_mutation_status = Some(observe(&fixture, &mutation).status);
    }
    assert!(matches!(
        final_mutation_status,
        Some(LearningCaptureStatus::Degraded {
            stage: "evidence_bounds",
            code: "mutation_limit_exceeded"
        })
    ));

    let success = observe(
        &fixture,
        &success(
            "overflow-success",
            "bash",
            &json!({"command": command}),
            "check passed",
        ),
    );
    assert!(matches!(
        success.status,
        LearningCaptureStatus::Degraded {
            stage: "evidence_bounds",
            code: "mutation_evidence_incomplete"
        }
    ));
    assert!(fixture.lessons().is_empty());
    assert_eq!(status_for_run(&fixture.run).degraded_events, 1);
}

#[test]
fn unbound_store_returns_typed_degradation_without_persisting() {
    let workspace = tempfile::tempdir().expect("workspace");
    let database_dir = tempfile::tempdir().expect("database directory");
    let db = MemoryDb::open(&database_dir.path().join("memory.db")).expect("unbound memory db");
    let run = support::test_run_context(workspace.path());
    let result = failure("unbound", "cargo +1.98.0 check", "failed");
    let receipt = observe_tool_result(&run, &db, None, &result).expect("typed degraded receipt");
    assert!(matches!(
        receipt.status,
        LearningCaptureStatus::Degraded {
            stage: "workspace_binding",
            code: "memory_store_unbound"
        }
    ));
    assert_eq!(status_for_run(&run).degraded_events, 1);
    assert!(db
        .query_technical_lessons(None, 20, chrono::Utc::now().timestamp())
        .expect_err("unbound store cannot query technical lessons")
        .to_string()
        .contains("workspace"));
    retire_run(&run);
}

#[test]
fn canonical_executor_attaches_receipt_and_exposes_status_tool() {
    let fixture = Fixture::new();
    let write = execute(
        &fixture,
        "canonical-write",
        "write_file",
        &json!({"path": "src/generated.rs", "content": "pub const WIRED: bool = true;\n"}),
    );
    assert!(!write.is_error(), "write failed: {}", write.content());
    let capture = write
        .observations()
        .iter()
        .find(|observation| observation.kind == "technical_learning_capture")
        .expect("canonical executor attaches learning receipt");
    assert!(!capture.authoritative);
    assert_eq!(capture.data["status"]["status"], "evidence_recorded");
    assert_eq!(
        capture.data["status"]["disposition"],
        Value::String("mutation_linked".to_string())
    );
    assert!(fixture.workspace.path().join("src/generated.rs").is_file());

    let status = execute(
        &fixture,
        "learning-status",
        "memory_learning_status",
        &json!({}),
    );
    assert!(!status.is_error(), "status failed: {}", status.content());
    let structured = status.structured().expect("typed learning status");
    assert_eq!(structured["operation"], "automatic_learning_status");
    assert_eq!(structured["authority"], "untrusted_reference_evidence");
    assert_eq!(structured["enabled"], true);
    assert_eq!(structured["status"]["observations"], 1);
    assert_eq!(structured["status"]["pending_checks"], 0);
}

#[test]
fn learning_status_rejects_unknown_arguments() {
    let fixture = Fixture::new();
    let manager = PermissionManager::unrestricted_for_run(&fixture.run);
    let arguments = HashMap::from([("capture_prose".to_string(), json!(true))]);
    let tool_call = support::tool_call("memory_learning_status", &arguments);
    let result = ToolExecutor::execute(ToolExecutorRequest {
        run_context: &fixture.run,
        tool_call: &tool_call,
        memory_db: Some(&fixture.db),
        app_config: None,
        task_mgr: None,
        permission_mgr: &manager,
        authorization: None,
        session_id: Some("s055-invalid-status"),
        policy_enforcer: None,
    });
    assert!(result.is_error());
    assert!(result.content().contains("memory_learning_status"));
}
