//! End-to-end host authority and canonical dispatch coverage for S-106.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::unwrap_used)]

mod support;

use std::sync::Arc;

use openclaudia::memory::{LessonReviewState, MemoryDb};
use openclaudia::permissions::{
    ApprovalProvenance, AuthorizationResult, ExecutionPermit, PermissionManager,
};
use openclaudia::services::tool_executor::{ToolExecutor, ToolExecutorRequest};
use openclaudia::tools::{FunctionCall, ToolCall, ToolFailureCode, ToolOutcome, ToolResult};
use serde_json::{json, Value};

struct Fixture {
    _host: tempfile::TempDir,
    workspace: tempfile::TempDir,
    db: MemoryDb,
    run: Arc<openclaudia::tools::ToolRunContext>,
}

impl Fixture {
    fn new() -> Self {
        let host = tempfile::tempdir().expect("host home");
        let workspace = tempfile::tempdir().expect("workspace");
        let db =
            MemoryDb::open_for_workspace(host.path(), workspace.path()).expect("workspace memory");
        let run = support::test_run_context(workspace.path());
        Self {
            _host: host,
            workspace,
            db,
            run,
        }
    }

    fn save(&self, call_id: &str, title: &str) -> (String, String) {
        let call = call(
            call_id,
            "memory_save",
            &lesson_value(
                title,
                "The exact consumed receipt is carried into registry dispatch.",
            ),
        );
        let manager = PermissionManager::unrestricted_for_run(&self.run);
        let result = execute(&self.run, &self.db, &manager, &call, None);
        assert!(!result.is_error(), "save failed: {}", result.content());
        let record = &result.structured().expect("save result")["record"];
        (
            record["logical_id"]
                .as_str()
                .expect("logical id")
                .to_string(),
            record["record_digest"]
                .as_str()
                .expect("record digest")
                .to_string(),
        )
    }

    fn current_record(&self) -> Value {
        let mut result = self
            .db
            .query_technical_lessons(None, 20, chrono::Utc::now().timestamp())
            .expect("technical lessons");
        serde_json::to_value(result.records.pop().expect("current record")).expect("record JSON")
    }
}

fn digest(label: &str) -> String {
    openclaudia::memory::MemoryDigest::for_fields(b"s106-review-e2e-v1", &[label.as_bytes()])
        .to_string()
}

fn lesson_value(title: &str, observation: &str) -> Value {
    json!({
        "title": title,
        "kind": "security",
        "observation": observation,
        "guidance": "Bind review to one exact revision and preserve evidence confidence.",
        "applicability": {
            "paths": ["src/memory/review.rs"],
            "symbols": ["MemoryDb::transition_technical_lesson_review"]
        },
        "citations": [{
            "kind": "test",
            "locator": "tests/technical_memory_review_e2e.rs",
            "source_version": "git:s106-e2e",
            "digest": digest(title),
            "line_start": 1,
            "line_end": 1
        }],
        "confidence": "verified_by_test",
        "sensitivity": "internal",
        "retention": {"policy": "indefinite"}
    })
}

fn call(id: &str, name: &str, arguments: &Value) -> ToolCall {
    ToolCall {
        id: id.to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: name.to_string(),
            arguments: serde_json::to_string(&arguments).expect("tool arguments"),
        },
    }
}

fn review_call(id: &str, action: &str, logical_id: &str, expected_digest: &str) -> ToolCall {
    call(
        id,
        "memory_review",
        &json!({
            "action": action,
            "logical_id": logical_id,
            "expected_record_digest": expected_digest,
        }),
    )
}

fn execute(
    run: &Arc<openclaudia::tools::ToolRunContext>,
    db: &MemoryDb,
    manager: &PermissionManager,
    tool_call: &ToolCall,
    authorization: Option<ExecutionPermit>,
) -> ToolResult {
    ToolExecutor::execute(ToolExecutorRequest {
        run_context: run,
        tool_call,
        memory_db: Some(db),
        app_config: None,
        task_mgr: None,
        permission_mgr: manager,
        authorization,
        session_id: Some("s106-e2e"),
        policy_enforcer: None,
    })
}

fn assert_permission_denied(result: &ToolResult) {
    match result.outcome() {
        ToolOutcome::Error { failure } => {
            assert_eq!(failure.code, ToolFailureCode::PermissionDenied);
        }
        other => panic!("expected permission denial, got {other:?}"),
    }
}

#[test]
fn policy_reusable_and_coordinator_authority_cannot_review() {
    let fixture = Fixture::new();
    let (logical_id, record_digest) =
        fixture.save("save-authority", "Review authority is host-owned");
    let review = review_call("review-authority", "review", &logical_id, &record_digest);
    let manager = PermissionManager::unrestricted_for_run(&fixture.run);

    assert!(matches!(
        manager.authorize_tool_call(&review, Some("s106-e2e")),
        AuthorizationResult::NeedsPrompt { .. }
    ));
    assert!(manager
        .approve_tool_call_for_session(&review, "s106-e2e", ApprovalProvenance::InteractiveUser,)
        .is_err());
    assert!(manager
        .approve_tool_call_persisted(
            &review,
            Some("s106-e2e"),
            ApprovalProvenance::HostAdministrator,
        )
        .is_err());
    assert!(manager
        .approve_tool_call_once(
            &review,
            Some("s106-e2e"),
            ApprovalProvenance::CoordinatorLeader,
        )
        .is_err());

    let denied = execute(&fixture.run, &fixture.db, &manager, &review, None);
    assert_permission_denied(&denied);
    let current = fixture.current_record();
    assert_eq!(current["record_digest"], record_digest);
    assert_eq!(current["lesson"]["review"], json!({"state": "candidate"}));
}

#[test]
fn interactive_one_use_review_and_revoke_execute_through_the_registry() {
    let fixture = Fixture::new();
    let title = "Host review changes metadata only";
    let (logical_id, candidate_digest) = fixture.save("save-transition", title);
    let manager = PermissionManager::unrestricted_for_run(&fixture.run);
    let review = review_call(
        "review-transition",
        "review",
        &logical_id,
        &candidate_digest,
    );
    let permit = manager
        .approve_tool_call_once(
            &review,
            Some("s106-e2e"),
            ApprovalProvenance::InteractiveUser,
        )
        .expect("interactive approval");
    let reviewed = execute(&fixture.run, &fixture.db, &manager, &review, Some(permit));
    assert!(
        !reviewed.is_error(),
        "review failed: {}",
        reviewed.content()
    );
    let reviewed_value = reviewed.structured().expect("review result");
    assert_eq!(reviewed_value["status"], "reviewed");
    assert_eq!(reviewed_value["effectively_host_reviewed"], true);
    assert!(reviewed_value.get("lesson").is_none());
    assert!(!reviewed.content().contains(title));

    let current = fixture.current_record();
    assert_eq!(current["lesson"]["confidence"], "verified_by_test");
    assert_eq!(current["effectively_host_reviewed"], true);
    let reviewed_digest = current["record_digest"]
        .as_str()
        .expect("reviewed digest")
        .to_string();
    let revoke = review_call("revoke-transition", "revoke", &logical_id, &reviewed_digest);
    let permit = manager
        .approve_tool_call_once(
            &revoke,
            Some("s106-e2e"),
            ApprovalProvenance::HostAdministrator,
        )
        .expect("administrator revoke");
    let revoked = execute(&fixture.run, &fixture.db, &manager, &revoke, Some(permit));
    assert!(!revoked.is_error(), "revoke failed: {}", revoked.content());
    assert_eq!(
        revoked.structured().expect("revoke result")["status"],
        "revoked"
    );
    assert_eq!(
        fixture.current_record()["lesson"]["review"],
        json!({"state": "candidate"})
    );
}

#[test]
fn cross_call_and_changed_arguments_are_rejected_before_mutation() {
    let fixture = Fixture::new();
    let (logical_id, record_digest) =
        fixture.save("save-call-binding", "Call IDs are exact capabilities");
    let manager = PermissionManager::unrestricted_for_run(&fixture.run);
    let approved = review_call("approved-call", "review", &logical_id, &record_digest);
    let permit = manager
        .approve_tool_call_once(
            &approved,
            Some("s106-e2e"),
            ApprovalProvenance::InteractiveUser,
        )
        .expect("approval");
    let changed_id = review_call("changed-call", "review", &logical_id, &record_digest);
    let denied = execute(
        &fixture.run,
        &fixture.db,
        &manager,
        &changed_id,
        Some(permit),
    );
    assert_permission_denied(&denied);

    let changed_args_approval = manager
        .approve_tool_call_once(
            &approved,
            Some("s106-e2e"),
            ApprovalProvenance::InteractiveUser,
        )
        .expect("second approval");
    let changed_args = review_call("approved-call", "revoke", &logical_id, &record_digest);
    let denied = execute(
        &fixture.run,
        &fixture.db,
        &manager,
        &changed_args,
        Some(changed_args_approval),
    );
    assert_permission_denied(&denied);
    assert_eq!(fixture.current_record()["record_digest"], record_digest);
}

#[test]
fn cross_run_and_cross_workspace_approvals_are_rejected() {
    let fixture = Fixture::new();
    let (logical_id, record_digest) = fixture.save("save-run-binding", "Run generations are exact");
    let manager = PermissionManager::unrestricted_for_run(&fixture.run);
    let approved = review_call("review-run-binding", "review", &logical_id, &record_digest);
    let permit = manager
        .approve_tool_call_once(
            &approved,
            Some("s106-e2e"),
            ApprovalProvenance::InteractiveUser,
        )
        .expect("approval");
    let other_run = support::test_run_context(fixture.workspace.path());
    let denied = execute(&other_run, &fixture.db, &manager, &approved, Some(permit));
    assert_permission_denied(&denied);
    assert_eq!(fixture.current_record()["record_digest"], record_digest);

    let permit = manager
        .approve_tool_call_once(
            &approved,
            Some("s106-e2e"),
            ApprovalProvenance::InteractiveUser,
        )
        .expect("second approval");
    let other_workspace = tempfile::tempdir().expect("other workspace");
    let other_run = support::test_run_context(other_workspace.path());
    let denied = execute(&other_run, &fixture.db, &manager, &approved, Some(permit));
    assert_permission_denied(&denied);
    assert_eq!(fixture.current_record()["record_digest"], record_digest);
}

#[test]
fn run_and_memory_store_must_share_the_same_workspace_binding() {
    let authority_fixture = Fixture::new();
    let target_fixture = Fixture::new();
    let (logical_id, record_digest) = target_fixture.save(
        "save-miswired-store",
        "The memory store must match the approving run workspace",
    );
    let review = review_call(
        "review-miswired-store",
        "review",
        &logical_id,
        &record_digest,
    );
    let manager = PermissionManager::unrestricted_for_run(&authority_fixture.run);
    let permit = manager
        .approve_tool_call_once(
            &review,
            Some("s106-e2e"),
            ApprovalProvenance::InteractiveUser,
        )
        .expect("approval bound to authority workspace");

    let denied = execute(
        &authority_fixture.run,
        &target_fixture.db,
        &manager,
        &review,
        Some(permit),
    );
    match denied.outcome() {
        ToolOutcome::Error { failure } => {
            assert_eq!(failure.code, ToolFailureCode::PermissionDenied);
        }
        other => panic!("miswired memory store must fail, got {other:?}"),
    }
    assert_eq!(
        target_fixture.current_record()["record_digest"],
        record_digest
    );
}

#[test]
fn stale_review_fails_and_later_correction_resets_review_to_candidate() {
    let fixture = Fixture::new();
    let title = "Corrections reset review";
    let (logical_id, candidate_digest) = fixture.save("save-stale", title);
    let manager = PermissionManager::unrestricted_for_run(&fixture.run);
    let stale_review = review_call("review-stale", "review", &logical_id, &candidate_digest);
    let stale_permit = manager
        .approve_tool_call_once(
            &stale_review,
            Some("s106-e2e"),
            ApprovalProvenance::InteractiveUser,
        )
        .expect("stale approval");
    let correction = call(
        "correct-before-review",
        "memory_update",
        &json!({
            "logical_id": logical_id,
            "expected_record_digest": candidate_digest,
            "correction_reason": "The focused test now covers the exact transition.",
            "replacement": lesson_value(title, "The corrected observation is still candidate evidence.")
        }),
    );
    let corrected = execute(&fixture.run, &fixture.db, &manager, &correction, None);
    assert!(
        !corrected.is_error(),
        "correction failed: {}",
        corrected.content()
    );
    let stale = execute(
        &fixture.run,
        &fixture.db,
        &manager,
        &stale_review,
        Some(stale_permit),
    );
    match stale.outcome() {
        ToolOutcome::Error { failure } => assert_eq!(failure.code, ToolFailureCode::Conflict),
        other => panic!("stale review must conflict, got {other:?}"),
    }

    let corrected_digest = fixture.current_record()["record_digest"]
        .as_str()
        .expect("corrected digest")
        .to_string();
    let fresh_review = review_call("review-fresh", "review", &logical_id, &corrected_digest);
    let permit = manager
        .approve_tool_call_once(
            &fresh_review,
            Some("s106-e2e"),
            ApprovalProvenance::InteractiveUser,
        )
        .expect("fresh approval");
    let reviewed = execute(
        &fixture.run,
        &fixture.db,
        &manager,
        &fresh_review,
        Some(permit),
    );
    assert!(!reviewed.is_error());
    let reviewed_digest = fixture.current_record()["record_digest"]
        .as_str()
        .expect("reviewed digest")
        .to_string();
    let correction = call(
        "correct-after-review",
        "memory_update",
        &json!({
            "logical_id": logical_id,
            "expected_record_digest": reviewed_digest,
            "correction_reason": "A newer test changed the evidence.",
            "replacement": lesson_value(title, "New evidence requires a new host review.")
        }),
    );
    let corrected = execute(&fixture.run, &fixture.db, &manager, &correction, None);
    assert!(!corrected.is_error(), "post-review correction failed");
    let current = fixture.current_record();
    assert_eq!(current["lesson"]["review"], json!({"state": "candidate"}));
    assert_eq!(current["effectively_host_reviewed"], false);
    let decoded: LessonReviewState = serde_json::from_value(current["lesson"]["review"].clone())
        .expect("candidate review state");
    assert_eq!(decoded, LessonReviewState::Candidate);
}

#[test]
fn deleting_a_reviewed_revision_exposes_no_effective_reviewed_state() {
    let fixture = Fixture::new();
    let (logical_id, candidate_digest) =
        fixture.save("save-delete", "Deletion cannot preserve review authority");
    let manager = PermissionManager::unrestricted_for_run(&fixture.run);
    let review = review_call("review-delete", "review", &logical_id, &candidate_digest);
    let permit = manager
        .approve_tool_call_once(
            &review,
            Some("s106-e2e"),
            ApprovalProvenance::InteractiveUser,
        )
        .expect("review approval");
    let reviewed = execute(&fixture.run, &fixture.db, &manager, &review, Some(permit));
    assert!(
        !reviewed.is_error(),
        "review failed: {}",
        reviewed.content()
    );
    let reviewed_digest = reviewed.structured().expect("review result")["record_digest"]
        .as_str()
        .expect("reviewed digest")
        .to_string();

    let delete = call(
        "delete-reviewed",
        "memory_delete",
        &json!({
            "logical_id": logical_id,
            "expected_record_digest": reviewed_digest,
        }),
    );
    let deleted = execute(&fixture.run, &fixture.db, &manager, &delete, None);
    assert!(!deleted.is_error(), "delete failed: {}", deleted.content());
    let query = fixture
        .db
        .query_technical_lessons(None, 20, chrono::Utc::now().timestamp())
        .expect("query after deletion");
    assert!(query.records.is_empty());
}
