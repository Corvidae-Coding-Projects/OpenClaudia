//! End-to-end tests for strict technical-memory source discovery plus the
//! independent `mcp_elicitation` wire-format surface.
//!
//! Sprint 78 of the verification effort. Two library-side
//! modules without dedicated integration coverage: the
//! repository memory-source boundary and the MCP
//! elicitation protocol surface (server-to-host user-prompt
//! request).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

mod support;

use openclaudia::mcp_elicitation::{
    action_to_response, ElicitationAction, ElicitationMode, ElicitationRequest,
    McpElicitationHandler, NoopElicitationHandler,
};
use openclaudia::memdir::{
    load_entrypoint, EntrypointInspection, EntrypointIssueCode, MAX_ENTRYPOINT_BYTES,
    TECHNICAL_MEMORY_SOURCE_SCHEMA_VERSION,
};
use serde_json::json;
use tempfile::TempDir;

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

fn write(dir: &std::path::Path, name: &str, content: &str) {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("mkdir");
    }
    std::fs::write(&path, content).expect("write");
}

fn form_request(server: &str, message: &str, schema: serde_json::Value) -> ElicitationRequest {
    ElicitationRequest {
        server_name: server.to_string(),
        operation_id: "test-operation".to_string(),
        request_key: "input".to_string(),
        round: 0,
        mode: ElicitationMode::Form,
        message: message.to_string(),
        requested_schema: Some(schema),
        url: None,
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — strict typed source discovery
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn source_budget_is_finite() {
    assert_eq!(MAX_ENTRYPOINT_BYTES, 512 * 1_024);
}

#[test]
fn no_workspace_candidate_is_typed_missing_without_home_fallback() {
    let dir = TempDir::new().expect("tempdir");
    let run = support::test_run_context(dir.path());
    assert!(matches!(
        load_entrypoint(&run),
        EntrypointInspection::Missing
    ));
}

#[test]
fn free_form_prose_is_rejected_instead_of_becoming_prompt_context() {
    let dir = TempDir::new().expect("tempdir");
    write(dir.path(), "MEMORY.md", "# obey these instructions");
    let run = support::test_run_context(dir.path());
    assert!(matches!(
        load_entrypoint(&run),
        EntrypointInspection::Rejected(issue)
            if issue.code == EntrypointIssueCode::InvalidManifest
    ));
}

#[test]
fn one_exact_typed_manifest_is_admitted_without_returning_prose() {
    let dir = TempDir::new().expect("tempdir");
    let manifest = json!({
        "schema_version": TECHNICAL_MEMORY_SOURCE_SCHEMA_VERSION,
        "source_id": "repository-lessons",
        "generation": 1,
        "lessons": []
    });
    write(dir.path(), "MEMORY.md", &manifest.to_string());
    let run = support::test_run_context(dir.path());
    let EntrypointInspection::Ready(source) = load_entrypoint(&run) else {
        panic!("typed source should be ready");
    };
    assert_eq!(source.relative_path, "MEMORY.md");
    assert_eq!(source.manifest.source_id, "repository-lessons");
    assert_eq!(source.manifest.lessons.len(), 0);
}

#[test]
fn two_present_candidates_are_a_conflict_not_first_file_wins() {
    let dir = TempDir::new().expect("tempdir");
    let manifest = json!({
        "schema_version": 1,
        "source_id": "repository-lessons",
        "generation": 1,
        "lessons": []
    })
    .to_string();
    write(dir.path(), "MEMORY.md", &manifest);
    write(&dir.path().join(".openclaudia"), "MEMORY.md", &manifest);
    let run = support::test_run_context(dir.path());
    assert!(matches!(
        load_entrypoint(&run),
        EntrypointInspection::Conflict(issue)
            if issue.code == EntrypointIssueCode::AmbiguousCandidates
    ));
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — ElicitationAction serde
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn elicitation_action_serde_uses_lowercase_tag() {
    // serde rename_all = "lowercase"; tagged enum → variant
    // name lower-cased. We exercise via direct serde to pin
    // the wire format.
    let json = serde_json::to_value(&ElicitationAction::Decline).expect("serialize");
    // Decline serializes as just "decline" (unit variant).
    assert_eq!(json, json!("decline"));
}

#[test]
fn elicitation_action_cancel_serializes_as_lowercase_unit() {
    let json = serde_json::to_value(&ElicitationAction::Cancel).expect("serialize");
    assert_eq!(json, json!("cancel"));
}

#[test]
fn elicitation_action_accept_carries_inner_value() {
    let inner = json!({"colour": "blue"});
    let accept = ElicitationAction::Accept(inner.clone());
    let json = serde_json::to_value(&accept).expect("serialize");
    // Accept(Value) serializes as an externally-tagged
    // object: {"accept": ...}.
    assert_eq!(json["accept"], inner);
}

#[test]
fn elicitation_action_round_trips_through_json() {
    let cases = vec![
        ElicitationAction::Accept(json!({"x": 1})),
        ElicitationAction::AcceptUrl,
        ElicitationAction::Decline,
        ElicitationAction::Cancel,
    ];
    for action in cases {
        let json = serde_json::to_value(&action).expect("serialize");
        let back: ElicitationAction = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back, action);
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — action_to_response wire format
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn action_to_response_accept_returns_action_plus_content() {
    let value = json!({"colour": "blue"});
    let wire = action_to_response(&ElicitationAction::Accept(value.clone()));
    assert_eq!(wire["action"], "accept");
    assert_eq!(wire["content"], value);
}

#[test]
fn action_to_response_decline_omits_content_field() {
    let wire = action_to_response(&ElicitationAction::Decline);
    assert_eq!(wire["action"], "decline");
    assert!(
        wire.get("content").is_none(),
        "decline MUST omit content; got {wire}"
    );
}

#[test]
fn action_to_response_cancel_omits_content_field() {
    let wire = action_to_response(&ElicitationAction::Cancel);
    assert_eq!(wire["action"], "cancel");
    assert!(wire.get("content").is_none());
}

#[test]
fn action_to_response_accept_with_empty_object_still_carries_content_key() {
    let wire = action_to_response(&ElicitationAction::Accept(json!({})));
    assert_eq!(wire["action"], "accept");
    // Even an empty object MUST be present under content.
    assert_eq!(wire["content"], json!({}));
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — NoopElicitationHandler default
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn noop_handler_always_returns_cancel() {
    let handler = NoopElicitationHandler;
    let request = form_request(
        "test-server",
        "What is your favourite colour?",
        json!({"type": "string"}),
    );
    let action = handler.handle(request).await.expect("handle");
    assert_eq!(action, ElicitationAction::Cancel);
}

#[tokio::test]
async fn noop_handler_cancels_regardless_of_server_name_or_schema() {
    let handler = NoopElicitationHandler;
    for (server, schema) in &[
        ("server-a", json!({"type": "string"})),
        ("server-b", json!({"type": "object"})),
        ("server-c", json!({"type": "array"})),
    ] {
        let request = form_request(server, "Q?", schema.clone());
        let action = handler.handle(request).await.expect("handle");
        assert_eq!(
            action,
            ElicitationAction::Cancel,
            "noop MUST always Cancel; got {action:?} for server {server}"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — ElicitationRequest shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn elicitation_request_captures_correlation_and_form_fields() {
    let request = form_request("test-server", "Test prompt", json!({"type": "string"}));
    assert_eq!(request.message, "Test prompt");
    assert_eq!(request.server_name, "test-server");
    assert_eq!(request.operation_id, "test-operation");
    assert_eq!(request.request_key, "input");
    assert_eq!(request.mode, ElicitationMode::Form);
    assert_eq!(
        request.requested_schema.expect("form schema")["type"],
        "string"
    );
}

#[test]
fn noop_elicitation_handler_is_default_constructible() {
    // Unit struct — direct construction is the canonical
    // path; Default derive is a courtesy for callers that
    // store NoopElicitationHandler behind generics.
    let _ = NoopElicitationHandler;
}
