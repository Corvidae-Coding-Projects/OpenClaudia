//! Public tool and registry coverage for S-104 team technical memory.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

mod support;

use std::collections::HashMap;
use std::sync::Arc;

use openclaudia::memory::{MemoryDb, MemoryDigest};
use openclaudia::permissions::PermissionManager;
use openclaudia::services::tool_executor::{ToolExecutor, ToolExecutorRequest};
use openclaudia::team_memory::{activate_team_memory, PrincipalId, TeamAuthorityStore, TeamRole};
use openclaudia::tools::{
    FunctionCall, ToolCall, ToolFailureCode, ToolOutcome, ToolResult, ToolRunContext,
};
use serde_json::{json, Value};

fn lesson(title: &str, observation: &str) -> Value {
    let digest =
        MemoryDigest::for_fields(b"openclaudia.s104.public-tool-test.v1", &[title.as_bytes()]);
    json!({
        "title": title,
        "kind": "operational",
        "observation": observation,
        "guidance": "Retrieve this lesson explicitly before changing the cited boundary.",
        "applicability": {
            "paths": ["src/team_memory/replication.rs"],
            "symbols": ["TeamReplica"]
        },
        "citations": [{
            "kind": "test",
            "locator": "tests/team_memory_replication_e2e.rs",
            "source_version": "git:s104-e2e",
            "digest": digest.to_string(),
            "line_start": 1,
            "line_end": 1
        }],
        "confidence": "verified_by_test",
        "sensitivity": "internal",
        "retention": {"policy": "indefinite"}
    })
}

fn execute(
    run: &Arc<ToolRunContext>,
    db: &MemoryDb,
    call_id: &str,
    name: &str,
    arguments: Value,
) -> ToolResult {
    let Value::Object(arguments) = arguments else {
        panic!("tool arguments must be an object");
    };
    let arguments = arguments.into_iter().collect::<HashMap<_, _>>();
    let call = ToolCall {
        id: call_id.to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: name.to_string(),
            arguments: serde_json::to_string(&arguments).expect("arguments"),
        },
    };
    let permissions = PermissionManager::unrestricted_for_run(run);
    ToolExecutor::execute(ToolExecutorRequest {
        run_context: run,
        tool_call: &call,
        memory_db: Some(db),
        app_config: None,
        task_mgr: None,
        permission_mgr: &permissions,
        authorization: None,
        session_id: Some("s104-public-e2e"),
        policy_enforcer: None,
    })
}

fn with_scope(mut draft: Value, scope: &str) -> Value {
    draft
        .as_object_mut()
        .expect("lesson object")
        .insert("scope".to_string(), Value::String(scope.to_string()));
    draft
}

fn save_private_lesson(run: &Arc<ToolRunContext>, db: &MemoryDb) {
    let private = execute(
        run,
        db,
        "s104-save-private",
        "memory_save",
        lesson(
            "Private storage remains private",
            "A private technical lesson must never enter a team replica.",
        ),
    );
    assert!(!private.is_error(), "private save: {}", private.content());
    assert_eq!(
        private.structured().expect("private result")["scope"],
        "user"
    );
}

fn save_team_lesson(run: &Arc<ToolRunContext>, db: &MemoryDb) -> (String, String) {
    let saved = execute(
        run,
        db,
        "s104-save-team",
        "memory_save",
        with_scope(
            lesson(
                "Replication batches preserve causal parents",
                "The team service accepts parent-before-child immutable revisions.",
            ),
            "team",
        ),
    );
    assert!(!saved.is_error(), "team save: {}", saved.content());
    let saved = saved.structured().expect("team save result");
    assert_eq!(saved["scope"], "team");
    assert_eq!(saved["sync_scheduled"], false);
    assert_eq!(saved["sync_status"], "offline");
    assert_eq!(saved["record"]["scope"], "team_shared");
    let logical_id = saved["record"]["logical_id"]
        .as_str()
        .expect("logical ID")
        .to_string();
    let first_digest = saved["record"]["record_digest"]
        .as_str()
        .expect("record digest")
        .to_string();
    (logical_id, first_digest)
}

fn assert_scoped_reads(run: &Arc<ToolRunContext>, db: &MemoryDb) {
    let searched = execute(
        run,
        db,
        "s104-search-team",
        "memory_search",
        json!({
            "query": "causal parents",
            "limit": 5,
            "scope": "team",
            "context": {
                "stage": "operate",
                "paths": ["src/team_memory/replication.rs"],
                "symbols": ["TeamReplica"]
            }
        }),
    );
    assert!(!searched.is_error(), "team search: {}", searched.content());
    let searched = searched.structured().expect("team search result");
    assert_eq!(searched["scope"], "team");
    assert_eq!(searched["status"], "stale");
    assert_eq!(searched["team_freshness"], "unconfigured");
    assert_eq!(searched["retrieval"]["policy"], "lexical_v1");
    assert_eq!(
        searched["retrieval"]["policy_status"],
        "evidence_rejected_fallback"
    );
    assert_eq!(searched["retrieval"]["context"]["stage"], "operate");
    assert_eq!(searched["records"].as_array().expect("records").len(), 1);
    assert!(!searched
        .to_string()
        .contains("Private storage remains private"));

    let both = execute(
        run,
        db,
        "s104-list-both",
        "memory_list",
        json!({"limit": 5, "scope": "both"}),
    );
    assert!(!both.is_error(), "both list: {}", both.content());
    let both = both.structured().expect("both list result");
    assert_eq!(both["scope"], "both");
    assert_eq!(both["status"], "stale");
    let scopes = both["records"]
        .as_array()
        .expect("both records")
        .iter()
        .map(|record| record["scope"].as_str().expect("record scope"))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        scopes,
        std::collections::BTreeSet::from(["team_shared", "user_private"])
    );
}

fn correct_team_lesson(
    run: &Arc<ToolRunContext>,
    db: &MemoryDb,
    logical_id: &str,
    first_digest: &str,
) -> String {
    let corrected = execute(
        run,
        db,
        "s104-update-team",
        "memory_update",
        json!({
            "logical_id": logical_id,
            "expected_record_digest": first_digest,
            "correction_reason": "A restart regression now proves durable retry identity.",
            "replacement": lesson(
                "Replication retries preserve causal parents",
                "Lost responses replay one exact parent-before-child revision batch."
            ),
            "scope": "team"
        }),
    );
    assert!(
        !corrected.is_error(),
        "team update: {}",
        corrected.content()
    );
    let corrected = corrected.structured().expect("team correction");
    assert_eq!(corrected["scope"], "team");
    assert_eq!(corrected["record"]["version"], 2);
    let corrected_digest = corrected["record"]["record_digest"]
        .as_str()
        .expect("corrected digest")
        .to_string();

    let listed = execute(
        run,
        db,
        "s104-list-team",
        "memory_list",
        json!({"limit": 5, "scope": "team"}),
    );
    let listed = listed.structured().expect("team list");
    assert_eq!(listed["records"][0]["version"], 2);
    corrected_digest
}

fn delete_team_lesson_and_verify_private_survives(
    run: &Arc<ToolRunContext>,
    db: &MemoryDb,
    logical_id: &str,
    corrected_digest: &str,
) {
    let deleted = execute(
        run,
        db,
        "s104-delete-team",
        "memory_delete",
        json!({
            "logical_id": logical_id,
            "expected_record_digest": corrected_digest,
            "scope": "team"
        }),
    );
    assert!(!deleted.is_error(), "team delete: {}", deleted.content());
    assert_eq!(
        deleted.structured().expect("team deletion")["scope"],
        "team"
    );

    let team_after = execute(
        run,
        db,
        "s104-list-team-after",
        "memory_list",
        json!({"limit": 5, "scope": "team"}),
    );
    assert!(
        team_after.structured().expect("team after delete")["records"]
            .as_array()
            .expect("team records")
            .is_empty()
    );
    let private_after = execute(
        run,
        db,
        "s104-list-private-after",
        "memory_list",
        json!({"limit": 5, "scope": "user"}),
    );
    let private_after = private_after
        .structured()
        .expect("private after team deletion");
    assert_eq!(
        private_after["records"]
            .as_array()
            .expect("private records")
            .len(),
        1
    );
    assert_eq!(private_after["records"][0]["scope"], "user_private");
}

#[test]
fn all_five_canonical_tools_route_team_scope_without_leaking_private_lessons() {
    let host = tempfile::tempdir().expect("host home");
    let workspace = tempfile::tempdir().expect("workspace");
    let principal: PrincipalId = "owner".parse().expect("principal");
    let authority =
        TeamAuthorityStore::bootstrap(host.path(), workspace.path(), principal, 31_536_000)
            .expect("team authority");
    let team_id = authority.team_id().clone();
    let db = MemoryDb::open_for_workspace(host.path(), workspace.path()).expect("private memory");
    let activated = activate_team_memory(&db, host.path(), workspace.path(), team_id.clone())
        .expect("activate team replica");
    assert_eq!(activated.team_id, team_id);
    assert!(!activated.service_configured);
    let run = support::test_run_context(workspace.path());

    save_private_lesson(&run, &db);
    let (logical_id, first_digest) = save_team_lesson(&run, &db);
    assert_scoped_reads(&run, &db);
    let corrected_digest = correct_team_lesson(&run, &db, &logical_id, &first_digest);
    delete_team_lesson_and_verify_private_survives(&run, &db, &logical_id, &corrected_digest);
}

#[test]
fn unconfigured_team_scope_and_ambiguous_writes_fail_explicitly() {
    let host = tempfile::tempdir().expect("host home");
    let workspace = tempfile::tempdir().expect("workspace");
    let db = MemoryDb::open_for_workspace(host.path(), workspace.path()).expect("private memory");
    let run = support::test_run_context(workspace.path());

    let team = execute(
        &run,
        &db,
        "s104-unconfigured-team",
        "memory_save",
        with_scope(
            lesson("Unavailable team", "This must not be stored."),
            "team",
        ),
    );
    match team.outcome() {
        ToolOutcome::Error { failure } => {
            assert_eq!(failure.code, ToolFailureCode::Unavailable);
            assert_eq!(
                failure.recovery.as_ref().expect("recovery")["action"],
                "configure_team_memory_service"
            );
        }
        other => panic!("unconfigured team write must fail, got {other:?}"),
    }

    let both_read = execute(
        &run,
        &db,
        "s104-unconfigured-both-read",
        "memory_list",
        json!({"scope": "both"}),
    );
    let both_read = both_read.structured().expect("truthful partial result");
    assert_eq!(both_read["status"], "partial");
    assert_eq!(both_read["team_freshness"], "unconfigured");

    let ambiguous = execute(
        &run,
        &db,
        "s104-ambiguous-write",
        "memory_save",
        with_scope(
            lesson("Ambiguous authority", "This must not be stored twice."),
            "both",
        ),
    );
    match ambiguous.outcome() {
        ToolOutcome::Error { failure } => assert_eq!(failure.code, ToolFailureCode::InvalidInput),
        other => panic!("ambiguous cross-authority write must fail, got {other:?}"),
    }
}

#[test]
fn invalid_team_lesson_is_invalid_input_and_never_becomes_durable() {
    let host = tempfile::tempdir().expect("host home");
    let workspace = tempfile::tempdir().expect("workspace");
    let authority = TeamAuthorityStore::bootstrap(
        host.path(),
        workspace.path(),
        "owner".parse().expect("owner principal"),
        31_536_000,
    )
    .expect("team authority");
    let db = MemoryDb::open_for_workspace(host.path(), workspace.path()).expect("private memory");
    activate_team_memory(
        &db,
        host.path(),
        workspace.path(),
        authority.team_id().clone(),
    )
    .expect("activate team replica");
    let run = support::test_run_context(workspace.path());
    let mut invalid = lesson(
        "Empty applicability is invalid",
        "The typed memory contract requires at least one exact applicability path, symbol, or topic.",
    );
    invalid["applicability"] = json!({});
    let rejected = execute(
        &run,
        &db,
        "s104-invalid-team-lesson",
        "memory_save",
        with_scope(invalid, "team"),
    );
    match rejected.outcome() {
        ToolOutcome::Error { failure } => assert_eq!(failure.code, ToolFailureCode::InvalidInput),
        other => panic!("invalid team lesson must fail, got {other:?}"),
    }

    let listed = execute(
        &run,
        &db,
        "s104-list-after-invalid",
        "memory_list",
        json!({"scope": "team", "limit": 5}),
    );
    assert!(
        listed.structured().expect("team list after invalid lesson")["records"]
            .as_array()
            .expect("team records")
            .is_empty()
    );
}

#[test]
fn combined_read_keeps_private_results_and_marks_a_revoked_team_side_partial() {
    let owner_home = tempfile::tempdir().expect("owner home");
    let member_home = tempfile::tempdir().expect("member home");
    let workspace = tempfile::tempdir().expect("workspace");
    let owner = TeamAuthorityStore::bootstrap(
        owner_home.path(),
        workspace.path(),
        "owner".parse().expect("owner principal"),
        31_536_000,
    )
    .expect("owner authority");
    let invitation = owner
        .create_enrollment_invitation(3_600)
        .expect("invitation");
    let (member, request) = TeamAuthorityStore::begin_enrollment(
        member_home.path(),
        workspace.path(),
        "member".parse().expect("member principal"),
        invitation.clone(),
    )
    .expect("begin enrollment");
    let approval = owner
        .approve_enrollment(&invitation, &request, TeamRole::Maintainer, 31_536_000)
        .expect("approval");
    member
        .accept_enrollment(&approval)
        .expect("accept enrollment");
    let db =
        MemoryDb::open_for_workspace(member_home.path(), workspace.path()).expect("private memory");
    activate_team_memory(
        &db,
        member_home.path(),
        workspace.path(),
        owner.team_id().clone(),
    )
    .expect("activate member team replica");
    let run = support::test_run_context(workspace.path());
    let private = execute(
        &run,
        &db,
        "s104-revoked-private",
        "memory_save",
        lesson(
            "Private result survives team revocation",
            "A combined read must retain its independently authorized private side.",
        ),
    );
    assert!(!private.is_error(), "private save: {}", private.content());

    let member_id = member.local_principal_id().expect("member ID");
    let revoked = owner.revoke_member(&member_id).expect("revoke member");
    member
        .apply_authority_bundle(&revoked)
        .expect("apply revocation");
    let combined = execute(
        &run,
        &db,
        "s104-revoked-both",
        "memory_list",
        json!({"scope": "both", "limit": 5}),
    );
    assert!(
        !combined.is_error(),
        "combined read: {}",
        combined.content()
    );
    let combined = combined.structured().expect("combined result");
    assert_eq!(combined["status"], "partial");
    assert_eq!(combined["team_freshness"], "unauthorized");
    assert_eq!(combined["records"].as_array().expect("records").len(), 1);
    assert_eq!(combined["records"][0]["scope"], "user_private");
}

#[test]
fn registry_exposes_exact_read_and_write_scope_contracts() {
    let definitions = openclaudia::tools::get_tool_definitions();
    let definitions = definitions.as_array().expect("tool definitions");
    for (name, expected) in [
        ("memory_save", &["user", "team"][..]),
        ("memory_search", &["user", "team", "both"][..]),
        ("memory_list", &["user", "team", "both"][..]),
        ("memory_update", &["user", "team"][..]),
        ("memory_delete", &["user", "team"][..]),
    ] {
        let definition = definitions
            .iter()
            .find(|definition| definition["function"]["name"] == name)
            .unwrap_or_else(|| panic!("missing {name}"));
        let scope = &definition["function"]["parameters"]["properties"]["scope"];
        assert_eq!(scope["default"], "user", "{name} default scope");
        assert_eq!(
            scope["enum"]
                .as_array()
                .expect("scope enum")
                .iter()
                .map(|value| value.as_str().expect("scope string"))
                .collect::<Vec<_>>(),
            expected,
            "{name} scope enum"
        );
    }
}
