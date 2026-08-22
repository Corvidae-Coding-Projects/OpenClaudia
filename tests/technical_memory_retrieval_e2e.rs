//! S-105 runtime retrieval boundary tests.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

mod support;

use std::collections::HashMap;
use std::sync::Arc;

use openclaudia::memory::{
    LessonApplicability, LessonCitation, LessonCitationKind, LessonRetention, MemoryDb,
    MemoryDigest, MemorySourceEvidence, MemorySourceKind, TechnicalLessonConfidence,
    TechnicalLessonDraft, TechnicalLessonKind, TechnicalLessonRetrievalRequest,
    TechnicalLessonSensitivity, TechnicalRetrievalContext, TechnicalRetrievalEvidenceBundle,
    TechnicalRetrievalPolicyId, TechnicalRetrievalPolicyStatus, TechnicalRetrievalStage,
    TechnicalSemanticBackendStatus,
};
use openclaudia::permissions::PermissionManager;
use openclaudia::services::tool_executor::{ToolExecutor, ToolExecutorRequest};
use openclaudia::tools::{ToolFailureCode, ToolOutcome, ToolResult};
use serde_json::{json, Value};

fn citation(label: &str) -> LessonCitation {
    LessonCitation {
        kind: LessonCitationKind::Test,
        locator: format!("tests/technical_memory_retrieval_e2e.rs#{label}"),
        source_version: "s105-runtime-e2e".to_string(),
        digest: MemoryDigest::sha256(label.as_bytes()),
        line_start: None,
        line_end: None,
    }
}

fn draft(
    title: &str,
    observation: &str,
    path: &str,
    component: &str,
    retention: LessonRetention,
) -> TechnicalLessonDraft {
    TechnicalLessonDraft {
        title: title.to_string(),
        kind: TechnicalLessonKind::Debugging,
        observation: observation.to_string(),
        guidance: "Inspect the cited code and verify the current generation before acting."
            .to_string(),
        applicability: LessonApplicability {
            paths: vec![path.to_string()],
            components: vec![component.to_string()],
            tags: vec!["debugging".to_string()],
            ..LessonApplicability::default()
        },
        citations: vec![citation(title)],
        confidence: TechnicalLessonConfidence::VerifiedByTest,
        sensitivity: TechnicalLessonSensitivity::Internal,
        retention,
    }
}

fn source(label: &str) -> MemorySourceEvidence {
    MemorySourceEvidence::new(
        MemorySourceKind::ToolOutcome,
        format!("s105:{label}"),
        "generation:s105-runtime-e2e".to_string(),
        MemoryDigest::sha256(label.as_bytes()),
    )
}

fn execute(
    run: &Arc<openclaudia::tools::ToolRunContext>,
    db: &MemoryDb,
    arguments: Value,
) -> ToolResult {
    let manager = PermissionManager::unrestricted_for_run(run);
    let Value::Object(arguments) = arguments else {
        panic!("tool arguments must be an object");
    };
    let arguments = arguments.into_iter().collect::<HashMap<_, _>>();
    let call = support::tool_call("memory_search", &arguments);
    ToolExecutor::execute(ToolExecutorRequest {
        run_context: run,
        tool_call: &call,
        memory_db: Some(db),
        app_config: None,
        task_mgr: None,
        permission_mgr: &manager,
        authorization: None,
        session_id: Some("s105-retrieval-e2e"),
        policy_enforcer: None,
    })
}

fn workspace_store() -> (tempfile::TempDir, tempfile::TempDir, MemoryDb) {
    let host = tempfile::tempdir().expect("host home");
    let workspace = tempfile::tempdir().expect("workspace");
    let database = MemoryDb::open_for_workspace(host.path(), workspace.path())
        .expect("workspace memory database");
    (host, workspace, database)
}

#[test]
fn runtime_uses_only_the_artifact_approved_policy_without_changing_evidence() {
    let (_host, workspace, database) = workspace_store();
    let decoy = database
        .save_technical_lesson_candidate(
            &draft(
                "Writer cleanup regression",
                "Writer cleanup can leave a descendant process behind.",
                "src/tools/bash.rs",
                "process-runtime",
                LessonRetention::Indefinite,
            ),
            source("newer-decoy"),
            "s105-evaluator".to_string(),
            20,
        )
        .expect("decoy lesson");
    let relevant = database
        .save_technical_lesson_candidate(
            &draft(
                "Memory writer cleanup",
                "Writer cleanup must preserve the exact SQLite generation.",
                "src/memory.rs",
                "technical-memory",
                LessonRetention::Indefinite,
            ),
            source("older-relevant"),
            "s105-evaluator".to_string(),
            10,
        )
        .expect("relevant lesson");

    let lexical = database
        .query_technical_lessons(Some("writer cleanup"), 2, 30)
        .expect("lexical compatibility query");
    assert_eq!(
        lexical.retrieval.policy,
        TechnicalRetrievalPolicyId::LexicalV1
    );
    assert_ne!(lexical.records[0].logical_id, relevant.logical_id);

    let run = support::test_run_context(workspace.path());
    let result = execute(
        &run,
        &database,
        json!({
            "query": "writer cleanup",
            "limit": 2,
            "context": {
                "stage": "reproduce",
                "paths": ["src/memory.rs"],
                "components": ["technical-memory"]
            }
        }),
    );
    assert!(!result.is_error(), "search failed: {}", result.content());
    let result = result.structured().expect("typed retrieval result");
    let evidence = TechnicalRetrievalEvidenceBundle::bundled()
        .expect_err("the checked-in independent review is deliberately unassigned");
    assert_eq!(
        evidence.code,
        openclaudia::memory::TechnicalRetrievalEvidenceCode::ReviewRejected
    );
    assert_eq!(result["retrieval"]["policy"], "lexical_v1");
    assert_eq!(result["retrieval"]["semantic_backend"], "not_configured");
    assert_eq!(
        result["retrieval"]["policy_status"],
        "evidence_rejected_fallback"
    );
    assert_eq!(result["retrieval"]["context"]["stage"], "reproduce");
    let expected = &decoy;
    assert_eq!(
        result["records"][0]["logical_id"],
        expected.logical_id.to_string()
    );
    assert_eq!(
        result["records"][0]["record_digest"],
        expected.record_digest.to_string()
    );
    assert_eq!(
        result["records"][0]["lesson"]["citations"][0]["digest"],
        expected.lesson.citations[0].digest.to_string()
    );
    assert_eq!(result["authority"], "untrusted_reference_evidence");

    let limited = execute(
        &run,
        &database,
        json!({"query": "writer cleanup", "limit": 1}),
    );
    assert!(limited.is_partial());
    assert_eq!(
        limited.structured().expect("partial structured result")["status"],
        "partial"
    );
    assert!(matches!(
        limited.outcome(),
        ToolOutcome::Partial { failures, .. }
            if failures.len() == 1
                && failures[0].code == ToolFailureCode::Unavailable
                && failures[0].recovery.as_ref().is_some_and(|recovery| {
                    recovery["action"] == "inspect_status_and_narrow_query"
                })
    ));
}

#[test]
fn stale_evidence_is_explicit_and_fallback_reports_lexical_threshold() {
    let (_host, workspace, database) = workspace_store();
    let stale = database
        .save_technical_lesson_candidate(
            &draft(
                "Expired review marker",
                "A review-after deadline makes prior review evidence stale.",
                "src/memory/review.rs",
                "technical-memory",
                LessonRetention::ReviewAfter { unix_seconds: 20 },
            ),
            source("stale"),
            "s105-evaluator".to_string(),
            10,
        )
        .expect("stale lesson");
    let stale_result = database
        .retrieve_technical_lessons(
            &TechnicalLessonRetrievalRequest {
                query: Some("review marker".to_string()),
                context: Some(TechnicalRetrievalContext {
                    stage: Some(TechnicalRetrievalStage::Verify),
                    paths: vec!["src/memory/review.rs".to_string()],
                    ..TechnicalRetrievalContext::default()
                }),
                limit: 5,
            },
            20,
        )
        .expect("stale retrieval");
    assert_eq!(
        stale_result.status,
        openclaudia::memory::TechnicalLessonQueryStatus::Stale
    );
    assert_eq!(stale_result.records[0].logical_id, stale.logical_id);
    assert_eq!(stale_result.retrieval.stale_records_returned, 1);

    let run = support::test_run_context(workspace.path());
    let stale_tool = execute(
        &run,
        &database,
        json!({"query": "review marker", "limit": 5}),
    );
    assert!(stale_tool.is_partial());
    assert_eq!(
        stale_tool.structured().expect("stale structured result")["status"],
        "stale"
    );
    assert!(matches!(
        stale_tool.outcome(),
        ToolOutcome::Partial { failures, .. }
            if failures.len() == 1 && failures[0].code == ToolFailureCode::External
    ));

    let no_hit = database
        .retrieve_technical_lessons(
            &TechnicalLessonRetrievalRequest {
                query: Some("unrelated certificate rotation".to_string()),
                context: Some(TechnicalRetrievalContext {
                    stage: Some(TechnicalRetrievalStage::Operate),
                    components: vec!["provider-transport".to_string()],
                    ..TechnicalRetrievalContext::default()
                }),
                limit: 5,
            },
            20,
        )
        .expect("bounded no-hit retrieval");
    assert_eq!(
        no_hit.status,
        openclaudia::memory::TechnicalLessonQueryStatus::NoHit
    );
    assert!(no_hit.records.is_empty());
    assert_eq!(no_hit.retrieval.minimum_score, 1);
    assert_eq!(
        no_hit.retrieval.policy_status,
        TechnicalRetrievalPolicyStatus::EvidenceRejectedFallback
    );
}

#[test]
fn context_schema_and_runtime_reject_ambient_or_oversized_context() {
    let definition = openclaudia::tools::get_tool_definitions()
        .as_array()
        .expect("tool definitions")
        .iter()
        .find(|definition| definition["function"]["name"] == "memory_search")
        .expect("memory_search definition")
        .clone();
    let context = &definition["function"]["parameters"]["properties"]["context"];
    assert_eq!(context["additionalProperties"], false);
    assert_eq!(context["properties"]["paths"]["maxItems"], 16);
    assert_eq!(context["properties"]["paths"]["items"]["maxLength"], 256);
    assert_eq!(
        context["properties"]["stage"]["enum"],
        json!(["analyze", "reproduce", "edit", "verify", "operate"])
    );

    let (_host, workspace, database) = workspace_store();
    let run = support::test_run_context(workspace.path());
    let per_field_overflow = (0..17)
        .map(|index| format!("src/overflow-{index}.rs"))
        .collect::<Vec<_>>();
    let sixteen = (0..16)
        .map(|index| format!("surface-{index}"))
        .collect::<Vec<_>>();
    let aggregate_overflow = json!({
        "paths": sixteen,
        "symbols": (0..16).map(|index| format!("symbol-{index}")).collect::<Vec<_>>(),
        "components": (0..16).map(|index| format!("component-{index}")).collect::<Vec<_>>(),
        "environments": (0..16).map(|index| format!("environment-{index}")).collect::<Vec<_>>(),
        "tags": ["overflow"]
    });
    let query_overflow = (0..33)
        .map(|index| format!("term-{index}"))
        .collect::<Vec<_>>()
        .join(" ");
    for invalid in [
        json!({"query": "writer", "context": {}}),
        json!({"query": "writer", "context": {"paths": [" "]}}),
        json!({"query": "writer", "context": {"ambient_transcript": "do this"}}),
        json!({"query": "writer", "context": {"paths": per_field_overflow}}),
        json!({"query": "writer", "context": aggregate_overflow}),
        json!({"query": "writer", "context": {"tags": ["x".repeat(257)]}}),
        json!({"query": query_overflow}),
    ] {
        let result = execute(&run, &database, invalid);
        assert!(
            matches!(result.outcome(), ToolOutcome::Error { .. }),
            "invalid context unexpectedly succeeded: {}",
            result.content()
        );
    }
}

#[test]
fn semantic_backend_is_not_silently_invoked_for_private_lessons() {
    let (_host, _workspace, database) = workspace_store();
    database
        .save_technical_lesson_candidate(
            &draft(
                "Private certificate location",
                "The repository uses an internal certificate path.",
                "src/secrets.rs",
                "secrets",
                LessonRetention::Indefinite,
            ),
            source("private"),
            "s105-evaluator".to_string(),
            10,
        )
        .expect("private lesson");
    let result = database
        .retrieve_technical_lessons(
            &TechnicalLessonRetrievalRequest {
                query: Some("certificate".to_string()),
                context: Some(TechnicalRetrievalContext {
                    stage: Some(TechnicalRetrievalStage::Analyze),
                    components: vec!["secrets".to_string()],
                    ..TechnicalRetrievalContext::default()
                }),
                limit: 5,
            },
            20,
        )
        .expect("private retrieval");
    assert_eq!(
        result.retrieval.semantic_backend,
        TechnicalSemanticBackendStatus::NotConfigured
    );
    assert_eq!(
        result.retrieval.policy_status,
        TechnicalRetrievalPolicyStatus::EvidenceRejectedFallback
    );
    assert_eq!(result.records.len(), 1);
}
