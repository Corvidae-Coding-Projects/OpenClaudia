//! End-to-end causal conflict inspection and resolution for technical memory.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::unwrap_used)]

mod support;

use std::collections::HashMap;
use std::sync::Arc;

use openclaudia::memory::{
    ApplyRevisionOutcome, LessonApplicability, LessonCitation, LessonCitationKind, LessonRetention,
    MemoryAttribution, MemoryDb, MemoryDigest, MemoryProvenance, MemoryRecordScope, MemoryRevision,
    MemoryRevisionState, MemorySourceEvidence, MemorySourceKind, TechnicalLesson,
    TechnicalLessonConfidence, TechnicalLessonDraft, TechnicalLessonKind,
    TechnicalLessonResolutionRequest, TechnicalLessonSensitivity, TechnicalLessonStoreError,
    MAX_LESSON_GUIDANCE_BYTES, MAX_LESSON_OBSERVATION_BYTES, MAX_TECHNICAL_CONFLICT_BRANCH_PAGE,
    MAX_TECHNICAL_QUERY_RESULT_BYTES, TECHNICAL_LESSON_TAG,
};
use openclaudia::permissions::PermissionManager;
use openclaudia::services::tool_executor::{ToolExecutor, ToolExecutorRequest};
use openclaudia::tools::{ToolFailureCode, ToolOutcome, ToolResult, ToolRunContext};
use serde_json::{json, Value};

struct Fixture {
    _host: tempfile::TempDir,
    workspace: tempfile::TempDir,
    db: MemoryDb,
}

fn fixture() -> Fixture {
    let host = tempfile::tempdir().expect("host state");
    let workspace = tempfile::tempdir().expect("workspace");
    let db = MemoryDb::open_for_workspace(host.path(), workspace.path())
        .expect("workspace memory store");
    Fixture {
        _host: host,
        workspace,
        db,
    }
}

fn digest(label: &str) -> MemoryDigest {
    MemoryDigest::for_fields(b"openclaudia.s1081.test.v1", &[label.as_bytes()])
}

fn source(label: &str) -> MemorySourceEvidence {
    MemorySourceEvidence::new(
        MemorySourceKind::ToolOutcome,
        format!("s1081:{label}"),
        "generation:test".to_string(),
        digest(label),
    )
}

fn draft(label: &str) -> TechnicalLessonDraft {
    TechnicalLessonDraft {
        title: format!("Resolve {label} technical evidence"),
        kind: TechnicalLessonKind::Compatibility,
        observation: format!("The {label} branch carries distinct verified evidence."),
        guidance: "Inspect every cited head before publishing one explicit resolution.".to_string(),
        applicability: LessonApplicability {
            paths: vec!["src/memory.rs".to_string()],
            symbols: vec!["MemoryDb::resolve_technical_lesson_conflict".to_string()],
            ..LessonApplicability::default()
        },
        citations: vec![LessonCitation {
            kind: LessonCitationKind::Test,
            locator: "tests/technical_memory_conflict_resolution_e2e.rs".to_string(),
            source_version: format!("fixture:{label}"),
            digest: digest(label),
            line_start: Some(1),
            line_end: Some(1),
        }],
        confidence: TechnicalLessonConfidence::VerifiedByTest,
        sensitivity: TechnicalLessonSensitivity::Internal,
        retention: LessonRetention::Indefinite,
    }
}

fn provenance(db: &MemoryDb, label: &str) -> MemoryProvenance {
    MemoryProvenance::new(
        source(label),
        MemoryAttribution::new(
            format!("actor:{label}"),
            Some(db.store_id().expect("store ID")),
            Some(db.workspace_id().expect("workspace binding").to_string()),
        ),
        MemoryRecordScope::UserPrivate,
    )
}

fn create_root(db: &MemoryDb) -> MemoryRevision {
    let record = db
        .save_technical_lesson_candidate(
            &draft("root"),
            source("root"),
            "actor:root".to_string(),
            1,
        )
        .expect("root lesson");
    db.revision_by_digest(&record.record_digest)
        .expect("root lookup")
        .expect("root revision")
}

fn active_branch(db: &MemoryDb, root: &MemoryRevision, label: &str) -> MemoryRevision {
    active_branch_with_draft(db, root, label, draft(label))
}

fn active_branch_with_draft(
    db: &MemoryDb,
    root: &MemoryRevision,
    label: &str,
    replacement: TechnicalLessonDraft,
) -> MemoryRevision {
    let root_lesson = TechnicalLesson::decode(&root.content).expect("root lesson payload");
    let lesson = root_lesson
        .corrected(
            replacement,
            root.record_digest.clone(),
            format!("resolve {label} evidence"),
            2,
        )
        .expect("branch lesson");
    root.successor(
        lesson.encode().expect("branch encoding"),
        vec![
            TECHNICAL_LESSON_TAG.to_string(),
            "technical-kind:compatibility".to_string(),
        ],
        provenance(db, label),
    )
    .expect("branch revision")
}

fn create_active_conflict(db: &MemoryDb) -> (MemoryRevision, MemoryRevision) {
    let root = create_root(db);
    let left = active_branch(db, &root, "left");
    let right = active_branch(db, &root, "right");
    assert_eq!(
        db.apply_revision(&left).expect("left branch"),
        ApplyRevisionOutcome::Advanced
    );
    assert_eq!(
        db.apply_revision(&right).expect("right branch"),
        ApplyRevisionOutcome::Conflicted
    );
    (left, right)
}

fn resolution_request(
    logical_id: openclaudia::memory::LogicalMemoryId,
    expected_head_digests: Vec<MemoryDigest>,
    label: &str,
) -> TechnicalLessonResolutionRequest {
    TechnicalLessonResolutionRequest {
        logical_id,
        expected_head_digests,
        replacement: draft(label),
        correction_reason: format!("explicitly resolve every {label} branch"),
        source: source(&format!("resolution-{label}")),
        author_id: "actor:resolver".to_string(),
        captured_at_unix_seconds: 3,
    }
}

fn execute(run: &Arc<ToolRunContext>, db: &MemoryDb, name: &str, arguments: Value) -> ToolResult {
    let Value::Object(arguments) = arguments else {
        panic!("tool arguments must be an object");
    };
    let args = arguments.into_iter().collect::<HashMap<_, _>>();
    let call = support::tool_call(name, &args);
    let manager = PermissionManager::unrestricted_for_run(run);
    ToolExecutor::execute(ToolExecutorRequest {
        run_context: run,
        tool_call: &call,
        memory_db: Some(db),
        app_config: None,
        task_mgr: None,
        permission_mgr: &manager,
        authorization: None,
        session_id: Some("s1081-conflict-resolution"),
        policy_enforcer: None,
    })
}

#[test]
fn inspection_respects_the_byte_budget_without_skipping_large_branches() {
    let fixture = fixture();
    let root = create_root(&fixture.db);
    for index in 0..5 {
        let label = format!("large-{index}");
        let mut replacement = draft(&label);
        replacement.observation = "o".repeat(MAX_LESSON_OBSERVATION_BYTES);
        replacement.guidance = "g".repeat(MAX_LESSON_GUIDANCE_BYTES);
        let branch = active_branch_with_draft(&fixture.db, &root, &label, replacement);
        fixture.db.apply_revision(&branch).expect("large branch");
    }

    let mut cursor = None;
    let mut seen = Vec::new();
    let mut expected_heads = None;
    loop {
        let page = fixture
            .db
            .inspect_technical_lesson_conflict(
                root.logical_id,
                cursor.as_ref(),
                MAX_TECHNICAL_CONFLICT_BRANCH_PAGE,
            )
            .expect("byte-bounded conflict page");
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_TECHNICAL_QUERY_RESULT_BYTES);
        assert!(!page.branches.is_empty());
        if let Some(expected) = &expected_heads {
            assert_eq!(&page.expected_head_digests, expected);
        } else {
            expected_heads = Some(page.expected_head_digests.clone());
        }
        seen.extend(
            page.branches
                .iter()
                .map(|branch| branch.record_digest.clone()),
        );
        if !page.branches_truncated {
            break;
        }
        cursor = page.next_after_head_digest;
    }

    assert_eq!(seen, expected_heads.expect("complete head set"));
}

#[test]
fn additional_parent_cannot_hide_a_technical_lineage_from_validation() {
    let fixture = fixture();
    let root = MemoryRevision::new(
        "generic causal root".to_string(),
        Vec::new(),
        provenance(&fixture.db, "generic-root"),
    );
    fixture.db.apply_revision(&root).expect("generic root");

    let workspace_id = fixture.db.workspace_id().expect("workspace binding");
    let typed_payload =
        TechnicalLesson::from_candidate(workspace_id.clone(), draft("typed-seed"), 1)
            .expect("typed seed")
            .corrected(
                draft("typed-branch"),
                root.record_digest.clone(),
                "convert this exact branch into cited technical evidence".to_string(),
                2,
            )
            .expect("typed branch payload");
    let typed = root
        .successor(
            typed_payload.encode().expect("typed encoding"),
            vec![
                TECHNICAL_LESSON_TAG.to_string(),
                "technical-kind:compatibility".to_string(),
            ],
            provenance(&fixture.db, "typed-branch"),
        )
        .expect("typed branch revision");
    fixture.db.apply_revision(&typed).expect("typed branch");

    let untyped = (0..1_024)
        .find_map(|index| {
            let candidate = root
                .successor(
                    format!("untyped branch {index}"),
                    Vec::new(),
                    provenance(&fixture.db, &format!("untyped-{index}")),
                )
                .expect("untyped branch revision");
            (candidate.record_digest < typed.record_digest).then_some(candidate)
        })
        .expect("find an untyped branch whose digest sorts first");
    assert_eq!(
        fixture.db.apply_revision(&untyped).expect("untyped branch"),
        ApplyRevisionOutcome::Conflicted
    );
    let heads_before = fixture.db.revision_heads(root.logical_id).expect("heads");

    let disguised = MemoryRevision::merge_successor(
        &[untyped.clone(), typed],
        "not a technical lesson".to_string(),
        Vec::new(),
        provenance(&fixture.db, "disguised-merge"),
    )
    .expect("structurally valid merge");
    assert_eq!(disguised.parent_digest, Some(untyped.record_digest));
    let error = fixture
        .db
        .apply_revision(&disguised)
        .expect_err("all causal parents must participate in typed-lineage validation");
    assert!(error.to_string().contains("technical lesson"));
    assert!(fixture
        .db
        .revision_by_digest(&disguised.record_digest)
        .expect("disguised lookup")
        .is_none());
    assert_eq!(
        fixture.db.revision_heads(root.logical_id).expect("heads"),
        heads_before
    );
}

#[test]
fn inspection_pages_cited_branches_but_always_returns_the_complete_head_set() {
    let fixture = fixture();
    let (left, right) = create_active_conflict(&fixture.db);
    let first = fixture
        .db
        .inspect_technical_lesson_conflict(left.logical_id, None, 1)
        .expect("first conflict page");
    let mut expected = vec![left.record_digest.clone(), right.record_digest];
    expected.sort();
    assert_eq!(first.expected_head_digests, expected);
    assert_eq!(first.branches.len(), 1);
    assert!(first.branches[0].lesson.is_some());
    assert_eq!(first.branches[0].state, MemoryRevisionState::Active);
    assert!(first.branches_truncated);
    let cursor = first
        .next_after_head_digest
        .as_ref()
        .expect("next conflict cursor");
    let second = fixture
        .db
        .inspect_technical_lesson_conflict(left.logical_id, Some(cursor), 1)
        .expect("second conflict page");
    assert_eq!(second.expected_head_digests, expected);
    assert_eq!(second.branches.len(), 1);
    assert!(!second.branches_truncated);
    assert!(second.next_after_head_digest.is_none());

    let oversized = fixture.db.inspect_technical_lesson_conflict(
        left.logical_id,
        None,
        MAX_TECHNICAL_CONFLICT_BRANCH_PAGE + 1,
    );
    assert!(oversized.is_err());
}

#[test]
fn complete_resolution_supersedes_every_head_and_replays_idempotently() {
    let fixture = fixture();
    let (left, right) = create_active_conflict(&fixture.db);
    let request = resolution_request(
        left.logical_id,
        vec![right.record_digest.clone(), left.record_digest.clone()],
        "merged",
    );
    let resolved = fixture
        .db
        .resolve_technical_lesson_conflict(request.clone())
        .expect("resolve complete head set");
    let revision = fixture
        .db
        .revision_by_digest(&resolved.record_digest)
        .expect("resolution lookup")
        .expect("resolution revision");
    assert_eq!(revision.version.get(), 3);
    assert_eq!(revision.additional_parent_digests.len(), 1);
    let parents = revision
        .causal_parent_digests()
        .cloned()
        .collect::<Vec<_>>();
    let mut expected = vec![left.record_digest, right.record_digest];
    expected.sort();
    assert_eq!(parents, expected);
    assert_eq!(
        fixture.db.revision_heads(left.logical_id).expect("heads"),
        vec![revision]
    );
    assert_eq!(
        fixture
            .db
            .resolve_technical_lesson_conflict(request)
            .expect("idempotent replay")
            .record_digest,
        resolved.record_digest
    );
    let query = fixture
        .db
        .query_technical_lessons(None, 20, 4)
        .expect("resolved query");
    assert_eq!(query.records.len(), 1);
    assert_eq!(query.records[0].record_digest, resolved.record_digest);
    assert_eq!(query.omitted_conflicted, 0);
}

#[test]
fn incomplete_duplicate_forged_and_stale_head_sets_fail_without_writes() {
    let fixture = fixture();
    let (left, right) = create_active_conflict(&fixture.db);
    let before = fixture.db.revision_heads(left.logical_id).expect("heads");
    for bad in [
        vec![left.record_digest.clone()],
        vec![left.record_digest.clone(), left.record_digest.clone()],
        vec![left.record_digest.clone(), digest("forged")],
    ] {
        let error = fixture
            .db
            .resolve_technical_lesson_conflict(resolution_request(left.logical_id, bad, "bad"))
            .expect_err("bad head set must fail");
        assert_eq!(
            error.downcast_ref::<TechnicalLessonStoreError>(),
            Some(&TechnicalLessonStoreError::StaleHeadSet)
        );
        assert_eq!(
            fixture.db.revision_heads(left.logical_id).expect("heads"),
            before
        );
    }

    let complete = vec![left.record_digest.clone(), right.record_digest];
    fixture
        .db
        .resolve_technical_lesson_conflict(resolution_request(
            left.logical_id,
            complete.clone(),
            "first",
        ))
        .expect("first resolution");
    let error = fixture
        .db
        .resolve_technical_lesson_conflict(resolution_request(
            left.logical_id,
            complete,
            "different",
        ))
        .expect_err("changed replay must fail");
    assert_eq!(
        error.downcast_ref::<TechnicalLessonStoreError>(),
        Some(&TechnicalLessonStoreError::StaleHeadSet)
    );
}

#[test]
fn active_and_tombstone_heads_are_both_visible_and_resolvable() {
    let fixture = fixture();
    let root = create_root(&fixture.db);
    let active = active_branch(&fixture.db, &root, "kept");
    let tombstone = root
        .tombstone(provenance(&fixture.db, "deleted"))
        .expect("tombstone branch");
    fixture.db.apply_revision(&active).expect("active branch");
    assert_eq!(
        fixture
            .db
            .apply_revision(&tombstone)
            .expect("tombstone branch"),
        ApplyRevisionOutcome::Conflicted
    );
    let inspected = fixture
        .db
        .inspect_technical_lesson_conflict(root.logical_id, None, 2)
        .expect("mixed conflict");
    assert_eq!(inspected.branches.len(), 2);
    assert!(inspected
        .branches
        .iter()
        .any(|branch| { branch.state == MemoryRevisionState::Active && branch.lesson.is_some() }));
    assert!(inspected.branches.iter().any(|branch| {
        branch.state == MemoryRevisionState::Tombstone && branch.lesson.is_none()
    }));
    fixture
        .db
        .resolve_technical_lesson_conflict(resolution_request(
            root.logical_id,
            inspected.expected_head_digests,
            "restore",
        ))
        .expect("mixed resolution");
    assert_eq!(
        fixture
            .db
            .revision_heads(root.logical_id)
            .expect("heads")
            .len(),
        1
    );
}

#[test]
fn canonical_tools_inspect_then_resolve_the_exact_head_set() {
    let fixture = fixture();
    let (left, _right) = create_active_conflict(&fixture.db);
    let run = support::test_run_context(fixture.workspace.path());
    let inspected = execute(
        &run,
        &fixture.db,
        "memory_conflicts",
        json!({
            "logical_id": left.logical_id,
            "scope": "user",
            "limit": 1
        }),
    );
    assert!(!inspected.is_error(), "inspection failed: {inspected:?}");
    let ToolOutcome::Success { content } = inspected.outcome() else {
        panic!("inspection must return typed success");
    };
    let heads = content
        .structured
        .as_ref()
        .expect("inspection structured result")["expected_head_digests"]
        .clone();
    let resolved = execute(
        &run,
        &fixture.db,
        "memory_update",
        json!({
            "logical_id": left.logical_id,
            "expected_head_digests": heads,
            "correction_reason": "tool resolved every inspected branch",
            "replacement": serde_json::to_value(draft("tool-merged")).unwrap(),
            "scope": "user"
        }),
    );
    assert!(!resolved.is_error(), "resolution failed: {resolved:?}");
    let ToolOutcome::Success { content } = resolved.outcome() else {
        panic!("resolution must return typed success");
    };
    assert_eq!(
        content
            .structured
            .as_ref()
            .and_then(|value| value["operation"].as_str()),
        Some("resolved")
    );

    let stale = execute(
        &run,
        &fixture.db,
        "memory_update",
        json!({
            "logical_id": left.logical_id,
            "expected_record_digest": digest("not-current"),
            "expected_head_digests": [digest("also-not-current"), digest("forged")],
            "correction_reason": "ambiguous request",
            "replacement": serde_json::to_value(draft("ambiguous")).unwrap(),
            "scope": "user"
        }),
    );
    let ToolOutcome::Error { failure } = stale.outcome() else {
        panic!("ambiguous update must fail");
    };
    assert_eq!(failure.code, ToolFailureCode::InvalidInput);
}
