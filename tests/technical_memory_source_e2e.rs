//! End-to-end lifecycle, authority, and adversarial coverage for S-056.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::unwrap_used)]

mod support;

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;

use openclaudia::memory::{
    MemoryDb, MemoryDigest, MemorySourceEvidence, MemorySourceKind, TechnicalLessonDraft,
    TechnicalMemorySourcePresence, TechnicalMemorySourceStoreStatus,
};
use openclaudia::permissions::PermissionManager;
use openclaudia::services::tool_executor::{ToolExecutor, ToolExecutorRequest};
use openclaudia::tools::{ToolFailureCode, ToolOutcome, ToolResult, ToolRunContext};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use tempfile::TempDir;

const SOURCE_ID: &str = "openclaudia-repo";
const LESSON_ID: &str = "descriptor-safe-sqlite";
const SEARCH_TERM: &str = "descriptor-safe";

struct Fixture {
    host: TempDir,
    workspace: TempDir,
    db: Arc<MemoryDb>,
    run: Arc<ToolRunContext>,
}

impl Fixture {
    fn new() -> Self {
        let host = tempfile::tempdir().expect("host home");
        let workspace = tempfile::tempdir().expect("workspace");
        fs::write(
            workspace.path().join("evidence.rs"),
            "fn open_store() { /* descriptor-safe evidence */ }\n",
        )
        .expect("write cited artifact");
        let db = Arc::new(
            MemoryDb::open_for_workspace(host.path(), workspace.path())
                .expect("host-owned workspace memory"),
        );
        let run = support::test_run_context(workspace.path());
        Self {
            host,
            workspace,
            db,
            run,
        }
    }

    fn source_path(&self, relative: &str) -> PathBuf {
        self.workspace.path().join(relative)
    }
}

fn execute(fixture: &Fixture, name: &str, arguments: Value) -> ToolResult {
    execute_on(&fixture.run, &fixture.db, name, arguments)
}

fn execute_on(
    run: &Arc<ToolRunContext>,
    db: &MemoryDb,
    name: &str,
    arguments: Value,
) -> ToolResult {
    let manager = PermissionManager::unrestricted_for_run(run);
    let Value::Object(arguments) = arguments else {
        panic!("tool arguments must be an object");
    };
    let arguments: HashMap<_, _> = arguments.into_iter().collect();
    let call = support::tool_call(name, &arguments);
    ToolExecutor::execute(ToolExecutorRequest {
        run_context: run,
        tool_call: &call,
        memory_db: Some(db),
        app_config: None,
        task_mgr: None,
        permission_mgr: &manager,
        authorization: None,
        session_id: Some("s056-e2e"),
        policy_enforcer: None,
    })
}

fn manifest_bytes(fixture: &Fixture, generation: u64, observation: Option<&str>) -> Vec<u8> {
    let artifact = fs::read(fixture.source_path("evidence.rs")).expect("read cited artifact");
    let digest = MemoryDigest::sha256(&artifact);
    let lessons = observation.map_or_else(Vec::new, |observation| {
        vec![json!({
            "lesson_id": LESSON_ID,
            "lesson": {
                "title": "Use descriptor-safe SQLite publication",
                "kind": "compatibility",
                "observation": observation,
                "guidance": "Pin the workspace artifact and publish every causal record in one transaction.",
                "applicability": {
                    "paths": ["evidence.rs"],
                    "symbols": ["open_store"]
                },
                "citations": [{
                    "kind": "source_file",
                    "locator": "evidence.rs",
                    "source_version": format!("workspace-file:{digest}"),
                    "digest": digest,
                    "line_start": 1,
                    "line_end": 1
                }],
                "confidence": "verified_by_test",
                "sensitivity": "internal",
                "retention": {"policy": "indefinite"}
            }
        })]
    });
    serde_json::to_vec_pretty(&json!({
        "schema_version": 1,
        "source_id": SOURCE_ID,
        "generation": generation,
        "lessons": lessons
    }))
    .expect("serialize manifest")
}

fn write_manifest(
    fixture: &Fixture,
    relative: &str,
    generation: u64,
    observation: Option<&str>,
) -> MemoryDigest {
    let bytes = manifest_bytes(fixture, generation, observation);
    let path = fixture.source_path(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create manifest parent");
    }
    fs::write(path, &bytes).expect("write manifest");
    MemoryDigest::sha256(&bytes)
}

fn write_manifest_value(fixture: &Fixture, relative: &str, value: &Value) -> MemoryDigest {
    let bytes = serde_json::to_vec_pretty(value).expect("serialize custom manifest");
    let path = fixture.source_path(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create custom manifest parent");
    }
    fs::write(path, &bytes).expect("write custom manifest");
    MemoryDigest::sha256(&bytes)
}

fn status(fixture: &Fixture) -> Value {
    let result = execute(fixture, "memory_source_status", json!({}));
    assert!(!result.is_error(), "status failed: {}", result.content());
    assert_eq!(result.observations().len(), 1);
    assert_eq!(
        result.observations()[0].kind,
        "technical_memory_source_status"
    );
    assert!(result.observations()[0].authoritative);
    result.structured().expect("structured status").clone()
}

fn refresh(fixture: &Fixture, expected: Option<&MemoryDigest>, prune: bool) -> ToolResult {
    let mut arguments = serde_json::Map::new();
    if let Some(expected) = expected {
        arguments.insert(
            "expected_source_digest".to_string(),
            Value::String(expected.to_string()),
        );
    }
    if prune {
        arguments.insert("prune_missing".to_string(), Value::Bool(true));
    }
    execute(fixture, "memory_source_refresh", Value::Object(arguments))
}

fn refresh_value(fixture: &Fixture, expected: Option<&MemoryDigest>, prune: bool) -> Value {
    let result = refresh(fixture, expected, prune);
    assert!(!result.is_error(), "refresh failed: {}", result.content());
    result.structured().expect("structured refresh").clone()
}

fn one_record(fixture: &Fixture) -> Value {
    let result = execute(
        fixture,
        "memory_search",
        json!({"query": SEARCH_TERM, "limit": 5}),
    );
    assert!(!result.is_error(), "search failed: {}", result.content());
    let records = result.structured().expect("structured search")["records"]
        .as_array()
        .expect("records");
    assert_eq!(records.len(), 1, "expected one technical lesson");
    records[0].clone()
}

fn current_source(fixture: &Fixture) -> (MemoryDigest, MemoryDigest) {
    match fixture
        .db
        .technical_memory_source_status()
        .expect("source status")
    {
        TechnicalMemorySourceStoreStatus::Ready {
            state_record_digest,
            state,
        } => (state.source_digest, state_record_digest),
        other => panic!("expected ready source state, got {other:?}"),
    }
}

fn assert_failure(result: &ToolResult, expected: ToolFailureCode) {
    match result.outcome() {
        ToolOutcome::Error { failure } => assert_eq!(failure.code, expected),
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}

#[test]
fn import_update_and_exact_replay_preserve_causal_identity() {
    let fixture = Fixture::new();
    let first_source = write_manifest(
        &fixture,
        "MEMORY.md",
        1,
        Some("Descriptor-safe publication avoids path replacement races."),
    );
    let untracked = status(&fixture);
    assert_eq!(untracked["relation"], "untracked");
    assert!(!untracked
        .to_string()
        .contains("avoids path replacement races"));

    let imported_result = refresh(&fixture, None, false);
    assert!(!imported_result.is_error());
    assert_eq!(imported_result.observations().len(), 1);
    assert_eq!(
        imported_result.observations()[0].kind,
        "technical_memory_source_refresh"
    );
    assert!(imported_result.observations()[0].authoritative);
    assert_eq!(
        imported_result.observations()[0].data["content_authority"],
        "untrusted_reference_evidence"
    );
    let imported = imported_result
        .structured()
        .expect("structured import")
        .clone();
    assert_eq!(imported["status"], "imported");
    assert_eq!(imported["created"], 1);
    let first_record = one_record(&fixture);
    assert_eq!(first_record["version"], 1);
    assert_eq!(first_record["provenance"]["source_kind"], "imported");
    assert_eq!(first_record["lesson"]["review"]["state"], "candidate");
    assert_eq!(
        first_record["lesson"]["citations"][0]["source_version"],
        format!(
            "workspace-file:{}",
            MemoryDigest::sha256(
                &fs::read(fixture.source_path("evidence.rs")).expect("read evidence")
            )
        )
    );
    let logical_id = first_record["logical_id"].clone();
    let (_, first_state_digest) = current_source(&fixture);

    let replayed = refresh_value(&fixture, None, false);
    assert_eq!(replayed["status"], "unchanged");
    assert_eq!(replayed["unchanged"], 1);
    assert_eq!(current_source(&fixture).1, first_state_digest);

    let second_source = write_manifest(
        &fixture,
        "MEMORY.md",
        2,
        Some("Descriptor-safe publication also requires a generation-bound transaction."),
    );
    assert_failure(&refresh(&fixture, None, false), ToolFailureCode::Conflict);
    let updated = refresh_value(&fixture, Some(&first_source), false);
    assert_eq!(updated["status"], "updated");
    assert_eq!(updated["updated"], 1);
    let second_record = one_record(&fixture);
    assert_eq!(second_record["logical_id"], logical_id);
    assert_eq!(second_record["version"], 2);

    let third_source = write_manifest(
        &fixture,
        "MEMORY.md",
        3,
        Some("Descriptor-safe publication rejects stale writers before mutation."),
    );
    assert_failure(
        &refresh(&fixture, Some(&first_source), false),
        ToolFailureCode::Conflict,
    );
    assert_eq!(current_source(&fixture).0, second_source);
    assert_eq!(one_record(&fixture)["version"], 2);
    let updated = refresh_value(&fixture, Some(&second_source), false);
    assert_eq!(updated["status"], "updated");
    assert_eq!(current_source(&fixture).0, third_source);
    assert_eq!(one_record(&fixture)["version"], 3);
}

#[test]
fn prune_restore_rename_and_missing_source_have_explicit_outcomes() {
    let fixture = Fixture::new();
    let first_source = write_manifest(
        &fixture,
        "MEMORY.md",
        1,
        Some("Descriptor-safe publication retains a stable causal identity."),
    );
    refresh_value(&fixture, None, false);
    let initial = one_record(&fixture);
    let logical_id = initial["logical_id"].clone();

    let empty_source = write_manifest(&fixture, "MEMORY.md", 2, None);
    let pending = refresh_value(&fixture, Some(&first_source), false);
    assert_eq!(pending["status"], "prune_required");
    assert_eq!(pending["removals_requiring_confirmation"][0], LESSON_ID);
    assert_eq!(current_source(&fixture).0, first_source);
    let pruned = refresh_value(&fixture, Some(&first_source), true);
    assert_eq!(pruned["status"], "pruned");
    assert_eq!(pruned["deleted"], 1);
    assert!(fixture
        .db
        .query_technical_lessons(Some(SEARCH_TERM), 5, 1)
        .expect("query pruned lessons")
        .records
        .is_empty());

    let restored_source = write_manifest(
        &fixture,
        "MEMORY.md",
        3,
        Some("Descriptor-safe publication restores the original logical lesson."),
    );
    let restored = refresh_value(&fixture, Some(&empty_source), false);
    assert_eq!(restored["status"], "updated");
    assert_eq!(restored["restored"], 1);
    let restored_record = one_record(&fixture);
    assert_eq!(restored_record["logical_id"], logical_id);
    assert_eq!(restored_record["version"], 3);

    fs::create_dir_all(fixture.source_path(".openclaudia")).expect("control directory");
    fs::rename(
        fixture.source_path("MEMORY.md"),
        fixture.source_path(".openclaudia/MEMORY.md"),
    )
    .expect("rename source");
    assert_eq!(status(&fixture)["relation"], "rename_available");
    let renamed = refresh_value(&fixture, Some(&restored_source), false);
    assert_eq!(renamed["status"], "renamed");
    assert_eq!(renamed["relative_path"], ".openclaudia/MEMORY.md");
    assert_eq!(
        one_record(&fixture)["record_digest"],
        restored_record["record_digest"]
    );

    fs::remove_file(fixture.source_path(".openclaudia/MEMORY.md")).expect("remove source");
    assert_eq!(status(&fixture)["relation"], "missing_requires_prune");
    let pending = refresh_value(&fixture, Some(&restored_source), false);
    assert_eq!(pending["status"], "prune_required");
    let missing = refresh_value(&fixture, Some(&restored_source), true);
    assert_eq!(missing["status"], "pruned");
    assert_eq!(missing["deleted"], 1);
    match fixture
        .db
        .technical_memory_source_status()
        .expect("missing source status")
    {
        TechnicalMemorySourceStoreStatus::Ready { state, .. } => {
            assert_eq!(state.presence, TechnicalMemorySourcePresence::Missing);
            assert!(state.members.is_empty());
        }
        other => panic!("expected tracked missing source, got {other:?}"),
    }
    let replay = refresh_value(&fixture, Some(&restored_source), true);
    assert_eq!(replay["status"], "unchanged");
}

#[test]
fn concurrent_identical_refresh_publishes_one_successor() {
    let fixture = Fixture::new();
    let first_source = write_manifest(
        &fixture,
        "MEMORY.md",
        1,
        Some("Descriptor-safe publication starts at generation one."),
    );
    refresh_value(&fixture, None, false);
    let second_source = write_manifest(
        &fixture,
        "MEMORY.md",
        2,
        Some("Descriptor-safe publication serializes identical concurrent refreshes."),
    );

    let barrier = Arc::new(Barrier::new(3));
    let second_db = Arc::new(
        MemoryDb::open_for_workspace(fixture.host.path(), fixture.workspace.path())
            .expect("second process-equivalent memory handle"),
    );
    let mut workers = Vec::new();
    for db in [Arc::clone(&fixture.db), second_db] {
        let run = Arc::clone(&fixture.run);
        let barrier = Arc::clone(&barrier);
        let expected = first_source.to_string();
        workers.push(thread::spawn(move || {
            barrier.wait();
            let result = execute_on(
                &run,
                &db,
                "memory_source_refresh",
                json!({"expected_source_digest": expected}),
            );
            assert!(
                !result.is_error(),
                "concurrent refresh: {}",
                result.content()
            );
            let value = result.structured().expect("structured concurrent result");
            (
                value["status"].as_str().expect("status").to_string(),
                value["state_record_digest"]
                    .as_str()
                    .expect("state digest")
                    .to_string(),
            )
        }));
    }
    barrier.wait();
    let mut outcomes = workers
        .into_iter()
        .map(|worker| worker.join().expect("refresh worker"))
        .collect::<Vec<_>>();
    outcomes.sort();
    assert_eq!(outcomes[0].0, "unchanged");
    assert_eq!(outcomes[1].0, "updated");
    assert_eq!(outcomes[0].1, outcomes[1].1);
    assert_eq!(current_source(&fixture).0, second_source);
    assert_eq!(one_record(&fixture)["version"], 2);
}

#[test]
fn later_member_collision_rolls_back_earlier_member_update() {
    let fixture = Fixture::new();
    let first_source = write_manifest(
        &fixture,
        "MEMORY.md",
        1,
        Some("Descriptor-safe publication starts from an exact causal record."),
    );
    refresh_value(&fixture, None, false);
    let initial_record = one_record(&fixture);

    let mut next: Value = serde_json::from_slice(&manifest_bytes(
        &fixture,
        2,
        Some("Descriptor-safe publication must roll back partial source refreshes."),
    ))
    .expect("decode second generation");
    let mut colliding_entry = next["lessons"][0].clone();
    colliding_entry["lesson_id"] = Value::String("z-preoccupied-identity".to_string());
    colliding_entry["lesson"]["title"] = Value::String("Unrelated occupied identity".to_string());
    colliding_entry["lesson"]["observation"] =
        Value::String("A prior record already owns this deterministic identity.".to_string());
    colliding_entry["lesson"]["guidance"] =
        Value::String("Reject adoption and preserve the prior transaction state.".to_string());
    colliding_entry["lesson"]["applicability"] = json!({"components": ["collision"]});
    next["lessons"]
        .as_array_mut()
        .expect("lessons array")
        .push(colliding_entry.clone());
    write_manifest_value(&fixture, "MEMORY.md", &next);

    let occupied_draft: TechnicalLessonDraft =
        serde_json::from_value(colliding_entry["lesson"].clone()).expect("collision draft");
    let collision_source_id = format!("memdir:{SOURCE_ID}:lesson:z-preoccupied-identity");
    fixture
        .db
        .save_technical_lesson_candidate(
            &occupied_draft,
            MemorySourceEvidence::new(
                MemorySourceKind::Imported,
                collision_source_id,
                "preexisting:v1".to_string(),
                MemoryDigest::for_fields(
                    b"openclaudia.s056.preexisting-collision.v1",
                    &[b"z-preoccupied-identity"],
                ),
            ),
            "s056-test".to_string(),
            1,
        )
        .expect("preoccupy deterministic member identity");

    assert_failure(
        &refresh(&fixture, Some(&first_source), false),
        ToolFailureCode::Conflict,
    );
    assert_eq!(current_source(&fixture).0, first_source);
    let after = one_record(&fixture);
    assert_eq!(after["record_digest"], initial_record["record_digest"]);
    assert_eq!(after["version"], 1);
}

#[test]
fn missing_source_restore_requires_a_new_generation() {
    let fixture = Fixture::new();
    let first_source = write_manifest(
        &fixture,
        "MEMORY.md",
        1,
        Some("Descriptor-safe missing sources retain causal history."),
    );
    refresh_value(&fixture, None, false);
    let original = one_record(&fixture);
    fs::remove_file(fixture.source_path("MEMORY.md")).expect("remove source");
    refresh_value(&fixture, Some(&first_source), true);

    let replayed_source = write_manifest(
        &fixture,
        "MEMORY.md",
        1,
        Some("Descriptor-safe missing sources retain causal history."),
    );
    assert_eq!(replayed_source, first_source);
    assert_eq!(status(&fixture)["relation"], "restore_generation_required");
    assert_failure(
        &refresh(&fixture, Some(&first_source), false),
        ToolFailureCode::Conflict,
    );

    let second_source = write_manifest(
        &fixture,
        "MEMORY.md",
        2,
        Some("Descriptor-safe missing sources restore only from a newer generation."),
    );
    assert_eq!(status(&fixture)["relation"], "restore_available");
    let restored = refresh_value(&fixture, Some(&first_source), false);
    assert_eq!(restored["status"], "updated");
    assert_eq!(restored["restored"], 1);
    assert_eq!(current_source(&fixture).0, second_source);
    let record = one_record(&fixture);
    assert_eq!(record["logical_id"], original["logical_id"]);
    assert_eq!(record["version"], 3);
}

#[test]
fn identity_generation_collision_and_regression_fail_before_mutation() {
    let identity = Fixture::new();
    let first_source = write_manifest(
        &identity,
        "MEMORY.md",
        1,
        Some("Descriptor-safe source identity is stable."),
    );
    refresh_value(&identity, None, false);
    let mut foreign: Value = serde_json::from_slice(&manifest_bytes(
        &identity,
        2,
        Some("Descriptor-safe foreign identity must not replace the source."),
    ))
    .expect("decode custom source");
    foreign["source_id"] = Value::String("different-repository".to_string());
    write_manifest_value(&identity, "MEMORY.md", &foreign);
    assert_eq!(status(&identity)["relation"], "source_identity_conflict");
    assert_failure(
        &refresh(&identity, Some(&first_source), false),
        ToolFailureCode::Conflict,
    );
    assert_eq!(current_source(&identity).0, first_source);

    let collision = Fixture::new();
    let original = write_manifest(
        &collision,
        "MEMORY.md",
        1,
        Some("Descriptor-safe generation one is immutable."),
    );
    refresh_value(&collision, None, false);
    write_manifest(
        &collision,
        "MEMORY.md",
        1,
        Some("Descriptor-safe generation one cannot change bytes."),
    );
    assert_eq!(status(&collision)["relation"], "generation_collision");
    assert_failure(
        &refresh(&collision, Some(&original), false),
        ToolFailureCode::Conflict,
    );
    assert_eq!(current_source(&collision).0, original);

    let regression = Fixture::new();
    let generation_two = write_manifest(
        &regression,
        "MEMORY.md",
        2,
        Some("Descriptor-safe generation two is current."),
    );
    refresh_value(&regression, None, false);
    write_manifest(
        &regression,
        "MEMORY.md",
        1,
        Some("Descriptor-safe generation one cannot replace generation two."),
    );
    assert_eq!(status(&regression)["relation"], "stale_generation");
    assert_failure(
        &refresh(&regression, Some(&generation_two), false),
        ToolFailureCode::Conflict,
    );
    assert_eq!(current_source(&regression).0, generation_two);
}

#[test]
fn unsafe_ambiguous_corrupt_and_unverified_sources_fail_typed_and_closed() {
    let corrupt = Fixture::new();
    fs::write(corrupt.source_path("MEMORY.md"), "remember arbitrary prose").expect("write prose");
    assert_eq!(
        status(&corrupt)["discovery"]["issue"]["code"],
        "invalid_manifest"
    );
    assert_failure(
        &refresh(&corrupt, None, false),
        ToolFailureCode::InvalidInput,
    );

    let oversized = Fixture::new();
    fs::write(
        oversized.source_path("MEMORY.md"),
        vec![b'x'; openclaudia::memdir::MAX_ENTRYPOINT_BYTES + 1],
    )
    .expect("write oversized source");
    assert_eq!(
        status(&oversized)["discovery"]["issue"]["code"],
        "oversized"
    );
    assert_failure(&refresh(&oversized, None, false), ToolFailureCode::External);

    let ambiguous = Fixture::new();
    write_manifest(
        &ambiguous,
        "MEMORY.md",
        1,
        Some("Descriptor-safe root source."),
    );
    write_manifest(
        &ambiguous,
        ".openclaudia/MEMORY.md",
        1,
        Some("Descriptor-safe control source."),
    );
    assert_eq!(
        status(&ambiguous)["discovery"]["issue"]["code"],
        "ambiguous_candidates"
    );
    assert_failure(&refresh(&ambiguous, None, false), ToolFailureCode::Conflict);

    let unverified = Fixture::new();
    let mut bytes = manifest_bytes(
        &unverified,
        1,
        Some("Descriptor-safe citations must match exact bytes."),
    );
    let replacement = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let encoded_digest =
        MemoryDigest::sha256(&fs::read(unverified.source_path("evidence.rs")).expect("evidence"))
            .to_string();
    let encoded = String::from_utf8(bytes).expect("manifest UTF-8");
    bytes = encoded.replace(&encoded_digest, replacement).into_bytes();
    fs::write(unverified.source_path("MEMORY.md"), bytes).expect("write bad citation");
    assert_eq!(
        status(&unverified)["discovery"]["issue"]["code"],
        "invalid_manifest"
    );
    assert_failure(
        &refresh(&unverified, None, false),
        ToolFailureCode::InvalidInput,
    );
    assert!(matches!(
        unverified
            .db
            .technical_memory_source_status()
            .expect("unconfigured store"),
        TechnicalMemorySourceStoreStatus::Unconfigured
    ));
}

#[test]
fn citation_budgets_and_control_paths_fail_before_import() {
    let oversized = Fixture::new();
    fs::write(
        oversized.source_path("evidence.rs"),
        vec![b'x'; openclaudia::memdir::MAX_ENTRYPOINT_CITATION_FILE_BYTES + 1],
    )
    .expect("write oversized citation");
    write_manifest(
        &oversized,
        "MEMORY.md",
        1,
        Some("Descriptor-safe citations have a hard byte budget."),
    );
    assert_eq!(
        status(&oversized)["discovery"]["issue"]["code"],
        "oversized"
    );
    assert_failure(&refresh(&oversized, None, false), ToolFailureCode::External);

    let control = Fixture::new();
    fs::create_dir_all(control.source_path(".openclaudia")).expect("control directory");
    let control_bytes = b"host control data\n";
    fs::write(
        control.source_path(".openclaudia/private.txt"),
        control_bytes,
    )
    .expect("control artifact");
    let digest = MemoryDigest::sha256(control_bytes);
    let mut manifest: Value = serde_json::from_slice(&manifest_bytes(
        &control,
        1,
        Some("Descriptor-safe citations cannot read host control state."),
    ))
    .expect("decode manifest");
    let citation = &mut manifest["lessons"][0]["lesson"]["citations"][0];
    citation["locator"] = Value::String(".openclaudia/private.txt".to_string());
    citation["source_version"] = Value::String(format!("workspace-file:{digest}"));
    citation["digest"] = Value::String(digest.to_string());
    write_manifest_value(&control, "MEMORY.md", &manifest);
    assert_eq!(
        status(&control)["discovery"]["issue"]["code"],
        "invalid_manifest"
    );
    assert_failure(
        &refresh(&control, None, false),
        ToolFailureCode::InvalidInput,
    );
}

#[cfg(unix)]
#[test]
fn source_and_citation_symlinks_are_never_followed() {
    use std::os::unix::fs::symlink;

    let source_link = Fixture::new();
    symlink("evidence.rs", source_link.source_path("MEMORY.md")).expect("source symlink");
    assert_eq!(
        status(&source_link)["discovery"]["issue"]["code"],
        "unsafe_file"
    );
    assert_failure(
        &refresh(&source_link, None, false),
        ToolFailureCode::External,
    );

    let citation_link = Fixture::new();
    fs::rename(
        citation_link.source_path("evidence.rs"),
        citation_link.source_path("real-evidence.rs"),
    )
    .expect("move citation target");
    symlink("real-evidence.rs", citation_link.source_path("evidence.rs"))
        .expect("citation symlink");
    write_manifest(
        &citation_link,
        "MEMORY.md",
        1,
        Some("Descriptor-safe citations reject links."),
    );
    assert_eq!(
        status(&citation_link)["discovery"]["issue"]["code"],
        "unsafe_file"
    );
    assert_failure(
        &refresh(&citation_link, None, false),
        ToolFailureCode::External,
    );
}

#[test]
fn persisted_projection_corruption_blocks_status_and_refresh() {
    let fixture = Fixture::new();
    write_manifest(
        &fixture,
        "MEMORY.md",
        1,
        Some("Descriptor-safe state must match its immutable revision."),
    );
    refresh_value(&fixture, None, false);

    let conn = Connection::open(fixture.db.path()).expect("open raw store");
    let changed = conn
        .execute(
            "UPDATE archival_memory SET content = ?1 WHERE id IN (\
             SELECT memory_id FROM archival_memory_tags WHERE tag = ?2)",
            params!["{}", openclaudia::memory::TECHNICAL_MEMORY_SOURCE_TAG],
        )
        .expect("tamper source projection");
    assert_eq!(changed, 1);
    drop(conn);

    assert!(fixture.db.technical_memory_source_status().is_err());
    let result = execute(&fixture, "memory_source_status", json!({}));
    assert_failure(&result, ToolFailureCode::External);
    assert!(!result.content().contains("{}"));
    assert_failure(&refresh(&fixture, None, false), ToolFailureCode::External);
}

#[test]
fn retired_member_head_drift_is_a_typed_source_conflict() {
    let fixture = Fixture::new();
    let first_source = write_manifest(
        &fixture,
        "MEMORY.md",
        1,
        Some("Descriptor-safe retired heads remain lifecycle evidence."),
    );
    refresh_value(&fixture, None, false);
    let active_record_digest = one_record(&fixture)["record_digest"]
        .as_str()
        .expect("active record digest")
        .to_string();
    write_manifest(&fixture, "MEMORY.md", 2, None);
    refresh_value(&fixture, Some(&first_source), true);
    let retired_logical_id = match fixture
        .db
        .technical_memory_source_status()
        .expect("retired source status")
    {
        TechnicalMemorySourceStoreStatus::Ready { state, .. } => {
            assert!(state.members.is_empty());
            assert_eq!(state.retired_members.len(), 1);
            state.retired_members[0].logical_id.to_string()
        }
        other => panic!("expected ready retired source, got {other:?}"),
    };

    let conn = Connection::open(fixture.db.path()).expect("open raw store");
    let changed = conn
        .execute(
            "UPDATE memory_heads SET record_digest = ?1 WHERE logical_id = ?2",
            params![active_record_digest, retired_logical_id],
        )
        .expect("drift retired head");
    assert_eq!(changed, 1);
    drop(conn);

    assert!(matches!(
        fixture
            .db
            .technical_memory_source_status()
            .expect("typed conflict status"),
        TechnicalMemorySourceStoreStatus::Conflict { .. }
    ));
    assert_eq!(status(&fixture)["relation"], "conflict");
    assert_failure(&refresh(&fixture, None, false), ToolFailureCode::Conflict);
}

#[test]
fn source_discovery_is_reachable_only_from_explicit_memory_tools() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut pending = vec![root];
    let mut callers = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).expect("read source directory") {
            let path = entry.expect("source entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs")
                && fs::read_to_string(&path)
                    .expect("read Rust source")
                    .contains("load_entrypoint(")
            {
                callers.insert(
                    path.strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")))
                        .expect("repository-relative source")
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }
    assert_eq!(
        callers,
        BTreeSet::from([
            "src/memdir/entrypoint.rs".to_string(),
            "src/tools/memory.rs".to_string(),
        ]),
        "repository technical-memory sources must never enter prompts or frontends implicitly"
    );
}
