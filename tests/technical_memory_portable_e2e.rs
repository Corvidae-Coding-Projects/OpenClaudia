//! End-to-end portable technical-memory authority and integrity coverage for S-107.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::unwrap_used)]

mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use std::collections::HashMap;

use openclaudia::memory::{
    MemoryDb, MemoryDigest, TechnicalMemoryPackageManifest, TechnicalMemorySourceStoreStatus,
    TECHNICAL_MEMORY_PACKAGE_MANIFEST_NAME,
};
use openclaudia::permissions::{
    ApprovalProvenance, AuthorizationResult, ExecutionPermit, PermissionManager,
};
use openclaudia::runtime::CancellationReason;
use openclaudia::services::tool_executor::{ToolExecutor, ToolExecutorRequest};
use openclaudia::tools::{
    FunctionCall, ToolCall, ToolFailureCode, ToolOutcome, ToolResult, ToolRunContext,
};
#[cfg(unix)]
use openclaudia::{state::SessionId, tools::WorkspaceAccess};
use serde_json::{json, Value};

const SESSION_ID: &str = "s107-portable-e2e";
const PRIVATE_LESSON_MARKER: &str = "PORTABLE_TECHNICAL_LESSON_MARKER";
const LEGACY_PROSE_MARKER: &str = "LEGACY_SESSION_PROSE_MUST_NOT_EXPORT";

struct Fixture {
    _host: tempfile::TempDir,
    workspace: tempfile::TempDir,
    db: MemoryDb,
    run: Arc<ToolRunContext>,
}

impl Fixture {
    fn new() -> Self {
        let host = tempfile::tempdir().expect("host home");
        let workspace = tempfile::tempdir().expect("workspace");
        let db = MemoryDb::open_for_workspace(host.path(), workspace.path())
            .expect("workspace technical memory");
        let run = support::test_run_context(workspace.path());
        Self {
            _host: host,
            workspace,
            db,
            run,
        }
    }

    fn package_dir(&self, name: &str) -> PathBuf {
        let path = self.workspace.path().join(name);
        fs::create_dir(&path).expect("private package directory");
        path.canonicalize().expect("canonical package directory")
    }

    fn execute(
        &self,
        manager: &PermissionManager,
        call: &ToolCall,
        permit: Option<ExecutionPermit>,
    ) -> ToolResult {
        execute(&self.run, &self.db, manager, call, permit)
    }

    fn save_lesson(&self, call_id: &str, title: &str) -> Value {
        let manager = PermissionManager::unrestricted_for_run(&self.run);
        let result = self.execute(
            &manager,
            &call(call_id, "memory_save", &lesson_value(title)),
            None,
        );
        assert!(!result.is_error(), "save failed: {}", result.content());
        result.structured().expect("structured save")["record"].clone()
    }
}

fn execute(
    run: &Arc<ToolRunContext>,
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
        session_id: Some(SESSION_ID),
        policy_enforcer: None,
    })
}

fn call(id: &str, name: &str, arguments: &Value) -> ToolCall {
    ToolCall {
        id: id.to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: name.to_string(),
            arguments: serde_json::to_string(arguments).expect("tool arguments"),
        },
    }
}

fn lesson_value(title: &str) -> Value {
    json!({
        "title": title,
        "kind": "security",
        "observation": format!("{PRIVATE_LESSON_MARKER}: descriptor-relative commits prevent path replacement races."),
        "guidance": "Validate the exact generation and publish through the descriptor-owned directory.",
        "applicability": {
            "paths": ["src/persistence.rs"],
            "symbols": ["PersistentStorage::commit"]
        },
        "citations": [{
            "kind": "test",
            "locator": "tests/technical_memory_portable_e2e.rs",
            "source_version": "git:s107-e2e",
            "digest": MemoryDigest::for_fields(b"s107-portable-citation-v1", &[title.as_bytes()]),
            "line_start": 1,
            "line_end": 1
        }],
        "confidence": "verified_by_test",
        "sensitivity": "internal",
        "retention": {"policy": "indefinite"}
    })
}

fn approve_once(
    manager: &PermissionManager,
    tool_call: &ToolCall,
    provenance: ApprovalProvenance,
) -> ExecutionPermit {
    manager
        .approve_tool_call_once(tool_call, Some(SESSION_ID), provenance)
        .expect("fresh host approval")
}

fn authorized_execute(run: &Arc<ToolRunContext>, db: &MemoryDb, call: &ToolCall) -> ToolResult {
    let manager = PermissionManager::unrestricted_for_run(run);
    let permit = approve_once(&manager, call, ApprovalProvenance::InteractiveUser);
    execute(run, db, &manager, call, Some(permit))
}

fn export_call(id: &str, root: &Path) -> ToolCall {
    call(
        id,
        "memory_export",
        &json!({"destination_root": root.to_string_lossy()}),
    )
}

fn import_call(id: &str, root: &Path) -> ToolCall {
    call(
        id,
        "memory_import",
        &json!({"source_root": root.to_string_lossy()}),
    )
}

fn load_manifest(root: &Path) -> TechnicalMemoryPackageManifest {
    serde_json::from_slice(
        &fs::read(root.join(TECHNICAL_MEMORY_PACKAGE_MANIFEST_NAME)).expect("manifest bytes"),
    )
    .expect("canonical package manifest")
}

fn assert_failure(result: &ToolResult, expected: ToolFailureCode) {
    match result.outcome() {
        ToolOutcome::Error { failure } => assert_eq!(failure.code, expected),
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}

fn write_source_manifest_generation(fixture: &Fixture, generation: u64, first_title: &str) {
    let evidence_path = fixture.workspace.path().join("portable_evidence.rs");
    fs::write(
        &evidence_path,
        "fn durable_package() { /* descriptor-safe package evidence */ }\n",
    )
    .expect("source evidence");
    let evidence = fs::read(&evidence_path).expect("source evidence bytes");
    let evidence_digest = MemoryDigest::sha256(&evidence);
    let manifest = json!({
        "schema_version": 1,
        "source_id": "s107-portable-source",
        "generation": generation,
        "lessons": [
            {
                "lesson_id": "portable-package-a-integrity",
                "lesson": {
                    "title": first_title,
                    "kind": "compatibility",
                    "observation": "A final manifest is the only complete-package marker.",
                    "guidance": "Verify every typed part before committing imported state.",
                    "applicability": {"paths": ["portable_evidence.rs"]},
                    "citations": [{
                        "kind": "source_file",
                        "locator": "portable_evidence.rs",
                        "source_version": format!("workspace-file:{evidence_digest}"),
                        "digest": evidence_digest,
                        "line_start": 1,
                        "line_end": 1
                    }],
                    "confidence": "verified_by_test",
                    "sensitivity": "internal",
                    "retention": {"policy": "indefinite"}
                }
            },
            {
                "lesson_id": "portable-package-b-bounds",
                "lesson": {
                    "title": "Portable parts retain fixed allocation bounds",
                    "kind": "performance",
                    "observation": "Each package part is validated before its bounded allocation.",
                    "guidance": "Keep package files within their dedicated persistence class.",
                    "applicability": {"paths": ["portable_evidence.rs"]},
                    "citations": [{
                        "kind": "source_file",
                        "locator": "portable_evidence.rs",
                        "source_version": format!("workspace-file:{evidence_digest}"),
                        "digest": evidence_digest,
                        "line_start": 1,
                        "line_end": 1
                    }],
                    "confidence": "verified_by_test",
                    "sensitivity": "internal",
                    "retention": {"policy": "indefinite"}
                }
            }
        ]
    });
    fs::write(
        fixture.workspace.path().join("MEMORY.md"),
        serde_json::to_vec_pretty(&manifest).expect("source manifest encoding"),
    )
    .expect("source manifest");
}

fn write_source_manifest(fixture: &Fixture) {
    write_source_manifest_generation(fixture, 1, "Portable packages are final-manifest committed");
    let manager = PermissionManager::unrestricted_for_run(&fixture.run);
    let refreshed = fixture.execute(
        &manager,
        &call("refresh-source", "memory_source_refresh", &json!({})),
        None,
    );
    assert!(
        !refreshed.is_error(),
        "source refresh failed: {}",
        refreshed.content()
    );
}

fn assert_imported_source_can_advance_with_mixed_origin_provenance(
    fixture: &Fixture,
    target: &MemoryDb,
) {
    let prior_digest = match target
        .technical_memory_source_status()
        .expect("imported source status before refresh")
    {
        TechnicalMemorySourceStoreStatus::Ready { state, .. } => state.source_digest,
        other => panic!("imported source is not ready before refresh: {other:?}"),
    };
    write_source_manifest_generation(
        fixture,
        2,
        "Portable packages remain refreshable after restoration",
    );
    let manager = PermissionManager::unrestricted_for_run(&fixture.run);
    let refreshed = execute(
        &fixture.run,
        target,
        &manager,
        &call(
            "refresh-imported-source",
            "memory_source_refresh",
            &json!({"expected_source_digest": prior_digest}),
        ),
        None,
    );
    assert!(
        !refreshed.is_error(),
        "imported source refresh failed: {}",
        refreshed.content()
    );
    assert_eq!(
        refreshed.structured().expect("refresh result")["status"],
        "updated"
    );
    assert!(matches!(
        target
            .technical_memory_source_status()
            .expect("imported source status after refresh"),
        TechnicalMemorySourceStoreStatus::Ready { .. }
    ));
}

fn add_review_and_tombstone(fixture: &Fixture) -> (Value, Value) {
    let candidate =
        fixture.save_lesson("save-reviewed", "Descriptor-safe portable technical memory");
    let review = call(
        "review-portable",
        "memory_review",
        &json!({
            "action": "review",
            "logical_id": candidate["logical_id"],
            "expected_record_digest": candidate["record_digest"],
        }),
    );
    let reviewed = authorized_execute(&fixture.run, &fixture.db, &review);
    assert!(
        !reviewed.is_error(),
        "review failed: {}",
        reviewed.content()
    );

    let disposable = fixture.save_lesson("save-tombstone", "Portable tombstones remain causal");
    let manager = PermissionManager::unrestricted_for_run(&fixture.run);
    let deleted = fixture.execute(
        &manager,
        &call(
            "delete-portable",
            "memory_delete",
            &json!({
                "logical_id": disposable["logical_id"],
                "expected_record_digest": disposable["record_digest"],
            }),
        ),
        None,
    );
    assert!(!deleted.is_error(), "delete failed: {}", deleted.content());
    (candidate, disposable)
}

fn assert_complete_scoped_package(
    exported: &ToolResult,
    package_root: &Path,
) -> TechnicalMemoryPackageManifest {
    let exported_value = exported.structured().expect("structured export");
    assert_eq!(exported_value["status"], "completed");
    assert_eq!(exported.artifacts().len(), 1);
    assert!(!exported.content().contains(PRIVATE_LESSON_MARKER));
    assert!(!serde_json::to_string(exported_value)
        .expect("export receipt encoding")
        .contains(LEGACY_PROSE_MARKER));

    let manifest = load_manifest(package_root);
    assert!(
        manifest.revision_count >= 7,
        "review/source/tombstone history"
    );
    assert!(manifest.head_count >= 4, "one head per portable lineage");
    assert!(!manifest.parts.is_empty());
    let package_bytes = fs::read_dir(package_root)
        .expect("package directory")
        .flat_map(|entry| fs::read(entry.expect("package entry").path()).expect("package file"))
        .collect::<Vec<_>>();
    let package_text = String::from_utf8_lossy(&package_bytes);
    assert!(package_text.contains(PRIVATE_LESSON_MARKER));
    assert!(!package_text.contains(LEGACY_PROSE_MARKER));
    manifest
}

fn assert_imported_causal_state(
    source: &Fixture,
    target: &MemoryDb,
    reviewed_candidate: &Value,
    tombstoned_candidate: &Value,
) {
    let reviewed_id = reviewed_candidate["logical_id"]
        .as_str()
        .expect("reviewed logical id")
        .parse()
        .expect("logical id");
    let source_revisions = source
        .db
        .revisions_for_logical_bounded(reviewed_id, 10)
        .expect("source reviewed history");
    let imported_revisions = target
        .revisions_for_logical_bounded(reviewed_id, 10)
        .expect("imported reviewed history");
    assert_eq!(imported_revisions, source_revisions);
    let reviewed = target
        .query_technical_lessons(None, 20, chrono::Utc::now().timestamp())
        .expect("imported reviewed lesson")
        .records
        .into_iter()
        .find(|record| record.logical_id == reviewed_id)
        .expect("reviewed record");
    assert!(reviewed.effectively_host_reviewed);
    assert_eq!(
        reviewed.provenance.origin_store_id,
        source_revisions[0].provenance.origin_store_id
    );
    assert!(matches!(
        target
            .technical_memory_source_status()
            .expect("imported source status"),
        TechnicalMemorySourceStoreStatus::Ready { .. }
    ));
    let tombstoned_id = tombstoned_candidate["logical_id"]
        .as_str()
        .expect("tombstoned logical id")
        .parse()
        .expect("logical id");
    assert_eq!(
        target
            .revisions_for_logical_bounded(tombstoned_id, 10)
            .expect("tombstone history"),
        source
            .db
            .revisions_for_logical_bounded(tombstoned_id, 10)
            .expect("source tombstone history")
    );
    assert!(target
        .memory_list(100)
        .expect("legacy target list")
        .iter()
        .any(|entry| entry.content == "TARGET_LEGACY_PROSE_REMAINS"));
}

fn assert_replay_and_reexport(
    source: &Fixture,
    target: &MemoryDb,
    package_root: &Path,
    snapshot_digest: &MemoryDigest,
) {
    let replay = authorized_execute(
        &source.run,
        target,
        &import_call("import-replay", package_root),
    );
    assert!(
        !replay.is_error(),
        "idempotent import: {}",
        replay.content()
    );
    assert_eq!(
        replay.structured().expect("replay result")["status"],
        "idempotent"
    );

    let reexport_root = source.package_dir("reexported-package");
    let reexported = authorized_execute(
        &source.run,
        target,
        &export_call("export-restored", &reexport_root),
    );
    assert!(
        !reexported.is_error(),
        "re-export: {}",
        reexported.content()
    );
    assert_eq!(
        &load_manifest(&reexport_root).snapshot_digest,
        snapshot_digest
    );
}

#[test]
fn complete_round_trip_preserves_typed_causal_state_and_excludes_legacy_prose() {
    let source = Fixture::new();
    write_source_manifest(&source);
    let (reviewed_candidate, tombstoned_candidate) = add_review_and_tombstone(&source);
    source
        .db
        .memory_save(LEGACY_PROSE_MARKER, &["legacy-session".to_string()])
        .expect("legacy prose fixture");

    let package_root = source.package_dir("complete-package");
    let exported = authorized_execute(
        &source.run,
        &source.db,
        &export_call("export-complete", &package_root),
    );
    assert!(
        !exported.is_error(),
        "export failed: {}",
        exported.content()
    );
    let manifest = assert_complete_scoped_package(&exported, &package_root);

    let target_host = tempfile::tempdir().expect("target host");
    let target = MemoryDb::open_for_workspace(target_host.path(), source.workspace.path())
        .expect("empty target store");
    target
        .memory_save("TARGET_LEGACY_PROSE_REMAINS", &["legacy".to_string()])
        .expect("target legacy fixture");
    let imported = authorized_execute(
        &source.run,
        &target,
        &import_call("import-complete", &package_root),
    );
    assert!(
        !imported.is_error(),
        "import failed: {}",
        imported.content()
    );
    assert_eq!(
        imported.structured().expect("structured import")["status"],
        "imported"
    );

    assert_imported_causal_state(&source, &target, &reviewed_candidate, &tombstoned_candidate);
    assert_replay_and_reexport(&source, &target, &package_root, &manifest.snapshot_digest);
    assert_imported_source_can_advance_with_mixed_origin_provenance(&source, &target);
}

#[test]
fn every_call_requires_fresh_exact_host_authority_and_cancellation_is_truthful() {
    let fixture = Fixture::new();
    fixture.save_lesson("save-authority", "Portable calls are exact capabilities");
    let first_root = fixture.package_dir("first-authority-package");
    let second_root = fixture.package_dir("second-authority-package");
    let approved_call = export_call("export-authority", &first_root);
    let manager = PermissionManager::unrestricted_for_run(&fixture.run);

    assert!(matches!(
        manager.authorize_tool_call(&approved_call, Some(SESSION_ID)),
        AuthorizationResult::NeedsPrompt { .. }
    ));
    assert!(manager
        .approve_tool_call_for_session(
            &approved_call,
            SESSION_ID,
            ApprovalProvenance::InteractiveUser,
        )
        .is_err());
    assert!(manager
        .approve_tool_call_persisted(
            &approved_call,
            Some(SESSION_ID),
            ApprovalProvenance::HostAdministrator,
        )
        .is_err());
    assert!(manager
        .approve_tool_call_once(
            &approved_call,
            Some(SESSION_ID),
            ApprovalProvenance::CoordinatorLeader,
        )
        .is_err());
    assert_failure(
        &fixture.execute(&manager, &approved_call, None),
        ToolFailureCode::PermissionDenied,
    );

    let permit = approve_once(
        &manager,
        &approved_call,
        ApprovalProvenance::InteractiveUser,
    );
    let changed_arguments = export_call("export-authority", &second_root);
    assert_failure(
        &fixture.execute(&manager, &changed_arguments, Some(permit)),
        ToolFailureCode::PermissionDenied,
    );
    assert!(!second_root
        .join(TECHNICAL_MEMORY_PACKAGE_MANIFEST_NAME)
        .exists());

    let cancelled_run = support::test_run_context(fixture.workspace.path());
    let cancelled_manager = PermissionManager::unrestricted_for_run(&cancelled_run);
    let cancelled_call = export_call("export-cancelled", &first_root);
    let permit = approve_once(
        &cancelled_manager,
        &cancelled_call,
        ApprovalProvenance::HostAdministrator,
    );
    let _ = cancelled_run
        .runtime()
        .cancellation()
        .cancel(CancellationReason::User);
    let cancelled = execute(
        &cancelled_run,
        &fixture.db,
        &cancelled_manager,
        &cancelled_call,
        Some(permit),
    );
    assert!(cancelled.is_partial());
    let value = cancelled.structured().expect("cancelled receipt");
    assert_eq!(value["status"], "cancelled");
    assert!(value["package_id"].is_null());
    assert!(value["snapshot_digest"].is_null());
    assert!(!first_root
        .join(TECHNICAL_MEMORY_PACKAGE_MANIFEST_NAME)
        .exists());
}

#[test]
fn tampered_oversized_and_incomplete_packages_fail_before_store_mutation() {
    for corruption in ["tampered", "oversized", "incomplete", "noncanonical"] {
        let source = Fixture::new();
        source.save_lesson("save-corruption", "Package corruption fails closed");
        let package_root = source.package_dir(&format!("{corruption}-package"));
        let exported = authorized_execute(
            &source.run,
            &source.db,
            &export_call(&format!("export-{corruption}"), &package_root),
        );
        assert!(
            !exported.is_error(),
            "fixture export: {}",
            exported.content()
        );
        let manifest = load_manifest(&package_root);
        let part_path = package_root.join(&manifest.parts[0].file_name);
        match corruption {
            "tampered" => {
                let mut bytes = fs::read(&part_path).expect("part bytes");
                let midpoint = bytes.len() / 2;
                bytes[midpoint] ^= 1;
                fs::write(&part_path, bytes).expect("tampered part");
            }
            "oversized" => {
                fs::write(&part_path, vec![b'x'; 4 * 1024 * 1024 + 1]).expect("oversized part");
            }
            "incomplete" => {
                fs::remove_file(package_root.join(TECHNICAL_MEMORY_PACKAGE_MANIFEST_NAME))
                    .expect("remove final marker");
            }
            "noncanonical" => {
                fs::write(
                    package_root.join(TECHNICAL_MEMORY_PACKAGE_MANIFEST_NAME),
                    serde_json::to_vec_pretty(&manifest).expect("noncanonical manifest"),
                )
                .expect("rewrite noncanonical manifest");
            }
            _ => unreachable!(),
        }

        let target_host = tempfile::tempdir().expect("target host");
        let target = MemoryDb::open_for_workspace(target_host.path(), source.workspace.path())
            .expect("empty target");
        let imported = authorized_execute(
            &source.run,
            &target,
            &import_call(&format!("import-{corruption}"), &package_root),
        );
        assert!(imported.is_error(), "{corruption} package was accepted");
        assert!(target
            .query_technical_lessons(None, 20, chrono::Utc::now().timestamp())
            .expect("target query")
            .records
            .is_empty());
    }
}

#[cfg(unix)]
#[test]
fn linked_package_parts_and_wrong_workspace_packages_fail_closed() {
    use std::os::unix::fs::symlink;

    let source = Fixture::new();
    source.save_lesson("save-link", "Portable package leaves are regular files");
    let linked_root = source.package_dir("linked-package");
    let exported = authorized_execute(
        &source.run,
        &source.db,
        &export_call("export-linked", &linked_root),
    );
    assert!(!exported.is_error());
    let manifest = load_manifest(&linked_root);
    let part = linked_root.join(&manifest.parts[0].file_name);
    let outside = source.workspace.path().join("outside-part");
    fs::copy(&part, &outside).expect("copy outside part");
    fs::remove_file(&part).expect("remove canonical part");
    symlink(&outside, &part).expect("linked package part");
    let linked_target_host = tempfile::tempdir().expect("linked target host");
    let linked_target =
        MemoryDb::open_for_workspace(linked_target_host.path(), source.workspace.path())
            .expect("linked target");
    let linked = authorized_execute(
        &source.run,
        &linked_target,
        &import_call("import-linked", &linked_root),
    );
    assert!(linked.is_error());
    assert!(linked_target
        .query_technical_lessons(None, 20, chrono::Utc::now().timestamp())
        .expect("linked target query")
        .records
        .is_empty());

    let valid_root = source.package_dir("wrong-workspace-package");
    let exported = authorized_execute(
        &source.run,
        &source.db,
        &export_call("export-wrong-workspace", &valid_root),
    );
    assert!(!exported.is_error());
    let wrong_workspace = tempfile::tempdir().expect("wrong workspace");
    let wrong_host = tempfile::tempdir().expect("wrong host");
    let wrong_db = MemoryDb::open_for_workspace(wrong_host.path(), wrong_workspace.path())
        .expect("wrong-workspace store");
    let wrong_run = ToolRunContext::builder(SessionId::new(), wrong_workspace.path())
        .working_directory(wrong_workspace.path())
        .read_only_roots(vec![valid_root.clone()])
        .read_write_roots(Vec::new())
        .environment_grants(HashMap::new())
        .workspace_access(WorkspaceAccess::ReadWrite)
        .process(false)
        .network(false)
        .secrets(false)
        .provider("s107-wrong-workspace")
        .build()
        .expect("wrong-workspace run");
    let wrong_run = Arc::new(wrong_run);
    let wrong = authorized_execute(
        &wrong_run,
        &wrong_db,
        &import_call("import-wrong-workspace", &valid_root),
    );
    assert_failure(&wrong, ToolFailureCode::InvalidInput);
    assert!(wrong_db
        .query_technical_lessons(None, 20, chrono::Utc::now().timestamp())
        .expect("wrong target query")
        .records
        .is_empty());
}

#[test]
fn empty_package_import_is_an_exact_idempotent_replay() {
    let source = Fixture::new();
    let package_root = source.package_dir("empty-package");
    let exported = authorized_execute(
        &source.run,
        &source.db,
        &export_call("export-empty", &package_root),
    );
    assert!(!exported.is_error(), "empty export: {}", exported.content());
    let manifest = load_manifest(&package_root);
    assert_eq!(manifest.entry_count, 0);
    assert!(manifest.parts.is_empty());

    let target_host = tempfile::tempdir().expect("empty target host");
    let target = MemoryDb::open_for_workspace(target_host.path(), source.workspace.path())
        .expect("empty target");
    let imported = authorized_execute(
        &source.run,
        &target,
        &import_call("import-empty", &package_root),
    );
    assert!(!imported.is_error(), "empty import: {}", imported.content());
    assert_eq!(
        imported.structured().expect("empty import result")["status"],
        "idempotent"
    );
}
