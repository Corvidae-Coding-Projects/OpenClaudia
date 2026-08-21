//! S-053 end-to-end contracts for logical identity and replica convergence.

use openclaudia::config::MemoryConfig;
use openclaudia::memory::{
    ApplyRevisionOutcome, MemoryAttribution, MemoryDb, MemoryDigest, MemoryProvenance,
    MemoryRecordScope, MemoryRevision, MemorySourceEvidence, MemorySourceKind,
};
use openclaudia::team_memory::{MemoryScope, TeamMemoryStore};
use tempfile::TempDir;

fn provenance(source: &str, scope: MemoryRecordScope) -> MemoryProvenance {
    MemoryProvenance::new(
        MemorySourceEvidence::new(
            MemorySourceKind::ToolOutcome,
            source.to_string(),
            "workspace-generation-7".to_string(),
            MemoryDigest::for_fields(b"memory-identity-e2e", &[source.as_bytes()]),
        ),
        MemoryAttribution::new(
            "agent-run-42".to_string(),
            None,
            Some("repo-openclaudia".to_string()),
        ),
        scope,
    )
}

#[test]
fn one_revision_is_idempotent_across_independent_stores() {
    let temp = TempDir::new().unwrap();
    let left = MemoryDb::open(&temp.path().join("left.db")).unwrap();
    let right = MemoryDb::open(&temp.path().join("right.db")).unwrap();
    let revision = MemoryRevision::new(
        "Rust 1.98 is the repository toolchain".to_string(),
        vec!["toolchain".to_string()],
        provenance("verified-toolchain-receipt", MemoryRecordScope::TeamShared),
    );

    assert_eq!(
        left.apply_revision(&revision).unwrap(),
        ApplyRevisionOutcome::Advanced
    );
    assert_eq!(
        right.apply_revision(&revision).unwrap(),
        ApplyRevisionOutcome::Advanced
    );
    assert_eq!(
        right.apply_revision(&revision).unwrap(),
        ApplyRevisionOutcome::Idempotent
    );
    let left_row = left.memory_list(10).unwrap().pop().unwrap();
    let right_row = right.memory_list(10).unwrap().pop().unwrap();
    assert_eq!(left_row.logical_id, right_row.logical_id);
    assert_eq!(left_row.record_digest, right_row.record_digest);
}

#[test]
fn equal_prose_from_distinct_evidence_remains_distinct() {
    let temp = TempDir::new().unwrap();
    let db = MemoryDb::open(&temp.path().join("memory.db")).unwrap();
    let first = MemoryRevision::new(
        "retry generation-checked writes".to_string(),
        vec!["persistence".to_string()],
        provenance("failure-a", MemoryRecordScope::UserPrivate),
    );
    let second = MemoryRevision::new(
        "retry generation-checked writes".to_string(),
        vec!["persistence".to_string()],
        provenance("failure-b", MemoryRecordScope::UserPrivate),
    );
    db.apply_revision(&first).unwrap();
    db.apply_revision(&second).unwrap();

    let rows = db.memory_list(10).unwrap();
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].logical_id, rows[1].logical_id);
    assert_eq!(rows[0].content_digest, rows[1].content_digest);
}

#[test]
fn team_both_write_has_one_logical_result_and_one_global_limit() {
    let temp = TempDir::new().unwrap();
    let user_path = temp.path().join("user").join("memory.db");
    std::fs::create_dir_all(user_path.parent().unwrap()).unwrap();
    let config = MemoryConfig {
        team_memory_path: Some(temp.path().join("team")),
    };
    let store = TeamMemoryStore::open(&user_path, &config).unwrap();
    store
        .save_archival(
            MemoryScope::Both,
            "cargo tests run single-threaded after a four-job build",
            &["tests".to_string()],
        )
        .unwrap();
    store
        .save_archival(MemoryScope::User, "private lesson", &[])
        .unwrap();

    let merged = store.list_archival(MemoryScope::Both, 1).unwrap();
    assert_eq!(merged.len(), 1);
    let shared_user = store
        .user()
        .memory_search("cargo tests run single-threaded", 10)
        .unwrap()
        .pop()
        .unwrap();
    let shared_team = store
        .team()
        .unwrap()
        .memory_search("cargo tests run single-threaded", 10)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(shared_user.logical_id, shared_team.logical_id);
    assert_eq!(shared_user.record_digest, shared_team.record_digest);
}

#[test]
fn concurrent_offline_corrections_surface_both_heads() {
    let temp = TempDir::new().unwrap();
    let user_path = temp.path().join("user").join("memory.db");
    std::fs::create_dir_all(user_path.parent().unwrap()).unwrap();
    let config = MemoryConfig {
        team_memory_path: Some(temp.path().join("team")),
    };
    let store = TeamMemoryStore::open(&user_path, &config).unwrap();
    let user_id = store
        .save_archival(MemoryScope::Both, "initial command", &[])
        .unwrap();
    let root = store.user().revision_for_row(user_id).unwrap().unwrap();
    let user_revision = root
        .successor(
            "cargo +1.98.0 test".to_string(),
            Vec::new(),
            provenance("user-correction", MemoryRecordScope::TeamShared),
        )
        .unwrap();
    let team_revision = root
        .successor(
            "cargo test".to_string(),
            Vec::new(),
            provenance("team-correction", MemoryRecordScope::TeamShared),
        )
        .unwrap();
    store.user().apply_revision(&user_revision).unwrap();
    store
        .team()
        .unwrap()
        .apply_revision(&team_revision)
        .unwrap();
    assert_eq!(store.reconcile_replica_histories().unwrap(), 2);
    assert_eq!(
        store.user().revision_heads(root.logical_id).unwrap().len(),
        2
    );
    assert_eq!(
        store
            .team()
            .unwrap()
            .revision_heads(root.logical_id)
            .unwrap()
            .len(),
        2
    );

    let merged = store.list_archival(MemoryScope::Both, 10).unwrap();
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].entry.conflict_heads.len(), 2);
    assert!(merged[0]
        .entry
        .conflict_heads
        .iter()
        .any(|head| head.record_digest == user_revision.record_digest));
    assert!(merged[0]
        .entry
        .conflict_heads
        .iter()
        .any(|head| head.record_digest == team_revision.record_digest));
}

#[test]
fn replacing_a_team_database_cannot_inherit_the_old_replica_log() {
    let temp = TempDir::new().unwrap();
    let user_path = temp.path().join("user").join("memory.db");
    std::fs::create_dir_all(user_path.parent().unwrap()).unwrap();
    let team_path = temp.path().join("team");
    let config = MemoryConfig {
        team_memory_path: Some(team_path.clone()),
    };
    let store = TeamMemoryStore::open(&user_path, &config).unwrap();
    let old_team_id = store.team_store_id().unwrap();
    store
        .save_archival(
            MemoryScope::Both,
            "this lesson belongs only to the original replica set",
            &[],
        )
        .unwrap();
    drop(store);

    std::fs::rename(&team_path, temp.path().join("retired-team")).unwrap();
    let Err(error) = TeamMemoryStore::open(&user_path, &config) else {
        panic!("replacement team database inherited stale sync authority");
    };
    assert!(error.to_string().contains("different team store"));

    let replacement = MemoryDb::open(&team_path.join("memory.db")).unwrap();
    assert_ne!(replacement.store_id().unwrap(), old_team_id);
    assert!(replacement.memory_list(10).unwrap().is_empty());
}
