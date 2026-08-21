//! S-053 end-to-end contracts for logical identity and replica convergence.

use openclaudia::config::MemoryConfig;
use openclaudia::memory::{
    ApplyRevisionOutcome, MemoryAttribution, MemoryDb, MemoryDigest, MemoryProvenance,
    MemoryRecordScope, MemoryRevision, MemorySourceEvidence, MemorySourceKind,
};
use openclaudia::team_memory::TeamMemoryStore;
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
fn shared_path_cannot_activate_team_replication() {
    let temp = TempDir::new().unwrap();
    let user_path = temp.path().join("user").join("memory.db");
    std::fs::create_dir_all(user_path.parent().unwrap()).unwrap();
    let config = MemoryConfig {
        team_memory_path: Some(temp.path().join("team")),
        ..MemoryConfig::default()
    };
    let Err(error) = TeamMemoryStore::open(&user_path, &config) else {
        panic!("a path must not create team authority");
    };
    assert!(error.to_string().contains("paths are not authorization"));
    assert!(!temp.path().join("team").exists());
}

#[test]
fn concurrent_offline_corrections_surface_both_heads() {
    let temp = TempDir::new().unwrap();
    let left = MemoryDb::open(&temp.path().join("left.db")).unwrap();
    let right = MemoryDb::open(&temp.path().join("right.db")).unwrap();
    let root = MemoryRevision::new(
        "initial command".to_string(),
        Vec::new(),
        provenance("shared-root", MemoryRecordScope::TeamShared),
    );
    left.apply_revision(&root).unwrap();
    right.apply_revision(&root).unwrap();
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
    left.apply_revision(&user_revision).unwrap();
    right.apply_revision(&team_revision).unwrap();
    left.apply_revision(&team_revision).unwrap();
    right.apply_revision(&user_revision).unwrap();
    let left_heads = left.revision_heads(root.logical_id).unwrap();
    let right_heads = right.revision_heads(root.logical_id).unwrap();
    assert_eq!(left_heads.len(), 2);
    assert_eq!(left_heads, right_heads);
    assert!(left_heads
        .iter()
        .any(|head| head.record_digest == user_revision.record_digest));
    assert!(left_heads
        .iter()
        .any(|head| head.record_digest == team_revision.record_digest));
}

#[test]
fn replacing_a_database_at_a_configured_path_still_cannot_create_authority() {
    let temp = TempDir::new().unwrap();
    let user_path = temp.path().join("user").join("memory.db");
    std::fs::create_dir_all(user_path.parent().unwrap()).unwrap();
    let team_path = temp.path().join("team");
    let config = MemoryConfig {
        team_memory_path: Some(team_path.clone()),
        ..MemoryConfig::default()
    };
    std::fs::create_dir_all(&team_path).unwrap();
    let first = MemoryDb::open(&team_path.join("memory.db")).unwrap();
    let first_id = first.store_id().unwrap();
    drop(first);
    std::fs::rename(&team_path, temp.path().join("retired-team")).unwrap();
    std::fs::create_dir_all(&team_path).unwrap();
    let replacement = MemoryDb::open(&team_path.join("memory.db")).unwrap();
    assert_ne!(replacement.store_id().unwrap(), first_id);
    drop(replacement);
    let Err(error) = TeamMemoryStore::open(&user_path, &config) else {
        panic!("replacement path still is not authority");
    };
    assert!(error.to_string().contains("paths are not authorization"));
}
