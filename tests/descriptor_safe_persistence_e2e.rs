//! Public-contract tests for S-031 descriptor-safe persistence.
//!
//! These tests use only the exported API and real filesystem objects. Fault
//! injection and process-crash boundaries live beside the private backend;
//! this suite independently proves that consumers receive the intended typed
//! generations and cannot redirect a target through a parent link.

#![allow(clippy::expect_used, clippy::missing_panics_doc)]

#[cfg(any(unix, windows))]
use openclaudia::persistence::{CommitState, FileClass, StorageGeneration};
use openclaudia::persistence::{PersistenceError, PersistentStorage};

#[cfg(any(unix, windows))]
#[test]
fn public_commit_observe_and_retry_contract_is_generation_bound() {
    let root = tempfile::tempdir().expect("storage root");
    let storage = PersistentStorage::open(root.path()).expect("open pinned root");

    let committed = storage
        .commit(
            "state.json",
            FileClass::State,
            StorageGeneration::Missing,
            b"generation-one",
        )
        .expect("durable commit");
    assert_eq!(committed.state(), CommitState::CommittedDurable);
    assert_eq!(committed.target(), std::path::Path::new("state.json"));
    assert_eq!(committed.root(), storage.root_id());

    let observed = storage
        .read("state.json", FileClass::State)
        .expect("bounded descriptor read");
    assert_eq!(observed.generation(), committed.generation());
    observed.expose_bytes(|bytes| assert_eq!(bytes, Some(b"generation-one".as_slice())));

    let recovered = storage
        .commit(
            "state.json",
            FileClass::State,
            StorageGeneration::Missing,
            b"generation-one",
        )
        .expect("idempotent retry");
    assert_eq!(recovered.state(), CommitState::Recovered);
    assert_eq!(recovered.generation(), committed.generation());
}

#[cfg(any(unix, windows))]
#[test]
fn public_parent_link_attempt_cannot_mutate_outside_root() {
    let root = tempfile::tempdir().expect("storage root");
    let outside = tempfile::tempdir().expect("outside root");
    let outside_target = outside.path().join("state.json");
    std::fs::write(&outside_target, b"outside-sentinel").expect("outside sentinel");
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), root.path().join("linked")).expect("parent symlink");
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(outside.path(), root.path().join("linked"))
        .expect("parent directory reparse point");
    let storage = PersistentStorage::open(root.path()).expect("open pinned root");

    assert!(matches!(
        storage.commit(
            "linked/state.json",
            FileClass::State,
            StorageGeneration::Missing,
            b"redirected",
        ),
        Err(PersistenceError::InvalidTarget { .. })
    ));
    assert_eq!(
        std::fs::read(outside_target).expect("outside target remains"),
        b"outside-sentinel"
    );
}

#[cfg(any(unix, windows))]
#[test]
fn public_independent_writers_cannot_overwrite_a_newer_generation() {
    let root = tempfile::tempdir().expect("storage root");
    let first = PersistentStorage::open(root.path()).expect("first root handle");
    let second = PersistentStorage::open(root.path()).expect("second root handle");
    let initial = first
        .commit(
            "state.json",
            FileClass::State,
            StorageGeneration::Missing,
            b"initial",
        )
        .expect("initial generation");

    let newer = first
        .commit(
            "state.json",
            FileClass::State,
            initial.generation(),
            b"newer",
        )
        .expect("newer generation");
    let conflict = second
        .commit(
            "state.json",
            FileClass::State,
            initial.generation(),
            b"stale-overwrite",
        )
        .expect_err("stale writer must conflict");
    assert_eq!(conflict.observed_generation(), Some(newer.generation()));
    assert!(matches!(conflict, PersistenceError::Conflict { .. }));
    first
        .read("state.json", FileClass::State)
        .expect("final state")
        .expose_bytes(|bytes| assert_eq!(bytes, Some(b"newer".as_slice())));
}

#[cfg(any(unix, windows))]
#[test]
fn public_credential_observation_is_explicit_and_debug_redacted() {
    let root = tempfile::tempdir().expect("storage root");
    let storage = PersistentStorage::open(root.path()).expect("open pinned root");
    let receipt = storage
        .commit(
            "credential.json",
            FileClass::Credentials,
            StorageGeneration::Missing,
            b"public-credential-sentinel",
        )
        .expect("credential commit");
    let observed = storage
        .read("credential.json", FileClass::Credentials)
        .expect("credential observation");

    assert_eq!(observed.class(), FileClass::Credentials);
    observed.expose_bytes(|bytes| {
        assert_eq!(bytes, Some(b"public-credential-sentinel".as_slice()));
    });
    let debug = format!("{observed:?}");
    assert!(!debug.contains("public-credential-sentinel"));
    assert!(!debug.contains(&receipt.generation().to_string()));
}

#[cfg(windows)]
#[test]
fn public_concurrent_windows_writers_publish_one_generation() {
    use std::sync::{Arc, Barrier};

    let root = tempfile::tempdir().expect("storage root");
    let first = PersistentStorage::open(root.path()).expect("first root handle");
    let second = PersistentStorage::open(root.path()).expect("second root handle");
    let verifier = PersistentStorage::open(root.path()).expect("verification root handle");
    let initial = first
        .commit(
            "state.json",
            FileClass::State,
            StorageGeneration::Missing,
            b"initial",
        )
        .expect("initial generation");
    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let first_expected = initial.generation();
    let first_writer = std::thread::spawn(move || {
        first_barrier.wait();
        first.commit(
            "state.json",
            FileClass::State,
            first_expected,
            b"winner-one",
        )
    });
    let second_barrier = Arc::clone(&barrier);
    let second_expected = initial.generation();
    let second_writer = std::thread::spawn(move || {
        second_barrier.wait();
        second.commit(
            "state.json",
            FileClass::State,
            second_expected,
            b"winner-two",
        )
    });
    barrier.wait();
    let first_result = first_writer.join().expect("first writer thread");
    let second_result = second_writer.join().expect("second writer thread");
    let (winner, winner_bytes, conflict) = match (first_result, second_result) {
        (Ok(receipt), Err(error)) => (receipt, b"winner-one".as_slice(), error),
        (Err(error), Ok(receipt)) => (receipt, b"winner-two".as_slice(), error),
        (first, second) => panic!(
            "exactly one stale-generation writer must publish: first={first:?}, second={second:?}"
        ),
    };
    assert!(matches!(conflict, PersistenceError::Conflict { .. }));
    assert_eq!(conflict.observed_generation(), Some(winner.generation()));
    let final_state = verifier
        .read("state.json", FileClass::State)
        .expect("read winning generation");
    assert_eq!(final_state.generation(), winner.generation());
    final_state.expose_bytes(|bytes| assert_eq!(bytes, Some(winner_bytes)));
}

#[cfg(not(any(unix, windows)))]
#[test]
fn unsupported_platform_fails_closed() {
    let error = PersistentStorage::open(std::path::Path::new("C:\\openclaudia"))
        .expect_err("unsupported platform must not use a path fallback");
    assert!(matches!(
        error,
        PersistenceError::UnsupportedPlatform { .. }
    ));
}
