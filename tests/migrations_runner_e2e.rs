//! Runtime acceptance coverage for the fail-closed startup migration gate.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::unwrap_used)]

use std::process::Command;

use openclaudia::migrations::{
    run_all, run_all_count_applied, MigrationContext, MigrationFailureKind, MigrationOutcome,
};
use openclaudia::state::{SessionDocument, SessionId, SessionState};
use tempfile::TempDir;

fn sandboxed_ctx() -> (TempDir, MigrationContext) {
    let root = tempfile::tempdir().expect("migration sandbox");
    let claude_home = root.path().join("claude");
    let openclaudia_data = root.path().join("data/openclaudia");
    std::fs::create_dir_all(&claude_home).expect("Claude root");
    std::fs::create_dir_all(&openclaudia_data).expect("OpenClaudia root");
    let context = MigrationContext::with_paths(claude_home, openclaudia_data);
    (root, context)
}

fn session_path(context: &MigrationContext, id: &str) -> std::path::PathBuf {
    context
        .openclaudia_data
        .join("chat_sessions")
        .join(format!("{id}.json"))
}

fn legacy_fixture(id: &str) -> String {
    include_str!("fixtures/session_legacy_tui.json").replace("legacy-session", id)
}

fn canonical_session(id: &str) -> Vec<u8> {
    let mut state = SessionState::default();
    state.identity.session_id = SessionId::from_raw_unchecked(id);
    let document = SessionDocument::from_state(
        "canonical".to_string(),
        chrono::Utc::now(),
        chrono::Utc::now(),
        "model".to_string(),
        "provider".to_string(),
        state,
    );
    serde_json::to_vec_pretty(&document).expect("canonical session bytes")
}

#[test]
fn first_start_and_restart_reach_deterministic_writable_states() {
    let (_root, context) = sandboxed_ctx();

    let first = run_all(&context);
    assert!(
        first.is_writable(),
        "empty supported stores must initialize"
    );
    assert_eq!(first.reports().len(), 2);
    assert!(first
        .reports()
        .iter()
        .all(|report| matches!(report.outcome, MigrationOutcome::Current)));
    assert!(!context.claude_home.join("projects").exists());
    assert!(!context.openclaudia_data.join("chat_sessions").exists());

    let second = run_all(&context);
    assert!(second.is_writable(), "restart must reconcile cleanly");
    assert!(second
        .reports()
        .iter()
        .all(|report| matches!(report.outcome, MigrationOutcome::Current)));
}

#[test]
fn count_wrapper_preserves_terminal_failure_instead_of_returning_a_false_count() {
    let (_root, context) = sandboxed_ctx();
    let projects = context.claude_home.join("projects");
    std::fs::create_dir_all(&projects).expect("projects root");
    std::fs::write(projects.join(".schema-version.json"), b"{broken").expect("malformed marker");

    let error = run_all_count_applied(&context)
        .expect_err("count wrapper must not erase the migration failure");

    assert_eq!(
        error.cause().kind(),
        MigrationFailureKind::InvalidPersistentState
    );
}

#[test]
fn complete_preflight_prevents_partial_publication_on_invalid_session() {
    let (_root, context) = sandboxed_ctx();
    let sessions = context.openclaudia_data.join("chat_sessions");
    std::fs::create_dir_all(&sessions).expect("session store");
    let valid_path = session_path(&context, "a-valid");
    let valid_original = legacy_fixture("a-valid");
    std::fs::write(&valid_path, &valid_original).expect("legacy session");
    let broken_path = session_path(&context, "z-broken");
    let broken_original = b"{persisted-secret-broken-json";
    std::fs::write(&broken_path, broken_original).expect("broken session");

    let status = run_all(&context);
    let error = status
        .into_writable()
        .expect_err("invalid session must block startup");

    assert_eq!(error.migration_id(), "m001-session-state-v1");
    assert_eq!(
        error.cause().kind(),
        MigrationFailureKind::InvalidPersistentState
    );
    assert_eq!(error.cause().committed_artifacts(), 0);
    assert_eq!(
        std::fs::read_to_string(valid_path).expect("valid legacy retained"),
        valid_original
    );
    assert_eq!(
        std::fs::read(broken_path).expect("broken bytes retained"),
        broken_original
    );
    assert!(!error.to_string().contains("persisted-secret-broken-json"));
}

#[test]
fn restart_reconciles_a_preexisting_partial_migration_prefix() {
    let (_root, context) = sandboxed_ctx();
    let sessions = context.openclaudia_data.join("chat_sessions");
    std::fs::create_dir_all(&sessions).expect("session store");
    let current_path = session_path(&context, "a-current");
    let current_bytes = canonical_session("a-current");
    std::fs::write(&current_path, &current_bytes).expect("current session");
    let legacy_path = session_path(&context, "z-legacy");
    std::fs::write(&legacy_path, legacy_fixture("z-legacy")).expect("legacy session");

    let recovered = run_all(&context);
    assert!(recovered.is_writable());
    let session_report = recovered
        .reports()
        .iter()
        .find(|report| report.id == "m001-session-state-v1")
        .expect("session migration report");
    assert!(matches!(
        session_report.outcome,
        MigrationOutcome::Applied {
            changed_artifacts: 1
        }
    ));
    assert_eq!(
        std::fs::read(&current_path).expect("current session retained"),
        current_bytes
    );
    let migrated: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&legacy_path).expect("migrated legacy session"))
            .expect("valid migrated JSON");
    assert_eq!(migrated["session_state"]["version"], 1);
    assert!(migrated.get("messages").is_none());

    let restart = run_all(&context);
    assert!(restart.is_writable());
    assert!(restart
        .reports()
        .iter()
        .all(|report| matches!(report.outcome, MigrationOutcome::Current)));
}

#[test]
fn injected_real_migration_failure_exits_before_print_agent_startup() {
    let root = tempfile::tempdir().expect("binary migration sandbox");
    let home = root.path().join("home");
    let data_home = root.path().join("data");
    let claude_home = root.path().join("claude");
    let sessions = data_home.join("openclaudia/chat_sessions");
    std::fs::create_dir_all(&home).expect("home");
    std::fs::create_dir_all(&claude_home).expect("Claude home");
    std::fs::create_dir_all(&sessions).expect("session store");
    let secret = "persisted-binary-secret";
    std::fs::write(
        sessions.join("sensitive-session-name.json"),
        format!("{{{secret}"),
    )
    .expect("malformed session");

    let output = Command::new(env!("CARGO_BIN_EXE_openclaudia"))
        .arg("--print")
        .arg("this prompt must never reach a provider")
        .env("HOME", &home)
        .env("XDG_DATA_HOME", &data_home)
        .env("CLAUDE_CONFIG_HOME_DIR", &claude_home)
        .output()
        .expect("run OpenClaudia binary");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "migration failure must be non-zero"
    );
    assert!(
        stderr.contains("migration_invalid_persistent_state"),
        "typed migration code missing: {stderr}"
    );
    assert!(
        stderr.contains("recovery:"),
        "actionable recovery missing: {stderr}"
    );
    assert!(!stderr.contains(secret));
    assert!(!stderr.contains("sensitive-session-name"));
    assert!(
        output.stdout.is_empty(),
        "agent emitted output despite gate"
    );
    assert_eq!(
        std::fs::read_to_string(sessions.join("sensitive-session-name.json"))
            .expect("malformed session retained"),
        format!("{{{secret}")
    );
}
