use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tempfile::TempDir;

use super::*;

#[derive(Clone, Default)]
struct TraceWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for TraceWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for TraceWriter {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

impl TraceWriter {
    fn text(&self) -> String {
        String::from_utf8_lossy(
            &self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
        .into_owned()
    }
}

struct TestContext {
    _root: TempDir,
    ctx: MigrationContext,
}

impl TestContext {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temporary migration root");
        let claude_home = root.path().join("claude");
        let openclaudia_data = root.path().join("data/openclaudia");
        let workspace = root.path().join("workspace");
        std::fs::create_dir_all(&claude_home).expect("Claude root");
        std::fs::create_dir_all(&openclaudia_data).expect("OpenClaudia root");
        std::fs::create_dir_all(&workspace).expect("workspace root");
        let ctx =
            MigrationContext::with_paths_and_workspace(claude_home, openclaudia_data, workspace);
        Self { _root: root, ctx }
    }
}

struct FakeMigration {
    id: &'static str,
    policy: RunPolicy,
    outcome: MigrationOutcome,
    calls: Arc<AtomicUsize>,
}

impl Migration for FakeMigration {
    fn id(&self) -> &'static str {
        self.id
    }

    fn description(&self) -> &'static str {
        "test migration"
    }

    fn store(&self) -> MigrationStore {
        MigrationStore::OpenClaudiaData
    }

    fn run_policy(&self) -> RunPolicy {
        self.policy
    }

    fn run(&self, _ctx: &MigrationContext) -> MigrationOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.outcome.clone()
    }
}

struct PanickingMigration;

impl Migration for PanickingMigration {
    fn id(&self) -> &'static str {
        "panic-test"
    }

    fn description(&self) -> &'static str {
        "panic containment test"
    }

    fn store(&self) -> MigrationStore {
        MigrationStore::OpenClaudiaData
    }

    fn run(&self, _ctx: &MigrationContext) -> MigrationOutcome {
        panic!("synthetic migration panic payload")
    }
}

fn fake(
    id: &'static str,
    outcome: MigrationOutcome,
    calls: Arc<AtomicUsize>,
) -> Box<dyn Migration> {
    Box::new(FakeMigration {
        id,
        policy: RunPolicy::Idempotent,
        outcome,
        calls,
    })
}

#[test]
fn failure_stops_later_migrations_and_requires_recovery() {
    let test = TestContext::new();
    let first_calls = Arc::new(AtomicUsize::new(0));
    let later_calls = Arc::new(AtomicUsize::new(0));
    let failure = MigrationFailure::new(
        MigrationFailureKind::InvalidPersistentState,
        MigrationStore::OpenClaudiaData,
        "validate test store",
    );

    let status = run_registered(
        &test.ctx,
        vec![
            fake(
                "failing",
                MigrationOutcome::Failed(failure),
                Arc::clone(&first_calls),
            ),
            fake(
                "must-not-run",
                MigrationOutcome::Applied {
                    changed_artifacts: 1,
                },
                Arc::clone(&later_calls),
            ),
        ],
    );

    assert!(!status.is_writable());
    assert_eq!(first_calls.load(Ordering::SeqCst), 1);
    assert_eq!(later_calls.load(Ordering::SeqCst), 0);
    assert_eq!(status.reports().len(), 1);
    let error = status
        .into_writable()
        .expect_err("failed migration must close writable startup");
    assert_eq!(error.migration_id(), "failing");
    assert_eq!(
        error.cause().kind(),
        MigrationFailureKind::InvalidPersistentState
    );
}

#[test]
fn applied_and_current_reports_reach_writable_terminal_state() {
    let test = TestContext::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let status = run_registered(
        &test.ctx,
        vec![
            fake(
                "applied",
                MigrationOutcome::Applied {
                    changed_artifacts: 2,
                },
                Arc::clone(&calls),
            ),
            fake("current", MigrationOutcome::Current, Arc::clone(&calls)),
        ],
    );

    assert!(status.is_writable());
    let reports = status
        .into_writable()
        .expect("complete migrations permit writable startup");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(reports.len(), 2);
}

#[test]
fn relative_context_is_rejected_before_migration_or_store_creation() {
    let calls = Arc::new(AtomicUsize::new(0));
    let context = MigrationContext::with_paths(
        PathBuf::from("relative-claude"),
        PathBuf::from("relative-openclaudia"),
    );
    assert!(!context.openclaudia_data.exists());

    let error = run_registered(
        &context,
        vec![fake(
            "must-not-run",
            MigrationOutcome::Current,
            Arc::clone(&calls),
        )],
    )
    .into_writable()
    .expect_err("relative roots cannot grant startup migration authority");

    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(error.migration_id(), "startup-context");
    assert_eq!(
        error.cause().kind(),
        MigrationFailureKind::ContextUnavailable
    );
    assert!(!context.openclaudia_data.exists());
}

#[test]
fn once_only_registration_is_rejected_before_side_effect() {
    let test = TestContext::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let migration: Box<dyn Migration> = Box::new(FakeMigration {
        id: "unsafe-once-only",
        policy: RunPolicy::OnceOnly,
        outcome: MigrationOutcome::Applied {
            changed_artifacts: 1,
        },
        calls: Arc::clone(&calls),
    });

    let error = run_registered(&test.ctx, vec![migration])
        .into_writable()
        .expect_err("once-only startup work cannot be transactionally retried");

    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        error.cause().kind(),
        MigrationFailureKind::NonIdempotentRegistration
    );
}

#[test]
fn panic_closes_startup_and_typed_diagnostic_omits_payload() {
    let test = TestContext::new();
    let error = run_registered(&test.ctx, vec![Box::new(PanickingMigration)])
        .into_writable()
        .expect_err("migration panic must close startup");
    let diagnostic = error.to_string();

    assert_eq!(
        error.cause().kind(),
        MigrationFailureKind::MigrationPanicked
    );
    assert!(
        !diagnostic.contains("synthetic migration panic payload"),
        "the typed returned diagnostic must not copy the panic payload"
    );
}

#[cfg(unix)]
#[test]
fn competing_startup_lock_reaches_bounded_recovery_state() {
    let test = TestContext::new();
    let held = MigrationLock::acquire(&test.ctx).expect("first migration lock");
    let started = Instant::now();

    let error = run_registered(&test.ctx, Vec::new())
        .into_writable()
        .expect_err("second runner must not proceed without the store lock");

    assert_eq!(error.migration_id(), "startup-store-lock");
    assert_eq!(error.cause().kind(), MigrationFailureKind::LockUnavailable);
    assert!(started.elapsed() < Duration::from_secs(1));
    drop(held);
    assert!(run_registered(&test.ctx, Vec::new()).is_writable());
}

#[test]
fn malformed_owned_manifest_fails_closed_without_exposing_stored_text() {
    let test = TestContext::new();
    let marker = test
        .ctx
        .openclaudia_data
        .join(".openclaudia-session-schema.json");
    let secret = "persisted-secret-marker-value";
    std::fs::write(&marker, format!("{{not-json-{secret}"))
        .expect("write malformed owned manifest");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600))
            .expect("owner-private malformed manifest");
    }

    let trace = TraceWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(trace.clone())
        .finish();
    let status = tracing::dispatcher::with_default(&tracing::Dispatch::new(subscriber), || {
        run_all(&test.ctx)
    });
    let error = status
        .into_writable()
        .expect_err("malformed marker must block startup");
    let diagnostic = error.to_string();

    assert_eq!(
        error.cause().kind(),
        MigrationFailureKind::InvalidPersistentState
    );
    assert!(!diagnostic.contains(secret));
    let trace = trace.text();
    assert!(trace.contains("m002-owned-session-schema-v1"));
    assert!(trace.contains("migration_invalid_persistent_state"));
    assert!(trace.contains("recovery="));
    assert!(!trace.contains(secret));
    assert_eq!(
        std::fs::read_to_string(marker).expect("malformed marker retained"),
        format!("{{not-json-{secret}")
    );
}

#[test]
fn foreign_marker_is_preserved_and_import_observation_is_owned() {
    let test = TestContext::new();
    let projects = test.ctx.claude_home.join("projects");
    std::fs::create_dir_all(&projects).expect("projects root");
    let marker = projects.join(".schema-version.json");
    let original = r#"{"other_producer": 7, "transcripts": 0}"#;
    std::fs::write(&marker, original).expect("write foreign marker");

    let first = run_all(&test.ctx);
    assert!(
        first.is_writable(),
        "foreign marker must be observed read-only"
    );
    let first_reports = first.into_writable().expect("first reports");
    assert!(matches!(
        first_reports[1].outcome,
        MigrationOutcome::Applied {
            changed_artifacts: 1
        }
    ));
    assert_eq!(
        std::fs::read_to_string(&marker).expect("read foreign marker"),
        original
    );
    let owned: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            test.ctx
                .openclaudia_data
                .join(".openclaudia-session-schema.json"),
        )
        .expect("owned manifest"),
    )
    .expect("valid owned manifest");
    assert_eq!(owned["producer"], "openclaudia");
    assert_eq!(owned["session_documents"]["minimum"], 0);
    assert_eq!(owned["session_documents"]["current"], 1);
    assert_eq!(
        owned["foreign_transcript_import"]["status"],
        "claimed_compatible"
    );

    let bytes = std::fs::read(
        test.ctx
            .openclaudia_data
            .join(".openclaudia-session-schema.json"),
    )
    .expect("read first owned generation");
    let second = run_all(&test.ctx);
    assert!(second.is_writable());
    assert!(matches!(
        second.reports()[1].outcome,
        MigrationOutcome::Current
    ));
    assert_eq!(
        std::fs::read(
            test.ctx
                .openclaudia_data
                .join(".openclaudia-session-schema.json")
        )
        .expect("read second owned generation"),
        bytes
    );
    assert_eq!(
        std::fs::read_to_string(marker).expect("foreign marker retained"),
        original
    );
}

#[test]
fn future_foreign_claim_is_recorded_without_granting_startup_authority() {
    let test = TestContext::new();
    let projects = test.ctx.claude_home.join("projects");
    std::fs::create_dir_all(&projects).expect("projects root");
    let marker = projects.join(".schema-version.json");
    let original = br#"{"transcripts": 999}"#;
    std::fs::write(&marker, original).expect("write future marker");

    let status = run_all(&test.ctx);

    assert!(status.is_writable());
    assert_eq!(
        std::fs::read(&marker).expect("future marker retained"),
        original
    );
    let owned: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            test.ctx
                .openclaudia_data
                .join(".openclaudia-session-schema.json"),
        )
        .expect("owned manifest"),
    )
    .expect("valid owned manifest");
    assert_eq!(
        owned["foreign_transcript_import"]["status"],
        "claimed_future"
    );
    assert_eq!(owned["foreign_transcript_import"]["schema_version"], 999);
}

#[test]
fn existing_foreign_store_without_marker_remains_unmodified() {
    let test = TestContext::new();
    let projects = test.ctx.claude_home.join("projects");
    std::fs::create_dir_all(&projects).expect("projects root");
    let marker = projects.join(".schema-version.json");

    let first = run_all(&test.ctx);
    assert!(first.is_writable());
    assert!(matches!(
        first.reports()[1].outcome,
        MigrationOutcome::Applied {
            changed_artifacts: 1
        }
    ));
    assert!(!marker.exists());
    let owned = test
        .ctx
        .openclaudia_data
        .join(".openclaudia-session-schema.json");
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&owned).expect("owned schema manifest"))
            .expect("valid owned schema manifest");
    assert_eq!(
        value["foreign_transcript_import"]["status"],
        "claimed_compatible"
    );
    assert_eq!(value["foreign_transcript_import"]["schema_version"], 1);
    assert_eq!(
        value["foreign_transcript_import"]["source_generation"]["state"],
        "missing"
    );

    let first_generation = std::fs::read(&owned).expect("first owned generation");
    let second = run_all(&test.ctx);
    assert!(second.is_writable());
    assert!(matches!(
        second.reports()[1].outcome,
        MigrationOutcome::Current
    ));
    assert_eq!(
        std::fs::read(owned).expect("second owned generation"),
        first_generation
    );
    assert!(!marker.exists());
}

#[test]
fn absent_foreign_and_session_stores_remain_absent_and_writable_on_restart() {
    let test = TestContext::new();

    let first = run_all(&test.ctx);
    assert!(first.is_writable());
    assert!(matches!(
        first.reports()[0].outcome,
        MigrationOutcome::Current
    ));
    assert!(matches!(
        first.reports()[1].outcome,
        MigrationOutcome::Applied {
            changed_artifacts: 1
        }
    ));
    assert!(!test.ctx.claude_home.join("projects").exists());
    assert!(!test.ctx.openclaudia_data.join("chat_sessions").exists());
    assert!(test
        .ctx
        .openclaudia_data
        .join(".openclaudia-session-schema.json")
        .is_file());

    let second = run_all(&test.ctx);
    assert!(second.is_writable());
    assert!(second
        .reports()
        .iter()
        .all(|report| matches!(report.outcome, MigrationOutcome::Current)));
}
