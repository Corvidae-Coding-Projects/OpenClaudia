//! End-to-end tests for explicit analytics composition and preserved background
//! job mechanics. The lifecycle catalog must expose the durable scheduler only
//! after a production composition root owns its startup and shutdown.
//!
//! Sprint 77 of the verification effort. Sprint 47 covered
//! `LspServerManager`, sprint 46 covered `JobScheduler` ticks
//! plus `MockRateLimit`; this file covers the `ServiceRegistry`
//! builder API plus the `MemoryConsolidationJob` body that
//! drives short-term pruning plus bounded, non-destructive archival
//! equivalence review against a tempdir-backed memory store.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::memory::MemoryDb;
use openclaudia::services::{
    lifecycle_service_catalog, AnalyticsEvent, AnalyticsSink, BackgroundJob,
    LifecycleServiceClassification, LifecycleServiceId, MemoryConsolidationJob, NoopAnalytics,
    PluginAutoupdateJob, PluginDelistingJob, ServiceRegistry,
};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tracing_subscriber::fmt::MakeWriter;

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

fn fresh_db() -> (Arc<MemoryDb>, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("memory.db");
    let db = MemoryDb::open(&path).expect("open db");
    (Arc::new(db), dir)
}

/// Recording sink that captures every event for assertion.
struct RecordingSink {
    events: Arc<Mutex<Vec<AnalyticsEvent>>>,
}

impl RecordingSink {
    fn new() -> (Arc<Self>, Arc<Mutex<Vec<AnalyticsEvent>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::new(Self {
            events: events.clone(),
        });
        (sink, events)
    }
}

impl AnalyticsSink for RecordingSink {
    fn record(&self, event: AnalyticsEvent) {
        self.events.lock().expect("poison").push(event);
    }
}

#[derive(Clone, Default)]
struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

impl CapturedWriter {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().expect("captured trace").clone())
            .expect("UTF-8 tracing output")
    }
}

impl std::io::Write for CapturedWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("captured trace poisoned"))?
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for CapturedWriter {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — explicit ServiceRegistry state
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn analytics_disabled_is_observable_and_has_no_fabricated_sink() {
    let registry = ServiceRegistry::analytics_disabled();
    assert!(!registry.analytics_is_enabled());
    assert!(registry.analytics().is_none());
}

#[test]
fn interactive_registry_routes_through_its_required_sink() {
    let (sink, captured) = RecordingSink::new();
    let registry = ServiceRegistry::interactive(sink);
    registry
        .analytics()
        .expect("interactive sink")
        .record(AnalyticsEvent::PromptSubmitted { prompt_chars: 42 });
    let events = captured.lock().expect("poison").clone();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0],
        AnalyticsEvent::PromptSubmitted { prompt_chars: 42 }
    ));
}

#[test]
fn analytics_arc_returns_clone_of_underlying_arc() {
    let registry = ServiceRegistry::interactive(Arc::new(NoopAnalytics));
    let a1 = registry.analytics_arc().expect("interactive sink");
    let a2 = registry.analytics_arc().expect("interactive sink");
    // Both Arcs point at the same sink — clone count went up.
    assert!(
        Arc::strong_count(&a1) >= 2,
        "analytics_arc MUST share ownership; got refcount {}",
        Arc::strong_count(&a1)
    );
    // Both can record independently.
    a1.record(AnalyticsEvent::SessionStart {
        session_id: "a".to_string(),
    });
    a2.record(AnalyticsEvent::SessionStart {
        session_id: "b".to_string(),
    });
}

#[test]
fn analytics_arc_outlives_the_registry_via_shared_ownership() {
    let arc = {
        let registry = ServiceRegistry::interactive(Arc::new(NoopAnalytics));
        registry.analytics_arc().expect("interactive sink")
    };
    // Registry has been dropped, but the Arc lives on.
    arc.record(AnalyticsEvent::SessionEnd {
        session_id: "post-drop".to_string(),
        messages: 0,
    });
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — scheduler lifecycle classification
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn durable_background_scheduler_has_an_owned_lifecycle_path() {
    let registration = lifecycle_service_catalog()
        .iter()
        .find(|registration| registration.id() == LifecycleServiceId::BackgroundJobs)
        .expect("background catalog row");
    assert_eq!(
        registration.classification(),
        LifecycleServiceClassification::Wired
    );
    let path = registration.path().expect("wired scheduler lifecycle path");
    assert!(path.construct().contains("SchedulerServiceHandle::start"));
    assert!(path.consume().contains("canonical child dispatch"));
    assert!(path.shutdown().contains("SchedulerServiceHandle::shutdown"));
    assert!(registration.follow_up().is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — ServiceRegistry Debug impl
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn registry_debug_format_does_not_panic() {
    let registry = ServiceRegistry::analytics_disabled();
    let debug = format!("{registry:?}");
    // The Debug impl uses type metadata strings (no actual
    // Arc<dyn Trait> Debug); minimum contract is non-panic +
    // non-empty.
    assert!(!debug.is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — MemoryConsolidationJob end-to-end
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn memory_consolidation_job_name_is_documented_stable_label() {
    let job = MemoryConsolidationJob;
    assert_eq!(job.name(), "memory_consolidation");
}

#[test]
fn memory_consolidation_on_empty_db_returns_zero_metrics() {
    let (db, _dir) = fresh_db();
    let job = MemoryConsolidationJob;
    let outcome = job.run(&db).expect("run OK");
    assert_eq!(outcome.job_name, "memory_consolidation");
    assert_eq!(outcome.records_pruned, 0);
    assert_eq!(outcome.records_deduped, 0);
}

#[test]
fn memory_consolidation_preserves_equal_prose_with_distinct_logical_identity() {
    let (db, _dir) = fresh_db();
    let content = "duplicate-content";
    let first_id = db.memory_save(content, &[]).expect("save 1");
    let second_id = db.memory_save(content, &[]).expect("save 2");
    let third_id = db.memory_save(content, &[]).expect("save 3");
    let unique_id = db.memory_save("unique-content", &[]).expect("save 4");

    let before = [first_id, second_id, third_id, unique_id].map(|id| {
        db.memory_get(id)
            .expect("read before")
            .expect("present before")
    });
    let mut logical_ids = before
        .iter()
        .map(|entry| entry.logical_id)
        .collect::<Vec<_>>();
    logical_ids.sort_unstable();
    logical_ids.dedup();
    assert_eq!(logical_ids.len(), 4, "equal prose is not logical identity");

    let job = MemoryConsolidationJob;
    let outcome = job.run(&db).expect("run OK");
    assert_eq!(outcome.records_deduped, 0);

    for (id, expected) in [first_id, second_id, third_id, unique_id]
        .into_iter()
        .zip(before)
    {
        let after = db.memory_get(id).expect("read after").expect("preserved");
        assert_eq!(after.logical_id, expected.logical_id);
        assert_eq!(after.record_digest, expected.record_digest);
        assert_eq!(after.content, expected.content);
    }
}

#[test]
fn memory_consolidation_is_idempotently_non_destructive() {
    let (db, _dir) = fresh_db();
    let first_id = db.memory_save("dup", &[]).expect("1");
    let second_id = db.memory_save("dup", &[]).expect("2");
    let before = [first_id, second_id].map(|id| {
        db.memory_get(id)
            .expect("read before")
            .expect("present before")
    });
    assert_ne!(before[0].logical_id, before[1].logical_id);

    let job = MemoryConsolidationJob;
    let first = job.run(&db).expect("first run");
    assert_eq!(first.records_deduped, 0);
    let second = job.run(&db).expect("second run");
    assert_eq!(second.records_deduped, 0);

    for (id, expected) in [first_id, second_id].into_iter().zip(before) {
        let after = db.memory_get(id).expect("read after").expect("preserved");
        assert_eq!(after.logical_id, expected.logical_id);
        assert_eq!(after.record_digest, expected.record_digest);
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — PluginAutoupdateJob outcome shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn plugin_autoupdate_job_name_is_documented_stable_label() {
    let job = PluginAutoupdateJob::new(vec![]);
    assert_eq!(job.name(), "plugin_autoupdate");
}

#[test]
fn plugin_autoupdate_with_empty_plugin_list_returns_zero_metrics() {
    let (db, _dir) = fresh_db();
    let job = PluginAutoupdateJob::new(vec![]);
    let outcome = job.run(&db).expect("run");
    assert_eq!(outcome.job_name, "plugin_autoupdate");
    assert_eq!(outcome.records_pruned, 0);
    assert_eq!(outcome.records_deduped, 0);
}

#[test]
fn plugin_autoupdate_with_plugins_reports_that_no_request_was_made() {
    let (db, _dir) = fresh_db();
    let plugins = vec![
        ("plugin-a".to_string(), Some("1.0.0".to_string())),
        ("plugin-b".to_string(), None),
    ];
    let job = PluginAutoupdateJob::new(plugins);
    let captured = CapturedWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .finish();
    let outcome = tracing::subscriber::with_default(subscriber, || job.run(&db)).expect("run");
    assert_eq!(outcome.job_name, "plugin_autoupdate");
    assert_eq!(outcome.records_pruned, 0);
    assert_eq!(outcome.records_deduped, 0);
    let trace = captured.contents();
    assert!(trace.contains("plugin update check unavailable"));
    assert!(trace.contains("no marketplace request was made"));
    assert!(!trace.contains("polled plugin source"));
}

#[test]
fn plugin_delisting_with_plugins_reports_that_no_request_was_made() {
    let (db, _dir) = fresh_db();
    let job = PluginDelistingJob::new(vec![("plugin-a".to_string(), "marketplace-a".to_string())]);
    let captured = CapturedWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .finish();
    let outcome = tracing::subscriber::with_default(subscriber, || job.run(&db)).expect("run");
    assert_eq!(outcome.job_name, "plugin_delisting_check");
    assert_eq!(outcome.records_pruned, 0);
    assert_eq!(outcome.records_deduped, 0);
    let trace = captured.contents();
    assert!(trace.contains("plugin delisting check unavailable"));
    assert!(trace.contains("no marketplace request was made"));
    assert!(!trace.contains("polled marketplace"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section H — JobOutcome shape + Eq
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn job_outcome_with_same_values_compares_equal() {
    use openclaudia::services::JobOutcome;
    let a = JobOutcome {
        job_name: "x",
        records_pruned: 5,
        records_deduped: 3,
    };
    let b = JobOutcome {
        job_name: "x",
        records_pruned: 5,
        records_deduped: 3,
    };
    assert_eq!(a, b);
}

#[test]
fn noop_analytics_struct_directly_constructable() {
    // Verify the NoopAnalytics tuple struct can be made
    // directly (it's pub).
    let noop = NoopAnalytics;
    let sink: &dyn AnalyticsSink = &noop;
    sink.record(AnalyticsEvent::ApiRequest {
        provider: "test".to_string(),
        model: "model".to_string(),
    });
}
