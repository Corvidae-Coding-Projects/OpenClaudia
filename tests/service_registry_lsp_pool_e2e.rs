//! End-to-end tests for explicit lifecycle-service composition plus the
//! preserved, currently unavailable `LspServerManager` implementation.
//!
//! Sprint 47 of the verification effort.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use anyhow::Result;
use openclaudia::services::{
    lifecycle_service_catalog, AnalyticsEvent, AnalyticsSink, ChildHandle,
    LifecycleServiceClassification, LifecycleServiceId, LspServerManager, LspSpawner,
    ServiceRegistry,
};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ───────────────────────────────────────────────────────────────────────────
// Helpers — capturing sinks for the registry tests
// ───────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct CapturingSink {
    events: Mutex<Vec<AnalyticsEvent>>,
}

impl AnalyticsSink for CapturingSink {
    fn record(&self, event: AnalyticsEvent) {
        if let Ok(mut g) = self.events.lock() {
            g.push(event);
        }
    }
}

impl CapturingSink {
    fn len(&self) -> usize {
        self.events.lock().map_or(0, |g| g.len())
    }
}

/// Stub spawner that launches `/bin/sleep 10` so the child stays
/// alive long enough for pool semantics to be tested deterministically.
struct SleepSpawner {
    spawn_count: Arc<AtomicUsize>,
}

impl SleepSpawner {
    fn new() -> (Self, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        (
            Self {
                spawn_count: counter.clone(),
            },
            counter,
        )
    }
}

impl LspSpawner for SleepSpawner {
    fn spawn(&self, _language: &str) -> Result<Child> {
        self.spawn_count.fetch_add(1, Ordering::SeqCst);
        // Long-running so the test can keep + release without race.
        let child = Command::new("/bin/sleep")
            .arg("30")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        Ok(child)
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — explicit analytics composition
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn disabled_registry_exposes_absence_instead_of_a_noop_claim() {
    let registry = ServiceRegistry::analytics_disabled();
    assert!(!registry.analytics_is_enabled());
    assert!(registry.analytics().is_none());
    assert!(registry.analytics_arc().is_none());
}

#[test]
fn interactive_registry_routes_to_the_required_sink() {
    let capturing = Arc::new(CapturingSink::default());
    let registry = ServiceRegistry::interactive(capturing.clone());
    registry
        .analytics()
        .expect("interactive sink")
        .record(AnalyticsEvent::ToolUsed {
            tool: "bash".to_string(),
            success: true,
        });
    assert_eq!(capturing.len(), 1);
}

#[test]
fn registry_is_clone_cheap_and_sinks_are_shared() {
    let capturing = Arc::new(CapturingSink::default());
    let reg1 = ServiceRegistry::interactive(capturing.clone());
    let reg2 = reg1.clone();
    reg1.analytics()
        .expect("interactive sink")
        .record(AnalyticsEvent::ThinkingEmitted { budget: 1000 });
    reg2.analytics()
        .expect("interactive sink")
        .record(AnalyticsEvent::ThinkingEmitted { budget: 2000 });
    assert_eq!(
        capturing.len(),
        2,
        "cloned registry MUST share the underlying Arc'd sink"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — audited classification
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn analytics_arc_returns_shared_arc_pointing_at_same_sink() {
    let capturing = Arc::new(CapturingSink::default());
    let reg = ServiceRegistry::interactive(capturing.clone());
    let cloned_arc = reg.analytics_arc().expect("interactive sink");
    cloned_arc.record(AnalyticsEvent::PromptSubmitted { prompt_chars: 42 });
    assert_eq!(
        capturing.len(),
        1,
        "analytics_arc MUST hand out an Arc pointing at the same sink"
    );
}

#[test]
fn lsp_pool_and_diagnostics_are_not_misreported_as_production_services() {
    for id in [
        LifecycleServiceId::LspPool,
        LifecycleServiceId::LspDiagnostics,
    ] {
        let registration = lifecycle_service_catalog()
            .iter()
            .find(|registration| registration.id() == id)
            .expect("catalog row");
        assert_eq!(
            registration.classification(),
            LifecycleServiceClassification::Unavailable
        );
        assert!(registration.path().is_none());
        assert!(registration.follow_up().is_some());
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — preserved LspServerManager mechanics
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn lsp_acquire_spawns_a_new_child_on_first_call_for_language() {
    let (spawner, count) = SleepSpawner::new();
    let mgr = LspServerManager::new(Arc::new(spawner));
    let handle = mgr.acquire("rust").expect("acquire rust");
    assert_eq!(handle.language, "rust");
    assert!(handle.child.is_some());
    let pid = handle.child.as_ref().map(Child::id).expect("child pid");
    assert_eq!(count.load(Ordering::SeqCst), 1, "first acquire MUST spawn");
    // Cleanup is part of the handle contract, not a test-only courtesy.
    drop(handle);
    let still_alive = Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .expect("inspect dropped child")
        .status
        .success();
    assert!(
        !still_alive,
        "dropping an acquired handle must reap child {pid}"
    );
}

#[test]
fn lsp_acquire_after_release_returns_pooled_child_no_respawn() {
    let (spawner, count) = SleepSpawner::new();
    let mgr = LspServerManager::new(Arc::new(spawner));
    let handle = mgr.acquire("rust").expect("first acquire");
    let pid_before = handle.child.as_ref().map(Child::id).unwrap();
    mgr.release(handle);
    // Spawn count was 1; second acquire MUST reuse the pooled
    // child without incrementing.
    let handle2 = mgr.acquire("rust").expect("second acquire");
    let pid_after = handle2.child.as_ref().map(Child::id).unwrap();
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "second acquire MUST reuse, not respawn"
    );
    assert_eq!(
        pid_before, pid_after,
        "reused handle MUST be the same OS process"
    );
    drop(handle2);
}

#[test]
fn lsp_acquire_for_distinct_languages_spawns_distinct_children() {
    let (spawner, count) = SleepSpawner::new();
    let mgr = LspServerManager::new(Arc::new(spawner));
    let rust = mgr.acquire("rust").expect("acquire rust");
    let python = mgr.acquire("python").expect("acquire python");
    assert_eq!(
        count.load(Ordering::SeqCst),
        2,
        "2 distinct langs → 2 spawns"
    );
    assert_ne!(
        rust.child.as_ref().map(Child::id),
        python.child.as_ref().map(Child::id),
        "distinct languages MUST yield distinct processes"
    );
    drop(rust);
    drop(python);
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — release stale-displace + reap_idle
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn lsp_release_after_concurrent_spawn_kills_displaced_child() {
    // Drive the race manually: acquire (handle A), spawn-out
    // a second handle while the first is still held (handle B),
    // release A → A should evict B from the pool, killing B's
    // child.
    let (spawner, _count) = SleepSpawner::new();
    let mgr = LspServerManager::new(Arc::new(spawner));
    let handle_a = mgr.acquire("rust").expect("a");
    // While A is out of the pool, second acquire spawns B.
    let handle_b = mgr.acquire("rust").expect("b");
    let pid_b = handle_b.child.as_ref().map(Child::id).unwrap();
    // Release B first → it's the only entry in the pool.
    mgr.release(handle_b);
    // Now release A → it displaces B from the pool. B's
    // child should be killed.
    mgr.release(handle_a);
    // Verify: the pool size is 1.
    assert_eq!(mgr.len(), 1);
    let displaced_still_alive = Command::new("kill")
        .args(["-0", &pid_b.to_string()])
        .output()
        .expect("inspect displaced child")
        .status
        .success();
    assert!(
        !displaced_still_alive,
        "releasing a competing generation must reap displaced child {pid_b}"
    );
}

#[test]
fn lsp_reap_idle_evicts_entries_older_than_ttl() {
    let (spawner, _) = SleepSpawner::new();
    // Very short TTL so the test runs quickly.
    let mgr = LspServerManager::with_ttl(Arc::new(spawner), Duration::from_millis(10));
    let handle = mgr.acquire("rust").expect("acquire");
    mgr.release(handle);
    assert_eq!(mgr.len(), 1);

    // Sleep past the TTL.
    std::thread::sleep(Duration::from_millis(50));
    let reaped = mgr.reap_idle();
    assert_eq!(reaped, 1, "1 entry older than TTL MUST be reaped");
    assert_eq!(mgr.len(), 0);
    assert!(mgr.is_empty());
}

#[test]
fn lsp_reap_idle_leaves_fresh_entries_alone() {
    let (spawner, _) = SleepSpawner::new();
    let mgr = LspServerManager::with_ttl(Arc::new(spawner), Duration::from_mins(1));
    let handle = mgr.acquire("rust").expect("acquire");
    mgr.release(handle);
    let reaped = mgr.reap_idle();
    assert_eq!(reaped, 0, "fresh entry MUST NOT be reaped");
    assert_eq!(mgr.len(), 1);
    mgr.kill_all();
}

// ───────────────────────────────────────────────────────────────────────────
// Section H — kill_all shutdown
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn lsp_kill_all_empties_the_pool() {
    let (spawner, _) = SleepSpawner::new();
    let mgr = LspServerManager::new(Arc::new(spawner));
    // Pool 3 entries.
    for lang in &["rust", "python", "go"] {
        let h = mgr.acquire(lang).expect("acquire");
        mgr.release(h);
    }
    assert_eq!(mgr.len(), 3);
    mgr.kill_all();
    assert_eq!(mgr.len(), 0);
    assert!(mgr.is_empty());
}

#[test]
fn lsp_empty_manager_reports_len_zero_and_is_empty() {
    let (spawner, _) = SleepSpawner::new();
    let mgr = LspServerManager::new(Arc::new(spawner));
    assert_eq!(mgr.len(), 0);
    assert!(mgr.is_empty());
    assert_eq!(mgr.reap_idle(), 0, "reap on empty pool MUST return 0");
}

// ───────────────────────────────────────────────────────────────────────────
// Section I — ChildHandle helpers
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn child_handle_carries_language_and_active_child() {
    let child = Command::new("/bin/sleep")
        .arg("5")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let handle = ChildHandle::new("ad-hoc-lang", child);
    assert_eq!(handle.language, "ad-hoc-lang");
    assert!(handle.child.is_some());
    // Kill the child manually so the test doesn't leave
    // /bin/sleep around.
    let mut h = handle;
    if let Some(mut c) = h.child.take() {
        let _ = c.kill();
        let _ = c.wait();
    }
}
