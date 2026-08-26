//! End-to-end checks for explicit lifecycle-service composition and the
//! production stateful LSP service registration.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::services::{
    lifecycle_service_catalog, AnalyticsEvent, AnalyticsSink, LifecycleServiceClassification,
    LifecycleServiceId, LspServerManager, ServiceRegistry,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct CapturingSink {
    events: Mutex<Vec<AnalyticsEvent>>,
}

impl AnalyticsSink for CapturingSink {
    fn record(&self, event: AnalyticsEvent) {
        self.events.lock().unwrap().push(event);
    }
}

#[test]
fn disabled_registry_exposes_absence_instead_of_a_noop_claim() {
    let registry = ServiceRegistry::analytics_disabled();
    assert!(!registry.analytics_is_enabled());
    assert!(registry.analytics().is_none());
    assert!(registry.analytics_arc().is_none());
}

#[test]
fn interactive_registry_routes_to_the_shared_sink() {
    let capturing = Arc::new(CapturingSink::default());
    let first = ServiceRegistry::interactive(capturing.clone());
    let second = first.clone();
    first
        .analytics()
        .expect("configured sink")
        .record(AnalyticsEvent::ThinkingEmitted { budget: 1000 });
    second
        .analytics()
        .expect("configured sink")
        .record(AnalyticsEvent::ThinkingEmitted { budget: 2000 });
    assert_eq!(capturing.events.lock().unwrap().len(), 2);
}

#[test]
fn analytics_arc_routes_to_the_same_configured_sink() {
    let capturing = Arc::new(CapturingSink::default());
    let registry = ServiceRegistry::interactive(capturing.clone());
    registry
        .analytics_arc()
        .expect("configured sink")
        .record(AnalyticsEvent::PromptSubmitted { prompt_chars: 42 });
    assert_eq!(capturing.events.lock().unwrap().len(), 1);
}

#[test]
fn lsp_pool_is_reported_as_a_real_production_lifecycle() {
    let registration = lifecycle_service_catalog()
        .iter()
        .find(|registration| registration.id() == LifecycleServiceId::LspPool)
        .expect("LSP lifecycle row");
    assert_eq!(
        registration.classification(),
        LifecycleServiceClassification::Wired
    );
    let path = registration.path().expect("wired lifecycle path");
    assert!(path.construct().contains("ToolRunContext"));
    assert!(path.consume().contains("LspServerManager"));
    assert!(path.shutdown().contains("drop"));
}

#[test]
fn diagnostics_remain_explicitly_unavailable_until_their_own_wiring_slice() {
    let registration = lifecycle_service_catalog()
        .iter()
        .find(|registration| registration.id() == LifecycleServiceId::LspDiagnostics)
        .expect("diagnostics lifecycle row");
    assert_eq!(
        registration.classification(),
        LifecycleServiceClassification::Unavailable
    );
    assert!(registration.follow_up().is_some());
}

#[test]
fn empty_stateful_manager_has_no_phantom_server_and_reaps_cleanly() {
    let manager = LspServerManager::with_ttl(Duration::ZERO);
    assert!(manager.is_empty());
    assert_eq!(manager.len(), 0);
    assert_eq!(manager.reap_idle(), 0);
    manager.shutdown();
    assert!(manager.is_empty());
}
