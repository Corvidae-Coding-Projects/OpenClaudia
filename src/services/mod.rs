//! Lifecycle-service composition and audited reachability.
//!
//! [`ServiceRegistry`] is intentionally not a global service locator. Rust
//! dependencies with different authority and lifetime requirements remain
//! explicit at their call sites. The registry owns the one genuinely injected
//! cross-frontend service (analytics) and exposes the audited lifecycle catalog
//! for every other service-shaped implementation. There is no `Default` or
//! production no-op constructor: absence is represented explicitly.

pub mod analytics;
pub mod auto_compactor;
pub mod background;
pub mod feature_flags;
pub mod lifecycle;
pub mod lsp_diagnostics;
pub mod lsp_pool;
pub mod mcp_registry;
pub mod policy;
pub mod rate_limit_mock;
pub mod tool_executor;

pub use analytics::{AnalyticsEvent, AnalyticsSink, NoopAnalytics, TracingAnalytics};
pub use auto_compactor::{AutoCompactPolicy, AutoCompactor};
pub use background::{
    AgentSummaryJob, BackgroundJob, JobOutcome, JobScheduler, MemoryConsolidationJob,
    PluginAutoupdateJob, PluginDelistingJob,
};
pub use feature_flags::{FeatureFlagSource, StaticFlags};
pub use lifecycle::{
    lifecycle_service_catalog, validate_lifecycle_service_catalog, LifecyclePath,
    LifecycleServiceClassification, LifecycleServiceId, LifecycleServiceRegistration,
};
pub use lsp_diagnostics::{
    DefaultDiagnosticInjector, Diagnostic, DiagnosticInjector, DiagnosticRegistry,
    DiagnosticSeverity, NoopDiagnosticInjector,
};
pub use lsp_pool::{
    LspCallHierarchyContinuation, LspServerManager, LspServiceError, LspServiceRequest,
    LspServiceResponse, PluginLspServer,
};
pub use mcp_registry::{McpRegistration, McpServerSpec, PluginMcpRegistry};
pub use policy::{
    EnterprisePolicy, PolicyDecision, PolicyError, ProviderRequestPolicy,
    ProviderRequestPolicyInput, ToolExecutionPolicy,
};
pub use rate_limit_mock::{MockRateLimit, RateLimitMock};
pub use tool_executor::{ToolExecutor, ToolExecutorRequest};

use std::sync::Arc;

/// Explicit analytics composition used by interactive production frontends.
///
/// Other services remain typed dependencies at their real owners and are
/// described by [`lifecycle_service_catalog`]. This avoids hiding run authority,
/// cancellation, or shutdown behind a heterogeneous global locator.
#[derive(Clone)]
pub struct ServiceRegistry {
    analytics: Option<Arc<dyn AnalyticsSink>>,
}

impl ServiceRegistry {
    /// Compose an interactive frontend with an explicit analytics sink.
    #[must_use]
    pub fn interactive(analytics: Arc<dyn AnalyticsSink>) -> Self {
        Self {
            analytics: Some(analytics),
        }
    }

    /// Compose a frontend that deliberately emits no analytics.
    ///
    /// This is an explicit disabled state, not a fallback for failed service
    /// construction.
    #[must_use]
    pub const fn analytics_disabled() -> Self {
        Self { analytics: None }
    }

    /// Whether analytics was deliberately composed for this frontend.
    #[must_use]
    pub const fn analytics_is_enabled(&self) -> bool {
        self.analytics.is_some()
    }

    /// Borrow the explicitly configured analytics sink.
    #[must_use]
    pub fn analytics(&self) -> Option<&dyn AnalyticsSink> {
        self.analytics.as_deref()
    }

    /// Clone the explicitly configured analytics sink.
    #[must_use]
    pub fn analytics_arc(&self) -> Option<Arc<dyn AnalyticsSink>> {
        self.analytics.as_ref().map(Arc::clone)
    }

    /// Bind the configured analytics sink to one canonical state store.
    ///
    /// Returning `None` preserves the registry's explicit disabled state;
    /// callers must decide whether that state is valid for their frontend.
    #[must_use]
    pub fn analytics_subscriber(
        &self,
        state: crate::state::StateStore,
    ) -> Option<analytics::StateAnalyticsSubscriber> {
        self.analytics_arc()
            .map(|sink| analytics::StateAnalyticsSubscriber::new(state, sink))
    }
}

impl std::fmt::Debug for ServiceRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Arc<dyn Trait>` isn't Debug; print type metadata without
        // trying to traverse the sinks. Keeps the struct usable in
        // `#[derive(Debug)]` contexts that transitively need it.
        f.debug_struct("ServiceRegistry")
            .field(
                "analytics",
                &if self.analytics.is_some() {
                    "configured"
                } else {
                    "disabled"
                },
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Test sink that records every event so assertions can inspect
    /// the order and contents. Mutex is fine — tests aren't hot.
    struct RecordingAnalytics {
        events: Mutex<Vec<AnalyticsEvent>>,
    }

    impl AnalyticsSink for RecordingAnalytics {
        fn record(&self, event: AnalyticsEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    #[test]
    fn disabled_registry_cannot_fabricate_an_analytics_sink() {
        let registry = ServiceRegistry::analytics_disabled();
        assert!(!registry.analytics_is_enabled());
        assert!(registry.analytics().is_none());
        assert!(registry.analytics_arc().is_none());
        assert!(registry
            .analytics_subscriber(crate::state::StateStore::new(
                crate::state::SessionState::default(),
            ))
            .is_none());
    }

    #[test]
    fn interactive_registry_constructs_and_routes_the_lifecycle_subscriber() {
        let recording = Arc::new(RecordingAnalytics {
            events: Mutex::new(Vec::new()),
        });
        let reg = ServiceRegistry::interactive(recording.clone());
        let mut subscriber = reg
            .analytics_subscriber(crate::state::StateStore::new(
                crate::state::SessionState::default(),
            ))
            .expect("interactive subscriber");
        subscriber.finish();
        let events = recording.events.lock().unwrap().clone();
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], AnalyticsEvent::SessionStart { .. }));
        assert!(matches!(events[1], AnalyticsEvent::SessionEnd { .. }));
    }

    #[test]
    fn lifecycle_catalog_is_complete_and_wired_paths_are_total() {
        validate_lifecycle_service_catalog().expect("bundled lifecycle catalog");
        for registration in lifecycle_service_catalog() {
            assert_eq!(
                registration.classification() == LifecycleServiceClassification::Wired,
                registration.path().is_some()
            );
        }
    }

    #[test]
    fn registry_is_clone() {
        // Clone-cheap Arc semantics: the two handles point at the
        // same sinks. A test sink receiving events through either
        // handle sees them in the same vector.
        let recording = Arc::new(RecordingAnalytics {
            events: Mutex::new(Vec::new()),
        });
        let reg = ServiceRegistry::interactive(recording.clone());
        let clone = reg.clone();

        reg.analytics()
            .expect("interactive sink")
            .record(AnalyticsEvent::SessionStart {
                session_id: "a".to_string(),
            });
        clone
            .analytics()
            .expect("interactive sink")
            .record(AnalyticsEvent::SessionEnd {
                session_id: "a".to_string(),
                messages: 10,
            });

        assert_eq!(recording.events.lock().unwrap().len(), 2);
    }
}
