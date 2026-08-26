//! Audited reachability catalog for lifecycle and cross-cutting services.
//!
//! A service being implemented is not the same thing as it being part of a
//! production run. This catalog records that distinction in typed data. A
//! `Wired` record names its construction, production consumer, and teardown
//! boundary. Every other record carries an explicit reason and follow-up.
//!
//! The strings in [`LifecyclePath`] are stable Rust entrypoint identities, not
//! executable code or user-facing instructions. Runtime acceptance tests bind
//! this catalog to the capability registry and exercise the configured failure
//! paths; changing a classification therefore requires changing evidence, not
//! merely editing prose.

use std::collections::BTreeSet;

/// Stable identity of a service or service-shaped implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LifecycleServiceId {
    Analytics,
    FeatureRollout,
    BackgroundJobs,
    AutoCompaction,
    PluginMcpRuntime,
    PluginMcpShadowRegistry,
    ProjectMemory,
    TeamMemory,
    Guardrails,
    EnterprisePolicy,
    ToolExecutor,
    LspPool,
    LspDiagnostics,
    RateLimitFailureInjection,
}

impl LifecycleServiceId {
    /// Stable identifier used by diagnostics and tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Analytics => "analytics",
            Self::FeatureRollout => "feature-rollout",
            Self::BackgroundJobs => "background-jobs",
            Self::AutoCompaction => "auto-compaction",
            Self::PluginMcpRuntime => "plugin-mcp-runtime",
            Self::PluginMcpShadowRegistry => "plugin-mcp-shadow-registry",
            Self::ProjectMemory => "project-memory",
            Self::TeamMemory => "team-memory",
            Self::Guardrails => "guardrails",
            Self::EnterprisePolicy => "enterprise-policy",
            Self::ToolExecutor => "tool-executor",
            Self::LspPool => "lsp-pool",
            Self::LspDiagnostics => "lsp-diagnostics",
            Self::RateLimitFailureInjection => "rate-limit-failure-injection",
        }
    }
}

/// Audited production disposition. This is reachability, not a maturity claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleServiceClassification {
    /// A production composition root constructs the service, a production path
    /// consumes it, and the owner has a defined completion boundary.
    Wired,
    /// Intentionally absent for a production profile; no configuration claims
    /// to enable it.
    Disabled,
    /// Preserved implementation work that is not admitted to production.
    Experimental,
    /// Intended capability that cannot safely be activated yet.
    Unavailable,
    /// Failure-injection or fixture support that is not a product service.
    TestOnly,
}

impl LifecycleServiceClassification {
    /// Stable classification label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Wired => "wired",
            Self::Disabled => "disabled",
            Self::Experimental => "experimental",
            Self::Unavailable => "unavailable",
            Self::TestOnly => "test-only",
        }
    }
}

/// Concrete construction-to-completion path for a wired service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecyclePath {
    construct: &'static str,
    consume: &'static str,
    shutdown: &'static str,
}

impl LifecyclePath {
    const fn new(construct: &'static str, consume: &'static str, shutdown: &'static str) -> Self {
        Self {
            construct,
            consume,
            shutdown,
        }
    }

    /// Production construction entrypoint.
    #[must_use]
    pub const fn construct(self) -> &'static str {
        self.construct
    }

    /// Production consumer entrypoint.
    #[must_use]
    pub const fn consume(self) -> &'static str {
        self.consume
    }

    /// Explicit completion, cancellation, retirement, or RAII boundary.
    #[must_use]
    pub const fn shutdown(self) -> &'static str {
        self.shutdown
    }
}

/// One audited catalog row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleServiceRegistration {
    id: LifecycleServiceId,
    classification: LifecycleServiceClassification,
    path: Option<LifecyclePath>,
    reason: &'static str,
    follow_up: Option<&'static str>,
}

impl LifecycleServiceRegistration {
    const fn wired(id: LifecycleServiceId, path: LifecyclePath, reason: &'static str) -> Self {
        Self {
            id,
            classification: LifecycleServiceClassification::Wired,
            path: Some(path),
            reason,
            follow_up: None,
        }
    }

    const fn classified(
        id: LifecycleServiceId,
        classification: LifecycleServiceClassification,
        reason: &'static str,
        follow_up: Option<&'static str>,
    ) -> Self {
        Self {
            id,
            classification,
            path: None,
            reason,
            follow_up,
        }
    }

    /// Service identity.
    #[must_use]
    pub const fn id(self) -> LifecycleServiceId {
        self.id
    }

    /// Audited reachability classification.
    #[must_use]
    pub const fn classification(self) -> LifecycleServiceClassification {
        self.classification
    }

    /// Construction-to-completion path, present only for `Wired` records.
    #[must_use]
    pub const fn path(self) -> Option<LifecyclePath> {
        self.path
    }

    /// Concise reason for the classification.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        self.reason
    }

    /// Remediation slice that owns safe activation, when applicable.
    #[must_use]
    pub const fn follow_up(self) -> Option<&'static str> {
        self.follow_up
    }
}

const CATALOG: &[LifecycleServiceRegistration] = &[
    LifecycleServiceRegistration::wired(
        LifecycleServiceId::Analytics,
        LifecyclePath::new(
            "ServiceRegistry::interactive",
            "ServiceRegistry::analytics_subscriber/StateAnalyticsSubscriber::drain_pending",
            "StateAnalyticsSubscriber::finish",
        ),
        "The TUI and legacy REPL consume the injected sink through ServiceRegistry.",
    ),
    LifecycleServiceRegistration::classified(
        LifecycleServiceId::FeatureRollout,
        LifecycleServiceClassification::Unavailable,
        "No declared production flag exists; arbitrary OPENCLAUDIA_FEATURE_* names are rejected.",
        Some("S-014/S-047"),
    ),
    LifecycleServiceRegistration::classified(
        LifecycleServiceId::BackgroundJobs,
        LifecycleServiceClassification::Unavailable,
        "The synchronous scheduler lacks ownership, durable leases, cancellation, and safe job semantics.",
        Some("S-055/S-061/S-062/S-084"),
    ),
    LifecycleServiceRegistration::wired(
        LifecycleServiceId::AutoCompaction,
        LifecyclePath::new(
            "proxy::compact_request_context",
            "AutoCompactor::auto_compact",
            "compact_request_context request future completion",
        ),
        "The proxy request path uses the typed decision wrapper around ContextCompactor.",
    ),
    LifecycleServiceRegistration::wired(
        LifecycleServiceId::PluginMcpRuntime,
        LifecyclePath::new(
            "proxy::build_proxy_state_with_loop_control/main::cmd_tui",
            "mcp::McpManager tool and resource dispatch",
            "McpManager::disconnect_all",
        ),
        "The proxy and TUI own real PluginManager/McpManager handles and disconnect them.",
    ),
    LifecycleServiceRegistration::classified(
        LifecycleServiceId::PluginMcpShadowRegistry,
        LifecycleServiceClassification::Experimental,
        "The transport-neutral mirror is preserved for migration but is not a runtime authority or secret store.",
        Some("S-063/S-064/S-066"),
    ),
    LifecycleServiceRegistration::wired(
        LifecycleServiceId::ProjectMemory,
        LifecyclePath::new(
            "main::open_workspace_memory_db/cli::chat_repl::init_memory_with_banner",
            "canonical memory_* tool handlers and role-scoped subagents",
            "frontend/subagent completion followed by MemoryDb drop",
        ),
        "Interactive frontends open one host-owned workspace store and expose typed technical lessons only through explicit tools.",
    ),
    LifecycleServiceRegistration::wired(
        LifecycleServiceId::TeamMemory,
        LifecyclePath::new(
            "team_memory::activate_team_memory/openclaudia team configure-service|serve",
            "canonical scoped memory_* tools and TeamReplicationSupervisor push/pull",
            "TeamReplicationSupervisor::shutdown/drop and serve_team_memory_tls shutdown",
        ),
        "Configured frontends attach a host-owned encrypted replica, consume S-103 grants for exact scoped operations, and own bounded transport shutdown; legacy shared-path activation remains rejected.",
    ),
    LifecycleServiceRegistration::wired(
        LifecycleServiceId::Guardrails,
        LifecyclePath::new(
            "guardrails::configure",
            "guardrails tool/diff/quality gates",
            "ToolRunContext last-Arc release_run",
        ),
        "TUI, REPL, proxy, ACP, and subagents bind guardrails to exact run generations.",
    ),
    LifecycleServiceRegistration::wired(
        LifecycleServiceId::EnterprisePolicy,
        LifecyclePath::new(
            "PolicyEnforcer::new",
            "ProviderRequestPolicy/ToolExecutionPolicy",
            "frontend-owned PolicyEnforcer drop",
        ),
        "Provider and tool paths consume the same typed policy service.",
    ),
    LifecycleServiceRegistration::wired(
        LifecycleServiceId::ToolExecutor,
        LifecyclePath::new(
            "ToolExecutorRequest construction",
            "ToolExecutor::execute",
            "request-scoped ToolResult publication",
        ),
        "Primary local-tool paths use the shared typed executor.",
    ),
    LifecycleServiceRegistration::wired(
        LifecycleServiceId::LspPool,
        LifecyclePath::new(
            "ToolRunContext construction",
            "lsp tool dispatch through run-owned LspServerManager",
            "ToolRunContext drop / explicit manager shutdown",
        ),
        "The production LSP tool uses one supervised stateful service per exact run generation.",
    ),
    LifecycleServiceRegistration::wired(
        LifecycleServiceId::LspDiagnostics,
        LifecyclePath::new(
            "ToolRunContext construction",
            "LspServerManager typed publishDiagnostics collection",
            "request result publication / ToolRunContext drop",
        ),
        "Bounded diagnostics are capability-validated and returned as typed, versioned, untrusted LSP result data.",
    ),
    LifecycleServiceRegistration::classified(
        LifecycleServiceId::RateLimitFailureInjection,
        LifecycleServiceClassification::TestOnly,
        "This deterministic mock tests itself and is not a provider transport service.",
        Some("S-048/S-050"),
    ),
];

/// Return the immutable audited catalog.
#[must_use]
pub const fn lifecycle_service_catalog() -> &'static [LifecycleServiceRegistration] {
    CATALOG
}

/// Validate catalog completeness and the wired/unwired path invariant.
///
/// # Errors
///
/// Returns a deterministic diagnostic for duplicate service IDs, missing wired
/// path stages, a path attached to an unwired service, or an unowned unavailable
/// service.
pub fn validate_lifecycle_service_catalog() -> Result<(), String> {
    let mut ids = BTreeSet::new();
    for registration in CATALOG {
        if !ids.insert(registration.id) {
            return Err(format!(
                "duplicate lifecycle service {}",
                registration.id.as_str()
            ));
        }
        match (registration.classification, registration.path) {
            (LifecycleServiceClassification::Wired, Some(path)) => {
                if path.construct.is_empty() || path.consume.is_empty() || path.shutdown.is_empty()
                {
                    return Err(format!(
                        "wired lifecycle service {} has an incomplete path",
                        registration.id.as_str()
                    ));
                }
            }
            (LifecycleServiceClassification::Wired, None) => {
                return Err(format!(
                    "wired lifecycle service {} has no path",
                    registration.id.as_str()
                ));
            }
            (_, Some(_)) => {
                return Err(format!(
                    "unwired lifecycle service {} must not publish a production path",
                    registration.id.as_str()
                ));
            }
            (LifecycleServiceClassification::Unavailable, None)
                if registration.follow_up.is_none() =>
            {
                return Err(format!(
                    "unavailable lifecycle service {} has no remediation owner",
                    registration.id.as_str()
                ));
            }
            _ => {}
        }
    }

    let expected = [
        LifecycleServiceId::Analytics,
        LifecycleServiceId::FeatureRollout,
        LifecycleServiceId::BackgroundJobs,
        LifecycleServiceId::AutoCompaction,
        LifecycleServiceId::PluginMcpRuntime,
        LifecycleServiceId::PluginMcpShadowRegistry,
        LifecycleServiceId::ProjectMemory,
        LifecycleServiceId::TeamMemory,
        LifecycleServiceId::Guardrails,
        LifecycleServiceId::EnterprisePolicy,
        LifecycleServiceId::ToolExecutor,
        LifecycleServiceId::LspPool,
        LifecycleServiceId::LspDiagnostics,
        LifecycleServiceId::RateLimitFailureInjection,
    ];
    if ids != expected.into_iter().collect() {
        return Err("lifecycle service catalog is incomplete".to_string());
    }
    Ok(())
}
