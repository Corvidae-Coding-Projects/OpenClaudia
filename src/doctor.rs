//! Evidence-safe diagnostics shared by every frontend.
//!
//! A diagnostic receipt describes both the authority a check could require and
//! the effects it actually observed. The default standalone report is bounded,
//! read-only, and offline. It never constructs agent runtime state merely to
//! make a health claim.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{self, AppConfig};

/// Schema for serialized doctor reports.
pub const DOCTOR_SCHEMA_VERSION: u16 = 1;
/// Monotonic generation of the checks and their interpretation.
pub const DOCTOR_EVIDENCE_GENERATION: u64 = 1;
/// The only active diagnostic currently accepted by the command surface.
pub const ACTIVE_PROVIDER_REACHABILITY: &str = "provider.reachability";

const MAX_RECEIPTS: usize = 32;
const MAX_DETAIL_BYTES: usize = 512;
const MAX_ACTIVE_GRANTS: usize = 8;
const MAX_REPORTED_COUNT: usize = 1_000_000;
const DOCTOR_CHECK_IDS: [&str; 10] = [
    "evidence.registry",
    "configuration",
    "provider.configuration",
    "runtime.context",
    "runtime.provider_transport",
    "runtime.plugins",
    "runtime.mcp",
    "runtime.memory",
    "provider.reachability",
    "startup.migration_gate",
];

/// Authority class for a diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorCheckClass {
    /// Pure validation over already-present immutable bytes or values.
    Offline,
    /// Local inspection that cannot write, execute, contact a network, or cost money.
    ReadOnly,
    /// A check that could require an explicitly granted external effect.
    Active,
}

/// Effect vocabulary used by every diagnostic receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorEffect {
    FilesystemRead,
    FilesystemWrite,
    CredentialRead,
    NetworkRequest,
    ProcessExecution,
    RuntimeStateMutation,
    ProviderCost,
}

impl DoctorEffect {
    const fn is_read_only(self) -> bool {
        matches!(self, Self::FilesystemRead | Self::CredentialRead)
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::FilesystemRead => "filesystem_read",
            Self::FilesystemWrite => "filesystem_write",
            Self::CredentialRead => "credential_read",
            Self::NetworkRequest => "network_request",
            Self::ProcessExecution => "process_execution",
            Self::RuntimeStateMutation => "runtime_state_mutation",
            Self::ProviderCost => "provider_cost",
        }
    }
}

/// Evidence conclusion for one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorOutcome {
    Pass,
    Fail,
    Degraded,
    Skipped,
}

impl DoctorOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Degraded => "degraded",
            Self::Skipped => "skipped",
        }
    }
}

/// Aggregate result for the selected diagnostic scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorAggregate {
    Healthy,
    Degraded,
    Failed,
}

impl DoctorAggregate {
    /// Stable user-facing value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
        }
    }

    /// Only a fully evidenced selected scope is successful.
    #[must_use]
    pub const fn is_healthy(self) -> bool {
        matches!(self, Self::Healthy)
    }
}

/// Composition root examined by the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorScope {
    Standalone,
    LiveRuntime,
}

/// One bounded, redacted diagnostic receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorReceipt {
    sequence: u16,
    check_id: String,
    class: DoctorCheckClass,
    declared_effects: Vec<DoctorEffect>,
    observed_effects: Vec<DoctorEffect>,
    outcome: DoctorOutcome,
    required_for_aggregate: bool,
    evidence_generation: u64,
    code: String,
    detail: String,
}

impl DoctorReceipt {
    #[allow(clippy::too_many_arguments)]
    fn new(
        sequence: u16,
        check_id: &str,
        class: DoctorCheckClass,
        declared_effects: &[DoctorEffect],
        observed_effects: &[DoctorEffect],
        outcome: DoctorOutcome,
        required_for_aggregate: bool,
        code: &str,
        detail: String,
    ) -> Self {
        Self {
            sequence,
            check_id: check_id.to_string(),
            class,
            declared_effects: sorted_effects(declared_effects),
            observed_effects: sorted_effects(observed_effects),
            outcome,
            required_for_aggregate,
            evidence_generation: DOCTOR_EVIDENCE_GENERATION,
            code: code.to_string(),
            detail,
        }
    }

    /// Stable check identifier.
    #[must_use]
    pub fn check_id(&self) -> &str {
        &self.check_id
    }

    /// Authority class for this check.
    #[must_use]
    pub const fn class(&self) -> DoctorCheckClass {
        self.class
    }

    /// Effects the check contract permits.
    #[must_use]
    pub fn declared_effects(&self) -> &[DoctorEffect] {
        &self.declared_effects
    }

    /// Effects observed while producing this receipt.
    #[must_use]
    pub fn observed_effects(&self) -> &[DoctorEffect] {
        &self.observed_effects
    }

    /// Evidence conclusion.
    #[must_use]
    pub const fn outcome(&self) -> DoctorOutcome {
        self.outcome
    }

    /// Stable redacted result code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Bounded redacted explanation.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Complete deterministic diagnostic report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorReport {
    schema_version: u16,
    evidence_generation: u64,
    scope: DoctorScope,
    requested_active_checks: Vec<String>,
    aggregate: DoctorAggregate,
    receipts: Vec<DoctorReceipt>,
}

impl DoctorReport {
    fn new(scope: DoctorScope, request: &DoctorRequest, receipts: Vec<DoctorReceipt>) -> Self {
        let aggregate = aggregate_receipts(&receipts);
        Self {
            schema_version: DOCTOR_SCHEMA_VERSION,
            evidence_generation: DOCTOR_EVIDENCE_GENERATION,
            scope,
            requested_active_checks: request.active_grants.iter().cloned().collect(),
            aggregate,
            receipts,
        }
    }

    /// Evidence generation that gives every receipt its interpretation.
    #[must_use]
    pub const fn evidence_generation(&self) -> u64 {
        self.evidence_generation
    }

    /// Examined composition root.
    #[must_use]
    pub const fn scope(&self) -> DoctorScope {
        self.scope
    }

    /// Aggregate result for the selected checks.
    #[must_use]
    pub const fn aggregate(&self) -> DoctorAggregate {
        self.aggregate
    }

    /// Ordered typed receipts.
    #[must_use]
    pub fn receipts(&self) -> &[DoctorReceipt] {
        &self.receipts
    }

    /// Validate a report before treating it as evidence.
    ///
    /// # Errors
    ///
    /// Returns a stable contract code if the schema, ordering, effects, bounds,
    /// generation, or aggregate has been forged or corrupted.
    pub fn validate(&self) -> Result<(), DoctorContractError> {
        if self.schema_version != DOCTOR_SCHEMA_VERSION
            || self.evidence_generation != DOCTOR_EVIDENCE_GENERATION
            || self.receipts.len() != DOCTOR_CHECK_IDS.len()
            || self.receipts.len() > MAX_RECEIPTS
            || self.requested_active_checks.len() > MAX_ACTIVE_GRANTS
        {
            return Err(DoctorContractError::Schema);
        }
        let known_active = self
            .requested_active_checks
            .iter()
            .all(|grant| grant == ACTIVE_PROVIDER_REACHABILITY);
        if !known_active
            || !strictly_sorted_unique(&self.requested_active_checks)
            || self.receipts.iter().enumerate().any(|(index, receipt)| {
                usize::from(receipt.sequence) != index + 1
                    || receipt.evidence_generation != self.evidence_generation
                    || receipt.check_id != DOCTOR_CHECK_IDS[index]
            })
        {
            return Err(DoctorContractError::Ordering);
        }
        let mut ids = BTreeSet::new();
        for receipt in &self.receipts {
            if !ids.insert(receipt.check_id.as_str())
                || !valid_identifier(&receipt.check_id)
                || !valid_identifier(&receipt.code)
                || receipt.detail.is_empty()
                || receipt.detail.len() > MAX_DETAIL_BYTES
            {
                return Err(DoctorContractError::Bounds);
            }
            if !strictly_sorted_unique(&receipt.declared_effects)
                || !strictly_sorted_unique(&receipt.observed_effects)
                || receipt
                    .observed_effects
                    .iter()
                    .any(|effect| !receipt.declared_effects.contains(effect))
            {
                return Err(DoctorContractError::Effects);
            }
            if receipt.class == DoctorCheckClass::Offline
                && (!receipt.declared_effects.is_empty() || !receipt.observed_effects.is_empty())
            {
                return Err(DoctorContractError::Effects);
            }
            if receipt.class == DoctorCheckClass::ReadOnly
                && receipt
                    .declared_effects
                    .iter()
                    .chain(&receipt.observed_effects)
                    .any(|effect| !effect.is_read_only())
            {
                return Err(DoctorContractError::Effects);
            }
            if receipt.outcome == DoctorOutcome::Skipped && !receipt.observed_effects.is_empty() {
                return Err(DoctorContractError::Effects);
            }
        }
        if self.receipts.iter().any(|receipt| {
            !receipt_semantics_valid(self.scope, &self.requested_active_checks, receipt)
                || !receipt_detail_valid(receipt)
        }) {
            return Err(DoctorContractError::Semantics);
        }
        if aggregate_receipts(&self.receipts) != self.aggregate {
            return Err(DoctorContractError::Aggregate);
        }
        Ok(())
    }

    /// Render stable human-readable output without paths, endpoints, model
    /// names, provider names, headers, or credential material.
    #[must_use]
    pub fn render_human(&self) -> String {
        let mut output = format!(
            "OpenClaudia Doctor\nschema={} evidence_generation={} scope={:?} aggregate={}\n",
            self.schema_version,
            self.evidence_generation,
            self.scope,
            self.aggregate.as_str()
        );
        for receipt in &self.receipts {
            let declared = render_effects(&receipt.declared_effects);
            let observed = render_effects(&receipt.observed_effects);
            let _ = writeln!(
                output,
                "[{}] {} class={:?} code={} effects(declared={declared}; observed={observed})",
                receipt.outcome.as_str().to_ascii_uppercase(),
                receipt.check_id,
                receipt.class,
                receipt.code
            );
            let _ = writeln!(output, "  {}", receipt.detail);
        }
        output
    }
}

/// Stable report-integrity error. It deliberately does not echo untrusted data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DoctorContractError {
    #[error("invalid doctor report schema or collection bounds")]
    Schema,
    #[error("invalid doctor report ordering")]
    Ordering,
    #[error("invalid doctor report field bounds")]
    Bounds,
    #[error("invalid doctor report effect declaration")]
    Effects,
    #[error("invalid doctor report check semantics")]
    Semantics,
    #[error("invalid doctor report aggregate")]
    Aggregate,
}

/// Invalid active-probe grant. Input is intentionally not retained or echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("unknown active diagnostic grant; supported grant: provider.reachability")]
pub struct DoctorRequestError;

/// Exact active authority selected for one report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DoctorRequest {
    active_grants: BTreeSet<String>,
}

impl DoctorRequest {
    /// Validate and bind exact active check identifiers before any diagnostic
    /// reads or effects occur.
    ///
    /// # Errors
    ///
    /// Returns a redacted error if a grant is empty, unknown, duplicated past
    /// the configured bound, or otherwise outside the finite registry.
    pub fn try_new<I, S>(grants: I) -> Result<Self, DoctorRequestError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut active_grants = BTreeSet::new();
        let mut grant_count = 0usize;
        for grant in grants {
            grant_count = grant_count.saturating_add(1);
            let grant = grant.as_ref();
            if grant != ACTIVE_PROVIDER_REACHABILITY || grant_count > MAX_ACTIVE_GRANTS {
                return Err(DoctorRequestError);
            }
            active_grants.insert(grant.to_string());
        }
        Ok(Self { active_grants })
    }

    fn grants_provider_reachability(&self) -> bool {
        self.active_grants.contains(ACTIVE_PROVIDER_REACHABILITY)
    }
}

/// Read-only result of resolving configuration for diagnostics.
#[derive(Clone, Copy)]
pub enum DoctorConfig<'a> {
    Missing,
    Invalid,
    Unavailable,
    LoadedFromSources(&'a AppConfig),
    Attached(&'a AppConfig),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompositionPresence {
    Present,
    Unavailable,
}

/// Actual runtime composition available to an inline frontend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorRuntimeSnapshot {
    scope: DoctorScope,
    run_context: CompositionPresence,
    read_only_roots: usize,
    read_write_roots: usize,
    environment_grants: usize,
    provider_transport: CompositionPresence,
    plugin_manager: CompositionPresence,
    plugin_count: usize,
    mcp_manager: CompositionPresence,
    mcp_registered_count: Option<usize>,
    mcp_live_count: Option<usize>,
    memory_store: CompositionPresence,
}

impl DoctorRuntimeSnapshot {
    /// Standalone diagnostics have no fabricated runtime composition.
    #[must_use]
    pub const fn standalone() -> Self {
        Self {
            scope: DoctorScope::Standalone,
            run_context: CompositionPresence::Unavailable,
            read_only_roots: 0,
            read_write_roots: 0,
            environment_grants: 0,
            provider_transport: CompositionPresence::Unavailable,
            plugin_manager: CompositionPresence::Unavailable,
            plugin_count: 0,
            mcp_manager: CompositionPresence::Unavailable,
            mcp_registered_count: None,
            mcp_live_count: None,
            memory_store: CompositionPresence::Unavailable,
        }
    }

    /// Inline frontend snapshot when construction of its real run failed.
    #[must_use]
    pub(crate) const fn live_without_run() -> Self {
        Self {
            scope: DoctorScope::LiveRuntime,
            ..Self::standalone()
        }
    }

    /// Snapshot immutable facts from an already-authorized real run.
    #[must_use]
    pub fn from_run(run: &crate::tools::ToolRunContext) -> Self {
        Self {
            scope: DoctorScope::LiveRuntime,
            run_context: CompositionPresence::Present,
            read_only_roots: bounded_count(run.read_only_roots().len()),
            read_write_roots: bounded_count(run.read_write_roots().len()),
            environment_grants: bounded_count(run.environment_grants().len()),
            ..Self::live_without_run()
        }
    }

    /// Snapshot a real run and its exact registered MCP manager without
    /// blocking or starting any server.
    #[must_use]
    pub fn from_run_with_mcp(
        run: &crate::tools::ToolRunContext,
        manager: Option<&std::sync::Arc<tokio::sync::RwLock<crate::mcp::McpManager>>>,
    ) -> Self {
        manager.map_or_else(
            || Self::from_run(run),
            |manager| Self::from_run(run).with_composed_mcp_manager(manager),
        )
    }

    /// Bind the provider transport actually owned by an interactive frontend.
    ///
    /// Requiring both concrete handles prevents callers from promoting a
    /// provider name or endpoint string into a composition-health claim.
    #[must_use]
    pub fn with_composed_provider_transport(
        mut self,
        _client: &reqwest::Client,
        _adapter: &dyn crate::providers::ProviderAdapter,
    ) -> Self {
        self.provider_transport = CompositionPresence::Present;
        self
    }

    /// Bind the plugin manager actually owned by an interactive frontend.
    #[must_use]
    pub fn with_composed_plugin_manager(mut self, manager: &crate::plugins::PluginManager) -> Self {
        self.plugin_manager = CompositionPresence::Present;
        self.plugin_count = bounded_count(manager.count());
        self
    }

    /// Bind the MCP manager actually owned by an interactive frontend and
    /// take a non-blocking snapshot without starting or reconnecting servers.
    #[must_use]
    pub fn with_composed_mcp_manager(
        mut self,
        manager: &std::sync::Arc<tokio::sync::RwLock<crate::mcp::McpManager>>,
    ) -> Self {
        let counts = manager
            .try_read()
            .ok()
            .and_then(|manager| manager.try_health_counts());
        self.mcp_manager = CompositionPresence::Present;
        self.mcp_registered_count = counts.map(|(registered, _)| bounded_count(registered));
        self.mcp_live_count = counts.map(|(_, live)| bounded_count(live));
        self
    }

    /// Bind the memory store actually owned by an interactive frontend.
    #[must_use]
    pub const fn with_composed_memory_store(mut self, _store: &crate::memory::MemoryDb) -> Self {
        self.memory_store = CompositionPresence::Present;
        self
    }
}

/// Build a typed report from read-only configuration state and an actual
/// composition snapshot.
#[must_use]
pub fn diagnose(
    config_state: DoctorConfig<'_>,
    runtime: &DoctorRuntimeSnapshot,
    request: &DoctorRequest,
) -> DoctorReport {
    let mut receipts = Vec::with_capacity(10);
    receipts.push(capability_registry_receipt(next_sequence(&receipts)));
    let loaded = match config_state {
        DoctorConfig::Missing => {
            receipts.push(receipt(
                next_sequence(&receipts),
                "configuration",
                DoctorCheckClass::ReadOnly,
                &[DoctorEffect::FilesystemRead],
                &[DoctorEffect::FilesystemRead],
                DoctorOutcome::Fail,
                true,
                "configuration.missing",
                "No configuration source exists; run openclaudia init.",
            ));
            None
        }
        DoctorConfig::Invalid => {
            receipts.push(receipt(
                next_sequence(&receipts),
                "configuration",
                DoctorCheckClass::ReadOnly,
                &[DoctorEffect::FilesystemRead, DoctorEffect::CredentialRead],
                &[DoctorEffect::FilesystemRead, DoctorEffect::CredentialRead],
                DoctorOutcome::Fail,
                true,
                "configuration.invalid",
                "Configuration could not be validated; details are withheld to avoid disclosing values or paths.",
            ));
            None
        }
        DoctorConfig::Unavailable => {
            receipts.push(receipt(
                next_sequence(&receipts),
                "configuration",
                DoctorCheckClass::Offline,
                &[],
                &[],
                DoctorOutcome::Skipped,
                true,
                "configuration.unavailable",
                "No validated configuration object is attached to this runtime composition.",
            ));
            None
        }
        DoctorConfig::LoadedFromSources(config) => {
            receipts.push(receipt(
                next_sequence(&receipts),
                "configuration",
                DoctorCheckClass::ReadOnly,
                &[DoctorEffect::FilesystemRead, DoctorEffect::CredentialRead],
                &[DoctorEffect::FilesystemRead, DoctorEffect::CredentialRead],
                DoctorOutcome::Pass,
                true,
                "configuration.validated",
                "Typed configuration loaded and passed its current validation boundary.",
            ));
            Some(config)
        }
        DoctorConfig::Attached(config) => {
            receipts.push(receipt(
                next_sequence(&receipts),
                "configuration",
                DoctorCheckClass::Offline,
                &[],
                &[],
                DoctorOutcome::Pass,
                true,
                "configuration.attached",
                "The runtime supplied an already-validated typed configuration object.",
            ));
            Some(config)
        }
    };
    receipts.push(provider_configuration_receipt(
        next_sequence(&receipts),
        loaded,
    ));
    receipts.extend(runtime_receipts(runtime, receipts.len()));
    receipts.push(provider_reachability_receipt(
        next_sequence(&receipts),
        request,
    ));
    receipts.push(receipt(
        next_sequence(&receipts),
        "startup.migration_gate",
        DoctorCheckClass::Offline,
        &[],
        &[],
        DoctorOutcome::Skipped,
        false,
        "startup.migration_gate.not_run",
        "Writable startup migration checks are intentionally excluded from evidence-safe doctor runs.",
    ));
    let report = DoctorReport::new(runtime.scope, request, receipts);
    debug_assert!(report.validate().is_ok());
    report
}

fn capability_registry_receipt(sequence: u16) -> DoctorReceipt {
    match crate::capability_evidence::CapabilityEvidenceBundle::bundled() {
        Ok(_) => receipt(
            sequence,
            "evidence.registry",
            DoctorCheckClass::Offline,
            &[],
            &[],
            DoctorOutcome::Pass,
            true,
            "evidence.registry.validated",
            "Bundled capability registry, corpus, and review bindings validated.",
        ),
        Err(_) => receipt(
            sequence,
            "evidence.registry",
            DoctorCheckClass::Offline,
            &[],
            &[],
            DoctorOutcome::Fail,
            true,
            "evidence.registry.invalid",
            "Bundled capability evidence failed closed validation.",
        ),
    }
}

fn provider_configuration_receipt(sequence: u16, loaded: Option<&AppConfig>) -> DoctorReceipt {
    let Some(config) = loaded else {
        return receipt(
            sequence,
            "provider.configuration",
            DoctorCheckClass::ReadOnly,
            &[DoctorEffect::CredentialRead],
            &[],
            DoctorOutcome::Skipped,
            true,
            "provider.configuration.unavailable",
            "Provider configuration cannot be assessed without valid configuration.",
        );
    };
    let Some(provider) = config.active_provider() else {
        return receipt(
            sequence,
            "provider.configuration",
            DoctorCheckClass::ReadOnly,
            &[DoctorEffect::CredentialRead],
            &[DoctorEffect::CredentialRead],
            DoctorOutcome::Fail,
            true,
            "provider.configuration.missing",
            "The selected provider has no matching typed configuration entry.",
        );
    };
    if config::is_local_provider_name(&config.proxy.target) {
        return receipt(
            sequence,
            "provider.configuration",
            DoctorCheckClass::ReadOnly,
            &[DoctorEffect::CredentialRead],
            &[DoctorEffect::CredentialRead],
            DoctorOutcome::Pass,
            true,
            "provider.configuration.local",
            "The selected local provider does not require a configured credential.",
        );
    }
    if provider.api_key.is_some() {
        return receipt(
            sequence,
            "provider.configuration",
            DoctorCheckClass::ReadOnly,
            &[DoctorEffect::CredentialRead],
            &[DoctorEffect::CredentialRead],
            DoctorOutcome::Pass,
            true,
            "provider.configuration.credential_present",
            "Credential material is configured; its value and validity were not exposed or probed.",
        );
    }
    if config.proxy.target.eq_ignore_ascii_case("anthropic") {
        return receipt(
            sequence,
            "provider.configuration",
            DoctorCheckClass::ReadOnly,
            &[DoctorEffect::CredentialRead],
            &[DoctorEffect::CredentialRead],
            DoctorOutcome::Degraded,
            true,
            "provider.configuration.foreign_credential_unread",
            "No configured API key is present; the foreign Claude credential store was intentionally not read or refreshed.",
        );
    }
    receipt(
        sequence,
        "provider.configuration",
        DoctorCheckClass::ReadOnly,
        &[DoctorEffect::CredentialRead],
        &[DoctorEffect::CredentialRead],
        DoctorOutcome::Fail,
        true,
        "provider.configuration.credential_missing",
        "The selected remote provider has no configured credential.",
    )
}

fn runtime_receipts(runtime: &DoctorRuntimeSnapshot, starting_len: usize) -> Vec<DoctorReceipt> {
    let live_scope = runtime.scope == DoctorScope::LiveRuntime;
    let sequence = |offset: usize| u16::try_from(starting_len + offset + 1).unwrap_or(u16::MAX);
    vec![
        runtime_context_receipt(sequence(0), runtime),
        provider_transport_receipt(sequence(1), runtime, live_scope),
        plugin_receipt(sequence(2), runtime, live_scope),
        mcp_receipt(sequence(3), runtime, live_scope),
        memory_receipt(sequence(4), runtime),
    ]
}

fn runtime_context_receipt(sequence: u16, runtime: &DoctorRuntimeSnapshot) -> DoctorReceipt {
    let (outcome, code, detail) = if runtime.run_context == CompositionPresence::Present {
        (
            DoctorOutcome::Pass,
            "runtime.context.composed",
            format!(
                "Actual run context is present with {} read-only roots, {} read-write roots, and {} named environment grants.",
                runtime.read_only_roots, runtime.read_write_roots, runtime.environment_grants
            ),
        )
    } else {
        (
            DoctorOutcome::Skipped,
            "runtime.context.unavailable",
            "No agent runtime was constructed for this diagnostic; runtime readiness is unavailable.".to_string(),
        )
    };
    DoctorReceipt::new(
        sequence,
        "runtime.context",
        DoctorCheckClass::Offline,
        &[],
        &[],
        outcome,
        true,
        code,
        detail,
    )
}

fn provider_transport_receipt(
    sequence: u16,
    runtime: &DoctorRuntimeSnapshot,
    required: bool,
) -> DoctorReceipt {
    if runtime.provider_transport == CompositionPresence::Present {
        receipt(
            sequence,
            "runtime.provider_transport",
            DoctorCheckClass::Offline,
            &[],
            &[],
            DoctorOutcome::Pass,
            required,
            "runtime.provider_transport.composed",
            "The real frontend provider transport is composed; remote readiness was not inferred.",
        )
    } else {
        receipt(
            sequence,
            "runtime.provider_transport",
            DoctorCheckClass::Offline,
            &[],
            &[],
            DoctorOutcome::Skipped,
            required,
            "runtime.provider_transport.unavailable",
            "No real provider transport is available in this diagnostic composition.",
        )
    }
}

fn plugin_receipt(sequence: u16, runtime: &DoctorRuntimeSnapshot, required: bool) -> DoctorReceipt {
    if runtime.plugin_manager == CompositionPresence::Unavailable {
        receipt(
            sequence,
            "runtime.plugins",
            DoctorCheckClass::Offline,
            &[],
            &[],
            DoctorOutcome::Skipped,
            required,
            "runtime.plugins.unavailable",
            "No real plugin manager is attached; no plugin health claim was made.",
        )
    } else if runtime.plugin_count == 0 {
        receipt(
            sequence,
            "runtime.plugins",
            DoctorCheckClass::Offline,
            &[],
            &[],
            DoctorOutcome::Degraded,
            required,
            "runtime.plugins.empty",
            "The real plugin manager is attached but contains no loaded plugins.",
        )
    } else {
        receipt(
            sequence,
            "runtime.plugins",
            DoctorCheckClass::Offline,
            &[],
            &[],
            DoctorOutcome::Pass,
            required,
            "runtime.plugins.composed",
            format!(
                "The real plugin manager contains {} loaded plugin components; execution health was not inferred.",
                runtime.plugin_count
            ),
        )
    }
}

fn memory_receipt(sequence: u16, runtime: &DoctorRuntimeSnapshot) -> DoctorReceipt {
    if runtime.memory_store == CompositionPresence::Present {
        receipt(
            sequence,
            "runtime.memory",
            DoctorCheckClass::Offline,
            &[],
            &[],
            DoctorOutcome::Pass,
            false,
            "runtime.memory.composed",
            "The real frontend memory service is composed; persistence health was not inferred.",
        )
    } else {
        receipt(
            sequence,
            "runtime.memory",
            DoctorCheckClass::Offline,
            &[],
            &[],
            DoctorOutcome::Skipped,
            false,
            "runtime.memory.unavailable",
            "No real memory service is attached; no persistence health claim was made.",
        )
    }
}

fn mcp_receipt(sequence: u16, runtime: &DoctorRuntimeSnapshot, required: bool) -> DoctorReceipt {
    if runtime.mcp_manager == CompositionPresence::Unavailable {
        return receipt(
            sequence,
            "runtime.mcp",
            DoctorCheckClass::Offline,
            &[],
            &[],
            DoctorOutcome::Skipped,
            required,
            "runtime.mcp.unavailable",
            "No real MCP manager is attached; no MCP health claim was made.",
        );
    }
    let Some(registered) = runtime.mcp_registered_count else {
        return receipt(
            sequence,
            "runtime.mcp",
            DoctorCheckClass::Offline,
            &[],
            &[],
            DoctorOutcome::Degraded,
            required,
            "runtime.mcp.unsampled",
            "The real MCP manager is attached, but bounded server state was unavailable without blocking.",
        );
    };
    if registered == 0 {
        return receipt(
            sequence,
            "runtime.mcp",
            DoctorCheckClass::Offline,
            &[],
            &[],
            DoctorOutcome::Degraded,
            required,
            "runtime.mcp.empty",
            "The real MCP manager is attached with zero registered servers; this is not live health.",
        );
    }
    match runtime.mcp_live_count {
        Some(live) if live > registered => receipt(
            sequence,
            "runtime.mcp",
            DoctorCheckClass::Offline,
            &[],
            &[],
            DoctorOutcome::Fail,
            required,
            "runtime.mcp.inconsistent",
            "The live MCP count exceeds the registered count; the snapshot is inconsistent.",
        ),
        Some(0) => receipt(
            sequence,
            "runtime.mcp",
            DoctorCheckClass::Offline,
            &[],
            &[],
            DoctorOutcome::Fail,
            required,
            "runtime.mcp.none_live",
            format!("{registered} MCP servers are registered and none are live."),
        ),
        Some(live) => receipt(
            sequence,
            "runtime.mcp",
            DoctorCheckClass::Offline,
            &[],
            &[],
            DoctorOutcome::Pass,
            required,
            "runtime.mcp.live",
            format!("{live} of {registered} registered MCP servers are live."),
        ),
        None => receipt(
            sequence,
            "runtime.mcp",
            DoctorCheckClass::Offline,
            &[],
            &[],
            DoctorOutcome::Degraded,
            required,
            "runtime.mcp.live_unsampled",
            format!(
                "{registered} MCP servers are registered, but live connectivity was not sampled."
            ),
        ),
    }
}

fn provider_reachability_receipt(sequence: u16, request: &DoctorRequest) -> DoctorReceipt {
    let granted = request.grants_provider_reachability();
    receipt(
        sequence,
        ACTIVE_PROVIDER_REACHABILITY,
        DoctorCheckClass::Active,
        &[DoctorEffect::CredentialRead, DoctorEffect::NetworkRequest],
        &[],
        DoctorOutcome::Skipped,
        granted,
        if granted {
            "provider.reachability.broker_unavailable"
        } else {
            "provider.reachability.not_granted"
        },
        if granted {
            "The active grant was accepted, but no trusted-origin, redirect-safe, credential-safe, deadline-bounded provider capability probe is implemented."
        } else {
            "Active provider reachability was not granted; no credential or network effect occurred."
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn receipt(
    sequence: u16,
    check_id: &str,
    class: DoctorCheckClass,
    declared_effects: &[DoctorEffect],
    observed_effects: &[DoctorEffect],
    outcome: DoctorOutcome,
    required_for_aggregate: bool,
    code: &str,
    detail: impl Into<String>,
) -> DoctorReceipt {
    DoctorReceipt::new(
        sequence,
        check_id,
        class,
        declared_effects,
        observed_effects,
        outcome,
        required_for_aggregate,
        code,
        detail.into(),
    )
}

fn aggregate_receipts(receipts: &[DoctorReceipt]) -> DoctorAggregate {
    if receipts
        .iter()
        .any(|receipt| receipt.outcome == DoctorOutcome::Fail)
    {
        DoctorAggregate::Failed
    } else if receipts.iter().any(|receipt| {
        receipt.outcome == DoctorOutcome::Degraded
            || (receipt.outcome == DoctorOutcome::Skipped && receipt.required_for_aggregate)
    }) {
        DoctorAggregate::Degraded
    } else {
        DoctorAggregate::Healthy
    }
}

fn receipt_semantics_valid(
    scope: DoctorScope,
    requested_active_checks: &[String],
    receipt: &DoctorReceipt,
) -> bool {
    let live_required = scope == DoctorScope::LiveRuntime;
    let active_required = requested_active_checks
        .binary_search_by(|grant| grant.as_str().cmp(ACTIVE_PROVIDER_REACHABILITY))
        .is_ok();
    match receipt.check_id.as_str() {
        "evidence.registry" => evidence_receipt_semantics(receipt),
        "configuration" => configuration_receipt_semantics(receipt),
        "provider.configuration" => provider_configuration_semantics(receipt),
        "runtime.context" => runtime_context_semantics(receipt, live_required),
        "runtime.provider_transport" => provider_transport_semantics(receipt, live_required),
        "runtime.plugins" => plugin_semantics(receipt, live_required),
        "runtime.mcp" => mcp_semantics(receipt, live_required),
        "runtime.memory" => memory_semantics(receipt, live_required),
        ACTIVE_PROVIDER_REACHABILITY => active_probe_semantics(receipt, active_required),
        "startup.migration_gate" => {
            receipt.code == "startup.migration_gate.not_run"
                && receipt_has_semantics(
                    receipt,
                    DoctorCheckClass::Offline,
                    &[],
                    &[],
                    DoctorOutcome::Skipped,
                    false,
                )
        }
        _ => false,
    }
}

fn evidence_receipt_semantics(receipt: &DoctorReceipt) -> bool {
    let outcome = match receipt.code.as_str() {
        "evidence.registry.validated" => DoctorOutcome::Pass,
        "evidence.registry.invalid" => DoctorOutcome::Fail,
        _ => return false,
    };
    receipt_has_semantics(receipt, DoctorCheckClass::Offline, &[], &[], outcome, true)
}

fn configuration_receipt_semantics(receipt: &DoctorReceipt) -> bool {
    use DoctorCheckClass::{Offline, ReadOnly};
    use DoctorEffect::{CredentialRead, FilesystemRead};
    use DoctorOutcome::{Fail, Pass, Skipped};

    match receipt.code.as_str() {
        "configuration.missing" => receipt_has_semantics(
            receipt,
            ReadOnly,
            &[FilesystemRead],
            &[FilesystemRead],
            Fail,
            true,
        ),
        "configuration.invalid" => receipt_has_semantics(
            receipt,
            ReadOnly,
            &[FilesystemRead, CredentialRead],
            &[FilesystemRead, CredentialRead],
            Fail,
            true,
        ),
        "configuration.unavailable" => {
            receipt_has_semantics(receipt, Offline, &[], &[], Skipped, true)
        }
        "configuration.validated" => receipt_has_semantics(
            receipt,
            ReadOnly,
            &[FilesystemRead, CredentialRead],
            &[FilesystemRead, CredentialRead],
            Pass,
            true,
        ),
        "configuration.attached" => receipt_has_semantics(receipt, Offline, &[], &[], Pass, true),
        _ => false,
    }
}

fn provider_configuration_semantics(receipt: &DoctorReceipt) -> bool {
    use DoctorEffect::CredentialRead;
    use DoctorOutcome::{Degraded, Fail, Pass, Skipped};

    let (observed, outcome) = match receipt.code.as_str() {
        "provider.configuration.unavailable" => (&[][..], Skipped),
        "provider.configuration.missing" | "provider.configuration.credential_missing" => {
            (&[CredentialRead][..], Fail)
        }
        "provider.configuration.local" | "provider.configuration.credential_present" => {
            (&[CredentialRead][..], Pass)
        }
        "provider.configuration.foreign_credential_unread" => (&[CredentialRead][..], Degraded),
        _ => return false,
    };
    receipt_has_semantics(
        receipt,
        DoctorCheckClass::ReadOnly,
        &[CredentialRead],
        observed,
        outcome,
        true,
    )
}

fn runtime_context_semantics(receipt: &DoctorReceipt, live: bool) -> bool {
    let outcome = match receipt.code.as_str() {
        "runtime.context.composed" if live => DoctorOutcome::Pass,
        "runtime.context.unavailable" => DoctorOutcome::Skipped,
        _ => return false,
    };
    receipt_has_semantics(receipt, DoctorCheckClass::Offline, &[], &[], outcome, true)
}

fn provider_transport_semantics(receipt: &DoctorReceipt, live: bool) -> bool {
    let outcome = match receipt.code.as_str() {
        "runtime.provider_transport.composed" if live => DoctorOutcome::Pass,
        "runtime.provider_transport.unavailable" => DoctorOutcome::Skipped,
        _ => return false,
    };
    offline_runtime_semantics(receipt, outcome, live)
}

fn plugin_semantics(receipt: &DoctorReceipt, live: bool) -> bool {
    let outcome = match receipt.code.as_str() {
        "runtime.plugins.unavailable" => DoctorOutcome::Skipped,
        "runtime.plugins.empty" if live => DoctorOutcome::Degraded,
        "runtime.plugins.composed" if live => DoctorOutcome::Pass,
        _ => return false,
    };
    offline_runtime_semantics(receipt, outcome, live)
}

fn mcp_semantics(receipt: &DoctorReceipt, live: bool) -> bool {
    use DoctorOutcome::{Degraded, Fail, Pass, Skipped};

    let outcome = match receipt.code.as_str() {
        "runtime.mcp.unavailable" => Skipped,
        "runtime.mcp.unsampled" | "runtime.mcp.empty" | "runtime.mcp.live_unsampled" if live => {
            Degraded
        }
        "runtime.mcp.inconsistent" | "runtime.mcp.none_live" if live => Fail,
        "runtime.mcp.live" if live => Pass,
        _ => return false,
    };
    offline_runtime_semantics(receipt, outcome, live)
}

fn memory_semantics(receipt: &DoctorReceipt, live: bool) -> bool {
    let outcome = match receipt.code.as_str() {
        "runtime.memory.composed" if live => DoctorOutcome::Pass,
        "runtime.memory.unavailable" => DoctorOutcome::Skipped,
        _ => return false,
    };
    receipt_has_semantics(receipt, DoctorCheckClass::Offline, &[], &[], outcome, false)
}

fn active_probe_semantics(receipt: &DoctorReceipt, granted: bool) -> bool {
    use DoctorEffect::{CredentialRead, NetworkRequest};

    let required = match receipt.code.as_str() {
        "provider.reachability.not_granted" if !granted => false,
        "provider.reachability.broker_unavailable" if granted => true,
        _ => return false,
    };
    receipt_has_semantics(
        receipt,
        DoctorCheckClass::Active,
        &[CredentialRead, NetworkRequest],
        &[],
        DoctorOutcome::Skipped,
        required,
    )
}

fn offline_runtime_semantics(
    receipt: &DoctorReceipt,
    outcome: DoctorOutcome,
    required: bool,
) -> bool {
    receipt_has_semantics(
        receipt,
        DoctorCheckClass::Offline,
        &[],
        &[],
        outcome,
        required,
    )
}

fn receipt_has_semantics(
    receipt: &DoctorReceipt,
    class: DoctorCheckClass,
    declared_effects: &[DoctorEffect],
    observed_effects: &[DoctorEffect],
    outcome: DoctorOutcome,
    required_for_aggregate: bool,
) -> bool {
    receipt.class == class
        && receipt.declared_effects == declared_effects
        && receipt.observed_effects == observed_effects
        && receipt.outcome == outcome
        && receipt.required_for_aggregate == required_for_aggregate
}

fn receipt_detail_valid(receipt: &DoctorReceipt) -> bool {
    let expected = match receipt.code.as_str() {
        "evidence.registry.validated" => {
            "Bundled capability registry, corpus, and review bindings validated."
        }
        "evidence.registry.invalid" => "Bundled capability evidence failed closed validation.",
        "configuration.missing" => {
            "No configuration source exists; run openclaudia init."
        }
        "configuration.invalid" => {
            "Configuration could not be validated; details are withheld to avoid disclosing values or paths."
        }
        "configuration.unavailable" => {
            "No validated configuration object is attached to this runtime composition."
        }
        "configuration.validated" => {
            "Typed configuration loaded and passed its current validation boundary."
        }
        "configuration.attached" => {
            "The runtime supplied an already-validated typed configuration object."
        }
        "provider.configuration.unavailable" => {
            "Provider configuration cannot be assessed without valid configuration."
        }
        "provider.configuration.missing" => {
            "The selected provider has no matching typed configuration entry."
        }
        "provider.configuration.local" => {
            "The selected local provider does not require a configured credential."
        }
        "provider.configuration.credential_present" => {
            "Credential material is configured; its value and validity were not exposed or probed."
        }
        "provider.configuration.foreign_credential_unread" => {
            "No configured API key is present; the foreign Claude credential store was intentionally not read or refreshed."
        }
        "provider.configuration.credential_missing" => {
            "The selected remote provider has no configured credential."
        }
        "runtime.context.unavailable" => {
            "No agent runtime was constructed for this diagnostic; runtime readiness is unavailable."
        }
        "runtime.provider_transport.composed" => {
            "The real frontend provider transport is composed; remote readiness was not inferred."
        }
        "runtime.provider_transport.unavailable" => {
            "No real provider transport is available in this diagnostic composition."
        }
        "runtime.plugins.unavailable" => {
            "No real plugin manager is attached; no plugin health claim was made."
        }
        "runtime.plugins.empty" => {
            "The real plugin manager is attached but contains no loaded plugins."
        }
        "runtime.mcp.unavailable" => {
            "No real MCP manager is attached; no MCP health claim was made."
        }
        "runtime.mcp.unsampled" => {
            "The real MCP manager is attached, but bounded server state was unavailable without blocking."
        }
        "runtime.mcp.empty" => {
            "The real MCP manager is attached with zero registered servers; this is not live health."
        }
        "runtime.mcp.inconsistent" => {
            "The live MCP count exceeds the registered count; the snapshot is inconsistent."
        }
        "runtime.memory.composed" => {
            "The real frontend memory service is composed; persistence health was not inferred."
        }
        "runtime.memory.unavailable" => {
            "No real memory service is attached; no persistence health claim was made."
        }
        "provider.reachability.broker_unavailable" => {
            "The active grant was accepted, but no trusted-origin, redirect-safe, credential-safe, deadline-bounded provider capability probe is implemented."
        }
        "provider.reachability.not_granted" => {
            "Active provider reachability was not granted; no credential or network effect occurred."
        }
        "startup.migration_gate.not_run" => {
            "Writable startup migration checks are intentionally excluded from evidence-safe doctor runs."
        }
        "runtime.context.composed" => return runtime_context_detail_valid(&receipt.detail),
        "runtime.plugins.composed" => return plugin_detail_valid(&receipt.detail),
        "runtime.mcp.none_live" => return mcp_none_live_detail_valid(&receipt.detail),
        "runtime.mcp.live" => return mcp_live_detail_valid(&receipt.detail),
        "runtime.mcp.live_unsampled" => return mcp_live_unsampled_detail_valid(&receipt.detail),
        _ => return false,
    };
    receipt.detail == expected
}

fn runtime_context_detail_valid(detail: &str) -> bool {
    let Some(counts) = detail
        .strip_prefix("Actual run context is present with ")
        .and_then(|detail| detail.strip_suffix(" named environment grants."))
    else {
        return false;
    };
    let Some((read_only, remainder)) = counts.split_once(" read-only roots, ") else {
        return false;
    };
    let Some((read_write, environment)) = remainder.split_once(" read-write roots, and ") else {
        return false;
    };
    [read_only, read_write, environment]
        .iter()
        .all(|count| parse_bounded_count(count).is_some())
}

fn plugin_detail_valid(detail: &str) -> bool {
    detail
        .strip_prefix("The real plugin manager contains ")
        .and_then(|detail| {
            detail.strip_suffix(" loaded plugin components; execution health was not inferred.")
        })
        .and_then(parse_bounded_count)
        .is_some_and(|count| count > 0)
}

fn mcp_none_live_detail_valid(detail: &str) -> bool {
    detail
        .strip_suffix(" MCP servers are registered and none are live.")
        .and_then(parse_bounded_count)
        .is_some_and(|registered| registered > 0)
}

fn mcp_live_detail_valid(detail: &str) -> bool {
    let Some(counts) = detail
        .strip_suffix(" registered MCP servers are live.")
        .and_then(|detail| detail.split_once(" of "))
    else {
        return false;
    };
    let (Some(live), Some(registered)) =
        (parse_bounded_count(counts.0), parse_bounded_count(counts.1))
    else {
        return false;
    };
    live > 0 && live <= registered
}

fn mcp_live_unsampled_detail_valid(detail: &str) -> bool {
    detail
        .strip_suffix(" MCP servers are registered, but live connectivity was not sampled.")
        .and_then(parse_bounded_count)
        .is_some_and(|registered| registered > 0)
}

fn parse_bounded_count(value: &str) -> Option<usize> {
    let count = value.parse::<usize>().ok()?;
    (count <= MAX_REPORTED_COUNT && count.to_string() == value).then_some(count)
}

fn sorted_effects(effects: &[DoctorEffect]) -> Vec<DoctorEffect> {
    let mut effects = effects.to_vec();
    effects.sort_unstable();
    effects.dedup();
    effects
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
}

fn next_sequence(receipts: &[DoctorReceipt]) -> u16 {
    u16::try_from(receipts.len() + 1).unwrap_or(u16::MAX)
}

fn bounded_count(count: usize) -> usize {
    count.min(MAX_REPORTED_COUNT)
}

fn render_effects(effects: &[DoctorEffect]) -> String {
    if effects.is_empty() {
        return "none".to_string();
    }
    effects
        .iter()
        .map(|effect| effect.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, ProviderConfig, ProxyConfig};
    use crate::providers::ApiKey;
    use crate::secrets::SensitiveHeaders;

    fn config_with_target(target: &str, key: Option<&str>) -> AppConfig {
        let mut providers = std::collections::HashMap::new();
        providers.insert(
            target.to_string(),
            ProviderConfig {
                api_key: key
                    .map(|value| ApiKey::try_from_string(value.to_string()).expect("test API key")),
                base_url: "https://example.invalid".to_string(),
                model: Some("redaction-canary-model".to_string()),
                headers: SensitiveHeaders::new(),
                thinking: config::ThinkingConfig::default(),
            },
        );
        AppConfig {
            proxy: ProxyConfig {
                target: target.to_string(),
                ..ProxyConfig::default()
            },
            providers,
            hooks: config::HooksConfig::default(),
            session: config::SessionConfig::default(),
            keybindings: config::KeybindingsConfig::default(),
            vdd: config::VddConfig::default(),
            guardrails: config::GuardrailsConfig::default(),
            permissions: config::PermissionsConfig::default(),
            memory: config::MemoryConfig::default(),
            web_fetch: config::WebFetchConfig::default(),
            remote_actions: config::RemoteActionsConfig::default(),
            policy: crate::services::policy::EnterprisePolicy::default(),
            managed_settings_path: None,
        }
    }

    #[test]
    fn standalone_report_is_degraded_and_effect_bounded() {
        let config = config_with_target("openai", Some("doctor-secret-canary"));
        let report = diagnose(
            DoctorConfig::Attached(&config),
            &DoctorRuntimeSnapshot::standalone(),
            &DoctorRequest::default(),
        );

        report.validate().expect("valid doctor report");
        assert_eq!(report.aggregate(), DoctorAggregate::Degraded);
        assert!(report.receipts().iter().all(|receipt| {
            !receipt
                .observed_effects()
                .iter()
                .any(|effect| !effect.is_read_only())
        }));
        let rendered = serde_json::to_string(&report).expect("serialize doctor report");
        assert!(!rendered.contains("doctor-secret-canary"));
        assert!(!rendered.contains("redaction-canary-model"));
        assert!(!rendered.contains("example.invalid"));
    }

    #[test]
    fn synthetic_empty_managers_cannot_be_healthy() {
        let config = config_with_target("local", None);
        let runtime = DoctorRuntimeSnapshot {
            scope: DoctorScope::LiveRuntime,
            run_context: CompositionPresence::Present,
            plugin_manager: CompositionPresence::Present,
            mcp_manager: CompositionPresence::Present,
            mcp_registered_count: Some(0),
            ..DoctorRuntimeSnapshot::standalone()
        };
        let report = diagnose(
            DoctorConfig::Attached(&config),
            &runtime,
            &DoctorRequest::default(),
        );

        assert_eq!(report.aggregate(), DoctorAggregate::Degraded);
        for check_id in ["runtime.plugins", "runtime.mcp"] {
            let receipt = report
                .receipts()
                .iter()
                .find(|receipt| receipt.check_id() == check_id)
                .expect("runtime receipt");
            assert_ne!(receipt.outcome(), DoctorOutcome::Pass);
        }
    }

    #[test]
    fn active_probe_requires_exact_grant_and_stays_skipped_without_safe_broker() {
        assert!(DoctorRequest::try_new(["provider.reachability-extra"]).is_err());
        assert!(DoctorRequest::try_new(std::iter::repeat_n(
            ACTIVE_PROVIDER_REACHABILITY,
            MAX_ACTIVE_GRANTS + 1
        ))
        .is_err());
        let request =
            DoctorRequest::try_new([ACTIVE_PROVIDER_REACHABILITY]).expect("known active grant");
        let config = config_with_target("local", None);
        let report = diagnose(
            DoctorConfig::Attached(&config),
            &DoctorRuntimeSnapshot::standalone(),
            &request,
        );
        let receipt = report
            .receipts()
            .iter()
            .find(|receipt| receipt.check_id() == ACTIVE_PROVIDER_REACHABILITY)
            .expect("provider receipt");
        assert_eq!(receipt.class(), DoctorCheckClass::Active);
        assert_eq!(receipt.outcome(), DoctorOutcome::Skipped);
        assert!(receipt.observed_effects().is_empty());
        assert_eq!(receipt.code(), "provider.reachability.broker_unavailable");
    }

    #[test]
    fn report_validation_rejects_forged_observed_network_effect() {
        let config = config_with_target("local", None);
        let mut report = diagnose(
            DoctorConfig::Attached(&config),
            &DoctorRuntimeSnapshot::standalone(),
            &DoctorRequest::default(),
        );
        report.receipts[0]
            .observed_effects
            .push(DoctorEffect::NetworkRequest);

        assert_eq!(report.validate(), Err(DoctorContractError::Effects));
    }

    #[test]
    fn report_validation_rejects_forged_code_with_a_consistent_aggregate() {
        let config = config_with_target("local", None);
        let mut report = diagnose(
            DoctorConfig::Attached(&config),
            &DoctorRuntimeSnapshot::standalone(),
            &DoctorRequest::default(),
        );
        report.receipts[0].code = "evidence.registry.fabricated".to_string();
        report.receipts[0].outcome = DoctorOutcome::Degraded;
        report.aggregate = aggregate_receipts(&report.receipts);

        assert_eq!(report.validate(), Err(DoctorContractError::Semantics));
    }

    #[test]
    fn report_validation_rejects_injected_detail_even_when_other_fields_are_valid() {
        let config = config_with_target("local", None);
        let mut report = diagnose(
            DoctorConfig::Attached(&config),
            &DoctorRuntimeSnapshot::standalone(),
            &DoctorRequest::default(),
        );
        report.receipts[0].detail = "doctor-secret-injected-detail".to_string();

        assert_eq!(report.validate(), Err(DoctorContractError::Semantics));
    }

    #[test]
    fn standalone_and_live_frontends_share_receipt_schema_and_order() {
        let config = config_with_target("local", None);
        let standalone = diagnose(
            DoctorConfig::Attached(&config),
            &DoctorRuntimeSnapshot::standalone(),
            &DoctorRequest::default(),
        );
        let live = diagnose(
            DoctorConfig::Attached(&config),
            &DoctorRuntimeSnapshot {
                provider_transport: CompositionPresence::Present,
                plugin_manager: CompositionPresence::Present,
                mcp_manager: CompositionPresence::Present,
                mcp_registered_count: Some(0),
                ..DoctorRuntimeSnapshot::live_without_run()
            },
            &DoctorRequest::default(),
        );

        assert_eq!(
            standalone
                .receipts()
                .iter()
                .map(DoctorReceipt::check_id)
                .collect::<Vec<_>>(),
            live.receipts()
                .iter()
                .map(DoctorReceipt::check_id)
                .collect::<Vec<_>>()
        );
        assert!(standalone.validate().is_ok());
        assert!(live.validate().is_ok());
    }
}
