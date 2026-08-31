//! Versioned, typed events emitted by the runtime kernel.

use serde::{Deserialize, Serialize};

use super::cancellation::CancellationReceipt;
use super::context::{Actor, ContentDigest, RunDescriptor, StateSnapshot};
use super::ids::{CallId, RunId};

/// Current runtime event schema. Replay rejects every other version.
pub const RUNTIME_EVENT_SCHEMA_VERSION: u16 = 1;

/// Causal scope of an event. Run-level events never use a sentinel call ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", content = "call_id", rename_all = "snake_case")]
pub enum EventScope {
    Run,
    Call(CallId),
}

/// Kind of work represented by a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    Provider,
    Tool,
    Hook,
    Persistence,
    Review,
    Frontend,
}

/// Stable class of a local or remote runtime failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunFailureCode {
    Provider,
    Tool,
    Hook,
    Policy,
    Persistence,
    Frontend,
    Trace,
    Protocol,
    Invariant,
}

/// Typed failure data. `detail` is inert evidence, not a control channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunFailure {
    pub code: RunFailureCode,
    pub detail: String,
}

/// Whether a failed call may be retried or has affected the run result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureImpact {
    Retryable,
    Partial,
    Fatal,
}

/// Typed outcome of an individual call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum CallOutcome {
    Succeeded {
        result_digest: ContentDigest,
    },
    Failed {
        failure: RunFailure,
        impact: FailureImpact,
    },
    Cancelled {
        cancellation: CancellationReceipt,
    },
}

/// Proposed next state, causally bound to the last committed generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateProposal {
    pub base: StateSnapshot,
    pub proposed: StateSnapshot,
}

/// State visible when a non-success terminal outcome is emitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case", deny_unknown_fields)]
pub enum TerminalState {
    Committed {
        state: StateSnapshot,
    },
    Pending {
        committed: StateSnapshot,
        proposal: StateProposal,
    },
}

/// Exactly one terminal outcome closes a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum TerminalOutcome {
    Succeeded {
        state: StateSnapshot,
    },
    Failed {
        failure: RunFailure,
        state: TerminalState,
    },
    PartiallyFailed {
        failures: Vec<RunFailure>,
        state: TerminalState,
    },
    Cancelled {
        cancellation: CancellationReceipt,
        state: TerminalState,
    },
    Uncommitted {
        proposal: StateProposal,
        last_committed: StateSnapshot,
    },
}

/// Versioned payload of a runtime event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeEventKind {
    RunStarted { descriptor: Box<RunDescriptor> },
    CallStarted { kind: CallKind },
    CallFinished { outcome: CallOutcome },
    StateProposed { proposal: StateProposal },
    StateCommitted { state: StateSnapshot },
    CancellationRequested { receipt: CancellationReceipt },
    RunTerminated { outcome: TerminalOutcome },
}

/// One causal event in a canonical run trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEvent {
    schema_version: u16,
    run_id: RunId,
    sequence: u64,
    actor: Actor,
    scope: EventScope,
    kind: RuntimeEventKind,
}

impl RuntimeEvent {
    pub(crate) const fn new(
        run_id: RunId,
        sequence: u64,
        actor: Actor,
        scope: EventScope,
        kind: RuntimeEventKind,
    ) -> Self {
        Self {
            schema_version: RUNTIME_EVENT_SCHEMA_VERSION,
            run_id,
            sequence,
            actor,
            scope,
            kind,
        }
    }

    /// Event schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Owning run identity.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Zero-based causal sequence within the run.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Actor that emitted the event.
    #[must_use]
    pub const fn actor(&self) -> &Actor {
        &self.actor
    }

    /// Run or call scope.
    #[must_use]
    pub const fn scope(&self) -> EventScope {
        self.scope
    }

    /// Typed event payload.
    #[must_use]
    pub const fn kind(&self) -> &RuntimeEventKind {
        &self.kind
    }
}
