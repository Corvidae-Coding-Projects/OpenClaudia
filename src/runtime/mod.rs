//! Canonical run identity, context bindings, cancellation, typed events, and
//! replayable terminal-state kernel.
//!
//! S-010 deliberately does not migrate the existing frontend loops. It
//! establishes the fail-closed state machine those adapters will target. The
//! follow-on slices named in the remediation graph own full capability
//! handles (S-019), provider-native continuation (S-044), atomic budget
//! reservations (S-051), persistence (S-031/S-037), and frontend migration.

mod cancellation;
mod context;
mod event;
mod ids;
mod kernel;
mod reference;
mod trace;

pub use cancellation::{
    CancellationHandle, CancellationReason, CancellationReceipt, CancellationTree,
};
pub use context::{
    Actor, ActorRole, BudgetLimits, CapabilityBinding, CapabilityKind, ContentDigest,
    DigestParseError, ProviderContinuation, ProviderId, RunBudget, RunContextError, RunDescriptor,
    RunDescriptorParts, StateSnapshot, WorkspaceBinding,
};
pub use event::{
    CallKind, CallOutcome, EventScope, FailureImpact, RunFailure, RunFailureCode, RuntimeEvent,
    RuntimeEventKind, StateProposal, TerminalOutcome, TerminalState, RUNTIME_EVENT_SCHEMA_VERSION,
};
pub use ids::{
    ActorId, BudgetGeneration, BudgetId, CallId, CancellationId, CapabilityGeneration,
    ContinuationGeneration, RunId, StateGeneration, WorkspaceGeneration,
};
pub use kernel::{KernelError, ReplayError, RunContext, RunPhase, RunSnapshot, RuntimeKernel};
pub use reference::{ReferenceRunAdapter, ReferenceRunResult};
pub use trace::{ReferenceTraceSink, TraceSink, TraceSinkError};
