//! Event-sourced state machine for one canonical run.

use std::collections::BTreeMap;
use std::sync::Arc;

use thiserror::Error;

use super::cancellation::{CancellationHandle, CancellationReason, CancellationReceipt};
use super::context::{Actor, RunContextError, RunDescriptor, StateSnapshot};
use super::event::{
    CallKind, CallOutcome, EventScope, FailureImpact, RunFailure, RuntimeEvent, RuntimeEventKind,
    StateProposal, TerminalOutcome, TerminalState, RUNTIME_EVENT_SCHEMA_VERSION,
};
use super::ids::{CallId, CancellationId, RunId};
use super::trace::{TraceSink, TraceSinkError};

/// Concrete non-serializable handles paired with an immutable descriptor.
///
/// The trace sink and cancellation root are mandatory. There is no `None`
/// path that silently disables security or observability.
pub struct RunContext {
    descriptor: RunDescriptor,
    cancellation: CancellationHandle,
    trace: Arc<dyn TraceSink>,
}

impl RunContext {
    /// Construct the live context for a descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error if the descriptor is invalid, the handle is not the
    /// root node, or the root identity differs from the serialized binding.
    pub fn new(
        descriptor: RunDescriptor,
        cancellation: CancellationHandle,
        trace: Arc<dyn TraceSink>,
    ) -> Result<Self, RunContextError> {
        descriptor.validate()?;
        if cancellation.id() != cancellation.root_id()
            || descriptor.cancellation_root != cancellation.root_id()
        {
            return Err(RunContextError::CancellationRootMismatch);
        }
        Ok(Self {
            descriptor,
            cancellation,
            trace,
        })
    }

    /// Immutable serializable descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &RunDescriptor {
        &self.descriptor
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CallState {
    Active(CallKind),
    Finished {
        kind: CallKind,
        outcome: CallOutcome,
    },
}

/// Lifecycle phase reconstructed from the event trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunPhase {
    Active,
    Terminated(TerminalOutcome),
}

/// Replayed state of a canonical run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSnapshot {
    descriptor: RunDescriptor,
    next_sequence: u64,
    trace_bytes: u64,
    calls: BTreeMap<CallId, CallState>,
    committed: StateSnapshot,
    pending: Option<StateProposal>,
    blocking_failures: Vec<RunFailure>,
    cancellations: BTreeMap<CancellationId, CancellationReceipt>,
    phase: RunPhase,
}

impl RunSnapshot {
    /// Replay and validate a complete or active typed event trace.
    ///
    /// # Errors
    ///
    /// Rejects missing start events, schema/run/sequence mismatches, invalid
    /// transitions, trace-budget overflow, and contradictory terminal state.
    pub fn replay(events: &[RuntimeEvent]) -> Result<Self, ReplayError> {
        let (first, remainder) = events.split_first().ok_or(ReplayError::EmptyTrace)?;
        let mut snapshot = Self::from_start(first)?;
        for event in remainder {
            snapshot.apply(event)?;
        }
        Ok(snapshot)
    }

    fn from_start(event: &RuntimeEvent) -> Result<Self, ReplayError> {
        validate_schema(event)?;
        if event.sequence() != 0 {
            return Err(ReplayError::SequenceMismatch {
                expected: 0,
                actual: event.sequence(),
            });
        }
        if event.scope() != EventScope::Run {
            return Err(ReplayError::InvalidScope);
        }
        let RuntimeEventKind::RunStarted { descriptor } = event.kind() else {
            return Err(ReplayError::MissingStart);
        };
        descriptor
            .validate()
            .map_err(ReplayError::InvalidDescriptor)?;
        if event.run_id() != descriptor.run_id || event.actor() != &descriptor.actor {
            return Err(ReplayError::StartIdentityMismatch);
        }
        let trace_bytes = serialized_event_size(event)?;
        if trace_bytes > descriptor.budget.limits.trace_bytes {
            return Err(ReplayError::TraceBudgetExceeded {
                limit: descriptor.budget.limits.trace_bytes,
                attempted: trace_bytes,
            });
        }
        Ok(Self {
            descriptor: descriptor.clone(),
            next_sequence: 1,
            trace_bytes,
            calls: BTreeMap::new(),
            committed: descriptor.initial_state.clone(),
            pending: None,
            blocking_failures: Vec::new(),
            cancellations: BTreeMap::new(),
            phase: RunPhase::Active,
        })
    }

    fn apply(&mut self, event: &RuntimeEvent) -> Result<(), ReplayError> {
        validate_schema(event)?;
        if event.run_id() != self.descriptor.run_id {
            return Err(ReplayError::RunMismatch {
                expected: self.descriptor.run_id,
                actual: event.run_id(),
            });
        }
        if event.sequence() != self.next_sequence {
            return Err(ReplayError::SequenceMismatch {
                expected: self.next_sequence,
                actual: event.sequence(),
            });
        }
        if matches!(self.phase, RunPhase::Terminated(_)) {
            return Err(ReplayError::EventAfterTerminal);
        }

        let event_bytes = serialized_event_size(event)?;
        let attempted = self
            .trace_bytes
            .checked_add(event_bytes)
            .ok_or(ReplayError::TraceByteOverflow)?;
        if attempted > self.descriptor.budget.limits.trace_bytes {
            return Err(ReplayError::TraceBudgetExceeded {
                limit: self.descriptor.budget.limits.trace_bytes,
                attempted,
            });
        }

        self.apply_kind(event.scope(), event.kind())?;
        self.trace_bytes = attempted;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(ReplayError::SequenceOverflow)?;
        Ok(())
    }

    fn apply_kind(
        &mut self,
        scope: EventScope,
        kind: &RuntimeEventKind,
    ) -> Result<(), ReplayError> {
        match kind {
            RuntimeEventKind::RunStarted { .. } => Err(ReplayError::DuplicateStart),
            RuntimeEventKind::CallStarted { kind } => {
                let EventScope::Call(call_id) = scope else {
                    return Err(ReplayError::InvalidScope);
                };
                if self.calls.contains_key(&call_id) {
                    return Err(ReplayError::DuplicateCall(call_id));
                }
                self.calls.insert(call_id, CallState::Active(*kind));
                Ok(())
            }
            RuntimeEventKind::CallFinished { outcome } => {
                let EventScope::Call(call_id) = scope else {
                    return Err(ReplayError::InvalidScope);
                };
                let Some(CallState::Active(kind)) = self.calls.get(&call_id).cloned() else {
                    return Err(ReplayError::CallNotActive(call_id));
                };
                if let CallOutcome::Failed { failure, impact } = outcome {
                    if matches!(impact, FailureImpact::Partial | FailureImpact::Fatal) {
                        self.blocking_failures.push(failure.clone());
                    }
                }
                if let CallOutcome::Cancelled { cancellation } = outcome {
                    self.record_cancellation(cancellation)?;
                }
                self.calls.insert(
                    call_id,
                    CallState::Finished {
                        kind,
                        outcome: outcome.clone(),
                    },
                );
                Ok(())
            }
            RuntimeEventKind::StateProposed { proposal } => {
                require_run_scope(scope)?;
                if self.pending.is_some()
                    || proposal.base != self.committed
                    || proposal.proposed.generation.get() <= proposal.base.generation.get()
                {
                    return Err(ReplayError::InvalidStateProposal);
                }
                self.pending = Some(proposal.clone());
                Ok(())
            }
            RuntimeEventKind::StateCommitted { state } => {
                require_run_scope(scope)?;
                let Some(proposal) = self.pending.as_ref() else {
                    return Err(ReplayError::NoPendingState);
                };
                if state != &proposal.proposed {
                    return Err(ReplayError::CommitMismatch);
                }
                self.committed = state.clone();
                self.pending = None;
                Ok(())
            }
            RuntimeEventKind::CancellationRequested { receipt } => {
                require_run_scope(scope)?;
                self.record_cancellation(receipt)
            }
            RuntimeEventKind::RunTerminated { outcome } => {
                require_run_scope(scope)?;
                self.validate_terminal(outcome)?;
                self.phase = RunPhase::Terminated(outcome.clone());
                Ok(())
            }
        }
    }

    fn record_cancellation(&mut self, receipt: &CancellationReceipt) -> Result<(), ReplayError> {
        if receipt.root != self.descriptor.cancellation_root {
            return Err(ReplayError::ForeignCancellationReceipt);
        }
        if let Some(existing) = self.cancellations.get(&receipt.node) {
            return if existing == receipt {
                Ok(())
            } else {
                Err(ReplayError::ConflictingCancellation(receipt.node))
            };
        }
        self.cancellations.insert(receipt.node, receipt.clone());
        Ok(())
    }

    fn validate_terminal(&self, outcome: &TerminalOutcome) -> Result<(), ReplayError> {
        if self.active_call_count() != 0 {
            return Err(ReplayError::ActiveCallsAtTerminal);
        }
        let terminal_state = self.terminal_state();
        match outcome {
            TerminalOutcome::Succeeded { state } => {
                if state != &self.committed
                    || self.pending.is_some()
                    || !self.blocking_failures.is_empty()
                    || !self.cancellations.is_empty()
                {
                    return Err(ReplayError::IllegalSuccess);
                }
            }
            TerminalOutcome::Failed { state, .. } => {
                if state != &terminal_state {
                    return Err(ReplayError::TerminalStateMismatch);
                }
            }
            TerminalOutcome::PartiallyFailed { failures, state } => {
                if failures.is_empty()
                    || failures != &self.blocking_failures
                    || state != &terminal_state
                {
                    return Err(ReplayError::PartialFailureMismatch);
                }
            }
            TerminalOutcome::Cancelled {
                cancellation,
                state,
            } => {
                if self.cancellations.get(&cancellation.node) != Some(cancellation)
                    || state != &terminal_state
                {
                    return Err(ReplayError::CancellationMismatch);
                }
            }
            TerminalOutcome::Uncommitted {
                proposal,
                last_committed,
            } => {
                if self.pending.as_ref() != Some(proposal) || last_committed != &self.committed {
                    return Err(ReplayError::UncommittedStateMismatch);
                }
            }
        }
        Ok(())
    }

    fn terminal_state(&self) -> TerminalState {
        self.pending.as_ref().map_or_else(
            || TerminalState::Committed {
                state: self.committed.clone(),
            },
            |proposal| TerminalState::Pending {
                committed: self.committed.clone(),
                proposal: proposal.clone(),
            },
        )
    }

    /// Immutable descriptor recovered from the first event.
    #[must_use]
    pub const fn descriptor(&self) -> &RunDescriptor {
        &self.descriptor
    }

    /// Sequence the next accepted event must carry.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// JSON byte accounting used for the trace budget.
    #[must_use]
    pub const fn trace_bytes(&self) -> u64 {
        self.trace_bytes
    }

    /// Last committed state.
    #[must_use]
    pub const fn committed_state(&self) -> &StateSnapshot {
        &self.committed
    }

    /// Pending state proposal, if mutation has not been committed.
    #[must_use]
    pub const fn pending_state(&self) -> Option<&StateProposal> {
        self.pending.as_ref()
    }

    /// Current lifecycle phase.
    #[must_use]
    pub const fn phase(&self) -> &RunPhase {
        &self.phase
    }

    /// Number of calls that have not emitted a typed outcome.
    #[must_use]
    pub fn active_call_count(&self) -> usize {
        self.calls
            .values()
            .filter(|state| matches!(state, CallState::Active(_)))
            .count()
    }

    /// Failures that make a normal success outcome illegal.
    #[must_use]
    pub fn blocking_failures(&self) -> &[RunFailure] {
        &self.blocking_failures
    }

    /// Cancellation receipts indexed by their typed node identity.
    #[must_use]
    pub const fn cancellations(&self) -> &BTreeMap<CancellationId, CancellationReceipt> {
        &self.cancellations
    }
}

/// Live kernel that emits and applies one acknowledged event at a time.
pub struct RuntimeKernel {
    snapshot: RunSnapshot,
    events: Vec<RuntimeEvent>,
    cancellation: CancellationHandle,
    trace: Arc<dyn TraceSink>,
}

impl RuntimeKernel {
    /// Start a run and emit its identity/authority bindings as sequence zero.
    ///
    /// # Errors
    ///
    /// Returns an error when the descriptor cannot be replayed, its trace
    /// budget cannot hold the start event, or the sink rejects the event.
    pub async fn start(context: RunContext) -> Result<Self, KernelError> {
        let event = RuntimeEvent::new(
            context.descriptor.run_id,
            0,
            context.descriptor.actor.clone(),
            EventScope::Run,
            RuntimeEventKind::RunStarted {
                descriptor: context.descriptor.clone(),
            },
        );
        let snapshot = RunSnapshot::replay(std::slice::from_ref(&event))?;
        context.trace.append(&event).await?;
        Ok(Self {
            snapshot,
            events: vec![event],
            cancellation: context.cancellation,
            trace: context.trace,
        })
    }

    /// Current replayable state.
    #[must_use]
    pub const fn snapshot(&self) -> &RunSnapshot {
        &self.snapshot
    }

    /// Events acknowledged by the trace sink.
    #[must_use]
    pub fn events(&self) -> &[RuntimeEvent] {
        &self.events
    }

    /// Begin a typed call.
    ///
    /// # Errors
    ///
    /// Returns an error for a duplicate call, terminal run, invalid trace, or
    /// sink failure.
    pub async fn begin_call(
        &mut self,
        actor: &Actor,
        call_id: CallId,
        kind: CallKind,
    ) -> Result<RuntimeEvent, KernelError> {
        self.emit(
            actor,
            EventScope::Call(call_id),
            RuntimeEventKind::CallStarted { kind },
        )
        .await
    }

    /// Finish an active call with a typed outcome.
    ///
    /// # Errors
    ///
    /// Returns an error when the call is unknown/already finished, the run is
    /// terminal, or the trace transition cannot be committed.
    pub async fn finish_call(
        &mut self,
        actor: &Actor,
        call_id: CallId,
        outcome: CallOutcome,
    ) -> Result<RuntimeEvent, KernelError> {
        if let CallOutcome::Cancelled { cancellation } = &outcome {
            let actual = self.cancellation.receipt_for(cancellation.node);
            if actual.as_ref() != Some(cancellation) {
                return Err(KernelError::CancellationReceiptMismatch);
            }
        }
        self.emit(
            actor,
            EventScope::Call(call_id),
            RuntimeEventKind::CallFinished { outcome },
        )
        .await
    }

    /// Propose a state mutation against the exact committed generation.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale/non-monotonic proposal, an existing
    /// proposal, terminal run, or trace failure.
    pub async fn propose_state(
        &mut self,
        actor: &Actor,
        proposal: StateProposal,
    ) -> Result<RuntimeEvent, KernelError> {
        self.emit(
            actor,
            EventScope::Run,
            RuntimeEventKind::StateProposed { proposal },
        )
        .await
    }

    /// Commit the exact pending state proposal.
    ///
    /// # Errors
    ///
    /// Returns an error when no matching proposal exists or the trace cannot
    /// commit the event.
    pub async fn commit_state(
        &mut self,
        actor: &Actor,
        state: StateSnapshot,
    ) -> Result<RuntimeEvent, KernelError> {
        self.emit(
            actor,
            EventScope::Run,
            RuntimeEventKind::StateCommitted { state },
        )
        .await
    }

    /// Record an already requested cancellation from this run's tree.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign tree, a live node, a duplicate receipt,
    /// terminal run, or trace failure.
    pub async fn observe_cancellation(
        &mut self,
        actor: &Actor,
        handle: &CancellationHandle,
    ) -> Result<RuntimeEvent, KernelError> {
        if handle.root_id() != self.cancellation.root_id() {
            return Err(KernelError::ForeignCancellationTree);
        }
        let receipt = handle
            .receipt()
            .ok_or(KernelError::CancellationNotRequested)?;
        self.emit(
            actor,
            EventScope::Run,
            RuntimeEventKind::CancellationRequested { receipt },
        )
        .await
    }

    /// Request and record cancellation for a node in this run's tree.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign tree or rejected trace transition.
    pub async fn cancel(
        &mut self,
        actor: &Actor,
        handle: &CancellationHandle,
        reason: CancellationReason,
    ) -> Result<RuntimeEvent, KernelError> {
        if handle.root_id() != self.cancellation.root_id() {
            return Err(KernelError::ForeignCancellationTree);
        }
        let _receipt = handle.cancel(reason);
        self.observe_cancellation(actor, handle).await
    }

    /// Emit committed success only when no cancellation, blocking failure,
    /// active call, or pending mutation exists.
    ///
    /// # Errors
    ///
    /// Returns an error when success is unsafe or the terminal event cannot be
    /// committed.
    pub async fn succeed(&mut self, actor: &Actor) -> Result<RuntimeEvent, KernelError> {
        if let Some(receipt) = self
            .cancellation
            .tree_receipts()
            .into_iter()
            .find(|receipt| !self.snapshot.cancellations.contains_key(&receipt.node))
        {
            return Err(KernelError::UnrecordedCancellation(receipt.node));
        }
        let outcome = TerminalOutcome::Succeeded {
            state: self.snapshot.committed.clone(),
        };
        self.terminate(actor, outcome).await
    }

    /// Terminate with a typed runtime failure.
    ///
    /// # Errors
    ///
    /// Returns an error if calls remain active or the terminal event cannot be
    /// committed.
    pub async fn fail(
        &mut self,
        actor: &Actor,
        failure: RunFailure,
    ) -> Result<RuntimeEvent, KernelError> {
        let outcome = TerminalOutcome::Failed {
            failure,
            state: self.snapshot.terminal_state(),
        };
        self.terminate(actor, outcome).await
    }

    /// Terminate after one or more calls produced partial/fatal effects.
    ///
    /// # Errors
    ///
    /// Returns an error when no blocking failure exists or the terminal event
    /// cannot be committed.
    pub async fn finish_partially_failed(
        &mut self,
        actor: &Actor,
    ) -> Result<RuntimeEvent, KernelError> {
        let outcome = TerminalOutcome::PartiallyFailed {
            failures: self.snapshot.blocking_failures.clone(),
            state: self.snapshot.terminal_state(),
        };
        self.terminate(actor, outcome).await
    }

    /// Terminate using a cancellation receipt already present in the trace.
    ///
    /// # Errors
    ///
    /// Returns an error if the receipt is absent or the terminal event cannot
    /// be committed.
    pub async fn finish_cancelled(
        &mut self,
        actor: &Actor,
        cancellation: CancellationId,
    ) -> Result<RuntimeEvent, KernelError> {
        let receipt = self
            .snapshot
            .cancellations
            .get(&cancellation)
            .cloned()
            .ok_or(KernelError::CancellationNotRecorded(cancellation))?;
        let outcome = TerminalOutcome::Cancelled {
            cancellation: receipt,
            state: self.snapshot.terminal_state(),
        };
        self.terminate(actor, outcome).await
    }

    /// Terminate explicitly because a proposed state was not committed.
    ///
    /// # Errors
    ///
    /// Returns an error if there is no pending proposal or the terminal event
    /// cannot be committed.
    pub async fn finish_uncommitted(&mut self, actor: &Actor) -> Result<RuntimeEvent, KernelError> {
        let proposal = self
            .snapshot
            .pending
            .clone()
            .ok_or(KernelError::NoPendingState)?;
        let outcome = TerminalOutcome::Uncommitted {
            proposal,
            last_committed: self.snapshot.committed.clone(),
        };
        self.terminate(actor, outcome).await
    }

    async fn terminate(
        &mut self,
        actor: &Actor,
        outcome: TerminalOutcome,
    ) -> Result<RuntimeEvent, KernelError> {
        self.emit(
            actor,
            EventScope::Run,
            RuntimeEventKind::RunTerminated { outcome },
        )
        .await
    }

    async fn emit(
        &mut self,
        actor: &Actor,
        scope: EventScope,
        kind: RuntimeEventKind,
    ) -> Result<RuntimeEvent, KernelError> {
        let event = RuntimeEvent::new(
            self.snapshot.descriptor.run_id,
            self.snapshot.next_sequence,
            actor.clone(),
            scope,
            kind,
        );
        let mut next = self.snapshot.clone();
        next.apply(&event)?;
        self.trace.append(&event).await?;
        self.snapshot = next;
        self.events.push(event.clone());
        Ok(event)
    }
}

const fn validate_schema(event: &RuntimeEvent) -> Result<(), ReplayError> {
    if event.schema_version() == RUNTIME_EVENT_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(ReplayError::SchemaMismatch {
            expected: RUNTIME_EVENT_SCHEMA_VERSION,
            actual: event.schema_version(),
        })
    }
}

fn require_run_scope(scope: EventScope) -> Result<(), ReplayError> {
    if scope == EventScope::Run {
        Ok(())
    } else {
        Err(ReplayError::InvalidScope)
    }
}

fn serialized_event_size(event: &RuntimeEvent) -> Result<u64, ReplayError> {
    let bytes = serde_json::to_vec(event).map_err(ReplayError::EventSerialization)?;
    u64::try_from(bytes.len()).map_err(|_| ReplayError::TraceByteOverflow)
}

/// Deterministic replay violation.
#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("runtime trace is empty")]
    EmptyTrace,
    #[error("runtime trace does not begin with run_started")]
    MissingStart,
    #[error("runtime event schema mismatch: expected {expected}, got {actual}")]
    SchemaMismatch { expected: u16, actual: u16 },
    #[error("runtime event sequence mismatch: expected {expected}, got {actual}")]
    SequenceMismatch { expected: u64, actual: u64 },
    #[error("runtime event sequence overflow")]
    SequenceOverflow,
    #[error("runtime event belongs to run {actual}, expected {expected}")]
    RunMismatch { expected: RunId, actual: RunId },
    #[error("run_started event identity does not match its descriptor")]
    StartIdentityMismatch,
    #[error("invalid run descriptor: {0}")]
    InvalidDescriptor(RunContextError),
    #[error("event has the wrong run/call scope for its type")]
    InvalidScope,
    #[error("run_started may only occur at sequence zero")]
    DuplicateStart,
    #[error("call id was already used: {0}")]
    DuplicateCall(CallId),
    #[error("call is unknown or no longer active: {0}")]
    CallNotActive(CallId),
    #[error("state proposal is stale, non-monotonic, or another proposal is pending")]
    InvalidStateProposal,
    #[error("there is no pending state proposal")]
    NoPendingState,
    #[error("state commit does not match the pending proposal")]
    CommitMismatch,
    #[error("cancellation node has a conflicting trace receipt: {0}")]
    ConflictingCancellation(CancellationId),
    #[error("cancellation receipt belongs to a different run tree")]
    ForeignCancellationReceipt,
    #[error("events cannot follow a terminal outcome")]
    EventAfterTerminal,
    #[error("terminal outcome cannot be emitted while calls are active")]
    ActiveCallsAtTerminal,
    #[error("success is illegal after cancellation, partial failure, or pending state")]
    IllegalSuccess,
    #[error("terminal state does not match replayed state")]
    TerminalStateMismatch,
    #[error("partial-failure terminal data does not match replayed failures")]
    PartialFailureMismatch,
    #[error("cancelled terminal data does not match a recorded cancellation")]
    CancellationMismatch,
    #[error("uncommitted terminal data does not match the pending proposal")]
    UncommittedStateMismatch,
    #[error("trace byte accounting overflow")]
    TraceByteOverflow,
    #[error("trace budget exceeded: limit {limit} bytes, attempted {attempted} bytes")]
    TraceBudgetExceeded { limit: u64, attempted: u64 },
    #[error("runtime event serialization failed: {0}")]
    EventSerialization(serde_json::Error),
}

/// Live-kernel failure.
#[derive(Debug, Error)]
pub enum KernelError {
    #[error(transparent)]
    Replay(#[from] ReplayError),
    #[error(transparent)]
    Trace(#[from] TraceSinkError),
    #[error("cancellation handle belongs to a different run tree")]
    ForeignCancellationTree,
    #[error("cancellation was not requested for this node")]
    CancellationNotRequested,
    #[error("cancellation was not recorded for node {0}")]
    CancellationNotRecorded(CancellationId),
    #[error("cancellation for node {0} must be recorded before finalization")]
    UnrecordedCancellation(CancellationId),
    #[error("cancelled call receipt does not match this run's live cancellation tree")]
    CancellationReceiptMismatch,
    #[error("there is no pending state proposal")]
    NoPendingState,
}
