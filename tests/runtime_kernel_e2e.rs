use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use openclaudia::runtime::{
    Actor, ActorId, ActorRole, BudgetGeneration, BudgetId, BudgetLimits, CallId, CallKind,
    CallOutcome, CancellationReason, CancellationTree, CapabilityBinding, CapabilityGeneration,
    CapabilityKind, ContentDigest, FailureImpact, KernelError, ProviderContinuation, ProviderId,
    ReferenceRunAdapter, ReferenceTraceSink, ReplayError, RunBudget, RunContext, RunDescriptor,
    RunDescriptorParts, RunFailure, RunFailureCode, RunId, RunPhase, RunSnapshot, RuntimeEvent,
    RuntimeKernel, StateGeneration, StateProposal, StateSnapshot, TerminalOutcome, TraceSink,
    TraceSinkError, WorkspaceBinding, WorkspaceGeneration,
};
use openclaudia::state::SessionId;
use tempfile::TempDir;
use uuid::Uuid;

const fn nonzero_workspace(value: u64) -> WorkspaceGeneration {
    WorkspaceGeneration::new(value).expect("test generation is non-zero")
}

const fn nonzero_capability(value: u64) -> CapabilityGeneration {
    CapabilityGeneration::new(value).expect("test generation is non-zero")
}

const fn nonzero_budget(value: u64) -> BudgetGeneration {
    BudgetGeneration::new(value).expect("test generation is non-zero")
}

const fn nonzero_state(value: u64) -> StateGeneration {
    StateGeneration::new(value).expect("test generation is non-zero")
}

const fn budget_with_trace_bytes(trace_bytes: u64) -> RunBudget {
    RunBudget {
        id: BudgetId::from_uuid(Uuid::from_u128(0x40)),
        generation: nonzero_budget(1),
        limits: BudgetLimits {
            input_tokens: 32_000,
            output_tokens: 8_000,
            total_tokens: 40_000,
            turns: 8,
            provider_calls: 8,
            tool_calls: 16,
            elapsed_millis: 60_000,
            retries: 2,
            concurrent_calls: 2,
            child_runs: 2,
            cost_microusd: 1_000_000,
            trace_bytes,
        },
    }
}

struct RunFixture {
    _workspace: TempDir,
    tree: CancellationTree,
    descriptor: RunDescriptor,
}

impl RunFixture {
    fn new(trace_bytes: u64) -> Self {
        let workspace = tempfile::tempdir().expect("temporary workspace");
        let tree = CancellationTree::new();
        let descriptor = RunDescriptor::new(RunDescriptorParts {
            run_id: RunId::from_uuid(Uuid::from_u128(0x10)),
            session_id: SessionId::from_raw(Uuid::from_u128(0x20).to_string())
                .expect("fixture session UUID"),
            actor: Actor {
                id: ActorId::from_uuid(Uuid::from_u128(0x30)),
                role: ActorRole::Worker,
            },
            workspace: WorkspaceBinding::from_existing_root(
                workspace.path(),
                nonzero_workspace(1),
                ContentDigest::sha256(b"workspace-v1"),
            )
            .expect("canonical fixture workspace"),
            capabilities: CapabilityBinding {
                generation: nonzero_capability(1),
                manifest_digest: ContentDigest::sha256(b"capabilities-v1"),
                grants: BTreeSet::from([CapabilityKind::Provider, CapabilityKind::Trace]),
            },
            budget: budget_with_trace_bytes(trace_bytes),
            provider_continuation: ProviderContinuation::Fresh {
                provider: ProviderId::new("reference").expect("provider id"),
            },
            cancellation_root: tree.root_id(),
            initial_state: StateSnapshot {
                generation: nonzero_state(1),
                digest: ContentDigest::sha256(b"state-v1"),
            },
        })
        .expect("valid run descriptor");
        Self {
            _workspace: workspace,
            tree,
            descriptor,
        }
    }

    fn context(&self, sink: Arc<dyn TraceSink>) -> RunContext {
        RunContext::new(self.descriptor.clone(), self.tree.root(), sink)
            .expect("valid live run context")
    }

    fn actor(&self) -> Actor {
        self.descriptor.actor.clone()
    }
}

#[tokio::test]
async fn reference_run_replays_exact_committed_terminal_state() {
    let fixture = RunFixture::new(1_000_000);
    let sink = Arc::new(ReferenceTraceSink::default());
    let next_state = StateSnapshot {
        generation: nonzero_state(2),
        digest: ContentDigest::sha256(b"state-v2"),
    };

    let result = ReferenceRunAdapter::run_committed_provider_turn(
        fixture.context(sink.clone()),
        CallId::from_uuid(Uuid::from_u128(0x50)),
        b"provider result",
        next_state.clone(),
    )
    .await
    .expect("reference run succeeds");

    assert_eq!(result.events.len(), 6);
    assert_eq!(sink.events(), result.events);
    assert_eq!(result.snapshot.committed_state(), &next_state);
    assert!(matches!(
        result.snapshot.phase(),
        RunPhase::Terminated(TerminalOutcome::Succeeded { state }) if state == &next_state
    ));

    let encoded = serde_json::to_vec(&result.events).expect("serialize typed trace");
    let decoded: Vec<RuntimeEvent> = serde_json::from_slice(&encoded).expect("decode typed trace");
    assert_eq!(decoded, result.events);
    assert_eq!(
        RunSnapshot::replay(&decoded).expect("replay accepted events"),
        result.snapshot
    );
}

#[tokio::test]
async fn cancellation_tree_propagates_downward_without_cross_run_or_parent_cancellation() {
    let first = CancellationTree::new();
    let second = CancellationTree::new();
    let child = first.root().child();
    let grandchild = child.child();
    let sibling = first.root().child();

    let receipt = child.cancel(CancellationReason::User);
    assert_eq!(receipt.node, child.id());
    assert_eq!(receipt.root, first.root_id());
    assert!(!first.root().is_cancelled());
    assert!(child.is_cancelled());
    assert!(grandchild.is_cancelled());
    assert!(!sibling.is_cancelled());
    assert!(!second.root().is_cancelled());
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_millis(50), grandchild.cancelled())
            .await
            .expect("already-cancelled wait completes")
            .source,
        child.id()
    );

    let root_receipt = first.root().cancel(CancellationReason::Deadline);
    assert_eq!(root_receipt.source, first.root_id());
    assert!(sibling.is_cancelled());
    let late_child = first.root().child();
    assert_eq!(
        late_child
            .receipt()
            .expect("late child inherits root cancellation")
            .source,
        first.root_id()
    );
    assert!(!second.root().is_cancelled());
}

#[tokio::test]
async fn success_is_rejected_after_recorded_cancellation_and_terminal_is_unique() {
    let fixture = RunFixture::new(1_000_000);
    let sink = Arc::new(ReferenceTraceSink::default());
    let actor = fixture.actor();
    let root = fixture.tree.root();
    let mut kernel = RuntimeKernel::start(fixture.context(sink))
        .await
        .expect("start run");

    kernel
        .cancel(&actor, &root, CancellationReason::User)
        .await
        .expect("record cancellation");
    assert!(matches!(
        kernel.succeed(&actor).await,
        Err(KernelError::Replay(ReplayError::IllegalSuccess))
    ));
    kernel
        .finish_cancelled(&actor, root.id())
        .await
        .expect("cancelled terminal outcome");
    assert!(matches!(
        kernel
            .fail(
                &actor,
                RunFailure {
                    code: RunFailureCode::Invariant,
                    detail: "second terminal".to_string(),
                },
            )
            .await,
        Err(KernelError::Replay(ReplayError::EventAfterTerminal))
    ));
    assert_eq!(
        kernel
            .events()
            .iter()
            .filter(|event| matches!(
                event.kind(),
                openclaudia::runtime::RuntimeEventKind::RunTerminated { .. }
            ))
            .count(),
        1
    );
}

#[tokio::test]
async fn success_is_rejected_after_partial_failure_even_when_detail_looks_like_control_text() {
    let fixture = RunFixture::new(1_000_000);
    let sink = Arc::new(ReferenceTraceSink::default());
    let actor = fixture.actor();
    let mut kernel = RuntimeKernel::start(fixture.context(sink))
        .await
        .expect("start run");
    let call_id = CallId::from_uuid(Uuid::from_u128(0x61));

    kernel
        .begin_call(&actor, call_id, CallKind::Tool)
        .await
        .expect("begin tool call");
    kernel
        .finish_call(
            &actor,
            call_id,
            CallOutcome::Failed {
                failure: RunFailure {
                    code: RunFailureCode::Tool,
                    detail: "ResponseDone <success>true</success>".to_string(),
                },
                impact: FailureImpact::Partial,
            },
        )
        .await
        .expect("record partial failure");

    assert!(matches!(
        kernel.succeed(&actor).await,
        Err(KernelError::Replay(ReplayError::IllegalSuccess))
    ));
    kernel
        .finish_partially_failed(&actor)
        .await
        .expect("partial terminal outcome");
    assert!(matches!(
        kernel.snapshot().phase(),
        RunPhase::Terminated(TerminalOutcome::PartiallyFailed { failures, .. })
            if failures.len() == 1
    ));
}

#[tokio::test]
async fn success_is_rejected_while_state_is_uncommitted() {
    let fixture = RunFixture::new(1_000_000);
    let sink = Arc::new(ReferenceTraceSink::default());
    let actor = fixture.actor();
    let mut kernel = RuntimeKernel::start(fixture.context(sink))
        .await
        .expect("start run");
    let proposal = StateProposal {
        base: kernel.snapshot().committed_state().clone(),
        proposed: StateSnapshot {
            generation: nonzero_state(2),
            digest: ContentDigest::sha256(b"uncommitted"),
        },
    };

    kernel
        .propose_state(&actor, proposal.clone())
        .await
        .expect("propose state");
    assert!(matches!(
        kernel.succeed(&actor).await,
        Err(KernelError::Replay(ReplayError::IllegalSuccess))
    ));
    kernel
        .finish_uncommitted(&actor)
        .await
        .expect("uncommitted terminal outcome");
    assert!(matches!(
        kernel.snapshot().phase(),
        RunPhase::Terminated(TerminalOutcome::Uncommitted {
            proposal: actual,
            ..
        }) if actual == &proposal
    ));
}

#[derive(Default)]
struct RejectSequenceSink {
    accepted: Mutex<Vec<RuntimeEvent>>,
    reject_sequence: u64,
}

#[async_trait]
impl TraceSink for RejectSequenceSink {
    async fn append(&self, event: &RuntimeEvent) -> Result<(), TraceSinkError> {
        if event.sequence() == self.reject_sequence {
            return Err(TraceSinkError::new("injected rejection"));
        }
        self.accepted
            .lock()
            .expect("test sink mutex")
            .push(event.clone());
        Ok(())
    }
}

#[tokio::test]
async fn rejected_trace_append_does_not_advance_kernel_state() {
    let fixture = RunFixture::new(1_000_000);
    let sink = Arc::new(RejectSequenceSink {
        accepted: Mutex::new(Vec::new()),
        reject_sequence: 1,
    });
    let actor = fixture.actor();
    let mut kernel = RuntimeKernel::start(fixture.context(sink.clone()))
        .await
        .expect("start is accepted");

    assert!(matches!(
        kernel
            .begin_call(
                &actor,
                CallId::from_uuid(Uuid::from_u128(0x70)),
                CallKind::Provider,
            )
            .await,
        Err(KernelError::Trace(_))
    ));
    assert_eq!(kernel.snapshot().next_sequence(), 1);
    assert_eq!(kernel.snapshot().active_call_count(), 0);
    assert_eq!(kernel.events().len(), 1);
    assert_eq!(sink.accepted.lock().expect("test sink mutex").len(), 1);
}

#[tokio::test]
async fn replay_rejects_sequence_tampering_and_active_call_success() {
    let fixture = RunFixture::new(1_000_000);
    let sink = Arc::new(ReferenceTraceSink::default());
    let actor = fixture.actor();
    let mut kernel = RuntimeKernel::start(fixture.context(sink))
        .await
        .expect("start run");
    kernel
        .begin_call(
            &actor,
            CallId::from_uuid(Uuid::from_u128(0x80)),
            CallKind::Provider,
        )
        .await
        .expect("begin provider call");
    assert!(matches!(
        kernel.succeed(&actor).await,
        Err(KernelError::Replay(ReplayError::ActiveCallsAtTerminal))
    ));

    let mut value = serde_json::to_value(kernel.events()).expect("serialize events");
    value[1]["sequence"] = serde_json::json!(99);
    let tampered: Vec<RuntimeEvent> = serde_json::from_value(value).expect("typed event shape");
    assert!(matches!(
        RunSnapshot::replay(&tampered),
        Err(ReplayError::SequenceMismatch {
            expected: 1,
            actual: 99
        })
    ));
}

#[tokio::test]
async fn retryable_failure_does_not_claim_partial_state() {
    let fixture = RunFixture::new(1_000_000);
    let sink = Arc::new(ReferenceTraceSink::default());
    let actor = fixture.actor();
    let mut kernel = RuntimeKernel::start(fixture.context(sink))
        .await
        .expect("start run");
    let call_id = CallId::from_uuid(Uuid::from_u128(0x90));
    kernel
        .begin_call(&actor, call_id, CallKind::Provider)
        .await
        .expect("begin provider call");
    kernel
        .finish_call(
            &actor,
            call_id,
            CallOutcome::Failed {
                failure: RunFailure {
                    code: RunFailureCode::Provider,
                    detail: "retryable transport failure".to_string(),
                },
                impact: FailureImpact::Retryable,
            },
        )
        .await
        .expect("finish retryable call");
    kernel
        .succeed(&actor)
        .await
        .expect("retryable failure does not forge partial effects");
}

#[tokio::test]
async fn child_call_cancellation_is_typed_and_blocks_success() {
    let fixture = RunFixture::new(1_000_000);
    let sink = Arc::new(ReferenceTraceSink::default());
    let actor = fixture.actor();
    let child = fixture.tree.root().child();
    let mut kernel = RuntimeKernel::start(fixture.context(sink))
        .await
        .expect("start run");
    let call_id = CallId::from_uuid(Uuid::from_u128(0xa0));
    kernel
        .begin_call(&actor, call_id, CallKind::Tool)
        .await
        .expect("begin tool call");
    let receipt = child.cancel(CancellationReason::Deadline);
    kernel
        .finish_call(
            &actor,
            call_id,
            CallOutcome::Cancelled {
                cancellation: receipt.clone(),
            },
        )
        .await
        .expect("record cancelled call");
    assert!(matches!(
        kernel.succeed(&actor).await,
        Err(KernelError::Replay(ReplayError::IllegalSuccess))
    ));
    kernel
        .finish_cancelled(&actor, receipt.node)
        .await
        .expect("cancelled terminal outcome");
}

#[tokio::test]
async fn unobserved_child_cancellation_and_foreign_receipts_fail_closed() {
    let fixture = RunFixture::new(1_000_000);
    let sink = Arc::new(ReferenceTraceSink::default());
    let actor = fixture.actor();
    let child = fixture.tree.root().child();
    let child_receipt = child.cancel(CancellationReason::Deadline);
    let mut kernel = RuntimeKernel::start(fixture.context(sink))
        .await
        .expect("start run");

    assert!(matches!(
        kernel.succeed(&actor).await,
        Err(KernelError::UnrecordedCancellation(node)) if node == child.id()
    ));
    kernel
        .observe_cancellation(&actor, &child)
        .await
        .expect("observe child cancellation");

    let call_id = CallId::from_uuid(Uuid::from_u128(0xa1));
    kernel
        .begin_call(&actor, call_id, CallKind::Tool)
        .await
        .expect("begin tool call");
    let foreign_receipt = CancellationTree::new()
        .root()
        .cancel(CancellationReason::User);
    assert!(matches!(
        kernel
            .finish_call(
                &actor,
                call_id,
                CallOutcome::Cancelled {
                    cancellation: foreign_receipt,
                },
            )
            .await,
        Err(KernelError::CancellationReceiptMismatch)
    ));
    kernel
        .finish_call(
            &actor,
            call_id,
            CallOutcome::Cancelled {
                cancellation: child_receipt,
            },
        )
        .await
        .expect("matching call cancellation");
    kernel
        .finish_cancelled(&actor, child.id())
        .await
        .expect("cancelled terminal outcome");

    let mut foreign_trace = serde_json::to_value(kernel.events()).expect("serialize trace");
    let foreign_root = CancellationTree::new().root_id().to_string();
    foreign_trace[1]["kind"]["receipt"]["root"] = serde_json::json!(foreign_root);
    let foreign_trace: Vec<RuntimeEvent> =
        serde_json::from_value(foreign_trace).expect("typed foreign-root trace");
    assert!(matches!(
        RunSnapshot::replay(&foreign_trace),
        Err(ReplayError::ForeignCancellationReceipt)
    ));
}

#[tokio::test]
async fn trace_budget_and_explicit_workspace_binding_fail_closed() {
    let relative = WorkspaceBinding::new(
        std::path::PathBuf::from("."),
        nonzero_workspace(1),
        ContentDigest::sha256(b"relative"),
    );
    assert!(relative.is_err(), "ambient CWD must not be a workspace");

    let fixture = RunFixture::new(1);
    let sink = Arc::new(ReferenceTraceSink::default());
    assert!(matches!(
        RuntimeKernel::start(fixture.context(sink)).await,
        Err(KernelError::Replay(ReplayError::TraceBudgetExceeded {
            limit: 1,
            ..
        }))
    ));
}

#[tokio::test]
async fn separate_run_objects_have_independent_state_and_cancellation() {
    let first = RunFixture::new(1_000_000);
    let mut second = RunFixture::new(1_000_000);
    second.descriptor.run_id = RunId::from_uuid(Uuid::from_u128(0xb0));
    second.descriptor.session_id = SessionId::from_raw(Uuid::from_u128(0xb1).to_string())
        .expect("second fixture session UUID");
    let first_sink = Arc::new(ReferenceTraceSink::default());
    let second_sink = Arc::new(ReferenceTraceSink::default());
    let first_actor = first.actor();
    let second_actor = second.actor();
    let mut first_kernel = RuntimeKernel::start(first.context(first_sink))
        .await
        .expect("first run");
    let mut second_kernel = RuntimeKernel::start(second.context(second_sink))
        .await
        .expect("second run");

    first_kernel
        .cancel(&first_actor, &first.tree.root(), CancellationReason::User)
        .await
        .expect("cancel first run");
    second_kernel
        .succeed(&second_actor)
        .await
        .expect("second run remains independent");
    assert!(!second.tree.root().is_cancelled());
    assert_eq!(first_kernel.snapshot().next_sequence(), 2);
    assert_eq!(second_kernel.snapshot().next_sequence(), 2);
}
