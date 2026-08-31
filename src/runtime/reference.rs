//! Deterministic reference adapter for kernel acceptance and future frontends.

use super::context::{ContentDigest, StateSnapshot};
use super::event::{CallKind, CallOutcome, StateProposal};
use super::ids::CallId;
use super::kernel::{KernelError, RunContext, RunSnapshot, RuntimeKernel};
use super::RuntimeEvent;

/// Result of one reference provider turn and committed state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceRunResult {
    pub events: Vec<RuntimeEvent>,
    pub snapshot: RunSnapshot,
}

/// Minimal adapter used to prove lifecycle ordering without migrating a
/// production frontend in S-010.
pub struct ReferenceRunAdapter;

impl ReferenceRunAdapter {
    /// Execute one provider call, bind its result digest to a state proposal,
    /// commit that proposal, and emit success.
    ///
    /// # Errors
    ///
    /// Returns the first kernel or trace invariant failure. No later lifecycle
    /// stage is attempted after an error.
    pub async fn run_committed_provider_turn(
        context: RunContext,
        call_id: CallId,
        provider_result: impl AsRef<[u8]>,
        next_state: StateSnapshot,
    ) -> Result<ReferenceRunResult, KernelError> {
        let mut kernel = RuntimeKernel::start(context).await?;
        let actor = kernel.snapshot().descriptor().actor.clone();
        kernel
            .begin_call(&actor, call_id, CallKind::Provider)
            .await?;
        kernel
            .finish_call(
                &actor,
                call_id,
                CallOutcome::Succeeded {
                    result_digest: ContentDigest::sha256(provider_result),
                },
            )
            .await?;
        kernel
            .propose_state(
                &actor,
                StateProposal {
                    base: kernel.snapshot().committed_state().clone(),
                    proposed: next_state.clone(),
                },
            )
            .await?;
        kernel.commit_state(&actor, next_state).await?;
        kernel.succeed(&actor).await?;
        Ok(ReferenceRunResult {
            events: kernel.events().to_vec(),
            snapshot: kernel.snapshot().clone(),
        })
    }
}
