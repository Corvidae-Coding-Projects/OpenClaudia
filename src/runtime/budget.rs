//! Atomic, hierarchical resource budgets for canonical runs.
//!
//! The serializable [`RunBudget`](super::RunBudget) describes immutable limits.
//! This module owns the live authority that atomically reserves those limits
//! across a run and every derived child. Reservations are conservative: a call
//! that never reports usage keeps its preflight charge, while known usage
//! releases only capacity proven unused.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    BudgetGeneration, BudgetId, BudgetLimits, CancellationHandle, CancellationReason, RunBudget,
};

/// Reservable cumulative dimensions in a run budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDimension {
    InputTokens,
    OutputTokens,
    TotalTokens,
    Turns,
    ProviderCalls,
    ToolCalls,
    ElapsedMillis,
    Retries,
    ConcurrentCalls,
    ChildRuns,
    CostMicrousd,
    TraceBytes,
}

impl fmt::Display for BudgetDimension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InputTokens => "input_tokens",
            Self::OutputTokens => "output_tokens",
            Self::TotalTokens => "total_tokens",
            Self::Turns => "turns",
            Self::ProviderCalls => "provider_calls",
            Self::ToolCalls => "tool_calls",
            Self::ElapsedMillis => "elapsed_millis",
            Self::Retries => "retries",
            Self::ConcurrentCalls => "concurrent_calls",
            Self::ChildRuns => "child_runs",
            Self::CostMicrousd => "cost_microusd",
            Self::TraceBytes => "trace_bytes",
        })
    }
}

/// Durable spend plus a temporary concurrency lease requested by one call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetAmounts {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub turns: u64,
    pub provider_calls: u64,
    pub tool_calls: u64,
    pub retries: u64,
    pub concurrent_calls: u64,
    pub child_runs: u64,
    pub cost_microusd: u64,
}

impl BudgetAmounts {
    const DURABLE_DIMENSIONS: [BudgetDimension; 8] = [
        BudgetDimension::InputTokens,
        BudgetDimension::OutputTokens,
        BudgetDimension::Turns,
        BudgetDimension::ProviderCalls,
        BudgetDimension::ToolCalls,
        BudgetDimension::Retries,
        BudgetDimension::ChildRuns,
        BudgetDimension::CostMicrousd,
    ];

    const fn get(self, dimension: BudgetDimension) -> u64 {
        match dimension {
            BudgetDimension::InputTokens => self.input_tokens,
            BudgetDimension::OutputTokens => self.output_tokens,
            BudgetDimension::TotalTokens => self.input_tokens.saturating_add(self.output_tokens),
            BudgetDimension::Turns => self.turns,
            BudgetDimension::ProviderCalls => self.provider_calls,
            BudgetDimension::ToolCalls => self.tool_calls,
            BudgetDimension::Retries => self.retries,
            BudgetDimension::ConcurrentCalls => self.concurrent_calls,
            BudgetDimension::ChildRuns => self.child_runs,
            BudgetDimension::CostMicrousd => self.cost_microusd,
            BudgetDimension::ElapsedMillis | BudgetDimension::TraceBytes => 0,
        }
    }

    const fn set(&mut self, dimension: BudgetDimension, value: u64) {
        match dimension {
            BudgetDimension::InputTokens => self.input_tokens = value,
            BudgetDimension::OutputTokens => self.output_tokens = value,
            BudgetDimension::Turns => self.turns = value,
            BudgetDimension::ProviderCalls => self.provider_calls = value,
            BudgetDimension::ToolCalls => self.tool_calls = value,
            BudgetDimension::Retries => self.retries = value,
            BudgetDimension::ConcurrentCalls => self.concurrent_calls = value,
            BudgetDimension::ChildRuns => self.child_runs = value,
            BudgetDimension::CostMicrousd => self.cost_microusd = value,
            BudgetDimension::TotalTokens
            | BudgetDimension::ElapsedMillis
            | BudgetDimension::TraceBytes => {}
        }
    }
}

/// Whether a settled charge came from reported usage or a conservative bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetUsageCertainty {
    Known,
    UnknownReserved,
}

/// Auditable outcome of one budget reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetReceipt {
    pub budget_id: BudgetId,
    pub generation: BudgetGeneration,
    pub reserved: BudgetAmounts,
    pub charged: BudgetAmounts,
    pub certainty: BudgetUsageCertainty,
}

/// Current live usage for one budget scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetSnapshot {
    pub budget_id: BudgetId,
    pub generation: BudgetGeneration,
    pub limits: BudgetLimits,
    pub used: BudgetAmounts,
    pub elapsed_millis: u64,
    pub remaining_elapsed_millis: u64,
}

/// A reservation or accounting operation was not admissible.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BudgetError {
    #[error("budget {budget_id} is cancelled")]
    Cancelled { budget_id: BudgetId },
    #[error(
        "budget {budget_id} exhausted {dimension}: limit={limit}, used={used}, requested={requested}"
    )]
    Exhausted {
        budget_id: BudgetId,
        dimension: BudgetDimension,
        limit: u64,
        used: u64,
        requested: u64,
    },
    #[error("budget accounting overflow for {dimension}")]
    AccountingOverflow { dimension: BudgetDimension },
    #[error(
        "child budget {child} exceeds parent {parent} for {dimension}: child={child_limit}, parent={parent_limit}"
    )]
    ChildLimitExceedsParent {
        child: BudgetId,
        parent: BudgetId,
        dimension: BudgetDimension,
        child_limit: u64,
        parent_limit: u64,
    },
    #[error("budget {0} is not registered in its authority tree")]
    UnknownBudget(BudgetId),
    #[error("budget authority state is unavailable after a poisoned lock")]
    StateUnavailable,
}

#[derive(Debug)]
struct BudgetNode {
    budget: RunBudget,
    parent: Option<BudgetId>,
    used: BudgetAmounts,
    started_at: Instant,
    cancellation: CancellationHandle,
}

#[derive(Debug)]
struct BudgetTreeState {
    nodes: BTreeMap<BudgetId, BudgetNode>,
    corrupted: bool,
}

#[derive(Debug)]
struct BudgetTree {
    state: Mutex<BudgetTreeState>,
}

/// Cloneable live authority for one node in a hierarchical run budget.
#[derive(Debug, Clone)]
pub struct RunBudgetAuthority {
    tree: Arc<BudgetTree>,
    budget_id: BudgetId,
    cancellation: CancellationHandle,
}

impl RunBudgetAuthority {
    /// Create a root authority from an immutable descriptor budget.
    #[must_use]
    pub fn root(budget: RunBudget, cancellation: CancellationHandle) -> Self {
        let budget_id = budget.id;
        let node = BudgetNode {
            budget,
            parent: None,
            used: BudgetAmounts::default(),
            started_at: Instant::now(),
            cancellation: cancellation.clone(),
        };
        Self {
            tree: Arc::new(BudgetTree {
                state: Mutex::new(BudgetTreeState {
                    nodes: BTreeMap::from([(budget_id, node)]),
                    corrupted: false,
                }),
            }),
            budget_id,
            cancellation,
        }
    }

    /// Register a child scope that shares every ancestor hard cap.
    ///
    /// Child admission atomically consumes one `child_runs` unit from every
    /// ancestor. The child's own limits may narrow, but never widen, its direct
    /// parent's immutable policy.
    ///
    /// # Errors
    ///
    /// Returns an error when a limit widens, the parent is exhausted or
    /// cancelled, accounting overflows, or live state is unavailable.
    pub fn child(
        &self,
        budget: RunBudget,
        cancellation: CancellationHandle,
    ) -> Result<Self, BudgetError> {
        self.ensure_live()?;
        let child_id = budget.id;
        let mut state = self.lock_state()?;
        let parent = state
            .nodes
            .get(&self.budget_id)
            .ok_or(BudgetError::UnknownBudget(self.budget_id))?;
        validate_child_limits(
            child_id,
            &budget.limits,
            self.budget_id,
            &parent.budget.limits,
        )?;
        let ancestors = ancestor_ids(&state, self.budget_id)?;
        check_elapsed(&state, &ancestors)?;
        check_charge(
            &state,
            &ancestors,
            BudgetAmounts {
                child_runs: 1,
                ..BudgetAmounts::default()
            },
        )?;
        apply_charge(
            &mut state,
            &ancestors,
            BudgetAmounts {
                child_runs: 1,
                ..BudgetAmounts::default()
            },
        )?;
        state.nodes.insert(
            child_id,
            BudgetNode {
                budget,
                parent: Some(self.budget_id),
                used: BudgetAmounts::default(),
                started_at: Instant::now(),
                cancellation: cancellation.clone(),
            },
        );
        drop(state);
        Ok(Self {
            tree: Arc::clone(&self.tree),
            budget_id: child_id,
            cancellation,
        })
    }

    /// Atomically reserve spend against this scope and every ancestor.
    ///
    /// # Errors
    ///
    /// Returns a typed error without charging any node when any hard cap would
    /// be exceeded. Exhaustion cancels the affected budget subtree.
    pub fn reserve(&self, amounts: BudgetAmounts) -> Result<BudgetReservation, BudgetError> {
        self.ensure_live()?;
        let result = (|| {
            let mut state = self.lock_state()?;
            let ancestors = ancestor_ids(&state, self.budget_id)?;
            check_elapsed(&state, &ancestors)?;
            check_charge(&state, &ancestors, amounts)?;
            apply_charge(&mut state, &ancestors, amounts)?;
            drop(state);
            Ok(BudgetReservation {
                authority: self.clone(),
                reserved: amounts,
                settled: false,
            })
        })();
        if let Err(error) = &result {
            self.cancel_for_error(error);
        }
        result
    }

    /// Return the current scope snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the node is missing or state is unavailable.
    pub fn snapshot(&self) -> Result<BudgetSnapshot, BudgetError> {
        let state = self.lock_state()?;
        let node = state
            .nodes
            .get(&self.budget_id)
            .ok_or(BudgetError::UnknownBudget(self.budget_id))?;
        let elapsed_millis = elapsed_millis(node.started_at);
        let snapshot = BudgetSnapshot {
            budget_id: node.budget.id,
            generation: node.budget.generation,
            limits: node.budget.limits.clone(),
            used: node.used,
            elapsed_millis,
            remaining_elapsed_millis: node
                .budget
                .limits
                .elapsed_millis
                .saturating_sub(elapsed_millis),
        };
        drop(state);
        Ok(snapshot)
    }

    /// Smallest remaining wall-clock allowance across this scope's ancestors.
    ///
    /// # Errors
    ///
    /// Returns an error when the deadline has expired or state is unavailable.
    pub fn remaining_time(&self) -> Result<Duration, BudgetError> {
        self.ensure_live()?;
        let state = self.lock_state()?;
        let ancestors = ancestor_ids(&state, self.budget_id)?;
        let mut remaining = u64::MAX;
        for id in ancestors {
            let node = state.nodes.get(&id).ok_or(BudgetError::UnknownBudget(id))?;
            let elapsed = elapsed_millis(node.started_at);
            if elapsed >= node.budget.limits.elapsed_millis {
                let error = BudgetError::Exhausted {
                    budget_id: id,
                    dimension: BudgetDimension::ElapsedMillis,
                    limit: node.budget.limits.elapsed_millis,
                    used: elapsed,
                    requested: 1,
                };
                drop(state);
                self.cancel_for_error(&error);
                return Err(error);
            }
            remaining = remaining.min(node.budget.limits.elapsed_millis - elapsed);
        }
        Ok(Duration::from_millis(remaining))
    }

    /// Smallest remaining allowance for a dimension across this scope and all
    /// ancestors.
    ///
    /// # Errors
    ///
    /// Returns an error when the authority is cancelled, expired, missing, or
    /// unavailable.
    pub fn remaining(&self, dimension: BudgetDimension) -> Result<u64, BudgetError> {
        self.ensure_live()?;
        let state = self.lock_state()?;
        let ancestors = ancestor_ids(&state, self.budget_id)?;
        check_elapsed(&state, &ancestors)?;
        let mut remaining = u64::MAX;
        for id in ancestors {
            let node = state.nodes.get(&id).ok_or(BudgetError::UnknownBudget(id))?;
            let used = match dimension {
                BudgetDimension::TotalTokens => node
                    .used
                    .input_tokens
                    .checked_add(node.used.output_tokens)
                    .ok_or(BudgetError::AccountingOverflow { dimension })?,
                BudgetDimension::ElapsedMillis => elapsed_millis(node.started_at),
                BudgetDimension::TraceBytes => 0,
                _ => node.used.get(dimension),
            };
            remaining =
                remaining.min(limit_for(&node.budget.limits, dimension).saturating_sub(used));
        }
        drop(state);
        Ok(remaining)
    }

    /// Immutable identity of this budget scope.
    #[must_use]
    pub const fn id(&self) -> BudgetId {
        self.budget_id
    }

    fn ensure_live(&self) -> Result<(), BudgetError> {
        if self.cancellation.is_cancelled() {
            Err(BudgetError::Cancelled {
                budget_id: self.budget_id,
            })
        } else {
            Ok(())
        }
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, BudgetTreeState>, BudgetError> {
        match self.tree.state.lock() {
            Ok(state) if !state.corrupted => Ok(state),
            Ok(_) => Err(BudgetError::StateUnavailable),
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.corrupted = true;
                drop(state);
                let _receipt = self
                    .cancellation
                    .cancel(CancellationReason::RuntimeFailure {
                        detail: "budget authority lock poisoned".to_string(),
                    });
                Err(BudgetError::StateUnavailable)
            }
        }
    }

    fn cancel_for_error(&self, error: &BudgetError) {
        if !matches!(
            error,
            BudgetError::Exhausted { .. }
                | BudgetError::AccountingOverflow { .. }
                | BudgetError::StateUnavailable
        ) {
            return;
        }
        let failing_id = match error {
            BudgetError::Exhausted { budget_id, .. } => *budget_id,
            BudgetError::AccountingOverflow { .. } | BudgetError::StateUnavailable => {
                self.budget_id
            }
            _ => return,
        };
        let handles = {
            let state = match self.tree.state.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
            descendant_cancellations(&state, failing_id)
        };
        for handle in handles {
            let _receipt = handle.cancel(CancellationReason::BudgetExhausted);
        }
    }

    fn settle(
        &self,
        reserved: BudgetAmounts,
        actual: Option<BudgetAmounts>,
    ) -> Result<BudgetReceipt, BudgetError> {
        let certainty = if actual.is_some() {
            BudgetUsageCertainty::Known
        } else {
            BudgetUsageCertainty::UnknownReserved
        };
        let charged = actual.unwrap_or(reserved);
        let result = (|| {
            let mut state = self.lock_state()?;
            let ancestors = ancestor_ids(&state, self.budget_id)?;
            if actual.is_some() {
                check_reconciliation(&state, &ancestors, reserved, charged)?;
                apply_reconciliation(&mut state, &ancestors, reserved, charged)?;
            }
            release_concurrency(&mut state, &ancestors, reserved.concurrent_calls);
            let node = state
                .nodes
                .get(&self.budget_id)
                .ok_or(BudgetError::UnknownBudget(self.budget_id))?;
            let generation = node.budget.generation;
            drop(state);
            Ok(BudgetReceipt {
                budget_id: self.budget_id,
                generation,
                reserved,
                charged,
                certainty,
            })
        })();
        if let Err(error) = &result {
            self.release_concurrency_after_error(reserved.concurrent_calls);
            self.cancel_for_error(error);
        }
        result
    }

    fn release_concurrency_after_error(&self, amount: u64) {
        if amount == 0 {
            return;
        }
        let mut state = match self.tree.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Ok(ancestors) = ancestor_ids(&state, self.budget_id) {
            release_concurrency(&mut state, &ancestors, amount);
        }
    }
}

/// RAII reservation. Dropping an unsettled reservation retains its durable
/// charge as unknown usage and releases only the concurrency lease.
#[derive(Debug)]
pub struct BudgetReservation {
    authority: RunBudgetAuthority,
    reserved: BudgetAmounts,
    settled: bool,
}

impl BudgetReservation {
    /// Settle with exact reported usage, releasing proven-unused capacity.
    ///
    /// # Errors
    ///
    /// Returns an error and cancels the affected scope when reported usage
    /// itself exceeds a hard cap or accounting cannot be represented.
    pub fn reconcile(mut self, actual: BudgetAmounts) -> Result<BudgetReceipt, BudgetError> {
        let result = self.authority.settle(self.reserved, Some(actual));
        self.settled = true;
        result
    }

    /// Retain the full conservative reservation because usage is unavailable.
    ///
    /// # Errors
    ///
    /// Returns an error only when live accounting state is unavailable.
    pub fn finish_unknown(mut self) -> Result<BudgetReceipt, BudgetError> {
        let result = self.authority.settle(self.reserved, None);
        self.settled = true;
        result
    }

    /// Commit the reserved amount as exact usage.
    ///
    /// # Errors
    ///
    /// Returns an error only when live accounting state is unavailable.
    pub fn commit(self) -> Result<BudgetReceipt, BudgetError> {
        let reserved = self.reserved;
        self.reconcile(BudgetAmounts {
            concurrent_calls: 0,
            ..reserved
        })
    }

    /// Amount admitted before dispatch.
    #[must_use]
    pub const fn reserved(&self) -> BudgetAmounts {
        self.reserved
    }
}

impl Drop for BudgetReservation {
    fn drop(&mut self) {
        if !self.settled {
            let _receipt = self.authority.settle(self.reserved, None);
            self.settled = true;
        }
    }
}

fn ancestor_ids(state: &BudgetTreeState, start: BudgetId) -> Result<Vec<BudgetId>, BudgetError> {
    let mut ids = Vec::new();
    let mut current = Some(start);
    while let Some(id) = current {
        if ids.contains(&id) {
            return Err(BudgetError::StateUnavailable);
        }
        let node = state.nodes.get(&id).ok_or(BudgetError::UnknownBudget(id))?;
        ids.push(id);
        current = node.parent;
    }
    Ok(ids)
}

fn descendant_cancellations(
    state: &BudgetTreeState,
    ancestor: BudgetId,
) -> Vec<CancellationHandle> {
    state
        .nodes
        .iter()
        .filter_map(|(id, node)| {
            ancestor_ids(state, *id)
                .ok()
                .filter(|ids| ids.contains(&ancestor))
                .map(|_| node.cancellation.clone())
        })
        .collect()
}

fn check_elapsed(state: &BudgetTreeState, ancestors: &[BudgetId]) -> Result<(), BudgetError> {
    for id in ancestors {
        let node = state.nodes.get(id).ok_or(BudgetError::UnknownBudget(*id))?;
        let elapsed = elapsed_millis(node.started_at);
        if elapsed >= node.budget.limits.elapsed_millis {
            return Err(BudgetError::Exhausted {
                budget_id: *id,
                dimension: BudgetDimension::ElapsedMillis,
                limit: node.budget.limits.elapsed_millis,
                used: elapsed,
                requested: 1,
            });
        }
    }
    Ok(())
}

fn check_charge(
    state: &BudgetTreeState,
    ancestors: &[BudgetId],
    charge: BudgetAmounts,
) -> Result<(), BudgetError> {
    for id in ancestors {
        let node = state.nodes.get(id).ok_or(BudgetError::UnknownBudget(*id))?;
        for dimension in BudgetAmounts::DURABLE_DIMENSIONS {
            let used = node.used.get(dimension);
            let requested = charge.get(dimension);
            let attempted = used
                .checked_add(requested)
                .ok_or(BudgetError::AccountingOverflow { dimension })?;
            let limit = limit_for(&node.budget.limits, dimension);
            if attempted > limit {
                return Err(BudgetError::Exhausted {
                    budget_id: *id,
                    dimension,
                    limit,
                    used,
                    requested,
                });
            }
        }
        check_total_tokens(node, charge)?;
        let attempted_concurrency = node
            .used
            .concurrent_calls
            .checked_add(charge.concurrent_calls)
            .ok_or(BudgetError::AccountingOverflow {
                dimension: BudgetDimension::ConcurrentCalls,
            })?;
        if attempted_concurrency > node.budget.limits.concurrent_calls {
            return Err(BudgetError::Exhausted {
                budget_id: *id,
                dimension: BudgetDimension::ConcurrentCalls,
                limit: node.budget.limits.concurrent_calls,
                used: node.used.concurrent_calls,
                requested: charge.concurrent_calls,
            });
        }
    }
    Ok(())
}

fn apply_charge(
    state: &mut BudgetTreeState,
    ancestors: &[BudgetId],
    charge: BudgetAmounts,
) -> Result<(), BudgetError> {
    for id in ancestors {
        let node = state
            .nodes
            .get_mut(id)
            .ok_or(BudgetError::UnknownBudget(*id))?;
        for dimension in BudgetAmounts::DURABLE_DIMENSIONS {
            let next = node
                .used
                .get(dimension)
                .checked_add(charge.get(dimension))
                .ok_or(BudgetError::AccountingOverflow { dimension })?;
            node.used.set(dimension, next);
        }
        node.used.concurrent_calls = node
            .used
            .concurrent_calls
            .checked_add(charge.concurrent_calls)
            .ok_or(BudgetError::AccountingOverflow {
                dimension: BudgetDimension::ConcurrentCalls,
            })?;
    }
    Ok(())
}

fn check_reconciliation(
    state: &BudgetTreeState,
    ancestors: &[BudgetId],
    reserved: BudgetAmounts,
    actual: BudgetAmounts,
) -> Result<(), BudgetError> {
    for id in ancestors {
        let node = state.nodes.get(id).ok_or(BudgetError::UnknownBudget(*id))?;
        for dimension in BudgetAmounts::DURABLE_DIMENSIONS {
            let without_reservation = node
                .used
                .get(dimension)
                .checked_sub(reserved.get(dimension))
                .ok_or(BudgetError::StateUnavailable)?;
            let attempted = without_reservation
                .checked_add(actual.get(dimension))
                .ok_or(BudgetError::AccountingOverflow { dimension })?;
            let limit = limit_for(&node.budget.limits, dimension);
            if attempted > limit {
                return Err(BudgetError::Exhausted {
                    budget_id: *id,
                    dimension,
                    limit,
                    used: without_reservation,
                    requested: actual.get(dimension),
                });
            }
        }
        check_reconciled_total_tokens(node, reserved, actual)?;
    }
    Ok(())
}

fn apply_reconciliation(
    state: &mut BudgetTreeState,
    ancestors: &[BudgetId],
    reserved: BudgetAmounts,
    actual: BudgetAmounts,
) -> Result<(), BudgetError> {
    for id in ancestors {
        let node = state
            .nodes
            .get_mut(id)
            .ok_or(BudgetError::UnknownBudget(*id))?;
        for dimension in BudgetAmounts::DURABLE_DIMENSIONS {
            let next = node
                .used
                .get(dimension)
                .checked_sub(reserved.get(dimension))
                .and_then(|value| value.checked_add(actual.get(dimension)))
                .ok_or(BudgetError::AccountingOverflow { dimension })?;
            node.used.set(dimension, next);
        }
    }
    Ok(())
}

fn release_concurrency(state: &mut BudgetTreeState, ancestors: &[BudgetId], amount: u64) {
    for id in ancestors {
        if let Some(node) = state.nodes.get_mut(id) {
            node.used.concurrent_calls = node.used.concurrent_calls.saturating_sub(amount);
        }
    }
}

fn validate_child_limits(
    child: BudgetId,
    child_limits: &BudgetLimits,
    parent: BudgetId,
    parent_limits: &BudgetLimits,
) -> Result<(), BudgetError> {
    for dimension in [
        BudgetDimension::InputTokens,
        BudgetDimension::OutputTokens,
        BudgetDimension::TotalTokens,
        BudgetDimension::Turns,
        BudgetDimension::ProviderCalls,
        BudgetDimension::ToolCalls,
        BudgetDimension::ElapsedMillis,
        BudgetDimension::Retries,
        BudgetDimension::ConcurrentCalls,
        BudgetDimension::ChildRuns,
        BudgetDimension::CostMicrousd,
        BudgetDimension::TraceBytes,
    ] {
        let child_limit = limit_for(child_limits, dimension);
        let parent_limit = limit_for(parent_limits, dimension);
        if child_limit > parent_limit {
            return Err(BudgetError::ChildLimitExceedsParent {
                child,
                parent,
                dimension,
                child_limit,
                parent_limit,
            });
        }
    }
    Ok(())
}

const fn limit_for(limits: &BudgetLimits, dimension: BudgetDimension) -> u64 {
    match dimension {
        BudgetDimension::InputTokens => limits.input_tokens,
        BudgetDimension::OutputTokens => limits.output_tokens,
        BudgetDimension::TotalTokens => limits.total_tokens,
        BudgetDimension::Turns => limits.turns,
        BudgetDimension::ProviderCalls => limits.provider_calls,
        BudgetDimension::ToolCalls => limits.tool_calls,
        BudgetDimension::ElapsedMillis => limits.elapsed_millis,
        BudgetDimension::Retries => limits.retries,
        BudgetDimension::ConcurrentCalls => limits.concurrent_calls,
        BudgetDimension::ChildRuns => limits.child_runs,
        BudgetDimension::CostMicrousd => limits.cost_microusd,
        BudgetDimension::TraceBytes => limits.trace_bytes,
    }
}

fn check_total_tokens(node: &BudgetNode, charge: BudgetAmounts) -> Result<(), BudgetError> {
    let used = node
        .used
        .input_tokens
        .checked_add(node.used.output_tokens)
        .ok_or(BudgetError::AccountingOverflow {
            dimension: BudgetDimension::TotalTokens,
        })?;
    let requested = charge
        .input_tokens
        .checked_add(charge.output_tokens)
        .ok_or(BudgetError::AccountingOverflow {
            dimension: BudgetDimension::TotalTokens,
        })?;
    let attempted = used
        .checked_add(requested)
        .ok_or(BudgetError::AccountingOverflow {
            dimension: BudgetDimension::TotalTokens,
        })?;
    if attempted > node.budget.limits.total_tokens {
        return Err(BudgetError::Exhausted {
            budget_id: node.budget.id,
            dimension: BudgetDimension::TotalTokens,
            limit: node.budget.limits.total_tokens,
            used,
            requested,
        });
    }
    Ok(())
}

fn check_reconciled_total_tokens(
    node: &BudgetNode,
    reserved: BudgetAmounts,
    actual: BudgetAmounts,
) -> Result<(), BudgetError> {
    let used_total = node
        .used
        .input_tokens
        .checked_add(node.used.output_tokens)
        .ok_or(BudgetError::AccountingOverflow {
            dimension: BudgetDimension::TotalTokens,
        })?;
    let reserved_total = reserved
        .input_tokens
        .checked_add(reserved.output_tokens)
        .ok_or(BudgetError::AccountingOverflow {
            dimension: BudgetDimension::TotalTokens,
        })?;
    let actual_total = actual
        .input_tokens
        .checked_add(actual.output_tokens)
        .ok_or(BudgetError::AccountingOverflow {
            dimension: BudgetDimension::TotalTokens,
        })?;
    let without_reservation = used_total
        .checked_sub(reserved_total)
        .ok_or(BudgetError::StateUnavailable)?;
    let attempted =
        without_reservation
            .checked_add(actual_total)
            .ok_or(BudgetError::AccountingOverflow {
                dimension: BudgetDimension::TotalTokens,
            })?;
    if attempted > node.budget.limits.total_tokens {
        return Err(BudgetError::Exhausted {
            budget_id: node.budget.id,
            dimension: BudgetDimension::TotalTokens,
            limit: node.budget.limits.total_tokens,
            used: without_reservation,
            requested: actual_total,
        });
    }
    Ok(())
}

fn elapsed_millis(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{BudgetGeneration, CancellationTree};

    fn limits(cap: u64) -> BudgetLimits {
        BudgetLimits {
            input_tokens: cap,
            output_tokens: cap,
            total_tokens: cap,
            turns: cap,
            provider_calls: cap,
            tool_calls: cap,
            elapsed_millis: 60_000,
            retries: cap,
            concurrent_calls: cap,
            child_runs: cap,
            cost_microusd: cap,
            trace_bytes: cap.max(1),
        }
    }

    fn authority(cap: u64) -> RunBudgetAuthority {
        let cancellation = CancellationTree::new();
        RunBudgetAuthority::root(
            RunBudget {
                id: BudgetId::new(),
                generation: BudgetGeneration::new(1).expect("non-zero"),
                limits: limits(cap),
            },
            cancellation.root(),
        )
    }

    #[test]
    fn concurrent_reservations_cannot_oversubscribe() {
        let budget = authority(1);
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let admitted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut threads = Vec::new();
        for _ in 0..16 {
            let budget = budget.clone();
            let barrier = Arc::clone(&barrier);
            let admitted = Arc::clone(&admitted);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                if let Ok(reservation) = budget.reserve(BudgetAmounts {
                    turns: 1,
                    ..BudgetAmounts::default()
                }) {
                    admitted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _receipt = reservation.commit().expect("settle");
                }
            }));
        }
        for thread in threads {
            thread.join().expect("worker");
        }
        assert_eq!(admitted.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn unknown_usage_keeps_the_conservative_charge() {
        let budget = authority(100);
        let receipt = budget
            .reserve(BudgetAmounts {
                input_tokens: 40,
                concurrent_calls: 1,
                ..BudgetAmounts::default()
            })
            .expect("reserve")
            .finish_unknown()
            .expect("settle");
        assert_eq!(receipt.certainty, BudgetUsageCertainty::UnknownReserved);
        let snapshot = budget.snapshot().expect("snapshot");
        assert_eq!(snapshot.used.input_tokens, 40);
        assert_eq!(snapshot.used.concurrent_calls, 0);
    }

    #[test]
    fn known_usage_refunds_only_proven_unused_capacity() {
        let budget = authority(100);
        let receipt = budget
            .reserve(BudgetAmounts {
                output_tokens: 80,
                concurrent_calls: 1,
                ..BudgetAmounts::default()
            })
            .expect("reserve")
            .reconcile(BudgetAmounts {
                output_tokens: 30,
                ..BudgetAmounts::default()
            })
            .expect("reconcile");
        assert_eq!(receipt.charged.output_tokens, 30);
        assert_eq!(budget.snapshot().expect("snapshot").used.output_tokens, 30);
    }

    #[test]
    fn child_and_parent_caps_are_both_enforced() {
        let parent = authority(10);
        let child_cancel = CancellationTree::new();
        let child = parent
            .child(
                RunBudget {
                    id: BudgetId::new(),
                    generation: BudgetGeneration::new(2).expect("non-zero"),
                    limits: limits(6),
                },
                child_cancel.root(),
            )
            .expect("child");
        child
            .reserve(BudgetAmounts {
                tool_calls: 6,
                ..BudgetAmounts::default()
            })
            .expect("reserve")
            .commit()
            .expect("commit");
        let error = child
            .reserve(BudgetAmounts {
                tool_calls: 1,
                ..BudgetAmounts::default()
            })
            .expect_err("child cap");
        assert!(matches!(
            error,
            BudgetError::Exhausted {
                dimension: BudgetDimension::ToolCalls,
                ..
            }
        ));
        assert_eq!(parent.snapshot().expect("parent").used.tool_calls, 6);
        assert!(child_cancel.root().is_cancelled());
    }

    #[test]
    fn child_cannot_widen_parent_limits() {
        let parent = authority(10);
        let cancellation = CancellationTree::new();
        let error = parent
            .child(
                RunBudget {
                    id: BudgetId::new(),
                    generation: BudgetGeneration::new(2).expect("non-zero"),
                    limits: limits(11),
                },
                cancellation.root(),
            )
            .expect_err("widening must fail");
        assert!(matches!(error, BudgetError::ChildLimitExceedsParent { .. }));
    }
}
