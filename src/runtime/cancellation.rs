//! Hierarchical, run-scoped cancellation without process-global flags.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use super::ids::CancellationId;

/// Typed reason for stopping a run or one of its child operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CancellationReason {
    User,
    Deadline,
    BudgetExhausted,
    FrontendDisconnected,
    ParentTerminated,
    RuntimeFailure { detail: String },
}

/// Immutable evidence that a cancellation node was stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationReceipt {
    pub root: CancellationId,
    pub node: CancellationId,
    pub source: CancellationId,
    pub reason: CancellationReason,
}

#[derive(Debug, Clone, Copy)]
enum CancellationParent {
    Root,
    Node(CancellationId),
}

#[derive(Debug)]
struct CancellationEntry {
    parent: CancellationParent,
    children: BTreeSet<CancellationId>,
    receipt: Option<CancellationReceipt>,
}

#[derive(Debug)]
struct CancellationState {
    entries: BTreeMap<CancellationId, CancellationEntry>,
}

#[derive(Debug)]
struct CancellationInner {
    root: CancellationId,
    state: Mutex<CancellationState>,
    notify: Notify,
}

/// Owner of one cancellation tree. Every run receives a fresh tree.
#[derive(Debug, Clone)]
pub struct CancellationTree {
    inner: Arc<CancellationInner>,
}

impl CancellationTree {
    /// Create a tree with a fresh root identity.
    #[must_use]
    pub fn new() -> Self {
        let root = CancellationId::new();
        let mut entries = BTreeMap::new();
        entries.insert(
            root,
            CancellationEntry {
                parent: CancellationParent::Root,
                children: BTreeSet::new(),
                receipt: None,
            },
        );
        Self {
            inner: Arc::new(CancellationInner {
                root,
                state: Mutex::new(CancellationState { entries }),
                notify: Notify::new(),
            }),
        }
    }

    /// Return a handle to the root cancellation node.
    #[must_use]
    pub fn root(&self) -> CancellationHandle {
        CancellationHandle {
            inner: Arc::clone(&self.inner),
            node: self.inner.root,
        }
    }

    /// Return the root identity used in the serializable run descriptor.
    #[must_use]
    pub fn root_id(&self) -> CancellationId {
        self.inner.root
    }
}

impl Default for CancellationTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Cloneable handle to a node in a cancellation tree.
#[derive(Debug, Clone)]
pub struct CancellationHandle {
    inner: Arc<CancellationInner>,
    node: CancellationId,
}

impl CancellationHandle {
    /// Return this node's identity.
    #[must_use]
    pub const fn id(&self) -> CancellationId {
        self.node
    }

    /// Return the tree's root identity.
    #[must_use]
    pub fn root_id(&self) -> CancellationId {
        self.inner.root
    }

    /// Create a child. Cancelling this child never cancels its parent; a child
    /// created beneath an already cancelled parent starts cancelled.
    #[must_use]
    pub fn child(&self) -> Self {
        let child = CancellationId::new();
        let mut state = lock_state(&self.inner);
        let inherited = state
            .entries
            .get(&self.node)
            .and_then(|entry| entry.receipt.clone());
        state.entries.insert(
            child,
            CancellationEntry {
                parent: CancellationParent::Node(self.node),
                children: BTreeSet::new(),
                receipt: inherited.map(|receipt| CancellationReceipt {
                    root: receipt.root,
                    node: child,
                    source: receipt.source,
                    reason: receipt.reason,
                }),
            },
        );
        if let Some(parent) = state.entries.get_mut(&self.node) {
            parent.children.insert(child);
        }
        drop(state);
        Self {
            inner: Arc::clone(&self.inner),
            node: child,
        }
    }

    /// Cancel this node and every current descendant.
    ///
    /// Repeated requests are idempotent and return the first receipt.
    #[must_use]
    pub fn cancel(&self, reason: CancellationReason) -> CancellationReceipt {
        let mut state = lock_state(&self.inner);
        if let Some(receipt) = state
            .entries
            .get(&self.node)
            .and_then(|entry| entry.receipt.clone())
        {
            return receipt;
        }

        let receipt = CancellationReceipt {
            root: self.inner.root,
            node: self.node,
            source: self.node,
            reason,
        };
        let mut pending = vec![self.node];
        while let Some(node) = pending.pop() {
            if let Some(entry) = state.entries.get_mut(&node) {
                entry.receipt = Some(CancellationReceipt {
                    root: receipt.root,
                    node,
                    source: receipt.source,
                    reason: receipt.reason.clone(),
                });
                pending.extend(entry.children.iter().copied());
            }
        }
        drop(state);
        self.inner.notify.notify_waiters();
        receipt
    }

    /// Return the cancellation receipt when this node or an ancestor stopped.
    #[must_use]
    pub fn receipt(&self) -> Option<CancellationReceipt> {
        lock_state(&self.inner)
            .entries
            .get(&self.node)
            .and_then(|entry| entry.receipt.clone())
    }

    /// Whether this node or an ancestor has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.receipt().is_some()
    }

    /// Wait until this node or an ancestor is cancelled.
    pub async fn cancelled(&self) -> CancellationReceipt {
        loop {
            let notified = self.inner.notify.notified();
            if let Some(receipt) = self.receipt() {
                return receipt;
            }
            notified.await;
        }
    }

    /// Return the parent node when this is not the root.
    #[must_use]
    pub fn parent_id(&self) -> Option<CancellationId> {
        lock_state(&self.inner)
            .entries
            .get(&self.node)
            .and_then(|entry| match entry.parent {
                CancellationParent::Root => None,
                CancellationParent::Node(parent) => Some(parent),
            })
    }

    pub(crate) fn receipt_for(&self, node: CancellationId) -> Option<CancellationReceipt> {
        lock_state(&self.inner)
            .entries
            .get(&node)
            .and_then(|entry| entry.receipt.clone())
    }

    pub(crate) fn tree_receipts(&self) -> Vec<CancellationReceipt> {
        lock_state(&self.inner)
            .entries
            .values()
            .filter_map(|entry| entry.receipt.clone())
            .collect()
    }
}

fn lock_state(inner: &CancellationInner) -> MutexGuard<'_, CancellationState> {
    inner
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
