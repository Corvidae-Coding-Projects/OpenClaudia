//! Clone-cheap, shared ownership for [`super::SessionState`].
//!
//! Both interactive frontends have synchronous input/render handlers, while
//! provider work is asynchronous. Exposing a lock guard from this type would
//! let a caller accidentally retain it across an `.await` and deadlock the
//! current-thread runtime. The API therefore uses closures: the guard is
//! acquired, the closure runs, and the guard is dropped before control returns
//! to the caller. References into the state cannot escape the closure.

use std::sync::{Arc, RwLock};

use tokio::sync::broadcast;

use super::categories::{EffortLevel, SessionId};
use super::SessionState;
use crate::modes::BehaviorMode;

const EVENT_CHANNEL_CAPACITY: usize = 64;

/// Granular state changes emitted after a successful mutation.
#[derive(Debug, Clone)]
pub enum StateEvent {
    SessionSwitched {
        from: SessionId,
        to: SessionId,
        from_messages: usize,
    },
    MessageAppended {
        role: String,
    },
    ModeChanged {
        new: BehaviorMode,
    },
    EffortChanged {
        new: EffortLevel,
    },
    PermissionsMutated,
    Cleared,
}

/// A broadcast receiver that applies the store's standard lag policy.
///
/// State notifications are best-effort: the canonical snapshot remains the
/// source of truth. A slow subscriber logs skipped notifications and resumes
/// at the oldest event still in the bounded channel instead of terminating.
pub struct StateSubscription {
    receiver: broadcast::Receiver<StateEvent>,
    lagged: bool,
}

impl StateSubscription {
    /// Receive the next available event, continuing after channel lag.
    pub async fn recv(&mut self) -> Option<StateEvent> {
        loop {
            match self.receiver.recv().await {
                Ok(event) => return Some(event),
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    self.note_lag(skipped);
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    /// Receive the next immediately available event, continuing after lag.
    #[must_use]
    pub fn try_recv(&mut self) -> Option<StateEvent> {
        loop {
            match self.receiver.try_recv() {
                Ok(event) => return Some(event),
                Err(broadcast::error::TryRecvError::Lagged(skipped)) => {
                    self.note_lag(skipped);
                }
                Err(
                    broadcast::error::TryRecvError::Empty | broadcast::error::TryRecvError::Closed,
                ) => return None,
            }
        }
    }

    /// Report whether one or more events were skipped since the last call.
    ///
    /// Snapshot-based consumers can use this to force a full reconciliation.
    pub fn take_lagged(&mut self) -> bool {
        std::mem::take(&mut self.lagged)
    }

    fn note_lag(&mut self, skipped: u64) {
        self.lagged = true;
        tracing::warn!(
            skipped,
            "state event subscriber lagged; reconciling from snapshot"
        );
    }
}

/// Shared session state plus a best-effort change notification channel.
#[derive(Clone)]
pub struct StateStore {
    inner: Arc<RwLock<SessionState>>,
    events: broadcast::Sender<StateEvent>,
}

impl StateStore {
    #[must_use]
    pub fn new(state: SessionState) -> Self {
        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            inner: Arc::new(RwLock::new(state)),
            events,
        }
    }

    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<StateEvent> {
        self.events.subscribe()
    }

    /// Subscribe with consistent lag logging and recovery behavior.
    #[must_use]
    pub fn subscribe_log_lag(&self) -> StateSubscription {
        StateSubscription {
            receiver: self.subscribe(),
            lagged: false,
        }
    }

    /// Clone a coherent point-in-time view of the state.
    #[must_use]
    pub fn snapshot(&self) -> SessionState {
        self.inspect(Clone::clone)
    }

    /// Inspect state without allowing the read guard to escape.
    pub fn inspect<R>(&self, inspect: impl FnOnce(&SessionState) -> R) -> R {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inspect(&guard)
    }

    /// Mutate state and queue zero or more events atomically.
    ///
    /// Events are emitted only after the write guard has been released. If the
    /// mutation panics, unwinding skips the emission entirely, so subscribers
    /// never act on a partially applied update.
    pub fn update<R>(
        &self,
        update: impl FnOnce(&mut SessionState, &mut Vec<StateEvent>) -> R,
    ) -> R {
        let (result, pending) = {
            let mut guard = self
                .inner
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut pending = Vec::new();
            let result = update(&mut guard, &mut pending);
            drop(guard);
            (result, pending)
        };

        for event in pending {
            let _ = self.events.send(event);
        }
        result
    }

    /// Replace the complete state snapshot.
    ///
    /// A session-switch event is emitted only when the identifier changed.
    pub fn replace(&self, replacement: SessionState) {
        self.update(|state, events| {
            let from = state.identity.session_id.clone();
            let from_messages = state.conversation.messages.len();
            let to = replacement.identity.session_id.clone();
            *state = replacement;
            if from != to {
                events.push(StateEvent::SessionSwitched {
                    from,
                    to,
                    from_messages,
                });
            }
        });
    }
}

impl Default for StateStore {
    fn default() -> Self {
        Self::new(SessionState::default())
    }
}

impl std::fmt::Debug for StateStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateStore")
            .field("state", &self.snapshot())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn update_flushes_events_after_mutation() {
        let store = StateStore::default();
        let mut rx = store.subscribe();

        store.update(|state, events| {
            state
                .conversation
                .messages
                .push(json!({"role": "user", "content": "hi"}));
            events.push(StateEvent::MessageAppended {
                role: "user".into(),
            });
        });

        let event = rx.recv().await.expect("event flushed");
        assert!(matches!(event, StateEvent::MessageAppended { role } if role == "user"));
    }

    #[tokio::test]
    async fn multiple_events_emit_in_order() {
        let store = StateStore::default();
        let mut rx = store.subscribe();

        store.update(|_, events| {
            events.push(StateEvent::EffortChanged {
                new: EffortLevel::High,
            });
            events.push(StateEvent::PermissionsMutated);
        });

        assert!(matches!(
            rx.recv().await.unwrap(),
            StateEvent::EffortChanged { .. }
        ));
        assert!(matches!(
            rx.recv().await.unwrap(),
            StateEvent::PermissionsMutated
        ));
    }

    #[test]
    fn snapshot_is_independent() {
        let store = StateStore::default();
        store.update(|state, _| state.budgets.effort_level = EffortLevel::High);

        let snapshot = store.snapshot();
        store.update(|state, _| state.budgets.effort_level = EffortLevel::Low);

        assert_eq!(snapshot.budgets.effort_level, EffortLevel::High);
    }

    #[test]
    fn clones_share_state() {
        let first = StateStore::default();
        let second = first.clone();

        first.update(|state, _| {
            state.conversation.messages.push(json!({"role": "user"}));
        });

        assert_eq!(second.inspect(|state| state.conversation.messages.len()), 1);
    }

    #[tokio::test]
    async fn closure_guard_is_released_before_await() {
        let store = StateStore::default();
        let other = store.clone();

        let session_id = store.inspect(|state| state.identity.session_id.clone());
        tokio::task::yield_now().await;
        other.update(|state, _| state.identity.parent_session_id = Some(session_id));

        assert!(store.inspect(|state| state.identity.parent_session_id.is_some()));
    }

    #[tokio::test]
    async fn replace_emits_session_switch_only_for_new_id() {
        let store = StateStore::default();
        let mut rx = store.subscribe();

        store.replace(store.snapshot());
        assert!(rx.try_recv().is_err());

        store.replace(SessionState::default());
        assert!(matches!(
            rx.recv().await.unwrap(),
            StateEvent::SessionSwitched {
                from_messages: 0,
                ..
            }
        ));
    }

    #[test]
    fn lag_logging_subscription_resumes_and_requests_reconciliation() {
        let store = StateStore::default();
        let mut subscription = store.subscribe_log_lag();

        for index in 0..=EVENT_CHANNEL_CAPACITY {
            store.update(|_, events| {
                events.push(StateEvent::MessageAppended {
                    role: format!("role-{index}"),
                });
            });
        }

        assert!(matches!(
            subscription.try_recv(),
            Some(StateEvent::MessageAppended { .. })
        ));
        assert!(subscription.take_lagged());
        assert!(!subscription.take_lagged());
    }

    #[test]
    fn poisoned_lock_recovers_for_followup_access() {
        let store = StateStore::default();
        let poisoned = store.clone();
        let _ = std::thread::spawn(move || {
            poisoned.update(|state, _| {
                state.budgets.effort_level = EffortLevel::High;
                panic!("poison test");
            });
        })
        .join();

        assert_eq!(
            store.inspect(|state| state.budgets.effort_level),
            EffortLevel::High
        );
    }
}
