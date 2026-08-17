//! Trace sink contract for canonical runtime events.

use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use thiserror::Error;

use super::event::RuntimeEvent;

/// A sink must acknowledge an event before the kernel advances its state.
#[async_trait]
pub trait TraceSink: Send + Sync {
    /// Append one event durably enough for the sink's declared contract.
    ///
    /// # Errors
    ///
    /// Returns an error when the event was not accepted. The kernel will not
    /// apply the corresponding state transition.
    async fn append(&self, event: &RuntimeEvent) -> Result<(), TraceSinkError>;
}

/// Trace append failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("trace sink rejected runtime event: {detail}")]
pub struct TraceSinkError {
    detail: String,
}

impl TraceSinkError {
    /// Construct a sink error with inert diagnostic detail.
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }

    /// Borrow the diagnostic detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// In-memory sink for deterministic adapters and acceptance tests.
///
/// Production persistence remains owned by S-031/S-037. This sink is
/// intentionally explicit rather than a silent no-op trace implementation.
#[derive(Debug, Default)]
pub struct ReferenceTraceSink {
    events: Mutex<Vec<RuntimeEvent>>,
}

impl ReferenceTraceSink {
    /// Return a stable snapshot of every accepted event.
    #[must_use]
    pub fn events(&self) -> Vec<RuntimeEvent> {
        lock_events(&self.events).clone()
    }
}

#[async_trait]
impl TraceSink for ReferenceTraceSink {
    async fn append(&self, event: &RuntimeEvent) -> Result<(), TraceSinkError> {
        lock_events(&self.events).push(event.clone());
        Ok(())
    }
}

fn lock_events(events: &Mutex<Vec<RuntimeEvent>>) -> MutexGuard<'_, Vec<RuntimeEvent>> {
    events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
