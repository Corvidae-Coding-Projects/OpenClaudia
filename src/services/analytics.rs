//! Analytics sink — where lifecycle + usage events get recorded.
//!
//! Port of Claude Code's `services/analytics/` layer. OC keeps this
//! minimal: a typed [`AnalyticsEvent`] enum covering the events we
//! actually emit, and two default impls:
//!
//! - [`NoopAnalytics`]: discards every event. Used in tests and
//!   headless invocations where recording would skew results or leak
//!   user data. This is the `ServiceRegistry` default.
//! - [`TracingAnalytics`]: forwards each event as a `tracing::info!`
//!   span. Lets operators turn analytics on via `RUST_LOG` without
//!   hauling in a full telemetry library.
//!
//! Callers invoke via `ServiceRegistry::analytics().record(...)` —
//! the sink lives behind an `Arc<dyn AnalyticsSink>` so a test can
//! substitute a recording impl without changing the call sites.

/// Structured event variants. New fields or new variants land here
/// so the type system forces every sink to handle them — a stringly-
/// typed event bag would silently drop unknown events.
use std::sync::Arc;

use crate::state::{StateEvent, StateStore, StateSubscription};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalyticsEvent {
    /// A new session started. Payload: session id.
    SessionStart { session_id: String },
    /// A session ended. Payload: session id + message count.
    SessionEnd { session_id: String, messages: usize },
    /// A tool ran. Payload: tool name + success bit.
    ToolUsed { tool: String, success: bool },
    /// User-facing prompt submitted. Payload: char length of the
    /// final prompt text (not the text itself — that's PII).
    PromptSubmitted { prompt_chars: usize },
    /// Context was compacted. Payload: trigger + tokens freed.
    ContextCompacted {
        trigger: &'static str,
        tokens_freed: usize,
    },
    /// API request sent to the provider. Payload: provider string +
    /// model name (no secrets; headers are logged elsewhere).
    ApiRequest { provider: String, model: String },
    /// An expected thinking burst happened. Payload: budget hint
    /// used. Mirrors Claude Code's `tengu_thinking` analytics event.
    ThinkingEmitted { budget: u32 },
}

/// Sink trait. Single required method — [`AnalyticsSink::record`].
/// Implementors decide what to do with events. Must be `Send + Sync`
/// so the `Arc<dyn AnalyticsSink>` can cross thread / task boundaries.
pub trait AnalyticsSink: Send + Sync {
    /// Record a single event. Must not panic; misbehaving sinks
    /// shouldn't bring down the caller. Sink impls that can fail
    /// (network IO, etc.) should buffer + log-on-failure internally.
    fn record(&self, event: AnalyticsEvent);
}

/// No-op sink — the `ServiceRegistry` default. Exists so callers can
/// record unconditionally without a `Some(sink)` check.
pub struct NoopAnalytics;

impl AnalyticsSink for NoopAnalytics {
    fn record(&self, _event: AnalyticsEvent) {
        // Intentionally empty — the Claude Code `NoopSink` equivalent.
    }
}

/// Forwards events to the `tracing` subscriber as structured fields.
///
/// Uses a stable target (`openclaudia::analytics`) so operators can filter
/// via `RUST_LOG=openclaudia::analytics=info` without flipping every tracing
/// span on.
pub struct TracingAnalytics;

impl AnalyticsSink for TracingAnalytics {
    fn record(&self, event: AnalyticsEvent) {
        match event {
            AnalyticsEvent::SessionStart { session_id } => {
                tracing::info!(
                    target: "openclaudia::analytics",
                    event = "session_start",
                    session_id = %session_id
                );
            }
            AnalyticsEvent::SessionEnd {
                session_id,
                messages,
            } => {
                tracing::info!(
                    target: "openclaudia::analytics",
                    event = "session_end",
                    session_id = %session_id,
                    messages
                );
            }
            AnalyticsEvent::ToolUsed { tool, success } => {
                tracing::info!(
                    target: "openclaudia::analytics",
                    event = "tool_used",
                    tool = %tool,
                    success
                );
            }
            AnalyticsEvent::PromptSubmitted { prompt_chars } => {
                tracing::info!(
                    target: "openclaudia::analytics",
                    event = "prompt_submitted",
                    prompt_chars
                );
            }
            AnalyticsEvent::ContextCompacted {
                trigger,
                tokens_freed,
            } => {
                tracing::info!(
                    target: "openclaudia::analytics",
                    event = "context_compacted",
                    trigger,
                    tokens_freed
                );
            }
            AnalyticsEvent::ApiRequest { provider, model } => {
                tracing::info!(
                    target: "openclaudia::analytics",
                    event = "api_request",
                    provider = %provider,
                    model = %model
                );
            }
            AnalyticsEvent::ThinkingEmitted { budget } => {
                tracing::info!(
                    target: "openclaudia::analytics",
                    event = "thinking_emitted",
                    budget
                );
            }
        }
    }
}

/// Converts state-store lifecycle notifications into analytics events.
///
/// The subscriber is polled by the owning frontend, keeping analytics sinks
/// off the state mutation path and avoiding a dedicated background task. It
/// records the current session at installation time, session boundaries on
/// every store replacement, and one final end event when finished.
pub struct StateAnalyticsSubscriber {
    state: StateStore,
    subscription: StateSubscription,
    sink: Arc<dyn AnalyticsSink>,
    finished: bool,
}

impl StateAnalyticsSubscriber {
    #[must_use]
    pub fn new(state: StateStore, sink: Arc<dyn AnalyticsSink>) -> Self {
        let subscription = state.subscribe_log_lag();
        let session_id = state.inspect(|snapshot| snapshot.identity.session_id.to_string());
        sink.record(AnalyticsEvent::SessionStart { session_id });
        Self {
            state,
            subscription,
            sink,
            finished: false,
        }
    }

    /// Process all lifecycle events currently queued by the state store.
    pub fn drain_pending(&mut self) {
        while let Some(event) = self.subscription.try_recv() {
            if let StateEvent::SessionSwitched {
                from,
                to,
                from_messages,
            } = event
            {
                self.sink.record(AnalyticsEvent::SessionEnd {
                    session_id: from.to_string(),
                    messages: from_messages,
                });
                self.sink.record(AnalyticsEvent::SessionStart {
                    session_id: to.to_string(),
                });
            }
        }
    }

    /// Record the active session's final message count exactly once.
    pub fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.drain_pending();
        let (session_id, messages) = self.state.inspect(|snapshot| {
            (
                snapshot.identity.session_id.to_string(),
                snapshot.conversation.messages.len(),
            )
        });
        self.sink.record(AnalyticsEvent::SessionEnd {
            session_id,
            messages,
        });
        self.finished = true;
    }
}

impl Drop for StateAnalyticsSubscriber {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Recording {
        events: Mutex<Vec<AnalyticsEvent>>,
    }

    impl AnalyticsSink for Recording {
        fn record(&self, event: AnalyticsEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    #[test]
    fn noop_sink_discards_events() {
        // Compiles if the trait object is Send + Sync (required for
        // Arc<dyn AnalyticsSink>). Record panics aren't a concern —
        // NoopAnalytics has no body.
        let sink: Box<dyn AnalyticsSink> = Box::new(NoopAnalytics);
        sink.record(AnalyticsEvent::SessionStart {
            session_id: "x".to_string(),
        });
    }

    #[test]
    fn tracing_sink_handles_all_variants() {
        // Exhaustive record call per variant: a missing arm in
        // TracingAnalytics::record would fail to compile. Running
        // each event here catches runtime panics (slice OOB,
        // unwrap on untrusted fields) even though most variants are
        // trivial.
        let sink = TracingAnalytics;
        sink.record(AnalyticsEvent::SessionStart {
            session_id: "s".to_string(),
        });
        sink.record(AnalyticsEvent::SessionEnd {
            session_id: "s".to_string(),
            messages: 3,
        });
        sink.record(AnalyticsEvent::ToolUsed {
            tool: "bash".to_string(),
            success: true,
        });
        sink.record(AnalyticsEvent::PromptSubmitted { prompt_chars: 42 });
        sink.record(AnalyticsEvent::ContextCompacted {
            trigger: "auto",
            tokens_freed: 1000,
        });
        sink.record(AnalyticsEvent::ApiRequest {
            provider: "anthropic".to_string(),
            model: "claude-opus-4-6".to_string(),
        });
        sink.record(AnalyticsEvent::ThinkingEmitted { budget: 31_999 });
    }

    #[test]
    fn recording_sink_captures_in_order() {
        let rec = Recording {
            events: Mutex::new(Vec::new()),
        };
        rec.record(AnalyticsEvent::SessionStart {
            session_id: "a".to_string(),
        });
        rec.record(AnalyticsEvent::ToolUsed {
            tool: "read_file".to_string(),
            success: false,
        });
        let events = rec.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        match &events[0] {
            AnalyticsEvent::SessionStart { session_id } => assert_eq!(session_id, "a"),
            other => panic!("expected SessionStart, got {other:?}"),
        }
        match &events[1] {
            AnalyticsEvent::ToolUsed { tool, success } => {
                assert_eq!(tool, "read_file");
                assert!(!success);
            }
            other => panic!("expected ToolUsed, got {other:?}"),
        }
    }

    // ── B4 spec pins (#536 §B4) ──────────────────────────────────────────────

    /// B4: `AnalyticsSink` is `Send + Sync` — the trait bound is required so
    /// the sink can live behind `Arc<dyn AnalyticsSink>` and cross thread /
    /// task boundaries. This compile-time pin verifies the bound; if the
    /// trait loses `Send + Sync`, the Arc construction below stops compiling.
    #[test]
    fn b4_analytics_sink_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoopAnalytics>();
        assert_send_sync::<TracingAnalytics>();
        // Arc<dyn AnalyticsSink> is the shape ServiceRegistry holds.
        let _: std::sync::Arc<dyn AnalyticsSink> = std::sync::Arc::new(NoopAnalytics);
        let _: std::sync::Arc<dyn AnalyticsSink> = std::sync::Arc::new(TracingAnalytics);
    }

    /// B4: `NoopAnalytics::record` is callable unconditionally — callers are
    /// NOT required to do an `Option` check before calling. Exercises every
    /// variant through the noop sink to confirm none panics (spec §B4:
    /// "Must not panic").
    #[test]
    fn b4_noop_analytics_accepts_all_variants_without_panic() {
        let sink = NoopAnalytics;
        sink.record(AnalyticsEvent::SessionStart {
            session_id: "s1".to_string(),
        });
        sink.record(AnalyticsEvent::SessionEnd {
            session_id: "s1".to_string(),
            messages: 0,
        });
        sink.record(AnalyticsEvent::ToolUsed {
            tool: "bash".to_string(),
            success: false,
        });
        sink.record(AnalyticsEvent::PromptSubmitted { prompt_chars: 0 });
        sink.record(AnalyticsEvent::ContextCompacted {
            trigger: "manual",
            tokens_freed: 0,
        });
        sink.record(AnalyticsEvent::ApiRequest {
            provider: "anthropic".to_string(),
            model: "claude-opus-4-6".to_string(),
        });
        sink.record(AnalyticsEvent::ThinkingEmitted { budget: 0 });
    }

    // Crosslink #914: removed `b4_cost_tracked_variant_not_yet_present_gap649`.
    // The sentinel test pinned the *absence* of an `AnalyticsEvent::CostTracked`
    // variant via an exhaustive match. Once #649 actually adds the variant the
    // test would be silently easy to forget to delete, leaving production test
    // code that intentionally invites a compile error. The exhaustive match in
    // `TracingAnalytics::record` already enforces compile-time coverage when a
    // new variant is added — the dedicated sentinel was redundant.

    /// B4: `Arc<dyn AnalyticsSink>` can be cloned and sent across a thread.
    /// Confirms that `Send + Sync` is sufficient for the `ServiceRegistry`
    /// arc-clone-then-spawn pattern.
    #[test]
    fn b4_arc_sink_clone_crosses_thread_boundary() {
        let sink: std::sync::Arc<dyn AnalyticsSink> = std::sync::Arc::new(NoopAnalytics);
        let sink2 = std::sync::Arc::clone(&sink);
        let handle = std::thread::spawn(move || {
            sink2.record(AnalyticsEvent::PromptSubmitted { prompt_chars: 7 });
        });
        handle.join().expect("thread must not panic");
        sink.record(AnalyticsEvent::PromptSubmitted { prompt_chars: 3 });
    }

    #[test]
    fn state_subscriber_emits_start_switch_and_final_end() {
        let mut initial = crate::state::SessionState::default();
        initial.identity.session_id = crate::state::SessionId::from_raw_unchecked("first");
        initial
            .conversation
            .messages
            .push(serde_json::json!({"role": "user", "content": "hello"}));
        let state = StateStore::new(initial);
        let recording = Arc::new(Recording {
            events: Mutex::new(Vec::new()),
        });
        let sink: Arc<dyn AnalyticsSink> = recording.clone();
        let mut subscriber = StateAnalyticsSubscriber::new(state.clone(), sink);

        let mut replacement = crate::state::SessionState::default();
        replacement.identity.session_id = crate::state::SessionId::from_raw_unchecked("second");
        replacement.conversation.messages.extend([
            serde_json::json!({"role": "user"}),
            serde_json::json!({"role": "assistant"}),
        ]);
        state.replace(replacement);
        subscriber.drain_pending();
        subscriber.finish();
        subscriber.finish();

        assert_eq!(
            *recording.events.lock().unwrap(),
            vec![
                AnalyticsEvent::SessionStart {
                    session_id: "first".to_string(),
                },
                AnalyticsEvent::SessionEnd {
                    session_id: "first".to_string(),
                    messages: 1,
                },
                AnalyticsEvent::SessionStart {
                    session_id: "second".to_string(),
                },
                AnalyticsEvent::SessionEnd {
                    session_id: "second".to_string(),
                    messages: 2,
                },
            ]
        );
    }
}
