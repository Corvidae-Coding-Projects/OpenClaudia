//! Event system — merges terminal key events with async API streaming events.

use crossterm::event::{self, Event as CEvent, KeyEvent, KeyEventKind};
use std::sync::mpsc;
use std::time::Duration;

/// User's response to a permission prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionResponse {
    /// Allow this one time
    Allow,
    /// Deny this one time
    Deny,
    /// Always allow this tool in this session
    AlwaysAllow,
    /// Always deny this tool in this session
    AlwaysDeny,
}

/// Which slash-command branch dispatched a backgrounded shell call, so the
/// UI thread knows how to render the resulting [`AppEvent::ShellDone`].
///
/// Closes crosslink #371 — the TUI used to call `std::process::Command::new()
/// .output()` directly on the sync event loop, freezing the render loop for
/// however long the child took to exit. The shell now runs on the tokio
/// runtime via `App::spawn_shell` and the receiver matches on this tag to
/// decide which message-shape to emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnTarget {
    /// `/diff` — render stdout (or "No uncommitted changes.") as a system message.
    Diff,
    /// `/review` — truncated `git diff HEAD` as a system message.
    Review,
    /// `/init` — output of `openclaudia init` as a system message.
    Init,
    /// `/files` — directory listing (reserved for future migration).
    Files,
    /// `/doctor` — diagnostics output (reserved for future migration).
    Doctor,
    /// `!<cmd>` shell escape — render under a `$ <displayed>` tool header.
    ShellCommand { displayed: String },
}

/// Fully resolved provider switch payload for the TUI event loop.
///
/// Resolution can touch disk and, for Anthropic OAuth, await the Claude
/// credential store. The background task sends this owned bundle back to
/// the UI thread, which then applies it atomically to App state.
#[derive(Debug, Clone)]
pub struct ProviderSwitch {
    /// Provider name selected by the slash command, normalised to lowercase.
    pub provider: String,
    /// Model selected from provider config or the shared provider default table.
    pub model: String,
    /// Fully resolved chat endpoint used by subsequent API turns.
    pub endpoint: String,
    /// Fully resolved request headers, including auth and custom provider headers.
    pub headers: Vec<(String, String)>,
    /// Wire protocol used for subsequent API turns.
    pub wire_api: crate::pipeline::WireApi,
    /// Claude Code OAuth bearer for Anthropic subscription auth.
    pub claude_code_token: Option<String>,
    /// Runtime auth used by VDD's builder-side verifier after switching.
    pub vdd_builder_auth: crate::vdd::VddProviderAuth,
    /// Existing split system prompt blocks, preserved for Anthropic cache efficiency.
    pub prompt_blocks: Option<crate::prompt::SystemPromptBlocks>,
}

/// Transient API retry cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiRetryKind {
    /// Network/connect/read timeout or another retryable transport failure.
    Transport,
    /// Retryable HTTP status response from the upstream provider.
    Status,
}

/// Application events from multiple sources.
pub enum AppEvent {
    /// Terminal key event
    Key(KeyEvent),
    /// Bracketed terminal paste payload
    Paste(String),
    /// Terminal resize
    Resize(u16, u16),
    /// Animation tick
    Tick,
    /// Streaming text delta from API
    StreamText(String),
    /// Streaming thinking text
    StreamThinking(String),
    /// Tool execution started
    ToolStart { name: String, description: String },
    /// Tool execution completed
    ToolDone {
        name: String,
        success: bool,
        content: String,
    },
    /// API response completed
    ResponseDone,
    /// API error
    ApiError(String),
    /// The upstream API request will be retried after a transient failure.
    ApiRetry {
        kind: ApiRetryKind,
        attempt: u32,
        max_attempts: u32,
        delay_ms: u64,
        status: Option<u16>,
    },
    /// An SSE stream stalled after partial or empty provider output.
    ///
    /// This is runtime metadata, not assistant-authored content. The UI may
    /// render it to the user, but it must not be appended to the conversation
    /// transcript or fed back to the provider as model text.
    StreamTimeout {
        elapsed_secs: u64,
        timeout_secs: u64,
    },
    /// Tool results require a follow-up API call
    FollowUp,
    /// Sync updated session messages back to the App after an agentic loop.
    SyncMessages(Vec<serde_json::Value>),
    /// Pipeline requesting permission to run a tool.
    ///
    /// Includes a tokio `oneshot::Sender` to reply with the user's
    /// decision. Tokio oneshot (vs `std::sync::mpsc`) is essential
    /// here: under `flavor = "current_thread"` the pipeline task
    /// must `.await` the user's response, and `std::sync::mpsc::recv`
    /// would pin the single runtime thread (deadlocking the main TUI
    /// loop that has to deliver the response). `oneshot::Receiver::await`
    /// yields to the runtime so events keep flowing.
    PermissionRequest {
        tool_name: String,
        tool_args: String,
        reply: tokio::sync::oneshot::Sender<PermissionResponse>,
    },
    /// A trusted typed `ask_user_question` follow-up reached the TUI. The UI
    /// should display a modal that walks the user
    /// through each question, collect answers, and send back a JSON
    /// object mapping `question_text → answer(s)` via the oneshot.
    ///
    /// The pipeline thread parks on the receiver until the modal sends
    /// (same yielding contract as `PermissionRequest`). Mirrors the
    /// REPL flow in `cli::repl::input::handle_user_questions` so the
    /// agent-facing contract is identical across both front-ends.
    UserQuestion {
        questions: Vec<serde_json::Value>,
        reply: tokio::sync::oneshot::Sender<String>,
    },
    /// A subprocess dispatched via `App::spawn_shell` has finished.
    /// The UI thread renders this according to [`SpawnTarget`].
    ShellDone {
        target: SpawnTarget,
        stdout: String,
        stderr: String,
        exit_code: Option<i32>,
    },
    /// The retry loop in `pipeline::send_with_retry` exhausted
    /// [`crate::pipeline::MAX_API_RETRIES`] attempts on a 529-class
    /// "service overloaded" status — the upstream API is sustainedly
    /// over capacity rather than transiently rate-limiting.
    ///
    /// Carries an advisory `model_hint`: the model name the user should
    /// consider falling back to. The UI / orchestrator may surface this
    /// to the user, automatically retry with the hinted model, or do
    /// nothing — this event is informational, not a control directive,
    /// because the model-routing decision is owned by the higher layer
    /// (session config, user prefs). See crosslink #598.
    OverloadFallback {
        /// Suggested replacement model name (e.g. `"claude-haiku-4-5"`).
        ///
        /// The hint is derived from `pipeline::overload_fallback_for(model)`,
        /// which maps each known model family to its lighter sibling.
        /// Empty when no sensible fallback is known.
        model_hint: String,
    },
    /// A `/provider <name>` background resolution completed successfully.
    ProviderSwitchReady(Box<ProviderSwitch>),
    /// A `/provider <name>` background resolution failed.
    ProviderSwitchError(String),
    /// A `/model list` background fetch completed.
    ModelListReady {
        provider: String,
        current_model: String,
        models: Vec<String>,
        source: String,
        fallback_note: Option<String>,
    },
    /// A `/model list` background fetch failed.
    ModelListError {
        provider: String,
        message: String,
        fallback_models: Vec<String>,
    },
}

/// Handles terminal events in a background thread, merges with async events.
pub struct EventHandler {
    rx: mpsc::Receiver<AppEvent>,
    tx: mpsc::Sender<AppEvent>,
}

impl EventHandler {
    #[must_use]
    pub fn new(tick_rate: Duration) -> Self {
        let (tx, rx) = mpsc::channel();
        let event_tx = tx.clone();

        std::thread::spawn(move || loop {
            if event::poll(tick_rate).unwrap_or(false) {
                if let Ok(evt) = event::read() {
                    if let Some(app_evt) = translate_terminal_event(&evt) {
                        if event_tx.send(app_evt).is_err() {
                            break;
                        }
                    }
                }
            } else if event_tx.send(AppEvent::Tick).is_err() {
                break;
            }
        });

        Self { rx, tx }
    }

    /// Get a sender for pushing async events (streaming, tool results) into the loop.
    #[must_use]
    pub fn sender(&self) -> mpsc::Sender<AppEvent> {
        self.tx.clone()
    }

    /// Block until next event.
    ///
    /// # Errors
    ///
    /// Returns an error if the event channel is disconnected.
    pub fn next(&self) -> Result<AppEvent, mpsc::RecvError> {
        self.rx.recv()
    }

    /// Non-blocking poll. Returns immediately whether an event is ready or not.
    ///
    /// Used by the async TUI loop so it can `.await tokio::time::sleep`
    /// between empty polls — that `.await` is what lets the
    /// current-thread tokio runtime drive spawned tasks (e.g.
    /// `run_api_turn_async`). A purely blocking `recv()` would pin
    /// the runtime thread and starve every spawned task.
    ///
    /// # Errors
    ///
    /// Returns `TryRecvError::Empty` when no event is ready yet, or
    /// `TryRecvError::Disconnected` when both producer halves
    /// (terminal-reader thread + API senders) have hung up.
    pub fn try_next(&self) -> Result<AppEvent, mpsc::TryRecvError> {
        self.rx.try_recv()
    }
}

/// Translate a raw crossterm terminal event into an [`AppEvent`], filtering
/// events we do not want to propagate to the UI thread.
///
/// On Windows, crossterm fires both [`KeyEventKind::Press`] and
/// [`KeyEventKind::Release`] for every keystroke. Forwarding both would cause
/// each key to be processed twice (e.g. `"a"` → `"aa"`, `"A"` → `"Aa"`, `"?"`
/// → `"?/"` because the shifted and unshifted forms of the same physical key
/// are delivered on press vs. release). We therefore accept only `Press` and
/// `Repeat`, which matches Unix behavior and keeps key-hold working on
/// terminals that support the kitty keyboard protocol.
///
/// See: <https://github.com/ratatui/ratatui/issues/347>
fn translate_terminal_event(evt: &CEvent) -> Option<AppEvent> {
    match evt {
        CEvent::Key(key) if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) => {
            Some(AppEvent::Key(*key))
        }
        CEvent::Paste(text) => Some(AppEvent::Paste(text.clone())),
        CEvent::Resize(w, h) => Some(AppEvent::Resize(*w, *h)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventState, KeyModifiers};

    fn key(code: KeyCode, kind: KeyEventKind) -> CEvent {
        CEvent::Key(KeyEvent::new_with_kind_and_state(
            code,
            KeyModifiers::NONE,
            kind,
            KeyEventState::NONE,
        ))
    }

    #[test]
    fn press_events_are_forwarded() {
        let evt = key(KeyCode::Char('a'), KeyEventKind::Press);
        match translate_terminal_event(&evt) {
            Some(AppEvent::Key(k)) => assert_eq!(k.code, KeyCode::Char('a')),
            _ => panic!("expected AppEvent::Key for Press"),
        }
    }

    #[test]
    fn repeat_events_are_forwarded() {
        // Repeat should be honored so holding a key still works under the
        // kitty keyboard protocol.
        let evt = key(KeyCode::Char('x'), KeyEventKind::Repeat);
        match translate_terminal_event(&evt) {
            Some(AppEvent::Key(k)) => assert_eq!(k.code, KeyCode::Char('x')),
            _ => panic!("expected AppEvent::Key for Repeat"),
        }
    }

    #[test]
    fn release_events_are_dropped() {
        // Regression test for https://github.com/dollspace-gay/OpenClaudia/issues/13
        // On Windows, crossterm fires a Release alongside every Press. If we
        // forwarded these, every key would be entered twice.
        let evt = key(KeyCode::Char('a'), KeyEventKind::Release);
        assert!(translate_terminal_event(&evt).is_none());
    }

    #[test]
    fn shifted_release_is_dropped() {
        // The original bug report noted that entering "A" produced "Aa" and
        // "?" produced "?/". That happens because Windows delivers the
        // shifted form on Press and the unshifted form on Release of the
        // same physical key. Verify that the Release is discarded regardless
        // of which glyph it carries.
        let evt = key(KeyCode::Char('/'), KeyEventKind::Release);
        assert!(translate_terminal_event(&evt).is_none());
    }

    #[test]
    fn resize_events_are_forwarded() {
        match translate_terminal_event(&CEvent::Resize(120, 40)) {
            Some(AppEvent::Resize(w, h)) => {
                assert_eq!(w, 120);
                assert_eq!(h, 40);
            }
            _ => panic!("expected AppEvent::Resize"),
        }
    }

    #[test]
    fn paste_events_are_forwarded() {
        match translate_terminal_event(&CEvent::Paste("one\ntwo".to_string())) {
            Some(AppEvent::Paste(text)) => assert_eq!(text, "one\ntwo"),
            _ => panic!("expected AppEvent::Paste"),
        }
    }
}
