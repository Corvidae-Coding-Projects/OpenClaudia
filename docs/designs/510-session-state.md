# Design: Centralized SessionState (crosslink #510)

> Implementation status: Phases 0–3 are complete. The TUI and legacy REPL now
> share identity, conversation state, agent mode, budgets, session UI state,
> permission state, transcript bookkeeping, IDE state, and a compatible session
> document. Phases 4–5 remain planned.

## Problem

OpenClaudia's per-session state is scattered across three concrete types and an assortment of unrelated modules:

- `tui::app::App` — the TUI event-loop struct (~30 fields)
- `tui::app::TuiSession` — the persistence struct (title / model / behavior / messages / undo_stack / plan_mode / approved_plan)
- `cli::repl::ChatSession` — the chat-REPL persistence struct (near-clone of TuiSession with a different serde format)
- Scattered Arcs: `memory_db`, `permission_mgr`, `hook_engine`, `plugin_manager`, `service_registry` (from #511) — each owned by whichever surface instantiates them
- Miscellaneous: `behavior_mode` on ChatSession, `effort_level` on App, IDE state on AcpServer (#517), todo thread-local (#518), transcript watermark on App (#516).

Consequences of the scatter:
1. **Field threading**: adding a new piece of session state requires touching multiple constructors, serde structs, and call sites (e.g. #518 had to add `SessionIdGuard` across 10+ call sites instead of reading from a central context).
2. **Drift**: TuiSession vs ChatSession have the same fields with subtly different defaults and serde layouts. Load-saved-in-TUI-resume-in-chat is not round-trip safe.
3. **No event bus**: when a session switch happens (`/load`, `/resume`, `/new`), there's no listener mechanism — every dependent subsystem polls or gets plumbed a new handle. Claude Code uses `tokio::sync::broadcast` for `on_session_switch`; OC has nothing equivalent.
4. **Hard to snapshot**: `/rewind`, `/dream`, `/compact` all want a coherent snapshot of "what does the agent know right now". Today they cobble it together from App fields manually.

Claude Code's equivalent: `Arc<RwLock<SessionState>>` singleton with ~98 fields grouped into 12 semantic categories and ~210 getter/setter exports. Detailed in `claude-code-design-documents/.design/state-management.md` REQ-1.

## Proposed architecture

Introduce `src/state/` as the home of a single `SessionState` struct plus `StateStore` wrapper with change-notification. Migrate fields into it across several phases so no single PR is "rewrite everything".

```
┌──────────────────────────────────────────────────────────────┐
│ state/mod.rs          SessionState struct + categories       │
├──────────────────────────────────────────────────────────────┤
│ state/store.rs        Arc<RwLock<SessionState>> wrapper +    │
│                       broadcast channel for change events    │
│ state/persist.rs      Serde layer — single source of truth   │
│                       for on-disk format, replaces divergent │
│                       TuiSession/ChatSession serde           │
│ state/categories.rs   Helper accessors grouped by concern    │
│                       (identity, permissions, UI, …)         │
└──────────────────────────────────────────────────────────────┘
            │                    │                    │
            ▼                    ▼                    ▼
     App / cmd_chat         services::         transcript.rs
     (consumers)            analytics         (already keyed
                            (subscribes to    by session_id)
                             session_switch)
```

### Key abstractions

```rust
/// The single source of truth for one session. Grouped by concern
/// so adding a new field lands inside the right sub-struct rather
/// than in a flat list of 98 fields. Each sub-struct is plain data —
/// no Arcs — so the whole thing is cheap to clone for snapshots.
pub struct SessionState {
    pub identity: Identity,
    pub conversation: Conversation,
    pub ui: UiState,
    pub modes: ModesState,
    pub permissions: PermissionsState,
    pub budgets: BudgetsState,
    pub ide: IdeState,               // from #517
    pub transcript: TranscriptState, // from #516, watermark lives here
    pub worktree: Option<WorktreeState>,
    pub teleport: Option<TeleportInfo>,
}

/// Who / where / which (7 fields from CC's REQ-1 "Identity" group).
pub struct Identity {
    pub session_id: SessionId,
    pub parent_session_id: Option<SessionId>,
    pub original_cwd: PathBuf,
    pub cwd: PathBuf,
    pub project_root: PathBuf,
    pub session_project_dir: PathBuf,
    pub additional_directories_for_claude_md: Vec<PathBuf>,
}

/// Messages + undo stack + behavioral mode — everything the
/// agentic loop reads per turn.
pub struct Conversation {
    pub messages: Vec<Value>,         // wire-format
    pub undo_stack: Vec<(Value, Value)>,
    pub approved_plan: Option<String>,
    pub plan_mode: Option<PlanModeState>,
    pub behavior_mode: BehaviorMode,
}

/// UI flags (4 fields from CC's "UI State" group).
pub struct UiState {
    pub has_exited_plan_mode: bool,
    pub needs_plan_mode_exit_attachment: bool,
    pub needs_auto_mode_exit_attachment: bool,
    pub lsp_recommendation_shown_this_session: bool,
}

/// Permission state (3 fields from CC's "Permissions" group).
pub struct PermissionsState {
    pub bypass_mode: bool,
    pub trust_accepted: bool,
    pub persistence_disabled: bool,
}

/// Budgets — tokens, cost, rate limits.
pub struct BudgetsState {
    pub effort_level: EffortLevel,
    pub thinking_budget_override: Option<u32>,
    pub estimated_tokens: usize,
}

/// Clone-cheap handle. Everywhere that today takes `&App` or
/// `&ChatSession` ends up taking `&StateStore` after migration.
#[derive(Clone)]
pub struct StateStore {
    inner: Arc<RwLock<SessionState>>,
    /// tokio broadcast — every listener subscribes once and receives
    /// each session-level change event in arrival order.
    events: broadcast::Sender<StateEvent>,
}

impl StateStore {
    pub fn snapshot(&self) -> SessionState;
    pub fn inspect<R>(&self, inspect: impl FnOnce(&SessionState) -> R) -> R;
    pub fn update<R>(
        &self,
        update: impl FnOnce(&mut SessionState, &mut Vec<StateEvent>) -> R,
    ) -> R;

    pub fn subscribe(&self) -> broadcast::Receiver<StateEvent>;
}

/// Queued inside `update` and emitted after the lock is released. Granular
/// events let subscribers react to only the categories they care about.
pub enum StateEvent {
    SessionSwitched { from: SessionId, to: SessionId },
    MessageAppended { role: String },
    ModeChanged { new: BehaviorMode },
    EffortChanged { new: EffortLevel },
    PermissionsMutated,
    Cleared,
}
```

### Arcs live outside SessionState

`memory_db`, `permission_mgr`, `hook_engine`, `plugin_manager`,
`service_registry` — these are **process-scoped** handles, not
per-session state. They stay on a separate `AppHandles` struct that
gets passed alongside `StateStore` wherever both are needed. Keeping
them out of SessionState keeps serialization + snapshots simple.

### Persistence is a separate concern

`state/persist.rs` owns one compatibility document with an embedded
`SessionStateV1` payload that both the TUI and chat REPL emit. Current readers
accept legacy top-level-only files and prefer the V1 payload when present.
`TuiSession` / `ChatSession` are metadata shims that
deserialize-then-convert. A later migration (via #506's framework) can remove
the duplicated legacy fields.

## Integration plan (phased)

The migration must be incremental — a single-PR rewrite would stall.
Each phase compiles + tests green on its own.

**Phase 0 — ship the module, empty**
- Complete.
- Create `src/state/` with the structs above. Nothing uses it yet.
- `SessionState::new(...)` constructs from existing `TuiSession` for compat.
- Tests: default construction, roundtrip serde.

**Phase 1 — migrate Identity + Conversation**
- Complete.
- Replace `App.chat_session.messages` / `App.chat_session.id` reads with short-lived `StateStore::inspect` / `update` closures.
- Same for the REPL. `TuiSession` / `ChatSession` forward to the new fields.
- Tests: `/load`, `/resume`, `/undo`, `/redo` still pass.

**Phase 2 — migrate BudgetsState + UiState**
- Complete.
- Removed the TUI `App.effort_level` / token-cache fields and the legacy REPL's
  string effort field; both now read and write `state.budgets`.
- Token estimates refresh in the canonical budget state before session saves.
- The plan/LSP UI flags already had no frontend-owned duplicates, so Phase 2
  verifies that their canonical values survive TUI ↔ REPL serialization rather
  than introducing unused mirror fields.
- Tests: effort parsing/cycling and cross-frontend budget/UI round trips pass.

**Phase 3 — migrate Permissions / Transcript / IDE**
- Complete.
- Removed `App.transcript_watermark` / `App.transcript_cwd`; TUI transcript
  appends now read and advance `state.transcript`, then save the canonical
  watermark only after successful JSONL writes. Rewind-shortened histories
  clamp the offset before slicing so a branched turn cannot panic or be skipped.
- Removed the legacy REPL's permission-bypass mirror. Both interactive
  frontends read `state.permissions.bypass_mode`, while startup deliberately
  reapplies the current command-line value after resume so a dangerous choice
  never leaks into a later process. The other permission flags already had no
  frontend-owned duplicates and remain canonical snapshot data.
- Moved ACP `IdeState` and its wire types into `state.ide`. IDE notifications
  mutate the shared `StateStore`; prompt construction reads a detached snapshot
  and injects bounded, XML-escaped editor context on the next turn.
- Tests: permission/transcript cross-frontend round trips, rewind watermark
  clamping, backward-compatible missing-IDE defaults, IDE bridge propagation,
  prompt visibility, injection escaping, and existing IDE wire-shape coverage.

**Phase 4 — StateEvent broadcast**
- Analytics sink subscribes; emits `SessionStart` / `SessionEnd` from `SessionSwitched`.
- Transcript writer subscribes; `MessageAppended` triggers `persist_transcript_tail` automatically.
- Tests: subscribe → drive switch → assert event fires.

**Phase 5 — delete TuiSession / ChatSession compat shims**
- Only after every caller migrated.
- Migration `m0xx_session_state_v1` rewrites on-disk old-format files to V1 on first load.

Phases 0–2 are single-commit each. Phases 3–4 are two-commit each. Phase 5 requires the migrations framework (already shipped in #506) and lands last.

## Test strategy

- `state::mod::tests` — field-per-field serde roundtrip against a golden JSON fixture.
- `state::store::tests` — subscribe-fires-on-change, write-guard-drop emits event, concurrent readers don't starve writers.
- Migration test: load an existing fixture of TuiSession JSON, assert the resulting V1 shape is lossless.
- Every phase's commit passes the whole suite — the phased plan is what keeps that tractable.

## Risks and open questions

1. **Deadlock via lock holding**. Addressed in Phase 1 by exposing closure-based `inspect` / `update` methods instead of lock guards. References into state cannot escape a closure, so callers clone the data they need before any `.await`.
2. **Broadcast channel bound**. `tokio::sync::broadcast` drops messages when the receiver falls behind. Subscribers must handle `RecvError::Lagged` — easy to forget. Ship a helper `StateStore::subscribe_log_lag()` that wraps recv + logs on lag so every caller gets the same behavior.
3. **Serialization drift with plugins**. Plugins persist per-plugin config (already in #514 policy work); keep those out of `SessionState` so the version-bump cost stays bounded to core fields.
4. **Migration atomicity**. Phase 5 rewrites every old session file. Must be crash-safe: write-temp + rename. Reuse the file-atomicity helpers the transcript writer already uses.
5. **Observability during the migration**. Later phases should add tracing around important `StateStore::update` calls. If a user reports a broken `/undo`, the log should identify which writer moved the field without sprinkling `eprintln!`s.
6. **API stability**. `pub` fields on `SessionState` make snapshot and closure access ergonomic but expose the shape. Revisit field visibility after Phase 5 removes the compatibility shims.

## Out of scope

- Sync with a remote state backend (CC's `remote/` handles this; ours would come via a future issue if SDK / remote-session parity is pursued)
- Telemetry / stats counters — those belong on `services::analytics` (#511), not SessionState
- Scheduled-tasks persistence — lives on its own `ScheduledTasksStore` if the `cron` feature is ever re-enabled
