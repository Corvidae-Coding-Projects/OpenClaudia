//! Interactive chat REPL — decomposed `cmd_chat` god-function.
//!
//! Crosslink #262 split the original 2.4k-line `cmd_chat` into a
//! [`ChatRepl`] struct that owns all loop state, plus a handful of
//! bounded methods that each fit under the `clippy::too_many_lines`
//! threshold. Behaviour is preserved bit-for-bit: every branch, every
//! `println!`, every `continue`/`break` from the original inline body
//! has been moved verbatim into a method here.
//!
//! All `crate::*` references resolve back to private helpers in
//! `src/main.rs` (auth resolution, prompt building, audit logging, etc.)
//! — Rust visibility rules let descendant modules of the crate root see
//! private items at the root, so no signatures had to change.
//!
//! Module overview:
//! - [`ChatRepl::new`] — setup, mirrors the original 130-line prelude.
//! - [`ChatRepl::run`] — outer readline loop.
//! - [`ChatRepl::process_line`] — one-iteration orchestrator.
//! - [`ChatRepl::dispatch_slash`] — every `/command` branch.
//! - [`ChatRepl::send_and_process_turn`] — request build, response dispatch.
//! - `process_google_*` / `process_streaming_*` — provider-specific paths.

use crate::cli::display::tool_result::display_tool_result;
use crate::cli::repl::input::expand_file_references;
use crate::cli::repl::keybindings::{display_keybindings, execute_key_action, key_event_to_string};
use crate::cli::repl::permissions::execute_shell_command_with_permission;
use crate::cli::repl::plan_mode::{check_plan_mode_restriction, process_tool_follow_up};
use crate::cli::repl::session_io::{
    compact_chat_session_with_instructions, estimate_session_tokens, export_chat_session,
    save_session_to_short_term_memory,
};
use crate::cli::repl::slash::{
    handle_activity_command, handle_memory_command, handle_slash_command_for_runtime,
    PluginActionOutcome, PluginActionRunner, PluginCommandInvocation, SkillInvocation,
    SlashCommandResult,
};
use crate::cli::repl::vim::{self, VimState};
use crate::cli::repl::{load_chat_session, save_chat_session, Session};
use crate::{
    build_chat_endpoint_and_headers, build_chat_request_body, build_hook_engine, chdir_to_git_root,
    check_tool_permission_interactive, finalize_chat, init_memory_with_banner,
    init_permission_manager, init_plugin_manager, init_rustyline_with_history,
    init_vdd_engine_if_enabled, maybe_auto_compact, maybe_resume_session,
    parse_initial_behavior_mode, read_multiline_continuation, render_welcome_or_fallback,
    resolve_chat_auth, resolve_model_name, run_vdd_review, ChatAuth, ChatAuthSelectionMode,
    ToolPermissionResult,
};

use eventsource_stream::Eventsource;
use openclaudia::providers::{
    convert_messages_to_anthropic_checked, convert_tool_definitions_to_anthropic_checked,
    convert_tools_to_gemini_functions, extract_gemini_text_content,
};
use openclaudia::state::EffortLevel;
use openclaudia::tools::safe_truncate;
use openclaudia::{
    config, guardrails, memory,
    permissions::{
        allowed_tool_specs_to_permission_rules, ExecutionPermit, PermissionManager, PermissionRule,
    },
    plugins, prompt, proxy, session, tools, tui, vdd,
};
use rustyline::error::ReadlineError;

fn execute_tool_with_memory_after_permission(
    run_context: &std::sync::Arc<tools::ToolRunContext>,
    tool_call: &tools::ToolCall,
    memory_db: Option<&memory::MemoryDb>,
    permission_mgr: &PermissionManager,
    authorization: Option<ExecutionPermit>,
    session_id: &str,
    policy_enforcer: Option<&openclaudia::services::policy::PolicyEnforcer>,
) -> tools::ToolResult {
    openclaudia::services::tool_executor::ToolExecutor::execute(
        openclaudia::services::tool_executor::ToolExecutorRequest {
            run_context,
            tool_call,
            memory_db,
            app_config: None,
            task_mgr: None,
            permission_mgr,
            authorization,
            session_id: Some(session_id),
            policy_enforcer,
        },
    )
}

fn observe_cli_model_visible_tool_result(
    run: &tools::ToolRunContext,
    session_id: &str,
    tool_call: &tools::ToolCall,
    tool_call_id: &str,
    content: &str,
    is_error: bool,
) {
    let mut bound_call = tool_call.clone();
    bound_call.id = tool_call_id.to_string();
    let result = tools::ToolResult::bind(
        &bound_call,
        &tool_call.function.name,
        tools::ToolHandlerResult::legacy(content.to_string(), is_error),
    );
    openclaudia::grounded_loop::observe_tool_result_for_session(run, session_id, &result);
}

fn push_observed_cli_typed_tool_result_message(
    run: &tools::ToolRunContext,
    session: &mut Session,
    _tool_call: &tools::ToolCall,
    result: &tools::ToolResult,
) {
    openclaudia::grounded_loop::observe_tool_result_for_session(run, &session.id(), result);
    push_chat_session_message_and_persist(
        session,
        result.openai_message(),
        "typed CLI tool result",
    );
}

fn push_observed_cli_tool_result_message(
    run: &tools::ToolRunContext,
    session: &mut Session,
    tool_call: &tools::ToolCall,
    tool_call_id: &str,
    final_content: &str,
    final_is_error: bool,
) {
    observe_cli_model_visible_tool_result(
        run,
        &session.id(),
        tool_call,
        tool_call_id,
        final_content,
        final_is_error,
    );
    push_cli_tool_result_message(session, tool_call_id, final_content, final_is_error);
}

fn push_cli_tool_result_message(
    session: &mut Session,
    tool_call_id: &str,
    final_content: &str,
    final_is_error: bool,
) {
    let result_content = if final_is_error {
        format!("[ERROR] {final_content}")
    } else {
        final_content.to_string()
    };
    push_chat_session_message_and_persist(
        session,
        serde_json::json!({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": result_content,
            "is_error": final_is_error
        }),
        "tool result",
    );
}

/// Arguments accepted by [`ChatRepl::new`] — kept as a struct so the
/// public `cmd_chat` signature stays a thin wrapper.
pub struct ChatReplArgs {
    pub model_override: Option<String>,
    pub target_override: Option<String>,
    pub resume: bool,
    pub session_id: Option<String>,
    pub coordinator: bool,
    pub dangerously_skip_permissions: bool,
    pub mode_arg: Option<String>,
}

/// All mutable state for one chat session, plus the configuration the
/// loop needs to reach providers and external services.
pub struct ChatRepl {
    // ── Configuration captured during setup ──
    config: config::AppConfig,
    coordinator: bool,
    // Crosslink #433: was `Box<dyn ProviderAdapter>`. Now `&'static dyn …`
    // — `get_adapter` returns a shared static singleton, so the REPL just
    // borrows it for the lifetime of the process. No allocation, no Drop.
    adapter: &'static dyn openclaudia::providers::ProviderAdapter,
    client: reqwest::Client,
    hook_engine: openclaudia::hooks::HookEngine,
    api_key: Option<openclaudia::providers::ApiKey>,
    claude_code_token: Option<openclaudia::secrets::OAuthToken>,
    permission_mgr: PermissionManager,
    policy_enforcer: std::sync::Arc<openclaudia::services::policy::PolicyEnforcer>,
    run_context: std::sync::Arc<tools::ToolRunContext>,
    vdd_engine: Option<vdd::VddEngine>,
    history_path: std::path::PathBuf,
    // ── Per-session mutable state ──
    model: String,
    rl: rustyline::DefaultEditor,
    chat_session: Session,
    service_registry: openclaudia::services::ServiceRegistry,
    analytics_subscriber: openclaudia::services::analytics::StateAnalyticsSubscriber,
    current_task_obs: Option<openclaudia::ledger::ObsId>,
    active_theme: tui::Theme,
    vim_enabled: bool,
    vim_state: VimState,
    audit_logger: openclaudia::session::AuditLogger,
    memory_db: Option<memory::MemoryDb>,
    // `auto_learner` borrows `memory_db` so it can't live on the same
    // struct (self-referential). It is constructed once in `run` and
    // threaded into any method that needs it via `&mut Option<_>`.
    permissions: openclaudia::permissions::LocalApprovalCache,
    transient_allowed_tool_rules: Vec<PermissionRule>,
    transient_model_restore: Option<String>,
    transient_effort_override: Option<EffortLevel>,
    plugin_manager: plugins::PluginManager,
}

/// Slash-command dispatch outcome — tells `process_line` whether to
/// short-circuit the iteration, exit, fall through to model send, or
/// note that the editor already pushed the user message.
enum SlashOutcome {
    Continue,
    Break,
    EditorMessageAdded,
    FallThrough,
    RewrittenPrompt,
}

/// Per-turn transport bundle — the URL + headers needed to POST to
/// the active provider. Grouped so tool-loop methods stay under the
/// `clippy::too_many_arguments` threshold without losing call-site
/// readability.
#[derive(Clone, Copy)]
struct TurnTransport<'a> {
    endpoint: &'a str,
    headers: &'a openclaudia::secrets::SensitiveHeaders,
}

fn derive_repl_session_run(
    parent: &tools::ToolRunContext,
    session: &Session,
    configured_provider: &str,
) -> Result<std::sync::Arc<tools::ToolRunContext>, String> {
    if canonical_provider_name(&session.provider) != canonical_provider_name(configured_provider) {
        return Err(format!(
            "Saved session provider '{}' differs from the active provider '{}'; relaunch with --target {} to resume it",
            session.provider, configured_provider, session.provider
        ));
    }
    let identity = session.inspect_state(|state| state.identity.clone());
    let project_root = std::fs::canonicalize(&identity.project_root).map_err(|error| {
        format!(
            "Cannot resume project root '{}': {error}",
            identity.project_root.display()
        )
    })?;
    if project_root != parent.project_root() {
        return Err(format!(
            "Session project '{}' differs from the authorized launch project '{}'; launch OpenClaudia from that project to resume it",
            project_root.display(),
            parent.project_root().display()
        ));
    }
    parent.derive_frontend_session(
        identity.session_id,
        &project_root,
        &identity.cwd,
        configured_provider,
    )
}

fn fresh_repl_session_in_run(current: &Session, model: &str, provider: &str) -> Session {
    let behavior_mode = current.behavior_mode();
    let identity = current.inspect_state(|state| state.identity.clone());
    let fresh = Session::new_with_behavior_mode(model, provider, behavior_mode);
    let fresh_id = fresh.inspect_state(|state| state.identity.session_id.clone());
    fresh.update_state(|state, _| {
        state.identity = identity;
        state.identity.session_id = fresh_id;
        state.identity.parent_session_id = None;
        state.transcript.transcript_cwd = state.identity.cwd.clone();
    });
    fresh
}

/// Mutable state threaded through the Gemini agentic tool loop.
/// Bundling these together keeps `run_gemini_tool_loop` under clippy's
/// `too_many_arguments` threshold without resorting to a suppression.
struct GeminiLoopState {
    full_content: String,
    tool_calls: Vec<tools::ToolCall>,
    contents: Vec<serde_json::Value>,
}

/// Mutable state carried through the OpenAI-compatible tool loop.
struct OpenAiLoopState {
    current_content: String,
    current_reasoning_content: String,
    cancelled: bool,
}

/// Mutable borrows threaded through SSE frame routing during initial
/// streaming. Bundled into one context so `route_sse_frame` stays under
/// clippy's argument-count ceiling.
struct SseFrameCtx<'a> {
    full_content: &'a mut String,
    reasoning_content: &'a mut String,
    tool_accumulator: &'a mut tools::ToolCallAccumulator,
    anthropic_accumulator: &'a mut tools::AnthropicToolAccumulator,
    stream_usage: &'a mut openclaudia::session::TokenUsage,
    in_thinking_block: &'a mut bool,
    thinking_start_time: &'a mut Option<std::time::Instant>,
    reasoning_started: &'a mut bool,
}

/// Spinner template — uses indicatif placeholder syntax, not `format!`.
const SPINNER_TMPL: &str = "{spinner:.cyan} {msg}";

fn active_provider_for_turn(config: &config::AppConfig) -> Result<&config::ProviderConfig, String> {
    config.active_provider().ok_or_else(|| {
        format!(
            "No provider configured for target '{}'",
            config.proxy.target
        )
    })
}

fn latest_user_message_content(messages: &[serde_json::Value]) -> Option<&str> {
    messages
        .iter()
        .rev()
        .find(|message| message.get("role").and_then(|role| role.as_str()) == Some("user"))
        .and_then(|message| message.get("content").and_then(|content| content.as_str()))
}

fn observe_cli_user_task(
    run: &tools::ToolRunContext,
    session_id: &str,
    content: &str,
    model_identity: &str,
) -> Option<openclaudia::ledger::ObsId> {
    openclaudia::grounded_loop::observe_session_user_task(run, session_id, content, model_identity)
}

fn request_messages_with_cli_grounding(
    run: &tools::ToolRunContext,
    session_id: &str,
    task_obs: Option<openclaudia::ledger::ObsId>,
    session_messages: &[serde_json::Value],
) -> Result<Vec<serde_json::Value>, String> {
    openclaudia::grounded_loop::request_messages_with_grounding(
        run,
        session_id,
        task_obs,
        session_messages,
    )
}

fn cli_grounding_system_content(
    run: &tools::ToolRunContext,
    session_id: &str,
    task_obs: openclaudia::ledger::ObsId,
) -> Option<String> {
    openclaudia::grounded_loop::session_grounding_system_content(run, session_id, task_obs)
}

fn validate_and_render_cli_agentic_final_response(
    run: &tools::ToolRunContext,
    session_id: &str,
    content: &str,
    model_identity: &str,
) -> Result<String, String> {
    openclaudia::grounded_loop::validate_and_render_agentic_final_response(
        run,
        session_id,
        content,
        model_identity,
    )
}

fn final_response_requires_grounding(content: &str, cancelled: bool) -> bool {
    !cancelled && !content.trim().is_empty()
}

fn check_provider_request_policy(
    policy_enforcer: &openclaudia::services::policy::PolicyEnforcer,
    model: &str,
    messages: &[serde_json::Value],
) -> Result<(), String> {
    let request = openclaudia::pipeline::build_chat_completion_request(model, messages)?;
    let estimated_input = openclaudia::compaction::estimate_request_tokens(&request);
    openclaudia::services::policy::ProviderRequestPolicy::new(policy_enforcer.policy())
        .check(
            openclaudia::services::policy::ProviderRequestPolicyInput::new(
                &request.model,
                estimated_input,
                request.max_tokens,
                0,
            ),
        )
        .map_err(|e| format!("Blocked by policy: {e}"))
}

fn load_repl_config(
    model_override: Option<&str>,
    target_override: Option<&str>,
) -> Option<config::AppConfig> {
    if !config::config_file_exists() {
        eprintln!("No configuration found. Run 'openclaudia init' first.");
        return None;
    }

    let mut config = match config::load_config() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("Failed to parse configuration: {err}");
            eprintln!("Check your .openclaudia/config.yaml for syntax errors.");
            return None;
        }
    };

    if let Some(target) = target_override {
        config.proxy.target = target.to_string();
    } else if let Some(model) = model_override {
        apply_model_provider_override(&mut config, model);
    }

    if let Err(err) = config.vdd.validate(&config.proxy.target) {
        eprintln!("VDD configuration error: {err}");
        return None;
    }

    Some(config)
}

fn apply_model_provider_override(config: &mut config::AppConfig, model: &str) {
    let detected = openclaudia::proxy::determine_provider(model, config);
    if detected != config.proxy.target {
        eprintln!(
            "[debug] Model '{}' detected as provider '{}' (overriding target '{}')",
            model, detected, config.proxy.target
        );
        config.proxy.target = detected;
    }
}

async fn resolve_repl_chat_auth(
    config: &config::AppConfig,
    provider: &config::ProviderConfig,
) -> anyhow::Result<ChatAuth> {
    let Some(auth) = resolve_chat_auth(
        &config.proxy.target,
        provider,
        ChatAuthSelectionMode::Automatic,
    )
    .await?
    else {
        anyhow::bail!(
            "could not resolve authentication for target '{}'",
            config.proxy.target
        );
    };
    if auth.codex_responses_auth.is_some() {
        anyhow::bail!(
            "Codex ChatGPT login currently requires the full-screen TUI Responses backend"
        );
    }
    Ok(auth)
}

impl ChatRepl {
    /// Resolve config + auth + provider + session and return a fully
    /// initialized REPL. Setup failures return an error after printing the
    /// same user-facing diagnostics as the default TUI path, so the process
    /// exits non-zero instead of making automation believe startup succeeded.
    #[allow(clippy::too_many_lines)] // Session composition is intentionally linear and fail-fast.
    pub async fn new(args: ChatReplArgs) -> anyhow::Result<Self> {
        chdir_to_git_root();

        let Some(config) = load_repl_config(
            args.model_override.as_deref(),
            args.target_override.as_deref(),
        ) else {
            anyhow::bail!("legacy REPL setup failed: configuration unavailable");
        };

        let initial_behavior_mode = match parse_initial_behavior_mode(args.mode_arg.as_deref()) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("{e}");
                anyhow::bail!(e);
            }
        };

        let provider = match active_provider_for_turn(&config) {
            Ok(provider) => provider,
            Err(err) => {
                eprintln!("{err}");
                anyhow::bail!(err);
            }
        };

        let ChatAuth {
            api_key,
            claude_code_token,
            codex_responses_auth: _,
        } = resolve_repl_chat_auth(&config, provider).await?;

        let model = resolve_model_name(
            args.model_override,
            provider.model.clone(),
            &config.proxy.target,
        );
        // Crosslink #433: typo in `proxy.target` fails fast at REPL setup
        // instead of silently falling back to OpenAIAdapter.
        let Some(adapter) = resolve_repl_adapter(&config.proxy.target) else {
            anyhow::bail!("unknown provider target '{}'", config.proxy.target);
        };
        let client = reqwest::Client::new();
        let hook_engine = build_hook_engine(&config);
        let (rl, history_path) = init_rustyline_with_history()?;

        render_welcome_or_fallback(&config.proxy.target, &model);
        let _ = tui::setup_pinned_bar();

        let mut chat_session =
            Session::new_with_behavior_mode(&model, &config.proxy.target, initial_behavior_mode);
        maybe_resume_session(&mut chat_session, args.resume, args.session_id.as_deref());
        // A dangerous bypass is a launch-scoped choice. Apply it after resume
        // so a saved session can neither enable nor disable the current CLI's
        // explicit posture.
        chat_session.set_permission_bypass(
            args.dangerously_skip_permissions || !config.permissions.enabled,
        );
        let analytics_sink: std::sync::Arc<dyn openclaudia::services::analytics::AnalyticsSink> =
            std::sync::Arc::new(openclaudia::services::analytics::TracingAnalytics);
        let service_registry = openclaudia::services::ServiceRegistry::interactive(
            std::sync::Arc::clone(&analytics_sink),
        );
        let Some(analytics_subscriber) =
            service_registry.analytics_subscriber(chat_session.state_store())
        else {
            anyhow::bail!("interactive REPL service registry has analytics disabled");
        };

        let audit_logger = openclaudia::session::AuditLogger::new(&chat_session.id())?;
        let memory_db: Option<memory::MemoryDb> = init_memory_with_banner();
        let policy_enforcer = std::sync::Arc::new(
            openclaudia::services::policy::PolicyEnforcer::new(config.policy.clone()),
        );
        let vdd_engine: Option<vdd::VddEngine> = init_vdd_engine_if_enabled(&config);
        let identity = chat_session.inspect_state(|state| state.identity.clone());
        let run_context =
            tools::ToolRunContext::builder(identity.session_id, identity.project_root)
                .working_directory(identity.cwd)
                .host_startup_grants()
                .workspace_access(tools::WorkspaceAccess::ReadWrite)
                .process(true)
                .network(true)
                .secrets(true)
                .provider(config.proxy.target.clone())
                .build()
                .map_err(anyhow::Error::msg)?;
        guardrails::configure(&run_context, &config.guardrails).map_err(anyhow::Error::msg)?;
        let permission_mgr =
            init_permission_manager(&config, args.dangerously_skip_permissions, &run_context);
        let plugin_manager = init_plugin_manager(run_context.project_root());
        let permissions = openclaudia::permissions::LocalApprovalCache::for_run(&run_context);

        Ok(Self {
            config,
            coordinator: args.coordinator,
            adapter,
            client,
            hook_engine,
            api_key,
            claude_code_token,
            permission_mgr,
            policy_enforcer,
            run_context,
            vdd_engine,
            history_path,
            model,
            rl,
            chat_session,
            service_registry,
            analytics_subscriber,
            current_task_obs: None,
            active_theme: tui::Theme::load(),
            vim_enabled: false,
            vim_state: VimState::new(),
            audit_logger,
            memory_db,
            permissions,
            transient_allowed_tool_rules: Vec::new(),
            transient_model_restore: None,
            transient_effort_override: None,
            plugin_manager,
        })
    }

    /// Drive the readline loop until the user exits. `auto_learner`
    /// is owned by `run` (it borrows `self.memory_db` only) and
    /// threaded into the few methods that need it via parameter; this
    /// side-steps the self-referential-struct problem without adding
    /// `unsafe` or changing the upstream `AutoLearner` lifetime.
    pub async fn run(mut self) -> anyhow::Result<()> {
        // Split the borrow: take memory_db out so the learner can
        // hold a stable borrow, then pass `memory_db.as_ref()` to
        // every site that used to call `memory_db`.
        let memory_db = self.memory_db.take();
        let mut auto_learner: Option<openclaudia::auto_learn::AutoLearner<'_>> = memory_db
            .as_ref()
            .map(openclaudia::auto_learn::AutoLearner::new);

        loop {
            let prompt = self.build_prompt_string();
            let readline = self.rl.readline(&prompt);
            match readline {
                Ok(line) => {
                    let should_break = self
                        .process_line(line, memory_db.as_ref(), &mut auto_learner)
                        .await?
                        == Some(true);
                    self.analytics_subscriber.drain_pending();
                    if should_break {
                        break;
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    println!("\n\x1b[90mInterrupted - saving session...\x1b[0m");
                    break;
                }
                Err(ReadlineError::Eof) => break,
                Err(err) => {
                    eprintln!("Error: {err:?}");
                    break;
                }
            }
        }
        finalize_chat(
            &mut auto_learner,
            &self.chat_session,
            memory_db.as_ref(),
            &mut self.rl,
            &self.history_path,
        );
        self.analytics_subscriber.finish();
        debug_assert!(self.service_registry.analytics_is_enabled());
        let end_input = openclaudia::hooks::HookInput::for_run(
            &self.run_context,
            openclaudia::hooks::HookEvent::SessionEnd,
        )
        .with_session_id(self.chat_session.id());
        let _ = self
            .hook_engine
            .run(openclaudia::hooks::HookEvent::SessionEnd, &end_input)
            .await;
        tools::retire_run(&self.run_context);
        // Drop the learner before memory_db.
        drop(auto_learner);
        drop(memory_db);
        println!("\nGoodbye!");
        Ok(())
    }

    /// Build the readline prompt string and render the status/bottom bars.
    fn build_prompt_string(&self) -> String {
        let behavior_name = self.chat_session.behavior_mode().display_name();
        let mode_str = format!(
            "{} ({})",
            self.chat_session.agent_mode().display().to_lowercase(),
            behavior_name,
        );
        let _ = tui::render_input_prompt(&mode_str);
        let effort = self.chat_session.effort_level();
        let _ = tui::render_bottom_bar(effort.as_str(), &mode_str);

        if self.vim_enabled {
            let pending = self.vim_state.pending_display();
            let status = vim::status_description(&self.vim_state);
            let _ = self.vim_state.yank_buffer.len();
            let _ = self.vim_state.last_find.is_some();
            let _ = vim::describe_action(&vim::VimAction::None);
            if self.vim_state.is_pending() {
                format!("{status} {pending} \u{203A} ")
            } else {
                format!("{status} \u{203A} ")
            }
        } else {
            "\u{203A} ".to_string()
        }
    }

    /// Process one line of user input. Returns `Some(true)` to break,
    /// `Some(false)` to continue without sending a turn, `None` after a
    /// full turn (autosave + auto-compact already handled).
    #[allow(clippy::too_many_lines)]
    async fn process_line(
        &mut self,
        line: String,
        memory_db: Option<&memory::MemoryDb>,
        auto_learner: &mut Option<openclaudia::auto_learn::AutoLearner<'_>>,
    ) -> anyhow::Result<Option<bool>> {
        let mut input = line.trim().to_string();
        let mut editor_message_added = false;
        let mut skip_local_input_shortcuts = false;
        self.current_task_obs = None;

        if self.vim_enabled {
            let _ = self.vim_state.process_key("Escape");
            let _ = self.vim_state.process_key("i");
        }
        if input.is_empty() {
            return Ok(Some(false));
        }
        read_multiline_continuation(&mut input, &mut self.rl);
        let _ = self.rl.add_history_entry(&input);
        let mut input = input.clone();

        match self.dispatch_slash(&mut input, memory_db) {
            SlashOutcome::Continue => return Ok(Some(false)),
            SlashOutcome::Break => return Ok(Some(true)),
            SlashOutcome::EditorMessageAdded => editor_message_added = true,
            SlashOutcome::FallThrough => {}
            SlashOutcome::RewrittenPrompt => {
                skip_local_input_shortcuts = true;
            }
        }

        if !skip_local_input_shortcuts {
            if let Some(cmd) = input.strip_prefix('!') {
                if cmd.is_empty() {
                    println!("Usage: !<command> (e.g., !ls -la)\n");
                    self.clear_transient_prompt_options();
                    return Ok(Some(false));
                }
                if let Some(execution) = execute_shell_command_with_permission(
                    &self.run_context,
                    cmd,
                    &mut self.permissions,
                ) {
                    openclaudia::grounded_loop::observe_shell_command_for_session(
                        &self.run_context,
                        &self.chat_session.id(),
                        &execution.cwd,
                        &execution.command,
                        execution.exit_code,
                        &execution.stdout,
                        &execution.stderr,
                    );
                }
                self.clear_transient_prompt_options();
                return Ok(Some(false));
            }
            if input.starts_with('#') {
                self.save_note_message(&input);
                self.clear_transient_prompt_options();
                return Ok(Some(false));
            }
        }

        if !editor_message_added && !self.prepare_user_message(&input, auto_learner).await {
            self.clear_transient_prompt_options();
            return Ok(Some(false));
        }

        let task_messages = self.chat_session.messages_snapshot();
        self.current_task_obs = latest_user_message_content(&task_messages).and_then(|content| {
            observe_cli_user_task(
                &self.run_context,
                &self.chat_session.id(),
                content,
                &self.model,
            )
        });

        let prompt_blocks = self.build_prompt_blocks_for_turn(memory_db);
        let request_state = self.chat_session.messages_snapshot();
        let request_messages = match request_messages_with_cli_grounding(
            &self.run_context,
            &self.chat_session.id(),
            self.current_task_obs,
            &request_state,
        ) {
            Ok(messages) => messages,
            Err(err) => {
                self.clear_transient_prompt_options();
                tracing::error!(error = %err, "Failed to build grounded chat request");
                eprintln!("\n\x1b[31mGrounding error: {err}\x1b[0m");
                return Ok(Some(false));
            }
        };
        if let Err(err) =
            check_provider_request_policy(&self.policy_enforcer, &self.model, &request_messages)
        {
            self.clear_transient_prompt_options();
            tracing::warn!(error = %err, "Enterprise policy blocked chat request");
            eprintln!("\n\x1b[31m{err}\x1b[0m");
            return Ok(Some(false));
        }

        let effort = self
            .transient_effort_override
            .unwrap_or_else(|| self.chat_session.effort_level());
        let request_body = match build_chat_request_body(
            &self.config.proxy.target,
            &request_messages,
            &self.model,
            &prompt_blocks,
            effort.as_str(),
            self.claude_code_token.as_ref(),
        ) {
            Ok(request_body) => request_body,
            Err(err) => {
                self.clear_transient_prompt_options();
                tracing::error!(error = %err, "Failed to build chat request");
                eprintln!("\n\x1b[31mRequest build error: {err}\x1b[0m");
                return Ok(Some(false));
            }
        };
        let provider = match active_provider_for_turn(&self.config) {
            Ok(provider) => provider,
            Err(err) => {
                self.clear_transient_prompt_options();
                tracing::error!(error = %err, "Missing active provider during chat turn");
                eprintln!("\n\x1b[31mRequest configuration error: {err}\x1b[0m");
                return Ok(Some(false));
            }
        };
        let (endpoint, headers) = build_chat_endpoint_and_headers(
            &self.config.proxy.target,
            &self.model,
            provider,
            self.adapter,
            self.api_key.as_ref(),
            self.claude_code_token.as_ref(),
        );

        let transport = TurnTransport {
            endpoint: &endpoint,
            headers: &headers,
        };
        let exit = self
            .send_and_process_turn(
                transport,
                request_body,
                &prompt_blocks,
                memory_db,
                auto_learner,
            )
            .await;

        self.clear_transient_prompt_options();
        save_session_to_short_term_memory(&self.chat_session, memory_db);
        maybe_auto_compact(&mut self.chat_session, &self.model);
        Ok(if exit { Some(true) } else { None })
    }

    /// Save a `#`-prefixed comment as a note message (not sent to AI).
    fn save_note_message(&mut self, input: &str) {
        let note = input.trim_start_matches('#').trim();
        if note.is_empty() {
            return;
        }
        self.chat_session.push_message(serde_json::json!({
            "role": "system",
            "content": format!("[Note: {}]", note),
            "metadata": { "type": "note" }
        }));
        self.chat_session.touch();
        if let Err(e) = save_chat_session(&self.chat_session) {
            tracing::warn!("Failed to save session: {}", e);
        }
        println!("Note saved.\n");
    }

    /// Dispatch a slash-prefixed input to the slash handler and act on
    /// the result. Mutates `input` when a skill rewrites it. Returns
    /// the [`SlashOutcome`] for `process_line`.
    fn dispatch_slash(
        &mut self,
        input: &mut String,
        memory_db: Option<&memory::MemoryDb>,
    ) -> SlashOutcome {
        let doctor_runtime = input.trim().eq_ignore_ascii_case("/doctor").then(|| {
            let manager = openclaudia::mcp::registered_manager(&self.run_context);
            let mut snapshot = openclaudia::doctor::DoctorRuntimeSnapshot::from_run_with_mcp(
                &self.run_context,
                manager.as_ref(),
            )
            .with_composed_provider_transport(&self.client, self.adapter)
            .with_composed_plugin_manager(&self.plugin_manager);
            if let Some(store) = memory_db {
                snapshot = snapshot.with_composed_memory_store(store);
            }
            snapshot
        });
        let result = self.chat_session.update_messages(|messages| {
            handle_slash_command_for_runtime(
                input,
                messages,
                &self.config.proxy.target,
                &self.model,
                &self.run_context,
                &self.config,
                doctor_runtime.as_ref(),
            )
        });
        let Some(result) = result else {
            return SlashOutcome::FallThrough;
        };
        match result {
            SlashCommandResult::Exit => {
                save_session_to_short_term_memory(&self.chat_session, memory_db);
                SlashOutcome::Break
            }
            SlashCommandResult::Clear => {
                save_session_to_short_term_memory(&self.chat_session, memory_db);
                let fresh = fresh_repl_session_in_run(
                    &self.chat_session,
                    &self.model,
                    &self.config.proxy.target,
                );
                if let Err(error) = self.apply_session_transition(&fresh) {
                    eprintln!("Could not start a new session: {error}");
                }
                SlashOutcome::Continue
            }
            SlashCommandResult::LoadSession(sid) => {
                match load_chat_session(&sid) {
                    Ok(Some(loaded)) => match self.apply_session_transition(&loaded) {
                        Ok(()) => println!(
                            "Loaded {} messages from previous session.\n",
                            self.chat_session.message_count()
                        ),
                        Err(error) => eprintln!("Failed to activate session {sid}: {error}"),
                    },
                    Ok(None) => {
                        eprintln!("Session {sid} was not found.");
                    }
                    Err(e) => {
                        eprintln!("Failed to load session {sid}: {e}");
                    }
                }
                SlashOutcome::Continue
            }
            SlashCommandResult::Export => {
                export_chat_session(&self.chat_session);
                SlashOutcome::Continue
            }
            SlashCommandResult::Compact { instructions } => {
                let (before, after) = compact_chat_session_with_instructions(
                    &mut self.chat_session,
                    instructions.as_deref(),
                );
                if before != after {
                    println!("\nCompacted: ~{before} tokens -> ~{after} tokens\n");
                    if let Err(e) = save_chat_session(&self.chat_session) {
                        tracing::warn!("Failed to save compacted session: {}", e);
                    }
                }
                SlashOutcome::Continue
            }
            other => self.dispatch_slash_rest(input, other, memory_db),
        }
    }

    fn apply_session_transition(&mut self, loaded: &Session) -> Result<(), String> {
        let next_run =
            derive_repl_session_run(&self.run_context, loaded, &self.config.proxy.target)?;
        let next_audit = openclaudia::session::AuditLogger::new(&loaded.id())
            .map_err(|error| format!("cannot initialize session audit log: {error}"))?;
        let permission_bypass = self.chat_session.permission_bypass_enabled();
        guardrails::configure(&next_run, &self.config.guardrails)?;

        self.clear_transient_prompt_options();
        tools::retire_run(&self.run_context);
        self.chat_session.apply_loaded(loaded);
        self.chat_session.set_permission_bypass(permission_bypass);
        self.model.clone_from(&loaded.model);
        self.run_context = next_run;
        self.permission_mgr =
            init_permission_manager(&self.config, permission_bypass, &self.run_context);
        self.audit_logger = next_audit;
        self.current_task_obs = None;
        self.permissions = openclaudia::permissions::LocalApprovalCache::for_run(&self.run_context);
        Ok(())
    }

    /// Tail of [`Self::dispatch_slash`] — kept separate so neither
    /// branch trips the `clippy::too_many_lines` limit.
    fn dispatch_slash_rest(
        &mut self,
        input: &mut String,
        result: SlashCommandResult,
        memory_db: Option<&memory::MemoryDb>,
    ) -> SlashOutcome {
        match result {
            SlashCommandResult::EditorInput(editor_content) => {
                self.handle_editor_input(editor_content)
            }
            SlashCommandResult::Undo => {
                self.handle_history_action(true);
                SlashOutcome::Continue
            }
            SlashCommandResult::Redo => {
                self.handle_history_action(false);
                SlashOutcome::Continue
            }
            SlashCommandResult::Rewind(turns) => {
                self.handle_rewind(turns);
                SlashOutcome::Continue
            }
            SlashCommandResult::TeleportSession { name, messages } => {
                self.handle_teleport(&name, messages);
                SlashOutcome::Continue
            }
            SlashCommandResult::Rename(new_title) => {
                self.handle_rename(&new_title);
                SlashOutcome::Continue
            }
            SlashCommandResult::AddWorkingDir(path) => {
                self.handle_add_working_dir(&path);
                SlashOutcome::Continue
            }
            SlashCommandResult::SideQuestion(question) => {
                let saved = self.chat_session.messages_snapshot();
                self.chat_session
                    .replace_messages(vec![serde_json::json!({"role":"user","content":question})]);
                eprintln!("\x1b[90m[/btw aside — main flow will be restored]\x1b[0m");
                self.chat_session
                    .update_messages(|messages| messages.extend(saved));
                SlashOutcome::FallThrough
            }
            SlashCommandResult::Skill(invocation) => {
                eprintln!("\x1b[36m⚡ Running skill...\x1b[0m");
                self.apply_skill_invocation(input, invocation);
                SlashOutcome::RewrittenPrompt
            }
            SlashCommandResult::Plugin(action) => {
                match action.apply(&mut self.plugin_manager, &self.run_context) {
                    PluginActionOutcome::Handled => SlashOutcome::Continue,
                    PluginActionOutcome::Prompt(invocation) => {
                        eprintln!("\x1b[36m⚡ Running plugin command...\x1b[0m");
                        self.apply_plugin_command_invocation(input, invocation);
                        SlashOutcome::RewrittenPrompt
                    }
                }
            }
            other => self.dispatch_slash_simple(other, memory_db),
        }
    }

    fn apply_plugin_command_invocation(
        &mut self,
        input: &mut String,
        invocation: PluginCommandInvocation,
    ) {
        self.apply_prompt_metadata(
            invocation.allowed_tools.as_deref(),
            invocation.model.as_deref(),
            None,
        );
        *input = invocation.prompt;
    }

    fn apply_skill_invocation(&mut self, input: &mut String, invocation: SkillInvocation) {
        self.apply_prompt_metadata(
            invocation.allowed_tools.as_deref(),
            invocation.model.as_deref(),
            invocation.effort.as_deref(),
        );
        *input = invocation.prompt;
    }

    fn apply_prompt_metadata(
        &mut self,
        allowed_tools: Option<&[String]>,
        model: Option<&str>,
        effort: Option<&str>,
    ) {
        self.transient_allowed_tool_rules = allowed_tool_specs_to_permission_rules(allowed_tools);

        if let Some(model) = model.filter(|model| self.can_use_prompt_model(model)) {
            self.transient_model_restore
                .get_or_insert_with(|| self.model.clone());
            self.model = model.to_string();
            self.chat_session.model.clone_from(&self.model);
        } else if let Some(model) = model {
            tracing::debug!(
                model = %model,
                provider = %self.config.proxy.target,
                "ignoring prompt model hint for a different provider in legacy REPL"
            );
        }

        if let Some(effort) = effort.and_then(normalize_prompt_effort) {
            self.transient_effort_override = Some(effort);
        }
    }

    fn can_use_prompt_model(&self, model: &str) -> bool {
        let detected = openclaudia::proxy::determine_provider(model, &self.config);
        canonical_provider_name(&detected) == canonical_provider_name(&self.config.proxy.target)
    }

    fn clear_transient_prompt_options(&mut self) {
        self.transient_allowed_tool_rules.clear();
        if let Some(model) = self.transient_model_restore.take() {
            self.model = model;
            self.chat_session.model.clone_from(&self.model);
        }
        self.transient_effort_override = None;
    }

    /// Handle the simple state-mutation slash results that share a
    /// `Continue` outcome (toggles, single setters, info displays).
    fn dispatch_slash_simple(
        &mut self,
        result: SlashCommandResult,
        memory_db: Option<&memory::MemoryDb>,
    ) -> SlashOutcome {
        match result {
            SlashCommandResult::SwitchModel(new_model) => {
                self.model = new_model;
                self.chat_session.model.clone_from(&self.model);
            }
            SlashCommandResult::Status => self.print_status(),
            SlashCommandResult::ToggleMode => {
                self.chat_session.toggle_mode();
                println!(
                    "\nSwitched to {} mode: {}\n",
                    self.chat_session.agent_mode().display(),
                    self.chat_session.mode_description()
                );
            }
            SlashCommandResult::Keybindings => display_keybindings(&self.config.keybindings),
            SlashCommandResult::Memory(args) => handle_memory_command(&args, memory_db),
            SlashCommandResult::Activity(args) => {
                handle_activity_command(&args, &self.chat_session.id(), memory_db);
            }
            SlashCommandResult::ThemeChanged(name) => {
                if let Some(theme) = tui::Theme::from_name(&name) {
                    self.active_theme = theme;
                }
            }
            SlashCommandResult::ToggleVim => self.toggle_vim(),
            SlashCommandResult::SetEffort(level) => self
                .chat_session
                .set_effort_level(EffortLevel::parse(&level).unwrap_or(EffortLevel::Medium)),
            SlashCommandResult::CycleEffort => self.cycle_effort(),
            SlashCommandResult::FastMode { effort, model } => {
                apply_fast_mode_result(&mut self.model, &mut self.chat_session, &effort, model);
            }
            SlashCommandResult::SetBehaviorMode(new_mode) => {
                self.chat_session.set_behavior_mode(new_mode);
            }
            // BranchSession plus the five already-handled-in-head variants
            // (Exit/Clear/LoadSession/Export/Compact) plus the catch-all
            // Handled all map to `Continue`.
            _ => {}
        }
        SlashOutcome::Continue
    }

    /// Push an `EditorInput` payload (possibly with `@file` references) as
    /// a fresh user message and reset undo state.
    fn handle_editor_input(&mut self, editor_content: String) -> SlashOutcome {
        let expanded = if editor_content.contains('@') {
            expand_file_references(&self.run_context, &editor_content)
        } else {
            editor_content
        };
        self.chat_session.push_message(serde_json::json!({
            "role": "user",
            "content": expanded
        }));
        self.chat_session.update_title();
        self.chat_session.touch();
        self.chat_session.clear_undo_stack();
        SlashOutcome::EditorMessageAdded
    }

    /// Apply an Undo (`is_undo = true`) or Redo (`is_undo = false`) on the
    /// chat session and persist on success.
    fn handle_history_action(&mut self, is_undo: bool) {
        let (applied, verb, after_word) = if is_undo {
            (self.chat_session.undo(), "Undone", "remaining")
        } else {
            (self.chat_session.redo(), "Redone", "now")
        };
        if applied {
            println!(
                "\n{} last exchange. {} messages {}.\n",
                verb,
                self.chat_session.message_count(),
                after_word
            );
            if let Err(e) = save_chat_session(&self.chat_session) {
                tracing::warn!("Failed to save session: {}", e);
            }
        } else {
            println!("\nNothing to {}.\n", if is_undo { "undo" } else { "redo" });
        }
    }

    /// Rewind multiple conversation turns using the same undo stack as `/undo`.
    fn handle_rewind(&mut self, turns: usize) {
        let rewound = rewind_chat_session(&mut self.chat_session, turns);

        if rewound > 0 {
            println!(
                "\nRewound {rewound} turn(s). {} messages remaining.\n",
                self.chat_session.message_count()
            );
            if let Err(e) = save_chat_session(&self.chat_session) {
                tracing::warn!("Failed to save session: {}", e);
            }
        } else {
            println!("\nNothing to rewind.\n");
        }
    }

    /// Replace the active transcript with a named `/branch` snapshot.
    fn handle_teleport(&mut self, name: &str, messages: Vec<serde_json::Value>) {
        self.chat_session.replace_messages(messages);
        self.chat_session.clear_undo_stack();
        self.chat_session.update_title();
        self.chat_session.touch();

        println!(
            "\nTeleported to branch snapshot '{name}'. {} messages active.\n",
            self.chat_session.message_count()
        );

        if let Err(e) = save_chat_session(&self.chat_session) {
            tracing::warn!("Failed to save session after teleport: {}", e);
        }
    }

    /// Rename the active session and persist the change.
    fn handle_rename(&mut self, new_title: &str) {
        self.chat_session.title.clear();
        self.chat_session.title.push_str(new_title);
        self.chat_session.touch();
        if let Err(e) = save_chat_session(&self.chat_session) {
            tracing::warn!("Failed to save session: {}", e);
        }
        println!("\nSession renamed to: {new_title}\n");
    }

    /// Add a directory to the session's working-dir scope and persist.
    fn handle_add_working_dir(&mut self, path: &std::path::Path) {
        if !self.chat_session.add_working_dir(path.to_path_buf()) {
            println!("\n(Directory already in scope: {})\n", path.display());
        } else if let Err(e) = save_chat_session(&self.chat_session) {
            tracing::warn!("Failed to save session after add-dir: {}", e);
        }
    }

    fn print_status(&self) {
        let tokens = estimate_session_tokens(&self.chat_session);
        let msg_count = self.chat_session.message_count();
        let duration = chrono::Utc::now().signed_duration_since(self.chat_session.created_at);
        let mins = duration.num_minutes();
        println!("\n=== Session Status ===");
        println!(
            "  Session ID: {}...",
            safe_truncate(&self.chat_session.id(), 8)
        );
        println!("  Title:      {}", self.chat_session.title);
        println!("  Provider:   {}", self.chat_session.provider);
        println!("  Model:      {}", self.chat_session.model);
        println!(
            "  Behavior:   {}",
            self.chat_session.behavior_mode().description()
        );
        println!(
            "  Mode:       {} ({})",
            self.chat_session.agent_mode().display(),
            self.chat_session.mode_description()
        );
        println!("  Messages:   {msg_count}");
        println!("  Est tokens: ~{tokens}");
        if let Some(pricing) = session::get_pricing(&self.chat_session.model) {
            let est_input = tokens as u64;
            let usage = openclaudia::session::TokenUsage {
                input_tokens: est_input,
                output_tokens: est_input / 4,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
            };
            // Display cost when pricing is known; on unknown-model we
            // intentionally skip the line rather than show $0.00 (the
            // bug #388 was filed against).
            if let Ok(cost) = session::calculate_cost(&self.chat_session.model, &usage) {
                println!("  Est cost:   ${cost:.4}");
            }
            println!(
                "  Pricing:    ${}/M in, ${}/M out",
                pricing.input_per_million, pricing.output_per_million
            );
        }
        println!("  Duration:   {mins} min");
        println!(
            "  Created:    {}",
            self.chat_session.created_at.format("%Y-%m-%d %H:%M UTC")
        );
        println!("  Theme:      {}", self.active_theme.name);
        println!();
    }

    fn toggle_vim(&mut self) {
        use rustyline::EditMode;

        let next_vim_enabled = !self.vim_enabled;
        let edit_mode = if next_vim_enabled {
            EditMode::Vi
        } else {
            EditMode::Emacs
        };

        let mut next_editor = match new_rustyline_editor(edit_mode) {
            Ok(editor) => editor,
            Err(err) => {
                eprintln!(
                    "Failed to switch editor mode ({err}). Keeping {} mode.",
                    if self.vim_enabled { "Vim" } else { "Emacs" }
                );
                return;
            }
        };

        let _ = next_editor.load_history(&self.history_path);
        self.rl = next_editor;
        self.vim_enabled = next_vim_enabled;
        if self.vim_enabled {
            self.vim_state = VimState::new();
            eprintln!("Vim mode enabled (rustyline Vi mode)");
        } else {
            eprintln!("Vim mode disabled (Emacs mode)");
        }
    }

    fn cycle_effort(&self) {
        let effort = match self.chat_session.effort_level() {
            EffortLevel::Low => EffortLevel::Medium,
            EffortLevel::Medium => EffortLevel::High,
            _ => EffortLevel::Low,
        };
        self.chat_session.set_effort_level(effort);
        let label = match effort {
            EffortLevel::Low => "\x1b[33mlow\x1b[0m (faster, less thorough)",
            EffortLevel::High => "\x1b[32mhigh\x1b[0m (thorough, slower)",
            _ => "\x1b[36mmedium\x1b[0m (balanced)",
        };
        println!("\n\u{2713} Effort set to {label}\n");
    }

    /// Push the user message (with `@file` expansion) and run
    /// `UserPromptSubmit` hooks. Returns `false` if a hook blocked the
    /// turn (caller should `continue` the outer loop).
    async fn prepare_user_message(
        &mut self,
        input: &str,
        auto_learner: &mut Option<openclaudia::auto_learn::AutoLearner<'_>>,
    ) -> bool {
        use openclaudia::hooks::{HookEvent, HookInput};

        let expanded_input = if input.contains('@') {
            expand_file_references(&self.run_context, input)
        } else {
            input.to_string()
        };

        self.chat_session.push_message(serde_json::json!({
            "role": "user",
            "content": expanded_input.clone()
        }));
        self.chat_session.update_title();
        self.chat_session.touch();
        self.chat_session.clear_undo_stack();

        if let Some(ref mut learner) = auto_learner {
            let messages = self.chat_session.messages_snapshot();
            let prev_assistant = messages
                .iter()
                .rev()
                .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("assistant"))
                .and_then(|m| m.get("content").and_then(|c| c.as_str()))
                .map(std::string::ToString::to_string);
            learner.on_user_message(&expanded_input, prev_assistant.as_deref());
        }

        let hook_input = HookInput::for_run(&self.run_context, HookEvent::UserPromptSubmit)
            .with_prompt(&expanded_input);
        let hook_result = self
            .hook_engine
            .run(HookEvent::UserPromptSubmit, &hook_input)
            .await;

        if !hook_result.allowed {
            let reason = hook_result
                .outputs
                .first()
                .and_then(|o| o.reason.clone())
                .unwrap_or_else(|| "Request blocked by hook".to_string());
            eprintln!("\nBlocked: {reason}\n");
            self.record_failed_turn(&format!("UserPromptSubmit hook blocked the turn: {reason}"));
            return false;
        }

        let hook_items = openclaudia::context::hook_result_reference_items(
            &hook_result,
            "user_prompt_submit",
            500,
        );
        if !hook_items.is_empty() {
            let projection = openclaudia::context::ContextProjector::project(
                hook_items,
                openclaudia::context::ContextBudget::default(),
            );
            self.chat_session.update_messages(|messages| {
                projection.append_reference_to_json_messages(messages);
            });
        }
        true
    }

    fn request_messages_with_grounding(&self) -> Result<Vec<serde_json::Value>, String> {
        let session_messages = self.chat_session.messages_snapshot();
        let mut messages = request_messages_with_cli_grounding(
            &self.run_context,
            &self.chat_session.id(),
            self.current_task_obs,
            &session_messages,
        )?;
        let normalized =
            openclaudia::pipeline::normalize_message_tool_arguments_for_history(&mut messages);
        if normalized > 0 {
            tracing::warn!(
                normalized,
                session_id = %self.chat_session.id(),
                "normalized malformed historical tool-call arguments before provider request"
            );
        }
        Ok(messages)
    }

    fn followup_request_policy_allows(&self, context: &'static str) -> bool {
        let request_messages = match self.request_messages_with_grounding() {
            Ok(messages) => messages,
            Err(e) => {
                tracing::error!(error = %e, context, "Failed to build grounded follow-up request");
                eprintln!("\n\x1b[31mRequest build error: {e}\x1b[0m");
                return false;
            }
        };
        match check_provider_request_policy(&self.policy_enforcer, &self.model, &request_messages) {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!(error = %err, context, "Enterprise policy blocked follow-up request");
                eprintln!("\n\x1b[31m{err}\x1b[0m");
                false
            }
        }
    }

    fn current_grounding_system_content(&self) -> Option<String> {
        self.current_task_obs.and_then(|task_obs| {
            cli_grounding_system_content(&self.run_context, &self.chat_session.id(), task_obs)
        })
    }

    fn policy_denied_tool_result(&self, tool_call: &tools::ToolCall) -> Option<tools::ToolResult> {
        let session_id = self.chat_session.id();
        let tool_policy = openclaudia::services::policy::ToolExecutionPolicy::new(
            Some(self.policy_enforcer.as_ref()),
            Some(&session_id),
        );
        tool_policy
            .check_tool(&tool_call.function.name)
            .err()
            .map(|err| {
                tools::ToolResult::failure(
                    tool_call,
                    tools::ToolFailureCode::PolicyDenied,
                    format!("Blocked by policy: {err}"),
                    tools::ToolRetryability::Never,
                )
            })
    }

    async fn pre_tool_use_denied_tool_result(
        &self,
        tool_call: &tools::ToolCall,
        tool_args: &serde_json::Value,
    ) -> Option<tools::ToolResult> {
        openclaudia::services::tool_executor::ToolExecutor::run_pre_tool_use(
            &self.run_context,
            &self.hook_engine,
            Some(&self.chat_session.id()),
            &tool_call.function.name,
            tool_args,
        )
        .await
        .err()
        .map(|blocked| blocked.into_tool_result(tool_call))
    }

    fn render_final_response(&self, content: &str, cancelled: bool) -> Option<String> {
        if !final_response_requires_grounding(content, cancelled) {
            return Some(content.to_string());
        }
        match validate_and_render_cli_agentic_final_response(
            &self.run_context,
            &self.chat_session.id(),
            content.trim(),
            &self.model,
        ) {
            Ok(rendered) => Some(rendered),
            Err(reason) => {
                eprintln!("\n\x1b[31mFinal answer failed grounding gate: {reason}\x1b[0m");
                None
            }
        }
    }

    fn record_failed_turn(&mut self, reason: &str) {
        self.chat_session.update_messages(|messages| {
            session::append_failed_turn_message(messages, reason);
        });
        persist_chat_session_update(&mut self.chat_session, "failed turn marker");
    }

    /// Build Claudia's typed, bounded prompt context for this turn.
    fn build_prompt_blocks_for_turn(
        &self,
        memory_db: Option<&memory::MemoryDb>,
    ) -> prompt::SystemPromptBlocks {
        let messages = self.chat_session.messages_snapshot();
        let behavior_mode = self.chat_session.behavior_mode();
        let mut additional_items = Vec::new();

        if self.coordinator {
            additional_items.push(openclaudia::context::ContextItem::host_instruction(
                "repl.coordinator_policy",
                openclaudia::context::HostInstructionSource::CoordinatorPolicy,
                "host:coordinator-role",
                openclaudia::subagent::AgentType::Coordinator.system_prompt(),
                openclaudia::context::ContextFreshness::Static,
                5,
            ));
        }

        if let Some(db) = memory_db {
            let mut injected_files: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for msg in messages.iter().rev().take(10) {
                if let Some(role) = msg.get("role").and_then(|r| r.as_str()) {
                    if role == "tool" || role == "assistant" {
                        if let Some(tool_calls) = msg.get("tool_calls").and_then(|t| t.as_array()) {
                            for tc in tool_calls {
                                let name = tc
                                    .get("function")
                                    .and_then(|f| f.get("name"))
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("");
                                if matches!(name, "read_file" | "edit_file" | "write_file") {
                                    if let Some(args_str) = tc
                                        .get("function")
                                        .and_then(|f| f.get("arguments"))
                                        .and_then(|a| a.as_str())
                                    {
                                        if let Ok(args) =
                                            serde_json::from_str::<serde_json::Value>(args_str)
                                        {
                                            if let Some(path) = args
                                                .get("path")
                                                .or_else(|| args.get("file_path"))
                                                .and_then(|p| p.as_str())
                                            {
                                                injected_files.insert(path.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            let mut injected_files: Vec<String> = injected_files.into_iter().collect();
            injected_files.sort();
            for (index, file_path) in injected_files.iter().take(3).enumerate() {
                if let Ok(knowledge) = db.format_file_knowledge(file_path) {
                    if !knowledge.is_empty() {
                        additional_items.push(openclaudia::context::ContextItem::reference(
                            format!("memory.file_knowledge.{index}"),
                            openclaudia::context::ReferenceSource::Memory,
                            format!("memory-db:file:{file_path}"),
                            knowledge,
                            openclaudia::context::ContextFreshness::Turn,
                            320,
                        ));
                    }
                }
            }
        }
        prompt::build_prompt_context_with_items_for_run(
            &behavior_mode,
            memory_db,
            &self.run_context,
            additional_items,
            openclaudia::context::ContextBudget::default(),
        )
    }

    /// Send the initial turn request and dispatch the response to the
    /// provider-specific handler. Returns `true` when streaming
    /// keybindings asked the REPL to exit.
    async fn send_and_process_turn(
        &mut self,
        transport: TurnTransport<'_>,
        request_body: serde_json::Value,
        prompt_blocks: &prompt::SystemPromptBlocks,
        memory_db: Option<&memory::MemoryDb>,
        auto_learner: &mut Option<openclaudia::auto_learn::AutoLearner<'_>>,
    ) -> bool {
        use indicatif::{ProgressBar, ProgressStyle};
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .template(SPINNER_TMPL)
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        spinner.set_message("Connecting...");
        spinner.enable_steady_tick(std::time::Duration::from_millis(80));

        let req = match transport
            .headers
            .apply(self.client.post(transport.endpoint).json(&request_body))
        {
            Ok(request) => request,
            Err(error) => {
                spinner.finish_and_clear();
                eprintln!("\nProvider header error: {error}\n");
                self.record_failed_turn(&format!("provider header error: {error}"));
                return false;
            }
        };

        match req.send().await {
            Ok(response) => {
                spinner.finish_and_clear();
                if !response.status().is_success() {
                    self.handle_failed_response(response, transport.headers)
                        .await;
                    return false;
                }
                if self.config.proxy.target == "google" {
                    self.process_google_response(
                        response,
                        &request_body,
                        transport,
                        memory_db,
                        auto_learner,
                    )
                    .await;
                    false
                } else {
                    self.process_streaming_response(
                        response,
                        transport,
                        prompt_blocks,
                        memory_db,
                        auto_learner,
                    )
                    .await
                }
            }
            Err(e) => {
                spinner.finish_and_clear();
                eprintln!("\nRequest failed: {e}\n");
                self.record_failed_turn(&format!("request failed: {e}"));
                false
            }
        }
    }

    /// Read body of a non-2xx response, print user-friendly error, and
    /// record a failed-turn marker.
    async fn handle_failed_response(
        &mut self,
        response: reqwest::Response,
        headers: &openclaudia::secrets::SensitiveHeaders,
    ) {
        let status = response.status();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = openclaudia::secrets::read_bounded_diagnostic_body(response)
            .await
            .unwrap_or_else(|_| zeroize::Zeroizing::new(String::new()));
        if content_type.contains("text/html") {
            eprintln!("\nError {status}: (HTML response — check your provider configuration)\n");
            self.record_failed_turn(&format!(
                "HTTP {status}: HTML response; check provider configuration"
            ));
        } else {
            let diagnostic = headers.sanitize_diagnostic(&body);
            eprintln!("\nError {status}: {diagnostic}\n");
            self.record_failed_turn(&format!("HTTP {status}: {diagnostic}"));
        }
    }

    /// Google Gemini path: non-streaming JSON response + native
    /// `functionCall` / `functionResponse` tool loop.
    async fn process_google_response(
        &mut self,
        response: reqwest::Response,
        request_body: &serde_json::Value,
        transport: TurnTransport<'_>,
        memory_db: Option<&memory::MemoryDb>,
        auto_learner: &mut Option<openclaudia::auto_learn::AutoLearner<'_>>,
    ) {
        println!();
        let body = zeroize::Zeroizing::new(response.text().await.unwrap_or_default());
        let Some(gemini_json) = self.parse_gemini_initial_body(&body, transport.headers) else {
            return;
        };

        let (full_content, tool_calls) =
            match Self::emit_gemini_initial_text_and_calls(&gemini_json) {
                Ok(parsed) => parsed,
                Err(e) => {
                    let diagnostic = transport.headers.sanitize_diagnostic(&e);
                    eprintln!("\nInvalid Gemini response: {diagnostic}");
                    self.record_failed_turn(&format!("invalid Gemini response: {diagnostic}"));
                    return;
                }
            };
        let (input_tokens, output_tokens) = gemini_extract_usage_tokens(&gemini_json);

        if let Err(e) = self.audit_logger.log(
            "model_response",
            &serde_json::json!({
                "model": &self.model,
                "content_length": full_content.len(),
                "tool_calls": tool_calls.len(),
                "cancelled": false,
            }),
        ) {
            tracing::warn!("Audit log failed for model_response: {e}");
        }

        let contents: Vec<serde_json::Value> = serde_json::from_value(
            request_body
                .get("contents")
                .cloned()
                .unwrap_or(serde_json::json!([])),
        )
        .unwrap_or_default();

        let mut state = GeminiLoopState {
            full_content,
            tool_calls,
            contents,
        };
        self.run_gemini_tool_loop(&mut state, request_body, transport, memory_db, auto_learner)
            .await;

        self.finalize_gemini_response(&state.full_content, input_tokens, output_tokens)
            .await;
    }

    /// Parse the Gemini HTTP body to JSON, or print an error and record
    /// a failed-turn marker on failure.
    fn parse_gemini_initial_body(
        &mut self,
        body: &str,
        headers: &openclaudia::secrets::SensitiveHeaders,
    ) -> Option<serde_json::Value> {
        match serde_json::from_str::<serde_json::Value>(body) {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!("\nFailed to parse Gemini response: {e}");
                eprintln!("Response body: {}", headers.sanitize_diagnostic(body));
                self.record_failed_turn(&format!("failed to parse Gemini response: {e}"));
                None
            }
        }
    }

    /// Return the assembled Gemini `(full_content, tool_calls)` pair.
    /// Terminal text stays buffered until the final evidence gate runs.
    fn emit_gemini_initial_text_and_calls(
        gemini_json: &serde_json::Value,
    ) -> Result<(String, Vec<tools::ToolCall>), String> {
        let mut full_content = String::new();
        let text = gemini_extract_text(gemini_json)?;
        let tool_calls = gemini_extract_tool_calls(gemini_json)?;
        if !text.is_empty() {
            full_content.push_str(&text);
        }
        Ok((full_content, tool_calls))
    }

    /// Drive the Gemini agentic tool loop until no tool calls remain or
    /// the `max_turns` ceiling is reached. Mutates `state` in place.
    async fn run_gemini_tool_loop(
        &mut self,
        state: &mut GeminiLoopState,
        request_body: &serde_json::Value,
        transport: TurnTransport<'_>,
        memory_db: Option<&memory::MemoryDb>,
        auto_learner: &mut Option<openclaudia::auto_learn::AutoLearner<'_>>,
    ) {
        let max_iterations = self.config.session.max_turns;
        let mut iteration: u32 = 0;
        while !state.tool_calls.is_empty() && (max_iterations == 0 || iteration < max_iterations) {
            iteration += 1;
            self.gemini_record_model_turn(
                &state.full_content,
                &state.tool_calls,
                &mut state.contents,
            );
            let function_responses = self
                .gemini_execute_tools(&state.tool_calls, memory_db, auto_learner)
                .await;
            state.contents.push(serde_json::json!({
                "role": "user",
                "parts": function_responses
            }));
            println!(
                "\n\x1b[90m(Sending {} tool result{} to Gemini...)\x1b[0m",
                state.tool_calls.len(),
                if state.tool_calls.len() == 1 { "" } else { "s" }
            );
            if !self.followup_request_policy_allows("gemini follow-up") {
                break;
            }
            match self
                .gemini_send_followup(&state.contents, request_body, transport)
                .await
            {
                Some((next_text, next_calls)) => {
                    state.full_content = next_text;
                    state.tool_calls = next_calls;
                }
                None => break,
            }
        }
        // #601 — Gemini path previously bailed silently when the
        // `max_turns` ceiling was reached. Emit a structured
        // `error_max_turns` result event so SDK/MCP consumers see a
        // typed signal, matching CC's QueryEngine.ts:851-873 behaviour.
        if max_iterations > 0 && iteration >= max_iterations && !state.tool_calls.is_empty() {
            let _ = emit_max_turns_event(
                &self.chat_session.id(),
                "google_gemini",
                max_iterations,
                iteration,
            );
            eprintln!(
                "\n\x1b[33m⚠ Reached max_turns limit ({max_iterations} turns). Configure session.max_turns in config.yaml (0 = unlimited).\x1b[0m"
            );
        }
    }

    /// Persist the final Gemini message, run VDD review, draw the status
    /// bar, and emit the trailing newline.
    async fn finalize_gemini_response(
        &mut self,
        full_content: &str,
        input_tokens: u64,
        output_tokens: u64,
    ) {
        let rendered_content = if full_content.trim().is_empty() {
            String::new()
        } else {
            let Some(rendered) = self.render_final_response(full_content.trim(), false) else {
                return;
            };
            println!("{rendered}");
            push_chat_session_message_and_persist(
                &mut self.chat_session,
                serde_json::json!({
                    "role": "assistant",
                    "content": rendered
                }),
                "gemini final assistant response",
            );
            rendered
        };

        if let Some(ref engine) = self.vdd_engine {
            let original = self.chat_session.messages_snapshot();
            let mut messages = original.clone();
            run_vdd_review(
                engine,
                &self.run_context,
                &rendered_content,
                &mut messages,
                &self.config.proxy.target,
                self.api_key.as_ref(),
            )
            .await;
            if messages != original {
                self.chat_session.replace_messages(messages);
                persist_chat_session_update(&mut self.chat_session, "gemini VDD context injection");
            }
        }

        let tokens = estimate_session_tokens(&self.chat_session) + rendered_content.len() / 4;
        // `draw_status_bar` accepts `Option<f64>` and elides the cost
        // segment when None; an unknown model therefore renders as a
        // blank cost rather than $0.00.
        let cost = session::calculate_cost(
            &self.model,
            &openclaudia::session::TokenUsage {
                input_tokens: input_tokens.max(tokens as u64),
                output_tokens: output_tokens.max(rendered_content.len() as u64 / 4),
                cache_read_tokens: 0,
                cache_write_tokens: 0,
            },
        )
        .ok();
        let duration = chrono::Utc::now().signed_duration_since(self.chat_session.created_at);
        let dur_str = format!("{}m", duration.num_minutes());
        tui::draw_status_bar(
            &self.model,
            tokens,
            cost,
            self.chat_session.agent_mode().display(),
            &dur_str,
        );
        println!();
    }

    /// Record the model's tool-call turn into both `gemini_contents`
    /// (native format) and the canonical session conversation (`OpenAI` format).
    fn gemini_record_model_turn(
        &mut self,
        full_content: &str,
        gemini_tool_calls: &[tools::ToolCall],
        gemini_contents: &mut Vec<serde_json::Value>,
    ) {
        let model_parts: Vec<serde_json::Value> = {
            let mut parts = Vec::new();
            if !full_content.is_empty() {
                parts.push(serde_json::json!({"text": full_content}));
            }
            for tc in gemini_tool_calls {
                let args: serde_json::Value = serde_json::from_str(&tc.function.arguments)
                    .unwrap_or_else(|_| serde_json::json!({}));
                parts.push(serde_json::json!({
                    "functionCall": {
                        "name": tc.function.name,
                        "args": args
                    }
                }));
            }
            parts
        };
        gemini_contents.push(serde_json::json!({
            "role": "model",
            "parts": model_parts
        }));

        let tool_calls_json: Vec<serde_json::Value> = gemini_tool_calls
            .iter()
            .map(|tc| {
                serde_json::json!({
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments
                    }
                })
            })
            .collect();
        push_chat_session_message_and_persist(
            &mut self.chat_session,
            serde_json::json!({
                "role": "assistant",
                "content": serde_json::Value::String(full_content.to_string()),
                "tool_calls": tool_calls_json
            }),
            "gemini tool-call assistant turn",
        );
    }

    /// Execute each tool call from a Gemini turn and produce the
    /// `functionResponse` parts to send back.
    async fn gemini_execute_tools(
        &mut self,
        gemini_tool_calls: &[tools::ToolCall],
        memory_db: Option<&memory::MemoryDb>,
        auto_learner: &mut Option<openclaudia::auto_learn::AutoLearner<'_>>,
    ) -> Vec<serde_json::Value> {
        let mut function_responses: Vec<serde_json::Value> = Vec::new();
        for tool_call in gemini_tool_calls {
            if let Some(blocked) = self.gemini_plan_mode_response(tool_call) {
                function_responses.push(blocked);
                continue;
            }
            let authorization = match self.gemini_permission_error_response(tool_call).await {
                Ok(authorization) => authorization,
                Err(blocked) => {
                    function_responses.push(blocked);
                    continue;
                }
            };
            let result =
                self.gemini_run_single_tool(tool_call, memory_db, auto_learner, authorization);
            function_responses.push(self.gemini_record_tool_outcome(tool_call, &result).await);
        }
        function_responses
    }

    /// If the tool is blocked by plan mode, push an error tool message
    /// into the session and return the matching `functionResponse`. None
    /// means the tool may proceed.
    fn gemini_plan_mode_response(
        &mut self,
        tool_call: &tools::ToolCall,
    ) -> Option<serde_json::Value> {
        let block_msg = check_plan_mode_restriction(
            &self.chat_session,
            &tool_call.function.name,
            &tool_call.function.arguments,
        )?;
        println!(
            "\n\x1b[33m⚠ Blocked in plan mode: {}\x1b[0m",
            tool_call.function.name
        );
        push_observed_cli_tool_result_message(
            &self.run_context,
            &mut self.chat_session,
            tool_call,
            &tool_call.id,
            &block_msg,
            true,
        );
        Some(serde_json::json!({
            "functionResponse": {
                "name": tool_call.function.name,
                "response": {"error": block_msg}
            }
        }))
    }

    /// Run the interactive permission check for a Gemini tool call.
    /// Returns a `functionResponse` error when the caller should not execute it.
    async fn gemini_permission_error_response(
        &mut self,
        tool_call: &tools::ToolCall,
    ) -> Result<Option<ExecutionPermit>, serde_json::Value> {
        let tool_args_val = match parse_tool_args(&tool_call.function) {
            Ok(args) => args,
            Err(msg) => {
                push_observed_cli_tool_result_message(
                    &self.run_context,
                    &mut self.chat_session,
                    tool_call,
                    &tool_call.id,
                    &msg,
                    true,
                );
                return Err(gemini_tool_error_response(tool_call, &msg));
            }
        };
        if let Some(result) = self
            .pre_tool_use_denied_tool_result(tool_call, &tool_args_val)
            .await
        {
            push_observed_cli_typed_tool_result_message(
                &self.run_context,
                &mut self.chat_session,
                tool_call,
                &result,
            );
            return Err(gemini_tool_error_response(tool_call, result.content()));
        }
        if let Some(result) = self.policy_denied_tool_result(tool_call) {
            push_observed_cli_typed_tool_result_message(
                &self.run_context,
                &mut self.chat_session,
                tool_call,
                &result,
            );
            return Err(gemini_tool_error_response(tool_call, result.content()));
        }
        let result = check_tool_permission_interactive(
            tool_call,
            &self.chat_session.id(),
            &self.permission_mgr,
            &self.transient_allowed_tool_rules,
        );
        match result {
            ToolPermissionResult::Allowed { authorization } => Ok(authorization),
            ToolPermissionResult::Denied(msg) => {
                push_observed_cli_tool_result_message(
                    &self.run_context,
                    &mut self.chat_session,
                    tool_call,
                    &tool_call.id,
                    &msg,
                    true,
                );
                Err(gemini_tool_error_response(tool_call, &msg))
            }
        }
    }

    /// Dispatch the tool, observe it for auto-learning, and return the
    /// raw `ToolResult` for downstream recording.
    fn gemini_run_single_tool(
        &mut self,
        tool_call: &tools::ToolCall,
        memory_db: Option<&memory::MemoryDb>,
        auto_learner: &mut Option<openclaudia::auto_learn::AutoLearner<'_>>,
        authorization: Option<ExecutionPermit>,
    ) -> tools::ToolResult {
        println!("\n\x1b[36m⚡ Running {}...\x1b[0m", tool_call.function.name);
        if let Err(e) = self.audit_logger.log_security(
            "tool_call",
            &serde_json::json!({
                "name": &tool_call.function.name,
                "arguments": &tool_call.function.arguments,
                "id": &tool_call.id,
            }),
        ) {
            // log_security already emitted tracing::error!; surface to stderr
            // so the user sees the failure mid-session, but continue (the
            // session itself is not corrupted by an audit-write failure).
            tracing::error!("Security audit failed for tool_call: {e}");
        }

        let result = execute_tool_with_memory_after_permission(
            &self.run_context,
            tool_call,
            memory_db,
            &self.permission_mgr,
            authorization,
            &self.chat_session.id(),
            Some(self.policy_enforcer.as_ref()),
        );
        Self::auto_learn_observe(auto_learner, tool_call, &result);
        result
    }

    /// Render the tool result, push it onto the session as a `tool`
    /// message, and return the `functionResponse` value for Gemini.
    async fn gemini_record_tool_outcome(
        &mut self,
        tool_call: &tools::ToolCall,
        result: &tools::ToolResult,
    ) -> serde_json::Value {
        let final_result = process_tool_follow_up(&self.run_context, &self.chat_session, result);
        let final_content = final_result.content();
        let final_is_error = final_result.is_error();
        let tool_input = parse_tool_args(&tool_call.function).unwrap_or_else(
            |_| serde_json::json!({ "raw_arguments": tool_call.function.arguments }),
        );
        openclaudia::services::tool_executor::ToolExecutor::fire_post_tool(
            &self.run_context,
            &self.hook_engine,
            !final_is_error,
            &tool_call.function.name,
            tool_input,
            final_content,
            Some(&self.chat_session.id()),
        )
        .await;
        display_tool_result(&final_result);
        push_observed_cli_typed_tool_result_message(
            &self.run_context,
            &mut self.chat_session,
            tool_call,
            &final_result,
        );

        let response = serde_json::json!({
            "functionResponse": {
                "id": final_result.tool_call_id(),
                "name": tool_call.function.name,
                "response": final_result.model_payload()
            }
        });
        response
    }

    /// Send the next Gemini turn with tool results. Returns the new
    /// (text, `tool_calls`) on success, `None` on transport / parse error.
    async fn gemini_send_followup(
        &self,
        gemini_contents: &[serde_json::Value],
        request_body: &serde_json::Value,
        transport: TurnTransport<'_>,
    ) -> Option<(String, Vec<tools::ToolCall>)> {
        let openai_tools = tools::get_all_tool_definitions(true);
        let functions = match openai_tools
            .as_array()
            .ok_or_else(|| "built-in tool definitions must be a JSON array".to_string())
            .and_then(|tools_vec| {
                convert_tools_to_gemini_functions(tools_vec).map_err(|e| e.to_string())
            }) {
            Ok(functions) => functions,
            Err(error) => {
                tracing::error!(
                    error = %error,
                    "failed to convert built-in tools to Gemini function declarations"
                );
                return None;
            }
        };

        let mut grounded_contents = gemini_contents.to_vec();
        if let Some(grounding) = self.current_grounding_system_content() {
            let projection = openclaudia::context::ContextProjector::project(
                vec![openclaudia::context::ContextItem::reference(
                    "reality.grounding",
                    openclaudia::context::ReferenceSource::Reality,
                    "reality-ledger:current-task",
                    grounding,
                    openclaudia::context::ContextFreshness::Turn,
                    800,
                )],
                openclaudia::context::ContextBudget::default(),
            );
            grounded_contents.push(serde_json::json!({
                "role": "user",
                "parts": [{"text": projection.reference}]
            }));
        }
        let mut followup_req = serde_json::json!({
            "contents": grounded_contents,
            "generationConfig": {"maxOutputTokens": 4096},
            "tools": [{"functionDeclarations": functions}]
        });
        if let Some(sys) = request_body.get("systemInstruction") {
            followup_req["systemInstruction"] = sys.clone();
        }

        let req = match transport
            .headers
            .apply(self.client.post(transport.endpoint).json(&followup_req))
        {
            Ok(request) => request,
            Err(error) => {
                eprintln!("\nProvider header error: {error}");
                return None;
            }
        };
        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                let resp_body = zeroize::Zeroizing::new(resp.text().await.unwrap_or_default());
                let Ok(resp_json) = serde_json::from_str::<serde_json::Value>(&resp_body) else {
                    eprintln!("\nFailed to parse Gemini follow-up response");
                    return None;
                };
                let text = match gemini_extract_text(&resp_json) {
                    Ok(text) => text,
                    Err(e) => {
                        eprintln!(
                            "\nInvalid Gemini follow-up response: {}",
                            transport.headers.sanitize_diagnostic(&e)
                        );
                        return None;
                    }
                };
                let calls = match gemini_extract_tool_calls(&resp_json) {
                    Ok(calls) => calls,
                    Err(e) => {
                        eprintln!(
                            "\nInvalid Gemini follow-up tool call response: {}",
                            transport.headers.sanitize_diagnostic(&e)
                        );
                        return None;
                    }
                };
                Some((text, calls))
            }
            Ok(resp) => {
                let status = resp.status();
                let err_body = openclaudia::secrets::read_bounded_diagnostic_body(resp)
                    .await
                    .unwrap_or_else(|_| zeroize::Zeroizing::new(String::new()));
                let diagnostic = transport.headers.sanitize_diagnostic(&err_body);
                eprintln!("\nGemini follow-up failed: {status} {diagnostic}");
                None
            }
            Err(e) => {
                eprintln!("\nGemini follow-up error: {e}");
                None
            }
        }
    }

    /// Anthropic / `OpenAI` SSE streaming path. Returns `true` when a
    /// keybinding pressed during streaming asked the REPL to exit.
    async fn process_streaming_response(
        &mut self,
        response: reqwest::Response,
        transport: TurnTransport<'_>,
        prompt_blocks: &prompt::SystemPromptBlocks,
        memory_db: Option<&memory::MemoryDb>,
        auto_learner: &mut Option<openclaudia::auto_learn::AutoLearner<'_>>,
    ) -> bool {
        println!();
        let mut tool_accumulator = tools::ToolCallAccumulator::new();
        let mut anthropic_accumulator = tools::AnthropicToolAccumulator::new();
        let mut stream_usage = openclaudia::session::TokenUsage::default();

        if let Err(e) = self.audit_logger.log(
            "model_request",
            &serde_json::json!({
                "model": &self.model,
                "provider": &self.config.proxy.target,
            }),
        ) {
            tracing::warn!("Audit log failed for model_request: {e}");
        }

        let stream_result = self
            .consume_initial_stream(
                response,
                &mut tool_accumulator,
                &mut anthropic_accumulator,
                &mut stream_usage,
            )
            .await;

        let mut full_content = stream_result.full_content;
        let reasoning_content = stream_result.reasoning_content;
        let cancelled = stream_result.cancelled;
        let pending_action = stream_result.pending_action;
        println!();

        self.log_streaming_completion(&full_content, cancelled, &stream_usage);
        self.draw_stream_status_bar(&full_content, &stream_usage);

        if cancelled && !full_content.is_empty() {
            full_content.push_str("\n\n[Response interrupted by user]");
        }

        if self.config.proxy.target.eq_ignore_ascii_case("anthropic") && !cancelled {
            self.dispatch_anthropic_tool_path(
                &mut anthropic_accumulator,
                full_content,
                transport,
                prompt_blocks,
                memory_db,
                auto_learner,
            )
            .await;
            return false;
        }

        self.run_openai_tool_loop(
            &mut tool_accumulator,
            OpenAiLoopState {
                current_content: full_content,
                current_reasoning_content: reasoning_content,
                cancelled,
            },
            transport,
            prompt_blocks,
            memory_db,
            auto_learner,
        )
        .await;

        self.handle_pending_action(pending_action)
    }

    /// Emit the `model_response` audit event for the initial stream.
    fn log_streaming_completion(
        &mut self,
        full_content: &str,
        cancelled: bool,
        stream_usage: &openclaudia::session::TokenUsage,
    ) {
        if let Err(e) = self.audit_logger.log(
            "model_response",
            &serde_json::json!({
                "model": &self.model,
                "content_length": full_content.len(),
                "cancelled": cancelled,
                "stream_usage": {
                    "input_tokens": stream_usage.input_tokens,
                    "output_tokens": stream_usage.output_tokens,
                },
            }),
        ) {
            tracing::warn!("Audit log failed for model_response: {e}");
        }
    }

    /// Compute cost + tokens for the initial stream and render the
    /// status bar.
    fn draw_stream_status_bar(
        &self,
        full_content: &str,
        stream_usage: &openclaudia::session::TokenUsage,
    ) {
        let tokens = estimate_session_tokens(&self.chat_session) + full_content.len() / 4;
        // Status bar accepts `Option<f64>`; unknown-model resolves to
        // None and the cost segment is omitted.
        let cost = session::calculate_cost(
            &self.model,
            &openclaudia::session::TokenUsage {
                input_tokens: tokens as u64,
                output_tokens: stream_usage
                    .output_tokens
                    .max(full_content.len() as u64 / 4),
                cache_read_tokens: stream_usage.cache_read_tokens,
                cache_write_tokens: stream_usage.cache_write_tokens,
            },
        )
        .ok();
        let duration = chrono::Utc::now().signed_duration_since(self.chat_session.created_at);
        let dur_str = format!("{}m", duration.num_minutes());
        tui::draw_status_bar(
            &self.model,
            tokens,
            cost,
            self.chat_session.agent_mode().display(),
            &dur_str,
        );
    }

    /// Run Anthropic's native `tool_use` loop, then VDD review and the
    /// trailing newline. Ordinary assistant text is never scanned for calls.
    async fn dispatch_anthropic_tool_path(
        &mut self,
        anthropic_accumulator: &mut tools::AnthropicToolAccumulator,
        full_content: String,
        transport: TurnTransport<'_>,
        prompt_blocks: &prompt::SystemPromptBlocks,
        memory_db: Option<&memory::MemoryDb>,
        auto_learner: &mut Option<openclaudia::auto_learn::AutoLearner<'_>>,
    ) {
        let final_content = self
            .run_anthropic_structured_tool_loop(
                anthropic_accumulator,
                full_content,
                transport,
                prompt_blocks,
                memory_db,
                auto_learner,
            )
            .await;
        if let Some(ref engine) = self.vdd_engine {
            if final_content.trim().is_empty() {
                println!();
                return;
            }
            let original = self.chat_session.messages_snapshot();
            let mut messages = original.clone();
            run_vdd_review(
                engine,
                &self.run_context,
                &final_content,
                &mut messages,
                &self.config.proxy.target,
                self.api_key.as_ref(),
            )
            .await;
            if messages != original {
                self.chat_session.replace_messages(messages);
                persist_chat_session_update(
                    &mut self.chat_session,
                    "anthropic VDD context injection",
                );
            }
        }
        println!();
    }

    /// Consume the initial SSE stream into bounded accumulators and return the
    /// assembled state. Terminal text stays buffered until final validation.
    async fn consume_initial_stream(
        &self,
        response: reqwest::Response,
        tool_accumulator: &mut tools::ToolCallAccumulator,
        anthropic_accumulator: &mut tools::AnthropicToolAccumulator,
        stream_usage: &mut openclaudia::session::TokenUsage,
    ) -> InitialStreamResult {
        use futures::StreamExt;

        let mut full_content = String::new();
        let mut reasoning_content = String::new();
        let mut stream = response.bytes_stream().eventsource();
        let mut cancelled = false;
        let mut pending_action: Option<SlashCommandResult> = None;

        let mut in_thinking_block = false;
        let mut thinking_start_time: Option<std::time::Instant> = None;
        let mut reasoning_started = false;
        let stream_timeout = std::time::Duration::from_secs(proxy::SSE_STREAM_TIMEOUT_SECS);

        loop {
            if self.poll_stream_keybinding(&mut cancelled, &mut pending_action) {
                break;
            }

            let sse = match tokio::time::timeout(stream_timeout, stream.next()).await {
                Ok(Some(Ok(sse))) => sse,
                Ok(Some(Err(e))) => {
                    eprintln!("\nStream error: {e}");
                    break;
                }
                Ok(None) => break,
                Err(_) => {
                    Self::handle_stream_timeout(&full_content);
                    break;
                }
            };
            if sse.data == "[DONE]" {
                break;
            }

            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&sse.data) {
                let mut ctx = SseFrameCtx {
                    full_content: &mut full_content,
                    reasoning_content: &mut reasoning_content,
                    tool_accumulator,
                    anthropic_accumulator,
                    stream_usage,
                    in_thinking_block: &mut in_thinking_block,
                    thinking_start_time: &mut thinking_start_time,
                    reasoning_started: &mut reasoning_started,
                };
                Self::route_sse_frame(&json, &mut ctx);
            }
        }
        if reasoning_started {
            let elapsed = thinking_start_time.map_or(0.0, |t| t.elapsed().as_secs_f64());
            tui::print_thinking_end(elapsed);
        }
        InitialStreamResult {
            full_content,
            reasoning_content,
            cancelled,
            pending_action,
        }
    }

    /// Print the timeout banner without mutating assistant content.
    fn handle_stream_timeout(full_content: &str) {
        eprintln!(
            "\nStream timeout: no data received for {}s",
            proxy::SSE_STREAM_TIMEOUT_SECS
        );
        if !full_content.is_empty() {
            tracing::warn!(
                content_len = full_content.len(),
                "Stream timed out with partial content; preserving {} bytes",
                full_content.len()
            );
        }
    }

    /// Non-blocking keybinding poll during streaming. Sets `cancelled`
    /// and returns `true` when the user pressed the Cancel binding;
    /// captures any other deferrable action into `pending_action`.
    fn poll_stream_keybinding(
        &self,
        cancelled: &mut bool,
        pending_action: &mut Option<SlashCommandResult>,
    ) -> bool {
        use crossterm::event::{self, Event, KeyEventKind};
        use std::io::Write;

        if !event::poll(std::time::Duration::from_millis(1)).unwrap_or(false) {
            return false;
        }
        let Ok(Event::Key(key_event)) = event::read() else {
            return false;
        };
        if key_event.kind != KeyEventKind::Press {
            return false;
        }
        let Some(key_str) = key_event_to_string(&key_event, false) else {
            return false;
        };
        if !self.config.keybindings.is_bound(&key_str) {
            return false;
        }
        let action = self.config.keybindings.get_action_or_default(&key_str);
        if action == config::KeyAction::Cancel {
            *cancelled = true;
            print!(" (cancelled)");
            std::io::stdout().flush().ok();
            return true;
        }
        if let Some(result) = execute_key_action(&action) {
            *pending_action = Some(result);
        }
        false
    }

    /// Route a single decoded SSE frame: usage extraction, thinking
    /// pass-through, then text/tool delta dispatch.
    fn route_sse_frame(json: &serde_json::Value, ctx: &mut SseFrameCtx<'_>) {
        if let Some(usage) = proxy::extract_usage_from_sse_event(json) {
            ctx.stream_usage.accumulate(&usage);
        }
        match openclaudia::pipeline::process_sse_event(
            json,
            *ctx.in_thinking_block,
            ctx.anthropic_accumulator,
            ctx.tool_accumulator,
        ) {
            openclaudia::pipeline::SseAction::Text(text) => {
                if *ctx.reasoning_started {
                    let elapsed = ctx
                        .thinking_start_time
                        .map_or(0.0, |started| started.elapsed().as_secs_f64());
                    tui::print_thinking_end(elapsed);
                    *ctx.reasoning_started = false;
                    *ctx.thinking_start_time = None;
                }
                ctx.full_content.push_str(&text);
            }
            openclaudia::pipeline::SseAction::Thinking(text) => {
                tui::print_thinking_chunk(&text);
            }
            openclaudia::pipeline::SseAction::Reasoning(text) => {
                let display_text =
                    openclaudia::pipeline::merge_reasoning_delta(ctx.reasoning_content, &text);
                if !display_text.is_empty() {
                    if !*ctx.reasoning_started {
                        *ctx.reasoning_started = true;
                        *ctx.thinking_start_time = Some(std::time::Instant::now());
                        tui::print_thinking_start();
                    }
                    tui::print_thinking_chunk(&display_text);
                }
            }
            openclaudia::pipeline::SseAction::ThinkingStart => {
                *ctx.in_thinking_block = true;
                *ctx.thinking_start_time = Some(std::time::Instant::now());
                tui::print_thinking_start();
            }
            openclaudia::pipeline::SseAction::ThinkingEnd => {
                let elapsed = ctx
                    .thinking_start_time
                    .map_or(0.0, |started| started.elapsed().as_secs_f64());
                tui::print_thinking_end(elapsed);
                *ctx.in_thinking_block = false;
                *ctx.thinking_start_time = None;
            }
            openclaudia::pipeline::SseAction::None => {}
        }
    }

    /// Anthropic structured `tool_use` loop — execute tools and follow-up.
    async fn run_anthropic_structured_tool_loop(
        &mut self,
        anthropic_accumulator: &mut tools::AnthropicToolAccumulator,
        mut full_content: String,
        transport: TurnTransport<'_>,
        prompt_blocks: &prompt::SystemPromptBlocks,
        memory_db: Option<&memory::MemoryDb>,
        auto_learner: &mut Option<openclaudia::auto_learn::AutoLearner<'_>>,
    ) -> String {
        let max_proxy_iterations = self.config.session.max_turns;
        let mut proxy_iteration: u32 = 0;
        let mut executed_tool_sigs: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        loop {
            if !anthropic_accumulator.has_tool_use() {
                break;
            }
            if max_proxy_iterations > 0 && proxy_iteration >= max_proxy_iterations {
                // #601 — emit structured `error_max_turns` result event
                // before printing the user-facing warning so subscribers
                // see a typed event, not just a stderr string.
                let _ = emit_max_turns_event(
                    &self.chat_session.id(),
                    "anthropic_proxy",
                    max_proxy_iterations,
                    proxy_iteration,
                );
                eprintln!(
                    "\n\x1b[33m⚠ Reached max_turns limit ({max_proxy_iterations} turns). Configure session.max_turns in config.yaml (0 = unlimited).\x1b[0m"
                );
                break;
            }
            proxy_iteration += 1;

            let Some(tool_calls) =
                self.collect_anthropic_iteration(&*anthropic_accumulator, &mut executed_tool_sigs)
            else {
                break;
            };

            self.dispatch_anthropic_tool_batch(
                &tool_calls,
                anthropic_accumulator,
                memory_db,
                auto_learner,
            )
            .await;

            let followup_req = match self.build_anthropic_followup(prompt_blocks) {
                Ok(req) => req,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to build Anthropic follow-up request");
                    eprintln!("\n\x1b[31mRequest build error: {e}\x1b[0m");
                    break;
                }
            };
            full_content = String::new();
            if !self.followup_request_policy_allows("anthropic follow-up") {
                break;
            }
            if !self
                .send_anthropic_followup(
                    followup_req,
                    transport,
                    anthropic_accumulator,
                    &mut full_content,
                )
                .await
            {
                break;
            }
        }

        if !full_content.trim().is_empty() {
            let Some(rendered) = self.render_final_response(full_content.trim(), false) else {
                return String::new();
            };
            println!("{rendered}");
            push_chat_session_message_and_persist(
                &mut self.chat_session,
                serde_json::json!({
                    "role": "assistant",
                    "content": rendered
                }),
                "anthropic final assistant response",
            );
            full_content = rendered;
        }
        full_content
    }

    /// Finalize tool calls + assistant message for one Anthropic loop
    /// iteration. Returns `None` when the loop should stop because every
    /// tool was already executed (duplicate detection).
    fn collect_anthropic_iteration(
        &mut self,
        anthropic_accumulator: &tools::AnthropicToolAccumulator,
        executed_tool_sigs: &mut std::collections::HashSet<String>,
    ) -> Option<Vec<tools::ToolCall>> {
        let text = anthropic_accumulator.get_text();
        let tool_calls = anthropic_accumulator.finalize_tool_calls();

        if !tool_calls.is_empty() && all_signatures_seen(&tool_calls, executed_tool_sigs) {
            eprintln!("\n\x1b[33m⚠ Detected duplicate tool calls - breaking agentic loop\x1b[0m");
            return None;
        }
        for tc in &tool_calls {
            executed_tool_sigs.insert(tool_call_signature(tc));
        }

        push_chat_session_message_and_persist(
            &mut self.chat_session,
            openclaudia::pipeline::build_assistant_message_with_tools(
                &text,
                None,
                &tool_calls,
                "anthropic",
            ),
            "anthropic tool-call assistant turn",
        );
        Some(tool_calls)
    }

    /// Execute every tool from one Anthropic iteration, run quality
    /// gates, clear the accumulator, and print the "sending N results"
    /// banner before the follow-up request.
    async fn dispatch_anthropic_tool_batch(
        &mut self,
        tool_calls: &[tools::ToolCall],
        anthropic_accumulator: &mut tools::AnthropicToolAccumulator,
        memory_db: Option<&memory::MemoryDb>,
        auto_learner: &mut Option<openclaudia::auto_learn::AutoLearner<'_>>,
    ) {
        for tool_call in tool_calls {
            self.execute_anthropic_tool(tool_call, memory_db, auto_learner)
                .await;
        }
        self.run_quality_gates_and_inject();
        anthropic_accumulator.clear();

        println!(
            "\n\x1b[90m(Sending {} tool result{} to Claude...)\x1b[0m",
            tool_calls.len(),
            if tool_calls.len() == 1 { "" } else { "s" }
        );
    }

    /// Execute a single tool call from the Anthropic structured path,
    /// updating chat history with the result.
    async fn execute_anthropic_tool(
        &mut self,
        tool_call: &tools::ToolCall,
        memory_db: Option<&memory::MemoryDb>,
        auto_learner: &mut Option<openclaudia::auto_learn::AutoLearner<'_>>,
    ) {
        if self.push_plan_mode_block_if_any(tool_call) {
            return;
        }
        let Some(authorization) = self.push_permission_or_proceed(tool_call).await else {
            return;
        };
        let result = self.run_tool_with_audit(tool_call, memory_db, auto_learner, authorization);

        let final_result = process_tool_follow_up(&self.run_context, &self.chat_session, &result);
        let final_content = final_result.content();
        let final_is_error = final_result.is_error();

        if let Err(e) = self.audit_logger.log_security(
            "tool_result",
            &serde_json::json!({
                "name": &tool_call.function.name,
                "id": &tool_call.id,
                "is_error": final_is_error,
                "content_length": final_content.len(),
            }),
        ) {
            tracing::error!("Security audit failed for tool_result: {e}");
        }
        let tool_input = parse_tool_args(&tool_call.function).unwrap_or_else(
            |_| serde_json::json!({ "raw_arguments": tool_call.function.arguments }),
        );
        openclaudia::services::tool_executor::ToolExecutor::fire_post_tool(
            &self.run_context,
            &self.hook_engine,
            !final_is_error,
            &tool_call.function.name,
            tool_input,
            final_content,
            Some(&self.chat_session.id()),
        )
        .await;
        display_tool_result(&final_result);
        push_observed_cli_typed_tool_result_message(
            &self.run_context,
            &mut self.chat_session,
            tool_call,
            &final_result,
        );
    }

    /// If `tool_call` is blocked by plan mode, push the error tool
    /// message and return `true` (caller should bail out).
    fn push_plan_mode_block_if_any(&mut self, tool_call: &tools::ToolCall) -> bool {
        let Some(block_msg) = check_plan_mode_restriction(
            &self.chat_session,
            &tool_call.function.name,
            &tool_call.function.arguments,
        ) else {
            return false;
        };
        println!(
            "\n\x1b[33m⚠ Blocked in plan mode: {}\x1b[0m",
            tool_call.function.name
        );
        push_observed_cli_tool_result_message(
            &self.run_context,
            &mut self.chat_session,
            tool_call,
            &tool_call.id,
            &block_msg,
            true,
        );
        true
    }

    /// Run the interactive permission check. On `Denied` push the error
    /// tool message and return `None`. On `Allowed`, return the exact one-use
    /// execution permit (or `None` for the explicit unrestricted path).
    async fn push_permission_or_proceed(
        &mut self,
        tool_call: &tools::ToolCall,
    ) -> Option<Option<ExecutionPermit>> {
        let tool_args_val = match parse_tool_args(&tool_call.function) {
            Ok(args) => args,
            Err(msg) => {
                push_observed_cli_tool_result_message(
                    &self.run_context,
                    &mut self.chat_session,
                    tool_call,
                    &tool_call.id,
                    &msg,
                    true,
                );
                return None;
            }
        };
        if let Some(result) = self
            .pre_tool_use_denied_tool_result(tool_call, &tool_args_val)
            .await
        {
            push_observed_cli_typed_tool_result_message(
                &self.run_context,
                &mut self.chat_session,
                tool_call,
                &result,
            );
            return None;
        }
        if let Some(result) = self.policy_denied_tool_result(tool_call) {
            push_observed_cli_typed_tool_result_message(
                &self.run_context,
                &mut self.chat_session,
                tool_call,
                &result,
            );
            return None;
        }
        let result = check_tool_permission_interactive(
            tool_call,
            &self.chat_session.id(),
            &self.permission_mgr,
            &self.transient_allowed_tool_rules,
        );
        match result {
            ToolPermissionResult::Denied(msg) => {
                push_observed_cli_tool_result_message(
                    &self.run_context,
                    &mut self.chat_session,
                    tool_call,
                    &tool_call.id,
                    &msg,
                    true,
                );
                None
            }
            ToolPermissionResult::Allowed { authorization } => Some(authorization),
        }
    }

    /// Emit the running banner + `tool_call` audit event, dispatch via
    /// `execute_tool_with_memory`, and observe the result for the
    /// auto-learner. Shared by both the Anthropic and `OpenAI` paths.
    fn run_tool_with_audit(
        &mut self,
        tool_call: &tools::ToolCall,
        memory_db: Option<&memory::MemoryDb>,
        auto_learner: &mut Option<openclaudia::auto_learn::AutoLearner<'_>>,
        authorization: Option<ExecutionPermit>,
    ) -> tools::ToolResult {
        println!("\n\x1b[36m⚡ Running {}...\x1b[0m", tool_call.function.name);
        if let Err(e) = self.audit_logger.log_security(
            "tool_call",
            &serde_json::json!({
                "name": &tool_call.function.name,
                "arguments": &tool_call.function.arguments,
                "id": &tool_call.id,
            }),
        ) {
            // log_security already emitted tracing::error!; surface to stderr
            // so the user sees the failure mid-session, but continue (the
            // session itself is not corrupted by an audit-write failure).
            tracing::error!("Security audit failed for tool_call: {e}");
        }
        let result = execute_tool_with_memory_after_permission(
            &self.run_context,
            tool_call,
            memory_db,
            &self.permission_mgr,
            authorization,
            &self.chat_session.id(),
            Some(self.policy_enforcer.as_ref()),
        );
        Self::auto_learn_observe(auto_learner, tool_call, &result);
        result
    }

    /// Build the next Anthropic follow-up request body reusing the
    /// cached prompt blocks.
    fn build_anthropic_followup(
        &self,
        prompt_blocks: &prompt::SystemPromptBlocks,
    ) -> Result<serde_json::Value, String> {
        let request_messages =
            prompt_blocks.prepare_json_messages(&self.request_messages_with_grounding()?);
        let anthropic_messages =
            convert_messages_to_anthropic_checked(&request_messages).map_err(|e| e.to_string())?;
        let openai_tools = tools::get_all_tool_definitions(true);
        let anthropic_tools = convert_tool_definitions_to_anthropic_checked(&openai_tools)
            .map_err(|e| e.to_string())?;

        let mut followup_req = serde_json::json!({
            "model": self.model,
            "messages": anthropic_messages,
            "max_tokens": openclaudia::DEFAULT_MAX_TOKENS,
            "stream": true,
            "tools": anthropic_tools
        });
        followup_req["system"] = openclaudia::providers::build_system_blocks(prompt_blocks);
        if self.claude_code_token.is_some() {
            openclaudia::claude_credentials::inject_oauth_prefix_only(&mut followup_req);
        }
        Ok(followup_req)
    }

    /// Send the Anthropic follow-up and stream its content into
    /// `anthropic_accumulator` + `full_content`. Returns `false` on
    /// transport/HTTP error (caller should break the loop).
    async fn send_anthropic_followup(
        &self,
        followup_req: serde_json::Value,
        transport: TurnTransport<'_>,
        anthropic_accumulator: &mut tools::AnthropicToolAccumulator,
        full_content: &mut String,
    ) -> bool {
        use futures::StreamExt;

        let req = match transport
            .headers
            .apply(self.client.post(transport.endpoint).json(&followup_req))
        {
            Ok(request) => request,
            Err(error) => {
                eprintln!("\nProvider header error: {error}");
                return false;
            }
        };
        match req.send().await {
            Ok(response) if response.status().is_success() => {
                let mut stream = response.bytes_stream().eventsource();
                let stream_timeout = std::time::Duration::from_secs(proxy::SSE_STREAM_TIMEOUT_SECS);
                loop {
                    let sse = match tokio::time::timeout(stream_timeout, stream.next()).await {
                        Ok(Some(Ok(sse))) => sse,
                        Ok(Some(Err(e))) => {
                            eprintln!("\nStream error: {e}");
                            break;
                        }
                        Ok(None) => break,
                        Err(_) => {
                            Self::handle_stream_timeout(full_content);
                            break;
                        }
                    };
                    if sse.data == "[DONE]" {
                        break;
                    }
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&sse.data) {
                        if let Some(text) = anthropic_accumulator.process_event(&json) {
                            full_content.push_str(&text);
                        }
                    }
                }
                true
            }
            Ok(response) => {
                eprintln!("\nFollow-up request failed: {}", response.status());
                false
            }
            Err(e) => {
                eprintln!("\nFollow-up request error: {e}");
                false
            }
        }
    }

    /// OpenAI-compatible agentic loop. Save the final response state to
    /// the session at the end.
    async fn run_openai_tool_loop(
        &mut self,
        tool_accumulator: &mut tools::ToolCallAccumulator,
        mut state: OpenAiLoopState,
        transport: TurnTransport<'_>,
        prompt_blocks: &prompt::SystemPromptBlocks,
        memory_db: Option<&memory::MemoryDb>,
        auto_learner: &mut Option<openclaudia::auto_learn::AutoLearner<'_>>,
    ) {
        let max_iterations = self.config.session.max_turns;
        let mut iteration: u32 = 0;
        let mut executed_tool_sigs: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        while tool_accumulator.has_tool_calls()
            && !state.cancelled
            && (max_iterations == 0 || iteration < max_iterations)
        {
            iteration += 1;
            let tool_calls = tool_accumulator.finalize();

            if iteration > 1
                && !tool_calls.is_empty()
                && all_signatures_seen(&tool_calls, &executed_tool_sigs)
            {
                eprintln!(
                    "\n\x1b[33m⚠ Detected duplicate tool calls - breaking agentic loop\x1b[0m"
                );
                break;
            }
            for tc in &tool_calls {
                executed_tool_sigs.insert(tool_call_signature(tc));
            }

            self.record_openai_assistant_turn(
                &tool_calls,
                &state.current_content,
                &state.current_reasoning_content,
            );
            self.dispatch_openai_tool_batch(&tool_calls, tool_accumulator, memory_db, auto_learner)
                .await;

            println!("\n\x1b[90mContinuing with tool results...\x1b[0m\n");
            let request_body = match self.build_openai_followup_request(prompt_blocks) {
                Ok(req) => req,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to build OpenAI follow-up request");
                    eprintln!("\n\x1b[31mRequest build error: {e}\x1b[0m");
                    break;
                }
            };
            state.current_content.clear();
            state.current_reasoning_content.clear();
            if !self.followup_request_policy_allows("openai follow-up") {
                break;
            }
            self.stream_openai_followup(
                request_body,
                transport,
                tool_accumulator,
                &mut state.current_content,
                &mut state.current_reasoning_content,
            )
            .await;
        }

        if max_iterations > 0 && iteration >= max_iterations && tool_accumulator.has_tool_calls() {
            // #601 — structured `error_max_turns` for the OpenAI path.
            let _ =
                emit_max_turns_event(&self.chat_session.id(), "openai", max_iterations, iteration);
            eprintln!(
                "\n\x1b[33m⚠ Reached max_turns limit ({max_iterations} turns). Configure session.max_turns in config.yaml (0 = unlimited).\x1b[0m"
            );
        }

        let final_allowed = self.persist_openai_loop_state(
            &state.current_content,
            &state.current_reasoning_content,
            tool_accumulator,
            iteration,
            state.cancelled,
        );
        if final_allowed {
            self.run_openai_vdd_review(&state.current_content, state.cancelled)
                .await;
        }
    }

    /// Append the assistant message that initiated this `OpenAI` tool
    /// batch, encoding tool calls into the standard `OpenAI` shape.
    fn record_openai_assistant_turn(
        &mut self,
        tool_calls: &[tools::ToolCall],
        current_content: &str,
        reasoning_content: &str,
    ) {
        let mut message = openclaudia::pipeline::build_assistant_message_with_tools(
            current_content,
            None,
            tool_calls,
            "openai",
        );
        attach_reasoning_content(&mut message, reasoning_content);
        push_chat_session_message_and_persist(
            &mut self.chat_session,
            message,
            "openai tool-call assistant turn",
        );
    }

    /// Execute every tool from one `OpenAI` iteration, run quality
    /// gates, and clear the accumulator for the next pass.
    async fn dispatch_openai_tool_batch(
        &mut self,
        tool_calls: &[tools::ToolCall],
        tool_accumulator: &mut tools::ToolCallAccumulator,
        memory_db: Option<&memory::MemoryDb>,
        auto_learner: &mut Option<openclaudia::auto_learn::AutoLearner<'_>>,
    ) {
        for tool_call in tool_calls {
            self.execute_openai_tool(tool_call, memory_db, auto_learner)
                .await;
        }
        self.run_quality_gates_and_inject();
        tool_accumulator.clear();
    }

    /// Persist the final session state from the `OpenAI` loop, mirroring
    /// the original three-way conditional (terminal content / iterated /
    /// no progress).
    fn persist_openai_loop_state(
        &mut self,
        current_content: &str,
        reasoning_content: &str,
        tool_accumulator: &tools::ToolCallAccumulator,
        iteration: u32,
        cancelled: bool,
    ) -> bool {
        if (!current_content.is_empty() || !reasoning_content.is_empty())
            && !tool_accumulator.has_tool_calls()
        {
            if cancelled {
                self.record_failed_turn("provider response was cancelled before final validation");
                return false;
            }
            let Some(rendered) = self.render_final_response(current_content.trim(), cancelled)
            else {
                return false;
            };
            println!("{rendered}");
            let mut message = serde_json::json!({
                "role": "assistant",
                "content": rendered
            });
            attach_reasoning_content(&mut message, reasoning_content);
            push_chat_session_message_and_persist(
                &mut self.chat_session,
                message,
                "openai final assistant response",
            );
            return true;
        }
        if iteration > 0 {
            persist_chat_session_update(&mut self.chat_session, "openai tool loop");
        } else if current_content.is_empty()
            && reasoning_content.is_empty()
            && !tool_accumulator.has_tool_calls()
        {
            self.record_failed_turn("provider returned no assistant content or tool calls");
        }
        true
    }

    /// Run VDD review on the final `OpenAI` loop content when applicable.
    async fn run_openai_vdd_review(&mut self, current_content: &str, cancelled: bool) {
        if cancelled {
            return;
        }
        let Some(ref engine) = self.vdd_engine else {
            return;
        };
        if current_content.trim().is_empty() {
            return;
        }
        let original = self.chat_session.messages_snapshot();
        let mut messages = original.clone();
        run_vdd_review(
            engine,
            &self.run_context,
            current_content,
            &mut messages,
            &self.config.proxy.target,
            self.api_key.as_ref(),
        )
        .await;
        if messages != original {
            self.chat_session.replace_messages(messages);
            persist_chat_session_update(&mut self.chat_session, "openai VDD context injection");
        }
    }

    /// Build the OpenAI-compatible follow-up request body (handles both
    /// the Anthropic direct branch and the generic `OpenAI` shape).
    fn build_openai_followup_request(
        &self,
        prompt_blocks: &prompt::SystemPromptBlocks,
    ) -> Result<serde_json::Value, String> {
        let request_messages =
            prompt_blocks.prepare_json_messages(&self.request_messages_with_grounding()?);
        if self.config.proxy.target.eq_ignore_ascii_case("anthropic") {
            let anthropic_messages = convert_messages_to_anthropic_checked(&request_messages)
                .map_err(|e| e.to_string())?;
            let openai_tools = tools::get_all_tool_definitions(true);
            let anthropic_tools = convert_tool_definitions_to_anthropic_checked(&openai_tools)
                .map_err(|e| e.to_string())?;
            let mut req = serde_json::json!({
                "model": self.model,
                "messages": anthropic_messages,
                "max_tokens": openclaudia::DEFAULT_MAX_TOKENS,
                "stream": true,
                "tools": anthropic_tools
            });
            req["system"] = openclaudia::providers::build_system_blocks(prompt_blocks);
            Ok(req)
        } else {
            Ok(serde_json::json!({
                "model": self.model,
                "messages": request_messages,
                "max_tokens": openclaudia::DEFAULT_MAX_TOKENS,
                "stream": true,
                "tools": tools::get_all_tool_definitions(true)
            }))
        }
    }

    /// Stream an OpenAI-style follow-up into `current_content` and feed
    /// tool deltas into `tool_accumulator` for the next loop iteration.
    async fn stream_openai_followup(
        &self,
        request_body: serde_json::Value,
        transport: TurnTransport<'_>,
        tool_accumulator: &mut tools::ToolCallAccumulator,
        current_content: &mut String,
        current_reasoning_content: &mut String,
    ) {
        use futures::StreamExt;

        let Ok(req) = transport
            .headers
            .apply(self.client.post(transport.endpoint).json(&request_body))
        else {
            return;
        };
        let Ok(response) = req.send().await else {
            return;
        };
        if !response.status().is_success() {
            return;
        }
        let mut stream = response.bytes_stream().eventsource();
        let stream_timeout = std::time::Duration::from_secs(proxy::SSE_STREAM_TIMEOUT_SECS);
        let mut anthropic_accumulator = tools::AnthropicToolAccumulator::new();
        let mut in_thinking_block = false;
        let mut thinking_start_time: Option<std::time::Instant> = None;
        let mut reasoning_started = false;
        loop {
            let sse = match tokio::time::timeout(stream_timeout, stream.next()).await {
                Ok(Some(Ok(sse))) => sse,
                Ok(Some(Err(e))) => {
                    eprintln!("\nStream error: {e}");
                    break;
                }
                Ok(None) => break,
                Err(_) => {
                    Self::handle_stream_timeout(current_content);
                    break;
                }
            };
            if sse.data == "[DONE]" {
                break;
            }
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&sse.data) {
                match openclaudia::pipeline::process_sse_event(
                    &json,
                    in_thinking_block,
                    &mut anthropic_accumulator,
                    tool_accumulator,
                ) {
                    openclaudia::pipeline::SseAction::Text(text) => {
                        if reasoning_started {
                            let elapsed = thinking_start_time
                                .map_or(0.0, |started| started.elapsed().as_secs_f64());
                            tui::print_thinking_end(elapsed);
                            reasoning_started = false;
                            thinking_start_time = None;
                        }
                        current_content.push_str(&text);
                    }
                    openclaudia::pipeline::SseAction::Thinking(text) => {
                        tui::print_thinking_chunk(&text);
                    }
                    openclaudia::pipeline::SseAction::Reasoning(text) => {
                        let display_text = openclaudia::pipeline::merge_reasoning_delta(
                            current_reasoning_content,
                            &text,
                        );
                        if !display_text.is_empty() {
                            if !reasoning_started {
                                reasoning_started = true;
                                thinking_start_time = Some(std::time::Instant::now());
                                tui::print_thinking_start();
                            }
                            tui::print_thinking_chunk(&display_text);
                        }
                    }
                    openclaudia::pipeline::SseAction::ThinkingStart => {
                        in_thinking_block = true;
                        thinking_start_time = Some(std::time::Instant::now());
                        tui::print_thinking_start();
                    }
                    openclaudia::pipeline::SseAction::ThinkingEnd => {
                        let elapsed = thinking_start_time
                            .map_or(0.0, |started| started.elapsed().as_secs_f64());
                        tui::print_thinking_end(elapsed);
                        in_thinking_block = false;
                        thinking_start_time = None;
                    }
                    openclaudia::pipeline::SseAction::None => {}
                }
            }
        }
        if reasoning_started {
            let elapsed =
                thinking_start_time.map_or(0.0, |started| started.elapsed().as_secs_f64());
            tui::print_thinking_end(elapsed);
        }
    }

    /// Execute a single tool call from the OpenAI-style loop (matches
    /// the original inline path including activity logging).
    async fn execute_openai_tool(
        &mut self,
        tool_call: &tools::ToolCall,
        memory_db: Option<&memory::MemoryDb>,
        auto_learner: &mut Option<openclaudia::auto_learn::AutoLearner<'_>>,
    ) {
        if self.push_plan_mode_block_if_any(tool_call) {
            return;
        }
        let Some(authorization) = self.push_permission_or_proceed(tool_call).await else {
            return;
        };
        let result =
            self.run_openai_tool_unaudited(tool_call, memory_db, auto_learner, authorization);

        let final_result = process_tool_follow_up(&self.run_context, &self.chat_session, &result);
        let final_content = final_result.content();
        let final_is_error = final_result.is_error();

        Self::log_openai_activity(
            memory_db,
            &self.chat_session.id(),
            tool_call,
            final_is_error,
        );
        let tool_input = parse_tool_args(&tool_call.function).unwrap_or_else(
            |_| serde_json::json!({ "raw_arguments": tool_call.function.arguments }),
        );
        openclaudia::services::tool_executor::ToolExecutor::fire_post_tool(
            &self.run_context,
            &self.hook_engine,
            !final_is_error,
            &tool_call.function.name,
            tool_input,
            final_content,
            Some(&self.chat_session.id()),
        )
        .await;
        display_tool_result(&final_result);
        push_observed_cli_typed_tool_result_message(
            &self.run_context,
            &mut self.chat_session,
            tool_call,
            &final_result,
        );
    }

    /// `OpenAI`-loop variant of `run_tool_with_audit` — same dispatch and
    /// auto-learner observation, but no audit logger calls (the `OpenAI`
    /// loop emits its own audit shape upstream).
    fn run_openai_tool_unaudited(
        &self,
        tool_call: &tools::ToolCall,
        memory_db: Option<&memory::MemoryDb>,
        auto_learner: &mut Option<openclaudia::auto_learn::AutoLearner<'_>>,
        authorization: Option<ExecutionPermit>,
    ) -> tools::ToolResult {
        println!("\n\x1b[36m⚡ Running {}...\x1b[0m", tool_call.function.name);
        let result = execute_tool_with_memory_after_permission(
            &self.run_context,
            tool_call,
            memory_db,
            &self.permission_mgr,
            authorization,
            &self.chat_session.id(),
            Some(self.policy_enforcer.as_ref()),
        );
        Self::auto_learn_observe(auto_learner, tool_call, &result);
        result
    }

    /// Persist a memory-DB activity row for one `OpenAI` tool execution.
    /// No-op when no memory DB is configured.
    fn log_openai_activity(
        memory_db: Option<&memory::MemoryDb>,
        session_id: &str,
        tool_call: &tools::ToolCall,
        final_is_error: bool,
    ) {
        let Some(db) = memory_db else { return };
        let activity_type = openai_activity_type(tool_call);
        let target = serde_json::from_str::<serde_json::Value>(&tool_call.function.arguments)
            .map_or_else(
                |_| tool_call.function.name.clone(),
                |args| {
                    args.get("path")
                        .or_else(|| args.get("file_path"))
                        .or_else(|| args.get("command"))
                        .or_else(|| args.get("operation"))
                        .and_then(|v| v.as_str())
                        .unwrap_or(&tool_call.function.name)
                        .to_string()
                },
            );
        let _ = db.log_activity(
            session_id,
            activity_type,
            &target,
            if final_is_error { Some("error") } else { None },
        );
    }

    /// Run quality gates after a tool batch and inject any failures
    /// back into the session as system messages.
    fn run_quality_gates_and_inject(&mut self) {
        let qg_results = guardrails::run_quality_gates(&self.run_context, &self.model);
        self.record_quality_gate_verifications(&qg_results);
        let mut injected_failure = false;
        for qg in &qg_results {
            if qg.passed() {
                tracing::debug!(name = %qg.name(), "Quality gate passed");
                continue;
            }
            let severity = if qg.required() { "FAILED" } else { "warning" };
            eprintln!(
                "\x1b[33m⚠ Quality gate '{}' {} (exit {})\x1b[0m",
                qg.name(),
                severity,
                qg.exit_code()
            );
            if !qg.stderr().is_empty() {
                let preview: String = qg.stderr().lines().take(3).collect::<Vec<_>>().join("\n");
                eprintln!("  {preview}");
            }
            self.chat_session.push_message(serde_json::json!({
                "role": "system",
                "content": format!(
                    "[Quality Gate '{}' {}] exit code {}\nstdout: {}\nstderr: {}",
                    qg.name(), severity, qg.exit_code(),
                    if qg.stdout().len() > 500 { safe_truncate(qg.stdout(), 500) } else { qg.stdout() },
                    if qg.stderr().len() > 500 { safe_truncate(qg.stderr(), 500) } else { qg.stderr() }
                ),
                "metadata": {
                    "openclaudia_context_source": "reality"
                }
            }));
            injected_failure = true;
        }
        if injected_failure {
            persist_chat_session_update(&mut self.chat_session, "quality gate injection");
        }
    }

    fn record_quality_gate_verifications(&self, qg_results: &[guardrails::QualityCheckResult]) {
        if qg_results.is_empty() {
            return;
        }
        let mut ledger =
            match openclaudia::ledger::RealityLedger::open_project_session(&self.chat_session.id())
            {
                Ok(ledger) => ledger,
                Err(err) => {
                    tracing::warn!(
                        session_id = %self.chat_session.id(),
                        error = %err,
                        "failed to open session reality ledger for CLI quality gates"
                    );
                    return;
                }
            };
        for gate in qg_results {
            if let Err(err) = openclaudia::grounded_loop::append_quality_gate_observations(
                &self.run_context,
                &mut ledger,
                gate,
            ) {
                tracing::warn!(
                    session_id = %self.chat_session.id(),
                    gate = %gate.name(),
                    error = %err,
                    "failed to append CLI quality-gate observations to reality ledger"
                );
            }
        }
    }

    fn auto_learn_observe(
        auto_learner: &mut Option<openclaudia::auto_learn::AutoLearner<'_>>,
        tool_call: &tools::ToolCall,
        result: &tools::ToolResult,
    ) {
        if let Some(ref mut learner) = auto_learner {
            let args: serde_json::Value =
                serde_json::from_str(&tool_call.function.arguments).unwrap_or_default();
            if result.is_error() {
                learner.on_tool_failure(&tool_call.function.name, &args, result.content());
            } else {
                learner.on_tool_success(&tool_call.function.name, &args, result.content());
            }
        }
    }

    /// Apply a keybinding-triggered action that was deferred during
    /// streaming. Returns `true` when Exit was queued.
    fn handle_pending_action(&mut self, action: Option<SlashCommandResult>) -> bool {
        let Some(action_result) = action else {
            return false;
        };
        match action_result {
            SlashCommandResult::Exit => {
                if let Err(e) = self.rl.save_history(&self.history_path) {
                    tracing::warn!("Failed to save history: {}", e);
                }
                println!("\nGoodbye!");
                true
            }
            SlashCommandResult::ToggleMode => {
                self.chat_session.toggle_mode();
                println!(
                    "\nSwitched to {} mode: {}\n",
                    self.chat_session.agent_mode().display(),
                    self.chat_session.mode_description()
                );
                false
            }
            SlashCommandResult::Status => {
                let tokens = estimate_session_tokens(&self.chat_session);
                let duration =
                    chrono::Utc::now().signed_duration_since(self.chat_session.created_at);
                println!(
                    "\n[{}] {} | ~{} tokens | {} min\n",
                    self.chat_session.agent_mode().display(),
                    self.chat_session.model,
                    tokens,
                    duration.num_minutes()
                );
                false
            }
            SlashCommandResult::Export => {
                export_chat_session(&self.chat_session);
                false
            }
            _ => false,
        }
    }
}

impl Drop for ChatRepl {
    fn drop(&mut self) {
        tools::retire_run(&self.run_context);
    }
}

/// State returned from the initial-stream consumer for the calling
/// streaming path to act on (cancel flag, deferred keybinding, etc.).
struct InitialStreamResult {
    full_content: String,
    reasoning_content: String,
    cancelled: bool,
    pending_action: Option<SlashCommandResult>,
}

// ── Free helpers (no `self`) used by ChatRepl methods ──

/// Resolve the REPL's provider adapter from `proxy.target`. Returns
/// `None` (with an error printed to stderr) when the configured target
/// is not a registered adapter name. The caller turns that into a setup
/// error so the process exits non-zero. Extracted to keep the body of
/// `new` under the clippy `too_many_lines` ceiling. See crosslink #433.
fn resolve_repl_adapter(
    target: &str,
) -> Option<&'static dyn openclaudia::providers::ProviderAdapter> {
    match openclaudia::providers::get_adapter(target) {
        Ok(a) => Some(a),
        Err(e) => {
            eprintln!("{e}");
            None
        }
    }
}

fn gemini_tool_error_response(tool_call: &tools::ToolCall, message: &str) -> serde_json::Value {
    serde_json::json!({
        "functionResponse": {
            "name": &tool_call.function.name,
            "response": {"error": message}
        }
    })
}

fn attach_reasoning_content(message: &mut serde_json::Value, reasoning_content: &str) {
    if !reasoning_content.is_empty() {
        message["reasoning_content"] = serde_json::Value::String(reasoning_content.to_string());
    }
}

fn persist_chat_session_update(session: &mut Session, reason: &str) {
    session.touch();
    if let Err(e) = save_chat_session(session) {
        tracing::warn!(
            save_reason = reason,
            "Failed to save session after transcript update: {}",
            e
        );
    }
}

fn push_chat_session_message_and_persist(
    session: &mut Session,
    message: serde_json::Value,
    reason: &str,
) {
    session.push_message(message);
    persist_chat_session_update(session, reason);
}

fn parse_tool_args(func: &tools::FunctionCall) -> Result<serde_json::Value, String> {
    openclaudia::services::tool_executor::ToolExecutor::parse_arguments(&func.name, &func.arguments)
        .map_err(|err| {
            if err.contains("Invalid tool arguments JSON")
                && !err.contains("expected a JSON object")
            {
                tracing::warn!("Malformed tool arguments for '{}': {}", func.name, err);
            }
            err
        })
}

fn canonical_provider_name(provider: &str) -> &str {
    match provider {
        "gemini" => "google",
        "alibaba" => "qwen",
        "zhipu" | "glm" => "zai",
        "moonshot" => "kimi",
        other => other,
    }
}

fn normalize_prompt_effort(effort: &str) -> Option<EffortLevel> {
    match effort.trim().to_ascii_lowercase().as_str() {
        "low" => Some(EffortLevel::Low),
        "medium" => Some(EffortLevel::Medium),
        "high" => Some(EffortLevel::High),
        "max" => Some(EffortLevel::Max),
        "auto" => Some(EffortLevel::Auto),
        _ => None,
    }
}

fn rewind_chat_session(session: &mut Session, turns: usize) -> usize {
    let mut rewound = 0;
    for _ in 0..turns {
        if session.undo() {
            rewound += 1;
        } else {
            break;
        }
    }
    rewound
}

fn apply_fast_mode_result(
    model: &mut String,
    session: &mut Session,
    effort: &str,
    fast_model: Option<String>,
) {
    session.set_effort_level(EffortLevel::parse(effort).unwrap_or(EffortLevel::Medium));
    if let Some(fast_model) = fast_model {
        *model = fast_model;
        session.model.clone_from(model);
    }
}

fn tool_call_signature(tc: &tools::ToolCall) -> String {
    format!("{}:{}", tc.function.name, tc.function.arguments)
}

fn all_signatures_seen(
    tool_calls: &[tools::ToolCall],
    executed: &std::collections::HashSet<String>,
) -> bool {
    tool_calls
        .iter()
        .all(|tc| executed.contains(&tool_call_signature(tc)))
}

fn gemini_response_parts(json: &serde_json::Value) -> Result<&[serde_json::Value], String> {
    let candidate = json
        .get("candidates")
        .and_then(|c| c.get(0))
        .ok_or_else(|| format!("Gemini response missing candidates[0]: {json}"))?;

    candidate
        .get("content")
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array())
        .map(Vec::as_slice)
        .ok_or_else(|| format!("Gemini candidate missing content.parts array: {candidate}"))
}

fn gemini_extract_text(json: &serde_json::Value) -> Result<String, String> {
    let parts = gemini_response_parts(json)?;
    extract_gemini_text_content(parts).map_err(|e| e.to_string())
}

fn gemini_extract_tool_calls(json: &serde_json::Value) -> Result<Vec<tools::ToolCall>, String> {
    let parts = gemini_response_parts(json)?;

    let mut calls = Vec::new();

    for part in parts {
        let Some(fc) = part.get("functionCall") else {
            continue;
        };

        if !fc.is_object() {
            return Err(format!("Gemini functionCall must be an object: {fc}"));
        }

        let name = fc
            .get("name")
            .and_then(serde_json::Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| format!("Gemini functionCall missing non-empty string 'name': {fc}"))?
            .to_string();

        let args = fc
            .get("args")
            .ok_or_else(|| format!("Gemini functionCall missing object 'args': {fc}"))?;

        if !args.is_object() {
            return Err(format!(
                "Gemini functionCall has non-object 'args': expected JSON object, got {}",
                gemini_args_type_name(args)
            ));
        }

        let args = serde_json::to_string(args).map_err(|e| {
            format!("Gemini functionCall has unserializable 'args': {e}; functionCall: {fc}")
        })?;

        calls.push(tools::ToolCall {
            id: format!("call_{}", uuid::Uuid::new_v4()),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name,
                arguments: args,
            },
        });
    }

    Ok(calls)
}

const fn gemini_args_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Pull `(promptTokenCount, candidatesTokenCount)` out of a Gemini
/// response's `usageMetadata` block. Missing fields default to zero.
fn gemini_extract_usage_tokens(json: &serde_json::Value) -> (u64, u64) {
    let usage = json.get("usageMetadata");
    let input = usage
        .and_then(|u| u.get("promptTokenCount"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let output = usage
        .and_then(|u| u.get("candidatesTokenCount"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    (input, output)
}

/// Emit a structured `error_max_turns` event when the agentic loop's
/// turn cap is reached.
///
/// Crosslink #601 / CC parity (`QueryEngine.ts:851-873`): when the
/// per-turn iteration counter trips the configured `session.max_turns`
/// ceiling, CC yields a typed `{type:'result', subtype:'error_max_turns'}`
/// envelope so SDK callers can distinguish a turn-cap stop from other
/// terminal conditions. OC previously only wrote an ANSI string to
/// stderr, which is invisible to API/MCP/TUI consumers. This helper
/// emits a `tracing::error!` at `target = "openclaudia::turns"` with
/// the structured fields a downstream subscriber needs to reconstruct
/// the `error_max_turns` result event.
///
/// The function is intentionally pure (no `eprintln!` here) so callers
/// can keep their existing terminal warning unchanged while subscribers
/// get a typed event. Returning the formatted string lets tests assert
/// the message verbatim without intercepting the global tracing
/// subscriber.
fn emit_max_turns_event(
    agent_id: &str,
    provider_path: &str,
    max_turns: u32,
    turns_executed: u32,
) -> String {
    let message = format!("Reached maximum number of turns ({max_turns})");
    tracing::error!(
        target: "openclaudia::turns",
        event = "error_max_turns",
        kind = "result",
        is_error = true,
        agent_id,
        provider_path,
        max_turns,
        num_turns = turns_executed,
        "max turns exceeded"
    );
    message
}

fn openai_activity_type(tool_call: &tools::ToolCall) -> &'static str {
    match tool_call.function.name.as_str() {
        "read_file" => "file_read",
        "write_file" => "file_write",
        "edit_file" => "file_edit",
        "bash" => "bash_command",
        "crosslink" => serde_json::from_str::<serde_json::Value>(&tool_call.function.arguments)
            .map_or("crosslink", |args| {
                args.get("operation")
                    .and_then(|v| v.as_str())
                    .map_or("crosslink", |operation| match operation {
                        "create" | "subissue" => "issue_created",
                        "close" => "issue_closed",
                        "comment" => "issue_comment",
                        _ => "crosslink",
                    })
            }),
        // SAFETY: tool-call names are static-ish strings; we don't get to choose them
        // from this caller's perspective, so we degrade to a constant rather than leak
        // an unbounded set of static strings into the activity log.
        _ => "tool",
    }
}

/// Build a rustyline editor for the requested edit mode.
///
/// Runtime mode switching must use the same fallible construction path as
/// startup. Terminal/editor initialization can fail in non-interactive
/// environments, and toggling Vim mode should report that error instead of
/// panicking mid-session.
fn new_rustyline_editor(
    edit_mode: rustyline::EditMode,
) -> rustyline::Result<rustyline::DefaultEditor> {
    use rustyline::{Config, Editor};
    Editor::with_config(Config::builder().edit_mode(edit_mode).build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::{Arc, Mutex};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn test_run() -> &'static Arc<openclaudia::tools::ToolRunContext> {
        static RUN: std::sync::OnceLock<Arc<openclaudia::tools::ToolRunContext>> =
            std::sync::OnceLock::new();
        RUN.get_or_init(|| {
            openclaudia::tools::ToolRunContext::builder(
                openclaudia::state::SessionId::new(),
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
            )
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(std::collections::HashMap::new())
            .workspace_access(openclaudia::tools::WorkspaceAccess::ReadWrite)
            .process(true)
            .network(false)
            .secrets(false)
            .provider("chat-repl-test")
            .build()
            .expect("explicit chat REPL test run")
        })
    }

    fn isolated_test_run() -> Arc<openclaudia::tools::ToolRunContext> {
        openclaudia::tools::ToolRunContext::builder(
            openclaudia::state::SessionId::new(),
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
        )
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(std::collections::HashMap::new())
        .workspace_access(openclaudia::tools::WorkspaceAccess::ReadWrite)
        .process(true)
        .network(false)
        .secrets(false)
        .provider("chat-repl-isolated-test")
        .build()
        .expect("isolated chat REPL test run")
    }

    fn test_session_at(root: &std::path::Path, provider: &str) -> Session {
        let session = Session::new("test-model", provider);
        session.update_state(|state, _| {
            state.identity.original_cwd = root.to_path_buf();
            state.identity.cwd = root.to_path_buf();
            state.identity.project_root = root.to_path_buf();
            state.identity.session_project_dir = root.to_path_buf();
            state.transcript.transcript_cwd = root.to_path_buf();
        });
        session
    }

    #[test]
    fn repl_session_derivation_preserves_authority_and_rejects_foreign_state() {
        let root = tempfile::tempdir().expect("REPL transition root");
        let foreign = tempfile::tempdir().expect("foreign REPL transition root");
        let parent = openclaudia::tools::ToolRunContext::builder(
            openclaudia::state::SessionId::new(),
            root.path(),
        )
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(std::collections::HashMap::new())
        .workspace_access(openclaudia::tools::WorkspaceAccess::ReadWrite)
        .process(true)
        .network(false)
        .secrets(false)
        .provider("anthropic")
        .build()
        .expect("parent REPL run");
        let loaded = test_session_at(root.path(), "anthropic");

        let derived = derive_repl_session_run(&parent, &loaded, "anthropic")
            .expect("same-project session must derive");
        assert_eq!(derived.session_id(), loaded.id());
        assert_eq!(derived.project_root(), parent.project_root());
        assert_ne!(derived.run_id(), parent.run_id());

        let foreign_session = test_session_at(foreign.path(), "anthropic");
        let foreign_error = derive_repl_session_run(&parent, &foreign_session, "anthropic")
            .expect_err("foreign project must not widen launch authority");
        assert!(foreign_error.contains("differs from the authorized launch project"));

        let provider_error = derive_repl_session_run(&parent, &loaded, "openai")
            .expect_err("foreign provider must not retain a mismatched transport");
        assert!(provider_error.contains("differs from the active provider"));
    }

    #[test]
    fn fresh_repl_session_keeps_the_run_workspace_without_reusing_identity() {
        let root = tempfile::tempdir().expect("fresh REPL root");
        let current = test_session_at(root.path(), "anthropic");
        let current_id = current.id();
        let fresh = fresh_repl_session_in_run(&current, "next-model", "anthropic");

        assert_ne!(fresh.id(), current_id);
        let identity = fresh.inspect_state(|state| state.identity.clone());
        assert_eq!(identity.project_root, root.path());
        assert_eq!(identity.cwd, root.path());
        assert_eq!(identity.original_cwd, root.path());
        assert_eq!(fresh.model, "next-model");
        assert_eq!(fresh.provider, "anthropic");
    }

    struct EnvGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvGuard {
        fn set_path(key: &'static str, value: &std::path::Path) -> Self {
            let previous = std::env::var_os(key);
            // SAFETY: this test module serializes environment mutation with
            // ENV_LOCK and restores the original value in Drop.
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: see EnvGuard::set_path.
            unsafe {
                if let Some(previous) = &self.previous {
                    std::env::set_var(self.key, previous);
                } else {
                    std::env::remove_var(self.key);
                }
            }
        }
    }

    #[test]
    fn active_provider_for_turn_returns_configured_provider() {
        let config: config::AppConfig = serde_yaml::from_str(
            r#"
proxy:
  target: anthropic
providers:
  anthropic:
    base_url: "https://api.anthropic.com"
"#,
        )
        .expect("fixture config must parse");

        let provider =
            active_provider_for_turn(&config).expect("anthropic provider should be active");

        assert_eq!(provider.base_url, "https://api.anthropic.com");
    }

    #[test]
    fn active_provider_for_turn_reports_missing_provider() {
        let config: config::AppConfig = serde_yaml::from_str(
            r"
proxy:
  target: missing
providers: {}
",
        )
        .expect("fixture config must parse");

        let err = active_provider_for_turn(&config)
            .expect_err("missing active provider must return an error");

        assert_eq!(err, "No provider configured for target 'missing'");
    }

    #[test]
    fn parse_tool_args_rejects_malformed_or_non_object_json() {
        let malformed = tools::FunctionCall {
            name: "bash".to_string(),
            arguments: "{not json".to_string(),
        };
        let err = parse_tool_args(&malformed).expect_err("malformed JSON must fail closed");
        assert!(err.contains("Invalid tool arguments JSON"), "{err}");
        assert!(err.contains("bash"), "{err}");

        let non_object = tools::FunctionCall {
            name: "read_file".to_string(),
            arguments: "[]".to_string(),
        };
        let err = parse_tool_args(&non_object).expect_err("non-object JSON must fail closed");
        assert!(err.contains("expected a JSON object"), "{err}");
    }

    #[test]
    fn parse_tool_args_accepts_object_json() {
        let func = tools::FunctionCall {
            name: "read_file".to_string(),
            arguments: "{\"path\":\"src/main.rs\"}".to_string(),
        };

        let parsed = parse_tool_args(&func).expect("object JSON should parse");

        assert_eq!(parsed["path"], "src/main.rs");
    }

    #[test]
    fn non_empty_final_responses_require_grounding() {
        assert!(final_response_requires_grounding("Done.", false));
        assert!(final_response_requires_grounding(
            "  Verified with cargo test.  ",
            false
        ));
    }

    #[test]
    fn empty_or_cancelled_final_responses_do_not_require_grounding() {
        assert!(!final_response_requires_grounding("", false));
        assert!(!final_response_requires_grounding("   ", false));
        assert!(!final_response_requires_grounding(
            "partial provider text\n\n[Response interrupted by user]",
            true
        ));
    }

    #[test]
    fn cli_plain_final_is_denied_and_records_policy_decision() {
        let session_id = format!("cli-plain-final-{}", uuid::Uuid::new_v4());
        let path = openclaudia::ledger::project_session_ledger_path(&session_id)
            .expect("safe test session");
        let content = "Verified with cargo test.";

        let err = validate_and_render_cli_agentic_final_response(
            test_run(),
            &session_id,
            content,
            "test-model",
        )
        .expect_err("plain assistant text must not bypass the claim gate");

        assert_eq!(err, "final answer must use the typed final claim envelope");

        let ledger = openclaudia::ledger::RealityLedger::open_project_session(&session_id)
            .expect("reopen CLI ledger");
        assert!(ledger
            .observations_chronological()
            .iter()
            .any(|obs| matches!(
                &obs.kind,
                openclaudia::ledger::ObservationKind::PolicyDecision { allowed: false, .. }
            )));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cli_structured_final_gate_rejects_missing_verification() {
        let session_id = format!("cli-ungrounded-final-{}", uuid::Uuid::new_v4());
        let path = openclaudia::ledger::project_session_ledger_path(&session_id)
            .expect("safe test session");
        let content = serde_json::json!({
            "kind": "final",
            "claims": [{
                "claim_type": "file_change",
                "path": "src/cli/chat_repl.rs",
                "evidence": []
            }]
        })
        .to_string();

        let err = validate_and_render_cli_agentic_final_response(
            test_run(),
            &session_id,
            &content,
            "test-model",
        )
        .expect_err("supported runtime claim without verification must be denied");

        assert_eq!(
            err,
            "supported runtime claims require a trusted verification claim"
        );
        let ledger = openclaudia::ledger::RealityLedger::open_project_session(&session_id)
            .expect("reopen CLI ledger");
        assert!(ledger
            .observations_chronological()
            .iter()
            .any(|obs| matches!(
                &obs.kind,
                openclaudia::ledger::ObservationKind::PolicyDecision { allowed: false, .. }
            )));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cli_structured_final_renders_typed_uncertainty_not_raw_json() {
        let session_id = format!("cli-typed-final-{}", uuid::Uuid::new_v4());
        let path = openclaudia::ledger::project_session_ledger_path(&session_id)
            .expect("safe test session");
        let content = serde_json::json!({
            "kind": "final",
            "claims": [{
                "claim_type": "unsupported",
                "statement": "The remote deployment is healthy.",
                "reason": "No deployment receipt is available."
            }]
        })
        .to_string();

        let rendered = validate_and_render_cli_agentic_final_response(
            test_run(),
            &session_id,
            &content,
            "test-model",
        )
        .expect("typed uncertainty should pass");

        assert_eq!(
            rendered,
            "Unsupported claim \"The remote deployment is healthy.\"; reason \"No deployment receipt is available.\"."
        );
        assert!(!rendered.contains("claim_type"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cli_quality_gate_result_records_command_and_verification_observations() {
        let run = isolated_test_run();
        let mut ledger = openclaudia::ledger::RealityLedger::new();
        let config = openclaudia::config::GuardrailsConfig {
            quality_gates: Some(openclaudia::config::QualityGatesConfig {
                enabled: true,
                checks: vec![openclaudia::config::QualityCheck {
                    name: "deliberate-failure".to_string(),
                    command: "sh -c 'printf format-drift; exit 1'".to_string(),
                    required: true,
                }],
                ..openclaudia::config::QualityGatesConfig::default()
            }),
            ..openclaudia::config::GuardrailsConfig::default()
        };
        guardrails::configure(&run, &config).expect("configure quality gate");
        let gate = guardrails::run_quality_gates(&run, "test-model")
            .into_iter()
            .next()
            .expect("configured quality gate result");

        let ids =
            openclaudia::grounded_loop::append_quality_gate_observations(&run, &mut ledger, &gate)
                .expect("quality gate should ledger command and verification");

        let command_obs = ledger
            .get(ids.command)
            .expect("command observation should exist");
        let openclaudia::ledger::ObservationKind::CommandRun {
            argv, exit_code, ..
        } = &command_obs.kind
        else {
            panic!("expected command observation");
        };
        assert_eq!(
            argv,
            &vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf format-drift; exit 1".to_string()
            ]
        );
        assert_eq!(*exit_code, 1);

        let obs = ledger
            .get(ids.verification)
            .expect("verification observation should exist");
        let openclaudia::ledger::ObservationKind::Verification {
            passed,
            command,
            findings,
        } = &obs.kind
        else {
            panic!("expected verification observation");
        };
        assert!(!passed);
        assert_eq!(
            command.as_deref(),
            Some("sh -c 'printf format-drift; exit 1'")
        );
        assert!(findings
            .iter()
            .any(|finding| finding.contains("deliberate-failure")));
        assert!(findings
            .iter()
            .any(|finding| finding.contains("format-drift")));
        assert_eq!(
            obs.provenance.trust,
            openclaudia::ledger::EvidenceTrust::TrustedVerifier
        );
        assert!(obs.provenance.is_bound_to(&run));
        assert!(obs.provenance.verification_method.is_some());
    }

    fn chat_session_with_turns(turns: usize) -> Session {
        let session = Session::new_with_behavior_mode(
            "claude-sonnet",
            "anthropic",
            openclaudia::modes::BehaviorMode::default(),
        );
        for i in 0..turns {
            session.push_message(serde_json::json!({
                "role": "user",
                "content": format!("user {i}")
            }));
            session.push_message(serde_json::json!({
                "role": "assistant",
                "content": format!("assistant {i}")
            }));
        }
        session
    }

    #[test]
    fn rewind_chat_session_rewinds_requested_turns() {
        let mut session = chat_session_with_turns(3);

        let rewound = rewind_chat_session(&mut session, 2);

        assert_eq!(rewound, 2);
        let state = session.state_snapshot();
        assert_eq!(state.conversation.messages.len(), 2);
        assert_eq!(state.conversation.undo_stack.len(), 2);
        assert_eq!(state.conversation.messages[0]["content"], "user 0");
        assert_eq!(state.conversation.messages[1]["content"], "assistant 0");
    }

    #[test]
    fn rewind_chat_session_stops_when_history_is_exhausted() {
        let mut session = chat_session_with_turns(1);

        let rewound = rewind_chat_session(&mut session, 5);

        assert_eq!(rewound, 1);
        let state = session.state_snapshot();
        assert!(state.conversation.messages.is_empty());
        assert_eq!(state.conversation.undo_stack.len(), 1);
    }

    #[test]
    fn apply_fast_mode_result_sets_effort_and_model() {
        let mut session = chat_session_with_turns(0);
        let mut model = "claude-opus-4-6".to_string();

        apply_fast_mode_result(
            &mut model,
            &mut session,
            "low",
            Some("claude-haiku-4-5-20251001".to_string()),
        );

        assert_eq!(session.effort_level(), EffortLevel::Low);
        assert_eq!(model, "claude-haiku-4-5-20251001");
        assert_eq!(session.model, "claude-haiku-4-5-20251001");
    }

    #[test]
    fn apply_fast_mode_result_without_model_only_sets_effort() {
        let mut session = chat_session_with_turns(0);
        let mut model = "custom-local".to_string();
        session.model.clone_from(&model);
        session.set_effort_level(EffortLevel::High);

        apply_fast_mode_result(&mut model, &mut session, "low", None);

        assert_eq!(session.effort_level(), EffortLevel::Low);
        assert_eq!(model, "custom-local");
        assert_eq!(session.model, "custom-local");
    }

    #[test]
    fn gemini_tool_error_response_uses_tool_name_and_message() {
        let tool_call = tools::ToolCall {
            id: "call_1".to_string(),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name: "read_file".to_string(),
                arguments: "{}".to_string(),
            },
        };

        let response = gemini_tool_error_response(&tool_call, "denied");

        assert_eq!(response["functionResponse"]["name"], "read_file");
        assert_eq!(response["functionResponse"]["response"]["error"], "denied");
    }

    #[test]
    fn gemini_extract_text_concatenates_text_parts_and_allows_tool_calls() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": "hello "},
                        {"functionCall": {"name": "bash", "args": {"command": "pwd"}}},
                        {"text": "world"}
                    ]
                }
            }]
        });

        let text = gemini_extract_text(&body).expect("mixed text/tool response should parse");

        assert_eq!(text, "hello world");
    }

    #[test]
    fn gemini_response_parts_rejects_missing_parts() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {}
            }]
        });

        let err = gemini_response_parts(&body).expect_err("missing parts must fail");

        assert!(err.contains("content.parts"), "{err}");
    }

    #[test]
    fn gemini_extract_text_rejects_non_string_text_part() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": 123}
                    ]
                }
            }]
        });

        let err = gemini_extract_text(&body).expect_err("non-string text must fail");

        assert!(err.contains("'text'"), "{err}");
    }

    #[test]
    fn gemini_extract_text_rejects_unsupported_part_shape() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"inlineData": {"mimeType": "image/png", "data": "..."}}
                    ]
                }
            }]
        });

        let err = gemini_extract_text(&body).expect_err("unsupported part must fail");

        assert!(err.contains("supported text or functionCall"), "{err}");
    }

    #[test]
    fn gemini_extract_tool_calls_accepts_valid_function_call() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": "using a tool"},
                        {"functionCall": {"name": "bash", "args": {"command": "pwd"}}}
                    ]
                }
            }]
        });

        let calls = gemini_extract_tool_calls(&body).expect("valid Gemini call should parse");

        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "bash");
        assert_eq!(calls[0].function.arguments, r#"{"command":"pwd"}"#);
    }

    #[test]
    fn gemini_extract_tool_calls_rejects_missing_name() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"args": {"command": "pwd"}}}
                    ]
                }
            }]
        });

        let err = gemini_extract_tool_calls(&body).expect_err("missing Gemini name must fail");

        assert!(err.contains("functionCall"), "{err}");
        assert!(err.contains("name"), "{err}");
    }

    #[test]
    fn gemini_extract_tool_calls_rejects_missing_args() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"name": "bash"}}
                    ]
                }
            }]
        });

        let err = gemini_extract_tool_calls(&body).expect_err("missing Gemini args must fail");

        assert!(err.contains("functionCall"), "{err}");
        assert!(err.contains("args"), "{err}");
    }

    #[test]
    fn gemini_extract_tool_calls_rejects_non_object_args() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"name": "bash", "args": []}}
                    ]
                }
            }]
        });

        let err = gemini_extract_tool_calls(&body).expect_err("non-object Gemini args must fail");

        assert!(err.contains("args"), "{err}");
        assert!(err.contains("object"), "{err}");
    }

    /// #601 — `emit_max_turns_event` returns the canonical
    /// `Reached maximum number of turns (N)` message string and the
    /// structured fields it logs include `max_turns` and the
    /// `agent_id` / `provider_path` so a downstream subscriber can
    /// reconstruct the `error_max_turns` result envelope.
    #[test]
    fn emit_max_turns_event_returns_canonical_message() {
        let msg = emit_max_turns_event("sess-123", "openai", 7, 7);
        assert_eq!(
            msg, "Reached maximum number of turns (7)",
            "message must match CC's error_max_turns wording exactly"
        );
    }

    /// #601 — the helper is provider-agnostic: each provider path label
    /// produces a stable message that only varies in the turn count,
    /// so subscribers can group by `provider_path` without re-parsing.
    #[test]
    fn emit_max_turns_event_message_varies_only_with_count() {
        let a = emit_max_turns_event("s1", "anthropic_proxy", 3, 3);
        let b = emit_max_turns_event("s2", "google_gemini", 3, 3);
        let c = emit_max_turns_event("s3", "openai", 10, 10);
        assert_eq!(a, b, "provider_path must not leak into the user message");
        assert_ne!(a, c, "different max_turns must yield different messages");
        assert!(c.contains("10"));
    }

    #[test]
    fn stream_timeout_preserves_assistant_content() {
        let content = "partial provider text".to_string();

        ChatRepl::handle_stream_timeout(&content);

        assert_eq!(content, "partial provider text");
    }

    #[test]
    fn transcript_persist_helper_writes_reloadable_session_file() {
        let _guard = ENV_LOCK.lock().expect("env lock poisoned");
        let tmp = tempfile::tempdir().expect("tempdir");
        let _xdg = EnvGuard::set_path("XDG_DATA_HOME", tmp.path());
        let mut session = Session::new_with_behavior_mode(
            "claude-sonnet",
            "anthropic",
            openclaudia::modes::BehaviorMode::default(),
        );
        let id = session.id();

        push_chat_session_message_and_persist(
            &mut session,
            serde_json::json!({
                "role": "assistant",
                "content": "partial provider text"
            }),
            "test transcript persistence",
        );

        let loaded = load_chat_session(&id)
            .expect("session load must not fail")
            .expect("session file must exist");
        let messages = loaded.messages_snapshot();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "assistant");
        assert_eq!(messages[0]["content"], "partial provider text");
    }

    #[test]
    fn cli_tool_result_append_records_grounding_observation() {
        let _guard = ENV_LOCK.lock().expect("env lock poisoned");
        let tmp = tempfile::tempdir().expect("tempdir");
        let _xdg = EnvGuard::set_path("XDG_DATA_HOME", tmp.path());
        let mut session = Session::new_with_behavior_mode(
            "claude-sonnet",
            "anthropic",
            openclaudia::modes::BehaviorMode::default(),
        );
        let ledger = Arc::new(Mutex::new(openclaudia::ledger::RealityLedger::new()));
        let _ledger_guard = openclaudia::ledger::install_active_ledger_for_session(
            session.id(),
            Arc::clone(&ledger),
        );
        let tool_call = tools::ToolCall {
            id: "call_denied".to_string(),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name: "bash".to_string(),
                arguments: r#"{"command":"cargo test"}"#.to_string(),
            },
        };

        push_observed_cli_tool_result_message(
            test_run(),
            &mut session,
            &tool_call,
            &tool_call.id,
            "Permission denied: policy",
            true,
        );

        let messages = session.messages_snapshot();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "tool");
        assert_eq!(messages[0]["content"], "[ERROR] Permission denied: policy");

        let observation = {
            let ledger = ledger.lock().expect("ledger lock");
            ledger
                .observations_chronological()
                .into_iter()
                .find(|obs| {
                    matches!(
                        obs.kind,
                        openclaudia::ledger::ObservationKind::ToolResult { .. }
                    )
                })
                .cloned()
        }
        .expect("tool result observation");
        assert_eq!(
            observation.provenance.trust,
            openclaudia::ledger::EvidenceTrust::UntrustedContent
        );
        assert!(observation.provenance.is_bound_to(test_run()));
        assert_eq!(
            observation
                .provenance
                .tool_call
                .as_ref()
                .expect("tool-call provenance")
                .call_id,
            "call_denied"
        );
        let openclaudia::ledger::ObservationKind::ToolResult { tool, result } = &observation.kind
        else {
            panic!("expected tool result observation");
        };
        assert_eq!(tool, "bash");
        assert_eq!(result["tool_call_id"], "call_denied");
        assert_eq!(result["content"], "Permission denied: policy");
        assert_eq!(result["is_error"], true);
    }

    /// Regression guard for the Vim toggle panic path: editor construction is
    /// fallible and must be represented as a `Result`, not hidden behind
    /// `expect()` in production code. The success path is environment-sensitive
    /// on some CI terminals, so this test only asserts that both modes travel
    /// through the non-panicking helper.
    #[test]
    fn rustyline_editor_mode_construction_is_fallible_not_panicking() {
        let _ = new_rustyline_editor(rustyline::EditMode::Emacs);
        let _ = new_rustyline_editor(rustyline::EditMode::Vi);
    }
}
