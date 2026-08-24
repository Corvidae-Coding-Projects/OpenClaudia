/// Command registry — OCP-clean slash command dispatch for `#232`.
///
/// Adding a new slash command is now:
///   1. Define a unit struct and implement [`CommandHandler`] for it.
///   2. Add one line to [`build_registry`].
///
/// The central match arm in `handle_slash_command` has been replaced by
/// [`CommandRegistry::dispatch`].
use std::collections::HashMap;
use std::sync::OnceLock;

use super::slash::SlashCommandResult;

// ─── Context ──────────────────────────────────────────────────────────────────

/// Everything a [`CommandHandler`] may need at dispatch time.
///
/// Mirrors the parameters that `handle_slash_command` used to receive.
pub struct SlashCtx<'a> {
    /// Current conversation history (mutable — `/clear` drains it).
    pub messages: &'a mut Vec<serde_json::Value>,
    /// Active provider name (e.g. `"anthropic"`).
    pub provider: &'a str,
    /// Currently selected model name.
    pub current_model: &'a str,
    /// Immutable run used for project-bounded commands. Compatibility callers
    /// without one must fail closed to global/user application layers.
    pub run_context: Option<&'a openclaudia::tools::ToolRunContext>,
    /// Already-validated configuration from the real frontend composition.
    pub app_config: Option<&'a openclaudia::config::AppConfig>,
    /// Exact service snapshot supplied by a composed frontend for `/doctor`.
    pub doctor_runtime: Option<&'a openclaudia::doctor::DoctorRuntimeSnapshot>,
}

// ─── Trait ────────────────────────────────────────────────────────────────────

/// A single slash command.
///
/// Implementations are unit structs stored as `&'static dyn CommandHandler`
/// inside the registry map, avoiding any heap allocation per dispatch.
pub trait CommandHandler: Send + Sync {
    /// The canonical name (no leading `/`).  Must match the registry key.
    fn name(&self) -> &'static str;

    /// Execute the command and return a result.
    fn handle(&self, ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult;

    /// Extra names this command should be reachable by.
    ///
    /// Each alias is inserted into the registry alongside `name()`.
    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }
}

// ─── Registry ─────────────────────────────────────────────────────────────────

/// Maps command names (and aliases) to static handler references.
pub struct CommandRegistry {
    handlers: HashMap<&'static str, &'static dyn CommandHandler>,
}

impl CommandRegistry {
    /// Look up a handler by name.
    ///
    /// Currently unused directly (dispatch is the primary entry point), but
    /// retained as public API for callers that need to introspect the registry
    /// without dispatching (e.g. tab-completion, help rendering).
    #[must_use]
    #[allow(dead_code)] // public API; callers outside this binary will use it
    pub fn get(&self, name: &str) -> Option<&'static dyn CommandHandler> {
        self.handlers.get(name).copied()
    }

    /// Dispatch `cmd_name` with `args` to the registered handler, or return
    /// `None` if no handler is registered (caller handles unknown-command path).
    pub fn dispatch(
        &self,
        cmd_name: &str,
        ctx: &mut SlashCtx<'_>,
        args: &str,
    ) -> Option<SlashCommandResult> {
        self.handlers.get(cmd_name).map(|h| h.handle(ctx, args))
    }
}

// ─── Command implementations ──────────────────────────────────────────────────

// The handler bodies are thin wrappers that delegate to the existing
// `slash_*` free functions in `slash.rs` (or inline trivial logic where the
// function was a one-liner in the match arm).  This keeps the diff reviewable
// and avoids duplicating logic.

use super::input::open_external_editor;
use super::review::{configure_provider_api_key, review_git_changes};
use super::slash::{
    handle_mode_command, slash_add_dir, slash_agents, slash_branch, slash_btw, slash_commit,
    slash_commit_push_pr, slash_config, slash_context, slash_continue, slash_copy, slash_cost,
    slash_debug, slash_doctor, slash_effort, slash_fast, slash_find, slash_help, slash_history,
    slash_hooks, slash_init, slash_login, slash_mcp, slash_model, slash_permissions, slash_plugin,
    slash_rewind, slash_sessions, slash_skill, slash_skill_for_run, slash_teleport,
    slash_thinkback, slash_version,
};
use crate::cli::display::theme::handle_theme_command;

// ── /help, /? ────────────────────────────────────────────────────────────────

struct HelpCommand;
impl CommandHandler for HelpCommand {
    fn name(&self) -> &'static str {
        "help"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["?"]
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        slash_help();
        SlashCommandResult::Handled
    }
}

// ── /new, /clear ─────────────────────────────────────────────────────────────

struct NewCommand;
impl CommandHandler for NewCommand {
    fn name(&self) -> &'static str {
        "new"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["clear"]
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        ctx.messages.clear();
        println!("\nStarting new conversation.\n");
        SlashCommandResult::Clear
    }
}

// ── /sessions, /list ─────────────────────────────────────────────────────────

struct SessionsCommand;
impl CommandHandler for SessionsCommand {
    fn name(&self) -> &'static str {
        "sessions"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["list"]
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        slash_sessions()
    }
}

// ── /continue, /load, /resume ─────────────────────────────────────────────────

struct ContinueCommand;
impl CommandHandler for ContinueCommand {
    fn name(&self) -> &'static str {
        "continue"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["load", "resume"]
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        slash_continue(args)
    }
}

// ── /exit, /quit, /q ─────────────────────────────────────────────────────────

struct ExitCommand;
impl CommandHandler for ExitCommand {
    fn name(&self) -> &'static str {
        "exit"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["quit", "q"]
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        SlashCommandResult::Exit
    }
}

// ── /history ─────────────────────────────────────────────────────────────────

struct HistoryCommand;
impl CommandHandler for HistoryCommand {
    fn name(&self) -> &'static str {
        "history"
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        slash_history(ctx.messages)
    }
}

// ── /model ───────────────────────────────────────────────────────────────────

struct ModelCommand;
impl CommandHandler for ModelCommand {
    fn name(&self) -> &'static str {
        "model"
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        slash_model(args, "model", ctx.provider, ctx.current_model)
    }
}

// ── /models ──────────────────────────────────────────────────────────────────

struct ModelsCommand;
impl CommandHandler for ModelsCommand {
    fn name(&self) -> &'static str {
        "models"
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        // Pass "models" as cmd so slash_model enters list mode when args is empty.
        slash_model(args, "models", ctx.provider, ctx.current_model)
    }
}

// ── /export ──────────────────────────────────────────────────────────────────

struct ExportCommand;
impl CommandHandler for ExportCommand {
    fn name(&self) -> &'static str {
        "export"
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        SlashCommandResult::Export
    }
}

// ── /compact, /summarize ─────────────────────────────────────────────────────

struct CompactCommand;
impl CommandHandler for CompactCommand {
    fn name(&self) -> &'static str {
        "compact"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["summarize"]
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        SlashCommandResult::Compact {
            instructions: (!args.trim().is_empty()).then(|| args.trim().to_string()),
        }
    }
}

// ── /editor, /edit, /e ───────────────────────────────────────────────────────

struct EditorCommand;
impl CommandHandler for EditorCommand {
    fn name(&self) -> &'static str {
        "editor"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["edit", "e"]
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        let Some(run) = ctx.run_context else {
            eprintln!("External editor is unavailable without a run context.");
            return SlashCommandResult::Handled;
        };
        open_external_editor(run)
            .map_or(SlashCommandResult::Handled, SlashCommandResult::EditorInput)
    }
}

// ── /undo ────────────────────────────────────────────────────────────────────

struct UndoCommand;
impl CommandHandler for UndoCommand {
    fn name(&self) -> &'static str {
        "undo"
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        SlashCommandResult::Undo
    }
}

// ── /redo ────────────────────────────────────────────────────────────────────

struct RedoCommand;
impl CommandHandler for RedoCommand {
    fn name(&self) -> &'static str {
        "redo"
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        SlashCommandResult::Redo
    }
}

// ── /rewind, /checkpoint ────────────────────────────────────────────────────

struct RewindCommand;
impl CommandHandler for RewindCommand {
    fn name(&self) -> &'static str {
        "rewind"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["checkpoint"]
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        slash_rewind(args, ctx.messages)
    }
}

// ── /teleport ────────────────────────────────────────────────────────────────

struct TeleportCommand;
impl CommandHandler for TeleportCommand {
    fn name(&self) -> &'static str {
        "teleport"
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        slash_teleport(args, ctx.run_context)
    }
}

// ── /thinkback ───────────────────────────────────────────────────────────────

struct ThinkbackCommand;
impl CommandHandler for ThinkbackCommand {
    fn name(&self) -> &'static str {
        "thinkback"
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        slash_thinkback(args, ctx.messages)
    }
}

// ── /copy, /yank, /y ─────────────────────────────────────────────────────────

struct CopyCommand;
impl CommandHandler for CopyCommand {
    fn name(&self) -> &'static str {
        "copy"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["yank", "y"]
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        slash_copy(ctx.messages)
    }
}

// ── /init ────────────────────────────────────────────────────────────────────

struct InitCommand;
impl CommandHandler for InitCommand {
    fn name(&self) -> &'static str {
        "init"
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        slash_init(ctx.run_context);
        SlashCommandResult::Handled
    }
}

// ── /review ──────────────────────────────────────────────────────────────────

struct ReviewCommand;
impl CommandHandler for ReviewCommand {
    fn name(&self) -> &'static str {
        "review"
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        review_git_changes(args);
        SlashCommandResult::Handled
    }
}

// ── /status, /info ───────────────────────────────────────────────────────────

struct StatusCommand;
impl CommandHandler for StatusCommand {
    fn name(&self) -> &'static str {
        "status"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["info"]
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        SlashCommandResult::Status
    }
}

// ── /connect, /auth ──────────────────────────────────────────────────────────

struct ConnectCommand;
impl CommandHandler for ConnectCommand {
    fn name(&self) -> &'static str {
        "connect"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["auth"]
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        configure_provider_api_key(ctx.app_config);
        SlashCommandResult::Handled
    }
}

// ── /theme, /themes ──────────────────────────────────────────────────────────

struct ThemeCommand;
impl CommandHandler for ThemeCommand {
    fn name(&self) -> &'static str {
        "theme"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["themes"]
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        handle_theme_command(args).map_or(
            SlashCommandResult::Handled,
            SlashCommandResult::ThemeChanged,
        )
    }
}

// ── /plan ────────────────────────────────────────────────────────────────────

struct PlanCommand;
impl CommandHandler for PlanCommand {
    fn name(&self) -> &'static str {
        "plan"
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        SlashCommandResult::ToggleMode
    }
}

// ── /mode ────────────────────────────────────────────────────────────────────

struct ModeCommand;
impl CommandHandler for ModeCommand {
    fn name(&self) -> &'static str {
        "mode"
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        handle_mode_command(args)
    }
}

// ── /vim ─────────────────────────────────────────────────────────────────────

struct VimCommand;
impl CommandHandler for VimCommand {
    fn name(&self) -> &'static str {
        "vim"
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        SlashCommandResult::ToggleVim
    }
}

// ── /agents ──────────────────────────────────────────────────────────────────

struct AgentsCommand;
impl CommandHandler for AgentsCommand {
    fn name(&self) -> &'static str {
        "agents"
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        slash_agents();
        SlashCommandResult::Handled
    }
}

// ── /keybindings, /keys, /bindings ───────────────────────────────────────────

struct KeybindingsCommand;
impl CommandHandler for KeybindingsCommand {
    fn name(&self) -> &'static str {
        "keybindings"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["keys", "bindings"]
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        SlashCommandResult::Keybindings
    }
}

// ── /rename, /title ──────────────────────────────────────────────────────────

struct RenameCommand;
impl CommandHandler for RenameCommand {
    fn name(&self) -> &'static str {
        "rename"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["title"]
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        if args.is_empty() {
            println!("\nUsage: /rename <new title>\n");
            SlashCommandResult::Handled
        } else {
            SlashCommandResult::Rename(args.to_string())
        }
    }
}

// ── /version, /v, /about ─────────────────────────────────────────────────────

struct VersionCommand;
impl CommandHandler for VersionCommand {
    fn name(&self) -> &'static str {
        "version"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["v", "about"]
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        slash_version();
        SlashCommandResult::Handled
    }
}

// ── /doctor ──────────────────────────────────────────────────────────────────

struct DoctorCommand;
impl CommandHandler for DoctorCommand {
    fn name(&self) -> &'static str {
        "doctor"
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        slash_doctor(ctx.run_context, ctx.app_config, ctx.doctor_runtime);
        SlashCommandResult::Handled
    }
}

// ── /config ──────────────────────────────────────────────────────────────────

struct ConfigCommand;
impl CommandHandler for ConfigCommand {
    fn name(&self) -> &'static str {
        "config"
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        slash_config(args);
        SlashCommandResult::Handled
    }
}

// ── /mcp ────────────────────────────────────────────────────────────────────

struct McpCommand;
impl CommandHandler for McpCommand {
    fn name(&self) -> &'static str {
        "mcp"
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        slash_mcp(args, ctx.run_context)
    }
}

// ── /permissions ────────────────────────────────────────────────────────────

struct PermissionsCommand;
impl CommandHandler for PermissionsCommand {
    fn name(&self) -> &'static str {
        "permissions"
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        slash_permissions()
    }
}

// ── /hooks ──────────────────────────────────────────────────────────────────

struct HooksCommand;
impl CommandHandler for HooksCommand {
    fn name(&self) -> &'static str {
        "hooks"
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        slash_hooks()
    }
}

// ── /debug ───────────────────────────────────────────────────────────────────

struct DebugCommand;
impl CommandHandler for DebugCommand {
    fn name(&self) -> &'static str {
        "debug"
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        slash_debug(ctx.provider, ctx.current_model, ctx.messages.len());
        SlashCommandResult::Handled
    }
}

// ── /effort ──────────────────────────────────────────────────────────────────

struct EffortCommand;
impl CommandHandler for EffortCommand {
    fn name(&self) -> &'static str {
        "effort"
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        slash_effort(args)
    }
}

// ── /fast ────────────────────────────────────────────────────────────────────

struct FastCommand;
impl CommandHandler for FastCommand {
    fn name(&self) -> &'static str {
        "fast"
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        slash_fast(ctx.provider, ctx.current_model)
    }
}

// ── /find, /f ────────────────────────────────────────────────────────────────

struct FindCommand;
impl CommandHandler for FindCommand {
    fn name(&self) -> &'static str {
        "find"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["f"]
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        slash_find(args, ctx.run_context)
    }
}

// ── /memory, /mem ────────────────────────────────────────────────────────────

struct MemoryCommand;
impl CommandHandler for MemoryCommand {
    fn name(&self) -> &'static str {
        "memory"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["mem"]
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        SlashCommandResult::Memory(args.to_string())
    }
}

// ── /activity, /act ──────────────────────────────────────────────────────────

struct ActivityCommand;
impl CommandHandler for ActivityCommand {
    fn name(&self) -> &'static str {
        "activity"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["act"]
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        SlashCommandResult::Activity(args.to_string())
    }
}

// ── /plugin, /plugins ────────────────────────────────────────────────────────

struct PluginCommand;
impl CommandHandler for PluginCommand {
    fn name(&self) -> &'static str {
        "plugin"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["plugins"]
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        slash_plugin(args)
    }
}

// ── /skill, /skills ──────────────────────────────────────────────────────────

struct SkillCommand;
impl CommandHandler for SkillCommand {
    fn name(&self) -> &'static str {
        "skill"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["skills"]
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        ctx.run_context
            .map_or_else(|| slash_skill(args), |run| slash_skill_for_run(args, run))
    }
}

// ── /commit ──────────────────────────────────────────────────────────────────

struct CommitCommand;
impl CommandHandler for CommitCommand {
    fn name(&self) -> &'static str {
        "commit"
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        slash_commit(ctx.run_context)
    }
}

// ── /commit-push-pr ──────────────────────────────────────────────────────────

struct CommitPushPrCommand;
impl CommandHandler for CommitPushPrCommand {
    fn name(&self) -> &'static str {
        "commit-push-pr"
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        slash_commit_push_pr(ctx.run_context)
    }
}

// ── /cost ────────────────────────────────────────────────────────────────────

struct CostCommand;
impl CommandHandler for CostCommand {
    fn name(&self) -> &'static str {
        "cost"
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        slash_cost(ctx.messages)
    }
}

// ── /context ─────────────────────────────────────────────────────────────────

struct ContextCommand;
impl CommandHandler for ContextCommand {
    fn name(&self) -> &'static str {
        "context"
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        slash_context(ctx.messages, ctx.current_model)
    }
}

// ── /login ───────────────────────────────────────────────────────────────────

struct LoginCommand;
impl CommandHandler for LoginCommand {
    fn name(&self) -> &'static str {
        "login"
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        slash_login()
    }
}

// ── /logout ──────────────────────────────────────────────────────────────────

struct LogoutCommand;
impl CommandHandler for LogoutCommand {
    fn name(&self) -> &'static str {
        "logout"
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, _args: &str) -> SlashCommandResult {
        println!("\nTo clear Claude Code credentials:");
        println!("  rm ~/.claude/.credentials.json");
        println!("\nTo use an API key instead:");
        println!("  export ANTHROPIC_API_KEY=sk-...");
        println!();
        SlashCommandResult::Handled
    }
}

// ── /add-dir ─────────────────────────────────────────────────────────────────

struct AddDirCommand;
impl CommandHandler for AddDirCommand {
    fn name(&self) -> &'static str {
        "add-dir"
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        slash_add_dir(args, ctx.run_context)
    }
}

// ── /branch ──────────────────────────────────────────────────────────────────

struct BranchCommand;
impl CommandHandler for BranchCommand {
    fn name(&self) -> &'static str {
        "branch"
    }
    fn handle(&self, ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        slash_branch(args, ctx.messages, ctx.run_context)
    }
}

// ── /btw ─────────────────────────────────────────────────────────────────────

struct BtwCommand;
impl CommandHandler for BtwCommand {
    fn name(&self) -> &'static str {
        "btw"
    }
    fn handle(&self, _ctx: &mut SlashCtx<'_>, args: &str) -> SlashCommandResult {
        slash_btw(args)
    }
}

// ─── Registry construction ────────────────────────────────────────────────────

/// All registered handlers as static references.
///
/// Each handler appears once; aliases are resolved at registry-build time
/// via [`CommandHandler::aliases`].
static HANDLERS: &[&dyn CommandHandler] = &[
    &HelpCommand,
    &NewCommand,
    &SessionsCommand,
    &ContinueCommand,
    &ExitCommand,
    &HistoryCommand,
    &ModelCommand,
    &ModelsCommand,
    &ExportCommand,
    &CompactCommand,
    &EditorCommand,
    &UndoCommand,
    &RedoCommand,
    &RewindCommand,
    &TeleportCommand,
    &ThinkbackCommand,
    &CopyCommand,
    &InitCommand,
    &ReviewCommand,
    &StatusCommand,
    &ConnectCommand,
    &ThemeCommand,
    &PlanCommand,
    &ModeCommand,
    &VimCommand,
    &AgentsCommand,
    &KeybindingsCommand,
    &RenameCommand,
    &VersionCommand,
    &DoctorCommand,
    &ConfigCommand,
    &McpCommand,
    &PermissionsCommand,
    &HooksCommand,
    &DebugCommand,
    &EffortCommand,
    &FastCommand,
    &FindCommand,
    &MemoryCommand,
    &ActivityCommand,
    &PluginCommand,
    &SkillCommand,
    &CommitCommand,
    &CommitPushPrCommand,
    &CostCommand,
    &ContextCommand,
    &LoginCommand,
    &LogoutCommand,
    &AddDirCommand,
    &BranchCommand,
    &BtwCommand,
];

fn build_registry() -> CommandRegistry {
    let mut handlers: HashMap<&'static str, &'static dyn CommandHandler> =
        HashMap::with_capacity(HANDLERS.len() * 2);
    for &handler in HANDLERS {
        handlers.insert(handler.name(), handler);
        for &alias in handler.aliases() {
            handlers.insert(alias, handler);
        }
    }
    CommandRegistry { handlers }
}

/// Global registry, initialised exactly once.
pub fn registry() -> &'static CommandRegistry {
    static REGISTRY: OnceLock<CommandRegistry> = OnceLock::new();
    REGISTRY.get_or_init(build_registry)
}
