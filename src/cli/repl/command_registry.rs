//! Legacy-REPL command execution backed by the canonical typed registry.

use std::fmt;

use openclaudia::command_registry::{
    self, CommandFrontend, CommandId, CommandParseError, ProposedCommand,
};

use super::slash::{PluginAction, SlashCommandResult};

/// Runtime dependencies available to legacy command handlers.
pub struct SlashCtx<'a> {
    pub messages: &'a mut Vec<serde_json::Value>,
    pub provider: &'a str,
    pub current_model: &'a str,
    pub run_context: Option<&'a openclaudia::tools::ToolRunContext>,
    pub app_config: Option<&'a openclaudia::config::AppConfig>,
    pub doctor_runtime: Option<&'a openclaudia::doctor::DoctorRuntimeSnapshot>,
}

/// Parse/admission error rendered by the legacy frontend.
#[derive(Debug)]
pub enum CommandDispatchError {
    Parse(CommandParseError),
    Execution(command_registry::CommandExecutionError),
}

impl fmt::Display for CommandDispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(formatter, "{error}"),
            Self::Execution(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for CommandDispatchError {}

/// Frontend executor. Handler selection is exhaustive over the same typed
/// [`CommandId`] carried by the canonical registry.
pub struct CommandRegistry {
    schema: &'static command_registry::CommandRegistry,
}

impl CommandRegistry {
    #[cfg(test)]
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&'static command_registry::CommandSpec> {
        self.schema.get(name)
    }

    /// Parse, admit, account for, trace, and invoke one legacy command.
    ///
    /// # Errors
    ///
    /// Returns the canonical parse or execution denial without invoking a
    /// handler when the proposal is invalid or unauthorized.
    pub fn parse_and_dispatch(
        &self,
        input: &str,
        ctx: &mut SlashCtx<'_>,
    ) -> Result<SlashCommandResult, CommandDispatchError> {
        let proposal = self
            .schema
            .parse(input, CommandFrontend::LegacyCli)
            .map_err(CommandDispatchError::Parse)?;
        let run = ctx.run_context;
        self.schema
            .execute(&proposal, run, |proposal| dispatch_proposed(proposal, ctx))
            .map_err(CommandDispatchError::Execution)
    }
}

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

// An exhaustive typed-handler match is easier to audit for missing legacy
// routes than several partial dispatch tables.
#[allow(clippy::too_many_lines)]
fn dispatch_proposed(proposal: &ProposedCommand, ctx: &mut SlashCtx<'_>) -> SlashCommandResult {
    let args = proposal.arguments_text();
    match proposal.id() {
        CommandId::Help => {
            slash_help();
            if let Some(config) = ctx.app_config {
                super::keybindings::display_keybindings(&config.keybindings);
            }
            SlashCommandResult::Handled
        }
        CommandId::New => {
            ctx.messages.clear();
            println!("\nStarting new conversation.\n");
            SlashCommandResult::Clear
        }
        CommandId::Sessions => slash_sessions(),
        CommandId::Continue => slash_continue(args),
        CommandId::Exit => SlashCommandResult::Exit,
        CommandId::History => slash_history(ctx.messages),
        CommandId::Model => {
            let command_name = if proposal.invoked_name() == "models" {
                "models"
            } else {
                "model"
            };
            slash_model(args, command_name, ctx.provider, ctx.current_model)
        }
        CommandId::Export => SlashCommandResult::Export,
        CommandId::Compact => SlashCommandResult::Compact {
            instructions: (!args.is_empty()).then(|| args.to_string()),
        },
        CommandId::Editor => {
            let Some(run) = ctx.run_context else {
                eprintln!("External editor is unavailable without a run context.");
                return SlashCommandResult::Handled;
            };
            open_external_editor(run)
                .map_or(SlashCommandResult::Handled, SlashCommandResult::EditorInput)
        }
        CommandId::Undo => SlashCommandResult::Undo,
        CommandId::Redo => SlashCommandResult::Redo,
        CommandId::Rewind => slash_rewind(args, ctx.messages),
        CommandId::Teleport => slash_teleport(args, ctx.run_context),
        CommandId::Thinkback => slash_thinkback(args, ctx.messages),
        CommandId::Copy => slash_copy(ctx.messages),
        CommandId::Init => {
            slash_init(ctx.run_context);
            SlashCommandResult::Handled
        }
        CommandId::Review => {
            review_git_changes(args);
            SlashCommandResult::Handled
        }
        CommandId::Status => SlashCommandResult::Status,
        CommandId::Connect => {
            configure_provider_api_key(ctx.app_config);
            SlashCommandResult::Handled
        }
        CommandId::Theme => handle_theme_command(args).map_or(
            SlashCommandResult::Handled,
            SlashCommandResult::ThemeChanged,
        ),
        CommandId::Plan => SlashCommandResult::ToggleMode,
        CommandId::Mode => handle_mode_command(args),
        CommandId::Vim => SlashCommandResult::ToggleVim,
        CommandId::Agents => {
            slash_agents();
            SlashCommandResult::Handled
        }
        CommandId::Keybindings => SlashCommandResult::Keybindings,
        CommandId::Rename => SlashCommandResult::Rename(args.to_string()),
        CommandId::Version => {
            slash_version();
            SlashCommandResult::Handled
        }
        CommandId::Doctor => {
            slash_doctor(ctx.run_context, ctx.app_config, ctx.doctor_runtime);
            SlashCommandResult::Handled
        }
        CommandId::Config => {
            slash_config(args);
            SlashCommandResult::Handled
        }
        CommandId::Mcp => slash_mcp(args, ctx.run_context),
        CommandId::Permissions => slash_permissions(),
        CommandId::Hooks => slash_hooks(),
        CommandId::Debug => {
            slash_debug(ctx.provider, ctx.current_model, ctx.messages.len());
            SlashCommandResult::Handled
        }
        CommandId::Effort => slash_effort(args),
        CommandId::Fast => slash_fast(ctx.provider, ctx.current_model),
        CommandId::Find => slash_find(args, ctx.run_context),
        CommandId::Memory => SlashCommandResult::Memory(args.to_string()),
        CommandId::Activity => SlashCommandResult::Activity(args.to_string()),
        CommandId::Plugin => slash_plugin(args),
        CommandId::Skill => ctx
            .run_context
            .map_or_else(|| slash_skill(args), |run| slash_skill_for_run(args, run)),
        CommandId::Commit => slash_commit(ctx.run_context),
        CommandId::CommitPushPr => slash_commit_push_pr(ctx.run_context),
        CommandId::Cost => slash_cost(ctx.messages),
        CommandId::Context => slash_context(ctx.messages, ctx.current_model),
        CommandId::Login => slash_login(),
        CommandId::Logout => {
            println!("\nTo clear Claude Code credentials:");
            println!("  rm ~/.claude/.credentials.json");
            println!("\nTo use an API key instead:");
            println!("  export ANTHROPIC_API_KEY=sk-...");
            println!();
            SlashCommandResult::Handled
        }
        CommandId::AddDir => slash_add_dir(args, ctx.run_context),
        CommandId::Branch => slash_branch(args, ctx.messages, ctx.run_context),
        CommandId::Btw => slash_btw(args),
        CommandId::DynamicPlugin => SlashCommandResult::Plugin(PluginAction::RunCommand {
            plugin_name: proposal.namespace().unwrap_or_default().to_string(),
            command_name: proposal.component().unwrap_or_default().to_string(),
            arguments: args.to_string(),
        }),
        CommandId::Provider | CommandId::Files | CommandId::Diff | CommandId::DirectSkill => {
            // Construction and frontend availability make this unreachable.
            SlashCommandResult::Handled
        }
    }
}

/// Process-wide legacy executor over the process-wide canonical schema.
#[must_use]
pub fn registry() -> &'static CommandRegistry {
    static REGISTRY: std::sync::OnceLock<CommandRegistry> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| CommandRegistry {
        schema: command_registry::registry(),
    })
}
