//! Canonical typed registry for interactive commands.
//!
//! Both interactive frontends parse through this module before invoking their
//! frontend-specific renderer or handler. Parsing only constructs a
//! [`ProposedCommand`]; capability checks, mode admission, budget accounting,
//! and trace emission happen in [`CommandRegistry::execute`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::OnceLock;

use crate::runtime::BudgetAmounts;
use crate::tools::effect::ToolEffect;
use crate::tools::{ToolResource, ToolRunContext};

/// Stable handler identity shared by the legacy REPL and full-screen TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommandId {
    Help,
    New,
    Sessions,
    Continue,
    Exit,
    History,
    Model,
    Export,
    Compact,
    Editor,
    Undo,
    Redo,
    Rewind,
    Teleport,
    Thinkback,
    Copy,
    Init,
    Review,
    Status,
    Connect,
    Theme,
    Plan,
    Mode,
    Vim,
    Agents,
    Keybindings,
    Rename,
    Version,
    Doctor,
    Config,
    Mcp,
    Permissions,
    Hooks,
    Debug,
    Effort,
    Fast,
    Find,
    Memory,
    Activity,
    Plugin,
    Skill,
    Commit,
    CommitPushPr,
    Cost,
    Context,
    Login,
    Logout,
    AddDir,
    Branch,
    Btw,
    Provider,
    Files,
    Diff,
    DynamicPlugin,
    DirectSkill,
}

/// Interactive surface on which a command may be proposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommandFrontend {
    LegacyCli,
    Tui,
}

/// Compact, const-friendly frontend availability set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrontendSet(u8);

impl FrontendSet {
    pub const EMPTY: Self = Self(0);
    pub const LEGACY: Self = Self(1);
    pub const TUI: Self = Self(2);
    pub const BOTH: Self = Self(Self::LEGACY.0 | Self::TUI.0);

    #[must_use]
    pub const fn contains(self, frontend: CommandFrontend) -> bool {
        let bit = match frontend {
            CommandFrontend::LegacyCli => Self::LEGACY.0,
            CommandFrontend::Tui => Self::TUI.0,
        };
        self.0 & bit != 0
    }

    const fn is_empty(self) -> bool {
        self.0 == 0
    }

    const fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }
}

/// How the text after a command name is converted into typed arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandArgumentSchema {
    /// Arguments are accepted for compatibility but have no semantic value.
    Ignored,
    /// The complete remainder is optional free-form text.
    OptionalText { value_name: &'static str },
    /// The complete remainder is required free-form text.
    RequiredText { value_name: &'static str },
    /// No value or one strictly positive integer.
    OptionalPositiveInteger { value_name: &'static str },
}

/// Parsed arguments carried by a proposed command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandArguments {
    None,
    OptionalText(Option<String>),
    RequiredText(String),
    OptionalPositiveInteger(Option<usize>),
}

/// Completion behavior generated from the same record used for dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionKind {
    Command,
    FreeText,
    Path,
    Model,
    Provider,
    Skill,
    Plugin,
    PositiveInteger,
}

/// One help row attached to a command specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandHelp {
    pub frontends: FrontendSet,
    pub section: &'static str,
    pub invocation: &'static str,
    pub description: &'static str,
}

const fn help(
    frontends: FrontendSet,
    section: &'static str,
    invocation: &'static str,
    description: &'static str,
) -> CommandHelp {
    CommandHelp {
        frontends,
        section,
        invocation,
        description,
    }
}

/// One immutable command definition. The handler identity, spelling, typed
/// schema, effect ceiling, capabilities, frontend availability, and
/// presentation metadata are deliberately inseparable.
#[derive(Debug)]
pub struct CommandSpec {
    pub id: CommandId,
    pub canonical_name: &'static str,
    pub aliases: &'static [&'static str],
    pub arguments: CommandArgumentSchema,
    pub effect: ToolEffect,
    pub required_capabilities: &'static [ToolResource],
    pub frontends: FrontendSet,
    pub completion: CompletionKind,
    pub help: &'static [CommandHelp],
}

/// Non-identity command metadata grouped for const construction.
#[derive(Debug, Clone, Copy)]
pub struct CommandShape {
    pub arguments: CommandArgumentSchema,
    pub effect: ToolEffect,
    pub required_capabilities: &'static [ToolResource],
    pub frontends: FrontendSet,
    pub completion: CompletionKind,
}

impl CommandShape {
    #[must_use]
    pub const fn new(
        arguments: CommandArgumentSchema,
        effect: ToolEffect,
        required_capabilities: &'static [ToolResource],
        frontends: FrontendSet,
        completion: CompletionKind,
    ) -> Self {
        Self {
            arguments,
            effect,
            required_capabilities,
            frontends,
            completion,
        }
    }
}

impl CommandSpec {
    #[must_use]
    pub const fn new(
        id: CommandId,
        canonical_name: &'static str,
        aliases: &'static [&'static str],
        shape: CommandShape,
        help: &'static [CommandHelp],
    ) -> Self {
        Self {
            id,
            canonical_name,
            aliases,
            arguments: shape.arguments,
            effect: shape.effect,
            required_capabilities: shape.required_capabilities,
            frontends: shape.frontends,
            completion: shape.completion,
            help,
        }
    }
}

const LEGACY_CORE: &str = "Slash Commands";
const LEGACY_MEMORY: &str = "Memory Commands (auto-learning)";
const LEGACY_ACTIVITY: &str = "Activity Commands";
const LEGACY_PLUGIN: &str = "Plugin Commands";
const LEGACY_SKILLS: &str = "Skill Commands";
const LEGACY_TIME: &str = "Time Travel & Session Shape";
const LEGACY_MANAGEMENT: &str = "Management Overlays";
const TUI_CORE: &str = "TUI Slash Commands";
const TUI_SESSIONS: &str = "TUI Sessions";
const TUI_DIAGNOSTICS: &str = "TUI Diagnostics";
const TUI_SKILLS: &str = "TUI Skills";

const READ: &[ToolResource] = &[ToolResource::WorkspaceRead];
const WRITE: &[ToolResource] = &[ToolResource::WorkspaceWrite];
const PROCESS_READ: &[ToolResource] = &[ToolResource::Process, ToolResource::WorkspaceRead];
const PROCESS_WRITE: &[ToolResource] = &[ToolResource::Process, ToolResource::WorkspaceWrite];
const NETWORK_SECRETS: &[ToolResource] = &[ToolResource::Network, ToolResource::Secrets];
const SECRETS: &[ToolResource] = &[ToolResource::Secrets];
const MCP: &[ToolResource] = &[ToolResource::Mcp];
const MEMORY: &[ToolResource] = &[ToolResource::Memory];

macro_rules! spec {
    ($id:ident, $name:literal, $aliases:expr, $args:expr, $effect:ident, $caps:expr, $frontends:expr, $completion:ident, [$($help:expr),* $(,)?]) => {
        CommandSpec::new(
            CommandId::$id,
            $name,
            $aliases,
            CommandShape::new(
                $args,
                ToolEffect::$effect,
                $caps,
                $frontends,
                CompletionKind::$completion,
            ),
            &[$($help),*],
        )
    };
}

/// Built-in and dynamic command definitions in stable presentation order.
pub static COMMAND_SPECS: &[CommandSpec] = &[
    spec!(
        Help,
        "help",
        &["?"],
        CommandArgumentSchema::Ignored,
        ReadOnly,
        &[],
        FrontendSet::BOTH,
        Command,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/help, /?",
                "Show this help message"
            ),
            help(
                FrontendSet::TUI,
                TUI_CORE,
                "/help, ?",
                "Show the TUI help overlay"
            ),
        ]
    ),
    spec!(
        New,
        "new",
        &["clear"],
        CommandArgumentSchema::Ignored,
        SessionMutation,
        &[],
        FrontendSet::BOTH,
        Command,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/new, /clear",
                "Start a new conversation"
            ),
            help(
                FrontendSet::TUI,
                TUI_CORE,
                "/new, /clear",
                "Clear the visible transcript and start a new conversation"
            ),
        ]
    ),
    spec!(
        Sessions,
        "sessions",
        &["list"],
        CommandArgumentSchema::Ignored,
        ReadOnly,
        &[],
        FrontendSet::BOTH,
        Command,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/sessions, /list",
                "List saved sessions"
            ),
            help(
                FrontendSet::TUI,
                TUI_SESSIONS,
                "/sessions, /list",
                "List saved sessions"
            ),
        ]
    ),
    spec!(
        Continue,
        "continue",
        &["load", "resume"],
        CommandArgumentSchema::OptionalText {
            value_name: "session"
        },
        SessionMutation,
        &[],
        FrontendSet::BOTH,
        FreeText,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/continue [n|id], /load [id], /resume",
                "Continue a saved session"
            ),
            help(
                FrontendSet::TUI,
                TUI_SESSIONS,
                "/resume, /continue, /load <id>",
                "Open the session picker or resume by ID"
            ),
        ]
    ),
    spec!(
        Exit,
        "exit",
        &["quit", "q"],
        CommandArgumentSchema::Ignored,
        SessionMutation,
        &[],
        FrontendSet::BOTH,
        Command,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/exit, /quit, /q",
                "Exit the chat"
            ),
            help(FrontendSet::TUI, TUI_CORE, "/exit, /quit", "Exit the TUI"),
        ]
    ),
    spec!(
        History,
        "history",
        &[],
        CommandArgumentSchema::Ignored,
        ReadOnly,
        &[],
        FrontendSet::LEGACY,
        Command,
        [help(
            FrontendSet::LEGACY,
            LEGACY_CORE,
            "/history",
            "Show conversation history"
        )]
    ),
    spec!(
        Model,
        "model",
        &["models"],
        CommandArgumentSchema::OptionalText { value_name: "name" },
        ReadOnly,
        &[],
        FrontendSet::BOTH,
        Model,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/model [list|name], /models",
                "Show, list, or switch models"
            ),
            help(
                FrontendSet::TUI,
                TUI_CORE,
                "/model [list|name], /models",
                "Show, list, or switch models"
            ),
        ]
    ),
    spec!(
        Export,
        "export",
        &[],
        CommandArgumentSchema::Ignored,
        ExternalMutation,
        WRITE,
        FrontendSet::BOTH,
        Command,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/export",
                "Export conversation to markdown"
            ),
            help(
                FrontendSet::TUI,
                TUI_SESSIONS,
                "/export",
                "Export the current conversation to markdown"
            ),
        ]
    ),
    spec!(
        Compact,
        "compact",
        &["summarize"],
        CommandArgumentSchema::OptionalText {
            value_name: "instructions"
        },
        SessionMutation,
        &[],
        FrontendSet::LEGACY,
        FreeText,
        [help(
            FrontendSet::LEGACY,
            LEGACY_CORE,
            "/compact [instructions], /summarize",
            "Summarize old messages to save context"
        )]
    ),
    spec!(
        Editor,
        "editor",
        &["edit", "e"],
        CommandArgumentSchema::Ignored,
        ExternalMutation,
        &[ToolResource::Process],
        FrontendSet::LEGACY,
        Command,
        [help(
            FrontendSet::LEGACY,
            LEGACY_CORE,
            "/editor, /edit, /e",
            "Open the configured external editor"
        )]
    ),
    spec!(
        Undo,
        "undo",
        &[],
        CommandArgumentSchema::Ignored,
        SessionMutation,
        &[],
        FrontendSet::BOTH,
        Command,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/undo",
                "Undo last message exchange"
            ),
            help(
                FrontendSet::TUI,
                TUI_SESSIONS,
                "/undo",
                "Undo the last message exchange"
            ),
        ]
    ),
    spec!(
        Redo,
        "redo",
        &[],
        CommandArgumentSchema::Ignored,
        SessionMutation,
        &[],
        FrontendSet::BOTH,
        Command,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/redo",
                "Redo last undone exchange"
            ),
            help(
                FrontendSet::TUI,
                TUI_SESSIONS,
                "/redo",
                "Redo the last undone message exchange"
            ),
        ]
    ),
    spec!(
        Rewind,
        "rewind",
        &["checkpoint"],
        CommandArgumentSchema::OptionalPositiveInteger {
            value_name: "turns"
        },
        SessionMutation,
        &[],
        FrontendSet::BOTH,
        PositiveInteger,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_TIME,
                "/rewind [N], /checkpoint [N]",
                "Show turns or rewind the last N turns"
            ),
            help(
                FrontendSet::TUI,
                TUI_SESSIONS,
                "/rewind [N]",
                "Show turns or rewind the last N turns"
            ),
        ]
    ),
    spec!(
        Teleport,
        "teleport",
        &[],
        CommandArgumentSchema::RequiredText { value_name: "name" },
        SessionMutation,
        READ,
        FrontendSet::LEGACY,
        FreeText,
        [help(
            FrontendSet::LEGACY,
            LEGACY_TIME,
            "/teleport <name>",
            "Restore a named branch snapshot"
        )]
    ),
    spec!(
        Thinkback,
        "thinkback",
        &[],
        CommandArgumentSchema::Ignored,
        ReadOnly,
        &[],
        FrontendSet::LEGACY,
        Command,
        [help(
            FrontendSet::LEGACY,
            LEGACY_TIME,
            "/thinkback",
            "Replay the latest assistant turn's saved thinking block"
        )]
    ),
    spec!(
        Copy,
        "copy",
        &["yank", "y"],
        CommandArgumentSchema::Ignored,
        ExternalMutation,
        &[],
        FrontendSet::BOTH,
        Command,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/copy, /yank, /y",
                "Copy last assistant response to clipboard"
            ),
            help(
                FrontendSet::TUI,
                TUI_CORE,
                "/copy",
                "Copy last assistant response to clipboard"
            ),
        ]
    ),
    spec!(
        Init,
        "init",
        &[],
        CommandArgumentSchema::Ignored,
        WorkspaceMutation,
        WRITE,
        FrontendSet::BOTH,
        Command,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/init",
                "Initialize project config and skills directory"
            ),
            help(
                FrontendSet::TUI,
                TUI_DIAGNOSTICS,
                "/init",
                "Initialize project config if absent"
            ),
        ]
    ),
    spec!(
        Review,
        "review",
        &[],
        CommandArgumentSchema::OptionalText {
            value_name: "branch"
        },
        ReadOnly,
        PROCESS_READ,
        FrontendSet::BOTH,
        FreeText,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/review [branch]",
                "Review uncommitted changes or compare a branch"
            ),
            help(
                FrontendSet::TUI,
                TUI_DIAGNOSTICS,
                "/review",
                "Show a truncated git diff for review"
            ),
        ]
    ),
    spec!(
        Status,
        "status",
        &["info"],
        CommandArgumentSchema::Ignored,
        ReadOnly,
        &[],
        FrontendSet::BOTH,
        Command,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/status, /info",
                "Show session status"
            ),
            help(
                FrontendSet::TUI,
                TUI_CORE,
                "/status",
                "Show model, provider, effort, and token estimate"
            ),
        ]
    ),
    spec!(
        Connect,
        "connect",
        &["auth"],
        CommandArgumentSchema::Ignored,
        ExternalMutation,
        SECRETS,
        FrontendSet::LEGACY,
        Command,
        [help(
            FrontendSet::LEGACY,
            LEGACY_CORE,
            "/connect, /auth",
            "Configure API keys for providers"
        )]
    ),
    spec!(
        Theme,
        "theme",
        &["themes"],
        CommandArgumentSchema::OptionalText { value_name: "name" },
        ExternalMutation,
        &[],
        FrontendSet::LEGACY,
        FreeText,
        [help(
            FrontendSet::LEGACY,
            LEGACY_CORE,
            "/theme [name], /themes",
            "List or switch color themes"
        )]
    ),
    spec!(
        Plan,
        "plan",
        &[],
        CommandArgumentSchema::Ignored,
        SessionMutation,
        &[],
        FrontendSet::BOTH,
        Command,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/plan",
                "Toggle between Build and Plan modes"
            ),
            help(
                FrontendSet::TUI,
                TUI_CORE,
                "/plan",
                "Toggle between Build and Plan modes"
            ),
        ]
    ),
    spec!(
        Mode,
        "mode",
        &[],
        CommandArgumentSchema::OptionalText {
            value_name: "preset"
        },
        SessionMutation,
        &[],
        FrontendSet::BOTH,
        FreeText,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/mode [preset]",
                "Show or switch behavioral mode"
            ),
            help(
                FrontendSet::TUI,
                TUI_CORE,
                "/mode",
                "Toggle between Build and Plan modes"
            ),
        ]
    ),
    spec!(
        Vim,
        "vim",
        &[],
        CommandArgumentSchema::Ignored,
        SessionMutation,
        &[],
        FrontendSet::LEGACY,
        Command,
        [help(
            FrontendSet::LEGACY,
            LEGACY_CORE,
            "/vim",
            "Toggle vim mode"
        )]
    ),
    spec!(
        Agents,
        "agents",
        &[],
        CommandArgumentSchema::Ignored,
        ReadOnly,
        &[],
        FrontendSet::LEGACY,
        Command,
        [help(
            FrontendSet::LEGACY,
            LEGACY_CORE,
            "/agents",
            "Show available subagent types"
        )]
    ),
    spec!(
        Keybindings,
        "keybindings",
        &["keys", "bindings"],
        CommandArgumentSchema::Ignored,
        ReadOnly,
        &[],
        FrontendSet::BOTH,
        Command,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/keybindings, /keys, /bindings",
                "Show configured keyboard shortcuts"
            ),
            help(
                FrontendSet::TUI,
                TUI_CORE,
                "/keybindings, /keys, /bindings",
                "Show effective keyboard shortcuts"
            ),
        ]
    ),
    spec!(
        Rename,
        "rename",
        &["title"],
        CommandArgumentSchema::RequiredText {
            value_name: "title"
        },
        SessionMutation,
        &[],
        FrontendSet::BOTH,
        FreeText,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/rename <title>, /title <title>",
                "Rename the current session"
            ),
            help(
                FrontendSet::TUI,
                TUI_SESSIONS,
                "/rename <title>",
                "Rename the current session"
            ),
        ]
    ),
    spec!(
        Version,
        "version",
        &["v", "about"],
        CommandArgumentSchema::Ignored,
        ReadOnly,
        &[],
        FrontendSet::LEGACY,
        Command,
        [help(
            FrontendSet::LEGACY,
            LEGACY_CORE,
            "/version, /v, /about",
            "Show version and system information"
        )]
    ),
    spec!(
        Doctor,
        "doctor",
        &[],
        CommandArgumentSchema::Ignored,
        ReadOnly,
        &[],
        FrontendSet::BOTH,
        Command,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/doctor",
                "Run inline diagnostics"
            ),
            help(
                FrontendSet::TUI,
                TUI_DIAGNOSTICS,
                "/doctor",
                "Run inline diagnostics"
            ),
        ]
    ),
    spec!(
        Config,
        "config",
        &[],
        CommandArgumentSchema::OptionalText {
            value_name: "query"
        },
        ReadOnly,
        &[],
        FrontendSet::LEGACY,
        FreeText,
        [help(
            FrontendSet::LEGACY,
            LEGACY_CORE,
            "/config [path]",
            "Show configuration or config file locations"
        )]
    ),
    spec!(
        Mcp,
        "mcp",
        &[],
        CommandArgumentSchema::OptionalText {
            value_name: "subcommand"
        },
        ReadOnly,
        MCP,
        FrontendSet::LEGACY,
        Plugin,
        [help(
            FrontendSet::LEGACY,
            LEGACY_MANAGEMENT,
            "/mcp [list|help]",
            "Show configured MCP servers"
        )]
    ),
    spec!(
        Permissions,
        "permissions",
        &[],
        CommandArgumentSchema::Ignored,
        ReadOnly,
        &[],
        FrontendSet::LEGACY,
        Command,
        [help(
            FrontendSet::LEGACY,
            LEGACY_MANAGEMENT,
            "/permissions",
            "Show permission rules and MCP allowlists"
        )]
    ),
    spec!(
        Hooks,
        "hooks",
        &[],
        CommandArgumentSchema::Ignored,
        ReadOnly,
        &[],
        FrontendSet::LEGACY,
        Command,
        [help(
            FrontendSet::LEGACY,
            LEGACY_MANAGEMENT,
            "/hooks",
            "Show configured lifecycle hooks"
        )]
    ),
    spec!(
        Debug,
        "debug",
        &[],
        CommandArgumentSchema::Ignored,
        ReadOnly,
        &[],
        FrontendSet::LEGACY,
        Command,
        [help(
            FrontendSet::LEGACY,
            LEGACY_CORE,
            "/debug",
            "Show debug paths, environment, and configuration"
        )]
    ),
    spec!(
        Effort,
        "effort",
        &[],
        CommandArgumentSchema::OptionalText {
            value_name: "level"
        },
        SessionMutation,
        &[],
        FrontendSet::BOTH,
        FreeText,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/effort [level]",
                "Set or cycle effort level"
            ),
            help(
                FrontendSet::TUI,
                TUI_CORE,
                "/effort [low|medium|high|max|xhigh|auto]",
                "Set or cycle effort level"
            ),
        ]
    ),
    spec!(
        Fast,
        "fast",
        &[],
        CommandArgumentSchema::Ignored,
        SessionMutation,
        &[],
        FrontendSet::LEGACY,
        Command,
        [help(
            FrontendSet::LEGACY,
            LEGACY_TIME,
            "/fast",
            "Set low effort and select a known fast model"
        )]
    ),
    spec!(
        Find,
        "find",
        &["f"],
        CommandArgumentSchema::RequiredText {
            value_name: "query"
        },
        ReadOnly,
        READ,
        FrontendSet::LEGACY,
        FreeText,
        [help(
            FrontendSet::LEGACY,
            LEGACY_CORE,
            "/find <query>, /f <query>",
            "Fuzzy-find files in the project"
        )]
    ),
    spec!(
        Memory,
        "memory",
        &["mem"],
        CommandArgumentSchema::OptionalText {
            value_name: "subcommand"
        },
        Destructive,
        MEMORY,
        FrontendSet::LEGACY,
        FreeText,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_MEMORY,
                "/memory [list|patterns|prefs]",
                "Show causal technical-learning status and data"
            ),
            help(
                FrontendSet::LEGACY,
                LEGACY_MEMORY,
                "/memory errors <path>",
                "Show legacy error-pattern data"
            ),
            help(
                FrontendSet::LEGACY,
                LEGACY_MEMORY,
                "/memory files <path>",
                "Show legacy co-edit relationship data"
            ),
            help(
                FrontendSet::LEGACY,
                LEGACY_MEMORY,
                "/memory reset",
                "Reset all learned data with confirmation"
            ),
        ]
    ),
    spec!(
        Activity,
        "activity",
        &["act"],
        CommandArgumentSchema::OptionalText {
            value_name: "subcommand"
        },
        ReadOnly,
        MEMORY,
        FrontendSet::LEGACY,
        FreeText,
        [help(
            FrontendSet::LEGACY,
            LEGACY_ACTIVITY,
            "/activity [sessions|files|issues]",
            "Show current or recent session activity"
        )]
    ),
    spec!(
        Plugin,
        "plugin",
        &["plugins"],
        CommandArgumentSchema::OptionalText {
            value_name: "subcommand"
        },
        ExternalMutation,
        &[],
        FrontendSet::LEGACY,
        Plugin,
        [help(
            FrontendSet::LEGACY,
            LEGACY_PLUGIN,
            "/plugin [help|install|manage]",
            "List, install, or manage plugins"
        ),]
    ),
    spec!(
        Skill,
        "skill",
        &["skills"],
        CommandArgumentSchema::OptionalText { value_name: "name" },
        SessionMutation,
        &[],
        FrontendSet::BOTH,
        Skill,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_SKILLS,
                "/skill [name], /skills",
                "List or invoke trusted skills"
            ),
            help(
                FrontendSet::TUI,
                TUI_SKILLS,
                "/skill [name], /skills",
                "List or invoke a trusted skill"
            ),
        ]
    ),
    spec!(
        Commit,
        "commit",
        &[],
        CommandArgumentSchema::Ignored,
        WorkspaceMutation,
        PROCESS_WRITE,
        FrontendSet::LEGACY,
        Command,
        [help(
            FrontendSet::LEGACY,
            LEGACY_CORE,
            "/commit",
            "Stage changes and commit with an auto-generated message"
        )]
    ),
    spec!(
        CommitPushPr,
        "commit-push-pr",
        &[],
        CommandArgumentSchema::Ignored,
        ExternalMutation,
        PROCESS_WRITE,
        FrontendSet::LEGACY,
        Command,
        [help(
            FrontendSet::LEGACY,
            LEGACY_CORE,
            "/commit-push-pr",
            "Commit, push, and create a pull request"
        )]
    ),
    spec!(
        Cost,
        "cost",
        &[],
        CommandArgumentSchema::Ignored,
        ReadOnly,
        &[],
        FrontendSet::BOTH,
        Command,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/cost",
                "Show session cost estimate"
            ),
            help(
                FrontendSet::TUI,
                TUI_DIAGNOSTICS,
                "/cost",
                "Show session cost estimate"
            ),
        ]
    ),
    spec!(
        Context,
        "context",
        &[],
        CommandArgumentSchema::Ignored,
        ReadOnly,
        &[],
        FrontendSet::BOTH,
        Command,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_CORE,
                "/context",
                "Show context window usage breakdown"
            ),
            help(
                FrontendSet::TUI,
                TUI_DIAGNOSTICS,
                "/context",
                "Show context usage breakdown"
            ),
        ]
    ),
    spec!(
        Login,
        "login",
        &[],
        CommandArgumentSchema::Ignored,
        ReadOnly,
        SECRETS,
        FrontendSet::LEGACY,
        Command,
        [help(
            FrontendSet::LEGACY,
            LEGACY_CORE,
            "/login",
            "Check authentication status"
        )]
    ),
    spec!(
        Logout,
        "logout",
        &[],
        CommandArgumentSchema::Ignored,
        ReadOnly,
        &[],
        FrontendSet::LEGACY,
        Command,
        [help(
            FrontendSet::LEGACY,
            LEGACY_CORE,
            "/logout",
            "Show how to clear Claude credentials manually"
        )]
    ),
    spec!(
        AddDir,
        "add-dir",
        &[],
        CommandArgumentSchema::RequiredText { value_name: "path" },
        SessionMutation,
        READ,
        FrontendSet::LEGACY,
        Path,
        [help(
            FrontendSet::LEGACY,
            LEGACY_MANAGEMENT,
            "/add-dir <path>",
            "Add a working directory to the session scope"
        )]
    ),
    spec!(
        Branch,
        "branch",
        &[],
        CommandArgumentSchema::OptionalText { value_name: "name" },
        WorkspaceMutation,
        WRITE,
        FrontendSet::LEGACY,
        FreeText,
        [help(
            FrontendSet::LEGACY,
            LEGACY_TIME,
            "/branch [name]",
            "Save a named conversation snapshot"
        )]
    ),
    spec!(
        Btw,
        "btw",
        &[],
        CommandArgumentSchema::RequiredText {
            value_name: "question"
        },
        SessionMutation,
        &[],
        FrontendSet::LEGACY,
        FreeText,
        [help(
            FrontendSet::LEGACY,
            LEGACY_CORE,
            "/btw <question>",
            "Ask a side question without changing the main conversation"
        )]
    ),
    spec!(
        Provider,
        "provider",
        &[],
        CommandArgumentSchema::OptionalText { value_name: "name" },
        ExternalMutation,
        NETWORK_SECRETS,
        FrontendSet::TUI,
        Provider,
        [help(
            FrontendSet::TUI,
            TUI_CORE,
            "/provider [name]",
            "Show or switch provider"
        )]
    ),
    spec!(
        Files,
        "files",
        &[],
        CommandArgumentSchema::OptionalText {
            value_name: "directory"
        },
        ReadOnly,
        READ,
        FrontendSet::TUI,
        Path,
        [help(
            FrontendSet::TUI,
            TUI_DIAGNOSTICS,
            "/files [dir]",
            "List files in the current or given directory"
        )]
    ),
    spec!(
        Diff,
        "diff",
        &[],
        CommandArgumentSchema::Ignored,
        ReadOnly,
        PROCESS_READ,
        FrontendSet::TUI,
        Command,
        [help(
            FrontendSet::TUI,
            TUI_DIAGNOSTICS,
            "/diff",
            "Show git diff summary"
        )]
    ),
    spec!(
        DynamicPlugin,
        "plugin-command",
        &[],
        CommandArgumentSchema::OptionalText {
            value_name: "arguments"
        },
        SessionMutation,
        &[],
        FrontendSet::BOTH,
        Plugin,
        [
            help(
                FrontendSet::LEGACY,
                LEGACY_PLUGIN,
                "/<plugin>:<command> [args]",
                "Run a namespaced plugin command"
            ),
            help(
                FrontendSet::TUI,
                TUI_SKILLS,
                "/<plugin>:<command> [args]",
                "Run a namespaced plugin command, skill, or agent"
            )
        ]
    ),
    spec!(
        DirectSkill,
        "skill-command",
        &[],
        CommandArgumentSchema::OptionalText {
            value_name: "arguments"
        },
        SessionMutation,
        &[],
        FrontendSet::TUI,
        Skill,
        [help(
            FrontendSet::TUI,
            TUI_SKILLS,
            "/<skill-name> [args]",
            "Invoke a trusted skill by name"
        )]
    ),
];

/// One generated help row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandHelpEntry {
    pub invocation: &'static str,
    pub description: &'static str,
}

/// One generated help section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandHelpSection {
    pub title: &'static str,
    pub commands: Vec<CommandHelpEntry>,
}

/// Generated registry matrix row used by diagnostics and deterministic tests.
#[derive(Debug, Clone, Copy)]
pub struct CommandMatrixRow {
    pub id: CommandId,
    pub canonical_name: &'static str,
    pub aliases: &'static [&'static str],
    pub arguments: CommandArgumentSchema,
    pub effect: ToolEffect,
    pub required_capabilities: &'static [ToolResource],
    pub frontend: CommandFrontend,
    pub completion: CompletionKind,
}

/// A pure, typed proposal. Construction does not read files, load plugins,
/// print output, reserve budget, or otherwise touch application state.
#[derive(Debug, Clone)]
pub struct ProposedCommand {
    spec: &'static CommandSpec,
    invoked_name: String,
    arguments: CommandArguments,
    original_arguments: String,
    namespace: Option<String>,
    component: Option<String>,
}

impl ProposedCommand {
    #[must_use]
    pub const fn id(&self) -> CommandId {
        self.spec.id
    }

    #[must_use]
    pub const fn spec(&self) -> &'static CommandSpec {
        self.spec
    }

    #[must_use]
    pub fn invoked_name(&self) -> &str {
        &self.invoked_name
    }

    #[must_use]
    pub const fn arguments(&self) -> &CommandArguments {
        &self.arguments
    }

    #[must_use]
    pub fn arguments_text(&self) -> &str {
        &self.original_arguments
    }

    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    #[must_use]
    pub fn component(&self) -> Option<&str> {
        self.component.as_deref()
    }
}

/// Registry construction failures are deterministic programmer/configuration
/// errors and never degrade to last-write-wins behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandRegistryError {
    EmptyName {
        id: CommandId,
    },
    UnemittableName {
        name: &'static str,
    },
    DuplicateName {
        name: &'static str,
    },
    DuplicateId {
        id: CommandId,
    },
    NoFrontend {
        name: &'static str,
    },
    EmptyHelp {
        name: &'static str,
    },
    InvalidHelp {
        name: &'static str,
        reason: &'static str,
    },
    UnsupportedEffectCapabilities {
        name: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for CommandRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName { id } => {
                write!(formatter, "command {id:?} has an empty canonical name")
            }
            Self::UnemittableName { name } => write!(
                formatter,
                "command name or alias {name:?} cannot be emitted as a slash command"
            ),
            Self::DuplicateName { name } => {
                write!(formatter, "duplicate command name or alias {name:?}")
            }
            Self::DuplicateId { id } => write!(formatter, "duplicate command handler id {id:?}"),
            Self::NoFrontend { name } => write!(
                formatter,
                "command {name:?} is unavailable on every frontend"
            ),
            Self::EmptyHelp { name } => write!(
                formatter,
                "command {name:?} has no help/completion metadata"
            ),
            Self::InvalidHelp { name, reason } => write!(
                formatter,
                "command {name:?} has invalid help metadata: {reason}"
            ),
            Self::UnsupportedEffectCapabilities { name, reason } => write!(
                formatter,
                "command {name:?} has an unsupported effect/capability combination: {reason}"
            ),
        }
    }
}

impl std::error::Error for CommandRegistryError {}

/// Pure parse failure suitable for either frontend's renderer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandParseError {
    NotACommand,
    UnknownCommand {
        name: String,
    },
    FrontendUnavailable {
        name: String,
        frontend: CommandFrontend,
    },
    InvalidArguments {
        invocation: String,
        reason: String,
    },
}

impl fmt::Display for CommandParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotACommand => formatter.write_str("input is not a slash command"),
            Self::UnknownCommand { name } => write!(
                formatter,
                "Unknown command: /{name}. Type /help for commands."
            ),
            Self::FrontendUnavailable { name, frontend } => write!(
                formatter,
                "Command /{name} is not available in the {frontend:?} frontend."
            ),
            Self::InvalidArguments { invocation, reason } => {
                write!(formatter, "Invalid arguments for /{invocation}: {reason}")
            }
        }
    }
}

impl std::error::Error for CommandParseError {}

/// Admission failure before a frontend handler is allowed to run.
#[derive(Debug)]
pub enum CommandExecutionError {
    ForeignProposal {
        command: &'static str,
    },
    EffectRunRequired {
        command: &'static str,
        effect: ToolEffect,
    },
    RunRequired {
        command: &'static str,
        capability: ToolResource,
    },
    Capability {
        command: &'static str,
        source: crate::tools::ToolCapabilityError,
    },
    ModeDenied {
        command: &'static str,
        reason: String,
    },
    Budget {
        command: &'static str,
        reason: String,
    },
}

impl fmt::Display for CommandExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForeignProposal { command } => write!(
                formatter,
                "command /{command} was not proposed by this registry"
            ),
            Self::EffectRunRequired { command, effect } => write!(
                formatter,
                "command /{command} requires an active run for {} authority",
                effect.as_str()
            ),
            Self::RunRequired {
                command,
                capability,
            } => write!(
                formatter,
                "command /{command} requires an active {capability:?} run capability"
            ),
            Self::Capability { command, source } => {
                write!(formatter, "command /{command} was denied: {source}")
            }
            Self::ModeDenied { command, reason } => write!(
                formatter,
                "command /{command} was denied by the active mode: {reason}"
            ),
            Self::Budget { command, reason } => write!(
                formatter,
                "command /{command} was denied by the run budget: {reason}"
            ),
        }
    }
}

impl std::error::Error for CommandExecutionError {}

/// Collision-checked typed command registry.
pub struct CommandRegistry {
    specs: &'static [CommandSpec],
    names: BTreeMap<&'static str, &'static CommandSpec>,
    ids: BTreeMap<CommandId, &'static CommandSpec>,
}

impl CommandRegistry {
    /// Validate and build a registry without silently overwriting collisions.
    ///
    /// # Errors
    ///
    /// Returns a structural error for duplicate/unemittable spellings,
    /// duplicate handler identities, missing frontend/help metadata, or an
    /// unsupported effect/capability declaration.
    pub fn try_new(specs: &'static [CommandSpec]) -> Result<Self, CommandRegistryError> {
        let mut names = BTreeMap::new();
        let mut ids = BTreeMap::new();
        let mut declared_names = BTreeSet::new();
        for spec in specs {
            validate_spec(spec)?;
            if ids.insert(spec.id, spec).is_some() {
                return Err(CommandRegistryError::DuplicateId { id: spec.id });
            }
            for name in std::iter::once(spec.canonical_name).chain(spec.aliases.iter().copied()) {
                if !is_emittable_name(name) {
                    return Err(CommandRegistryError::UnemittableName { name });
                }
                if !declared_names.insert(name) {
                    return Err(CommandRegistryError::DuplicateName { name });
                }
                if !matches!(spec.id, CommandId::DynamicPlugin | CommandId::DirectSkill) {
                    names.insert(name, spec);
                }
            }
        }
        let registry = Self { specs, names, ids };
        registry.validate_help_routes()?;
        Ok(registry)
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&'static CommandSpec> {
        self.names.get(name).copied()
    }

    #[must_use]
    pub fn spec(&self, id: CommandId) -> Option<&'static CommandSpec> {
        self.ids.get(&id).copied()
    }

    /// Parse user input without performing I/O or changing state.
    ///
    /// # Errors
    ///
    /// Returns a typed error for non-command input, unknown or unavailable
    /// commands, and arguments that do not satisfy the command's schema.
    pub fn parse(
        &self,
        input: &str,
        frontend: CommandFrontend,
    ) -> Result<ProposedCommand, CommandParseError> {
        let trimmed = input.trim();
        let command_line = if trimmed == "?" {
            "?"
        } else {
            trimmed
                .strip_prefix('/')
                .ok_or(CommandParseError::NotACommand)?
        };
        let split_at = command_line
            .find(char::is_whitespace)
            .unwrap_or(command_line.len());
        let invoked_name = command_line[..split_at].to_ascii_lowercase();
        let original_arguments = command_line[split_at..].trim().to_string();

        if let Some(spec) = self.get(&invoked_name) {
            if !spec.frontends.contains(frontend) {
                return Err(CommandParseError::FrontendUnavailable {
                    name: invoked_name,
                    frontend,
                });
            }
            let arguments = parse_arguments(spec, &original_arguments)?;
            return Ok(ProposedCommand {
                spec,
                invoked_name,
                arguments,
                original_arguments,
                namespace: None,
                component: None,
            });
        }

        if let Some((namespace, component)) = invoked_name.split_once(':') {
            if !namespace.is_empty() && !component.is_empty() {
                if let Some(spec) = self.ids.get(&CommandId::DynamicPlugin).copied() {
                    if spec.frontends.contains(frontend) {
                        let arguments = parse_arguments(spec, &original_arguments)?;
                        return Ok(ProposedCommand {
                            spec,
                            invoked_name: invoked_name.clone(),
                            arguments,
                            original_arguments,
                            namespace: Some(namespace.to_string()),
                            component: Some(component.to_string()),
                        });
                    }
                }
            }
        }

        if frontend == CommandFrontend::Tui && is_emittable_name(&invoked_name) {
            if let Some(spec) = self.ids.get(&CommandId::DirectSkill).copied() {
                let arguments = parse_arguments(spec, &original_arguments)?;
                return Ok(ProposedCommand {
                    spec,
                    invoked_name: invoked_name.clone(),
                    arguments,
                    original_arguments,
                    namespace: None,
                    component: Some(invoked_name),
                });
            }
        }

        Err(CommandParseError::UnknownCommand { name: invoked_name })
    }

    /// Names available to completion for one frontend, generated from the
    /// exact canonical/alias map used by parsing.
    #[must_use]
    pub fn completion_names(&self, frontend: CommandFrontend) -> Vec<&'static str> {
        self.names
            .iter()
            .filter_map(|(name, spec)| spec.frontends.contains(frontend).then_some(*name))
            .collect()
    }

    /// Help sections generated from definitions that dispatch on `frontend`.
    #[must_use]
    pub fn help_sections(&self, frontend: CommandFrontend) -> Vec<CommandHelpSection> {
        let mut sections = Vec::<CommandHelpSection>::new();
        for spec in self.specs {
            if !spec.frontends.contains(frontend) {
                continue;
            }
            for row in spec
                .help
                .iter()
                .filter(|row| row.frontends.contains(frontend))
            {
                if let Some(section) = sections
                    .iter_mut()
                    .find(|section| section.title == row.section)
                {
                    section.commands.push(CommandHelpEntry {
                        invocation: row.invocation,
                        description: row.description,
                    });
                } else {
                    sections.push(CommandHelpSection {
                        title: row.section,
                        commands: vec![CommandHelpEntry {
                            invocation: row.invocation,
                            description: row.description,
                        }],
                    });
                }
            }
        }
        sections
    }

    /// Effect/capability/argument matrix generated from dispatch definitions.
    #[must_use]
    pub fn matrix(&self, frontend: CommandFrontend) -> Vec<CommandMatrixRow> {
        self.specs
            .iter()
            .filter(|spec| spec.frontends.contains(frontend))
            .map(|spec| CommandMatrixRow {
                id: spec.id,
                canonical_name: spec.canonical_name,
                aliases: spec.aliases,
                arguments: spec.arguments,
                effect: spec.effect,
                required_capabilities: spec.required_capabilities,
                frontend,
                completion: spec.completion,
            })
            .collect()
    }

    /// Resolve the concrete effect of a proposal produced by this registry.
    ///
    /// Command families such as `/model`, `/memory`, and `/plugin` contain
    /// both read-only and mutating forms, so callers must use this query rather
    /// than treating the declaration's effect ceiling as the proposed action.
    ///
    /// # Errors
    ///
    /// Returns [`CommandExecutionError::ForeignProposal`] when `proposal` was
    /// created by another registry instance.
    pub fn resolved_effect(
        &self,
        proposal: &ProposedCommand,
    ) -> Result<ToolEffect, CommandExecutionError> {
        self.require_registered_proposal(proposal)?;
        Ok(concrete_effect(proposal))
    }

    /// Resolve the concrete capability set of a proposal produced by this
    /// registry.
    ///
    /// # Errors
    ///
    /// Returns [`CommandExecutionError::ForeignProposal`] when `proposal` was
    /// created by another registry instance.
    pub fn resolved_capabilities(
        &self,
        proposal: &ProposedCommand,
    ) -> Result<&'static [ToolResource], CommandExecutionError> {
        self.require_registered_proposal(proposal)?;
        Ok(concrete_capabilities(proposal))
    }

    fn validate_help_routes(&self) -> Result<(), CommandRegistryError> {
        for spec in self.specs {
            for row in spec.help {
                for form in row.invocation.split(',').map(str::trim) {
                    let root = form.split_whitespace().next().unwrap_or(form);
                    let routed_id = if root.contains("<plugin>") {
                        Some(CommandId::DynamicPlugin)
                    } else if root.contains("<skill-name>") {
                        Some(CommandId::DirectSkill)
                    } else {
                        self.get(root.trim_start_matches('/'))
                            .map(|target| target.id)
                    };
                    if routed_id != Some(spec.id) {
                        return Err(CommandRegistryError::InvalidHelp {
                            name: spec.canonical_name,
                            reason: "help invocation does not resolve to its declaring command",
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Admit and execute exactly one typed proposal through the canonical
    /// capability, mode, budget, and trace boundary.
    ///
    /// # Errors
    ///
    /// Returns a typed denial when the required run/capability is absent, the
    /// active mode refuses the effect, or command-budget accounting fails.
    pub fn execute<T>(
        &self,
        proposal: &ProposedCommand,
        run: Option<&ToolRunContext>,
        handler: impl FnOnce(&ProposedCommand) -> T,
    ) -> Result<T, CommandExecutionError> {
        let spec = proposal.spec;
        self.require_registered_proposal(proposal)?;
        let effect = concrete_effect(proposal);
        if run.is_none()
            && matches!(
                effect,
                ToolEffect::WorkspaceMutation
                    | ToolEffect::NetworkRead
                    | ToolEffect::ExternalMutation
                    | ToolEffect::Destructive
            )
        {
            return Err(CommandExecutionError::EffectRunRequired {
                command: spec.canonical_name,
                effect,
            });
        }
        for &capability in concrete_capabilities(proposal) {
            let Some(run) = run else {
                return Err(CommandExecutionError::RunRequired {
                    command: spec.canonical_name,
                    capability,
                });
            };
            run.require(capability)
                .map_err(|source| CommandExecutionError::Capability {
                    command: spec.canonical_name,
                    source,
                })?;
        }
        if matches!(
            effect,
            ToolEffect::WorkspaceMutation | ToolEffect::ExternalMutation | ToolEffect::Destructive
        ) {
            if let Some(run) = run {
                run.admit_runtime_mode_direct_operation(&format!(
                    "slash command /{}",
                    spec.canonical_name
                ))
                .map_err(|reason| CommandExecutionError::ModeDenied {
                    command: spec.canonical_name,
                    reason,
                })?;
            }
        }
        let reservation = run
            .map(|run| {
                run.budget()
                    .reserve(BudgetAmounts {
                        tool_calls: 1,
                        ..BudgetAmounts::default()
                    })
                    .map_err(|error| CommandExecutionError::Budget {
                        command: spec.canonical_name,
                        reason: error.to_string(),
                    })
            })
            .transpose()?;
        tracing::info!(
            target: "openclaudia::commands",
            event = "command_dispatch_started",
            command = spec.canonical_name,
            invoked_as = proposal.invoked_name(),
            effect = effect.as_str(),
            run_id = ?run.map(ToolRunContext::run_id).map(|id| id.to_string()),
            "Dispatching admitted interactive command"
        );
        let output = handler(proposal);
        if let Some(reservation) = reservation {
            reservation
                .commit()
                .map_err(|error| CommandExecutionError::Budget {
                    command: spec.canonical_name,
                    reason: error.to_string(),
                })?;
        }
        tracing::info!(
            target: "openclaudia::commands",
            event = "command_dispatch_completed",
            command = spec.canonical_name,
            effect = effect.as_str(),
            "Completed interactive command dispatch"
        );
        Ok(output)
    }

    fn require_registered_proposal(
        &self,
        proposal: &ProposedCommand,
    ) -> Result<(), CommandExecutionError> {
        let spec = proposal.spec;
        if self
            .spec(spec.id)
            .is_some_and(|registered| std::ptr::eq(registered, spec))
        {
            Ok(())
        } else {
            Err(CommandExecutionError::ForeignProposal {
                command: spec.canonical_name,
            })
        }
    }
}

fn parse_arguments(
    spec: &'static CommandSpec,
    raw: &str,
) -> Result<CommandArguments, CommandParseError> {
    let invalid = |reason: String| CommandParseError::InvalidArguments {
        invocation: spec.canonical_name.to_string(),
        reason,
    };
    match spec.arguments {
        CommandArgumentSchema::Ignored => Ok(CommandArguments::None),
        CommandArgumentSchema::OptionalText { .. } => Ok(CommandArguments::OptionalText(
            (!raw.is_empty()).then(|| raw.to_string()),
        )),
        CommandArgumentSchema::RequiredText { value_name } => {
            if raw.is_empty() {
                Err(invalid(format!("missing required <{value_name}>")))
            } else {
                Ok(CommandArguments::RequiredText(raw.to_string()))
            }
        }
        CommandArgumentSchema::OptionalPositiveInteger { value_name } => {
            if raw.is_empty() {
                Ok(CommandArguments::OptionalPositiveInteger(None))
            } else {
                raw.parse::<usize>()
                    .ok()
                    .filter(|value| *value > 0)
                    .map(|value| CommandArguments::OptionalPositiveInteger(Some(value)))
                    .ok_or_else(|| invalid(format!("<{value_name}> must be a positive integer")))
            }
        }
    }
}

fn concrete_capabilities(proposal: &ProposedCommand) -> &'static [ToolResource] {
    match proposal.id() {
        // Read-only/plugin listing forms do not require mutation or network
        // authority merely because another subcommand in the family does.
        CommandId::Memory
            if !first_argument(proposal)
                .is_some_and(|value| value.eq_ignore_ascii_case("reset")) =>
        {
            MEMORY
        }
        CommandId::Plugin
            if proposal.arguments_text().is_empty()
                || first_argument(proposal).is_some_and(|value| {
                    value.eq_ignore_ascii_case("help") || value.eq_ignore_ascii_case("manage")
                }) =>
        {
            &[]
        }
        CommandId::Model if !is_model_listing(proposal) => &[],
        CommandId::Provider if proposal.arguments_text().is_empty() => &[],
        _ => proposal.spec.required_capabilities,
    }
}

fn concrete_effect(proposal: &ProposedCommand) -> ToolEffect {
    match proposal.id() {
        CommandId::Memory
            if !first_argument(proposal)
                .is_some_and(|value| value.eq_ignore_ascii_case("reset")) =>
        {
            ToolEffect::ReadOnly
        }
        CommandId::Plugin
            if proposal.arguments_text().is_empty()
                || first_argument(proposal).is_some_and(|value| {
                    value.eq_ignore_ascii_case("help") || value.eq_ignore_ascii_case("manage")
                }) =>
        {
            ToolEffect::ReadOnly
        }
        CommandId::Model
            if proposal.arguments_text().is_empty() && proposal.invoked_name() != "models" =>
        {
            ToolEffect::ReadOnly
        }
        CommandId::Model if !is_model_listing(proposal) => ToolEffect::SessionMutation,
        CommandId::Provider | CommandId::Skill if proposal.arguments_text().is_empty() => {
            ToolEffect::ReadOnly
        }
        _ => proposal.spec.effect,
    }
}

fn first_argument(proposal: &ProposedCommand) -> Option<&str> {
    proposal.arguments_text().split_whitespace().next()
}

fn is_model_listing(proposal: &ProposedCommand) -> bool {
    proposal.invoked_name() == "models" || proposal.arguments_text().eq_ignore_ascii_case("list")
}

fn validate_spec(spec: &CommandSpec) -> Result<(), CommandRegistryError> {
    if spec.canonical_name.is_empty() {
        return Err(CommandRegistryError::EmptyName { id: spec.id });
    }
    if spec.frontends.is_empty() {
        return Err(CommandRegistryError::NoFrontend {
            name: spec.canonical_name,
        });
    }
    if spec.help.is_empty() {
        return Err(CommandRegistryError::EmptyHelp {
            name: spec.canonical_name,
        });
    }
    let mut documented_frontends = FrontendSet(0);
    for row in spec.help {
        if row.frontends.is_empty() || !row.frontends.is_subset_of(spec.frontends) {
            return Err(CommandRegistryError::InvalidHelp {
                name: spec.canonical_name,
                reason: "help frontend is empty or exceeds command availability",
            });
        }
        if row.section.trim().is_empty()
            || row.invocation.trim().is_empty()
            || row.description.trim().is_empty()
        {
            return Err(CommandRegistryError::InvalidHelp {
                name: spec.canonical_name,
                reason: "help section, invocation, and description must be non-empty",
            });
        }
        documented_frontends = FrontendSet(documented_frontends.0 | row.frontends.0);
    }
    if documented_frontends != spec.frontends {
        return Err(CommandRegistryError::InvalidHelp {
            name: spec.canonical_name,
            reason: "every available frontend must have help metadata",
        });
    }
    if matches!(spec.id, CommandId::DynamicPlugin | CommandId::DirectSkill)
        && !spec.aliases.is_empty()
    {
        return Err(CommandRegistryError::UnsupportedEffectCapabilities {
            name: spec.canonical_name,
            reason: "dynamic command patterns cannot declare fixed aliases",
        });
    }
    if spec.effect == ToolEffect::WorkspaceMutation
        && !spec
            .required_capabilities
            .contains(&ToolResource::WorkspaceWrite)
    {
        return Err(CommandRegistryError::UnsupportedEffectCapabilities {
            name: spec.canonical_name,
            reason: "workspace mutation must require workspace-write authority",
        });
    }
    if spec.effect == ToolEffect::NetworkRead
        && !spec.required_capabilities.contains(&ToolResource::Network)
    {
        return Err(CommandRegistryError::UnsupportedEffectCapabilities {
            name: spec.canonical_name,
            reason: "network read must require network authority",
        });
    }
    for (index, capability) in spec.required_capabilities.iter().enumerate() {
        if spec.required_capabilities[..index].contains(capability) {
            return Err(CommandRegistryError::UnsupportedEffectCapabilities {
                name: spec.canonical_name,
                reason: "required capability is duplicated",
            });
        }
    }
    Ok(())
}

fn is_emittable_name(name: &str) -> bool {
    !name.is_empty()
        && name == name.trim()
        && !name.starts_with('/')
        && !name.contains(char::is_whitespace)
        && !name.contains(':')
        && !name.bytes().any(|byte| byte.is_ascii_uppercase())
        && name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '?' | '_')
        })
}

/// Process-wide canonical registry. Construction is deterministic; a broken
/// built-in declaration aborts at composition instead of shipping a partial
/// command surface.
///
/// # Panics
///
/// Panics when a built-in declaration violates registry invariants. External
/// or dynamically discovered commands never enter this static construction.
#[must_use]
pub fn registry() -> &'static CommandRegistry {
    static REGISTRY: OnceLock<CommandRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| match CommandRegistry::try_new(COMMAND_SPECS) {
        Ok(registry) => registry,
        Err(error) => panic!("invalid built-in command registry: {error}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_registry_constructs_and_every_help_root_parses() {
        let registry = CommandRegistry::try_new(COMMAND_SPECS).expect("canonical registry");
        for frontend in [CommandFrontend::LegacyCli, CommandFrontend::Tui] {
            for section in registry.help_sections(frontend) {
                for row in section.commands {
                    let root = row
                        .invocation
                        .split(',')
                        .next()
                        .expect("help invocation")
                        .split_whitespace()
                        .next()
                        .expect("help root");
                    if root.contains("<plugin>") || root.contains("<skill-name>") {
                        let concrete = root
                            .replace("<plugin>", "demo")
                            .replace("<command>", "run")
                            .replace("<skill-name>", "demo-skill");
                        assert!(
                            registry.parse(&concrete, frontend).is_ok(),
                            "{frontend:?}: generated help route {root:?} as {concrete:?}"
                        );
                        continue;
                    }
                    let name = root.trim_start_matches('/');
                    assert!(
                        registry
                            .get(name)
                            .is_some_and(|spec| spec.frontends.contains(frontend)),
                        "{frontend:?}: {root}"
                    );
                }
            }
        }
    }

    #[test]
    fn construction_rejects_duplicate_and_unemittable_aliases() {
        static DUPLICATE: &[CommandSpec] = &[
            CommandSpec::new(
                CommandId::Help,
                "help",
                &["same"],
                CommandShape::new(
                    CommandArgumentSchema::Ignored,
                    ToolEffect::ReadOnly,
                    &[],
                    FrontendSet::BOTH,
                    CompletionKind::Command,
                ),
                &[help(FrontendSet::BOTH, "Test", "/help", "help")],
            ),
            CommandSpec::new(
                CommandId::Exit,
                "exit",
                &["same"],
                CommandShape::new(
                    CommandArgumentSchema::Ignored,
                    ToolEffect::ReadOnly,
                    &[],
                    FrontendSet::BOTH,
                    CompletionKind::Command,
                ),
                &[help(FrontendSet::BOTH, "Test", "/exit", "exit")],
            ),
        ];
        static UNEMITTABLE: &[CommandSpec] = &[CommandSpec::new(
            CommandId::Help,
            "help",
            &["bad alias"],
            CommandShape::new(
                CommandArgumentSchema::Ignored,
                ToolEffect::ReadOnly,
                &[],
                FrontendSet::BOTH,
                CompletionKind::Command,
            ),
            &[help(FrontendSet::BOTH, "Test", "/help", "help")],
        )];
        assert!(matches!(
            CommandRegistry::try_new(DUPLICATE),
            Err(CommandRegistryError::DuplicateName { name: "same" })
        ));
        assert!(matches!(
            CommandRegistry::try_new(UNEMITTABLE),
            Err(CommandRegistryError::UnemittableName { name: "bad alias" })
        ));
    }

    #[test]
    fn parsing_dynamic_commands_is_pure_and_namespaced() {
        let registry = registry();
        let plugin = registry
            .parse("/demo:fix src/lib.rs", CommandFrontend::LegacyCli)
            .expect("plugin proposal");
        assert_eq!(plugin.id(), CommandId::DynamicPlugin);
        assert_eq!(plugin.namespace(), Some("demo"));
        assert_eq!(plugin.component(), Some("fix"));
        assert_eq!(plugin.arguments_text(), "src/lib.rs");

        let skill = registry
            .parse("/summarizer concise", CommandFrontend::Tui)
            .expect("direct skill proposal");
        assert_eq!(skill.id(), CommandId::DirectSkill);
        assert_eq!(skill.component(), Some("summarizer"));
    }

    #[test]
    fn generated_matrix_and_completion_cover_every_dispatchable_builtin() {
        let registry = registry();
        for frontend in [CommandFrontend::LegacyCli, CommandFrontend::Tui] {
            let matrix = registry.matrix(frontend);
            for name in registry.completion_names(frontend) {
                let spec = registry.get(name).expect("completion entry must resolve");
                assert!(matrix.iter().any(|row| row.id == spec.id));
            }
        }
    }

    #[test]
    fn effectful_command_without_a_run_never_reaches_its_handler() {
        let registry = registry();
        let proposal = registry
            .parse("/copy", CommandFrontend::LegacyCli)
            .expect("copy proposal");
        let invoked = std::cell::Cell::new(false);

        let error = registry
            .execute(&proposal, None, |_| invoked.set(true))
            .expect_err("external mutation must require a run");

        assert!(matches!(
            error,
            CommandExecutionError::EffectRunRequired {
                command: "copy",
                effect: ToolEffect::ExternalMutation,
            }
        ));
        assert!(!invoked.get(), "denied handlers must remain pure and inert");
    }
}
