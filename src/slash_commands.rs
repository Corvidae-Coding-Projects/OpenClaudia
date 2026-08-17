//! Canonical slash-command catalogues.
//!
//! There are two user-facing chat seams:
//! - the legacy line-oriented REPL, which exposes the broad command
//!   registry in [`SLASH_SECTIONS`]
//! - the default full-screen TUI, which currently implements a smaller
//!   command set in [`TUI_SLASH_SECTIONS`]
//!
//! Keep these catalogues honest for the seam that renders them. The TUI
//! must not import the legacy table and advertise commands that route to
//! `Unknown command` in `App::handle_slash_command`.
//!
//! Entries are grouped by section to preserve the visual structure each
//! seam renders. The legacy CLI printer renders each section as its own
//! heading; the TUI overlay renders the smaller TUI-specific sections.
//!
//! Out of scope for this table:
//! - Keybindings (TUI-only; see `tui/components/help.rs`)
//! - Shell `!cmd`, note `#text`, file `@path` syntax (CLI-only)
//! - `/plugin-name:command` open-ended plugin dispatch (registry bypass)
//!
//! When a new slash command is added to `CommandRegistry`, append it to
//! [`SLASH_SECTIONS`]. When a command is implemented in `tui::app::App`,
//! append it to [`TUI_SLASH_SECTIONS`] with the TUI-specific behavior.

/// A single slash-command entry: invocation form + one-line description.
///
/// `invocation` is the user-visible string including the leading `/` and
/// any synopsis (e.g. `"/model <name>"`). It is shown verbatim — the
/// renderers do not parse it.
#[derive(Debug, Clone, Copy)]
pub struct SlashCommand {
    /// Invocation as the user would type it, including leading `/`.
    pub invocation: &'static str,
    /// Short, single-line description rendered next to the invocation.
    pub description: &'static str,
}

/// A named group of related commands. Section titles are stable strings
/// rendered by both the CLI printer and the TUI overlay.
#[derive(Debug, Clone, Copy)]
pub struct SlashSection {
    /// Heading shown above the group (e.g. `"Slash Commands"`).
    pub title: &'static str,
    /// Commands in this section, in display order.
    pub commands: &'static [SlashCommand],
}

const fn cmd(invocation: &'static str, description: &'static str) -> SlashCommand {
    SlashCommand {
        invocation,
        description,
    }
}

/// Core slash commands — the always-available set the registry dispatches.
const CORE: &[SlashCommand] = &[
    cmd("/help, /?", "Show this help message"),
    cmd("/new, /clear", "Start a new conversation"),
    cmd("/sessions", "List saved sessions"),
    cmd("/continue <n>", "Continue session number n"),
    cmd("/export", "Export conversation to markdown"),
    cmd("/compact", "Summarize old messages to save context"),
    cmd("/editor", "Open $EDITOR for composing message"),
    cmd("/undo", "Undo last message exchange"),
    cmd("/redo", "Redo last undone exchange"),
    cmd("/exit, /quit", "Exit the chat"),
    cmd("/history", "Show conversation history"),
    cmd("/model", "Show current model and provider"),
    cmd("/model list", "List available models for current provider"),
    cmd("/model <name>", "Switch to a different model"),
    cmd("/copy", "Copy last assistant response to clipboard"),
    cmd("/init", "Initialize project config and skills directory"),
    cmd("/review", "Review uncommitted git changes"),
    cmd(
        "/commit",
        "Stage changes and commit with auto-generated message",
    ),
    cmd("/commit-push-pr", "Commit, push, and create a pull request"),
    cmd(
        "/review <branch>",
        "Compare current branch against <branch>",
    ),
    cmd("/status", "Show session status (model, tokens, etc.)"),
    cmd("/connect", "Configure API keys for providers"),
    cmd("/theme", "List available color themes"),
    cmd("/theme <name>", "Switch to a color theme"),
    cmd("/mode", "Show current behavioral mode and list presets"),
    cmd(
        "/mode <preset>",
        "Switch behavioral mode (create/extend/safe/refactor/...)",
    ),
    cmd("/plan", "Toggle between Build and Plan modes"),
    cmd("/vim", "Toggle vim mode (show mode indicator in prompt)"),
    cmd(
        "/effort [level]",
        "Set effort level (low/medium/high/max/auto)",
    ),
    cmd("/keybindings", "Show configured keyboard shortcuts"),
    cmd("/rename <title>", "Rename the current session"),
    cmd("/version", "Show version and system information"),
    cmd("/debug", "Show debug info (paths, env vars, config)"),
    cmd("/find <query>", "Fuzzy-find files in the project"),
    cmd("/doctor", "Run inline diagnostics"),
    cmd("/config", "Show current configuration"),
    cmd("/config path", "Show config file locations"),
    cmd("/cost", "Show session cost estimate"),
    cmd("/context", "Show context window usage breakdown"),
    cmd("/login", "Check authentication status"),
    cmd("/logout", "Show how to clear Claude credentials manually"),
];

const MEMORY: &[SlashCommand] = &[
    cmd("/memory", "Show auto-learning stats"),
    cmd("/memory patterns", "Show learned coding patterns"),
    cmd("/memory errors <path>", "Show known errors for a file"),
    cmd("/memory prefs", "Show learned preferences"),
    cmd(
        "/memory files <path>",
        "Show co-edit relationships for a file",
    ),
    cmd(
        "/memory reset",
        "Reset all learned data (with confirmation)",
    ),
];

const ACTIVITY: &[SlashCommand] = &[
    cmd("/activity", "Show current session activities"),
    cmd("/activity sessions", "Show recent session summaries"),
    cmd("/activity files", "Show files modified this session"),
    cmd("/activity issues", "Show issues worked this session"),
];

const PLUGIN: &[SlashCommand] = &[
    cmd("/plugin", "List installed plugins"),
    cmd("/plugin install", "Install a plugin"),
    cmd("/plugin manage", "Manage installed plugins"),
    cmd("/plugin help", "Show all plugin commands"),
    cmd("/<plugin>:<cmd>", "Run a plugin command"),
];

const SKILLS: &[SlashCommand] = &[
    cmd("/skill", "List available skills"),
    cmd(
        "/skill <name>",
        "Invoke a skill (inject prompt as next message)",
    ),
];

/// Time-travel and session-shape commands (crosslink #653, #657, #659,
/// #662). These commands are implemented in the legacy REPL; the default TUI
/// exposes the subset listed in [`TUI_SLASH_SECTIONS`].
const TIME_TRAVEL: &[SlashCommand] = &[
    cmd("/rewind", "Show turns or rewind the last N turns"),
    cmd("/checkpoint", "Alias for /rewind"),
    cmd(
        "/teleport",
        "Restore a named /branch snapshot into the conversation",
    ),
    cmd(
        "/thinkback",
        "Replay the latest assistant turn's saved thinking block",
    ),
    cmd(
        "/fast",
        "Set low effort and switch to a known fast model when available",
    ),
];

/// Management/status commands (crosslink #663, #666). These are intentionally
/// read-only in the legacy REPL; live MCP lifecycle controls require the
/// process-wide MCP manager that the full-screen TUI installs at startup.
const MANAGEMENT: &[SlashCommand] = &[
    cmd("/mcp", "Show configured MCP servers"),
    cmd(
        "/mcp list",
        "List MCP servers declared by plugins and .mcp.json",
    ),
    cmd(
        "/mcp help",
        "Show MCP command usage and lifecycle limitations",
    ),
    cmd("/permissions", "Show permission rules and MCP allowlists"),
    cmd("/hooks", "Show configured lifecycle hooks"),
];

const TUI_CORE: &[SlashCommand] = &[
    cmd("/help, ?", "Show the TUI help overlay"),
    cmd("/clear", "Clear the visible transcript"),
    cmd("/exit, /quit", "Exit the TUI"),
    cmd(
        "/status",
        "Show model, provider, effort, and token estimate",
    ),
    cmd("/provider [name]", "Show or switch provider"),
    cmd("/model", "Show current model and provider"),
    cmd("/model list, /models", "List fallback models"),
    cmd("/model <name>", "Switch to a different model"),
    cmd("/mode", "Toggle between Build and Plan modes"),
    cmd(
        "/effort [low|medium|high|max|xhigh|auto]",
        "Set or cycle effort level",
    ),
];

const TUI_SESSIONS: &[SlashCommand] = &[
    cmd("/sessions, /list", "List saved sessions"),
    cmd("/resume, /continue", "Open the session picker"),
    cmd("/load <id>", "Resume a saved session by ID prefix"),
    cmd("/continue <id>", "Resume a saved session by ID prefix"),
    cmd("/rename <title>", "Rename the current session"),
    cmd("/export", "Export the current conversation to markdown"),
    cmd("/undo", "Undo the last message exchange"),
    cmd("/redo", "Redo the last undone message exchange"),
    cmd("/rewind [N]", "Show turns or rewind the last N turns"),
];

const TUI_DIAGNOSTICS: &[SlashCommand] = &[
    cmd("/cost", "Show session cost estimate"),
    cmd("/context", "Show context usage breakdown"),
    cmd(
        "/files [dir]",
        "List files in the current or given directory",
    ),
    cmd("/diff", "Show git diff summary"),
    cmd("/review", "Show a truncated git diff for review"),
    cmd("/doctor", "Run inline diagnostics"),
    cmd("/init", "Initialize project config if absent"),
];

const TUI_SKILLS: &[SlashCommand] = &[
    cmd("/skill, /skills", "List available skills"),
    cmd("/skill <name>", "Invoke a skill as the next prompt"),
    cmd("/<skill-name>", "Invoke a skill by name"),
];

/// All sections in the order they should render.
///
/// Iterated by both `slash_help()` (CLI printer) and `HelpOverlay`
/// (TUI cheatsheet). Adding a section here automatically shows up in
/// both seams.
pub const SLASH_SECTIONS: &[SlashSection] = &[
    SlashSection {
        title: "Slash Commands",
        commands: CORE,
    },
    SlashSection {
        title: "Memory Commands (auto-learning)",
        commands: MEMORY,
    },
    SlashSection {
        title: "Activity Commands",
        commands: ACTIVITY,
    },
    SlashSection {
        title: "Plugin Commands",
        commands: PLUGIN,
    },
    SlashSection {
        title: "Skill Commands",
        commands: SKILLS,
    },
    SlashSection {
        title: "Time Travel & Session Shape",
        commands: TIME_TRAVEL,
    },
    SlashSection {
        title: "Management Overlays",
        commands: MANAGEMENT,
    },
];

/// Slash commands implemented by the default full-screen TUI.
///
/// This table intentionally excludes legacy REPL-only commands such as
/// `/connect`, `/config path`, `/login`, `/plugin`, and the management-overlay
/// stubs until `tui::app::App` implements them.
pub const TUI_SLASH_SECTIONS: &[SlashSection] = &[
    SlashSection {
        title: "TUI Slash Commands",
        commands: TUI_CORE,
    },
    SlashSection {
        title: "TUI Sessions",
        commands: TUI_SESSIONS,
    },
    SlashSection {
        title: "TUI Diagnostics",
        commands: TUI_DIAGNOSTICS,
    },
    SlashSection {
        title: "TUI Skills",
        commands: TUI_SKILLS,
    },
];

/// Flat iterator over every command across every section.
///
/// Useful for legacy REPL help checks and tab-completion sources.
pub fn all_commands() -> impl Iterator<Item = &'static SlashCommand> {
    SLASH_SECTIONS.iter().flat_map(|s| s.commands.iter())
}

/// Flat iterator over every default-TUI command.
pub fn all_tui_commands() -> impl Iterator<Item = &'static SlashCommand> {
    TUI_SLASH_SECTIONS.iter().flat_map(|s| s.commands.iter())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn readme_default_tui_slash_commands() -> Vec<String> {
        let readme = include_str!("../README.md");
        let section = readme
            .split_once("## Slash Commands (Default TUI)")
            .expect("README must document default TUI slash commands")
            .1
            .split_once("## Keyboard Shortcuts (Default TUI)")
            .expect("default TUI slash command section must end before keyboard shortcuts")
            .0;

        section
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if !trimmed.starts_with('|') || trimmed.starts_with("| Command") {
                    return None;
                }
                let mut columns = trimmed
                    .trim_matches('|')
                    .split_terminator_unescaped('|')
                    .into_iter()
                    .map(str::trim);
                let command_column = columns.next()?;
                if command_column.is_empty() || command_column.chars().all(|c| c == '-') {
                    return None;
                }
                Some(command_column.replace("\\|", "|").replace('`', ""))
            })
            .collect()
    }

    trait SplitTerminatorUnescaped<'a> {
        fn split_terminator_unescaped(self, separator: char) -> Vec<&'a str>;
    }

    impl<'a> SplitTerminatorUnescaped<'a> for &'a str {
        fn split_terminator_unescaped(self, separator: char) -> Vec<&'a str> {
            let mut parts = Vec::new();
            let mut start = 0;
            let mut escaped = false;

            for (index, ch) in self.char_indices() {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == separator {
                    parts.push(&self[start..index]);
                    start = index + ch.len_utf8();
                }
            }

            parts.push(&self[start..]);
            parts
        }
    }

    /// Guard: if someone empties the table by accident, this fails rather
    /// than shipping an empty help screen in both seams.
    #[test]
    fn sections_non_empty() {
        assert!(!SLASH_SECTIONS.is_empty());
        for section in SLASH_SECTIONS {
            assert!(!section.title.is_empty());
            assert!(
                !section.commands.is_empty(),
                "section {} has no commands",
                section.title
            );
            for c in section.commands {
                assert!(c.invocation.starts_with('/'));
                assert!(!c.description.is_empty());
            }
        }
        assert!(!TUI_SLASH_SECTIONS.is_empty());
        for section in TUI_SLASH_SECTIONS {
            assert!(!section.title.is_empty());
            assert!(
                !section.commands.is_empty(),
                "TUI section {} has no commands",
                section.title
            );
            for c in section.commands {
                assert!(c.invocation.starts_with('/'));
                assert!(!c.description.is_empty());
            }
        }
    }

    /// Sanity: must include the universally expected commands. If any of
    /// these disappear the help table is almost certainly broken.
    #[test]
    fn table_includes_canonical_commands() {
        let invocations: Vec<&str> = all_commands().map(|c| c.invocation).collect();
        for canonical in [
            "/help, /?",
            "/new, /clear",
            "/exit, /quit",
            "/model",
            "/compact",
        ] {
            assert!(
                invocations.contains(&canonical),
                "canonical command {canonical} missing from SLASH_SECTIONS"
            );
        }
    }

    /// CC-parity time-travel + management commands (#653, #657, #659,
    /// #662, #663, #666). Each entry must appear at least once in the
    /// flat iterator so legacy /help surfaces it.
    #[test]
    fn time_travel_and_management_commands_present() {
        let invocations: Vec<&str> = all_commands().map(|c| c.invocation).collect();
        for canonical in [
            "/rewind",
            "/teleport",
            "/thinkback",
            "/fast",
            "/mcp",
            "/permissions",
            "/hooks",
        ] {
            assert!(
                invocations.contains(&canonical),
                "CC-parity command {canonical} missing from SLASH_SECTIONS"
            );
        }
    }

    #[test]
    fn memory_file_queries_advertise_required_paths() {
        let invocations: Vec<&str> = all_commands().map(|c| c.invocation).collect();
        for invocation in ["/memory errors <path>", "/memory files <path>"] {
            assert!(
                invocations.contains(&invocation),
                "memory query must advertise its required path: {invocation}"
            );
        }
        for stale in ["/memory errors", "/memory files"] {
            assert!(
                !invocations.contains(&stale),
                "memory query must not advertise an argument-free form: {stale}"
            );
        }
    }

    #[test]
    fn tui_table_excludes_legacy_repl_only_commands() {
        let invocations: Vec<&str> = all_tui_commands().map(|c| c.invocation).collect();
        for legacy_only in [
            "/connect",
            "/config path",
            "/login",
            "/plugin",
            "/mcp",
            "/permissions",
            "/hooks",
        ] {
            assert!(
                !invocations.contains(&legacy_only),
                "TUI help must not advertise unimplemented legacy command {legacy_only}"
            );
        }
        for tui_command in [
            "/help, ?",
            "/provider [name]",
            "/model",
            "/model <name>",
            "/load <id>",
            "/doctor",
            "/skill, /skills",
        ] {
            assert!(
                invocations.contains(&tui_command),
                "TUI help missing implemented command {tui_command}"
            );
        }
    }

    #[test]
    fn readme_default_tui_slash_commands_match_tui_catalog() {
        let documented = readme_default_tui_slash_commands();
        let catalogued = all_tui_commands()
            .map(|c| c.invocation.to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            documented, catalogued,
            "README default-TUI slash commands must match TUI_SLASH_SECTIONS exactly"
        );
    }
}
