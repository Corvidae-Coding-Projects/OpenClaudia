use super::models::get_available_models;
use super::{get_data_dir, get_history_path, get_sessions_dir, list_chat_sessions};
use openclaudia::config::{Hook, HookEntry, HooksConfig, PermissionsConfig, SandboxMode};
use openclaudia::memory;
use openclaudia::permissions::PermissionStoreSummary;
use openclaudia::plugins;
use openclaudia::skills;
use openclaudia::tools::file_index::FileIndex;
use openclaudia::tools::safe_truncate;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

/// Plugin slash command actions
pub enum PluginAction {
    /// Show main plugin menu / list installed plugins
    Menu,
    /// Show plugin help
    Help,
    /// Install a plugin (optionally from marketplace)
    Install {
        plugin: Option<String>,
        marketplace: Option<String>,
    },
    /// Manage installed plugins
    Manage,
    /// Uninstall a plugin
    Uninstall { plugin: String },
    /// Enable a plugin
    Enable { plugin: String },
    /// Disable a plugin
    Disable { plugin: String },
    /// Validate a plugin manifest
    Validate { path: Option<String> },
    /// Marketplace subcommand
    Marketplace {
        action: Option<String>,
        target: Option<String>,
    },
    /// Reload all plugins
    Reload,
    /// Execute a specific plugin command (/plugin-name:command)
    RunCommand {
        plugin_name: String,
        command_name: String,
        arguments: String,
    },
}

/// Result of applying a plugin action in the legacy REPL.
pub enum PluginActionOutcome {
    /// Management/listing action completed without producing a prompt.
    Handled,
    /// A plugin slash command resolved to a prompt that should be sent.
    Prompt(PluginCommandInvocation),
}

/// Resolved prompt plus per-command metadata for a plugin slash command.
pub struct PluginCommandInvocation {
    /// Prompt content to send as the user message.
    pub prompt: String,
    /// Tools that should be pre-approved for this prompt.
    pub allowed_tools: Option<Vec<String>>,
    /// Optional model hint from command front matter.
    pub model: Option<String>,
}

/// Resolved prompt plus per-skill metadata for a skill slash command.
pub struct SkillInvocation {
    /// Prompt content to send as the user message.
    pub prompt: String,
    /// Tools that should be pre-approved while this skill prompt runs.
    pub allowed_tools: Option<Vec<String>>,
    /// Optional model hint from skill front matter.
    pub model: Option<String>,
    /// Optional reasoning-effort hint from skill front matter.
    pub effort: Option<String>,
}

/// Slash command result
pub enum SlashCommandResult {
    /// Exit the chat
    Exit,
    /// Clear the conversation (start new session)
    Clear,
    /// Load a specific session
    LoadSession(String),
    /// Export conversation to markdown
    Export,
    /// Compact conversation (summarize old messages)
    Compact {
        /// Optional user instructions to preserve during compaction.
        instructions: Option<String>,
    },
    /// Editor returned content to send
    EditorInput(String),
    /// Undo last message pair
    Undo,
    /// Redo last undone message pair
    Redo,
    /// Rewind the last N message pairs
    Rewind(usize),
    /// Switch to a different model
    SwitchModel(String),
    /// Show status information
    Status,
    /// Toggle agent mode (Build/Plan)
    ToggleMode,
    /// Switch behavioral mode to a preset or custom configuration
    SetBehaviorMode(openclaudia::modes::BehaviorMode),
    /// Show keybindings
    Keybindings,
    /// Rename session with new title
    Rename(String),
    /// Memory command with subcommand and args
    Memory(String),
    /// Activity command to show recent session activities
    Activity(String),
    /// Plugin management command
    Plugin(PluginAction),
    /// Theme was changed to the given name
    ThemeChanged(String),
    /// Toggle vim mode (visual indicator in prompt)
    ToggleVim,
    /// Invoke a skill (inject its prompt as the next user message)
    Skill(SkillInvocation),
    /// Set effort level for the session (low/medium/high/max/auto)
    SetEffort(String),
    /// Cycle effort level: low → medium → high → low
    CycleEffort,
    /// Set fast profile for the session: low effort plus optional fast model.
    FastMode {
        effort: String,
        model: Option<String>,
    },
    /// Show help message (already printed)
    Handled,
    /// Add a working directory to the session scope (#176)
    AddWorkingDir(std::path::PathBuf),
    /// Branch conversation at current point, saving snapshot under the given name (#177)
    // The snapshot is already persisted by `slash_branch`; the inner name is
    // retained for tests and future UI affordances.
    #[allow(dead_code)]
    BranchSession(String),
    /// Restore a named branch snapshot into the active conversation (#657).
    TeleportSession {
        name: String,
        messages: Vec<serde_json::Value>,
    },
    /// Ask a side question without disturbing main conversation flow (#179)
    SideQuestion(String),
}

/// Width to which the invocation column is padded so the dash-aligned
/// descriptions line up. Wide enough for the longest invocation in the
/// shared table (`/commit-push-pr` = 15 chars) plus a little slack.
const SLASH_INVOCATION_WIDTH: usize = 19;
const STATUS_ITEM_LIMIT: usize = 6;

/// Absolute, PATH-independent location of `git` for slash-command helpers.
static GIT_BIN: LazyLock<Result<PathBuf, String>> =
    LazyLock::new(|| which::which("git").map_err(|e| format!("git binary not found on PATH: {e}")));

/// Absolute, PATH-independent location of `gh` for PR automation.
static GH_BIN: LazyLock<Result<PathBuf, String>> =
    LazyLock::new(|| which::which("gh").map_err(|e| format!("gh binary not found on PATH: {e}")));

fn git_bin() -> Result<&'static Path, String> {
    match &*GIT_BIN {
        Ok(path) => Ok(path.as_path()),
        Err(msg) => Err(msg.clone()),
    }
}

fn gh_bin() -> Result<&'static Path, String> {
    match &*GH_BIN {
        Ok(path) => Ok(path.as_path()),
        Err(msg) => Err(msg.clone()),
    }
}

fn git_command() -> Result<Command, String> {
    Ok(Command::new(git_bin()?))
}

fn gh_command() -> Result<Command, String> {
    Ok(Command::new(gh_bin()?))
}

pub fn slash_help() {
    // Sections (Slash / Memory / Activity / Plugin / Skill) come from the
    // shared SLASH_SECTIONS table so the CLI printer and the TUI help
    // overlay never drift (crosslink #499).
    for section in openclaudia::slash_commands::SLASH_SECTIONS {
        println!("\n{}:", section.title);
        for c in section.commands {
            println!(
                "  {:<width$} - {}",
                c.invocation,
                c.description,
                width = SLASH_INVOCATION_WIDTH
            );
        }
    }

    // CLI-only input affordances. These have no TUI analogue (the TUI
    // shows keybindings instead), so they live here and not in the
    // shared table.
    println!();
    println!("Shell Commands:");
    println!("  !<cmd>           - Execute shell command (e.g., !ls -la)");
    println!();
    println!("Notes:");
    println!("  #<text>          - Save a note without sending to AI");
    println!();
    println!("File Attachment:");
    println!("  @<path>          - Include file contents (e.g., @src/main.rs)");
    println!("  @\"path with spaces\" - Paths with spaces need quotes");
    println!();
    println!("Multiline Input:");
    println!("  End line with \\ to continue on next line");
    println!();
    println!("Keyboard Shortcuts:");
    println!("  Up/Down          - Navigate command history");
    println!("  Ctrl+R           - Search command history");
    println!("  Ctrl+C           - Cancel current input");
    println!("  Ctrl+D           - Exit (on empty line)");
    println!("  Escape           - Cancel AI response mid-stream");
    println!();
}

pub fn slash_doctor(
    run: Option<&openclaudia::tools::ToolRunContext>,
    app_config: Option<&openclaudia::config::AppConfig>,
    composed_runtime: Option<&openclaudia::doctor::DoctorRuntimeSnapshot>,
) {
    let report = repl_doctor_report(run, app_config, composed_runtime);
    print!("{}", report.render_human());
}

fn repl_doctor_report(
    run: Option<&openclaudia::tools::ToolRunContext>,
    app_config: Option<&openclaudia::config::AppConfig>,
    composed_runtime: Option<&openclaudia::doctor::DoctorRuntimeSnapshot>,
) -> openclaudia::doctor::DoctorReport {
    let config_exists = app_config.is_some() || openclaudia::config::config_file_exists();
    let loaded_config = if app_config.is_none() && config_exists {
        openclaudia::config::load_config().ok()
    } else {
        None
    };
    let unavailable_config = if config_exists {
        openclaudia::doctor::DoctorConfig::Invalid
    } else {
        openclaudia::doctor::DoctorConfig::Missing
    };
    let config_state = app_config
        .map(openclaudia::doctor::DoctorConfig::Attached)
        .or_else(|| {
            loaded_config
                .as_ref()
                .map(openclaudia::doctor::DoctorConfig::LoadedFromSources)
        })
        .unwrap_or(unavailable_config);
    let runtime = composed_runtime.cloned().unwrap_or_else(|| {
        run.map_or_else(
            openclaudia::doctor::DoctorRuntimeSnapshot::standalone,
            |run| {
                let manager = openclaudia::mcp::registered_manager(run);
                openclaudia::doctor::DoctorRuntimeSnapshot::from_run_with_mcp(run, manager.as_ref())
            },
        )
    });
    openclaudia::doctor::diagnose(
        config_state,
        &runtime,
        &openclaudia::doctor::DoctorRequest::default(),
    )
}

pub fn slash_config(args: &str) {
    let config_parts: Vec<&str> = args.splitn(3, ' ').collect();
    match config_parts.first().copied().unwrap_or("show") {
        "" | "show" => match openclaudia::config::load_config() {
            Ok(cfg) => {
                println!("\nConfiguration:\n");
                println!("  Provider: {}", cfg.proxy.target);
                println!("  Host: {}:{}", cfg.proxy.host, cfg.proxy.port);
                for (name, p) in &cfg.providers {
                    let has_key = p.api_key.is_some();
                    println!(
                        "  {} \u{2192} {} (key: {})",
                        name,
                        p.base_url,
                        if has_key { "\u{2713}" } else { "\u{2717}" }
                    );
                }
                println!(
                    "  VDD: {} ({})",
                    if cfg.vdd.enabled { "on" } else { "off" },
                    cfg.vdd.mode
                );
                println!("  Session timeout: {} min", cfg.session.timeout_minutes);
                println!();
            }
            Err(e) => println!("\nFailed to load config: {e}\n"),
        },
        "path" => {
            println!("\nConfig locations:");
            println!("  Project: .openclaudia/config.yaml");
            if let Some(home) = dirs::home_dir() {
                println!(
                    "  User: {}",
                    home.join(".openclaudia/config.yaml").display()
                );
            }
            println!("  Credentials: ~/.claude/.credentials.json");
            println!("  MCP: .mcp.json");
            println!("  Skills: .openclaudia/skills/");
            println!();
        }
        _ => println!("\nUsage: /config [show|path]\n"),
    }
}

pub fn slash_permissions() -> SlashCommandResult {
    println!("\nPermissions:\n");
    match openclaudia::config::load_config() {
        Ok(cfg) => {
            let persisted_path = openclaudia::permissions::trusted_permission_store_path();
            match openclaudia::permissions::inspect_permission_store(&persisted_path) {
                Ok(summary) => {
                    for line in
                        permission_status_lines(&cfg.permissions, summary, None, &persisted_path)
                    {
                        println!("  {line}");
                    }
                }
                Err(err) => {
                    for line in
                        permission_status_lines(&cfg.permissions, None, Some(&err), &persisted_path)
                    {
                        println!("  {line}");
                    }
                }
            }
        }
        Err(e) => println!("  Config: failed to load ({e})"),
    }
    println!();
    SlashCommandResult::Handled
}

pub fn slash_hooks() -> SlashCommandResult {
    println!("\nHooks:\n");
    match openclaudia::config::load_config() {
        Ok(cfg) => {
            let hooks = openclaudia::hooks::load_effective_hooks(cfg.hooks);
            for line in hook_status_lines(&hooks) {
                println!("  {line}");
            }
            let imports = openclaudia::hooks::inspect_repository_hook_imports();
            for proposal in imports.proposals {
                println!(
                    "  Import {:?}: {} ({})",
                    proposal.state,
                    proposal.source.display(),
                    proposal.proposal_digest
                );
                println!(
                    "    events: {}; effects: {}",
                    proposal.requested_events.join(", "),
                    proposal.requested_effects.join(", ")
                );
            }
            for diagnostic in imports.diagnostics {
                println!("  Import unavailable: {}", diagnostic.message);
            }
        }
        Err(e) => println!("  Config: failed to load ({e})"),
    }
    println!();
    SlashCommandResult::Handled
}

pub fn slash_mcp(
    args: &str,
    run: Option<&openclaudia::tools::ToolRunContext>,
) -> SlashCommandResult {
    let mut parts = args.split_whitespace();
    let subcmd = parts.next().unwrap_or("").to_ascii_lowercase();

    match subcmd.as_str() {
        "" | "status" | "list" => print_mcp_status(run),
        "help" => print_mcp_help(),
        "enable" | "disable" | "reconnect" => {
            println!("\nMCP lifecycle controls are not available in the legacy REPL.");
            println!(
                "Edit plugin MCP declarations, then restart OpenClaudia so startup can reconnect them."
            );
            println!();
        }
        "add" => {
            println!("\nUsage: declare MCP servers in a plugin manifest `mcpServers` block.");
            println!("Project .mcp.json files are detected for diagnostics but are not auto-connected here.");
            println!();
        }
        unknown => {
            println!("\nUnknown MCP subcommand: {unknown}");
            print_mcp_help();
        }
    }

    SlashCommandResult::Handled
}

fn print_mcp_help() {
    println!("\nMCP Commands:\n");
    println!("  /mcp        - Show MCP server status");
    println!("  /mcp list   - List configured MCP servers");
    println!("  /mcp help   - Show this help");
    println!();
    println!("MCP servers are connected at startup from enabled plugin `mcpServers` declarations.");
    println!("Restart OpenClaudia after changing plugin MCP configuration.\n");
}

fn print_mcp_status(run: Option<&openclaudia::tools::ToolRunContext>) {
    println!("\nMCP:\n");
    print_plugin_mcp_status(run);
    print_project_mcp_status(run);

    println!(
        "  Live MCP connections are isolated to the active run and exposed through MCP tools."
    );
    println!();
}

fn print_plugin_mcp_status(run: Option<&openclaudia::tools::ToolRunContext>) {
    let Some(run) = run else {
        println!("  Plugin MCP servers: unavailable without a run context");
        return;
    };
    let mut plugin_manager = match plugins::PluginManager::try_new_for_project(run.project_root()) {
        Ok(manager) => manager,
        Err(e) => {
            println!("  Plugin MCP servers: unavailable ({e})");
            return;
        }
    };

    let discovery_errors = plugin_manager.discover();
    if !discovery_errors.is_empty() {
        println!("  Plugin discovery warnings: {}", discovery_errors.len());
    }

    let mut servers = plugin_manager.all_mcp_servers_for_run(run);
    if servers.is_empty() {
        println!("  Plugin MCP servers: none declared");
        return;
    }

    let total = servers.len();
    servers.sort_by(|(a_plugin, a_server), (b_plugin, b_server)| {
        a_plugin
            .name()
            .cmp(b_plugin.name())
            .then_with(|| a_server.name.cmp(&b_server.name))
    });

    println!("  Plugin MCP servers: {total}");
    for (plugin, server) in servers.into_iter().take(STATUS_ITEM_LIMIT) {
        println!(
            "    {}/{} [{}] {}{}",
            plugin.name(),
            server.name,
            server.transport,
            mcp_server_endpoint(&server),
            server
                .timeout
                .map(|ms| format!(" (timeout {ms}ms)"))
                .unwrap_or_default()
        );
    }
    if total > STATUS_ITEM_LIMIT {
        println!("    ... {} more server(s)", total - STATUS_ITEM_LIMIT);
    }
}

fn mcp_server_endpoint(server: &plugins::PluginMcpServer) -> String {
    match server.transport.as_str() {
        "stdio" => server.command.as_deref().map_or_else(
            || "<missing command>".to_string(),
            |command| {
                if server.args.is_empty() {
                    command.to_string()
                } else {
                    format!("{} {}", command, server.args.join(" "))
                }
            },
        ),
        "http" => server.url.as_deref().unwrap_or("<missing url>").to_string(),
        _ => "unsupported transport".to_string(),
    }
}

fn print_project_mcp_status(run: Option<&openclaudia::tools::ToolRunContext>) {
    let Some(run) = run else {
        println!("  Project .mcp.json: unavailable without a run context");
        return;
    };
    match project_mcp_server_count_for_run(run) {
        Ok(Some(count)) => println!(
            "  Project .mcp.json: {count} server(s) declared (diagnostic only in the legacy REPL)"
        ),
        Ok(None) => println!("  Project .mcp.json: not found"),
        Err(e) => println!("  Project .mcp.json: invalid ({e})"),
    }
}

fn project_mcp_server_count_for_run(
    run: &openclaudia::tools::ToolRunContext,
) -> Result<Option<usize>, String> {
    let path = run.working_directory().join(".mcp.json");
    if !path.exists() {
        return Ok(None);
    }
    let (_, content) = openclaudia::tools::read_capability_text_attachment(run, ".mcp.json")?;
    project_mcp_server_count_from_str(&content).map(Some)
}

fn project_mcp_server_count_from_str(content: &str) -> Result<usize, String> {
    let value = serde_json::from_str::<serde_json::Value>(content)
        .map_err(|e| format!("JSON parse error: {e}"))?;
    let servers = if let Some(servers) = value.get("mcpServers") {
        servers
            .as_object()
            .ok_or_else(|| "`mcpServers` must be an object".to_string())?
    } else {
        value
            .as_object()
            .ok_or_else(|| ".mcp.json root must be an object".to_string())?
    };
    Ok(servers.len())
}

fn permission_status_lines(
    config: &PermissionsConfig,
    persisted: Option<PermissionStoreSummary>,
    persisted_error: Option<&str>,
    persisted_path: &Path,
) -> Vec<String> {
    let mut lines = vec![
        "Host safety: always enabled (repository and approval settings cannot disable it)"
            .to_string(),
        format!("Approval prompts enabled: {}", yes_no(config.enabled)),
        format!(
            "Default allow: {}",
            summarize_strings(&config.default_allow, "none")
        ),
        "Precedence: host hard deny > explicit deny > exact approval receipt > policy default"
            .to_string(),
        format!("Trusted approval store: {}", persisted_path.display()),
    ];

    if let Some(proposal) = config.project_proposal.as_ref() {
        lines.push(format!(
            "Repository permission proposal: inert (schema {}, {})",
            proposal.schema_version, proposal.proposal_digest
        ));
        lines.push(format!("  Source: {}", proposal.source.display()));
        if proposal.requests_prompt_bypass {
            lines.push("  Requested prompt bypass: ignored".to_string());
        }
        if !proposal.default_allow.is_empty() {
            lines.push(format!(
                "  Requested default allows: {} (ignored; approve exact calls instead)",
                proposal.default_allow.len()
            ));
        }
        if !proposal.web_fetch_preapproved_domains.is_empty() {
            lines.push(format!(
                "  Requested web preapprovals: {} (ignored; configure trusted host state)",
                proposal.web_fetch_preapproved_domains.len()
            ));
        }
    }

    if config.mcp.is_empty() {
        lines.push("MCP allowlists: none configured".to_string());
    } else {
        lines.push(format!("MCP allowlists: {} server(s)", config.mcp.len()));
        let mut servers: Vec<(&String, &Vec<String>)> = config.mcp.iter().collect();
        servers.sort_by_key(|(server, _)| *server);
        for (server, tools) in servers.into_iter().take(STATUS_ITEM_LIMIT) {
            if tools.is_empty() {
                lines.push(format!("  {server}: deny all tools"));
            } else {
                lines.push(format!(
                    "  {server}: {}",
                    summarize_strings(tools, "no tools")
                ));
            }
        }
        if config.mcp.len() > STATUS_ITEM_LIMIT {
            lines.push(format!(
                "  ... {} more server(s)",
                config.mcp.len() - STATUS_ITEM_LIMIT
            ));
        }
    }

    match (persisted, persisted_error) {
        (Some(summary), _) => {
            lines.push(format!(
                "Persisted exact approvals: {} (generation {}, expiring/use-limited)",
                summary.approval_count, summary.capability_generation
            ));
            lines.push(format!(
                "Persisted explicit denials: {}",
                summary.denial_count
            ));
        }
        (None, Some(err)) => {
            lines.push(format!("Persisted rules: unavailable ({err})"));
        }
        (None, None) => {
            lines.push("Persisted approvals/denials: none".to_string());
        }
    }

    lines
}

fn hook_status_lines(config: &HooksConfig) -> Vec<String> {
    let slots = hook_slots(config);
    let active_slots = slots
        .iter()
        .filter(|(_, entries)| !entries.is_empty())
        .count();
    let entry_count: usize = slots.iter().map(|(_, entries)| entries.len()).sum();
    let hook_count: usize = slots
        .iter()
        .flat_map(|(_, entries)| entries.iter())
        .map(|entry| entry.hooks.len())
        .sum();

    let mut lines = vec![
        "Sources: host config plus exact host-approved repository imports".to_string(),
        format!(
            "Configured: {}, {}, {}",
            count_label(active_slots, "active event", "active events"),
            count_label(entry_count, "entry", "entries"),
            count_label(hook_count, "hook action", "hook actions")
        ),
        format!("Policy: {}", hook_policy_label(config)),
    ];

    if entry_count == 0 {
        lines.push("No lifecycle hooks configured".to_string());
        return lines;
    }

    for (name, entries) in slots {
        if entries.is_empty() {
            continue;
        }
        lines.push(hook_slot_line(name, entries));
    }

    lines
}

fn hook_slots(config: &HooksConfig) -> [(&'static str, &[HookEntry]); 16] {
    [
        ("session_start", &config.session_start),
        ("session_end", &config.session_end),
        ("pre_tool_use", &config.pre_tool_use),
        ("post_tool_use", &config.post_tool_use),
        ("post_tool_use_failure", &config.post_tool_use_failure),
        ("user_prompt_submit", &config.user_prompt_submit),
        ("stop", &config.stop),
        ("subagent_start", &config.subagent_start),
        ("subagent_stop", &config.subagent_stop),
        ("pre_compact", &config.pre_compact),
        ("permission_request", &config.permission_request),
        ("notification", &config.notification),
        ("pre_adversary_review", &config.pre_adversary_review),
        ("post_adversary_review", &config.post_adversary_review),
        ("vdd_conflict", &config.vdd_conflict),
        ("vdd_converged", &config.vdd_converged),
    ]
}

fn hook_slot_line(name: &str, entries: &[HookEntry]) -> String {
    let hook_count: usize = entries.iter().map(|entry| entry.hooks.len()).sum();
    let previews: Vec<String> = entries
        .iter()
        .take(STATUS_ITEM_LIMIT)
        .map(hook_entry_preview)
        .collect();
    let suffix = if entries.len() > STATUS_ITEM_LIMIT {
        format!(
            "; {}; ... {} more",
            previews.join("; "),
            entries.len() - STATUS_ITEM_LIMIT
        )
    } else {
        format!("; {}", previews.join("; "))
    };

    format!(
        "{name}: {}, {}{suffix}",
        count_label(entries.len(), "entry", "entries"),
        count_label(hook_count, "hook action", "hook actions")
    )
}

fn hook_entry_preview(entry: &HookEntry) -> String {
    let matcher = entry.matcher.as_deref().unwrap_or("*");
    let hooks: Vec<&str> = entry.hooks.iter().map(hook_kind_label).collect();
    format!("{matcher} -> {}", hooks.join(", "))
}

const fn hook_kind_label(hook: &Hook) -> &'static str {
    match hook {
        Hook::Command { shell: true, .. } => "shell command",
        Hook::Command { shell: false, .. } => "command",
        Hook::Prompt { .. } => "prompt",
        Hook::Model { .. } => "model",
    }
}

fn hook_policy_label(config: &HooksConfig) -> String {
    let Some(policy) = config.policy.as_ref() else {
        return "not set (legacy allow-all command policy with env scrub)".to_string();
    };

    let allowed = match policy.allowed_commands.as_ref() {
        None => "all command executables allowed".to_string(),
        Some(commands) if commands.is_empty() => "all command hooks denied".to_string(),
        Some(commands) => {
            let mut sorted: Vec<&String> = commands.iter().collect();
            sorted.sort();
            format!(
                "allowed commands {}",
                summarize_string_refs(&sorted, "none")
            )
        }
    };

    format!("{allowed}; sandbox {}", sandbox_label(&policy.sandbox))
}

fn summarize_strings(items: &[String], empty_label: &str) -> String {
    let refs: Vec<&String> = items.iter().collect();
    summarize_string_refs(&refs, empty_label)
}

fn summarize_string_refs(items: &[&String], empty_label: &str) -> String {
    if items.is_empty() {
        return empty_label.to_string();
    }

    let shown: Vec<&str> = items
        .iter()
        .take(STATUS_ITEM_LIMIT)
        .map(|item| item.as_str())
        .collect();
    if items.len() > STATUS_ITEM_LIMIT {
        format!(
            "{} (+{} more)",
            shown.join(", "),
            items.len() - STATUS_ITEM_LIMIT
        )
    } else {
        shown.join(", ")
    }
}

const fn sandbox_label(sandbox: &SandboxMode) -> &'static str {
    match sandbox {
        SandboxMode::None => "none",
        SandboxMode::EnvScrub => "env_scrub",
        SandboxMode::FullSandbox => "full_sandbox",
    }
}

const fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn count_label(count: usize, singular: &str, plural: &str) -> String {
    let noun = if count == 1 { singular } else { plural };
    format!("{count} {noun}")
}

pub fn slash_debug(provider: &str, current_model: &str, msg_count: usize) {
    println!("\n=== Debug Information ===\n");
    println!("Provider:     {provider}");
    println!("Model:        {current_model}");
    println!("Messages:     {msg_count}");
    println!();
    println!("Configuration Paths:");
    println!("  Project:    .openclaudia/config.yaml");
    if let Some(home) = dirs::home_dir() {
        println!(
            "  User:       {}",
            home.join(".openclaudia/config.yaml").display()
        );
    }
    println!();
    println!("Data Directories:");
    println!("  Sessions:   {}", get_sessions_dir().display());
    println!("  History:    {}", get_history_path().display());
    println!("  Data:       {}", get_data_dir().display());
    println!();
    println!("Environment Variables:");
    for var in &[
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "DEEPSEEK_API_KEY",
        "QWEN_API_KEY",
        "DASHSCOPE_API_KEY",
        "ALIYUN_API_KEY",
        "ZAI_API_KEY",
        "KIMI_API_KEY",
        "MOONSHOT_API_KEY",
        "MINIMAX_API_KEY",
        "OPENROUTER_API_KEY",
        "OPEN_ROUTER_API_KEY",
        "OPENCODE_API_KEY",
        "OPENCODE_GO_API_KEY",
        "EDITOR",
    ] {
        let status = if std::env::var(var).is_ok() {
            "set"
        } else {
            "not set"
        };
        println!("  {var}: {status}");
    }
    println!();
}

pub fn slash_commit() -> SlashCommandResult {
    use crate::cli::commit_pipeline::{
        execute_commit_pipeline, CommitError, CommitOptions, CommitOutcome, RealGitRunner,
        StdioPrompt,
    };
    let mut git = RealGitRunner;
    let mut prompt = StdioPrompt;
    match execute_commit_pipeline(&mut git, &mut prompt, CommitOptions::interactive()) {
        Ok(CommitOutcome::Committed { message }) => println!("\n✓ Committed: {message}"),
        Ok(CommitOutcome::NothingToCommit) => println!("\nNo changes to commit.\n"),
        Ok(CommitOutcome::Cancelled) => println!("Commit cancelled."),
        Err(CommitError::NotARepo) => println!("\nNot inside a git repository.\n"),
        Err(CommitError::CommitFailed(stderr)) => println!("\n✗ {stderr}"),
    }
    SlashCommandResult::Handled
}

/// Auto-stage + auto-commit step for `/commit-push-pr`. Returns `false` when
/// the caller should bail out (commit failed). `NothingToCommit` is treated
/// as success so the push step can still run.
fn commit_push_pr_stage_and_commit() -> bool {
    use crate::cli::commit_pipeline::{
        execute_commit_pipeline, CommitError, CommitOptions, CommitOutcome, RealGitRunner,
        StdioPrompt,
    };
    let mut git = RealGitRunner;
    let mut prompt = StdioPrompt;
    match execute_commit_pipeline(&mut git, &mut prompt, CommitOptions::automatic()) {
        Ok(CommitOutcome::Committed { message }) => {
            println!("✓ Committed: {message}");
            true
        }
        Ok(CommitOutcome::NothingToCommit | CommitOutcome::Cancelled) => true,
        Err(CommitError::NotARepo) => {
            println!("\nNot inside a git repository.\n");
            false
        }
        Err(CommitError::CommitFailed(stderr)) => {
            println!("✗ Commit failed: {stderr}");
            false
        }
    }
}

/// Read a single line from stdin after printing `prompt`, returning the
/// trimmed lower-cased response.  Extracted (#791) so the protected-branch
/// confirmation can be tested in isolation rather than wedged inline.
fn prompt_confirm_line(prompt: &str) -> String {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).ok();
    line.trim().to_lowercase()
}

/// Returns the current branch name, or an empty string when `git` is
/// unavailable / not in a repo.  Pure git-status probe — no I/O on stdin.
fn current_branch() -> String {
    git_command()
        .and_then(|mut cmd| {
            cmd.args(["rev-parse", "--abbrev-ref", "HEAD"])
                .output()
                .map_err(|e| e.to_string())
        })
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Returns true when the user agrees to push (or the branch is not
/// protected and no confirmation is needed).  Encapsulates the entire
/// stdin-reading dance for the protected-branch case (#791).
fn confirm_push_to_branch(branch: &str) -> bool {
    if branch == "main" || branch == "master" {
        let answer = prompt_confirm_line(&format!(
            "\n\u{26a0} You're on '{branch}'. Push anyway? [y/n] "
        ));
        if !answer.starts_with('y') {
            println!("Push cancelled.");
            return false;
        }
    }
    true
}

/// Push the current branch to origin, asking for confirmation when on a
/// protected branch. Returns the branch name on success, or `None` to bail.
fn commit_push_pr_push() -> Option<String> {
    let branch = current_branch();
    if !confirm_push_to_branch(&branch) {
        return None;
    }
    let mut cmd = match git_command() {
        Ok(cmd) => cmd,
        Err(e) => {
            println!("\u{2717} {e}");
            return None;
        }
    };
    match cmd.args(["push", "-u", "origin", &branch]).output() {
        Ok(o) if o.status.success() => {
            println!("\u{2713} Pushed to origin/{branch}");
            Some(branch)
        }
        Ok(o) => {
            println!(
                "\u{2717} Push failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
            None
        }
        Err(e) => {
            println!("\u{2717} {e}");
            None
        }
    }
}

/// Create a GitHub pull request via the `gh` CLI using the last commit subject
/// as the title. No-ops with a hint when `gh` is not installed.
fn commit_push_pr_create_pr(branch: String) {
    let Ok(mut gh) = gh_command() else {
        println!("(gh CLI not found — install it to auto-create PRs)");
        return;
    };
    let last_msg = git_command()
        .and_then(|mut cmd| {
            cmd.args(["log", "-1", "--format=%s"])
                .output()
                .map_err(|e| e.to_string())
        })
        .map_or(branch, |o| {
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        });
    match gh
        .args(["pr", "create", "--title", &last_msg, "--body", ""])
        .output()
    {
        Ok(o) if o.status.success() => {
            println!(
                "✓ PR created: {}",
                String::from_utf8_lossy(&o.stdout).trim()
            );
        }
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            if err.contains("already exists") {
                println!("PR already exists for this branch.");
            } else {
                println!("✗ PR creation failed: {}", err.trim());
            }
        }
        Err(e) => println!("✗ {e}"),
    }
}

pub fn slash_commit_push_pr() -> SlashCommandResult {
    // Repo check is performed inside `commit_push_pr_stage_and_commit`
    // (via the shared commit pipeline, #476). Bailing here would re-shell
    // out to git for no benefit.
    if !commit_push_pr_stage_and_commit() {
        return SlashCommandResult::Handled;
    }
    if let Some(branch) = commit_push_pr_push() {
        commit_push_pr_create_pr(branch);
    }
    SlashCommandResult::Handled
}

pub fn slash_init(run: Option<&openclaudia::tools::ToolRunContext>) {
    let Some(run) = run else {
        println!("\n\u{2717} Initialization is unavailable without a run context.\n");
        return;
    };
    match openclaudia::tools::initialize_project_for_run(run) {
        Ok(openclaudia::tools::ProjectInitOutcome::AlreadyExists) => {
            println!("\n\u{26a0} Configuration already exists at .openclaudia/config.yaml");
            println!("Use /config to view, or delete the file to reinitialize.\n");
        }
        Ok(openclaudia::tools::ProjectInitOutcome::Created) => {
            println!("\n\u{2713} Created .openclaudia/config.yaml");
            println!("\u{2713} Created .openclaudia/skills/");
            println!("\nEdit .openclaudia/config.yaml to configure providers and API keys.\n");
        }
        Err(error) => println!("\n\u{2717} Failed to initialize project: {error}\n"),
    }
}

pub fn slash_model(
    args: &str,
    cmd: &str,
    provider: &str,
    current_model: &str,
) -> SlashCommandResult {
    let args = args.trim();
    if args.is_empty() && cmd == "model" {
        println!("\nCurrent model: \x1b[36m{current_model}\x1b[0m");
        println!("Provider: {provider}");
        println!("Use /model list to see available models, /model <name> to switch.\n");
        return SlashCommandResult::Handled;
    }
    if args.is_empty() && cmd == "models" || args == "list" {
        let models = get_available_models(provider);
        println!("\nAvailable models for \x1b[36m{provider}\x1b[0m:\n");
        for m in &models {
            let marker = if *m == current_model {
                " \x1b[32m← current\x1b[0m"
            } else {
                ""
            };
            println!("  \x1b[36m{m}\x1b[0m{marker}");
        }
        // Crosslink #433: get_adapter now returns Result. If the provider
        // name from `/models <provider>` is unknown, skip the dynamic-model
        // lookup quietly — the static list above has already been printed.
        if let (Ok(config), Ok(adapter)) = (
            openclaudia::config::load_config(),
            openclaudia::providers::get_adapter(provider),
        ) {
            if let Some(provider_config) = config.get_provider(provider) {
                if let Some(dynamic) = fetch_dynamic_models_for_slash(provider_config, adapter) {
                    println!("\n  Dynamic models (from API):");
                    for m in &dynamic {
                        let marker = if m == current_model {
                            " \x1b[32m← current\x1b[0m"
                        } else {
                            ""
                        };
                        println!("    \x1b[36m{m}\x1b[0m{marker}");
                    }
                }
            }
        }
        println!("\nUse /model <name> to switch.\n");
        return SlashCommandResult::Handled;
    }
    if args.eq_ignore_ascii_case("default") {
        let default_model = openclaudia::providers::default_model_for_target(provider).to_string();
        println!("\nSwitching to default model: \x1b[36m{default_model}\x1b[0m\n");
        return SlashCommandResult::SwitchModel(default_model);
    }
    let new_model = args.to_string();
    println!("\nSwitching to model: \x1b[36m{new_model}\x1b[0m\n");
    SlashCommandResult::SwitchModel(new_model)
}

fn fetch_dynamic_models_for_slash(
    provider_config: &openclaudia::config::ProviderConfig,
    adapter: &dyn openclaudia::providers::ProviderAdapter,
) -> Option<Vec<String>> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return None;
    }

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?
        .block_on(super::models::fetch_dynamic_models(
            provider_config,
            adapter,
        ))
}

/// Split a slash-command argument string into shell-style tokens.
///
/// Crosslink #906: `args.splitn(2, ' ')` chopped quoted paths and URLs
/// at the first whitespace, so `/plugin marketplace add "/Users/me/My Plugins/mp"`
/// resolved as `target="/Users/me/My`. We now use `shlex::split` which
/// honours single and double quotes plus backslash escapes. The function
/// returns the (subcommand, remaining-args-string) pair; the remaining
/// args are re-joined with single spaces so downstream parsers that
/// still want to split further can do so without re-quoting concerns.
///
/// Falls back to the legacy whitespace split when `shlex` rejects the
/// input (typically an unbalanced quote): we keep the original text
/// rather than refuse the command outright, matching the prior UX.
fn split_slash_args(args: &str) -> (String, String) {
    let tokens: Option<Vec<String>> = ::shlex::split(args);
    let tokens = match tokens {
        Some(t) if !t.is_empty() => t,
        _ => {
            // Either an empty input or an unbalanced quote — fall back to
            // the legacy first-word split so behaviour is no worse than
            // before for these inputs.
            let parts: Vec<&str> = args.splitn(2, ' ').collect();
            return (
                parts.first().copied().unwrap_or("").to_string(),
                parts.get(1).copied().unwrap_or("").trim().to_string(),
            );
        }
    };
    let subcmd = tokens[0].clone();
    let rest = tokens[1..].join(" ");
    (subcmd, rest)
}

pub fn slash_plugin(args: &str) -> SlashCommandResult {
    let (subcmd_raw, sub_args_owned) = split_slash_args(args);
    let subcmd = subcmd_raw.to_lowercase();
    let sub_args = sub_args_owned.trim();
    let action = match subcmd.as_str() {
        "" => PluginAction::Menu,
        "help" | "?" => PluginAction::Help,
        "install" | "i" => {
            if sub_args.is_empty() {
                PluginAction::Install {
                    plugin: None,
                    marketplace: None,
                }
            } else if looks_like_git_plugin_source(sub_args) {
                PluginAction::Install {
                    plugin: Some(sub_args.to_string()),
                    marketplace: None,
                }
            } else if sub_args.contains('@') {
                let parts: Vec<&str> = sub_args.splitn(2, '@').collect();
                PluginAction::Install {
                    plugin: Some(parts[0].to_string()),
                    marketplace: Some(parts[1].to_string()),
                }
            } else {
                PluginAction::Install {
                    plugin: Some(sub_args.to_string()),
                    marketplace: None,
                }
            }
        }
        "manage" => PluginAction::Manage,
        "uninstall" | "remove" | "rm" => {
            if sub_args.is_empty() {
                println!("\nUsage: /plugin uninstall <plugin-name>\n");
                return SlashCommandResult::Handled;
            }
            PluginAction::Uninstall {
                plugin: sub_args.to_string(),
            }
        }
        "enable" => {
            if sub_args.is_empty() {
                println!("\nUsage: /plugin enable <plugin-name>\n");
                return SlashCommandResult::Handled;
            }
            PluginAction::Enable {
                plugin: sub_args.to_string(),
            }
        }
        "disable" => {
            if sub_args.is_empty() {
                println!("\nUsage: /plugin disable <plugin-name>\n");
                return SlashCommandResult::Handled;
            }
            PluginAction::Disable {
                plugin: sub_args.to_string(),
            }
        }
        "validate" => PluginAction::Validate {
            path: if sub_args.is_empty() {
                None
            } else {
                Some(sub_args.to_string())
            },
        },
        "marketplace" | "market" => {
            // Crosslink #906: use shell-style tokenisation so a quoted
            // target (`add "path with spaces"`) survives intact.
            let (market_cmd, market_target_owned) = split_slash_args(sub_args);
            let market_target = market_target_owned.trim();
            PluginAction::Marketplace {
                action: if market_cmd.is_empty() {
                    None
                } else {
                    Some(market_cmd)
                },
                target: if market_target.is_empty() {
                    None
                } else {
                    Some(market_target.to_string())
                },
            }
        }
        "reload" => PluginAction::Reload,
        _ => {
            println!("\nUnknown plugin subcommand: {subcmd}. Use /plugin help.\n");
            return SlashCommandResult::Handled;
        }
    };
    SlashCommandResult::Plugin(action)
}

pub fn slash_skill(args: &str) -> SlashCommandResult {
    slash_skill_scoped(args, None)
}

/// Invoke a user-facing skill through one immutable project boundary.
pub fn slash_skill_for_run(
    args: &str,
    run: &openclaudia::tools::ToolRunContext,
) -> SlashCommandResult {
    slash_skill_scoped(args, Some(run))
}

fn slash_skill_scoped(
    args: &str,
    run: Option<&openclaudia::tools::ToolRunContext>,
) -> SlashCommandResult {
    if args.is_empty() {
        let all_skills = run.map_or_else(skills::load_global_skills, |run| {
            skills::load_skills_for_project(run.project_root(), run.working_directory())
        });
        let invocable_skills = all_skills
            .iter()
            .filter(|skill| skill.user_invocable)
            .collect::<Vec<_>>();
        if invocable_skills.is_empty() {
            println!("\nNo skills found.");
            println!("Add skill files to .openclaudia/skills/ or ~/.openclaudia/skills/");
            println!("\nSkill file format (YAML frontmatter + markdown body):");
            println!("  ---\n  name: my-skill\n  description: Does something useful\n  ---\n  \n  You are a specialized agent that...\n");
        } else {
            println!("\n=== Available Skills ({}) ===\n", invocable_skills.len());
            for skill in invocable_skills {
                println!("  \x1b[36m{}\x1b[0m - {}", skill.name, skill.description);
                println!("    \x1b[90m{}\x1b[0m", skill.path.display());
            }
            println!("\nUse /skill <name> to invoke a skill.\n");
        }
        SlashCommandResult::Handled
    } else {
        let skill_name = args.trim();
        let skill = run.map_or_else(
            || skills::get_user_invocable_skill(skill_name),
            |run| {
                skills::get_user_invocable_skill_for_project(
                    skill_name,
                    run.project_root(),
                    run.working_directory(),
                )
            },
        );
        if let Some(skill) = skill {
            println!("\n\x1b[36mInvoking skill: {}\x1b[0m\n", skill.name);
            SlashCommandResult::Skill(SkillInvocation {
                prompt: skill.prompt,
                allowed_tools: skill.allowed_tools,
                model: skill.model,
                effort: skill.effort,
            })
        } else {
            eprintln!("\nSkill '{skill_name}' not found. Use /skill to list available skills.\n");
            SlashCommandResult::Handled
        }
    }
}

pub fn slash_cost(messages: &[serde_json::Value]) -> SlashCommandResult {
    let msg_text: String = messages
        .iter()
        .filter_map(|m| m.get("content").and_then(|c| c.as_str()))
        .collect::<Vec<_>>()
        .join(" ");
    let tokens = openclaudia::compaction::estimate_tokens(&msg_text);
    let est_cost = f64::from(u32::try_from(tokens).unwrap_or(u32::MAX)) * 0.000_009;
    println!("\nSession cost estimate:");
    println!("  Tokens used: ~{tokens}");
    println!("  Estimated cost: ${est_cost:.4}");
    println!("  (Approximate — actual cost depends on model and input/output ratio)\n");
    SlashCommandResult::Handled
}

pub fn slash_context(messages: &[serde_json::Value], current_model: &str) -> SlashCommandResult {
    let msg_count = messages.len();
    let ctx_text: String = messages
        .iter()
        .filter_map(|m| m.get("content").and_then(|c| c.as_str()))
        .collect::<Vec<_>>()
        .join(" ");
    let tokens = openclaudia::compaction::estimate_tokens(&ctx_text);
    let count_role = |role: &str| {
        messages
            .iter()
            .filter(|m| m.get("role").and_then(|r| r.as_str()) == Some(role))
            .count()
    };
    let (user_msgs, asst_msgs, tool_msgs, sys_msgs) = (
        count_role("user"),
        count_role("assistant"),
        count_role("tool"),
        count_role("system"),
    );
    let max_tokens = openclaudia::compaction::get_context_window(current_model);
    let pct_int = tokens
        .saturating_mul(100)
        .checked_div(max_tokens)
        .unwrap_or(0);
    println!("\nContext window:");
    println!("  Messages: {msg_count} total (user: {user_msgs}, assistant: {asst_msgs}, tool: {tool_msgs}, system: {sys_msgs})");
    println!("  Tokens: ~{tokens} / {max_tokens} ({pct_int}%)");
    if pct_int >= 85 {
        println!("  \x1b[33m⚠ Nearing limit — use /compact\x1b[0m");
    }
    println!();
    SlashCommandResult::Handled
}

pub fn slash_login() -> SlashCommandResult {
    match openclaudia::claude_credentials::peek_credentials() {
        Ok(Some(status)) => {
            println!("\n✓ Authenticated via Claude Code credentials.");
            println!("  File: ~/.claude/.credentials.json");
            println!(
                "  Type: {}",
                status.subscription_type.as_deref().unwrap_or("unknown")
            );
            println!(
                "  Tier: {}",
                status.rate_limit_tier.as_deref().unwrap_or("default")
            );
            if status.expired {
                println!("  Status: expired (auto-refreshes on next use)");
            } else if status.expires_soon {
                println!("  Status: valid, expiring soon");
            } else {
                println!("  Status: valid");
            }
        }
        Ok(None) => {
            println!("\n✗ Not authenticated via Claude Code.");
            println!("  To log in:");
            println!("  1. Install Claude Code: npm install -g @anthropic-ai/claude-code");
            println!("  2. Run: claude");
            println!("  3. Complete the login flow");
            println!("  4. Restart OpenClaudia");
        }
        Err(error) => {
            println!("\n✗ Could not read Claude Code credentials: {error}");
        }
    }
    println!();
    SlashCommandResult::Handled
}

pub fn slash_sessions() -> SlashCommandResult {
    let sessions = list_chat_sessions();
    if sessions.is_empty() {
        println!("\nNo saved sessions.\n");
    } else {
        println!("\nSaved Sessions ({}):\n", sessions.len());
        for (i, session) in sessions.iter().take(10).enumerate() {
            let date = session.updated_at.format("%Y-%m-%d %H:%M");
            let msg_count = session.inspect_state(|state| state.conversation.messages.len());
            let session_id = session.id();
            let id_prefix = safe_truncate(&session_id, 8);
            println!(
                "  {}. \x1b[36m{}\x1b[0m  \x1b[90m{} · {} · {} msgs\x1b[0m",
                i + 1,
                session.title,
                date,
                session.model,
                msg_count
            );
            println!("     \x1b[90mid: {id_prefix}\x1b[0m");
        }
        if sessions.len() > 10 {
            println!("  ... and {} more", sessions.len() - 10);
        }
        println!("\nUse /continue <n|session-id> to resume a session.\n");
    }
    SlashCommandResult::Handled
}

fn parse_session_uuid_arg(args: &str) -> Option<String> {
    uuid::Uuid::parse_str(args.trim())
        .ok()
        .map(|id| id.to_string())
}

pub fn slash_continue(args: &str) -> SlashCommandResult {
    let args = args.trim();
    if args.is_empty() {
        let sessions = list_chat_sessions();
        if let Some(session) = sessions.first() {
            println!("\nContinuing: {}\n", session.title);
            return SlashCommandResult::LoadSession(session.id());
        }
        println!("\nNo sessions to continue.\n");
    } else if let Some(session_id) = parse_session_uuid_arg(args) {
        println!("\nContinuing session: {}\n", safe_truncate(&session_id, 8));
        return SlashCommandResult::LoadSession(session_id);
    } else if let Ok(num) = args.parse::<usize>() {
        let sessions = list_chat_sessions();
        if num > 0 && num <= sessions.len() {
            let session = &sessions[num - 1];
            println!("\nContinuing: {}\n", session.title);
            return SlashCommandResult::LoadSession(session.id());
        }
        println!("\nInvalid session number. Use /sessions to see available sessions.\n");
    } else {
        println!("\nUsage: /continue <number|session-id>\n");
    }
    SlashCommandResult::Handled
}

pub fn slash_history(messages: &[serde_json::Value]) -> SlashCommandResult {
    if messages.is_empty() {
        println!("\nNo messages in conversation.\n");
    } else {
        println!("\nConversation History ({} messages):", messages.len());
        for (i, msg) in messages.iter().enumerate() {
            let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("?");
            let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");
            let preview = if content.len() > 60 {
                format!("{}...", safe_truncate(content, 57))
            } else {
                content.to_string()
            };
            println!("  {}. [{}] {}", i + 1, role, preview);
        }
        println!();
    }
    SlashCommandResult::Handled
}

pub fn slash_rewind(args: &str, messages: &[serde_json::Value]) -> SlashCommandResult {
    let trimmed = args.trim();
    if trimmed.is_empty() {
        use std::fmt::Write as _;

        let mut turn_list = String::new();
        let mut turn_num = 0;
        for msg in messages {
            if msg.get("role").and_then(|r| r.as_str()) == Some("user") {
                turn_num += 1;
                let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");
                let preview = if content.len() > 60 {
                    format!("{}...", safe_truncate(content, 57))
                } else {
                    content.to_string()
                };
                let _ = writeln!(turn_list, "  {turn_num}. {preview}");
            }
        }
        if turn_list.is_empty() {
            turn_list = "  (no conversation turns yet)\n".to_string();
        }
        println!(
            "\nConversation has {turn_num} turn(s):\n{turn_list}\nUse /rewind N to undo the last N turns.\n"
        );
        return SlashCommandResult::Handled;
    }

    match trimmed.parse::<usize>() {
        Ok(0) => {
            println!("\nNothing to rewind (0 turns).\n");
            SlashCommandResult::Handled
        }
        Ok(turns) => SlashCommandResult::Rewind(turns),
        Err(_) => {
            println!("\nUsage: /rewind [N]\n");
            SlashCommandResult::Handled
        }
    }
}

fn latest_assistant_reasoning_content(messages: &[serde_json::Value]) -> Option<&str> {
    let latest_assistant = messages
        .iter()
        .rev()
        .find(|msg| msg.get("role").and_then(|role| role.as_str()) == Some("assistant"))?;

    latest_assistant
        .get("reasoning_content")
        .and_then(|content| content.as_str())
        .map(str::trim)
        .filter(|content| !content.is_empty())
}

pub fn slash_thinkback(args: &str, messages: &[serde_json::Value]) -> SlashCommandResult {
    if !args.trim().is_empty() {
        println!("\nUsage: /thinkback\n");
        return SlashCommandResult::Handled;
    }

    match latest_assistant_reasoning_content(messages) {
        Some(reasoning) => {
            println!("\nLast assistant thinking block:\n");
            println!("{reasoning}");
            println!();
        }
        None => {
            println!("\nNo saved thinking block for the latest assistant turn.\n");
        }
    }

    SlashCommandResult::Handled
}

pub fn slash_copy(messages: &[serde_json::Value]) -> SlashCommandResult {
    if let Some(last_assistant) = messages
        .iter()
        .rev()
        .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("assistant"))
    {
        if let Some(content) = last_assistant.get("content").and_then(|c| c.as_str()) {
            match arboard::Clipboard::new() {
                Ok(mut clipboard) => match clipboard.set_text(content) {
                    Ok(()) => println!("\nCopied {} chars to clipboard.\n", content.len()),
                    Err(e) => eprintln!("\nFailed to copy to clipboard: {e}\n"),
                },
                Err(e) => eprintln!("\nClipboard not available: {e}\n"),
            }
        } else {
            println!("\nNo content to copy.\n");
        }
    } else {
        println!("\nNo assistant response to copy.\n");
    }
    SlashCommandResult::Handled
}

pub fn slash_agents() {
    print!("{}", render_agents_listing());
}

#[must_use]
pub fn render_agents_listing() -> String {
    use std::fmt::Write as _;

    let mut output = String::new();
    output.push_str("\nTask-spawnable subagent types:\n\n");
    for kind in openclaudia::subagent::AgentType::TASK_SPAWNABLE {
        let Some(task_name) = kind.task_tool_name() else {
            continue;
        };
        let _ = writeln!(
            output,
            "  \u{2022} {:<20} {}",
            task_name,
            kind.description()
        );
    }
    output.push_str("\nInvoke via the `task` tool with `subagent_type: \"<name>\"`.\n\n");

    let coordinator = openclaudia::subagent::AgentType::Coordinator;
    let _ = writeln!(
        output,
        "Coordinator profile:\n\n  \u{2022} {:<20} {}",
        coordinator.name(),
        coordinator.description()
    );
    output.push_str("    Legacy REPL profile: `openclaudia --coordinator --tui-mode`.\n");
    output.push_str("    Not accepted by the `task` tool until coordinator dispatch is wired.\n\n");
    output
}

pub fn slash_version() {
    println!("\nOpenClaudia v{}", env!("CARGO_PKG_VERSION"));
    println!("{}", env!("CARGO_PKG_DESCRIPTION"));
    println!();
    println!("Repository: {}", env!("CARGO_PKG_REPOSITORY"));
    println!("License:    {}", env!("CARGO_PKG_LICENSE"));
    println!(
        "Platform:   {} / {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!();
}

pub fn slash_effort(args: &str) -> SlashCommandResult {
    let level = args.trim().to_lowercase();
    match level.as_str() {
        "low" | "l" => {
            println!("\n\u{2713} Effort set to \x1b[33mlow\x1b[0m (faster, less thorough)\n");
            SlashCommandResult::SetEffort("low".to_string())
        }
        "medium" | "med" | "m" => {
            println!("\n\u{2713} Effort set to \x1b[36mmedium\x1b[0m (balanced)\n");
            SlashCommandResult::SetEffort("medium".to_string())
        }
        "high" | "h" => {
            println!("\n\u{2713} Effort set to \x1b[32mhigh\x1b[0m (thorough, slower)\n");
            SlashCommandResult::SetEffort("high".to_string())
        }
        "max" | "x" | "xhigh" => {
            println!("\n\u{2713} Effort set to \x1b[35mmax\x1b[0m (maximum thinking)\n");
            SlashCommandResult::SetEffort("max".to_string())
        }
        "auto" | "unset" => {
            println!("\n\u{2713} Effort set to \x1b[36mauto\x1b[0m (provider default)\n");
            SlashCommandResult::SetEffort("auto".to_string())
        }
        "" => SlashCommandResult::CycleEffort,
        _ => {
            println!("\nUsage: /effort [low|medium|high|max|xhigh|auto]");
            println!("  low    - Quick answers, minimal thinking");
            println!("  medium - Balanced (default)");
            println!("  high   - Thorough, more thinking time");
            println!("  max    - Maximum thinking where supported (OpenAI xhigh)");
            println!("  auto   - Omit effort hints and use provider default");
            println!("  (no argument cycles through levels)\n");
            SlashCommandResult::Handled
        }
    }
}

fn fast_model_for_provider(provider: &str) -> Option<&'static str> {
    let static_provider = match provider {
        "gemini" => "google",
        "glm" | "zhipu" => "zai",
        "alibaba" => "qwen",
        "moonshot" => "kimi",
        other => other,
    };
    let preferred: &[&str] = match static_provider {
        "anthropic" => &["claude-haiku-4-5-20251001"],
        "openai" => &[
            "gpt-5.4-mini",
            "gpt-5.4-nano",
            "gpt-5-mini",
            "gpt-5-nano",
            "gpt-4.1-mini",
            "gpt-4o-mini",
        ],
        "google" => &[
            "gemini-3.1-flash-lite",
            "gemini-3.5-flash",
            "gemini-2.5-flash-lite",
            "gemini-3-flash-preview",
        ],
        "zai" => &["glm-5.2", "glm-5v-turbo", "glm-5-turbo"],
        "qwen" => &["qwen3.7-plus", "qwen3.6-flash", "qwen3-coder-flash"],
        "deepseek" => &["deepseek-v4-flash", "deepseek-chat"],
        "kimi" => &["kimi-k2.7-code-highspeed", "moonshot-v1-8k"],
        "minimax" => &["MiniMax-M2.7-highspeed", "MiniMax-M2.5-highspeed"],
        _ => return None,
    };
    let available = get_available_models(static_provider);
    preferred
        .iter()
        .copied()
        .find(|candidate| available.contains(candidate))
}

pub fn slash_fast(provider: &str, current_model: &str) -> SlashCommandResult {
    let target_model = fast_model_for_provider(provider)
        .filter(|model| *model != current_model)
        .map(str::to_string);

    match target_model.as_deref() {
        Some(model) => println!(
            "\n\u{2713} Fast mode enabled: effort \x1b[33mlow\x1b[0m, model \x1b[36m{model}\x1b[0m\n"
        ),
        None => println!("\n\u{2713} Fast mode enabled: effort \x1b[33mlow\x1b[0m\n"),
    }

    SlashCommandResult::FastMode {
        effort: "low".to_string(),
        model: target_model,
    }
}

pub fn slash_find(
    args: &str,
    run: Option<&openclaudia::tools::ToolRunContext>,
) -> SlashCommandResult {
    if args.is_empty() {
        println!("\nUsage: /find <query>\n");
    } else {
        let Some(run) = run else {
            println!("\nFile search is unavailable without a run context.\n");
            return SlashCommandResult::Handled;
        };
        let root = run.working_directory();
        let index = FileIndex::build(root);
        let results = index.search(args, 20);
        if results.is_empty() {
            println!(
                "\nNo files matching '{}' ({} files indexed)\n",
                args,
                index.len()
            );
        } else {
            println!(
                "\nTop {} matches for '{}' ({} files indexed):\n",
                results.len(),
                args,
                index.len()
            );
            for (i, r) in results.iter().enumerate() {
                println!(
                    "  {:>2}. \x1b[36m{}\x1b[0m \x1b[90m(score: {})\x1b[0m",
                    i + 1,
                    r.path,
                    r.score
                );
            }
            println!();
        }
    }
    SlashCommandResult::Handled
}

/// Handle `/add-dir <path>` — add a working directory to the session scope (#176).
///
/// Validates that `path` exists and is a directory, canonicalises it, then
/// returns `AddWorkingDir(canonical_path)` for the REPL loop to store on the
/// session.  Returns `Handled` (with an error message printed) on any failure.
pub fn slash_add_dir(
    args: &str,
    run: Option<&openclaudia::tools::ToolRunContext>,
) -> SlashCommandResult {
    let raw = args.trim();
    if raw.is_empty() {
        println!("\nUsage: /add-dir <path>\n");
        return SlashCommandResult::Handled;
    }
    let Some(run) = run else {
        println!("\nError: /add-dir is unavailable without a run context.\n");
        return SlashCommandResult::Handled;
    };
    let supplied = std::path::Path::new(raw);
    let path = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        run.working_directory().join(supplied)
    };
    if !path.exists() {
        println!("\nError: path does not exist: {raw}\n");
        return SlashCommandResult::Handled;
    }
    if !path.is_dir() {
        println!("\nError: path is not a directory: {raw}\n");
        return SlashCommandResult::Handled;
    }
    match path.canonicalize() {
        Ok(canonical) => {
            println!("\nAdded working directory: {}\n", canonical.display());
            SlashCommandResult::AddWorkingDir(canonical)
        }
        Err(e) => {
            println!("\nError: could not resolve path '{raw}': {e}\n");
            SlashCommandResult::Handled
        }
    }
}

/// Handle `/branch [name]` — snapshot the conversation at this point (#177).
///
/// Serialises the current message history to
/// `.openclaudia/branches/<name>.json`.  `name` defaults to a timestamp
/// with a UUID suffix when not supplied.  Returns `BranchSession(name)`.
pub fn slash_branch(
    args: &str,
    messages: &[serde_json::Value],
    run: Option<&openclaudia::tools::ToolRunContext>,
) -> SlashCommandResult {
    let Some(run) = run else {
        println!("\nBranch snapshots are unavailable without a run context.\n");
        return SlashCommandResult::Handled;
    };
    let name: String = {
        let raw = args.trim();
        if raw.is_empty() {
            let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S");
            let suffix = &uuid::Uuid::new_v4().to_string()[..8];
            format!("{ts}_{suffix}")
        } else {
            raw.to_string()
        }
    };

    if let Err(reason) = validate_branch_snapshot_name(&name) {
        println!("\nError: invalid branch name '{name}': {reason}\n");
        return SlashCommandResult::Handled;
    }

    let branch_path = branch_snapshot_path(run, &name);
    let snapshot = serde_json::json!({
        "name": name,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "messages": messages,
    });
    match serde_json::to_string_pretty(&snapshot) {
        Ok(json) => match openclaudia::tools::create_run_control_text_file(
            run,
            &branch_path.to_string_lossy(),
            &json,
        ) {
            Ok(_) => {
                println!(
                    "\nBranched session as {name}; snapshot saved to {}\n",
                    branch_path.display()
                );
                SlashCommandResult::BranchSession(name)
            }
            Err(error) if error.ends_with("already exists") => {
                println!("\nError: branch '{name}' already exists. Choose a different name.\n");
                SlashCommandResult::Handled
            }
            Err(error) => {
                println!("\nError: could not write branch file: {error}\n");
                SlashCommandResult::Handled
            }
        },
        Err(e) => {
            println!("\nError: could not serialise session: {e}\n");
            SlashCommandResult::Handled
        }
    }
}

fn branch_snapshot_path(run: &openclaudia::tools::ToolRunContext, name: &str) -> PathBuf {
    run.project_root()
        .join(".openclaudia/branches")
        .join(format!("{name}.json"))
}

fn validate_branch_snapshot_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("name must not be empty");
    }

    if name.len() > 128 {
        return Err("name must be 128 bytes or fewer");
    }

    if name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Ok(())
    } else {
        Err("use only ASCII letters, numbers, '-' or '_'")
    }
}

fn load_branch_snapshot(
    run: &openclaudia::tools::ToolRunContext,
    name: &str,
) -> Result<Vec<serde_json::Value>, String> {
    validate_branch_snapshot_name(name)
        .map_err(|reason| format!("invalid branch name: {reason}"))?;

    let path = branch_snapshot_path(run, name);
    let (_, raw) = openclaudia::tools::read_run_control_text(run, &path.to_string_lossy())
        .map_err(|error| {
            if error.starts_with("NOT_FOUND:") {
                format!("branch snapshot '{name}' was not found")
            } else {
                format!("could not read {}: {error}", path.display())
            }
        })?;

    let snapshot: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|err| format!("could not parse {}: {err}", path.display()))?;
    let messages = snapshot
        .get("messages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("{} does not contain a messages array", path.display()))?;

    Ok(messages.clone())
}

pub fn slash_teleport(
    args: &str,
    run: Option<&openclaudia::tools::ToolRunContext>,
) -> SlashCommandResult {
    let name = args.trim();
    if name.is_empty() {
        println!("\nUsage: /teleport <branch-name>\n");
        return SlashCommandResult::Handled;
    }

    let Some(run) = run else {
        println!("\nTeleport is unavailable without a run context.\n");
        return SlashCommandResult::Handled;
    };
    match load_branch_snapshot(run, name) {
        Ok(messages) => SlashCommandResult::TeleportSession {
            name: name.to_string(),
            messages,
        },
        Err(reason) => {
            println!("\nError: {reason}\n");
            SlashCommandResult::Handled
        }
    }
}

/// Handle `/btw <question>` — ask a side question without disturbing the main
/// conversation flow (#179).
///
/// Returns `SideQuestion(question)` so the REPL can execute a single-turn
/// exchange (save history → inject question → stream answer → restore history).
pub fn slash_btw(args: &str) -> SlashCommandResult {
    let question = args.trim();
    if question.is_empty() {
        println!("\nUsage: /btw <question>\n");
        return SlashCommandResult::Handled;
    }
    SlashCommandResult::SideQuestion(question.to_string())
}

/// Handle slash commands, returns Some if command was handled
#[cfg(test)]
pub fn handle_slash_command(
    input: &str,
    messages: &mut Vec<serde_json::Value>,
    provider: &str,
    current_model: &str,
) -> Option<SlashCommandResult> {
    handle_slash_command_scoped(input, messages, provider, current_model, None, None, None)
}

/// Handle slash commands with one immutable run available to commands that
/// discover project-owned resources.
#[cfg(test)]
pub fn handle_slash_command_for_run(
    input: &str,
    messages: &mut Vec<serde_json::Value>,
    provider: &str,
    current_model: &str,
    run: &openclaudia::tools::ToolRunContext,
) -> Option<SlashCommandResult> {
    handle_slash_command_scoped(
        input,
        messages,
        provider,
        current_model,
        Some(run),
        None,
        None,
    )
}

/// Handle slash commands against the exact run and validated configuration
/// already composed by the production legacy frontend.
pub fn handle_slash_command_for_runtime(
    input: &str,
    messages: &mut Vec<serde_json::Value>,
    provider: &str,
    current_model: &str,
    run: &openclaudia::tools::ToolRunContext,
    app_config: &openclaudia::config::AppConfig,
    doctor_runtime: Option<&openclaudia::doctor::DoctorRuntimeSnapshot>,
) -> Option<SlashCommandResult> {
    handle_slash_command_scoped(
        input,
        messages,
        provider,
        current_model,
        Some(run),
        Some(app_config),
        doctor_runtime,
    )
}

fn handle_slash_command_scoped(
    input: &str,
    messages: &mut Vec<serde_json::Value>,
    provider: &str,
    current_model: &str,
    run_context: Option<&openclaudia::tools::ToolRunContext>,
    app_config: Option<&openclaudia::config::AppConfig>,
    doctor_runtime: Option<&openclaudia::doctor::DoctorRuntimeSnapshot>,
) -> Option<SlashCommandResult> {
    if !input.starts_with('/') {
        return None;
    }

    let parts: Vec<&str> = input[1..].splitn(2, ' ').collect();
    let cmd = parts[0].to_lowercase();
    let args = parts.get(1).copied().unwrap_or("");

    // Plugin run-command path: `/plugin-name:command` bypasses the registry
    // because the key space is open-ended (any installed plugin name).
    if cmd.contains(':') {
        let colon_parts: Vec<&str> = cmd.splitn(2, ':').collect();
        if colon_parts.len() == 2 {
            return Some(SlashCommandResult::Plugin(PluginAction::RunCommand {
                plugin_name: colon_parts[0].to_string(),
                command_name: colon_parts[1].to_string(),
                arguments: args.trim().to_string(),
            }));
        }
    }

    let mut ctx = super::command_registry::SlashCtx {
        messages,
        provider,
        current_model,
        run_context,
        app_config,
        doctor_runtime,
    };

    Some(
        super::command_registry::registry()
            .dispatch(&cmd, &mut ctx, args)
            .unwrap_or_else(|| {
                eprintln!("Unknown command: /{cmd}. Type /help for available commands.\n");
                SlashCommandResult::Handled
            }),
    )
}

/// Handle `/memory` inspection. Technical lessons are explicit reference
/// evidence; the legacy pattern tables remain visible only as compatibility
/// data and are never fed into automatic learning.
pub fn handle_memory_command(
    args: &str,
    memory_db: Option<&memory::MemoryDb>,
    run: &openclaudia::tools::ToolRunContext,
    automatic_learning_enabled: bool,
) {
    let Some(db) = memory_db else {
        println!("\n\x1b[33mMemory database not available.\x1b[0m\n");
        return;
    };

    let parts: Vec<&str> = args.splitn(2, ' ').collect();
    let subcmd = parts.first().map(|s| s.to_lowercase()).unwrap_or_default();
    let subargs = parts.get(1).copied().unwrap_or("");

    match subcmd.as_str() {
        "" | "status" | "stats" => {
            let status = openclaudia::auto_learn::status_for_run(run);
            println!("\n=== Automatic Technical Learning ===");
            println!(
                "  Capture policy:       {}",
                if automatic_learning_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!("  Pending exact checks: {}", status.pending_checks);
            println!("  Candidate transitions: {}", status.candidates_stored);
            println!("  Contradictions:        {}", status.contradictions_stored);
            println!("  Degraded events:       {}", status.degraded_events);
            println!("  Private store:         {}", db.path().display());
            println!("  Authority:             untrusted reference evidence");
            println!();
        }
        "list" | "lessons" => {
            match db.query_technical_lessons(None, 20, chrono::Utc::now().timestamp()) {
                Ok(result) if result.records.is_empty() => {
                    println!("\nNo technical lessons are stored for this workspace.\n");
                }
                Ok(result) => {
                    println!("\n=== Codebase Technical Lessons ===\n");
                    for record in result.records {
                        let review = if record.effectively_host_reviewed {
                            "host-reviewed"
                        } else if record.due_for_review {
                            "review-due"
                        } else {
                            "candidate"
                        };
                        println!(
                            "  {} (version {}, {review})",
                            record.lesson.title,
                            record.version.get()
                        );
                    }
                    println!();
                }
                Err(error) => eprintln!("\nFailed to list technical lessons: {error}\n"),
            }
        }
        "patterns" => memory_show_patterns(db, subargs),
        "errors" => memory_show_errors(db, subargs),
        "prefs" | "preferences" => match db.get_all_preferences() {
            Ok(prefs) => {
                if prefs.is_empty() {
                    println!("\nNo preferences learned yet.\n");
                } else {
                    println!("\n=== Learned Preferences ({}) ===\n", prefs.len());
                    for p in &prefs {
                        println!(
                            "  \x1b[35m[{}]\x1b[0m {} \x1b[90m(confidence: {})\x1b[0m",
                            p.category, p.preference, p.confidence
                        );
                    }
                    println!();
                }
            }
            Err(e) => eprintln!("\nFailed to get preferences: {e}\n"),
        },
        "files" | "relationships" => memory_show_files(db, subargs),
        "reset" => memory_reset(db, subargs),
        _ => {
            println!("\nUnknown memory subcommand: {subcmd}");
            println!(
                "Available: status, list, patterns, errors, prefs, files, reset\n\
                 patterns/errors/prefs/files are legacy compatibility views"
            );
        }
    }
}

fn memory_show_patterns(db: &memory::MemoryDb, subargs: &str) {
    match db.get_patterns_for_file(if subargs.is_empty() { "*" } else { subargs }) {
        Ok(patterns) => {
            if patterns.is_empty() {
                println!("\nNo coding patterns learned yet.\n");
            } else {
                println!("\n=== Coding Patterns ({}) ===\n", patterns.len());
                for p in patterns.iter().take(20) {
                    println!(
                        "  \x1b[36m[{}]\x1b[0m {} \x1b[90m({}x, {})\x1b[0m",
                        p.pattern_type, p.description, p.confidence, p.file_glob
                    );
                }
                println!();
            }
        }
        Err(e) => eprintln!("\nFailed to get patterns: {e}\n"),
    }
}

fn memory_show_errors(db: &memory::MemoryDb, subargs: &str) {
    if subargs.is_empty() {
        println!("\nUsage: /memory errors <file_path>");
        println!("Example: /memory errors src/main.rs\n");
        return;
    }
    match db.get_error_patterns_for_file(subargs) {
        Ok(errors) => {
            if errors.is_empty() {
                println!("\nNo error patterns for '{subargs}'.\n");
            } else {
                println!(
                    "\n=== Error Patterns for '{}' ({}) ===\n",
                    subargs,
                    errors.len()
                );
                for e in &errors {
                    print!(
                        "  \x1b[31m{}\x1b[0m ({}x)",
                        e.error_signature, e.occurrences
                    );
                    if let Some(ref res) = e.resolution {
                        print!(" \x1b[32m-> {res}\x1b[0m");
                    }
                    println!();
                }
                println!();
            }
        }
        Err(e) => eprintln!("\nFailed to get error patterns: {e}\n"),
    }
}

fn memory_show_files(db: &memory::MemoryDb, subargs: &str) {
    if subargs.is_empty() {
        println!("\nUsage: /memory files <file_path>");
        println!("Example: /memory files src/main.rs\n");
        return;
    }
    match db.get_related_files(subargs) {
        Ok(related) => {
            if related.is_empty() {
                println!("\nNo file relationships for '{subargs}'.\n");
            } else {
                println!("\n=== Files Co-Edited with '{subargs}' ===\n");
                for (file, count) in &related {
                    println!("  {file} ({count}x)");
                }
                println!();
            }
        }
        Err(e) => eprintln!("\nFailed to get file relationships: {e}\n"),
    }
}

fn memory_reset(db: &memory::MemoryDb, subargs: &str) {
    if subargs == "confirm" || subargs == "yes" {
        match db.reset_all() {
            Ok(()) => println!("\n\x1b[32mAll learned data reset.\x1b[0m\n"),
            Err(e) => eprintln!("\nFailed to reset memory: {e}\n"),
        }
    } else {
        println!("\n\x1b[31mWarning: This will delete ALL learned data!\x1b[0m");
        println!(
            "This includes typed technical lessons and their causal history, plus legacy coding patterns, error patterns, preferences, and file relationships."
        );
        println!("\nTo confirm, run: /memory reset confirm\n");
    }
}

/// Handle /activity command for viewing recent session activities
pub fn handle_activity_command(
    args: &str,
    current_session_id: &str,
    memory_db: Option<&memory::MemoryDb>,
) {
    let Some(db) = memory_db else {
        println!(
            "\n\x1b[33mActivity tracking not available (memory database failed to open).\x1b[0m\n"
        );
        return;
    };

    let parts: Vec<&str> = args.splitn(2, ' ').collect();
    let subcmd = parts.first().map(|s| s.to_lowercase()).unwrap_or_default();
    let subargs = parts.get(1).copied().unwrap_or("");

    match subcmd.as_str() {
        "" | "current" => activity_show_current(db, current_session_id),
        "sessions" | "recent" => activity_show_recent_sessions(db, subargs),
        "files" => match db.get_session_files_modified(current_session_id) {
            Ok(files) => {
                if files.is_empty() {
                    println!("\nNo files modified in this session yet.\n");
                } else {
                    println!("\n=== Files Modified This Session ({}) ===\n", files.len());
                    for file in &files {
                        println!("  {file}");
                    }
                    println!();
                }
            }
            Err(e) => eprintln!("\nFailed to get modified files: {e}\n"),
        },
        "issues" => match db.get_session_issues(current_session_id) {
            Ok(issues) => {
                if issues.is_empty() {
                    println!("\nNo issues worked on in this session yet.\n");
                } else {
                    println!("\n=== Issues Worked This Session ({}) ===\n", issues.len());
                    for issue in &issues {
                        println!("  {issue}");
                    }
                    println!();
                }
            }
            Err(e) => eprintln!("\nFailed to get issues: {e}\n"),
        },
        "help" => {
            println!("\nActivity Commands:");
            println!("  /activity          - Show current session activities");
            println!("  /activity sessions - Show recent session summaries");
            println!("  /activity files    - Show files modified this session");
            println!("  /activity issues   - Show issues worked this session");
            println!();
        }
        _ => {
            println!("\nUnknown activity subcommand: {subcmd}");
            println!("Available: current, sessions, files, issues, help\n");
        }
    }
}

fn activity_show_current(db: &memory::MemoryDb, current_session_id: &str) {
    match db.get_session_activities(current_session_id) {
        Ok(activities) => {
            if activities.is_empty() {
                println!("\nNo activities recorded in this session yet.\n");
            } else {
                println!(
                    "\n=== Current Session Activities ({}) ===",
                    activities.len()
                );
                println!("Session: {current_session_id}\n");
                for activity in activities.iter().take(20) {
                    let icon = match activity.activity_type.as_str() {
                        "file_read" => "R",
                        "file_write" => "W",
                        "file_edit" => "E",
                        "bash_command" => "$",
                        "issue_created" => "+",
                        "issue_closed" => "x",
                        "issue_comment" => "#",
                        _ => ".",
                    };
                    let details = activity.details.as_deref().unwrap_or("");
                    let details_str = if details.is_empty() {
                        String::new()
                    } else {
                        format!(" ({details})")
                    };
                    println!(
                        "  \x1b[90m[{}]\x1b[0m {} \x1b[36m{}\x1b[0m {}{}",
                        activity.created_at,
                        icon,
                        activity.activity_type,
                        activity.target,
                        details_str
                    );
                    println!(
                        "       \x1b[90mID: {} | Session: {}\x1b[0m",
                        activity.id,
                        safe_truncate(&activity.session_id, 8)
                    );
                }
                if activities.len() > 20 {
                    println!("\n  ... and {} more activities", activities.len() - 20);
                }
                println!();
            }
        }
        Err(e) => eprintln!("\nFailed to get activities: {e}\n"),
    }
}

fn activity_show_recent_sessions(db: &memory::MemoryDb, subargs: &str) {
    let limit = subargs.parse().unwrap_or(5);
    match db.get_recent_sessions(limit) {
        Ok(sessions) => {
            if sessions.is_empty() {
                println!("\nNo recent sessions recorded.\n");
            } else {
                println!("\n=== Recent Sessions ({}) ===\n", sessions.len());
                for (i, session) in sessions.iter().enumerate() {
                    println!(
                        "  \x1b[36m{}.\x1b[0m [ID:{}] Session {} (ended {})",
                        i + 1,
                        session.id,
                        safe_truncate(&session.session_id, 8),
                        session.ended_at
                    );
                    println!("     Started: {}", session.started_at);
                    let summary_preview = if session.summary.len() > 100 {
                        format!("{}...", safe_truncate(&session.summary, 97))
                    } else {
                        session.summary.clone()
                    };
                    println!("     Summary: {summary_preview}");
                    if !session.files_modified.is_empty() {
                        println!("     Files: {}", session.files_modified.join(", "));
                    }
                    if !session.issues_worked.is_empty() {
                        println!("     Issues: {}", session.issues_worked.join(", "));
                    }
                    println!();
                }
            }
        }
        Err(e) => eprintln!("\nFailed to get recent sessions: {e}\n"),
    }
}

fn plugin_action_menu(plugin_manager: &plugins::PluginManager) {
    let all: Vec<_> = plugin_manager.all().collect();
    if all.is_empty() {
        println!("\nNo plugins installed.");
        println!("Use /plugin install to browse and install plugins.");
        println!("Use /plugin help for all commands.\n");
    } else {
        println!("\n=== Installed Plugins ({}) ===\n", all.len());
        for plugin in &all {
            let status = if plugin.enabled {
                "\x1b[32menabled\x1b[0m"
            } else {
                "\x1b[31mdisabled\x1b[0m"
            };
            let version = plugin.manifest.version.as_deref().unwrap_or("0.0.0");
            println!("  {} v{} [{}]", plugin.name(), version, status);
            if let Some(desc) = &plugin.manifest.description {
                println!("    {desc}");
            }
            let cmd_count = plugin.command_paths.len() + plugin.command_metadata.len();
            let hook_count = plugin.hook_definitions.len();
            let mcp_count = plugin.mcp_configs.len();
            let mut components = Vec::new();
            if cmd_count > 0 {
                components.push(format!("{cmd_count} command(s)"));
            }
            if hook_count > 0 {
                components.push(format!("{hook_count} hook def(s)"));
            }
            if mcp_count > 0 {
                components.push(format!("{mcp_count} MCP server(s)"));
            }
            if !components.is_empty() {
                println!("    Components: {}", components.join(", "));
            }
            let commands = plugin.resolved_commands();
            for cmd in &commands {
                println!(
                    "    /{}:{} - {}",
                    plugin.name(),
                    cmd.name,
                    cmd.description.as_deref().unwrap_or("No description")
                );
            }
        }
        println!("\nUse /plugin help for management commands.\n");
    }
}

fn plugin_action_help() {
    println!("\nPlugin Commands:\n");
    println!("  Installation:");
    println!("    /plugin install              - Browse and install plugins");
    println!("    /plugin install <plugin>      - Install specific plugin");
    println!("    /plugin install <p>@<market>  - Install from marketplace");
    println!("    /plugin install <git-url>#<ref> - Install pinned git plugin\n");
    println!("  Management:");
    println!("    /plugin                      - List installed plugins");
    println!("    /plugin manage               - Manage installed plugins");
    println!("    /plugin enable <plugin>      - Enable a plugin");
    println!("    /plugin disable <plugin>     - Disable a plugin");
    println!("    /plugin uninstall <plugin>   - Uninstall a plugin");
    println!("    /plugin reload               - Reload all plugins\n");
    println!("  Marketplaces:");
    println!("    /plugin marketplace          - Marketplace management");
    println!("    /plugin marketplace add <p>  - Add a marketplace");
    println!("    /plugin marketplace remove <n> - Remove a marketplace");
    println!("    /plugin marketplace update   - Update marketplaces");
    println!("    /plugin marketplace list     - List all marketplaces\n");
    println!("  Validation:");
    println!("    /plugin validate <path>      - Validate a manifest\n");
    println!("  Plugin Commands:");
    println!("    /<plugin-name>:<command>     - Run a plugin command\n");
}

/// Tell-Don't-Ask interface for `PluginAction` variants.
///
/// crosslink #898: the original `handle_plugin_action` was a 70-line `match`
/// that branched on every variant and threaded `&mut PluginManager` into
/// helper functions. Variants now own their dispatch via `apply`, so adding
/// or splitting a variant changes one impl arm instead of two callers (the
/// constructor in slash parsing and the dispatcher here).
pub trait PluginActionRunner {
    /// Execute this action against `plugin_manager`. Errors are surfaced
    /// to stdout/stderr by the impl — the CLI is the only consumer.
    fn apply(
        self,
        plugin_manager: &mut plugins::PluginManager,
        run: &openclaudia::tools::ToolRunContext,
    ) -> PluginActionOutcome;
}

impl PluginActionRunner for PluginAction {
    fn apply(
        self,
        plugin_manager: &mut plugins::PluginManager,
        run: &openclaudia::tools::ToolRunContext,
    ) -> PluginActionOutcome {
        match self {
            Self::Menu => {
                plugin_action_menu(plugin_manager);
                PluginActionOutcome::Handled
            }
            Self::Help => {
                plugin_action_help();
                PluginActionOutcome::Handled
            }
            Self::Install {
                plugin,
                marketplace,
            } => {
                plugin_install(
                    plugin.as_deref(),
                    marketplace.as_deref(),
                    plugin_manager,
                    run,
                );
                PluginActionOutcome::Handled
            }
            Self::Manage => {
                plugin_action_manage(plugin_manager);
                PluginActionOutcome::Handled
            }
            Self::Uninstall { plugin } => {
                plugin_action_uninstall(&plugin, plugin_manager, run);
                PluginActionOutcome::Handled
            }
            Self::Enable { plugin } => {
                match plugin_manager.enable(&plugin) {
                    Ok(()) => println!("\nEnabled plugin '{plugin}'. Restart to apply changes.\n"),
                    Err(e) => eprintln!("\nFailed to enable plugin: {e}\n"),
                }
                PluginActionOutcome::Handled
            }
            Self::Disable { plugin } => {
                match plugin_manager.disable(&plugin) {
                    Ok(()) => println!("\nDisabled plugin '{plugin}'. Restart to apply changes.\n"),
                    Err(e) => eprintln!("\nFailed to disable plugin: {e}\n"),
                }
                PluginActionOutcome::Handled
            }
            Self::Validate { path } => {
                plugin_validate(path, run);
                PluginActionOutcome::Handled
            }
            Self::Marketplace { action, target } => {
                plugin_marketplace(action.as_deref(), target.as_deref(), plugin_manager, run);
                PluginActionOutcome::Handled
            }
            Self::Reload => {
                plugin_action_reload(plugin_manager);
                PluginActionOutcome::Handled
            }
            Self::RunCommand {
                plugin_name,
                command_name,
                arguments,
            } => plugin_run_command(&plugin_name, &command_name, &arguments, plugin_manager),
        }
    }
}

/// Print the management menu — extracted so [`PluginActionRunner::apply`]
/// stays one-line-per-variant.
fn plugin_action_manage(plugin_manager: &plugins::PluginManager) {
    let all: Vec<_> = plugin_manager.all().collect();
    if all.is_empty() {
        println!("\nNo plugins installed.\n");
        return;
    }
    println!("\n=== Plugin Management ===\n");
    for plugin in &all {
        let status = if plugin.enabled {
            "enabled"
        } else {
            "disabled"
        };
        println!("  {} [{}]", plugin.name(), status);
        println!("    Path: {}", plugin.root().display());
    }
    println!();
    println!("  /plugin enable <name>    - Enable a plugin");
    println!("  /plugin disable <name>   - Disable a plugin");
    println!("  /plugin uninstall <name> - Remove a plugin\n");
}

/// Remove a plugin from install tracking, delete its on-disk directory,
/// and refresh the in-memory manager.
fn plugin_action_uninstall(
    plugin: &str,
    plugin_manager: &mut plugins::PluginManager,
    run: &openclaudia::tools::ToolRunContext,
) {
    let uninstall_dir = match plugin_install_dir_for_name(plugin, run.project_root()) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("\nInvalid plugin name '{plugin}': {e}\n");
            return;
        }
    };
    let mut installed = plugins::InstalledPlugins::load(run.project_root());
    if installed.remove(plugin) {
        if let Err(e) = installed.save(run.project_root()) {
            tracing::warn!("Failed to save install tracking: {}", e);
        }
        if uninstall_dir.exists() {
            if let Err(e) = fs::remove_dir_all(&uninstall_dir) {
                eprintln!("Warning: Could not remove plugin directory: {e}");
            }
        }
        let _ = plugin_manager.reload();
        println!("\nUninstalled plugin '{plugin}'. Restart to apply changes.\n");
    } else {
        eprintln!("\nPlugin '{plugin}' not found in install tracking.\n");
    }
}

/// Reload manager and print discovered-plugin summary.
fn plugin_action_reload(plugin_manager: &mut plugins::PluginManager) {
    let errors = plugin_manager.reload();
    println!("\nReloaded plugins: {} loaded", plugin_manager.count());
    for err in &errors {
        eprintln!("  Error: {err}");
    }
    println!();
}

fn plugin_install(
    plugin: Option<&str>,
    marketplace: Option<&str>,
    plugin_manager: &mut plugins::PluginManager,
    run: &openclaudia::tools::ToolRunContext,
) {
    match (plugin, marketplace) {
        (Some(p), Some(m)) => plugin_install_from_marketplace(p, m, plugin_manager),
        (Some(p), None) => plugin_install_from_source(p, plugin_manager, run),
        (None, _) => print_available_plugin_installs(plugin_manager),
    }
}

fn plugin_install_from_marketplace(
    plugin: &str,
    marketplace: &str,
    plugin_manager: &mut plugins::PluginManager,
) {
    println!("\nInstalling plugin '{plugin}' from marketplace '{marketplace}'...");
    let policy = repl_plugin_policy();
    match plugin_manager.install_from_marketplace_with_policy(plugin, marketplace, &policy) {
        Ok(id) => println!("Installed '{id}'. Restart to apply changes.\n"),
        Err(e) => eprintln!("Failed to install: {e}\n"),
    }
}

fn plugin_install_from_source(
    plugin: &str,
    plugin_manager: &mut plugins::PluginManager,
    run: &openclaudia::tools::ToolRunContext,
) {
    println!("\nInstalling plugin '{plugin}'...");
    let requested = std::path::Path::new(plugin);
    let candidate = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        run.working_directory().join(requested)
    };
    let local_path = candidate
        .canonicalize()
        .ok()
        .filter(|path| path.is_dir() && run.permits_read(path));
    if let Some(path) = local_path.as_deref() {
        install_local_plugin_path(path, plugin_manager, run.project_root());
    } else if looks_like_git_plugin_source(plugin) {
        install_git_plugin_source(plugin, plugin_manager);
    } else {
        eprintln!("\nPlugin '{plugin}' not found as a local path.");
        println!(
            "Try: /plugin install <git-url>#<ref> or /plugin install <plugin>@<marketplace>\n"
        );
    }
}

fn install_local_plugin_path(
    path: &std::path::Path,
    plugin_manager: &mut plugins::PluginManager,
    project_root: &std::path::Path,
) {
    match plugins::Plugin::load(path) {
        Ok(loaded) => {
            let name = loaded.name().to_string();
            let dest = match plugin_install_dir_for_name(&name, project_root) {
                Ok(path) => path,
                Err(e) => {
                    eprintln!("Failed to install plugin: invalid plugin name '{name}': {e}\n");
                    return;
                }
            };
            if let Err(e) = plugins::copy_dir_recursive(path, &dest) {
                eprintln!("Failed to install plugin: {e}\n");
                return;
            }
            record_local_plugin_install(&name, &dest, loaded.manifest.version, project_root);
            let _ = plugin_manager.reload();
            println!("Installed plugin '{name}'. Restart to apply changes.\n");
        }
        Err(e) => eprintln!("Failed to load plugin from path: {e}\n"),
    }
}

fn record_local_plugin_install(
    name: &str,
    dest: &std::path::Path,
    version: Option<String>,
    project_root: &std::path::Path,
) {
    let mut installed = plugins::InstalledPlugins::load(project_root);
    installed.upsert(
        name,
        plugins::PluginInstallEntry {
            scope: plugins::InstallScope::Project,
            project_path: Some(project_root.to_string_lossy().to_string()),
            install_path: dest.to_string_lossy().to_string(),
            version,
            installed_at: Some(chrono::Utc::now().to_rfc3339()),
            last_updated: None,
            git_commit_sha: None,
        },
    );
    if let Err(e) = installed.save(project_root) {
        tracing::warn!("Failed to save install tracking: {}", e);
    }
}

fn install_git_plugin_source(source: &str, plugin_manager: &mut plugins::PluginManager) {
    let spec = match parse_pinned_git_source(source) {
        Ok(spec) => spec,
        Err(e) => {
            eprintln!("\nCannot install git plugin: {e}");
            println!("Use: /plugin install <git-url>#<tag-or-commit>\n");
            return;
        }
    };
    println!(
        "\nCloning plugin from '{}' at ref '{}'...",
        spec.url, spec.git_ref
    );
    let policy = repl_plugin_policy();
    match plugin_manager.install_from_git_with_policy(spec.url, Some(spec.git_ref), &policy) {
        Ok(name) => println!("Installed plugin '{name}'. Restart to apply changes.\n"),
        Err(e) => eprintln!("Failed to install: {e}\n"),
    }
}

fn print_available_plugin_installs(plugin_manager: &plugins::PluginManager) {
    let available = plugin_manager.list_available_plugins();
    if available.is_empty() {
        println!("\nNo marketplaces configured.");
        println!("Add a marketplace: /plugin marketplace add <path-or-url>");
        println!("Install from local directory: /plugin install /path/to/plugin");
        println!("Install from git: /plugin install <git-url>#<ref>\n");
    } else {
        println!("\n=== Available Plugins ===\n");
        for (mkt, plug) in &available {
            let desc = plug.description.as_deref().unwrap_or("No description");
            println!("  {}@{} - {}", plug.name, mkt, desc);
        }
        println!("\nInstall: /plugin install <plugin-name>@<marketplace>\n");
    }
}

fn plugin_validate(path: Option<String>, run: &openclaudia::tools::ToolRunContext) {
    let target = path.unwrap_or_else(|| ".".to_string());
    let requested = std::path::Path::new(&target);
    let candidate = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        run.working_directory().join(requested)
    };
    let target_path = match candidate.canonicalize() {
        Ok(path) if run.permits_read(&path) => path,
        Ok(_) => {
            println!("\nPath is outside the active run's readable roots: {target}\n");
            return;
        }
        Err(_) => candidate,
    };
    if target_path.is_dir() {
        match plugins::Plugin::load(&target_path) {
            Ok(plugin) => {
                println!("\n=== Plugin Validation: PASSED ===\n");
                println!("  Name:        {}", plugin.name());
                println!(
                    "  Version:     {}",
                    plugin.manifest.version.as_deref().unwrap_or("not set")
                );
                if let Some(desc) = &plugin.manifest.description {
                    println!("  Description: {desc}");
                }
                println!("  Commands:    {}", plugin.resolved_commands().len());
                println!("  Hooks:       {}", plugin.resolved_hooks().len());
                println!("  MCP Servers: {}", plugin.resolved_mcp_servers().len());
                println!();
            }
            Err(e) => {
                println!("\n=== Plugin Validation: FAILED ===\n");
                println!("  Error: {e}\n");
            }
        }
    } else if target_path.is_file() {
        match openclaudia::tools::read_capability_text_attachment(
            run,
            &target_path.to_string_lossy(),
        ) {
            Ok((_, content)) => {
                if let Ok(manifest) = serde_json::from_str::<plugins::PluginManifest>(&content) {
                    println!("\n=== Manifest Validation: PASSED ===\n");
                    println!("  Name:    {}", manifest.name);
                    println!(
                        "  Version: {}",
                        manifest.version.as_deref().unwrap_or("not set")
                    );
                    println!();
                } else if let Ok(marketplace) =
                    serde_json::from_str::<plugins::MarketplaceManifest>(&content)
                {
                    println!("\n=== Marketplace Manifest: PASSED ===\n");
                    println!("  Name:    {}", marketplace.name);
                    println!("  Plugins: {}", marketplace.plugins.len());
                    println!();
                } else {
                    println!("\n=== Manifest Validation: FAILED ===\n");
                    println!("  Could not parse as plugin or marketplace manifest.\n");
                }
            }
            Err(e) => {
                println!("\n=== Manifest Validation: FAILED ===\n");
                println!("  Could not read file: {e}\n");
            }
        }
    } else {
        println!("\nPath not found: {target}\n");
        println!("Usage: /plugin validate <path>");
        println!("  /plugin validate .                          - Validate current directory");
        println!("  /plugin validate .claude-plugin/plugin.json - Validate manifest file");
        println!("  /plugin validate /path/to/plugin-directory\n");
    }
}

fn plugin_install_dir_for_name(
    plugin: &str,
    project_root: &std::path::Path,
) -> Result<std::path::PathBuf, plugins::PluginError> {
    plugins::validate_plugin_dir_name(plugin)?;
    Ok(project_root.join(".openclaudia/plugins").join(plugin))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PinnedGitSource<'a> {
    url: &'a str,
    git_ref: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinnedGitSourceError {
    MissingRef,
    EmptyUrl,
    EmptyRef,
}

impl std::fmt::Display for PinnedGitSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRef => write!(
                f,
                "git installs must include an explicit ref, for example <url>#v1.2.3"
            ),
            Self::EmptyUrl => write!(f, "git install URL is empty"),
            Self::EmptyRef => write!(f, "git install ref is empty"),
        }
    }
}

fn parse_pinned_git_source(raw: &str) -> Result<PinnedGitSource<'_>, PinnedGitSourceError> {
    let Some((url, git_ref)) = raw.rsplit_once('#') else {
        return Err(PinnedGitSourceError::MissingRef);
    };
    let url = url.trim();
    let git_ref = git_ref.trim();
    if url.is_empty() {
        return Err(PinnedGitSourceError::EmptyUrl);
    }
    if git_ref.is_empty() {
        return Err(PinnedGitSourceError::EmptyRef);
    }
    Ok(PinnedGitSource { url, git_ref })
}

fn looks_like_git_plugin_source(candidate: &str) -> bool {
    candidate.starts_with("http://")
        || candidate.starts_with("https://")
        || candidate.starts_with("ssh://")
        || candidate.starts_with("git@")
        || candidate.contains('/')
        || std::path::Path::new(candidate)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("git"))
}

fn repl_plugin_policy() -> plugins::policy::PluginPolicy {
    plugins::policy::PluginPolicy::default()
}

fn plugin_marketplace(
    action: Option<&str>,
    target: Option<&str>,
    plugin_manager: &plugins::PluginManager,
    run: &openclaudia::tools::ToolRunContext,
) {
    match action {
        Some("add") => plugin_marketplace_add(target, plugin_manager, run),
        Some("remove" | "rm") => plugin_marketplace_remove(target, plugin_manager),
        Some("update") => plugin_marketplace_update(target, plugin_manager),
        Some("list") => plugin_marketplace_list(plugin_manager),
        _ => plugin_marketplace_help(),
    }
}

fn plugin_marketplace_add(
    target: Option<&str>,
    plugin_manager: &plugins::PluginManager,
    run: &openclaudia::tools::ToolRunContext,
) {
    let Some(target) = target else {
        println!("\nUsage: /plugin marketplace add <path-or-git-url>#<ref>\n");
        return;
    };

    let requested = std::path::Path::new(target);
    let candidate = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        run.working_directory().join(requested)
    };
    let local_path = candidate
        .canonicalize()
        .ok()
        .filter(|path| path.is_dir() && run.permits_read(path));
    if let Some(path) = local_path.as_deref() {
        add_marketplace_from_local_dir(path, plugin_manager);
    } else if looks_like_git_plugin_source(target) {
        add_marketplace_from_git_source(target, plugin_manager);
    } else {
        eprintln!("\nCould not resolve '{target}' as a path or URL.\n");
    }
}

fn add_marketplace_from_local_dir(path: &std::path::Path, plugin_manager: &plugins::PluginManager) {
    let policy = repl_plugin_policy();
    match plugin_manager.add_marketplace_from_directory_with_policy(path, &policy) {
        Ok(manifest) => println!(
            "\nAdded marketplace '{}' ({} plugins).\n",
            manifest.name,
            manifest.plugins.len()
        ),
        Err(e) => eprintln!("\nFailed to add marketplace: {e}\n"),
    }
}

fn add_marketplace_from_git_source(source: &str, plugin_manager: &plugins::PluginManager) {
    let spec = match parse_pinned_git_source(source) {
        Ok(spec) => spec,
        Err(e) => {
            eprintln!("\nCannot add git marketplace: {e}");
            println!("Use: /plugin marketplace add <git-url>#<tag-or-commit>\n");
            return;
        }
    };
    println!(
        "\nCloning marketplace from '{}' at ref '{}'...",
        spec.url, spec.git_ref
    );
    let policy = repl_plugin_policy();
    match plugin_manager.add_marketplace_from_git_with_policy(spec.url, Some(spec.git_ref), &policy)
    {
        Ok(manifest) => println!(
            "Added marketplace '{}' ({} plugins).\n",
            manifest.name,
            manifest.plugins.len()
        ),
        Err(e) => eprintln!("Failed to add marketplace: {e}\n"),
    }
}

fn plugin_marketplace_remove(target: Option<&str>, plugin_manager: &plugins::PluginManager) {
    if let Some(target) = target {
        match plugin_manager.remove_marketplace(target) {
            Ok(()) => println!("\nRemoved marketplace '{target}'.\n"),
            Err(e) => eprintln!("\nFailed to remove marketplace: {e}\n"),
        }
    } else {
        println!("\nUsage: /plugin marketplace remove <name>\n");
    }
}

fn plugin_marketplace_update(target: Option<&str>, plugin_manager: &plugins::PluginManager) {
    let marketplaces = plugin_manager.list_marketplaces();
    if marketplaces.is_empty() {
        println!("\nNo marketplaces installed.\n");
    } else if let Some(target) = target {
        update_named_marketplace(target, plugin_manager);
    } else {
        println!("\nUpdating {} marketplace(s)...", marketplaces.len());
        for (name, _) in &marketplaces {
            update_marketplace_row(name, plugin_manager);
        }
        println!();
    }
}

fn update_named_marketplace(name: &str, plugin_manager: &plugins::PluginManager) {
    match plugin_manager.update_marketplace(name) {
        Ok(manifest) => println!(
            "\nUpdated marketplace '{}' ({} plugins).\n",
            manifest.name,
            manifest.plugins.len()
        ),
        Err(e) => eprintln!("\nFailed to update '{name}': {e}\n"),
    }
}

fn update_marketplace_row(name: &str, plugin_manager: &plugins::PluginManager) {
    match plugin_manager.update_marketplace(name) {
        Ok(manifest) => println!(
            "  {} - updated ({} plugins)",
            manifest.name,
            manifest.plugins.len()
        ),
        Err(e) => eprintln!("  {name} - failed: {e}"),
    }
}

fn plugin_marketplace_list(plugin_manager: &plugins::PluginManager) {
    let marketplaces = plugin_manager.list_marketplaces();
    if marketplaces.is_empty() {
        println!("\nNo marketplaces installed.");
        println!("Use /plugin marketplace add <path-or-git-url>#<ref> to add one.\n");
        return;
    }

    println!(
        "\n=== Installed Marketplaces ({}) ===\n",
        marketplaces.len()
    );
    for (name, manifest) in &marketplaces {
        println!("  {} ({} plugins)", name, manifest.plugins.len());
        for plugin in &manifest.plugins {
            println!(
                "    - {} - {}",
                plugin.name,
                plugin.description.as_deref().unwrap_or("No description")
            );
        }
    }
    println!("\nInstall: /plugin install <plugin>@<marketplace>\n");
}

fn plugin_marketplace_help() {
    println!("\nMarketplace Commands:");
    println!("  /plugin marketplace add <path/git-url>#<ref> - Add a marketplace");
    println!("  /plugin marketplace remove <name>  - Remove a marketplace");
    println!("  /plugin marketplace update         - Update all marketplaces");
    println!("  /plugin marketplace list           - List marketplaces\n");
}

fn plugin_run_command(
    plugin_name: &str,
    command_name: &str,
    arguments: &str,
    plugin_manager: &plugins::PluginManager,
) -> PluginActionOutcome {
    if let Some(plugin) = plugin_manager.get(plugin_name) {
        let commands = plugin.resolved_commands();
        if let Some(cmd) = commands.iter().find(|c| c.name == command_name) {
            println!("\nRunning plugin command /{plugin_name}:{command_name}\n");
            return PluginActionOutcome::Prompt(PluginCommandInvocation {
                prompt: render_plugin_command_prompt(cmd, arguments),
                allowed_tools: cmd.allowed_tools.clone(),
                model: cmd.model.clone(),
            });
        }
        let available: Vec<_> = commands.iter().map(|c| c.name.clone()).collect();
        eprintln!("\nCommand '{command_name}' not found in plugin '{plugin_name}'.");
        if available.is_empty() {
            eprintln!("This plugin has no commands.\n");
        } else {
            eprintln!("Available: {}\n", available.join(", "));
        }
    } else {
        eprintln!("\nPlugin '{plugin_name}' not found. Use /plugin to see installed plugins.\n");
    }
    PluginActionOutcome::Handled
}

fn render_plugin_command_prompt(cmd: &plugins::PluginCommand, arguments: &str) -> String {
    let arguments = arguments.trim();
    if arguments.is_empty() {
        return cmd.content.clone();
    }

    if cmd.content.contains("$ARGUMENTS") {
        return cmd.content.replace("$ARGUMENTS", arguments);
    }

    format!("{}\n\nArguments:\n{arguments}", cmd.content.trim_end())
}

/// Handle the `/mode` slash command.
///
/// - No args: show current mode info and list presets
/// - Preset name: switch to that preset
/// - `--agency`/`--quality`/`--scope`: override individual axes
pub fn handle_mode_command(args: &str) -> SlashCommandResult {
    use openclaudia::modes::{self, BehaviorMode, Preset};

    let args = args.trim();

    // No args: show available presets
    if args.is_empty() {
        println!("\nBehavioral Modes:");
        println!("  Switch with /mode <preset> or override axes individually.\n");
        println!("  Presets:");
        for (name, desc) in modes::list_presets() {
            println!("    {name:<12} {desc}");
        }
        println!();
        println!("  Modifiers (add with /mode <preset> +<modifier>):");
        for (name, desc) in modes::list_modifiers() {
            println!("    {name:<16} {desc}");
        }
        println!();
        println!("  Examples:");
        println!("    /mode create              Switch to create preset");
        println!("    /mode create +bold        Create preset with bold modifier");
        println!("    /mode safe +context-pacing  Safe preset with pacing");
        println!();
        return SlashCommandResult::Handled;
    }

    // Parse: <preset> [+modifier ...] or axis overrides
    let parts: Vec<&str> = args.split_whitespace().collect();

    // Try to parse first arg as a preset
    let first = parts[0];

    // Check for axis-override syntax: --agency=X --quality=Y --scope=Z
    if first.starts_with("--") {
        return parse_axis_overrides(&parts);
    }

    // Parse as preset name
    let preset = match first.parse::<Preset>() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\n{e}");
            eprintln!("Use /mode to see available presets.\n");
            return SlashCommandResult::Handled;
        }
    };

    let mut mode = BehaviorMode::from_preset(preset);

    // Parse remaining args for +modifiers
    for part in &parts[1..] {
        if let Some(mod_name) = part.strip_prefix('+') {
            match mod_name.parse::<openclaudia::modes::Modifier>() {
                Ok(m) => mode.add_modifier(m),
                Err(e) => {
                    eprintln!("\n{e}\n");
                    return SlashCommandResult::Handled;
                }
            }
        } else {
            eprintln!("\nUnexpected argument: \"{part}\". Use +modifier to add modifiers.\n");
            return SlashCommandResult::Handled;
        }
    }

    println!(
        "\n\u{2713} Mode: \x1b[36m{}\x1b[0m ({})\n",
        mode.display_name(),
        mode
    );

    SlashCommandResult::SetBehaviorMode(mode)
}

/// Parse `--agency=X --quality=Y --scope=Z` style overrides into a custom mode.
fn parse_axis_overrides(parts: &[&str]) -> SlashCommandResult {
    use openclaudia::modes::BehaviorMode;

    let mut mode = BehaviorMode::default();
    let mut had_error = false;

    for part in parts {
        if let Some(val) = part
            .strip_prefix("--agency=")
            .or_else(|| part.strip_prefix("--agency "))
        {
            match val.parse() {
                Ok(a) => mode.agency = a,
                Err(e) => {
                    eprintln!("\n{e}\n");
                    had_error = true;
                }
            }
        } else if let Some(val) = part
            .strip_prefix("--quality=")
            .or_else(|| part.strip_prefix("--quality "))
        {
            match val.parse() {
                Ok(q) => mode.quality = q,
                Err(e) => {
                    eprintln!("\n{e}\n");
                    had_error = true;
                }
            }
        } else if let Some(val) = part
            .strip_prefix("--scope=")
            .or_else(|| part.strip_prefix("--scope "))
        {
            match val.parse() {
                Ok(s) => mode.scope = s,
                Err(e) => {
                    eprintln!("\n{e}\n");
                    had_error = true;
                }
            }
        } else if let Some(mod_name) = part.strip_prefix('+') {
            match mod_name.parse() {
                Ok(m) => mode.add_modifier(m),
                Err(e) => {
                    eprintln!("\n{e}\n");
                    had_error = true;
                }
            }
        } else {
            eprintln!("\nUnrecognized flag: \"{part}\"\n");
            had_error = true;
        }
    }

    if had_error {
        return SlashCommandResult::Handled;
    }

    println!("\n\u{2713} Mode: \x1b[36mcustom\x1b[0m ({mode})\n");

    SlashCommandResult::SetBehaviorMode(mode)
}

// ─── Tests ────────────────────────────────────────────────────────────────────
//
// These tests pin the *current* OC contracts against the Phase 1 spec (#539).
// Some cases document divergences from CC reference behavior (filed as gap
// issues #653, #657, #659, #662, #663, #666); others pin gaps that have since
// been closed. If a test starts failing, the production behavior changed and
// the pin should be updated consciously.
//
// Test layout:
//   - spec_compact_*      — §1 /compact
//   - spec_resume_*       — §2 /continue|/load|/resume
//   - spec_effort_*       — §3 /effort
//   - spec_plan_*         — §4 /plan
//   - spec_model_*        — §5 /model
//   - spec_cost_*         — §6 /cost
//   - spec_agents_*       — §7 /agents
//   - spec_skill_*        — §8 /skill|/skills
//   - spec_unknown_*      — §9 unknown command
//   - gap_missing_*       — Commands entirely absent from OC (gap A–F)
//
#[cfg(test)]
mod tests {
    use super::{
        gh_bin, git_bin, handle_slash_command, handle_slash_command_for_run, hook_status_lines,
        parse_pinned_git_source, permission_status_lines, plugin_install_dir_for_name,
        project_mcp_server_count_from_str, render_agents_listing, render_plugin_command_prompt,
        repl_doctor_report, slash_plugin, PinnedGitSource, PinnedGitSourceError, PluginAction,
        SlashCommandResult,
    };
    use openclaudia::config::{Hook, HookEntry, HookPolicy, HooksConfig, PermissionsConfig};
    use openclaudia::plugins::PluginCommand;
    use std::collections::{HashMap, HashSet};

    /// Convenience: empty message vec, dummy provider + model.
    fn ctx() -> Vec<serde_json::Value> {
        Vec::new()
    }

    #[test]
    fn repl_doctor_uses_attached_config_without_claiming_a_file_read() {
        let config: openclaudia::config::AppConfig = serde_yaml::from_str(
            "proxy:\n  port: 8080\n  host: 127.0.0.1\n  target: local\nproviders:\n  local:\n    base_url: http://localhost:1234/v1\n",
        )
        .expect("typed test configuration");
        let (_root, run) = scoped_run();
        let client = reqwest::Client::new();
        let adapter = openclaudia::providers::get_adapter("local").expect("local adapter");
        let plugin_manager =
            openclaudia::plugins::PluginManager::new_for_project(run.project_root());
        let runtime = openclaudia::doctor::DoctorRuntimeSnapshot::from_run(&run)
            .with_composed_provider_transport(&client, adapter)
            .with_composed_plugin_manager(&plugin_manager);
        let report = repl_doctor_report(Some(&run), Some(&config), Some(&runtime));
        let receipt = report
            .receipts()
            .iter()
            .find(|receipt| receipt.check_id() == "configuration")
            .expect("configuration receipt");

        assert_eq!(receipt.code(), "configuration.attached");
        assert!(receipt.observed_effects().is_empty());
        assert_eq!(
            report
                .receipts()
                .iter()
                .find(|receipt| receipt.check_id() == "runtime.context")
                .expect("runtime context receipt")
                .code(),
            "runtime.context.composed"
        );
        assert_eq!(
            report
                .receipts()
                .iter()
                .find(|receipt| receipt.check_id() == "runtime.provider_transport")
                .expect("provider transport receipt")
                .code(),
            "runtime.provider_transport.composed"
        );
        assert_eq!(
            report
                .receipts()
                .iter()
                .find(|receipt| receipt.check_id() == "runtime.plugins")
                .expect("plugin receipt")
                .code(),
            "runtime.plugins.empty"
        );
    }

    fn scoped_run() -> (
        tempfile::TempDir,
        std::sync::Arc<openclaudia::tools::ToolRunContext>,
    ) {
        let root = tempfile::tempdir().expect("slash project root");
        let run = openclaudia::tools::ToolRunContext::builder(
            openclaudia::state::SessionId::new(),
            root.path(),
        )
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(HashMap::new())
        .workspace_access(openclaudia::tools::WorkspaceAccess::ReadWrite)
        .process(false)
        .network(false)
        .secrets(false)
        .provider("slash-test")
        .build()
        .expect("slash run");
        (root, run)
    }

    // ── §1 /compact ──────────────────────────────────────────────────────────

    /// OC: `/compact` and `/summarize` both return `SlashCommandResult::Compact`.
    /// CC parity: both aliases should trigger compaction.
    #[test]
    fn spec_compact_bare_returns_compact() {
        let result = handle_slash_command("/compact", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(
                result,
                Some(SlashCommandResult::Compact { instructions: None })
            ),
            "/compact must return Compact"
        );
    }

    #[test]
    fn spec_compact_summarize_alias_returns_compact() {
        let result = handle_slash_command("/summarize", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(
                result,
                Some(SlashCommandResult::Compact { instructions: None })
            ),
            "/summarize alias must return Compact"
        );
    }

    #[test]
    fn spec_compact_arg_is_preserved_as_custom_instructions() {
        let result = handle_slash_command(
            "/compact write tests first",
            &mut ctx(),
            "anthropic",
            "claude-sonnet",
        );
        let Some(SlashCommandResult::Compact { instructions }) = result else {
            panic!("/compact with custom instructions must return Compact")
        };
        assert_eq!(instructions.as_deref(), Some("write tests first"));
    }

    // ── §2 /continue | /load | /resume ───────────────────────────────────────

    /// OC: bare `/resume` with no sessions returns `Handled` (not an interactive
    /// picker as CC does).
    #[test]
    fn spec_resume_bare_no_sessions_returns_handled() {
        // list_chat_sessions() reads from disk; in test environment it should
        // return an empty list unless the dev machine has sessions.  We only
        // assert on the return type, not whether a session was loaded.
        let result = handle_slash_command("/resume", &mut ctx(), "anthropic", "claude-sonnet");
        // Either Handled (no sessions) or LoadSession (sessions exist on disk).
        // Both are valid OC behaviors; neither matches CC's interactive picker.
        assert!(
            matches!(
                result,
                Some(SlashCommandResult::Handled | SlashCommandResult::LoadSession(_))
            ),
            "bare /resume must return Handled or LoadSession, never None"
        );
    }

    /// OC: `/resume <non-numeric>` prints usage and returns Handled.
    /// CC: would treat the arg as a search term / UUID.  Pinned divergence.
    #[test]
    fn spec_resume_non_numeric_arg_rejected() {
        let result = handle_slash_command(
            "/resume some-title-search",
            &mut ctx(),
            "anthropic",
            "claude-sonnet",
        );
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/resume <non-numeric> must return Handled (not LoadSession) — OC only accepts numeric index (gap)"
        );
    }

    /// `/resume <UUID>` loads the session by ID. The actual disk read happens
    /// in the REPL dispatcher so this parser can return `LoadSession` without
    /// requiring the file to exist in unit tests.
    #[test]
    fn spec_resume_uuid_arg_returns_load_session() {
        let result = handle_slash_command(
            "/resume 550e8400-e29b-41d4-a716-446655440000",
            &mut ctx(),
            "anthropic",
            "claude-sonnet",
        );
        assert!(
            matches!(
                result,
                Some(SlashCommandResult::LoadSession(ref s))
                    if s == "550e8400-e29b-41d4-a716-446655440000"
            ),
            "/resume <UUID> must return LoadSession"
        );
    }

    #[test]
    fn spec_resume_uuid_aliases_return_load_session() {
        for input in [
            "/continue 550E8400-E29B-41D4-A716-446655440000",
            "/load 550e8400e29b41d4a716446655440000",
        ] {
            let result = handle_slash_command(input, &mut ctx(), "anthropic", "claude-sonnet");
            assert!(
                matches!(
                    result,
                    Some(SlashCommandResult::LoadSession(ref s))
                        if s == "550e8400-e29b-41d4-a716-446655440000"
                ),
                "{input} must canonicalize and return LoadSession"
            );
        }
    }

    /// `/continue` is an alias for `/resume` — same behavior.
    #[test]
    fn spec_resume_continue_alias_non_numeric_rejected() {
        let result = handle_slash_command(
            "/continue fuzzy-search-term",
            &mut ctx(),
            "anthropic",
            "claude-sonnet",
        );
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/continue <non-numeric> must return Handled"
        );
    }

    /// `/load` is an alias for `/resume` — same behavior.
    #[test]
    fn spec_resume_load_alias_non_numeric_rejected() {
        let result =
            handle_slash_command("/load my-session", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/load <non-numeric> must return Handled"
        );
    }

    // ── §3 /effort ───────────────────────────────────────────────────────────

    /// OC: `/effort low` returns `SetEffort("low")`.
    #[test]
    fn spec_effort_low_returns_set_effort() {
        let result = handle_slash_command("/effort low", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::SetEffort(ref s)) if s == "low"),
            "/effort low must return SetEffort(\"low\")"
        );
    }

    /// OC: `/effort l` (short alias) returns `SetEffort("low")`.
    #[test]
    fn spec_effort_short_alias_l() {
        let result = handle_slash_command("/effort l", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::SetEffort(ref s)) if s == "low"),
            "/effort l alias must return SetEffort(\"low\")"
        );
    }

    /// OC: `/effort medium` returns `SetEffort("medium")`.
    #[test]
    fn spec_effort_medium_returns_set_effort() {
        let result =
            handle_slash_command("/effort medium", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::SetEffort(ref s)) if s == "medium"),
            "/effort medium must return SetEffort(\"medium\")"
        );
    }

    /// OC: `/effort high` returns `SetEffort("high")`.
    #[test]
    fn spec_effort_high_returns_set_effort() {
        let result = handle_slash_command("/effort high", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::SetEffort(ref s)) if s == "high"),
            "/effort high must return SetEffort(\"high\")"
        );
    }

    /// OC: bare `/effort` returns `CycleEffort`.
    /// CC: bare `/effort` shows current value (no cycling).  Pinned divergence.
    #[test]
    fn spec_effort_bare_cycles_not_shows_current() {
        let result = handle_slash_command("/effort", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::CycleEffort)),
            "bare /effort must return CycleEffort (OC diverges from CC — CC shows current value)"
        );
    }

    /// OC: `/effort max` returns `SetEffort("max")`.
    #[test]
    fn spec_effort_max_returns_set_effort() {
        let result = handle_slash_command("/effort max", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::SetEffort(ref s)) if s == "max"),
            "/effort max must return SetEffort(\"max\")"
        );
    }

    /// OC: `/effort auto` returns `SetEffort("auto")`.
    #[test]
    fn spec_effort_auto_returns_set_effort() {
        let result = handle_slash_command("/effort auto", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::SetEffort(ref s)) if s == "auto"),
            "/effort auto must return SetEffort(\"auto\")"
        );
    }

    #[test]
    fn spec_fast_anthropic_switches_to_haiku_and_low_effort() {
        let result = handle_slash_command("/fast", &mut ctx(), "anthropic", "claude-opus-4-6");
        assert!(
            matches!(
                result,
                Some(SlashCommandResult::FastMode { ref effort, ref model })
                    if effort == "low"
                        && model.as_deref() == Some("claude-haiku-4-5-20251001")
            ),
            "/fast must set low effort and switch Anthropic sessions to Haiku"
        );
    }

    #[test]
    fn spec_fast_keeps_model_when_already_fast() {
        let result = handle_slash_command(
            "/fast",
            &mut ctx(),
            "anthropic",
            "claude-haiku-4-5-20251001",
        );
        assert!(
            matches!(
                result,
                Some(SlashCommandResult::FastMode { ref effort, ref model })
                    if effort == "low" && model.is_none()
            ),
            "/fast must avoid a no-op model switch when already on the fast model"
        );
    }

    #[test]
    fn spec_fast_unknown_provider_sets_low_effort_without_model_switch() {
        let result = handle_slash_command("/fast", &mut ctx(), "local", "custom-fast");
        assert!(
            matches!(
                result,
                Some(SlashCommandResult::FastMode { ref effort, ref model })
                    if effort == "low" && model.is_none()
            ),
            "/fast must still lower effort for providers without a static fast model"
        );
    }

    #[test]
    fn spec_fast_kimi_uses_highspeed_model() {
        let result = handle_slash_command("/fast", &mut ctx(), "kimi", "kimi-k2.7-code");
        assert!(
            matches!(
                result,
                Some(SlashCommandResult::FastMode { ref effort, ref model })
                    if effort == "low" && model.as_deref() == Some("kimi-k2.7-code-highspeed")
            ),
            "/fast must switch Kimi sessions to the highspeed model"
        );
    }

    #[test]
    fn spec_fast_minimax_uses_highspeed_model() {
        let result = handle_slash_command("/fast", &mut ctx(), "minimax", "MiniMax-M3");
        assert!(
            matches!(
                result,
                Some(SlashCommandResult::FastMode { ref effort, ref model })
                    if effort == "low" && model.as_deref() == Some("MiniMax-M2.7-highspeed")
            ),
            "/fast must switch MiniMax sessions to a highspeed model"
        );
    }

    // ── §4 /plan ─────────────────────────────────────────────────────────────

    /// OC: `/plan` returns `ToggleMode` (unconditionally toggles Build↔Plan).
    /// CC: `/plan` only ever enters plan mode; second invocation shows current plan.
    /// Pinned divergence.
    #[test]
    fn spec_plan_bare_returns_toggle_mode() {
        let result = handle_slash_command("/plan", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::ToggleMode)),
            "/plan must return ToggleMode (OC toggles both ways; CC only enables)"
        );
    }

    /// OC: `/plan open` is not a special sub-command — still returns `ToggleMode`
    /// (the arg is ignored).  CC: `/plan open` opens the plan file in $EDITOR.
    /// Pinned divergence.
    #[test]
    fn spec_plan_open_arg_ignored_returns_toggle_mode() {
        let result = handle_slash_command("/plan open", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::ToggleMode)),
            "/plan open must return ToggleMode — OC ignores args (gap: CC opens $EDITOR)"
        );
    }

    /// OC: `/plan <description>` ignores the description and returns `ToggleMode`.
    /// CC: passes description to trigger an immediate LLM query.  Pinned divergence.
    #[test]
    fn spec_plan_description_arg_ignored_returns_toggle_mode() {
        let result = handle_slash_command(
            "/plan design the new API",
            &mut ctx(),
            "anthropic",
            "claude-sonnet",
        );
        assert!(
            matches!(result, Some(SlashCommandResult::ToggleMode)),
            "/plan <description> must return ToggleMode — OC ignores description arg (gap)"
        );
    }

    // ── §5 /model ────────────────────────────────────────────────────────────

    /// OC: bare `/model` prints current model and returns `Handled`.
    /// CC: bare `/model` opens an interactive TUI picker.  Pinned divergence.
    #[test]
    fn spec_model_bare_returns_handled_not_picker() {
        let result = handle_slash_command("/model", &mut ctx(), "anthropic", "claude-sonnet-4-5");
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "bare /model must return Handled (OC shows info; CC shows interactive picker)"
        );
    }

    /// OC: `/model list` returns `Handled` (prints static list).
    #[test]
    fn spec_model_list_returns_handled() {
        let result =
            handle_slash_command("/model list", &mut ctx(), "anthropic", "claude-sonnet-4-5");
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/model list must return Handled"
        );
    }

    #[test]
    fn spec_model_list_returns_handled_inside_current_thread_runtime() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        rt.block_on(async {
            let result = handle_slash_command("/model list", &mut ctx(), "openai", "gpt-5.5");
            assert!(
                matches!(result, Some(SlashCommandResult::Handled)),
                "/model list must not panic when called from the legacy REPL runtime"
            );
        });
    }

    /// OC: `/models` is an alias that lists models (returns `Handled`).
    #[test]
    fn spec_models_alias_returns_handled() {
        let result = handle_slash_command("/models", &mut ctx(), "anthropic", "claude-sonnet-4-5");
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/models must return Handled"
        );
    }

    /// OC: `/model <name>` returns `SwitchModel` for any non-empty upstream model ID.
    /// Static catalog entries are discovery hints, not an allowlist.
    #[test]
    fn spec_model_switch_accepts_arbitrary_upstream_model_id() {
        let result = handle_slash_command(
            "/model claude-opus-4-99-future",
            &mut ctx(),
            "anthropic",
            "claude-sonnet-4-5",
        );
        assert!(
            matches!(result, Some(SlashCommandResult::SwitchModel(model)) if model == "claude-opus-4-99-future"),
            "/model <name> must accept arbitrary upstream model IDs"
        );
    }

    /// `/model default` resets to the canonical provider default instead of
    /// treating `default` as a literal upstream model ID.
    #[test]
    fn spec_model_default_resets_to_provider_default() {
        let result = handle_slash_command(
            "/model default",
            &mut ctx(),
            "anthropic",
            "claude-sonnet-4-5",
        );
        assert!(
            matches!(result, Some(SlashCommandResult::SwitchModel(model)) if model == openclaudia::providers::default_model_for_target("anthropic")),
            "/model default must switch to the provider default model"
        );
    }

    #[test]
    fn spec_model_default_reset_is_case_insensitive() {
        let result = handle_slash_command("/model DEFAULT", &mut ctx(), "qwen", "qwen3.7-coder");
        assert!(
            matches!(result, Some(SlashCommandResult::SwitchModel(model)) if model == openclaudia::providers::default_model_for_target("qwen")),
            "/model DEFAULT must reset using the provider default table"
        );
    }

    // ── §6 /cost ─────────────────────────────────────────────────────────────

    /// OC: `/cost` prints token estimate + dollar figure and returns `Handled`.
    /// Estimation is over concatenated message content strings (not actual billed
    /// tokens).  Pin: always returns `Handled`.
    #[test]
    fn spec_cost_returns_handled() {
        let mut msgs = vec![
            serde_json::json!({"role": "user", "content": "hello world"}),
            serde_json::json!({"role": "assistant", "content": "hi there"}),
        ];
        let result = handle_slash_command("/cost", &mut msgs, "anthropic", "claude-sonnet-4-5");
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/cost must return Handled"
        );
    }

    /// OC: `/cost` with empty message list still returns `Handled` (zero tokens).
    #[test]
    fn spec_cost_empty_messages_returns_handled() {
        let result = handle_slash_command("/cost", &mut ctx(), "anthropic", "claude-sonnet-4-5");
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/cost on empty conversation must return Handled"
        );
    }

    // ── §7 /agents ───────────────────────────────────────────────────────────

    /// OC: `/agents` prints a static list and returns `Handled`.
    /// CC: renders an interactive `AgentsMenu` TUI component.  Pinned divergence.
    #[test]
    fn spec_agents_returns_handled_not_interactive() {
        let result = handle_slash_command("/agents", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/agents must return Handled (OC is non-interactive; CC renders TUI)"
        );
    }

    #[test]
    fn spec_agents_listing_separates_task_spawnable_agents_from_coordinator() {
        let listing = render_agents_listing();
        assert!(listing.contains("Task-spawnable subagent types"));
        assert!(listing.contains("general-purpose"));
        assert!(listing.contains("explore"));
        assert!(listing.contains("plan"));
        assert!(listing.contains("guide"));
        assert!(listing.contains("Coordinator profile"));
        assert!(listing.contains("coordinator"));
        assert!(listing.contains("Not accepted by the `task` tool"));
    }

    // ── §8 /skill | /skills ──────────────────────────────────────────────────

    /// OC: bare `/skill` lists skills from disk and returns `Handled`.
    #[test]
    fn spec_skill_bare_returns_handled() {
        let result = handle_slash_command("/skill", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "bare /skill must return Handled"
        );
    }

    /// OC: `/skills` is an alias for `/skill` bare — returns `Handled`.
    #[test]
    fn spec_skills_alias_returns_handled() {
        let result = handle_slash_command("/skills", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/skills alias must return Handled"
        );
    }

    /// OC: `/skill <unknown-name>` returns `Handled` (skill not found path).
    /// The `eprintln!` fires; result is still Handled.
    #[test]
    fn spec_skill_unknown_name_returns_handled() {
        let result = handle_slash_command(
            "/skill oc-test-nonexistent-skill-xyz",
            &mut ctx(),
            "anthropic",
            "claude-sonnet",
        );
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/skill <unknown> must return Handled"
        );
    }

    #[test]
    fn skill_invocation_uses_the_exact_run_project_layer() {
        let root_a = tempfile::tempdir().expect("slash skill root A");
        let root_b = tempfile::tempdir().expect("slash skill root B");
        let skill_name = "s019-slash-run-bound-cc308c2e";
        let skill_dir = root_a.path().join(".openclaudia/skills").join(skill_name);
        std::fs::create_dir_all(&skill_dir).expect("slash skill directory");
        std::fs::write(
            skill_dir.join("SKILL.md"),
            format!(
                "---\nname: {skill_name}\ndescription: exact slash run\n---\nS019-SLASH-RUN-A\n"
            ),
        )
        .expect("slash skill fixture");
        let make_run = |root: &std::path::Path| {
            openclaudia::tools::ToolRunContext::builder(openclaudia::state::SessionId::new(), root)
                .read_only_roots(Vec::new())
                .read_write_roots(Vec::new())
                .environment_grants(HashMap::new())
                .workspace_access(openclaudia::tools::WorkspaceAccess::ReadWrite)
                .process(false)
                .network(false)
                .secrets(false)
                .provider("slash-test")
                .build()
                .expect("slash test run")
        };
        let run_a = make_run(root_a.path());
        let run_b = make_run(root_b.path());
        let command = format!("/skill {skill_name}");

        let own = handle_slash_command_for_run(
            &command,
            &mut ctx(),
            "anthropic",
            "claude-sonnet",
            &run_a,
        );
        assert!(matches!(
            own,
            Some(SlashCommandResult::Skill(invocation))
                if invocation.prompt.contains("S019-SLASH-RUN-A")
        ));

        let foreign = handle_slash_command_for_run(
            &command,
            &mut ctx(),
            "anthropic",
            "claude-sonnet",
            &run_b,
        );
        assert!(
            matches!(foreign, Some(SlashCommandResult::Handled)),
            "a sibling run must not invoke the other project's skill"
        );
    }

    // ── §9 Unknown slash command ──────────────────────────────────────────────

    /// OC: any unrecognised command returns `Some(Handled)` (with `eprintln!`).
    /// CC: the UI layer returns `undefined` / null; the message is the caller's
    /// responsibility.  OC inlines the error message.  Acceptable divergence.
    #[test]
    fn spec_unknown_command_returns_handled() {
        let result = handle_slash_command(
            "/xyzzy_unknown_cmd",
            &mut ctx(),
            "anthropic",
            "claude-sonnet",
        );
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "unknown command must return Some(Handled)"
        );
    }

    /// OC: unknown command never returns None (which would mean "not a slash command").
    #[test]
    fn spec_unknown_command_never_none() {
        let result = handle_slash_command(
            "/totally_bogus_command",
            &mut ctx(),
            "anthropic",
            "claude-sonnet",
        );
        assert!(
            result.is_some(),
            "unknown slash command must not return None"
        );
    }

    #[test]
    fn slash_git_helpers_use_resolved_binary_paths() {
        let git = git_bin().expect("slash tests require git on PATH");
        assert!(
            git.is_absolute(),
            "git_bin must resolve git to an absolute path, got {}",
            git.display()
        );

        if let Ok(gh) = gh_bin() {
            assert!(
                gh.is_absolute(),
                "gh_bin must resolve gh to an absolute path, got {}",
                gh.display()
            );
        }

        let src = include_str!("slash.rs");
        let cfg_test = src
            .find("#[cfg(test)]")
            .expect("test module marker must be present");
        let production = &src[..cfg_test];

        for (idx, raw_line) in production.lines().enumerate() {
            let code = raw_line.split("//").next().unwrap_or("");
            assert!(
                !code.contains("Command::new(\"git\")")
                    && !code.contains("std::process::Command::new(\"git\")"),
                "production slash code must not invoke bare git; line {n}: {raw_line}",
                n = idx + 1,
            );
            assert!(
                !code.contains("Command::new(\"gh\")")
                    && !code.contains("std::process::Command::new(\"gh\")"),
                "production slash code must not invoke bare gh; line {n}: {raw_line}",
                n = idx + 1,
            );
            assert!(
                !code.contains("Command::new(\"which\")")
                    && !code.contains("std::process::Command::new(\"which\")"),
                "production slash code must not probe PATH with bare which; line {n}: {raw_line}",
                n = idx + 1,
            );
        }
    }

    #[test]
    fn plugin_install_dir_rejects_path_like_plugin_names() {
        for bad in ["../outside", "bad/name", "bad\\name", ".hidden", "CON"] {
            assert!(
                plugin_install_dir_for_name(bad, std::path::Path::new("/project")).is_err(),
                "plugin name {bad:?} must not be usable as an install path"
            );
        }
    }

    #[test]
    fn plugin_install_dir_accepts_safe_plugin_name() {
        let path =
            plugin_install_dir_for_name("safe-plugin", std::path::Path::new("/explicit-project"))
                .expect("safe name should pass");

        assert_eq!(
            path,
            std::path::PathBuf::from("/explicit-project/.openclaudia/plugins/safe-plugin")
        );
    }

    #[test]
    fn pinned_git_source_accepts_https_url_with_ref() {
        assert_eq!(
            parse_pinned_git_source("https://github.com/acme/demo.git#v1.2.3").unwrap(),
            PinnedGitSource {
                url: "https://github.com/acme/demo.git",
                git_ref: "v1.2.3"
            }
        );
    }

    #[test]
    fn pinned_git_source_accepts_scp_style_url_with_ref() {
        assert_eq!(
            parse_pinned_git_source("git@github.com:acme/demo.git#main").unwrap(),
            PinnedGitSource {
                url: "git@github.com:acme/demo.git",
                git_ref: "main"
            }
        );
    }

    #[test]
    fn pinned_git_source_rejects_missing_or_empty_ref() {
        assert_eq!(
            parse_pinned_git_source("https://github.com/acme/demo.git").unwrap_err(),
            PinnedGitSourceError::MissingRef
        );
        assert_eq!(
            parse_pinned_git_source("https://github.com/acme/demo.git#").unwrap_err(),
            PinnedGitSourceError::EmptyRef
        );
    }

    #[test]
    fn plugin_install_scp_git_url_is_not_parsed_as_marketplace_spec() {
        let result = slash_plugin("install git@github.com:acme/demo.git#main");
        match result {
            SlashCommandResult::Plugin(PluginAction::Install {
                plugin,
                marketplace,
            }) => {
                assert_eq!(plugin.as_deref(), Some("git@github.com:acme/demo.git#main"));
                assert_eq!(marketplace, None);
            }
            _ => panic!("scp-style git source must remain a direct plugin install"),
        }
    }

    #[test]
    fn plugin_run_command_slash_preserves_arguments() {
        let result = handle_slash_command(
            "/demo:fix src/main.rs --strict",
            &mut ctx(),
            "anthropic",
            "claude-sonnet",
        );
        match result {
            Some(SlashCommandResult::Plugin(PluginAction::RunCommand {
                plugin_name,
                command_name,
                arguments,
            })) => {
                assert_eq!(plugin_name, "demo");
                assert_eq!(command_name, "fix");
                assert_eq!(arguments, "src/main.rs --strict");
            }
            _ => panic!("/plugin:command args must resolve to RunCommand with arguments"),
        }
    }

    #[test]
    fn plugin_command_prompt_replaces_arguments_placeholder() {
        let cmd = PluginCommand {
            name: "fix".to_string(),
            description: None,
            content: "Review $ARGUMENTS carefully.".to_string(),
            allowed_tools: None,
            argument_hint: None,
            model: None,
        };

        assert_eq!(
            render_plugin_command_prompt(&cmd, "src/main.rs"),
            "Review src/main.rs carefully."
        );
    }

    #[test]
    fn plugin_command_prompt_appends_arguments_when_no_placeholder_exists() {
        let cmd = PluginCommand {
            name: "fix".to_string(),
            description: None,
            content: "Review this request.\n".to_string(),
            allowed_tools: None,
            argument_hint: None,
            model: None,
        };

        assert_eq!(
            render_plugin_command_prompt(&cmd, "src/main.rs"),
            "Review this request.\n\nArguments:\nsrc/main.rs"
        );
    }

    // ── Rewind/checkpoint command parity ─────────────────────────────────────
    //
    // `/rewind` and `/checkpoint` are implemented in the legacy REPL by
    // listing user turns or returning a typed multi-undo request.

    fn conversation_with_two_turns() -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({"role": "user", "content": "first"}),
            serde_json::json!({"role": "assistant", "content": "reply"}),
            serde_json::json!({"role": "user", "content": "second"}),
            serde_json::json!({"role": "assistant", "content": "reply"}),
        ]
    }

    #[test]
    fn rewind_without_count_lists_turns_and_returns_handled() {
        let result = handle_slash_command(
            "/rewind",
            &mut conversation_with_two_turns(),
            "anthropic",
            "claude-sonnet",
        );
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/rewind without a count must list turns and be fully handled"
        );
    }

    #[test]
    fn rewind_with_count_returns_typed_rewind_request() {
        let result = handle_slash_command(
            "/rewind 2",
            &mut conversation_with_two_turns(),
            "anthropic",
            "claude-sonnet",
        );
        assert!(
            matches!(result, Some(SlashCommandResult::Rewind(2))),
            "/rewind N must request an N-turn rewind"
        );
    }

    #[test]
    fn checkpoint_alias_returns_typed_rewind_request() {
        let result = handle_slash_command(
            "/checkpoint 1",
            &mut conversation_with_two_turns(),
            "anthropic",
            "claude-sonnet",
        );
        assert!(
            matches!(result, Some(SlashCommandResult::Rewind(1))),
            "/checkpoint N must alias /rewind N"
        );
    }

    #[test]
    fn latest_assistant_reasoning_uses_newest_assistant_only() {
        let messages = vec![
            serde_json::json!({
                "role": "assistant",
                "content": "older",
                "reasoning_content": "older thinking"
            }),
            serde_json::json!({"role": "user", "content": "next"}),
            serde_json::json!({
                "role": "assistant",
                "content": "newer",
                "reasoning_content": "  newest thinking  "
            }),
        ];

        assert_eq!(
            super::latest_assistant_reasoning_content(&messages),
            Some("newest thinking")
        );
    }

    #[test]
    fn latest_assistant_reasoning_does_not_skip_back_past_latest_assistant() {
        let messages = vec![
            serde_json::json!({
                "role": "assistant",
                "content": "older",
                "reasoning_content": "older thinking"
            }),
            serde_json::json!({"role": "user", "content": "next"}),
            serde_json::json!({"role": "assistant", "content": "newer"}),
        ];

        assert_eq!(super::latest_assistant_reasoning_content(&messages), None);
    }

    #[test]
    fn thinkback_command_is_registered_and_returns_handled() {
        assert!(
            super::super::command_registry::registry()
                .get("thinkback")
                .is_some(),
            "/thinkback must be registered, not unknown-command fallback"
        );
        let result = handle_slash_command(
            "/thinkback",
            &mut vec![serde_json::json!({
                "role": "assistant",
                "content": "answer",
                "reasoning_content": "private reasoning"
            })],
            "anthropic",
            "claude-sonnet",
        );
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/thinkback must replay saved reasoning and return Handled"
        );
    }

    #[test]
    fn thinkback_with_args_returns_usage_handled() {
        let result = handle_slash_command(
            "/thinkback now",
            &mut conversation_with_two_turns(),
            "anthropic",
            "claude-sonnet",
        );
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/thinkback with extra args must stay handled"
        );
    }

    /// Gap E (#663): `/mcp` now reports configured MCP servers instead of
    /// falling through to the unknown-command path.
    #[test]
    fn mcp_command_is_registered_and_returns_handled() {
        assert!(
            super::super::command_registry::registry()
                .get("mcp")
                .is_some(),
            "/mcp must be registered, not unknown-command fallback"
        );
        let result = handle_slash_command("/mcp help", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/mcp help must return Handled through the registry"
        );
    }

    /// Gap E (#663): `/mcp add <server>` now returns an explicit diagnostic
    /// instead of falling through as an unknown command.
    #[test]
    fn mcp_add_returns_handled_with_guidance() {
        let result = handle_slash_command(
            "/mcp add my-server",
            &mut ctx(),
            "anthropic",
            "claude-sonnet",
        );
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/mcp add must return Handled with configuration guidance"
        );
    }

    #[test]
    fn project_mcp_count_accepts_claude_code_wrapper_shape() {
        let count = project_mcp_server_count_from_str(
            r#"{"mcpServers":{"github":{"command":"gh","args":["api"]},"docs":{"type":"http","url":"https://example.com/mcp"}}}"#,
        )
        .expect("wrapper shape must parse");
        assert_eq!(count, 2);
    }

    #[test]
    fn project_mcp_count_accepts_direct_map_shape() {
        let count = project_mcp_server_count_from_str(
            r#"{"github":{"command":"gh"},"docs":{"type":"http","url":"https://example.com/mcp"}}"#,
        )
        .expect("direct map shape must parse");
        assert_eq!(count, 2);
    }

    #[test]
    fn project_mcp_count_rejects_non_object_mcp_servers() {
        let err = project_mcp_server_count_from_str(r#"{"mcpServers":[]}"#)
            .expect_err("array mcpServers must be rejected");
        assert!(
            err.contains("mcpServers"),
            "error should identify mcpServers shape: {err}"
        );
    }

    /// Gap F (#666): `/hooks` now reports configured lifecycle hooks.
    #[test]
    fn hooks_command_is_registered_and_returns_handled() {
        assert!(
            super::super::command_registry::registry()
                .get("hooks")
                .is_some(),
            "/hooks must be registered, not unknown-command fallback"
        );
        let result = handle_slash_command("/hooks", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/hooks must print status and return Handled"
        );
    }

    /// Gap F (#666): `/permissions` now reports rules and MCP allowlists.
    #[test]
    fn permissions_command_is_registered_and_returns_handled() {
        assert!(
            super::super::command_registry::registry()
                .get("permissions")
                .is_some(),
            "/permissions must be registered, not unknown-command fallback"
        );
        let result = handle_slash_command("/permissions", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/permissions must print status and return Handled"
        );
    }

    #[test]
    fn permission_status_summarizes_config_mcp_and_persisted_rules() {
        let mut mcp = HashMap::new();
        mcp.insert(
            "github".to_string(),
            vec!["search".to_string(), "fetch".to_string()],
        );
        mcp.insert("blocked".to_string(), Vec::new());
        let config = PermissionsConfig {
            enabled: true,
            default_allow: vec!["git status".to_string()],
            mcp,
            project_proposal: None,
        };
        let persisted = openclaudia::permissions::PermissionStoreSummary {
            approval_count: 1,
            denial_count: 1,
            capability_generation: 4,
        };

        let lines = permission_status_lines(
            &config,
            Some(persisted),
            None,
            std::path::Path::new("/trusted/permissions-v1.json"),
        );
        let joined = lines.join("\n");

        assert!(joined.contains("Host safety: always enabled"));
        assert!(joined.contains("Approval prompts enabled: yes"));
        assert!(joined.contains("Default allow: git status"));
        assert!(joined.contains("MCP allowlists: 2 server(s)"));
        assert!(joined.contains("blocked: deny all tools"));
        assert!(joined.contains("github: search, fetch"));
        assert!(joined.contains("Persisted exact approvals: 1 (generation 4"));
        assert!(joined.contains("Persisted explicit denials: 1"));
        assert!(joined.contains("host hard deny > explicit deny > exact approval receipt"));
    }

    #[test]
    fn permission_status_exposes_inert_repository_grants_without_applying_them() {
        let config = PermissionsConfig {
            project_proposal: Some(openclaudia::config::ProjectPermissionProposal {
                schema_version: openclaudia::config::PROJECT_PERMISSION_PROPOSAL_SCHEMA_VERSION,
                source: std::path::PathBuf::from("/project/.openclaudia/config.yaml"),
                source_digest: "sha256:source".to_string(),
                proposal_digest: "sha256:proposal".to_string(),
                requests_prompt_bypass: true,
                default_allow: vec!["Bash(git push)".to_string()],
                web_fetch_preapproved_domains: vec!["attacker.example".to_string()],
            }),
            ..Default::default()
        };

        let joined = permission_status_lines(
            &config,
            None,
            None,
            std::path::Path::new("/trusted/permissions-v1.json"),
        )
        .join("\n");

        assert!(joined.contains("Repository permission proposal: inert (schema 1"));
        assert!(joined.contains("Requested prompt bypass: ignored"));
        assert!(joined.contains("Requested default allows: 1 (ignored"));
        assert!(joined.contains("Requested web preapprovals: 1 (ignored"));
        assert!(joined.contains("Approval prompts enabled: yes"));
    }

    #[test]
    fn hook_status_summarizes_policy_and_all_slots() {
        let mut allowed = HashSet::new();
        allowed.insert("python".to_string());
        let mut hooks = HooksConfig {
            policy: Some(HookPolicy {
                allowed_commands: Some(allowed),
                sandbox: openclaudia::config::SandboxMode::EnvScrub,
            }),
            ..HooksConfig::default()
        };
        hooks.permission_request.push(HookEntry {
            matcher: Some("Bash".to_string()),
            hooks: vec![Hook::Command {
                command: "python guard.py".to_string(),
                shell: false,
                timeout: 60,
            }],
        });
        hooks.notification.push(HookEntry {
            matcher: None,
            hooks: vec![Hook::Prompt {
                prompt: "Summarize notification".to_string(),
                timeout: 30,
            }],
        });

        let lines = hook_status_lines(&hooks);
        let joined = lines.join("\n");

        assert!(joined.contains("2 active events"));
        assert!(joined.contains("Policy: allowed commands python; sandbox env_scrub"));
        assert!(joined.contains("permission_request: 1 entry, 1 hook action"));
        assert!(joined.contains("Bash -> command"));
        assert!(joined.contains("notification: 1 entry, 1 hook action"));
        assert!(joined.contains("* -> prompt"));
    }

    // ── Input-parsing invariants ──────────────────────────────────────────────

    /// Non-slash input must return None (not a slash command).
    #[test]
    fn non_slash_input_returns_none() {
        let result = handle_slash_command("just text", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(result.is_none(), "non-slash input must return None");
    }

    /// Commands are case-normalised: `/COMPACT` behaves like `/compact`.
    #[test]
    fn command_case_normalised() {
        let result = handle_slash_command("/COMPACT", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(
                result,
                Some(SlashCommandResult::Compact { instructions: None })
            ),
            "/COMPACT must be treated the same as /compact (case-insensitive)"
        );
    }

    /// Commands are case-normalised: `/Effort High` behaves like `/effort high`.
    #[test]
    fn effort_case_normalised() {
        let result = handle_slash_command("/Effort High", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::SetEffort(ref s)) if s == "high"),
            "/Effort High must be case-insensitive"
        );
    }

    // ── §10 /add-dir (#176) ──────────────────────────────────────────────

    /// `/add-dir` with a valid directory returns `AddWorkingDir` with the
    /// canonicalised path.
    #[test]
    fn add_dir_valid_directory_returns_add_working_dir() {
        let (_root, run) = scoped_run();
        let dir = std::env::temp_dir();
        let input = format!("/add-dir {}", dir.display());
        let result =
            handle_slash_command_for_run(&input, &mut ctx(), "anthropic", "claude-sonnet", &run);
        assert!(
            matches!(result, Some(SlashCommandResult::AddWorkingDir(_))),
            "/add-dir <valid-dir> must return AddWorkingDir"
        );
        if let Some(SlashCommandResult::AddWorkingDir(p)) = result {
            assert!(
                p.is_absolute(),
                "returned path must be absolute (canonicalised)"
            );
        }
    }

    /// `/add-dir` with a path that does not exist returns `Handled`.
    #[test]
    fn add_dir_nonexistent_path_returns_handled() {
        let (_root, run) = scoped_run();
        let result = handle_slash_command_for_run(
            "/add-dir /this/path/does/not/exist/9f3a",
            &mut ctx(),
            "anthropic",
            "claude-sonnet",
            &run,
        );
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/add-dir <nonexistent> must return Handled"
        );
    }

    /// `/add-dir` with a file path (not a directory) returns `Handled`.
    #[test]
    fn add_dir_file_path_returns_handled() {
        let (_root, run) = scoped_run();
        let tmp = tempfile::NamedTempFile::new().expect("temp file");
        let input = format!("/add-dir {}", tmp.path().display());
        let result =
            handle_slash_command_for_run(&input, &mut ctx(), "anthropic", "claude-sonnet", &run);
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/add-dir <file> must return Handled (only directories are accepted)"
        );
    }

    /// `/add-dir` with no argument returns `Handled` (usage printed).
    #[test]
    fn add_dir_no_arg_returns_handled() {
        let result = handle_slash_command("/add-dir", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/add-dir with no arg must return Handled"
        );
    }

    // ── §11 /branch (#177) ──────────────────────────────────────────────

    /// `/branch` with an explicit name creates a branch file and returns
    /// `BranchSession(name)`.
    #[test]
    fn branch_explicit_name_creates_file_and_returns_branch_session() {
        let (root, run) = scoped_run();
        let name = format!("test-branch-{}", uuid::Uuid::new_v4().simple());
        let input = format!("/branch {name}");
        let result =
            handle_slash_command_for_run(&input, &mut ctx(), "anthropic", "claude-sonnet", &run);
        assert!(
            matches!(result, Some(SlashCommandResult::BranchSession(ref n)) if n == &name),
            "/branch <name> must return BranchSession(name)"
        );
        let branch_path = root
            .path()
            .join(format!(".openclaudia/branches/{name}.json"));
        assert!(branch_path.exists(), "branch file must be created on disk");
    }

    /// `/branch` with no argument uses an auto-generated name and returns
    /// `BranchSession`.
    #[test]
    fn branch_no_arg_uses_generated_name() {
        let (root, run) = scoped_run();
        let result =
            handle_slash_command_for_run("/branch", &mut ctx(), "anthropic", "claude-sonnet", &run);
        if let Some(SlashCommandResult::BranchSession(ref name)) = result {
            assert!(
                !name.is_empty(),
                "auto-generated branch name must be non-empty"
            );
            let branch_path = root
                .path()
                .join(format!(".openclaudia/branches/{name}.json"));
            assert!(branch_path.is_file());
        } else {
            panic!("/branch with no arg must return BranchSession");
        }
    }

    /// `/branch <name>` called twice with the same name fails on the second call.
    #[test]
    fn branch_name_collision_returns_handled() {
        let (_root, run) = scoped_run();
        let name = format!("test-collision-{}", uuid::Uuid::new_v4().simple());
        let input = format!("/branch {name}");
        let first =
            handle_slash_command_for_run(&input, &mut ctx(), "anthropic", "claude-sonnet", &run);
        assert!(
            matches!(first, Some(SlashCommandResult::BranchSession(_))),
            "first /branch must succeed"
        );
        let second =
            handle_slash_command_for_run(&input, &mut ctx(), "anthropic", "claude-sonnet", &run);
        assert!(
            matches!(second, Some(SlashCommandResult::Handled)),
            "/branch with duplicate name must return Handled"
        );
    }

    #[test]
    fn branch_rejects_path_traversal_name_without_writing_outside_branches() {
        let (root, run) = scoped_run();
        let escape_name = format!("branch-escape-{}", uuid::Uuid::new_v4().simple());
        let input = format!("/branch ../{escape_name}");

        let result =
            handle_slash_command_for_run(&input, &mut ctx(), "anthropic", "claude-sonnet", &run);

        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "path-like branch names must be rejected"
        );
        let escaped_path = root.path().join(format!(".openclaudia/{escape_name}.json"));
        assert!(
            !escaped_path.exists(),
            "invalid branch name must not write outside .openclaudia/branches"
        );
    }

    #[test]
    fn branch_rejects_names_with_shell_or_path_punctuation() {
        let (_root, run) = scoped_run();
        for bad in ["bad/name", "bad\\name", "bad name", "bad$name", ".hidden"] {
            let input = format!("/branch {bad}");
            let result = handle_slash_command_for_run(
                &input,
                &mut ctx(),
                "anthropic",
                "claude-sonnet",
                &run,
            );

            assert!(
                matches!(result, Some(SlashCommandResult::Handled)),
                "branch name {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn teleport_missing_name_returns_usage_handled() {
        let (_root, run) = scoped_run();
        let result = handle_slash_command_for_run(
            "/teleport",
            &mut ctx(),
            "anthropic",
            "claude-sonnet",
            &run,
        );
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/teleport without a name must return Handled usage"
        );
    }

    #[test]
    fn teleport_rejects_path_traversal_name() {
        let (_root, run) = scoped_run();
        let result = handle_slash_command_for_run(
            "/teleport ../escape",
            &mut ctx(),
            "anthropic",
            "claude-sonnet",
            &run,
        );
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "path-like teleport names must be rejected"
        );
    }

    #[test]
    fn teleport_restores_named_branch_snapshot() {
        let (_root, run) = scoped_run();
        let name = format!("test-teleport-{}", uuid::Uuid::new_v4().simple());
        let mut branched_messages = vec![
            serde_json::json!({"role": "user", "content": "saved prompt"}),
            serde_json::json!({"role": "assistant", "content": "saved answer"}),
        ];

        let branch_input = format!("/branch {name}");
        let branch_result = handle_slash_command_for_run(
            &branch_input,
            &mut branched_messages,
            "anthropic",
            "claude",
            &run,
        );
        assert!(matches!(
            branch_result,
            Some(SlashCommandResult::BranchSession(_))
        ));

        let teleport_input = format!("/teleport {name}");
        let teleport_result =
            handle_slash_command_for_run(&teleport_input, &mut ctx(), "anthropic", "claude", &run);
        match teleport_result {
            Some(SlashCommandResult::TeleportSession { messages, .. }) => {
                assert_eq!(messages, branched_messages);
            }
            _ => panic!("/teleport must load branch snapshot"),
        }
    }

    #[test]
    fn branch_snapshots_cannot_cross_run_roots() {
        let (_first_root, first_run) = scoped_run();
        let (_second_root, second_run) = scoped_run();
        let name = format!("run-isolated-{}", uuid::Uuid::new_v4().simple());
        let command = format!("/branch {name}");
        let mut messages = vec![serde_json::json!({
            "role": "user",
            "content": "FIRST-RUN-BRANCH-SECRET"
        })];
        let created = handle_slash_command_for_run(
            &command,
            &mut messages,
            "anthropic",
            "claude",
            &first_run,
        );
        assert!(matches!(
            created,
            Some(SlashCommandResult::BranchSession(_))
        ));

        let foreign = handle_slash_command_for_run(
            &format!("/teleport {name}"),
            &mut ctx(),
            "anthropic",
            "claude",
            &second_run,
        );
        assert!(matches!(foreign, Some(SlashCommandResult::Handled)));
        assert!(!super::branch_snapshot_path(&second_run, &name).exists());
    }

    #[test]
    fn teleport_malformed_snapshot_returns_handled() {
        let (_root, run) = scoped_run();
        let name = format!("test-teleport-bad-{}", uuid::Uuid::new_v4().simple());
        let path = super::branch_snapshot_path(&run, &name);
        std::fs::create_dir_all(path.parent().expect("branch path has parent")).unwrap();
        std::fs::write(&path, r#"{"name":"bad","messages":"not-array"}"#).unwrap();

        let input = format!("/teleport {name}");
        let result =
            handle_slash_command_for_run(&input, &mut ctx(), "anthropic", "claude-sonnet", &run);

        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "malformed branch snapshots must not mutate the session"
        );
    }

    // ── §12 /btw (#179) ───────────────────────────────────────────────

    /// `/btw <question>` returns `SideQuestion` with the trimmed question text.
    #[test]
    fn btw_with_question_returns_side_question() {
        let result = handle_slash_command(
            "/btw what is the capital of France?",
            &mut ctx(),
            "anthropic",
            "claude-sonnet",
        );
        assert!(
            matches!(
                result,
                Some(SlashCommandResult::SideQuestion(ref q))
                    if q == "what is the capital of France?"
            ),
            "/btw <question> must return SideQuestion with the question text"
        );
    }

    /// `/btw` with no argument (empty question) returns `Handled`.
    #[test]
    fn btw_empty_question_returns_handled() {
        let result = handle_slash_command("/btw", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/btw with empty question must return Handled"
        );
    }

    /// `/btw` with whitespace-only argument is rejected.
    #[test]
    fn btw_whitespace_only_returns_handled() {
        let result = handle_slash_command("/btw   ", &mut ctx(), "anthropic", "claude-sonnet");
        assert!(
            matches!(result, Some(SlashCommandResult::Handled)),
            "/btw with whitespace-only arg must return Handled"
        );
    }

    /// The messages vec is not modified by `/btw`.
    #[test]
    fn btw_does_not_modify_messages() {
        let mut msgs = vec![
            serde_json::json!({"role": "user", "content": "hello"}),
            serde_json::json!({"role": "assistant", "content": "hi"}),
        ];
        let before_len = msgs.len();
        let _ = handle_slash_command(
            "/btw quick side question",
            &mut msgs,
            "anthropic",
            "claude-sonnet",
        );
        assert_eq!(
            msgs.len(),
            before_len,
            "/btw must not mutate the messages vec"
        );
    }
}
