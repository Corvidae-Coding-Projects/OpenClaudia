//! `OpenClaudia` - Open-source universal agent harness
//!
//! Provides Claude Code-like capabilities for any AI agent.

// Per project policy (CLAUDE.md "no_allow_dead_code" rule + crosslink
// #461), blanket pedantic-lint suppressions are not allowed here. Each
// individual offense surfaced by `cargo clippy -W clippy::pedantic` is
// tracked in the clippy-strict issue batch (#384 uninlined_format_args,
// #385 doc_markdown, #387 unreadable_literal, #394 needless_raw_string_hashes,
// #402 must_use_candidate, #424 too_many_lines / god-functions, etc.).
// Default `cargo build` and non-pedantic `cargo clippy` are unaffected.

mod cli;

use anyhow::Context as _;
use openclaudia::{
    config, guardrails, memory,
    permissions::{
        ApprovalProvenance, AuthorizationResult, ExecutionPermit, PermissionManager, PermissionRule,
    },
    plugins, prompt,
    proxy::normalize_base_url,
    tools::safe_truncate,
    tui, vdd,
};

use clap::{builder::PossibleValuesParser, Parser, Subcommand};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Re-import the extracted helpers still used by main.rs after the
// `cmd_chat` god-function decomposition (crosslink #262). The bulk
// of the REPL lives in `cli::chat_repl` now.
use cli::display::tips::get_random_tip;
use cli::repl::session_io::save_session_to_short_term_memory;
use cli::repl::{get_history_path, list_chat_sessions, Session};

/// Absolute, PATH-independent location of `git` for startup repository probes.
static GIT_BIN: LazyLock<Result<PathBuf, String>> =
    LazyLock::new(|| which::which("git").map_err(|e| format!("git binary not found on PATH: {e}")));

fn git_bin() -> Result<&'static Path, String> {
    match &*GIT_BIN {
        Ok(path) => Ok(path.as_path()),
        Err(msg) => Err(msg.clone()),
    }
}

fn git_command() -> Result<Command, String> {
    Ok(Command::new(git_bin()?))
}

fn open_tui_log_file(dir: &Path, pid: u32) -> Option<std::fs::File> {
    if std::fs::create_dir_all(dir).is_err() {
        return None;
    }

    let path = dir.join(format!("tui-{pid}.log"));
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok()
}

const fn should_redirect_tui_logs(cli: &Cli) -> bool {
    cli.command.is_none() && !cli.tui_mode && cli.print.is_none()
}

#[derive(Parser)]
#[command(name = "openclaudia")]
#[command(author, version, about = "Open-source universal agent harness")]
#[allow(clippy::struct_excessive_bools)] // CLI flags are naturally boolean
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Model to use for chat
    #[arg(short, long)]
    model: Option<String>,

    /// Target provider to use for chat
    #[arg(
        short = 't',
        long,
        ignore_case = true,
        value_parser = PossibleValuesParser::new(openclaudia::providers::SUPPORTED_PROVIDERS),
    )]
    target: Option<String>,

    /// Resume the most recent chat session
    #[arg(long, alias = "continue")]
    resume: bool,

    /// Resume a specific session by ID (prefix match)
    #[arg(long)]
    session_id: Option<String>,

    /// Run the legacy REPL in coordinator mode (requires --tui-mode)
    #[arg(long)]
    coordinator: bool,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Skip all interactive permission prompts (auto-allow everything).
    /// WARNING: Only use in CI/automation. Disables safety prompts for write/destructive tools.
    #[arg(long)]
    dangerously_skip_permissions: bool,

    /// Launch legacy line-oriented REPL instead of the default full-screen TUI
    #[arg(long)]
    tui_mode: bool,

    /// Behavioral mode preset (create, extend, safe, refactor, explore, debug, methodical, director)
    #[arg(
        long,
        value_name = "PRESET",
        value_parser = PossibleValuesParser::new(openclaudia::modes::SUPPORTED_PRESETS),
    )]
    mode: Option<String>,

    /// Approve one path or `tool:<name>` for adjacent/narrow behavioral scope
    #[arg(long = "scope-target", value_name = "PATH|tool:NAME")]
    scope_targets: Vec<String>,

    /// Send a single prompt and print the response to stdout
    #[arg(short = 'p', long, value_name = "PROMPT")]
    print: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize `OpenClaudia` configuration in the current directory
    Init {
        /// Force overwrite existing configuration
        #[arg(short, long)]
        force: bool,
    },

    /// Manage the Claude Code login used by Anthropic's supported transport
    Auth {
        /// Show current auth status instead of starting new auth
        #[arg(long)]
        status: bool,

        /// Clear native OAuth session cache without deleting shared Claude credentials
        #[arg(long)]
        logout: bool,
    },

    /// Start the `OpenClaudia` proxy server
    Start {
        /// Port to listen on (overrides config)
        #[arg(short, long)]
        port: Option<u16>,

        /// Host to bind to (overrides config)
        #[arg(long)]
        host: Option<String>,

        /// Target provider (anthropic, openai, google, gemini, deepseek, qwen, alibaba, zai, glm, zhipu, kimi, moonshot, minimax, ollama, local, lmstudio, localai, text-generation-webui, openrouter, opencode, opencode-go, openai-compatible)
        #[arg(
            short,
            long,
            ignore_case = true,
            value_parser = PossibleValuesParser::new(openclaudia::providers::SUPPORTED_PROVIDERS),
        )]
        target: Option<String>,
    },

    /// Show current configuration
    Config,

    /// Emit evidence-safe configuration and runtime diagnostics
    Doctor {
        /// Emit the typed receipt envelope as JSON
        #[arg(long)]
        json: bool,

        /// Grant one exact active diagnostic check (repeatable)
        #[arg(long = "allow-active", value_name = "CHECK_ID")]
        allow_active: Vec<String>,
    },

    /// Review, approve, or revoke repository hook imports
    Hooks {
        #[command(subcommand)]
        command: Option<HookCommands>,
    },

    /// Review, trust, or revoke repository skill packages
    Skills {
        #[command(subcommand)]
        command: Option<SkillCommands>,
    },

    /// Manage host-owned authenticated team-memory authority
    Team {
        #[command(subcommand)]
        command: TeamCommands,
    },

    /// Start ACP server on stdin/stdout for agent interoperability (acpx)
    Acp {
        /// Target provider (overrides config)
        #[arg(
            short,
            long,
            ignore_case = true,
            value_parser = PossibleValuesParser::new(openclaudia::providers::SUPPORTED_PROVIDERS),
        )]
        target: Option<String>,

        /// Model to use
        #[arg(short, long)]
        model: Option<String>,
    },

    /// Run in iteration/loop mode with Stop hooks
    Loop {
        /// Maximum number of iterations (0 = unlimited)
        #[arg(short = 'n', long, default_value = "0")]
        max_iterations: u32,

        /// Port to listen on (overrides config)
        #[arg(short, long)]
        port: Option<u16>,

        /// Host to bind to (overrides config)
        #[arg(long)]
        host: Option<String>,

        /// Target provider (anthropic, openai, google, gemini, deepseek, qwen, alibaba, zai, glm, zhipu, kimi, moonshot, minimax, ollama, local, lmstudio, localai, text-generation-webui, openrouter, opencode, opencode-go, openai-compatible)
        #[arg(
            short,
            long,
            ignore_case = true,
            value_parser = PossibleValuesParser::new(openclaudia::providers::SUPPORTED_PROVIDERS),
        )]
        target: Option<String>,
    },
}

#[derive(Subcommand)]
enum HookCommands {
    /// Show inert and approved repository hook proposals
    Status,
    /// Approve the exact proposal digest shown by `hooks status`
    Approve {
        /// Full `sha256:...` proposal digest
        proposal_digest: String,
    },
    /// Revoke an exact approved proposal digest
    Revoke {
        /// Full `sha256:...` proposal digest
        proposal_digest: String,
    },
}

#[derive(Subcommand)]
enum SkillCommands {
    /// Show the exact workspace's current host trust decision
    Status,
    /// Trust repository skill text with an explicit capability ceiling
    Trust {
        /// Permit one exact declared tool specification (repeatable)
        #[arg(long = "allow-tool", value_name = "TOOL_SPEC")]
        allowed_tools: Vec<String>,
        /// Permit explicitly invoked skills to request a model for one turn
        #[arg(long)]
        allow_model: bool,
        /// Permit explicitly invoked skills to request reasoning effort for one turn
        #[arg(long)]
        allow_effort: bool,
        /// Permit explicitly invoked skills to install sandboxed hooks for one turn
        #[arg(long)]
        allow_hooks: bool,
    },
    /// Revoke repository skill trust for this exact workspace
    Revoke,
}

#[derive(Subcommand)]
enum TeamCommands {
    /// Create a new team with this principal as its first owner
    Create {
        #[arg(long)]
        principal_id: String,
        #[arg(long, default_value_t = 31_536_000)]
        membership_ttl_seconds: i64,
    },
    /// Show local enrollment and authority status
    Status {
        #[arg(long)]
        team_id: Option<String>,
    },
    /// Emit a signed public enrollment invitation
    Invite {
        #[arg(long)]
        team_id: Option<String>,
        #[arg(long, default_value_t = 3_600)]
        ttl_seconds: i64,
    },
    /// Create a host-private credential and public proof-of-possession request
    BeginEnrollment {
        #[arg(long)]
        invitation: PathBuf,
        #[arg(long)]
        principal_id: String,
    },
    /// Approve an enrollment request and emit a signed public approval
    ApproveEnrollment {
        #[arg(long)]
        team_id: Option<String>,
        #[arg(long)]
        invitation: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        role: String,
        #[arg(long, default_value_t = 31_536_000)]
        membership_ttl_seconds: i64,
    },
    /// Accept a signed enrollment approval on the requesting host
    AcceptEnrollment {
        #[arg(long)]
        team_id: Option<String>,
        #[arg(long)]
        approval: PathBuf,
    },
    /// Change one member's role
    SetRole {
        #[arg(long)]
        team_id: Option<String>,
        #[arg(long)]
        principal_id: String,
        #[arg(long)]
        role: String,
    },
    /// Revoke one member immediately
    Revoke {
        #[arg(long)]
        team_id: Option<String>,
        #[arg(long)]
        principal_id: String,
    },
    /// Renew one active membership
    Renew {
        #[arg(long)]
        team_id: Option<String>,
        #[arg(long)]
        principal_id: String,
        #[arg(long, default_value_t = 31_536_000)]
        membership_ttl_seconds: i64,
    },
    /// Recover an expired local owner using this host's authority credential
    RecoverExpiredOwner {
        #[arg(long)]
        team_id: Option<String>,
        #[arg(long, default_value_t = 31_536_000)]
        membership_ttl_seconds: i64,
    },
    /// Rotate the team authority key and emit the successor public bundle
    RotateAuthority {
        #[arg(long)]
        team_id: Option<String>,
    },
    /// Begin rotation of this host principal's credential
    BeginCredentialRotation {
        #[arg(long)]
        team_id: Option<String>,
    },
    /// Approve a principal credential-rotation request
    ApproveCredentialRotation {
        #[arg(long)]
        team_id: Option<String>,
        #[arg(long)]
        request: PathBuf,
    },
    /// Apply a newer signed public authority bundle
    ApplyAuthority {
        #[arg(long)]
        team_id: Option<String>,
        #[arg(long)]
        bundle: PathBuf,
    },
    /// Print bounded redacted local authorization receipts
    Audit {
        #[arg(long)]
        team_id: Option<String>,
    },
    /// Show the encrypted local team-replica status without lesson content
    ReplicaStatus {
        #[arg(long)]
        team_id: Option<String>,
    },
    /// Emit a fresh short-lived descriptor for an existing team-memory service
    ServiceDescriptor {
        #[arg(long)]
        team_id: Option<String>,
        /// Externally reachable HTTPS origin encoded into the signed descriptor
        #[arg(long)]
        endpoint: String,
        /// Exact DER-encoded leaf certificate presented by this service
        #[arg(long)]
        tls_certificate: PathBuf,
    },
    /// Authenticate and pin a signed team-memory service descriptor
    ConfigureService {
        #[arg(long)]
        team_id: Option<String>,
        #[arg(long)]
        descriptor: PathBuf,
        /// Explicitly authorize endpoint/certificate rotation for the same
        /// pinned service identity
        #[arg(long)]
        rotate_transport: bool,
    },
    /// Run one observed push/pull cycle against the pinned service
    Sync {
        #[arg(long)]
        team_id: Option<String>,
    },
    /// Serve the bounded authenticated replication protocol over TLS
    Serve {
        #[arg(long)]
        team_id: Option<String>,
        #[arg(long)]
        listen: SocketAddr,
        /// Externally reachable HTTPS origin encoded into the signed descriptor
        #[arg(long)]
        endpoint: String,
        /// Exact DER-encoded leaf certificate presented by this service
        #[arg(long)]
        tls_certificate: PathBuf,
        /// Owner-only PKCS#8 DER private key used by this service
        #[arg(long)]
        tls_private_key: PathBuf,
    },
}

// OpenClaudia is a single-user CLI. A current-thread runtime keeps scheduling
// deterministic and avoids allocating an idle worker pool for interactive use.
#[tokio::main(flavor = "current_thread")]
#[allow(clippy::too_many_lines)]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging. The full-screen ratatui TUI owns the terminal, so
    // writing log lines to stderr would smear them across the rendered frame.
    // In that mode we redirect tracing to a per-run log file under
    // .openclaudia/logs/ even before project config has been created;
    // everywhere else we keep the stderr writer.
    let filter = if cli.verbose {
        "openclaudia=debug,tower_http=debug"
    } else {
        "openclaudia=info,tower_http=warn"
    };

    let tui_file_logging_active = should_redirect_tui_logs(&cli);
    let log_writer: tracing_subscriber::fmt::writer::BoxMakeWriter = if tui_file_logging_active {
        let file = open_tui_log_file(Path::new(".openclaudia/logs"), std::process::id());
        file.map_or_else(
            || tracing_subscriber::fmt::writer::BoxMakeWriter::new(std::io::sink),
            |f| tracing_subscriber::fmt::writer::BoxMakeWriter::new(std::sync::Mutex::new(f)),
        )
    } else {
        tracing_subscriber::fmt::writer::BoxMakeWriter::new(std::io::stderr)
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(!tui_file_logging_active)
                .with_writer(log_writer),
        )
        .init();

    // A writable frontend may start only after every required persistent
    // store reaches a known, current state. Evidence-safe doctor is the sole
    // exception: it must not acquire a migration lock, repair data, or publish
    // a marker merely to report that runtime migration evidence is unavailable.
    if command_requires_writable_startup(cli.command.as_ref()) {
        openclaudia::migrations::run_startup()
            .into_writable()
            .map_err(anyhow::Error::new)?;
    }

    let agent_capable_surface = cli.print.is_some()
        || matches!(
            cli.command.as_ref(),
            None | Some(Commands::Acp { .. } | Commands::Start { .. } | Commands::Loop { .. })
        );
    if agent_capable_surface {
        openclaudia::tools::sandbox_preflight().map_err(anyhow::Error::msg)?;
    }

    if let Some(prompt) = cli.print.clone() {
        if cli.command.is_some() {
            anyhow::bail!("--print cannot be used with subcommands");
        }
        reject_ignored_root_flags_for_print(&cli)?;
        return cli::print_mode::cmd_print(cli::print_mode::PrintOptions {
            model_override: cli.model.clone(),
            target_override: cli.target.clone(),
            prompt,
        })
        .await;
    }

    reject_ignored_root_flags_for_subcommand(&cli)?;

    match cli.command {
        None if cli.tui_mode => {
            // Legacy rustyline REPL (--tui-mode is now the escape hatch name, kept for compat)
            Box::pin(cmd_chat(cli::chat_repl::ChatReplArgs {
                model_override: cli.model,
                target_override: cli.target,
                resume: cli.resume,
                session_id: cli.session_id,
                coordinator: cli.coordinator,
                dangerously_skip_permissions: cli.dangerously_skip_permissions,
                mode_arg: cli.mode,
                scope_target_values: cli.scope_targets,
            }))
            .await
        }
        None => {
            // Default: full-screen TUI
            if cli.coordinator {
                anyhow::bail!(
                    "--coordinator is only supported by the legacy REPL; pass --tui-mode to use it"
                );
            }
            cmd_tui(TuiStartupOptions {
                model_override: cli.model,
                target_override: cli.target,
                resume: cli.resume,
                session_id: cli.session_id,
                dangerously_skip_permissions: cli.dangerously_skip_permissions,
                mode_arg: cli.mode,
                scope_target_values: cli.scope_targets,
            })
            .await
        }
        Some(Commands::Init { force }) => cli::commands::init::cmd_init(force),
        Some(Commands::Auth { status, logout }) => {
            cli::commands::auth::cmd_auth(status, logout).await
        }
        Some(Commands::Acp {
            target,
            model: acp_model,
        }) => {
            Box::pin(cli::commands::acp::cmd_acp(
                target.or(cli.target),
                acp_model.or(cli.model),
            ))
            .await
        }
        Some(Commands::Start { port, host, target }) => {
            Box::pin(cli::commands::start::cmd_start(
                port,
                host,
                target.or(cli.target),
            ))
            .await
        }
        Some(Commands::Config) => cli::commands::config_cmd::cmd_config(),
        Some(Commands::Doctor { json, allow_active }) => {
            cli::commands::doctor::cmd_doctor(json, &allow_active)
        }
        Some(Commands::Hooks { command }) => match command.unwrap_or(HookCommands::Status) {
            HookCommands::Status => {
                cli::commands::hooks::cmd_hooks_status();
                Ok(())
            }
            HookCommands::Approve { proposal_digest } => {
                cli::commands::hooks::cmd_hooks_approve(&proposal_digest)
            }
            HookCommands::Revoke { proposal_digest } => {
                cli::commands::hooks::cmd_hooks_revoke(&proposal_digest)
            }
        },
        Some(Commands::Skills { command }) => {
            chdir_to_git_root();
            match command.unwrap_or(SkillCommands::Status) {
                SkillCommands::Status => cli::commands::skills::cmd_skills_status(),
                SkillCommands::Trust {
                    allowed_tools,
                    allow_model,
                    allow_effort,
                    allow_hooks,
                } => cli::commands::skills::cmd_skills_trust(
                    allowed_tools,
                    allow_model,
                    allow_effort,
                    allow_hooks,
                ),
                SkillCommands::Revoke => cli::commands::skills::cmd_skills_revoke(),
            }
        }
        Some(Commands::Team { command }) => {
            chdir_to_git_root();
            match command {
                TeamCommands::Create {
                    principal_id,
                    membership_ttl_seconds,
                } => cli::commands::team::cmd_team_create(&principal_id, membership_ttl_seconds),
                TeamCommands::Status { team_id } => {
                    cli::commands::team::cmd_team_status(team_id.as_deref())
                }
                TeamCommands::Invite {
                    team_id,
                    ttl_seconds,
                } => cli::commands::team::cmd_team_invite(team_id.as_deref(), ttl_seconds),
                TeamCommands::BeginEnrollment {
                    invitation,
                    principal_id,
                } => cli::commands::team::cmd_team_begin_enrollment(&invitation, &principal_id),
                TeamCommands::ApproveEnrollment {
                    team_id,
                    invitation,
                    request,
                    role,
                    membership_ttl_seconds,
                } => cli::commands::team::cmd_team_approve_enrollment(
                    team_id.as_deref(),
                    &invitation,
                    &request,
                    &role,
                    membership_ttl_seconds,
                ),
                TeamCommands::AcceptEnrollment { team_id, approval } => {
                    cli::commands::team::cmd_team_accept_enrollment(team_id.as_deref(), &approval)
                }
                TeamCommands::SetRole {
                    team_id,
                    principal_id,
                    role,
                } => {
                    cli::commands::team::cmd_team_set_role(team_id.as_deref(), &principal_id, &role)
                }
                TeamCommands::Revoke {
                    team_id,
                    principal_id,
                } => cli::commands::team::cmd_team_revoke(team_id.as_deref(), &principal_id),
                TeamCommands::Renew {
                    team_id,
                    principal_id,
                    membership_ttl_seconds,
                } => cli::commands::team::cmd_team_renew(
                    team_id.as_deref(),
                    &principal_id,
                    membership_ttl_seconds,
                ),
                TeamCommands::RecoverExpiredOwner {
                    team_id,
                    membership_ttl_seconds,
                } => cli::commands::team::cmd_team_recover_expired_owner(
                    team_id.as_deref(),
                    membership_ttl_seconds,
                ),
                TeamCommands::RotateAuthority { team_id } => {
                    cli::commands::team::cmd_team_rotate_authority(team_id.as_deref())
                }
                TeamCommands::BeginCredentialRotation { team_id } => {
                    cli::commands::team::cmd_team_begin_credential_rotation(team_id.as_deref())
                }
                TeamCommands::ApproveCredentialRotation { team_id, request } => {
                    cli::commands::team::cmd_team_approve_credential_rotation(
                        team_id.as_deref(),
                        &request,
                    )
                }
                TeamCommands::ApplyAuthority { team_id, bundle } => {
                    cli::commands::team::cmd_team_apply_authority(team_id.as_deref(), &bundle)
                }
                TeamCommands::Audit { team_id } => {
                    cli::commands::team::cmd_team_audit(team_id.as_deref())
                }
                TeamCommands::ReplicaStatus { team_id } => {
                    cli::commands::team::cmd_team_replica_status(team_id.as_deref())
                }
                TeamCommands::ServiceDescriptor {
                    team_id,
                    endpoint,
                    tls_certificate,
                } => cli::commands::team::cmd_team_service_descriptor(
                    team_id.as_deref(),
                    &endpoint,
                    &tls_certificate,
                ),
                TeamCommands::ConfigureService {
                    team_id,
                    descriptor,
                    rotate_transport,
                } => cli::commands::team::cmd_team_configure_service(
                    team_id.as_deref(),
                    &descriptor,
                    rotate_transport,
                ),
                TeamCommands::Sync { team_id } => {
                    cli::commands::team::cmd_team_sync(team_id.as_deref())
                }
                TeamCommands::Serve {
                    team_id,
                    listen,
                    endpoint,
                    tls_certificate,
                    tls_private_key,
                } => {
                    cli::commands::team::cmd_team_serve(
                        team_id.as_deref(),
                        listen,
                        &endpoint,
                        &tls_certificate,
                        &tls_private_key,
                    )
                    .await
                }
            }
        }
        Some(Commands::Loop {
            max_iterations,
            port,
            host,
            target,
        }) => {
            cli::commands::loop_cmd::cmd_loop(max_iterations, port, host, target.or(cli.target))
                .await
        }
    }
}

fn reject_ignored_root_flags_for_print(cli: &Cli) -> anyhow::Result<()> {
    if cli.resume {
        anyhow::bail!("--resume/--continue cannot be used with --print");
    }
    if cli.session_id.is_some() {
        anyhow::bail!("--session-id cannot be used with --print");
    }
    if cli.coordinator {
        anyhow::bail!("--coordinator cannot be used with --print");
    }
    if cli.dangerously_skip_permissions {
        anyhow::bail!("--dangerously-skip-permissions cannot be used with --print");
    }
    if cli.tui_mode {
        anyhow::bail!("--tui-mode cannot be used with --print");
    }
    if cli.mode.is_some() {
        anyhow::bail!("--mode cannot be used with --print");
    }
    if !cli.scope_targets.is_empty() {
        anyhow::bail!("--scope-target cannot be used with --print");
    }

    Ok(())
}

fn reject_ignored_root_flags_for_subcommand(cli: &Cli) -> anyhow::Result<()> {
    let Some(command) = cli.command.as_ref() else {
        return Ok(());
    };

    let command_name = subcommand_name(command);
    let allows_root_target = matches!(
        command,
        Commands::Start { .. } | Commands::Acp { .. } | Commands::Loop { .. }
    );
    let allows_root_model = matches!(command, Commands::Acp { .. });

    if cli.model.is_some() && !allows_root_model {
        anyhow::bail!("--model cannot be used with '{command_name}'");
    }
    if cli.target.is_some() && !allows_root_target {
        anyhow::bail!("--target cannot be used with '{command_name}'");
    }
    if cli.resume {
        anyhow::bail!("--resume/--continue cannot be used with '{command_name}'");
    }
    if cli.session_id.is_some() {
        anyhow::bail!("--session-id cannot be used with '{command_name}'");
    }
    if cli.coordinator {
        anyhow::bail!("--coordinator cannot be used with '{command_name}'");
    }
    if cli.dangerously_skip_permissions {
        anyhow::bail!("--dangerously-skip-permissions cannot be used with '{command_name}'");
    }
    if cli.tui_mode {
        anyhow::bail!("--tui-mode cannot be used with '{command_name}'");
    }
    if cli.mode.is_some() {
        anyhow::bail!("--mode cannot be used with '{command_name}'");
    }
    if !cli.scope_targets.is_empty() {
        anyhow::bail!("--scope-target cannot be used with '{command_name}'");
    }

    Ok(())
}

const fn subcommand_name(command: &Commands) -> &'static str {
    match command {
        Commands::Init { .. } => "init",
        Commands::Auth { .. } => "auth",
        Commands::Start { .. } => "start",
        Commands::Config => "config",
        Commands::Doctor { .. } => "doctor",
        Commands::Hooks { .. } => "hooks",
        Commands::Skills { .. } => "skills",
        Commands::Team { .. } => "team",
        Commands::Acp { .. } => "acp",
        Commands::Loop { .. } => "loop",
    }
}

const fn command_requires_writable_startup(command: Option<&Commands>) -> bool {
    !matches!(command, Some(Commands::Doctor { .. }))
}

/// Full-screen TUI mode (default when no subcommand).
///
/// Loads config, resolves the provider/model/API key, builds the system prompt,
/// then launches the ratatui interactive TUI with the API pipeline wired up.
struct TuiStartupOptions {
    model_override: Option<String>,
    target_override: Option<String>,
    resume: bool,
    session_id: Option<String>,
    dangerously_skip_permissions: bool,
    mode_arg: Option<String>,
    scope_target_values: Vec<String>,
}

struct PreparedTuiStartup {
    config: config::AppConfig,
    startup_auth: Option<TuiStartupSelections>,
    vdd_adversary_auth: Option<openclaudia::vdd::VddProviderAuth>,
}

fn prepare_tui_startup(options: &TuiStartupOptions) -> anyhow::Result<PreparedTuiStartup> {
    let mut config = config::load_config().map_err(|e| {
        if config::config_file_exists() {
            eprintln!("Failed to parse configuration: {e}");
            anyhow::anyhow!("invalid configuration: {e}")
        } else {
            eprintln!("No configuration found. Run 'openclaudia init' first.");
            anyhow::anyhow!("no configuration found")
        }
    })?;

    let startup_auth = if should_prompt_tui_startup_auth(options) {
        select_tui_startup_auth(&config)?
    } else {
        None
    };

    if let Some(selection) = startup_auth.as_ref() {
        config.proxy.target.clone_from(&selection.chat.target);
    } else if let Some(ref target) = options.target_override {
        config.proxy.target.clone_from(target);
    } else if let Some(ref model) = options.model_override {
        let detected = openclaudia::proxy::determine_provider(model, &config);
        if detected != config.proxy.target {
            config.proxy.target = detected;
        }
    }

    let vdd_adversary_auth = startup_auth
        .as_ref()
        .and_then(|selection| match &selection.vdd {
            TuiStartupVddChoice::Disabled => {
                config.vdd.enabled = false;
                None
            }
            TuiStartupVddChoice::Adversary(vdd_selection) => {
                config.vdd.enabled = true;
                config
                    .vdd
                    .adversary
                    .provider
                    .clone_from(&vdd_selection.target);
                config
                    .vdd
                    .adversary
                    .api_key
                    .clone_from(&vdd_selection.auth.api_key);
                Some(vdd_selection.auth.to_vdd_provider_auth())
            }
        });

    config
        .vdd
        .validate(&config.proxy.target)
        .map_err(|e| anyhow::anyhow!("VDD configuration error: {e}"))?;

    Ok(PreparedTuiStartup {
        config,
        startup_auth,
        vdd_adversary_auth,
    })
}

#[allow(clippy::future_not_send)] // Full-screen terminal input is intentionally current-thread owned.
async fn cmd_tui(options: TuiStartupOptions) -> anyhow::Result<()> {
    chdir_to_git_root();

    let behavior_mode_explicit = options.mode_arg.is_some();
    let behavior_mode =
        parse_initial_behavior_mode(options.mode_arg.as_deref()).map_err(|e| anyhow::anyhow!(e))?;

    let PreparedTuiStartup {
        config,
        startup_auth,
        vdd_adversary_auth,
    } = prepare_tui_startup(&options)?;

    let Some(provider) = config.active_provider() else {
        eprintln!(
            "No provider configured for target '{}'",
            config.proxy.target
        );
        anyhow::bail!(
            "no provider configured for target '{}'",
            config.proxy.target
        );
    };

    let Some(chat_auth) =
        resolve_tui_chat_auth(&config.proxy.target, provider, startup_auth.as_ref()).await?
    else {
        // resolve_chat_auth already printed the user-facing error; surface
        // as a non-zero exit so shell wrappers detect the failure.
        anyhow::bail!(
            "could not resolve authentication for target '{}'",
            config.proxy.target
        );
    };
    let builder_vdd_auth = chat_auth.to_vdd_provider_auth();
    let ChatAuth {
        api_key,
        claude_code_token,
        claude_agent_sdk,
        codex_agent_sdk,
    } = chat_auth;

    let model = resolve_model_name(
        options.model_override,
        provider.model.clone(),
        &config.proxy.target,
    )
    .map_err(anyhow::Error::msg)?;
    let wire_api = if codex_agent_sdk.is_some() {
        openclaudia::pipeline::WireApi::OpenAiResponses
    } else {
        openclaudia::pipeline::WireApi::ChatCompletions
    };
    // Crosslink #433: a typo'd `proxy.target` now surfaces as an explicit
    // error here, instead of being silently mapped to `OpenAIAdapter` and
    // producing 4xx responses from the upstream that the user can't
    // attribute to a config typo.
    let provider_headers = provider.headers.clone();
    let (endpoint, headers) = if codex_agent_sdk.is_some() {
        let endpoint = openclaudia::pipeline::resolve_endpoint_for_wire(
            wire_api,
            &config.proxy.target,
            &model,
            &provider.base_url,
            None,
        )?;
        (endpoint, openclaudia::secrets::SensitiveHeaders::new())
    } else {
        let endpoint = openclaudia::pipeline::resolve_endpoint_for_wire(
            wire_api,
            &config.proxy.target,
            &model,
            &provider.base_url,
            claude_code_token.as_ref(),
        )?;
        let headers = openclaudia::pipeline::resolve_headers(
            &config.proxy.target,
            api_key.as_ref(),
            claude_code_token.as_ref(),
            &provider_headers,
        )?;
        (endpoint, headers)
    };

    tui_launch(TuiLaunchOptions {
        config: &config,
        model: &model,
        endpoint,
        headers,
        wire_api,
        claude_code_token,
        claude_agent_sdk,
        codex_agent_sdk,
        builder_vdd_auth,
        vdd_adversary_auth,
        behavior_mode_override: behavior_mode_explicit.then_some(&behavior_mode),
        scope_target_values: options.scope_target_values,
        resume: options.resume,
        session_id: options.session_id.as_deref(),
        dangerously_skip_permissions: options.dangerously_skip_permissions,
    })
    .await
}

/// Build TUI system resources (memory, prompt, hooks) and launch the app.
///
/// Extracted from `cmd_tui` to keep that function under the line limit.
struct TuiLaunchOptions<'a> {
    config: &'a config::AppConfig,
    model: &'a str,
    endpoint: String,
    headers: openclaudia::secrets::SensitiveHeaders,
    wire_api: openclaudia::pipeline::WireApi,
    claude_code_token: Option<openclaudia::secrets::OAuthToken>,
    claude_agent_sdk: Option<openclaudia::claude_agent_sdk::ClaudeAgentSdk>,
    codex_agent_sdk: Option<openclaudia::codex_agent_sdk::CodexAgentSdk>,
    builder_vdd_auth: openclaudia::vdd::VddProviderAuth,
    vdd_adversary_auth: Option<openclaudia::vdd::VddProviderAuth>,
    behavior_mode_override: Option<&'a openclaudia::modes::BehaviorMode>,
    scope_target_values: Vec<String>,
    resume: bool,
    session_id: Option<&'a str>,
    dangerously_skip_permissions: bool,
}

fn apply_tui_launch_behavior(
    app: &mut tui::app::App,
    resume: bool,
    session_id: Option<&str>,
    behavior_mode: Option<&openclaudia::modes::BehaviorMode>,
    scope_target_values: &[String],
) -> anyhow::Result<()> {
    app.apply_startup_resume_with_behavior(
        resume,
        session_id,
        behavior_mode.cloned(),
        scope_target_values,
    )
    .map_err(anyhow::Error::msg)
}

fn rebuild_resumed_tui_endpoint(
    config: &config::AppConfig,
    model: &str,
    wire_api: openclaudia::pipeline::WireApi,
    claude_code_token: Option<&openclaudia::secrets::OAuthToken>,
) -> anyhow::Result<String> {
    let provider = config.active_provider().ok_or_else(|| {
        anyhow::anyhow!(
            "cannot rebuild resumed TUI endpoint for missing provider '{}'",
            config.proxy.target
        )
    })?;
    Ok(openclaudia::pipeline::resolve_endpoint_for_wire(
        wire_api,
        &config.proxy.target,
        model,
        &provider.base_url,
        claude_code_token,
    )?)
}

#[allow(clippy::too_many_lines, clippy::future_not_send)] // Current-thread TUI composition is one fail-closed startup transaction.
async fn tui_launch(options: TuiLaunchOptions<'_>) -> anyhow::Result<()> {
    use openclaudia::hooks::{load_effective_hooks, HookEngine};

    let TuiLaunchOptions {
        config,
        model,
        endpoint,
        headers,
        wire_api,
        claude_code_token,
        claude_agent_sdk,
        codex_agent_sdk,
        builder_vdd_auth,
        vdd_adversary_auth,
        behavior_mode_override,
        scope_target_values,
        resume,
        session_id,
        dangerously_skip_permissions,
    } = options;

    let merged_hooks = load_effective_hooks(config.hooks.clone());
    let hook_engine = std::sync::Arc::new(HookEngine::new(merged_hooks));

    let policy_enforcer = std::sync::Arc::new(openclaudia::services::policy::PolicyEnforcer::new(
        config.policy.clone(),
    ));
    let budget_limits = config
        .session
        .run_budget
        .limits_for_session(&config.session);
    let mut app = tui::app::App::new_with_policy_budget_and_remote_actions(
        model,
        &config.proxy.target,
        policy_enforcer,
        budget_limits,
        config
            .remote_actions
            .build_registry()
            .map_err(anyhow::Error::msg)?,
        config
            .build_web_egress_grants()
            .map_err(anyhow::Error::msg)?,
    );
    app.hook_engine = Some(hook_engine);
    app.vdd_engine =
        init_vdd_engine_if_enabled_with_auth(config, vdd_adversary_auth).map(std::sync::Arc::new);
    app.vdd_builder_auth = builder_vdd_auth;
    app.app_config = Some(std::sync::Arc::new(config.clone()));
    apply_tui_launch_behavior(
        &mut app,
        resume,
        session_id,
        behavior_mode_override,
        &scope_target_values,
    )?;
    app.bind_durable_task_graph().map_err(anyhow::Error::msg)?;
    let endpoint = if app.model == model {
        endpoint
    } else {
        rebuild_resumed_tui_endpoint(config, &app.model, wire_api, claude_code_token.as_ref())?
    };
    // MCP subprocesses/reconnects retain this exact resumed-session
    // capability rather than discovering identity from a worker thread.
    let run_context = app.tool_run_context().map_err(anyhow::Error::msg)?;
    let memory_db = Some(open_workspace_memory_db(&run_context, config)?);
    app.permission_mgr = Some(std::sync::Arc::new(init_permission_manager(
        config,
        dangerously_skip_permissions,
        &run_context,
    )));
    let tui_prompt_blocks =
        prompt::build_prompt_context_for_run(&app.behavior_mode(), &run_context);
    app.set_api_config(
        endpoint,
        headers,
        wire_api,
        Some(tui_prompt_blocks),
        claude_code_token,
        claude_agent_sdk,
        codex_agent_sdk,
    );
    app.memory_db = memory_db.map(std::sync::Arc::new);
    guardrails::configure(&run_context, &config.guardrails).map_err(anyhow::Error::msg)?;
    let plugin_manager = std::sync::Arc::new(init_plugin_manager(run_context.project_root()));
    plugin_manager.configure_lsp_service_for_run(&run_context);
    if let Some(host) = app.hook_engine.as_ref() {
        app.hook_engine = Some(std::sync::Arc::new(
            plugin_manager
                .compose_hook_engine(host.as_ref())
                .map_err(anyhow::Error::new)?,
        ));
    }
    let mcp_manager = std::sync::Arc::new(tokio::sync::RwLock::new(
        openclaudia::mcp::McpManager::new_with_permissions(
            std::sync::Arc::clone(&run_context),
            config.permissions.clone(),
        ),
    ));
    let trusted_mcp_servers =
        openclaudia::proxy::connect_mcp_servers(&mcp_manager, &plugin_manager).await;
    let _ = openclaudia::mcp::install_manager(&run_context, &mcp_manager);
    app.set_mcp_runtime(plugin_manager, mcp_manager, trusted_mcp_servers);
    app.set_permission_bypass(dangerously_skip_permissions || !config.permissions.enabled);
    app.set_service_registry(openclaudia::services::ServiceRegistry::interactive(
        std::sync::Arc::new(openclaudia::services::analytics::TracingAnalytics),
    ))
    .map_err(anyhow::Error::msg)?;
    app.run()
        .await
        .map_err(|e| anyhow::anyhow!("TUI error: {e}"))
}

/// Result of an interactive permission prompt for a tool call.
enum ToolPermissionResult {
    /// User allowed execution (or tool doesn't need permission).
    Allowed {
        authorization: Option<ExecutionPermit>,
    },
    /// User denied execution.
    Denied(String),
}

/// Build a human-readable description of a tool call for the permission prompt.
fn tool_call_description(tool_name: &str, tool_args: &serde_json::Value) -> String {
    match tool_name {
        "bash" => {
            let cmd = tool_args
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("(unknown)");
            format!("Run command: {cmd}")
        }
        "write_file" => {
            let path = tool_args
                .get("file_path")
                .or_else(|| tool_args.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("(unknown)");
            format!("Write file: {path}")
        }
        "edit_file" => {
            let path = tool_args
                .get("file_path")
                .or_else(|| tool_args.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("(unknown)");
            format!("Edit file: {path}")
        }
        _ => format!("Execute: {tool_name}"),
    }
}

/// Check whether a tool call requires interactive permission and prompt the user if so.
///
/// Read-only / informational tools execute without prompting. Write/destructive tools
/// (`bash`, `write_file`, `edit_file`, etc.) prompt the user unless the tool has been
/// marked "always allow" for this session via a previous `a` response.
///
/// # Fix #284
///
/// This function replaces the old `check_tool_permission_interactive(skip_permissions: bool, …)`
/// boolean-flag anti-pattern. The two distinct behaviors are now two distinct functions.
///
/// Returns `Allowed` to proceed, or `Denied(message)` to send back to the model.
fn parse_interactive_permission_arguments(
    tool_call: &openclaudia::tools::ToolCall,
) -> Result<serde_json::Value, String> {
    let tool_name = &tool_call.function.name;
    match serde_json::from_str::<serde_json::Value>(&tool_call.function.arguments) {
        Ok(value @ serde_json::Value::Object(_)) => Ok(value),
        Ok(_) => Err(format!(
            "Permission denied: invalid non-object arguments for tool '{tool_name}'"
        )),
        Err(error) => Err(format!(
            "Permission denied: invalid arguments for tool '{tool_name}': {error}"
        )),
    }
}

fn check_tool_permission_interactive(
    tool_call: &openclaudia::tools::ToolCall,
    session_id: &str,
    permission_mgr: &PermissionManager,
    transient_allow_rules: &[PermissionRule],
) -> ToolPermissionResult {
    use std::io::Write as _;

    let tool_name = &tool_call.function.name;
    let tool_args = match parse_interactive_permission_arguments(tool_call) {
        Ok(arguments) => arguments,
        Err(reason) => return ToolPermissionResult::Denied(reason),
    };

    match permission_mgr.authorize_tool_call_with_transient_rules(
        tool_call,
        Some(session_id),
        transient_allow_rules,
    ) {
        AuthorizationResult::Allowed(permit) => {
            return ToolPermissionResult::Allowed {
                authorization: Some(permit),
            };
        }
        AuthorizationResult::Denied(reason) => {
            return ToolPermissionResult::Denied(format!("Permission denied: {reason}"));
        }
        AuthorizationResult::NeedsPrompt { .. } => {}
    }

    let description = tool_call_description(tool_name, &tool_args);

    eprint!("\x1b[33m⚠ {description}\x1b[0m [y/n/a(lways)] ");
    std::io::stderr().flush().ok();

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        // Non-interactive / broken pipe -> deny
        return ToolPermissionResult::Denied(format!(
            "Permission denied (non-interactive) for tool '{tool_name}'"
        ));
    }
    let response = input.trim().to_lowercase();

    match response.as_str() {
        "y" | "yes" | "" => permission_mgr
            .approve_tool_call_once(
                tool_call,
                Some(session_id),
                ApprovalProvenance::InteractiveUser,
            )
            .map_or_else(
                |reason| {
                    ToolPermissionResult::Denied(format!(
                        "Permission approval could not be issued: {reason}"
                    ))
                },
                |permit| ToolPermissionResult::Allowed {
                    authorization: Some(permit),
                },
            ),
        "a" | "always" => {
            match permission_mgr.approve_tool_call_for_session(
                tool_call,
                session_id,
                ApprovalProvenance::InteractiveUser,
            ) {
                Ok(permit) => {
                    eprintln!(
                        "\x1b[32m✓ Will auto-allow this exact '{tool_name}' invocation for the bounded session receipt.\x1b[0m"
                    );
                    ToolPermissionResult::Allowed {
                        authorization: Some(permit),
                    }
                }
                Err(reason) => ToolPermissionResult::Denied(format!(
                    "Permission approval could not be issued: {reason}"
                )),
            }
        }
        _ => ToolPermissionResult::Denied(format!(
            "Permission denied by user for tool '{tool_name}'"
        )),
    }
}

/// Interactive chat mode (default command)
/// Read multiline continuation lines after the initial input ends
/// with a trailing backslash. Replaces each trailing `\\` with a
/// newline and appends the next prompted line, stopping when the user
/// submits a line that does NOT end with `\\` or when readline errors
/// (EOF / interrupt).
///
/// Extracted from `cmd_chat` per crosslink #262.
fn read_multiline_continuation(input: &mut String, rl: &mut rustyline::DefaultEditor) {
    while input.ends_with('\\') {
        input.pop(); // remove the trailing backslash
        match rl.readline("... ") {
            Ok(cont_line) => {
                input.push('\n');
                input.push_str(cont_line.trim());
            }
            Err(_) => break,
        }
    }
}

/// Build a hook engine from host config plus explicitly approved imports.
///
/// Extracted from `cmd_chat` per crosslink #262.
fn build_hook_engine(config: &config::AppConfig) -> openclaudia::hooks::HookEngine {
    let merged_hooks = openclaudia::hooks::load_effective_hooks(config.hooks.clone());
    openclaudia::hooks::HookEngine::new(merged_hooks)
}

/// Clear the screen, render the TUI welcome panel, and fall back to a
/// plain-text banner when the TUI fails to render (e.g. non-TTY).
///
/// Extracted from `cmd_chat` per crosslink #262.
fn render_welcome_or_fallback(target: &str, model: &str) {
    let _ = tui::clear_screen();
    let welcome = tui::WelcomeScreen::new(env!("CARGO_PKG_VERSION"), target, model);
    if let Err(e) = welcome.render() {
        eprintln!("TUI render failed: {e}, using simple output");
        println!("OpenClaudia v{}", env!("CARGO_PKG_VERSION"));
        println!("Provider: {target} | Model: {model}");
        println!("Type /help for commands, /sessions to list saved chats");
        println!("Tip: {}\n", get_random_tip());
    }
}

/// Construct the library-layer `PermissionManager` with the config's
/// `default_allow` patterns. Extracted from `cmd_chat` per #262.
fn init_permission_manager(
    config: &config::AppConfig,
    dangerously_skip_permissions: bool,
    run: &openclaudia::tools::ToolRunContext,
) -> PermissionManager {
    // `--dangerously-skip-permissions` is the documented bypass. Lift it all
    // the way to the lower-level gate by constructing a permission manager
    // with `enabled = false`, which short-circuits `check()` to `Allowed`
    // (see `PermissionManager::unrestricted` + sprint-211 tests). Previously
    // the flag only affected the higher-level REPL gate and the inner
    // `execute_tool_with_*` path kept producing `PERMISSION_PROMPT` results
    // that the model could not satisfy in a non-interactive run.
    if dangerously_skip_permissions {
        return PermissionManager::unrestricted_for_run(run);
    }
    PermissionManager::trusted_for_run(
        run,
        config.permissions.enabled,
        config.permissions.default_allow.clone(),
        config.web_fetch.preapproved_domains.clone(),
    )
}

/// Apply `--resume` / `--session-id` to select a prior chat session.
///
/// If `resume` is true OR `session_id` is `Some`, looks up the saved
/// sessions and replaces the passed-in session in-place with the best
/// match (prefix match on `session_id`, else the most-recent one).
/// Prints a user-facing status line in either case.
///
/// Extracted from `cmd_chat` per crosslink #262.
fn maybe_resume_session(chat_session: &mut Session, resume: bool, session_id: Option<&str>) {
    if !resume && session_id.is_none() {
        return;
    }
    let sessions = list_chat_sessions();
    let target = if let Some(id) = session_id {
        sessions
            .iter()
            .find(|session| session.id().starts_with(id))
            .cloned()
    } else {
        sessions.into_iter().next()
    };
    if let Some(loaded) = target {
        eprintln!(
            "Resuming session: {} ({})",
            loaded.title,
            safe_truncate(&loaded.id(), 8)
        );
        *chat_session = loaded;
    } else {
        eprintln!("No session found to resume. Starting new session.");
    }
}

/// Open the exact workspace's host-owned technical-memory service and report
/// the non-authoritative archival/session counts retained for compatibility.
/// Startup fails closed when the store cannot be validated or opened.
fn init_memory_with_banner(
    run: &std::sync::Arc<openclaudia::tools::ToolRunContext>,
    config: &config::AppConfig,
) -> anyhow::Result<memory::MemoryDb> {
    let db = open_workspace_memory_db(run, config)?;

    let recent_count = db.get_recent_sessions(10).map_or(0, |s| s.len());
    if recent_count > 0 {
        println!("\x1b[90m📝 {recent_count} recent session(s) loaded from memory\x1b[0m");
    }

    Ok(db)
}

fn open_workspace_memory_db(
    run: &std::sync::Arc<openclaudia::tools::ToolRunContext>,
    config: &config::AppConfig,
) -> anyhow::Result<memory::MemoryDb> {
    let host_home = run
        .host_home()
        .ok_or_else(|| anyhow::anyhow!("host home is unavailable for private technical memory"))?;
    let db = memory::MemoryDb::open_for_workspace(host_home, run.project_root())
        .context("opening host-owned workspace technical memory")?;
    if let Some(team_id) = config.memory.team_id.clone() {
        let status = openclaudia::team_memory::activate_team_memory(
            &db,
            host_home,
            run.project_root(),
            team_id,
        )
        .context("activating authenticated team technical memory")?;
        tracing::info!(
            team_id = %status.team_id,
            freshness = ?status.freshness,
            queued_mutations = status.queued_mutations,
            service_configured = status.service_configured,
            "Authenticated team technical memory ready"
        );
    }
    tracing::debug!(
        path = %db.path().display(),
        workspace_id = ?db.workspace_id().map(ToString::to_string),
        "Technical memory database ready"
    );
    Ok(db)
}

/// Build the VDD engine if VDD is enabled in config, printing a status
/// banner. Returns `None` when disabled — `cmd_chat` passes that
/// through to every review call site so VDD is a no-op.
///
/// VDD applies its configured per-call deadline inside the engine while the
/// shared provider client supplies the canonical TLS, redirect, connect/read,
/// and absolute transport policy. Extracted from `cmd_chat` per #262.
fn init_vdd_engine_if_enabled(config: &config::AppConfig) -> Option<vdd::VddEngine> {
    init_vdd_engine_if_enabled_with_auth(config, None)
}

fn init_vdd_engine_if_enabled_with_auth(
    config: &config::AppConfig,
    adversary_auth: Option<vdd::VddProviderAuth>,
) -> Option<vdd::VddEngine> {
    if !config.vdd.enabled {
        return None;
    }
    let http_client = openclaudia::provider_transport::shared_client_required();
    println!(
        "\x1b[33m🔍 VDD enabled ({} mode) - adversary: {}\x1b[0m",
        config.vdd.mode, config.vdd.adversary.provider
    );
    Some(vdd::VddEngine::new_with_adversary_auth(
        &config.vdd,
        config,
        http_client,
        adversary_auth,
    ))
}

/// Chat-session cleanup: finalize auto-learner, autosave session,
/// persist readline history, restore terminal scroll region.
///
/// Each step is best-effort — failures in any one are logged at
/// `warn!` but do not propagate, because the CLI is already about to
/// exit. Extracted from `cmd_chat` per crosslink #262.
fn finalize_chat(
    chat_session: &Session,
    memory_db: Option<&memory::MemoryDb>,
    rl: &mut rustyline::DefaultEditor,
    history_path: &std::path::Path,
) {
    // Autosave to short-term memory so a future resume can pick up.
    save_session_to_short_term_memory(chat_session, memory_db);

    // Persist readline history — missing file is a warning, not an error.
    if let Err(e) = rl.save_history(history_path) {
        tracing::warn!("Failed to save history: {}", e);
    }

    // Restore the terminal scroll region before returning control.
    let _ = tui::teardown_pinned_bar();
}

/// Discover plugins and log a one-line status banner.
///
/// Wraps `PluginManager::new()` + `.discover()` + the "N plugin(s)
/// loaded" print + per-error `tracing::warn!`. Returns the manager
/// for the caller to use. Extracted from `cmd_chat` per crosslink #262.
fn init_plugin_manager(project_root: &std::path::Path) -> plugins::PluginManager {
    // crosslink #893: try_new surfaces "no home directory" as an explicit
    // error. Production code logs it loudly and falls back to the
    // project-only manager so the operator sees the misconfiguration
    // rather than discovering it via missing plugins.
    let mut plugin_manager = match plugins::PluginManager::try_new_for_project(project_root) {
        Ok(pm) => pm,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "PluginManager: falling back to project-only search (no user home)"
            );
            plugins::PluginManager::new_for_project(project_root)
        }
    };
    let plugin_errors = plugin_manager.discover();
    if plugin_manager.count() > 0 {
        println!("\x1b[90m{} plugin(s) loaded\x1b[0m", plugin_manager.count());
    }
    for err in &plugin_errors {
        tracing::warn!("Plugin error: {}", err);
    }
    plugin_manager
}

/// Initialize the rustyline editor with history file loaded.
///
/// Creates the history directory on a best-effort basis, logging a
/// warning (but never failing) if creation or load fails. Extracted
/// from `cmd_chat` per crosslink #262.
///
/// # Errors
/// Propagates errors from `DefaultEditor::new()` — these are
/// terminal-initialization failures that mean the CLI cannot run.
fn init_rustyline_with_history() -> anyhow::Result<(rustyline::DefaultEditor, std::path::PathBuf)> {
    let mut rl = rustyline::DefaultEditor::new()?;
    let history_path = get_history_path();

    if let Some(parent) = history_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(error = %e, path = ?parent, "Failed to create history directory");
        }
    }

    // Missing history file on first run is expected; ignore load errors.
    let _ = rl.load_history(&history_path);

    Ok((rl, history_path))
}

/// Auto-detect the project's git root and `chdir` into it.
///
/// Silent on failure — non-git directories or missing `git` binary are
/// both valid reasons to just use the caller's current working
/// directory. Extracted from `cmd_chat` per crosslink #262
/// (god-function decomposition).
fn chdir_to_git_root() {
    let Ok(output) = git_command().and_then(|mut cmd| {
        cmd.args(["rev-parse", "--show-toplevel"])
            .output()
            .map_err(|e| e.to_string())
    }) else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !root.is_empty() {
        let _ = std::env::set_current_dir(&root);
    }
}

/// Resolve the model name to use for a chat session.
///
/// Priority: explicit `-m` flag > provider's configured model > a
/// per-target default sourced from [`openclaudia::providers::DEFAULT_MODELS_BY_TARGET`]. Pure
/// function — no I/O, no mutation. Extracted from `cmd_chat` per crosslink
/// #262.
fn resolve_model_name(
    model_override: Option<String>,
    provider_model: Option<String>,
    target: &str,
) -> Result<String, String> {
    model_override
        .or(provider_model)
        .or_else(|| openclaudia::providers::default_model_for_target(target).map(str::to_string))
        .ok_or_else(|| {
            format!(
                "provider '{target}' has no configured model; set providers.{target}.model or pass --model"
            )
        })
}

/// Parse a behavioral-mode string (`--mode`) into a `BehaviorMode`.
/// `None` yields the default preset.
///
/// Extracted from `cmd_chat` per crosslink #262.
///
/// # Errors
/// Returns the `String` error produced by `Preset::FromStr` when the
/// user supplied an unknown preset name. The CLI layer prints it and
/// exits `Ok(())` — this helper surfaces the error rather than
/// coupling to stderr.
fn parse_initial_behavior_mode(
    mode_override: Option<&str>,
) -> Result<openclaudia::modes::BehaviorMode, String> {
    let Some(s) = mode_override else {
        return Ok(openclaudia::modes::BehaviorMode::default());
    };
    let preset: openclaudia::modes::Preset = s.parse()?;
    Ok(openclaudia::modes::BehaviorMode::from_preset(preset))
}

/// Outcome of resolving authentication for a chat session.
///
/// Exactly one transport is set: a provider API key, the supported Claude
/// Agent SDK, the experimental direct Claude token, or the Codex SDK runtime.
/// All are `None` only for local providers. See [`resolve_chat_auth`].
#[derive(Clone)]
struct ChatAuth {
    /// Provider API key (newtype — Debug/Display redact).
    api_key: Option<openclaudia::providers::ApiKey>,
    /// Claude Code OAuth Bearer token, when auth came from the
    /// `~/.claude/.credentials.json` store.
    claude_code_token: Option<openclaudia::secrets::OAuthToken>,
    /// Supported subscription transport through Anthropic's unmodified Agent
    /// SDK executable. `OpenClaudia` never receives its credential material.
    claude_agent_sdk: Option<openclaudia::claude_agent_sdk::ClaudeAgentSdk>,
    /// Supported account transport through `OpenAI`'s pinned Codex runtime.
    /// `OpenClaudia` never receives its credential material or routing claims.
    codex_agent_sdk: Option<openclaudia::codex_agent_sdk::CodexAgentSdk>,
}

impl ChatAuth {
    #[allow(clippy::option_if_let_else)] // Ordered precedence prevents combining incompatible auth modes.
    fn to_vdd_provider_auth(&self) -> openclaudia::vdd::VddProviderAuth {
        if let Some(sdk) = self.codex_agent_sdk.as_ref() {
            openclaudia::vdd::VddProviderAuth::codex_agent_sdk(sdk.clone())
        } else if let Some(sdk) = self.claude_agent_sdk.as_ref() {
            openclaudia::vdd::VddProviderAuth::claude_agent_sdk(sdk.clone())
        } else if let Some(token) = self.claude_code_token.as_ref() {
            openclaudia::vdd::VddProviderAuth::claude_code_token(token.clone())
        } else if let Some(api_key) = self.api_key.as_ref() {
            openclaudia::vdd::VddProviderAuth::api_key(api_key.clone())
        } else {
            openclaudia::vdd::VddProviderAuth::None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChatAuthSelectionMode {
    Automatic,
    Interactive,
}

struct TuiStartupAuthSelection {
    target: String,
    auth: ChatAuth,
}

struct TuiStartupVddSelection {
    target: String,
    auth: ChatAuth,
}

enum TuiStartupVddChoice {
    Disabled,
    Adversary(TuiStartupVddSelection),
}

enum TuiStartupVddPromptChoice {
    Disabled,
    Candidate(usize),
}

struct TuiStartupSelections {
    chat: TuiStartupAuthSelection,
    vdd: TuiStartupVddChoice,
}

enum TuiStartupAuthCandidate {
    AnthropicAgentSdk,
    AnthropicExperimentalDirect,
    OpenAi(OpenAiAuthCandidate),
    CurrentProviderApiKey {
        target: String,
        api_key: openclaudia::providers::ApiKey,
        source_label: String,
    },
    CurrentLocalProvider {
        target: String,
    },
    EnterProviderApiKey {
        allowed_targets: Vec<String>,
    },
}

enum OpenAiAuthCandidate {
    ApiKey {
        api_key: openclaudia::providers::ApiKey,
        label: String,
    },
    CodexAgentSdk(openclaudia::codex_agent_sdk::CodexAgentSdk),
    EnterApiKey,
}

impl OpenAiAuthCandidate {
    fn label(&self) -> String {
        match self {
            Self::ApiKey { label, .. } => label.clone(),
            Self::CodexAgentSdk(_) => "official Codex runtime login".to_string(),
            Self::EnterApiKey => "enter OpenAI API key".to_string(),
        }
    }

    fn into_chat_auth(self) -> anyhow::Result<ChatAuth> {
        match self {
            Self::ApiKey { api_key, .. } => Ok(ChatAuth {
                api_key: Some(api_key),
                claude_code_token: None,
                claude_agent_sdk: None,
                codex_agent_sdk: None,
            }),
            Self::CodexAgentSdk(sdk) => Ok(ChatAuth {
                api_key: None,
                claude_code_token: None,
                claude_agent_sdk: None,
                codex_agent_sdk: Some(sdk),
            }),
            Self::EnterApiKey => {
                let api_key = prompt_openai_api_key()?;
                Ok(ChatAuth {
                    api_key: Some(api_key),
                    claude_code_token: None,
                    claude_agent_sdk: None,
                    codex_agent_sdk: None,
                })
            }
        }
    }
}

impl TuiStartupAuthCandidate {
    fn label(&self) -> String {
        match self {
            Self::AnthropicAgentSdk => {
                "Anthropic subscription via official Claude Agent SDK".to_string()
            }
            Self::AnthropicExperimentalDirect => {
                "EXPERIMENTAL: direct Claude subscription compatibility".to_string()
            }
            Self::OpenAi(candidate) => format!("OpenAI: {}", candidate.label()),
            Self::CurrentProviderApiKey {
                target,
                source_label,
                ..
            } => {
                format!("Use API key: {target} via {source_label}")
            }
            Self::CurrentLocalProvider { target } => {
                format!("{target}: local provider (no API key)")
            }
            Self::EnterProviderApiKey { .. } => "Enter an API key...".to_string(),
        }
    }

    fn target(&self) -> Option<&str> {
        match self {
            Self::AnthropicAgentSdk | Self::AnthropicExperimentalDirect => Some("anthropic"),
            Self::OpenAi(_) => Some("openai"),
            Self::CurrentProviderApiKey { target, .. } | Self::CurrentLocalProvider { target } => {
                Some(target)
            }
            Self::EnterProviderApiKey { .. } => None,
        }
    }

    fn into_selection(self) -> anyhow::Result<TuiStartupAuthSelection> {
        let target = self.target().map(str::to_string);
        let auth = match self {
            Self::AnthropicAgentSdk => ChatAuth {
                api_key: None,
                claude_code_token: None,
                claude_agent_sdk: Some(
                    openclaudia::claude_agent_sdk::ClaudeAgentSdk::discover()
                        .map_err(anyhow::Error::new)?,
                ),
                codex_agent_sdk: None,
            },
            Self::AnthropicExperimentalDirect => {
                let creds = openclaudia::claude_credentials::load_credentials()
                    .map_err(|e| anyhow::anyhow!("Claude Code credentials unusable: {e}"))?;
                ChatAuth {
                    api_key: None,
                    claude_code_token: Some(creds.access_token),
                    claude_agent_sdk: None,
                    codex_agent_sdk: None,
                }
            }
            Self::CurrentProviderApiKey { api_key, .. } => ChatAuth {
                api_key: Some(api_key),
                claude_code_token: None,
                claude_agent_sdk: None,
                codex_agent_sdk: None,
            },
            Self::OpenAi(candidate) => candidate.into_chat_auth()?,
            Self::CurrentLocalProvider { .. } => ChatAuth {
                api_key: None,
                claude_code_token: None,
                claude_agent_sdk: None,
                codex_agent_sdk: None,
            },
            Self::EnterProviderApiKey { allowed_targets } => {
                let target =
                    prompt_provider_target_choice("Provider for API key:", &allowed_targets)?;
                let api_key = prompt_provider_api_key(&target)?;
                return Ok(TuiStartupAuthSelection {
                    target,
                    auth: ChatAuth {
                        api_key: Some(api_key),
                        claude_code_token: None,
                        claude_agent_sdk: None,
                        codex_agent_sdk: None,
                    },
                });
            }
        };

        let target = target.expect("non-manual startup candidate must have a provider target");
        Ok(TuiStartupAuthSelection { target, auth })
    }

    fn into_vdd_selection(self) -> anyhow::Result<TuiStartupVddSelection> {
        let selection = self.into_selection()?;
        Ok(TuiStartupVddSelection {
            target: selection.target,
            auth: selection.auth,
        })
    }
}

fn prompt_openai_api_key() -> anyhow::Result<openclaudia::providers::ApiKey> {
    prompt_provider_api_key("OpenAI")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiKeyDestinationChoice {
    SessionOnly,
    UserStore,
    Cancel,
}

fn parse_api_key_destination_choice(
    input: &str,
    user_store_available: bool,
) -> Option<ApiKeyDestinationChoice> {
    match input.trim().to_ascii_lowercase().as_str() {
        "" | "1" | "session" => Some(ApiKeyDestinationChoice::SessionOnly),
        "2" | "save" | "store" if user_store_available => Some(ApiKeyDestinationChoice::UserStore),
        "q" | "quit" | "cancel" => Some(ApiKeyDestinationChoice::Cancel),
        _ => None,
    }
}

fn prompt_api_key_destination(target: &str) -> anyhow::Result<(bool, bool)> {
    use std::io::Write as _;

    let store_path = if openclaudia::provider_credentials::protected_persistence_supported() {
        openclaudia::provider_credentials::user_store_path().ok()
    } else {
        None
    };
    let user_store_available = store_path.is_some();

    eprintln!("\nProvider: {target}");
    eprintln!("Choose API-key scope and destination:");
    eprintln!("  1. This session only (not saved)");
    if let Some(path) = &store_path {
        eprintln!(
            "  2. Save for this user in the protected OpenClaudia store ({})",
            path.display()
        );
    } else {
        eprintln!("  Protected user persistence is unavailable on this platform.");
    }
    eprintln!("  q. Cancel");

    for _ in 0..3 {
        eprint!("Select destination [1]: ");
        std::io::stderr().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        match parse_api_key_destination_choice(&input, user_store_available) {
            Some(ApiKeyDestinationChoice::SessionOnly) => return Ok((false, false)),
            Some(ApiKeyDestinationChoice::Cancel) => {
                anyhow::bail!("API-key entry cancelled; no credentials were changed");
            }
            Some(ApiKeyDestinationChoice::UserStore) => {
                let existing = openclaudia::provider_credentials::has_saved_user_api_key(target)?;
                if existing {
                    eprintln!("A protected key is already saved for {target}.");
                    if !prompt_stderr_confirmation("Replace the existing saved key? [y/N]: ")? {
                        anyhow::bail!(
                            "API-key replacement cancelled; the existing credential is unchanged"
                        );
                    }
                }
                return Ok((true, existing));
            }
            None => eprintln!("Invalid destination. Enter 1, 2, or q."),
        }
    }
    anyhow::bail!("No valid API-key destination selected; no credentials were changed")
}

fn prompt_stderr_confirmation(prompt: &str) -> anyhow::Result<bool> {
    use std::io::Write as _;

    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(matches!(
        input.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn prompt_provider_api_key(target: &str) -> anyhow::Result<openclaudia::providers::ApiKey> {
    let (save, overwrite) = prompt_api_key_destination(target)?;
    let api_key = openclaudia::provider_credentials::prompt_hidden_api_key(target)?;
    if save {
        let path = openclaudia::provider_credentials::user_store_path()?;
        let outcome = openclaudia::provider_credentials::save_user_api_key(
            target,
            api_key.clone(),
            overwrite,
        )?;
        let action = match outcome {
            openclaudia::provider_credentials::SaveOutcome::Saved => "saved",
            openclaudia::provider_credentials::SaveOutcome::Replaced => "replaced",
            openclaudia::provider_credentials::SaveOutcome::Unchanged => "already current",
        };
        eprintln!("Protected API key {action} at {}.", path.display());
    } else {
        eprintln!("Using the API key for this session only; nothing was saved.");
    }
    Ok(api_key)
}

fn prompt_provider_target_choice(prompt: &str, targets: &[String]) -> anyhow::Result<String> {
    use std::io::Write as _;

    if targets.is_empty() {
        anyhow::bail!("No provider targets are available for API-key entry");
    }

    eprintln!("{prompt}");
    for (index, target) in targets.iter().enumerate() {
        eprintln!("  {}. {}", index + 1, target);
    }

    for _ in 0..3 {
        eprint!("Select provider [1]: ");
        std::io::stderr().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(targets[0].clone());
        }
        if let Ok(selection) = trimmed.parse::<usize>() {
            if (1..=targets.len()).contains(&selection) {
                return Ok(targets[selection - 1].clone());
            }
        }
        eprintln!("Enter a number from 1 to {}.", targets.len());
    }

    anyhow::bail!("provider selection cancelled")
}

fn prompt_openai_auth_choice(candidates: &[OpenAiAuthCandidate]) -> anyhow::Result<usize> {
    use std::io::{IsTerminal as _, Write as _};

    if !std::io::stdin().is_terminal() {
        return Ok(0);
    }

    eprintln!("OpenAI authentication options:");
    for (index, candidate) in candidates.iter().enumerate() {
        eprintln!("  {}. {}", index + 1, candidate.label());
    }

    for _ in 0..3 {
        eprint!("Select auth [1]: ");
        std::io::stderr().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(0);
        }
        if let Ok(selection) = trimmed.parse::<usize>() {
            if (1..=candidates.len()).contains(&selection) {
                return Ok(selection - 1);
            }
        }
        eprintln!("Enter a number from 1 to {}.", candidates.len());
    }

    anyhow::bail!("OpenAI authentication selection cancelled")
}

fn select_openai_auth_candidate(
    mut candidates: Vec<OpenAiAuthCandidate>,
    selection_mode: ChatAuthSelectionMode,
) -> anyhow::Result<ChatAuth> {
    use std::io::IsTerminal as _;

    if selection_mode == ChatAuthSelectionMode::Interactive && std::io::stdin().is_terminal() {
        candidates.push(OpenAiAuthCandidate::EnterApiKey);
    }
    if candidates.is_empty() {
        anyhow::bail!("No OpenAI authentication option is available");
    }

    let selected = if selection_mode == ChatAuthSelectionMode::Interactive {
        prompt_openai_auth_choice(&candidates)?
    } else {
        0
    };
    let candidate = candidates.remove(selected);
    let label = candidate.label();
    let auth = candidate.into_chat_auth()?;
    eprintln!("✓ Selected {label}");
    Ok(auth)
}

const fn should_prompt_tui_startup_auth(options: &TuiStartupOptions) -> bool {
    options.target_override.is_none() && options.model_override.is_none()
}

fn collect_current_target_startup_auth_candidate(
    config: &config::AppConfig,
) -> Option<TuiStartupAuthCandidate> {
    let target = config.proxy.target.trim();
    if target.eq_ignore_ascii_case("anthropic") || target.eq_ignore_ascii_case("openai") {
        return None;
    }
    if openclaudia::config::is_local_provider_name(target) {
        return config.get_provider(target).map(|_| {
            TuiStartupAuthCandidate::CurrentLocalProvider {
                target: target.to_string(),
            }
        });
    }

    let provider = config.get_provider(target)?;
    provider
        .api_key
        .as_ref()
        .map(|api_key| TuiStartupAuthCandidate::CurrentProviderApiKey {
            target: target.to_string(),
            api_key: api_key.clone(),
            source_label: "configured/environment".to_string(),
        })
}

fn collect_openai_startup_auth_candidates(
    _config: &config::AppConfig,
    candidates: &mut Vec<TuiStartupAuthCandidate>,
) {
    match openclaudia::codex_agent_sdk::CodexAgentSdk::discover() {
        Ok(sdk) => candidates.push(TuiStartupAuthCandidate::OpenAi(
            OpenAiAuthCandidate::CodexAgentSdk(sdk),
        )),
        Err(openclaudia::codex_agent_sdk::CodexAgentSdkError::NotInstalled) => {}
        Err(error) => eprintln!("Ignoring unusable Codex runtime: {error}"),
    }
}

fn canonical_startup_provider(provider: &str) -> &str {
    match provider.trim().to_ascii_lowercase().as_str() {
        "gemini" | "google" => "google",
        "alibaba" | "qwen" => "qwen",
        "zhipu" | "glm" | "zai" => "zai",
        "moonshot" | "kimi" => "kimi",
        "lmstudio" | "localai" | "text-generation-webui" | "local" => "local",
        "anthropic" => "anthropic",
        "openai" => "openai",
        "deepseek" => "deepseek",
        "minimax" => "minimax",
        "ollama" => "ollama",
        _ => provider.trim(),
    }
}

fn same_startup_provider(a: &str, b: &str) -> bool {
    canonical_startup_provider(a).eq_ignore_ascii_case(canonical_startup_provider(b))
}

fn push_unique_startup_candidate(
    candidates: &mut Vec<TuiStartupAuthCandidate>,
    candidate: TuiStartupAuthCandidate,
) {
    let label = candidate.label();
    if !candidates.iter().any(|existing| existing.label() == label) {
        candidates.push(candidate);
    }
}

fn push_configured_provider_startup_candidate(
    config: &config::AppConfig,
    candidates: &mut Vec<TuiStartupAuthCandidate>,
    target: &str,
) {
    let Some(provider) = config.get_provider(target) else {
        return;
    };
    if openclaudia::config::is_local_provider_name(target) {
        push_unique_startup_candidate(
            candidates,
            TuiStartupAuthCandidate::CurrentLocalProvider {
                target: target.to_string(),
            },
        );
    } else if let Some(api_key) = &provider.api_key {
        push_unique_startup_candidate(
            candidates,
            TuiStartupAuthCandidate::CurrentProviderApiKey {
                target: target.to_string(),
                api_key: api_key.clone(),
                source_label: "configured/environment".to_string(),
            },
        );
    }
}

fn provider_uses_api_key_for_startup(target: &str) -> bool {
    !openclaudia::config::is_local_provider_name(target)
        && openclaudia::providers::get_adapter(target).is_ok()
}

fn sorted_provider_targets(config: &config::AppConfig) -> Vec<String> {
    let mut targets = config.providers.keys().cloned().collect::<Vec<_>>();
    targets.sort_by_key(|target| target.to_ascii_lowercase());
    targets
}

fn collect_configured_provider_api_key_candidates(
    config: &config::AppConfig,
    candidates: &mut Vec<TuiStartupAuthCandidate>,
    excluded_target: Option<&str>,
) {
    for target in sorted_provider_targets(config) {
        if excluded_target.is_some_and(|excluded| same_startup_provider(&target, excluded))
            || !provider_uses_api_key_for_startup(&target)
        {
            continue;
        }
        push_configured_provider_startup_candidate(config, candidates, &target);
    }
}

fn manual_api_key_targets(
    config: &config::AppConfig,
    excluded_target: Option<&str>,
) -> Vec<String> {
    let mut targets: Vec<String> = Vec::new();
    for target in sorted_provider_targets(config) {
        if excluded_target.is_some_and(|excluded| same_startup_provider(&target, excluded))
            || !provider_uses_api_key_for_startup(&target)
        {
            continue;
        }
        if !targets
            .iter()
            .any(|existing| same_startup_provider(existing.as_str(), &target))
        {
            targets.push(target);
        }
    }
    targets
}

fn push_manual_api_key_candidate(
    config: &config::AppConfig,
    candidates: &mut Vec<TuiStartupAuthCandidate>,
    excluded_target: Option<&str>,
) {
    use std::io::IsTerminal as _;

    if !std::io::stdin().is_terminal() {
        return;
    }
    let allowed_targets = manual_api_key_targets(config, excluded_target);
    if allowed_targets.is_empty() {
        return;
    }
    push_unique_startup_candidate(
        candidates,
        TuiStartupAuthCandidate::EnterProviderApiKey { allowed_targets },
    );
}

fn collect_tui_startup_vdd_auth_candidates(
    config: &config::AppConfig,
    chat_target: &str,
) -> Vec<TuiStartupAuthCandidate> {
    let mut candidates = Vec::new();

    let preferred = config.vdd.adversary.provider.trim();
    if !preferred.is_empty()
        && !same_startup_provider(preferred, chat_target)
        && !preferred.eq_ignore_ascii_case("anthropic")
        && !preferred.eq_ignore_ascii_case("openai")
    {
        push_configured_provider_startup_candidate(config, &mut candidates, preferred);
    }

    collect_configured_provider_api_key_candidates(config, &mut candidates, Some(chat_target));

    if !same_startup_provider("anthropic", chat_target)
        && openclaudia::claude_agent_sdk::ClaudeAgentSdk::discover().is_ok()
    {
        push_unique_startup_candidate(&mut candidates, TuiStartupAuthCandidate::AnthropicAgentSdk);
    }
    if !same_startup_provider("anthropic", chat_target)
        && openclaudia::claude_credentials::has_claude_code_credentials()
    {
        push_unique_startup_candidate(
            &mut candidates,
            TuiStartupAuthCandidate::AnthropicExperimentalDirect,
        );
    }

    if !same_startup_provider("openai", chat_target) {
        collect_openai_startup_auth_candidates(config, &mut candidates);
    }

    push_manual_api_key_candidate(config, &mut candidates, Some(chat_target));

    candidates
}

fn collect_tui_startup_auth_candidates(config: &config::AppConfig) -> Vec<TuiStartupAuthCandidate> {
    let mut candidates = Vec::new();

    if let Some(candidate) = collect_current_target_startup_auth_candidate(config) {
        push_unique_startup_candidate(&mut candidates, candidate);
    }

    collect_configured_provider_api_key_candidates(config, &mut candidates, None);

    if openclaudia::claude_agent_sdk::ClaudeAgentSdk::discover().is_ok() {
        push_unique_startup_candidate(&mut candidates, TuiStartupAuthCandidate::AnthropicAgentSdk);
    }
    if openclaudia::claude_credentials::has_claude_code_credentials() {
        push_unique_startup_candidate(
            &mut candidates,
            TuiStartupAuthCandidate::AnthropicExperimentalDirect,
        );
    }

    collect_openai_startup_auth_candidates(config, &mut candidates);

    push_manual_api_key_candidate(config, &mut candidates, None);

    candidates
}

fn prompt_tui_startup_auth_choice(candidates: &[TuiStartupAuthCandidate]) -> anyhow::Result<usize> {
    use std::io::{IsTerminal as _, Write as _};

    if !std::io::stdin().is_terminal() {
        return Ok(0);
    }

    eprintln!("Select startup login:");
    for (index, candidate) in candidates.iter().enumerate() {
        eprintln!("  {}. {}", index + 1, candidate.label());
    }

    for _ in 0..3 {
        eprint!("Select login [1]: ");
        std::io::stderr().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(0);
        }
        if let Ok(selection) = trimmed.parse::<usize>() {
            if (1..=candidates.len()).contains(&selection) {
                return Ok(selection - 1);
            }
        }
        eprintln!("Enter a number from 1 to {}.", candidates.len());
    }

    anyhow::bail!("startup login selection cancelled")
}

fn prompt_tui_startup_vdd_auth_choice(
    candidates: &[TuiStartupAuthCandidate],
    chat_target: &str,
    configured_enabled: bool,
) -> anyhow::Result<TuiStartupVddPromptChoice> {
    use std::io::{IsTerminal as _, Write as _};

    if !std::io::stdin().is_terminal() {
        if configured_enabled && !candidates.is_empty() {
            return Ok(TuiStartupVddPromptChoice::Candidate(0));
        }
        return Ok(TuiStartupVddPromptChoice::Disabled);
    }

    if configured_enabled {
        eprintln!("Select VDD adversary login (chat provider: {chat_target}):");
        for (index, candidate) in candidates.iter().enumerate() {
            eprintln!("  {}. {}", index + 1, candidate.label());
        }
        eprintln!("  {}. Disable VDD for this session", candidates.len() + 1);
    } else {
        eprintln!("VDD adversarial review is disabled for this project.");
        eprintln!("Select VDD adversary login, or skip for this session:");
        eprintln!("  1. Skip VDD for this session");
        for (index, candidate) in candidates.iter().enumerate() {
            eprintln!("  {}. {}", index + 2, candidate.label());
        }
    }

    let max_selection = candidates.len() + 1;
    for _ in 0..3 {
        eprint!("Select VDD login [1]: ");
        std::io::stderr().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            if configured_enabled && !candidates.is_empty() {
                return Ok(TuiStartupVddPromptChoice::Candidate(0));
            }
            return Ok(TuiStartupVddPromptChoice::Disabled);
        }
        if let Ok(selection) = trimmed.parse::<usize>() {
            if (1..=max_selection).contains(&selection) {
                if configured_enabled {
                    if selection <= candidates.len() {
                        return Ok(TuiStartupVddPromptChoice::Candidate(selection - 1));
                    }
                    return Ok(TuiStartupVddPromptChoice::Disabled);
                }
                if selection == 1 {
                    return Ok(TuiStartupVddPromptChoice::Disabled);
                }
                return Ok(TuiStartupVddPromptChoice::Candidate(selection - 2));
            }
        }
        eprintln!("Enter a number from 1 to {max_selection}.");
    }

    anyhow::bail!("VDD login selection cancelled")
}

fn select_tui_startup_auth(
    config: &config::AppConfig,
) -> anyhow::Result<Option<TuiStartupSelections>> {
    use std::io::IsTerminal as _;

    if !std::io::stdin().is_terminal() {
        return Ok(None);
    }

    let mut candidates = collect_tui_startup_auth_candidates(config);
    if candidates.is_empty() {
        return Ok(None);
    }

    let selected = prompt_tui_startup_auth_choice(&candidates)?;
    let label = candidates[selected].label();
    let chat = candidates.remove(selected).into_selection()?;
    eprintln!("✓ Starting with {label}");

    let mut vdd_candidates = collect_tui_startup_vdd_auth_candidates(config, &chat.target);
    let vdd = match prompt_tui_startup_vdd_auth_choice(
        &vdd_candidates,
        &chat.target,
        config.vdd.enabled,
    )? {
        TuiStartupVddPromptChoice::Disabled => {
            eprintln!("✓ VDD disabled for this session");
            TuiStartupVddChoice::Disabled
        }
        TuiStartupVddPromptChoice::Candidate(selected) => {
            let label = vdd_candidates[selected].label();
            let selection = vdd_candidates.remove(selected).into_vdd_selection()?;
            eprintln!("✓ VDD adversary will use {label}");
            TuiStartupVddChoice::Adversary(selection)
        }
    };

    Ok(Some(TuiStartupSelections { chat, vdd }))
}

async fn resolve_tui_chat_auth(
    target: &str,
    provider: &openclaudia::config::ProviderConfig,
    preselected_auth: Option<&TuiStartupSelections>,
) -> anyhow::Result<Option<ChatAuth>> {
    if let Some(selection) = preselected_auth {
        if let Some(sdk) = selection.chat.auth.codex_agent_sdk.as_ref() {
            sdk.require_authenticated()
                .await
                .map_err(anyhow::Error::new)?;
        }
        return Ok(Some(selection.chat.auth.clone()));
    }

    resolve_chat_auth(target, provider, ChatAuthSelectionMode::Interactive).await
}

fn select_openai_auth_if_available(
    candidates: Vec<OpenAiAuthCandidate>,
    selection_mode: ChatAuthSelectionMode,
) -> anyhow::Result<Option<ChatAuth>> {
    if selection_mode == ChatAuthSelectionMode::Interactive || !candidates.is_empty() {
        return Ok(Some(select_openai_auth_candidate(
            candidates,
            selection_mode,
        )?));
    }
    Ok(None)
}

fn resolve_openai_chat_auth(
    target: &str,
    provider: &openclaudia::config::ProviderConfig,
    selection_mode: ChatAuthSelectionMode,
) -> anyhow::Result<Option<ChatAuth>> {
    let mut candidates = Vec::new();
    if let Some(k) = &provider.api_key {
        candidates.push(OpenAiAuthCandidate::ApiKey {
            api_key: k.clone(),
            label: "configured OpenAI API key".to_string(),
        });
    }

    match openclaudia::codex_agent_sdk::CodexAgentSdk::discover() {
        Ok(sdk) => candidates.push(OpenAiAuthCandidate::CodexAgentSdk(sdk)),
        Err(openclaudia::codex_agent_sdk::CodexAgentSdkError::NotInstalled) => {}
        Err(error) => {
            if let Some(auth) = select_openai_auth_if_available(candidates, selection_mode)? {
                return Ok(Some(auth));
            }
            eprintln!("Error: Codex runtime unusable: {error}");
            eprintln!("Set OPENAI_API_KEY, or run `codex login`.");
            return Ok(None);
        }
    }

    if let Some(auth) = select_openai_auth_if_available(candidates, selection_mode)? {
        return Ok(Some(auth));
    }

    let env_var = openclaudia::providers::api_key_env_var_for_target(target);
    eprintln!("No API key configured for '{target}'. Set {env_var} or add to config.");
    Ok(None)
}

/// Resolve which authentication mechanism the chat session should use.
///
/// Priority for Anthropic:
///  1. Explicit provider API key.
///  2. Anthropic's unmodified Agent SDK executable with its owned login.
///  3. The direct subscription experiment only when both compile-time and
///     runtime acknowledgement gates are active.
///
/// Returns `Ok(None)` when authentication is impossible AND
/// `cmd_chat` should exit cleanly — each such branch prints a
/// user-facing `eprintln!` before returning. Returns `Ok(Some(_))`
/// with the chosen auth material. Returns `Err(_)` only for
/// unexpected I/O errors. Extracted from `cmd_chat` per crosslink #262.
async fn resolve_chat_auth(
    target: &str,
    provider: &openclaudia::config::ProviderConfig,
    selection_mode: ChatAuthSelectionMode,
) -> anyhow::Result<Option<ChatAuth>> {
    // Anthropic / no API-key branch: an explicit legacy acknowledgement wins
    // so the research path remains testable; otherwise use the supported SDK.
    if target.eq_ignore_ascii_case("anthropic") && provider.api_key.is_none() {
        if openclaudia::claude_credentials::experimental_direct_subscription_enabled() {
            match openclaudia::claude_credentials::load_credentials() {
                Ok(creds) => {
                    eprintln!(
                        "⚠ EXPERIMENTAL direct Claude subscription protocol active ({}, {})",
                        creds.subscription_type.as_deref().unwrap_or("unknown"),
                        creds.rate_limit_tier.as_deref().unwrap_or("default"),
                    );
                    return Ok(Some(ChatAuth {
                        api_key: None,
                        claude_code_token: Some(creds.access_token),
                        claude_agent_sdk: None,
                        codex_agent_sdk: None,
                    }));
                }
                Err(error) => {
                    eprintln!("Experimental direct Claude credentials unusable: {error}");
                    return Ok(None);
                }
            }
        }

        match openclaudia::claude_agent_sdk::ClaudeAgentSdk::discover() {
            Ok(sdk) => match sdk.require_authenticated().await {
                Ok(()) => {
                    eprintln!("✓ Authenticated via official Claude Agent SDK");
                    return Ok(Some(ChatAuth {
                        api_key: None,
                        claude_code_token: None,
                        claude_agent_sdk: Some(sdk),
                        codex_agent_sdk: None,
                    }));
                }
                Err(error) => {
                    eprintln!("Claude Agent SDK login unavailable: {error}");
                }
            },
            Err(error) => eprintln!("Claude Agent SDK unavailable: {error}"),
        }
        eprintln!("No API key configured for Anthropic.");
        eprintln!("Install Claude Code and run `claude auth login`, or set ANTHROPIC_API_KEY.");
        return Ok(None);
    }

    if target.eq_ignore_ascii_case("openai") {
        let auth = resolve_openai_chat_auth(target, provider, selection_mode)?;
        if let Some(sdk) = auth.as_ref().and_then(|auth| auth.codex_agent_sdk.as_ref()) {
            sdk.require_authenticated()
                .await
                .map_err(anyhow::Error::new)?;
            eprintln!("✓ Codex runtime confirmed an owned login");
        }
        return Ok(auth);
    }

    if let Some(k) = &provider.api_key {
        return Ok(Some(ChatAuth {
            api_key: Some(k.clone()),
            claude_code_token: None,
            claude_agent_sdk: None,
            codex_agent_sdk: None,
        }));
    }

    if openclaudia::config::is_local_provider_name(target) {
        return Ok(Some(ChatAuth {
            api_key: None,
            claude_code_token: None,
            claude_agent_sdk: None,
            codex_agent_sdk: None,
        }));
    }

    let env_var = openclaudia::providers::api_key_env_var_for_target(target);
    eprintln!("No API key configured for '{target}'. Set {env_var} or add to config.");
    Ok(None)
}

/// Build the provider-specific JSON request body for one chat turn.
///
/// Handles Anthropic multi-block system prompts, Google Gemini content
/// format, and the OpenAI-compatible format used by every other provider.
/// Also applies effort-level thinking parameters and injects the Claude
/// Code OAuth system prompt when `claude_code_token` is present.
///
/// Extracted from `cmd_chat` (crosslink #262) to reduce function length
/// and enable independent unit tests.
/// Run VDD adversarial review and print findings.
///
/// The host finalization policy is applied even when the engine is absent, so
/// blocking mode fails closed instead of silently returning the candidate.
#[allow(clippy::too_many_arguments)] // Legacy frontends supply the complete host-owned review boundary explicitly.
async fn run_vdd_review(
    engine: Option<&vdd::VddEngine>,
    config: &config::VddConfig,
    run_context: &std::sync::Arc<openclaudia::tools::ToolRunContext>,
    content: String,
    messages: &[serde_json::Value],
    target: &str,
    model: &str,
    api_key: Option<&openclaudia::providers::ApiKey>,
) -> Result<(String, Option<openclaudia::context::ContextItem>), String> {
    let user_task = messages
        .iter()
        .rev()
        .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
        .and_then(|m| m.get("content").and_then(|c| c.as_str()))
        .unwrap_or("");

    let builder = vdd::BuilderProvider::new(target, api_key).with_model(model);
    let policy = vdd::VddFinalizationPolicy::from_config(config);
    if policy.requirement() == vdd::VddFinalizationRequirement::Disabled {
        return Ok((content, None));
    }
    let scope = format!(
        "legacy:{}:{user_task}",
        run_context.runtime().descriptor().session_id
    );
    let finalization = vdd::finalize_text_candidate(
        engine,
        run_context,
        &policy,
        content,
        &scope,
        user_task,
        builder,
    )
    .await;
    let (publication, observation) = finalization.into_parts();
    match publication {
        vdd::VddPublication::Publish(candidate) => {
            let outcome = candidate.outcome();
            println!(
                "\n\x1b[32m✓ VDD finalization {outcome:?}: {}\x1b[0m",
                candidate.detail()
            );
            Ok((candidate.into_candidate(), observation))
        }
        vdd::VddPublication::Withhold(withheld) => {
            let reason = format!(
                "VDD finalization withheld assistant success ({:?}): {}",
                withheld.outcome(),
                withheld.detail()
            );
            tracing::warn!(reason = %reason, "VDD finalization blocked legacy response");
            println!("\n\x1b[31m⚠ {reason}\x1b[0m");
            Err(reason)
        }
    }
}

/// Build a per-turn chat request body for the configured target provider.
///
/// Test-only full-catalog compatibility baseline. Production frontends use the
/// run-aware progressive builders directly.
#[cfg(test)]
fn build_chat_request_body(
    target: &str,
    messages: &[serde_json::Value],
    model: &str,
    prompt_blocks: &openclaudia::prompt::SystemPromptBlocks,
    effort_level: &str,
    claude_code_token: Option<&openclaudia::secrets::OAuthToken>,
) -> Result<serde_json::Value, String> {
    openclaudia::pipeline::build_request(
        target,
        model,
        messages,
        effort_level,
        claude_code_token,
        Some(prompt_blocks),
    )
}

/// Build the per-turn API endpoint URL and auth headers.
///
/// Handles Claude Code OAuth (direct Anthropic) vs key-based auth
/// and merges any custom headers from the provider configuration.
///
/// Extracted from `cmd_chat` (crosslink #262).
fn build_chat_endpoint_and_headers(
    target: &str,
    model: &str,
    provider: &config::ProviderConfig,
    adapter: &dyn openclaudia::providers::ProviderAdapter,
    api_key: Option<&openclaudia::providers::ApiKey>,
    claude_code_token: Option<&openclaudia::secrets::OAuthToken>,
) -> Result<(String, openclaudia::secrets::SensitiveHeaders), String> {
    let _ = target; // used only for documentation clarity; routing is on claude_code_token
    let endpoint = if claude_code_token.is_some() {
        openclaudia::claude_credentials::get_oauth_endpoint(model)
            .map_err(|error| error.to_string())?
    } else {
        format!(
            "{}{}",
            normalize_base_url(&provider.base_url),
            adapter.chat_endpoint(model)
        )
    };

    let mut headers = if let Some(token) = claude_code_token {
        openclaudia::claude_credentials::get_oauth_headers(token)
            .map_err(|error| error.to_string())?
    } else {
        api_key.map_or_else(openclaudia::secrets::SensitiveHeaders::new, |key| {
            adapter.get_headers(key)
        })
    };
    // Merge in any custom headers from provider config
    headers.extend(&provider.headers);
    Ok((endpoint, headers))
}

async fn cmd_chat(args: cli::chat_repl::ChatReplArgs) -> anyhow::Result<()> {
    // The original \~2.4k-line `cmd_chat` body was decomposed into
    // `cli::chat_repl::ChatRepl` (crosslink #262) so each method fits
    // under the clippy::too_many_lines threshold. Behaviour is
    // preserved — see `src/cli/chat_repl.rs` for the loop body, slash
    // dispatcher, and provider-specific response handlers.
    let repl = cli::chat_repl::ChatRepl::new(args).await?;
    Box::pin(repl.run()).await
}

// ============================================================================
// Tests for cmd_chat helpers (crosslink #262 decomposition).
//
// These pure-function tests would have been impossible when the logic
// lived inline inside cmd_chat — the 3200-line function made unit
// testing of any slice impossible. Each extraction enables the test
// cases below.
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn permission_test_call(
        name: &str,
        arguments: &serde_json::Value,
    ) -> openclaudia::tools::ToolCall {
        openclaudia::tools::ToolCall {
            id: "permission-test-call".to_string(),
            call_type: "function".to_string(),
            function: openclaudia::tools::FunctionCall {
                name: name.to_string(),
                arguments: arguments.to_string(),
            },
        }
    }

    fn permission_manager_with_deny(
        canonical_tool: &str,
        pattern: &str,
    ) -> (PermissionManager, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut mgr = PermissionManager::new(dir.path().join("permissions.json"), true, Vec::new());
        mgr.add_session_rule(PermissionRule {
            tool: canonical_tool.to_string(),
            pattern: pattern.to_string(),
            decision: openclaudia::permissions::PermissionDecision::Deny,
        });
        (mgr, dir)
    }

    #[test]
    fn interactive_permission_path_does_not_bypass_read_denials() {
        let (mgr, _dir) = permission_manager_with_deny("Read", "/etc/**");
        let call = permission_test_call("read_file", &serde_json::json!({"path": "/etc/shadow"}));
        let result = check_tool_permission_interactive(&call, "session", &mgr, &[]);
        assert!(
            matches!(result, ToolPermissionResult::Denied(_)),
            "the CLI frontend must not skip an explicit deny merely because the call is read-only"
        );
    }

    #[test]
    fn interactive_permission_path_does_not_bypass_effectful_tool_denials() {
        // `lsp` was in this frontend's former hard-coded safe list even though
        // it starts and mutates a long-lived language-server process.
        let (mgr, _dir) = permission_manager_with_deny("Lsp", "**");
        let call = permission_test_call(
            "lsp",
            &serde_json::json!({"action": "hover", "file_path": "src/main.rs"}),
        );
        let result = check_tool_permission_interactive(&call, "session", &mgr, &[]);
        assert!(
            matches!(result, ToolPermissionResult::Denied(_)),
            "the CLI frontend must consult catalog policy for effectful tools"
        );
    }

    #[test]
    fn interactive_permission_path_denies_unknown_tool_without_prompting() {
        let call = permission_test_call("unknown_from_model", &serde_json::json!({}));
        let manager = PermissionManager::unrestricted();
        let result = check_tool_permission_interactive(&call, "session", &manager, &[]);
        assert!(matches!(result, ToolPermissionResult::Denied(_)));
    }

    #[test]
    fn interactive_prompt_bypass_is_derived_from_the_manager_and_keeps_host_safety() {
        let manager = PermissionManager::unrestricted();
        let safe = permission_test_call("bash", &serde_json::json!({"command": "git status"}));
        assert!(matches!(
            check_tool_permission_interactive(&safe, "session", &manager, &[]),
            ToolPermissionResult::Allowed {
                authorization: Some(_)
            }
        ));

        let catastrophic =
            permission_test_call("bash", &serde_json::json!({"command": "rm -rf /"}));
        assert!(matches!(
            check_tool_permission_interactive(&catastrophic, "session", &manager, &[]),
            ToolPermissionResult::Denied(reason) if reason.contains("Host safety")
        ));
    }

    fn tui_options(
        model_override: Option<&str>,
        target_override: Option<&str>,
    ) -> TuiStartupOptions {
        TuiStartupOptions {
            model_override: model_override.map(ToString::to_string),
            target_override: target_override.map(ToString::to_string),
            resume: false,
            session_id: None,
            dangerously_skip_permissions: false,
            mode_arg: None,
            scope_target_values: Vec::new(),
        }
    }

    fn test_api_key(raw: &str) -> openclaudia::providers::ApiKey {
        openclaudia::providers::ApiKey::try_from_string(format!("{raw}-0000000000"))
            .expect("valid api key")
    }

    fn test_provider(
        base_url: &str,
        key: Option<openclaudia::providers::ApiKey>,
    ) -> config::ProviderConfig {
        config::ProviderConfig {
            api_key: key,
            base_url: base_url.to_string(),
            model: None,
            headers: openclaudia::secrets::SensitiveHeaders::new(),
            thinking: config::ThinkingConfig::default(),
        }
    }

    fn startup_vdd_config() -> config::AppConfig {
        let mut providers = std::collections::HashMap::new();
        providers.insert(
            "anthropic".to_string(),
            test_provider("https://api.anthropic.com", Some(test_api_key("anthropic"))),
        );
        providers.insert(
            "openai".to_string(),
            test_provider("https://api.openai.com", Some(test_api_key("openai"))),
        );
        providers.insert(
            "google".to_string(),
            test_provider(
                "https://generativelanguage.googleapis.com",
                Some(test_api_key("google")),
            ),
        );

        config::AppConfig {
            proxy: config::ProxyConfig {
                target: "anthropic".to_string(),
                ..Default::default()
            },
            providers,
            hooks: config::HooksConfig::default(),
            session: config::SessionConfig::default(),
            keybindings: config::KeybindingsConfig::default(),
            vdd: config::VddConfig {
                enabled: true,
                adversary: config::VddAdversaryConfig {
                    provider: "openai".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            guardrails: config::GuardrailsConfig::default(),
            permissions: config::PermissionsConfig::default(),
            memory: config::MemoryConfig::default(),
            web_fetch: config::WebFetchConfig::default(),
            remote_actions: config::RemoteActionsConfig::default(),
            policy: openclaudia::services::policy::EnterprisePolicy::default(),
            managed_settings_path: None,
        }
    }

    #[test]
    fn startup_git_probe_uses_resolved_binary_path() {
        let git = git_bin().expect("main tests require git on PATH");
        assert!(
            git.is_absolute(),
            "git_bin must resolve git to an absolute path, got {}",
            git.display()
        );

        let src = include_str!("main.rs");
        let cfg_test = src
            .find("#[cfg(test)]")
            .expect("test module marker must be present");
        let production = &src[..cfg_test];

        for (idx, raw_line) in production.lines().enumerate() {
            let code = raw_line.split("//").next().unwrap_or("");
            assert!(
                !code.contains("Command::new(\"git\")")
                    && !code.contains("std::process::Command::new(\"git\")"),
                "production main code must not invoke bare git; line {n}: {raw_line}",
                n = idx + 1,
            );
        }
    }

    #[test]
    fn host_owned_memory_open_fails_when_state_path_is_a_file() {
        let host = tempfile::tempdir().expect("host home");
        let project = tempfile::tempdir().expect("project");
        std::fs::write(host.path().join(".openclaudia"), b"not a directory")
            .expect("write .openclaudia file");

        assert!(memory::MemoryDb::open_for_workspace(host.path(), project.path()).is_err());
    }

    #[test]
    fn shared_repl_and_tui_startup_opens_the_configured_authenticated_team_replica() {
        let host = tempfile::tempdir().expect("host home");
        let project = tempfile::tempdir().expect("project");
        let principal: openclaudia::team_memory::PrincipalId = "owner".parse().expect("principal");
        let authority = openclaudia::team_memory::TeamAuthorityStore::bootstrap(
            host.path(),
            project.path(),
            principal,
            31_536_000,
        )
        .expect("team authority");
        let mut config = startup_vdd_config();
        config.memory.team_id = Some(authority.team_id().clone());
        let run = openclaudia::tools::ToolRunContext::builder(
            openclaudia::state::SessionId::new(),
            project.path(),
        )
        .working_directory(project.path())
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(std::collections::HashMap::new())
        .host_home(Some(host.path().to_path_buf()))
        .workspace_access(openclaudia::tools::WorkspaceAccess::ReadWrite)
        .process(true)
        .network(true)
        .secrets(true)
        .provider("test")
        .build()
        .expect("frontend run");
        let memory = open_workspace_memory_db(&run, &config).expect("frontend memory");
        let permissions = PermissionManager::unrestricted_for_run(&run);
        let call = permission_test_call(
            "memory_list",
            &serde_json::json!({"scope": "team", "limit": 5}),
        );
        let result = openclaudia::services::tool_executor::ToolExecutor::execute(
            openclaudia::services::tool_executor::ToolExecutorRequest {
                run_context: &run,
                tool_call: &call,
                memory_db: Some(&memory),
                app_config: Some(&config),
                task_mgr: None,
                permission_mgr: &permissions,
                authorization: None,
                session_id: Some("s104-frontend-startup"),
                policy_enforcer: None,
            },
        );
        assert!(!result.is_error(), "team list failed: {}", result.content());
        let structured = result.structured().expect("typed team result");
        assert_eq!(structured["scope"], "team");
        assert_eq!(structured["team_freshness"], "unconfigured");
    }

    #[test]
    fn open_tui_log_file_creates_log_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_dir = dir.path().join("logs");

        let file = open_tui_log_file(&log_dir, 42).expect("log file");
        drop(file);

        assert!(log_dir.join("tui-42.log").exists());
    }

    #[test]
    fn open_tui_log_file_returns_none_when_log_dir_path_is_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_dir = dir.path().join("logs");
        std::fs::write(&log_dir, b"not a directory").expect("write log-dir file");

        assert!(open_tui_log_file(&log_dir, 42).is_none());
    }

    #[test]
    fn full_screen_tui_redirects_logs_without_requiring_config() {
        let cli = Cli {
            command: None,
            model: None,
            target: None,
            resume: false,
            session_id: None,
            coordinator: false,
            verbose: false,
            dangerously_skip_permissions: false,
            tui_mode: false,
            mode: None,
            scope_targets: Vec::new(),
            print: None,
        };

        assert!(should_redirect_tui_logs(&cli));
    }

    #[test]
    fn non_tui_commands_keep_stderr_logging() {
        let cli = Cli {
            command: Some(Commands::Config),
            model: None,
            target: None,
            resume: false,
            session_id: None,
            coordinator: false,
            verbose: false,
            dangerously_skip_permissions: false,
            tui_mode: false,
            mode: None,
            scope_targets: Vec::new(),
            print: None,
        };

        assert!(!should_redirect_tui_logs(&cli));
    }

    #[test]
    fn cli_accepts_repeatable_explicit_behavior_scope_targets() {
        let cli = Cli::try_parse_from([
            "openclaudia",
            "--mode",
            "safe",
            "--scope-target",
            "src/lib.rs",
            "--scope-target",
            "tool:bash",
        ])
        .expect("scoped behavioral CLI");

        assert_eq!(cli.mode.as_deref(), Some("safe"));
        assert_eq!(cli.scope_targets, ["src/lib.rs", "tool:bash"]);
    }

    #[test]
    fn cli_parses_explicit_repository_skill_capability_ceiling() {
        let cli = Cli::try_parse_from([
            "openclaudia",
            "skills",
            "trust",
            "--allow-tool",
            "read_file",
            "--allow-tool",
            "Bash(git status *)",
            "--allow-model",
            "--allow-hooks",
        ])
        .expect("repository skill trust CLI");

        let Some(Commands::Skills {
            command:
                Some(SkillCommands::Trust {
                    allowed_tools,
                    allow_model,
                    allow_effort,
                    allow_hooks,
                }),
        }) = cli.command
        else {
            panic!("expected skills trust command");
        };
        assert_eq!(allowed_tools, ["read_file", "Bash(git status *)"]);
        assert!(allow_model);
        assert!(!allow_effort);
        assert!(allow_hooks);
    }

    #[test]
    fn skills_command_defaults_to_visible_status() {
        let cli =
            Cli::try_parse_from(["openclaudia", "skills"]).expect("repository skill status CLI");
        assert!(matches!(
            cli.command,
            Some(Commands::Skills { command: None })
        ));
    }

    #[test]
    fn only_doctor_bypasses_writable_startup_migrations() {
        assert!(!command_requires_writable_startup(Some(
            &Commands::Doctor {
                json: true,
                allow_active: Vec::new(),
            }
        )));
        assert!(command_requires_writable_startup(Some(&Commands::Config)));
        assert!(command_requires_writable_startup(None));
    }

    #[test]
    fn full_screen_tui_prompts_for_startup_auth_without_overrides() {
        assert!(should_prompt_tui_startup_auth(&tui_options(None, None)));
        assert!(!should_prompt_tui_startup_auth(&tui_options(
            None,
            Some("openai")
        )));
        assert!(!should_prompt_tui_startup_auth(&tui_options(
            Some("gpt-5.5"),
            None
        )));
    }

    #[test]
    fn api_key_destination_defaults_to_non_persistent_session_scope() {
        assert_eq!(
            parse_api_key_destination_choice("", true),
            Some(ApiKeyDestinationChoice::SessionOnly)
        );
        assert_eq!(
            parse_api_key_destination_choice("cancel", true),
            Some(ApiKeyDestinationChoice::Cancel)
        );
    }

    #[test]
    fn api_key_destination_never_selects_an_unavailable_store() {
        assert_eq!(parse_api_key_destination_choice("2", false), None);
        assert_eq!(
            parse_api_key_destination_choice("store", true),
            Some(ApiKeyDestinationChoice::UserStore)
        );
    }

    #[test]
    fn tui_startup_openai_api_key_candidate_selects_openai_auth() {
        let api_key =
            openclaudia::providers::ApiKey::try_from_string("sk-startup-openai".to_string())
                .expect("valid api key");

        let selection = TuiStartupAuthCandidate::OpenAi(OpenAiAuthCandidate::ApiKey {
            api_key: api_key.clone(),
            label: "configured OpenAI API key".to_string(),
        })
        .into_selection()
        .expect("selection");

        assert_eq!(selection.target, "openai");
        assert_eq!(selection.auth.api_key.as_ref(), Some(&api_key));
        assert!(selection.auth.claude_code_token.is_none());
    }

    #[test]
    fn chat_auth_converts_to_vdd_runtime_auth() {
        let api_key = test_api_key("openai");
        let auth = ChatAuth {
            api_key: Some(api_key.clone()),
            claude_code_token: None,
            claude_agent_sdk: None,
            codex_agent_sdk: None,
        };

        assert_eq!(
            auth.to_vdd_provider_auth(),
            openclaudia::vdd::VddProviderAuth::api_key(api_key)
        );
    }

    #[test]
    fn vdd_startup_candidates_exclude_selected_chat_provider() {
        let config = startup_vdd_config();
        let candidates = collect_tui_startup_vdd_auth_candidates(&config, "anthropic");

        assert!(
            candidates.iter().any(|candidate| candidate
                .target()
                .is_some_and(|target| target.eq_ignore_ascii_case("openai"))),
            "OpenAI should be available as VDD adversary when chat uses Anthropic"
        );
        assert!(
            candidates.iter().all(|candidate| candidate
                .target()
                .is_none_or(|target| !target.eq_ignore_ascii_case("anthropic"))),
            "VDD candidates must not include the selected chat provider"
        );
    }

    #[test]
    fn startup_candidates_include_configured_provider_api_keys() {
        let config = startup_vdd_config();
        let candidates = collect_tui_startup_auth_candidates(&config);

        assert!(
            candidates.iter().any(|candidate| candidate
                .target()
                .is_some_and(|target| target.eq_ignore_ascii_case("google"))),
            "startup auth should include detected Google API key candidates, not only Anthropic/OpenAI"
        );
    }

    #[test]
    fn manual_vdd_api_key_targets_exclude_selected_chat_provider() {
        let config = startup_vdd_config();
        let targets = manual_api_key_targets(&config, Some("anthropic"));

        assert!(
            targets
                .iter()
                .any(|target| target.eq_ignore_ascii_case("openai")),
            "OpenAI should be a manual VDD API-key target when chat uses Anthropic"
        );
        assert!(
            targets
                .iter()
                .any(|target| target.eq_ignore_ascii_case("google")),
            "Google should be a manual VDD API-key target when chat uses Anthropic"
        );
        assert!(
            targets
                .iter()
                .all(|target| !target.eq_ignore_ascii_case("anthropic")),
            "manual VDD API-key targets must exclude the selected chat provider"
        );
    }

    #[test]
    fn automatic_openai_auth_selection_keeps_first_candidate() {
        let first_key = openclaudia::providers::ApiKey::try_from_string("sk-first".to_string())
            .expect("valid api key");
        let second_key = openclaudia::providers::ApiKey::try_from_string("sk-second".to_string())
            .expect("valid api key");

        let auth = select_openai_auth_candidate(
            vec![
                OpenAiAuthCandidate::ApiKey {
                    api_key: first_key.clone(),
                    label: "configured OpenAI API key".to_string(),
                },
                OpenAiAuthCandidate::ApiKey {
                    api_key: second_key,
                    label: "secondary configured OpenAI API key".to_string(),
                },
            ],
            ChatAuthSelectionMode::Automatic,
        )
        .expect("selection");

        assert_eq!(auth.api_key.as_ref(), Some(&first_key));
        assert!(auth.claude_code_token.is_none());
    }

    #[test]
    fn resolve_model_prefers_explicit_override() {
        let got = resolve_model_name(
            Some("custom-model".to_string()),
            Some("provider-default".to_string()),
            "anthropic",
        )
        .expect("explicit model");
        assert_eq!(got, "custom-model");
    }

    #[test]
    fn resolve_model_falls_back_to_provider_config() {
        let got = resolve_model_name(None, Some("provider-default".to_string()), "openai")
            .expect("configured model");
        assert_eq!(got, "provider-default");
    }

    #[test]
    fn resolve_model_per_target_defaults() {
        assert_eq!(
            resolve_model_name(None, None, "anthropic").expect("known default"),
            "claude-opus-4-8"
        );
        assert_eq!(
            resolve_model_name(None, None, "openai").unwrap(),
            "gpt-5.6-sol"
        );
        assert_eq!(
            resolve_model_name(None, None, "google").unwrap(),
            "gemini-3.7-flash"
        );
        assert_eq!(
            resolve_model_name(None, None, "gemini").unwrap(),
            "gemini-3.7-flash"
        );
        assert_eq!(resolve_model_name(None, None, "zai").unwrap(), "glm-5.2");
        assert_eq!(resolve_model_name(None, None, "glm").unwrap(), "glm-5.2");
        assert_eq!(resolve_model_name(None, None, "zhipu").unwrap(), "glm-5.2");
        assert_eq!(
            resolve_model_name(None, None, "deepseek").unwrap(),
            "deepseek-v4-pro"
        );
        assert_eq!(
            resolve_model_name(None, None, "qwen").unwrap(),
            "qwen3.7-plus"
        );
        assert_eq!(
            resolve_model_name(None, None, "alibaba").unwrap(),
            "qwen3.7-plus"
        );
        assert_eq!(
            resolve_model_name(None, None, "kimi").unwrap(),
            "kimi-k2.7-code"
        );
        assert_eq!(
            resolve_model_name(None, None, "moonshot").unwrap(),
            "kimi-k2.7-code"
        );
        assert_eq!(
            resolve_model_name(None, None, "minimax").unwrap(),
            "MiniMax-M3"
        );
        assert!(resolve_model_name(None, None, "unknown-provider").is_err());
    }

    #[test]
    fn legacy_chat_request_builder_propagates_max_effort() {
        let prev = std::env::var("MAX_THINKING_TOKENS").ok();
        unsafe {
            std::env::remove_var("MAX_THINKING_TOKENS");
        }

        let messages = vec![serde_json::json!({"role": "user", "content": "hi"})];
        let prompt_blocks = openclaudia::prompt::SystemPromptBlocks::from_items(
            vec![openclaudia::context::ContextItem::host_instruction(
                "test.stable",
                openclaudia::context::HostInstructionSource::CorePolicy,
                "compiled:test",
                "stable",
                openclaudia::context::ContextFreshness::Static,
                1,
            )],
            openclaudia::context::ContextBudget::default(),
        );

        let anthropic = build_chat_request_body(
            "anthropic",
            &messages,
            "claude-sonnet-4-6",
            &prompt_blocks,
            "max",
            None,
        )
        .expect("anthropic request must build");
        assert_eq!(
            anthropic["thinking"]["budget_tokens"],
            openclaudia::thinking::ULTRATHINK_BUDGET_TOKENS
        );
        assert_eq!(anthropic["max_tokens"], 40_000);

        let openai = build_chat_request_body(
            "openai",
            &messages,
            "gpt-5.6-sol",
            &prompt_blocks,
            "max",
            None,
        )
        .expect("openai-like request must build");
        assert_eq!(openai["reasoning_effort"], "xhigh");

        let gpt5 =
            build_chat_request_body("openai", &messages, "gpt-5.5", &prompt_blocks, "max", None)
                .expect("gpt-5 request must build");
        assert_eq!(gpt5["reasoning_effort"], "xhigh");

        let google = build_chat_request_body(
            "google",
            &messages,
            "gemini-3.7-flash",
            &prompt_blocks,
            "max",
            None,
        )
        .expect("google request must build");
        assert_eq!(
            google["generationConfig"]["thinkingConfig"]["thinkingBudget"],
            openclaudia::thinking::ULTRATHINK_BUDGET_TOKENS
        );

        if let Some(v) = prev {
            unsafe {
                std::env::set_var("MAX_THINKING_TOKENS", v);
            }
        }
    }

    /// Crosslink #802: the per-target default model table is the single
    /// source of truth for [`resolve_model_name`]. This test pins every
    /// entry against the resolver so that:
    ///
    /// * any new entry added to [`DEFAULT_MODELS_BY_TARGET`] is exercised
    ///   end-to-end without anyone having to remember to update a parallel
    ///   match arm,
    /// * removing or renaming an entry forces the test to be updated in
    ///   lockstep (no silent drift between the table and the resolver),
    /// * the literal model strings themselves are pinned — a stray edit
    ///   from e.g. `claude-opus-4-8` to `claude-opus-4-9` will fail the
    ///   round-trip and force a deliberate version bump.
    #[test]
    fn default_models_table_is_canonical_for_resolver() {
        for (target, expected_model) in openclaudia::providers::DEFAULT_MODELS_BY_TARGET {
            let got = resolve_model_name(None, None, target).expect("known default");
            assert_eq!(
                got, *expected_model,
                "DEFAULT_MODELS_BY_TARGET entry for `{target}` must round-trip through resolve_model_name"
            );
            assert_eq!(
                openclaudia::providers::default_model_for_target(target),
                Some(*expected_model),
                "default_model_for_target must agree with DEFAULT_MODELS_BY_TARGET for `{target}`"
            );
        }
        assert_eq!(
            openclaudia::providers::default_model_for_target("definitely-not-a-known-target"),
            None
        );
    }

    /// #802 (companion): the table must not contain duplicate target keys —
    /// duplicates would silently shadow each other depending on iteration
    /// order. Also enforces that no target key is empty.
    #[test]
    fn default_models_table_keys_are_unique_and_non_empty() {
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for (target, _) in openclaudia::providers::DEFAULT_MODELS_BY_TARGET {
            assert!(!target.is_empty(), "target key must not be empty");
            assert!(
                seen.insert(target),
                "duplicate target key `{target}` in DEFAULT_MODELS_BY_TARGET"
            );
        }
    }

    #[test]
    fn parse_initial_mode_none_is_default() {
        let got = parse_initial_behavior_mode(None).expect("default always succeeds");
        let default = openclaudia::modes::BehaviorMode::default();
        // Compare via display name rather than relying on `Eq`.
        assert_eq!(got.display_name(), default.display_name());
    }

    #[test]
    fn parse_initial_mode_unknown_preset_returns_err() {
        let err = parse_initial_behavior_mode(Some("this-preset-does-not-exist"))
            .expect_err("unknown preset should fail");
        // The error string must be user-facing — cmd_chat prints it.
        assert!(!err.is_empty());
    }

    #[test]
    fn tui_session_document_loads_in_legacy_repl() {
        let seed = Session::new_with_behavior_mode(
            "claude-sonnet-4-6",
            "anthropic",
            openclaudia::modes::BehaviorMode::default(),
        );
        let seed_json = serde_json::to_string(&seed).expect("serialize seed session");
        let tui_session: Session =
            serde_json::from_str(&seed_json).expect("TUI must load shared session document");
        tui_session.push_message(serde_json::json!({
            "role": "user",
            "content": "shared conversation"
        }));

        let json = serde_json::to_string(&tui_session).expect("serialize TUI session");
        let repl_session: Session =
            serde_json::from_str(&json).expect("REPL must load TUI session document");

        assert_eq!(repl_session.id(), tui_session.id());
        assert_eq!(
            repl_session.messages_snapshot(),
            tui_session.messages_snapshot()
        );
        assert!(json.contains("\"session_state\""));
    }

    #[test]
    fn repl_session_document_round_trips_through_tui_with_non_authority_state_intact() {
        let repl_session = Session::new_with_behavior_mode(
            "gpt-5.5",
            "openai",
            openclaudia::modes::BehaviorMode::default(),
        );
        repl_session.set_agent_mode(openclaudia::state::AgentMode::Extend);
        repl_session.push_message(serde_json::json!({
            "role": "assistant",
            "content": "persist me"
        }));
        repl_session.update_state(|state, _| {
            state.conversation.approved_plan = Some("approved steps".to_string());
            state
                .identity
                .additional_directories_for_claude_md
                .push(PathBuf::from("/tmp/shared-context"));
            state.budgets.effort_level = openclaudia::state::EffortLevel::Minimal;
            state.budgets.thinking_budget_override = Some(8_192);
            state.budgets.estimated_tokens = 4_242;
            state.ui.plan_mode.has_exited = true;
            state.ui.plan_mode.needs_exit_attachment = true;
            state.ui.plan_mode.needs_auto_exit_attachment = true;
            state.ui.lsp_recommendation_shown_this_session = true;
            state.permissions.bypass_mode = true;
            state.permissions.trust_accepted = true;
            state.permissions.persistence_disabled = true;
            state.transcript.watermark = 1;
            state.transcript.transcript_cwd = PathBuf::from("/tmp/transcript-root");
            state.ide.active_file = Some("/tmp/project/src/lib.rs".to_string());
            state.ide.selection = Some(openclaudia::state::IdeSelection {
                file_path: "/tmp/project/src/lib.rs".to_string(),
                line_start: 12,
                line_count: 2,
                text: "selected source".to_string(),
            });
        });

        let repl_json = serde_json::to_string(&repl_session).expect("serialize REPL session");
        let tui_session: Session =
            serde_json::from_str(&repl_json).expect("TUI must load REPL session document");
        let tui_json = serde_json::to_string(&tui_session).expect("re-serialize TUI session");
        let restored: Session =
            serde_json::from_str(&tui_json).expect("REPL must reload TUI document");
        let state = restored.state_snapshot();

        assert_eq!(restored.id(), repl_session.id());
        assert_eq!(restored.agent_mode(), openclaudia::state::AgentMode::Extend);
        assert_eq!(
            state.conversation.approved_plan.as_deref(),
            Some("approved steps")
        );
        assert_eq!(
            state.identity.additional_directories_for_claude_md,
            vec![PathBuf::from("/tmp/shared-context")]
        );
        assert_eq!(
            state.conversation.messages,
            repl_session.messages_snapshot()
        );
        assert_eq!(
            state.budgets.effort_level,
            openclaudia::state::EffortLevel::Minimal
        );
        assert_eq!(state.budgets.thinking_budget_override, Some(8_192));
        assert_eq!(state.budgets.estimated_tokens, 4_242);
        assert!(state.ui.plan_mode.has_exited);
        assert!(state.ui.plan_mode.needs_exit_attachment);
        assert!(state.ui.plan_mode.needs_auto_exit_attachment);
        assert!(state.ui.lsp_recommendation_shown_this_session);
        assert!(
            !state.permissions.bypass_mode,
            "conversation documents must not restore permission bypass authority"
        );
        assert!(
            !state.permissions.trust_accepted,
            "conversation documents must not restore trust authority"
        );
        assert!(
            !state.permissions.persistence_disabled,
            "conversation documents must not restore invocation-local persistence policy"
        );
        assert_eq!(state.transcript.watermark, 1);
        assert_eq!(
            state.transcript.transcript_cwd,
            PathBuf::from("/tmp/transcript-root")
        );
        assert_eq!(
            state.ide.active_file.as_deref(),
            Some("/tmp/project/src/lib.rs")
        );
        assert_eq!(
            state
                .ide
                .selection
                .as_ref()
                .map(|selection| selection.text.as_str()),
            Some("selected source")
        );
    }
}
