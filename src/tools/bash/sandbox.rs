//! OS-level containment for model-supplied shell commands.
//!
//! Shell parsing is intentionally not part of the security boundary. A model
//! can reach the same syscall through parameter expansion, an interpreter, a
//! compiler, or a freshly-written executable, so command/path denylists cannot
//! contain it. On Linux we instead execute every Bash tool call in a
//! bubblewrap-created set of namespaces with an allowlisted filesystem.

#[cfg(target_os = "linux")]
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::os::{
    fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
    unix::ffi::OsStrExt as _,
};
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(target_os = "linux")]
use std::process::Stdio;
#[cfg(target_os = "linux")]
use std::sync::Arc;
use std::sync::LazyLock;

const DISABLE_ENV: &str = "OPENCLAUDIA_BASH_SANDBOX";
#[cfg(target_os = "linux")]
const SECCOMP_FILTER_FD: libc::c_int = 198;
#[cfg(target_os = "linux")]
const MAX_PROJECT_SCAN_ENTRIES: usize = 1_000_000;

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
struct BubblewrapBackend {
    path: PathBuf,
    share_network_namespace: bool,
}

#[cfg(target_os = "linux")]
static BWRAP_BACKEND: LazyLock<Result<BubblewrapBackend, String>> = LazyLock::new(find_bwrap);
static SANDBOX_DISABLED: LazyLock<Result<bool, String>> =
    LazyLock::new(sandbox_explicitly_disabled_from_env);

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum ControlPathAccess {
    Hidden,
    ReadOnly,
}

/// Named policy profiles for agent-influenced subprocess classes.
#[derive(Clone, Copy, Debug)]
pub enum SandboxProfile {
    Shell,
    RepositoryHook,
    LanguageServer,
    StaticAnalyzer,
    QualityGate,
    DocumentParser,
    McpStdio,
    McpHeaderHelper,
    GitWorktree,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkspaceMountPolicy {
    /// Only the run-owned private scratch directory is visible.
    ScratchOnly,
    /// Only the project and scratch are visible, with the project read-only.
    ProjectReadOnly,
    /// Only the project and scratch are visible, preserving project write mode.
    ProjectRunBound,
    /// Preserve the exact read/write modes in the immutable run capability.
    RunBound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnvironmentPolicy {
    Empty,
    NonSecretRunGrants,
    RunGrants,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SandboxProfilePolicy {
    workspace: WorkspaceMountPolicy,
    environment: EnvironmentPolicy,
    permits_explicit_environment: bool,
    permits_project_path: bool,
    permits_child_processes: bool,
}

impl SandboxProfile {
    /// Compile a subprocess class into concrete authority. Keeping the matrix in
    /// one place prevents a new caller from silently inheriting shell access.
    const fn policy(self) -> SandboxProfilePolicy {
        match self {
            Self::Shell => SandboxProfilePolicy {
                workspace: WorkspaceMountPolicy::RunBound,
                environment: EnvironmentPolicy::RunGrants,
                permits_explicit_environment: false,
                permits_project_path: true,
                permits_child_processes: true,
            },
            Self::RepositoryHook => SandboxProfilePolicy {
                // Hooks commonly format files and maintain generated state.
                workspace: WorkspaceMountPolicy::ProjectRunBound,
                environment: EnvironmentPolicy::NonSecretRunGrants,
                permits_explicit_environment: true,
                permits_project_path: true,
                permits_child_processes: true,
            },
            Self::LanguageServer | Self::StaticAnalyzer | Self::QualityGate => {
                // Compiler, language-server, and cache output is redirected to
                // private scratch while source stays read-only.
                SandboxProfilePolicy {
                    workspace: WorkspaceMountPolicy::ProjectReadOnly,
                    environment: EnvironmentPolicy::NonSecretRunGrants,
                    permits_explicit_environment: false,
                    permits_project_path: true,
                    permits_child_processes: true,
                }
            }
            Self::DocumentParser => SandboxProfilePolicy {
                // Parser input arrives over stdin; project files are unnecessary.
                workspace: WorkspaceMountPolicy::ScratchOnly,
                environment: EnvironmentPolicy::Empty,
                permits_explicit_environment: false,
                permits_project_path: false,
                permits_child_processes: false,
            },
            Self::McpStdio => SandboxProfilePolicy {
                // The MCP-specific derived run carries only the server's declared
                // environment and its explicitly granted workspace access.
                workspace: WorkspaceMountPolicy::ProjectRunBound,
                environment: EnvironmentPolicy::RunGrants,
                permits_explicit_environment: false,
                permits_project_path: false,
                permits_child_processes: true,
            },
            Self::McpHeaderHelper => SandboxProfilePolicy {
                workspace: WorkspaceMountPolicy::ScratchOnly,
                environment: EnvironmentPolicy::Empty,
                permits_explicit_environment: true,
                permits_project_path: false,
                permits_child_processes: true,
            },
            Self::GitWorktree => SandboxProfilePolicy {
                workspace: WorkspaceMountPolicy::ProjectRunBound,
                environment: EnvironmentPolicy::Empty,
                permits_explicit_environment: true,
                permits_project_path: false,
                permits_child_processes: true,
            },
        }
    }
}

/// Redacted status for operator diagnostics. Counts and policy states are
/// exposed; environment values and credential material never are.
#[derive(Clone, Debug)]
pub struct SandboxDiagnostics {
    pub backend: &'static str,
    pub healthy: bool,
    pub detail: String,
    pub network: &'static str,
    pub syscall_filter: &'static str,
    pub resource_limits: &'static str,
    pub explicit_host_opt_out: bool,
    pub read_only_root_count: usize,
    pub read_write_root_count: usize,
    pub environment_grant_count: usize,
}

/// Probe the active backend and summarize the effective default policy.
#[must_use]
pub fn sandbox_diagnostics() -> SandboxDiagnostics {
    let disabled = SANDBOX_DISABLED.as_ref().copied().unwrap_or(false);
    // Startup diagnostics intentionally do not discover a run context. Exact
    // capability counts are emitted when a concrete sandbox command is built.
    let (read_only_root_count, read_write_root_count, environment_grant_count) = (0, 0, 0);
    if disabled {
        return SandboxDiagnostics {
            backend: "host-opt-out",
            healthy: true,
            detail: format!("{DISABLE_ENV}=off was set by the host operator"),
            network: "host (UNRESTRICTED)",
            syscall_filter: "disabled",
            resource_limits: "disabled",
            explicit_host_opt_out: true,
            read_only_root_count,
            read_write_root_count,
            environment_grant_count,
        };
    }

    #[cfg(target_os = "linux")]
    let (backend, result, syscall_filter) = (
        "bubblewrap",
        BWRAP_BACKEND.as_ref().map(|_| ()).map_err(Clone::clone),
        "seccomp-v1",
    );
    #[cfg(target_os = "macos")]
    let (backend, result, syscall_filter) = (
        "macos-unavailable",
        Err(
            "No maintained OS-supported macOS subprocess sandbox backend is available in this build"
                .to_string(),
        ),
        "unavailable",
    );
    #[cfg(windows)]
    let (backend, result, syscall_filter) = (
        "windows-appcontainer",
        Err("AppContainer backend is unavailable in this build".to_string()),
        "unavailable",
    );
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    let (backend, result, syscall_filter) = (
        "unsupported",
        Err(format!(
            "No sandbox backend is implemented for {}",
            std::env::consts::OS
        )),
        "unavailable",
    );
    let (healthy, detail) = match result {
        Ok(()) => (true, "backend health probe passed".to_string()),
        Err(error) => (false, redact_diagnostic(&error)),
    };
    SandboxDiagnostics {
        backend,
        healthy,
        detail,
        network: "denied",
        syscall_filter,
        resource_limits: if cfg!(target_os = "linux") {
            "cpu=300s, address-space=4GiB, processes=host-baseline+256, files=1024, file-size=256MiB"
        } else {
            "unavailable (agent subprocesses fail closed)"
        },
        explicit_host_opt_out: false,
        read_only_root_count,
        read_write_root_count,
        environment_grant_count,
    }
}

/// Probe the backend and include redacted counts from one explicit run.
#[must_use]
pub fn sandbox_diagnostics_for_run(run: &crate::tools::ToolRunContext) -> SandboxDiagnostics {
    let mut diagnostics = sandbox_diagnostics();
    diagnostics.read_only_root_count = run.read_only_roots().len();
    diagnostics.read_write_root_count = run.read_write_roots().len();
    diagnostics.environment_grant_count = run.environment_grants().len();
    diagnostics
}

/// Fail closed during startup when an agent-capable surface has no usable
/// backend. This forces backend failures to appear before the first tool call.
///
/// # Errors
///
/// Returns a redacted actionable diagnostic when the configured platform
/// backend is unavailable, unhealthy, or explicitly misconfigured.
pub fn sandbox_preflight() -> Result<(), String> {
    let diagnostics = sandbox_diagnostics();
    if diagnostics.healthy {
        if diagnostics.explicit_host_opt_out {
            tracing::warn!(
                target: "openclaudia::sandbox",
                event = "sandbox_host_opt_out",
                "Host operator explicitly disabled agent process isolation"
            );
        } else {
            tracing::info!(
                target: "openclaudia::sandbox",
                event = "sandbox_preflight_passed",
                backend = diagnostics.backend,
                network = diagnostics.network,
                syscall_filter = diagnostics.syscall_filter,
                resource_limits = diagnostics.resource_limits,
                "Agent sandbox preflight passed"
            );
        }
        Ok(())
    } else {
        tracing::error!(
            target: "openclaudia::sandbox",
            event = "sandbox_preflight_failed",
            backend = diagnostics.backend,
            detail = diagnostics.detail,
            "Agent sandbox preflight failed closed"
        );
        Err(format!(
            "Agent execution is unavailable: {} backend failed its startup health check: {}",
            diagnostics.backend, diagnostics.detail
        ))
    }
}

fn redact_diagnostic(value: &str) -> String {
    let mut redacted = String::with_capacity(value.len().min(512));
    for token in value.split_whitespace() {
        if token.starts_with('/') || token.contains('=') {
            redacted.push_str("[redacted] ");
        } else {
            redacted.push_str(token);
            redacted.push(' ');
        }
        if redacted.len() >= 512 {
            break;
        }
    }
    redacted.trim().to_string()
}

#[cfg(target_os = "linux")]
impl SandboxProfile {
    const fn control_path_access(self) -> ControlPathAccess {
        if matches!(self, Self::RepositoryHook) {
            ControlPathAccess::ReadOnly
        } else {
            ControlPathAccess::Hidden
        }
    }

    const fn permits_project_path(self) -> bool {
        self.policy().permits_project_path
    }
}

/// Build the command used for a model-supplied Bash invocation.
///
/// The opt-out is deliberately process-level only. Tool arguments are hostile
/// input and can never select the unsandboxed branch.
pub(super) fn sandboxed_bash_command(
    run: &crate::tools::security::ToolRunContext,
    bash: &Path,
    command: &str,
    cwd: &Path,
) -> Result<crate::tools::command::PreparedProcessCommand, String> {
    sandboxed_process_command(
        run,
        SandboxProfile::Shell,
        bash.as_os_str(),
        &[OsString::from("-c"), OsString::from(command)],
        cwd,
    )
}

/// Build an OS-contained process command for code that may have been
/// influenced by project content (quality gates, compilers, and similar).
pub fn sandboxed_process_command(
    run: &crate::tools::security::ToolRunContext,
    profile: SandboxProfile,
    program: &OsStr,
    args: &[OsString],
    cwd: &Path,
) -> Result<crate::tools::command::PreparedProcessCommand, String> {
    sandboxed_process_command_for_profile(run, profile, program, args, cwd, &[])
}

/// Build a sandboxed process with a small caller-declared environment overlay.
/// Profiles that do not explicitly permit such an overlay fail closed.
pub fn sandboxed_process_command_with_env(
    run: &crate::tools::security::ToolRunContext,
    profile: SandboxProfile,
    program: &OsStr,
    args: &[OsString],
    cwd: &Path,
    environment: &[(OsString, OsString)],
) -> Result<crate::tools::command::PreparedProcessCommand, String> {
    sandboxed_process_command_for_profile(run, profile, program, args, cwd, environment)
}

/// Contain a user-configured hook while leaving its control-directory scripts
/// readable. Only the harness-owned project-directory value is forwarded from
/// the prepared command; ambient and credential environment remains excluded.
pub fn sandboxed_hook_command(
    run: &crate::tools::security::ToolRunContext,
    source: &Command,
    cwd: &Path,
) -> Result<crate::tools::command::PreparedProcessCommand, String> {
    let args: Vec<OsString> = source.get_args().map(OsString::from).collect();
    let environment = source
        .get_envs()
        .filter(|(key, _)| *key == OsStr::new("CLAUDE_PROJECT_DIR"))
        .filter_map(|(key, value)| value.map(|value| (key.to_os_string(), value.to_os_string())))
        .collect::<Vec<_>>();
    sandboxed_process_command_for_profile(
        run,
        SandboxProfile::RepositoryHook,
        source.get_program(),
        &args,
        cwd,
        &environment,
    )
}

fn sandboxed_process_command_for_profile(
    run: &crate::tools::security::ToolRunContext,
    profile: SandboxProfile,
    program: &OsStr,
    args: &[OsString],
    cwd: &Path,
    explicit_environment: &[(OsString, OsString)],
) -> Result<crate::tools::command::PreparedProcessCommand, String> {
    run.require(crate::tools::security::ToolResource::Process)
        .map_err(|error| error.to_string())?;
    validate_explicit_environment(profile, explicit_environment)?;
    if *SANDBOX_DISABLED.as_ref().map_err(Clone::clone)? {
        static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !WARNED.swap(true, std::sync::atomic::Ordering::SeqCst) {
            tracing::warn!(
                target: "openclaudia::bash",
                env = DISABLE_ENV,
                "Bash OS sandbox explicitly disabled by the host user; model commands have host access"
            );
        }
        return unsandboxed_process_command(run, profile, program, args, cwd, explicit_environment);
    }

    #[cfg(target_os = "linux")]
    {
        linux_bubblewrap_command(run, profile, program, args, cwd, explicit_environment)
    }

    #[cfg(target_os = "macos")]
    {
        let _ = (profile, program, args, cwd);
        Err(format!(
            "Agent subprocess execution is blocked on macOS: the deprecated sandbox-exec \
             interface is not accepted as a production security boundary, and this build has \
             no signed helper sandbox. OpenClaudia will not fall back to host execution. \
             A host user may explicitly accept the risk with {DISABLE_ENV}=off"
        ))
    }

    #[cfg(windows)]
    {
        let _ = (profile, program, args, cwd);
        Err(format!(
            "Agent subprocess execution is blocked: the Windows AppContainer backend is not \
             available in this build. OpenClaudia will not fall back to host execution. \
             A host user may explicitly accept the risk with {DISABLE_ENV}=off"
        ))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (profile, program, args, cwd);
        Err(format!(
            "Agent subprocess execution is blocked: {} has no supported OpenClaudia sandbox \
             backend, and host execution is never selected automatically. A host user may \
             explicitly accept the risk with {DISABLE_ENV}=off",
            std::env::consts::OS
        ))
    }
}

fn validate_explicit_environment(
    profile: SandboxProfile,
    environment: &[(OsString, OsString)],
) -> Result<(), String> {
    if environment.is_empty() {
        return Ok(());
    }
    if !profile.policy().permits_explicit_environment {
        return Err(format!(
            "Sandbox profile {profile:?} does not permit an explicit environment overlay"
        ));
    }
    for (name, _) in environment {
        let name = name
            .to_str()
            .ok_or_else(|| "Environment variable names must be Unicode".to_string())?;
        let mut characters = name.chars();
        let valid = characters
            .next()
            .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
            && characters.all(|character| character == '_' || character.is_ascii_alphanumeric());
        if !valid {
            return Err(format!("Refusing invalid child environment name '{name}'"));
        }
        let upper = name.to_ascii_uppercase();
        if upper.starts_with("LD_")
            || upper.starts_with("DYLD_")
            || matches!(
                upper.as_str(),
                "HOME"
                    | "PATH"
                    | "TMPDIR"
                    | "TMP"
                    | "TEMP"
                    | "CARGO_HOME"
                    | "RUSTUP_HOME"
                    | "GCONV_PATH"
                    | "GLIBC_TUNABLES"
                    | "LOCPATH"
                    | "NLSPATH"
                    | "OPENCLAUDIA_SANDBOX"
            )
        {
            return Err(format!(
                "Refusing child environment override for sandbox-owned or loader variable '{name}'"
            ));
        }
    }
    Ok(())
}

fn sandbox_explicitly_disabled_from_env() -> Result<bool, String> {
    std::env::var_os(DISABLE_ENV).map_or(Ok(false), |value| {
        value.to_str().map_or_else(
            || {
                Err(format!(
                    "{DISABLE_ENV} contains non-Unicode data; refusing to weaken the Bash sandbox"
                ))
            },
            sandbox_explicitly_disabled_value,
        )
    })
}

fn sandbox_explicitly_disabled_value(value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "on" | "1" | "true" | "required" => Ok(false),
        "off" | "0" | "false" | "disabled" => Ok(true),
        _ => Err(format!(
            "Invalid {DISABLE_ENV} value '{value}'; use 'on' (default) or 'off'"
        )),
    }
}

fn unsandboxed_process_command(
    run: &crate::tools::security::ToolRunContext,
    profile: SandboxProfile,
    program: &OsStr,
    args: &[OsString],
    cwd: &Path,
    explicit_environment: &[(OsString, OsString)],
) -> Result<crate::tools::command::PreparedProcessCommand, String> {
    let policy = profile.policy();
    let cwd = if policy.workspace == WorkspaceMountPolicy::ScratchOnly {
        canonical_working_directory(run.private_temp_root())?
    } else {
        canonical_working_directory(cwd)?
    };
    let mut cmd = Command::new(program);
    cmd.args(args).current_dir(cwd);
    super::apply_env_scrub(&mut cmd);
    cmd.env("HOME", run.private_temp_root())
        .env("TMPDIR", run.private_temp_root())
        .env("TMP", run.private_temp_root())
        .env("TEMP", run.private_temp_root())
        .env("PATH", run.executable_search_path());
    apply_profile_environment(run, policy.environment, &mut cmd);
    cmd.envs(
        explicit_environment
            .iter()
            .map(|(name, value)| (name, value)),
    );
    Ok(crate::tools::command::PreparedProcessCommand::host(cmd))
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_lines)]
fn linux_bubblewrap_command(
    security: &crate::tools::security::ToolRunContext,
    profile: SandboxProfile,
    program: &OsStr,
    args: &[OsString],
    cwd: &Path,
    explicit_environment: &[(OsString, OsString)],
) -> Result<crate::tools::command::PreparedProcessCommand, String> {
    let policy = profile.policy();
    let cwd = if policy.workspace == WorkspaceMountPolicy::ScratchOnly {
        canonical_working_directory(security.private_temp_root())?
    } else {
        canonical_working_directory(cwd)?
    };
    let backend = BWRAP_BACKEND.as_ref().map_err(Clone::clone)?;
    if policy.workspace != WorkspaceMountPolicy::ScratchOnly && !security.permits_read(&cwd) {
        return Err(format!(
            "Sandbox working directory '{}' is outside the immutable session capabilities rooted at '{}'",
            cwd.display(),
            security.project_root().display()
        ));
    }
    let project_root = security.project_root();
    let host_home = security.host_home();

    // A writable bind of HOME (or an ancestor of it) would make the nominal
    // "project" mount expose credentials and host configuration.
    if policy.workspace != WorkspaceMountPolicy::ScratchOnly
        && (is_unsafe_broad_project_root(project_root)
            || host_home.is_some_and(|home| home == project_root || home.starts_with(project_root)))
    {
        return Err(format!(
            "Refusing to sandbox Bash with working directory '{}': choose a dedicated \
             project directory, not a broad system root or an ancestor of the user home",
            project_root.display()
        ));
    }
    let sandbox_home =
        host_home.map_or_else(|| PathBuf::from("/home/openclaudia"), Path::to_path_buf);
    let workspace_projection = if matches!(
        policy.workspace,
        WorkspaceMountPolicy::ProjectRunBound | WorkspaceMountPolicy::RunBound
    ) {
        // Validate the granted host tree before projecting it. Candidate files
        // use independent workspace inodes, so inspecting only the candidate
        // would hide a source inode that also has a hardlink outside the
        // writable grant.
        validate_writable_project_tree(project_root)?;
        crate::tools::file::workspace_projection::WorkspaceProjection::prepare(
            security,
            matches!(profile, SandboxProfile::GitWorktree),
        )?
    } else {
        None
    };
    let private_cargo_target = workspace_projection
        .as_ref()
        .filter(|projection| projection.uses_private_cargo_target())
        .map(|_| security.private_temp_root().join("cargo-target"));
    let mut pinned_bind_roots = security.duplicate_linux_bind_roots()?;
    pinned_bind_roots.retain(|root| match policy.workspace {
        WorkspaceMountPolicy::ScratchOnly => root.path == security.private_temp_root(),
        WorkspaceMountPolicy::ProjectReadOnly | WorkspaceMountPolicy::ProjectRunBound => {
            root.path == security.private_temp_root() || root.path == project_root
        }
        WorkspaceMountPolicy::RunBound => true,
    });
    if policy.workspace == WorkspaceMountPolicy::ProjectReadOnly {
        for root in &mut pinned_bind_roots {
            if root.path != security.private_temp_root() {
                root.writable = false;
            }
        }
    }
    if let Some(projection) = &workspace_projection {
        for root in &mut pinned_bind_roots {
            if root.path == project_root && root.writable {
                root.directory = projection.duplicate_candidate_bind_fd()?;
            }
        }
    }
    for writable_root in pinned_bind_roots.iter().filter(|root| {
        root.writable && root.path != security.private_temp_root() && root.path != project_root
    }) {
        validate_writable_project_tree(&writable_root.path)?;
    }
    let effective_read_write_roots = pinned_bind_roots
        .iter()
        .filter(|root| root.writable)
        .count();
    let effective_read_only_roots = pinned_bind_roots.len() - effective_read_write_roots;
    let effective_environment_grants = match policy.environment {
        EnvironmentPolicy::Empty => 0,
        EnvironmentPolicy::NonSecretRunGrants => security
            .environment_grants()
            .keys()
            .filter(|name| !super::is_sensitive_env(name))
            .count(),
        EnvironmentPolicy::RunGrants => security.environment_grants().len(),
    } + explicit_environment.len();
    tracing::debug!(
        target: "openclaudia::sandbox",
        event = "effective_subprocess_grants",
        session_id = security.session_id(),
        project_root = %project_root.display(),
        working_directory = %cwd.display(),
        profile = ?profile,
        read_only_roots = effective_read_only_roots,
        read_write_roots = effective_read_write_roots,
        environment_grants = effective_environment_grants,
        network = "denied",
        devices = "minimal",
        child_processes = policy.permits_child_processes,
        "Compiled least-privilege subprocess profile"
    );
    if let Some(projection) = &workspace_projection {
        tracing::debug!(
            target: "openclaudia::workspace_projection",
            event = "workspace_projection_bound",
            generation = projection.generation(),
            profile = ?profile,
            "Bound isolated writable candidate instead of the host project"
        );
    }
    let mut metadata_bind_fds = Vec::new();
    let mut cmd = Command::new(&backend.path);
    cmd.args(["--die-with-parent", "--new-session", "--unshare-all"]);
    if backend.share_network_namespace {
        cmd.arg("--share-net");
    }
    cmd.args([
        "--unshare-user",
        "--disable-userns",
        "--assert-userns-disabled",
        "--cap-drop",
        "ALL",
        "--hostname",
        "openclaudia-sandbox",
        "--seccomp",
        "198",
    ]);

    // Start from an empty root and add only runtime trees. In particular,
    // host /etc, /home, /root, /run, /tmp, /var, /proc and /sys are not
    // inherited.
    add_read_only_tree_if_present(&mut cmd, Path::new("/usr"));
    add_read_only_tree_if_present(&mut cmd, Path::new("/nix/store"));
    add_read_only_tree_if_present(&mut cmd, Path::new("/nix/var/nix/profiles"));
    add_runtime_alias(&mut cmd, "/bin", "usr/bin");
    add_runtime_alias(&mut cmd, "/sbin", "usr/sbin");
    add_runtime_alias(&mut cmd, "/lib", "usr/lib");
    add_runtime_alias(&mut cmd, "/lib64", "usr/lib64");
    cmd.args([
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/run",
    ]);

    let mut made_dirs = HashSet::new();
    add_directory_ancestors(&mut cmd, &mut made_dirs, &sandbox_home);

    // Make common local toolchains available without exposing the rest of
    // HOME. Cargo's directory itself stays writable tmpfs for lock/cache
    // metadata; binaries and the registry cache are nested read-only binds.
    let sandbox_cargo = sandbox_home.join(".cargo");
    add_directory(&mut cmd, &mut made_dirs, &sandbox_cargo);
    if let Some(home) = host_home {
        add_read_only_tree_if_present(&mut cmd, &home.join(".cargo/bin"));
        add_read_only_tree_if_present(&mut cmd, &home.join(".cargo/registry"));
        add_read_only_tree_if_present(&mut cmd, &home.join(".rustup"));
    }

    for root in &pinned_bind_roots {
        add_directory_ancestors(&mut cmd, &mut made_dirs, &root.path);
        cmd.arg(if root.writable {
            "--bind-fd"
        } else {
            "--ro-bind-fd"
        })
        .arg(root.directory.as_raw_fd().to_string())
        .arg(&root.path);
    }
    if let Some(cargo_target) = &private_cargo_target {
        add_pinned_writable_directory_bind(
            &mut cmd,
            &mut metadata_bind_fds,
            cargo_target,
            &project_root.join("target"),
        )?;
    }

    // Repository metadata and harness control state are not ordinary project
    // output. A shell must not persist hooks/configuration that execute after
    // the sandbox exits, or read transcripts and local agent state.
    if policy.workspace == WorkspaceMountPolicy::ScratchOnly {
        // The project is absent from this namespace.
    } else if matches!(profile, SandboxProfile::GitWorktree) {
        tracing::info!(
            target: "openclaudia::sandbox",
            event = "git_metadata_write_grant",
            session_id = security.session_id(),
            "Git worktree profile received project-local metadata write access"
        );
    } else {
        protect_repository_metadata(
            &mut cmd,
            &mut made_dirs,
            &mut metadata_bind_fds,
            project_root,
        )?;
    }
    if policy.workspace != WorkspaceMountPolicy::ScratchOnly {
        match profile.control_path_access() {
            ControlPathAccess::Hidden => {
                hide_control_path(&mut cmd, &project_root.join(".openclaudia"));
                hide_control_path(&mut cmd, &project_root.join(".claude"));
            }
            ControlPathAccess::ReadOnly => {
                for control_path in [
                    project_root.join(".openclaudia"),
                    project_root.join(".claude"),
                ] {
                    if control_path.exists() {
                        add_pinned_read_only_bind(&mut cmd, &mut metadata_bind_fds, &control_path)?;
                    }
                }
            }
        }
        for denied_path in security.denied_paths() {
            if denied_path != &project_root.join(".openclaudia")
                && denied_path != &project_root.join(".claude")
            {
                hide_control_path(&mut cmd, denied_path);
            }
        }
        if let Some(projection) = &workspace_projection {
            hide_control_path(&mut cmd, projection.transaction_parent());
        }
    }

    let safe_path = sandbox_path(
        project_root,
        host_home,
        profile.permits_project_path(),
        security.executable_search_path(),
    );
    let private_temp = security.private_temp_root();
    cmd.arg("--chdir")
        .arg(&cwd)
        .args(["--setenv", "HOME"])
        .arg(private_temp)
        .args(["--setenv", "TMPDIR"])
        .arg(private_temp)
        .args(["--setenv", "TMP"])
        .arg(private_temp)
        .args(["--setenv", "TEMP"])
        .arg(private_temp)
        .args(["--setenv", "CARGO_HOME"])
        .arg(&sandbox_cargo);
    cmd.args(["--setenv", "CARGO_TARGET_DIR"])
        .arg(private_temp.join("cargo-target"))
        .args(["--setenv", "PYTHONPYCACHEPREFIX"])
        .arg(private_temp.join("python-cache"));
    cmd.args(["--setenv", "RUSTUP_HOME"])
        .arg(sandbox_home.join(".rustup"))
        .args(["--setenv", "PATH", &safe_path])
        .args(["--setenv", "XDG_CONFIG_HOME", "/tmp/xdg/config"])
        .args(["--setenv", "XDG_CACHE_HOME", "/tmp/xdg/cache"])
        .args(["--setenv", "XDG_DATA_HOME", "/tmp/xdg/data"])
        .args(["--setenv", "OPENCLAUDIA_SANDBOX", "1"])
        // Do not carry pointers to host IPC endpoints into the namespace.
        .args(["--unsetenv", "SSH_AUTH_SOCK"])
        .args(["--unsetenv", "SSH_AGENT_PID"])
        .args(["--unsetenv", "DBUS_SESSION_BUS_ADDRESS"])
        .args(["--unsetenv", "DISPLAY"])
        .args(["--unsetenv", "WAYLAND_DISPLAY"])
        .args(["--unsetenv", "XDG_RUNTIME_DIR"])
        .args(["--"])
        .arg(program)
        .args(args)
        .current_dir(&cwd);
    super::apply_env_scrub(&mut cmd);
    apply_profile_environment(security, policy.environment, &mut cmd);
    cmd.envs(
        explicit_environment
            .iter()
            .map(|(name, value)| (name, value)),
    );
    let inherited_bind_fds = pinned_bind_roots
        .into_iter()
        .map(|root| root.directory)
        .chain(metadata_bind_fds)
        .collect();
    install_linux_process_hardening(&mut cmd, inherited_bind_fds, policy.permits_child_processes)?;
    Ok(crate::tools::command::PreparedProcessCommand::sandboxed(
        cmd,
        workspace_projection,
    ))
}

#[cfg(target_os = "linux")]
fn is_unsafe_broad_project_root(path: &Path) -> bool {
    const BROAD_ROOTS: &[&str] = &[
        "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/media", "/mnt", "/opt",
        "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var",
    ];
    BROAD_ROOTS.iter().any(|root| path == Path::new(root))
}

fn canonical_working_directory(cwd: &Path) -> Result<PathBuf, String> {
    let canonical = cwd.canonicalize().map_err(|e| {
        format!(
            "Cannot resolve Bash working directory '{}': {e}",
            cwd.display()
        )
    })?;
    if !canonical.is_dir() {
        return Err(format!(
            "Bash working directory '{}' is not a directory",
            canonical.display()
        ));
    }
    Ok(canonical)
}

#[cfg(target_os = "linux")]
fn find_bwrap() -> Result<BubblewrapBackend, String> {
    const TRUSTED_LOCATIONS: &[&str] = &[
        "/usr/bin/bwrap",
        "/usr/sbin/bwrap",
        "/bin/bwrap",
        "/sbin/bwrap",
    ];
    for candidate in TRUSTED_LOCATIONS {
        let path = Path::new(candidate);
        if path.is_file() {
            let resolved = path
                .canonicalize()
                .map_err(|e| format!("Cannot resolve bubblewrap at '{candidate}': {e}"))?;
            let metadata = fs::metadata(&resolved).map_err(|e| {
                format!("Cannot inspect bubblewrap at '{}': {e}", resolved.display())
            })?;
            if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
                return Err(format!(
                    "Agent execution is blocked because bubblewrap at '{}' is not root-owned \
                     and non-writable by group/other",
                    resolved.display()
                ));
            }
            let share_network_namespace = match probe_bwrap(&resolved, false) {
                Ok(()) => false,
                Err(error) if is_network_namespace_probe_failure(&error) => {
                    probe_bwrap(&resolved, true).map_err(|fallback_error| {
                        format!(
                            "{error}; Bubblewrap also failed with the seccomp-enforced network \
                             fallback: {fallback_error}"
                        )
                    })?;
                    true
                }
                Err(error) => return Err(error),
            };
            return Ok(BubblewrapBackend {
                path: resolved,
                share_network_namespace,
            });
        }
    }
    Err(format!(
        "Bash execution is blocked because bubblewrap (bwrap) is not installed. \
         Install bubblewrap, or have the host user explicitly accept unsandboxed \
         execution with {DISABLE_ENV}=off"
    ))
}

#[cfg(target_os = "linux")]
fn probe_bwrap(bwrap: &Path, share_network_namespace: bool) -> Result<(), String> {
    let true_bin = ["/usr/bin/true", "/bin/true"]
        .iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .ok_or_else(|| {
            "Agent execution is blocked because no trusted `true` binary is available for the sandbox health check"
                .to_string()
        })?;
    let root = Arc::new(
        std::fs::File::open("/")
            .map_err(|error| format!("Cannot pin root for Bubblewrap probe: {error}"))?,
    );
    let root_fd = root.as_raw_fd();
    let root_for_child = Arc::clone(&root);
    let filter = Arc::new(linux_seccomp_filter(true)?);
    let filter_for_child = Arc::clone(&filter);
    let mut command = Command::new(bwrap);
    command.args(["--die-with-parent", "--new-session", "--unshare-all"]);
    if share_network_namespace {
        command.arg("--share-net");
    }
    command
        .args([
            "--unshare-user",
            "--disable-userns",
            "--assert-userns-disabled",
            "--cap-drop",
            "ALL",
            "--ro-bind-fd",
        ])
        .arg(root_fd.to_string())
        .args([
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--seccomp",
            "198",
            "--",
        ])
        .arg(true_bin)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: fcntl is async-signal-safe and `root_for_child` pins the
    // descriptor until spawn completes.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(root_for_child.as_raw_fd(), libc::F_SETFD, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            install_seccomp_filter_fd(&filter_for_child)?;
            close_inherited_file_descriptors(&[root_for_child.as_raw_fd(), SECCOMP_FILTER_FD])
        });
    }
    let output = command.output().map_err(|error| {
        format!(
            "Agent execution is blocked because bubblewrap health check could not start: {error}"
        )
    })?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let diagnostic = crate::tools::safe_truncate(stderr.trim(), 2048);
    let category = classify_bwrap_probe_failure(diagnostic);
    Err(format!(
        "Agent execution is blocked because bubblewrap is installed but unusable \
         ({category}, status {}): {diagnostic}",
        output.status,
    ))
}

#[cfg(target_os = "linux")]
fn is_network_namespace_probe_failure(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("loopback")
        && (lower.contains("rtm_newaddr") || lower.contains("operation not permitted"))
}

#[cfg(target_os = "linux")]
fn classify_bwrap_probe_failure(stderr: &str) -> &'static str {
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("user namespace") || lower.contains("userns") {
        "user namespaces disabled or restricted"
    } else if lower.contains("operation not permitted") || lower.contains("permission denied") {
        "container or kernel namespace policy denied the probe"
    } else if lower.contains("mount") {
        "required mount behavior unavailable"
    } else if lower.contains("setuid") {
        "setuid bubblewrap configuration rejected"
    } else {
        "backend health probe failed"
    }
}

#[cfg(target_os = "linux")]
fn validate_writable_project_tree(root: &Path) -> Result<(), String> {
    validate_no_nested_mounts(root)?;
    let root_device = fs::metadata(root)
        .map_err(|error| format!("Cannot inspect project root '{}': {error}", root.display()))?
        .dev();
    let mut stack = vec![root.to_path_buf()];
    let mut visited = 0usize;
    let mut hardlinks: HashMap<(u64, u64), (PathBuf, u64, u64)> = HashMap::new();

    while let Some(directory) = stack.pop() {
        let entries = fs::read_dir(&directory).map_err(|error| {
            format!(
                "Cannot securely inspect writable project directory '{}': {error}",
                directory.display()
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "Cannot securely inspect an entry below '{}': {error}",
                    directory.display()
                )
            })?;
            visited = visited.saturating_add(1);
            if visited > MAX_PROJECT_SCAN_ENTRIES {
                return Err(format!(
                    "Refusing to mount project '{}' writable because its security scan exceeded \
                     {MAX_PROJECT_SCAN_ENTRIES} entries",
                    root.display()
                ));
            }

            let path = entry.path();
            let relative = path.strip_prefix(root).map_err(|error| {
                format!(
                    "Project security scan produced an out-of-root path '{}': {error}",
                    path.display()
                )
            })?;
            if relative
                .components()
                .next()
                .and_then(|component| component.as_os_str().to_str())
                .is_some_and(|name| matches!(name, ".git" | ".openclaudia" | ".claude"))
            {
                continue;
            }

            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                format!(
                    "Cannot securely inspect project entry '{}': {error}",
                    path.display()
                )
            })?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                continue;
            }
            if metadata.dev() != root_device {
                return Err(format!(
                    "Refusing writable project mount: '{}' crosses onto another filesystem or mount",
                    path.display()
                ));
            }
            if file_type.is_socket()
                || file_type.is_fifo()
                || file_type.is_block_device()
                || file_type.is_char_device()
            {
                return Err(format!(
                    "Refusing writable project mount because '{}' is a socket, FIFO, or device node",
                    path.display()
                ));
            }
            if file_type.is_file() && metadata.nlink() > 1 {
                let record = hardlinks
                    .entry((metadata.dev(), metadata.ino()))
                    .or_insert_with(|| (path.clone(), metadata.nlink(), 0));
                record.2 = record.2.saturating_add(1);
            }
            if file_type.is_dir() {
                stack.push(path);
            }
        }
    }
    for (_, (path, link_count, observed_inside_root)) in hardlinks {
        if observed_inside_root != link_count {
            return Err(format!(
                "Refusing writable project mount because '{}' has {link_count} hardlinks but \
                 only {observed_inside_root} are inside the writable grant; another link may \
                 alias a file outside the sandbox",
                path.display()
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_no_nested_mounts(root: &Path) -> Result<(), String> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("Cannot inspect Linux mount table: {error}"))?;
    for line in mountinfo.lines() {
        let Some(encoded_mountpoint) = line.split_whitespace().nth(4) else {
            return Err(
                "Malformed /proc/self/mountinfo entry; refusing writable mount".to_string(),
            );
        };
        let mountpoint = PathBuf::from(decode_mountinfo_path(encoded_mountpoint)?);
        if mountpoint != root && mountpoint.starts_with(root) {
            return Err(format!(
                "Refusing writable project mount because nested host mount '{}' is inside '{}'",
                mountpoint.display(),
                root.display()
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn decode_mountinfo_path(encoded: &str) -> Result<String, String> {
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if index + 3 >= bytes.len()
                || !bytes[index + 1..=index + 3].iter().all(u8::is_ascii_digit)
            {
                return Err(format!(
                    "Malformed escaped mount path in /proc/self/mountinfo: {encoded}"
                ));
            }
            let octal = &encoded[index + 1..=index + 3];
            let value = u8::from_str_radix(octal, 8)
                .map_err(|error| format!("Malformed mount path escape '\\{octal}': {error}"))?;
            decoded.push(value);
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded)
        .map_err(|error| format!("Non-UTF-8 mount path is not supported safely: {error}"))
}

#[cfg(target_os = "linux")]
fn install_linux_process_hardening(
    command: &mut Command,
    inherited_bind_fds: Vec<OwnedFd>,
    permits_child_processes: bool,
) -> Result<(), String> {
    let filter = Arc::new(linux_seccomp_filter(permits_child_processes)?);
    let process_limit = host_uid_process_limit()?;
    let inherited_bind_fds = Arc::new(inherited_bind_fds);
    let preserved_fds: Vec<libc::c_int> = inherited_bind_fds
        .iter()
        .map(std::os::fd::AsRawFd::as_raw_fd)
        .chain(std::iter::once(SECCOMP_FILTER_FD))
        .collect();
    // SAFETY: the closure only invokes async-signal-safe libc syscalls between
    // fork and exec. It performs no allocation, locking, or environment access.
    unsafe {
        command.pre_exec(move || {
            apply_sandbox_rlimits(Some(process_limit))?;
            for fd in inherited_bind_fds.iter() {
                if libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            install_seccomp_filter_fd(&filter)?;
            close_inherited_file_descriptors(&preserved_fds)
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn close_inherited_file_descriptors(preserved: &[libc::c_int]) -> std::io::Result<()> {
    const CLOSE_RANGE_LAST: libc::c_uint = libc::c_uint::MAX;
    // Keep only stdio and descriptors explicitly consumed by Bubblewrap.
    // `close_range` is required; an unavailable syscall fails spawn closed
    // instead of preserving ambient host handles.
    let mut preserved: Vec<u32> = preserved
        .iter()
        .filter_map(|fd| u32::try_from(*fd).ok())
        .filter(|fd| *fd >= 3)
        .collect();
    preserved.sort_unstable();
    preserved.dedup();
    let mut ranges = Vec::with_capacity(preserved.len() + 1);
    let mut first = 3u32;
    for fd in preserved {
        if first < fd {
            ranges.push((first, fd - 1));
        }
        first = fd.saturating_add(1);
    }
    ranges.push((first, CLOSE_RANGE_LAST));
    for (first, last) in ranges {
        let result = unsafe { libc::syscall(libc::SYS_close_range, first, last, 0u32) };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_sandbox_rlimits(process_limit: Option<libc::rlim_t>) -> std::io::Result<()> {
    set_rlimit(libc::RLIMIT_CORE, 0)?;
    set_rlimit(libc::RLIMIT_NOFILE, 1024)?;
    set_rlimit(libc::RLIMIT_FSIZE, 256 * 1024 * 1024)?;
    set_rlimit(libc::RLIMIT_CPU, 300)?;
    set_rlimit(libc::RLIMIT_AS, 4 * 1024 * 1024 * 1024)?;
    if let Some(limit) = process_limit {
        set_rlimit(libc::RLIMIT_NPROC, limit)?;
    }
    Ok(())
}

/// `RLIMIT_NPROC` is per real host UID rather than per PID namespace. A fixed
/// value can prevent Bubblewrap itself from cloning when the desktop account
/// already owns many processes. Pin the observed baseline and allow at most
/// 256 additional processes across the command lifetime. cgroup-v2 remains
/// preferable when the service manager delegates a writable subtree, while
/// this conservative fallback works in ordinary unprivileged shells.
#[cfg(target_os = "linux")]
fn host_uid_process_limit() -> Result<libc::rlim_t, String> {
    let uid = unsafe { libc::geteuid() };
    let entries = fs::read_dir("/proc")
        .map_err(|error| format!("Cannot inspect process count for sandbox limits: {error}"))?;
    let mut count = 0u64;
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        if entry.metadata().is_ok_and(|metadata| metadata.uid() == uid) {
            // Linux accounts threads, not merely thread-group leaders,
            // against RLIMIT_NPROC.
            let task_count = fs::read_dir(entry.path().join("task"))
                .map_or(1, |tasks| u64::try_from(tasks.count()).unwrap_or(u64::MAX));
            count = count.saturating_add(task_count);
        }
    }
    Ok(count.saturating_add(256))
}

#[cfg(target_os = "linux")]
fn set_rlimit(resource: libc::__rlimit_resource_t, value: libc::rlim_t) -> std::io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: `limit` points to an initialized `rlimit`, and `resource` is
    // one of the platform constants supplied by the callers above.
    if unsafe { libc::setrlimit(resource, &raw const limit) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn install_seccomp_filter_fd(filter: &[u8]) -> std::io::Result<()> {
    let mut pipe_fds = [0; 2];
    // SAFETY: `pipe_fds` points to two writable integers.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let read_fd = pipe_fds[0];
    let write_fd = pipe_fds[1];
    let mut written = 0usize;
    while written < filter.len() {
        // SAFETY: the slice pointer is valid for the remaining byte count and
        // `write_fd` is the pipe endpoint created above.
        let result = unsafe {
            libc::write(
                write_fd,
                filter[written..].as_ptr().cast(),
                filter.len() - written,
            )
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: both descriptors were returned by `pipe`.
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return Err(error);
        }
        if result == 0 {
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "seccomp filter pipe accepted zero bytes",
            ));
        }
        written += usize::try_from(result)
            .map_err(|_| std::io::Error::other("seccomp write count overflow"))?;
    }
    // SAFETY: write endpoint is no longer needed after the complete filter has
    // been buffered.
    unsafe {
        libc::close(write_fd);
    }
    if read_fd != SECCOMP_FILTER_FD {
        // SAFETY: duplicate the valid read endpoint onto the fixed descriptor
        // named in Bubblewrap's `--seccomp` argument.
        if unsafe { libc::dup2(read_fd, SECCOMP_FILTER_FD) } < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: `read_fd` remains owned by this closure on failure.
            unsafe {
                libc::close(read_fd);
            }
            return Err(error);
        }
        // SAFETY: the duplicated descriptor now owns the same open file.
        unsafe {
            libc::close(read_fd);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_seccomp_filter(permits_child_processes: bool) -> Result<Vec<u8>, String> {
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        return Err(format!(
            "Agent execution is blocked: no seccomp policy is defined for Linux architecture {}",
            std::env::consts::ARCH
        ));
    }

    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

    let statement = |code, value| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    };
    let jump = |value, jt, jf| libc::sock_filter {
        code: BPF_JMP_JEQ_K,
        jt,
        jf,
        k: value,
    };
    let mut program = vec![
        statement(BPF_LD_W_ABS, 4),
        jump(AUDIT_ARCH, 1, 0),
        statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        statement(BPF_LD_W_ABS, 0),
    ];
    for syscall in denied_linux_syscalls(permits_child_processes) {
        program.push(jump(syscall, 0, 1));
        program.push(statement(
            BPF_RET_K,
            SECCOMP_RET_ERRNO | u32::try_from(libc::EPERM).unwrap_or(1),
        ));
    }
    program.push(statement(BPF_RET_K, SECCOMP_RET_ALLOW));

    let byte_len = program
        .len()
        .checked_mul(std::mem::size_of::<libc::sock_filter>())
        .ok_or_else(|| "seccomp filter size overflow".to_string())?;
    // SAFETY: `program` is alive for the copy, and `byte_len` exactly spans
    // its contiguous initialized `sock_filter` elements.
    let bytes =
        unsafe { std::slice::from_raw_parts(program.as_ptr().cast::<u8>(), byte_len) }.to_vec();
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn denied_linux_syscalls(permits_child_processes: bool) -> Vec<u32> {
    let mut denied = vec![
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_ptrace,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_userfaultfd,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_io_uring_setup,
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
    ];
    if !permits_child_processes {
        denied.extend([libc::SYS_clone, libc::SYS_clone3]);
        #[cfg(target_arch = "x86_64")]
        denied.extend([libc::SYS_fork, libc::SYS_vfork]);
    }
    denied
        .into_iter()
        .filter_map(|syscall| u32::try_from(syscall).ok())
        .collect()
}

fn apply_profile_environment(
    run: &crate::tools::security::ToolRunContext,
    policy: EnvironmentPolicy,
    command: &mut Command,
) {
    match policy {
        EnvironmentPolicy::Empty => {}
        EnvironmentPolicy::NonSecretRunGrants => {
            for name in run.environment_grants().keys() {
                if !super::is_sensitive_env(name) {
                    let _ = run.environment_grants().with_value(name, |value| {
                        command.env(name, value);
                    });
                }
            }
        }
        EnvironmentPolicy::RunGrants => run.environment_grants().apply_std(command),
    }
}

#[cfg(target_os = "linux")]
fn add_read_only_tree_if_present(cmd: &mut Command, path: &Path) {
    if path.exists() {
        cmd.arg("--ro-bind").arg(path).arg(path);
    }
}

#[cfg(target_os = "linux")]
fn add_runtime_alias(cmd: &mut Command, destination: &str, target: &str) {
    let destination_path = Path::new(destination);
    if let Ok(link_target) = std::fs::read_link(destination_path) {
        cmd.arg("--symlink").arg(link_target).arg(destination_path);
    } else if destination_path.exists() {
        add_read_only_tree_if_present(cmd, destination_path);
    } else if Path::new("/usr")
        .join(target.trim_start_matches("usr/"))
        .exists()
    {
        cmd.args(["--symlink", target, destination]);
    }
}

#[cfg(target_os = "linux")]
fn add_directory_ancestors(cmd: &mut Command, made_dirs: &mut HashSet<PathBuf>, path: &Path) {
    let mut ancestors: Vec<_> = path.ancestors().collect();
    ancestors.reverse();
    for ancestor in ancestors {
        if ancestor != Path::new("/") {
            add_directory(cmd, made_dirs, ancestor);
        }
    }
}

#[cfg(target_os = "linux")]
fn add_directory(cmd: &mut Command, made_dirs: &mut HashSet<PathBuf>, path: &Path) {
    if made_dirs.insert(path.to_path_buf()) {
        cmd.arg("--dir").arg(path);
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_lines)]
fn protect_repository_metadata(
    cmd: &mut Command,
    made_dirs: &mut HashSet<PathBuf>,
    inherited_bind_fds: &mut Vec<OwnedFd>,
    project_root: &Path,
) -> Result<(), String> {
    let path = project_root.join(".git");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "Cannot inspect repository metadata boundary: {error}"
            ))
        }
    };
    if metadata.file_type().is_symlink() {
        return Err("Refusing a symbolic-link .git metadata entry".to_string());
    }
    if metadata.is_dir() {
        // Present a minimal read-only Git database instead of the whole
        // directory. This keeps status/diff functional without exposing
        // credential-bearing remote URLs, hooks, reflogs, or mutable locks.
        cmd.arg("--tmpfs").arg(&path);
        for entry in ["HEAD", "index", "objects", "refs", "packed-refs", "shallow"] {
            let source = path.join(entry);
            if source.exists() {
                add_pinned_read_only_bind(cmd, inherited_bind_fds, &source)?;
            }
        }
        cmd.args(["--chmod", "0555"]).arg(&path);
        return Ok(());
    }
    if !metadata.is_file() {
        return Err("Refusing non-file, non-directory .git metadata entry".to_string());
    }

    let contents = fs::read_to_string(&path)
        .map_err(|error| format!("Cannot read linked-worktree .git file: {error}"))?;
    if contents.len() > 4096 {
        return Err("Refusing oversized linked-worktree .git file".to_string());
    }
    let target = contents
        .trim()
        .strip_prefix("gitdir:")
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .ok_or_else(|| "Refusing malformed linked-worktree .git file".to_string())?;
    let target = Path::new(target);
    let admin_candidate = if target.is_absolute() {
        target.to_path_buf()
    } else {
        project_root.join(target)
    };
    let admin = admin_candidate
        .canonicalize()
        .map_err(|error| format!("Cannot resolve linked-worktree metadata: {error}"))?;
    if !admin.is_dir() {
        return Err("Linked-worktree metadata target is not a directory".to_string());
    }
    let commondir_text = fs::read_to_string(admin.join("commondir"))
        .map_err(|error| format!("Linked-worktree metadata has no valid commondir: {error}"))?;
    let commondir_rel = Path::new(commondir_text.trim());
    if commondir_rel.as_os_str().is_empty() {
        return Err("Linked-worktree commondir is empty".to_string());
    }
    let common_candidate = if commondir_rel.is_absolute() {
        commondir_rel.to_path_buf()
    } else {
        admin.join(commondir_rel)
    };
    let common = common_candidate
        .canonicalize()
        .map_err(|error| format!("Cannot resolve linked-worktree common metadata: {error}"))?;
    let expected_admin_parent = common.join("worktrees").canonicalize().map_err(|error| {
        format!("Linked-worktree common metadata has no worktrees directory: {error}")
    })?;
    if admin.parent() != Some(expected_admin_parent.as_path()) {
        return Err(
            "Refusing linked-worktree metadata that is not owned by its declared common repository"
                .to_string(),
        );
    }
    let backlink = fs::read_to_string(admin.join("gitdir"))
        .map_err(|error| format!("Linked-worktree metadata has no backlink: {error}"))?;
    let backlink = Path::new(backlink.trim())
        .canonicalize()
        .map_err(|error| format!("Cannot resolve linked-worktree backlink: {error}"))?;
    let expected_backlink = path
        .canonicalize()
        .map_err(|error| format!("Cannot resolve worktree .git backlink target: {error}"))?;
    if backlink != expected_backlink {
        return Err(
            "Refusing linked-worktree metadata whose backlink does not name this worktree"
                .to_string(),
        );
    }

    // The indirection file is harmless after the target and backlink have
    // been proven. Construct empty metadata directories at their original
    // absolute locations, then expose only object/ref/index state. Config,
    // hooks, credentials, logs/reflogs, and sibling worktrees stay absent.
    add_pinned_read_only_bind(cmd, inherited_bind_fds, &path)?;
    for directory in [&common, &expected_admin_parent, &admin] {
        add_directory_ancestors(cmd, made_dirs, directory);
    }
    for entry in ["HEAD", "index", "commondir", "gitdir"] {
        let source = admin.join(entry);
        if source.exists() {
            add_pinned_read_only_bind(cmd, inherited_bind_fds, &source)?;
        }
    }
    for entry in ["HEAD", "objects", "refs", "packed-refs", "shallow"] {
        let source = common.join(entry);
        if source.exists() {
            add_pinned_read_only_bind(cmd, inherited_bind_fds, &source)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn add_pinned_writable_directory_bind(
    cmd: &mut Command,
    inherited_bind_fds: &mut Vec<OwnedFd>,
    source: &Path,
    destination: &Path,
) -> Result<(), String> {
    match fs::create_dir(source) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(format!(
                "Cannot create private Cargo target '{}': {error}",
                source.display()
            ));
        }
    }
    fs::set_permissions(source, fs::Permissions::from_mode(0o700)).map_err(|error| {
        format!(
            "Cannot secure private Cargo target '{}': {error}",
            source.display()
        )
    })?;
    let source_c = std::ffi::CString::new(source.as_os_str().as_bytes())
        .map_err(|_| format!("Cargo target path contains NUL: '{}'", source.display()))?;
    // SAFETY: source_c is NUL-terminated; O_NOFOLLOW and O_DIRECTORY reject
    // replacement with a symbolic link or non-directory cache entry.
    let opened = unsafe {
        libc::open(
            source_c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if opened < 0 {
        return Err(format!(
            "Cannot pin private Cargo target '{}': {}",
            source.display(),
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: open returned a fresh descriptor.
    let pinned = unsafe { OwnedFd::from_raw_fd(opened) };
    cmd.arg("--bind-fd")
        .arg(pinned.as_raw_fd().to_string())
        .arg(destination);
    inherited_bind_fds.push(pinned);
    Ok(())
}

#[cfg(target_os = "linux")]
fn add_pinned_read_only_bind(
    cmd: &mut Command,
    inherited_bind_fds: &mut Vec<OwnedFd>,
    source: &Path,
) -> Result<(), String> {
    let source_c = std::ffi::CString::new(source.as_os_str().as_bytes())
        .map_err(|_| format!("Git metadata path contains NUL: '{}'", source.display()))?;
    let opened = unsafe {
        libc::open(
            source_c.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if opened < 0 {
        return Err(format!(
            "Cannot pin Git metadata '{}': {}",
            source.display(),
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: open returned a fresh descriptor.
    let opened = unsafe { OwnedFd::from_raw_fd(opened) };
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(opened.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(format!(
            "Cannot inspect pinned Git metadata '{}': {}",
            source.display(),
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fstat initialized `stat` on success.
    let stat = unsafe { stat.assume_init() };
    let kind = stat.st_mode & libc::S_IFMT;
    if kind != libc::S_IFREG && kind != libc::S_IFDIR {
        return Err(format!(
            "Refusing non-regular, non-directory Git metadata '{}'",
            source.display()
        ));
    }
    if kind == libc::S_IFREG && stat.st_nlink > 1 {
        return Err(format!(
            "Refusing hardlinked Git metadata '{}'; another name may be outside the session capability",
            source.display()
        ));
    }
    let duplicated = unsafe { libc::fcntl(opened.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 200) };
    if duplicated < 0 {
        return Err(format!(
            "Cannot duplicate Git metadata handle '{}': {}",
            source.display(),
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fcntl returned a fresh owned descriptor.
    let pinned = unsafe { OwnedFd::from_raw_fd(duplicated) };
    cmd.arg("--ro-bind-fd")
        .arg(pinned.as_raw_fd().to_string())
        .arg(source);
    inherited_bind_fds.push(pinned);
    Ok(())
}

#[cfg(target_os = "linux")]
fn hide_control_path(cmd: &mut Command, path: &Path) {
    if path.is_dir() {
        cmd.arg("--tmpfs").arg(path);
    } else if path.exists() {
        cmd.arg("--ro-bind").arg("/dev/null").arg(path);
    }
}

#[cfg(target_os = "linux")]
fn sandbox_path(
    cwd: &Path,
    home: Option<&Path>,
    permit_project_path: bool,
    executable_search_path: &OsStr,
) -> String {
    let mut allowed = Vec::new();
    let cargo_bin = home.map(|path| path.join(".cargo/bin"));
    for entry in std::env::split_paths(executable_search_path) {
        let is_allowed = entry.starts_with("/usr")
            || entry.starts_with("/bin")
            || entry.starts_with("/sbin")
            || entry.starts_with("/nix/store")
            || (permit_project_path && entry.starts_with(cwd))
            || cargo_bin
                .as_ref()
                .is_some_and(|path| entry.starts_with(path));
        if is_allowed && !allowed.contains(&entry) {
            allowed.push(entry);
        }
    }
    if allowed.is_empty() {
        allowed.extend([
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ]);
    }
    std::env::join_paths(allowed)
        .unwrap_or_else(|_| std::ffi::OsString::from("/usr/local/bin:/usr/bin:/bin"))
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subprocess_profiles_compile_to_distinct_least_privilege_policies() {
        assert_eq!(
            SandboxProfile::Shell.policy(),
            SandboxProfilePolicy {
                workspace: WorkspaceMountPolicy::RunBound,
                environment: EnvironmentPolicy::RunGrants,
                permits_explicit_environment: false,
                permits_project_path: true,
                permits_child_processes: true,
            }
        );
        assert_eq!(
            SandboxProfile::DocumentParser.policy(),
            SandboxProfilePolicy {
                workspace: WorkspaceMountPolicy::ScratchOnly,
                environment: EnvironmentPolicy::Empty,
                permits_explicit_environment: false,
                permits_project_path: false,
                permits_child_processes: false,
            }
        );
        assert_eq!(
            SandboxProfile::LanguageServer.policy().workspace,
            WorkspaceMountPolicy::ProjectReadOnly
        );
        assert_eq!(
            SandboxProfile::McpHeaderHelper.policy().workspace,
            WorkspaceMountPolicy::ScratchOnly
        );
        for profile in [
            SandboxProfile::RepositoryHook,
            SandboxProfile::LanguageServer,
            SandboxProfile::StaticAnalyzer,
            SandboxProfile::QualityGate,
            SandboxProfile::DocumentParser,
            SandboxProfile::McpHeaderHelper,
            SandboxProfile::GitWorktree,
        ] {
            assert_ne!(
                profile.policy().environment,
                EnvironmentPolicy::RunGrants,
                "{profile:?} must not receive secret-bearing general run grants"
            );
        }
    }

    #[test]
    fn explicit_environment_is_profile_scoped_and_cannot_replace_sandbox_state() {
        let safe = [(
            OsString::from("GIT_CONFIG_GLOBAL"),
            OsString::from("/dev/null"),
        )];
        assert!(validate_explicit_environment(SandboxProfile::GitWorktree, &safe).is_ok());
        assert!(validate_explicit_environment(SandboxProfile::Shell, &safe).is_err());

        let loader = [(OsString::from("LD_PRELOAD"), OsString::from("attack.so"))];
        assert!(validate_explicit_environment(SandboxProfile::GitWorktree, &loader).is_err());
        let sandbox_owned = [(OsString::from("PATH"), OsString::from("/host/bin"))];
        assert!(
            validate_explicit_environment(SandboxProfile::McpHeaderHelper, &sandbox_owned).is_err()
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn profile_mounts_and_environment_match_the_compiled_policy() {
        let project = tempfile::tempdir().expect("profile project");
        std::fs::write(
            project.path().join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .expect("Cargo manifest fixture");
        let run =
            crate::tools::ToolRunContext::builder(crate::state::SessionId::new(), project.path())
                .read_only_roots(Vec::new())
                .read_write_roots(Vec::new())
                .environment_grants(HashMap::from([
                    ("CARGO_BUILD_JOBS".to_string(), "4".to_string()),
                    ("OPENAI_API_KEY".to_string(), "secret".to_string()),
                ]))
                .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
                .process(true)
                .network(false)
                .secrets(true)
                .build()
                .expect("profile run");

        let language_server = sandboxed_process_command(
            &run,
            SandboxProfile::LanguageServer,
            OsStr::new("/usr/bin/true"),
            &[],
            project.path(),
        )
        .expect("language server sandbox");
        let args = language_server
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args
            .windows(2)
            .any(|window| { window[0] == "--setenv" && window[1] == "CARGO_TARGET_DIR" }));
        assert!(args.windows(3).any(|window| {
            window[0] == "--ro-bind-fd" && window[2] == project.path().to_string_lossy()
        }));
        let env_names = language_server
            .get_envs()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(env_names.iter().any(|name| name == "CARGO_BUILD_JOBS"));
        assert!(!env_names.iter().any(|name| name == "OPENAI_API_KEY"));

        let parser = sandboxed_process_command(
            &run,
            SandboxProfile::DocumentParser,
            OsStr::new("/usr/bin/true"),
            &[],
            project.path(),
        )
        .expect("parser sandbox");
        let args = parser
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(!args
            .iter()
            .any(|arg| arg == &project.path().to_string_lossy()));
        assert!(args.windows(2).any(|window| {
            window[0] == "--chdir" && window[1] == run.private_temp_root().to_string_lossy()
        }));

        let shell = sandboxed_process_command(
            &run,
            SandboxProfile::Shell,
            OsStr::new("/usr/bin/true"),
            &[],
            project.path(),
        )
        .expect("shell sandbox");
        let args = shell
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args
            .windows(2)
            .any(|window| { window[0] == "--setenv" && window[1] == "CARGO_TARGET_DIR" }));
        assert!(args.windows(3).any(|window| {
            window[0] == "--bind-fd" && window[2] == project.path().join("target").to_string_lossy()
        }));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn parser_cannot_observe_project_and_read_only_profiles_cannot_modify_it() {
        let project = tempfile::tempdir().expect("runtime profile project");
        let sentinel = project.path().join("sentinel");
        std::fs::write(&sentinel, "original").expect("sentinel");
        let run =
            crate::tools::ToolRunContext::builder(crate::state::SessionId::new(), project.path())
                .read_only_roots(Vec::new())
                .read_write_roots(Vec::new())
                .environment_grants(HashMap::from([(
                    "OPENAI_API_KEY".to_string(),
                    "secret".to_string(),
                )]))
                .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
                .process(true)
                .network(false)
                .secrets(true)
                .build()
                .expect("runtime profile run");

        let probe = format!(
            "if test -e {}; then printf visible; else printf hidden; fi; printf ':%s' \"${{OPENAI_API_KEY-unset}}\"",
            shlex::try_quote(sentinel.to_str().expect("UTF-8 sentinel")).expect("quote sentinel")
        );
        let mut parser = sandboxed_process_command(
            &run,
            SandboxProfile::DocumentParser,
            OsStr::new("/bin/sh"),
            &[OsString::from("-c"), OsString::from(probe)],
            project.path(),
        )
        .expect("parser command");
        let output = parser.output().expect("run parser probe");
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout), "hidden:unset");

        let mut parser_child_probe = sandboxed_process_command(
            &run,
            SandboxProfile::DocumentParser,
            OsStr::new("/usr/bin/python3"),
            &[
                OsString::from("-c"),
                OsString::from(
                    "import os,sys\ntry:\n os.fork()\nexcept PermissionError:\n sys.exit(0)\nsys.exit(1)",
                ),
            ],
            project.path(),
        )
        .expect("parser child-process probe");
        assert!(
            parser_child_probe
                .status()
                .expect("run parser child-process probe")
                .success(),
            "document parser unexpectedly created a child process"
        );

        for profile in [
            SandboxProfile::LanguageServer,
            SandboxProfile::StaticAnalyzer,
            SandboxProfile::QualityGate,
        ] {
            let write = format!(
                "printf changed > {}",
                shlex::try_quote(sentinel.to_str().expect("UTF-8 sentinel"))
                    .expect("quote sentinel")
            );
            let mut child = sandboxed_process_command(
                &run,
                profile,
                OsStr::new("/bin/sh"),
                &[OsString::from("-c"), OsString::from(write)],
                project.path(),
            )
            .expect("read-only profile command");
            let output = child.output().expect("run read-only profile probe");
            assert!(!output.status.success(), "{profile:?} wrote the project");
            assert_eq!(
                std::fs::read_to_string(&sentinel).expect("sentinel"),
                "original",
                "{profile:?} changed the project"
            );
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_path_does_not_include_arbitrary_home_directories() {
        let cwd = Path::new("/home/user/project");
        let home = Path::new("/home/user");
        let path = sandbox_path(
            cwd,
            Some(home),
            true,
            OsStr::new("/home/user/private/bin:/usr/bin"),
        );
        assert!(!path
            .split(':')
            .any(|entry| entry == "/home/user/private/bin"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_path_uses_only_the_run_bound_search_path() {
        let path = sandbox_path(
            Path::new("/workspace/project"),
            None,
            true,
            OsStr::new("/outside/bin:/workspace/project/bin:/usr/bin"),
        );
        let entries: Vec<&str> = path.split(':').collect();
        assert_eq!(entries, ["/workspace/project/bin", "/usr/bin"]);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn broad_system_roots_are_never_writable_project_mounts() {
        for root in ["/", "/etc", "/home", "/mnt", "/tmp", "/usr", "/var"] {
            assert!(is_unsafe_broad_project_root(Path::new(root)), "{root}");
        }
        for project in ["/app", "/tmp/project", "/mnt/c/project", "/var/src/project"] {
            assert!(
                !is_unsafe_broad_project_root(Path::new(project)),
                "{project}"
            );
        }
    }

    #[test]
    fn mode_parser_only_accepts_explicit_values() {
        for enabled in ["", "on", "1", "true", "required", "ON"] {
            assert_eq!(sandbox_explicitly_disabled_value(enabled), Ok(false));
        }
        for disabled in ["off", "0", "false", "disabled", "OFF"] {
            assert_eq!(sandbox_explicitly_disabled_value(disabled), Ok(true));
        }
        for invalid in ["maybe", "auto-ish", "please"] {
            assert!(sandbox_explicitly_disabled_value(invalid).is_err());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn health_probe_failures_are_classified() {
        assert_eq!(
            classify_bwrap_probe_failure("No permissions to create new user namespace"),
            "user namespaces disabled or restricted"
        );
        assert_eq!(
            classify_bwrap_probe_failure("Creating new namespace failed: Operation not permitted"),
            "container or kernel namespace policy denied the probe"
        );
        assert_eq!(
            classify_bwrap_probe_failure("mount source failed"),
            "required mount behavior unavailable"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn network_namespace_fallback_only_accepts_loopback_setup_failures() {
        assert!(is_network_namespace_probe_failure(
            "bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted"
        ));
        assert!(!is_network_namespace_probe_failure(
            "Creating new namespace failed: Operation not permitted"
        ));
        assert!(!is_network_namespace_probe_failure(
            "bwrap: Can't mount proc on /newroot/proc: Operation not permitted"
        ));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn seccomp_network_fallback_probe_is_usable() {
        let backend = BWRAP_BACKEND
            .as_ref()
            .expect("Bubblewrap backend must be usable");
        probe_bwrap(&backend.path, true)
            .expect("shared network namespace must remain blocked by the seccomp filter");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn capability_roots_are_handed_to_bubblewrap_by_descriptor() {
        let security = crate::tools::security::test_run_context();
        let command = sandboxed_process_command(
            security,
            SandboxProfile::Shell,
            std::ffi::OsStr::new("/usr/bin/true"),
            &[],
            security.working_directory(),
        )
        .expect("sandbox command");
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(args.iter().any(|arg| arg == "--bind-fd"));
        assert!(!args.windows(2).any(|pair| {
            pair[0] == "--bind" && pair[1] == security.project_root().to_string_lossy()
        }));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linked_worktree_metadata_is_validated_and_minimized() {
        let fixture = tempfile::tempdir().expect("linked-worktree fixture");
        let common = fixture.path().join("main.git");
        let worktree = fixture.path().join("worktree");
        let admin = common.join("worktrees").join("agent");
        std::fs::create_dir_all(common.join("objects")).expect("objects");
        std::fs::create_dir_all(common.join("refs")).expect("refs");
        std::fs::create_dir_all(&admin).expect("admin");
        std::fs::create_dir_all(&worktree).expect("worktree");
        std::fs::write(common.join("HEAD"), "ref: refs/heads/main\n").expect("common HEAD");
        std::fs::write(common.join("config"), "credential.helper=escape\n").expect("config");
        std::fs::create_dir_all(common.join("hooks")).expect("hooks");
        std::fs::write(admin.join("HEAD"), "ref: refs/heads/agent\n").expect("admin HEAD");
        std::fs::write(admin.join("index"), "").expect("index");
        std::fs::write(admin.join("commondir"), "../..\n").expect("commondir");
        std::fs::write(
            admin.join("gitdir"),
            format!("{}\n", worktree.join(".git").display()),
        )
        .expect("backlink");
        std::fs::write(
            worktree.join(".git"),
            format!("gitdir: {}\n", admin.display()),
        )
        .expect("indirection");

        let mut command = Command::new("/usr/bin/true");
        let mut made_dirs = HashSet::new();
        let mut inherited_bind_fds = Vec::new();
        protect_repository_metadata(
            &mut command,
            &mut made_dirs,
            &mut inherited_bind_fds,
            &worktree,
        )
        .expect("valid linked worktree");
        let args: Vec<_> = command.get_args().map(PathBuf::from).collect();
        assert!(args.contains(&common.join("objects")));
        assert!(args.contains(&common.join("refs")));
        assert!(!args.contains(&common.join("config")));
        assert!(!args.contains(&common.join("hooks")));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn forged_linked_worktree_indirection_is_rejected() {
        let fixture = tempfile::tempdir().expect("forged worktree fixture");
        let worktree = fixture.path().join("worktree");
        let arbitrary = fixture.path().join("arbitrary-host-directory");
        std::fs::create_dir_all(&worktree).expect("worktree");
        std::fs::create_dir_all(&arbitrary).expect("arbitrary");
        std::fs::write(
            worktree.join(".git"),
            format!("gitdir: {}\n", arbitrary.display()),
        )
        .expect("forged indirection");

        let mut command = Command::new("/usr/bin/true");
        let mut made_dirs = HashSet::new();
        let mut inherited_bind_fds = Vec::new();
        let error = protect_repository_metadata(
            &mut command,
            &mut made_dirs,
            &mut inherited_bind_fds,
            &worktree,
        )
        .expect_err("arbitrary metadata target must be rejected");
        assert!(error.contains("commondir") || error.contains("owned"));
    }
}
