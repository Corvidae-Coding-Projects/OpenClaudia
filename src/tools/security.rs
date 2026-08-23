//! Explicit immutable capabilities for one canonical agent run.
//!
//! The host composition root constructs one [`ToolRunContext`] from explicit
//! session and workspace inputs, then passes the same `Arc` through every tool
//! and helper call. This module deliberately has no process-global registry,
//! thread-local lookup, default session, or current-directory fallback.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use thiserror::Error;

use crate::runtime::{
    Actor, ActorId, ActorRole, BudgetGeneration, BudgetId, BudgetLimits, CapabilityBinding,
    CapabilityGeneration, CapabilityKind, ContentDigest, ProviderContinuation, ProviderId,
    RunBudget, RunContext, RunDescriptor, RunDescriptorParts, RunId, StateGeneration,
    StateSnapshot, TracingTraceSink, WorkspaceBinding, WorkspaceGeneration,
};
use crate::state::SessionId;

static NEXT_CAPABILITY_GENERATION: AtomicU64 = AtomicU64::new(1);

fn runtime_mode_name(mode: &crate::modes::RuntimeMode) -> String {
    match mode {
        crate::modes::RuntimeMode::Behavioral(behavior) => behavior.display_name(),
        crate::modes::RuntimeMode::Plan => "plan".to_string(),
        crate::modes::RuntimeMode::Initializer => "initializer".to_string(),
        crate::modes::RuntimeMode::Coordinator => "coordinator".to_string(),
    }
}

/// Workspace mutation authority attached to a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceAccess {
    ReadOnly,
    ReadWrite,
}

/// Concrete host resource required by a tool/helper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolResource {
    WorkspaceRead,
    WorkspaceWrite,
    Process,
    Network,
    Secrets,
    /// Host-owned, workspace-bound technical-memory service.
    Memory,
    /// Run-owned Model Context Protocol manager and its registered servers.
    Mcp,
}

/// Typed fail-closed resource error.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ToolCapabilityError {
    #[error("run capability {resource:?} is unavailable for run {run_id} generation {generation}")]
    Unavailable {
        resource: ToolResource,
        run_id: RunId,
        generation: CapabilityGeneration,
    },
    #[error("run capability binding does not match its canonical descriptor: {detail}")]
    BindingMismatch { detail: String },
}

/// Failure to install a new run-scoped behavioral capability generation.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum RuntimeModeTransitionError {
    #[error("{detail}")]
    InvalidProfile { detail: String },
    #[error("background-effect lifecycle is unavailable: {detail}")]
    LifecycleUnavailable { detail: String },
    #[error(
        "Cannot enter runtime mode '{requested_mode}' while this run owns {shell_count} active background shell(s) and {agent_count} active background agent(s). Stop them with kill_shell/task_stop, then retry. shell_ids={shell_ids:?}, agent_ids={agent_ids:?}"
    )]
    InFlightBackgroundEffects {
        requested_mode: String,
        shell_count: usize,
        agent_count: usize,
        shell_ids: Vec<String>,
        agent_ids: Vec<String>,
    },
}

/// Holds the run lifecycle boundary until one background effect is registered.
pub(crate) struct BackgroundEffectRegistration<'a> {
    _guard: MutexGuard<'a, ()>,
}

/// Failure to resolve an executable through one run's immutable process
/// capability.
#[derive(Debug, Error)]
pub enum ToolExecutableError {
    #[error(transparent)]
    Capability(#[from] ToolCapabilityError),
    #[error("executable '{executable}' could not be resolved on the run-bound PATH: {source}")]
    Resolve {
        executable: String,
        #[source]
        source: which::Error,
    },
}

/// Builder for a host-created [`ToolRunContext`].
enum EnvironmentGrantSource {
    Raw(HashMap<String, String>),
    Protected(crate::secrets::EnvironmentGrants),
}

pub struct ToolRunContextBuilder {
    session_id: SessionId,
    project_root: PathBuf,
    working_directory: PathBuf,
    read_only_roots: Option<Vec<PathBuf>>,
    read_write_roots: Option<Vec<PathBuf>>,
    project_secret_masks: Option<Vec<PathBuf>>,
    environment_grants: Option<EnvironmentGrantSource>,
    mcp_environment_grants: Option<EnvironmentGrantSource>,
    executable_search_path: Option<OsString>,
    host_home: Option<PathBuf>,
    inherit_host_startup_grants: bool,
    workspace_access: Option<WorkspaceAccess>,
    process: Option<bool>,
    network: Option<bool>,
    secrets: Option<bool>,
    process_owner: String,
    actor_role: ActorRole,
    provider: String,
    budget_limits: Option<BudgetLimits>,
    parent_budget: Option<crate::runtime::RunBudgetAuthority>,
    runtime_mode: crate::modes::RuntimeMode,
    behavior_scope_targets: crate::modes::BehaviorScopeTargets,
    background_job_storage: BackgroundJobStorage,
}

#[derive(Clone, Copy, Debug)]
enum BackgroundJobStorage {
    Durable,
    Ephemeral,
}

impl ToolRunContextBuilder {
    fn new(session_id: SessionId, project_root: PathBuf) -> Self {
        let process_owner = session_id.as_str().to_string();
        Self {
            session_id,
            working_directory: project_root.clone(),
            project_root,
            read_only_roots: None,
            read_write_roots: None,
            project_secret_masks: None,
            environment_grants: None,
            mcp_environment_grants: None,
            executable_search_path: None,
            host_home: None,
            inherit_host_startup_grants: false,
            workspace_access: None,
            process: None,
            network: None,
            secrets: None,
            process_owner,
            actor_role: ActorRole::Frontend,
            provider: "local".to_string(),
            budget_limits: None,
            parent_budget: None,
            runtime_mode: crate::modes::RuntimeMode::default(),
            behavior_scope_targets: crate::modes::BehaviorScopeTargets::workspace_root(),
            background_job_storage: if cfg!(test) {
                BackgroundJobStorage::Ephemeral
            } else {
                BackgroundJobStorage::Durable
            },
        }
    }

    #[must_use]
    pub fn working_directory(mut self, path: impl Into<PathBuf>) -> Self {
        self.working_directory = path.into();
        self
    }

    #[must_use]
    pub const fn workspace_access(mut self, access: WorkspaceAccess) -> Self {
        self.workspace_access = Some(access);
        self
    }

    /// Explicitly opt this top-level run into operator-provided startup grants.
    ///
    /// Without this call, callers must supply both root lists and the exact
    /// environment map. Derived runs should always do that so they can only
    /// inherit authority from their parent generation, never rediscover it
    /// from mutable process state.
    #[must_use]
    pub const fn host_startup_grants(mut self) -> Self {
        self.inherit_host_startup_grants = true;
        self
    }

    #[must_use]
    pub fn read_only_roots(mut self, roots: Vec<PathBuf>) -> Self {
        self.read_only_roots = Some(roots);
        self
    }

    #[must_use]
    pub fn read_write_roots(mut self, roots: Vec<PathBuf>) -> Self {
        self.read_write_roots = Some(roots);
        self
    }

    /// Supply project-relative subtrees that stay masked from this run.
    ///
    /// Derived runs should pass the parent's mask list so a mutable host
    /// environment cannot silently change filesystem authority between
    /// generations. Omitting this field uses the built-in control-directory
    /// masks; top-level host startup grants may add operator-configured masks.
    #[must_use]
    pub fn project_secret_masks(mut self, masks: Vec<PathBuf>) -> Self {
        self.project_secret_masks = Some(masks);
        self
    }

    /// Supply the exact environment values visible to this run's processes.
    ///
    /// Derived runs must pass their parent's map so a later process-environment
    /// mutation cannot widen or replace authority. Top-level composition roots
    /// may instead opt into [`Self::host_startup_grants`].
    #[must_use]
    pub fn environment_grants(mut self, grants: HashMap<String, String>) -> Self {
        self.environment_grants = Some(EnvironmentGrantSource::Raw(grants));
        self
    }

    /// Inherit an already-protected environment capability without copying
    /// any secret bytes.
    #[must_use]
    pub(crate) fn protected_environment_grants(
        mut self,
        grants: crate::secrets::EnvironmentGrants,
    ) -> Self {
        self.environment_grants = Some(EnvironmentGrantSource::Protected(grants));
        self
    }

    /// Supply the exact host values that trusted MCP configuration may place
    /// in a child server environment.
    ///
    /// This is separate from ordinary agent environment grants: an MCP plugin
    /// may need a credential that must never become visible to Bash or hook
    /// processes. Top-level composition roots snapshot
    /// `OPENCLAUDIA_MCP_ENV_GRANTS`; derived MCP runs copy this map from their
    /// parent instead of rereading mutable process state.
    #[must_use]
    pub fn mcp_environment_grants(mut self, grants: HashMap<String, String>) -> Self {
        self.mcp_environment_grants = Some(EnvironmentGrantSource::Raw(grants));
        self
    }

    /// Inherit an already-protected MCP-only environment capability.
    #[must_use]
    pub(crate) fn protected_mcp_environment_grants(
        mut self,
        grants: crate::secrets::EnvironmentGrants,
    ) -> Self {
        self.mcp_environment_grants = Some(EnvironmentGrantSource::Protected(grants));
        self
    }

    /// Supply the executable search path captured by the parent run.
    ///
    /// Top-level composition roots normally obtain this once through
    /// [`Self::host_startup_grants`]. Derived runs must copy the parent's value
    /// instead of consulting a mutable process `PATH` during tool execution.
    #[must_use]
    pub fn executable_search_path(mut self, path: impl Into<OsString>) -> Self {
        self.executable_search_path = Some(path.into());
        self
    }

    /// Supply the host-home snapshot associated with a captured toolchain.
    ///
    /// Linux sandbox construction uses this exact path only to expose
    /// conventional Cargo and Rustup trees read-only. Derived runs must copy
    /// their parent's value; top-level composition roots normally capture it
    /// through [`Self::host_startup_grants`].
    #[must_use]
    pub fn host_home(mut self, path: Option<PathBuf>) -> Self {
        self.host_home = path;
        self
    }

    #[must_use]
    pub const fn process(mut self, available: bool) -> Self {
        self.process = Some(available);
        self
    }

    #[must_use]
    pub const fn network(mut self, available: bool) -> Self {
        self.network = Some(available);
        self
    }

    #[must_use]
    pub const fn secrets(mut self, available: bool) -> Self {
        self.secrets = Some(available);
        self
    }

    /// Set the logical process owner shown to the model and lifecycle APIs.
    ///
    /// Exact process access is still keyed by the unforgeable run id. This
    /// label preserves stable subagent/session UX without granting authority.
    #[must_use]
    pub fn process_owner(mut self, owner: impl Into<String>) -> Self {
        self.process_owner = owner.into();
        self
    }

    #[must_use]
    pub const fn actor_role(mut self, role: ActorRole) -> Self {
        self.actor_role = role;
        self
    }

    #[must_use]
    pub fn provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = provider.into();
        self
    }

    /// Bind explicit immutable limits to this run generation.
    #[must_use]
    pub const fn budget_limits(mut self, limits: BudgetLimits) -> Self {
        self.budget_limits = Some(limits);
        self
    }

    /// Attach a derived run to its parent's live hierarchical budget.
    #[must_use]
    pub(crate) fn parent_budget(mut self, parent: crate::runtime::RunBudgetAuthority) -> Self {
        self.parent_budget = Some(parent);
        self
    }

    /// Bind the initial host-enforced behavioral capability profile.
    #[must_use]
    pub fn runtime_mode(mut self, mode: crate::modes::RuntimeMode) -> Self {
        self.runtime_mode = mode;
        self
    }

    /// Bind persisted user/task-approved behavioral targets to this run.
    #[must_use]
    pub fn behavior_scope_targets(mut self, targets: crate::modes::BehaviorScopeTargets) -> Self {
        self.behavior_scope_targets = targets;
        self
    }

    /// Keep durable background-job artifacts inside this run's private scratch
    /// root. This is intended for hermetic tests and embedded ephemeral runs;
    /// normal frontends retain the default user-state-backed restart record.
    #[must_use]
    pub const fn ephemeral_background_jobs(mut self) -> Self {
        self.background_job_storage = BackgroundJobStorage::Ephemeral;
        self
    }

    const fn background_job_storage(mut self, storage: BackgroundJobStorage) -> Self {
        self.background_job_storage = storage;
        self
    }

    /// Construct and validate the complete immutable run capability.
    ///
    /// # Errors
    ///
    /// Returns an error when roots cannot be pinned, host capability inputs
    /// are invalid, or the concrete capability and descriptor generations do
    /// not agree.
    pub fn build(self) -> Result<Arc<ToolRunContext>, String> {
        ToolRunContext::new(self).map(Arc::new)
    }
}

/// Filesystem capabilities pinned to one session.
pub struct ToolRunContext {
    runtime: Arc<RunContext>,
    generation: CapabilityGeneration,
    runtime_mode: crate::modes::RuntimeModeAuthority,
    background_effect_lifecycle: Mutex<()>,
    tool_catalog: super::catalog::RunToolCatalog,
    project_root: PathBuf,
    working_directory: PathBuf,
    private_temp: PrivateTempDir,
    background_job_storage: BackgroundJobStorage,
    read_only_roots: Vec<PathBuf>,
    read_write_roots: Vec<PathBuf>,
    denied_paths: Vec<PathBuf>,
    agent_plan_file: PathBuf,
    project_secret_masks: Vec<PathBuf>,
    environment_grants: crate::secrets::EnvironmentGrants,
    mcp_environment_grants: crate::secrets::EnvironmentGrants,
    executable_search_path: OsString,
    host_home: Option<PathBuf>,
    network_policy: AgentNetworkPolicy,
    process_available: bool,
    network_available: bool,
    secrets_available: bool,
    process_owner: String,
    #[cfg(unix)]
    root_handles: Vec<CapabilityRootHandle>,
}

impl std::fmt::Debug for ToolRunContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ToolRunContext")
            .field("run_id", &self.run_id())
            .field("generation", &self.generation)
            .field("runtime_mode", &self.runtime_mode.snapshot())
            .field("session_id", &self.session_id())
            .field("project_root", &self.project_root)
            .field("working_directory", &self.working_directory)
            .field("private_temp", &self.private_temp.path())
            .field("read_only_root_count", &self.read_only_roots.len())
            .field("read_write_root_count", &self.read_write_roots.len())
            .field(
                "project_secret_mask_count",
                &self.project_secret_masks.len(),
            )
            .field("agent_plan_file", &self.agent_plan_file)
            .field("environment_grant_count", &self.environment_grants.len())
            .field(
                "mcp_environment_grant_count",
                &self.mcp_environment_grants.len(),
            )
            .field("executable_search_path", &"<redacted>")
            .field("host_home_bound", &self.host_home.is_some())
            .field("process_available", &self.process_available)
            .field("network_available", &self.network_available)
            .field("secrets_available", &self.secrets_available)
            .field("process_owner", &self.process_owner)
            .finish_non_exhaustive()
    }
}

/// Compatibility name for leaf filesystem/sandbox code. The value is the
/// complete explicit run context, not a separately discoverable security
/// singleton.
pub type ToolSecurityContext = ToolRunContext;

/// Network authority carried by an agent session.
///
/// Only the fail-closed default is currently implemented; unsupported grants
/// are rejected during context creation rather than silently restoring the
/// host namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentNetworkPolicy {
    Denied,
}

#[cfg(unix)]
#[derive(Debug)]
struct CapabilityRootHandle {
    path: PathBuf,
    writable: bool,
    directory: std::fs::File,
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxBindRoot {
    pub(crate) path: PathBuf,
    pub(crate) writable: bool,
    pub(crate) directory: std::os::fd::OwnedFd,
}

impl ToolRunContext {
    /// Begin explicit run-capability construction at a host composition root.
    #[must_use]
    pub fn builder(
        session_id: SessionId,
        project_root: impl Into<PathBuf>,
    ) -> ToolRunContextBuilder {
        ToolRunContextBuilder::new(session_id, project_root.into())
    }

    #[allow(clippy::too_many_lines)] // Capability validation and descriptor binding are one transaction.
    fn new(builder: ToolRunContextBuilder) -> Result<Self, String> {
        let ToolRunContextBuilder {
            session_id,
            project_root,
            working_directory,
            read_only_roots,
            read_write_roots,
            project_secret_masks,
            environment_grants,
            mcp_environment_grants,
            executable_search_path,
            host_home,
            inherit_host_startup_grants,
            workspace_access,
            process,
            network,
            secrets,
            process_owner,
            actor_role,
            provider,
            budget_limits,
            parent_budget,
            runtime_mode,
            behavior_scope_targets,
            background_job_storage,
        } = builder;
        let workspace_access = workspace_access.ok_or_else(|| {
            "Run construction requires an explicit workspace access capability".to_string()
        })?;
        let process = process.ok_or_else(|| {
            "Run construction requires an explicit process capability decision".to_string()
        })?;
        let network = network.ok_or_else(|| {
            "Run construction requires an explicit network capability decision".to_string()
        })?;
        let secrets = secrets.ok_or_else(|| {
            "Run construction requires an explicit secret capability decision".to_string()
        })?;
        let read_only_roots = match read_only_roots {
            Some(roots) => roots,
            None if inherit_host_startup_grants => {
                startup_root_grants("OPENCLAUDIA_AGENT_READ_ONLY_ROOTS")?
            }
            None => {
                return Err(
                    "Run construction requires explicit read-only roots or host startup grants"
                        .to_string(),
                )
            }
        };
        let read_write_roots =
            match read_write_roots {
                Some(roots) => roots,
                None if inherit_host_startup_grants => {
                    startup_root_grants("OPENCLAUDIA_AGENT_READ_WRITE_ROOTS")?
                }
                None => return Err(
                    "Run construction requires explicit read-write roots or host startup grants"
                        .to_string(),
                ),
            };
        let project_root = canonical_directory(&project_root, "project root")?;
        let working_directory = canonical_directory(&working_directory, "working directory")?;
        let runtime_mode = crate::modes::RuntimeModeAuthority::new_for_run(
            runtime_mode,
            behavior_scope_targets,
            &project_root,
        )?;
        let mut canonical_read_only = canonical_roots(&read_only_roots, "read-only")?;
        let mut canonical_read_write = canonical_roots(&read_write_roots, "read-write")?;
        if !path_is_within(&working_directory, &project_root)
            && !canonical_read_only
                .iter()
                .chain(&canonical_read_write)
                .any(|root| path_is_within(&working_directory, root))
        {
            return Err(format!(
                "Working directory '{}' is outside the session project root '{}'",
                working_directory.display(),
                project_root.display()
            ));
        }
        if is_unsafe_broad_root(&project_root) {
            return Err(format!(
                "Refusing to create an agent security context for broad project root '{}'",
                project_root.display()
            ));
        }
        if process_owner.is_empty()
            || process_owner.len() > 128
            || !process_owner
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(
                "Process owner must be 1-128 ASCII letters, digits, '-' or '_'".to_string(),
            );
        }
        match workspace_access {
            WorkspaceAccess::ReadOnly => {
                if !canonical_read_write.is_empty() {
                    return Err(
                        "A read-only workspace capability cannot include writable roots"
                            .to_string(),
                    );
                }
                if !canonical_read_only.contains(&project_root) {
                    canonical_read_only.push(project_root.clone());
                }
            }
            WorkspaceAccess::ReadWrite => {
                if !canonical_read_write.contains(&project_root) {
                    canonical_read_write.push(project_root.clone());
                }
            }
        }
        let private_temp = PrivateTempDir::create()?;
        canonical_read_write.push(private_temp.path().to_path_buf());
        let project_secret_masks = match project_secret_masks {
            Some(masks) => validate_project_secret_masks(masks)?,
            None if inherit_host_startup_grants => startup_project_secret_masks()?,
            None => default_project_secret_masks(),
        };
        let denied_paths = project_secret_masks
            .iter()
            .map(|mask| project_root.join(mask))
            .collect::<Vec<_>>();
        let agent_plan_file = project_plan_file(&project_root, session_id.as_str());
        let environment_grants =
            match environment_grants {
                Some(EnvironmentGrantSource::Raw(grants)) => {
                    protect_environment_grants(validate_environment_grants(grants)?)?
                }
                Some(EnvironmentGrantSource::Protected(grants)) => {
                    for name in grants.keys() {
                        validate_environment_grant_name(name)?;
                    }
                    grants
                }
                None if inherit_host_startup_grants => {
                    protect_environment_grants(startup_environment_grants()?)?
                }
                None => return Err(
                    "Run construction requires explicit environment grants or host startup grants"
                        .to_string(),
                ),
            };
        let mcp_environment_grants = match mcp_environment_grants {
            Some(EnvironmentGrantSource::Raw(grants)) => {
                protect_environment_grants(validate_mcp_environment_grants(grants)?)?
            }
            Some(EnvironmentGrantSource::Protected(grants)) => {
                for name in grants.keys() {
                    validate_mcp_environment_grant_name(name)?;
                }
                grants
            }
            None if inherit_host_startup_grants => {
                protect_environment_grants(startup_mcp_environment_grants()?)?
            }
            None => crate::secrets::EnvironmentGrants::new(),
        };
        let executable_search_path = match executable_search_path {
            Some(path) => path,
            None if inherit_host_startup_grants => {
                std::env::var_os("PATH").unwrap_or_else(default_executable_search_path)
            }
            None => default_executable_search_path(),
        };
        let host_home = match host_home {
            Some(path) => Some(canonical_directory(&path, "host home")?),
            None if inherit_host_startup_grants => {
                dirs::home_dir().and_then(|path| path.canonicalize().ok())
            }
            None => None,
        };
        if !secrets {
            if let Some(name) = environment_grants
                .keys()
                .chain(mcp_environment_grants.keys())
                .find(|name| super::is_sensitive_env(name))
            {
                return Err(format!(
                    "Environment grant '{name}' requires an explicit secret capability"
                ));
            }
        }
        let network_policy = if inherit_host_startup_grants {
            startup_network_policy()?
        } else {
            AgentNetworkPolicy::Denied
        };
        #[cfg(unix)]
        let root_handles = open_capability_roots(&canonical_read_only, &canonical_read_write)?;

        let generation = next_capability_generation()?;
        let workspace_generation = WorkspaceGeneration::new(generation.get())
            .ok_or_else(|| "workspace generation must be non-zero".to_string())?;
        let run_id = RunId::new();
        let mut grants = BTreeSet::from([
            CapabilityKind::ContextAssembly,
            CapabilityKind::Provider,
            CapabilityKind::WorkspaceRead,
            CapabilityKind::Hooks,
            CapabilityKind::Memory,
            CapabilityKind::Mcp,
            CapabilityKind::Trace,
        ]);
        if workspace_access == WorkspaceAccess::ReadWrite {
            grants.insert(CapabilityKind::WorkspaceWrite);
        }
        if process {
            grants.insert(CapabilityKind::Process);
        }
        if network {
            grants.insert(CapabilityKind::Network);
        }
        if secrets {
            grants.insert(CapabilityKind::Secrets);
        }
        let manifest_digest = capability_manifest_digest(
            run_id,
            generation,
            &project_root,
            &working_directory,
            private_temp.path(),
            &canonical_read_only,
            &canonical_read_write,
            &denied_paths,
            &agent_plan_file,
            &environment_grants,
            &mcp_environment_grants,
            &executable_search_path,
            host_home.as_deref(),
            network_policy,
            &grants,
            &process_owner,
        );
        let cancellation = crate::runtime::CancellationTree::new();
        let descriptor = RunDescriptor::new(RunDescriptorParts {
            run_id,
            session_id,
            actor: Actor {
                id: ActorId::new(),
                role: actor_role,
            },
            workspace: WorkspaceBinding::new(
                project_root.clone(),
                workspace_generation,
                ContentDigest::sha256(project_root.as_os_str().as_encoded_bytes()),
            )
            .map_err(|error| error.to_string())?,
            capabilities: CapabilityBinding {
                generation,
                manifest_digest,
                grants,
            },
            budget: run_budget(generation, budget_limits.unwrap_or_default())?,
            provider_continuation: ProviderContinuation::Fresh {
                provider: ProviderId::new(provider).map_err(|error| error.to_string())?,
            },
            cancellation_root: cancellation.root_id(),
            initial_state: StateSnapshot {
                generation: StateGeneration::new(1)
                    .ok_or_else(|| "initial state generation must be non-zero".to_string())?,
                digest: ContentDigest::sha256(b"tool-run-initial-state"),
            },
        })
        .map_err(|error| error.to_string())?;
        let runtime = Arc::new(if let Some(parent_budget) = parent_budget.as_ref() {
            RunContext::new_child(
                descriptor,
                cancellation.root(),
                Arc::new(TracingTraceSink),
                parent_budget,
            )?
        } else {
            RunContext::new(descriptor, cancellation.root(), Arc::new(TracingTraceSink))
                .map_err(|error| error.to_string())?
        });

        let context = Self {
            runtime,
            generation,
            runtime_mode,
            background_effect_lifecycle: Mutex::new(()),
            tool_catalog: super::catalog::RunToolCatalog::default(),
            project_root,
            working_directory,
            private_temp,
            background_job_storage,
            read_only_roots: canonical_read_only,
            read_write_roots: canonical_read_write,
            denied_paths,
            agent_plan_file,
            project_secret_masks,
            environment_grants,
            mcp_environment_grants,
            executable_search_path,
            host_home,
            network_policy,
            process_available: process,
            network_available: network,
            secrets_available: secrets,
            process_owner,
            #[cfg(unix)]
            root_handles,
        };
        context
            .validate_binding()
            .map_err(|error| error.to_string())?;
        Ok(context)
    }

    /// Canonical runtime identity paired with these concrete resources.
    #[must_use]
    pub const fn runtime(&self) -> &Arc<RunContext> {
        &self.runtime
    }

    /// Atomic hierarchical budget authority carried by this run.
    #[must_use]
    pub fn budget(&self) -> &crate::runtime::RunBudgetAuthority {
        self.runtime.budget()
    }

    /// Stable identity of this exact run generation.
    #[must_use]
    pub fn run_id(&self) -> RunId {
        self.runtime.descriptor().run_id
    }

    /// Capability-manifest generation bound to descriptors and scratch space.
    #[must_use]
    pub const fn generation(&self) -> CapabilityGeneration {
        self.generation
    }

    /// Progressive tool-catalog state owned by this exact run generation.
    ///
    /// Catalog selection is mutable runtime state, but it cannot grant host
    /// authority: dispatch still revalidates the immutable capability binding,
    /// effect policy, approval, and guardrails for every invocation.
    #[must_use]
    pub const fn tool_catalog(&self) -> &super::catalog::RunToolCatalog {
        &self.tool_catalog
    }

    /// Current immutable mode capability generation.
    #[must_use]
    pub fn runtime_mode(&self) -> crate::modes::RuntimeModeSnapshot {
        self.runtime_mode.snapshot()
    }

    /// Atomically validate and install a new mode capability generation.
    ///
    /// # Errors
    ///
    /// Returns an error for a conflicting mode or exhausted generation.
    pub fn transition_runtime_mode(
        &self,
        mode: crate::modes::RuntimeMode,
    ) -> Result<crate::modes::RuntimeModeSnapshot, String> {
        self.try_transition_runtime_mode(mode)
            .map_err(|error| error.to_string())
    }

    /// Atomically validate and install a mode, preserving typed refusal data.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the profile is invalid, lifecycle state is
    /// unavailable, or this run still owns effects that can mutate after a
    /// restrictive generation would be published.
    pub fn try_transition_runtime_mode(
        &self,
        mode: crate::modes::RuntimeMode,
    ) -> Result<crate::modes::RuntimeModeSnapshot, RuntimeModeTransitionError> {
        let targets = self.runtime_mode.snapshot().scope_targets;
        self.try_transition_runtime_mode_scoped(mode, targets)
    }

    /// Atomically install a mode and its exact approved target set.
    ///
    /// # Errors
    ///
    /// Returns an error before mutation when the target set cannot be bound to
    /// this run's project or the requested mode is ambiguous/conflicting.
    pub fn transition_runtime_mode_scoped(
        &self,
        mode: crate::modes::RuntimeMode,
        targets: crate::modes::BehaviorScopeTargets,
    ) -> Result<crate::modes::RuntimeModeSnapshot, String> {
        self.try_transition_runtime_mode_scoped(mode, targets)
            .map_err(|error| error.to_string())
    }

    /// Atomically install a scoped mode while preserving typed refusal data.
    ///
    /// Restrictive transitions do not implicitly destroy user work. They fail
    /// before publication until the exact run's active shells and workers have
    /// been explicitly stopped or have completed.
    ///
    /// # Errors
    ///
    /// Returns a typed error before mutation when validation or the restrictive
    /// transition precondition fails.
    pub fn try_transition_runtime_mode_scoped(
        &self,
        mode: crate::modes::RuntimeMode,
        targets: crate::modes::BehaviorScopeTargets,
    ) -> Result<crate::modes::RuntimeModeSnapshot, RuntimeModeTransitionError> {
        let _lifecycle = self.background_effect_lifecycle.lock().map_err(|error| {
            RuntimeModeTransitionError::LifecycleUnavailable {
                detail: error.to_string(),
            }
        })?;
        let class = self
            .runtime_mode
            .validate_scoped_transition(&mode, &targets)
            .map_err(|detail| RuntimeModeTransitionError::InvalidProfile { detail })?;
        if matches!(
            class,
            crate::modes::RuntimeModeClass::Plan | crate::modes::RuntimeModeClass::ReadOnly
        ) {
            let shell_ids = crate::tools::BACKGROUND_SHELLS.active_ids_for_run(self);
            let agent_ids = crate::subagent::BACKGROUND_AGENTS
                .active_ids_for_run(self)
                .map_err(|detail| RuntimeModeTransitionError::LifecycleUnavailable { detail })?;
            if !shell_ids.is_empty() || !agent_ids.is_empty() {
                return Err(RuntimeModeTransitionError::InFlightBackgroundEffects {
                    requested_mode: runtime_mode_name(&mode),
                    shell_count: shell_ids.len(),
                    agent_count: agent_ids.len(),
                    shell_ids,
                    agent_ids,
                });
            }
        }
        self.runtime_mode
            .transition_scoped(mode, targets)
            .map_err(|detail| RuntimeModeTransitionError::InvalidProfile { detail })
    }

    /// Serialize final background registration with restrictive transitions.
    ///
    /// The mode is rechecked after taking the lifecycle gate, closing the race
    /// between canonical dispatch admission and process/worker registration.
    pub(crate) fn begin_background_effect_registration(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
    ) -> Result<BackgroundEffectRegistration<'_>, String> {
        let guard = self
            .background_effect_lifecycle
            .lock()
            .map_err(|error| format!("background-effect lifecycle is unavailable: {error}"))?;
        self.admit_runtime_mode_tool(tool_name, arguments)?;
        Ok(BackgroundEffectRegistration { _guard: guard })
    }

    /// Serialize lower-level child-run registration with mode publication.
    ///
    /// This covers callers that enter the subagent runner without passing
    /// through the model-facing `task` adapter.
    pub(crate) fn begin_child_run_registration(
        &self,
    ) -> Result<BackgroundEffectRegistration<'_>, String> {
        let guard = self
            .background_effect_lifecycle
            .lock()
            .map_err(|error| format!("background-effect lifecycle is unavailable: {error}"))?;
        let snapshot = self.runtime_mode();
        if !snapshot.allows_child_runs() {
            return Err(format!(
                "Runtime mode '{}' generation {} denies child-run registration",
                snapshot.display_name(),
                snapshot.generation
            ));
        }
        Ok(BackgroundEffectRegistration { _guard: guard })
    }

    /// Validate a prospective mode against this run's current target set
    /// without changing the installed generation.
    pub(crate) fn validate_runtime_mode_transition(
        &self,
        mode: &crate::modes::RuntimeMode,
    ) -> Result<(), String> {
        self.runtime_mode.validate_transition(mode)
    }

    /// Enforce the active mode against a concrete classified tool call.
    ///
    /// # Errors
    ///
    /// Returns an error when the call is malformed, unclassified, or denied
    /// by the current runtime mode.
    pub fn admit_runtime_mode_tool(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
    ) -> Result<(), String> {
        let snapshot = self.runtime_mode();
        if snapshot.class == crate::modes::RuntimeModeClass::Standard
            && matches!(
                &snapshot.mode,
                crate::modes::RuntimeMode::Behavioral(mode)
                    if mode.scope == crate::modes::Scope::Adjacent
            )
            && !snapshot.scope_targets.is_explicit()
        {
            return Ok(());
        }
        let resolved = super::effect::resolve_for_call(tool_name, arguments)
            .map_err(|error| error.reason())?;
        self.admit_runtime_mode_resolved(tool_name, &resolved, arguments)
    }

    /// Re-check mode authority at the final effect reservation boundary.
    pub(crate) fn admit_runtime_mode_resolved(
        &self,
        tool_name: &str,
        resolved: &super::effect::ResolvedEffect,
        arguments: &serde_json::Value,
    ) -> Result<(), String> {
        let canonical_path = if matches!(
            resolved.target_kind,
            super::effect::ToolTargetKind::Path | super::effect::ToolTargetKind::PathScope
        ) {
            Some(super::resolve_capability_path(self, &resolved.target)?)
        } else {
            None
        };
        self.runtime_mode.admit_resolved_tool(
            tool_name,
            resolved,
            canonical_path.as_deref(),
            arguments,
            &self.agent_plan_file,
        )
    }

    /// Gate effectful frontend shortcuts that bypass the model tool dispatcher.
    ///
    /// # Errors
    ///
    /// Returns an error when the current runtime mode denies direct effects.
    pub fn admit_runtime_mode_direct_operation(&self, operation: &str) -> Result<(), String> {
        self.runtime_mode.admit_direct_operation(operation)
    }

    /// Session identifier that owns these capabilities.
    #[must_use]
    pub fn session_id(&self) -> &str {
        self.runtime.descriptor().session_id.as_str()
    }

    /// Stable logical owner label for model-facing process lifecycle tools.
    #[must_use]
    pub fn process_owner(&self) -> &str {
        &self.process_owner
    }

    /// Require one concrete resource or return a typed unavailable error.
    ///
    /// # Errors
    ///
    /// Returns [`ToolCapabilityError::BindingMismatch`] when the immutable
    /// descriptor no longer matches its concrete resources, or
    /// [`ToolCapabilityError::Unavailable`] when the requested grant is absent.
    pub fn require(&self, resource: ToolResource) -> Result<(), ToolCapabilityError> {
        if let Err(error) = self.validate_binding() {
            tracing::error!(
                target: "openclaudia::capabilities",
                event = "capability_binding_mismatch",
                run_id = %self.run_id(),
                generation = %self.generation,
                detail = %error,
                "Rejected an invalid run capability binding"
            );
            return Err(error);
        }
        let available = self.grants_resource(resource);
        if available {
            Ok(())
        } else {
            tracing::warn!(
                target: "openclaudia::capabilities",
                event = "capability_unavailable",
                run_id = %self.run_id(),
                generation = %self.generation,
                resource = ?resource,
                "Denied unavailable run resource"
            );
            Err(ToolCapabilityError::Unavailable {
                resource,
                run_id: self.run_id(),
                generation: self.generation,
            })
        }
    }

    /// Inspect an already-validated immutable grant without recording a denied
    /// access attempt.
    ///
    /// This is crate-visible only for deriving a child run's authority. Tool
    /// and helper boundaries must call [`Self::require`] so an actual denied
    /// operation produces a typed error and trace event.
    #[must_use]
    pub(crate) fn grants_resource(&self, resource: ToolResource) -> bool {
        let kind = match resource {
            ToolResource::WorkspaceRead => CapabilityKind::WorkspaceRead,
            ToolResource::WorkspaceWrite => CapabilityKind::WorkspaceWrite,
            ToolResource::Process => CapabilityKind::Process,
            ToolResource::Network => CapabilityKind::Network,
            ToolResource::Secrets => CapabilityKind::Secrets,
            ToolResource::Memory => CapabilityKind::Memory,
            ToolResource::Mcp => CapabilityKind::Mcp,
        };
        self.runtime
            .descriptor()
            .capabilities
            .grants
            .contains(&kind)
    }

    fn validate_binding(&self) -> Result<(), ToolCapabilityError> {
        let descriptor = self.runtime.descriptor();
        if descriptor.capabilities.generation != self.generation {
            return Err(ToolCapabilityError::BindingMismatch {
                detail: "capability generation differs".to_string(),
            });
        }
        if descriptor.workspace.root() != self.project_root {
            return Err(ToolCapabilityError::BindingMismatch {
                detail: "workspace root differs".to_string(),
            });
        }
        if descriptor.workspace.generation.get() != self.generation.get() {
            return Err(ToolCapabilityError::BindingMismatch {
                detail: "workspace generation differs".to_string(),
            });
        }
        let grants = &descriptor.capabilities.grants;
        let binding_pairs = [
            (
                CapabilityKind::WorkspaceWrite,
                self.read_write_roots
                    .iter()
                    .any(|root| path_is_within(&self.project_root, root)),
            ),
            (CapabilityKind::Process, self.process_available),
            (CapabilityKind::Network, self.network_available),
            (CapabilityKind::Secrets, self.secrets_available),
        ];
        for (kind, available) in binding_pairs {
            if grants.contains(&kind) != available {
                return Err(ToolCapabilityError::BindingMismatch {
                    detail: format!("{kind:?} availability differs from descriptor grant"),
                });
            }
        }
        let expected_manifest = capability_manifest_digest(
            descriptor.run_id,
            self.generation,
            &self.project_root,
            &self.working_directory,
            self.private_temp.path(),
            &self.read_only_roots,
            &self.read_write_roots,
            &self.denied_paths,
            &self.agent_plan_file,
            &self.environment_grants,
            &self.mcp_environment_grants,
            &self.executable_search_path,
            self.host_home.as_deref(),
            self.network_policy,
            grants,
            &self.process_owner,
        );
        if descriptor.capabilities.manifest_digest != expected_manifest {
            return Err(ToolCapabilityError::BindingMismatch {
                detail: "capability manifest digest differs".to_string(),
            });
        }
        Ok(())
    }

    /// Canonical immutable project root.
    #[must_use]
    pub fn project_root(&self) -> &Path {
        &self.project_root
    }

    /// Canonical immutable working directory.
    #[must_use]
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    /// Private temporary directory granted only to this session.
    #[must_use]
    pub fn private_temp_root(&self) -> &Path {
        self.private_temp.path()
    }

    pub(crate) fn background_job_storage_root(&self) -> Result<PathBuf, String> {
        match self.background_job_storage {
            BackgroundJobStorage::Ephemeral => Ok(self.private_temp.path().join("background-jobs")),
            BackgroundJobStorage::Durable => dirs::data_local_dir()
                .or_else(dirs::data_dir)
                .map(|root| root.join("openclaudia").join("background-jobs"))
                .ok_or_else(|| {
                    "Cannot resolve a host user-data directory for background-job state".to_string()
                }),
        }
    }

    /// Derive a new frontend session from this run's immutable authority.
    ///
    /// The requested project and working directory must already be contained
    /// by this run's filesystem grants. Intrinsic roots owned by the parent
    /// generation are replaced with roots for the child generation, while
    /// operator-provided additional roots and all non-filesystem grants are
    /// copied exactly. No process environment or current directory is read.
    ///
    /// # Errors
    ///
    /// Returns an error when either requested directory is outside the parent
    /// authority or the derived capability cannot be pinned and validated.
    pub fn derive_frontend_session(
        &self,
        session_id: SessionId,
        project_root: &Path,
        working_directory: &Path,
        provider: &str,
    ) -> Result<Arc<Self>, String> {
        let project_root = canonical_directory(project_root, "derived project root")?;
        let working_directory =
            canonical_directory(working_directory, "derived working directory")?;
        let workspace_access = if self.grants_resource(ToolResource::WorkspaceWrite) {
            WorkspaceAccess::ReadWrite
        } else {
            WorkspaceAccess::ReadOnly
        };
        let permits_workspace = |path: &Path| match workspace_access {
            WorkspaceAccess::ReadOnly => self.permits_read(path),
            WorkspaceAccess::ReadWrite => self.permits_write(path),
        };
        if !permits_workspace(&project_root) {
            return Err(format!(
                "Derived project root '{}' is outside the parent run's {:?} workspace authority",
                project_root.display(),
                workspace_access
            ));
        }
        if !permits_workspace(&working_directory) {
            return Err(format!(
                "Derived working directory '{}' is outside the parent run's {:?} workspace authority",
                working_directory.display(),
                workspace_access
            ));
        }

        let is_parent_intrinsic_root = |root: &&PathBuf| {
            root.as_path() == self.project_root || root.as_path() == self.private_temp.path()
        };
        let read_only_roots = self
            .read_only_roots
            .iter()
            .filter(|root| !is_parent_intrinsic_root(root))
            .cloned()
            .collect();
        let read_write_roots = self
            .read_write_roots
            .iter()
            .filter(|root| !is_parent_intrinsic_root(root))
            .cloned()
            .collect();
        let process_owner = session_id.as_str().to_string();
        let runtime_mode = self.runtime_mode();

        Self::builder(session_id, &project_root)
            .working_directory(working_directory)
            .read_only_roots(read_only_roots)
            .read_write_roots(read_write_roots)
            .project_secret_masks(self.project_secret_masks.clone())
            .protected_environment_grants(self.environment_grants.clone())
            .protected_mcp_environment_grants(self.mcp_environment_grants.clone())
            .executable_search_path(&self.executable_search_path)
            .host_home(self.host_home.clone())
            .workspace_access(workspace_access)
            .process(self.grants_resource(ToolResource::Process))
            .network(self.grants_resource(ToolResource::Network))
            .secrets(self.grants_resource(ToolResource::Secrets))
            .process_owner(process_owner)
            .actor_role(ActorRole::Frontend)
            .provider(provider)
            .budget_limits(self.runtime.descriptor().budget.limits.clone())
            .parent_budget(self.runtime.budget().clone())
            .runtime_mode(runtime_mode.mode)
            .behavior_scope_targets(runtime_mode.scope_targets)
            .background_job_storage(self.background_job_storage)
            .build()
    }

    /// Whether a canonical path is readable by this session.
    #[must_use]
    pub fn permits_read(&self, path: &Path) -> bool {
        !self.is_denied_path(path)
            && self
                .read_write_roots
                .iter()
                .chain(&self.read_only_roots)
                .any(|root| path_is_within(path, root))
    }

    /// Whether a canonical path is writable by this session.
    #[must_use]
    pub fn permits_write(&self, path: &Path) -> bool {
        !self.is_denied_path(path)
            && self
                .read_write_roots
                .iter()
                .any(|root| path_is_within(path, root))
    }

    /// Canonical roots visible to diagnostic and sandbox profile builders.
    #[must_use]
    pub fn read_only_roots(&self) -> &[PathBuf] {
        &self.read_only_roots
    }

    /// Canonical writable roots visible to diagnostic and sandbox builders.
    #[must_use]
    pub fn read_write_roots(&self) -> &[PathBuf] {
        &self.read_write_roots
    }

    /// Project subtrees excluded from otherwise broad project capabilities.
    #[must_use]
    pub fn denied_paths(&self) -> &[PathBuf] {
        &self.denied_paths
    }

    /// The only masked project-control file exposed to this exact run.
    ///
    /// Plan-mode dispatch separately restricts writes to this path. Binding
    /// it to the immutable session identity prevents one concurrent session
    /// from reading or mutating another session's plan.
    #[must_use]
    pub fn agent_plan_file(&self) -> &Path {
        &self.agent_plan_file
    }

    /// Project-relative masks inherited by derived run generations.
    #[must_use]
    pub fn project_secret_masks(&self) -> &[PathBuf] {
        &self.project_secret_masks
    }

    /// Exact host-approved environment values inherited by agent processes.
    #[must_use]
    pub const fn environment_grants(&self) -> &crate::secrets::EnvironmentGrants {
        &self.environment_grants
    }

    /// Exact host-approved values available only to trusted MCP server
    /// configuration for this run generation.
    #[must_use]
    pub const fn mcp_environment_grants(&self) -> &crate::secrets::EnvironmentGrants {
        &self.mcp_environment_grants
    }

    /// Sanitize untrusted process/provider diagnostics against every secret
    /// capability bound to this run generation.
    #[must_use]
    pub fn sanitize_diagnostic(&self, raw: &str) -> crate::secrets::SafeDiagnostic {
        let environment_safe = self.environment_grants.sanitize_diagnostic(raw);
        self.mcp_environment_grants
            .sanitize_diagnostic(environment_safe.as_str())
    }

    /// Exact executable search path captured when this run was constructed.
    #[must_use]
    pub fn executable_search_path(&self) -> &OsStr {
        &self.executable_search_path
    }

    /// Host-home path captured at composition time for local toolchain mounts.
    ///
    /// The sandbox never exposes this directory wholesale. It may bind only
    /// conventional Cargo binary/registry and Rustup subtrees read-only.
    #[must_use]
    pub fn host_home(&self) -> Option<&Path> {
        self.host_home.as_deref()
    }

    /// Resolve an executable using only the immutable search path captured by
    /// this run.
    ///
    /// This is the sole resolver for process-capability helpers. It prevents a
    /// later mutation of the host process environment from redirecting an
    /// agent subprocess and fails with the same typed unavailable error used
    /// by tool dispatch when this run has no process authority.
    ///
    /// # Errors
    ///
    /// Returns [`ToolExecutableError::Capability`] when process execution is
    /// unavailable, or [`ToolExecutableError::Resolve`] when the program is
    /// absent from the captured search path.
    pub fn resolve_executable(
        &self,
        executable: impl AsRef<OsStr>,
    ) -> Result<PathBuf, ToolExecutableError> {
        self.require(ToolResource::Process)?;
        let executable = executable.as_ref();
        which::which_in(
            executable,
            Some(&self.executable_search_path),
            &self.working_directory,
        )
        .map_err(|source| ToolExecutableError::Resolve {
            executable: executable.to_string_lossy().into_owned(),
            source,
        })
    }

    /// Immutable session network policy.
    #[must_use]
    pub const fn network_policy(&self) -> AgentNetworkPolicy {
        self.network_policy
    }

    /// Whether a path names or descends from a masked control/secret subtree.
    #[must_use]
    pub fn is_denied_path(&self, path: &Path) -> bool {
        path != self.agent_plan_file
            && self
                .denied_paths
                .iter()
                .any(|denied| path == denied || path.starts_with(denied))
    }

    /// Return the longest matching pre-opened Linux capability-root handle.
    ///
    /// Root descriptors are pinned when the session is created. File tools
    /// must anchor authoritative lookups to these descriptors rather than
    /// reopening a root by pathname after policy validation.
    #[cfg(unix)]
    pub(crate) fn root_handle_for(
        &self,
        path: &Path,
        write: bool,
    ) -> Result<(&Path, &std::fs::File), String> {
        if self.is_denied_path(path) {
            return Err(format!(
                "Path '{}' is masked from agent filesystem capabilities",
                path.display()
            ));
        }
        self.root_handles
            .iter()
            .filter(|root| {
                (!write || root.writable)
                    && (path == root.path.as_path() || path.starts_with(&root.path))
            })
            .max_by_key(|root| root.path.components().count())
            .map(|root| (root.path.as_path(), &root.directory))
            .ok_or_else(|| {
                let access = if write { "writable" } else { "readable" };
                format!(
                    "Path '{}' is outside the session's {access} capability roots",
                    path.display()
                )
            })
    }

    /// Return the pinned project-root handle for host-owned control state.
    ///
    /// Agent file tools must use [`Self::root_handle_for`], which rejects
    /// `.openclaudia`, `.claude`, and configured secret masks. Frontend
    /// lifecycle code occasionally needs to maintain files inside those
    /// masked subtrees (for example plan-mode and branch snapshots). This
    /// separate boundary keeps that authority explicit and refuses paths that
    /// are either outside the exact run project or not masked control state.
    #[cfg(unix)]
    pub(crate) fn host_control_root_handle_for(
        &self,
        path: &Path,
        write: bool,
    ) -> Result<(&Path, &std::fs::File), String> {
        if !self.is_denied_path(path) || !path_is_within(path, &self.project_root) {
            return Err(format!(
                "Path '{}' is not host-owned control state for run project '{}'",
                path.display(),
                self.project_root.display()
            ));
        }
        self.root_handles
            .iter()
            .find(|root| root.path == self.project_root && (!write || root.writable))
            .map(|root| (root.path.as_path(), &root.directory))
            .ok_or_else(|| {
                let access = if write { "writable" } else { "readable" };
                format!(
                    "Run project '{}' has no pinned {access} host-control capability",
                    self.project_root.display()
                )
            })
    }

    /// Duplicate the pinned capability roots onto descriptors reserved above
    /// the seccomp descriptor. The launcher clears `FD_CLOEXEC` only in the
    /// forked child, so concurrent host spawns never inherit them.
    #[cfg(target_os = "linux")]
    pub(crate) fn duplicate_linux_bind_roots(&self) -> Result<Vec<LinuxBindRoot>, String> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};

        let mut roots = Vec::with_capacity(self.root_handles.len());
        for root in &self.root_handles {
            let duplicated =
                unsafe { libc::fcntl(root.directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 200) };
            if duplicated < 0 {
                return Err(format!(
                    "Cannot duplicate pinned capability root for sandbox mounting: {}",
                    std::io::Error::last_os_error()
                ));
            }
            roots.push(LinuxBindRoot {
                path: root.path.clone(),
                writable: root.writable,
                // SAFETY: fcntl returned a fresh owned descriptor.
                directory: unsafe { std::os::fd::OwnedFd::from_raw_fd(duplicated) },
            });
        }
        Ok(roots)
    }
}

impl Drop for ToolRunContext {
    fn drop(&mut self) {
        // The last `Arc` is the run lifecycle boundary. Remove the exact-run
        // read-before-edit bucket so completed runs cannot accumulate process-
        // global path observations or leave authority-looking residue behind.
        super::file::READ_TRACKER.clear_run(self);
        crate::guardrails::release_run(self);
    }
}

fn next_capability_generation() -> Result<CapabilityGeneration, String> {
    let generation = NEXT_CAPABILITY_GENERATION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| "run capability generation space exhausted".to_string())?;
    CapabilityGeneration::new(generation)
        .ok_or_else(|| "run capability generation must be non-zero".to_string())
}

#[allow(clippy::too_many_arguments)] // Hash every explicit capability field at one binding boundary.
fn capability_manifest_digest(
    run_id: RunId,
    generation: CapabilityGeneration,
    project_root: &Path,
    working_directory: &Path,
    scratch_root: &Path,
    read_only_roots: &[PathBuf],
    read_write_roots: &[PathBuf],
    denied_paths: &[PathBuf],
    agent_plan_file: &Path,
    environment_grants: &crate::secrets::EnvironmentGrants,
    mcp_environment_grants: &crate::secrets::EnvironmentGrants,
    executable_search_path: &OsStr,
    host_home: Option<&Path>,
    network_policy: AgentNetworkPolicy,
    grants: &BTreeSet<CapabilityKind>,
    process_owner: &str,
) -> ContentDigest {
    let mut manifest = format!(
        "run={run_id}\ngeneration={generation}\nproject={}\nworking={}\nscratch={}\n",
        project_root.display(),
        working_directory.display(),
        scratch_root.display()
    );
    manifest.push_str("process_owner=");
    manifest.push_str(process_owner);
    manifest.push('\n');
    for root in read_only_roots {
        manifest.push_str("read_only=");
        manifest.push_str(&root.to_string_lossy());
        manifest.push('\n');
    }
    for root in read_write_roots {
        manifest.push_str("read_write=");
        manifest.push_str(&root.to_string_lossy());
        manifest.push('\n');
    }
    for path in denied_paths {
        manifest.push_str("denied=");
        manifest.push_str(&path.to_string_lossy());
        manifest.push('\n');
    }
    manifest.push_str("agent_plan_file=");
    manifest.push_str(&agent_plan_file.to_string_lossy());
    manifest.push('\n');
    for (name, digest) in environment_grants.sorted_name_digests() {
        manifest.push_str("environment=");
        manifest.push_str(name);
        manifest.push(':');
        manifest.push_str(&digest);
        manifest.push('\n');
    }
    for (name, digest) in mcp_environment_grants.sorted_name_digests() {
        manifest.push_str("mcp_environment=");
        manifest.push_str(name);
        manifest.push(':');
        manifest.push_str(&digest);
        manifest.push('\n');
    }
    manifest.push_str("executable_search_path=");
    manifest
        .push_str(&ContentDigest::sha256(executable_search_path.as_encoded_bytes()).to_string());
    manifest.push('\n');
    manifest.push_str("host_home=");
    if let Some(path) = host_home {
        manifest.push_str(&path.to_string_lossy());
    }
    manifest.push('\n');
    manifest.push_str("network_policy=");
    let _ = write!(manifest, "{network_policy:?}");
    manifest.push('\n');
    for grant in grants {
        manifest.push_str("grant=");
        let _ = write!(manifest, "{grant:?}");
        manifest.push('\n');
    }
    ContentDigest::sha256(manifest)
}

fn default_executable_search_path() -> OsString {
    #[cfg(windows)]
    {
        OsString::new()
    }
    #[cfg(not(windows))]
    {
        OsString::from("/usr/local/bin:/usr/bin:/bin")
    }
}

fn run_budget(generation: CapabilityGeneration, limits: BudgetLimits) -> Result<RunBudget, String> {
    Ok(RunBudget {
        id: BudgetId::new(),
        generation: BudgetGeneration::new(generation.get())
            .ok_or_else(|| "budget generation must be non-zero".to_string())?,
        limits,
    })
}

fn default_project_secret_masks() -> Vec<PathBuf> {
    vec![PathBuf::from(".openclaudia"), PathBuf::from(".claude")]
}

fn project_plan_file(project_root: &Path, session_id: &str) -> PathBuf {
    let safe_session_id: String = session_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect();
    project_root
        .join(".openclaudia/plans")
        .join(format!("{safe_session_id}.md"))
}

fn startup_project_secret_masks() -> Result<Vec<PathBuf>, String> {
    let mut masks = default_project_secret_masks();
    let Some(raw) = std::env::var_os("OPENCLAUDIA_PROJECT_SECRET_MASKS") else {
        return Ok(masks);
    };
    let raw = raw.to_str().ok_or_else(|| {
        "OPENCLAUDIA_PROJECT_SECRET_MASKS contains non-Unicode data; refusing to create session capabilities"
            .to_string()
    })?;
    masks.extend(
        raw.split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(PathBuf::from),
    );
    validate_project_secret_masks(masks)
}

fn validate_project_secret_masks(masks: Vec<PathBuf>) -> Result<Vec<PathBuf>, String> {
    let mut validated = Vec::with_capacity(masks.len());
    for path in masks {
        if path.is_absolute()
            || path.as_os_str().is_empty()
            || !path
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
        {
            return Err(format!(
                "Invalid project secret mask '{}': use a non-empty relative path without '.' or '..'",
                path.display()
            ));
        }
        if !validated.contains(&path) {
            validated.push(path);
        }
    }
    Ok(validated)
}

fn startup_environment_grants() -> Result<HashMap<String, String>, String> {
    let Some(raw) = std::env::var_os("OPENCLAUDIA_AGENT_ENV_GRANTS") else {
        return Ok(HashMap::new());
    };
    let raw = raw.to_str().ok_or_else(|| {
        "OPENCLAUDIA_AGENT_ENV_GRANTS contains non-Unicode data; refusing session startup"
            .to_string()
    })?;
    let mut grants = HashMap::new();
    for name in raw
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        validate_environment_grant_name(name)?;
        if let Some(value) = std::env::var_os(name) {
            let value = value.to_str().ok_or_else(|| {
                format!("Granted environment variable '{name}' is not valid UTF-8")
            })?;
            grants.insert(name.to_string(), value.to_string());
        }
    }
    validate_environment_grants(grants)
}

fn startup_mcp_environment_grants() -> Result<HashMap<String, String>, String> {
    let Some(raw) = std::env::var_os("OPENCLAUDIA_MCP_ENV_GRANTS") else {
        return Ok(HashMap::new());
    };
    let raw = raw.to_str().ok_or_else(|| {
        "OPENCLAUDIA_MCP_ENV_GRANTS contains non-Unicode data; refusing session startup".to_string()
    })?;
    let mut grants = HashMap::new();
    for name in raw
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        validate_mcp_environment_grant_name(name)?;
        if let Some(value) = std::env::var_os(name) {
            let value = value.to_str().ok_or_else(|| {
                format!("Granted MCP environment variable '{name}' is not valid UTF-8")
            })?;
            grants.insert(name.to_string(), value.to_string());
        }
    }
    validate_mcp_environment_grants(grants)
}

fn validate_mcp_environment_grants(
    grants: HashMap<String, String>,
) -> Result<HashMap<String, String>, String> {
    for (name, value) in &grants {
        validate_mcp_environment_grant_name(name)?;
        if value.contains('\0') {
            return Err(format!(
                "Granted MCP environment variable '{name}' contains a NUL byte"
            ));
        }
    }
    Ok(grants)
}

fn protect_environment_grants(
    grants: HashMap<String, String>,
) -> Result<crate::secrets::EnvironmentGrants, String> {
    crate::secrets::EnvironmentGrants::from_validated(grants)
        .map_err(|error| format!("Invalid environment grant value: {error}"))
}

fn validate_mcp_environment_grant_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let valid = chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric());
    if valid {
        Ok(())
    } else {
        Err(format!(
            "Invalid environment variable name in OPENCLAUDIA_MCP_ENV_GRANTS: '{name}'"
        ))
    }
}

fn validate_environment_grants(
    grants: HashMap<String, String>,
) -> Result<HashMap<String, String>, String> {
    for (name, value) in &grants {
        validate_environment_grant_name(name)?;
        if value.contains('\0') {
            return Err(format!(
                "Granted environment variable '{name}' contains a NUL byte"
            ));
        }
    }
    Ok(grants)
}

fn validate_environment_grant_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let valid = chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric());
    let upper = name.to_ascii_uppercase();
    let reserved = matches!(
        upper.as_str(),
        "HOME"
            | "PATH"
            | "TMP"
            | "TEMP"
            | "TMPDIR"
            | "SSH_AUTH_SOCK"
            | "DBUS_SESSION_BUS_ADDRESS"
            | "DISPLAY"
            | "WAYLAND_DISPLAY"
            | "XDG_RUNTIME_DIR"
            | "LD_PRELOAD"
            | "DYLD_INSERT_LIBRARIES"
            | "GCONV_PATH"
            | "GLIBC_TUNABLES"
            | "LOCPATH"
            | "NLSPATH"
    ) || upper.starts_with("LD_")
        || upper.starts_with("DYLD_")
        || upper.starts_with("OPENCLAUDIA_");
    if !valid || reserved {
        return Err(format!(
            "Invalid or policy-reserved agent environment grant '{name}'"
        ));
    }
    Ok(())
}

fn startup_network_policy() -> Result<AgentNetworkPolicy, String> {
    match std::env::var("OPENCLAUDIA_AGENT_NETWORK") {
        Ok(value) if !value.trim().is_empty() && !value.eq_ignore_ascii_case("denied") => Err(
            "Only OPENCLAUDIA_AGENT_NETWORK=denied is supported; loopback and destination grants require a broker and will not fall back to the host network"
                .to_string(),
        ),
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(AgentNetworkPolicy::Denied),
        Err(std::env::VarError::NotUnicode(_)) => Err(
            "OPENCLAUDIA_AGENT_NETWORK contains non-Unicode data; refusing session startup"
                .to_string(),
        ),
    }
}

#[cfg(unix)]
fn open_capability_roots(
    read_only_roots: &[PathBuf],
    read_write_roots: &[PathBuf],
) -> Result<Vec<CapabilityRootHandle>, String> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    let mut handles = Vec::with_capacity(read_only_roots.len() + read_write_roots.len());
    for (path, writable) in read_only_roots
        .iter()
        .map(|path| (path, false))
        .chain(read_write_roots.iter().map(|path| (path, true)))
    {
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| format!("Capability root contains NUL: '{}'", path.display()))?;
        // SAFETY: `path_c` is stable and NUL-terminated. A successful call
        // returns one uniquely owned descriptor.
        #[cfg(target_os = "linux")]
        let directory_flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        #[cfg(not(target_os = "linux"))]
        let directory_flags =
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        let fd = unsafe { libc::open(path_c.as_ptr(), directory_flags) };
        if fd < 0 {
            return Err(format!(
                "Cannot pin capability root '{}': {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: the successful `open` returned a new owned descriptor.
        let directory = unsafe { std::fs::File::from_raw_fd(fd) };
        handles.push(CapabilityRootHandle {
            path: path.clone(),
            writable,
            directory,
        });
    }
    Ok(handles)
}

#[derive(Debug)]
struct PrivateTempDir {
    path: PathBuf,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl PrivateTempDir {
    fn create() -> Result<Self, String> {
        let parent = std::env::temp_dir();
        for _ in 0..16 {
            let path = parent.join(format!("openclaudia-agent-{}", uuid::Uuid::new_v4()));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt as _;
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                            .map_err(|error| {
                                let _ = std::fs::remove_dir(&path);
                                format!(
                                    "Cannot secure private session temp directory '{}': {error}",
                                    path.display()
                                )
                            })?;
                    }
                    let canonical = path.canonicalize().map_err(|error| {
                        let _ = std::fs::remove_dir(&path);
                        format!(
                            "Cannot resolve private session temp directory '{}': {error}",
                            path.display()
                        )
                    })?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt as _;
                        let metadata = std::fs::symlink_metadata(&canonical).map_err(|error| {
                            let _ = std::fs::remove_dir(&canonical);
                            format!(
                                "Cannot pin private session temp identity '{}': {error}",
                                canonical.display()
                            )
                        })?;
                        return Ok(Self {
                            path: canonical,
                            device: metadata.dev(),
                            inode: metadata.ino(),
                        });
                    }
                    #[cfg(not(unix))]
                    return Ok(Self { path: canonical });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!(
                        "Cannot create private session temp directory below '{}': {error}",
                        parent.display()
                    ));
                }
            }
        }
        Err("Cannot allocate a unique private session temp directory".to_string())
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        let tombstone = self
            .path
            .with_file_name(format!(".openclaudia-cleanup-{}", uuid::Uuid::new_v4()));
        if let Err(error) = std::fs::rename(&self.path, &tombstone) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %self.path.display(),
                    %error,
                    "Failed to atomically detach private session temp directory for cleanup"
                );
            }
            return;
        }
        match std::fs::symlink_metadata(&tombstone) {
            Ok(metadata)
                if metadata.file_type().is_dir()
                    && !metadata.file_type().is_symlink()
                    && private_temp_identity_matches(self, &metadata) =>
            {
                // `remove_dir_all` uses descriptor-relative, no-follow
                // traversal on supported Unix platforms. The unpredictable
                // tombstone name also prevents reuse of the original
                // capability path while cleanup proceeds.
                if let Err(error) = std::fs::remove_dir_all(&tombstone) {
                    tracing::warn!(
                        path = %tombstone.display(),
                        %error,
                        "Failed to remove private session temp directory"
                    );
                }
            }
            Ok(_) => {
                tracing::error!(
                    path = %tombstone.display(),
                    "Private session temp root changed identity or type; refusing recursive cleanup"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(
                    path = %self.path.display(),
                    %error,
                    "Failed to inspect private session temp directory during cleanup"
                );
            }
        }
    }
}

#[cfg(unix)]
fn private_temp_identity_matches(temp: &PrivateTempDir, metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    metadata.dev() == temp.device && metadata.ino() == temp.inode
}

#[cfg(not(unix))]
const fn private_temp_identity_matches(
    _temp: &PrivateTempDir,
    _metadata: &std::fs::Metadata,
) -> bool {
    true
}

fn startup_root_grants(name: &str) -> Result<Vec<PathBuf>, String> {
    let Some(raw) = std::env::var_os(name) else {
        return Ok(Vec::new());
    };
    std::env::split_paths(&raw)
        .map(|path| {
            if path.as_os_str().is_empty() {
                Err(format!("{name} contains an empty path"))
            } else {
                Ok(path)
            }
        })
        .collect()
}

/// Validate an IDE/client buffer path against the active immutable
/// capability without opening the file. Existing symlink components are
/// rejected so a client cannot label an outside buffer as project-local.
pub(crate) fn validate_client_buffer_path(
    context: &ToolRunContext,
    path: &Path,
) -> Result<PathBuf, String> {
    context
        .require(ToolResource::WorkspaceRead)
        .map_err(|error| error.to_string())?;
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        context.working_directory().join(path)
    };
    let mut normalized = PathBuf::new();
    for component in candidate.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                normalized.push(component.as_os_str());
            }
            std::path::Component::Normal(name) => normalized.push(name),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err("IDE buffer path contains '..' traversal".to_string())
            }
        }
    }
    if !context.permits_read(&normalized) {
        return Err("IDE buffer path is outside or masked from the session capability".to_string());
    }
    #[cfg(unix)]
    {
        let (root, _) = context.root_handle_for(&normalized, false)?;
        let relative = normalized
            .strip_prefix(root)
            .map_err(|_| "IDE buffer path escaped its capability root".to_string())?;
        let mut walked = root.to_path_buf();
        for component in relative.components() {
            let std::path::Component::Normal(name) = component else {
                continue;
            };
            walked.push(name);
            match std::fs::symlink_metadata(&walked) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err("IDE buffer path traverses a symbolic link".to_string())
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => return Err(format!("Cannot inspect IDE buffer path: {error}")),
            }
        }
        Ok(normalized)
    }
    #[cfg(not(unix))]
    {
        let _ = normalized;
        Err(
            "IDE buffer access is blocked because this platform lacks a handle-relative backend"
                .to_string(),
        )
    }
}

fn canonical_roots(roots: &[PathBuf], kind: &str) -> Result<Vec<PathBuf>, String> {
    let mut canonical = Vec::with_capacity(roots.len());
    for root in roots {
        let root = canonical_directory(root, kind)?;
        if is_unsafe_broad_root(&root) {
            return Err(format!(
                "Refusing broad {kind} capability root '{}'",
                root.display()
            ));
        }
        if !canonical.contains(&root) {
            canonical.push(root);
        }
    }
    Ok(canonical)
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("Cannot resolve {label} '{}': {error}", path.display()))?;
    if !canonical.is_dir() {
        return Err(format!(
            "{label} '{}' is not a directory",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn path_is_within(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

fn is_unsafe_broad_root(path: &Path) -> bool {
    #[cfg(unix)]
    const BROAD_ROOTS: &[&str] = &[
        "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/media", "/mnt", "/opt",
        "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var",
    ];
    #[cfg(unix)]
    if BROAD_ROOTS.iter().any(|root| path == Path::new(root)) {
        return true;
    }
    #[cfg(windows)]
    if path.parent().is_none() {
        return true;
    }
    false
}

/// Explicit crate-test capability rooted at this checkout.
///
/// This helper is compiled only into the crate's unit-test harness. Production
/// code has no default, registry, or ambient lookup path.
#[cfg(test)]
pub(crate) fn test_run_context() -> &'static Arc<ToolRunContext> {
    static RUN: std::sync::OnceLock<Arc<ToolRunContext>> = std::sync::OnceLock::new();
    RUN.get_or_init(|| {
        ToolRunContext::builder(SessionId::new(), Path::new(env!("CARGO_MANIFEST_DIR")))
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .workspace_access(WorkspaceAccess::ReadWrite)
            .process(true)
            .network(true)
            .secrets(true)
            .provider("unit-test")
            .build()
            .expect("crate test root must produce an explicit run capability")
    })
}

/// Build an isolated crate-test capability for a caller-owned root.
#[cfg(test)]
pub(crate) fn test_run_context_for(root: &Path) -> Arc<ToolRunContext> {
    ToolRunContext::builder(SessionId::new(), root)
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(HashMap::new())
        .workspace_access(WorkspaceAccess::ReadWrite)
        .process(true)
        .network(true)
        .secrets(true)
        .provider("unit-test")
        .build()
        .expect("test root must produce an explicit run capability")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct TraceWriter(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for TraceWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for TraceWriter {
        type Writer = Self;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn sessions_receive_distinct_private_temp_roots() {
        let root = tempfile::tempdir().expect("project root");
        let first = ToolRunContext::builder(SessionId::new(), root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .workspace_access(WorkspaceAccess::ReadWrite)
            .process(false)
            .network(false)
            .secrets(false)
            .build()
            .expect("first context");
        let second = ToolRunContext::builder(SessionId::new(), root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .workspace_access(WorkspaceAccess::ReadWrite)
            .process(false)
            .network(false)
            .secrets(false)
            .build()
            .expect("second context");
        assert_ne!(first.private_temp_root(), second.private_temp_root());
        assert_ne!(first.run_id(), second.run_id());
        assert_ne!(first.generation(), second.generation());
        assert!(first.permits_write(first.private_temp_root()));
        assert!(!first.permits_read(second.private_temp_root()));
    }

    #[test]
    fn derived_frontend_session_narrows_roots_and_never_rediscovers_host_grants() {
        let root = tempfile::tempdir().expect("parent project root");
        let child_root = root.path().join("child");
        std::fs::create_dir(&child_root).expect("child project root");
        let foreign = tempfile::tempdir().expect("foreign project root");
        let host_home = tempfile::tempdir().expect("host-home snapshot");
        let parent = ToolRunContext::builder(SessionId::new(), root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::from([(
                "S019_DERIVED_ENV".to_string(),
                "immutable".to_string(),
            )]))
            .host_home(Some(host_home.path().to_path_buf()))
            .workspace_access(WorkspaceAccess::ReadWrite)
            .process(true)
            .network(false)
            .secrets(false)
            .provider("parent")
            .build()
            .expect("parent run");
        let child_session = SessionId::new();
        let child = parent
            .derive_frontend_session(
                child_session.clone(),
                &child_root,
                &child_root,
                "child-provider",
            )
            .expect("authorized child session");

        assert_eq!(child.session_id(), child_session.as_str());
        assert_eq!(child.project_root(), child_root.canonicalize().unwrap());
        assert_ne!(child.run_id(), parent.run_id());
        assert_ne!(child.generation(), parent.generation());
        assert!(child
            .environment_grants()
            .matches_value("S019_DERIVED_ENV", "immutable"));
        assert_eq!(child.host_home(), parent.host_home());
        assert_eq!(
            child.host_home(),
            Some(host_home.path().canonicalize().unwrap().as_path())
        );
        assert!(child.require(ToolResource::Process).is_ok());
        assert!(matches!(
            child.require(ToolResource::Network),
            Err(ToolCapabilityError::Unavailable {
                resource: ToolResource::Network,
                ..
            })
        ));
        assert!(child.permits_write(&child_root));
        assert!(
            !child.permits_read(root.path()),
            "a narrowed generation must not retain its parent's broader intrinsic root"
        );

        let error = parent
            .derive_frontend_session(
                SessionId::new(),
                foreign.path(),
                foreign.path(),
                "foreign-provider",
            )
            .expect_err("foreign root must not become authority during derivation");
        assert!(error.contains("outside the parent run's"));
    }

    #[test]
    fn read_only_workspace_omits_write_capability_and_handle() {
        let root = tempfile::tempdir().expect("project root");
        let context = ToolRunContext::builder(SessionId::new(), root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .workspace_access(WorkspaceAccess::ReadOnly)
            .process(false)
            .network(false)
            .secrets(false)
            .build()
            .expect("read-only context");
        assert!(context.require(ToolResource::WorkspaceRead).is_ok());
        assert!(matches!(
            context.require(ToolResource::WorkspaceWrite),
            Err(ToolCapabilityError::Unavailable {
                resource: ToolResource::WorkspaceWrite,
                ..
            })
        ));
        assert!(context.permits_read(context.project_root()));
        assert!(!context.permits_write(context.project_root()));
        assert!(context.permits_write(context.private_temp_root()));
    }

    #[test]
    fn unavailable_resource_trace_binds_exact_run_and_generation() {
        let root = tempfile::tempdir().expect("project root");
        let context = ToolRunContext::builder(SessionId::new(), root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .workspace_access(WorkspaceAccess::ReadOnly)
            .process(false)
            .network(false)
            .secrets(false)
            .build()
            .expect("restricted context");
        let writer = TraceWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(writer.clone())
            .finish();

        let error = tracing::subscriber::with_default(subscriber, || {
            context
                .require(ToolResource::Network)
                .expect_err("network must be unavailable")
        });
        assert!(matches!(
            error,
            ToolCapabilityError::Unavailable {
                resource: ToolResource::Network,
                ..
            }
        ));
        let trace = String::from_utf8(
            writer
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        )
        .expect("trace output is UTF-8");
        assert!(trace.contains("capability_unavailable"), "{trace}");
        assert!(trace.contains(&context.run_id().to_string()), "{trace}");
        assert!(trace.contains(&context.generation().to_string()), "{trace}");
        assert!(trace.contains("Network"), "{trace}");
    }

    #[test]
    fn explicit_environment_grants_are_validated_and_bound() {
        let root = tempfile::tempdir().expect("project root");
        let context = ToolRunContext::builder(SessionId::new(), root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::from([(
                "S019_TEST_MARKER".to_string(),
                "run-specific".to_string(),
            )]))
            .workspace_access(WorkspaceAccess::ReadWrite)
            .process(true)
            .network(false)
            .secrets(false)
            .build()
            .expect("explicit environment grant");
        assert!(context
            .environment_grants()
            .matches_value("S019_TEST_MARKER", "run-specific"));

        let rejected = ToolRunContext::builder(SessionId::new(), root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::from([(
                "PATH".to_string(),
                "/attacker-controlled".to_string(),
            )]))
            .workspace_access(WorkspaceAccess::ReadWrite)
            .process(true)
            .network(false)
            .secrets(false)
            .build()
            .expect_err("policy-reserved values must be rejected");
        assert!(rejected.contains("policy-reserved"), "{rejected}");

        let secret_without_capability = ToolRunContext::builder(SessionId::new(), root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::from([(
                "SERVICE_API_KEY".to_string(),
                "secret".to_string(),
            )]))
            .workspace_access(WorkspaceAccess::ReadWrite)
            .process(true)
            .network(false)
            .secrets(false)
            .build()
            .expect_err("secret environment values require secret capability");
        assert!(
            secret_without_capability.contains("secret capability"),
            "{secret_without_capability}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn executable_resolution_is_process_authorized_and_run_bound() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("project root");
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).expect("binary directory");
        let executable = bin.join("s019-run-bound-probe");
        std::fs::write(&executable, "#!/bin/sh\nexit 0\n").expect("probe executable");
        let mut permissions = std::fs::metadata(&executable)
            .expect("probe metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&executable, permissions).expect("probe permissions");

        let authorized = ToolRunContext::builder(SessionId::new(), root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .executable_search_path(bin.as_os_str())
            .workspace_access(WorkspaceAccess::ReadWrite)
            .process(true)
            .network(false)
            .secrets(false)
            .build()
            .expect("process-capable run");
        assert_eq!(
            authorized
                .resolve_executable("s019-run-bound-probe")
                .expect("probe must resolve through the run path"),
            executable
        );
        assert!(matches!(
            authorized.resolve_executable("sh"),
            Err(ToolExecutableError::Resolve { .. })
        ));

        let denied = ToolRunContext::builder(SessionId::new(), root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .executable_search_path(bin.as_os_str())
            .workspace_access(WorkspaceAccess::ReadWrite)
            .process(false)
            .network(false)
            .secrets(false)
            .build()
            .expect("process-denied run");
        assert!(matches!(
            denied.resolve_executable("s019-run-bound-probe"),
            Err(ToolExecutableError::Capability(
                ToolCapabilityError::Unavailable {
                    resource: ToolResource::Process,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn capability_manifest_changes_with_environment_value() {
        let root = tempfile::tempdir().expect("project root");
        let scratch = tempfile::tempdir().expect("scratch root");
        let run_id = RunId::new();
        let generation = CapabilityGeneration::new(7).expect("generation");
        let grants = BTreeSet::from([CapabilityKind::WorkspaceRead]);
        let roots = vec![root.path().to_path_buf()];
        let first_environment =
            crate::secrets::EnvironmentGrants::from_validated(HashMap::from([(
                "S019_MARKER".to_string(),
                "first".to_string(),
            )]))
            .expect("environment");
        let second_environment = crate::secrets::EnvironmentGrants::from_validated(HashMap::from(
            [("S019_MARKER".to_string(), "second".to_string())],
        ))
        .expect("environment");
        let empty_environment = crate::secrets::EnvironmentGrants::new();
        let first = capability_manifest_digest(
            run_id,
            generation,
            root.path(),
            root.path(),
            scratch.path(),
            &[],
            &roots,
            &[],
            &root.path().join(".openclaudia/plans/run.md"),
            &first_environment,
            &empty_environment,
            OsStr::new("/usr/bin"),
            None,
            AgentNetworkPolicy::Denied,
            &grants,
            "owner",
        );
        let second = capability_manifest_digest(
            run_id,
            generation,
            root.path(),
            root.path(),
            scratch.path(),
            &[],
            &roots,
            &[],
            &root.path().join(".openclaudia/plans/run.md"),
            &second_environment,
            &empty_environment,
            OsStr::new("/usr/bin"),
            None,
            AgentNetworkPolicy::Denied,
            &grants,
            "owner",
        );
        assert_ne!(first, second, "environment values must bind the manifest");
    }

    #[test]
    fn mcp_secret_environment_is_generation_bound_and_requires_secret_authority() {
        let root = tempfile::tempdir().expect("project root");
        let grants = HashMap::from([("SERVICE_API_KEY".to_string(), "first".to_string())]);
        let context = ToolRunContext::builder(SessionId::new(), root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .mcp_environment_grants(grants.clone())
            .workspace_access(WorkspaceAccess::ReadOnly)
            .process(true)
            .network(false)
            .secrets(true)
            .build()
            .expect("MCP secret-authorized run");
        assert!(context
            .mcp_environment_grants()
            .matches_value("SERVICE_API_KEY", "first"));
        context.validate_binding().expect("manifest remains exact");

        let error = ToolRunContext::builder(SessionId::new(), root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .mcp_environment_grants(grants)
            .workspace_access(WorkspaceAccess::ReadOnly)
            .process(true)
            .network(false)
            .secrets(false)
            .build()
            .expect_err("secret MCP values require secret capability");
        assert!(error.contains("SERVICE_API_KEY"), "{error}");
    }

    #[test]
    fn omitted_capability_decisions_fail_closed() {
        let root = tempfile::tempdir().expect("project root");
        let error = ToolRunContext::builder(SessionId::new(), root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .build()
            .expect_err("resource decisions must not default to broad authority");
        assert!(error.contains("workspace access capability"), "{error}");
    }

    #[test]
    fn read_only_workspace_rejects_explicit_writable_roots() {
        let root = tempfile::tempdir().expect("project root");
        let extra = tempfile::tempdir().expect("extra writable root");
        let error = ToolRunContext::builder(SessionId::new(), root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(vec![extra.path().to_path_buf()])
            .environment_grants(HashMap::new())
            .workspace_access(WorkspaceAccess::ReadOnly)
            .process(false)
            .network(false)
            .secrets(false)
            .build()
            .expect_err("read-only descriptors must not retain writable handles");
        assert!(error.contains("read-only workspace"), "{error}");
    }

    #[test]
    fn omitted_roots_and_environment_fail_closed_independently() {
        let root = tempfile::tempdir().expect("project root");
        let missing_roots = ToolRunContext::builder(SessionId::new(), root.path())
            .environment_grants(HashMap::new())
            .workspace_access(WorkspaceAccess::ReadWrite)
            .process(false)
            .network(false)
            .secrets(false)
            .build()
            .expect_err("root grants must be explicit");
        assert!(missing_roots.contains("read-only roots"), "{missing_roots}");

        let missing_environment = ToolRunContext::builder(SessionId::new(), root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .workspace_access(WorkspaceAccess::ReadWrite)
            .process(false)
            .network(false)
            .secrets(false)
            .build()
            .expect_err("environment grants must be explicit");
        assert!(
            missing_environment.contains("environment grants"),
            "{missing_environment}"
        );
    }

    #[test]
    fn every_resource_decision_is_mandatory() {
        let root = tempfile::tempdir().expect("project root");
        let base = || {
            ToolRunContext::builder(SessionId::new(), root.path())
                .read_only_roots(Vec::new())
                .read_write_roots(Vec::new())
                .environment_grants(HashMap::new())
                .workspace_access(WorkspaceAccess::ReadWrite)
        };

        let missing_process = base()
            .network(false)
            .secrets(false)
            .build()
            .expect_err("process decision must be explicit");
        assert!(missing_process.contains("process capability"));

        let missing_network = base()
            .process(false)
            .secrets(false)
            .build()
            .expect_err("network decision must be explicit");
        assert!(missing_network.contains("network capability"));

        let missing_secrets = base()
            .process(false)
            .network(false)
            .build()
            .expect_err("secret decision must be explicit");
        assert!(missing_secrets.contains("secret capability"));
    }
}
