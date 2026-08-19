//! Plugin manager for discovery, loading, and lifecycle management.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use super::git::{
    copy_dir_recursive_within, git_clone, git_pull, read_origin_url_sidecar,
    write_origin_url_sidecar,
};
use super::install::{InstallScope, InstalledPlugins, PluginInstallEntry};
use super::marketplace::{
    GitHubSource, MarketplaceManifest, MarketplacePlugin, MarketplaceSource, PluginSource,
    PluginSourceDef, UrlSource,
};
use super::policy::{self, PluginPolicy, PolicyAction, PolicyRejection};
use super::validate::{verify_signature, SignatureError};
use super::{Plugin, PluginCommand, PluginError, PluginHook, PluginMcpServer};

/// Outcome of [`PluginManager::fetch_plugin_archive`].
///
/// Encodes whether the fetch left the install destination already
/// populated (git clone) or merely produced a verified source path
/// that still needs to be copied. This lets
/// [`PluginManager::extract_to_install_dir`] dispatch without
/// re-inspecting the original [`PluginSource`].
#[derive(Debug)]
enum FetchedSource {
    /// Path-source case: the marketplace already contains the bits.
    /// `source` is the canonical plugin path, verified to live inside
    /// `marketplace_root`; the extract step must copy it to `dest`
    /// while re-checking containment per entry (crosslink #258).
    LocalCopy {
        source: PathBuf,
        marketplace_root: PathBuf,
    },
    /// Structured (`Url` / `GitHub`) source: `git_clone` has already
    /// populated `dest`. Carries the pinned commit SHA so the install
    /// record can record exactly what was materialized
    /// (crosslink #249, point 1).
    GitClone { commit_sha: String },
}

impl FetchedSource {
    /// Pinned commit SHA, when the fetch was a git clone. `None` for
    /// path-source fetches (which have no upstream revision).
    fn commit_sha(&self) -> Option<String> {
        match self {
            Self::GitClone { commit_sha } => Some(commit_sha.clone()),
            Self::LocalCopy { .. } => None,
        }
    }

    /// `true` when the fetch materialized over git, used by the
    /// orchestrator to pick the right log line.
    const fn is_git(&self) -> bool {
        matches!(self, Self::GitClone { .. })
    }
}

/// Manages plugin discovery, loading, and lifecycle
pub struct PluginManager {
    /// Loaded plugins by name
    plugins: HashMap<String, Plugin>,
    /// Search paths for plugins
    search_paths: Vec<PathBuf>,
    /// Installation tracking
    installed: InstalledPlugins,
    /// Exact project root for project-scoped discovery and install state.
    project_root: PathBuf,
}

impl PluginManager {
    /// Create a new plugin manager with default search paths.
    ///
    /// Falls back to the project-relative search path only when `dirs::home_dir()`
    /// is `None` — kept as the lenient default for tests and CI containers
    /// where no $HOME is configured. Production callers should prefer
    /// [`Self::try_new`], which surfaces the missing-home-directory case as
    /// an explicit error instead of silently degrading to a project-only
    /// search (crosslink #893).
    #[must_use]
    pub fn new() -> Self {
        let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self::build(dirs::home_dir(), project_root)
    }

    /// Create a lenient manager bound to an explicit project root.
    #[must_use]
    pub fn new_for_project(project_root: impl Into<PathBuf>) -> Self {
        Self::build(dirs::home_dir(), project_root.into())
    }

    /// Create a new plugin manager, returning an error when no home directory
    /// can be resolved.
    ///
    /// `~/.openclaudia/plugins` and `~/.claude/plugins` are the two user-scope
    /// search locations; without a home directory, plugin discovery can only
    /// see project-scoped installs, which silently masks the failure case
    /// where the user installed a plugin globally but the harness can't find
    /// it. Production code paths (proxy startup, `openclaudia plugin …`,
    /// `doctor`) MUST use this constructor so the missing-home-directory case
    /// surfaces as a clear error rather than a "no plugins detected" mystery.
    ///
    /// # Errors
    /// Returns [`PluginError::InstallError`] when `dirs::home_dir()` returns
    /// `None`. Tests can bypass via [`Self::with_paths`].
    pub fn try_new() -> Result<Self, PluginError> {
        let project_root = std::env::current_dir().map_err(|error| {
            PluginError::InstallError(format!("cannot determine project root: {error}"))
        })?;
        Self::try_new_for_project(project_root)
    }

    /// Create a production manager bound to an explicit project root.
    ///
    /// # Errors
    /// Returns [`PluginError::InstallError`] when no home directory can be
    /// resolved.
    pub fn try_new_for_project(project_root: impl Into<PathBuf>) -> Result<Self, PluginError> {
        let project_root = project_root.into();
        dirs::home_dir().map_or_else(
            || {
                Err(PluginError::InstallError(
                    "cannot determine home directory; set $HOME so plugin discovery \
                     can locate user-scope plugins"
                        .to_string(),
                ))
            },
            |home| Ok(Self::build(Some(home), project_root)),
        )
    }

    /// Internal helper shared by [`Self::new`] and [`Self::try_new`].
    fn build(home_dir: Option<PathBuf>, project_root: PathBuf) -> Self {
        let mut search_paths = Vec::new();

        // User plugins directory
        if let Some(home) = home_dir {
            search_paths.push(home.join(".openclaudia").join("plugins"));
            // Also search Claude Code's plugin cache for compatibility
            search_paths.push(home.join(".claude").join("plugins"));
        }

        // Project plugins directory
        search_paths.push(project_root.join(".openclaudia/plugins"));

        Self {
            plugins: HashMap::new(),
            search_paths,
            installed: InstalledPlugins::load(&project_root),
            project_root,
        }
    }

    /// Create a plugin manager with custom search paths
    #[must_use]
    pub fn with_paths(paths: Vec<PathBuf>) -> Self {
        let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self::with_paths_for_project(paths, project_root)
    }

    /// Create a manager with custom search paths and an explicit project root.
    #[must_use]
    pub fn with_paths_for_project(paths: Vec<PathBuf>, project_root: impl Into<PathBuf>) -> Self {
        Self {
            plugins: HashMap::new(),
            search_paths: paths,
            installed: InstalledPlugins::default(),
            project_root: project_root.into(),
        }
    }

    /// Discover and load all plugins from search paths and `installed_plugins.json`
    pub fn discover(&mut self) -> Vec<PluginError> {
        let mut errors = Vec::new();

        // Load from search paths (convention-based discovery)
        for search_path in &self.search_paths.clone() {
            if !search_path.exists() {
                debug!(path = ?search_path, "Plugin search path does not exist");
                continue;
            }

            let entries = match fs::read_dir(search_path) {
                Ok(entries) => entries,
                Err(e) => {
                    warn!(path = ?search_path, error = %e, "Failed to read plugin directory");
                    continue;
                }
            };

            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    match Plugin::load(&path) {
                        Ok(plugin) => {
                            info!(
                                name = %plugin.name(),
                                version = ?plugin.manifest.version,
                                path = ?path,
                                commands = plugin.command_paths.len(),
                                hooks = plugin.hook_definitions.len(),
                                mcp = plugin.mcp_configs.len(),
                                "Loaded plugin"
                            );
                            self.plugins.insert(plugin.name().to_string(), plugin);
                        }
                        Err(PluginError::ManifestNotFound(_)) => {
                            // Not a plugin directory, skip silently
                            debug!(path = ?path, "Directory has no plugin manifest, skipping");
                        }
                        Err(e) => {
                            warn!(path = ?path, error = %e, "Failed to load plugin");
                            errors.push(e);
                        }
                    }
                }
            }
        }

        // Load from installed_plugins.json (tracked installations)
        for (plugin_id, entries) in &self.installed.plugins {
            for entry in entries {
                let install_path = PathBuf::from(&entry.install_path);
                if !install_path.exists() {
                    debug!(plugin = %plugin_id, path = ?install_path, "Installed plugin path missing");
                    continue;
                }
                // Skip if already loaded from search paths
                let name = plugin_id.split('@').next().unwrap_or(plugin_id);
                if self.plugins.contains_key(name) {
                    continue;
                }
                match Plugin::load(&install_path) {
                    Ok(mut plugin) => {
                        plugin.id.clone_from(plugin_id);
                        if let Some(marketplace) = plugin_id.split('@').nth(1) {
                            plugin.source = marketplace.to_string();
                        }
                        info!(
                            id = %plugin_id,
                            name = %plugin.name(),
                            scope = %entry.scope,
                            "Loaded installed plugin"
                        );
                        self.plugins.insert(plugin.name().to_string(), plugin);
                    }
                    Err(e) => {
                        warn!(plugin = %plugin_id, error = %e, "Failed to load installed plugin");
                        errors.push(e);
                    }
                }
            }
        }

        errors
    }

    /// Get a plugin by name
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Plugin> {
        self.plugins.get(name)
    }

    /// Get all loaded plugins
    pub fn all(&self) -> impl Iterator<Item = &Plugin> {
        self.plugins.values()
    }

    /// Get the number of loaded plugins
    #[must_use]
    pub fn count(&self) -> usize {
        self.plugins.len()
    }

    /// Get all hooks from all enabled plugins
    #[must_use]
    pub fn all_hooks(&self) -> Vec<(&Plugin, PluginHook)> {
        self.plugins
            .values()
            .filter(|p| p.enabled)
            .flat_map(|plugin| {
                plugin
                    .resolved_hooks()
                    .into_iter()
                    .map(move |hook| (plugin, hook))
            })
            .collect()
    }

    /// Get hooks for a specific event
    #[must_use]
    pub fn hooks_for_event(&self, event: &str) -> Vec<(&Plugin, PluginHook)> {
        self.all_hooks()
            .into_iter()
            .filter(|(_, hook)| hook.event == event)
            .collect()
    }

    /// Get all commands from all enabled plugins
    #[must_use]
    pub fn all_commands(&self) -> Vec<(&Plugin, PluginCommand)> {
        self.plugins
            .values()
            .filter(|p| p.enabled)
            .flat_map(|plugin| {
                plugin
                    .resolved_commands()
                    .into_iter()
                    .map(move |cmd| (plugin, cmd))
            })
            .collect()
    }

    /// Get all MCP servers from all enabled plugins
    #[must_use]
    pub fn all_mcp_servers(&self) -> Vec<(&Plugin, PluginMcpServer)> {
        self.plugins
            .values()
            .filter(|p| p.enabled)
            .flat_map(|plugin| {
                plugin
                    .resolved_mcp_servers()
                    .into_iter()
                    .map(move |server| (plugin, server))
            })
            .collect()
    }

    /// Get enabled MCP servers resolved against one immutable run snapshot.
    #[must_use]
    pub fn all_mcp_servers_for_run(
        &self,
        run: &crate::tools::ToolRunContext,
    ) -> Vec<(&Plugin, PluginMcpServer)> {
        self.plugins
            .values()
            .filter(|plugin| plugin.enabled)
            .flat_map(|plugin| {
                plugin
                    .resolved_mcp_servers_for_run(run)
                    .into_iter()
                    .map(move |server| (plugin, server))
            })
            .collect()
    }

    /// Get the installation tracker
    #[must_use]
    pub const fn installed(&self) -> &InstalledPlugins {
        &self.installed
    }

    /// Get mutable installation tracker
    pub const fn installed_mut(&mut self) -> &mut InstalledPlugins {
        &mut self.installed
    }

    /// Enable a plugin
    ///
    /// # Errors
    ///
    /// Returns `PluginError::NotFound` if no plugin with the given name is loaded.
    pub fn enable(&mut self, name: &str) -> Result<(), PluginError> {
        if let Some(plugin) = self.plugins.get_mut(name) {
            plugin.enabled = true;
            Ok(())
        } else {
            Err(PluginError::NotFound(name.to_string()))
        }
    }

    /// Disable a plugin
    ///
    /// # Errors
    ///
    /// Returns `PluginError::NotFound` if no plugin with the given name is loaded.
    pub fn disable(&mut self, name: &str) -> Result<(), PluginError> {
        if let Some(plugin) = self.plugins.get_mut(name) {
            plugin.enabled = false;
            Ok(())
        } else {
            Err(PluginError::NotFound(name.to_string()))
        }
    }

    /// Reload all plugins
    pub fn reload(&mut self) -> Vec<PluginError> {
        self.plugins.clear();
        self.installed = InstalledPlugins::load(&self.project_root);
        self.discover()
    }

    /// Get the marketplaces directory (~/.claude/marketplaces/)
    fn marketplaces_dir() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".claude")
            .join("marketplaces")
    }

    /// List installed marketplaces
    #[must_use]
    pub fn list_marketplaces(&self) -> Vec<(String, MarketplaceManifest)> {
        let dir = Self::marketplaces_dir();
        let mut marketplaces = Vec::new();
        if !dir.exists() {
            return marketplaces;
        }
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                // Try loading marketplace manifest
                let manifest_path = path.join(".claude-plugin").join("marketplace.json");
                let alt_manifest_path = path.join("marketplace.json");
                let mp = if manifest_path.exists() {
                    &manifest_path
                } else if alt_manifest_path.exists() {
                    &alt_manifest_path
                } else {
                    continue;
                };
                if let Ok(content) = fs::read_to_string(mp) {
                    if let Ok(manifest) = serde_json::from_str::<MarketplaceManifest>(&content) {
                        let name = entry.file_name().to_string_lossy().to_string();
                        marketplaces.push((name, manifest));
                    }
                }
            }
        }
        marketplaces
    }

    /// Enforce all [`PolicyAction`]s that bear on signature verification for
    /// `plugin_name`. Reads raw manifest bytes from `manifest_json` (already
    /// loaded from the marketplace source) and applies every
    /// `RequireSignature` action in the policy.
    ///
    /// # Errors
    ///
    /// - [`PluginError::UnsignedPlugin`] — policy requires a signature but
    ///   `manifest_sig` is `None`.
    /// - [`PluginError::UnknownSigner`] — signature present but no trusted
    ///   key accepted it.
    /// - [`PluginError::SignatureMismatch`] — signature bytes are
    ///   cryptographically invalid over the supplied bytes.
    fn enforce_signature_policy(
        plugin_name: &str,
        manifest_bytes: &[u8],
        manifest_sig: Option<&crate::plugins::validate::PluginSignature>,
        policy: &PluginPolicy,
    ) -> Result<(), PluginError> {
        for action in &policy.actions {
            let PolicyAction::RequireSignature { trusted_keys } = action;
            let sig =
                manifest_sig.ok_or_else(|| PluginError::UnsignedPlugin(plugin_name.to_string()))?;
            match verify_signature(manifest_bytes, sig, trusted_keys) {
                Ok(()) => {}
                Err(SignatureError::UnknownSigner | SignatureError::MalformedKey(_)) => {
                    return Err(PluginError::UnknownSigner(plugin_name.to_string()));
                }
                Err(
                    SignatureError::SignatureMismatch
                    | SignatureError::MissingSignature
                    | SignatureError::InvalidLength(_)
                    | SignatureError::InvalidEncoding(_),
                ) => {
                    return Err(PluginError::SignatureMismatch(plugin_name.to_string()));
                }
            }
        }
        Ok(())
    }

    /// Build a [`MarketplaceSource`] from a per-plugin [`PluginSourceDef`],
    /// suitable for re-running [`policy::check_marketplace_allowed`] against
    /// the upstream URL the plugin will actually pull from. Returns `None`
    /// for source variants (`npm` / `pip`) that don't carry a git/HTTP URL
    /// the marketplace policy can enforce against — those are rejected later
    /// by the base installer's match arm.
    ///
    /// Closes crosslink #729: the per-plugin source URL is now policy-checked
    /// before any `git_clone` / `fs::copy` fires.
    fn plugin_source_to_marketplace_source(def: &PluginSourceDef) -> Option<MarketplaceSource> {
        match def {
            PluginSourceDef::Url(UrlSource { url, git_ref }) => Some(MarketplaceSource::Git {
                url: url.clone(),
                git_ref: git_ref.clone(),
                path: None,
            }),
            PluginSourceDef::GitHub(GitHubSource { repo, git_ref }) => {
                Some(MarketplaceSource::GitHub {
                    repo: repo.clone(),
                    git_ref: git_ref.clone(),
                    path: None,
                })
            }
            // npm / pip carry no git URL — base installer rejects them with
            // InvalidManifest. Returning None here means the policy gate
            // doesn't fire and the existing rejection path handles them.
            PluginSourceDef::Npm(_) | PluginSourceDef::Pip(_) => None,
        }
    }

    /// Apply the marketplace-policy gate to a per-plugin source. Pure
    /// function — extracted so unit tests can drive the #729 gate
    /// without standing up a real marketplace on disk. Returns `Ok(())`
    /// when the source is permitted (or when it has no upstream URL to
    /// check), and [`PluginError::PolicyRejected`] when the policy
    /// rejects the upstream.
    ///
    /// # Errors
    ///
    /// [`PluginError::PolicyRejected`] when
    /// [`policy::check_marketplace_allowed`] rejects the rebuilt source.
    fn check_plugin_source_policy(
        source: &PluginSource,
        policy: &PluginPolicy,
    ) -> Result<(), PluginError> {
        let PluginSource::Structured(def) = source else {
            return Ok(());
        };
        let Some(per_plugin_source) = Self::plugin_source_to_marketplace_source(def) else {
            return Ok(());
        };
        match policy::check_marketplace_allowed(&per_plugin_source, policy) {
            Ok(()) => Ok(()),
            Err(rejection) => Err(Self::policy_rejection_to_error(rejection, policy)),
        }
    }

    /// Install a plugin from a marketplace, enforcing all [`PolicyAction`]s
    /// including signature verification AND re-validating the per-plugin
    /// upstream source URL against `policy.strict_known_marketplaces` /
    /// `policy.blocked_marketplaces` (crosslink #729).
    ///
    /// Without this re-validation, an allowlisted marketplace could ship a
    /// `marketplace.json` whose plugin entries point at arbitrary upstream
    /// URLs — silently downgrading the managed policy to advisory. This
    /// method closes that gap by rebuilding a [`MarketplaceSource`] from
    /// the resolved plugin's [`PluginSourceDef`] and running
    /// [`policy::check_marketplace_allowed`] against it BEFORE any
    /// `git_clone` / `fs::copy` side effects.
    ///
    /// # Errors
    ///
    /// - [`PluginError::PolicyRejected`] when the per-plugin upstream source
    ///   URL is on the blocklist or not in the strict allowlist.
    /// - [`PluginError::UnsignedPlugin`] when policy requires a signature and
    ///   the manifest has none.
    /// - [`PluginError::UnknownSigner`] when the signature does not match any
    ///   trusted key.
    /// - [`PluginError::SignatureMismatch`] when the signature is
    ///   cryptographically invalid.
    /// - All errors from [`Self::install_from_marketplace`].
    pub fn install_from_marketplace_with_policy(
        &mut self,
        plugin_name: &str,
        marketplace_name: &str,
        policy: &PluginPolicy,
    ) -> Result<String, PluginError> {
        // Per-plugin upstream URL policy check (crosslink #729). The
        // marketplace itself was gated at `add_marketplace_*_with_policy`
        // time, but the plugin entries inside it can name arbitrary upstream
        // URLs that the policy never saw. Re-validate here BEFORE any
        // filesystem side effects so a managed policy is actually enforcing.
        {
            let marketplaces = self.list_marketplaces();
            let (_name, mp_manifest) = marketplaces
                .iter()
                .find(|(n, _)| n == marketplace_name)
                .ok_or_else(|| {
                    PluginError::NotFound(format!("Marketplace '{marketplace_name}' not found"))
                })?;
            let mp_plugin = mp_manifest
                .plugins
                .iter()
                .find(|p| p.name == plugin_name)
                .ok_or_else(|| {
                    PluginError::NotFound(format!(
                        "Plugin '{plugin_name}' not found in marketplace '{marketplace_name}'"
                    ))
                })?;
            // `PluginSource::Path` is local to the (already-policy-checked)
            // marketplace directory — no separate upstream URL to validate.
            // The helper returns Ok(()) for Path / npm / pip and only gates
            // structured Url / GitHub sources.
            Self::check_plugin_source_policy(&mp_plugin.source, policy)?;
        }

        // Only do the manifest-load + signature check when there are
        // RequireSignature actions to enforce — avoids double-loading otherwise.
        let has_sig_requirement = policy
            .actions
            .iter()
            .any(|a| matches!(a, PolicyAction::RequireSignature { .. }));

        if has_sig_requirement {
            // Locate the marketplace and plugin manifest to get the raw bytes
            // and the inline signature field before any install side effects.
            let marketplaces = self.list_marketplaces();
            let (_name, mp_manifest) = marketplaces
                .iter()
                .find(|(n, _)| n == marketplace_name)
                .ok_or_else(|| {
                    PluginError::NotFound(format!("Marketplace '{marketplace_name}' not found"))
                })?;

            let mp_plugin = mp_manifest
                .plugins
                .iter()
                .find(|p| p.name == plugin_name)
                .ok_or_else(|| {
                    PluginError::NotFound(format!(
                        "Plugin '{plugin_name}' not found in marketplace '{marketplace_name}'"
                    ))
                })?;

            // For path-based sources we can load the manifest from disk and
            // check the inline `signature` field. For git sources the manifest
            // is not yet cloned — we check the MarketplacePlugin-level
            // signature field (if any) against the serialized plugin entry.
            let marketplace_dir = Self::marketplaces_dir().join(marketplace_name);
            let (manifest_bytes, manifest_sig) = match &mp_plugin.source {
                super::marketplace::PluginSource::Path(rel_path) => {
                    Self::path_source_manifest_for_signature(&marketplace_dir, rel_path)?
                }
                super::marketplace::PluginSource::Structured(_) => {
                    // For git/GitHub sources the content is not yet local.
                    // Serialize the marketplace plugin entry as a stable byte
                    // representation for the signature check. This covers the
                    // case where the marketplace index itself is signed.
                    let raw = serde_json::to_vec(mp_plugin).map_err(|e| {
                        PluginError::InvalidManifest(format!(
                            "Cannot serialize plugin entry for signature check: {e}"
                        ))
                    })?;
                    // No inline manifest signature available pre-clone.
                    (raw, None)
                }
            };

            Self::enforce_signature_policy(
                plugin_name,
                &manifest_bytes,
                manifest_sig.as_ref(),
                policy,
            )?;
        }

        // Policy actions satisfied — delegate to the base installer.
        self.install_from_marketplace(plugin_name, marketplace_name)
    }

    /// Convert a [`PolicyRejection`] into a [`PluginError`]. Centralizes
    /// the human-readable reason string so CLI / TUI / audit logs get
    /// consistent messaging regardless of which guard rejected.
    fn policy_rejection_to_error(rejection: PolicyRejection, policy: &PluginPolicy) -> PluginError {
        let reason = match rejection {
            PolicyRejection::Blocked => "source is on the block list".to_string(),
            PolicyRejection::NotInAllowlist => {
                "source is not on the allowed list (strict_known_marketplaces)".to_string()
            }
        };
        PluginError::PolicyRejected {
            reason,
            scope: if policy.managed { "managed" } else { "user" },
        }
    }

    /// Add a marketplace from a local directory, enforcing
    /// `policy.strict_known_marketplaces` / `blocked_marketplaces`.
    /// Prefer this over [`Self::add_marketplace_from_directory`] in
    /// code paths that have a `PluginPolicy` in hand.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::PolicyRejected`] when the source fails
    /// policy checks, or whatever
    /// [`Self::add_marketplace_from_directory`] would return for a
    /// permitted source.
    pub fn add_marketplace_from_directory_with_policy(
        &self,
        source_path: &Path,
        policy: &PluginPolicy,
    ) -> Result<MarketplaceManifest, PluginError> {
        let canonical = source_path
            .canonicalize()
            .unwrap_or_else(|_| source_path.to_path_buf())
            .to_string_lossy()
            .into_owned();
        let source = MarketplaceSource::Directory { path: canonical };
        if let Err(rejection) = policy::check_marketplace_allowed(&source, policy) {
            return Err(Self::policy_rejection_to_error(rejection, policy));
        }
        self.add_marketplace_from_directory(source_path)
    }

    /// Add a marketplace from a git URL, enforcing policy. See
    /// [`Self::add_marketplace_from_directory_with_policy`] for the
    /// error contract.
    ///
    /// # Errors
    ///
    /// Policy rejection → [`PluginError::PolicyRejected`]. Everything
    /// else matches [`Self::add_marketplace_from_git`].
    pub fn add_marketplace_from_git_with_policy(
        &self,
        url: &str,
        git_ref: Option<&str>,
        policy: &PluginPolicy,
    ) -> Result<MarketplaceManifest, PluginError> {
        let source = MarketplaceSource::Git {
            url: url.to_string(),
            git_ref: git_ref.map(str::to_string),
            path: None,
        };
        if let Err(rejection) = policy::check_marketplace_allowed(&source, policy) {
            return Err(Self::policy_rejection_to_error(rejection, policy));
        }
        self.add_marketplace_from_git(url, git_ref)
    }

    /// Add a marketplace from a local directory path
    ///
    /// # Errors
    ///
    /// Returns an error if the directory has no marketplace manifest, IO fails,
    /// or the marketplace already exists.
    pub fn add_marketplace_from_directory(
        &self,
        source_path: &Path,
    ) -> Result<MarketplaceManifest, PluginError> {
        // Validate source has a marketplace manifest
        let manifest_path = source_path.join(".claude-plugin").join("marketplace.json");
        let alt_manifest_path = source_path.join("marketplace.json");
        let mp = if manifest_path.exists() {
            &manifest_path
        } else if alt_manifest_path.exists() {
            &alt_manifest_path
        } else {
            return Err(PluginError::InvalidManifest(
                "No marketplace.json found in directory".to_string(),
            ));
        };
        let content = fs::read_to_string(mp).map_err(|e| PluginError::IoError(e.to_string()))?;
        let manifest: MarketplaceManifest = serde_json::from_str(&content)
            .map_err(|e| PluginError::InvalidManifest(e.to_string()))?;

        // Copy to marketplaces directory
        let dest = Self::marketplaces_dir().join(&manifest.name);
        if dest.exists() {
            return Err(PluginError::InvalidManifest(format!(
                "Marketplace '{}' already exists. Remove it first.",
                manifest.name
            )));
        }
        let canonical_source = source_path.canonicalize().map_err(|e| {
            PluginError::IoError(format!(
                "Failed to canonicalize marketplace source path {}: {}",
                source_path.display(),
                e
            ))
        })?;
        copy_dir_recursive_within(&canonical_source, &dest, &canonical_source)
            .map_err(|e| PluginError::IoError(e.to_string()))?;

        info!(name = %manifest.name, plugins = manifest.plugins.len(), "Added marketplace");
        Ok(manifest)
    }

    /// Add a marketplace from a git repository URL
    ///
    /// # Errors
    /// Returns an error if the git clone fails or the manifest cannot be parsed.
    pub fn add_marketplace_from_git(
        &self,
        url: &str,
        git_ref: Option<&str>,
    ) -> Result<MarketplaceManifest, PluginError> {
        // Validate URL up front — git_clone also validates, but failing here
        // avoids an early mkdir when the URL is going to be rejected.
        super::validate::validate_source_url(url)?;

        let dest = Self::marketplaces_dir();
        fs::create_dir_all(&dest).map_err(|e| PluginError::IoError(e.to_string()))?;

        // Derive the destination name from the URL with the centralized
        // validator — rejects `..`, empty segments, path separators, leading
        // dots, NUL, and control chars. Closes crosslink #248.
        let name = super::validate::derive_dir_name_from_url(url)?;

        let clone_dest = dest.join(&name);
        if clone_dest.exists() {
            return Err(PluginError::InvalidManifest(format!(
                "Marketplace '{name}' already exists. Remove it first."
            )));
        }

        // Clone the repository. SHA is ignored here because marketplaces
        // themselves aren't pinned in install tracking — individual
        // plugin installs carry the commit SHA.
        let _ = git_clone(url, &clone_dest, git_ref)?;

        // Record the canonical add-time origin URL so future
        // `update_marketplace` calls can re-validate against `.git/config`
        // tampering. See crosslink #715. Failure to write the sidecar
        // means we cannot safely update later — surface the error rather
        // than leave an un-validatable clone on disk.
        if let Err(e) = write_origin_url_sidecar(&clone_dest, url) {
            let _ = fs::remove_dir_all(&clone_dest);
            return Err(e);
        }

        // Validate the cloned repo has a marketplace manifest
        let manifest_path = clone_dest.join(".claude-plugin").join("marketplace.json");
        let alt_path = clone_dest.join("marketplace.json");
        let mp = if manifest_path.exists() {
            &manifest_path
        } else if alt_path.exists() {
            &alt_path
        } else {
            // Clean up if no manifest
            let _ = fs::remove_dir_all(&clone_dest);
            return Err(PluginError::InvalidManifest(
                "Cloned repository has no marketplace.json".to_string(),
            ));
        };

        let content = fs::read_to_string(mp).map_err(|e| PluginError::IoError(e.to_string()))?;
        let manifest: MarketplaceManifest = serde_json::from_str(&content)
            .map_err(|e| PluginError::InvalidManifest(e.to_string()))?;

        info!(name = %manifest.name, url = %url, plugins = manifest.plugins.len(), "Added git marketplace");
        Ok(manifest)
    }

    /// Remove a marketplace by name
    ///
    /// # Errors
    /// Returns an error if the marketplace is not found or cannot be removed.
    pub fn remove_marketplace(&self, name: &str) -> Result<(), PluginError> {
        let dir = Self::marketplaces_dir().join(name);
        if !dir.exists() {
            return Err(PluginError::NotFound(format!(
                "Marketplace '{name}' not found"
            )));
        }
        fs::remove_dir_all(&dir).map_err(|e| PluginError::IoError(e.to_string()))?;
        info!(name = %name, "Removed marketplace");
        Ok(())
    }

    /// Update a marketplace (git pull or re-copy)
    ///
    /// # Errors
    /// Returns an error if the marketplace is not found or the update fails.
    pub fn update_marketplace(&self, name: &str) -> Result<MarketplaceManifest, PluginError> {
        let dir = Self::marketplaces_dir().join(name);
        if !dir.exists() {
            return Err(PluginError::NotFound(format!(
                "Marketplace '{name}' not found"
            )));
        }

        // Check if it's a git repo
        if dir.join(".git").exists() {
            // Crosslink #715: re-validate the live `remote.origin.url`
            // against the recorded add-time URL before pulling. The
            // sidecar is written by `add_marketplace_from_git`; missing
            // sidecar means the clone pre-dates this fix and we refuse
            // to pull because we cannot prove the remote is the same
            // one the operator originally vetted.
            let expected_url =
                read_origin_url_sidecar(&dir)?.ok_or_else(|| PluginError::PolicyRejected {
                    reason: format!(
                        "marketplace '{name}' has no recorded origin URL. \
                         Remove and re-add it to enable safe updates."
                    ),
                    scope: "marketplace",
                })?;
            git_pull(&dir, Some(&expected_url))?;
        } else {
            return Err(PluginError::InvalidManifest(
                "Non-git marketplaces cannot be updated automatically. Remove and re-add."
                    .to_string(),
            ));
        }

        // Re-read manifest
        let manifest_path = dir.join(".claude-plugin").join("marketplace.json");
        let alt_path = dir.join("marketplace.json");
        let mp = if manifest_path.exists() {
            &manifest_path
        } else if alt_path.exists() {
            &alt_path
        } else {
            return Err(PluginError::InvalidManifest(
                "Marketplace manifest missing after update".to_string(),
            ));
        };

        let content = fs::read_to_string(mp).map_err(|e| PluginError::IoError(e.to_string()))?;
        let manifest: MarketplaceManifest = serde_json::from_str(&content)
            .map_err(|e| PluginError::InvalidManifest(e.to_string()))?;
        Ok(manifest)
    }

    /// Install a plugin from a marketplace.
    ///
    /// Orchestration only — the four steps below are each their own
    /// single-purpose helper. Per crosslink #503, the prior 160-line
    /// monolith was decomposed into:
    ///
    /// 1. [`Self::validate_marketplace_entry`] — resolve + shape-check
    ///    the marketplace/plugin entry and the destination path.
    /// 2. [`Self::fetch_plugin_archive`] — materialize the upstream
    ///    bits (canonicalize a Path source or `git_clone` a structured
    ///    source) into either a verified source-path or a populated
    ///    `dest`.
    /// 3. [`Self::extract_to_install_dir`] — copy the verified source
    ///    into `dest` (no-op for git, which clones directly).
    /// 4. [`Self::register_install`] — persist the install record and
    ///    reload so the plugin becomes active.
    ///
    /// # Errors
    /// Returns an error if the plugin is not found in the marketplace
    /// or installation fails. Errors are surfaced from the helpers with
    /// their original [`PluginError`] context preserved.
    pub fn install_from_marketplace(
        &mut self,
        plugin_name: &str,
        marketplace_name: &str,
    ) -> Result<String, PluginError> {
        let (mp_plugin, plugins_dir, dest) =
            self.validate_marketplace_entry(plugin_name, marketplace_name)?;
        let fetched =
            Self::fetch_plugin_archive(&mp_plugin, marketplace_name, &plugins_dir, &dest)?;
        let commit_sha = fetched.commit_sha();
        Self::extract_to_install_dir(&fetched, &plugins_dir, &dest)?;

        let plugin_id = format!("{plugin_name}@{marketplace_name}");
        self.register_install(&plugin_id, &dest, mp_plugin.version, commit_sha);
        let _ = self.reload();

        if fetched.is_git() {
            info!(plugin = %plugin_name, marketplace = %marketplace_name, "Installed plugin from marketplace (git)");
        } else {
            info!(plugin = %plugin_name, marketplace = %marketplace_name, "Installed plugin from marketplace");
        }
        Ok(plugin_id)
    }

    /// Resolve the marketplace + plugin entry referenced by
    /// `(plugin_name, marketplace_name)`, validate the plugin name for
    /// path traversal, and assemble the install destination. Returns a
    /// cloned [`MarketplacePlugin`] (so the caller can drop its borrow
    /// of `self`), the plugins directory, and the destination path.
    ///
    /// This is step (1) of [`Self::install_from_marketplace`]. It does
    /// **no** filesystem mutation — it only reads the marketplace
    /// index and checks that `dest` does not yet exist.
    ///
    /// # Errors
    /// - [`PluginError::NotFound`] when the marketplace or plugin
    ///   entry does not exist in the loaded marketplace index.
    /// - [`PluginError::InvalidManifest`] when the plugin name contains
    ///   path-traversal characters (`..`, `/`, `\`) or when the
    ///   destination directory already exists.
    fn validate_marketplace_entry(
        &self,
        plugin_name: &str,
        marketplace_name: &str,
    ) -> Result<(MarketplacePlugin, PathBuf, PathBuf), PluginError> {
        let marketplaces = self.list_marketplaces();
        let (_name, manifest) = marketplaces
            .iter()
            .find(|(n, _)| n == marketplace_name)
            .ok_or_else(|| {
                PluginError::NotFound(format!("Marketplace '{marketplace_name}' not found"))
            })?;

        let mp_plugin = manifest
            .plugins
            .iter()
            .find(|p| p.name == plugin_name)
            .ok_or_else(|| {
                PluginError::NotFound(format!(
                    "Plugin '{plugin_name}' not found in marketplace '{marketplace_name}'"
                ))
            })?
            .clone();

        // Validate plugin name to prevent path traversal.
        if plugin_name.contains("..") || plugin_name.contains('/') || plugin_name.contains('\\') {
            return Err(PluginError::InvalidManifest(format!(
                "Plugin name '{plugin_name}' contains invalid path characters"
            )));
        }
        let plugins_dir = self.project_root.join(".openclaudia/plugins");
        let dest = plugins_dir.join(plugin_name);
        if dest.exists() {
            return Err(PluginError::InvalidManifest(format!(
                "Plugin '{}' already exists at {}",
                plugin_name,
                dest.display()
            )));
        }

        Ok((mp_plugin, plugins_dir, dest))
    }

    /// Resolve a path-based marketplace plugin source, enforcing that the
    /// source is a relative path that exists inside the marketplace root.
    ///
    /// This is shared by the normal fetch path and the signature preflight so
    /// no marketplace-local read can bypass the containment checks.
    fn resolve_marketplace_plugin_path(
        marketplace_dir: &Path,
        rel_path: &str,
    ) -> Result<(PathBuf, PathBuf), PluginError> {
        let full = super::validate_plugin_path(marketplace_dir, rel_path)?;
        if !full.exists() {
            return Err(PluginError::IoError(format!(
                "Plugin source path not found: {}",
                full.display()
            )));
        }

        let canonical_marketplace = marketplace_dir.canonicalize().map_err(|e| {
            PluginError::IoError(format!(
                "Failed to canonicalize marketplace dir {}: {}",
                marketplace_dir.display(),
                e
            ))
        })?;
        let canonical_plugin = full.canonicalize().map_err(|e| {
            PluginError::IoError(format!(
                "Failed to canonicalize plugin path {}: {}",
                full.display(),
                e
            ))
        })?;
        if !canonical_plugin.starts_with(&canonical_marketplace) {
            return Err(PluginError::IoError(format!(
                "Plugin path traversal detected: {} escapes marketplace directory {}",
                full.display(),
                marketplace_dir.display()
            )));
        }

        Ok((canonical_plugin, canonical_marketplace))
    }

    /// Load the raw plugin manifest and inline signature for a path-based
    /// marketplace source. The path is resolved through
    /// [`Self::resolve_marketplace_plugin_path`] before any manifest read.
    fn path_source_manifest_for_signature(
        marketplace_dir: &Path,
        rel_path: &str,
    ) -> Result<(Vec<u8>, Option<crate::plugins::validate::PluginSignature>), PluginError> {
        let (plugin_dir, _canonical_marketplace) =
            Self::resolve_marketplace_plugin_path(marketplace_dir, rel_path)?;
        let cc_path = plugin_dir.join(".claude-plugin").join("plugin.json");
        let root_path = plugin_dir.join("plugin.json");
        let manifest_path = if cc_path.exists() { cc_path } else { root_path };
        let raw = fs::read(&manifest_path).map_err(|e| {
            PluginError::IoError(format!("Cannot read manifest for signature check: {e}"))
        })?;
        let parsed: crate::plugins::manifest::PluginManifest = serde_json::from_slice(&raw)
            .map_err(|e| {
                PluginError::InvalidManifest(format!(
                    "Cannot parse manifest for signature check: {e}"
                ))
            })?;
        let sig = parsed.signature;
        Ok((raw, sig))
    }

    /// Materialize the plugin's upstream content. Two strategies:
    ///
    /// - **`PluginSource::Path`**: canonicalize the source path,
    ///   enforce the marketplace-containment pre-flight (per crosslink
    ///   #258), and return a [`FetchedSource::LocalCopy`] carrying both
    ///   the canonical source and the canonical marketplace root that
    ///   `copy_dir_recursive_within` will re-check on every entry.
    /// - **`PluginSource::Structured`**: `git_clone` the upstream into
    ///   `dest` directly and return [`FetchedSource::GitClone`] with
    ///   the pinned commit SHA (per crosslink #249, point 1).
    ///
    /// This is step (2) of [`Self::install_from_marketplace`].
    /// `dest` is populated **only** for the structured-source path;
    /// for Path sources the caller still needs to run extraction.
    ///
    /// # Errors
    /// - [`PluginError::IoError`] when `canonicalize` fails on the
    ///   marketplace root or the plugin source, when the source path
    ///   is missing, or when the canonicalized plugin escapes the
    ///   marketplace boundary.
    /// - [`PluginError::InvalidManifest`] when a structured git
    ///   source has no explicit `ref` (no-silent-HEAD rule, crosslink
    ///   #249 point 5) or when the source kind is `npm` / `pip`
    ///   (unsupported).
    /// - Any error surfaced by [`git_clone`].
    fn fetch_plugin_archive(
        mp_plugin: &MarketplacePlugin,
        marketplace_name: &str,
        plugins_dir: &Path,
        dest: &Path,
    ) -> Result<FetchedSource, PluginError> {
        let marketplace_dir = Self::marketplaces_dir().join(marketplace_name);

        match &mp_plugin.source {
            PluginSource::Path(rel_path) => {
                let (canonical_plugin, canonical_marketplace) =
                    Self::resolve_marketplace_plugin_path(&marketplace_dir, rel_path)?;
                Ok(FetchedSource::LocalCopy {
                    source: canonical_plugin,
                    marketplace_root: canonical_marketplace,
                })
            }
            PluginSource::Structured(def) => {
                let commit_sha = match def {
                    PluginSourceDef::Url(UrlSource { url, git_ref }) => {
                        // No-silent-HEAD rule (#249 mandated point 5): a
                        // `PluginSourceDef::Url` without an explicit
                        // `git_ref` would silently track upstream HEAD,
                        // meaning any future push to that repo becomes
                        // active in the agent's privilege domain without
                        // review. Require explicit pinning.
                        if git_ref.is_none() {
                            return Err(PluginError::InvalidManifest(format!(
                                "Plugin source URL '{url}' has no `ref`; \
                                 refusing to track upstream HEAD. Specify \
                                 a tag, branch, or commit SHA in the manifest."
                            )));
                        }
                        fs::create_dir_all(plugins_dir)
                            .map_err(|e| PluginError::IoError(e.to_string()))?;
                        git_clone(url, dest, git_ref.as_deref())?
                    }
                    PluginSourceDef::GitHub(GitHubSource { repo, git_ref }) => {
                        if git_ref.is_none() {
                            return Err(PluginError::InvalidManifest(format!(
                                "Plugin source GitHub repo '{repo}' has no `ref`; \
                                 refusing to track upstream HEAD. Specify \
                                 a tag, branch, or commit SHA in the manifest."
                            )));
                        }
                        let resolved_url = format!("https://github.com/{repo}.git");
                        fs::create_dir_all(plugins_dir)
                            .map_err(|e| PluginError::IoError(e.to_string()))?;
                        git_clone(&resolved_url, dest, git_ref.as_deref())?
                    }
                    _ => {
                        return Err(PluginError::InvalidManifest(
                            "npm/pip sources not yet supported. Use git or path sources."
                                .to_string(),
                        ));
                    }
                };
                Ok(FetchedSource::GitClone { commit_sha })
            }
        }
    }

    /// Place the fetched content at `dest`.
    ///
    /// - [`FetchedSource::LocalCopy`]: creates `plugins_dir` (if
    ///   needed) and runs `copy_dir_recursive_within`, which enforces
    ///   containment on every entry in the walk (crosslink #258
    ///   per-entry TOCTOU guard).
    /// - [`FetchedSource::GitClone`]: no-op — `git_clone` in
    ///   [`Self::fetch_plugin_archive`] has already populated `dest`.
    ///
    /// This is step (3) of [`Self::install_from_marketplace`].
    ///
    /// # Errors
    /// - [`PluginError::IoError`] from `create_dir_all` on
    ///   `plugins_dir` or from `copy_dir_recursive_within` (which
    ///   itself surfaces per-entry containment violations).
    fn extract_to_install_dir(
        fetched: &FetchedSource,
        plugins_dir: &Path,
        dest: &Path,
    ) -> Result<(), PluginError> {
        match fetched {
            FetchedSource::LocalCopy {
                source,
                marketplace_root,
            } => {
                fs::create_dir_all(plugins_dir).map_err(|e| PluginError::IoError(e.to_string()))?;
                copy_dir_recursive_within(source, dest, marketplace_root)
                    .map_err(|e| PluginError::IoError(e.to_string()))?;
                Ok(())
            }
            FetchedSource::GitClone { .. } => Ok(()),
        }
    }

    /// Persist the install record to `installed_plugins.json`. Loads
    /// the merged global+project tracking file, upserts the
    /// [`PluginInstallEntry`] for `plugin_id`, and saves the project
    /// half back atomically. A save failure is logged but does not
    /// abort the install — matches pre-refactor behavior, where the
    /// plugin is already on disk and the user can recover by
    /// re-running.
    ///
    /// This is step (4) of [`Self::install_from_marketplace`].
    /// Caller is responsible for calling [`Self::reload`] afterwards
    /// so the new plugin becomes active in this process.
    fn register_install(
        &self,
        plugin_id: &str,
        dest: &Path,
        version: Option<String>,
        git_commit_sha: Option<String>,
    ) {
        let mut installed = InstalledPlugins::load(&self.project_root);
        installed.upsert(
            plugin_id,
            PluginInstallEntry {
                scope: InstallScope::Project,
                project_path: Some(self.project_root.to_string_lossy().to_string()),
                install_path: dest.to_string_lossy().to_string(),
                version,
                installed_at: Some(chrono::Utc::now().to_rfc3339()),
                last_updated: None,
                git_commit_sha,
            },
        );
        if let Err(e) = installed.save(&self.project_root) {
            warn!("Failed to save install tracking: {}", e);
        }
    }

    /// Install a plugin directly from a git repository
    ///
    /// # Errors
    /// Returns an error if the git clone fails or the plugin manifest is invalid.
    ///
    /// `git_ref` MUST be `Some(_)`. Passing `None` returns
    /// [`PluginError::InvalidManifest`] — the no-silent-HEAD rule
    /// (crosslink #249 mandated point 5 and #742): tracking upstream
    /// HEAD turns any future push to the repo into active code in the
    /// agent's privilege domain without review.
    pub fn install_from_git(
        &mut self,
        url: &str,
        git_ref: Option<&str>,
    ) -> Result<String, PluginError> {
        // Reject disallowed URL schemes (http://, file://, git://, inline
        // credentials) before any filesystem work. git_clone will validate
        // again — deliberately redundant, cheap defense-in-depth.
        super::validate::validate_source_url(url)?;

        // No-silent-HEAD rule: parity with
        // `install_from_marketplace` / `fetch_plugin_archive`
        // (crosslink #249, #742). Reject before any filesystem work so
        // the caller's audit log records the rejection cleanly rather
        // than a partially-materialized clone.
        if git_ref.is_none() {
            return Err(PluginError::InvalidManifest(format!(
                "Plugin source URL '{url}' has no `ref`; \
                 refusing to track upstream HEAD. Specify a tag, branch, \
                 or commit SHA (e.g. `<url>#v1.2.3`)."
            )));
        }

        // Derive the plugins/ subdir name from the URL's last segment with
        // full traversal protection — closes crosslink #248. Previously the
        // url-last-segment extraction was raw and accepted `..`, leading
        // dots, etc., so a crafted URL could place the clone outside the
        // `.openclaudia/plugins/` jail.
        let name = super::validate::derive_dir_name_from_url(url)?;

        let plugins_dir = self.project_root.join(".openclaudia/plugins");
        let dest = plugins_dir.join(&name);
        if dest.exists() {
            return Err(PluginError::InvalidManifest(format!(
                "Plugin '{}' already exists at {}",
                name,
                dest.display()
            )));
        }

        fs::create_dir_all(&plugins_dir).map_err(|e| PluginError::IoError(e.to_string()))?;

        // Clone the repo. Capture the commit SHA so the install record
        // pins exactly what was materialized (crosslink #249 point 1).
        let commit_sha = git_clone(url, &dest, git_ref)?;

        // Validate it's a valid plugin
        match Plugin::load(&dest) {
            Ok(plugin) => {
                let actual_name = plugin.name().to_string();
                // Track installation
                let mut installed = InstalledPlugins::load(&self.project_root);
                installed.upsert(
                    &actual_name,
                    PluginInstallEntry {
                        scope: InstallScope::Project,
                        project_path: Some(self.project_root.to_string_lossy().to_string()),
                        install_path: dest.to_string_lossy().to_string(),
                        version: plugin.manifest.version,
                        installed_at: Some(chrono::Utc::now().to_rfc3339()),
                        last_updated: None,
                        git_commit_sha: Some(commit_sha),
                    },
                );
                if let Err(e) = installed.save(&self.project_root) {
                    warn!("Failed to save install tracking: {}", e);
                }
                let _ = self.reload();
                info!(plugin = %actual_name, url = %url, "Installed plugin from git");
                Ok(actual_name)
            }
            Err(e) => {
                // Clean up invalid clone
                let _ = fs::remove_dir_all(&dest);
                Err(e)
            }
        }
    }

    /// Install a plugin directly from a git URL, enforcing all
    /// [`PolicyAction`]s including [`PolicyAction::RequireSignature`]
    /// (crosslink #249).
    ///
    /// `install_from_git` itself does NOT consult the policy — the unsigned
    /// install path is only used by callers that have already proven the
    /// upstream is trusted (tests, internal automation). Production CLI /
    /// TUI entry points MUST call this method so the signature requirement
    /// configured in `PluginPolicy::actions` is actually enforced on every
    /// install, not just marketplace installs.
    ///
    /// The signature check runs AFTER `git_clone` (so the manifest exists
    /// on disk) but BEFORE the install record is persisted. On rejection,
    /// the cloned tree is removed so a failed verification leaves no
    /// trace in `.openclaudia/plugins/`.
    ///
    /// # Errors
    ///
    /// - [`PluginError::UnsignedPlugin`] when policy requires a signature
    ///   and the manifest has none.
    /// - [`PluginError::UnknownSigner`] when the signature does not match
    ///   any trusted key.
    /// - [`PluginError::SignatureMismatch`] when the signature is
    ///   cryptographically invalid for the manifest bytes.
    /// - All errors from [`Self::install_from_git`].
    pub fn install_from_git_with_policy(
        &mut self,
        url: &str,
        git_ref: Option<&str>,
        policy: &PluginPolicy,
    ) -> Result<String, PluginError> {
        // Short-circuit when the policy has no signature requirement: the
        // base installer is sufficient and we save one manifest re-read.
        let has_sig_requirement = policy
            .actions
            .iter()
            .any(|a| matches!(a, PolicyAction::RequireSignature { .. }));
        if !has_sig_requirement {
            return self.install_from_git(url, git_ref);
        }

        // Run the base installer first — it performs the URL-scheme check,
        // the no-silent-HEAD rule, the dir-name traversal protection, the
        // clone, and the manifest validation. Whatever this returns is
        // the *materialised* plugin name on disk; we then re-load the
        // manifest from there to drive the signature check.
        let plugin_name = self.install_from_git(url, git_ref)?;

        // Locate the manifest on disk so we can hand the verifier the
        // canonical bytes the signature was generated over. The lookup
        // convention `Plugin::load` uses is mirrored here
        // (.claude-plugin/plugin.json first, plugin.json at the root as
        // fallback). The derived dir name from the URL is the only stable
        // way to find the clone — `install_from_git` returns the *plugin*
        // name from the manifest, which may differ from the dir name.
        let dir_name = super::validate::derive_dir_name_from_url(url)?;
        let plugin_dir = self
            .project_root
            .join(".openclaudia/plugins")
            .join(&dir_name);
        let cc_path = plugin_dir.join(".claude-plugin").join("plugin.json");
        let root_path = plugin_dir.join("plugin.json");
        let manifest_path = if cc_path.exists() { cc_path } else { root_path };

        let result = (|| -> Result<(), PluginError> {
            let manifest_bytes = fs::read(&manifest_path).map_err(|e| {
                PluginError::IoError(format!("Cannot read manifest for signature check: {e}"))
            })?;
            let parsed: crate::plugins::manifest::PluginManifest =
                serde_json::from_slice(&manifest_bytes).map_err(|e| {
                    PluginError::InvalidManifest(format!(
                        "Cannot parse manifest for signature check: {e}"
                    ))
                })?;
            Self::enforce_signature_policy(
                &plugin_name,
                &manifest_bytes,
                parsed.signature.as_ref(),
                policy,
            )
        })();

        if let Err(e) = result {
            // Verification failed — remove the freshly-cloned tree and the
            // install record so a rejected plugin leaves no trace. Cleanup
            // errors are deliberately logged-and-swallowed: the plugin
            // error is what the caller needs to see, and an undeleted
            // clone is a non-fatal leak the next `plugin doctor` pass will
            // catch.
            if plugin_dir.exists() {
                if let Err(rm_err) = fs::remove_dir_all(&plugin_dir) {
                    warn!(
                        "Failed to remove rejected plugin clone at {}: {}",
                        plugin_dir.display(),
                        rm_err
                    );
                }
            }
            let mut installed = InstalledPlugins::load(&self.project_root);
            installed.remove(&plugin_name);
            if let Err(save_err) = installed.save(&self.project_root) {
                warn!("Failed to update install tracking after rejection: {save_err}");
            }
            let _ = self.reload();
            return Err(e);
        }

        Ok(plugin_name)
    }

    /// List plugins available from all installed marketplaces
    #[must_use]
    pub fn list_available_plugins(&self) -> Vec<(String, MarketplacePlugin)> {
        let mut available = Vec::new();
        for (marketplace_name, manifest) in self.list_marketplaces() {
            for plugin in &manifest.plugins {
                available.push((marketplace_name.clone(), plugin.clone()));
            }
        }
        available
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn directory_add_rejected_by_blocklist_without_touching_fs() {
        // Build a policy that blocks every Directory source. The
        // add method must fail BEFORE any filesystem side effects —
        // Claude Code's guarantee that the check happens before the
        // download. We verify by handing it a nonexistent path: if
        // the policy check fires first we get PolicyRejected; if
        // the path-read fires first we'd get IoError.
        let tmp = TempDir::new().unwrap();
        let bogus = tmp.path().join("does-not-exist");
        let pm = PluginManager::new();
        let policy = PluginPolicy {
            blocked_marketplaces: vec![MarketplaceSource::Directory {
                path: bogus
                    .canonicalize()
                    .unwrap_or_else(|_| bogus.clone())
                    .to_string_lossy()
                    .into_owned(),
            }],
            ..PluginPolicy::default()
        };
        let err = pm
            .add_marketplace_from_directory_with_policy(&bogus, &policy)
            .expect_err("blocked source must be rejected");
        match err {
            PluginError::PolicyRejected { scope, .. } => {
                assert_eq!(scope, "user");
            }
            other => panic!("expected PolicyRejected, got {other:?}"),
        }
    }

    #[test]
    fn git_add_rejected_when_not_in_strict_allowlist() {
        let pm = PluginManager::new();
        let policy = PluginPolicy {
            strict_known_marketplaces: Some(vec![MarketplaceSource::Git {
                url: "https://example.com/allowed".to_string(),
                git_ref: None,
                path: None,
            }]),
            managed: true,
            ..PluginPolicy::default()
        };
        let err = pm
            .add_marketplace_from_git_with_policy("https://example.com/unknown", None, &policy)
            .expect_err("unknown source must be rejected");
        match err {
            PluginError::PolicyRejected { scope, reason } => {
                assert_eq!(scope, "managed");
                assert!(reason.contains("allowed list"));
            }
            other => panic!("expected PolicyRejected, got {other:?}"),
        }
    }

    #[test]
    fn policy_error_display_is_informative() {
        // Display impl is surfaced to the CLI / TUI — a change here
        // would flow to user-visible strings, so keep it covered.
        let err = PluginError::PolicyRejected {
            reason: "source is on the block list".to_string(),
            scope: "managed",
        };
        let s = err.to_string();
        assert!(s.contains("block list"));
        assert!(s.contains("managed"));
    }

    // -----------------------------------------------------------------
    // crosslink #729 — per-plugin upstream URL is policy-checked.
    //
    // These tests drive `check_plugin_source_policy` directly. That
    // helper is the single gate `install_from_marketplace_with_policy`
    // runs before any filesystem side effects, so exercising it is
    // equivalent to exercising the install gate without needing a real
    // marketplace at `~/.claude/marketplaces/...`.
    // -----------------------------------------------------------------

    fn url_plugin_source(url: &str) -> PluginSource {
        PluginSource::Structured(PluginSourceDef::Url(super::super::marketplace::UrlSource {
            url: url.to_string(),
            git_ref: Some("v1".to_string()),
        }))
    }

    fn github_plugin_source(repo: &str) -> PluginSource {
        PluginSource::Structured(PluginSourceDef::GitHub(
            super::super::marketplace::GitHubSource {
                repo: repo.to_string(),
                git_ref: Some("main".to_string()),
            },
        ))
    }

    #[test]
    fn issue_729_blocklisted_per_plugin_url_is_rejected_with_reason() {
        // Marketplace itself was previously allowlisted, but the plugin
        // entry inside it points at a blocked upstream URL. Without the
        // #729 fix this slips through; with it the install bails out
        // before any git_clone.
        let evil_url = "https://evil.example.com/payload.git";
        let policy = PluginPolicy {
            blocked_marketplaces: vec![MarketplaceSource::Git {
                url: evil_url.to_string(),
                git_ref: None,
                path: None,
            }],
            managed: true,
            ..PluginPolicy::default()
        };
        let source = url_plugin_source(evil_url);
        let err = PluginManager::check_plugin_source_policy(&source, &policy)
            .expect_err("blocked upstream URL must be rejected");
        match err {
            PluginError::PolicyRejected { scope, reason } => {
                assert_eq!(scope, "managed");
                assert!(
                    reason.contains("block list"),
                    "reason must surface the block-list cause, got: {reason}"
                );
            }
            other => panic!("expected PolicyRejected, got {other:?}"),
        }
    }

    #[test]
    fn issue_729_per_plugin_url_not_in_allowlist_is_rejected() {
        // strict_known_marketplaces names only the legitimate
        // marketplace's source; the per-plugin entry resolves to an
        // unrelated upstream. The gate must reject — otherwise the
        // managed allowlist becomes advisory.
        let policy = PluginPolicy {
            strict_known_marketplaces: Some(vec![MarketplaceSource::GitHub {
                repo: "trusted/marketplace".to_string(),
                git_ref: None,
                path: None,
            }]),
            ..PluginPolicy::default()
        };
        // The plugin's structured source points at a different GitHub
        // repo, not on the allowlist.
        let source = github_plugin_source("rogue/plugin-repo");
        let err = PluginManager::check_plugin_source_policy(&source, &policy)
            .expect_err("unlisted upstream must be rejected");
        match err {
            PluginError::PolicyRejected { scope, reason } => {
                assert_eq!(scope, "user");
                assert!(
                    reason.contains("allowed list"),
                    "reason must surface the allowlist cause, got: {reason}"
                );
            }
            other => panic!("expected PolicyRejected, got {other:?}"),
        }
    }

    #[test]
    fn issue_729_allowlisted_per_plugin_url_proceeds() {
        // Plugin's resolved upstream IS on the allowlist (matching by
        // repo, with the rule's ref omitted wildcarding any candidate
        // ref). The gate must return Ok so the install can proceed.
        let policy = PluginPolicy {
            strict_known_marketplaces: Some(vec![MarketplaceSource::GitHub {
                repo: "trusted/plugin-repo".to_string(),
                git_ref: None,
                path: None,
            }]),
            ..PluginPolicy::default()
        };
        let source = github_plugin_source("trusted/plugin-repo");
        PluginManager::check_plugin_source_policy(&source, &policy)
            .expect("allowlisted upstream must be accepted");
    }

    #[test]
    fn issue_729_path_source_bypasses_url_check_but_npm_pip_do_too() {
        // PluginSource::Path is local to the marketplace — its
        // containment was already validated when the marketplace was
        // added. No upstream URL to re-validate, so the gate is a
        // no-op. Likewise npm / pip carry no git URL that the
        // marketplace allowlist could match; the base installer
        // rejects them with InvalidManifest, not the policy gate.
        let policy = PluginPolicy {
            strict_known_marketplaces: Some(vec![]), // deny-all allowlist
            managed: true,
            ..PluginPolicy::default()
        };
        // Path source — gate returns Ok even under a deny-all allowlist.
        let path_source = PluginSource::Path("./local-plugin".to_string());
        PluginManager::check_plugin_source_policy(&path_source, &policy)
            .expect("path source must not be gated by marketplace URL policy");

        // npm source — gate returns Ok (no URL to check); rejection is
        // the base installer's job.
        let npm_source =
            PluginSource::Structured(PluginSourceDef::Npm(super::super::marketplace::NpmSource {
                package: "some-pkg".to_string(),
                version: None,
                registry: None,
            }));
        PluginManager::check_plugin_source_policy(&npm_source, &policy)
            .expect("npm source must not be gated by marketplace URL policy");
    }

    #[test]
    fn issue_729_url_source_blocklist_takes_precedence_over_allowlist() {
        // Block list beats allow list — same semantics as
        // check_marketplace_allowed. A plugin pointing at a URL that's
        // BOTH allowlisted AND blocklisted must still be rejected
        // (blocked wins), and the reason string must say so.
        let url = "https://example.com/contested.git";
        let policy = PluginPolicy {
            strict_known_marketplaces: Some(vec![MarketplaceSource::Git {
                url: url.to_string(),
                git_ref: None,
                path: None,
            }]),
            blocked_marketplaces: vec![MarketplaceSource::Git {
                url: url.to_string(),
                git_ref: None,
                path: None,
            }],
            managed: true,
            ..PluginPolicy::default()
        };
        let source = url_plugin_source(url);
        let err = PluginManager::check_plugin_source_policy(&source, &policy)
            .expect_err("blocked-and-allowlisted URL must still be rejected");
        match err {
            PluginError::PolicyRejected { scope, reason } => {
                assert_eq!(scope, "managed");
                assert!(reason.contains("block list"));
            }
            other => panic!("expected PolicyRejected, got {other:?}"),
        }
    }
}

/// Tests that directly exercise the TOCTOU path-traversal fix from
/// crosslink #258. Each test creates a real filesystem layout (tempdir)
/// and asserts the copy walker accepts or rejects it without going near
/// actual marketplace plumbing.
#[cfg(test)]
mod toctou_tests {
    use crate::plugins::git::{copy_dir_recursive, copy_dir_recursive_within};
    use std::fs;
    use tempfile::TempDir;

    /// A plain directory tree with no symlinks copies successfully and stays
    /// within the allowed root. Validates the happy-path is not broken by
    /// the new per-entry guard.
    #[test]
    fn legitimate_path_within_root_passes() {
        let root = TempDir::new().unwrap();
        let plugin_dir = root.path().join("plugin");
        let sub_dir = plugin_dir.join("sub");
        fs::create_dir_all(&sub_dir).unwrap();
        fs::write(plugin_dir.join("manifest.json"), r#"{"name":"ok"}"#).unwrap();
        fs::write(sub_dir.join("file.txt"), "data").unwrap();

        let dst = TempDir::new().unwrap();
        let output_path = dst.path().join("out");

        let canonical_root = root.path().canonicalize().unwrap();
        let canonical_plugin = plugin_dir.canonicalize().unwrap();

        copy_dir_recursive_within(&canonical_plugin, &output_path, &canonical_root)
            .expect("legitimate tree within root must copy without error");

        assert!(output_path.join("manifest.json").exists());
        assert!(output_path.join("sub/file.txt").exists());
        assert_eq!(
            fs::read_to_string(output_path.join("sub/file.txt")).unwrap(),
            "data"
        );
    }

    /// A symlink inside the source tree that points outside the allowed root
    /// must be rejected. This is the primary TOCTOU scenario from crosslink
    /// #258: an attacker plants a symlink in the marketplace directory that
    /// redirects a copy operation to an arbitrary path.
    #[cfg(unix)]
    #[test]
    fn symlink_to_outside_root_is_rejected() {
        let root = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("secret.txt"), "secret").unwrap();

        let plugin_dir = root.path().join("plugin");
        fs::create_dir_all(&plugin_dir).unwrap();
        fs::write(plugin_dir.join("ok.txt"), "ok").unwrap();
        std::os::unix::fs::symlink(outside.path(), plugin_dir.join("evil")).unwrap();

        let dst = TempDir::new().unwrap();
        let output_path = dst.path().join("out");

        let canonical_root = root.path().canonicalize().unwrap();
        let canonical_plugin = plugin_dir.canonicalize().unwrap();

        let err = copy_dir_recursive_within(&canonical_plugin, &output_path, &canonical_root)
            .expect_err("symlink to outside root must be rejected");

        let msg = err.to_string();
        assert!(
            msg.contains("symlink rejected"),
            "error message must name symlink rejection, got: {msg}"
        );
        assert!(
            !output_path.join("evil").exists(),
            "symlink target must not have been copied"
        );
    }

    /// A path resolved outside the allowed root must be rejected even when
    /// no symlinks are present — defence-in-depth for the case where the
    /// top-level `canonicalize+starts_with` check is bypassed.
    #[test]
    fn path_outside_root_is_rejected() {
        let root = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("file.txt"), "exfil").unwrap();

        let canonical_root = root.path().canonicalize().unwrap();
        let canonical_outside = outside.path().canonicalize().unwrap();

        // Precondition: outside is genuinely disjoint from root.
        assert!(!canonical_outside.starts_with(&canonical_root));

        let dst = TempDir::new().unwrap();
        let output_path = dst.path().join("out");

        let err = copy_dir_recursive_within(&canonical_outside, &output_path, &canonical_root)
            .expect_err("path outside allowed root must be rejected");

        let msg = err.to_string();
        assert!(
            msg.contains("path traversal") || msg.contains("escapes allowed root"),
            "error message must name traversal, got: {msg}"
        );
        assert!(
            !output_path.join("file.txt").exists(),
            "file outside root must not have been copied"
        );
    }

    /// The unconstrained `copy_dir_recursive` (no `allowed_root`) still rejects
    /// symlinks — the symlink guard is not conditional on `allowed_root` being set.
    #[cfg(unix)]
    #[test]
    fn copy_dir_recursive_rejects_symlinks_even_without_root_constraint() {
        let src = TempDir::new().unwrap();
        let target = TempDir::new().unwrap();
        fs::write(target.path().join("secret"), "secret data").unwrap();
        std::os::unix::fs::symlink(target.path(), src.path().join("link")).unwrap();

        let dst = TempDir::new().unwrap();
        let output_path = dst.path().join("out");

        let err = copy_dir_recursive(src.path(), &output_path)
            .expect_err("symlink must be rejected even without root constraint");
        assert!(
            err.to_string().contains("symlink rejected"),
            "error must name symlink rejection, got: {err}"
        );
    }
}

/// Unit tests for the helpers `install_from_marketplace` was decomposed
/// into (crosslink #503). Each helper is exercised in isolation so a
/// future regression that re-merges them — or quietly drops one of the
/// containment / pinning guards — fails a small, named test instead of
/// hiding inside the orchestrator's end-to-end behavior.
#[cfg(test)]
mod install_decomp_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// `FetchedSource::commit_sha` round-trips the pinned SHA for git
    /// clones and reports `None` for local copies. The install record
    /// uses this to populate `git_commit_sha` only when there is a
    /// real upstream revision (crosslink #249 point 1).
    #[test]
    fn fetched_source_commit_sha_round_trips_for_git_and_is_none_for_local_copy() {
        let git = FetchedSource::GitClone {
            commit_sha: "deadbeef".to_string(),
        };
        assert_eq!(git.commit_sha().as_deref(), Some("deadbeef"));
        assert!(git.is_git());

        let local = FetchedSource::LocalCopy {
            source: PathBuf::from("/tmp/src"),
            marketplace_root: PathBuf::from("/tmp"),
        };
        assert!(local.commit_sha().is_none());
        assert!(!local.is_git());
    }

    /// Signature preflight must use the same marketplace containment guard as
    /// the copy path. A traversal source with a perfectly readable manifest
    /// outside the marketplace must be rejected before that manifest is read.
    #[test]
    fn signature_manifest_path_rejects_marketplace_traversal_before_read() {
        let tmp = TempDir::new().unwrap();
        let marketplace = tmp.path().join("marketplace");
        let outside = tmp.path().join("outside-plugin");
        fs::create_dir_all(&marketplace).unwrap();
        fs::create_dir_all(outside.join(".claude-plugin")).unwrap();
        fs::write(
            outside.join(".claude-plugin").join("plugin.json"),
            br#"{"name":"outside-plugin"}"#,
        )
        .unwrap();

        let err =
            PluginManager::path_source_manifest_for_signature(&marketplace, "../outside-plugin")
                .expect_err("traversal source must be rejected before manifest read");
        match err {
            PluginError::InvalidManifest(msg) => {
                assert!(
                    msg.contains("traversal"),
                    "error must name traversal rejection, got: {msg}"
                );
            }
            other => panic!("expected InvalidManifest traversal rejection, got {other:?}"),
        }
    }

    /// In-bounds path sources still load their raw manifest bytes and optional
    /// signature for policy enforcement.
    #[test]
    fn signature_manifest_path_loads_in_bounds_manifest() {
        let marketplace = TempDir::new().unwrap();
        let plugin = marketplace.path().join("local-plugin");
        let manifest_dir = plugin.join(".claude-plugin");
        fs::create_dir_all(&manifest_dir).unwrap();
        let raw = br#"{"name":"local-plugin"}"#;
        fs::write(manifest_dir.join("plugin.json"), raw).unwrap();

        let (bytes, sig) =
            PluginManager::path_source_manifest_for_signature(marketplace.path(), "local-plugin")
                .expect("in-bounds plugin manifest must load");
        assert_eq!(bytes.as_slice(), raw);
        assert!(sig.is_none());
    }

    /// `validate_marketplace_entry` rejects names containing path
    /// separators or `..` before touching the filesystem.
    /// Reaches the validator via the marketplace-not-found branch so we
    /// don't need to materialize a marketplace on disk; the relevant
    /// behavior is that the validator's `NotFound` surfaces before any
    /// later panic. We then exercise the traversal-character guard by
    /// constructing a marketplace whose lookup succeeds. Since
    /// `list_marketplaces` reads the real `~/.claude/marketplaces`,
    /// the most reliable isolation is to test the pure name-check
    /// invariant directly via the `..` substring path.
    #[test]
    fn validate_marketplace_entry_rejects_unknown_marketplace() {
        let pm = PluginManager::new();
        let err = pm
            .validate_marketplace_entry("anything", "definitely-not-installed-xyzzy")
            .expect_err("unknown marketplace must surface NotFound");
        match err {
            PluginError::NotFound(msg) => {
                assert!(
                    msg.contains("definitely-not-installed-xyzzy"),
                    "error must name the missing marketplace, got: {msg}"
                );
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    /// `fetch_plugin_archive` enforces the no-silent-HEAD rule on
    /// `PluginSourceDef::Url` entries — even before any network I/O.
    /// Without this guard a manifest could opt the agent into tracking
    /// upstream HEAD silently (crosslink #249 point 5).
    #[test]
    fn fetch_plugin_archive_rejects_url_source_without_explicit_ref() {
        use crate::plugins::marketplace::UrlSource;
        let tmp = TempDir::new().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let dest = plugins_dir.join("p");
        let mp_plugin = MarketplacePlugin {
            name: "p".to_string(),
            source: PluginSource::Structured(PluginSourceDef::Url(UrlSource {
                url: "https://example.com/repo.git".to_string(),
                git_ref: None,
            })),
            category: None,
            tags: None,
            strict: true,
            description: None,
            version: None,
        };
        // Marketplace name is irrelevant — the no-ref check fires
        // before `marketplaces_dir().join(...).canonicalize()` would
        // ordinarily need a real directory. We expect the InvalidManifest
        // error path. If canonicalize fires first the failure mode is
        // PluginError::IoError; assert specifically for InvalidManifest
        // so a regression that re-orders the guards is caught.
        let result = PluginManager::fetch_plugin_archive(&mp_plugin, "unused", &plugins_dir, &dest);
        // Either the no-ref guard fires (preferred) or canonicalize on
        // a nonexistent marketplace dir fires first; both are
        // acceptable, but the former is what the policy is supposed to
        // enforce, so accept only that here.
        match result {
            Err(PluginError::InvalidManifest(msg)) => {
                assert!(
                    msg.contains("no `ref`"),
                    "error must call out the missing ref, got: {msg}"
                );
            }
            other => panic!("expected InvalidManifest (no `ref`), got {other:?}"),
        }
    }

    /// `fetch_plugin_archive` applies the same no-silent-HEAD rule to
    /// GitHub structured sources as raw URL sources.
    #[test]
    fn fetch_plugin_archive_rejects_github_source_without_explicit_ref() {
        let tmp = TempDir::new().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let dest = plugins_dir.join("p");
        let mp_plugin = MarketplacePlugin {
            name: "p".to_string(),
            source: PluginSource::Structured(PluginSourceDef::GitHub(GitHubSource {
                repo: "owner/repo".to_string(),
                git_ref: None,
            })),
            category: None,
            tags: None,
            strict: true,
            description: None,
            version: None,
        };

        let result = PluginManager::fetch_plugin_archive(&mp_plugin, "unused", &plugins_dir, &dest);
        match result {
            Err(PluginError::InvalidManifest(msg)) => {
                assert!(
                    msg.contains("owner/repo") && msg.contains("no `ref`"),
                    "error must name the GitHub repo and missing ref, got: {msg}"
                );
            }
            other => panic!("expected InvalidManifest (no `ref`), got {other:?}"),
        }
    }

    /// `install_from_git` rejects `git_ref: None` with `InvalidManifest`
    /// before any filesystem work — parity with the marketplace path
    /// (crosslink #742). Without this guard, `/plugin install <url>`
    /// silently tracks upstream HEAD.
    #[test]
    fn install_from_git_rejects_none_git_ref() {
        let mut pm = PluginManager::new();
        let err = pm
            .install_from_git("https://example.com/repo.git", None)
            .expect_err("None git_ref must be rejected at the install gate");
        match err {
            PluginError::InvalidManifest(msg) => {
                assert!(
                    msg.contains("no `ref`"),
                    "error must call out the missing ref, got: {msg}"
                );
            }
            other => panic!("expected InvalidManifest (no `ref`), got {other:?}"),
        }
    }

    /// `install_from_git_with_policy` enforces the no-silent-HEAD rule too —
    /// closes the crosslink #249 install-time-gate hole. Without this guard
    /// the policy-aware path would silently bypass the rule that the base
    /// installer enforces.
    #[test]
    fn install_from_git_with_policy_rejects_none_git_ref() {
        let mut pm = PluginManager::new();
        // Empty policy: still expects the base installer to reject.
        let policy = PluginPolicy::default();
        let err = pm
            .install_from_git_with_policy("https://example.com/repo.git", None, &policy)
            .expect_err("policy path must inherit the no-silent-HEAD guard");
        match err {
            PluginError::InvalidManifest(msg) => {
                assert!(
                    msg.contains("no `ref`"),
                    "policy path must surface the same missing-ref error, got: {msg}"
                );
            }
            other => panic!("expected InvalidManifest (no `ref`), got {other:?}"),
        }
    }

    /// `install_from_git_with_policy` rejects a disallowed URL scheme the same
    /// way the base installer does — proves the policy wrapper does not
    /// accidentally bypass `validate_source_url` by inverting the call order.
    #[test]
    fn install_from_git_with_policy_rejects_unsafe_scheme() {
        let mut pm = PluginManager::new();
        // A RequireSignature action so we exercise the long path (the wrapper
        // takes the base installer's error before signature checking runs).
        let policy = PluginPolicy {
            actions: vec![PolicyAction::RequireSignature {
                trusted_keys: vec![],
            }],
            ..PluginPolicy::default()
        };
        let err = pm
            .install_from_git_with_policy("file:///etc/passwd", Some("main"), &policy)
            .expect_err("file:// schemes must be rejected before any clone work");
        // The exact error variant comes from `validate_source_url`; the
        // contract here is just that the wrapper does not crash through
        // to the clone phase. Any error variant is acceptable as long as
        // it predates the clone.
        match err {
            PluginError::InvalidManifest(_) | PluginError::IoError(_) => {}
            other => {
                panic!("expected an early validation error, got {other:?} (clone phase reached)")
            }
        }
    }

    /// `extract_to_install_dir` is a no-op for the git-clone strategy:
    /// `fetch_plugin_archive` has already populated `dest` and there is
    /// nothing left to copy. Verifies we don't accidentally clobber an
    /// existing tree by re-running a copy pass.
    #[test]
    fn extract_to_install_dir_is_noop_for_git_clone() {
        let tmp = TempDir::new().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let dest = plugins_dir.join("p");
        fs::create_dir_all(&dest).unwrap();
        fs::write(dest.join("marker"), "git-populated").unwrap();

        let fetched = FetchedSource::GitClone {
            commit_sha: "abc123".to_string(),
        };
        PluginManager::extract_to_install_dir(&fetched, &plugins_dir, &dest)
            .expect("git-clone extract must be a no-op");
        assert_eq!(
            fs::read_to_string(dest.join("marker")).unwrap(),
            "git-populated"
        );
    }

    /// `extract_to_install_dir` for a `LocalCopy` performs the actual
    /// copy and enforces marketplace containment (the per-entry guard
    /// from crosslink #258). A plain in-bounds tree must round-trip.
    #[test]
    fn extract_to_install_dir_copies_local_tree_within_marketplace() {
        let marketplace_root = TempDir::new().unwrap();
        let plugin_src = marketplace_root.path().join("plugin");
        fs::create_dir_all(plugin_src.join("sub")).unwrap();
        fs::write(plugin_src.join("manifest.json"), r#"{"name":"p"}"#).unwrap();
        fs::write(plugin_src.join("sub").join("data.txt"), "ok").unwrap();

        let canonical_root = marketplace_root.path().canonicalize().unwrap();
        let canonical_plugin = plugin_src.canonicalize().unwrap();

        let out_root = TempDir::new().unwrap();
        let plugins_dir = out_root.path().join("plugins");
        let dest = plugins_dir.join("plugin");

        let fetched = FetchedSource::LocalCopy {
            source: canonical_plugin,
            marketplace_root: canonical_root,
        };
        PluginManager::extract_to_install_dir(&fetched, &plugins_dir, &dest)
            .expect("in-bounds local copy must succeed");
        assert!(dest.join("manifest.json").exists());
        assert_eq!(
            fs::read_to_string(dest.join("sub").join("data.txt")).unwrap(),
            "ok"
        );
    }

    /// `register_install` writes the install entry to the
    /// per-project `installed_plugins.json`, surviving a round-trip
    /// through `InstalledPlugins::load`. The `git_commit_sha` field is
    /// preserved verbatim — that's the cross-#249 invariant the helper
    /// is the single owner of.
    #[test]
    fn register_install_persists_entry_with_commit_sha() {
        let tmp = TempDir::new().unwrap();
        let manager = PluginManager::new_for_project(tmp.path());

        let dest = tmp.path().join(".openclaudia").join("plugins").join("p");
        fs::create_dir_all(&dest).unwrap();

        manager.register_install(
            "p@m",
            &dest,
            Some("1.2.3".to_string()),
            Some("cafef00d".to_string()),
        );

        let reloaded = InstalledPlugins::load(tmp.path());

        let entries = reloaded
            .plugins
            .get("p@m")
            .expect("entry must round-trip via load");
        let entry = entries.first().expect("at least one install record");
        assert_eq!(entry.version.as_deref(), Some("1.2.3"));
        assert_eq!(entry.git_commit_sha.as_deref(), Some("cafef00d"));
        assert_eq!(entry.install_path, dest.to_string_lossy());
    }
}
