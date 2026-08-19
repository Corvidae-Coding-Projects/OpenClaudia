//! Plugin System - Claude Code-compatible plugin loading and management.
//!
//! Supports the Claude Code plugin format:
//! - `.claude-plugin/plugin.json` manifest
//! - `commands/` directory for slash commands (markdown files)
//! - `hooks/hooks.json` for lifecycle hooks
//! - `.mcp.json` for MCP server configurations
//! - `agents/` directory for agent definitions
//! - `skills/` directory for skill definitions
//!
//! Also supports legacy `OpenClaudia` `manifest.json` format for backward compatibility.
//!
//! Plugin ID format: `plugin-name@marketplace-name`
//!
//! Storage:
//! - `~/.openclaudia/plugins/` (user plugins)
//! - `.openclaudia/plugins/` (project plugins)
//! - Tracked in `~/.openclaudia/plugins/installed_plugins.json`

pub mod git;
pub mod install;
pub mod manager;
pub mod manifest;
pub mod marketplace;
pub mod policy;
pub mod validate;
pub mod zip_cache;

// Re-export all public types for backward compatibility
pub use git::copy_dir_recursive;
pub use install::{InstallScope, InstalledPlugins, PluginInstallEntry};
pub use manager::PluginManager;
pub use manifest::{
    AgentsSpec, CommandMetadata, CommandsSpec, HookEntry, HooksDefinition, HooksSpec,
    HooksSpecEntry, McpServerConfig, McpServersSpec, McpServersSpecEntry, PluginAuthor,
    PluginManifest, SkillsSpec,
};
pub use marketplace::{
    GitHubSource, MarketplaceManifest, MarketplaceMetadata, MarketplacePlugin, MarketplaceSource,
    NpmSource, PipSource, PluginSource, PluginSourceDef, UrlSource,
};
pub use validate::{
    derive_dir_name_from_url, validate_plugin_dir_name, validate_source_url, PublicKey,
    SignatureError,
};

use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Path safety helpers (crosslink #347)
// ---------------------------------------------------------------------------
//
// `validate_plugin_path` is the single chokepoint for turning a manifest-
// supplied relative path into a `PathBuf` that is guaranteed to refer to a
// file under `root`. It rejects:
//
//   * empty strings,
//   * absolute paths (`/etc/passwd`, `C:\windows`),
//   * paths containing `..` components (path traversal),
//   * paths containing Windows prefix or root-dir components,
//   * paths whose final canonical form escapes the plugin root,
//   * any component that is or traverses through a symbolic link
//     (so an attacker cannot drop a symlink inside the plugin tree
//     that points to `/etc/shadow`).
//
// The function is intentionally pure-syntactic when the target does not
// exist (so we can validate manifest paths that point at not-yet-created
// files) and falls back to canonicalization-based containment when it does.
//
// All callers MUST use this helper rather than `root.join(rel)` directly.

/// Reject a single path component if it is unsafe.
const fn component_is_safe(c: &Component<'_>) -> bool {
    matches!(c, Component::Normal(_) | Component::CurDir)
}

/// Validate and resolve `rel` against `root`, refusing traversal,
/// absolute paths, and symlink components.
///
/// On success returns a `PathBuf` joined under `root` and confirmed to
/// stay there.  See module-level docs above for the exact rejection
/// criteria.
fn validate_plugin_path(root: &Path, rel: &str) -> Result<PathBuf, PluginError> {
    if rel.is_empty() {
        return Err(PluginError::InvalidManifest(
            "plugin path cannot be empty".to_string(),
        ));
    }
    // NUL bytes are illegal in *nix paths and are a classic truncation
    // attack on naive C-string-based file handling.
    if rel.contains('\0') {
        return Err(PluginError::InvalidManifest(format!(
            "plugin path contains NUL byte: {rel:?}"
        )));
    }

    let candidate = Path::new(rel);

    // Syntactic pass: reject absolute paths, Windows prefixes, and any
    // `..` traversal *before* we touch the filesystem.
    for comp in candidate.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => {
                return Err(PluginError::InvalidManifest(format!(
                    "plugin path must be relative, got: {rel:?}"
                )));
            }
            Component::ParentDir => {
                return Err(PluginError::InvalidManifest(format!(
                    "plugin path may not contain '..' traversal: {rel:?}"
                )));
            }
            other if !component_is_safe(&other) => {
                return Err(PluginError::InvalidManifest(format!(
                    "plugin path has unsupported component: {rel:?}"
                )));
            }
            _ => {}
        }
    }

    let joined = root.join(candidate);

    // Symlink rejection: walk each existing prefix of `joined` and refuse
    // if any component on the path is a symlink. We accept that `root`
    // itself may be a symlink (the install dir is chosen by the harness)
    // but every component *under* `root` must be a real directory/file.
    let root_components: usize = root.components().count();
    let mut walked = PathBuf::new();
    for (idx, comp) in joined.components().enumerate() {
        walked.push(comp);
        // Skip components that are part of `root` itself.
        if idx < root_components {
            continue;
        }
        // `symlink_metadata` does not follow the final symlink, so this
        // detects "x is a symlink" without dereferencing it.
        match fs::symlink_metadata(&walked) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(PluginError::InvalidManifest(format!(
                    "plugin path component is a symlink (refusing to follow): {}",
                    walked.display()
                )));
            }
            Ok(_) => {}
            // Component does not exist yet — that's fine; canonicalization
            // below will handle the existing-prefix case and the caller
            // will simply find the file missing.
            Err(_) => break,
        }
    }

    // Containment pass: if both root and joined exist, canonicalize and
    // verify the resolved path is still under the canonical root. This
    // catches edge cases that pure-syntactic checks miss (e.g. a
    // case-insensitive filesystem alias).
    if let (Ok(canon_root), Ok(canon_joined)) = (root.canonicalize(), joined.canonicalize()) {
        if !canon_joined.starts_with(&canon_root) {
            return Err(PluginError::InvalidManifest(format!(
                "plugin path escapes plugin root: {rel:?}"
            )));
        }
    }

    Ok(joined)
}

/// Read a plugin file, refusing to follow symlinks.
///
/// Wraps `fs::read_to_string` with an explicit `symlink_metadata` check
/// so an attacker who can plant `.claude-plugin/plugin.json` as a
/// symlink to `/etc/shadow` cannot make us read it.
fn read_plugin_file(path: &Path) -> Result<String, PluginError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(PluginError::InvalidManifest(format!(
            "plugin file is a symlink (refusing to follow): {}",
            path.display()
        ))),
        Ok(_) => fs::read_to_string(path).map_err(|e| PluginError::IoError(e.to_string())),
        Err(e) => Err(PluginError::IoError(e.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Plugin errors
// ---------------------------------------------------------------------------

/// Errors that can occur during plugin operations
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("Manifest not found: {0}")]
    ManifestNotFound(PathBuf),

    #[error("Invalid manifest: {0}")]
    InvalidManifest(String),

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Plugin not found: {0}")]
    NotFound(String),

    #[error("Installation error: {0}")]
    InstallError(String),

    #[error("Marketplace error: {0}")]
    MarketplaceError(String),

    /// Rejected by the installed [`policy::PluginPolicy`]. The inner
    /// string carries a caller-facing reason (blocklist hit /
    /// not-in-allowlist); the `managed` flag lets the CLI distinguish
    /// administrator-applied denials from user preferences.
    #[error("Plugin policy rejected this source: {reason} ({scope})")]
    PolicyRejected { reason: String, scope: &'static str },

    /// The plugin manifest carries no `signature` field but the active
    /// [`policy::PluginPolicy`] includes a
    /// [`policy::PolicyAction::RequireSignature`] action.
    #[error("plugin '{0}' is not signed; policy requires a signature")]
    UnsignedPlugin(String),

    /// A signature was present but none of the trusted keys accepted it —
    /// the plugin was signed by an unknown or untrusted signer.
    #[error("plugin '{0}' signature does not match any trusted key (unknown signer)")]
    UnknownSigner(String),

    /// A signature was present and the correct key was identified, but the
    /// cryptographic verification failed (manifest bytes may have been
    /// tampered with after signing).
    #[error("plugin '{0}' signature is cryptographically invalid (manifest may be tampered)")]
    SignatureMismatch(String),
}

// ---------------------------------------------------------------------------
// Resolved plugin types (for backward-compatible API)
// ---------------------------------------------------------------------------

/// A resolved hook from a plugin, ready for the hook engine
pub struct PluginHook {
    /// Hook event type (`PreToolUse`, `PostToolUse`, `SessionStart`, etc.)
    pub event: String,
    /// Matcher pattern for the hook
    pub matcher: Option<String>,
    /// Hook type (command or prompt)
    pub hook_type: String,
    /// Command to run (for command hooks)
    pub command: Option<String>,
    /// Prompt to inject (for prompt hooks)
    pub prompt: Option<String>,
    /// Timeout in seconds
    pub timeout: u64,
}

/// A resolved command from a plugin
pub struct PluginCommand {
    /// Command name (used as /plugin-name:command)
    pub name: String,
    /// Command description
    pub description: Option<String>,
    /// Markdown content (loaded from file, with front matter stripped)
    pub content: String,
    /// Allowed tools when running this command
    pub allowed_tools: Option<Vec<String>>,
    /// Argument hint (e.g., "<required-arg> [optional-arg]")
    pub argument_hint: Option<String>,
    /// Model override for this command
    pub model: Option<String>,
}

/// Parsed YAML front matter from a command markdown file
#[derive(Deserialize, Default)]
#[serde(default)]
struct CommandFrontMatter {
    description: Option<String>,
    #[serde(
        rename = "allowed-tools",
        deserialize_with = "deserialize_tools_list",
        default
    )]
    allowed_tools: Option<Vec<String>>,
    #[serde(rename = "argument-hint")]
    argument_hint: Option<String>,
    model: Option<String>,
    /// Content after front matter (not deserialized from YAML)
    #[serde(skip)]
    body: String,
}

/// Deserialize allowed-tools from either a YAML array or a comma-separated string.
fn deserialize_tools_list<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let value: Option<serde_yaml::Value> = Option::deserialize(deserializer)?;
    match value {
        Some(serde_yaml::Value::Sequence(seq)) => {
            let tools: Vec<String> = seq
                .into_iter()
                .filter_map(|v| match v {
                    serde_yaml::Value::String(s) => Some(s),
                    _ => None,
                })
                .collect();
            Ok(if tools.is_empty() { None } else { Some(tools) })
        }
        Some(serde_yaml::Value::String(s)) => {
            let tools = crate::permissions::split_allowed_tool_specs_scalar(&s);
            Ok(if tools.is_empty() { None } else { Some(tools) })
        }
        None | Some(_) => Ok(None),
    }
}

/// Parse YAML front matter from a markdown command file.
/// Front matter is delimited by `---` on its own line at the start.
/// Uses `serde_yaml` for robust parsing of the YAML block.
///
/// All slicing is done via `str::get` (panic-safe on non-char boundaries)
/// even though the byte offsets here are produced from ASCII-only patterns
/// (`"---"`, `"\n---"`) — this is defense-in-depth so future edits cannot
/// regress into a panic on adversarial multibyte input. See crosslink #373.
fn parse_command_front_matter(content: &str) -> CommandFrontMatter {
    // Fallback body identical for every error/no-frontmatter branch.
    let fallback = || CommandFrontMatter {
        body: content.to_string(),
        ..Default::default()
    };

    let trimmed = content.trim_start();
    if !trimmed.starts_with("---") {
        return fallback();
    }

    // Skip the opening "---" (3 ASCII bytes) and any leading CR/LF.
    // `str::get` returns `None` on a non-char boundary instead of panicking.
    let Some(after_open_marker) = trimmed.get(3..) else {
        return fallback();
    };
    let after_first = after_open_marker.trim_start_matches(['\r', '\n']);

    // Locate closing "\n---" (4 ASCII bytes).
    let Some(end_pos) = after_first.find("\n---") else {
        // No closing ---, treat entire content as body.
        return fallback();
    };

    // Boundary-safe slice for the YAML block.
    let Some(yaml_block) = after_first.get(..end_pos) else {
        warn!("front matter YAML block slice landed on non-char boundary");
        return fallback();
    };

    // body_start = end_pos + 4 (skip "\n---"). `find` guarantees
    // end_pos + 4 <= after_first.len(), but use `get` so we never panic
    // even if the invariant is later violated.
    let body_start = end_pos.saturating_add(4);
    let Some(body_slice) = after_first.get(body_start..) else {
        warn!("front matter body slice landed on non-char boundary");
        return fallback();
    };
    let body = body_slice.trim_start_matches(['\r', '\n']).to_string();

    match serde_yaml::from_str::<CommandFrontMatter>(yaml_block) {
        Ok(mut fm) => {
            fm.body = body;
            fm
        }
        Err(e) => {
            warn!("Failed to parse command front matter as YAML: {}", e);
            fallback()
        }
    }
}

/// A resolved MCP server from a plugin
pub struct PluginMcpServer {
    /// Server name
    pub name: String,
    /// Transport type (stdio or http)
    pub transport: String,
    /// Command to run (for stdio)
    pub command: Option<String>,
    /// Arguments for the command
    pub args: Vec<String>,
    /// URL (for http)
    pub url: Option<String>,
    /// Environment variables
    pub env: HashMap<String, String>,
    /// Static HTTP headers
    pub headers: HashMap<String, String>,
    /// Dynamic header helper command
    pub headers_helper: Option<String>,
    /// Per-server tool execution timeout in milliseconds
    pub timeout: Option<u64>,
    /// Whether Claude Code should eagerly load this server's tools
    pub always_load: Option<bool>,
}

fn validate_mcp_env_var_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first == '_' || first.is_ascii_alphabetic() => {}
        Some(_) => {
            return Err(format!(
                "environment variable name {name:?} must start with a letter or underscore"
            ));
        }
        None => return Err("environment variable name cannot be empty".to_string()),
    }

    if chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        Ok(())
    } else {
        Err(format!(
            "environment variable name {name:?} may only contain letters, digits, and underscores"
        ))
    }
}

fn expand_mcp_env_vars_with<F>(value: &str, lookup: &F) -> Result<String, String>
where
    F: Fn(&str) -> Result<Option<String>, String>,
{
    let mut expanded = String::with_capacity(value.len());
    let mut rest = value;

    while let Some(start) = rest.find("${") {
        expanded.push_str(&rest[..start]);
        let after_marker = &rest[start + 2..];
        let Some(end) = after_marker.find('}') else {
            return Err("unterminated environment expansion".to_string());
        };

        let expression = &after_marker[..end];
        let (name, default_value) = match expression.split_once(":-") {
            Some((name, default_value)) => (name, Some(default_value)),
            None => (expression, None),
        };
        validate_mcp_env_var_name(name)?;

        match lookup(name)? {
            Some(value) => expanded.push_str(&value),
            None => match default_value {
                Some(value) => expanded.push_str(value),
                None => return Err(format!("required environment variable {name} is not set")),
            },
        }

        rest = &after_marker[end + 1..];
    }

    expanded.push_str(rest);
    Ok(expanded)
}

fn expand_mcp_config_value_with<F>(field: &str, value: &str, lookup: &F) -> Result<String, String>
where
    F: Fn(&str) -> Result<Option<String>, String>,
{
    expand_mcp_env_vars_with(value, lookup).map_err(|err| format!("{field}: {err}"))
}

fn expand_mcp_config_map_with<F>(
    field: &str,
    values: &HashMap<String, String>,
    lookup: &F,
) -> Result<HashMap<String, String>, String>
where
    F: Fn(&str) -> Result<Option<String>, String>,
{
    let expand_entry = |key: &String, value: &String| {
        expand_mcp_config_value_with(&format!("{field}.{key}"), value, lookup)
            .map(|expanded| (key.clone(), expanded))
    };

    values
        .iter()
        .map(|(key, value)| expand_entry(key, value))
        .collect()
}

fn resolved_mcp_server_from_config_with<F>(
    name: &str,
    config: &McpServerConfig,
    lookup: &F,
) -> Result<PluginMcpServer, String>
where
    F: Fn(&str) -> Result<Option<String>, String>,
{
    Ok(PluginMcpServer {
        name: name.to_string(),
        transport: config.transport.clone(),
        command: config
            .command
            .as_deref()
            .map(|value| expand_mcp_config_value_with("command", value, lookup))
            .transpose()?,
        args: config
            .args
            .iter()
            .enumerate()
            .map(|(index, value)| {
                expand_mcp_config_value_with(&format!("args[{index}]"), value, lookup)
            })
            .collect::<Result<Vec<_>, _>>()?,
        url: config
            .url
            .as_deref()
            .map(|value| expand_mcp_config_value_with("url", value, lookup))
            .transpose()?,
        env: expand_mcp_config_map_with("env", &config.env, lookup)?,
        headers: expand_mcp_config_map_with("headers", &config.headers, lookup)?,
        headers_helper: config.headers_helper.clone(),
        timeout: config.timeout,
        always_load: config.always_load,
    })
}

// ---------------------------------------------------------------------------
// Plugin loading
// ---------------------------------------------------------------------------

/// A loaded plugin
#[derive(Debug, Clone)]
pub struct Plugin {
    /// Plugin manifest
    pub manifest: PluginManifest,
    /// Path to the plugin directory
    pub path: PathBuf,
    /// Whether the plugin is enabled
    pub enabled: bool,
    /// Plugin ID (plugin@marketplace or just plugin name for local)
    pub id: String,
    /// Source identifier (marketplace name or "local")
    pub source: String,
    /// Resolved command paths
    pub command_paths: Vec<PathBuf>,
    /// Resolved command metadata (from manifest object form)
    pub command_metadata: HashMap<String, CommandMetadata>,
    /// Resolved hook definitions
    pub hook_definitions: Vec<HooksDefinition>,
    /// Resolved MCP server configs
    pub mcp_configs: HashMap<String, McpServerConfig>,
    /// Resolved LSP server configs (CC parity, crosslink #655). One entry
    /// per `lspServers` map entry in the manifest. Empty when the plugin
    /// declares no language servers — the common case.
    pub lsp_configs: HashMap<String, crate::plugins::manifest::LspServerConfig>,
    /// Resolved agent paths
    pub agent_paths: Vec<PathBuf>,
    /// Resolved skill paths
    pub skill_paths: Vec<PathBuf>,
}

impl Plugin {
    /// Load a plugin from a directory using Claude Code format (.claude-plugin/plugin.json)
    ///
    /// # Errors
    /// Returns an error if plugin loading fails.
    pub fn load(path: &Path) -> Result<Self, PluginError> {
        // Try Claude Code format first: .claude-plugin/plugin.json
        let cc_manifest_path = path.join(".claude-plugin").join("plugin.json");
        // Also try plugin.json at root (legacy Claude Code location)
        let root_plugin_json = path.join("plugin.json");
        // Legacy OpenClaudia format
        let legacy_manifest_path = path.join("manifest.json");

        // Manifest reads MUST go through `read_plugin_file` so that a
        // symlinked `plugin.json` (pointing at e.g. `/etc/shadow`) is
        // rejected before we touch its contents. See crosslink #347.
        let manifest: PluginManifest = if cc_manifest_path.exists() {
            debug!(path = ?cc_manifest_path, "Loading Claude Code plugin manifest");
            let content = read_plugin_file(&cc_manifest_path)?;
            serde_json::from_str(&content).map_err(|e| {
                PluginError::InvalidManifest(format!("{}: {}", cc_manifest_path.display(), e))
            })?
        } else if root_plugin_json.exists() {
            debug!(path = ?root_plugin_json, "Loading plugin.json from root");
            let content = read_plugin_file(&root_plugin_json)?;
            serde_json::from_str(&content).map_err(|e| {
                PluginError::InvalidManifest(format!("{}: {}", root_plugin_json.display(), e))
            })?
        } else if legacy_manifest_path.exists() {
            debug!(path = ?legacy_manifest_path, "Loading legacy manifest.json");
            Self::load_legacy_manifest(&legacy_manifest_path)?
        } else {
            return Err(PluginError::ManifestNotFound(path.to_path_buf()));
        };

        Self::validate_manifest(&manifest)?;

        let mut plugin = Self {
            id: manifest.name.clone(),
            source: "local".to_string(),
            manifest,
            path: path.to_path_buf(),
            enabled: true,
            command_paths: Vec::new(),
            command_metadata: HashMap::new(),
            hook_definitions: Vec::new(),
            mcp_configs: HashMap::new(),
            lsp_configs: HashMap::new(),
            agent_paths: Vec::new(),
            skill_paths: Vec::new(),
        };

        // Resolve all components
        plugin.resolve_commands();
        plugin.resolve_hooks();
        plugin.resolve_mcp_servers();
        plugin.resolve_lsp_servers();
        plugin.resolve_agents();
        plugin.resolve_skills();

        Ok(plugin)
    }

    /// Load a legacy `OpenClaudia` manifest.json and convert to `PluginManifest`
    fn load_legacy_manifest(path: &Path) -> Result<PluginManifest, PluginError> {
        // Use the symlink-rejecting reader: a legacy manifest.json that
        // is actually a symlink to /etc/shadow would otherwise be read
        // blindly and leak its contents in error messages.
        let content = read_plugin_file(path)?;
        let legacy: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| PluginError::InvalidManifest(e.to_string()))?;

        // crosslink #347: the previous code defaulted missing names to
        // the literal "unknown" string. Multiple malformed manifests
        // would all collide into a single plugin slot, and the bogus
        // name passed `validate_manifest` because it is valid kebab-case.
        // We now require an explicit string for both the plugin name
        // AND each mcp_server name.
        let name = legacy["name"]
            .as_str()
            .ok_or_else(|| {
                PluginError::InvalidManifest(format!(
                    "legacy manifest at {} is missing required string field `name`",
                    path.display()
                ))
            })?
            .to_string();
        let version = legacy["version"].as_str().map(String::from);
        let description = legacy["description"].as_str().map(String::from);

        // Convert legacy MCP servers to new format
        let mcp_servers = if let Some(servers) = legacy["mcp_servers"].as_array() {
            let mut map = HashMap::new();
            for server in servers {
                let server_name = server["name"]
                    .as_str()
                    .ok_or_else(|| {
                        PluginError::InvalidManifest(format!(
                            "legacy manifest at {} has an mcp_servers entry missing required string field `name`",
                            path.display()
                        ))
                    })?
                    .to_string();
                let transport = server["transport"].as_str().unwrap_or("stdio").to_string();
                map.insert(
                    server_name,
                    McpServerConfig {
                        command: server["command"].as_str().map(String::from),
                        args: server["args"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        env: HashMap::new(),
                        transport,
                        url: server["url"].as_str().map(String::from),
                        headers: HashMap::new(),
                        headers_helper: None,
                        timeout: None,
                        always_load: None,
                    },
                );
            }
            if map.is_empty() {
                None
            } else {
                Some(McpServersSpec::Map(map))
            }
        } else {
            None
        };

        Ok(PluginManifest {
            name,
            version,
            description,
            author: legacy["author"].as_str().map(|a| PluginAuthor {
                name: a.to_string(),
                ..Default::default()
            }),
            homepage: None,
            repository: None,
            license: None,
            keywords: None,
            hooks: None,    // Legacy hooks handled differently
            commands: None, // Legacy commands handled differently
            agents: None,
            skills: None,
            mcp_servers,
            lsp_servers: None,
            signature: None,
        })
    }

    /// Validate the plugin manifest
    fn validate_manifest(manifest: &PluginManifest) -> Result<(), PluginError> {
        if manifest.name.is_empty() {
            return Err(PluginError::InvalidManifest(
                "Plugin name cannot be empty".to_string(),
            ));
        }
        if manifest.name.contains(' ') {
            return Err(PluginError::InvalidManifest(
                "Plugin name cannot contain spaces. Use kebab-case (e.g., \"my-plugin\")"
                    .to_string(),
            ));
        }
        validate_plugin_dir_name(&manifest.name)?;
        Ok(())
    }

    /// Resolve command paths and metadata from manifest + convention.
    ///
    /// Failures to read the convention directory or any individual command
    /// file now surface via `tracing::warn!` with the plugin name, path, and
    /// underlying error (crosslink #799). The previous implementation buried
    /// the read in `if let Ok(...)` chains with no `else`, so an unreadable
    /// `commands/` directory was indistinguishable from one with no commands.
    fn resolve_commands(&mut self) {
        // Convention: commands/ directory
        let commands_dir = self.path.join("commands");
        if commands_dir.exists() && self.manifest.commands.is_none() {
            match fs::read_dir(&commands_dir) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.extension().is_some_and(|e| e == "md") {
                            self.command_paths.push(p);
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        path = ?commands_dir,
                        plugin = %self.manifest.name,
                        error = %e,
                        "Plugin commands/ directory unreadable; skipping convention-discovered commands"
                    );
                }
            }
        }

        // Manifest-specified commands. All `self.path.join(...)` sites
        // were rewritten to use `validate_plugin_path` so an attacker
        // who controls the manifest cannot point us at
        // `../../../../etc/passwd`. See crosslink #347.
        if let Some(ref commands) = self.manifest.commands {
            match commands {
                CommandsSpec::Path(p) => match validate_plugin_path(&self.path, p) {
                    Ok(resolved) if resolved.exists() => {
                        if resolved.is_dir() {
                            if let Ok(entries) = fs::read_dir(&resolved) {
                                for entry in entries.flatten() {
                                    let ep = entry.path();
                                    if ep.extension().is_some_and(|e| e == "md") {
                                        self.command_paths.push(ep);
                                    }
                                }
                            }
                        } else {
                            self.command_paths.push(resolved);
                        }
                    }
                    Ok(_) => {
                        warn!(path = %p, plugin = %self.manifest.name, "Command path not found");
                    }
                    Err(e) => {
                        warn!(path = %p, plugin = %self.manifest.name, error = %e, "Rejected unsafe command path");
                    }
                },
                CommandsSpec::Paths(paths) => {
                    for p in paths {
                        match validate_plugin_path(&self.path, p) {
                            Ok(resolved) if resolved.exists() => {
                                self.command_paths.push(resolved);
                            }
                            Ok(_) => {
                                warn!(path = %p, plugin = %self.manifest.name, "Command path not found");
                            }
                            Err(e) => {
                                warn!(path = %p, plugin = %self.manifest.name, error = %e, "Rejected unsafe command path");
                            }
                        }
                    }
                }
                CommandsSpec::Map(map) => {
                    for (name, meta) in map {
                        if let Some(ref source) = meta.source {
                            match validate_plugin_path(&self.path, source) {
                                Ok(resolved) if resolved.exists() => {
                                    self.command_paths.push(resolved);
                                }
                                Ok(_) => {
                                    warn!(path = %source, command = %name, plugin = %self.manifest.name, "Command source not found");
                                }
                                Err(e) => {
                                    warn!(path = %source, command = %name, plugin = %self.manifest.name, error = %e, "Rejected unsafe command source");
                                }
                            }
                        }
                        self.command_metadata.insert(name.clone(), meta.clone());
                    }
                }
            }
        }
    }

    /// Resolve hooks from manifest + convention
    fn resolve_hooks(&mut self) {
        // Convention: hooks/hooks.json
        let hooks_json = self.path.join("hooks").join("hooks.json");
        if hooks_json.exists() {
            match Self::load_hooks_file(&hooks_json) {
                Ok(def) => self.hook_definitions.push(def),
                Err(e) => warn!(
                    path = ?hooks_json,
                    error = %e,
                    plugin = %self.manifest.name,
                    "Failed to load hooks"
                ),
            }
        }

        // Manifest-specified hooks — paths go through `validate_plugin_path`.
        if let Some(ref hooks_spec) = self.manifest.hooks {
            match hooks_spec {
                HooksSpec::Path(p) => match validate_plugin_path(&self.path, p) {
                    Ok(resolved) if resolved.exists() => match Self::load_hooks_file(&resolved) {
                        Ok(def) => self.hook_definitions.push(def),
                        Err(e) => warn!(error = %e, "Failed to load hooks from {}", p),
                    },
                    Ok(_) => {}
                    Err(e) => {
                        warn!(path = %p, plugin = %self.manifest.name, error = %e, "Rejected unsafe hooks path");
                    }
                },
                HooksSpec::Inline(def) => {
                    self.hook_definitions.push(def.clone());
                }
                HooksSpec::Array(entries) => {
                    for entry in entries {
                        match entry {
                            HooksSpecEntry::Path(p) => match validate_plugin_path(&self.path, p) {
                                Ok(resolved) if resolved.exists() => {
                                    match Self::load_hooks_file(&resolved) {
                                        Ok(def) => self.hook_definitions.push(def),
                                        Err(e) => {
                                            warn!(error = %e, "Failed to load hooks from {}", p);
                                        }
                                    }
                                }
                                Ok(_) => {}
                                Err(e) => {
                                    warn!(path = %p, plugin = %self.manifest.name, error = %e, "Rejected unsafe hooks path");
                                }
                            },
                            HooksSpecEntry::Inline(def) => {
                                self.hook_definitions.push(def.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    /// Load a hooks JSON file
    fn load_hooks_file(path: &Path) -> Result<HooksDefinition, PluginError> {
        // Try wrapper format: { "description": "...", "hooks": { ... } }
        #[derive(Deserialize)]
        struct HooksWrapper {
            #[serde(default)]
            description: Option<String>,
            hooks: HooksDefinition,
        }

        let content = read_plugin_file(path)?;
        // Try parsing as HooksDefinition directly, or as a wrapper with "hooks" key
        if let Ok(def) = serde_json::from_str::<HooksDefinition>(&content) {
            return Ok(def);
        }
        let wrapper: HooksWrapper = serde_json::from_str(&content)
            .map_err(|e| PluginError::InvalidManifest(format!("Invalid hooks file: {e}")))?;
        let mut def = wrapper.hooks;
        if def.description.is_none() {
            def.description = wrapper.description;
        }
        Ok(def)
    }

    /// Resolve MCP server configurations from manifest + convention.
    ///
    /// Every read / parse failure is surfaced as a `tracing::warn!` line tagged
    /// with the plugin name, file path, and underlying error (crosslink #799).
    /// The previous implementation buried every fallible step in nested
    /// `if let Ok(...)` chains with no `else`, which meant a plugin author who
    /// shipped a broken `.mcp.json` got zero diagnostic — the plugin loaded
    /// with the broken server silently absent.
    fn resolve_mcp_servers(&mut self) {
        // Convention: .mcp.json at plugin root. Use the symlink-rejecting
        // reader so an attacker cannot swap .mcp.json for a symlink to
        // a sensitive file. See crosslink #347.
        let mcp_json = self.path.join(".mcp.json");
        if mcp_json.exists() {
            match read_plugin_file(&mcp_json) {
                Ok(content) => self.parse_mcp_json_file(&mcp_json, &content),
                Err(e) => {
                    warn!(
                        path = ?mcp_json,
                        plugin = %self.manifest.name,
                        error = %e,
                        "Plugin .mcp.json unreadable; skipping MCP servers from this file"
                    );
                }
            }
        }

        // Manifest-specified MCP servers — paths go through
        // `validate_plugin_path` and `read_plugin_file` so neither path
        // traversal nor symlink swapping is possible.
        //
        // The manifest is cloned out of `self.manifest.mcp_servers` so the
        // subsequent `&mut self.mcp_configs` writes don't conflict with the
        // shared borrow of the manifest field. McpServersSpec is plain data
        // and the clone is one-shot per plugin load, so the cost is trivial.
        let mcp_spec = self.manifest.mcp_servers.clone();
        if let Some(mcp_spec) = mcp_spec {
            match mcp_spec {
                McpServersSpec::Path(p) => match validate_plugin_path(&self.path, &p) {
                    Ok(resolved) if resolved.exists() => {
                        self.load_mcp_servers_from_path(&p, &resolved);
                    }
                    Ok(_) => {
                        warn!(
                            path = %p,
                            plugin = %self.manifest.name,
                            "Plugin manifest mcp_servers path does not exist"
                        );
                    }
                    Err(e) => {
                        warn!(path = %p, plugin = %self.manifest.name, error = %e, "Rejected unsafe mcp_servers path");
                    }
                },
                McpServersSpec::Map(map) => {
                    self.mcp_configs.extend(map);
                }
                McpServersSpec::Array(entries) => {
                    for entry in entries {
                        match entry {
                            McpServersSpecEntry::Path(p) => {
                                match validate_plugin_path(&self.path, &p) {
                                    Ok(resolved) if resolved.exists() => {
                                        self.load_mcp_servers_from_path(&p, &resolved);
                                    }
                                    Ok(_) => {
                                        warn!(
                                            path = %p,
                                            plugin = %self.manifest.name,
                                            "Plugin manifest mcp_servers path does not exist"
                                        );
                                    }
                                    Err(e) => {
                                        warn!(path = %p, plugin = %self.manifest.name, error = %e, "Rejected unsafe mcp_servers path");
                                    }
                                }
                            }
                            McpServersSpecEntry::Map(map) => {
                                self.mcp_configs.extend(map);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Parse a `.mcp.json` body (the convention file at the plugin root) and
    /// extend `self.mcp_configs`. Every parse failure logs a `warn!` with the
    /// plugin name and path so operators can spot a broken file (crosslink #799).
    fn parse_mcp_json_file(&mut self, path: &Path, content: &str) {
        // .mcp.json can be `{ "mcpServers": { ... } }` or a direct map.
        match serde_json::from_str::<HashMap<String, serde_json::Value>>(content) {
            Ok(wrapper) => {
                if let Some(servers_val) = wrapper.get("mcpServers") {
                    match serde_json::from_value::<HashMap<String, McpServerConfig>>(
                        servers_val.clone(),
                    ) {
                        Ok(servers) => {
                            self.mcp_configs.extend(servers);
                        }
                        Err(e) => {
                            warn!(
                                path = ?path,
                                plugin = %self.manifest.name,
                                error = %e,
                                "Plugin .mcp.json `mcpServers` block could not be decoded as McpServerConfig map"
                            );
                        }
                    }
                } else {
                    match serde_json::from_str::<HashMap<String, McpServerConfig>>(content) {
                        Ok(servers) => {
                            self.mcp_configs.extend(servers);
                        }
                        Err(e) => {
                            warn!(
                                path = ?path,
                                plugin = %self.manifest.name,
                                error = %e,
                                "Plugin .mcp.json (direct-map form) could not be decoded as McpServerConfig map"
                            );
                        }
                    }
                }
            }
            Err(e) => {
                warn!(
                    path = ?path,
                    plugin = %self.manifest.name,
                    error = %e,
                    "Plugin .mcp.json is not valid JSON; skipping MCP servers from this file"
                );
            }
        }
    }

    /// Read and parse a manifest-referenced MCP servers file. Logs every
    /// failure with full context (crosslink #799). Honours both the
    /// `{ "mcpServers": { ... } }` wrapper form and the bare-map form so
    /// manifest-Path branches and the convention `.mcp.json` branch agree
    /// on accepted shapes (crosslink #919).
    fn load_mcp_servers_from_path(&mut self, declared: &str, resolved: &Path) {
        match read_plugin_file(resolved) {
            Ok(content) => self.parse_mcp_json_file(resolved, &content),
            Err(e) => {
                warn!(
                    declared = %declared,
                    resolved = ?resolved,
                    plugin = %self.manifest.name,
                    error = %e,
                    "Plugin manifest mcp_servers file unreadable"
                );
            }
        }
    }

    /// Resolve plugin-declared LSP server registrations (CC parity with
    /// `lspPluginIntegration.ts`, crosslink #655).
    ///
    /// Copies `manifest.lsp_servers` into `self.lsp_configs`. We don't
    /// validate the binary on `PATH` here — that's runtime concern owned
    /// by [`crate::tools::lsp::is_lsp_connected`]. Validating ahead of
    /// time would force the plugin to fail-load when the user's `PATH`
    /// happens not to contain the server yet (e.g. it's installed by a
    /// post-install hook), which is too strict.
    fn resolve_lsp_servers(&mut self) {
        if let Some(servers) = &self.manifest.lsp_servers {
            for (lang, cfg) in servers {
                self.lsp_configs.insert(lang.clone(), cfg.clone());
            }
        }
    }

    /// Resolve agent paths from manifest + convention
    fn resolve_agents(&mut self) {
        let agents_dir = self.path.join("agents");
        if agents_dir.exists() && self.manifest.agents.is_none() {
            if let Ok(entries) = fs::read_dir(&agents_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.extension().is_some_and(|e| e == "md") {
                        self.agent_paths.push(p);
                    }
                }
            }
        }
        if let Some(ref agents_spec) = self.manifest.agents {
            let paths = match agents_spec {
                AgentsSpec::Path(p) => vec![p.clone()],
                AgentsSpec::Paths(ps) => ps.clone(),
            };
            for p in paths {
                match validate_plugin_path(&self.path, &p) {
                    Ok(resolved) if resolved.exists() => {
                        self.agent_paths.push(resolved);
                    }
                    Ok(_) => {
                        warn!(path = %p, plugin = %self.manifest.name, "Agent path not found");
                    }
                    Err(e) => {
                        warn!(path = %p, plugin = %self.manifest.name, error = %e, "Rejected unsafe agent path");
                    }
                }
            }
        }
    }

    /// Resolve skill paths from manifest + convention.
    ///
    /// Convention-based discovery walks `<plugin>/skills/` for the same
    /// layouts `skills::load_skills` understands — subdirectories
    /// containing a `SKILL.md` AND bare top-level `.md` files
    /// (crosslink #832). Both call sites route through
    /// [`crate::skills::walk_skill_entries`] so the rule for "what
    /// counts as a skill" is defined once.
    fn resolve_skills(&mut self) {
        let skills_dir = self.path.join("skills");
        if skills_dir.exists() && self.manifest.skills.is_none() {
            for entry in crate::skills::walk_skill_entries(&skills_dir) {
                self.skill_paths.push(entry.root_path().to_path_buf());
            }
        }
        if let Some(ref skills_spec) = self.manifest.skills {
            let paths = match skills_spec {
                SkillsSpec::Path(p) => vec![p.clone()],
                SkillsSpec::Paths(ps) => ps.clone(),
            };
            for p in paths {
                match validate_plugin_path(&self.path, &p) {
                    Ok(resolved) if resolved.exists() => {
                        self.skill_paths.push(resolved);
                    }
                    Ok(_) => {
                        warn!(path = %p, plugin = %self.manifest.name, "Skill path not found");
                    }
                    Err(e) => {
                        warn!(path = %p, plugin = %self.manifest.name, error = %e, "Rejected unsafe skill path");
                    }
                }
            }
        }
    }

    /// Get the plugin name
    #[must_use]
    pub fn name(&self) -> &str {
        &self.manifest.name
    }

    /// Get the plugin root path
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.path
    }

    /// Get environment variables to set when running plugin scripts
    #[must_use]
    pub fn env_vars(&self) -> HashMap<String, String> {
        let mut vars = HashMap::new();
        vars.insert(
            "PLUGIN_ROOT".to_string(),
            self.path.to_string_lossy().to_string(),
        );
        vars.insert("PLUGIN_NAME".to_string(), self.manifest.name.clone());
        vars.insert(
            "PLUGIN_VERSION".to_string(),
            self.manifest
                .version
                .clone()
                .unwrap_or_else(|| "0.0.0".to_string()),
        );
        vars
    }

    /// Resolve a path relative to the plugin root
    #[must_use]
    pub fn resolve_path(&self, relative: &str) -> PathBuf {
        self.path.join(relative)
    }

    /// Get all resolved hooks as flat list
    #[must_use]
    pub fn resolved_hooks(&self) -> Vec<PluginHook> {
        let mut hooks = Vec::new();
        for def in &self.hook_definitions {
            for h in &def.pre_tool_use {
                hooks.push(PluginHook {
                    event: "PreToolUse".to_string(),
                    matcher: h.matcher.clone(),
                    hook_type: h.hook_type.clone(),
                    command: h.command.clone(),
                    prompt: None,
                    timeout: h.timeout.unwrap_or(30),
                });
            }
            for h in &def.post_tool_use {
                hooks.push(PluginHook {
                    event: "PostToolUse".to_string(),
                    matcher: h.matcher.clone(),
                    hook_type: h.hook_type.clone(),
                    command: h.command.clone(),
                    prompt: None,
                    timeout: h.timeout.unwrap_or(30),
                });
            }
            for h in &def.session_start {
                hooks.push(PluginHook {
                    event: "SessionStart".to_string(),
                    matcher: h.matcher.clone(),
                    hook_type: h.hook_type.clone(),
                    command: h.command.clone(),
                    prompt: None,
                    timeout: h.timeout.unwrap_or(30),
                });
            }
            for h in &def.notification {
                hooks.push(PluginHook {
                    event: "Notification".to_string(),
                    matcher: h.matcher.clone(),
                    hook_type: h.hook_type.clone(),
                    command: h.command.clone(),
                    prompt: None,
                    timeout: h.timeout.unwrap_or(30),
                });
            }
            for h in &def.stop {
                hooks.push(PluginHook {
                    event: "Stop".to_string(),
                    matcher: h.matcher.clone(),
                    hook_type: h.hook_type.clone(),
                    command: h.command.clone(),
                    prompt: None,
                    timeout: h.timeout.unwrap_or(30),
                });
            }
            for h in &def.user_prompt_submit {
                hooks.push(PluginHook {
                    event: "UserPromptSubmit".to_string(),
                    matcher: h.matcher.clone(),
                    hook_type: h.hook_type.clone(),
                    command: h.command.clone(),
                    prompt: None,
                    timeout: h.timeout.unwrap_or(30),
                });
            }
        }
        hooks
    }

    /// Get all resolved commands
    #[must_use]
    pub fn resolved_commands(&self) -> Vec<PluginCommand> {
        let mut commands = Vec::new();

        // Load commands from paths (markdown files)
        for path in &self.command_paths {
            let cmd_name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();

            // Crosslink #799: read failures used to silently fall back to
            // an empty string via `unwrap_or_default()`, which then yielded
            // a "command" with no description, no body, and no flags — the
            // plugin author who shipped an unreadable file got zero signal.
            // Log and skip the entry so operators can grep for the warning.
            let raw_content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(e) => {
                    warn!(
                        path = ?path,
                        plugin = %self.manifest.name,
                        command = %cmd_name,
                        error = %e,
                        "Plugin command file unreadable; skipping this command"
                    );
                    continue;
                }
            };
            let front_matter = parse_command_front_matter(&raw_content);

            let meta = self.command_metadata.get(&cmd_name);
            // Front matter values take precedence, then manifest metadata, then fallback
            let description = meta
                .and_then(|m| m.description.clone())
                .or(front_matter.description)
                .or_else(|| {
                    // Extract first non-empty line from body as description
                    front_matter
                        .body
                        .lines()
                        .find(|l| !l.trim().is_empty())
                        .map(|l| l.trim_start_matches('#').trim().to_string())
                });
            let allowed_tools = meta
                .and_then(|m| m.allowed_tools.clone())
                .or(front_matter.allowed_tools);

            commands.push(PluginCommand {
                name: cmd_name.clone(),
                description,
                content: front_matter.body,
                allowed_tools,
                argument_hint: front_matter.argument_hint,
                model: front_matter.model,
            });
        }

        // Load inline content commands (no file path)
        for (name, meta) in &self.command_metadata {
            if meta.source.is_none() {
                if let Some(ref content) = meta.content {
                    let front_matter = parse_command_front_matter(content);
                    commands.push(PluginCommand {
                        name: name.clone(),
                        description: meta.description.clone().or(front_matter.description),
                        content: front_matter.body,
                        allowed_tools: meta.allowed_tools.clone().or(front_matter.allowed_tools),
                        argument_hint: front_matter.argument_hint,
                        model: front_matter.model,
                    });
                }
            }
        }

        commands
    }

    /// Get all resolved MCP servers
    #[must_use]
    pub fn resolved_mcp_servers(&self) -> Vec<PluginMcpServer> {
        self.resolved_mcp_servers_with_lookup(&|_| Ok(None))
    }

    /// Resolve MCP configuration only from one immutable run environment
    /// snapshot. Missing names may still use manifest defaults, but can never
    /// fall back to the mutable host process environment.
    #[must_use]
    pub fn resolved_mcp_servers_for_run(
        &self,
        run: &crate::tools::ToolRunContext,
    ) -> Vec<PluginMcpServer> {
        self.resolved_mcp_servers_with_lookup(&|name| {
            Ok(run.mcp_environment_grants().get(name).cloned())
        })
    }

    fn resolved_mcp_servers_with_lookup<F>(&self, lookup: &F) -> Vec<PluginMcpServer>
    where
        F: Fn(&str) -> Result<Option<String>, String>,
    {
        self.mcp_configs
            .iter()
            .filter_map(|(name, config)| {
                match resolved_mcp_server_from_config_with(name, config, lookup) {
                    Ok(server) => Some(server),
                    Err(error) => {
                        warn!(
                            plugin = %self.id,
                            server = %name,
                            error = %error,
                            "Skipping plugin MCP server because environment expansion failed"
                        );
                        None
                    }
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn mcp_env_ref(name: &str) -> String {
        let mut value = String::from("${");
        value.push_str(name);
        value.push('}');
        value
    }

    fn mcp_env_default(name: &str, default_value: &str) -> String {
        let mut value = String::from("${");
        value.push_str(name);
        value.push_str(":-");
        value.push_str(default_value);
        value.push('}');
        value
    }

    /// Create a Claude Code-style plugin in a temp directory
    fn create_cc_plugin(dir: &Path, name: &str) {
        let plugin_dir = dir.join(name);
        let cc_dir = plugin_dir.join(".claude-plugin");
        let commands_dir = plugin_dir.join("commands");
        let hooks_dir = plugin_dir.join("hooks");

        fs::create_dir_all(&cc_dir).unwrap();
        fs::create_dir_all(&commands_dir).unwrap();
        fs::create_dir_all(&hooks_dir).unwrap();

        // Write plugin.json manifest
        let manifest = serde_json::json!({
            "name": name,
            "version": "1.0.0",
            "description": "A test plugin",
            "author": {
                "name": "Test Author",
                "email": "test@example.com"
            },
            "keywords": ["test", "example"]
        });
        fs::write(
            cc_dir.join("plugin.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        // Write a command markdown file
        fs::write(
            commands_dir.join("greet.md"),
            "# Greet\nSay hello to the user in a friendly way.",
        )
        .unwrap();

        // Write hooks.json
        let hooks = serde_json::json!({
            "PreToolUse": [
                {
                    "matcher": "bash",
                    "type": "command",
                    "command": "echo checking bash"
                }
            ],
            "SessionStart": [
                {
                    "type": "command",
                    "command": "echo plugin loaded"
                }
            ]
        });
        fs::write(
            hooks_dir.join("hooks.json"),
            serde_json::to_string_pretty(&hooks).unwrap(),
        )
        .unwrap();
    }

    /// Create a legacy OpenClaudia-style plugin
    fn create_legacy_plugin(dir: &Path, name: &str) {
        let plugin_dir = dir.join(name);
        fs::create_dir_all(&plugin_dir).unwrap();

        let manifest = serde_json::json!({
            "name": name,
            "version": "1.0.0",
            "description": "Legacy test plugin",
            "hooks": [
                {
                    "event": "session_start",
                    "type": "command",
                    "command": "echo hello"
                }
            ],
            "commands": [
                {
                    "name": "test",
                    "description": "Test command",
                    "script": "echo test"
                }
            ],
            "mcp_servers": [
                {
                    "name": "test-server",
                    "transport": "stdio",
                    "command": "node",
                    "args": ["server.js"]
                }
            ]
        });

        fs::write(
            plugin_dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn test_cc_plugin_manifest_parsing() {
        let manifest_json = r#"{
            "name": "my-plugin",
            "version": "1.0.0",
            "description": "A test plugin",
            "author": {
                "name": "Test Author",
                "email": "test@example.com",
                "url": "https://example.com"
            },
            "keywords": ["test"],
            "commands": {
                "greet": {
                    "source": "./commands/greet.md",
                    "description": "Say hello"
                }
            },
            "mcpServers": {
                "my-server": {
                    "command": "node",
                    "args": ["server.js"],
                    "transport": "stdio"
                }
            }
        }"#;

        let manifest: PluginManifest = serde_json::from_str(manifest_json).unwrap();
        assert_eq!(manifest.name, "my-plugin");
        assert_eq!(manifest.version.as_deref(), Some("1.0.0"));
        assert!(manifest.commands.is_some());
        assert!(manifest.mcp_servers.is_some());
    }

    #[test]
    fn test_cc_plugin_load() {
        let dir = TempDir::new().unwrap();
        create_cc_plugin(dir.path(), "test-plugin");

        let plugin = Plugin::load(&dir.path().join("test-plugin")).unwrap();
        assert_eq!(plugin.name(), "test-plugin");
        assert_eq!(plugin.manifest.version.as_deref(), Some("1.0.0"));
        assert!(plugin.enabled);
        // Should find commands/greet.md
        assert_eq!(plugin.command_paths.len(), 1);
        // Should load hooks/hooks.json
        assert_eq!(plugin.hook_definitions.len(), 1);
    }

    #[test]
    fn test_cc_plugin_resolved_hooks() {
        let dir = TempDir::new().unwrap();
        create_cc_plugin(dir.path(), "hook-plugin");

        let plugin = Plugin::load(&dir.path().join("hook-plugin")).unwrap();
        let hooks = plugin.resolved_hooks();

        assert_eq!(hooks.len(), 2); // PreToolUse + SessionStart
        assert!(hooks.iter().any(|h| h.event == "PreToolUse"));
        assert!(hooks.iter().any(|h| h.event == "SessionStart"));
    }

    #[test]
    fn test_cc_plugin_resolved_commands() {
        let dir = TempDir::new().unwrap();
        create_cc_plugin(dir.path(), "cmd-plugin");

        let plugin = Plugin::load(&dir.path().join("cmd-plugin")).unwrap();
        let commands = plugin.resolved_commands();

        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].name, "greet");
        assert!(commands[0].content.contains("hello"));
    }

    #[test]
    fn test_legacy_plugin_load() {
        let dir = TempDir::new().unwrap();
        create_legacy_plugin(dir.path(), "legacy-plugin");

        let plugin = Plugin::load(&dir.path().join("legacy-plugin")).unwrap();
        assert_eq!(plugin.name(), "legacy-plugin");
        // Legacy MCP servers should be resolved
        assert_eq!(plugin.mcp_configs.len(), 1);
        assert!(plugin.mcp_configs.contains_key("test-server"));
    }

    #[test]
    fn test_plugin_env_vars() {
        let dir = TempDir::new().unwrap();
        create_cc_plugin(dir.path(), "env-test");

        let plugin = Plugin::load(&dir.path().join("env-test")).unwrap();
        let vars = plugin.env_vars();

        assert!(vars.contains_key("PLUGIN_ROOT"));
        assert_eq!(vars.get("PLUGIN_NAME"), Some(&"env-test".to_string()));
        assert_eq!(vars.get("PLUGIN_VERSION"), Some(&"1.0.0".to_string()));
    }

    #[test]
    fn test_plugin_manager_discover() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        fs::create_dir_all(&plugins_dir).unwrap();

        create_cc_plugin(&plugins_dir, "plugin-a");
        create_cc_plugin(&plugins_dir, "plugin-b");
        create_legacy_plugin(&plugins_dir, "plugin-c");

        let mut manager = PluginManager::with_paths(vec![plugins_dir]);
        let errors = manager.discover();

        assert!(errors.is_empty(), "Errors: {errors:?}");
        assert_eq!(manager.count(), 3);
        assert!(manager.get("plugin-a").is_some());
        assert!(manager.get("plugin-b").is_some());
        assert!(manager.get("plugin-c").is_some());
    }

    #[test]
    fn test_plugin_manager_hooks() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        fs::create_dir_all(&plugins_dir).unwrap();

        create_cc_plugin(&plugins_dir, "hook-test");

        let mut manager = PluginManager::with_paths(vec![plugins_dir]);
        manager.discover();

        let hooks = manager.hooks_for_event("SessionStart");
        assert_eq!(hooks.len(), 1);

        let hooks = manager.hooks_for_event("PreToolUse");
        assert_eq!(hooks.len(), 1);
    }

    #[test]
    fn test_plugin_manager_commands() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        fs::create_dir_all(&plugins_dir).unwrap();

        create_cc_plugin(&plugins_dir, "cmd-test");

        let mut manager = PluginManager::with_paths(vec![plugins_dir]);
        manager.discover();

        let commands = manager.all_commands();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].1.name, "greet");
    }

    #[test]
    fn test_plugin_manager_mcp_servers() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        fs::create_dir_all(&plugins_dir).unwrap();

        create_legacy_plugin(&plugins_dir, "mcp-test");

        let mut manager = PluginManager::with_paths(vec![plugins_dir]);
        manager.discover();

        let servers = manager.all_mcp_servers();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].1.name, "test-server");
    }

    #[test]
    fn test_plugin_manager_enable_disable() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        fs::create_dir_all(&plugins_dir).unwrap();

        create_cc_plugin(&plugins_dir, "toggle-test");

        let mut manager = PluginManager::with_paths(vec![plugins_dir]);
        manager.discover();

        assert!(manager.get("toggle-test").unwrap().enabled);

        manager.disable("toggle-test").unwrap();
        assert!(!manager.get("toggle-test").unwrap().enabled);
        // Disabled plugin hooks should not appear
        assert!(manager.hooks_for_event("SessionStart").is_empty());

        manager.enable("toggle-test").unwrap();
        assert!(manager.get("toggle-test").unwrap().enabled);
        assert_eq!(manager.hooks_for_event("SessionStart").len(), 1);
    }

    #[test]
    fn test_invalid_manifest_empty_name() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = dir.path().join("bad");
        let cc_dir = plugin_dir.join(".claude-plugin");
        fs::create_dir_all(&cc_dir).unwrap();
        fs::write(cc_dir.join("plugin.json"), r#"{"name": ""}"#).unwrap();

        let result = Plugin::load(&plugin_dir);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_invalid_manifest_spaces_in_name() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = dir.path().join("bad");
        let cc_dir = plugin_dir.join(".claude-plugin");
        fs::create_dir_all(&cc_dir).unwrap();
        fs::write(cc_dir.join("plugin.json"), r#"{"name": "my plugin"}"#).unwrap();

        let result = Plugin::load(&plugin_dir);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("spaces"));
    }

    #[test]
    fn test_invalid_manifest_path_like_name() {
        for bad_name in ["../evil", "bad/name", "bad\\name", ".hidden", "CON"] {
            let dir = TempDir::new().unwrap();
            let plugin_dir = dir.path().join("bad");
            let cc_dir = plugin_dir.join(".claude-plugin");
            fs::create_dir_all(&cc_dir).unwrap();
            fs::write(
                cc_dir.join("plugin.json"),
                serde_json::json!({"name": bad_name}).to_string(),
            )
            .unwrap();

            let result = Plugin::load(&plugin_dir);

            assert!(
                result.is_err(),
                "manifest name {bad_name:?} must be rejected"
            );
        }
    }

    #[test]
    fn test_no_manifest_error() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = dir.path().join("empty");
        fs::create_dir_all(&plugin_dir).unwrap();

        let result = Plugin::load(&plugin_dir);
        assert!(matches!(result, Err(PluginError::ManifestNotFound(_))));
    }

    #[test]
    fn test_marketplace_manifest_parsing() {
        let json = r#"{
            "name": "my-marketplace",
            "owner": {
                "name": "Test Org",
                "email": "org@example.com"
            },
            "plugins": [
                {
                    "name": "cool-plugin",
                    "source": "./cool-plugin",
                    "category": "productivity",
                    "tags": ["cool"]
                },
                {
                    "name": "remote-plugin",
                    "source": {
                        "source": "github",
                        "repo": "user/repo"
                    },
                    "strict": true
                }
            ],
            "metadata": {
                "pluginRoot": ".",
                "version": "1.0.0"
            }
        }"#;

        let marketplace: MarketplaceManifest = serde_json::from_str(json).unwrap();
        assert_eq!(marketplace.name, "my-marketplace");
        assert_eq!(marketplace.plugins.len(), 2);
        assert_eq!(marketplace.plugins[0].name, "cool-plugin");
    }

    #[test]
    fn test_installed_plugins_tracking() {
        let mut installed = InstalledPlugins::default();
        assert_eq!(installed.version, 2);
        assert!(installed.plugins.is_empty());

        installed.upsert(
            "test-plugin@my-marketplace",
            PluginInstallEntry {
                scope: InstallScope::User,
                project_path: None,
                install_path: "/tmp/plugins/test-plugin".to_string(),
                version: Some("1.0.0".to_string()),
                installed_at: Some("2026-01-15T00:00:00Z".to_string()),
                last_updated: None,
                git_commit_sha: None,
            },
        );

        assert_eq!(installed.plugins.len(), 1);
        assert!(installed.plugins.contains_key("test-plugin@my-marketplace"));

        // Update same entry
        installed.upsert(
            "test-plugin@my-marketplace",
            PluginInstallEntry {
                scope: InstallScope::User,
                project_path: None,
                install_path: "/tmp/plugins/test-plugin".to_string(),
                version: Some("1.1.0".to_string()),
                installed_at: Some("2026-01-15T00:00:00Z".to_string()),
                last_updated: Some("2026-01-16T00:00:00Z".to_string()),
                git_commit_sha: None,
            },
        );
        // Should still be 1 entry, not 2
        assert_eq!(installed.plugins["test-plugin@my-marketplace"].len(), 1);
        assert_eq!(
            installed.plugins["test-plugin@my-marketplace"][0]
                .version
                .as_deref(),
            Some("1.1.0")
        );

        assert!(installed.remove("test-plugin@my-marketplace"));
        assert!(installed.plugins.is_empty());
    }

    #[test]
    fn test_plugin_with_mcp_json() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = dir.path().join("mcp-plugin");
        let cc_dir = plugin_dir.join(".claude-plugin");
        fs::create_dir_all(&cc_dir).unwrap();

        fs::write(cc_dir.join("plugin.json"), r#"{"name": "mcp-plugin"}"#).unwrap();

        // Write .mcp.json at plugin root
        let mcp_config = serde_json::json!({
            "mcpServers": {
                "my-server": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                    "transport": "stdio"
                }
            }
        });
        fs::write(
            plugin_dir.join(".mcp.json"),
            serde_json::to_string(&mcp_config).unwrap(),
        )
        .unwrap();

        let plugin = Plugin::load(&plugin_dir).unwrap();
        assert_eq!(plugin.mcp_configs.len(), 1);
        assert!(plugin.mcp_configs.contains_key("my-server"));

        let servers = plugin.resolved_mcp_servers();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "my-server");
        assert_eq!(servers[0].command.as_deref(), Some("npx"));
    }

    #[test]
    fn mcp_env_expansion_supports_required_vars_defaults_and_repeats() {
        let lookup = |name: &str| -> Result<Option<String>, String> {
            Ok(match name {
                "TOKEN" => Some("secret".to_string()),
                "EMPTY" => Some(String::new()),
                _ => None,
            })
        };

        let template = [
            mcp_env_ref("TOKEN"),
            mcp_env_default("MISSING", "fallback"),
            mcp_env_ref("TOKEN"),
            mcp_env_ref("EMPTY"),
        ]
        .join(":");
        let expanded = expand_mcp_env_vars_with(&template, &lookup).unwrap();

        assert_eq!(expanded, "secret:fallback:secret:");
    }

    #[test]
    fn mcp_resolution_uses_each_run_snapshot_without_ambient_lookup() {
        let root = TempDir::new().unwrap();
        create_cc_plugin(root.path(), "snapshot-mcp");
        let plugin_dir = root.path().join("snapshot-mcp");
        fs::write(
            plugin_dir.join(".mcp.json"),
            serde_json::json!({
                "mcpServers": {
                    "snapshot": {
                        "transport": "stdio",
                        "command": "runner",
                        "env": {"SNAPSHOT_TOKEN": "${S019_MCP_TOKEN}"}
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        let plugin = Plugin::load(&plugin_dir).unwrap();
        let build_run = |value: &str| {
            crate::tools::ToolRunContext::builder(crate::state::SessionId::new(), root.path())
                .workspace_access(crate::tools::WorkspaceAccess::ReadOnly)
                .read_only_roots(Vec::new())
                .read_write_roots(Vec::new())
                .mcp_environment_grants(HashMap::from([(
                    "S019_MCP_TOKEN".to_string(),
                    value.to_string(),
                )]))
                .environment_grants(HashMap::new())
                .process(false)
                .network(false)
                .secrets(true)
                .provider("plugin-mcp-snapshot-test")
                .build()
                .unwrap()
        };
        let run_a = build_run("run-a");
        let run_b = build_run("run-b");

        let resolved_a = plugin.resolved_mcp_servers_for_run(&run_a);
        let resolved_b = plugin.resolved_mcp_servers_for_run(&run_b);
        assert_eq!(resolved_a[0].env["SNAPSHOT_TOKEN"], "run-a");
        assert_eq!(resolved_b[0].env["SNAPSHOT_TOKEN"], "run-b");
    }

    #[test]
    fn mcp_env_expansion_rejects_unset_required_vars() {
        let lookup = |_name: &str| -> Result<Option<String>, String> { Ok(None) };

        let template = format!("Bearer {}", mcp_env_ref("MISSING_TOKEN"));
        let err = expand_mcp_env_vars_with(&template, &lookup).unwrap_err();

        assert!(
            err.contains("MISSING_TOKEN"),
            "error should name the missing variable; got: {err}"
        );
    }

    #[test]
    fn mcp_env_expansion_rejects_malformed_expressions() {
        let lookup = |_name: &str| -> Result<Option<String>, String> { Ok(None) };

        let unterminated = expand_mcp_env_vars_with("${TOKEN", &lookup).unwrap_err();
        assert!(
            unterminated.contains("unterminated"),
            "unterminated expression should be explicit; got: {unterminated}"
        );

        let invalid_name = expand_mcp_env_vars_with("${TOKEN-NAME}", &lookup).unwrap_err();
        assert!(
            invalid_name.contains("may only contain"),
            "invalid variable name should be explicit; got: {invalid_name}"
        );
    }

    #[test]
    fn resolved_mcp_server_expands_documented_fields_only() {
        let lookup = |name: &str| -> Result<Option<String>, String> {
            Ok(match name {
                "HOST" => Some("mcp.example.test".to_string()),
                "TOKEN" => Some("secret".to_string()),
                _ => None,
            })
        };

        let mut env = HashMap::new();
        env.insert("AUTH_TOKEN".to_string(), mcp_env_ref("TOKEN"));
        env.insert("MODE".to_string(), mcp_env_default("MODE", "production"));

        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".to_string(),
            format!("Bearer {}", mcp_env_ref("TOKEN")),
        );

        let config = McpServerConfig {
            command: Some(mcp_env_default("BIN", "node")),
            args: vec![format!("--token={}", mcp_env_ref("TOKEN"))],
            env,
            transport: "http".to_string(),
            url: Some(format!("https://{}/mcp", mcp_env_ref("HOST"))),
            headers,
            headers_helper: Some(format!("printf '%s' '{}'", mcp_env_ref("TOKEN"))),
            timeout: Some(250),
            always_load: Some(true),
        };

        let server = resolved_mcp_server_from_config_with("remote", &config, &lookup).unwrap();

        assert_eq!(server.command.as_deref(), Some("node"));
        assert_eq!(server.args, vec!["--token=secret"]);
        assert_eq!(server.url.as_deref(), Some("https://mcp.example.test/mcp"));
        assert_eq!(
            server.env.get("AUTH_TOKEN").map(String::as_str),
            Some("secret")
        );
        assert_eq!(
            server.env.get("MODE").map(String::as_str),
            Some("production")
        );
        assert_eq!(
            server.headers.get("Authorization").map(String::as_str),
            Some("Bearer secret")
        );
        assert_eq!(server.headers_helper, config.headers_helper);
        assert_eq!(server.timeout, Some(250));
        assert_eq!(server.always_load, Some(true));
    }

    #[test]
    fn test_inline_commands() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = dir.path().join("inline-cmd");
        let cc_dir = plugin_dir.join(".claude-plugin");
        fs::create_dir_all(&cc_dir).unwrap();

        let manifest = serde_json::json!({
            "name": "inline-cmd",
            "commands": {
                "hello": {
                    "content": "Say hello to the user warmly.",
                    "description": "Greet the user"
                }
            }
        });
        fs::write(
            cc_dir.join("plugin.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let plugin = Plugin::load(&plugin_dir).unwrap();
        let commands = plugin.resolved_commands();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].name, "hello");
        assert_eq!(commands[0].content, "Say hello to the user warmly.");
    }

    #[test]
    fn test_plugin_error_variants() {
        let err = PluginError::InvalidManifest("missing field".to_string());
        assert!(err.to_string().contains("missing field"));

        let err = PluginError::NotFound("test-plugin".to_string());
        assert!(err.to_string().contains("test-plugin"));

        let err = PluginError::InstallError("download failed".to_string());
        assert!(err.to_string().contains("download failed"));

        let err = PluginError::MarketplaceError("not found".to_string());
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_local_plugin_install_end_to_end() {
        // Create a source plugin directory (simulates what user provides)
        let source_dir = TempDir::new().unwrap();
        let plugin_src = source_dir.path().join("my-test-plugin");
        let cc_dir = plugin_src.join(".claude-plugin");
        let commands_dir = plugin_src.join("commands");
        fs::create_dir_all(&cc_dir).unwrap();
        fs::create_dir_all(&commands_dir).unwrap();

        fs::write(
            cc_dir.join("plugin.json"),
            r#"{
                "name": "my-test-plugin",
                "version": "2.0.0",
                "description": "End-to-end test plugin"
            }"#,
        )
        .unwrap();
        fs::write(
            commands_dir.join("hello.md"),
            "# Hello command\nSay hello to the user.",
        )
        .unwrap();
        fs::write(
            commands_dir.join("status.md"),
            "# Status check\nShow system status.",
        )
        .unwrap();

        // Create destination plugins directory (simulates .openclaudia/plugins/)
        let install_dir = TempDir::new().unwrap();
        let dest = install_dir.path().join("my-test-plugin");

        // Step 1: Load plugin from source (validates manifest)
        let loaded = Plugin::load(&plugin_src).unwrap();
        assert_eq!(loaded.name(), "my-test-plugin");
        assert_eq!(loaded.manifest.version.as_deref(), Some("2.0.0"));
        assert_eq!(loaded.command_paths.len(), 2);

        // Step 2: Copy to install directory
        copy_dir_recursive(&plugin_src, &dest).unwrap();
        assert!(dest.join(".claude-plugin/plugin.json").exists());
        assert!(dest.join("commands/hello.md").exists());
        assert!(dest.join("commands/status.md").exists());

        // Step 3: Load the installed copy and verify
        let installed_plugin = Plugin::load(&dest).unwrap();
        assert_eq!(installed_plugin.name(), "my-test-plugin");
        assert_eq!(installed_plugin.command_paths.len(), 2);

        // Step 4: Verify resolved commands
        let commands = installed_plugin.resolved_commands();
        assert_eq!(commands.len(), 2);
        let cmd_names: Vec<&str> = commands.iter().map(|c| c.name.as_str()).collect();
        assert!(cmd_names.contains(&"hello"));
        assert!(cmd_names.contains(&"status"));

        // Verify command content was preserved
        let hello_cmd = commands.iter().find(|c| c.name == "hello").unwrap();
        assert!(hello_cmd.content.contains("Say hello"));
        assert!(hello_cmd
            .description
            .as_deref()
            .unwrap()
            .contains("Hello command"));

        // Step 5: PluginManager discovers the installed plugin
        let mut manager = PluginManager::with_paths(vec![install_dir.path().to_path_buf()]);
        let errors = manager.discover();
        assert!(errors.is_empty(), "Discovery errors: {errors:?}");
        assert_eq!(manager.count(), 1);

        let plugin = manager.get("my-test-plugin").unwrap();
        assert_eq!(plugin.name(), "my-test-plugin");
        assert!(plugin.enabled);

        // Step 6: all_commands returns the plugin's commands
        let all_cmds = manager.all_commands();
        assert_eq!(all_cmds.len(), 2);
        for (p, cmd) in &all_cmds {
            assert_eq!(p.name(), "my-test-plugin");
            assert!(cmd.name == "hello" || cmd.name == "status");
        }
    }

    #[test]
    fn test_marketplace_install_from_directory() {
        // Create a marketplace directory with plugins inside
        let marketplace_dir = TempDir::new().unwrap();
        let mp_root = marketplace_dir.path().join("test-marketplace");
        let mp_meta = mp_root.join(".claude-plugin");
        fs::create_dir_all(&mp_meta).unwrap();

        // Create marketplace manifest
        let marketplace_manifest = serde_json::json!({
            "name": "test-marketplace",
            "owner": { "name": "Test Owner" },
            "plugins": [
                {
                    "name": "cool-plugin",
                    "source": "cool-plugin",
                    "description": "A cool test plugin"
                }
            ]
        });
        fs::write(
            mp_meta.join("marketplace.json"),
            serde_json::to_string_pretty(&marketplace_manifest).unwrap(),
        )
        .unwrap();

        // Create the actual plugin inside the marketplace
        let plugin_dir = mp_root.join("cool-plugin");
        let plugin_cc_dir = plugin_dir.join(".claude-plugin");
        let plugin_cmds = plugin_dir.join("commands");
        fs::create_dir_all(&plugin_cc_dir).unwrap();
        fs::create_dir_all(&plugin_cmds).unwrap();

        fs::write(
            plugin_cc_dir.join("plugin.json"),
            r#"{"name": "cool-plugin", "version": "1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            plugin_cmds.join("do-stuff.md"),
            "# Do stuff\nDo something cool.",
        )
        .unwrap();

        // Verify we can parse the marketplace manifest
        let content = fs::read_to_string(mp_meta.join("marketplace.json")).unwrap();
        let manifest: MarketplaceManifest = serde_json::from_str(&content).unwrap();
        assert_eq!(manifest.name, "test-marketplace");
        assert_eq!(manifest.plugins.len(), 1);
        assert_eq!(manifest.plugins[0].name, "cool-plugin");

        // Verify the plugin within the marketplace loads correctly
        let plugin = Plugin::load(&plugin_dir).unwrap();
        assert_eq!(plugin.name(), "cool-plugin");
        assert_eq!(plugin.resolved_commands().len(), 1);
    }

    #[test]
    fn test_copy_dir_recursive() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();

        // Create a nested structure
        let sub = src.path().join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(src.path().join("file1.txt"), "hello").unwrap();
        fs::write(sub.join("file2.txt"), "world").unwrap();

        let dest_path = dst.path().join("copy");
        copy_dir_recursive(src.path(), &dest_path).unwrap();

        assert!(dest_path.join("file1.txt").exists());
        assert!(dest_path.join("sub/file2.txt").exists());
        assert_eq!(
            fs::read_to_string(dest_path.join("file1.txt")).unwrap(),
            "hello"
        );
        assert_eq!(
            fs::read_to_string(dest_path.join("sub/file2.txt")).unwrap(),
            "world"
        );
    }

    #[test]
    fn test_plugin_enable_disable_flow() {
        let dir = TempDir::new().unwrap();
        create_cc_plugin(dir.path(), "toggle-plugin");

        let mut manager = PluginManager::with_paths(vec![dir.path().to_path_buf()]);
        let errors = manager.discover();
        assert!(errors.is_empty());

        // Initially enabled
        assert!(manager.get("toggle-plugin").unwrap().enabled);

        // Disable
        manager.disable("toggle-plugin").unwrap();
        assert!(!manager.get("toggle-plugin").unwrap().enabled);

        // all_commands should not return disabled plugin commands
        let cmds = manager.all_commands();
        for (p, _) in &cmds {
            assert_ne!(p.name(), "toggle-plugin");
        }

        // Re-enable
        manager.enable("toggle-plugin").unwrap();
        assert!(manager.get("toggle-plugin").unwrap().enabled);

        // Error on nonexistent plugin
        assert!(manager.enable("nonexistent").is_err());
        assert!(manager.disable("nonexistent").is_err());
    }

    #[test]
    fn test_plugin_reload() {
        let dir = TempDir::new().unwrap();
        create_cc_plugin(dir.path(), "reload-plugin");

        let mut manager = PluginManager::with_paths(vec![dir.path().to_path_buf()]);
        manager.discover();
        assert_eq!(manager.count(), 1);

        // Add another plugin to the directory
        create_cc_plugin(dir.path(), "new-plugin");

        // Reload should find it
        let errors = manager.reload();
        assert!(errors.is_empty());
        assert_eq!(manager.count(), 2);
        assert!(manager.get("reload-plugin").is_some());
        assert!(manager.get("new-plugin").is_some());
    }

    #[test]
    fn test_command_front_matter_parsing() {
        let content = r"---
description: Create a git commit
allowed-tools: Bash(git add:*), Bash(git status:*), Bash(git commit:*)
---

## Context

Based on the above changes, create a single git commit.
";
        let fm = parse_command_front_matter(content);
        assert_eq!(fm.description.as_deref(), Some("Create a git commit"));
        assert!(fm.allowed_tools.is_some());
        let tools = fm.allowed_tools.unwrap();
        assert_eq!(tools.len(), 3);
        assert_eq!(tools[0], "Bash(git add:*)");
        assert!(fm.body.contains("## Context"));
        assert!(!fm.body.contains("---"));
    }

    #[test]
    fn test_command_front_matter_array_syntax() {
        let content = r"---
description: An example command
argument-hint: <required-arg> [optional-arg]
allowed-tools: [Read, Glob, Grep, Bash]
model: haiku
---

# Example Command

Do something.
";
        let fm = parse_command_front_matter(content);
        assert_eq!(fm.description.as_deref(), Some("An example command"));
        assert_eq!(
            fm.argument_hint.as_deref(),
            Some("<required-arg> [optional-arg]")
        );
        assert_eq!(fm.model.as_deref(), Some("haiku"));
        let tools = fm.allowed_tools.unwrap();
        assert_eq!(tools, vec!["Read", "Glob", "Grep", "Bash"]);
        assert!(fm.body.starts_with("# Example Command"));
    }

    #[test]
    fn test_command_front_matter_space_separated_scoped_tools() {
        let content = r"---
description: Commit helper
allowed-tools: Bash(git add *) Bash(git status *) Bash(git commit *)
---

Create a commit.
";
        let fm = parse_command_front_matter(content);
        let tools = fm.allowed_tools.unwrap();

        assert_eq!(
            tools,
            vec![
                "Bash(git add *)",
                "Bash(git status *)",
                "Bash(git commit *)"
            ]
        );
    }

    #[test]
    fn test_command_no_front_matter() {
        let content = "# Just a heading\n\nSome content.\n";
        let fm = parse_command_front_matter(content);
        assert!(fm.description.is_none());
        assert!(fm.allowed_tools.is_none());
        assert!(fm.argument_hint.is_none());
        assert!(fm.model.is_none());
        assert_eq!(fm.body, content);
    }

    // ----- crosslink #373: panic-safety regression tests ---------------------
    // The pre-fix implementation used raw byte slicing (`&s[..end]`,
    // `&s[body_start..]`) into command markdown. While `find("\n---")` only
    // ever returns ASCII-aligned offsets, defense-in-depth requires that no
    // future edit can regress into a panic on multibyte input. These tests
    // exercise emoji, CJK, mixed scripts, and adversarial truncation. The
    // function must NEVER panic — it falls back to the raw body on any
    // parse failure (matching the existing API contract).

    /// Emoji (4-byte UTF-8) inside the YAML description must not panic and
    /// must round-trip through `serde_yaml` unchanged.
    #[test]
    fn test_front_matter_emoji_in_yaml() {
        let content = "---\ndescription: \"Deploy rocket \u{1F680} now\"\n---\n\nBody here.\n";
        let fm = parse_command_front_matter(content);
        assert_eq!(
            fm.description.as_deref(),
            Some("Deploy rocket \u{1F680} now")
        );
        assert!(fm.body.contains("Body here."));
    }

    /// CJK content (3-byte UTF-8 codepoints) in the body section. The
    /// closing `\n---` offset is computed in bytes — body slicing must use
    /// char-boundary-safe access.
    #[test]
    fn test_front_matter_cjk_in_body() {
        let content = "---\ndescription: cjk-test\n---\n\u{4F60}\u{597D}\u{4E16}\u{754C}\n";
        let fm = parse_command_front_matter(content);
        assert_eq!(fm.description.as_deref(), Some("cjk-test"));
        assert!(
            fm.body.contains('\u{4F60}'),
            "CJK body must survive slicing: {:?}",
            fm.body
        );
    }

    /// Mixed multibyte: emoji in YAML AND CJK in body simultaneously.
    /// Any naive byte-arithmetic regression hits both slice sites at once.
    #[test]
    fn test_front_matter_mixed_multibyte() {
        let content = concat!(
            "---\n",
            "description: \"\u{1F4A1} idea\"\n",
            "argument-hint: \"\u{2728} sparkle\"\n",
            "---\n",
            "\n",
            "\u{65E5}\u{672C}\u{8A9E} content with \u{1F389}.\n",
        );
        let fm = parse_command_front_matter(content);
        assert_eq!(fm.description.as_deref(), Some("\u{1F4A1} idea"));
        assert_eq!(fm.argument_hint.as_deref(), Some("\u{2728} sparkle"));
        assert!(fm.body.contains('\u{65E5}'));
        assert!(fm.body.contains('\u{1F389}'));
    }

    /// Adversarial truncation: opening `---` followed by closing `\n---`
    /// with nothing after it (`body_start` equals `after_first.len()`).
    /// Pre-fix code claimed this would overflow; in practice `find`
    /// guarantees it, but the test pins the no-panic contract.
    #[test]
    fn test_front_matter_truncated_at_closing_marker() {
        let content = "---\ndescription: tiny\n---";
        let fm = parse_command_front_matter(content);
        // serde_yaml should parse the description; body is empty.
        assert_eq!(fm.description.as_deref(), Some("tiny"));
        assert_eq!(fm.body, "");
    }

    /// Malformed YAML (unclosed quote with multibyte content) must fall
    /// back to the raw-body branch, not panic. This is the "Err not panic"
    /// contract translated to this function's struct-return API.
    #[test]
    fn test_front_matter_malformed_yaml_with_multibyte_no_panic() {
        let content = "---\ndescription: \"unterminated \u{1F525}\nallowed-tools: [Bash\n---\n\nbody \u{4E2D}\u{6587}\n";
        // Must not panic; on YAML parse failure the whole content becomes the body.
        let fm = parse_command_front_matter(content);
        assert!(fm.description.is_none());
        assert!(fm.allowed_tools.is_none());
        assert_eq!(fm.body, content);
    }

    /// Pathological input: opening `---` then immediately EOF (no closing
    /// marker, no body). Pre-fix `trimmed[3..]` would still work because
    /// `---` is ASCII, but a future regression that lands the index mid-
    /// codepoint must produce a graceful fallback, not a panic. We use
    /// `trim_start` input prefixed with non-ASCII to also exercise the
    /// outer `trim_start().starts_with("---")` short-circuit on multibyte.
    #[test]
    fn test_front_matter_unclosed_and_leading_multibyte_no_panic() {
        // Leading multibyte prefix: function should not treat this as
        // front matter at all (trim_start preserves the non-whitespace
        // codepoint, so starts_with("---") is false).
        let leading = "\u{1F600}---\ndescription: x\n";
        let fm = parse_command_front_matter(leading);
        assert!(fm.description.is_none());
        assert_eq!(fm.body, leading);

        // Opening marker but no closing marker — falls through to the
        // "no closing ---" branch. Must not panic.
        let unclosed = "---\ndescription: orphan with \u{1F4A5}\nand more \u{4E2D}\u{6587}\n";
        let fm2 = parse_command_front_matter(unclosed);
        assert!(fm2.description.is_none());
        assert_eq!(fm2.body, unclosed);
    }

    #[test]
    fn test_real_plugin_front_matter_integration() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = dir.path().join("commit-test");
        let cc_dir = plugin_dir.join(".claude-plugin");
        let commands_dir = plugin_dir.join("commands");
        fs::create_dir_all(&cc_dir).unwrap();
        fs::create_dir_all(&commands_dir).unwrap();

        fs::write(
            cc_dir.join("plugin.json"),
            r#"{"name": "commit-test", "description": "Test front matter"}"#,
        )
        .unwrap();

        // Write a command with front matter (matching real Claude plugin format)
        fs::write(
            commands_dir.join("commit.md"),
            r"---
allowed-tools: Bash(git add:*), Bash(git status:*), Bash(git commit:*)
description: Create a git commit
---

## Context

- Current git status: !`git status`

## Your task

Based on the above changes, create a single git commit.
",
        )
        .unwrap();

        let plugin = Plugin::load(&plugin_dir).unwrap();
        let commands = plugin.resolved_commands();
        assert_eq!(commands.len(), 1);

        let cmd = &commands[0];
        assert_eq!(cmd.name, "commit");
        assert_eq!(cmd.description.as_deref(), Some("Create a git commit"));
        assert!(cmd.allowed_tools.is_some());
        assert_eq!(cmd.allowed_tools.as_ref().unwrap().len(), 3);
        // Content should NOT contain front matter
        assert!(!cmd.content.contains("allowed-tools:"));
        assert!(cmd.content.contains("## Context"));
        assert!(cmd.content.contains("git commit"));
    }

    // ---------------------------------------------------------------------
    // crosslink #347: plugin path-validation hardening
    //
    // Three independent defects covered by these tests:
    //   (1) Plugin::load followed manifest symlinks.
    //   (2) resolve_* methods used `self.path.join(rel)` with no
    //       traversal / absolute-path / symlink rejection, so a
    //       manifest could request `../../../../etc/passwd`.
    //   (3) load_legacy_manifest used `unwrap_or("unknown")` for
    //       missing names, collapsing many bad manifests into one
    //       plugin slot and passing validate_manifest accidentally.
    //
    // Each test exercises one defect end-to-end.
    // ---------------------------------------------------------------------

    /// (Helper) Drop a Claude-Code-style plugin shell at `<root>/<name>`
    /// with the given JSON manifest (no commands/hooks generated). Used
    /// by the path-traversal tests below where the manifest itself is
    /// hostile and the convention-based discovery would otherwise mask
    /// the failure mode under test.
    fn write_manifest(root: &Path, name: &str, manifest_json: &serde_json::Value) -> PathBuf {
        let plugin_dir = root.join(name);
        let cc_dir = plugin_dir.join(".claude-plugin");
        fs::create_dir_all(&cc_dir).unwrap();
        fs::write(
            cc_dir.join("plugin.json"),
            serde_json::to_string_pretty(manifest_json).unwrap(),
        )
        .unwrap();
        plugin_dir
    }

    // ----- validate_plugin_path direct unit tests --------------------------

    #[test]
    fn test_validate_plugin_path_accepts_normal_relative() {
        let dir = TempDir::new().unwrap();
        // Real file so canonicalization succeeds.
        let sub = dir.path().join("commands");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("hello.md"), "x").unwrap();

        let resolved = validate_plugin_path(dir.path(), "commands/hello.md").unwrap();
        assert!(resolved.ends_with("commands/hello.md"));
        // Containment property: canonical resolved is under canonical root.
        let canon_root = dir.path().canonicalize().unwrap();
        let canon = resolved.canonicalize().unwrap();
        assert!(canon.starts_with(&canon_root));
    }

    #[test]
    fn test_validate_plugin_path_rejects_parent_traversal() {
        let dir = TempDir::new().unwrap();
        let err = validate_plugin_path(dir.path(), "../../etc/passwd").unwrap_err();
        assert!(
            matches!(err, PluginError::InvalidManifest(ref m) if m.contains("'..'")),
            "expected traversal rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_plugin_path_rejects_embedded_parent_traversal() {
        let dir = TempDir::new().unwrap();
        // Even hidden inside otherwise-normal components.
        let err = validate_plugin_path(dir.path(), "commands/../../../etc/shadow").unwrap_err();
        assert!(matches!(err, PluginError::InvalidManifest(_)));
    }

    #[test]
    fn test_validate_plugin_path_rejects_absolute_path() {
        let dir = TempDir::new().unwrap();
        let err = validate_plugin_path(dir.path(), "/etc/passwd").unwrap_err();
        assert!(
            matches!(err, PluginError::InvalidManifest(ref m) if m.contains("relative")),
            "expected absolute-path rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_plugin_path_rejects_empty() {
        let dir = TempDir::new().unwrap();
        let err = validate_plugin_path(dir.path(), "").unwrap_err();
        assert!(matches!(err, PluginError::InvalidManifest(_)));
    }

    #[test]
    fn test_validate_plugin_path_rejects_nul_byte() {
        // Classic NUL-truncation attack: "safe.md\0/etc/passwd". A naive
        // CString-based file open would silently read /etc/passwd.
        let dir = TempDir::new().unwrap();
        let err = validate_plugin_path(dir.path(), "safe.md\0/etc/passwd").unwrap_err();
        assert!(matches!(err, PluginError::InvalidManifest(ref m) if m.contains("NUL")));
    }

    #[test]
    #[cfg(unix)]
    fn test_validate_plugin_path_rejects_symlink_component() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        // Create an attacker-controlled "decoy" symlink inside the plugin
        // root that points to /etc.
        let attack = dir.path().join("decoy");
        symlink("/etc", &attack).unwrap();

        let err = validate_plugin_path(dir.path(), "decoy/passwd").unwrap_err();
        assert!(
            matches!(err, PluginError::InvalidManifest(ref m) if m.contains("symlink")),
            "expected symlink rejection, got: {err}"
        );
    }

    // ----- read_plugin_file: forensic proof we do not follow symlinks ------

    #[test]
    #[cfg(unix)]
    fn test_read_plugin_file_rejects_symlinked_manifest() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        // The "secret" target the attacker wants exfiltrated.
        let secret = dir.path().join("secret.txt");
        fs::write(&secret, "SUPER-SECRET").unwrap();

        // The plugin's manifest is a symlink to the secret.
        let plugin_dir = dir.path().join("evil");
        let cc_dir = plugin_dir.join(".claude-plugin");
        fs::create_dir_all(&cc_dir).unwrap();
        let manifest_path = cc_dir.join("plugin.json");
        symlink(&secret, &manifest_path).unwrap();

        let err = read_plugin_file(&manifest_path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("symlink"), "expected symlink rejection: {msg}");
        // Forensic: the secret contents MUST NOT appear in the error.
        assert!(
            !msg.contains("SUPER-SECRET"),
            "secret leaked into error message: {msg}"
        );
    }

    // ----- (1) Plugin::load: symlinked manifest is refused -----------------

    #[test]
    #[cfg(unix)]
    fn test_plugin_load_rejects_symlinked_manifest_to_outside_file() {
        use std::os::unix::fs::symlink;
        let scratch = TempDir::new().unwrap();
        // Sensitive file outside any plugin dir.
        let outside = scratch.path().join("outside_secret");
        fs::write(&outside, "OUTSIDE").unwrap();

        let plugin_dir = scratch.path().join("p");
        let cc_dir = plugin_dir.join(".claude-plugin");
        fs::create_dir_all(&cc_dir).unwrap();
        // plugin.json is a symlink that escapes the plugin tree entirely.
        symlink(&outside, cc_dir.join("plugin.json")).unwrap();

        let result = Plugin::load(&plugin_dir);
        assert!(result.is_err(), "symlinked manifest must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("symlink"),
            "expected symlink error, got: {msg}"
        );
        assert!(
            !msg.contains("OUTSIDE"),
            "outside file contents leaked: {msg}"
        );
    }

    // ----- (2) Path traversal in manifest command/hook/mcp paths -----------

    #[test]
    fn test_manifest_commands_path_with_traversal_is_rejected() {
        let dir = TempDir::new().unwrap();
        // Attacker manifest: commands is a sibling-escaping path.
        let plugin_dir = write_manifest(
            dir.path(),
            "evil",
            &serde_json::json!({
                "name": "evil-plugin",
                "commands": "../../../../etc/passwd",
            }),
        );
        // Plant a "fake passwd" outside the plugin dir to prove we never
        // would have read it even if traversal worked: it must not show
        // up in command_paths regardless.
        let outside = dir.path().join("passwd_decoy");
        fs::write(&outside, "decoy").unwrap();

        let plugin = Plugin::load(&plugin_dir).unwrap();
        assert!(
            plugin.command_paths.is_empty(),
            "command_paths must reject traversal: {:?}",
            plugin.command_paths
        );
    }

    #[test]
    fn test_manifest_commands_paths_array_with_traversal_is_rejected() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = write_manifest(
            dir.path(),
            "evil2",
            &serde_json::json!({
                "name": "evil2-plugin",
                "commands": ["../escape.md", "/etc/passwd"],
            }),
        );
        let plugin = Plugin::load(&plugin_dir).unwrap();
        assert!(plugin.command_paths.is_empty());
    }

    #[test]
    fn test_manifest_commands_map_source_with_traversal_is_rejected() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = write_manifest(
            dir.path(),
            "evil3",
            &serde_json::json!({
                "name": "evil3-plugin",
                "commands": {
                    "pwned": { "source": "../../../etc/passwd" }
                }
            }),
        );
        let plugin = Plugin::load(&plugin_dir).unwrap();
        // The unsafe source must not be added to command_paths even
        // though the entry's metadata is recorded.
        assert!(plugin.command_paths.is_empty());
    }

    #[test]
    fn test_manifest_hooks_path_with_traversal_is_rejected() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = write_manifest(
            dir.path(),
            "evil-hooks",
            &serde_json::json!({
                "name": "evil-hooks-plugin",
                "hooks": "../../../etc/hosts",
            }),
        );
        let plugin = Plugin::load(&plugin_dir).unwrap();
        assert!(plugin.hook_definitions.is_empty());
    }

    #[test]
    fn test_manifest_mcp_servers_path_with_traversal_is_rejected() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = write_manifest(
            dir.path(),
            "evil-mcp",
            &serde_json::json!({
                "name": "evil-mcp-plugin",
                "mcpServers": "../../../etc/passwd",
            }),
        );
        let plugin = Plugin::load(&plugin_dir).unwrap();
        assert!(plugin.mcp_configs.is_empty());
    }

    #[test]
    fn test_manifest_agents_path_with_traversal_is_rejected() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = write_manifest(
            dir.path(),
            "evil-agents",
            &serde_json::json!({
                "name": "evil-agents-plugin",
                "agents": ["../../../etc/passwd"],
            }),
        );
        let plugin = Plugin::load(&plugin_dir).unwrap();
        assert!(plugin.agent_paths.is_empty());
    }

    #[test]
    fn test_manifest_skills_path_with_traversal_is_rejected() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = write_manifest(
            dir.path(),
            "evil-skills",
            &serde_json::json!({
                "name": "evil-skills-plugin",
                "skills": "/etc",
            }),
        );
        let plugin = Plugin::load(&plugin_dir).unwrap();
        assert!(plugin.skill_paths.is_empty());
    }

    // ----- (3) Legacy manifest fallback-name vulnerability -----------------

    #[test]
    fn test_legacy_manifest_missing_name_is_rejected() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = dir.path().join("nameless-legacy");
        fs::create_dir_all(&plugin_dir).unwrap();
        // No "name" field at all.
        fs::write(
            plugin_dir.join("manifest.json"),
            r#"{ "version": "1.0.0" }"#,
        )
        .unwrap();

        let err = Plugin::load(&plugin_dir).unwrap_err();
        assert!(
            matches!(err, PluginError::InvalidManifest(ref m) if m.contains("name")),
            "expected explicit name-missing error, got: {err}"
        );
    }

    #[test]
    fn test_legacy_manifest_non_string_name_is_rejected() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = dir.path().join("badname-legacy");
        fs::create_dir_all(&plugin_dir).unwrap();
        // `name` is not a string — previously this silently became
        // "unknown". Now it must error.
        fs::write(
            plugin_dir.join("manifest.json"),
            r#"{ "name": 42, "version": "1.0.0" }"#,
        )
        .unwrap();

        let err = Plugin::load(&plugin_dir).unwrap_err();
        assert!(matches!(err, PluginError::InvalidManifest(_)));
    }

    #[test]
    fn test_legacy_mcp_server_missing_name_is_rejected() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = dir.path().join("badmcp-legacy");
        fs::create_dir_all(&plugin_dir).unwrap();
        // Top-level name is fine; the mcp_servers entry is missing
        // its own name (previously silently coerced to "unknown",
        // so two such entries would collide on the same key).
        fs::write(
            plugin_dir.join("manifest.json"),
            r#"{
                "name": "ok-plugin",
                "mcp_servers": [
                    { "transport": "stdio", "command": "node" }
                ]
            }"#,
        )
        .unwrap();

        let err = Plugin::load(&plugin_dir).unwrap_err();
        assert!(
            matches!(err, PluginError::InvalidManifest(ref m) if m.contains("mcp_servers") && m.contains("name")),
            "expected mcp_servers name-missing error, got: {err}"
        );
    }

    /// Forensic test: the "fallback name with shell metacharacters"
    /// case from the task brief. Verifies that a legacy plugin name
    /// containing shell-dangerous characters does NOT silently become
    /// the literal "unknown" fallback. We accept either of two equally
    /// safe outcomes — outright rejection (preferred), or surfacing
    /// the literal hostile string so a downstream consumer can sanitize
    /// — but the one outcome we forbid is the silent "unknown"
    /// collapse that the old code produced.
    #[test]
    fn test_legacy_manifest_hostile_name_does_not_collapse_to_unknown() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = dir.path().join("hostile-legacy");
        fs::create_dir_all(&plugin_dir).unwrap();
        // A name field that's still a JSON string but contains shell
        // metacharacters + NUL byte. The old fallback code would have
        // produced "unknown" if this had failed type coercion; with
        // `as_str()` returning Some(...) we now surface the literal
        // string, which `validate_manifest` rejects.
        fs::write(
            plugin_dir.join("manifest.json"),
            r#"{ "name": "evil; rm -rf /" }"#,
        )
        .unwrap();

        let result = Plugin::load(&plugin_dir);
        // Either it errors (validate_manifest catches the space) or
        // the plugin name is preserved verbatim — but it must NEVER
        // be the literal "unknown".
        match result {
            Err(_) => { /* preferred: rejected */ }
            Ok(p) => {
                assert_ne!(
                    p.name(),
                    "unknown",
                    "hostile name silently collapsed to 'unknown' fallback"
                );
            }
        }
    }
}
