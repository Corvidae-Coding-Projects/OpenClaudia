//! Plugin manifest types and Claude Code-compatible structures.
//!
//! Contains all types related to `.claude-plugin/plugin.json` parsing,
//! including commands, hooks, MCP servers, agents, and skills specs.
//!
//! # Deserialization safety
//!
//! Several fields in plugin manifests accept multiple YAML/JSON shapes (string
//! path, inline object, array, …).  These are modelled with
//! `#[serde(untagged)]` enums.  To prevent serde's "first variant that parses"
//! behaviour from silently swallowing mis-shaped input we apply two mitigations:
//!
//! * `#[serde(deny_unknown_fields)]` on every struct that appears as an untagged
//!   variant — unknown keys cause an explicit error instead of being silently
//!   dropped.
//! * A custom [`Deserialize`] for [`CommandsSpec`] that validates the `Map`
//!   variant: every entry in the map must supply at least one of `source` or
//!   `content`, so an empty `CommandMetadata` (all `None`) is rejected.  This
//!   prevents a stray YAML object like `{source: "./cmds"}` (intended as a path
//!   string) from silently becoming `Map{"source" → CommandMetadata{…all None}}`.

use crate::plugins::validate::PluginSignature;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Claude Code-compatible plugin manifest (.claude-plugin/plugin.json)
// ---------------------------------------------------------------------------

/// Plugin author information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginAuthor {
    /// Display name of the plugin author or organization
    pub name: String,
    /// Contact email
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Website or GitHub profile URL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Command metadata in the manifest (object form).
///
/// `deny_unknown_fields` is required so that a stray YAML object like
/// `{source: "./cmds"}` — which the author intended as the string form of
/// `CommandsSpec::Path` — cannot silently deserialize as a one-entry
/// `CommandsSpec::Map` whose `CommandMetadata` value absorbs `source` as an
/// optional field.  With `deny_unknown_fields` any key not listed here becomes
/// a hard error, making the bug surface at parse time instead of at install time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandMetadata {
    /// Path to command markdown file, relative to plugin root
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Inline markdown content for the command
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Command description override
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Hint for command arguments (e.g., "[file]")
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "argumentHint"
    )]
    pub argument_hint: Option<String>,
    /// Default model for this command
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Tools allowed when command runs
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "allowedTools"
    )]
    pub allowed_tools: Option<Vec<String>>,
}

impl CommandMetadata {
    /// Returns `true` when the entry carries at least one content pointer.
    ///
    /// Used by the custom [`CommandsSpec`] deserializer to reject all-`None`
    /// entries that result from a mis-shaped YAML object being silently coerced
    /// into a map variant.
    #[must_use]
    pub const fn has_content(&self) -> bool {
        self.source.is_some() || self.content.is_some()
    }
}

/// Commands field in manifest — can be a path string, array of paths, or object map.
///
/// # Deserialization order and safety
///
/// Variants are tried in declaration order by serde's untagged machinery.  The
/// ordering is safe because the three shapes are structurally disjoint:
///
/// 1. `Path(String)` — YAML scalar.  Cannot be confused with an array or object.
/// 2. `Paths(Vec<String>)` — YAML sequence of scalars.  Cannot be confused with
///    an object.
/// 3. `Map(HashMap<…>)` — YAML mapping.  Tried last.
///
/// The custom [`Deserialize`] impl below adds an extra check on the `Map`
/// variant: every entry must have at least one of `source` or `content`.  An
/// all-`None` entry indicates that the object was never meant to be a map.
#[derive(Debug, Clone, Serialize)]
pub enum CommandsSpec {
    /// Single path to command file or directory
    Path(String),
    /// Array of paths to command files or directories
    Paths(Vec<String>),
    /// Object mapping of command names to their metadata
    Map(HashMap<String, CommandMetadata>),
}

impl<'de> Deserialize<'de> for CommandsSpec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        use serde_json::Value;

        let raw = Value::deserialize(deserializer)?;
        match raw {
            Value::String(s) => Ok(Self::Path(s)),
            Value::Array(arr) => {
                let mut paths = Vec::with_capacity(arr.len());
                for v in arr {
                    match v {
                        Value::String(s) => paths.push(s),
                        other => {
                            return Err(D::Error::custom(format!(
                                "commands array must contain strings, got: {other}"
                            )));
                        }
                    }
                }
                Ok(Self::Paths(paths))
            }
            Value::Object(obj) => {
                let mut map = HashMap::with_capacity(obj.len());
                for (key, val) in obj {
                    let meta: CommandMetadata = serde_json::from_value(val).map_err(|e| {
                        D::Error::custom(format!(
                            "commands map entry '{key}' is not valid CommandMetadata: {e}"
                        ))
                    })?;
                    if !meta.has_content() {
                        return Err(D::Error::custom(format!(
                            "commands map entry '{key}' must specify at least one of \
                             'source' or 'content'; \
                             did you mean `commands: \"<path>\"` instead of an object?"
                        )));
                    }
                    map.insert(key, meta);
                }
                Ok(Self::Map(map))
            }
            other => Err(D::Error::custom(format!(
                "commands must be a string, array of strings, or object map; got: {other}"
            ))),
        }
    }
}

/// Hooks field in manifest — can be a path string, inline object, or array.
///
/// # Disambiguation
///
/// serde's `untagged` tries variants in declaration order.  The ordering below
/// is safe because the three shapes are structurally disjoint:
///
/// * `Path` — YAML scalar (string).
/// * `Inline` — YAML mapping.  Safe because [`HooksDefinition`] carries
///   `deny_unknown_fields`, so any key that is not one of the seven known hook
///   event names causes a hard error.  In particular, `{"path": "./hooks.json"}`
///   will **not** silently become an empty `Inline` — the unknown key `path` is
///   rejected.
/// * `Array` — YAML sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HooksSpec {
    /// Path to hooks JSON file relative to plugin root
    Path(String),
    /// Inline hooks object (same format as settings hooks)
    Inline(HooksDefinition),
    /// Array of paths or inline hooks
    Array(Vec<HooksSpecEntry>),
}

/// Single entry in a hooks array.
///
/// Same disambiguation guarantees as [`HooksSpec`]: `deny_unknown_fields` on
/// [`HooksDefinition`] prevents a stray `{"path": "…"}` entry from being
/// silently accepted as an empty inline definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HooksSpecEntry {
    /// Path to hooks JSON file
    Path(String),
    /// Inline hooks definition
    Inline(HooksDefinition),
}

/// Hooks definition matching Claude Code's hooks format.
///
/// `deny_unknown_fields` is the load-bearing safety mechanism here: it ensures
/// that any YAML object whose keys do not match the known hook event names
/// (`PreToolUse`, `PostToolUse`, `Notification`, `Stop`, `UserPromptSubmit`,
/// `SessionStart`, `description`) is rejected at parse time.  Without it, serde
/// produces an all-empty `HooksDefinition` for arbitrary objects — silently
/// discarding the user's configuration.  In particular, `{"path":
/// "./hooks.json"}` would parse as `Inline(HooksDefinition{all empty})` and
/// silently ignore the file reference entirely.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HooksDefinition {
    /// Optional human-readable description of this hooks block
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Pre-tool-use hooks
    #[serde(default, rename = "PreToolUse", skip_serializing_if = "Vec::is_empty")]
    pub pre_tool_use: Vec<HookEntry>,
    /// Post-tool-use hooks
    #[serde(default, rename = "PostToolUse", skip_serializing_if = "Vec::is_empty")]
    pub post_tool_use: Vec<HookEntry>,
    /// Notification hooks
    #[serde(
        default,
        rename = "Notification",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub notification: Vec<HookEntry>,
    /// Stop hooks
    #[serde(default, rename = "Stop", skip_serializing_if = "Vec::is_empty")]
    pub stop: Vec<HookEntry>,
    /// Prompt submit hooks
    #[serde(
        default,
        rename = "UserPromptSubmit",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub user_prompt_submit: Vec<HookEntry>,
    /// Session start hooks
    #[serde(
        default,
        rename = "SessionStart",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub session_start: Vec<HookEntry>,
}

/// A single hook entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookEntry {
    /// Matcher pattern (tool name regex for PreToolUse/PostToolUse)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matcher: Option<String>,
    /// Hook type
    #[serde(rename = "type")]
    pub hook_type: String,
    /// Command to execute (for "command" type)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Timeout in seconds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
}

/// MCP server configurations - can be a path, object map, or array
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum McpServersSpec {
    /// Path to MCP servers JSON configuration file
    Path(String),
    /// MCP server configurations keyed by server name
    Map(HashMap<String, McpServerConfig>),
    /// Array of configurations
    Array(Vec<McpServersSpecEntry>),
}

/// Single entry in MCP servers array
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum McpServersSpecEntry {
    /// Path to configuration file
    Path(String),
    /// Inline MCP server configurations
    Map(HashMap<String, McpServerConfig>),
}

/// MCP server configuration (matches Claude Code format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    /// Command to execute
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Command arguments
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Environment variables
    #[serde(
        default,
        skip_serializing_if = "crate::secrets::EnvironmentGrants::is_empty"
    )]
    pub env: crate::secrets::EnvironmentGrants,
    /// Transport type (stdio or http)
    #[serde(
        default = "default_transport",
        alias = "type",
        deserialize_with = "deserialize_transport"
    )]
    pub transport: String,
    /// URL for HTTP transport
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Static HTTP headers for remote MCP transports.
    #[serde(
        default,
        skip_serializing_if = "crate::secrets::SensitiveHeaders::is_empty"
    )]
    pub headers: crate::secrets::SensitiveHeaders,
    /// Dynamic header helper command. Parsed so the connection layer can
    /// explicitly reject unsupported dynamic auth instead of silently
    /// dropping it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "headersHelper"
    )]
    pub headers_helper: Option<String>,
    /// Per-server tool execution timeout in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// Claude Code tool-search hint for eager loading.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "alwaysLoad"
    )]
    pub always_load: Option<bool>,
}

fn default_transport() -> String {
    "stdio".to_string()
}

fn normalize_transport(transport: &str) -> String {
    match transport {
        "streamable-http" => "http".to_string(),
        other => other.to_string(),
    }
}

fn deserialize_transport<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    Ok(normalize_transport(&raw))
}

/// LSP server configuration declared by a plugin manifest (CC parity
/// with `lspPluginIntegration.ts`, crosslink #655).
///
/// A plugin can ship its own language server (e.g. a custom DSL the
/// plugin author owns); on enable the host registers it with the LSP
/// pool so the standard `lsp` tool dispatches against it transparently.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LspServerConfig {
    /// Executable to spawn.
    pub command: String,
    /// Arguments passed to the executable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Extra environment variables injected into the spawned process.
    /// The standard LSP env-scrub allowlist (see `tools::lsp`) still
    /// applies — credentials that fail the allowlist are dropped with a
    /// `warn!` log.
    #[serde(
        default,
        skip_serializing_if = "crate::secrets::EnvironmentGrants::is_empty"
    )]
    pub env: crate::secrets::EnvironmentGrants,
    /// File extensions the server claims (e.g. `["rs"]`). Empty means
    /// the server is invocation-only — it does not auto-register against
    /// any extension.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
}

/// Agents field - can be path string or array of paths
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AgentsSpec {
    /// Single path to agent markdown file
    Path(String),
    /// Array of paths to agent markdown files
    Paths(Vec<String>),
}

/// Skills field - can be path string or array of paths
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SkillsSpec {
    /// Single path to skill directory
    Path(String),
    /// Array of paths to skill directories
    Paths(Vec<String>),
}

/// Claude Code-compatible plugin manifest (.claude-plugin/plugin.json)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Plugin name (kebab-case, unique identifier)
    pub name: String,
    /// Semantic version
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Brief description of what the plugin provides
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Plugin author information
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<PluginAuthor>,
    /// Plugin homepage URL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    /// Source code repository URL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// SPDX license identifier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Tags for discovery and categorization
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keywords: Option<Vec<String>>,
    /// Hook definitions
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hooks: Option<HooksSpec>,
    /// Command definitions
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commands: Option<CommandsSpec>,
    /// Agent definitions
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<AgentsSpec>,
    /// Skill definitions
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skills: Option<SkillsSpec>,
    /// MCP server configurations
    #[serde(
        default,
        rename = "mcpServers",
        skip_serializing_if = "Option::is_none"
    )]
    pub mcp_servers: Option<McpServersSpec>,
    /// LSP server registrations declared by the plugin (CC parity with
    /// `lspPluginIntegration.ts`, crosslink #655).
    ///
    /// Each entry maps a language identifier (e.g. `"rust"`) to an
    /// [`LspServerConfig`] describing how to spawn the server binary.
    /// On plugin load the host wires every entry into the LSP pool so
    /// `is_lsp_connected(run, "rust")` returns true once the plugin is enabled.
    /// `None` ⇒ plugin contributes no LSP servers (overwhelmingly common).
    #[serde(
        default,
        rename = "lspServers",
        skip_serializing_if = "Option::is_none"
    )]
    pub lsp_servers: Option<HashMap<String, LspServerConfig>>,
    /// Optional detached ed25519 signature over the manifest bytes.
    ///
    /// When present, the signature is verified by
    /// [`crate::plugins::validate::verify_signature`] during install if the
    /// active [`crate::plugins::policy::PluginPolicy`] includes a
    /// `RequireSignature` action. The field is skipped during serialization
    /// when absent so existing manifests are unaffected.
    ///
    /// On-disk shape: serialized as a base64 string via the `Serialize` /
    /// `Deserialize` impls on `PluginSignature` itself.
    #[serde(default, rename = "signature", skip_serializing_if = "Option::is_none")]
    pub signature: Option<PluginSignature>,
}

// ---------------------------------------------------------------------------
// Tests — deserialization correctness and forensic regression cases
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- CommandsSpec ---

    /// String scalar → Path variant (backwards-compat, basic case).
    #[test]
    fn commands_spec_string_parses_as_path() {
        let spec: CommandsSpec = serde_json::from_str(r#""./commands""#).unwrap();
        assert!(matches!(spec, CommandsSpec::Path(ref p) if p == "./commands"));
    }

    /// Array of strings → Paths variant.
    #[test]
    fn commands_spec_array_parses_as_paths() {
        let spec: CommandsSpec = serde_json::from_str(r#"["./cmd1.md", "./cmd2.md"]"#).unwrap();
        assert!(matches!(spec, CommandsSpec::Paths(ref v) if v.len() == 2));
    }

    /// Well-formed map with a `source` field → Map variant, content preserved.
    #[test]
    fn commands_spec_map_with_source_parses_correctly() {
        let spec: CommandsSpec =
            serde_json::from_str(r#"{"deploy": {"source": "./deploy.md"}}"#).unwrap();
        match spec {
            CommandsSpec::Map(ref m) => {
                let meta = m.get("deploy").expect("entry must exist");
                assert_eq!(meta.source.as_deref(), Some("./deploy.md"));
            }
            other => panic!("expected Map, got {other:?}"),
        }
    }

    /// Forensic case A — `CommandsSpec` all-None map entry is rejected.
    ///
    /// Before this fix: `{"deploy": {}}` silently deserialized as
    /// `Map{"deploy" => CommandMetadata{all None}}` because `CommandMetadata`
    /// had no required fields.  Now the custom deserializer rejects it.
    #[test]
    fn commands_spec_all_none_map_entry_is_rejected() {
        let err = serde_json::from_str::<CommandsSpec>(r#"{"deploy": {}}"#).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("must specify at least one of"),
            "error must name the constraint; got: {msg}"
        );
    }

    /// Unknown key inside a `CommandMetadata` object is rejected.
    #[test]
    fn commands_spec_map_entry_unknown_field_is_rejected() {
        let err = serde_json::from_str::<CommandsSpec>(
            r#"{"deploy": {"source": "./d.md", "typo_field": true}}"#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("deploy"),
            "error must identify the bad entry; got: {err}"
        );
    }

    /// An array containing a non-string value is rejected.
    #[test]
    fn commands_spec_array_with_non_string_is_rejected() {
        let err = serde_json::from_str::<CommandsSpec>(r#"["./cmd.md", 42]"#).unwrap_err();
        assert!(
            err.to_string().contains("must contain strings"),
            "got: {err}"
        );
    }

    // --- HooksSpec / HooksDefinition ---

    /// String → Path variant.
    #[test]
    fn hooks_spec_string_parses_as_path() {
        let spec: HooksSpec = serde_json::from_str(r#""./hooks/hooks.json""#).unwrap();
        assert!(matches!(spec, HooksSpec::Path(ref p) if p == "./hooks/hooks.json"));
    }

    /// Inline object with known hook keys → Inline(HooksDefinition).
    #[test]
    fn hooks_spec_inline_known_keys_parses_correctly() {
        let json = r#"{"PreToolUse": [{"type": "command", "command": "echo pre"}]}"#;
        let spec: HooksSpec = serde_json::from_str(json).unwrap();
        match spec {
            HooksSpec::Inline(ref def) => {
                assert_eq!(def.pre_tool_use.len(), 1);
                assert_eq!(def.pre_tool_use[0].hook_type, "command");
            }
            other => panic!("expected Inline, got {other:?}"),
        }
    }

    /// Forensic case B — `{"path": "./hooks.json"}` must NOT parse as an empty Inline.
    ///
    /// Before this fix: `HooksDefinition` had no required fields, so any object
    /// silently became `Inline(HooksDefinition{all empty})`.  The user's file
    /// path was completely ignored.  Now `deny_unknown_fields` on
    /// `HooksDefinition` rejects the unknown key `path`.
    #[test]
    fn hooks_spec_unknown_key_object_is_rejected() {
        let result = serde_json::from_str::<HooksSpec>(r#"{"path": "./hooks.json"}"#);
        assert!(
            result.is_err(),
            "expected parse error for unknown field, but got: {result:?}"
        );
    }

    /// Array of hooks entries (mix of path and inline) parses correctly.
    #[test]
    fn hooks_spec_array_parses_correctly() {
        let json = r#"[
            "./hooks/a.json",
            {"PreToolUse": [{"type": "command", "command": "lint"}]}
        ]"#;
        let spec: HooksSpec = serde_json::from_str(json).unwrap();
        match spec {
            HooksSpec::Array(ref entries) => {
                assert_eq!(entries.len(), 2);
                assert!(matches!(entries[0], HooksSpecEntry::Path(_)));
                assert!(matches!(entries[1], HooksSpecEntry::Inline(_)));
            }
            other => panic!("expected Array, got {other:?}"),
        }
    }

    /// `HooksSpecEntry` array with an unknown-field object is rejected.
    #[test]
    fn hooks_spec_entry_unknown_field_rejected() {
        let result = serde_json::from_str::<HooksSpec>(r#"[{"not_a_hook_key": true}]"#);
        assert!(
            result.is_err(),
            "expected parse error for unknown field in array entry; got: {result:?}"
        );
    }

    // --- PluginManifest round-trip (backwards-compat) ---

    /// All three `CommandsSpec` shapes survive a full parse — existing config
    /// files continue to work.
    #[test]
    fn plugin_manifest_commands_backwards_compat_roundtrip() {
        // String form
        let m: PluginManifest =
            serde_json::from_str(r#"{"name":"p","commands":"./commands"}"#).unwrap();
        assert!(matches!(m.commands, Some(CommandsSpec::Path(_))));

        // Array form
        let m: PluginManifest =
            serde_json::from_str(r#"{"name":"p","commands":["./a.md","./b.md"]}"#).unwrap();
        assert!(matches!(m.commands, Some(CommandsSpec::Paths(_))));

        // Map form
        let m: PluginManifest =
            serde_json::from_str(r#"{"name":"p","commands":{"build":{"source":"./build.md"}}}"#)
                .unwrap();
        assert!(matches!(m.commands, Some(CommandsSpec::Map(_))));
    }

    /// #655: a manifest with `lspServers` parses each entry into a typed
    /// [`LspServerConfig`].
    #[test]
    fn plugin_manifest_lsp_servers_parse() {
        let json = r#"{
            "name": "rust-tools",
            "lspServers": {
                "rust": {
                    "command": "rust-analyzer",
                    "args": ["--no-cargo-watch"],
                    "extensions": ["rs"]
                }
            }
        }"#;
        let m: PluginManifest = serde_json::from_str(json).unwrap();
        let servers = m.lsp_servers.expect("lspServers must parse");
        let rust = servers.get("rust").expect("rust server present");
        assert_eq!(rust.command, "rust-analyzer");
        assert_eq!(rust.args, vec!["--no-cargo-watch"]);
        assert_eq!(rust.extensions, vec!["rs"]);
        assert!(rust.env.is_empty());
    }

    /// A manifest with an inline hooks block with valid hook keys parses correctly.
    #[test]
    fn plugin_manifest_hooks_inline_backwards_compat() {
        let json = r#"{
            "name": "my-plugin",
            "hooks": {
                "PreToolUse": [{"type": "command", "command": "lint"}],
                "Stop": [{"type": "command", "command": "cleanup"}]
            }
        }"#;
        let m: PluginManifest = serde_json::from_str(json).unwrap();
        match m.hooks {
            Some(HooksSpec::Inline(ref def)) => {
                assert_eq!(def.pre_tool_use.len(), 1);
                assert_eq!(def.stop.len(), 1);
            }
            other => panic!("expected Inline hooks, got {other:?}"),
        }
    }
}
