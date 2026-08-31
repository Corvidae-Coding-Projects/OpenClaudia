//! Plugin-declared MCP server registry (crosslink #654, CC parity with
//! `mcpPluginIntegration.ts`).
//!
//! Plugins may declare MCP servers in their manifest. The production runtime
//! consumes those declarations directly through `PluginManager` and
//! `McpManager`; this transport-neutral mirror is preserved as experimental
//! migration scaffolding and is not a runtime authority or secret store.
//!
//! Why a typed struct instead of `HashMap<String, McpServerConfig>`: we
//! want to remember which *plugin* contributed each server so a
//! reload-of-one-plugin doesn't drop the others, and so `/mcp list` can
//! attribute each entry to its owning plugin (CC parity).
//!
//! ## Phase 1 scope
//!
//! - In-memory registry with `replace_plugin` / `remove_plugin` /
//!   `all`. No transport layer yet — the actual `mcp::Client` wiring is
//!   the next step and is tracked under #654's runtime follow-up.
//! - [`McpServerSpec`] is a transport-neutral mirror of
//!   [`crate::plugins::manifest::McpServerConfig`] so the consumer can
//!   match on it without taking a plugin-layer dependency.

use crate::plugins::manifest::McpServerConfig;
use crate::secrets::{EnvironmentGrants, SensitiveHeaders};
use std::collections::HashMap;

/// Transport-neutral description of one MCP server, derived from a
/// plugin manifest entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerSpec {
    /// Executable to spawn (`stdio` transport) or absent for `http`.
    pub command: Option<String>,
    /// Arguments to the executable (`stdio` transport).
    pub args: Vec<String>,
    /// Environment variables injected on spawn.
    pub env: EnvironmentGrants,
    /// `"stdio"` or `"http"`.
    pub transport: String,
    /// Endpoint URL (`http` transport) or absent for `stdio`.
    pub url: Option<String>,
    /// Static HTTP headers for remote transports.
    pub headers: SensitiveHeaders,
    /// Dynamic header helper command.
    pub headers_helper: Option<String>,
    /// Standards-based OAuth settings for remote MCP transports.
    pub oauth: Option<crate::mcp_oauth::McpOAuthClientConfig>,
    /// Per-server tool timeout in milliseconds.
    pub timeout: Option<u64>,
    /// Tool-search hint for eager loading.
    pub always_load: Option<bool>,
}

impl McpServerSpec {
    /// Mirror a manifest-side [`McpServerConfig`] into the registry's
    /// transport-neutral form. Cheap clone — no validation here; the
    /// runtime spawner reports invalid combinations.
    #[must_use]
    pub fn from_plugin_config(cfg: &McpServerConfig) -> Self {
        Self {
            command: cfg.command.clone(),
            args: cfg.args.clone(),
            env: cfg.env.clone(),
            transport: cfg.transport.clone(),
            url: cfg.url.clone(),
            headers: cfg.headers.clone(),
            headers_helper: cfg.headers_helper.clone(),
            oauth: cfg.oauth.clone(),
            timeout: cfg.timeout,
            always_load: cfg.always_load,
        }
    }
}

/// One registered (plugin, server) pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpRegistration {
    /// Owning plugin id (matches [`crate::plugins::Plugin::id`]). Used
    /// by `/mcp list` to attribute the server and by [`PluginMcpRegistry
    /// ::replace_plugin`] to atomically swap one plugin's set.
    pub plugin_id: String,
    /// Name the plugin gave the server (manifest map key).
    pub server_name: String,
    /// Spawn spec.
    pub spec: McpServerSpec,
}

/// In-memory registry of plugin-contributed MCP servers.
#[derive(Debug, Clone, Default)]
pub struct PluginMcpRegistry {
    by_plugin: HashMap<String, Vec<McpRegistration>>,
}

impl PluginMcpRegistry {
    /// Replace every registration currently associated with
    /// `plugin_id` with the supplied set. Atomic from the perspective
    /// of [`PluginMcpRegistry::all`] callers — they either see the old
    /// or the new set, never a half-applied state — because this is the
    /// single mutation entry point and runs under the caller's write
    /// lock.
    pub fn replace_plugin(&mut self, plugin_id: &str, registrations: Vec<McpRegistration>) {
        if registrations.is_empty() {
            self.by_plugin.remove(plugin_id);
        } else {
            self.by_plugin.insert(plugin_id.to_string(), registrations);
        }
    }

    /// Drop every registration owned by `plugin_id`. No-op when the
    /// plugin had no registrations. Used on plugin uninstall (#658).
    pub fn remove_plugin(&mut self, plugin_id: &str) {
        self.by_plugin.remove(plugin_id);
    }

    /// Flatten every registration into one vec. Order is unspecified
    /// (`HashMap` iteration); callers that need a stable order should
    /// sort by `(plugin_id, server_name)` themselves.
    #[must_use]
    pub fn all(&self) -> Vec<McpRegistration> {
        self.by_plugin.values().flatten().cloned().collect()
    }

    /// Per-plugin lookup, used by `/mcp list <plugin>` and reload paths.
    #[must_use]
    pub fn for_plugin(&self, plugin_id: &str) -> Vec<McpRegistration> {
        self.by_plugin.get(plugin_id).cloned().unwrap_or_default()
    }

    /// Total registration count across every plugin. Cheap — avoids
    /// allocating the [`Self::all`] vec just for length.
    #[must_use]
    pub fn count(&self) -> usize {
        self.by_plugin.values().map(Vec::len).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_reg(plugin: &str, name: &str) -> McpRegistration {
        McpRegistration {
            plugin_id: plugin.into(),
            server_name: name.into(),
            spec: McpServerSpec {
                command: Some("foo".into()),
                args: vec![],
                env: EnvironmentGrants::new(),
                transport: "stdio".into(),
                url: None,
                headers: SensitiveHeaders::new(),
                headers_helper: None,
                oauth: None,
                timeout: None,
                always_load: None,
            },
        }
    }

    #[test]
    fn replace_plugin_with_empty_removes_entries() {
        let mut r = PluginMcpRegistry::default();
        r.replace_plugin("p", vec![make_reg("p", "a"), make_reg("p", "b")]);
        assert_eq!(r.count(), 2);

        r.replace_plugin("p", vec![]);
        assert_eq!(
            r.count(),
            0,
            "empty registrations must drop the plugin entry"
        );
    }

    #[test]
    fn replace_plugin_is_per_plugin_atomic() {
        let mut r = PluginMcpRegistry::default();
        r.replace_plugin("p1", vec![make_reg("p1", "a")]);
        r.replace_plugin("p2", vec![make_reg("p2", "b")]);
        // Swap p1's contents; p2 is untouched.
        r.replace_plugin("p1", vec![make_reg("p1", "c"), make_reg("p1", "d")]);

        assert_eq!(r.for_plugin("p1").len(), 2);
        assert_eq!(r.for_plugin("p2").len(), 1);
        assert_eq!(r.count(), 3);
    }

    #[test]
    fn remove_plugin_drops_only_its_entries() {
        let mut r = PluginMcpRegistry::default();
        r.replace_plugin("p1", vec![make_reg("p1", "a")]);
        r.replace_plugin("p2", vec![make_reg("p2", "b")]);
        r.remove_plugin("p1");
        assert!(r.for_plugin("p1").is_empty());
        assert_eq!(r.for_plugin("p2").len(), 1);
    }

    #[test]
    fn spec_round_trips_from_manifest_config() {
        let cfg = McpServerConfig {
            command: Some("python".into()),
            args: vec!["-m".into(), "server".into()],
            env: EnvironmentGrants::try_from(HashMap::from([("X".to_string(), "1".to_string())]))
                .expect("valid test environment"),
            transport: "stdio".into(),
            url: None,
            headers: SensitiveHeaders::new(),
            headers_helper: None,
            oauth: None,
            timeout: None,
            always_load: None,
        };
        let spec = McpServerSpec::from_plugin_config(&cfg);
        assert_eq!(spec.command.as_deref(), Some("python"));
        assert_eq!(spec.args, vec!["-m", "server"]);
        assert!(spec.env.matches_value("X", "1"));
        assert_eq!(spec.transport, "stdio");
        assert!(spec.url.is_none());
    }
}
