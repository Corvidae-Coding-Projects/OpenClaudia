use std::collections::HashMap;

use serde::Deserialize;

/// Tool permission system configuration.
///
/// Controls whether permission checks are performed before tool execution
/// and provides default allow-list patterns.
///
/// # Default posture
///
/// `enabled` defaults to `true` (deny-by-default, matching Claude Code's
/// always-on permission pipeline). A fresh installation with no
/// `permissions:` block in `config.yaml` will **prompt before every
/// destructive tool call**.
///
/// To opt out of the permission system entirely, set `enabled: false` in
/// your config. This is **not recommended** for production use; it is
/// equivalent to Claude Code's `bypassPermissions` mode and removes all
/// audit trails.
///
/// # Deprecation note
///
/// The `enabled` field is scheduled for removal. The long-term plan is to
/// make permissions always-on and replace opt-out with an explicit
/// `dangerously_disable_permissions: true`. See crosslink #282.
#[derive(Debug, Deserialize, Clone)]
pub struct PermissionsConfig {
    /// Enable the permission system.
    ///
    /// Defaults to `true` (deny-by-default). Set to `false` only to
    /// replicate the old allow-all behaviour; note that doing so also
    /// silences all persisted Deny rules.
    ///
    /// **Deprecated**: prefer leaving this unset (the default `true`)
    /// and use `dangerously_disable_permissions` when an explicit bypass
    /// is required. See crosslink #282.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Tool-scoped glob patterns that are pre-allowed without prompting.
    /// Use `Tool(pattern)` (for example `Bash(git status *)` or
    /// `Write(src/**)`). Legacy unqualified entries remain Bash-only so a
    /// command pattern can never authorize a file or network target.
    #[serde(default)]
    pub default_allow: Vec<String>,
    /// Per-server MCP tool allow-list (crosslink #619).
    ///
    /// Maps **server name** (the key under `mcp.servers` in
    /// `config.yaml`) to the list of tool names exposed by that
    /// server that the leader is allowed to invoke. A server absent
    /// from the map is **not restricted** — every tool it exposes is
    /// admissible; that matches the historical posture before #619
    /// where MCP tools went through the generic permission pipeline
    /// only. To restrict a server to a specific subset, list it here
    /// with the explicit tools.
    ///
    /// An entry with an **empty** tool vector denies every tool on
    /// that server — use this when you want to block a server entirely
    /// without unloading it from the manager.
    ///
    /// Wildcards are not interpreted here: each tool name is compared
    /// verbatim (case-sensitive). This avoids the unbounded-glob
    /// foot-gun from `default_allow` and keeps the matrix grep-able.
    #[serde(default)]
    pub mcp: HashMap<String, Vec<String>>,
}

/// Returns the default value for `PermissionsConfig::enabled`.
///
/// `true` — permissions are on by default (deny-by-default posture).
/// Fixes crosslink #282: the previous `#[serde(default)]` on a `bool`
/// field silently defaulted to `false`, making a fresh install allow-all.
const fn default_enabled() -> bool {
    true
}

impl Default for PermissionsConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            default_allow: Vec::new(),
            mcp: HashMap::new(),
        }
    }
}

impl PermissionsConfig {
    /// Validate `default_allow` entries at config-load time
    /// (crosslink #938). Rejects:
    ///
    /// * **Empty** patterns — a zero-byte glob silently matches every
    ///   empty target argument and is almost always a YAML quoting bug.
    /// * **Bare `*` / `**`** — unbounded patterns disable the permission
    ///   system while *looking* enabled. Reject unless the operator
    ///   explicitly opted in via a `bypass-permissions` mode.
    /// * **NUL bytes / control chars** — these never appear in a real
    ///   tool argument and almost always come from a misencoded YAML.
    ///
    /// Also emits a WARN log when `default_allow` is non-empty but
    /// `enabled = false` — the entries would be ignored and the
    /// operator probably meant to enable the system.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` with a human-readable diagnostic when any
    /// pattern fails validation. The caller (`config::load_config`)
    /// surfaces this as `ConfigError::Message`.
    pub fn validate(&self) -> Result<(), String> {
        for (idx, configured) in self.default_allow.iter().enumerate() {
            let (scope, pat) = split_scoped_default_allow(configured);
            if pat.is_empty() {
                return Err(format!(
                    "permissions.default_allow[{idx}]: empty pattern is invalid \
                     (use a real glob or remove the entry)"
                ));
            }
            if pat == "*" || pat == "**" {
                return Err(format!(
                    "permissions.default_allow[{idx}] = '{configured}': unbounded pattern \
                     '{pat}' would pre-allow every target in {}. Use a narrower glob \
                     (for example 'Bash(git *)' or 'Write(src/**)').",
                    scope.map_or("the legacy Bash scope", |_| "the named tool scope")
                ));
            }
            if configured
                .chars()
                .any(|c| c == '\0' || (c.is_control() && c != '\t'))
            {
                return Err(format!(
                    "permissions.default_allow[{idx}] = '{pat}': pattern contains \
                     NUL / control characters that no real tool argument carries"
                ));
            }
        }
        if !self.default_allow.is_empty() && !self.enabled {
            tracing::warn!(
                count = self.default_allow.len(),
                "permissions.default_allow has entries but permissions.enabled=false; \
                 entries will be ignored. Set enabled=true to honour them."
            );
        }
        Ok(())
    }

    /// Check whether `tool` on `server` is admissible under the
    /// per-server MCP permissions map (crosslink #619).
    ///
    /// Semantics:
    ///
    /// * Server **absent from the map** → `true` (unrestricted; the
    ///   generic permission pipeline still applies).
    /// * Server present with **empty** tool list → `false` for every
    ///   tool (server is blocked).
    /// * Server present with a non-empty tool list → `true` iff
    ///   `tool` is an exact case-sensitive match.
    ///
    /// This is **only** the per-server gate; the generic permission
    /// system (`PermissionManager`) still gets the final say. Callers
    /// should consult `mcp_tool_allowed` first and short-circuit when
    /// it returns `false`.
    #[must_use]
    pub fn mcp_tool_allowed(&self, server: &str, tool: &str) -> bool {
        self.mcp
            .get(server)
            .is_none_or(|allowed| allowed.iter().any(|t| t == tool))
    }
}

/// Split the explicit `Tool(pattern)` form used by `default_allow`.
/// Parenthesized shell commands remain legacy Bash patterns unless the prefix
/// is a plausible tool identifier, avoiding accidental reinterpretation.
fn split_scoped_default_allow(configured: &str) -> (Option<&str>, &str) {
    let Some(open) = configured.find('(') else {
        return (None, configured);
    };
    if !configured.ends_with(')') || open == 0 {
        return (None, configured);
    }
    let tool = configured[..open].trim();
    if tool.is_empty()
        || !tool
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return (None, configured);
    }
    (
        Some(tool),
        configured[open + 1..configured.len() - 1].trim(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_scoped_globs() {
        let cfg = PermissionsConfig {
            enabled: true,
            default_allow: vec![
                "Write(/project/**)".into(),
                "Bash(git *)".into(),
                "Bash(*.rs)".into(),
            ],
            mcp: HashMap::new(),
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_pattern() {
        let cfg = PermissionsConfig {
            enabled: true,
            default_allow: vec!["ok".into(), String::new()],
            mcp: HashMap::new(),
        };
        let err = cfg.validate().expect_err("empty pattern must be rejected");
        assert!(err.contains("[1]"), "error must name the index: {err}");
        assert!(
            err.contains("empty pattern"),
            "error must mention emptiness: {err}"
        );
    }

    #[test]
    fn validate_rejects_unbounded_glob() {
        for unbounded in ["*", "**", "Bash(*)", "Write(**)"] {
            let cfg = PermissionsConfig {
                enabled: true,
                default_allow: vec![unbounded.into()],
                mcp: HashMap::new(),
            };
            let err = cfg.validate().expect_err("unbounded glob must be rejected");
            assert!(
                err.contains("unbounded"),
                "error must mention 'unbounded': {err}"
            );
        }
    }

    #[test]
    fn validate_rejects_control_characters() {
        let cfg = PermissionsConfig {
            enabled: true,
            default_allow: vec!["foo\u{1}bar".into()],
            mcp: HashMap::new(),
        };
        let err = cfg.validate().expect_err("control chars must be rejected");
        assert!(
            err.contains("control"),
            "error must mention 'control': {err}"
        );
    }

    #[test]
    fn validate_default_is_ok() {
        // Default is empty default_allow, so nothing to validate.
        assert!(PermissionsConfig::default().validate().is_ok());
    }

    // ── Crosslink #619: per-server MCP permissions ──────────────────────

    #[test]
    fn mcp_unrestricted_when_server_absent() {
        let cfg = PermissionsConfig::default();
        // No `mcp` entries → every server/tool is unrestricted at
        // this layer.
        assert!(cfg.mcp_tool_allowed("github", "create_issue"));
        assert!(cfg.mcp_tool_allowed("anything", "anything"));
    }

    #[test]
    fn mcp_allowlist_admits_exact_match_only() {
        let mut mcp = HashMap::new();
        mcp.insert(
            "github".into(),
            vec!["read_file".into(), "list_repos".into()],
        );
        let cfg = PermissionsConfig {
            enabled: true,
            default_allow: Vec::new(),
            mcp,
        };
        assert!(cfg.mcp_tool_allowed("github", "read_file"));
        assert!(cfg.mcp_tool_allowed("github", "list_repos"));
        assert!(!cfg.mcp_tool_allowed("github", "delete_file"));
        // Case-sensitive: capitalisation differences must not match.
        assert!(!cfg.mcp_tool_allowed("github", "Read_File"));
        // Unmentioned server is still wide-open.
        assert!(cfg.mcp_tool_allowed("railway", "deploy"));
    }

    #[test]
    fn mcp_empty_allowlist_denies_every_tool_on_server() {
        let mut mcp = HashMap::new();
        mcp.insert("blocked".into(), Vec::new());
        let cfg = PermissionsConfig {
            enabled: true,
            default_allow: Vec::new(),
            mcp,
        };
        assert!(!cfg.mcp_tool_allowed("blocked", "anything"));
        assert!(!cfg.mcp_tool_allowed("blocked", ""));
    }

    #[test]
    fn mcp_deserializes_from_yaml() {
        let yaml = r"
mcp:
  github:
    - read_file
    - list_repos
  blocked: []
";
        let cfg: PermissionsConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.mcp_tool_allowed("github", "read_file"));
        assert!(!cfg.mcp_tool_allowed("github", "delete_file"));
        assert!(!cfg.mcp_tool_allowed("blocked", "anything"));
        assert!(cfg.mcp_tool_allowed("absent", "anything"));
    }
}
