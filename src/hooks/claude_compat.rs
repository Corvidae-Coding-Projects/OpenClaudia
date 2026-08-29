//! Claude Code Compatibility Layer
//!
//! Types and functions for loading hooks from Claude Code's `.claude/settings.json`
//! format and converting them to `OpenClaudia`'s internal representation.

use crate::config::HooksConfig;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use super::compat_import::load_approved_repository_hooks;
use super::merge::{enforce_total_size, merge_claude_hooks, merge_host_hooks, merge_settings_file};

/// Claude Code settings.json structure
#[derive(Debug, Deserialize, Default)]
pub struct ClaudeCodeSettings {
    #[serde(default)]
    pub hooks: HashMap<String, Vec<ClaudeCodeHookEntry>>,
}

/// Claude Code hook entry format
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeCodeHookEntry {
    #[serde(default)]
    pub matcher: Option<String>,
    #[serde(default)]
    pub hooks: Vec<ClaudeCodeHook>,
}

/// Claude Code hook definition
#[derive(Debug, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum ClaudeCodeHook {
    #[serde(rename = "command")]
    Command {
        command: String,
        #[serde(default = "default_claude_timeout")]
        timeout: Option<u64>,
    },
}

#[allow(clippy::unnecessary_wraps)]
const fn default_claude_timeout() -> Option<u64> {
    Some(60)
}

/// Load hooks from Claude Code-compatible settings sources.
///
/// This is the runtime-facing helper used by the CLI, ACP, and proxy paths.
/// User-global, repository, and project-local Claude settings are inert
/// compatibility proposals until an exact host approval is recorded by the
/// explicit import workflow. Managed enterprise settings remain a host-owned
/// ceiling.
#[must_use]
pub fn load_claude_code_hooks() -> HooksConfig {
    let (config, _) = load_claude_code_hooks_layered();
    config
}

// ============================================================================
// Settings File Layering
// ============================================================================

/// Result of loading layered Claude settings
pub struct LayeredSettings {
    /// The merged settings value
    pub settings: Value,
    /// Allowed tools extracted from merged settings
    pub allowed_tools: Vec<String>,
    /// Path to managed (enterprise) settings if loaded
    pub managed_settings_path: Option<PathBuf>,
}

/// Load host-owned Claude settings, merging them in authority order.
///
/// Load order (later overrides earlier):
/// 1. `~/.claude/settings.json` (user global)
/// 2. System-level managed settings (enterprise)
///
/// Repository settings are deliberately absent from this function. They are
/// discovered only through the explicit proposal/approval path in
/// `compat_import`.
pub fn load_claude_settings() -> LayeredSettings {
    let mut settings = Value::Object(serde_json::Map::default());

    // 1. User global settings
    if let Some(home) = dirs::home_dir() {
        let user_settings = home.join(".claude/settings.json");
        if user_settings.exists() {
            merge_settings_file(&mut settings, &user_settings);
            debug!(path = ?user_settings, "Loaded user-global Claude settings");
        }
    }

    // 2. System-level managed settings (enterprise). Only Linux and macOS
    // have well-known managed locations; on other platforms this is None.
    let managed_path: Option<PathBuf> = {
        #[cfg(target_os = "linux")]
        {
            let p = Path::new("/etc/openclaudia/managed-settings.json");
            p.exists().then(|| p.to_path_buf())
        }
        #[cfg(target_os = "macos")]
        {
            let p = Path::new("/Library/Application Support/openclaudia/managed-settings.json");
            p.exists().then(|| p.to_path_buf())
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            None
        }
    };

    if let Some(path) = &managed_path {
        warn!(
            path = ?path,
            "Loading enterprise managed settings - these override all user and project settings"
        );
        merge_settings_file(&mut settings, path);
    }

    // Post-merge size guard for the host-owned settings tree. Fall back to an
    // empty object rather than handing the harness an oversized blob to walk.
    if let Err(e) = enforce_total_size(&settings) {
        tracing::error!(
            error = %e,
            "Merged Claude settings exceed size cap; falling back to empty settings"
        );
        settings = Value::Object(serde_json::Map::default());
    }

    // Extract allowedTools from merged settings
    let allowed_tools: Vec<String> = settings
        .get("allowedTools")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    if !allowed_tools.is_empty() {
        info!(
            count = allowed_tools.len(),
            "Extracted allowedTools from settings"
        );
    }

    LayeredSettings {
        settings,
        allowed_tools,
        managed_settings_path: managed_path,
    }
}

/// Load compatible hooks while enforcing the explicit import trust boundary.
///
/// The returned [`LayeredSettings`] remains a diagnostic view of host-owned
/// settings sources. It is never the source of executable hooks. Runtime hooks
/// are built from exact approved user/repository compatibility proposals and
/// finally managed host settings, in increasing authority order.
#[must_use]
pub fn load_claude_code_hooks_layered() -> (HooksConfig, LayeredSettings) {
    let layered = load_claude_settings();
    let mut config = load_approved_repository_hooks();
    if let Some(managed_path) = layered.managed_settings_path.as_deref() {
        config = merge_host_hooks(config, load_hooks_from_trusted_settings(managed_path));
    }

    (config, layered)
}

fn load_hooks_from_trusted_settings(path: &Path) -> HooksConfig {
    if !path.exists() {
        return HooksConfig::default();
    }
    let mut value = Value::Object(serde_json::Map::default());
    merge_settings_file(&mut value, path);
    let Some(hooks) = value.get("hooks") else {
        return HooksConfig::default();
    };
    let settings = match serde_json::from_value::<ClaudeCodeSettings>(json!({ "hooks": hooks })) {
        Ok(settings) => settings,
        Err(error) => {
            warn!(path = ?path, error = %error, "Failed to parse trusted Claude hook settings");
            return HooksConfig::default();
        }
    };
    let mut config = HooksConfig::default();
    merge_claude_hooks(&mut config, &settings);
    info!(path = ?path, "Loaded host-owned Claude-compatible hooks");
    config
}
