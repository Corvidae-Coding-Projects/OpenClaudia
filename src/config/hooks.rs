use serde::Deserialize;
use std::collections::HashSet;

// ── Hook security policy ──────────────────────────────────────────────────────

/// Sandbox isolation level applied when spawning a hook command.
///
/// Defaults to [`SandboxMode::FullSandbox`] when a policy is present and the
/// field is omitted. Weaker modes require a separate host-startup trust
/// decision; repository configuration alone cannot opt out of isolation.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxMode {
    /// No additional isolation beyond the defaults provided by the OS.
    /// Credentials are still scrubbed (same as `EnvScrub`).
    None,
    /// Remove every credential-classified env var before spawning.
    EnvScrub,
    /// Run the hook inside the OS subprocess sandbox. Project and hook scripts
    /// remain readable, while VCS/harness control state is read-only, host
    /// files and networking are unavailable, and project output is writable.
    #[default]
    FullSandbox,
}

/// Per-`HooksConfig` security policy for command hook execution.
///
/// When `None` (the field is absent from the config), every command name is
/// permitted but command hooks still run in the full OS sandbox. This keeps
/// compatibility with existing hook command lists without trusting repository
/// code with host process access.
///
/// Example config YAML:
/// ```yaml
/// hooks:
///   policy:
///     allowed_commands: ["python", "node", "jq"]
///     sandbox: full_sandbox
/// ```
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct HookPolicy {
    /// Allowlist of executable base-names (not full paths) that hook
    /// commands may use as their first token.
    ///
    /// `None` → allow every executable (backwards-compatible legacy mode).
    /// `Some([])` → deny every command hook.
    /// `Some(["python", "node"])` → only those two binaries are permitted.
    #[serde(default)]
    pub allowed_commands: Option<HashSet<String>>,

    /// Isolation mode applied during spawn. Defaults to [`SandboxMode::FullSandbox`].
    #[serde(default)]
    pub sandbox: SandboxMode,
}

/// Hooks configuration
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct HooksConfig {
    /// Security policy applied to all command hooks in this config.
    /// Absent → allow every executable name inside the full OS sandbox.
    #[serde(default)]
    pub policy: Option<HookPolicy>,
    #[serde(default)]
    pub session_start: Vec<HookEntry>,
    #[serde(default)]
    pub session_end: Vec<HookEntry>,
    #[serde(default)]
    pub pre_tool_use: Vec<HookEntry>,
    #[serde(default)]
    pub post_tool_use: Vec<HookEntry>,
    /// Tool completed with `is_error = true`. Claude Code-compatible.
    /// When absent, `post_tool_use` handlers still run on failures too.
    #[serde(default)]
    pub post_tool_use_failure: Vec<HookEntry>,
    #[serde(default)]
    pub user_prompt_submit: Vec<HookEntry>,
    #[serde(default)]
    pub stop: Vec<HookEntry>,
    /// A subagent was spawned. Claude Code-compatible.
    #[serde(default)]
    pub subagent_start: Vec<HookEntry>,
    /// A subagent finished. Claude Code-compatible.
    #[serde(default)]
    pub subagent_stop: Vec<HookEntry>,
    /// About to run compaction. Claude Code-compatible.
    #[serde(default)]
    pub pre_compact: Vec<HookEntry>,
    /// Permission prompt is about to be shown. Claude Code-compatible.
    #[serde(default)]
    pub permission_request: Vec<HookEntry>,
    /// Generic notification surface (API errors, token limits, etc.).
    /// Claude Code-compatible.
    #[serde(default)]
    pub notification: Vec<HookEntry>,
    #[serde(default)]
    pub pre_adversary_review: Vec<HookEntry>,
    #[serde(default)]
    pub post_adversary_review: Vec<HookEntry>,
    #[serde(default)]
    pub vdd_conflict: Vec<HookEntry>,
    #[serde(default)]
    pub vdd_converged: Vec<HookEntry>,
}

impl HooksConfig {
    /// Validate the exact hook surface supported by production composition
    /// roots. This runs before an engine is constructed so malformed matchers,
    /// empty definitions, zero timeouts, and provider callbacks that no
    /// production runtime owns cannot become silently inert configuration.
    ///
    /// # Errors
    ///
    /// Returns a source-oriented validation error for the first unsupported
    /// entry in canonical event order.
    pub fn validate_runtime(&self) -> Result<(), String> {
        let events: [(&str, &[HookEntry]); 16] = [
            ("session_start", &self.session_start),
            ("user_prompt_submit", &self.user_prompt_submit),
            ("pre_tool_use", &self.pre_tool_use),
            ("permission_request", &self.permission_request),
            ("post_tool_use", &self.post_tool_use),
            ("post_tool_use_failure", &self.post_tool_use_failure),
            ("pre_compact", &self.pre_compact),
            ("subagent_start", &self.subagent_start),
            ("subagent_stop", &self.subagent_stop),
            ("pre_adversary_review", &self.pre_adversary_review),
            ("post_adversary_review", &self.post_adversary_review),
            ("vdd_conflict", &self.vdd_conflict),
            ("vdd_converged", &self.vdd_converged),
            ("notification", &self.notification),
            ("stop", &self.stop),
            ("session_end", &self.session_end),
        ];

        for (event, entries) in events {
            for (entry_index, entry) in entries.iter().enumerate() {
                if entry.hooks.is_empty() {
                    return Err(format!(
                        "hooks.{event}[{entry_index}] must contain at least one hook"
                    ));
                }
                if let Some(matcher) = entry.matcher.as_deref() {
                    crate::hooks::validate_hook_matcher(matcher, "").map_err(|error| {
                        format!("hooks.{event}[{entry_index}].matcher is invalid: {error}")
                    })?;
                }
                for (hook_index, hook) in entry.hooks.iter().enumerate() {
                    let timeout = match hook {
                        Hook::Command {
                            command, timeout, ..
                        } => {
                            if command.trim().is_empty() {
                                return Err(format!(
                                    "hooks.{event}[{entry_index}].hooks[{hook_index}].command must not be empty"
                                ));
                            }
                            *timeout
                        }
                        Hook::Prompt { prompt, timeout } => {
                            if prompt.trim().is_empty() {
                                return Err(format!(
                                    "hooks.{event}[{entry_index}].hooks[{hook_index}].prompt must not be empty"
                                ));
                            }
                            *timeout
                        }
                        Hook::Model { .. } => {
                            return Err(format!(
                                "hooks.{event}[{entry_index}].hooks[{hook_index}] uses type=model, which is unavailable until a canonical provider callback is owned by every frontend"
                            ));
                        }
                    };
                    if timeout == 0 {
                        return Err(format!(
                            "hooks.{event}[{entry_index}].hooks[{hook_index}].timeout must be at least one second"
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Which slot of [`crate::hooks::HookInput`] the [`HookEntry::matcher`] regex
/// is tested against.
///
/// Before crosslink #350 the matcher context was inferred at runtime from
/// whichever field happened to be populated on the input — so a
/// `PreToolUse` matcher like `"rm"` could accidentally match against a user
/// prompt of `"I want to rm a file"` when no `tool_name` had been set. Each
/// `HookEvent` now has a *default* target (see
/// `crate::hooks::HookMatcherTarget::default_for`), and users who need to
/// override it can set this field explicitly in YAML/JSON.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HookMatcherTarget {
    /// Match the regex against [`crate::hooks::HookInput::tool_name`].
    /// Empty when the field is absent.
    ToolName,
    /// Match the regex against [`crate::hooks::HookInput::prompt`].
    /// Empty when the field is absent.
    Prompt,
    /// Match the regex against [`crate::hooks::HookEvent::config_key`] of the
    /// firing event (e.g. `"session_start"`, `"notification"`). Used for
    /// events that carry neither a tool name nor a prompt.
    EventKey,
}

/// Individual hook entry
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HookEntry {
    #[serde(default)]
    pub matcher: Option<String>,
    pub hooks: Vec<Hook>,
}

/// Hook definition
#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Hook {
    #[serde(rename = "command")]
    Command {
        command: String,
        /// When `true` the command is passed to `sh -c` verbatim, enabling
        /// pipes and redirects. A security warning is logged on every
        /// invocation. Requires explicit opt-in; defaults to `false`.
        #[serde(default)]
        shell: bool,
        #[serde(default = "default_timeout")]
        timeout: u64,
    },
    #[serde(rename = "prompt")]
    Prompt {
        prompt: String,
        #[serde(default = "default_prompt_timeout")]
        timeout: u64,
    },
    /// Model hook: sends a prompt to a specific model/provider and returns
    /// the model's response as the hook result.
    #[serde(rename = "model")]
    Model {
        /// The prompt to send to the model
        prompt: String,
        /// The model identifier (e.g., "claude-3-5-haiku-20241022")
        model: String,
        /// Optional provider name (defaults to proxy target)
        #[serde(default)]
        provider: Option<String>,
        #[serde(default = "default_timeout")]
        timeout: u64,
    },
}

const fn default_timeout() -> u64 {
    60
}

const fn default_prompt_timeout() -> u64 {
    30
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hooks_config_default() {
        let config = HooksConfig::default();
        assert!(config.session_start.is_empty());
        assert!(config.session_end.is_empty());
        assert!(config.pre_tool_use.is_empty());
        assert!(config.post_tool_use.is_empty());
        assert!(config.user_prompt_submit.is_empty());
        assert!(config.stop.is_empty());
    }

    #[test]
    fn test_hook_entry_with_matcher() {
        let json = r#"{
            "matcher": "Write|Edit",
            "hooks": []
        }"#;

        let entry: HookEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.matcher, Some("Write|Edit".to_string()));
    }

    #[test]
    fn test_hook_matcher_target_variants_distinct() {
        // Crosslink #350: the enum is the public type used by the engine to
        // route matchers; pin its three variants so a future rename to
        // collapse them surfaces as a test failure.
        assert_ne!(HookMatcherTarget::ToolName, HookMatcherTarget::Prompt);
        assert_ne!(HookMatcherTarget::Prompt, HookMatcherTarget::EventKey);
        assert_ne!(HookMatcherTarget::ToolName, HookMatcherTarget::EventKey);
    }

    #[test]
    fn test_hook_command_type() {
        let json = r#"{
            "type": "command",
            "command": "echo test",
            "timeout": 30
        }"#;

        let hook: Hook = serde_json::from_str(json).unwrap();
        match hook {
            Hook::Command {
                command,
                shell,
                timeout,
            } => {
                assert_eq!(command, "echo test");
                assert!(!shell, "shell must default to false");
                assert_eq!(timeout, 30);
            }
            _ => panic!("Expected Command hook"),
        }
    }

    #[test]
    fn test_hook_command_shell_opt_in() {
        let json = r#"{
            "type": "command",
            "command": "echo hello | cat",
            "shell": true
        }"#;

        let hook: Hook = serde_json::from_str(json).unwrap();
        match hook {
            Hook::Command { shell, .. } => assert!(shell, "shell must be true when set"),
            _ => panic!("Expected Command hook"),
        }
    }

    #[test]
    fn test_hook_policy_default() {
        let policy = HookPolicy::default();
        assert!(policy.allowed_commands.is_none());
        assert_eq!(policy.sandbox, SandboxMode::FullSandbox);
    }

    #[test]
    fn test_hook_policy_deserialize() {
        let json = r#"{"allowed_commands": ["python3", "node"], "sandbox": "env_scrub"}"#;
        let policy: HookPolicy = serde_json::from_str(json).unwrap();
        let allowed = policy.allowed_commands.unwrap();
        assert!(allowed.contains("python3"));
        assert!(allowed.contains("node"));
        assert_eq!(policy.sandbox, SandboxMode::EnvScrub);
    }

    #[test]
    fn test_hooks_config_with_policy() {
        let json = r#"{
            "policy": {"allowed_commands": ["jq"]},
            "pre_tool_use": []
        }"#;
        let config: HooksConfig = serde_json::from_str(json).unwrap();
        let policy = config.policy.unwrap();
        let allowed = policy.allowed_commands.unwrap();
        assert!(allowed.contains("jq"));
        assert_eq!(policy.sandbox, SandboxMode::FullSandbox);
    }

    #[test]
    fn test_hook_prompt_type() {
        let json = r#"{
            "type": "prompt",
            "prompt": "Always be helpful",
            "timeout": 10
        }"#;

        let hook: Hook = serde_json::from_str(json).unwrap();
        match hook {
            Hook::Prompt { prompt, timeout } => {
                assert_eq!(prompt, "Always be helpful");
                assert_eq!(timeout, 10);
            }
            _ => panic!("Expected Prompt hook"),
        }
    }

    #[test]
    fn test_hook_default_timeouts() {
        // Command hook default timeout
        let cmd_json = r#"{"type": "command", "command": "test"}"#;
        let cmd_hook: Hook = serde_json::from_str(cmd_json).unwrap();
        match cmd_hook {
            Hook::Command { timeout, .. } => assert_eq!(timeout, 60), // default
            _ => panic!("Expected Command"),
        }

        // Prompt hook default timeout
        let prompt_json = r#"{"type": "prompt", "prompt": "test"}"#;
        let prompt_hook: Hook = serde_json::from_str(prompt_json).unwrap();
        match prompt_hook {
            Hook::Prompt { timeout, .. } => assert_eq!(timeout, 30), // default
            _ => panic!("Expected Prompt"),
        }
    }

    #[test]
    fn test_hook_model_type() {
        let json = r#"{
            "type": "model",
            "prompt": "Review this code",
            "model": "claude-3-5-haiku-20241022",
            "provider": "anthropic",
            "timeout": 45
        }"#;

        let hook: Hook = serde_json::from_str(json).unwrap();
        match hook {
            Hook::Model {
                prompt,
                model,
                provider,
                timeout,
            } => {
                assert_eq!(prompt, "Review this code");
                assert_eq!(model, "claude-3-5-haiku-20241022");
                assert_eq!(provider, Some("anthropic".to_string()));
                assert_eq!(timeout, 45);
            }
            _ => panic!("Expected Model hook"),
        }
    }

    #[test]
    fn test_hook_model_type_defaults() {
        let json = r#"{
            "type": "model",
            "prompt": "Validate",
            "model": "gpt-4o-mini"
        }"#;

        let hook: Hook = serde_json::from_str(json).unwrap();
        match hook {
            Hook::Model {
                provider, timeout, ..
            } => {
                assert!(provider.is_none());
                assert_eq!(timeout, 60); // default_timeout
            }
            _ => panic!("Expected Model hook"),
        }
    }
}
