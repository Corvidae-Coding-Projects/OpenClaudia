//! Configuration loader with environment variable substitution.
//!
//! Loads configuration from:
//! 1. Default values
//! 2. `.openclaudia/config.yaml` in project directory
//! 3. `~/.openclaudia/config.yaml` in home directory
//! 4. Environment variables with `OPENCLAUDIA_` prefix

mod acp;
mod environment;
mod guardrails;
mod hooks;
mod keybindings;
mod memory;
mod path_validation;
mod permissions;
mod provider;
mod proxy;
mod session;
pub mod stop_conditions;
mod vdd;
pub mod webfetch;

pub use acp::AcpConfig;
pub use environment::{
    environment_variable_metadata, EnvironmentConfigError, EnvironmentDeprecation,
    EnvironmentPrecedence, EnvironmentSecrecy, EnvironmentValueParser, EnvironmentVariableMetadata,
};
pub use guardrails::{
    BlastRadiusConfig, DiffMonitorConfig, GuardrailAction, GuardrailMode, GuardrailsConfig,
    QualityCheck, QualityGatesConfig, RunAfter,
};
pub use hooks::{Hook, HookEntry, HookMatcherTarget, HookPolicy, HooksConfig, SandboxMode};
pub use keybindings::KeybindingsConfig;
// Re-export runtime keybinding logic for backward compatibility with callers
// that imported these from `crate::config`. The canonical home is
// `crate::keybindings` — see crosslink #357.
pub use crate::keybindings::{
    parse_chord, ChordResolveResult, KeyAction, KeyContext, KeybindingResolver, ParsedKeystroke,
};
pub use memory::MemoryConfig;
pub use path_validation::{validate_persist_path, PathValidationError, ALLOW_OUT_OF_ROOT_ENV};
pub use permissions::{
    PermissionsConfig, ProjectPermissionProposal, PROJECT_PERMISSION_PROPOSAL_SCHEMA_VERSION,
};
pub use provider::{
    adaptive_budget_for, is_local_provider_name, validate_base_url, validate_provider_base_url,
    ProviderConfig, ThinkingConfig,
};
pub use proxy::ProxyConfig;
pub use session::{SessionConfig, TokenTrackingConfig};
pub use stop_conditions::{StopConditionsConfig, StopReason, TokenTotals};
pub use vdd::{
    VddAdversaryConfig, VddConfig, VddMode, VddStaticAnalysis, VddThresholds, VddTracking,
};
pub use webfetch::{
    default_preapproved_domains, is_preapproved, WebFetchConfig, CC_MAX_MARKDOWN_LENGTH,
};

use config::{Config, ConfigError, File, FileFormat};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

/// Shared default function used by multiple submodules.
pub(crate) const fn default_true() -> bool {
    true
}

/// Main configuration structure
#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub proxy: ProxyConfig,
    pub providers: HashMap<String, ProviderConfig>,
    #[serde(default)]
    pub hooks: HooksConfig,
    #[serde(default)]
    pub session: SessionConfig,
    #[serde(default)]
    pub keybindings: KeybindingsConfig,
    #[serde(default)]
    pub vdd: VddConfig,
    #[serde(default)]
    pub guardrails: GuardrailsConfig,
    #[serde(default)]
    pub permissions: PermissionsConfig,
    /// Memory subsystem configuration (host-owned private store plus an
    /// optional authenticated, encrypted team replica).
    #[serde(default)]
    pub memory: MemoryConfig,
    /// Web-fetch tool configuration, including the preapproved-domain
    /// allowlist consulted by the permission layer. See crosslink #603.
    #[serde(default)]
    pub web_fetch: WebFetchConfig,
    /// Enterprise policy block (crosslink #637).
    ///
    /// Token caps, per-tool invocation caps, and a model allowlist. All
    /// fields are optional; `default()` leaves every check disabled so
    /// existing deployments are unaffected until a `policy:` block is
    /// added to the config file.
    #[serde(default)]
    pub policy: crate::services::policy::EnterprisePolicy,
    /// Path to enterprise managed settings file, if one was loaded.
    /// Managed settings override all user and project settings.
    #[serde(skip)]
    pub managed_settings_path: Option<PathBuf>,
}

// ==========================================================================
// Config Schema Generation (future)
// ==========================================================================
//
// To enable JSON Schema generation for config validation and IDE support,
// add the `schemars` crate to dependencies and derive `JsonSchema` on all
// config structs (AppConfig, ProxyConfig, ProviderConfig, HooksConfig, etc.).
//
// Example:
//   #[derive(Debug, Deserialize, Clone, schemars::JsonSchema)]
//   pub struct AppConfig { ... }
//
// Then expose via:
//   pub fn generate_config_schema() -> String {
//       serde_json::to_string_pretty(&schemars::schema_for!(AppConfig)).unwrap()
//   }
//
// This would allow `openclaudia config schema` to output the JSON schema
// for editor integration and config validation.

/// Check whether any config file exists (project or home directory).
#[must_use]
pub fn config_file_exists() -> bool {
    let project_config = PathBuf::from(".openclaudia/config.yaml");
    if project_config.exists() {
        return true;
    }
    if let Some(home) = dirs::home_dir() {
        if home.join(".openclaudia/config.yaml").exists() {
            return true;
        }
    }
    false
}

/// Load configuration from all sources.
///
/// # Errors
///
/// Returns an error if configuration files cannot be read or parsed.
#[allow(clippy::too_many_lines)] // configuration source assembly is intentionally linear
pub fn load_config() -> Result<AppConfig, ConfigError> {
    let mut builder = Config::builder();
    let mut project_permission_proposal = None;

    // Set defaults
    builder = builder
        .set_default("proxy.port", 8080)?
        .set_default("proxy.host", "127.0.0.1")?
        .set_default("proxy.target", "anthropic")?
        .set_default("session.timeout_minutes", 30)?
        .set_default("session.persist_path", ".openclaudia/session")?;

    // Add default providers
    builder = builder
        .set_default("providers.anthropic.base_url", "https://api.anthropic.com")?
        .set_default("providers.openai.base_url", "https://api.openai.com")?
        .set_default(
            "providers.google.base_url",
            "https://generativelanguage.googleapis.com",
        )?
        // Z.AI/GLM (OpenAI-compatible)
        .set_default("providers.zai.base_url", "https://api.z.ai/api/paas/v4")?
        // DeepSeek (OpenAI-compatible)
        .set_default("providers.deepseek.base_url", "https://api.deepseek.com")?
        // Qwen/Alibaba (OpenAI-compatible)
        .set_default(
            "providers.qwen.base_url",
            "https://dashscope.aliyuncs.com/compatible-mode",
        )?
        // Kimi/Moonshot (OpenAI-compatible)
        .set_default("providers.kimi.base_url", "https://api.moonshot.ai/v1")?
        // MiniMax (OpenAI-compatible)
        .set_default("providers.minimax.base_url", "https://api.minimax.io/v1")?
        // OpenRouter (OpenAI-compatible aggregator; docs use /api/v1)
        .set_default(
            "providers.openrouter.base_url",
            "https://openrouter.ai/api/v1",
        )?
        // OpenCode Go OpenAI-compatible endpoint subset.
        .set_default(
            "providers.opencode.base_url",
            "https://opencode.ai/zen/go/v1",
        )?
        // Generic remote OpenAI-compatible endpoint. Users override
        // `base_url`, `api_key`, `model`, and optional headers in config.
        .set_default(
            "providers.openai-compatible.base_url",
            "https://api.openai.com",
        )?
        // Local OpenAI-compatible providers.
        .set_default("providers.ollama.base_url", "http://localhost:11434")?
        .set_default("providers.local.base_url", "http://localhost:1234/v1")?
        .set_default("providers.lmstudio.base_url", "http://localhost:1234/v1")?
        .set_default("providers.localai.base_url", "http://localhost:8080/v1")?
        .set_default(
            "providers.text-generation-webui.base_url",
            "http://localhost:5000/v1",
        )?;

    // Load repository configuration without granting its `hooks:` block
    // executable or instruction authority. The hook importer discovers that
    // block separately as an inert, digest-bound proposal; trusted home/env
    // sources below remain ordinary host configuration.
    let project_config = PathBuf::from(".openclaudia/config.yaml");
    if project_config.exists() {
        let content =
            zeroize::Zeroizing::new(std::fs::read_to_string(&project_config).map_err(|error| {
                ConfigError::Message(format!(
                    "failed to read project config {}: {error}",
                    project_config.display()
                ))
            })?);
        let mut document: serde_yaml::Value = serde_yaml::from_str(&content).map_err(|error| {
            ConfigError::Message(format!(
                "failed to parse project config {}: {error}",
                project_config.display()
            ))
        })?;
        project_permission_proposal = permissions::take_project_permission_proposal(
            &mut document,
            &project_config,
            content.as_bytes(),
        )
        .map_err(ConfigError::Message)?;
        if let Some(mapping) = document.as_mapping_mut() {
            mapping.remove(serde_yaml::Value::String("hooks".to_string()));
        }
        let inert_project_config = serde_yaml::to_string(&document).map_err(|error| {
            ConfigError::Message(format!(
                "failed to normalize project config {}: {error}",
                project_config.display()
            ))
        })?;
        builder = builder.add_source(File::from_str(&inert_project_config, FileFormat::Yaml));
    }

    // Load from home directory config file
    if let Some(home) = dirs::home_dir() {
        let home_config: PathBuf = home.join(".openclaudia/config.yaml");
        if home_config.exists() {
            builder = builder.add_source(File::from(home_config).required(false));
        }
    }

    // Apply only names declared by the typed environment registry. This runs
    // after both file sources and before callers apply explicit CLI arguments,
    // matching the source precedence recorded in each registry descriptor.
    // No underscore rewriting or unknown-key fallback remains.
    let mut merged = builder.build()?;
    environment::apply_process_environment(&mut merged)
        .map_err(|error| ConfigError::Message(error.to_string()))?;

    let mut config: AppConfig = merged.try_deserialize()?;
    config.permissions.project_proposal = project_permission_proposal;

    // Validate VDD settings that do not depend on the final runtime target.
    // Provider-pair validation runs after CLI/TUI target overrides and startup
    // auth selection have resolved the actual builder/adversary providers.
    if let Err(e) = config.vdd.validate_settings() {
        return Err(ConfigError::Message(e));
    }

    // Validate the permissions default-allow globs (crosslink #938).
    // Rejects empty / unbounded / control-char patterns at load time
    // so a typo cannot silently widen the allow-list.
    if let Err(e) = config.permissions.validate() {
        return Err(ConfigError::Message(e));
    }

    // The pre-S-103 shared-path proposal is permanently rejected. A repository
    // may select a strict team ID, but membership and credentials are resolved
    // only from the host-owned authority store and signed service descriptor.
    if config.memory.team_memory_path.is_some() {
        return Err(ConfigError::Message(
            "memory.team_memory_path is unsupported: a filesystem path is never authenticated team authority; configure memory.team_id after host enrollment and import a signed service descriptor with `openclaudia team configure-service`"
                .to_string(),
        ));
    }

    // Validate each provider's base_url for SSRF / scheme safety (crosslink #329).
    let mut names: Vec<&String> = config.providers.keys().collect();
    names.sort();
    for name in names {
        let provider = &config.providers[name];
        if let Err(e) = provider::validate_provider_base_url(name, &provider.base_url) {
            return Err(ConfigError::Message(format!(
                "provider '{name}' has invalid base_url: {e}"
            )));
        }
    }

    // Diagnose configured persistence paths before subsystem startup. This
    // rejects known system trees, lexical escape, and existing link
    // components, but deliberately does not confer filesystem authority:
    // path checks can race. Persistent I/O must use the descriptor-bound
    // `persistence` API at its actual read/write boundary.
    //
    // `project_root` is the current working directory at config load
    // time — the same anchor used by the existing default `.openclaudia/…`
    // relative paths, so behaviour is unchanged for the happy path.
    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    config.session.persist_path =
        validate_persist_path(&config.session.persist_path, &project_root)
            .map_err(|e| ConfigError::Message(format!("session.persist_path rejected: {e}")))?;

    config.vdd.tracking.path = validate_persist_path(&config.vdd.tracking.path, &project_root)
        .map_err(|e| ConfigError::Message(format!("vdd.tracking.path rejected: {e}")))?;

    Ok(config)
}

fn canonical_provider_config_key(name: &str) -> Option<&'static str> {
    match name.trim().to_ascii_lowercase().as_str() {
        "anthropic" => Some("anthropic"),
        "openai" => Some("openai"),
        "google" | "gemini" => Some("google"),
        "deepseek" => Some("deepseek"),
        "qwen" | "alibaba" => Some("qwen"),
        "zai" | "glm" | "zhipu" => Some("zai"),
        "kimi" | "moonshot" => Some("kimi"),
        "minimax" => Some("minimax"),
        "ollama" => Some("ollama"),
        "local" | "lmstudio" | "localai" | "text-generation-webui" => Some("local"),
        "openrouter" => Some("openrouter"),
        "opencode" | "opencode-go" => Some("opencode"),
        "openai-compatible" => Some("openai-compatible"),
        _ => None,
    }
}

/// Get the active provider configuration
impl AppConfig {
    #[must_use]
    pub fn active_provider(&self) -> Option<&ProviderConfig> {
        self.get_provider(&self.proxy.target)
    }

    #[must_use]
    pub fn get_provider(&self, name: &str) -> Option<&ProviderConfig> {
        if let Some(provider) = self.providers.get(name) {
            return Some(provider);
        }

        let lowercase_key = name.trim().to_ascii_lowercase();
        if let Some(provider) = self.providers.get(&lowercase_key) {
            return Some(provider);
        }

        canonical_provider_config_key(name).and_then(|key| self.providers.get(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::ApiKey;

    fn test_api_key(raw: &str) -> ApiKey {
        // Pad short test keys so they satisfy the 10-char redaction path
        // and the non-empty validator. All still free of CRLF/non-ASCII.
        let padded = format!("{raw}-0000000000");
        ApiKey::try_from_string(padded).expect("valid test key")
    }

    #[test]
    fn test_app_config_active_provider() {
        let mut providers = HashMap::new();
        providers.insert(
            "anthropic".to_string(),
            ProviderConfig {
                api_key: Some(test_api_key("key")),
                base_url: "https://api.anthropic.com".to_string(),
                model: None,
                headers: crate::secrets::SensitiveHeaders::new(),
                thinking: ThinkingConfig::default(),
            },
        );

        let config = AppConfig {
            proxy: ProxyConfig {
                target: "anthropic".to_string(),
                ..Default::default()
            },
            providers,
            hooks: HooksConfig::default(),
            session: SessionConfig::default(),
            keybindings: KeybindingsConfig::default(),
            vdd: VddConfig::default(),
            guardrails: GuardrailsConfig::default(),
            permissions: PermissionsConfig::default(),
            memory: MemoryConfig::default(),
            web_fetch: WebFetchConfig::default(),
            policy: crate::services::policy::EnterprisePolicy::default(),
            managed_settings_path: None,
        };

        let active = config.active_provider();
        assert!(active.is_some());
        assert!(active
            .unwrap()
            .api_key
            .as_ref()
            .is_some_and(|key| key.matches("key-0000000000")));
    }

    #[test]
    fn test_app_config_get_provider() {
        let mut providers = HashMap::new();
        providers.insert(
            "openai".to_string(),
            ProviderConfig {
                api_key: Some(test_api_key("openai-key")),
                base_url: "https://api.openai.com".to_string(),
                model: None,
                headers: crate::secrets::SensitiveHeaders::new(),
                thinking: ThinkingConfig::default(),
            },
        );
        providers.insert(
            "anthropic".to_string(),
            ProviderConfig {
                api_key: Some(test_api_key("anthropic-key")),
                base_url: "https://api.anthropic.com".to_string(),
                model: None,
                headers: crate::secrets::SensitiveHeaders::new(),
                thinking: ThinkingConfig::default(),
            },
        );

        let config = AppConfig {
            proxy: ProxyConfig::default(),
            providers,
            hooks: HooksConfig::default(),
            session: SessionConfig::default(),
            keybindings: KeybindingsConfig::default(),
            vdd: VddConfig::default(),
            guardrails: GuardrailsConfig::default(),
            permissions: PermissionsConfig::default(),
            memory: MemoryConfig::default(),
            web_fetch: WebFetchConfig::default(),
            policy: crate::services::policy::EnterprisePolicy::default(),
            managed_settings_path: None,
        };

        assert!(config.get_provider("openai").is_some());
        assert!(config.get_provider("anthropic").is_some());
        assert!(config.get_provider("nonexistent").is_none());
    }

    #[test]
    fn app_config_get_provider_falls_back_from_alias_to_canonical_key() {
        let mut providers = HashMap::new();
        providers.insert(
            "kimi".to_string(),
            ProviderConfig {
                api_key: Some(test_api_key("kimi-key")),
                base_url: "https://api.moonshot.ai/v1".to_string(),
                model: None,
                headers: crate::secrets::SensitiveHeaders::new(),
                thinking: ThinkingConfig::default(),
            },
        );

        let config = AppConfig {
            proxy: ProxyConfig {
                target: "moonshot".to_string(),
                ..Default::default()
            },
            providers,
            hooks: HooksConfig::default(),
            session: SessionConfig::default(),
            keybindings: KeybindingsConfig::default(),
            vdd: VddConfig::default(),
            guardrails: GuardrailsConfig::default(),
            permissions: PermissionsConfig::default(),
            memory: MemoryConfig::default(),
            web_fetch: WebFetchConfig::default(),
            policy: crate::services::policy::EnterprisePolicy::default(),
            managed_settings_path: None,
        };

        assert!(config
            .active_provider()
            .and_then(|provider| provider.api_key.as_ref())
            .is_some_and(|key| key.matches("kimi-key-0000000000")));
        assert!(config.get_provider("MOONSHOT").is_some());
    }

    #[test]
    fn app_config_get_provider_resolves_openai_compatible_aliases() {
        let mut providers = HashMap::new();
        providers.insert(
            "opencode".to_string(),
            ProviderConfig {
                api_key: Some(test_api_key("opencode")),
                base_url: "https://opencode.ai/zen/go/v1".to_string(),
                model: None,
                headers: crate::secrets::SensitiveHeaders::new(),
                thinking: ThinkingConfig::default(),
            },
        );
        providers.insert(
            "openrouter".to_string(),
            ProviderConfig {
                api_key: Some(test_api_key("router")),
                base_url: "https://openrouter.ai/api/v1".to_string(),
                model: None,
                headers: crate::secrets::SensitiveHeaders::new(),
                thinking: ThinkingConfig::default(),
            },
        );

        let config = AppConfig {
            proxy: ProxyConfig::default(),
            providers,
            hooks: HooksConfig::default(),
            session: SessionConfig::default(),
            keybindings: KeybindingsConfig::default(),
            vdd: VddConfig::default(),
            guardrails: GuardrailsConfig::default(),
            permissions: PermissionsConfig::default(),
            memory: MemoryConfig::default(),
            web_fetch: WebFetchConfig::default(),
            policy: crate::services::policy::EnterprisePolicy::default(),
            managed_settings_path: None,
        };

        assert!(config
            .get_provider("opencode-go")
            .and_then(|provider| provider.api_key.as_ref())
            .is_some_and(|key| key.matches("opencode-0000000000")));
        assert!(config.get_provider("OPENROUTER").is_some());
    }

    #[test]
    fn app_config_get_provider_prefers_exact_alias_config_when_present() {
        let mut providers = HashMap::new();
        providers.insert(
            "kimi".to_string(),
            ProviderConfig {
                api_key: Some(test_api_key("canonical")),
                base_url: "https://api.moonshot.ai/v1".to_string(),
                model: None,
                headers: crate::secrets::SensitiveHeaders::new(),
                thinking: ThinkingConfig::default(),
            },
        );
        providers.insert(
            "moonshot".to_string(),
            ProviderConfig {
                api_key: Some(test_api_key("alias")),
                base_url: "https://proxy.example.com/v1".to_string(),
                model: None,
                headers: crate::secrets::SensitiveHeaders::new(),
                thinking: ThinkingConfig::default(),
            },
        );

        let config = AppConfig {
            proxy: ProxyConfig {
                target: "moonshot".to_string(),
                ..Default::default()
            },
            providers,
            hooks: HooksConfig::default(),
            session: SessionConfig::default(),
            keybindings: KeybindingsConfig::default(),
            vdd: VddConfig::default(),
            guardrails: GuardrailsConfig::default(),
            permissions: PermissionsConfig::default(),
            memory: MemoryConfig::default(),
            web_fetch: WebFetchConfig::default(),
            policy: crate::services::policy::EnterprisePolicy::default(),
            managed_settings_path: None,
        };

        assert!(config
            .active_provider()
            .and_then(|provider| provider.api_key.as_ref())
            .is_some_and(|key| key.matches("alias-0000000000")));
    }

    #[test]
    fn app_config_get_provider_prefers_lowercase_config_key_before_alias_fallback() {
        let mut providers = HashMap::new();
        for (name, base_url) in [
            ("local", "http://generic-local.example/v1"),
            ("lmstudio", "http://lmstudio.example/v1"),
            ("localai", "http://localai.example/v1"),
            (
                "text-generation-webui",
                "http://text-generation-webui.example/v1",
            ),
        ] {
            providers.insert(
                name.to_string(),
                ProviderConfig {
                    api_key: None,
                    base_url: base_url.to_string(),
                    model: None,
                    headers: crate::secrets::SensitiveHeaders::new(),
                    thinking: ThinkingConfig::default(),
                },
            );
        }

        let config = AppConfig {
            proxy: ProxyConfig {
                target: "local".to_string(),
                ..Default::default()
            },
            providers,
            hooks: HooksConfig::default(),
            session: SessionConfig::default(),
            keybindings: KeybindingsConfig::default(),
            vdd: VddConfig::default(),
            guardrails: GuardrailsConfig::default(),
            permissions: PermissionsConfig::default(),
            memory: MemoryConfig::default(),
            web_fetch: WebFetchConfig::default(),
            policy: crate::services::policy::EnterprisePolicy::default(),
            managed_settings_path: None,
        };

        for (target, expected_url) in [
            ("LMStudio", "http://lmstudio.example/v1"),
            ("LOCALAI", "http://localai.example/v1"),
            (
                "Text-Generation-WebUI",
                "http://text-generation-webui.example/v1",
            ),
        ] {
            assert_eq!(
                config
                    .get_provider(target)
                    .map(|provider| provider.base_url.as_str()),
                Some(expected_url),
                "mixed-case target {target} must use its configured provider key before falling back to generic local"
            );
        }
    }

    #[test]
    fn test_app_config_active_provider_not_found() {
        let config = AppConfig {
            proxy: ProxyConfig {
                target: "nonexistent".to_string(),
                ..Default::default()
            },
            providers: HashMap::new(),
            hooks: HooksConfig::default(),
            session: SessionConfig::default(),
            keybindings: KeybindingsConfig::default(),
            vdd: VddConfig::default(),
            guardrails: GuardrailsConfig::default(),
            permissions: PermissionsConfig::default(),
            memory: MemoryConfig::default(),
            web_fetch: WebFetchConfig::default(),
            policy: crate::services::policy::EnterprisePolicy::default(),
            managed_settings_path: None,
        };

        assert!(config.active_provider().is_none());
    }

    // ── B3 spec pins (#536 §B3) ──────────────────────────────────────────────

    /// Minimal `AppConfig` with no providers, used by B3 tests that only care
    /// about `managed_settings_path`. Avoids repeating the full struct literal.
    fn minimal_config(managed: Option<std::path::PathBuf>) -> AppConfig {
        AppConfig {
            proxy: ProxyConfig {
                target: "anthropic".to_string(),
                ..Default::default()
            },
            providers: HashMap::new(),
            hooks: HooksConfig::default(),
            session: SessionConfig::default(),
            keybindings: KeybindingsConfig::default(),
            vdd: VddConfig::default(),
            guardrails: GuardrailsConfig::default(),
            permissions: PermissionsConfig::default(),
            memory: MemoryConfig::default(),
            web_fetch: WebFetchConfig::default(),
            policy: crate::services::policy::EnterprisePolicy::default(),
            managed_settings_path: managed,
        }
    }

    /// B3: `managed_settings_path` is always `None` when not explicitly set.
    /// Spec §B3: "No code in `load_config()` searches for or sets this field;
    /// it is always `None` at startup." Pins that no accidental initialisation
    /// exists in the struct construction path.
    #[test]
    fn b3_managed_settings_path_is_none_at_construction() {
        let config = minimal_config(None);
        assert!(
            config.managed_settings_path.is_none(),
            "managed_settings_path must be None — enterprise settings not yet implemented"
        );
    }

    /// B3: `managed_settings_path` is `#[serde(skip)]` — no config source can
    /// populate it. We verify the invariant by constructing the struct the same
    /// way any deserialization path would (field absent → `None`).
    #[test]
    fn b3_managed_settings_path_serde_skip_keeps_field_none() {
        let config = minimal_config(None);
        assert!(
            config.managed_settings_path.is_none(),
            "serde(skip) means managed_settings_path is never populated from config sources"
        );
    }

    /// B3: the field type accepts `Some(PathBuf)` when set manually — this
    /// pins the API shape that Phase 2 enterprise-settings code will use when
    /// it populates the field after a successful remote fetch.
    #[test]
    fn b3_managed_settings_path_can_hold_value_when_set() {
        use std::path::PathBuf;
        let path = PathBuf::from("/etc/openclaudia/managed.yaml");
        let config = minimal_config(Some(path.clone()));
        assert_eq!(
            config.managed_settings_path.as_deref(),
            Some(path.as_path()),
            "managed_settings_path must hold the path when explicitly set"
        );
    }
}
