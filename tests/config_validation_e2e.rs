//! End-to-end tests for the config-layer validators that run during
//! `load_config`: `validate_base_url`, `ApiKey` deserialization,
//! and `PermissionsConfig::validate`.
//!
//! Sprint 15 of the verification effort. `src/config/mod.rs` has 11
//! unit tests but no integration coverage that drives the validators
//! against adversarial inputs through the deserialize path the way
//! `load_config` does. Focus areas:
//!
//!   - **`validate_base_url`** — reuses the SSRF guard from
//!     `web::validate_url`. A provider `base_url` of `file://`,
//!     `ftp://`, `data:`, `http://localhost`, `http://169.254.169.254`,
//!     or `[::1]` MUST be rejected.
//!   - **`ApiKey` deserialize gate** — empty, whitespace-only,
//!     control-char-bearing, and non-ASCII keys all rejected with
//!     the documented `ApiKeyError` variants. Catches a hostile
//!     YAML / env value before it propagates into a request header.
//!   - **`PermissionsConfig::validate`** — empty patterns, the
//!     unbounded `*` and `**` patterns, and patterns with embedded
//!     NUL / control chars all refused.
//!   - **`AppConfig` YAML round-trip** — a minimal YAML config
//!     deserializes into the expected shape; defaults apply for
//!     omitted optional fields.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::config::{
    load_config, validate_base_url, validate_provider_base_url, AppConfig, PermissionsConfig,
};
use openclaudia::providers::api_key::{ApiKey, ApiKeyError};
use serde_yaml::Value as YamlValue;
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, OnceLock},
};

const CONFIG_ENV_VARS: &[&str] = &[
    "OPENCLAUDIA_PROXY_TARGET",
    "OPENCLAUDIA_PROVIDERS_OLLAMA_BASE_URL",
    "OPENCLAUDIA_PROVIDERS_LOCAL_BASE_URL",
    "OPENCLAUDIA_PROVIDERS_LMSTUDIO_BASE_URL",
    "OPENCLAUDIA_PROVIDERS_LOCALAI_BASE_URL",
    "OPENCLAUDIA_PROVIDERS_TEXT-GENERATION-WEBUI_BASE_URL",
    "OPENCLAUDIA_PROVIDERS_ANTHROPIC_API_KEY",
    "OPENCLAUDIA_PROVIDERS_OPENAI_API_KEY",
    "OPENCLAUDIA_PROVIDERS_GOOGLE_API_KEY",
    "OPENCLAUDIA_PROVIDERS_ZAI_API_KEY",
    "OPENCLAUDIA_PROVIDERS_DEEPSEEK_API_KEY",
    "OPENCLAUDIA_PROVIDERS_QWEN_API_KEY",
    "OPENCLAUDIA_PROVIDERS_KIMI_API_KEY",
    "OPENCLAUDIA_PROVIDERS_MINIMAX_API_KEY",
    "OPENCLAUDIA_PROVIDERS_OPENROUTER_API_KEY",
    "OPENCLAUDIA_PROVIDERS_OPENCODE_API_KEY",
    "OPENCLAUDIA_PROVIDERS_OPENAI_COMPATIBLE_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "DEEPSEEK_API_KEY",
    "QWEN_API_KEY",
    "DASHSCOPE_API_KEY",
    "ALIYUN_API_KEY",
    "ZAI_API_KEY",
    "KIMI_API_KEY",
    "MOONSHOT_API_KEY",
    "MINIMAX_API_KEY",
    "OPENROUTER_API_KEY",
    "OPEN_ROUTER_API_KEY",
    "OPENCODE_API_KEY",
    "OPENCODE_GO_API_KEY",
    "OPENAI_COMPATIBLE_API_KEY",
    "API_KEY",
];

fn process_env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct CwdGuard {
    previous: PathBuf,
}

impl CwdGuard {
    fn set_to(path: &Path) -> Self {
        let previous = std::env::current_dir().expect("current dir");
        std::env::set_current_dir(path).expect("set temp cwd");
        Self { previous }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.previous);
    }
}

struct EnvGuard {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvGuard {
    fn set_path(key: &'static str, value: &Path) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, previous }
    }

    fn remove(key: &'static str) -> Self {
        let previous = std::env::var_os(key);
        std::env::remove_var(key);
        Self { key, previous }
    }

    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.previous {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — validate_base_url adversarial inputs
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn validate_base_url_accepts_routable_public_https() {
    // Public hosts — the validator does live DNS so we allow either
    // success or DNS-failure (no network) but require: the rejection
    // message MUST NOT mention a policy term (loopback / private /
    // metadata) for a routable public URL.
    let outcome = validate_base_url("https://api.anthropic.com");
    if let Err(msg) = outcome {
        let lowered = msg.to_lowercase();
        for policy_word in &["loopback", "rfc 1918", "private", "link-local", "metadata"] {
            assert!(
                !lowered.contains(policy_word),
                "rejection of public URL MUST NOT mention policy term \
                 {policy_word:?}; got msg={msg:?}"
            );
        }
    }
}

#[test]
fn validate_base_url_refuses_loopback_and_private_addresses() {
    // Sample of canonical SSRF-blockable URLs covered by the
    // `web::validate_url` perimeter that `validate_base_url`
    // delegates to.
    for url in &[
        "http://127.0.0.1/",
        "http://localhost/",
        "http://[::1]/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/", // AWS metadata
    ] {
        let outcome = validate_base_url(url);
        assert!(
            outcome.is_err(),
            "{url:?} must be refused as SSRF; got {outcome:?}"
        );
    }
}

#[test]
fn provider_base_url_validation_allows_local_provider_loopback_urls_only() {
    for provider in [
        "ollama",
        "local",
        "lmstudio",
        "localai",
        "text-generation-webui",
    ] {
        assert!(
            validate_provider_base_url(provider, "http://localhost:11434").is_ok(),
            "local provider {provider} must allow localhost base_url"
        );
        assert!(
            validate_provider_base_url(provider, "http://10.0.0.5:1234/v1").is_ok(),
            "local provider {provider} must allow private-network base_url"
        );
    }

    assert!(
        validate_provider_base_url("anthropic", "http://localhost:11434").is_err(),
        "remote providers must keep SSRF guard for localhost"
    );
    assert!(
        validate_provider_base_url("ollama", "file:///tmp/socket").is_err(),
        "local provider validation must still reject non-http schemes"
    );
}

#[test]
fn validate_base_url_refuses_non_http_schemes() {
    for url in &[
        "file:///etc/passwd",
        "ftp://example.com/",
        "data:text/plain,x",
        "javascript:alert(1)",
        "gopher://example.com/",
    ] {
        let outcome = validate_base_url(url);
        assert!(
            outcome.is_err(),
            "non-http scheme {url:?} must be refused; got {outcome:?}"
        );
    }
}

#[test]
fn validate_base_url_message_carries_url_for_diagnostics() {
    // The error message must include the offending URL string so
    // log consumers can pivot on it without re-deriving from
    // context.
    let url = "http://127.0.0.1/";
    let Err(msg) = validate_base_url(url) else {
        panic!("loopback must be refused");
    };
    assert!(
        msg.contains(url),
        "error message must include offending URL; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — ApiKey deserialize gate
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn api_key_refuses_empty_string() {
    let outcome = ApiKey::try_from_string(String::new());
    assert!(
        matches!(outcome, Err(ApiKeyError::Empty)),
        "empty key must error ApiKeyError::Empty; got {outcome:?}"
    );
}

#[test]
fn api_key_refuses_whitespace_only_string() {
    let outcome = ApiKey::try_from_string("   \n\t".to_string());
    assert!(
        matches!(outcome, Err(ApiKeyError::Empty)),
        "whitespace-only key must error Empty; got {outcome:?}"
    );
}

#[test]
fn api_key_refuses_embedded_newline() {
    // Newline-bearing keys would smuggle into request headers
    // and split the HTTP frame. ApiKey MUST refuse any control
    // character.
    let outcome = ApiKey::try_from_string("sk-ant-PREFIX\nINJECT: header".to_string());
    assert!(
        matches!(outcome, Err(ApiKeyError::ControlChar { .. })),
        "newline-bearing key must error ControlChar; got {outcome:?}"
    );
}

#[test]
fn api_key_refuses_embedded_carriage_return() {
    let outcome = ApiKey::try_from_string("sk-ant-PREFIX\rINJECT".to_string());
    assert!(
        matches!(outcome, Err(ApiKeyError::ControlChar { .. })),
        "CR-bearing key must error ControlChar; got {outcome:?}"
    );
}

#[test]
fn api_key_refuses_embedded_nul_byte() {
    let outcome = ApiKey::try_from_string("sk-ant-PREFIX\0EVIL".to_string());
    assert!(
        matches!(outcome, Err(ApiKeyError::ControlChar { .. })),
        "NUL-bearing key must error ControlChar; got {outcome:?}"
    );
}

#[test]
fn api_key_refuses_non_ascii_input() {
    let outcome = ApiKey::try_from_string("sk-ant-héllo".to_string());
    assert!(
        matches!(outcome, Err(ApiKeyError::NonAscii)),
        "non-ASCII key must error NonAscii; got {outcome:?}"
    );
}

#[test]
fn api_key_accepts_realistic_keys() {
    // Canonical shape — the validator must NOT over-reject.
    for raw in &[
        "sk-ant-api03-1234567890abcdef",
        "sk-proj-1234567890abcdefABCDEF",
        "AIzaSyBxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "glm-4-32B-API-KEY-ABCDEF1234567890",
    ] {
        let outcome = ApiKey::try_from_string((*raw).to_string());
        assert!(
            outcome.is_ok(),
            "canonical key {raw:?} must be accepted; got {outcome:?}"
        );
    }
}

#[test]
fn api_key_deserialize_from_yaml_rejects_invalid_string() {
    // The YAML deserialize path delegates to try_from_string, so
    // every invalid input above must also fail at YAML load time.
    // Pin both happy and sad path.
    #[derive(serde::Deserialize)]
    struct Wrapper {
        key: ApiKey,
    }
    let good: Wrapper = serde_yaml::from_str("key: sk-ant-PRODUCTION-KEY").expect("yaml ok");
    let _ = good.key;

    let bad: Result<Wrapper, _> = serde_yaml::from_str("key: \"\"");
    assert!(
        bad.is_err(),
        "empty string key MUST fail YAML deserialization"
    );

    let bad_ws: Result<Wrapper, _> = serde_yaml::from_str("key: \"   \"");
    assert!(
        bad_ws.is_err(),
        "whitespace-only key MUST fail YAML deserialization"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — PermissionsConfig::validate
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn permissions_validate_rejects_empty_pattern() {
    let yaml = r#"
enabled: true
default_allow:
  - ""
"#;
    let cfg: PermissionsConfig = serde_yaml::from_str(yaml).expect("yaml parses");
    let outcome = cfg.validate();
    assert!(
        outcome.is_err(),
        "empty pattern must be refused; got {outcome:?}"
    );
    assert!(
        outcome.unwrap_err().contains("empty"),
        "error must name 'empty'"
    );
}

#[test]
fn permissions_validate_rejects_unbounded_star_patterns() {
    for pattern in &["*", "**"] {
        let yaml = format!("enabled: true\ndefault_allow:\n  - \"{pattern}\"\n");
        let cfg: PermissionsConfig = serde_yaml::from_str(&yaml).expect("yaml parses");
        let outcome = cfg.validate();
        assert!(
            outcome.is_err(),
            "unbounded pattern {pattern:?} must be refused; got {outcome:?}"
        );
        let msg = outcome.unwrap_err();
        assert!(
            msg.contains("unbounded"),
            "error must name 'unbounded'; got {msg:?}"
        );
    }
}

#[test]
fn permissions_validate_rejects_nul_byte_in_pattern() {
    let cfg = PermissionsConfig {
        enabled: true,
        default_allow: vec!["legit\0evil".to_string()],
        ..Default::default()
    };
    let outcome = cfg.validate();
    assert!(
        outcome.is_err(),
        "NUL-byte pattern must be refused; got {outcome:?}"
    );
}

#[test]
fn permissions_validate_admits_scoped_globs() {
    // Counter-test: legitimate scoped globs must pass.
    let cfg = PermissionsConfig {
        enabled: true,
        default_allow: vec![
            "/project/**".to_string(),
            "git status".to_string(),
            "src/**/*.rs".to_string(),
        ],
        ..Default::default()
    };
    let outcome = cfg.validate();
    assert!(
        outcome.is_ok(),
        "scoped globs must pass validation; got {outcome:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — AppConfig YAML round-trip
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn app_config_minimal_yaml_round_trips_with_defaults_for_optionals() {
    let yaml = r#"
proxy:
  port: 9090
  host: "127.0.0.1"
  target: anthropic
providers:
  anthropic:
    base_url: https://api.anthropic.com
    api_key: sk-ant-test-PRODUCTION-KEY
"#;
    let cfg: AppConfig = serde_yaml::from_str(yaml).expect("minimal yaml must deserialize");
    assert_eq!(cfg.proxy.port, 9090);
    assert_eq!(cfg.proxy.target, "anthropic");
    assert!(cfg.providers.contains_key("anthropic"));
    // Defaults for optionals: hooks, permissions, etc.
    assert!(cfg.hooks.pre_tool_use.is_empty());
    assert!(cfg.permissions.default_allow.is_empty());
}

#[test]
fn app_config_yaml_with_invalid_provider_api_key_fails_load() {
    let yaml = r#"
proxy:
  port: 8080
  host: "127.0.0.1"
  target: anthropic
providers:
  anthropic:
    base_url: https://api.anthropic.com
    api_key: ""
"#;
    let outcome: Result<AppConfig, _> = serde_yaml::from_str(yaml);
    assert!(
        outcome.is_err(),
        "empty api_key must fail YAML deserialization at the ApiKey gate; got {outcome:?}"
    );
}

#[test]
fn app_config_active_provider_lookup_respects_proxy_target() {
    let yaml = r#"
proxy:
  port: 8080
  host: "127.0.0.1"
  target: openai
providers:
  anthropic:
    base_url: https://api.anthropic.com
    api_key: sk-ant-key
  openai:
    base_url: https://api.openai.com
    api_key: sk-openai-key
"#;
    let cfg: AppConfig = serde_yaml::from_str(yaml).expect("yaml ok");
    let active = cfg.active_provider().expect("active provider must resolve");
    assert_eq!(active.base_url, "https://api.openai.com");
}

fn readme_config_file_example_yaml() -> &'static str {
    include_str!("../README.md")
        .split_once("### Config File")
        .expect("README must have Config File section")
        .1
        .split_once("```yaml")
        .expect("Config File section must contain a yaml block")
        .1
        .split_once("```")
        .expect("Config File yaml block must be closed")
        .0
}

#[test]
fn readme_config_file_example_uses_real_schema_and_valid_provider_urls() {
    let yaml = readme_config_file_example_yaml();
    let root: YamlValue = serde_yaml::from_str(yaml).expect("README config sample is valid YAML");
    let mapping = root.as_mapping().expect("README config sample root is map");
    assert!(
        !mapping.contains_key(YamlValue::String("thinking".to_string())),
        "README must not document ignored top-level thinking config"
    );

    let cfg: AppConfig = serde_yaml::from_str(yaml).expect("README config sample deserializes");
    for provider in openclaudia::providers::SUPPORTED_PROVIDERS {
        assert!(
            yaml.contains(provider),
            "README config sample provider inventory must mention supported target {provider}"
        );
    }
    assert_eq!(
        cfg.session.max_turns, 0,
        "README sample must show default unlimited max_turns"
    );
    let anthropic_thinking = &cfg.providers["anthropic"].thinking;
    assert!(
        !anthropic_thinking.enabled,
        "README sample must place Anthropic thinking.enabled under providers.anthropic"
    );
    assert_eq!(
        anthropic_thinking.reasoning_effort.as_deref(),
        Some("high"),
        "README sample must place Anthropic reasoning_effort under providers.anthropic"
    );
    assert_eq!(
        anthropic_thinking.budget_tokens, None,
        "README sample must keep Anthropic budget_tokens commented unless manually enabled"
    );
    assert!(
        yaml.contains("# budget_tokens: 10000"),
        "README sample must still document the optional manual-thinking Claude budget"
    );
    assert_eq!(
        cfg.providers["openai"].thinking.reasoning_effort.as_deref(),
        Some("medium"),
        "README sample must place OpenAI reasoning effort under providers.openai"
    );

    for (name, provider) in &cfg.providers {
        validate_provider_base_url(name, &provider.base_url)
            .unwrap_or_else(|err| panic!("README provider {name:?} base_url must validate: {err}"));
    }
}

#[test]
fn load_config_seeds_advertised_local_provider_defaults() {
    let _lock = process_env_lock();
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let _cwd_guard = CwdGuard::set_to(cwd.path());
    let _home_guard = EnvGuard::set_path("HOME", home.path());
    let _env_guards: Vec<EnvGuard> = CONFIG_ENV_VARS
        .iter()
        .copied()
        .map(EnvGuard::remove)
        .collect();

    let cfg = load_config().expect("default config must load in isolated cwd");
    for (name, expected_url) in [
        ("ollama", "http://localhost:11434"),
        ("local", "http://localhost:1234/v1"),
        ("lmstudio", "http://localhost:1234/v1"),
        ("localai", "http://localhost:8080/v1"),
        ("text-generation-webui", "http://localhost:5000/v1"),
    ] {
        let provider = cfg
            .providers
            .get(name)
            .unwrap_or_else(|| panic!("default config must include local provider {name}"));
        assert_eq!(provider.base_url, expected_url);
        validate_provider_base_url(name, &provider.base_url)
            .unwrap_or_else(|err| panic!("default {name} base_url must validate: {err}"));
    }
}

#[test]
fn load_config_accepts_provider_api_key_env_aliases() {
    let _lock = process_env_lock();
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let _cwd_guard = CwdGuard::set_to(cwd.path());
    let _home_guard = EnvGuard::set_path("HOME", home.path());
    let _clean_env: Vec<EnvGuard> = CONFIG_ENV_VARS
        .iter()
        .copied()
        .map(EnvGuard::remove)
        .collect();
    let _alias_env = [
        EnvGuard::set("GEMINI_API_KEY", "gemini-alias-key"),
        EnvGuard::set("DASHSCOPE_API_KEY", "dashscope-alias-key"),
        EnvGuard::set("OPEN_ROUTER_API_KEY", "open-router-alias-key"),
        EnvGuard::set("OPENCODE_GO_API_KEY", "opencode-go-alias-key"),
    ];

    let cfg = load_config().expect("alias-only config must load");
    for (provider, expected_key) in [
        ("google", "gemini-alias-key"),
        ("qwen", "dashscope-alias-key"),
        ("openrouter", "open-router-alias-key"),
        ("opencode", "opencode-go-alias-key"),
    ] {
        let actual_key = cfg.providers[provider]
            .api_key
            .as_ref()
            .unwrap_or_else(|| panic!("{provider} alias key must be discovered"));
        assert_eq!(actual_key.as_str(), expected_key);
    }
}

#[test]
fn load_config_accepts_advertised_prefixed_provider_api_keys() {
    let _lock = process_env_lock();
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let _cwd_guard = CwdGuard::set_to(cwd.path());
    let _home_guard = EnvGuard::set_path("HOME", home.path());
    let _clean_env: Vec<EnvGuard> = CONFIG_ENV_VARS
        .iter()
        .copied()
        .map(EnvGuard::remove)
        .collect();
    let _prefixed_env = [
        EnvGuard::set(
            "OPENCLAUDIA_PROVIDERS_GOOGLE_API_KEY",
            "prefixed-google-key",
        ),
        EnvGuard::set("OPENCLAUDIA_PROVIDERS_QWEN_API_KEY", "prefixed-qwen-key"),
        EnvGuard::set(
            "OPENCLAUDIA_PROVIDERS_OPENROUTER_API_KEY",
            "prefixed-openrouter-key",
        ),
        EnvGuard::set(
            "OPENCLAUDIA_PROVIDERS_OPENCODE_API_KEY",
            "prefixed-opencode-key",
        ),
    ];

    let cfg = load_config().expect("prefixed API-key config must load");
    for (provider, expected_key) in [
        ("google", "prefixed-google-key"),
        ("qwen", "prefixed-qwen-key"),
        ("openrouter", "prefixed-openrouter-key"),
        ("opencode", "prefixed-opencode-key"),
    ] {
        let actual_key = cfg.providers[provider]
            .api_key
            .as_ref()
            .unwrap_or_else(|| panic!("{provider} prefixed key must be discovered"));
        assert_eq!(actual_key.as_str(), expected_key);
    }
}

#[test]
fn load_config_defaults_zai_to_the_general_api() {
    let _lock = process_env_lock();
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let _cwd_guard = CwdGuard::set_to(cwd.path());
    let _home_guard = EnvGuard::set_path("HOME", home.path());
    let _env_guards: Vec<EnvGuard> = CONFIG_ENV_VARS
        .iter()
        .copied()
        .map(EnvGuard::remove)
        .collect();

    let cfg = load_config().expect("default config must load");
    assert_eq!(
        cfg.providers["zai"].base_url,
        "https://api.z.ai/api/paas/v4"
    );
}
