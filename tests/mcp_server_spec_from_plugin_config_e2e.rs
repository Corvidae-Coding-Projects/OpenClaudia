//! End-to-end tests for `services::McpServerSpec::from_plugin_config`
//! — the manifest → registry mirroring step, plus
//! `McpServerSpec` Eq/Clone/Debug invariants and the
//! transport field defaults from `McpServerConfig`.
//!
//! Sprint 203 of the verification effort. Sprint 117/etc.
//! covered the registry surface; this file pins the
//! manifest-to-registry transform specifically.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::plugins::manifest::McpServerConfig;
use openclaudia::secrets::{EnvironmentGrants, SensitiveHeaders};
use openclaudia::services::McpServerSpec;
use std::collections::HashMap;

fn secret_env(values: impl IntoIterator<Item = (&'static str, &'static str)>) -> EnvironmentGrants {
    EnvironmentGrants::try_from(
        values
            .into_iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect::<HashMap<_, _>>(),
    )
    .expect("valid test environment")
}

fn secret_headers(
    values: impl IntoIterator<Item = (&'static str, &'static str)>,
) -> SensitiveHeaders {
    SensitiveHeaders::try_from(
        values
            .into_iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect::<HashMap<_, _>>(),
    )
    .expect("valid test headers")
}

fn default_cfg() -> McpServerConfig {
    McpServerConfig {
        command: None,
        args: Vec::new(),
        env: EnvironmentGrants::new(),
        transport: "stdio".to_string(),
        url: None,
        headers: SensitiveHeaders::new(),
        headers_helper: None,
        oauth: None,
        timeout: None,
        always_load: None,
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — from_plugin_config field-by-field mirroring
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn from_plugin_config_propagates_command() {
    let cfg = McpServerConfig {
        command: Some("npx".to_string()),
        ..default_cfg()
    };
    let spec = McpServerSpec::from_plugin_config(&cfg);
    assert_eq!(spec.command.as_deref(), Some("npx"));
}

#[test]
fn from_plugin_config_propagates_args() {
    let cfg = McpServerConfig {
        args: vec![
            "-y".to_string(),
            "@modelcontextprotocol/server-x".to_string(),
        ],
        ..default_cfg()
    };
    let spec = McpServerSpec::from_plugin_config(&cfg);
    assert_eq!(spec.args.len(), 2);
    assert_eq!(spec.args[0], "-y");
}

#[test]
fn from_plugin_config_propagates_env() {
    let cfg = McpServerConfig {
        env: secret_env([("MY_VAR", "value")]),
        ..default_cfg()
    };
    let spec = McpServerSpec::from_plugin_config(&cfg);
    assert!(spec.env.matches_value("MY_VAR", "value"));
}

#[test]
fn from_plugin_config_propagates_headers_and_mcp_metadata() {
    let cfg = McpServerConfig {
        headers: secret_headers([("Authorization", "Bearer token")]),
        headers_helper: Some("/bin/get-headers".to_string()),
        oauth: Some(openclaudia::mcp_oauth::McpOAuthClientConfig {
            client_id: "registry-client".to_string(),
            client_secret: None,
            redirect_uri: "http://127.0.0.1:7777/callback".to_string(),
            scopes: vec!["mcp.read".to_string()],
        }),
        timeout: Some(600_000),
        always_load: Some(true),
        ..default_cfg()
    };
    let spec = McpServerSpec::from_plugin_config(&cfg);
    assert!(spec.headers.matches_value("Authorization", "Bearer token"));
    assert_eq!(spec.headers_helper.as_deref(), Some("/bin/get-headers"));
    assert_eq!(
        spec.oauth.as_ref().map(|oauth| oauth.client_id.as_str()),
        Some("registry-client")
    );
    assert_eq!(spec.timeout, Some(600_000));
    assert_eq!(spec.always_load, Some(true));
}

#[test]
fn from_plugin_config_propagates_transport_stdio() {
    let cfg = McpServerConfig {
        transport: "stdio".to_string(),
        ..default_cfg()
    };
    let spec = McpServerSpec::from_plugin_config(&cfg);
    assert_eq!(spec.transport, "stdio");
}

#[test]
fn from_plugin_config_propagates_transport_http() {
    let cfg = McpServerConfig {
        transport: "http".to_string(),
        url: Some("https://mcp.example.com".to_string()),
        ..default_cfg()
    };
    let spec = McpServerSpec::from_plugin_config(&cfg);
    assert_eq!(spec.transport, "http");
    assert_eq!(spec.url.as_deref(), Some("https://mcp.example.com"));
}

#[test]
fn from_plugin_config_command_none_stays_none() {
    let cfg = default_cfg();
    let spec = McpServerSpec::from_plugin_config(&cfg);
    assert!(spec.command.is_none());
}

#[test]
fn from_plugin_config_url_none_stays_none() {
    let cfg = default_cfg();
    let spec = McpServerSpec::from_plugin_config(&cfg);
    assert!(spec.url.is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Default values from McpServerConfig serde defaults
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn mcp_server_config_default_transport_is_stdio() {
    // PINS DOC: default transport from manifest is "stdio".
    let yaml = "{}";
    let cfg: McpServerConfig = serde_yaml::from_str(yaml).expect("de");
    assert_eq!(cfg.transport, "stdio");
}

#[test]
fn mcp_server_config_with_only_command_uses_default_transport() {
    let yaml = "command: npx";
    let cfg: McpServerConfig = serde_yaml::from_str(yaml).expect("de");
    assert_eq!(cfg.command.as_deref(), Some("npx"));
    assert_eq!(cfg.transport, "stdio");
}

#[test]
fn mcp_server_config_args_default_to_empty_vec() {
    let yaml = "{}";
    let cfg: McpServerConfig = serde_yaml::from_str(yaml).expect("de");
    assert!(cfg.args.is_empty());
}

#[test]
fn mcp_server_config_env_defaults_to_empty_map() {
    let yaml = "{}";
    let cfg: McpServerConfig = serde_yaml::from_str(yaml).expect("de");
    assert!(cfg.env.is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — McpServerSpec PartialEq + Clone
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn spec_clone_preserves_all_fields() {
    let original = McpServerSpec {
        command: Some("npx".to_string()),
        args: vec!["-y".to_string()],
        env: secret_env([("K", "V")]),
        transport: "stdio".to_string(),
        url: None,
        headers: SensitiveHeaders::new(),
        headers_helper: None,
        oauth: None,
        timeout: None,
        always_load: None,
    };
    let cloned = original.clone();
    assert_eq!(cloned, original);
    assert_eq!(cloned.command.as_deref(), Some("npx"));
    assert_eq!(cloned.args.len(), 1);
}

#[test]
fn spec_partial_eq_distinguishes_different_commands() {
    let a = McpServerSpec {
        command: Some("npx".to_string()),
        args: Vec::new(),
        env: EnvironmentGrants::new(),
        transport: "stdio".to_string(),
        url: None,
        headers: SensitiveHeaders::new(),
        headers_helper: None,
        oauth: None,
        timeout: None,
        always_load: None,
    };
    let b = McpServerSpec {
        command: Some("python".to_string()),
        ..a.clone()
    };
    assert_ne!(a, b);
}

#[test]
fn spec_partial_eq_distinguishes_different_args() {
    let a = McpServerSpec {
        command: None,
        args: vec!["a".to_string()],
        env: EnvironmentGrants::new(),
        transport: "stdio".to_string(),
        url: None,
        headers: SensitiveHeaders::new(),
        headers_helper: None,
        oauth: None,
        timeout: None,
        always_load: None,
    };
    let b = McpServerSpec {
        args: vec!["b".to_string()],
        ..a.clone()
    };
    assert_ne!(a, b);
}

#[test]
fn spec_partial_eq_distinguishes_different_transports() {
    let a = McpServerSpec {
        command: None,
        args: Vec::new(),
        env: EnvironmentGrants::new(),
        transport: "stdio".to_string(),
        url: None,
        headers: SensitiveHeaders::new(),
        headers_helper: None,
        oauth: None,
        timeout: None,
        always_load: None,
    };
    let b = McpServerSpec {
        transport: "http".to_string(),
        ..a.clone()
    };
    assert_ne!(a, b);
}

#[test]
fn spec_debug_format_includes_field_names() {
    let spec = McpServerSpec {
        command: Some("npx".to_string()),
        args: vec!["-y".to_string()],
        env: EnvironmentGrants::new(),
        transport: "stdio".to_string(),
        url: None,
        headers: SensitiveHeaders::new(),
        headers_helper: None,
        oauth: None,
        timeout: None,
        always_load: None,
    };
    let d = format!("{spec:?}");
    assert!(d.contains("command"));
    assert!(d.contains("transport"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Round-trip via from_plugin_config
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn from_plugin_config_called_twice_yields_equal_specs() {
    let cfg = McpServerConfig {
        command: Some("npx".to_string()),
        args: vec!["-y".to_string()],
        env: secret_env([("X", "Y")]),
        transport: "stdio".to_string(),
        url: None,
        headers: SensitiveHeaders::new(),
        headers_helper: None,
        oauth: None,
        timeout: None,
        always_load: None,
    };
    let s1 = McpServerSpec::from_plugin_config(&cfg);
    let s2 = McpServerSpec::from_plugin_config(&cfg);
    assert_eq!(s1, s2);
}

#[test]
fn from_plugin_config_with_full_config_propagates_every_field() {
    let cfg = McpServerConfig {
        command: Some("uvx".to_string()),
        args: vec![
            "server".to_string(),
            "--port".to_string(),
            "8080".to_string(),
        ],
        env: secret_env([("API_KEY", "secret")]),
        transport: "stdio".to_string(),
        url: None,
        headers: secret_headers([("X-Api-Key", "secret")]),
        headers_helper: Some("/bin/helper".to_string()),
        oauth: None,
        timeout: Some(1234),
        always_load: Some(false),
    };
    let spec = McpServerSpec::from_plugin_config(&cfg);
    assert_eq!(spec.command.as_deref(), Some("uvx"));
    assert_eq!(spec.args, vec!["server", "--port", "8080"]);
    assert!(spec.env.matches_value("API_KEY", "secret"));
    assert_eq!(spec.transport, "stdio");
    assert!(spec.url.is_none());
    assert!(spec.headers.matches_value("X-Api-Key", "secret"));
    assert_eq!(spec.headers_helper.as_deref(), Some("/bin/helper"));
    assert_eq!(spec.timeout, Some(1234));
    assert_eq!(spec.always_load, Some(false));
}
