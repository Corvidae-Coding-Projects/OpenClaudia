//! End-to-end tests for `plugins::manifest` data types
//! beyond the `PluginManifest` parser (sprint 32) —
//! `PluginAuthor`, `McpServerConfig`, `LspServerConfig`,
//! `AgentsSpec` / `SkillsSpec` Path/Paths variants, and
//! enum-variant Eq behavior.
//!
//! Sprint 116 of the verification effort. Sprint 32
//! (`plugin_loader_e2e`) covered the manifest parser +
//! `CommandsSpec` / `HooksSpec` / `McpServersSpec`; this
//! file pins the nested type shapes (`PluginAuthor`
//! skip-None serde, `McpServerConfig` transport default,
//! `LspServerConfig` extensions field, `AgentsSpec` +
//! `SkillsSpec` untagged path / paths variants).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::plugins::manifest::{
    AgentsSpec, LspServerConfig, McpServerConfig, PluginAuthor, SkillsSpec,
};
use openclaudia::secrets::{EnvironmentGrants, SensitiveHeaders};
use std::collections::HashMap;

// ───────────────────────────────────────────────────────────────────────────
// Section A — PluginAuthor serde
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn plugin_author_default_has_empty_name_and_none_contacts() {
    let author = PluginAuthor::default();
    assert!(author.name.is_empty());
    assert!(author.email.is_none());
    assert!(author.url.is_none());
}

#[test]
fn plugin_author_minimal_serializes_with_only_name() {
    let author = PluginAuthor {
        name: "test author".to_string(),
        email: None,
        url: None,
    };
    let json = serde_json::to_string(&author).expect("ser");
    assert!(json.contains("\"name\":\"test author\""));
    assert!(
        !json.contains("\"email\""),
        "None email MUST be skipped; got {json:?}"
    );
    assert!(
        !json.contains("\"url\""),
        "None url MUST be skipped; got {json:?}"
    );
}

#[test]
fn plugin_author_full_shape_round_trips() {
    let original = PluginAuthor {
        name: "Author Name".to_string(),
        email: Some("author@example.com".to_string()),
        url: Some("https://example.com/author".to_string()),
    };
    let json = serde_json::to_string(&original).expect("ser");
    let back: PluginAuthor = serde_json::from_str(&json).expect("de");
    assert_eq!(back.name, original.name);
    assert_eq!(back.email, original.email);
    assert_eq!(back.url, original.url);
}

#[test]
fn plugin_author_deserializes_with_name_only() {
    let json = r#"{"name": "minimal"}"#;
    let author: PluginAuthor = serde_json::from_str(json).expect("de");
    assert_eq!(author.name, "minimal");
    assert!(author.email.is_none());
    assert!(author.url.is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — McpServerConfig
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn mcp_server_config_minimal_yields_stdio_transport_by_default() {
    let json = "{}";
    let config: McpServerConfig = serde_json::from_str(json).expect("de");
    assert_eq!(
        config.transport, "stdio",
        "PINS DEFAULT: missing transport MUST default to stdio"
    );
}

#[test]
fn mcp_server_config_with_command_and_args_round_trips() {
    let json = r#"{
        "command": "python",
        "args": ["-u", "server.py"],
        "transport": "stdio"
    }"#;
    let config: McpServerConfig = serde_json::from_str(json).expect("de");
    assert_eq!(config.command.as_deref(), Some("python"));
    assert_eq!(config.args, vec!["-u", "server.py"]);
}

#[test]
fn mcp_server_config_http_transport_with_url_round_trips() {
    let json = r#"{
        "transport": "http",
        "url": "https://api.example.com/mcp"
    }"#;
    let config: McpServerConfig = serde_json::from_str(json).expect("de");
    assert_eq!(config.transport, "http");
    assert_eq!(config.url.as_deref(), Some("https://api.example.com/mcp"));
}

#[test]
fn mcp_server_config_type_alias_http_protects_headers_on_parse() {
    let json = r#"{
        "type": "http",
        "url": "https://api.example.com/mcp",
        "headers": {"Authorization": "Bearer token"}
    }"#;
    let config: McpServerConfig = serde_json::from_str(json).expect("de");
    assert_eq!(config.transport, "http");
    assert!(config
        .headers
        .matches_value("Authorization", "Bearer token"));
    assert!(!format!("{config:?}").contains("Bearer token"));
    assert!(!serde_json::to_string(&config)
        .expect("ser")
        .contains("Bearer token"));
}

#[test]
fn mcp_server_config_streamable_http_type_normalizes_to_http() {
    let json = r#"{
        "type": "streamable-http",
        "url": "https://api.example.com/mcp"
    }"#;
    let config: McpServerConfig = serde_json::from_str(json).expect("de");
    assert_eq!(config.transport, "http");
}

#[test]
fn mcp_server_config_env_vars_are_protected_on_parse() {
    let json = r#"{
        "command": "node",
        "env": {"API_KEY": "secret", "DEBUG": "1"}
    }"#;
    let config: McpServerConfig = serde_json::from_str(json).expect("de");
    assert_eq!(config.env.len(), 2);
    assert!(config.env.matches_value("API_KEY", "secret"));
    assert!(config.env.matches_value("DEBUG", "1"));
    assert!(!format!("{config:?}").contains("secret"));
    assert!(!serde_json::to_string(&config)
        .expect("ser")
        .contains("secret"));
}

#[test]
fn mcp_server_config_omits_empty_args_and_env_on_serialize() {
    let config = McpServerConfig {
        command: Some("cmd".to_string()),
        args: Vec::new(),
        env: EnvironmentGrants::new(),
        transport: "stdio".to_string(),
        url: None,
        headers: SensitiveHeaders::new(),
        headers_helper: None,
        timeout: None,
        always_load: None,
    };
    let json = serde_json::to_string(&config).expect("ser");
    assert!(
        !json.contains("\"args\""),
        "empty args MUST be skipped; got {json:?}"
    );
    assert!(
        !json.contains("\"env\""),
        "empty env MUST be skipped; got {json:?}"
    );
    assert!(!json.contains("\"url\""), "None url MUST be skipped");
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — LspServerConfig (#655)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn lsp_server_config_required_command_field() {
    let json = r#"{"command": "rust-analyzer"}"#;
    let config: LspServerConfig = serde_json::from_str(json).expect("de");
    assert_eq!(config.command, "rust-analyzer");
    assert!(config.args.is_empty());
    assert!(config.env.is_empty());
    assert!(config.extensions.is_empty());
}

#[test]
fn lsp_server_config_full_shape_protects_environment() {
    let json = r#"{
        "command": "rust-analyzer",
        "args": ["--no-log-buffering"],
        "env": {"RUST_LOG": "info"},
        "extensions": ["rs"]
    }"#;
    let config: LspServerConfig = serde_json::from_str(json).expect("de");
    assert_eq!(config.command, "rust-analyzer");
    assert_eq!(config.args, vec!["--no-log-buffering"]);
    assert!(config.env.matches_value("RUST_LOG", "info"));
    assert!(!format!("{config:?}").contains("info"));
    assert!(!serde_json::to_string(&config)
        .expect("ser")
        .contains("info"));
    assert_eq!(config.extensions, vec!["rs"]);
}

#[test]
fn lsp_server_config_partial_eq_holds_for_equal_configs() {
    let a = LspServerConfig {
        command: "ls".to_string(),
        args: vec!["x".to_string()],
        env: EnvironmentGrants::new(),
        extensions: vec!["a".to_string()],
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn lsp_server_config_partial_eq_distinguishes_different_commands() {
    let a = LspServerConfig {
        command: "ls".to_string(),
        args: Vec::new(),
        env: EnvironmentGrants::new(),
        extensions: Vec::new(),
    };
    let b = LspServerConfig {
        command: "other".to_string(),
        args: Vec::new(),
        env: EnvironmentGrants::new(),
        extensions: Vec::new(),
    };
    assert_ne!(a, b);
}

#[test]
fn lsp_server_config_empty_extensions_omitted_on_serialize() {
    let config = LspServerConfig {
        command: "x".to_string(),
        args: Vec::new(),
        env: EnvironmentGrants::new(),
        extensions: Vec::new(),
    };
    let json = serde_json::to_string(&config).expect("ser");
    assert!(
        !json.contains("\"extensions\""),
        "empty extensions MUST be skipped"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — AgentsSpec untagged Path / Paths
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn agents_spec_path_string_parses_as_path_variant() {
    let json = r#""./agents""#;
    let spec: AgentsSpec = serde_json::from_str(json).expect("de");
    match spec {
        AgentsSpec::Path(p) => assert_eq!(p, "./agents"),
        AgentsSpec::Paths(_) => panic!("MUST parse as Path variant"),
    }
}

#[test]
fn agents_spec_paths_array_parses_as_paths_variant() {
    let json = r#"["./agents/a.md", "./agents/b.md"]"#;
    let spec: AgentsSpec = serde_json::from_str(json).expect("de");
    match spec {
        AgentsSpec::Paths(p) => assert_eq!(p, vec!["./agents/a.md", "./agents/b.md"]),
        AgentsSpec::Path(_) => panic!("MUST parse as Paths variant"),
    }
}

#[test]
fn agents_spec_path_round_trips() {
    let original = AgentsSpec::Path("./agents".to_string());
    let json = serde_json::to_string(&original).expect("ser");
    let back: AgentsSpec = serde_json::from_str(&json).expect("de");
    let AgentsSpec::Path(p) = back else {
        panic!("variant mismatch");
    };
    assert_eq!(p, "./agents");
}

#[test]
fn agents_spec_paths_round_trips() {
    let original = AgentsSpec::Paths(vec!["a".to_string(), "b".to_string()]);
    let json = serde_json::to_string(&original).expect("ser");
    let back: AgentsSpec = serde_json::from_str(&json).expect("de");
    let AgentsSpec::Paths(p) = back else {
        panic!("variant mismatch");
    };
    assert_eq!(p, vec!["a", "b"]);
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — SkillsSpec untagged Path / Paths
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn skills_spec_path_string_parses_as_path_variant() {
    let json = r#""./skills""#;
    let spec: SkillsSpec = serde_json::from_str(json).expect("de");
    let SkillsSpec::Path(p) = spec else {
        panic!("MUST parse as Path variant");
    };
    assert_eq!(p, "./skills");
}

#[test]
fn skills_spec_paths_array_parses_as_paths_variant() {
    let json = r#"["s1", "s2", "s3"]"#;
    let spec: SkillsSpec = serde_json::from_str(json).expect("de");
    let SkillsSpec::Paths(p) = spec else {
        panic!("MUST parse as Paths variant");
    };
    assert_eq!(p, vec!["s1", "s2", "s3"]);
}

#[test]
fn skills_spec_empty_paths_array_parses_as_empty_paths_variant() {
    let json = "[]";
    let spec: SkillsSpec = serde_json::from_str(json).expect("de");
    let SkillsSpec::Paths(p) = spec else {
        panic!("MUST parse as Paths variant");
    };
    assert!(p.is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Untagged enum disambiguation (no confusion between
// string and array variants)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn agents_spec_rejects_object_form_no_silent_fallthrough() {
    // Neither variant accepts an object — MUST error.
    let json = r#"{"path": "x"}"#;
    let outcome: Result<AgentsSpec, _> = serde_json::from_str(json);
    assert!(outcome.is_err());
}

#[test]
fn skills_spec_rejects_object_form_no_silent_fallthrough() {
    let json = r#"{"key": "value"}"#;
    let outcome: Result<SkillsSpec, _> = serde_json::from_str(json);
    assert!(outcome.is_err());
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — Clone semantics
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn mcp_server_config_clone_preserves_all_fields() {
    let original = McpServerConfig {
        command: Some("cmd".to_string()),
        args: vec!["a".to_string()],
        env: EnvironmentGrants::try_from(HashMap::from([("K".to_string(), "V".to_string())]))
            .expect("valid test environment"),
        transport: "http".to_string(),
        url: Some("https://x".to_string()),
        headers: SensitiveHeaders::try_from(HashMap::from([(
            "Authorization".to_string(),
            "Bearer token".to_string(),
        )]))
        .expect("valid test headers"),
        headers_helper: Some("/bin/headers".to_string()),
        timeout: Some(5000),
        always_load: Some(true),
    };
    let cloned = original.clone();
    assert_eq!(cloned.command, original.command);
    assert_eq!(cloned.args, original.args);
    assert_eq!(cloned.env.len(), original.env.len());
    assert_eq!(cloned.transport, original.transport);
    assert_eq!(cloned.url, original.url);
    assert_eq!(cloned.headers, original.headers);
    assert_eq!(cloned.headers_helper, original.headers_helper);
    assert_eq!(cloned.timeout, original.timeout);
    assert_eq!(cloned.always_load, original.always_load);
}

#[test]
fn lsp_server_config_clone_preserves_all_fields() {
    let original = LspServerConfig {
        command: "x".to_string(),
        args: vec!["a".to_string()],
        env: EnvironmentGrants::new(),
        extensions: vec!["rs".to_string()],
    };
    let cloned = original.clone();
    assert_eq!(cloned, original);
}
