use openclaudia::{
    claude_credentials, config,
    mcp::McpManager,
    pipeline,
    plugins::PluginManager,
    providers::{get_adapter, ProviderAdapter, ProviderError},
    session::SessionManager,
};
use std::path::PathBuf;
use std::time::Duration;
use tracing::info;

const DOCTOR_ADAPTER_PROVIDER: &str = "anthropic";

#[derive(Debug, PartialEq, Eq)]
enum ActiveProviderAuthRequirement {
    ConfiguredApiKey,
    NotRequiredForLocal,
    AnthropicCanUseClaudeCode,
    MissingApiKey { env_var: &'static str },
}

struct DoctorResolvedAuth {
    auth_ok: bool,
    claude_code_token: Option<String>,
}

fn lookup_doctor_adapter(
    provider_name: &str,
) -> Result<&'static dyn ProviderAdapter, ProviderError> {
    get_adapter(provider_name)
}

fn provider_api_key_env_var(provider_name: &str) -> &'static str {
    openclaudia::providers::api_key_env_var_for_target(provider_name)
}

fn active_provider_auth_requirement(
    provider_name: &str,
    provider: &config::ProviderConfig,
) -> ActiveProviderAuthRequirement {
    if provider.api_key.is_some() {
        return ActiveProviderAuthRequirement::ConfiguredApiKey;
    }

    if config::is_local_provider_name(provider_name) {
        return ActiveProviderAuthRequirement::NotRequiredForLocal;
    }

    if provider_name.eq_ignore_ascii_case("anthropic") {
        return ActiveProviderAuthRequirement::AnthropicCanUseClaudeCode;
    }

    ActiveProviderAuthRequirement::MissingApiKey {
        env_var: provider_api_key_env_var(provider_name),
    }
}

async fn check_active_provider_auth(
    provider_name: &str,
    provider: &config::ProviderConfig,
) -> DoctorResolvedAuth {
    print!("\nActive provider auth... ");
    match active_provider_auth_requirement(provider_name, provider) {
        ActiveProviderAuthRequirement::ConfiguredApiKey => {
            println!("configured");
            DoctorResolvedAuth {
                auth_ok: true,
                claude_code_token: None,
            }
        }
        ActiveProviderAuthRequirement::NotRequiredForLocal => {
            println!("not required for local provider");
            DoctorResolvedAuth {
                auth_ok: true,
                claude_code_token: None,
            }
        }
        ActiveProviderAuthRequirement::AnthropicCanUseClaudeCode => {
            if !claude_credentials::has_claude_code_credentials() {
                println!(
                    "FAILED (no API key or Claude Code credentials; set ANTHROPIC_API_KEY or run `claude`)"
                );
                return DoctorResolvedAuth {
                    auth_ok: false,
                    claude_code_token: None,
                };
            }

            match claude_credentials::load_credentials().await {
                Ok(creds) => {
                    println!(
                        "Claude Code credentials OK ({}, {})",
                        creds.subscription_type.as_deref().unwrap_or("unknown"),
                        creds.rate_limit_tier.as_deref().unwrap_or("default")
                    );
                    DoctorResolvedAuth {
                        auth_ok: true,
                        claude_code_token: Some(creds.access_token),
                    }
                }
                Err(err) => {
                    println!("FAILED (Claude Code credentials unusable: {err})");
                    DoctorResolvedAuth {
                        auth_ok: false,
                        claude_code_token: None,
                    }
                }
            }
        }
        ActiveProviderAuthRequirement::MissingApiKey { env_var } => {
            println!("FAILED (set {env_var} or configure providers.{provider_name}.api_key)");
            DoctorResolvedAuth {
                auth_ok: false,
                claude_code_token: None,
            }
        }
    }
}

fn doctor_model_for_provider(provider_name: &str, provider: &config::ProviderConfig) -> String {
    provider.model.clone().unwrap_or_else(|| {
        openclaudia::providers::default_model_for_target(provider_name).to_string()
    })
}

fn resolve_doctor_endpoint(
    provider_name: &str,
    provider: &config::ProviderConfig,
    claude_code_token: Option<&str>,
) -> Result<String, ProviderError> {
    let model = doctor_model_for_provider(provider_name, provider);
    pipeline::resolve_endpoint(provider_name, &model, &provider.base_url, claude_code_token)
}

fn doctor_http_status_is_reachable(status: reqwest::StatusCode) -> bool {
    if status.is_server_error() {
        return false;
    }
    !matches!(
        status,
        reqwest::StatusCode::UNAUTHORIZED
            | reqwest::StatusCode::FORBIDDEN
            | reqwest::StatusCode::NOT_FOUND
    )
}

#[allow(clippy::too_many_lines)]
/// Check configuration and connectivity
pub async fn cmd_doctor() -> anyhow::Result<()> {
    println!("OpenClaudia Doctor\n");

    let mut has_failures = false;

    let sandbox = openclaudia::tools::sandbox_diagnostics();
    println!(
        "Agent sandbox... {}",
        if sandbox.healthy { "OK" } else { "FAILED" }
    );
    println!("  Backend: {}", sandbox.backend);
    println!("  Detail: {}", sandbox.detail);
    println!("  Network: {}", sandbox.network);
    println!("  Syscall policy: {}", sandbox.syscall_filter);
    println!("  Resource limits: {}", sandbox.resource_limits);
    println!(
        "  Capability roots: {} read-only, {} read-write",
        sandbox.read_only_root_count, sandbox.read_write_root_count
    );
    println!(
        "  Explicit environment grants: {} variable name(s), values redacted",
        sandbox.environment_grant_count
    );
    if sandbox.explicit_host_opt_out {
        println!("  WARNING: host operator explicitly disabled process isolation");
    }
    has_failures |= !sandbox.healthy;

    // Check configuration
    print!("Configuration... ");
    let loaded_config = if config::config_file_exists() {
        match config::load_config() {
            Ok(config) => {
                println!("OK");

                for (name, provider) in &config.providers {
                    print!("  {name} API key... ");
                    if provider.api_key.is_some() {
                        println!("configured");
                    } else {
                        println!("NOT SET");
                    }
                    if let Some(model) = &provider.model {
                        println!("    Default model: {model}");
                    }
                }

                Some(config)
            }
            Err(e) => {
                println!("FAILED: {e}");
                println!(
                    "\nConfig file exists but has errors. Check your .openclaudia/config.yaml for syntax errors."
                );
                has_failures = true;
                None
            }
        }
    } else {
        println!("MISSING (No configuration found)");
        println!("\nRun 'openclaudia init' to create a configuration file.");
        has_failures = true;
        None
    };

    if let Some(config) = &loaded_config {
        if let Some(provider) = config.active_provider() {
            let auth = check_active_provider_auth(&config.proxy.target, provider).await;
            if auth.auth_ok {
                print!("\nEndpoint reachability for {}... ", config.proxy.target);
                match resolve_doctor_endpoint(
                    &config.proxy.target,
                    provider,
                    auth.claude_code_token.as_deref(),
                ) {
                    Ok(endpoint) => {
                        let extra_headers: Vec<(String, String)> = provider
                            .headers
                            .iter()
                            .map(|(key, value)| (key.clone(), value.clone()))
                            .collect();
                        match pipeline::resolve_headers(
                            &config.proxy.target,
                            provider.api_key.as_ref(),
                            auth.claude_code_token.as_deref(),
                            &extra_headers,
                        ) {
                            Ok(headers) => {
                                let client = reqwest::Client::builder()
                                    .timeout(Duration::from_secs(5))
                                    .build()?;
                                let mut request = client.get(&endpoint);
                                for (key, value) in &headers {
                                    request = request.header(key, value);
                                }
                                match request.send().await {
                                    Ok(response) => {
                                        let status = response.status();
                                        if doctor_http_status_is_reachable(status) {
                                            println!("OK (HTTP {status})");
                                        } else {
                                            println!("FAILED (HTTP {status})");
                                            has_failures = true;
                                        }
                                    }
                                    Err(e) => {
                                        println!("FAILED: {e}");
                                        has_failures = true;
                                    }
                                }
                            }
                            Err(err) => {
                                println!("FAILED (header resolution: {err})");
                                has_failures = true;
                            }
                        }
                    }
                    Err(err) => {
                        println!("FAILED (endpoint resolution: {err})");
                        has_failures = true;
                    }
                }
            } else {
                has_failures = true;
                println!(
                    "\nEndpoint reachability for {}... SKIPPED (auth failed)",
                    config.proxy.target
                );
            }
        } else {
            println!("FAILED (no provider configured)");
            has_failures = true;
        }
    }

    // Check for hooks directory
    print!("\nHooks directory... ");
    if PathBuf::from(".openclaudia/hooks").exists() {
        println!("OK");
    } else {
        println!("NOT FOUND");
    }

    // Check plugins
    print!("\nPlugins... ");
    // crosslink #893: try_new surfaces missing-$HOME loudly in `doctor`
    // since that is the exact UX a confused user is checking.
    let mut plugin_manager = match PluginManager::try_new() {
        Ok(pm) => pm,
        Err(e) => {
            println!("WARN ({e}); using project-only search");
            PluginManager::new()
        }
    };
    let errors = plugin_manager.discover();
    if plugin_manager.count() > 0 {
        println!("OK ({} loaded)", plugin_manager.count());
        for plugin in plugin_manager.all() {
            let root = plugin.root();
            println!(
                "  - {} v{} ({})",
                plugin.name(),
                plugin.manifest.version.as_deref().unwrap_or("0.0.0"),
                root.display()
            );

            let env_vars = plugin.env_vars();
            if !env_vars.is_empty() {
                println!("    Environment: {} vars", env_vars.len());
            }

            let resolved_cmds = plugin.resolved_commands();
            if !resolved_cmds.is_empty() {
                println!("    Commands: {}", resolved_cmds.len());
                for cmd in &resolved_cmds {
                    let desc = cmd.description.as_deref().unwrap_or("(no description)");
                    let extras = [
                        cmd.argument_hint.as_ref().map(|h| format!("args: {h}")),
                        cmd.model.as_ref().map(|m| format!("model: {m}")),
                        cmd.allowed_tools
                            .as_ref()
                            .map(|t| format!("tools: {}", t.len())),
                    ]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();

                    if extras.is_empty() {
                        println!("      /{} - {}", cmd.name, desc);
                    } else {
                        println!("      /{} - {} [{}]", cmd.name, desc, extras.join(", "));
                    }
                }
            }

            if !plugin.mcp_configs.is_empty() {
                println!("    MCP servers: {}", plugin.mcp_configs.len());
            }
        }

        let all_mcp = plugin_manager.all_mcp_servers();
        if !all_mcp.is_empty() {
            println!("\n  MCP Servers from plugins:");
            for (plugin, server) in all_mcp {
                let effective_permissions = if server.transport == "stdio" {
                    format!(
                        "trust=required, profile=mcp-stdio, network=denied, env-grants={}",
                        server.env.len()
                    )
                } else {
                    format!(
                        "trust=required, brokered transport, header-grants={}",
                        server.headers.len()
                    )
                };
                println!(
                    "    - {} from {} ({}; {})",
                    server.name,
                    plugin.name(),
                    server.transport,
                    effective_permissions
                );
            }
        }

        for plugin in plugin_manager.all() {
            let resolved = plugin.resolve_path("scripts/init.sh");
            info!(
                "Plugin {} script path: {}",
                plugin.name(),
                resolved.display()
            );
        }
    } else if !errors.is_empty() {
        println!("ERRORS");
        for err in errors {
            println!("  Error: {err}");
        }
        has_failures = true;
    } else {
        println!("none found");
    }

    // Test MCP manager functionality
    print!("\nMCP Manager... ");
    let mcp_manager = McpManager::new();

    let is_connected = mcp_manager.is_connected("test-server").await;
    println!(
        "{}",
        if is_connected {
            "connected"
        } else {
            "no servers"
        }
    );

    if let Some((name, supports_list_changed)) = mcp_manager.get_server_info("test-server").await {
        println!("  Server: {name} (list_changed: {supports_list_changed})");
    }

    // Check session state
    print!("\nSession... ");
    let session_dir = PathBuf::from(".openclaudia/session");
    if session_dir.exists() {
        let session_manager = SessionManager::new(&session_dir);
        match session_manager.get_handoff_context() {
            Ok(Some(handoff)) => println!("found handoff context ({} bytes)", handoff.len()),
            Ok(None) => {}
            Err(err) => {
                println!("handoff unreadable: {err}");
                has_failures = true;
            }
        }

        let sessions = session_manager.list_sessions();
        if sessions.is_empty() {
            println!("  No previous sessions");
        } else {
            println!("  Previous sessions: {}", sessions.len());
            for session in sessions.iter().take(3) {
                println!(
                    "    - {} ({:?}, {} requests)",
                    session.id, session.mode, session.request_count
                );
            }
            if sessions.len() > 10 {
                println!("  Note: Consider running cleanup (>10 sessions stored)");
            }
        }
    } else {
        println!("  No previous sessions");
    }

    // Test provider adapters and error variants
    print!("\nProvider adapters... ");
    match lookup_doctor_adapter(DOCTOR_ADAPTER_PROVIDER) {
        Ok(adapter) => {
            println!("{} adapter OK", adapter.name());

            let test_response = serde_json::json!({
                "id": "test",
                "content": [{"type": "text", "text": "test"}],
                "model": "test-model",
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 10, "output_tokens": 5}
            });
            match adapter.transform_response(test_response, false) {
                Ok(transformed) => info!("Response transformed: {}", transformed["object"]),
                Err(e) => info!("Transform error (expected): {}", e),
            }
        }
        Err(e) => {
            println!("FAILED: {e}");
            info!("Provider adapter lookup failed: {}", e);
            has_failures = true;
        }
    }

    let custom_paths = vec![PathBuf::from(".openclaudia/plugins")];
    let mut custom_plugin_manager = PluginManager::with_paths(custom_paths);
    let _ = custom_plugin_manager.discover();
    info!(
        "Custom plugin manager: {} plugins",
        custom_plugin_manager.count()
    );

    if let Some(plugin) = custom_plugin_manager.get("test-plugin") {
        info!("Found plugin: {}", plugin.name());
    }

    let all_hooks = custom_plugin_manager.all_hooks();
    info!("All hooks: {}", all_hooks.len());

    let session_hooks = custom_plugin_manager.hooks_for_event("session_start");
    info!("Session start hooks: {}", session_hooks.len());

    let reload_errors = custom_plugin_manager.reload();
    info!("Plugin reload: {} errors", reload_errors.len());

    println!("\nDoctor check complete.");
    if has_failures {
        anyhow::bail!("doctor found one or more failures");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openclaudia::providers::ApiKey;
    use std::collections::HashMap;

    fn provider_with_key(api_key: Option<ApiKey>) -> config::ProviderConfig {
        config::ProviderConfig {
            api_key,
            base_url: "https://api.example.com".to_string(),
            model: None,
            headers: HashMap::new(),
            thinking: config::ThinkingConfig::default(),
        }
    }

    #[test]
    fn lookup_doctor_adapter_resolves_builtin_provider() {
        let adapter = lookup_doctor_adapter(DOCTOR_ADAPTER_PROVIDER).expect("doctor provider");
        assert_eq!(adapter.name(), "anthropic");
    }

    #[test]
    fn lookup_doctor_adapter_returns_provider_errors() {
        match lookup_doctor_adapter("missing-provider") {
            Ok(adapter) => panic!("unexpected adapter {}", adapter.name()),
            Err(ProviderError::UnknownProvider { name, supported }) => {
                assert_eq!(name, "missing-provider");
                assert!(supported.contains(&"anthropic"));
            }
            Err(err) => panic!("unexpected provider error: {err}"),
        }
    }

    #[test]
    fn active_provider_auth_accepts_configured_api_key() {
        let api_key = ApiKey::try_from_string("sk-test-key".to_string()).expect("valid key");
        assert_eq!(
            active_provider_auth_requirement("openai", &provider_with_key(Some(api_key))),
            ActiveProviderAuthRequirement::ConfiguredApiKey
        );
    }

    #[test]
    fn active_provider_auth_allows_keyless_local_providers() {
        for provider in [
            "ollama",
            "local",
            "lmstudio",
            "localai",
            "text-generation-webui",
        ] {
            assert_eq!(
                active_provider_auth_requirement(provider, &provider_with_key(None)),
                ActiveProviderAuthRequirement::NotRequiredForLocal,
                "local provider {provider} must not require a remote API key"
            );
        }
    }

    #[test]
    fn active_provider_auth_flags_missing_remote_api_key() {
        assert_eq!(
            active_provider_auth_requirement("openai", &provider_with_key(None)),
            ActiveProviderAuthRequirement::MissingApiKey {
                env_var: "OPENAI_API_KEY"
            }
        );
        assert_eq!(
            active_provider_auth_requirement("moonshot", &provider_with_key(None)),
            ActiveProviderAuthRequirement::MissingApiKey {
                env_var: "KIMI_API_KEY or MOONSHOT_API_KEY"
            }
        );
        assert_eq!(
            active_provider_auth_requirement("minimax", &provider_with_key(None)),
            ActiveProviderAuthRequirement::MissingApiKey {
                env_var: "MINIMAX_API_KEY"
            }
        );
    }

    #[test]
    fn active_provider_auth_routes_keyless_anthropic_to_claude_code_check() {
        assert_eq!(
            active_provider_auth_requirement("anthropic", &provider_with_key(None)),
            ActiveProviderAuthRequirement::AnthropicCanUseClaudeCode
        );
    }

    #[test]
    fn doctor_model_for_provider_prefers_configured_model() {
        let mut provider = provider_with_key(None);
        provider.model = Some("custom-model".to_string());
        assert_eq!(
            doctor_model_for_provider("openai", &provider),
            "custom-model"
        );
    }

    #[test]
    fn doctor_model_for_provider_uses_shared_target_default() {
        assert_eq!(
            doctor_model_for_provider("google", &provider_with_key(None)),
            "gemini-3.5-flash"
        );
        assert_eq!(
            doctor_model_for_provider("unknown-target", &provider_with_key(None)),
            openclaudia::providers::DEFAULT_MODEL_FALLBACK
        );
    }

    #[test]
    fn resolve_doctor_endpoint_uses_adapter_endpoint() {
        let provider = provider_with_key(None);
        let endpoint = resolve_doctor_endpoint("google", &provider, None).expect("google endpoint");
        assert_eq!(
            endpoint,
            "https://api.example.com/v1beta/models/gemini-3.5-flash:generateContent"
        );
    }

    #[test]
    fn resolve_doctor_endpoint_uses_oauth_endpoint_when_token_present() {
        let mut provider = provider_with_key(None);
        provider.model = Some("claude-opus-4-8".to_string());
        let endpoint =
            resolve_doctor_endpoint("anthropic", &provider, Some("token")).expect("oauth endpoint");
        assert_eq!(endpoint, "https://api.anthropic.com/v1/messages");
    }

    #[test]
    fn doctor_http_status_classification_matches_endpoint_probe_contract() {
        assert!(doctor_http_status_is_reachable(reqwest::StatusCode::OK));
        assert!(doctor_http_status_is_reachable(
            reqwest::StatusCode::METHOD_NOT_ALLOWED
        ));
        assert!(doctor_http_status_is_reachable(
            reqwest::StatusCode::TOO_MANY_REQUESTS
        ));
        assert!(!doctor_http_status_is_reachable(
            reqwest::StatusCode::UNAUTHORIZED
        ));
        assert!(!doctor_http_status_is_reachable(
            reqwest::StatusCode::FORBIDDEN
        ));
        assert!(!doctor_http_status_is_reachable(
            reqwest::StatusCode::NOT_FOUND
        ));
        assert!(!doctor_http_status_is_reachable(
            reqwest::StatusCode::BAD_GATEWAY
        ));
    }
}
