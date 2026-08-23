use openclaudia::config;

fn anthropic_oauth_unavailable_message(error: &str) -> String {
    format!(
        "No API key configured for 'anthropic', and Claude OAuth credentials are unavailable: {error}. Run 'openclaudia auth' or set ANTHROPIC_API_KEY."
    )
}

/// ACP server mode -- stdin/stdout JSON-RPC for acpx interoperability
pub async fn cmd_acp(
    target_override: Option<String>,
    model_override: Option<String>,
) -> anyhow::Result<()> {
    if !config::config_file_exists() {
        eprintln!("No configuration found. Run 'openclaudia init' first.");
        anyhow::bail!("no configuration found; run `openclaudia init` first");
    }

    let config = match config::load_config() {
        Ok(mut c) => {
            if let Some(ref target) = target_override {
                c.proxy.target.clone_from(target);
            } else if let Some(ref model) = model_override {
                let detected = openclaudia::proxy::determine_provider(model, &c);
                if detected != c.proxy.target {
                    c.proxy.target = detected;
                }
            }
            c
        }
        Err(e) => {
            eprintln!("Failed to parse configuration: {e}");
            eprintln!("Check your .openclaudia/config.yaml for syntax errors.");
            anyhow::bail!("invalid configuration: {e}");
        }
    };

    let target = config.proxy.target.clone();
    let Some(provider) = config.active_provider() else {
        eprintln!("No provider configured for target '{target}'");
        anyhow::bail!("no provider configured for target '{target}'");
    };
    let provider_api_key = provider.api_key.clone();
    let provider_model = provider.model.clone();

    let (api_key, claude_code_token, codex_responses_auth) = if let Some(k) = provider_api_key {
        (Some(k), None, None)
    } else if target.eq_ignore_ascii_case("anthropic") {
        match openclaudia::claude_credentials::load_credentials().await {
            Ok(creds) => (None, Some(creds.access_token), None),
            Err(e) => {
                let msg = anthropic_oauth_unavailable_message(&e);
                eprintln!("{msg}");
                anyhow::bail!(msg);
            }
        }
    } else if target.eq_ignore_ascii_case("openai") {
        match openclaudia::codex_credentials::load_codex_auth() {
            Ok(Some(openclaudia::codex_credentials::CodexAuthMaterial::ApiKey {
                api_key, ..
            })) => (Some(api_key), None, None),
            Ok(Some(openclaudia::codex_credentials::CodexAuthMaterial::Responses(auth))) => {
                (None, None, Some(auth))
            }
            Ok(Some(openclaudia::codex_credentials::CodexAuthMaterial::Unsupported {
                mode,
                ..
            })) => {
                anyhow::bail!(
                    "{} is not supported by OpenClaudia ACP",
                    mode.display_name()
                );
            }
            Ok(None) => {
                anyhow::bail!(
                    "no OpenAI credentials are configured for ACP; set OPENAI_API_KEY or run `codex login`"
                );
            }
            Err(error) => anyhow::bail!("could not load Codex credentials for ACP: {error}"),
        }
    } else if config::is_local_provider_name(&target) {
        (None, None, None)
    } else {
        let env_var = super::provider_api_key_env_var(&target);
        eprintln!("No API key configured for '{target}'. Set {env_var} or add to config.");
        anyhow::bail!("no API key configured for '{target}'; set {env_var} or add to config");
    };

    let model = model_override
        .or(provider_model)
        .unwrap_or_else(|| openclaudia::providers::default_model_for_target(&target).to_string());

    openclaudia::acp::run_acp_server(
        config,
        model,
        api_key,
        claude_code_token,
        codex_responses_auth,
    )
    .await
}
