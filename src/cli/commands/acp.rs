use openclaudia::config;

fn anthropic_auth_unavailable_message(error: impl std::fmt::Display) -> String {
    format!(
        "No API key configured for 'anthropic', and the Claude Agent SDK login is unavailable: {error}. Install Claude Code and run 'claude auth login', or set ANTHROPIC_API_KEY."
    )
}

/// ACP server mode -- stdin/stdout JSON-RPC for acpx interoperability
#[allow(clippy::too_many_lines)] // Startup keeps provider selection and its one auth carrier together.
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

    let (api_key, claude_code_token, claude_agent_sdk, codex_agent_sdk) = if let Some(k) =
        provider_api_key
    {
        (Some(k), None, None, None)
    } else if target.eq_ignore_ascii_case("anthropic") {
        if openclaudia::claude_credentials::experimental_direct_subscription_enabled() {
            match openclaudia::claude_credentials::load_credentials() {
                Ok(creds) => (None, Some(creds.access_token), None, None),
                Err(error) => {
                    let msg = format!(
                        "Experimental direct Claude subscription credentials are unavailable: {error}"
                    );
                    eprintln!("{msg}");
                    anyhow::bail!(msg);
                }
            }
        } else {
            let sdk = openclaudia::claude_agent_sdk::ClaudeAgentSdk::discover()
                .map_err(|error| anyhow::anyhow!(anthropic_auth_unavailable_message(error)))?;
            if let Err(error) = sdk.require_authenticated().await {
                let msg = anthropic_auth_unavailable_message(error);
                eprintln!("{msg}");
                anyhow::bail!(msg);
            }
            (None, None, Some(sdk), None)
        }
    } else if target.eq_ignore_ascii_case("openai") {
        let sdk =
            openclaudia::codex_agent_sdk::CodexAgentSdk::discover().map_err(anyhow::Error::new)?;
        sdk.require_authenticated()
            .await
            .map_err(anyhow::Error::new)?;
        (None, None, None, Some(sdk))
    } else if config::is_local_provider_name(&target) {
        (None, None, None, None)
    } else {
        let env_var = super::provider_api_key_env_var(&target);
        eprintln!("No API key configured for '{target}'. Set {env_var} or add to config.");
        anyhow::bail!("no API key configured for '{target}'; set {env_var} or add to config");
    };

    let model = model_override
        .or(provider_model)
        .or_else(|| {
            openclaudia::providers::default_model_for_target(&target).map(str::to_string)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "provider '{target}' has no configured model; set providers.{target}.model or pass --model"
            )
        })?;

    openclaudia::acp::run_acp_server(
        config,
        model,
        api_key,
        claude_code_token,
        claude_agent_sdk,
        codex_agent_sdk,
    )
    .await
}
