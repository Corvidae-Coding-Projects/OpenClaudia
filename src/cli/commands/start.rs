use openclaudia::{config, proxy};
use tracing::{error, info};

/// Start the proxy server
pub async fn cmd_start(
    port: Option<u16>,
    host: Option<String>,
    target: Option<String>,
) -> anyhow::Result<()> {
    if !config::config_file_exists() {
        error!("No configuration found. Run 'openclaudia init' first.");
        anyhow::bail!("no configuration found; run `openclaudia init` first");
    }

    let mut config = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse configuration: {}", e);
            eprintln!("Check your .openclaudia/config.yaml for syntax errors.");
            anyhow::bail!("invalid configuration: {e}");
        }
    };

    if let Some(p) = port {
        config.proxy.port = p;
    }
    if let Some(h) = host {
        config.proxy.host = h;
    }
    if let Some(t) = target {
        config.proxy.target = t;
    }

    let Some(provider) = config.active_provider() else {
        error!(
            "No provider configured for target '{}'",
            config.proxy.target
        );
        anyhow::bail!(
            "no provider configured for target '{}'",
            config.proxy.target
        );
    };

    if provider.api_key.is_none() {
        if config.proxy.target.eq_ignore_ascii_case("anthropic") {
            tracing::warn!(
                "No API key configured for '{}'. OAuth authentication is available.",
                config.proxy.target
            );
            info!(
                "Visit http://localhost:{}/auth/device to authenticate with Claude Max",
                config.proxy.port
            );
        } else if config::is_local_provider_name(&config.proxy.target) {
            info!(
                "No API key configured for local provider '{}'; continuing without auth headers.",
                config.proxy.target
            );
        } else {
            let env_var = super::provider_api_key_env_var(&config.proxy.target);
            error!(
                "No API key configured for provider '{}'. Set {} environment variable.",
                config.proxy.target, env_var
            );
            anyhow::bail!(
                "no API key configured for provider '{}'; set {} environment variable",
                config.proxy.target,
                env_var
            );
        }
    }

    info!("OpenClaudia v{} starting...", env!("CARGO_PKG_VERSION"));
    info!(
        "Proxy: http://{}:{} -> {}",
        config.proxy.host, config.proxy.port, config.proxy.target
    );
    info!(
        "Point your AI client at: http://localhost:{}",
        config.proxy.port
    );

    proxy::start_server(config).await
}
