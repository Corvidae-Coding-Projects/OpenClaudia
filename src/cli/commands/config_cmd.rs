use openclaudia::config;
use tracing::{error, info};

/// Show current configuration
pub fn cmd_config() -> anyhow::Result<()> {
    if !config::config_file_exists() {
        error!("No configuration found.");
        info!("Run 'openclaudia init' to create a configuration file.");
        anyhow::bail!("no configuration found; run `openclaudia init` first");
    }

    match config::load_config() {
        Ok(config) => {
            println!("OpenClaudia Configuration\n");
            println!("Proxy:");
            println!("  Host: {}", config.proxy.host);
            println!("  Port: {}", config.proxy.port);
            println!("  Target: {}", config.proxy.target);
            println!();
            println!("Providers:");
            for (name, provider) in &config.providers {
                let has_key = provider.api_key.is_some();
                println!(
                    "  {}: {} (API key: {})",
                    name,
                    provider.base_url,
                    if has_key { "configured" } else { "not set" }
                );
            }
            println!();
            println!("Session:");
            println!("  Timeout: {} minutes", config.session.timeout_minutes);
            println!("  Persist path: {}", config.session.persist_path.display());
            println!();
            println!("Technical memory:");
            println!(
                "  Team: {}",
                config
                    .memory
                    .team_id
                    .as_ref()
                    .map_or("not selected", openclaudia::team_memory::TeamId::as_str)
            );
            Ok(())
        }
        Err(e) => {
            error!("Failed to parse configuration: {}", e);
            info!("Check your .openclaudia/config.yaml for syntax errors.");
            anyhow::bail!("invalid configuration: {e}");
        }
    }
}
