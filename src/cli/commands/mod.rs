pub mod acp;
pub mod auth;
pub mod config_cmd;
pub mod doctor;
pub mod hooks;
pub mod init;
pub mod loop_cmd;
pub mod skills;
pub mod start;
pub mod team;

fn provider_api_key_env_var(provider_name: &str) -> &'static str {
    openclaudia::providers::api_key_env_var_for_target(provider_name)
}

fn can_start_without_api_key(provider_name: &str) -> bool {
    provider_name.eq_ignore_ascii_case("anthropic")
        || openclaudia::config::is_local_provider_name(provider_name)
}
