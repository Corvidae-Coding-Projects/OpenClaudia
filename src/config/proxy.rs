use serde::Deserialize;

use crate::secrets::SecretString;

/// Exact acknowledgement required before binding the plaintext proxy listener
/// to a non-loopback interface.
pub const UNSAFE_EXTERNAL_BIND_ACKNOWLEDGEMENT: &str =
    "I acknowledge that this proxy listener has no native TLS";

/// Caller capabilities enforced at the HTTP admission boundary.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyClientScope {
    Inference,
    ModelsRead,
    StateRead,
    AuthManage,
    All,
}

/// One explicitly provisioned proxy caller.
#[derive(Debug, Deserialize, Clone)]
pub struct ProxyClientConfig {
    /// Stable tenant boundary for this caller. When omitted, the caller
    /// identity is also the tenant identity, preserving the single-principal
    /// S-092 configuration contract without creating an ambient tenant.
    #[serde(default)]
    pub tenant: Option<String>,
    /// Stable, non-secret identity sent in `x-openclaudia-client-id`.
    pub identity: String,
    /// HMAC key used to authenticate request metadata. This is distinct from
    /// every upstream provider credential.
    pub secret: SecretString,
    #[serde(default)]
    pub scopes: Vec<ProxyClientScope>,
    #[serde(default = "default_requests_per_minute")]
    pub requests_per_minute: u32,
    #[serde(default = "default_cost_units_per_minute")]
    pub cost_units_per_minute: u32,
}

impl ProxyClientConfig {
    /// Return the provisioned tenant boundary for this caller.
    #[must_use]
    pub(crate) fn tenant_identity(&self) -> &str {
        self.tenant.as_deref().unwrap_or(&self.identity)
    }

    #[must_use]
    pub(crate) fn allows_scope(&self, required: &str) -> bool {
        self.scopes.iter().any(|scope| {
            matches!(scope, ProxyClientScope::All)
                || matches!(
                    (scope, required),
                    (ProxyClientScope::Inference, "inference")
                        | (ProxyClientScope::ModelsRead, "models-read")
                        | (ProxyClientScope::StateRead, "state-read")
                        | (ProxyClientScope::AuthManage, "auth-manage")
                )
        })
    }
}

/// Replay and caller-admission policy for the proxy listener.
#[derive(Debug, Deserialize, Clone)]
pub struct ProxyAuthConfig {
    #[serde(default)]
    pub clients: Vec<ProxyClientConfig>,
    #[serde(default = "default_replay_window_secs")]
    pub replay_window_secs: u64,
    #[serde(default = "default_max_nonces_per_client")]
    pub max_nonces_per_client: usize,
    #[serde(default = "default_inference_cost_units")]
    pub inference_cost_units: u32,
}

impl Default for ProxyAuthConfig {
    fn default() -> Self {
        Self {
            clients: Vec::new(),
            replay_window_secs: default_replay_window_secs(),
            max_nonces_per_client: default_max_nonces_per_client(),
            inference_cost_units: default_inference_cost_units(),
        }
    }
}

/// Proxy server configuration
#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_target")]
    pub target: String,
    /// Maximum bytes read from an upstream response body before aborting.
    ///
    /// Guards against memory-exhaustion `DoS` from malicious or buggy
    /// upstreams that stream gigabytes of data. Default: 50 MiB — enough
    /// for any legitimate LLM response including thinking + tool-use
    /// tokens, two orders of magnitude below a typical attack threshold.
    /// See crosslink #352.
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
    /// Maximum bytes accepted from a proxy caller before JSON parsing.
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: usize,
    /// Explicit caller identities and bounded admission policy. An empty
    /// client list fails server startup and makes a directly-created router
    /// deny every protected route.
    #[serde(default)]
    pub auth: ProxyAuthConfig,
    /// Exact opt-in required for a non-loopback plaintext listener.
    #[serde(default)]
    pub unsafe_external_bind_acknowledgement: Option<String>,
    /// Additional exact browser origins allowed to call protected routes.
    /// Same-origin requests are always admitted to origin evaluation.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

pub const fn default_port() -> u16 {
    8080
}

/// Default bind address for the proxy server. Loopback by default —
/// users who need to bind 0.0.0.0 must do so explicitly via config.
pub const DEFAULT_HOST: &str = "127.0.0.1";

/// Default upstream provider when none is configured.
pub const DEFAULT_TARGET: &str = "anthropic";

pub fn default_host() -> String {
    DEFAULT_HOST.to_string()
}

pub fn default_target() -> String {
    DEFAULT_TARGET.to_string()
}

pub const fn default_max_response_bytes() -> usize {
    50 * 1024 * 1024
}

pub const fn default_max_request_bytes() -> usize {
    10 * 1024 * 1024
}

const fn default_requests_per_minute() -> u32 {
    60
}

const fn default_cost_units_per_minute() -> u32 {
    60
}

const fn default_replay_window_secs() -> u64 {
    30
}

const fn default_max_nonces_per_client() -> usize {
    256
}

const fn default_inference_cost_units() -> u32 {
    1
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            host: default_host(),
            target: default_target(),
            max_response_bytes: default_max_response_bytes(),
            max_request_bytes: default_max_request_bytes(),
            auth: ProxyAuthConfig::default(),
            unsafe_external_bind_acknowledgement: None,
            allowed_origins: Vec::new(),
        }
    }
}

impl ProxyConfig {
    #[must_use]
    pub(crate) fn has_unsafe_external_bind_acknowledgement(&self) -> bool {
        self.unsafe_external_bind_acknowledgement.as_deref()
            == Some(UNSAFE_EXTERNAL_BIND_ACKNOWLEDGEMENT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        // This test verifies defaults work without any config files
        let config = ProxyConfig::default();
        assert_eq!(config.port, 8080);
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.target, "anthropic");
        assert_eq!(config.max_response_bytes, 50 * 1024 * 1024);
        assert_eq!(config.max_request_bytes, 10 * 1024 * 1024);
        assert!(config.auth.clients.is_empty());
        assert_eq!(config.auth.replay_window_secs, 30);
        assert_eq!(config.auth.max_nonces_per_client, 256);
        assert_eq!(config.auth.inference_cost_units, 1);
        assert!(config.unsafe_external_bind_acknowledgement.is_none());
        assert!(config.allowed_origins.is_empty());
    }

    #[test]
    fn test_proxy_config_default_values() {
        let config = ProxyConfig::default();
        assert_eq!(config.port, default_port());
        assert_eq!(config.host, default_host());
        assert_eq!(config.target, default_target());
        assert_eq!(config.max_response_bytes, default_max_response_bytes());
        assert_eq!(config.max_request_bytes, default_max_request_bytes());
        assert!(config.auth.clients.is_empty());
        assert!(config.unsafe_external_bind_acknowledgement.is_none());
        assert!(config.allowed_origins.is_empty());
    }
}
