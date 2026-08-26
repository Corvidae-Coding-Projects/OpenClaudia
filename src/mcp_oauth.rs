//! MCP OAuth authorization lifecycle.
//!
//! [`McpOAuthManager`] owns protected-resource and authorization-server
//! discovery, PKCE/state-bound pending grants, protected token persistence,
//! serialized refresh, rotation, expiry, scope binding, and revocation for
//! one HTTP MCP server. It deliberately does not share state with provider
//! login, and it never launches a browser or captures a redirect on its own;
//! host frontends own those visible user interactions through the manager API.
//!
//! The older consuming [`OAuthFlow`] state machine remains public for source
//! compatibility and focused transition tests.

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Errors surfaced by the OAuth state machine.
#[derive(Debug, Error)]
pub enum OAuthError {
    /// A transition method was called on a state from which it is not
    /// reachable (e.g. `complete_exchange` on `Idle`). Indicates a logic
    /// bug in the caller, not a runtime failure.
    #[error("invalid OAuth transition from state `{from}` via `{action}`")]
    InvalidTransition {
        /// Name of the source state.
        from: &'static str,
        /// Name of the attempted transition method.
        action: &'static str,
    },
    /// The authorization-server response did not carry the expected fields
    /// or the values were structurally malformed (e.g. negative `expires_in`).
    #[error("malformed authorization-server response: {0}")]
    Malformed(String),
    /// The `state` returned by the redirect did not match the value we sent
    /// in the authorize URL. CSRF or response-mixing — flow MUST abort.
    #[error("state-token mismatch")]
    StateMismatch {},
}

/// OAuth token bundle.
///
/// Mirrors the RFC 6749 token-endpoint response with one OC-local field
/// (`obtained_at`) that lets `is_expired` compute its answer without
/// trusting the caller to also remember when the bundle was issued.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenBundle {
    /// Bearer access token (the value that goes in `Authorization: Bearer`).
    pub access_token: crate::secrets::OAuthToken,
    /// Refresh token, present when the server issued one. Absent for
    /// flows that opted out of refresh (`offline_access` not requested).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<crate::secrets::OAuthToken>,
    /// Token lifetime in seconds, as reported by the token endpoint.
    pub expires_in_secs: u64,
    /// UNIX epoch seconds at which this bundle was obtained — combined with
    /// `expires_in_secs` to compute the absolute expiry instant.
    pub obtained_at: u64,
    /// Token type — almost always `"Bearer"`. Stored so we can refuse
    /// non-Bearer responses at the boundary instead of silently misusing
    /// them downstream.
    #[serde(default = "default_token_type")]
    pub token_type: String,
    /// Granted scopes, space-joined into a single string per RFC 6749 §3.3.
    /// Empty string when the server did not echo a `scope` field.
    #[serde(default)]
    pub scope: String,
}

fn default_token_type() -> String {
    "Bearer".to_string()
}

impl TokenBundle {
    /// Current UNIX epoch in seconds. Centralised so tests can swap it
    /// later via a clock abstraction without touching call sites.
    fn now_epoch() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    /// Absolute expiry instant in UNIX epoch seconds.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.obtained_at.saturating_add(self.expires_in_secs)
    }

    /// Has this bundle already expired against the wall clock?
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Self::now_epoch() >= self.expires_at()
    }

    /// Should we proactively refresh this bundle?
    ///
    /// Returns `true` when the bundle is within `safety_window` of expiry —
    /// the typical caller passes `Duration::from_secs(60)` so the refresh
    /// happens a minute before the upstream rejects.
    #[must_use]
    pub fn needs_refresh(&self, safety_window: Duration) -> bool {
        let now = Self::now_epoch();
        self.expires_at().saturating_sub(safety_window.as_secs()) <= now
    }
}

/// Configuration provided at flow construction.
///
/// `client_id` and the endpoints are the only required values; the rest
/// have sensible defaults documented per field.
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// OAuth client identifier registered with the `IdP`.
    pub client_id: String,
    /// Optional client secret. Modern public clients (single-tenant MCP
    /// servers, `IdP` confidential clients running outside this process)
    /// usually omit it and rely on PKCE.
    pub client_secret: Option<crate::secrets::SecretString>,
    /// `IdP` authorization-endpoint URL.
    pub authorize_url: String,
    /// `IdP` token-endpoint URL.
    pub token_url: String,
    /// Redirect `URI` registered with the `IdP` — typically a loopback URL
    /// (`http://127.0.0.1:<port>/cb`) that the local listener serves.
    pub redirect_uri: String,
    /// Requested scopes; passed verbatim to the authorize URL.
    pub scopes: Vec<String>,
}

/// PKCE pair — `code_verifier` stays in memory until exchange, `challenge`
/// goes on the wire in the authorize URL.
#[derive(Debug, Clone)]
pub struct PkcePair {
    /// Opaque high-entropy string the `IdP` echoes back at the token endpoint.
    pub code_verifier: crate::secrets::SecretString,
    /// `BASE64URL(SHA256(code_verifier))` — sent in the authorize URL.
    pub code_challenge: String,
    /// Always `"S256"` in this codebase; `plain` is forbidden.
    pub method: &'static str,
}

/// State-machine variants. See module docs for the transition graph.
#[derive(Debug, Clone)]
pub enum OAuthFlow {
    /// Pre-flight: no authorize URL has been built yet.
    Idle { config: OAuthConfig },
    /// `start_authorization` has been called — the user is being redirected
    /// to the `IdP`. Stores everything needed to verify the redirect when it
    /// returns: `state` nonce, `code_verifier`, original config.
    AwaitingAuthorization {
        config: OAuthConfig,
        state: crate::secrets::SecretString,
        pkce: PkcePair,
    },
    /// `accept_redirect` has been called — we have the authorization code
    /// and are about to call the token endpoint.
    Exchanging {
        config: OAuthConfig,
        pkce: PkcePair,
        code: crate::secrets::SecretString,
    },
    /// Token-endpoint exchange succeeded.
    Authorized {
        config: OAuthConfig,
        token: TokenBundle,
    },
    /// Terminal failure state. The error is preserved so callers can render
    /// it to the user; the flow is consumed (no further transitions).
    Failed {
        reason: crate::secrets::SafeDiagnostic,
    },
}

impl OAuthFlow {
    /// Build a fresh `Idle` flow from configuration.
    #[must_use]
    pub const fn new(config: OAuthConfig) -> Self {
        Self::Idle { config }
    }

    /// Human-readable state name for logging / error messages.
    #[must_use]
    pub const fn state_name(&self) -> &'static str {
        match self {
            Self::Idle { .. } => "Idle",
            Self::AwaitingAuthorization { .. } => "AwaitingAuthorization",
            Self::Exchanging { .. } => "Exchanging",
            Self::Authorized { .. } => "Authorized",
            Self::Failed { .. } => "Failed",
        }
    }

    /// Transition `Idle` → `AwaitingAuthorization`.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::InvalidTransition`] when called on any state
    /// other than `Idle`, or [`OAuthError::Malformed`] when the state token is
    /// structurally invalid.
    ///
    /// The caller supplies the `state` nonce and PKCE pair — generation of
    /// those values lives in the (forthcoming) transport submodule because
    /// it needs a CSPRNG. Keeping it out of this layer lets the state-
    /// machine tests use deterministic stub values.
    pub fn start_authorization(self, state: String, pkce: PkcePair) -> Result<Self, OAuthError> {
        let Self::Idle { config } = self else {
            return Err(OAuthError::InvalidTransition {
                from: self.state_name(),
                action: "start_authorization",
            });
        };
        let state = crate::secrets::SecretString::try_from_string(state)
            .map_err(|error| OAuthError::Malformed(format!("invalid state token: {error}")))?;
        Ok(Self::AwaitingAuthorization {
            config,
            state,
            pkce,
        })
    }

    /// Transition `AwaitingAuthorization` → `Exchanging`.
    ///
    /// Verifies the redirect-supplied `state` matches the value we issued.
    /// A mismatch is a hard error — the flow MUST NOT proceed to the token
    /// endpoint with the supplied code because that code might belong to a
    /// different session (CSRF or response-mixing attack).
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::InvalidTransition`] when called outside the
    /// `AwaitingAuthorization` state, or [`OAuthError::StateMismatch`]
    /// when `returned_state` does not match the value issued at
    /// [`Self::start_authorization`].
    pub fn accept_redirect(self, returned_state: &str, code: String) -> Result<Self, OAuthError> {
        let Self::AwaitingAuthorization {
            config,
            state,
            pkce,
        } = self
        else {
            return Err(OAuthError::InvalidTransition {
                from: self.state_name(),
                action: "accept_redirect",
            });
        };
        if !state.matches(returned_state) {
            return Err(OAuthError::StateMismatch {});
        }
        let code = crate::secrets::SecretString::try_from_string(code).map_err(|error| {
            OAuthError::Malformed(format!("invalid authorization code: {error}"))
        })?;
        Ok(Self::Exchanging { config, pkce, code })
    }

    /// Transition `Exchanging` → `Authorized`.
    ///
    /// `token` is whatever the (forthcoming) HTTP transport returns from
    /// the token endpoint. We validate basic structural invariants here
    /// so a malformed response cannot land an `Authorized` state with
    /// nonsensical values: `token_type` must be `Bearer`, `expires_in`
    /// must be positive, `access_token` must be non-empty.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::InvalidTransition`] when called outside the
    /// `Exchanging` state, or [`OAuthError::Malformed`] when the supplied
    /// `token` violates one of the structural invariants above.
    pub fn complete_exchange(self, token: TokenBundle) -> Result<Self, OAuthError> {
        let Self::Exchanging { config, .. } = self else {
            return Err(OAuthError::InvalidTransition {
                from: self.state_name(),
                action: "complete_exchange",
            });
        };
        if !token.token_type.eq_ignore_ascii_case("Bearer") {
            return Err(OAuthError::Malformed(
                "unsupported token_type (only Bearer is accepted)".to_string(),
            ));
        }
        if token.expires_in_secs == 0 {
            return Err(OAuthError::Malformed(
                "expires_in_secs was zero".to_string(),
            ));
        }
        Ok(Self::Authorized { config, token })
    }

    /// Move any non-terminal state to `Failed` with the supplied reason.
    /// Idempotent on `Failed`.
    #[must_use]
    pub fn fail(self, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        let reason = self.sanitize_failure_reason(&reason);
        Self::Failed { reason }
    }

    fn sanitize_failure_reason(&self, reason: &str) -> crate::secrets::SafeDiagnostic {
        let mut secrets = Vec::new();
        match self {
            Self::Idle { config } => {
                secrets.extend(config.client_secret.iter().cloned());
            }
            Self::AwaitingAuthorization {
                config,
                state,
                pkce,
            } => {
                secrets.extend(config.client_secret.iter().cloned());
                secrets.push(state.clone());
                secrets.push(pkce.code_verifier.clone());
            }
            Self::Exchanging { config, pkce, code } => {
                secrets.extend(config.client_secret.iter().cloned());
                secrets.push(pkce.code_verifier.clone());
                secrets.push(code.clone());
            }
            Self::Authorized { config, token } => {
                secrets.extend(config.client_secret.iter().cloned());
                secrets.push(token.access_token.secret());
                secrets.extend(
                    token
                        .refresh_token
                        .iter()
                        .map(crate::secrets::OAuthToken::secret),
                );
            }
            Self::Failed { .. } => {}
        }
        crate::secrets::sanitize_diagnostic(reason, secrets.iter())
    }

    /// Borrow the authorized token bundle, if any.
    #[must_use]
    pub const fn token(&self) -> Option<&TokenBundle> {
        match self {
            Self::Authorized { token, .. } => Some(token),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Production MCP authorization owner
// ---------------------------------------------------------------------------

use base64::Engine as _;
use futures::StreamExt as _;
use rand::Rng as _;
use serde::ser::SerializeStruct as _;
use sha2::Digest as _;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex;
use url::Url;
use zeroize::Zeroizing;

const DISCOVERY_DOCUMENT_LIMIT: usize = 1024 * 1024;
const PENDING_AUTHORIZATION_TTL_SECS: u64 = 10 * 60;
const MAX_PENDING_AUTHORIZATIONS: usize = 16;
const REFRESH_SKEW: Duration = Duration::from_secs(60);
const MCP_OAUTH_STORE_SCHEMA: u32 = 1;

/// Declarative public-client settings for one remote MCP server.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpOAuthClientConfig {
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<crate::secrets::SecretString>,
    pub redirect_uri: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

impl std::fmt::Debug for McpOAuthClientConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpOAuthClientConfig")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self
                    .client_secret
                    .as_ref()
                    .map(|_| crate::secrets::REDACTED_SECRET),
            )
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl McpOAuthClientConfig {
    fn validate(&self) -> Result<(), McpOAuthRuntimeError> {
        if self.client_id.trim().is_empty() || self.client_id.len() > 4096 {
            return Err(McpOAuthRuntimeError::Configuration(
                "clientId must be 1..=4096 bytes".to_string(),
            ));
        }
        let redirect = Url::parse(&self.redirect_uri).map_err(|_| {
            McpOAuthRuntimeError::Configuration("redirectUri is not a valid URL".to_string())
        })?;
        if redirect.fragment().is_some() {
            return Err(McpOAuthRuntimeError::Configuration(
                "redirectUri must not contain a fragment".to_string(),
            ));
        }
        let loopback_http = redirect.scheme() == "http"
            && matches!(redirect.host_str(), Some("127.0.0.1" | "[::1]" | "::1"));
        if redirect.scheme() != "https" && !loopback_http {
            return Err(McpOAuthRuntimeError::Configuration(
                "redirectUri must use HTTPS or an explicit loopback HTTP address".to_string(),
            ));
        }
        normalize_scopes(&self.scopes)?;
        Ok(())
    }
}

/// Typed reason an HTTP request needs a new user authorization step.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("MCP authorization required for server '{server}' ({reason})")]
pub struct McpAuthorizationRequired {
    pub server: String,
    pub reason: String,
    pub scopes: Vec<String>,
}

/// Browser handoff created from a bound pending PKCE session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpAuthorizationStart {
    pub pending_id: String,
    pub authorization_url: Url,
    pub expires_at: u64,
}

#[derive(Debug, Error)]
pub enum McpOAuthRuntimeError {
    #[error("invalid MCP OAuth configuration: {0}")]
    Configuration(String),
    #[error("MCP OAuth discovery failed: {0}")]
    Discovery(crate::secrets::SafeDiagnostic),
    #[error("MCP OAuth transport failed: {0}")]
    Transport(crate::secrets::SafeDiagnostic),
    #[error("MCP OAuth server response is invalid: {0}")]
    Protocol(String),
    #[error("MCP OAuth pending authorization is unavailable or expired")]
    PendingUnavailable,
    #[error("MCP OAuth state-token mismatch")]
    StateMismatch,
    #[error("MCP OAuth authorization response issuer mismatch")]
    IssuerMismatch,
    #[error("MCP OAuth authorization response is bound to another server, client, or scope set")]
    BindingMismatch,
    #[error("MCP OAuth session has been revoked")]
    Revoked,
    #[error("MCP OAuth session requires interactive authorization")]
    AuthorizationRequired,
    #[error("protected MCP OAuth storage failed: {0}")]
    Storage(crate::secrets::SafeDiagnostic),
}

#[derive(Debug, Clone, Deserialize)]
struct ProtectedResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
    #[serde(default)]
    scopes_supported: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthorizationServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    revocation_endpoint: Option<String>,
    #[serde(default)]
    scopes_supported: Vec<String>,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    authorization_response_iss_parameter_supported: bool,
}

#[derive(Debug, Clone)]
struct DiscoveredAuthorization {
    resource: Url,
    issuer: Url,
    authorization_endpoint: Url,
    token_endpoint: Url,
    revocation_endpoint: Option<Url>,
    scopes_supported: BTreeSet<String>,
    authorization_response_iss_parameter_supported: bool,
}

#[derive(Clone)]
struct PendingAuthorization {
    binding: String,
    state: crate::secrets::SecretString,
    verifier: crate::secrets::SecretString,
    endpoints: DiscoveredAuthorization,
    scopes: Vec<String>,
    expires_at: u64,
}

#[derive(Debug, Clone)]
struct StoredSession {
    binding: String,
    endpoints: DiscoveredAuthorization,
    token: TokenBundle,
    generation: u64,
}

#[derive(Debug, Default)]
struct OAuthStoreState {
    sessions: HashMap<String, StoredSession>,
    revocations: HashMap<String, u64>,
}

#[derive(Debug)]
struct PersistentOAuthStore {
    storage: crate::persistence::PersistentStorage,
    target: PathBuf,
    generation: crate::persistence::StorageGeneration,
}

#[derive(Debug, Default)]
struct McpOAuthStore {
    state: RwLock<OAuthStoreState>,
    persistent: std::sync::Mutex<Option<PersistentOAuthStore>>,
}

/// One server-specific OAuth owner. It is shared by a connection blueprint so
/// reconnects reuse the same session and serialized refresh gate.
pub struct McpOAuthManager {
    server_name: String,
    resource: Url,
    config: McpOAuthClientConfig,
    client: reqwest::Client,
    validate_network_urls: bool,
    store: Arc<McpOAuthStore>,
    discovery: Mutex<Option<DiscoveredAuthorization>>,
    resource_metadata_hint: Mutex<Option<Url>>,
    pending: Mutex<HashMap<String, PendingAuthorization>>,
    refresh_gate: Mutex<()>,
}

impl std::fmt::Debug for McpOAuthManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpOAuthManager")
            .field("server_name", &self.server_name)
            .field("resource", &self.resource)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl McpOAuthManager {
    /// Create a persistent authorization owner using the application data
    /// directory and descriptor-safe credential storage.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, protected storage failure,
    /// or a stored session that violates the configured binding.
    pub fn persistent(
        server_name: impl Into<String>,
        resource: &str,
        config: McpOAuthClientConfig,
    ) -> Result<Arc<Self>, McpOAuthRuntimeError> {
        let server_name = server_name.into();
        let root = dirs::data_local_dir()
            .ok_or_else(|| {
                McpOAuthRuntimeError::Configuration(
                    "platform data directory is unavailable".to_string(),
                )
            })?
            .join("openclaudia");
        std::fs::create_dir_all(&root).map_err(storage_error)?;
        let target = persistent_target(&server_name, resource, &config.client_id);
        Self::with_store(server_name, resource, config, Some((&root, &target)), true)
    }

    /// Create a non-persistent owner, primarily for ephemeral hosts.
    ///
    /// # Errors
    ///
    /// Returns an error when the client or resource configuration is invalid.
    pub fn ephemeral(
        server_name: impl Into<String>,
        resource: &str,
        config: McpOAuthClientConfig,
    ) -> Result<Arc<Self>, McpOAuthRuntimeError> {
        Self::with_store(server_name, resource, config, None, true)
    }

    fn with_store(
        server_name: impl Into<String>,
        resource: &str,
        config: McpOAuthClientConfig,
        persistence: Option<(&Path, &Path)>,
        validate_network_urls: bool,
    ) -> Result<Arc<Self>, McpOAuthRuntimeError> {
        config.validate()?;
        let resource = Url::parse(resource).map_err(|_| {
            McpOAuthRuntimeError::Configuration("MCP resource URL is invalid".to_string())
        })?;
        if resource.fragment().is_some() {
            return Err(McpOAuthRuntimeError::Configuration(
                "MCP resource URL must not contain a fragment".to_string(),
            ));
        }
        validate_oauth_url(&resource, validate_network_urls)?;
        let store = Arc::new(McpOAuthStore::default());
        if let Some((root, target)) = persistence {
            store.open_persistent(root, target)?;
        }
        let manager = Arc::new(Self {
            server_name: server_name.into(),
            resource,
            config,
            client: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|error| {
                    McpOAuthRuntimeError::Transport(crate::secrets::SafeDiagnostic::from_untrusted(
                        &error.to_string(),
                    ))
                })?,
            validate_network_urls,
            store,
            discovery: Mutex::new(None),
            resource_metadata_hint: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            refresh_gate: Mutex::new(()),
        });
        match manager.store.current() {
            Ok(Some(session)) => manager.validate_loaded_session(&session)?,
            Ok(None) | Err(McpOAuthRuntimeError::Revoked) => {}
            Err(error) => return Err(error),
        }
        Ok(manager)
    }

    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn __test_ephemeral_unchecked(
        server_name: impl Into<String>,
        resource: &str,
        config: McpOAuthClientConfig,
    ) -> Result<Arc<Self>, McpOAuthRuntimeError> {
        Self::with_store(server_name, resource, config, None, false)
    }

    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn __test_persistent_unchecked(
        server_name: impl Into<String>,
        resource: &str,
        config: McpOAuthClientConfig,
        root: &Path,
    ) -> Result<Arc<Self>, McpOAuthRuntimeError> {
        let server_name = server_name.into();
        let target = persistent_target(&server_name, resource, &config.client_id);
        Self::with_store(server_name, resource, config, Some((root, &target)), false)
    }

    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Discover authorization metadata and create a bound, expiring PKCE
    /// browser handoff.
    ///
    /// # Errors
    ///
    /// Returns an error when discovery, network policy, PKCE generation, or
    /// authorization metadata validation fails.
    pub async fn begin_authorization(
        &self,
        additional_scopes: &[String],
    ) -> Result<McpAuthorizationStart, McpOAuthRuntimeError> {
        let metadata_hint = self.resource_metadata_hint.lock().await.clone();
        let endpoints = self.discover(metadata_hint.as_ref()).await?;
        let mut scopes = normalize_scopes(&self.config.scopes)?;
        scopes.extend(normalize_scopes(additional_scopes)?);
        if scopes.is_empty() {
            scopes.extend(endpoints.scopes_supported.iter().cloned());
        }
        let scopes = scopes.into_iter().collect::<Vec<_>>();
        let verifier = random_secret(64)?;
        let challenge = verifier.expose(|value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(value.as_bytes()))
        });
        let state = random_secret(32)?;
        let pending_id = uuid::Uuid::new_v4().to_string();
        let expires_at = now_epoch().saturating_add(PENDING_AUTHORIZATION_TTL_SECS);
        let binding = session_binding(
            &self.resource,
            &endpoints.issuer,
            &self.config.client_id,
            &scopes,
        );
        let mut authorization_url = endpoints.authorization_endpoint.clone();
        authorization_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("resource", self.resource.as_str());
        if !scopes.is_empty() {
            authorization_url
                .query_pairs_mut()
                .append_pair("scope", &scopes.join(" "));
        }
        state.expose(|value| {
            authorization_url
                .query_pairs_mut()
                .append_pair("state", value);
        });

        let mut pending = self.pending.lock().await;
        pending.retain(|_, value| value.expires_at > now_epoch());
        if pending.len() >= MAX_PENDING_AUTHORIZATIONS {
            let oldest = pending
                .iter()
                .min_by_key(|(_, value)| value.expires_at)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                pending.remove(&oldest);
            }
        }
        pending.insert(
            pending_id.clone(),
            PendingAuthorization {
                binding,
                state,
                verifier,
                endpoints,
                scopes,
                expires_at,
            },
        );
        drop(pending);
        Ok(McpAuthorizationStart {
            pending_id,
            authorization_url,
            expires_at,
        })
    }

    /// Consume one pending flow, validate state/bindings, exchange the code,
    /// and publish the resulting token generation.
    ///
    /// # Errors
    ///
    /// Returns an error for expired, replayed, mismatched, under-scoped, or
    /// failed authorization responses and protected-storage failures.
    pub async fn complete_authorization(
        &self,
        pending_id: &str,
        returned_state: &str,
        returned_issuer: Option<&str>,
        code: String,
    ) -> Result<(), McpOAuthRuntimeError> {
        let pending = self
            .pending
            .lock()
            .await
            .remove(pending_id)
            .ok_or(McpOAuthRuntimeError::PendingUnavailable)?;
        if pending.expires_at <= now_epoch() {
            return Err(McpOAuthRuntimeError::PendingUnavailable);
        }
        if !pending.state.matches(returned_state) {
            return Err(McpOAuthRuntimeError::StateMismatch);
        }
        match returned_issuer {
            Some(issuer) if issuer != pending.endpoints.issuer.as_str() => {
                return Err(McpOAuthRuntimeError::IssuerMismatch);
            }
            None if pending
                .endpoints
                .authorization_response_iss_parameter_supported =>
            {
                return Err(McpOAuthRuntimeError::IssuerMismatch);
            }
            Some(_) | None => {}
        }
        let expected = session_binding(
            &self.resource,
            &pending.endpoints.issuer,
            &self.config.client_id,
            &pending.scopes,
        );
        if expected != pending.binding {
            return Err(McpOAuthRuntimeError::BindingMismatch);
        }
        let code = crate::secrets::SecretString::try_from_string(code)
            .map_err(|_| McpOAuthRuntimeError::Protocol("authorization code is invalid".into()))?;
        let token = self
            .exchange_code(
                &pending.endpoints,
                &pending.scopes,
                &pending.verifier,
                &code,
            )
            .await?;
        let granted_scopes = scope_vec(&token.scope);
        let granted = granted_scopes.iter().collect::<BTreeSet<_>>();
        if pending.scopes.iter().any(|scope| !granted.contains(scope)) {
            return Err(McpOAuthRuntimeError::Protocol(
                "token response did not grant every requested scope".to_string(),
            ));
        }
        self.store.store_authorized(StoredSession {
            binding: session_binding(
                &self.resource,
                &pending.endpoints.issuer,
                &self.config.client_id,
                &granted_scopes,
            ),
            endpoints: pending.endpoints,
            token,
            generation: 1,
        })
    }

    /// Return a usable access token, refreshing once under a serialized gate
    /// when the current generation is expired or near expiry.
    ///
    /// # Errors
    ///
    /// Returns an error when authorization is absent or revoked, refresh fails,
    /// or the stored session no longer matches this server binding.
    pub async fn access_token(&self) -> Result<crate::secrets::OAuthToken, McpOAuthRuntimeError> {
        if let Some(token) = self.active_token(false)? {
            return Ok(token);
        }
        let _gate = self.refresh_gate.lock().await;
        if let Some(token) = self.active_token(false)? {
            return Ok(token);
        }
        self.refresh_current().await
    }

    /// Return a token when a session exists. Absence or local revocation is
    /// `None`, allowing the transport to obtain an authoritative challenge.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed storage, binding failures, or refresh
    /// transport and protocol failures.
    pub async fn optional_access_token(
        &self,
    ) -> Result<Option<crate::secrets::OAuthToken>, McpOAuthRuntimeError> {
        match self.access_token().await {
            Ok(token) => Ok(Some(token)),
            Err(McpOAuthRuntimeError::AuthorizationRequired | McpOAuthRuntimeError::Revoked) => {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    #[must_use]
    pub fn required(
        &self,
        reason: impl Into<String>,
        scopes: Vec<String>,
    ) -> McpAuthorizationRequired {
        let reason = reason.into();
        McpAuthorizationRequired {
            server: self.server_name.clone(),
            reason: self.sanitize_diagnostic(&reason).as_str().to_string(),
            scopes: scopes
                .into_iter()
                .map(|scope| self.sanitize_diagnostic(&scope).as_str().to_string())
                .collect(),
        }
    }

    /// Retain a protected-resource metadata URL supplied by the resource
    /// server's bearer challenge. It is validated again during discovery and
    /// its document must still bind back to this manager's exact resource.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is malformed or denied by network policy.
    pub async fn note_resource_metadata(&self, raw: &str) -> Result<(), McpOAuthRuntimeError> {
        let url = Url::parse(raw).map_err(|_| {
            McpOAuthRuntimeError::Protocol(
                "WWW-Authenticate resource_metadata is not a valid URL".to_string(),
            )
        })?;
        validate_oauth_url(&url, self.validate_network_urls)?;
        *self.resource_metadata_hint.lock().await = Some(url);
        Ok(())
    }

    #[must_use]
    pub fn sanitize_diagnostic(&self, raw: &str) -> crate::secrets::SafeDiagnostic {
        let state = self
            .store
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut secrets = self
            .config
            .client_secret
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        for session in state.sessions.values() {
            secrets.push(session.token.access_token.secret());
            secrets.extend(
                session
                    .token
                    .refresh_token
                    .iter()
                    .map(crate::secrets::OAuthToken::secret),
            );
        }
        drop(state);
        crate::secrets::sanitize_diagnostic(raw, secrets.iter())
    }

    /// Force one serialized refresh after an `invalid_token` response.
    ///
    /// # Errors
    ///
    /// Returns an error when no refreshable authorization exists or the
    /// refresh response, binding, transport, or storage operation fails.
    pub async fn force_refresh(&self) -> Result<crate::secrets::OAuthToken, McpOAuthRuntimeError> {
        let _gate = self.refresh_gate.lock().await;
        self.refresh_current().await
    }

    /// Refresh after a resource server rejected one exact bearer. Concurrent
    /// rejections for that same generation collapse onto the first refresh;
    /// waiters reuse the rotated access token instead of rotating twice.
    ///
    /// # Errors
    ///
    /// Returns an error when the current session is unavailable, revoked,
    /// invalidly bound, or cannot be refreshed and stored.
    pub async fn refresh_after_rejection(
        &self,
        rejected: &crate::secrets::OAuthToken,
    ) -> Result<crate::secrets::OAuthToken, McpOAuthRuntimeError> {
        let _gate = self.refresh_gate.lock().await;
        if let Some(session) = self.store.current()? {
            self.validate_stored_session_binding(&session)?;
            if session.token.access_token != *rejected && !session.token.is_expired() {
                return Ok(session.token.access_token);
            }
        }
        self.refresh_current().await
    }

    /// Discover metadata from a challenge-provided protected-resource URL, or
    /// from the resource's well-known location when no challenge was supplied.
    #[allow(clippy::too_many_lines)] // One discovery transaction validates every bound endpoint.
    async fn discover(
        &self,
        resource_metadata: Option<&Url>,
    ) -> Result<DiscoveredAuthorization, McpOAuthRuntimeError> {
        if resource_metadata.is_none() {
            let existing = self.discovery.lock().await.clone();
            if let Some(existing) = existing {
                return Ok(existing);
            }
        }
        let resource_candidates = resource_metadata.map_or_else(
            || protected_resource_metadata_candidates(&self.resource),
            |url| vec![url.clone()],
        );
        let mut last_error = None;
        let mut resource_metadata = None;
        for candidate in resource_candidates {
            match self.get_json::<ProtectedResourceMetadata>(&candidate).await {
                Ok(metadata) => {
                    resource_metadata = Some(metadata);
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }
        let metadata = resource_metadata.ok_or_else(|| {
            last_error.unwrap_or_else(|| {
                McpOAuthRuntimeError::Discovery(crate::secrets::SafeDiagnostic::from_untrusted(
                    "protected-resource metadata is unavailable",
                ))
            })
        })?;
        let declared_resource = Url::parse(&metadata.resource).map_err(|_| {
            McpOAuthRuntimeError::Protocol("resource metadata contains an invalid resource".into())
        })?;
        if canonical_resource(&declared_resource) != canonical_resource(&self.resource) {
            return Err(McpOAuthRuntimeError::BindingMismatch);
        }
        let issuer = metadata.authorization_servers.first().ok_or_else(|| {
            McpOAuthRuntimeError::Protocol(
                "resource metadata has no authorization_servers".to_string(),
            )
        })?;
        let issuer = Url::parse(issuer).map_err(|_| {
            McpOAuthRuntimeError::Protocol("authorization server URL is invalid".to_string())
        })?;
        validate_oauth_url(&issuer, self.validate_network_urls)?;

        let mut authorization_metadata = None;
        for candidate in authorization_server_metadata_candidates(&issuer) {
            if let Ok(metadata) = self
                .get_json::<AuthorizationServerMetadata>(&candidate)
                .await
            {
                authorization_metadata = Some(metadata);
                break;
            }
        }
        let authorization = authorization_metadata.ok_or_else(|| {
            McpOAuthRuntimeError::Discovery(crate::secrets::SafeDiagnostic::from_untrusted(
                "authorization-server metadata is unavailable",
            ))
        })?;
        let discovered_issuer = Url::parse(&authorization.issuer).map_err(|_| {
            McpOAuthRuntimeError::Protocol("authorization metadata issuer is invalid".to_string())
        })?;
        if discovered_issuer.as_str() != issuer.as_str() {
            return Err(McpOAuthRuntimeError::BindingMismatch);
        }
        if !authorization.code_challenge_methods_supported.is_empty()
            && !authorization
                .code_challenge_methods_supported
                .iter()
                .any(|method| method == "S256")
        {
            return Err(McpOAuthRuntimeError::Protocol(
                "authorization server does not support PKCE S256".to_string(),
            ));
        }
        let resource_scopes = metadata
            .scopes_supported
            .into_iter()
            .collect::<BTreeSet<_>>();
        let authorization_scopes = authorization
            .scopes_supported
            .into_iter()
            .collect::<BTreeSet<_>>();
        let scopes_supported = if resource_scopes.is_empty() {
            authorization_scopes
        } else {
            resource_scopes
        };
        let endpoints = DiscoveredAuthorization {
            resource: self.resource.clone(),
            issuer,
            authorization_endpoint: parse_endpoint(
                &authorization.authorization_endpoint,
                self.validate_network_urls,
            )?,
            token_endpoint: parse_endpoint(
                &authorization.token_endpoint,
                self.validate_network_urls,
            )?,
            revocation_endpoint: authorization
                .revocation_endpoint
                .as_deref()
                .map(|url| parse_endpoint(url, self.validate_network_urls))
                .transpose()?,
            scopes_supported,
            authorization_response_iss_parameter_supported: authorization
                .authorization_response_iss_parameter_supported,
        };
        *self.discovery.lock().await = Some(endpoints.clone());
        Ok(endpoints)
    }

    /// Revoke local use immediately and attempt remote revocation when the
    /// authorization server advertises an endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid stored binding, protected-storage failure,
    /// or an unsuccessful configured revocation endpoint.
    pub async fn revoke(&self) -> Result<bool, McpOAuthRuntimeError> {
        let Some(session) = self.store.current()? else {
            return Ok(false);
        };
        self.validate_stored_session_binding(&session)?;
        let remote_result = if let Some(endpoint) = session.endpoints.revocation_endpoint.as_ref() {
            let (token, hint) = session
                .token
                .refresh_token
                .as_ref()
                .map_or((&session.token.access_token, "access_token"), |refresh| {
                    (refresh, "refresh_token")
                });
            let mut form = vec![
                ("client_id", self.config.client_id.clone()),
                ("token_type_hint", hint.to_string()),
            ];
            token.expose(|value| form.push(("token", value.to_string())));
            if let Some(secret) = self.config.client_secret.as_ref() {
                secret.expose(|value| form.push(("client_secret", value.to_string())));
            }
            self.client.post(endpoint.clone()).form(&form).send().await
        } else {
            return self.store.revoke().map(|()| true);
        };
        self.store.revoke()?;
        let response = remote_result.map_err(transport_error)?;
        if !response.status().is_success() {
            return Err(McpOAuthRuntimeError::Protocol(format!(
                "revocation endpoint returned HTTP {}",
                response.status().as_u16()
            )));
        }
        Ok(true)
    }

    fn active_token(
        &self,
        accept_near_expiry: bool,
    ) -> Result<Option<crate::secrets::OAuthToken>, McpOAuthRuntimeError> {
        let Some(session) = self.store.current()? else {
            return Ok(None);
        };
        self.validate_stored_session_binding(&session)?;
        let configured_scopes = normalize_scopes(&self.config.scopes)?;
        let granted_scopes = normalize_scopes(&scope_vec(&session.token.scope))?;
        if configured_scopes
            .iter()
            .any(|scope| !granted_scopes.contains(scope))
        {
            return Err(McpOAuthRuntimeError::AuthorizationRequired);
        }
        if !accept_near_expiry && session.token.needs_refresh(REFRESH_SKEW) {
            return Ok(None);
        }
        if session.token.is_expired() {
            return Ok(None);
        }
        Ok(Some(session.token.access_token))
    }

    async fn refresh_current(&self) -> Result<crate::secrets::OAuthToken, McpOAuthRuntimeError> {
        let session = self
            .store
            .current()?
            .ok_or(McpOAuthRuntimeError::AuthorizationRequired)?;
        self.validate_stored_session_binding(&session)?;
        let refresh = session
            .token
            .refresh_token
            .as_ref()
            .ok_or(McpOAuthRuntimeError::AuthorizationRequired)?;
        let mut form = vec![
            ("grant_type", "refresh_token".to_string()),
            ("client_id", self.config.client_id.clone()),
            ("resource", self.resource.as_str().to_string()),
        ];
        refresh.expose(|value| form.push(("refresh_token", value.to_string())));
        if let Some(secret) = self.config.client_secret.as_ref() {
            secret.expose(|value| form.push(("client_secret", value.to_string())));
        }
        let response = self
            .client
            .post(session.endpoints.token_endpoint.clone())
            .form(&form)
            .send()
            .await
            .map_err(transport_error)?;
        if !response.status().is_success() {
            if matches!(response.status().as_u16(), 400 | 401) {
                self.store.revoke()?;
            }
            return Err(McpOAuthRuntimeError::AuthorizationRequired);
        }
        let mut token = parse_token_response(response, &scope_vec(&session.token.scope)).await?;
        if token.refresh_token.is_none() {
            token.refresh_token = session.token.refresh_token;
        }
        let updated = StoredSession {
            binding: session_binding(
                &self.resource,
                &session.endpoints.issuer,
                &self.config.client_id,
                &scope_vec(&token.scope),
            ),
            endpoints: session.endpoints,
            token: token.clone(),
            generation: session.generation.saturating_add(1),
        };
        self.store.store(updated)?;
        Ok(token.access_token)
    }

    fn validate_stored_session_binding(
        &self,
        session: &StoredSession,
    ) -> Result<(), McpOAuthRuntimeError> {
        if canonical_resource(&session.endpoints.resource) != canonical_resource(&self.resource)
            || session.binding
                != session_binding(
                    &self.resource,
                    &session.endpoints.issuer,
                    &self.config.client_id,
                    &scope_vec(&session.token.scope),
                )
        {
            return Err(McpOAuthRuntimeError::BindingMismatch);
        }
        Ok(())
    }

    fn validate_loaded_session(&self, session: &StoredSession) -> Result<(), McpOAuthRuntimeError> {
        self.validate_stored_session_binding(session)?;
        validate_oauth_url(&session.endpoints.resource, self.validate_network_urls)?;
        validate_oauth_url(&session.endpoints.issuer, self.validate_network_urls)?;
        validate_oauth_url(
            &session.endpoints.authorization_endpoint,
            self.validate_network_urls,
        )?;
        validate_oauth_url(
            &session.endpoints.token_endpoint,
            self.validate_network_urls,
        )?;
        if let Some(endpoint) = session.endpoints.revocation_endpoint.as_ref() {
            validate_oauth_url(endpoint, self.validate_network_urls)?;
        }
        Ok(())
    }

    async fn exchange_code(
        &self,
        endpoints: &DiscoveredAuthorization,
        scopes: &[String],
        verifier: &crate::secrets::SecretString,
        code: &crate::secrets::SecretString,
    ) -> Result<TokenBundle, McpOAuthRuntimeError> {
        let mut form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("client_id", self.config.client_id.clone()),
            ("redirect_uri", self.config.redirect_uri.clone()),
            ("resource", self.resource.as_str().to_string()),
        ];
        verifier.expose(|value| form.push(("code_verifier", value.to_string())));
        code.expose(|value| form.push(("code", value.to_string())));
        if let Some(secret) = self.config.client_secret.as_ref() {
            secret.expose(|value| form.push(("client_secret", value.to_string())));
        }
        let response = self
            .client
            .post(endpoints.token_endpoint.clone())
            .form(&form)
            .send()
            .await
            .map_err(transport_error)?;
        if !response.status().is_success() {
            return Err(McpOAuthRuntimeError::Protocol(format!(
                "token endpoint returned HTTP {}",
                response.status().as_u16()
            )));
        }
        parse_token_response(response, scopes).await
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &Url,
    ) -> Result<T, McpOAuthRuntimeError> {
        validate_oauth_url(url, self.validate_network_urls)?;
        let response = self
            .client
            .get(url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(transport_error)?;
        if !response.status().is_success() {
            return Err(McpOAuthRuntimeError::Discovery(
                crate::secrets::SafeDiagnostic::from_untrusted(&format!(
                    "metadata endpoint returned HTTP {}",
                    response.status().as_u16()
                )),
            ));
        }
        bounded_json(response).await
    }
}

impl McpOAuthStore {
    fn open_persistent(&self, root: &Path, target: &Path) -> Result<(), McpOAuthRuntimeError> {
        let storage = crate::persistence::PersistentStorage::open(root).map_err(storage_error)?;
        let read = storage
            .read(target, crate::persistence::FileClass::Credentials)
            .map_err(storage_error)?;
        let generation = read.generation();
        let state = read.expose_bytes(|bytes| {
            bytes.map_or_else(
                || Ok(OAuthStoreState::default()),
                |bytes| {
                    let document: PersistedDocument =
                        serde_json::from_slice(bytes).map_err(storage_error)?;
                    document.into_state()
                },
            )
        })?;
        *self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = state;
        *self
            .persistent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(PersistentOAuthStore {
            storage,
            target: target.to_path_buf(),
            generation,
        });
        Ok(())
    }

    fn current(&self) -> Result<Option<StoredSession>, McpOAuthRuntimeError> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.revocations.contains_key("current") {
            return Err(McpOAuthRuntimeError::Revoked);
        }
        Ok(state.sessions.get("current").cloned())
    }

    #[allow(clippy::significant_drop_tightening)] // Lock binds this state generation to persistence.
    fn store(&self, session: StoredSession) -> Result<(), McpOAuthRuntimeError> {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(revoked_generation) = state.revocations.get("current") {
            if session.generation <= *revoked_generation {
                return Err(McpOAuthRuntimeError::Revoked);
            }
            state.revocations.remove("current");
        }
        state.sessions.insert("current".to_string(), session);
        self.persist(&state)
    }

    /// Publish a newly completed interactive grant. Unlike refresh, a fresh
    /// grant is allowed to supersede a local revocation tombstone, but it must
    /// advance the generation so an older refresh cannot resurrect itself.
    #[allow(clippy::significant_drop_tightening)] // Lock binds this state generation to persistence.
    fn store_authorized(&self, mut session: StoredSession) -> Result<(), McpOAuthRuntimeError> {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous_generation = state
            .sessions
            .get("current")
            .map(|current| current.generation)
            .into_iter()
            .chain(state.revocations.get("current").copied())
            .max()
            .unwrap_or(0);
        session.generation = session
            .generation
            .max(previous_generation.saturating_add(1));
        state.revocations.remove("current");
        state.sessions.insert("current".to_string(), session);
        self.persist(&state)
    }

    #[allow(clippy::significant_drop_tightening)] // Revocation stays fail-closed through persistence.
    fn revoke(&self) -> Result<(), McpOAuthRuntimeError> {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let generation = state
            .sessions
            .remove("current")
            .map_or(1, |session| session.generation.saturating_add(1));
        state.revocations.insert("current".to_string(), generation);
        self.persist(&state)
    }

    #[allow(clippy::significant_drop_tightening)] // Storage generation is serialized by this owner.
    fn persist(&self, state: &OAuthStoreState) -> Result<(), McpOAuthRuntimeError> {
        let mut persistent = self
            .persistent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(persistent) = persistent.as_mut() else {
            return Ok(());
        };
        let encoded = Zeroizing::new(
            serde_json::to_vec_pretty(&PersistedDocumentRef { state }).map_err(storage_error)?,
        );
        let expected = persistent.generation;
        let receipt = persistent
            .storage
            .commit(
                &persistent.target,
                crate::persistence::FileClass::Credentials,
                expected,
                &*encoded,
            )
            .map_err(storage_error)?;
        if receipt.state() == crate::persistence::CommitState::PublishedDurabilityUncertain {
            let recovery = persistent
                .storage
                .commit(
                    &persistent.target,
                    crate::persistence::FileClass::Credentials,
                    expected,
                    &*encoded,
                )
                .map_err(storage_error)?;
            if recovery.state() == crate::persistence::CommitState::PublishedDurabilityUncertain {
                return Err(McpOAuthRuntimeError::Storage(
                    crate::secrets::SafeDiagnostic::from_untrusted(
                        "credential publication durability remains uncertain",
                    ),
                ));
            }
            persistent.generation = recovery.generation();
        } else {
            persistent.generation = receipt.generation();
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct PersistedDocument {
    schema_version: u32,
    #[serde(default)]
    sessions: HashMap<String, PersistedSession>,
    #[serde(default)]
    revocations: HashMap<String, u64>,
}

impl PersistedDocument {
    fn into_state(self) -> Result<OAuthStoreState, McpOAuthRuntimeError> {
        if self.schema_version != MCP_OAUTH_STORE_SCHEMA {
            return Err(McpOAuthRuntimeError::Storage(
                crate::secrets::SafeDiagnostic::from_untrusted(
                    "unsupported MCP OAuth credential schema",
                ),
            ));
        }
        let sessions = self
            .sessions
            .into_iter()
            .map(|(key, session)| session.into_runtime().map(|session| (key, session)))
            .collect::<Result<HashMap<_, _>, _>>()?;
        Ok(OAuthStoreState {
            sessions,
            revocations: self.revocations,
        })
    }
}

#[derive(Deserialize)]
struct PersistedSession {
    binding: String,
    resource: String,
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: Option<String>,
    scopes_supported: Vec<String>,
    #[serde(default)]
    authorization_response_iss_parameter_supported: bool,
    token: TokenBundle,
    generation: u64,
}

impl PersistedSession {
    fn into_runtime(self) -> Result<StoredSession, McpOAuthRuntimeError> {
        if self.generation == 0 {
            return Err(McpOAuthRuntimeError::Storage(
                crate::secrets::SafeDiagnostic::from_untrusted(
                    "stored MCP OAuth generation is invalid",
                ),
            ));
        }
        Ok(StoredSession {
            binding: self.binding,
            endpoints: DiscoveredAuthorization {
                resource: Url::parse(&self.resource).map_err(storage_error)?,
                issuer: Url::parse(&self.issuer).map_err(storage_error)?,
                authorization_endpoint: Url::parse(&self.authorization_endpoint)
                    .map_err(storage_error)?,
                token_endpoint: Url::parse(&self.token_endpoint).map_err(storage_error)?,
                revocation_endpoint: self
                    .revocation_endpoint
                    .map(|value| Url::parse(&value).map_err(storage_error))
                    .transpose()?,
                scopes_supported: self.scopes_supported.into_iter().collect(),
                authorization_response_iss_parameter_supported: self
                    .authorization_response_iss_parameter_supported,
            },
            token: self.token,
            generation: self.generation,
        })
    }
}

struct PersistedDocumentRef<'a> {
    state: &'a OAuthStoreState,
}

impl Serialize for PersistedDocumentRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut document = serializer.serialize_struct("McpOAuthDocument", 3)?;
        document.serialize_field("schema_version", &MCP_OAUTH_STORE_SCHEMA)?;
        document.serialize_field("sessions", &PersistedSessionsRef(&self.state.sessions))?;
        document.serialize_field("revocations", &self.state.revocations)?;
        document.end()
    }
}

struct PersistedSessionsRef<'a>(&'a HashMap<String, StoredSession>);

impl Serialize for PersistedSessionsRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, session) in self.0 {
            map.serialize_entry(key, &PersistedSessionRef(session))?;
        }
        map.end()
    }
}

struct PersistedSessionRef<'a>(&'a StoredSession);

impl Serialize for PersistedSessionRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let session = self.0;
        let mut value = serializer.serialize_struct("McpOAuthSession", 10)?;
        value.serialize_field("binding", &session.binding)?;
        value.serialize_field("resource", session.endpoints.resource.as_str())?;
        value.serialize_field("issuer", session.endpoints.issuer.as_str())?;
        value.serialize_field(
            "authorization_endpoint",
            session.endpoints.authorization_endpoint.as_str(),
        )?;
        value.serialize_field("token_endpoint", session.endpoints.token_endpoint.as_str())?;
        value.serialize_field(
            "revocation_endpoint",
            &session
                .endpoints
                .revocation_endpoint
                .as_ref()
                .map(Url::as_str),
        )?;
        value.serialize_field("scopes_supported", &session.endpoints.scopes_supported)?;
        value.serialize_field(
            "authorization_response_iss_parameter_supported",
            &session
                .endpoints
                .authorization_response_iss_parameter_supported,
        )?;
        value.serialize_field("token", &PersistedTokenRef(&session.token))?;
        value.serialize_field("generation", &session.generation)?;
        value.end()
    }
}

struct PersistedTokenRef<'a>(&'a TokenBundle);

impl Serialize for PersistedTokenRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let token = self.0;
        let mut value = serializer.serialize_struct("TokenBundle", 6)?;
        token
            .access_token
            .expose(|raw| value.serialize_field("access_token", raw))?;
        if let Some(refresh) = token.refresh_token.as_ref() {
            refresh.expose(|raw| value.serialize_field("refresh_token", raw))?;
        }
        value.serialize_field("expires_in_secs", &token.expires_in_secs)?;
        value.serialize_field("obtained_at", &token.obtained_at)?;
        value.serialize_field("token_type", &token.token_type)?;
        value.serialize_field("scope", &token.scope)?;
        value.end()
    }
}

#[derive(Deserialize)]
struct TokenEndpointResponse {
    access_token: crate::secrets::OAuthToken,
    #[serde(default)]
    refresh_token: Option<crate::secrets::OAuthToken>,
    expires_in: u64,
    #[serde(default = "default_token_type")]
    token_type: String,
    #[serde(default)]
    scope: Option<String>,
}

async fn parse_token_response(
    response: reqwest::Response,
    requested_scopes: &[String],
) -> Result<TokenBundle, McpOAuthRuntimeError> {
    let response: TokenEndpointResponse = bounded_json(response).await?;
    if !response.token_type.eq_ignore_ascii_case("Bearer") || response.expires_in == 0 {
        return Err(McpOAuthRuntimeError::Protocol(
            "token response has an invalid token_type or expires_in".to_string(),
        ));
    }
    let requested = normalize_scopes(requested_scopes)?;
    let granted = match response.scope.as_deref() {
        Some(scope) => normalize_scopes(&scope_vec(scope))?,
        None => requested.clone(),
    };
    if !requested.is_empty() && granted.iter().any(|scope| !requested.contains(scope)) {
        return Err(McpOAuthRuntimeError::BindingMismatch);
    }
    Ok(TokenBundle {
        access_token: response.access_token,
        refresh_token: response.refresh_token,
        expires_in_secs: response.expires_in,
        obtained_at: now_epoch(),
        token_type: response.token_type,
        scope: granted.into_iter().collect::<Vec<_>>().join(" "),
    })
}

async fn bounded_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, McpOAuthRuntimeError> {
    if response
        .content_length()
        .is_some_and(|length| length > DISCOVERY_DOCUMENT_LIMIT as u64)
    {
        return Err(McpOAuthRuntimeError::Protocol(
            "OAuth response exceeds the 1 MiB limit".to_string(),
        ));
    }
    let mut bytes = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or_default()
            .min(DISCOVERY_DOCUMENT_LIMIT),
    );
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(transport_error)?;
        if bytes.len().saturating_add(chunk.len()) > DISCOVERY_DOCUMENT_LIMIT {
            return Err(McpOAuthRuntimeError::Protocol(
                "OAuth response exceeds the 1 MiB limit".to_string(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| McpOAuthRuntimeError::Protocol("OAuth response is not valid JSON".to_string()))
}

fn normalize_scopes(scopes: &[String]) -> Result<BTreeSet<String>, McpOAuthRuntimeError> {
    let mut normalized = BTreeSet::new();
    for scope in scopes {
        for scope in scope.split_ascii_whitespace() {
            if scope.is_empty() || scope.len() > 256 || scope.chars().any(char::is_control) {
                return Err(McpOAuthRuntimeError::Configuration(
                    "OAuth scope is invalid".to_string(),
                ));
            }
            normalized.insert(scope.to_string());
        }
    }
    Ok(normalized)
}

fn scope_vec(scopes: &str) -> Vec<String> {
    scopes
        .split_ascii_whitespace()
        .map(str::to_string)
        .collect()
}

fn session_binding(resource: &Url, issuer: &Url, client_id: &str, scopes: &[String]) -> String {
    let scopes = normalize_scopes(scopes).unwrap_or_default();
    let material = format!(
        "{}\0{}\0{}\0{}",
        canonical_resource(resource),
        canonical_resource(issuer),
        client_id,
        scopes.into_iter().collect::<Vec<_>>().join(" ")
    );
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(material))
}

fn persistent_target(server_name: &str, resource: &str, client_id: &str) -> PathBuf {
    let material = format!("{server_name}\0{resource}\0{client_id}");
    let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(material.as_bytes()));
    PathBuf::from(format!("mcp_oauth_session_{digest}.json"))
}

fn canonical_resource(url: &Url) -> String {
    url.as_str().trim_end_matches('/').to_string()
}

fn random_secret(bytes: usize) -> Result<crate::secrets::SecretString, McpOAuthRuntimeError> {
    let mut raw = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut raw);
    crate::secrets::SecretString::try_from_string(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw),
    )
    .map_err(|_| McpOAuthRuntimeError::Protocol("failed to generate OAuth nonce".to_string()))
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn validate_oauth_url(url: &Url, validate_network: bool) -> Result<(), McpOAuthRuntimeError> {
    if validate_network {
        crate::web::validate_url(url.as_str()).map_err(|error| {
            McpOAuthRuntimeError::Configuration(format!(
                "OAuth endpoint failed network policy: {error}"
            ))
        })?;
    } else if !matches!(url.scheme(), "http" | "https") {
        return Err(McpOAuthRuntimeError::Configuration(
            "OAuth endpoint must use HTTP or HTTPS".to_string(),
        ));
    }
    Ok(())
}

fn parse_endpoint(url: &str, validate_network: bool) -> Result<Url, McpOAuthRuntimeError> {
    let url = Url::parse(url)
        .map_err(|_| McpOAuthRuntimeError::Protocol("OAuth endpoint URL is invalid".to_string()))?;
    validate_oauth_url(&url, validate_network)?;
    Ok(url)
}

fn protected_resource_metadata_candidates(resource: &Url) -> Vec<Url> {
    let mut path_candidate = resource.clone();
    let resource_path = resource.path().trim_start_matches('/');
    path_candidate.set_path(&format!(
        "/.well-known/oauth-protected-resource/{resource_path}"
    ));
    path_candidate.set_query(None);
    path_candidate.set_fragment(None);
    let mut root_candidate = resource.clone();
    root_candidate.set_path("/.well-known/oauth-protected-resource");
    root_candidate.set_query(None);
    root_candidate.set_fragment(None);
    if path_candidate == root_candidate {
        vec![root_candidate]
    } else {
        vec![path_candidate, root_candidate]
    }
}

fn authorization_server_metadata_candidates(issuer: &Url) -> Vec<Url> {
    let issuer_path = issuer.path().trim_start_matches('/');
    let mut oauth = issuer.clone();
    oauth.set_path(&format!(
        "/.well-known/oauth-authorization-server/{issuer_path}"
    ));
    oauth.set_query(None);
    oauth.set_fragment(None);
    let mut oidc = issuer.clone();
    let suffix = if issuer.path().ends_with('/') {
        ".well-known/openid-configuration"
    } else {
        "/.well-known/openid-configuration"
    };
    oidc.set_path(&format!("{}{suffix}", issuer.path()));
    oidc.set_query(None);
    oidc.set_fragment(None);
    vec![oauth, oidc]
}

fn transport_error(error: reqwest::Error) -> McpOAuthRuntimeError {
    let rendered = error.to_string();
    drop(error);
    McpOAuthRuntimeError::Transport(crate::secrets::SafeDiagnostic::from_untrusted(&rendered))
}

fn storage_error(error: impl std::fmt::Display) -> McpOAuthRuntimeError {
    McpOAuthRuntimeError::Storage(crate::secrets::SafeDiagnostic::from_untrusted(
        &error.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn secret(value: &str) -> crate::secrets::SecretString {
        crate::secrets::SecretString::try_from_string(value.to_string()).expect("secret")
    }

    fn token(value: &str) -> crate::secrets::OAuthToken {
        crate::secrets::OAuthToken::try_from_string(value.to_string()).expect("token")
    }

    fn cfg() -> OAuthConfig {
        OAuthConfig {
            client_id: "cid".into(),
            client_secret: None,
            authorize_url: "https://idp.example/auth".into(),
            token_url: "https://idp.example/token".into(),
            redirect_uri: "http://127.0.0.1:7000/cb".into(),
            scopes: vec!["mcp.read".into()],
        }
    }

    fn pkce() -> PkcePair {
        PkcePair {
            code_verifier: secret("verifier"),
            code_challenge: "challenge".into(),
            method: "S256",
        }
    }

    fn good_token() -> TokenBundle {
        TokenBundle {
            access_token: token("at"),
            refresh_token: Some(token("rt")),
            expires_in_secs: 3600,
            obtained_at: 1_000_000,
            token_type: "Bearer".into(),
            scope: "mcp.read".into(),
        }
    }

    fn runtime_config(scopes: &[&str]) -> McpOAuthClientConfig {
        McpOAuthClientConfig {
            client_id: "mcp-client".to_string(),
            client_secret: Some(secret("client-secret-sentinel")),
            redirect_uri: "http://127.0.0.1:7777/callback".to_string(),
            scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
        }
    }

    async fn mount_runtime_discovery(server: &MockServer, scopes: &[&str]) {
        let issuer = format!("{}/issuer", server.uri());
        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-protected-resource/mcp"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "resource": format!("{}/mcp", server.uri()),
                "authorization_servers": [issuer],
                "scopes_supported": scopes,
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-authorization-server/issuer"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": format!("{}/issuer", server.uri()),
                "authorization_endpoint": format!("{}/authorize", server.uri()),
                "token_endpoint": format!("{}/token", server.uri()),
                "revocation_endpoint": format!("{}/revoke", server.uri()),
                "scopes_supported": scopes,
                "code_challenge_methods_supported": ["S256"],
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    fn authorization_state(start: &McpAuthorizationStart) -> String {
        start
            .authorization_url
            .query_pairs()
            .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
            .expect("authorization state")
    }

    fn direct_endpoints() -> DiscoveredAuthorization {
        DiscoveredAuthorization {
            resource: Url::parse("https://mcp.example/resource").expect("resource"),
            issuer: Url::parse("https://id.example/issuer").expect("issuer"),
            authorization_endpoint: Url::parse("https://id.example/authorize").expect("authorize"),
            token_endpoint: Url::parse("https://id.example/token").expect("token"),
            revocation_endpoint: Some(
                Url::parse("https://id.example/revoke").expect("revoke endpoint"),
            ),
            scopes_supported: BTreeSet::from(["mcp.read".to_string()]),
            authorization_response_iss_parameter_supported: false,
        }
    }

    fn stored_runtime_session(access: &str, refresh: &str, generation: u64) -> StoredSession {
        StoredSession {
            binding: "binding".to_string(),
            endpoints: direct_endpoints(),
            token: TokenBundle {
                access_token: token(access),
                refresh_token: Some(token(refresh)),
                expires_in_secs: 3600,
                obtained_at: now_epoch(),
                token_type: "Bearer".to_string(),
                scope: "mcp.read".to_string(),
            },
            generation,
        }
    }

    #[tokio::test]
    async fn runtime_pkce_flow_serializes_refresh_and_rotates_then_revokes() {
        let server = MockServer::start().await;
        mount_runtime_discovery(&server, &["mcp.read"]).await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .and(body_string_contains("code_verifier="))
            .and(body_string_contains("resource="))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "access-one",
                "refresh_token": "refresh-one",
                "expires_in": 1,
                "token_type": "Bearer",
                "scope": "mcp.read",
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=refresh-one"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "access-two",
                "refresh_token": "refresh-two",
                "expires_in": 3600,
                "token_type": "Bearer",
                "scope": "mcp.read",
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .and(body_string_contains("token=refresh-two"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let manager = McpOAuthManager::__test_ephemeral_unchecked(
            "fixture",
            &format!("{}/mcp", server.uri()),
            runtime_config(&["mcp.read"]),
        )
        .expect("manager");
        let start = manager.begin_authorization(&[]).await.expect("begin");
        let query = start
            .authorization_url
            .query_pairs()
            .collect::<HashMap<_, _>>();
        assert_eq!(
            query.get("code_challenge_method").map(AsRef::as_ref),
            Some("S256")
        );
        assert_eq!(
            query.get("resource").map(AsRef::as_ref),
            Some(format!("{}/mcp", server.uri()).as_str())
        );
        let state = authorization_state(&start);
        manager
            .complete_authorization(&start.pending_id, &state, None, "fixture-code".to_string())
            .await
            .expect("complete");

        let (left, right) = tokio::join!(manager.access_token(), manager.access_token());
        assert!(left.expect("left token").matches("access-two"));
        assert!(right.expect("right token").matches("access-two"));
        let required = manager.required(
            "server echoed access-two",
            vec!["scope-access-two".to_string()],
        );
        let rendered = format!("{required:?}");
        assert!(!rendered.contains("access-two"), "{rendered}");
        assert!(manager.revoke().await.expect("revoke"));
        assert!(manager
            .optional_access_token()
            .await
            .expect("optional")
            .is_none());
        let rendered = format!("{manager:?}");
        assert!(!rendered.contains("client-secret-sentinel"), "{rendered}");
    }

    #[test]
    fn runtime_config_rejects_redirect_uri_fragments() {
        let mut config = runtime_config(&["mcp.read"]);
        config.redirect_uri = "https://client.example/callback#fragment".to_string();
        let error = McpOAuthManager::__test_ephemeral_unchecked(
            "fixture",
            "https://mcp.example/resource",
            config,
        )
        .expect_err("redirect fragments are forbidden");
        assert!(matches!(error, McpOAuthRuntimeError::Configuration(_)));
    }

    #[tokio::test]
    async fn runtime_concurrent_invalid_token_rejections_rotate_only_once() {
        let server = MockServer::start().await;
        mount_runtime_discovery(&server, &["mcp.read"]).await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "rejected-access",
                "refresh_token": "refresh-one",
                "expires_in": 3600,
                "token_type": "Bearer",
                "scope": "mcp.read"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "rotated-access",
                "refresh_token": "refresh-two",
                "expires_in": 3600,
                "token_type": "Bearer",
                "scope": "mcp.read"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let manager = McpOAuthManager::__test_ephemeral_unchecked(
            "fixture",
            &format!("{}/mcp", server.uri()),
            runtime_config(&["mcp.read"]),
        )
        .expect("manager");
        let start = manager.begin_authorization(&[]).await.expect("begin");
        manager
            .complete_authorization(
                &start.pending_id,
                &authorization_state(&start),
                None,
                "fixture-code".to_string(),
            )
            .await
            .expect("complete");
        let rejected = manager.access_token().await.expect("initial token");
        assert!(rejected.matches("rejected-access"));

        let (left, right) = tokio::join!(
            manager.refresh_after_rejection(&rejected),
            manager.refresh_after_rejection(&rejected)
        );
        assert!(left.expect("left refresh").matches("rotated-access"));
        assert!(right.expect("right refresh").matches("rotated-access"));
    }

    #[tokio::test]
    async fn runtime_concurrent_states_are_isolated_and_replay_is_consumed() {
        let server = MockServer::start().await;
        mount_runtime_discovery(&server, &["mcp.read"]).await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "right-access",
                "expires_in": 3600,
                "token_type": "Bearer",
                "scope": "mcp.read"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let manager = McpOAuthManager::__test_ephemeral_unchecked(
            "fixture",
            &format!("{}/mcp", server.uri()),
            runtime_config(&["mcp.read"]),
        )
        .expect("manager");
        let left = manager.begin_authorization(&[]).await.expect("left begin");
        let right = manager.begin_authorization(&[]).await.expect("right begin");
        let left_state = authorization_state(&left);
        let right_state = authorization_state(&right);
        assert_ne!(left.pending_id, right.pending_id);
        assert_ne!(left_state, right_state);
        let mismatch = manager
            .complete_authorization(
                &left.pending_id,
                &right_state,
                None,
                "left-code".to_string(),
            )
            .await
            .expect_err("state mismatch");
        assert!(matches!(mismatch, McpOAuthRuntimeError::StateMismatch));
        let replay = manager
            .complete_authorization(&left.pending_id, &left_state, None, "left-code".to_string())
            .await
            .expect_err("consumed pending flow");
        assert!(matches!(replay, McpOAuthRuntimeError::PendingUnavailable));
        manager
            .complete_authorization(
                &right.pending_id,
                &right_state,
                None,
                "right-code".to_string(),
            )
            .await
            .expect("unrelated pending flow survives");
        assert!(manager
            .access_token()
            .await
            .expect("right token")
            .matches("right-access"));
    }

    #[tokio::test]
    async fn runtime_validates_authorization_response_issuer_when_required() {
        let server = MockServer::start().await;
        let issuer = format!("{}/issuer", server.uri());
        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-protected-resource/mcp"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "resource": format!("{}/mcp", server.uri()),
                "authorization_servers": [issuer],
                "scopes_supported": ["mcp.read"]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-authorization-server/issuer"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": format!("{}/issuer", server.uri()),
                "authorization_endpoint": format!("{}/authorize", server.uri()),
                "token_endpoint": format!("{}/token", server.uri()),
                "code_challenge_methods_supported": ["S256"],
                "authorization_response_iss_parameter_supported": true
            })))
            .expect(1)
            .mount(&server)
            .await;
        let manager = McpOAuthManager::__test_ephemeral_unchecked(
            "fixture",
            &format!("{}/mcp", server.uri()),
            runtime_config(&["mcp.read"]),
        )
        .expect("manager");
        let start = manager.begin_authorization(&[]).await.expect("begin");
        let error = manager
            .complete_authorization(
                &start.pending_id,
                &authorization_state(&start),
                None,
                "fixture-code".to_string(),
            )
            .await
            .expect_err("missing issuer must fail when metadata requires it");
        assert!(matches!(error, McpOAuthRuntimeError::IssuerMismatch));

        let retry = manager.begin_authorization(&[]).await.expect("retry begin");
        let error = manager
            .complete_authorization(
                &retry.pending_id,
                &authorization_state(&retry),
                Some("https://wrong.example/issuer"),
                "fixture-code".to_string(),
            )
            .await
            .expect_err("wrong issuer must fail");
        assert!(matches!(error, McpOAuthRuntimeError::IssuerMismatch));
    }

    #[tokio::test]
    async fn runtime_scope_step_up_requires_the_union_to_be_granted() {
        let server = MockServer::start().await;
        // Challenge scopes are authoritative even when discovery does not
        // advertise them; the eventual token still has to grant the union.
        mount_runtime_discovery(&server, &["mcp.read"]).await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "under-scoped-access",
                "expires_in": 3600,
                "token_type": "Bearer",
                "scope": "mcp.read"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let manager = McpOAuthManager::__test_ephemeral_unchecked(
            "fixture",
            &format!("{}/mcp", server.uri()),
            runtime_config(&["mcp.read"]),
        )
        .expect("manager");
        let start = manager
            .begin_authorization(&["mcp.write".to_string()])
            .await
            .expect("step-up begin");
        let scope = start
            .authorization_url
            .query_pairs()
            .find_map(|(name, value)| (name == "scope").then(|| value.into_owned()))
            .expect("scope query");
        assert_eq!(scope, "mcp.read mcp.write");
        let error = manager
            .complete_authorization(
                &start.pending_id,
                &authorization_state(&start),
                None,
                "step-up-code".to_string(),
            )
            .await
            .expect_err("partial grant must not satisfy step-up");
        assert!(matches!(error, McpOAuthRuntimeError::Protocol(_)));
        assert!(manager
            .optional_access_token()
            .await
            .expect("optional")
            .is_none());
    }

    #[tokio::test]
    async fn runtime_discovery_uses_challenge_resource_metadata_hint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/challenge-resource-metadata"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "resource": format!("{}/mcp", server.uri()),
                "authorization_servers": [format!("{}/issuer", server.uri())],
                "scopes_supported": ["mcp.read"]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-authorization-server/issuer"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": format!("{}/issuer", server.uri()),
                "authorization_endpoint": format!("{}/authorize", server.uri()),
                "token_endpoint": format!("{}/token", server.uri()),
                "scopes_supported": ["mcp.read"],
                "code_challenge_methods_supported": ["S256"]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let manager = McpOAuthManager::__test_ephemeral_unchecked(
            "fixture",
            &format!("{}/mcp", server.uri()),
            runtime_config(&["mcp.read"]),
        )
        .expect("manager");
        manager
            .note_resource_metadata(&format!("{}/challenge-resource-metadata", server.uri()))
            .await
            .expect("challenge metadata");
        let start = manager.begin_authorization(&[]).await.expect("begin");
        assert_eq!(start.authorization_url.path(), "/authorize");
    }

    #[test]
    fn revocation_blocks_stale_refresh_but_fresh_authorization_advances_generation() {
        let store = McpOAuthStore::default();
        store
            .store_authorized(stored_runtime_session("access-one", "refresh-one", 1))
            .expect("initial authorization");
        store.revoke().expect("revoke");
        let stale = store
            .store(stored_runtime_session("stale-access", "stale-refresh", 2))
            .expect_err("stale refresh cannot cross tombstone");
        assert!(matches!(stale, McpOAuthRuntimeError::Revoked));
        store
            .store_authorized(stored_runtime_session("access-two", "refresh-two", 1))
            .expect("fresh authorization");
        let current = store.current().expect("current").expect("session");
        assert!(current.token.access_token.matches("access-two"));
        assert!(current.generation >= 3);
    }

    #[test]
    fn persistent_runtime_store_is_protected_reloadable_and_generic_debug_is_redacted() {
        let root = tempfile::tempdir().expect("tempdir");
        let target = Path::new("mcp_oauth_sessions.json");
        let store = McpOAuthStore::default();
        store.open_persistent(root.path(), target).expect("open");
        store
            .store_authorized(stored_runtime_session(
                "persisted-access-sentinel",
                "persisted-refresh-sentinel",
                1,
            ))
            .expect("store");

        let path = root.path().join(target);
        let bytes = std::fs::read(&path).expect("credential bytes");
        assert!(bytes
            .windows(25)
            .any(|window| window == b"persisted-access-sentinel"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
        }
        let reloaded = McpOAuthStore::default();
        reloaded
            .open_persistent(root.path(), target)
            .expect("reload");
        let current = reloaded.current().expect("current").expect("session");
        assert!(current
            .token
            .access_token
            .matches("persisted-access-sentinel"));
        let debug = format!("{current:?}");
        assert!(!debug.contains("persisted-access-sentinel"), "{debug}");
        assert!(!debug.contains("persisted-refresh-sentinel"), "{debug}");
    }

    #[test]
    fn persistent_runtime_targets_isolate_server_resource_and_client() {
        let baseline = persistent_target("alpha", "https://mcp.example/a", "client-a");
        assert_eq!(
            baseline,
            persistent_target("alpha", "https://mcp.example/a", "client-a")
        );
        assert_ne!(
            baseline,
            persistent_target("beta", "https://mcp.example/a", "client-a")
        );
        assert_ne!(
            baseline,
            persistent_target("alpha", "https://mcp.example/b", "client-a")
        );
        assert_ne!(
            baseline,
            persistent_target("alpha", "https://mcp.example/a", "client-b")
        );
        assert_eq!(baseline.parent(), Some(Path::new("")));
    }

    #[test]
    fn happy_path_transitions() {
        let flow = OAuthFlow::new(cfg());
        let flow = flow
            .start_authorization("nonce".into(), pkce())
            .expect("Idle -> AwaitingAuthorization");
        assert_eq!(flow.state_name(), "AwaitingAuthorization");

        let flow = flow
            .accept_redirect("nonce", "code-xyz".into())
            .expect("AwaitingAuthorization -> Exchanging");
        assert_eq!(flow.state_name(), "Exchanging");

        let flow = flow
            .complete_exchange(good_token())
            .expect("Exchanging -> Authorized");
        assert_eq!(flow.state_name(), "Authorized");
        assert!(flow.token().is_some());
    }

    #[test]
    fn rejects_state_mismatch() {
        let flow = OAuthFlow::new(cfg())
            .start_authorization("expected-state-secret".into(), pkce())
            .unwrap();
        let err = flow
            .accept_redirect("attacker-state-secret", "code".into())
            .unwrap_err();
        assert!(matches!(err, OAuthError::StateMismatch { .. }));
        let rendered = format!("{err:?} {err}");
        assert!(!rendered.contains("expected-state-secret"), "{rendered}");
        assert!(!rendered.contains("attacker-state-secret"), "{rendered}");
    }

    #[test]
    fn rejects_invalid_transitions() {
        let flow = OAuthFlow::new(cfg());
        let err = flow
            .accept_redirect("x", "y".into())
            .expect_err("Idle cannot accept redirect");
        assert!(matches!(err, OAuthError::InvalidTransition { .. }));
    }

    #[test]
    fn token_bundle_deserialization_rejects_empty_access_token() {
        let json = r#"{"access_token":"","expires_in_secs":60,"obtained_at":0}"#;
        assert!(serde_json::from_str::<TokenBundle>(json).is_err());
    }

    #[test]
    fn complete_exchange_rejects_non_bearer() {
        let flow = OAuthFlow::new(cfg())
            .start_authorization("n".into(), pkce())
            .unwrap()
            .accept_redirect("n", "c".into())
            .unwrap();
        let mut bad = good_token();
        bad.token_type = "mcp-token-type-secret-sentinel".into();
        let err = flow.complete_exchange(bad).unwrap_err();
        assert!(matches!(err, OAuthError::Malformed(_)));
        assert!(!err.to_string().contains("mcp-token-type-secret-sentinel"));
    }

    #[test]
    fn complete_exchange_rejects_zero_expiry() {
        let flow = OAuthFlow::new(cfg())
            .start_authorization("n".into(), pkce())
            .unwrap()
            .accept_redirect("n", "c".into())
            .unwrap();
        let mut bad = good_token();
        bad.expires_in_secs = 0;
        let err = flow.complete_exchange(bad).unwrap_err();
        assert!(matches!(err, OAuthError::Malformed(_)));
    }

    #[test]
    fn fail_consumes_to_terminal() {
        let flow = OAuthFlow::new(cfg()).fail("user cancelled");
        assert_eq!(flow.state_name(), "Failed");
    }

    #[test]
    fn failed_state_redacts_active_credentials_from_retained_reason() {
        let secret = "mcp-active-token-secret-sentinel";
        let mut bundle = good_token();
        bundle.access_token = token(secret);
        let flow = OAuthFlow::Authorized {
            config: cfg(),
            token: bundle,
        }
        .fail(format!("provider echoed {secret}"));

        let OAuthFlow::Failed { reason } = flow else {
            panic!("expected failed state");
        };
        assert!(!reason.as_str().contains(secret), "{reason}");
        assert!(reason.as_str().contains(crate::secrets::REDACTED_SECRET));
    }

    #[test]
    fn token_bundle_expiry_math() {
        let bundle = TokenBundle {
            access_token: token("a"),
            refresh_token: None,
            expires_in_secs: 100,
            obtained_at: TokenBundle::now_epoch().saturating_sub(50),
            token_type: "Bearer".into(),
            scope: String::new(),
        };
        assert!(!bundle.is_expired());
        // Within the safety window (50s left, 60s window) → refresh now.
        assert!(bundle.needs_refresh(Duration::from_mins(1)));
        // Outside the safety window → no refresh yet.
        assert!(!bundle.needs_refresh(Duration::from_secs(10)));

        let stale = TokenBundle {
            access_token: token("a"),
            refresh_token: None,
            expires_in_secs: 1,
            obtained_at: TokenBundle::now_epoch().saturating_sub(3600),
            token_type: "Bearer".into(),
            scope: String::new(),
        };
        assert!(stale.is_expired());
    }

    #[test]
    fn token_bundle_generic_json_is_redacted_and_not_reloadable() {
        let bundle = good_token();
        let s = serde_json::to_string(&bundle).unwrap();
        assert!(!s.contains("\"at\""));
        assert!(!s.contains("\"rt\""));
        assert!(serde_json::from_str::<TokenBundle>(&s).is_err());
    }

    #[test]
    fn token_bundle_default_token_type() {
        // Missing `token_type` in JSON defaults to "Bearer" so historical
        // bundles persisted before we tracked the field still load.
        let json = r#"{"access_token":"a","expires_in_secs":60,"obtained_at":0}"#;
        let bundle: TokenBundle = serde_json::from_str(json).unwrap();
        assert_eq!(bundle.token_type, "Bearer");
    }
}
