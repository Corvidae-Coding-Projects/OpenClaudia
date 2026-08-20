//! MCP / XAA / `IdP` OAuth login state machine (crosslink #616).
//!
//! This module owns the *protocol* side of OAuth for MCP servers: token
//! shape, PKCE-state lifecycle, and the explicit state transitions a flow
//! goes through (`Idle → AwaitingAuthorization → Exchanging → Authorized /
//! Failed`). Network I/O lives in a separate concrete `Provider` impl that
//! plugs in once OC has settled on which HTTP client / browser-launch
//! strategy it wants — we keep the seam abstract here so #616's first
//! landing is reviewable in isolation.
//!
//! ## Why a state machine
//!
//! OAuth flows are easy to get subtly wrong: code injection by reusing a
//! stale `code_verifier`, token write-after-clear races, accepting an
//! authorization response from a different state nonce. Encoding the flow
//! as an enum with `next_*` transitions forbids the "I'll just stash a few
//! fields on the struct" pattern that produces those classes of bug.
//!
//! ## What ships now
//!
//! * `TokenBundle` — the token shape every callsite reads.
//! * `OAuthFlow` — the state enum + builder.
//! * `next_*` transition methods that consume the previous state and return
//!   a new one, so a stale state value cannot be replayed.
//! * `is_expired` / `needs_refresh` helpers with a configurable safety
//!   window so refresh can happen *before* the upstream rejects a request.
//!
//! What is intentionally *out of scope* for the schema-only landing:
//!
//! * Concrete HTTP calls to the authorization / token endpoints.
//! * Browser launch (`open` crate) and loopback redirect listener.
//! * Persistence of the resulting `TokenBundle` to keyring / file.
//!
//! Those land as a separate `crate::mcp_oauth::http` submodule once the
//! transport choice is settled. The state machine here is the dispatch seam
//! they bind against.

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

#[cfg(test)]
mod tests {
    use super::*;

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
