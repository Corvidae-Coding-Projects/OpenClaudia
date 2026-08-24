//! Read-only Claude Code credential compatibility for Anthropic authentication.
//!
//! Valid credentials from Claude Code's store (`~/.claude/.credentials.json`)
//! can be used directly with the Anthropic Messages API. Claude Code owns that
//! document and its OAuth lifecycle: `OpenClaudia` never refreshes, normalizes,
//! locks, or writes it. Expired or nearly expired credentials direct the user
//! back to `claude auth login`.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::debug;

/// OAuth beta header required when using subscriber tokens
pub const OAUTH_BETA_HEADER: &str = "oauth-2025-04-20";

/// Claude Code beta header for agentic queries
pub const CLAUDE_CODE_BETA_HEADER: &str = "claude-code-20250219";

/// Interleaved thinking beta
pub const INTERLEAVED_THINKING_BETA: &str = "interleaved-thinking-2025-05-14";

/// Fine-grained tool streaming beta
pub const FINE_GRAINED_TOOL_STREAMING_BETA: &str = "fine-grained-tool-streaming-2025-05-14";

/// The canonical `anthropic-beta` header value sent on every OAuth request.
///
/// All OAuth code paths **must** call this function instead of interpolating
/// individual constants, so that adding or removing a beta flag is a
/// single-file change with no risk of drift. See crosslink #272.
///
/// # Examples
///
/// ```
/// use openclaudia::claude_credentials::claude_code_beta_header_value;
/// let v = claude_code_beta_header_value();
/// assert!(v.contains("oauth-2025-04-20"));
/// assert!(v.contains("claude-code-20250219"));
/// ```
#[must_use]
pub fn claude_code_beta_header_value() -> String {
    format!(
        "{CLAUDE_CODE_BETA_HEADER},{OAUTH_BETA_HEADER},{INTERLEAVED_THINKING_BETA},{FINE_GRAINED_TOOL_STREAMING_BETA}"
    )
}

/// Five-minute margin in which Claude Code should refresh its own credentials.
const REFRESH_BUFFER_MS: i64 = 5 * 60 * 1000;

const CREDENTIALS_FILENAME: &str = ".credentials.json";

/// Credential structure matching Claude Code's `~/.claude/.credentials.json`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialsFile {
    #[serde(rename = "claudeAiOauth")]
    pub claude_ai_oauth: Option<ClaudeAiOauth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeAiOauth {
    #[serde(rename = "accessToken")]
    pub access_token: crate::secrets::OAuthToken,
    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<crate::secrets::OAuthToken>,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64, // milliseconds since epoch
    pub scopes: Vec<String>,
    #[serde(rename = "subscriptionType")]
    pub subscription_type: Option<String>,
    #[serde(rename = "rateLimitTier")]
    pub rate_limit_tier: Option<String>,
}

/// Result of loading credentials
#[derive(Debug, Clone)]
pub struct LoadedCredentials {
    pub access_token: crate::secrets::OAuthToken,
    pub subscription_type: Option<String>,
    pub rate_limit_tier: Option<String>,
    pub scopes: Vec<String>,
}

/// Resolve the Claude-compatible config directory.
///
/// `OpenClaudia` already uses `CLAUDE_CONFIG_HOME_DIR` for transcript
/// compatibility. `CLAUDE_CONFIG_DIR` is accepted as a compatibility alias for
/// Claude Code forks that use that spelling.
fn claude_config_dir() -> Option<PathBuf> {
    std::env::var_os("CLAUDE_CONFIG_HOME_DIR")
        .filter(|dir| !dir.is_empty())
        .or_else(|| std::env::var_os("CLAUDE_CONFIG_DIR").filter(|dir| !dir.is_empty()))
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".claude")))
}

/// Get the path to Claude Code's credentials file.
#[must_use]
pub fn credentials_path() -> Option<PathBuf> {
    claude_config_dir().map(|dir| dir.join(CREDENTIALS_FILENAME))
}

/// Check if Claude Code credentials exist
#[must_use]
pub fn has_claude_code_credentials() -> bool {
    credentials_path().is_some_and(|p| p.exists())
}

/// Typed failures from the read-only Claude Code credential adapter.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClaudeCredentialError {
    /// No Claude-compatible configuration directory could be resolved.
    #[error("cannot determine the Claude Code config directory; run `claude auth login`")]
    LocationUnavailable,
    /// Claude Code has not published a credential document.
    #[error("Claude Code credentials not found at {}; run `claude auth login`", path.display())]
    Missing { path: PathBuf },
    /// Descriptor-safe validation or reading failed.
    #[error("could not safely read Claude Code credentials at {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: crate::persistence::PersistenceError,
    },
    /// A portable read-only fallback could not read the document.
    #[error("could not read Claude Code credentials at {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The foreign document did not name a regular, direct file.
    #[error("refusing to read unsafe Claude Code credential path {}: {reason}", path.display())]
    UnsafePath { path: PathBuf, reason: &'static str },
    /// The foreign document exceeded the explicit credential ceiling.
    #[error(
        "Claude Code credential file {} is {actual_bytes} bytes, exceeding the {max_bytes}-byte limit",
        path.display()
    )]
    TooLarge {
        path: PathBuf,
        actual_bytes: u64,
        max_bytes: u64,
    },
    /// Claude Code replaced the document while it was being observed.
    #[error(
        "Claude Code credentials at {} changed while being read; retry after Claude Code finishes updating them",
        path.display()
    )]
    ChangedDuringRead { path: PathBuf },
    /// The credential document was not valid JSON for the compatibility schema.
    #[error("invalid Claude Code credential document at {}: {source}", path.display())]
    InvalidDocument {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    /// The document did not include Claude's OAuth record.
    #[error(
        "Claude Code credentials at {} have no claudeAiOauth section; run `claude auth login`",
        path.display()
    )]
    MissingOauthSection { path: PathBuf },
    /// The token cannot authorize inference requests.
    #[error(
        "Claude Code credentials at {} lack the 'user:inference' scope; run `claude auth login`",
        path.display()
    )]
    MissingInferenceScope { path: PathBuf },
    /// The access token is no longer valid.
    #[error(
        "Claude Code credentials at {} expired at {expires_at_ms}; run `claude auth login` to refresh them",
        path.display()
    )]
    Expired { path: PathBuf, expires_at_ms: i64 },
    /// The access token is too close to expiry for a new agent operation.
    #[error(
        "Claude Code credentials at {} expire soon at {expires_at_ms}; run `claude auth login` to refresh them",
        path.display()
    )]
    ExpiresSoon { path: PathBuf, expires_at_ms: i64 },
}

#[cfg(unix)]
fn read_credentials_document(
    config_dir: &Path,
    before_confirmation: impl FnOnce(),
) -> Result<Option<CredentialsFile>, ClaudeCredentialError> {
    let path = config_dir.join(CREDENTIALS_FILENAME);
    match std::fs::symlink_metadata(config_dir) {
        Ok(_) => {}
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(ClaudeCredentialError::Io { path, source }),
    }

    let storage = crate::persistence::PersistentStorage::open(config_dir).map_err(|source| {
        ClaudeCredentialError::Read {
            path: path.clone(),
            source,
        }
    })?;
    let first = storage
        .read(
            CREDENTIALS_FILENAME,
            crate::persistence::FileClass::Credentials,
        )
        .map_err(|source| ClaudeCredentialError::Read {
            path: path.clone(),
            source,
        })?;
    if first.bytes().is_none() {
        return Ok(None);
    }

    before_confirmation();
    let confirmed = storage
        .read(
            CREDENTIALS_FILENAME,
            crate::persistence::FileClass::Credentials,
        )
        .map_err(|source| ClaudeCredentialError::Read {
            path: path.clone(),
            source,
        })?;
    if first.generation() != confirmed.generation() {
        return Err(ClaudeCredentialError::ChangedDuringRead { path });
    }

    first
        .expose_bytes(|bytes| {
            let bytes = bytes.expect("present read state must expose credential bytes");
            serde_json::from_slice(bytes)
        })
        .map(Some)
        .map_err(|source| ClaudeCredentialError::InvalidDocument { path, source })
}

#[cfg(not(unix))]
fn read_credentials_document(
    config_dir: &Path,
    before_confirmation: impl FnOnce(),
) -> Result<Option<CredentialsFile>, ClaudeCredentialError> {
    let path = config_dir.join(CREDENTIALS_FILENAME);
    let first = read_credentials_portable(&path)?;
    let Some(first) = first else {
        return Ok(None);
    };
    before_confirmation();
    let confirmed = read_credentials_portable(&path)?;
    if confirmed.as_ref().map(|bytes| bytes.as_slice()) != Some(first.as_slice()) {
        return Err(ClaudeCredentialError::ChangedDuringRead { path });
    }
    serde_json::from_slice(&first)
        .map(Some)
        .map_err(|source| ClaudeCredentialError::InvalidDocument { path, source })
}

#[cfg(not(unix))]
fn read_credentials_portable(
    path: &Path,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, ClaudeCredentialError> {
    use std::io::Read as _;

    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ClaudeCredentialError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(ClaudeCredentialError::UnsafePath {
            path: path.to_path_buf(),
            reason: "the credential file is a symlink",
        });
    }
    if !metadata.is_file() {
        return Err(ClaudeCredentialError::UnsafePath {
            path: path.to_path_buf(),
            reason: "the credential path is not a regular file",
        });
    }

    let max_bytes = crate::persistence::FileClass::Credentials.max_bytes();
    if metadata.len() > max_bytes {
        return Err(ClaudeCredentialError::TooLarge {
            path: path.to_path_buf(),
            actual_bytes: metadata.len(),
            max_bytes,
        });
    }
    let file = std::fs::File::open(path).map_err(|source| ClaudeCredentialError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| ClaudeCredentialError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let actual_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual_bytes > max_bytes {
        return Err(ClaudeCredentialError::TooLarge {
            path: path.to_path_buf(),
            actual_bytes,
            max_bytes,
        });
    }
    Ok(Some(bytes))
}

fn load_credentials_from_dir_at(
    config_dir: &Path,
    now_ms: i64,
    before_confirmation: impl FnOnce(),
) -> Result<LoadedCredentials, ClaudeCredentialError> {
    let path = config_dir.join(CREDENTIALS_FILENAME);
    let creds = read_credentials_document(config_dir, before_confirmation)?
        .ok_or_else(|| ClaudeCredentialError::Missing { path: path.clone() })?;
    let oauth = creds
        .claude_ai_oauth
        .ok_or_else(|| ClaudeCredentialError::MissingOauthSection { path: path.clone() })?;

    if !oauth.scopes.iter().any(|scope| scope == "user:inference") {
        return Err(ClaudeCredentialError::MissingInferenceScope { path });
    }
    if now_ms >= oauth.expires_at {
        return Err(ClaudeCredentialError::Expired {
            path,
            expires_at_ms: oauth.expires_at,
        });
    }
    if now_ms.saturating_add(REFRESH_BUFFER_MS) >= oauth.expires_at {
        return Err(ClaudeCredentialError::ExpiresSoon {
            path,
            expires_at_ms: oauth.expires_at,
        });
    }

    debug!(
        "Claude Code credentials loaded read-only (expires in {}s, type: {:?})",
        (oauth.expires_at - now_ms) / 1000,
        oauth.subscription_type
    );
    Ok(LoadedCredentials {
        access_token: oauth.access_token,
        subscription_type: oauth.subscription_type,
        rate_limit_tier: oauth.rate_limit_tier,
        scopes: oauth.scopes,
    })
}

/// Load a valid Claude Code access token without mutating its credential store.
///
/// Returns the access token ready for use as `Authorization: Bearer <token>`.
/// Claude Code remains responsible for refreshing near-expiry or expired
/// credentials.
///
/// # Errors
///
/// Returns a typed error when the store is missing, unsafe, malformed, stale,
/// replaced during observation, or lacks the inference scope.
pub fn load_credentials() -> Result<LoadedCredentials, ClaudeCredentialError> {
    let config_dir = claude_config_dir().ok_or(ClaudeCredentialError::LocationUnavailable)?;
    load_credentials_from_dir_at(&config_dir, chrono::Utc::now().timestamp_millis(), || {})
}

/// Read-only credential status used by `openclaudia auth --status`.
#[derive(Debug, Clone)]
pub struct CredentialStatus {
    /// Token expiry as milliseconds since Unix epoch.
    pub expires_at_ms: i64,
    /// Whether the token is already expired.
    pub expired: bool,
    /// Whether the token is within the refresh buffer.
    pub expires_soon: bool,
    /// Whether the credential has the chat-required `user:inference` scope.
    pub has_inference_scope: bool,
    /// Recorded subscription type, when present.
    pub subscription_type: Option<String>,
    /// Recorded rate-limit tier, when present.
    pub rate_limit_tier: Option<String>,
}

/// Inspect the shared Claude credential store without mutating it.
///
/// # Errors
///
/// Returns an error when an existing credential file is unsafe, unreadable,
/// malformed, or replaced during observation.
pub fn peek_credentials() -> Result<Option<CredentialStatus>, ClaudeCredentialError> {
    let Some(config_dir) = claude_config_dir() else {
        return Ok(None);
    };
    let Some(creds) = read_credentials_document(&config_dir, || {})? else {
        return Ok(None);
    };
    let Some(oauth) = creds.claude_ai_oauth else {
        return Ok(None);
    };

    Ok(Some(status_from_oauth(
        &oauth,
        chrono::Utc::now().timestamp_millis(),
    )))
}

fn status_from_oauth(oauth: &ClaudeAiOauth, now_ms: i64) -> CredentialStatus {
    CredentialStatus {
        expires_at_ms: oauth.expires_at,
        expired: now_ms >= oauth.expires_at,
        expires_soon: now_ms < oauth.expires_at
            && now_ms.saturating_add(REFRESH_BUFFER_MS) >= oauth.expires_at,
        has_inference_scope: oauth.scopes.iter().any(|scope| scope == "user:inference"),
        subscription_type: oauth.subscription_type.clone(),
        rate_limit_tier: oauth.rate_limit_tier.clone(),
    }
}

/// Build the HTTP headers for Anthropic API with OAuth Bearer auth.
///
/// These headers replace the `x-api-key` header used with API keys.
#[must_use]
pub fn get_oauth_headers(
    access_token: &crate::secrets::OAuthToken,
) -> crate::secrets::SensitiveHeaders {
    crate::providers::AnthropicAdapter::oauth_headers(access_token)
}

/// Get the API endpoint for OAuth-authenticated requests.
#[must_use]
pub fn get_oauth_endpoint(_model: &str) -> String {
    "https://api.anthropic.com/v1/messages".to_string()
}

/// The system prompt prefix that must be present for OAuth tokens to access premium models.
///
/// The Anthropic API validates this exact string. Must be in its own system
/// block — do NOT append to this.
///
/// # Crosslink #923 — why this constant lives here (deliberate coupling)
///
/// The QA review flagged this constant as a decoupling violation: a
/// `claude_credentials` module injects content into the system prompt the
/// prompt-builder is unaware of, and the literal string couples
/// `OpenClaudia`'s identity attestation to a specific Anthropic policy.
///
/// We have accepted the feedback but kept the current shape, for the
/// following reasons:
///
/// 1. **The string IS an OAuth credential.** The Anthropic OAuth endpoint
///    refuses requests whose first system block does not contain exactly
///    this literal. The string is therefore part of the OAuth contract
///    (alongside the bearer token and `anthropic-beta` header), not a
///    free-form prompt fragment, and so belongs in the credentials module
///    that owns the rest of that contract.
/// 2. **Single source of truth.** Every OAuth-authenticated transport uses
///    `inject_oauth_prefix_only`; behavioral context is assembled separately
///    by the typed prompt authority boundary.
/// 3. **Operational risk is bounded.** If Anthropic changes the literal,
///    the failure mode is a 401 from `/v1/messages` with a clear server
///    message ("invalid system prefix") — not a silent degradation.
///    Updating the constant is a one-line fix in one file.
///
/// The prefix remains a provider-protocol compatibility credential, not a
/// general prompt extension API.
pub const CLAUDE_CODE_SYSTEM_PROMPT: &str =
    "You are Claude Code, Anthropic's official CLI for Claude.";

/// Inject only the Claude Code prefix block required for OAuth tokens.
///
/// Block 0: The exact one-liner prefix (API validates this string for OAuth)
/// Block 1+: Whatever was already in the system field (preserved as-is)
///
/// This does not prepend behavioral prose. It is the minimum mutation required
/// for the Anthropic API to accept an OAuth Bearer request; caller/system
/// context remains owned by the typed prompt or proxy boundary.
///
/// Centralized here so that the magic-string prefix and the three-way
/// match on the existing `system` shape live in one place. Previously
/// inlined into `proxy::proxy_anthropic_messages` — see crosslink #386.
pub fn inject_oauth_prefix_only(request: &mut serde_json::Value) {
    let prefix_block = serde_json::json!({
        "type": "text",
        "text": CLAUDE_CODE_SYSTEM_PROMPT,
    });

    match request.get_mut("system") {
        Some(serde_json::Value::Array(arr)) => {
            arr.insert(0, prefix_block);
        }
        Some(serde_json::Value::String(existing)) => {
            let existing_obj = serde_json::json!({
                "type": "text",
                "text": existing.clone(),
            });
            request["system"] = serde_json::json!([prefix_block, existing_obj]);
        }
        _ => {
            request["system"] = serde_json::json!([prefix_block]);
        }
    }
}

/// Maximum recursion depth for [`strip_cache_control_ttl`].
///
/// Matches the cap used by `hooks::merge::deep_merge` (crosslink #333).
/// Realistic Anthropic Messages API request bodies bottom out at <10
/// levels of nesting (system / messages / content blocks / tool inputs);
/// 32 leaves ample headroom while preventing a hostile request body
/// from blowing the stack via unbounded JSON nesting (crosslink #805).
pub(crate) const MAX_STRIP_DEPTH: usize = 32;

/// Recursively strip `ttl` from any `cache_control` objects in a JSON
/// value.
///
/// The Anthropic Messages API rejects `cache_control.ttl` when the
/// request is authenticated with an OAuth Bearer token (the field is
/// only legal under `x-api-key` auth on accounts with the appropriate
/// entitlement). Co-located with [`inject_oauth_prefix_only`] because
/// the two are co-requisites of every OAuth-authenticated request —
/// see crosslink #386.
///
/// Recursion is capped at [`MAX_STRIP_DEPTH`] levels. A hostile request
/// body containing thousands of nested arrays or objects would
/// otherwise overflow the stack before `serde_json` itself bailed
/// (crosslink #805). On reaching the cap we emit a `warn!` with the
/// JSON path that triggered the cutoff and stop recursing into that
/// subtree; any `cache_control.ttl` deeper than the cap is left in
/// place, which the upstream API will reject with a 400 — strictly
/// safer than crashing the proxy.
pub fn strip_cache_control_ttl(value: &mut serde_json::Value) {
    strip_cache_control_ttl_inner(value, 0, "$");
}

fn strip_cache_control_ttl_inner(value: &mut serde_json::Value, depth: usize, path: &str) {
    if depth >= MAX_STRIP_DEPTH {
        tracing::warn!(
            path = %path,
            limit = MAX_STRIP_DEPTH,
            "strip_cache_control_ttl depth cap reached; refusing to recurse further (crosslink #805)",
        );
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::Object(cc_map)) = map.get_mut("cache_control") {
                cc_map.remove("ttl");
            }
            for (k, v) in map.iter_mut() {
                let child_path = format!("{path}.{k}");
                strip_cache_control_ttl_inner(v, depth + 1, &child_path);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter_mut().enumerate() {
                let child_path = format!("{path}[{i}]");
                strip_cache_control_ttl_inner(v, depth + 1, &child_path);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(value: &str) -> crate::secrets::OAuthToken {
        crate::secrets::OAuthToken::try_from_string(value.to_string()).expect("valid test token")
    }

    #[test]
    fn test_credentials_path() {
        let path = credentials_path();
        assert!(path.is_some());
        let p = path.unwrap();
        assert_eq!(
            p.file_name().and_then(|s| s.to_str()),
            Some(".credentials.json")
        );
    }

    #[test]
    fn test_parse_credentials() {
        let json = r#"{
            "claudeAiOauth": {
                "accessToken": "test-token",
                "refreshToken": "test-refresh",
                "expiresAt": 9999999999999,
                "scopes": ["user:inference", "user:profile"],
                "subscriptionType": "max",
                "rateLimitTier": "default_claude_max_20x"
            }
        }"#;

        let creds: CredentialsFile = serde_json::from_str(json).unwrap();
        let oauth = creds.claude_ai_oauth.unwrap();
        assert!(oauth.access_token.matches("test-token"));
        assert!(oauth
            .refresh_token
            .as_ref()
            .is_some_and(|token| token.matches("test-refresh")));
        assert_eq!(oauth.subscription_type, Some("max".to_string()));
        assert!(oauth.scopes.contains(&"user:inference".to_string()));
    }

    #[test]
    fn test_parse_credentials_no_oauth() {
        let json = r"{}";
        let creds: CredentialsFile = serde_json::from_str(json).unwrap();
        assert!(creds.claude_ai_oauth.is_none());
    }

    #[test]
    fn test_get_oauth_headers() {
        let headers = get_oauth_headers(&token("test-token-123"));
        assert!(headers.matches_value("Authorization", "Bearer test-token-123"));
        assert!(headers.matches_value("anthropic-beta", &claude_code_beta_header_value()));
        assert!(headers.matches_value("anthropic-version", "2023-06-01"));
    }

    #[test]
    fn test_has_credentials_function() {
        // Just verify it doesn't panic
        let _ = has_claude_code_credentials();
    }

    #[cfg(unix)]
    fn credential_fixture(expires_at_ms: i64, access_token: &str) -> Vec<u8> {
        format!(
            r#"{{
  "claudeAiOauth": {{
    "accessToken": "{access_token}",
    "refreshToken": "fixture-refresh-token",
    "expiresAt": {expires_at_ms},
    "refreshTokenExpiresAt": 4102444800000,
    "scopes": ["user:inference", "user:profile"],
    "subscriptionType": "max",
    "rateLimitTier": "fixture-tier",
    "ownerMetadata": {{"mustRemain": true}}
  }},
  "foreignTopLevel": ["preserve", 7]
}}"#
        )
        .into_bytes()
    }

    #[cfg(unix)]
    fn write_private(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn valid_foreign_credentials_are_loaded_without_changing_unknown_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIALS_FILENAME);
        let original = credential_fixture(2_000_000, "fixture-access-token");
        write_private(&path, &original);

        let loaded = load_credentials_from_dir_at(dir.path(), 1_000_000, || {}).unwrap();

        assert!(loaded.access_token.matches("fixture-access-token"));
        assert_eq!(loaded.subscription_type.as_deref(), Some("max"));
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn stale_foreign_credentials_return_recovery_errors_without_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIALS_FILENAME);
        let expired = credential_fixture(999_999, "expired-access-token");
        write_private(&path, &expired);
        let error = load_credentials_from_dir_at(dir.path(), 1_000_000, || {}).unwrap_err();
        assert!(matches!(error, ClaudeCredentialError::Expired { .. }));
        assert!(error.to_string().contains("claude auth login"));
        assert_eq!(std::fs::read(&path).unwrap(), expired);

        let expiring =
            credential_fixture(1_000_000 + REFRESH_BUFFER_MS - 1, "expiring-access-token");
        write_private(&path, &expiring);
        let error = load_credentials_from_dir_at(dir.path(), 1_000_000, || {}).unwrap_err();
        assert!(matches!(error, ClaudeCredentialError::ExpiresSoon { .. }));
        assert!(error.to_string().contains("claude auth login"));
        assert_eq!(std::fs::read(&path).unwrap(), expiring);
    }

    #[cfg(unix)]
    #[test]
    fn missing_inference_scope_is_typed_and_does_not_change_foreign_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIALS_FILENAME);
        let original = String::from_utf8(credential_fixture(2_000_000, "fixture-access-token"))
            .unwrap()
            .replace("user:inference", "user:account");
        write_private(&path, original.as_bytes());

        let error = load_credentials_from_dir_at(dir.path(), 1_000_000, || {}).unwrap_err();

        assert!(matches!(
            error,
            ClaudeCredentialError::MissingInferenceScope { .. }
        ));
        assert!(error.to_string().contains("claude auth login"));
        assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn group_readable_foreign_credentials_are_rejected_without_writes() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIALS_FILENAME);
        let original = credential_fixture(2_000_000, "fixture-access-token");
        write_private(&path, &original);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let error = load_credentials_from_dir_at(dir.path(), 1_000_000, || {}).unwrap_err();
        assert!(matches!(error, ClaudeCredentialError::Read { .. }));
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_foreign_credentials_are_rejected_without_writes() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real-credentials.json");
        let path = dir.path().join(CREDENTIALS_FILENAME);
        let original = credential_fixture(2_000_000, "fixture-access-token");
        write_private(&target, &original);
        symlink(&target, &path).unwrap();

        let error = load_credentials_from_dir_at(dir.path(), 1_000_000, || {}).unwrap_err();
        assert!(matches!(error, ClaudeCredentialError::Read { .. }));
        assert_eq!(std::fs::read(&target).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_foreign_replacement_is_reported_without_openclaudia_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIALS_FILENAME);
        let replacement_path = dir.path().join("replacement.json");
        let original = credential_fixture(2_000_000, "original-access-token");
        let replacement = credential_fixture(3_000_000, "replacement-access-token");
        write_private(&path, &original);
        write_private(&replacement_path, &replacement);

        let error = load_credentials_from_dir_at(dir.path(), 1_000_000, || {
            std::fs::rename(&replacement_path, &path).unwrap();
        })
        .unwrap_err();

        assert!(matches!(
            error,
            ClaudeCredentialError::ChangedDuringRead { .. }
        ));
        assert_eq!(std::fs::read(&path).unwrap(), replacement);
    }

    #[test]
    fn status_from_oauth_flags_expiry_refresh_buffer_and_scope() {
        let base = ClaudeAiOauth {
            access_token: token("token"),
            refresh_token: None,
            expires_at: REFRESH_BUFFER_MS * 100,
            scopes: vec!["user:inference".into(), "user:profile".into()],
            subscription_type: Some("pro".into()),
            rate_limit_tier: None,
        };

        let far = status_from_oauth(&base, 0);
        assert!(!far.expired);
        assert!(!far.expires_soon);
        assert!(far.has_inference_scope);
        assert_eq!(far.subscription_type.as_deref(), Some("pro"));
        assert_eq!(far.rate_limit_tier, None);

        let expired = ClaudeAiOauth {
            expires_at: 100,
            ..base.clone()
        };
        let expired_status = status_from_oauth(&expired, 200);
        assert!(expired_status.expired);
        assert!(!expired_status.expires_soon);

        let soon = ClaudeAiOauth {
            expires_at: REFRESH_BUFFER_MS,
            ..base.clone()
        };
        let soon_status = status_from_oauth(&soon, 1);
        assert!(!soon_status.expired);
        assert!(soon_status.expires_soon);

        let no_inference = ClaudeAiOauth {
            scopes: vec!["user:profile".into()],
            ..base
        };
        assert!(!status_from_oauth(&no_inference, 0).has_inference_scope);
    }

    // --- Regression guard for crosslink #272: beta-header string drift ---

    #[test]
    fn beta_header_consts_have_expected_values() {
        assert_eq!(CLAUDE_CODE_BETA_HEADER, "claude-code-20250219");
        assert_eq!(OAUTH_BETA_HEADER, "oauth-2025-04-20");
        assert_eq!(INTERLEAVED_THINKING_BETA, "interleaved-thinking-2025-05-14");
        assert_eq!(
            FINE_GRAINED_TOOL_STREAMING_BETA,
            "fine-grained-tool-streaming-2025-05-14"
        );
    }

    #[test]
    fn claude_code_beta_header_value_contains_all_flags() {
        let v = claude_code_beta_header_value();
        assert!(
            v.contains("claude-code-20250219"),
            "missing claude-code beta in: {v}"
        );
        assert!(v.contains("oauth-2025-04-20"), "missing oauth beta in: {v}");
        assert!(
            v.contains("interleaved-thinking-2025-05-14"),
            "missing interleaved-thinking beta in: {v}"
        );
        assert!(
            v.contains("fine-grained-tool-streaming-2025-05-14"),
            "missing fine-grained-tool-streaming beta in: {v}"
        );
    }

    #[test]
    fn get_oauth_headers_beta_includes_fine_grained_tool_streaming() {
        let headers = get_oauth_headers(&token("tok"));
        assert_eq!(
            headers.with_value("anthropic-beta", |value| value
                .contains("fine-grained-tool-streaming-2025-05-14")),
            Some(true)
        );
    }

    // --- Regression guards for crosslink #386: decomposition of
    // proxy_anthropic_messages. These tests pin the wire-level behavior
    // that was previously inlined into the proxy handler, so any future
    // edit to the helpers preserves what subscriber clients observe.

    /// Spec — `inject_oauth_prefix_only` prepends the exact prefix block
    /// when `system` is already an array (preserves existing blocks).
    #[test]
    fn inject_oauth_prefix_only_prepends_to_array() {
        let mut req = serde_json::json!({
            "system": [{"type": "text", "text": "user-provided"}]
        });
        inject_oauth_prefix_only(&mut req);
        let arr = req["system"].as_array().expect("system must be array");
        assert_eq!(arr.len(), 2, "must prepend exactly one block");
        assert_eq!(arr[0]["text"], CLAUDE_CODE_SYSTEM_PROMPT);
        assert_eq!(arr[1]["text"], "user-provided");
    }

    /// Spec — `inject_oauth_prefix_only` upgrades a string `system` to a
    /// two-block array (prefix, then the original string).
    #[test]
    fn inject_oauth_prefix_only_upgrades_string() {
        let mut req = serde_json::json!({"system": "you are helpful"});
        inject_oauth_prefix_only(&mut req);
        let arr = req["system"].as_array().expect("system must be array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["text"], CLAUDE_CODE_SYSTEM_PROMPT);
        assert_eq!(arr[1]["text"], "you are helpful");
    }

    /// Spec — `inject_oauth_prefix_only` creates a one-block array when
    /// `system` is missing entirely.
    #[test]
    fn inject_oauth_prefix_only_creates_when_absent() {
        let mut req = serde_json::json!({});
        inject_oauth_prefix_only(&mut req);
        let arr = req["system"].as_array().expect("system must be array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["text"], CLAUDE_CODE_SYSTEM_PROMPT);
    }

    /// Spec — `inject_oauth_prefix_only` does not inject a second behavioral
    /// prompt. Behavioral context comes from the typed context projector.
    #[test]
    fn inject_oauth_prefix_only_does_not_add_behavioral_block() {
        let mut req = serde_json::json!({});
        inject_oauth_prefix_only(&mut req);
        let arr = req["system"].as_array().expect("system must be array");
        assert_eq!(arr.len(), 1, "must be prefix-only, not prefix+behavioral");
    }

    /// Spec — `strip_cache_control_ttl` removes `ttl` from nested
    /// `cache_control` objects (the OAuth API rejects TTL).
    #[test]
    fn strip_cache_control_ttl_removes_nested_ttl() {
        let mut value = serde_json::json!({
            "system": [
                {
                    "type": "text",
                    "text": "hello",
                    "cache_control": { "type": "ephemeral", "ttl": 3600 }
                }
            ]
        });
        strip_cache_control_ttl(&mut value);
        let cc = &value["system"][0]["cache_control"];
        assert_eq!(cc["type"], "ephemeral", "type must be preserved");
        assert!(
            cc.get("ttl").is_none(),
            "ttl must be stripped from cache_control"
        );
    }

    /// Spec — `strip_cache_control_ttl` is a no-op when no `ttl` is
    /// present.
    #[test]
    fn strip_cache_control_ttl_noop_when_no_ttl() {
        let mut value = serde_json::json!({
            "cache_control": { "type": "ephemeral" }
        });
        strip_cache_control_ttl(&mut value);
        assert_eq!(value["cache_control"]["type"], "ephemeral");
    }

    // ────────────────────────────────────────────────────────────────
    // Regression tests for crosslink #805: unbounded recursion in
    // `strip_cache_control_ttl` would let a hostile request body
    // (deeply nested objects or arrays) blow the stack. The fix caps
    // recursion at MAX_STRIP_DEPTH levels.
    // ────────────────────────────────────────────────────────────────

    /// A 1000-level nested array would previously recurse 1000 frames
    /// deep and could overflow the stack on smaller-stack platforms.
    /// With the cap, the call returns cleanly without panicking.
    #[test]
    fn strip_cache_control_ttl_rejects_1000_level_nesting_without_stack_overflow() {
        // Build [[[…[]…]]] 1000 levels deep.
        let mut value = serde_json::Value::Array(Vec::new());
        for _ in 0..1000u16 {
            value = serde_json::Value::Array(vec![value]);
        }
        // Must not panic / stack-overflow.
        strip_cache_control_ttl(&mut value);
    }

    /// At the depth cap, anything beyond is intentionally not visited
    /// — so a `cache_control.ttl` planted at depth > cap survives
    /// (and the API will 400, which is strictly safer than crashing).
    #[test]
    fn strip_cache_control_ttl_does_not_visit_past_depth_cap() {
        // Wrap a cache_control object inside MAX_STRIP_DEPTH + 5 arrays.
        let payload = serde_json::json!({
            "cache_control": { "type": "ephemeral", "ttl": 3600 }
        });
        let mut value = payload;
        for _ in 0..(MAX_STRIP_DEPTH + 5) {
            value = serde_json::Value::Array(vec![value]);
        }

        strip_cache_control_ttl(&mut value);

        // Unwrap back down to find the inner cache_control.
        let mut cursor = &value;
        while let Some(arr) = cursor.as_array() {
            if arr.is_empty() {
                break;
            }
            cursor = &arr[0];
        }
        // The ttl beyond the cap MUST still be present — proving the
        // cap actually stopped recursion (and that the function did
        // not silently rewrite arbitrary depth without bound). The
        // ttl lives inside `cache_control`, not at the top-level
        // cursor — we are testing that the cap prevented the
        // descent into the object that contains it.
        let cc = cursor
            .get("cache_control")
            .expect("cache_control object survives wrapping");
        let ttl = cc.get("ttl");
        assert!(
            ttl.is_some(),
            "ttl beyond depth cap should be left intact (cap stopped recursion), got cc={cc:?}",
        );
    }

    /// Just *under* the cap, the strip still happens — proving the
    /// cap is permissive enough for realistic request shapes. A real
    /// Anthropic Messages API request bottoms out at ~10 levels
    /// (system / messages / content blocks / tool inputs), so a 16-
    /// level test is comfortably realistic and well under the 32 cap.
    #[test]
    fn strip_cache_control_ttl_strips_within_depth_cap() {
        let mut inner = serde_json::json!({
            "cache_control": { "type": "ephemeral", "ttl": 3600 }
        });
        // Wrap in 16 layers of arrays — well under MAX_STRIP_DEPTH = 32.
        for _ in 0..16 {
            inner = serde_json::Value::Array(vec![inner]);
        }

        strip_cache_control_ttl(&mut inner);

        // Unwrap down to the cache_control object.
        let mut cursor = &inner;
        while let Some(arr) = cursor.as_array() {
            cursor = &arr[0];
        }
        let cc = cursor.get("cache_control").expect("cache_control survives");
        assert_eq!(cc["type"], "ephemeral");
        assert!(
            cc.get("ttl").is_none(),
            "ttl within depth cap MUST be stripped, got cc={cc:?}",
        );
    }

    /// Depth cap is exactly `MAX_STRIP_DEPTH` (boundary pin). At depth
    /// `MAX_STRIP_DEPTH - 1` we still descend; at `MAX_STRIP_DEPTH`
    /// we don't. A `cache_control` at *exactly* the cap depth survives
    /// (because depth incremented before the descend).
    #[test]
    fn strip_cache_control_ttl_depth_cap_boundary() {
        // 31 wraps means the inner `cache_control` object is visited
        // at depth = 31 (the loop increments once per array
        // descent), which is < MAX_STRIP_DEPTH (32) — so it strips.
        let mut value = serde_json::json!({
            "cache_control": { "type": "ephemeral", "ttl": 1 }
        });
        for _ in 0..(MAX_STRIP_DEPTH - 1) {
            value = serde_json::Value::Array(vec![value]);
        }
        strip_cache_control_ttl(&mut value);
        let mut cursor = &value;
        while let Some(arr) = cursor.as_array() {
            cursor = &arr[0];
        }
        assert!(
            cursor["cache_control"].get("ttl").is_none(),
            "ttl just under the cap must be stripped"
        );
    }
}
