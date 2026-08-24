//! Experimental OAuth 2.0 Device Flow Authentication for Claude subscriptions.
//!
//! This direct protocol implementation is unsupported by Anthropic and is not
//! part of `OpenClaudia`'s default subscription-authentication path. Operational
//! entry points require both the `experimental-claude-subscription-auth` Cargo
//! feature and the exact runtime acknowledgement documented by
//! [`crate::claude_credentials::experimental_direct_subscription_enabled`].
//! The supported default delegates authentication and transport ownership to
//! Anthropic's unmodified `claude` executable.
//!
//! ## Flow Overview
//! 1. Generate PKCE challenge and authorization URL
//! 2. User visits URL, authenticates with Claude, receives code
//! 3. Exchange code for access/refresh tokens
//! 4. Use Bearer token with OAuth beta header for API requests
//!
//! ## Important Notes
//! - Requires Claude Pro or Max subscription
//! - Access tokens expire, auto-refresh supported
//! - System prompt injection required for OAuth tokens

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use serde::ser::{SerializeMap as _, SerializeStruct as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, error, info};
use zeroize::Zeroizing;

/// Current on-disk schema for OpenClaudia-owned native OAuth sessions.
pub const OAUTH_STORE_SCHEMA_VERSION: u32 = 1;
const OAUTH_REFRESH_SKEW_SECS: i64 = 60;
const PENDING_GRANT_TTL_SECS: i64 = 10 * 60;
const MAX_PENDING_GRANTS: usize = 32;
const REQUIRED_INFERENCE_SCOPE: &str = "user:inference";

/// Clamp an OAuth `expires_in` value to a plausible window and convert
/// it to an absolute `DateTime<Utc>`.
///
/// The spec says `expires_in` is a positive integer number of seconds
/// but doesn't bound the value. Misconfigured or malicious servers
/// have returned:
///  * `0` / missing field — produces a session that is immediately
///    expired, leading to infinite 401-retry loops.
///  * `2^63` — would wrap via `.cast_signed()` to a negative duration
///    landing the session in the past.
///  * absurdly long values (e.g. `31_536_000_000` = 1000 years) — stores
///    a token on disk with no re-check.
///
/// We clamp to `[MIN_EXPIRES_IN_SECS, MAX_EXPIRES_IN_SECS]` and emit
/// `tracing::warn!` on any clamp so operators can diagnose a broken
/// upstream. See crosslink #480.
pub(crate) fn clamped_expires_at(expires_in: u64) -> DateTime<Utc> {
    const MIN_EXPIRES_IN_SECS: u64 = 60;
    const MAX_EXPIRES_IN_SECS: u64 = 30 * 24 * 3600; // 30 days

    let clamped = if expires_in < MIN_EXPIRES_IN_SECS {
        tracing::warn!(
            received = expires_in,
            clamped_to = MIN_EXPIRES_IN_SECS,
            "OAuth expires_in too small (< 60s); clamping to avoid 401-retry loop"
        );
        MIN_EXPIRES_IN_SECS
    } else if expires_in > MAX_EXPIRES_IN_SECS {
        tracing::warn!(
            received = expires_in,
            clamped_to = MAX_EXPIRES_IN_SECS,
            "OAuth expires_in too large (> 30d); clamping to refuse multi-year tokens"
        );
        MAX_EXPIRES_IN_SECS
    } else {
        expires_in
    };

    // `clamped` is now in [60, 2_592_000] — well within i64 range.
    #[allow(clippy::cast_possible_wrap)]
    let as_i64 = clamped as i64;
    Utc::now() + Duration::seconds(as_i64)
}

/// Anthropic's fixed OAuth client identifier
pub const ANTHROPIC_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

/// Fixed redirect URI for Anthropic OAuth
pub const ANTHROPIC_REDIRECT_URI: &str = "https://console.anthropic.com/oauth/code/callback";

/// OAuth authorization endpoint for personal Claude Max accounts
/// Use claude.ai for personal Max subscribers, console.anthropic.com for org accounts
pub const OAUTH_AUTHORIZE_URL: &str = "https://claude.ai/oauth/authorize";

/// Token exchange endpoint
pub const TOKEN_ENDPOINT: &str = "https://console.anthropic.com/v1/oauth/token";

/// API key creation endpoint - creates ephemeral API key from OAuth token
pub const API_KEY_ENDPOINT: &str = "https://api.anthropic.com/api/oauth/claude_cli/create_api_key";

/// OAuth scopes required for API access
/// Must include `user:sessions:claude_code` to get `org:create_api_key` permission
pub const OAUTH_SCOPES: &str =
    "org:create_api_key user:profile user:inference user:sessions:claude_code";

// ============================================================================
// PKCE (Proof Key for Code Exchange) Implementation
// ============================================================================

/// PKCE parameters for secure OAuth flow
#[derive(Debug, Clone)]
pub struct PkceParams {
    /// Random verifier string (kept secret, sent during token exchange)
    pub verifier: crate::secrets::SecretString,
    /// SHA256 hash of verifier (sent during authorization)
    pub challenge: String,
    /// Random state for CSRF protection
    pub state: crate::secrets::SecretString,
}

impl PkceParams {
    /// Generate new PKCE parameters with cryptographically secure randomness
    ///
    /// # Panics
    /// Panics only if the fixed-size URL-safe random verifier violates the
    /// internal secret invariant, which would indicate a programming defect.
    #[must_use]
    pub fn generate() -> Self {
        let verifier = crate::secrets::SecretString::try_from_string(generate_random_string(64))
            .expect("generated PKCE verifier must satisfy secret validation");
        let challenge = verifier.expose(compute_s256_challenge);
        let state = crate::secrets::SecretString::try_from_string(generate_random_string(64))
            .expect("generated OAuth state must satisfy secret validation");

        Self {
            verifier,
            challenge,
            state,
        }
    }

    /// Build the full authorization URL with all required parameters
    #[must_use]
    pub fn build_auth_url(&self) -> String {
        self.state.expose(|state| {
            let params = [
                ("code", "true"),
                ("client_id", ANTHROPIC_CLIENT_ID),
                ("response_type", "code"),
                ("redirect_uri", ANTHROPIC_REDIRECT_URI),
                ("scope", OAUTH_SCOPES),
                ("code_challenge", &self.challenge),
                ("code_challenge_method", "S256"),
                ("state", state),
            ];

            let query = params
                .iter()
                .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");

            format!("{OAUTH_AUTHORIZE_URL}?{query}")
        })
    }
}

/// Generate a cryptographically secure random string (base64url encoded)
fn generate_random_string(byte_length: usize) -> String {
    let mut bytes = vec![0u8; byte_length];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// Generate the opaque browser-client capability used to bind an OAuth grant
/// and its resulting session. Raw bytes belong only in an `HttpOnly` cookie.
///
/// # Panics
///
/// Panics only if URL-safe random output violates the secret-string invariant,
/// which would indicate a programming defect.
#[must_use]
pub fn generate_client_binding() -> crate::secrets::SecretString {
    crate::secrets::SecretString::try_from_string(generate_random_string(32))
        .expect("generated OAuth client binding must satisfy secret validation")
}

/// Compute S256 challenge from verifier (SHA256 + base64url)
fn compute_s256_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

// ============================================================================
// OAuth Token Types
// ============================================================================

/// OAuth token pair with expiration tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCredentials {
    /// Bearer access token for API requests
    pub access_token: crate::secrets::OAuthToken,
    /// Refresh token for obtaining new access tokens
    pub refresh_token: Option<crate::secrets::OAuthToken>,
    /// When the access token expires
    pub expires_at: DateTime<Utc>,
}

impl OAuthCredentials {
    /// Check if token is completely expired
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }
}

/// Borrowed request body for the token endpoint. This exists only long enough
/// for reqwest to form-encode it into the transport request.
#[derive(Serialize)]
struct TokenExchangeRequest<'a> {
    grant_type: &'static str,
    client_id: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_uri: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code_verifier: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<&'a str>,
}

/// Response from token endpoint
#[derive(Debug, Deserialize)]
pub struct TokenExchangeResponse {
    pub access_token: crate::secrets::OAuthToken,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<crate::secrets::OAuthToken>,
    pub scope: Option<String>,
}

fn validate_oauth_token_type(token_type: &str) -> Result<()> {
    if token_type.eq_ignore_ascii_case("bearer") {
        Ok(())
    } else {
        anyhow::bail!("Unexpected OAuth token type; expected 'Bearer'")
    }
}

// ============================================================================
// OAuth Session Management
// ============================================================================

/// Authentication mode for API calls
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthMode {
    /// Use ephemeral API key (x-api-key header) - for org accounts with `org:create_api_key`
    ApiKey,
    /// Use Bearer token directly (Authorization: Bearer) - for personal Max accounts
    BearerToken,
    /// Use anthropic-proxy with session cookie - simplest mode that actually works
    ProxyMode,
}

/// Active OAuth session with credentials and metadata
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthSession {
    /// Session identifier (used as pseudo API key)
    pub id: String,
    /// OAuth credentials
    pub credentials: OAuthCredentials,
    /// Ephemeral API key created from OAuth token (used for actual API calls)
    pub api_key: Option<crate::providers::ApiKey>,
    /// Authentication mode for API calls
    pub auth_mode: AuthMode,
    /// Scopes that were actually granted by OAuth server
    pub granted_scopes: Vec<String>,
    /// When session was created
    pub created_at: DateTime<Utc>,
    /// Optional user identifier
    pub user_id: Option<String>,
}

const fn initial_session_generation() -> u64 {
    1
}

impl fmt::Debug for OAuthSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthSession")
            .field("id", &"[REDACTED]")
            .field("credentials", &self.credentials)
            .field("api_key", &self.api_key)
            .field("auth_mode", &self.auth_mode)
            .field("granted_scopes", &self.granted_scopes)
            .field("created_at", &self.created_at)
            .field("user_id", &self.user_id)
            .finish()
    }
}

impl OAuthSession {
    /// Create new session from token response
    pub fn from_token_response(response: TokenExchangeResponse) -> Self {
        // Parse granted scopes from response
        let granted_scopes: Vec<String> = response
            .scope
            .as_ref()
            .map(|s| s.split_whitespace().map(String::from).collect())
            .unwrap_or_default();

        // Determine initial auth mode based on granted scopes
        // If we have org:create_api_key, we'll try API key mode
        // Otherwise, fall back to Bearer token mode
        let has_api_key_scope = granted_scopes.iter().any(|s| s == "org:create_api_key");
        let auth_mode = if has_api_key_scope {
            AuthMode::ApiKey
        } else {
            AuthMode::BearerToken
        };

        if auth_mode == AuthMode::BearerToken {
            info!(
                "Personal account detected (no org:create_api_key scope) - using Bearer token auth"
            );
        }

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            credentials: OAuthCredentials {
                access_token: response.access_token,
                refresh_token: response.refresh_token,
                // Clamped conversion — rejects 0/implausibly-short (prevents
                // 401-retry loops), rejects decade-long expiries (prevents
                // permanent on-disk tokens), and avoids the `cast_signed`
                // u64→i64 wrap that would put a 2^63 expiry in the past.
                // See crosslink #480.
                expires_at: clamped_expires_at(response.expires_in),
            },
            api_key: None, // Set after calling create_api_key if auth_mode is ApiKey
            auth_mode,
            granted_scopes,
            created_at: Utc::now(),
            user_id: None,
        }
    }

    /// Check if this session can create API keys
    #[must_use]
    pub fn can_create_api_key(&self) -> bool {
        self.granted_scopes
            .iter()
            .any(|s| s == "org:create_api_key")
    }

    fn has_inference_scope(&self) -> bool {
        self.granted_scopes
            .iter()
            .any(|scope| scope == REQUIRED_INFERENCE_SCOPE)
    }
}

#[derive(Clone)]
struct OAuthSessionRecord {
    session: OAuthSession,
    generation: u64,
    client_binding: Option<String>,
}

impl OAuthSessionRecord {
    const fn new(session: OAuthSession, client_binding: Option<String>) -> Self {
        Self {
            session,
            generation: initial_session_generation(),
            client_binding,
        }
    }

    fn matches_client(&self, binding: &crate::secrets::SecretString) -> bool {
        self.client_binding
            .as_deref()
            .is_some_and(|expected| expected == binding_digest(binding))
    }
}

fn binding_digest(binding: &crate::secrets::SecretString) -> String {
    binding.expose(|raw| URL_SAFE_NO_PAD.encode(Sha256::digest(raw.as_bytes())))
}

/// Borrowed serializer used only by the owner-only OAuth session store.
///
/// Runtime `Serialize` implementations stay redacted. This wrapper is the
/// single explicit persistence boundary where live credential bytes are
/// written to a `0600` file, and it never creates another owned secret copy.
struct PersistedOAuthSessionRef<'a>(&'a OAuthSessionRecord);

impl Serialize for PersistedOAuthSessionRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let record = self.0;
        let session = &record.session;
        let mut state = serializer.serialize_struct("OAuthSession", 9)?;
        state.serialize_field("id", &session.id)?;
        state.serialize_field(
            "credentials",
            &PersistedOAuthCredentialsRef(&session.credentials),
        )?;
        if let Some(api_key) = &session.api_key {
            api_key.expose(|raw| state.serialize_field("api_key", raw))?;
        } else {
            state.serialize_field("api_key", &Option::<&str>::None)?;
        }
        state.serialize_field("auth_mode", &session.auth_mode)?;
        state.serialize_field("granted_scopes", &session.granted_scopes)?;
        state.serialize_field("created_at", &session.created_at)?;
        state.serialize_field("user_id", &session.user_id)?;
        state.serialize_field("generation", &record.generation)?;
        state.serialize_field("client_binding", &record.client_binding)?;
        state.end()
    }
}

struct PersistedOAuthCredentialsRef<'a>(&'a OAuthCredentials);

impl Serialize for PersistedOAuthCredentialsRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let credentials = self.0;
        let mut state = serializer.serialize_struct("OAuthCredentials", 3)?;
        credentials
            .access_token
            .expose(|raw| state.serialize_field("access_token", raw))?;
        if let Some(refresh_token) = &credentials.refresh_token {
            refresh_token.expose(|raw| state.serialize_field("refresh_token", raw))?;
        } else {
            state.serialize_field("refresh_token", &Option::<&str>::None)?;
        }
        state.serialize_field("expires_at", &credentials.expires_at)?;
        state.end()
    }
}

struct PersistedOAuthSessionMap<'a>(&'a HashMap<String, OAuthSessionRecord>);

impl Serialize for PersistedOAuthSessionMap<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (id, session) in self.0 {
            map.serialize_entry(id, &PersistedOAuthSessionRef(session))?;
        }
        map.end()
    }
}

struct PersistedOAuthDocumentRef<'a> {
    sessions: &'a HashMap<String, OAuthSessionRecord>,
    revocations: &'a HashMap<String, OAuthRevocation>,
}

impl Serialize for PersistedOAuthDocumentRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("OAuthSessionDocument", 3)?;
        state.serialize_field("schema_version", &OAUTH_STORE_SCHEMA_VERSION)?;
        state.serialize_field("sessions", &PersistedOAuthSessionMap(self.sessions))?;
        state.serialize_field("revocations", self.revocations)?;
        state.end()
    }
}

#[derive(Deserialize)]
struct PersistedOAuthCredentials {
    access_token: crate::secrets::OAuthToken,
    refresh_token: Option<crate::secrets::OAuthToken>,
    expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct PersistedOAuthSession {
    id: String,
    credentials: PersistedOAuthCredentials,
    api_key: Option<crate::providers::ApiKey>,
    auth_mode: AuthMode,
    granted_scopes: Vec<String>,
    created_at: DateTime<Utc>,
    user_id: Option<String>,
    #[serde(default = "initial_session_generation")]
    generation: u64,
    #[serde(default)]
    client_binding: Option<String>,
}

impl PersistedOAuthSession {
    fn into_runtime(self) -> OAuthSessionRecord {
        OAuthSessionRecord {
            session: OAuthSession {
                id: self.id,
                credentials: OAuthCredentials {
                    access_token: self.credentials.access_token,
                    refresh_token: self.credentials.refresh_token,
                    expires_at: self.credentials.expires_at,
                },
                api_key: self.api_key,
                auth_mode: self.auth_mode,
                granted_scopes: self.granted_scopes,
                created_at: self.created_at,
                user_id: self.user_id,
            },
            generation: self.generation,
            client_binding: self.client_binding,
        }
    }
}

#[derive(Deserialize)]
struct PersistedOAuthDocument {
    schema_version: u32,
    sessions: HashMap<String, PersistedOAuthSession>,
    #[serde(default)]
    revocations: HashMap<String, OAuthRevocation>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PersistedOAuthDocumentCompat {
    Versioned(PersistedOAuthDocument),
    Legacy(HashMap<String, PersistedOAuthSession>),
}

impl PersistedOAuthDocumentCompat {
    fn into_parts(
        self,
    ) -> Result<(
        HashMap<String, PersistedOAuthSession>,
        HashMap<String, OAuthRevocation>,
    )> {
        match self {
            Self::Versioned(document) => {
                if document.schema_version != OAUTH_STORE_SCHEMA_VERSION {
                    anyhow::bail!(
                        "unsupported OAuth session store schema version {}",
                        document.schema_version
                    );
                }
                Ok((document.sessions, document.revocations))
            }
            Self::Legacy(sessions) => Ok((sessions, HashMap::new())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OAuthRevocation {
    generation: u64,
    revoked_at: DateTime<Utc>,
}

#[derive(Clone, Default)]
struct OAuthRuntimeState {
    sessions: HashMap<String, OAuthSessionRecord>,
    revocations: HashMap<String, OAuthRevocation>,
}

struct PendingOAuthGrant {
    pkce: PkceParams,
    client_binding: Option<String>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl PendingOAuthGrant {
    fn unbound(pkce: PkceParams) -> Self {
        Self {
            pkce,
            client_binding: None,
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(PENDING_GRANT_TTL_SECS),
        }
    }

    fn bound(pkce: PkceParams, binding: &crate::secrets::SecretString) -> Self {
        Self {
            pkce,
            client_binding: Some(binding_digest(binding)),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(PENDING_GRANT_TTL_SECS),
        }
    }

    fn matches_client(&self, binding: Option<&crate::secrets::SecretString>) -> bool {
        match (&self.client_binding, binding) {
            (None, None) => true,
            (Some(expected), Some(binding)) => expected == &binding_digest(binding),
            _ => false,
        }
    }
}

/// Thread-safe storage for OAuth sessions and pending PKCE challenges
pub struct OAuthStore {
    /// Active sessions and durable revocation tombstones.
    state: RwLock<OAuthRuntimeState>,
    /// Bounded, expiring PKCE grants. Browser grants carry only a digest of
    /// their `HttpOnly` client-binding cookie.
    pending_challenges: RwLock<Vec<PendingOAuthGrant>>,
    /// Serializes refresh within one process. The file lock below extends the
    /// same single-flight property across independently running frontends.
    refresh_gate: AsyncMutex<()>,
    /// Path for persistent session storage
    persist_path: Option<PathBuf>,
}

/// Advisory lock for one OAuth session persistence file.
///
/// This is process-wide coordination, not an in-process mutex: proxy,
/// CLI, TUI, and ACP can all be separate processes touching the same
/// `oauth_sessions.json`. The lock serializes the read-merge-write cycle so
/// one process cannot overwrite another process's freshly stored session.
struct OAuthSessionFileLock {
    _file: fs::File,
}

impl OAuthSessionFileLock {
    fn acquire_for(path: &std::path::Path) -> Result<Self> {
        const LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(35);
        const LOCK_RETRY: std::time::Duration = std::time::Duration::from_millis(25);
        let lock_path = oauth_session_lock_path(path);
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create OAuth lock directory {}", parent.display())
            })?;
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("failed to open OAuth lock {}", lock_path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let deadline = std::time::Instant::now() + LOCK_TIMEOUT;
            loop {
                let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
                if ret == 0 {
                    break;
                }
                let error = std::io::Error::last_os_error();
                if !matches!(error.kind(), std::io::ErrorKind::WouldBlock)
                    || std::time::Instant::now() >= deadline
                {
                    return Err(error)
                        .with_context(|| format!("failed to lock {}", lock_path.display()));
                }
                std::thread::sleep(LOCK_RETRY);
            }
        }

        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;

            const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
            const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
            let deadline = std::time::Instant::now() + LOCK_TIMEOUT;
            loop {
                let mut overlapped =
                    std::mem::MaybeUninit::<windows_sys::Win32::System::IO::OVERLAPPED>::zeroed();
                let ok = unsafe {
                    windows_sys::Win32::Storage::FileSystem::LockFileEx(
                        file.as_raw_handle() as _,
                        LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                        0,
                        0xFFFF_FFFF,
                        0xFFFF_FFFF,
                        overlapped.as_mut_ptr(),
                    )
                };
                if ok != 0 {
                    break;
                }
                let error = std::io::Error::last_os_error();
                if std::time::Instant::now() >= deadline {
                    return Err(error)
                        .with_context(|| format!("failed to lock {}", lock_path.display()));
                }
                std::thread::sleep(LOCK_RETRY);
            }
        }

        Ok(Self { _file: file })
    }
}

fn oauth_session_lock_path(path: &std::path::Path) -> PathBuf {
    path.with_extension("json.lock")
}

struct OAuthDiskState {
    storage: crate::persistence::PersistentStorage,
    target: PathBuf,
    generation: crate::persistence::StorageGeneration,
    sessions: HashMap<String, OAuthSessionRecord>,
    revocations: HashMap<String, OAuthRevocation>,
}

fn read_oauth_disk_state(path: &Path) -> Result<OAuthDiskState> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("OAuth session path has no parent"))?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create OAuth session directory {}",
            parent.display()
        )
    })?;
    let target = path
        .file_name()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("OAuth session path has no file name"))?;
    let storage = crate::persistence::PersistentStorage::open(parent)
        .context("failed to open protected OAuth storage")?;
    let read = storage
        .read(&target, crate::persistence::FileClass::Credentials)
        .context("failed to read protected OAuth session document")?;
    let generation = read.generation();
    let (sessions, revocations) = read.expose_bytes(|bytes| -> Result<_> {
        let Some(bytes) = bytes else {
            return Ok((HashMap::new(), HashMap::new()));
        };
        let persisted: PersistedOAuthDocumentCompat =
            serde_json::from_slice(bytes).context("failed to parse OAuth session document")?;
        let (sessions, revocations) = persisted.into_parts()?;
        let sessions = sessions
            .into_iter()
            .map(|(storage_id, persisted)| {
                let session = persisted.into_runtime();
                if storage_id != session.session.id {
                    anyhow::bail!("OAuth session map key does not match embedded session id");
                }
                if session.generation == 0 {
                    anyhow::bail!("OAuth session generation must be positive");
                }
                Ok((storage_id, session))
            })
            .collect::<Result<HashMap<_, _>>>()?;
        if revocations.values().any(|entry| entry.generation == 0) {
            anyhow::bail!("OAuth revocation generation must be positive");
        }
        Ok((sessions, revocations))
    })?;
    Ok(OAuthDiskState {
        storage,
        target,
        generation,
        sessions,
        revocations,
    })
}

fn commit_oauth_disk_state(state: &OAuthDiskState) -> Result<()> {
    let encoded = Zeroizing::new(
        serde_json::to_vec_pretty(&PersistedOAuthDocumentRef {
            sessions: &state.sessions,
            revocations: &state.revocations,
        })
        .context("failed to serialize OAuth session document")?,
    );
    let receipt = state
        .storage
        .commit(
            &state.target,
            crate::persistence::FileClass::Credentials,
            state.generation,
            &*encoded,
        )
        .context("failed to commit protected OAuth session document")?;
    if receipt.state() == crate::persistence::CommitState::PublishedDurabilityUncertain {
        let recovery = state
            .storage
            .commit(
                &state.target,
                crate::persistence::FileClass::Credentials,
                state.generation,
                &*encoded,
            )
            .context("failed to recover OAuth session document durability")?;
        if recovery.state() == crate::persistence::CommitState::PublishedDurabilityUncertain {
            anyhow::bail!("OAuth session document publication durability is uncertain");
        }
    }
    Ok(())
}

impl Default for OAuthStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OAuthSessionUseError {
    #[error("OAuth session is unavailable")]
    Unavailable,
    #[error("OAuth session has been revoked")]
    Revoked,
    #[error("OAuth session is not bound to this client")]
    ClientBinding,
    #[error("OAuth session lacks the required inference scope")]
    MissingScope,
    #[error("OAuth session has expired and cannot be refreshed")]
    Expired,
    #[error("OAuth session refresh failed: {0}")]
    RefreshFailed(String),
    #[error("OAuth session storage failed: {0}")]
    Storage(String),
}

struct OAuthSessionRefresh {
    tokens: TokenExchangeResponse,
    api_key: Option<crate::providers::ApiKey>,
}

#[async_trait::async_trait]
trait OAuthSessionRefresher: Send + Sync {
    async fn refresh_session(&self, session: &OAuthSession) -> Result<OAuthSessionRefresh>;
}

fn revocation_key(session_id: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(session_id.as_bytes()))
}

impl OAuthStore {
    /// Create new OAuth store with optional persistence
    #[must_use]
    pub fn new() -> Self {
        let persist_path =
            dirs::data_local_dir().map(|d| d.join("openclaudia").join("oauth_sessions.json"));
        Self::with_optional_persist_path(persist_path)
    }

    /// Create an isolated in-memory store. This is the correct constructor for
    /// tests and short-lived callers that must not touch the user's login.
    #[must_use]
    pub fn ephemeral() -> Self {
        Self::with_optional_persist_path(None)
    }

    fn with_optional_persist_path(persist_path: Option<PathBuf>) -> Self {
        let store = Self {
            state: RwLock::new(OAuthRuntimeState::default()),
            pending_challenges: RwLock::new(Vec::new()),
            refresh_gate: AsyncMutex::new(()),
            persist_path,
        };
        store.load_from_disk();
        store
    }

    /// Construct a store with a caller-supplied persistence path. Used by
    /// the `persist_to_disk` regression suite (crosslink #801) so tests
    /// don't have to clobber `$XDG_DATA_HOME`.
    #[cfg(test)]
    pub(crate) fn with_persist_path(path: PathBuf) -> Self {
        Self::with_optional_persist_path(Some(path))
    }

    /// Store PKCE challenge for pending authorization
    pub fn store_challenge(&self, pkce: PkceParams) {
        self.store_pending_grant(PendingOAuthGrant::unbound(pkce));
    }

    /// Store a browser-bound PKCE challenge.
    pub fn store_bound_challenge(
        &self,
        pkce: PkceParams,
        client_binding: &crate::secrets::SecretString,
    ) {
        self.store_pending_grant(PendingOAuthGrant::bound(pkce, client_binding));
    }

    fn store_pending_grant(&self, grant: PendingOAuthGrant) {
        let mut challenges = self
            .pending_challenges
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Utc::now();
        challenges.retain(|candidate| candidate.expires_at > now);
        if let Some(existing) = challenges
            .iter_mut()
            .find(|candidate| candidate.pkce.state == grant.pkce.state)
        {
            *existing = grant;
        } else {
            if challenges.len() >= MAX_PENDING_GRANTS {
                let oldest = challenges
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, candidate)| candidate.issued_at)
                    .map_or(0, |(index, _)| index);
                challenges.swap_remove(oldest);
            }
            challenges.push(grant);
        }
    }

    /// Retrieve and remove PKCE challenge by state
    pub fn take_challenge(&self, state: &str) -> Option<PkceParams> {
        self.take_pending_grant(state, None)
    }

    /// Consume a browser-bound challenge exactly once.
    pub fn take_bound_challenge(
        &self,
        state: &str,
        client_binding: &crate::secrets::SecretString,
    ) -> Option<PkceParams> {
        self.take_pending_grant(state, Some(client_binding))
    }

    fn take_pending_grant(
        &self,
        state: &str,
        client_binding: Option<&crate::secrets::SecretString>,
    ) -> Option<PkceParams> {
        let mut challenges = self
            .pending_challenges
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = challenges
            .iter()
            .position(|candidate| candidate.pkce.state.matches(state))?;
        if challenges[index].expires_at <= Utc::now() {
            challenges.swap_remove(index);
            return None;
        }
        if !challenges[index].matches_client(client_binding) {
            return None;
        }
        Some(challenges.swap_remove(index).pkce)
    }

    /// Store new OAuth session and report persistence failures to the caller.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is unusable, stale, or cannot be
    /// durably persisted. A failed durable write is never advertised in memory.
    pub fn try_store_session(&self, session: OAuthSession) -> Result<()> {
        self.try_store_session_record(OAuthSessionRecord::new(session, None))
    }

    /// Durably store a session bound to the browser client that completed the
    /// authorization flow.
    ///
    /// # Errors
    ///
    /// Returns an error for unusable/stale sessions or failed protected
    /// persistence.
    pub fn try_store_bound_session(
        &self,
        session: OAuthSession,
        client_binding: &crate::secrets::SecretString,
    ) -> Result<()> {
        self.try_store_session_record(OAuthSessionRecord::new(
            session,
            Some(binding_digest(client_binding)),
        ))
    }

    fn try_store_session_record(&self, record: OAuthSessionRecord) -> Result<()> {
        let session = &record.session;
        if session.id.is_empty() || session.id.len() > 256 {
            anyhow::bail!("OAuth session id is invalid");
        }
        if !session.has_inference_scope() {
            anyhow::bail!("OAuth session lacks the required inference scope");
        }

        let Some(path) = &self.persist_path else {
            self.state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .sessions
                .insert(session.id.clone(), record);
            return Ok(());
        };
        let _lock = OAuthSessionFileLock::acquire_for(path)?;
        let mut disk = read_oauth_disk_state(path)?;
        if disk
            .revocations
            .get(&revocation_key(&session.id))
            .is_some_and(|revocation| revocation.generation >= record.generation)
        {
            anyhow::bail!("refusing to resurrect a revoked OAuth session");
        }
        if disk
            .sessions
            .get(&session.id)
            .is_some_and(|current| current.generation > record.generation)
        {
            anyhow::bail!("refusing to overwrite a newer OAuth session generation");
        }
        disk.sessions.insert(session.id.clone(), record);
        commit_oauth_disk_state(&disk)?;
        self.replace_state_in_memory(OAuthRuntimeState {
            sessions: disk.sessions,
            revocations: disk.revocations,
        });
        info!("OAuth session stored");
        Ok(())
    }

    /// Store new OAuth session.
    ///
    /// Compatibility wrapper for non-CLI callers that already tolerate a
    /// process-local session when persistence is unavailable. Use
    /// [`Self::try_store_session`] when the caller needs to surface disk write
    /// failures to a human.
    pub fn store_session(&self, session: OAuthSession) {
        let fallback = session.clone();
        if let Err(e) = self.try_store_session(session) {
            error!("Failed to persist OAuth session: {e:#}");
            self.state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .sessions
                .insert(fallback.id.clone(), OAuthSessionRecord::new(fallback, None));
        }
    }

    /// Inspect a currently valid session without refreshing or authorizing it.
    ///
    /// Provider traffic must use [`Self::get_session_for_use`] so that browser
    /// binding, durable revocation, and refresh are enforced.
    pub fn get_session(&self, id: &str) -> Option<OAuthSession> {
        if let Some(path) = &self.persist_path {
            let result = OAuthSessionFileLock::acquire_for(path)
                .and_then(|_lock| read_oauth_disk_state(path));
            match result {
                Ok(disk) => self.replace_state_in_memory(OAuthRuntimeState {
                    sessions: disk.sessions,
                    revocations: disk.revocations,
                }),
                Err(error) => {
                    error!("Failed to reload OAuth sessions for use: {error:#}");
                    return None;
                }
            }
        }
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sessions
            .get(id)
            .filter(|record| {
                record.session.has_inference_scope() && !record.session.credentials.is_expired()
            })
            .map(|record| record.session.clone())
    }

    // `get_any_valid_session` was deleted as part of crosslink #375 (critical).
    // It returned the first valid OAuth session regardless of caller identity,
    // which let any unauthenticated request impersonate an authenticated one.
    // Callers must now resolve sessions by explicit `anthropic_session` and
    // client-binding cookies via `get_session_for_use`; no ambient-session
    // fallback remains.

    /// Resolve a browser session for provider use, refreshing and rotating its
    /// credentials once when expiry is near.
    ///
    /// # Errors
    ///
    /// Returns a typed unavailable, binding, scope, expiry, refresh, or
    /// storage error.
    pub async fn get_session_for_use(
        &self,
        id: &str,
        client_binding: &crate::secrets::SecretString,
    ) -> Result<OAuthSession, OAuthSessionUseError> {
        let client = OAuthClient::new()
            .map_err(|error| OAuthSessionUseError::RefreshFailed(error.to_string()))?;
        self.get_session_for_use_with(id, client_binding, &client)
            .await
    }

    #[allow(clippy::too_many_lines)] // Validation, rotation, and durable publication are one transaction.
    async fn get_session_for_use_with(
        &self,
        id: &str,
        client_binding: &crate::secrets::SecretString,
        refresher: &dyn OAuthSessionRefresher,
    ) -> Result<OAuthSession, OAuthSessionUseError> {
        let _refresh_guard = self.refresh_gate.lock().await;
        let file_lock = if let Some(path) = &self.persist_path {
            let lock_path = path.clone();
            Some(
                tokio::task::spawn_blocking(move || OAuthSessionFileLock::acquire_for(&lock_path))
                    .await
                    .map_err(|_| {
                        OAuthSessionUseError::Storage(
                            "OAuth session lock task did not complete".to_string(),
                        )
                    })?
                    .map_err(|error| OAuthSessionUseError::Storage(error.to_string()))?,
            )
        } else {
            None
        };

        let mut runtime = if let Some(path) = &self.persist_path {
            let disk = read_oauth_disk_state(path)
                .map_err(|error| OAuthSessionUseError::Storage(error.to_string()))?;
            OAuthRuntimeState {
                sessions: disk.sessions,
                revocations: disk.revocations,
            }
        } else {
            self.state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        };
        let mut record = match runtime.sessions.get(id).cloned() {
            Some(record) => record,
            None if runtime.revocations.contains_key(&revocation_key(id)) => {
                return Err(OAuthSessionUseError::Revoked);
            }
            None => return Err(OAuthSessionUseError::Unavailable),
        };
        if !record.matches_client(client_binding) {
            return Err(OAuthSessionUseError::ClientBinding);
        }
        if !record.session.has_inference_scope() {
            return Err(OAuthSessionUseError::MissingScope);
        }

        if record.session.credentials.expires_at
            > Utc::now() + Duration::seconds(OAUTH_REFRESH_SKEW_SECS)
        {
            self.replace_state_in_memory(runtime);
            drop(file_lock);
            return Ok(record.session);
        }
        if record.session.credentials.refresh_token.is_none() {
            return Err(OAuthSessionUseError::Expired);
        }

        let refresh_result = refresher
            .refresh_session(&record.session)
            .await
            .map_err(|error| OAuthSessionUseError::RefreshFailed(error.to_string()))?;
        validate_oauth_token_type(&refresh_result.tokens.token_type)
            .map_err(|error| OAuthSessionUseError::RefreshFailed(error.to_string()))?;
        if let Some(scopes) = refresh_result.tokens.scope.as_deref() {
            record.session.granted_scopes = scopes.split_whitespace().map(String::from).collect();
        }
        if !record.session.has_inference_scope() {
            return Err(OAuthSessionUseError::MissingScope);
        }
        record.session.credentials.access_token = refresh_result.tokens.access_token;
        if let Some(refresh_token) = refresh_result.tokens.refresh_token {
            record.session.credentials.refresh_token = Some(refresh_token);
        }
        record.session.credentials.expires_at =
            clamped_expires_at(refresh_result.tokens.expires_in);
        if record.session.auth_mode == AuthMode::ApiKey {
            record.session.api_key = Some(refresh_result.api_key.ok_or_else(|| {
                OAuthSessionUseError::RefreshFailed(
                    "API-key session refresh did not rotate its API key".to_string(),
                )
            })?);
        }
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or_else(|| OAuthSessionUseError::Storage("generation exhausted".to_string()))?;
        runtime
            .sessions
            .insert(record.session.id.clone(), record.clone());

        if let Some(path) = &self.persist_path {
            let disk = read_oauth_disk_state(path)
                .map_err(|error| OAuthSessionUseError::Storage(error.to_string()))?;
            let current_generation = disk
                .sessions
                .get(id)
                .map(|current| current.generation)
                .ok_or(OAuthSessionUseError::Unavailable)?;
            if current_generation.checked_add(1) != Some(record.generation) {
                return Err(OAuthSessionUseError::Storage(
                    "OAuth session generation changed during refresh".to_string(),
                ));
            }
            let mut updated = disk;
            updated.sessions.insert(id.to_string(), record.clone());
            commit_oauth_disk_state(&updated)
                .map_err(|error| OAuthSessionUseError::Storage(error.to_string()))?;
            runtime = OAuthRuntimeState {
                sessions: updated.sessions,
                revocations: updated.revocations,
            };
        }
        self.replace_state_in_memory(runtime);
        drop(file_lock);
        Ok(record.session)
    }

    /// Revoke one browser session and delete its credential material.
    ///
    /// # Errors
    ///
    /// Returns a binding or protected-storage error when revocation cannot be
    /// applied.
    pub async fn revoke_session_for_client(
        &self,
        id: &str,
        client_binding: &crate::secrets::SecretString,
    ) -> Result<bool, OAuthSessionUseError> {
        let _refresh_guard = self.refresh_gate.lock().await;
        self.revoke_sessions(Some((id, client_binding)))
            .await
            .map(|count| count != 0)
    }

    /// Revoke every OpenClaudia-owned native OAuth session.
    ///
    /// # Errors
    ///
    /// Returns a protected-storage error when revocation cannot be committed.
    pub async fn revoke_all(&self) -> Result<usize, OAuthSessionUseError> {
        let _refresh_guard = self.refresh_gate.lock().await;
        self.revoke_sessions(None).await
    }

    async fn revoke_sessions(
        &self,
        selected: Option<(&str, &crate::secrets::SecretString)>,
    ) -> Result<usize, OAuthSessionUseError> {
        let file_lock = if let Some(path) = &self.persist_path {
            let lock_path = path.clone();
            Some(
                tokio::task::spawn_blocking(move || OAuthSessionFileLock::acquire_for(&lock_path))
                    .await
                    .map_err(|_| {
                        OAuthSessionUseError::Storage(
                            "OAuth session lock task did not complete".to_string(),
                        )
                    })?
                    .map_err(|error| OAuthSessionUseError::Storage(error.to_string()))?,
            )
        } else {
            None
        };
        let mut runtime = if let Some(path) = &self.persist_path {
            let disk = read_oauth_disk_state(path)
                .map_err(|error| OAuthSessionUseError::Storage(error.to_string()))?;
            OAuthRuntimeState {
                sessions: disk.sessions,
                revocations: disk.revocations,
            }
        } else {
            self.state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        };

        let ids = match selected {
            Some((id, binding)) => {
                let Some(session) = runtime.sessions.get(id) else {
                    return Ok(0);
                };
                if !session.matches_client(binding) {
                    return Err(OAuthSessionUseError::ClientBinding);
                }
                vec![id.to_string()]
            }
            None => runtime.sessions.keys().cloned().collect(),
        };
        if ids.is_empty() {
            self.replace_state_in_memory(runtime);
            drop(file_lock);
            return Ok(0);
        }
        let now = Utc::now();
        for id in &ids {
            if let Some(session) = runtime.sessions.remove(id) {
                runtime.revocations.insert(
                    revocation_key(id),
                    OAuthRevocation {
                        generation: session.generation.saturating_add(1),
                        revoked_at: now,
                    },
                );
            }
        }
        if let Some(path) = &self.persist_path {
            let mut disk = read_oauth_disk_state(path)
                .map_err(|error| OAuthSessionUseError::Storage(error.to_string()))?;
            disk.sessions.clone_from(&runtime.sessions);
            disk.revocations.clone_from(&runtime.revocations);
            commit_oauth_disk_state(&disk)
                .map_err(|error| OAuthSessionUseError::Storage(error.to_string()))?;
        }
        self.replace_state_in_memory(runtime);
        drop(file_lock);
        Ok(ids.len())
    }

    /// Count active (not revoked) native OAuth sessions from protected state.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential document cannot be locked, read,
    /// or validated.
    pub fn active_session_count(&self) -> Result<usize> {
        if let Some(path) = &self.persist_path {
            let _lock = OAuthSessionFileLock::acquire_for(path)?;
            let disk = read_oauth_disk_state(path)?;
            let count = disk.sessions.len();
            self.replace_state_in_memory(OAuthRuntimeState {
                sessions: disk.sessions,
                revocations: disk.revocations,
            });
            return Ok(count);
        }
        Ok(self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sessions
            .len())
    }

    /// Load sessions from disk without treating expired-but-refreshable
    /// sessions as deleted.
    fn load_from_disk(&self) {
        let Some(path) = &self.persist_path else {
            return;
        };

        let _lock = match OAuthSessionFileLock::acquire_for(path) {
            Ok(lock) => lock,
            Err(e) => {
                error!("Failed to lock OAuth sessions for load: {e:#}");
                return;
            }
        };

        match read_oauth_disk_state(path) {
            Ok(disk) => {
                let session_count = disk.sessions.len();
                self.replace_state_in_memory(OAuthRuntimeState {
                    sessions: disk.sessions,
                    revocations: disk.revocations,
                });
                info!("Loaded {} OAuth sessions from disk", session_count);
            }
            Err(error) => error!("Failed to load OAuth sessions: {error:#}"),
        }
    }

    fn replace_state_in_memory(&self, state: OAuthRuntimeState) {
        let mut guard = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = state;
    }
}

// ============================================================================
// OAuth Client for Token Operations
// ============================================================================

/// Client for OAuth token operations
pub struct OAuthClient {
    http: reqwest::Client,
}

impl OAuthClient {
    /// Build an `OAuthClient` with the `Claude Code/1.0` User-Agent and a
    /// 30-second timeout.
    ///
    /// # Errors
    ///
    /// Returns a sanitized transport error if the canonical TLS client cannot
    /// initialize or the fixed OAuth endpoints fail validation. Without the
    /// `Claude Code/1.0` User-Agent the Anthropic OAuth endpoint rejects all
    /// token exchanges, so initialization must fail explicitly.
    pub fn new() -> Result<Self> {
        crate::claude_credentials::require_experimental_direct_subscription()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        crate::provider_transport::validate_endpoint("anthropic", TOKEN_ENDPOINT)?;
        crate::provider_transport::validate_endpoint("anthropic", API_KEY_ENDPOINT)?;
        let http = crate::provider_transport::client_with_user_agent("Claude Code/1.0")?;
        Ok(Self { http })
    }

    /// Exchange authorization code for tokens
    ///
    /// NOTE: This performs an immediate token refresh after initial exchange,
    /// which is required for the tokens to work with the API. The initial tokens
    /// from the authorization code exchange may not be valid for API use.
    ///
    /// # Errors
    /// Returns an error if the token exchange HTTP request fails or the response cannot be parsed.
    pub async fn exchange_code(
        &self,
        code: String,
        pkce: &PkceParams,
    ) -> Result<TokenExchangeResponse> {
        let code = crate::secrets::SecretString::try_from_string(code)
            .context("invalid OAuth authorization code")?;
        let request = code.expose(|code_raw| {
            pkce.verifier.expose(|verifier_raw| {
                pkce.state.expose(|state_raw| {
                    let form = TokenExchangeRequest {
                        grant_type: "authorization_code",
                        client_id: ANTHROPIC_CLIENT_ID,
                        code: Some(code_raw),
                        redirect_uri: Some(ANTHROPIC_REDIRECT_URI),
                        code_verifier: Some(verifier_raw),
                        refresh_token: None,
                        state: Some(state_raw),
                    };
                    self.token_request(&form)
                })
            })
        });

        let initial_response = self
            .send_token_request(request, &[code, pkce.verifier.clone(), pkce.state.clone()])
            .await?;

        // CRITICAL: Immediate token refresh after initial exchange
        // The anthropic-proxy discovered that initial tokens may not be valid for API use
        // Refreshing immediately gives us tokens that work
        info!("Initial token obtained, attempting immediate refresh...");

        if let Some(ref refresh_token) = initial_response.refresh_token {
            match self.refresh_token(refresh_token).await {
                Ok(refreshed) => {
                    info!("✅ Immediate token refresh successful!");
                    // Return refreshed tokens, keeping original refresh_token if not returned
                    Ok(TokenExchangeResponse {
                        access_token: refreshed.access_token,
                        token_type: refreshed.token_type,
                        expires_in: refreshed.expires_in,
                        refresh_token: refreshed.refresh_token.or(initial_response.refresh_token),
                        scope: refreshed.scope.or(initial_response.scope),
                    })
                }
                Err(e) => {
                    tracing::warn!(
                        "Immediate token refresh failed: {:?}, using original tokens",
                        e
                    );
                    Ok(initial_response)
                }
            }
        } else {
            tracing::warn!("No refresh token in initial response, using original tokens");
            Ok(initial_response)
        }
    }

    /// Refresh access token using refresh token
    ///
    /// # Errors
    /// Returns an error if the refresh HTTP request fails or the response cannot be parsed.
    pub async fn refresh_token(
        &self,
        refresh_token: &crate::secrets::OAuthToken,
    ) -> Result<TokenExchangeResponse> {
        let request = refresh_token.expose(|refresh_raw| {
            let form = TokenExchangeRequest {
                grant_type: "refresh_token",
                client_id: ANTHROPIC_CLIENT_ID,
                code: None,
                redirect_uri: None,
                code_verifier: None,
                refresh_token: Some(refresh_raw),
                state: None,
            };
            self.token_request(&form)
        });
        self.send_token_request(request, &[refresh_token.secret()])
            .await
    }

    fn token_request(&self, request: &TokenExchangeRequest<'_>) -> reqwest::RequestBuilder {
        self.http
            .post(TOKEN_ENDPOINT)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(request)
    }

    /// Send a fully materialized token request to Anthropic.
    async fn send_token_request(
        &self,
        request: reqwest::RequestBuilder,
        known_secrets: &[crate::secrets::SecretString],
    ) -> Result<TokenExchangeResponse> {
        debug!("Sending token request to {}", TOKEN_ENDPOINT);

        let response = crate::provider_transport::send(request)
            .await
            .context("Failed to send token request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = crate::secrets::read_bounded_diagnostic_body(response)
                .await
                .context("Failed to read token-exchange error body")?;
            let safe = crate::secrets::sanitize_diagnostic(&body, known_secrets);
            debug!(status = %status, body = %safe, "token exchange failed");
            anyhow::bail!("Token exchange failed ({status}): {safe}");
        }

        debug!("Token response received");

        let token_response: TokenExchangeResponse =
            crate::provider_transport::read_sensitive_json_capped(
                response,
                crate::provider_transport::MAX_JSON_RESPONSE_BYTES,
            )
            .await
            .context("Failed to parse token response")?;

        // Validate token type is Bearer
        validate_oauth_token_type(&token_response.token_type)?;

        // Scope values originate in the provider response. Keep them out of
        // logs because a compromised endpoint can echo active credentials in
        // otherwise non-secret fields.
        if token_response.scope.is_some() {
            info!("OAuth response included a scope field");
        } else {
            info!("OAuth response did not include scope field");
        }

        Ok(token_response)
    }

    /// Create an ephemeral API key from OAuth access token
    ///
    /// Claude Code uses this to convert OAuth tokens into API keys for actual
    /// API calls, since the /v1/messages endpoint doesn't support OAuth directly.
    ///
    /// # Errors
    /// Returns an error if the API key creation request fails or the response cannot be parsed.
    pub async fn create_api_key(
        &self,
        access_token: &crate::secrets::OAuthToken,
    ) -> Result<crate::providers::ApiKey> {
        #[derive(Deserialize)]
        struct ApiKeyResponse {
            raw_key: crate::providers::ApiKey,
        }

        debug!("Creating API key from OAuth token at {}", API_KEY_ENDPOINT);

        // Claude Code sends null body with just Authorization header
        let mut headers = crate::secrets::SensitiveHeaders::new();
        headers.insert_header_bearer(reqwest::header::AUTHORIZATION, access_token.secret());
        let request = headers.apply(self.http.post(API_KEY_ENDPOINT))?;
        let response = crate::provider_transport::send(request)
            .await
            .context("Failed to send API key creation request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = crate::secrets::read_bounded_diagnostic_body(response)
                .await
                .context("Failed to read API-key creation error body")?;
            let safe = headers.sanitize_diagnostic(&body);
            debug!(status = %status, body = %safe, "API key creation failed");
            anyhow::bail!("API key creation failed ({status}): {safe}");
        }

        let key_response: ApiKeyResponse = crate::provider_transport::read_sensitive_json_capped(
            response,
            crate::provider_transport::MAX_JSON_RESPONSE_BYTES,
        )
        .await
        .context("Failed to parse API key response")?;

        info!("Successfully created API key from OAuth token");
        Ok(key_response.raw_key)
    }
}

#[async_trait::async_trait]
impl OAuthSessionRefresher for OAuthClient {
    async fn refresh_session(&self, session: &OAuthSession) -> Result<OAuthSessionRefresh> {
        let refresh_token = session
            .credentials
            .refresh_token
            .as_ref()
            .context("OAuth session has no refresh token")?;
        let tokens = self.refresh_token(refresh_token).await?;
        let api_key = if session.auth_mode == AuthMode::ApiKey {
            Some(self.create_api_key(&tokens.access_token).await?)
        } else {
            None
        };
        Ok(OAuthSessionRefresh { tokens, api_key })
    }
}

// ============================================================================
// Authorization Code Parsing
// ============================================================================

/// Parse authorization code from Claude's combined format
///
/// Claude returns the code as: `{authorization_code}#{state}`
#[must_use]
pub fn parse_auth_code(input: &str) -> (String, Option<String>) {
    input.find('#').map_or_else(
        || (input.to_string(), None),
        |idx| {
            let code = input[..idx].to_string();
            let state = input[idx + 1..].to_string();
            (code, Some(state))
        },
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Regression tests for crosslink #480 ---

    #[test]
    fn clamped_expires_at_accepts_normal_value() {
        let before = Utc::now();
        let at = clamped_expires_at(3600);
        let after = Utc::now();
        // Should be roughly 3600 seconds in the future.
        let lower = before + Duration::seconds(3600);
        let upper = after + Duration::seconds(3600);
        assert!(at >= lower && at <= upper);
    }

    #[test]
    fn clamped_expires_at_rejects_zero_value() {
        // 0 would produce an immediately-expired session → 401 loop.
        let before = Utc::now();
        let at = clamped_expires_at(0);
        // Clamped to 60s, so must be at least 60s in the future.
        assert!(at >= before + Duration::seconds(60));
    }

    #[test]
    fn clamped_expires_at_caps_implausibly_large_value() {
        // u64::MAX should not produce a DateTime overflow or a past
        // timestamp (as `.cast_signed()` used to).
        let before = Utc::now();
        let at = clamped_expires_at(u64::MAX);
        let cap_upper = before + Duration::seconds(30 * 24 * 3600 + 5);
        assert!(at <= cap_upper, "expires_at {at:?} exceeded 30-day cap");
        assert!(at > before, "expires_at {at:?} is not in the future");
    }

    #[test]
    fn clamped_expires_at_caps_thousand_year_value() {
        // 1000 years in seconds ≈ 3.15e10 — a real bug shape from the
        // issue description.
        let before = Utc::now();
        let at = clamped_expires_at(31_536_000_000);
        let cap_upper = before + Duration::seconds(30 * 24 * 3600 + 5);
        assert!(at <= cap_upper);
    }

    #[test]
    fn test_pkce_generation() {
        let pkce = PkceParams::generate();

        // Verifier should be base64url encoded 64 bytes
        assert!(!pkce.verifier.is_empty());
        assert!(!pkce.challenge.is_empty());
        assert!(!pkce.state.is_empty());

        pkce.verifier.expose(|verifier| {
            assert!(
                verifier
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric()
                        || matches!(character, '-' | '_')),
                "generated verifier must remain URL-safe"
            );
        });

        // Challenge should be different from verifier
        assert!(!pkce.verifier.matches(&pkce.challenge));
    }

    #[test]
    fn test_s256_challenge() {
        // Known test vector
        let verifier = "test_verifier";
        let challenge = compute_s256_challenge(verifier);

        // Should be consistent
        assert_eq!(challenge, compute_s256_challenge(verifier));
    }

    #[test]
    fn invalid_token_type_diagnostic_does_not_echo_provider_value() {
        let sentinel = "oauth-token-type-secret-sentinel";
        let error = validate_oauth_token_type(sentinel)
            .expect_err("non-bearer token type must be rejected")
            .to_string();
        assert!(error.contains("expected 'Bearer'"), "{error}");
        assert!(!error.contains(sentinel), "{error}");
    }

    #[test]
    fn test_auth_url_construction() {
        let pkce = PkceParams::generate();
        let url = pkce.build_auth_url();

        assert!(url.starts_with(OAUTH_AUTHORIZE_URL));
        assert!(url.contains("client_id="));
        assert!(url.contains("code_challenge="));
        assert!(url.contains("state="));
    }

    #[test]
    fn test_parse_auth_code_combined() {
        let input = "auth_code_123#state_abc";
        let (code, state) = parse_auth_code(input);

        assert_eq!(code, "auth_code_123");
        assert_eq!(state, Some("state_abc".to_string()));
    }

    #[test]
    fn test_parse_auth_code_simple() {
        let input = "just_a_code";
        let (code, state) = parse_auth_code(input);

        assert_eq!(code, "just_a_code");
        assert_eq!(state, None);
    }

    #[test]
    fn test_token_expiry_check() {
        let creds = OAuthCredentials {
            access_token: crate::secrets::OAuthToken::try_from_string("test".to_string())
                .expect("token"),
            refresh_token: None,
            expires_at: Utc::now() + Duration::seconds(100),
        };

        // 100 seconds remaining - not expired
        assert!(!creds.is_expired());

        let expired_creds = OAuthCredentials {
            access_token: crate::secrets::OAuthToken::try_from_string("test".to_string())
                .expect("token"),
            refresh_token: None,
            expires_at: Utc::now() - Duration::seconds(10),
        };

        // Already past expiry
        assert!(expired_creds.is_expired());
    }

    fn lifecycle_session(
        id: &str,
        expires_at: DateTime<Utc>,
        with_refresh_token: bool,
    ) -> OAuthSession {
        OAuthSession {
            id: id.to_string(),
            credentials: OAuthCredentials {
                access_token: crate::secrets::OAuthToken::try_from_string(format!("access-{id}"))
                    .expect("access token"),
                refresh_token: with_refresh_token.then(|| {
                    crate::secrets::OAuthToken::try_from_string(format!("refresh-{id}"))
                        .expect("refresh token")
                }),
                expires_at,
            },
            api_key: None,
            auth_mode: AuthMode::BearerToken,
            granted_scopes: vec![REQUIRED_INFERENCE_SCOPE.to_string()],
            created_at: Utc::now(),
            user_id: None,
        }
    }

    struct CountingRefresher {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl OAuthSessionRefresher for CountingRefresher {
        async fn refresh_session(&self, _session: &OAuthSession) -> Result<OAuthSessionRefresh> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            Ok(OAuthSessionRefresh {
                tokens: TokenExchangeResponse {
                    access_token: crate::secrets::OAuthToken::try_from_string(
                        "rotated-access-token".to_string(),
                    )
                    .expect("token"),
                    token_type: "Bearer".to_string(),
                    expires_in: 3600,
                    refresh_token: Some(
                        crate::secrets::OAuthToken::try_from_string(
                            "rotated-refresh-token".to_string(),
                        )
                        .expect("refresh token"),
                    ),
                    scope: Some(REQUIRED_INFERENCE_SCOPE.to_string()),
                },
                api_key: None,
            })
        }
    }

    #[test]
    fn browser_bound_pkce_rejects_cross_client_and_replay() {
        let store = OAuthStore::ephemeral();
        let owner = generate_client_binding();
        let other = generate_client_binding();
        let pkce = PkceParams::generate();
        let state = pkce.state.expose(str::to_string);
        store.store_bound_challenge(pkce, &owner);

        assert!(store.take_bound_challenge(&state, &other).is_none());
        assert!(store.take_bound_challenge(&state, &owner).is_some());
        assert!(store.take_bound_challenge(&state, &owner).is_none());
    }

    #[test]
    fn expired_browser_grant_is_consumed_and_rejected() {
        let store = OAuthStore::ephemeral();
        let binding = generate_client_binding();
        let pkce = PkceParams::generate();
        let state = pkce.state.expose(str::to_string);
        store.store_bound_challenge(pkce, &binding);
        store
            .pending_challenges
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)[0]
            .expires_at = Utc::now() - Duration::seconds(1);

        assert!(store.take_bound_challenge(&state, &binding).is_none());
        assert!(store.take_bound_challenge(&state, &binding).is_none());
    }

    #[test]
    fn pending_browser_grants_have_a_hard_capacity() {
        let store = OAuthStore::ephemeral();
        let binding = generate_client_binding();
        for _ in 0..(MAX_PENDING_GRANTS + 5) {
            store.store_bound_challenge(PkceParams::generate(), &binding);
        }
        assert_eq!(
            store
                .pending_challenges
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            MAX_PENDING_GRANTS
        );
    }

    #[tokio::test]
    async fn expired_session_without_refresh_fails_without_network_attempt() {
        let store = OAuthStore::ephemeral();
        let binding = generate_client_binding();
        let session = lifecycle_session(
            "expired-no-refresh",
            Utc::now() - Duration::seconds(1),
            false,
        );
        store
            .try_store_bound_session(session, &binding)
            .expect("store");
        let refresher = CountingRefresher {
            calls: std::sync::atomic::AtomicUsize::new(0),
        };

        let error = store
            .get_session_for_use_with("expired-no-refresh", &binding, &refresher)
            .await
            .expect_err("expired session without refresh must fail");
        assert!(matches!(error, OAuthSessionUseError::Expired));
        assert_eq!(refresher.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn active_session_rejects_a_different_browser_binding() {
        let store = OAuthStore::ephemeral();
        let owner = generate_client_binding();
        let other = generate_client_binding();
        store
            .try_store_bound_session(
                lifecycle_session("bound-session", Utc::now() + Duration::hours(1), true),
                &owner,
            )
            .expect("store");
        let refresher = CountingRefresher {
            calls: std::sync::atomic::AtomicUsize::new(0),
        };

        let error = store
            .get_session_for_use_with("bound-session", &other, &refresher)
            .await
            .expect_err("cross-client session use must fail");
        assert!(matches!(error, OAuthSessionUseError::ClientBinding));
    }

    #[tokio::test]
    async fn concurrent_expiry_refreshes_once_and_reuses_rotated_generation() {
        let store = OAuthStore::ephemeral();
        let binding = generate_client_binding();
        store
            .try_store_bound_session(
                lifecycle_session(
                    "single-flight-session",
                    Utc::now() - Duration::seconds(1),
                    true,
                ),
                &binding,
            )
            .expect("store");
        let refresher = CountingRefresher {
            calls: std::sync::atomic::AtomicUsize::new(0),
        };

        let (first, second) = tokio::join!(
            store.get_session_for_use_with("single-flight-session", &binding, &refresher),
            store.get_session_for_use_with("single-flight-session", &binding, &refresher)
        );
        let first = first.expect("first refreshed session");
        let second = second.expect("second refreshed session");
        assert_eq!(refresher.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(first
            .credentials
            .access_token
            .matches("rotated-access-token"));
        assert!(second
            .credentials
            .access_token
            .matches("rotated-access-token"));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn independent_stores_serialize_one_durable_refresh() {
        let tmp = tempfile::tempdir().expect("root");
        let path = tmp.path().join("oauth_sessions.json");
        let first_store = OAuthStore::with_persist_path(path.clone());
        let binding = generate_client_binding();
        first_store
            .try_store_bound_session(
                lifecycle_session(
                    "cross-process-shape",
                    Utc::now() - Duration::seconds(1),
                    true,
                ),
                &binding,
            )
            .expect("store");
        let second_store = OAuthStore::with_persist_path(path);
        let refresher = CountingRefresher {
            calls: std::sync::atomic::AtomicUsize::new(0),
        };

        let (first, second) = tokio::join!(
            first_store.get_session_for_use_with("cross-process-shape", &binding, &refresher),
            second_store.get_session_for_use_with("cross-process-shape", &binding, &refresher)
        );
        assert!(first.is_ok(), "first refresh failed: {first:?}");
        assert!(second.is_ok(), "second refresh failed: {second:?}");
        assert_eq!(refresher.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn durable_revocation_erases_secrets_and_blocks_stale_resurrection() {
        let tmp = tempfile::tempdir().expect("root");
        let path = tmp.path().join("oauth_sessions.json");
        let store = OAuthStore::with_persist_path(path.clone());
        let binding = generate_client_binding();
        let stale = lifecycle_session("revoked-session-id", Utc::now() + Duration::hours(1), true);
        store
            .try_store_bound_session(stale.clone(), &binding)
            .expect("store");
        assert!(store
            .revoke_session_for_client("revoked-session-id", &binding)
            .await
            .expect("revoke"));

        let persisted = fs::read_to_string(&path).expect("persisted tombstone");
        assert!(!persisted.contains("access-revoked-session-id"));
        assert!(!persisted.contains("refresh-revoked-session-id"));
        assert!(!persisted.contains("revoked-session-id"));
        let reopened = OAuthStore::with_persist_path(path);
        let refresher = CountingRefresher {
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        assert!(matches!(
            reopened
                .get_session_for_use_with("revoked-session-id", &binding, &refresher)
                .await,
            Err(OAuthSessionUseError::Revoked)
        ));
        let resurrection = reopened
            .try_store_bound_session(stale, &binding)
            .expect_err("stale record must not resurrect after revocation");
        assert!(resurrection.to_string().contains("revoked"));
    }

    #[cfg(unix)]
    #[test]
    fn legacy_session_map_loads_and_migrates_on_next_commit() {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let tmp = tempfile::tempdir().expect("root");
        let path = tmp.path().join("oauth_sessions.json");
        let legacy = OAuthSessionRecord::new(
            lifecycle_session("legacy-session", Utc::now() + Duration::hours(1), true),
            None,
        );
        let legacy_sessions = HashMap::from([("legacy-session".to_string(), legacy)]);
        let encoded = serde_json::to_vec_pretty(&PersistedOAuthSessionMap(&legacy_sessions))
            .expect("legacy encoding");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("legacy store");
        file.write_all(&encoded).expect("legacy write");
        file.sync_all().expect("legacy fsync");
        drop(file);

        let store = OAuthStore::with_persist_path(path.clone());
        assert!(store.get_session("legacy-session").is_some());
        store
            .try_store_session(lifecycle_session(
                "new-session",
                Utc::now() + Duration::hours(1),
                true,
            ))
            .expect("migration commit");
        let migrated: serde_json::Value =
            serde_json::from_slice(&fs::read(path).expect("migrated store")).expect("json");
        assert_eq!(migrated["schema_version"], OAUTH_STORE_SCHEMA_VERSION);
        assert!(migrated["sessions"]["legacy-session"].is_object());
        assert!(migrated["sessions"]["new-session"].is_object());
    }

    // --- Regression tests for crosslink #801 ---
    //
    // persist_to_disk historically used `fs::write` (which obeys the process
    // umask, typically 0o022 → mode 0o644) and then chmodded the destination
    // to 0o600 *after* rename. That left two windows in which the temp file
    // and the destination contained plaintext OAuth tokens at a world-readable
    // mode. The fix uses `OpenOptions::create_new(true).mode(0o600).open()`
    // on Unix so the file is 0o600 from the very first syscall, and the
    // rename carries that mode to the destination.

    #[cfg(unix)]
    fn make_session(token: &str) -> OAuthSession {
        OAuthSession {
            id: format!("session-{token}"),
            credentials: OAuthCredentials {
                access_token: crate::secrets::OAuthToken::try_from_string(token.to_string())
                    .expect("token"),
                refresh_token: Some(
                    crate::secrets::OAuthToken::try_from_string(format!("refresh-{token}"))
                        .expect("refresh token"),
                ),
                expires_at: Utc::now() + Duration::seconds(3600),
            },
            api_key: None,
            auth_mode: AuthMode::BearerToken,
            granted_scopes: vec!["user:inference".to_string()],
            created_at: Utc::now(),
            user_id: None,
        }
    }

    /// FORENSIC EVIDENCE #1: the destination file lands at exactly mode
    /// 0o600 — never world-readable, never group-readable — even when the
    /// process umask is fully permissive.
    #[cfg(unix)]
    struct UmaskGuard(libc::mode_t);

    #[cfg(unix)]
    impl UmaskGuard {
        fn set(mask: libc::mode_t) -> Self {
            Self(unsafe { libc::umask(mask) })
        }
    }

    #[cfg(unix)]
    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            unsafe {
                libc::umask(self.0);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn persist_to_disk_destination_is_0600_under_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;

        // Create the authorized storage root before changing the process-wide
        // umask, then restore the umask through RAII even if an assertion fails.
        let tmp = tempfile::tempdir().unwrap();
        let umask = UmaskGuard::set(0);
        let path = tmp.path().join("oauth_sessions.json");
        let store = OAuthStore::with_persist_path(path.clone());
        store
            .try_store_session(make_session("alpha-access-token"))
            .expect("protected persistence");

        let mode = fs::metadata(&path)
            .expect("destination file must exist")
            .permissions()
            .mode()
            & 0o777;
        drop(umask);

        assert_eq!(
            mode, 0o600,
            "OAuth session file landed at mode {mode:o} (expected 0o600); \
             other users on the host can read access+refresh tokens"
        );
    }

    /// FORENSIC EVIDENCE #2: while `persist_to_disk` is running, the temp
    /// file is never observable at a mode that would let another user read
    /// the tokens. We race a watcher thread against many writes and assert
    /// that every storage artifact in which token bytes become visible has
    /// mode 0o600. The descriptor-safe persistence layer owns temp naming.
    #[cfg(unix)]
    #[test]
    fn persist_to_disk_tmp_never_world_readable_under_race() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::{Duration as StdDuration, Instant};

        let tmp = tempfile::tempdir().unwrap();
        let umask = UmaskGuard::set(0);
        let path = tmp.path().join("oauth_sessions.json");
        let watch_dir = tmp.path().to_path_buf();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_w = Arc::clone(&stop);

        // Watcher: poll random OAuth temp files as fast as we can and record
        // every mode we observe along with whether the token bytes were there.
        let watcher = thread::spawn(move || -> Vec<(u32, bool)> {
            let mut observations = Vec::new();
            let deadline = Instant::now() + StdDuration::from_secs(3);
            while !stop_w.load(Ordering::Relaxed) && Instant::now() < deadline {
                if let Ok(entries) = fs::read_dir(&watch_dir) {
                    for entry in entries.flatten() {
                        if let Ok(md) = fs::symlink_metadata(entry.path()) {
                            let mode = md.permissions().mode() & 0o777;
                            let has_token = fs::read_to_string(entry.path())
                                .is_ok_and(|s| s.contains("racy-secret-token-CANARY"));
                            if has_token {
                                observations.push((mode, true));
                            }
                        }
                    }
                }
            }
            observations
        });

        // Writer: hammer persist_to_disk so the watcher has many chances
        // to catch the tmp file mid-existence. Include the canary token
        // literal so observed `has_token` flags are meaningful.
        let store = OAuthStore::with_persist_path(path.clone());
        for i in 0..64 {
            store
                .try_store_session(make_session(&format!("racy-secret-token-CANARY-{i}")))
                .expect("protected persistence");
        }

        stop.store(true, Ordering::Relaxed);
        let observations = watcher.join().unwrap();
        drop(umask);

        // Every observation we made of the tmp file must have been at 0o600.
        // If even one snapshot was 0o644 / 0o664 / 0o666 the fix is broken.
        let bad: Vec<_> = observations
            .iter()
            .filter(|(mode, _)| *mode != 0o600)
            .collect();
        assert!(
            bad.is_empty(),
            "tmp file observed at non-0600 mode(s): {:?} out of {} samples — \
             tokens were readable to other host users mid-write",
            bad,
            observations.len()
        );

        // And the destination ends up 0o600 too.
        let dest_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            dest_mode, 0o600,
            "destination mode regressed to {dest_mode:o}"
        );
    }

    /// FORENSIC EVIDENCE #3: a pre-existing legacy `.tmp` file (e.g. a
    /// symlink to `/etc/shadow` staged against the older predictable temp
    /// name, or stale crash residue) must not be truncated. Persistence now
    /// uses random `oauth_sessions.json.tmp.*` siblings, so the stale file is
    /// left untouched while the real destination is still written.
    #[cfg(unix)]
    #[test]
    fn persist_to_disk_does_not_clobber_legacy_tmp_path() {
        use std::io::Write;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("oauth_sessions.json");
        let tmp_path = path.with_extension("tmp");

        // Stage a foreign file at the tmp path. In the real attack this
        // would be a symlink to /etc/shadow; here we use a regular file
        // with a sentinel we can check survived intact.
        let attacker_sentinel = b"DO_NOT_OVERWRITE_attacker_owned_bytes";
        {
            let mut f = fs::File::create(&tmp_path).unwrap();
            f.write_all(attacker_sentinel).unwrap();
        }

        let store = OAuthStore::with_persist_path(path.clone());
        store.store_session(make_session("beta-access-token"));

        // Attacker file untouched.
        let after = fs::read(&tmp_path).expect("attacker file should still exist");
        assert_eq!(
            after, attacker_sentinel,
            "persist_to_disk truncated a pre-existing legacy .tmp file"
        );

        // Destination is still written through the random temp path.
        assert!(
            path.exists(),
            "persist_to_disk should ignore stale legacy .tmp and use a random sibling"
        );
    }

    /// FORENSIC EVIDENCE #4: control assertion — the round-trip actually
    /// persists token bytes to disk. Proves the watcher in test #2 was
    /// looking at the right bytes, and proves that a regression to
    /// `fs::write` would in fact leak the token to disk in plaintext.
    #[cfg(unix)]
    #[test]
    fn persist_to_disk_round_trips_token_at_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("oauth_sessions.json");
        let store = OAuthStore::with_persist_path(path.clone());
        store.store_session(make_session("gamma-token-marker"));

        let bytes = fs::read_to_string(&path).expect("destination must exist");
        assert!(
            bytes.contains("gamma-token-marker"),
            "round-trip failed: token absent from on-disk file (test #2's premise is invalid)"
        );
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// Binary-facing contract: callers that promise "session saved" must be
    /// able to distinguish durable persistence from process-local storage.
    #[cfg(unix)]
    #[test]
    fn try_store_session_reports_persistence_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let blocked_parent = tmp.path().join("not-a-directory");
        fs::write(&blocked_parent, b"file blocks directory creation").unwrap();
        let path = blocked_parent.join("oauth_sessions.json");
        let store = OAuthStore::with_persist_path(path);

        let err = store
            .try_store_session(make_session("delta-token-marker"))
            .expect_err("try_store_session must report disk persistence failure");
        let message = format!("{err:#}");

        assert!(
            message.contains("failed to create OAuth lock directory"),
            "unexpected persistence error: {message}"
        );
        assert!(
            store.get_session("session-delta-token-marker").is_none(),
            "a failed durable claim must not publish a process-local session"
        );
    }

    /// FORENSIC EVIDENCE #5: two independent store instances writing the
    /// same persistence file must merge under the advisory lock instead of
    /// losing the first writer's session.
    #[cfg(unix)]
    #[test]
    fn persist_to_disk_merges_sessions_from_independent_stores() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("oauth_sessions.json");
        let store_a = OAuthStore::with_persist_path(path.clone());
        let store_b = OAuthStore::with_persist_path(path.clone());

        store_a.store_session(make_session("alpha-race-token"));
        store_b.store_session(make_session("beta-race-token"));

        let bytes = fs::read_to_string(&path).expect("destination must exist");
        assert!(
            bytes.contains("alpha-race-token"),
            "second store overwrote first store's persisted session"
        );
        assert!(
            bytes.contains("beta-race-token"),
            "second store did not persist its own session"
        );

        let reloaded = OAuthStore::with_persist_path(path);
        reloaded.load_from_disk();
        assert!(reloaded.get_session("session-alpha-race-token").is_some());
        assert!(reloaded.get_session("session-beta-race-token").is_some());
    }
}
