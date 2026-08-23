//! OAuth 2.0 Device Flow Authentication for Claude Max subscriptions
//!
//! Enables `OpenClaudia` to authenticate using Claude Pro/Max subscriptions
//! via OAuth 2.0 device authorization flow with PKCE.
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
use std::fs;
use std::path::PathBuf;
use std::sync::RwLock;
use tracing::{debug, error, info};
use zeroize::Zeroizing;

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// Borrowed serializer used only by the owner-only OAuth session store.
///
/// Runtime `Serialize` implementations stay redacted. This wrapper is the
/// single explicit persistence boundary where live credential bytes are
/// written to a `0600` file, and it never creates another owned secret copy.
struct PersistedOAuthSessionRef<'a>(&'a OAuthSession);

impl Serialize for PersistedOAuthSessionRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let session = self.0;
        let mut state = serializer.serialize_struct("OAuthSession", 7)?;
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

struct PersistedOAuthSessionMap<'a>(&'a HashMap<String, OAuthSession>);

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
}

impl PersistedOAuthSession {
    fn into_runtime(self) -> OAuthSession {
        OAuthSession {
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
        }
    }
}

/// Thread-safe storage for OAuth sessions and pending PKCE challenges
pub struct OAuthStore {
    /// Active sessions keyed by session ID
    sessions: RwLock<HashMap<String, OAuthSession>>,
    /// Pending PKCE challenges retaining the state only in protected storage.
    pending_challenges: RwLock<Vec<PkceParams>>,
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
            let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if ret != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("failed to lock {}", lock_path.display()));
            }
        }

        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;

            const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
            let mut overlapped =
                std::mem::MaybeUninit::<windows_sys::Win32::System::IO::OVERLAPPED>::zeroed();
            let ok = unsafe {
                windows_sys::Win32::Storage::FileSystem::LockFileEx(
                    file.as_raw_handle() as _,
                    LOCKFILE_EXCLUSIVE_LOCK,
                    0,
                    0xFFFF_FFFF,
                    0xFFFF_FFFF,
                    overlapped.as_mut_ptr(),
                )
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("failed to lock {}", lock_path.display()));
            }
        }

        Ok(Self { _file: file })
    }
}

fn oauth_session_lock_path(path: &std::path::Path) -> PathBuf {
    path.with_extension("json.lock")
}

#[cfg(unix)]
fn oauth_session_tmp_path(path: &std::path::Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("oauth_sessions.json");
    path.with_file_name(format!(
        "{file_name}.tmp.{}.{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ))
}

fn read_valid_sessions_from_disk(path: &std::path::Path) -> Option<HashMap<String, OAuthSession>> {
    let file = open_oauth_session_file(path)?;
    match std::io::read_to_string(file) {
        Ok(data) => {
            let data = Zeroizing::new(data);
            decode_oauth_sessions(&data, path)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug!("No persisted OAuth sessions found");
            None
        }
        Err(e) => {
            error!("Failed to load OAuth sessions: {}", e);
            None
        }
    }
}

fn open_oauth_session_file(path: &std::path::Path) -> Option<fs::File> {
    // Open the session file refusing to follow symlinks (crosslink #814).
    // With O_NOFOLLOW the open itself fails with ELOOP on a symlink, so there
    // is no post-open race window.
    //
    // On non-Unix targets there is no O_NOFOLLOW equivalent here; fall back to
    // the prior open-then-check pattern.
    Some({
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            match fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
            {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    debug!("No persisted OAuth sessions found");
                    return None;
                }
                Err(e) => {
                    if e.raw_os_error() == Some(libc::ELOOP) {
                        error!(
                            "OAuth session file {} is a symlink — refusing to read for security",
                            path.display()
                        );
                    } else {
                        tracing::warn!(
                            "Failed to open OAuth session file {}: {}",
                            path.display(),
                            e
                        );
                    }
                    return None;
                }
            }
        }
        #[cfg(not(unix))]
        {
            let f = match fs::File::open(path) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    debug!("No persisted OAuth sessions found");
                    return None;
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to open OAuth session file {}: {}",
                        path.display(),
                        e
                    );
                    return None;
                }
            };
            if path
                .symlink_metadata()
                .is_ok_and(|sm| sm.file_type().is_symlink())
            {
                error!(
                    "OAuth session file {} is a symlink — refusing to read for security",
                    path.display()
                );
                return None;
            }
            f
        }
    })
}

fn decode_oauth_sessions(
    data: &str,
    path: &std::path::Path,
) -> Option<HashMap<String, OAuthSession>> {
    let persisted = match serde_json::from_str::<HashMap<String, PersistedOAuthSession>>(data) {
        Ok(persisted) => persisted,
        Err(e) => {
            error!(
                "Failed to parse OAuth sessions from {}: {}",
                path.display(),
                e
            );
            return None;
        }
    };
    let loaded = persisted
        .into_iter()
        .map(|(storage_id, persisted)| {
            let session = persisted.into_runtime();
            if storage_id != session.id {
                anyhow::bail!("OAuth session map key does not match embedded session id");
            }
            Ok((storage_id, session))
        })
        .collect::<Result<HashMap<_, _>>>();
    match loaded {
        Ok(loaded) => Some(
            loaded
                .into_iter()
                .filter(|(id, session)| {
                    if session.credentials.is_expired() {
                        info!("Removing expired OAuth session: {}", id);
                        false
                    } else {
                        true
                    }
                })
                .collect(),
        ),
        Err(e) => {
            error!(
                "Failed to validate OAuth sessions from {}: {e:#}",
                path.display()
            );
            None
        }
    }
}

impl Default for OAuthStore {
    fn default() -> Self {
        Self::new()
    }
}

impl OAuthStore {
    /// Create new OAuth store with optional persistence
    #[must_use]
    pub fn new() -> Self {
        let persist_path =
            dirs::data_local_dir().map(|d| d.join("openclaudia").join("oauth_sessions.json"));

        let store = Self {
            sessions: RwLock::new(HashMap::new()),
            pending_challenges: RwLock::new(Vec::new()),
            persist_path: persist_path.clone(),
        };

        // Load persisted sessions
        if persist_path.is_some() {
            store.load_from_disk();
        }

        store
    }

    /// Construct a store with a caller-supplied persistence path. Used by
    /// the `persist_to_disk` regression suite (crosslink #801) so tests
    /// don't have to clobber `$XDG_DATA_HOME`.
    #[cfg(test)]
    pub(crate) fn with_persist_path(path: PathBuf) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            pending_challenges: RwLock::new(Vec::new()),
            persist_path: Some(path),
        }
    }

    /// Store PKCE challenge for pending authorization
    pub fn store_challenge(&self, pkce: PkceParams) {
        let mut challenges = self
            .pending_challenges
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = challenges
            .iter_mut()
            .find(|candidate| candidate.state == pkce.state)
        {
            *existing = pkce;
        } else {
            challenges.push(pkce);
        }
    }

    /// Retrieve and remove PKCE challenge by state
    pub fn take_challenge(&self, state: &str) -> Option<PkceParams> {
        let mut challenges = self
            .pending_challenges
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = challenges
            .iter()
            .position(|candidate| candidate.state.matches(state))?;
        Some(challenges.swap_remove(index))
    }

    /// Store new OAuth session and report persistence failures to the caller.
    ///
    /// The session is inserted into the in-memory map before the disk write so
    /// long-running proxy/server processes can still use freshly-authenticated
    /// credentials in this process. Callers that make a user-facing durability
    /// claim, such as `openclaudia auth`, must use this fallible variant and
    /// only report success after it returns `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns an error if the session cannot be durably persisted to disk.
    /// The session still remains available from this store's in-memory map.
    pub fn try_store_session(&self, session: OAuthSession) -> Result<()> {
        let id = session.id.clone();
        {
            let mut sessions = self
                .sessions
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            sessions.insert(id.clone(), session);
        }
        self.persist_to_disk()?;
        info!("OAuth session stored: {}", id);
        Ok(())
    }

    /// Store new OAuth session.
    ///
    /// Compatibility wrapper for non-CLI callers that already tolerate a
    /// process-local session when persistence is unavailable. Use
    /// [`Self::try_store_session`] when the caller needs to surface disk write
    /// failures to a human.
    pub fn store_session(&self, session: OAuthSession) {
        if let Err(e) = self.try_store_session(session) {
            error!("Failed to persist OAuth session: {e:#}");
        }
    }

    /// Retrieve session by ID
    pub fn get_session(&self, id: &str) -> Option<OAuthSession> {
        let sessions = self
            .sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sessions.get(id).cloned()
    }

    // `get_any_valid_session` was deleted as part of crosslink #375 (critical).
    // It returned the first valid OAuth session regardless of caller identity,
    // which let any unauthenticated request impersonate an authenticated one.
    // Callers must now look up sessions by explicit `anthropic_session` cookie
    // via `get_session(&id)`; no ambient-session fallback remains.

    /// Load sessions from disk, filtering out expired ones
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

        if let Some(valid_sessions) = read_valid_sessions_from_disk(path) {
            let mut sessions = self
                .sessions
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *sessions = valid_sessions;
            let session_count = sessions.len();
            drop(sessions);
            info!("Loaded {} OAuth sessions from disk", session_count);
        }
    }

    #[cfg(unix)]
    fn replace_sessions_in_memory(&self, sessions: HashMap<String, OAuthSession>) {
        let mut guard = self
            .sessions
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = sessions;
    }

    /// Persist sessions to disk with restrictive file permissions.
    ///
    /// # Security (crosslink #801)
    ///
    /// On Unix, the temp file is created with `O_CREAT | O_EXCL | O_WRONLY`
    /// at mode `0o600` in a single `open(2)` call. This closes two
    /// pre-existing windows in which plaintext OAuth tokens were
    /// world-readable on disk:
    ///
    /// 1. **Mid-write readability**: previously `fs::write` created the
    ///    temp file with the process umask (typically `0o022` →
    ///    `mode 0o644`), exposing the access+refresh tokens to any other
    ///    user on the host for the window between write and the post-rename
    ///    `chmod`. The destination also inherited the temp file's loose
    ///    permissions across the rename.
    /// 2. **Temp-file pre-creation / symlink attack**: `fs::write` happily
    ///    truncates an existing `.tmp` file, including one staged as a
    ///    symlink to e.g. `/etc/shadow`. `O_EXCL` rejects any pre-existing
    ///    path (regular file or symlink), forcing us to fail closed.
    ///
    /// On non-Unix targets we refuse to persist credentials — there is no
    /// portable way to atomically create-with-mode, and persisting plaintext
    /// OAuth tokens to a world-readable file would be worse than losing the
    /// session on shutdown.
    #[allow(clippy::too_many_lines)]
    fn persist_to_disk(&self) -> Result<()> {
        let Some(path) = &self.persist_path else {
            return Ok(());
        };

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create OAuth session directory {}",
                    parent.display()
                )
            })?;
        }

        let local_sessions = self
            .sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();

        let _lock = match OAuthSessionFileLock::acquire_for(path) {
            Ok(lock) => lock,
            Err(e) => {
                error!("Failed to lock OAuth sessions for persist: {e:#}");
                return Err(e).with_context(|| {
                    format!("failed to lock OAuth session file {}", path.display())
                });
            }
        };

        let mut merged_sessions = read_valid_sessions_from_disk(path).unwrap_or_default();
        merged_sessions.extend(local_sessions);

        let json = match serde_json::to_string_pretty(&PersistedOAuthSessionMap(&merged_sessions)) {
            Ok(j) => Zeroizing::new(j),
            Err(e) => {
                error!("Failed to serialize OAuth sessions: {}", e);
                return Err(e).context("failed to serialize OAuth sessions");
            }
        };

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

            let tmp_path = oauth_session_tmp_path(path);

            // Atomically create the temp file with O_CREAT|O_EXCL|O_WRONLY
            // at mode 0o600. The random sibling name plus create_new avoids
            // clobbering stale crash residue or a pre-planted symlink.
            let mut file = match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)
            {
                Ok(f) => f,
                Err(e) => {
                    error!(
                        "Failed to create OAuth temp file {} (mode 0600, exclusive): {}",
                        tmp_path.display(),
                        e
                    );
                    return Err(e).with_context(|| {
                        format!(
                            "failed to create OAuth temp file {} (mode 0600, exclusive)",
                            tmp_path.display()
                        )
                    });
                }
            };

            if let Err(e) = file.write_all(json.as_bytes()) {
                error!("Failed to write OAuth temp file: {}", e);
                drop(file);
                let _ = fs::remove_file(&tmp_path);
                return Err(e).with_context(|| {
                    format!("failed to write OAuth temp file {}", tmp_path.display())
                });
            }
            if let Err(e) = file.sync_all() {
                error!("Failed to fsync OAuth temp file: {}", e);
                drop(file);
                let _ = fs::remove_file(&tmp_path);
                return Err(e).with_context(|| {
                    format!("failed to fsync OAuth temp file {}", tmp_path.display())
                });
            }
            drop(file);

            // The rename inherits the tmp file's already-restrictive 0o600
            // mode, so the destination is never observable as world-readable.
            if let Err(e) = fs::rename(&tmp_path, path) {
                error!("Failed to rename OAuth temp file: {}", e);
                let _ = fs::remove_file(&tmp_path);
                return Err(e).with_context(|| {
                    format!(
                        "failed to move OAuth temp file {} into {}",
                        tmp_path.display(),
                        path.display()
                    )
                });
            }

            // Defense-in-depth: re-assert 0o600 on the destination in case
            // an older run (pre-fix) left a 0o644 destination inode that a
            // filesystem chose to preserve across rename.
            if let Ok(metadata) = fs::metadata(path) {
                let mut perms = metadata.permissions();
                if perms.mode() & 0o777 != 0o600 {
                    perms.set_mode(0o600);
                    if let Err(e) = fs::set_permissions(path, perms) {
                        error!("Failed to enforce 0o600 on OAuth session file: {}", e);
                        return Err(e).with_context(|| {
                            format!(
                                "failed to enforce 0o600 on OAuth session file {}",
                                path.display()
                            )
                        });
                    }
                }
            }
        }

        #[cfg(not(unix))]
        {
            let _ = json; // suppress unused-variable warning on non-unix
            let _ = merged_sessions;
            error!(
                "Refusing to persist OAuth sessions on non-Unix target: no portable way to \
                 atomically create the file with owner-only permissions. OAuth sessions will \
                 not survive process restart on this platform."
            );
            anyhow::bail!(
                "refusing to persist OAuth sessions on non-Unix target: no portable way to \
                 atomically create the file with owner-only permissions"
            );
        }

        #[cfg(unix)]
        {
            self.replace_sessions_in_memory(merged_sessions);
            Ok(())
        }
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
    pub fn new() -> Result<Self, crate::provider_transport::ProviderTransportError> {
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
    #[test]
    fn persist_to_disk_destination_is_0600_under_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;

        // Force a permissive umask so any unguarded `open(2)` call would
        // produce 0o666-derived modes. If the fix regresses, this test
        // catches it even on machines whose default umask is 0o022.
        // SAFETY: umask is process-global. We restore the previous value
        // before returning.
        let prev_umask = unsafe { libc::umask(0) };

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("oauth_sessions.json");
        let store = OAuthStore::with_persist_path(path.clone());
        store.store_session(make_session("alpha-access-token"));

        let mode = fs::metadata(&path)
            .expect("destination file must exist")
            .permissions()
            .mode()
            & 0o777;

        // Restore umask before any assertion that might unwind.
        unsafe { libc::umask(prev_umask) };

        assert_eq!(
            mode, 0o600,
            "OAuth session file landed at mode {mode:o} (expected 0o600); \
             other users on the host can read access+refresh tokens"
        );
    }

    /// FORENSIC EVIDENCE #2: while `persist_to_disk` is running, the temp
    /// file is never observable at a mode that would let another user read
    /// the tokens. We race a watcher thread against many writes and assert
    /// that every snapshot we caught of the `.tmp` file had mode 0o600.
    /// Before the fix, the watcher would catch 0o666 (under zeroed umask)
    /// containing the literal token bytes.
    #[cfg(unix)]
    #[test]
    fn persist_to_disk_tmp_never_world_readable_under_race() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::{Duration as StdDuration, Instant};

        let prev_umask = unsafe { libc::umask(0) };

        let tmp = tempfile::tempdir().unwrap();
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
                        let file_name = entry.file_name();
                        let file_name = file_name.to_string_lossy();
                        if !file_name.starts_with("oauth_sessions.json.tmp.") {
                            continue;
                        }
                        if let Ok(md) = fs::symlink_metadata(entry.path()) {
                            let mode = md.permissions().mode() & 0o777;
                            let has_token = fs::read_to_string(entry.path())
                                .is_ok_and(|s| s.contains("racy-secret-token-CANARY"));
                            observations.push((mode, has_token));
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
        for i in 0..500 {
            store.store_session(make_session(&format!("racy-secret-token-CANARY-{i}")));
        }

        stop.store(true, Ordering::Relaxed);
        let observations = watcher.join().unwrap();
        unsafe { libc::umask(prev_umask) };

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
            message.contains("failed to create OAuth session directory"),
            "unexpected persistence error: {message}"
        );
        assert!(
            store.get_session("session-delta-token-marker").is_some(),
            "failed persistence should still leave the current process with the session"
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
