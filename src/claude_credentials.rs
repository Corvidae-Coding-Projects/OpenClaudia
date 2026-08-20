//! Claude Code credential reader for direct Anthropic API authentication.
//!
//! Reads OAuth tokens from Claude Code's credential store (`~/.claude/.credentials.json`)
//! and uses them directly with the Anthropic Messages API via `Authorization: Bearer`.
//! Handles automatic token refresh when tokens are expired.
//!
//! This enables `OpenClaudia` users who have Claude Code installed and logged in
//! to use their existing subscription without an API key or proxy.

use serde::ser::SerializeStruct as _;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Claude Code's OAuth client ID (public, hardcoded in Claude Code source)
const CLAUDE_CODE_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

/// Token exchange/refresh endpoint
const TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";

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

/// 5 minute buffer before expiry to trigger refresh
const REFRESH_BUFFER_MS: i64 = 5 * 60 * 1000;

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
    claude_config_dir().map(|dir| dir.join(".credentials.json"))
}

/// Path to the advisory lock file for credential access.
fn lock_path() -> Option<PathBuf> {
    claude_config_dir().map(|dir| dir.join(".credentials.lock"))
}

/// Advisory file lock for credential access.
/// Prevents TOCTOU race conditions when multiple processes refresh tokens.
/// Uses flock on Unix, `CreateFile` exclusive lock on Windows.
struct CredentialLock {
    _file: std::fs::File,
}

impl CredentialLock {
    /// Acquire an exclusive lock on the credentials lock file.
    /// Blocks until the lock is available.
    fn acquire() -> Result<Self, String> {
        let path = lock_path().ok_or("Cannot determine home directory for lock file")?;

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // Note (crosslink #492 follow-up): this `OpenOptions::open` site is a
        // remaining candidate for `FileError`. The focused #492 pass left it on
        // `String` because converting `CredentialLock` to return `FileError`
        // would also require accommodating the libc::flock branch below
        // (an OS syscall, not file-content I/O). Tracked for a follow-up pass
        // so the public `acquire(...) -> Result<_, String>` contract stays
        // stable until that wider change is scoped.
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| format!("Failed to open lock file {}: {e}", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            // LOCK_EX = exclusive, blocks until acquired
            let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
            if ret != 0 {
                return Err(format!(
                    "Failed to acquire credential lock: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;

            const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
            let handle = file.as_raw_handle();
            let mut overlapped =
                std::mem::MaybeUninit::<windows_sys::Win32::System::IO::OVERLAPPED>::zeroed();
            // SAFETY: Win32 accepts a zeroed OVERLAPPED for synchronous
            // LockFileEx calls with a blocking file handle.
            let ret = unsafe {
                windows_sys::Win32::Storage::FileSystem::LockFileEx(
                    handle as _,
                    LOCKFILE_EXCLUSIVE_LOCK,
                    0,
                    0xFFFF_FFFF,
                    0xFFFF_FFFF,
                    overlapped.as_mut_ptr(),
                )
            };
            if ret == 0 {
                return Err(format!(
                    "Failed to acquire credential lock: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        // Lock is released when the File is dropped:
        //   Unix: flock is released on close.
        //   Windows: CloseHandle releases the LockFileEx lock.
        Ok(Self { _file: file })
    }
}

/// Check if Claude Code credentials exist
#[must_use]
pub fn has_claude_code_credentials() -> bool {
    credentials_path().is_some_and(|p| p.exists())
}

/// Load Claude Code credentials, refreshing if expired.
///
/// Returns the access token ready for use as `Authorization: Bearer <token>`.
///
/// # Errors
///
/// Returns an error if credentials cannot be found, read, parsed, or refreshed.
pub async fn load_credentials() -> Result<LoadedCredentials, String> {
    // Acquire advisory lock — prevents race conditions with other OpenClaudia
    // instances or Claude Code refreshing tokens concurrently.
    let _lock = CredentialLock::acquire()?;

    let path = credentials_path().ok_or("Cannot determine home directory")?;

    if !path.exists() {
        return Err(format!(
            "Claude Code credentials not found at {}. Run `claude` and log in first.",
            path.display()
        ));
    }

    // Reject symlinks to prevent credential theft via symlink attacks
    if path
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink())
    {
        return Err(format!(
            "Credentials file {} is a symlink — refusing to read for security",
            path.display()
        ));
    }

    // File I/O and JSON parsing flow through the typed `FileError` enum so
    // the underlying io::ErrorKind / serde_json::Error are preserved on the
    // way out — see crosslink #492. We stringify here at the public boundary
    // because `load_credentials` still returns `Result<_, String>` for
    // backwards-compat with existing callers; the rendered message now
    // always names the file and the source chain.
    let content = zeroize::Zeroizing::new(
        crate::file_error::read_file(&path)
            .map_err(|e: crate::file_error::FileError| e.to_string())?,
    );

    let creds: CredentialsFile = serde_json::from_str(&content)
        .map_err(crate::file_error::FileError::json_with_path(&path))
        .map_err(|e| e.to_string())?;

    let oauth = creds
        .claude_ai_oauth
        .ok_or("No claudeAiOauth section in credentials file")?;

    // Check if user:inference scope is present
    if !oauth.scopes.iter().any(|s| s == "user:inference") {
        return Err(
            "Claude Code credentials lack 'user:inference' scope. Re-login with Claude Code."
                .to_string(),
        );
    }

    // Check expiry (with 5 minute buffer)
    let now_ms = chrono::Utc::now().timestamp_millis();
    if now_ms + REFRESH_BUFFER_MS >= oauth.expires_at {
        info!("Claude Code token expired or expiring soon, refreshing...");
        return refresh_and_load(&path, &oauth).await;
    }

    debug!(
        "Claude Code credentials loaded (expires in {}s, type: {:?})",
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

/// Refresh the token and update the credentials file.
///
/// Caller must hold `CredentialLock` — this function reads, refreshes via API,
/// and writes the credentials file. The lock prevents concurrent processes from
/// racing on the same file.
/// Call the OAuth token-refresh endpoint and return the raw JSON response body.
async fn call_token_refresh_api(
    refresh_token: &crate::secrets::OAuthToken,
    scopes: &str,
) -> Result<TokenRefreshResponse, String> {
    #[derive(Serialize)]
    struct TokenRefreshRequest<'a> {
        grant_type: &'static str,
        refresh_token: &'a str,
        client_id: &'static str,
        scope: &'a str,
    }

    let client = reqwest::Client::new();
    let request = refresh_token.expose(|refresh_raw| {
        client.post(TOKEN_URL).json(&TokenRefreshRequest {
            grant_type: "refresh_token",
            refresh_token: refresh_raw,
            client_id: CLAUDE_CODE_CLIENT_ID,
            scope: scopes,
        })
    });
    let response = request
        .send()
        .await
        .map_err(|e| format!("Token refresh request failed: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = crate::secrets::read_bounded_diagnostic_body(response)
            .await
            .map_err(|error| format!("Failed to read token refresh error body: {error}"))?;
        let known = refresh_token.secret();
        let safe = crate::secrets::sanitize_diagnostic(&body, [&known]);
        tracing::debug!(status = %status, body = %safe, "token refresh failed");
        return Err(format!("Token refresh failed ({status}): {safe}"));
    }

    response
        .json()
        .await
        .map_err(|e| format!("Failed to parse refresh response: {e}"))
}

#[derive(Deserialize)]
struct TokenRefreshResponse {
    access_token: crate::secrets::OAuthToken,
    refresh_token: Option<crate::secrets::OAuthToken>,
    expires_in: i64,
    scope: Option<String>,
}

/// Resolve the `refresh_token` to persist after a successful refresh.
///
/// Returns the response's `refresh_token` field when present. When absent,
/// requires `OPENCLAUDIA_ALLOW_REFRESH_TOKEN_REUSE=1` to be set before
/// silently reusing the old one — see crosslink #825.
fn resolve_new_refresh_token(
    response_field: Option<crate::secrets::OAuthToken>,
    previous_refresh_token: &crate::secrets::OAuthToken,
) -> Result<crate::secrets::OAuthToken, String> {
    if let Some(token) = response_field {
        return Ok(token);
    }
    let allow_reuse = std::env::var("OPENCLAUDIA_ALLOW_REFRESH_TOKEN_REUSE")
        .ok()
        .as_deref()
        == Some("1");
    if !allow_reuse {
        return Err(
            "Refresh response omitted 'refresh_token' field; refusing to reuse \
             the previous one (set OPENCLAUDIA_ALLOW_REFRESH_TOKEN_REUSE=1 to \
             opt in if your provider uses non-rotating refresh tokens)"
                .to_string(),
        );
    }
    tracing::warn!(
        "Refresh response omitted 'refresh_token' field; reusing previous \
         refresh token under OPENCLAUDIA_ALLOW_REFRESH_TOKEN_REUSE=1 — if your \
         provider rotates refresh tokens this will break on the next refresh"
    );
    Ok(previous_refresh_token.clone())
}

async fn refresh_and_load(path: &Path, oauth: &ClaudeAiOauth) -> Result<LoadedCredentials, String> {
    const MIN_EXPIRES_IN_SECS: i64 = 60;
    const MAX_EXPIRES_IN_SECS: i64 = 30 * 24 * 3600;

    let refresh_token = oauth
        .refresh_token
        .as_ref()
        .ok_or("No refresh token available — re-login with Claude Code")?;

    let scopes = oauth.scopes.join(" ");
    let refresh_response = call_token_refresh_api(refresh_token, &scopes).await?;

    let new_access_token = refresh_response.access_token;

    // Crosslink #825: when the refresh response omits the `refresh_token`
    // field, the OAuth server may either (a) be using non-rotating refresh
    // tokens — in which case reusing the old one is intentional — or (b) be
    // returning a partial / broken response. Silently reusing the old token
    // under (b) means we could lose the ability to refresh on the *next*
    // cycle without any operator-visible signal. Require an explicit
    // opt-in (`OPENCLAUDIA_ALLOW_REFRESH_TOKEN_REUSE=1`) before reusing,
    // and `warn!` so it shows up in logs either way.
    let new_refresh_token =
        resolve_new_refresh_token(refresh_response.refresh_token, refresh_token)?;

    // `expires_in` is required by the OAuth spec — refuse to silently
    // default to 3600 when the field is missing or malformed. A missing
    // field indicates a protocol deviation the operator needs to see.
    // Clamp the received value to [60s, 30d] with a tracing warn on any
    // clamp to avoid 401-retry loops (too short) and multi-year tokens
    // (too long). See crosslink #480.
    let expires_in_raw = refresh_response.expires_in;
    if expires_in_raw <= 0 {
        return Err(format!(
            "Refresh response returned non-positive 'expires_in' ({expires_in_raw})"
        ));
    }
    let expires_in = if expires_in_raw < MIN_EXPIRES_IN_SECS {
        tracing::warn!(
            received = expires_in_raw,
            clamped_to = MIN_EXPIRES_IN_SECS,
            "Refresh expires_in too small; clamping to avoid 401-retry loop"
        );
        MIN_EXPIRES_IN_SECS
    } else if expires_in_raw > MAX_EXPIRES_IN_SECS {
        tracing::warn!(
            received = expires_in_raw,
            clamped_to = MAX_EXPIRES_IN_SECS,
            "Refresh expires_in too large; clamping to refuse multi-year tokens"
        );
        MAX_EXPIRES_IN_SECS
    } else {
        expires_in_raw
    };

    let new_expires_at = chrono::Utc::now().timestamp_millis() + (expires_in * 1000);

    // Parse scopes from response
    let new_scopes: Vec<String> = refresh_response.scope.as_deref().map_or_else(
        || oauth.scopes.clone(),
        |s| s.split_whitespace().map(String::from).collect(),
    );

    // Update credentials file
    let updated = CredentialsFile {
        claude_ai_oauth: Some(ClaudeAiOauth {
            access_token: new_access_token.clone(),
            refresh_token: Some(new_refresh_token),
            expires_at: new_expires_at,
            scopes: new_scopes.clone(),
            subscription_type: oauth.subscription_type.clone(),
            rate_limit_tier: oauth.rate_limit_tier.clone(),
        }),
    };

    write_credentials_file(path, &updated)?;

    info!("Token refreshed successfully (expires in {}s)", expires_in);

    Ok(LoadedCredentials {
        access_token: new_access_token,
        subscription_type: oauth.subscription_type.clone(),
        rate_limit_tier: oauth.rate_limit_tier.clone(),
        scopes: new_scopes,
    })
}

fn reject_credentials_symlink(path: &Path) -> Result<(), String> {
    if path
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink())
    {
        return Err(format!(
            "Credentials file {} is a symlink — refusing to write for security",
            path.display()
        ));
    }
    Ok(())
}

/// Explicit serializer for Claude Code's owner-only credential file.
/// Generic `CredentialsFile` serialization remains redacted.
struct PersistedCredentialsFileRef<'a>(&'a CredentialsFile);

impl Serialize for PersistedCredentialsFileRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("CredentialsFile", 1)?;
        let oauth = self
            .0
            .claude_ai_oauth
            .as_ref()
            .map(PersistedClaudeAiOauthRef);
        state.serialize_field("claudeAiOauth", &oauth)?;
        state.end()
    }
}

struct PersistedClaudeAiOauthRef<'a>(&'a ClaudeAiOauth);

impl Serialize for PersistedClaudeAiOauthRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let oauth = self.0;
        let mut state = serializer.serialize_struct("ClaudeAiOauth", 6)?;
        oauth
            .access_token
            .expose(|raw| state.serialize_field("accessToken", raw))?;
        if let Some(refresh_token) = &oauth.refresh_token {
            refresh_token.expose(|raw| state.serialize_field("refreshToken", raw))?;
        } else {
            state.serialize_field("refreshToken", &Option::<&str>::None)?;
        }
        state.serialize_field("expiresAt", &oauth.expires_at)?;
        state.serialize_field("scopes", &oauth.scopes)?;
        state.serialize_field("subscriptionType", &oauth.subscription_type)?;
        state.serialize_field("rateLimitTier", &oauth.rate_limit_tier)?;
        state.end()
    }
}

/// Serialize and atomically write a [`CredentialsFile`] to `path`.
///
/// The target must not be a symlink. The replacement is written to a random
/// sibling temp file created with `create_new`, then atomically moved into
/// place. On Unix the temp file is created as `0600` before secret bytes are
/// written.
fn write_credentials_file(path: &Path, creds: &CredentialsFile) -> Result<(), String> {
    reject_credentials_symlink(path)?;

    let parent = path.parent().ok_or_else(|| {
        format!(
            "credentials path {} has no parent directory",
            path.display()
        )
    })?;
    crate::file_error::create_dir_all(parent).map_err(|e| e.to_string())?;

    let json = zeroize::Zeroizing::new(
        serde_json::to_vec_pretty(&PersistedCredentialsFileRef(creds))
            .map_err(crate::file_error::FileError::json_with_path(path))
            .map_err(|e| e.to_string())?,
    );

    let tmp = match write_secret_tmp(parent, &json) {
        Ok(tmp) => tmp,
        Err(e) => return Err(format!("Failed to write credentials temp file: {e}")),
    };

    if let Err(e) = crate::file_error::replace_file_atomic(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("Failed to replace {}: {e}", path.display()));
    }
    sync_parent_dir(parent);
    Ok(())
}

fn write_secret_tmp(parent: &Path, bytes: &[u8]) -> std::io::Result<PathBuf> {
    use std::io::{ErrorKind, Write};

    let mut last_exists = None;
    for _ in 0..16 {
        let tmp = parent.join(format!(
            ".credentials.json.tmp.{}.{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));

        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        match options.open(&tmp) {
            Ok(mut file) => {
                file.write_all(bytes)?;
                if let Err(e) = file.sync_all() {
                    tracing::warn!(path = ?tmp, error = %e, "Failed to fsync credentials temp file");
                }
                return Ok(tmp);
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                last_exists = Some(e);
            }
            Err(e) => return Err(e),
        }
    }

    Err(last_exists.unwrap_or_else(|| {
        std::io::Error::new(
            ErrorKind::AlreadyExists,
            "could not allocate unique credentials temp file",
        )
    }))
}

#[cfg(unix)]
fn sync_parent_dir(parent: &Path) {
    if let Err(e) = std::fs::OpenOptions::new()
        .read(true)
        .open(parent)
        .and_then(|dir| dir.sync_all())
    {
        tracing::warn!(path = ?parent, error = %e, "Failed to fsync credentials directory");
    }
}

#[cfg(not(unix))]
fn sync_parent_dir(_parent: &Path) {}

fn read_existing_oauth(path: &Path) -> Option<ClaudeAiOauth> {
    if !path.exists()
        || path
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
    {
        return None;
    }
    crate::file_error::read_file(path)
        .ok()
        .and_then(|content| {
            let content = zeroize::Zeroizing::new(content);
            serde_json::from_str::<CredentialsFile>(&content).ok()
        })
        .and_then(|creds| creds.claude_ai_oauth)
}

fn merge_oauth_fields(
    access_token: &crate::secrets::OAuthToken,
    refresh_token: Option<&crate::secrets::OAuthToken>,
    expires_at_ms: i64,
    scopes: Vec<String>,
    subscription_type: Option<String>,
    rate_limit_tier: Option<String>,
    existing: Option<&ClaudeAiOauth>,
) -> ClaudeAiOauth {
    ClaudeAiOauth {
        access_token: access_token.clone(),
        refresh_token: refresh_token
            .cloned()
            .or_else(|| existing.and_then(|oauth| oauth.refresh_token.clone())),
        expires_at: expires_at_ms,
        scopes,
        subscription_type: subscription_type
            .or_else(|| existing.and_then(|oauth| oauth.subscription_type.clone())),
        rate_limit_tier: rate_limit_tier
            .or_else(|| existing.and_then(|oauth| oauth.rate_limit_tier.clone())),
    }
}

/// Persist OAuth credentials to Claude Code's shared credential store.
///
/// This makes `openclaudia auth` produce the same `claudeAiOauth` file that
/// chat, proxy, and TUI paths already consume through [`load_credentials`].
///
/// # Errors
///
/// Returns an error when the config directory cannot be resolved, the target is
/// a symlink, or the credential file cannot be written.
pub fn store_credentials(
    access_token: &crate::secrets::OAuthToken,
    refresh_token: Option<&crate::secrets::OAuthToken>,
    expires_at_ms: i64,
    scopes: Vec<String>,
    subscription_type: Option<String>,
    rate_limit_tier: Option<String>,
) -> Result<(), String> {
    let _lock = CredentialLock::acquire()?;
    let path = credentials_path().ok_or("Cannot determine credentials directory")?;
    let need_existing =
        refresh_token.is_none() || subscription_type.is_none() || rate_limit_tier.is_none();
    let existing = if need_existing {
        read_existing_oauth(&path)
    } else {
        None
    };
    let oauth = merge_oauth_fields(
        access_token,
        refresh_token,
        expires_at_ms,
        scopes,
        subscription_type,
        rate_limit_tier,
        existing.as_ref(),
    );
    if oauth.refresh_token.is_none() {
        tracing::warn!(
            "OAuth login returned no refresh token and no existing refresh token was available; automatic refresh will be unavailable"
        );
    }

    write_credentials_file(
        &path,
        &CredentialsFile {
            claude_ai_oauth: Some(oauth),
        },
    )
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

/// Inspect the shared Claude credential store without refreshing tokens.
///
/// # Errors
///
/// Returns an error when an existing credential file is a symlink, unreadable,
/// or malformed.
pub fn peek_credentials() -> Result<Option<CredentialStatus>, String> {
    let Some(path) = credentials_path().filter(|path| path.exists()) else {
        return Ok(None);
    };
    reject_credentials_symlink(&path)?;

    let content =
        zeroize::Zeroizing::new(crate::file_error::read_file(&path).map_err(|e| e.to_string())?);
    let creds: CredentialsFile = serde_json::from_str(&content)
        .map_err(crate::file_error::FileError::json_with_path(&path))
        .map_err(|e| e.to_string())?;
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
        expires_soon: now_ms < oauth.expires_at && now_ms + REFRESH_BUFFER_MS >= oauth.expires_at,
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

    // --- Crosslink #825: refresh_token rotation policy ---

    /// Spec — when the OAuth response carries a `refresh_token`, the helper
    /// returns it verbatim (this is the rotating-token happy path). This
    /// path doesn't touch env vars so it can run in parallel with anything.
    #[test]
    fn resolve_new_refresh_token_uses_response_field_when_present() {
        let old = token("old-token");
        let result = resolve_new_refresh_token(Some(token("new-rotated-token")), &old)
            .expect("rotated token");
        assert!(result.matches("new-rotated-token"));
    }

    /// Spec — both env-var-sensitive branches of [`resolve_new_refresh_token`]
    /// folded into one test so they cannot race each other or other tests in
    /// this binary on the shared `OPENCLAUDIA_ALLOW_REFRESH_TOKEN_REUSE` slot.
    /// Saves and restores the ambient value on the way in and out so a parent
    /// process that legitimately set the var observes no side effect.
    #[test]
    fn resolve_new_refresh_token_optin_policy() {
        const VAR: &str = "OPENCLAUDIA_ALLOW_REFRESH_TOKEN_REUSE";
        let prev = std::env::var(VAR).ok();
        // SAFETY (both `unsafe` calls below): this single test owns the env
        // var for its duration — the only other site that reads it is the
        // production code under test, called synchronously from here. No
        // background thread in this binary writes to this var.
        unsafe {
            std::env::remove_var(VAR);
        }
        let old = token("old-token");
        let err_result = resolve_new_refresh_token(None, &old);
        // SAFETY: see comment above.
        unsafe {
            std::env::set_var(VAR, "1");
        }
        let reuse_result = resolve_new_refresh_token(None, &old);
        // Restore before any assertion that might unwind.
        // SAFETY: see comment above.
        unsafe {
            match prev {
                Some(v) => std::env::set_var(VAR, v),
                None => std::env::remove_var(VAR),
            }
        }

        let err = err_result.expect_err("must refuse silent reuse without explicit opt-in");
        assert!(
            err.contains(VAR),
            "error must name the opt-in env var; got: {err}"
        );
        assert!(reuse_result
            .expect("with opt-in set, helper must return the previous token")
            .matches("old-token"));
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

    #[test]
    fn write_credentials_file_round_trips_with_claude_code_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".credentials.json");
        let creds = CredentialsFile {
            claude_ai_oauth: Some(ClaudeAiOauth {
                access_token: token("sk-ant-oat01-test"),
                refresh_token: Some(token("sk-ant-ort01-refresh")),
                expires_at: 1_999_999_999_999,
                scopes: vec!["user:inference".to_string(), "user:profile".to_string()],
                subscription_type: Some("pro".to_string()),
                rate_limit_tier: Some("default_claude_ai".to_string()),
            }),
        };

        write_credentials_file(&path, &creds).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"claudeAiOauth\""));
        assert!(content.contains("\"accessToken\""));
        assert!(content.contains("\"refreshToken\""));
        assert!(content.contains("\"expiresAt\""));

        let parsed: CredentialsFile = serde_json::from_str(&content).unwrap();
        let oauth = parsed.claude_ai_oauth.unwrap();
        assert!(oauth.access_token.matches("sk-ant-oat01-test"));
        assert!(oauth
            .refresh_token
            .as_ref()
            .is_some_and(|token| token.matches("sk-ant-ort01-refresh")));
        assert_eq!(oauth.subscription_type.as_deref(), Some("pro"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "credentials must be written 0600");
        }
    }

    #[cfg(unix)]
    #[test]
    fn write_credentials_file_rejects_symlink_target() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.json");
        let link = dir.path().join(".credentials.json");
        std::fs::write(&target, "{}").unwrap();
        symlink(&target, &link).unwrap();

        let creds = CredentialsFile {
            claude_ai_oauth: None,
        };
        let err = write_credentials_file(&link, &creds).unwrap_err();
        assert!(err.contains("symlink"), "error must mention symlink: {err}");
    }

    #[test]
    fn merge_oauth_fields_preserves_existing_metadata_when_missing() {
        let existing = ClaudeAiOauth {
            access_token: token("old-access"),
            refresh_token: Some(token("old-refresh")),
            expires_at: 1,
            scopes: vec!["old".into()],
            subscription_type: Some("max".into()),
            rate_limit_tier: Some("tier-x".into()),
        };

        let new_access = token("new-access");
        let merged = merge_oauth_fields(
            &new_access,
            None,
            42,
            vec!["user:inference".into()],
            None,
            None,
            Some(&existing),
        );

        assert!(merged.access_token.matches("new-access"));
        assert_eq!(merged.expires_at, 42);
        assert!(merged
            .refresh_token
            .as_ref()
            .is_some_and(|token| token.matches("old-refresh")));
        assert_eq!(merged.subscription_type.as_deref(), Some("max"));
        assert_eq!(merged.rate_limit_tier.as_deref(), Some("tier-x"));
        assert_eq!(merged.scopes, vec!["user:inference"]);
    }

    #[test]
    fn merge_oauth_fields_prefers_fresh_values() {
        let existing = ClaudeAiOauth {
            access_token: token("old-access"),
            refresh_token: Some(token("old-refresh")),
            expires_at: 1,
            scopes: vec![],
            subscription_type: Some("pro".into()),
            rate_limit_tier: Some("tier-old".into()),
        };

        let new_access = token("new-access");
        let new_refresh = token("new-refresh");
        let merged = merge_oauth_fields(
            &new_access,
            Some(&new_refresh),
            99,
            vec!["user:inference".into()],
            Some("max".into()),
            Some("tier-new".into()),
            Some(&existing),
        );

        assert!(merged
            .refresh_token
            .as_ref()
            .is_some_and(|token| token.matches("new-refresh")));
        assert_eq!(merged.subscription_type.as_deref(), Some("max"));
        assert_eq!(merged.rate_limit_tier.as_deref(), Some("tier-new"));
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
