//! Owned lifecycle and hard bounds for Chromium-backed web operations.

use std::collections::BTreeSet;
#[cfg(feature = "browser")]
use std::fmt::Write as _;
#[cfg(feature = "browser")]
use std::fs::File;
#[cfg(feature = "browser")]
use std::io::{BufRead as _, BufReader, Read as _};
#[cfg(any(feature = "browser", test))]
use std::path::Path;
use std::path::PathBuf;
#[cfg(feature = "browser")]
use std::process::{Child, Command, Stdio};
#[cfg(feature = "browser")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
#[cfg(feature = "browser")]
use std::sync::LazyLock;
#[cfg(feature = "browser")]
use std::time::{Duration, Instant};

#[cfg(feature = "browser")]
use aes_gcm::aead::{Aead as _, Payload};
#[cfg(feature = "browser")]
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
#[cfg(feature = "browser")]
use rand::rngs::SysRng;
#[cfg(feature = "browser")]
use rand::TryRng as _;
use serde::{Deserialize, Serialize};
#[cfg(feature = "browser")]
use sha2::{Digest as _, Sha256};
use url::Url;
#[cfg(feature = "browser")]
use zeroize::Zeroizing;

#[cfg(feature = "browser")]
use crate::runtime::{CancellationHandle, CancellationReason};
#[cfg(feature = "browser")]
use crate::tools::ToolRunContext;

pub const BROWSER_SUPERVISION_RECEIPT_SCHEMA_VERSION: u16 = 1;
#[cfg(feature = "browser")]
const BROWSER_COOKIE_STATE_SCHEMA_VERSION: u16 = 1;
#[cfg(feature = "browser")]
const BROWSER_START_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(feature = "browser")]
const RESOURCE_SAMPLE_INTERVAL: Duration = Duration::from_millis(100);
#[cfg(feature = "browser")]
const MAX_PERSISTED_COOKIES: usize = 256;
#[cfg(feature = "browser")]
const MAX_COOKIE_STATE_PLAINTEXT_BYTES: usize = 512 * 1024;

#[cfg(feature = "browser")]
static BROWSER_ADMISSION: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(2)));

/// Immutable trusted-host capability for exact-origin encrypted cookie state.
#[derive(Clone, PartialEq, Eq)]
pub struct BrowserPersistenceGrant {
    profile_id: String,
    exact_origins: Arc<BTreeSet<String>>,
    encryption_key: crate::secrets::SecretString,
    retention_seconds: u64,
    storage_root: PathBuf,
}

impl std::fmt::Debug for BrowserPersistenceGrant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrowserPersistenceGrant")
            .field("profile_id", &self.profile_id)
            .field("exact_origin_count", &self.exact_origins.len())
            .field("retention_seconds", &self.retention_seconds)
            .field("storage_root", &self.storage_root)
            .field("encryption_key", &"[REDACTED]")
            .finish()
    }
}

impl BrowserPersistenceGrant {
    pub(crate) fn new<I, S>(
        profile_id: String,
        origins: I,
        encryption_key: crate::secrets::SecretString,
        retention_seconds: u64,
    ) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if profile_id.is_empty()
            || profile_id.len() > 64
            || !profile_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(
                "browser persistence profile_id must be 1-64 ASCII letters, digits, '-' or '_'"
                    .to_string(),
            );
        }
        if retention_seconds == 0 || retention_seconds > 365 * 24 * 60 * 60 {
            return Err(
                "browser persistence retention_seconds must be between 1 second and 1 year"
                    .to_string(),
            );
        }
        let mut exact_origins = BTreeSet::new();
        for value in origins {
            exact_origins.insert(normalize_exact_http_origin(value.as_ref())?);
            if exact_origins.len() > 32 {
                return Err("browser persistence permits at most 32 exact origins".to_string());
            }
        }
        if exact_origins.is_empty() {
            return Err("browser persistence requires at least one exact origin".to_string());
        }
        validate_encryption_key(&encryption_key)?;
        let storage_root = dirs::data_local_dir()
            .or_else(dirs::data_dir)
            .ok_or_else(|| {
                "browser persistence cannot resolve a host local-data directory".to_string()
            })?
            .join("openclaudia")
            .join("browser-login")
            .join(&profile_id);
        Ok(Self {
            profile_id,
            exact_origins: Arc::new(exact_origins),
            encryption_key,
            retention_seconds,
            storage_root,
        })
    }

    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    #[must_use]
    pub fn authority_digest(&self) -> crate::runtime::ContentDigest {
        let key_digest = self
            .encryption_key
            .expose(|key| crate::runtime::ContentDigest::sha256(key));
        let mut manifest = format!(
            "browser-persistence-v1\nprofile={}\nretention={}\nstorage={}\nkey={}\n",
            self.profile_id,
            self.retention_seconds,
            self.storage_root.display(),
            key_digest
        );
        for origin in self.exact_origins.iter() {
            manifest.push_str("origin=");
            manifest.push_str(origin);
            manifest.push('\n');
        }
        crate::runtime::ContentDigest::sha256(manifest)
    }

    #[cfg(feature = "browser")]
    fn origin_for_navigation(&self, raw_url: &str) -> Option<String> {
        let origin = normalize_navigation_origin(raw_url).ok()?;
        self.exact_origins.contains(&origin).then_some(origin)
    }
}

fn normalize_exact_http_origin(value: &str) -> Result<String, String> {
    let url = Url::parse(value).map_err(|_| "invalid browser persistence exact origin")?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "browser persistence origins must be exact HTTP(S) origins without credentials, path, query, or fragment"
                .to_string(),
        );
    }
    normalize_navigation_origin(value)
}

fn normalize_navigation_origin(value: &str) -> Result<String, String> {
    let url = Url::parse(value).map_err(|_| "invalid browser navigation URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("browser navigation is not an HTTP(S) origin".to_string());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "browser navigation has no host".to_string())?
        .to_ascii_lowercase();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "browser navigation has no known port".to_string())?;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    let default_port = matches!((url.scheme(), port), ("http", 80) | ("https", 443));
    if default_port {
        Ok(format!("{}://{host}", url.scheme()))
    } else {
        Ok(format!("{}://{host}:{port}", url.scheme()))
    }
}

#[cfg(feature = "browser")]
fn cookie_matches_origin(
    cookie: &headless_chrome::protocol::cdp::Network::Cookie,
    origin: &str,
) -> bool {
    let Ok(url) = Url::parse(origin) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let domain = cookie.domain.trim_start_matches('.');
    let domain_matches = host.eq_ignore_ascii_case(domain)
        || host
            .to_ascii_lowercase()
            .strip_suffix(&format!(".{}", domain.to_ascii_lowercase()))
            .is_some();
    domain_matches && (!cookie.secure || url.scheme() == "https")
}

fn validate_encryption_key(key: &crate::secrets::SecretString) -> Result<(), String> {
    key.expose(|encoded| {
        let decoded = BASE64_STANDARD
            .decode(encoded)
            .map_err(|_| "browser persistence encryption_key must be valid base64")?;
        if decoded.len() != 32 {
            return Err(
                "browser persistence encryption_key must decode to exactly 32 bytes".to_string(),
            );
        }
        Ok(())
    })
}

#[cfg(feature = "browser")]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptedCookieEnvelope {
    schema_version: u16,
    saved_unix_seconds: u64,
    nonce_base64: String,
    ciphertext_base64: String,
}

#[cfg(feature = "browser")]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserCookieState {
    schema_version: u16,
    origin: String,
    cookies: Vec<headless_chrome::protocol::cdp::Network::CookieParam>,
}

#[cfg(feature = "browser")]
impl BrowserPersistenceGrant {
    pub(crate) fn restore_cookies(
        &self,
        tab: &Arc<headless_chrome::Tab>,
        navigation_url: &str,
        counters: &BrowserCounters,
    ) -> Result<(), String> {
        let Some(origin) = self.origin_for_navigation(navigation_url) else {
            return Ok(());
        };
        counters.mark_persistent_state();
        let storage = self.open_storage()?;
        let target = cookie_state_target(&origin);
        let observed = storage
            .read(&target, crate::persistence::FileClass::Credentials)
            .map_err(|_| "Failed to read encrypted browser cookie state".to_string())?;
        let state = observed
            .expose_bytes(|encoded| {
                encoded
                    .map(|encoded| self.decrypt_cookie_state(&origin, encoded))
                    .transpose()
            })?
            .flatten();
        if let Some(state) = state {
            tab.set_cookies(state.cookies)
                .map_err(|_| "Failed to restore encrypted browser cookies".to_string())?;
        }
        Ok(())
    }

    pub(crate) fn save_cookies(
        &self,
        tab: &Arc<headless_chrome::Tab>,
        counters: &BrowserCounters,
    ) -> Result<(), String> {
        let Some(origin) = self.origin_for_navigation(&tab.get_url()) else {
            return Ok(());
        };
        counters.mark_persistent_state();
        let observed_cookies = tab
            .get_cookies()
            .map_err(|_| "Failed to capture browser cookies for encrypted storage".to_string())?;
        let observed_cookies = observed_cookies
            .into_iter()
            .filter(|cookie| cookie_matches_origin(cookie, &origin))
            .collect::<Vec<_>>();
        if observed_cookies.len() > MAX_PERSISTED_COOKIES {
            return Err(format!(
                "Browser cookie state exceeded the {MAX_PERSISTED_COOKIES}-cookie limit"
            ));
        }
        let cookies = observed_cookies
            .into_iter()
            .map(|cookie| cookie_param_for_exact_origin(cookie, &origin))
            .collect();
        let state = BrowserCookieState {
            schema_version: BROWSER_COOKIE_STATE_SCHEMA_VERSION,
            origin: origin.clone(),
            cookies,
        };
        let encoded = self.encrypt_cookie_state(&origin, &state)?;
        let storage = self.open_storage()?;
        let target = cookie_state_target(&origin);
        let observed = storage
            .read(&target, crate::persistence::FileClass::Credentials)
            .map_err(|_| "Failed to inspect encrypted browser cookie state".to_string())?;
        storage
            .commit(
                &target,
                crate::persistence::FileClass::Credentials,
                observed.generation(),
                encoded.as_slice(),
            )
            .map_err(|_| "Failed to commit encrypted browser cookie state".to_string())?;
        Ok(())
    }

    fn open_storage(&self) -> Result<crate::persistence::PersistentStorage, String> {
        std::fs::create_dir_all(&self.storage_root)
            .map_err(|_| "Failed to create browser cookie storage".to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&self.storage_root, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "Failed to make browser cookie storage owner-private".to_string())?;
        }
        crate::persistence::PersistentStorage::open(&self.storage_root)
            .map_err(|_| "Failed to pin browser cookie storage".to_string())
    }

    fn encrypt_cookie_state(
        &self,
        origin: &str,
        state: &BrowserCookieState,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(state)
                .map_err(|_| "Failed to encode browser cookie state".to_string())?,
        );
        if plaintext.len() > MAX_COOKIE_STATE_PLAINTEXT_BYTES {
            return Err(format!(
                "Browser cookie state exceeded the {MAX_COOKIE_STATE_PLAINTEXT_BYTES}-byte limit"
            ));
        }
        let key = self.decoded_key()?;
        let cipher = Aes256Gcm::new_from_slice(key.as_slice())
            .map_err(|_| "Browser cookie encryption key is invalid".to_string())?;
        let mut nonce = [0_u8; 12];
        SysRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| "Operating-system randomness is unavailable".to_string())?;
        let saved_unix_seconds = current_unix_seconds()?;
        let aad = self.cookie_aad(origin, saved_unix_seconds);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| "Failed to encrypt browser cookie state".to_string())?;
        let envelope = EncryptedCookieEnvelope {
            schema_version: BROWSER_COOKIE_STATE_SCHEMA_VERSION,
            saved_unix_seconds,
            nonce_base64: BASE64_STANDARD.encode(nonce),
            ciphertext_base64: BASE64_STANDARD.encode(ciphertext),
        };
        serde_json::to_vec(&envelope)
            .map(Zeroizing::new)
            .map_err(|_| "Failed to encode encrypted browser cookie envelope".to_string())
    }

    fn decrypt_cookie_state(
        &self,
        origin: &str,
        encoded: &[u8],
    ) -> Result<Option<BrowserCookieState>, String> {
        let storage_limit = usize::try_from(crate::persistence::FileClass::Credentials.max_bytes())
            .unwrap_or(usize::MAX);
        if encoded.len() > storage_limit {
            return Err("Encrypted browser cookie state exceeded its storage limit".to_string());
        }
        let envelope: EncryptedCookieEnvelope = serde_json::from_slice(encoded)
            .map_err(|_| "Encrypted browser cookie state is corrupt".to_string())?;
        if envelope.schema_version != BROWSER_COOKIE_STATE_SCHEMA_VERSION
            || envelope.nonce_base64.len() > 24
            || envelope.ciphertext_base64.len() > 4 * MAX_COOKIE_STATE_PLAINTEXT_BYTES / 3 + 64
        {
            return Err("Encrypted browser cookie state is corrupt".to_string());
        }
        let now = current_unix_seconds()?;
        if envelope.saved_unix_seconds > now.saturating_add(300) {
            return Err("Encrypted browser cookie state has an invalid timestamp".to_string());
        }
        if now.saturating_sub(envelope.saved_unix_seconds) > self.retention_seconds {
            return Ok(None);
        }
        let nonce = BASE64_STANDARD
            .decode(&envelope.nonce_base64)
            .map_err(|_| "Encrypted browser cookie state is corrupt".to_string())?;
        let nonce: [u8; 12] = nonce
            .try_into()
            .map_err(|_| "Encrypted browser cookie state is corrupt".to_string())?;
        let ciphertext = BASE64_STANDARD
            .decode(&envelope.ciphertext_base64)
            .map_err(|_| "Encrypted browser cookie state is corrupt".to_string())?;
        if ciphertext.len() > MAX_COOKIE_STATE_PLAINTEXT_BYTES + 32 {
            return Err("Encrypted browser cookie state is corrupt".to_string());
        }
        let key = self.decoded_key()?;
        let cipher = Aes256Gcm::new_from_slice(key.as_slice())
            .map_err(|_| "Browser cookie encryption key is invalid".to_string())?;
        let aad = self.cookie_aad(origin, envelope.saved_unix_seconds);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| "Encrypted browser cookie state failed authentication".to_string())?;
        if plaintext.len() > MAX_COOKIE_STATE_PLAINTEXT_BYTES {
            return Err("Encrypted browser cookie state is corrupt".to_string());
        }
        let state: BrowserCookieState = serde_json::from_slice(&plaintext)
            .map_err(|_| "Encrypted browser cookie state is corrupt".to_string())?;
        if state.schema_version != BROWSER_COOKIE_STATE_SCHEMA_VERSION
            || state.origin != origin
            || state.cookies.len() > MAX_PERSISTED_COOKIES
        {
            return Err("Encrypted browser cookie state is corrupt".to_string());
        }
        Ok(Some(state))
    }

    fn decoded_key(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        self.encryption_key.expose(|encoded| {
            BASE64_STANDARD
                .decode(encoded)
                .map(Zeroizing::new)
                .map_err(|_| "Browser cookie encryption key is invalid".to_string())
        })
    }

    fn cookie_aad(&self, origin: &str, saved_unix_seconds: u64) -> String {
        format!(
            "openclaudia-browser-cookie-v1\nprofile={}\norigin={origin}\nsaved={saved_unix_seconds}\n",
            self.profile_id,
        )
    }
}

#[cfg(feature = "browser")]
fn cookie_param_for_exact_origin(
    cookie: headless_chrome::protocol::cdp::Network::Cookie,
    origin: &str,
) -> headless_chrome::protocol::cdp::Network::CookieParam {
    headless_chrome::protocol::cdp::Network::CookieParam {
        name: cookie.name,
        value: cookie.value,
        url: Some(origin.to_string()),
        domain: None,
        path: Some(cookie.path),
        secure: Some(cookie.secure),
        http_only: Some(cookie.http_only),
        same_site: cookie.same_site,
        expires: (!cookie.session).then_some(cookie.expires),
        priority: Some(cookie.priority),
        same_party: Some(cookie.same_party),
        source_scheme: Some(cookie.source_scheme),
        source_port: Some(cookie.source_port),
        partition_key: None,
    }
}

#[cfg(feature = "browser")]
fn cookie_state_target(origin: &str) -> PathBuf {
    let digest = Sha256::digest(origin.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2 + 13);
    for byte in digest {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded.push_str(".cookies.json");
    PathBuf::from(encoded)
}

#[cfg(feature = "browser")]
fn current_unix_seconds() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "System clock is before the Unix epoch".to_string())
}

/// Hard ceilings applied to one Chromium operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserLimits {
    pub concurrent_sessions: u64,
    pub tabs: u64,
    pub requests: u64,
    pub dom_bytes: u64,
    pub dom_nodes: u64,
    pub downloads: u64,
    pub processes: u64,
    pub resident_memory_bytes: u64,
    pub cpu_millis: u64,
    pub profile_disk_bytes: u64,
    pub elapsed_millis: u64,
}

impl Default for BrowserLimits {
    fn default() -> Self {
        Self {
            concurrent_sessions: 2,
            tabs: 4,
            requests: 128,
            dom_bytes: 10 * 1024 * 1024,
            dom_nodes: 100_000,
            downloads: 0,
            processes: 16,
            // Linux RSS sums shared Chrome mappings once per process, so a
            // 1 GiB ceiling kills a normal two-renderer startup despite much
            // lower physical use. Two admitted sessions remain capped at a
            // conservative 4 GiB aggregate.
            resident_memory_bytes: 2 * 1024 * 1024 * 1024,
            cpu_millis: 30_000,
            profile_disk_bytes: 128 * 1024 * 1024,
            elapsed_millis: 45_000,
        }
    }
}

/// Largest resource observations retained without exposing page data.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserResourceUsage {
    pub tabs: u64,
    pub requests: u64,
    pub dom_bytes: u64,
    pub dom_nodes: u64,
    pub downloads: u64,
    pub processes: u64,
    pub resident_memory_bytes: u64,
    pub cpu_millis: u64,
    pub profile_disk_bytes: u64,
    pub elapsed_millis: u64,
}

#[cfg(any(feature = "browser", test))]
impl BrowserResourceUsage {
    #[cfg(feature = "browser")]
    fn merge_max(&mut self, other: Self) {
        self.tabs = self.tabs.max(other.tabs);
        self.requests = self.requests.max(other.requests);
        self.dom_bytes = self.dom_bytes.max(other.dom_bytes);
        self.dom_nodes = self.dom_nodes.max(other.dom_nodes);
        self.downloads = self.downloads.max(other.downloads);
        self.processes = self.processes.max(other.processes);
        self.resident_memory_bytes = self.resident_memory_bytes.max(other.resident_memory_bytes);
        self.cpu_millis = self.cpu_millis.max(other.cpu_millis);
        self.profile_disk_bytes = self.profile_disk_bytes.max(other.profile_disk_bytes);
        self.elapsed_millis = self.elapsed_millis.max(other.elapsed_millis);
    }

    fn exceeded(self, limits: BrowserLimits) -> Option<&'static str> {
        [
            (self.tabs > limits.tabs, "tabs"),
            (self.requests > limits.requests, "requests"),
            (self.dom_bytes > limits.dom_bytes, "dom_bytes"),
            (self.dom_nodes > limits.dom_nodes, "dom_nodes"),
            (self.downloads > limits.downloads, "downloads"),
            (self.processes > limits.processes, "processes"),
            (
                self.resident_memory_bytes > limits.resident_memory_bytes,
                "resident_memory_bytes",
            ),
            (self.cpu_millis > limits.cpu_millis, "cpu_millis"),
            (
                self.profile_disk_bytes > limits.profile_disk_bytes,
                "profile_disk_bytes",
            ),
            (
                self.elapsed_millis > limits.elapsed_millis,
                "elapsed_millis",
            ),
        ]
        .into_iter()
        .find_map(|(exceeded, dimension)| exceeded.then_some(dimension))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrowserTerminalState {
    Completed,
    Failed,
    Cancelled,
    Deadline,
    ResourceLimit { dimension: String },
}

/// Artifact- and limit-bound proof that browser descendants reached terminal state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserSupervisionReceipt {
    pub schema_version: u16,
    pub browser_sha256: String,
    pub ephemeral_profile: bool,
    pub persistent_state: bool,
    pub limits: BrowserLimits,
    pub usage: BrowserResourceUsage,
    pub terminal: BrowserTerminalState,
    pub descendants_reaped: bool,
}

/// Work result plus page-level counters unavailable from the OS process tree.
#[cfg(feature = "browser")]
pub(crate) struct BrowserWorkOutput<T> {
    pub value: T,
}

/// Shared page-level counters sampled by the supervisor while Chromium works.
#[cfg(feature = "browser")]
pub(crate) struct BrowserCounters {
    tabs: AtomicU64,
    requests: AtomicU64,
    dom_bytes: AtomicU64,
    dom_nodes: AtomicU64,
    persistent_state: AtomicBool,
}

#[cfg(feature = "browser")]
impl BrowserCounters {
    const fn new() -> Self {
        Self {
            tabs: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            dom_bytes: AtomicU64::new(0),
            dom_nodes: AtomicU64::new(0),
            persistent_state: AtomicBool::new(false),
        }
    }

    /// Reserve one intercepted request without allowing the hard limit to be
    /// exceeded. Rejected attempts remain visible in the terminal receipt.
    pub(crate) fn admit_request(&self, limit: u64) -> bool {
        let previous = self.requests.fetch_add(1, Ordering::Relaxed);
        previous < limit
    }

    pub(crate) fn record_dom(&self, bytes: u64, nodes: u64) {
        self.dom_bytes.store(bytes, Ordering::Relaxed);
        self.dom_nodes.store(nodes, Ordering::Relaxed);
    }

    fn record_tabs(&self, tabs: usize) {
        self.tabs
            .store(u64::try_from(tabs).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    pub(crate) fn mark_persistent_state(&self) {
        self.persistent_state.store(true, Ordering::Relaxed);
    }

    fn persistent_state(&self) -> bool {
        self.persistent_state.load(Ordering::Relaxed)
    }

    fn usage(&self) -> BrowserResourceUsage {
        BrowserResourceUsage {
            tabs: self.tabs.load(Ordering::Relaxed),
            requests: self.requests.load(Ordering::Relaxed),
            dom_bytes: self.dom_bytes.load(Ordering::Relaxed),
            dom_nodes: self.dom_nodes.load(Ordering::Relaxed),
            ..BrowserResourceUsage::default()
        }
    }
}

#[cfg(feature = "browser")]
pub(crate) struct SupervisedBrowserOutput<T> {
    pub value: T,
    pub receipt: BrowserSupervisionReceipt,
}

#[cfg(feature = "browser")]
pub(crate) struct BrowserSupervisionFailure {
    pub message: String,
    pub receipt: Box<BrowserSupervisionReceipt>,
}

#[cfg(feature = "browser")]
struct BrowserArtifact {
    path: PathBuf,
    sha256: String,
}

#[cfg(feature = "browser")]
enum WorkerEvent<T> {
    Started { pid: u32 },
    Verified { artifact: BrowserArtifact },
    Finished(Result<BrowserWorkOutput<T>, String>),
}

#[cfg(feature = "browser")]
struct ManagedBrowser {
    browser: Option<headless_chrome::Browser>,
    child: Child,
    pid: u32,
}

#[cfg(feature = "browser")]
impl Drop for ManagedBrowser {
    fn drop(&mut self) {
        self.browser.take();
        crate::tools::terminate_sandbox_process_tree(self.pid);
        let _ = self.child.wait();
    }
}

/// Run one Chromium job under bounded admission and reconcile every descendant.
#[cfg(feature = "browser")]
#[allow(clippy::too_many_lines)] // One select loop owns the complete browser lifecycle state machine.
pub(crate) async fn supervise_browser<T, F>(
    run: Arc<ToolRunContext>,
    cancellation: CancellationHandle,
    proxy_url: String,
    work: F,
) -> Result<SupervisedBrowserOutput<T>, BrowserSupervisionFailure>
where
    T: Send + 'static,
    F: FnOnce(
            &headless_chrome::Browser,
            BrowserLimits,
            Arc<BrowserCounters>,
        ) -> Result<BrowserWorkOutput<T>, String>
        + Send
        + 'static,
{
    let limits = BrowserLimits::default();
    let permit = tokio::select! {
        permit = Arc::clone(&BROWSER_ADMISSION).acquire_owned() => permit.map_err(|_| {
            failure_without_artifact("Browser admission pool is unavailable", limits)
        })?,
        receipt = cancellation.cancelled() => {
            return Err(failure_without_artifact_terminal(
                cancellation_message(&receipt.reason),
                limits,
                terminal_for_cancellation(&receipt.reason),
            ));
        }
    };
    let mut artifact =
        resolve_browser_artifact(Arc::clone(&run), cancellation.clone(), limits).await?;
    let profile = tempfile::Builder::new()
        .prefix("ocb-")
        .tempdir_in(browser_profile_parent())
        .map_err(|error| {
            failure(
                &artifact,
                limits,
                format!("Failed to create ephemeral browser profile: {error}"),
            )
        })?;
    let profile_path = profile.path().to_path_buf();
    let monitored_profile_path = profile_path.clone();
    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
    let worker_artifact = BrowserArtifact {
        path: artifact.path.clone(),
        sha256: artifact.sha256.clone(),
    };
    let counters = Arc::new(BrowserCounters::new());
    let worker_counters = Arc::clone(&counters);
    let mut worker = Some(
        std::thread::Builder::new()
            .name("openclaudia-browser".to_string())
            .spawn(move || {
                let outcome = launch_managed_browser(
                    &worker_artifact.path,
                    &profile_path,
                    &proxy_url,
                    &events_tx,
                )
                .and_then(|managed| {
                    let runtime_artifact =
                        resolve_running_browser_artifact(managed.pid, &worker_artifact)?;
                    let _ = events_tx.send(WorkerEvent::Verified {
                        artifact: runtime_artifact,
                    });
                    let outcome = work(
                        managed.browser.as_ref().expect("browser is installed"),
                        limits,
                        Arc::clone(&worker_counters),
                    );
                    let tabs = managed
                        .browser
                        .as_ref()
                        .expect("browser is installed")
                        .get_tabs()
                        .lock()
                        .map_or(usize::MAX, |tabs| tabs.len());
                    worker_counters.record_tabs(tabs);
                    outcome
                });
                let _ = events_tx.send(WorkerEvent::Finished(outcome));
                drop(profile);
            })
            .map_err(|error| {
                failure(
                    &artifact,
                    limits,
                    format!("Failed to start browser owner thread: {error}"),
                )
            })?,
    );

    let started_at = Instant::now();
    let mut interval = tokio::time::interval(RESOURCE_SAMPLE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pid = None;
    let mut usage = BrowserResourceUsage::default();
    let mut forced_terminal = None;

    loop {
        tokio::select! {
            event = events_rx.recv() => match event {
                Some(WorkerEvent::Started { pid: started_pid }) => {
                    pid = Some(started_pid);
                    if forced_terminal.is_some() {
                        terminate_pid(pid).await;
                    }
                }
                Some(WorkerEvent::Verified { artifact: runtime_artifact }) => {
                    artifact = runtime_artifact;
                }
                Some(WorkerEvent::Finished(outcome)) => {
                    join_worker(worker.take());
                    drop(permit);
                    usage.elapsed_millis = millis(started_at.elapsed());
                    usage.merge_max(counters.usage());
                    let forced_terminal = forced_terminal.or_else(|| {
                        cancellation
                            .receipt()
                            .map(|receipt| terminal_for_cancellation(&receipt.reason))
                    });
                    return finish_worker(
                        outcome,
                        forced_terminal,
                        &artifact,
                        limits,
                        usage,
                        counters.persistent_state(),
                    );
                }
                None => {
                    join_worker(worker.take());
                    drop(permit);
                    usage.elapsed_millis = millis(started_at.elapsed());
                    return Err(BrowserSupervisionFailure {
                        message: "Browser owner thread ended without a terminal result".to_string(),
                        receipt: Box::new(receipt(
                            &artifact,
                            limits,
                            usage,
                            BrowserTerminalState::Failed,
                            true,
                            counters.persistent_state(),
                        )),
                    });
                }
            },
            receipt = cancellation.cancelled(), if forced_terminal.is_none() => {
                forced_terminal = Some(terminal_for_cancellation(&receipt.reason));
                terminate_pid(pid).await;
            }
            _ = interval.tick(), if forced_terminal.is_none() => {
                let mut sample = pid.map_or_else(BrowserResourceUsage::default, process_tree_usage);
                sample.merge_max(counters.usage());
                sample.profile_disk_bytes = directory_bytes(&monitored_profile_path, 20_000)
                    .unwrap_or(u64::MAX);
                sample.elapsed_millis = millis(started_at.elapsed());
                usage.merge_max(sample);
                if let Some(dimension) = usage.exceeded(limits) {
                    let _receipt = cancellation.cancel(CancellationReason::BudgetExhausted);
                    forced_terminal = Some(BrowserTerminalState::ResourceLimit {
                        dimension: dimension.to_string(),
                    });
                    terminate_pid(pid).await;
                }
            }
        }
    }
}

#[cfg(all(feature = "browser", unix))]
fn browser_profile_parent() -> &'static Path {
    // Chromium adds a long randomized singleton-socket suffix below HOME and
    // aborts when the resulting Unix-domain path exceeds the platform limit.
    // `tempfile` still creates each operation directory mode 0700 and owns its
    // cleanup; the short fixed parent keeps the browser functional.
    Path::new("/tmp")
}

#[cfg(all(feature = "browser", not(unix)))]
fn browser_profile_parent() -> PathBuf {
    std::env::temp_dir()
}

#[cfg(feature = "browser")]
fn finish_worker<T>(
    outcome: Result<BrowserWorkOutput<T>, String>,
    forced_terminal: Option<BrowserTerminalState>,
    artifact: &BrowserArtifact,
    limits: BrowserLimits,
    usage: BrowserResourceUsage,
    persistent_state: bool,
) -> Result<SupervisedBrowserOutput<T>, BrowserSupervisionFailure> {
    match (forced_terminal, outcome) {
        (Some(terminal), _outcome) => {
            let message = terminal_message(&terminal);
            Err(BrowserSupervisionFailure {
                message,
                receipt: Box::new(receipt(
                    artifact,
                    limits,
                    usage,
                    terminal,
                    true,
                    persistent_state,
                )),
            })
        }
        (None, Ok(output)) => {
            if let Some(dimension) = usage.exceeded(limits) {
                let terminal = BrowserTerminalState::ResourceLimit {
                    dimension: dimension.to_string(),
                };
                return Err(BrowserSupervisionFailure {
                    message: terminal_message(&terminal),
                    receipt: Box::new(receipt(
                        artifact,
                        limits,
                        usage,
                        terminal,
                        true,
                        persistent_state,
                    )),
                });
            }
            Ok(SupervisedBrowserOutput {
                value: output.value,
                receipt: receipt(
                    artifact,
                    limits,
                    usage,
                    BrowserTerminalState::Completed,
                    true,
                    persistent_state,
                ),
            })
        }
        (None, Err(message)) => Err(BrowserSupervisionFailure {
            message,
            receipt: Box::new(receipt(
                artifact,
                limits,
                usage,
                BrowserTerminalState::Failed,
                true,
                persistent_state,
            )),
        }),
    }
}

#[cfg(feature = "browser")]
async fn resolve_browser_artifact(
    run: Arc<ToolRunContext>,
    cancellation: CancellationHandle,
    limits: BrowserLimits,
) -> Result<BrowserArtifact, BrowserSupervisionFailure> {
    let mut task = tokio::task::spawn_blocking(move || resolve_browser_artifact_sync(&run));
    tokio::select! {
        result = &mut task => result
            .map_err(|error| failure_without_artifact(format!("Browser artifact inspection failed: {error}"), limits))?
            .map_err(|error| failure_without_artifact(error, limits)),
        receipt = cancellation.cancelled() => {
            let _ = task.await;
            Err(failure_without_artifact_terminal(
                cancellation_message(&receipt.reason),
                limits,
                terminal_for_cancellation(&receipt.reason),
            ))
        },
    }
}

#[cfg(feature = "browser")]
fn resolve_browser_artifact_sync(run: &ToolRunContext) -> Result<BrowserArtifact, String> {
    let path = [
        "chromium",
        "chromium-browser",
        "google-chrome-stable",
        "google-chrome",
        "chrome",
    ]
    .into_iter()
    .find_map(|name| run.resolve_executable(name).ok())
    .ok_or_else(|| {
        "No operator-installed Chromium/Chrome executable is available in the run-bound startup PATH"
            .to_string()
    })?;
    inspect_browser_artifact(&path)
}

#[cfg(feature = "browser")]
fn inspect_browser_artifact(path: &Path) -> Result<BrowserArtifact, String> {
    let path = path
        .canonicalize()
        .map_err(|error| format!("Failed to canonicalize browser executable: {error}"))?;
    let metadata = path
        .metadata()
        .map_err(|error| format!("Failed to inspect browser executable: {error}"))?;
    if !metadata.is_file() {
        return Err("Resolved browser artifact is not a regular file".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err("Resolved browser artifact is not executable".to_string());
        }
    }
    let mut file = File::open(&path)
        .map_err(|error| format!("Failed to open browser artifact for verification: {error}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("Failed to verify browser artifact: {error}"))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let digest = hasher.finalize();
    let mut sha256 = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(sha256, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(BrowserArtifact { path, sha256 })
}

#[cfg(all(feature = "browser", target_os = "linux"))]
fn resolve_running_browser_artifact(
    pid: u32,
    _launch_artifact: &BrowserArtifact,
) -> Result<BrowserArtifact, String> {
    let path = std::fs::read_link(format!("/proc/{pid}/exe"))
        .map_err(|error| format!("Failed to identify the running Chromium artifact: {error}"))?;
    inspect_browser_artifact(&path)
}

#[cfg(all(feature = "browser", not(target_os = "linux")))]
fn resolve_running_browser_artifact(
    _pid: u32,
    launch_artifact: &BrowserArtifact,
) -> Result<BrowserArtifact, String> {
    Ok(BrowserArtifact {
        path: launch_artifact.path.clone(),
        sha256: launch_artifact.sha256.clone(),
    })
}

#[cfg(feature = "browser")]
fn launch_managed_browser<T>(
    executable: &Path,
    profile: &Path,
    proxy_url: &str,
    events: &tokio::sync::mpsc::UnboundedSender<WorkerEvent<T>>,
) -> Result<ManagedBrowser, String> {
    let mut command = Command::new(executable);
    command
        .args([
            "--headless=new",
            "--remote-debugging-port=0",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-default-apps",
            "--disable-extensions",
            "--disable-gpu",
            "--disable-quic",
            "--disable-sync",
            "--disable-dev-shm-usage",
            "--disk-cache-size=0",
            "--media-cache-size=0",
            "--no-default-browser-check",
            "--no-first-run",
            "--password-store=basic",
            "--use-mock-keychain",
            "--renderer-process-limit=2",
            "--js-flags=--max-old-space-size=256",
            "--proxy-bypass-list=<-loopback>",
            "--disable-features=AsyncDns,DnsOverHttps,TranslateUI",
        ])
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg(format!("--proxy-server={proxy_url}"))
        .current_dir(profile)
        .env_clear()
        .env("HOME", profile)
        .env("TMPDIR", profile)
        .env("TMP", profile)
        .env("TEMP", profile)
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    let child = command
        .spawn()
        .map_err(|error| format!("Failed to launch verified Chromium artifact: {error}"))?;
    let pid = child.id();
    let mut managed = ManagedBrowser {
        browser: None,
        child,
        pid,
    };
    let _ = events.send(WorkerEvent::Started { pid });
    let stderr = managed
        .child
        .stderr
        .take()
        .ok_or_else(|| "Chromium launch did not expose its diagnostic pipe".to_string())?;
    let (url_tx, url_rx) = std::sync::mpsc::sync_channel(1);
    let diagnostics = Arc::new(std::sync::Mutex::new(String::new()));
    let reader_diagnostics = Arc::clone(&diagnostics);
    std::thread::Builder::new()
        .name("openclaudia-browser-bootstrap".to_string())
        .spawn(move || {
            let reader = BufReader::new(stderr);
            let mut endpoint_published = false;
            for line in reader.lines().map_while(Result::ok) {
                if let Ok(mut retained) = reader_diagnostics.lock() {
                    if retained.len() < 4 * 1024 {
                        retained.push_str(&line);
                        retained.push('\n');
                    }
                }
                if !endpoint_published {
                    if let Some(url) = line
                        .split_once("DevTools listening on ")
                        .map(|(_, url)| url.trim().to_string())
                    {
                        let _ = url_tx.try_send(url);
                        endpoint_published = true;
                    }
                }
            }
        })
        .map_err(|error| format!("Failed to start Chromium bootstrap reader: {error}"))?;
    let ws_url = wait_for_devtools_endpoint(profile, &mut managed.child, &url_rx, &diagnostics)?;
    let browser =
        headless_chrome::Browser::connect_with_timeout(ws_url, Duration::from_secs(10))
            .map_err(|error| format!("Failed to attach to verified Chromium artifact: {error}"))?;
    managed.browser = Some(browser);
    Ok(managed)
}

#[cfg(feature = "browser")]
fn wait_for_devtools_endpoint(
    profile: &Path,
    child: &mut Child,
    url_rx: &std::sync::mpsc::Receiver<String>,
    diagnostics: &std::sync::Mutex<String>,
) -> Result<String, String> {
    let deadline = Instant::now() + BROWSER_START_TIMEOUT;
    loop {
        match url_rx.try_recv() {
            Ok(url) => return Ok(url),
            Err(
                std::sync::mpsc::TryRecvError::Disconnected | std::sync::mpsc::TryRecvError::Empty,
            ) => {}
        }
        if let Ok(active_port) = std::fs::read_to_string(profile.join("DevToolsActivePort")) {
            let mut lines = active_port.lines();
            if let (Some(port), Some(path)) = (lines.next(), lines.next()) {
                if port.parse::<u16>().is_ok() && path.starts_with("/devtools/browser/") {
                    return Ok(format!("ws://127.0.0.1:{port}{path}"));
                }
            }
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|_| "Failed to inspect Chromium startup state".to_string())?
        {
            let diagnostic = startup_diagnostic(diagnostics);
            return Err(format!(
                "Chromium exited before publishing a DevTools endpoint ({status}): {diagnostic}"
            ));
        }
        if Instant::now() >= deadline {
            let diagnostic = startup_diagnostic(diagnostics);
            return Err(format!(
                "Chromium did not publish a DevTools endpoint before its startup deadline: {diagnostic}"
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(feature = "browser")]
fn startup_diagnostic(diagnostics: &std::sync::Mutex<String>) -> crate::secrets::SafeDiagnostic {
    diagnostics.lock().map_or_else(
        |_| crate::secrets::SafeDiagnostic::from_untrusted("diagnostic unavailable"),
        |diagnostic| crate::secrets::SafeDiagnostic::from_untrusted(&diagnostic),
    )
}

#[cfg(feature = "browser")]
fn join_worker(worker: Option<std::thread::JoinHandle<()>>) {
    if let Some(worker) = worker {
        let _ = worker.join();
    }
}

#[cfg(feature = "browser")]
async fn terminate_pid(pid: Option<u32>) {
    if let Some(pid) = pid {
        let _ = tokio::task::spawn_blocking(move || {
            crate::tools::terminate_sandbox_process_tree(pid);
        })
        .await;
    }
}

#[cfg(feature = "browser")]
fn receipt(
    artifact: &BrowserArtifact,
    limits: BrowserLimits,
    usage: BrowserResourceUsage,
    terminal: BrowserTerminalState,
    descendants_reaped: bool,
    persistent_state: bool,
) -> BrowserSupervisionReceipt {
    BrowserSupervisionReceipt {
        schema_version: BROWSER_SUPERVISION_RECEIPT_SCHEMA_VERSION,
        browser_sha256: artifact.sha256.clone(),
        ephemeral_profile: true,
        persistent_state,
        limits,
        usage,
        terminal,
        descendants_reaped,
    }
}

#[cfg(feature = "browser")]
fn failure(
    artifact: &BrowserArtifact,
    limits: BrowserLimits,
    message: impl Into<String>,
) -> BrowserSupervisionFailure {
    BrowserSupervisionFailure {
        message: message.into(),
        receipt: Box::new(receipt(
            artifact,
            limits,
            BrowserResourceUsage::default(),
            BrowserTerminalState::Failed,
            true,
            false,
        )),
    }
}

#[cfg(feature = "browser")]
fn failure_without_artifact(
    message: impl Into<String>,
    limits: BrowserLimits,
) -> BrowserSupervisionFailure {
    failure_without_artifact_terminal(message, limits, BrowserTerminalState::Failed)
}

#[cfg(feature = "browser")]
fn failure_without_artifact_terminal(
    message: impl Into<String>,
    limits: BrowserLimits,
    terminal: BrowserTerminalState,
) -> BrowserSupervisionFailure {
    BrowserSupervisionFailure {
        message: message.into(),
        receipt: Box::new(BrowserSupervisionReceipt {
            schema_version: BROWSER_SUPERVISION_RECEIPT_SCHEMA_VERSION,
            browser_sha256: "unavailable".to_string(),
            ephemeral_profile: true,
            persistent_state: false,
            limits,
            usage: BrowserResourceUsage::default(),
            terminal,
            descendants_reaped: true,
        }),
    }
}

#[cfg(feature = "browser")]
const fn cancellation_message(reason: &CancellationReason) -> &'static str {
    match reason {
        CancellationReason::Deadline | CancellationReason::BudgetExhausted => {
            "Browser operation was cancelled by its deadline or budget"
        }
        _ => "Browser operation was cancelled by its owning run",
    }
}

#[cfg(feature = "browser")]
const fn terminal_for_cancellation(reason: &CancellationReason) -> BrowserTerminalState {
    match reason {
        CancellationReason::Deadline | CancellationReason::BudgetExhausted => {
            BrowserTerminalState::Deadline
        }
        _ => BrowserTerminalState::Cancelled,
    }
}

#[cfg(feature = "browser")]
fn terminal_message(terminal: &BrowserTerminalState) -> String {
    match terminal {
        BrowserTerminalState::Completed => "Browser operation completed".to_string(),
        BrowserTerminalState::Failed => "Browser operation failed".to_string(),
        BrowserTerminalState::Cancelled => {
            "Browser operation was cancelled and its descendants were reaped".to_string()
        }
        BrowserTerminalState::Deadline => {
            "Browser operation exceeded its deadline and its descendants were reaped".to_string()
        }
        BrowserTerminalState::ResourceLimit { dimension } => format!(
            "Browser operation exceeded its {dimension} limit and its descendants were reaped"
        ),
    }
}

#[cfg(feature = "browser")]
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(all(feature = "browser", target_os = "linux"))]
fn process_tree_usage(root_pid: u32) -> BrowserResourceUsage {
    // SAFETY: sysconf reads immutable kernel limits for the named constants;
    // it does not dereference pointers or mutate Rust-owned state.
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    // SAFETY: same contract as the sysconf call above.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return BrowserResourceUsage::default();
    };
    let mut usage = BrowserResourceUsage::default();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let Some(end) = stat.rfind(')') else {
            continue;
        };
        let fields = stat[end + 1..].split_whitespace().collect::<Vec<_>>();
        if fields.len() <= 21 || fields[2].parse::<u32>().ok() != Some(root_pid) {
            continue;
        }
        usage.processes = usage.processes.saturating_add(1);
        let ticks = fields[11]
            .parse::<u64>()
            .unwrap_or(0)
            .saturating_add(fields[12].parse::<u64>().unwrap_or(0));
        if ticks_per_second > 0 {
            usage.cpu_millis = usage.cpu_millis.saturating_add(
                ticks.saturating_mul(1000) / u64::try_from(ticks_per_second).unwrap_or(100),
            );
        }
        let resident_pages = fields[21].parse::<u64>().unwrap_or(0);
        if page_size > 0 {
            usage.resident_memory_bytes = usage.resident_memory_bytes.saturating_add(
                resident_pages.saturating_mul(u64::try_from(page_size).unwrap_or(4096)),
            );
        }
    }
    usage
}

#[cfg(all(feature = "browser", not(target_os = "linux")))]
fn process_tree_usage(_root_pid: u32) -> BrowserResourceUsage {
    BrowserResourceUsage::default()
}

#[cfg(any(feature = "browser", test))]
fn directory_bytes(root: &Path, max_entries: usize) -> Result<u64, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0_usize;
    let mut bytes = 0_u64;
    while let Some(path) = pending.pop() {
        let entries = match std::fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "Failed to inspect browser profile storage: {error}"
                ));
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(format!("Failed to inspect browser profile entry: {error}"));
                }
            };
            visited = visited.saturating_add(1);
            if visited > max_entries {
                return Err("Browser profile exceeded its entry-count limit".to_string());
            }
            let metadata = match entry.file_type() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(format!("Failed to classify browser profile entry: {error}"));
                }
            };
            if metadata.is_symlink() {
                // Chromium creates SingletonLock/SingletonSocket links in a
                // normal profile. Never follow them or charge their targets
                // to the operation; only regular files below the pinned
                // ephemeral profile contribute to the disk ceiling.
                continue;
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                match entry.metadata() {
                    Ok(metadata) => bytes = bytes.saturating_add(metadata.len()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(format!("Failed to inspect browser profile file: {error}"));
                    }
                }
            }
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> crate::secrets::SecretString {
        crate::secrets::SecretString::try_from_string(BASE64_STANDARD.encode([7_u8; 32]))
            .expect("test key")
    }

    fn test_grant() -> BrowserPersistenceGrant {
        BrowserPersistenceGrant::new(
            "primary".to_string(),
            ["https://example.com"],
            test_secret(),
            3_600,
        )
        .expect("test grant")
    }

    #[test]
    fn every_browser_resource_dimension_is_hard_bounded() {
        let limits = BrowserLimits::default();
        assert_eq!(limits.downloads, 0);
        assert!(limits.concurrent_sessions > 0);
        assert!(limits.tabs > 0);
        assert!(limits.requests > 0);
        assert!(limits.dom_bytes > 0);
        assert!(limits.dom_nodes > 0);
        assert!(limits.processes > 0);
        assert!(limits.resident_memory_bytes > 0);
        assert!(limits.cpu_millis > 0);
        assert!(limits.profile_disk_bytes > 0);
        assert!(limits.elapsed_millis > 0);
    }

    #[test]
    fn resource_limit_reports_the_first_exceeded_dimension() {
        let limits = BrowserLimits::default();
        let usage = BrowserResourceUsage {
            requests: limits.requests + 1,
            ..BrowserResourceUsage::default()
        };
        assert_eq!(usage.exceeded(limits), Some("requests"));
    }

    #[test]
    fn profile_measurement_never_follows_links() {
        #[cfg(unix)]
        {
            let root = tempfile::tempdir().expect("profile");
            let outside = tempfile::NamedTempFile::new().expect("outside file");
            std::fs::write(outside.path(), vec![0_u8; 4096]).expect("outside contents");
            std::os::unix::fs::symlink(outside.path(), root.path().join("link")).expect("link");
            assert_eq!(directory_bytes(root.path(), 10).expect("measurement"), 0);
        }
    }

    #[test]
    fn browser_persistence_is_exact_origin_and_redacted() {
        let grant = test_grant();
        assert_eq!(grant.profile_id(), "primary");
        assert!(format!("{grant:?}").contains("[REDACTED]"));
        assert!(!format!("{grant:?}").contains(&BASE64_STANDARD.encode([7_u8; 32])));
        #[cfg(feature = "browser")]
        {
            assert_eq!(
                grant.origin_for_navigation("https://example.com/account"),
                Some("https://example.com".to_string())
            );
            assert_eq!(
                grant.origin_for_navigation("https://sub.example.com/account"),
                None
            );
        }
    }

    #[test]
    fn browser_persistence_rejects_weak_or_ambiguous_authority() {
        assert!(BrowserPersistenceGrant::new(
            "../shared".to_string(),
            ["https://example.com"],
            test_secret(),
            3_600,
        )
        .is_err());
        let short_key =
            crate::secrets::SecretString::try_from_string(BASE64_STANDARD.encode([1_u8; 16]))
                .expect("short key string");
        assert!(BrowserPersistenceGrant::new(
            "primary".to_string(),
            ["https://example.com/path"],
            short_key,
            3_600,
        )
        .is_err());
    }

    #[test]
    fn browser_persistence_requires_run_secrets_authority() {
        let grants = crate::web_egress::WebEgressGrants::public_only()
            .with_browser_persistence(
                "primary".to_string(),
                ["https://example.com"],
                test_secret(),
                3_600,
            )
            .expect("browser persistence grant");
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let error = crate::tools::ToolRunContext::builder(crate::state::SessionId::new(), root)
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(std::collections::HashMap::new())
            .web_egress_grants(grants)
            .workspace_access(crate::tools::WorkspaceAccess::ReadOnly)
            .process(true)
            .network(true)
            .secrets(false)
            .provider("browser-persistence-test")
            .ephemeral_background_jobs()
            .build()
            .expect_err("secretless run must reject browser persistence");
        assert!(error.contains("explicit secrets capability"));
    }

    #[cfg(feature = "browser")]
    #[test]
    fn encrypted_cookie_state_authenticates_origin_and_ciphertext() {
        let grant = test_grant();
        let cookie = serde_json::from_value(serde_json::json!({
            "name": "session",
            "value": "cookie-secret",
            "url": "https://example.com",
            "path": "/",
            "secure": true,
            "httpOnly": true
        }))
        .expect("cookie parameter");
        let state = BrowserCookieState {
            schema_version: BROWSER_COOKIE_STATE_SCHEMA_VERSION,
            origin: "https://example.com".to_string(),
            cookies: vec![cookie],
        };
        let encoded = grant
            .encrypt_cookie_state("https://example.com", &state)
            .expect("encrypted state");
        assert!(!String::from_utf8_lossy(&encoded).contains("cookie-secret"));
        let decoded = grant
            .decrypt_cookie_state("https://example.com", &encoded)
            .expect("authenticated state")
            .expect("fresh state");
        assert_eq!(decoded.cookies[0].value, "cookie-secret");
        assert!(grant
            .decrypt_cookie_state("https://other.example", &encoded)
            .is_err());

        let mut envelope: EncryptedCookieEnvelope =
            serde_json::from_slice(&encoded).expect("envelope");
        envelope.saved_unix_seconds = envelope.saved_unix_seconds.saturating_add(1);
        let tampered_timestamp = serde_json::to_vec(&envelope).expect("tampered timestamp");
        assert!(grant
            .decrypt_cookie_state("https://example.com", &tampered_timestamp)
            .is_err());
        envelope.saved_unix_seconds = envelope.saved_unix_seconds.saturating_sub(1);
        let mut ciphertext = BASE64_STANDARD
            .decode(&envelope.ciphertext_base64)
            .expect("ciphertext");
        ciphertext[0] ^= 0x80;
        envelope.ciphertext_base64 = BASE64_STANDARD.encode(ciphertext);
        let tampered = serde_json::to_vec(&envelope).expect("tampered envelope");
        assert!(grant
            .decrypt_cookie_state("https://example.com", &tampered)
            .is_err());
    }

    #[cfg(feature = "browser")]
    #[test]
    fn encrypted_cookie_file_uses_descriptor_safe_credentials_storage() {
        let root = tempfile::tempdir().expect("storage parent");
        let mut grant = test_grant();
        grant.storage_root = root.path().join("profile");
        let state = BrowserCookieState {
            schema_version: BROWSER_COOKIE_STATE_SCHEMA_VERSION,
            origin: "https://example.com".to_string(),
            cookies: Vec::new(),
        };
        let encoded = grant
            .encrypt_cookie_state("https://example.com", &state)
            .expect("encrypted state");
        let storage = grant.open_storage().expect("pinned storage");
        let target = cookie_state_target("https://example.com");
        let observed = storage
            .read(&target, crate::persistence::FileClass::Credentials)
            .expect("missing generation");
        storage
            .commit(
                &target,
                crate::persistence::FileClass::Credentials,
                observed.generation(),
                &encoded,
            )
            .expect("credential commit");
        let persisted = storage
            .read(&target, crate::persistence::FileClass::Credentials)
            .expect("persisted state");
        persisted.expose_bytes(|bytes| {
            let decoded = grant
                .decrypt_cookie_state("https://example.com", bytes.expect("bytes"))
                .expect("authenticated state")
                .expect("fresh state");
            assert!(decoded.cookies.is_empty());
        });
    }
}
