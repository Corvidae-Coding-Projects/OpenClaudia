//! Canonical connection-boundary policy for web tools.
//!
//! URL validation is not a network boundary: a resolver can return a
//! different address when the HTTP client dials, redirects can cross origins,
//! and Chromium owns many connections that the caller never sees. This module
//! resolves and classifies every candidate address, pins the admitted set into
//! the client that performs the dial, disables ambient proxies for direct
//! requests, and provides the only proxy Chromium may use.

use async_trait::async_trait;
use futures::StreamExt as _;
use reqwest::header::{HeaderMap, LOCATION};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[cfg(feature = "browser")]
use tokio::net::TcpStream;
use tokio::time::Instant;
use url::{Host, Url};

use crate::runtime::ContentDigest;
use crate::tools::ToolRunContext;

/// Serialized receipt schema for connection-boundary evidence.
pub const NETWORK_RECEIPT_SCHEMA_VERSION: u16 = 1;
/// Direct web requests must finish within this wall-clock budget.
pub const DIRECT_WEB_TIME_LIMIT: Duration = Duration::from_secs(30);
/// Browser proxy connections are bounded independently of browser supervision.
pub const BROWSER_CONNECTION_TIME_LIMIT: Duration = Duration::from_secs(45);
/// DNS must not consume the complete operation budget before a dial begins.
const DNS_RESOLUTION_TIME_LIMIT: Duration = Duration::from_secs(10);
/// No proxy request header may grow without bound before admission.
#[cfg(feature = "browser")]
const MAX_PROXY_HEADER_BYTES: usize = 64 * 1024;

/// Why a private origin is present in one immutable run capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum WebEgressUse {
    /// Model-selected fetches and all browser/search traffic.
    WebContent,
    /// The host-configured provider used to distill an already fetched page.
    Distillation,
}

/// Normalized origin. Paths, queries, fragments, and credentials are never
/// retained in policy or receipt state.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct WebOrigin {
    scheme: String,
    host: String,
    port: u16,
}

impl fmt::Debug for WebOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.redacted())
    }
}

impl WebOrigin {
    fn from_url(url: &Url) -> Result<Self, WebEgressError> {
        if !url.username().is_empty() || url.password().is_some() {
            return Err(WebEgressError::policy(
                "URL userinfo is forbidden at the web connection boundary",
            ));
        }
        let host = match url.host() {
            Some(Host::Domain(host)) => host.to_ascii_lowercase(),
            Some(Host::Ipv4(address)) => address.to_string(),
            Some(Host::Ipv6(address)) => address.to_string(),
            None => return Err(WebEgressError::invalid("URL has no host")),
        };
        let port = url
            .port_or_known_default()
            .ok_or_else(|| WebEgressError::invalid("URL scheme has no known port"))?;
        Ok(Self {
            scheme: url.scheme().to_ascii_lowercase(),
            host,
            port,
        })
    }

    /// Parse a configuration value that must be exactly one origin.
    ///
    /// # Errors
    ///
    /// Rejects unsupported schemes, userinfo, paths, queries, or fragments.
    fn parse_exact(value: &str) -> Result<Self, String> {
        let url = Url::parse(value).map_err(|error| format!("invalid exact origin: {error}"))?;
        if !matches!(url.scheme(), "http" | "https" | "ws" | "wss") {
            return Err(format!(
                "exact web origin '{}' uses unsupported scheme '{}'",
                redact_untrusted_url(value),
                url.scheme()
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("exact web origin cannot contain userinfo".to_string());
        }
        if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
            return Err("exact web origin cannot contain a path, query, or fragment".to_string());
        }
        Self::from_url(&url).map_err(|error| error.to_string())
    }

    #[must_use]
    fn redacted(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default_port = matches!(
            (self.scheme.as_str(), self.port),
            ("http" | "ws", 80) | ("https" | "wss", 443)
        );
        if default_port {
            format!("{}://{host}", self.scheme)
        } else {
            format!("{}://{host}:{}", self.scheme, self.port)
        }
    }

    fn socket_host(&self) -> &str {
        &self.host
    }
}

/// Immutable private/local origin grants bound into one run generation.
/// Public destinations still require the run's ordinary Network capability.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct WebEgressGrants {
    web_content: Arc<BTreeSet<WebOrigin>>,
    distillation: Arc<BTreeSet<WebOrigin>>,
    browser_persistence: Option<crate::web_supervisor::BrowserPersistenceGrant>,
}

impl fmt::Debug for WebEgressGrants {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebEgressGrants")
            .field("web_content_origin_count", &self.web_content.len())
            .field("distillation_origin_count", &self.distillation.len())
            .field(
                "browser_persistence",
                &self
                    .browser_persistence
                    .as_ref()
                    .map(crate::web_supervisor::BrowserPersistenceGrant::profile_id),
            )
            .finish()
    }
}

impl WebEgressGrants {
    #[must_use]
    pub fn public_only() -> Self {
        Self::default()
    }

    /// Build model-selected web-content grants from trusted exact origins.
    ///
    /// # Errors
    ///
    /// Fails closed when any configured value is not a pure HTTP(S)/WS(S)
    /// origin.
    pub fn from_exact_web_origins<I, S>(origins: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut web_content = BTreeSet::new();
        for value in origins {
            web_content.insert(WebOrigin::parse_exact(value.as_ref())?);
        }
        Ok(Self {
            web_content: Arc::new(web_content),
            distillation: Arc::new(BTreeSet::new()),
            browser_persistence: None,
        })
    }

    /// Add the origin portion of one configured provider endpoint. Provider
    /// base URLs legitimately contain paths, so this constructor deliberately
    /// discards path/query/fragment after rejecting credentials and schemes
    /// other than HTTP(S).
    ///
    /// # Errors
    ///
    /// Fails when the endpoint is malformed, credential-bearing, or non-HTTP.
    pub fn with_distillation_endpoint(mut self, endpoint: &str) -> Result<Self, String> {
        let url = Url::parse(endpoint)
            .map_err(|error| format!("invalid distillation provider endpoint: {error}"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(format!(
                "distillation provider endpoint uses unsupported scheme '{}'",
                url.scheme()
            ));
        }
        let origin = WebOrigin::from_url(&url).map_err(|error| error.to_string())?;
        let mut origins = (*self.distillation).clone();
        origins.insert(origin);
        self.distillation = Arc::new(origins);
        Ok(self)
    }

    /// Add an exact-origin, encrypted cookie capability from trusted host
    /// configuration. Normal browser runs remain ephemeral when absent.
    ///
    /// # Errors
    ///
    /// Rejects malformed profile identifiers, keys, origins, retention, or a
    /// host without a resolvable local-data directory.
    pub fn with_browser_persistence<I, S>(
        mut self,
        profile_id: String,
        origins: I,
        encryption_key: crate::secrets::SecretString,
        retention_seconds: u64,
    ) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.browser_persistence = Some(crate::web_supervisor::BrowserPersistenceGrant::new(
            profile_id,
            origins,
            encryption_key,
            retention_seconds,
        )?);
        Ok(self)
    }

    #[cfg(feature = "browser")]
    pub(crate) const fn browser_persistence(
        &self,
    ) -> Option<&crate::web_supervisor::BrowserPersistenceGrant> {
        self.browser_persistence.as_ref()
    }

    pub(crate) const fn has_browser_persistence(&self) -> bool {
        self.browser_persistence.is_some()
    }

    fn permits_private(&self, origin: &WebOrigin, usage: WebEgressUse) -> bool {
        match usage {
            WebEgressUse::WebContent => self.web_content.contains(origin),
            WebEgressUse::Distillation => {
                self.distillation.contains(origin) || self.web_content.contains(origin)
            }
        }
    }

    #[must_use]
    pub fn authority_digest(&self) -> ContentDigest {
        let mut manifest = String::from("web-egress-grants-v1\n");
        for origin in self.web_content.iter() {
            manifest.push_str("web_content=");
            manifest.push_str(&origin.redacted());
            manifest.push('\n');
        }
        for origin in self.distillation.iter() {
            manifest.push_str("distillation=");
            manifest.push_str(&origin.redacted());
            manifest.push('\n');
        }
        if let Some(grant) = &self.browser_persistence {
            manifest.push_str("browser_persistence=");
            manifest.push_str(&grant.authority_digest().to_string());
            manifest.push('\n');
        }
        ContentDigest::sha256(manifest)
    }
}

/// Concrete transport that produced one receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebEgressBackend {
    DirectHttp,
    BrowserProxy,
    Distillation,
}

/// Redacted connection-boundary evidence returned with every web tool result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkReceipt {
    pub schema_version: u16,
    pub origin: String,
    pub redirect_chain: Vec<String>,
    pub final_peer: Option<String>,
    pub policy_generation: u64,
    pub backend: WebEgressBackend,
    pub byte_limit: u64,
    pub time_limit_ms: u64,
    /// Body bytes observed by buffered HTTP backends. Browser tunnel traffic
    /// is bidirectional and therefore leaves this unset rather than claiming
    /// an inaccurate response count.
    pub bytes_received: Option<u64>,
}

impl NetworkReceipt {
    fn new(
        origin: &WebOrigin,
        run: &ToolRunContext,
        backend: WebEgressBackend,
        byte_limit: usize,
        time_limit: Duration,
    ) -> Self {
        Self {
            schema_version: NETWORK_RECEIPT_SCHEMA_VERSION,
            origin: origin.redacted(),
            redirect_chain: Vec::new(),
            final_peer: None,
            policy_generation: run.generation().get(),
            backend,
            byte_limit: u64::try_from(byte_limit).unwrap_or(u64::MAX),
            time_limit_ms: u64::try_from(time_limit.as_millis()).unwrap_or(u64::MAX),
            bytes_received: None,
        }
    }
}

/// Stable web-egress failure category used by typed tool results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebEgressErrorKind {
    InvalidUrl,
    PolicyDenied,
    Resolution,
    Rebinding,
    Connect,
    Deadline,
    ResponseTooLarge,
    Protocol,
    Cancelled,
    External,
}

/// A safe diagnostic plus any receipts produced before the failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebEgressError {
    pub kind: WebEgressErrorKind,
    pub message: String,
    pub receipts: Vec<NetworkReceipt>,
    pub browser_receipts: Vec<crate::web_supervisor::BrowserSupervisionReceipt>,
}

impl fmt::Display for WebEgressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for WebEgressError {}

impl WebEgressError {
    pub(crate) fn new(kind: WebEgressErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            receipts: Vec::new(),
            browser_receipts: Vec::new(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new(WebEgressErrorKind::InvalidUrl, message)
    }

    fn policy(message: impl Into<String>) -> Self {
        Self::new(WebEgressErrorKind::PolicyDenied, message)
    }

    fn with_receipt(mut self, receipt: NetworkReceipt) -> Self {
        self.receipts.push(receipt);
        self
    }

    pub(crate) fn with_receipts(mut self, receipts: Vec<NetworkReceipt>) -> Self {
        self.receipts = receipts;
        self
    }

    #[cfg(feature = "browser")]
    pub(crate) fn with_browser_receipt(
        mut self,
        receipt: crate::web_supervisor::BrowserSupervisionReceipt,
    ) -> Self {
        self.browser_receipts.push(receipt);
        self
    }

    pub(crate) fn with_browser_receipts(
        mut self,
        receipts: Vec<crate::web_supervisor::BrowserSupervisionReceipt>,
    ) -> Self {
        self.browser_receipts = receipts;
        self
    }

    #[must_use]
    pub fn external(message: impl Into<String>, receipts: Vec<NetworkReceipt>) -> Self {
        Self {
            kind: WebEgressErrorKind::External,
            message: message.into(),
            receipts,
            browser_receipts: Vec::new(),
        }
    }
}

/// Buffered HTTP response returned only after the body cap has been enforced.
#[derive(Debug)]
pub struct BrokeredHttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub final_url: String,
    pub receipt: NetworkReceipt,
}

#[async_trait]
trait WebResolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String>;
}

struct SystemWebResolver;

#[async_trait]
impl WebResolver for SystemWebResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        tokio::net::lookup_host((host, port))
            .await
            .map(std::iter::Iterator::collect)
            .map_err(|_| "system resolver failed".to_string())
    }
}

#[derive(Clone, Debug)]
struct AdmittedDestination {
    origin: WebOrigin,
    addresses: Vec<SocketAddr>,
}

/// Operation-scoped broker. Its resolution cache pins one exact address set
/// for each origin for the lifetime of a tool invocation.
pub struct WebEgressBroker {
    run: Arc<ToolRunContext>,
    cancellation: crate::runtime::CancellationHandle,
    resolver: Arc<dyn WebResolver>,
    resolved: Mutex<BTreeMap<WebOrigin, Vec<SocketAddr>>>,
}

impl fmt::Debug for WebEgressBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let resolved_count = self
            .resolved
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        formatter
            .debug_struct("WebEgressBroker")
            .field("run_id", &self.run.run_id())
            .field("policy_generation", &self.run.generation())
            .field("resolved_origin_count", &resolved_count)
            .finish_non_exhaustive()
    }
}

impl WebEgressBroker {
    /// Bind one broker to an already-authorized run and one tool operation.
    ///
    /// # Errors
    ///
    /// Returns a capability error if the run has no network authority.
    pub fn new(run: Arc<ToolRunContext>) -> Result<Arc<Self>, WebEgressError> {
        let cancellation = run.runtime().cancellation();
        Self::new_with_cancellation(run, cancellation)
    }

    /// Bind a broker to one supervised child operation in the run tree.
    ///
    /// # Errors
    ///
    /// Returns a capability error if the run has no network authority.
    pub(crate) fn new_with_cancellation(
        run: Arc<ToolRunContext>,
        cancellation: crate::runtime::CancellationHandle,
    ) -> Result<Arc<Self>, WebEgressError> {
        run.require(crate::tools::ToolResource::Network)
            .map_err(|error| WebEgressError::policy(error.to_string()))?;
        Ok(Arc::new(Self {
            run,
            cancellation,
            resolver: Arc::new(SystemWebResolver),
            resolved: Mutex::new(BTreeMap::new()),
        }))
    }

    #[cfg(test)]
    fn with_resolver(
        run: Arc<ToolRunContext>,
        resolver: Arc<dyn WebResolver>,
    ) -> Result<Arc<Self>, WebEgressError> {
        run.require(crate::tools::ToolResource::Network)
            .map_err(|error| WebEgressError::policy(error.to_string()))?;
        let cancellation = run.runtime().cancellation();
        Ok(Arc::new(Self {
            run,
            cancellation,
            resolver,
            resolved: Mutex::new(BTreeMap::new()),
        }))
    }

    #[cfg(feature = "browser")]
    pub(crate) fn cancellation(&self) -> crate::runtime::CancellationHandle {
        self.cancellation.clone()
    }

    fn parse_url(raw: &str, browser: bool) -> Result<Url, WebEgressError> {
        let url = Url::parse(raw).map_err(|_| WebEgressError::invalid("Invalid web URL"))?;
        let allowed = if browser {
            matches!(url.scheme(), "http" | "https" | "ws" | "wss")
        } else {
            matches!(url.scheme(), "http" | "https")
        };
        if !allowed {
            return Err(WebEgressError::policy(format!(
                "Unsupported URL scheme '{}'",
                url.scheme()
            )));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(WebEgressError::policy(
                "URL userinfo is forbidden at the web connection boundary",
            ));
        }
        Ok(url)
    }

    async fn admit_url(
        &self,
        raw: &str,
        usage: WebEgressUse,
        browser: bool,
    ) -> Result<AdmittedDestination, WebEgressError> {
        let url = Self::parse_url(raw, browser)?;
        let origin = WebOrigin::from_url(&url)?;
        self.admit_origin(origin, usage).await
    }

    async fn admit_origin(
        &self,
        origin: WebOrigin,
        usage: WebEgressUse,
    ) -> Result<AdmittedDestination, WebEgressError> {
        let cached_addresses = self
            .resolved
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&origin)
            .cloned();
        if let Some(addresses) = cached_addresses {
            return Ok(AdmittedDestination { origin, addresses });
        }

        let exact_private_grant = self.run.web_egress_grants().permits_private(&origin, usage);
        if crate::web::is_dangerous_hostname(origin.socket_host()) && !exact_private_grant {
            return Err(WebEgressError::policy(format!(
                "Web origin '{}' is a known local or metadata endpoint without an exact grant",
                origin.redacted()
            )));
        }

        let cancellation = self.cancellation.clone();
        let resolved = tokio::select! {
            _ = cancellation.cancelled() => {
                return Err(WebEgressError::new(
                    WebEgressErrorKind::Cancelled,
                    "Web origin resolution was cancelled",
                ));
            }
            result = tokio::time::timeout(
                DNS_RESOLUTION_TIME_LIMIT,
                self.resolver.resolve(origin.socket_host(), origin.port),
            ) => {
                result.unwrap_or_else(|_| Err("resolver deadline exceeded".to_string()))
            },
        }
        .map_err(|_| {
            WebEgressError::new(
                WebEgressErrorKind::Resolution,
                format!("Web origin '{}' could not be resolved", origin.redacted()),
            )
        })?;
        let mut addresses = resolved;
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(WebEgressError::new(
                WebEgressErrorKind::Resolution,
                format!(
                    "Web origin '{}' resolved to no addresses",
                    origin.redacted()
                ),
            ));
        }
        for address in &addresses {
            if !exact_private_grant {
                crate::web::validate_resolved_ip(address.ip()).map_err(|_| {
                    WebEgressError::policy(format!(
                        "Web origin '{}' resolved to a reserved/internal, private, local, or metadata address",
                        origin.redacted()
                    ))
                })?;
            }
        }

        let mut cache = self
            .resolved
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = cache.get(&origin) {
            if existing != &addresses {
                return Err(WebEgressError::new(
                    WebEgressErrorKind::Rebinding,
                    format!(
                        "Web origin '{}' changed its address set during one operation",
                        origin.redacted()
                    ),
                ));
            }
        } else {
            cache.insert(origin.clone(), addresses.clone());
        }
        drop(cache);
        Ok(AdmittedDestination { origin, addresses })
    }

    #[cfg(feature = "browser")]
    async fn admit_connect_authority(
        &self,
        authority: &str,
    ) -> Result<AdmittedDestination, WebEgressError> {
        let url = Self::parse_url(&format!("https://{authority}/"), true)?;
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err(WebEgressError::new(
                WebEgressErrorKind::Protocol,
                "Browser proxy CONNECT target was not a bare authority",
            ));
        }
        let mut origin = WebOrigin::from_url(&url)?;
        let wss_origin = WebOrigin {
            scheme: "wss".to_string(),
            host: origin.host.clone(),
            port: origin.port,
        };
        if !self
            .run
            .web_egress_grants()
            .permits_private(&origin, WebEgressUse::WebContent)
            && self
                .run
                .web_egress_grants()
                .permits_private(&wss_origin, WebEgressUse::WebContent)
        {
            origin = wss_origin;
        }
        let receipt = NetworkReceipt::new(
            &origin,
            &self.run,
            WebEgressBackend::BrowserProxy,
            crate::web::MAX_WEB_FETCH_BYTES,
            BROWSER_CONNECTION_TIME_LIMIT,
        );
        self.admit_origin(origin, WebEgressUse::WebContent)
            .await
            .map_err(|error| error.with_receipt(receipt))
    }

    #[cfg(feature = "browser")]
    async fn admit_browser_url(&self, raw: &str) -> Result<AdmittedDestination, WebEgressError> {
        let url = Self::parse_url(raw, true)?;
        let origin = WebOrigin::from_url(&url)?;
        let receipt = NetworkReceipt::new(
            &origin,
            &self.run,
            WebEgressBackend::BrowserProxy,
            crate::web::MAX_WEB_FETCH_BYTES,
            BROWSER_CONNECTION_TIME_LIMIT,
        );
        self.admit_origin(origin, WebEgressUse::WebContent)
            .await
            .map_err(|error| error.with_receipt(receipt))
    }

    /// Validate a browser request before CDP permits it. Actual DNS/address
    /// enforcement still occurs in [`BrowserEgressProxy`].
    ///
    /// Non-network `about:`, `data:`, and `blob:` URLs are admitted because
    /// they cannot create a socket themselves. All other schemes fail closed.
    ///
    /// # Errors
    ///
    /// Returns a typed policy error for malformed, credential-bearing,
    /// unsupported, or ungranted private/local network URLs.
    pub fn validate_browser_request(&self, raw: &str) -> Result<Option<String>, WebEgressError> {
        let url = Url::parse(raw).map_err(|_| WebEgressError::invalid("Invalid browser URL"))?;
        if matches!(url.scheme(), "about" | "data" | "blob") {
            return Ok(None);
        }
        let url = Self::parse_url(raw, true)?;
        let origin = WebOrigin::from_url(&url)?;
        let exact = self
            .run
            .web_egress_grants()
            .permits_private(&origin, WebEgressUse::WebContent);
        if crate::web::is_dangerous_hostname(origin.socket_host()) && !exact {
            return Err(WebEgressError::policy(format!(
                "Browser origin '{}' is local or metadata-bound without an exact grant",
                origin.redacted()
            )));
        }
        if let Ok(address) = origin.socket_host().parse::<IpAddr>() {
            if !exact && crate::web::validate_resolved_ip(address).is_err() {
                return Err(WebEgressError::policy(format!(
                    "Browser origin '{}' is private, local, metadata, or reserved without an exact grant",
                    origin.redacted()
                )));
            }
        }
        Ok(Some(origin.redacted()))
    }

    /// Validate an operator/model-selected top-level browser destination.
    /// Unlike subresource interception, a top-level fetch may not start from
    /// an inert `data:`, `blob:`, or `about:` document.
    ///
    /// # Errors
    ///
    /// Returns a typed policy error unless the destination is an admitted
    /// HTTP(S) browser navigation.
    pub fn validate_browser_navigation(&self, raw: &str) -> Result<Option<String>, WebEgressError> {
        Self::parse_url(raw, false)?;
        self.validate_browser_request(raw)
    }

    /// GET one URL with no ambient proxy, pinned resolution, manual
    /// redirect re-admission, cancellation, and a bounded response body.
    ///
    /// # Errors
    ///
    /// Returns a typed policy, resolution, connection, redirect, deadline,
    /// cancellation, protocol, or response-limit error with redacted evidence.
    pub async fn get(
        &self,
        raw: &str,
        backend: WebEgressBackend,
        byte_limit: usize,
        time_limit: Duration,
    ) -> Result<BrokeredHttpResponse, WebEgressError> {
        self.send_http(
            Method::GET,
            raw,
            None,
            None,
            WebEgressUse::WebContent,
            backend,
            byte_limit,
            time_limit,
            true,
        )
        .await
    }

    /// POST host-built JSON to a configured distillation origin through the
    /// same pinned/no-proxy connection policy.
    ///
    /// # Errors
    ///
    /// Returns a typed policy, resolution, connection, deadline,
    /// cancellation, protocol, or response-limit error with redacted evidence.
    pub async fn post_distillation_json(
        &self,
        raw: &str,
        headers: &crate::secrets::SensitiveHeaders,
        body: &serde_json::Value,
        byte_limit: usize,
        time_limit: Duration,
    ) -> Result<BrokeredHttpResponse, WebEgressError> {
        self.send_http(
            Method::POST,
            raw,
            Some(headers),
            Some(body),
            WebEgressUse::Distillation,
            WebEgressBackend::Distillation,
            byte_limit,
            time_limit,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_http(
        &self,
        method: Method,
        raw: &str,
        sensitive_headers: Option<&crate::secrets::SensitiveHeaders>,
        json_body: Option<&serde_json::Value>,
        usage: WebEgressUse,
        backend: WebEgressBackend,
        byte_limit: usize,
        time_limit: Duration,
        follow_redirects: bool,
    ) -> Result<BrokeredHttpResponse, WebEgressError> {
        let requested = Self::parse_url(raw, false)?;
        let requested_origin = WebOrigin::from_url(&requested)?;
        let mut receipt = NetworkReceipt::new(
            &requested_origin,
            &self.run,
            backend,
            byte_limit,
            time_limit,
        );
        let deadline = Instant::now() + time_limit;
        let cancellation = self.cancellation.clone();
        let mut current = requested;

        for hop in 0..=crate::web::SSRF_REDIRECT_LIMIT {
            let admitted = self
                .admit_url(current.as_str(), usage, false)
                .await
                .map_err(|error| error.with_receipt(receipt.clone()))?;
            let client = crate::provider_transport::direct_client_with_pinned_resolution(
                admitted.origin.socket_host(),
                &admitted.addresses,
            )
            .map_err(|_| {
                WebEgressError::new(
                    WebEgressErrorKind::Connect,
                    "Pinned web HTTP client could not be built",
                )
                .with_receipt(receipt.clone())
            })?;
            let mut request = client
                .request(method.clone(), current.clone())
                .timeout(time_limit)
                .header(
                    "User-Agent",
                    "Mozilla/5.0 (compatible; OpenClaudia/0.5; +https://github.com/dollspace-gay/OpenClaudia)",
                );
            if method == Method::GET {
                request = request.header(
                    "Accept",
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                );
            }
            if let Some(headers) = sensitive_headers {
                request = headers.apply(request).map_err(|_| {
                    WebEgressError::new(
                        WebEgressErrorKind::Protocol,
                        "Configured distillation headers are invalid",
                    )
                    .with_receipt(receipt.clone())
                })?;
            }
            if let Some(body) = json_body {
                request = request.json(body);
            }

            let response = tokio::select! {
                _ = cancellation.cancelled() => {
                    return Err(WebEgressError::new(
                        WebEgressErrorKind::Cancelled,
                        "Web request was cancelled",
                    ).with_receipt(receipt));
                }
                result = tokio::time::timeout_at(deadline, request.send()) => {
                    match result {
                        Ok(Ok(response)) => response,
                        Ok(Err(_)) => {
                            return Err(WebEgressError::new(
                                WebEgressErrorKind::Connect,
                                format!("Connection to '{}' failed", admitted.origin.redacted()),
                            ).with_receipt(receipt));
                        }
                        Err(_) => {
                            return Err(WebEgressError::new(
                                WebEgressErrorKind::Deadline,
                                "Web request exceeded its time limit",
                            ).with_receipt(receipt));
                        }
                    }
                }
            };
            let final_peer = response.remote_addr().ok_or_else(|| {
                WebEgressError::new(
                    WebEgressErrorKind::Protocol,
                    "Web transport did not report its final peer",
                )
                .with_receipt(receipt.clone())
            })?;
            if !admitted.addresses.contains(&final_peer) {
                receipt.final_peer = Some(final_peer.to_string());
                return Err(WebEgressError::new(
                    WebEgressErrorKind::Rebinding,
                    "Web transport connected outside the broker-pinned address set",
                )
                .with_receipt(receipt));
            }
            receipt.final_peer = Some(final_peer.to_string());

            if follow_redirects && response.status().is_redirection() {
                if hop == crate::web::SSRF_REDIRECT_LIMIT {
                    return Err(WebEgressError::new(
                        WebEgressErrorKind::Protocol,
                        format!(
                            "Web redirect chain exceeded {} hops",
                            crate::web::SSRF_REDIRECT_LIMIT
                        ),
                    )
                    .with_receipt(receipt));
                }
                let location = response
                    .headers()
                    .get(LOCATION)
                    .ok_or_else(|| {
                        WebEgressError::new(
                            WebEgressErrorKind::Protocol,
                            "Web redirect omitted its Location header",
                        )
                        .with_receipt(receipt.clone())
                    })?
                    .to_str()
                    .map_err(|_| {
                        WebEgressError::new(
                            WebEgressErrorKind::Protocol,
                            "Web redirect Location was not valid text",
                        )
                        .with_receipt(receipt.clone())
                    })?;
                let next = current.join(location).map_err(|_| {
                    WebEgressError::new(
                        WebEgressErrorKind::InvalidUrl,
                        "Web redirect Location was not a valid URL",
                    )
                    .with_receipt(receipt.clone())
                })?;
                let next_origin = WebOrigin::from_url(&next)
                    .map_err(|error| error.with_receipt(receipt.clone()))?;
                receipt.redirect_chain.push(next_origin.redacted());
                current = next;
                continue;
            }

            let status = response.status();
            let headers = response.headers().clone();
            let body =
                read_response_body(response, byte_limit, deadline, &cancellation, &receipt).await?;
            receipt.bytes_received = Some(u64::try_from(body.len()).unwrap_or(u64::MAX));
            return Ok(BrokeredHttpResponse {
                status,
                headers,
                body,
                final_url: current.to_string(),
                receipt,
            });
        }
        unreachable!("bounded redirect loop returns from every branch")
    }

    #[cfg(feature = "browser")]
    async fn connect_admitted(
        &self,
        admitted: AdmittedDestination,
        byte_limit: usize,
        time_limit: Duration,
    ) -> Result<(TcpStream, NetworkReceipt), WebEgressError> {
        let mut receipt = NetworkReceipt::new(
            &admitted.origin,
            &self.run,
            WebEgressBackend::BrowserProxy,
            byte_limit,
            time_limit,
        );
        let deadline = Instant::now() + time_limit;
        let cancellation = self.cancellation.clone();
        for address in admitted.addresses {
            let result = tokio::select! {
                _ = cancellation.cancelled() => {
                    return Err(WebEgressError::new(
                        WebEgressErrorKind::Cancelled,
                        "Browser proxy connection was cancelled",
                    ).with_receipt(receipt));
                }
                result = tokio::time::timeout_at(deadline, TcpStream::connect(address)) => result,
            };
            match result {
                Ok(Ok(stream)) => {
                    receipt.final_peer = Some(address.to_string());
                    return Ok((stream, receipt));
                }
                Ok(Err(_)) => {}
                Err(_) => {
                    return Err(WebEgressError::new(
                        WebEgressErrorKind::Deadline,
                        "Browser proxy connection exceeded its time limit",
                    )
                    .with_receipt(receipt));
                }
            }
        }
        Err(WebEgressError::new(
            WebEgressErrorKind::Connect,
            format!("Connection to '{}' failed", admitted.origin.redacted()),
        )
        .with_receipt(receipt))
    }
}

async fn read_response_body(
    response: reqwest::Response,
    byte_limit: usize,
    deadline: Instant,
    cancellation: &crate::runtime::CancellationHandle,
    receipt: &NetworkReceipt,
) -> Result<Vec<u8>, WebEgressError> {
    if response
        .content_length()
        .is_some_and(|length| length > u64::try_from(byte_limit).unwrap_or(u64::MAX))
    {
        return Err(WebEgressError::new(
            WebEgressErrorKind::ResponseTooLarge,
            format!("Web response exceeded its {byte_limit}-byte limit"),
        )
        .with_receipt(receipt.clone()));
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    loop {
        let chunk = tokio::select! {
            _ = cancellation.cancelled() => {
                return Err(WebEgressError::new(
                    WebEgressErrorKind::Cancelled,
                    "Web response read was cancelled",
                ).with_receipt(receipt.clone()));
            }
            result = tokio::time::timeout_at(deadline, stream.next()) => {
                match result {
                    Ok(chunk) => chunk,
                    Err(_) => {
                        return Err(WebEgressError::new(
                            WebEgressErrorKind::Deadline,
                            "Web response exceeded its time limit",
                        ).with_receipt(receipt.clone()));
                    }
                }
            }
        };
        let Some(chunk) = chunk else {
            break;
        };
        let chunk = chunk.map_err(|_| {
            WebEgressError::new(
                WebEgressErrorKind::Connect,
                "Web response body could not be read",
            )
            .with_receipt(receipt.clone())
        })?;
        let next = bytes
            .len()
            .checked_add(chunk.len())
            .filter(|length| *length <= byte_limit)
            .ok_or_else(|| {
                WebEgressError::new(
                    WebEgressErrorKind::ResponseTooLarge,
                    format!("Web response exceeded its {byte_limit}-byte limit"),
                )
                .with_receipt(receipt.clone())
            })?;
        bytes.reserve(next.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn redact_untrusted_url(raw: &str) -> String {
    Url::parse(raw)
        .ok()
        .and_then(|url| WebOrigin::from_url(&url).ok())
        .map_or_else(|| "<invalid-url>".to_string(), |origin| origin.redacted())
}

/// Loopback forward proxy used as Chromium's sole network route.
#[cfg(feature = "browser")]
pub struct BrowserEgressProxy {
    address: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
    receipts: Arc<Mutex<Vec<NetworkReceipt>>>,
}

#[cfg(feature = "browser")]
impl BrowserEgressProxy {
    /// Start one operation-scoped proxy on an ephemeral loopback port.
    ///
    /// # Errors
    ///
    /// Returns a typed external error when the loopback listener cannot be
    /// created or its address cannot be inspected.
    pub async fn start(broker: Arc<WebEgressBroker>) -> Result<Self, WebEgressError> {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| {
                WebEgressError::new(
                    WebEgressErrorKind::External,
                    "Browser egress proxy could not bind loopback",
                )
            })?;
        let address = listener.local_addr().map_err(|_| {
            WebEgressError::new(
                WebEgressErrorKind::External,
                "Browser egress proxy address was unavailable",
            )
        })?;
        let (shutdown, mut shutdown_rx) = tokio::sync::oneshot::channel();
        let receipts = Arc::new(Mutex::new(Vec::new()));
        let task_receipts = Arc::clone(&receipts);
        let cancellation = broker.cancellation();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    _ = cancellation.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break; };
                        let connection_broker = Arc::clone(&broker);
                        let connection_receipts = Arc::clone(&task_receipts);
                        connections.spawn(async move {
                            if let Err(error) = Box::pin(handle_proxy_connection(
                                stream,
                                connection_broker,
                                Arc::clone(&connection_receipts),
                            )).await {
                                connection_receipts
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .extend(error.receipts);
                            }
                        });
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Ok(Self {
            address,
            shutdown: Some(shutdown),
            task: Some(task),
            receipts,
        })
    }

    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    #[must_use]
    pub fn receipts(&self) -> Vec<NetworkReceipt> {
        self.receipts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub async fn shutdown(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

#[cfg(feature = "browser")]
impl Drop for BrowserEgressProxy {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

#[cfg(feature = "browser")]
#[allow(clippy::too_many_lines)] // one linear HTTP/1 proxy parser keeps admission before every dial
async fn handle_proxy_connection(
    mut inbound: TcpStream,
    broker: Arc<WebEgressBroker>,
    receipts: Arc<Mutex<Vec<NetworkReceipt>>>,
) -> Result<(), WebEgressError> {
    use tokio::io::AsyncWriteExt as _;

    let (head, buffered_body) = read_proxy_head(&mut inbound).await?;
    let head_text = std::str::from_utf8(&head).map_err(|_| {
        WebEgressError::new(
            WebEgressErrorKind::Protocol,
            "Browser proxy request header was not valid UTF-8",
        )
    })?;
    let mut lines = head_text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        WebEgressError::new(
            WebEgressErrorKind::Protocol,
            "Browser proxy request line was missing",
        )
    })?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
        return Err(WebEgressError::new(
            WebEgressErrorKind::Protocol,
            "Browser proxy request line was malformed",
        ));
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let admitted = broker.admit_connect_authority(target).await?;
        let (mut upstream, receipt) = broker
            .connect_admitted(
                admitted,
                crate::web::MAX_WEB_FETCH_BYTES,
                BROWSER_CONNECTION_TIME_LIMIT,
            )
            .await?;
        receipts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(receipt);
        inbound
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|_| {
                WebEgressError::new(
                    WebEgressErrorKind::Connect,
                    "Browser proxy could not acknowledge the tunnel",
                )
            })?;
        Box::pin(copy_bidirectional_bounded(
            &mut inbound,
            &mut upstream,
            crate::web::MAX_WEB_FETCH_BYTES,
            BROWSER_CONNECTION_TIME_LIMIT,
        ))
        .await?;
        return Ok(());
    }

    let url = Url::parse(target).map_err(|_| {
        WebEgressError::new(
            WebEgressErrorKind::Protocol,
            "Browser proxy requires an absolute HTTP request target",
        )
    })?;
    if !matches!(url.scheme(), "http" | "ws") {
        return Err(WebEgressError::new(
            WebEgressErrorKind::Protocol,
            "Browser proxy absolute requests require http or ws",
        ));
    }
    let admitted = broker.admit_browser_url(url.as_str()).await?;
    let (mut upstream, receipt) = broker
        .connect_admitted(
            admitted,
            crate::web::MAX_WEB_FETCH_BYTES,
            BROWSER_CONNECTION_TIME_LIMIT,
        )
        .await?;
    receipts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(receipt);

    let path = url.query().map_or_else(
        || {
            if url.path().is_empty() {
                "/".to_string()
            } else {
                url.path().to_string()
            }
        },
        |query| format!("{}?{query}", url.path()),
    );
    let authority = url.authority();
    let mut forwarded = format!("{method} {path} {version}\r\nHost: {authority}\r\n");
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if line.is_empty()
            || lower.starts_with("host:")
            || lower.starts_with("proxy-connection:")
            || lower.starts_with("proxy-authorization:")
        {
            continue;
        }
        forwarded.push_str(line);
        forwarded.push_str("\r\n");
    }
    forwarded.push_str("\r\n");
    upstream
        .write_all(forwarded.as_bytes())
        .await
        .map_err(|_| {
            WebEgressError::new(
                WebEgressErrorKind::Connect,
                "Browser proxy could not forward the request header",
            )
        })?;
    if !buffered_body.is_empty() {
        upstream.write_all(&buffered_body).await.map_err(|_| {
            WebEgressError::new(
                WebEgressErrorKind::Connect,
                "Browser proxy could not forward the buffered request body",
            )
        })?;
    }
    Box::pin(copy_bidirectional_bounded(
        &mut inbound,
        &mut upstream,
        crate::web::MAX_WEB_FETCH_BYTES,
        BROWSER_CONNECTION_TIME_LIMIT,
    ))
    .await
}

#[cfg(feature = "browser")]
async fn read_proxy_head(stream: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>), WebEgressError> {
    use tokio::io::AsyncReadExt as _;

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = tokio::time::timeout_at(deadline, stream.read(&mut chunk))
            .await
            .map_err(|_| {
                WebEgressError::new(
                    WebEgressErrorKind::Deadline,
                    "Browser proxy request header timed out",
                )
            })?
            .map_err(|_| {
                WebEgressError::new(
                    WebEgressErrorKind::Connect,
                    "Browser proxy request header could not be read",
                )
            })?;
        if read == 0 {
            return Err(WebEgressError::new(
                WebEgressErrorKind::Protocol,
                "Browser proxy connection closed before a complete request",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > MAX_PROXY_HEADER_BYTES {
            return Err(WebEgressError::new(
                WebEgressErrorKind::ResponseTooLarge,
                "Browser proxy request header exceeded its byte limit",
            ));
        }
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let split = end + 4;
            let body = bytes.split_off(split);
            return Ok((bytes, body));
        }
    }
}

#[cfg(feature = "browser")]
async fn copy_bidirectional_bounded(
    left: &mut TcpStream,
    right: &mut TcpStream,
    byte_limit: usize,
    time_limit: Duration,
) -> Result<(), WebEgressError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

    async fn copy_one<R, W>(
        mut reader: R,
        mut writer: W,
        consumed: Arc<AtomicU64>,
        byte_limit: u64,
    ) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut buffer = [0_u8; 8192];
        loop {
            let read = reader.read(&mut buffer).await?;
            if read == 0 {
                writer.shutdown().await?;
                return Ok(());
            }
            let read_u64 = u64::try_from(read).unwrap_or(u64::MAX);
            consumed
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current
                        .checked_add(read_u64)
                        .filter(|next| *next <= byte_limit)
                })
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::FileTooLarge,
                        "browser proxy byte limit exceeded",
                    )
                })?;
            writer.write_all(&buffer[..read]).await?;
        }
    }

    let (left_read, left_write) = left.split();
    let (right_read, right_write) = right.split();
    let consumed = Arc::new(AtomicU64::new(0));
    let limit = u64::try_from(byte_limit).unwrap_or(u64::MAX);
    let copies = async {
        tokio::select! {
            result = copy_one(left_read, right_write, Arc::clone(&consumed), limit) => result,
            result = copy_one(right_read, left_write, consumed, limit) => result,
        }
    };
    match Box::pin(tokio::time::timeout(time_limit, copies)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::FileTooLarge => {
            Err(WebEgressError::new(
                WebEgressErrorKind::ResponseTooLarge,
                "Browser proxy connection exceeded its byte limit",
            ))
        }
        Ok(Err(_)) => Err(WebEgressError::new(
            WebEgressErrorKind::Connect,
            "Browser proxy tunnel failed",
        )),
        Err(_) => Err(WebEgressError::new(
            WebEgressErrorKind::Deadline,
            "Browser proxy connection exceeded its time limit",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, VecDeque};

    struct SequenceResolver {
        answers: Mutex<VecDeque<Vec<SocketAddr>>>,
    }

    #[async_trait]
    impl WebResolver for SequenceResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, String> {
            self.answers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
                .ok_or_else(|| "no fixture answer".to_string())
        }
    }

    fn run(grants: WebEgressGrants) -> Arc<ToolRunContext> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        ToolRunContext::builder(crate::state::SessionId::new(), root)
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .web_egress_grants(grants)
            .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
            .process(true)
            .network(true)
            .secrets(false)
            .provider("web-egress-test")
            .build()
            .expect("run")
    }

    fn addr(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip.parse().expect("IP"), port)
    }

    fn serve_one_response(
        listener: tokio::net::TcpListener,
        response: String,
    ) -> tokio::task::JoinHandle<Vec<u8>> {
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

            let (mut stream, _) = listener.accept().await.expect("fixture accept");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 2048];
            loop {
                let read = stream.read(&mut buffer).await.expect("fixture read");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(response.as_bytes())
                .await
                .expect("fixture response");
            stream.shutdown().await.expect("fixture shutdown");
            request
        })
    }

    #[test]
    fn exact_origin_rejects_credentials_and_non_origin_components() {
        assert!(WebOrigin::parse_exact("http://user:pass@127.0.0.1:8080").is_err());
        assert!(WebOrigin::parse_exact("http://127.0.0.1:8080/path").is_err());
        assert!(WebOrigin::parse_exact("file:///tmp/x").is_err());
        assert_eq!(
            WebOrigin::parse_exact("http://[::1]:8080")
                .expect("IPv6 origin")
                .redacted(),
            "http://[::1]:8080"
        );
    }

    #[tokio::test]
    async fn alternate_private_address_fails_the_entire_public_origin() {
        let resolver = Arc::new(SequenceResolver {
            answers: Mutex::new(VecDeque::from([vec![
                addr("8.8.8.8", 443),
                addr("127.0.0.1", 443),
            ]])),
        });
        let broker = WebEgressBroker::with_resolver(run(WebEgressGrants::public_only()), resolver)
            .expect("broker");
        let error = broker
            .admit_url("https://mixed.test/", WebEgressUse::WebContent, false)
            .await
            .expect_err("one private alternate must deny the complete address set");
        assert_eq!(error.kind, WebEgressErrorKind::PolicyDenied);
    }

    #[tokio::test]
    async fn operation_cache_pins_first_resolution_against_rebinding() {
        let resolver = Arc::new(SequenceResolver {
            answers: Mutex::new(VecDeque::from([
                vec![addr("8.8.8.8", 443)],
                vec![addr("127.0.0.1", 443)],
            ])),
        });
        let broker =
            WebEgressBroker::with_resolver(run(WebEgressGrants::public_only()), resolver.clone())
                .expect("broker");
        let first = broker
            .admit_url("https://rebind.test/", WebEgressUse::WebContent, false)
            .await
            .expect("first public resolution");
        let second = broker
            .admit_url("https://rebind.test/again", WebEgressUse::WebContent, false)
            .await
            .expect("cached resolution");
        assert_eq!(first.addresses, second.addresses);
        assert_eq!(
            resolver
                .answers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            1,
            "the dial set must stay pinned instead of consulting the rebound answer"
        );
    }

    #[tokio::test]
    async fn userinfo_and_ipv6_private_literal_fail_before_any_dial() {
        let broker = WebEgressBroker::new(run(WebEgressGrants::public_only())).expect("broker");
        assert_eq!(
            broker
                .admit_url(
                    "https://user:secret@example.com/",
                    WebEgressUse::WebContent,
                    false,
                )
                .await
                .expect_err("userinfo")
                .kind,
            WebEgressErrorKind::PolicyDenied
        );
        assert_eq!(
            broker
                .admit_url("http://[::1]/", WebEgressUse::WebContent, false)
                .await
                .expect_err("IPv6 loopback")
                .kind,
            WebEgressErrorKind::PolicyDenied
        );
    }

    #[tokio::test]
    async fn pinned_client_dials_only_the_granted_fixture_address() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("fixture bind");
        let port = listener.local_addr().expect("fixture address").port();
        let server = serve_one_response(
            listener,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: close\r\n\r\npinned"
                .to_string(),
        );
        let origin = format!("http://pinned.test:{port}");
        let grants = WebEgressGrants::from_exact_web_origins([&origin]).expect("grant");
        let resolver = Arc::new(SequenceResolver {
            answers: Mutex::new(VecDeque::from([vec![addr("127.0.0.1", port)]])),
        });
        let broker = WebEgressBroker::with_resolver(run(grants), resolver).expect("broker");
        let response = broker
            .get(
                &format!("{origin}/page?secret=hidden"),
                WebEgressBackend::DirectHttp,
                1024,
                Duration::from_secs(3),
            )
            .await
            .expect("pinned GET");
        assert_eq!(response.body, b"pinned");
        assert_eq!(response.receipt.origin, origin);
        assert_eq!(
            response.receipt.final_peer,
            Some(format!("127.0.0.1:{port}"))
        );
        let request = String::from_utf8(server.await.expect("fixture task")).expect("request text");
        assert!(request.starts_with("GET /page?secret=hidden HTTP/1.1"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains(&format!("host: pinned.test:{port}")),
            "TLS/HTTP hostname authority must remain the URL host: {request}"
        );
        let receipt_json = serde_json::to_string(&response.receipt).expect("receipt JSON");
        assert!(!receipt_json.contains("secret"));
        assert!(!receipt_json.contains("hidden"));
    }

    #[tokio::test]
    async fn broker_enforces_streaming_body_limit_on_the_actual_response() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("fixture bind");
        let port = listener.local_addr().expect("fixture address").port();
        let server = serve_one_response(
            listener,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n0123456789overflow"
                .to_string(),
        );
        let origin = format!("http://bounded.test:{port}");
        let grants = WebEgressGrants::from_exact_web_origins([&origin]).expect("grant");
        let resolver = Arc::new(SequenceResolver {
            answers: Mutex::new(VecDeque::from([vec![addr("127.0.0.1", port)]])),
        });
        let broker = WebEgressBroker::with_resolver(run(grants), resolver).expect("broker");
        let error = broker
            .get(
                &format!("{origin}/oversize"),
                WebEgressBackend::DirectHttp,
                10,
                Duration::from_secs(3),
            )
            .await
            .expect_err("body over the broker limit must fail");
        assert_eq!(error.kind, WebEgressErrorKind::ResponseTooLarge);
        assert_eq!(error.receipts.len(), 1);
        assert_eq!(error.receipts[0].byte_limit, 10);
        assert_eq!(
            error.receipts[0].final_peer,
            Some(format!("127.0.0.1:{port}"))
        );
        server.await.expect("fixture task");
    }

    #[tokio::test]
    async fn redirect_to_ungranted_private_origin_is_blocked_before_second_socket() {
        let first = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("first bind");
        let second = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("second bind");
        let first_port = first.local_addr().expect("first address").port();
        let second_port = second.local_addr().expect("second address").port();
        let target = format!("http://private.test:{second_port}/admin?token=hidden");
        let first_server = serve_one_response(
            first,
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
        );
        let first_origin = format!("http://start.test:{first_port}");
        let grants = WebEgressGrants::from_exact_web_origins([&first_origin]).expect("grant");
        let resolver = Arc::new(SequenceResolver {
            answers: Mutex::new(VecDeque::from([
                vec![addr("127.0.0.1", first_port)],
                vec![addr("127.0.0.1", second_port)],
            ])),
        });
        let broker = WebEgressBroker::with_resolver(run(grants), resolver).expect("broker");
        let error = broker
            .get(
                &format!("{first_origin}/start"),
                WebEgressBackend::DirectHttp,
                1024,
                Duration::from_secs(3),
            )
            .await
            .expect_err("private redirect must be denied");
        assert_eq!(error.kind, WebEgressErrorKind::PolicyDenied);
        assert_eq!(error.receipts.len(), 1);
        assert_eq!(
            error.receipts[0].redirect_chain,
            vec![format!("http://private.test:{second_port}")]
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), second.accept())
                .await
                .is_err(),
            "the denied redirect target must receive no TCP connection"
        );
        first_server.await.expect("first fixture");
        let receipt_json = serde_json::to_string(&error.receipts).expect("receipt JSON");
        assert!(!receipt_json.contains("admin"));
        assert!(!receipt_json.contains("token"));
    }

    #[tokio::test]
    async fn legitimate_exact_private_redirect_chain_remains_functional() {
        let first = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("first bind");
        let second = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("second bind");
        let first_port = first.local_addr().expect("first address").port();
        let second_port = second.local_addr().expect("second address").port();
        let first_origin = format!("http://first.test:{first_port}");
        let second_origin = format!("http://second.test:{second_port}");
        let first_server = serve_one_response(
            first,
            format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {second_origin}/final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
        );
        let second_server = serve_one_response(
            second,
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string(),
        );
        let grants = WebEgressGrants::from_exact_web_origins([&first_origin, &second_origin])
            .expect("grants");
        let resolver = Arc::new(SequenceResolver {
            answers: Mutex::new(VecDeque::from([
                vec![addr("127.0.0.1", first_port)],
                vec![addr("127.0.0.1", second_port)],
            ])),
        });
        let broker = WebEgressBroker::with_resolver(run(grants), resolver).expect("broker");
        let response = broker
            .get(
                &format!("{first_origin}/start"),
                WebEgressBackend::DirectHttp,
                1024,
                Duration::from_secs(3),
            )
            .await
            .expect("allowed redirect");
        assert_eq!(response.body, b"ok");
        assert_eq!(response.final_url, format!("{second_origin}/final"));
        assert_eq!(response.receipt.redirect_chain, vec![second_origin]);
        assert_eq!(
            response.receipt.final_peer,
            Some(format!("127.0.0.1:{second_port}"))
        );
        first_server.await.expect("first fixture");
        second_server.await.expect("second fixture");
    }

    #[tokio::test]
    async fn distillation_service_grant_does_not_widen_model_selected_web_access() {
        let origin = "http://127.0.0.1:12345";
        let grants = WebEgressGrants::public_only()
            .with_distillation_endpoint(origin)
            .expect("distillation grant");
        let broker = WebEgressBroker::new(run(grants)).expect("broker");
        assert!(
            broker
                .admit_url(origin, WebEgressUse::WebContent, false)
                .await
                .is_err(),
            "configured provider must not become a general fetch target"
        );
        broker
            .admit_url(origin, WebEgressUse::Distillation, false)
            .await
            .expect("distillation-only origin");
    }

    #[test]
    fn browser_static_policy_rejects_non_network_and_private_escape_schemes() {
        let broker = WebEgressBroker::new(run(WebEgressGrants::public_only())).expect("broker");
        assert!(broker
            .validate_browser_request("file:///etc/passwd")
            .is_err());
        assert!(broker
            .validate_browser_request("ftp://127.0.0.1/x")
            .is_err());
        assert!(broker
            .validate_browser_request("http://127.0.0.1/x")
            .is_err());
        assert!(broker
            .validate_browser_request("ws://[::1]/socket")
            .is_err());
        assert!(broker
            .validate_browser_request("data:text/plain,local")
            .is_ok());

        let grants =
            WebEgressGrants::from_exact_web_origins(["ws://[::1]:9000"]).expect("WebSocket grant");
        let broker = WebEgressBroker::new(run(grants)).expect("broker");
        assert!(
            broker
                .validate_browser_request("ws://[::1]:9000/socket")
                .is_ok(),
            "an exact WebSocket origin must remain usable"
        );
    }

    #[cfg(feature = "browser")]
    #[tokio::test]
    async fn browser_proxy_denies_private_absolute_request_before_origin_connect() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("origin bind");
        let port = origin.local_addr().expect("origin address").port();
        let resolver = Arc::new(SequenceResolver {
            answers: Mutex::new(VecDeque::from([vec![addr("127.0.0.1", port)]])),
        });
        let broker = WebEgressBroker::with_resolver(run(WebEgressGrants::public_only()), resolver)
            .expect("broker");
        let mut proxy = BrowserEgressProxy::start(broker).await.expect("proxy");
        let proxy_url = Url::parse(&proxy.url()).expect("proxy URL");
        let mut client = TcpStream::connect((
            proxy_url.host_str().expect("proxy host"),
            proxy_url.port().expect("proxy port"),
        ))
        .await
        .expect("proxy client");
        client
            .write_all(
                format!(
                    "GET http://private.test:{port}/secret HTTP/1.1\r\nHost: private.test:{port}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("proxy request");
        let mut response = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response)).await;
        assert!(
            response.is_empty(),
            "denied proxy request must not be forwarded"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), origin.accept())
                .await
                .is_err(),
            "private origin must receive no proxy TCP connection"
        );
        proxy.shutdown().await;
        assert_eq!(proxy.receipts()[0].backend, WebEgressBackend::BrowserProxy);
        assert!(proxy.receipts()[0].final_peer.is_none());
    }

    #[cfg(feature = "browser")]
    #[tokio::test]
    async fn browser_proxy_forwards_only_an_exact_private_origin() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let origin_listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("origin bind");
        let port = origin_listener.local_addr().expect("origin address").port();
        let server = serve_one_response(
            origin_listener,
            "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nbrokered".to_string(),
        );
        let exact_origin = format!("http://private.test:{port}");
        let grants = WebEgressGrants::from_exact_web_origins([&exact_origin]).expect("grant");
        let resolver = Arc::new(SequenceResolver {
            answers: Mutex::new(VecDeque::from([vec![addr("127.0.0.1", port)]])),
        });
        let broker = WebEgressBroker::with_resolver(run(grants), resolver).expect("broker");
        let mut proxy = BrowserEgressProxy::start(broker).await.expect("proxy");
        let proxy_url = Url::parse(&proxy.url()).expect("proxy URL");
        let mut client = TcpStream::connect((
            proxy_url.host_str().expect("proxy host"),
            proxy_url.port().expect("proxy port"),
        ))
        .await
        .expect("proxy client");
        client
            .write_all(
                format!(
                    "GET {exact_origin}/page HTTP/1.1\r\nHost: attacker.invalid\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("proxy request");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .expect("proxy response deadline")
            .expect("proxy response");
        assert!(String::from_utf8_lossy(&response).contains("brokered"));
        drop(client);
        let request = String::from_utf8(server.await.expect("origin task")).expect("request text");
        assert!(request.starts_with("GET /page HTTP/1.1"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains(&format!("host: private.test:{port}")),
            "proxy must replace a smuggled Host header: {request}"
        );
        proxy.shutdown().await;
        let receipts = proxy.receipts();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].origin, exact_origin);
        assert_eq!(receipts[0].final_peer, Some(format!("127.0.0.1:{port}")));
    }

    #[cfg(feature = "browser")]
    #[tokio::test]
    async fn browser_proxy_rejects_userinfo_before_dns_or_dial() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let resolver = Arc::new(SequenceResolver {
            answers: Mutex::new(VecDeque::from([vec![addr("8.8.8.8", 80)]])),
        });
        let broker =
            WebEgressBroker::with_resolver(run(WebEgressGrants::public_only()), resolver.clone())
                .expect("broker");
        let mut proxy = BrowserEgressProxy::start(broker).await.expect("proxy");
        let proxy_url = Url::parse(&proxy.url()).expect("proxy URL");
        let mut client = TcpStream::connect((
            proxy_url.host_str().expect("proxy host"),
            proxy_url.port().expect("proxy port"),
        ))
        .await
        .expect("proxy client");
        client
            .write_all(
                b"GET http://user:secret@public.test/private HTTP/1.1\r\nHost: public.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("proxy request");
        let mut response = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response)).await;
        proxy.shutdown().await;
        assert!(response.is_empty());
        assert!(proxy.receipts().is_empty());
        assert_eq!(
            resolver
                .answers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            1,
            "userinfo must be rejected before DNS resolution"
        );
    }

    #[cfg(feature = "browser")]
    #[tokio::test]
    async fn browser_proxy_connect_honors_an_exact_wss_origin_grant() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("origin bind");
        let port = origin.local_addr().expect("origin address").port();
        let origin_task = tokio::spawn(async move {
            let (_stream, _) = origin.accept().await.expect("origin accept");
        });
        let exact_origin = format!("wss://socket.test:{port}");
        let grants = WebEgressGrants::from_exact_web_origins([&exact_origin]).expect("grant");
        let resolver = Arc::new(SequenceResolver {
            answers: Mutex::new(VecDeque::from([vec![addr("127.0.0.1", port)]])),
        });
        let broker = WebEgressBroker::with_resolver(run(grants), resolver).expect("broker");
        let mut proxy = BrowserEgressProxy::start(broker).await.expect("proxy");
        let proxy_url = Url::parse(&proxy.url()).expect("proxy URL");
        let mut client = TcpStream::connect((
            proxy_url.host_str().expect("proxy host"),
            proxy_url.port().expect("proxy port"),
        ))
        .await
        .expect("proxy client");
        client
            .write_all(
                format!("CONNECT socket.test:{port} HTTP/1.1\r\nHost: socket.test:{port}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("CONNECT request");
        let mut response = [0_u8; 128];
        let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut response))
            .await
            .expect("CONNECT response deadline")
            .expect("CONNECT response");
        assert!(response[..read].starts_with(b"HTTP/1.1 200 Connection Established"));
        client.shutdown().await.expect("client shutdown");
        drop(client);
        origin_task.await.expect("origin task");
        proxy.shutdown().await;
        let receipts = proxy.receipts();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].origin, exact_origin);
        assert_eq!(receipts[0].final_peer, Some(format!("127.0.0.1:{port}")));
    }

    #[test]
    fn receipt_serialization_contains_only_redacted_origin() {
        let run = run(WebEgressGrants::public_only());
        let url = Url::parse("https://user:secret@example.com/private?token=abc").expect("URL");
        let origin = WebOrigin {
            scheme: url.scheme().to_string(),
            host: url.host_str().expect("host").to_string(),
            port: 443,
        };
        let receipt = NetworkReceipt::new(
            &origin,
            &run,
            WebEgressBackend::DirectHttp,
            1024,
            Duration::from_secs(3),
        );
        let serialized = serde_json::to_string(&receipt).expect("receipt JSON");
        assert!(serialized.contains("https://example.com"));
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("token"));
        assert!(!serialized.contains("private"));
    }
}
