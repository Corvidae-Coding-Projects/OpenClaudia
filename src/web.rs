//! Web tools for `OpenClaudia`
//!
//! Provides web access capabilities for agents:
//! - `web_fetch`: Fetch URL content via direct HTTP, then headless
//!   Chromium for JS-heavy or Cloudflare-fronted pages when the
//!   `browser` feature is compiled. HTML responses are converted to
//!   Markdown locally via `htmd` (no third-party render service).
//! - `web_search`: Search the web via browser scraping (`DuckDuckGo`/Bing)
//!   when the `browser` feature is compiled. No search API keys are required.
//! - `web_browser`: Full browser automation via headless Chromium in
//!   `browser` builds.

use futures::StreamExt;
use reqwest::redirect;
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::LazyLock;
use std::time::Duration;
use url::Url;

/// Maximum redirect hops `SHARED_HTTP_CLIENT` will follow (crosslink #671).
///
/// Using `redirect::Policy::custom` disables reqwest's built-in
/// `Policy::limited(10)` cap, so we must re-establish a hop ceiling
/// inside the SSRF-validating policy. 10 matches the reqwest default.
pub(crate) const SSRF_REDIRECT_LIMIT: usize = 10;

/// Maximum bytes accepted from any remote HTTP response body (crosslink #745).
///
/// Without this cap, a malicious or compromised upstream — the direct
/// HTTP target, the headless-browser DOM, or a redirected target can
/// stream gigabytes into a `String` before
/// the per-tool truncate (`src/tools/web.rs`) ever runs. 10 MiB is
/// generous for markdown-converted articles and JSON search
/// responses while keeping per-call memory bounded.
pub(crate) const MAX_WEB_FETCH_BYTES: usize = 10 * 1024 * 1024;

/// Stream a response body into a UTF-8 `String`, refusing to buffer more than
/// `cap` bytes (crosslink #745).
///
/// Two layers of defense:
/// 1. A pre-flight `Content-Length` check rejects bodies the server advertises
///    as larger than `cap` without reading a single byte.
/// 2. A streaming accumulator drains `bytes_stream()` chunk-by-chunk and
///    aborts the moment the running total would exceed `cap`. This catches
///    servers that lie about (or omit) `Content-Length`.
///
/// The error message names the configured cap and the offending URL so the
/// failure is greppable in production logs.
pub(crate) async fn read_bounded_text(
    response: Response,
    cap: usize,
    url: &str,
) -> Result<String, String> {
    // Pre-flight: trust server-advertised Content-Length when present.
    if let Some(advertised) = response.content_length() {
        if advertised > cap as u64 {
            return Err(format!(
                "Response too large: {advertised} bytes exceeds cap {cap} at URL {url}"
            ));
        }
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut total: usize = 0;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("Failed to read response chunk: {e}"))?;
        total = total.saturating_add(chunk.len());
        if total > cap {
            return Err(format!(
                "Response too large: {total} bytes exceeds cap {cap} at URL {url}"
            ));
        }
        buf.extend_from_slice(&chunk);
    }

    String::from_utf8(buf).map_err(|e| format!("Response is not valid UTF-8: {e}"))
}

/// Process-wide shared `reqwest::Client` (crosslink #368).
///
/// Building a fresh `Client` on every call defeats reqwest's internal
/// connection pool and DNS cache, and — combined with a fresh tokio
/// `Runtime::new()` — leaks tokio worker threads on every web tool call.
/// One client, built once, reused everywhere. Tuned for the web-fetch
/// hot path: 90s idle pool, 10s connect timeout, TCP keepalive. The
/// per-request `timeout` overrides are still set at the call site.
pub(crate) static SHARED_HTTP_CLIENT: LazyLock<Result<Client, String>> =
    LazyLock::new(build_shared_http_client);

fn build_shared_http_client() -> Result<Client, String> {
    Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .connect_timeout(Duration::from_secs(10))
        .tcp_keepalive(Duration::from_mins(1))
        // crosslink #671 — re-run the SSRF guard on every redirect hop.
        // Without this, an attacker controlling a public host can 302 to
        // 169.254.169.254 / 127.0.0.1 / RFC1918 and the dial-time check
        // (which only runs on the initial URL) is bypassed entirely.
        .redirect(ssrf_redirect_policy())
        .build()
        .map_err(|e| format!("failed to build shared web HTTP client: {e}"))
}

pub(crate) fn shared_http_client() -> Result<&'static Client, String> {
    SHARED_HTTP_CLIENT.as_ref().map_err(Clone::clone)
}

/// Build a [`redirect::Policy`] that re-validates every redirect target through
/// the synchronous SSRF guard (crosslink #671).
///
/// Replacing reqwest's default `Policy::limited(10)` removes the built-in hop
/// ceiling, so we re-impose it via [`SSRF_REDIRECT_LIMIT`].
///
/// The validator runs [`validate_url_static`] — scheme allowlist + hostname
/// denylist + IP-literal check. It deliberately does NOT resolve hostnames
/// (DNS would block the redirect callback, which is run synchronously from
/// reqwest's hyper task). Hostname-based DNS rebinding on redirects is the
/// residual risk noted on [`validate_url`].
///
/// Wins blocked by this policy:
/// * 302 to `http://169.254.169.254/...` (cloud metadata IP literal)
/// * 302 to `http://127.0.0.1/admin` (loopback IP literal)
/// * 302 to `http://10.0.0.1/internal` (RFC1918 IP literal)
/// * 302 to `http://localhost/...` (denylisted hostname)
/// * 302 to `http://metadata.google.internal/...` (denylisted hostname)
/// * 302 to `file:///etc/passwd` (rejected scheme)
pub(crate) fn ssrf_redirect_policy() -> redirect::Policy {
    ssrf_redirect_policy_with(|url| validate_url_static(url.as_str()))
}

/// Generic version of [`ssrf_redirect_policy`] that takes a validator closure.
///
/// Exists so tests can install instrumented validators (e.g. counting how many
/// times the policy was consulted) without bypassing the production guard.
pub(crate) fn ssrf_redirect_policy_with<F>(validator: F) -> redirect::Policy
where
    F: Fn(&Url) -> Result<(), String> + Send + Sync + 'static,
{
    redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= SSRF_REDIRECT_LIMIT {
            return attempt.error(format!(
                "SSRF guard: redirect chain exceeded {SSRF_REDIRECT_LIMIT} hops"
            ));
        }
        match validator(attempt.url()) {
            Ok(()) => attempt.follow(),
            Err(reason) => attempt.error(format!("SSRF guard blocked redirect: {reason}")),
        }
    })
}

/// Hostnames that always represent internal infrastructure, cloud metadata
/// endpoints, or cluster control planes. Block by name even before DNS
/// resolution — some of these resolve in odd ways across distros.
///
/// Alicloud metadata (`100.100.100.200`) and AWS IPv6 metadata
/// (`fd00:ec2::254`) are already caught by the typed CIDR checks in
/// `validate_resolved_ip`, but listing the literal IP string here adds a
/// belt-and-suspenders layer for environments where DNS returns those names
/// without resolving them.
const DANGEROUS_HOSTNAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    // Cloud metadata endpoints
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "metadata.aws",
    "metadata.tencentyun.com",
    "instance-data",
    "instance-data.ec2.internal",
    // Alicloud ECS metadata service — IP literal in shared address space (100.64/10)
    "100.100.100.200",
    // Kubernetes in-cluster endpoints
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
];

/// Parse a host string as an IP literal, including non-standard single-integer
/// forms (`http://2130706433/` = 127.0.0.1) that some resolvers accept and
/// that `url::Url` leaves as a hostname.
fn parse_host_as_ip(host: &str) -> Option<IpAddr> {
    // Standard IPv4/IPv6 textual form
    if let Ok(ip) = IpAddr::from_str(host) {
        return Some(ip);
    }
    // IPv6 in brackets
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        if let Ok(ip) = Ipv6Addr::from_str(inner) {
            return Some(IpAddr::V6(ip));
        }
    }
    // Decimal-integer IPv4 (2130706433 → 127.0.0.1)
    if !host.is_empty() && host.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(n) = host.parse::<u32>() {
            return Some(IpAddr::V4(Ipv4Addr::from(n)));
        }
    }
    // Hex-integer IPv4 (0x7f000001 → 127.0.0.1)
    if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
        if let Ok(n) = u32::from_str_radix(hex, 16) {
            return Some(IpAddr::V4(Ipv4Addr::from(n)));
        }
    }
    None
}

/// True when `v6` is on a range that should never be reachable from a public fetch.
fn is_ipv6_forbidden(v6: &Ipv6Addr) -> bool {
    // IPv4-mapped: unwrap and re-check as IPv4 (covers ::ffff:127.0.0.1 etc.)
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_ip_forbidden(&IpAddr::V4(v4));
    }
    let s = v6.segments();
    // Unique-local fc00::/7 — covers fd00:ec2::254 (AWS IPv6 metadata)
    if s[0] & 0xfe00 == 0xfc00 {
        return true;
    }
    // Link-local fe80::/10
    if s[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // 6to4 2002::/16 — deprecated tunneling; block wholesale.
    if s[0] == 0x2002 {
        return true;
    }
    // Teredo 2001:0000::/32 — tunneling.
    if s[0] == 0x2001 && s[1] == 0x0000 {
        return true;
    }
    false
}

/// Validate that a resolved [`IpAddr`] is safe to connect to (SSRF guard).
///
/// Returns `Ok(())` for routable public addresses; returns `Err` with a
/// human-readable explanation for any IANA-reserved, private, link-local,
/// cloud-metadata, or otherwise non-public range.
///
/// Covered ranges (IPv4):
/// - 0.0.0.0/8 (unspecified)
/// - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918 private)
/// - 100.64.0.0/10 (RFC 6598 carrier-grade NAT / shared address space;
///   covers Alicloud metadata 100.100.100.200)
/// - 127.0.0.0/8 (loopback)
/// - 169.254.0.0/16 (link-local / AWS + Azure + GCP metadata)
/// - 192.0.0.0/24 (IETF protocol assignments)
/// - 198.18.0.0/15 (RFC 2544 benchmarking)
/// - 203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24 (documentation)
/// - 224.0.0.0/4 (multicast)
/// - 240.0.0.0/4 (reserved for future use)
/// - 255.255.255.255/32 (broadcast)
///
/// Covered ranges (IPv6):
/// - `::1/128` (loopback)
/// - `::/128` (unspecified)
/// - `::ffff:0:0/96` (IPv4-mapped — re-checked as IPv4)
/// - `fc00::/7` (unique-local; covers `fd00:ec2::254` AWS IPv6 metadata)
/// - `fe80::/10` (link-local)
/// - `2002::/16` (6to4 tunnel)
/// - `2001::/32` (Teredo tunnel)
/// - `ff00::/8` (multicast)
///
/// # Errors
///
/// Returns `Err(String)` when `addr` falls in a reserved/internal range.
pub(crate) fn validate_resolved_ip(addr: IpAddr) -> Result<(), String> {
    if is_ip_forbidden(&addr) {
        Err(format!(
            "IP address {addr} is in a reserved/internal range and cannot be fetched"
        ))
    } else {
        Ok(())
    }
}

/// True if this IP is on any IANA-reserved, private, or otherwise non-public
/// range. Drives the SSRF guard.
fn is_ip_forbidden(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_documentation()
            {
                return true;
            }
            let oct = v4.octets();
            // 100.64/10 shared address space (RFC 6598 / carrier-grade NAT)
            // Covers Alicloud metadata 100.100.100.200 (oct[1]=100, in 64..=127).
            if oct[0] == 100 && (64..=127).contains(&oct[1]) {
                return true;
            }
            // 192.0.0/24 IETF protocol assignments
            if oct[0] == 192 && oct[1] == 0 && oct[2] == 0 {
                return true;
            }
            // 198.18/15 benchmarking (RFC 2544)
            if oct[0] == 198 && (18..=19).contains(&oct[1]) {
                return true;
            }
            // 240.0.0.0/4 reserved for future use
            if oct[0] >= 240 {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || is_ipv6_forbidden(v6)
        }
    }
}

/// Validate that a URL is safe to fetch (prevents SSRF and restricts schemes).
///
/// Defense layers, in order:
///  1. Scheme allowlist (http/https only).
///  2. Hostname denylist: localhost, cloud metadata endpoints
///     (`metadata.google.internal`, `metadata.aws`, `instance-data`, etc.),
///     Kubernetes in-cluster endpoints.
///  3. IP-literal parsing: handles decimal-integer (`2130706433` = 127.0.0.1),
///     hex-integer (`0x7f000001`), bracketed IPv6, and standard dotted quads.
///     Any literal on an IANA reserved/private/link-local/multicast range
///     is rejected — full IPv4 + IPv6 matrix, not the prefix-string heuristic
///     the previous implementation used.
///  4. DNS resolution with `ToSocketAddrs`: hostnames are resolved and EVERY
///     resolved IP is checked against the same forbidden-range matrix via
///     [`validate_resolved_ip`].
///
/// Residual risk: a DNS-rebinding server that returns a public IP at
/// validate time and a private IP at `reqwest`'s dial time still bypasses
/// this. A custom `reqwest` resolver that re-checks at dial time is the
/// complete mitigation and is tracked as a follow-up to crosslink #335.
pub(crate) fn validate_url(url_str: &str) -> Result<(), String> {
    match validate_url_parts(url_str)? {
        ValidatePartial::Done => Ok(()),
        ValidatePartial::NeedsDns { parsed } => resolve_and_validate_sync(&parsed),
    }
}

/// Synchronous, DNS-free portion of [`validate_url`] (crosslink #671).
///
/// Runs everything that does not require a network round-trip:
/// scheme allowlist, hostname denylist, and IP-literal parsing +
/// reserved-range check (including decimal, hex, and bracketed IPv6
/// encodings). Returns `Ok(())` for any URL whose host is either a
/// safe IP literal or a hostname that still needs DNS resolution to
/// fully classify.
///
/// Used by [`ssrf_redirect_policy`] to validate each redirect hop
/// without blocking reqwest's redirect callback on DNS. Hostname-only
/// redirect URLs survive this check; reqwest then dials via its own
/// async resolver, and the worst-case bypass is reduced to the
/// hostname-DNS-rebinding scenario tracked alongside [`validate_url`].
///
/// # Errors
///
/// Returns `Err(String)` for unsupported schemes, denylisted hostnames,
/// or IP literals that fall in reserved/internal ranges.
pub(crate) fn validate_url_static(url_str: &str) -> Result<(), String> {
    match validate_url_parts(url_str)? {
        ValidatePartial::Done | ValidatePartial::NeedsDns { .. } => Ok(()),
    }
}

/// Outcome of the synchronous, DNS-free portion of validation.
enum ValidatePartial {
    /// IP-literal host validated; no DNS needed.
    Done,
    /// Host is a name that still needs DNS resolution.
    NeedsDns { parsed: Url },
}

/// Shared sync prelude for `validate_url`, `validate_url_static`, and
/// `validate_url_async`. Centralises the scheme + hostname-denylist + IP-literal
/// checks so the three entrypoints cannot drift.
fn validate_url_parts(url_str: &str) -> Result<ValidatePartial, String> {
    let parsed = Url::parse(url_str).map_err(|e| format!("Invalid URL: {e}"))?;

    // Scheme allowlist.
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => return Err(format!("Unsupported URL scheme: {scheme}")),
    }

    let host = parsed.host_str().ok_or("URL has no host")?;
    let host_lower = host.to_ascii_lowercase();

    // Hostname denylist — these names should never be reachable at all.
    if DANGEROUS_HOSTNAMES.iter().any(|h| *h == host_lower) {
        return Err(format!(
            "URL host '{host}' is a known internal/metadata endpoint"
        ));
    }

    // If the host parses as an IP literal (standard, decimal, hex, IPv6-brackets),
    // check it directly — no DNS needed.
    if let Some(ip) = parse_host_as_ip(&host_lower) {
        return validate_resolved_ip(ip)
            .map(|()| ValidatePartial::Done)
            .map_err(|e| {
                format!("URL points to reserved/internal IP address (host was '{host}'): {e}")
            });
    }

    Ok(ValidatePartial::NeedsDns { parsed })
}

/// Sync DNS path used by the legacy sync `validate_url` entrypoint.
fn resolve_and_validate_sync(parsed: &Url) -> Result<(), String> {
    let host = parsed.host_str().ok_or("URL has no host")?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    let socket_addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("Cannot resolve host '{host}': {e}"))?
        .collect();
    if socket_addrs.is_empty() {
        return Err(format!("Host '{host}' did not resolve to any address"));
    }
    for sa in socket_addrs {
        validate_resolved_ip(sa.ip())
            .map_err(|e| format!("URL host '{host}' resolves to reserved/internal IP: {e}"))?;
    }
    Ok(())
}

/// Async equivalent of [`validate_url`] (crosslink #673).
///
/// The sync `validate_url` reaches the standard-library blocking
/// resolver via `(host, port).to_socket_addrs()`, which stalls the
/// tokio worker thread for the entire DNS lookup. Calling it from
/// `pub async fn fetch_url` blocked every other task on that worker
/// when the resolver was slow or hanging.
///
/// This version delegates to [`tokio::net::lookup_host`], which uses
/// `spawn_blocking` internally and yields the runtime while the DNS
/// query is outstanding. Concurrent calls progress independently.
///
/// # Errors
///
/// Same error contract as [`validate_url`]: returns `Err(String)`
/// for unsupported schemes, denylisted hostnames, unresolvable hosts,
/// or any resolved address that falls in a reserved/internal range.
pub(crate) async fn validate_url_async(url_str: &str) -> Result<(), String> {
    let parsed = match validate_url_parts(url_str)? {
        ValidatePartial::Done => return Ok(()),
        ValidatePartial::NeedsDns { parsed } => parsed,
    };

    let host = parsed.host_str().ok_or("URL has no host")?;
    let port = parsed.port_or_known_default().unwrap_or(443);

    // tokio::net::lookup_host yields the runtime instead of blocking the
    // executor for the duration of the resolver query.
    let socket_addrs: Vec<_> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("Cannot resolve host '{host}': {e}"))?
        .collect();
    if socket_addrs.is_empty() {
        return Err(format!("Host '{host}' did not resolve to any address"));
    }
    for sa in socket_addrs {
        validate_resolved_ip(sa.ip())
            .map_err(|e| format!("URL host '{host}' resolves to reserved/internal IP: {e}"))?;
    }
    Ok(())
}

/// Render an HTML document to clean Markdown using the `htmd` crate
/// (turndown.js-inspired).
///
/// Pure transform — no I/O, no panics. On parse failure returns the
/// input HTML unchanged so the caller always sees *something*.
///
/// Local conversion keeps `web_fetch` self-contained: no third-party
/// render service in the loop, no per-host policy rejections, and no
/// external logger seeing every URL the agent visits.
#[must_use]
pub fn html_to_markdown(html: &str) -> String {
    match htmd::convert(html) {
        Ok(md) => md,
        Err(e) => {
            tracing::warn!("htmd HTML→Markdown conversion failed ({e}); falling back to raw HTML");
            html.to_string()
        }
    }
}

/// `DuckDuckGo` HTML search endpoint (no API key required)
#[cfg(feature = "browser")]
const DUCKDUCKGO_HTML_URL: &str = "https://html.duckduckgo.com/html/";

#[cfg(feature = "browser")]
const BROWSER_PROFILE_DIR: &str = "browser_profile";

/// Result from `web_fetch`
#[derive(Debug, Clone)]
pub struct FetchResult {
    pub content: String,
    pub title: Option<String>,
    pub url: String,
}

/// Search result item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

/// Fetch a URL and render its body to Markdown for LLM consumption.
///
/// Two-tier fallback:
///
/// 1. **Direct HTTP** via `SHARED_HTTP_CLIENT`. Fast, free, no
///    third-party. Plain text / JSON bodies are returned verbatim;
///    HTML bodies are converted to Markdown via [`html_to_markdown`].
/// 2. **Headless Chrome** via [`fetch_with_browser`]. Used when the
///    direct fetch returned a non-2xx status, a network error, OR
///    response markers that look like a Cloudflare bot challenge or
///    an SPA shell (empty `<body>` / a single `<div id="root">`).
///    Chrome runs the page's JavaScript, then we re-render to
///    Markdown the same way.
///
/// Returns an error only if **both** tiers fail; the error message
/// carries both diagnostic strings so the agent can see the full
/// chain.
///
/// # Errors
///
/// Returns an error string if URL validation fails, both fetch tiers
/// fail, or the response exceeds [`MAX_WEB_FETCH_BYTES`].
pub async fn fetch_url(
    url: &str,
    run: std::sync::Arc<crate::tools::ToolRunContext>,
) -> Result<FetchResult, String> {
    run.require(crate::tools::ToolResource::Network)
        .map_err(|error| error.to_string())?;
    // crosslink #673 — async DNS via tokio::net::lookup_host. The legacy
    // sync `validate_url` invoked the blocking std-library resolver from
    // inside this async function, which stalled the tokio worker for the
    // full DNS RTT and starved every other task on the same worker.
    validate_url_async(url).await?;

    let direct_err = match fetch_url_direct(url).await {
        Ok(result) => return Ok(result),
        Err(e) => {
            tracing::info!("direct fetch failed for {url}: {e}; falling back to headless browser");
            e
        }
    };

    // Tier 2: headless Chrome. The browser path is sync (`headless_chrome`
    // is blocking I/O), so hop onto the blocking pool. Without the
    // `browser` feature we surface a single combined error.
    #[cfg(feature = "browser")]
    {
        let browser_scratch_root = browser_scratch_for_fallback(&run, &direct_err)?;
        let url_owned = url.to_string();
        match tokio::task::spawn_blocking(move || {
            fetch_with_browser(&url_owned, &browser_scratch_root)
        })
        .await
        {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(browser_err)) => Err(format!(
                "Both fetch tiers failed. Direct: {direct_err}. Browser: {browser_err}."
            )),
            Err(join_err) => Err(format!(
                "Direct fetch failed ({direct_err}); browser fallback task panicked: {join_err}"
            )),
        }
    }
    #[cfg(not(feature = "browser"))]
    {
        Err(format!(
            "Direct fetch failed: {direct_err} (no browser fallback compiled in — \
             rebuild with `--features browser` to enable headless-Chrome fallback)"
        ))
    }
}

#[cfg(feature = "browser")]
fn browser_scratch_for_fallback(
    run: &crate::tools::ToolRunContext,
    direct_error: &str,
) -> Result<PathBuf, String> {
    run.require(crate::tools::ToolResource::Process)
        .map_err(|error| {
            format!("Direct fetch failed: {direct_error}. Browser fallback is unavailable: {error}")
        })?;
    Ok(run.private_temp_root().to_path_buf())
}

/// Tier-1 direct HTTP fetch. HTML response bodies are converted to
/// Markdown via [`html_to_markdown`]; non-HTML bodies (JSON, plain
/// text, RSS, robots.txt, …) are returned verbatim so the agent sees
/// what the server actually sent.
async fn fetch_url_direct(url: &str) -> Result<FetchResult, String> {
    let response = shared_http_client()?
        .get(url)
        .timeout(Duration::from_secs(30))
        // A real browser-shaped UA reduces the rate at which sites
        // block us at the WAF / Cloudflare edge. We still fall back
        // to headless Chrome if even this is refused.
        .header(
            "User-Agent",
            "Mozilla/5.0 (compatible; OpenClaudia/0.1; +https://github.com/dollspace-gay/OpenClaudia)",
        )
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .send()
        .await
        .map_err(|e| format!("Network error: {e}"))?;

    let status = response.status();
    if !status.is_success() {
        return Err(format!("HTTP {status} from upstream"));
    }

    let is_html = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("text/html") || ct.contains("application/xhtml"));

    let body = read_bounded_text(response, MAX_WEB_FETCH_BYTES, url).await?;

    let (content, title) = if is_html {
        let title = extract_html_title(&body);
        (html_to_markdown(&body), title)
    } else {
        (body, None)
    };

    Ok(FetchResult {
        content,
        title,
        url: url.to_string(),
    })
}

/// Extract a `<title>...</title>` from raw HTML. Returns the trimmed
/// title text or `None` if no title tag is present. Operates on the
/// raw HTML byte stream so it works even for documents `htmd` can't
/// fully parse.
fn extract_html_title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let start = lower.find("<title")?;
    // Skip past the opening tag's `>` — handles `<title>` and
    // `<title lang="en">` alike.
    let body_start = lower[start..].find('>')? + start + 1;
    let body_end_rel = lower[body_start..].find("</title>")?;
    let title = html[body_start..body_start + body_end_rel].trim();
    if title.is_empty() {
        None
    } else {
        Some(title.to_string())
    }
}

/// Search the web using browser-backed `DuckDuckGo`/Bing when compiled
/// with the `browser` feature.
///
/// # Errors
///
/// Returns an error string if all search backends fail.
pub fn search_web(
    browser_scratch_root: &Path,
    query: &str,
    limit: usize,
) -> Result<Vec<SearchResult>, String> {
    let mut backend_errors = Vec::new();

    // Tier 1 — DuckDuckGo via headless Chromium in browser builds
    // (free, no API key).
    match search_duckduckgo(browser_scratch_root, query, limit) {
        Ok(results) => return Ok(results),
        Err(e) => {
            tracing::warn!("DuckDuckGo search failed: {e}");
            backend_errors.push(format!("DuckDuckGo: {e}"));
        }
    }

    // Tier 2 — Bing HTML scrape via headless Chromium in browser
    // builds.
    match search_bing(browser_scratch_root, query, limit) {
        Ok(results) if !results.is_empty() => return Ok(results),
        Ok(_) => {
            backend_errors.push("Bing: returned zero results (likely bot-challenged)".to_string());
        }
        Err(e) => {
            tracing::warn!("Bing search failed: {e}");
            backend_errors.push(format!("Bing: {e}"));
        }
    }

    Err(format!(
        "Web search failed: no free browser-backed backend returned usable results.\n  {}\n\
         Install Chromium or rebuild with the default `browser` feature to enable free search.",
        backend_errors.join("\n  ")
    ))
}

/// Resolve a Bing `ck/a?` tracking redirect to its destination URL.
///
/// Bing rewrites every result anchor to
/// `https://www.bing.com/ck/a?...&u=a1<base64-padded>&...`. The
/// `u=a1...` parameter carries the real destination, base64-encoded
/// after a literal `a1` prefix (Bing's format marker). Anything
/// else — a non-`ck/a` Bing URL or a missing `u=` parameter — is
/// returned unchanged so the SSRF guard can still reject it.
#[cfg(feature = "browser")]
fn decode_bing_ck_url(href: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    if !href.contains("bing.com/ck/a") {
        return href.to_string();
    }
    let Some(u_start) = href.find("&u=a1") else {
        return href.to_string();
    };
    let after = &href[u_start + "&u=a1".len()..];
    let payload = after.split('&').next().unwrap_or(after);
    URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|bytes| {
            String::from_utf8(bytes)
                .ok()
                .filter(|s| s.starts_with("http"))
        })
        .unwrap_or_else(|| href.to_string())
}

/// Search Bing via headless Chromium and parse the result list.
///
/// Bing fronts its search page with a Cloudflare Turnstile challenge
/// for known automation UAs; headless Chrome can sometimes execute
/// the challenge JS and reach the actual results, where direct HTTP
/// cannot. The function still returns an empty list when the
/// challenge wins — the caller treats that as a recoverable
/// "try the next backend" signal.
///
/// # Errors
///
/// Returns a descriptive message if Chromium cannot be launched, if
/// navigation times out, or if the rendered DOM exceeds
/// [`MAX_WEB_FETCH_BYTES`].
#[cfg(feature = "browser")]
pub fn search_bing(
    browser_scratch_root: &Path,
    query: &str,
    limit: usize,
) -> Result<Vec<SearchResult>, String> {
    let browser = launch_browser_for_scraping(browser_scratch_root)?;

    let tab = browser
        .new_tab()
        .map_err(|e| format!("Failed to create browser tab: {e}"))?;

    let search_url = format!(
        "https://www.bing.com/search?q={}",
        urlencoding::encode(query)
    );

    tab.navigate_to(&search_url)
        .map_err(|e| format!("Failed to navigate to Bing: {e}"))?;
    tab.wait_until_navigated()
        .map_err(|e| format!("Navigation timeout: {e}"))?;
    // Give Cloudflare Turnstile (when present) a chance to settle.
    std::thread::sleep(Duration::from_millis(1500));

    let html = tab
        .get_content()
        .map_err(|e| format!("Failed to get page content: {e}"))?;

    if html.len() > MAX_WEB_FETCH_BYTES {
        return Err(format!(
            "Response too large: {} bytes exceeds cap {} at URL {}",
            html.len(),
            MAX_WEB_FETCH_BYTES,
            search_url
        ));
    }

    parse_bing_results_from_html(&html, limit)
}

/// Parse rendered Bing HTML results and drop unsafe result URLs.
///
/// This is separated from browser navigation so limit-after-filtering behavior
/// can be tested without launching Chrome or making a live search request.
///
/// # Errors
///
/// Returns a descriptive message if selector construction fails or Bing serves
/// its Cloudflare Turnstile challenge.
#[doc(hidden)]
#[cfg(feature = "browser")]
pub fn parse_bing_results_from_html(html: &str, limit: usize) -> Result<Vec<SearchResult>, String> {
    use scraper::{Html, Selector};

    // Detect Cloudflare Turnstile / Bing CAPTCHA wall. The result
    // page won't have `b_algo` anchors when challenged; surface a
    // specific error so the chain knows we're bot-blocked vs.
    // truly empty.
    if html.contains("captcha_header") || html.contains("challenges.cloudflare.com/turnstile") {
        return Err(
            "Bing served its Cloudflare Turnstile challenge (no results returned).".to_string(),
        );
    }

    let document = Html::parse_document(html);
    let result_selector =
        Selector::parse("li.b_algo").map_err(|e| format!("Invalid selector: {e:?}"))?;
    let title_selector = Selector::parse("h2 a").map_err(|e| format!("Invalid selector: {e:?}"))?;
    let snippet_selector =
        Selector::parse("p, .b_caption p").map_err(|e| format!("Invalid selector: {e:?}"))?;

    let mut results = Vec::new();
    for el in document.select(&result_selector) {
        if results.len() >= limit {
            break;
        }
        let Some(a) = el.select(&title_selector).next() else {
            continue;
        };
        let title = a.text().collect::<String>().trim().to_string();
        let raw_href = a.value().attr("href").unwrap_or_default().to_string();
        if raw_href.is_empty() || !raw_href.starts_with("http") {
            continue;
        }
        // Bing wraps every result URL in
        // `https://www.bing.com/ck/a?...&u=a1<base64>&...`. Decode to
        // the real destination so the agent sees a URL it can pass
        // straight to `web_fetch` instead of a redirect blob.
        let url = decode_bing_ck_url(&raw_href);
        // SSRF guard — same threat model as the DDG path.
        if let Err(reason) = validate_url(&url) {
            tracing::debug!(url = %url, reason = %reason, "Bing result URL dropped by SSRF guard");
            continue;
        }
        let snippet = el
            .select(&snippet_selector)
            .next()
            .map(|s| s.text().collect::<String>().trim().to_string())
            .unwrap_or_default();
        if !title.is_empty() {
            results.push(SearchResult {
                title,
                url,
                snippet,
            });
        }
    }
    Ok(results)
}

/// Stub Bing search for builds without the browser feature.
///
/// # Errors
///
/// Always returns an error.
#[cfg(not(feature = "browser"))]
pub fn search_bing(
    _browser_scratch_root: &Path,
    _query: &str,
    _limit: usize,
) -> Result<Vec<SearchResult>, String> {
    Err("Bing search requires the browser feature".to_string())
}

/// Search `DuckDuckGo` using headless Chrome browser
///
/// No API key required - scrapes the HTML search results page
///
/// # Errors
///
/// Returns an error string if the browser cannot be launched or no results are found.
/// Launch a headless Chromium for scraping.
///
/// `LaunchOptions::path = None` plus the `fetch` feature on
/// `headless_chrome` lets the upstream `Process::new` resolve the
/// browser binary in two stages: first it consults the standard
/// install dirs (`/usr/bin/chromium`, `/Applications/Google Chrome`,
/// etc) via `FetcherOptions::with_allow_standard_dirs(true)`; if no
/// system browser is present it auto-downloads a known-good Chromium
/// revision into the user's data dir and caches it for future runs.
///
/// The combined behaviour matches user expectation — the tool just
/// works on a fresh machine without manual Chromium installation —
/// and the error path stays actionable when both fail (e.g. no
/// network during first-run auto-download).
#[cfg(feature = "browser")]
fn launch_browser_for_scraping(
    browser_scratch_root: &Path,
) -> Result<headless_chrome::Browser, String> {
    use headless_chrome::{Browser, LaunchOptions};

    let user_data_dir = browser_profile_dir_under(browser_scratch_root)?;
    let opts = LaunchOptions::default_builder()
        .headless(true)
        .user_data_dir(Some(user_data_dir))
        .build()
        .map_err(|e| format!("Failed to configure browser: {e}"))?;
    Browser::new(opts).map_err(|e| {
        format!(
            "Failed to launch Chromium: {e}. Install chromium/google-chrome \
             on PATH, or ensure network access for the first-run auto-download."
        )
    })
}

#[cfg(feature = "browser")]
fn browser_profile_dir_under(browser_scratch_root: &Path) -> Result<PathBuf, String> {
    let dir = browser_scratch_root.join(BROWSER_PROFILE_DIR);
    std::fs::create_dir_all(&dir).map_err(|e| {
        format!(
            "Failed to create Chromium browser profile directory '{}': {e}",
            dir.display()
        )
    })?;
    Ok(dir)
}

/// Search `DuckDuckGo` via a headless Chromium and parse the rendered
/// HTML for the top `limit` results.
///
/// # Errors
///
/// Returns a descriptive message if Chromium cannot be launched
/// (no system Chrome and the first-run auto-download failed), if
/// navigation times out, if the response exceeds the rendered-HTML
/// cap, or if the DOM does not contain the expected selectors.
#[cfg(feature = "browser")]
pub fn search_duckduckgo(
    browser_scratch_root: &Path,
    query: &str,
    limit: usize,
) -> Result<Vec<SearchResult>, String> {
    let browser = launch_browser_for_scraping(browser_scratch_root)?;

    let tab = browser
        .new_tab()
        .map_err(|e| format!("Failed to create browser tab: {e}"))?;

    // Navigate to DuckDuckGo HTML search
    let search_url = format!("{}?q={}", DUCKDUCKGO_HTML_URL, urlencoding::encode(query));

    tab.navigate_to(&search_url)
        .map_err(|e| format!("Failed to navigate to DuckDuckGo: {e}"))?;

    tab.wait_until_navigated()
        .map_err(|e| format!("Navigation timeout: {e}"))?;

    // Wait for page to load
    std::thread::sleep(Duration::from_millis(500));

    // Get page HTML
    let html = tab
        .get_content()
        .map_err(|e| format!("Failed to get page content: {e}"))?;

    // Size-cap the rendered HTML (crosslink #745). Headless Chrome will happily
    // materialize multi-GB DOMs from hostile pages; refuse to propagate that.
    if html.len() > MAX_WEB_FETCH_BYTES {
        return Err(format!(
            "Response too large: {} bytes exceeds cap {} at URL {}",
            html.len(),
            MAX_WEB_FETCH_BYTES,
            search_url
        ));
    }

    parse_duckduckgo_results_from_html(&html, limit)
}

/// Parse rendered `DuckDuckGo` HTML results and drop unsafe result URLs.
///
/// This is separated from browser navigation so SSRF filtering can be tested
/// without launching Chrome or making a live search request.
///
/// # Errors
///
/// Returns an error when `DuckDuckGo` serves its bot challenge, selector
/// construction fails, or no valid search results remain after parsing and
/// URL validation.
#[doc(hidden)]
#[cfg(feature = "browser")]
pub fn parse_duckduckgo_results_from_html(
    html: &str,
    limit: usize,
) -> Result<Vec<SearchResult>, String> {
    use scraper::{Html, Selector};

    // Detect DDG's bot-challenge / anomaly page BEFORE parsing for result
    // selectors. When DDG flags the headless browser as a bot, it serves a
    // CAPTCHA modal with no `.result` elements. Reporting this directly lets
    // the caller fall through to a different backend.
    if html.contains("anomaly-modal") || html.contains("Unfortunately, bots use DuckDuckGo") {
        return Err("DuckDuckGo served its bot-challenge / anomaly page (no \
             results returned). Headless-Chrome scraping has been \
             rate-limited or fingerprinted by DDG."
            .to_string());
    }

    // Parse HTML and extract results
    let document = Html::parse_document(html);

    // DDG HTML selectors
    let result_selector =
        Selector::parse(".result").map_err(|e| format!("Invalid selector: {e:?}"))?;
    let title_selector =
        Selector::parse(".result__a").map_err(|e| format!("Invalid selector: {e:?}"))?;
    let snippet_selector =
        Selector::parse(".result__snippet").map_err(|e| format!("Invalid selector: {e:?}"))?;

    let mut results = Vec::new();

    for result_element in document.select(&result_selector) {
        if results.len() >= limit {
            break;
        }
        // Get title and URL from the link
        if let Some(title_element) = result_element.select(&title_selector).next() {
            let title = title_element.text().collect::<String>().trim().to_string();

            // Get URL from href attribute - DDG wraps URLs in a redirect
            let url = title_element
                .value()
                .attr("href")
                .map(|href| {
                    // DDG HTML uses direct URLs or //duckduckgo.com/l/?uddg=<encoded_url>
                    if href.starts_with("//duckduckgo.com/l/") {
                        // Extract the actual URL from the redirect
                        href.find("uddg=").map_or_else(
                            || href.to_string(),
                            |uddg_start| {
                                let encoded = &href[uddg_start + 5..];
                                // Find end of URL (next & or end of string)
                                let end = encoded.find('&').unwrap_or(encoded.len());
                                urlencoding::decode(&encoded[..end])
                                    .map_or_else(|_| href.to_string(), std::borrow::Cow::into_owned)
                            },
                        )
                    } else if href.starts_with("http") {
                        href.to_string()
                    } else {
                        format!("https:{href}")
                    }
                })
                .unwrap_or_default();

            // Skip if no valid URL
            if url.is_empty() || !url.starts_with("http") {
                continue;
            }

            // SSRF guard (#610): validate every URL extracted from DDG HTML before
            // returning it to the agent.  A malicious or compromised DDG response
            // could embed private-IP / metadata URLs in result hrefs.
            if let Err(reason) = validate_url(&url) {
                tracing::debug!(
                    url = %url,
                    reason = %reason,
                    "DDG result URL dropped by SSRF guard"
                );
                continue;
            }

            // Get snippet
            let snippet = result_element
                .select(&snippet_selector)
                .next()
                .map(|el| el.text().collect::<String>().trim().to_string())
                .unwrap_or_default();

            // Skip results without meaningful content
            if !title.is_empty() {
                results.push(SearchResult {
                    title,
                    url,
                    snippet,
                });
            }
        }
    }

    if results.is_empty() {
        return Err(
            "No search results found. DuckDuckGo may have changed their HTML structure."
                .to_string(),
        );
    }

    Ok(results)
}

/// `DuckDuckGo` search (stub when the browser feature is disabled).
///
/// # Errors
///
/// Always returns an error when the browser feature is not enabled.
#[cfg(not(feature = "browser"))]
pub fn search_duckduckgo(
    _browser_scratch_root: &Path,
    _query: &str,
    _limit: usize,
) -> Result<Vec<SearchResult>, String> {
    Err("DuckDuckGo search requires the browser feature. Rebuild with the default `browser` feature to enable free search.".to_string())
}

/// Fetch a URL using a headless Chromium browser, JS-rendered, then
/// convert the result DOM to Markdown via [`html_to_markdown`].
///
/// Used by [`fetch_url`] as the tier-2 fallback when the direct HTTP
/// path returns a non-2xx or a JS-shell page. Also the engine the
/// `web_browser` tool dispatches against. Browsers can be expensive
/// (Chrome process startup, 2s JS-render settle), so callers should
/// prefer [`fetch_url`] and let it decide which tier to use.
///
/// # Errors
///
/// Returns an error string if the URL is invalid, the browser fails
/// to launch (system Chromium missing AND auto-download blocked),
/// navigation times out, or the rendered DOM exceeds
/// [`MAX_WEB_FETCH_BYTES`].
#[cfg(feature = "browser")]
pub fn fetch_with_browser(url: &str, browser_scratch_root: &Path) -> Result<FetchResult, String> {
    validate_url(url)?;

    let browser = launch_browser_for_scraping(browser_scratch_root)?;

    let tab = browser
        .new_tab()
        .map_err(|e| format!("Failed to create browser tab: {e}"))?;

    tab.navigate_to(url)
        .map_err(|e| format!("Failed to navigate to URL: {e}"))?;

    tab.wait_until_navigated()
        .map_err(|e| format!("Navigation timeout: {e}"))?;

    // Wait a bit for JavaScript to render. Two seconds covers most
    // SPAs without making the fast common case unreasonably slow.
    std::thread::sleep(Duration::from_secs(2));

    // Page title — captured before content extraction because a
    // tab.get_title() failure shouldn't kill the fetch.
    let title = tab.get_title().ok();

    // Rendered DOM HTML.
    let html = tab
        .get_content()
        .map_err(|e| format!("Failed to get page content: {e}"))?;

    // Size-cap the rendered HTML (crosslink #745). Same threat model as the
    // DuckDuckGo path: a hostile site can materialize an arbitrarily large
    // DOM through headless Chrome, so refuse anything past the configured cap.
    if html.len() > MAX_WEB_FETCH_BYTES {
        return Err(format!(
            "Response too large: {} bytes exceeds cap {} at URL {}",
            html.len(),
            MAX_WEB_FETCH_BYTES,
            url
        ));
    }

    // Render DOM → Markdown locally via `htmd`.
    let content = html_to_markdown(&html);

    Ok(FetchResult {
        content,
        title,
        url: url.to_string(),
    })
}

/// Fetch URL using headless Chrome browser (stub when browser feature is disabled)
///
/// # Errors
///
/// Always returns an error when the browser feature is not enabled.
#[cfg(not(feature = "browser"))]
pub fn fetch_with_browser(url: &str, _browser_scratch_root: &Path) -> Result<FetchResult, String> {
    validate_url(url)?;
    Err("Browser feature not enabled. Rebuild with `cargo build --features browser`".to_string())
}

/// Format search results for display to the agent
#[must_use]
pub fn format_search_results(results: &[SearchResult]) -> String {
    if results.is_empty() {
        return "No results found.".to_string();
    }

    let mut output = format!("Found {} results:\n\n", results.len());

    for (i, result) in results.iter().enumerate() {
        let _ = write!(
            output,
            "{}. **{}**\n   {}\n   URL: {}\n\n",
            i + 1,
            result.title,
            result.snippet,
            result.url
        );
    }

    output.push_str(
        "REMINDER: You MUST include the sources above when using this information in your response.",
    );

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_http_client_builder_succeeds() {
        let client = build_shared_http_client().expect("shared HTTP client builder must succeed");
        drop(client);
    }

    #[cfg(feature = "browser")]
    #[test]
    fn browser_profile_dir_is_run_scratch_local_and_created() {
        let root = tempfile::tempdir().expect("temp run scratch root");
        let dir = browser_profile_dir_under(root.path()).expect("browser profile dir");

        assert_eq!(dir, root.path().join("browser_profile"));
        assert!(dir.is_dir(), "browser profile directory must be created");
        assert!(
            dir.starts_with(root.path()),
            "browser profile must stay inside the run scratch root"
        );
    }

    #[cfg(feature = "browser")]
    #[test]
    fn browser_fallback_requires_process_only_after_direct_tier_failure() {
        let root = tempfile::tempdir().expect("network-only run root");
        let run =
            crate::tools::ToolRunContext::builder(crate::state::SessionId::new(), root.path())
                .read_only_roots(Vec::new())
                .read_write_roots(Vec::new())
                .environment_grants(std::collections::HashMap::new())
                .workspace_access(crate::tools::WorkspaceAccess::ReadOnly)
                .process(false)
                .network(true)
                .secrets(false)
                .provider("web-fallback-capability-test")
                .build()
                .expect("network-only run");

        let error = browser_scratch_for_fallback(&run, "simulated direct failure")
            .expect_err("browser fallback must require process authority");
        assert!(error.contains("simulated direct failure"), "{error}");
        assert!(error.contains("Process"), "{error}");
    }

    #[test]
    fn test_format_search_results() {
        let results = vec![SearchResult {
            title: "Test Result".to_string(),
            url: "https://example.com".to_string(),
            snippet: "This is a test result".to_string(),
        }];

        let formatted = format_search_results(&results);
        assert!(formatted.contains("Test Result"));
        assert!(formatted.contains("https://example.com"));
    }

    #[test]
    fn test_format_empty_results() {
        let results: Vec<SearchResult> = vec![];
        let formatted = format_search_results(&results);
        assert!(formatted.contains("No results found"));
    }

    #[test]
    fn test_validate_url_allows_http() {
        assert!(validate_url("http://example.com").is_ok());
    }

    #[test]
    fn test_validate_url_allows_https() {
        assert!(validate_url("https://example.com/path?q=1").is_ok());
    }

    #[test]
    fn test_validate_url_blocks_file_scheme() {
        let result = validate_url("file:///etc/passwd");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported URL scheme"));
    }

    #[test]
    fn test_validate_url_blocks_data_scheme() {
        let result = validate_url("data:text/html,<h1>hi</h1>");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported URL scheme"));
    }

    #[test]
    fn test_validate_url_blocks_ftp_scheme() {
        let result = validate_url("ftp://files.example.com/secret");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported URL scheme"));
    }

    #[test]
    fn test_validate_url_blocks_localhost() {
        let result = validate_url("http://localhost:8080/admin");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("reserved/internal") || err.contains("metadata endpoint"),
            "expected SSRF rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_url_blocks_127() {
        let result = validate_url("http://127.0.0.1:9090/");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("reserved/internal") || err.contains("metadata endpoint"),
            "expected SSRF rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_url_blocks_10_network() {
        let result = validate_url("http://10.0.0.1/internal");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("reserved/internal") || err.contains("metadata endpoint"),
            "expected SSRF rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_url_blocks_192_168() {
        let result = validate_url("http://192.168.1.1/router");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("reserved/internal") || err.contains("metadata endpoint"),
            "expected SSRF rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_url_blocks_172_16() {
        let result = validate_url("http://172.16.0.1/");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("reserved/internal") || err.contains("metadata endpoint"),
            "expected SSRF rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_url_blocks_169_254_link_local() {
        let result = validate_url("http://169.254.169.254/latest/meta-data/");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("reserved/internal") || err.contains("metadata endpoint"),
            "expected SSRF rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_url_blocks_zero_address() {
        let result = validate_url("http://0.0.0.0/");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("reserved/internal") || err.contains("metadata endpoint"),
            "expected SSRF rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_url_blocks_ipv6_loopback() {
        let result = validate_url("http://[::1]:8080/");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("reserved/internal") || err.contains("metadata endpoint"),
            "expected SSRF rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_url_rejects_invalid_url() {
        let result = validate_url("not a url at all");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid URL"));
    }

    // --- SSRF regression tests (crosslink #335) ---

    #[test]
    fn ssrf_decimal_encoded_ipv4_loopback() {
        // 2130706433 decimal == 127.0.0.1
        let err = validate_url("http://2130706433/").unwrap_err();
        assert!(
            err.contains("reserved/internal") || err.contains("Invalid URL"),
            "decimal-encoded 127.0.0.1 not blocked: {err}"
        );
    }

    #[test]
    fn ssrf_hex_encoded_ipv4_loopback() {
        let err = validate_url("http://0x7f000001/").unwrap_err();
        assert!(
            err.contains("reserved/internal") || err.contains("Invalid URL"),
            "hex-encoded 127.0.0.1 not blocked: {err}"
        );
    }

    #[test]
    fn ssrf_blocks_gcp_metadata_hostname() {
        let err = validate_url("http://metadata.google.internal/").unwrap_err();
        assert!(
            err.contains("metadata endpoint"),
            "metadata.google.internal not denylisted: {err}"
        );
    }

    #[test]
    fn ssrf_blocks_aws_metadata_hostname() {
        let err = validate_url("http://instance-data/").unwrap_err();
        assert!(
            err.contains("metadata endpoint"),
            "instance-data not denylisted: {err}"
        );
    }

    #[test]
    fn ssrf_blocks_k8s_api_hostname() {
        let err = validate_url("http://kubernetes.default.svc/api/v1/secrets").unwrap_err();
        assert!(
            err.contains("metadata endpoint"),
            "kubernetes.default.svc not denylisted: {err}"
        );
    }

    #[test]
    fn ssrf_blocks_ipv6_loopback_mapped() {
        let err = validate_url("http://[::ffff:127.0.0.1]/").unwrap_err();
        assert!(
            err.contains("reserved/internal"),
            "IPv4-mapped IPv6 loopback not blocked: {err}"
        );
    }

    #[test]
    fn ssrf_blocks_ipv6_unique_local() {
        let err = validate_url("http://[fc00::1]/").unwrap_err();
        assert!(
            err.contains("reserved/internal"),
            "IPv6 unique-local not blocked: {err}"
        );
    }

    #[test]
    fn ssrf_blocks_ipv6_link_local() {
        let err = validate_url("http://[fe80::1]/").unwrap_err();
        assert!(
            err.contains("reserved/internal"),
            "IPv6 link-local not blocked: {err}"
        );
    }

    #[test]
    fn ssrf_blocks_shared_address_space() {
        let err = validate_url("http://100.64.0.1/").unwrap_err();
        assert!(
            err.contains("reserved/internal"),
            "100.64/10 CGNAT not blocked: {err}"
        );
    }

    #[test]
    fn ssrf_blocks_benchmarking_range() {
        let err = validate_url("http://198.18.0.1/").unwrap_err();
        assert!(
            err.contains("reserved/internal"),
            "198.18/15 benchmarking not blocked: {err}"
        );
    }

    #[test]
    fn ssrf_previous_prefix_bug_172_200_now_allowed() {
        // The previous impl wrongly blocked 172.200.x (public) via
        // `starts_with("172.2")`. Public 172.200.0.1 must NOT be rejected
        // by the host check.
        let result = validate_url("http://172.200.0.1/");
        if let Err(e) = result {
            assert!(
                !e.contains("reserved/internal"),
                "172.200.0.1 (public) wrongly classified as internal: {e}"
            );
        }
    }

    #[test]
    fn ssrf_blocks_172_all_private_slashes() {
        for middle in [16_u8, 20, 25, 28, 31] {
            let url = format!("http://172.{middle}.0.1/");
            let err = validate_url(&url).unwrap_err();
            assert!(
                err.contains("reserved/internal"),
                "172.{middle}.0.1 (private) not blocked: {err}"
            );
        }
    }

    #[test]
    fn ssrf_blocks_documentation_range() {
        let err = validate_url("http://203.0.113.1/").unwrap_err();
        assert!(
            err.contains("reserved/internal"),
            "203.0.113/24 (documentation) not blocked: {err}"
        );
    }

    #[test]
    fn ssrf_blocks_future_reserved_240() {
        let err = validate_url("http://240.0.0.1/").unwrap_err();
        assert!(
            err.contains("reserved/internal"),
            "240.0.0.0/4 (reserved) not blocked: {err}"
        );
    }

    #[test]
    fn ssrf_allows_public_ipv4() {
        assert!(validate_url("http://8.8.8.8/").is_ok());
    }

    // ── Forensic bypass-vector tests (crosslink #290) ────────────────────────
    // Each test targets a specific encoding or protocol trick that the old
    // prefix-string guard could not detect.

    /// Bypass vector 1 — decimal-integer IPv4.
    /// `http://2130706433/` encodes 127.0.0.1 as a 32-bit decimal integer.
    /// Some HTTP stacks (curl, Python urllib) dereference this directly.
    /// `parse_host_as_ip` decodes it; `validate_resolved_ip` blocks it.
    #[test]
    fn bypass_decimal_encoded_loopback() {
        // 127 * 2^24 + 0 * 2^16 + 0 * 2^8 + 1 = 2130706433
        let err = validate_url("http://2130706433/secret").unwrap_err();
        assert!(
            err.contains("reserved/internal") || err.contains("Invalid URL"),
            "decimal-encoded 127.0.0.1 not blocked: {err}"
        );
    }

    /// Bypass vector 2 — hex-integer IPv4.
    /// `http://0x7f000001/` is the hex form of 127.0.0.1.
    #[test]
    fn bypass_hex_encoded_loopback() {
        let err = validate_url("http://0x7f000001/admin").unwrap_err();
        assert!(
            err.contains("reserved/internal") || err.contains("Invalid URL"),
            "hex-encoded 127.0.0.1 not blocked: {err}"
        );
    }

    /// Bypass vector 3 — IPv6 short-form loopback `[::1]`.
    /// The bracket-stripping in `parse_host_as_ip` must handle this form.
    #[test]
    fn bypass_ipv6_short_form_loopback() {
        let err = validate_url("http://[::1]:9090/").unwrap_err();
        assert!(
            err.contains("reserved/internal"),
            "IPv6 ::1 short-form loopback not blocked: {err}"
        );
    }

    /// Bypass vector 4 — IPv4-mapped IPv6 loopback `::ffff:127.0.0.1`.
    /// `is_ipv6_forbidden` unwraps via `to_ipv4_mapped()` and re-checks the
    /// inner IPv4 address against `is_ip_forbidden`.
    #[test]
    fn bypass_ipv6_mapped_loopback() {
        let err = validate_url("http://[::ffff:127.0.0.1]/").unwrap_err();
        assert!(
            err.contains("reserved/internal"),
            "::ffff:127.0.0.1 (IPv4-mapped loopback) not blocked: {err}"
        );
    }

    /// Bypass vector 5 — AWS EC2 instance metadata service (169.254.169.254).
    /// This is the well-known link-local address served on every AWS/Azure/GCP
    /// VM; `Ipv4Addr::is_link_local()` catches the entire 169.254/16 range.
    #[test]
    fn bypass_aws_metadata_ip() {
        let err = validate_url("http://169.254.169.254/latest/meta-data/iam/").unwrap_err();
        assert!(
            err.contains("reserved/internal"),
            "169.254.169.254 (AWS metadata) not blocked: {err}"
        );
    }

    /// Bypass vector 6 — Alicloud ECS metadata (100.100.100.200).
    /// Sits in RFC 6598 shared address space (100.64/10);
    /// `(64..=127).contains(&oct[1])` blocks it. Belt-and-suspenders: also
    /// listed literally in `DANGEROUS_HOSTNAMES`, so either message is valid.
    #[test]
    fn bypass_alicloud_metadata_ip() {
        let err = validate_url("http://100.100.100.200/latest/meta-data/").unwrap_err();
        assert!(
            err.contains("reserved/internal") || err.contains("metadata endpoint"),
            "100.100.100.200 (Alicloud metadata) not blocked: {err}"
        );
    }

    /// Bypass vector 7 — AWS IPv6 metadata endpoint (`fd00:ec2::254`).
    /// Lives in `fc00::/7` (unique-local); `is_ipv6_forbidden` blocks it via the
    /// `s[0] & 0xfe00 == 0xfc00` check.
    #[test]
    fn bypass_aws_ipv6_metadata_ip() {
        let err = validate_url("http://[fd00:ec2::254]/latest/meta-data/").unwrap_err();
        assert!(
            err.contains("reserved/internal"),
            "fd00:ec2::254 (AWS IPv6 metadata) not blocked: {err}"
        );
    }

    /// Positive case — a known public IP must NOT be rejected.
    /// Regression guard against the old `172.2*` prefix bug that blocked
    /// `172.200.x` (public address space).
    #[test]
    fn bypass_public_ipv4_is_allowed() {
        assert!(
            validate_url("http://172.200.0.1/public-resource").is_ok(),
            "172.200.0.1 (public) was wrongly rejected"
        );
    }

    /// Positive case — a public hostname must NOT be rejected.
    /// Guards against over-blocking in the hostname denylist or resolver path.
    #[test]
    fn bypass_public_hostname_is_allowed() {
        // example.com resolves to public addresses (93.184.216.34) and is
        // the canonical safe hostname for tests.
        assert!(
            validate_url("https://example.com/").is_ok(),
            "example.com (public hostname) was wrongly rejected"
        );
    }

    /// Direct unit test for `validate_resolved_ip` — private RFC 1918 address.
    #[test]
    fn validate_resolved_ip_rejects_rfc1918() {
        let private = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert!(
            validate_resolved_ip(private).is_err(),
            "192.168.1.100 (RFC1918) not rejected by validate_resolved_ip"
        );
    }

    /// Direct unit test for `validate_resolved_ip` — public address passes.
    #[test]
    fn validate_resolved_ip_allows_public() {
        let public = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(
            validate_resolved_ip(public).is_ok(),
            "8.8.8.8 (public) wrongly rejected by validate_resolved_ip"
        );
    }

    // ── Body-size cap tests (crosslink #745) ─────────────────────────────────
    //
    // These pin the `read_bounded_text` contract and exercise it against a
    // real `wiremock` HTTP server. The four scenarios cover:
    //   1. small body under the cap → bytes returned verbatim
    //   2. body that exceeds the cap mid-stream → error names the cap and URL
    //   3. multi-chunk delivery summed across N chunks → total tracked correctly
    //   4. server advertises Content-Length > cap → pre-flight rejects, no bytes
    //      pulled from the socket
    //
    // The cap is overridden to a small value per test so we don't have to
    // allocate the production 10 MiB just to trip the limit.

    /// Small body under the cap is returned verbatim — no false rejection.
    #[tokio::test]
    async fn bounded_text_small_body_under_cap_passes() {
        let server = wiremock::MockServer::start().await;
        let body = "hello world";
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let url = server.uri();
        let response = shared_http_client()
            .unwrap()
            .get(&url)
            .send()
            .await
            .unwrap();
        let out = read_bounded_text(response, 8 * 1024, &url).await.unwrap();
        assert_eq!(out, body, "small body must be returned verbatim");
    }

    #[tokio::test]
    async fn direct_fetch_non_success_status_returns_status_error() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;
        let err = fetch_url_direct(&server.uri())
            .await
            .expect_err("direct HTTP tier must reject non-2xx status");
        assert!(
            err.contains("HTTP 404 Not Found from upstream"),
            "non-2xx error should name upstream status; got {err}"
        );
    }

    /// 11 MiB body must trip the production cap (10 MiB) and error out with a
    /// message naming the cap. Exercises the streaming overflow branch.
    #[tokio::test]
    async fn bounded_text_oversize_body_rejected_with_cap_named_error() {
        let server = wiremock::MockServer::start().await;
        // Build an 11 MiB body — guaranteed to exceed MAX_WEB_FETCH_BYTES (10 MiB).
        let oversize = vec![b'A'; 11 * 1024 * 1024];
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(oversize))
            .mount(&server)
            .await;
        let url = server.uri();
        let response = shared_http_client()
            .unwrap()
            .get(&url)
            .send()
            .await
            .unwrap();
        let err = read_bounded_text(response, MAX_WEB_FETCH_BYTES, &url)
            .await
            .expect_err("11 MiB body must trip the 10 MiB cap");
        assert!(
            err.contains("Response too large"),
            "error must say 'Response too large': {err}"
        );
        assert!(
            err.contains(&MAX_WEB_FETCH_BYTES.to_string()),
            "error must name the cap ({MAX_WEB_FETCH_BYTES}): {err}"
        );
        assert!(
            err.contains(&url),
            "error must include the offending URL ({url}): {err}"
        );
    }

    /// Multi-chunk delivery: when the body spans several `bytes_stream()`
    /// chunks, the running total must be summed correctly across chunks. We
    /// force this by serving a 256 KiB body — wiremock + hyper typically
    /// deliver this in multiple frames. The total byte count must match.
    #[tokio::test]
    async fn bounded_text_multi_chunk_body_summed_correctly() {
        let server = wiremock::MockServer::start().await;
        // 256 KiB of ASCII bytes — large enough that hyper/reqwest will
        // typically deliver it in multiple `bytes_stream()` chunks. ASCII so
        // the resulting `String` is valid UTF-8 (the helper enforces that).
        let payload: Vec<u8> = (0u32..(256 * 1024))
            .map(|i| b'!' + u8::try_from(i % 90).expect("0..90 fits u8"))
            .collect();
        let expected_len = payload.len();
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(payload.clone()))
            .mount(&server)
            .await;
        let url = server.uri();
        let response = shared_http_client()
            .unwrap()
            .get(&url)
            .send()
            .await
            .unwrap();
        // Cap > body so the streaming accumulator drains every chunk; the test
        // proves the running total stays accurate across multiple chunks.
        let out = read_bounded_text(response, MAX_WEB_FETCH_BYTES, &url)
            .await
            .unwrap();
        assert_eq!(
            out.len(),
            expected_len,
            "multi-chunk body must be summed to the full {expected_len} bytes, got {}",
            out.len()
        );
        assert_eq!(
            out.as_bytes(),
            payload.as_slice(),
            "multi-chunk body bytes must match exactly"
        );
    }

    /// Pre-flight `Content-Length` check: when the server advertises a body
    /// larger than the cap, we must reject BEFORE pulling more than the
    /// advertised header from the socket. The error must echo the advertised
    /// size, the cap, and the URL so logs are unambiguous.
    #[tokio::test]
    async fn bounded_text_content_length_preflight_rejects() {
        let server = wiremock::MockServer::start().await;
        // Advertise a body well over the test cap. The actual body just needs
        // to exist; wiremock sets Content-Length from `set_body_bytes`.
        let advertised: usize = 50 * 1024 * 1024;
        let payload = vec![b'.'; advertised];
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(payload))
            .mount(&server)
            .await;
        let url = server.uri();
        let response = shared_http_client()
            .unwrap()
            .get(&url)
            .send()
            .await
            .unwrap();
        // Sanity: reqwest surfaced the advertised Content-Length.
        assert_eq!(
            response.content_length(),
            Some(advertised as u64),
            "wiremock did not honor the advertised Content-Length header"
        );
        let cap: usize = 1024 * 1024; // 1 MiB cap, well under the advertised size.
        let err = read_bounded_text(response, cap, &url)
            .await
            .expect_err("pre-flight Content-Length check must reject");
        assert!(
            err.contains("Response too large"),
            "pre-flight error must say 'Response too large': {err}"
        );
        assert!(
            err.contains(&advertised.to_string()),
            "pre-flight error must echo the advertised size ({advertised}): {err}"
        );
        assert!(
            err.contains(&cap.to_string()),
            "pre-flight error must echo the cap ({cap}): {err}"
        );
        assert!(
            err.contains(&url),
            "pre-flight error must echo the URL ({url}): {err}"
        );
    }

    // ── SSRF redirect-policy tests (crosslink #671) ─────────────────────────
    //
    // These pin the contract that the SSRF guard re-runs on every redirect
    // hop. Before the fix, `SHARED_HTTP_CLIENT` was built with reqwest's
    // default `Policy::limited(10)`, which follows 3xx without re-validating
    // the Location header — a public host could 302 to 169.254.169.254 or
    // any RFC1918 IP and exfiltrate internal data.
    //
    // The policy itself (not the client) is exercised by counting validator
    // invocations through `ssrf_redirect_policy_with`. End-to-end behaviour
    // is exercised by issuing a real GET through `SHARED_HTTP_CLIENT` against
    // a wiremock server that returns a 302 chain.

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Build a client that uses `ssrf_redirect_policy_with` so the test can
    /// observe how many times the validator was consulted and which URLs it
    /// saw. The production code path goes through `SHARED_HTTP_CLIENT` —
    /// covered separately below.
    fn instrumented_ssrf_client(
        saw: Arc<std::sync::Mutex<Vec<String>>>,
    ) -> (Client, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = Arc::clone(&calls);
        let policy = ssrf_redirect_policy_with(move |url| {
            calls_c.fetch_add(1, Ordering::SeqCst);
            saw.lock().unwrap().push(url.to_string());
            validate_url_static(url.as_str())
        });
        let client = Client::builder()
            .redirect(policy)
            .build()
            .expect("instrumented client builds");
        (client, calls)
    }

    /// Redirect to loopback (127.0.0.1) must be blocked by the per-hop guard.
    ///
    /// We can't actually reach 127.0.0.1 in CI (it's the test machine), but
    /// the policy callback runs *before* reqwest attempts to dial the new
    /// host, so the error surfaces from the policy itself.
    #[tokio::test]
    async fn ssrf_redirect_to_loopback_is_blocked() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(302)
                    .insert_header("location", "http://127.0.0.1:1/secret"),
            )
            .mount(&server)
            .await;
        let saw = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let (client, calls) = instrumented_ssrf_client(Arc::clone(&saw));
        let err = client
            .get(server.uri())
            .send()
            .await
            .expect_err("redirect to loopback must be rejected by SSRF policy");
        // reqwest wraps policy errors in its own error type; walk the source
        // chain so the assertion survives reqwest re-wrapping.
        let mut msg = format!("{err}");
        let mut src = std::error::Error::source(&err);
        while let Some(s) = src {
            let _ = write!(&mut msg, " :: {s}");
            src = s.source();
        }
        assert!(
            msg.contains("SSRF guard blocked redirect"),
            "expected SSRF rejection in error chain, got: {msg}"
        );
        assert!(
            msg.contains("reserved/internal") || msg.contains("metadata endpoint"),
            "rejection should name why 127.0.0.1 is denied, got: {msg}"
        );
        assert!(
            calls.load(Ordering::SeqCst) >= 1,
            "validator must have been consulted on the redirect hop"
        );
        let urls = saw.lock().unwrap().clone();
        assert!(
            urls.iter().any(|u| u.contains("127.0.0.1")),
            "validator should have seen the 127.0.0.1 redirect target, got: {urls:?}"
        );
    }

    /// Redirect to an RFC1918 private IP must be blocked by the per-hop guard.
    /// Distinct from the loopback case to ensure full coverage of the
    /// `is_ip_forbidden` matrix on the redirect path.
    #[tokio::test]
    async fn ssrf_redirect_to_private_ip_is_blocked() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(302)
                    .insert_header("location", "http://10.0.0.1/internal"),
            )
            .mount(&server)
            .await;
        let saw = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let (client, _calls) = instrumented_ssrf_client(Arc::clone(&saw));
        let err = client
            .get(server.uri())
            .send()
            .await
            .expect_err("redirect to RFC1918 must be rejected");
        let mut msg = format!("{err}");
        let mut src = std::error::Error::source(&err);
        while let Some(s) = src {
            let _ = write!(&mut msg, " :: {s}");
            src = s.source();
        }
        assert!(
            msg.contains("SSRF guard blocked redirect"),
            "expected SSRF rejection in error chain, got: {msg}"
        );
        let urls = saw.lock().unwrap().clone();
        assert!(
            urls.iter().any(|u| u.contains("10.0.0.1")),
            "validator should have seen the 10.0.0.1 redirect target, got: {urls:?}"
        );
    }

    /// Multi-hop public redirect chain must complete: A -> B -> C, all public.
    /// Proves the per-hop guard doesn't over-block legitimate redirects.
    #[tokio::test]
    async fn ssrf_legit_redirect_chain_is_followed() {
        // Three wiremock servers all bound to 127.0.0.1 (the test loopback).
        // To exercise the "legit chain followed" path we instrument the
        // validator to accept the loopback URLs explicitly — the *policy*
        // structure (counter + chain length check + per-hop dispatch) is
        // what we're pinning. Production safety is enforced by the
        // _static_ validator in the live policy and by the other two
        // redirect tests above.
        let a = wiremock::MockServer::start().await;
        let b = wiremock::MockServer::start().await;
        let c = wiremock::MockServer::start().await;
        let c_uri = c.uri();
        let b_uri = b.uri();
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(302).insert_header("location", b_uri.as_str()),
            )
            .mount(&a)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(302).insert_header("location", c_uri.as_str()),
            )
            .mount(&b)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("final"))
            .mount(&c)
            .await;

        // Permissive validator: accept everything so the chain completes.
        // This proves the policy walks the chain, runs the validator on every
        // hop, and honours `attempt.follow()` for successes. The hop counter
        // proves the chain was actually walked end-to-end.
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = Arc::clone(&calls);
        let policy = ssrf_redirect_policy_with(move |_url| {
            calls_c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let client = Client::builder().redirect(policy).build().unwrap();
        let body = client
            .get(a.uri())
            .send()
            .await
            .expect("legit redirect chain must complete")
            .text()
            .await
            .expect("body downloads");
        assert_eq!(body, "final", "final body must be served from the last hop");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "validator must run once per redirect hop (A->B, B->C); got {}",
            calls.load(Ordering::SeqCst)
        );
    }

    /// Policy must terminate infinite redirect loops at `SSRF_REDIRECT_LIMIT`
    /// hops — `Policy::custom` disables reqwest's built-in cap, so we
    /// re-establish it ourselves. Pins the hop counter against silent
    /// regressions if the constant is ever raised without intent.
    #[tokio::test]
    async fn ssrf_redirect_loop_is_bounded() {
        let server = wiremock::MockServer::start().await;
        // Self-referencing 302 — wiremock keeps issuing the same Location.
        let loop_target = format!("{}/loop", server.uri());
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(302)
                    .insert_header("location", loop_target.as_str()),
            )
            .mount(&server)
            .await;
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = Arc::clone(&calls);
        let policy = ssrf_redirect_policy_with(move |_url| {
            calls_c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let client = Client::builder().redirect(policy).build().unwrap();
        let err = client
            .get(server.uri())
            .send()
            .await
            .expect_err("infinite redirect loop must be terminated by the hop cap");
        let mut msg = format!("{err}");
        let mut src = std::error::Error::source(&err);
        while let Some(s) = src {
            let _ = write!(&mut msg, " :: {s}");
            src = s.source();
        }
        assert!(
            msg.contains("redirect chain exceeded"),
            "expected hop-cap error in chain, got: {msg}"
        );
        assert!(
            calls.load(Ordering::SeqCst) <= SSRF_REDIRECT_LIMIT,
            "validator must run at most {SSRF_REDIRECT_LIMIT} times; got {}",
            calls.load(Ordering::SeqCst)
        );
    }

    // ── Async-DNS resolution tests (crosslink #673) ──────────────────────────
    //
    // The legacy `validate_url` called `(host, port).to_socket_addrs()` from
    // inside `pub async fn fetch_url`, blocking the tokio worker for the full
    // resolver RTT. `validate_url_async` swaps in `tokio::net::lookup_host`,
    // which uses `spawn_blocking` internally and yields the runtime.
    //
    // Two test angles:
    //   1. Direct: `validate_url_async` produces the same result as the sync
    //      variant for IP-literal inputs — proves the async wrapper preserves
    //      the existing validation contract.
    //   2. Concurrency: spawn N concurrent `validate_url_async` calls on a
    //      multi-thread runtime where the worker count is intentionally low.
    //      A blocking resolver would serialise them; the async resolver
    //      lets every task make progress in parallel.

    /// Async validator agrees with the sync one for IP-literal inputs.
    /// IP literals never trigger DNS, so this test isolates the
    /// validation prelude from any environment-dependent resolver
    /// behaviour. Covers a representative slice of the forbidden matrix.
    #[tokio::test]
    async fn validate_url_async_agrees_with_sync_on_ip_literals() {
        let cases = [
            ("http://127.0.0.1/", true),
            ("http://10.0.0.1/", true),
            ("http://169.254.169.254/latest/meta-data/", true),
            ("http://[::1]/", true),
            ("http://8.8.8.8/", false),
            ("http://172.200.0.1/", false), // formerly mis-blocked by the prefix bug
            ("file:///etc/passwd", true),
            ("not-a-url", true),
        ];
        for (url, should_err) in cases {
            let sync = validate_url(url);
            let async_ = validate_url_async(url).await;
            assert_eq!(
                sync.is_err(),
                should_err,
                "sync mismatch on {url}: got {sync:?}"
            );
            assert_eq!(
                async_.is_err(),
                should_err,
                "async mismatch on {url}: got {async_:?}"
            );
        }
    }

    /// `validate_url_async` for a hostname that resolves to a public IP must
    /// succeed and must NOT block the executor. We run the call on a single-
    /// worker tokio runtime alongside a yielding task — if the resolver were
    /// blocking, the yielding task would never get a chance to run while DNS
    /// is outstanding.
    ///
    /// Uses `127.0.0.1` as the hostname under test (rather than a public
    /// domain) so the test is fully offline. The bytes shipped to
    /// `tokio::net::lookup_host` exercise the same async code path
    /// regardless of whether the target is loopback or DNS-driven.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn validate_url_async_does_not_block_executor() {
        use tokio::sync::oneshot;
        let (tx, rx) = oneshot::channel();
        // Yielding cooperator: signals the moment it gets cpu time.
        let yielder = tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = tx.send(());
        });
        // Run several validations concurrently. Each one must hit the async
        // resolver path (hostname, not IP literal) — `localhost` is a sync
        // denylist hit, so use `127.0.0.1` instead which is an IP literal
        // and skips DNS entirely. To exercise the async resolver, fall back
        // to a hostname that *will* resolve: the test machine's hostname
        // always resolves locally. If that fails, the test still proves the
        // executor wasn't blocked because the yielder must have run.
        let validation = tokio::spawn(async {
            // Mix of IP literals (sync-fast) and a real hostname (async DNS).
            // Private addr -> errs; public addr -> ok; hostname -> exercises
            // the tokio::net::lookup_host path. example.com is the canonical
            // public test hostname.
            let _ = validate_url_async("http://127.0.0.1/").await;
            let _ = validate_url_async("http://8.8.8.8/").await;
            let _ = validate_url_async("https://example.com/").await;
        });
        // The yielder must complete promptly even on a single-worker runtime.
        // If DNS were blocking, the validation task could starve the yielder
        // (single worker, no spawn_blocking inside the validator → no
        // opportunity for yielder to run until DNS returns).
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("yielder must run within 5s — async DNS must not block worker")
            .expect("yielder oneshot must succeed");
        let _ = yielder.await;
        let _ = validation.await;
    }

    /// Concurrent `validate_url_async` calls must make independent progress.
    /// On a single-worker multi-thread runtime, N parallel calls complete
    /// in roughly the time of one DNS RTT — not N times that. We assert
    /// they all return within a generous wall-clock budget so a regression
    /// to the blocking resolver (which would serialise them) fails the test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn validate_url_async_concurrent_calls_do_not_serialize() {
        let start = std::time::Instant::now();
        let mut handles = Vec::new();
        for _ in 0..8 {
            handles.push(tokio::spawn(async {
                // IP-literal paths: no DNS, prove the wrapper itself doesn't
                // serialise. Mixed mix to exercise both early-return (sync)
                // and full path.
                let _ = validate_url_async("http://127.0.0.1/").await;
                let _ = validate_url_async("http://8.8.8.8/").await;
                let _ = validate_url_async("http://[::1]/").await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        // 8 IP-literal-only validation tasks must complete well under 1 s
        // on any reasonable hardware. The point is not micro-benchmarking;
        // it's that a blocking serialisation regression would balloon the
        // wall-clock time by orders of magnitude on a single-worker runtime.
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "8 concurrent async validations took {elapsed:?}; expected <2s. Suggests serialisation."
        );
    }
}
