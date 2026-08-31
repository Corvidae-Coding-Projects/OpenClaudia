//! Canonical outbound HTTP policy for provider and provider-auth traffic.
//!
//! Provider adapters still own wire formats and authentication headers. This
//! module owns the transport invariants that must not drift between frontends:
//! TLS, redirect behavior, connection reuse, deadlines, bounded reads, retry
//! admission, and safe diagnostics.

use bytes::Bytes;
use futures::{Stream, StreamExt as _};
use reqwest::{Client, ClientBuilder, RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::secrets::{SafeDiagnostic, SensitiveHeaders};

/// Maximum time allowed to establish the TCP/TLS connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum idle gap while reading provider response bytes.
pub const READ_TIMEOUT: Duration = Duration::from_secs(300);
/// Absolute reqwest deadline for one request, including its response body.
pub const REQUEST_TOTAL_TIMEOUT: Duration = Duration::from_secs(600);
/// Time-to-headers budget for one provider attempt.
pub const RESPONSE_HEADER_TIMEOUT: Duration = Duration::from_secs(120);
/// Absolute ceiling for a buffered provider JSON response.
pub const MAX_JSON_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// Absolute ceiling for provider stream payload data in one turn.
pub const MAX_STREAM_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
/// Total attempts for a retry-admitted request, including the first attempt.
///
/// The historical model-call contract allows ten retries. The monotonic retry
/// window below is the hard wall-clock bound, so this cap preserves short
/// `Retry-After: 0` recovery without permitting unbounded exponential waits.
pub const MAX_PROVIDER_ATTEMPTS: u32 = 11;
/// One monotonic budget shared by all attempts and backoff sleeps.
pub const RETRY_WINDOW: Duration = Duration::from_secs(60);
/// Upstream `Retry-After` and local backoff cannot exceed this delay.
pub const MAX_RETRY_DELAY: Duration = Duration::from_secs(15);

/// Source used by reqwest to resolve outbound provider proxies.
///
/// This preserves the application's established `HTTP_PROXY`/`HTTPS_PROXY`/
/// `NO_PROXY` behavior while making the provenance explicit. Proxy URLs and
/// credentials are deliberately never included in diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderProxyProvenance {
    ReqwestSystemEnvironment,
}

/// Report the canonical provider proxy policy without exposing proxy values.
#[must_use]
pub const fn proxy_provenance() -> ProviderProxyProvenance {
    ProviderProxyProvenance::ReqwestSystemEnvironment
}

/// Typed provider transport failure with bounded, sanitized diagnostics.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProviderTransportError {
    #[error("provider HTTP client could not be built: {0}")]
    ClientBuild(SafeDiagnostic),
    #[error("provider endpoint rejected: {0}")]
    InvalidEndpoint(SafeDiagnostic),
    #[error("provider request failed: {diagnostic}")]
    Request {
        diagnostic: SafeDiagnostic,
        connect_failure: bool,
        timeout: bool,
    },
    #[error("provider request exceeded its {phase} deadline")]
    Deadline { phase: &'static str },
    #[error("provider response exceeded {limit}-byte limit")]
    ResponseTooLarge { limit: usize },
    #[error("provider response body failed: {0}")]
    Body(SafeDiagnostic),
    #[error("provider response JSON was invalid: {0}")]
    InvalidJson(SafeDiagnostic),
}

/// Whether replaying a request is known to be safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestReplaySafety {
    /// GET-like operations that do not mutate provider state.
    Idempotent,
    /// Model calls may retry only explicit pre-admission failures.
    AdmissionOnly,
    /// Token exchanges and other one-shot mutations are never replayed.
    Never,
}

impl ProviderTransportError {
    /// Whether this failure occurred early enough to replay under `safety`.
    #[must_use]
    pub const fn retryable(&self, safety: RequestReplaySafety) -> bool {
        let Self::Request {
            connect_failure,
            timeout,
            ..
        } = self
        else {
            return false;
        };
        match safety {
            RequestReplaySafety::Never => false,
            RequestReplaySafety::AdmissionOnly => *connect_failure,
            RequestReplaySafety::Idempotent => *connect_failure || *timeout,
        }
    }
}

/// Bounded aggregate accounting for provider response bytes.
#[derive(Debug, Clone)]
pub struct StreamByteBudget {
    consumed: usize,
    limit: usize,
}

impl StreamByteBudget {
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self { consumed: 0, limit }
    }

    /// Charge provider bytes before retaining, framing, or projecting them.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderTransportError::ResponseTooLarge`] before the limit
    /// can be exceeded.
    pub fn consume(&mut self, bytes: usize) -> Result<(), ProviderTransportError> {
        self.consumed = self
            .consumed
            .checked_add(bytes)
            .filter(|total| *total <= self.limit)
            .ok_or(ProviderTransportError::ResponseTooLarge { limit: self.limit })?;
        Ok(())
    }

    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }
}

fn canonical_client_builder() -> ClientBuilder {
    Client::builder()
        .use_rustls_tls()
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        // Provider credentials must never be replayed to a redirect target.
        // A changed provider endpoint must be explicit configuration.
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .timeout(REQUEST_TOTAL_TIMEOUT)
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(8)
        .tcp_keepalive(Duration::from_secs(60))
}

fn build_client_from(builder: ClientBuilder) -> Result<Client, ProviderTransportError> {
    tracing::debug!(
        tls_backend = "rustls",
        minimum_tls = "1.2",
        proxy_provenance = ?proxy_provenance(),
        redirects = "disabled",
        "building canonical provider HTTP client"
    );
    builder.build().map_err(|error| {
        ProviderTransportError::ClientBuild(SafeDiagnostic::from_untrusted(&error.to_string()))
    })
}

static SHARED_PROVIDER_CLIENT: OnceLock<Result<Client, ProviderTransportError>> = OnceLock::new();

/// Clone the process-wide provider client.
///
/// `reqwest::Client` clones share their pool, so CLI, TUI, ACP, proxy,
/// subagents, and model discovery reuse connections without sharing mutable
/// request state.
///
/// # Errors
///
/// Returns a sanitized client-build error if TLS initialization fails.
pub fn shared_client() -> Result<Client, ProviderTransportError> {
    SHARED_PROVIDER_CLIENT
        .get_or_init(|| build_client_from(canonical_client_builder()))
        .clone()
}

/// Clone the canonical client for compatibility constructors that cannot
/// return an initialization error.
///
/// # Panics
///
/// Panics only when the statically configured Rustls client cannot initialize.
/// This matches `reqwest::Client::new()`'s existing fail-fast contract while
/// retaining the hardened policy instead of silently falling back to defaults.
#[must_use]
pub fn shared_client_required() -> Client {
    match shared_client() {
        Ok(client) => client,
        Err(error) => panic!("{error}"),
    }
}

/// Build a policy-identical client with a required application user agent.
///
/// OAuth endpoints require a specific user agent, so they cannot use the
/// otherwise shared client without weakening that protocol requirement.
///
/// # Errors
///
/// Returns a sanitized client-build error.
pub fn client_with_user_agent(user_agent: &'static str) -> Result<Client, ProviderTransportError> {
    build_client_from(canonical_client_builder().user_agent(user_agent))
}

/// Build a direct, redirect-disabled client pinned to addresses validated by
/// the caller for one exact destination hostname.
///
/// System proxies are deliberately disabled: routing a named action through
/// an ambient proxy would bypass the caller's DNS/IP admission and make the
/// actual destination unverifiable.
pub(crate) fn direct_client_with_pinned_resolution(
    host: &str,
    addresses: &[SocketAddr],
) -> Result<Client, ProviderTransportError> {
    if host.is_empty() || addresses.is_empty() {
        return Err(ProviderTransportError::InvalidEndpoint(
            SafeDiagnostic::from("pinned destination requires a host and at least one address"),
        ));
    }
    build_client_from(
        canonical_client_builder()
            .no_proxy()
            .resolve_to_addrs(host, addresses),
    )
}

/// Validate a fully resolved endpoint at the transport boundary.
///
/// # Errors
///
/// Rejects malformed, non-HTTP, metadata, reserved, or private destinations;
/// explicitly local providers retain their loopback/LAN exception.
pub fn validate_endpoint(
    provider_name: &str,
    endpoint: &str,
) -> Result<(), ProviderTransportError> {
    crate::config::validate_provider_base_url(provider_name, endpoint).map_err(|error| {
        ProviderTransportError::InvalidEndpoint(SafeDiagnostic::from_untrusted(&error))
    })
}

/// Send one request with a bounded time-to-headers deadline.
///
/// Dropping or aborting this future cancels the underlying reqwest future. The
/// explicit deadline makes the same behavior deterministic when a frontend
/// does not supply its own cancellation signal.
///
/// # Errors
///
/// Returns a sanitized request error or a typed deadline failure.
pub async fn send(request: RequestBuilder) -> Result<Response, ProviderTransportError> {
    send_until(request, Instant::now() + RESPONSE_HEADER_TIMEOUT).await
}

/// Send one request under a caller-owned monotonic deadline.
///
/// # Errors
///
/// Returns a sanitized request error or a typed deadline failure.
pub async fn send_until(
    request: RequestBuilder,
    deadline: Instant,
) -> Result<Response, ProviderTransportError> {
    tokio::time::timeout_at(deadline, request.send())
        .await
        .map_err(|_| ProviderTransportError::Deadline {
            phase: "response-header",
        })?
        .map_err(|error| ProviderTransportError::Request {
            diagnostic: SafeDiagnostic::from_untrusted(&error.to_string()),
            connect_failure: error.is_connect(),
            timeout: error.is_timeout(),
        })
}

/// Read a provider body without exceeding `max_bytes`.
///
/// # Errors
///
/// Returns a typed over-limit or sanitized body-read error.
pub async fn read_body_capped(
    response: Response,
    max_bytes: usize,
) -> Result<Vec<u8>, ProviderTransportError> {
    if content_length_exceeds(&response, max_bytes) {
        return Err(ProviderTransportError::ResponseTooLarge { limit: max_bytes });
    }

    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            ProviderTransportError::Body(SafeDiagnostic::from_untrusted(&error.to_string()))
        })?;
        let next_len = bytes
            .len()
            .checked_add(chunk.len())
            .filter(|length| *length <= max_bytes)
            .ok_or(ProviderTransportError::ResponseTooLarge { limit: max_bytes })?;
        bytes.reserve(next_len.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Stream provider response bytes under one aggregate cap.
///
/// The limit is enforced on raw chunks before an SSE or JSON-lines parser can
/// retain an unterminated frame in its own buffer.
pub fn bounded_byte_stream(
    response: Response,
    max_bytes: usize,
) -> impl Stream<Item = Result<Bytes, ProviderTransportError>> {
    let mut budget = StreamByteBudget::new(max_bytes);
    response.bytes_stream().map(move |chunk| {
        let chunk = chunk.map_err(|error| {
            ProviderTransportError::Body(SafeDiagnostic::from_untrusted(&error.to_string()))
        })?;
        budget.consume(chunk.len())?;
        Ok(chunk)
    })
}

/// Read and decode a bounded provider JSON body.
///
/// # Errors
///
/// Returns body-limit/read errors or a sanitized JSON parse error.
pub async fn read_json_capped<T: DeserializeOwned>(
    response: Response,
    max_bytes: usize,
) -> Result<T, ProviderTransportError> {
    let body = read_body_capped(response, max_bytes).await?;
    serde_json::from_slice(&body).map_err(|error| {
        ProviderTransportError::InvalidJson(SafeDiagnostic::from_untrusted(&error.to_string()))
    })
}

/// Read and decode a bounded credential-bearing JSON body, zeroizing retained
/// response bytes when parsing completes.
///
/// # Errors
///
/// Returns body-limit/read errors or a sanitized JSON parse error.
pub async fn read_sensitive_json_capped<T: DeserializeOwned>(
    response: Response,
    max_bytes: usize,
) -> Result<T, ProviderTransportError> {
    if content_length_exceeds(&response, max_bytes) {
        return Err(ProviderTransportError::ResponseTooLarge { limit: max_bytes });
    }

    let mut stream = response.bytes_stream();
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            ProviderTransportError::Body(SafeDiagnostic::from_untrusted(&error.to_string()))
        })?;
        bytes
            .len()
            .checked_add(chunk.len())
            .filter(|length| *length <= max_bytes)
            .ok_or(ProviderTransportError::ResponseTooLarge { limit: max_bytes })?;
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(bytes.as_slice()).map_err(|error| {
        ProviderTransportError::InvalidJson(SafeDiagnostic::from_untrusted(&error.to_string()))
    })
}

fn content_length_exceeds(response: &Response, max_bytes: usize) -> bool {
    let Ok(max_bytes) = u64::try_from(max_bytes) else {
        return false;
    };
    response
        .content_length()
        .is_some_and(|length| length > max_bytes)
}

/// Return whether one response status may be replayed under `safety`.
#[must_use]
pub const fn should_retry_status(status: StatusCode, safety: RequestReplaySafety) -> bool {
    match safety {
        RequestReplaySafety::Never => false,
        RequestReplaySafety::AdmissionOnly => matches!(status.as_u16(), 408 | 429 | 503 | 529),
        RequestReplaySafety::Idempotent => {
            matches!(
                status.as_u16(),
                408 | 409 | 429 | 500 | 502 | 503 | 504 | 529
            )
        }
    }
}

/// Only a connection-stage failure is safe to replay for a model POST.
#[must_use]
pub fn should_retry_error(error: &reqwest::Error, safety: RequestReplaySafety) -> bool {
    match safety {
        RequestReplaySafety::Never => false,
        RequestReplaySafety::AdmissionOnly => error.is_connect(),
        RequestReplaySafety::Idempotent => error.is_connect() || error.is_timeout(),
    }
}

/// Compute a jittered, bounded retry delay.
#[must_use]
pub fn retry_delay(attempt: u32, retry_after: Option<&str>) -> Duration {
    let retry_after = retry_after
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs);
    let base = retry_after.unwrap_or_else(|| {
        let seconds = 2_u64.saturating_pow(attempt.saturating_add(1));
        let jitter_bound = (seconds / 4).max(1);
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| u64::from(duration.subsec_nanos()));
        let span = jitter_bound.saturating_mul(2).saturating_add(1);
        let offset = seed % span;
        Duration::from_secs(seconds.saturating_sub(jitter_bound).saturating_add(offset))
    });
    base.min(MAX_RETRY_DELAY)
}

/// Sanitize a diagnostic against the exact request credentials.
#[must_use]
pub fn sanitize_with_headers(raw: &str, headers: &SensitiveHeaders) -> SafeDiagnostic {
    headers.sanitize_diagnostic(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn retry_policy_is_bounded_and_never_replays_one_shot_requests() {
        assert!(should_retry_status(
            StatusCode::TOO_MANY_REQUESTS,
            RequestReplaySafety::AdmissionOnly
        ));
        assert!(!should_retry_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            RequestReplaySafety::AdmissionOnly
        ));
        assert!(!should_retry_status(
            StatusCode::TOO_MANY_REQUESTS,
            RequestReplaySafety::Never
        ));
        assert_eq!(retry_delay(20, Some("999999")), MAX_RETRY_DELAY);
    }

    #[test]
    fn stream_budget_rejects_before_overflow() {
        let mut budget = StreamByteBudget::new(8);
        budget.consume(5).expect("within budget");
        let error = budget.consume(4).expect_err("over budget");
        assert_eq!(error, ProviderTransportError::ResponseTooLarge { limit: 8 });
        assert_eq!(budget.consumed(), 5);
    }

    #[test]
    fn endpoint_validation_preserves_local_provider_exception() {
        validate_endpoint("ollama", "http://127.0.0.1:11434/api/chat").expect("local provider");
        assert!(validate_endpoint("anthropic", "http://169.254.169.254/latest/meta-data").is_err());
    }

    #[tokio::test]
    async fn canonical_client_refuses_redirects() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/redirected"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/redirected", server.uri())),
            )
            .mount(&server)
            .await;

        let response = send(
            shared_client()
                .expect("client")
                .get(format!("{}/start", server.uri())),
        )
        .await
        .expect("redirect response");
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        server.verify().await;
    }

    #[tokio::test]
    async fn bounded_json_reader_rejects_oversized_success_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/large"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 1024]))
            .mount(&server)
            .await;
        let response = send(
            shared_client()
                .expect("client")
                .get(format!("{}/large", server.uri())),
        )
        .await
        .expect("response");
        let error = read_json_capped::<Value>(response, 32)
            .await
            .expect_err("body must be rejected before JSON parsing");
        assert_eq!(
            error,
            ProviderTransportError::ResponseTooLarge { limit: 32 }
        );
    }

    #[tokio::test]
    async fn bounded_stream_rejects_an_unterminated_oversized_frame() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/unterminated"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 1024]))
            .mount(&server)
            .await;
        let response = send(
            shared_client()
                .expect("client")
                .get(format!("{}/unterminated", server.uri())),
        )
        .await
        .expect("response");
        let error = bounded_byte_stream(response, 32)
            .next()
            .await
            .expect("one stream item")
            .expect_err("raw bytes must be rejected before framing");
        assert_eq!(
            error,
            ProviderTransportError::ResponseTooLarge { limit: 32 }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn request_deadline_terminates_a_pending_send() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/slow"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
            .mount(&server)
            .await;
        let request = shared_client()
            .expect("client")
            .get(format!("{}/slow", server.uri()));
        let error = send_until(request, Instant::now() + Duration::from_secs(1))
            .await
            .expect_err("deadline");
        assert_eq!(
            error,
            ProviderTransportError::Deadline {
                phase: "response-header"
            }
        );
    }
}
