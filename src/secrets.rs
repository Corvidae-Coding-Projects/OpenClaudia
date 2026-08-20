//! Secret ownership, sensitive HTTP headers, and safe diagnostics.
//!
//! Secret bytes live in one reference-counted, zeroizing allocation. Cloning a
//! capability clones only the allocation handle; it never duplicates the
//! secret `String`. Raw access is crate-private and closure-bounded so every
//! materialization site is explicit and auditable.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt;
use std::sync::{Arc, LazyLock};

use regex::Regex;
use reqwest::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

/// Stable marker emitted in place of secret values.
pub const REDACTED_SECRET: &str = "[REDACTED]";
/// Maximum accepted size for a single generic secret value.
pub const MAX_SECRET_BYTES: usize = 64 * 1024;
/// Maximum safe diagnostic retained after sanitization.
pub const MAX_DIAGNOSTIC_BYTES: usize = 4 * 1024;
pub(crate) const MAX_DIAGNOSTIC_INPUT_BYTES: usize = 64 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SecretValueError {
    #[error("secret value exceeds the {max}-byte cap ({actual} bytes)")]
    TooLong { actual: usize, max: usize },
    #[error("secret value contains a NUL byte")]
    ContainsNul,
    #[error("redaction marker cannot be used as credential material")]
    RedactionMarker,
}

struct SecretAllocation(Zeroizing<String>);

/// An opaque secret capability.
///
/// `Clone` shares the same zeroizing allocation. `Debug`, `Display`, and
/// `Serialize` never reveal bytes. Deserialization intentionally rejects the
/// redaction marker so a generic round trip cannot silently replace a live
/// credential with `[REDACTED]`.
#[derive(Clone)]
pub struct SecretString(Arc<SecretAllocation>);

impl SecretString {
    /// Consume raw secret bytes into a zeroizing allocation.
    ///
    /// # Errors
    /// Rejects NUL-containing, oversized, and redaction-placeholder values.
    pub fn try_from_string(raw: String) -> Result<Self, SecretValueError> {
        let raw = Zeroizing::new(raw);
        if raw.as_str() == REDACTED_SECRET {
            return Err(SecretValueError::RedactionMarker);
        }
        if raw.len() > MAX_SECRET_BYTES {
            return Err(SecretValueError::TooLong {
                actual: raw.len(),
                max: MAX_SECRET_BYTES,
            });
        }
        if raw.contains('\0') {
            return Err(SecretValueError::ContainsNul);
        }
        Ok(Self(Arc::new(SecretAllocation(raw))))
    }

    /// Return the byte length without exposing the contents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0 .0.len()
    }

    /// Return whether the secret contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0 .0.is_empty()
    }

    /// Compare a candidate without returning the secret.
    #[must_use]
    pub fn matches(&self, candidate: &str) -> bool {
        self.0 .0.as_str() == candidate
    }

    /// Check whether the secret occurs in a candidate diagnostic or payload
    /// without returning its bytes.
    #[must_use]
    pub fn appears_in(&self, candidate: &str) -> bool {
        candidate.contains(self.0 .0.as_str())
    }

    /// Borrow raw bytes only for the duration of an audited crate-internal
    /// materialization operation.
    pub(crate) fn expose<R>(&self, operation: impl FnOnce(&str) -> R) -> R {
        operation(self.0 .0.as_str())
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.0 .0.as_bytes() == other.0 .0.as_bytes()
    }
}

impl Eq for SecretString {}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED_SECRET)
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(REDACTED_SECRET)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::try_from_string(raw).map_err(serde::de::Error::custom)
    }
}

/// Immutable environment authority whose values stay zeroizing and redacted
/// until they are installed into a child process.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct EnvironmentGrants(HashMap<String, SecretString>);

impl EnvironmentGrants {
    #[must_use]
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Consume a policy-validated raw map into protected allocations.
    pub(crate) fn from_validated(
        grants: HashMap<String, String>,
    ) -> Result<Self, SecretValueError> {
        grants
            .into_iter()
            .map(|(name, value)| SecretString::try_from_string(value).map(|value| (name, value)))
            .collect::<Result<HashMap<_, _>, _>>()
            .map(Self)
    }

    pub(crate) fn insert_validated(
        &mut self,
        name: String,
        value: String,
    ) -> Result<(), SecretValueError> {
        self.0.insert(name, SecretString::try_from_string(value)?);
        Ok(())
    }

    pub(crate) fn extend(&mut self, other: &Self) {
        self.0.extend(other.0.clone());
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn contains_key(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&SecretString> {
        self.0.get(name)
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.0.keys()
    }

    #[must_use]
    pub fn matches_value(&self, name: &str, candidate: &str) -> bool {
        self.get(name).is_some_and(|value| value.matches(candidate))
    }

    /// Borrow one value only for the duration of an explicit capability
    /// operation. Prefer `apply_std`/`apply_tokio` for child environments.
    #[doc(hidden)]
    pub fn with_value<R>(&self, name: &str, operation: impl FnOnce(&str) -> R) -> Option<R> {
        self.get(name).map(|value| value.expose(operation))
    }

    /// Deterministic name/digest pairs for capability binding and evidence
    /// freshness without exposing the granted bytes.
    #[must_use]
    pub fn sorted_name_digests(&self) -> Vec<(&str, String)> {
        let mut values = self
            .0
            .iter()
            .map(|(name, value)| {
                let digest = value.expose(|raw| {
                    crate::runtime::ContentDigest::sha256(raw.as_bytes()).to_string()
                });
                (name.as_str(), digest)
            })
            .collect::<Vec<_>>();
        values.sort_unstable_by(|left, right| left.0.cmp(right.0));
        values
    }

    /// Apply the exact grants to a standard-library child command.
    pub fn apply_std(&self, command: &mut std::process::Command) {
        for (name, value) in &self.0 {
            value.expose(|raw| {
                command.env(OsStr::new(name), OsStr::new(raw));
            });
        }
    }

    /// Apply the exact grants to a Tokio child command.
    pub fn apply_tokio(&self, command: &mut tokio::process::Command) {
        for (name, value) in &self.0 {
            value.expose(|raw| {
                command.env(OsStr::new(name), OsStr::new(raw));
            });
        }
    }

    #[must_use]
    pub fn sanitize_diagnostic(&self, raw: &str) -> SafeDiagnostic {
        sanitize_diagnostic(raw, self.0.values())
    }
}

impl fmt::Debug for EnvironmentGrants {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvironmentGrants")
            .field("count", &self.len())
            .field("values", &REDACTED_SECRET)
            .finish()
    }
}

impl Serialize for EnvironmentGrants {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for name in self.keys() {
            map.serialize_entry(name, REDACTED_SECRET)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for EnvironmentGrants {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = HashMap::<String, String>::deserialize(deserializer)?;
        Self::from_validated(values).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<HashMap<String, String>> for EnvironmentGrants {
    type Error = SecretValueError;

    fn try_from(values: HashMap<String, String>) -> Result<Self, Self::Error> {
        Self::from_validated(values)
    }
}

/// An OAuth access or refresh token with header-safe validation.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthToken(SecretString);

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OAuthTokenError {
    #[error("OAuth token is empty or whitespace-only")]
    Empty,
    #[error("OAuth token contains non-ASCII bytes")]
    NonAscii,
    #[error("OAuth token contains an ASCII control character")]
    ControlCharacter,
    #[error(transparent)]
    Secret(#[from] SecretValueError),
}

impl OAuthToken {
    /// Consume and validate a token before it enters runtime state.
    ///
    /// # Errors
    /// Rejects empty, non-ASCII, control-character, oversized, NUL, and
    /// redaction-marker input.
    pub fn try_from_string(raw: String) -> Result<Self, OAuthTokenError> {
        let secret = SecretString::try_from_string(raw).map_err(|error| match error {
            SecretValueError::ContainsNul => OAuthTokenError::ControlCharacter,
            other => OAuthTokenError::Secret(other),
        })?;
        if secret.expose(|raw| raw.trim().is_empty()) {
            return Err(OAuthTokenError::Empty);
        }
        if secret.expose(|raw| !raw.is_ascii()) {
            return Err(OAuthTokenError::NonAscii);
        }
        if secret.expose(|raw| raw.chars().any(|character| character.is_ascii_control())) {
            return Err(OAuthTokenError::ControlCharacter);
        }
        Ok(Self(secret))
    }

    #[must_use]
    pub fn matches(&self, candidate: &str) -> bool {
        self.0.matches(candidate)
    }

    pub(crate) fn secret(&self) -> SecretString {
        self.0.clone()
    }

    pub(crate) fn expose<R>(&self, operation: impl FnOnce(&str) -> R) -> R {
        self.0.expose(operation)
    }
}

impl fmt::Debug for OAuthToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OAuthToken([REDACTED])")
    }
}

impl fmt::Display for OAuthToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED_SECRET)
    }
}

impl Serialize for OAuthToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(REDACTED_SECRET)
    }
}

impl<'de> Deserialize<'de> for OAuthToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::try_from_string(raw).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, PartialEq, Eq)]
enum SensitiveHeaderTemplate {
    Exact(SecretString),
    Bearer(SecretString),
}

impl SensitiveHeaderTemplate {
    fn materialize(&self) -> Result<HeaderValue, reqwest::header::InvalidHeaderValue> {
        let mut value = match self {
            Self::Exact(secret) => secret.expose(HeaderValue::from_str)?,
            Self::Bearer(secret) => secret.expose(|raw| {
                let materialized = Zeroizing::new(format!("Bearer {raw}"));
                HeaderValue::from_str(materialized.as_str())
            })?,
        };
        value.set_sensitive(true);
        Ok(value)
    }

    fn matches(&self, candidate: &str) -> bool {
        match self {
            Self::Exact(secret) => secret.matches(candidate),
            Self::Bearer(secret) => candidate
                .strip_prefix("Bearer ")
                .is_some_and(|raw| secret.matches(raw)),
        }
    }

    const fn secret(&self) -> &SecretString {
        match self {
            Self::Exact(secret) | Self::Bearer(secret) => secret,
        }
    }
}

/// An ordered collection of headers whose values are always treated as
/// sensitive, including user-defined provider headers.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SensitiveHeaders(Vec<(HeaderName, SensitiveHeaderTemplate)>);

#[derive(Debug, Error)]
pub enum SensitiveHeaderError {
    #[error("invalid sensitive header name '{name}': {source}")]
    Name {
        name: String,
        #[source]
        source: reqwest::header::InvalidHeaderName,
    },
    #[error("invalid value for sensitive header '{name}': {source}")]
    Value {
        name: HeaderName,
        #[source]
        source: reqwest::header::InvalidHeaderValue,
    },
    #[error("invalid sensitive header secret: {0}")]
    Secret(#[from] SecretValueError),
}

impl SensitiveHeaders {
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Insert an exact secret header value.
    ///
    /// # Errors
    /// Returns an error if the header name or exact value is invalid.
    pub fn insert_secret(
        &mut self,
        name: &str,
        value: SecretString,
    ) -> Result<(), SensitiveHeaderError> {
        let name = parse_header_name(name)?;
        let template = SensitiveHeaderTemplate::Exact(value);
        template
            .materialize()
            .map_err(|source| SensitiveHeaderError::Value {
                name: name.clone(),
                source,
            })?;
        self.insert_template(name, template);
        Ok(())
    }

    /// Insert an already-validated static header name without a fallible name
    /// conversion. Used by provider adapters with compile-time literals.
    pub(crate) fn insert_header_secret(&mut self, name: HeaderName, value: SecretString) {
        self.insert_template(name, SensitiveHeaderTemplate::Exact(value));
    }

    /// Insert a bearer token header value.
    ///
    /// # Errors
    /// Returns an error if the header name or bearer value is invalid.
    pub fn insert_bearer(
        &mut self,
        name: &str,
        token: SecretString,
    ) -> Result<(), SensitiveHeaderError> {
        let name = parse_header_name(name)?;
        let template = SensitiveHeaderTemplate::Bearer(token);
        template
            .materialize()
            .map_err(|source| SensitiveHeaderError::Value {
                name: name.clone(),
                source,
            })?;
        self.insert_template(name, template);
        Ok(())
    }

    /// Insert an already-validated static bearer header name.
    pub(crate) fn insert_header_bearer(&mut self, name: HeaderName, token: SecretString) {
        self.insert_template(name, SensitiveHeaderTemplate::Bearer(token));
    }

    /// Protect a non-secret compile-time provider header in the same opaque
    /// collection so callers cannot accidentally split auth and custom header
    /// handling into different transport paths.
    ///
    /// # Panics
    /// Panics if the compile-time literal violates the secret value bounds.
    pub(crate) fn insert_static_literal(&mut self, name: HeaderName, value: &'static str) {
        let secret = SecretString::try_from_string(value.to_string())
            .expect("compile-time provider header literal must be valid");
        self.insert_header_secret(name, secret);
    }

    /// Consume a literal header value into protected storage immediately.
    ///
    /// # Errors
    /// Returns an error if the name is invalid or the value violates the
    /// generic secret bounds.
    pub fn insert_literal(
        &mut self,
        name: &str,
        value: String,
    ) -> Result<(), SensitiveHeaderError> {
        self.insert_secret(name, SecretString::try_from_string(value)?)
    }

    pub fn extend(&mut self, other: &Self) {
        for (name, value) in &other.0 {
            self.insert_template(name.clone(), value.clone());
        }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn contains_name(&self, name: &str) -> bool {
        HeaderName::from_bytes(name.as_bytes())
            .ok()
            .is_some_and(|name| self.0.iter().any(|(candidate, _)| candidate == name))
    }

    /// Compare one value without exposing it. Intended for behavioral tests
    /// and compatibility probes.
    #[must_use]
    pub fn matches_value(&self, name: &str, candidate: &str) -> bool {
        HeaderName::from_bytes(name.as_bytes())
            .ok()
            .and_then(|name| {
                self.0
                    .iter()
                    .find(|(candidate, _)| candidate == name)
                    .map(|(_, value)| value)
            })
            .is_some_and(|value| value.matches(candidate))
    }

    /// Borrow one exact header value for a bounded configuration transform.
    /// Transport callers should use [`Self::apply`] instead.
    pub(crate) fn with_value<R>(&self, name: &str, operation: impl FnOnce(&str) -> R) -> Option<R> {
        HeaderName::from_bytes(name.as_bytes())
            .ok()
            .and_then(|name| {
                self.0
                    .iter()
                    .find(|(candidate, _)| candidate == name)
                    .map(|(_, value)| value)
            })
            .map(|value| match value {
                SensitiveHeaderTemplate::Exact(secret) => secret.expose(operation),
                SensitiveHeaderTemplate::Bearer(secret) => secret.expose(|raw| {
                    let materialized = Zeroizing::new(format!("Bearer {raw}"));
                    operation(materialized.as_str())
                }),
            })
    }

    /// Apply headers at the final HTTP request boundary. Materialized
    /// `HeaderValue`s are marked sensitive before entering reqwest.
    ///
    /// # Errors
    /// Returns a value error without including the rejected secret bytes.
    pub fn apply(
        &self,
        mut request: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, SensitiveHeaderError> {
        for (name, value) in &self.0 {
            let value = value
                .materialize()
                .map_err(|source| SensitiveHeaderError::Value {
                    name: name.clone(),
                    source,
                })?;
            request = request.header(name.clone(), value);
        }
        Ok(request)
    }

    /// Names only; values never leave the collection.
    pub fn names(&self) -> impl Iterator<Item = &HeaderName> {
        self.0.iter().map(|(name, _)| name)
    }

    /// Sanitize a provider diagnostic against every exact secret carried by
    /// this request in addition to the global structured policy.
    #[must_use]
    pub fn sanitize_diagnostic(&self, raw: &str) -> SafeDiagnostic {
        sanitize_diagnostic_with(raw, |sanitized| {
            for (name, value) in &self.0 {
                value.secret().expose(|needle| {
                    redact_exact_secret(sanitized, needle);
                    if matches!(value, SensitiveHeaderTemplate::Exact(_))
                        && (name == reqwest::header::AUTHORIZATION
                            || name == reqwest::header::PROXY_AUTHORIZATION)
                    {
                        let mut parts = needle.splitn(2, char::is_whitespace);
                        let _scheme = parts.next();
                        if let Some(credential) = parts.next().map(str::trim_start) {
                            redact_exact_secret(sanitized, credential);
                        }
                    }
                });
            }
        })
    }

    fn insert_template(&mut self, name: HeaderName, value: SensitiveHeaderTemplate) {
        if let Some((_, current)) = self.0.iter_mut().find(|(candidate, _)| candidate == name) {
            *current = value;
        } else {
            self.0.push((name, value));
        }
    }
}

impl TryFrom<HashMap<String, String>> for SensitiveHeaders {
    type Error = SensitiveHeaderError;

    fn try_from(values: HashMap<String, String>) -> Result<Self, Self::Error> {
        let mut headers = Self::new();
        for (name, value) in values {
            headers.insert_literal(&name, value)?;
        }
        Ok(headers)
    }
}

fn parse_header_name(name: &str) -> Result<HeaderName, SensitiveHeaderError> {
    HeaderName::from_bytes(name.as_bytes()).map_err(|source| SensitiveHeaderError::Name {
        name: name.to_string(),
        source,
    })
}

impl fmt::Debug for SensitiveHeaders {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveHeaders")
            .field("names", &self.names().collect::<Vec<_>>())
            .field("values", &"[REDACTED]")
            .finish()
    }
}

impl Serialize for SensitiveHeaders {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for name in self.names() {
            map.serialize_entry(name.as_str(), REDACTED_SECRET)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for SensitiveHeaders {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = std::collections::HashMap::<String, String>::deserialize(deserializer)?;
        let mut headers = Self::new();
        for (name, value) in values {
            headers
                .insert_literal(&name, value)
                .map_err(serde::de::Error::custom)?;
        }
        Ok(headers)
    }
}

/// Text proven safe for logs, UI error channels, and retained failure state.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SafeDiagnostic(String);

impl SafeDiagnostic {
    /// Sanitize arbitrary external or dynamically composed text before it
    /// enters an error channel, retained state, or log field.
    #[must_use]
    pub fn from_untrusted(raw: &str) -> Self {
        sanitize_diagnostic(raw, std::iter::empty())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for SafeDiagnostic {
    fn from(raw: String) -> Self {
        Self::from_untrusted(&raw)
    }
}

impl From<&str> for SafeDiagnostic {
    fn from(raw: &str) -> Self {
        Self::from_untrusted(raw)
    }
}

impl fmt::Debug for SafeDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SafeDiagnostic")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for SafeDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

static SENSITIVE_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(authorization|proxy-authorization|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|cookie|set-cookie|password|client[_-]?secret|secret)\s*[:=]\s*(?:bearer\s+)?[^\s,;]+",
    )
    .expect("static sensitive-assignment regex")
});
static BEARER_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bbearer\s+[A-Za-z0-9._~+\-/]+=*").expect("static bearer regex")
});

/// Sanitize untrusted external text with structured key redaction, exact
/// active-secret scanning, generic credential-pattern redaction, and a hard
/// retained-size bound.
#[must_use]
pub fn sanitize_diagnostic<'a>(
    raw: &str,
    known_secrets: impl IntoIterator<Item = &'a SecretString>,
) -> SafeDiagnostic {
    let known_secrets = known_secrets.into_iter().collect::<Vec<_>>();
    sanitize_diagnostic_with(raw, |sanitized| {
        for secret in &known_secrets {
            secret.expose(|needle| redact_exact_secret(sanitized, needle));
        }
    })
}

/// Read at most the diagnostic input budget from an HTTP response body.
///
/// The returned buffer is zeroized on drop. Callers must still pass it through
/// [`SafeDiagnostic`] or a secret-aware sanitizer before displaying, logging,
/// or retaining it.
///
/// # Errors
/// Returns the underlying transport error when a response chunk cannot be
/// read.
pub async fn read_bounded_diagnostic_body(
    mut response: reqwest::Response,
) -> Result<Zeroizing<String>, reqwest::Error> {
    let initial_capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
        .min(MAX_DIAGNOSTIC_INPUT_BYTES);
    let mut bytes = Zeroizing::new(Vec::with_capacity(initial_capacity));

    while bytes.len() < MAX_DIAGNOSTIC_INPUT_BYTES {
        let Some(chunk) = response.chunk().await? else {
            break;
        };
        let remaining = MAX_DIAGNOSTIC_INPUT_BYTES - bytes.len();
        let take = remaining.min(chunk.len());
        bytes.extend_from_slice(&chunk[..take]);
        if take < chunk.len() {
            break;
        }
    }

    Ok(Zeroizing::new(
        String::from_utf8_lossy(bytes.as_slice()).into_owned(),
    ))
}

fn sanitize_diagnostic_with(raw: &str, redact_exact: impl FnOnce(&mut String)) -> SafeDiagnostic {
    let input = truncate_utf8(raw, MAX_DIAGNOSTIC_INPUT_BYTES);
    let mut sanitized = serde_json::from_str::<Value>(input).map_or_else(
        |_| input.to_string(),
        |mut value| {
            redact_json_value(&mut value, None);
            value.to_string()
        },
    );
    redact_exact(&mut sanitized);
    sanitized = SENSITIVE_ASSIGNMENT
        .replace_all(&sanitized, "$1=[REDACTED]")
        .into_owned();
    sanitized = BEARER_VALUE
        .replace_all(&sanitized, "Bearer [REDACTED]")
        .into_owned();
    let was_truncated = sanitized.len() > MAX_DIAGNOSTIC_BYTES || raw.len() > input.len();
    let mut bounded = truncate_utf8(&sanitized, MAX_DIAGNOSTIC_BYTES).to_string();
    if was_truncated {
        const MARKER: &str = "…[truncated]";
        let keep = MAX_DIAGNOSTIC_BYTES.saturating_sub(MARKER.len());
        bounded.truncate(nearest_char_boundary(&bounded, keep));
        bounded.push_str(MARKER);
    }
    SafeDiagnostic(bounded)
}

fn redact_exact_secret(sanitized: &mut String, needle: &str) {
    if needle.is_empty() {
        return;
    }
    *sanitized = sanitized.replace(needle, REDACTED_SECRET);
    if let Ok(encoded) = serde_json::to_string(needle) {
        let encoded = Zeroizing::new(encoded);
        let escaped = &encoded[1..encoded.len() - 1];
        if escaped != needle {
            *sanitized = sanitized.replace(escaped, REDACTED_SECRET);
        }
    }
}

fn redact_json_value(value: &mut Value, key: Option<&str>) {
    if key.is_some_and(is_sensitive_field) {
        *value = Value::String(REDACTED_SECRET.to_string());
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                redact_json_value(value, Some(key));
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_json_value(value, None);
            }
        }
        _ => {}
    }
}

fn is_sensitive_field(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace('-', "_");
    normalized == "authorization"
        || normalized == "proxy_authorization"
        || normalized == "cookie"
        || normalized == "set_cookie"
        || normalized == "password"
        || normalized == "secret"
        || normalized.ends_with("_secret")
        || normalized == "token"
        || normalized.ends_with("_token")
        || normalized == "api_key"
        || normalized.ends_with("_api_key")
}

fn truncate_utf8(value: &str, max: usize) -> &str {
    &value[..nearest_char_boundary(value, max)]
}

fn nearest_char_boundary(value: &str, max: usize) -> usize {
    let mut index = value.len().min(max);
    while !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEEDED: &str = "s025-super-secret-token-123456";

    #[test]
    fn secret_debug_display_and_serde_are_redacted_and_marker_is_rejected() {
        let secret = SecretString::try_from_string(SEEDED.to_string()).expect("secret");
        let clone = secret.clone();
        assert!(
            Arc::ptr_eq(&secret.0, &clone.0),
            "clones must share one zeroizing allocation"
        );
        let outputs = [
            format!("{secret:?}"),
            format!("{secret}"),
            serde_json::to_string(&secret).expect("serialize"),
        ];
        for output in outputs {
            assert!(!output.contains(SEEDED), "secret leaked: {output}");
        }
        assert!(serde_json::from_str::<SecretString>("\"[REDACTED]\"").is_err());
    }

    #[test]
    fn oauth_and_environment_capabilities_redact_and_reject_lossy_round_trips() {
        let token = OAuthToken::try_from_string(SEEDED.to_string()).expect("token");
        let environment = EnvironmentGrants::try_from(HashMap::from([(
            "S025_TOKEN".to_string(),
            SEEDED.to_string(),
        )]))
        .expect("environment");
        for output in [
            format!("{token:?}"),
            format!("{token}"),
            format!("{environment:?}"),
            serde_json::to_string(&token).expect("serialize token"),
            serde_json::to_string(&environment).expect("serialize environment"),
        ] {
            assert!(!output.contains(SEEDED), "secret leaked: {output}");
        }
        assert!(environment.matches_value("S025_TOKEN", SEEDED));
        let redacted = serde_json::to_string(&environment).expect("serialize environment");
        assert!(serde_json::from_str::<EnvironmentGrants>(&redacted).is_err());
    }

    #[test]
    fn sensitive_headers_redact_and_mark_materialized_values_sensitive() {
        let secret = SecretString::try_from_string(SEEDED.to_string()).expect("secret");
        let mut headers = SensitiveHeaders::new();
        headers
            .insert_bearer("authorization", secret)
            .expect("header");
        assert!(!format!("{headers:?}").contains(SEEDED));
        assert!(!serde_json::to_string(&headers)
            .expect("serialize")
            .contains(SEEDED));
        assert!(headers.matches_value("authorization", &format!("Bearer {SEEDED}")));

        let request = headers
            .apply(reqwest::Client::new().get("https://example.com"))
            .expect("apply")
            .build()
            .expect("request");
        let value = request.headers().get("authorization").expect("header");
        assert!(value.is_sensitive());
        assert!(!format!("{:?}", request.headers()).contains(SEEDED));
    }

    #[test]
    fn diagnostic_sanitizer_redacts_structured_patterns_exact_secrets_and_bounds() {
        let secret = SecretString::try_from_string(SEEDED.to_string()).expect("secret");
        let raw = format!(
            r#"{{"error":"Authorization: Bearer {SEEDED}","access_token":"{SEEDED}","nested":{{"api-key":"abc"}},"padding":"{}"}}"#,
            "x".repeat(MAX_DIAGNOSTIC_BYTES * 2)
        );
        let safe = sanitize_diagnostic(&raw, [&secret]);
        assert!(!safe.as_str().contains(SEEDED), "{safe}");
        assert!(!safe.as_str().contains("abc"), "{safe}");
        assert!(safe.as_str().contains(REDACTED_SECRET), "{safe}");
        assert!(safe.len() <= MAX_DIAGNOSTIC_BYTES);
        assert!(!format!("{safe:?}").contains(SEEDED));
    }

    #[test]
    fn diagnostic_sanitizer_redacts_json_escaped_exact_secret_bytes() {
        let raw_secret = r#"s025-quote-"-slash-\-secret"#;
        let secret = SecretString::try_from_string(raw_secret.to_string()).expect("secret");
        let raw =
            serde_json::json!({"message": format!("provider echoed {raw_secret}")}).to_string();
        let encoded = serde_json::to_string(raw_secret).expect("encode test secret");
        let escaped = &encoded[1..encoded.len() - 1];

        let safe = sanitize_diagnostic(&raw, [&secret]);

        assert!(!safe.as_str().contains(raw_secret), "{safe}");
        assert!(!safe.as_str().contains(escaped), "{safe}");
        assert!(safe.as_str().contains(REDACTED_SECRET), "{safe}");
    }

    #[tokio::test]
    async fn diagnostic_body_reader_never_retains_more_than_the_input_budget() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oversized-error"))
            .respond_with(ResponseTemplate::new(500).set_body_bytes(vec![
                b'x';
                MAX_DIAGNOSTIC_INPUT_BYTES
                    * 4
            ]))
            .mount(&server)
            .await;

        let response = reqwest::Client::new()
            .get(format!("{}/oversized-error", server.uri()))
            .send()
            .await
            .expect("response");
        let retained = read_bounded_diagnostic_body(response)
            .await
            .expect("bounded response body");

        assert_eq!(retained.len(), MAX_DIAGNOSTIC_INPUT_BYTES);
        let safe = SafeDiagnostic::from_untrusted(&retained);
        assert!(safe.len() <= MAX_DIAGNOSTIC_BYTES);
        assert!(safe.as_str().ends_with("…[truncated]"));
    }
}
