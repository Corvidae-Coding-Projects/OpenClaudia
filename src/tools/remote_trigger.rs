//! `remote_trigger` tool — webhook fan-out (crosslink #617).
//!
//! Claude Code exposes a `remote_trigger` tool that lets the leader
//! agent kick an external system via a registered webhook. The
//! implementation has two parts:
//!
//! 1. A **registry** of webhook endpoints, keyed by a short symbolic
//!    name. The leader doesn't pass URLs around in tool calls — it
//!    refers to the webhook by name, and the registry resolves it to
//!    a URL plus headers. This keeps secrets out of the model's
//!    context.
//! 2. **HTTPS-default scheme validation** — registrations without an
//!    explicit scheme are upgraded to `https://`, and `http://`
//!    registrations are rejected unless explicitly opted in. This
//!    closes the foot-gun where a typo (`https//` ⇒ relative URL)
//!    silently downgraded the request to plaintext.
//!
//! This module ships the registry + validator; wiring into the tool
//! registry (so `remote_trigger` is callable as a tool name) is left
//! to the registry layer and uses the public types exported here.
//!
//! ## Scheme policy
//!
//! - `https://example.com/hook` — accepted as-is.
//! - `http://example.com/hook` — accepted **only** when the registry
//!   is built via [`WebhookRegistry::new_allow_plaintext`]. The
//!   default [`WebhookRegistry::new`] rejects every `http://` URL
//!   with [`WebhookError::InsecureScheme`].
//! - `example.com/hook` (no scheme) — upgraded to `https://` and
//!   accepted.
//! - Any other scheme (`file://`, `ftp://`, `javascript:`, …) is
//!   rejected with [`WebhookError::InvalidScheme`].

use std::collections::HashMap;
use std::fmt;

/// Canonical webhook URL kept opaque because signed webhook URLs commonly
/// carry credentials in their path, query, or user-info components.
#[derive(Clone, PartialEq, Eq)]
pub struct WebhookUrl(crate::secrets::SecretString);

impl WebhookUrl {
    fn from_validated(url: String) -> Result<Self, WebhookError> {
        crate::secrets::SecretString::try_from_string(url)
            .map(Self)
            .map_err(|_| WebhookError::Malformed {})
    }

    /// Compare a canonical URL without returning its bytes.
    #[must_use]
    pub fn matches(&self, candidate: &str) -> bool {
        self.0.matches(candidate)
    }
}

impl fmt::Debug for WebhookUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WebhookUrl([REDACTED])")
    }
}

impl fmt::Display for WebhookUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(crate::secrets::REDACTED_SECRET)
    }
}

/// Errors registering or invoking a webhook.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WebhookError {
    /// URL parsed but uses a scheme other than `http` / `https`.
    #[error(
        "webhook URL uses an unsupported scheme; expected https (or http with explicit opt-in)"
    )]
    InvalidScheme {},
    /// URL uses `http://` and the registry was built with the strict
    /// default that rejects plaintext.
    #[error("webhook URL uses insecure http://; build the registry with new_allow_plaintext() to opt in")]
    InsecureScheme {},
    /// URL is empty or could not be parsed as a host-bearing URL.
    #[error("webhook URL is not a valid absolute URL with a host")]
    Malformed {},
    /// Caller asked to invoke a name that was never registered.
    #[error("no webhook registered under name '{name}'")]
    UnknownWebhook {
        /// The lookup key the caller used.
        name: String,
    },
    /// Caller registered a name that already exists. Use
    /// [`WebhookRegistry::replace`] to overwrite intentionally.
    #[error("webhook name '{name}' is already registered")]
    Duplicate {
        /// The name that collided.
        name: String,
    },
    /// A configured header name or value cannot be represented safely on the
    /// outbound HTTP request.
    #[error("invalid webhook headers: {reason}")]
    InvalidHeaders {
        /// Validation detail that never contains the rejected value.
        reason: String,
    },
}

/// One registered webhook endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookEndpoint {
    /// Final, validated URL — always carries an explicit scheme
    /// (https by default, http only when explicitly opted in).
    pub url: WebhookUrl,
    /// Extra headers to include on the outbound request. Values remain opaque
    /// until a future sender applies them at its HTTP transport boundary.
    pub headers: crate::secrets::SensitiveHeaders,
}

/// Webhook registry — name → endpoint.
#[derive(Debug, Clone)]
pub struct WebhookRegistry {
    entries: HashMap<String, WebhookEndpoint>,
    allow_plaintext: bool,
}

impl WebhookRegistry {
    /// Strict registry — `http://` is rejected, missing schemes are
    /// upgraded to `https://`. This is the right default for
    /// production deployments.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            allow_plaintext: false,
        }
    }

    /// Opt-in registry that allows `http://` URLs. Intended for
    /// localhost / loopback testing or air-gapped internal networks.
    /// **Not** for production — `http://` over the public internet
    /// leaks tokens and payloads.
    #[must_use]
    pub fn new_allow_plaintext() -> Self {
        Self {
            entries: HashMap::new(),
            allow_plaintext: true,
        }
    }

    /// Validate and normalise a raw URL string. Returns the canonical
    /// form (with the default `https://` scheme prepended when the
    /// input was scheme-less).
    ///
    /// # Errors
    ///
    /// See [`WebhookError`] for the cases.
    pub fn validate_url(&self, raw: &str) -> Result<WebhookUrl, WebhookError> {
        if raw.trim().is_empty() {
            return Err(WebhookError::Malformed {});
        }

        // Decide whether the caller supplied a scheme. We deliberately
        // hand-roll this instead of trying `url::Url::parse` first,
        // because a scheme-less input like `example.com/hook` parses
        // as a relative URL — we want to UPGRADE it to https, not
        // reject it.
        let (with_scheme, was_implicit) = scheme_with_default(raw);

        let parsed = url::Url::parse(&with_scheme).map_err(|_| WebhookError::Malformed {})?;

        if parsed.host_str().is_none_or(str::is_empty) {
            return Err(WebhookError::Malformed {});
        }

        match parsed.scheme() {
            "https" => WebhookUrl::from_validated(parsed.into()),
            "http" => {
                if self.allow_plaintext {
                    WebhookUrl::from_validated(parsed.into())
                } else if was_implicit {
                    // `was_implicit` means the caller never wrote
                    // "http://" explicitly — we'd have upgraded to
                    // https. This branch is unreachable in practice
                    // because `scheme_with_default` prepends https.
                    // Surface it as Malformed for defence-in-depth.
                    Err(WebhookError::Malformed {})
                } else {
                    Err(WebhookError::InsecureScheme {})
                }
            }
            _ => Err(WebhookError::InvalidScheme {}),
        }
    }

    /// Register `name → url` (with optional headers).
    ///
    /// # Errors
    ///
    /// * [`WebhookError::Duplicate`] if `name` is already registered.
    /// * Any error from [`Self::validate_url`].
    pub fn register(
        &mut self,
        name: impl Into<String>,
        url: &str,
        headers: HashMap<String, String>,
    ) -> Result<(), WebhookError> {
        let name = name.into();
        if self.entries.contains_key(&name) {
            return Err(WebhookError::Duplicate { name });
        }
        let url = self.validate_url(url)?;
        let headers = protect_headers(headers)?;
        self.entries.insert(name, WebhookEndpoint { url, headers });
        Ok(())
    }

    /// Replace an existing entry (or insert if absent).
    ///
    /// # Errors
    ///
    /// Any error from [`Self::validate_url`].
    pub fn replace(
        &mut self,
        name: impl Into<String>,
        url: &str,
        headers: HashMap<String, String>,
    ) -> Result<(), WebhookError> {
        let url = self.validate_url(url)?;
        let headers = protect_headers(headers)?;
        self.entries
            .insert(name.into(), WebhookEndpoint { url, headers });
        Ok(())
    }

    /// Look up a registered webhook by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&WebhookEndpoint> {
        self.entries.get(name)
    }

    /// Names of every registered webhook, in unspecified order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// Number of registered entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when the registry has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `http://` is permitted in this registry.
    #[must_use]
    pub const fn allows_plaintext(&self) -> bool {
        self.allow_plaintext
    }
}

fn protect_headers(
    headers: HashMap<String, String>,
) -> Result<crate::secrets::SensitiveHeaders, WebhookError> {
    crate::secrets::SensitiveHeaders::try_from(headers).map_err(|error| {
        WebhookError::InvalidHeaders {
            reason: error.to_string(),
        }
    })
}

impl Default for WebhookRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns `(url_with_scheme, was_implicit)`.
///
/// `was_implicit == true` means we prepended `https://` because the
/// input lacked a scheme.
fn scheme_with_default(raw: &str) -> (String, bool) {
    // A scheme per RFC 3986 is `ALPHA *( ALPHA / DIGIT / "+" / "-" /
    // "." )` followed by `:`. We approximate that: if the prefix
    // before the first `:` is a valid scheme, treat it as one. We
    // can't just look for "://" because schemes like `mailto:`
    // don't use authority slashes (and we want to reject them
    // explicitly, not pretend they were missing schemes).
    if let Some(colon) = raw.find(':') {
        let prefix = &raw[..colon];
        if !prefix.is_empty()
            && prefix
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
            && prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            return (raw.to_string(), false);
        }
    }
    (format!("https://{raw}"), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_url_is_accepted_verbatim() {
        let reg = WebhookRegistry::new();
        let url = reg.validate_url("https://example.com/hook").unwrap();
        assert!(url.matches("https://example.com/hook"));
    }

    #[test]
    fn scheme_less_url_is_upgraded_to_https() {
        let reg = WebhookRegistry::new();
        let url = reg.validate_url("example.com/hook").unwrap();
        assert!(url.matches("https://example.com/hook"));
    }

    #[test]
    fn scheme_less_root_url_is_upgraded_and_normalised() {
        // url::Url normalises bare hosts by appending the empty path
        // `/`; pin that contract so callers know what to compare
        // against.
        let reg = WebhookRegistry::new();
        let url = reg.validate_url("example.com").unwrap();
        assert!(url.matches("https://example.com/"));
    }

    #[test]
    fn http_is_rejected_by_default() {
        let reg = WebhookRegistry::new();
        let err = reg
            .validate_url("http://example.com/hook")
            .expect_err("http must be rejected by default");
        assert!(
            matches!(err, WebhookError::InsecureScheme { .. }),
            "expected InsecureScheme, got {err:?}",
        );
    }

    #[test]
    fn http_is_accepted_with_explicit_opt_in() {
        let reg = WebhookRegistry::new_allow_plaintext();
        let url = reg.validate_url("http://localhost:1234/hook").unwrap();
        assert!(url.matches("http://localhost:1234/hook"));
    }

    #[test]
    fn other_schemes_are_rejected() {
        let reg = WebhookRegistry::new();
        for bad in [
            "ftp://x.invalid/",
            "file:///etc/passwd",
            "javascript:alert(1)",
        ] {
            let err = reg.validate_url(bad).expect_err("must reject");
            assert!(
                matches!(
                    err,
                    WebhookError::InvalidScheme { .. } | WebhookError::Malformed { .. }
                ),
                "expected scheme or malformed error for {bad}, got {err:?}",
            );
        }
    }

    #[test]
    fn empty_url_is_malformed() {
        let reg = WebhookRegistry::new();
        assert!(matches!(
            reg.validate_url(""),
            Err(WebhookError::Malformed { .. })
        ));
        assert!(matches!(
            reg.validate_url("   "),
            Err(WebhookError::Malformed { .. })
        ));
    }

    #[test]
    fn register_then_get_roundtrips() {
        let mut reg = WebhookRegistry::new();
        let mut headers = HashMap::new();
        headers.insert("X-Auth".into(), "tok-123".into());
        reg.register(
            "deploy",
            "https://hooks.example.com/deploy",
            headers.clone(),
        )
        .unwrap();
        let ep = reg.get("deploy").unwrap();
        assert!(ep.url.matches("https://hooks.example.com/deploy"));
        assert!(ep.headers.matches_value("X-Auth", "tok-123"));
        assert!(!format!("{ep:?}").contains("tok-123"));
    }

    #[test]
    fn register_rejects_duplicate_name() {
        let mut reg = WebhookRegistry::new();
        reg.register("a", "https://x.example.com", HashMap::new())
            .unwrap();
        let err = reg
            .register("a", "https://y.example.com", HashMap::new())
            .expect_err("duplicate must error");
        assert!(matches!(err, WebhookError::Duplicate { ref name } if name == "a"));
    }

    #[test]
    fn replace_overwrites_existing_entry() {
        let mut reg = WebhookRegistry::new();
        reg.register("a", "https://x.example.com/old", HashMap::new())
            .unwrap();
        reg.replace("a", "https://z.example.com/new", HashMap::new())
            .unwrap();
        assert!(reg
            .get("a")
            .unwrap()
            .url
            .matches("https://z.example.com/new"));
    }

    #[test]
    fn get_returns_none_for_unknown_name() {
        let reg = WebhookRegistry::new();
        assert!(reg.get("absent").is_none());
    }

    #[test]
    fn len_is_empty_track_entries() {
        let mut reg = WebhookRegistry::new();
        assert!(reg.is_empty());
        reg.register("a", "https://x.example.com", HashMap::new())
            .unwrap();
        reg.register("b", "https://y.example.com", HashMap::new())
            .unwrap();
        assert_eq!(reg.len(), 2);
        assert!(!reg.is_empty());
    }

    #[test]
    fn allows_plaintext_flag_reflects_constructor() {
        assert!(!WebhookRegistry::new().allows_plaintext());
        assert!(WebhookRegistry::new_allow_plaintext().allows_plaintext());
    }
}
