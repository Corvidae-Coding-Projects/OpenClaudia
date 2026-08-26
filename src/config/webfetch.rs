//! Web-fetch configuration (crosslink #608, CC parity with
//! `web_fetch` + `applyPromptToMarkdown`).
//!
//! CC's `web_fetch` accepts a `prompt` field alongside `url`; the fetched
//! markdown is fed to a small distillation model (Haiku by default) and
//! the model's answer becomes the returned `result`. This module owns
//! the schema half of that contract; `tools/web.rs` owns the runtime
//! fetch + secondary-model dispatch.
//!
//! Schema fields:
//! * `distillation_enabled` — opt-in; when `false` the tool returns raw
//!   reader markdown the way it does today (back-compat).
//! * `max_distillation_bytes` — hard cap on the raw markdown sent to the
//!   distillation model. CC uses 100 000 chars (`MAX_MARKDOWN_LENGTH`);
//!   we mirror that exactly so a prompt that distils correctly under CC
//!   distils identically here.
//! * `distillation_provider` / `distillation_model` — explicit selection
//!   of the secondary model. Both optional: `None` lets the runtime pick
//!   the active provider's "small / fast" tier (matches CC's
//!   Haiku-default behaviour on Anthropic-first-party).

use serde::{Deserialize, Serialize};

/// Trusted-host opt-in for encrypted cookie continuity between ephemeral
/// browser operations. Repository configuration is stripped before merge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrowserPersistenceConfig {
    /// Stable, non-secret namespace for one explicitly managed login profile.
    pub profile_id: String,
    /// Exact HTTP(S) origins whose cookies may be restored and saved.
    pub exact_origins: Vec<String>,
    /// Base64-encoded 32-byte AES-256 key. Debug/display/serialization remain
    /// redacted through [`crate::secrets::SecretString`].
    pub encryption_key: crate::secrets::SecretString,
    /// Discard encrypted state older than this many seconds.
    #[serde(default = "default_browser_cookie_retention_seconds")]
    pub retention_seconds: u64,
}

const fn default_browser_cookie_retention_seconds() -> u64 {
    30 * 24 * 60 * 60
}

/// Hard cap CC enforces on the markdown blob handed to the distillation model.
///
/// Mirrors `MAX_MARKDOWN_LENGTH` in `applyPromptToMarkdown.ts` — diverging
/// here would silently change the rendered answer for the same input.
pub const CC_MAX_MARKDOWN_LENGTH: usize = 100_000;

/// Configuration for the optional secondary-model distillation step
/// applied to `web_fetch` output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebFetchConfig {
    /// When `true`, `web_fetch` accepts a `prompt` field and routes the
    /// fetched markdown through the distillation model. When `false`
    /// (default), the tool returns raw markdown — preserving today's
    /// behaviour for users who haven't opted in.
    #[serde(default)]
    pub distillation_enabled: bool,
    /// Max byte length of the raw markdown sent to the secondary model.
    /// Defaults to [`CC_MAX_MARKDOWN_LENGTH`] for CC parity.
    #[serde(default = "default_max_distillation_bytes")]
    pub max_distillation_bytes: usize,
    /// Override the provider used for distillation. `None` ⇒ session's
    /// active provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distillation_provider: Option<String>,
    /// Override the model used for distillation. `None` ⇒ the provider's
    /// "small / fast" tier (Haiku on Anthropic, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distillation_model: Option<String>,
    /// Hosts that bypass the SSRF prompt for fetches (#603).
    #[serde(default = "default_preapproved_domains")]
    pub preapproved_domains: Vec<String>,
    /// Exact private/local origins that model-selected fetch and browser
    /// traffic may reach. This authority is accepted only from trusted host
    /// configuration; repository values are stripped before source merge.
    #[serde(default)]
    pub exact_private_origins: Vec<String>,
    /// Explicit trusted-host capability for encrypted cookie continuity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_persistence: Option<BrowserPersistenceConfig>,
}

const fn default_max_distillation_bytes() -> usize {
    CC_MAX_MARKDOWN_LENGTH
}

impl Default for WebFetchConfig {
    fn default() -> Self {
        Self {
            distillation_enabled: false,
            max_distillation_bytes: CC_MAX_MARKDOWN_LENGTH,
            distillation_provider: None,
            distillation_model: None,
            preapproved_domains: default_preapproved_domains(),
            exact_private_origins: Vec::new(),
            browser_persistence: None,
        }
    }
}

impl WebFetchConfig {
    /// Truncate `markdown` to `max_distillation_bytes` along a char
    /// boundary so the slice is always valid UTF-8.
    ///
    /// This is the host-side mirror of CC's pre-distillation truncate
    /// step; isolating it here keeps the cap and the truncate in lock
    /// step (modifying the cap in serde without touching the truncate
    /// would silently over-spend on the secondary model).
    #[must_use]
    pub fn truncate_for_distillation<'a>(&self, markdown: &'a str) -> &'a str {
        let max = self.max_distillation_bytes;
        if markdown.len() <= max {
            return markdown;
        }
        let mut end = max;
        while end > 0 && !markdown.is_char_boundary(end) {
            end -= 1;
        }
        &markdown[..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_cc_back_compat_posture() {
        let cfg = WebFetchConfig::default();
        assert!(
            !cfg.distillation_enabled,
            "distillation must default off so existing /web_fetch behaviour is preserved"
        );
        assert_eq!(cfg.max_distillation_bytes, CC_MAX_MARKDOWN_LENGTH);
        assert!(cfg.distillation_provider.is_none());
        assert!(cfg.distillation_model.is_none());
        assert!(cfg.exact_private_origins.is_empty());
        assert!(cfg.browser_persistence.is_none());
    }

    #[test]
    fn truncate_at_char_boundary_does_not_split_multibyte() {
        let cfg = WebFetchConfig {
            // 5 bytes — splits inside the 3-byte `é` if we naively cut.
            max_distillation_bytes: 4,
            ..Default::default()
        };
        let s = "ab\u{e9}cd"; // 'a', 'b', 'é' (2 bytes), 'c', 'd' → 6 bytes
        let out = cfg.truncate_for_distillation(s);
        // out must be valid UTF-8 and ≤ 4 bytes.
        assert!(out.len() <= 4);
        // and prefix-of-s.
        assert!(s.starts_with(out));
    }

    #[test]
    fn truncate_returns_input_when_under_cap() {
        let cfg = WebFetchConfig::default();
        let s = "short";
        assert_eq!(cfg.truncate_for_distillation(s), s);
    }

    #[test]
    fn yaml_round_trip_preserves_overrides() {
        let cfg = WebFetchConfig {
            distillation_enabled: true,
            max_distillation_bytes: 5_000,
            distillation_provider: Some("anthropic".into()),
            distillation_model: Some("claude-haiku-4".into()),
            preapproved_domains: default_preapproved_domains(),
            exact_private_origins: vec!["http://127.0.0.1:8080".to_string()],
            browser_persistence: None,
        };
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        let back: WebFetchConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn cc_max_markdown_length_is_one_hundred_k() {
        // Pin the constant — a drift from CC would silently change the
        // rendered answer for the same input.
        assert_eq!(CC_MAX_MARKDOWN_LENGTH, 100_000);
    }
}

/// Default preapproved-domain list shipped with `OpenClaudia`.
///
/// Mirrors CC's bundled allowlist: documentation sites for the major
/// languages and frameworks an agent commonly reads while debugging,
/// plus package indexes (npm/PyPI/crates.io/Go) and the canonical
/// reference hosts (MDN, Stack Overflow, GitHub). Every entry must be
/// a bare host — schemes, paths, ports, and `www.` prefixes are stripped
/// before matching.
///
/// Hosts are sourced from CC's `webFetch_PREAPPROVED_HOSTS` constant and
/// trimmed to the categories where the agent's typical "fetch docs"
/// flows live. The list is intentionally short — adding a host requires
/// thinking about whether arbitrary content under that host should be
/// fetchable without a prompt.
#[must_use]
pub fn default_preapproved_domains() -> Vec<String> {
    vec![
        // Language references
        "docs.python.org".to_string(),
        "doc.rust-lang.org".to_string(),
        "docs.rs".to_string(),
        "go.dev".to_string(),
        "pkg.go.dev".to_string(),
        "nodejs.org".to_string(),
        "developer.mozilla.org".to_string(),
        "ruby-doc.org".to_string(),
        "docs.oracle.com".to_string(),
        // Framework / library docs
        "reactjs.org".to_string(),
        "react.dev".to_string(),
        "vuejs.org".to_string(),
        "angular.io".to_string(),
        "svelte.dev".to_string(),
        "nextjs.org".to_string(),
        "tailwindcss.com".to_string(),
        // Cloud / infra docs
        "docs.aws.amazon.com".to_string(),
        "cloud.google.com".to_string(),
        "learn.microsoft.com".to_string(),
        "docs.docker.com".to_string(),
        "kubernetes.io".to_string(),
        // AI / model provider docs
        "docs.anthropic.com".to_string(),
        "platform.openai.com".to_string(),
        "ai.google.dev".to_string(),
        "huggingface.co".to_string(),
        // Package indexes / source forges
        "pypi.org".to_string(),
        "npmjs.com".to_string(),
        "crates.io".to_string(),
        "github.com".to_string(),
        "gitlab.com".to_string(),
        // Reference / Q&A
        "stackoverflow.com".to_string(),
        "wikipedia.org".to_string(),
    ]
}

/// True when `url`'s host matches an entry in `preapproved`.
///
/// A match is either an exact host equality with one of the entries, or
/// a subdomain of it. Mirrors the subdomain match used by web-search
/// `allowed_domains` filtering so users only have one mental model of
/// how domain lists behave.
///
/// Unparseable URLs return `false` (fail-closed for unrecognised input).
#[must_use]
pub fn is_preapproved(url: &str, preapproved: &[String]) -> bool {
    let Some(host) = host_of(url) else {
        return false;
    };
    preapproved.iter().any(|d| domain_matches(&host, d))
}

/// Lowercased host with any `www.` prefix stripped, or `None` when the URL
/// can't be parsed by `url::Url`. Mirrors `tools::web::host_of` so the two
/// allowlists share one normalisation pass. Duplicated here (rather than
/// re-exported) because `tools::web::host_of` is module-private — calling
/// across `tools` from `config` would force a public surface change that
/// is out of scope for #603.
fn host_of(url: &str) -> Option<String> {
    let host = url::Url::parse(url).ok()?.host_str()?.to_ascii_lowercase();
    let stripped = host.strip_prefix("www.").unwrap_or(&host).to_string();
    if stripped.is_empty() {
        None
    } else {
        Some(stripped)
    }
}

/// Same semantics as `tools::web::domain_matches`: `host` is allowed when
/// it equals `needle` or when `needle` is a parent of `host` by at least
/// one DNS label.
fn domain_matches(host: &str, needle: &str) -> bool {
    let needle = needle.trim_start_matches("www.").to_ascii_lowercase();
    if needle.is_empty() {
        return false;
    }
    host == needle || host.ends_with(&format!(".{needle}"))
}

#[cfg(test)]
mod preapproved_tests {
    use super::*;

    #[test]
    fn default_list_contains_expected_categories() {
        let defaults = default_preapproved_domains();
        // ~30 entries; tolerate ±2 if we tweak the list later.
        assert!(
            defaults.len() >= 25 && defaults.len() <= 40,
            "default list should be roughly 30 entries; got {}",
            defaults.len()
        );
        // Spot-check coverage across categories.
        assert!(defaults.iter().any(|d| d == "docs.python.org"));
        assert!(defaults.iter().any(|d| d == "docs.rs"));
        assert!(defaults.iter().any(|d| d == "developer.mozilla.org"));
        assert!(defaults.iter().any(|d| d == "github.com"));
        assert!(defaults.iter().any(|d| d == "docs.anthropic.com"));
    }

    #[test]
    fn config_default_populates_preapproved_list() {
        let cfg = WebFetchConfig::default();
        assert!(
            !cfg.preapproved_domains.is_empty(),
            "default config must ship a non-empty allowlist (#603)"
        );
        assert!(cfg.preapproved_domains.contains(&"crates.io".to_string()));
    }

    #[test]
    fn serde_default_matches_struct_default() {
        let cfg: WebFetchConfig = serde_json::from_str("{}").expect("deserialize {}");
        assert_eq!(
            cfg.preapproved_domains,
            default_preapproved_domains(),
            "serde-default empty object must produce shipped allowlist"
        );
    }

    #[test]
    fn serde_explicit_empty_list_disables_preapproval() {
        let cfg: WebFetchConfig =
            serde_json::from_str(r#"{"preapproved_domains": []}"#).expect("deserialize");
        assert!(
            cfg.preapproved_domains.is_empty(),
            "explicit empty list must be honoured (opt-out path)"
        );
    }

    #[test]
    fn serde_user_extended_list_overrides_default() {
        let cfg: WebFetchConfig =
            serde_json::from_str(r#"{"preapproved_domains": ["example.com", "foo.test"]}"#)
                .expect("deserialize");
        assert_eq!(cfg.preapproved_domains.len(), 2);
        assert!(cfg.preapproved_domains.contains(&"example.com".to_string()));
        assert!(cfg.preapproved_domains.contains(&"foo.test".to_string()));
    }

    #[test]
    fn is_preapproved_exact_host_match() {
        let list = vec!["docs.python.org".to_string()];
        assert!(is_preapproved("https://docs.python.org/3/", &list));
    }

    #[test]
    fn is_preapproved_subdomain_match() {
        let list = vec!["github.com".to_string()];
        assert!(is_preapproved("https://api.github.com/repos/foo", &list));
        assert!(is_preapproved("https://github.com/foo/bar", &list));
    }

    #[test]
    fn is_preapproved_sibling_domain_rejected() {
        let list = vec!["docs.python.org".to_string()];
        // Sibling: `python.org` is NOT a subdomain of `docs.python.org`.
        assert!(!is_preapproved("https://python.org/", &list));
        // Lookalike: `evildocs.python.org` is not a subdomain match.
        assert!(!is_preapproved("https://evildocs.python.org/", &list));
    }

    #[test]
    fn is_preapproved_unparseable_url_rejected() {
        let list = vec!["github.com".to_string()];
        assert!(!is_preapproved("not-a-url", &list));
        assert!(!is_preapproved("", &list));
    }

    #[test]
    fn is_preapproved_handles_www_prefix() {
        let list = vec!["wikipedia.org".to_string()];
        assert!(is_preapproved("https://www.wikipedia.org/wiki/X", &list));
        assert!(is_preapproved("https://en.wikipedia.org/wiki/Rust", &list));
    }
}
