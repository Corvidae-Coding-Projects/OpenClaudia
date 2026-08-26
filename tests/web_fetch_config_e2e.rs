//! End-to-end tests for `config::WebFetchConfig` defaults +
//! `default_preapproved_domains` catalog + `is_preapproved`
//! subdomain-match semantics + `CC_MAX_MARKDOWN_LENGTH` cap.
//!
//! Sprint 99 of the verification effort. The `web_fetch`
//! distillation surface (crosslink #603) is security-sensitive
//! because pre-approved domains bypass the SSRF prompt — drift
//! here can either lock users out of legitimate docs or let
//! attackers smuggle URLs through. This file pins the
//! catalog membership + the subdomain-match contract.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::config::{
    default_preapproved_domains, is_preapproved, WebFetchConfig, CC_MAX_MARKDOWN_LENGTH,
};

// ───────────────────────────────────────────────────────────────────────────
// Section A — CC_MAX_MARKDOWN_LENGTH constant
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn cc_max_markdown_length_is_documented_100k() {
    // CC parity: applyPromptToMarkdown.ts MAX_MARKDOWN_LENGTH.
    assert_eq!(CC_MAX_MARKDOWN_LENGTH, 100_000);
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — WebFetchConfig defaults
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn web_fetch_config_default_disables_distillation() {
    let config = WebFetchConfig::default();
    assert!(
        !config.distillation_enabled,
        "distillation MUST default to OFF (opt-in per docs)"
    );
}

#[test]
fn web_fetch_config_default_max_bytes_matches_cc_constant() {
    let config = WebFetchConfig::default();
    assert_eq!(config.max_distillation_bytes, CC_MAX_MARKDOWN_LENGTH);
}

#[test]
fn web_fetch_config_default_provider_and_model_are_none() {
    let config = WebFetchConfig::default();
    assert!(
        config.distillation_provider.is_none(),
        "default provider = session's active provider"
    );
    assert!(
        config.distillation_model.is_none(),
        "default model = provider's small/fast tier"
    );
}

#[test]
fn web_fetch_config_default_preapproved_domains_is_populated_catalog() {
    let config = WebFetchConfig::default();
    assert!(
        !config.preapproved_domains.is_empty(),
        "default catalog MUST be populated"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — default_preapproved_domains catalog
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn preapproved_catalog_includes_documented_language_references() {
    let domains = default_preapproved_domains();
    // Per documented categories: language references.
    for d in &[
        "docs.python.org",
        "doc.rust-lang.org",
        "docs.rs",
        "nodejs.org",
        "developer.mozilla.org",
    ] {
        assert!(
            domains.iter().any(|x| x == d),
            "MUST include language ref {d:?}; got {domains:?}"
        );
    }
}

#[test]
fn preapproved_catalog_includes_ai_provider_docs() {
    let domains = default_preapproved_domains();
    for d in &[
        "docs.anthropic.com",
        "platform.openai.com",
        "ai.google.dev",
        "huggingface.co",
    ] {
        assert!(
            domains.iter().any(|x| x == d),
            "MUST include AI provider doc {d:?}"
        );
    }
}

#[test]
fn preapproved_catalog_includes_source_forges() {
    let domains = default_preapproved_domains();
    assert!(domains.iter().any(|d| d == "github.com"));
    assert!(domains.iter().any(|d| d == "gitlab.com"));
    assert!(domains.iter().any(|d| d == "crates.io"));
}

#[test]
fn preapproved_catalog_includes_cloud_provider_docs() {
    let domains = default_preapproved_domains();
    for d in &[
        "docs.aws.amazon.com",
        "cloud.google.com",
        "learn.microsoft.com",
        "kubernetes.io",
    ] {
        assert!(
            domains.iter().any(|x| x == d),
            "MUST include cloud doc {d:?}"
        );
    }
}

#[test]
fn preapproved_catalog_entries_have_no_trailing_dot_or_scheme() {
    let domains = default_preapproved_domains();
    for d in &domains {
        assert!(
            !d.starts_with("http://") && !d.starts_with("https://"),
            "catalog entry {d:?} MUST be bare host (no scheme)"
        );
        assert!(!d.ends_with('.'), "catalog entry {d:?} MUST NOT end with .");
        assert!(
            !d.contains(' '),
            "catalog entry {d:?} MUST NOT contain spaces"
        );
    }
}

#[test]
fn preapproved_catalog_entries_are_pairwise_distinct() {
    let mut domains = default_preapproved_domains();
    let n = domains.len();
    domains.sort();
    domains.dedup();
    assert_eq!(
        domains.len(),
        n,
        "catalog MUST have no duplicates; got {n} entries, {} unique",
        domains.len()
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — is_preapproved subdomain-match contract
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn is_preapproved_exact_host_match_returns_true() {
    let allow = vec!["docs.python.org".to_string()];
    assert!(is_preapproved("https://docs.python.org/3/library/", &allow));
}

#[test]
fn is_preapproved_subdomain_of_allowed_host_returns_true() {
    // PINS SUBDOMAIN MATCH: "docs.python.org" allowlist
    // entry MUST cover any.subdomain.docs.python.org.
    let allow = vec!["docs.python.org".to_string()];
    assert!(is_preapproved("https://nested.docs.python.org/x", &allow));
}

#[test]
fn is_preapproved_sibling_host_not_match() {
    // "docs.python.org" allow MUST NOT cover "python.org" parent.
    let allow = vec!["docs.python.org".to_string()];
    assert!(!is_preapproved("https://python.org/news", &allow));
}

#[test]
fn is_preapproved_unrelated_host_returns_false() {
    let allow = vec!["docs.python.org".to_string()];
    assert!(!is_preapproved("https://evil.example.com/", &allow));
}

#[test]
fn is_preapproved_unparseable_url_returns_false_fail_closed() {
    // PINS DOCUMENTED CONTRACT: unparseable URLs FAIL-CLOSED
    // (return false), not panic / not error / not allow.
    let allow = vec!["github.com".to_string()];
    assert!(!is_preapproved("not a url", &allow));
    assert!(!is_preapproved("", &allow));
    assert!(!is_preapproved("javascript:alert(1)", &allow));
}

#[test]
fn is_preapproved_empty_allowlist_rejects_everything() {
    let allow: Vec<String> = Vec::new();
    assert!(!is_preapproved("https://docs.python.org/", &allow));
    assert!(!is_preapproved("https://github.com/", &allow));
}

#[test]
fn is_preapproved_with_default_catalog_admits_documented_hosts() {
    let allow = default_preapproved_domains();
    assert!(is_preapproved("https://docs.python.org/3/", &allow));
    assert!(is_preapproved("https://github.com/owner/repo", &allow));
    assert!(is_preapproved("https://crates.io/crates/foo", &allow));
}

#[test]
fn is_preapproved_default_catalog_refuses_random_evil_host() {
    let allow = default_preapproved_domains();
    assert!(!is_preapproved(
        "https://malicious-attacker.example/",
        &allow
    ));
}

#[test]
fn is_preapproved_match_is_host_only_not_path_dependent() {
    // Path content MUST NOT affect the match decision.
    let allow = vec!["docs.python.org".to_string()];
    assert!(is_preapproved("https://docs.python.org", &allow));
    assert!(is_preapproved("https://docs.python.org/", &allow));
    assert!(is_preapproved(
        "https://docs.python.org/3/library/stdtypes.html",
        &allow
    ));
    assert!(is_preapproved(
        "https://docs.python.org:443/path?q=1#frag",
        &allow
    ));
}

#[test]
fn is_preapproved_with_user_info_in_url_still_matches_host() {
    let allow = vec!["github.com".to_string()];
    assert!(is_preapproved("https://user:pass@github.com/repo", &allow));
}

#[test]
fn is_preapproved_with_ipv6_literal_url_no_match_unless_listed() {
    // IPv6 literal hosts aren't in the catalog.
    let allow = vec!["github.com".to_string()];
    assert!(!is_preapproved("http://[::1]/", &allow));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Serde round-trip
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn web_fetch_config_yaml_round_trips() {
    let original = WebFetchConfig::default();
    let yaml = serde_yaml::to_string(&original).expect("ser");
    let back: WebFetchConfig = serde_yaml::from_str(&yaml).expect("de");
    assert_eq!(back, original);
}

#[test]
fn web_fetch_config_minimal_yaml_uses_documented_defaults() {
    let config: WebFetchConfig = serde_yaml::from_str("{}").expect("de");
    assert_eq!(config, WebFetchConfig::default());
}

#[test]
fn web_fetch_config_with_distillation_enabled_round_trips() {
    let original = WebFetchConfig {
        distillation_enabled: true,
        max_distillation_bytes: 50_000,
        distillation_provider: Some("anthropic".to_string()),
        distillation_model: Some("claude-haiku-4-5".to_string()),
        preapproved_domains: vec!["custom.example.com".to_string()],
        exact_private_origins: vec!["http://127.0.0.1:8080".to_string()],
    };
    let yaml = serde_yaml::to_string(&original).expect("ser");
    let back: WebFetchConfig = serde_yaml::from_str(&yaml).expect("de");
    assert_eq!(back, original);
}

#[test]
fn web_fetch_config_none_provider_is_skipped_in_serialization() {
    let config = WebFetchConfig::default();
    let yaml = serde_yaml::to_string(&config).expect("ser");
    assert!(
        !yaml.contains("distillation_provider"),
        "None provider MUST be skipped per skip_serializing_if; got {yaml:?}"
    );
}

#[test]
fn web_fetch_config_clone_preserves_all_fields() {
    let original = WebFetchConfig {
        distillation_enabled: true,
        max_distillation_bytes: 12_345,
        distillation_provider: Some("p".to_string()),
        distillation_model: Some("m".to_string()),
        preapproved_domains: vec!["a".to_string(), "b".to_string()],
        exact_private_origins: vec!["http://localhost:1234".to_string()],
    };
    let cloned = original.clone();
    assert_eq!(cloned, original);
}
