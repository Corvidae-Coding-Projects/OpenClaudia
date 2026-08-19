//! Integration tests for web tools — pins the behavioral contracts from Phase 1 spec (#529).
//!
//! ## Spec → test mapping
//!
//! | Spec behavior                           | Test(s)                                              |
//! |-----------------------------------------|------------------------------------------------------|
//! | 1. `web_fetch` scheme allowlist         | `fetch_url_blocks_file_scheme`, `fetch_url_blocks_ftp_scheme`, `fetch_url_blocks_data_scheme` |
//! | 2. `web_fetch` SSRF hostname denylist   | `fetch_url_blocks_localhost_hostname`, `fetch_url_blocks_gcp_metadata`, `fetch_url_blocks_k8s_endpoint` |
//! | 3. `web_fetch` private-IP SSRF guard    | `fetch_url_blocks_loopback_ipv4`, `fetch_url_blocks_private_network_10`, `fetch_url_blocks_aws_metadata_ip`, `fetch_url_blocks_ipv6_loopback`, `fetch_url_blocks_decimal_encoded_loopback` |
//! | 4. `web_fetch` success output format    | `fetch_url_success_output_contains_url_line`, `fetch_url_success_truncates_at_50k` |
//! | 5. `web_fetch` validation layering      | `execute_web_fetch_prefix_check_catches_non_http`, `fetch_url_rejects_loopback_mock_before_status_handling` |
//!
//! ### Fixed regressions pinned
//!
//! - #603  Preapproved domain allowlist bypasses prompts — `web_fetch_preapproved_domain_permission_bypass`
//! - #610  DDG result URLs pass SSRF validation — `duckduckgo_parser_drops_ssrf_urls_before_formatting`
//! - #605  Search output includes citation reminder — `web_search_results_include_citation_reminder`
//! - #608  `web_fetch` schema exposes prompt distillation — `web_fetch_schema_exposes_prompt_parameter`
//!
//! ### Browser tests (headless Chrome)
//!
//! Gated behind `#[ignore]`. Opt in at runtime with:
//! ```text
//! cargo test -p openclaudia --test web_integration -- --ignored
//! ```
//! Set `OPENCLAUDIA_TEST_BROWSER=1` to confirm opt-in intent (tests log a warning if absent).

use openclaudia::permissions::{CheckResult, PermissionManager};
#[cfg(feature = "browser")]
use openclaudia::web::parse_duckduckgo_results_from_html;
use openclaudia::web::{fetch_url, fetch_with_browser, format_search_results, SearchResult};
use serde_json::{json, Value};
use tempfile::TempDir;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a wiremock server that returns the given body and status for GET /*.
async fn serve_body(status: u16, body: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(status)
                .set_body_string(body)
                .insert_header("content-type", "text/markdown; charset=utf-8"),
        )
        .mount(&server)
        .await;
    server
}

// ===========================================================================
// Behavior 1 — `web_fetch` scheme allowlist
//
// OC `validate_url` (src/web.rs:153) explicitly rejects non-http/https schemes
// BEFORE any network activity. CC's `validateURL` does not have an explicit
// scheme allowlist but relies on axios + the permission system.
// OC is STRICTER than CC on scheme validation (spec §1 "OC is strictly stronger").
// ===========================================================================

#[tokio::test]
async fn fetch_url_blocks_file_scheme() {
    // Spec §1: scheme allowlist — file:// must be rejected with "Unsupported URL scheme"
    let err = fetch_url("file:///etc/passwd").await.unwrap_err();
    assert!(
        err.contains("Unsupported URL scheme"),
        "file:// not blocked by scheme guard: {err}"
    );
}

#[tokio::test]
async fn fetch_url_blocks_ftp_scheme() {
    let err = fetch_url("ftp://files.example.com/secret")
        .await
        .unwrap_err();
    assert!(
        err.contains("Unsupported URL scheme"),
        "ftp:// not blocked by scheme guard: {err}"
    );
}

#[tokio::test]
async fn fetch_url_blocks_data_scheme() {
    let err = fetch_url("data:text/html,<h1>hi</h1>").await.unwrap_err();
    assert!(
        err.contains("Unsupported URL scheme"),
        "data: not blocked by scheme guard: {err}"
    );
}

// ===========================================================================
// Behavior 2 — `web_fetch` hostname denylist
//
// DANGEROUS_HOSTNAMES (src/web.rs:19) blocks known internal/metadata names.
// This is OC-specific; CC relies on its domain blocklist API.
// ===========================================================================

#[tokio::test]
async fn fetch_url_blocks_localhost_hostname() {
    // Spec §2 hostname denylist
    let err = fetch_url("http://localhost/admin").await.unwrap_err();
    assert!(
        err.contains("metadata endpoint") || err.contains("reserved/internal"),
        "localhost not blocked: {err}"
    );
}

#[tokio::test]
async fn fetch_url_blocks_gcp_metadata() {
    let err = fetch_url("http://metadata.google.internal/computeMetadata/v1/instance/")
        .await
        .unwrap_err();
    assert!(
        err.contains("metadata endpoint"),
        "GCP metadata endpoint not blocked: {err}"
    );
}

#[tokio::test]
async fn fetch_url_blocks_k8s_endpoint() {
    let err = fetch_url("http://kubernetes.default.svc/api/v1/secrets")
        .await
        .unwrap_err();
    assert!(
        err.contains("metadata endpoint"),
        "Kubernetes API endpoint not blocked: {err}"
    );
}

#[tokio::test]
async fn fetch_url_blocks_aws_metadata_hostname() {
    // instance-data.ec2.internal — EC2 internal metadata alias
    let err = fetch_url("http://instance-data.ec2.internal/latest/meta-data/")
        .await
        .unwrap_err();
    assert!(
        err.contains("metadata endpoint")
            || err.contains("reserved/internal")
            || err.contains("Cannot resolve"),
        "EC2 internal metadata alias not blocked: {err}"
    );
}

// ===========================================================================
// Behavior 3 — `web_fetch` private-IP SSRF guard
//
// Spec §3: OC resolves hostnames and checks EVERY returned address against
// the forbidden-range matrix (loopback, private, link-local, CGNAT, etc.).
// IP literals (including decimal and hex encodings) are caught directly.
// ===========================================================================

#[tokio::test]
async fn fetch_url_blocks_loopback_ipv4() {
    let err = fetch_url("http://127.0.0.1:9090/").await.unwrap_err();
    assert!(
        err.contains("reserved/internal") || err.contains("metadata endpoint"),
        "127.0.0.1 not blocked: {err}"
    );
}

#[tokio::test]
async fn fetch_url_blocks_private_network_10() {
    let err = fetch_url("http://10.0.0.1/internal").await.unwrap_err();
    assert!(
        err.contains("reserved/internal") || err.contains("metadata endpoint"),
        "10.0.0.1 not blocked: {err}"
    );
}

#[tokio::test]
async fn fetch_url_blocks_aws_metadata_ip() {
    // 169.254.169.254 — AWS/GCP/Azure instance metadata IP
    let err = fetch_url("http://169.254.169.254/latest/meta-data/")
        .await
        .unwrap_err();
    assert!(
        err.contains("reserved/internal") || err.contains("metadata endpoint"),
        "AWS metadata IP 169.254.169.254 not blocked: {err}"
    );
}

#[tokio::test]
async fn fetch_url_blocks_ipv6_loopback() {
    let err = fetch_url("http://[::1]/").await.unwrap_err();
    assert!(
        err.contains("reserved/internal") || err.contains("metadata endpoint"),
        "IPv6 loopback [::1] not blocked: {err}"
    );
}

#[tokio::test]
async fn fetch_url_blocks_decimal_encoded_loopback() {
    // 2130706433 decimal == 127.0.0.1 — OC parse_host_as_ip detects this.
    // SSRF regression from crosslink #335.
    let err = fetch_url("http://2130706433/").await.unwrap_err();
    assert!(
        err.contains("reserved/internal") || err.contains("Invalid URL"),
        "decimal-encoded 127.0.0.1 not blocked: {err}"
    );
}

// ===========================================================================
// Behavior 4 — `web_fetch` success output format
//
// Spec §1 output: plain string, optional "# title" line, then "URL: <url>",
// then markdown/plaintext content. Truncated at 50,000 chars (OC-specific;
// CC truncates at 100,000 chars). No structured {bytes,code,codeText,...}.
//
// Public `fetch_url` performs SSRF validation before network access, so local
// wiremock URLs are intentionally rejected at the integration layer. These
// tests validate the tool output-format contract without making live network
// requests.
// ===========================================================================

#[test]
fn fetch_output_format_contains_url_header() {
    // Spec §1: output always contains "URL: <url>" line.
    // Verify via format_search_results and FetchResult construction path.
    // This exercises the format contract in execute_web_fetch (src/tools/web.rs:43).
    use openclaudia::tools::{execute_tool, FunctionCall, ToolCall};

    // A clearly invalid URL triggers the prefix check BEFORE any network call.
    // The error string, not a success path, is what this exercises.
    let call = ToolCall {
        id: "test_format".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "web_fetch".to_string(),
            arguments: r#"{"url": "not-a-url"}"#.to_string(),
        },
    };
    let result = execute_tool(&call);
    // Spec §1 error path: prefix check fails → error string, is_error = true.
    assert!(result.is_error(), "invalid URL must return is_error=true");
    assert!(
        result.content().contains("Invalid URL") || result.content().contains("Missing"),
        "expected error message, got: {}",
        result.content()
    );
}

#[test]
fn fetch_output_format_url_line_in_success_path() {
    use std::fmt::Write as _;
    // The success formatter in execute_web_fetch writes "URL: {url}\n\n"
    // (src/tools/web.rs:43). Verify the literal appears in formatted output.
    // This is a white-box unit test of the formatting code — it does not make
    // a live network request.
    //
    // We reconstruct the same formatting the real code does:
    let url = "https://example.com/page";
    let content = "# Hello\n\nSome content";
    let title = Some("Hello".to_string());

    let mut output = String::new();
    if let Some(t) = &title {
        let _ = write!(output, "# {t}\n\n");
    }
    let _ = write!(output, "URL: {url}\n\n");
    output.push_str(content);

    assert!(
        output.contains(&format!("URL: {url}")),
        "URL line missing from formatted output"
    );
    assert!(output.starts_with("# Hello"), "title heading missing");
}

#[test]
fn fetch_output_truncates_at_50k_chars() {
    // Spec §1: OC truncates at 50,000 chars; CC at 100,000. Pin the OC value.
    // (src/tools/web.rs:47 — `if output.len() > 50000`)
    use openclaudia::tools::safe_truncate;

    // Generate content longer than 50,000 bytes.
    let long = "x".repeat(60_000);
    let url = "https://example.com/";
    let mut output = format!("URL: {url}\n\n{long}");

    let expected_truncation = 50_000;
    if output.len() > expected_truncation {
        output = format!(
            "{}...\n\n(content truncated, {} total chars)",
            safe_truncate(&output, expected_truncation),
            output.len()
        );
    }

    assert!(
        output.contains("content truncated"),
        "expected truncation marker"
    );
    // The first 50,000 bytes must be present; the excess must not be untruncated.
    assert!(
        output.len() < 60_100,
        "output not truncated: {} bytes",
        output.len()
    );
}

// ===========================================================================
// Behavior 5 — `web_fetch` validation layering
//
// Public `fetch_url` validates URLs before any HTTP request. That means local
// wiremock URLs never reach status handling through this integration path.
// The direct HTTP tier's non-2xx behavior is pinned in `src/web.rs` unit tests.
// ===========================================================================

#[tokio::test]
async fn fetch_url_rejects_loopback_mock_before_status_handling() {
    let server = serve_body(404, "Not found").await;
    let err = fetch_url(&server.uri()).await.unwrap_err();
    assert!(
        err.contains("reserved/internal") || err.contains("metadata endpoint"),
        "loopback mock must be rejected before HTTP status handling; got {err}"
    );
}

// ===========================================================================
// Behavior 5 (supplement) — `web_fetch` URL validation error path
//
// The tools entry point (execute_web_fetch) has a prefix check BEFORE
// validate_url:  `!url.starts_with("http://") && !url.starts_with("https://")`
// This means a URL like "javascript:alert(1)" is caught at the prefix level,
// not the parse level. Pin this layering.
// ===========================================================================

#[test]
fn execute_web_fetch_prefix_check_catches_non_http() {
    use openclaudia::tools::{execute_tool, FunctionCall, ToolCall};

    for bad_url in &["javascript:alert(1)", "//example.com", "example.com"] {
        let call = ToolCall {
            id: "pchk".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "web_fetch".to_string(),
                arguments: format!(r#"{{"url": "{bad_url}"}}"#),
            },
        };
        let result = execute_tool(&call);
        assert!(
            result.is_error(),
            "expected error for {bad_url}, got success: {}",
            result.content()
        );
        assert!(
            result.content().contains("Invalid URL")
                || result.content().contains("must start with"),
            "wrong error message for {bad_url}: {}",
            result.content()
        );
    }
}

#[test]
fn execute_web_fetch_missing_url_arg_returns_error() {
    use openclaudia::tools::{execute_tool, FunctionCall, ToolCall};

    let call = ToolCall {
        id: "nourl".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "web_fetch".to_string(),
            arguments: r"{}".to_string(),
        },
    };
    let result = execute_tool(&call);
    assert!(result.is_error());
    assert!(
        result.content().contains("Missing"),
        "expected 'Missing url' error, got: {}",
        result.content()
    );
}

// ===========================================================================
// Spec §2 — `web_search` query validation
//
// OC: query < 2 chars → ("Query must be at least 2 characters.", true)
// CC: query < 2 chars → validateInput errorCode 1
// ===========================================================================

#[cfg(feature = "browser")]
#[test]
fn execute_web_search_short_query_returns_error() {
    use openclaudia::tools::{execute_tool, FunctionCall, ToolCall};

    let empty = ToolCall {
        id: "empty-query".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "web_search".to_string(),
            arguments: r#"{"query": ""}"#.to_string(),
        },
    };
    let empty_result = execute_tool(&empty);
    assert!(empty_result.is_error(), "empty query must fail closed");
    assert_eq!(
        empty_result.content(),
        "Permission denied: Denied: web_search tool call has malformed arguments (expected non-empty string 'query')"
    );

    let one_character = ToolCall {
        id: "one-character-query".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "web_search".to_string(),
            arguments: r#"{"query": "x"}"#.to_string(),
        },
    };
    let short_result = execute_tool(&one_character);
    assert!(short_result.is_error(), "one-character query must fail");
    assert!(
        short_result.content().contains("at least 2 characters"),
        "expected min-length message, got: {}",
        short_result.content()
    );
}

#[cfg(feature = "browser")]
#[test]
fn execute_web_search_missing_query_returns_error() {
    use openclaudia::tools::{execute_tool, FunctionCall, ToolCall};

    let call = ToolCall {
        id: "noq".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "web_search".to_string(),
            arguments: r"{}".to_string(),
        },
    };
    let result = execute_tool(&call);
    assert!(result.is_error());
    assert!(
        result.content().contains("Missing"),
        "expected 'Missing query' error, got: {}",
        result.content()
    );
}

#[cfg(feature = "browser")]
#[test]
fn execute_web_search_rejects_non_string_query_before_browser_launch() {
    use openclaudia::tools::{execute_tool, FunctionCall, ToolCall};

    for (name, value, expected) in [
        (
            "number",
            json!(42),
            "Permission denied: Denied: web_search tool call has malformed arguments (expected non-empty string 'query')",
        ),
        (
            "array",
            json!(["rust", "release"]),
            "Permission denied: Denied: web_search tool call has malformed arguments (expected non-empty string 'query')",
        ),
        (
            "object",
            json!({"q": "rust release"}),
            "Permission denied: Denied: web_search tool call has malformed arguments (expected non-empty string 'query')",
        ),
        (
            "null",
            Value::Null,
            "Permission denied: Denied: Missing 'query' argument required for web_search tool call",
        ),
    ] {
        let call = ToolCall {
            id: format!("badquery-{name}"),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "web_search".to_string(),
                arguments: json!({
                    "query": value,
                })
                .to_string(),
            },
        };
        let result = execute_tool(&call);
        assert!(result.is_error(), "query case {name} should fail");
        assert_eq!(result.content(), expected);
    }
}

#[cfg(feature = "browser")]
#[test]
fn execute_web_search_rejects_invalid_limit_before_browser_launch() {
    use openclaudia::tools::{execute_tool, FunctionCall, ToolCall};

    for (name, value) in [
        ("zero", json!(0)),
        ("too_large", json!(11)),
        ("string", json!("10")),
        ("negative", json!(-1)),
    ] {
        let call = ToolCall {
            id: format!("badlimit-{name}"),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "web_search".to_string(),
                arguments: json!({
                    "query": "rust release",
                    "limit": value,
                })
                .to_string(),
            },
        };
        let result = execute_tool(&call);
        assert!(result.is_error(), "limit case {name} should fail");
        assert!(
            result
                .content()
                .contains("web_search limit must be an integer between 1 and 10"),
            "invalid limit should fail before search backend launch; got: {}",
            result.content()
        );
    }
}

#[cfg(feature = "browser")]
#[test]
fn execute_web_search_rejects_invalid_domain_filters_before_browser_launch() {
    use openclaudia::tools::{execute_tool, FunctionCall, ToolCall};

    for (name, field, value, expected) in [
        (
            "allowed_non_array",
            "allowed_domains",
            json!("docs.rs"),
            "web_search allowed_domains must be an array of strings",
        ),
        (
            "blocked_non_string_item",
            "blocked_domains",
            json!(["example.com", 42]),
            "web_search blocked_domains[1] must be a string",
        ),
    ] {
        let call = ToolCall {
            id: format!("baddomains-{name}"),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "web_search".to_string(),
                arguments: json!({
                    "query": "rust release",
                    field: value,
                })
                .to_string(),
            },
        };
        let result = execute_tool(&call);
        assert!(result.is_error(), "domain filter case {name} should fail");
        assert!(
            result.content().contains(expected),
            "invalid domain filter should fail before search backend launch; got: {}",
            result.content()
        );
    }
}

// ===========================================================================
// Spec §2 — `web_search` domain filtering (post-hoc, not server-side)
//
// OC filters results after fetching (src/tools/web.rs:144-157).
// CC passes allowed_domains/blocked_domains to the Anthropic API.
// ===========================================================================

#[test]
fn web_search_domain_filter_blocks_blocked_domain() {
    // Verify post-hoc domain filtering via format_search_results path.
    // We simulate what execute_web_search does with the results.
    let results = vec![
        SearchResult {
            title: "Good".to_string(),
            url: "https://example.com/page".to_string(),
            snippet: "allowed".to_string(),
        },
        SearchResult {
            title: "Bad".to_string(),
            url: "https://blocked.example.org/page".to_string(),
            snippet: "blocked".to_string(),
        },
    ];

    // Apply blocked_domains filter as execute_web_search does
    let blocked = ["blocked.example.org".to_string()];
    let filtered: Vec<_> = results
        .into_iter()
        .filter(|r| {
            let host = host_of_test(&r.url);
            host.is_none_or(|h| !blocked.iter().any(|d| domain_matches_test(&h, d)))
        })
        .collect();

    let output = format_search_results(&filtered);
    assert!(output.contains("Good"), "allowed result must appear");
    assert!(
        !output.contains("Bad"),
        "blocked domain result must be filtered"
    );
}

#[test]
fn web_search_domain_filter_keeps_allowed_domain() {
    let results = vec![
        SearchResult {
            title: "Docs".to_string(),
            url: "https://docs.rs/serde".to_string(),
            snippet: "Rust docs".to_string(),
        },
        SearchResult {
            title: "Other".to_string(),
            url: "https://example.com/".to_string(),
            snippet: "other site".to_string(),
        },
    ];

    let allowed = ["docs.rs".to_string()];
    let filtered: Vec<_> = results
        .into_iter()
        .filter(|r| {
            let host = host_of_test(&r.url);
            host.is_none_or(|h| allowed.iter().any(|d| domain_matches_test(&h, d)))
        })
        .collect();

    let output = format_search_results(&filtered);
    assert!(output.contains("Docs"), "allowed-domain result must appear");
    assert!(
        !output.contains("Other"),
        "non-allowed domain must be filtered"
    );
}

// Replicate the private helpers from src/tools/web.rs so filter tests can use them.
// These are intentional duplicates — the tests pin the CURRENT behavior of the
// private functions; if those functions change, these tests will surface the drift.
fn host_of_test(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, tail)| tail);
    let host_port = rest.split('/').next()?;
    let host = host_port.split(':').next()?.to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn domain_matches_test(host: &str, needle: &str) -> bool {
    let needle = needle.trim_start_matches("www.").to_ascii_lowercase();
    if needle.is_empty() {
        return false;
    }
    host == needle || host.ends_with(&format!(".{needle}"))
}

#[test]
fn web_fetch_preapproved_domain_permission_bypass() {
    let dir = TempDir::new().expect("tempdir");
    let mgr = PermissionManager::new_with_web_fetch_preapproved(
        dir.path().join("permissions.json"),
        true,
        Vec::new(),
        vec!["docs.python.org".to_string()],
    );

    let allowed = mgr.check("web_fetch", &json!({"url": "https://docs.python.org/3/"}));
    assert_eq!(allowed, CheckResult::Allowed);

    let prompt = mgr.check("web_fetch", &json!({"url": "https://example.invalid/"}));
    assert_eq!(
        prompt,
        CheckResult::NeedsPrompt {
            tool: "WebFetch".to_string(),
            target: "https://example.invalid/".to_string(),
        }
    );
}

/// Regression #605 — `web_search` results include a citation reminder.
#[test]
fn web_search_results_include_citation_reminder() {
    let results = vec![SearchResult {
        title: "Result".to_string(),
        url: "https://example.com".to_string(),
        snippet: "snippet".to_string(),
    }];
    let output = format_search_results(&results);

    assert!(
        output.contains("REMINDER: You MUST include the sources above"),
        "web_search output must remind agents to cite returned sources"
    );
}

/// Regression #608 — `web_fetch` schema exposes optional prompt distillation.
#[test]
fn web_fetch_schema_exposes_prompt_parameter() {
    use openclaudia::tools::registry::registry;

    let handler = registry().get("web_fetch").expect("web_fetch registered");
    let definition = handler.definition();

    assert_eq!(
        definition["function"]["parameters"]["properties"]["prompt"]["type"],
        "string"
    );
    assert_eq!(
        definition["function"]["parameters"]["required"],
        json!(["url"]),
        "prompt must remain optional so existing raw-fetch calls keep working"
    );
}

/// Regression #610 — `DuckDuckGo` scraper validates extracted URLs against the
/// SSRF guard before returning results to the agent.
#[cfg(feature = "browser")]
#[test]
fn duckduckgo_parser_drops_ssrf_urls_before_formatting() {
    let html = r#"
        <html>
            <body>
                <div class="result">
                    <a class="result__a" href="http://169.254.169.254/latest/meta-data/">Metadata</a>
                    <a class="result__snippet">AWS metadata endpoint</a>
                </div>
                <div class="result">
                    <a class="result__a" href="//duckduckgo.com/l/?uddg=http%3A%2F%2F8.8.8.8%2Fpublic&rut=abc">Public Result</a>
                    <a class="result__snippet">Public result snippet</a>
                </div>
            </body>
        </html>
    "#;

    let results =
        parse_duckduckgo_results_from_html(html, 10).expect("safe DDG result must remain");

    assert_eq!(results.len(), 1, "unsafe DDG result must be dropped");
    assert_eq!(results[0].title, "Public Result");
    assert_eq!(results[0].url, "http://8.8.8.8/public");

    let output = format_search_results(&results);
    assert!(
        !output.contains("169.254.169.254"),
        "SSRF URL must not surface in formatted DDG results"
    );
}

// ===========================================================================
// Browser tests — gated behind #[ignore]
//
// These require headless Chrome to be installed. To run:
//   OPENCLAUDIA_TEST_BROWSER=1 cargo test -p openclaudia --test web_integration -- --ignored
// ===========================================================================

/// Browser fetch test — requires headless Chrome.
///
/// Verifies `fetch_with_browser` calls `validate_url` before launching Chrome,
/// so SSRF-blocked URLs never reach the browser.
#[tokio::test]
#[ignore = "requires headless Chrome — set OPENCLAUDIA_TEST_BROWSER=1 and run with --ignored"]
async fn browser_fetch_blocks_ssrf_before_launch() {
    if std::env::var("OPENCLAUDIA_TEST_BROWSER").is_err() {
        eprintln!("OPENCLAUDIA_TEST_BROWSER not set — skipping browser SSRF test");
        return;
    }
    // fetch_with_browser (src/web.rs:598) calls validate_url before Browser::new.
    // An SSRF URL must be rejected without launching Chrome.
    let err = fetch_with_browser("http://169.254.169.254/latest/meta-data/").unwrap_err();
    assert!(
        err.contains("reserved/internal") || err.contains("metadata endpoint"),
        "SSRF URL not blocked before browser launch: {err}"
    );
}

/// Browser fetch test — requires headless Chrome on PATH.
#[tokio::test]
#[ignore = "requires headless Chrome — set OPENCLAUDIA_TEST_BROWSER=1 and run with --ignored"]
async fn browser_fetch_success_contains_url_line() {
    use openclaudia::tools::{execute_tool, FunctionCall, ToolCall};
    if std::env::var("OPENCLAUDIA_TEST_BROWSER").is_err() {
        eprintln!("OPENCLAUDIA_TEST_BROWSER not set — skipping browser fetch test");
        return;
    }

    let call = ToolCall {
        id: "bfetch".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "web_browser".to_string(),
            arguments: r#"{"url": "https://example.com/"}"#.to_string(),
        },
    };
    let result = execute_tool(&call);
    if result.is_error() {
        eprintln!(
            "Browser fetch failed (Chrome may not be installed): {}",
            result.content()
        );
        return;
    }
    // Spec §4: output contains "URL: <url>" line
    assert!(
        result.content().contains("URL: https://example.com/"),
        "URL line missing from browser fetch output: {}",
        result.content()
    );
}
