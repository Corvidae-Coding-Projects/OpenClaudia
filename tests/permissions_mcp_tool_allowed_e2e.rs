//! End-to-end tests for `config::PermissionsConfig::mcp_tool_allowed` —
//! per-server MCP allowlist semantics including the
//! "absent server means allow all" default (#619) and
//! the empty-allowlist-denies-all special case.
//!
//! Sprint 176 of the verification effort. Sprint 49 had
//! `validate()` coverage but `mcp_tool_allowed` was
//! uncovered in integration tests.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::config::PermissionsConfig;
use std::collections::HashMap;

const fn cfg_with_mcp(mcp: HashMap<String, Vec<String>>) -> PermissionsConfig {
    PermissionsConfig {
        enabled: true,
        default_allow: Vec::new(),
        mcp,
        project_proposal: None,
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Default semantics
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn default_permissions_allow_any_mcp_server_and_tool() {
    // PINS DEFAULT: empty mcp map → every server is unrestricted.
    let cfg = PermissionsConfig::default();
    assert!(cfg.mcp_tool_allowed("any-server", "any-tool"));
    assert!(cfg.mcp_tool_allowed("github", "create_issue"));
    assert!(cfg.mcp_tool_allowed("filesystem", "read_file"));
}

#[test]
fn server_absent_from_allowlist_yields_unrestricted() {
    // PINS DOC: a server not present in `mcp` map → all
    // its tools allowed (is_none_or branch).
    let cfg = cfg_with_mcp(HashMap::from([(
        "configured-server".to_string(),
        vec!["only-tool".to_string()],
    )]));
    assert!(
        cfg.mcp_tool_allowed("unconfigured-server", "whatever"),
        "absent server MUST allow all"
    );
    assert!(
        cfg.mcp_tool_allowed("unconfigured-server", "another"),
        "absent server allows even another tool"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Configured server allowlist
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn configured_server_allows_listed_tool() {
    let cfg = cfg_with_mcp(HashMap::from([(
        "github".to_string(),
        vec!["create_issue".to_string(), "list_repos".to_string()],
    )]));
    assert!(cfg.mcp_tool_allowed("github", "create_issue"));
    assert!(cfg.mcp_tool_allowed("github", "list_repos"));
}

#[test]
fn configured_server_denies_unlisted_tool() {
    // PINS DOC: if a server IS configured with an allowlist,
    // unlisted tools are DENIED.
    let cfg = cfg_with_mcp(HashMap::from([(
        "github".to_string(),
        vec!["create_issue".to_string()],
    )]));
    assert!(
        !cfg.mcp_tool_allowed("github", "delete_repo"),
        "unlisted tool MUST be denied"
    );
    assert!(
        !cfg.mcp_tool_allowed("github", "any_other"),
        "all unlisted denied"
    );
}

#[test]
fn empty_allowlist_for_a_server_denies_every_tool() {
    // PINS EDGE: explicit empty Vec means "no tools allowed
    // from this server" — distinct from absence.
    let cfg = cfg_with_mcp(HashMap::from([(
        "locked-down-server".to_string(),
        Vec::new(),
    )]));
    assert!(
        !cfg.mcp_tool_allowed("locked-down-server", "any-tool"),
        "empty allowlist MUST deny all tools (not allow all)"
    );
    assert!(
        !cfg.mcp_tool_allowed("locked-down-server", ""),
        "empty allowlist denies even empty tool name"
    );
}

#[test]
fn allowlist_match_is_case_sensitive() {
    // PINS DOC: name comparison is exact-string match.
    let cfg = cfg_with_mcp(HashMap::from([(
        "github".to_string(),
        vec!["create_issue".to_string()],
    )]));
    assert!(
        !cfg.mcp_tool_allowed("github", "Create_Issue"),
        "uppercase variant MUST NOT match"
    );
    assert!(
        !cfg.mcp_tool_allowed("github", "CREATE_ISSUE"),
        "all-caps variant MUST NOT match"
    );
}

#[test]
fn server_name_match_is_case_sensitive() {
    // PINS DOC: server lookup is exact-string.
    let cfg = cfg_with_mcp(HashMap::from([(
        "github".to_string(),
        vec!["create_issue".to_string()],
    )]));
    // "GitHub" is NOT in the map → server-absent branch → allowed.
    assert!(
        cfg.mcp_tool_allowed("GitHub", "create_issue"),
        "different-case server name treated as absent (allowed)"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Multi-server independence
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn two_servers_have_independent_allowlists() {
    let mut mcp = HashMap::new();
    mcp.insert("server-a".to_string(), vec!["tool-a1".to_string()]);
    mcp.insert("server-b".to_string(), vec!["tool-b1".to_string()]);
    let cfg = cfg_with_mcp(mcp);

    assert!(cfg.mcp_tool_allowed("server-a", "tool-a1"));
    assert!(!cfg.mcp_tool_allowed("server-a", "tool-b1"));
    assert!(cfg.mcp_tool_allowed("server-b", "tool-b1"));
    assert!(!cfg.mcp_tool_allowed("server-b", "tool-a1"));
}

#[test]
fn one_server_locked_down_other_unrestricted() {
    let cfg = cfg_with_mcp(HashMap::from([("locked".to_string(), Vec::new())]));
    // "locked" denies all.
    assert!(!cfg.mcp_tool_allowed("locked", "x"));
    // Other server: not in map → unrestricted.
    assert!(cfg.mcp_tool_allowed("unrestricted", "x"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — YAML round-trip for the mcp field
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn yaml_with_mcp_block_propagates_to_allowlist() {
    let yaml = r"
enabled: true
default_allow: []
mcp:
  github:
    - create_issue
    - list_repos
  filesystem: []
";
    let cfg: PermissionsConfig = serde_yaml::from_str(yaml).expect("ok");
    assert!(cfg.mcp_tool_allowed("github", "create_issue"));
    assert!(cfg.mcp_tool_allowed("github", "list_repos"));
    assert!(!cfg.mcp_tool_allowed("github", "delete_repo"));
    // filesystem with [] denies all.
    assert!(!cfg.mcp_tool_allowed("filesystem", "read_file"));
    // Unknown server: unrestricted.
    assert!(cfg.mcp_tool_allowed("other", "any-tool"));
}

#[test]
fn yaml_without_mcp_block_yields_unrestricted_for_every_server() {
    let yaml = "enabled: true\ndefault_allow: []";
    let cfg: PermissionsConfig = serde_yaml::from_str(yaml).expect("ok");
    assert!(cfg.mcp_tool_allowed("any-server", "any-tool"));
}

#[test]
fn empty_yaml_yields_default_unrestricted_mcp() {
    let cfg: PermissionsConfig = serde_yaml::from_str("{}").expect("ok");
    assert!(cfg.mcp_tool_allowed("any-server", "any-tool"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — PermissionsConfig defaults
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn default_enabled_is_true_for_deny_by_default() {
    // PINS SECURITY: default enabled = true (deny-by-default).
    let cfg = PermissionsConfig::default();
    assert!(
        cfg.enabled,
        "PINS DEFAULT: permissions MUST be enabled (deny-by-default)"
    );
}

#[test]
fn default_default_allow_is_empty() {
    let cfg = PermissionsConfig::default();
    assert!(
        cfg.default_allow.is_empty(),
        "PINS DEFAULT: no pre-allowed globs"
    );
}

#[test]
fn default_mcp_is_empty_map() {
    let cfg = PermissionsConfig::default();
    assert!(
        cfg.mcp.is_empty(),
        "PINS DEFAULT: no per-server MCP restrictions"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Edge cases
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn empty_server_name_with_no_allowlist_is_unrestricted() {
    let cfg = PermissionsConfig::default();
    // Empty server name not in map → absent → allowed.
    assert!(cfg.mcp_tool_allowed("", "some-tool"));
}

#[test]
fn empty_tool_name_against_unrestricted_server_allowed() {
    let cfg = PermissionsConfig::default();
    assert!(cfg.mcp_tool_allowed("server", ""));
}

#[test]
fn tool_name_with_unicode_handled_exactly() {
    let cfg = cfg_with_mcp(HashMap::from([(
        "server".to_string(),
        vec!["日本語ツール".to_string()],
    )]));
    assert!(cfg.mcp_tool_allowed("server", "日本語ツール"));
    assert!(!cfg.mcp_tool_allowed("server", "ascii-only"));
}

#[test]
fn repeated_calls_yield_same_result() {
    // PINS PURE: no caching, no mutation.
    let cfg = cfg_with_mcp(HashMap::from([(
        "server".to_string(),
        vec!["tool".to_string()],
    )]));
    for _ in 0..10 {
        assert!(cfg.mcp_tool_allowed("server", "tool"));
        assert!(!cfg.mcp_tool_allowed("server", "denied"));
    }
}
