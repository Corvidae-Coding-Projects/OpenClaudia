//! End-to-end tests for `permissions::PermissionManager` glob
//! match semantics — `*` (non-`/`), `**` (cross-`/`), `?`
//! (single non-`/` char), special-char escaping for `.`/`(`/etc.
//! Pins permission-rule matching after mandatory call classification.
//! Pure glob edge cases that cannot be valid tool targets are pinned by the
//! permissions module's internal glob tests instead.
//!
//! Sprint 213 of the verification effort.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::permissions::{
    CheckResult, PermissionDecision, PermissionManager, PermissionRule,
};
use serde_json::json;
use tempfile::TempDir;

fn mgr_with_rule(pattern: &str, decision: PermissionDecision) -> (PermissionManager, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("rules.json");
    let mut mgr = PermissionManager::new(path, true, Vec::new());
    mgr.add_session_rule(PermissionRule {
        tool: "Bash".to_string(),
        pattern: pattern.to_string(),
        decision,
    });
    (mgr, dir)
}

fn matches_pattern(pattern: &str, command: &str) -> bool {
    let (mgr, _dir) = mgr_with_rule(pattern, PermissionDecision::Allow);
    let outcome = mgr.check("bash", &json!({"command": command}));
    matches!(outcome, CheckResult::Allowed)
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Star (*) matches non-slash characters
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn star_matches_zero_chars_with_prefix() {
    // PINS: "ls*" matches just "ls".
    assert!(matches_pattern("ls*", "ls"));
}

#[test]
fn star_matches_multiple_non_slash_chars() {
    assert!(matches_pattern("echo *", "echo hello"));
}

#[test]
fn star_alone_matches_any_non_slash_command() {
    assert!(matches_pattern("*", "ls"));
    assert!(matches_pattern("*", "echo"));
}

#[test]
fn star_does_not_cross_slash() {
    // PINS DOC: single * matches [^/]*, so "ls *" doesn't match "ls /tmp".
    assert!(!matches_pattern("echo *", "echo /tmp/x"));
}

#[test]
fn star_in_middle_does_not_cross_slash() {
    assert!(!matches_pattern("echo*x", "echo/x"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Double-star (**) crosses slashes
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn double_star_matches_paths_with_slashes() {
    // PINS DOC: `**` matches everything including path separators.
    assert!(matches_pattern("**", "ls /tmp/x"));
    assert!(matches_pattern("**", "cat /a/b/c/d/file.txt"));
}

#[test]
fn double_star_with_prefix_matches_descending_paths() {
    assert!(matches_pattern("cat **", "cat /tmp/file.txt"));
}

#[test]
fn double_star_followed_by_slash_then_path_pattern() {
    assert!(matches_pattern("**/file.txt", "/a/b/c/file.txt"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Question mark (?) matches single non-slash char
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn question_mark_matches_exactly_one_non_slash_char() {
    assert!(matches_pattern("ls?", "lsx"));
    assert!(matches_pattern("ls?", "ls1"));
}

#[test]
fn question_mark_does_not_match_zero_chars() {
    // PINS: ? = exactly 1 char, NOT optional.
    assert!(!matches_pattern("ls?", "ls"));
}

#[test]
fn question_mark_does_not_match_two_chars() {
    assert!(!matches_pattern("ls?", "lsxx"));
}

#[test]
fn question_mark_does_not_match_slash() {
    // PINS: ? = [^/], so slash is excluded.
    assert!(!matches_pattern("ls?", "ls/"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Regex special chars are escaped
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn dot_is_literal_not_any_char() {
    // PINS DOC: `.` in glob is literal, NOT regex-any-char.
    assert!(matches_pattern("file.txt", "file.txt"));
    // Without escape, dot would match "fileXtxt" — verify it does NOT.
    assert!(!matches_pattern("file.txt", "fileXtxt"));
}

#[test]
fn parens_are_literal_not_grouping() {
    assert!(matches_pattern("func(arg)", "func(arg)"));
    assert!(!matches_pattern("func(arg)", "funcarg"));
}

#[test]
fn plus_is_literal_not_one_or_more() {
    assert!(matches_pattern("a+b", "a+b"));
    assert!(!matches_pattern("a+b", "aab"));
}

#[test]
fn dollar_is_literal_not_end_anchor() {
    assert!(matches_pattern("$HOME", "$HOME"));
}

#[test]
fn caret_is_literal_not_start_anchor() {
    assert!(matches_pattern("^test", "^test"));
}

#[test]
fn pipe_is_literal_not_alternation() {
    assert!(matches_pattern("a|b", "a|b"));
    assert!(!matches_pattern("a|b", "a"));
    assert!(!matches_pattern("a|b", "b"));
}

#[test]
fn backslash_is_escaped() {
    assert!(matches_pattern(r"a\b", r"a\b"));
}

#[test]
fn brackets_are_escaped_to_literal() {
    // PINS DOC: glob_to_regex escapes `[` and `]` as literals.
    assert!(matches_pattern("[ab]_foo", "[ab]_foo"));
    // It does NOT treat as char class — "a_foo" doesn't match.
    assert!(!matches_pattern("[ab]_foo", "a_foo"));
}

#[test]
fn curly_braces_are_escaped() {
    assert!(matches_pattern("{a,b}", "{a,b}"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Anchoring
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn pattern_is_fully_anchored_with_caret_and_dollar() {
    // PINS DOC: glob_to_regex prepends ^ and appends $.
    // So "ls" matches "ls" but NOT "ls -la".
    assert!(matches_pattern("ls", "ls"));
    assert!(!matches_pattern("ls", "ls -la"));
}

#[test]
fn prefix_only_match_uses_star_suffix() {
    // To allow "ls" prefix matches, use "ls*".
    assert!(matches_pattern("ls*", "ls"));
    assert!(matches_pattern("ls*", "lsabc"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Empty pattern + edge inputs
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn empty_pattern_cannot_authorize_an_empty_required_command() {
    // The primitive glob is still ^$, but an empty required Bash target is an
    // invalid call and is denied before rule matching.
    assert!(!matches_pattern("", "ls"));
    assert!(!matches_pattern("", ""));
}

#[test]
fn pattern_with_only_double_star_matches_any_valid_command_not_empty() {
    // `**` remains broad for valid targets; it must not turn a missing/empty
    // required effect target into an allowed invocation.
    assert!(!matches_pattern("**", ""));
    assert!(matches_pattern("**", "anything goes"));
    assert!(matches_pattern("**", "with/slashes"));
}

#[test]
fn unicode_command_matches_unicode_pattern_literally() {
    // PINS: unicode chars pass through unchanged.
    assert!(matches_pattern("日本語", "日本語"));
    assert!(!matches_pattern("日本語", "English"));
}

#[test]
fn unicode_with_star_suffix() {
    assert!(matches_pattern("日本語*", "日本語"));
    assert!(matches_pattern("日本語*", "日本語abc"));
}
