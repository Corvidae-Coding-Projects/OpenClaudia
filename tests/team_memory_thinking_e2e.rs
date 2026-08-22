//! End-to-end tests for the production team-memory fail-closed boundary and
//! user-only compatibility wrapper, plus `thinking` effort helpers. Detailed
//! causal compatibility behavior remains unit-covered beside the authenticated
//! production replica.
//!
//! Sprint 59 of the verification effort.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::config::MemoryConfig;
use openclaudia::team_memory::{MemoryScope, TeamMemoryError, TeamMemoryStore};
use openclaudia::thinking::{
    anthropic_thinking_budget, env_effort_override, env_max_thinking_tokens,
    has_ultrathink_in_messages, has_ultrathink_keyword, resolve_effort, ULTRATHINK_BUDGET_TOKENS,
};
use serde_json::json;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::TempDir;

// ───────────────────────────────────────────────────────────────────────────
// Env-mutation lock — thinking env-var tests must serialize.
// ───────────────────────────────────────────────────────────────────────────

fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct EnvGuard {
    key: String,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(key: &str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        unsafe {
            std::env::set_var(key, value);
        }
        Self {
            key: key.to_string(),
            previous,
        }
    }
    fn remove(key: &str) -> Self {
        let previous = std::env::var(key).ok();
        unsafe {
            std::env::remove_var(key);
        }
        Self {
            key: key.to_string(),
            previous,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe {
            match self.previous.take() {
                Some(v) => std::env::set_var(&self.key, v),
                None => std::env::remove_var(&self.key),
            }
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// TeamMemoryStore helpers
// ───────────────────────────────────────────────────────────────────────────

/// Build a user-only store (no team path).
fn open_user_only() -> (TempDir, TeamMemoryStore) {
    let tmp = TempDir::new().expect("tempdir");
    let user_path = tmp.path().join("user.db");
    let cfg = MemoryConfig::default();
    let store = TeamMemoryStore::open(&user_path, &cfg).expect("open");
    (tmp, store)
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — TeamMemoryStore::open
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn open_with_team_path_is_rejected_without_creating_the_directory() {
    let tmp = TempDir::new().expect("tempdir");
    let user_path = tmp.path().join("user.db");
    let team_dir = tmp.path().join("new-team-dir");
    assert!(!team_dir.exists(), "premise: team dir absent");
    let cfg = MemoryConfig {
        team_memory_path: Some(team_dir.clone()),
        ..MemoryConfig::default()
    };
    let Err(error) = TeamMemoryStore::open(&user_path, &cfg) else {
        panic!("shared path is not authenticated authority");
    };
    assert!(error.to_string().contains("paths are not authorization"));
    assert!(!team_dir.exists(), "rejected path must not be created");
}

#[test]
fn open_without_team_path_yields_user_only_store() {
    let (_tmp, store) = open_user_only();
    assert!(
        store.team_path().is_none(),
        "user-only store MUST have no team_path"
    );
}

#[test]
fn team_identity_selector_does_not_open_a_legacy_replica() {
    let tmp = TempDir::new().expect("tempdir");
    let user_path = tmp.path().join("user.db");
    let cfg = MemoryConfig {
        team_id: Some(
            "team-0123456789abcdef0123456789abcdef"
                .parse()
                .expect("team ID"),
        ),
        ..MemoryConfig::default()
    };
    let store = TeamMemoryStore::open(&user_path, &cfg).expect("user-only wrapper");
    assert!(!store.has_team());
    assert!(store.team_path().is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Team scope errors on user-only store
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn save_to_team_scope_on_user_only_store_errors_team_unavailable() {
    let (_tmp, store) = open_user_only();
    let outcome = store.save_archival(MemoryScope::Team, "content", &[]);
    let err = outcome.expect_err("MUST error");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("team_unavailable")
            || msg.to_lowercase().contains("team")
            || msg.contains("TeamUnavailable")
            || matches!(
                err.downcast_ref::<TeamMemoryError>(),
                Some(TeamMemoryError::TeamUnavailable)
            ),
        "MUST surface TeamUnavailable; got {err:?}"
    );
}

#[test]
fn list_team_scope_on_user_only_store_errors() {
    let (_tmp, store) = open_user_only();
    let outcome = store.list_archival(MemoryScope::Team, 10);
    assert!(
        outcome.is_err(),
        "list(Team) on user-only MUST error; got {outcome:?}"
    );
}

#[test]
fn update_core_team_scope_on_user_only_errors() {
    let (_tmp, store) = open_user_only();
    let outcome = store.update_core(MemoryScope::Team, "section", "value");
    assert!(outcome.is_err());
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Scope-mediated save + list
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn save_to_user_scope_appears_in_user_list() {
    let (_tmp, store) = open_user_only();
    let id = store
        .save_archival(MemoryScope::User, "user content", &[])
        .expect("save");
    assert!(id > 0);
    let entries = store.list_archival(MemoryScope::User, 10).expect("list");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].entry.content, "user content");
    assert_eq!(entries[0].scope, MemoryScope::User);
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — has_ultrathink_keyword
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn detects_plain_ultrathink_in_text() {
    assert!(has_ultrathink_keyword("please ultrathink this"));
}

#[test]
fn detects_uppercase_ultrathink_case_insensitive() {
    assert!(has_ultrathink_keyword("ULTRATHINK now"));
    assert!(has_ultrathink_keyword("UltraThink that"));
}

#[test]
fn detects_think_ultra_hard_phrase() {
    assert!(has_ultrathink_keyword("please think ultra hard about this"));
}

#[test]
fn detects_think_ultrahard_phrase() {
    assert!(has_ultrathink_keyword("now think ultrahard"));
}

#[test]
fn does_not_detect_ultrathink_as_substring_of_longer_identifier() {
    // Documented: "ultrathink must be a whole word".
    assert!(
        !has_ultrathink_keyword("my_ultrathinkfunction"),
        "embedded ultrathink MUST NOT trigger (whole-word only)"
    );
}

#[test]
fn does_not_detect_unrelated_text() {
    assert!(!has_ultrathink_keyword("think about it"));
    assert!(!has_ultrathink_keyword("ultra fast"));
    assert!(!has_ultrathink_keyword(""));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — has_ultrathink_in_messages
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn has_ultrathink_in_messages_finds_in_user_role() {
    let msgs = vec![json!({"role": "user", "content": "ultrathink this"})];
    assert!(has_ultrathink_in_messages(&msgs));
}

#[test]
fn has_ultrathink_in_messages_ignores_assistant_role() {
    let msgs = vec![json!({"role": "assistant", "content": "ultrathink"})];
    assert!(
        !has_ultrathink_in_messages(&msgs),
        "ultrathink in assistant-role MUST NOT trigger (user-only)"
    );
}

#[test]
fn has_ultrathink_in_messages_returns_true_if_any_user_message_has_it() {
    let msgs = vec![
        json!({"role": "user", "content": "first message"}),
        json!({"role": "assistant", "content": "ok"}),
        json!({"role": "user", "content": "now ultrathink please"}),
    ];
    assert!(has_ultrathink_in_messages(&msgs));
}

#[test]
fn has_ultrathink_in_messages_empty_array_returns_false() {
    assert!(!has_ultrathink_in_messages(&[]));
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — env_effort_override parsing
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn env_effort_override_unset_or_auto_yields_some_none() {
    let _l = env_lock();
    let _g = EnvGuard::set("CLAUDE_CODE_EFFORT_LEVEL", "unset");
    assert_eq!(env_effort_override(), Some(None));
    let _g = EnvGuard::set("CLAUDE_CODE_EFFORT_LEVEL", "auto");
    assert_eq!(env_effort_override(), Some(None));
}

#[test]
fn env_effort_override_documented_levels_yield_some_some() {
    let _l = env_lock();
    for level in &["low", "medium", "high", "max"] {
        let _g = EnvGuard::set("CLAUDE_CODE_EFFORT_LEVEL", level);
        assert_eq!(
            env_effort_override(),
            Some(Some((*level).to_string())),
            "{level} MUST resolve to Some(Some({level}))"
        );
    }
}

#[test]
fn env_effort_override_case_insensitive() {
    let _l = env_lock();
    let _g = EnvGuard::set("CLAUDE_CODE_EFFORT_LEVEL", "HIGH");
    assert_eq!(env_effort_override(), Some(Some("high".to_string())));
}

#[test]
fn env_effort_override_unrecognized_yields_none() {
    let _l = env_lock();
    let _g = EnvGuard::set("CLAUDE_CODE_EFFORT_LEVEL", "totally-not-a-level");
    assert!(env_effort_override().is_none());
}

#[test]
fn env_effort_override_absent_yields_none() {
    let _l = env_lock();
    let _g = EnvGuard::remove("CLAUDE_CODE_EFFORT_LEVEL");
    assert!(env_effort_override().is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — env_max_thinking_tokens parsing
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn env_max_thinking_tokens_positive_integer_parses() {
    let _l = env_lock();
    let _g = EnvGuard::set("MAX_THINKING_TOKENS", "32000");
    assert_eq!(env_max_thinking_tokens(), Some(32000));
}

#[test]
fn env_max_thinking_tokens_zero_yields_none() {
    let _l = env_lock();
    let _g = EnvGuard::set("MAX_THINKING_TOKENS", "0");
    assert!(
        env_max_thinking_tokens().is_none(),
        "0 MUST yield None (positive-only filter)"
    );
}

#[test]
fn env_max_thinking_tokens_non_numeric_yields_none() {
    let _l = env_lock();
    let _g = EnvGuard::set("MAX_THINKING_TOKENS", "not a number");
    assert!(env_max_thinking_tokens().is_none());
}

#[test]
fn env_max_thinking_tokens_absent_yields_none() {
    let _l = env_lock();
    let _g = EnvGuard::remove("MAX_THINKING_TOKENS");
    assert!(env_max_thinking_tokens().is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section H — resolve_effort precedence
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn resolve_effort_env_unset_wins_over_keyword_and_default() {
    let _l = env_lock();
    let _g = EnvGuard::set("CLAUDE_CODE_EFFORT_LEVEL", "unset");
    let msgs = vec![json!({"role": "user", "content": "ultrathink"})];
    let outcome = resolve_effort("medium", &msgs);
    assert!(outcome.is_none(), "env=unset MUST win → no effort emitted");
}

#[test]
fn resolve_effort_keyword_promotes_to_high_when_no_env_override() {
    let _l = env_lock();
    let _g = EnvGuard::remove("CLAUDE_CODE_EFFORT_LEVEL");
    let msgs = vec![json!({"role": "user", "content": "ultrathink this"})];
    let outcome = resolve_effort("medium", &msgs);
    assert_eq!(outcome, Some("high".to_string()));
}

#[test]
fn resolve_effort_falls_through_to_base_when_no_env_and_no_keyword() {
    let _l = env_lock();
    let _g = EnvGuard::remove("CLAUDE_CODE_EFFORT_LEVEL");
    let msgs = vec![json!({"role": "user", "content": "nothing special"})];
    let outcome = resolve_effort("low", &msgs);
    assert_eq!(outcome, Some("low".to_string()));
}

// ───────────────────────────────────────────────────────────────────────────
// Section I — anthropic_thinking_budget
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn anthropic_thinking_budget_env_max_overrides_effort() {
    let _l = env_lock();
    let _g = EnvGuard::set("MAX_THINKING_TOKENS", "12345");
    let outcome = anthropic_thinking_budget(Some("low"));
    assert_eq!(outcome, Some(12345), "env MAX MUST win over effort=low");
}

#[test]
fn anthropic_thinking_budget_high_yields_ultrathink_budget() {
    let _l = env_lock();
    let _g = EnvGuard::remove("MAX_THINKING_TOKENS");
    assert_eq!(
        anthropic_thinking_budget(Some("high")),
        Some(ULTRATHINK_BUDGET_TOKENS)
    );
    assert_eq!(
        anthropic_thinking_budget(Some("max")),
        Some(ULTRATHINK_BUDGET_TOKENS)
    );
}

#[test]
fn anthropic_thinking_budget_low_or_medium_yields_none() {
    let _l = env_lock();
    let _g = EnvGuard::remove("MAX_THINKING_TOKENS");
    assert!(anthropic_thinking_budget(Some("low")).is_none());
    assert!(anthropic_thinking_budget(Some("medium")).is_none());
}

#[test]
fn anthropic_thinking_budget_none_effort_yields_none() {
    let _l = env_lock();
    let _g = EnvGuard::remove("MAX_THINKING_TOKENS");
    assert!(anthropic_thinking_budget(None).is_none());
}

#[test]
fn ultrathink_budget_tokens_constant_matches_documented_value() {
    // Documented: 31999 (matches CC's `_Q0.ULTRATHINK`).
    assert_eq!(ULTRATHINK_BUDGET_TOKENS, 31999);
}
