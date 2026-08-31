//! End-to-end tests for the Bash deny-only defence-in-depth policy:
//! `validate_command`, `dangerous_shell_construct`, environment scrubbing,
//! and the `MAX_COMMAND_LEN` cap.
//!
//! Sprint 84 of the verification effort. Sprint 23 covered the
//! denylist + env-scrub paths; sprint 9
//! (`tools_security_e2e`) covered the attack catalog. This file pins the
//! structural diagnostic catalog without treating it as effect authority.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::{
    dangerous_shell_construct, is_sensitive_env_pub, validate_command, MAX_COMMAND_LEN,
};

// ───────────────────────────────────────────────────────────────────────────
// Section A — MAX_COMMAND_LEN + validate_command length cap
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn max_command_len_constant_matches_documented_value() {
    assert_eq!(MAX_COMMAND_LEN, 4096);
}

#[test]
fn validate_command_at_max_length_succeeds() {
    let cmd: String = std::iter::repeat_n('a', MAX_COMMAND_LEN).collect();
    validate_command(&cmd).expect("at-max MUST validate");
}

#[test]
fn validate_command_over_max_length_errors_with_byte_count() {
    let cmd: String = std::iter::repeat_n('a', MAX_COMMAND_LEN + 1).collect();
    let err = validate_command(&cmd).unwrap_err();
    assert!(
        err.contains("4096"),
        "MUST surface the cap in the error; got {err:?}"
    );
    assert!(
        err.contains(&(MAX_COMMAND_LEN + 1).to_string()),
        "MUST surface observed length; got {err:?}"
    );
}

#[test]
fn validate_command_short_safe_command_succeeds() {
    validate_command("ls -la").expect("ls -la MUST validate");
    validate_command("pwd").expect("pwd MUST validate");
    validate_command("cat README.md").expect("cat MUST validate");
}

#[test]
fn validate_command_denylisted_command_errors_with_explanation() {
    // rm -rf / is in the documented hard denylist.
    let outcome = validate_command("rm -rf /");
    let err = outcome.unwrap_err();
    assert!(
        err.contains("denylist") || err.contains("rejected"),
        "MUST surface denylist refusal; got {err:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — dangerous_shell_construct catalog
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn dangerous_detects_dollar_command_substitution() {
    let outcome = dangerous_shell_construct("ls $(pwd)");
    let reason = outcome.expect("MUST detect");
    assert!(
        reason.contains("substitution") || reason.contains("$("),
        "reason MUST mention substitution; got {reason:?}"
    );
}

#[test]
fn dangerous_detects_backtick_command_substitution() {
    let outcome = dangerous_shell_construct("cat `ls`");
    assert!(outcome.is_some(), "MUST detect backtick substitution");
}

#[test]
fn dangerous_detects_process_substitution() {
    assert!(dangerous_shell_construct("diff <(ls) <(pwd)").is_some());
    assert!(dangerous_shell_construct("tee >(cat)").is_some());
}

#[test]
fn dangerous_detects_pipe_to_interpreter_variants() {
    for cmd in &["cat file | sh", "ls | bash", "cat | python", "x | node"] {
        assert!(
            dangerous_shell_construct(cmd).is_some(),
            "MUST detect pipe-to-interpreter {cmd:?}"
        );
    }
}

#[test]
fn dangerous_does_not_flag_pipe_to_filter() {
    // `| grep`, `| awk` are filters — safe.
    assert!(
        dangerous_shell_construct("ls | grep foo").is_none(),
        "pipe to filter (grep) MUST NOT be dangerous"
    );
    assert!(dangerous_shell_construct("cat file | wc -l").is_none());
}

#[test]
fn dangerous_detects_eval_exec_source_keywords() {
    assert!(dangerous_shell_construct("eval ls").is_some());
    assert!(dangerous_shell_construct("exec ls").is_some());
    assert!(dangerous_shell_construct("source script.sh").is_some());
}

#[test]
fn dangerous_does_not_flag_substring_matches_for_interpreter_keywords() {
    // "execute_query" / "source_file.txt" are NOT eval/exec/source.
    // (Pinned because the regex MUST anchor on word boundaries.)
    assert!(dangerous_shell_construct("ls source_file.txt").is_none());
    assert!(dangerous_shell_construct("cat execute_query.sql").is_none());
}

#[test]
fn dangerous_detects_find_exec_flag() {
    assert!(dangerous_shell_construct("find . -exec rm {} \\;").is_some());
    assert!(dangerous_shell_construct("find . -execdir ls {} \\;").is_some());
    assert!(dangerous_shell_construct("find . -delete").is_some());
    assert!(dangerous_shell_construct("find . -ok rm {} \\;").is_some());
}

#[test]
fn dangerous_detects_compound_commands() {
    assert!(dangerous_shell_construct("ls; pwd").is_some());
    assert!(dangerous_shell_construct("ls && pwd").is_some());
    assert!(dangerous_shell_construct("ls || pwd").is_some());
}

#[test]
fn dangerous_detects_write_redirections() {
    assert!(dangerous_shell_construct("ls > out").is_some());
    assert!(dangerous_shell_construct("ls >> log").is_some());
}

#[test]
fn dangerous_does_not_flag_input_redirect_from_file() {
    // Reading from a file as stdin is read-only.
    assert!(
        dangerous_shell_construct("sort < file.txt").is_none(),
        "stdin-from-file MUST NOT be dangerous"
    );
}

#[test]
fn dangerous_returns_none_for_plain_safe_commands() {
    for cmd in &["ls", "pwd", "cat README.md", "echo hello", "git status"] {
        assert!(
            dangerous_shell_construct(cmd).is_none(),
            "plain safe {cmd:?} MUST be free of dangerous constructs"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — is_sensitive_env_pub
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn is_sensitive_env_detects_documented_api_key_suffixes() {
    assert!(is_sensitive_env_pub("ANTHROPIC_API_KEY"));
    assert!(is_sensitive_env_pub("OPENAI_API_KEY"));
    assert!(is_sensitive_env_pub("MY_CUSTOM_API_KEY"));
}

#[test]
fn is_sensitive_env_detects_token_suffixes() {
    assert!(is_sensitive_env_pub("GITHUB_TOKEN"));
    assert!(is_sensitive_env_pub("CLAUDE_CODE_OAUTH_TOKEN"));
    assert!(is_sensitive_env_pub("SOMETHING_TOKEN"));
}

#[test]
fn is_sensitive_env_is_case_insensitive() {
    assert!(is_sensitive_env_pub("anthropic_api_key"));
    assert!(is_sensitive_env_pub("github_token"));
}

#[test]
fn is_sensitive_env_does_not_flag_benign_env_keys() {
    assert!(!is_sensitive_env_pub("PATH"));
    assert!(!is_sensitive_env_pub("HOME"));
    assert!(!is_sensitive_env_pub("CARGO_HOME"));
    assert!(!is_sensitive_env_pub("PWD"));
    assert!(!is_sensitive_env_pub("USER"));
}
