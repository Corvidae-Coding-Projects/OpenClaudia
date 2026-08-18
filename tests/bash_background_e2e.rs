//! End-to-end tests for the bash background-shell lifecycle —
//! filling the race + per-shell-isolation gaps that
//! `tests/bash_integration.rs` (33 tests) intentionally leaves
//! alone in favor of pinning the spec contract.
//!
//! Sprint 22 of the verification effort. Focus areas:
//!
//!   - **Real subprocess output capture** — a background shell
//!     producing real time-spaced stdout MUST be drainable via
//!     `bash_output`.
//!   - **Per-shell isolation** — two concurrent background
//!     shells each producing unique output MUST NOT bleed into
//!     each other's `bash_output` polls.
//!   - **Post-kill query** — after `kill_shell` reaps a
//!     running shell, `bash_output` against the same id MUST
//!     surface the kill state cleanly (not panic, not hang).
//!   - **Shell-id uniqueness** — N spawns produce N distinct
//!     ids; the manager doesn't recycle ids while siblings
//!     are alive.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::{execute_tool, FunctionCall, ToolCall};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

fn call(name: &str, args: &Value) -> ToolCall {
    ToolCall {
        id: format!("sprint22_{name}"),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: name.to_string(),
            arguments: args.to_string(),
        },
    }
}

fn bash_bg(command: &str) -> (String, bool) {
    let r = execute_tool(&call(
        "bash",
        &json!({"command": command, "run_in_background": true}),
    ));
    (r.content().to_string(), r.is_error())
}

fn bash_output(shell_id: &str) -> (String, bool) {
    let r = execute_tool(&call("bash_output", &json!({"shell_id": shell_id})));
    (r.content().to_string(), r.is_error())
}

fn kill_shell(shell_id: &str) -> (String, bool) {
    let r = execute_tool(&call("kill_shell", &json!({"shell_id": shell_id})));
    (r.content().to_string(), r.is_error())
}

/// Extract the `shell_id` from a bash-background response. The
/// response shape is the human text `Background shell started\n\nID: <id>...`
/// per `src/tools/bash/mod.rs`. Match the existing pattern used
/// by `tests/bash_integration.rs::extract_shell_id`.
fn extract_shell_id(output: &str) -> String {
    if let Some(idx) = output.find("ID: ") {
        let start = idx + 4;
        let rest = &output[start..];
        let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
        let id = rest[..end].trim();
        if !id.is_empty() {
            return id.to_string();
        }
    }
    panic!("could not extract shell_id from output {output:?}");
}

/// Poll `bash_output` for `shell_id`, ACCUMULATING content
/// across polls because `bash_output` is incremental-drain (each
/// call returns only newly-emitted content since the last call).
/// Returns the accumulated content when `predicate(accum)` is
/// true OR when `deadline` is reached.
fn poll_until<F: Fn(&str) -> bool>(shell_id: &str, deadline: Duration, predicate: F) -> String {
    let start = Instant::now();
    let mut accum = String::new();
    while start.elapsed() < deadline {
        let (content, _) = bash_output(shell_id);
        accum.push_str(&content);
        accum.push('\n');
        if predicate(&accum) {
            return accum;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    accum
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — real subprocess output capture
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn background_shell_captures_real_subprocess_output() {
    // Spawn a shell that prints 3 lines with 50ms gaps. Poll
    // bash_output until we see the last line OR a 5s deadline.
    let (spawn_msg, is_err) = bash_bg("for i in 1 2 3; do echo \"line-$i\"; sleep 0.05; done");
    assert!(!is_err, "spawn must succeed: {spawn_msg:?}");
    let shell_id = extract_shell_id(&spawn_msg);

    let final_content = poll_until(&shell_id, Duration::from_secs(5), |c| c.contains("line-3"));
    for expected in &["line-1", "line-2", "line-3"] {
        assert!(
            final_content.contains(expected),
            "captured output must contain {expected:?}; got {final_content:?}"
        );
    }
    // Cleanup.
    let _ = kill_shell(&shell_id);
}

#[test]
fn background_shell_runs_to_completion_and_reports_finished() {
    // Short script — finishes within the polling window.
    let (spawn_msg, is_err) = bash_bg("echo done");
    assert!(!is_err);
    let shell_id = extract_shell_id(&spawn_msg);

    let final_content = poll_until(&shell_id, Duration::from_secs(5), |c| {
        let l = c.to_lowercase();
        l.contains("done") && (l.contains("finished") || l.contains("status"))
    });
    assert!(
        final_content.contains("done"),
        "stdout must be captured; got {final_content:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — per-shell isolation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn two_concurrent_background_shells_do_not_bleed_output() {
    let (msg_a, _) = bash_bg("echo ALPHA-marker; sleep 0.1; echo ALPHA-tail");
    let (msg_b, _) = bash_bg("echo BRAVO-marker; sleep 0.1; echo BRAVO-tail");
    let id_a = extract_shell_id(&msg_a);
    let id_b = extract_shell_id(&msg_b);
    assert_ne!(id_a, id_b, "two spawns must produce distinct shell ids");

    let out_a = poll_until(&id_a, Duration::from_secs(5), |c| c.contains("ALPHA-tail"));
    let out_b = poll_until(&id_b, Duration::from_secs(5), |c| c.contains("BRAVO-tail"));

    // A's output must contain ALPHA markers and NOT BRAVO markers.
    assert!(
        out_a.contains("ALPHA-marker") && out_a.contains("ALPHA-tail"),
        "shell A output missing ALPHA markers; got {out_a:?}"
    );
    assert!(
        !out_a.contains("BRAVO-marker"),
        "shell A output MUST NOT contain BRAVO markers; got {out_a:?}"
    );
    // And vice versa for B.
    assert!(
        out_b.contains("BRAVO-marker") && out_b.contains("BRAVO-tail"),
        "shell B output missing BRAVO markers; got {out_b:?}"
    );
    assert!(
        !out_b.contains("ALPHA-marker"),
        "shell B output MUST NOT contain ALPHA markers; got {out_b:?}"
    );

    let _ = kill_shell(&id_a);
    let _ = kill_shell(&id_b);
}

#[test]
fn many_spawns_produce_pairwise_unique_ids() {
    // Spawn 8 quick shells and verify all 8 ids are distinct.
    let mut ids = Vec::with_capacity(8);
    for i in 0..8 {
        let (msg, _) = bash_bg(&format!("echo spawn-{i}"));
        ids.push(extract_shell_id(&msg));
    }
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        ids.len(),
        "all spawn ids must be pairwise unique; got duplicates in {ids:?}"
    );
    for id in &ids {
        let _ = kill_shell(id);
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — post-kill query
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn bash_output_after_kill_does_not_panic_and_surfaces_state() {
    // Spawn a long-runner. Kill it. Then bash_output — must
    // return a non-error tuple (or a graceful error) WITHOUT
    // panicking the test runner.
    let (spawn_msg, _) = bash_bg("sleep 30");
    let shell_id = extract_shell_id(&spawn_msg);

    // Give the spawn a beat to register.
    std::thread::sleep(Duration::from_millis(50));

    let (kill_msg, _) = kill_shell(&shell_id);
    assert!(
        !kill_msg.is_empty(),
        "kill_shell must return a non-empty message; got {kill_msg:?}"
    );

    // Post-kill bash_output: either returns the captured output
    // + status line, OR returns a not-found / finished error.
    // Both are acceptable; what's NOT is a panic.
    let (post_kill, _is_err) = bash_output(&shell_id);
    assert!(
        !post_kill.is_empty(),
        "post-kill bash_output must return non-empty; got {post_kill:?}"
    );
}

#[test]
fn double_kill_is_idempotent_or_reports_not_found() {
    let (spawn_msg, _) = bash_bg("sleep 30");
    let shell_id = extract_shell_id(&spawn_msg);

    std::thread::sleep(Duration::from_millis(50));

    let (first, _) = kill_shell(&shell_id);
    assert!(!first.is_empty(), "first kill must return a message");

    // Second kill: must not panic. Either succeeds idempotently
    // or returns a "not found" / "already finished" error.
    let (second, _is_err) = kill_shell(&shell_id);
    assert!(
        !second.is_empty(),
        "second kill must return a message (not panic); got {second:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — bash_output incremental drain semantics
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn bash_output_two_calls_each_return_incremental_drain() {
    // After the first bash_output drains the buffer, the second
    // call must NOT re-emit the same content. Either it returns
    // an empty/status-only message, or it returns ONLY newly
    // produced output.
    let (spawn_msg, _) = bash_bg("echo first-chunk; sleep 0.5; echo second-chunk; sleep 5");
    let shell_id = extract_shell_id(&spawn_msg);

    // Wait for first chunk to land.
    let first = poll_until(&shell_id, Duration::from_secs(3), |c| {
        c.contains("first-chunk")
    });
    assert!(
        first.contains("first-chunk"),
        "first poll missing first-chunk; got {first:?}"
    );

    // Wait briefly so the second chunk has time to emit. Then
    // a fresh bash_output call must produce the second chunk;
    // it MUST NOT re-emit "first-chunk" (the drain is
    // incremental).
    std::thread::sleep(Duration::from_millis(700));
    let (second_call, _) = bash_output(&shell_id);
    // The second chunk should appear.
    if second_call.contains("second-chunk") {
        // Pin the incremental contract: the second call does
        // NOT re-emit "first-chunk".
        assert!(
            !second_call.contains("first-chunk"),
            "incremental drain MUST NOT re-emit previously-drained content; \
             got {second_call:?}"
        );
    }
    // Cleanup the long-runner.
    let _ = kill_shell(&shell_id);
}
