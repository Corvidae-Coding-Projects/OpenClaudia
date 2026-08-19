//! S-017 adversarial coverage for exact, generation-bound approval receipts.
//!
//! This binary replaces tests that required a bare tool-name `HashSet`. That
//! behavior made one Bash approval ambient authority for every Bash command.

use openclaudia::permissions::{
    inspect_permission_store, ApprovalBinding, ApprovalProvenance, AuthorizationResult,
    LocalApprovalCache, LocalApprovalDecision, PermissionDecision, PermissionManager,
    PermissionRule,
};
use openclaudia::tools::{FunctionCall, ToolCall};
use serde_json::json;
use std::io::Write as _;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct TraceBuffer(Arc<Mutex<Vec<u8>>>);

struct TraceWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for TraceWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for TraceBuffer {
    type Writer = TraceWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        TraceWriter(Arc::clone(&self.0))
    }
}

fn call(id: &str, tool: &str, arguments: &serde_json::Value) -> ToolCall {
    ToolCall {
        id: id.to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: tool.to_string(),
            arguments: arguments.to_string(),
        },
    }
}

fn manager(path: &std::path::Path, binding: ApprovalBinding) -> PermissionManager {
    PermissionManager::new_with_binding_and_web_fetch_preapproved(
        path,
        true,
        Vec::new(),
        Vec::new(),
        binding,
    )
}

#[test]
fn one_bash_approval_cannot_authorize_a_different_command() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(
        &dir.path().join("permissions.json"),
        ApprovalBinding::new("actor-a", dir.path(), 1),
    );
    let approved = call("approved", "bash", &json!({"command": "git status"}));
    let different = call("different", "bash", &json!({"command": "git push --force"}));

    let permit = mgr
        .approve_tool_call_for_session(&approved, "session-a", ApprovalProvenance::InteractiveUser)
        .unwrap();
    mgr.consume_execution_permit(&permit, &approved, Some("session-a"))
        .unwrap();

    assert!(matches!(
        mgr.authorize_tool_call(&different, Some("session-a")),
        AuthorizationResult::NeedsPrompt { .. }
    ));
}

#[test]
fn reusable_receipt_is_bound_to_session_and_exact_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(
        &dir.path().join("permissions.json"),
        ApprovalBinding::new("actor-a", dir.path(), 1),
    );
    let original = call(
        "original",
        "write_file",
        &json!({"path": "src/exact.rs", "content": "one"}),
    );
    let reordered = ToolCall {
        id: "reordered".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "write_file".to_string(),
            arguments: r#"{"content":"one","path":"src/exact.rs"}"#.to_string(),
        },
    };
    let changed = call(
        "changed",
        "write_file",
        &json!({"path": "src/exact.rs", "content": "two"}),
    );

    let first = mgr
        .approve_tool_call_for_session(&original, "session-a", ApprovalProvenance::InteractiveUser)
        .unwrap();
    mgr.consume_execution_permit(&first, &original, Some("session-a"))
        .unwrap();

    assert!(matches!(
        mgr.authorize_tool_call(&reordered, Some("session-a")),
        AuthorizationResult::Allowed(_)
    ));
    assert!(matches!(
        mgr.authorize_tool_call(&changed, Some("session-a")),
        AuthorizationResult::NeedsPrompt { .. }
    ));
    assert!(matches!(
        mgr.authorize_tool_call(&original, Some("session-b")),
        AuthorizationResult::NeedsPrompt { .. }
    ));
}

#[test]
fn execution_permit_is_call_bound_and_single_use() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(
        &dir.path().join("permissions.json"),
        ApprovalBinding::new("actor-a", dir.path(), 1),
    );
    let original = call("call-a", "bash", &json!({"command": "git status"}));
    let different_id = call("call-b", "bash", &json!({"command": "git status"}));
    let permit = mgr
        .approve_tool_call_once(
            &original,
            Some("session-a"),
            ApprovalProvenance::InteractiveUser,
        )
        .unwrap();

    assert!(mgr
        .consume_execution_permit(&permit, &different_id, Some("session-a"))
        .is_err());
    mgr.consume_execution_permit(&permit, &original, Some("session-a"))
        .unwrap();
    assert!(mgr
        .consume_execution_permit(&permit, &original, Some("session-a"))
        .is_err());
}

#[test]
fn persisted_receipt_survives_restart_only_for_same_actor_workspace_and_generation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("permissions.json");
    let binding = ApprovalBinding::new("actor-a", dir.path(), 7);
    let approved = call("first", "bash", &json!({"command": "git status"}));

    {
        let mgr = manager(&path, binding.clone());
        let permit = mgr
            .approve_tool_call_persisted(
                &approved,
                Some("session-a"),
                ApprovalProvenance::HostAdministrator,
            )
            .unwrap();
        mgr.consume_execution_permit(&permit, &approved, Some("session-a"))
            .unwrap();
    }

    let resumed = call("resumed", "bash", &json!({"command": "git status"}));
    let same = manager(&path, binding);
    assert!(matches!(
        same.authorize_tool_call(&resumed, Some("session-b")),
        AuthorizationResult::Allowed(_)
    ));

    let other_actor = manager(&path, ApprovalBinding::new("actor-b", dir.path(), 7));
    assert!(matches!(
        other_actor.authorize_tool_call(&resumed, Some("session-b")),
        AuthorizationResult::NeedsPrompt { .. }
    ));

    let other_generation = manager(&path, ApprovalBinding::new("actor-a", dir.path(), 8));
    assert!(matches!(
        other_generation.authorize_tool_call(&resumed, Some("session-b")),
        AuthorizationResult::NeedsPrompt { .. }
    ));

    let other_workspace_path = dir.path().join("other-workspace");
    std::fs::create_dir(&other_workspace_path).unwrap();
    let other_workspace = manager(
        &path,
        ApprovalBinding::new("actor-a", &other_workspace_path, 7),
    );
    assert!(matches!(
        other_workspace.authorize_tool_call(&resumed, Some("session-b")),
        AuthorizationResult::NeedsPrompt { .. }
    ));
}

#[test]
fn later_exact_denial_rotates_generation_and_dominates_old_approval() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(
        &dir.path().join("permissions.json"),
        ApprovalBinding::new("actor-a", dir.path(), 1),
    );
    let approved = call("approved", "bash", &json!({"command": "git status"}));
    let permit = mgr
        .approve_tool_call_for_session(&approved, "session-a", ApprovalProvenance::InteractiveUser)
        .unwrap();
    let before = mgr.approval_capability_generation();

    mgr.deny_tool_call_for_session(&approved, "session-a", ApprovalProvenance::InteractiveUser)
        .unwrap();
    assert!(mgr.approval_capability_generation() > before);
    assert!(mgr
        .consume_execution_permit(&permit, &approved, Some("session-a"))
        .is_err());
    assert!(matches!(
        mgr.authorize_tool_call(&approved, Some("session-a")),
        AuthorizationResult::Denied(_)
    ));
}

#[test]
fn multiple_exact_denials_remain_effective_across_generation_rotations() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(
        &dir.path().join("permissions.json"),
        ApprovalBinding::new("actor-a", dir.path(), 1),
    );
    let first = call("first", "bash", &json!({"command": "git status"}));
    let second = call("second", "bash", &json!({"command": "cargo check"}));
    mgr.deny_tool_call_for_session(&first, "session-a", ApprovalProvenance::InteractiveUser)
        .unwrap();
    mgr.deny_tool_call_for_session(&second, "session-a", ApprovalProvenance::InteractiveUser)
        .unwrap();

    assert!(matches!(
        mgr.authorize_tool_call(&first, Some("session-a")),
        AuthorizationResult::Denied(_)
    ));
    assert!(matches!(
        mgr.authorize_tool_call(&second, Some("session-a")),
        AuthorizationResult::Denied(_)
    ));
}

#[test]
fn later_broad_deny_dominates_persisted_exact_approval() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("permissions.json");
    let binding = ApprovalBinding::new("actor-a", dir.path(), 1);
    let approved = call("approved", "bash", &json!({"command": "git status"}));
    let mut mgr = manager(&path, binding);
    let old = mgr
        .approve_tool_call_persisted(
            &approved,
            Some("session-a"),
            ApprovalProvenance::HostAdministrator,
        )
        .unwrap();
    mgr.add_session_rule(PermissionRule {
        tool: "Bash".to_string(),
        pattern: "git *".to_string(),
        decision: PermissionDecision::Deny,
    });

    assert!(mgr
        .consume_execution_permit(&old, &approved, Some("session-a"))
        .is_err());
    assert!(matches!(
        mgr.authorize_tool_call(&approved, Some("session-a")),
        AuthorizationResult::Denied(_)
    ));
}

#[test]
fn denial_rotation_durably_revokes_persisted_approval_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("permissions.json");
    let binding = ApprovalBinding::new("actor-a", dir.path(), 1);
    let approved = call("approved", "bash", &json!({"command": "git status"}));
    {
        let mgr = manager(&path, binding.clone());
        let _permit = mgr
            .approve_tool_call_persisted(&approved, None, ApprovalProvenance::HostAdministrator)
            .unwrap();
        mgr.deny_tool_call_for_session(&approved, "session-a", ApprovalProvenance::InteractiveUser)
            .unwrap();
    }

    let resumed = manager(&path, binding);
    let replay = call("replay", "bash", &json!({"command": "git status"}));
    assert!(matches!(
        resumed.authorize_tool_call(&replay, Some("session-b")),
        AuthorizationResult::NeedsPrompt { .. }
    ));
}

#[test]
fn generation_rotation_invalidates_permit_minted_by_another_live_manager() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("permissions.json");
    let binding = ApprovalBinding::new("actor-a", dir.path(), 1);
    let approved_call = call("shared-call", "bash", &json!({"command": "git status"}));
    let revoker = manager(&path, binding.clone());
    let initial = revoker
        .approve_tool_call_persisted(&approved_call, None, ApprovalProvenance::HostAdministrator)
        .unwrap();
    revoker
        .consume_execution_permit(&initial, &approved_call, None)
        .unwrap();

    let peer = manager(&path, binding);
    let peer_call = call("peer-call", "bash", &json!({"command": "git status"}));
    let AuthorizationResult::Allowed(peer_permit) = peer.authorize_tool_call(&peer_call, None)
    else {
        panic!("peer should consume the persisted exact approval");
    };
    revoker
        .deny_tool_call_for_session(
            &approved_call,
            "session-a",
            ApprovalProvenance::InteractiveUser,
        )
        .unwrap();

    assert!(peer
        .consume_execution_permit(&peer_permit, &peer_call, None)
        .is_err());
}

#[test]
fn local_approval_cache_keeps_denials_and_invalidates_older_allows() {
    let dir = tempfile::tempdir().unwrap();
    let mut cache = LocalApprovalCache::new(ApprovalBinding::new("actor-a", dir.path(), 1));
    cache.remember_allowed(
        "bash",
        r#"{"command":"git status"}"#,
        ApprovalProvenance::InteractiveUser,
    );
    cache.remember_denied(
        "bash",
        r#"{"command":"cargo publish"}"#,
        ApprovalProvenance::InteractiveUser,
    );
    cache.remember_denied(
        "write_file",
        r#"{"content":"x","path":"src/main.rs"}"#,
        ApprovalProvenance::InteractiveUser,
    );

    assert_eq!(
        cache.decision("bash", r#"{"command":"git status"}"#),
        None,
        "a later denial generation must invalidate every older allow"
    );
    assert_eq!(
        cache.decision("bash", r#"{"command":"cargo publish"}"#),
        Some(LocalApprovalDecision::Denied)
    );
    assert_eq!(
        cache.decision("write_file", r#"{"path":"src/main.rs","content":"x"}"#),
        Some(LocalApprovalDecision::Denied),
        "earlier exact denials must survive later generation rotations"
    );
}

#[test]
fn persisted_store_contains_digests_not_raw_targets_or_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("permissions.json");
    let mgr = manager(&path, ApprovalBinding::new("actor-a", dir.path(), 1));
    let secret_command = "printf receipt-raw-secret-marker";
    let approved = call("approved", "bash", &json!({"command": secret_command}));
    let _permit = mgr
        .approve_tool_call_persisted(
            &approved,
            Some("session-a"),
            ApprovalProvenance::HostAdministrator,
        )
        .unwrap();

    let raw = std::fs::read_to_string(path).unwrap();
    assert!(!raw.contains(secret_command));
    assert!(!raw.contains("receipt-raw-secret-marker"));
    assert!(raw.contains("target_digest"));
    assert!(raw.contains("arguments_digest"));
}

#[test]
fn persisted_receipt_expires_and_use_count_is_exhaustible() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("permissions.json");
    let binding = ApprovalBinding::new("actor-a", dir.path(), 1);
    let approved = call("approved", "bash", &json!({"command": "git status"}));
    {
        let mgr = manager(&path, binding.clone());
        let _permit = mgr
            .approve_tool_call_persisted(&approved, None, ApprovalProvenance::HostAdministrator)
            .unwrap();
    }

    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    state["approvals"][0]["remaining_uses"] = json!(1);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    file.write_all(&serde_json::to_vec_pretty(&state).unwrap())
        .unwrap();
    drop(file);

    let mgr = manager(&path, binding.clone());
    let peer_loaded_before_last_use = manager(&path, binding.clone());
    let last = call("last", "bash", &json!({"command": "git status"}));
    assert!(matches!(
        mgr.authorize_tool_call(&last, None),
        AuthorizationResult::Allowed(_)
    ));
    let exhausted = call("exhausted", "bash", &json!({"command": "git status"}));
    assert!(matches!(
        mgr.authorize_tool_call(&exhausted, None),
        AuthorizationResult::NeedsPrompt { .. }
    ));
    let peer_attempt = call("peer", "bash", &json!({"command": "git status"}));
    assert!(matches!(
        peer_loaded_before_last_use.authorize_tool_call(&peer_attempt, None),
        AuthorizationResult::NeedsPrompt { .. }
    ));
    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(persisted["approvals"].as_array().unwrap().len(), 0);

    // Recreate a valid record, move its whole validity interval into the past,
    // then prove restart drops it rather than minting authority.
    {
        let mgr = manager(&path, binding.clone());
        let _permit = mgr
            .approve_tool_call_persisted(&approved, None, ApprovalProvenance::HostAdministrator)
            .unwrap();
    }
    let mut expired: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    expired["approvals"][0]["issued_at"] = json!("2020-01-01T00:00:00Z");
    expired["approvals"][0]["expires_at"] = json!("2020-01-02T00:00:00Z");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    file.write_all(&serde_json::to_vec_pretty(&expired).unwrap())
        .unwrap();
    drop(file);
    let expired_mgr = manager(&path, binding);
    assert!(matches!(
        expired_mgr.authorize_tool_call(&approved, None),
        AuthorizationResult::NeedsPrompt { .. }
    ));
}

#[test]
fn persisted_receipt_rejects_widened_use_time_and_not_before_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("permissions.json");
    let binding = ApprovalBinding::new("actor-a", dir.path(), 1);
    let approved = call("approved", "bash", &json!({"command": "git status"}));
    let mgr = manager(&path, binding);
    let _permit = mgr
        .approve_tool_call_persisted(&approved, None, ApprovalProvenance::HostAdministrator)
        .unwrap();
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();

    let mut too_many_uses = original.clone();
    too_many_uses["approvals"][0]["remaining_uses"] = json!(65);
    std::fs::write(&path, serde_json::to_vec_pretty(&too_many_uses).unwrap()).unwrap();
    assert!(inspect_permission_store(&path).is_err());

    let mut too_long = original.clone();
    too_long["approvals"][0]["issued_at"] = json!("2020-01-01T00:00:00Z");
    too_long["approvals"][0]["expires_at"] = json!("2020-02-01T00:00:01Z");
    std::fs::write(&path, serde_json::to_vec_pretty(&too_long).unwrap()).unwrap();
    assert!(inspect_permission_store(&path).is_err());

    let mut future = original;
    future["approvals"][0]["issued_at"] = json!("2099-01-01T00:00:00Z");
    future["approvals"][0]["expires_at"] = json!("2099-01-02T00:00:00Z");
    std::fs::write(&path, serde_json::to_vec_pretty(&future).unwrap()).unwrap();
    assert!(inspect_permission_store(&path).is_err());
}

#[test]
fn exhausted_capability_generation_fails_closed_without_wrapping() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("permissions.json");
    let binding = ApprovalBinding::new("actor-a", dir.path(), 1);
    let approved = call("approved", "bash", &json!({"command": "git status"}));
    let mgr = manager(&path, binding.clone());
    let _permit = mgr
        .approve_tool_call_persisted(&approved, None, ApprovalProvenance::HostAdministrator)
        .unwrap();
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    state["capability_generation"] = json!(u64::MAX);
    state["approvals"] = json!([]);
    std::fs::write(&path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

    let exhausted = manager(&path, binding);
    assert!(exhausted
        .deny_tool_call_for_session(&approved, "session-a", ApprovalProvenance::InteractiveUser,)
        .is_err());
    assert_eq!(exhausted.approval_capability_generation(), u64::MAX);
    assert!(matches!(
        exhausted.authorize_tool_call(&approved, Some("session-a")),
        AuthorizationResult::Denied(_)
    ));
}

#[test]
fn legacy_policy_check_cannot_consume_or_project_receipt_authority() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("permissions.json");
    let binding = ApprovalBinding::new("actor-a", dir.path(), 1);
    let approved = call("approved", "bash", &json!({"command": "git status"}));
    {
        let mgr = manager(&path, binding.clone());
        let _initial = mgr
            .approve_tool_call_persisted(&approved, None, ApprovalProvenance::HostAdministrator)
            .unwrap();
    }

    let mgr = manager(&path, binding);
    assert!(matches!(
        mgr.check("bash", &json!({"command": "git status"})),
        openclaudia::permissions::CheckResult::NeedsPrompt { .. }
    ));

    let replay = call("replay", "bash", &json!({"command": "git status"}));
    assert!(matches!(
        mgr.authorize_tool_call(&replay, None),
        AuthorizationResult::Allowed(_)
    ));
}

#[test]
fn network_receipt_is_bound_to_the_exact_url_and_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(
        &dir.path().join("permissions.json"),
        ApprovalBinding::new("actor-a", dir.path(), 1),
    );
    let approved = call(
        "approved",
        "web_fetch",
        &json!({"url": "https://example.com/approved"}),
    );
    let changed = call(
        "changed",
        "web_fetch",
        &json!({"url": "https://example.com/other"}),
    );
    let permit = mgr
        .approve_tool_call_for_session(&approved, "session-a", ApprovalProvenance::InteractiveUser)
        .unwrap();
    mgr.consume_execution_permit(&permit, &approved, Some("session-a"))
        .unwrap();

    assert!(matches!(
        mgr.authorize_tool_call(&changed, Some("session-a")),
        AuthorizationResult::NeedsPrompt { .. }
    ));
}

#[test]
fn permission_traces_show_precedence_and_digests_without_raw_targets() {
    let dir = tempfile::tempdir().unwrap();
    let mut mgr = manager(
        &dir.path().join("permissions.json"),
        ApprovalBinding::new("actor-a", dir.path(), 1),
    );
    let secret = "receipt-trace-secret-command";
    let attempt = call("attempt", "bash", &json!({"command": secret}));
    let output = TraceBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(output.clone())
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::INFO)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        let permit = mgr
            .approve_tool_call_once(
                &attempt,
                Some("session-a"),
                ApprovalProvenance::InteractiveUser,
            )
            .unwrap();
        mgr.consume_execution_permit(&permit, &attempt, Some("session-a"))
            .unwrap();
        mgr.add_session_rule(PermissionRule {
            tool: "Bash".to_string(),
            pattern: secret.to_string(),
            decision: PermissionDecision::Deny,
        });
        assert!(matches!(
            mgr.authorize_tool_call(&attempt, Some("session-a")),
            AuthorizationResult::Denied(_)
        ));
    });

    let trace = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    assert!(trace.contains("approval_permit_consumed"), "{trace}");
    assert!(trace.contains("explicit_deny_rule"), "{trace}");
    assert!(trace.contains("sha256:"), "{trace}");
    assert!(
        !trace.contains(secret),
        "raw target leaked in trace: {trace}"
    );
}

#[test]
fn legacy_broad_allow_is_not_migrated_into_authority() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("permissions.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&vec![PermissionRule {
            tool: "Bash".to_string(),
            pattern: "**".to_string(),
            decision: PermissionDecision::AlwaysAllow,
        }])
        .unwrap(),
    )
    .unwrap();
    let mgr = manager(&path, ApprovalBinding::new("actor-a", dir.path(), 1));
    let attempt = call("attempt", "bash", &json!({"command": "git status"}));

    assert!(mgr.persisted_rules().is_empty());
    assert!(matches!(
        mgr.authorize_tool_call(&attempt, Some("session-a")),
        AuthorizationResult::NeedsPrompt { .. }
    ));
}

#[test]
fn malformed_or_oversized_persisted_state_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("permissions.json");
    let binding = ApprovalBinding::new("actor-a", dir.path(), 1);
    let attempt = call("attempt", "bash", &json!({"command": "git status"}));

    std::fs::write(&path, vec![b'x'; 1024 * 1024 + 1]).unwrap();
    let oversized = manager(&path, binding.clone());
    assert!(matches!(
        oversized.authorize_tool_call(&attempt, None),
        AuthorizationResult::Denied(_)
    ));

    std::fs::write(
        &path,
        br#"{"schema_version":1,"capability_generation":1,"approvals":[],"denials":[],"exact_denials":[],"unexpected":true}"#,
    )
    .unwrap();
    let unknown_field = manager(&path, binding);
    assert!(matches!(
        unknown_field.authorize_tool_call(&attempt, None),
        AuthorizationResult::Denied(_)
    ));
}

#[cfg(unix)]
#[test]
fn persistence_rejects_a_symlink_target() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.json");
    std::fs::write(&real, b"{}").unwrap();
    let link = dir.path().join("permissions.json");
    symlink(&real, &link).unwrap();
    let mgr = manager(&link, ApprovalBinding::new("actor-a", dir.path(), 1));
    let attempt = call("attempt", "bash", &json!({"command": "git status"}));
    assert!(mgr
        .approve_tool_call_persisted(
            &attempt,
            Some("session-a"),
            ApprovalProvenance::HostAdministrator,
        )
        .is_err());
}

#[cfg(unix)]
#[test]
fn persisted_store_is_restrictive_and_world_writable_state_is_rejected() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("permissions.json");
    let binding = ApprovalBinding::new("actor-a", dir.path(), 1);
    let approved = call("approved", "bash", &json!({"command": "git status"}));
    {
        let mgr = manager(&path, binding.clone());
        let _permit = mgr
            .approve_tool_call_persisted(&approved, None, ApprovalProvenance::HostAdministrator)
            .unwrap();
    }
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o022,
        0,
        "the existing store parent must not be group/world writable"
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    let untrusted = manager(&path, binding);
    assert!(matches!(
        untrusted.authorize_tool_call(&approved, None),
        AuthorizationResult::Denied(_)
    ));
}

#[cfg(unix)]
#[test]
fn existing_store_parent_is_validated_without_rewriting_its_mode() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("existing-parent");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = parent.join("permissions.json");
    let binding = ApprovalBinding::new("actor-a", dir.path(), 1);
    let approved = call("approved", "bash", &json!({"command": "git status"}));

    let mgr = manager(&path, binding.clone());
    let _permit = mgr
        .approve_tool_call_persisted(&approved, None, ApprovalProvenance::HostAdministrator)
        .unwrap();
    assert_eq!(
        std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
        0o755,
        "an existing safe parent must not be chmod'd as a side effect"
    );

    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o775)).unwrap();
    let unsafe_parent = manager(&path, binding);
    assert!(unsafe_parent
        .approve_tool_call_persisted(&approved, None, ApprovalProvenance::HostAdministrator)
        .is_err());
}

#[cfg(unix)]
#[test]
fn path_receipt_does_not_follow_a_repointed_symlink_parent() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    let link = dir.path().join("current");
    symlink(&first, &link).unwrap();
    let path = link.join("output.txt");
    let mgr = manager(
        &dir.path().join("permissions.json"),
        ApprovalBinding::new("actor-a", dir.path(), 1),
    );
    let approved = call(
        "approved",
        "write_file",
        &json!({"path": path, "content": "same"}),
    );
    let permit = mgr
        .approve_tool_call_for_session(&approved, "session-a", ApprovalProvenance::InteractiveUser)
        .unwrap();
    mgr.consume_execution_permit(&permit, &approved, Some("session-a"))
        .unwrap();

    std::fs::remove_file(&link).unwrap();
    symlink(&second, &link).unwrap();
    let replay = call(
        "replay",
        "write_file",
        &json!({"path": path, "content": "same"}),
    );
    assert!(matches!(
        mgr.authorize_tool_call(&replay, Some("session-a")),
        AuthorizationResult::NeedsPrompt { .. }
    ));
}
