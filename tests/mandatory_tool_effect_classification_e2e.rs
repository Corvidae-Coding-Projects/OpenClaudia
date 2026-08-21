//! S-016 acceptance: every tool carries an enforced effect classification.
//!
//! Findings under test:
//!
//! * **F-001** — `ToolHandler::permission_target()` defaulted to `None`, and a
//!   `None` target meant "read-only / safe, skip the gate". Twenty-eight of
//!   thirty-three handlers inherited that by omission, an unknown tool name
//!   resolved the same way, and `auto_allow_score` returned `1.0` for both.
//! * **F-052** — Crosslink accepted one shell-like `args` string that the
//!   handler parsed privately, *after* classification, so `create`, `close`,
//!   `comment` and session mutation were indistinguishable from `list`.
//!
//! These tests assert observed authorization outcomes. A test that only
//! asserted the presence of a constant would pass against a classification
//! that nothing consults, which is the failure mode the slice exists to close.

use openclaudia::permissions::{
    auto_allow_score, CheckResult, PermissionDecision, PermissionManager, PermissionRule,
};
use openclaudia::tools::crosslink;
use openclaudia::tools::effect::{
    effect_matrix, lookup, render_effect_matrix, resolve_for_call, EffectResolutionError,
    ToolEffect, ToolEffectSpec, ToolSurface, ToolTarget,
};
use openclaudia::tools::registry::{iter_handlers, registry, validate_handlers, ToolHandler};
use openclaudia::tools::{execute_tool_with_permission_required, FunctionCall, ToolCall};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

mod support;

#[derive(Clone, Default)]
struct TraceWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for TraceWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("trace buffer").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TraceWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A manager with rules enabled and nothing pre-allowed, so any tool that
/// reaches the rule engine surfaces as `NeedsPrompt` and anything that skips
/// it surfaces as `Allowed`. That difference is what these tests read.
///
/// The empty preapproved catalog keeps `web_fetch` on the prompting path so a
/// documentation-host bypass cannot be mistaken for a classification bypass.
fn gated_manager() -> (PermissionManager, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("perms.json");
    let mgr = PermissionManager::new_with_web_fetch_preapproved(path, true, vec![], vec![]);
    (mgr, dir)
}

// ───────────────────────────────────────────────────────────────────────────
// Acceptance 1 — unclassified and unknown tools fail closed
// ───────────────────────────────────────────────────────────────────────────

/// F-001's core claim: an unknown tool name was allowed. It must now deny.
#[test]
fn unknown_tool_is_denied_at_the_authorization_boundary() {
    let (mgr, _dir) = gated_manager();
    let outcome = mgr.check("mystery_tool", &json!({"path": "/etc/shadow"}));
    assert!(
        matches!(outcome, CheckResult::Denied(_)),
        "an unclassified tool must be denied, got {outcome:?}"
    );
}

/// Disabling prompts/rules is not permission to invent an effect. The
/// unrestricted policy applies only after the mandatory classifier succeeds.
#[test]
fn unrestricted_manager_still_denies_unclassified_tools() {
    let mgr = PermissionManager::unrestricted();
    assert!(matches!(
        mgr.check("unknown_from_model", &json!({})),
        CheckResult::Denied(_)
    ));
}

/// Acceptance requires an auditable classification receipt, not merely an
/// in-memory enum. Capture the real permission-boundary event and assert its
/// concrete operation/effect fields. Raw targets are intentionally absent
/// because commands, paths, and URLs can contain secrets.
#[test]
fn authorization_emits_structured_effect_trace_before_policy() {
    let writer = TraceWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .without_time()
        .finish();
    let (mgr, _dir) = gated_manager();

    let outcome = tracing::subscriber::with_default(subscriber, || {
        mgr.check("crosslink", &json!({"operation": "close", "id": 42}))
    });
    assert!(matches!(outcome, CheckResult::NeedsPrompt { .. }));

    let captured = String::from_utf8(writer.0.lock().expect("trace buffer").clone())
        .expect("trace output is utf-8");
    let classification = captured
        .lines()
        .find(|line| line.contains("tool_effect_classified"))
        .unwrap_or_else(|| panic!("missing classification event: {captured}"));
    for field in [
        "tool_effect_classified",
        "tool_name=crosslink",
        "canonical_tool=Crosslink",
        "effect=\"workspace_mutation\"",
        "operation=\"close\"",
    ] {
        assert!(
            classification.contains(field),
            "classification trace missing {field:?}: {captured}"
        );
    }
    assert!(
        !classification.contains("target_arg="),
        "classification trace must not add a second raw-target leak: {classification}"
    );
}

/// A name that merely *looks* like a known tool gets no credit for it.
#[test]
fn near_miss_tool_names_are_denied() {
    let (mgr, _dir) = gated_manager();
    for name in ["Bash", "bash ", "bash_", "read_file2", "write_filex"] {
        let outcome = mgr.check(name, &json!({"command": "ls", "path": "/tmp/x"}));
        assert!(
            matches!(outcome, CheckResult::Denied(_)),
            "{name} is not a registered tool and must be denied, got {outcome:?}"
        );
    }
}

/// F-001 explicitly records the `1.0` auto-allow score for unknown tools.
#[test]
fn unclassified_tools_never_score_as_auto_allowable() {
    assert!(
        auto_allow_score("mystery_tool", &json!({})) < f32::EPSILON,
        "an unclassified tool must not be scored safe for auto-allow"
    );
}

/// Every handler resolves to a usable declaration. The declaration itself is
/// mandatory at compile time (no trait default), so this covers the part the
/// compiler cannot: that it is structurally usable by the rule engine.
#[test]
fn every_registered_handler_has_a_valid_declaration() {
    let mut count = 0;
    for handler in iter_handlers() {
        let name = handler.name();
        handler
            .effect_spec()
            .validate(name)
            .unwrap_or_else(|e| panic!("handler '{name}' declaration unusable: {e}"));
        count += 1;
    }
    assert!(
        count >= 30,
        "expected the full handler catalog, saw {count}"
    );
}

/// The durable and external tools F-001 named as fail-open must now reach a
/// decision, observed as a `NeedsPrompt`/`Denied` outcome rather than as a
/// property of the declaration.
///
/// Session-local tools (`todo_write`, `task_create`, `task_update`,
/// `enter_plan_mode`, `exit_plan_mode`, `agent_output`) are covered separately by
/// [`session_mutation_defaults_to_allowed_but_honours_an_explicit_deny`]:
/// they reach the decision but default to allow, because projecting them onto
/// a prompt hard-denies every non-interactive frontend.
#[test]
fn previously_fail_open_tools_now_reach_an_authorization_decision() {
    let (mgr, _dir) = gated_manager();
    let cases: &[(&str, serde_json::Value)] = &[
        (
            "cron_create",
            json!({"name": "x", "schedule": "* * * * *", "prompt": "p"}),
        ),
        ("cron_delete", json!({"name": "x"})),
        ("cron_list", json!({})),
        ("enter_worktree", json!({"branch": "agent/x"})),
        ("kill_shell", json!({"shell_id": "sh-1"})),
        ("kill_shells_for_agent", json!({"agent_id": "a-1"})),
        ("lsp", json!({"action": "hover", "file_path": "/tmp/a.rs"})),
        ("list_mcp_resources", json!({})),
        ("read_mcp_resource", json!({"server": "s", "uri": "u"})),
        ("crosslink", json!({"operation": "close", "id": 1})),
    ];

    for (tool, args) in cases {
        let outcome = mgr.check(tool, args);
        assert!(
            !matches!(outcome, CheckResult::Allowed),
            "{tool} was listed in F-001 as fail-open; it must not silently return Allowed \
             (got {outcome:?})"
        );
    }
}

/// The destructive worktree case F-001 calls out by name.
///
/// `discard_changes: true` knowingly throws away uncommitted work. The other
/// variants also end in `git worktree remove --force`, so argument-only
/// classification cannot prove that ignored files will survive. All variants
/// must therefore carry the conservative destructive ceiling, while retaining
/// distinct operation labels for auditability.
#[test]
fn every_exit_worktree_variant_is_classified_destructive() {
    let discard = resolve_for_call(
        "exit_worktree",
        &json!({"path": "/tmp/wt", "discard_changes": true}),
    )
    .expect("discard must classify");
    assert_eq!(discard.effect, ToolEffect::Destructive);
    assert_eq!(discard.operation.as_deref(), Some("discard"));

    let clean = resolve_for_call("exit_worktree", &json!({"path": "/tmp/wt"}))
        .expect("clean removal must classify");
    assert_eq!(clean.effect, ToolEffect::Destructive);
    assert_eq!(clean.operation.as_deref(), Some("remove_clean"));

    let apply = resolve_for_call(
        "exit_worktree",
        &json!({"path": "/tmp/wt", "apply_changes": true}),
    )
    .expect("apply removal must classify");
    assert_eq!(apply.effect, ToolEffect::Destructive);
    assert_eq!(apply.operation.as_deref(), Some("apply"));

    let (mgr, _dir) = gated_manager();
    let outcome = mgr.check(
        "exit_worktree",
        &json!({"path": "/tmp/wt", "discard_changes": true}),
    );
    assert!(
        !matches!(outcome, CheckResult::Allowed),
        "destructive worktree removal must reach a decision, got {outcome:?}"
    );
}

/// An invocation whose effect cannot be established is denied, not assumed
/// safe. A non-boolean flag is the shape a confused or hostile caller sends.
#[test]
fn unclassifiable_arguments_deny_rather_than_default() {
    let err = resolve_for_call(
        "exit_worktree",
        &json!({"path": "/tmp/wt", "discard_changes": "yes"}),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        EffectResolutionError::UnclassifiableOperation { .. }
    ));

    let (mgr, _dir) = gated_manager();
    let outcome = mgr.check(
        "exit_worktree",
        &json!({"path": "/tmp/wt", "discard_changes": "yes"}),
    );
    assert!(
        matches!(outcome, CheckResult::Denied(_)),
        "an unclassifiable call must deny, got {outcome:?}"
    );
}

/// Declared read-only tools still skip the prompt, so the change is not
/// simply "deny everything".
#[test]
fn declared_read_only_tools_still_run_without_a_prompt() {
    let (mgr, _dir) = gated_manager();
    for (tool, args) in [
        ("read_file", json!({"path": "/tmp/a"})),
        ("list_files", json!({})),
        ("glob", json!({"pattern": "*.rs"})),
        ("grep", json!({"pattern": "fn main"})),
        ("todo_read", json!({})),
        ("task_list", json!({})),
    ] {
        assert_eq!(
            mgr.check(tool, &args),
            CheckResult::Allowed,
            "{tool} declares ReadOnly and must not require authorization"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Acceptance 1 (cont.) — dynamic tools
// ───────────────────────────────────────────────────────────────────────────

/// MCP-served tools are classified at the true conservative ceiling rather than
/// falling through the registry miss into "allowed".
#[test]
fn dynamic_mcp_tools_are_classified_and_gated() {
    let resolved = resolve_for_call("mcp__files__write", &json!({"path": "/etc/passwd"}))
        .expect("an mcp tool must classify");
    assert_eq!(resolved.effect, ToolEffect::Destructive);
    assert_eq!(resolved.canonical, "Mcp");
    assert_eq!(
        resolved.target, "mcp__files__write",
        "the fully qualified name is what a rule scopes against"
    );

    let (mgr, _dir) = gated_manager();
    let outcome = mgr.check("mcp__files__write", &json!({"path": "/etc/passwd"}));
    assert!(
        !matches!(outcome, CheckResult::Allowed),
        "an MCP-served tool must reach a decision, got {outcome:?}"
    );
}

/// A name that is not a real MCP tool name is still unknown.
#[test]
fn malformed_mcp_prefixes_do_not_grant_classification() {
    let (mgr, _dir) = gated_manager();
    for name in [
        "mcp_",
        "mcp",
        "mcp__",
        "mcp____",
        "mcp__server",
        "mcp____tool",
        "mcp__ __tool",
        "mcp__server__ ",
        "__mcp__x__y",
        " mcp__a__b",
    ] {
        assert!(
            matches!(mgr.check(name, &json!({})), CheckResult::Denied(_)),
            "{name} must not resolve to an MCP classification"
        );
    }
}

/// Subagent tools dispatch outside the registry and were therefore invisible
/// to the old lookup. `task` spawns an agent with the union of all tool
/// authority, so it carries the ceiling.
#[test]
fn subagent_tools_are_classified_and_gated() {
    let resolved = resolve_for_call(
        "task",
        &json!({"description": "d", "prompt": "p", "subagent_type": "general-purpose"}),
    )
    .expect("task must classify");
    assert_eq!(resolved.effect, ToolEffect::Destructive);
    assert_eq!(resolved.target, "general-purpose");

    let (mgr, _dir) = gated_manager();
    let outcome = mgr.check(
        "task",
        &json!({"description": "d", "prompt": "p", "subagent_type": "general-purpose"}),
    );
    assert!(
        !matches!(outcome, CheckResult::Allowed),
        "task dispatches outside the registry and must still be gated, got {outcome:?}"
    );

    // `task_stop` aborts a spawned agent and terminates its background process
    // groups. Calling that session-only would conceal the external effect.
    let stop = resolve_for_call("task_stop", &json!({"agent_id": "a-1"})).expect("classifies");
    assert_eq!(stop.effect, ToolEffect::ExternalMutation);
    assert!(stop.effect.requires_authorization());

    // `agent_output` consumes finished results and removes their manager entry,
    // so it is a session mutation even though its output is observational.
    let output = resolve_for_call("agent_output", &json!({"agent_id": "a-1"}))
        .expect("agent_output classifies");
    assert_eq!(output.effect, ToolEffect::SessionMutation);
    assert_eq!(
        mgr.check("agent_output", &json!({"agent_id": "a-1"})),
        CheckResult::Allowed,
        "classified session-local mutations follow the explicit default policy"
    );
}

/// Subagent definitions and effect declarations live in different modules.
/// Comparing only their names would miss a drift such as the declaration
/// targeting `agent` while the model-facing schema publishes `agent_id`.
#[test]
fn subagent_effect_targets_match_their_independent_wire_schemas() {
    let definitions = openclaudia::subagent::get_subagent_tool_definitions();
    for definition in definitions.as_array().expect("subagent definitions") {
        let name = definition["function"]["name"]
            .as_str()
            .expect("subagent function name");
        let (surface, spec) =
            lookup(name).unwrap_or_else(|| panic!("{name} has no effect declaration"));
        assert_eq!(surface, ToolSurface::Subagent, "{name}");
        spec.validate(name)
            .unwrap_or_else(|error| panic!("{name}: {error}"));

        let properties = definition["function"]["parameters"]["properties"]
            .as_object()
            .expect("subagent properties");
        match spec.target {
            ToolTarget::ToolScope => {}
            ToolTarget::Arg(key) | ToolTarget::ArgOrDefault { key, .. } => {
                let field = properties
                    .get(key)
                    .unwrap_or_else(|| panic!("{name} target {key:?} is absent from its schema"));
                assert_eq!(field["type"], "string", "{name}.{key}");
                if matches!(spec.target, ToolTarget::Arg(_)) {
                    let required = definition["function"]["parameters"]["required"]
                        .as_array()
                        .expect("required array");
                    assert!(
                        required.iter().any(|value| value == key),
                        "{name} requires {key:?} for classification but the wire schema marks it optional"
                    );
                }
            }
            ToolTarget::TypedOperation => {
                panic!("{name} has no subagent typed-operation resolver")
            }
        }
    }
}

#[test]
fn user_question_is_classified_as_session_control_not_read_only() {
    let resolved =
        resolve_for_call("ask_user_question", &json!({})).expect("ask_user_question must classify");
    assert_eq!(resolved.effect, ToolEffect::SessionMutation);
    assert!(resolved.effect.requires_authorization());

    let (mgr, _dir) = gated_manager();
    assert_eq!(
        mgr.check("ask_user_question", &json!({})),
        CheckResult::Allowed,
        "session-control mutations reach policy and use its explicit session-local default"
    );
}

#[test]
fn output_polling_is_not_mislabeled_as_read_only() {
    let list = resolve_for_call("bash_output", &json!({})).expect("list classifies");
    assert_eq!(list.effect, ToolEffect::ReadOnly);
    assert_eq!(list.operation.as_deref(), Some("list"));

    let poll =
        resolve_for_call("bash_output", &json!({"shell_id": "sh-1"})).expect("poll classifies");
    assert_eq!(poll.effect, ToolEffect::SessionMutation);
    assert_eq!(poll.operation.as_deref(), Some("poll"));
    assert_eq!(poll.target, "sh-1");

    assert!(resolve_for_call("bash_output", &json!({"shell_id": 1})).is_err());
}

#[test]
fn mcp_resource_reads_account_for_reconnection_state() {
    for (tool, args) in [
        ("list_mcp_resources", json!({})),
        (
            "read_mcp_resource",
            json!({"server": "docs", "uri": "resource://manual"}),
        ),
    ] {
        let resolved = resolve_for_call(tool, &args).expect("MCP resource call classifies");
        assert_eq!(resolved.effect, ToolEffect::ExternalMutation, "{tool}");
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Acceptance 2 — Crosslink typed operations
// ───────────────────────────────────────────────────────────────────────────

/// F-052: the argv string is gone. The wire schema advertises a closed
/// operation enum and no free-form command field.
#[test]
fn crosslink_schema_has_no_command_string_field() {
    let definition = registry()
        .get("crosslink")
        .expect("crosslink registered")
        .definition();
    let properties = &definition["function"]["parameters"]["properties"];

    assert!(
        properties.get("args").is_none(),
        "the free-form argv field must be gone; found {properties:?}"
    );
    assert!(
        properties.get("operation").is_some(),
        "a typed operation field must replace it"
    );

    let required = definition["function"]["parameters"]["required"]
        .as_array()
        .expect("required list");
    assert!(
        required.iter().any(|v| v == "operation"),
        "operation must be required so a call cannot arrive unclassified"
    );

    // No property may still accept a whole command line.
    for (name, schema) in properties.as_object().expect("object") {
        let description = schema["description"].as_str().unwrap_or_default();
        assert!(
            !description.contains("subcommand"),
            "property '{name}' still describes a subcommand string: {description}"
        );
    }
}

/// The per-operation identity is decided before execution rather than inside
/// the handler, and the query/mutation split is recorded honestly.
///
/// Every store operation declares `WorkspaceMutation` because reaching the
/// store initializes it. What distinguishes a query is `mutates_records`,
/// which the dispatcher uses to choose a store-opening path that refuses to
/// create anything. Static help operations require no store and are genuinely
/// read-only.
#[test]
fn crosslink_operations_are_individually_identified_before_dispatch() {
    let queries = [
        "list",
        "show",
        "search",
        "tree",
        "next",
        "ready",
        "session_status",
    ];
    let mutations = [
        "create",
        "close",
        "reopen",
        "comment",
        "label",
        "unlabel",
        "subissue",
        "relate",
        "block",
        "unblock",
        "update",
        "session_start",
        "session_end",
        "session_work",
        "session_action",
    ];

    let documentation = ["help", "--help", "-h"];

    for name in queries
        .iter()
        .chain(mutations.iter())
        .chain(documentation.iter())
    {
        let resolved = resolve_for_call("crosslink", &json!({"operation": name}))
            .unwrap_or_else(|e| panic!("{name}: {}", e.reason()));
        assert_eq!(
            resolved.operation.as_deref(),
            Some(*name),
            "the operation must be identified before authorization"
        );
    }

    for name in queries {
        let op = crosslink::operation(name).expect("declared");
        assert!(!op.mutates_records, "{name} must not be a record mutation");
        assert!(op.requires_store, "{name} must open the existing store");
        assert!(op.effect.requires_authorization(), "{name}");
    }
    for name in mutations {
        let op = crosslink::operation(name).expect("declared");
        assert!(op.mutates_records, "{name} must be a record mutation");
        assert!(op.requires_store, "{name} must open the store");
        assert!(op.effect.requires_authorization(), "{name}");
    }
    for name in documentation {
        let op = crosslink::operation(name).expect("declared");
        assert!(!op.mutates_records, "{name}");
        assert!(!op.requires_store, "{name} must not touch the store");
        assert_eq!(op.effect, ToolEffect::ReadOnly, "{name}");
    }
}

/// The behavioural half of F-052: distinct operations produce distinct
/// authorization targets, so a rule can approve one without approving all.
#[test]
fn crosslink_operations_carry_distinct_authorization_targets() {
    let (mgr, _dir) = gated_manager();

    let list = mgr.check("crosslink", &json!({"operation": "list"}));
    let close = mgr.check("crosslink", &json!({"operation": "close", "id": 1}));

    assert!(
        matches!(&list, CheckResult::NeedsPrompt { target, .. } if target == "list"),
        "got {list:?}"
    );
    assert!(
        matches!(&close, CheckResult::NeedsPrompt { target, .. } if target == "close"),
        "got {close:?}"
    );

    // Approving one operation must not approve another.
    let (mut scoped, _dir2) = gated_manager();
    scoped.add_session_rule(PermissionRule {
        tool: "Crosslink".to_string(),
        pattern: "list".to_string(),
        decision: PermissionDecision::Allow,
    });
    assert_eq!(
        scoped.check("crosslink", &json!({"operation": "list"})),
        CheckResult::Allowed
    );
    assert!(
        !matches!(
            scoped.check("crosslink", &json!({"operation": "close", "id": 1})),
            CheckResult::Allowed
        ),
        "approving `list` must not approve `close`"
    );
}

/// A shell-shaped payload is no longer parsed at all — it is simply not an
/// operation, so it denies before the database is opened.
#[test]
fn crosslink_rejects_shell_shaped_payloads() {
    let (mgr, _dir) = gated_manager();
    for payload in [
        "create \"pwned\" -p high",
        "list; create \"x\"",
        "list && close 1",
        "close 1 | tee /tmp/x",
    ] {
        let outcome = mgr.check("crosslink", &json!({"operation": payload}));
        assert!(
            matches!(outcome, CheckResult::Denied(_)),
            "{payload:?} must be denied as an unknown operation, got {outcome:?}"
        );
    }
}

/// A Crosslink call with no operation cannot be authorized, so it denies.
#[test]
fn crosslink_without_an_operation_is_denied() {
    let (mgr, _dir) = gated_manager();
    assert!(matches!(
        mgr.check("crosslink", &json!({})),
        CheckResult::Denied(_)
    ));
    assert!(matches!(
        mgr.check("crosslink", &json!({"operation": 7})),
        CheckResult::Denied(_)
    ));
}

/// The classifier and the dispatcher must read one table. If a new operation
/// were added to dispatch without a classification, its effect would be
/// unknown at authorization time.
#[test]
fn crosslink_advertised_operations_equal_classified_operations() {
    let definition = registry()
        .get("crosslink")
        .expect("crosslink registered")
        .definition();
    let advertised: Vec<String> = definition["function"]["parameters"]["properties"]["operation"]
        ["enum"]
        .as_array()
        .expect("operation enum")
        .iter()
        .map(|v| v.as_str().expect("string").to_string())
        .collect();

    let classified: Vec<String> = crosslink::OPERATIONS
        .iter()
        .map(|op| op.name.to_string())
        .collect();

    assert_eq!(
        advertised, classified,
        "every advertised operation must be classified and vice versa"
    );

    for name in &advertised {
        assert!(
            resolve_for_call("crosslink", &json!({"operation": name})).is_ok(),
            "advertised operation {name} does not classify"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Acceptance 3 — generated matrix
// ───────────────────────────────────────────────────────────────────────────

/// The matrix covers every advertised tool, on every surface, and is derived
/// from the declarations dispatch consults rather than hand-maintained.
#[test]
fn generated_matrix_covers_every_advertised_tool() {
    let matrix = effect_matrix();

    // Registry surface: one row per handler, no more and no fewer.
    let registry_rows: Vec<&String> = matrix
        .iter()
        .filter(|row| row.surface == ToolSurface::Registry)
        .map(|row| &row.tool)
        .collect();
    let handler_names: Vec<String> = iter_handlers().map(|h| h.name().to_string()).collect();
    assert_eq!(
        registry_rows.len(),
        handler_names.len(),
        "the matrix must have exactly one row per registered handler"
    );
    for name in &handler_names {
        assert!(
            registry_rows.contains(&name),
            "{name} is dispatchable but missing from the matrix"
        );
    }

    // Every advertised tool — including the subagent tools the registry does
    // not own — must appear.
    let advertised = openclaudia::tools::get_all_tool_definitions(true);
    for tool in advertised.as_array().expect("array") {
        let name = tool["function"]["name"].as_str().expect("name");
        assert!(
            matrix.iter().any(|row| row.tool == name),
            "{name} is advertised to the model but has no matrix row"
        );
    }

    // The dynamic surface is represented too.
    assert!(
        matrix.iter().any(|row| row.surface == ToolSurface::Mcp),
        "the MCP surface must appear in the matrix"
    );
    assert!(
        matrix
            .iter()
            .filter(|row| row.surface == ToolSurface::Subagent)
            .count()
            >= 3,
        "the subagent surface must appear in the matrix"
    );
}

/// Each area the acceptance criteria names is present with an enforced
/// effect, and every row's effect is one the authorization path acts on.
#[test]
fn matrix_covers_each_named_area_with_an_enforced_effect() {
    let matrix = effect_matrix();
    let row_for = |name: &str| {
        matrix
            .iter()
            .find(|row| row.tool == name)
            .unwrap_or_else(|| panic!("{name} missing from matrix"))
    };

    // task, cron, worktree, process, MCP, skill, tool_search, Crosslink.
    assert!(row_for("task").effect.requires_authorization());
    assert!(row_for("cron_create").effect.requires_authorization());
    assert!(row_for("enter_worktree").effect.requires_authorization());
    assert!(row_for("bash").effect.requires_authorization());
    assert!(row_for("kill_shell").effect.requires_authorization());
    assert!(row_for("read_mcp_resource").effect.requires_authorization());
    assert!(row_for("crosslink").effect.requires_authorization());

    // skill and tool_search read from disk and from the registry; they are
    // declared read-only, which is a claim rather than an omission.
    assert_eq!(row_for("skill").effect, ToolEffect::ReadOnly);
    assert_eq!(row_for("tool_search").effect, ToolEffect::ReadOnly);

    // Typed-operation rows enumerate their per-operation effects.
    let crosslink_row = row_for("crosslink");
    assert_eq!(
        crosslink_row.operations.len(),
        crosslink::OPERATIONS.len(),
        "the matrix must enumerate every Crosslink operation"
    );
    let worktree_row = row_for("exit_worktree");
    assert!(
        worktree_row
            .operations
            .values()
            .any(|effect| *effect == ToolEffect::Destructive),
        "the matrix must show the destructive exit_worktree operation"
    );
}

/// Rendering is stable and mentions each surface, so the matrix is usable as
/// evidence rather than only as an in-memory structure.
#[test]
fn rendered_matrix_is_stable_and_complete() {
    let first = render_effect_matrix();
    let second = render_effect_matrix();
    assert_eq!(first, second, "matrix rendering must be deterministic");

    for expected in ["registry", "subagent", "mcp", "destructive", "read_only"] {
        assert!(
            first.contains(expected),
            "rendered matrix is missing {expected}"
        );
    }
    for handler in iter_handlers() {
        assert!(
            first.contains(&format!("`{}`", handler.name())),
            "rendered matrix is missing {}",
            handler.name()
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Acceptance 1 — the construction-failure path actually fires
// ───────────────────────────────────────────────────────────────────────────
//
// Added after adversarial review. The compile-time half of "registry
// construction fails for an unclassified handler" is real — `effect_spec` has
// no default body — but the runtime half was previously unreachable dead code
// that no test drove. These construct deliberately broken handler sets and
// observe the validator rejecting each one.

struct FakeHandler {
    name: &'static str,
    spec: ToolEffectSpec,
    resolver: bool,
    operations: Vec<(&'static str, ToolEffect)>,
}

impl ToolHandler for FakeHandler {
    fn name(&self) -> &'static str {
        self.name
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": self.name,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "arg": {"type": "string"},
                        "t": {"type": "string"}
                    },
                    "required": ["arg", "t"]
                }
            }
        })
    }
    fn effect_spec(&self) -> ToolEffectSpec {
        self.spec
    }
    fn resolve_typed_effect(
        &self,
        _args: &Value,
    ) -> Option<Result<openclaudia::tools::effect::TypedEffect, String>> {
        self.resolver.then(|| {
            Ok(openclaudia::tools::effect::TypedEffect::new(
                ToolEffect::ReadOnly,
                "op",
                "t",
            ))
        })
    }
    fn typed_operations(&self) -> Vec<(&'static str, ToolEffect)> {
        self.operations.clone()
    }
}

fn leak(handler: FakeHandler) -> &'static dyn ToolHandler {
    Box::leak(Box::new(handler))
}

fn expect_rejected(handlers: &[&'static dyn ToolHandler], expected: &str) {
    match validate_handlers(handlers) {
        Ok(()) => panic!("validator accepted a broken handler set (expected {expected:?})"),
        Err(problems) => assert!(
            problems.iter().any(|p| p.contains(expected)),
            "expected a problem containing {expected:?}, got {problems:?}"
        ),
    }
}

#[test]
fn construction_rejects_an_empty_canonical_capability() {
    let handler = leak(FakeHandler {
        name: "broken",
        spec: ToolEffectSpec::effectful(ToolEffect::Destructive, "", "arg"),
        resolver: false,
        operations: Vec::new(),
    });
    expect_rejected(&[handler], "empty canonical capability name");
}

#[test]
fn construction_rejects_an_empty_target_argument_key() {
    let handler = leak(FakeHandler {
        name: "broken",
        spec: ToolEffectSpec::effectful(ToolEffect::WorkspaceMutation, "Cap", "   "),
        resolver: false,
        operations: Vec::new(),
    });
    expect_rejected(&[handler], "empty argument key");
}

#[test]
fn construction_rejects_an_empty_optional_target_default() {
    let handler = leak(FakeHandler {
        name: "broken",
        spec: ToolEffectSpec::read_only_arg_or_default("Read", "arg", ""),
        resolver: false,
        operations: Vec::new(),
    });
    expect_rejected(&[handler], "empty default");
}

#[test]
fn construction_rejects_a_target_missing_from_the_schema() {
    let handler = leak(FakeHandler {
        name: "broken",
        spec: ToolEffectSpec::effectful(ToolEffect::WorkspaceMutation, "Cap", "missing"),
        resolver: false,
        operations: Vec::new(),
    });
    expect_rejected(&[handler], "schema has no such property");
}

struct OptionalTargetHandler;

impl ToolHandler for OptionalTargetHandler {
    fn name(&self) -> &'static str {
        "optional_target"
    }

    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "optional_target",
                "parameters": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": []
                }
            }
        })
    }

    fn effect_spec(&self) -> ToolEffectSpec {
        ToolEffectSpec::effectful(ToolEffect::WorkspaceMutation, "Write", "path")
    }
}

#[test]
fn construction_rejects_a_required_target_that_schema_marks_optional() {
    expect_rejected(
        &[&OptionalTargetHandler],
        "schema does not require that field",
    );
}

#[test]
fn empty_declared_targets_deny_before_policy() {
    for (tool, args) in [
        ("read_file", json!({"path": ""})),
        ("bash", json!({"command": "   "})),
        ("web_fetch", json!({"url": ""})),
        ("list_files", json!({"path": ""})),
    ] {
        assert!(
            resolve_for_call(tool, &args).is_err(),
            "{tool} must not classify an empty permission target"
        );
    }
}

#[test]
fn non_object_argument_envelopes_deny_for_every_surface() {
    for (tool, args) in [
        ("todo_read", json!(null)),
        ("ask_user_question", json!([])),
        ("mcp__server__tool", json!("scalar")),
    ] {
        assert!(
            matches!(
                resolve_for_call(tool, &args),
                Err(EffectResolutionError::MalformedEnvelope { .. })
            ),
            "{tool} accepted non-object args {args}"
        );
    }
}

#[test]
fn construction_rejects_a_duplicate_tool_name() {
    let one = leak(FakeHandler {
        name: "dup",
        spec: ToolEffectSpec::read_only("Cap"),
        resolver: false,
        operations: Vec::new(),
    });
    let two = leak(FakeHandler {
        name: "dup",
        spec: ToolEffectSpec::read_only("Cap"),
        resolver: false,
        operations: Vec::new(),
    });
    expect_rejected(&[one, two], "registered twice");
}

#[test]
fn construction_rejects_an_empty_tool_name() {
    let handler = leak(FakeHandler {
        name: "  ",
        spec: ToolEffectSpec::read_only("Cap"),
        resolver: false,
        operations: Vec::new(),
    });
    expect_rejected(&[handler], "empty name");
}

#[test]
fn construction_rejects_typed_operation_without_a_resolver() {
    let handler = leak(FakeHandler {
        name: "multiplexer",
        spec: ToolEffectSpec::typed_operation(ToolEffect::Destructive, "Cap"),
        resolver: false,
        operations: vec![("op", ToolEffect::ReadOnly)],
    });
    expect_rejected(
        &handler_slice(handler),
        "does not implement resolve_typed_effect",
    );
}

#[test]
fn construction_rejects_a_resolver_without_a_typed_operation_spec() {
    let handler = leak(FakeHandler {
        name: "confused",
        spec: ToolEffectSpec::read_only("Cap"),
        resolver: true,
        operations: Vec::new(),
    });
    expect_rejected(&handler_slice(handler), "does not declare");
}

#[test]
fn construction_rejects_typed_operation_that_enumerates_nothing() {
    let handler = leak(FakeHandler {
        name: "opaque",
        spec: ToolEffectSpec::typed_operation(ToolEffect::Destructive, "Cap"),
        resolver: true,
        operations: Vec::new(),
    });
    expect_rejected(&handler_slice(handler), "enumerates no operations");
}

#[test]
fn construction_rejects_an_unnamed_operation() {
    let handler = leak(FakeHandler {
        name: "unnamed_op",
        spec: ToolEffectSpec::typed_operation(ToolEffect::Destructive, "Cap"),
        resolver: true,
        operations: vec![("", ToolEffect::ReadOnly)],
    });
    expect_rejected(&handler_slice(handler), "unnamed operation");
}

#[test]
fn construction_rejects_a_duplicate_typed_operation() {
    let handler = leak(FakeHandler {
        name: "duplicate_op",
        spec: ToolEffectSpec::typed_operation(ToolEffect::Destructive, "Cap"),
        resolver: true,
        operations: vec![("op", ToolEffect::ReadOnly), ("op", ToolEffect::ReadOnly)],
    });
    expect_rejected(&handler_slice(handler), "more than once");
}

#[test]
fn construction_rejects_an_operation_above_its_ceiling() {
    let handler = leak(FakeHandler {
        name: "low_ceiling",
        spec: ToolEffectSpec::typed_operation(ToolEffect::WorkspaceMutation, "Cap"),
        resolver: false,
        operations: vec![("op", ToolEffect::Destructive)],
    });
    expect_rejected(
        &handler_slice(handler),
        "above its workspace_mutation ceiling",
    );
}

#[test]
fn construction_rejects_resolver_and_table_effect_drift() {
    // FakeHandler's resolver returns ReadOnly/op. This table deliberately says
    // the same operation is destructive; construction must detect the lie.
    let handler = leak(FakeHandler {
        name: "drifting_resolver",
        spec: ToolEffectSpec::typed_operation(ToolEffect::Destructive, "Cap"),
        resolver: true,
        operations: vec![("op", ToolEffect::Destructive)],
    });
    expect_rejected(&handler_slice(handler), "resolver probe returned read_only");
}

#[test]
fn construction_accepts_the_real_catalog() {
    let handlers: Vec<&'static dyn ToolHandler> = iter_handlers().collect();
    validate_handlers(&handlers).expect("the shipped catalog must validate");
}

fn handler_slice(handler: &'static dyn ToolHandler) -> Vec<&'static dyn ToolHandler> {
    vec![handler]
}

// ───────────────────────────────────────────────────────────────────────────
// Enforcement observed at an execution entrypoint, not just at `check`
// ───────────────────────────────────────────────────────────────────────────

fn tool_call(name: &str, args: &Value) -> ToolCall {
    ToolCall {
        id: "call-1".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: name.to_string(),
            arguments: args.to_string(),
        },
    }
}

/// The classification must stop a tool from *running*, not merely produce a
/// `CheckResult`. This drives the public gated dispatch entrypoint and
/// observes that an unclassified tool never reaches a handler.
#[test]
fn unclassified_tool_does_not_execute_through_the_gated_entrypoint() {
    let (mgr, _dir) = gated_manager();
    let call = tool_call("mystery_tool", &json!({"path": "/tmp/x"}));
    let result = execute_tool_with_permission_required(
        support::shared_run_context(),
        &call,
        None,
        None,
        None,
        &mgr,
    );

    let rendered = format!("{result:?}");
    assert!(
        rendered.contains("effect classification") || rendered.contains("Permission denied"),
        "an unclassified tool must be refused before execution; got {rendered}"
    );
}

/// A destructive tool with no matching rule must not execute either.
#[test]
fn destructive_tool_without_a_rule_does_not_execute() {
    let (mgr, _dir) = gated_manager();
    let call = tool_call(
        "exit_worktree",
        &json!({"path": "/tmp/wt", "discard_changes": true}),
    );
    let result = execute_tool_with_permission_required(
        support::shared_run_context(),
        &call,
        None,
        None,
        None,
        &mgr,
    );

    let rendered = format!("{result:?}");
    assert!(
        rendered.contains("Permission") || rendered.contains("permission"),
        "a destructive call with no rule must not run; got {rendered}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Regressions found by adversarial review
// ───────────────────────────────────────────────────────────────────────────

/// Crosslink store operations must not claim to be read-only.
///
/// Reaching the store goes through `Database::open`, which runs `init_schema`
/// and writes DDL; the write path additionally creates `.crosslink/`. A `list`
/// that created a directory and wrote a schema while declaring `ReadOnly`
/// would be the same dishonest-classification shape F-001 records. Retired
/// `.chainlink` stores now fail closed instead of being copied implicitly.
#[test]
fn no_crosslink_store_operation_claims_to_be_read_only() {
    for op in crosslink::OPERATIONS {
        if !op.requires_store {
            assert_eq!(op.effect, ToolEffect::ReadOnly, "{}", op.name);
            continue;
        }
        assert_eq!(
            op.effect,
            ToolEffect::WorkspaceMutation,
            "{} must not be declared read-only: opening the store initializes it",
            op.name
        );
        let resolved = resolve_for_call("crosslink", &json!({"operation": op.name}))
            .unwrap_or_else(|e| panic!("{}: {}", op.name, e.reason()));
        assert!(resolved.effect.requires_authorization(), "{}", op.name);
    }
}

/// Session-local mutation reaches a decision but does not hard-deny
/// non-interactive frontends.
///
/// ACP and swarm workers project `NeedsPrompt` onto `Denied`. Classifying
/// in-memory todo/task/plan state as needing a prompt therefore broke those
/// frontends outright. An explicit deny still applies — proven below.
#[test]
fn session_mutation_defaults_to_allowed_but_honours_an_explicit_deny() {
    let (mgr, _dir) = gated_manager();
    assert_eq!(
        mgr.check("todo_write", &json!({"todos": []})),
        CheckResult::Allowed,
        "session-local mutation must not hard-deny non-interactive frontends"
    );

    let (mut denying, _dir2) = gated_manager();
    denying.add_session_rule(PermissionRule {
        tool: "TodoWrite".to_string(),
        pattern: "**".to_string(),
        decision: PermissionDecision::Deny,
    });
    assert!(
        matches!(
            denying.check("todo_write", &json!({"todos": []})),
            CheckResult::Denied(_)
        ),
        "an explicit deny must still stop a session mutation"
    );
}

/// An explicit deny must be reachable for a declared read-only tool too,
/// otherwise the target those tools declare advertises rule-matching that can
/// never happen.
#[test]
fn explicit_deny_applies_to_read_only_tools() {
    let (mut mgr, _dir) = gated_manager();
    mgr.add_session_rule(PermissionRule {
        tool: "Read".to_string(),
        pattern: "/etc/**".to_string(),
        decision: PermissionDecision::Deny,
    });

    assert!(
        matches!(
            mgr.check("read_file", &json!({"path": "/etc/shadow"})),
            CheckResult::Denied(_)
        ),
        "a Deny rule on a read-only tool must fire"
    );
    assert_eq!(
        mgr.check("read_file", &json!({"path": "/tmp/ok"})),
        CheckResult::Allowed,
        "unrelated reads stay allowed"
    );
    for tool in ["list_files", "glob", "grep"] {
        let args = match tool {
            "list_files" => json!({"path": "/etc/secret"}),
            _ => json!({"path": "/etc/secret", "pattern": "secret"}),
        };
        assert!(
            matches!(mgr.check(tool, &args), CheckResult::Denied(_)),
            "{tool} must scope Read policy to its path, not its search expression or tool name"
        );
    }
}

/// Whole-tool-scope capabilities must not resolve to an empty target.
///
/// An empty target is matched by ordinary path globs — `**` compiles to
/// `^.*$`, which matches `""` — so a user's `default_allow: ["**"]`, written
/// with file paths in mind, would silently grant every such capability.
#[test]
fn tool_scope_targets_are_never_empty() {
    for name in [
        "todo_write",
        "cron_delete",
        "enter_plan_mode",
        "exit_plan_mode",
        "task_create",
        "list_mcp_resources",
    ] {
        let resolved =
            resolve_for_call(name, &json!({})).unwrap_or_else(|e| panic!("{name}: {}", e.reason()));
        assert!(
            !resolved.target.is_empty(),
            "{name} resolved to an empty authorization target"
        );
        assert_eq!(resolved.target, name);
    }
}

/// The matrix asks handlers for their operations; it does not switch on tool
/// names. Every multiplexing handler therefore enumerates, and the registry
/// validator rejects one that does not.
#[test]
fn every_typed_operation_handler_enumerates_its_operations() {
    for handler in iter_handlers() {
        let spec = handler.effect_spec();
        let declares_typed = matches!(
            spec.target,
            openclaudia::tools::effect::ToolTarget::TypedOperation
        );
        let operations = handler.typed_operations();
        assert_eq!(
            declares_typed,
            !operations.is_empty(),
            "{} must enumerate operations exactly when it declares TypedOperation",
            handler.name()
        );
    }
}

/// The `exit_worktree` operation table and its classifier must agree.
///
/// They are separate functions, so a drift between them would show a
/// per-operation effect in the matrix that the authorization path never
/// produces.
#[test]
fn exit_worktree_table_matches_its_classifier() {
    let cases = [
        (
            json!({"path": "/tmp/w", "discard_changes": true}),
            "discard",
        ),
        (json!({"path": "/tmp/w", "apply_changes": true}), "apply"),
        (json!({"path": "/tmp/w"}), "remove_clean"),
    ];

    let table: HashMap<String, ToolEffect> = registry()
        .get("exit_worktree")
        .expect("registered")
        .typed_operations()
        .into_iter()
        .map(|(op, effect)| (op.to_string(), effect))
        .collect();

    assert_eq!(table.len(), cases.len(), "table and classifier must agree");

    for (args, expected_operation) in cases {
        let resolved = resolve_for_call("exit_worktree", &args).expect("classifies");
        assert_eq!(resolved.operation.as_deref(), Some(expected_operation));
        assert_eq!(
            table.get(expected_operation),
            Some(&resolved.effect),
            "{expected_operation}: matrix effect disagrees with the classifier"
        );
    }

    let both = resolve_for_call(
        "exit_worktree",
        &json!({
            "path": "/tmp/w",
            "discard_changes": true,
            "apply_changes": true
        }),
    )
    .expect("both flags still classify according to execution precedence");
    assert_eq!(both.operation.as_deref(), Some("apply"));
    assert_eq!(both.effect, ToolEffect::Destructive);
}

/// Plugin-prefixed names are not classified by any surface, so they deny —
/// and the matrix records that surface rather than omitting it.
#[test]
fn plugin_prefixed_tools_are_unavailable_and_represented() {
    let (mgr, _dir) = gated_manager();
    for name in ["plugin__evil__read_file", "plugin__x__y"] {
        assert!(
            matches!(mgr.check(name, &json!({})), CheckResult::Denied(_)),
            "{name} must be denied: no surface claims it"
        );
    }

    assert!(
        effect_matrix()
            .iter()
            .any(|row| row.surface == ToolSurface::Plugin),
        "the plugin surface must appear in the matrix even though it is unavailable"
    );
}
