//! Adversarial end-to-end coverage for S-020 Bash effect classification.
//!
//! Every case traverses the same mandatory registry resolver and permission
//! manager API available to production callers. Lexical appearance is never
//! accepted as positive evidence: only a declared typed `ReadOnly` operation
//! can receive classifier auto-approval.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

use openclaudia::permissions::{
    auto_allow_score, CheckResult, PermissionDecision, PermissionManager, PermissionRule,
};
use openclaudia::tools::effect::{resolve_for_call, ToolEffect};
use openclaudia::tools::{
    execute_tool_with_permission_required, FunctionCall, ToolCall, ToolFailureCode, ToolOutcome,
};
use serde_json::{json, Value};
use tempfile::TempDir;

mod support;

fn fresh_manager() -> (PermissionManager, TempDir) {
    let directory = TempDir::new().expect("permission state tempdir");
    let manager = PermissionManager::new(directory.path().join("rules.json"), true, Vec::new());
    (manager, directory)
}

fn assert_requires_policy(manager: &PermissionManager, tool: &str, args: &Value) {
    assert!(
        auto_allow_score(tool, args) < f32::EPSILON,
        "effectful call received positive auto-approval evidence: {tool} {args}"
    );
    for threshold in [0.0, 0.5, 1.0] {
        let outcome = manager.check_auto_allow(tool, args, threshold);
        assert!(
            matches!(
                outcome,
                CheckResult::NeedsPrompt { .. } | CheckResult::Denied(_)
            ),
            "effectful call bypassed policy at threshold {threshold}: {tool} {args} -> {outcome:?}"
        );
    }
}

fn tool_call(command: &str) -> ToolCall {
    ToolCall {
        id: "s020-bash".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "bash".to_string(),
            arguments: json!({"command": command}).to_string(),
        },
    }
}

#[test]
fn arbitrary_shell_text_is_always_destructive_and_requires_policy() {
    let (manager, _directory) = fresh_manager();
    let commands = [
        ("plain inspector", "ls -la"),
        ("vcs mutation", "git push origin HEAD"),
        ("package hook", "npm install package"),
        (
            "interpreter",
            "python3 -c 'open(\"owned\", \"w\").write(\"x\")'",
        ),
        ("nested shell", "sh -c 'rm -f owned'"),
        ("alias", "alias inspect='rm -f'; inspect owned"),
        ("command wrapper", "command rm -f owned"),
        ("environment wrapper", "env sh -c 'rm -f owned'"),
        ("quoted command", "bash -c \"printf x > owned\""),
        ("substitution", "printf '%s' \"$(rm -f owned)\""),
        ("redirection", "printf x > owned"),
        ("script", "./mutate.sh"),
        ("mixed pipeline", "cat input | rm -f owned"),
    ];

    for (family, command) in commands {
        let args = json!({"command": command});
        let resolved = resolve_for_call("bash", &args).expect("registered Bash must classify");
        assert_eq!(
            resolved.effect,
            ToolEffect::Destructive,
            "Bash family {family:?} was downgraded by shell text"
        );
        assert_requires_policy(&manager, "bash", &args);
    }
}

#[test]
fn public_dispatch_does_not_execute_hidden_mutation_without_policy() {
    let workspace = TempDir::new().expect("workspace tempdir");
    let run = support::test_run_context(workspace.path());
    let (manager, _directory) = fresh_manager();
    let script = workspace.path().join("mutate.sh");
    let script_target = workspace.path().join("script-owned");
    let quoted_script_target =
        shlex::try_quote(script_target.to_str().expect("UTF-8 script target")).expect("quote");
    std::fs::write(&script, format!("printf x > {quoted_script_target}\n"))
        .expect("write inert test script");

    for (family, command, target) in [
        {
            let target = workspace.path().join("alias-owned");
            let quoted = shlex::try_quote(target.to_str().expect("UTF-8 target")).expect("quote");
            (
                "alias",
                format!("alias inspect='printf x > {quoted}'\ninspect"),
                target,
            )
        },
        {
            let target = workspace.path().join("interpreter-owned");
            let literal =
                serde_json::to_string(target.to_str().expect("UTF-8 target")).expect("JSON string");
            (
                "interpreter",
                format!("python3 -c 'open({literal}, \"w\").write(\"x\")'"),
                target,
            )
        },
        {
            let target = workspace.path().join("quoted-owned");
            let quoted = shlex::try_quote(target.to_str().expect("UTF-8 target")).expect("quote");
            (
                "quoted nested shell",
                format!("bash -c 'printf x > {quoted}'"),
                target,
            )
        },
        {
            let target = workspace.path().join("substitution-owned");
            let quoted = shlex::try_quote(target.to_str().expect("UTF-8 target")).expect("quote");
            (
                "substitution",
                format!("printf '%s' \"$(printf x > {quoted})\""),
                target,
            )
        },
        {
            let target = workspace.path().join("redirect-owned");
            let quoted = shlex::try_quote(target.to_str().expect("UTF-8 target")).expect("quote");
            ("redirection", format!("printf x > {quoted}"), target)
        },
        (
            "script",
            format!(
                "bash {}",
                shlex::try_quote(script.to_str().expect("UTF-8 script")).expect("quote")
            ),
            script_target,
        ),
        {
            let target = workspace.path().join("pipeline-owned");
            let quoted = shlex::try_quote(target.to_str().expect("UTF-8 target")).expect("quote");
            (
                "mixed pipeline",
                format!("cat /dev/null | tee {quoted}"),
                target,
            )
        },
    ] {
        let call = tool_call(&command);
        let result = execute_tool_with_permission_required(&run, &call, None, None, None, &manager);
        let ToolOutcome::Error { failure } = result.outcome() else {
            panic!("{family} unexpectedly executed: {result:?}");
        };
        assert_eq!(
            failure.code,
            ToolFailureCode::PermissionDenied,
            "{family} should stop at explicit policy: {failure:?}"
        );
        assert!(
            !target.exists(),
            "{family} mutated the workspace before authorization: {}",
            target.display()
        );
    }
}

#[test]
fn only_declared_typed_reads_receive_auto_approval() {
    let (manager, _directory) = fresh_manager();
    for (tool, args) in [
        ("read_file", json!({"path": "README.md"})),
        ("list_files", json!({"path": "."})),
        ("glob", json!({"path": ".", "pattern": "*.rs"})),
        ("grep", json!({"path": ".", "pattern": "fn main"})),
    ] {
        let resolved = resolve_for_call(tool, &args).expect("typed read must classify");
        assert_eq!(resolved.effect, ToolEffect::ReadOnly, "{tool}");
        assert!((auto_allow_score(tool, &args) - 1.0).abs() < f32::EPSILON);
        assert_eq!(
            manager.check_auto_allow(tool, &args, 1.0),
            CheckResult::Allowed
        );
    }
}

#[test]
fn workspace_mutations_do_not_inherit_path_based_confidence() {
    let (manager, _directory) = fresh_manager();
    for (tool, args) in [
        (
            "edit_file",
            json!({"path": "src/main.rs", "old_string": "a", "new_string": "b"}),
        ),
        ("write_file", json!({"path": "tests/new.rs", "content": ""})),
    ] {
        assert_requires_policy(&manager, tool, &args);
    }
}

#[test]
fn explicit_user_policy_still_authorizes_non_catastrophic_bash() {
    let (mut manager, _directory) = fresh_manager();
    manager.add_session_rule(PermissionRule {
        tool: "Bash".to_string(),
        pattern: "printf **".to_string(),
        decision: PermissionDecision::Allow,
    });

    let args = json!({"command": "printf explicit-policy"});
    assert!(auto_allow_score("bash", &args) < f32::EPSILON);
    assert_eq!(
        manager.check_auto_allow("bash", &args, 0.0),
        CheckResult::Allowed,
        "removing lexical auto-approval must not remove an explicit user authorization"
    );
}

#[test]
fn explicit_denials_and_malformed_calls_remain_fail_closed() {
    let (mut manager, _directory) = fresh_manager();
    manager.add_session_rule(PermissionRule {
        tool: "Read".to_string(),
        pattern: "/secret/**".to_string(),
        decision: PermissionDecision::Deny,
    });
    assert!(matches!(
        manager.check_auto_allow("read_file", &json!({"path": "/secret/value"}), 0.5),
        CheckResult::Denied(_)
    ));

    for (tool, args) in [
        ("bash", json!({})),
        ("bash", json!({"command": 42})),
        ("unknown_tool", json!({})),
    ] {
        assert!(auto_allow_score(tool, &args) < f32::EPSILON);
        assert!(!matches!(
            manager.check_auto_allow(tool, &args, 0.0),
            CheckResult::Allowed
        ));
    }
}

#[test]
fn invalid_thresholds_cannot_enable_effectful_calls() {
    let (manager, _directory) = fresh_manager();
    let args = json!({"command": "ls"});
    for threshold in [f32::NAN, f32::NEG_INFINITY, -0.1, 1.1, f32::INFINITY] {
        assert!(!matches!(
            manager.check_auto_allow("bash", &args, threshold),
            CheckResult::Allowed
        ));
    }
}
