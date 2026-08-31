//! S-021 acceptance coverage for atomic, exact-run blast-radius reservations.

#![allow(clippy::expect_used, clippy::missing_panics_doc)]

use openclaudia::config::{BlastRadiusConfig, GuardrailMode, GuardrailsConfig};
use openclaudia::state::SessionId;
use openclaudia::tools::effect::{resolve_for_call, ToolTargetKind};
use openclaudia::tools::{
    execute_tool, FunctionCall, ToolCall, ToolFailureCode, ToolOutcome, ToolRunContext,
    WorkspaceAccess,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone, Default)]
struct TraceWriter(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for TraceWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("trace buffer")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for TraceWriter {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

fn isolated_run(root: &Path) -> Arc<ToolRunContext> {
    ToolRunContext::builder(SessionId::new(), root)
        .working_directory(root)
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(HashMap::new())
        .workspace_access(WorkspaceAccess::ReadWrite)
        .process(true)
        .network(false)
        .secrets(false)
        .provider("s-021-acceptance")
        .build()
        .expect("isolated run capability")
}

fn strict_config(blast_radius: BlastRadiusConfig) -> GuardrailsConfig {
    GuardrailsConfig {
        blast_radius: Some(BlastRadiusConfig {
            enabled: true,
            mode: GuardrailMode::Strict,
            ..blast_radius
        }),
        diff_monitor: None,
        quality_gates: None,
    }
}

fn tool_call(id: &str, name: &str, arguments: &Value) -> ToolCall {
    ToolCall {
        id: id.to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: name.to_string(),
            arguments: arguments.to_string(),
        },
    }
}

#[test]
fn path_normalization_is_declared_metadata_not_tool_name_guessing() {
    let write = resolve_for_call(
        "write_file",
        &json!({"path":"src/lib.rs","content":"changed"}),
    )
    .expect("write classification");
    let bash = resolve_for_call("bash", &json!({"command":"printf src/lib.rs"}))
        .expect("bash classification");
    let lsp = resolve_for_call(
        "lsp",
        &json!({"action":"hover","file_path":"src/lib.rs","line":1,"character":0}),
    )
    .expect("LSP classification");
    let worktree = resolve_for_call(
        "exit_worktree",
        &json!({"path":".worktrees/agent-fix","operation":"discard"}),
    )
    .expect("worktree classification");
    let grep = resolve_for_call("grep", &json!({"path":".","pattern":"needle"}))
        .expect("recursive scope classification");
    assert_eq!(write.target_kind, ToolTargetKind::Path);
    assert_eq!(lsp.target_kind, ToolTargetKind::Path);
    assert_eq!(worktree.target_kind, ToolTargetKind::Path);
    assert_eq!(grep.target_kind, ToolTargetKind::PathScope);
    assert_eq!(bash.target_kind, ToolTargetKind::Opaque);
}

#[test]
fn reservation_trace_records_exact_run_resource_and_terminal_state() {
    let root = tempfile::tempdir().expect("project root");
    std::fs::write(root.path().join("trace.txt"), "trace").expect("trace fixture");
    let run = isolated_run(root.path());
    let config = strict_config(BlastRadiusConfig {
        max_tool_calls_per_run: NonZeroU32::new(1),
        ..BlastRadiusConfig::default()
    });
    let trace = TraceWriter::default();
    let capture = trace.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(trace)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        openclaudia::guardrails::configure(&run, &config).expect("trace policy");
        let missing = tool_call("trace-missing", "read_file", &json!({"path":"missing.txt"}));
        assert!(
            execute_tool(&run, &missing).is_error(),
            "missing-file failure must exercise reservation release"
        );
        let read = tool_call("trace-read", "read_file", &json!({"path":"trace.txt"}));
        assert!(!execute_tool(&run, &read).is_error());
    });

    let output =
        String::from_utf8(capture.0.lock().expect("trace buffer").clone()).expect("UTF-8 trace");
    assert!(output.contains("blast_radius_effect_reserved"), "{output}");
    assert!(
        output.contains("blast_radius_reservation_committed"),
        "{output}"
    );
    assert!(
        output.contains("blast_radius_reservation_released"),
        "{output}"
    );
    assert!(output.contains(&run.run_id().to_string()), "{output}");
    assert!(output.contains(&run.generation().to_string()), "{output}");
    assert!(output.contains("trace.txt"), "{output}");
}

#[test]
fn invalid_reconfiguration_is_atomic_and_preserves_the_prior_policy() {
    let root = tempfile::tempdir().expect("project root");
    let run = isolated_run(root.path());
    let valid = strict_config(BlastRadiusConfig {
        denied_paths: vec![".env*".to_string()],
        ..BlastRadiusConfig::default()
    });
    openclaudia::guardrails::configure(&run, &valid).expect("valid initial policy");
    assert!(openclaudia::guardrails::check_file_access(&run, ".env.local").is_err());

    let invalid = strict_config(BlastRadiusConfig {
        allowed_paths: vec!["src/../secrets/**".to_string()],
        ..BlastRadiusConfig::default()
    });
    assert!(openclaudia::guardrails::configure(&run, &invalid).is_err());
    assert!(
        openclaudia::guardrails::check_file_access(&run, ".env.local").is_err(),
        "failed replacement must not discard the already-installed strict policy"
    );
    let traversal = openclaudia::guardrails::check_file_access(&run, "src/../.env")
        .expect_err("lexical traversal must never bypass canonical policy");
    assert!(traversal.contains("traversal"), "{traversal}");
}

#[test]
fn relative_and_absolute_aliases_share_one_unique_file_identity() {
    let root = tempfile::tempdir().expect("project root");
    std::fs::write(root.path().join("same.txt"), "same").expect("same file");
    std::fs::write(root.path().join("other.txt"), "other").expect("other file");
    let run = isolated_run(root.path());
    let config = strict_config(BlastRadiusConfig {
        max_files_per_run: NonZeroU32::new(1),
        ..BlastRadiusConfig::default()
    });
    openclaudia::guardrails::configure(&run, &config).expect("strict one-file policy");

    let relative = tool_call("relative", "read_file", &json!({"path":"same.txt"}));
    assert!(!execute_tool(&run, &relative).is_error());
    let absolute = tool_call(
        "absolute",
        "read_file",
        &json!({"path":root.path().join("same.txt").to_string_lossy()}),
    );
    assert!(!execute_tool(&run, &absolute).is_error());
    let other = tool_call("other", "read_file", &json!({"path":"other.txt"}));
    let denied = execute_tool(&run, &other);
    assert!(denied.is_error());
    assert!(
        denied.content().contains("files limit exceeded"),
        "test must prove canonical resource quota denial: {}",
        denied.content()
    );
}

#[cfg(unix)]
#[test]
fn symlink_aliases_share_the_canonical_resource_identity() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("project root");
    std::fs::write(root.path().join("real.txt"), "same").expect("real file");
    std::fs::write(root.path().join("other.txt"), "other").expect("other file");
    symlink("real.txt", root.path().join("alias.txt")).expect("symlink alias");
    let run = isolated_run(root.path());
    let config = strict_config(BlastRadiusConfig {
        max_files_per_run: NonZeroU32::new(1),
        ..BlastRadiusConfig::default()
    });
    openclaudia::guardrails::configure(&run, &config).expect("strict one-file policy");

    openclaudia::guardrails::check_file_access(&run, "real.txt").expect("real path");
    openclaudia::guardrails::check_file_access(&run, "alias.txt")
        .expect("symlink resolves to already-admitted resource");
    let denied = openclaudia::guardrails::check_file_access(&run, "other.txt")
        .expect_err("a different canonical file must exceed the unique-resource cap");
    assert!(denied.contains("files limit exceeded"), "{denied}");
}

#[test]
fn tool_quotas_are_exact_run_scoped_and_failed_calls_release_reservations() {
    let first_root = tempfile::tempdir().expect("first project");
    let second_root = tempfile::tempdir().expect("second project");
    std::fs::write(first_root.path().join("data.txt"), "first").expect("first data");
    std::fs::write(second_root.path().join("data.txt"), "second").expect("second data");
    let first = isolated_run(first_root.path());
    let second = isolated_run(second_root.path());
    let config = strict_config(BlastRadiusConfig {
        max_tool_calls_per_run: NonZeroU32::new(1),
        ..BlastRadiusConfig::default()
    });
    openclaudia::guardrails::configure(&first, &config).expect("first policy");
    openclaudia::guardrails::configure(&second, &config).expect("second policy");

    let failed_overwrite = tool_call(
        "failed-write",
        "write_file",
        &json!({"path":"data.txt","content":"replacement"}),
    );
    assert!(execute_tool(&first, &failed_overwrite).is_error());

    let first_read = tool_call("first-read", "read_file", &json!({"path":"data.txt"}));
    assert!(
        !execute_tool(&first, &first_read).is_error(),
        "the failed write must release its tool/mutation/file reservation"
    );
    let second_read = tool_call("second-read", "read_file", &json!({"path":"data.txt"}));
    assert!(
        !execute_tool(&second, &second_read).is_error(),
        "the first run must not consume the second run's quota"
    );
    let first_exhausted = execute_tool(&first, &first_read);
    let second_exhausted = execute_tool(&second, &second_read);
    for exhausted in [&first_exhausted, &second_exhausted] {
        assert!(exhausted.is_error());
        assert!(
            exhausted.content().contains("tool calls limit exceeded"),
            "test must prove the exact-run quota denied: {}",
            exhausted.content()
        );
    }
}

#[test]
fn recursive_read_families_enforce_policy_on_discovered_children() {
    for (tool_name, arguments) in [
        ("list_files", json!({"path":"."})),
        ("glob", json!({"path":".","pattern":"**"})),
        ("grep", json!({"path":".","pattern":"secret"})),
    ] {
        let root = tempfile::tempdir().expect("project root");
        std::fs::write(root.path().join("visible.txt"), "visible\n").expect("visible fixture");
        std::fs::write(root.path().join(".env-secret"), "secret\n").expect("denied fixture");
        let run = isolated_run(root.path());
        let config = strict_config(BlastRadiusConfig {
            denied_paths: vec![".env*".to_string()],
            ..BlastRadiusConfig::default()
        });
        openclaudia::guardrails::configure(&run, &config).expect("strict child policy");

        let result = execute_tool(
            &run,
            &tool_call(&format!("recursive-{tool_name}"), tool_name, &arguments),
        );
        assert!(
            result.is_error(),
            "{tool_name} must not bypass child policy"
        );
        assert!(
            result.content().contains("matches deny list pattern"),
            "test must prove child-path policy denial for {tool_name}: {}",
            result.content()
        );
        assert!(
            !result.content().contains("secret\n"),
            "denied file content must not be returned by {tool_name}"
        );
    }
}

#[test]
fn recursive_scope_reaches_descendants_allowed_by_a_directory_glob() {
    let root = tempfile::tempdir().expect("project root");
    std::fs::create_dir(root.path().join("allowed")).expect("allowed directory");
    std::fs::write(root.path().join("allowed/data.txt"), "needle\n").expect("allowed fixture");
    let run = isolated_run(root.path());
    let config = strict_config(BlastRadiusConfig {
        allowed_paths: vec!["allowed/**".to_string()],
        ..BlastRadiusConfig::default()
    });
    openclaudia::guardrails::configure(&run, &config).expect("strict allow policy");

    let grep = tool_call(
        "allowed-recursive-scope",
        "grep",
        &json!({"path":"allowed","pattern":"needle"}),
    );
    let result = execute_tool(&run, &grep);
    assert!(
        !result.is_error(),
        "directory scope must reach explicitly allowed descendants: {}",
        result.content()
    );
    assert!(result.content().contains("data.txt:1:needle"));
}

#[test]
fn recursive_scope_does_not_disclose_denied_or_unrelated_directories() {
    let denied_root = tempfile::tempdir().expect("denied project root");
    std::fs::create_dir(denied_root.path().join("secrets")).expect("empty denied directory");
    let denied_run = isolated_run(denied_root.path());
    openclaudia::guardrails::configure(
        &denied_run,
        &strict_config(BlastRadiusConfig {
            denied_paths: vec!["secrets/**".to_string()],
            ..BlastRadiusConfig::default()
        }),
    )
    .expect("denied subtree policy");
    let denied = execute_tool(
        &denied_run,
        &tool_call("denied-empty-directory", "list_files", &json!({"path":"."})),
    );
    assert!(
        denied.is_error(),
        "denied directory name must not be disclosed"
    );
    assert!(denied.content().contains("matches deny list pattern"));
    assert!(!denied.content().contains("secrets/"));

    let allowed_root = tempfile::tempdir().expect("allowed project root");
    std::fs::create_dir(allowed_root.path().join("allowed")).expect("allowed directory");
    std::fs::create_dir(allowed_root.path().join("unrelated")).expect("unrelated directory");
    let allowed_run = isolated_run(allowed_root.path());
    openclaudia::guardrails::configure(
        &allowed_run,
        &strict_config(BlastRadiusConfig {
            allowed_paths: vec!["allowed/**".to_string()],
            ..BlastRadiusConfig::default()
        }),
    )
    .expect("allowed subtree policy");
    let unrelated = execute_tool(
        &allowed_run,
        &tool_call(
            "unrelated-empty-directory",
            "list_files",
            &json!({"path":"."}),
        ),
    );
    assert!(
        unrelated.is_error(),
        "directory outside the allow list must not be disclosed"
    );
    assert!(unrelated.content().contains("not in allowed list"));
    assert!(!unrelated.content().contains("unrelated/"));
}

#[test]
fn recursive_file_quota_denial_releases_the_whole_pending_batch() {
    let root = tempfile::tempdir().expect("project root");
    std::fs::write(root.path().join("a.txt"), "needle a\n").expect("first fixture");
    std::fs::write(root.path().join("b.txt"), "needle b\n").expect("second fixture");
    let run = isolated_run(root.path());
    let config = strict_config(BlastRadiusConfig {
        max_files_per_run: NonZeroU32::new(1),
        ..BlastRadiusConfig::default()
    });
    openclaudia::guardrails::configure(&run, &config).expect("one-file policy");

    let grep = tool_call(
        "recursive-over-cap",
        "grep",
        &json!({"path":".","pattern":"needle"}),
    );
    let denied = execute_tool(&run, &grep);
    assert!(denied.is_error());
    assert!(matches!(
        denied.outcome(),
        ToolOutcome::Error { failure } if failure.code == ToolFailureCode::PolicyDenied
    ));
    assert!(
        denied.content().contains("files limit exceeded"),
        "test must prove concrete-file batch denial: {}",
        denied.content()
    );

    let first = tool_call("after-batch-release", "read_file", &json!({"path":"a.txt"}));
    assert!(
        !execute_tool(&run, &first).is_error(),
        "failed recursive batch must release every pending file identity"
    );
    let second = tool_call("after-one-commit", "read_file", &json!({"path":"b.txt"}));
    let exhausted = execute_tool(&run, &second);
    assert!(exhausted.is_error());
    assert!(exhausted.content().contains("files limit exceeded"));
}

#[test]
fn an_exact_run_policy_cannot_be_reconfigured_to_reset_consumed_quota() {
    let root = tempfile::tempdir().expect("project root");
    std::fs::write(root.path().join("data.txt"), "data").expect("data fixture");
    let run = isolated_run(root.path());
    let config = strict_config(BlastRadiusConfig {
        max_tool_calls_per_run: NonZeroU32::new(1),
        ..BlastRadiusConfig::default()
    });
    openclaudia::guardrails::configure(&run, &config).expect("initial immutable policy");
    let read = tool_call("first-read", "read_file", &json!({"path":"data.txt"}));
    assert!(!execute_tool(&run, &read).is_error());

    let reconfigure = openclaudia::guardrails::configure(&run, &config)
        .expect_err("same-run reconfiguration would reset security quota state");
    assert!(reconfigure.contains("already bound"), "{reconfigure}");
    let exhausted = execute_tool(&run, &read);
    assert!(exhausted.is_error());
    assert!(exhausted.content().contains("tool calls limit exceeded"));
}

#[test]
fn changed_line_limit_denies_before_creating_the_target_and_denial_is_reusable() {
    let root = tempfile::tempdir().expect("project root");
    let run = isolated_run(root.path());
    let config = strict_config(BlastRadiusConfig {
        max_lines_per_run: NonZeroU32::new(1),
        ..BlastRadiusConfig::default()
    });
    openclaudia::guardrails::configure(&run, &config).expect("one-line policy");

    let too_large = tool_call(
        "two-lines",
        "write_file",
        &json!({"path":"too-large.txt","content":"one\ntwo\n"}),
    );
    let denied = execute_tool(&run, &too_large);
    assert!(denied.is_error(), "two changed lines must be denied");
    assert!(
        denied.content().contains("changed lines limit exceeded"),
        "test must prove the line guard denied, not an unrelated boundary: {}",
        denied.content()
    );
    assert!(
        !root.path().join("too-large.txt").exists(),
        "line admission must occur before file creation"
    );

    let allowed = tool_call(
        "one-line",
        "write_file",
        &json!({"path":"allowed.txt","content":"one\n"}),
    );
    assert!(!execute_tool(&run, &allowed).is_error());
    assert_eq!(
        std::fs::read_to_string(root.path().join("allowed.txt")).expect("allowed content"),
        "one\n"
    );
}

#[test]
fn mutation_limit_blocks_a_different_family_before_its_effect() {
    let root = tempfile::tempdir().expect("project root");
    let run = isolated_run(root.path());
    let config = strict_config(BlastRadiusConfig {
        max_mutations_per_run: NonZeroU32::new(1),
        ..BlastRadiusConfig::default()
    });
    openclaudia::guardrails::configure(&run, &config).expect("one-mutation policy");

    let write = tool_call(
        "workspace-mutation",
        "write_file",
        &json!({"path":"committed.txt","content":"done\n"}),
    );
    assert!(!execute_tool(&run, &write).is_error());

    let sentinel = root.path().join("must-not-exist");
    let bash = tool_call(
        "process-mutation",
        "bash",
        &json!({"command":format!("touch {}", sentinel.display())}),
    );
    let denied = execute_tool(&run, &bash);
    assert!(denied.is_error(), "second mutating family must be denied");
    assert!(
        denied.content().contains("mutations limit exceeded"),
        "test must prove the mutation guard denied, not host safety: {}",
        denied.content()
    );
    assert!(
        !sentinel.exists(),
        "mutation quota must deny before the Bash handler starts"
    );
}

#[cfg(unix)]
#[test]
fn failed_bash_rolls_back_effect_but_commits_its_mutation_reservation() {
    let root = tempfile::tempdir().expect("project root");
    let run = isolated_run(root.path());
    let config = strict_config(BlastRadiusConfig {
        max_mutations_per_run: NonZeroU32::new(1),
        ..BlastRadiusConfig::default()
    });
    openclaudia::guardrails::configure(&run, &config).expect("one-mutation policy");

    let source = root.path().join("partial-effect.txt");
    let missing = root.path().join("missing-source.txt");
    let destination = root.path().join("destination");
    std::fs::write(&source, "partial\n").expect("source fixture");
    std::fs::create_dir(&destination).expect("destination fixture");
    let sentinel = destination.join("partial-effect.txt");
    let bash = tool_call(
        "partial-process-mutation",
        "bash",
        &json!({"command":format!(
            "cp '{}' '{}' '{}'",
            source.display(), missing.display(), destination.display()
        )}),
    );
    let partial = execute_tool(&run, &bash);
    assert!(
        partial.is_partial(),
        "started non-zero Bash must be typed partial: {}",
        partial.content()
    );
    assert!(
        !sentinel.exists(),
        "a failed transactional Bash command must not publish its partial workspace effect"
    );
    assert_eq!(
        std::fs::read_to_string(&source).expect("source remains after rollback"),
        "partial\n"
    );

    let write = tool_call(
        "after-partial",
        "write_file",
        &json!({"path":"must-not-exist.txt","content":"blocked\n"}),
    );
    let denied = execute_tool(&run, &write);
    assert!(denied.is_error(), "partial mutation must consume the quota");
    assert!(
        denied.content().contains("mutations limit exceeded"),
        "test must prove the blast-radius quota denied: {}",
        denied.content()
    );
    assert!(!root.path().join("must-not-exist.txt").exists());
}
