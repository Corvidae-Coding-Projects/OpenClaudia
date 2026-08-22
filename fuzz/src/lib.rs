//! Hermetic, bounded entry points shared by the `cargo-fuzz` binaries and
//! ordinary Rust 1.98 regression tests.
//!
//! Fuzzer-controlled bytes never reach a production tool handler. Pure
//! validators and classifiers receive bounded data directly; the one
//! filesystem-oriented target resolves paths through a process/network/secret
//! denied run capability rooted in owned temporary directories.

use openclaudia::pipeline::{build_request, process_sse_event, SseAction};
use openclaudia::providers::convert_messages_to_anthropic_checked;
use openclaudia::state::SessionId;
use openclaudia::tools::{
    effect, registry, resolve_capability_path, safe_truncate, validate_cron_expression,
    AnthropicContentBlock, AnthropicToolAccumulator, ToolCallAccumulator, ToolRunContext,
    WorkspaceAccess, MAX_PARALLEL_TOOL_CALL_SLOTS,
};
use openclaudia::tui::{MarkdownRenderState, StreamingMarkdownRenderer, Theme};
use serde_json::Value;
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tempfile::TempDir;

/// Maximum bytes admitted by any single fuzz iteration.
pub const MAX_FUZZ_INPUT_BYTES: usize = 64 * 1024;
const MAX_JSON_ITEMS: usize = 256;
const MAX_DERIVED_BYTES: usize = 8 * 1024 * 1024;
const FUZZ_TERMINAL_COLUMNS: u16 = 80;

fn bounded(data: &[u8]) -> Option<&[u8]> {
    (data.len() <= MAX_FUZZ_INPUT_BYTES).then_some(data)
}

fn bounded_utf8(data: &[u8]) -> Option<&str> {
    std::str::from_utf8(bounded(data)?).ok()
}

fn encoded_json(value: &Value) -> Vec<u8> {
    let bytes = serde_json::to_vec(value).expect("serializing serde_json::Value cannot fail");
    assert!(
        bytes.len() <= MAX_DERIVED_BYTES,
        "derived JSON exceeded the fuzz allocation bound"
    );
    bytes
}

fn conversion_signature(messages: &[Value]) -> Result<Vec<u8>, String> {
    convert_messages_to_anthropic_checked(messages)
        .map(|converted| encoded_json(&Value::Array(converted)))
        .map_err(|error| error.to_string())
}

/// Exercise checked Anthropic history conversion and its deterministic output
/// bounds.
///
/// # Panics
///
/// Panics only when the pure converter is nondeterministic or produces output
/// beyond the declared harness bound.
pub fn fuzz_anthropic_convert(data: &[u8]) {
    let Some(data) = bounded(data) else {
        return;
    };
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    let messages = match value {
        Value::Array(messages) if messages.len() <= MAX_JSON_ITEMS => messages,
        Value::Array(_) => return,
        message => vec![message],
    };

    let first = conversion_signature(&messages);
    let second = conversion_signature(&messages);
    assert_eq!(first, second, "Anthropic conversion must be deterministic");
    if let Err(error) = first {
        assert!(
            error.len() <= MAX_DERIVED_BYTES,
            "Anthropic conversion error exceeded the harness bound"
        );
    }
}

fn request_signature(provider: &str, effort: &str, messages: &[Value]) -> Result<Vec<u8>, String> {
    build_request(provider, "fuzz-model", messages, effort, None, None).and_then(|request| {
        if !request.is_object() {
            return Err("provider request builder returned a non-object envelope".to_string());
        }
        Ok(encoded_json(&request))
    })
}

/// Exercise every provider request-builder family without transport, secrets,
/// or ambient service access.
///
/// # Panics
///
/// Panics only when a pure request builder is nondeterministic or violates the
/// declared output bound/object-envelope invariant.
pub fn fuzz_build_request(data: &[u8]) {
    let Some((&selector, payload)) = bounded(data).and_then(|bytes| bytes.split_first()) else {
        return;
    };
    let Ok(Value::Array(messages)) = serde_json::from_slice::<Value>(payload) else {
        return;
    };
    if messages.len() > MAX_JSON_ITEMS {
        return;
    }

    const PROVIDERS: &[&str] = &[
        "anthropic",
        "openai",
        "google",
        "deepseek",
        "qwen",
        "zai",
        "kimi",
        "minimax",
        "ollama",
        "unknown",
    ];
    const EFFORTS: &[&str] = &["low", "medium", "high", "max", "invalid"];
    let provider = PROVIDERS[usize::from(selector) % PROVIDERS.len()];
    let effort = EFFORTS[(usize::from(selector) / PROVIDERS.len()) % EFFORTS.len()];
    let first = request_signature(provider, effort, &messages);
    let second = request_signature(provider, effort, &messages);
    assert_eq!(
        first, second,
        "provider request construction must be deterministic"
    );
    if let Err(error) = first {
        assert!(
            error.len() <= MAX_DERIVED_BYTES,
            "provider request error exceeded the harness bound"
        );
    }
}

/// Exercise the pure cron grammar without opening schedule storage.
///
/// # Panics
///
/// Panics only when a validation diagnostic exceeds the declared bound.
pub fn fuzz_cron_validate(data: &[u8]) {
    let Some(expression) = bounded_utf8(data) else {
        return;
    };
    if let Err(error) = validate_cron_expression(expression) {
        assert!(
            error.len() <= MAX_DERIVED_BYTES,
            "cron validation error exceeded the harness bound"
        );
    }
}

/// Exercise the production hook matcher without loading or executing hooks.
///
/// # Panics
///
/// Panics only when a matcher diagnostic exceeds the declared bound.
pub fn fuzz_hook_matcher(data: &[u8]) {
    let Some(input) = bounded_utf8(data) else {
        return;
    };
    let midpoint = input.floor_char_boundary(input.len() / 2);
    let (pattern, context) = input.split_at(midpoint);
    if let Err(error) = openclaudia::hooks::validate_hook_matcher(pattern, context) {
        assert!(
            error.to_string().len() <= MAX_DERIVED_BYTES,
            "hook matcher error exceeded the harness bound"
        );
    }
}

fn effect_signature(
    tool_name: &str,
    arguments: &Value,
) -> Result<(String, String, String, String, Option<String>), String> {
    effect::resolve_for_call(tool_name, arguments)
        .map(|resolved| {
            (
                resolved.effect.as_str().to_string(),
                resolved.canonical,
                resolved.target,
                format!("{:?}", resolved.target_kind),
                resolved.operation,
            )
        })
        .map_err(|error| error.reason())
}

/// Parse arbitrary JSON and run only the mandatory effect classifier for one
/// registered or unknown tool name. No handler dispatch is reachable.
///
/// # Panics
///
/// Panics only when pure classification is nondeterministic or produces a
/// diagnostic/target beyond the declared bound.
pub fn fuzz_json_tool_args(data: &[u8]) {
    let Some((&selector, payload)) = bounded(data).and_then(|bytes| bytes.split_first()) else {
        return;
    };
    let Ok(arguments) = serde_json::from_slice::<Value>(payload) else {
        return;
    };
    let handler_count = registry::iter_handlers().count();
    let selected = usize::from(selector) % (handler_count + 1);
    let tool_name = registry::iter_handlers()
        .nth(selected)
        .map_or("unknown_fuzz_tool", openclaudia::tools::ToolHandler::name);

    let first = effect_signature(tool_name, &arguments);
    let second = effect_signature(tool_name, &arguments);
    assert_eq!(
        first, second,
        "tool effect classification must be deterministic"
    );
    let derived_size = match &first {
        Ok((effect, canonical, target, target_kind, operation)) => effect
            .len()
            .saturating_add(canonical.len())
            .saturating_add(target.len())
            .saturating_add(target_kind.len())
            .saturating_add(operation.as_ref().map_or(0, String::len)),
        Err(error) => error.len(),
    };
    assert!(
        derived_size <= MAX_DERIVED_BYTES,
        "tool classification output exceeded the harness bound"
    );
}

struct HermeticPathHost {
    _project: TempDir,
    project_root: PathBuf,
    run: Arc<ToolRunContext>,
}

impl HermeticPathHost {
    fn new() -> Self {
        let project = tempfile::Builder::new()
            .prefix("openclaudia-fuzz-path-")
            .tempdir()
            .expect("create owned fuzz project root");
        let project_root = project
            .path()
            .canonicalize()
            .expect("canonicalize owned fuzz project root");
        let run = ToolRunContext::builder(SessionId::new(), &project_root)
            .workspace_access(WorkspaceAccess::ReadWrite)
            .read_only_roots(Vec::new())
            .read_write_roots(vec![project_root.clone()])
            .environment_grants(HashMap::new())
            .process(false)
            .network(false)
            .secrets(false)
            .build()
            .expect("build hermetic fuzz run capability");
        Self {
            _project: project,
            project_root,
            run,
        }
    }

    fn resolve(&self, input: &str) -> Result<PathBuf, String> {
        resolve_capability_path(&self.run, input)
    }

    fn contains(&self, path: &std::path::Path) -> bool {
        path.starts_with(&self.project_root) || path.starts_with(self.run.private_temp_root())
    }
}

fn path_host() -> &'static HermeticPathHost {
    static HOST: OnceLock<HermeticPathHost> = OnceLock::new();
    HOST.get_or_init(HermeticPathHost::new)
}

/// Resolve arbitrary path text against an owned, explicitly denied host
/// capability and assert that successful resolution cannot escape it.
///
/// # Panics
///
/// Panics when the harness cannot create its owned temporary capability root,
/// resolution is nondeterministic, or a successful path escapes the capability.
pub fn fuzz_path_resolve(data: &[u8]) {
    let Some(path) = bounded_utf8(data) else {
        return;
    };
    let host = path_host();
    let first = host.resolve(path);
    let second = host.resolve(path);
    assert_eq!(
        first, second,
        "capability path resolution must be deterministic"
    );
    match first {
        Ok(resolved) => assert!(
            host.contains(&resolved),
            "resolved path escaped the owned fuzz capability"
        ),
        Err(error) => assert!(
            error.len() <= MAX_DERIVED_BYTES,
            "path resolution error exceeded the harness bound"
        ),
    }
}

/// Exercise UTF-8 truncation at input-derived and boundary-adjacent lengths.
///
/// # Panics
///
/// Panics when truncation violates prefix, boundary, monotonicity, or
/// idempotence invariants.
pub fn fuzz_safe_truncate(data: &[u8]) {
    let Some(input) = bounded_utf8(data) else {
        return;
    };
    let selected = data.first().map_or(0, |byte| usize::from(*byte));
    let mut limits = vec![
        0,
        1,
        selected,
        input.len() / 2,
        input.len(),
        input.len().saturating_add(1),
    ];
    limits.sort_unstable();
    limits.dedup();

    let mut previous = "";
    for limit in limits {
        let truncated = safe_truncate(input, limit);
        assert!(truncated.len() <= limit);
        assert!(input.starts_with(truncated));
        assert!(truncated.is_char_boundary(truncated.len()));
        assert_eq!(safe_truncate(truncated, limit), truncated);
        assert!(truncated.starts_with(previous));
        previous = truncated;
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SseSummary {
    action_bytes: usize,
    thinking_open: bool,
    stop_reason: Option<String>,
    has_tool_use: bool,
    anthropic_blocks: usize,
    openai_slots: usize,
    tool_calls: Vec<u8>,
    anthropic_tool_calls: Vec<u8>,
}

fn summarize_sse(events: &[Value]) -> SseSummary {
    let mut anthropic = AnthropicToolAccumulator::new();
    let mut openai = ToolCallAccumulator::new();
    let mut thinking_open = false;
    let mut action_bytes = 0usize;

    for event in events {
        let action = process_sse_event(event, thinking_open, &mut anthropic, &mut openai);
        match action {
            SseAction::Text(text) | SseAction::Thinking(text) | SseAction::Reasoning(text) => {
                action_bytes = action_bytes.saturating_add(text.len());
            }
            SseAction::ThinkingStart => thinking_open = true,
            SseAction::ThinkingEnd => thinking_open = false,
            SseAction::None => {}
        }
    }

    assert!(openai.tool_calls.len() <= MAX_PARALLEL_TOOL_CALL_SLOTS);
    assert!(anthropic.blocks.len() <= events.len());
    assert!(action_bytes <= MAX_DERIVED_BYTES);
    let has_tool_use = anthropic.has_tool_use();
    if has_tool_use {
        assert_eq!(anthropic.stop_reason.as_deref(), Some("tool_use"));
        assert!(anthropic
            .blocks
            .iter()
            .any(|block| matches!(block, AnthropicContentBlock::ToolUse { .. })));
    }

    let tool_calls = serde_json::to_vec(&openai.finalize())
        .expect("serializing finalized OpenAI tool calls cannot fail");
    let anthropic_tool_calls = serde_json::to_vec(&anthropic.to_openai_tool_calls_json())
        .expect("serializing finalized Anthropic tool calls cannot fail");
    assert!(tool_calls.len() <= MAX_DERIVED_BYTES);
    assert!(anthropic_tool_calls.len() <= MAX_DERIVED_BYTES);

    SseSummary {
        action_bytes,
        thinking_open,
        stop_reason: anthropic.stop_reason.clone(),
        has_tool_use,
        anthropic_blocks: anthropic.blocks.len(),
        openai_slots: openai.tool_calls.len(),
        tool_calls,
        anthropic_tool_calls,
    }
}

/// Exercise a bounded sequence of SSE events and assert deterministic protocol,
/// accumulator, terminal, and allocation state.
///
/// # Panics
///
/// Panics when processing is nondeterministic or a protocol/allocation invariant
/// is violated.
pub fn fuzz_sse_event(data: &[u8]) {
    let Some(data) = bounded(data) else {
        return;
    };
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    let events = match value {
        Value::Array(events) if events.len() <= MAX_JSON_ITEMS => events,
        Value::Array(_) => return,
        event => vec![event],
    };
    assert_eq!(
        summarize_sse(&events),
        summarize_sse(&events),
        "SSE state transition must be deterministic"
    );
}

#[derive(Default)]
struct BoundedWriter {
    bytes: Vec<u8>,
}

impl io::Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next_len = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("render output length overflow"))?;
        if next_len > MAX_DERIVED_BYTES {
            return Err(io::Error::other("render output exceeded fuzz bound"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn render_whole(input: &str) -> (Vec<u8>, MarkdownRenderState) {
    let mut renderer = StreamingMarkdownRenderer::with_theme(Theme::default());
    let mut writer = BoundedWriter::default();
    renderer
        .push_to(input, &mut writer, FUZZ_TERMINAL_COLUMNS)
        .and_then(|()| renderer.flush_to(&mut writer, FUZZ_TERMINAL_COLUMNS))
        .expect("bounded deterministic Markdown render");
    (writer.bytes, renderer.into_state())
}

fn render_partitioned(input: &str, chunk_bytes: usize) -> (Vec<u8>, MarkdownRenderState) {
    let mut renderer = StreamingMarkdownRenderer::with_theme(Theme::default());
    let mut writer = BoundedWriter::default();
    let mut position = 0usize;
    while position < input.len() {
        let proposed = position.saturating_add(chunk_bytes).min(input.len());
        let mut end = input.floor_char_boundary(proposed);
        if end == position {
            end = position + input[position..].chars().next().map_or(0, char::len_utf8);
        }
        renderer
            .push_to(&input[position..end], &mut writer, FUZZ_TERMINAL_COLUMNS)
            .expect("bounded partitioned Markdown render");
        position = end;
    }
    renderer
        .flush_to(&mut writer, FUZZ_TERMINAL_COLUMNS)
        .expect("flush bounded partitioned Markdown render");
    (writer.bytes, renderer.into_state())
}

/// Render bounded Markdown into memory and prove whole-input and arbitrary
/// UTF-8-safe chunk partitions have identical bytes and parser state.
///
/// # Panics
///
/// Panics when rendering exceeds the bound or chunking changes output/state.
pub fn fuzz_streaming_markdown(data: &[u8]) {
    let Some(input) = bounded_utf8(data) else {
        return;
    };
    let chunk_bytes = data.first().map_or(1, |byte| usize::from(*byte) % 64 + 1);
    assert_eq!(
        render_whole(input),
        render_partitioned(input, chunk_bytes),
        "Markdown rendering must be invariant to UTF-8-safe chunking"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct TargetContract {
        name: &'static str,
        function_name: &'static str,
        runner: fn(&[u8]),
    }

    const TARGETS: &[TargetContract] = &[
        TargetContract {
            name: "fuzz_anthropic_convert",
            function_name: "fuzz_anthropic_convert",
            runner: fuzz_anthropic_convert,
        },
        TargetContract {
            name: "fuzz_build_request",
            function_name: "fuzz_build_request",
            runner: fuzz_build_request,
        },
        TargetContract {
            name: "fuzz_cron_validate",
            function_name: "fuzz_cron_validate",
            runner: fuzz_cron_validate,
        },
        TargetContract {
            name: "fuzz_hook_matcher",
            function_name: "fuzz_hook_matcher",
            runner: fuzz_hook_matcher,
        },
        TargetContract {
            name: "fuzz_json_tool_args",
            function_name: "fuzz_json_tool_args",
            runner: fuzz_json_tool_args,
        },
        TargetContract {
            name: "fuzz_path_resolve",
            function_name: "fuzz_path_resolve",
            runner: fuzz_path_resolve,
        },
        TargetContract {
            name: "fuzz_safe_truncate",
            function_name: "fuzz_safe_truncate",
            runner: fuzz_safe_truncate,
        },
        TargetContract {
            name: "fuzz_sse_event",
            function_name: "fuzz_sse_event",
            runner: fuzz_sse_event,
        },
        TargetContract {
            name: "fuzz_streaming_markdown",
            function_name: "fuzz_streaming_markdown",
            runner: fuzz_streaming_markdown,
        },
    ];

    #[test]
    fn target_sources_delegate_only_to_the_hermetic_harness() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let expected_targets = TARGETS
            .iter()
            .map(|target| target.name)
            .collect::<std::collections::BTreeSet<_>>();
        let actual_targets = fs::read_dir(manifest.join("fuzz_targets"))
            .expect("read fuzz target directory")
            .map(|entry| entry.expect("read fuzz target entry").path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
            .map(|path| {
                path.file_stem()
                    .and_then(|stem| stem.to_str())
                    .expect("fuzz target name must be UTF-8")
                    .to_string()
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            actual_targets,
            expected_targets
                .iter()
                .map(ToString::to_string)
                .collect::<std::collections::BTreeSet<_>>(),
            "every fuzz target must be represented by the hermetic target contract"
        );

        for target in TARGETS {
            let source = fs::read_to_string(
                manifest
                    .join("fuzz_targets")
                    .join(format!("{}.rs", target.name)),
            )
            .expect("read fuzz target source");
            assert!(
                source.contains(&format!("openclaudia_fuzz::{}(data)", target.function_name)),
                "{} must delegate to its tested hermetic entry point",
                target.name
            );
            for forbidden in [
                "execute_tool",
                "std::process::Command",
                "reqwest::",
                "std::fs::",
            ] {
                assert!(
                    !source.contains(forbidden),
                    "{} contains forbidden ambient effect surface {forbidden}",
                    target.name
                );
            }
        }

        let library = fs::read_to_string(manifest.join("src/lib.rs"))
            .expect("read shared fuzz harness source");
        let production = library
            .split_once("#[cfg(test)]")
            .map_or(library.as_str(), |(production, _)| production);
        for forbidden in [
            "execute_tool",
            "std::process",
            "tokio::process",
            "reqwest::",
            "ToolContext",
            "ToolDispatchPermit",
            "execute_legacy",
        ] {
            assert!(
                !production.contains(forbidden),
                "shared fuzz harness contains forbidden ambient effect surface {forbidden}"
            );
        }
    }

    #[test]
    fn every_target_has_a_small_tracked_seed() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for target in TARGETS {
            let corpus = manifest.join("corpus").join(target.name);
            let seeds = fs::read_dir(&corpus)
                .unwrap_or_else(|error| panic!("read {}: {error}", corpus.display()))
                .map(|entry| entry.expect("read corpus entry").path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("seed-"))
                })
                .collect::<Vec<_>>();
            assert!(
                !seeds.is_empty(),
                "{} has no reviewed seed corpus",
                target.name
            );
            for seed in seeds {
                let metadata = fs::symlink_metadata(&seed).expect("inspect seed metadata");
                assert!(
                    metadata.is_file(),
                    "{} is not a regular seed",
                    seed.display()
                );
                assert!(
                    metadata.len()
                        <= u64::try_from(MAX_FUZZ_INPUT_BYTES)
                            .expect("fuzz input bound must fit in u64"),
                    "{} exceeds the fuzz input bound",
                    seed.display()
                );
                let data = fs::read(&seed).expect("read reviewed corpus seed");
                (target.runner)(&data);
            }
        }
    }

    #[test]
    fn hostile_regressions_cannot_create_the_requested_host_file() {
        let outside = tempfile::Builder::new()
            .prefix("openclaudia-fuzz-sentinel-")
            .tempdir()
            .expect("create sentinel parent");
        let sentinel = outside.path().join("must-not-exist");
        let shell_arguments = serde_json::json!({
            "command": format!("touch {}", sentinel.display()),
            "path": sentinel,
            "operation": "close",
            "id": 1,
        })
        .to_string();
        for selector in 0..=u8::MAX {
            let mut input = vec![selector];
            input.extend_from_slice(shell_arguments.as_bytes());
            fuzz_json_tool_args(&input);
        }
        fuzz_path_resolve(sentinel.to_string_lossy().as_bytes());
        fuzz_cron_validate(b"*/0 * * * *");
        assert!(
            !sentinel.exists(),
            "a hermetic fuzz entry point created attacker-selected host state"
        );
    }

    #[test]
    fn semantic_regression_inputs_exercise_every_entry_point() {
        let messages = serde_json::json!([{"role": "user", "content": "hello"}]);
        let message_array = messages.as_array().expect("fixture must be an array");
        let converted =
            conversion_signature(message_array).expect("convert valid Anthropic fixture");
        assert!(!converted.is_empty());
        let request = request_signature("anthropic", "medium", message_array)
            .expect("build valid provider fixture");
        assert!(serde_json::from_slice::<Value>(&request)
            .expect("decode request fixture")
            .is_object());
        assert!(validate_cron_expression("*/5 0-12/2 * * 1,5").is_ok());
        assert!(openclaudia::hooks::validate_hook_matcher("Write", "Write")
            .expect("match valid hook fixture"));
        let effect = effect_signature("read_file", &serde_json::json!({"path": "src/lib.rs"}))
            .expect("classify valid file-read fixture");
        assert_eq!(effect.0, "read_only");
        assert_eq!(effect.1, "Read");
        assert_eq!(effect.2, "src/lib.rs");

        let resolved = path_host()
            .resolve("nested/new-file.txt")
            .expect("resolve path below hermetic root");
        assert!(path_host().contains(&resolved));
        assert_eq!(safe_truncate("aé🙂z", 4), "aé");

        let events = serde_json::from_slice::<Vec<Value>>(
            br#"[{"type":"content_block_start","content_block":{"type":"tool_use","id":"call-1","name":"read_file"}},{"type":"content_block_delta","delta":{"type":"input_json_delta","partial_json":"{\"path\":\"README.md\"}"}},{"type":"message_delta","delta":{"stop_reason":"tool_use"}}]"#,
        )
        .expect("decode valid SSE fixture");
        let sse = summarize_sse(&events);
        assert!(sse.has_tool_use);
        assert_eq!(sse.stop_reason.as_deref(), Some("tool_use"));

        let markdown = "# heading\n```rust\nfn main() { println!(\"hello\"); }\n```\n🙂";
        let whole = render_whole(markdown);
        assert!(!whole.0.is_empty());
        assert_eq!(whole, render_partitioned(markdown, 3));

        fuzz_anthropic_convert(messages.to_string().as_bytes());
        fuzz_build_request(format!("a{messages}").as_bytes());
        fuzz_cron_validate(b"*/5 0-12/2 * * 1,5");
        fuzz_hook_matcher(b"WriteWrite");
        fuzz_json_tool_args(b"a{\"path\":\"src/lib.rs\"}");
        fuzz_path_resolve(b"nested/new-file.txt");
        fuzz_safe_truncate("aé🙂z".as_bytes());
        fuzz_sse_event(
            serde_json::to_string(&events)
                .expect("encode SSE fixture")
                .as_bytes(),
        );
        fuzz_streaming_markdown(markdown.as_bytes());
    }
}
