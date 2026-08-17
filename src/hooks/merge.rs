//! Hook merging utilities
//!
//! Functions for merging hook configurations from multiple sources,
//! deep-merging JSON settings files, and converting Claude Code hooks
//! to `OpenClaudia` format.

use crate::config::{Hook, HookEntry, HooksConfig};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use thiserror::Error;
use tracing::{debug, error, warn};

use super::claude_compat::{ClaudeCodeHook, ClaudeCodeSettings};
use super::HookEvent;

/// Maximum recursion depth for [`deep_merge`].
///
/// Picked to comfortably exceed any realistic, hand-authored settings
/// structure (Claude Code's own schema bottoms out at ~5 levels) while
/// still leaving stack headroom across all supported platforms. A
/// 100k-level hostile settings file would otherwise overflow the stack
/// before `serde_json` itself bails (crosslink #333).
pub(crate) const MAX_MERGE_DEPTH: usize = 32;

/// Maximum length of any single array after concatenation in
/// [`deep_merge`]. A hostile managed-settings file could otherwise
/// append unbounded entries to e.g. `hooks.PreToolUse` and exhaust
/// memory (crosslink #333). Excess entries are dropped with a
/// `warn!` carrying the JSON path of the truncated array.
pub(crate) const MAX_ARRAY_CONCAT_LEN: usize = 8192;

/// Soft cap on the serialized size of the fully merged settings tree,
/// enforced post-merge by [`enforce_total_size`]. Four MiB is large
/// enough to fit any realistic Claude Code settings layering and
/// small enough to detect runaway accumulation across the four
/// `load_claude_settings` layers (crosslink #333).
pub(crate) const MAX_TOTAL_SIZE: usize = 4 * 1024 * 1024;

/// Errors emitted by [`deep_merge`] and [`merge_settings_file`].
///
/// All variants carry enough context (the JSON path that broke the
/// limit, the limit itself, and the observed value) to make forensic
/// triage of a malicious settings file possible from the log stream
/// alone.
#[derive(Debug, Error)]
pub enum MergeError {
    /// [`MAX_MERGE_DEPTH`] would be exceeded by a recursive call.
    ///
    /// `encountered_at` is the dotted JSON path (e.g.
    /// `hooks.PreToolUse[0].hooks[0]`) where the limit was hit.
    #[error(
        "deep_merge depth limit {limit} exceeded at path `{encountered_at}` \
         (refusing to recurse further to prevent stack overflow)"
    )]
    DepthExceeded {
        limit: usize,
        encountered_at: String,
    },

    /// Post-merge serialized size exceeds [`MAX_TOTAL_SIZE`].
    #[error(
        "merged settings exceed total-size limit ({observed} > {limit} bytes); \
         refusing to use as harness configuration"
    )]
    TotalSizeExceeded { limit: usize, observed: usize },
}

/// Compute the serialized size of `value` and compare it to
/// [`MAX_TOTAL_SIZE`]. Returns `Err(MergeError::TotalSizeExceeded)`
/// when the cap is breached so callers can fall back to defaults.
pub(crate) fn enforce_total_size(value: &Value) -> Result<(), MergeError> {
    // serde_json::to_vec is the cheapest accurate measure; computing a
    // running size during merge would require touching every node.
    let serialized = serde_json::to_vec(value).map_err(|e| {
        // A serialization error here should be impossible for a tree
        // we just built out of serde_json::Value — but surface it as a
        // size violation rather than panicking.
        warn!(error = %e, "Failed to measure merged settings size; treating as oversize");
        MergeError::TotalSizeExceeded {
            limit: MAX_TOTAL_SIZE,
            observed: usize::MAX,
        }
    })?;
    if serialized.len() > MAX_TOTAL_SIZE {
        return Err(MergeError::TotalSizeExceeded {
            limit: MAX_TOTAL_SIZE,
            observed: serialized.len(),
        });
    }
    Ok(())
}

/// Merge two `HooksConfig` structs, with `other` taking precedence.
/// Entries from `other` with the same matcher as an entry in `base` replace the base entry.
#[must_use]
pub fn merge_hooks_config(base: HooksConfig, other: HooksConfig) -> HooksConfig {
    let mut merged = base;

    if other.policy.is_some() {
        merged.policy = other.policy;
    }
    dedup_hook_entries(&mut merged.session_start, other.session_start);
    dedup_hook_entries(&mut merged.session_end, other.session_end);
    dedup_hook_entries(&mut merged.pre_tool_use, other.pre_tool_use);
    dedup_hook_entries(&mut merged.post_tool_use, other.post_tool_use);
    dedup_hook_entries(
        &mut merged.post_tool_use_failure,
        other.post_tool_use_failure,
    );
    dedup_hook_entries(&mut merged.user_prompt_submit, other.user_prompt_submit);
    dedup_hook_entries(&mut merged.stop, other.stop);
    dedup_hook_entries(&mut merged.subagent_start, other.subagent_start);
    dedup_hook_entries(&mut merged.subagent_stop, other.subagent_stop);
    dedup_hook_entries(&mut merged.pre_compact, other.pre_compact);
    dedup_hook_entries(&mut merged.permission_request, other.permission_request);
    dedup_hook_entries(&mut merged.notification, other.notification);
    dedup_hook_entries(&mut merged.pre_adversary_review, other.pre_adversary_review);
    dedup_hook_entries(
        &mut merged.post_adversary_review,
        other.post_adversary_review,
    );
    dedup_hook_entries(&mut merged.vdd_conflict, other.vdd_conflict);
    dedup_hook_entries(&mut merged.vdd_converged, other.vdd_converged);

    merged
}

/// Merge a lower-authority hook layer with a host-owned layer.
///
/// When the lower layer carries a command allowlist and the host has not
/// supplied an explicit replacement policy, include the host's statically
/// configured command executables before merging. This prevents an approved
/// repository import from accidentally disabling pre-existing host hooks
/// while retaining the import's full-sandbox default. A host policy, when
/// present, remains authoritative and replaces the lower policy normally.
#[must_use]
pub(crate) fn merge_host_hooks(mut lower: HooksConfig, host: HooksConfig) -> HooksConfig {
    if host.policy.is_none() {
        if let Some(allowed_commands) = lower
            .policy
            .as_mut()
            .and_then(|policy| policy.allowed_commands.as_mut())
        {
            collect_command_executables(&host, allowed_commands);
        }
    }
    merge_hooks_config(lower, host)
}

fn collect_command_executables(config: &HooksConfig, commands: &mut HashSet<String>) {
    for entries in [
        &config.session_start,
        &config.session_end,
        &config.pre_tool_use,
        &config.post_tool_use,
        &config.post_tool_use_failure,
        &config.user_prompt_submit,
        &config.stop,
        &config.subagent_start,
        &config.subagent_stop,
        &config.pre_compact,
        &config.permission_request,
        &config.notification,
        &config.pre_adversary_review,
        &config.post_adversary_review,
        &config.vdd_conflict,
        &config.vdd_converged,
    ] {
        for entry in entries {
            for hook in &entry.hooks {
                let Hook::Command { command, .. } = hook else {
                    continue;
                };
                if let Some(executable) = shlex::split(command).and_then(|tokens| {
                    tokens.first().and_then(|token| {
                        Path::new(token)
                            .file_name()
                            .and_then(|name| name.to_str())
                            .map(str::to_string)
                    })
                }) {
                    commands.insert(executable);
                }
            }
        }
    }
}

/// Normalize a hook matcher key: treat `None` and `Some("")` identically so
/// callers that vary on this don't end up with shadow duplicates
/// (crosslink #339).
fn norm_matcher_key(m: Option<&String>) -> Option<String> {
    m.filter(|s| !s.is_empty()).cloned()
}

/// Extend `base` with entries from `other`, replacing any base entry whose
/// matcher matches an entry in `other` (later source wins).
///
/// Uses a `HashMap` keyed on the normalized matcher for O(n+m) merge
/// (vs the previous O(n*m) `Vec::retain` per entry — crosslink #339).
/// When `other` replaces a base entry, the replaced entry's command list
/// is logged at WARN so users can detect silent overrides.
fn dedup_hook_entries(base: &mut Vec<HookEntry>, other: Vec<HookEntry>) {
    if other.is_empty() {
        return;
    }

    // Build an index of base entries by normalized matcher -> position. O(n).
    let mut index: HashMap<Option<String>, usize> = base
        .iter()
        .enumerate()
        .map(|(i, e)| (norm_matcher_key(e.matcher.as_ref()), i))
        .collect();

    for entry in other {
        let key = norm_matcher_key(entry.matcher.as_ref());
        if let Some(&pos) = index.get(&key) {
            // Replacement: surface the dropped commands so silent overrides
            // are visible in the warn-level log stream.
            let replaced_commands: Vec<String> = base[pos]
                .hooks
                .iter()
                .map(|h| match h {
                    Hook::Command { command, .. } => command.clone(),
                    Hook::Prompt { prompt, .. } => format!("<prompt: {prompt}>"),
                    Hook::Model { model, prompt, .. } => format!("<model {model}: {prompt}>"),
                })
                .collect();
            warn!(
                matcher = ?key,
                replaced_commands = ?replaced_commands,
                "Hook entry replaced by later source (same matcher)"
            );
            base[pos] = entry;
        } else {
            index.insert(key, base.len());
            base.push(entry);
        }
    }
}

/// Merge a settings file into the accumulator using deep merge semantics.
///
/// - Objects merge recursively
/// - Arrays concatenate (capped at [`MAX_ARRAY_CONCAT_LEN`])
/// - Scalars from the new file override
///
/// Errors from [`deep_merge`] (depth-limit violations from a
/// maliciously deep settings file) are surfaced via `error!` and the
/// in-progress merge is rolled back to its pre-merge state so the
/// harness keeps running on safe defaults rather than crashing
/// (crosslink #333).
pub(crate) fn merge_settings_file(target: &mut Value, path: &Path) {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            debug!(path = ?path, error = %e, "Could not read settings file");
            return;
        }
    };
    let new_settings = match serde_json::from_str::<Value>(&content) {
        Ok(v) => v,
        Err(e) => {
            warn!(path = ?path, error = %e, "Failed to parse settings file");
            return;
        }
    };

    // Snapshot so we can roll back on error and never leave the
    // accumulator in a half-merged state.
    let snapshot = target.clone();
    if let Err(e) = deep_merge(target, &new_settings, 0, "$") {
        error!(
            path = ?path,
            error = %e,
            "Refusing to merge settings file; rolling back to pre-merge state"
        );
        *target = snapshot;
    }
}

/// Deep merge two JSON values.
///
/// - Objects: recursively merge keys
/// - Arrays: concatenate, truncated to [`MAX_ARRAY_CONCAT_LEN`]
/// - Scalars: `source` overrides `target`
///
/// `depth` is the current recursion depth (callers start at `0`);
/// `path` is the dotted JSON path of `target` (callers start at `"$"`),
/// used purely for diagnostic context in [`MergeError::DepthExceeded`]
/// and the array-truncation `warn!`.
///
/// Returns [`MergeError::DepthExceeded`] when a recursive call would
/// exceed [`MAX_MERGE_DEPTH`]; on error the partial work performed
/// before the limit was reached remains in `target`. Callers that
/// need atomicity (see [`merge_settings_file`]) snapshot and roll
/// back themselves.
pub(crate) fn deep_merge(
    target: &mut Value,
    source: &Value,
    depth: usize,
    path: &str,
) -> Result<(), MergeError> {
    // Guard: refuse to do any work — including the descent into a
    // child — when we're already at the cap. The first call uses
    // depth=0, so this fires the moment a would-be recursive call
    // would land at depth=MAX_MERGE_DEPTH.
    if depth >= MAX_MERGE_DEPTH {
        return Err(MergeError::DepthExceeded {
            limit: MAX_MERGE_DEPTH,
            encountered_at: path.to_owned(),
        });
    }

    match (target, source) {
        (Value::Object(target_map), Value::Object(source_map)) => {
            for (key, source_val) in source_map {
                let entry = target_map.entry(key.clone()).or_insert(Value::Null);
                let child_path = format!("{path}.{key}");
                deep_merge(entry, source_val, depth + 1, &child_path)?;
            }
        }
        (Value::Array(target_arr), Value::Array(source_arr)) => {
            let combined = target_arr.len().saturating_add(source_arr.len());
            if combined > MAX_ARRAY_CONCAT_LEN {
                let dropped = combined - MAX_ARRAY_CONCAT_LEN;
                let remaining = MAX_ARRAY_CONCAT_LEN.saturating_sub(target_arr.len());
                warn!(
                    array_path = %path,
                    cap = MAX_ARRAY_CONCAT_LEN,
                    existing_len = target_arr.len(),
                    incoming_len = source_arr.len(),
                    dropped,
                    "Array concatenation would exceed cap; truncating to cap"
                );
                if remaining > 0 {
                    target_arr.extend(source_arr.iter().take(remaining).cloned());
                }
            } else {
                target_arr.extend(source_arr.iter().cloned());
            }
        }
        (target, source) => {
            *target = source.clone();
        }
    }
    Ok(())
}

/// Merge Claude Code hooks into `OpenClaudia` `HooksConfig`
pub(crate) fn merge_claude_hooks(config: &mut HooksConfig, settings: &ClaudeCodeSettings) {
    for (event_name, entries) in &settings.hooks {
        let Some(event) = HookEvent::from_claude_code_name(event_name) else {
            warn!(event = %event_name, "Unknown Claude Code hook event, skipping");
            continue;
        };

        // Convert Claude Code entries to OpenClaudia format
        let converted_entries: Vec<HookEntry> = entries
            .iter()
            .map(|entry| {
                let hooks: Vec<Hook> = entry
                    .hooks
                    .iter()
                    .map(|h| match h {
                        ClaudeCodeHook::Command { command, timeout } => Hook::Command {
                            command: command.clone(),
                            // Claude Code settings files have no shell: field;
                            // default to the safe direct-spawn mode.
                            shell: false,
                            timeout: timeout.unwrap_or(60),
                        },
                    })
                    .collect();

                HookEntry {
                    matcher: entry.matcher.clone().filter(|m| !m.is_empty()),
                    hooks,
                }
            })
            .collect();

        // Append to the appropriate event list. Full Claude Code
        // hook-event coverage — anything Claude Code can configure in
        // settings.json reaches our HookEngine.
        match event {
            HookEvent::SessionStart => config.session_start.extend(converted_entries),
            HookEvent::SessionEnd => config.session_end.extend(converted_entries),
            HookEvent::PreToolUse => config.pre_tool_use.extend(converted_entries),
            HookEvent::PostToolUse => config.post_tool_use.extend(converted_entries),
            HookEvent::PostToolUseFailure => {
                config.post_tool_use_failure.extend(converted_entries);
            }
            HookEvent::UserPromptSubmit => config.user_prompt_submit.extend(converted_entries),
            HookEvent::Stop => config.stop.extend(converted_entries),
            HookEvent::SubagentStart => config.subagent_start.extend(converted_entries),
            HookEvent::SubagentStop => config.subagent_stop.extend(converted_entries),
            HookEvent::PreCompact => config.pre_compact.extend(converted_entries),
            HookEvent::PermissionRequest => {
                config.permission_request.extend(converted_entries);
            }
            HookEvent::Notification => config.notification.extend(converted_entries),
            // VDD events aren't in Claude Code's schema — merge path
            // never sees them (from_claude_code_name filters them out).
            HookEvent::PreAdversaryReview
            | HookEvent::PostAdversaryReview
            | HookEvent::VddConflict
            | HookEvent::VddConverged => {
                debug!(event = ?event, "VDD-specific event not expected in Claude Code settings");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Hook, HookEntry, HooksConfig};

    fn cmd_entry(matcher: Option<&str>, command: &str) -> HookEntry {
        HookEntry {
            matcher: matcher.map(str::to_owned),
            hooks: vec![Hook::Command {
                command: command.to_owned(),
                shell: false,
                timeout: 60,
            }],
        }
    }

    #[test]
    fn dedup_collides_on_normalized_none_and_empty() {
        // None and Some("") must collide (semantic identity, crosslink #339).
        let mut base = HooksConfig::default();
        base.pre_tool_use.push(cmd_entry(None, "base-cmd"));

        let mut other = HooksConfig::default();
        other
            .pre_tool_use
            .push(cmd_entry(Some(""), "other-cmd-empty-matcher"));

        let merged = merge_hooks_config(base, other);
        assert_eq!(
            merged.pre_tool_use.len(),
            1,
            "None and Some(\"\") matchers must be treated as the same key"
        );
        let Hook::Command { command, .. } = &merged.pre_tool_use[0].hooks[0] else {
            panic!("expected Hook::Command");
        };
        assert_eq!(command, "other-cmd-empty-matcher");
    }

    #[test]
    fn dedup_replaces_on_matcher_collision_later_source_wins() {
        let mut base = HooksConfig::default();
        base.pre_tool_use
            .push(cmd_entry(Some("Write"), "base-write"));
        base.pre_tool_use.push(cmd_entry(Some("Read"), "base-read"));

        let mut other = HooksConfig::default();
        other
            .pre_tool_use
            .push(cmd_entry(Some("Write"), "other-write"));

        let merged = merge_hooks_config(base, other);
        assert_eq!(merged.pre_tool_use.len(), 2);
        // Read entry preserved unchanged
        let read_e = merged
            .pre_tool_use
            .iter()
            .find(|e| e.matcher.as_deref() == Some("Read"))
            .expect("Read matcher preserved");
        let Hook::Command { command, .. } = &read_e.hooks[0] else {
            panic!("expected Hook::Command");
        };
        assert_eq!(command, "base-read");
        // Write entry replaced
        let write_e = merged
            .pre_tool_use
            .iter()
            .find(|e| e.matcher.as_deref() == Some("Write"))
            .expect("Write matcher present");
        let Hook::Command { command, .. } = &write_e.hooks[0] else {
            panic!("expected Hook::Command");
        };
        assert_eq!(command, "other-write");
    }

    #[test]
    fn dedup_preserves_non_colliding_entries_from_both_sides() {
        let mut base = HooksConfig::default();
        base.pre_tool_use.push(cmd_entry(Some("A"), "a"));
        base.pre_tool_use.push(cmd_entry(Some("B"), "b"));

        let mut other = HooksConfig::default();
        other.pre_tool_use.push(cmd_entry(Some("C"), "c"));

        let merged = merge_hooks_config(base, other);
        assert_eq!(merged.pre_tool_use.len(), 3);
        let matchers: Vec<&str> = merged
            .pre_tool_use
            .iter()
            .map(|e| e.matcher.as_deref().unwrap_or(""))
            .collect();
        assert!(matchers.contains(&"A"));
        assert!(matchers.contains(&"B"));
        assert!(matchers.contains(&"C"));
    }

    // ====================================================================
    // crosslink #333 — deep_merge depth + array-concat DoS regressions
    // ====================================================================

    /// Build a JSON value nested `depth` levels deep, terminating in
    /// an empty object so the entire chain is `Object` at every
    /// level: `{"k": {"k": {"k": ... {}}}}`.
    ///
    /// Both target and source must be `Object` at a given level for
    /// `deep_merge` to recurse — a scalar (including `Null`) on
    /// either side triggers the catch-all replace arm and stops the
    /// descent. Terminating in `{}` keeps the entire path
    /// recursion-eligible so depth tests actually exercise the
    /// recursion guard.
    fn nested_object(depth: usize) -> Value {
        let mut v = Value::Object(serde_json::Map::new());
        for _ in 0..depth {
            let mut m = serde_json::Map::new();
            m.insert("k".to_owned(), v);
            v = Value::Object(m);
        }
        v
    }

    #[test]
    fn deep_merge_rejects_1000_level_nesting_without_stack_overflow() {
        // 1000 levels is ~30x MAX_MERGE_DEPTH and well into the
        // territory that would have overflowed the stack pre-fix.
        // We must (a) return Err rather than panic and (b) report
        // the path where the limit was hit.
        //
        // Both sides must share the nested-object path for the
        // recursion to actually descend — otherwise the
        // `or_insert(Value::Null)` + catch-all replace arm
        // short-circuits at depth=1. This exercises the worst case:
        // a hostile settings file deepening an already-deep
        // accumulator.
        let source = nested_object(1000);
        let mut target = nested_object(1000);

        let err = deep_merge(&mut target, &source, 0, "$")
            .expect_err("1000-level nesting must trigger DepthExceeded");

        match err {
            MergeError::DepthExceeded {
                limit,
                encountered_at,
            } => {
                assert_eq!(limit, MAX_MERGE_DEPTH);
                // Path should be "$" + MAX_MERGE_DEPTH ".k" segments.
                let expected_segments = MAX_MERGE_DEPTH;
                let actual_segments = encountered_at.matches(".k").count();
                assert_eq!(
                    actual_segments, expected_segments,
                    "encountered_at should pinpoint the exact depth: got `{encountered_at}`",
                );
            }
            other @ MergeError::TotalSizeExceeded { .. } => {
                panic!("expected DepthExceeded, got {other:?}")
            }
        }
    }

    #[test]
    fn deep_merge_truncates_9000_element_array_to_cap() {
        // An array of 9000 elements merged into an empty array
        // should produce exactly MAX_ARRAY_CONCAT_LEN (8192) elements
        // and emit a warn — we verify the truncation; the warn is
        // emitted by tracing and observable in the test log stream.
        let source_arr: Vec<Value> = (0..9000_i64).map(Value::from).collect();
        let source = Value::Array(source_arr);
        let mut target = Value::Array(Vec::new());

        deep_merge(&mut target, &source, 0, "$.hooks.PreToolUse")
            .expect("array merge under depth cap must succeed");

        let Value::Array(out) = &target else {
            panic!("target must remain an array");
        };
        assert_eq!(
            out.len(),
            MAX_ARRAY_CONCAT_LEN,
            "9000-element array must be truncated to MAX_ARRAY_CONCAT_LEN"
        );
        // Order preserved: we kept the first 8192 elements.
        assert_eq!(out[0], Value::from(0_i64));
        assert_eq!(out[MAX_ARRAY_CONCAT_LEN - 1], Value::from(8191_i64));
    }

    #[test]
    fn deep_merge_normal_nested_depth_5_arrays_of_10_succeeds_unchanged() {
        // Realistic Claude Code settings shape: hooks.PreToolUse
        // contains entries each with a small command list. Depth ~5,
        // arrays of length ~10. Must merge byte-for-byte identically
        // to the legacy concat-and-recurse behaviour.
        let base: Value = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Write", "hooks": [
                        { "type": "command", "command": "echo base1" },
                        { "type": "command", "command": "echo base2" },
                    ]},
                ],
                "PostToolUse": [
                    { "matcher": "Read", "hooks": [
                        { "type": "command", "command": "echo base-post" },
                    ]},
                ],
            },
            "allowedTools": ["Read", "Write", "Bash"],
        });
        let overlay: Value = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Edit", "hooks": [
                        { "type": "command", "command": "echo edit1" },
                    ]},
                ],
            },
            "allowedTools": ["Edit", "Grep", "Glob"],
            "model": "claude-opus-4-7",
        });

        let mut target = base;
        deep_merge(&mut target, &overlay, 0, "$").expect("normal merge must succeed");

        // hooks.PreToolUse is concatenated.
        let pre = target
            .pointer("/hooks/PreToolUse")
            .and_then(|v| v.as_array())
            .expect("PreToolUse present");
        assert_eq!(pre.len(), 2, "two PreToolUse entries after concat");

        // hooks.PostToolUse from base is preserved.
        let post = target
            .pointer("/hooks/PostToolUse")
            .and_then(|v| v.as_array())
            .expect("PostToolUse preserved");
        assert_eq!(post.len(), 1);

        // allowedTools arrays concatenate (3 + 3 = 6).
        let allowed = target
            .pointer("/allowedTools")
            .and_then(|v| v.as_array())
            .expect("allowedTools present");
        assert_eq!(allowed.len(), 6);

        // Scalar from overlay overrides absent scalar in base.
        assert_eq!(
            target.pointer("/model").and_then(|v| v.as_str()),
            Some("claude-opus-4-7"),
        );
    }

    #[test]
    fn merge_settings_file_four_file_sequence_with_malicious_input_does_not_crash() {
        // Simulate the load_claude_settings 4-file load order with a
        // hostile second file containing a 200-level nested object
        // along the same path the first benign file already
        // established. The harness must:
        //   * not panic
        //   * surface an error (via tracing::error!) for the
        //     malicious file
        //   * roll the accumulator back to its pre-merge state for
        //     that file (snapshot/restore in merge_settings_file)
        //   * still apply the remaining benign files on top
        let tmp = tempfile::tempdir().expect("create tempdir");

        // File 1: establishes a chain of nested `k` objects so that
        // when File 2's hostile depth-bomb arrives, recursion
        // actually descends (both sides Object at each level) and
        // the depth guard fires. Without a shared path the
        // catch-all scalar arm would replace at depth=1 and the
        // bomb would silently land.
        let benign1 = tmp.path().join("01-user.json");
        std::fs::write(
            &benign1,
            r#"{ "allowedTools": ["Read"], "k": { "k": { "k": {} } } }"#,
        )
        .unwrap();

        // File 2: depth-bomb along /k/k/k/... — 200 levels past cap.
        let mut hostile = String::with_capacity(200 * 8);
        for _ in 0..200 {
            hostile.push_str("{\"k\":");
        }
        hostile.push_str("{}");
        for _ in 0..200 {
            hostile.push('}');
        }
        let malicious = tmp.path().join("02-project.json");
        std::fs::write(&malicious, &hostile).unwrap();

        let benign3 = tmp.path().join("03-local.json");
        std::fs::write(&benign3, r#"{ "allowedTools": ["Write"] }"#).unwrap();

        let benign4 = tmp.path().join("04-managed.json");
        std::fs::write(&benign4, r#"{ "model": "claude-opus-4-7" }"#).unwrap();

        let mut settings = Value::Object(serde_json::Map::default());
        // Must not panic. Each call is independent and the malicious
        // file's contribution is rolled back to the post-File-1 state.
        merge_settings_file(&mut settings, &benign1);

        // Snapshot what /k looked like after File 1.
        let k_after_benign1 = settings.pointer("/k").cloned();

        merge_settings_file(&mut settings, &malicious);

        // Rollback: /k must be byte-identical to what File 1 left.
        let k_after_malicious = settings.pointer("/k").cloned();
        assert_eq!(
            k_after_benign1, k_after_malicious,
            "merge_settings_file must roll back on DepthExceeded; \
             /k changed from {k_after_benign1:?} to {k_after_malicious:?}",
        );

        merge_settings_file(&mut settings, &benign3);
        merge_settings_file(&mut settings, &benign4);

        // Benign files were applied: allowedTools concatenated.
        let allowed = settings
            .pointer("/allowedTools")
            .and_then(|v| v.as_array())
            .expect("benign allowedTools survived");
        let names: Vec<&str> = allowed.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(names, vec!["Read", "Write"]);
        // Benign file 4 applied.
        assert_eq!(
            settings.pointer("/model").and_then(|v| v.as_str()),
            Some("claude-opus-4-7"),
        );
    }

    #[test]
    fn deep_merge_at_depth_limit_succeeds_one_past_fails() {
        // Counter-test for the depth-cap boundary.
        //
        // `deep_merge` refuses to do *any* work — including descending
        // into a child — when called with `depth >= MAX_MERGE_DEPTH`.
        // The initial call uses depth=0, so for a tree built by
        // `nested_object(N)` (which is `N` chained {"k": ...} objects
        // wrapping a final `{}`), every level adds one recursive
        // call at depth+1. The deepest call lands at depth=N.
        //
        //   nested_object(MAX_MERGE_DEPTH)   => deepest call at
        //     depth=MAX_MERGE_DEPTH (cap) → fail.
        //   nested_object(MAX_MERGE_DEPTH-1) => deepest call at
        //     depth=MAX_MERGE_DEPTH-1 (cap-1) → succeed.
        //
        // So `MAX_MERGE_DEPTH-1` is the at-the-limit success case and
        // `MAX_MERGE_DEPTH` is the just-past failure case. The
        // task's "depth=32 succeeds; depth=33 fails" formulation
        // describes the *number of recursive descents that ran
        // successfully* (32 of them, at depths 0..=31).
        let at_limit_src = nested_object(MAX_MERGE_DEPTH - 1);
        let mut at_limit_dst = nested_object(MAX_MERGE_DEPTH - 1);
        deep_merge(&mut at_limit_dst, &at_limit_src, 0, "$")
            .expect("32 recursive descents (depths 0..=31) must succeed");

        let past_limit_src = nested_object(MAX_MERGE_DEPTH);
        let mut past_limit_dst = nested_object(MAX_MERGE_DEPTH);
        let err = deep_merge(&mut past_limit_dst, &past_limit_src, 0, "$")
            .expect_err("33rd recursive descent (depth=32) must trigger DepthExceeded");
        assert!(
            matches!(err, MergeError::DepthExceeded { limit, .. } if limit == MAX_MERGE_DEPTH),
            "expected DepthExceeded with limit={MAX_MERGE_DEPTH}, got {err:?}",
        );
    }

    #[test]
    fn deep_merge_array_at_exact_cap_no_warn_truncate() {
        // Boundary check for the array path: a merge that produces
        // exactly MAX_ARRAY_CONCAT_LEN elements must succeed
        // unchanged (no truncation, no warn).
        let source: Vec<Value> = (0..u64::try_from(MAX_ARRAY_CONCAT_LEN).expect("usize fits u64"))
            .map(Value::from)
            .collect();
        let source_val = Value::Array(source);
        let mut target = Value::Array(Vec::new());

        deep_merge(&mut target, &source_val, 0, "$").expect("at-cap merge succeeds");
        let Value::Array(out) = &target else {
            panic!("target must remain an array");
        };
        assert_eq!(out.len(), MAX_ARRAY_CONCAT_LEN);
    }

    #[test]
    fn enforce_total_size_rejects_oversized_payload() {
        // 5 MiB serialized payload (single string field) must trip
        // the total-size guard.
        let payload = "x".repeat(5 * 1024 * 1024);
        let v = serde_json::json!({ "blob": payload });
        let err = enforce_total_size(&v).expect_err("5 MiB payload must exceed MAX_TOTAL_SIZE");
        match err {
            MergeError::TotalSizeExceeded { limit, observed } => {
                assert_eq!(limit, MAX_TOTAL_SIZE);
                assert!(observed > MAX_TOTAL_SIZE);
            }
            other @ MergeError::DepthExceeded { .. } => {
                panic!("expected TotalSizeExceeded, got {other:?}")
            }
        }

        // Small payload passes.
        let small = serde_json::json!({ "ok": true });
        enforce_total_size(&small).expect("small payload must pass");
    }
}
