//! Non-bypassable host policy for model-supplied tool invocations.
//!
//! Approval policy answers whether a user wants an otherwise admissible
//! operation to run. This module answers the earlier question: whether the
//! host will permit the operation at all. The answer is independent of
//! repository configuration, approval receipts, prompt mode, and frontend.

use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;

use super::effect::{self, ResolvedEffect};

/// Generation of the host-owned safety policy enforced at dispatch.
///
/// Bump this whenever the hard ceiling or its classification contract changes
/// so traces and verification receipts can name the exact policy artifact.
pub const HOST_SAFETY_POLICY_GENERATION: u32 = 1;

/// Stateless, non-configurable host-safety ceiling.
pub struct HostSafetyPolicy;

impl HostSafetyPolicy {
    /// Resolve one concrete invocation and enforce host-owned hard policy.
    ///
    /// The returned effect is the exact classification evaluated by the
    /// policy. Unknown tools, malformed effects, catastrophic shell payloads,
    /// model-supplied sandbox weakening, and protected control-file writes all
    /// fail closed.
    pub fn enforce(tool_name: &str, tool_args: &Value) -> Result<ResolvedEffect, String> {
        let resolved = effect::resolve_for_call(tool_name, tool_args).map_err(|error| {
            let reason = error.reason();
            log_decision("denied", "effect_classification", tool_name, None, "", "");
            reason
        })?;

        tracing::info!(
            target: "openclaudia::permissions",
            event = "tool_effect_classified",
            tool_name = %tool_name,
            canonical_tool = %resolved.canonical,
            effect = resolved.effect.as_str(),
            operation = resolved.operation.as_deref().unwrap_or(""),
            "tool effect classified before policy"
        );

        if let Some((source, reason, target)) = hard_denial(tool_name, tool_args) {
            log_decision(
                "denied",
                source,
                tool_name,
                Some(&resolved),
                &target,
                &reason,
            );
            return Err(reason);
        }

        log_decision(
            "allowed",
            "host_safety_ceiling",
            tool_name,
            Some(&resolved),
            &resolved.target,
            "",
        );
        Ok(resolved)
    }
}

fn hard_denial(tool_name: &str, tool_args: &Value) -> Option<(&'static str, String, String)> {
    match tool_name.to_ascii_lowercase().as_str() {
        "bash" => bash_denial(tool_args),
        "edit" | "edit_file" | "write" | "write_file" => protected_write_denial(tool_args, "path"),
        "notebook_edit" => protected_write_denial(tool_args, "notebook_path"),
        _ => None,
    }
}

fn bash_denial(tool_args: &Value) -> Option<(&'static str, String, String)> {
    if tool_args
        .get("dangerously_disable_sandbox")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        let target = tool_args
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        return Some((
            "model_sandbox_escalation",
            "dangerously_disable_sandbox cannot be set from tool arguments; only the host operator can select sandbox policy"
                .to_string(),
            target,
        ));
    }

    let command = tool_args.get("command")?.as_str()?;
    super::validate_command(command).err().map(|reason| {
        (
            "catastrophic_command",
            format!("Denied by bash hard safety check: {reason}"),
            command.to_string(),
        )
    })
}

fn protected_write_denial(
    tool_args: &Value,
    path_key: &str,
) -> Option<(&'static str, String, String)> {
    let path = tool_args.get(path_key)?.as_str()?;
    protected_write_reason(path).map(|reason| {
        (
            "protected_control_resource",
            reason.to_string(),
            path.to_string(),
        )
    })
}

fn protected_write_reason(path: &str) -> Option<&'static str> {
    let components = normalised_path_components(path);
    if components.iter().any(|component| component == ".git") {
        return Some("Denied by hard safety check: writes inside .git are protected");
    }
    components.windows(2).find_map(|window| {
        (window[0] == ".claude" && window[1] == "settings.json")
            .then_some("Denied by hard safety check: .claude/settings.json is protected")
    })
}

fn normalised_path_components(path: &str) -> Vec<String> {
    let slash_path = path.replace('\\', "/");
    let mut components = Vec::new();
    for raw in slash_path.split('/') {
        // Win32 strips trailing spaces and periods from ordinary path
        // components. Apply that conservative spelling fold on every host so
        // `.git.` and `settings.json ` cannot alias protected controls on
        // Windows while appearing harmless to the host policy. Preserve the
        // two navigation components before trimming periods.
        let without_trailing_spaces = raw.trim_end_matches(' ');
        let normalised = match without_trailing_spaces {
            "." | ".." => without_trailing_spaces,
            component => component.trim_end_matches('.'),
        };
        match normalised {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            component => components.push(component.to_ascii_lowercase()),
        }
    }
    components
}

fn digest_text(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut hexadecimal = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(hexadecimal, "{byte:02x}").expect("writing to a String cannot fail");
    }
    format!("sha256:{hexadecimal}")
}

fn log_decision(
    decision: &'static str,
    source: &'static str,
    wire_tool: &str,
    resolved: Option<&ResolvedEffect>,
    target: &str,
    reason: &str,
) {
    tracing::info!(
        target: "openclaudia::host_safety",
        event = "host_safety_decision",
        policy_generation = HOST_SAFETY_POLICY_GENERATION,
        decision,
        source,
        wire_tool,
        canonical_tool = resolved.map_or("", |effect| effect.canonical.as_str()),
        effect = resolved.map_or("", |effect| effect.effect.as_str()),
        operation = resolved.and_then(|effect| effect.operation.as_deref()).unwrap_or(""),
        target_digest = %digest_text(target),
        reason_digest = %digest_text(reason),
        "non-bypassable host-safety decision"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn catastrophic_bash_is_denied() {
        assert!(HostSafetyPolicy::enforce("bash", &json!({"command": "rm -rf /"})).is_err());
    }

    #[test]
    fn protected_write_is_denied_after_lexical_normalisation() {
        assert!(HostSafetyPolicy::enforce(
            "write_file",
            &json!({"path": "src/../.git/config", "content": "x"})
        )
        .is_err());
    }

    #[test]
    fn windows_trailing_dot_and_space_aliases_are_protected_on_every_host() {
        for path in [r"C:\repo\.git.\config", r"C:\repo\.claude\settings.json "] {
            assert!(
                HostSafetyPolicy::enforce("write_file", &json!({"path": path, "content": "x"}))
                    .is_err(),
                "Windows-normalized control alias escaped host safety: {path}"
            );
        }
    }

    #[test]
    fn every_registered_write_surface_uses_the_same_protected_resource_ceiling() {
        for (tool, arguments) in [
            (
                "write_file",
                json!({"path": ".claude/settings.json", "content": "x"}),
            ),
            (
                "edit_file",
                json!({
                    "path": ".git/config",
                    "old_string": "a",
                    "new_string": "b"
                }),
            ),
            (
                "notebook_edit",
                json!({"notebook_path": ".git/notebook.ipynb", "new_source": "x"}),
            ),
        ] {
            assert!(
                HostSafetyPolicy::enforce(tool, &arguments).is_err(),
                "{tool} bypassed the protected-resource ceiling"
            );
        }
    }

    #[test]
    fn ordinary_classified_call_is_admitted_to_approval_policy() {
        let resolved = HostSafetyPolicy::enforce("bash", &json!({"command": "git status"}))
            .expect("ordinary command clears the host ceiling");
        assert_eq!(resolved.canonical, "Bash");
    }
}
