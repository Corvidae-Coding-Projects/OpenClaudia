//! Typed `skill` tool dispatch.
//!
//! A model may select a skill that the host already made visible to the exact
//! run. The result remains ordinary source-labelled tool data: model selection
//! never activates the skill's declared tools, hooks, model, or effort.

use serde_json::Value;
use std::collections::HashMap;
use std::hash::BuildHasher;

use crate::skills::{self, SkillActivationTrigger};
use crate::tools::security::ToolRunContext;
use crate::tools::{ToolFailure, ToolFailureCode, ToolHandlerResult, ToolRetryability};

/// Resolve one run-visible skill into a typed, provenance-bearing tool result.
#[must_use]
pub fn execute_skill<S: BuildHasher>(
    run: &ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> ToolHandlerResult {
    let name = match args.get("name") {
        None => return invalid_arguments("skill: missing required argument `name`"),
        Some(Value::String(name)) => name.trim(),
        Some(_) => return invalid_arguments("skill: Invalid 'name' argument: expected string"),
    };
    if name.is_empty() {
        return invalid_arguments("skill: `name` is empty");
    }

    match skills::activate_skill_for_run(run, name, SkillActivationTrigger::ModelSelection) {
        Ok(activation) => {
            let selection = activation.selection();
            let text = format!(
                "Selected skill `{}` as source-labelled reference data. Declared runtime capabilities were not activated.\n\n{}",
                selection.name, selection.prompt
            );
            ToolHandlerResult::success_structured(text, activation.structured())
        }
        Err(error) => ToolHandlerResult::error(ToolFailure::new(
            ToolFailureCode::Unavailable,
            format!("skill: {error}"),
            ToolRetryability::Never,
        )),
    }
}

fn invalid_arguments(message: &str) -> ToolHandlerResult {
    ToolHandlerResult::error(ToolFailure::new(
        ToolFailureCode::InvalidArguments,
        message.to_string(),
        ToolRetryability::Never,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::ToolOutcome;
    use serde_json::json;

    fn run() -> &'static ToolRunContext {
        crate::tools::security::test_run_context().as_ref()
    }

    fn is_error(result: &ToolHandlerResult) -> bool {
        matches!(result.outcome, ToolOutcome::Error { .. })
    }

    #[test]
    fn missing_name_arg_errors() {
        let result = execute_skill(run(), &HashMap::new());
        assert!(is_error(&result));
        assert!(result.content().contains("missing required argument"));
    }

    #[test]
    fn wrong_type_name_arg_errors() {
        let mut args = HashMap::new();
        args.insert("name".to_string(), json!(42));
        let result = execute_skill(run(), &args);
        assert!(is_error(&result));
        assert!(result.content().contains("expected string"));
    }

    #[test]
    fn empty_name_errors() {
        let mut args = HashMap::new();
        args.insert("name".to_string(), json!(""));
        let result = execute_skill(run(), &args);
        assert!(is_error(&result));
        assert!(result.content().contains("empty"));
    }

    #[test]
    fn unknown_skill_errors_without_ambient_project_lookup() {
        let mut args = HashMap::new();
        args.insert(
            "name".to_string(),
            json!("__definitely_not_a_real_skill_xyz_637__"),
        );
        let result = execute_skill(run(), &args);
        assert!(is_error(&result));
        assert!(result.content().contains("unknown or unavailable skill"));
    }
}
