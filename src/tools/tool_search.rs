//! Host-owned progressive tool selection.
//!
//! The previous implementation returned schemas inside an XML-shaped string.
//! No provider treated that text as callable API definitions, so the feature
//! consumed context without deferring anything. The catalog now performs a
//! trusted state transition and the next host-built request publishes the
//! selected schemas. Ordinary result text remains data.

use std::collections::HashMap;
use std::hash::BuildHasher;

use serde_json::{json, Value};

use super::catalog::ToolSelectionReceipt;
use super::{ToolHandlerResult, ToolRunContext};

/// Select bounded schemas in the exact run-owned catalog.
#[must_use]
pub fn execute_tool_search<S: BuildHasher>(
    run: &ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> ToolHandlerResult {
    let owned = args
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<HashMap<_, _>>();
    match run.tool_catalog().activate(run, &owned) {
        Ok(receipt) => selection_result(&receipt),
        Err(failure) => ToolHandlerResult::error(failure),
    }
}

fn selection_result(receipt: &ToolSelectionReceipt) -> ToolHandlerResult {
    let names = receipt
        .activated
        .iter()
        .map(|entry| entry.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    ToolHandlerResult::success_structured(
        format!(
            "Activated for the next provider request: {names}. Catalog generation: {}.",
            receipt.catalog_generation
        ),
        json!({"tool_selection": receipt}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (
        tempfile::TempDir,
        std::sync::Arc<crate::tools::ToolRunContext>,
        crate::tools::catalog::ToolCatalogSnapshot,
    ) {
        let root = tempfile::tempdir().expect("catalog root");
        let run = crate::tools::security::test_run_context_for(root.path());
        let definitions = crate::tools::get_all_tool_definitions(true)
            .as_array()
            .expect("definitions")
            .clone();
        let snapshot = run
            .tool_catalog()
            .snapshot(
                &run,
                &[json!({"role": "user", "content": "inspect code"})],
                &definitions,
            )
            .expect("snapshot");
        (root, run, snapshot)
    }

    #[test]
    fn selection_returns_a_typed_receipt_not_schema_text() {
        let (_root, run, snapshot) = fixture();
        let deferred = crate::tools::get_all_tool_definitions(true)
            .as_array()
            .expect("definitions")
            .iter()
            .filter_map(|definition| definition.pointer("/function/name").and_then(Value::as_str))
            .find(|name| !snapshot.active_names.iter().any(|active| active == name))
            .expect("deferred tool")
            .to_string();
        let args = HashMap::from([
            ("query".to_string(), json!(format!("select:{deferred}"))),
            (
                "catalog_generation".to_string(),
                json!(snapshot.generation.to_string()),
            ),
        ]);
        let result = execute_tool_search(&run, &args);
        assert!(!matches!(
            result.outcome,
            super::super::ToolOutcome::Error { .. }
        ));
        assert!(!result.content().contains("<functions>"));
        let super::super::ToolOutcome::Success { content } = &result.outcome else {
            panic!("selection must succeed: {result:#?}");
        };
        let structured = content
            .structured
            .as_ref()
            .expect("typed selection receipt");
        assert_eq!(
            structured["tool_selection"]["catalog_generation"],
            snapshot.generation.to_string()
        );
        assert_eq!(
            structured["tool_selection"]["activated"][0]["name"],
            deferred
        );
    }

    #[test]
    fn duplicate_direct_names_do_not_bypass_result_cap() {
        let (_root, run, snapshot) = fixture();
        let args = HashMap::from([
            (
                "query".to_string(),
                json!("select:memory_search,memory_search,memory_search"),
            ),
            (
                "catalog_generation".to_string(),
                json!(snapshot.generation.to_string()),
            ),
            ("max_results".to_string(), json!(1)),
        ]);
        let result = execute_tool_search(&run, &args);
        let super::super::ToolOutcome::Success { content } = &result.outcome else {
            panic!("selection must succeed: {result:#?}");
        };
        assert_eq!(
            content.structured.as_ref().expect("selection")["tool_selection"]["activated"]
                .as_array()
                .expect("activated")
                .len(),
            1
        );
    }
}
