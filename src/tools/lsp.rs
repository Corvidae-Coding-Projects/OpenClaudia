//! Language Server Protocol code-intelligence tool.
//!
//! Model-facing validation and result projection live here. Process and
//! protocol lifetime are owned by the run-scoped
//! [`crate::services::LspServerManager`].

use crate::services::{LspCallHierarchyContinuation, LspDiagnosticPublication, LspServiceRequest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;
use std::io::Read as _;
use std::path::PathBuf;
use std::time::Duration;

/// Maximum source-file size accepted for LSP analysis.
pub const LSP_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;
const LSP_GITIGNORE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SYMBOL_DEPTH: usize = 20;
const MAX_RESULT_ITEMS: usize = 256;
const MAX_SYMBOL_NODES: usize = 512;
const MAX_QUERY_BYTES: usize = 16 * 1024;
const MAX_CONTINUATION_TOKEN_BYTES: usize = 1024;
const MAX_HOVER_BYTES: usize = 64 * 1024;
const MAX_SYMBOL_TEXT_BYTES: usize = 8 * 1024;
const MAX_LSP_OUTPUT_BYTES: usize = 2 * 1024 * 1024;

/// LSP operation types exposed by the tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LspAction {
    GoToDefinition,
    FindReferences,
    Hover,
    DocumentSymbols,
    WorkspaceSymbol,
    GoToImplementation,
    PrepareCallHierarchy,
    IncomingCalls,
    OutgoingCalls,
}

/// Exact service/document generation that produced a result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LspResultProvenance {
    pub server_generation: u64,
    pub document_version: i32,
    #[serde(default)]
    pub server_restarted: bool,
}

/// Result from an LSP operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspResult {
    pub action: String,
    pub file_path: String,
    pub results: Vec<LspLocation>,
    pub hover_text: Option<String>,
    pub symbols: Vec<LspSymbol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<LspResultProvenance>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_hierarchy_items: Vec<LspCallHierarchyContinuation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<LspDiagnosticPublication>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub partial_reasons: Vec<String>,
    #[serde(default = "default_content_authority")]
    pub content_authority: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspLocation {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub resource_id: String,
    pub uri: String,
    pub line: u32,
    pub character: u32,
    pub end_line: Option<u32>,
    pub end_character: Option<u32>,
    pub preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspSymbol {
    pub name: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_name: Option<String>,
    pub line: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub character: Option<u32>,
    pub end_line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_character: Option<u32>,
    pub children: Vec<Self>,
}

#[derive(Debug, Default, Clone)]
struct LspRequestExtras {
    query: Option<String>,
    continuation_token: Option<String>,
}

pub(crate) enum LspExecution {
    Complete {
        text: String,
        structured: Value,
    },
    Partial {
        text: String,
        structured: Value,
        reasons: Vec<String>,
    },
    Error(String),
}

#[derive(Default)]
struct ProjectionState {
    symbol_nodes: usize,
    partial_reasons: Vec<String>,
}

fn default_content_authority() -> String {
    "untrusted_language_server_output".to_string()
}

/// Return whether a built-in or registered plugin server is available under
/// this exact run's process/configuration authority.
#[must_use]
pub fn is_lsp_connected(run: &crate::tools::ToolRunContext, language_or_ext: &str) -> bool {
    run.lsp_service()
        .language_for_input(language_or_ext)
        .ok()
        .flatten()
        .is_some_and(|language| run.lsp_service().is_available(run, &language))
}

/// Execute an LSP action through the run-owned stateful service.
#[must_use]
pub fn execute_lsp<S: BuildHasher>(
    run: &crate::tools::ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> (String, bool) {
    match execute_lsp_typed(run, args) {
        LspExecution::Complete { text, .. } | LspExecution::Partial { text, .. } => (text, false),
        LspExecution::Error(error) => (error, true),
    }
}

pub(crate) fn execute_lsp_typed<S: BuildHasher>(
    run: &crate::tools::ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> LspExecution {
    let file_path = match parse_file_path(args.get("file_path")) {
        Ok(file_path) => file_path,
        Err(error) => return LspExecution::Error(error),
    };
    let action = match parse_action(args.get("action")) {
        Ok(action) => action,
        Err(error) => return LspExecution::Error(error),
    };
    let extras = match parse_extras(action, args) {
        Ok(extras) => extras,
        Err(error) => return LspExecution::Error(error),
    };
    let line = match parse_line(args.get("line")) {
        Ok(line) => line,
        Err(error) => return LspExecution::Error(error),
    };
    let character = match parse_character(args.get("character")) {
        Ok(character) => character,
        Err(error) => return LspExecution::Error(error),
    };
    let extension = file_path.rsplit('.').next().unwrap_or("");
    let language = match run.lsp_service().language_for_input(extension) {
        Ok(Some(language)) => language,
        Ok(None) => {
            return LspExecution::Error(format!("No language server known for file: {file_path}"))
        }
        Err(error) => return LspExecution::Error(format!("LSP error: {error}")),
    };

    let (absolute_path, file) = match crate::tools::open_capability_regular_read(run, file_path) {
        Ok(opened) => opened,
        Err(error) => return LspExecution::Error(format!("LSP error: {error}")),
    };
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            return LspExecution::Error(format!(
                "LSP error: cannot inspect confined input '{file_path}': {error}"
            ))
        }
    };
    if metadata.len() > LSP_MAX_FILE_SIZE {
        return LspExecution::Error(format!(
            "LSP error: file is {} bytes; maximum is {LSP_MAX_FILE_SIZE} bytes (10 MiB)",
            metadata.len()
        ));
    }
    let mut document_text = String::new();
    if let Err(error) = file
        .take(LSP_MAX_FILE_SIZE + 1)
        .read_to_string(&mut document_text)
    {
        return LspExecution::Error(format!(
            "LSP error: cannot read confined input '{file_path}': {error}"
        ));
    }
    if document_text.len() > usize::try_from(LSP_MAX_FILE_SIZE).unwrap_or(usize::MAX) {
        return LspExecution::Error(format!(
            "LSP error: file grew beyond {LSP_MAX_FILE_SIZE} bytes while it was being read"
        ));
    }
    let document_uri = match url::Url::from_file_path(&absolute_path) {
        Ok(uri) => uri.to_string(),
        Err(()) => {
            return LspExecution::Error(format!(
                "LSP error: '{}' cannot be represented as a file URI",
                absolute_path.display()
            ))
        }
    };
    let (method, params) = build_action_request(
        action,
        &document_uri,
        line,
        character,
        extras.query.as_deref(),
    );
    let request = LspServiceRequest {
        language,
        document_path: absolute_path,
        document_uri,
        document_text,
        method,
        params,
        continuation_token: extras.continuation_token,
    };
    let service_response = match run.lsp_service().execute(run, &request) {
        Ok(response) => response,
        Err(error) => return LspExecution::Error(format!("LSP error: {error}")),
    };
    format_lsp_result(run, action, file_path, service_response)
}

fn format_lsp_result(
    run: &crate::tools::ToolRunContext,
    action: LspAction,
    file_path: &str,
    service_response: crate::services::LspServiceResponse,
) -> LspExecution {
    let mut state = ProjectionState::default();
    let mut result = match parse_lsp_response(
        run,
        action,
        file_path,
        &service_response.response,
        &mut state,
    ) {
        Ok(result) => result,
        Err(error) => return LspExecution::Error(format!("LSP error: {error}")),
    };
    result.provenance = Some(LspResultProvenance {
        server_generation: service_response.server_generation,
        document_version: service_response.document_version,
        server_restarted: service_response.server_restarted,
    });
    result.call_hierarchy_items = service_response.continuations;
    result.diagnostics = service_response.diagnostics;
    state
        .partial_reasons
        .extend(service_response.partial_reasons);
    if matches!(
        action,
        LspAction::GoToDefinition
            | LspAction::FindReferences
            | LspAction::GoToImplementation
            | LspAction::WorkspaceSymbol
    ) {
        result.results = filter_gitignored(run, result.results);
    }
    result.partial_reasons = state.partial_reasons;
    if let Err(error) = bound_model_result(&mut result) {
        return LspExecution::Error(format!("LSP error: {error}"));
    }
    let structured = match serde_json::to_value(&result) {
        Ok(structured) => structured,
        Err(error) => {
            return LspExecution::Error(format!("LSP error: cannot serialize result: {error}"))
        }
    };
    let text = match serde_json::to_string(&structured) {
        Ok(text) => text,
        Err(error) => {
            return LspExecution::Error(format!("LSP error: cannot serialize result: {error}"))
        }
    };
    if result.partial_reasons.is_empty() {
        LspExecution::Complete { text, structured }
    } else {
        LspExecution::Partial {
            text,
            structured,
            reasons: result.partial_reasons,
        }
    }
}

fn parse_file_path(value: Option<&Value>) -> Result<&str, String> {
    match value {
        None => Err("Error: file_path is required".to_string()),
        Some(Value::String(path)) if !path.is_empty() => Ok(path),
        Some(Value::String(_)) => Err("Error: file_path must not be empty".to_string()),
        Some(_) => Err("Invalid 'file_path' argument: expected string".to_string()),
    }
}

fn parse_action(value: Option<&Value>) -> Result<LspAction, String> {
    let action = value
        .ok_or_else(|| "Error: action is required".to_string())?
        .as_str()
        .ok_or_else(|| "Invalid 'action' argument: expected string".to_string())?;
    match action {
        "goToDefinition" | "definition" => Ok(LspAction::GoToDefinition),
        "findReferences" | "references" => Ok(LspAction::FindReferences),
        "hover" => Ok(LspAction::Hover),
        "documentSymbols" | "symbols" => Ok(LspAction::DocumentSymbols),
        "workspaceSymbol" => Ok(LspAction::WorkspaceSymbol),
        "goToImplementation" | "implementation" => Ok(LspAction::GoToImplementation),
        "prepareCallHierarchy" => Ok(LspAction::PrepareCallHierarchy),
        "incomingCalls" => Ok(LspAction::IncomingCalls),
        "outgoingCalls" => Ok(LspAction::OutgoingCalls),
        _ => Err(format!(
            "Unknown LSP action: {action}. Use: goToDefinition, findReferences, hover, \
             documentSymbols, workspaceSymbol, goToImplementation, prepareCallHierarchy, \
             incomingCalls, outgoingCalls"
        )),
    }
}

fn parse_extras<S: BuildHasher>(
    action: LspAction,
    args: &HashMap<String, Value, S>,
) -> Result<LspRequestExtras, String> {
    let query = match args.get("query") {
        None => None,
        Some(Value::String(query)) if query.len() <= MAX_QUERY_BYTES => Some(query.clone()),
        Some(Value::String(query)) => {
            return Err(format!(
                "Invalid 'query' argument: {} bytes exceeds the {MAX_QUERY_BYTES}-byte limit",
                query.len()
            ))
        }
        Some(_) => return Err("Invalid 'query' argument: expected string".to_string()),
    };
    let direct_token = match args.get("continuation_token") {
        None => None,
        Some(Value::String(token)) if !token.is_empty() => Some(token.clone()),
        Some(Value::String(_)) => {
            return Err("Invalid 'continuation_token' argument: must not be empty".to_string())
        }
        Some(_) => return Err("Invalid 'continuation_token' argument: expected string".to_string()),
    };
    let compatibility_token = match args.get("hierarchy_item") {
        None => None,
        Some(Value::Object(item)) => Some(item
            .get("continuation_token")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                "Invalid 'hierarchy_item': pass a returned call_hierarchy_items entry or use its continuation_token"
                    .to_string()
            })?),
        Some(_) => return Err("Invalid 'hierarchy_item' argument: expected object".to_string()),
    };
    let continuation_token = direct_token.or(compatibility_token);
    if continuation_token
        .as_ref()
        .is_some_and(|token| token.len() > MAX_CONTINUATION_TOKEN_BYTES)
    {
        return Err(format!(
            "Invalid 'continuation_token' argument: maximum is {MAX_CONTINUATION_TOKEN_BYTES} bytes"
        ));
    }
    if matches!(action, LspAction::IncomingCalls | LspAction::OutgoingCalls)
        && continuation_token.is_none()
    {
        return Err(
            "Error: continuation_token is required for incomingCalls/outgoingCalls. Run prepareCallHierarchy first."
                .to_string(),
        );
    }
    Ok(LspRequestExtras {
        query,
        continuation_token,
    })
}

fn parse_line(value: Option<&Value>) -> Result<u32, String> {
    let Some(value) = value else {
        return Ok(1);
    };
    let line = value
        .as_u64()
        .ok_or_else(|| "Error: line must be a 1-indexed positive integer".to_string())?;
    if line == 0 {
        return Err("Error: line must be a 1-indexed positive integer".to_string());
    }
    u32::try_from(line).map_err(|_| "Error: line must fit an unsigned 32-bit integer".to_string())
}

fn parse_character(value: Option<&Value>) -> Result<u32, String> {
    let Some(value) = value else {
        return Ok(0);
    };
    let character = value
        .as_u64()
        .ok_or_else(|| "Error: character must be a 0-indexed non-negative integer".to_string())?;
    u32::try_from(character)
        .map_err(|_| "Error: character must fit an unsigned 32-bit integer".to_string())
}

fn build_action_request(
    action: LspAction,
    file_uri: &str,
    line: u32,
    character: u32,
    query: Option<&str>,
) -> (&'static str, Value) {
    let position = || json!({"line": line.saturating_sub(1), "character": character});
    let text_document = || json!({"uri": file_uri});
    match action {
        LspAction::GoToDefinition => (
            "textDocument/definition",
            json!({"textDocument": text_document(), "position": position()}),
        ),
        LspAction::FindReferences => (
            "textDocument/references",
            json!({
                "textDocument": text_document(),
                "position": position(),
                "context": {"includeDeclaration": true}
            }),
        ),
        LspAction::Hover => (
            "textDocument/hover",
            json!({"textDocument": text_document(), "position": position()}),
        ),
        LspAction::DocumentSymbols => (
            "textDocument/documentSymbol",
            json!({"textDocument": text_document()}),
        ),
        LspAction::WorkspaceSymbol => ("workspace/symbol", json!({"query": query.unwrap_or("")})),
        LspAction::GoToImplementation => (
            "textDocument/implementation",
            json!({"textDocument": text_document(), "position": position()}),
        ),
        LspAction::PrepareCallHierarchy => (
            "textDocument/prepareCallHierarchy",
            json!({"textDocument": text_document(), "position": position()}),
        ),
        LspAction::IncomingCalls => ("callHierarchy/incomingCalls", Value::Null),
        LspAction::OutgoingCalls => ("callHierarchy/outgoingCalls", Value::Null),
    }
}

fn parse_lsp_response(
    run: &crate::tools::ToolRunContext,
    action: LspAction,
    file_path: &str,
    response: &Value,
    state: &mut ProjectionState,
) -> Result<LspResult, String> {
    let result = response
        .get("result")
        .ok_or_else(|| "JSON-RPC response omitted result".to_string())?;
    let mut output = empty_result(action_name(action), file_path);
    if result.is_null() {
        return Ok(output);
    }
    match action {
        LspAction::Hover => {
            let contents = result
                .as_object()
                .and_then(|result| result.get("contents"))
                .ok_or_else(|| "hover result omitted contents".to_string())?;
            output.hover_text = Some(extract_hover_contents(run, contents, state)?);
        }
        LspAction::GoToDefinition | LspAction::FindReferences | LspAction::GoToImplementation => {
            output.results = parse_locations(run, result, state)?;
        }
        LspAction::DocumentSymbols => {
            output.symbols = parse_symbols(run, result, false, state)?;
        }
        LspAction::WorkspaceSymbol => {
            output.symbols = parse_symbols(run, result, true, state)?;
            let symbols = result
                .as_array()
                .ok_or_else(|| "workspace symbol result must be an array or null".to_string())?;
            let mut locations = Vec::with_capacity(symbols.len().min(MAX_RESULT_ITEMS));
            for symbol in symbols.iter().take(MAX_RESULT_ITEMS) {
                let location = symbol
                    .get("location")
                    .ok_or_else(|| "workspace symbol omitted location".to_string())?;
                locations.push(parse_location(run, location, None)?);
            }
            if symbols.len() > MAX_RESULT_ITEMS {
                note_partial(
                    state,
                    format!("workspace symbol locations were capped at {MAX_RESULT_ITEMS} items"),
                );
            }
            output.results = locations;
        }
        LspAction::PrepareCallHierarchy => {
            output.results = parse_prepared_hierarchy(run, result, state)?;
        }
        LspAction::IncomingCalls => {
            output.results = parse_call_hierarchy(run, result, "from", state)?;
        }
        LspAction::OutgoingCalls => {
            output.results = parse_call_hierarchy(run, result, "to", state)?;
        }
    }
    Ok(output)
}

fn empty_result(action: &str, file_path: &str) -> LspResult {
    LspResult {
        action: action.to_string(),
        file_path: file_path.to_string(),
        results: Vec::new(),
        hover_text: None,
        symbols: Vec::new(),
        provenance: None,
        call_hierarchy_items: Vec::new(),
        diagnostics: Vec::new(),
        partial_reasons: Vec::new(),
        content_authority: default_content_authority(),
    }
}

const fn action_name(action: LspAction) -> &'static str {
    match action {
        LspAction::GoToDefinition => "goToDefinition",
        LspAction::FindReferences => "findReferences",
        LspAction::Hover => "hover",
        LspAction::DocumentSymbols => "documentSymbols",
        LspAction::WorkspaceSymbol => "workspaceSymbol",
        LspAction::GoToImplementation => "goToImplementation",
        LspAction::PrepareCallHierarchy => "prepareCallHierarchy",
        LspAction::IncomingCalls => "incomingCalls",
        LspAction::OutgoingCalls => "outgoingCalls",
    }
}

fn extract_hover_contents(
    run: &crate::tools::ToolRunContext,
    contents: &Value,
    state: &mut ProjectionState,
) -> Result<String, String> {
    let text = if let Some(text) = contents.as_str() {
        text.to_string()
    } else if let Some(object) = contents.as_object() {
        object
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| "hover markup content omitted a string value".to_string())?
            .to_string()
    } else if let Some(items) = contents.as_array() {
        let mut parts = Vec::with_capacity(items.len().min(MAX_RESULT_ITEMS));
        for item in items.iter().take(MAX_RESULT_ITEMS) {
            let text = item
                .as_str()
                .or_else(|| item.get("value").and_then(Value::as_str))
                .ok_or_else(|| "hover content array contained an invalid item".to_string())?;
            parts.push(text);
        }
        if items.len() > MAX_RESULT_ITEMS {
            note_partial(
                state,
                format!("hover content was capped at {MAX_RESULT_ITEMS} items"),
            );
        }
        parts.join("\n\n")
    } else {
        return Err("hover contents must be text, markup, or an array".to_string());
    };
    Ok(bound_server_text(
        run,
        &text,
        MAX_HOVER_BYTES,
        "hover text",
        state,
    ))
}

fn normalise_location(location: &Value) -> Result<(&str, &Value), String> {
    if let (Some(uri), Some(range)) = (
        location.get("uri").and_then(Value::as_str),
        location.get("range"),
    ) {
        return Ok((uri, range));
    }
    let uri = location
        .get("targetUri")
        .and_then(Value::as_str)
        .ok_or_else(|| "location omitted a string URI".to_string())?;
    let range = location
        .get("targetSelectionRange")
        .or_else(|| location.get("targetRange"))
        .ok_or_else(|| "location link omitted target range".to_string())?;
    Ok((uri, range))
}

fn parse_locations(
    run: &crate::tools::ToolRunContext,
    data: &Value,
    state: &mut ProjectionState,
) -> Result<Vec<LspLocation>, String> {
    let values = match data {
        Value::Array(values) => values.as_slice(),
        Value::Object(_) => std::slice::from_ref(data),
        _ => return Err("location result must be an object, array, or null".to_string()),
    };
    let mut output = Vec::with_capacity(values.len().min(MAX_RESULT_ITEMS));
    for location in values.iter().take(MAX_RESULT_ITEMS) {
        output.push(parse_location(run, location, None)?);
    }
    if values.len() > MAX_RESULT_ITEMS {
        note_partial(
            state,
            format!("locations were capped at {MAX_RESULT_ITEMS} items"),
        );
    }
    Ok(output)
}

fn parse_prepared_hierarchy(
    run: &crate::tools::ToolRunContext,
    data: &Value,
    state: &mut ProjectionState,
) -> Result<Vec<LspLocation>, String> {
    let items = data
        .as_array()
        .ok_or_else(|| "prepare call hierarchy result must be an array or null".to_string())?;
    let mut output = Vec::with_capacity(items.len().min(MAX_RESULT_ITEMS));
    for item in items.iter().take(MAX_RESULT_ITEMS) {
        output.push(hierarchy_item_location(run, item, state)?);
    }
    if items.len() > MAX_RESULT_ITEMS {
        note_partial(
            state,
            format!("call hierarchy was capped at {MAX_RESULT_ITEMS} items"),
        );
    }
    Ok(output)
}

fn parse_call_hierarchy(
    run: &crate::tools::ToolRunContext,
    data: &Value,
    item_key: &str,
    state: &mut ProjectionState,
) -> Result<Vec<LspLocation>, String> {
    let edges = data
        .as_array()
        .ok_or_else(|| "call hierarchy result must be an array or null".to_string())?;
    let mut output = Vec::with_capacity(edges.len().min(MAX_RESULT_ITEMS));
    for edge in edges.iter().take(MAX_RESULT_ITEMS) {
        let item = edge
            .get(item_key)
            .ok_or_else(|| format!("call hierarchy edge omitted '{item_key}'"))?;
        output.push(hierarchy_item_location(run, item, state)?);
    }
    if edges.len() > MAX_RESULT_ITEMS {
        note_partial(
            state,
            format!("call hierarchy was capped at {MAX_RESULT_ITEMS} items"),
        );
    }
    Ok(output)
}

fn hierarchy_item_location(
    run: &crate::tools::ToolRunContext,
    item: &Value,
    state: &mut ProjectionState,
) -> Result<LspLocation, String> {
    let uri = item
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| "call hierarchy item omitted a string URI".to_string())?;
    let range = item
        .get("selectionRange")
        .or_else(|| item.get("range"))
        .ok_or_else(|| "call hierarchy item omitted a range".to_string())?;
    let name = item
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "call hierarchy item omitted a string name".to_string())?;
    let preview = Some(bound_server_text(
        run,
        name,
        MAX_SYMBOL_TEXT_BYTES,
        "call hierarchy name",
        state,
    ));
    location_from_range(run, uri, range, preview)
}

fn parse_location(
    run: &crate::tools::ToolRunContext,
    location: &Value,
    preview: Option<String>,
) -> Result<LspLocation, String> {
    let (uri, range) = normalise_location(location)?;
    location_from_range(run, uri, range, preview)
}

fn location_from_range(
    run: &crate::tools::ToolRunContext,
    uri: &str,
    range: &Value,
    preview: Option<String>,
) -> Result<LspLocation, String> {
    let (uri, resource_id) = crate::services::lsp_pool::validate_returned_resource(run, uri)
        .map_err(|error| error.to_string())?;
    let start = range
        .get("start")
        .ok_or_else(|| "location range omitted start".to_string())?;
    let end = range
        .get("end")
        .ok_or_else(|| "location range omitted end".to_string())?;
    Ok(LspLocation {
        resource_id,
        uri,
        line: user_coordinate(start, "line")?,
        character: user_coordinate(start, "character")?,
        end_line: Some(user_coordinate(end, "line")?),
        end_character: Some(user_coordinate(end, "character")?),
        preview,
    })
}

fn parse_symbols(
    run: &crate::tools::ToolRunContext,
    data: &Value,
    require_location: bool,
    state: &mut ProjectionState,
) -> Result<Vec<LspSymbol>, String> {
    parse_symbols_inner(run, data, require_location, 0, state)
}

fn parse_symbols_inner(
    run: &crate::tools::ToolRunContext,
    data: &Value,
    require_location: bool,
    depth: usize,
    state: &mut ProjectionState,
) -> Result<Vec<LspSymbol>, String> {
    if depth >= MAX_SYMBOL_DEPTH {
        note_partial(
            state,
            format!("symbol nesting was capped at {MAX_SYMBOL_DEPTH} levels"),
        );
        return Ok(Vec::new());
    }
    let symbols = data
        .as_array()
        .ok_or_else(|| "symbol result must be an array or null".to_string())?;
    let mut output = Vec::new();
    for symbol in symbols {
        if state.symbol_nodes >= MAX_SYMBOL_NODES {
            note_partial(
                state,
                format!("symbols were capped at {MAX_SYMBOL_NODES} nodes"),
            );
            break;
        }
        if output.len() >= MAX_RESULT_ITEMS {
            note_partial(
                state,
                format!("one symbol level was capped at {MAX_RESULT_ITEMS} items"),
            );
            break;
        }
        state.symbol_nodes += 1;
        let name = symbol
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "symbol omitted a string name".to_string())?;
        let kind = symbol
            .get("kind")
            .and_then(Value::as_u64)
            .ok_or_else(|| "symbol omitted an integer kind".to_string())?;
        let location = symbol.get("location");
        if require_location && location.is_none() {
            return Err("workspace symbol omitted location".to_string());
        }
        let range = symbol
            .get("range")
            .or_else(|| location.and_then(|location| location.get("range")))
            .ok_or_else(|| "symbol omitted range".to_string())?;
        let start = range
            .get("start")
            .ok_or_else(|| "symbol range omitted start".to_string())?;
        let end = range
            .get("end")
            .ok_or_else(|| "symbol range omitted end".to_string())?;
        let (uri, resource_id) = match location {
            Some(location) => {
                let raw_uri = location
                    .get("uri")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "symbol location omitted a string URI".to_string())?;
                let (uri, resource_id) =
                    crate::services::lsp_pool::validate_returned_resource(run, raw_uri)
                        .map_err(|error| error.to_string())?;
                (Some(uri), Some(resource_id))
            }
            None => (None, None),
        };
        let container_name = symbol
            .get("containerName")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| "symbol containerName must be a string".to_string())
                    .map(|text| {
                        bound_server_text(
                            run,
                            text,
                            MAX_SYMBOL_TEXT_BYTES,
                            "symbol container name",
                            state,
                        )
                    })
            })
            .transpose()?;
        let children = match symbol.get("children") {
            Some(children) => parse_symbols_inner(run, children, false, depth + 1, state)?,
            None => Vec::new(),
        };
        output.push(LspSymbol {
            name: bound_server_text(run, name, MAX_SYMBOL_TEXT_BYTES, "symbol name", state),
            kind: symbol_kind_name(kind),
            uri,
            resource_id,
            container_name,
            line: user_coordinate(start, "line")?,
            character: Some(user_coordinate(start, "character")?),
            end_line: Some(user_coordinate(end, "line")?),
            end_character: Some(user_coordinate(end, "character")?),
            children,
        });
    }
    Ok(output)
}

fn user_coordinate(position: &Value, name: &str) -> Result<u32, String> {
    let raw = position
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("LSP position '{name}' must be a non-negative integer"))?;
    let raw = u32::try_from(raw)
        .map_err(|_| format!("LSP position '{name}' must fit an unsigned 32-bit integer"))?;
    raw.checked_add(1)
        .ok_or_else(|| format!("LSP position '{name}' cannot be represented as 1-indexed output"))
}

fn bound_server_text(
    run: &crate::tools::ToolRunContext,
    raw: &str,
    max_bytes: usize,
    label: &str,
    state: &mut ProjectionState,
) -> String {
    let sanitized = run.sanitize_diagnostic(raw);
    let bounded = crate::tools::safe_truncate(sanitized.as_str(), max_bytes);
    if bounded.len() < sanitized.as_str().len() {
        note_partial(state, format!("{label} was truncated to {max_bytes} bytes"));
    }
    bounded.to_string()
}

fn note_partial(state: &mut ProjectionState, reason: String) {
    if !state.partial_reasons.contains(&reason) {
        state.partial_reasons.push(reason);
    }
}

fn bound_model_result(result: &mut LspResult) -> Result<(), String> {
    if serialized_result_len(result)? <= MAX_LSP_OUTPUT_BYTES {
        return Ok(());
    }
    let reason = format!(
        "model-facing LSP output exceeded {MAX_LSP_OUTPUT_BYTES} bytes; tail data was omitted"
    );
    if !result.partial_reasons.contains(&reason) {
        result.partial_reasons.push(reason);
    }
    while serialized_result_len(result)? > MAX_LSP_OUTPUT_BYTES {
        if let Some(publication) = result.diagnostics.last_mut() {
            if publication.diagnostics.pop().is_some() {
                publication.omitted_diagnostics = publication.omitted_diagnostics.saturating_add(1);
                continue;
            }
        }
        if result.diagnostics.pop().is_some() {
            continue;
        }
        if result.call_hierarchy_items.pop().is_some()
            || result.symbols.pop().is_some()
            || result.results.pop().is_some()
        {
            continue;
        }
        if let Some(hover) = result.hover_text.as_mut() {
            if hover.len() > 256 {
                let shorter = crate::tools::safe_truncate(hover, hover.len() / 2).to_string();
                *hover = shorter;
                continue;
            }
            result.hover_text = None;
            continue;
        }
        return Err("bounded LSP metadata alone exceeds the model output limit".to_string());
    }
    Ok(())
}

fn serialized_result_len(result: &LspResult) -> Result<usize, String> {
    serde_json::to_vec(result)
        .map(|encoded| encoded.len())
        .map_err(|error| format!("cannot serialize result: {error}"))
}

fn symbol_kind_name(kind: u64) -> String {
    match kind {
        1 => "File",
        2 => "Module",
        3 => "Namespace",
        4 => "Package",
        5 => "Class",
        6 => "Method",
        7 => "Property",
        8 => "Field",
        9 => "Constructor",
        10 => "Enum",
        11 => "Interface",
        12 => "Function",
        13 => "Variable",
        14 => "Constant",
        15 => "String",
        16 => "Number",
        17 => "Boolean",
        18 => "Array",
        19 => "Object",
        20 => "Key",
        21 => "Null",
        22 => "EnumMember",
        23 => "Struct",
        24 => "Event",
        25 => "Operator",
        26 => "TypeParameter",
        _ => "Unknown",
    }
    .to_string()
}

#[cfg(test)]
fn detect_language_id(file_path: &str) -> &'static str {
    normalize_language(file_path.rsplit('.').next().unwrap_or(""))
}

#[cfg(test)]
fn normalize_language(language_or_extension: &str) -> &'static str {
    match language_or_extension.trim().trim_start_matches('.') {
        "rs" | "rust" => "rust",
        "ts" | "typescript" => "typescript",
        "tsx" | "typescriptreact" => "typescriptreact",
        "js" | "javascript" => "javascript",
        "jsx" | "javascriptreact" => "javascriptreact",
        "py" | "python" => "python",
        "go" => "go",
        "c" => "c",
        "cpp" | "cc" | "cxx" | "h" | "hpp" => "cpp",
        "java" => "java",
        "rb" | "ruby" => "ruby",
        _ => "",
    }
}

fn git_bin(run: &crate::tools::ToolRunContext) -> Result<PathBuf, String> {
    run.resolve_executable("git")
        .map_err(|error| error.to_string())
}

fn uri_to_local_path(uri: &str) -> Option<PathBuf> {
    let uri = url::Url::parse(uri).ok()?;
    uri.to_file_path().ok()
}

fn filter_gitignored(
    run: &crate::tools::ToolRunContext,
    locations: Vec<LspLocation>,
) -> Vec<LspLocation> {
    if locations.is_empty() {
        return locations;
    }
    let mut paths = Vec::new();
    for location in &locations {
        if let Some(path) = uri_to_local_path(&location.uri) {
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    let path_strings = paths
        .iter()
        .filter_map(|path| path.to_str())
        .collect::<Vec<_>>();
    if path_strings.is_empty() {
        return locations;
    }
    let input = format!("{}\n", path_strings.join("\n"));
    let output = match git_bin(run).and_then(|git| {
        crate::tools::command::run_sandboxed_with_timeout_with_input(
            run,
            &git,
            &["check-ignore", "--stdin"],
            run.working_directory(),
            LSP_GITIGNORE_TIMEOUT,
            input.as_bytes(),
        )
        .map_err(|error| error.to_string())
    }) {
        Ok(output) if output.status.code() != Some(128) => output,
        Ok(_) | Err(_) => return locations,
    };
    let ignored = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect::<HashSet<_>>();
    locations
        .into_iter()
        .filter(|location| {
            uri_to_local_path(&location.uri)
                .is_none_or(|path| path.to_str().is_none_or(|path| !ignored.contains(path)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_run() -> &'static std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context()
    }

    fn source_uri() -> String {
        url::Url::from_file_path(test_run().project_root().join("src/lib.rs"))
            .expect("source path is representable as a file URI")
            .to_string()
    }

    #[test]
    fn action_parser_preserves_all_nine_operations() {
        for action in [
            "goToDefinition",
            "findReferences",
            "hover",
            "documentSymbols",
            "workspaceSymbol",
            "goToImplementation",
            "prepareCallHierarchy",
            "incomingCalls",
            "outgoingCalls",
        ] {
            assert!(parse_action(Some(&json!(action))).is_ok(), "{action}");
        }
    }

    #[test]
    fn followup_requires_an_opaque_continuation() {
        let args = HashMap::from([
            ("file_path".to_string(), json!("src/lib.rs")),
            ("action".to_string(), json!("incomingCalls")),
        ]);
        let error = parse_extras(LspAction::IncomingCalls, &args).unwrap_err();
        assert!(error.contains("continuation_token"));
    }

    #[test]
    fn compatibility_item_must_carry_a_token_not_raw_server_data() {
        let args = HashMap::from([("hierarchy_item".to_string(), json!({"name": "old"}))]);
        let error = parse_extras(LspAction::IncomingCalls, &args).unwrap_err();
        assert!(error.contains("returned call_hierarchy_items"));
    }

    #[test]
    fn oversized_coordinates_are_rejected_instead_of_clamped() {
        assert!(parse_line(Some(&json!(u64::MAX))).is_err());
        assert!(parse_character(Some(&json!(u64::MAX))).is_err());
    }

    #[test]
    fn complete_workspace_symbols_preserve_identity_and_location() {
        let uri = source_uri();
        let response = json!({"result": [{
            "name": "Engine",
            "kind": 23,
            "containerName": "runtime",
            "location": {
                "uri": uri,
                "range": {"start": {"line": 4, "character": 2}, "end": {"line": 4, "character": 8}}
            }
        }]});
        let result = parse_lsp_response(
            test_run(),
            LspAction::WorkspaceSymbol,
            "src/lib.rs",
            &response,
            &mut ProjectionState::default(),
        )
        .expect("valid workspace symbol result");
        assert_eq!(result.symbols[0].name, "Engine");
        assert_eq!(result.symbols[0].kind, "Struct");
        assert_eq!(result.symbols[0].container_name.as_deref(), Some("runtime"));
        assert_eq!(result.symbols[0].resource_id.as_deref(), Some("src/lib.rs"));
        assert_eq!(result.results[0].line, 5);
    }

    #[test]
    fn call_hierarchy_projection_preserves_complete_location_summary() {
        let uri = source_uri();
        let item = json!({
            "name": "caller",
            "kind": 12,
            "uri": uri,
            "range": {"start": {"line": 1, "character": 0}, "end": {"line": 3, "character": 1}},
            "selectionRange": {"start": {"line": 1, "character": 3}, "end": {"line": 1, "character": 9}},
            "data": {"opaque": 42}
        });
        let response = json!({"result": [item]});
        let result = parse_lsp_response(
            test_run(),
            LspAction::PrepareCallHierarchy,
            "src/lib.rs",
            &response,
            &mut ProjectionState::default(),
        )
        .expect("valid hierarchy result");
        assert_eq!(result.results[0].preview.as_deref(), Some("caller"));
        assert_eq!(result.results[0].character, 4);
    }

    #[test]
    fn location_links_prefer_target_selection_range() {
        let locations = parse_locations(test_run(), &json!([{
            "targetUri": source_uri(),
            "targetRange": {"start": {"line": 2, "character": 0}, "end": {"line": 2, "character": 8}},
            "targetSelectionRange": {"start": {"line": 2, "character": 4}, "end": {"line": 2, "character": 8}}
        }]), &mut ProjectionState::default()).expect("valid location link");
        assert_eq!(locations[0].line, 3);
        assert_eq!(locations[0].character, 5);
    }

    #[test]
    fn hover_shapes_remain_supported() {
        assert_eq!(
            extract_hover_contents(test_run(), &json!("plain"), &mut ProjectionState::default())
                .expect("plain hover"),
            "plain"
        );
        assert_eq!(
            extract_hover_contents(
                test_run(),
                &json!(["first", {"value": "second"}]),
                &mut ProjectionState::default()
            )
            .expect("array hover"),
            "first\n\nsecond"
        );
    }

    #[test]
    fn known_language_mapping_is_complete() {
        assert_eq!(detect_language_id("main.rs"), "rust");
        assert_eq!(detect_language_id("main.tsx"), "typescriptreact");
        assert_eq!(detect_language_id("main.hpp"), "cpp");
        assert_eq!(detect_language_id("README.md"), "");
    }
}
