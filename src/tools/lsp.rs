//! Language Server Protocol code-intelligence tool.
//!
//! Model-facing validation and result projection live here. Process and
//! protocol lifetime are owned by the run-scoped
//! [`crate::services::LspServerManager`].

use crate::services::{LspCallHierarchyContinuation, LspServiceRequest};
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspLocation {
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
    let file_path = match parse_file_path(args.get("file_path")) {
        Ok(file_path) => file_path,
        Err(error) => return (error, true),
    };
    let action = match parse_action(args.get("action")) {
        Ok(action) => action,
        Err(error) => return (error, true),
    };
    let extras = match parse_extras(action, args) {
        Ok(extras) => extras,
        Err(error) => return (error, true),
    };
    let line = match parse_line(args.get("line")) {
        Ok(line) => line,
        Err(error) => return (error, true),
    };
    let character = match parse_character(args.get("character")) {
        Ok(character) => character,
        Err(error) => return (error, true),
    };
    let extension = file_path.rsplit('.').next().unwrap_or("");
    let language = match run.lsp_service().language_for_input(extension) {
        Ok(Some(language)) => language,
        Ok(None) => {
            return (
                format!("No language server known for file: {file_path}"),
                true,
            )
        }
        Err(error) => return (format!("LSP error: {error}"), true),
    };

    let (absolute_path, file) = match crate::tools::open_capability_regular_read(run, file_path) {
        Ok(opened) => opened,
        Err(error) => return (format!("LSP error: {error}"), true),
    };
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            return (
                format!("LSP error: cannot inspect confined input '{file_path}': {error}"),
                true,
            )
        }
    };
    if metadata.len() > LSP_MAX_FILE_SIZE {
        return (
            format!(
                "LSP error: file is {} bytes; maximum is {LSP_MAX_FILE_SIZE} bytes (10 MiB)",
                metadata.len()
            ),
            true,
        );
    }
    let mut document_text = String::new();
    if let Err(error) = file
        .take(LSP_MAX_FILE_SIZE + 1)
        .read_to_string(&mut document_text)
    {
        return (
            format!("LSP error: cannot read confined input '{file_path}': {error}"),
            true,
        );
    }
    let document_uri = match url::Url::from_file_path(&absolute_path) {
        Ok(uri) => uri.to_string(),
        Err(()) => {
            return (
                format!(
                    "LSP error: '{}' cannot be represented as a file URI",
                    absolute_path.display()
                ),
                true,
            )
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
        Err(error) => return (format!("LSP error: {error}"), true),
    };
    format_lsp_result(run, action, file_path, service_response)
}

fn format_lsp_result(
    run: &crate::tools::ToolRunContext,
    action: LspAction,
    file_path: &str,
    service_response: crate::services::LspServiceResponse,
) -> (String, bool) {
    let mut result = parse_lsp_response(action, file_path, &service_response.response);
    result.provenance = Some(LspResultProvenance {
        server_generation: service_response.server_generation,
        document_version: service_response.document_version,
    });
    result.call_hierarchy_items = service_response.continuations;
    if matches!(
        action,
        LspAction::GoToDefinition
            | LspAction::FindReferences
            | LspAction::GoToImplementation
            | LspAction::WorkspaceSymbol
    ) {
        result.results = filter_gitignored(run, result.results);
    }
    match serde_json::to_string_pretty(&result) {
        Ok(result) => (result, false),
        Err(error) => (format!("LSP error: cannot serialize result: {error}"), true),
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
        Some(Value::String(query)) => Some(query.clone()),
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
    Ok(u64_to_u32_saturating(line))
}

fn parse_character(value: Option<&Value>) -> Result<u32, String> {
    let Some(value) = value else {
        return Ok(0);
    };
    let character = value
        .as_u64()
        .ok_or_else(|| "Error: character must be a 0-indexed non-negative integer".to_string())?;
    Ok(u64_to_u32_saturating(character))
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

fn parse_lsp_response(action: LspAction, file_path: &str, response: &Value) -> LspResult {
    let result = response.get("result");
    let mut output = empty_result(action_name(action), file_path);
    match action {
        LspAction::Hover => {
            output.hover_text = result
                .and_then(|result| result.get("contents"))
                .map(extract_hover_contents);
        }
        LspAction::GoToDefinition | LspAction::FindReferences | LspAction::GoToImplementation => {
            output.results = parse_locations(result);
        }
        LspAction::DocumentSymbols => output.symbols = parse_symbols(result),
        LspAction::WorkspaceSymbol => {
            output.symbols = parse_symbols(result);
            output.results = result
                .and_then(Value::as_array)
                .map(|symbols| {
                    let locations = symbols
                        .iter()
                        .filter_map(|symbol| symbol.get("location").cloned())
                        .collect::<Vec<_>>();
                    parse_locations(Some(&Value::Array(locations)))
                })
                .unwrap_or_default();
        }
        LspAction::PrepareCallHierarchy => {
            output.results = parse_prepared_hierarchy(result);
        }
        LspAction::IncomingCalls => output.results = parse_call_hierarchy(result, "from"),
        LspAction::OutgoingCalls => output.results = parse_call_hierarchy(result, "to"),
    }
    output
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

fn extract_hover_contents(contents: &Value) -> String {
    if let Some(text) = contents.as_str() {
        return text.to_string();
    }
    if let Some(object) = contents.as_object() {
        return object
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
    }
    contents.as_array().map_or_else(String::new, |items| {
        items
            .iter()
            .filter_map(|item| {
                item.as_str()
                    .or_else(|| item.get("value").and_then(Value::as_str))
            })
            .collect::<Vec<_>>()
            .join("\n\n")
    })
}

fn normalise_location(location: &Value) -> Option<(&str, &Value)> {
    if let (Some(uri), Some(range)) = (
        location.get("uri").and_then(Value::as_str),
        location.get("range"),
    ) {
        return Some((uri, range));
    }
    let uri = location.get("targetUri").and_then(Value::as_str)?;
    let range = location
        .get("targetSelectionRange")
        .or_else(|| location.get("targetRange"))?;
    Some((uri, range))
}

fn parse_locations(data: Option<&Value>) -> Vec<LspLocation> {
    let values = match data {
        Some(Value::Array(values)) => values.clone(),
        Some(value @ Value::Object(_)) => vec![value.clone()],
        _ => return Vec::new(),
    };
    values
        .iter()
        .filter_map(|location| {
            let (uri, range) = normalise_location(location)?;
            location_from_range(uri, range, None)
        })
        .collect()
}

fn parse_prepared_hierarchy(data: Option<&Value>) -> Vec<LspLocation> {
    data.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(hierarchy_item_location)
        .collect()
}

fn parse_call_hierarchy(data: Option<&Value>, item_key: &str) -> Vec<LspLocation> {
    data.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|edge| edge.get(item_key))
        .filter_map(hierarchy_item_location)
        .collect()
}

fn hierarchy_item_location(item: &Value) -> Option<LspLocation> {
    let uri = item.get("uri").and_then(Value::as_str)?;
    let range = item.get("selectionRange").or_else(|| item.get("range"))?;
    let preview = item.get("name").and_then(Value::as_str).map(str::to_string);
    location_from_range(uri, range, preview)
}

fn location_from_range(uri: &str, range: &Value, preview: Option<String>) -> Option<LspLocation> {
    let start = range.get("start")?;
    let end = range.get("end");
    Some(LspLocation {
        uri: uri.to_string(),
        line: start
            .get("line")
            .and_then(Value::as_u64)
            .map_or(1, lsp_position_to_user_coordinate),
        character: start
            .get("character")
            .and_then(Value::as_u64)
            .map_or(1, lsp_position_to_user_coordinate),
        end_line: end
            .and_then(|end| end.get("line"))
            .and_then(Value::as_u64)
            .map(lsp_position_to_user_coordinate),
        end_character: end
            .and_then(|end| end.get("character"))
            .and_then(Value::as_u64)
            .map(lsp_position_to_user_coordinate),
        preview,
    })
}

fn parse_symbols(data: Option<&Value>) -> Vec<LspSymbol> {
    parse_symbols_inner(data, 0)
}

fn parse_symbols_inner(data: Option<&Value>, depth: usize) -> Vec<LspSymbol> {
    if depth >= MAX_SYMBOL_DEPTH {
        return Vec::new();
    }
    let Some(Value::Array(symbols)) = data else {
        return Vec::new();
    };
    symbols
        .iter()
        .filter_map(|symbol| {
            let name = symbol.get("name").and_then(Value::as_str)?;
            let kind = symbol.get("kind").and_then(Value::as_u64).unwrap_or(0);
            let range = symbol.get("range").or_else(|| {
                symbol
                    .get("location")
                    .and_then(|location| location.get("range"))
            })?;
            let start = range.get("start")?;
            let end = range.get("end");
            Some(LspSymbol {
                name: name.to_string(),
                kind: symbol_kind_name(kind),
                uri: symbol
                    .get("location")
                    .and_then(|location| location.get("uri"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                container_name: symbol
                    .get("containerName")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                line: start
                    .get("line")
                    .and_then(Value::as_u64)
                    .map_or(1, lsp_position_to_user_coordinate),
                character: start
                    .get("character")
                    .and_then(Value::as_u64)
                    .map(lsp_position_to_user_coordinate),
                end_line: end
                    .and_then(|end| end.get("line"))
                    .and_then(Value::as_u64)
                    .map(lsp_position_to_user_coordinate),
                end_character: end
                    .and_then(|end| end.get("character"))
                    .and_then(Value::as_u64)
                    .map(lsp_position_to_user_coordinate),
                children: parse_symbols_inner(symbol.get("children"), depth + 1),
            })
        })
        .collect()
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

fn u64_to_u32_saturating(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn lsp_position_to_user_coordinate(value: u64) -> u32 {
    u64_to_u32_saturating(value).saturating_add(1)
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
    fn complete_workspace_symbols_preserve_identity_and_location() {
        let response = json!({"result": [{
            "name": "Engine",
            "kind": 23,
            "containerName": "runtime",
            "location": {
                "uri": "file:///src/lib.rs",
                "range": {"start": {"line": 4, "character": 2}, "end": {"line": 4, "character": 8}}
            }
        }]});
        let result = parse_lsp_response(LspAction::WorkspaceSymbol, "src/lib.rs", &response);
        assert_eq!(result.symbols[0].name, "Engine");
        assert_eq!(result.symbols[0].kind, "Struct");
        assert_eq!(result.symbols[0].container_name.as_deref(), Some("runtime"));
        assert_eq!(result.symbols[0].uri.as_deref(), Some("file:///src/lib.rs"));
        assert_eq!(result.results[0].line, 5);
    }

    #[test]
    fn call_hierarchy_projection_preserves_complete_location_summary() {
        let item = json!({
            "name": "caller",
            "kind": 12,
            "uri": "file:///src/lib.rs",
            "range": {"start": {"line": 1, "character": 0}, "end": {"line": 3, "character": 1}},
            "selectionRange": {"start": {"line": 1, "character": 3}, "end": {"line": 1, "character": 9}},
            "data": {"opaque": 42}
        });
        let response = json!({"result": [item]});
        let result = parse_lsp_response(LspAction::PrepareCallHierarchy, "src/lib.rs", &response);
        assert_eq!(result.results[0].preview.as_deref(), Some("caller"));
        assert_eq!(result.results[0].character, 4);
    }

    #[test]
    fn location_links_prefer_target_selection_range() {
        let locations = parse_locations(Some(&json!([{
            "targetUri": "file:///src/lib.rs",
            "targetRange": {"start": {"line": 2, "character": 0}, "end": {"line": 2, "character": 8}},
            "targetSelectionRange": {"start": {"line": 2, "character": 4}, "end": {"line": 2, "character": 8}}
        }])));
        assert_eq!(locations[0].line, 3);
        assert_eq!(locations[0].character, 5);
    }

    #[test]
    fn hover_shapes_remain_supported() {
        assert_eq!(extract_hover_contents(&json!("plain")), "plain");
        assert_eq!(
            extract_hover_contents(&json!(["first", {"value": "second"}])),
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
