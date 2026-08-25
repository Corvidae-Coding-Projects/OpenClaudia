use super::{resolve_open_path, resolve_path, secure_fs, MAX_MUTATION_BYTES, READ_TRACKER};
use crate::tools::args::{ToolArgError, ToolArgs as _};
use crate::tools::{ToolFailure, ToolFailureCode, ToolHandlerResult, ToolRetryability};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const SUPPORTED_NBFORMAT_MAJOR: u64 = 4;
const CELL_ID_NBFORMAT_MINOR: u64 = 5;
const MAX_NOTEBOOK_CELLS: usize = 10_000;
const MAX_CELL_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_NOTEBOOK_METADATA_BYTES: usize = 2 * 1024 * 1024;
const MAX_NOTEBOOK_OUTPUT_BYTES: usize = 5 * 1024 * 1024;
const MAX_OUTPUTS_PER_CELL: usize = 10_000;
const MAX_SOURCE_PARTS: usize = 100_000;

/// Split source text into a JSON array of line strings for notebook cell source format.
/// Each line except possibly the last ends with '\n'.
#[must_use]
pub fn source_to_line_array(source: &str) -> Value {
    if source.is_empty() {
        return json!([]);
    }
    let lines: Vec<&str> = source.split('\n').collect();
    let mut result: Vec<Value> = Vec::with_capacity(lines.len());
    for (i, line) in lines.iter().enumerate() {
        if i < lines.len() - 1 {
            // Not the last line: append \n
            result.push(json!(format!("{}\n", line)));
        } else {
            // Last line: include as-is (no trailing \n unless empty)
            if !line.is_empty() {
                result.push(json!(*line));
            }
        }
    }
    result.into()
}

/// Look up a cell's position in the array by its stable `id` field
/// (set by modern Jupyter clients in each cell's top-level metadata).
/// Returns `None` when no cell matches.
fn find_cell_by_id(cells: &[Value], cell_id: &str) -> Option<usize> {
    cells.iter().position(|c| {
        c.get("id")
            .and_then(|v| v.as_str())
            .is_some_and(|id| id == cell_id)
    })
}

/// Validation helpers return a message so the entry point can `?`-bubble
/// errors and keep its body linear (validate → resolve → dispatch → persist).
type NotebookValidationError = String;

/// Edit operation on a notebook cell. crosslink #974.
///
/// Was a `String` validated against `["replace", "insert", "delete"]` then
/// re-matched in three downstream sites (one of them ending in
/// `_ => unreachable!()`). A closed enum lets the type system prove the
/// dispatch is total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EditMode {
    Replace,
    Insert,
    Delete,
}

impl EditMode {
    fn parse(s: &str) -> Result<Self, NotebookValidationError> {
        match s {
            "replace" => Ok(Self::Replace),
            "insert" => Ok(Self::Insert),
            "delete" => Ok(Self::Delete),
            other => Err(format!(
                "Invalid edit_mode '{other}'. Must be 'replace', 'insert', or 'delete'."
            )),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Replace => "replace",
            Self::Insert => "insert",
            Self::Delete => "delete",
        }
    }
}

/// Cell kind in a Jupyter notebook (matches the nbformat `cell_type` field).
/// crosslink #985: the prior code accepted any string verbatim for
/// `cell_type`, so a model could persist a cell with `cell_type: "garbage"`
/// (or `"raw"` with no `outputs`/`execution_count` cleanup) and corrupt the
/// notebook for downstream Jupyter clients. Validate against a closed
/// allowlist of nbformat-defined cell types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CellType {
    Code,
    Markdown,
    Raw,
}

impl CellType {
    fn parse(s: &str) -> Result<Self, NotebookValidationError> {
        match s {
            "code" => Ok(Self::Code),
            "markdown" => Ok(Self::Markdown),
            "raw" => Ok(Self::Raw),
            other => Err(format!(
                "Invalid cell_type '{other}'. Must be 'code', 'markdown', or 'raw' (nbformat)."
            )),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::Markdown => "markdown",
            Self::Raw => "raw",
        }
    }
}

/// Parsed-and-validated arguments. Owning `String`s avoids tying the lifetime
/// of the helper chain to the borrowed `HashMap` arg map.
struct ParsedArgs {
    raw_path: String,
    cell_id: Option<String>,
    cell_number: Option<usize>,
    new_source: String,
    cell_type: Option<CellType>,
    edit_mode: EditMode,
}

/// Path/preflight context shared across snapshot validation and publication.
struct NotebookHandle {
    /// Canonicalized path, used in user-facing error messages and guardrails.
    canonical_path: String,
    /// Leaf-preserving path passed to the descriptor-relative atomic writer.
    /// It rejects symlinks and publishes only over the reviewed generation.
    open_path: PathBuf,
}

/// Result of resolving `cell_id` / `cell_number` against the parsed cells.
struct Locator {
    /// `Some(idx)` when a locator was supplied and (for `cell_id`) found.
    /// `None` only when neither locator was supplied — handled per-mode.
    index: Option<usize>,
    /// Human-readable description used in out-of-bounds error messages
    /// (`"id 'abc'"` vs `"number 3"` vs `"<unspecified>"`).
    target_desc: String,
}

/// What happened during the dispatch step, threaded into the summary line.
struct EditOutcome {
    /// Index that should appear in `Replaced/Inserted/Deleted cell <N>`.
    /// `None` only for "insert at the head with no locator" which falls
    /// back to `target_desc`.
    summary_index: Option<usize>,
}

/// Step 1 of the entry point: extract & validate every argument. No I/O,
/// no path resolution — just argument shape and the `edit_mode` enum check.
fn parse_args(args: &HashMap<String, Value>) -> Result<ParsedArgs, NotebookValidationError> {
    let raw_path = args
        .arg_str_strict("notebook_path")
        .map_err(ToolArgError::into_tool_error)
        .map_err(|(message, _)| message)?
        .to_string();

    let edit_mode = EditMode::parse(
        args.arg_str_or_strict("edit_mode", "replace")
            .map_err(ToolArgError::into_tool_error)
            .map_err(|(message, _)| message)?,
    )?;

    let new_source = args
        .arg_str_opt_strict("new_source")
        .map_err(ToolArgError::into_tool_error)
        .map_err(|(message, _)| message)?;
    let new_source = match (edit_mode, new_source) {
        (EditMode::Delete, None) => String::new(),
        (_, Some(source)) => source.to_string(),
        _ => {
            return Err(format!(
                "Missing 'new_source' argument: it is required for {} mode.",
                edit_mode.as_str()
            ))
        }
    };
    if new_source.len() > MAX_CELL_SOURCE_BYTES {
        return Err(format!(
            "new_source is {} bytes, exceeding the {MAX_CELL_SOURCE_BYTES}-byte cell source limit.",
            new_source.len()
        ));
    }
    let source_parts = new_source.bytes().filter(|byte| *byte == b'\n').count() + 1;
    if source_parts > MAX_SOURCE_PARTS {
        return Err(format!(
            "new_source has {source_parts} lines, exceeding the {MAX_SOURCE_PARTS}-part cell source limit."
        ));
    }

    let cell_id = args
        .arg_str_opt_strict("cell_id")
        .map_err(ToolArgError::into_tool_error)
        .map_err(|(message, _)| message)?
        .map(str::to_string);
    // crosslink #470: do NOT saturate a u64 cell_number into usize::MAX. On a
    // 32-bit target the silent truncation would let `cell_number = u64::MAX`
    // through to the downstream "cell N out of bounds" check with a misleading
    // length comparison. Reject anything that does not fit `usize` up front so
    // the error names the real cause (out-of-range index, not "out of bounds
    // for a 1-cell notebook"). The `?` returns `(message, true)` via the
    // ToolFailure shape used throughout this module.
    let cell_number = match args.get("cell_number") {
        None => None,
        Some(value) => {
            let n = value.as_u64().ok_or_else(|| {
                ToolArgError::WrongType {
                    key: "cell_number",
                    expected: "non-negative integer",
                }
                .into_tool_error()
                .0
            })?;
            Some(
                usize::try_from(n)
                    .map_err(|_| format!("Cell number {n} is out of range for this platform."))?,
            )
        }
    };
    // crosslink #985: validate `cell_type` against the nbformat allowlist —
    // `code`, `markdown`, `raw` — instead of accepting any string verbatim.
    let cell_type = match args
        .arg_str_opt_strict("cell_type")
        .map_err(ToolArgError::into_tool_error)
        .map_err(|(message, _)| message)?
    {
        Some(s) => Some(CellType::parse(s)?),
        None => None,
    };

    Ok(ParsedArgs {
        raw_path,
        cell_id,
        cell_number,
        new_source,
        cell_type,
        edit_mode,
    })
}

/// Step 2: resolve the path, enforce read-before-edit, canonicalize for the
/// blast-radius check, then open ONCE with `O_NOFOLLOW`. Returns the open
/// handle plus the canonicalized path for downstream messages.
fn preflight_and_open(
    run: &std::sync::Arc<crate::tools::security::ToolRunContext>,
    raw_path: &str,
) -> Result<NotebookHandle, NotebookValidationError> {
    let resolved = resolve_path(run, raw_path)?;
    // Leaf-preserving path for the O_NOFOLLOW open. See crosslink #417.
    let open_path = resolve_open_path(run, raw_path)?;

    if !READ_TRACKER.has_been_read(run, &resolved) {
        return Err(format!(
            "You must read '{}' before editing it. Use read_file first to see the actual contents.",
            resolved.display()
        ));
    }

    let canonical_path = std::fs::canonicalize(&resolved)
        .map(|c| c.to_string_lossy().to_string())
        .map_err(|_| format!("Cannot resolve notebook path '{}'", resolved.display()))?;

    super::require_fresh_file_observation_if_ledger_active(
        run,
        Path::new(&canonical_path),
        "editing it",
    )?;

    Ok(NotebookHandle {
        canonical_path,
        open_path,
    })
}

#[derive(Default)]
struct NotebookBudget {
    metadata_bytes: usize,
    output_bytes: usize,
}

fn add_budget(total: &mut usize, amount: usize, maximum: usize, label: &str) -> Result<(), String> {
    *total = total
        .checked_add(amount)
        .ok_or_else(|| format!("Notebook {label} size overflow."))?;
    if *total > maximum {
        return Err(format!(
            "Notebook {label} uses {} bytes, exceeding the {maximum}-byte limit.",
            *total
        ));
    }
    Ok(())
}

fn serialized_len(value: &Value, label: &str) -> Result<usize, String> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|error| format!("Could not measure {label}: {error}"))
}

fn validate_metadata(
    value: Option<&Value>,
    label: &str,
    budget: &mut NotebookBudget,
) -> Result<(), String> {
    let metadata = value.ok_or_else(|| format!("{label} is missing required metadata."))?;
    if !metadata.is_object() {
        return Err(format!("{label} metadata must be a JSON object."));
    }
    add_budget(
        &mut budget.metadata_bytes,
        serialized_len(metadata, &format!("{label} metadata"))?,
        MAX_NOTEBOOK_METADATA_BYTES,
        "metadata",
    )
}

fn validate_multiline(value: Option<&Value>, label: &str) -> Result<(), String> {
    let value = value.ok_or_else(|| format!("{label} is missing."))?;
    let (parts, bytes) = if let Some(text) = value.as_str() {
        (1, text.len())
    } else if let Some(lines) = value.as_array() {
        let mut bytes = 0_usize;
        for (index, line) in lines.iter().enumerate() {
            let line = line
                .as_str()
                .ok_or_else(|| format!("{label}[{index}] must be a string."))?;
            bytes = bytes
                .checked_add(line.len())
                .ok_or_else(|| format!("{label} size overflow."))?;
        }
        (lines.len(), bytes)
    } else {
        return Err(format!("{label} must be a string or an array of strings."));
    };
    if parts > MAX_SOURCE_PARTS {
        return Err(format!(
            "{label} has {parts} parts, exceeding the {MAX_SOURCE_PARTS}-part limit."
        ));
    }
    if bytes > MAX_CELL_SOURCE_BYTES {
        return Err(format!(
            "{label} uses {bytes} bytes, exceeding the {MAX_CELL_SOURCE_BYTES}-byte limit."
        ));
    }
    Ok(())
}

fn validate_mime_bundle(value: Option<&Value>, label: &str) -> Result<(), String> {
    let bundle = value
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{label} must be a JSON object."))?;
    for (mime, data) in bundle {
        if mime == "application/json" || mime.ends_with("+json") {
            continue;
        }
        if data.is_string()
            || data
                .as_array()
                .is_some_and(|parts| parts.iter().all(Value::is_string))
        {
            continue;
        }
        return Err(format!(
            "{label} entry '{mime}' must be a string or an array of strings unless it is JSON MIME data."
        ));
    }
    Ok(())
}

fn validate_attachments(value: &Value, label: &str) -> Result<(), String> {
    let attachments = value
        .as_object()
        .ok_or_else(|| format!("{label} must be a JSON object."))?;
    for (name, bundle) in attachments {
        validate_mime_bundle(Some(bundle), &format!("{label}.{name}"))?;
    }
    Ok(())
}

fn validate_execution_count(value: Option<&Value>, label: &str) -> Result<(), String> {
    match value {
        Some(Value::Null) => Ok(()),
        Some(value) if value.as_u64().is_some() => Ok(()),
        Some(_) => Err(format!("{label} must be null or a non-negative integer.")),
        None => Err(format!("{label} is missing.")),
    }
}

fn validate_outputs(
    value: Option<&Value>,
    cell_index: usize,
    budget: &mut NotebookBudget,
) -> Result<(), String> {
    let outputs = value
        .and_then(Value::as_array)
        .ok_or_else(|| format!("Code cell {cell_index} outputs must be an array."))?;
    if outputs.len() > MAX_OUTPUTS_PER_CELL {
        return Err(format!(
            "Code cell {cell_index} has {} outputs, exceeding the {MAX_OUTPUTS_PER_CELL}-output limit.",
            outputs.len()
        ));
    }
    for (output_index, output) in outputs.iter().enumerate() {
        let label = format!("Cell {cell_index} output {output_index}");
        let object = output
            .as_object()
            .ok_or_else(|| format!("{label} must be a JSON object."))?;
        let output_type = object
            .get("output_type")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{label} is missing string output_type."))?;
        match output_type {
            "stream" => {
                if object.get("name").and_then(Value::as_str).is_none() {
                    return Err(format!("{label} stream name must be a string."));
                }
                validate_multiline(object.get("text"), &format!("{label} text"))?;
            }
            "display_data" => {
                validate_mime_bundle(object.get("data"), &format!("{label} data"))?;
                validate_metadata(object.get("metadata"), &label, budget)?;
            }
            "execute_result" => {
                validate_mime_bundle(object.get("data"), &format!("{label} data"))?;
                validate_metadata(object.get("metadata"), &label, budget)?;
                validate_execution_count(
                    object.get("execution_count"),
                    &format!("{label} execution_count"),
                )?;
            }
            "error" => {
                for field in ["ename", "evalue"] {
                    if object.get(field).and_then(Value::as_str).is_none() {
                        return Err(format!("{label} {field} must be a string."));
                    }
                }
                let traceback = object
                    .get("traceback")
                    .and_then(Value::as_array)
                    .ok_or_else(|| format!("{label} traceback must be an array."))?;
                if !traceback.iter().all(Value::is_string) {
                    return Err(format!("{label} traceback entries must be strings."));
                }
            }
            other => return Err(format!("{label} has unsupported output_type '{other}'.")),
        }
        add_budget(
            &mut budget.output_bytes,
            serialized_len(output, &label)?,
            MAX_NOTEBOOK_OUTPUT_BYTES,
            "outputs",
        )?;
    }
    Ok(())
}

fn valid_cell_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Validate the nbformat subset this editor can preserve safely. Major version
/// 4 is stable across minor revisions. Missing IDs are tolerated only during
/// input validation so legacy notebooks—and modern notebooks written by the
/// former editor—can be repaired before strict publication validation.
fn validate_notebook(notebook: &Value, allow_missing_ids: bool) -> Result<u64, String> {
    let root = notebook
        .as_object()
        .ok_or_else(|| "Notebook root must be a JSON object.".to_string())?;
    let major = root
        .get("nbformat")
        .and_then(Value::as_u64)
        .ok_or_else(|| "Notebook nbformat must be a non-negative integer.".to_string())?;
    if major != SUPPORTED_NBFORMAT_MAJOR {
        return Err(format!(
            "Unsupported notebook nbformat {major}; notebook_edit supports nbformat {SUPPORTED_NBFORMAT_MAJOR}."
        ));
    }
    let minor = root
        .get("nbformat_minor")
        .and_then(Value::as_u64)
        .ok_or_else(|| "Notebook nbformat_minor must be a non-negative integer.".to_string())?;
    let cells = root
        .get("cells")
        .and_then(Value::as_array)
        .ok_or_else(|| "Notebook has no valid 'cells' array.".to_string())?;
    if cells.len() > MAX_NOTEBOOK_CELLS {
        return Err(format!(
            "Notebook has {} cells, exceeding the {MAX_NOTEBOOK_CELLS}-cell limit.",
            cells.len()
        ));
    }

    let mut budget = NotebookBudget::default();
    validate_metadata(root.get("metadata"), "Notebook", &mut budget)?;
    let mut ids = HashSet::with_capacity(cells.len());
    for (index, cell) in cells.iter().enumerate() {
        let object = cell
            .as_object()
            .ok_or_else(|| format!("Cell {index} must be a JSON object."))?;
        match object.get("id") {
            Some(Value::String(id)) if valid_cell_id(id) => {
                if !ids.insert(id.clone()) {
                    return Err(format!("Cell {index} repeats cell id '{id}'."));
                }
            }
            Some(Value::String(id)) => {
                return Err(format!(
                    "Cell {index} id '{id}' must be 1-64 ASCII letters, digits, '-' or '_'."
                ));
            }
            Some(_) => return Err(format!("Cell {index} id must be a string.")),
            None if allow_missing_ids => {}
            None => return Err(format!("Cell {index} is missing required stable id.")),
        }
        let cell_type = object
            .get("cell_type")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Cell {index} is missing string cell_type."))?;
        let cell_type = CellType::parse(cell_type)?;
        validate_metadata(
            object.get("metadata"),
            &format!("Cell {index}"),
            &mut budget,
        )?;
        validate_multiline(object.get("source"), &format!("Cell {index} source"))?;
        if let Some(attachments) = object.get("attachments") {
            validate_attachments(attachments, &format!("Cell {index} attachments"))?;
        }
        match cell_type {
            CellType::Code => {
                if object.contains_key("attachments") {
                    return Err(format!("Code cell {index} must not contain attachments."));
                }
                validate_outputs(object.get("outputs"), index, &mut budget)?;
                validate_execution_count(
                    object.get("execution_count"),
                    &format!("Code cell {index} execution_count"),
                )?;
            }
            CellType::Markdown | CellType::Raw => {
                if object.contains_key("outputs") || object.contains_key("execution_count") {
                    return Err(format!(
                        "{} cell {index} must not contain code-only outputs or execution_count.",
                        cell_type.as_str()
                    ));
                }
            }
        }
    }
    Ok(minor)
}

fn generate_cell_id(existing: &HashSet<String>) -> Result<String, String> {
    for _ in 0..16 {
        let candidate = uuid::Uuid::new_v4().simple().to_string();
        if !existing.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err("Could not generate a unique notebook cell id after 16 attempts.".to_string())
}

fn ensure_stable_cell_ids(notebook: &mut Value, minor: u64) -> Result<(), String> {
    let cells = notebook
        .get_mut("cells")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "Notebook has no valid 'cells' array.".to_string())?;
    let mut ids: HashSet<String> = cells
        .iter()
        .filter_map(|cell| cell.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let mut added_id = false;
    for cell in cells {
        if cell.get("id").is_none() {
            let id = generate_cell_id(&ids)?;
            ids.insert(id.clone());
            cell["id"] = json!(id);
            added_id = true;
        }
    }
    if minor < CELL_ID_NBFORMAT_MINOR || added_id {
        notebook["nbformat_minor"] = json!(CELL_ID_NBFORMAT_MINOR);
    }
    Ok(())
}

/// Step 4: resolve `cell_id` / `cell_number` against the cells array. When
/// `cell_id` is present it wins (stable id beats positional). Unknown ids
/// are a hard error; absent locators yield `index = None` for the modes
/// that allow it (`insert`).
fn resolve_locator(
    parsed: &ParsedArgs,
    cells: &[Value],
) -> Result<Locator, NotebookValidationError> {
    let index = if let Some(id) = parsed.cell_id.as_deref() {
        Some(
            find_cell_by_id(cells, id)
                .ok_or_else(|| format!("No cell with id '{id}' found in notebook."))?,
        )
    } else {
        parsed.cell_number
    };

    let target_desc = parsed.cell_id.as_deref().map_or_else(
        || {
            parsed
                .cell_number
                .map_or_else(|| "<unspecified>".to_string(), |n| format!("number {n}"))
        },
        |id| format!("id '{id}'"),
    );

    Ok(Locator { index, target_desc })
}

/// Replace-mode dispatch. `cell_id` or `cell_number` is required.
///
/// Bounds policy: a request at `index == cells.len()` is promoted to an
/// append-at-end insert (CC parity, crosslink #704). Promotion requires
/// `cell_type` because the new cell needs a kind. Indices strictly past
/// the end still error.
///
/// Code-cell side-effects: when the resulting cell is a code cell, the
/// stale `outputs` array and `execution_count` from the previous source
/// are reset to `[]` and `null` respectively (crosslink #702). The old
/// values describe code that no longer exists; preserving them produces
/// a notebook whose displayed output is from source that's been replaced.
fn apply_replace(
    cells: &mut Vec<Value>,
    locator: &Locator,
    parsed: &ParsedArgs,
) -> Result<EditOutcome, NotebookValidationError> {
    let index = locator
        .index
        .ok_or_else(|| "replace requires either 'cell_id' or 'cell_number'.".to_string())?;
    // crosslink #704: index == cells.len() (one past the end) is promoted
    // to insert-at-end — matches CC's silent promotion. Requires cell_type
    // because the new cell needs a kind.
    if index == cells.len() {
        if parsed.cell_type.is_none() {
            return Err(format!(
                "Cell {} is out of bounds for replace. Notebook has {} cells. \
                     To append a new cell at the end via replace, pass 'cell_type' \
                     (the request is promoted to insert).",
                locator.target_desc,
                cells.len(),
            ));
        }
        return apply_insert(cells, locator, parsed);
    }
    if index > cells.len() {
        return Err(format!(
            "Cell {} is out of bounds. Notebook has {} cells (valid range: 0-{}).",
            locator.target_desc,
            cells.len(),
            cells.len().saturating_sub(1)
        ));
    }
    cells[index]["source"] = source_to_line_array(&parsed.new_source);
    // Prevalidation guarantees a supported existing type. An explicit
    // override wins; malformed or future cell types are never guessed as code.
    let existing_ct = cells[index]
        .get("cell_type")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Cell {index} is missing string cell_type."))
        .and_then(CellType::parse)?;
    let effective_ct = parsed.cell_type.unwrap_or(existing_ct);
    if let Some(ct) = parsed.cell_type {
        cells[index]["cell_type"] = json!(ct.as_str());
    }
    // crosslink #985 + #702: normalise the type-specific fields so the
    // notebook satisfies nbformat. Markdown / raw cells must NOT carry
    // code-only fields. Code cells MUST carry both, AND the previous
    // execution state is dropped — the source has changed, so the old
    // outputs and execution_count are stale by definition.
    let cell_obj = &mut cells[index];
    match effective_ct {
        CellType::Code => {
            if let Some(obj) = cell_obj.as_object_mut() {
                obj.remove("attachments");
            }
            cell_obj["outputs"] = json!([]);
            cell_obj["execution_count"] = Value::Null;
        }
        CellType::Markdown | CellType::Raw => {
            if let Some(obj) = cell_obj.as_object_mut() {
                obj.remove("outputs");
                obj.remove("execution_count");
            }
        }
    }
    Ok(EditOutcome {
        summary_index: Some(index),
    })
}

/// Insert-mode dispatch. `cell_type` is required. `cell_id` semantics
/// diverge from replace/delete: "insert AFTER the cell with this id".
/// Legacy `cell_number` still means "at this exact position". Omitting
/// both inserts at the head.
fn apply_insert(
    cells: &mut Vec<Value>,
    locator: &Locator,
    parsed: &ParsedArgs,
) -> Result<EditOutcome, NotebookValidationError> {
    let ct = parsed.cell_type.ok_or_else(|| {
        "cell_type is required when inserting a new cell. Use 'code', 'markdown', or 'raw'."
            .to_string()
    })?;

    let insert_at = match (parsed.cell_id.as_deref(), parsed.cell_number) {
        (Some(_), _) => locator.index.map_or(0, |i| i + 1),
        (None, Some(n)) => n,
        (None, None) => 0,
    };

    if insert_at > cells.len() {
        return Err(format!(
            "Cell {} is out of bounds for insertion. Notebook has {} cells (valid range: 0-{}).",
            locator.target_desc,
            cells.len(),
            cells.len()
        ));
    }

    let ids = cells
        .iter()
        .filter_map(|cell| cell.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let id = generate_cell_id(&ids)?;

    let mut new_cell = json!({
        "id": id,
        "cell_type": ct.as_str(),
        "metadata": {},
        "source": source_to_line_array(&parsed.new_source)
    });
    // crosslink #985: only code cells carry `outputs` / `execution_count` in
    // nbformat. The typed `CellType` lets us decide once at the dispatch
    // site instead of comparing strings.
    if ct == CellType::Code {
        new_cell["outputs"] = json!([]);
        new_cell["execution_count"] = Value::Null;
    }
    cells.insert(insert_at, new_cell);
    Ok(EditOutcome {
        summary_index: Some(insert_at),
    })
}

/// Delete-mode dispatch. Same locator + bounds rules as replace.
fn apply_delete(
    cells: &mut Vec<Value>,
    locator: &Locator,
) -> Result<EditOutcome, NotebookValidationError> {
    let index = locator
        .index
        .ok_or_else(|| "delete requires either 'cell_id' or 'cell_number'.".to_string())?;
    if index >= cells.len() {
        return Err(format!(
            "Cell {} is out of bounds. Notebook has {} cells (valid range: 0-{}).",
            locator.target_desc,
            cells.len(),
            cells.len().saturating_sub(1)
        ));
    }
    cells.remove(index);
    Ok(EditOutcome {
        summary_index: Some(index),
    })
}

/// Step 5: dispatch on `edit_mode`. crosslink #974: the typed `EditMode`
/// enum makes this match exhaustive without a wildcard — adding a new mode
/// is a compile error here, not a runtime `unreachable!()`.
fn dispatch_edit(
    cells: &mut Vec<Value>,
    locator: &Locator,
    parsed: &ParsedArgs,
) -> Result<EditOutcome, NotebookValidationError> {
    match parsed.edit_mode {
        EditMode::Replace => apply_replace(cells, locator, parsed),
        EditMode::Insert => apply_insert(cells, locator, parsed),
        EditMode::Delete => apply_delete(cells, locator),
    }
}

const fn invalid_failure(message: String) -> ToolFailure {
    ToolFailure::new(
        ToolFailureCode::InvalidInput,
        message,
        ToolRetryability::Never,
    )
}

const fn external_failure(message: String) -> ToolFailure {
    ToolFailure::new(
        ToolFailureCode::External,
        message,
        ToolRetryability::Unknown,
    )
}

/// Step 6: publish the fully validated notebook over exactly the generation
/// returned by `read_file`. The shared atomic writer stages and synchronizes
/// complete bytes before a descriptor-relative namespace swap, so a failed or
/// interrupted write never exposes a truncated notebook.
fn write_notebook(
    run: &crate::tools::security::ToolRunContext,
    handle: &NotebookHandle,
    notebook: &Value,
    original_content: &str,
    before_snapshot: super::FileSnapshot,
) -> Result<crate::runtime::ContentDigest, ToolFailure> {
    let pretty = serde_json::to_string_pretty(notebook)
        .map_err(|error| invalid_failure(format!("Failed to serialize notebook: {error}")))?;
    if pretty.len() > MAX_MUTATION_BYTES {
        return Err(invalid_failure(format!(
                "Edited notebook would be {} bytes, exceeding the {MAX_MUTATION_BYTES}-byte file limit.",
                pretty.len()
            )));
    }
    let prepared_diff =
        super::prepare_file_diff(run, &handle.canonical_path, original_content, &pretty)
            .map_err(invalid_failure)?;
    let mut line_reservation = crate::guardrails::reserve_changed_lines(
        run,
        u64::from(prepared_diff.lines_added) + u64::from(prepared_diff.lines_removed),
    )
    .map_err(external_failure)?;
    let diff_permit = crate::guardrails::admit_file_change(
        run,
        Path::new(&handle.canonical_path),
        pretty.as_bytes(),
    )
    .map_err(external_failure)?;

    match secure_fs::write_atomic_generation(
        run,
        &handle.open_path,
        Some(before_snapshot.generation()),
        pretty.as_bytes(),
        MAX_MUTATION_BYTES,
    ) {
        Ok(after_snapshot) => {
            line_reservation.commit();
            diff_permit.commit();
            crate::guardrails::record_file_modification(
                run,
                &handle.canonical_path,
                prepared_diff.lines_added,
                prepared_diff.lines_removed,
            );
            super::record_prepared_diff_observation(
                run,
                &handle.canonical_path,
                pretty.as_bytes(),
                &prepared_diff,
            );
            Ok(after_snapshot)
        }
        Err(secure_fs::AtomicWriteError::Conflict { expected, observed }) => {
            READ_TRACKER.mark_stale(run, Path::new(&handle.canonical_path));
            let mut failure = ToolFailure::new(
                ToolFailureCode::Conflict,
                format!(
                    "Notebook '{}' changed before the edit could be committed (expected {}, observed {}). No newer content was overwritten; read it again and retry.",
                    handle.canonical_path,
                    expected.map_or_else(|| "missing".to_string(), |value| value.to_string()),
                    observed.map_or_else(|| "missing".to_string(), |value| value.to_string())
                ),
                ToolRetryability::Safe,
            );
            failure.recovery = Some(json!({
                "action": "read_file",
                "path": handle.canonical_path,
                "expected_snapshot": before_snapshot.generation(),
                "observed_snapshot": observed,
            }));
            Err(failure)
        }
        Err(secure_fs::AtomicWriteError::Failed(message)) => Err(external_failure(format!(
                "Failed to atomically edit notebook '{}': {message}. The prior notebook generation remains published.",
                handle.canonical_path
            ))),
    }
}

/// Step 7: format the success summary. The summary index falls back to
/// the locator's target description for the (rare) head-insert case where
/// the caller supplied no locator.
fn format_success(
    run: &crate::tools::ToolRunContext,
    handle: &NotebookHandle,
    notebook: &Value,
    locator: &Locator,
    outcome: &EditOutcome,
    parsed: &ParsedArgs,
    snapshots: (crate::runtime::ContentDigest, crate::runtime::ContentDigest),
) -> ToolHandlerResult {
    let (before_snapshot, after_snapshot) = snapshots;
    let where_str = outcome
        .summary_index
        .map_or_else(|| locator.target_desc.clone(), |idx| format!("{idx}"));
    let action = match parsed.edit_mode {
        EditMode::Replace => format!("Replaced cell {where_str} contents"),
        EditMode::Insert => format!(
            "Inserted new {} cell at position {}",
            parsed.cell_type.map_or("unknown", CellType::as_str),
            where_str
        ),
        EditMode::Delete => format!("Deleted cell {where_str}"),
    };
    let mut result = format!(
        "Successfully edited '{}'. {}. Notebook now has {} cells.",
        handle.canonical_path,
        action,
        notebook
            .get("cells")
            .and_then(|c| c.as_array())
            .map_or(0, std::vec::Vec::len)
    );
    if let Some(warning) = crate::guardrails::check_diff_thresholds(run) {
        let _ = write!(result, "\n\nWarning: {}", warning.message);
    }
    ToolHandlerResult::success_structured(
        result,
        json!({
            "path": handle.canonical_path,
            "edit_mode": parsed.edit_mode.as_str(),
            "cell_index": outcome.summary_index,
            "cell_count": notebook
                .get("cells")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
            "before_snapshot": before_snapshot,
            "after_snapshot": after_snapshot,
        }),
    )
}

/// Edit a Jupyter notebook cell.
///
/// Accepts either `cell_id` (Claude Code-compatible — matches the `id`
/// field Jupyter clients write into each cell's top-level metadata) or
/// `cell_number` (legacy 0-indexed position, kept for back-compat). At
/// least one of the two must be present for `replace` and `delete`.
/// For `insert`, `cell_id` means "insert AFTER the cell with this id";
/// omitting both inserts at position 0.
///
/// Body is the linear pipeline: validate → preflight → read → resolve
/// → dispatch → persist → summarize. Each step is a private helper above.
/// Refactored from a 200+-line god function per crosslink #681.
#[cfg(test)]
pub fn execute_notebook_edit(
    run: &std::sync::Arc<crate::tools::security::ToolRunContext>,
    args: &HashMap<String, Value>,
) -> (String, bool) {
    execute_notebook_edit_typed(run, args).into_legacy()
}

pub fn execute_notebook_edit_typed(
    run: &std::sync::Arc<crate::tools::security::ToolRunContext>,
    args: &HashMap<String, Value>,
) -> ToolHandlerResult {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(message) => return notebook_invalid(message),
    };
    let handle = match preflight_and_open(run, &parsed.raw_path) {
        Ok(h) => h,
        Err(message) => return notebook_invalid(message),
    };
    let before_snapshot = match super::require_expected_snapshot(
        run,
        Path::new(&handle.canonical_path),
        args.get("expected_snapshot"),
    ) {
        Ok(snapshot) => snapshot,
        Err(failure) => return notebook_failure(failure),
    };
    let bytes = match super::read_expected_snapshot_bytes(
        run,
        Path::new(&handle.canonical_path),
        before_snapshot,
    ) {
        Ok(bytes) => bytes,
        Err(failure) => return notebook_failure(failure),
    };
    let original_content = match String::from_utf8(bytes) {
        Ok(content) => content,
        Err(error) => {
            return notebook_invalid(format!(
                "Notebook '{}' is not UTF-8 JSON: {error}",
                handle.canonical_path
            ))
        }
    };
    let mut notebook: Value = match serde_json::from_str(&original_content) {
        Ok(notebook) => notebook,
        Err(error) => {
            return notebook_invalid(format!(
                "Failed to parse notebook '{}' as JSON: {error}",
                handle.canonical_path
            ))
        }
    };
    let minor = match validate_notebook(&notebook, true) {
        Ok(minor) => minor,
        Err(message) => return notebook_invalid(message),
    };
    if let Err(message) = ensure_stable_cell_ids(&mut notebook, minor) {
        return notebook_invalid(message);
    }
    let Some(cells) = notebook.get_mut("cells").and_then(|c| c.as_array_mut()) else {
        return notebook_invalid("Notebook has no 'cells' array.".to_string());
    };
    let locator = match resolve_locator(&parsed, cells) {
        Ok(l) => l,
        Err(message) => return notebook_invalid(message),
    };
    let outcome = match dispatch_edit(cells, &locator, &parsed) {
        Ok(o) => o,
        Err(message) => return notebook_invalid(message),
    };
    if let Err(message) = validate_notebook(&notebook, false) {
        return notebook_invalid(format!("Edited notebook is invalid: {message}"));
    }
    match write_notebook(run, &handle, &notebook, &original_content, before_snapshot) {
        Ok(after_snapshot) => format_success(
            run,
            &handle,
            &notebook,
            &locator,
            &outcome,
            &parsed,
            (before_snapshot.generation(), after_snapshot),
        ),
        Err(failure) => notebook_failure(failure),
    }
}

fn notebook_invalid(message: String) -> ToolHandlerResult {
    notebook_failure(invalid_failure(message))
}

fn notebook_failure(failure: ToolFailure) -> ToolHandlerResult {
    ToolHandlerResult::error(failure)
}

#[cfg(test)]
mod tests {
    use super::super::READ_TRACKER;
    use super::{
        execute_notebook_edit, source_to_line_array, validate_notebook, MAX_CELL_SOURCE_BYTES,
        MAX_NOTEBOOK_CELLS, MAX_NOTEBOOK_OUTPUT_BYTES,
    };
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::io::Write as _;
    use std::path::Path;
    use tempfile::{NamedTempFile, TempDir};

    fn test_run() -> &'static std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context()
    }

    // =========================================================================
    // source_to_line_array unit tests
    // =========================================================================

    #[test]
    fn source_to_line_array_empty_yields_empty_array() {
        let v = source_to_line_array("");
        assert_eq!(v, json!([]));
    }

    #[test]
    fn source_to_line_array_single_line_no_trailing_newline() {
        let v = source_to_line_array("hello");
        assert_eq!(v, json!(["hello"]));
    }

    #[test]
    fn source_to_line_array_multiline_adds_newlines_to_non_last() {
        let v = source_to_line_array("a\nb\nc");
        // Lines "a" and "b" get \n appended; last line "c" does not.
        assert_eq!(v, json!(["a\n", "b\n", "c"]));
    }

    #[test]
    fn notebook_validation_rejects_unsupported_and_malformed_shapes() {
        let cases = [
            (
                json!({"nbformat": 3, "nbformat_minor": 0, "metadata": {}, "cells": []}),
                "Unsupported notebook nbformat",
            ),
            (
                json!({"nbformat": 4, "nbformat_minor": 5, "metadata": [], "cells": []}),
                "metadata must be a JSON object",
            ),
            (
                make_notebook(
                    &json!([{"id": "bad id", "cell_type": "markdown", "metadata": {}, "source": []}]),
                ),
                "must be 1-64 ASCII",
            ),
            (
                make_notebook(
                    &json!([{"id": "cell", "cell_type": "markdown", "metadata": {}, "source": [1]}]),
                ),
                "source[0] must be a string",
            ),
            (
                make_notebook(
                    &json!([{"id": "cell", "cell_type": "code", "metadata": {}, "source": [], "outputs": [{"output_type": "stream", "name": 7, "text": []}], "execution_count": null}]),
                ),
                "stream name must be a string",
            ),
        ];
        for (notebook, expected) in cases {
            let error = validate_notebook(&notebook, true).expect_err("shape must be rejected");
            assert!(
                error.contains(expected),
                "expected {expected:?}, got {error:?}"
            );
        }
    }

    #[test]
    fn notebook_validation_enforces_practical_cell_source_and_output_bounds() {
        let too_many_cells = Value::Array(vec![Value::Null; MAX_NOTEBOOK_CELLS + 1]);
        let error = validate_notebook(&make_notebook(&too_many_cells), true)
            .expect_err("cell count must be bounded");
        assert!(error.contains("cell limit"), "{error}");

        let oversized_source = "x".repeat(MAX_CELL_SOURCE_BYTES + 1);
        let error = validate_notebook(
            &make_notebook(&json!([{"id": "cell", "cell_type": "markdown", "metadata": {}, "source": oversized_source}])),
            true,
        )
        .expect_err("source bytes must be bounded");
        assert!(
            error.contains("cell source") || error.contains("source uses"),
            "{error}"
        );

        let output_chunk = "x".repeat(MAX_NOTEBOOK_OUTPUT_BYTES / 5);
        let outputs: Vec<Value> = (0..6)
            .map(|_| {
                json!({
                    "output_type": "display_data",
                    "data": {"text/plain": output_chunk},
                    "metadata": {}
                })
            })
            .collect();
        let error = validate_notebook(
            &make_notebook(&json!([{
                "id": "cell",
                "cell_type": "code",
                "metadata": {},
                "source": [],
                "outputs": outputs,
                "execution_count": null
            }])),
            true,
        )
        .expect_err("aggregate output bytes must be bounded");
        assert!(error.contains("Notebook outputs uses"), "{error}");
    }

    // =========================================================================
    // Helpers for notebook edit tests
    // =========================================================================

    /// Build a minimal valid .ipynb JSON with the given cells.
    fn make_notebook(cells: &Value) -> Value {
        json!({
            "nbformat": 4,
            "nbformat_minor": 5,
            "metadata": {},
            "cells": cells
        })
    }

    /// Write a notebook JSON to a `NamedTempFile`, mark it read in `READ_TRACKER`,
    /// and return (file, `canonical_path_string`).
    fn tmp_notebook(nb: &Value) -> (NamedTempFile, String) {
        let mut f = NamedTempFile::new_in(".").expect("tempfile");
        let text = serde_json::to_string_pretty(nb).expect("serialize");
        f.write_all(text.as_bytes()).expect("write");
        let canon = f.path().canonicalize().expect("canonicalize");
        READ_TRACKER.mark_read(test_run(), &canon);
        (f, canon.to_string_lossy().to_string())
    }

    fn add_expected_snapshot(args: &mut HashMap<String, Value>, path: &str) {
        let canonical = Path::new(path).canonicalize().expect("canonical notebook");
        let snapshot = READ_TRACKER
            .snapshot_for(test_run(), &canonical)
            .expect("test notebook must have a tracked snapshot");
        args.insert(
            "expected_snapshot".to_string(),
            json!(snapshot.generation().to_string()),
        );
    }

    fn args_replace_by_id(path: &str, cell_id: &str, new_source: &str) -> HashMap<String, Value> {
        let mut m = HashMap::new();
        m.insert("notebook_path".to_string(), json!(path));
        m.insert("cell_id".to_string(), json!(cell_id));
        m.insert("new_source".to_string(), json!(new_source));
        m.insert("edit_mode".to_string(), json!("replace"));
        add_expected_snapshot(&mut m, path);
        m
    }

    fn args_replace_by_number(
        path: &str,
        cell_number: u64,
        new_source: &str,
    ) -> HashMap<String, Value> {
        let mut m = HashMap::new();
        m.insert("notebook_path".to_string(), json!(path));
        m.insert("cell_number".to_string(), json!(cell_number));
        m.insert("new_source".to_string(), json!(new_source));
        m.insert("edit_mode".to_string(), json!("replace"));
        add_expected_snapshot(&mut m, path);
        m
    }

    fn args_insert(
        path: &str,
        cell_id: Option<&str>,
        cell_number: Option<u64>,
        cell_type: &str,
        new_source: &str,
    ) -> HashMap<String, Value> {
        let mut m = HashMap::new();
        m.insert("notebook_path".to_string(), json!(path));
        m.insert("cell_type".to_string(), json!(cell_type));
        m.insert("new_source".to_string(), json!(new_source));
        m.insert("edit_mode".to_string(), json!("insert"));
        if let Some(id) = cell_id {
            m.insert("cell_id".to_string(), json!(id));
        }
        if let Some(n) = cell_number {
            m.insert("cell_number".to_string(), json!(n));
        }
        add_expected_snapshot(&mut m, path);
        m
    }

    fn args_delete_by_id(path: &str, cell_id: &str) -> HashMap<String, Value> {
        let mut m = HashMap::new();
        m.insert("notebook_path".to_string(), json!(path));
        m.insert("cell_id".to_string(), json!(cell_id));
        m.insert("edit_mode".to_string(), json!("delete"));
        add_expected_snapshot(&mut m, path);
        m
    }

    /// Read the cells array back from a written notebook file.
    fn read_cells(path: &str) -> Vec<Value> {
        let text = std::fs::read_to_string(path).expect("read back");
        let nb: Value = serde_json::from_str(&text).expect("parse");
        nb["cells"].as_array().expect("cells array").clone()
    }

    // =========================================================================
    // Behavior 7: replace by cell_id — primary lookup
    // =========================================================================

    #[test]
    fn notebook_replace_by_cell_id_succeeds() {
        // Behavior 7: cell found by id field → source updated
        let nb = make_notebook(&json!([
            {"id": "cell-a", "cell_type": "code", "source": "old source", "metadata": {}, "outputs": [], "execution_count": null}
        ]));
        let (_f, path) = tmp_notebook(&nb);
        let args = args_replace_by_id(&path, "cell-a", "new source");
        let (msg, is_err) = execute_notebook_edit(test_run(), &args);
        assert!(!is_err, "replace by id must succeed: {msg}");
        let cells = read_cells(&path);
        let src: String = match &cells[0]["source"] {
            Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
            Value::String(s) => s.clone(),
            _ => panic!("unexpected source type"),
        };
        assert_eq!(src, "new source");
    }

    #[test]
    fn notebook_edit_publishes_snapshot_for_a_followup_edit() {
        let _lock = super::super::shared_tracker_lock();
        let nb = make_notebook(&json!([
            {"id": "cell-a", "cell_type": "code", "source": "old", "metadata": {}, "outputs": [], "execution_count": null},
            {"id": "cell-b", "cell_type": "code", "source": "second", "metadata": {}, "outputs": [], "execution_count": null}
        ]));
        let (_f, path) = tmp_notebook(&nb);
        let args = args_replace_by_id(&path, "cell-a", "new");
        let (msg, is_err) = execute_notebook_edit(test_run(), &args);
        assert!(!is_err, "first notebook edit must succeed: {msg}");

        let args2 = args_replace_by_id(&path, "cell-b", "changed");
        let (msg2, is_err2) = execute_notebook_edit(test_run(), &args2);
        assert!(
            !is_err2,
            "a committed tool generation may be edited again without discarding its snapshot: {msg2}"
        );
    }

    #[test]
    fn active_ledger_notebook_edit_requires_fresh_file_read_observation() {
        let _lock = super::super::shared_tracker_lock();
        READ_TRACKER.clear_all();
        let run = test_run();
        let ledger =
            std::sync::Arc::new(std::sync::Mutex::new(crate::ledger::RealityLedger::new()));
        let _ledger_guard =
            crate::ledger::install_active_ledger_for_session(run.session_id(), ledger);
        let nb = make_notebook(&json!([
            {"id": "cell-a", "cell_type": "code", "source": "old", "metadata": {}, "outputs": [], "execution_count": null}
        ]));
        let (_f, path) = tmp_notebook(&nb);

        let args = args_replace_by_id(&path, "cell-a", "new");
        let (msg, is_err) = execute_notebook_edit(run, &args);

        assert!(is_err, "notebook edit without ledger read must fail: {msg}");
        assert!(
            msg.contains("active reality ledger has no fresh file read observation"),
            "{msg}"
        );
        let cells = read_cells(&path);
        let src: String = match &cells[0]["source"] {
            Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
            Value::String(s) => s.clone(),
            _ => panic!("unexpected source type"),
        };
        assert_eq!(src, "old");
    }

    #[test]
    fn notebook_replace_by_cell_id_not_found_returns_error() {
        // Behavior 7 edge: cell_id not found and no cell_number fallback → error
        let nb = make_notebook(&json!([
            {"id": "cell-a", "cell_type": "code", "source": "x", "metadata": {}, "outputs": [], "execution_count": null}
        ]));
        let (_f, path) = tmp_notebook(&nb);
        let args = args_replace_by_id(&path, "nonexistent-id", "y");
        let (msg, is_err) = execute_notebook_edit(test_run(), &args);
        assert!(is_err, "unknown cell_id must error: {msg}");
        assert!(msg.contains("No cell with id"), "message: {msg}");
    }

    // =========================================================================
    // Behavior 7: replace by cell_number — fallback when no cell_id given
    // =========================================================================

    #[test]
    fn notebook_replace_by_cell_number_succeeds() {
        // Behavior 7: OC exposes cell_number as a distinct parameter (not a
        // fallback parse of cell_id as CC does). When cell_id is absent,
        // cell_number is used directly as the 0-indexed position.
        let nb = make_notebook(&json!([
            {"cell_type": "code", "source": "first", "metadata": {}, "outputs": [], "execution_count": null},
            {"cell_type": "code", "source": "second", "metadata": {}, "outputs": [], "execution_count": null}
        ]));
        let (_f, path) = tmp_notebook(&nb);
        let args = args_replace_by_number(&path, 1, "updated second");
        let (msg, is_err) = execute_notebook_edit(test_run(), &args);
        assert!(!is_err, "replace by cell_number must succeed: {msg}");
        let cells = read_cells(&path);
        let src: String = match &cells[1]["source"] {
            Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
            Value::String(s) => s.clone(),
            _ => panic!("unexpected source type"),
        };
        assert!(src.contains("updated second"), "source updated: {src}");
    }

    #[test]
    fn notebook_replace_without_cell_id_or_number_errors() {
        // Behavior 7 edge: replace requires cell_id or cell_number
        let nb = make_notebook(&json!([
            {"cell_type": "code", "source": "x", "metadata": {}, "outputs": [], "execution_count": null}
        ]));
        let (_f, path) = tmp_notebook(&nb);
        let mut args = HashMap::new();
        args.insert("notebook_path".to_string(), json!(&path));
        args.insert("new_source".to_string(), json!("y"));
        args.insert("edit_mode".to_string(), json!("replace"));
        add_expected_snapshot(&mut args, &path);
        let (msg, is_err) = execute_notebook_edit(test_run(), &args);
        assert!(is_err, "replace without locator must error: {msg}");
        assert!(msg.contains("replace requires"), "message: {msg}");
    }

    // =========================================================================
    // Behavior 7: out-of-bounds replace → error (NOT silent promote to insert)
    // =========================================================================

    #[test]
    fn notebook_replace_at_len_without_cell_type_errors() {
        // crosslink #704: index == cells.len() is now promoted to an
        // append-at-end insert (CC parity), but the promotion requires
        // `cell_type` because the new cell needs a kind. Without it the
        // tool returns an error pointing at the missing field — the file
        // must NOT be mutated.
        let nb = make_notebook(&json!([
            {"cell_type": "code", "source": "only", "metadata": {}, "outputs": [], "execution_count": null}
        ]));
        let (_f, path) = tmp_notebook(&nb);
        // cell_number = 1 but there is only 1 cell (index 0)
        let args = args_replace_by_number(&path, 1, "oob");
        let (msg, is_err) = execute_notebook_edit(test_run(), &args);
        assert!(
            is_err,
            "replace at index == len without cell_type must error: {msg}"
        );
        assert!(
            msg.contains("cell_type"),
            "message should mention the missing cell_type: {msg}"
        );
        // File must be unchanged
        let cells = read_cells(&path);
        assert_eq!(cells.len(), 1, "cell count unchanged");
    }

    #[test]
    fn notebook_replace_at_len_with_cell_type_appends() {
        // crosslink #704: index == cells.len() with cell_type silently
        // promotes to an insert-at-end (CC parity).
        let nb = make_notebook(&json!([
            {"cell_type": "code", "source": "only", "metadata": {}, "outputs": [], "execution_count": null}
        ]));
        let (_f, path) = tmp_notebook(&nb);
        let mut args = args_replace_by_number(&path, 1, "appended via replace");
        args.insert("cell_type".to_string(), json!("markdown"));
        let (msg, is_err) = execute_notebook_edit(test_run(), &args);
        assert!(!is_err, "replace at len with cell_type must succeed: {msg}");
        let cells = read_cells(&path);
        assert_eq!(cells.len(), 2, "cell appended at end");
        assert_eq!(cells[1]["cell_type"], json!("markdown"));
    }

    #[test]
    fn notebook_replace_strictly_past_end_still_errors() {
        // index > cells.len() (strictly past one-past-end) remains a hard
        // out-of-bounds error — only the exact `len()` promotes.
        let nb = make_notebook(&json!([
            {"cell_type": "code", "source": "only", "metadata": {}, "outputs": [], "execution_count": null}
        ]));
        let (_f, path) = tmp_notebook(&nb);
        let mut args = args_replace_by_number(&path, 5, "way past");
        args.insert("cell_type".to_string(), json!("code"));
        let (msg, is_err) = execute_notebook_edit(test_run(), &args);
        assert!(is_err, "replace strictly past end must still error: {msg}");
        assert!(msg.contains("out of bounds"), "message: {msg}");
    }

    // =========================================================================
    // Behavior 7: code cell replace resets stale execution_count/outputs
    // =========================================================================

    #[test]
    fn notebook_replace_code_cell_resets_execution_count_and_outputs() {
        // crosslink #702: a code-cell source replace MUST clear the stale
        // `outputs` array and reset `execution_count` to null. The old
        // outputs describe code that no longer exists; preserving them
        // produces a notebook whose displayed output is from source that's
        // been overwritten.
        let nb = make_notebook(&json!([
            {
                "id": "cell-x",
                "cell_type": "code",
                "source": "print('hello')",
                "metadata": {},
                "outputs": [{"output_type": "stream", "name": "stdout", "text": ["hello\n"]}],
                "execution_count": 3
            }
        ]));
        let (_f, path) = tmp_notebook(&nb);
        let args = args_replace_by_id(&path, "cell-x", "print('world')");
        let (msg, is_err) = execute_notebook_edit(test_run(), &args);
        assert!(!is_err, "replace must succeed: {msg}");
        let cells = read_cells(&path);
        assert_eq!(
            cells[0]["outputs"],
            json!([]),
            "code-cell replace clears stale outputs"
        );
        assert_eq!(
            cells[0]["execution_count"],
            Value::Null,
            "code-cell replace resets execution_count to null"
        );
    }

    #[test]
    fn notebook_replace_markdown_cell_does_not_grow_outputs() {
        // Companion to #702: replacing a markdown cell must NOT grow
        // an `outputs` array (markdown cells don't carry one in nbformat).
        let nb = make_notebook(&json!([
            {
                "id": "md",
                "cell_type": "markdown",
                "source": "# hi",
                "metadata": {}
            }
        ]));
        let (_f, path) = tmp_notebook(&nb);
        let args = args_replace_by_id(&path, "md", "# bye");
        let (msg, is_err) = execute_notebook_edit(test_run(), &args);
        assert!(!is_err, "markdown replace must succeed: {msg}");
        let cells = read_cells(&path);
        assert!(
            cells[0].get("outputs").is_none(),
            "markdown cell must not carry an outputs field"
        );
        assert!(
            cells[0].get("execution_count").is_none(),
            "markdown cell must not carry an execution_count field"
        );
    }

    #[test]
    fn notebook_replace_markdown_as_code_removes_attachments_and_resets_execution_state() {
        let nb = make_notebook(&json!([{
            "id": "convert",
            "cell_type": "markdown",
            "source": "![plot](attachment:plot.png)",
            "metadata": {"keep": true},
            "attachments": {"plot.png": {"image/png": "AA=="}}
        }]));
        let (_file, path) = tmp_notebook(&nb);
        let mut args = args_replace_by_id(&path, "convert", "print('converted')");
        args.insert("cell_type".to_string(), json!("code"));

        let (message, is_error) = execute_notebook_edit(test_run(), &args);
        assert!(!is_error, "cell conversion must succeed: {message}");
        let cells = read_cells(&path);
        assert_eq!(cells[0]["cell_type"], "code");
        assert!(cells[0].get("attachments").is_none());
        assert_eq!(cells[0]["metadata"]["keep"], true);
        assert_eq!(cells[0]["outputs"], json!([]));
        assert_eq!(cells[0]["execution_count"], Value::Null);
    }

    // =========================================================================
    // Behavior 7: insert — no cell_id inserts at position 0
    // =========================================================================

    #[test]
    fn notebook_insert_without_cell_id_inserts_at_position_zero() {
        // Behavior 7 edge: omitting both cell_id and cell_number on insert → position 0
        let nb = make_notebook(&json!([
            {"cell_type": "code", "source": "existing", "metadata": {}, "outputs": [], "execution_count": null}
        ]));
        let (_f, path) = tmp_notebook(&nb);
        let args = args_insert(&path, None, None, "markdown", "# new first");
        let (msg, is_err) = execute_notebook_edit(test_run(), &args);
        assert!(!is_err, "insert at 0 must succeed: {msg}");
        let cells = read_cells(&path);
        assert_eq!(cells.len(), 2, "cell count grew by 1");
        let first_src: String = match &cells[0]["source"] {
            Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
            Value::String(s) => s.clone(),
            _ => panic!(),
        };
        assert!(first_src.contains("# new first"), "new cell at position 0");
    }

    #[test]
    fn notebook_insert_after_cell_id_inserts_at_next_position() {
        // Behavior 7: insert with cell_id means "insert AFTER" that cell
        let nb = make_notebook(&json!([
            {"id": "first", "cell_type": "code", "source": "a", "metadata": {}, "outputs": [], "execution_count": null},
            {"id": "second", "cell_type": "code", "source": "b", "metadata": {}, "outputs": [], "execution_count": null}
        ]));
        let (_f, path) = tmp_notebook(&nb);
        let args = args_insert(&path, Some("first"), None, "markdown", "inserted");
        let (msg, is_err) = execute_notebook_edit(test_run(), &args);
        assert!(!is_err, "insert after cell must succeed: {msg}");
        let cells = read_cells(&path);
        assert_eq!(cells.len(), 3, "cell count");
        let mid_src: String = match &cells[1]["source"] {
            Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
            Value::String(s) => s.clone(),
            _ => panic!(),
        };
        assert!(mid_src.contains("inserted"), "inserted cell at index 1");
    }

    // =========================================================================
    // Behavior 7: delete by cell_id
    // =========================================================================

    #[test]
    fn notebook_delete_by_cell_id_removes_correct_cell() {
        let nb = make_notebook(&json!([
            {"id": "keep", "cell_type": "code", "source": "keep me", "metadata": {}, "outputs": [], "execution_count": null},
            {"id": "remove", "cell_type": "code", "source": "remove me", "metadata": {}, "outputs": [], "execution_count": null}
        ]));
        let (_f, path) = tmp_notebook(&nb);
        let args = args_delete_by_id(&path, "remove");
        let (msg, is_err) = execute_notebook_edit(test_run(), &args);
        assert!(!is_err, "delete must succeed: {msg}");
        let cells = read_cells(&path);
        assert_eq!(cells.len(), 1, "one cell remains");
        let src: String = match &cells[0]["source"] {
            Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
            Value::String(s) => s.clone(),
            _ => panic!(),
        };
        assert!(src.contains("keep me"), "correct cell remains");
    }

    // =========================================================================
    // Behavior 7 / error path: invalid JSON notebook
    // =========================================================================

    #[test]
    fn notebook_invalid_json_returns_error() {
        // Behavior 7 error path: invalid JSON → error (both CC and OC agree)
        let mut f = NamedTempFile::new_in(".").expect("tempfile");
        f.write_all(b"not valid json {{{{").expect("write");
        let canon = f.path().canonicalize().expect("canon");
        READ_TRACKER.mark_read(test_run(), &canon);
        let path = canon.to_string_lossy().to_string();
        let args = args_replace_by_number(&path, 0, "x");
        let (msg, is_err) = execute_notebook_edit(test_run(), &args);
        assert!(is_err, "invalid JSON must error: {msg}");
        assert!(msg.contains("Failed to parse notebook"), "message: {msg}");
    }

    // =========================================================================
    // Behavior 7 / error path: invalid edit_mode
    // =========================================================================

    #[test]
    fn notebook_invalid_edit_mode_returns_error() {
        let nb = make_notebook(&json!([]));
        let (_f, path) = tmp_notebook(&nb);
        let mut args = HashMap::new();
        args.insert("notebook_path".to_string(), json!(&path));
        args.insert("new_source".to_string(), json!("x"));
        args.insert("edit_mode".to_string(), json!("upsert"));
        let (msg, is_err) = execute_notebook_edit(test_run(), &args);
        assert!(is_err, "invalid edit_mode must error: {msg}");
        assert!(msg.contains("Invalid edit_mode"), "message: {msg}");
    }

    // ===== crosslink #470: cell_number is range-checked, not silently truncated =====

    #[test]
    fn fix470_notebook_cell_number_u64_max_returns_out_of_range_error() {
        // crosslink #470: passing cell_number = u64::MAX previously saturated
        // to usize::MAX via `usize::try_from(n).unwrap_or(usize::MAX)`, then
        // tripped the downstream bounds check with a misleading "out of bounds
        // for a 1-cell notebook" message. The fix uses a checked conversion
        // so the error message names the real cause: an out-of-range index.
        //
        // This test is only meaningful when u64 does not fit in usize (i.e.
        // 32-bit targets). On 64-bit targets the conversion succeeds and we
        // fall through to the existing out-of-bounds path; assert that the
        // file is still unmodified there so the test stays useful under both.
        let nb = make_notebook(&json!([
            {"cell_type": "code", "source": "only", "metadata": {}, "outputs": [], "execution_count": null}
        ]));
        let (_f, path) = tmp_notebook(&nb);
        let args = args_replace_by_number(&path, u64::MAX, "boom");
        let (msg, is_err) = execute_notebook_edit(test_run(), &args);
        assert!(is_err, "u64::MAX cell_number must error: {msg}");
        // On 32-bit: hits the new checked-conversion branch.
        // On 64-bit: hits the existing bounds check (the cast succeeds since
        // u64::MAX fits a 64-bit usize). Either way the error must NOT be a
        // silent success and the file must be untouched.
        if usize::try_from(u64::MAX).is_err() {
            assert!(
                msg.contains("out of range"),
                "32-bit must surface the checked-conversion error: {msg}"
            );
        } else {
            assert!(
                msg.contains("out of bounds"),
                "64-bit must surface the bounds-check error: {msg}"
            );
        }
        let cells = read_cells(&path);
        assert_eq!(cells.len(), 1, "cell count unchanged");
        let src: String = match &cells[0]["source"] {
            Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
            Value::String(s) => s.clone(),
            _ => panic!("unexpected source type"),
        };
        assert_eq!(src, "only", "cell source must be untouched");
    }

    // ===== crosslink #417: notebook_edit rejects symlink-swap on the leaf =====

    #[cfg(any(unix, windows))]
    #[test]
    fn fix417_notebook_rejects_link_at_target() {
        use tempfile::TempDir;
        let dir = TempDir::new_in(".").expect("tempdir");
        let target = dir.path().join("attacker_target.ipynb");
        let nb = make_notebook(&json!([
            {"id": "guarded", "cell_type": "code", "source": "SAFE", "metadata": {}, "outputs": [], "execution_count": null}
        ]));
        std::fs::write(
            &target,
            serde_json::to_string_pretty(&nb).expect("serialize"),
        )
        .expect("setup target");
        let leaf = dir.path().join("leaf.ipynb");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &leaf).expect("symlink");
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&target, &leaf).expect("file reparse point");
        let leaf_canon = leaf.canonicalize().expect("canonicalize leaf");
        READ_TRACKER.mark_read(test_run(), &leaf_canon);
        let args = args_replace_by_id(
            &leaf.to_string_lossy(),
            "guarded",
            "ATTACKER_INJECTED_SOURCE",
        );
        let (msg, is_err) = execute_notebook_edit(test_run(), &args);
        assert!(
            is_err,
            "notebook_edit through a symlink leaf must fail (O_NOFOLLOW): {msg}"
        );
        let after = std::fs::read_to_string(&target).expect("read target");
        assert!(
            after.contains("SAFE"),
            "symlink target must not be overwritten; got: {after}"
        );
        assert!(
            !after.contains("ATTACKER_INJECTED_SOURCE"),
            "injected source must not appear in target"
        );
    }

    #[test]
    fn fix417_notebook_legitimate_edit_still_works() {
        let nb = make_notebook(&json!([
            {"id": "a", "cell_type": "code", "source": "old", "metadata": {}, "outputs": [], "execution_count": null}
        ]));
        let (_f, path) = tmp_notebook(&nb);
        let args = args_replace_by_id(&path, "a", "new");
        let (msg, is_err) = execute_notebook_edit(test_run(), &args);
        assert!(!is_err, "regular notebook edit must succeed: {msg}");
        let cells = read_cells(&path);
        let src: String = match &cells[0]["source"] {
            Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
            Value::String(s) => s.clone(),
            _ => panic!(),
        };
        assert_eq!(src, "new");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn interruption_before_publication_preserves_prior_generation_and_retry_recovers() {
        let _lock = super::super::shared_tracker_lock();
        let dir = TempDir::new_in(".").expect("tempdir");
        let path = dir.path().join("transaction.ipynb");
        let original = make_notebook(&json!([
            {"id": "stable", "cell_type": "code", "source": "old", "metadata": {}, "outputs": [], "execution_count": null}
        ]));
        let original_bytes = serde_json::to_vec_pretty(&original).expect("serialize");
        std::fs::write(&path, &original_bytes).expect("write notebook");
        let canonical = path.canonicalize().expect("canonicalize");
        READ_TRACKER.mark_read(test_run(), &canonical);
        let args = args_replace_by_id(&canonical.to_string_lossy(), "stable", "new");

        super::super::secure_fs::fail_next_atomic_write_before_publish();
        let (message, is_error) = execute_notebook_edit(test_run(), &args);
        assert!(is_error, "injected interruption must fail: {message}");
        assert!(
            message.contains("prior notebook generation remains published"),
            "failure must state recovery semantics: {message}"
        );
        assert_eq!(
            std::fs::read(&path).expect("read after interruption"),
            original_bytes,
            "the published notebook must remain byte-for-byte unchanged"
        );
        assert!(
            std::fs::read_dir(dir.path())
                .expect("read tempdir")
                .filter_map(Result::ok)
                .all(|entry| !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".openclaudia-edit-")),
            "the interrupted staging generation must be cleaned up"
        );

        let (message, is_error) = execute_notebook_edit(test_run(), &args);
        assert!(
            !is_error,
            "retry over the unchanged generation must recover: {message}"
        );
        assert_eq!(
            read_cells(&canonical.to_string_lossy())[0]["source"],
            json!(["new"])
        );
    }
}
