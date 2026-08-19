use base64::Engine;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Read as _;
use std::path::{Path, PathBuf};

/// Hard cap on file size accepted by all read functions.  Prevents OOM via
/// `/dev/zero` and similar unbounded sources.  10 MiB is generous for any
/// text file an agent would realistically need to read in full; callers
/// should use `offset`+`limit` or `grep` for larger artifacts.
pub(super) const MAX_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024;

/// Maximum chars retained in [`read_text_file`] output before truncation
/// at the next line boundary kicks in. crosslink #939.
const READ_TEXT_BUDGET: usize = 100_000;

fn pdftotext_bin(run: &super::super::security::ToolRunContext) -> Result<PathBuf, String> {
    run.resolve_executable("pdftotext")
        .map_err(|error| match error {
            capability @ crate::tools::ToolExecutableError::Capability(_) => capability.to_string(),
            crate::tools::ToolExecutableError::Resolve { .. } => {
                "pdftotext is not installed on the run-bound PATH. Install it with:\n  \
                 Ubuntu/Debian: sudo apt install poppler-utils\n  \
                 macOS: brew install poppler\n  \
                 Fedora: sudo dnf install poppler-utils"
                    .to_string()
            }
        })
}

fn pdfinfo_bin(run: &super::super::security::ToolRunContext) -> Option<PathBuf> {
    run.resolve_executable("pdfinfo").ok()
}

/// Return `(error_message, is_error=true)` if an already-confined open handle
/// is too large or is not a regular file. Authorization and inspection must
/// apply to the same kernel object; checking a pathname here would reopen the
/// TOCTOU window closed by `secure_fs`.
fn check_file_safety(file: &std::fs::File, path: &str) -> Option<(String, bool)> {
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(e) => return Some((format!("Cannot inspect open file '{path}': {e}"), true)),
    };

    if !meta.file_type().is_file() {
        return Some((
            format!(
                "File '{path}' is not a regular file and cannot be read safely. \
                 Directories, devices, FIFOs, and sockets are not file-tool capabilities."
            ),
            true,
        ));
    }

    if meta.len() > MAX_FILE_SIZE_BYTES {
        return Some((
            format!(
                "File '{path}' is too large ({} bytes; cap {MAX_FILE_SIZE_BYTES} bytes). \
                 Use offset+limit for partial read or grep for search.",
                meta.len()
            ),
            true,
        ));
    }

    None
}

fn open_safe_read(
    run: &super::super::security::ToolRunContext,
    path: &str,
) -> Result<std::fs::File, (String, bool)> {
    let file = super::secure_fs::open_regular_read(run, Path::new(path)).map_err(|error| {
        (
            format!("Failed to securely open file '{path}': {error}"),
            true,
        )
    })?;
    if let Some(error) = check_file_safety(&file, path) {
        return Err(error);
    }
    Ok(file)
}

fn read_safe_bytes(
    run: &super::super::security::ToolRunContext,
    path: &str,
) -> Result<Vec<u8>, (String, bool)> {
    let file = open_safe_read(run, path)?;
    let mut bytes = Vec::new();
    file.take(MAX_FILE_SIZE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| (format!("Failed to read file '{path}': {error}"), true))?;
    if bytes.len() > usize::try_from(MAX_FILE_SIZE_BYTES).unwrap_or(usize::MAX) {
        return Err((
            format!(
                "File '{path}' grew beyond the {MAX_FILE_SIZE_BYTES}-byte safety cap while it was being read"
            ),
            true,
        ));
    }
    Ok(bytes)
}

/// Image formats the harness can hand to vision-capable models.
///
/// crosslink #966: this used to live as a raw `&'static str` (the MIME type)
/// inside `FileType::Image`. Adding a new format had to update three
/// independent string literals across `detect_file_type`, `read_image_file`,
/// and any downstream adapter assumption. With a closed enum the type system
/// enforces exhaustiveness — every match arm sees every supported image kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    Png,
    Jpeg,
    Gif,
    Webp,
}

impl ImageKind {
    /// MIME type the `Anthropic` / `OpenAI` / `Google` adapters expect for
    /// this image kind. The mapping lives here so that the [`FileType`]
    /// variant is no longer the carrier of stringly-typed format
    /// information.
    #[must_use]
    pub const fn mime(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Gif => "image/gif",
            Self::Webp => "image/webp",
        }
    }

    /// Map a filename extension (case-insensitive, without the leading dot)
    /// to an `ImageKind`. Returns `None` for unknown / non-image extensions.
    #[must_use]
    pub const fn from_extension(ext: &str) -> Option<Self> {
        if ext.eq_ignore_ascii_case("png") {
            Some(Self::Png)
        } else if ext.eq_ignore_ascii_case("jpg") || ext.eq_ignore_ascii_case("jpeg") {
            Some(Self::Jpeg)
        } else if ext.eq_ignore_ascii_case("gif") {
            Some(Self::Gif)
        } else if ext.eq_ignore_ascii_case("webp") {
            Some(Self::Webp)
        } else {
            None
        }
    }
}

/// Supported file types for `read_file`
pub enum FileType {
    Text,
    Image(ImageKind),
    Pdf,
    Notebook,
}

/// Detect file type from extension
pub fn detect_file_type(path: &str) -> FileType {
    let p = Path::new(path);
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
    ImageKind::from_extension(ext).map_or_else(
        || {
            if ext.eq_ignore_ascii_case("pdf") {
                FileType::Pdf
            } else if ext.eq_ignore_ascii_case("ipynb") {
                FileType::Notebook
            } else {
                FileType::Text
            }
        },
        FileType::Image,
    )
}

/// Read an image file, base64-encode it, and return a structured result.
///
/// The image kind is carried by the typed [`ImageKind`] enum (crosslink #966)
/// rather than as a raw MIME-type `&str`, so callers can no longer fabricate a
/// nonsense MIME like `"image/whatever"` at the call site.
pub fn read_image_file(
    run: &super::super::security::ToolRunContext,
    path: &str,
    kind: ImageKind,
) -> (String, bool) {
    let bytes = match read_safe_bytes(run, path) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };

    // Fail fast at the boundary: a 0-byte image is never valid input for any
    // vision-capable model. Without this check the upstream API rejects the
    // empty base64 with an opaque 400 after we've already burned a turn.
    // crosslink #942.
    if bytes.is_empty() {
        return (
            format!(
                "Image file '{path}' is empty (0 bytes); refusing to send empty base64 payload"
            ),
            true,
        );
    }

    let file_size = bytes.len();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let filename = Path::new(path)
        .file_name()
        .map_or_else(|| path.to_string(), |n| n.to_string_lossy().to_string());

    let mime_type = kind.mime();
    let result = format!(
        "[Image: {filename} ({file_size} bytes, {mime_type}) - base64 data included for vision-capable models]\n{b64}"
    );
    (result, false)
}

/// Parse a page range string like "1-5", "3", or "10-20"
/// Returns (`first_page`, `last_page`) as 1-indexed values
pub fn parse_page_range(pages: &str) -> Result<(u32, u32), String> {
    let pages = pages.trim();
    if let Some((start, end)) = pages.split_once('-') {
        let start: u32 = start
            .trim()
            .parse()
            .map_err(|_| format!("Invalid page range start: '{}'", start.trim()))?;
        let end: u32 = end
            .trim()
            .parse()
            .map_err(|_| format!("Invalid page range end: '{}'", end.trim()))?;
        if start == 0 || end == 0 {
            return Err("Page numbers must be 1 or greater".to_string());
        }
        if start > end {
            return Err(format!("Invalid page range: start ({start}) > end ({end})"));
        }
        Ok((start, end))
    } else {
        let page: u32 = pages
            .parse()
            .map_err(|_| format!("Invalid page number: '{pages}'"))?;
        if page == 0 {
            return Err("Page numbers must be 1 or greater".to_string());
        }
        Ok((page, page))
    }
}

/// Reject file paths whose final component begins with `-`.
///
/// Even with `Command::arg()` (no shell), `pdftotext`/`pdfinfo` still parse
/// their own argv: a file literally named `-help`, `--version`, `-opw`, or
/// `-upw` is interpreted as a flag (some of which consume the *next* argv
/// entry as a password). Rejecting flag-prefixed paths before invocation —
/// combined with the `--` option terminator at the call site — closes that
/// hole. See crosslink #381, #389.
///
/// Returns `Some(error_message)` when the path must be refused, `None` when
/// it is safe to forward.
fn reject_flag_prefix(path: &str) -> Option<String> {
    // We check the path string the caller will hand to the subprocess. If
    // the path itself starts with '-' (e.g. `-help`, `--bad.pdf`), the
    // subprocess sees a flag at argv[1]. Absolute paths (start with `/`)
    // and relative paths starting with `./` are immune.
    if path.starts_with('-') {
        return Some(format!(
            "Refusing to invoke pdftotext/pdfinfo on path '{path}': leading '-' is interpreted \
             as a flag by the subprocess. Pass an absolute path or prefix the relative path \
             with './' (e.g. './{stripped}').",
            stripped = path.trim_start_matches('-')
        ));
    }
    None
}

/// Maximum wall-clock time we allow pdftotext / pdfinfo to run before
/// killing the child. A malformed PDF can pin the parser indefinitely
/// (loops in the `XRef` table, encrypted streams the wrong way around);
/// 30 s is more than any well-formed extraction needs while still
/// bounding the worker thread (crosslink #827).
const PDF_TIMEOUT_SECS: u64 = 30;

/// Read a PDF file using pdftotext.
///
/// # Subprocess hardening
///
/// `pdftotext` and `pdfinfo` are spawned via
/// [`crate::tools::command::run_sandboxed_with_timeout`] with a 30 s deadline so
/// a malformed PDF cannot pin the worker (crosslink #827, #836). Both
/// stdout and stderr are captured (`Stdio::piped`); on a non-zero
/// exit, the stderr tail is included in the error message so the
/// model can react.
///
/// # Locale dependency
///
/// `pdftotext` sees only locale variables explicitly captured in the run's
/// environment grants. It never inherits the process environment at spawn.
/// Operators that need a specific encoding should grant the corresponding
/// `LANG`/`LC_*` value when constructing the top-level run.
pub fn read_pdf_file(
    run: &super::super::security::ToolRunContext,
    path: &str,
    pages: Option<&str>,
) -> (String, bool) {
    // Reject any path the subprocess would parse as a flag BEFORE we spawn.
    if let Some(err) = reject_flag_prefix(path) {
        return (err, true);
    }

    let pdftotext = match pdftotext_bin(run) {
        Ok(path) => path,
        Err(msg) => return (msg, true),
    };
    let project_root = match super::project_root(run) {
        Ok(root) => root,
        Err(message) => return (message, true),
    };
    // Feed the parser bytes read from the already-confined descriptor. Passing
    // the original pathname would let a concurrent rename swap the parser's
    // input after authorization.
    let pdf_bytes = match read_safe_bytes(run, path) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };

    let timeout = std::time::Duration::from_secs(PDF_TIMEOUT_SECS);

    // If no pages specified, check total page count first.
    if pages.is_none() {
        // `--` terminates options so a hostile filename cannot be parsed as a flag
        // (defence-in-depth alongside reject_flag_prefix above).
        let info_args = ["--", "-"];
        if let Some(pdfinfo) = pdfinfo_bin(run) {
            if let Ok(info) = crate::tools::command::run_sandboxed_with_timeout_with_input(
                run,
                &pdfinfo,
                &info_args,
                &project_root,
                timeout,
                &pdf_bytes,
            ) {
                if info.status.success() {
                    let info_text = String::from_utf8_lossy(&info.stdout);
                    for line in info_text.lines() {
                        if line.starts_with("Pages:") {
                            if let Some(count_str) = line.split(':').nth(1) {
                                if let Ok(count) = count_str.trim().parse::<u32>() {
                                    const MAX_PDF_PAGES_WITHOUT_RANGE: u32 = 10;
                                    if count > MAX_PDF_PAGES_WITHOUT_RANGE {
                                        return (
                                            format!(
                                                "PDF has {count} pages. For large PDFs (>{MAX_PDF_PAGES_WITHOUT_RANGE} pages), you must specify \
                                                 a page range using the 'pages' parameter (e.g., '1-5', '3', '10-20')."
                                            ),
                                            true,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Build pdftotext argv.
    // SAFETY: option terminator `--` is placed immediately before the path
    // (and before the stdout `-` sentinel) so neither argv entry can be
    // re-parsed as a flag. See crosslink #381, #389.
    let mut argv: Vec<String> = Vec::new();
    if let Some(pages_str) = pages {
        match parse_page_range(pages_str) {
            Ok((first, last)) => {
                argv.push("-f".to_string());
                argv.push(first.to_string());
                argv.push("-l".to_string());
                argv.push(last.to_string());
            }
            Err(e) => return (format!("Invalid pages parameter: {e}"), true),
        }
    }
    argv.push("--".to_string());
    argv.push("-".to_string()); // stdin, from the confined file descriptor
    argv.push("-".to_string()); // stdout sentinel
    let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();

    match crate::tools::command::run_sandboxed_with_timeout_with_input(
        run,
        &pdftotext,
        &argv_refs,
        &project_root,
        timeout,
        &pdf_bytes,
    ) {
        Ok(output) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return (format!("pdftotext failed for '{path}': {stderr}"), true);
            }
            let text = String::from_utf8_lossy(&output.stdout).to_string();
            if text.trim().is_empty() {
                (
                    format!("PDF '{path}' produced no extractable text (may be image-based)."),
                    false,
                )
            } else {
                (text, false)
            }
        }
        Err(e) => (format!("Failed to run pdftotext on '{path}': {e}"), true),
    }
}

/// Join the string elements of an nbformat "source"/"text"/"traceback" array,
/// emitting a `tracing::warn!` for every non-string element instead of
/// silently dropping it (crosslink #976).
///
/// The prior implementation used `filter_map(Value::as_str)`, which made an
/// `.ipynb` containing a number or object inside a `source` array look
/// truncated to the model — the rest of the cell vanished with no signal.
/// The model then made edits based on an incomplete view of the cell.
///
/// Returns the joined string. The caller decides whether to embed it into
/// the output unconditionally; warnings are surfaced as a side effect on
/// the `tracing` subscriber so test capture and operator logs can both
/// detect the malformed input.
fn join_string_array_with_warn(arr: &[Value], context: &str) -> String {
    let mut out = String::new();
    for (i, v) in arr.iter().enumerate() {
        if let Some(s) = v.as_str() {
            out.push_str(s);
        } else {
            tracing::warn!(
                context = %context,
                index = i,
                kind = ?v,
                "notebook_read: non-string element in array — entry dropped",
            );
        }
    }
    out
}

/// Render a single notebook cell's outputs into `output`. Extracted from
/// `read_notebook_file` to keep that function under the clippy
/// `too_many_lines` budget after the crosslink #976 warn-on-drop
/// hardening expanded each output branch. Handles `stream`,
/// `execute_result`/`display_data`, and `error` cell-output kinds.
fn render_cell_outputs(output: &mut String, outputs: &[Value]) {
    for out in outputs {
        let output_type = out.get("output_type").and_then(|t| t.as_str());
        match output_type {
            Some("stream") => {
                if let Some(text) = out.get("text") {
                    let text_str = match text {
                        Value::Array(arr) => join_string_array_with_warn(arr, "stream.text"),
                        Value::String(s) => s.clone(),
                        _ => {
                            tracing::warn!(
                                kind = ?text,
                                "notebook_read: stream.text is neither array nor string — output skipped",
                            );
                            continue;
                        }
                    };
                    let _ = write!(output, "Output:\n{text_str}\n");
                }
            }
            Some("execute_result" | "display_data") => {
                if let Some(data) = out.get("data") {
                    if let Some(text_plain) = data.get("text/plain") {
                        let text_str = match text_plain {
                            Value::Array(arr) => {
                                join_string_array_with_warn(arr, "data.text/plain")
                            }
                            Value::String(s) => s.clone(),
                            _ => {
                                tracing::warn!(
                                    kind = ?text_plain,
                                    "notebook_read: data.text/plain is neither array nor string — output skipped",
                                );
                                continue;
                            }
                        };
                        let _ = write!(output, "Output:\n{text_str}\n");
                    }
                }
            }
            Some("error") => {
                if let Some(traceback) = out.get("traceback").and_then(|t| t.as_array()) {
                    let mut frames: Vec<String> = Vec::with_capacity(traceback.len());
                    for (i, v) in traceback.iter().enumerate() {
                        if let Some(s) = v.as_str() {
                            frames.push(s.to_string());
                        } else {
                            tracing::warn!(
                                index = i,
                                kind = ?v,
                                "notebook_read: non-string traceback frame — dropped",
                            );
                        }
                    }
                    let _ = write!(output, "Error:\n{}\n", frames.join("\n"));
                }
            }
            _ => {}
        }
    }
}

/// Read a Jupyter notebook (.ipynb) and format cells for display
pub fn read_notebook_file(
    run: &super::super::security::ToolRunContext,
    path: &str,
) -> (String, bool) {
    let mut file = match open_safe_read(run, path) {
        Ok(file) => file,
        Err(error) => return error,
    };
    let content = match super::secure_fs::read_to_string(&mut file, Path::new(path)) {
        Ok(content) => content,
        Err(error) => return (error, true),
    };

    let notebook: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return (
                format!("Failed to parse notebook '{path}' as JSON: {e}"),
                true,
            )
        }
    };

    let Some(cells) = notebook.get("cells").and_then(|c| c.as_array()) else {
        return ("Notebook has no 'cells' array.".to_string(), true);
    };

    let mut output = String::new();
    for (i, cell) in cells.iter().enumerate() {
        let cell_type = cell
            .get("cell_type")
            .and_then(|t| t.as_str())
            .unwrap_or("unknown");

        // Get source - can be a string or array of strings. crosslink #976:
        // warn on non-string array elements instead of silently dropping them.
        let source = match cell.get("source") {
            Some(Value::Array(arr)) => join_string_array_with_warn(arr, "cell.source"),
            Some(Value::String(s)) => s.clone(),
            _ => String::new(),
        };

        let _ = write!(output, "Cell {i} ({cell_type}):\n```\n{source}\n```\n");

        // For code cells, include text outputs (skip binary/image outputs).
        // crosslink #976: warn-on-drop is implemented inside render_cell_outputs.
        if cell_type == "code" {
            if let Some(outputs) = cell.get("outputs").and_then(|o| o.as_array()) {
                render_cell_outputs(&mut output, outputs);
            }
        }
        output.push('\n');
    }

    (output, false)
}
/// Read a plain text file with optional offset/limit
pub fn read_text_file(
    run: &super::super::security::ToolRunContext,
    path: &str,
    args: &HashMap<String, Value>,
) -> (String, bool) {
    // Get optional offset (1-indexed line number to start from)
    let offset = match parse_read_offset_arg(args.get("offset")) {
        Ok(offset) => offset,
        Err(msg) => return (msg, true),
    };

    // Get optional limit (max lines to read)
    let limit = match parse_read_limit_arg(args.get("limit")) {
        Ok(limit) => limit,
        Err(msg) => return (msg, true),
    };

    let mut file = match open_safe_read(run, path) {
        Ok(file) => file,
        Err(error) => return error,
    };
    let file_content = match super::secure_fs::read_to_string(&mut file, Path::new(path)) {
        Ok(content) => content,
        Err(error) => return (error, true),
    };

    let lines: Vec<&str> = file_content.lines().collect();
    let total_lines = lines.len();

    // Apply offset and limit
    let selected_lines: Vec<(usize, &str)> = lines
        .into_iter()
        .enumerate()
        .skip(offset)
        .take(limit.unwrap_or(usize::MAX))
        .collect();

    // Add line numbers (original line numbers, not relative)
    let numbered: Vec<String> = selected_lines
        .iter()
        .map(|(i, line)| format!("{:4}| {}", i + 1, line))
        .collect();

    // Truncate at a *line boundary* so that the last shown line is never
    // a half-line ending mid line-number prefix (`   N|`). crosslink #939.
    // We accumulate lines until adding the next would exceed the budget,
    // then emit a structured `<truncated …/>` sentinel that downstream
    // dispatchers can detect programmatically rather than substring-grepping.
    let total_chars: usize = numbered.iter().map(|line| line.len() + 1).sum();

    // Add context about what was shown (lines actually selected, not lines
    // surviving the byte budget — the truncation sentinel reports that).
    let suffix = if offset > 0 || limit.is_some() {
        let shown_start = offset + 1;
        let shown_end = offset + selected_lines.len();
        format!("\n(showing lines {shown_start}-{shown_end} of {total_lines} total)")
    } else {
        String::new()
    };

    if total_chars > READ_TEXT_BUDGET {
        let mut acc = String::with_capacity(READ_TEXT_BUDGET + 256);
        let mut kept_lines = 0usize;
        let mut kept_chars = 0usize;
        for line in &numbered {
            // `+1` accounts for the join newline we are about to append.
            let next_size = line.len() + 1;
            if kept_chars + next_size > READ_TEXT_BUDGET {
                break;
            }
            if !acc.is_empty() {
                acc.push('\n');
            }
            acc.push_str(line);
            kept_chars += next_size;
            kept_lines += 1;
        }
        let dropped_lines = numbered.len().saturating_sub(kept_lines);
        // Truncation sentinel: structured marker (easy to grep / parse) plus
        // a human-readable hint pointing at offset+limit recovery.
        let sentinel = format!(
            "\n<truncated kept_lines=\"{kept_lines}\" dropped_lines=\"{dropped_lines}\" \
             total_chars=\"{total_chars}\" budget_chars=\"{READ_TEXT_BUDGET}\"/>\n\
             (file truncated at line boundary; retry with offset={} or limit=… to read the rest){suffix}",
            kept_lines + 1
        );
        acc.push_str(&sentinel);
        (acc, false)
    } else {
        let result = numbered.join("\n");
        (format!("{result}{suffix}"), false)
    }
}

fn parse_read_offset_arg(value: Option<&Value>) -> Result<usize, String> {
    let Some(value) = value else {
        return Ok(0);
    };
    let Some(offset) = value.as_u64() else {
        return Err("Error: offset must be a 1-indexed positive integer".to_string());
    };
    if offset == 0 {
        return Err("Error: offset must be a 1-indexed positive integer".to_string());
    }
    Ok(usize::try_from(offset.saturating_sub(1)).unwrap_or(usize::MAX))
}

fn parse_read_limit_arg(value: Option<&Value>) -> Result<Option<usize>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some(limit) = value.as_u64() else {
        return Err("Error: limit must be a positive integer".to_string());
    };
    if limit == 0 {
        return Err("Error: limit must be a positive integer".to_string());
    }
    Ok(Some(usize::try_from(limit).unwrap_or(usize::MAX)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    fn test_run() -> &'static std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context()
    }

    // =========================================================================
    // Behavior 1: read_text_file offset + limit — 1-indexed line slice
    // =========================================================================

    /// Helper: write content to a `NamedTempFile` and return (file, `path_string`).
    fn tmp_text(content: &str) -> (NamedTempFile, String) {
        let mut f = NamedTempFile::new_in(".").expect("tempfile");
        f.write_all(content.as_bytes()).expect("write");
        let path = f.path().to_string_lossy().to_string();
        (f, path)
    }

    #[test]
    fn read_pdf_uses_resolved_poppler_binaries() {
        let source = include_str!("read.rs");
        let cfg_test = source
            .find("#[cfg(test)]")
            .expect("test module marker must be present");
        let production = &source[..cfg_test];

        assert!(
            !production.contains("Command::new(\"which\")")
                && !production.contains("std::process::Command::new(\"which\")"),
            "production PDF reader must not shell out to which"
        );
        assert!(
            !production.contains("run_with_timeout(\"pdftotext\"")
                && !production.contains("run_with_timeout(\"pdfinfo\""),
            "production PDF reader must pass resolved Poppler binary paths to run_with_timeout"
        );
        assert!(
            production.contains("run.resolve_executable(\"pdftotext\")"),
            "pdftotext availability must use the run-bound resolver"
        );
    }

    #[test]
    fn read_text_no_offset_returns_all_lines() {
        // Behavior 1: without offset/limit every line is returned
        let (_f, path) = tmp_text("alpha\nbeta\ngamma\n");
        let args = HashMap::new();
        let (output, is_err) = read_text_file(test_run(), &path, &args);
        assert!(!is_err);
        assert!(output.contains("alpha"));
        assert!(output.contains("beta"));
        assert!(output.contains("gamma"));
        // No suffix when neither offset nor limit is given
        assert!(
            !output.contains("showing lines"),
            "no suffix without offset/limit"
        );
    }

    #[test]
    fn read_text_offset_1_is_first_line() {
        // Behavior 1: offset=1 means start at line 1 (no skip)
        let (_f, path) = tmp_text("first\nsecond\nthird\n");
        let mut args = HashMap::new();
        args.insert("offset".to_string(), serde_json::json!(1u64));
        let (output, is_err) = read_text_file(test_run(), &path, &args);
        assert!(!is_err);
        assert!(output.contains("first"), "offset=1 must include line 1");
    }

    #[test]
    fn read_text_offset_and_limit_returns_correct_slice() {
        // Behavior 1: offset=2,limit=1 returns only line 2
        let (_f, path) = tmp_text("line1\nline2\nline3\n");
        let mut args = HashMap::new();
        args.insert("offset".to_string(), serde_json::json!(2u64));
        args.insert("limit".to_string(), serde_json::json!(1u64));
        let (output, is_err) = read_text_file(test_run(), &path, &args);
        assert!(!is_err);
        assert!(output.contains("line2"), "must include line 2");
        assert!(!output.contains("line1"), "must not include line 1");
        assert!(!output.contains("line3"), "must not include line 3");
        // Suffix is present when offset/limit used
        assert!(output.contains("showing lines 2-2 of 3 total"));
    }

    #[test]
    fn read_text_line_numbers_use_original_numbering() {
        // Behavior 1: line numbers in output are 1-indexed originals, not relative
        let (_f, path) = tmp_text("aaa\nbbb\nccc\n");
        let mut args = HashMap::new();
        args.insert("offset".to_string(), serde_json::json!(2u64));
        args.insert("limit".to_string(), serde_json::json!(2u64));
        let (output, is_err) = read_text_file(test_run(), &path, &args);
        assert!(!is_err);
        // Line 2 ("bbb") must be labeled with "2|" and line 3 with "3|"
        assert!(output.contains("2|"), "line 2 label present: {output}");
        assert!(output.contains("3|"), "line 3 label present: {output}");
        assert!(
            !output.contains("1|"),
            "line 1 label must be absent: {output}"
        );
    }

    #[test]
    fn read_text_offset_zero_returns_validation_error() {
        let (_f, path) = tmp_text("alpha\nbeta\n");
        let mut args = HashMap::new();
        args.insert("offset".to_string(), serde_json::json!(0u64));
        let (output, is_err) = read_text_file(test_run(), &path, &args);
        assert!(is_err);
        assert!(
            output.contains("offset") && output.contains("1-indexed"),
            "offset=0 must fail with a clear contract error; got: {output}"
        );
    }

    #[test]
    fn read_text_offset_beyond_eof_returns_empty_body() {
        // Behavior 1 edge: offset beyond end → empty body, suffix present
        let (_f, path) = tmp_text("one\ntwo\n");
        let mut args = HashMap::new();
        args.insert("offset".to_string(), serde_json::json!(99u64));
        let (output, is_err) = read_text_file(test_run(), &path, &args);
        assert!(!is_err, "not an error — just empty content");
        // The body before the suffix is empty; suffix shows 0 selected lines.
        // OC does NOT emit a "file has fewer lines" warning here (CC does).
        // Pinned as current OC behavior; CC parity tracked via issue #525 edge-case.
        assert!(
            output.contains("showing lines"),
            "suffix must be present: {output}"
        );
        assert!(!output.contains("one"), "line 1 must be absent");
    }

    #[test]
    fn read_text_limit_zero_returns_validation_error() {
        let (_f, path) = tmp_text("data\n");
        let mut args = HashMap::new();
        args.insert("limit".to_string(), serde_json::json!(0u64));
        let (output, is_err) = read_text_file(test_run(), &path, &args);
        assert!(is_err);
        assert!(
            output.contains("limit") && output.contains("positive"),
            "limit=0 must fail with a clear contract error; got: {output}"
        );
    }

    #[test]
    fn read_text_missing_file_returns_error() {
        // Keep the nonexistent fixture inside the readable capability so this
        // exercises secure-open ENOENT rather than the outer capability gate.
        let path = std::env::current_dir()
            .expect("cwd")
            .join("__oc_test_does_not_exist_xyz.txt");
        let args = HashMap::new();
        let (output, is_err) = read_text_file(test_run(), &path.to_string_lossy(), &args);
        assert!(is_err);
        assert!(
            output.contains("does not exist") || output.contains("securely open"),
            "error message: {output}"
        );
    }

    // =========================================================================
    // Behavior 2: read_image_file — base64 encode, empty image edge case
    // =========================================================================

    #[test]
    fn read_image_returns_base64_text_block() {
        // Behavior 2: OC returns a plain-text string with base64 inline
        // (not a structured image block — CC parity gap, pinned as current behavior).
        let mut f = NamedTempFile::new_in(".").expect("tempfile");
        // Minimal valid PNG bytes (1×1 red pixel)
        let minimal_png: &[u8] = &[
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // signature
            0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, // IHDR length + type
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1
            0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, // bit depth, color type, ...
            0xde, 0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41, // IDAT length + type
            0x54, 0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0x00, // IDAT data
            0x00, 0x00, 0x02, 0x00, 0x01, 0xe2, 0x21, 0xbc, // ...
            0x33, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, // IEND
            0x44, 0xae, 0x42, 0x60, 0x82,
        ];
        f.write_all(minimal_png).expect("write png");
        let path = f.path().to_string_lossy().to_string();
        let (output, is_err) = read_image_file(test_run(), &path, ImageKind::Png);
        assert!(!is_err);
        assert!(output.contains("[Image:"), "header line present: {output}");
        assert!(output.contains("image/png"), "mime type present");
        assert!(output.contains("bytes"), "byte count present");
        // base64 data follows the header line
        assert!(output.len() > 50, "output non-trivial");
    }

    #[test]
    fn read_image_empty_file_returns_error() {
        // Behavior 2 edge: empty image file is rejected at the boundary
        // (crosslink #942 — previously OC accepted 0-byte images and let the
        // upstream vision API reject the empty base64 after a turn was burned).
        let f = NamedTempFile::new_in(".").expect("tempfile");
        // Write nothing — file is 0 bytes
        let path = f.path().to_string_lossy().to_string();
        let (output, is_err) = read_image_file(test_run(), &path, ImageKind::Png);
        assert!(is_err, "0-byte image must be a structured error: {output}");
        assert!(
            output.contains("empty") && output.contains("0 bytes"),
            "error message must name the failure mode: {output}"
        );
    }

    #[test]
    fn read_image_nonexistent_returns_error() {
        let path = std::env::current_dir()
            .expect("cwd")
            .join("__oc_no_such_image.png");
        let (output, is_err) = read_image_file(test_run(), &path.to_string_lossy(), ImageKind::Png);
        assert!(is_err);
        assert!(
            output.contains("does not exist") || output.contains("securely open"),
            "error message: {output}"
        );
    }

    // =========================================================================
    // Behavior 3: parse_page_range — PDF page range parsing
    // =========================================================================

    #[test]
    fn parse_page_range_single_page() {
        // Behavior 3 edge: single page "3" → (3, 3) — matches CC semantics
        let r = parse_page_range("3").expect("valid");
        assert_eq!(r, (3, 3));
    }

    #[test]
    fn parse_page_range_range() {
        // Behavior 3: "1-5" → (1, 5)
        let r = parse_page_range("1-5").expect("valid");
        assert_eq!(r, (1, 5));
    }

    #[test]
    fn parse_page_range_with_whitespace() {
        // Behavior 3: leading/trailing whitespace is trimmed
        let r = parse_page_range(" 2 - 4 ").expect("valid");
        assert_eq!(r, (2, 4));
    }

    #[test]
    fn parse_page_range_page_zero_is_error() {
        // Behavior 3 edge: page 0 is not valid (1-indexed)
        let r = parse_page_range("0");
        assert!(r.is_err(), "page 0 must be rejected");
    }

    #[test]
    fn parse_page_range_inverted_range_is_error() {
        // Behavior 3 edge: start > end must be rejected
        let r = parse_page_range("5-2");
        assert!(r.is_err(), "5-2 must be rejected");
    }

    #[test]
    fn parse_page_range_non_numeric_is_error() {
        let r = parse_page_range("abc");
        assert!(r.is_err());
    }

    // =========================================================================
    // Behavior 8: truncation — silent non-error truncation at 100 000 chars
    // =========================================================================

    #[test]
    fn read_text_large_file_truncated_as_non_error() {
        // Behavior 8: large files are truncated at a *line boundary* (crosslink
        // #939) and tagged with a structured <truncated …/> sentinel that the
        // dispatcher can detect programmatically. The truncation itself is not
        // surfaced as an error — the caller is told how to recover via offset.
        let line = "x".repeat(200) + "\n"; // 201 chars per line
                                           // Need > 100_000 chars in the numbered output: with "   N| " prefix (~7 chars)
                                           // each line becomes ~208 chars; 600 lines = ~124 800 chars → triggers truncation.
        let content = line.repeat(600);
        let mut f = NamedTempFile::new_in(".").expect("tempfile");
        f.write_all(content.as_bytes()).expect("write");
        let path = f.path().to_string_lossy().to_string();
        let args = HashMap::new();
        let (output, is_err) = read_text_file(test_run(), &path, &args);
        assert!(
            !is_err,
            "truncation is not an error — the sentinel signals it: {output}"
        );
        assert!(
            output.contains("<truncated"),
            "structured truncation sentinel must be present: {output}"
        );
        assert!(
            output.contains("file truncated at line boundary"),
            "human-readable retry hint must be present: {output}"
        );
        // The kept body is bounded by the budget; the only thing past 100_000
        // chars should be the sentinel + retry hint (a few hundred bytes).
        assert!(
            output.len() < 100_000 + 1024,
            "kept body must respect the budget, only the sentinel exceeds it: {} bytes",
            output.len()
        );
    }

    #[test]
    fn read_text_within_cap_not_truncated() {
        // Behavior 8: files under the 100 000-char cap are returned in full
        let (_f, path) = tmp_text("short line\n");
        let args = HashMap::new();
        let (output, is_err) = read_text_file(test_run(), &path, &args);
        assert!(!is_err);
        assert!(
            !output.contains("file truncated"),
            "no truncation note for small files"
        );
    }

    // =========================================================================
    // Behavior 9: MAX_FILE_SIZE_BYTES — OOM-safe size cap (#288)
    // =========================================================================

    /// Helper: write `size` bytes of 'a' to a temp file.
    fn tmp_sized(size: usize) -> (NamedTempFile, String) {
        let mut f = NamedTempFile::new_in(".").expect("tempfile");
        let buf = vec![b'a'; size];
        f.write_all(&buf).expect("write");
        let path = f.path().to_string_lossy().to_string();
        (f, path)
    }

    #[test]
    fn read_text_oversize_file_is_rejected_with_actionable_error() {
        // Behavior 9: file exceeding MAX_FILE_SIZE_BYTES (10 MiB) is rejected.
        // The error message must mention "too large" so the caller can act on it.
        let size = (10 * 1024 * 1024) + 1; // 1 byte over the cap
        let (_f, path) = tmp_sized(size);
        let args = HashMap::new();
        let (output, is_err) = read_text_file(test_run(), &path, &args);
        assert!(is_err, "oversized file must be an error: {output}");
        assert!(
            output.contains("too large"),
            "error must mention 'too large': {output}"
        );
    }

    #[test]
    fn read_text_small_file_reads_cleanly() {
        // Behavior 9: files well under the cap go through the bounded read path
        // without any error or spurious truncation note.
        let (_f, path) = tmp_text("hello world\n");
        let args = HashMap::new();
        let (output, is_err) = read_text_file(test_run(), &path, &args);
        assert!(!is_err, "small file must succeed: {output}");
        assert!(output.contains("hello world"), "content present: {output}");
    }

    #[test]
    fn read_text_empty_file_is_ok() {
        // Behavior 9 edge: zero-byte regular file — not a device, not oversized.
        // Must succeed with an empty body.
        let f = NamedTempFile::new_in(".").expect("tempfile");
        let path = f.path().to_string_lossy().to_string();
        let args = HashMap::new();
        let (output, is_err) = read_text_file(test_run(), &path, &args);
        assert!(!is_err, "empty file must not be an error: {output}");
    }

    #[cfg(unix)]
    #[test]
    fn read_text_device_outside_capability_is_rejected() {
        // Devices are never session file capabilities. The outer capability
        // check should reject /dev before the implementation can open it.
        let args = HashMap::new();
        let (output, is_err) = read_text_file(test_run(), "/dev/null", &args);
        assert!(is_err, "/dev/null (char device) must be rejected: {output}");
        assert!(
            output.contains("outside the session") || output.contains("not a regular file"),
            "error must explain the capability/type denial: {output}"
        );
    }

    // =========================================================================
    // Behavior 10: pdftotext/pdfinfo flag-injection hardening (#381, #389)
    // =========================================================================
    //
    // pdftotext and pdfinfo parse their OWN argv even when invoked via
    // Command::arg() (no shell). A file named '-help', '--version', '-opw',
    // or '-upw' is interpreted as a flag. Defence is two-layered:
    //   1. reject_flag_prefix() refuses any path starting with '-' BEFORE spawn.
    //   2. an explicit '--' option terminator is placed before the path arg.
    // These tests pin both layers.

    #[test]
    fn reject_flag_prefix_rejects_single_dash_filename() {
        // Layer 1: a bare file named '-help' must be refused.
        let err = reject_flag_prefix("-help").expect("must reject -help");
        assert!(
            err.contains("leading '-'"),
            "error must explain the cause: {err}"
        );
        assert!(
            err.contains("./") || err.contains("absolute"),
            "error must point at the remediation: {err}"
        );
    }

    #[test]
    fn reject_flag_prefix_rejects_double_dash_filename() {
        // Layer 1: '--version' would print version and skip extraction.
        let err = reject_flag_prefix("--version").expect("must reject --version");
        assert!(err.contains("--version"), "error mentions path: {err}");
    }

    #[test]
    fn reject_flag_prefix_rejects_password_flag_filename() {
        // Layer 1: '-opw' (owner password) and '-upw' (user password) consume
        // the NEXT argv entry — the most dangerous shape. Must be refused.
        assert!(
            reject_flag_prefix("-opw").is_some(),
            "owner-password flag name must be rejected"
        );
        assert!(
            reject_flag_prefix("-upw").is_some(),
            "user-password flag name must be rejected"
        );
    }

    #[test]
    fn reject_flag_prefix_accepts_absolute_path() {
        // Layer 1 positive: an absolute path is immune (starts with '/').
        assert!(
            reject_flag_prefix("/tmp/normal.pdf").is_none(),
            "absolute path must pass"
        );
    }

    #[test]
    fn reject_flag_prefix_accepts_dot_slash_relative_path() {
        // Layer 1 positive: explicitly-anchored relative path is safe.
        assert!(
            reject_flag_prefix("./doc.pdf").is_none(),
            "./relative path must pass"
        );
        assert!(
            reject_flag_prefix("subdir/doc.pdf").is_none(),
            "plain relative path must pass"
        );
    }

    #[test]
    fn read_pdf_file_rejects_leading_hyphen_filename() {
        // Layer 1 end-to-end: read_pdf_file must surface the rejection BEFORE
        // any subprocess is spawned (so the test does not depend on poppler
        // being installed). A leading-hyphen path is returned as is_error=true.
        let (output, is_err) = read_pdf_file(test_run(), "-help", None);
        assert!(is_err, "leading-hyphen path must be an error: {output}");
        assert!(
            output.contains("leading '-'") || output.contains("interpreted as a flag"),
            "error must explain why: {output}"
        );
    }

    #[test]
    fn read_pdf_file_rejects_password_flag_filename_with_pages() {
        // Layer 1 end-to-end: rejection must happen on the page-range path too,
        // not only on the no-pages branch. '-opw' is the highest-risk shape.
        let (output, is_err) = read_pdf_file(test_run(), "-opw", Some("1-3"));
        assert!(is_err, "must reject '-opw' even with pages: {output}");
        assert!(
            output.contains("leading '-'") || output.contains("interpreted as a flag"),
            "error must explain why: {output}"
        );
    }

    #[test]
    fn read_pdf_file_uses_double_dash_terminator_in_source() {
        // Layer 2: the source file must place an explicit '--' option terminator
        // immediately before the path arg in BOTH the pdfinfo and the pdftotext
        // invocation. We assert this by inspecting the source rather than
        // shelling out to poppler (which may not be installed in CI). This pins
        // the defence-in-depth invariant against accidental regression.
        //
        // Crosslink #827 / #836: pdf-reader subprocess invocations now route
        // through `crate::tools::command::run_with_timeout` with an explicit
        // argv. The terminator still leads the path; the source-level shape
        // changed from `cmd.arg("--").arg(path)` to a `[..., "--", path, ...]`
        // slice literal pushed into the argv vector.
        let source = include_str!("read.rs");
        // pdfinfo invocation builds `let info_args = ["--", path];` then calls
        // run_with_timeout("pdfinfo", &info_args, …).
        assert!(
            source.contains("let info_args = [\"--\", path];"),
            "pdfinfo invocation must build argv with '--' immediately before path"
        );
        // pdftotext invocation pushes a literal "--" String to argv before path.
        assert!(
            source.contains("argv.push(\"--\".to_string());"),
            "pdftotext argv must place '--' option terminator before the path"
        );
    }
}
