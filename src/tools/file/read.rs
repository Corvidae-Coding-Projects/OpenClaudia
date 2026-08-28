use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};

/// Hard cap for read modes that materialize the complete file in memory.
/// Text and binary reads use the bounded paged path below instead.
pub(super) const MAX_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024;

/// Maximum source bytes represented by one text or binary page. Provider
/// envelopes add metadata and line prefixes on top of this source budget.
const READ_PAGE_BYTES: usize = 64 * 1024;
const READ_TEXT_RENDER_BUDGET: usize = 96 * 1024;

/// Streaming reads are memory bounded, but still need a realistic time/I/O
/// ceiling so a model cannot make the harness hash a multi-terabyte artifact
/// twice. Files below this ceiling remain usable even though the legacy path
/// rejected everything above 10 MiB.
const MAX_PAGED_FILE_BYTES: u64 = 1024 * 1024 * 1024;

const READ_SCAN_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum StablePageContent {
    Text {
        text: String,
        start_line: u64,
        start_column_bytes: u64,
        end_line: u64,
        end_column_bytes: u64,
    },
    Binary(Vec<u8>),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct StableReadPage {
    pub generation: crate::runtime::ContentDigest,
    pub total_bytes: u64,
    pub byte_start: u64,
    pub byte_end: u64,
    pub next_cursor: Option<String>,
    pub content: StablePageContent,
}

struct Utf8StreamValidator {
    pending: Vec<u8>,
    invalid: bool,
}

impl Utf8StreamValidator {
    fn new() -> Self {
        Self {
            pending: Vec::with_capacity(4),
            invalid: false,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        if self.invalid {
            return;
        }
        let mut combined = Vec::with_capacity(self.pending.len().saturating_add(bytes.len()));
        combined.extend_from_slice(&self.pending);
        combined.extend_from_slice(bytes);
        self.pending.clear();
        if let Err(error) = std::str::from_utf8(&combined) {
            if error.error_len().is_some() {
                self.invalid = true;
            } else {
                self.pending
                    .extend_from_slice(&combined[error.valid_up_to()..]);
            }
        }
    }

    const fn is_valid(&self) -> bool {
        !self.invalid && self.pending.is_empty()
    }
}

#[derive(Clone, Copy)]
enum ReadStart {
    Line(u64),
    Byte(u64),
}

struct FileInspection {
    generation: crate::runtime::ContentDigest,
    total_bytes: u64,
    start_byte: u64,
    start_line: u64,
    start_column_bytes: u64,
    utf8: bool,
}

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
#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
pub(super) fn read_safe_bytes(
    run: &super::super::security::ToolRunContext,
    path: &str,
) -> Result<Vec<u8>, (String, bool)> {
    let mut file = open_safe_read(run, path)?;
    super::secure_fs::read_stable_bounded_bytes(
        &mut file,
        Path::new(path),
        usize::try_from(MAX_FILE_SIZE_BYTES).unwrap_or(usize::MAX),
    )
    .map_err(|error| (error, true))
}

fn read_failure(
    code: crate::tools::ToolFailureCode,
    message: impl Into<String>,
    retryability: crate::tools::ToolRetryability,
) -> crate::tools::ToolFailure {
    crate::tools::ToolFailure::new(code, message.into(), retryability)
}

fn parse_positive_u64(
    name: &str,
    value: Option<&Value>,
) -> Result<Option<u64>, crate::tools::ToolFailure> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some(value) = value.as_u64().filter(|value| *value > 0) else {
        let qualifier = if name == "offset" { " (1-indexed)" } else { "" };
        return Err(read_failure(
            crate::tools::ToolFailureCode::InvalidArguments,
            format!("'{name}' must be a positive integer{qualifier}"),
            crate::tools::ToolRetryability::Never,
        ));
    };
    Ok(Some(value))
}

fn digest_from_hasher(hasher: Sha256) -> crate::runtime::ContentDigest {
    crate::runtime::ContentDigest::from_sha256_bytes(hasher.finalize().into())
}

// Keeping hashing, UTF-8 validation, and line-position accounting in one scan
// makes the byte offsets auditable and avoids another pass over large files.
#[allow(clippy::too_many_lines)]
fn inspect_paged_file(
    file: &mut std::fs::File,
    path: &Path,
    start: ReadStart,
) -> Result<FileInspection, crate::tools::ToolFailure> {
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        read_failure(
            crate::tools::ToolFailureCode::External,
            format!("Failed to seek '{}': {error}", path.display()),
            crate::tools::ToolRetryability::Safe,
        )
    })?;
    let mut hasher = Sha256::new();
    let mut validator = Utf8StreamValidator::new();
    let mut buffer = vec![0_u8; READ_SCAN_BUFFER_BYTES];
    let mut total_bytes = 0_u64;
    let mut newline_count = 0_u64;
    let mut last_byte = None;
    let mut start_byte = match start {
        ReadStart::Line(1) => Some(0),
        ReadStart::Line(_) => None,
        ReadStart::Byte(byte) => Some(byte),
    };
    let mut byte_start_line = 1_u64;
    let mut byte_start_column = 0_u64;
    let requested_byte = match start {
        ReadStart::Byte(byte) => Some(byte),
        ReadStart::Line(_) => None,
    };
    let requested_line = match start {
        ReadStart::Line(line) => Some(line),
        ReadStart::Byte(_) => None,
    };
    let mut byte_at_start = None;

    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            read_failure(
                crate::tools::ToolFailureCode::External,
                format!("Failed to read '{}': {error}", path.display()),
                crate::tools::ToolRetryability::Safe,
            )
        })?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        hasher.update(chunk);
        validator.push(chunk);
        for (index, byte) in chunk.iter().copied().enumerate() {
            let position = total_bytes.saturating_add(u64::try_from(index).unwrap_or(u64::MAX));
            if requested_byte == Some(position) {
                byte_at_start = Some(byte);
            }
            if requested_byte.is_some_and(|requested| position < requested) {
                if byte == b'\n' {
                    byte_start_line = byte_start_line.saturating_add(1);
                    byte_start_column = 0;
                } else {
                    byte_start_column = byte_start_column.saturating_add(1);
                }
            }
            if byte == b'\n' {
                newline_count = newline_count.saturating_add(1);
                if requested_line.is_some_and(|line| newline_count == line.saturating_sub(1)) {
                    start_byte = Some(position.saturating_add(1));
                }
            }
            last_byte = Some(byte);
        }
        total_bytes = total_bytes.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
    }

    let total_lines = if total_bytes == 0 {
        0
    } else if last_byte == Some(b'\n') {
        newline_count
    } else {
        newline_count.saturating_add(1)
    };
    if let Some(line) = requested_line {
        if line != 1 && line > total_lines {
            // Preserve the established line-window contract: an explicit
            // offset beyond EOF is an empty successful page, not a failure.
            start_byte = Some(total_bytes);
        }
    }
    let start_byte = start_byte.ok_or_else(|| {
        read_failure(
            crate::tools::ToolFailureCode::InvalidInput,
            "Requested line could not be resolved in the file",
            crate::tools::ToolRetryability::Never,
        )
    })?;
    if start_byte > total_bytes
        || matches!(start, ReadStart::Byte(_) if total_bytes > 0 && start_byte == total_bytes)
    {
        return Err(read_failure(
            crate::tools::ToolFailureCode::InvalidInput,
            format!("Read cursor byte {start_byte} is at or beyond end of file"),
            crate::tools::ToolRetryability::Never,
        ));
    }
    let utf8 = validator.is_valid();
    if utf8 && byte_at_start.is_some_and(|byte| byte & 0b1100_0000 == 0b1000_0000) {
        return Err(read_failure(
            crate::tools::ToolFailureCode::InvalidArguments,
            "Read cursor does not point to a UTF-8 code-point boundary",
            crate::tools::ToolRetryability::Never,
        ));
    }
    let (start_line, start_column_bytes) = match start {
        ReadStart::Line(line) => (line, 0),
        ReadStart::Byte(_) => (byte_start_line, byte_start_column),
    };
    Ok(FileInspection {
        generation: digest_from_hasher(hasher),
        total_bytes,
        start_byte,
        start_line,
        start_column_bytes,
        utf8,
    })
}

fn scan_page_and_digest(
    file: &mut std::fs::File,
    path: &Path,
    inspection: &FileInspection,
    line_limit: Option<u64>,
) -> Result<(crate::runtime::ContentDigest, Vec<u8>), crate::tools::ToolFailure> {
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        read_failure(
            crate::tools::ToolFailureCode::External,
            format!("Failed to seek '{}': {error}", path.display()),
            crate::tools::ToolRetryability::Safe,
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; READ_SCAN_BUFFER_BYTES];
    let mut absolute = 0_u64;
    let mut collected = Vec::with_capacity(READ_PAGE_BYTES.saturating_add(4));
    let mut completed_lines = 0_u64;
    let mut line_boundary = None;
    let collect_ceiling = if inspection.utf8 {
        READ_PAGE_BYTES.saturating_add(3)
    } else {
        READ_PAGE_BYTES
    };

    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            read_failure(
                crate::tools::ToolFailureCode::External,
                format!("Failed to read '{}': {error}", path.display()),
                crate::tools::ToolRetryability::Safe,
            )
        })?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        hasher.update(chunk);
        for (index, byte) in chunk.iter().copied().enumerate() {
            let position = absolute.saturating_add(u64::try_from(index).unwrap_or(u64::MAX));
            if position < inspection.start_byte
                || collected.len() >= collect_ceiling
                || line_boundary.is_some()
            {
                continue;
            }
            collected.push(byte);
            if inspection.utf8 && byte == b'\n' {
                completed_lines = completed_lines.saturating_add(1);
                if line_limit.is_some_and(|limit| completed_lines >= limit) {
                    line_boundary = Some(collected.len());
                }
            }
        }
        absolute = absolute.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
    }

    let mut retained = line_boundary
        .filter(|boundary| *boundary <= READ_PAGE_BYTES)
        .unwrap_or_else(|| collected.len().min(READ_PAGE_BYTES));
    if inspection.utf8 {
        while retained < collected.len()
            && collected
                .get(retained)
                .is_some_and(|byte| byte & 0b1100_0000 == 0b1000_0000)
        {
            retained = retained.saturating_sub(1);
        }
    }
    collected.truncate(retained);
    Ok((digest_from_hasher(hasher), collected))
}

struct ReadRequest {
    binding: String,
    start: ReadStart,
    expected_generation: Option<crate::runtime::ContentDigest>,
    line_limit: Option<u64>,
}

fn parse_read_request(
    run: &super::super::security::ToolRunContext,
    resolved: &Path,
    args: &HashMap<String, Value>,
) -> Result<ReadRequest, crate::tools::ToolFailure> {
    let binding = super::discovery::cursor_binding(&[
        "read_file",
        &run.run_id().to_string(),
        &resolved.to_string_lossy(),
    ]);
    let cursor_raw = match args.get("cursor") {
        None => None,
        Some(Value::String(cursor)) => Some(cursor.as_str()),
        Some(_) => {
            return Err(read_failure(
                crate::tools::ToolFailureCode::InvalidArguments,
                "'cursor' must be a string",
                crate::tools::ToolRetryability::Never,
            ));
        }
    };
    let requested_limit = parse_positive_u64("limit", args.get("limit"))?;
    let decoded = super::discovery::decode_cursor(cursor_raw, &binding).map_err(|message| {
        read_failure(
            crate::tools::ToolFailureCode::InvalidArguments,
            message,
            crate::tools::ToolRetryability::Never,
        )
    })?;
    let (start, expected_generation, line_limit) = match decoded {
        Some(super::discovery::CursorPosition::Read {
            resource_id,
            generation,
            byte,
            line_limit,
        }) => {
            if args.contains_key("offset") {
                return Err(read_failure(
                    crate::tools::ToolFailureCode::InvalidArguments,
                    "'offset' cannot be combined with a read continuation cursor",
                    crate::tools::ToolRetryability::Never,
                ));
            }
            if resource_id != resolved.to_string_lossy() {
                return Err(read_failure(
                    crate::tools::ToolFailureCode::InvalidArguments,
                    "Read cursor resource identity does not match the requested path",
                    crate::tools::ToolRetryability::Never,
                ));
            }
            if requested_limit.is_some_and(|limit| Some(limit) != line_limit) {
                return Err(read_failure(
                    crate::tools::ToolFailureCode::InvalidArguments,
                    "'limit' cannot change while continuing a read cursor",
                    crate::tools::ToolRetryability::Never,
                ));
            }
            let generation = generation.parse().map_err(|_| {
                read_failure(
                    crate::tools::ToolFailureCode::InvalidArguments,
                    "Read cursor contains an invalid file generation",
                    crate::tools::ToolRetryability::Never,
                )
            })?;
            (ReadStart::Byte(byte), Some(generation), line_limit)
        }
        Some(_) => {
            return Err(read_failure(
                crate::tools::ToolFailureCode::InvalidArguments,
                "Cursor belongs to a different file operation",
                crate::tools::ToolRetryability::Never,
            ));
        }
        None => {
            let offset = parse_positive_u64("offset", args.get("offset"))?.unwrap_or(1);
            (ReadStart::Line(offset), None, requested_limit)
        }
    };
    Ok(ReadRequest {
        binding,
        start,
        expected_generation,
        line_limit,
    })
}

fn page_content(inspection: &FileInspection, page: Vec<u8>) -> StablePageContent {
    if inspection.utf8 {
        let mut text = String::from_utf8(page).expect("stable UTF-8 inspection covers page bytes");
        let retained = bounded_numbered_source_len(
            &text,
            inspection.start_line,
            inspection.start_column_bytes,
            READ_TEXT_RENDER_BUDGET,
        );
        text.truncate(retained);
        let mut end_line = inspection.start_line;
        let mut end_column_bytes = inspection.start_column_bytes;
        for byte in text.bytes() {
            if byte == b'\n' {
                end_line = end_line.saturating_add(1);
                end_column_bytes = 0;
            } else {
                end_column_bytes = end_column_bytes.saturating_add(1);
            }
        }
        StablePageContent::Text {
            text,
            start_line: inspection.start_line,
            start_column_bytes: inspection.start_column_bytes,
            end_line,
            end_column_bytes,
        }
    } else {
        StablePageContent::Binary(page)
    }
}

/// Read one stable bounded page from an already-confined descriptor.
pub(super) fn read_stable_page(
    run: &super::super::security::ToolRunContext,
    file: &mut std::fs::File,
    resolved: &Path,
    args: &HashMap<String, Value>,
) -> Result<StableReadPage, crate::tools::ToolFailure> {
    let metadata_before = file.metadata().map_err(|error| {
        read_failure(
            crate::tools::ToolFailureCode::External,
            format!("Cannot inspect open file '{}': {error}", resolved.display()),
            crate::tools::ToolRetryability::Safe,
        )
    })?;
    if !metadata_before.file_type().is_file() {
        return Err(read_failure(
            crate::tools::ToolFailureCode::InvalidInput,
            format!("'{}' is not a regular file", resolved.display()),
            crate::tools::ToolRetryability::Never,
        ));
    }
    if metadata_before.len() > MAX_PAGED_FILE_BYTES {
        return Err(read_failure(
            crate::tools::ToolFailureCode::Unavailable,
            format!(
                "File '{}' is {} bytes; paged read scanning is capped at {MAX_PAGED_FILE_BYTES} bytes. Use grep or a domain-specific bounded reader.",
                resolved.display(),
                metadata_before.len()
            ),
            crate::tools::ToolRetryability::Never,
        ));
    }

    let request = parse_read_request(run, resolved, args)?;

    let inspection = inspect_paged_file(file, resolved, request.start)?;
    if let Some(expected) = request.expected_generation {
        if expected != inspection.generation {
            return Err(read_failure(
                crate::tools::ToolFailureCode::Conflict,
                format!(
                    "File '{}' changed after the previous read page (expected {expected}, found {})",
                    resolved.display(),
                    inspection.generation
                ),
                crate::tools::ToolRetryability::Safe,
            ));
        }
    }
    if !inspection.utf8 && (args.contains_key("offset") || request.line_limit.is_some()) {
        return Err(read_failure(
            crate::tools::ToolFailureCode::InvalidArguments,
            "Binary reads use byte cursors; line offset/limit arguments are unsupported",
            crate::tools::ToolRetryability::Never,
        ));
    }
    let metadata_middle = file.metadata().map_err(|error| {
        read_failure(
            crate::tools::ToolFailureCode::External,
            format!("Cannot inspect open file '{}': {error}", resolved.display()),
            crate::tools::ToolRetryability::Safe,
        )
    })?;
    let (second_generation, page) =
        scan_page_and_digest(file, resolved, &inspection, request.line_limit)?;
    let metadata_after = file.metadata().map_err(|error| {
        read_failure(
            crate::tools::ToolFailureCode::External,
            format!("Cannot inspect open file '{}': {error}", resolved.display()),
            crate::tools::ToolRetryability::Safe,
        )
    })?;
    if inspection.generation != second_generation
        || !super::secure_fs::same_file_snapshot(&metadata_before, &metadata_middle)
        || !super::secure_fs::same_file_snapshot(&metadata_middle, &metadata_after)
    {
        return Err(read_failure(
            crate::tools::ToolFailureCode::Conflict,
            format!("File '{}' changed while it was read", resolved.display()),
            crate::tools::ToolRetryability::Safe,
        ));
    }

    let content = page_content(&inspection, page);
    let page_len = match &content {
        StablePageContent::Text { text, .. } => text.len(),
        StablePageContent::Binary(bytes) => bytes.len(),
    };
    let byte_end = inspection
        .start_byte
        .saturating_add(u64::try_from(page_len).unwrap_or(u64::MAX));
    let next_cursor = (byte_end < inspection.total_bytes).then(|| {
        super::discovery::encode_cursor(
            &request.binding,
            super::discovery::CursorPosition::Read {
                resource_id: resolved.to_string_lossy().into_owned(),
                generation: inspection.generation.to_string(),
                byte: byte_end,
                line_limit: request.line_limit,
            },
        )
    });
    Ok(StableReadPage {
        generation: inspection.generation,
        total_bytes: inspection.total_bytes,
        byte_start: inspection.start_byte,
        byte_end,
        next_cursor,
        content,
    })
}

fn bounded_numbered_source_len(
    text: &str,
    start_line: u64,
    start_column_bytes: u64,
    budget: usize,
) -> usize {
    let mut rendered_bytes = 0_usize;
    let mut source_bytes = 0_usize;
    let mut line = start_line;
    let mut column = start_column_bytes;
    for segment in text.split_inclusive('\n') {
        let body = segment.strip_suffix('\n').unwrap_or(segment);
        let prefix = if column == 0 {
            format!("{line:>6}| ")
        } else {
            format!("{line:>6}:{column}| ")
        };
        let separator = usize::from(source_bytes > 0);
        let fixed = separator.saturating_add(prefix.len());
        let Some(remaining) = budget
            .checked_sub(rendered_bytes)
            .and_then(|remaining| remaining.checked_sub(fixed))
        else {
            break;
        };
        if body.len() <= remaining {
            rendered_bytes = rendered_bytes
                .saturating_add(fixed)
                .saturating_add(body.len());
            source_bytes = source_bytes.saturating_add(segment.len());
            if segment.ends_with('\n') {
                line = line.saturating_add(1);
                column = 0;
            } else {
                column = column.saturating_add(u64::try_from(body.len()).unwrap_or(u64::MAX));
            }
            continue;
        }
        let mut retained = remaining.min(body.len());
        while retained > 0 && !body.is_char_boundary(retained) {
            retained = retained.saturating_sub(1);
        }
        source_bytes = source_bytes.saturating_add(retained);
        break;
    }
    source_bytes
}

pub(super) fn render_numbered_text_page(
    text: &str,
    start_line: u64,
    start_column_bytes: u64,
) -> String {
    if text.is_empty() {
        return "(empty file)".to_string();
    }
    let mut rendered = String::new();
    let mut line = start_line;
    let mut column = start_column_bytes;
    for segment in text.split_inclusive('\n') {
        let body = segment.strip_suffix('\n').unwrap_or(segment);
        if !rendered.is_empty() {
            rendered.push('\n');
        }
        if column == 0 {
            let _ = write!(rendered, "{line:>6}| {body}");
        } else {
            let _ = write!(rendered, "{line:>6}:{column}| {body}");
        }
        if segment.ends_with('\n') {
            line = line.saturating_add(1);
            column = 0;
        } else {
            column = column.saturating_add(u64::try_from(body.len()).unwrap_or(u64::MAX));
        }
    }
    rendered
}

/// Image formats the harness can hand to vision-capable models.
///
/// crosslink #966: this used to live as a raw `&'static str` (the MIME type)
/// inside `FileType::Image`. Adding a new format had to update three
/// independent string literals across file detection, image rendering, and
/// downstream adapter assumptions. With a closed enum the type system
/// enforces exhaustiveness — every match arm sees every supported image kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    Png,
    Jpeg,
    Gif,
    Webp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageDimensions {
    pub width: u32,
    pub height: u32,
}

fn nonzero_dimensions(width: u32, height: u32) -> Option<ImageDimensions> {
    (width > 0 && height > 0).then_some(ImageDimensions { width, height })
}

fn jpeg_dimensions(bytes: &[u8]) -> Option<ImageDimensions> {
    if !bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        return None;
    }
    let mut offset = 2_usize;
    while offset < bytes.len() {
        while bytes.get(offset) == Some(&0xff) {
            offset = offset.saturating_add(1);
        }
        let marker = *bytes.get(offset)?;
        offset = offset.saturating_add(1);
        if marker == 0xd9 || marker == 0xda {
            return None;
        }
        if marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        let length = usize::from(u16::from_be_bytes([
            *bytes.get(offset)?,
            *bytes.get(offset.saturating_add(1))?,
        ]));
        if length < 2 || offset.checked_add(length)? > bytes.len() {
            return None;
        }
        if matches!(
            marker,
            0xc0 | 0xc1
                | 0xc2
                | 0xc3
                | 0xc5
                | 0xc6
                | 0xc7
                | 0xc9
                | 0xca
                | 0xcb
                | 0xcd
                | 0xce
                | 0xcf
        ) {
            if length < 7 {
                return None;
            }
            let height = u32::from(u16::from_be_bytes([
                *bytes.get(offset.saturating_add(3))?,
                *bytes.get(offset.saturating_add(4))?,
            ]));
            let width = u32::from(u16::from_be_bytes([
                *bytes.get(offset.saturating_add(5))?,
                *bytes.get(offset.saturating_add(6))?,
            ]));
            return nonzero_dimensions(width, height);
        }
        offset = offset.saturating_add(length);
    }
    None
}

fn webp_dimensions(bytes: &[u8]) -> Option<ImageDimensions> {
    if !bytes.starts_with(b"RIFF") || bytes.get(8..12) != Some(b"WEBP") {
        return None;
    }
    match bytes.get(12..16)? {
        b"VP8X" => {
            let width = 1_u32
                .saturating_add(u32::from(*bytes.get(24)?))
                .saturating_add(u32::from(*bytes.get(25)?) << 8)
                .saturating_add(u32::from(*bytes.get(26)?) << 16);
            let height = 1_u32
                .saturating_add(u32::from(*bytes.get(27)?))
                .saturating_add(u32::from(*bytes.get(28)?) << 8)
                .saturating_add(u32::from(*bytes.get(29)?) << 16);
            nonzero_dimensions(width, height)
        }
        b"VP8L" if bytes.get(20) == Some(&0x2f) => {
            let b0 = u32::from(*bytes.get(21)?);
            let b1 = u32::from(*bytes.get(22)?);
            let b2 = u32::from(*bytes.get(23)?);
            let b3 = u32::from(*bytes.get(24)?);
            let width = 1_u32.saturating_add(b0 | ((b1 & 0x3f) << 8));
            let height = 1_u32.saturating_add((b1 >> 6) | (b2 << 2) | ((b3 & 0x0f) << 10));
            nonzero_dimensions(width, height)
        }
        b"VP8 " if bytes.get(23..26) == Some(&[0x9d, 0x01, 0x2a]) => {
            let width = u32::from(u16::from_le_bytes([*bytes.get(26)?, *bytes.get(27)?]) & 0x3fff);
            let height = u32::from(u16::from_le_bytes([*bytes.get(28)?, *bytes.get(29)?]) & 0x3fff);
            nonzero_dimensions(width, height)
        }
        _ => None,
    }
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

    #[must_use]
    pub fn dimensions(self, bytes: &[u8]) -> Option<ImageDimensions> {
        match self {
            Self::Png if bytes.starts_with(b"\x89PNG\r\n\x1a\n") => {
                let width = u32::from_be_bytes(bytes.get(16..20)?.try_into().ok()?);
                let height = u32::from_be_bytes(bytes.get(20..24)?.try_into().ok()?);
                (bytes.get(12..16) == Some(b"IHDR"))
                    .then(|| nonzero_dimensions(width, height))
                    .flatten()
            }
            Self::Jpeg => jpeg_dimensions(bytes),
            Self::Gif if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") => {
                let width = u32::from(u16::from_le_bytes(bytes.get(6..8)?.try_into().ok()?));
                let height = u32::from(u16::from_le_bytes(bytes.get(8..10)?.try_into().ok()?));
                nonzero_dimensions(width, height)
            }
            Self::Webp => webp_dimensions(bytes),
            _ => None,
        }
    }
}

/// Supported file types for `read_file`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
/// `pdftotext` receives no run environment grants and never inherits the host
/// process environment. PDF bytes arrive over stdin and parser output leaves
/// over stdout, so locale and credential state are outside this profile.
#[cfg(test)]
pub fn read_pdf_file(
    run: &super::super::security::ToolRunContext,
    path: &str,
    pages: Option<&str>,
) -> (String, bool) {
    // Reject any path the subprocess would parse as a flag BEFORE we spawn.
    if let Some(err) = reject_flag_prefix(path) {
        return (err, true);
    }

    // Feed the parser bytes read from the already-confined descriptor. Passing
    // the original pathname would let a concurrent rename swap the parser's
    // input after authorization.
    let pdf_bytes = match read_safe_bytes(run, path) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };

    render_pdf_bytes(run, path, pages, &pdf_bytes)
}

pub(super) fn render_pdf_bytes(
    run: &super::super::security::ToolRunContext,
    path: &str,
    pages: Option<&str>,
    pdf_bytes: &[u8],
) -> (String, bool) {
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
                pdf_bytes,
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
        pdf_bytes,
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
#[cfg(test)]
pub fn read_notebook_file(
    run: &super::super::security::ToolRunContext,
    path: &str,
) -> (String, bool) {
    let bytes = match read_safe_bytes(run, path) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };

    render_notebook_bytes(path, &bytes)
}

pub(super) fn render_notebook_bytes(path: &str, bytes: &[u8]) -> (String, bool) {
    let content = match std::str::from_utf8(bytes) {
        Ok(content) => content,
        Err(error) => {
            return (
                format!("Failed to read notebook '{path}' as UTF-8: {error}"),
                true,
            )
        }
    };

    let notebook: Value = match serde_json::from_str(content) {
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
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    fn test_run() -> &'static std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context()
    }

    // Stable, bounded text paging and continuation behavior.

    /// Helper: write content to a `NamedTempFile` and return (file, `path_string`).
    fn tmp_text(content: &str) -> (NamedTempFile, String) {
        let mut f = NamedTempFile::new_in(".").expect("tempfile");
        f.write_all(content.as_bytes()).expect("write");
        let path = f.path().to_string_lossy().to_string();
        (f, path)
    }

    fn stable_page(path: &str, args: &HashMap<String, Value>) -> StableReadPage {
        let resolved = std::fs::canonicalize(path).expect("canonical test file");
        let mut file = super::super::secure_fs::open_regular_read(test_run(), &resolved)
            .expect("confined test read");
        read_stable_page(test_run(), &mut file, &resolved, args).expect("stable read page")
    }

    #[test]
    fn stable_cursor_pages_reconstruct_utf8_without_gaps() {
        let source = (0..8_000).fold(String::new(), |mut source, line| {
            writeln!(source, "line-{line:05} snowman=☃").expect("write string fixture");
            source
        });
        let (_file, path) = tmp_text(&source);
        let mut args = HashMap::from([("limit".to_string(), serde_json::json!(333))]);
        let mut reconstructed = Vec::new();
        let mut expected_start = 0_u64;
        let mut generation = None;
        let mut pages = 0_usize;

        loop {
            let page = stable_page(&path, &args);
            assert_eq!(page.byte_start, expected_start);
            assert!(page.byte_end >= page.byte_start);
            if let Some(expected) = generation {
                assert_eq!(page.generation, expected);
            } else {
                generation = Some(page.generation);
            }
            let StablePageContent::Text { text, .. } = page.content else {
                panic!("UTF-8 fixture became binary")
            };
            reconstructed.extend_from_slice(text.as_bytes());
            expected_start = page.byte_end;
            pages = pages.saturating_add(1);
            let Some(cursor) = page.next_cursor else {
                assert_eq!(page.byte_end, u64::try_from(source.len()).unwrap());
                break;
            };
            args = HashMap::from([("cursor".to_string(), Value::String(cursor))]);
        }

        assert!(pages > 2, "fixture must exercise multiple continuations");
        assert_eq!(reconstructed, source.as_bytes());
    }

    #[test]
    fn stable_cursor_reconstructs_one_oversized_multibyte_line() {
        let source = "☃".repeat(100_000);
        let (_file, path) = tmp_text(&source);
        let mut args = HashMap::new();
        let mut reconstructed = Vec::new();
        let mut expected_start = 0_u64;
        let mut saw_nonzero_column = false;

        loop {
            let page = stable_page(&path, &args);
            assert_eq!(page.byte_start, expected_start);
            let StablePageContent::Text {
                text,
                start_column_bytes,
                ..
            } = page.content
            else {
                panic!("valid UTF-8 long line became binary")
            };
            saw_nonzero_column |= start_column_bytes > 0;
            reconstructed.extend_from_slice(text.as_bytes());
            expected_start = page.byte_end;
            let Some(cursor) = page.next_cursor else {
                break;
            };
            args = HashMap::from([("cursor".to_string(), Value::String(cursor))]);
        }

        assert!(saw_nonzero_column, "continuation must expose a byte column");
        assert_eq!(reconstructed, source.as_bytes());
    }

    #[test]
    fn paged_text_read_accepts_files_above_legacy_ten_megabyte_cap() {
        let mut file = NamedTempFile::new_in(".").expect("tempfile");
        let bytes = vec![b'a'; usize::try_from(MAX_FILE_SIZE_BYTES).unwrap() + 4_096];
        file.write_all(&bytes).expect("write oversized text");
        file.flush().expect("flush oversized text");
        let page = stable_page(&file.path().to_string_lossy(), &HashMap::new());
        assert_eq!(page.byte_start, 0);
        assert_eq!(page.byte_end, u64::try_from(READ_PAGE_BYTES).unwrap());
        assert!(page.next_cursor.is_some());
        assert!(matches!(page.content, StablePageContent::Text { .. }));
    }

    #[test]
    fn read_cursor_rejects_a_changed_file_generation() {
        let source = "a".repeat(READ_PAGE_BYTES.saturating_add(128));
        let root = tempfile::tempdir_in(".").expect("mutation fixture root");
        let path = root.path().join("changing.txt");
        std::fs::write(&path, &source).expect("write initial fixture");
        let first = stable_page(&path.to_string_lossy(), &HashMap::new());
        let cursor = first.next_cursor.expect("first page continuation");
        std::fs::write(&path, "b".repeat(source.len())).expect("replace fixture generation");
        let resolved = std::fs::canonicalize(&path).expect("canonical changed file");
        let mut reopened = super::super::secure_fs::open_regular_read(test_run(), &resolved)
            .expect("reopen changed file");
        let args = HashMap::from([("cursor".to_string(), Value::String(cursor))]);
        let failure = read_stable_page(test_run(), &mut reopened, &resolved, &args)
            .expect_err("changed generation must invalidate cursor");
        assert_eq!(failure.code, crate::tools::ToolFailureCode::Conflict);
    }

    #[test]
    fn supported_image_headers_report_dimensions() {
        let mut png = vec![0_u8; 24];
        png[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        png[12..16].copy_from_slice(b"IHDR");
        png[16..20].copy_from_slice(&3_u32.to_be_bytes());
        png[20..24].copy_from_slice(&2_u32.to_be_bytes());
        assert_eq!(
            ImageKind::Png.dimensions(&png),
            Some(ImageDimensions {
                width: 3,
                height: 2
            })
        );

        let mut gif = b"GIF89a\0\0\0\0".to_vec();
        gif[6..8].copy_from_slice(&3_u16.to_le_bytes());
        gif[8..10].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            ImageKind::Gif.dimensions(&gif),
            ImageKind::Png.dimensions(&png)
        );

        let mut jpeg = vec![0_u8; 21];
        jpeg[..7].copy_from_slice(&[0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 0x08]);
        jpeg[7..9].copy_from_slice(&2_u16.to_be_bytes());
        jpeg[9..11].copy_from_slice(&3_u16.to_be_bytes());
        assert_eq!(
            ImageKind::Jpeg.dimensions(&jpeg),
            ImageKind::Png.dimensions(&png)
        );

        let mut webp = vec![0_u8; 30];
        webp[..4].copy_from_slice(b"RIFF");
        webp[8..12].copy_from_slice(b"WEBP");
        webp[12..16].copy_from_slice(b"VP8X");
        webp[24] = 2;
        webp[27] = 1;
        assert_eq!(
            ImageKind::Webp.dimensions(&webp),
            ImageKind::Png.dimensions(&png)
        );
        assert_eq!(ImageKind::Png.dimensions(b"\x89PNG\r\n\x1a\n"), None);
    }

    #[test]
    fn read_pdf_uses_resolved_poppler_binaries() {
        let source = include_str!("read.rs");
        let start = source
            .find("fn pdftotext_bin")
            .expect("pdftotext resolver must exist");
        let end = source[start..]
            .find("\n}\n")
            .map(|end| start + end)
            .expect("pdftotext resolver must terminate");
        let production = &source[start..end];

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
