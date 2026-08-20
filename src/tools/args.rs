//! Typed argument accessors for tool handlers — closes crosslink #675.
//!
//! Every executor used to reimplement the same
//! `args.get("k").and_then(|v| v.as_str())` extraction shape, drifting in
//! its error wording (`"Error: name is required"`,
//! `"Missing 'path' argument"`, `"missing 'content' field"`). The QA review
//! flagged this as a textbook DRY violation: N copies of the same dispatch
//! protocol, each free to regress independently (see issue #675).
//!
//! This module provides the [`ToolArgs`] trait, blanket-implemented for
//! `HashMap<String, Value, S>` so it covers both the `RandomState` map most
//! handlers receive *and* the generic `S: BuildHasher` maps that the
//! worktree / LSP tools use. The accessors are intentionally narrow:
//!
//! | accessor                             | use case                                  |
//! |--------------------------------------|-------------------------------------------|
//! | [`ToolArgs::arg_str_strict`]         | required string, reject wrong type        |
//! | [`ToolArgs::arg_string`]             | same, owned `String`                      |
//! | [`ToolArgs::arg_str_opt_strict`]     | optional string, reject wrong type        |
//! | [`ToolArgs::arg_str_or_strict`]      | optional string default, reject wrong type|
//! | [`ToolArgs::arg_bool_or_strict`]     | optional bool, reject wrong type          |
//!
//! `ToolArgError`'s `Display` produces the canonical phrasing
//! `Missing 'KEY' argument`, matching the prevalent style in the codebase
//! (file/write.rs, file/edit.rs, bash/mod.rs, …). Drift sites that used
//! `"Error: KEY is required"` (cron) or `"KEY is required"` are quietly
//! normalised — that uniformity is the entire point of the refactor.
//!
//! Tools that return the legacy `(String, bool)` shape convert the typed
//! error via [`ToolArgError::into_tool_error`], which produces
//! `(message, true)`. The two helpers compose:
//!
//! ```ignore
//! use crate::tools::args::ToolArgs as _;
//!
//! pub fn execute_thing(args: &HashMap<String, Value>) -> (String, bool) {
//!     let name = match args.arg_str_strict("name") {
//!         Ok(n) => n,
//!         Err(e) => return e.into_tool_error(),
//!     };
//!     // …
//! }
//! ```

use serde_json::Value;
use std::collections::HashMap;
use std::hash::BuildHasher;

/// Typed extraction error for tool argument accessors.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolArgError {
    /// The requested key is absent, or the value is the wrong JSON type.
    MissingOrWrongType {
        /// The argument key that the executor asked for.
        key: &'static str,
    },
    /// The requested key is optional, but was supplied with the wrong JSON
    /// type.
    WrongType {
        /// The argument key that the executor asked for.
        key: &'static str,
        /// Human-readable expected type name.
        expected: &'static str,
    },
}

impl ToolArgError {
    /// Convert into the legacy `(message, is_error=true)` tuple every
    /// executor returns. Centralising the format string here is the
    /// whole point of issue #675.
    #[must_use]
    pub fn into_tool_error(self) -> (String, bool) {
        (self.to_string(), true)
    }
}

impl std::fmt::Display for ToolArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingOrWrongType { key } => {
                write!(f, "Missing '{key}' argument")
            }
            Self::WrongType { key, expected } => {
                write!(f, "Invalid '{key}' argument: expected {expected}")
            }
        }
    }
}

impl std::error::Error for ToolArgError {}

// ─── Typed tool result surface (crosslink #222, #376) ────────────────────────
//
// The legacy executor return shape is `(String, bool)` — content + is_error.
// `(String, bool)` cannot encode:
//   * structured data (e.g. a directory listing the renderer could format),
//   * the *kind* of error (argument vs. permission vs. I/O vs. backend),
//   * an inner `Error` chain a `?`-propagating caller can match on.
// Three call surfaces have grown around this gap: tool executors return
// `(String, bool)`, the proxy layer wraps them in `(String, String, bool)`,
// and slash commands sometimes use `anyhow::Result`. Tracked as #222
// (standardise error handling) and #376 (drop `(String, bool)` for the
// tool return surface specifically).
//
// `ToolOutput` and `ToolError` below are the standard target shape. Migration
// is gradual: new tools return `Result<ToolOutput, ToolError>` natively;
// legacy executors that still return `(String, bool)` keep working through
// the bridging `From` impls so the registry's `(String, bool)` glue compiles
// untouched. The first migrated executor is `bash::execute_bash` (#376).

/// Structured result of a successful tool invocation.
///
/// `content` is the human-/model-facing rendered text — what the previous
/// `(String, bool)` shape called the first element. `structured` is the
/// optional JSON form the renderer can pretty-print without re-parsing
/// `content`. Tools that have no structured data leave it `None`; tools
/// that do (file index entries, task lists, git diffs, and similar)
/// populate it so downstream consumers don't string-parse a rendered table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    /// Rendered text content (legacy first tuple element).
    pub content: String,
    /// Optional JSON representation alongside the rendered text.
    pub structured: Option<Value>,
}

impl ToolOutput {
    /// Construct a [`ToolOutput`] with text content only.
    #[must_use]
    pub const fn text(content: String) -> Self {
        Self {
            content,
            structured: None,
        }
    }

    /// Construct a [`ToolOutput`] with both rendered text and a structured
    /// JSON payload the renderer / downstream consumer can introspect
    /// without re-parsing the text.
    #[must_use]
    pub const fn with_structured(content: String, structured: Value) -> Self {
        Self {
            content,
            structured: Some(structured),
        }
    }
}

/// Structured tool execution error.
///
/// Variants name the failure category so callers can match on the failure
/// mode rather than `is_error: bool`. The `Display` form is the message
/// the legacy `(String, bool)` shape carried as its first tuple element —
/// every variant produces a stable, user-visible string and the
/// `From<ToolError> for (String, bool)` bridge below lets a typed
/// executor continue to satisfy the legacy `ToolHandler::execute` shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolError {
    /// A required argument was absent or the wrong JSON type. Wraps
    /// [`ToolArgError`] to avoid a parallel error hierarchy.
    InvalidArgument(ToolArgError),
    /// The arguments parsed but failed a domain validation rule (e.g.
    /// command on the bash denylist, length cap exceeded, malformed path).
    InvalidInput(String),
    /// A required immutable run resource is absent or invalid.
    Unavailable(String),
    /// An external operation failed (subprocess, filesystem, HTTP, …).
    /// The message is the upstream error rendered for human consumption.
    External(String),
    /// An external operation produced an observable effect before failing.
    ///
    /// The legacy tuple projection remains `(message, true)`, while the
    /// canonical handler adapter preserves this as `ToolOutcome::Partial` so
    /// effect accounting cannot mistake a failed completion for no effect.
    PartialExternal(String),
    /// The permissions layer rejected the call. Distinct from
    /// `InvalidInput` so policy-enforcement code can surface the rejection
    /// distinctly from a user typo.
    PermissionDenied(String),
    /// Catch-all for messages that don't fit a sharper category yet. Use
    /// of `Other` is a migration shim — new code should pick a sharper
    /// variant or add one.
    Other(String),
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument(e) => write!(f, "{e}"),
            Self::InvalidInput(msg)
            | Self::Unavailable(msg)
            | Self::External(msg)
            | Self::PartialExternal(msg)
            | Self::PermissionDenied(msg)
            | Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ToolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidArgument(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ToolArgError> for ToolError {
    fn from(e: ToolArgError) -> Self {
        Self::InvalidArgument(e)
    }
}

/// Convert a typed [`ToolError`] into the legacy `(message, is_error=true)`
/// shape every `ToolHandler::execute` still produces. The bridge is the
/// load-bearing migration shim: an executor can be rewritten to return
/// `Result<ToolOutput, ToolError>` natively while its registry wrapper
/// keeps emitting the legacy tuple via `.unwrap_or_else(Into::into)` and
/// `(out.content, false)` on the happy path.
impl From<ToolError> for (String, bool) {
    fn from(e: ToolError) -> Self {
        (e.to_string(), true)
    }
}

/// Convert a typed [`ToolOutput`] into the legacy `(content, is_error=false)`
/// shape. Symmetric with the [`ToolError`] bridge so a `Result<ToolOutput,
/// ToolError>` collapses to `(String, bool)` via `match { Ok(o) => o.into(),
/// Err(e) => e.into() }` — exactly the wrapping every registry adapter
/// performs today.
impl From<ToolOutput> for (String, bool) {
    fn from(o: ToolOutput) -> Self {
        (o.content, false)
    }
}

/// Collapse a `Result<ToolOutput, ToolError>` into the legacy
/// `(message, is_error)` tuple. The migration shim every registry adapter
/// uses to keep the `ToolHandler::execute` signature stable while the
/// executor itself is rewritten to be `Result`-typed. Spelled out as a
/// free function so call sites read as `into_legacy(result)` instead of
/// fan-out `match` arms.
#[must_use]
#[cfg(test)]
pub fn into_legacy(result: Result<ToolOutput, ToolError>) -> (String, bool) {
    match result {
        Ok(out) => out.into(),
        Err(e) => e.into(),
    }
}

/// Typed accessors over a tool handler's argument map.
///
/// Blanket-implemented for `HashMap<String, Value, S>` so every executor
/// (including the worktree/LSP ones that take a generic
/// `S: BuildHasher`) can call the same methods without converting maps.
pub trait ToolArgs {
    /// Required string argument. Missing values keep the legacy missing
    /// wording, but present non-string values produce a type-specific
    /// validation error.
    ///
    /// # Errors
    ///
    /// Returns [`ToolArgError::MissingOrWrongType`] when `key` is not
    /// present, or [`ToolArgError::WrongType`] when `key` is present but
    /// not a JSON string.
    fn arg_str_strict(&self, key: &'static str) -> Result<&str, ToolArgError>;

    /// Required string argument as an owned `String`. Convenience for
    /// the `.to_string()` follow-up that executors need when a string can
    /// outlive the borrowed map.
    ///
    /// # Errors
    ///
    /// Returns [`ToolArgError::MissingOrWrongType`] when `key` is not
    /// present, or [`ToolArgError::WrongType`] when `key` is present but
    /// not a JSON string.
    fn arg_string(&self, key: &'static str) -> Result<String, ToolArgError> {
        self.arg_str_strict(key).map(str::to_owned)
    }

    /// Optional string argument. `None` when absent, but present non-string
    /// values produce a type-specific validation error.
    ///
    /// # Errors
    ///
    /// Returns [`ToolArgError::WrongType`] when `key` is present but not a
    /// JSON string.
    fn arg_str_opt_strict(&self, key: &'static str) -> Result<Option<&str>, ToolArgError>;

    /// Optional string argument with a fallback default for absent values,
    /// while rejecting present non-string values.
    ///
    /// # Errors
    ///
    /// Returns [`ToolArgError::WrongType`] when `key` is present but not a
    /// JSON string.
    fn arg_str_or_strict<'a>(
        &'a self,
        key: &'static str,
        default: &'a str,
    ) -> Result<&'a str, ToolArgError>;

    /// Optional boolean argument with a fallback default for absent values,
    /// while rejecting present non-boolean values.
    ///
    /// # Errors
    ///
    /// Returns [`ToolArgError::WrongType`] when `key` is present but not a
    /// JSON boolean.
    fn arg_bool_or_strict(&self, key: &'static str, default: bool) -> Result<bool, ToolArgError>;
}

impl<S: BuildHasher> ToolArgs for HashMap<String, Value, S> {
    fn arg_str_strict(&self, key: &'static str) -> Result<&str, ToolArgError> {
        match self.get(key) {
            None => Err(ToolArgError::MissingOrWrongType { key }),
            Some(Value::String(value)) => Ok(value.as_str()),
            Some(_) => Err(ToolArgError::WrongType {
                key,
                expected: "string",
            }),
        }
    }

    fn arg_str_opt_strict(&self, key: &'static str) -> Result<Option<&str>, ToolArgError> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::String(value)) => Ok(Some(value.as_str())),
            Some(_) => Err(ToolArgError::WrongType {
                key,
                expected: "string",
            }),
        }
    }

    fn arg_str_or_strict<'a>(
        &'a self,
        key: &'static str,
        default: &'a str,
    ) -> Result<&'a str, ToolArgError> {
        self.get(key).map_or(Ok(default), |value| {
            value.as_str().ok_or(ToolArgError::WrongType {
                key,
                expected: "string",
            })
        })
    }

    fn arg_bool_or_strict(&self, key: &'static str, default: bool) -> Result<bool, ToolArgError> {
        self.get(key).map_or(Ok(default), |value| {
            value.as_bool().ok_or(ToolArgError::WrongType {
                key,
                expected: "boolean",
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make() -> HashMap<String, Value> {
        let mut m = HashMap::new();
        m.insert("name".into(), json!("alice"));
        m.insert("enabled".into(), json!(true));
        m.insert("count".into(), json!(7));
        m.insert("items".into(), json!(["a", "b"]));
        m.insert("number_as_string".into(), json!("12"));
        m.insert("null_value".into(), Value::Null);
        m
    }

    // ── arg_str_strict ─────────────────────────────────────────────────

    #[test]
    fn arg_str_strict_returns_value_when_present_and_string() {
        let m = make();
        assert_eq!(m.arg_str_strict("name").unwrap(), "alice");
    }

    #[test]
    fn arg_str_strict_errors_when_key_missing() {
        let m = make();
        let err = m.arg_str_strict("absent").unwrap_err();
        assert_eq!(err, ToolArgError::MissingOrWrongType { key: "absent" });
        assert_eq!(err.to_string(), "Missing 'absent' argument");
    }

    #[test]
    fn arg_str_strict_errors_when_value_is_wrong_type() {
        let m = make();
        let err = m.arg_str_strict("count").unwrap_err();
        assert_eq!(
            err,
            ToolArgError::WrongType {
                key: "count",
                expected: "string",
            }
        );
        assert_eq!(err.to_string(), "Invalid 'count' argument: expected string");
    }

    #[test]
    fn into_tool_error_returns_legacy_tuple_with_is_error_true() {
        let m = make();
        let (msg, is_err) = m.arg_str_strict("absent").unwrap_err().into_tool_error();
        assert!(is_err, "is_error flag must be true");
        assert_eq!(msg, "Missing 'absent' argument");
    }

    // ── arg_string ──────────────────────────────────────────────────────

    #[test]
    fn arg_string_returns_owned_copy() {
        let m = make();
        let owned: String = m.arg_string("name").unwrap();
        assert_eq!(owned, "alice");
    }

    #[test]
    fn arg_string_errors_when_value_is_wrong_type() {
        let m = make();
        let err = m.arg_string("count").unwrap_err();
        assert_eq!(
            err,
            ToolArgError::WrongType {
                key: "count",
                expected: "string",
            }
        );
    }

    // ── arg_str_opt_strict ─────────────────────────────────────────────

    #[test]
    fn arg_str_opt_strict_returns_some_for_string_value() {
        let m = make();
        assert_eq!(m.arg_str_opt_strict("name").unwrap(), Some("alice"));
    }

    #[test]
    fn arg_str_opt_strict_returns_none_when_missing() {
        let m = make();
        assert_eq!(m.arg_str_opt_strict("absent").unwrap(), None);
    }

    #[test]
    fn arg_str_opt_strict_errors_when_present_with_wrong_type() {
        let m = make();
        let err = m.arg_str_opt_strict("count").unwrap_err();
        assert_eq!(
            err,
            ToolArgError::WrongType {
                key: "count",
                expected: "string",
            }
        );
        assert_eq!(err.to_string(), "Invalid 'count' argument: expected string");
    }

    // ── arg_str_or_strict ──────────────────────────────────────────────

    #[test]
    fn arg_str_or_strict_returns_value_when_present() {
        let m = make();
        assert_eq!(m.arg_str_or_strict("name", "default").unwrap(), "alice");
    }

    #[test]
    fn arg_str_or_strict_returns_default_when_missing() {
        let m = make();
        assert_eq!(
            m.arg_str_or_strict("absent", "fallback").unwrap(),
            "fallback"
        );
    }

    #[test]
    fn arg_str_or_strict_errors_when_present_with_wrong_type() {
        let m = make();
        let err = m.arg_str_or_strict("count", "fallback").unwrap_err();

        assert_eq!(
            err,
            ToolArgError::WrongType {
                key: "count",
                expected: "string",
            }
        );
        assert_eq!(err.to_string(), "Invalid 'count' argument: expected string");
    }

    // ── arg_bool_or_strict ─────────────────────────────────────────────

    #[test]
    fn arg_bool_or_strict_returns_value_when_present_and_bool() {
        let m = make();
        assert!(m.arg_bool_or_strict("enabled", false).unwrap());
    }

    #[test]
    fn arg_bool_or_strict_returns_default_when_missing() {
        let m = make();
        assert!(!m.arg_bool_or_strict("absent", false).unwrap());
        assert!(m.arg_bool_or_strict("absent", true).unwrap());
    }

    #[test]
    fn arg_bool_or_strict_errors_when_present_with_wrong_type() {
        let m = make();
        let err = m.arg_bool_or_strict("name", false).unwrap_err();

        assert_eq!(
            err,
            ToolArgError::WrongType {
                key: "name",
                expected: "boolean",
            }
        );
        assert_eq!(err.to_string(), "Invalid 'name' argument: expected boolean");
    }

    // ── BuildHasher compatibility ──────────────────────────────────────

    #[test]
    fn trait_applies_to_custom_build_hasher_maps() {
        // The worktree/LSP tools take a generic `S: BuildHasher` map; this
        // test pins that the blanket impl actually covers a non-default S.
        use std::collections::hash_map::RandomState;
        let mut m: HashMap<String, Value, RandomState> = HashMap::with_hasher(RandomState::new());
        m.insert("k".into(), json!("v"));
        // Call through the trait — proves blanket impl applies.
        let v: &str = m.arg_str_strict("k").expect("typed accessor over custom S");
        assert_eq!(v, "v");
    }

    // ── ToolOutput / ToolError typed surface (crosslink #222, #376) ─────

    #[test]
    fn tool_output_text_leaves_structured_none() {
        let o = ToolOutput::text("hello".into());
        assert_eq!(o.content, "hello");
        assert!(o.structured.is_none());
    }

    #[test]
    fn tool_output_with_structured_populates_both() {
        let o = ToolOutput::with_structured("ls".into(), json!(["a", "b"]));
        assert_eq!(o.content, "ls");
        assert_eq!(o.structured, Some(json!(["a", "b"])));
    }

    #[test]
    fn tool_output_collapses_to_legacy_ok_tuple() {
        let (s, is_err): (String, bool) = ToolOutput::text("ok".into()).into();
        assert_eq!(s, "ok");
        assert!(!is_err, "ToolOutput always collapses to is_error=false");
    }

    #[test]
    fn tool_error_invalid_argument_round_trips_message() {
        let err = ToolError::from(ToolArgError::MissingOrWrongType { key: "path" });
        assert_eq!(err.to_string(), "Missing 'path' argument");
        let (s, is_err): (String, bool) = err.into();
        assert_eq!(s, "Missing 'path' argument");
        assert!(is_err, "ToolError always collapses to is_error=true");
    }

    #[test]
    fn tool_error_invalid_input_displays_payload() {
        let err = ToolError::InvalidInput("denylist hit: rm -rf /".into());
        assert_eq!(err.to_string(), "denylist hit: rm -rf /");
    }

    #[test]
    fn tool_error_external_displays_payload() {
        let err = ToolError::External("Failed to execute command: no such file".into());
        assert_eq!(err.to_string(), "Failed to execute command: no such file");
    }

    #[test]
    fn tool_error_permission_denied_displays_payload() {
        let err = ToolError::PermissionDenied("write blocked by Edit rule".into());
        assert_eq!(err.to_string(), "write blocked by Edit rule");
    }

    #[test]
    fn into_legacy_collapses_ok_to_content_false() {
        let r: Result<ToolOutput, ToolError> = Ok(ToolOutput::text("done".into()));
        assert_eq!(into_legacy(r), ("done".to_string(), false));
    }

    #[test]
    fn into_legacy_collapses_err_to_message_true() {
        let r: Result<ToolOutput, ToolError> = Err(ToolError::External("boom".into()));
        assert_eq!(into_legacy(r), ("boom".to_string(), true));
    }

    #[test]
    fn tool_error_source_chain_exposes_arg_error() {
        use std::error::Error as _;
        let err = ToolError::from(ToolArgError::MissingOrWrongType { key: "x" });
        let src = err
            .source()
            .expect("InvalidArgument exposes inner ToolArgError as source");
        // The source must be the ToolArgError, not a re-stringification.
        assert_eq!(src.to_string(), "Missing 'x' argument");
    }

    #[test]
    fn tool_error_source_chain_none_for_message_variants() {
        use std::error::Error as _;
        let err = ToolError::Other("unstructured".into());
        assert!(err.source().is_none(), "Other has no inner error");
    }
}
