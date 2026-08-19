//! `skill` tool — make user-authored skills directly callable by the model
//! (crosslink #612).
//!
//! Skills already live on disk as YAML-frontmatter markdown under
//! `.openclaudia/skills/` and `~/.openclaudia/skills/`; they were previously
//! reachable only via the `/skill` slash command in the TUI. This tool wraps
//! [`crate::skills::get_skill_for_project`] so the model can request a skill body during
//! tool dispatch the same way it requests any other tool, returning the
//! markdown body inside an explicit `<skill>...</skill>` envelope that the
//! caller can splice into the next turn's system prompt.
//!
//! ## Design notes
//!
//! * **Pure lookup, no side effects.** Skill invocation does not mutate
//!   global state, spawn subprocesses, or touch the network. The envelope is
//!   intentionally a labelled XML-ish marker so downstream readers (transcript
//!   loader, system-prompt builder) can find and re-inject it without parsing
//!   YAML again.
//! * **Stable error contract.** A missing skill returns the
//!   `(message, is_error = true)` tuple convention used by every other
//!   `(String, bool)` tool handler. Tests pin both the wording prefix and the
//!   `is_error` flag so callers can branch on either signal.
//! * **Cache reuse.** `get_skill` consults the shared
//!   [`crate::skills`] cache (mtime-fingerprinted), so repeated invocations of
//!   the same skill name are O(1) after the first scan.

use serde_json::Value;
use std::collections::HashMap;
use std::hash::BuildHasher;

use crate::skills;
use crate::tools::args::ToolArgError;
use crate::tools::security::ToolRunContext;

/// Open-tag emitted before the skill body.
pub(crate) const ENVELOPE_OPEN: &str = "<skill";
/// Close-tag emitted after the skill body.
pub(crate) const ENVELOPE_CLOSE: &str = "</skill>";

/// Render the loaded skill in the envelope shape the orchestrator expects.
///
/// The envelope includes the skill name as an attribute so transcript readers
/// can route multiple `<skill>` blocks to the right grouping without parsing
/// the body. The body is the raw markdown from the skill file (post-
/// frontmatter), exactly as `skills::get_skill` returns it.
fn render_envelope(name: &str, body: &str) -> String {
    let mut out = String::with_capacity(ENVELOPE_OPEN.len() + ENVELOPE_CLOSE.len() + body.len());
    out.push_str(ENVELOPE_OPEN);
    out.push_str(" name=\"");
    out.push_str(&xml_attr_escape(name));
    out.push_str("\">\n");
    out.push_str(body);
    if !body.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(ENVELOPE_CLOSE);
    out
}

/// Escape a string for embedding inside a double-quoted XML attribute.
///
/// Skill names ship straight to the model, so we treat them as untrusted —
/// even though current callers slugify them at write time, a future loader
/// might accept arbitrary YAML names.
fn xml_attr_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Execute the `skill` tool.
///
/// Required argument: `name` (string). The handler looks up the skill via
/// [`crate::skills::get_skill_for_project`] and returns either an
/// envelope-wrapped body or
/// a structured error message.
///
/// Returns `(text, is_error)`.
#[must_use]
pub fn execute_skill<S: BuildHasher>(
    run: &ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> (String, bool) {
    let name = match args.get("name") {
        None => return ("skill: missing required argument `name`".to_string(), true),
        Some(Value::String(name)) => name.as_str(),
        Some(_) => {
            return ToolArgError::WrongType {
                key: "name",
                expected: "string",
            }
            .into_tool_error();
        }
    };

    let trimmed = name.trim();
    if trimmed.is_empty() {
        return ("skill: `name` is empty".to_string(), true);
    }

    let Some(def) =
        skills::get_skill_for_project(trimmed, run.project_root(), run.working_directory())
    else {
        // Listing the available skills here would be friendly but the cache is
        // potentially large and we do not want to surprise the model with a
        // multi-KiB error blob; the caller can request the list via the
        // existing slash-command path if it wants the catalogue.
        return (format!("skill: unknown skill `{trimmed}`"), true);
    };

    (render_envelope(&def.name, &def.prompt), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run() -> &'static ToolRunContext {
        crate::tools::security::test_run_context().as_ref()
    }

    // Note: tests do NOT mutate the process CWD because that races with
    // every other parallel test in the same binary. Instead, the
    // unknown / known-skill tests just exercise the `(name, body)`
    // contract through `execute_skill` against argument shapes (the
    // happy-path skill-loading is covered separately by
    // `skills::tests::*` which is single-threaded over a tempdir).

    #[test]
    fn missing_name_arg_errors() {
        let args = HashMap::new();
        let (text, is_err) = execute_skill(run(), &args);
        assert!(is_err);
        assert!(text.contains("missing required argument"));
    }

    #[test]
    fn wrong_type_name_arg_errors() {
        let mut args = HashMap::new();
        args.insert("name".to_string(), json!(42));
        let (text, is_err) = execute_skill(run(), &args);
        assert!(is_err);
        assert!(text.contains("Invalid 'name' argument: expected string"));
    }

    #[test]
    fn empty_name_errors() {
        let mut args = HashMap::new();
        args.insert("name".to_string(), json!(""));
        let (text, is_err) = execute_skill(run(), &args);
        assert!(is_err);
        assert!(text.contains("empty"));
    }

    #[test]
    fn unknown_skill_errors() {
        // No CWD manipulation: `get_skill` returns None for a name no
        // installed skill carries, which is what we want to assert.
        let mut args = HashMap::new();
        args.insert(
            "name".to_string(),
            json!("__definitely_not_a_real_skill_xyz_637__"),
        );
        let (text, is_err) = execute_skill(run(), &args);
        assert!(is_err);
        assert!(text.contains("unknown skill"));
    }

    #[test]
    fn envelope_render_round_trips() {
        // Cover the envelope shape directly so tests don't need to
        // install a skill on disk (which would require CWD manipulation
        // that races other parallel tests).
        let body = render_envelope("demo", "Hello body line");
        assert!(body.starts_with("<skill name=\"demo\">"));
        assert!(body.contains("Hello body line"));
        assert!(body.ends_with("</skill>"));
    }

    #[test]
    fn xml_escape_attribute() {
        assert_eq!(xml_attr_escape("a&b<c>d\""), "a&amp;b&lt;c&gt;d&quot;");
    }

    #[test]
    fn render_envelope_normalises_trailing_newline() {
        // Body without trailing newline gets one inserted so close-tag
        // lands on its own line.
        let s = render_envelope("x", "body");
        assert!(s.contains("body\n</skill>"));
        // Body that already ends with a newline does not get a second.
        let s2 = render_envelope("x", "body\n");
        assert!(s2.ends_with("body\n</skill>"));
        assert!(!s2.contains("body\n\n</skill>"));
    }
}
