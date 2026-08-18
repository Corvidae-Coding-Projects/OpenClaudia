use std::collections::{HashMap, HashSet};

use serde_json::Value;

use super::{
    ToolFailure, ToolFailureCode, ToolFollowUp, ToolFollowUpState, ToolHandlerResult, ToolQuestion,
    ToolQuestionOption, ToolRetryability,
};

/// Claude Code-compatible chip width for the question `header` field.
/// Matches `ASK_USER_QUESTION_TOOL_CHIP_WIDTH` in
/// `claude-code/tools/AskUserQuestionTool/prompt.ts`.
const HEADER_CHIP_WIDTH: usize = 12;

/// Pull the `questions` array out of the raw tool arguments and apply the
/// outer 1-4 count bound.  Returns the borrowed slice on success.
fn parse_args(args: &HashMap<String, Value>) -> Result<&[Value], String> {
    let questions = match args.get("questions") {
        None => return Err("Missing 'questions' argument".to_string()),
        Some(Value::Array(questions)) => questions,
        Some(_) => return Err("Invalid 'questions' argument: expected array".to_string()),
    };
    if questions.is_empty() || questions.len() > 4 {
        return Err("Must provide 1-4 questions".to_string());
    }
    Ok(questions.as_slice())
}

fn required_string_field<'a>(
    value: &'a Value,
    field: &'static str,
    missing_msg: impl FnOnce() -> String,
    wrong_type_msg: impl FnOnce() -> String,
) -> Result<&'a str, String> {
    match value.get(field) {
        None => Err(missing_msg()),
        Some(Value::String(text)) => Ok(text),
        Some(_) => Err(wrong_type_msg()),
    }
}

/// Validate the shape of a single option object.  Index `i` and `j` are
/// carried through purely for error-message context.
fn validate_option(
    i: usize,
    j: usize,
    opt: &Value,
    seen: &mut HashSet<String>,
) -> Result<(), String> {
    let label = required_string_field(
        opt,
        "label",
        || format!("Question {i} option {j} missing 'label'"),
        || format!("Question {i} option {j} 'label' must be a string"),
    )?;
    if !seen.insert(label.to_string()) {
        return Err(format!(
            "Question {i} option labels must be unique; '{label}' appears more than once"
        ));
    }
    let _description = required_string_field(
        opt,
        "description",
        || format!("Question {i} option {j} missing 'description'"),
        || format!("Question {i} option {j} 'description' must be a string"),
    )?;
    // `preview` is optional (CC parity).  When present it must be a string —
    // fail loudly rather than silently dropping it.
    if let Some(v) = opt.get("preview") {
        if !v.is_string() {
            return Err(format!(
                "Question {i} option {j} 'preview' must be a string"
            ));
        }
    }
    Ok(())
}

/// Validate the shape of a single question and its options.  Does not
/// enforce cross-question uniqueness — that belongs in
/// [`validate_question_set`].
fn validate_question(i: usize, q: &Value) -> Result<&str, String> {
    let question_text = required_string_field(
        q,
        "question",
        || format!("Question {i} missing 'question' field"),
        || format!("Question {i} 'question' must be a string"),
    )?;

    let header = required_string_field(
        q,
        "header",
        || format!("Question {i} missing 'header' field"),
        || format!("Question {i} 'header' must be a string"),
    )?;
    // CC uses `.length`, which for ASCII matches byte count.  For multi-byte
    // UTF-8 we use chars().count() so a header like "日本語" (3 chars, 9
    // bytes) fits the same way users expect in CC.
    if header.chars().count() > HEADER_CHIP_WIDTH {
        return Err(format!(
            "Question {i} header '{header}' exceeds {HEADER_CHIP_WIDTH} character limit"
        ));
    }

    // `multiSelect` is CC's name; `multi_select` is OC's original
    // camelCase-impaired spelling.  Accept either for back-compat.  Both
    // must be booleans when present.
    for key in ["multiSelect", "multi_select"] {
        if let Some(v) = q.get(key) {
            if !v.is_boolean() {
                return Err(format!("Question {i} '{key}' must be a boolean"));
            }
        }
    }

    let opts = match q.get("options") {
        None => return Err(format!("Question {i} missing 'options' field")),
        Some(Value::Array(opts)) => opts,
        Some(_) => return Err(format!("Question {i} 'options' must be an array")),
    };
    if opts.len() < 2 || opts.len() > 4 {
        return Err(format!(
            "Question {} must have 2-4 options, got {}",
            i,
            opts.len()
        ));
    }
    let mut seen_labels: HashSet<String> = HashSet::new();
    for (j, opt) in opts.iter().enumerate() {
        validate_option(i, j, opt, &mut seen_labels)?;
    }

    Ok(question_text)
}

/// Enforce cross-question uniqueness on the question-text field.  CC parity:
/// see `claude-code/tools/AskUserQuestionTool/AskUserQuestionTool.tsx`
/// (`UNIQUENESS_REFINE`).
fn validate_question_set(questions: &[Value]) -> Result<(), String> {
    let mut seen: HashSet<&str> = HashSet::new();
    for (i, q) in questions.iter().enumerate() {
        let text = validate_question(i, q)?;
        if !seen.insert(text) {
            return Err(format!(
                "Question texts must be unique; '{text}' appears more than once"
            ));
        }
    }
    Ok(())
}

fn typed_question(value: &Value) -> ToolQuestion {
    let options = value["options"]
        .as_array()
        .expect("validated question options")
        .iter()
        .map(|option| ToolQuestionOption {
            label: option["label"]
                .as_str()
                .expect("validated option label")
                .to_string(),
            description: option["description"]
                .as_str()
                .expect("validated option description")
                .to_string(),
            preview: option
                .get("preview")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
        .collect();
    ToolQuestion {
        question: value["question"]
            .as_str()
            .expect("validated question text")
            .to_string(),
        header: value["header"]
            .as_str()
            .expect("validated question header")
            .to_string(),
        options,
        multi_select: value
            .get("multiSelect")
            .or_else(|| value.get("multi_select"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

fn invalid_question(message: String) -> ToolHandlerResult {
    ToolHandlerResult::error(ToolFailure::new(
        ToolFailureCode::InvalidArguments,
        message,
        ToolRetryability::Never,
    ))
}

/// Execute the `ask_user_question` tool by returning a trusted typed follow-up.
pub fn execute_ask_user_question(args: &HashMap<String, Value>) -> ToolHandlerResult {
    let questions = match parse_args(args) {
        Ok(qs) => qs,
        Err(msg) => return invalid_question(msg),
    };
    if let Err(msg) = validate_question_set(questions) {
        return invalid_question(msg);
    }
    let questions = questions.iter().map(typed_question).collect();
    ToolHandlerResult::success_text("Waiting for user answers".to_string()).with_follow_up(
        ToolFollowUp::UserQuestion {
            questions,
            state: ToolFollowUpState::Pending,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_args(questions: Value) -> HashMap<String, Value> {
        let mut m = HashMap::new();
        m.insert("questions".to_string(), questions);
        m
    }

    #[test]
    fn rejects_duplicate_question_text() {
        let args = make_args(json!([
            {
                "question": "Which library?",
                "header": "Library",
                "options": [
                    {"label": "A", "description": "a"},
                    {"label": "B", "description": "b"},
                ]
            },
            {
                "question": "Which library?",
                "header": "Library",
                "options": [
                    {"label": "C", "description": "c"},
                    {"label": "D", "description": "d"},
                ]
            },
        ]));
        let (msg, is_err) = execute_ask_user_question(&args).into_legacy();
        assert!(is_err, "duplicate text should error");
        assert!(msg.contains("unique"));
    }

    #[test]
    fn rejects_duplicate_option_labels() {
        let args = make_args(json!([{
            "question": "Pick one",
            "header": "Pick",
            "options": [
                {"label": "Same", "description": "x"},
                {"label": "Same", "description": "y"},
            ]
        }]));
        let (msg, is_err) = execute_ask_user_question(&args).into_legacy();
        assert!(is_err);
        assert!(msg.contains("unique"));
    }

    #[test]
    fn accepts_multi_select_and_preview() {
        let args = make_args(json!([{
            "question": "Pick",
            "header": "Pick",
            "multiSelect": true,
            "options": [
                {"label": "A", "description": "a", "preview": "```\nexample\n```"},
                {"label": "B", "description": "b"},
            ]
        }]));
        let result = execute_ask_user_question(&args);
        let q = first_typed_question(&result).expect("typed follow-up question");
        assert!(q.multi_select);
        assert_eq!(q.options[0].preview.as_deref(), Some("```\nexample\n```"));
    }

    #[test]
    fn accepts_legacy_multi_select_spelling() {
        let args = make_args(json!([{
            "question": "Pick",
            "header": "Pick",
            "multi_select": true,
            "options": [
                {"label": "A", "description": "a"},
                {"label": "B", "description": "b"},
            ]
        }]));
        let result = execute_ask_user_question(&args);
        let q = first_typed_question(&result).expect("typed follow-up question");
        assert!(q.multi_select);
        let widget = q.widget_value();
        assert_eq!(widget["multiSelect"].as_bool(), Some(true));
        assert!(widget.get("multi_select").is_none());
    }

    /// crosslink #585: emulate the read pattern in
    /// `cli::repl::input::handle_user_questions` (post-fix): prefer
    /// `multiSelect`, fall back to `multi_select`. Both keys must yield
    /// `true` after the validator normalises the JSON.
    fn read_multi_select(q: &Value) -> bool {
        q.get("multiSelect")
            .or_else(|| q.get("multi_select"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    fn first_typed_question(result: &ToolHandlerResult) -> Option<&ToolQuestion> {
        match &result.follow_up {
            ToolFollowUp::UserQuestion { questions, .. } => questions.first(),
            _ => None,
        }
    }

    #[test]
    fn fix585_canonical_multiselect_survives_validator() {
        // crosslink #585: a caller passing the canonical `multiSelect: true`
        // must see that flag preserved (not silently dropped) in the
        // normalised output that the renderer subsequently consumes.
        let args = make_args(json!([{
            "question": "Pick",
            "header": "Pick",
            "multiSelect": true,
            "options": [
                {"label": "A", "description": "a"},
                {"label": "B", "description": "b"},
            ]
        }]));
        let result = execute_ask_user_question(&args);
        let q = first_typed_question(&result).expect("validator must emit typed question");
        let q = q.widget_value();
        assert_eq!(
            q.get("multiSelect").and_then(Value::as_bool),
            Some(true),
            "canonical multiSelect must survive validator"
        );
        assert!(
            read_multi_select(&q),
            "renderer's read pattern must observe multiSelect=true after validator"
        );
    }

    #[test]
    fn fix585_legacy_multi_select_normalised_then_read_by_renderer() {
        // crosslink #585: the legacy `multi_select` key must be canonicalised
        // to `multiSelect`, AND the renderer (which now reads `multiSelect`
        // first) must still observe `true`. Without the input.rs fix, the
        // renderer reads the legacy key and sees `None`, silently dropping
        // multi-select mode.
        let args = make_args(json!([{
            "question": "Pick",
            "header": "Pick",
            "multi_select": true,
            "options": [
                {"label": "A", "description": "a"},
                {"label": "B", "description": "b"},
            ]
        }]));
        let result = execute_ask_user_question(&args);
        let q = first_typed_question(&result).expect("validator must emit typed question");
        let q = q.widget_value();
        // The validator's contract: canonical key only, no legacy leftover.
        assert!(
            q.get("multi_select").is_none(),
            "legacy key must be removed after normalisation: {q}"
        );
        assert_eq!(
            q.get("multiSelect").and_then(Value::as_bool),
            Some(true),
            "legacy multi_select must be rewritten to multiSelect=true: {q}"
        );
        assert!(
            read_multi_select(&q),
            "renderer's read pattern must observe true after legacy→canonical rewrite"
        );
    }

    #[test]
    fn rejects_non_string_preview() {
        let args = make_args(json!([{
            "question": "Pick",
            "header": "Pick",
            "options": [
                {"label": "A", "description": "a", "preview": 42},
                {"label": "B", "description": "b"},
            ]
        }]));
        let (_, is_err) = execute_ask_user_question(&args).into_legacy();
        assert!(is_err);
    }
}
