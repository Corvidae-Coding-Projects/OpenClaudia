//! Correlated MCP elicitation for the 2026-07-28 multi round-trip protocol.
//!
//! Modern MCP servers return an `input_required` result containing a keyed
//! `inputRequests` map. The client gathers input and retries only that original
//! operation with a matching `inputResponses` map. This module owns that user
//! input boundary; transport and tool policy remain in [`crate::mcp`].

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

pub const MAX_ELICITATION_ROUNDS: usize = 8;
pub const MAX_INPUT_REQUESTS_PER_ROUND: usize = 16;
const MAX_REQUEST_STATE_BYTES: usize = 64 * 1024;
const MAX_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_FORM_SCHEMA_BYTES: usize = 64 * 1024;
const MAX_FORM_CHOICES: usize = 100;

#[derive(Debug, Error)]
pub enum ElicitationError {
    #[error("MCP input-required result is malformed: {0}")]
    Malformed(String),
    #[error("MCP input-required result requested unsupported method '{0}'")]
    UnsupportedMethod(String),
    #[error("MCP elicitation handler failed: {0}")]
    Handler(crate::secrets::SafeDiagnostic),
    #[error("MCP elicitation form response does not satisfy requestedSchema")]
    InvalidResponse,
    #[error("MCP form elicitation cannot request credentials or other sensitive values")]
    SensitiveFormField,
    #[error("MCP elicitation exceeded {MAX_ELICITATION_ROUNDS} rounds")]
    TooManyRounds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ElicitationMode {
    Form,
    Url,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ElicitationAction {
    Accept(Value),
    /// URL navigation was explicitly approved. No content returns through MCP.
    AcceptUrl,
    Decline,
    Cancel,
}

#[derive(Debug, Clone)]
pub struct ElicitationRequest {
    pub server_name: String,
    pub operation_id: String,
    pub request_key: String,
    pub round: usize,
    pub mode: ElicitationMode,
    pub message: String,
    pub requested_schema: Option<Value>,
    pub url: Option<url::Url>,
}

#[async_trait]
pub trait McpElicitationHandler: Send + Sync {
    async fn handle(&self, request: ElicitationRequest) -> anyhow::Result<ElicitationAction>;
}

/// Safe headless owner. It never invents user input or opens a URL.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopElicitationHandler;

#[async_trait]
impl McpElicitationHandler for NoopElicitationHandler {
    async fn handle(&self, request: ElicitationRequest) -> anyhow::Result<ElicitationAction> {
        tracing::debug!(
            server = %request.server_name,
            operation_id = %request.operation_id,
            request_key = %request.request_key,
            round = request.round,
            "MCP elicitation reached a non-interactive owner; cancelling"
        );
        Ok(ElicitationAction::Cancel)
    }
}

/// Cloneable handler owner installed into every connection for one manager.
#[derive(Clone)]
pub struct McpElicitationRouter {
    handler: Arc<dyn McpElicitationHandler>,
}

impl std::fmt::Debug for McpElicitationRouter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpElicitationRouter")
            .finish_non_exhaustive()
    }
}

impl Default for McpElicitationRouter {
    fn default() -> Self {
        Self::new(Arc::new(NoopElicitationHandler))
    }
}

impl McpElicitationRouter {
    #[must_use]
    pub const fn new(handler: Arc<dyn McpElicitationHandler>) -> Self {
        Self { handler }
    }

    #[must_use]
    pub fn client_capability(&self) -> Value {
        serde_json::json!({"form": {}, "url": {}})
    }

    /// Resolve one modern `input_required` result into an exact keyed response
    /// map. State stays local to the caller, so concurrent operations cannot
    /// overwrite one another.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed or unsupported requests, handler
    /// failures, invalid responses, sensitive forms, or excess rounds.
    pub async fn resolve_round(
        &self,
        server_name: &str,
        operation_id: &str,
        round: usize,
        result: &Value,
        sanitize: impl Fn(&str) -> crate::secrets::SafeDiagnostic,
    ) -> Result<ResolvedInputRound, ElicitationError> {
        if round >= MAX_ELICITATION_ROUNDS {
            return Err(ElicitationError::TooManyRounds);
        }
        let object = result
            .as_object()
            .ok_or_else(|| ElicitationError::Malformed("result must be an object".to_string()))?;
        let request_state = object
            .get("requestState")
            .map(|value| {
                let value = value.as_str().ok_or_else(|| {
                    ElicitationError::Malformed("requestState must be a string".to_string())
                })?;
                if value.len() > MAX_REQUEST_STATE_BYTES {
                    return Err(ElicitationError::Malformed(
                        "requestState exceeds the 64 KiB limit".to_string(),
                    ));
                }
                Ok(value.to_string())
            })
            .transpose()?;
        let requests = object.get("inputRequests").map_or_else(
            || Ok(BTreeMap::new()),
            |value| {
                serde_json::from_value::<BTreeMap<String, RawInputRequest>>(value.clone()).map_err(
                    |_| {
                        ElicitationError::Malformed(
                            "inputRequests must be a string-keyed request map".to_string(),
                        )
                    },
                )
            },
        )?;
        if requests.is_empty() && request_state.is_none() {
            return Err(ElicitationError::Malformed(
                "input_required must include inputRequests or requestState".to_string(),
            ));
        }
        if requests.len() > MAX_INPUT_REQUESTS_PER_ROUND {
            return Err(ElicitationError::Malformed(format!(
                "inputRequests exceeds the {MAX_INPUT_REQUESTS_PER_ROUND}-request limit"
            )));
        }

        let mut responses = Map::new();
        for (request_key, raw) in requests {
            validate_request_key(&request_key)?;
            if raw.method != "elicitation/create" {
                return Err(ElicitationError::UnsupportedMethod(raw.method));
            }
            let request = parse_elicitation_request(
                server_name,
                operation_id,
                request_key.clone(),
                round,
                &raw.params,
            )?;
            let requested_schema = request.requested_schema.clone();
            let mode = request.mode;
            let action = self
                .handler
                .handle(request)
                .await
                .map_err(|error| ElicitationError::Handler(sanitize(&error.to_string())))?;
            responses.insert(
                request_key,
                action_to_response_checked(mode, requested_schema.as_ref(), action)?,
            );
        }

        Ok(ResolvedInputRound {
            input_responses: Value::Object(responses),
            request_state,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedInputRound {
    pub input_responses: Value,
    pub request_state: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInputRequest {
    method: String,
    #[serde(default)]
    params: Value,
}

fn validate_request_key(key: &str) -> Result<(), ElicitationError> {
    if key.is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
        return Err(ElicitationError::Malformed(
            "inputRequests contains an invalid request key".to_string(),
        ));
    }
    Ok(())
}

fn parse_elicitation_request(
    server_name: &str,
    operation_id: &str,
    request_key: String,
    round: usize,
    params: &Value,
) -> Result<ElicitationRequest, ElicitationError> {
    let params = params.as_object().ok_or_else(|| {
        ElicitationError::Malformed("elicitation params must be an object".to_string())
    })?;
    let message = params
        .get("message")
        .and_then(Value::as_str)
        .filter(|message| !message.is_empty() && message.len() <= MAX_MESSAGE_BYTES)
        .ok_or_else(|| {
            ElicitationError::Malformed("elicitation message must be 1..=16384 bytes".to_string())
        })?
        .to_string();
    let mode = match params.get("mode").and_then(Value::as_str) {
        None | Some("form") => ElicitationMode::Form,
        Some("url") => ElicitationMode::Url,
        Some(_) => {
            return Err(ElicitationError::Malformed(
                "elicitation mode must be 'form' or 'url'".to_string(),
            ));
        }
    };
    let (requested_schema, url) = match mode {
        ElicitationMode::Form => {
            let schema = params.get("requestedSchema").cloned().ok_or_else(|| {
                ElicitationError::Malformed(
                    "form elicitation is missing requestedSchema".to_string(),
                )
            })?;
            validate_form_schema(&schema)?;
            (Some(schema), None)
        }
        ElicitationMode::Url => {
            let raw = params.get("url").and_then(Value::as_str).ok_or_else(|| {
                ElicitationError::Malformed("URL elicitation is missing url".to_string())
            })?;
            let parsed = url::Url::parse(raw).map_err(|_| {
                ElicitationError::Malformed("URL elicitation contains an invalid URL".to_string())
            })?;
            if !matches!(parsed.scheme(), "https" | "http") {
                return Err(ElicitationError::Malformed(
                    "URL elicitation must use http or https".to_string(),
                ));
            }
            (None, Some(parsed))
        }
    };
    Ok(ElicitationRequest {
        server_name: server_name.to_string(),
        operation_id: operation_id.to_string(),
        request_key,
        round,
        mode,
        message,
        requested_schema,
        url,
    })
}

fn validate_form_schema(schema: &Value) -> Result<(), ElicitationError> {
    if serde_json::to_vec(schema)
        .map_err(|_| ElicitationError::Malformed("requestedSchema is invalid".to_string()))?
        .len()
        > MAX_FORM_SCHEMA_BYTES
    {
        return Err(ElicitationError::Malformed(
            "requestedSchema exceeds the 64 KiB limit".to_string(),
        ));
    }
    let object = schema.as_object().ok_or_else(|| {
        ElicitationError::Malformed("requestedSchema must be an object".to_string())
    })?;
    if object.get("type").and_then(Value::as_str) != Some("object") {
        return Err(ElicitationError::Malformed(
            "requestedSchema root must declare type 'object'".to_string(),
        ));
    }
    let properties = object
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ElicitationError::Malformed(
                "requestedSchema must contain an object properties map".to_string(),
            )
        })?;
    if properties.len() > 32 {
        return Err(ElicitationError::Malformed(
            "requestedSchema exceeds 32 form fields".to_string(),
        ));
    }
    for (name, property) in properties {
        if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            return Err(ElicitationError::Malformed(
                "requestedSchema contains an invalid property name".to_string(),
            ));
        }
        let Some(property) = property.as_object() else {
            return Err(ElicitationError::Malformed(
                "requestedSchema properties must be schema objects".to_string(),
            ));
        };
        if form_field_is_sensitive(name, property) {
            return Err(ElicitationError::SensitiveFormField);
        }
        validate_form_property(property)?;
    }
    jsonschema::draft202012::new(schema).map_err(|_| {
        ElicitationError::Malformed("requestedSchema is not valid JSON Schema".to_string())
    })?;
    Ok(())
}

fn validate_form_property(property: &Map<String, Value>) -> Result<(), ElicitationError> {
    if [
        "$ref",
        "properties",
        "additionalProperties",
        "allOf",
        "not",
        "if",
        "then",
        "else",
    ]
    .iter()
    .any(|keyword| property.contains_key(*keyword))
    {
        return Err(ElicitationError::Malformed(
            "requestedSchema contains a nested or unsupported form field".to_string(),
        ));
    }
    match property.get("type").and_then(Value::as_str) {
        Some("string") => {
            if property
                .get("format")
                .and_then(Value::as_str)
                .is_some_and(|format| !matches!(format, "email" | "uri" | "date" | "date-time"))
            {
                return Err(ElicitationError::Malformed(
                    "requestedSchema uses an unsupported string format".to_string(),
                ));
            }
            validate_form_choices(property, &["enum", "oneOf"])
        }
        Some("number" | "integer" | "boolean") => {
            validate_form_choices(property, &["enum", "oneOf"])
        }
        Some("array") => validate_form_array(property),
        None if property.contains_key("oneOf") => validate_form_choices(property, &["oneOf"]),
        _ => Err(ElicitationError::Malformed(
            "requestedSchema contains a non-primitive form field".to_string(),
        )),
    }
}

fn validate_form_array(property: &Map<String, Value>) -> Result<(), ElicitationError> {
    let items = property
        .get("items")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ElicitationError::Malformed("array form fields must declare enum items".to_string())
        })?;
    if items
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind != "string")
    {
        return Err(ElicitationError::Malformed(
            "array form fields may only contain string enum values".to_string(),
        ));
    }
    if !items.contains_key("enum") && !items.contains_key("anyOf") {
        return Err(ElicitationError::Malformed(
            "array form fields must contain enum or anyOf choices".to_string(),
        ));
    }
    validate_form_choices(items, &["enum", "anyOf"])
}

fn validate_form_choices(
    property: &Map<String, Value>,
    allowed_keywords: &[&str],
) -> Result<(), ElicitationError> {
    for keyword in ["enum", "oneOf", "anyOf"] {
        let Some(choices) = property.get(keyword) else {
            continue;
        };
        if !allowed_keywords.contains(&keyword) {
            return Err(ElicitationError::Malformed(
                "requestedSchema uses choices unsupported for this form field".to_string(),
            ));
        }
        let choices = choices
            .as_array()
            .filter(|choices| !choices.is_empty() && choices.len() <= MAX_FORM_CHOICES);
        let Some(choices) = choices else {
            return Err(ElicitationError::Malformed(
                "requestedSchema choices must contain 1..=100 entries".to_string(),
            ));
        };
        let valid = if keyword == "enum" {
            choices.iter().all(value_is_form_scalar)
        } else {
            choices.iter().all(|choice| {
                choice.as_object().is_some_and(|choice| {
                    choice.get("const").is_some_and(value_is_form_scalar)
                        && choice.get("title").is_none_or(serde_json::Value::is_string)
                })
            })
        };
        if !valid {
            return Err(ElicitationError::Malformed(
                "requestedSchema choices must contain scalar values".to_string(),
            ));
        }
    }
    Ok(())
}

fn value_is_form_scalar(value: &Value) -> bool {
    value.is_string() || value.is_number() || value.is_boolean()
}

fn form_field_is_sensitive(name: &str, property: &Map<String, Value>) -> bool {
    const SENSITIVE_NAMES: &[&str] = &[
        "password",
        "passwd",
        "passphrase",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "private_key",
        "credit_card",
        "card_number",
        "cvv",
        "cvc",
    ];
    let normalized_name = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    if SENSITIVE_NAMES.contains(&normalized_name.as_str())
        || property.get("writeOnly").and_then(Value::as_bool) == Some(true)
        || matches!(
            property.get("format").and_then(Value::as_str),
            Some("password" | "secret" | "credential")
        )
    {
        return true;
    }
    property
        .get("title")
        .and_then(Value::as_str)
        .into_iter()
        .chain(property.get("description").and_then(Value::as_str))
        .any(|text| {
            let text = text.to_ascii_lowercase();
            [
                "password",
                "passphrase",
                "api key",
                "access token",
                "refresh token",
                "private key",
                "credit card",
            ]
            .iter()
            .any(|needle| text.contains(needle))
        })
}

fn action_to_response_checked(
    mode: ElicitationMode,
    schema: Option<&Value>,
    action: ElicitationAction,
) -> Result<Value, ElicitationError> {
    match (mode, action) {
        (ElicitationMode::Form, ElicitationAction::Accept(content)) => {
            let schema = schema.ok_or_else(|| {
                ElicitationError::Malformed("form response lost its schema".to_string())
            })?;
            let validator = jsonschema::draft202012::new(schema)
                .map_err(|_| ElicitationError::InvalidResponse)?;
            if !validator.is_valid(&content) {
                return Err(ElicitationError::InvalidResponse);
            }
            Ok(serde_json::json!({"action": "accept", "content": content}))
        }
        (ElicitationMode::Url, ElicitationAction::AcceptUrl) => {
            Ok(serde_json::json!({"action": "accept"}))
        }
        (_, ElicitationAction::Decline) => Ok(serde_json::json!({"action": "decline"})),
        (_, ElicitationAction::Cancel) => Ok(serde_json::json!({"action": "cancel"})),
        _ => Err(ElicitationError::InvalidResponse),
    }
}

/// Historical helper retained for legacy nested-request response call sites.
#[must_use]
pub fn action_to_response(action: &ElicitationAction) -> Value {
    match action {
        ElicitationAction::Accept(content) => {
            serde_json::json!({"action": "accept", "content": content})
        }
        ElicitationAction::AcceptUrl => serde_json::json!({"action": "accept"}),
        ElicitationAction::Decline => serde_json::json!({"action": "decline"}),
        ElicitationAction::Cancel => serde_json::json!({"action": "cancel"}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingHandler {
        seen: Mutex<Vec<(String, String, usize)>>,
    }

    #[async_trait]
    impl McpElicitationHandler for RecordingHandler {
        async fn handle(&self, request: ElicitationRequest) -> anyhow::Result<ElicitationAction> {
            self.seen.lock().expect("seen").push((
                request.operation_id,
                request.request_key,
                request.round,
            ));
            Ok(match request.mode {
                ElicitationMode::Form => {
                    ElicitationAction::Accept(serde_json::json!({"name": "octocat"}))
                }
                ElicitationMode::Url => ElicitationAction::AcceptUrl,
            })
        }
    }

    fn form_result(state: &str) -> Value {
        serde_json::json!({
            "resultType": "input_required",
            "inputRequests": {
                "github": {
                    "method": "elicitation/create",
                    "params": {
                        "mode": "form",
                        "message": "GitHub name",
                        "requestedSchema": {
                            "type": "object",
                            "properties": {"name": {"type": "string"}},
                            "required": ["name"]
                        }
                    }
                }
            },
            "requestState": state
        })
    }

    #[tokio::test]
    async fn resolves_keyed_form_and_echoes_opaque_state() {
        let handler = Arc::new(RecordingHandler::default());
        let router = McpElicitationRouter::new(handler.clone());
        let round = router
            .resolve_round("github", "operation-a", 2, &form_result("opaque"), |text| {
                crate::secrets::SafeDiagnostic::from_untrusted(text)
            })
            .await
            .expect("resolve");
        assert_eq!(round.request_state.as_deref(), Some("opaque"));
        assert_eq!(round.input_responses["github"]["action"], "accept");
        assert_eq!(
            round.input_responses["github"]["content"]["name"],
            "octocat"
        );
        assert_eq!(
            handler.seen.lock().expect("seen").as_slice(),
            &[("operation-a".to_string(), "github".to_string(), 2)]
        );
    }

    #[tokio::test]
    async fn concurrent_rounds_keep_operation_identity_separate() {
        let handler = Arc::new(RecordingHandler::default());
        let router = McpElicitationRouter::new(handler.clone());
        let left_result = form_result("left-state");
        let right_result = form_result("right-state");
        let left = router.resolve_round("server", "left", 0, &left_result, |text| {
            crate::secrets::SafeDiagnostic::from_untrusted(text)
        });
        let right = router.resolve_round("server", "right", 0, &right_result, |text| {
            crate::secrets::SafeDiagnostic::from_untrusted(text)
        });
        let (left, right) = tokio::join!(left, right);
        assert_eq!(
            left.expect("left").request_state.as_deref(),
            Some("left-state")
        );
        assert_eq!(
            right.expect("right").request_state.as_deref(),
            Some("right-state")
        );
        let mut operations = handler
            .seen
            .lock()
            .expect("seen")
            .iter()
            .map(|entry| entry.0.clone())
            .collect::<Vec<_>>();
        operations.sort();
        assert_eq!(operations, ["left", "right"]);
    }

    #[tokio::test]
    async fn invalid_form_response_is_rejected_before_retry() {
        struct Invalid;
        #[async_trait]
        impl McpElicitationHandler for Invalid {
            async fn handle(
                &self,
                _request: ElicitationRequest,
            ) -> anyhow::Result<ElicitationAction> {
                Ok(ElicitationAction::Accept(serde_json::json!({"name": 7})))
            }
        }
        let router = McpElicitationRouter::new(Arc::new(Invalid));
        let error = router
            .resolve_round("server", "op", 0, &form_result("state"), |text| {
                crate::secrets::SafeDiagnostic::from_untrusted(text)
            })
            .await
            .expect_err("invalid content");
        assert!(matches!(error, ElicitationError::InvalidResponse));
    }

    #[tokio::test]
    async fn noop_cancels_without_fabricating_content() {
        let router = McpElicitationRouter::default();
        let resolved = router
            .resolve_round("server", "op", 0, &form_result("state"), |text| {
                crate::secrets::SafeDiagnostic::from_untrusted(text)
            })
            .await
            .expect("cancel");
        assert_eq!(resolved.input_responses["github"]["action"], "cancel");
        assert!(resolved.input_responses["github"].get("content").is_none());
    }

    #[tokio::test]
    async fn unsupported_nested_method_is_rejected() {
        let router = McpElicitationRouter::default();
        let result = serde_json::json!({
            "resultType": "input_required",
            "inputRequests": {"x": {"method": "sampling/createMessage", "params": {}}}
        });
        assert!(matches!(
            router
                .resolve_round("server", "op", 0, &result, |text| {
                    crate::secrets::SafeDiagnostic::from_untrusted(text)
                })
                .await,
            Err(ElicitationError::UnsupportedMethod(_))
        ));
    }

    #[tokio::test]
    async fn form_elicitation_rejects_obvious_credential_fields() {
        let router = McpElicitationRouter::default();
        let result = serde_json::json!({
            "resultType": "input_required",
            "inputRequests": {
                "credential": {
                    "method": "elicitation/create",
                    "params": {
                        "message": "Enter a credential",
                        "requestedSchema": {
                            "type": "object",
                            "properties": {
                                "password": {"type": "string", "format": "password"}
                            }
                        }
                    }
                }
            }
        });
        let error = router
            .resolve_round("server", "operation", 0, &result, |text| {
                crate::secrets::SafeDiagnostic::from_untrusted(text)
            })
            .await
            .expect_err("credential form must be rejected");
        assert!(matches!(error, ElicitationError::SensitiveFormField));
    }

    #[tokio::test]
    async fn url_accept_never_carries_content() {
        let router = McpElicitationRouter::new(Arc::new(RecordingHandler::default()));
        let result = serde_json::json!({
            "resultType": "input_required",
            "inputRequests": {
                "connect": {
                    "method": "elicitation/create",
                    "params": {
                        "mode": "url",
                        "message": "Connect an external service",
                        "url": "https://mcp.example.test/connect"
                    }
                }
            }
        });
        let resolved = router
            .resolve_round("server", "op", 0, &result, |text| {
                crate::secrets::SafeDiagnostic::from_untrusted(text)
            })
            .await
            .expect("url");
        assert_eq!(
            resolved.input_responses["connect"],
            serde_json::json!({"action": "accept"})
        );
    }
}
