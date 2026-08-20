//! Shared `OpenAI`-compatible adapter for providers that accept Chat Completions
//! requests on the wire (`OpenAI`, `DeepSeek`, Qwen, Z.AI/GLM,
//! Kimi/Moonshot, `MiniMax`, plus the generic `LM Studio` / `LocalAI` /
//! `text-generation-webui` fallbacks).
//!
//! These upstream services accept the same canonical `OpenAI`
//! `ChatCompletionRequest` body and return responses in `OpenAI` shape.
//! They differ only on:
//!
//! - the provider `name`,
//! - the chat-completions URL suffix (most use `/v1/chat/completions`;
//!   `DeepSeek` and `Z.AI` use `/chat/completions` because their public base URLs
//!   do not want an extra `/v1` in the adapter path),
//! - the thinking/reasoning toggle keyed into the request body
//!   (different providers spell the toggle differently — `enable_thinking`,
//!   `thinking: { type: enabled }`, `reasoning_effort`, etc.),
//! - whether `/v1/models` listing is supported.
//!
//! Rather than carry near-identical copies of `ProviderAdapter`
//! impls, those variations are parameterized on this struct.
//!
//! Behavioural preservation: every request emitted by this adapter is
//! byte-identical to what the prior per-provider adapter produced. See
//! crosslink #281.

use async_trait::async_trait;
use serde_json::{json, Value};
use tracing::{debug, warn};

use crate::config::ThinkingConfig;
use crate::proxy::ChatCompletionRequest;

use super::{ApiKey, ProviderAdapter, ProviderError};

/// How the provider expects the "thinking mode" toggle to be encoded in
/// the request body.
///
/// Each variant captures the exact JSON shape the corresponding upstream
/// API expects. The variants are chosen narrowly: keeping a discriminated
/// enum (rather than `fn(&mut Value, &ThinkingConfig, &str)`) keeps the
/// behavioural matrix inspectable in one place, keeps the per-adapter
/// constructors `const fn`, and avoids handing out raw function pointers.
#[derive(Debug, Clone, Copy)]
pub(super) enum ThinkingInjector {
    /// `OpenAI` reasoning-family models.
    ///
    /// Sets `reasoning_effort` to the configured value (default
    /// `"medium"`) if and only if `thinking.enabled` is true AND the
    /// target model is in the reasoning family. Non-reasoning models
    /// (e.g. `gpt-4`) get no change — matching prior `OpenAIAdapter`
    /// behaviour.
    OpenAiReasoningEffort,
    /// `DeepSeek` V4 thinking controls.
    ///
    /// Sets `thinking: {type:"enabled"|"disabled"}`. When enabled, also
    /// sets `reasoning_effort` to `high` or `max`.
    DeepSeekThinking,
    /// Qwen `QwQ` / Alibaba.
    ///
    /// Always sets `enable_thinking` to the value of `thinking.enabled`
    /// (i.e. `false` is explicitly written, unlike `DeepSeek`). This
    /// matches prior `QwenAdapter` behaviour.
    QwenEnableThinking,
    /// Z.AI / GLM.
    ///
    /// Sets the `thinking` object to `{type:"enabled"}` or
    /// `{type:"disabled"}`. When enabled and `preserve_across_turns` is
    /// set, also emits `thinking.clear_thinking: false`. For `GLM-5.2`,
    /// also forwards `reasoning_effort`.
    GlmThinking,
    /// `MiniMax-M3` thinking controls.
    ///
    /// Sets `thinking: {type:"adaptive"|"disabled"}` for `MiniMax-M3` and
    /// requests split reasoning output when thinking is enabled.
    MiniMaxThinking,
    /// Kimi K2 thinking controls.
    ///
    /// Emits Kimi's documented `thinking` object only for models where the
    /// server accepts it. K2.7 code models always think and reject disabled
    /// thinking, so they intentionally receive no explicit thinking field.
    KimiThinking,
}

impl ThinkingInjector {
    /// Mutates `body` to add the provider-specific thinking parameters.
    ///
    /// Pre-condition: `body` is the value produced by
    /// `serde_json::to_value(request)` (an object). The `model` argument
    /// is supplied for variants that gate behaviour on the model name
    /// (currently only `OpenAiReasoningEffort`).
    #[allow(clippy::too_many_lines)]
    fn inject(self, body: &mut Value, thinking: &ThinkingConfig, model: &str) {
        match self {
            Self::OpenAiReasoningEffort => {
                if thinking.enabled {
                    let effort = openai_reasoning_effort(thinking.reasoning_effort.as_deref());
                    if is_openai_reasoning_model(model) {
                        body["reasoning_effort"] = json!(effort);
                        debug!("Added OpenAI reasoning params: effort={}", effort);
                    } else {
                        // Crosslink #779: previously a `debug!` log silently
                        // swallowed the user's `reasoning_effort` config for
                        // non-reasoning models. Operators who set
                        // `effort=high` for `gpt-4` had no signal their
                        // request was downgraded. Now we surface it as a
                        // warning that names both the model and the ignored
                        // effort value.
                        warn!(
                            model = %model,
                            ignored_reasoning_effort = %effort,
                            "ignoring reasoning_effort: model is not in the OpenAI reasoning family — \
                             configured thinking is a no-op for this model",
                        );
                    }
                }
            }
            Self::DeepSeekThinking => {
                if thinking.enabled {
                    let effort = deepseek_reasoning_effort(thinking.reasoning_effort.as_deref());
                    body["thinking"] = json!({ "type": "enabled" });
                    body["reasoning_effort"] = json!(effort);
                    debug!("Added DeepSeek thinking params: enabled=true, effort={effort}");
                } else {
                    body["thinking"] = json!({ "type": "disabled" });
                }
            }
            Self::QwenEnableThinking => {
                if thinking.enabled {
                    body["enable_thinking"] = json!(true);
                    debug!("Added Qwen thinking params: enable_thinking=true");
                } else {
                    body["enable_thinking"] = json!(false);
                }
            }
            Self::GlmThinking => {
                if thinking.enabled {
                    body["thinking"] = json!({ "type": "enabled" });
                    if thinking.preserve_across_turns {
                        body["thinking"]["clear_thinking"] = json!(false);
                    }
                    if is_zai_reasoning_effort_model(model) {
                        let effort = zai_reasoning_effort(thinking.reasoning_effort.as_deref());
                        body["reasoning_effort"] = json!(effort);
                    }
                    debug!(
                        "Added GLM thinking params: enabled=true, preserve={}",
                        thinking.preserve_across_turns
                    );
                } else {
                    body["thinking"] = json!({ "type": "disabled" });
                }
            }
            Self::MiniMaxThinking => {
                if is_minimax_m3_model(model) {
                    if thinking.enabled {
                        body["thinking"] = json!({ "type": "adaptive" });
                        body["reasoning_split"] = json!(true);
                    } else {
                        body["thinking"] = json!({ "type": "disabled" });
                    }
                } else if !thinking.enabled {
                    warn!(
                        model = %model,
                        "MiniMax thinking disable requested for a model whose OpenAI-compatible \
                         API keeps thinking enabled",
                    );
                }
            }
            Self::KimiThinking => {
                if is_kimi_k27_code_model(model) {
                    if !thinking.enabled {
                        warn!(
                            model = %model,
                            "Kimi K2.7 Code always thinks and rejects thinking.type=disabled; \
                             omitting unsupported thinking override",
                        );
                    }
                } else if is_kimi_k26_model(model) {
                    if thinking.enabled {
                        body["thinking"] = json!({ "type": "enabled" });
                        if thinking.preserve_across_turns {
                            body["thinking"]["keep"] = json!("all");
                        }
                    } else {
                        body["thinking"] = json!({ "type": "disabled" });
                    }
                } else if is_kimi_k25_model(model) {
                    if thinking.enabled {
                        body["thinking"] = json!({ "type": "enabled" });
                        if thinking.preserve_across_turns {
                            warn!(
                                model = %model,
                                "Kimi K2.5 does not support preserved thinking; omitting thinking.keep",
                            );
                        }
                    } else {
                        body["thinking"] = json!({ "type": "disabled" });
                    }
                } else if thinking.enabled && has_explicit_kimi_thinking_option(thinking) {
                    warn!(
                        model = %model,
                        "Kimi/Moonshot thinking requested for a model without documented thinking controls; \
                         omitting unsupported thinking field",
                    );
                }
            }
        }
    }
}

fn is_openai_reasoning_model(model: &str) -> bool {
    let model = model.to_ascii_lowercase();
    ["o1", "o3", "o4", "gpt-5"]
        .iter()
        .any(|family| is_model_family(&model, family))
}

fn openai_reasoning_effort(effort: Option<&str>) -> &'static str {
    match effort.map(str::to_ascii_lowercase).as_deref() {
        Some("none") => "none",
        Some("low") => "low",
        Some("high") => "high",
        Some("max" | "xhigh") => "xhigh",
        _ => "medium",
    }
}

fn deepseek_reasoning_effort(effort: Option<&str>) -> &'static str {
    match effort {
        Some("max" | "xhigh") => "max",
        _ => "high",
    }
}

fn zai_reasoning_effort(effort: Option<&str>) -> &'static str {
    match effort {
        Some("none") => "none",
        Some("minimal") => "minimal",
        Some("low" | "medium" | "high") => "high",
        _ => "max",
    }
}

const fn is_zai_reasoning_effort_model(model: &str) -> bool {
    model.eq_ignore_ascii_case("glm-5.2")
}

const fn is_minimax_m3_model(model: &str) -> bool {
    model.eq_ignore_ascii_case("MiniMax-M3")
}

fn is_kimi_k27_code_model(model: &str) -> bool {
    let model = model.to_ascii_lowercase();
    model == "kimi-k2.7-code" || model == "kimi-k2.7-code-highspeed"
}

const fn is_kimi_k26_model(model: &str) -> bool {
    model.eq_ignore_ascii_case("kimi-k2.6")
}

const fn is_kimi_k25_model(model: &str) -> bool {
    model.eq_ignore_ascii_case("kimi-k2.5")
}

const fn has_explicit_kimi_thinking_option(thinking: &ThinkingConfig) -> bool {
    thinking.budget_tokens.is_some()
        || thinking.reasoning_effort.is_some()
        || thinking.preserve_across_turns
}

fn is_model_family(model: &str, family: &str) -> bool {
    if model == family {
        return true;
    }

    model
        .strip_prefix(family)
        .is_some_and(|suffix| suffix.starts_with('-') || suffix.starts_with('.'))
}

/// Shared `OpenAI`-compatible adapter parameterized on the provider's
/// name, endpoint, thinking-mode encoding, and capabilities.
///
/// Provider-specific adapters (`OpenAIAdapter`, `DeepSeekAdapter`,
/// `QwenAdapter`, `ZaiAdapter`, `KimiAdapter`, and `MiniMaxAdapter`) are
/// thin newtypes around an instance of this struct.
pub(super) struct OpenAiCompatibleAdapter {
    name: &'static str,
    /// Path returned from [`ProviderAdapter::chat_endpoint`]. Stored as
    /// `&'static str` (rather than a closure) because every observed
    /// variation is a string constant — most providers use
    /// `/v1/chat/completions`; `DeepSeek` and `Z.AI` use `/chat/completions`.
    chat_path: &'static str,
    thinking: ThinkingInjector,
    supports_models: bool,
}

impl OpenAiCompatibleAdapter {
    pub(super) const fn new(
        name: &'static str,
        chat_path: &'static str,
        thinking: ThinkingInjector,
        supports_models: bool,
    ) -> Self {
        Self {
            name,
            chat_path,
            thinking,
            supports_models,
        }
    }
}

#[async_trait]
impl ProviderAdapter for OpenAiCompatibleAdapter {
    fn name(&self) -> &str {
        self.name
    }

    fn transform_request(&self, request: &ChatCompletionRequest) -> Result<Value, ProviderError> {
        // OpenAI Chat Completions is our canonical wire format, so the
        // body is just the serialized request.
        serde_json::to_value(request).map_err(|e| ProviderError::RequestFailed(e.to_string()))
    }

    fn transform_request_with_thinking(
        &self,
        request: &ChatCompletionRequest,
        thinking: &ThinkingConfig,
    ) -> Result<Value, ProviderError> {
        let mut body = serde_json::to_value(request)
            .map_err(|e| ProviderError::RequestFailed(e.to_string()))?;
        self.thinking.inject(&mut body, thinking, &request.model);
        Ok(body)
    }

    fn transform_response(&self, response: Value, stream: bool) -> Result<Value, ProviderError> {
        // All OpenAI-compatible providers return responses already in
        // OpenAI shape. `reasoning_content` (when present) is carried
        // through verbatim for DeepSeek/Qwen/Z.AI thinking output.
        if !stream {
            validate_openai_chat_response(self.name, &response)?;
        }
        Ok(response)
    }

    fn chat_endpoint(&self, _model: &str) -> String {
        self.chat_path.to_string()
    }

    fn get_headers(&self, api_key: &ApiKey) -> crate::secrets::SensitiveHeaders {
        let mut headers = crate::secrets::SensitiveHeaders::new();
        headers.insert_header_bearer(reqwest::header::AUTHORIZATION, api_key.secret());
        headers.insert_static_literal(reqwest::header::CONTENT_TYPE, "application/json");
        headers
    }

    fn supports_model_listing(&self) -> bool {
        self.supports_models
    }
}

fn validate_openai_chat_response(provider: &str, response: &Value) -> Result<(), ProviderError> {
    let choices = response
        .get("choices")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProviderError::InvalidResponse(format!(
                "{provider} response missing required 'choices' array"
            ))
        })?;

    if choices.is_empty() {
        return Err(ProviderError::InvalidResponse(format!(
            "{provider} response contains empty 'choices' array"
        )));
    }

    for (choice_index, choice) in choices.iter().enumerate() {
        if !choice.is_object() {
            return Err(ProviderError::InvalidResponse(format!(
                "{provider} response choices[{choice_index}] must be an object"
            )));
        }

        let message = choice
            .get("message")
            .filter(|message| message.is_object())
            .ok_or_else(|| {
                ProviderError::InvalidResponse(format!(
                    "{provider} response choices[{choice_index}] missing object 'message'"
                ))
            })?;

        message
            .get("role")
            .and_then(Value::as_str)
            .filter(|role| !role.is_empty())
            .ok_or_else(|| {
                ProviderError::InvalidResponse(format!(
                    "{provider} response choices[{choice_index}].message.role must be a \
                     non-empty string"
                ))
            })?;

        let has_content = match message.get("content") {
            Some(Value::String(_)) => true,
            Some(Value::Null) | None => false,
            Some(_) => {
                return Err(ProviderError::InvalidResponse(format!(
                    "{provider} response choices[{choice_index}].message.content must be a string or null"
                )));
            }
        };

        let has_tool_calls = match message.get("tool_calls") {
            Some(tool_calls) if tool_calls.is_array() => true,
            Some(_) => {
                return Err(ProviderError::InvalidResponse(format!(
                    "{provider} response choices[{choice_index}].message.tool_calls must be an array"
                )));
            }
            None => false,
        };

        let has_refusal = message
            .get("refusal")
            .and_then(Value::as_str)
            .is_some_and(|refusal| !refusal.is_empty());

        if !has_content && !has_tool_calls && !has_refusal {
            return Err(ProviderError::InvalidResponse(format!(
                "{provider} response choices[{choice_index}].message must contain string \
                 content, tool_calls, or a non-empty refusal"
            )));
        }

        if let Some(finish_reason) = choice.get("finish_reason") {
            if !finish_reason.is_string() && !finish_reason.is_null() {
                return Err(ProviderError::InvalidResponse(format!(
                    "{provider} response choices[{choice_index}].finish_reason must be a string or null"
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    //! Behaviour-preservation tests for the shared adapter.
    //!
    //! Each test pins the JSON shape that the prior per-provider adapter
    //! emitted, so any regression in the shared transform is caught
    //! independently of the provider-level test surface in `mod.rs`.

    use super::*;
    use crate::proxy::{ChatMessage, MessageContent};
    use std::collections::HashMap;

    fn req(model: &str) -> ChatCompletionRequest {
        ChatCompletionRequest {
            model: model.to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: MessageContent::Text("hi".to_string()),
                name: None,
                tool_calls: None,
                tool_call_id: None,
                extra: std::collections::HashMap::new(),
            }],
            temperature: None,
            max_tokens: None,
            stream: None,
            tools: None,
            tool_choice: None,
            extra: HashMap::new(),
        }
    }

    fn thinking_on() -> ThinkingConfig {
        ThinkingConfig {
            enabled: true,
            budget_tokens: None,
            preserve_across_turns: false,
            reasoning_effort: None,
            adaptive: true,
        }
    }

    fn thinking_off() -> ThinkingConfig {
        ThinkingConfig {
            enabled: false,
            ..thinking_on()
        }
    }

    #[test]
    fn openai_reasoning_effort_set_for_reasoning_model() {
        let injector = ThinkingInjector::OpenAiReasoningEffort;
        let mut body = serde_json::to_value(req("o3-mini")).unwrap();
        injector.inject(&mut body, &thinking_on(), "o3-mini");
        assert_eq!(body["reasoning_effort"], "medium");
    }

    #[test]
    fn openai_reasoning_effort_honours_configured_level() {
        let mut t = thinking_on();
        t.reasoning_effort = Some("high".to_string());
        let mut body = serde_json::to_value(req("o1-preview")).unwrap();
        ThinkingInjector::OpenAiReasoningEffort.inject(&mut body, &t, "o1-preview");
        assert_eq!(body["reasoning_effort"], "high");
    }

    #[test]
    fn openai_reasoning_effort_maps_max_alias_to_xhigh() {
        let mut t = thinking_on();
        t.reasoning_effort = Some("max".to_string());
        let mut body = serde_json::to_value(req("gpt-5.5")).unwrap();
        ThinkingInjector::OpenAiReasoningEffort.inject(&mut body, &t, "gpt-5.5");
        assert_eq!(body["reasoning_effort"], "xhigh");
    }

    #[test]
    fn openai_reasoning_effort_accepts_current_extremes() {
        let mut none = thinking_on();
        none.reasoning_effort = Some("none".to_string());
        let mut none_body = serde_json::to_value(req("gpt-5.5")).unwrap();
        ThinkingInjector::OpenAiReasoningEffort.inject(&mut none_body, &none, "gpt-5.5");
        assert_eq!(none_body["reasoning_effort"], "none");

        let mut xhigh = thinking_on();
        xhigh.reasoning_effort = Some("xhigh".to_string());
        let mut xhigh_body = serde_json::to_value(req("gpt-5.5")).unwrap();
        ThinkingInjector::OpenAiReasoningEffort.inject(&mut xhigh_body, &xhigh, "gpt-5.5");
        assert_eq!(xhigh_body["reasoning_effort"], "xhigh");
    }

    #[test]
    fn openai_reasoning_effort_set_for_gpt5_model_family() {
        for model in ["gpt-5", "gpt-5.5", "gpt-5.3-codex", "gpt-5.1-codex-max"] {
            let mut body = serde_json::to_value(req(model)).unwrap();
            ThinkingInjector::OpenAiReasoningEffort.inject(&mut body, &thinking_on(), model);
            assert_eq!(
                body["reasoning_effort"], "medium",
                "{model} should receive reasoning_effort"
            );
        }
    }

    #[test]
    fn openai_reasoning_effort_absent_for_non_reasoning_model() {
        let mut body = serde_json::to_value(req("gpt-4")).unwrap();
        ThinkingInjector::OpenAiReasoningEffort.inject(&mut body, &thinking_on(), "gpt-4");
        assert!(body.get("reasoning_effort").is_none());
    }

    #[test]
    fn openai_reasoning_effort_absent_for_near_miss_model_family() {
        let mut body = serde_json::to_value(req("gpt-50")).unwrap();
        ThinkingInjector::OpenAiReasoningEffort.inject(&mut body, &thinking_on(), "gpt-50");
        assert!(body.get("reasoning_effort").is_none());
    }

    #[test]
    fn openai_reasoning_effort_absent_when_disabled() {
        let mut body = serde_json::to_value(req("o3-mini")).unwrap();
        ThinkingInjector::OpenAiReasoningEffort.inject(&mut body, &thinking_off(), "o3-mini");
        assert!(body.get("reasoning_effort").is_none());
    }

    #[test]
    fn deepseek_thinking_writes_current_thinking_shape() {
        let mut on = serde_json::to_value(req("deepseek-v4-pro")).unwrap();
        ThinkingInjector::DeepSeekThinking.inject(&mut on, &thinking_on(), "deepseek-v4-pro");
        assert_eq!(on["thinking"]["type"], "enabled");
        assert_eq!(on["reasoning_effort"], "high");
        assert!(on.get("enable_thinking").is_none());

        let mut max = thinking_on();
        max.reasoning_effort = Some("max".to_string());
        let mut max_body = serde_json::to_value(req("deepseek-v4-pro")).unwrap();
        ThinkingInjector::DeepSeekThinking.inject(&mut max_body, &max, "deepseek-v4-pro");
        assert_eq!(max_body["reasoning_effort"], "max");

        let mut off = serde_json::to_value(req("deepseek-v4-pro")).unwrap();
        ThinkingInjector::DeepSeekThinking.inject(&mut off, &thinking_off(), "deepseek-v4-pro");
        assert_eq!(off["thinking"]["type"], "disabled");
        assert!(off.get("reasoning_effort").is_none());
    }

    #[test]
    fn qwen_thinking_always_writes_explicit_bool() {
        let mut on = serde_json::to_value(req("qwq-32b")).unwrap();
        ThinkingInjector::QwenEnableThinking.inject(&mut on, &thinking_on(), "qwq-32b");
        assert_eq!(on["enable_thinking"], true);

        let mut off = serde_json::to_value(req("qwq-32b")).unwrap();
        ThinkingInjector::QwenEnableThinking.inject(&mut off, &thinking_off(), "qwq-32b");
        // Qwen prior behaviour: explicit false when disabled.
        assert_eq!(off["enable_thinking"], false);
    }

    #[test]
    fn glm_thinking_encodes_enabled_disabled_object() {
        let mut on = serde_json::to_value(req("glm-4.7")).unwrap();
        ThinkingInjector::GlmThinking.inject(&mut on, &thinking_on(), "glm-4.7");
        assert_eq!(on["thinking"]["type"], "enabled");
        // No preserve flag by default.
        assert!(on["thinking"].get("clear_thinking").is_none());

        let mut off = serde_json::to_value(req("glm-4.7")).unwrap();
        ThinkingInjector::GlmThinking.inject(&mut off, &thinking_off(), "glm-4.7");
        assert_eq!(off["thinking"]["type"], "disabled");
    }

    #[test]
    fn glm_thinking_preserve_emits_clear_thinking_false() {
        let mut t = thinking_on();
        t.preserve_across_turns = true;
        let mut body = serde_json::to_value(req("glm-4.7")).unwrap();
        ThinkingInjector::GlmThinking.inject(&mut body, &t, "glm-4.7");
        assert_eq!(body["thinking"]["type"], "enabled");
        assert_eq!(body["thinking"]["clear_thinking"], false);
        assert!(body.get("clear_thinking").is_none());
    }

    #[test]
    fn glm52_thinking_emits_reasoning_effort() {
        let mut max = thinking_on();
        max.reasoning_effort = Some("max".to_string());
        let mut body = serde_json::to_value(req("glm-5.2")).unwrap();
        ThinkingInjector::GlmThinking.inject(&mut body, &max, "glm-5.2");
        assert_eq!(body["thinking"]["type"], "enabled");
        assert_eq!(body["reasoning_effort"], "max");

        let mut low = thinking_on();
        low.reasoning_effort = Some("low".to_string());
        let mut low_body = serde_json::to_value(req("glm-5.2")).unwrap();
        ThinkingInjector::GlmThinking.inject(&mut low_body, &low, "glm-5.2");
        assert_eq!(low_body["reasoning_effort"], "high");
    }

    #[test]
    fn minimax_m3_thinking_uses_adaptive_or_disabled_shape() {
        let mut on = serde_json::to_value(req("MiniMax-M3")).unwrap();
        ThinkingInjector::MiniMaxThinking.inject(&mut on, &thinking_on(), "MiniMax-M3");
        assert_eq!(on["thinking"]["type"], "adaptive");
        assert_eq!(on["reasoning_split"], true);
        assert!(on.get("reasoning_effort").is_none());

        let mut off = serde_json::to_value(req("MiniMax-M3")).unwrap();
        ThinkingInjector::MiniMaxThinking.inject(&mut off, &thinking_off(), "MiniMax-M3");
        assert_eq!(off["thinking"]["type"], "disabled");
        assert!(off.get("reasoning_split").is_none());
    }

    #[test]
    fn kimi_k27_omits_thinking_because_it_is_always_on() {
        for model in ["kimi-k2.7-code", "kimi-k2.7-code-highspeed"] {
            let mut on = serde_json::to_value(req(model)).unwrap();
            ThinkingInjector::KimiThinking.inject(&mut on, &thinking_on(), model);
            assert!(
                on.get("thinking").is_none(),
                "{model} should omit explicit thinking because K2.7 always thinks: {on}"
            );

            let mut off = serde_json::to_value(req(model)).unwrap();
            ThinkingInjector::KimiThinking.inject(&mut off, &thinking_off(), model);
            assert!(
                off.get("thinking").is_none(),
                "{model} rejects thinking.type=disabled, so the adapter must omit it: {off}"
            );
        }
    }

    #[test]
    fn kimi_k26_supports_enabled_disabled_and_preserved_thinking() {
        let mut on = serde_json::to_value(req("kimi-k2.6")).unwrap();
        ThinkingInjector::KimiThinking.inject(&mut on, &thinking_on(), "kimi-k2.6");
        assert_eq!(on["thinking"], json!({"type": "enabled"}));

        let mut preserve = thinking_on();
        preserve.preserve_across_turns = true;
        let mut preserve_body = serde_json::to_value(req("kimi-k2.6")).unwrap();
        ThinkingInjector::KimiThinking.inject(&mut preserve_body, &preserve, "kimi-k2.6");
        assert_eq!(
            preserve_body["thinking"],
            json!({"type": "enabled", "keep": "all"})
        );

        let mut off = serde_json::to_value(req("kimi-k2.6")).unwrap();
        ThinkingInjector::KimiThinking.inject(&mut off, &thinking_off(), "kimi-k2.6");
        assert_eq!(off["thinking"], json!({"type": "disabled"}));
    }

    #[test]
    fn kimi_k25_does_not_emit_preserved_thinking_keep() {
        let mut preserve = thinking_on();
        preserve.preserve_across_turns = true;
        let mut body = serde_json::to_value(req("kimi-k2.5")).unwrap();
        ThinkingInjector::KimiThinking.inject(&mut body, &preserve, "kimi-k2.5");
        assert_eq!(body["thinking"], json!({"type": "enabled"}));
        assert!(body["thinking"].get("keep").is_none());
    }

    #[test]
    fn moonshot_v1_models_do_not_receive_kimi_thinking_fields() {
        let mut body = serde_json::to_value(req("moonshot-v1-128k")).unwrap();
        ThinkingInjector::KimiThinking.inject(&mut body, &thinking_on(), "moonshot-v1-128k");
        assert!(body.get("thinking").is_none());
    }

    #[test]
    fn shared_adapter_endpoint_and_headers() {
        let a = OpenAiCompatibleAdapter::new(
            "openai",
            "/v1/chat/completions",
            ThinkingInjector::OpenAiReasoningEffort,
            true,
        );
        assert_eq!(a.name(), "openai");
        assert_eq!(a.chat_endpoint("gpt-4"), "/v1/chat/completions");
        assert!(a.supports_model_listing());

        let key = ApiKey::try_from_string("sk-test-key".to_string()).unwrap();
        let headers = a.get_headers(&key);
        assert_eq!(headers.len(), 2);
        assert!(headers.matches_value("Authorization", "Bearer sk-test-key"));
        assert!(headers.matches_value("content-type", "application/json"));
    }

    #[test]
    fn zai_endpoint_omits_v1_prefix() {
        let a = OpenAiCompatibleAdapter::new(
            "zai",
            "/chat/completions",
            ThinkingInjector::GlmThinking,
            false,
        );
        assert_eq!(a.chat_endpoint("glm-4"), "/chat/completions");
        assert!(!a.supports_model_listing());
    }

    #[test]
    fn transform_response_accepts_valid_openai_text_response() {
        let a = OpenAiCompatibleAdapter::new(
            "openai",
            "/v1/chat/completions",
            ThinkingInjector::OpenAiReasoningEffort,
            true,
        );
        let response = json!({
            "id": "chatcmpl-123",
            "choices": [{
                "message": {"role": "assistant", "content": "hello"},
                "finish_reason": "stop"
            }]
        });

        assert_eq!(
            a.transform_response(response.clone(), false).unwrap(),
            response
        );
    }

    #[test]
    fn transform_response_accepts_valid_tool_call_response() {
        let a = OpenAiCompatibleAdapter::new(
            "deepseek",
            "/v1/chat/completions",
            ThinkingInjector::DeepSeekThinking,
            false,
        );
        let response = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "bash", "arguments": "{\"command\":\"pwd\"}"}
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        });

        assert_eq!(
            a.transform_response(response.clone(), false).unwrap(),
            response
        );
    }

    #[test]
    fn transform_response_rejects_missing_choices_array() {
        let a = OpenAiCompatibleAdapter::new(
            "openai",
            "/v1/chat/completions",
            ThinkingInjector::OpenAiReasoningEffort,
            true,
        );

        let err = a
            .transform_response(json!({"id": "bad"}), false)
            .expect_err("missing choices must be invalid");

        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("'choices' array"), "{msg}");
                assert!(msg.contains("openai"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_rejects_empty_choices_array() {
        let a = OpenAiCompatibleAdapter::new(
            "qwen",
            "/v1/chat/completions",
            ThinkingInjector::QwenEnableThinking,
            false,
        );

        let err = a
            .transform_response(json!({"choices": []}), false)
            .expect_err("empty choices must be invalid");

        match err {
            ProviderError::InvalidResponse(msg) => assert!(msg.contains("empty"), "{msg}"),
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_rejects_choice_missing_message() {
        let a = OpenAiCompatibleAdapter::new(
            "zai",
            "/chat/completions",
            ThinkingInjector::GlmThinking,
            false,
        );

        let err = a
            .transform_response(json!({"choices": [{"finish_reason": "stop"}]}), false)
            .expect_err("choice without message must be invalid");

        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("choices[0]"), "{msg}");
                assert!(msg.contains("'message'"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_rejects_message_missing_role() {
        let a = OpenAiCompatibleAdapter::new(
            "openai",
            "/v1/chat/completions",
            ThinkingInjector::OpenAiReasoningEffort,
            true,
        );

        let err = a
            .transform_response(json!({"choices": [{"message": {"content": "hi"}}]}), false)
            .expect_err("message without role must be invalid");

        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("message.role"), "{msg}");
                assert!(msg.contains("non-empty string"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_rejects_empty_message_role() {
        let a = OpenAiCompatibleAdapter::new(
            "openai",
            "/v1/chat/completions",
            ThinkingInjector::OpenAiReasoningEffort,
            true,
        );

        let err = a
            .transform_response(
                json!({"choices": [{"message": {"role": "", "content": "hi"}}]}),
                false,
            )
            .expect_err("empty message role must be invalid");

        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("message.role"), "{msg}");
                assert!(msg.contains("non-empty string"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_rejects_message_without_payload() {
        let a = OpenAiCompatibleAdapter::new(
            "deepseek",
            "/v1/chat/completions",
            ThinkingInjector::DeepSeekThinking,
            false,
        );

        let err = a
            .transform_response(
                json!({"choices": [{"message": {"role": "assistant"}}]}),
                false,
            )
            .expect_err("message without content, tool calls, or refusal must be invalid");

        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("must contain"), "{msg}");
                assert!(msg.contains("content"), "{msg}");
                assert!(msg.contains("tool_calls"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_rejects_null_content_without_payload() {
        let a = OpenAiCompatibleAdapter::new(
            "qwen",
            "/v1/chat/completions",
            ThinkingInjector::QwenEnableThinking,
            false,
        );

        let err = a
            .transform_response(
                json!({"choices": [{"message": {"role": "assistant", "content": null}}]}),
                false,
            )
            .expect_err("null content without tool calls or refusal must be invalid");

        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("must contain"), "{msg}");
                assert!(msg.contains("refusal"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_accepts_refusal_payload() {
        let a = OpenAiCompatibleAdapter::new(
            "openai",
            "/v1/chat/completions",
            ThinkingInjector::OpenAiReasoningEffort,
            true,
        );
        let response = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "refusal": "I can't help with that."
                },
                "finish_reason": "stop"
            }]
        });

        assert_eq!(
            a.transform_response(response.clone(), false).unwrap(),
            response
        );
    }

    #[test]
    fn transform_response_rejects_non_string_content() {
        let a = OpenAiCompatibleAdapter::new(
            "openai",
            "/v1/chat/completions",
            ThinkingInjector::OpenAiReasoningEffort,
            true,
        );

        let err = a
            .transform_response(
                json!({"choices": [{"message": {"role": "assistant", "content": ["bad"]}}]}),
                false,
            )
            .expect_err("array content must be invalid");

        match err {
            ProviderError::InvalidResponse(msg) => assert!(msg.contains("content"), "{msg}"),
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_keeps_stream_chunks_passthrough() {
        let a = OpenAiCompatibleAdapter::new(
            "openai",
            "/v1/chat/completions",
            ThinkingInjector::OpenAiReasoningEffort,
            true,
        );
        let chunk = json!({"choices": [{"delta": {"content": "he"}}]});

        assert_eq!(a.transform_response(chunk.clone(), true).unwrap(), chunk);
    }
}
