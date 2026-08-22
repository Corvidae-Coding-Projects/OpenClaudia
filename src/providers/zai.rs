//! Z.AI/GLM API adapter (OpenAI-compatible with structured `thinking` object).
//!
//! Thin newtype around [`OpenAiCompatibleAdapter`]. Z.AI differs from the
//! other OpenAI-compat providers in two ways:
//!
//! - the chat endpoint omits the `/v1/` prefix because Z.AI's `base_url`
//!   already encodes the API version;
//! - thinking mode is keyed as a structured object
//!   (`thinking: {type: enabled|disabled}`) rather than a bare bool, and
//!   `preserve_across_turns` emits `thinking.clear_thinking: false`;
//! - `GLM-5.2` supports an additional top-level `reasoning_effort`.
//!
//! See crosslink #281.

use async_trait::async_trait;
use serde_json::Value;

use crate::config::ThinkingConfig;
use crate::proxy::ChatCompletionRequest;

use super::openai_compat::{OpenAiCompatibleAdapter, ThinkingInjector};
use super::{ApiKey, ProviderAdapter, ProviderError};

/// Z.AI/GLM API adapter (OpenAI-compatible with structured thinking object
/// and a `/chat/completions` endpoint that does not carry a `/v1/` prefix).
pub struct ZaiAdapter(OpenAiCompatibleAdapter);

impl ZaiAdapter {
    #[must_use]
    pub const fn new() -> Self {
        Self(OpenAiCompatibleAdapter::new(
            "zai",
            "/chat/completions",
            ThinkingInjector::GlmThinking,
            false,
        ))
    }
}

impl Default for ZaiAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for ZaiAdapter {
    fn name(&self) -> &str {
        self.0.name()
    }

    fn transform_request(&self, request: &ChatCompletionRequest) -> Result<Value, ProviderError> {
        self.0.transform_request(request)
    }

    fn transform_request_with_thinking(
        &self,
        request: &ChatCompletionRequest,
        thinking: &ThinkingConfig,
    ) -> Result<Value, ProviderError> {
        self.0.transform_request_with_thinking(request, thinking)
    }

    fn transform_response(&self, response: Value, stream: bool) -> Result<Value, ProviderError> {
        self.0.transform_response(response, stream)
    }

    fn chat_endpoint(&self, model: &str) -> String {
        self.0.chat_endpoint(model)
    }

    fn get_headers(&self, api_key: &ApiKey) -> crate::secrets::SensitiveHeaders {
        self.0.get_headers(api_key)
    }

    fn supports_model_listing(&self) -> bool {
        self.0.supports_model_listing()
    }
}
