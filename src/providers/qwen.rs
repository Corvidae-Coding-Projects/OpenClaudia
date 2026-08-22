//! Qwen/Alibaba API adapter (OpenAI-compatible with `enable_thinking` toggle).
//!
//! Thin newtype around [`OpenAiCompatibleAdapter`]. Qwen always writes an
//! explicit `enable_thinking: true|false`.
//!
//! See crosslink #281.

use async_trait::async_trait;
use serde_json::Value;

use crate::config::ThinkingConfig;
use crate::proxy::ChatCompletionRequest;

use super::openai_compat::{OpenAiCompatibleAdapter, ThinkingInjector};
use super::{ApiKey, ProviderAdapter, ProviderError};

/// Qwen/Alibaba API adapter (OpenAI-compatible with thinking support).
pub struct QwenAdapter(OpenAiCompatibleAdapter);

impl QwenAdapter {
    #[must_use]
    pub const fn new() -> Self {
        Self(OpenAiCompatibleAdapter::new(
            "qwen",
            "/v1/chat/completions",
            ThinkingInjector::QwenEnableThinking,
            false,
        ))
    }
}

impl Default for QwenAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for QwenAdapter {
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
