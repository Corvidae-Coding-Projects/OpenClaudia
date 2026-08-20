//! `OpenAI` Chat Completions API adapter.
//!
//! Thin newtype around [`OpenAiCompatibleAdapter`]. The only `OpenAI`-specific
//! configuration is the `reasoning_effort` injection for `OpenAI`
//! reasoning-family models - every other behaviour is the shared
//! OpenAI-compatible path.
//!
//! See crosslink #281 for the Stovepipe-de-duplication that introduced
//! this shape.

use async_trait::async_trait;
use serde_json::Value;

use crate::config::ThinkingConfig;
use crate::proxy::ChatCompletionRequest;

use super::openai_compat::{OpenAiCompatibleAdapter, ThinkingInjector};
use super::{ApiKey, ProviderAdapter, ProviderError};

/// `OpenAI` API adapter (Chat Completions, with optional `reasoning_effort`
/// for `OpenAI` reasoning-family models).
pub struct OpenAIAdapter(OpenAiCompatibleAdapter);

impl OpenAIAdapter {
    #[must_use]
    pub const fn new() -> Self {
        Self(OpenAiCompatibleAdapter::new(
            "openai",
            "/v1/chat/completions",
            ThinkingInjector::OpenAiReasoningEffort,
            true,
        ))
    }
}

impl Default for OpenAIAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for OpenAIAdapter {
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
