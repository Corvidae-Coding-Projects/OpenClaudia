//! `DeepSeek` API adapter (OpenAI-compatible with `DeepSeek` thinking controls).
//!
//! Thin newtype around [`OpenAiCompatibleAdapter`]. `DeepSeek`-specific
//! behaviour is using root-level `/chat/completions` and `/models` paths plus
//! injecting `thinking: {type:"enabled"|"disabled"}` and
//! `reasoning_effort: "high"|"max"`.
//!
//! See crosslink #281.

use async_trait::async_trait;
use serde_json::Value;

use crate::config::ThinkingConfig;
use crate::proxy::ChatCompletionRequest;

use super::openai_compat::{OpenAiCompatibleAdapter, ThinkingInjector};
use super::{ApiKey, ProviderAdapter, ProviderError};

/// `DeepSeek` API adapter (OpenAI-compatible with thinking support).
pub struct DeepSeekAdapter(OpenAiCompatibleAdapter);

impl DeepSeekAdapter {
    #[must_use]
    pub const fn new() -> Self {
        Self(OpenAiCompatibleAdapter::new(
            "deepseek",
            "/chat/completions",
            ThinkingInjector::DeepSeekThinking,
            true,
        ))
    }
}

impl Default for DeepSeekAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for DeepSeekAdapter {
    fn name(&self) -> &str {
        self.0.name()
    }

    fn state_contract(
        &self,
        protocol: crate::runtime::ProviderWireProtocol,
    ) -> Result<&'static crate::runtime::ProviderStateContract, ProviderError> {
        self.0.state_contract(protocol)
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

    fn models_endpoint(&self) -> &'static str {
        "/models"
    }
}
