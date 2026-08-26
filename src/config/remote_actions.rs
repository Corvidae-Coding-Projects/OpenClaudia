//! Trusted host configuration for named remote actions.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::secrets::{SecretString, SensitiveHeaders};
use crate::tools::remote_trigger::{
    RemoteActionContract, RemoteActionContractSpec, RemoteActionEffect, RemoteActionIdempotency,
    WebhookRegistry,
};

const DEFAULT_TIMEOUT_MILLISECONDS: u64 = 30_000;
const DEFAULT_MAX_REQUEST_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_CALLS_PER_RUN: u32 = 16;
const DEFAULT_MAX_IN_FLIGHT: u32 = 2;
const DEFAULT_MAX_ATTEMPTS: u32 = 1;

const fn default_timeout_milliseconds() -> u64 {
    DEFAULT_TIMEOUT_MILLISECONDS
}

const fn default_max_request_bytes() -> usize {
    DEFAULT_MAX_REQUEST_BYTES
}

const fn default_max_response_bytes() -> usize {
    DEFAULT_MAX_RESPONSE_BYTES
}

const fn default_max_calls_per_run() -> u32 {
    DEFAULT_MAX_CALLS_PER_RUN
}

const fn default_max_in_flight() -> u32 {
    DEFAULT_MAX_IN_FLIGHT
}

const fn default_max_attempts() -> u32 {
    DEFAULT_MAX_ATTEMPTS
}

fn default_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {}
    })
}

/// One exact action configured by the trusted host.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteActionConfig {
    /// Destination bytes stay opaque because signed webhook URLs may contain
    /// credentials in their path or query.
    pub url: SecretString,
    /// Host-owned request headers. Values are never included in model context.
    #[serde(default)]
    pub headers: SensitiveHeaders,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_input_schema")]
    pub input_schema: Value,
    #[serde(default)]
    pub output_schema: Option<Value>,
    #[serde(default)]
    pub effect: RemoteActionEffect,
    #[serde(default)]
    pub idempotency: RemoteActionIdempotency,
    #[serde(default = "default_timeout_milliseconds")]
    pub timeout_milliseconds: u64,
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default = "default_max_calls_per_run")]
    pub max_calls_per_run: u32,
    #[serde(default = "default_max_in_flight")]
    pub max_in_flight: u32,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
}

impl std::fmt::Debug for RemoteActionConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteActionConfig")
            .field("url", &crate::secrets::REDACTED_SECRET)
            .field("headers", &self.headers)
            .field("description", &self.description)
            .field("input_schema", &self.input_schema)
            .field("output_schema", &self.output_schema)
            .field("effect", &self.effect)
            .field("idempotency", &self.idempotency)
            .field("timeout_milliseconds", &self.timeout_milliseconds)
            .field("max_request_bytes", &self.max_request_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_calls_per_run", &self.max_calls_per_run)
            .field("max_in_flight", &self.max_in_flight)
            .field("max_attempts", &self.max_attempts)
            .finish()
    }
}

/// Complete host-owned named-action catalog.
///
/// Project configuration is stripped before `AppConfig` deserialization, so
/// the standard loader accepts this block only from the trusted home source.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RemoteActionsConfig {
    /// Exact opt-in for HTTP loopback fixtures and user-owned local services.
    /// Public plaintext destinations remain forbidden even when this is true.
    pub allow_loopback_plaintext: bool,
    pub actions: BTreeMap<String, RemoteActionConfig>,
}

impl RemoteActionsConfig {
    /// Validate and protect every configured action as an immutable registry.
    ///
    /// # Errors
    ///
    /// Returns a redacted configuration error for invalid names, endpoints,
    /// headers, schemas, effects, idempotency policy, or bounds.
    pub fn build_registry(&self) -> Result<WebhookRegistry, String> {
        let mut registry = if self.allow_loopback_plaintext {
            WebhookRegistry::new_allow_plaintext()
        } else {
            WebhookRegistry::new()
        };
        for (name, configured) in &self.actions {
            let contract = RemoteActionContract::try_from_spec(RemoteActionContractSpec {
                description: configured.description.clone(),
                input_schema: configured.input_schema.clone(),
                output_schema: configured.output_schema.clone(),
                effect: configured.effect,
                idempotency: configured.idempotency,
                deadline: Duration::from_millis(configured.timeout_milliseconds),
                max_request_bytes: configured.max_request_bytes,
                max_response_bytes: configured.max_response_bytes,
                max_calls_per_run: configured.max_calls_per_run,
                max_in_flight: configured.max_in_flight,
                max_attempts: configured.max_attempts,
            })
            .map_err(|error| format!("remote action '{name}' contract rejected: {error}"))?;
            configured
                .url
                .expose(|url| {
                    registry.register_action(
                        name.clone(),
                        url,
                        configured.headers.clone(),
                        contract,
                    )
                })
                .map_err(|error| format!("remote action '{name}' rejected: {error}"))?;
        }
        Ok(registry)
    }
}
