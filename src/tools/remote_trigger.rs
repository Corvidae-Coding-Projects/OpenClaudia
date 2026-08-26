//! Host-registered named remote actions.
//!
//! A model may select only a symbolic action name and provide data satisfying
//! that action's host-owned input schema. The destination, HTTP method,
//! headers, credentials, effect class, retry policy, deadlines, and byte/rate
//! limits never appear in model arguments. Registries are bound to one
//! [`super::ToolRunContext`] generation; there is no process-global fallback.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tokio::time::Instant;

const MAX_ACTION_NAME_BYTES: usize = 96;
const MAX_ACTION_DESCRIPTION_BYTES: usize = 512;
const MAX_ACTION_SCHEMA_BYTES: usize = 32 * 1024;
const MAX_ACTION_DEADLINE: Duration = Duration::from_secs(60);
const MIN_ACTION_DEADLINE: Duration = Duration::from_millis(100);
const MAX_ACTION_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_ACTION_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_ACTION_CALLS_PER_RUN: u32 = 10_000;
const MAX_ACTION_IN_FLIGHT: u32 = 16;
const MAX_ACTION_ATTEMPTS: u32 = 3;
const REMOTE_ACTION_RECEIPT_SCHEMA_VERSION: u16 = 1;

/// Mandatory effect classification for a named remote action.
///
/// The current product contract is intentionally narrow: named actions invoke
/// a remote service and therefore always represent an external mutation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteActionEffect {
    #[default]
    ExternalMutation,
}

impl RemoteActionEffect {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExternalMutation => "external_mutation",
        }
    }
}

/// Whether the host contract permits replaying an ambiguous action attempt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteActionIdempotency {
    /// Never replay the fixed POST request.
    #[default]
    None,
    /// Send one stable `Idempotency-Key` for every attempt of the invocation.
    KeyHeader,
}

/// Unvalidated host inputs used to construct a [`RemoteActionContract`].
#[derive(Debug, Clone)]
pub struct RemoteActionContractSpec {
    pub description: String,
    pub input_schema: Value,
    pub output_schema: Option<Value>,
    pub effect: RemoteActionEffect,
    pub idempotency: RemoteActionIdempotency,
    pub deadline: Duration,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_calls_per_run: u32,
    pub max_in_flight: u32,
    pub max_attempts: u32,
}

/// Validated payload/result, budget, and retry contract for one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteActionContract {
    description: String,
    input_schema: Value,
    output_schema: Option<Value>,
    effect: RemoteActionEffect,
    idempotency: RemoteActionIdempotency,
    deadline: Duration,
    max_request_bytes: usize,
    max_response_bytes: usize,
    max_calls_per_run: u32,
    max_in_flight: u32,
    max_attempts: u32,
}

impl RemoteActionContract {
    /// Validate all host-owned action bounds and schemas.
    ///
    /// # Errors
    ///
    /// Returns a redacted structural error. Schema contents are never copied
    /// into the diagnostic.
    pub fn try_from_spec(spec: RemoteActionContractSpec) -> Result<Self, WebhookError> {
        if spec.description.len() > MAX_ACTION_DESCRIPTION_BYTES || spec.description.contains('\0')
        {
            return Err(invalid_contract(
                "description is NUL-free and at most 512 bytes",
            ));
        }
        validate_json_schema(&spec.input_schema, true, "input")?;
        if let Some(output_schema) = &spec.output_schema {
            validate_json_schema(output_schema, false, "output")?;
        }
        if spec.deadline < MIN_ACTION_DEADLINE || spec.deadline > MAX_ACTION_DEADLINE {
            return Err(invalid_contract(
                "deadline must be between 100 milliseconds and 60 seconds",
            ));
        }
        if !(1..=MAX_ACTION_REQUEST_BYTES).contains(&spec.max_request_bytes) {
            return Err(invalid_contract(
                "request-byte limit must be between 1 and 1048576",
            ));
        }
        if !(1..=MAX_ACTION_RESPONSE_BYTES).contains(&spec.max_response_bytes) {
            return Err(invalid_contract(
                "response-byte limit must be between 1 and 1048576",
            ));
        }
        if !(1..=MAX_ACTION_CALLS_PER_RUN).contains(&spec.max_calls_per_run) {
            return Err(invalid_contract(
                "per-run call limit must be between 1 and 10000",
            ));
        }
        if !(1..=MAX_ACTION_IN_FLIGHT).contains(&spec.max_in_flight) {
            return Err(invalid_contract("in-flight limit must be between 1 and 16"));
        }
        if !(1..=MAX_ACTION_ATTEMPTS).contains(&spec.max_attempts) {
            return Err(invalid_contract("attempt limit must be between 1 and 3"));
        }
        if spec.idempotency == RemoteActionIdempotency::None && spec.max_attempts != 1 {
            return Err(invalid_contract(
                "non-idempotent actions must use exactly one attempt",
            ));
        }
        Ok(Self {
            description: spec.description,
            input_schema: spec.input_schema,
            output_schema: spec.output_schema,
            effect: spec.effect,
            idempotency: spec.idempotency,
            deadline: spec.deadline,
            max_request_bytes: spec.max_request_bytes,
            max_response_bytes: spec.max_response_bytes,
            max_calls_per_run: spec.max_calls_per_run,
            max_in_flight: spec.max_in_flight,
            max_attempts: spec.max_attempts,
        })
    }

    fn compatibility_default() -> Self {
        Self::try_from_spec(RemoteActionContractSpec {
            description: "Invoke this host-registered remote action.".to_string(),
            input_schema: json!({"type": "object", "maxProperties": 64}),
            output_schema: None,
            effect: RemoteActionEffect::ExternalMutation,
            idempotency: RemoteActionIdempotency::None,
            deadline: Duration::from_secs(30),
            max_request_bytes: 64 * 1024,
            max_response_bytes: 256 * 1024,
            max_calls_per_run: 16,
            max_in_flight: 2,
            max_attempts: 1,
        })
        .expect("static remote-action compatibility contract is valid")
    }
}

fn validate_json_schema(
    schema: &Value,
    require_object_root: bool,
    label: &'static str,
) -> Result<(), WebhookError> {
    let Some(object) = schema.as_object() else {
        return Err(invalid_contract(match label {
            "input" => "input schema must be a JSON Schema object",
            _ => "output schema must be a JSON Schema object",
        }));
    };
    if require_object_root && object.get("type").and_then(Value::as_str) != Some("object") {
        return Err(invalid_contract(
            "input schema root must declare type 'object'",
        ));
    }
    let encoded = serde_json::to_vec(schema)
        .map_err(|_| invalid_contract("schema could not be serialized"))?;
    if encoded.len() > MAX_ACTION_SCHEMA_BYTES {
        return Err(invalid_contract("schema exceeds the 32768-byte limit"));
    }
    reject_external_schema_references(schema)?;
    jsonschema::draft202012::new(schema)
        .map(|_| ())
        .map_err(|_| invalid_contract("schema is not valid local JSON Schema"))
}

fn reject_external_schema_references(value: &Value) -> Result<(), WebhookError> {
    match value {
        Value::Array(values) => {
            for value in values {
                reject_external_schema_references(value)?;
            }
        }
        Value::Object(values) => {
            if values
                .get("$ref")
                .and_then(Value::as_str)
                .is_some_and(|reference| !reference.starts_with('#'))
            {
                return Err(invalid_contract(
                    "schemas may use only document-local references",
                ));
            }
            for value in values.values() {
                reject_external_schema_references(value)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn invalid_contract(reason: impl Into<String>) -> WebhookError {
    WebhookError::InvalidContract {
        reason: reason.into(),
    }
}

/// Canonical webhook URL kept opaque because signed URLs commonly carry
/// credentials in their path or query.
#[derive(Clone, PartialEq, Eq)]
pub struct WebhookUrl(crate::secrets::SecretString);

impl WebhookUrl {
    fn from_validated(url: String) -> Result<Self, WebhookError> {
        crate::secrets::SecretString::try_from_string(url)
            .map(Self)
            .map_err(|_| WebhookError::Malformed {})
    }

    /// Compare a canonical URL without returning its bytes.
    #[must_use]
    pub fn matches(&self, candidate: &str) -> bool {
        self.0.matches(candidate)
    }

    fn expose<R>(&self, operation: impl FnOnce(&str) -> R) -> R {
        self.0.expose(operation)
    }

    fn sanitize(&self, raw: &str) -> crate::secrets::SafeDiagnostic {
        crate::secrets::sanitize_diagnostic(raw, [&self.0])
    }
}

impl fmt::Debug for WebhookUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WebhookUrl([REDACTED])")
    }
}

impl fmt::Display for WebhookUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(crate::secrets::REDACTED_SECRET)
    }
}

/// Errors registering or resolving a named remote action.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WebhookError {
    #[error(
        "webhook URL uses an unsupported scheme; expected https (or http with explicit loopback opt-in)"
    )]
    InvalidScheme {},
    #[error("webhook URL uses insecure http://; only exact loopback destinations may opt in with new_allow_plaintext()")]
    InsecureScheme {},
    #[error("webhook URL is not a valid absolute URL with a host")]
    Malformed {},
    #[error("webhook URL must not contain user-info credentials or a fragment")]
    CredentialsInUrl {},
    #[error("webhook name is invalid; expected 1-96 ASCII letters, digits, '.', '_' or '-'")]
    InvalidName {},
    #[error("no webhook registered under name '{name}'")]
    UnknownWebhook { name: String },
    #[error("webhook name '{name}' is already registered")]
    Duplicate { name: String },
    #[error("invalid webhook headers: {reason}")]
    InvalidHeaders { reason: String },
    #[error("invalid remote-action contract: {reason}")]
    InvalidContract { reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestinationPolicy {
    PublicHttps,
    ExactLoopback,
}

/// One protected webhook endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookEndpoint {
    pub url: WebhookUrl,
    pub headers: crate::secrets::SensitiveHeaders,
    destination_policy: DestinationPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegisteredRemoteAction {
    endpoint: WebhookEndpoint,
    contract: RemoteActionContract,
}

/// Immutable name-to-action registry constructed only by the host.
#[derive(Debug, Clone)]
pub struct WebhookRegistry {
    entries: BTreeMap<String, RegisteredRemoteAction>,
    allow_loopback_plaintext: bool,
}

impl WebhookRegistry {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            allow_loopback_plaintext: false,
        }
    }

    /// Opt into plaintext only for exact loopback fixtures or local services.
    /// Public and private-network plaintext targets remain forbidden.
    #[must_use]
    pub const fn new_allow_plaintext() -> Self {
        Self {
            entries: BTreeMap::new(),
            allow_loopback_plaintext: true,
        }
    }

    /// Validate and normalize one hidden destination.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for malformed, credential-bearing,
    /// unsupported, insecure, or statically forbidden destinations.
    pub fn validate_url(&self, raw: &str) -> Result<WebhookUrl, WebhookError> {
        if raw.trim().is_empty() {
            return Err(WebhookError::Malformed {});
        }
        let (with_scheme, was_implicit) = scheme_with_default(raw);
        let parsed = url::Url::parse(&with_scheme).map_err(|_| WebhookError::Malformed {})?;
        if parsed.host_str().is_none_or(str::is_empty) {
            return Err(WebhookError::Malformed {});
        }
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(WebhookError::CredentialsInUrl {});
        }
        match parsed.scheme() {
            "https" => {
                crate::web::validate_url_static(parsed.as_str())
                    .map_err(|_| WebhookError::Malformed {})?;
                WebhookUrl::from_validated(parsed.into())
            }
            "http" if self.allow_loopback_plaintext && exact_loopback_host(&parsed) => {
                WebhookUrl::from_validated(parsed.into())
            }
            "http" if !was_implicit => Err(WebhookError::InsecureScheme {}),
            "http" => Err(WebhookError::Malformed {}),
            _ => Err(WebhookError::InvalidScheme {}),
        }
    }

    /// Register a compatibility action with a bounded arbitrary-object input.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for an invalid or duplicate name, unsafe
    /// destination, invalid header, or rejected compatibility contract.
    pub fn register(
        &mut self,
        name: impl Into<String>,
        url: &str,
        headers: HashMap<String, String>,
    ) -> Result<(), WebhookError> {
        let headers = protect_headers(headers)?;
        self.register_action(
            name,
            url,
            headers,
            RemoteActionContract::compatibility_default(),
        )
    }

    /// Register a fully typed host-owned action.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for an invalid or duplicate name, unsafe
    /// destination, invalid header, or rejected action contract.
    pub fn register_action(
        &mut self,
        name: impl Into<String>,
        url: &str,
        headers: crate::secrets::SensitiveHeaders,
        contract: RemoteActionContract,
    ) -> Result<(), WebhookError> {
        let name = name.into();
        validate_action_name(&name)?;
        if self.entries.contains_key(&name) {
            return Err(WebhookError::Duplicate { name });
        }
        validate_remote_headers(&headers)?;
        let url = self.validate_url(url)?;
        let destination_policy = destination_policy(&url)?;
        self.entries.insert(
            name,
            RegisteredRemoteAction {
                endpoint: WebhookEndpoint {
                    url,
                    headers,
                    destination_policy,
                },
                contract,
            },
        );
        Ok(())
    }

    /// Replace a compatibility action, or insert it when absent.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for an invalid name, unsafe destination,
    /// invalid header, or rejected compatibility contract. Existing state is
    /// retained when validation fails.
    pub fn replace(
        &mut self,
        name: impl Into<String>,
        url: &str,
        headers: HashMap<String, String>,
    ) -> Result<(), WebhookError> {
        let name = name.into();
        validate_action_name(&name)?;
        let headers = protect_headers(headers)?;
        validate_remote_headers(&headers)?;
        let url = self.validate_url(url)?;
        let destination_policy = destination_policy(&url)?;
        self.entries.insert(
            name,
            RegisteredRemoteAction {
                endpoint: WebhookEndpoint {
                    url,
                    headers,
                    destination_policy,
                },
                contract: RemoteActionContract::compatibility_default(),
            },
        );
        Ok(())
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&WebhookEndpoint> {
        self.entries.get(name).map(|action| &action.endpoint)
    }

    fn action(&self, name: &str) -> Option<&RegisteredRemoteAction> {
        self.entries.get(name)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub const fn allows_plaintext(&self) -> bool {
        self.allow_loopback_plaintext
    }

    fn tool_parameters(&self) -> Value {
        let choices = self
            .entries
            .iter()
            .map(|(name, action)| {
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "name": {
                            "type": "string",
                            "const": name,
                            "description": action.contract.description
                        },
                        "payload": action.contract.input_schema
                    },
                    "required": ["name", "payload"]
                })
            })
            .collect::<Vec<_>>();
        json!({"type": "object", "oneOf": choices})
    }

    fn authority_digest(&self) -> crate::runtime::ContentDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"openclaudia.remote-actions.v1");
        hasher.update([u8::from(self.allow_loopback_plaintext)]);
        for (name, action) in &self.entries {
            hash_field(&mut hasher, name.as_bytes());
            action
                .endpoint
                .url
                .expose(|url| hash_field(&mut hasher, url.as_bytes()));
            let mut header_names = action
                .endpoint
                .headers
                .names()
                .map(|name| name.as_str().to_string())
                .collect::<Vec<_>>();
            header_names.sort_unstable();
            for name in header_names {
                hash_field(&mut hasher, name.as_bytes());
                let _ = action.endpoint.headers.with_value(&name, |value| {
                    hash_field(&mut hasher, value.as_bytes());
                });
            }
            hash_field(
                &mut hasher,
                &serde_json::to_vec(&action.contract.input_schema)
                    .expect("JSON values always serialize"),
            );
            if let Some(output) = &action.contract.output_schema {
                hash_field(
                    &mut hasher,
                    &serde_json::to_vec(output).expect("JSON values always serialize"),
                );
            }
            hash_field(&mut hasher, action.contract.effect.as_str().as_bytes());
            hasher.update(action.contract.deadline.as_millis().to_le_bytes());
            hasher.update(action.contract.max_request_bytes.to_le_bytes());
            hasher.update(action.contract.max_response_bytes.to_le_bytes());
            hasher.update(action.contract.max_calls_per_run.to_le_bytes());
            hasher.update(action.contract.max_in_flight.to_le_bytes());
            hasher.update(action.contract.max_attempts.to_le_bytes());
            hasher.update([action.contract.idempotency as u8]);
        }
        crate::runtime::ContentDigest::from_sha256_bytes(hasher.finalize().into())
    }
}

impl Default for WebhookRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(bytes.len().to_le_bytes());
    hasher.update(bytes);
}

fn validate_action_name(name: &str) -> Result<(), WebhookError> {
    if name.is_empty()
        || name.len() > MAX_ACTION_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(WebhookError::InvalidName {});
    }
    Ok(())
}

fn protect_headers(
    headers: HashMap<String, String>,
) -> Result<crate::secrets::SensitiveHeaders, WebhookError> {
    let headers = crate::secrets::SensitiveHeaders::try_from(headers).map_err(|error| {
        WebhookError::InvalidHeaders {
            reason: error.to_string(),
        }
    })?;
    validate_remote_headers(&headers)?;
    Ok(headers)
}

fn validate_remote_headers(headers: &crate::secrets::SensitiveHeaders) -> Result<(), WebhookError> {
    const RESERVED: &[&str] = &[
        "accept",
        "connection",
        "content-length",
        "content-type",
        "host",
        "idempotency-key",
        "proxy-authorization",
        "transfer-encoding",
    ];
    if headers
        .names()
        .any(|name| RESERVED.contains(&name.as_str()))
    {
        return Err(WebhookError::InvalidHeaders {
            reason: "reserved transport header name".to_string(),
        });
    }
    Ok(())
}

fn scheme_with_default(raw: &str) -> (String, bool) {
    if let Some(colon) = raw.find(':') {
        let prefix = &raw[..colon];
        if !prefix.is_empty()
            && prefix
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
            && prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            return (raw.to_string(), false);
        }
    }
    (format!("https://{raw}"), true)
}

fn exact_loopback_host(parsed: &url::Url) -> bool {
    match parsed.host() {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn destination_policy(url: &WebhookUrl) -> Result<DestinationPolicy, WebhookError> {
    url.expose(|raw| {
        let parsed = url::Url::parse(raw).map_err(|_| WebhookError::Malformed {})?;
        if parsed.scheme() == "http" && exact_loopback_host(&parsed) {
            Ok(DestinationPolicy::ExactLoopback)
        } else {
            Ok(DestinationPolicy::PublicHttps)
        }
    })
}

#[derive(Debug, Default)]
struct ActionRuntimeState {
    calls: u32,
    in_flight: u32,
}

/// Run-owned action catalog and invocation counters.
pub struct RemoteActionService {
    registry: WebhookRegistry,
    state: Mutex<BTreeMap<String, ActionRuntimeState>>,
}

impl fmt::Debug for RemoteActionService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteActionService")
            .field("action_names", &self.registry.names().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl RemoteActionService {
    #[must_use]
    pub const fn new(registry: WebhookRegistry) -> Self {
        Self {
            registry,
            state: Mutex::new(BTreeMap::new()),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.registry.is_empty()
    }

    #[must_use]
    pub const fn registry(&self) -> &WebhookRegistry {
        &self.registry
    }

    pub(crate) fn tool_parameters(&self) -> Value {
        self.registry.tool_parameters()
    }

    pub(crate) fn authority_digest(&self) -> crate::runtime::ContentDigest {
        self.registry.authority_digest()
    }

    fn reserve(
        &self,
        name: &str,
        contract: &RemoteActionContract,
    ) -> Result<ActionLease<'_>, String> {
        let mut state = lock_state(&self.state);
        let action = state.entry(name.to_string()).or_default();
        if action.calls >= contract.max_calls_per_run {
            return Err(format!(
                "remote action '{name}' reached its per-run call limit of {}",
                contract.max_calls_per_run
            ));
        }
        if action.in_flight >= contract.max_in_flight {
            return Err(format!(
                "remote action '{name}' reached its in-flight limit of {}",
                contract.max_in_flight
            ));
        }
        action.calls = action.calls.saturating_add(1);
        action.in_flight = action.in_flight.saturating_add(1);
        drop(state);
        Ok(ActionLease {
            service: self,
            name: name.to_string(),
        })
    }
}

struct ActionLease<'a> {
    service: &'a RemoteActionService,
    name: String,
}

impl Drop for ActionLease<'_> {
    fn drop(&mut self) {
        let mut state = lock_state(&self.service.state);
        if let Some(action) = state.get_mut(&self.name) {
            action.in_flight = action.in_flight.saturating_sub(1);
        }
    }
}

fn lock_state(
    state: &Mutex<BTreeMap<String, ActionRuntimeState>>,
) -> MutexGuard<'_, BTreeMap<String, ActionRuntimeState>> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RemoteDelivery {
    Confirmed,
    NotDelivered,
    Ambiguous,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoteActionReceipt {
    schema_version: u16,
    action: String,
    effect: &'static str,
    delivery: RemoteDelivery,
    attempts: u32,
    status_code: Option<u16>,
    request_digest: String,
    idempotency_key_bound: bool,
    response: Option<Value>,
}

impl RemoteActionReceipt {
    fn new(name: &str, action: &RegisteredRemoteAction, request_digest: String) -> Self {
        Self {
            schema_version: REMOTE_ACTION_RECEIPT_SCHEMA_VERSION,
            action: name.to_string(),
            effect: action.contract.effect.as_str(),
            delivery: RemoteDelivery::NotDelivered,
            attempts: 0,
            status_code: None,
            request_digest,
            idempotency_key_bound: action.contract.idempotency
                == RemoteActionIdempotency::KeyHeader,
            response: None,
        }
    }
}

/// Execute one already-authorized named action through the run-owned service.
pub(crate) fn execute_remote_action(
    run: &std::sync::Arc<super::ToolRunContext>,
    permit: &super::registry::ToolDispatchPermit,
    args: &HashMap<String, Value>,
) -> super::ToolHandlerResult {
    if args.len() != 2 || !args.contains_key("name") || !args.contains_key("payload") {
        return invalid_arguments(
            "remote_trigger accepts only the host-published 'name' and 'payload' arguments",
        );
    }
    let Some(name) = args.get("name").and_then(Value::as_str) else {
        return invalid_arguments("remote_trigger requires string argument 'name'");
    };
    let Some(payload) = args.get("payload") else {
        return invalid_arguments("remote_trigger requires argument 'payload'");
    };
    let Some(action) = run.remote_actions().registry.action(name).cloned() else {
        return super::ToolHandlerResult::error(super::ToolFailure::new(
            super::ToolFailureCode::Unavailable,
            WebhookError::UnknownWebhook {
                name: name.to_string(),
            }
            .to_string(),
            super::ToolRetryability::Never,
        ));
    };
    if let Err(reason) = permit.require_host_approval() {
        return super::ToolHandlerResult::error(super::ToolFailure::new(
            super::ToolFailureCode::PermissionDenied,
            format!("remote action requires exact host approval: {reason}"),
            super::ToolRetryability::Never,
        ));
    }
    let Ok(validator) = jsonschema::draft202012::new(&action.contract.input_schema) else {
        return super::ToolHandlerResult::error(super::ToolFailure::new(
            super::ToolFailureCode::Internal,
            "host-registered remote action has an invalid input schema".to_string(),
            super::ToolRetryability::Never,
        ));
    };
    if !validator.is_valid(payload) {
        return invalid_arguments(format!(
            "payload does not satisfy the host-owned schema for remote action '{name}'"
        ));
    }
    let Ok(body) = serde_json::to_vec(payload) else {
        return invalid_arguments("remote action payload could not be serialized");
    };
    if body.len() > action.contract.max_request_bytes {
        return invalid_arguments(format!(
            "remote action payload exceeds its {}-byte request limit",
            action.contract.max_request_bytes
        ));
    }
    let cancellation = run.runtime().cancellation();
    if cancellation.is_cancelled() {
        return cancelled_before_dispatch(name);
    }
    let _lease = match run.remote_actions().reserve(name, &action.contract) {
        Ok(lease) => lease,
        Err(message) => {
            return super::ToolHandlerResult::error(super::ToolFailure::new(
                super::ToolFailureCode::PolicyDenied,
                message,
                super::ToolRetryability::Never,
            ));
        }
    };
    let request_digest = crate::runtime::ContentDigest::sha256(&body).to_string();
    let receipt = RemoteActionReceipt::new(name, &action, request_digest.clone());
    let idempotency_key = format!("openclaudia-{}-{}", run.run_id(), permit.invocation_id());
    let timeout = action
        .contract
        .deadline
        .saturating_add(Duration::from_secs(1));
    match super::web::run_blocking_with_timeout(
        execute_remote_action_async(
            name.to_string(),
            action.clone(),
            body,
            idempotency_key,
            cancellation,
            receipt,
        ),
        timeout,
    ) {
        Ok(result) => result,
        Err(message) => partial_result(
            &RemoteActionReceipt {
                delivery: RemoteDelivery::Ambiguous,
                ..RemoteActionReceipt::new(name, &action, request_digest)
            },
            super::ToolFailureCode::DeadlineExceeded,
            format!("remote action supervisor failed: {message}"),
            super::ToolRetryability::Unknown,
        ),
    }
}

#[allow(clippy::too_many_lines)] // Keep the dispatch-to-receipt state transition linear and auditable.
async fn execute_remote_action_async(
    name: String,
    action: RegisteredRemoteAction,
    body: Vec<u8>,
    idempotency_key: String,
    cancellation: crate::runtime::CancellationHandle,
    mut receipt: RemoteActionReceipt,
) -> super::ToolHandlerResult {
    let deadline = Instant::now() + action.contract.deadline;
    let (url, host, addrs) = match resolve_destination(&action, &cancellation, deadline).await {
        Ok(resolved) => resolved,
        Err(failure) => return super::ToolHandlerResult::error(failure),
    };
    let client =
        match crate::provider_transport::direct_client_with_pinned_resolution(&host, &addrs) {
            Ok(client) => client,
            Err(error) => {
                return super::ToolHandlerResult::error(super::ToolFailure::new(
                    super::ToolFailureCode::Unavailable,
                    safe_transport_message(&action.endpoint, &error.to_string()),
                    super::ToolRetryability::Never,
                ));
            }
        };

    for attempt in 1..=action.contract.max_attempts {
        if cancellation.is_cancelled() {
            return if receipt.attempts == 0 {
                cancelled_before_dispatch(&name)
            } else {
                partial_result(
                    &receipt,
                    super::ToolFailureCode::Cancelled,
                    format!("remote action '{name}' was cancelled after dispatch"),
                    super::ToolRetryability::Unknown,
                )
            };
        }
        receipt.attempts = attempt;
        let mut request = client
            .post(url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .body(body.clone());
        if action.contract.idempotency == RemoteActionIdempotency::KeyHeader {
            request = request.header("Idempotency-Key", &idempotency_key);
        }
        request = match action.endpoint.headers.apply(request) {
            Ok(request) => request,
            Err(error) => {
                return super::ToolHandlerResult::error(super::ToolFailure::new(
                    super::ToolFailureCode::Internal,
                    format!("remote action headers could not be applied: {error}"),
                    super::ToolRetryability::Never,
                ));
            }
        };

        // Crossing this line may have changed the remote system. Every later
        // transport/protocol failure is therefore partial, never a clean error.
        let response = tokio::select! {
            _ = cancellation.cancelled() => {
                return partial_result(
                    &receipt,
                    super::ToolFailureCode::Cancelled,
                    format!("remote action '{name}' was cancelled after dispatch"),
                    super::ToolRetryability::Unknown,
                );
            }
            response = crate::provider_transport::send_until(request, deadline) => response,
        };
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                let retryable = error
                    .retryable(crate::provider_transport::RequestReplaySafety::Idempotent)
                    && action.contract.idempotency == RemoteActionIdempotency::KeyHeader
                    && attempt < action.contract.max_attempts;
                if retryable {
                    if let Err(result) = retry_pause(&cancellation, deadline, attempt).await {
                        return partial_result(
                            &receipt,
                            result.0,
                            format!("remote action '{name}' {}", result.1),
                            super::ToolRetryability::Unknown,
                        );
                    }
                    continue;
                }
                receipt.delivery = if matches!(
                    error,
                    crate::provider_transport::ProviderTransportError::Request {
                        connect_failure: true,
                        ..
                    }
                ) {
                    RemoteDelivery::NotDelivered
                } else {
                    RemoteDelivery::Ambiguous
                };
                let message = safe_transport_message(&action.endpoint, &error.to_string());
                if receipt.delivery == RemoteDelivery::NotDelivered {
                    return error_with_receipt(
                        receipt,
                        super::ToolFailureCode::External,
                        message,
                        super::ToolRetryability::Safe,
                    );
                }
                return partial_result(
                    &receipt,
                    super::ToolFailureCode::External,
                    message,
                    super::ToolRetryability::Unknown,
                );
            }
        };
        receipt.status_code = Some(response.status().as_u16());
        receipt.delivery = RemoteDelivery::Confirmed;
        if crate::provider_transport::should_retry_status(
            response.status(),
            crate::provider_transport::RequestReplaySafety::Idempotent,
        ) && action.contract.idempotency == RemoteActionIdempotency::KeyHeader
            && attempt < action.contract.max_attempts
        {
            drop(response);
            if let Err(result) = retry_pause(&cancellation, deadline, attempt).await {
                return partial_result(
                    &receipt,
                    result.0,
                    format!("remote action '{name}' {}", result.1),
                    super::ToolRetryability::Unknown,
                );
            }
            continue;
        }
        let status = response.status();
        let bytes = tokio::select! {
            _ = cancellation.cancelled() => {
                return partial_result(
                    &receipt,
                    super::ToolFailureCode::Cancelled,
                    format!("remote action '{name}' was cancelled while reading its response"),
                    super::ToolRetryability::Unknown,
                );
            }
            result = tokio::time::timeout_at(
                deadline,
                crate::provider_transport::read_body_capped(
                    response,
                    action.contract.max_response_bytes,
                ),
            ) => match result {
                Ok(result) => result,
                Err(_) => {
                    return partial_result(
                        &receipt,
                        super::ToolFailureCode::DeadlineExceeded,
                        format!("remote action '{name}' exceeded its response-body deadline"),
                        super::ToolRetryability::Unknown,
                    );
                }
            },
        };
        let bytes = match bytes {
            Ok(bytes) => bytes,
            Err(error) => {
                return partial_result(
                    &receipt,
                    match error {
                        crate::provider_transport::ProviderTransportError::ResponseTooLarge {
                            ..
                        } => super::ToolFailureCode::InvalidInput,
                        crate::provider_transport::ProviderTransportError::Deadline { .. } => {
                            super::ToolFailureCode::DeadlineExceeded
                        }
                        _ => super::ToolFailureCode::External,
                    },
                    safe_transport_message(&action.endpoint, &error.to_string()),
                    super::ToolRetryability::Unknown,
                );
            }
        };
        let response_value = if bytes.is_empty() {
            Value::Null
        } else {
            match serde_json::from_slice::<Value>(&bytes) {
                Ok(value) => value,
                Err(_) => {
                    return partial_result(
                        &receipt,
                        super::ToolFailureCode::InvalidInput,
                        format!("remote action '{name}' returned invalid JSON"),
                        super::ToolRetryability::Never,
                    );
                }
            }
        };
        receipt.response = Some(response_value.clone());
        if !status.is_success() {
            return partial_result(
                &receipt,
                super::ToolFailureCode::External,
                format!(
                    "remote action '{name}' returned HTTP status {}",
                    status.as_u16()
                ),
                super::ToolRetryability::Never,
            );
        }
        if let Some(output_schema) = &action.contract.output_schema {
            let Ok(validator) = jsonschema::draft202012::new(output_schema) else {
                return partial_result(
                    &receipt,
                    super::ToolFailureCode::Internal,
                    "host-registered remote action has an invalid output schema".to_string(),
                    super::ToolRetryability::Never,
                );
            };
            if !validator.is_valid(&response_value) {
                return partial_result(
                    &receipt,
                    super::ToolFailureCode::InvalidInput,
                    format!("remote action '{name}' response violated its host-owned schema"),
                    super::ToolRetryability::Never,
                );
            }
        }
        return success_result(&receipt);
    }
    partial_result(
        &receipt,
        super::ToolFailureCode::External,
        format!("remote action '{name}' exhausted its bounded attempts"),
        super::ToolRetryability::Unknown,
    )
}

async fn resolve_destination(
    action: &RegisteredRemoteAction,
    cancellation: &crate::runtime::CancellationHandle,
    deadline: Instant,
) -> Result<(url::Url, String, Vec<SocketAddr>), super::ToolFailure> {
    let parsed = action
        .endpoint
        .url
        .expose(url::Url::parse)
        .map_err(|_| unavailable_failure("remote action destination became malformed"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| unavailable_failure("remote action destination has no host"))?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| unavailable_failure("remote action destination has no port"))?;
    let resolved = tokio::select! {
        _ = cancellation.cancelled() => {
            return Err(super::ToolFailure::new(
                super::ToolFailureCode::Cancelled,
                "remote action cancelled before destination resolution".to_string(),
                super::ToolRetryability::Never,
            ));
        }
        result = tokio::time::timeout_at(deadline, tokio::net::lookup_host((host.as_str(), port))) => {
            match result {
                Ok(Ok(addresses)) => addresses.collect::<Vec<_>>(),
                Ok(Err(_)) => return Err(unavailable_failure("remote action destination could not be resolved")),
                Err(_) => return Err(super::ToolFailure::new(
                    super::ToolFailureCode::DeadlineExceeded,
                    "remote action destination resolution exceeded its deadline".to_string(),
                    super::ToolRetryability::Safe,
                )),
            }
        }
    };
    if resolved.is_empty() {
        return Err(unavailable_failure(
            "remote action destination resolved to no addresses",
        ));
    }
    validate_resolved_addresses(action.endpoint.destination_policy, &resolved)?;
    Ok((parsed, host, resolved))
}

fn validate_resolved_addresses(
    policy: DestinationPolicy,
    resolved: &[SocketAddr],
) -> Result<(), super::ToolFailure> {
    for address in resolved {
        match policy {
            DestinationPolicy::PublicHttps => {
                crate::web::validate_resolved_ip(address.ip()).map_err(|_| {
                    super::ToolFailure::new(
                        super::ToolFailureCode::PolicyDenied,
                        "remote action destination resolved to a forbidden address".to_string(),
                        super::ToolRetryability::Never,
                    )
                })?;
            }
            DestinationPolicy::ExactLoopback if !address.ip().is_loopback() => {
                return Err(super::ToolFailure::new(
                    super::ToolFailureCode::PolicyDenied,
                    "loopback remote action resolved outside loopback".to_string(),
                    super::ToolRetryability::Never,
                ));
            }
            DestinationPolicy::ExactLoopback => {}
        }
    }
    Ok(())
}

async fn retry_pause(
    cancellation: &crate::runtime::CancellationHandle,
    deadline: Instant,
    attempt: u32,
) -> Result<(), (super::ToolFailureCode, &'static str)> {
    let delay = Duration::from_millis(u64::from(attempt).saturating_mul(100).min(300));
    tokio::select! {
        _ = cancellation.cancelled() => Err((super::ToolFailureCode::Cancelled, "was cancelled during bounded retry backoff")),
        result = tokio::time::timeout_at(deadline, tokio::time::sleep(delay)) => {
            result.map_err(|_| (super::ToolFailureCode::DeadlineExceeded, "exceeded its deadline during bounded retry backoff"))
        }
    }
}

fn safe_transport_message(endpoint: &WebhookEndpoint, raw: &str) -> String {
    let header_safe = endpoint.headers.sanitize_diagnostic(raw);
    endpoint.url.sanitize(header_safe.as_str()).to_string()
}

fn invalid_arguments(message: impl Into<String>) -> super::ToolHandlerResult {
    super::ToolHandlerResult::error(super::ToolFailure::new(
        super::ToolFailureCode::InvalidArguments,
        message.into(),
        super::ToolRetryability::Never,
    ))
}

fn unavailable_failure(message: impl Into<String>) -> super::ToolFailure {
    super::ToolFailure::new(
        super::ToolFailureCode::Unavailable,
        message.into(),
        super::ToolRetryability::Safe,
    )
}

fn cancelled_before_dispatch(name: &str) -> super::ToolHandlerResult {
    super::ToolHandlerResult::error(super::ToolFailure::new(
        super::ToolFailureCode::Cancelled,
        format!("remote action '{name}' was cancelled before dispatch"),
        super::ToolRetryability::Never,
    ))
}

fn success_result(receipt: &RemoteActionReceipt) -> super::ToolHandlerResult {
    let structured = serde_json::to_value(receipt).expect("remote action receipt serializes");
    super::ToolHandlerResult::success_structured(
        format!("Remote action '{}' completed", receipt.action),
        structured,
    )
}

fn error_with_receipt(
    receipt: RemoteActionReceipt,
    code: super::ToolFailureCode,
    message: String,
    retryability: super::ToolRetryability,
) -> super::ToolHandlerResult {
    let mut failure = super::ToolFailure::new(code, message, retryability);
    failure.source = Some("remote_action".to_string());
    failure.recovery =
        Some(serde_json::to_value(receipt).expect("remote action receipt serializes"));
    super::ToolHandlerResult::error(failure)
}

fn partial_result(
    receipt: &RemoteActionReceipt,
    code: super::ToolFailureCode,
    message: String,
    retryability: super::ToolRetryability,
) -> super::ToolHandlerResult {
    let structured = serde_json::to_value(receipt).expect("remote action receipt serializes");
    let mut failure = super::ToolFailure::new(code, message, retryability);
    failure.source = Some("remote_action".to_string());
    failure.recovery = Some(structured.clone());
    super::ToolHandlerResult::partial_structured(
        format!(
            "Remote action '{}' may have changed the remote system; inspect the typed receipt",
            receipt.action
        ),
        structured,
        vec![failure],
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_url_and_loopback_plaintext_policy_are_exact() {
        let strict = WebhookRegistry::new();
        assert!(strict.validate_url("https://example.com/hook").is_ok());
        assert!(matches!(
            strict.validate_url("http://localhost:8080/hook"),
            Err(WebhookError::InsecureScheme {})
        ));

        let local = WebhookRegistry::new_allow_plaintext();
        assert!(local.validate_url("http://127.0.0.1:8080/hook").is_ok());
        assert!(matches!(
            local.validate_url("http://example.com/hook"),
            Err(WebhookError::InsecureScheme {})
        ));
        assert!(matches!(
            strict.validate_url("https://user:pass@example.com/hook"),
            Err(WebhookError::CredentialsInUrl {})
        ));
        assert!(matches!(
            strict.validate_url("https://127.0.0.1/hook"),
            Err(WebhookError::Malformed {})
        ));
        assert!(matches!(
            strict.validate_url("https://169.254.169.254/latest/meta-data"),
            Err(WebhookError::Malformed {})
        ));
        assert!(matches!(
            strict.validate_url("https://metadata.google.internal/computeMetadata/v1"),
            Err(WebhookError::Malformed {})
        ));
        assert!(matches!(
            strict.validate_url("https://example.com/hook#credential"),
            Err(WebhookError::CredentialsInUrl {})
        ));
    }

    #[test]
    fn generated_parameters_contain_only_names_and_payload_contracts() {
        let mut registry = WebhookRegistry::new();
        registry
            .register(
                "deploy",
                "https://signed.example.com/hook?secret=marker-s070",
                HashMap::from([(
                    "Authorization".to_string(),
                    "Bearer marker-s070".to_string(),
                )]),
            )
            .expect("action");
        let encoded = registry.tool_parameters().to_string();
        assert!(encoded.contains("deploy"));
        assert!(encoded.contains("payload"));
        assert!(!encoded.contains("signed.example.com"));
        assert!(!encoded.contains("marker-s070"));
        assert!(!encoded.to_ascii_lowercase().contains("authorization"));
        assert!(!encoded.contains("url"));
    }

    #[test]
    fn schema_and_retry_contracts_fail_closed() {
        let invalid = RemoteActionContract::try_from_spec(RemoteActionContractSpec {
            description: String::new(),
            input_schema: json!({"type": "string"}),
            output_schema: None,
            effect: RemoteActionEffect::ExternalMutation,
            idempotency: RemoteActionIdempotency::None,
            deadline: Duration::from_secs(1),
            max_request_bytes: 1024,
            max_response_bytes: 1024,
            max_calls_per_run: 1,
            max_in_flight: 1,
            max_attempts: 2,
        });
        assert!(invalid.is_err());
    }

    #[test]
    fn resolved_destination_policy_blocks_rebinding_in_both_directions() {
        let private: SocketAddr = "127.0.0.1:443".parse().expect("private address");
        let public: SocketAddr = "8.8.8.8:443".parse().expect("public address");
        assert!(validate_resolved_addresses(DestinationPolicy::PublicHttps, &[private]).is_err());
        assert!(validate_resolved_addresses(DestinationPolicy::ExactLoopback, &[public]).is_err());
        assert!(validate_resolved_addresses(DestinationPolicy::ExactLoopback, &[private]).is_ok());
        assert!(validate_resolved_addresses(DestinationPolicy::PublicHttps, &[public]).is_ok());
    }
}
