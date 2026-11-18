//! Response wrapping: single-use wrapping tokens.

use std::time::{Duration, SystemTime};

use serde_json::{json, Map, Value};

use crate::api::{self, ApiRequest, Envelope};
use crate::auth::AuthInfo;
use crate::client::OpenBaoClient;
use crate::core::{Error, Result, Secret};

/// A wrapping token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WrapInfo {
    /// The single-use wrapping token (redacted when printed).
    pub token: Secret,
    /// Accessor.
    pub accessor: String,
    /// TTL.
    pub ttl: Duration,
    /// Creation time.
    pub creation_time: Option<SystemTime>,
    /// Path whose response was wrapped (`sys/wrapping/wrap` for `wrap`).
    pub creation_path: String,
}

impl WrapInfo {
    fn from_value(v: &Value) -> Option<Self> {
        let token = api::s(v, "token");
        (!token.is_empty()).then(|| WrapInfo {
            token: Secret::new(token),
            accessor: api::s(v, "accessor"),
            ttl: api::secs(v, "ttl"),
            creation_time: api::time(v, "creation_time"),
            creation_path: api::s(v, "creation_path"),
        })
    }
}

/// Result of [`Wrapping::lookup_wrapping`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WrapLookup {
    /// Path whose response was wrapped.
    pub creation_path: String,
    /// Creation time.
    pub creation_time: Option<SystemTime>,
    /// TTL at creation.
    pub creation_ttl: Duration,
}

/// A full OpenBao response (the payload of an unwrapped token can be any API response).
#[derive(Clone, PartialEq)]
pub struct SecretResponse {
    /// Request id.
    pub request_id: String,
    /// Lease id (leased secrets).
    pub lease_id: String,
    /// Whether the lease can be renewed.
    pub renewable: bool,
    /// Lease TTL.
    pub lease_duration: Duration,
    /// Response data (the wrapped map for a `wrap` token; redacted in `Debug`).
    pub data: Map<String, Value>,
    /// Warnings.
    pub warnings: Vec<String>,
    /// Token issued by the response (logins, token create).
    pub auth: Option<AuthInfo>,
    /// Set when the response itself was wrapped.
    pub wrap_info: Option<WrapInfo>,
}

impl std::fmt::Debug for SecretResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretResponse")
            .field("request_id", &self.request_id)
            .field("lease_id", &self.lease_id)
            .field("lease_duration", &self.lease_duration)
            .field(
                "data",
                &format_args!("[REDACTED; {} keys]", self.data.len()),
            )
            .field("auth", &self.auth)
            .field("wrap_info", &self.wrap_info)
            .finish_non_exhaustive()
    }
}

impl SecretResponse {
    fn from_envelope(env: Envelope) -> Self {
        SecretResponse {
            request_id: env.request_id,
            lease_id: env.lease_id,
            renewable: env.renewable,
            lease_duration: env.lease_duration,
            data: env.data.as_object().cloned().unwrap_or_default(),
            warnings: env.warnings,
            auth: (!env.auth.is_null()).then(|| AuthInfo::from_value(&env.auth)),
            wrap_info: WrapInfo::from_value(&env.wrap_info),
        }
    }
}

/// Response-wrapping module; get it with [`OpenBaoClient::wrapping`].
#[derive(Debug, Clone)]
pub struct Wrapping {
    client: OpenBaoClient,
}

impl Wrapping {
    pub(crate) fn new(client: OpenBaoClient) -> Self {
        Wrapping { client }
    }

    /// Stores `data` (a JSON object) behind a new wrapping token valid for `ttl`
    /// (`POST sys/wrapping/wrap` with `X-Vault-Wrap-TTL`).
    pub async fn wrap(&self, data: Value, ttl: Duration) -> Result<WrapInfo> {
        let op = "wrapping.wrap";
        if ttl.is_zero() {
            return Err(api::invalid(op, "ttl must be positive"));
        }
        let data = match data {
            Value::Object(m) => Value::Object(m),
            Value::Null => json!({}),
            _ => return Err(api::invalid(op, "data must be a JSON object")),
        };
        let env = self
            .client
            .call(
                ApiRequest::post("sys/wrapping/wrap", op)
                    .json(data)
                    .wrap_ttl(ttl),
            )
            .await?;
        WrapInfo::from_value(&env.wrap_info).ok_or_else(|| {
            Error::unavailable(format!("{op}: the response carried no wrapping token"))
        })
    }

    /// Returns the wrapped response and consumes the token (`POST sys/wrapping/unwrap`
    /// authenticated with the wrapping token). Never retried after the request was sent;
    /// a used or invalid token is `VALIDATION`.
    pub async fn unwrap(&self, token: &str) -> Result<SecretResponse> {
        let op = "wrapping.unwrap";
        api::require_arg(op, "token", token)?;
        let token = Secret::new(token);
        self.client.remember_secret(&token);
        let env = self
            .client
            .call(
                ApiRequest::post("sys/wrapping/unwrap", op)
                    .token(token)
                    .idempotent(false),
            )
            .await?;
        Ok(SecretResponse::from_envelope(env))
    }

    /// A wrapping token's properties without consuming it (`POST sys/wrapping/lookup`).
    pub async fn lookup_wrapping(&self, token: &str) -> Result<WrapLookup> {
        let op = "wrapping.lookup";
        api::require_arg(op, "token", token)?;
        self.client.remember(token);
        let d = self
            .client
            .data(ApiRequest::post("sys/wrapping/lookup", op).json(json!({ "token": token })))
            .await?;
        Ok(WrapLookup {
            creation_path: api::s(&d, "creation_path"),
            creation_time: api::time(&d, "creation_time"),
            creation_ttl: api::secs(&d, "creation_ttl"),
        })
    }
}
