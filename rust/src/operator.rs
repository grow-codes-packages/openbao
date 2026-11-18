//! Server lifecycle helpers for tests and bootstrap scripts (feature `testing`): `init`,
//! `unseal`, `seal` and `wait_for_active`.
//!
//! ```no_run
//! # async fn demo() -> grow_openbao::Result<()> {
//! use grow_openbao::operator::{self, InitOptions};
//! use grow_openbao::{OpenBaoClient, OpenBaoConfig};
//!
//! let client = OpenBaoClient::new(OpenBaoConfig::builder().url("http://openbao:8200").build()?)?;
//! if !operator::init_status(&client).await? {
//!     let init = operator::init(&client, &InitOptions::default()).await?;
//!     operator::unseal(&client, init.keys[0].expose_secret()).await?;
//!     client.set_token(Some(init.root_token.clone()));
//! }
//! operator::wait_for_active(&client, std::time::Duration::from_secs(30)).await?;
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

use serde_json::{json, Value};

use crate::api::{self, ApiRequest};
use crate::client::OpenBaoClient;
use crate::core::{poll_until, Error, HealthStatus, PollOptions, Result, Secret};
use crate::sys::SealStatus;

/// Options of [`init`]. With `recovery_shares` or `recovery_threshold` set (auto-unseal or
/// static seals), recovery shares are sent instead of secret shares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InitOptions {
    /// Unseal key shares (Shamir seal, default 1).
    pub secret_shares: Option<u32>,
    /// Shares needed to unseal (Shamir seal, default 1).
    pub secret_threshold: Option<u32>,
    /// Recovery key shares (auto-unseal / static seal).
    pub recovery_shares: Option<u32>,
    /// Recovery threshold (auto-unseal / static seal).
    pub recovery_threshold: Option<u32>,
}

/// Result of [`init`]. Every key is redacted when printed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InitResult {
    /// Unseal keys (hex); empty with an auto-unseal seal.
    pub keys: Vec<Secret>,
    /// Unseal keys (base64).
    pub keys_base64: Vec<Secret>,
    /// Recovery keys (hex), auto-unseal seals only.
    pub recovery_keys: Vec<Secret>,
    /// Recovery keys (base64).
    pub recovery_keys_base64: Vec<Secret>,
    /// Initial root token.
    pub root_token: Secret,
}

fn secrets(client: &OpenBaoClient, v: &Value, key: &str) -> Vec<Secret> {
    api::strings(v, key)
        .into_iter()
        .filter(|s| !s.is_empty())
        .map(|s| {
            let s = Secret::new(s);
            client.remember_secret(&s);
            s
        })
        .collect()
}

/// Whether the server is initialised (`GET sys/init`).
pub async fn init_status(client: &OpenBaoClient) -> Result<bool> {
    let resp = client
        .send(ApiRequest::get("sys/init", "testing.initStatus").no_auth())
        .await?;
    Ok(api::b(&resp.json::<Value>()?, "initialized"))
}

/// Initialises a new server (`PUT sys/init`). An initialised server is `VALIDATION`
/// ("already initialized"). Never retried after the request was sent.
pub async fn init(client: &OpenBaoClient, opts: &InitOptions) -> Result<InitResult> {
    let op = "testing.init";
    let body = if opts.recovery_shares.is_some() || opts.recovery_threshold.is_some() {
        json!({
            "recovery_shares": opts.recovery_shares.unwrap_or(1),
            "recovery_threshold": opts.recovery_threshold.unwrap_or(1),
        })
    } else {
        json!({
            "secret_shares": opts.secret_shares.unwrap_or(1),
            "secret_threshold": opts.secret_threshold.unwrap_or(1),
        })
    };
    let resp = client
        .send(
            ApiRequest::put("sys/init", op)
                .json(body)
                .no_auth()
                .idempotent(false),
        )
        .await?;
    let v: Value = resp.json()?;
    let root = api::s(&v, "root_token");
    if root.is_empty() {
        return Err(Error::unavailable(format!(
            "{op}: the response carried no root token"
        )));
    }
    let root_token = Secret::new(root);
    client.remember_secret(&root_token);
    Ok(InitResult {
        keys: secrets(client, &v, "keys"),
        keys_base64: secrets(client, &v, "keys_base64"),
        recovery_keys: secrets(client, &v, "recovery_keys"),
        recovery_keys_base64: secrets(client, &v, "recovery_keys_base64"),
        root_token,
    })
}

/// Enters one unseal key (hex or base64) (`PUT sys/unseal`); returns the seal status.
pub async fn unseal(client: &OpenBaoClient, key: &str) -> Result<SealStatus> {
    let op = "testing.unseal";
    api::require_arg(op, "key", key)?;
    client.remember(key);
    unseal_body(client, json!({ "key": key })).await
}

/// Discards the unseal keys entered so far (`PUT sys/unseal {"reset": true}`).
pub async fn unseal_reset(client: &OpenBaoClient) -> Result<SealStatus> {
    unseal_body(client, json!({ "reset": true })).await
}

async fn unseal_body(client: &OpenBaoClient, body: Value) -> Result<SealStatus> {
    let resp = client
        .send(
            ApiRequest::put("sys/unseal", "testing.unseal")
                .json(body)
                .no_auth()
                .idempotent(false),
        )
        .await?;
    Ok(SealStatus::from_value(&resp.json::<Value>()?))
}

/// Seals the server (`PUT sys/seal`, needs a root or sudo token).
pub async fn seal(client: &OpenBaoClient) -> Result<()> {
    client
        .call(ApiRequest::put("sys/seal", "testing.seal"))
        .await?;
    Ok(())
}

/// Polls `health()` every 250 ms until the node is active (initialised, unsealed and
/// leader); `TIMEOUT` when it does not become active within `timeout`.
pub async fn wait_for_active(client: &OpenBaoClient, timeout: Duration) -> Result<HealthStatus> {
    let opts = PollOptions {
        timeout,
        interval: Duration::from_millis(250),
    };
    poll_until("testing.waitForActive", opts, || async {
        let h = client.health().await?;
        Ok(h.healthy.then_some(h))
    })
    .await
}
