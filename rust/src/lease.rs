//! Lease manager: renew, revoke, look up and auto-renew leases.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde_json::json;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::api::{self, ApiRequest};
use crate::client::OpenBaoClient;
use crate::core::{Error, Result};
use crate::database::Lease;
use crate::renew::{guarded, renew_wait, sleep, Background};

/// Result of [`LeaseManager::renew`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeaseInfo {
    /// Lease id.
    pub id: String,
    /// Whether the lease can be renewed again.
    pub renewable: bool,
    /// Granted TTL (capped by the max TTL; see `warnings`).
    pub duration: Duration,
    /// Server warnings (for example the max-TTL cap).
    pub warnings: Vec<String>,
}

impl LeaseInfo {
    /// Whether the server capped the grant at the lease's max TTL.
    pub fn capped(&self) -> bool {
        self.warnings.iter().any(|w| {
            let w = w.to_ascii_lowercase();
            w.contains("capped") || w.contains("max_ttl")
        })
    }
}

/// Result of [`LeaseManager::lookup`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeaseLookup {
    /// Lease id.
    pub id: String,
    /// Secret path that issued it.
    pub path: String,
    /// Issue time.
    pub issue_time: Option<SystemTime>,
    /// Expiry time.
    pub expire_time: Option<SystemTime>,
    /// Last renewal time.
    pub last_renewal: Option<SystemTime>,
    /// Whether it can be renewed.
    pub renewable: bool,
    /// Remaining TTL.
    pub ttl: Duration,
}

/// Lease manager; get it with [`OpenBaoClient::leases`]. Closing the client stops
/// every managed lease (leases are not revoked).
#[derive(Debug, Clone)]
pub struct LeaseManager {
    client: OpenBaoClient,
}

/// Callback receiving a renewal result.
pub type OnLeaseRenew = Arc<dyn Fn(&LeaseInfo) + Send + Sync>;
/// Callback receiving a renewal error.
pub type OnLeaseError = Arc<dyn Fn(&Error) + Send + Sync>;
/// Callback run exactly once when a managed lease expires.
pub type OnLeaseExpire = Arc<dyn Fn(&Lease) + Send + Sync>;

/// Options of [`LeaseManager::manage`].
#[derive(Clone, Default)]
pub struct ManageOptions {
    /// TTL requested on every renewal (`None` = the lease default).
    pub increment: Option<Duration>,
    /// Called after every successful renewal.
    pub on_renew: Option<OnLeaseRenew>,
    /// Receives renewal errors; renewal continues while the lease is valid.
    pub on_error: Option<OnLeaseError>,
    /// Called exactly once when the lease expires (max TTL reached, not renewable or
    /// rejected by the server); management then stops.
    pub on_expire: Option<OnLeaseExpire>,
}

impl fmt::Debug for ManageOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManageOptions")
            .field("increment", &self.increment)
            .finish_non_exhaustive()
    }
}

/// A lease renewed in the background ([`LeaseManager::manage`]). Clones share it.
#[derive(Clone)]
pub struct ManagedLease {
    lease: Arc<Lease>,
    bg: Arc<Background>,
}

impl fmt::Debug for ManagedLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedLease")
            .field("lease", &self.lease.id)
            .field("stopped", &self.is_stopped())
            .finish()
    }
}

impl ManagedLease {
    /// The managed lease.
    pub fn lease(&self) -> &Lease {
        &self.lease
    }
    /// Stops renewing (the lease is not revoked). Idempotent.
    pub fn stop(&self) {
        self.bg.stop();
    }
    /// Whether management ended (stopped, expired or client closed).
    pub fn is_stopped(&self) -> bool {
        self.bg.is_stopped()
    }
    /// Waits until management has ended.
    pub async fn done(&self) {
        self.bg.wait().await;
    }
}

impl LeaseManager {
    pub(crate) fn new(client: OpenBaoClient) -> Self {
        LeaseManager { client }
    }

    /// Renews a lease (`PUT sys/leases/renew`); `increment` is the requested TTL (`None` =
    /// the lease default). An unknown or revoked lease is `VALIDATION`.
    pub async fn renew(&self, lease_id: &str, increment: Option<Duration>) -> Result<LeaseInfo> {
        let op = "lease.renew";
        api::require_arg(op, "lease_id", lease_id)?;
        let mut body = json!({ "lease_id": lease_id });
        if let Some(inc) = increment.filter(|d| !d.is_zero()) {
            body["increment"] = json!(inc.as_secs().max(1));
        }
        let env = self
            .client
            .call(ApiRequest::put("sys/leases/renew", op).json(body))
            .await?;
        Ok(LeaseInfo {
            id: if env.lease_id.is_empty() {
                lease_id.to_owned()
            } else {
                env.lease_id
            },
            renewable: env.renewable,
            duration: env.lease_duration,
            warnings: env.warnings,
        })
    }

    /// Revokes a lease now (`PUT sys/leases/revoke`). A managed lease then ends with
    /// `on_expire` at its next renewal (the server rejects it).
    pub async fn revoke(&self, lease_id: &str) -> Result<()> {
        let op = "lease.revoke";
        api::require_arg(op, "lease_id", lease_id)?;
        self.client
            .call(ApiRequest::put("sys/leases/revoke", op).json(json!({ "lease_id": lease_id })))
            .await?;
        Ok(())
    }

    /// Revokes every lease under `prefix` (`PUT sys/leases/revoke-prefix/<prefix>`).
    pub async fn revoke_prefix(&self, prefix: &str) -> Result<()> {
        let op = "lease.revokePrefix";
        api::require_arg(op, "prefix", prefix)?;
        self.client
            .call(ApiRequest::put(
                format!("sys/leases/revoke-prefix/{}", api::encode_path(prefix)),
                op,
            ))
            .await?;
        Ok(())
    }

    /// Properties of a lease (`PUT sys/leases/lookup`).
    pub async fn lookup(&self, lease_id: &str) -> Result<LeaseLookup> {
        let op = "lease.lookup";
        api::require_arg(op, "lease_id", lease_id)?;
        let d = self
            .client
            .data(ApiRequest::put("sys/leases/lookup", op).json(json!({ "lease_id": lease_id })))
            .await?;
        Ok(LeaseLookup {
            id: api::s(&d, "id"),
            path: api::s(&d, "path"),
            issue_time: api::time(&d, "issue_time"),
            expire_time: api::time(&d, "expire_time"),
            last_renewal: api::time(&d, "last_renewal"),
            renewable: api::b(&d, "renewable"),
            ttl: api::secs(&d, "ttl"),
        })
    }

    /// Renews `lease` at 2/3 of its remaining TTL until the max TTL caps the grant, then
    /// calls `on_expire` once at expiry. Stop the handle or close the client to end it.
    pub fn manage(&self, lease: Lease, opts: ManageOptions) -> ManagedLease {
        let bg = Background::new(self.client.background());
        let lease = Arc::new(lease);
        bg.set_task(tokio::spawn(run(
            self.clone(),
            lease.clone(),
            opts,
            bg.token.clone(),
        )));
        ManagedLease { lease, bg }
    }
}

async fn run(m: LeaseManager, lease: Arc<Lease>, opts: ManageOptions, token: CancellationToken) {
    if lease.duration.is_zero() {
        token.cancelled().await;
        return;
    }
    let expire = || {
        if let Some(cb) = &opts.on_expire {
            guarded(|| cb(&lease));
        }
        token.cancel();
    };
    let mut expiry = lease.issued_at + lease.duration;
    let mut renewable = lease.renewable && !lease.id.is_empty();
    while renewable {
        if !sleep(&token, renew_wait(Instant::now(), expiry)).await {
            return;
        }
        let result = tokio::select! {
            biased;
            _ = token.cancelled() => return,
            r = m.renew(&lease.id, opts.increment) => r,
        };
        match result {
            Ok(info) => {
                expiry = Instant::now() + info.duration;
                let capped = info.capped()
                    || opts
                        .increment
                        .is_some_and(|inc| !inc.is_zero() && info.duration < inc);
                renewable = info.renewable && !capped && !info.duration.is_zero();
                if let Some(cb) = &opts.on_renew {
                    guarded(|| cb(&info));
                }
            }
            Err(err) => {
                if let Some(cb) = &opts.on_error {
                    guarded(|| cb(&err));
                }
                if !err.is_retryable() {
                    expire();
                    return;
                }
                if Instant::now() >= expiry {
                    break;
                }
            }
        }
    }
    let wait = expiry.saturating_duration_since(Instant::now());
    if !wait.is_zero() && !sleep(&token, wait).await {
        return;
    }
    expire();
}
