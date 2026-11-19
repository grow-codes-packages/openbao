//! Background renewal: [`TokenRenewer`] and the scheduling shared with managed leases.

use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::auth::{Auth, AuthInfo, TokenInfo};
use crate::core::Error;

/// Share of the remaining TTL after which a renewal runs.
const RENEW_FRACTION: f64 = 2.0 / 3.0;
/// Keeps a failing renewal loop from spinning.
const MIN_RENEW_WAIT: Duration = Duration::from_millis(100);

/// How long to wait before renewing something that expires at `expiry`.
pub(crate) fn renew_wait(now: Instant, expiry: Instant) -> Duration {
    expiry
        .saturating_duration_since(now)
        .mul_f64(RENEW_FRACTION)
        .max(MIN_RENEW_WAIT)
}

/// Calls `f`, ignoring panics (callbacks must never kill a background task).
pub(crate) fn guarded(f: impl FnOnce()) {
    let _ = catch_unwind(AssertUnwindSafe(f));
}

/// Sleeps for `d`; `false` when `token` was cancelled first.
pub(crate) async fn sleep(token: &CancellationToken, d: Duration) -> bool {
    tokio::select! {
        biased;
        _ = token.cancelled() => false,
        _ = tokio::time::sleep(d) => true,
    }
}

/// A stoppable background task owned by the client.
pub(crate) struct Background {
    pub token: CancellationToken,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl Background {
    pub fn new(token: CancellationToken) -> Arc<Self> {
        Arc::new(Background {
            token,
            task: Mutex::new(None),
        })
    }
    pub fn set_task(&self, task: JoinHandle<()>) {
        *self.task.lock().unwrap_or_else(|e| e.into_inner()) = Some(task);
    }
    pub fn stop(&self) {
        self.token.cancel();
    }
    pub fn is_stopped(&self) -> bool {
        self.token.is_cancelled()
    }
    /// Waits until the task ended (without stopping it).
    pub async fn wait(&self) {
        let task = self.task.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }
}

/// Callback receiving a renewed token.
pub type OnRenew = Arc<dyn Fn(&AuthInfo) + Send + Sync>;
/// Callback receiving a renewal error.
pub type OnRenewError = Arc<dyn Fn(&Error) + Send + Sync>;
/// Callback run once when the token expires for good.
pub type OnExpire = Arc<dyn Fn() + Send + Sync>;

/// Options of [`Auth::start_renewer`].
#[derive(Clone, Default)]
pub struct TokenRenewerOptions {
    /// TTL requested on every renewal (`None` = the token default).
    pub increment: Option<Duration>,
    /// Logs in again with the method of the last [`Auth::login`] when the token can no
    /// longer be renewed (not renewable, max TTL reached or renewal rejected). Without it,
    /// `on_expire` is called when the token expires.
    pub relogin: bool,
    /// Called after every successful renewal or re-login.
    pub on_renew: Option<OnRenew>,
    /// Receives renewal and re-login errors; the loop keeps going while the token is valid.
    pub on_error: Option<OnRenewError>,
    /// Called once when the token expires and cannot be renewed or replaced; the renewer
    /// then stops.
    pub on_expire: Option<OnExpire>,
}

impl fmt::Debug for TokenRenewerOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRenewerOptions")
            .field("increment", &self.increment)
            .field("relogin", &self.relogin)
            .finish_non_exhaustive()
    }
}

/// Keeps the client token alive: renews at 2/3 of the remaining TTL, stops renewing when
/// the token is not renewable or the max TTL caps the grant, then re-logs in
/// ([`TokenRenewerOptions::relogin`]) or calls `on_expire`. Clones share the renewer.
#[derive(Clone)]
pub struct TokenRenewer {
    bg: Arc<Background>,
}

impl fmt::Debug for TokenRenewer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRenewer")
            .field("stopped", &self.is_stopped())
            .finish()
    }
}

impl TokenRenewer {
    pub(crate) fn start(auth: Auth, info: TokenInfo, opts: TokenRenewerOptions) -> Self {
        let bg = Background::new(auth.client().background());
        let token = bg.token.clone();
        bg.set_task(tokio::spawn(run(
            auth,
            opts,
            token,
            info.ttl,
            info.renewable,
        )));
        TokenRenewer { bg }
    }

    /// Stops the renewer (the token is not revoked). Idempotent.
    pub fn stop(&self) {
        self.bg.stop();
    }

    /// Whether the renewer was stopped (by [`TokenRenewer::stop`] or the client's close).
    pub fn is_stopped(&self) -> bool {
        self.bg.is_stopped()
    }

    /// Waits until the renewer has ended (stopped or expired).
    pub async fn done(&self) {
        self.bg.wait().await;
    }
}

async fn run(
    auth: Auth,
    opts: TokenRenewerOptions,
    token: CancellationToken,
    ttl: Duration,
    mut renewable: bool,
) {
    if ttl.is_zero() {
        token.cancelled().await; // the token never expires: nothing to renew
        return;
    }
    let mut expiry = Instant::now() + ttl;
    let emit_error = |err: &Error| {
        if let Some(cb) = &opts.on_error {
            guarded(|| cb(err));
        }
    };
    let emit_renew = |info: &AuthInfo| {
        if let Some(cb) = &opts.on_renew {
            guarded(|| cb(info));
        }
    };
    loop {
        if renewable {
            if !sleep(&token, renew_wait(Instant::now(), expiry)).await {
                return;
            }
            let result = tokio::select! {
                biased;
                _ = token.cancelled() => return,
                r = auth.renew_self(opts.increment) => r,
            };
            match result {
                Ok(info) => {
                    expiry = Instant::now() + info.lease_duration;
                    let capped = opts
                        .increment
                        .is_some_and(|inc| !inc.is_zero() && info.lease_duration < inc);
                    renewable = info.renewable && !capped && !info.lease_duration.is_zero();
                    emit_renew(&info);
                }
                Err(err) => {
                    emit_error(&err);
                    if !err.is_retryable() || Instant::now() >= expiry {
                        renewable = false;
                    }
                }
            }
            continue;
        }
        if opts.relogin {
            if let Some(method) = auth.client().last_login() {
                if Instant::now() < expiry
                    && !sleep(&token, renew_wait(Instant::now(), expiry)).await
                {
                    return;
                }
                let result = tokio::select! {
                    biased;
                    _ = token.cancelled() => return,
                    r = auth.login_arc(method) => r,
                };
                match result {
                    Ok(info) => {
                        expiry = Instant::now() + info.lease_duration;
                        renewable = info.renewable;
                        emit_renew(&info);
                        if info.lease_duration.is_zero() {
                            token.cancelled().await;
                            return;
                        }
                        continue;
                    }
                    Err(err) => {
                        emit_error(&err);
                        if err.is_retryable() && Instant::now() < expiry {
                            continue;
                        }
                    }
                }
            }
        }
        let wait = expiry.saturating_duration_since(Instant::now());
        if !wait.is_zero() && !sleep(&token, wait).await {
            return;
        }
        if let Some(cb) = &opts.on_expire {
            guarded(|| cb());
        }
        token.cancel();
        return;
    }
}
