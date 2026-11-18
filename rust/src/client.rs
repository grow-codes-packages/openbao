// Skeleton created by sdk-kit 0.1.0; owned by this repository (edit freely).
//! `OpenBaoClient`: entry point of the SDK (SPEC §2.4) and the request plumbing of the
//! service modules.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::future::BoxFuture;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::api::{self, ApiRequest, Envelope};
use crate::auth::{Auth, AuthMethod};
use crate::config::OpenBaoConfig;
use crate::core::lifecycle::CloseGroup;
use crate::core::{Error, ErrorCode, HealthStatus, HttpTransport, Response, Result, Secret};
use crate::database::Database;
use crate::kv::{Kv, KvV1, KvV2};
use crate::lease::LeaseManager;
use crate::pki::Pki;
use crate::provider::{KvSecretsProvider, SecretsProviderOptions};
use crate::sys::Sys;
use crate::transit::Transit;
use crate::wrapping::Wrapping;

/// `sys/health` statuses that describe a server state rather than a failure.
const HEALTH_STATUSES: [u16; 6] = [429, 472, 473, 500, 501, 503];

/// Async client for OpenBao. Cheap to clone (clones share one connection pool, the token
/// and the background tasks).
///
/// Service modules hang off the client: [`auth`](Self::auth), [`kv`](Self::kv) /
/// [`kv_v1`](Self::kv_v1) / [`kv_v2`](Self::kv_v2), [`secrets`](Self::secrets) (the
/// `SecretsProvider` over KV), [`transit`](Self::transit), [`database`](Self::database),
/// [`lease_manager`](Self::lease_manager), [`pki`](Self::pki), [`sys`](Self::sys) and
/// [`wrapping`](Self::wrapping). [`close`](Self::close) stops every token renewer, managed
/// lease and secrets watcher started through the client.
#[derive(Debug, Clone)]
pub struct OpenBaoClient {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    config: OpenBaoConfig,
    transport: HttpTransport,
    on_close: CloseGroup,
    token: RwLock<Option<Secret>>,
    kv_versions: Mutex<HashMap<String, u8>>,
    last_login: Mutex<Option<Arc<dyn AuthMethod>>>,
    background: CancellationToken,
}

impl OpenBaoClient {
    /// Creates a client from a configuration.
    pub fn new(config: OpenBaoConfig) -> Result<Self> {
        config.validate()?;
        let transport = HttpTransport::new(config.common())?;
        if let Some(token) = config.token() {
            transport.add_known_secret(token);
        }
        let token = config.token().cloned();
        Ok(OpenBaoClient {
            inner: Arc::new(Inner {
                config,
                transport,
                on_close: CloseGroup::new(),
                token: RwLock::new(token),
                kv_versions: Mutex::new(HashMap::new()),
                last_login: Mutex::new(None),
                background: CancellationToken::new(),
            }),
        })
    }

    /// Creates a client from the process environment (see [`OpenBaoConfig::from_env`]).
    pub fn from_env() -> Result<Self> {
        Self::new(OpenBaoConfig::from_env()?)
    }

    /// The configuration in use (its token is the configured one, not a token obtained
    /// later by a login).
    pub fn config(&self) -> &OpenBaoConfig {
        &self.inner.config
    }

    /// The HTTP transport (for custom calls).
    pub fn transport(&self) -> &HttpTransport {
        &self.inner.transport
    }

    /// Replaces the token sent as `X-Vault-Token` (`None` sends none). Logins through
    /// [`Auth::login`] call it automatically.
    pub fn set_token(&self, token: Option<Secret>) {
        if let Some(t) = &token {
            self.inner.transport.add_known_secret(t);
        }
        *self.inner.token.write().unwrap_or_else(|e| e.into_inner()) = token;
    }

    /// The current token (redacted when printed).
    pub fn token(&self) -> Option<Secret> {
        self.inner
            .token
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Registers work that [`OpenBaoClient::close`] runs (flush, stop watchers, …).
    pub fn on_close<F>(&self, f: F)
    where
        F: FnOnce() -> BoxFuture<'static, ()> + Send + 'static,
    {
        self.inner.on_close.register(f);
    }

    /// Unauthenticated health check (`GET sys/health`). Never fails for a sealed, standby,
    /// uninitialised or unreachable server: `status` is `active`, `standby`, `perfstandby`,
    /// `sealed`, `uninitialized`, `unhealthy` or `unreachable`, and `healthy` is true only
    /// for an active node (HTTP 200). Only `CANCELLED` and `CONFIG` are returned as errors.
    pub async fn health(&self) -> Result<HealthStatus> {
        let mut req = ApiRequest::get("sys/health", "health").no_auth();
        for status in HEALTH_STATUSES {
            req = req.ok_status(status);
        }
        let resp = match self.send(req).await {
            Ok(resp) => resp,
            Err(err) => return HealthStatus::from_error(err),
        };
        let body: Value = resp.json().unwrap_or(Value::Null);
        let flag = |k: &str| body.get(k).and_then(Value::as_bool);
        let word = if flag("initialized") == Some(false) {
            "uninitialized"
        } else if flag("sealed") == Some(true) {
            "sealed"
        } else if flag("performance_standby") == Some(true) {
            "perfstandby"
        } else if flag("standby") == Some(true) {
            "standby"
        } else if resp.status() == 200 {
            "active"
        } else {
            "unhealthy"
        };
        let mut status = if resp.status() == 200 {
            HealthStatus::healthy(word)
        } else {
            HealthStatus::unhealthy(word)
        }
        .with_detail("httpStatus", resp.status().to_string());
        for key in [
            "initialized",
            "sealed",
            "standby",
            "performance_standby",
            "version",
            "cluster_name",
            "cluster_id",
        ] {
            if body.get(key).is_some_and(|v| !v.is_null()) {
                status = status.with_detail(key, api::s(&body, key));
            }
        }
        Ok(status)
    }

    /// Authenticated round trip (`GET auth/token/lookup-self`); returns the latency.
    /// `AUTHENTICATION` on a missing, invalid or revoked token.
    pub async fn ping(&self) -> Result<Duration> {
        let started = Instant::now();
        self.send(ApiRequest::get("auth/token/lookup-self", "ping"))
            .await?;
        Ok(started.elapsed())
    }

    /// Server version from `sys/health` (no token needed; it also answers while sealed or
    /// uninitialised). `UNSUPPORTED` when the server reports none.
    pub async fn server_version(&self) -> Result<String> {
        let mut req = ApiRequest::get("sys/health", "serverVersion").no_auth();
        for status in HEALTH_STATUSES {
            req = req.ok_status(status);
        }
        let resp = self.send(req).await?;
        let body: Value = resp.json().unwrap_or(Value::Null);
        let version = api::s(&body, "version");
        if !version.is_empty() {
            return Ok(version);
        }
        if resp.status() >= 300 {
            return Err(Error::from_status(
                resp.status(),
                format!("serverVersion: server unavailable (HTTP {})", resp.status()),
            ));
        }
        Err(Error::unsupported(
            "serverVersion: the server exposes no version",
        ))
    }

    /// Stops every token renewer, managed lease and secrets watcher, runs the registered
    /// close callbacks, then closes the transport. Idempotent.
    pub async fn close(&self) {
        self.inner.background.cancel();
        self.inner.on_close.close().await;
        self.inner.transport.close();
    }

    /// Whether [`OpenBaoClient::close`] was called.
    pub fn is_closed(&self) -> bool {
        self.inner.transport.is_closed()
    }

    // --- service modules ------------------------------------------------------

    /// Auth module: logins, token self-operations, token creation and the token renewer.
    pub fn auth(&self) -> Auth {
        Auth::new(self.clone())
    }

    /// System and admin module: seal status, leader, policies, mounts, auth methods and
    /// AppRole admin.
    pub fn sys(&self) -> Sys {
        Sys::new(self.clone())
    }

    /// Response-wrapping module.
    pub fn wrapping(&self) -> Wrapping {
        Wrapping::new(self.clone())
    }

    /// Lease manager: renew, revoke, look up and auto-renew leases.
    pub fn lease_manager(&self) -> LeaseManager {
        LeaseManager::new(self.clone())
    }

    /// Transit engine at the default mount `transit` (use [`Transit::at`] for another).
    pub fn transit(&self) -> Transit {
        Transit::new(self.clone(), "transit")
    }

    /// Database secrets engine at the default mount `database` (use [`Database::at`]).
    pub fn database(&self) -> Database {
        Database::new(self.clone(), "database")
    }

    /// PKI engine at the default mount `pki` (use [`Pki::at`] for another).
    pub fn pki(&self) -> Pki {
        Pki::new(self.clone(), "pki")
    }

    /// KV version 1 API at the configured KV mount (use [`KvV1::at`] for another).
    pub fn kv_v1(&self) -> KvV1 {
        KvV1::new(self.clone(), self.config().kv_mount())
    }

    /// KV version 2 API at the configured KV mount (use [`KvV2::at`] for another).
    pub fn kv_v2(&self) -> KvV2 {
        KvV2::new(self.clone(), self.config().kv_mount())
    }

    /// KV API at the configured mount, its version detected (or forced by the config).
    pub async fn kv(&self) -> Result<Kv> {
        self.kv_at(self.config().kv_mount()).await
    }

    /// KV API at `mount`, its version auto-detected through `sys/internal/ui/mounts`
    /// (cached per mount) unless the config forces one.
    pub async fn kv_at(&self, mount: &str) -> Result<Kv> {
        let mount = api::mount_or(mount, self.config().kv_mount());
        let version = self.kv_version(&mount, self.config().kv_version()).await?;
        Ok(if version == 1 {
            Kv::V1(KvV1::new(self.clone(), &mount))
        } else {
            Kv::V2(KvV2::new(self.clone(), &mount))
        })
    }

    /// Detects the KV version (1 or 2) of `mount` (`VALIDATION` when it is not a KV mount).
    pub async fn detect_kv_version(&self, mount: &str) -> Result<u8> {
        let mount = api::mount_or(mount, self.config().kv_mount());
        let op = format!("kv.detectVersion {mount}");
        let data = self
            .data(ApiRequest::get(
                format!("sys/internal/ui/mounts/{}", api::encode_path(&mount)),
                op.clone(),
            ))
            .await?;
        let kind = api::s(&data, "type");
        if kind != "kv" && kind != "generic" {
            return Err(api::invalid(&op, "the mount is not a KV mount"));
        }
        let version = data
            .get("options")
            .map(|o| api::s(o, "version"))
            .unwrap_or_default();
        let version = if version == "2" { 2 } else { 1 };
        self.lock_kv().insert(mount, version);
        Ok(version)
    }

    pub(crate) async fn kv_version(&self, mount: &str, forced: Option<u8>) -> Result<u8> {
        if let Some(v) = forced {
            return Ok(v);
        }
        if let Some(v) = self.lock_kv().get(mount) {
            return Ok(*v);
        }
        self.detect_kv_version(mount).await
    }

    pub(crate) fn forget_kv_version(&self, mount: &str) {
        self.lock_kv().remove(mount.trim_matches('/'));
    }

    fn lock_kv(&self) -> std::sync::MutexGuard<'_, HashMap<String, u8>> {
        self.inner
            .kv_versions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// The secrets provider (SPEC §3) over the configured KV mount and secrets path.
    pub fn secrets(&self) -> KvSecretsProvider {
        KvSecretsProvider::new(self.clone(), SecretsProviderOptions::default())
    }

    /// A secrets provider with its own mount, base path, value field or KV version.
    pub fn secrets_with(&self, opts: SecretsProviderOptions) -> KvSecretsProvider {
        KvSecretsProvider::new(self.clone(), opts)
    }

    // --- crate plumbing -----------------------------------------------------------

    pub(crate) fn remember(&self, value: &str) {
        self.inner.transport.add_known_secret(&Secret::new(value));
    }

    pub(crate) fn remember_secret(&self, value: &Secret) {
        self.inner.transport.add_known_secret(value);
    }

    pub(crate) fn set_last_login(&self, method: Arc<dyn AuthMethod>) {
        *self
            .inner
            .last_login
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(method);
    }

    pub(crate) fn last_login(&self) -> Option<Arc<dyn AuthMethod>> {
        self.inner
            .last_login
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// A token cancelled by [`OpenBaoClient::close`] (parent of every background task).
    pub(crate) fn background(&self) -> CancellationToken {
        self.inner.background.child_token()
    }

    /// Executes `req` and maps OpenBao-specific error bodies.
    pub(crate) async fn send(&self, req: ApiRequest) -> Result<Response> {
        let path = format!("/v1/{}", req.path.trim_start_matches('/'));
        let mut b = self
            .inner
            .transport
            .request(req.method.clone(), &path)
            .operation(req.op.clone());
        let token = match req.token {
            Some(t) => Some(t),
            None if req.no_auth => None,
            None => self.token(),
        };
        if let Some(t) = token.filter(|t| !t.is_empty()) {
            b = b.secret_header("x-vault-token", &t);
        }
        if let Some(ns) = self.config().namespace() {
            b = b.header("x-vault-namespace", ns);
        }
        if let Some(ttl) = req.wrap_ttl {
            b = b.header("x-vault-wrap-ttl", api::duration_string(ttl));
        }
        for (k, v) in &req.query {
            b = b.query(k.clone(), v.clone());
        }
        if let Some(body) = &req.body {
            b = match req.content_type {
                Some(ct) => b.body(Bytes::from(serde_json::to_vec(body)?), ct),
                None => b.json(body),
            };
        }
        for status in &req.ok_statuses {
            b = b.ok_status(*status);
        }
        if let Some(i) = req.idempotent {
            b = b.idempotent(i);
        }
        b.send().await.map_err(api::map_error)
    }

    /// Executes `req` and parses the response envelope (an empty body is an empty envelope).
    pub(crate) async fn call(&self, req: ApiRequest) -> Result<Envelope> {
        let op = req.op.clone();
        let resp = self.send(req).await?;
        let env = Envelope::parse(resp.bytes(), &op)?;
        self.remember_envelope(&env);
        Ok(env)
    }

    /// Executes `req` and returns the envelope's `data` (`Null` when absent).
    pub(crate) async fn data(&self, req: ApiRequest) -> Result<Value> {
        Ok(self.call(req).await?.data)
    }

    /// Runs a LIST (`GET …?list=true`) and returns `data.keys`; 404 is an empty list.
    pub(crate) async fn list_keys(&self, path: String, op: String) -> Result<Vec<String>> {
        match self
            .data(ApiRequest::get(path, op).query("list", "true"))
            .await
        {
            Ok(data) => Ok(api::strings(&data, "keys")),
            Err(e) if e.code() == ErrorCode::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    fn remember_envelope(&self, env: &Envelope) {
        for key in ["client_token", "accessor"] {
            let v = api::s(&env.auth, key);
            if !v.is_empty() {
                self.remember(&v);
            }
        }
        let wrap = api::s(&env.wrap_info, "token");
        if !wrap.is_empty() {
            self.remember(&wrap);
        }
    }
}
