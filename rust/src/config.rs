// Skeleton created by sdk-kit 0.1.0; owned by this repository (edit freely).
//! `OpenBaoConfig`: common settings (SPEC §2.2) plus the OpenBao credentials and KV defaults.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::core::{
    CommonConfig, CommonConfigBuilder, EnvReader, Error, Hooks, Result, RetryPolicy, Secret,
    TlsConfig,
};

/// Endpoint used when neither the builder nor the environment sets one.
pub const DEFAULT_URL: &str = "http://127.0.0.1:8200";
/// KV mount used by the secrets provider when none is configured.
pub const DEFAULT_KV_MOUNT: &str = "secret";
/// KV data field that holds a secrets-provider value.
pub const DEFAULT_VALUE_FIELD: &str = "value";

/// Vendor variables checked (in order) after `GROW_OPENBAO_URL`.
const VENDOR_URL_VARS: &[&str] = &["BAO_ADDR", "VAULT_ADDR"];
/// Vendor variables checked (in order) after `GROW_OPENBAO_TOKEN`.
const VENDOR_TOKEN_VARS: &[&str] = &["BAO_TOKEN", "VAULT_TOKEN"];
/// Vendor variables checked (in order) after `GROW_OPENBAO_NAMESPACE`.
const VENDOR_NAMESPACE_VARS: &[&str] = &["BAO_NAMESPACE", "VAULT_NAMESPACE"];
/// Vendor variables checked (in order) after `GROW_OPENBAO_CA_CERT`.
const VENDOR_CA_VARS: &[&str] = &["BAO_CACERT", "VAULT_CACERT"];
/// Vendor variables checked (in order) after `GROW_OPENBAO_CLIENT_CERT`.
const VENDOR_CLIENT_CERT_VARS: &[&str] = &["BAO_CLIENT_CERT", "VAULT_CLIENT_CERT"];
/// Vendor variables checked (in order) after `GROW_OPENBAO_CLIENT_KEY`.
const VENDOR_CLIENT_KEY_VARS: &[&str] = &["BAO_CLIENT_KEY", "VAULT_CLIENT_KEY"];
/// Vendor variables checked (in order) after `GROW_OPENBAO_INSECURE_SKIP_VERIFY`.
const VENDOR_SKIP_VERIFY_VARS: &[&str] = &["BAO_SKIP_VERIFY", "VAULT_SKIP_VERIFY"];

/// Immutable client configuration; build it with [`OpenBaoConfig::builder`] or
/// [`OpenBaoConfig::from_env`]. `Debug` output redacts every credential.
///
/// Environment variables read by [`OpenBaoConfig::from_env`] (explicit value >
/// `GROW_OPENBAO_*` > vendor variables > default):
///
/// | Field | Variables |
/// | - | - |
/// | url | `GROW_OPENBAO_URL`, `BAO_ADDR`, `VAULT_ADDR` |
/// | token | `GROW_OPENBAO_TOKEN`, `BAO_TOKEN`, `VAULT_TOKEN` |
/// | namespace | `GROW_OPENBAO_NAMESPACE`, `BAO_NAMESPACE`, `VAULT_NAMESPACE` |
/// | CA certificate | `GROW_OPENBAO_CA_CERT`, `BAO_CACERT`, `VAULT_CACERT` |
/// | client certificate / key | `GROW_OPENBAO_CLIENT_CERT` / `_KEY`, `BAO_CLIENT_CERT` / `_KEY`, `VAULT_CLIENT_CERT` / `_KEY` |
/// | insecure skip verify | `GROW_OPENBAO_INSECURE_SKIP_VERIFY`, `BAO_SKIP_VERIFY`, `VAULT_SKIP_VERIFY` |
/// | kv mount / version / secrets path | `GROW_OPENBAO_KV_MOUNT`, `GROW_OPENBAO_KV_VERSION`, `GROW_OPENBAO_SECRETS_PATH` |
///
/// plus the common `GROW_OPENBAO_CONNECT_TIMEOUT`, `REQUEST_TIMEOUT`, `TOTAL_TIMEOUT`,
/// `MAX_RETRIES` and `PROXY`.
#[derive(Clone)]
pub struct OpenBaoConfig {
    common: CommonConfig,
    token: Option<Secret>,
    namespace: Option<String>,
    kv_mount: String,
    kv_version: Option<u8>,
    secrets_path: String,
    value_field: String,
}

impl fmt::Debug for OpenBaoConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenBaoConfig")
            .field("common", &self.common)
            .field("token", &self.token)
            .field("namespace", &self.namespace)
            .field("kv_mount", &self.kv_mount)
            .field("kv_version", &self.kv_version)
            .field("secrets_path", &self.secrets_path)
            .field("value_field", &self.value_field)
            .finish()
    }
}

impl OpenBaoConfig {
    /// A builder with nothing set.
    pub fn builder() -> OpenBaoConfigBuilder {
        OpenBaoConfigBuilder::default()
    }

    /// Configuration from the process environment
    /// (explicit > `GROW_OPENBAO_*` > vendor variables > defaults).
    pub fn from_env() -> Result<Self> {
        Self::builder().build_from_env()
    }

    /// Settings shared by every Grow Codes SDK.
    pub fn common(&self) -> &CommonConfig {
        &self.common
    }

    /// Endpoint base URL.
    pub fn url(&self) -> &url::Url {
        self.common.url()
    }

    /// Token sent as `X-Vault-Token`, when configured.
    pub fn token(&self) -> Option<&Secret> {
        self.token.as_ref()
    }

    /// Namespace sent as `X-Vault-Namespace` (`None` = root namespace).
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// KV mount used by the secrets provider and `client.kv()` (default `secret`).
    pub fn kv_mount(&self) -> &str {
        &self.kv_mount
    }

    /// Forced KV version (1 or 2); `None` auto-detects it per mount.
    pub fn kv_version(&self) -> Option<u8> {
        self.kv_version
    }

    /// Base path inside the KV mount under which the secrets provider stores secrets.
    pub fn secrets_path(&self) -> &str {
        &self.secrets_path
    }

    /// KV data field holding a secrets-provider value (default `value`).
    pub fn value_field(&self) -> &str {
        &self.value_field
    }

    /// Checks the service rules (common rules are checked when building).
    pub fn validate(&self) -> Result<()> {
        if let Some(v) = self.kv_version {
            if v != 1 && v != 2 {
                return Err(Error::config("kv_version must be 1 or 2"));
            }
        }
        if let Some(ns) = &self.namespace {
            if ns.chars().any(char::is_whitespace) {
                return Err(Error::config("namespace must not contain whitespace"));
            }
        }
        if self.value_field.trim().is_empty() {
            return Err(Error::config("value_field must not be empty"));
        }
        Ok(())
    }
}

/// Builder for [`OpenBaoConfig`]. Values set here win over the environment.
#[derive(Debug, Clone, Default)]
pub struct OpenBaoConfigBuilder {
    common: CommonConfigBuilder,
    token: Option<Secret>,
    namespace: Option<String>,
    kv_mount: Option<String>,
    kv_version: Option<u8>,
    secrets_path: Option<String>,
    value_field: Option<String>,
    ca_cert_path: Option<PathBuf>,
    client_cert: Option<(PathBuf, PathBuf)>,
    insecure_skip_verify: Option<bool>,
}

impl OpenBaoConfigBuilder {
    /// Endpoint base URL (default [`DEFAULT_URL`]).
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.common = self.common.url(url);
        self
    }
    /// Token sent as `X-Vault-Token`.
    pub fn token(mut self, token: impl Into<Secret>) -> Self {
        self.token = Some(token.into());
        self
    }
    /// Namespace sent as `X-Vault-Namespace`.
    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }
    /// KV mount for the secrets provider and `client.kv()` (default `secret`).
    pub fn kv_mount(mut self, mount: impl Into<String>) -> Self {
        self.kv_mount = Some(mount.into());
        self
    }
    /// Forces the KV version (1 or 2) instead of auto-detecting it.
    pub fn kv_version(mut self, version: u8) -> Self {
        self.kv_version = Some(version);
        self
    }
    /// Base path inside the KV mount for the secrets provider.
    pub fn secrets_path(mut self, path: impl Into<String>) -> Self {
        self.secrets_path = Some(path.into());
        self
    }
    /// KV data field holding a secrets-provider value (default `value`).
    pub fn value_field(mut self, field: impl Into<String>) -> Self {
        self.value_field = Some(field.into());
        self
    }
    /// Connect timeout (default 10 s).
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.common = self.common.connect_timeout(timeout);
        self
    }
    /// Per-attempt timeout (default 30 s).
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.common = self.common.request_timeout(timeout);
        self
    }
    /// Whole-call timeout including retries (default 120 s).
    pub fn total_timeout(mut self, timeout: Duration) -> Self {
        self.common = self.common.total_timeout(timeout);
        self
    }
    /// Retry policy.
    pub fn retry(mut self, retry: RetryPolicy) -> Self {
        self.common = self.common.retry(retry);
        self
    }
    /// Maximum retries (default 3).
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.common = self.common.max_retries(max_retries);
        self
    }
    /// TLS settings.
    pub fn tls(mut self, tls: TlsConfig) -> Self {
        if tls.ca_cert_path.is_some() {
            self.ca_cert_path = tls.ca_cert_path.clone();
        }
        if let (Some(c), Some(k)) = (&tls.client_cert_path, &tls.client_key_path) {
            self.client_cert = Some((c.clone(), k.clone()));
        }
        if tls.insecure_skip_verify {
            self.insecure_skip_verify = Some(true);
        }
        self.common = self.common.tls(tls);
        self
    }
    /// Extra trusted CA certificates (PEM file).
    pub fn ca_cert_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.ca_cert_path = Some(path.into());
        self
    }
    /// Client certificate and key (PEM files) for mutual TLS.
    pub fn client_cert(mut self, cert: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        self.client_cert = Some((cert.into(), key.into()));
        self
    }
    /// Disables TLS verification (tests only).
    pub fn insecure_skip_verify(mut self, skip: bool) -> Self {
        self.insecure_skip_verify = Some(skip);
        self
    }
    /// Proxy URL (environment proxies are ignored).
    pub fn proxy(mut self, proxy: impl Into<String>) -> Self {
        self.common = self.common.proxy(proxy);
        self
    }
    /// Extra request header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.common = self.common.header(name, value);
        self
    }
    /// Text appended to the User-Agent.
    pub fn user_agent_suffix(mut self, suffix: impl Into<String>) -> Self {
        self.common = self.common.user_agent_suffix(suffix);
        self
    }
    /// Request hooks.
    pub fn hooks(mut self, hooks: Arc<dyn Hooks>) -> Self {
        self.common = self.common.hooks(hooks);
        self
    }
    /// Edits any other common setting.
    pub fn common(mut self, f: impl FnOnce(CommonConfigBuilder) -> CommonConfigBuilder) -> Self {
        self.common = f(self.common);
        self
    }

    /// Builds without reading the environment.
    pub fn build(self) -> Result<OpenBaoConfig> {
        let mut common = self.common;
        if let Some(path) = self.ca_cert_path {
            common = common.ca_cert_path(path);
        }
        if let Some((cert, key)) = self.client_cert {
            common = common.client_cert(cert, key);
        }
        if let Some(skip) = self.insecure_skip_verify {
            common = common.insecure_skip_verify(skip);
        }
        let trimmed = |s: Option<String>| s.map(|v| v.trim_matches('/').to_owned());
        let config = OpenBaoConfig {
            common: common.build(DEFAULT_URL)?,
            token: self.token.filter(|t| !t.is_empty()),
            namespace: trimmed(self.namespace).filter(|n| !n.is_empty()),
            kv_mount: trimmed(self.kv_mount)
                .filter(|m| !m.is_empty())
                .unwrap_or_else(|| DEFAULT_KV_MOUNT.to_owned()),
            kv_version: self.kv_version.filter(|v| *v != 0),
            secrets_path: trimmed(self.secrets_path).unwrap_or_default(),
            value_field: self
                .value_field
                .unwrap_or_else(|| DEFAULT_VALUE_FIELD.to_owned()),
        };
        config.validate()?;
        Ok(config)
    }

    /// Fills unset values from the process environment, then builds.
    pub fn build_from_env(self) -> Result<OpenBaoConfig> {
        self.build_with_env(&EnvReader::new())
    }

    /// Fills unset values from `env`, then builds.
    pub fn build_with_env(mut self, env: &EnvReader) -> Result<OpenBaoConfig> {
        if self.ca_cert_path.is_none() {
            self.ca_cert_path = env.string("CA_CERT", VENDOR_CA_VARS).map(PathBuf::from);
        }
        if self.client_cert.is_none() {
            let cert = env.string("CLIENT_CERT", VENDOR_CLIENT_CERT_VARS);
            let key = env.string("CLIENT_KEY", VENDOR_CLIENT_KEY_VARS);
            match (cert, key) {
                (Some(c), Some(k)) => self.client_cert = Some((c.into(), k.into())),
                (None, None) => {}
                _ => {
                    return Err(Error::config(
                        "client certificate and client key must be given together",
                    ))
                }
            }
        }
        if self.insecure_skip_verify.is_none() {
            self.insecure_skip_verify =
                env.bool("INSECURE_SKIP_VERIFY", VENDOR_SKIP_VERIFY_VARS)?;
        }
        self.common = self.common.apply_env(env, VENDOR_URL_VARS)?;
        if self.token.is_none() {
            self.token = env.secret("TOKEN", VENDOR_TOKEN_VARS);
        }
        if self.namespace.is_none() {
            self.namespace = env.string("NAMESPACE", VENDOR_NAMESPACE_VARS);
        }
        if self.kv_mount.is_none() {
            self.kv_mount = env.string("KV_MOUNT", &[]);
        }
        if self.secrets_path.is_none() {
            self.secrets_path = env.string("SECRETS_PATH", &[]);
        }
        if self.kv_version.is_none() {
            if let Some(v) = env.int("KV_VERSION", &[])? {
                let v = u8::try_from(v).ok().filter(|v| *v <= 2).ok_or_else(|| {
                    Error::config(format!(
                        "environment variable {}KV_VERSION must be 1 or 2",
                        env.prefix()
                    ))
                })?;
                self.kv_version = Some(v);
            }
        }
        self.build()
    }
}
