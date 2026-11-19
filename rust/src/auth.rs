//! Auth module: login methods, token self-operations, token creation and the token renewer.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use serde_json::{json, Map, Value};

use crate::api::{self, ApiRequest};
use crate::client::OpenBaoClient;
use crate::core::{Error, Result, Secret};
use crate::renew::{TokenRenewer, TokenRenewerOptions};

/// Default path of the Kubernetes service-account token.
pub const DEFAULT_KUBERNETES_JWT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

/// A token issued by a login or `create_token` (the `auth` block of a response).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthInfo {
    /// The token (redacted when printed).
    pub client_token: Secret,
    /// Token accessor.
    pub accessor: String,
    /// All policies attached to the token.
    pub policies: Vec<String>,
    /// Policies attached directly to the token.
    pub token_policies: Vec<String>,
    /// Metadata of the login (for example `role_name`, `username`).
    pub metadata: BTreeMap<String, String>,
    /// Granted TTL.
    pub lease_duration: Duration,
    /// Whether the token can be renewed.
    pub renewable: bool,
    /// Identity entity id.
    pub entity_id: String,
    /// `service` or `batch`.
    pub token_type: String,
    /// Whether the token has no parent.
    pub orphan: bool,
    /// Remaining uses (0 = unlimited).
    pub num_uses: u64,
}

impl AuthInfo {
    pub(crate) fn from_value(v: &Value) -> AuthInfo {
        AuthInfo {
            client_token: Secret::new(api::s(v, "client_token")),
            accessor: api::s(v, "accessor"),
            policies: api::strings(v, "policies"),
            token_policies: api::strings(v, "token_policies"),
            metadata: api::smap(v, "metadata"),
            lease_duration: api::secs(v, "lease_duration"),
            renewable: api::b(v, "renewable"),
            entity_id: api::s(v, "entity_id"),
            token_type: api::s(v, "token_type"),
            orphan: api::b(v, "orphan"),
            num_uses: api::u(v, "num_uses"),
        }
    }
}

/// Properties of the current token (`lookup_self`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenInfo {
    /// Token accessor.
    pub accessor: String,
    /// The token itself (redacted when printed).
    pub id: Secret,
    /// Policies.
    pub policies: Vec<String>,
    /// Remaining TTL (zero = never expires).
    pub ttl: Duration,
    /// TTL at creation.
    pub creation_ttl: Duration,
    /// Creation time.
    pub creation_time: Option<SystemTime>,
    /// Expiry time (`None` = never).
    pub expire_time: Option<SystemTime>,
    /// Issue time.
    pub issue_time: Option<SystemTime>,
    /// Whether the token can be renewed.
    pub renewable: bool,
    /// Display name (`token-<name>`).
    pub display_name: String,
    /// Token metadata.
    pub meta: BTreeMap<String, String>,
    /// Remaining uses (0 = unlimited).
    pub num_uses: u64,
    /// Whether the token has no parent.
    pub orphan: bool,
    /// Creation path (for example `auth/token/create`).
    pub path: String,
    /// `service` or `batch`.
    pub token_type: String,
    /// Explicit max TTL (zero = none).
    pub explicit_max_ttl: Duration,
    /// Identity entity id.
    pub entity_id: String,
}

impl TokenInfo {
    fn from_value(v: &Value) -> TokenInfo {
        TokenInfo {
            accessor: api::s(v, "accessor"),
            id: Secret::new(api::s(v, "id")),
            policies: api::strings(v, "policies"),
            ttl: api::secs(v, "ttl"),
            creation_ttl: api::secs(v, "creation_ttl"),
            creation_time: api::time(v, "creation_time"),
            expire_time: api::time(v, "expire_time"),
            issue_time: api::time(v, "issue_time"),
            renewable: api::b(v, "renewable"),
            display_name: api::s(v, "display_name"),
            meta: api::smap(v, "meta"),
            num_uses: api::u(v, "num_uses"),
            orphan: api::b(v, "orphan"),
            path: api::s(v, "path"),
            token_type: api::s(v, "type"),
            explicit_max_ttl: api::secs(v, "explicit_max_ttl"),
            entity_id: api::s(v, "entity_id"),
        }
    }
}

/// A way to obtain a token. Implemented by [`TokenAuth`], [`AppRoleAuth`],
/// [`UserpassAuth`], [`JwtAuth`] and [`KubernetesAuth`]; custom methods can build on
/// [`Auth::login_with`].
#[async_trait]
pub trait AuthMethod: Send + Sync + fmt::Debug {
    /// Obtains a token (without setting it on the client).
    async fn login(&self, auth: &Auth) -> Result<AuthInfo>;
}

/// Auth module; get it with [`OpenBaoClient::auth`].
#[derive(Debug, Clone)]
pub struct Auth {
    client: OpenBaoClient,
}

impl Auth {
    pub(crate) fn new(client: OpenBaoClient) -> Self {
        Auth { client }
    }

    /// The client this module belongs to.
    pub fn client(&self) -> &OpenBaoClient {
        &self.client
    }

    /// Authenticates with `method`, sets the resulting token on the client and returns it.
    /// The method is remembered for [`TokenRenewerOptions::relogin`].
    pub async fn login<M: AuthMethod + 'static>(&self, method: M) -> Result<AuthInfo> {
        self.login_arc(Arc::new(method)).await
    }

    /// [`Auth::login`] with a shared method.
    pub async fn login_arc(&self, method: Arc<dyn AuthMethod>) -> Result<AuthInfo> {
        let info = method.login(self).await?;
        self.client.set_token(Some(info.client_token.clone()));
        self.client.set_last_login(method);
        Ok(info)
    }

    /// Posts `body` to `auth/<path>` without a token and returns the issued token (building
    /// block for [`AuthMethod`] implementations; the token is not set on the client).
    /// `path` is relative to `auth/`, for example `approle/login`.
    pub async fn login_with(&self, path: &str, body: Value) -> Result<AuthInfo> {
        let path = path.trim_matches('/');
        let op = format!("auth.login {path}");
        if let Value::Object(map) = &body {
            for v in map.values() {
                if let Some(s) = v.as_str() {
                    self.client.remember(s);
                }
            }
        }
        let env = self
            .client
            .call(
                ApiRequest::post(format!("auth/{}", api::encode_path(path)), op.clone())
                    .json(body)
                    .no_auth(),
            )
            .await
            .map_err(api::login_error)?;
        let info = AuthInfo::from_value(&env.auth);
        if info.client_token.is_empty() {
            return Err(Error::new(
                crate::core::ErrorCode::Authentication,
                format!("{op}: the response carried no token"),
            ));
        }
        Ok(info)
    }

    /// Properties of the current token (`GET auth/token/lookup-self`).
    pub async fn lookup_self(&self) -> Result<TokenInfo> {
        let data = self
            .client
            .data(ApiRequest::get("auth/token/lookup-self", "auth.lookupSelf"))
            .await?;
        Ok(TokenInfo::from_value(&data))
    }

    /// Renews the current token (`POST auth/token/renew-self`); `increment` is the
    /// requested TTL (`None` = the token default). A non-renewable token is `VALIDATION`.
    pub async fn renew_self(&self, increment: Option<Duration>) -> Result<AuthInfo> {
        let mut body = api::obj();
        if let Some(inc) = increment.filter(|d| !d.is_zero()) {
            body.insert("increment".into(), json!(api::duration_string(inc)));
        }
        let env = self
            .client
            .call(ApiRequest::post("auth/token/renew-self", "auth.renewSelf").json(body.into()))
            .await?;
        Ok(AuthInfo::from_value(&env.auth))
    }

    /// Revokes the current token (`POST auth/token/revoke-self`) and clears it on the client.
    pub async fn revoke_self(&self) -> Result<()> {
        self.client
            .call(ApiRequest::post(
                "auth/token/revoke-self",
                "auth.revokeSelf",
            ))
            .await?;
        self.client.set_token(None);
        Ok(())
    }

    /// Creates a child token (`POST auth/token/create[/<role>]`). The new token is returned,
    /// not set on the client.
    pub async fn create_token(&self, opts: &TokenCreateOptions) -> Result<AuthInfo> {
        let mut path = "auth/token/create".to_owned();
        if let Some(role) = opts.role.as_deref().filter(|r| !r.trim().is_empty()) {
            path = format!("{path}/{}", api::encode_path(role));
        }
        let env = self
            .client
            .call(ApiRequest::post(path, "auth.createToken").json(opts.body()))
            .await?;
        if env.auth.is_null() {
            return Err(Error::unavailable(
                "auth.createToken: the response carried no token",
            ));
        }
        Ok(AuthInfo::from_value(&env.auth))
    }

    /// Looks up the current token and keeps it alive in the background (renews at 2/3 of
    /// the remaining TTL). Stop the renewer or close the client to end it.
    pub async fn start_renewer(&self, opts: TokenRenewerOptions) -> Result<TokenRenewer> {
        let info = self.lookup_self().await?;
        Ok(TokenRenewer::start(self.clone(), info, opts))
    }
}

/// Options of [`Auth::create_token`]. Unset fields use the server defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenCreateOptions {
    /// Creates the token against `auth/token/create/<role>`.
    pub role: Option<String>,
    /// Policies.
    pub policies: Vec<String>,
    /// TTL.
    pub ttl: Option<Duration>,
    /// Explicit max TTL.
    pub explicit_max_ttl: Option<Duration>,
    /// Period (periodic token).
    pub period: Option<Duration>,
    /// Whether the token can be renewed.
    pub renewable: Option<bool>,
    /// Display name.
    pub display_name: Option<String>,
    /// Metadata.
    pub meta: BTreeMap<String, String>,
    /// Maximum uses (0 = unlimited).
    pub num_uses: u64,
    /// Creates an orphan token (needs root or sudo).
    pub no_parent: bool,
    /// Leaves out the `default` policy.
    pub no_default_policy: bool,
    /// `service` or `batch`.
    pub token_type: Option<String>,
    /// Explicit token id (root only).
    pub id: Option<Secret>,
}

impl TokenCreateOptions {
    fn body(&self) -> Value {
        let mut body = Map::new();
        if !self.policies.is_empty() {
            body.insert("policies".into(), json!(self.policies));
        }
        for (k, d) in [
            ("ttl", self.ttl),
            ("explicit_max_ttl", self.explicit_max_ttl),
            ("period", self.period),
        ] {
            if let Some(d) = d.filter(|d| !d.is_zero()) {
                body.insert(k.into(), json!(api::duration_string(d)));
            }
        }
        if let Some(r) = self.renewable {
            body.insert("renewable".into(), json!(r));
        }
        if let Some(n) = &self.display_name {
            body.insert("display_name".into(), json!(n));
        }
        if !self.meta.is_empty() {
            body.insert("meta".into(), json!(self.meta));
        }
        if self.num_uses > 0 {
            body.insert("num_uses".into(), json!(self.num_uses));
        }
        if self.no_parent {
            body.insert("no_parent".into(), json!(true));
        }
        if self.no_default_policy {
            body.insert("no_default_policy".into(), json!(true));
        }
        if let Some(t) = &self.token_type {
            body.insert("type".into(), json!(t));
        }
        if let Some(id) = &self.id {
            body.insert("id".into(), json!(id.expose_secret()));
        }
        Value::Object(body)
    }
}

// --- auth methods -------------------------------------------------------------

/// Uses an existing token: login sets it on the client and verifies it with `lookup-self`.
#[derive(Debug, Clone)]
pub struct TokenAuth {
    token: Secret,
}

impl TokenAuth {
    /// A token method.
    pub fn new(token: impl Into<Secret>) -> Self {
        TokenAuth {
            token: token.into(),
        }
    }
}

#[async_trait]
impl AuthMethod for TokenAuth {
    async fn login(&self, auth: &Auth) -> Result<AuthInfo> {
        let op = "auth.login token";
        api::require_arg(op, "token", self.token.expose_secret())?;
        auth.client.remember_secret(&self.token);
        let data = auth
            .client
            .data(ApiRequest::get("auth/token/lookup-self", op).token(self.token.clone()))
            .await?;
        let t = TokenInfo::from_value(&data);
        Ok(AuthInfo {
            client_token: self.token.clone(),
            accessor: t.accessor,
            policies: t.policies.clone(),
            token_policies: t.policies,
            metadata: t.meta,
            lease_duration: t.ttl,
            renewable: t.renewable,
            entity_id: t.entity_id,
            token_type: t.token_type,
            orphan: t.orphan,
            num_uses: t.num_uses,
        })
    }
}

/// AppRole login (`POST auth/<mount>/login`, default mount `approle`).
#[derive(Debug, Clone)]
pub struct AppRoleAuth {
    role_id: String,
    secret_id: Secret,
    mount: String,
}

impl AppRoleAuth {
    /// An AppRole method.
    pub fn new(role_id: impl Into<String>, secret_id: impl Into<Secret>) -> Self {
        AppRoleAuth {
            role_id: role_id.into(),
            secret_id: secret_id.into(),
            mount: "approle".into(),
        }
    }
    /// Uses another auth mount.
    pub fn mount(mut self, mount: impl Into<String>) -> Self {
        self.mount = mount.into();
        self
    }
}

#[async_trait]
impl AuthMethod for AppRoleAuth {
    async fn login(&self, auth: &Auth) -> Result<AuthInfo> {
        api::require_arg("auth.login approle", "role_id", &self.role_id)?;
        let mut body = json!({ "role_id": self.role_id });
        if !self.secret_id.is_empty() {
            body["secret_id"] = json!(self.secret_id.expose_secret());
        }
        auth.login_with(
            &api::join(&[&api::mount_or(&self.mount, "approle"), "login"]),
            body,
        )
        .await
    }
}

/// Userpass login (`POST auth/<mount>/login/<username>`, default mount `userpass`).
#[derive(Debug, Clone)]
pub struct UserpassAuth {
    username: String,
    password: Secret,
    mount: String,
}

impl UserpassAuth {
    /// A userpass method.
    pub fn new(username: impl Into<String>, password: impl Into<Secret>) -> Self {
        UserpassAuth {
            username: username.into(),
            password: password.into(),
            mount: "userpass".into(),
        }
    }
    /// Uses another auth mount.
    pub fn mount(mut self, mount: impl Into<String>) -> Self {
        self.mount = mount.into();
        self
    }
}

#[async_trait]
impl AuthMethod for UserpassAuth {
    async fn login(&self, auth: &Auth) -> Result<AuthInfo> {
        api::require_arg("auth.login userpass", "username", &self.username)?;
        let path = format!(
            "{}/login/{}",
            api::mount_or(&self.mount, "userpass"),
            self.username
        );
        auth.login_with(&path, json!({ "password": self.password.expose_secret() }))
            .await
    }
}

/// JWT/OIDC login with a JWT (`POST auth/<mount>/login`, default mount `jwt`).
#[derive(Debug, Clone)]
pub struct JwtAuth {
    role: String,
    jwt: Secret,
    mount: String,
}

impl JwtAuth {
    /// A JWT method.
    pub fn new(role: impl Into<String>, jwt: impl Into<Secret>) -> Self {
        JwtAuth {
            role: role.into(),
            jwt: jwt.into(),
            mount: "jwt".into(),
        }
    }
    /// Uses another auth mount.
    pub fn mount(mut self, mount: impl Into<String>) -> Self {
        self.mount = mount.into();
        self
    }
}

#[async_trait]
impl AuthMethod for JwtAuth {
    async fn login(&self, auth: &Auth) -> Result<AuthInfo> {
        api::require_arg("auth.login jwt", "jwt", self.jwt.expose_secret())?;
        let mut body = json!({ "jwt": self.jwt.expose_secret() });
        if !self.role.is_empty() {
            body["role"] = json!(self.role);
        }
        auth.login_with(
            &api::join(&[&api::mount_or(&self.mount, "jwt"), "login"]),
            body,
        )
        .await
    }
}

/// Kubernetes login with the pod's service-account JWT (`POST auth/<mount>/login`, default
/// mount `kubernetes`). The JWT is read from `jwt_path` at every login.
#[derive(Debug, Clone)]
pub struct KubernetesAuth {
    role: String,
    jwt_path: PathBuf,
    mount: String,
}

impl KubernetesAuth {
    /// A Kubernetes method; an empty `jwt_path` means [`DEFAULT_KUBERNETES_JWT_PATH`].
    pub fn new(role: impl Into<String>, jwt_path: impl Into<PathBuf>) -> Self {
        let mut jwt_path = jwt_path.into();
        if jwt_path.as_os_str().is_empty() {
            jwt_path = PathBuf::from(DEFAULT_KUBERNETES_JWT_PATH);
        }
        KubernetesAuth {
            role: role.into(),
            jwt_path,
            mount: "kubernetes".into(),
        }
    }
    /// Uses another auth mount.
    pub fn mount(mut self, mount: impl Into<String>) -> Self {
        self.mount = mount.into();
        self
    }
    /// The JWT file in use.
    pub fn jwt_path(&self) -> &std::path::Path {
        &self.jwt_path
    }
}

#[async_trait]
impl AuthMethod for KubernetesAuth {
    async fn login(&self, auth: &Auth) -> Result<AuthInfo> {
        let op = "auth.login kubernetes";
        api::require_arg(op, "role", &self.role)?;
        let jwt = std::fs::read_to_string(&self.jwt_path).map_err(|e| {
            Error::config(format!(
                "{op}: service-account token file {} cannot be read",
                self.jwt_path.display()
            ))
            .with_source(e)
        })?;
        let jwt = Secret::new(jwt.trim());
        auth.client.remember_secret(&jwt);
        let body = json!({ "role": self.role, "jwt": jwt.expose_secret() });
        auth.login_with(
            &api::join(&[&api::mount_or(&self.mount, "kubernetes"), "login"]),
            body,
        )
        .await
    }
}
