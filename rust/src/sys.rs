//! System and admin module: seal status, leader, version, policies, mounts, auth methods
//! and AppRole admin.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use serde_json::{json, Map, Value};

use crate::api::{self, ApiRequest};
use crate::client::OpenBaoClient;
use crate::core::{HealthStatus, Result, Secret};

/// Seal state (`seal_status` and the testing `unseal`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SealStatus {
    /// Seal type (`shamir`, `static`, …).
    pub seal_type: String,
    /// Whether the server is initialised.
    pub initialized: bool,
    /// Whether the server is sealed.
    pub sealed: bool,
    /// Unseal threshold.
    pub t: u64,
    /// Number of key shares.
    pub n: u64,
    /// Unseal progress.
    pub progress: u64,
    /// Unseal nonce.
    pub nonce: String,
    /// Server version.
    pub version: String,
    /// Build commit date (RFC 3339 text).
    pub commit_date: String,
    /// Whether a recovery seal is in use.
    pub recovery_seal: bool,
    /// Storage type (`raft`, …).
    pub storage_type: String,
    /// Cluster name.
    pub cluster_name: String,
    /// Cluster id.
    pub cluster_id: String,
}

impl SealStatus {
    pub(crate) fn from_value(v: &Value) -> Self {
        SealStatus {
            seal_type: api::s(v, "type"),
            initialized: api::b(v, "initialized"),
            sealed: api::b(v, "sealed"),
            t: api::u(v, "t"),
            n: api::u(v, "n"),
            progress: api::u(v, "progress"),
            nonce: api::s(v, "nonce"),
            version: api::s(v, "version"),
            commit_date: api::s(v, "commit_date"),
            recovery_seal: api::b(v, "recovery_seal"),
            storage_type: api::s(v, "storage_type"),
            cluster_name: api::s(v, "cluster_name"),
            cluster_id: api::s(v, "cluster_id"),
        }
    }
}

/// HA leader (`leader`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeaderStatus {
    /// Whether HA is enabled.
    pub ha_enabled: bool,
    /// Whether this node is the leader.
    pub is_self: bool,
    /// Time the leader became active.
    pub active_time: Option<SystemTime>,
    /// Leader API address.
    pub leader_address: String,
    /// Leader cluster address.
    pub leader_cluster_address: String,
    /// Raft committed index.
    pub raft_committed_index: u64,
    /// Raft applied index.
    pub raft_applied_index: u64,
}

/// An ACL policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// Name.
    pub name: String,
    /// HCL document.
    pub policy: String,
}

/// A secrets engine or auth method mount.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MountInfo {
    /// Engine / method type.
    pub mount_type: String,
    /// Description.
    pub description: String,
    /// Accessor.
    pub accessor: String,
    /// Engine options (`version` for KV).
    pub options: BTreeMap<String, String>,
    /// Default lease TTL (zero = system default).
    pub default_lease_ttl: Duration,
    /// Max lease TTL (zero = system default).
    pub max_lease_ttl: Duration,
    /// Local (not replicated).
    pub local: bool,
    /// Seal-wrapped.
    pub seal_wrap: bool,
    /// Mount UUID.
    pub uuid: String,
    /// Running plugin version.
    pub running_plugin_version: String,
}

/// Options of `enable_secrets_engine` and `enable_auth_method`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MountOptions {
    /// Description.
    pub description: Option<String>,
    /// Engine options, e.g. `{"version": "2"}` for KV v2.
    pub options: BTreeMap<String, String>,
    /// Default lease TTL.
    pub default_lease_ttl: Option<Duration>,
    /// Max lease TTL.
    pub max_lease_ttl: Option<Duration>,
    /// Local (not replicated).
    pub local: bool,
    /// Seal-wrapped.
    pub seal_wrap: bool,
}

impl MountOptions {
    fn body(&self, kind: &str) -> Value {
        let mut body = Map::new();
        body.insert("type".into(), json!(kind));
        if let Some(d) = &self.description {
            body.insert("description".into(), json!(d));
        }
        if !self.options.is_empty() {
            body.insert("options".into(), json!(self.options));
        }
        let mut cfg = Map::new();
        if let Some(d) = self.default_lease_ttl.filter(|d| !d.is_zero()) {
            cfg.insert("default_lease_ttl".into(), json!(api::duration_string(d)));
        }
        if let Some(d) = self.max_lease_ttl.filter(|d| !d.is_zero()) {
            cfg.insert("max_lease_ttl".into(), json!(api::duration_string(d)));
        }
        if !cfg.is_empty() {
            body.insert("config".into(), Value::Object(cfg));
        }
        if self.local {
            body.insert("local".into(), json!(true));
        }
        if self.seal_wrap {
            body.insert("seal_wrap".into(), json!(true));
        }
        Value::Object(body)
    }
}

/// Options of [`Sys::create_app_role`]. Unset fields use the server defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppRoleOptions {
    /// AppRole auth mount (default `approle`).
    pub mount: Option<String>,
    /// Token policies.
    pub token_policies: Vec<String>,
    /// Token TTL.
    pub token_ttl: Option<Duration>,
    /// Token max TTL.
    pub token_max_ttl: Option<Duration>,
    /// Token uses (0 = unlimited).
    pub token_num_uses: u64,
    /// `service` or `batch`.
    pub token_type: Option<String>,
    /// Secret id TTL.
    pub secret_id_ttl: Option<Duration>,
    /// Secret id uses (0 = unlimited).
    pub secret_id_num_uses: u64,
    /// Requires a secret id at login (server default true).
    pub bind_secret_id: Option<bool>,
}

/// Options of [`Sys::generate_secret_id`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretIdOptions {
    /// AppRole auth mount (default `approle`).
    pub mount: Option<String>,
    /// Metadata attached to tokens issued with the secret id.
    pub metadata: BTreeMap<String, String>,
    /// TTL.
    pub ttl: Option<Duration>,
    /// Uses (0 = unlimited).
    pub num_uses: u64,
    /// Allowed source CIDRs.
    pub cidr_list: Vec<String>,
}

/// A generated AppRole secret id.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretId {
    /// The secret id (redacted when printed).
    pub secret_id: Secret,
    /// Accessor.
    pub accessor: String,
    /// TTL (zero = none).
    pub ttl: Duration,
    /// Uses (0 = unlimited).
    pub num_uses: u64,
}

/// System module; get it with [`OpenBaoClient::sys`].
#[derive(Debug, Clone)]
pub struct Sys {
    client: OpenBaoClient,
}

fn approle(mount: Option<&str>) -> String {
    api::mount_or(mount.unwrap_or(""), "approle")
}

impl Sys {
    pub(crate) fn new(client: OpenBaoClient) -> Self {
        Sys { client }
    }

    /// Same as [`OpenBaoClient::health`].
    pub async fn health(&self) -> Result<HealthStatus> {
        self.client.health().await
    }

    /// Same as [`OpenBaoClient::server_version`].
    pub async fn version(&self) -> Result<String> {
        self.client.server_version().await
    }

    /// Seal state (`GET sys/seal-status`, no token needed).
    pub async fn seal_status(&self) -> Result<SealStatus> {
        let resp = self
            .client
            .send(ApiRequest::get("sys/seal-status", "sys.sealStatus").no_auth())
            .await?;
        Ok(SealStatus::from_value(&resp.json::<Value>()?))
    }

    /// HA leader (`GET sys/leader`, no token needed).
    pub async fn leader(&self) -> Result<LeaderStatus> {
        let resp = self
            .client
            .send(ApiRequest::get("sys/leader", "sys.leader").no_auth())
            .await?;
        let d: Value = resp.json()?;
        Ok(LeaderStatus {
            ha_enabled: api::b(&d, "ha_enabled"),
            is_self: api::b(&d, "is_self"),
            active_time: api::time(&d, "active_time"),
            leader_address: api::s(&d, "leader_address"),
            leader_cluster_address: api::s(&d, "leader_cluster_address"),
            raft_committed_index: api::u(&d, "raft_committed_index"),
            raft_applied_index: api::u(&d, "raft_applied_index"),
        })
    }

    // --- policies ---------------------------------------------------------------

    fn policy_path(name: &str) -> String {
        format!("sys/policies/acl/{}", api::encode_path(name))
    }

    /// Creates or replaces an ACL policy (invalid HCL is `VALIDATION`).
    pub async fn write_policy(&self, name: &str, policy: &str) -> Result<()> {
        let op = format!("sys.writePolicy {name}");
        api::require_arg(&op, "name", name)?;
        self.client
            .call(ApiRequest::put(Self::policy_path(name), op).json(json!({ "policy": policy })))
            .await?;
        Ok(())
    }

    /// Reads an ACL policy (`NOT_FOUND` when missing).
    pub async fn read_policy(&self, name: &str) -> Result<Policy> {
        let op = format!("sys.readPolicy {name}");
        api::require_arg(&op, "name", name)?;
        let d = self
            .client
            .data(ApiRequest::get(Self::policy_path(name), op))
            .await?;
        Ok(Policy {
            name: api::s(&d, "name"),
            policy: api::s(&d, "policy"),
        })
    }

    /// ACL policy names (including `default` and `root`).
    pub async fn list_policies(&self) -> Result<Vec<String>> {
        self.client
            .list_keys("sys/policies/acl".into(), "sys.listPolicies".into())
            .await
    }

    /// Deletes an ACL policy.
    pub async fn delete_policy(&self, name: &str) -> Result<()> {
        let op = format!("sys.deletePolicy {name}");
        api::require_arg(&op, "name", name)?;
        self.client
            .call(ApiRequest::delete(Self::policy_path(name), op))
            .await?;
        Ok(())
    }

    // --- mounts and auth methods ---------------------------------------------------

    async fn mounts(&self, path: &str, op: &str) -> Result<BTreeMap<String, MountInfo>> {
        let d = self.client.data(ApiRequest::get(path, op)).await?;
        let Value::Object(map) = d else {
            return Ok(BTreeMap::new());
        };
        Ok(map
            .iter()
            .filter(|(_, v)| !api::s(v, "type").is_empty())
            .map(|(k, v)| {
                let cfg = v.get("config").cloned().unwrap_or(Value::Null);
                (
                    k.clone(),
                    MountInfo {
                        mount_type: api::s(v, "type"),
                        description: api::s(v, "description"),
                        accessor: api::s(v, "accessor"),
                        options: api::smap(v, "options"),
                        default_lease_ttl: api::secs(&cfg, "default_lease_ttl"),
                        max_lease_ttl: api::secs(&cfg, "max_lease_ttl"),
                        local: api::b(v, "local"),
                        seal_wrap: api::b(v, "seal_wrap"),
                        uuid: api::s(v, "uuid"),
                        running_plugin_version: api::s(v, "running_plugin_version"),
                    },
                )
            })
            .collect())
    }

    /// Secrets engines keyed by path (`secret/`).
    pub async fn list_mounts(&self) -> Result<BTreeMap<String, MountInfo>> {
        self.mounts("sys/mounts", "sys.listMounts").await
    }

    /// Mounts an engine of `engine_type` at `path` (a used path is `VALIDATION`). A new KV
    /// v2 mount may answer 400 "Upgrading from non-versioned to versioned data" for a
    /// moment; retry writes briefly.
    pub async fn enable_secrets_engine(
        &self,
        path: &str,
        engine_type: &str,
        opts: Option<&MountOptions>,
    ) -> Result<()> {
        let path = path.trim_matches('/');
        let op = format!("sys.enableSecretsEngine {path}");
        api::require_arg(&op, "path", path)?;
        api::require_arg(&op, "type", engine_type)?;
        self.client.forget_kv_version(path);
        let body = opts.cloned().unwrap_or_default().body(engine_type);
        self.client
            .call(ApiRequest::post(format!("sys/mounts/{}", api::encode_path(path)), op).json(body))
            .await?;
        Ok(())
    }

    /// Unmounts the engine at `path` (all its data is deleted).
    pub async fn disable_secrets_engine(&self, path: &str) -> Result<()> {
        let path = path.trim_matches('/');
        let op = format!("sys.disableSecretsEngine {path}");
        api::require_arg(&op, "path", path)?;
        self.client.forget_kv_version(path);
        self.client
            .call(ApiRequest::delete(
                format!("sys/mounts/{}", api::encode_path(path)),
                op,
            ))
            .await?;
        Ok(())
    }

    /// Auth methods keyed by path (`approle/`).
    pub async fn list_auth_methods(&self) -> Result<BTreeMap<String, MountInfo>> {
        self.mounts("sys/auth", "sys.listAuthMethods").await
    }

    /// Enables an auth method of `method_type` at `path`.
    pub async fn enable_auth_method(
        &self,
        path: &str,
        method_type: &str,
        opts: Option<&MountOptions>,
    ) -> Result<()> {
        let path = path.trim_matches('/');
        let op = format!("sys.enableAuthMethod {path}");
        api::require_arg(&op, "path", path)?;
        api::require_arg(&op, "type", method_type)?;
        let body = opts.cloned().unwrap_or_default().body(method_type);
        self.client
            .call(ApiRequest::post(format!("sys/auth/{}", api::encode_path(path)), op).json(body))
            .await?;
        Ok(())
    }

    /// Disables the auth method at `path`.
    pub async fn disable_auth_method(&self, path: &str) -> Result<()> {
        let path = path.trim_matches('/');
        let op = format!("sys.disableAuthMethod {path}");
        api::require_arg(&op, "path", path)?;
        self.client
            .call(ApiRequest::delete(
                format!("sys/auth/{}", api::encode_path(path)),
                op,
            ))
            .await?;
        Ok(())
    }

    // --- AppRole admin ---------------------------------------------------------------

    fn role_path(mount: &str, name: &str, rest: &[&str]) -> String {
        let mut parts = vec!["auth", mount, "role", name];
        parts.extend_from_slice(rest);
        api::encode_path(&api::join(&parts))
    }

    /// Creates or updates an AppRole role (`POST auth/<mount>/role/<name>`).
    pub async fn create_app_role(&self, name: &str, opts: &AppRoleOptions) -> Result<()> {
        let op = format!("sys.createAppRole {name}");
        api::require_arg(&op, "name", name)?;
        let mut body = Map::new();
        if !opts.token_policies.is_empty() {
            body.insert("token_policies".into(), json!(opts.token_policies));
        }
        for (k, d) in [
            ("token_ttl", opts.token_ttl),
            ("token_max_ttl", opts.token_max_ttl),
            ("secret_id_ttl", opts.secret_id_ttl),
        ] {
            if let Some(d) = d.filter(|d| !d.is_zero()) {
                body.insert(k.into(), json!(api::duration_string(d)));
            }
        }
        if opts.token_num_uses > 0 {
            body.insert("token_num_uses".into(), json!(opts.token_num_uses));
        }
        if let Some(t) = &opts.token_type {
            body.insert("token_type".into(), json!(t));
        }
        if opts.secret_id_num_uses > 0 {
            body.insert("secret_id_num_uses".into(), json!(opts.secret_id_num_uses));
        }
        if let Some(b) = opts.bind_secret_id {
            body.insert("bind_secret_id".into(), json!(b));
        }
        let mount = approle(opts.mount.as_deref());
        self.client
            .call(
                ApiRequest::post(Self::role_path(&mount, name, &[]), op).json(Value::Object(body)),
            )
            .await?;
        Ok(())
    }

    /// AppRole role names on `mount` (`None` = `approle`), sorted.
    pub async fn list_app_roles(&self, mount: Option<&str>) -> Result<Vec<String>> {
        let mount = approle(mount);
        let mut keys = self
            .client
            .list_keys(
                api::encode_path(&format!("auth/{mount}/role")),
                "sys.listAppRoles".into(),
            )
            .await?;
        keys.sort();
        Ok(keys)
    }

    /// Removes an AppRole role.
    pub async fn delete_app_role(&self, name: &str, mount: Option<&str>) -> Result<()> {
        let op = format!("sys.deleteAppRole {name}");
        api::require_arg(&op, "name", name)?;
        self.client
            .call(ApiRequest::delete(
                Self::role_path(&approle(mount), name, &[]),
                op,
            ))
            .await?;
        Ok(())
    }

    /// The role id of an AppRole role (`NOT_FOUND` for an unknown role).
    pub async fn read_role_id(&self, name: &str, mount: Option<&str>) -> Result<String> {
        let op = format!("sys.readRoleId {name}");
        api::require_arg(&op, "name", name)?;
        let d = self
            .client
            .data(ApiRequest::get(
                Self::role_path(&approle(mount), name, &["role-id"]),
                op,
            ))
            .await?;
        Ok(api::s(&d, "role_id"))
    }

    /// Creates a secret id for an AppRole role (`POST auth/<mount>/role/<name>/secret-id`).
    pub async fn generate_secret_id(&self, name: &str, opts: &SecretIdOptions) -> Result<SecretId> {
        let op = format!("sys.generateSecretId {name}");
        api::require_arg(&op, "name", name)?;
        let mut body = Map::new();
        if !opts.metadata.is_empty() {
            body.insert(
                "metadata".into(),
                json!(serde_json::to_string(&opts.metadata)?),
            );
        }
        if let Some(t) = opts.ttl.filter(|t| !t.is_zero()) {
            body.insert("ttl".into(), json!(api::duration_string(t)));
        }
        if opts.num_uses > 0 {
            body.insert("num_uses".into(), json!(opts.num_uses));
        }
        if !opts.cidr_list.is_empty() {
            body.insert("cidr_list".into(), json!(opts.cidr_list));
        }
        let mount = approle(opts.mount.as_deref());
        let d = self
            .client
            .data(
                ApiRequest::post(Self::role_path(&mount, name, &["secret-id"]), op)
                    .json(Value::Object(body)),
            )
            .await?;
        let secret_id = Secret::new(api::s(&d, "secret_id"));
        self.client.remember_secret(&secret_id);
        Ok(SecretId {
            secret_id,
            accessor: api::s(&d, "secret_id_accessor"),
            ttl: api::secs(&d, "secret_id_ttl"),
            num_uses: api::u(&d, "secret_id_num_uses"),
        })
    }
}
