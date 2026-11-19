//! KV secrets engine: [`KvV1`], [`KvV2`] and the auto-detected [`Kv`].

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use serde_json::{json, Map, Value};

use crate::api::{self, ApiRequest, MERGE_PATCH};
use crate::client::OpenBaoClient;
use crate::core::{Error, Result};

/// A KV secret: its data and (KV v2) the version metadata.
#[derive(Clone, PartialEq)]
pub struct KvSecret {
    /// The secret data (redacted in `Debug`).
    pub data: Map<String, Value>,
    /// Version metadata (`None` on KV v1).
    pub metadata: Option<KvVersionMetadata>,
}

impl std::fmt::Debug for KvSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvSecret")
            .field(
                "data",
                &format_args!("[REDACTED; {} keys]", self.data.len()),
            )
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Metadata of one KV v2 version.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KvVersionMetadata {
    /// Version number.
    pub version: u64,
    /// Creation time.
    pub created_time: Option<SystemTime>,
    /// Soft-delete time (`None` = not deleted).
    pub deletion_time: Option<SystemTime>,
    /// Whether the version was destroyed.
    pub destroyed: bool,
    /// Custom metadata of the key.
    pub custom_metadata: BTreeMap<String, String>,
}

impl KvVersionMetadata {
    fn from_value(v: &Value, version: Option<u64>) -> Self {
        KvVersionMetadata {
            version: version.unwrap_or_else(|| api::u(v, "version")),
            created_time: api::time(v, "created_time"),
            deletion_time: api::time(v, "deletion_time"),
            destroyed: api::b(v, "destroyed"),
            custom_metadata: api::smap(v, "custom_metadata"),
        }
    }

    /// Whether the version is soft-deleted or destroyed.
    pub fn is_deleted(&self) -> bool {
        self.destroyed || self.deletion_time.is_some()
    }
}

/// Metadata of a KV v2 key (all versions).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KvMetadata {
    /// Whether writes must pass `cas`.
    pub cas_required: bool,
    /// Creation time of the key.
    pub created_time: Option<SystemTime>,
    /// Last update time.
    pub updated_time: Option<SystemTime>,
    /// Current version.
    pub current_version: u64,
    /// Oldest stored version.
    pub oldest_version: u64,
    /// Maximum stored versions (0 = mount default).
    pub max_versions: u64,
    /// Versions are deleted this long after being written (zero = never).
    pub delete_version_after: Duration,
    /// Custom metadata.
    pub custom_metadata: BTreeMap<String, String>,
    /// Every stored version.
    pub versions: BTreeMap<u64, KvVersionMetadata>,
}

impl KvMetadata {
    /// Whether the current version is soft-deleted, destroyed or missing.
    pub fn current_deleted(&self) -> bool {
        self.versions
            .get(&self.current_version)
            .is_none_or(KvVersionMetadata::is_deleted)
    }
}

/// Options of `write_metadata`. Unset fields are left unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KvMetadataOptions {
    /// Maximum stored versions.
    pub max_versions: Option<u64>,
    /// Whether writes must pass `cas`.
    pub cas_required: Option<bool>,
    /// Delete versions this long after writing (zero = never).
    pub delete_version_after: Option<Duration>,
    /// Custom metadata (replaces the existing map).
    pub custom_metadata: Option<BTreeMap<String, String>>,
}

fn data_object(op: &str, data: Value) -> Result<Map<String, Value>> {
    match data {
        Value::Object(m) => Ok(m),
        Value::Null => Ok(Map::new()),
        _ => Err(api::invalid(op, "data must be a JSON object")),
    }
}

fn check_versions(op: &str, versions: &[u64]) -> Result<()> {
    if versions.is_empty() || versions.contains(&0) {
        return Err(api::invalid(op, "versions must be positive and not empty"));
    }
    Ok(())
}

fn kv_op(name: &str, mount: &str, path: &str) -> String {
    format!("kv.{name} {}", api::join(&[mount, path]))
}

// --- KV v1 --------------------------------------------------------------------

/// KV version 1 at one mount (no versions, metadata or `cas`; those calls fail with
/// `UNSUPPORTED` without a request).
#[derive(Debug, Clone)]
pub struct KvV1 {
    client: OpenBaoClient,
    mount: String,
}

impl KvV1 {
    pub(crate) fn new(client: OpenBaoClient, mount: &str) -> Self {
        KvV1 {
            client,
            mount: api::mount_or(mount, crate::config::DEFAULT_KV_MOUNT),
        }
    }

    /// The same API at another mount.
    pub fn at(mut self, mount: &str) -> Self {
        self.mount = api::mount_or(mount, &self.mount);
        self
    }

    /// The mount path.
    pub fn mount(&self) -> &str {
        &self.mount
    }

    fn path(&self, path: &str) -> String {
        api::encode_path(&api::join(&[&self.mount, path]))
    }

    fn unsupported(&self, name: &str, path: &str) -> Error {
        Error::unsupported(format!(
            "{}: not available on KV version 1",
            kv_op(name, &self.mount, path)
        ))
    }

    /// Reads a secret (`GET <mount>/<path>`); a `version` is `VALIDATION` on KV v1.
    pub async fn read(&self, path: &str, version: Option<u64>) -> Result<KvSecret> {
        let op = kv_op("read", &self.mount, path);
        if version.is_some() {
            return Err(api::invalid(
                &op,
                "versions are not available on KV version 1",
            ));
        }
        let data = self
            .client
            .data(ApiRequest::get(self.path(path), op))
            .await?;
        Ok(KvSecret {
            data: data.as_object().cloned().unwrap_or_default(),
            metadata: None,
        })
    }

    /// Writes (fully replaces) a secret; `cas` is `UNSUPPORTED` on KV v1. Returns `None`.
    pub async fn write(
        &self,
        path: &str,
        data: Value,
        cas: Option<u64>,
    ) -> Result<Option<KvVersionMetadata>> {
        let op = kv_op("write", &self.mount, path);
        if cas.is_some() {
            return Err(self.unsupported("write", path));
        }
        let data = data_object(&op, data)?;
        self.client
            .call(ApiRequest::post(self.path(path), op).json(Value::Object(data)))
            .await?;
        Ok(None)
    }

    /// `UNSUPPORTED`: KV v1 has no patch.
    pub async fn patch(
        &self,
        path: &str,
        _data: Value,
        _cas: Option<u64>,
    ) -> Result<Option<KvVersionMetadata>> {
        Err(self.unsupported("patch", path))
    }

    /// Deletes a secret (missing paths also succeed).
    pub async fn delete(&self, path: &str) -> Result<()> {
        self.client
            .call(ApiRequest::delete(
                self.path(path),
                kv_op("delete", &self.mount, path),
            ))
            .await?;
        Ok(())
    }

    /// `UNSUPPORTED` on KV v1.
    pub async fn delete_versions(&self, path: &str, _versions: &[u64]) -> Result<()> {
        Err(self.unsupported("deleteVersions", path))
    }

    /// `UNSUPPORTED` on KV v1.
    pub async fn undelete(&self, path: &str, _versions: &[u64]) -> Result<()> {
        Err(self.unsupported("undelete", path))
    }

    /// `UNSUPPORTED` on KV v1.
    pub async fn destroy(&self, path: &str, _versions: &[u64]) -> Result<()> {
        Err(self.unsupported("destroy", path))
    }

    /// Keys directly under `path` (folders end in `/`); a missing path is an empty list.
    pub async fn list(&self, path: &str) -> Result<Vec<String>> {
        self.client
            .list_keys(self.path(path), kv_op("list", &self.mount, path))
            .await
    }

    /// `UNSUPPORTED` on KV v1.
    pub async fn read_metadata(&self, path: &str) -> Result<KvMetadata> {
        Err(self.unsupported("readMetadata", path))
    }

    /// `UNSUPPORTED` on KV v1.
    pub async fn write_metadata(&self, path: &str, _opts: &KvMetadataOptions) -> Result<()> {
        Err(self.unsupported("writeMetadata", path))
    }

    /// `UNSUPPORTED` on KV v1.
    pub async fn delete_metadata(&self, path: &str) -> Result<()> {
        Err(self.unsupported("deleteMetadata", path))
    }
}

// --- KV v2 --------------------------------------------------------------------

/// KV version 2 at one mount.
#[derive(Debug, Clone)]
pub struct KvV2 {
    client: OpenBaoClient,
    mount: String,
}

impl KvV2 {
    pub(crate) fn new(client: OpenBaoClient, mount: &str) -> Self {
        KvV2 {
            client,
            mount: api::mount_or(mount, crate::config::DEFAULT_KV_MOUNT),
        }
    }

    /// The same API at another mount.
    pub fn at(mut self, mount: &str) -> Self {
        self.mount = api::mount_or(mount, &self.mount);
        self
    }

    /// The mount path.
    pub fn mount(&self) -> &str {
        &self.mount
    }

    fn path(&self, kind: &str, path: &str) -> String {
        let mut p = format!("{}/{kind}", api::encode_path(&self.mount));
        let rest = api::encode_path(path);
        if !rest.is_empty() {
            p = format!("{p}/{rest}");
        }
        p
    }

    /// Reads the latest (or the given) version (`GET <mount>/data/<path>`). A missing key
    /// or a deleted/destroyed version is `NOT_FOUND`.
    pub async fn read(&self, path: &str, version: Option<u64>) -> Result<KvSecret> {
        let op = kv_op("read", &self.mount, path);
        let mut req = ApiRequest::get(self.path("data", path), op.clone());
        if let Some(v) = version.filter(|v| *v > 0) {
            req = req.query("version", v.to_string());
        }
        let data = self.client.data(req).await?;
        match data.get("data") {
            Some(Value::Object(m)) => Ok(KvSecret {
                data: m.clone(),
                metadata: data
                    .get("metadata")
                    .map(|m| KvVersionMetadata::from_value(m, None)),
            }),
            _ => Err(Error::not_found(format!(
                "{op}: version is deleted or destroyed"
            ))),
        }
    }

    fn cas_body(data: Map<String, Value>, cas: Option<u64>) -> Value {
        let mut body = json!({ "data": data });
        if let Some(c) = cas {
            body["options"] = json!({ "cas": c });
        }
        body
    }

    /// Writes a new version (`POST <mount>/data/<path>`); `cas` = expected current version
    /// (`0` = create only). A CAS mismatch is `CONFLICT`.
    pub async fn write(
        &self,
        path: &str,
        data: Value,
        cas: Option<u64>,
    ) -> Result<Option<KvVersionMetadata>> {
        let op = kv_op("write", &self.mount, path);
        let data = data_object(&op, data)?;
        let out = self
            .client
            .data(ApiRequest::post(self.path("data", path), op).json(Self::cas_body(data, cas)))
            .await?;
        Ok(Some(KvVersionMetadata::from_value(&out, None)))
    }

    /// Merges `data` into the latest version (RFC 7386: a `null` value removes the key).
    pub async fn patch(
        &self,
        path: &str,
        data: Value,
        cas: Option<u64>,
    ) -> Result<Option<KvVersionMetadata>> {
        let op = kv_op("patch", &self.mount, path);
        let data = data_object(&op, data)?;
        let out = self
            .client
            .data(
                ApiRequest::patch(self.path("data", path), op)
                    .json(Self::cas_body(data, cas))
                    .content_type(MERGE_PATCH),
            )
            .await?;
        Ok(Some(KvVersionMetadata::from_value(&out, None)))
    }

    /// Soft-deletes the latest version (missing paths also succeed).
    pub async fn delete(&self, path: &str) -> Result<()> {
        self.client
            .call(ApiRequest::delete(
                self.path("data", path),
                kv_op("delete", &self.mount, path),
            ))
            .await?;
        Ok(())
    }

    async fn versions_call(
        &self,
        kind: &str,
        name: &str,
        path: &str,
        versions: &[u64],
    ) -> Result<()> {
        let op = kv_op(name, &self.mount, path);
        check_versions(&op, versions)?;
        let req = if kind == "destroy" {
            ApiRequest::put(self.path(kind, path), op)
        } else {
            ApiRequest::post(self.path(kind, path), op)
        };
        self.client
            .call(req.json(json!({ "versions": versions })))
            .await?;
        Ok(())
    }

    /// Soft-deletes the given versions.
    pub async fn delete_versions(&self, path: &str, versions: &[u64]) -> Result<()> {
        self.versions_call("delete", "deleteVersions", path, versions)
            .await
    }

    /// Restores soft-deleted versions (no-op for destroyed versions).
    pub async fn undelete(&self, path: &str, versions: &[u64]) -> Result<()> {
        self.versions_call("undelete", "undelete", path, versions)
            .await
    }

    /// Permanently destroys the given versions' data.
    pub async fn destroy(&self, path: &str, versions: &[u64]) -> Result<()> {
        self.versions_call("destroy", "destroy", path, versions)
            .await
    }

    /// Keys directly under `path` (folders end in `/`); a missing path is an empty list.
    pub async fn list(&self, path: &str) -> Result<Vec<String>> {
        self.client
            .list_keys(
                self.path("metadata", path),
                kv_op("list", &self.mount, path),
            )
            .await
    }

    /// Metadata of a key and all its versions (`NOT_FOUND` when missing).
    pub async fn read_metadata(&self, path: &str) -> Result<KvMetadata> {
        let d = self
            .client
            .data(ApiRequest::get(
                self.path("metadata", path),
                kv_op("readMetadata", &self.mount, path),
            ))
            .await?;
        let versions = match d.get("versions") {
            Some(Value::Object(m)) => m
                .iter()
                .filter_map(|(k, v)| {
                    let n: u64 = k.parse().ok()?;
                    Some((n, KvVersionMetadata::from_value(v, Some(n))))
                })
                .collect(),
            _ => BTreeMap::new(),
        };
        Ok(KvMetadata {
            cas_required: api::b(&d, "cas_required"),
            created_time: api::time(&d, "created_time"),
            updated_time: api::time(&d, "updated_time"),
            current_version: api::u(&d, "current_version"),
            oldest_version: api::u(&d, "oldest_version"),
            max_versions: api::u(&d, "max_versions"),
            delete_version_after: api::secs(&d, "delete_version_after"),
            custom_metadata: api::smap(&d, "custom_metadata"),
            versions,
        })
    }

    /// Updates a key's metadata settings (`POST <mount>/metadata/<path>`).
    pub async fn write_metadata(&self, path: &str, opts: &KvMetadataOptions) -> Result<()> {
        let mut body = Map::new();
        if let Some(n) = opts.max_versions {
            body.insert("max_versions".into(), json!(n));
        }
        if let Some(c) = opts.cas_required {
            body.insert("cas_required".into(), json!(c));
        }
        if let Some(d) = opts.delete_version_after {
            body.insert(
                "delete_version_after".into(),
                json!(api::duration_string(d)),
            );
        }
        if let Some(m) = &opts.custom_metadata {
            body.insert("custom_metadata".into(), json!(m));
        }
        self.client
            .call(
                ApiRequest::post(
                    self.path("metadata", path),
                    kv_op("writeMetadata", &self.mount, path),
                )
                .json(Value::Object(body)),
            )
            .await?;
        Ok(())
    }

    /// Deletes a key with all versions and metadata (missing paths also succeed).
    pub async fn delete_metadata(&self, path: &str) -> Result<()> {
        self.client
            .call(ApiRequest::delete(
                self.path("metadata", path),
                kv_op("deleteMetadata", &self.mount, path),
            ))
            .await?;
        Ok(())
    }
}

// --- auto-detected --------------------------------------------------------------

/// A KV mount whose version was detected ([`OpenBaoClient::kv`]). Every method dispatches
/// to [`KvV1`] or [`KvV2`]; v2-only calls fail with `UNSUPPORTED` on v1.
#[derive(Debug, Clone)]
pub enum Kv {
    /// KV version 1.
    V1(KvV1),
    /// KV version 2.
    V2(KvV2),
}

macro_rules! dispatch {
    ($self:ident, $kv:ident => $e:expr) => {
        match $self {
            Kv::V1($kv) => $e,
            Kv::V2($kv) => $e,
        }
    };
}

impl Kv {
    /// 1 or 2.
    pub fn version(&self) -> u8 {
        match self {
            Kv::V1(_) => 1,
            Kv::V2(_) => 2,
        }
    }
    /// The mount path.
    pub fn mount(&self) -> &str {
        dispatch!(self, kv => kv.mount())
    }
    /// See [`KvV2::read`] / [`KvV1::read`].
    pub async fn read(&self, path: &str, version: Option<u64>) -> Result<KvSecret> {
        dispatch!(self, kv => kv.read(path, version).await)
    }
    /// See [`KvV2::write`] / [`KvV1::write`].
    pub async fn write(
        &self,
        path: &str,
        data: Value,
        cas: Option<u64>,
    ) -> Result<Option<KvVersionMetadata>> {
        dispatch!(self, kv => kv.write(path, data, cas).await)
    }
    /// See [`KvV2::patch`].
    pub async fn patch(
        &self,
        path: &str,
        data: Value,
        cas: Option<u64>,
    ) -> Result<Option<KvVersionMetadata>> {
        dispatch!(self, kv => kv.patch(path, data, cas).await)
    }
    /// See [`KvV2::delete`] / [`KvV1::delete`].
    pub async fn delete(&self, path: &str) -> Result<()> {
        dispatch!(self, kv => kv.delete(path).await)
    }
    /// See [`KvV2::delete_versions`].
    pub async fn delete_versions(&self, path: &str, versions: &[u64]) -> Result<()> {
        dispatch!(self, kv => kv.delete_versions(path, versions).await)
    }
    /// See [`KvV2::undelete`].
    pub async fn undelete(&self, path: &str, versions: &[u64]) -> Result<()> {
        dispatch!(self, kv => kv.undelete(path, versions).await)
    }
    /// See [`KvV2::destroy`].
    pub async fn destroy(&self, path: &str, versions: &[u64]) -> Result<()> {
        dispatch!(self, kv => kv.destroy(path, versions).await)
    }
    /// See [`KvV2::list`] / [`KvV1::list`].
    pub async fn list(&self, path: &str) -> Result<Vec<String>> {
        dispatch!(self, kv => kv.list(path).await)
    }
    /// See [`KvV2::read_metadata`].
    pub async fn read_metadata(&self, path: &str) -> Result<KvMetadata> {
        dispatch!(self, kv => kv.read_metadata(path).await)
    }
    /// See [`KvV2::write_metadata`].
    pub async fn write_metadata(&self, path: &str, opts: &KvMetadataOptions) -> Result<()> {
        dispatch!(self, kv => kv.write_metadata(path, opts).await)
    }
    /// See [`KvV2::delete_metadata`].
    pub async fn delete_metadata(&self, path: &str) -> Result<()> {
        dispatch!(self, kv => kv.delete_metadata(path).await)
    }
}
