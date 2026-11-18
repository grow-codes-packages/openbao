//! `SecretsProvider` (SPEC §3) over an OpenBao KV mount.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use futures::stream::{self, StreamExt, TryStreamExt};
use serde_json::{json, Map, Value};

use crate::api;
use crate::client::OpenBaoClient;
use crate::core::{Error, ErrorCode, Result};
use crate::kv::{Kv, KvMetadataOptions};
use crate::secrets::{
    watch, BaseSecretsProvider, DeleteOptions, GetOptions, SecretMetadata, SecretValue, SetOptions,
    WatchHandle, WatchOptions,
};

/// Concurrent metadata reads of `list` on KV v2.
const LIST_CONCURRENCY: usize = 8;

/// Options of [`OpenBaoClient::secrets_with`]. Unset fields fall back to the client config
/// (`kv_mount`, `secrets_path`, `value_field`, `kv_version`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretsProviderOptions {
    /// KV mount (default: config `kv_mount`, then `secret`).
    pub mount: Option<String>,
    /// Base path inside the mount under which names live.
    pub path: Option<String>,
    /// Data field holding the value (default `value`).
    pub value_field: Option<String>,
    /// Forces KV version 1 or 2 (default: auto-detect).
    pub kv_version: Option<u8>,
}

/// The [`SecretsProvider`](crate::secrets::SecretsProvider) over an OpenBao KV mount.
///
/// Model: a secret is one KV path `<path>/<name>` (`GetOptions::path` / `SetOptions::path`
/// replace the base path). The value is stored as `{"value": "<text>"}`; bytes that are
/// not valid UTF-8 are stored as `{"value": "<base64>", "encoding": "base64"}`; JSON
/// documents are JSON-encoded into `value`. Reading a path without a `value` field returns
/// the whole data map JSON-encoded. Versions are the KV v2 version numbers as strings
/// (`""` on KV v1). A KV v2 key whose current version is deleted or destroyed counts as
/// missing.
#[derive(Debug, Clone)]
pub struct KvSecretsProvider {
    client: OpenBaoClient,
    mount: String,
    path: String,
    value_field: String,
    kv_version: Option<u8>,
}

impl KvSecretsProvider {
    pub(crate) fn new(client: OpenBaoClient, opts: SecretsProviderOptions) -> Self {
        let cfg = client.config();
        let mount = api::mount_or(opts.mount.as_deref().unwrap_or(""), cfg.kv_mount());
        let path = opts
            .path
            .unwrap_or_else(|| cfg.secrets_path().to_owned())
            .trim_matches('/')
            .to_owned();
        let value_field = opts
            .value_field
            .filter(|f| !f.is_empty())
            .unwrap_or_else(|| cfg.value_field().to_owned());
        let kv_version = opts.kv_version.filter(|v| *v != 0).or(cfg.kv_version());
        KvSecretsProvider {
            client,
            mount,
            path,
            value_field,
            kv_version,
        }
    }

    /// The KV mount in use.
    pub fn mount(&self) -> &str {
        &self.mount
    }

    /// The base path inside the mount.
    pub fn base_path(&self) -> &str {
        &self.path
    }

    /// The KV engine the provider uses (its version detected or forced).
    pub async fn kv(&self) -> Result<Kv> {
        let version = self.client.kv_version(&self.mount, self.kv_version).await?;
        Ok(if version == 1 {
            Kv::V1(self.client.kv_v1().at(&self.mount))
        } else {
            Kv::V2(self.client.kv_v2().at(&self.mount))
        })
    }

    /// Polls `name` every `interval` and calls `on_change(new, old)` on a version change or
    /// deletion (see [`watch`]). The watch stops on [`WatchHandle::stop`] or when the
    /// client is closed (not when the handle is dropped: the client keeps a reference to
    /// stop it on close).
    pub fn watch<F>(
        &self,
        name: impl Into<String>,
        interval: Duration,
        on_change: F,
        opts: WatchOptions,
    ) -> WatchHandle
    where
        F: Fn(Option<&SecretValue>, Option<&SecretValue>) + Send + Sync + 'static,
    {
        let handle = watch(Arc::new(self.clone()), name, interval, on_change, opts);
        let stop = handle.clone();
        let closed = self.client.background();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = closed.cancelled() => {
                        stop.stop();
                        return;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(500)) => {
                        if stop.is_stopped() {
                            return;
                        }
                    }
                }
            }
        });
        handle
    }

    fn key(&self, name: &str, path: Option<&str>) -> String {
        let base = path.unwrap_or(&self.path);
        api::join(&[base, name])
    }

    fn decode(&self, op: &str, data: &Map<String, Value>) -> Result<Vec<u8>> {
        match data.get(&self.value_field) {
            None => Ok(serde_json::to_vec(data)?),
            Some(Value::String(s)) => {
                if data.get("encoding").and_then(Value::as_str) == Some("base64") {
                    base64::engine::general_purpose::STANDARD
                        .decode(s)
                        .map_err(|_| api::invalid(op, "value is not valid base64"))
                } else {
                    Ok(s.clone().into_bytes())
                }
            }
            Some(other) => Ok(serde_json::to_vec(other)?),
        }
    }

    fn encode(&self, value: Vec<u8>) -> Value {
        match String::from_utf8(value) {
            Ok(text) => json!({ self.value_field.clone(): text }),
            Err(e) => json!({
                self.value_field.clone(): api::b64(e.as_bytes()),
                "encoding": "base64",
            }),
        }
    }

    fn parent(name: &str) -> Option<String> {
        name.trim_matches('/')
            .rsplit_once('/')
            .map(|(p, _)| p.to_owned())
    }
}

fn is_not_found(err: &Error) -> bool {
    err.code() == ErrorCode::NotFound
}

#[async_trait]
impl BaseSecretsProvider for KvSecretsProvider {
    async fn fetch_secret(&self, name: &str, opts: &GetOptions) -> Result<Option<SecretValue>> {
        let kv = self.kv().await?;
        let key = self.key(name, opts.path.as_deref());
        let op = format!("secrets.get {key}");
        let version = match opts.version.as_deref().filter(|v| !v.is_empty()) {
            None => None,
            Some(_) if kv.version() == 1 => {
                return Err(api::invalid(
                    &op,
                    "versions are not available on KV version 1",
                ))
            }
            Some(v) => Some(
                v.parse::<u64>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| api::invalid(&op, "version must be a positive integer"))?,
            ),
        };
        let secret = match kv.read(&key, version).await {
            Ok(s) => s,
            Err(e) if is_not_found(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut value = SecretValue::new(self.decode(&op, &secret.data)?);
        if let Some(md) = &secret.metadata {
            value = value.with_version(md.version.to_string());
        }
        Ok(Some(value))
    }

    async fn list_secrets(&self, path: Option<&str>) -> Result<Vec<SecretMetadata>> {
        let kv = self.kv().await?;
        let prefix = path.unwrap_or("").trim_matches('/').to_owned();
        let keys = kv.list(&api::join(&[&self.path, &prefix])).await?;
        let names: Vec<String> = keys
            .iter()
            .filter(|k| !k.ends_with('/'))
            .map(|k| api::join(&[&prefix, k]))
            .collect();
        if kv.version() == 1 {
            return Ok(names
                .into_iter()
                .map(|n| SecretMetadata {
                    name: n,
                    path: (!prefix.is_empty()).then(|| prefix.clone()),
                    ..SecretMetadata::default()
                })
                .collect());
        }
        let opts = GetOptions::default();
        let reads: Vec<_> = names
            .iter()
            .map(|n| self.fetch_metadata(n, &opts))
            .collect();
        let found: Vec<Option<SecretMetadata>> = stream::iter(reads)
            .buffered(LIST_CONCURRENCY)
            .try_collect()
            .await?;
        Ok(found.into_iter().flatten().collect())
    }

    async fn put_secret(&self, name: &str, value: Vec<u8>, opts: &SetOptions) -> Result<String> {
        let kv = self.kv().await?;
        let key = self.key(name, opts.path.as_deref());
        let op = format!("secrets.set {key}");
        let data = self.encode(value);
        if kv.version() == 1 {
            if opts.cas.is_some() || !opts.tags.is_empty() || opts.description.is_some() {
                return Err(Error::unsupported(format!(
                    "{op}: cas, tags and description need KV version 2"
                )));
            }
            kv.write(&key, data, None).await?;
            return Ok(String::new());
        }
        let md = kv.write(&key, data, opts.cas).await?;
        if !opts.tags.is_empty() || opts.description.is_some() {
            let mut custom = opts.tags.clone();
            if let Some(d) = &opts.description {
                custom.insert("description".into(), d.clone());
            }
            kv.write_metadata(
                &key,
                &KvMetadataOptions {
                    custom_metadata: Some(custom),
                    ..KvMetadataOptions::default()
                },
            )
            .await?;
        }
        Ok(md.map(|m| m.version.to_string()).unwrap_or_default())
    }

    async fn remove_secret(&self, name: &str, opts: &DeleteOptions) -> Result<()> {
        let kv = self.kv().await?;
        let key = self.key(name, opts.path.as_deref());
        let op = format!("secrets.delete {key}");
        let not_found = || Error::not_found(format!("{op}: not found"));
        if kv.version() == 1 {
            if !opts.versions.is_empty() {
                return Err(Error::unsupported(format!(
                    "{op}: versions need KV version 2"
                )));
            }
            match kv.read(&key, None).await {
                Ok(_) => {}
                Err(e) if is_not_found(&e) => return Err(not_found()),
                Err(e) => return Err(e),
            }
            return kv.delete(&key).await;
        }
        let md = match kv.read_metadata(&key).await {
            Ok(md) => md,
            Err(e) if is_not_found(&e) => return Err(not_found()),
            Err(e) => return Err(e),
        };
        if opts.permanent {
            return kv.delete_metadata(&key).await;
        }
        if !opts.versions.is_empty() {
            let versions = opts
                .versions
                .iter()
                .map(|v| v.parse::<u64>().ok().filter(|n| *n > 0))
                .collect::<Option<Vec<u64>>>()
                .ok_or_else(|| api::invalid(&op, "versions must be positive integers"))?;
            return kv.delete_versions(&key, &versions).await;
        }
        if md.current_deleted() {
            return Err(not_found());
        }
        kv.delete(&key).await
    }

    async fn fetch_metadata(
        &self,
        name: &str,
        opts: &GetOptions,
    ) -> Result<Option<SecretMetadata>> {
        let kv = self.kv().await?;
        let key = self.key(name, opts.path.as_deref());
        let name = name.trim_matches('/').to_owned();
        let path = Self::parent(&name);
        if kv.version() == 1 {
            return match kv.read(&key, None).await {
                Ok(_) => Ok(Some(SecretMetadata {
                    name,
                    path,
                    ..SecretMetadata::default()
                })),
                Err(e) if is_not_found(&e) => Ok(None),
                Err(e) => Err(e),
            };
        }
        let md = match kv.read_metadata(&key).await {
            Ok(md) => md,
            Err(e) if is_not_found(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        if md.current_deleted() {
            return Ok(None);
        }
        let mut extra = std::collections::BTreeMap::new();
        extra.insert("max_versions".into(), md.max_versions.to_string());
        extra.insert("cas_required".into(), md.cas_required.to_string());
        extra.insert(
            "delete_version_after".into(),
            format!("{}s", md.delete_version_after.as_secs()),
        );
        extra.insert("oldest_version".into(), md.oldest_version.to_string());
        Ok(Some(SecretMetadata {
            name,
            path,
            version: Some(md.current_version.to_string()),
            created_at: md.created_time,
            updated_at: md.updated_time,
            tags: md.custom_metadata.clone(),
            versions: Some(md.versions.len() as u64),
            extra,
        }))
    }
}
