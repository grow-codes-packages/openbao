// Skeleton created by sdk-kit 0.1.0; owned by this repository (edit freely).
//! # grow-openbao
//!
//! Rust SDK for [OpenBao](https://grow-codes-packages.github.io/openbao/) by Grow Codes:
//! one async client (tokio) for auth, KV v1/v2, transit, dynamic database credentials with
//! a lease manager, PKI, policies and mounts, response wrapping and the Grow
//! [`SecretsProvider`](secrets::SecretsProvider) over KV.
//!
//! ```no_run
//! # async fn demo() -> grow_openbao::Result<()> {
//! use grow_openbao::secrets::SecretsProvider;
//! use grow_openbao::{OpenBaoClient, OpenBaoConfig};
//!
//! // explicit > GROW_OPENBAO_* > BAO_* / VAULT_* > defaults
//! let client = OpenBaoClient::new(OpenBaoConfig::from_env()?)?;
//! println!("healthy: {}", client.health().await?.healthy);
//!
//! // KV v2 (auto-detected per mount)
//! let kv = client.kv().await?;
//! kv.write("app/db", serde_json::json!({"password": "s3cr3t"}), None).await?;
//! let secret = kv.read("app/db", None).await?;
//! assert_eq!(secret.data["password"], "s3cr3t");
//!
//! // transit
//! let ct = client.transit().encrypt("app-key", b"hello", None).await?;
//! let pt = client.transit().decrypt("app-key", &ct.ciphertext, None).await?;
//! assert_eq!(pt, b"hello");
//!
//! // the Grow SecretsProvider over KV
//! let secrets = client.secrets();
//! secrets.set("api-key", "abc123".into(), None).await?;
//! assert_eq!(secrets.get_string("api-key", None).await?.as_deref(), Some("abc123"));
//!
//! client.close().await;
//! # Ok(())
//! # }
//! ```
//!
//! Features: `blocking` (a blocking client), `testing` (in-memory fakes, the conformance
//! runner and the [`operator`] init/unseal helpers).
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod core;

mod api;
mod auth;
mod client;
mod config;
mod database;
mod kv;
mod lease;
mod pki;
mod provider;
mod renew;
mod sys;
mod transit;
mod wrapping;

#[cfg(feature = "blocking")]
#[cfg_attr(docsrs, doc(cfg(feature = "blocking")))]
pub mod blocking;

#[cfg(feature = "testing")]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod testing;

#[cfg(feature = "testing")]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod operator;

pub mod secrets;

pub use crate::core::{Error, ErrorCode, HealthStatus, Result, RetryPolicy, Secret};

pub use crate::config::{DEFAULT_KV_MOUNT, DEFAULT_URL, DEFAULT_VALUE_FIELD};

pub use crate::client::OpenBaoClient;

pub use crate::config::OpenBaoConfig;

pub use crate::config::OpenBaoConfigBuilder;

pub use crate::auth::{
    AppRoleAuth, Auth, AuthInfo, AuthMethod, JwtAuth, KubernetesAuth, TokenAuth,
    TokenCreateOptions, TokenInfo, UserpassAuth, DEFAULT_KUBERNETES_JWT_PATH,
};
pub use crate::database::{Database, DatabaseConnectionConfig, DatabaseRole, Lease};
pub use crate::kv::{Kv, KvMetadata, KvMetadataOptions, KvSecret, KvV1, KvV2, KvVersionMetadata};
pub use crate::lease::{
    LeaseInfo, LeaseLookup, LeaseManager, ManageOptions, ManagedLease, OnLeaseError, OnLeaseExpire,
    OnLeaseRenew,
};
pub use crate::pki::{
    Certificate, CertificateInfo, IssueOptions, Pki, Revocation, TidyOptions, TidyStatus,
};
pub use crate::provider::{KvSecretsProvider, SecretsProviderOptions};
pub use crate::renew::{OnExpire, OnRenew, OnRenewError, TokenRenewer, TokenRenewerOptions};
pub use crate::sys::{
    AppRoleOptions, LeaderStatus, MountInfo, MountOptions, Policy, SealStatus, SecretId,
    SecretIdOptions, Sys,
};
pub use crate::transit::{
    CreateKeyOptions, DataKey, DataKeyOptions, EncryptOptions, HashOptions, HmacOptions,
    SignOptions, Transit, TransitBatchItem, TransitBatchResult, TransitCiphertext, TransitKey,
    TransitKeyConfig, TransitKeyVersion, TransitSignature,
};
pub use crate::wrapping::{SecretResponse, WrapInfo, WrapLookup, Wrapping};

/// Service-prefixed alias of [`Error`].
pub type OpenBaoError = Error;
