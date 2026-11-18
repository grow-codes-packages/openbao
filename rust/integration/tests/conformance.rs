// Created by sdk-kit 0.1.0; owned by this repository.
//! Integration suite against the real service (Docker): client round trips and the
//! conformance scenarios for `core` and `secrets` (KV v2 at `secret/`, and KV v1 at `kv1/`).

use std::sync::Arc;

use grow_openbao as sdk;
use grow_openbao_integration as support;
use sdk::testing::{ConformanceRunner, CoreHandler, SecretsHandler};
use sdk::ErrorCode;
use support::{conformance_dir, load_bootstrap_env, root_client, test_env};

use sdk::blocking::OpenBaoClient as BlockingClient;

use sdk::OpenBaoClient as Client;

#[tokio::test]
async fn client_round_trip() {
    let c = root_client();
    let health = c.health().await.expect("health");
    assert!(health.healthy, "service not healthy: {health:?}");
    assert_eq!(health.status, "active");
    c.ping().await.expect("authenticated ping");
    let version = c.server_version().await.expect("server version");
    assert_eq!(version, test_env("SERVER_VERSION"));
    c.close().await;
    c.close().await;
    assert_eq!(c.ping().await.unwrap_err().code(), ErrorCode::Cancelled);
}

#[test]
fn blocking_round_trip() {
    load_bootstrap_env();
    let c = BlockingClient::from_env().expect("client");
    assert!(c.health().expect("health").healthy);
    c.ping().expect("ping");
    assert!(!c.server_version().expect("version").is_empty());
    // service modules through block_on
    let bao = c.async_client().clone();
    let ct = c
        .block_on(bao.transit().encrypt("sdk-aes", b"blocking", None))
        .expect("encrypt");
    let pt = c
        .block_on(bao.transit().decrypt("sdk-aes", &ct.ciphertext, None))
        .expect("decrypt");
    assert_eq!(pt, b"blocking");
    c.close();
}

#[tokio::test]
async fn conformance() {
    load_bootstrap_env();
    let kv2: Arc<dyn sdk::secrets::SecretsProvider> = Arc::new(root_client().secrets());
    let report = ConformanceRunner::new(conformance_dir())
        // Declared: serverVersion, write, delete, versions (KV v2). Not applicable to a
        // secrets store: query/tail/labels/streams/services/dependencies.
        .capabilities(["version", "write", "delete", "versions"])
        .handler(CoreHandler::new(Client::from_env))
        .handler(SecretsHandler::new(move || kv2.clone()))
        .run()
        .await
        .expect("scenarios load");
    println!("{report}");
    report.assert_success();
}

#[tokio::test]
async fn conformance_kv_v1() {
    load_bootstrap_env();
    let c = root_client();
    let kv1: Arc<dyn sdk::secrets::SecretsProvider> =
        Arc::new(c.secrets_with(sdk::SecretsProviderOptions {
            mount: Some(test_env("KV1_MOUNT")),
            ..Default::default()
        }));
    let report = ConformanceRunner::new(conformance_dir())
        // KV v1 has no versions; versions-only steps are skipped.
        .capabilities(["write", "delete"])
        .handler(SecretsHandler::new(move || kv1.clone()))
        .run()
        .await
        .expect("scenarios load");
    println!("{report}");
    report.assert_success();
}
