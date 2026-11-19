// Created by sdk-kit 0.1.0; owned by this repository.
//! Basics of the OpenBao Rust SDK: configuration from the environment, health, an
//! authenticated ping, hooks and error handling, then KV v2, transit, response wrapping and
//! the Grow `SecretsProvider` against a real server (needs a token that may use `secret/`
//! and `transit/`, e.g. a dev server: `bao server -dev`).
//!
//! ```sh
//! GROW_OPENBAO_URL=http://127.0.0.1:8200 GROW_OPENBAO_TOKEN=... cargo run
//! ```

use std::sync::Arc;
use std::time::Duration;

use grow_openbao as sdk;
use sdk::core::{ErrorInfo, Hooks};
use sdk::secrets::SecretsProvider;
use sdk::ErrorCode;
use serde_json::json;

use sdk::OpenBaoClient as Client;
use sdk::OpenBaoConfig as Config;

/// Prints every retry.
struct RetryLogger;

impl Hooks for RetryLogger {
    fn on_error(&self, info: &ErrorInfo) {
        if info.will_retry {
            eprintln!(
                "retrying {} {} (attempt {})",
                info.method, info.url, info.attempt
            );
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error [{}]: {err}", err.code());
        std::process::exit(1);
    }
}

async fn run() -> sdk::Result<()> {
    // explicit > GROW_OPENBAO_* > vendor variables > defaults; invalid values name the
    // variable, never its value.
    let config = Config::builder()
        .hooks(Arc::new(RetryLogger))
        .build_from_env()?;
    println!("config: {config:?}"); // credentials print as [REDACTED]

    let client = Client::new(config)?;
    let health = client.health().await?; // never fails for an unreachable service
    println!("health: {} ({})", health.healthy, health.status);

    match client.ping().await {
        Ok(latency) => println!("ping: {} ms", latency.as_millis()),
        Err(e) if e.code() == ErrorCode::Authentication => {
            println!("ping: check GROW_OPENBAO_TOKEN ({e})")
        }
        Err(e) => return Err(e),
    }
    match client.server_version().await {
        Ok(version) => println!("server version: {version}"),
        Err(e) if e.code() == ErrorCode::Unsupported => println!("server version: not exposed"),
        Err(e) => return Err(e),
    }

    // KV v2 (the version of the mount is detected automatically)
    let kv = client.kv().await?;
    let written = kv
        .write(
            "examples/rust/db",
            json!({"user": "app", "password": "s3cr3t"}),
            None,
        )
        .await?;
    println!("kv: wrote version {:?}", written.map(|m| m.version));
    let secret = kv.read("examples/rust/db", None).await?;
    println!("kv: user = {}", secret.data["user"]);

    // transit: create a key (idempotent), encrypt and decrypt
    let transit = client.transit();
    transit
        .create_key("examples-rust", "aes256-gcm96", None)
        .await?;
    let ct = transit.encrypt("examples-rust", b"hello", None).await?;
    let pt = transit
        .decrypt("examples-rust", &ct.ciphertext, None)
        .await?;
    println!(
        "transit: {} -> {:?}",
        ct.ciphertext,
        String::from_utf8_lossy(&pt)
    );

    // response wrapping: hand a secret over with a single-use token
    let wrap = client
        .wrapping()
        .wrap(json!({"api-key": "abc123"}), Duration::from_secs(60))
        .await?;
    let unwrapped = client.wrapping().unwrap(wrap.token.expose_secret()).await?;
    println!(
        "wrapping: unwrapped keys {:?}",
        unwrapped.data.keys().collect::<Vec<_>>()
    );

    // the Grow SecretsProvider over KV (same API for every secrets service)
    let secrets = client.secrets();
    let version = secrets
        .set("examples/rust/api-key", "abc123".into(), None)
        .await?;
    let value = secrets.require("examples/rust/api-key", None).await?;
    println!("secrets: version {version}, value {value}"); // prints SecretValue([REDACTED])

    client.close().await;
    Ok(())
}
