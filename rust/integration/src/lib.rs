// Created by sdk-kit 0.1.0; owned by this repository.
//! Helpers for the integration tests: bootstrap credentials and the conformance directory.

use std::path::PathBuf;

use grow_openbao as sdk;

/// Loads `KEY=value` lines from `$GROW_BOOTSTRAP_ENV` (default `/bootstrap/env`) into the
/// process environment; variables that are already set win. A missing file is not an error.
pub fn load_bootstrap_env() {
    let path = std::env::var("GROW_BOOTSTRAP_ENV").unwrap_or_else(|_| "/bootstrap/env".to_owned());
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().trim_start_matches("export ").trim();
            let value = value.trim().trim_matches('"');
            if !key.is_empty() && std::env::var_os(key).is_none() {
                std::env::set_var(key, value);
            }
        }
    }
}

/// `$GROW_CONFORMANCE_DIR`, else `<repo>/conformance/scenarios`.
pub fn conformance_dir() -> PathBuf {
    sdk::testing::scenarios_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
}

/// A bootstrap variable (`GROW_OPENBAO_TEST_<name>`); panics with a clear message when unset.
pub fn test_env(name: &str) -> String {
    load_bootstrap_env();
    let var = format!("GROW_OPENBAO_TEST_{name}");
    std::env::var(&var).unwrap_or_else(|_| panic!("{var} is not set (bootstrap env missing?)"))
}

/// An optional bootstrap variable (empty = `None`).
pub fn test_env_opt(name: &str) -> Option<String> {
    load_bootstrap_env();
    std::env::var(format!("GROW_OPENBAO_TEST_{name}"))
        .ok()
        .filter(|v| !v.is_empty())
}

/// A short id unique to this test process and call.
pub fn run_id() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!(
        "rs{:x}{:x}{}",
        std::process::id(),
        nanos,
        N.fetch_add(1, Ordering::SeqCst)
    )
}

/// The root client from the bootstrap environment (`GROW_OPENBAO_URL` + `GROW_OPENBAO_TOKEN`).
pub fn root_client() -> sdk::OpenBaoClient {
    load_bootstrap_env();
    sdk::OpenBaoClient::from_env().expect("client from env")
}

/// A client for the same server without a token.
pub fn anonymous_client() -> sdk::OpenBaoClient {
    load_bootstrap_env();
    let url = std::env::var("GROW_OPENBAO_URL").unwrap_or_else(|_| sdk::DEFAULT_URL.to_owned());
    sdk::OpenBaoClient::new(
        sdk::OpenBaoConfig::builder()
            .url(url)
            .build()
            .expect("config"),
    )
    .expect("client")
}
