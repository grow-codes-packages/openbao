//! Helpers for the OpenBao service tests: recorded fixtures and a client on a mock server.
#![allow(dead_code)]

use std::path::PathBuf;

use grow_openbao::{OpenBaoClient, OpenBaoConfig, OpenBaoConfigBuilder, RetryPolicy};
use serde_json::Value;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Token used by [`client`].
pub const TOKEN: &str = "s.test-token-1234";

/// A recorded fixture (`tests/fixtures/openbao/<name>.json`).
pub fn fixture(name: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/openbao")
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("fixture {name}"));
    serde_json::from_str(&text).expect("fixture json")
}

/// The fixture's recorded response body.
pub fn body(name: &str) -> Value {
    fixture(name)["response"]["body"].clone()
}

/// The fixture's response as a mock reply.
pub fn reply(name: &str) -> ResponseTemplate {
    let f = fixture(name);
    let status = f["response"]["status"].as_u64().expect("status") as u16;
    match &f["response"]["body"] {
        Value::Null => ResponseTemplate::new(status),
        Value::String(s) => ResponseTemplate::new(status).set_body_string(s.clone()),
        other => ResponseTemplate::new(status).set_body_json(other.clone()),
    }
}

/// A JSON reply.
pub fn json(status: u16, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(body)
}

/// Mounts `method path → fixture` (matched any number of times).
pub async fn on(server: &MockServer, verb: &str, p: &str, name: &str) {
    Mock::given(method(verb))
        .and(path(p))
        .respond_with(reply(name))
        .mount(server)
        .await;
}

/// Mounts `method path → fixture` for exactly one call (then falls through).
pub async fn once(server: &MockServer, verb: &str, p: &str, name: &str) {
    Mock::given(method(verb))
        .and(path(p))
        .respond_with(reply(name))
        .up_to_n_times(1)
        .mount(server)
        .await;
}

/// Mounts a LIST (`GET <path>?list=true`) answered by a fixture.
pub async fn on_list(server: &MockServer, p: &str, name: &str) {
    Mock::given(method("GET"))
        .and(path(p))
        .and(query_param("list", "true"))
        .respond_with(reply(name))
        .mount(server)
        .await;
}

/// Mounts a raw reply.
pub async fn on_reply(server: &MockServer, verb: &str, p: &str, r: ResponseTemplate) {
    Mock::given(method(verb))
        .and(path(p))
        .respond_with(r)
        .mount(server)
        .await;
}

/// A config builder pointing at `server` with the test token and no retries.
pub fn builder(server: &MockServer) -> OpenBaoConfigBuilder {
    OpenBaoConfig::builder()
        .url(server.uri())
        .token(TOKEN)
        .retry(RetryPolicy::none())
}

/// A client on `server` with the test token and no retries.
pub fn client(server: &MockServer) -> OpenBaoClient {
    OpenBaoClient::new(builder(server).build().expect("config")).expect("client")
}

/// The JSON bodies of the requests with a body the mock server received for `p`.
pub async fn sent(server: &MockServer, p: &str) -> Vec<Value> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path() == p && !r.body.is_empty())
        .map(|r| serde_json::from_slice(&r.body).unwrap_or(Value::Null))
        .collect()
}

/// The requests the mock server received for `p`.
pub async fn requests(server: &MockServer, p: &str) -> Vec<wiremock::Request> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path() == p)
        .collect()
}
