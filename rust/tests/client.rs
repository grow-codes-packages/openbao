// Taken over from sdk-kit 0.1.0 (header removed): the skeleton tests targeted the demo
// service; these test the OpenBao client surface against recorded OpenBao responses.
//! `OpenBaoClient`: health, ping, server version, close, token handling, KV detection.

mod common;
mod support;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::closed_port;
use grow_openbao as sdk;
use sdk::core::{EnvReader, ErrorCode};
use sdk::{OpenBaoClient as Client, OpenBaoConfig as Config, RetryPolicy, Secret};
use serde_json::json;
use support::*;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn client_surface() {
    let server = MockServer::start().await;
    on(&server, "GET", "/v1/sys/health", "health.active").await;
    Mock::given(path("/v1/auth/token/lookup-self"))
        .and(header("x-vault-token", TOKEN))
        .respond_with(reply("ping.lookup-self"))
        .mount(&server)
        .await;
    on(
        &server,
        "GET",
        "/v1/auth/token/lookup-self",
        "ping.invalid-token",
    )
    .await;
    let c = client(&server);
    let h = c.health().await.unwrap();
    assert!(h.healthy);
    assert_eq!(h.status, "active");
    assert_eq!(h.details["version"], "2.7.2");
    assert_eq!(h.details["httpStatus"], "200");
    assert_eq!(h.details["sealed"], "false");
    assert!(c.ping().await.unwrap() < Duration::from_secs(5));
    assert_eq!(c.server_version().await.unwrap(), "2.7.2");
    assert_eq!(c.sys().version().await.unwrap(), "2.7.2");
    assert!(c.sys().health().await.unwrap().healthy);
    assert_eq!(c.config().token().unwrap().expose_secret(), TOKEN);
    assert!(format!("{c:?}").contains("[REDACTED]"));
    assert!(!format!("{c:?}").contains(TOKEN));
    // the health check sends no token
    let health = requests(&server, "/v1/sys/health").await;
    assert!(health[0].headers.get("x-vault-token").is_none());

    let bad = Client::new(builder(&server).token("wrong-token").build().unwrap()).unwrap();
    let err = bad.ping().await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Authentication);
    assert_eq!(err.http_status(), Some(403));
    assert!(!err.message().contains("wrong-token"));
    let none = Client::new(Config::builder().url(server.uri()).build().unwrap()).unwrap();
    assert!(none.token().is_none());
    assert_eq!(
        none.ping().await.unwrap_err().code(),
        ErrorCode::Authentication
    );
}

#[tokio::test]
async fn client_health_variants() {
    let server = MockServer::start().await;
    let cases = [
        ("/a", reply("health.sealed"), false, "sealed", "503"),
        (
            "/b",
            reply("health.uninitialized"),
            false,
            "uninitialized",
            "501",
        ),
        (
            "/c",
            json(
                429,
                json!({"initialized": true, "sealed": false, "standby": true}),
            ),
            false,
            "standby",
            "429",
        ),
        (
            "/d",
            json(
                473,
                json!({"initialized": true, "sealed": false, "standby": true, "performance_standby": true}),
            ),
            false,
            "perfstandby",
            "473",
        ),
        ("/e", ResponseTemplate::new(500), false, "unhealthy", "500"),
        ("/f", ResponseTemplate::new(200), true, "active", "200"),
    ];
    for (prefix, r, healthy, word, code) in cases {
        on_reply(&server, "GET", &format!("{prefix}/v1/sys/health"), r).await;
        let c = Client::new(
            builder(&server)
                .url(format!("{}{prefix}", server.uri()))
                .build()
                .unwrap(),
        )
        .unwrap();
        let h = c.health().await.unwrap();
        assert_eq!((h.healthy, h.status.as_str()), (healthy, word), "{prefix}");
        assert_eq!(h.details["httpStatus"], code);
    }
    // an unexpected HTTP error is unhealthy, not an error
    on_reply(
        &server,
        "GET",
        "/g/v1/sys/health",
        ResponseTemplate::new(404),
    )
    .await;
    let c = Client::new(
        builder(&server)
            .url(format!("{}/g", server.uri()))
            .build()
            .unwrap(),
    )
    .unwrap();
    let h = c.health().await.unwrap();
    assert_eq!((h.healthy, h.status.as_str()), (false, "unhealthy"));
}

#[tokio::test]
async fn core_health_unreachable() {
    let c = Client::new(
        Config::builder()
            .url(format!("http://127.0.0.1:{}", closed_port()))
            .retry(RetryPolicy::none())
            .build()
            .unwrap(),
    )
    .unwrap();
    let h = c.health().await.unwrap();
    assert!(!h.healthy);
    assert_eq!(h.status, "unreachable");
    assert!(h.details.contains_key("error"));
    c.close().await;
    assert_eq!(c.health().await.unwrap_err().code(), ErrorCode::Cancelled);
}

#[tokio::test]
async fn client_server_version_variants() {
    let server = MockServer::start().await;
    on(&server, "GET", "/a/v1/sys/health", "health.sealed").await;
    on_reply(&server, "GET", "/b/v1/sys/health", json(200, json!({}))).await;
    on_reply(
        &server,
        "GET",
        "/c/v1/sys/health",
        ResponseTemplate::new(503),
    )
    .await;
    on_reply(
        &server,
        "GET",
        "/d/v1/sys/health",
        ResponseTemplate::new(403),
    )
    .await;
    let at = |p: &str| {
        Client::new(
            builder(&server)
                .url(format!("{}{p}", server.uri()))
                .build()
                .unwrap(),
        )
        .unwrap()
    };
    // a sealed server still reports its version
    assert_eq!(at("/a").server_version().await.unwrap(), "2.7.2");
    assert_eq!(
        at("/b").server_version().await.unwrap_err().code(),
        ErrorCode::Unsupported
    );
    let e = at("/c").server_version().await.unwrap_err();
    assert_eq!(
        (e.code(), e.http_status()),
        (ErrorCode::Unavailable, Some(503))
    );
    assert_eq!(
        at("/d").server_version().await.unwrap_err().code(),
        ErrorCode::Authentication
    );
}

#[tokio::test]
async fn core_close_idempotent() {
    let server = MockServer::start().await;
    on(
        &server,
        "GET",
        "/v1/auth/token/lookup-self",
        "ping.lookup-self",
    )
    .await;
    let c = client(&server);
    let closed = Arc::new(AtomicU32::new(0));
    let counter = closed.clone();
    c.on_close(move || {
        Box::pin(async move {
            counter.fetch_add(1, Ordering::SeqCst);
        })
    });
    assert!(!c.is_closed());
    c.ping().await.unwrap();
    c.close().await;
    c.close().await;
    assert!(c.is_closed());
    assert_eq!(closed.load(Ordering::SeqCst), 1);
    assert_eq!(c.ping().await.unwrap_err().code(), ErrorCode::Cancelled);
    assert!(c.transport().is_closed());
}

#[tokio::test]
async fn client_config_errors() {
    let err = Config::builder().url("mailto:x").build().unwrap_err();
    assert_eq!(err.code(), ErrorCode::Config);
    let cfg = Config::builder()
        .ca_cert_path("/nonexistent/ca.pem")
        .build()
        .unwrap();
    assert_eq!(Client::new(cfg).unwrap_err().code(), ErrorCode::Config);
    let _ = Client::from_env();
    assert_eq!(
        Config::builder().kv_version(3).build().unwrap_err().code(),
        ErrorCode::Config
    );
    assert_eq!(
        Config::builder()
            .namespace("a b")
            .build()
            .unwrap_err()
            .code(),
        ErrorCode::Config
    );
    assert_eq!(
        Config::builder()
            .value_field(" ")
            .build()
            .unwrap_err()
            .code(),
        ErrorCode::Config
    );
}

#[test]
fn config_from_env_vendor_variables() {
    let env = EnvReader::from_map([
        ("BAO_ADDR", "https://bao.example:8200"),
        ("VAULT_ADDR", "https://vault.example:8200"),
        ("VAULT_TOKEN", "vault-token-1"),
        ("VAULT_NAMESPACE", "team/a/"),
        ("VAULT_CACERT", "/etc/ca.pem"),
        ("BAO_CLIENT_CERT", "/etc/c.pem"),
        ("VAULT_CLIENT_KEY", "/etc/c.key"),
        ("BAO_SKIP_VERIFY", "true"),
        ("GROW_OPENBAO_KV_MOUNT", "/kv/"),
        ("GROW_OPENBAO_KV_VERSION", "1"),
        ("GROW_OPENBAO_SECRETS_PATH", "/apps/web/"),
    ]);
    let c = Config::builder().build_with_env(&env).unwrap();
    assert_eq!(c.url().as_str(), "https://bao.example:8200/");
    assert_eq!(c.token().unwrap().expose_secret(), "vault-token-1");
    assert_eq!(c.namespace(), Some("team/a"));
    assert_eq!(c.kv_mount(), "kv");
    assert_eq!(c.kv_version(), Some(1));
    assert_eq!(c.secrets_path(), "apps/web");
    assert_eq!(c.value_field(), "value");
    let tls = c.common().tls();
    assert_eq!(
        tls.ca_cert_path.as_deref(),
        Some(std::path::Path::new("/etc/ca.pem"))
    );
    assert_eq!(
        tls.client_cert_path.as_deref(),
        Some(std::path::Path::new("/etc/c.pem"))
    );
    assert_eq!(
        tls.client_key_path.as_deref(),
        Some(std::path::Path::new("/etc/c.key"))
    );
    assert!(tls.insecure_skip_verify);
    assert!(!format!("{c:?}").contains("vault-token-1"));

    // GROW_OPENBAO_* beats vendor variables; explicit beats both
    let env = EnvReader::from_map([
        ("GROW_OPENBAO_URL", "http://grow:1"),
        ("BAO_ADDR", "http://bao:1"),
        ("GROW_OPENBAO_TOKEN", "grow-token"),
        ("BAO_TOKEN", "bao-token"),
        ("GROW_OPENBAO_NAMESPACE", "grow-ns"),
        ("BAO_NAMESPACE", "bao-ns"),
        ("GROW_OPENBAO_CA_CERT", "/grow.pem"),
        ("BAO_CACERT", "/bao.pem"),
        ("GROW_OPENBAO_INSECURE_SKIP_VERIFY", "no"),
        ("BAO_SKIP_VERIFY", "yes"),
    ]);
    let c = Config::builder().build_with_env(&env).unwrap();
    assert_eq!(c.url().as_str(), "http://grow:1/");
    assert_eq!(c.token().unwrap().expose_secret(), "grow-token");
    assert_eq!(c.namespace(), Some("grow-ns"));
    assert_eq!(
        c.common().tls().ca_cert_path.as_deref(),
        Some(std::path::Path::new("/grow.pem"))
    );
    assert!(!c.common().tls().insecure_skip_verify);
    let c = Config::builder()
        .url("http://explicit:1")
        .namespace("explicit-ns")
        .kv_mount("explicit")
        .kv_version(2)
        .secrets_path("p")
        .value_field("v")
        .ca_cert_path("/explicit.pem")
        .client_cert("/x.pem", "/x.key")
        .insecure_skip_verify(true)
        .build_with_env(&env)
        .unwrap();
    assert_eq!(c.url().as_str(), "http://explicit:1/");
    assert_eq!(c.namespace(), Some("explicit-ns"));
    assert_eq!((c.kv_mount(), c.kv_version()), ("explicit", Some(2)));
    assert_eq!((c.secrets_path(), c.value_field()), ("p", "v"));
    assert!(c.common().tls().insecure_skip_verify);
    assert_eq!(
        c.common().tls().client_cert_path.as_deref(),
        Some(std::path::Path::new("/x.pem"))
    );

    // invalid values name the variable, never the value
    for (var, value) in [
        ("GROW_OPENBAO_KV_VERSION", "7"),
        ("GROW_OPENBAO_KV_VERSION", "x"),
        ("BAO_SKIP_VERIFY", "maybe"),
    ] {
        let env = EnvReader::from_map([(var, value)]);
        let err = Config::builder().build_with_env(&env).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Config, "{var}");
        assert!(err.message().contains("KV_VERSION") || err.message().contains("SKIP_VERIFY"));
        assert!(!err.message().contains("maybe"));
    }
    let env = EnvReader::from_map([("BAO_CLIENT_CERT", "/c.pem")]);
    assert_eq!(
        Config::builder().build_with_env(&env).unwrap_err().code(),
        ErrorCode::Config
    );
    // tls() via the builder also feeds the service fields; empty token = none
    let c = Config::builder()
        .tls(sdk::core::TlsConfig {
            ca_cert_path: Some("/t.pem".into()),
            client_cert_path: Some("/t.crt".into()),
            client_key_path: Some("/t.key".into()),
            ..Default::default()
        })
        .token("")
        .kv_version(0)
        .build()
        .unwrap();
    assert!(c.token().is_none());
    assert_eq!(c.kv_version(), None);
    assert_eq!(
        c.common().tls().ca_cert_path.as_deref(),
        Some(std::path::Path::new("/t.pem"))
    );
}

#[tokio::test]
async fn token_and_namespace_headers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/auth/token/lookup-self"))
        .and(header("x-vault-token", "new-token-5678"))
        .and(header("x-vault-namespace", "team-a"))
        .respond_with(reply("ping.lookup-self"))
        .mount(&server)
        .await;
    on(
        &server,
        "GET",
        "/v1/auth/token/lookup-self",
        "ping.invalid-token",
    )
    .await;
    let c = Client::new(builder(&server).namespace("/team-a/").build().unwrap()).unwrap();
    assert_eq!(
        c.ping().await.unwrap_err().code(),
        ErrorCode::Authentication
    );
    c.set_token(Some(Secret::new("new-token-5678")));
    assert_eq!(c.token().unwrap().expose_secret(), "new-token-5678");
    c.ping().await.unwrap();
    c.set_token(None);
    assert!(c.token().is_none());
    assert_eq!(
        c.ping().await.unwrap_err().code(),
        ErrorCode::Authentication
    );
    let reqs = requests(&server, "/v1/auth/token/lookup-self").await;
    assert!(reqs.last().unwrap().headers.get("x-vault-token").is_none());
    let ua = reqs[0].headers.get("user-agent").unwrap().to_str().unwrap();
    assert!(ua.starts_with("grow-codes-openbao/"), "{ua}");
}

#[tokio::test]
async fn kv_detection() {
    let server = MockServer::start().await;
    on(
        &server,
        "GET",
        "/v1/sys/internal/ui/mounts/kv1",
        "mountDetect.kv1",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/sys/internal/ui/mounts/secret",
        "mountDetect.kv2",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/sys/internal/ui/mounts/nope",
        "mountDetect.no-mount",
    )
    .await;
    on_reply(
        &server,
        "GET",
        "/v1/sys/internal/ui/mounts/transit",
        json(200, json!({"data": {"type": "transit"}})),
    )
    .await;
    let c = client(&server);
    assert_eq!(c.detect_kv_version("kv1").await.unwrap(), 1);
    assert_eq!(c.detect_kv_version("").await.unwrap(), 2);
    let kv = c.kv().await.unwrap();
    assert_eq!((kv.version(), kv.mount()), (2, "secret"));
    let kv = c.kv_at("/kv1/").await.unwrap();
    assert_eq!((kv.version(), kv.mount()), (1, "kv1"));
    // cached: a second detection makes no request
    c.kv_at("kv1").await.unwrap();
    assert_eq!(
        requests(&server, "/v1/sys/internal/ui/mounts/kv1")
            .await
            .len(),
        1
    );
    assert_eq!(
        c.kv_at("nope").await.unwrap_err().code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        c.detect_kv_version("transit").await.unwrap_err().code(),
        ErrorCode::Validation
    );
    // forced version: no detection request
    let forced = Client::new(
        builder(&server)
            .kv_version(1)
            .kv_mount("other")
            .build()
            .unwrap(),
    )
    .unwrap();
    let kv = forced.kv().await.unwrap();
    assert_eq!((kv.version(), kv.mount()), (1, "other"));
    assert_eq!(c.kv_v1().mount(), "secret");
    assert_eq!(c.kv_v2().at("x").mount(), "x");
    assert_eq!(c.kv_v1().at("").mount(), "secret");
}

#[tokio::test]
async fn module_accessors_and_mounts() {
    let server = MockServer::start().await;
    let c = client(&server);
    assert_eq!(c.transit().mount(), "transit");
    assert_eq!(c.transit().at("/t2/").mount(), "t2");
    assert_eq!(c.database().mount(), "database");
    assert_eq!(c.database().at("db2").mount(), "db2");
    assert_eq!(c.pki().mount(), "pki");
    assert_eq!(c.pki().at("pki_int").mount(), "pki_int");
    assert_eq!(c.secrets().mount(), "secret");
    assert!(format!("{:?}", c.auth()).contains("Auth"));
    assert!(format!("{:?}", c.sys()).contains("Sys"));
    assert!(format!("{:?}", c.wrapping()).contains("Wrapping"));
    assert!(format!("{:?}", c.lease_manager()).contains("LeaseManager"));
    assert_eq!(c.auth().client().config().kv_mount(), "secret");
}

#[tokio::test]
async fn retries_and_error_text_redaction() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/auth/token/lookup-self"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    on(
        &server,
        "GET",
        "/v1/auth/token/lookup-self",
        "ping.lookup-self",
    )
    .await;
    let c = Client::new(
        builder(&server)
            .retry(RetryPolicy {
                initial_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(2),
                ..RetryPolicy::default()
            })
            .build()
            .unwrap(),
    )
    .unwrap();
    c.ping().await.unwrap();
    assert_eq!(
        requests(&server, "/v1/auth/token/lookup-self").await.len(),
        2
    );

    // a vendor message echoing the token is redacted
    on_reply(
        &server,
        "GET",
        "/v1/sys/policies/acl/x",
        json(400, json!({"errors": [format!("bad token {TOKEN}")]})),
    )
    .await;
    let err = c.sys().read_policy("x").await.unwrap_err();
    assert!(!err.message().contains(TOKEN), "{}", err.message());
    assert!(err.message().contains("[REDACTED]"));
}
