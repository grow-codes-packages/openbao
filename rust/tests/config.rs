//! `OpenBaoConfig`: environment, builder setters and redaction of the service config (the
//! generated `core_config.rs` covers only the common config).

use std::sync::Arc;
use std::time::Duration;

use grow_openbao as sdk;
use sdk::core::env::ENV_PREFIX;
use sdk::core::{EnvReader, Hooks, RetryPolicy, TlsConfig};
use sdk::DEFAULT_URL;

use sdk::OpenBaoConfig as Config;

fn var(name: &str) -> String {
    format!("{ENV_PREFIX}{name}")
}

#[test]
fn service_config_from_env() {
    let env = EnvReader::from_map([
        (var("URL"), "https://svc.example:8443"),
        (var("TOKEN"), "tok-from-env"),
    ]);
    let c = Config::builder().build_with_env(&env).unwrap();
    assert_eq!(c.url().as_str(), "https://svc.example:8443/");
    assert_eq!(c.token().unwrap().expose_secret(), "tok-from-env");
    let c = Config::builder()
        .token("explicit")
        .build_with_env(&env)
        .unwrap();
    assert_eq!(c.token().unwrap().expose_secret(), "explicit");
    let c = Config::builder().build().unwrap();
    assert_eq!(c.url().as_str(), format!("{DEFAULT_URL}/"));
    assert!(c.token().is_none());
    assert!(c.validate().is_ok());
    // the process-environment entry points work (values depend on the environment)
    let _ = Config::from_env();
    let _ = Config::builder().build_from_env();
}

#[test]
fn service_config_builder_setters() {
    struct NoHooks;
    impl Hooks for NoHooks {}
    let c = Config::builder()
        .url("http://h:1/base")
        .connect_timeout(Duration::from_secs(1))
        .request_timeout(Duration::from_secs(2))
        .total_timeout(Duration::from_secs(3))
        .retry(RetryPolicy::none())
        .max_retries(2)
        .tls(TlsConfig {
            insecure_skip_verify: true,
            ..TlsConfig::default()
        })
        .ca_cert_path("/ca.pem")
        .insecure_skip_verify(true)
        .proxy("http://p:1")
        .header("x-a", "b")
        .user_agent_suffix("app/1")
        .hooks(Arc::new(NoHooks))
        .common(|b| b.ca_cert_pem("pem"))
        .build()
        .unwrap();
    let common = c.common();
    assert_eq!(common.connect_timeout(), Duration::from_secs(1));
    assert_eq!(common.request_timeout(), Duration::from_secs(2));
    assert_eq!(common.total_timeout(), Duration::from_secs(3));
    assert_eq!(common.retry().max_retries, 2);
    assert!(common.tls().insecure_skip_verify);
    assert_eq!(common.tls().ca_cert_pem.as_deref(), Some("pem"));
    assert_eq!(common.headers(), &[("x-a".to_owned(), "b".to_owned())]);
    assert_eq!(common.user_agent_suffix(), Some("app/1"));
    assert!(common.hooks().is_some());
}

#[test]
fn service_config_redaction() {
    let c = Config::builder()
        .url("https://user:url-password-1@svc.example/?token=query-token-1&x=1")
        .token("config-token-secret-1")
        .header("Authorization", "Bearer header-token-1")
        .header("x-trace", "visible-value")
        .proxy("http://puser:proxy-password-1@proxy:3128")
        .build()
        .unwrap();
    let text = format!("{c:?} {:?}", c.common());
    for secret in [
        "url-password-1",
        "query-token-1",
        "config-token-secret-1",
        "header-token-1",
        "proxy-password-1",
    ] {
        assert!(!text.contains(secret), "{secret} leaked: {text}");
    }
    assert!(text.contains("visible-value"));
    assert!(text.contains("[REDACTED]"));
    assert!(format!("{:?}", Config::builder().token("t-builder-1")).contains("[REDACTED]"));
}
