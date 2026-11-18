//! Database engine (dynamic credentials, admin helpers) and the lease manager.

mod support;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use grow_openbao as sdk;
use sdk::core::ErrorCode;
use sdk::{DatabaseConnectionConfig, DatabaseRole, Lease, ManageOptions, Secret};
use serde_json::{json, Map};
use support::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn database_admin_and_credentials() {
    let server = MockServer::start().await;
    on(
        &server,
        "POST",
        "/v1/database/config/pg",
        "database.configureConnection.ok",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/database/config/bad",
        "database.configureConnection.bad-credentials",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/database/config/pg",
        "database.readConnection.ok",
    )
    .await;
    on(
        &server,
        "DELETE",
        "/v1/database/config/pg",
        "database.deleteConnection.ok",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/database/roles/ro",
        "database.createRole.ok",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/database/roles/ro",
        "database.readRole.ok",
    )
    .await;
    on(
        &server,
        "DELETE",
        "/v1/database/roles/ro",
        "database.deleteRole.ok",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/database/creds/ro",
        "database.getCredentials.ok",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/database/creds/nope",
        "database.getCredentials.unknown-role",
    )
    .await;
    let c = client(&server);
    let db = c.database();
    let mut extra = Map::new();
    extra.insert("max_open_connections".into(), json!(4));
    let cfg = DatabaseConnectionConfig {
        plugin_name: "postgresql-database-plugin".into(),
        connection_url: "postgresql://{{username}}:{{password}}@pg:5432/app".into(),
        username: Some("postgres".into()),
        password: Some(Secret::new("pg-admin-pw-1")),
        allowed_roles: vec!["ro".into()],
        verify_connection: Some(true),
        extra,
    };
    assert!(!format!("{cfg:?}").contains("pg-admin-pw-1"));
    db.configure_connection("pg", &cfg).await.unwrap();
    assert_eq!(
        sent(&server, "/v1/database/config/pg").await[0],
        json!({"plugin_name": "postgresql-database-plugin",
               "connection_url": "postgresql://{{username}}:{{password}}@pg:5432/app",
               "username": "postgres", "password": "pg-admin-pw-1", "allowed_roles": ["ro"],
               "verify_connection": true, "max_open_connections": 4})
    );
    let err = db.configure_connection("bad", &cfg).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    assert!(!err.message().contains("pg-admin-pw-1"));
    let conn = db.read_connection("pg").await.unwrap();
    assert_eq!(conn["plugin_name"], "postgresql-database-plugin");
    db.delete_connection("pg").await.unwrap();

    let role = DatabaseRole {
        db_name: "pg".into(),
        creation_statements: vec!["CREATE ROLE \"{{name}}\"".into()],
        revocation_statements: vec!["DROP ROLE \"{{name}}\"".into()],
        rollback_statements: vec!["R".into()],
        renew_statements: vec!["N".into()],
        default_ttl: Some(Duration::from_secs(3600)),
        max_ttl: Some(Duration::from_secs(7200)),
    };
    db.create_role("ro", &role).await.unwrap();
    assert_eq!(
        sent(&server, "/v1/database/roles/ro").await[0],
        json!({"db_name": "pg", "creation_statements": ["CREATE ROLE \"{{name}}\""],
               "revocation_statements": ["DROP ROLE \"{{name}}\""], "rollback_statements": ["R"],
               "renew_statements": ["N"], "default_ttl": "3600s", "max_ttl": "7200s"})
    );
    let r = db.read_role("ro").await.unwrap();
    assert_eq!(r.default_ttl, Some(Duration::from_secs(3600)));
    assert_eq!(r.max_ttl, Some(Duration::from_secs(7200)));
    assert_eq!(r.db_name, "pg-f43633d7");
    assert!(!r.creation_statements.is_empty());
    db.delete_role("ro").await.unwrap();

    let lease = db.get_credentials("ro").await.unwrap();
    assert!(lease.id.starts_with("database/creds/ro-"));
    assert!(lease.renewable);
    assert_eq!(lease.duration, Duration::from_secs(3600));
    assert!(lease.username.as_deref().unwrap().starts_with("v-root-ro"));
    assert!(lease.password.is_some());
    assert!(!lease.data.contains_key("password"));
    assert!(lease.expires_at().is_some());
    assert!(format!("{lease:?}").contains("[REDACTED]"));
    let err = db.get_credentials("nope").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    assert!(err.message().contains("unknown role"));
    for e in [
        db.get_credentials("").await.unwrap_err(),
        db.create_role("", &role).await.unwrap_err(),
        db.configure_connection("", &cfg).await.unwrap_err(),
    ] {
        assert_eq!(e.code(), ErrorCode::Validation);
    }
}

#[tokio::test]
async fn lease_renew_revoke_lookup() {
    let server = MockServer::start().await;
    once(&server, "PUT", "/v1/sys/leases/renew", "leases.renew.ok").await;
    once(
        &server,
        "PUT",
        "/v1/sys/leases/renew",
        "leases.renew.capped",
    )
    .await;
    on(
        &server,
        "PUT",
        "/v1/sys/leases/renew",
        "leases.renew.not-found",
    )
    .await;
    on(&server, "PUT", "/v1/sys/leases/revoke", "leases.revoke.ok").await;
    on(
        &server,
        "PUT",
        "/v1/sys/leases/revoke-prefix/database/creds/sdk-short",
        "leases.revokePrefix.ok",
    )
    .await;
    once(&server, "PUT", "/v1/sys/leases/lookup", "leases.lookup.ok").await;
    on(
        &server,
        "PUT",
        "/v1/sys/leases/lookup",
        "leases.lookup.revoked",
    )
    .await;
    let c = client(&server);
    let m = c.lease_manager();
    let id = "database/creds/ro/abc";
    let info = m.renew(id, Some(Duration::from_secs(600))).await.unwrap();
    assert!(info.renewable && !info.capped());
    assert_eq!(
        sent(&server, "/v1/sys/leases/renew").await[0],
        json!({"lease_id": id, "increment": 600})
    );
    let capped = m.renew(id, Some(Duration::from_millis(10))).await.unwrap();
    assert!(capped.capped());
    assert_eq!(capped.duration, Duration::from_secs(7200));
    assert_eq!(
        sent(&server, "/v1/sys/leases/renew").await[1]["increment"],
        1
    );
    let err = m.renew(id, None).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    assert!(err.message().contains("lease not found"));
    m.revoke(id).await.unwrap();
    m.revoke_prefix("database/creds/sdk-short").await.unwrap();
    let l = m.lookup(id).await.unwrap();
    assert!(l.id.starts_with("database/creds/"));
    assert!(l.renewable && l.issue_time.is_some() && l.expire_time.is_some());
    assert!(l.last_renewal.is_none());
    assert_eq!(l.ttl, Duration::from_secs(3599));
    assert_eq!(
        m.lookup(id).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    for e in [
        m.renew("", None).await.unwrap_err(),
        m.revoke("").await.unwrap_err(),
        m.revoke_prefix("").await.unwrap_err(),
        m.lookup("").await.unwrap_err(),
    ] {
        assert_eq!(e.code(), ErrorCode::Validation);
    }
    // an empty lease id in the response falls back to the requested one
    let server = MockServer::start().await;
    on_reply(
        &server,
        "PUT",
        "/v1/sys/leases/renew",
        json(200, json!({"lease_duration": 5, "renewable": true})),
    )
    .await;
    let m = client(&server).lease_manager();
    assert_eq!(m.renew("given-id", None).await.unwrap().id, "given-id");
}

fn lease(id: &str, secs: u64, renewable: bool) -> Lease {
    Lease {
        id: id.into(),
        renewable,
        duration: Duration::from_secs(secs),
        issued_at: tokio::time::Instant::now(),
        username: None,
        password: None,
        data: Map::new(),
        warnings: Vec::new(),
    }
}

fn renewed(secs: u64, renewable: bool, warnings: &[&str]) -> ResponseTemplate {
    json(
        200,
        json!({"lease_id": "l1", "lease_duration": secs, "renewable": renewable, "warnings": warnings}),
    )
}

fn counters() -> (
    Arc<AtomicU32>,
    Arc<AtomicU32>,
    Arc<AtomicU32>,
    ManageOptions,
) {
    let (r, e, x) = (
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
    );
    let (r1, e1, x1) = (r.clone(), e.clone(), x.clone());
    let opts = ManageOptions {
        increment: None,
        on_renew: Some(Arc::new(move |_| {
            r1.fetch_add(1, Ordering::SeqCst);
        })),
        on_error: Some(Arc::new(move |_| {
            e1.fetch_add(1, Ordering::SeqCst);
        })),
        on_expire: Some(Arc::new(move |_| {
            x1.fetch_add(1, Ordering::SeqCst);
            panic!("contained");
        })),
    };
    (r, e, x, opts)
}

#[tokio::test]
async fn managed_lease_renews_until_capped_then_expires_once() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/v1/sys/leases/renew"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/v1/sys/leases/renew"))
        .respond_with(renewed(1, true, &[]))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    on_reply(
        &server,
        "PUT",
        "/v1/sys/leases/renew",
        renewed(1, true, &["TTL value is capped accordingly"]),
    )
    .await;
    let c = client(&server);
    let (renews, errors, expired, opts) = counters();
    let ml = c.lease_manager().manage(lease("l1", 1, true), opts);
    assert_eq!(ml.lease().id, "l1");
    assert!(format!("{ml:?}").contains("l1"));
    assert!(format!("{:?}", ManageOptions::default()).contains("increment"));
    tokio::time::timeout(Duration::from_secs(10), ml.done())
        .await
        .expect("managed lease ends");
    assert_eq!(errors.load(Ordering::SeqCst), 1);
    assert_eq!(renews.load(Ordering::SeqCst), 2);
    assert_eq!(expired.load(Ordering::SeqCst), 1);
    assert!(ml.is_stopped());
}

#[tokio::test]
async fn managed_lease_rejected_increment_capped_and_close() {
    // rejected renewal (non-retryable): on_expire at once
    let server = MockServer::start().await;
    on(
        &server,
        "PUT",
        "/v1/sys/leases/renew",
        "leases.renew.not-found",
    )
    .await;
    let c = client(&server);
    let (_r, errors, expired, opts) = counters();
    let ml = c.lease_manager().manage(lease("l1", 1, true), opts);
    tokio::time::timeout(Duration::from_secs(10), ml.done())
        .await
        .unwrap();
    assert_eq!(
        (
            errors.load(Ordering::SeqCst),
            expired.load(Ordering::SeqCst)
        ),
        (1, 1)
    );

    // granted less than the increment: capped, then expires
    let server = MockServer::start().await;
    on_reply(
        &server,
        "PUT",
        "/v1/sys/leases/renew",
        renewed(1, true, &[]),
    )
    .await;
    let c = client(&server);
    let (renews, _e, expired, mut opts) = counters();
    opts.increment = Some(Duration::from_secs(60));
    let ml = c.lease_manager().manage(lease("l1", 1, true), opts);
    tokio::time::timeout(Duration::from_secs(10), ml.done())
        .await
        .unwrap();
    assert_eq!(
        (
            renews.load(Ordering::SeqCst),
            expired.load(Ordering::SeqCst)
        ),
        (1, 1)
    );

    // a non-renewable lease just expires; a lease without TTL waits for close
    let (renews, _e, expired, opts) = counters();
    let ml = c
        .lease_manager()
        .manage(lease("l2", 1, false), opts.clone());
    tokio::time::timeout(Duration::from_secs(10), ml.done())
        .await
        .unwrap();
    assert_eq!(
        (
            renews.load(Ordering::SeqCst),
            expired.load(Ordering::SeqCst)
        ),
        (0, 1)
    );
    let forever = c.lease_manager().manage(lease("l3", 0, true), opts.clone());
    let long = c.lease_manager().manage(lease("l4", 3600, true), opts);
    let stopped = c
        .lease_manager()
        .manage(lease("l5", 3600, true), ManageOptions::default());
    stopped.stop();
    tokio::time::timeout(Duration::from_secs(5), stopped.done())
        .await
        .unwrap();
    assert!(!forever.is_stopped());
    c.close().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        forever.done().await;
        long.done().await;
    })
    .await
    .expect("close stops managed leases");
    assert!(forever.is_stopped() && long.is_stopped());
    assert_eq!(expired.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn managed_lease_retryable_error_until_expiry() {
    let server = MockServer::start().await;
    on_reply(
        &server,
        "PUT",
        "/v1/sys/leases/renew",
        ResponseTemplate::new(503),
    )
    .await;
    let c = client(&server);
    let (_r, errors, expired, opts) = counters();
    let ml = c.lease_manager().manage(lease("l1", 1, true), opts);
    tokio::time::timeout(Duration::from_secs(10), ml.done())
        .await
        .unwrap();
    assert!(errors.load(Ordering::SeqCst) >= 2);
    assert_eq!(expired.load(Ordering::SeqCst), 1);
}
