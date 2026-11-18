//! System/admin module, response wrapping and the testing `operator` helpers.

mod support;

use std::collections::BTreeMap;
use std::time::Duration;

use grow_openbao as sdk;
use sdk::core::ErrorCode;
use sdk::{AppRoleOptions, MountOptions, SecretIdOptions};
use serde_json::json;
use support::*;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer};

#[tokio::test]
async fn seal_status_and_leader() {
    let server = MockServer::start().await;
    on(&server, "GET", "/v1/sys/seal-status", "sealStatus.unsealed").await;
    on(&server, "GET", "/v1/sys/leader", "leader.active").await;
    let c = client(&server);
    let s = c.sys().seal_status().await.unwrap();
    assert_eq!(s.seal_type, "static");
    assert!(s.initialized && !s.sealed && s.recovery_seal);
    assert_eq!((s.t, s.n, s.progress), (1, 1, 0));
    assert_eq!(s.version, "2.7.2");
    assert_eq!(s.storage_type, "raft");
    assert!(!s.cluster_id.is_empty() && !s.cluster_name.is_empty() && !s.commit_date.is_empty());
    let l = c.sys().leader().await.unwrap();
    assert!(l.ha_enabled && l.is_self);
    assert_eq!(l.leader_address, "http://openbao:8200");
    assert_eq!(l.raft_committed_index, 108);
    assert!(l.active_time.is_some());
    assert!(!l.leader_cluster_address.is_empty());
    assert_eq!(l.raft_applied_index, 108);
    let r = requests(&server, "/v1/sys/seal-status").await;
    assert!(r[0].headers.get("x-vault-token").is_none());
}

#[tokio::test]
async fn policies() {
    let server = MockServer::start().await;
    on(
        &server,
        "PUT",
        "/v1/sys/policies/acl/p1",
        "admin.writePolicy.ok",
    )
    .await;
    on(
        &server,
        "PUT",
        "/v1/sys/policies/acl/bad",
        "admin.writePolicy.invalid",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/sys/policies/acl/p1",
        "admin.readPolicy.ok",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/sys/policies/acl/missing",
        "admin.readPolicy.not-found",
    )
    .await;
    on_list(&server, "/v1/sys/policies/acl", "admin.listPolicies.ok").await;
    on(
        &server,
        "DELETE",
        "/v1/sys/policies/acl/p1",
        "admin.deletePolicy.ok",
    )
    .await;
    let c = client(&server);
    let sys = c.sys();
    let hcl = "path \"secret/*\" { capabilities = [\"read\"] }";
    sys.write_policy("p1", hcl).await.unwrap();
    assert_eq!(
        sent(&server, "/v1/sys/policies/acl/p1").await[0],
        json!({"policy": hcl})
    );
    assert_eq!(
        sys.write_policy("bad", "nope {").await.unwrap_err().code(),
        ErrorCode::Validation
    );
    let p = sys.read_policy("p1").await.unwrap();
    assert_eq!(p.name, "sdk-tmp-f43633d7");
    assert!(p.policy.contains("capabilities"));
    assert_eq!(
        sys.read_policy("missing").await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    let names = sys.list_policies().await.unwrap();
    assert!(names.contains(&"default".to_owned()) && names.contains(&"root".to_owned()));
    sys.delete_policy("p1").await.unwrap();
    for e in [
        sys.write_policy("", "x").await.unwrap_err(),
        sys.read_policy("").await.unwrap_err(),
        sys.delete_policy("").await.unwrap_err(),
    ] {
        assert_eq!(e.code(), ErrorCode::Validation);
    }
}

#[tokio::test]
async fn mounts_and_auth_methods() {
    let server = MockServer::start().await;
    on(&server, "GET", "/v1/sys/mounts", "admin.listMounts.ok").await;
    on(&server, "GET", "/v1/sys/auth", "admin.listAuthMethods.ok").await;
    once(
        &server,
        "POST",
        "/v1/sys/mounts/tmp",
        "admin.enableSecretsEngine.ok",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/sys/mounts/tmp",
        "admin.enableSecretsEngine.conflict",
    )
    .await;
    on(
        &server,
        "DELETE",
        "/v1/sys/mounts/tmp",
        "admin.disableSecretsEngine.ok",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/sys/auth/ar",
        "admin.enableAuthMethod.ok",
    )
    .await;
    on(
        &server,
        "DELETE",
        "/v1/sys/auth/ar",
        "admin.disableAuthMethod.ok",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/sys/internal/ui/mounts/tmp",
        "mountDetect.kv1",
    )
    .await;
    let c = client(&server);
    let sys = c.sys();
    let mounts = sys.list_mounts().await.unwrap();
    assert_eq!(mounts["secret/"].mount_type, "kv");
    assert_eq!(mounts["secret/"].options["version"], "2");
    assert!(mounts.contains_key("transit/") && mounts.contains_key("sys/"));
    assert!(!mounts["secret/"].uuid.is_empty());
    let auths = sys.list_auth_methods().await.unwrap();
    assert_eq!(auths["approle/"].mount_type, "approle");
    assert!(auths.contains_key("token/"));

    // detection is cached, enabling or disabling a mount forgets it
    assert_eq!(c.detect_kv_version("tmp").await.unwrap(), 1);
    let opts = MountOptions {
        description: Some("tmp kv".into()),
        options: BTreeMap::from([("version".to_owned(), "2".to_owned())]),
        default_lease_ttl: Some(Duration::from_secs(60)),
        max_lease_ttl: Some(Duration::from_secs(120)),
        local: true,
        seal_wrap: true,
    };
    sys.enable_secrets_engine("/tmp/", "kv", Some(&opts))
        .await
        .unwrap();
    assert_eq!(
        sent(&server, "/v1/sys/mounts/tmp").await[0],
        json!({"type": "kv", "description": "tmp kv", "options": {"version": "2"},
               "config": {"default_lease_ttl": "60s", "max_lease_ttl": "120s"}, "local": true, "seal_wrap": true})
    );
    c.kv_at("tmp").await.unwrap();
    assert_eq!(
        requests(&server, "/v1/sys/internal/ui/mounts/tmp")
            .await
            .len(),
        2
    );
    let err = sys
        .enable_secrets_engine("tmp", "kv", None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    assert!(err.message().contains("already in use"));
    assert_eq!(
        sent(&server, "/v1/sys/mounts/tmp").await[1],
        json!({"type": "kv"})
    );
    sys.disable_secrets_engine("tmp").await.unwrap();
    sys.enable_auth_method("ar", "approle", None).await.unwrap();
    sys.disable_auth_method("ar").await.unwrap();
    for e in [
        sys.enable_secrets_engine("", "kv", None).await.unwrap_err(),
        sys.enable_secrets_engine("x", "", None).await.unwrap_err(),
        sys.disable_secrets_engine("/").await.unwrap_err(),
        sys.enable_auth_method("x", "", None).await.unwrap_err(),
        sys.enable_auth_method("", "approle", None)
            .await
            .unwrap_err(),
        sys.disable_auth_method("").await.unwrap_err(),
    ] {
        assert_eq!(e.code(), ErrorCode::Validation);
    }
    // a restricted token cannot list mounts; an odd body is an empty map
    let server = MockServer::start().await;
    on(
        &server,
        "GET",
        "/v1/sys/mounts",
        "admin.listMounts.permission-denied",
    )
    .await;
    on_reply(
        &server,
        "GET",
        "/v1/sys/auth",
        json(200, json!({"data": "x"})),
    )
    .await;
    let c = client(&server);
    assert_eq!(
        c.sys().list_mounts().await.unwrap_err().code(),
        ErrorCode::PermissionDenied
    );
    assert!(c.sys().list_auth_methods().await.unwrap().is_empty());
}

#[tokio::test]
async fn approle_admin() {
    let server = MockServer::start().await;
    on(
        &server,
        "POST",
        "/v1/auth/ar/role/r1",
        "admin.createAppRole.ok",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/auth/approle/role/r1",
        "admin.createAppRole.ok",
    )
    .await;
    on_reply(
        &server,
        "GET",
        "/v1/auth/approle/role",
        json(200, json!({"data": {"keys": ["zeta", "alpha"]}})),
    )
    .await;
    on_list(&server, "/v1/auth/ar/role", "admin.listAppRoles.ok").await;
    on(
        &server,
        "DELETE",
        "/v1/auth/approle/role/r1",
        "admin.deletePolicy.ok",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/auth/ar/role/r1/role-id",
        "admin.readRoleId.ok",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/auth/approle/role/missing/role-id",
        "admin.readRoleId.not-found",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/auth/ar/role/r1/secret-id",
        "admin.generateSecretId.ok",
    )
    .await;
    let c = client(&server);
    let sys = c.sys();
    let opts = AppRoleOptions {
        mount: Some("ar".into()),
        token_policies: vec!["sdk-app".into()],
        token_ttl: Some(Duration::from_secs(3600)),
        token_max_ttl: Some(Duration::from_secs(7200)),
        token_num_uses: 2,
        token_type: Some("service".into()),
        secret_id_ttl: Some(Duration::from_secs(600)),
        secret_id_num_uses: 1,
        bind_secret_id: Some(true),
    };
    sys.create_app_role("r1", &opts).await.unwrap();
    assert_eq!(
        sent(&server, "/v1/auth/ar/role/r1").await[0],
        json!({"token_policies": ["sdk-app"], "token_ttl": "3600s", "token_max_ttl": "7200s",
               "secret_id_ttl": "600s", "token_num_uses": 2, "token_type": "service",
               "secret_id_num_uses": 1, "bind_secret_id": true})
    );
    sys.create_app_role("r1", &AppRoleOptions::default())
        .await
        .unwrap();
    assert_eq!(
        sys.list_app_roles(None).await.unwrap(),
        vec!["alpha", "zeta"]
    );
    assert_eq!(sys.list_app_roles(Some("ar")).await.unwrap(), vec!["r1"]);
    sys.delete_app_role("r1", None).await.unwrap();
    let id = sys.read_role_id("r1", Some("ar")).await.unwrap();
    assert_eq!(id, "0a235ec1-2d7d-fd7a-8b4f-8a684196312e");
    assert_eq!(
        sys.read_role_id("missing", None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    let sid = sys
        .generate_secret_id(
            "r1",
            &SecretIdOptions {
                mount: Some("ar".into()),
                metadata: BTreeMap::from([("purpose".to_owned(), "sdk".to_owned())]),
                ttl: Some(Duration::from_secs(60)),
                num_uses: 1,
                cidr_list: vec!["10.0.0.0/8".into()],
            },
        )
        .await
        .unwrap();
    assert_eq!(sid.num_uses, 1);
    assert_eq!(sid.ttl, Duration::ZERO);
    assert!(!sid.secret_id.is_empty());
    assert!(format!("{sid:?}").contains("[REDACTED]"));
    assert_eq!(
        sent(&server, "/v1/auth/ar/role/r1/secret-id").await[0],
        json!({"metadata": "{\"purpose\":\"sdk\"}", "ttl": "60s", "num_uses": 1, "cidr_list": ["10.0.0.0/8"]})
    );
    for e in [
        sys.create_app_role("", &opts).await.unwrap_err(),
        sys.delete_app_role("", None).await.unwrap_err(),
        sys.read_role_id("", None).await.unwrap_err(),
        sys.generate_secret_id("", &SecretIdOptions::default())
            .await
            .unwrap_err(),
    ] {
        assert_eq!(e.code(), ErrorCode::Validation);
    }
}

#[tokio::test]
async fn wrap_lookup_unwrap() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/wrap"))
        .and(header("x-vault-wrap-ttl", "60s"))
        .respond_with(reply("wrapping.wrap.ok"))
        .mount(&server)
        .await;
    on(
        &server,
        "POST",
        "/v1/sys/wrapping/wrap",
        "wrapping.wrap.missing-ttl",
    )
    .await;
    once(
        &server,
        "POST",
        "/v1/sys/wrapping/lookup",
        "wrapping.lookupWrapping.ok",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/sys/wrapping/lookup",
        "wrapping.lookupWrapping.used",
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/unwrap"))
        .and(header("x-vault-token", "wrap-token-1"))
        .respond_with(reply("wrapping.unwrap.ok"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    on(
        &server,
        "POST",
        "/v1/sys/wrapping/unwrap",
        "wrapping.unwrap.already-used",
    )
    .await;
    let c = client(&server);
    let w = c.wrapping();
    let info = w
        .wrap(
            json!({"secret": "wrapped", "n": 1}),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert_eq!(info.ttl, Duration::from_secs(60));
    assert_eq!(info.creation_path, "sys/wrapping/wrap");
    assert!(info.creation_time.is_some() && !info.token.is_empty());
    assert!(format!("{info:?}").contains("token: [REDACTED]"));
    assert_eq!(
        sent(&server, "/v1/sys/wrapping/wrap").await[0],
        json!({"secret": "wrapped", "n": 1})
    );
    let l = w.lookup_wrapping("wrap-token-1").await.unwrap();
    assert_eq!(l.creation_path, "sys/wrapping/wrap");
    assert_eq!(l.creation_ttl, Duration::from_secs(60));
    assert!(l.creation_time.is_some());
    let r = w.unwrap("wrap-token-1").await.unwrap();
    assert_eq!(r.data["secret"], "wrapped-f43633d7");
    assert!(r.auth.is_none() && r.wrap_info.is_none());
    assert!(!r.request_id.is_empty());
    assert!(!format!("{r:?}").contains("wrapped-f43633d7"));
    let err = w.unwrap("wrap-token-1").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    assert!(!err.message().contains("wrap-token-1"));
    assert_eq!(
        w.lookup_wrapping("wrap-token-1").await.unwrap_err().code(),
        ErrorCode::Validation
    );
    w.wrap(serde_json::Value::Null, Duration::from_millis(1))
        .await
        .unwrap_err();
    for e in [
        w.wrap(json!({}), Duration::ZERO).await.unwrap_err(),
        w.wrap(json!([1]), Duration::from_secs(1))
            .await
            .unwrap_err(),
        w.unwrap("").await.unwrap_err(),
        w.lookup_wrapping("").await.unwrap_err(),
    ] {
        assert_eq!(e.code(), ErrorCode::Validation);
    }
    // a wrapped login response carries auth; a wrap answer without wrap_info is an error
    let server = MockServer::start().await;
    on_reply(
        &server,
        "POST",
        "/v1/sys/wrapping/unwrap",
        json(200, json!({"auth": {"client_token": "child-token-1", "lease_duration": 60}, "wrap_info": {"token": "inner-wrap", "ttl": 5}})),
    )
    .await;
    on_reply(
        &server,
        "POST",
        "/v1/sys/wrapping/wrap",
        json(200, json!({"data": null})),
    )
    .await;
    let w = client(&server).wrapping();
    let r = w.unwrap("t-1234").await.unwrap();
    assert_eq!(r.auth.unwrap().lease_duration, Duration::from_secs(60));
    assert_eq!(r.wrap_info.unwrap().ttl, Duration::from_secs(5));
    assert_eq!(
        w.wrap(json!({}), Duration::from_secs(1))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Unavailable
    );
}

#[cfg(feature = "testing")]
#[tokio::test]
async fn operator_init_unseal_seal() {
    use sdk::operator::{self, InitOptions};
    let server = MockServer::start().await;
    on(&server, "GET", "/v1/sys/init", "init.status").await;
    once(&server, "PUT", "/v1/sys/init", "init.shamir").await;
    on(&server, "PUT", "/v1/sys/init", "init.already-initialized").await;
    once(&server, "PUT", "/v1/sys/unseal", "unseal.ok").await;
    on(&server, "PUT", "/v1/sys/unseal", "unseal.invalid-key").await;
    on(&server, "PUT", "/v1/sys/seal", "seal.testing").await;
    on(&server, "GET", "/v1/sys/health", "health.active").await;
    let c = client(&server);
    assert!(!operator::init_status(&c).await.unwrap());
    let init = operator::init(&c, &InitOptions::default()).await.unwrap();
    assert_eq!((init.keys.len(), init.keys_base64.len()), (1, 1));
    assert!(init.recovery_keys.is_empty() && init.recovery_keys_base64.is_empty());
    assert!(!init.root_token.is_empty());
    assert!(!format!("{init:?}").contains("<redacted>"));
    assert_eq!(
        sent(&server, "/v1/sys/init").await[0],
        json!({"secret_shares": 1, "secret_threshold": 1})
    );
    let err = operator::init(
        &c,
        &InitOptions {
            recovery_shares: Some(3),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    assert!(err.message().contains("already initialized"));
    assert_eq!(
        sent(&server, "/v1/sys/init").await[1],
        json!({"recovery_shares": 3, "recovery_threshold": 1})
    );
    let st = operator::unseal(&c, "abcd1234").await.unwrap();
    assert!(!st.sealed && st.initialized);
    assert_eq!(st.seal_type, "shamir");
    assert_eq!(
        operator::unseal(&c, "zz").await.unwrap_err().code(),
        ErrorCode::Validation
    );
    assert_eq!(
        operator::unseal(&c, "").await.unwrap_err().code(),
        ErrorCode::Validation
    );
    let _ = operator::unseal_reset(&c).await;
    assert_eq!(
        sent(&server, "/v1/sys/unseal").await.last().unwrap(),
        &json!({"reset": true})
    );
    operator::seal(&c).await.unwrap();
    let h = operator::wait_for_active(&c, Duration::from_secs(5))
        .await
        .unwrap();
    assert!(h.healthy);

    // never active: TIMEOUT; no root token: UNAVAILABLE
    let server = MockServer::start().await;
    on(&server, "GET", "/v1/sys/health", "health.sealed").await;
    on_reply(
        &server,
        "PUT",
        "/v1/sys/init",
        json(200, json!({"keys": []})),
    )
    .await;
    let c = client(&server);
    assert_eq!(
        operator::wait_for_active(&c, Duration::from_millis(300))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Timeout
    );
    assert_eq!(
        operator::init(&c, &InitOptions::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Unavailable
    );
}
