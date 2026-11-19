//! `KvSecretsProvider`: the SPEC §3 secrets provider over KV v1 and v2.

mod support;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use grow_openbao as sdk;
use sdk::core::ErrorCode;
use sdk::secrets::{
    DeleteOptions, GetOptions, SecretData, SecretsProvider, SetOptions, WatchOptions,
};
use sdk::{OpenBaoClient, SecretsProviderOptions};
use serde_json::json;
use support::*;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn kv2_read(data: serde_json::Value, version: u64) -> ResponseTemplate {
    json(
        200,
        json!({"data": {"data": data, "metadata": {"version": version, "created_time": "2026-11-18T20:28:54Z", "deletion_time": "", "destroyed": false}}}),
    )
}

fn metadata(current: u64, deleted: bool) -> ResponseTemplate {
    json(
        200,
        json!({"data": {
            "cas_required": false, "created_time": "2026-11-18T20:28:54Z",
            "updated_time": "2026-11-18T20:29:54Z", "current_version": current,
            "oldest_version": 0, "max_versions": 0, "delete_version_after": "0s",
            "custom_metadata": {"owner": "sdk"},
            "versions": {current.to_string(): {"created_time": "2026-11-18T20:28:54Z",
                "deletion_time": if deleted { "2026-11-18T20:30:00Z" } else { "" }, "destroyed": false}}
        }}),
    )
}

fn v2(server: &MockServer) -> (OpenBaoClient, sdk::KvSecretsProvider) {
    let c = Client::new(builder(server).secrets_path("apps/web").build().unwrap()).unwrap();
    let p = c.secrets_with(SecretsProviderOptions {
        kv_version: Some(2),
        ..Default::default()
    });
    (c, p)
}

use sdk::OpenBaoClient as Client;

#[tokio::test]
async fn get_variants() {
    let server = MockServer::start().await;
    let base = "/v1/secret/data/apps/web";
    on_reply(
        &server,
        "GET",
        &format!("{base}/text"),
        kv2_read(json!({"value": "hello"}), 3),
    )
    .await;
    on_reply(
        &server,
        "GET",
        &format!("{base}/bin"),
        kv2_read(json!({"value": "AP8=", "encoding": "base64"}), 1),
    )
    .await;
    on_reply(
        &server,
        "GET",
        &format!("{base}/bad64"),
        kv2_read(json!({"value": "!!", "encoding": "base64"}), 1),
    )
    .await;
    on_reply(
        &server,
        "GET",
        &format!("{base}/multi"),
        kv2_read(json!({"a": "1", "b": 2}), 1),
    )
    .await;
    on_reply(
        &server,
        "GET",
        &format!("{base}/num"),
        kv2_read(json!({"value": 42}), 1),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/text")))
        .and(query_param("version", "2"))
        .respond_with(kv2_read(json!({"value": "older"}), 2))
        .with_priority(1)
        .mount(&server)
        .await;
    on(
        &server,
        "GET",
        &format!("{base}/missing"),
        "kvV2.read.not-found",
    )
    .await;
    on(
        &server,
        "GET",
        &format!("{base}/deleted"),
        "kvV2.read.deleted-version",
    )
    .await;
    on(
        &server,
        "GET",
        &format!("{base}/denied"),
        "kvV2.read.permission-denied",
    )
    .await;
    on(&server, "GET", "/v1/secret/data/other/text", "kvV2.read.ok").await;
    let (_c, p) = v2(&server);
    let v = p.get("text", None).await.unwrap().unwrap();
    assert_eq!((v.reveal().unwrap(), v.version()), ("hello", Some("3")));
    assert_eq!(format!("{v:?}"), "SecretValue([REDACTED])");
    let older = GetOptions {
        version: Some("2".into()),
        path: None,
    };
    assert_eq!(
        p.get_string("text", Some(&older)).await.unwrap().unwrap(),
        "older"
    );
    assert_eq!(
        p.get("bin", None).await.unwrap().unwrap().reveal_bytes(),
        &[0u8, 255]
    );
    assert_eq!(
        p.get("bad64", None).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    assert_eq!(
        p.get_json("multi", None).await.unwrap().unwrap(),
        json!({"a": "1", "b": 2})
    );
    assert_eq!(p.get_number("num", None).await.unwrap(), Some(42.0));
    assert!(p.get("missing", None).await.unwrap().is_none());
    assert!(p.get("deleted", None).await.unwrap().is_none());
    assert!(!p.exists("missing", None).await.unwrap());
    assert_eq!(
        p.require("missing", None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        p.get("denied", None).await.unwrap_err().code(),
        ErrorCode::PermissionDenied
    );
    let other = GetOptions {
        version: None,
        path: Some("other".into()),
    };
    assert!(p.get("text", Some(&other)).await.unwrap().is_some());
    for bad in ["0", "x"] {
        let o = GetOptions {
            version: Some(bad.into()),
            path: None,
        };
        assert_eq!(
            p.get("text", Some(&o)).await.unwrap_err().code(),
            ErrorCode::Validation
        );
    }
    let many = p.get_many(&["text", "missing", "num"], None).await.unwrap();
    assert_eq!(many.names().collect::<Vec<_>>(), vec!["text", "num"]);
    assert_eq!(p.mount(), "secret");
    assert_eq!(p.base_path(), "apps/web");
    assert_eq!(p.kv().await.unwrap().version(), 2);
}

#[tokio::test]
async fn list_metadata_and_get_all() {
    let server = MockServer::start().await;
    on_reply(
        &server,
        "GET",
        "/v1/secret/metadata/apps/web",
        json(
            200,
            json!({"data": {"keys": ["beta", "alpha", "dir/", "gone"]}}),
        ),
    )
    .await;
    on_reply(
        &server,
        "GET",
        "/v1/secret/metadata/apps/web/alpha",
        metadata(2, false),
    )
    .await;
    on_reply(
        &server,
        "GET",
        "/v1/secret/metadata/apps/web/beta",
        metadata(1, false),
    )
    .await;
    on_reply(
        &server,
        "GET",
        "/v1/secret/metadata/apps/web/gone",
        metadata(4, true),
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/secret/metadata/apps/web/missing",
        "kvV2.readMetadata.not-found",
    )
    .await;
    on_reply(
        &server,
        "GET",
        "/v1/secret/metadata/apps/web/sub",
        json(200, json!({"data": {"keys": ["x"]}})),
    )
    .await;
    on_reply(
        &server,
        "GET",
        "/v1/secret/metadata/apps/web/sub/x",
        metadata(1, false),
    )
    .await;
    on_reply(
        &server,
        "GET",
        "/v1/secret/data/apps/web/alpha",
        kv2_read(json!({"value": "A"}), 2),
    )
    .await;
    on_reply(
        &server,
        "GET",
        "/v1/secret/data/apps/web/beta",
        kv2_read(json!({"value": "B"}), 1),
    )
    .await;
    let (_c, p) = v2(&server);
    let items = p.list(None).await.unwrap();
    let names: Vec<_> = items.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(names, vec!["alpha", "beta"]);
    let a = &items[0];
    assert_eq!(a.version.as_deref(), Some("2"));
    assert_eq!(a.versions, Some(1));
    assert_eq!(a.tags["owner"], "sdk");
    assert!(a.created_at.is_some() && a.updated_at.is_some());
    assert_eq!(a.extra["casRequired"], "false");
    assert!(a.extra["deleteVersionAfter"].ends_with('s'));
    assert!(a.extra.contains_key("maxVersions") && a.extra.contains_key("oldestVersion"));
    assert_eq!(a.path, None);
    let sub = p.list(Some("/sub/")).await.unwrap();
    assert_eq!(sub[0].name, "sub/x");
    assert_eq!(sub[0].path.as_deref(), Some("sub"));
    assert!(p.metadata("gone", None).await.unwrap().is_none());
    assert!(p.metadata("missing", None).await.unwrap().is_none());
    let all = p.get_all(None).await.unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all.get("beta").unwrap().reveal().unwrap(), "B");
}

#[tokio::test]
async fn set_and_delete_v2() {
    let server = MockServer::start().await;
    let data = "/v1/secret/data/apps/web/k";
    let meta = "/v1/secret/metadata/apps/web/k";
    on(&server, "POST", data, "kvV2.write.cas0").await;
    on(&server, "POST", meta, "kvV2.writeMetadata.ok").await;
    on(
        &server,
        "POST",
        "/v1/secret/data/apps/web/conflict",
        "kvV2.write.cas-mismatch",
    )
    .await;
    let (_c, p) = v2(&server);
    assert_eq!(p.set("k", "text-value".into(), None).await.unwrap(), "1");
    assert_eq!(
        p.set("k", SecretData::Bytes(vec![0, 255]), None)
            .await
            .unwrap(),
        "1"
    );
    assert_eq!(p.set("k", json!({"a": 1}).into(), None).await.unwrap(), "1");
    let tagged = SetOptions {
        cas: Some(1),
        tags: BTreeMap::from([("team".to_owned(), "web".to_owned())]),
        description: Some("db password".into()),
        path: None,
    };
    p.set("k", "v".into(), Some(&tagged)).await.unwrap();
    let bodies = sent(&server, data).await;
    assert_eq!(bodies[0], json!({"data": {"value": "text-value"}}));
    assert_eq!(
        bodies[1],
        json!({"data": {"value": "AP8=", "encoding": "base64"}})
    );
    assert_eq!(bodies[2], json!({"data": {"value": "{\"a\":1}"}}));
    assert_eq!(
        bodies[3],
        json!({"data": {"value": "v"}, "options": {"cas": 1}})
    );
    assert_eq!(
        sent(&server, meta).await[0],
        json!({"custom_metadata": {"team": "web", "description": "db password"}})
    );
    assert_eq!(
        p.set("conflict", "x".into(), None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Conflict
    );

    // delete: pre-read for NOT_FOUND, soft delete, versions, permanent
    let server = MockServer::start().await;
    on_reply(&server, "GET", meta, metadata(2, false)).await;
    on_reply(
        &server,
        "GET",
        "/v1/secret/metadata/apps/web/gone",
        metadata(2, true),
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/secret/metadata/apps/web/missing",
        "kvV2.readMetadata.not-found",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/secret/metadata/apps/web/denied",
        "kvV2.read.permission-denied",
    )
    .await;
    on(&server, "DELETE", data, "kvV2.delete.ok").await;
    on(&server, "DELETE", meta, "kvV2.deleteMetadata.ok").await;
    on(
        &server,
        "POST",
        "/v1/secret/delete/apps/web/k",
        "kvV2.deleteVersions.ok",
    )
    .await;
    let (_c, p) = v2(&server);
    p.delete("k", None).await.unwrap();
    assert_eq!(requests(&server, data).await.len(), 1);
    let versions = DeleteOptions {
        versions: vec!["1".into(), "2".into()],
        ..Default::default()
    };
    p.delete("k", Some(&versions)).await.unwrap();
    assert_eq!(
        sent(&server, "/v1/secret/delete/apps/web/k").await[0],
        json!({"versions": [1, 2]})
    );
    let bad = DeleteOptions {
        versions: vec!["x".into()],
        ..Default::default()
    };
    assert_eq!(
        p.delete("k", Some(&bad)).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    let permanent = DeleteOptions {
        permanent: true,
        ..Default::default()
    };
    p.delete("k", Some(&permanent)).await.unwrap();
    assert_eq!(
        requests(&server, meta)
            .await
            .iter()
            .filter(|r| r.method.as_str() == "DELETE")
            .count(),
        1
    );
    for (name, code) in [
        ("missing", ErrorCode::NotFound),
        ("gone", ErrorCode::NotFound),
        ("denied", ErrorCode::PermissionDenied),
    ] {
        assert_eq!(
            p.delete(name, None).await.unwrap_err().code(),
            code,
            "{name}"
        );
    }
}

#[tokio::test]
async fn kv_v1_provider() {
    let server = MockServer::start().await;
    on(
        &server,
        "GET",
        "/v1/sys/internal/ui/mounts/kv1",
        "mountDetect.kv1",
    )
    .await;
    on_reply(
        &server,
        "GET",
        "/v1/kv1/a",
        json(200, json!({"data": {"value": "one"}})),
    )
    .await;
    on(&server, "GET", "/v1/kv1/missing", "kvV1.read.not-found").await;
    on(
        &server,
        "GET",
        "/v1/kv1/denied",
        "kvV1.read.permission-denied",
    )
    .await;
    on(&server, "POST", "/v1/kv1/a", "kvV1.write.ok").await;
    on(&server, "DELETE", "/v1/kv1/a", "kvV1.delete.ok").await;
    on_reply(
        &server,
        "GET",
        "/v1/kv1",
        json(200, json!({"data": {"keys": ["b", "a", "dir/"]}})),
    )
    .await;
    let c = client(&server);
    let p = c.secrets_with(SecretsProviderOptions {
        mount: Some("kv1".into()),
        path: Some("".into()),
        value_field: Some("value".into()),
        kv_version: None,
    });
    let v = p.get("a", None).await.unwrap().unwrap();
    assert_eq!((v.reveal().unwrap(), v.version()), ("one", None));
    let o = GetOptions {
        version: Some("1".into()),
        path: None,
    };
    assert_eq!(
        p.get("a", Some(&o)).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    assert_eq!(p.set("a", "one".into(), None).await.unwrap(), "");
    let cas = SetOptions {
        cas: Some(1),
        ..Default::default()
    };
    assert_eq!(
        p.set("a", "x".into(), Some(&cas)).await.unwrap_err().code(),
        ErrorCode::Unsupported
    );
    let items = p.list(None).await.unwrap();
    assert_eq!(
        items.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
        vec!["a", "b"]
    );
    assert!(items[0].version.is_none());
    let m = p.metadata("a", None).await.unwrap().unwrap();
    assert_eq!((m.name.as_str(), m.path.as_deref()), ("a", None));
    assert!(p.metadata("missing", None).await.unwrap().is_none());
    assert_eq!(
        p.metadata("denied", None).await.unwrap_err().code(),
        ErrorCode::PermissionDenied
    );
    p.delete("a", None).await.unwrap();
    assert_eq!(
        p.delete("missing", None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        p.delete("denied", None).await.unwrap_err().code(),
        ErrorCode::PermissionDenied
    );
    let versions = DeleteOptions {
        versions: vec!["1".into()],
        ..Default::default()
    };
    assert_eq!(
        p.delete("a", Some(&versions)).await.unwrap_err().code(),
        ErrorCode::Unsupported
    );
}

#[tokio::test]
async fn watch_reports_changes_and_stops_on_close() {
    let server = MockServer::start().await;
    let url = "/v1/secret/data/apps/web/w";
    Mock::given(method("GET"))
        .and(path(url))
        .respond_with(kv2_read(json!({"value": "v1"}), 1))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    on_reply(&server, "GET", url, kv2_read(json!({"value": "v2"}), 2)).await;
    let (c, p) = v2(&server);
    let changes = Arc::new(Mutex::new(Vec::new()));
    let seen = changes.clone();
    let handle = p.watch(
        "w",
        Duration::from_millis(20),
        move |new, old| {
            seen.lock().unwrap().push((
                new.and_then(|v| v.version().map(str::to_owned)),
                old.and_then(|v| v.version().map(str::to_owned)),
            ));
        },
        WatchOptions::default(),
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while changes.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        changes.lock().unwrap()[0],
        (Some("2".to_owned()), Some("1".to_owned()))
    );
    assert!(!handle.is_stopped());
    // a watch stopped by hand releases its close guard
    let other = p.watch(
        "w",
        Duration::from_secs(1),
        |_, _| {},
        WatchOptions::default(),
    );
    other.stop();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(other.is_stopped());
    c.close().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !handle.is_stopped() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("close stops the watch");
}

#[tokio::test]
async fn detection_failure_propagates() {
    let server = MockServer::start().await;
    on(
        &server,
        "GET",
        "/v1/sys/internal/ui/mounts/secret",
        "mountDetect.no-access",
    )
    .await;
    let c = client(&server);
    let p = c.secrets();
    assert_eq!(
        p.get("x", None).await.unwrap_err().code(),
        ErrorCode::PermissionDenied
    );
    assert!(p.list(None).await.is_err());
    assert!(p.set("x", "y".into(), None).await.is_err());
    assert!(p.delete("x", None).await.is_err());
    assert!(p.metadata("x", None).await.is_err());
}
