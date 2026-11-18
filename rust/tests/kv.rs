//! KV v1, KV v2 and the auto-detected `Kv`.

mod support;

use std::collections::BTreeMap;
use std::time::Duration;

use grow_openbao as sdk;
use sdk::core::ErrorCode;
use sdk::{Kv, KvMetadataOptions};
use serde_json::json;
use support::*;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer};

const P: &str = "/v1/secret/data/app/alpha";
const M: &str = "/v1/secret/metadata/app/alpha";

#[tokio::test]
async fn kv_v2_read_write_patch() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(P))
        .and(query_param("version", "1"))
        .respond_with(reply("kvV2.read.version"))
        .mount(&server)
        .await;
    on(&server, "GET", P, "kvV2.read.ok").await;
    on(
        &server,
        "GET",
        "/v1/secret/data/app/missing",
        "kvV2.read.not-found",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/secret/data/app/deleted",
        "kvV2.read.deleted-version",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/secret/data/app/denied",
        "kvV2.read.permission-denied",
    )
    .await;
    on_reply(
        &server,
        "GET",
        "/v1/secret/data/app/null",
        json(200, json!({"data": {"data": null}})),
    )
    .await;
    once(&server, "POST", P, "kvV2.write.cas0").await;
    on(&server, "POST", P, "kvV2.write.cas-mismatch").await;
    Mock::given(method("PATCH"))
        .and(path(P))
        .and(header("content-type", "application/merge-patch+json"))
        .respond_with(reply("kvV2.patch.ok"))
        .mount(&server)
        .await;
    let c = client(&server);
    let kv = c.kv_v2();
    let s = kv.read("app/alpha", None).await.unwrap();
    assert_eq!(s.data["a"], "1");
    let md = s.metadata.unwrap();
    assert_eq!(md.version, 1);
    assert!(md.created_time.is_some() && !md.is_deleted());
    assert!(!format!("{:?}", kv.read("app/alpha", None).await.unwrap()).contains("\"1\""));
    assert_eq!(
        kv.read("app/alpha", Some(1))
            .await
            .unwrap()
            .metadata
            .unwrap()
            .version,
        1
    );
    assert_eq!(
        kv.read("app/missing", None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        kv.read("app/deleted", None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        kv.read("app/null", None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        kv.read("app/denied", None).await.unwrap_err().code(),
        ErrorCode::PermissionDenied
    );

    let w = kv
        .write("app/alpha", json!({"a": "1", "b": "2"}), Some(0))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(w.version, 1);
    assert_eq!(
        sent(&server, P).await[0],
        json!({"data": {"a": "1", "b": "2"}, "options": {"cas": 0}})
    );
    let err = kv
        .write("app/alpha", json!({"a": "x"}), None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Conflict);
    assert_eq!(sent(&server, P).await[1], json!({"data": {"a": "x"}}));
    assert_eq!(
        kv.write("app/alpha", json!("text"), None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
    // null data writes an empty map
    let _ = kv.write("app/alpha", serde_json::Value::Null, None).await;

    let p = kv
        .patch("app/alpha", json!({"b": "3", "c": null}), Some(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(p.version, 2);
    assert_eq!(
        kv.patch("app/alpha", json!(1), None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
}

#[tokio::test]
async fn kv_v2_versions_list_metadata() {
    let server = MockServer::start().await;
    on(&server, "DELETE", P, "kvV2.delete.ok").await;
    on(
        &server,
        "POST",
        "/v1/secret/delete/app/alpha",
        "kvV2.deleteVersions.ok",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/secret/undelete/app/alpha",
        "kvV2.undelete.ok",
    )
    .await;
    on(
        &server,
        "PUT",
        "/v1/secret/destroy/app/alpha",
        "kvV2.destroy.ok",
    )
    .await;
    on_list(&server, "/v1/secret/metadata/app", "kvV2.list.ok").await;
    on_list(&server, "/v1/secret/metadata", "kvV2.list.ok").await;
    on_list(&server, "/v1/secret/metadata/none", "kvV2.list.not-found").await;
    on(&server, "GET", M, "kvV2.readMetadata.ok").await;
    on(
        &server,
        "GET",
        "/v1/secret/metadata/app/gone",
        "kvV2.readMetadata.after-delete",
    )
    .await;
    on(&server, "POST", M, "kvV2.writeMetadata.ok").await;
    on(&server, "DELETE", M, "kvV2.deleteMetadata.ok").await;
    let c = client(&server);
    let kv = c.kv_v2();
    kv.delete("app/alpha").await.unwrap();
    kv.delete_versions("app/alpha", &[1]).await.unwrap();
    kv.undelete("app/alpha", &[1, 2]).await.unwrap();
    kv.destroy("app/alpha", &[1]).await.unwrap();
    assert_eq!(
        sent(&server, "/v1/secret/undelete/app/alpha").await[0],
        json!({"versions": [1, 2]})
    );
    for bad in [&[][..], &[0][..]] {
        assert_eq!(
            kv.destroy("app/alpha", bad).await.unwrap_err().code(),
            ErrorCode::Validation
        );
    }
    assert_eq!(kv.list("app").await.unwrap(), vec!["alpha", "beta", "dir/"]);
    assert_eq!(kv.list("").await.unwrap().len(), 3);
    assert!(kv.list("none").await.unwrap().is_empty());

    let md = kv.read_metadata("app/alpha").await.unwrap();
    assert_eq!(md.current_version, 3);
    assert_eq!(md.max_versions, 5);
    assert_eq!(md.delete_version_after, Duration::from_secs(720 * 3600));
    assert_eq!(md.custom_metadata["owner"], "sdk");
    assert_eq!(md.versions.len(), 3);
    assert_eq!(md.versions[&2].version, 2);
    assert!(md.created_time.is_some() && md.updated_time.is_some());
    assert!(!md.cas_required);
    assert_eq!(
        kv.read_metadata("app/gone").await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    kv.write_metadata(
        "app/alpha",
        &KvMetadataOptions {
            max_versions: Some(5),
            cas_required: Some(false),
            delete_version_after: Some(Duration::from_secs(720 * 3600)),
            custom_metadata: Some(BTreeMap::from([("k".to_owned(), "v".to_owned())])),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        sent(&server, M).await[0],
        json!({"max_versions": 5, "cas_required": false, "delete_version_after": "2592000s", "custom_metadata": {"k": "v"}})
    );
    kv.write_metadata("app/alpha", &KvMetadataOptions::default())
        .await
        .unwrap();
    kv.delete_metadata("app/alpha").await.unwrap();
}

#[tokio::test]
async fn kv_v1_operations() {
    let server = MockServer::start().await;
    on(&server, "GET", "/v1/kv1/app/alpha", "kvV1.read.ok").await;
    on(
        &server,
        "GET",
        "/v1/kv1/app/with%20space",
        "kvV1.read.encoded-path",
    )
    .await;
    on(&server, "GET", "/v1/kv1/app/missing", "kvV1.read.not-found").await;
    on(&server, "POST", "/v1/kv1/app/alpha", "kvV1.write.ok").await;
    on(&server, "DELETE", "/v1/kv1/app/alpha", "kvV1.delete.ok").await;
    on_list(&server, "/v1/kv1/app", "kvV1.list.ok").await;
    on_list(&server, "/v1/kv1/none", "kvV1.list.not-found").await;
    let c = client(&server);
    let kv = c.kv_v1().at("kv1");
    let s = kv.read("app/alpha", None).await.unwrap();
    assert_eq!(
        (s.data["a"].clone(), s.data["n"].clone()),
        (json!("1"), json!(2))
    );
    assert!(s.metadata.is_none());
    assert!(kv.read("app/with space", None).await.is_ok());
    assert_eq!(
        kv.read("app/missing", None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        kv.read("app/alpha", Some(1)).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    assert!(kv
        .write("app/alpha", json!({"a": "1"}), None)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        sent(&server, "/v1/kv1/app/alpha").await[0],
        json!({"a": "1"})
    );
    assert_eq!(
        kv.write("app/alpha", json!({}), Some(1))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Unsupported
    );
    assert_eq!(
        kv.write("app/alpha", json!([1]), None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
    kv.delete("app/alpha").await.unwrap();
    assert_eq!(
        kv.list("app").await.unwrap(),
        vec!["alpha", "dir/", "with space"]
    );
    assert!(kv.list("none").await.unwrap().is_empty());
    // v2-only operations fail without a request
    let before = server.received_requests().await.unwrap().len();
    assert_eq!(
        kv.patch("x", json!({}), None).await.unwrap_err().code(),
        ErrorCode::Unsupported
    );
    assert!(kv.delete_versions("x", &[1]).await.is_err());
    assert!(kv.undelete("x", &[1]).await.is_err());
    assert!(kv.destroy("x", &[1]).await.is_err());
    assert!(kv.read_metadata("x").await.is_err());
    assert!(kv
        .write_metadata("x", &KvMetadataOptions::default())
        .await
        .is_err());
    let err = kv.delete_metadata("x").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported);
    assert!(err.message().contains("KV version 1"));
    assert_eq!(server.received_requests().await.unwrap().len(), before);
}

#[tokio::test]
async fn kv_enum_dispatch() {
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
    on(&server, "GET", "/v1/kv1/app/alpha", "kvV1.read.ok").await;
    on(&server, "POST", "/v1/kv1/app/alpha", "kvV1.write.ok").await;
    on(&server, "DELETE", "/v1/kv1/app/alpha", "kvV1.delete.ok").await;
    on(
        &server,
        "PATCH",
        "/v1/kv1/app/alpha",
        "kvV1.patch.unsupported",
    )
    .await;
    on_list(&server, "/v1/kv1/app", "kvV1.list.ok").await;
    on(&server, "GET", P, "kvV2.read.ok").await;
    on(&server, "POST", P, "kvV2.write.cas0").await;
    on(&server, "PATCH", P, "kvV2.patch.ok").await;
    on(&server, "DELETE", P, "kvV2.delete.ok").await;
    on(
        &server,
        "POST",
        "/v1/secret/delete/app/alpha",
        "kvV2.deleteVersions.ok",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/secret/undelete/app/alpha",
        "kvV2.undelete.ok",
    )
    .await;
    on(
        &server,
        "PUT",
        "/v1/secret/destroy/app/alpha",
        "kvV2.destroy.ok",
    )
    .await;
    on_list(&server, "/v1/secret/metadata/app", "kvV2.list.ok").await;
    on(&server, "GET", M, "kvV2.readMetadata.ok").await;
    on(&server, "POST", M, "kvV2.writeMetadata.ok").await;
    on(&server, "DELETE", M, "kvV2.deleteMetadata.ok").await;
    let c = client(&server);
    let v1 = c.kv_at("kv1").await.unwrap();
    assert!(matches!(v1, Kv::V1(_)));
    assert_eq!(v1.read("app/alpha", None).await.unwrap().data["a"], "1");
    v1.write("app/alpha", json!({"a": 1}), None).await.unwrap();
    v1.delete("app/alpha").await.unwrap();
    assert_eq!(v1.list("app").await.unwrap().len(), 3);
    assert_eq!(
        v1.patch("app/alpha", json!({}), None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Unsupported
    );
    let v2 = c.kv().await.unwrap();
    assert_eq!((v2.version(), v2.mount()), (2, "secret"));
    assert_eq!(v2.read("app/alpha", None).await.unwrap().data["b"], "2");
    v2.write("app/alpha", json!({"a": 1}), Some(0))
        .await
        .unwrap();
    v2.patch("app/alpha", json!({"b": 2}), None).await.unwrap();
    v2.delete("app/alpha").await.unwrap();
    v2.delete_versions("app/alpha", &[1]).await.unwrap();
    v2.undelete("app/alpha", &[1]).await.unwrap();
    v2.destroy("app/alpha", &[1]).await.unwrap();
    assert_eq!(v2.list("app").await.unwrap().len(), 3);
    assert_eq!(
        v2.read_metadata("app/alpha").await.unwrap().current_version,
        3
    );
    v2.write_metadata("app/alpha", &KvMetadataOptions::default())
        .await
        .unwrap();
    v2.delete_metadata("app/alpha").await.unwrap();
    // PATCH on a v1 mount through the server maps 405 to UNSUPPORTED as well
    let raw = c
        .transport()
        .request(sdk::core::Method::PATCH, "/v1/kv1/app/alpha");
    let e = raw.send().await.unwrap_err();
    assert_eq!(e.http_status(), Some(405));
}
