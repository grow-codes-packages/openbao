//! Transit engine: keys, encryption, batches, data keys, HMAC, signatures, hash, random.

mod support;

use std::time::Duration;

use grow_openbao as sdk;
use sdk::core::ErrorCode;
use sdk::{
    CreateKeyOptions, DataKeyOptions, EncryptOptions, HashOptions, HmacOptions, SignOptions,
    TransitBatchItem, TransitKeyConfig,
};
use serde_json::json;
use support::*;
use wiremock::MockServer;

const K: &str = "/v1/transit/keys/k1";

#[tokio::test]
async fn key_management() {
    let server = MockServer::start().await;
    once(&server, "POST", K, "transit.createKey.ok").await;
    on_reply(&server, "POST", K, json(204, json!(null))).await;
    on(&server, "GET", K, "transit.readKey.ok").await;
    on(
        &server,
        "GET",
        "/v1/transit/keys/missing",
        "transit.readKey.not-found",
    )
    .await;
    on_list(&server, "/v1/transit/keys", "transit.listKeys.ok").await;
    on(
        &server,
        "POST",
        "/v1/transit/keys/k1/rotate",
        "transit.rotateKey.ok",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/transit/keys/k1/config",
        "transit.updateKeyConfig.ok",
    )
    .await;
    once(&server, "DELETE", K, "transit.deleteKey.not-allowed").await;
    on(&server, "DELETE", K, "transit.deleteKey.ok").await;
    on_reply(
        &server,
        "GET",
        "/v1/transit/keys/asym",
        json(
            200,
            json!({"data": {"name": "asym", "type": "ed25519",
            "keys": {"1": {"creation_time": "2026-11-18T20:28:54Z", "public_key": "PUB"}, "x": 1},
            "auto_rotate_period": "24h0m0s"}}),
        ),
    )
    .await;
    let c = client(&server);
    let t = c.transit();
    let k = t
        .create_key(
            "k1",
            "aes256-gcm96",
            Some(&CreateKeyOptions {
                exportable: true,
                derived: true,
                allow_plaintext_backup: true,
                auto_rotate_period: Some(Duration::from_secs(3600)),
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        (k.name.as_str(), k.key_type.as_str()),
        ("sdk-f43633d7", "aes256-gcm96")
    );
    assert_eq!(
        sent(&server, K).await[0],
        json!({"type": "aes256-gcm96", "exportable": true, "derived": true, "allow_plaintext_backup": true, "auto_rotate_period": "3600s"})
    );
    // a server answering 204 is followed by a read
    let k = t.create_key("k1", "", None).await.unwrap();
    assert_eq!(k.latest_version, 1);
    assert_eq!(sent(&server, K).await[1], json!({}));
    let k = t.read_key("k1").await.unwrap();
    assert!(k.supports_encryption && k.supports_decryption && !k.supports_signing);
    assert_eq!(k.min_decryption_version, 1);
    assert!(k.keys[&1].creation_time.is_some());
    assert_eq!(
        t.read_key("missing").await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    let asym = t.read_key("asym").await.unwrap();
    assert_eq!(asym.keys[&1].public_key.as_deref(), Some("PUB"));
    assert_eq!(asym.keys.len(), 1);
    assert_eq!(asym.auto_rotate_period, Duration::from_secs(86_400));
    assert_eq!(t.list_keys().await.unwrap().len(), 4);
    assert_eq!(t.rotate_key("k1").await.unwrap().latest_version, 2);
    let cfg = TransitKeyConfig {
        deletion_allowed: Some(true),
        min_decryption_version: Some(1),
        min_encryption_version: Some(0),
        exportable: Some(false),
        allow_plaintext_backup: Some(false),
        auto_rotate_period: Some(Duration::ZERO),
    };
    t.update_key_config("k1", &cfg).await.unwrap();
    assert_eq!(
        sent(&server, "/v1/transit/keys/k1/config").await[0],
        json!({"deletion_allowed": true, "min_decryption_version": 1, "min_encryption_version": 0,
               "exportable": false, "allow_plaintext_backup": false, "auto_rotate_period": "0s"})
    );
    let err = t.delete_key("k1").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    assert!(err.message().contains("deletion is not allowed"));
    t.delete_key("k1").await.unwrap();
    for e in [
        t.create_key("", "", None).await.unwrap_err(),
        t.read_key(" ").await.unwrap_err(),
        t.rotate_key("").await.unwrap_err(),
        t.update_key_config("", &cfg).await.unwrap_err(),
        t.delete_key("").await.unwrap_err(),
    ] {
        assert_eq!(e.code(), ErrorCode::Validation);
    }
}

#[tokio::test]
async fn encrypt_decrypt_rewrap() {
    let server = MockServer::start().await;
    on(
        &server,
        "POST",
        "/v1/transit/encrypt/k1",
        "transit.encrypt.ok",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/transit/decrypt/k1",
        "transit.decrypt.ok",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/transit/decrypt/bad",
        "transit.decrypt.invalid",
    )
    .await;
    on_reply(
        &server,
        "POST",
        "/v1/transit/decrypt/garbage",
        json(200, json!({"data": {"plaintext": "!!"}})),
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/transit/rewrap/k1",
        "transit.rewrap.ok",
    )
    .await;
    let c = client(&server);
    let t = c.transit().at("transit");
    let opts = EncryptOptions {
        context: Some(b"ctx".to_vec()),
        key_version: Some(1),
    };
    let ct = t
        .encrypt("k1", b"grow\0\xffbinary", Some(&opts))
        .await
        .unwrap();
    assert!(ct.ciphertext.starts_with("vault:v1:"));
    assert_eq!(ct.key_version, 1);
    assert_eq!(
        sent(&server, "/v1/transit/encrypt/k1").await[0],
        json!({"plaintext": "Z3JvdwD/YmluYXJ5", "context": "Y3R4", "key_version": 1})
    );
    let pt = t.decrypt("k1", &ct.ciphertext, None).await.unwrap();
    assert_eq!(pt, b"grow\0\xffbinary-f43633d7");
    assert_eq!(
        t.decrypt("bad", "vault:v1:x", None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
    assert_eq!(
        t.decrypt("garbage", "vault:v1:x", None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Unavailable
    );
    let rw = t.rewrap("k1", &ct.ciphertext, None).await.unwrap();
    assert!(rw.ciphertext.starts_with("vault:v2:"));
}

#[tokio::test]
async fn batches() {
    let server = MockServer::start().await;
    on(
        &server,
        "POST",
        "/v1/transit/encrypt/k1",
        "transit.encryptBatch.ok",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/transit/decrypt/k1",
        "transit.decryptBatch.partial-207",
    )
    .await;
    on_reply(
        &server,
        "POST",
        "/v1/transit/decrypt/odd",
        json(
            200,
            json!({"data": {"batch_results": [{"plaintext": "!!"}]}}),
        ),
    )
    .await;
    on_reply(
        &server,
        "POST",
        "/v1/transit/decrypt/none",
        json(200, json!({"data": {}})),
    )
    .await;
    let c = client(&server);
    let t = c.transit();
    let items = [
        TransitBatchItem::plaintext(b"one".to_vec()),
        TransitBatchItem::plaintext(b"two".to_vec())
            .with_reference("r2")
            .with_context(b"c".to_vec()),
    ];
    let out = t
        .encrypt_batch(
            "k1",
            &items,
            Some(&EncryptOptions {
                key_version: Some(2),
                context: None,
            }),
        )
        .await
        .unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!((out[1].reference.as_str(), out[1].key_version), ("r2", 2));
    assert!(out.iter().all(|r| r.error.is_none()));
    assert_eq!(
        sent(&server, "/v1/transit/encrypt/k1").await[0],
        json!({"batch_input": [{"plaintext": "b25l"}, {"plaintext": "dHdv", "context": "Yw==", "reference": "r2"}],
               "partial_failure_response_code": 207, "key_version": 2})
    );
    assert!(!format!("{:?}{:?}", items[0], out[0]).contains("b25l"));
    let res = t
        .decrypt_batch(
            "k1",
            &[
                TransitBatchItem::ciphertext("vault:v2:a"),
                TransitBatchItem::ciphertext("vault:v1:AAAA"),
            ],
        )
        .await
        .unwrap();
    assert_eq!(res[0].plaintext, b"one");
    assert_eq!(res[1].error.as_deref(), Some("invalid ciphertext length"));
    let odd = t
        .decrypt_batch("odd", &[TransitBatchItem::ciphertext("x")])
        .await
        .unwrap();
    assert!(odd[0].error.as_deref().unwrap().contains("not base64"));
    assert!(t
        .decrypt_batch("none", &[TransitBatchItem::ciphertext("x")])
        .await
        .unwrap()
        .is_empty());
    assert!(t.encrypt_batch("k1", &[], None).await.unwrap().is_empty());
}

#[tokio::test]
async fn data_keys_hmac_sign_verify_hash_random() {
    let server = MockServer::start().await;
    on(
        &server,
        "POST",
        "/v1/transit/datakey/plaintext/k1",
        "transit.generateDataKey.plaintext",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/transit/datakey/wrapped/k1",
        "transit.generateDataKey.wrapped",
    )
    .await;
    on_reply(
        &server,
        "POST",
        "/v1/transit/datakey/plaintext/odd",
        json(200, json!({"data": {"plaintext": "!!"}})),
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/transit/hmac/k1/sha2-256",
        "transit.hmac.ok",
    )
    .await;
    on(&server, "POST", "/v1/transit/hmac/k1", "transit.hmac.ok").await;
    on(
        &server,
        "POST",
        "/v1/transit/sign/sign-key",
        "transit.sign.ed25519",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/transit/sign/rsa/sha2-256",
        "transit.sign.rsa-pkcs1v15",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/transit/sign/k1",
        "transit.sign.unsupported-key-type",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/transit/verify/sign-key",
        "transit.verify.invalid",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/transit/verify/rsa/sha2-256",
        "transit.verify.rsa-valid",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/transit/verify/k1/sha2-256",
        "transit.verify.hmac-valid",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/transit/hash",
        "transit.hash.default-hex",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/transit/hash/sha2-256",
        "transit.hash.base64",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/transit/random/32",
        "transit.randomBytes.hex",
    )
    .await;
    let c = client(&server);
    let t = c.transit();
    let dk = t
        .generate_data_key(
            "k1",
            &DataKeyOptions {
                bits: Some(256),
                context: Some(b"c".to_vec()),
                wrapped: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(dk.plaintext.as_ref().unwrap().len(), 32);
    assert!(!format!("{dk:?}").contains("h4dd3"));
    assert_eq!(
        sent(&server, "/v1/transit/datakey/plaintext/k1").await[0],
        json!({"bits": 256, "context": "Yw=="})
    );
    let wrapped = t
        .generate_data_key(
            "k1",
            &DataKeyOptions {
                wrapped: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(wrapped.plaintext.is_none() && wrapped.ciphertext.starts_with("vault:v1:"));
    assert_eq!(
        t.generate_data_key("odd", &DataKeyOptions::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Unavailable
    );

    let mac = t
        .hmac(
            "k1",
            b"hmac-me",
            Some(&HmacOptions {
                algorithm: Some("sha2-256".into()),
                key_version: Some(2),
            }),
        )
        .await
        .unwrap();
    assert!(mac.starts_with("vault:v2:"));
    assert_eq!(
        sent(&server, "/v1/transit/hmac/k1/sha2-256").await[0],
        json!({"input": "aG1hYy1tZQ==", "key_version": 2})
    );
    t.hmac("k1", b"x", None).await.unwrap();
    let ok = t
        .verify(
            "k1",
            b"hmac-me",
            &mac,
            Some(&SignOptions {
                hmac: true,
                hash_algorithm: Some("sha2-256".into()),
                key_version: Some(9),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert!(ok);
    assert_eq!(
        sent(&server, "/v1/transit/verify/k1/sha2-256").await[0],
        json!({"input": "aG1hYy1tZQ==", "hmac": mac})
    );

    let sig = t.sign("sign-key", b"sign-me", None).await.unwrap();
    assert!(sig.signature.starts_with("vault:v1:"));
    assert_eq!(sig.key_version, 1);
    let rsa_opts = SignOptions {
        hash_algorithm: Some("sha2-256".into()),
        signature_algorithm: Some("pkcs1v15".into()),
        prehashed: true,
        key_version: Some(1),
        context: Some(b"c".to_vec()),
        hmac: false,
    };
    let rsa = t.sign("rsa", b"x", Some(&rsa_opts)).await.unwrap();
    assert_eq!(
        sent(&server, "/v1/transit/sign/rsa/sha2-256").await[0],
        json!({"input": "eA==", "signature_algorithm": "pkcs1v15", "prehashed": true, "key_version": 1, "context": "Yw=="})
    );
    assert!(t
        .verify("rsa", b"x", &rsa.signature, Some(&rsa_opts))
        .await
        .unwrap());
    assert!(!t
        .verify("sign-key", b"other", &sig.signature, None)
        .await
        .unwrap());
    assert_eq!(
        t.sign("k1", b"x", None).await.unwrap_err().code(),
        ErrorCode::Validation
    );

    let hex = t.hash(b"abc", None).await.unwrap();
    assert_eq!(hex.len(), 64);
    let b64 = t
        .hash(
            b"abc",
            Some(&HashOptions {
                algorithm: Some("sha2-256".into()),
                format: Some("base64".into()),
            }),
        )
        .await
        .unwrap();
    assert!(b64.ends_with('='));
    let rnd = t.random_bytes(32, Some("HEX")).await.unwrap();
    assert_eq!(rnd.len(), 64);
    assert_eq!(
        sent(&server, "/v1/transit/random/32").await[0],
        json!({"format": "hex"})
    );
    assert_eq!(
        t.random_bytes(0, None).await.unwrap_err().code(),
        ErrorCode::Validation
    );
}
