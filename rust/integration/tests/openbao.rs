//! Every public function of the OpenBao package against the real service (Docker), each with
//! a round-trip assertion. Run with `--test-threads=1` (the Docker image does).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use grow_openbao as sdk;
use grow_openbao_integration::{anonymous_client, root_client, run_id, test_env, test_env_opt};
use sdk::testing::{self, InitOptions};
use sdk::secrets::{
    DeleteOptions, EnvSource, GetOptions, LoadEnvOptions, SecretsProvider, SetOptions, WatchOptions,
};
use sdk::*;
use serde_json::json;

const CSR: &str = "-----BEGIN CERTIFICATE REQUEST-----
MIHfMIGGAgEAMCQxIjAgBgNVBAMMGWNzci1mNDM2MzNkNy5leGFtcGxlLnRlc3Qw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASLUbyChWs1jvdN6EMvW3CmyTVCXlKq
b5HYZpBwTZaMn+T5SKb0NqiCY43WMbo9sSxTCJJ1+vqAyUpz3dfNK9IgoAAwCgYI
KoZIzj0EAwIDSAAwRQIgXIhEmRL/CHOD7zV07qDAVLrGIr35B2TNmWcfU2+hhdkC
IQDVNUsOXsSOFHaG62Xxy16kxvmiMhSvUjqf8QBW99RWQQ==
-----END CERTIFICATE REQUEST-----
";

async fn eventually<F, Fut, T>(what: &str, mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    for _ in 0..200 {
        if let Some(v) = f().await {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{what} did not happen in time");
}

#[tokio::test]
async fn sys_status_calls() {
    let c = root_client();
    let sys = c.sys();
    let h = sys.health().await.unwrap();
    assert_eq!(h.state, "active");
    assert_eq!(h.version, test_env("SERVER_VERSION"));
    assert_eq!(sys.version().await.unwrap(), test_env("SERVER_VERSION"));
    let seal = sys.seal_status().await.unwrap();
    assert!(seal.initialized && !seal.sealed);
    assert_eq!(seal.version, test_env("SERVER_VERSION"));
    let leader = sys.leader().await.unwrap();
    assert!(leader.ha_enabled && leader.is_self);
    assert!(!leader.leader_address.is_empty());
}

#[tokio::test]
async fn kv_v2_round_trip() {
    let c = root_client();
    let mount = test_env("KV2_MOUNT");
    assert_eq!(c.detect_kv_version(&mount).await.unwrap(), 2);
    let kv = c.kv_at(&mount).await.unwrap();
    assert_eq!(kv.version(), 2);
    let v2 = c.kv_v2().at(&mount);
    let base = format!("sdk/rust/{}", run_id());
    let p = format!("{base}/alpha");

    let w = kv
        .write(&p, json!({"a": "1", "b": "2"}), Some(0))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(w.version, 1);
    let s = kv.read(&p, None).await.unwrap();
    assert_eq!(s.data["a"], "1");
    assert_eq!(s.metadata.unwrap().version, 1);
    let err = kv.write(&p, json!({"a": "x"}), Some(0)).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Conflict);
    let pt = v2
        .patch(&p, json!({"b": "3", "c": "4"}), Some(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pt.version, 2);
    assert_eq!(v2.read(&p, None).await.unwrap().data["b"], "3");
    assert_eq!(v2.read(&p, Some(1)).await.unwrap().data["b"], "2");
    kv.patch(&p, json!({"c": null}), None).await.unwrap();
    assert!(!kv.read(&p, None).await.unwrap().data.contains_key("c"));

    kv.write_metadata(
        &p,
        &KvMetadataOptions {
            max_versions: Some(5),
            cas_required: Some(false),
            delete_version_after: Some(Duration::from_secs(720 * 3600)),
            custom_metadata: Some(BTreeMap::from([("owner".to_owned(), "sdk".to_owned())])),
        },
    )
    .await
    .unwrap();
    let md = kv.read_metadata(&p).await.unwrap();
    assert_eq!((md.current_version, md.max_versions), (3, 5));
    assert_eq!(md.custom_metadata["owner"], "sdk");
    assert_eq!(md.delete_version_after, Duration::from_secs(720 * 3600));
    assert_eq!(md.versions.len(), 3);

    kv.write(&format!("{base}/dir/x"), json!({"x": 1}), None)
        .await
        .unwrap();
    assert_eq!(kv.list(&base).await.unwrap(), vec!["alpha", "dir/"]);

    kv.delete(&p).await.unwrap();
    assert_eq!(
        kv.read(&p, None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    kv.undelete(&p, &[3]).await.unwrap();
    assert_eq!(
        kv.read(&p, None).await.unwrap().metadata.unwrap().version,
        3
    );
    kv.delete_versions(&p, &[1]).await.unwrap();
    assert_eq!(
        kv.read(&p, Some(1)).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    kv.destroy(&p, &[2]).await.unwrap();
    assert!(kv.read_metadata(&p).await.unwrap().versions[&2].destroyed);
    kv.delete_metadata(&p).await.unwrap();
    kv.delete_metadata(&format!("{base}/dir/x")).await.unwrap();
    assert!(kv.list(&base).await.unwrap().is_empty());
    assert_eq!(
        kv.read_metadata(&p).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
}

#[tokio::test]
async fn kv_v1_round_trip() {
    let c = root_client();
    let mount = test_env("KV1_MOUNT");
    let kv = c.kv_at(&mount).await.unwrap();
    assert_eq!(kv.version(), 1);
    let v1 = c.kv_v1().at(&mount);
    let base = format!("sdk/rust/{}", run_id());
    let p = format!("{base}/with space");
    assert!(kv
        .write(&p, json!({"a": "1", "n": 2}), None)
        .await
        .unwrap()
        .is_none());
    let s = v1.read(&p, None).await.unwrap();
    assert_eq!(
        (s.data["a"].clone(), s.data["n"].clone()),
        (json!("1"), json!(2))
    );
    v1.write(&p, json!({"a": "2"}), None).await.unwrap();
    assert!(!kv.read(&p, None).await.unwrap().data.contains_key("n"));
    assert_eq!(v1.list(&base).await.unwrap(), vec!["with space"]);
    assert_eq!(
        kv.patch(&p, json!({"a": "3"}), None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Unsupported
    );
    for e in [
        v1.delete_versions(&p, &[1]).await.unwrap_err(),
        v1.undelete(&p, &[1]).await.unwrap_err(),
        v1.destroy(&p, &[1]).await.unwrap_err(),
        v1.read_metadata(&p).await.unwrap_err(),
        v1.write_metadata(&p, &KvMetadataOptions::default())
            .await
            .unwrap_err(),
        v1.delete_metadata(&p).await.unwrap_err(),
    ] {
        assert_eq!(e.code(), ErrorCode::Unsupported);
    }
    v1.delete(&p).await.unwrap();
    assert_eq!(
        v1.read(&p, None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    assert!(kv.list(&base).await.unwrap().is_empty());
}

#[tokio::test]
async fn secrets_provider_round_trip() {
    let c = root_client();
    let run = run_id();
    let p = c.secrets_with(SecretsProviderOptions {
        path: Some(format!("sdk/rust/{run}")),
        ..Default::default()
    });
    assert_eq!(p.kv().await.unwrap().version(), 2);
    let tags = SetOptions {
        tags: BTreeMap::from([("team".to_owned(), "web".to_owned())]),
        description: Some("api key".into()),
        ..Default::default()
    };
    assert_eq!(
        p.set("api-key", "abc123".into(), Some(&tags))
            .await
            .unwrap(),
        "1"
    );
    assert_eq!(
        p.set("bin", vec![0u8, 255].into(), None).await.unwrap(),
        "1"
    );
    assert_eq!(
        p.set("cfg", json!({"port": 8080}).into(), None)
            .await
            .unwrap(),
        "1"
    );
    assert_eq!(p.set("api-key", "abc456".into(), None).await.unwrap(), "2");
    assert_eq!(
        p.get_string("api-key", None).await.unwrap().unwrap(),
        "abc456"
    );
    let v1 = GetOptions {
        version: Some("1".into()),
        path: None,
    };
    assert_eq!(
        p.get_string("api-key", Some(&v1)).await.unwrap().unwrap(),
        "abc123"
    );
    assert_eq!(
        p.get("bin", None).await.unwrap().unwrap().reveal_bytes(),
        &[0, 255]
    );
    assert_eq!(
        p.get_json("cfg", None).await.unwrap().unwrap()["port"],
        8080
    );
    let md = p.metadata("api-key", None).await.unwrap().unwrap();
    assert_eq!(md.version.as_deref(), Some("2"));
    assert_eq!(md.tags["team"], "web");
    assert_eq!(md.tags["description"], "api key");
    let names: Vec<_> = p
        .list(None)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    assert_eq!(names, vec!["api-key", "bin", "cfg"]);
    assert_eq!(p.get_all(None).await.unwrap().len(), 3);

    // load_env from a mapping
    let var = format!("GROW_RS_IT_{}", run.to_uppercase());
    let mapping = EnvSource::Mapping(vec![(var.clone(), "api-key".to_owned())]);
    let set = p
        .load_env(&mapping, &LoadEnvOptions::default())
        .await
        .unwrap();
    assert!(set.contains_key(&var));
    assert_eq!(std::env::var(&var).unwrap(), "abc456");

    // watch sees a new version
    let seen = Arc::new(Mutex::new(None));
    let s2 = seen.clone();
    let handle = p.watch(
        "api-key",
        Duration::from_millis(100),
        move |new, _old| *s2.lock().unwrap() = new.and_then(|v| v.version().map(str::to_owned)),
        WatchOptions::default(),
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    p.set("api-key", "abc789".into(), None).await.unwrap();
    let version = eventually("watch change", || {
        let s = seen.clone();
        async move { s.lock().unwrap().clone() }
    })
    .await;
    assert_eq!(version, "3");
    handle.stop();

    let versions = DeleteOptions {
        versions: vec!["1".into()],
        ..Default::default()
    };
    p.delete("api-key", Some(&versions)).await.unwrap();
    assert!(p.get("api-key", Some(&v1)).await.unwrap().is_none());
    p.delete("api-key", None).await.unwrap();
    assert!(p.get("api-key", None).await.unwrap().is_none());
    assert_eq!(
        p.delete("api-key", None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    let permanent = DeleteOptions {
        permanent: true,
        ..Default::default()
    };
    for n in ["api-key", "bin", "cfg"] {
        p.delete(n, Some(&permanent)).await.unwrap();
    }
    assert!(p.list(None).await.unwrap().is_empty());
    c.close().await;
}

#[tokio::test]
async fn transit_round_trip() {
    let c = root_client();
    let t = c.transit().at(&test_env("TRANSIT_MOUNT"));
    let name = format!("sdk-{}", run_id());
    let k = t
        .create_key(&name, "aes256-gcm96", Some(&CreateKeyOptions::default()))
        .await
        .unwrap();
    assert_eq!(k.name, name);
    assert_eq!(t.read_key(&name).await.unwrap().latest_version, 1);
    assert!(t.list_keys().await.unwrap().contains(&name));

    let ct = t.encrypt(&name, b"grow\0\xff", None).await.unwrap();
    assert_eq!(
        t.decrypt(&name, &ct.ciphertext, None).await.unwrap(),
        b"grow\0\xff"
    );
    assert_eq!(t.rotate_key(&name).await.unwrap().latest_version, 2);
    let rw = t.rewrap(&name, &ct.ciphertext, None).await.unwrap();
    assert!(rw.ciphertext.starts_with("vault:v2:"));
    assert_eq!(
        t.decrypt(&name, &rw.ciphertext, None).await.unwrap(),
        b"grow\0\xff"
    );

    let items = [
        TransitBatchItem::plaintext(b"one".to_vec()),
        TransitBatchItem::plaintext(b"two".to_vec()).with_reference("r2"),
    ];
    let enc = t.encrypt_batch(&name, &items, None).await.unwrap();
    assert_eq!(enc[1].reference, "r2");
    let dec_in: Vec<_> = enc
        .iter()
        .map(|r| TransitBatchItem::ciphertext(r.ciphertext.clone()))
        .chain([TransitBatchItem::ciphertext("vault:v1:AAAA")])
        .collect();
    let dec = t.decrypt_batch(&name, &dec_in).await.unwrap();
    assert_eq!(
        (dec[0].plaintext.as_slice(), dec[1].plaintext.as_slice()),
        (&b"one"[..], &b"two"[..])
    );
    assert!(dec[2].error.is_some());

    let dk = t
        .generate_data_key(&name, &DataKeyOptions::default())
        .await
        .unwrap();
    let plain = dk.plaintext.clone().unwrap();
    assert_eq!(plain.len(), 32);
    assert_eq!(t.decrypt(&name, &dk.ciphertext, None).await.unwrap(), plain);
    let wrapped = t
        .generate_data_key(
            &name,
            &DataKeyOptions {
                wrapped: true,
                bits: Some(128),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(wrapped.plaintext.is_none());
    assert_eq!(
        t.decrypt(&name, &wrapped.ciphertext, None)
            .await
            .unwrap()
            .len(),
        16
    );

    let mac = t.hmac(&name, b"hmac-me", None).await.unwrap();
    let hmac_opts = SignOptions {
        hmac: true,
        ..Default::default()
    };
    assert!(t
        .verify(&name, b"hmac-me", &mac, Some(&hmac_opts))
        .await
        .unwrap());
    assert!(!t
        .verify(&name, b"other", &mac, Some(&hmac_opts))
        .await
        .unwrap());

    let sign_key = test_env("TRANSIT_SIGN_KEY");
    let sig = t.sign(&sign_key, b"sign-me", None).await.unwrap();
    assert!(t
        .verify(&sign_key, b"sign-me", &sig.signature, None)
        .await
        .unwrap());
    assert!(!t
        .verify(&sign_key, b"tampered", &sig.signature, None)
        .await
        .unwrap());
    let rsa = test_env("TRANSIT_RSA_KEY");
    let rsa_opts = SignOptions {
        hash_algorithm: Some("sha2-256".into()),
        signature_algorithm: Some("pkcs1v15".into()),
        ..Default::default()
    };
    let rs = t.sign(&rsa, b"rsa", Some(&rsa_opts)).await.unwrap();
    assert!(t
        .verify(&rsa, b"rsa", &rs.signature, Some(&rsa_opts))
        .await
        .unwrap());
    assert_eq!(
        t.sign(&name, b"x", None).await.unwrap_err().code(),
        ErrorCode::Validation
    );

    assert_eq!(
        t.hash(b"abc", None).await.unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
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
    assert_eq!(b64, "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=");
    assert_eq!(t.random_bytes(32, Some("hex")).await.unwrap().len(), 64);
    assert_eq!(t.random_bytes(16, None).await.unwrap().len(), 24);

    assert_eq!(
        t.delete_key(&name).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    let k = t
        .update_key_config(
            &name,
            &TransitKeyConfig {
                deletion_allowed: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(k.deletion_allowed);
    t.delete_key(&name).await.unwrap();
    assert_eq!(
        t.read_key(&name).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
}

#[tokio::test]
async fn database_and_leases_round_trip() {
    let c = root_client();
    let db = c.database().at(&test_env("DB_MOUNT"));
    let run = run_id();
    let conn = format!("pg-{run}");
    let role = format!("ro-{run}");
    let url = format!(
        "postgresql://{{{{username}}}}:{{{{password}}}}@{}:{}/{}?sslmode=disable",
        test_env("PG_HOST"),
        test_env("PG_PORT"),
        test_env("PG_DB")
    );
    let cfg = DatabaseConnectionConfig {
        plugin_name: "postgresql-database-plugin".into(),
        connection_url: url,
        username: Some(test_env("PG_ADMIN_USER")),
        password: Some(Secret::new(test_env("PG_ADMIN_PASSWORD"))),
        allowed_roles: vec![role.clone()],
        verify_connection: Some(true),
        ..Default::default()
    };
    db.configure_connection(&conn, &cfg).await.unwrap();
    let read = db.read_connection(&conn).await.unwrap();
    assert_eq!(read["plugin_name"], "postgresql-database-plugin");
    assert!(!read.contains_key("password"));
    let bad = DatabaseConnectionConfig {
        password: Some(Secret::new("wrong-password")),
        ..cfg.clone()
    };
    assert_eq!(
        db.configure_connection(&format!("bad-{run}"), &bad)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
    db.create_role(
        &role,
        &DatabaseRole {
            db_name: conn.clone(),
            creation_statements: vec![
                "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';".into(),
            ],
            default_ttl: Some(Duration::from_secs(3600)),
            max_ttl: Some(Duration::from_secs(7200)),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let r = db.read_role(&role).await.unwrap();
    assert_eq!(
        (r.db_name.as_str(), r.default_ttl),
        (conn.as_str(), Some(Duration::from_secs(3600)))
    );
    let lease = db.get_credentials(&role).await.unwrap();
    assert!(lease.renewable && lease.username.is_some() && lease.password.is_some());
    assert_eq!(lease.duration, Duration::from_secs(3600));

    let lm = c.leases();
    let info = lm
        .renew(&lease.id, Some(Duration::from_secs(600)))
        .await
        .unwrap();
    assert_eq!(info.duration, Duration::from_secs(600));
    let capped = lm
        .renew(&lease.id, Some(Duration::from_secs(100 * 3600)))
        .await
        .unwrap();
    assert!(capped.capped());
    let l = lm.lookup(&lease.id).await.unwrap();
    assert_eq!(l.id, lease.id);
    lm.revoke(&lease.id).await.unwrap();
    assert_eq!(
        lm.lookup(&lease.id).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    let second = db.get_credentials(&role).await.unwrap();
    lm.revoke_prefix(&format!("{}/creds/{role}", db.mount()))
        .await
        .unwrap();
    assert!(lm.lookup(&second.id).await.is_err());

    // auto-renewal of a short lease (10 s TTL): the first renewal arrives within ~7 s
    let short = db
        .get_credentials(&test_env("DB_SHORT_ROLE"))
        .await
        .unwrap();
    let renews = Arc::new(AtomicU32::new(0));
    let r1 = renews.clone();
    let managed = lm.manage(
        short.clone(),
        ManageOptions {
            on_renew: Some(Arc::new(move |_| {
                r1.fetch_add(1, Ordering::SeqCst);
            })),
            ..Default::default()
        },
    );
    eventually("lease renewal", || {
        let r = renews.clone();
        async move { (r.load(Ordering::SeqCst) > 0).then_some(()) }
    })
    .await;
    managed.stop();
    lm.revoke(&short.id).await.unwrap();

    db.delete_role(&role).await.unwrap();
    assert_eq!(
        db.read_role(&role).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    db.delete_connection(&conn).await.unwrap();
    assert!(db.read_connection(&conn).await.is_err());
    assert_eq!(
        db.get_credentials(&format!("missing-{run}"))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
}

#[tokio::test]
async fn pki_round_trip() {
    let c = root_client();
    let pki = c.pki().at(&test_env("PKI_MOUNT"));
    let role = test_env("PKI_ROLE");
    let domain = test_env("PKI_DOMAIN");
    let cn = format!("{}.{domain}", run_id());
    let cert = pki
        .issue_certificate(
            &role,
            &cn,
            Some(&IssueOptions {
                alt_names: vec![format!("alt.{domain}")],
                ip_sans: vec!["127.0.0.1".into()],
                ttl: Some(Duration::from_secs(3600)),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert!(cert.certificate.contains("BEGIN CERTIFICATE") && cert.private_key.is_some());
    assert_eq!(
        pki.issue_certificate(&role, "evil.example.com", None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
    let signed = pki.sign_csr(&role, CSR, None).await.unwrap();
    assert!(signed.private_key.is_none() && !signed.serial_number.is_empty());
    let chain = pki.read_ca_chain().await.unwrap();
    assert!(chain.contains("BEGIN CERTIFICATE"));
    assert!(chain.contains(cert.issuing_ca.trim()));
    let serials = pki.list_certificates().await.unwrap();
    assert!(serials.contains(&cert.serial_number));
    let info = pki.read_certificate(&cert.serial_number).await.unwrap();
    assert_eq!(info.certificate.trim(), cert.certificate.trim());
    assert!(!info.revoked());
    let rev = pki.revoke_certificate(&cert.serial_number).await.unwrap();
    assert_eq!(rev.state, "revoked");
    assert!(pki
        .read_certificate(&cert.serial_number)
        .await
        .unwrap()
        .revoked());
    assert_eq!(
        pki.read_certificate("ff:ff:ff:ff")
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
    let st = pki
        .tidy(&TidyOptions {
            safety_buffer: Some(Duration::from_secs(1)),
            wait: true,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_ne!(st.state, "Running");
    assert_eq!(pki.tidy_status().await.unwrap().state, st.state);
}

#[tokio::test]
async fn auth_methods_round_trip() {
    let root = root_client();
    let allowed = test_env("ALLOWED_PATH");
    let denied = test_env("DENIED_PATH");

    // AppRole
    let c = anonymous_client();
    let info = c
        .auth()
        .login(AppRoleAuth::new(
            test_env("APPROLE_ROLE_ID"),
            test_env("APPROLE_SECRET_ID"),
        ))
        .await
        .unwrap();
    assert!(info.policies.contains(&test_env("POLICY")));
    assert_eq!(info.metadata["role_name"], test_env("APPROLE_ROLE"));
    let kv = c.kv_v2();
    assert_eq!(
        kv.read(&allowed, None).await.unwrap().data["value"],
        "world"
    );
    assert_eq!(
        kv.read(&denied, None).await.unwrap_err().code(),
        ErrorCode::PermissionDenied
    );
    let ti = c.auth().lookup_self().await.unwrap();
    assert!(ti.policies.contains(&test_env("POLICY")));
    // the auto-detection works for a restricted token too
    assert_eq!(c.kv().await.unwrap().version(), 2);
    let bad = anonymous_client()
        .auth()
        .login(AppRoleAuth::new(
            test_env("APPROLE_ROLE_ID"),
            "wrong-secret-id",
        ))
        .await
        .unwrap_err();
    assert_eq!(bad.code(), ErrorCode::Authentication);

    // Userpass
    let c = anonymous_client();
    let info = c
        .auth()
        .login(UserpassAuth::new(
            test_env("USERPASS_USER"),
            test_env("USERPASS_PASSWORD"),
        ))
        .await
        .unwrap();
    assert_eq!(info.metadata["username"], test_env("USERPASS_USER"));
    assert_eq!(
        c.kv_v2().read(&allowed, None).await.unwrap().data["value"],
        "world"
    );
    assert_eq!(
        anonymous_client()
            .auth()
            .login(UserpassAuth::new(test_env("USERPASS_USER"), "wrong"))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Authentication
    );

    // JWT
    let c = anonymous_client();
    let info = c
        .auth()
        .login(JwtAuth::new(test_env("JWT_ROLE"), test_env("JWT")))
        .await
        .unwrap();
    assert!(info.renewable);
    assert_eq!(
        c.kv_v2().read(&allowed, None).await.unwrap().data["value"],
        "world"
    );
    let expired = anonymous_client()
        .auth()
        .login(JwtAuth::new(test_env("JWT_ROLE"), test_env("JWT_EXPIRED")))
        .await
        .unwrap_err();
    assert!(expired.message().contains("expired"));
    assert_eq!(expired.code(), ErrorCode::Authentication);

    // Kubernetes: no Kubernetes API behind the fixture → TokenReview fails (request shape only)
    let dir = std::env::temp_dir().join(format!("grow-rs-k8s-{}", run_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let jwt_path = dir.join("token");
    std::fs::write(&jwt_path, test_env("K8S_JWT")).unwrap();
    let err = anonymous_client()
        .auth()
        .login(KubernetesAuth::new(test_env("K8S_ROLE"), &jwt_path).mount(test_env("K8S_MOUNT")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Authentication);
    std::fs::remove_dir_all(&dir).unwrap();

    // login_with (custom method building block)
    let raw = anonymous_client()
        .auth()
        .login_with(
            &format!("{}/login", test_env("APPROLE_MOUNT")),
            json!({"role_id": test_env("APPROLE_ROLE_ID"), "secret_id": test_env("APPROLE_SECRET_ID")}),
        )
        .await
        .unwrap();
    assert!(!raw.client_token.is_empty());

    // tokens: create → TokenAuth → renew → revoke
    let child = root
        .auth()
        .create_token(&TokenCreateOptions {
            policies: vec![test_env("POLICY")],
            ttl: Some(Duration::from_secs(600)),
            renewable: Some(true),
            display_name: Some("rust-it".into()),
            meta: BTreeMap::from([("run".to_owned(), run_id())]),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(child.lease_duration, Duration::from_secs(600));
    let c = anonymous_client();
    let info = c
        .auth()
        .login(TokenAuth::new(child.client_token.expose_secret()))
        .await
        .unwrap();
    assert!(info.renewable);
    c.ping().await.unwrap();
    let renewed = c
        .auth()
        .renew_self(Some(Duration::from_secs(1200)))
        .await
        .unwrap();
    assert_eq!(renewed.lease_duration, Duration::from_secs(1200));
    assert_eq!(
        c.auth()
            .create_token(&TokenCreateOptions::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    c.auth().revoke_self().await.unwrap();
    assert!(c.token().is_none());
    c.set_token(Some(child.client_token.clone()));
    assert_eq!(
        c.ping().await.unwrap_err().code(),
        ErrorCode::Authentication
    );
    // an ordinary call with the revoked token: plain "permission denied" 403 → AUTHENTICATION
    assert_eq!(
        c.kv_v2()
            .read("sdk/allowed/hello", None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Authentication
    );

    // token renewer on a short token
    let short = root
        .auth()
        .create_token(&TokenCreateOptions {
            ttl: Some(Duration::from_secs(3)),
            renewable: Some(true),
            ..Default::default()
        })
        .await
        .unwrap();
    let c = anonymous_client();
    c.set_token(Some(short.client_token.clone()));
    let renews = Arc::new(AtomicU32::new(0));
    let r1 = renews.clone();
    let renewer = c
        .auth()
        .start_renewer(TokenRenewerOptions {
            increment: Some(Duration::from_secs(3)),
            on_renew: Some(Arc::new(move |_| {
                r1.fetch_add(1, Ordering::SeqCst);
            })),
            ..Default::default()
        })
        .await
        .unwrap();
    eventually("token renewal", || {
        let r = renews.clone();
        async move { (r.load(Ordering::SeqCst) >= 2).then_some(()) }
    })
    .await;
    // the token outlived its original 3 s TTL thanks to the renewer
    c.ping().await.unwrap();
    c.close().await;
    assert!(renewer.is_stopped());
}

#[tokio::test]
async fn admin_round_trip() {
    let c = root_client();
    let sys = c.sys();
    let run = run_id();

    // policies
    let policy = format!("sdk-rs-{run}");
    let hcl = format!("path \"secret/data/sdk/{run}/*\" {{ capabilities = [\"read\"] }}");
    sys.write_policy(&policy, &hcl).await.unwrap();
    assert_eq!(sys.read_policy(&policy).await.unwrap().policy, hcl);
    assert!(sys.list_policies().await.unwrap().contains(&policy));
    assert_eq!(
        sys.write_policy("bad", "nope {").await.unwrap_err().code(),
        ErrorCode::Validation
    );
    sys.delete_policy(&policy).await.unwrap();
    assert_eq!(
        sys.read_policy(&policy).await.unwrap_err().code(),
        ErrorCode::NotFound
    );

    // secrets engines
    let mount = format!("tmp-{run}");
    sys.enable_secrets_engine(
        &mount,
        "kv",
        Some(&MountOptions {
            description: Some("rust it".into()),
            options: BTreeMap::from([("version".to_owned(), "2".to_owned())]),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let mounts = sys.list_mounts().await.unwrap();
    let m = &mounts[&format!("{mount}/")];
    assert_eq!(
        (m.mount_type.as_str(), m.options["version"].as_str()),
        ("kv", "2")
    );
    assert_eq!(
        sys.enable_secrets_engine(&mount, "kv", None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
    sys.disable_secrets_engine(&mount).await.unwrap();
    assert!(!sys
        .list_mounts()
        .await
        .unwrap()
        .contains_key(&format!("{mount}/")));

    // auth methods + AppRole admin
    let ar = format!("ar-{run}");
    sys.enable_auth_method(&ar, "approle", None).await.unwrap();
    assert_eq!(
        sys.list_auth_methods().await.unwrap()[&format!("{ar}/")].mount_type,
        "approle"
    );
    sys.create_app_role(
        "r1",
        &AppRoleOptions {
            mount: Some(ar.clone()),
            token_policies: vec!["default".into()],
            token_ttl: Some(Duration::from_secs(600)),
            secret_id_num_uses: 1,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(sys.list_app_roles(Some(&ar)).await.unwrap(), vec!["r1"]);
    let role_id = sys.read_role_id("r1", Some(&ar)).await.unwrap();
    let sid = sys
        .generate_secret_id(
            "r1",
            &SecretIdOptions {
                mount: Some(ar.clone()),
                metadata: BTreeMap::from([("purpose".to_owned(), "sdk".to_owned())]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(sid.num_uses, 1);
    let login = anonymous_client()
        .auth()
        .login(AppRoleAuth::new(role_id.clone(), sid.secret_id.expose_secret()).mount(&ar))
        .await
        .unwrap();
    assert_eq!(login.metadata["purpose"], "sdk");
    // single-use secret id is used up
    assert!(anonymous_client()
        .auth()
        .login(AppRoleAuth::new(role_id, sid.secret_id.expose_secret()).mount(&ar))
        .await
        .is_err());
    sys.delete_app_role("r1", Some(&ar)).await.unwrap();
    assert_eq!(
        sys.read_role_id("r1", Some(&ar)).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    sys.disable_auth_method(&ar).await.unwrap();
    assert!(!sys
        .list_auth_methods()
        .await
        .unwrap()
        .contains_key(&format!("{ar}/")));
}

#[tokio::test]
async fn wrapping_round_trip() {
    let c = root_client();
    let w = c.wrapping();
    let info = w
        .wrap(
            json!({"secret": "wrapped-rs", "n": 1}),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert_eq!(info.ttl, Duration::from_secs(60));
    let token = info.token.expose_secret().to_owned();
    let look = w.lookup_wrapping(&token).await.unwrap();
    assert_eq!(look.creation_path, "sys/wrapping/wrap");
    assert_eq!(look.creation_ttl, Duration::from_secs(60));
    let out = anonymous_client().wrapping().unwrap(&token).await.unwrap();
    assert_eq!(out.data["secret"], "wrapped-rs");
    assert_eq!(out.data["n"], 1);
    assert_eq!(
        w.unwrap(&token).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    assert_eq!(
        w.lookup_wrapping(&token).await.unwrap_err().code(),
        ErrorCode::Validation
    );
}

#[tokio::test]
async fn namespace_isolation() {
    let Some(ns) = test_env_opt("NAMESPACE") else {
        println!("namespaces not available in this server; skipped");
        return;
    };
    grow_openbao_integration::load_bootstrap_env();
    let cfg = OpenBaoConfig::builder()
        .namespace(ns)
        .build_from_env()
        .unwrap();
    let c = OpenBaoClient::new(cfg).unwrap();
    let s = c.kv_v2().read("sdk/in-namespace", None).await.unwrap();
    assert_eq!(s.data["value"], "ns-only");
    assert_eq!(
        root_client()
            .kv_v2()
            .read("sdk/in-namespace", None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
}

#[tokio::test]
async fn operator_init_unseal_seal() {
    let url = test_env("SHAMIR_URL");
    let c = OpenBaoClient::new(
        OpenBaoConfig::builder()
            .url(url)
            .retry(RetryPolicy::none())
            .build()
            .unwrap(),
    )
    .unwrap();
    let before = c.health().await.unwrap();
    if testing::init_status(&c).await.unwrap() {
        println!(
            "shamir instance already initialised ({}); skipped",
            before.status
        );
        return;
    }
    assert_eq!(before.status, "uninitialized");
    let init = testing::init(&c, &InitOptions::default()).await.unwrap();
    assert_eq!(init.keys.len(), 1);
    assert!(testing::init_status(&c).await.unwrap());
    assert_eq!(
        testing::init(&c, &InitOptions::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
    assert_eq!(c.health().await.unwrap().status, "sealed");
    assert_eq!(
        testing::unseal(&c, "zz").await.unwrap_err().code(),
        ErrorCode::Validation
    );
    let st = testing::unseal(&c, init.keys[0].expose_secret())
        .await
        .unwrap();
    assert!(!st.sealed);
    let h = testing::wait_for_active(&c, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(h.state, "active");
    c.set_token(Some(init.root_token.clone()));
    testing::seal(&c).await.unwrap();
    assert!(c.sys().seal_status().await.unwrap().sealed);
    let _ = testing::unseal_reset(&c).await.unwrap();
}
