//! PKI engine: issue, sign, revoke, read, list, tidy.

mod support;

use std::time::Duration;

use grow_openbao as sdk;
use sdk::core::ErrorCode;
use sdk::{IssueOptions, TidyOptions};
use serde_json::json;
use support::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

#[tokio::test]
async fn issue_sign_revoke_read() {
    let server = MockServer::start().await;
    on(
        &server,
        "POST",
        "/v1/pki/issue/web",
        "pki.issueCertificate.ok",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/pki/issue/strict",
        "pki.issueCertificate.not-allowed",
    )
    .await;
    on(&server, "POST", "/v1/pki/sign/web", "pki.signCsr.ok").await;
    on(&server, "POST", "/v1/pki/sign/bad", "pki.signCsr.invalid").await;
    once(
        &server,
        "POST",
        "/v1/pki/revoke",
        "pki.revokeCertificate.ok",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/pki/revoke",
        "pki.revokeCertificate.not-found",
    )
    .await;
    on(&server, "GET", "/v1/pki/ca_chain", "pki.readCaChain.pem").await;
    on(
        &server,
        "GET",
        "/v1/pki/cert/aa:bb",
        "pki.readCertificate.ok",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/pki/cert/cc:dd",
        "pki.readCertificate.revoked",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/pki/cert/ff:ff",
        "pki.readCertificate.not-found",
    )
    .await;
    on_list(&server, "/v1/pki/certs", "pki.listCertificates.ok").await;
    let c = client(&server);
    let pki = c.pki();
    let opts = IssueOptions {
        alt_names: vec!["alt.example.test".into(), "b.example.test".into()],
        ip_sans: vec!["127.0.0.1".into()],
        uri_sans: vec!["spiffe://x".into()],
        ttl: Some(Duration::from_secs(3600)),
        format: Some("pem".into()),
        private_key_format: Some("pkcs8".into()),
        exclude_cn_from_sans: true,
        common_name: Some("ignored-for-issue".into()),
    };
    let cert = pki
        .issue_certificate("web", "svc.example.test", Some(&opts))
        .await
        .unwrap();
    assert!(cert.certificate.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(cert.issuing_ca.starts_with("-----BEGIN CERTIFICATE-----"));
    assert_eq!(cert.ca_chain.len(), 1);
    assert!(cert.private_key.is_some());
    assert_eq!(cert.private_key_type, "ec");
    assert!(cert.serial_number.contains(':'));
    assert!(cert.expiration.is_some());
    assert!(!format!("{cert:?}").contains("PRIVATE KEY-----\nMI"));
    assert_eq!(
        sent(&server, "/v1/pki/issue/web").await[0],
        json!({"common_name": "svc.example.test", "alt_names": "alt.example.test,b.example.test",
               "ip_sans": "127.0.0.1", "uri_sans": "spiffe://x", "ttl": "3600s", "format": "pem",
               "private_key_format": "pkcs8", "exclude_cn_from_sans": true})
    );
    let err = pki
        .issue_certificate("strict", "evil.example.com", None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    assert!(err.message().contains("not allowed by this role"));

    let csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIH\n-----END CERTIFICATE REQUEST-----\n";
    let signed = pki
        .sign_csr(
            "web",
            csr,
            Some(&IssueOptions {
                common_name: Some("csr.example.test".into()),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert!(signed.private_key.is_none());
    assert_eq!(
        sent(&server, "/v1/pki/sign/web").await[0],
        json!({"csr": csr, "common_name": "csr.example.test"})
    );
    pki.sign_csr("web", csr, None).await.unwrap();
    assert_eq!(
        pki.sign_csr("bad", "nope", None).await.unwrap_err().code(),
        ErrorCode::Validation
    );

    let rev = pki.revoke_certificate("aa:bb").await.unwrap();
    assert_eq!(rev.state, "revoked");
    assert!(rev.revocation_time.is_some());
    assert_eq!(
        pki.revoke_certificate("ff:ff").await.unwrap_err().code(),
        ErrorCode::Validation
    );
    let chain = pki.read_ca_chain().await.unwrap();
    assert!(chain.starts_with("-----BEGIN CERTIFICATE-----"));
    let info = pki.read_certificate("aa:bb").await.unwrap();
    assert!(!info.revoked());
    assert!(info.certificate.contains("BEGIN CERTIFICATE"));
    assert!(pki.read_certificate("cc:dd").await.unwrap().revoked());
    assert_eq!(
        pki.read_certificate("ff:ff").await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    assert_eq!(pki.list_certificates().await.unwrap().len(), 3);
    for e in [
        pki.issue_certificate("", "x", None).await.unwrap_err(),
        pki.issue_certificate("r", "", None).await.unwrap_err(),
        pki.sign_csr("r", " ", None).await.unwrap_err(),
        pki.revoke_certificate("").await.unwrap_err(),
        pki.read_certificate("").await.unwrap_err(),
    ] {
        assert_eq!(e.code(), ErrorCode::Validation);
    }
}

#[tokio::test]
async fn tidy_and_status() {
    let server = MockServer::start().await;
    on(&server, "POST", "/v1/pki/tidy", "pki.tidy.accepted").await;
    Mock::given(method("GET"))
        .and(path("/v1/pki/tidy-status"))
        .respond_with(json(
            200,
            json!({"data": {"state": "Running", "error": null}}),
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    on(
        &server,
        "GET",
        "/v1/pki/tidy-status",
        "pki.tidyStatus.finished",
    )
    .await;
    let c = client(&server);
    let pki = c.pki();
    let st = pki.tidy(&TidyOptions::default()).await.unwrap();
    assert_eq!(st.state, "Running");
    assert_eq!(
        sent(&server, "/v1/pki/tidy").await[0],
        json!({"tidy_cert_store": true, "tidy_revoked_certs": true})
    );
    let st = pki
        .tidy(&TidyOptions {
            safety_buffer: Some(Duration::from_secs(1)),
            wait: true,
            wait_timeout: Duration::from_secs(10),
            tidy_cert_store: false,
            tidy_revoked_certs: true,
        })
        .await
        .unwrap();
    assert_eq!(st.state, "Finished");
    assert!(st.error.is_none());
    assert_eq!(st.cert_store_deleted_count, 0);
    assert_eq!(
        sent(&server, "/v1/pki/tidy").await[1],
        json!({"tidy_cert_store": false, "tidy_revoked_certs": true, "safety_buffer": "1s"})
    );
    let server = MockServer::start().await;
    on_reply(
        &server,
        "GET",
        "/v1/pki/tidy-status",
        json(
            200,
            json!({"data": {"state": "Error", "error": "boom", "revoked_cert_deleted_count": 2}}),
        ),
    )
    .await;
    let st = client(&server).pki().tidy_status().await.unwrap();
    assert_eq!(
        (st.state.as_str(), st.error.as_deref()),
        ("Error", Some("boom"))
    );
    assert_eq!(st.revoked_cert_deleted_count, 2);
}
