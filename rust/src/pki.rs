//! PKI secrets engine: issue, sign, revoke and read certificates.

use std::time::{Duration, SystemTime};

use serde_json::{json, Map, Value};

use crate::api::{self, ApiRequest};
use crate::client::OpenBaoClient;
use crate::core::{poll_until, PollOptions, Result, Secret};

/// An issued or signed certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Certificate {
    /// PEM certificate.
    pub certificate: String,
    /// PEM certificate of the issuer.
    pub issuing_ca: String,
    /// PEM chain (issuer first).
    pub ca_chain: Vec<String>,
    /// PEM private key (`issue_certificate` only; redacted when printed).
    pub private_key: Option<Secret>,
    /// Private key type (`ec`, `rsa`, …).
    pub private_key_type: String,
    /// Colon-separated hex serial (`56:f1:…`).
    pub serial_number: String,
    /// Expiry time.
    pub expiration: Option<SystemTime>,
}

/// Options of [`Pki::issue_certificate`] and [`Pki::sign_csr`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IssueOptions {
    /// DNS / email subject alternative names.
    pub alt_names: Vec<String>,
    /// IP subject alternative names.
    pub ip_sans: Vec<String>,
    /// URI subject alternative names.
    pub uri_sans: Vec<String>,
    /// Requested TTL.
    pub ttl: Option<Duration>,
    /// `pem` (default), `der` or `pem_bundle`.
    pub format: Option<String>,
    /// `der` (default) or `pkcs8` (issue only).
    pub private_key_format: Option<String>,
    /// Leaves the common name out of the SANs.
    pub exclude_cn_from_sans: bool,
    /// Common name (sign only; defaults to the CSR's).
    pub common_name: Option<String>,
}

impl IssueOptions {
    fn apply(&self, body: &mut Map<String, Value>) {
        for (k, v) in [
            ("alt_names", &self.alt_names),
            ("ip_sans", &self.ip_sans),
            ("uri_sans", &self.uri_sans),
        ] {
            if !v.is_empty() {
                body.insert(k.into(), json!(v.join(",")));
            }
        }
        if let Some(t) = self.ttl.filter(|t| !t.is_zero()) {
            body.insert("ttl".into(), json!(api::duration_string(t)));
        }
        if let Some(f) = &self.format {
            body.insert("format".into(), json!(f));
        }
        if let Some(f) = &self.private_key_format {
            body.insert("private_key_format".into(), json!(f));
        }
        if self.exclude_cn_from_sans {
            body.insert("exclude_cn_from_sans".into(), json!(true));
        }
        if let Some(cn) = &self.common_name {
            body.entry("common_name").or_insert_with(|| json!(cn));
        }
    }
}

/// Result of [`Pki::revoke_certificate`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Revocation {
    /// Revocation time.
    pub revocation_time: Option<SystemTime>,
    /// State (`revoked`).
    pub state: String,
}

/// Result of [`Pki::read_certificate`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateInfo {
    /// PEM certificate.
    pub certificate: String,
    /// Revocation time (`None` = not revoked).
    pub revocation_time: Option<SystemTime>,
}

impl CertificateInfo {
    /// Whether the certificate is revoked.
    pub fn revoked(&self) -> bool {
        self.revocation_time.is_some()
    }
}

/// Options of [`Pki::tidy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TidyOptions {
    /// Removes expired certificates from storage (default true).
    pub tidy_cert_store: bool,
    /// Removes expired revoked certificates (default true).
    pub tidy_revoked_certs: bool,
    /// How long past expiry certificates are kept (server default 72 h).
    pub safety_buffer: Option<Duration>,
    /// Polls `tidy-status` until the run finishes (every 500 ms, at most `wait_timeout`).
    pub wait: bool,
    /// Bound of `wait` (default 60 s).
    pub wait_timeout: Duration,
}

impl Default for TidyOptions {
    fn default() -> Self {
        TidyOptions {
            tidy_cert_store: true,
            tidy_revoked_certs: true,
            safety_buffer: None,
            wait: false,
            wait_timeout: Duration::from_secs(60),
        }
    }
}

/// State of the current or last tidy run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TidyStatus {
    /// `Inactive`, `Running`, `Finished`, `Error` or `Cancelled`.
    pub state: String,
    /// Error text of a failed run.
    pub error: Option<String>,
    /// Certificates removed from the store.
    pub cert_store_deleted_count: u64,
    /// Revoked certificates removed.
    pub revoked_cert_deleted_count: u64,
}

/// PKI engine at one mount; get it with [`OpenBaoClient::pki`].
#[derive(Debug, Clone)]
pub struct Pki {
    client: OpenBaoClient,
    mount: String,
}

impl Pki {
    pub(crate) fn new(client: OpenBaoClient, mount: &str) -> Self {
        Pki {
            client,
            mount: mount.to_owned(),
        }
    }

    /// The same engine at another mount.
    pub fn at(mut self, mount: &str) -> Self {
        self.mount = api::mount_or(mount, &self.mount);
        self
    }

    /// The mount path.
    pub fn mount(&self) -> &str {
        &self.mount
    }

    fn path(&self, parts: &[&str]) -> String {
        let mut all = vec![self.mount.as_str()];
        all.extend_from_slice(parts);
        api::encode_path(&api::join(&all))
    }

    async fn cert_call(&self, path: String, op: String, body: Value) -> Result<Certificate> {
        let d = self
            .client
            .data(ApiRequest::post(path, op).json(body))
            .await?;
        let key = api::s(&d, "private_key");
        let private_key = (!key.is_empty()).then(|| Secret::new(key));
        if let Some(k) = &private_key {
            self.client.remember_secret(k);
        }
        Ok(Certificate {
            certificate: api::s(&d, "certificate"),
            issuing_ca: api::s(&d, "issuing_ca"),
            ca_chain: api::strings(&d, "ca_chain"),
            private_key,
            private_key_type: api::s(&d, "private_key_type"),
            serial_number: api::s(&d, "serial_number"),
            expiration: api::time(&d, "expiration"),
        })
    }

    /// Issues a certificate and private key for `common_name` with `role`
    /// (`POST <mount>/issue/<role>`). A name the role does not allow is `VALIDATION`.
    pub async fn issue_certificate(
        &self,
        role: &str,
        common_name: &str,
        opts: Option<&IssueOptions>,
    ) -> Result<Certificate> {
        let op = format!("pki.issueCertificate {role}");
        api::require_arg(&op, "role", role)?;
        api::require_arg(&op, "common_name", common_name)?;
        let mut body = Map::new();
        body.insert("common_name".into(), json!(common_name));
        if let Some(o) = opts {
            o.apply(&mut body);
        }
        self.cert_call(self.path(&["issue", role]), op, Value::Object(body))
            .await
    }

    /// Signs a PEM certificate signing request with `role` (`POST <mount>/sign/<role>`).
    pub async fn sign_csr(
        &self,
        role: &str,
        csr: &str,
        opts: Option<&IssueOptions>,
    ) -> Result<Certificate> {
        let op = format!("pki.signCsr {role}");
        api::require_arg(&op, "role", role)?;
        api::require_arg(&op, "csr", csr)?;
        let mut body = Map::new();
        body.insert("csr".into(), json!(csr));
        if let Some(o) = opts {
            o.apply(&mut body);
        }
        self.cert_call(self.path(&["sign", role]), op, Value::Object(body))
            .await
    }

    /// Revokes a certificate by serial (`POST <mount>/revoke`); an unknown serial is
    /// `VALIDATION`.
    pub async fn revoke_certificate(&self, serial: &str) -> Result<Revocation> {
        let op = "pki.revokeCertificate";
        api::require_arg(op, "serial", serial)?;
        let d = self
            .client
            .data(
                ApiRequest::post(self.path(&["revoke"]), op)
                    .json(json!({ "serial_number": serial })),
            )
            .await?;
        Ok(Revocation {
            revocation_time: api::time(&d, "revocation_time_rfc3339")
                .or_else(|| api::time(&d, "revocation_time")),
            state: api::s(&d, "state"),
        })
    }

    /// The CA chain as concatenated PEM (`GET <mount>/ca_chain`, raw text).
    pub async fn read_ca_chain(&self) -> Result<String> {
        let resp = self
            .client
            .send(ApiRequest::get(self.path(&["ca_chain"]), "pki.readCaChain"))
            .await?;
        resp.text()
    }

    /// A certificate by serial (`NOT_FOUND` when unknown; `ca`, `ca_chain` and `crl` are
    /// also accepted).
    pub async fn read_certificate(&self, serial: &str) -> Result<CertificateInfo> {
        let op = format!("pki.readCertificate {serial}");
        api::require_arg(&op, "serial", serial)?;
        let d = self
            .client
            .data(ApiRequest::get(self.path(&["cert", serial]), op))
            .await?;
        Ok(CertificateInfo {
            certificate: api::s(&d, "certificate"),
            revocation_time: api::time(&d, "revocation_time_rfc3339")
                .or_else(|| api::time(&d, "revocation_time")),
        })
    }

    /// Serial numbers of the stored certificates.
    pub async fn list_certificates(&self) -> Result<Vec<String>> {
        self.client
            .list_keys(self.path(&["certs"]), "pki.listCertificates".into())
            .await
    }

    /// Starts a tidy run (`POST <mount>/tidy`, answered 202) and optionally waits for it.
    pub async fn tidy(&self, opts: &TidyOptions) -> Result<TidyStatus> {
        let mut body = json!({
            "tidy_cert_store": opts.tidy_cert_store,
            "tidy_revoked_certs": opts.tidy_revoked_certs,
        });
        if let Some(b) = opts.safety_buffer.filter(|b| !b.is_zero()) {
            body["safety_buffer"] = json!(api::duration_string(b));
        }
        self.client
            .call(ApiRequest::post(self.path(&["tidy"]), "pki.tidy").json(body))
            .await?;
        if !opts.wait {
            return Ok(TidyStatus {
                state: "Running".into(),
                ..TidyStatus::default()
            });
        }
        let poll = PollOptions {
            timeout: opts.wait_timeout,
            interval: Duration::from_millis(500),
        };
        poll_until("pki.tidy", poll, || async {
            let st = self.tidy_status().await?;
            Ok((st.state != "Running").then_some(st))
        })
        .await
    }

    /// State of the current or last tidy run (`GET <mount>/tidy-status`).
    pub async fn tidy_status(&self) -> Result<TidyStatus> {
        let d = self
            .client
            .data(ApiRequest::get(
                self.path(&["tidy-status"]),
                "pki.tidyStatus",
            ))
            .await?;
        Ok(TidyStatus {
            state: api::s(&d, "state"),
            error: Some(api::s(&d, "error")).filter(|e| !e.is_empty()),
            cert_store_deleted_count: api::u(&d, "cert_store_deleted_count"),
            revoked_cert_deleted_count: api::u(&d, "revoked_cert_deleted_count"),
        })
    }
}
