//! Transit secrets engine (encryption as a service).

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, SystemTime};

use serde_json::{json, Map, Value};

use crate::api::{self, ApiRequest};
use crate::client::OpenBaoClient;
use crate::core::Result;

/// Transit engine at one mount; get it with [`OpenBaoClient::transit`].
#[derive(Debug, Clone)]
pub struct Transit {
    client: OpenBaoClient,
    mount: String,
}

/// One version of a transit key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransitKeyVersion {
    /// Creation time.
    pub creation_time: Option<SystemTime>,
    /// Public key (asymmetric keys only).
    pub public_key: Option<String>,
}

/// A transit key (returned by `read_key` and the key-changing calls).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransitKey {
    /// Key name.
    pub name: String,
    /// Key type (`aes256-gcm96`, `ed25519`, …).
    pub key_type: String,
    /// Versions by number.
    pub keys: BTreeMap<u64, TransitKeyVersion>,
    /// Latest version.
    pub latest_version: u64,
    /// Minimum version allowed for decryption.
    pub min_decryption_version: u64,
    /// Minimum version used for encryption (0 = latest).
    pub min_encryption_version: u64,
    /// Minimum available version.
    pub min_available_version: u64,
    /// Whether the key may be deleted.
    pub deletion_allowed: bool,
    /// Whether the key may be exported.
    pub exportable: bool,
    /// Whether keys are derived per context.
    pub derived: bool,
    /// Whether a plaintext backup is allowed.
    pub allow_plaintext_backup: bool,
    /// Supports encryption.
    pub supports_encryption: bool,
    /// Supports decryption.
    pub supports_decryption: bool,
    /// Supports signing.
    pub supports_signing: bool,
    /// Supports derivation.
    pub supports_derivation: bool,
    /// Whether the key is soft-deleted.
    pub soft_deleted: bool,
    /// Whether the key was imported.
    pub imported_key: bool,
    /// Automatic rotation period (zero = off).
    pub auto_rotate_period: Duration,
}

impl TransitKey {
    fn from_value(d: &Value) -> Self {
        let keys = match d.get("keys") {
            Some(Value::Object(m)) => m
                .iter()
                .filter_map(|(k, v)| {
                    let n: u64 = k.parse().ok()?;
                    let version = match v {
                        Value::Object(_) => TransitKeyVersion {
                            creation_time: api::time(v, "creation_time"),
                            public_key: Some(api::s(v, "public_key")).filter(|s| !s.is_empty()),
                        },
                        _ => TransitKeyVersion {
                            creation_time: api::time(&json!({ "t": v }), "t"),
                            public_key: None,
                        },
                    };
                    Some((n, version))
                })
                .collect(),
            _ => BTreeMap::new(),
        };
        TransitKey {
            name: api::s(d, "name"),
            key_type: api::s(d, "type"),
            keys,
            latest_version: api::u(d, "latest_version"),
            min_decryption_version: api::u(d, "min_decryption_version"),
            min_encryption_version: api::u(d, "min_encryption_version"),
            min_available_version: api::u(d, "min_available_version"),
            deletion_allowed: api::b(d, "deletion_allowed"),
            exportable: api::b(d, "exportable"),
            derived: api::b(d, "derived"),
            allow_plaintext_backup: api::b(d, "allow_plaintext_backup"),
            supports_encryption: api::b(d, "supports_encryption"),
            supports_decryption: api::b(d, "supports_decryption"),
            supports_signing: api::b(d, "supports_signing"),
            supports_derivation: api::b(d, "supports_derivation"),
            soft_deleted: api::b(d, "soft_deleted"),
            imported_key: api::b(d, "imported_key"),
            auto_rotate_period: api::secs(d, "auto_rotate_period"),
        }
    }
}

/// Optional settings of [`Transit::create_key`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateKeyOptions {
    /// Allows exporting the key.
    pub exportable: bool,
    /// Derives keys per context.
    pub derived: bool,
    /// Allows a plaintext backup.
    pub allow_plaintext_backup: bool,
    /// Enables automatic rotation.
    pub auto_rotate_period: Option<Duration>,
}

/// Settings changed by [`Transit::update_key_config`]; unset fields stay unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransitKeyConfig {
    /// Allows deleting the key.
    pub deletion_allowed: Option<bool>,
    /// Minimum version allowed for decryption.
    pub min_decryption_version: Option<u64>,
    /// Minimum version used for encryption.
    pub min_encryption_version: Option<u64>,
    /// Allows exporting the key (cannot be disabled again).
    pub exportable: Option<bool>,
    /// Allows a plaintext backup.
    pub allow_plaintext_backup: Option<bool>,
    /// Automatic rotation period (zero disables it).
    pub auto_rotate_period: Option<Duration>,
}

/// A ciphertext (`vault:v<N>:...`) with the key version that produced it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransitCiphertext {
    /// The ciphertext.
    pub ciphertext: String,
    /// Key version used.
    pub key_version: u64,
}

/// Optional settings of encrypt, decrypt and rewrap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EncryptOptions {
    /// Derivation context for derived keys.
    pub context: Option<Vec<u8>>,
    /// Key version to encrypt with (encrypt/rewrap; `None` = latest).
    pub key_version: Option<u64>,
}

/// One input of a batch call: `plaintext` for encryption, `ciphertext` for decryption.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct TransitBatchItem {
    /// Plaintext (encrypt).
    pub plaintext: Vec<u8>,
    /// Ciphertext (decrypt).
    pub ciphertext: String,
    /// Derivation context.
    pub context: Option<Vec<u8>>,
    /// Echoed in the result.
    pub reference: Option<String>,
}

impl fmt::Debug for TransitBatchItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransitBatchItem")
            .field("ciphertext", &self.ciphertext)
            .field("reference", &self.reference)
            .finish_non_exhaustive()
    }
}

impl TransitBatchItem {
    /// An encryption input.
    pub fn plaintext(plaintext: impl Into<Vec<u8>>) -> Self {
        TransitBatchItem {
            plaintext: plaintext.into(),
            ..Self::default()
        }
    }
    /// A decryption input.
    pub fn ciphertext(ciphertext: impl Into<String>) -> Self {
        TransitBatchItem {
            ciphertext: ciphertext.into(),
            ..Self::default()
        }
    }
    /// Sets the reference echoed in the result.
    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.reference = Some(reference.into());
        self
    }
    /// Sets the derivation context.
    pub fn with_context(mut self, context: impl Into<Vec<u8>>) -> Self {
        self.context = Some(context.into());
        self
    }
}

/// One result of a batch call, in input order. A failed item carries `error`; the call
/// itself succeeds when only some items fail.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct TransitBatchResult {
    /// Ciphertext (encrypt).
    pub ciphertext: String,
    /// Plaintext (decrypt).
    pub plaintext: Vec<u8>,
    /// Key version used.
    pub key_version: u64,
    /// Echoed reference.
    pub reference: String,
    /// Per-item error text (`None` on success).
    pub error: Option<String>,
}

impl fmt::Debug for TransitBatchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransitBatchResult")
            .field("ciphertext", &self.ciphertext)
            .field("key_version", &self.key_version)
            .field("reference", &self.reference)
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// Options of [`Transit::generate_data_key`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataKeyOptions {
    /// Returns only the encrypted data key (no plaintext).
    pub wrapped: bool,
    /// Key size: 128, 256 (default) or 512.
    pub bits: Option<u32>,
    /// Derivation context.
    pub context: Option<Vec<u8>>,
}

/// A generated data key.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct DataKey {
    /// The data key encrypted with the named key.
    pub ciphertext: String,
    /// The raw data key (`None` when wrapped; redacted in `Debug`).
    pub plaintext: Option<Vec<u8>>,
    /// Key version used.
    pub key_version: u64,
}

impl fmt::Debug for DataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataKey")
            .field("ciphertext", &self.ciphertext)
            .field("plaintext", &self.plaintext.as_ref().map(|_| "[REDACTED]"))
            .field("key_version", &self.key_version)
            .finish()
    }
}

/// Options of [`Transit::hmac`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HmacOptions {
    /// Hash algorithm (`sha2-256` default, `sha2-512`, …).
    pub algorithm: Option<String>,
    /// Key version (`None` = latest).
    pub key_version: Option<u64>,
}

/// Options of [`Transit::sign`] and [`Transit::verify`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignOptions {
    /// Hash algorithm (`sha2-256` default; ignored by ed25519). For an HMAC verify, the
    /// HMAC algorithm.
    pub hash_algorithm: Option<String>,
    /// `pss` or `pkcs1v15` for RSA keys.
    pub signature_algorithm: Option<String>,
    /// The input is an already computed hash.
    pub prehashed: bool,
    /// Key version to sign with (sign only; `None` = latest).
    pub key_version: Option<u64>,
    /// Derivation context.
    pub context: Option<Vec<u8>>,
    /// Verify only: checks the value as an HMAC produced by [`Transit::hmac`].
    pub hmac: bool,
}

/// A signature (`vault:v<N>:...`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransitSignature {
    /// The signature.
    pub signature: String,
    /// Key version used.
    pub key_version: u64,
}

/// Options of [`Transit::hash`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HashOptions {
    /// `sha2-256` (default), `sha2-224`, `sha2-384`, `sha2-512`, `sha3-*`.
    pub algorithm: Option<String>,
    /// `hex` (default) or `base64`.
    pub format: Option<String>,
}

fn cipher_body(key: &str, value: String, opts: Option<&EncryptOptions>) -> Value {
    let mut body = Map::new();
    body.insert(key.into(), json!(value));
    if let Some(o) = opts {
        if let Some(c) = o.context.as_deref().filter(|c| !c.is_empty()) {
            body.insert("context".into(), json!(api::b64(c)));
        }
        if let Some(v) = o.key_version.filter(|v| *v > 0) {
            body.insert("key_version".into(), json!(v));
        }
    }
    Value::Object(body)
}

impl Transit {
    pub(crate) fn new(client: OpenBaoClient, mount: &str) -> Self {
        Transit {
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

    fn op(&self, name: &str, key: &str) -> String {
        if key.is_empty() {
            format!("transit.{name}")
        } else {
            format!("transit.{name} {key}")
        }
    }

    fn path(&self, parts: &[&str]) -> String {
        let mut all = vec![self.mount.as_str()];
        all.extend_from_slice(parts);
        api::encode_path(&api::join(&all))
    }

    async fn post(&self, parts: &[&str], op: String, body: Value) -> Result<Value> {
        self.client
            .data(ApiRequest::post(self.path(parts), op).json(body))
            .await
    }

    async fn key_call(&self, req: ApiRequest, name: &str) -> Result<TransitKey> {
        let data = self.client.data(req).await?;
        if api::s(&data, "name").is_empty() {
            return self.read_key(name).await; // servers that answer 204
        }
        Ok(TransitKey::from_value(&data))
    }

    /// Creates a named key of `key_type` (`""` = `aes256-gcm96`; also
    /// `chacha20-poly1305`, `ed25519`, `ecdsa-p256`, `rsa-2048`, …). Creating an existing
    /// key returns it unchanged.
    pub async fn create_key(
        &self,
        name: &str,
        key_type: &str,
        opts: Option<&CreateKeyOptions>,
    ) -> Result<TransitKey> {
        let op = self.op("createKey", name);
        api::require_arg(&op, "name", name)?;
        let mut body = Map::new();
        if !key_type.is_empty() {
            body.insert("type".into(), json!(key_type));
        }
        if let Some(o) = opts {
            if o.exportable {
                body.insert("exportable".into(), json!(true));
            }
            if o.derived {
                body.insert("derived".into(), json!(true));
            }
            if o.allow_plaintext_backup {
                body.insert("allow_plaintext_backup".into(), json!(true));
            }
            if let Some(p) = o.auto_rotate_period.filter(|p| !p.is_zero()) {
                body.insert("auto_rotate_period".into(), json!(api::duration_string(p)));
            }
        }
        let req = ApiRequest::post(self.path(&["keys", name]), op).json(Value::Object(body));
        self.key_call(req, name).await
    }

    /// Reads a key (`NOT_FOUND` when missing).
    pub async fn read_key(&self, name: &str) -> Result<TransitKey> {
        let op = self.op("readKey", name);
        api::require_arg(&op, "name", name)?;
        let data = self
            .client
            .data(ApiRequest::get(self.path(&["keys", name]), op))
            .await?;
        Ok(TransitKey::from_value(&data))
    }

    /// Key names.
    pub async fn list_keys(&self) -> Result<Vec<String>> {
        self.client
            .list_keys(self.path(&["keys"]), self.op("listKeys", ""))
            .await
    }

    /// Adds a new key version.
    pub async fn rotate_key(&self, name: &str) -> Result<TransitKey> {
        let op = self.op("rotateKey", name);
        api::require_arg(&op, "name", name)?;
        let req = ApiRequest::post(self.path(&["keys", name, "rotate"]), op).json(json!({}));
        self.key_call(req, name).await
    }

    /// Changes key settings (deletion, minimum versions, export, rotation).
    pub async fn update_key_config(
        &self,
        name: &str,
        cfg: &TransitKeyConfig,
    ) -> Result<TransitKey> {
        let op = self.op("updateKeyConfig", name);
        api::require_arg(&op, "name", name)?;
        let mut body = Map::new();
        if let Some(v) = cfg.deletion_allowed {
            body.insert("deletion_allowed".into(), json!(v));
        }
        if let Some(v) = cfg.min_decryption_version {
            body.insert("min_decryption_version".into(), json!(v));
        }
        if let Some(v) = cfg.min_encryption_version {
            body.insert("min_encryption_version".into(), json!(v));
        }
        if let Some(v) = cfg.exportable {
            body.insert("exportable".into(), json!(v));
        }
        if let Some(v) = cfg.allow_plaintext_backup {
            body.insert("allow_plaintext_backup".into(), json!(v));
        }
        if let Some(p) = cfg.auto_rotate_period {
            body.insert("auto_rotate_period".into(), json!(api::duration_string(p)));
        }
        let req =
            ApiRequest::post(self.path(&["keys", name, "config"]), op).json(Value::Object(body));
        self.key_call(req, name).await
    }

    /// Deletes a key (`VALIDATION` unless `deletion_allowed` was set).
    pub async fn delete_key(&self, name: &str) -> Result<()> {
        let op = self.op("deleteKey", name);
        api::require_arg(&op, "name", name)?;
        self.client
            .call(ApiRequest::delete(self.path(&["keys", name]), op))
            .await?;
        Ok(())
    }

    /// Encrypts `plaintext` with the named key.
    pub async fn encrypt(
        &self,
        name: &str,
        plaintext: &[u8],
        opts: Option<&EncryptOptions>,
    ) -> Result<TransitCiphertext> {
        let d = self
            .post(
                &["encrypt", name],
                self.op("encrypt", name),
                cipher_body("plaintext", api::b64(plaintext), opts),
            )
            .await?;
        Ok(TransitCiphertext {
            ciphertext: api::s(&d, "ciphertext"),
            key_version: api::u(&d, "key_version"),
        })
    }

    /// Decrypts a ciphertext produced by [`Transit::encrypt`].
    pub async fn decrypt(
        &self,
        name: &str,
        ciphertext: &str,
        opts: Option<&EncryptOptions>,
    ) -> Result<Vec<u8>> {
        let op = self.op("decrypt", name);
        let d = self
            .post(
                &["decrypt", name],
                op.clone(),
                cipher_body("ciphertext", ciphertext.to_owned(), opts),
            )
            .await?;
        api::unb64(&api::s(&d, "plaintext"), &op, "plaintext")
    }

    /// Re-encrypts a ciphertext with the latest (or `opts.key_version`) key version without
    /// exposing the plaintext.
    pub async fn rewrap(
        &self,
        name: &str,
        ciphertext: &str,
        opts: Option<&EncryptOptions>,
    ) -> Result<TransitCiphertext> {
        let d = self
            .post(
                &["rewrap", name],
                self.op("rewrap", name),
                cipher_body("ciphertext", ciphertext.to_owned(), opts),
            )
            .await?;
        Ok(TransitCiphertext {
            ciphertext: api::s(&d, "ciphertext"),
            key_version: api::u(&d, "key_version"),
        })
    }

    async fn batch(
        &self,
        kind: &str,
        name: &str,
        items: &[TransitBatchItem],
        opts: Option<&EncryptOptions>,
    ) -> Result<Vec<TransitBatchResult>> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let encrypt = kind == "encrypt";
        let input: Vec<Value> = items
            .iter()
            .map(|it| {
                let mut m = Map::new();
                if encrypt {
                    m.insert("plaintext".into(), json!(api::b64(&it.plaintext)));
                } else {
                    m.insert("ciphertext".into(), json!(it.ciphertext));
                }
                if let Some(c) = it.context.as_deref().filter(|c| !c.is_empty()) {
                    m.insert("context".into(), json!(api::b64(c)));
                }
                if let Some(r) = &it.reference {
                    m.insert("reference".into(), json!(r));
                }
                Value::Object(m)
            })
            .collect();
        let mut body = json!({ "batch_input": input, "partial_failure_response_code": 207 });
        if let Some(v) = opts
            .and_then(|o| o.key_version)
            .filter(|v| *v > 0 && encrypt)
        {
            body["key_version"] = json!(v);
        }
        let op = self.op(&format!("{kind}Batch"), name);
        let d = self.post(&[kind, name], op, body).await?;
        let results = match d.get("batch_results") {
            Some(Value::Array(r)) => r.clone(),
            _ => Vec::new(),
        };
        Ok(results
            .iter()
            .map(|r| {
                let mut out = TransitBatchResult {
                    ciphertext: api::s(r, "ciphertext"),
                    plaintext: Vec::new(),
                    key_version: api::u(r, "key_version"),
                    reference: api::s(r, "reference"),
                    error: Some(api::s(r, "error")).filter(|e| !e.is_empty()),
                };
                let plain = api::s(r, "plaintext");
                if out.error.is_none() && !plain.is_empty() {
                    match api::unb64(&plain, "", "") {
                        Ok(b) => out.plaintext = b,
                        Err(_) => {
                            out.error = Some("plaintext in the response is not base64".into())
                        }
                    }
                }
                out
            })
            .collect())
    }

    /// Encrypts several plaintexts in one call (`opts.key_version` applies to all).
    pub async fn encrypt_batch(
        &self,
        name: &str,
        items: &[TransitBatchItem],
        opts: Option<&EncryptOptions>,
    ) -> Result<Vec<TransitBatchResult>> {
        self.batch("encrypt", name, items, opts).await
    }

    /// Decrypts several ciphertexts in one call.
    pub async fn decrypt_batch(
        &self,
        name: &str,
        items: &[TransitBatchItem],
    ) -> Result<Vec<TransitBatchResult>> {
        self.batch("decrypt", name, items, None).await
    }

    /// Creates a new high-entropy data key encrypted with the named key.
    pub async fn generate_data_key(&self, name: &str, opts: &DataKeyOptions) -> Result<DataKey> {
        let kind = if opts.wrapped { "wrapped" } else { "plaintext" };
        let mut body = Map::new();
        if let Some(bits) = opts.bits.filter(|b| *b > 0) {
            body.insert("bits".into(), json!(bits));
        }
        if let Some(c) = opts.context.as_deref().filter(|c| !c.is_empty()) {
            body.insert("context".into(), json!(api::b64(c)));
        }
        let op = self.op("generateDataKey", name);
        let d = self
            .post(&["datakey", kind, name], op.clone(), Value::Object(body))
            .await?;
        let plain = api::s(&d, "plaintext");
        let plaintext = if plain.is_empty() {
            None
        } else {
            Some(api::unb64(&plain, &op, "plaintext")?)
        };
        Ok(DataKey {
            ciphertext: api::s(&d, "ciphertext"),
            plaintext,
            key_version: api::u(&d, "key_version"),
        })
    }

    /// HMAC of `input` with the named key (`vault:v<N>:...`).
    pub async fn hmac(
        &self,
        name: &str,
        input: &[u8],
        opts: Option<&HmacOptions>,
    ) -> Result<String> {
        let mut parts = vec!["hmac", name];
        let mut body = json!({ "input": api::b64(input) });
        if let Some(o) = opts {
            if let Some(a) = o.algorithm.as_deref().filter(|a| !a.is_empty()) {
                parts.push(a);
            }
            if let Some(v) = o.key_version.filter(|v| *v > 0) {
                body["key_version"] = json!(v);
            }
        }
        let d = self.post(&parts, self.op("hmac", name), body).await?;
        Ok(api::s(&d, "hmac"))
    }

    fn sign_body<'a>(
        input: &[u8],
        opts: Option<&'a SignOptions>,
        verify: bool,
    ) -> (Option<&'a str>, Value) {
        let mut body = json!({ "input": api::b64(input) });
        let mut hash = None;
        if let Some(o) = opts {
            hash = o.hash_algorithm.as_deref().filter(|h| !h.is_empty());
            if let Some(a) = &o.signature_algorithm {
                body["signature_algorithm"] = json!(a);
            }
            if o.prehashed {
                body["prehashed"] = json!(true);
            }
            if let Some(v) = o.key_version.filter(|v| *v > 0 && !verify) {
                body["key_version"] = json!(v);
            }
            if let Some(c) = o.context.as_deref().filter(|c| !c.is_empty()) {
                body["context"] = json!(api::b64(c));
            }
        }
        (hash, body)
    }

    /// Signs `input` with an asymmetric key (`VALIDATION` for symmetric keys).
    pub async fn sign(
        &self,
        name: &str,
        input: &[u8],
        opts: Option<&SignOptions>,
    ) -> Result<TransitSignature> {
        let (hash, body) = Self::sign_body(input, opts, false);
        let mut parts = vec!["sign", name];
        parts.extend(hash);
        let d = self.post(&parts, self.op("sign", name), body).await?;
        Ok(TransitSignature {
            signature: api::s(&d, "signature"),
            key_version: api::u(&d, "key_version"),
        })
    }

    /// Checks a signature (or, with `opts.hmac`, an HMAC) of `input`. An invalid
    /// signature is `Ok(false)`, not an error.
    pub async fn verify(
        &self,
        name: &str,
        input: &[u8],
        signature: &str,
        opts: Option<&SignOptions>,
    ) -> Result<bool> {
        let (hash, mut body) = Self::sign_body(input, opts, true);
        let field = if opts.is_some_and(|o| o.hmac) {
            "hmac"
        } else {
            "signature"
        };
        body[field] = json!(signature);
        let mut parts = vec!["verify", name];
        parts.extend(hash);
        let d = self.post(&parts, self.op("verify", name), body).await?;
        Ok(api::b(&d, "valid"))
    }

    /// Digest of `input` (hex by default).
    pub async fn hash(&self, input: &[u8], opts: Option<&HashOptions>) -> Result<String> {
        let mut parts = vec!["hash"];
        let mut body = json!({ "input": api::b64(input) });
        if let Some(o) = opts {
            if let Some(a) = o.algorithm.as_deref().filter(|a| !a.is_empty()) {
                parts.push(a);
            }
            if let Some(f) = &o.format {
                body["format"] = json!(f);
            }
        }
        let d = self.post(&parts, self.op("hash", ""), body).await?;
        Ok(api::s(&d, "sum"))
    }

    /// `n` random bytes from the server, encoded as `format` (`base64` default, or `hex`).
    pub async fn random_bytes(&self, n: usize, format: Option<&str>) -> Result<String> {
        let op = self.op("randomBytes", "");
        if n == 0 {
            return Err(api::invalid(&op, "n must be positive"));
        }
        let mut body = Map::new();
        if let Some(f) = format.filter(|f| !f.is_empty()) {
            body.insert("format".into(), json!(f.to_ascii_lowercase()));
        }
        let n = n.to_string();
        let d = self.post(&["random", &n], op, Value::Object(body)).await?;
        Ok(api::s(&d, "random_bytes"))
    }
}
