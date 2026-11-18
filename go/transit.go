package openbao

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Transit is the transit secrets engine (encryption as a service). Plaintext,
// input and context values are raw bytes (base64-encoded on the wire);
// ciphertexts, signatures and HMACs are "vault:v<N>:..." strings.
type Transit struct {
	c     *Client
	mount string
}

// Transit returns the transit engine at mount ("" = "transit").
func (c *Client) Transit(mount string) *Transit {
	return &Transit{c: c, mount: mountOr(mount, "transit")}
}

// Mount returns the mount path.
func (t *Transit) Mount() string { return t.mount }

// TransitKeyVersion is one version of a transit key.
type TransitKeyVersion struct {
	CreationTime time.Time
	// PublicKey is set for asymmetric keys.
	PublicKey string
}

// TransitKey describes a transit key (ReadKey and the key-changing calls).
type TransitKey struct {
	Name                 string
	Type                 string
	Keys                 map[int]TransitKeyVersion
	LatestVersion        int
	MinDecryptionVersion int
	MinEncryptionVersion int
	MinAvailableVersion  int
	DeletionAllowed      bool
	Exportable           bool
	Derived              bool
	AllowPlaintextBackup bool
	SupportsEncryption   bool
	SupportsDecryption   bool
	SupportsSigning      bool
	SupportsDerivation   bool
	SoftDeleted          bool
	ImportedKey          bool
	AutoRotatePeriod     time.Duration
}

type transitKeyJSON struct {
	Name                 string                     `json:"name"`
	Type                 string                     `json:"type"`
	Keys                 map[string]json.RawMessage `json:"keys"`
	LatestVersion        int                        `json:"latest_version"`
	MinDecryptionVersion int                        `json:"min_decryption_version"`
	MinEncryptionVersion int                        `json:"min_encryption_version"`
	MinAvailableVersion  int                        `json:"min_available_version"`
	DeletionAllowed      bool                       `json:"deletion_allowed"`
	Exportable           bool                       `json:"exportable"`
	Derived              bool                       `json:"derived"`
	AllowPlaintextBackup bool                       `json:"allow_plaintext_backup"`
	SupportsEncryption   bool                       `json:"supports_encryption"`
	SupportsDecryption   bool                       `json:"supports_decryption"`
	SupportsSigning      bool                       `json:"supports_signing"`
	SupportsDerivation   bool                       `json:"supports_derivation"`
	SoftDeleted          bool                       `json:"soft_deleted"`
	ImportedKey          bool                       `json:"imported_key"`
	AutoRotatePeriod     flexDuration               `json:"auto_rotate_period"`
}

func (k *transitKeyJSON) public() *TransitKey {
	out := &TransitKey{
		Name: k.Name, Type: k.Type, Keys: make(map[int]TransitKeyVersion, len(k.Keys)),
		LatestVersion: k.LatestVersion, MinDecryptionVersion: k.MinDecryptionVersion,
		MinEncryptionVersion: k.MinEncryptionVersion, MinAvailableVersion: k.MinAvailableVersion,
		DeletionAllowed: k.DeletionAllowed, Exportable: k.Exportable, Derived: k.Derived,
		AllowPlaintextBackup: k.AllowPlaintextBackup, SupportsEncryption: k.SupportsEncryption,
		SupportsDecryption: k.SupportsDecryption, SupportsSigning: k.SupportsSigning,
		SupportsDerivation: k.SupportsDerivation, SoftDeleted: k.SoftDeleted, ImportedKey: k.ImportedKey,
		AutoRotatePeriod: k.AutoRotatePeriod.Duration,
	}
	for key, raw := range k.Keys {
		n, err := strconv.Atoi(key)
		if err != nil {
			continue
		}
		var v TransitKeyVersion
		var ts flexTime
		var obj struct {
			CreationTime flexTime `json:"creation_time"`
			PublicKey    string   `json:"public_key"`
		}
		if json.Unmarshal(raw, &obj) == nil {
			v = TransitKeyVersion{CreationTime: obj.CreationTime.Time, PublicKey: obj.PublicKey}
		} else if json.Unmarshal(raw, &ts) == nil {
			v.CreationTime = ts.Time
		}
		out.Keys[n] = v
	}
	return out
}

func (t *Transit) op(name, key string) string {
	if key == "" {
		return "transit." + name
	}
	return "transit." + name + " " + key
}

func (t *Transit) keyCall(ctx context.Context, method, path, op string, body any) (*TransitKey, error) {
	var d transitKeyJSON
	env, err := t.c.call(ctx, apiRequest{method: method, path: joinPath(t.mount, path), body: body, op: op})
	if err != nil {
		return nil, err
	}
	if err := env.decodeData(&d); err != nil {
		return nil, err
	}
	return d.public(), nil
}

// CreateKeyOptions are optional key settings for CreateKey.
type CreateKeyOptions struct {
	Exportable           bool
	Derived              bool
	AllowPlaintextBackup bool
	// AutoRotatePeriod enables automatic rotation (0 = off).
	AutoRotatePeriod time.Duration
}

// CreateKey creates a named key of keyType ("" = "aes256-gcm96"; also
// "chacha20-poly1305", "ed25519", "ecdsa-p256", "rsa-2048", ...). Creating an
// existing key returns it unchanged.
func (t *Transit) CreateKey(ctx context.Context, name, keyType string, opts *CreateKeyOptions) (*TransitKey, error) {
	op := t.op("createKey", name)
	if err := requireArg(op, "name", name); err != nil {
		return nil, err
	}
	body := map[string]any{}
	if keyType != "" {
		body["type"] = keyType
	}
	if opts != nil {
		if opts.Exportable {
			body["exportable"] = true
		}
		if opts.Derived {
			body["derived"] = true
		}
		if opts.AllowPlaintextBackup {
			body["allow_plaintext_backup"] = true
		}
		if opts.AutoRotatePeriod > 0 {
			body["auto_rotate_period"] = durationString(opts.AutoRotatePeriod)
		}
	}
	k, err := t.keyCall(ctx, http.MethodPost, "keys/"+name, op, body)
	if err != nil {
		return nil, err
	}
	if k.Name == "" { // older servers answer 204
		return t.ReadKey(ctx, name)
	}
	return k, nil
}

// ReadKey returns a key (NOT_FOUND when missing).
func (t *Transit) ReadKey(ctx context.Context, name string) (*TransitKey, error) {
	return t.keyCall(ctx, http.MethodGet, "keys/"+name, t.op("readKey", name), nil)
}

// ListKeys returns the key names (empty when there are none).
func (t *Transit) ListKeys(ctx context.Context) ([]string, error) {
	return t.c.list(ctx, joinPath(t.mount, "keys"), t.op("listKeys", ""))
}

// RotateKey adds a new key version and returns the key.
func (t *Transit) RotateKey(ctx context.Context, name string) (*TransitKey, error) {
	k, err := t.keyCall(ctx, http.MethodPost, "keys/"+name+"/rotate", t.op("rotateKey", name), nil)
	if err == nil && k.Name == "" {
		return t.ReadKey(ctx, name)
	}
	return k, err
}

// TransitKeyConfig are the key settings UpdateKeyConfig changes; nil fields are left unchanged.
type TransitKeyConfig struct {
	DeletionAllowed      *bool
	MinDecryptionVersion *int
	MinEncryptionVersion *int
	Exportable           *bool
	AllowPlaintextBackup *bool
	AutoRotatePeriod     *time.Duration
}

// UpdateKeyConfig changes a key's settings and returns the key.
func (t *Transit) UpdateKeyConfig(ctx context.Context, name string, cfg TransitKeyConfig) (*TransitKey, error) {
	body := map[string]any{}
	if cfg.DeletionAllowed != nil {
		body["deletion_allowed"] = *cfg.DeletionAllowed
	}
	if cfg.MinDecryptionVersion != nil {
		body["min_decryption_version"] = *cfg.MinDecryptionVersion
	}
	if cfg.MinEncryptionVersion != nil {
		body["min_encryption_version"] = *cfg.MinEncryptionVersion
	}
	if cfg.Exportable != nil {
		body["exportable"] = *cfg.Exportable
	}
	if cfg.AllowPlaintextBackup != nil {
		body["allow_plaintext_backup"] = *cfg.AllowPlaintextBackup
	}
	if cfg.AutoRotatePeriod != nil {
		body["auto_rotate_period"] = durationString(*cfg.AutoRotatePeriod)
	}
	k, err := t.keyCall(ctx, http.MethodPost, "keys/"+name+"/config", t.op("updateKeyConfig", name), body)
	if err == nil && k.Name == "" {
		return t.ReadKey(ctx, name)
	}
	return k, err
}

// DeleteKey deletes a key; it must have DeletionAllowed (VALIDATION error otherwise).
func (t *Transit) DeleteKey(ctx context.Context, name string) error {
	_, err := t.c.call(ctx, apiRequest{method: http.MethodDelete, path: joinPath(t.mount, "keys", name), op: t.op("deleteKey", name)})
	return err
}

// TransitCiphertext is the result of Encrypt and Rewrap.
type TransitCiphertext struct {
	Ciphertext string
	KeyVersion int
}

// EncryptOptions are optional Encrypt/Rewrap settings.
type EncryptOptions struct {
	// Context is the derivation context for derived keys.
	Context []byte
	// KeyVersion encrypts with this key version (0 = latest).
	KeyVersion int
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func (t *Transit) data(ctx context.Context, path, op string, body map[string]any, out any) error {
	return t.c.callData(ctx, apiRequest{method: http.MethodPost, path: joinPath(t.mount, path), body: body, op: op}, out)
}

func cipherBody(key string, value string, opts *EncryptOptions) map[string]any {
	body := map[string]any{key: value}
	if opts != nil {
		if len(opts.Context) > 0 {
			body["context"] = b64(opts.Context)
		}
		if opts.KeyVersion > 0 {
			body["key_version"] = opts.KeyVersion
		}
	}
	return body
}

// Encrypt encrypts plaintext with the named key.
func (t *Transit) Encrypt(ctx context.Context, name string, plaintext []byte, opts *EncryptOptions) (*TransitCiphertext, error) {
	var d struct {
		Ciphertext string `json:"ciphertext"`
		KeyVersion int    `json:"key_version"`
	}
	if err := t.data(ctx, "encrypt/"+name, t.op("encrypt", name), cipherBody("plaintext", b64(plaintext), opts), &d); err != nil {
		return nil, err
	}
	return &TransitCiphertext{Ciphertext: d.Ciphertext, KeyVersion: d.KeyVersion}, nil
}

// Decrypt decrypts a ciphertext produced by Encrypt (opts.Context for derived keys).
func (t *Transit) Decrypt(ctx context.Context, name, ciphertext string, opts *EncryptOptions) ([]byte, error) {
	var d struct {
		Plaintext string `json:"plaintext"`
	}
	op := t.op("decrypt", name)
	if err := t.data(ctx, "decrypt/"+name, op, cipherBody("ciphertext", ciphertext, opts), &d); err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(d.Plaintext)
	if err != nil {
		return nil, &Error{Code: ErrorCodeUnavailable, Message: op + ": plaintext in the response is not base64"}
	}
	return b, nil
}

// Rewrap re-encrypts a ciphertext with the latest (or opts.KeyVersion) key
// version without exposing the plaintext.
func (t *Transit) Rewrap(ctx context.Context, name, ciphertext string, opts *EncryptOptions) (*TransitCiphertext, error) {
	var d struct {
		Ciphertext string `json:"ciphertext"`
		KeyVersion int    `json:"key_version"`
	}
	if err := t.data(ctx, "rewrap/"+name, t.op("rewrap", name), cipherBody("ciphertext", ciphertext, opts), &d); err != nil {
		return nil, err
	}
	return &TransitCiphertext{Ciphertext: d.Ciphertext, KeyVersion: d.KeyVersion}, nil
}

// TransitBatchItem is one input of EncryptBatch (Plaintext) or DecryptBatch (Ciphertext).
type TransitBatchItem struct {
	Plaintext  []byte
	Ciphertext string
	Context    []byte
	// Reference is echoed in the result.
	Reference string
}

// TransitBatchResult is one result of EncryptBatch/DecryptBatch, in input order.
// Error is the per-item error text ("" on success); the call itself succeeds
// when only some items fail.
type TransitBatchResult struct {
	Ciphertext string
	Plaintext  []byte
	KeyVersion int
	Reference  string
	Error      string
}

func (t *Transit) batch(ctx context.Context, kind, name string, items []TransitBatchItem, opts *EncryptOptions) ([]TransitBatchResult, error) {
	op := t.op(kind+"Batch", name)
	if len(items) == 0 {
		return []TransitBatchResult{}, nil
	}
	input := make([]map[string]any, len(items))
	for i, it := range items {
		m := map[string]any{}
		if kind == "encrypt" {
			m["plaintext"] = b64(it.Plaintext)
		} else {
			m["ciphertext"] = it.Ciphertext
		}
		if len(it.Context) > 0 {
			m["context"] = b64(it.Context)
		}
		if it.Reference != "" {
			m["reference"] = it.Reference
		}
		input[i] = m
	}
	body := map[string]any{"batch_input": input, "partial_failure_response_code": http.StatusMultiStatus}
	if opts != nil && opts.KeyVersion > 0 && kind == "encrypt" {
		body["key_version"] = opts.KeyVersion
	}
	var d struct {
		BatchResults []struct {
			Ciphertext string `json:"ciphertext"`
			Plaintext  string `json:"plaintext"`
			KeyVersion int    `json:"key_version"`
			Reference  string `json:"reference"`
			Error      string `json:"error"`
		} `json:"batch_results"`
	}
	if err := t.data(ctx, kind+"/"+name, op, body, &d); err != nil {
		return nil, err
	}
	out := make([]TransitBatchResult, len(d.BatchResults))
	for i, r := range d.BatchResults {
		out[i] = TransitBatchResult{Ciphertext: r.Ciphertext, KeyVersion: r.KeyVersion, Reference: r.Reference, Error: r.Error}
		if r.Plaintext != "" && r.Error == "" {
			b, err := base64.StdEncoding.DecodeString(r.Plaintext)
			if err != nil {
				out[i].Error = "plaintext in the response is not base64"
			}
			out[i].Plaintext = b
		}
	}
	return out, nil
}

// EncryptBatch encrypts several plaintexts in one call (opts.KeyVersion applies to all).
func (t *Transit) EncryptBatch(ctx context.Context, name string, items []TransitBatchItem, opts *EncryptOptions) ([]TransitBatchResult, error) {
	return t.batch(ctx, "encrypt", name, items, opts)
}

// DecryptBatch decrypts several ciphertexts in one call.
func (t *Transit) DecryptBatch(ctx context.Context, name string, items []TransitBatchItem) ([]TransitBatchResult, error) {
	return t.batch(ctx, "decrypt", name, items, nil)
}

// DataKeyOptions configure GenerateDataKey.
type DataKeyOptions struct {
	// Wrapped returns only the encrypted data key (no plaintext).
	Wrapped bool
	// Bits is the key size: 128, 256 (default) or 512.
	Bits int
	// Context is the derivation context for derived keys.
	Context []byte
}

// DataKey is a generated data key.
type DataKey struct {
	// Ciphertext is the data key encrypted with the named key.
	Ciphertext string
	// Plaintext is the raw data key (nil when Wrapped).
	Plaintext  []byte
	KeyVersion int
}

// GenerateDataKey creates a new high-entropy key encrypted with the named key.
func (t *Transit) GenerateDataKey(ctx context.Context, name string, opts *DataKeyOptions) (*DataKey, error) {
	o := DataKeyOptions{}
	if opts != nil {
		o = *opts
	}
	kind := "plaintext"
	if o.Wrapped {
		kind = "wrapped"
	}
	body := map[string]any{}
	if o.Bits > 0 {
		body["bits"] = o.Bits
	}
	if len(o.Context) > 0 {
		body["context"] = b64(o.Context)
	}
	var d struct {
		Ciphertext string `json:"ciphertext"`
		Plaintext  string `json:"plaintext"`
		KeyVersion int    `json:"key_version"`
	}
	op := t.op("generateDataKey", name)
	if err := t.data(ctx, "datakey/"+kind+"/"+name, op, body, &d); err != nil {
		return nil, err
	}
	dk := &DataKey{Ciphertext: d.Ciphertext, KeyVersion: d.KeyVersion}
	if d.Plaintext != "" {
		b, err := base64.StdEncoding.DecodeString(d.Plaintext)
		if err != nil {
			return nil, &Error{Code: ErrorCodeUnavailable, Message: op + ": plaintext in the response is not base64"}
		}
		dk.Plaintext = b
	}
	return dk, nil
}

// HMACOptions configure HMAC.
type HMACOptions struct {
	// Algorithm is the hash ("sha2-256" default, "sha2-512", ...).
	Algorithm  string
	KeyVersion int
}

// HMAC returns the HMAC of input with the named key ("vault:v<N>:...").
func (t *Transit) HMAC(ctx context.Context, name string, input []byte, opts *HMACOptions) (string, error) {
	path := "hmac/" + name
	body := map[string]any{"input": b64(input)}
	if opts != nil {
		if opts.Algorithm != "" {
			path += "/" + opts.Algorithm
		}
		if opts.KeyVersion > 0 {
			body["key_version"] = opts.KeyVersion
		}
	}
	var d struct {
		HMAC string `json:"hmac"`
	}
	if err := t.data(ctx, path, t.op("hmac", name), body, &d); err != nil {
		return "", err
	}
	return d.HMAC, nil
}

// SignOptions configure Sign and Verify.
type SignOptions struct {
	// HashAlgorithm is the hash ("sha2-256" default; ignored by ed25519).
	HashAlgorithm string
	// SignatureAlgorithm is "pss" or "pkcs1v15" for RSA keys.
	SignatureAlgorithm string
	// Prehashed marks input as an already computed hash.
	Prehashed bool
	// KeyVersion signs with this key version (0 = latest; Sign only).
	KeyVersion int
	// Context is the derivation context for derived keys.
	Context []byte
}

func signBody(input []byte, opts *SignOptions) (string, map[string]any) {
	body := map[string]any{"input": b64(input)}
	suffix := ""
	if opts != nil {
		if opts.HashAlgorithm != "" {
			suffix = "/" + opts.HashAlgorithm
		}
		if opts.SignatureAlgorithm != "" {
			body["signature_algorithm"] = opts.SignatureAlgorithm
		}
		if opts.Prehashed {
			body["prehashed"] = true
		}
		if opts.KeyVersion > 0 {
			body["key_version"] = opts.KeyVersion
		}
		if len(opts.Context) > 0 {
			body["context"] = b64(opts.Context)
		}
	}
	return suffix, body
}

// TransitSignature is the result of Sign.
type TransitSignature struct {
	Signature  string
	KeyVersion int
}

// Sign signs input with an asymmetric key (VALIDATION error for symmetric keys).
func (t *Transit) Sign(ctx context.Context, name string, input []byte, opts *SignOptions) (*TransitSignature, error) {
	suffix, body := signBody(input, opts)
	var d struct {
		Signature  string `json:"signature"`
		KeyVersion int    `json:"key_version"`
	}
	if err := t.data(ctx, "sign/"+name+suffix, t.op("sign", name), body, &d); err != nil {
		return nil, err
	}
	return &TransitSignature{Signature: d.Signature, KeyVersion: d.KeyVersion}, nil
}

// VerifyOptions configure Verify.
type VerifyOptions struct {
	SignOptions
	// HMAC verifies signature as an HMAC produced by HMAC (opts.HashAlgorithm
	// is then the HMAC algorithm).
	HMAC bool
}

// Verify checks a signature (or, with opts.HMAC, an HMAC) of input. An
// invalid signature is (false, nil), not an error.
func (t *Transit) Verify(ctx context.Context, name string, input []byte, signature string, opts *VerifyOptions) (bool, error) {
	var so *SignOptions
	field := "signature"
	if opts != nil {
		s := opts.SignOptions
		s.KeyVersion = 0
		so = &s
		if opts.HMAC {
			field = "hmac"
		}
	}
	suffix, body := signBody(input, so)
	body[field] = signature
	var d struct {
		Valid bool `json:"valid"`
	}
	if err := t.data(ctx, "verify/"+name+suffix, t.op("verify", name), body, &d); err != nil {
		return false, err
	}
	return d.Valid, nil
}

// HashOptions configure Hash.
type HashOptions struct {
	// Algorithm is "sha2-256" (default), "sha2-224", "sha2-384", "sha2-512", "sha3-*".
	Algorithm string
	// Format is "hex" (default) or "base64".
	Format string
}

// Hash returns the digest of input in the requested format (hex by default).
func (t *Transit) Hash(ctx context.Context, input []byte, opts *HashOptions) (string, error) {
	path := "hash"
	body := map[string]any{"input": b64(input)}
	if opts != nil {
		if opts.Algorithm != "" {
			path += "/" + opts.Algorithm
		}
		if opts.Format != "" {
			body["format"] = opts.Format
		}
	}
	var d struct {
		Sum string `json:"sum"`
	}
	if err := t.data(ctx, path, t.op("hash", ""), body, &d); err != nil {
		return "", err
	}
	return d.Sum, nil
}

// RandomOptions configure RandomBytes.
type RandomOptions struct {
	// Format is "base64" (default) or "hex".
	Format string
}

// RandomBytes returns n random bytes from the server, encoded in opts.Format
// (base64 by default).
func (t *Transit) RandomBytes(ctx context.Context, n int, opts *RandomOptions) (string, error) {
	op := t.op("randomBytes", "")
	if n <= 0 {
		return "", ValidationError(op, "n must be positive")
	}
	body := map[string]any{}
	if opts != nil && opts.Format != "" {
		body["format"] = strings.ToLower(opts.Format)
	}
	var d struct {
		RandomBytes string `json:"random_bytes"`
	}
	if err := t.data(ctx, "random/"+url.PathEscape(strconv.Itoa(n)), op, body, &d); err != nil {
		return "", err
	}
	return d.RandomBytes, nil
}
