package openbao

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestTransit(t *testing.T) {
	const k = "/v1/transit/keys/k1"
	m := newMockBao(t).
		fixture("POST", k, "transit.createKey.ok").
		fixture("GET", k, "transit.readKey.ok").
		fixture("GET", "/v1/transit/keys", "transit.listKeys.ok").
		fixture("POST", k+"/rotate", "transit.rotateKey.ok").
		fixture("POST", k+"/config", "transit.updateKeyConfig.ok").
		noContent("DELETE", k).
		fixture("POST", "/v1/transit/encrypt/k1", "transit.encrypt.ok").
		fixture("POST", "/v1/transit/decrypt/k1", "transit.decrypt.ok").
		fixture("POST", "/v1/transit/rewrap/k1", "transit.rewrap.ok").
		fixture("POST", "/v1/transit/datakey/plaintext/k1", "transit.generateDataKey.plaintext").
		fixture("POST", "/v1/transit/datakey/wrapped/k1", "transit.generateDataKey.wrapped").
		fixture("POST", "/v1/transit/hmac/k1/sha2-256", "transit.hmac.ok").
		fixture("POST", "/v1/transit/sign/sign1", "transit.sign.ed25519").
		fixture("POST", "/v1/transit/verify/sign1", "transit.verify.valid").
		fixture("POST", "/v1/transit/verify/k1/sha2-256", "transit.verify.hmac-valid").
		fixture("POST", "/v1/transit/verify/rsa", "transit.verify.invalid").
		fixture("POST", "/v1/transit/hash", "transit.hash.default-hex").
		fixture("POST", "/v1/transit/hash/sha2-256", "transit.hash.base64").
		fixture("POST", "/v1/transit/random/32", "transit.randomBytes.hex")
	tr := newBao(t, m, nil).Transit("")
	ctx := t.Context()
	if tr.Mount() != "transit" {
		t.Fatal("mount")
	}

	key, err := tr.CreateKey(ctx, "k1", "aes256-gcm96", &CreateKeyOptions{Exportable: true, Derived: true, AllowPlaintextBackup: true, AutoRotatePeriod: time.Hour})
	if err != nil || key.Type != "aes256-gcm96" || key.LatestVersion != 1 || key.Keys[1].CreationTime.IsZero() || !key.SupportsEncryption {
		t.Fatalf("create %+v %v", key, err)
	}
	b := m.last("POST", k).JSON(t)
	if b["type"] != "aes256-gcm96" || b["exportable"] != true || b["derived"] != true || b["allow_plaintext_backup"] != true || b["auto_rotate_period"] != "3600s" {
		t.Fatalf("create body %v", b)
	}
	if key, err := tr.ReadKey(ctx, "k1"); err != nil || key.Name == "" {
		t.Fatalf("read %v", err)
	}
	if keys, err := tr.ListKeys(ctx); err != nil || len(keys) == 0 {
		t.Fatalf("list %v %v", keys, err)
	}
	if key, err := tr.RotateKey(ctx, "k1"); err != nil || key.LatestVersion != 2 {
		t.Fatalf("rotate %v", err)
	}
	key, err = tr.UpdateKeyConfig(ctx, "k1", TransitKeyConfig{
		DeletionAllowed: Ptr(true), MinDecryptionVersion: Ptr(2), MinEncryptionVersion: Ptr(0), Exportable: Ptr(true),
		AllowPlaintextBackup: Ptr(true), AutoRotatePeriod: Ptr(time.Duration(0)),
	})
	if b := m.last("POST", k+"/config").JSON(t); err != nil || key.MinDecryptionVersion != 2 || b["deletion_allowed"] != true || len(b) != 6 {
		t.Fatalf("config %v %v", b, err)
	}
	if err := tr.DeleteKey(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	ct, err := tr.Encrypt(ctx, "k1", []byte("hello"), &EncryptOptions{Context: []byte("ctx"), KeyVersion: 1})
	if b := m.last("POST", "/v1/transit/encrypt/k1").JSON(t); err != nil || ct.Ciphertext == "" || ct.KeyVersion == 0 ||
		b["plaintext"] != "aGVsbG8=" || b["context"] != "Y3R4" || b["key_version"] != float64(1) {
		t.Fatalf("encrypt %+v %v %v", ct, b, err)
	}
	if pt, err := tr.Decrypt(ctx, "k1", ct.Ciphertext, nil); err != nil || len(pt) == 0 {
		t.Fatalf("decrypt %q %v", pt, err)
	}
	if rw, err := tr.Rewrap(ctx, "k1", ct.Ciphertext, nil); err != nil || rw.Ciphertext == "" {
		t.Fatalf("rewrap %v", err)
	}
	dk, err := tr.GenerateDataKey(ctx, "k1", &DataKeyOptions{Bits: 256, Context: []byte("c")})
	if err != nil || len(dk.Plaintext) != 32 || dk.Ciphertext == "" {
		t.Fatalf("datakey %+v %v", dk, err)
	}
	if dk, err := tr.GenerateDataKey(ctx, "k1", &DataKeyOptions{Wrapped: true}); err != nil || dk.Plaintext != nil {
		t.Fatalf("wrapped datakey %v", err)
	}
	mac, err := tr.HMAC(ctx, "k1", []byte("hmac-me"), &HMACOptions{Algorithm: "sha2-256", KeyVersion: 2})
	if err != nil || mac == "" {
		t.Fatalf("hmac %v", err)
	}
	if ok, err := tr.Verify(ctx, "k1", []byte("hmac-me"), mac, &VerifyOptions{SignOptions: SignOptions{HashAlgorithm: "sha2-256"}, HMAC: true}); err != nil || !ok ||
		m.last("POST", "/v1/transit/verify/k1/sha2-256").JSON(t)["hmac"] != mac {
		t.Fatalf("verify hmac %v", err)
	}
	sig, err := tr.Sign(ctx, "sign1", []byte("sign-me"), &SignOptions{SignatureAlgorithm: "pss", Prehashed: true, KeyVersion: 1, Context: []byte("c")})
	if b := m.last("POST", "/v1/transit/sign/sign1").JSON(t); err != nil || sig.Signature == "" || sig.KeyVersion != 1 || b["prehashed"] != true || b["signature_algorithm"] != "pss" {
		t.Fatalf("sign %+v %v", sig, err)
	}
	if ok, err := tr.Verify(ctx, "sign1", []byte("sign-me"), sig.Signature, nil); err != nil || !ok {
		t.Fatalf("verify %v", err)
	}
	if ok, err := tr.Verify(ctx, "rsa", []byte("x"), "vault:v1:bad", &VerifyOptions{SignOptions: SignOptions{KeyVersion: 9}}); err != nil || ok {
		t.Fatalf("invalid signature must be false without error: %v", err)
	}
	if _, ok := m.last("POST", "/v1/transit/verify/rsa").JSON(t)["key_version"]; ok {
		t.Fatal("verify must not send key_version")
	}
	if sum, err := tr.Hash(ctx, []byte("abc"), nil); err != nil || len(sum) != 64 {
		t.Fatalf("hash %q %v", sum, err)
	}
	if sum, err := tr.Hash(ctx, []byte("abc"), &HashOptions{Algorithm: "sha2-256", Format: "base64"}); err != nil || sum == "" {
		t.Fatalf("hash b64 %v", err)
	}
	if rnd, err := tr.RandomBytes(ctx, 32, &RandomOptions{Format: "HEX"}); err != nil || len(rnd) != 64 || m.last("POST", "/v1/transit/random/32").JSON(t)["format"] != "hex" {
		t.Fatalf("random %q %v", rnd, err)
	}
	_, err = tr.RandomBytes(ctx, 0, nil)
	wantCode(t, err, ErrorCodeValidation)
	_, err = tr.CreateKey(ctx, "", "", nil)
	wantCode(t, err, ErrorCodeValidation)
}

func TestTransitBatchAndErrors(t *testing.T) {
	m := newMockBao(t).
		fixture("POST", "/v1/transit/encrypt/k1", "transit.encryptBatch.ok").
		fixture("POST", "/v1/transit/decrypt/k1", "transit.decryptBatch.partial-207").
		fixture("POST", "/v1/transit/decrypt/k2", "transit.decrypt.invalid").
		fixture("POST", "/v1/transit/sign/aes", "transit.sign.unsupported-key-type").
		fixture("DELETE", "/v1/transit/keys/k1", "transit.deleteKey.not-allowed").
		fixture("GET", "/v1/transit/keys/gone", "transit.readKey.not-found").
		noContent("POST", "/v1/transit/keys/old").
		noContent("POST", "/v1/transit/keys/old/rotate").
		noContent("POST", "/v1/transit/keys/old/config").
		fixture("GET", "/v1/transit/keys/old", "transit.readKey.ok").
		data("POST", "/v1/transit/decrypt/badb64", map[string]any{"plaintext": "!!", "batch_results": []map[string]any{{"plaintext": "!!"}}}).
		data("POST", "/v1/transit/datakey/plaintext/badb64", map[string]any{"plaintext": "!!"})
	tr := newBao(t, m, nil).Transit("transit")
	ctx := t.Context()
	res, err := tr.EncryptBatch(ctx, "k1", []TransitBatchItem{{Plaintext: []byte("one")}, {Plaintext: []byte("two"), Reference: "r2", Context: []byte("c")}}, &EncryptOptions{KeyVersion: 2})
	b := m.last("POST", "/v1/transit/encrypt/k1").JSON(t)
	if err != nil || len(res) != 2 || res[1].Reference != "r2" || res[0].Ciphertext == "" || b["partial_failure_response_code"] != float64(http.StatusMultiStatus) || b["key_version"] != float64(2) {
		t.Fatalf("encrypt batch %+v %v %v", res, b, err)
	}
	res, err = tr.DecryptBatch(ctx, "k1", []TransitBatchItem{{Ciphertext: "vault:v2:x"}, {Ciphertext: "vault:v1:AAAA"}})
	if err != nil || len(res) != 2 || string(res[0].Plaintext) != "one" || res[1].Error == "" {
		t.Fatalf("decrypt batch partial %+v %v", res, err)
	}
	if res, err := tr.DecryptBatch(ctx, "k1", nil); err != nil || len(res) != 0 {
		t.Fatal("empty batch")
	}
	if res, err := tr.DecryptBatch(ctx, "badb64", []TransitBatchItem{{Ciphertext: "x"}}); err != nil || res[0].Error == "" {
		t.Fatalf("bad base64 item %+v %v", res, err)
	}
	_, err = tr.Decrypt(ctx, "badb64", "x", nil)
	wantCode(t, err, ErrorCodeUnavailable)
	_, err = tr.GenerateDataKey(ctx, "badb64", nil)
	wantCode(t, err, ErrorCodeUnavailable)
	_, err = tr.Decrypt(ctx, "k2", "vault:v1:junk", nil)
	wantCode(t, err, ErrorCodeValidation)
	_, err = tr.Sign(ctx, "aes", []byte("x"), nil)
	wantCode(t, err, ErrorCodeValidation)
	wantCode(t, tr.DeleteKey(ctx, "k1"), ErrorCodeValidation)
	_, err = tr.ReadKey(ctx, "gone")
	wantCode(t, err, ErrorCodeNotFound)
	// 204 answers (older servers) fall back to ReadKey
	if key, err := tr.CreateKey(ctx, "old", "", nil); err != nil || key.Name == "" {
		t.Fatalf("create 204 %v", err)
	}
	if key, err := tr.RotateKey(ctx, "old"); err != nil || key.Name == "" {
		t.Fatalf("rotate 204 %v", err)
	}
	if key, err := tr.UpdateKeyConfig(ctx, "old", TransitKeyConfig{}); err != nil || key.Name == "" {
		t.Fatalf("config 204 %v", err)
	}
	for _, call := range []func() error{
		func() error { _, err := tr.Encrypt(ctx, "nope", nil, nil); return err },
		func() error { _, err := tr.Rewrap(ctx, "nope", "x", nil); return err },
		func() error { _, err := tr.EncryptBatch(ctx, "nope", []TransitBatchItem{{}}, nil); return err },
		func() error { _, err := tr.GenerateDataKey(ctx, "nope", nil); return err },
		func() error { _, err := tr.HMAC(ctx, "nope", nil, nil); return err },
		func() error { _, err := tr.Verify(ctx, "nope", nil, "s", nil); return err },
		func() error { _, err := tr.Hash(ctx, nil, &HashOptions{Algorithm: "nope"}); return err },
		func() error { _, err := tr.RandomBytes(ctx, 1, nil); return err },
		func() error { _, err := tr.RotateKey(ctx, "nope"); return err },
		func() error { _, err := tr.UpdateKeyConfig(ctx, "nope", TransitKeyConfig{}); return err },
	} {
		wantCode(t, call(), ErrorCodeNotFound)
	}
	pub := (&transitKeyJSON{Keys: map[string]json.RawMessage{"x": json.RawMessage("1"), "1": json.RawMessage("1795033741"),
		"2": json.RawMessage(`{"creation_time":"2026-11-18T20:28:54Z","public_key":"pk"}`)}}).public()
	if len(pub.Keys) != 2 || pub.Keys[2].PublicKey != "pk" || pub.Keys[2].CreationTime.IsZero() || pub.Keys[1].CreationTime.IsZero() {
		t.Fatalf("asymmetric keys %+v", pub.Keys)
	}
}
