package openbao

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPKI(t *testing.T) {
	const serial = "1b:51:42:eb:c5:7c:6c:ad:fd:ec:85:5d:e7:c1:67:10:db:61:b1:34"
	m := newMockBao(t).
		fixture("POST", "/v1/pki/issue/sdk-test", "pki.issueCertificate.ok").
		fixture("POST", "/v1/pki/sign/sdk-test", "pki.signCsr.ok").
		fixture("POST", "/v1/pki/revoke", "pki.revokeCertificate.ok").
		fixture("GET", "/v1/pki/ca_chain", "pki.readCaChain.pem").
		fixture("GET", "/v1/pki/cert/"+serial, "pki.readCertificate.revoked").
		fixture("GET", "/v1/pki/cert/11:22", "pki.readCertificate.ok").
		fixture("GET", "/v1/pki/certs", "pki.listCertificates.ok").
		fixture("POST", "/v1/pki/tidy", "pki.tidy.accepted").
		data("GET", "/v1/pki/tidy-status", map[string]any{"state": "Running"}).
		fixture("GET", "/v1/pki/tidy-status", "pki.tidyStatus.finished")
	p := newBao(t, m, nil).PKI("")
	ctx := t.Context()
	if p.Mount() != "pki" {
		t.Fatal("mount")
	}
	cert, err := p.IssueCertificate(ctx, "sdk-test", "svc.example.test", &IssueOptions{
		AltNames: []string{"a.example.test", "b.example.test"}, IPSANs: []string{"127.0.0.1"}, URISANs: []string{"spiffe://x"},
		TTL: time.Hour, Format: "pem", PrivateKeyFormat: "pkcs8", ExcludeCNFromSANs: true,
	})
	b := m.last("POST", "/v1/pki/issue/sdk-test").JSON(t)
	if err != nil || !strings.HasPrefix(cert.Certificate, "-----BEGIN CERTIFICATE") || len(cert.CAChain) != 1 || cert.SerialNumber == "" ||
		cert.PrivateKey.IsZero() || cert.Expiration.IsZero() || b["alt_names"] != "a.example.test,b.example.test" || b["ttl"] != "3600s" ||
		b["exclude_cn_from_sans"] != true || b["uri_sans"] != "spiffe://x" || b["private_key_format"] != "pkcs8" {
		t.Fatalf("issue %+v %v %v", cert, b, err)
	}
	if strings.Contains(fmt.Sprintf("%+v", cert), "PrivateKey:<redacted>") {
		t.Fatal("private key must print redacted")
	}
	if cert, err := p.SignCSR(ctx, "sdk-test", "-----BEGIN CERTIFICATE REQUEST-----", nil); err != nil || cert.Certificate == "" || !cert.PrivateKey.IsZero() {
		t.Fatalf("sign %v", err)
	}
	rev, err := p.RevokeCertificate(ctx, serial)
	if err != nil || rev.State != "revoked" || rev.RevocationTime.IsZero() {
		t.Fatalf("revoke %+v %v", rev, err)
	}
	if chain, err := p.ReadCAChain(ctx); err != nil || !strings.HasPrefix(chain, "-----BEGIN CERTIFICATE") {
		t.Fatalf("chain %q %v", chain, err)
	}
	if info, err := p.ReadCertificate(ctx, serial); err != nil || !info.Revoked() {
		t.Fatalf("read revoked %+v %v", info, err)
	}
	if info, err := p.ReadCertificate(ctx, "11:22"); err != nil || info.Revoked() || info.Certificate == "" {
		t.Fatalf("read %+v %v", info, err)
	}
	if certs, err := p.ListCertificates(ctx); err != nil || len(certs) == 0 {
		t.Fatalf("list %v %v", certs, err)
	}
	st, err := p.Tidy(ctx, &TidyOptions{TidyCertStore: Ptr(true), TidyRevokedCerts: Ptr(false), SafetyBuffer: time.Second, Wait: true, WaitTimeout: 5 * time.Second})
	if b := m.last("POST", "/v1/pki/tidy").JSON(t); err != nil || st.State != "Finished" || b["safety_buffer"] != "1s" || b["tidy_revoked_certs"] != false {
		t.Fatalf("tidy %+v %v %v", st, b, err)
	}
	if st, err := p.Tidy(ctx, nil); err != nil || st.State != "Running" {
		t.Fatalf("tidy no wait %v", err)
	}

	t.Run("errors", func(t *testing.T) {
		m := newMockBao(t).
			fixture("POST", "/v1/pki/issue/sdk-test", "pki.issueCertificate.not-allowed").
			fixture("POST", "/v1/pki/sign/sdk-test", "pki.signCsr.invalid").
			fixture("POST", "/v1/pki/revoke", "pki.revokeCertificate.not-found").
			fixture("GET", "/v1/pki/cert/ff", "pki.readCertificate.not-found").
			data("GET", "/v1/pki/tidy-status", map[string]any{"state": "Error", "error": "boom"}).
			noContent("POST", "/v1/pki/tidy")
		p := newBao(t, m, nil).PKI("pki")
		ctx := t.Context()
		_, err := p.IssueCertificate(ctx, "sdk-test", "evil.example.com", nil)
		wantCode(t, err, ErrorCodeValidation)
		_, err = p.SignCSR(ctx, "sdk-test", "bad", nil)
		wantCode(t, err, ErrorCodeValidation)
		_, err = p.RevokeCertificate(ctx, "ff:ff")
		wantCode(t, err, ErrorCodeValidation)
		_, err = p.ReadCertificate(ctx, "ff")
		wantCode(t, err, ErrorCodeNotFound)
		for _, call := range []func() error{
			func() error { _, err := p.IssueCertificate(ctx, "r", "", nil); return err },
			func() error { _, err := p.SignCSR(ctx, "r", "", nil); return err },
			func() error { _, err := p.RevokeCertificate(ctx, ""); return err },
			func() error { _, err := p.ReadCertificate(ctx, ""); return err },
		} {
			wantCode(t, call(), ErrorCodeValidation)
		}
		if st, err := p.Tidy(ctx, &TidyOptions{Wait: true}); err != nil || st.State != "Error" || st.Error != "boom" {
			t.Fatalf("tidy error state %+v %v", st, err)
		}
		_, err = newBao(t, newMockBao(t), nil).PKI("").Tidy(ctx, nil)
		wantCode(t, err, ErrorCodeNotFound)
		_, err = newBao(t, newMockBao(t).noContent("POST", "/v1/pki/tidy"), nil).PKI("").Tidy(ctx, &TidyOptions{Wait: true, WaitTimeout: time.Second})
		wantCode(t, err, ErrorCodeNotFound)
		_, err = newBao(t, newMockBao(t), nil).PKI("").ReadCAChain(ctx)
		wantCode(t, err, ErrorCodeNotFound)
	})
}

func TestSys(t *testing.T) {
	m := newMockBao(t).
		fixture("GET", "/v1/sys/seal-status", "sealStatus.unsealed").
		fixture("GET", "/v1/sys/leader", "leader.active").
		fixture("PUT", "/v1/sys/policies/acl/p1", "admin.writePolicy.ok").
		fixture("GET", "/v1/sys/policies/acl/p1", "admin.readPolicy.ok").
		fixture("GET", "/v1/sys/policies/acl", "admin.listPolicies.ok").
		fixture("DELETE", "/v1/sys/policies/acl/p1", "admin.deletePolicy.ok").
		fixture("GET", "/v1/sys/mounts", "admin.listMounts.ok").
		fixture("POST", "/v1/sys/mounts/kv-x", "admin.enableSecretsEngine.ok").
		fixture("DELETE", "/v1/sys/mounts/kv-x", "admin.disableSecretsEngine.ok").
		fixture("GET", "/v1/sys/auth", "admin.listAuthMethods.ok").
		fixture("POST", "/v1/sys/auth/ar-x", "admin.enableAuthMethod.ok").
		fixture("DELETE", "/v1/sys/auth/ar-x", "admin.disableAuthMethod.ok").
		fixture("POST", "/v1/auth/approle/role/r1", "admin.createAppRole.ok").
		fixture("GET", "/v1/auth/approle/role", "admin.listAppRoles.ok").
		noContent("DELETE", "/v1/auth/ar-x/role/r1").
		fixture("GET", "/v1/auth/approle/role/r1/role-id", "admin.readRoleId.ok").
		fixture("POST", "/v1/auth/ar-x/role/r1/secret-id", "admin.generateSecretId.ok")
	c := newBao(t, m, nil)
	s := c.Sys()
	ctx := t.Context()
	st, err := s.SealStatus(ctx)
	if err != nil || st.Sealed || !st.Initialized || st.Type != "static" || st.Version != "2.7.2" || st.StorageType != "raft" {
		t.Fatalf("seal status %+v %v", st, err)
	}
	if m.last("GET", "/v1/sys/seal-status").Header.Get("X-Vault-Token") != "" {
		t.Fatal("seal-status is unauthenticated")
	}
	ld, err := s.Leader(ctx)
	if err != nil || !ld.HAEnabled || !ld.IsSelf || ld.LeaderAddress == "" || ld.ActiveTime.IsZero() || ld.RaftAppliedIndex == 0 {
		t.Fatalf("leader %+v %v", ld, err)
	}
	if err := s.WritePolicy(ctx, "p1", `path "x" { capabilities = ["read"] }`); err != nil || m.last("PUT", "/v1/sys/policies/acl/p1").JSON(t)["policy"] == nil {
		t.Fatal(err)
	}
	if pol, err := s.ReadPolicy(ctx, "p1"); err != nil || pol.Name == "" || !strings.Contains(pol.Policy, "capabilities") {
		t.Fatalf("read policy %+v %v", pol, err)
	}
	if names, err := s.ListPolicies(ctx); err != nil || len(names) == 0 {
		t.Fatalf("list policies %v %v", names, err)
	}
	if err := s.DeletePolicy(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	mounts, err := s.ListMounts(ctx)
	if err != nil || mounts["secret/"].Type != "kv" || mounts["secret/"].Options["version"] != "2" {
		t.Fatalf("mounts %v %v", mounts["secret/"], err)
	}
	err = s.EnableSecretsEngine(ctx, "/kv-x/", "kv", &MountOptions{
		Description: "d", Options: map[string]string{"version": "2"}, DefaultLeaseTTL: time.Hour, MaxLeaseTTL: 2 * time.Hour, Local: true, SealWrap: true,
	})
	b := m.last("POST", "/v1/sys/mounts/kv-x").JSON(t)
	if err != nil || b["type"] != "kv" || b["config"].(map[string]any)["max_lease_ttl"] != "7200s" || b["local"] != true || b["seal_wrap"] != true {
		t.Fatalf("enable %v %v", b, err)
	}
	if err := s.DisableSecretsEngine(ctx, "kv-x"); err != nil {
		t.Fatal(err)
	}
	if auths, err := s.ListAuthMethods(ctx); err != nil || auths["token/"].Type != "token" {
		t.Fatalf("auths %v %v", auths, err)
	}
	if err := s.EnableAuthMethod(ctx, "ar-x", "approle", nil); err != nil || m.last("POST", "/v1/sys/auth/ar-x").JSON(t)["type"] != "approle" {
		t.Fatal(err)
	}
	if err := s.DisableAuthMethod(ctx, "ar-x"); err != nil {
		t.Fatal(err)
	}
	err = s.CreateAppRole(ctx, "r1", &AppRoleOptions{
		TokenPolicies: []string{"p"}, TokenTTL: time.Hour, TokenMaxTTL: 2 * time.Hour, TokenNumUses: 2, TokenType: "service",
		SecretIDTTL: time.Minute, SecretIDNumUses: 1, BindSecretID: Ptr(true),
	})
	b = m.last("POST", "/v1/auth/approle/role/r1").JSON(t)
	if err != nil || b["token_ttl"] != "3600s" || b["secret_id_ttl"] != "60s" || b["secret_id_num_uses"] != float64(1) || b["bind_secret_id"] != true {
		t.Fatalf("create approle %v %v", b, err)
	}
	if roles, err := s.ListAppRoles(ctx, ""); err != nil || len(roles) == 0 {
		t.Fatalf("list approles %v %v", roles, err)
	}
	if err := s.DeleteAppRole(ctx, "r1", "ar-x"); err != nil {
		t.Fatal(err)
	}
	if id, err := s.ReadRoleID(ctx, "r1", ""); err != nil || id == "" {
		t.Fatalf("role id %q %v", id, err)
	}
	sid, err := s.GenerateSecretID(ctx, "r1", &SecretIDOptions{Mount: "ar-x", Metadata: map[string]string{"purpose": "sdk"}, TTL: time.Minute, NumUses: 1, CIDRList: []string{"10.0.0.0/8"}})
	b = m.last("POST", "/v1/auth/ar-x/role/r1/secret-id").JSON(t)
	if err != nil || sid.SecretID.IsZero() || sid.NumUses != 1 || b["metadata"] != `{"purpose":"sdk"}` || b["ttl"] != "60s" || b["cidr_list"] == nil {
		t.Fatalf("secret id %+v %v %v", sid, b, err)
	}

	t.Run("errors", func(t *testing.T) {
		m := newMockBao(t).
			fixture("GET", "/v1/sys/mounts", "admin.listMounts.permission-denied").
			fixture("POST", "/v1/sys/mounts/secret", "admin.enableSecretsEngine.conflict").
			fixture("PUT", "/v1/sys/policies/acl/bad", "admin.writePolicy.invalid").
			fixture("GET", "/v1/sys/policies/acl/gone", "admin.readPolicy.not-found").
			fixture("GET", "/v1/auth/approle/role/nope/role-id", "admin.readRoleId.not-found").
			add("GET", "/v1/sys/seal-status", reply{status: 200, body: []byte("x")}).
			add("GET", "/v1/sys/leader", reply{status: 200, body: []byte("x")}).
			data("GET", "/v1/sys/auth", map[string]any{"bad": "x", "ok/": map[string]any{"type": "token"}})
		s := newBao(t, m, nil).Sys()
		ctx := t.Context()
		_, err := s.ListMounts(ctx)
		wantCode(t, err, ErrorCodePermissionDenied)
		wantCode(t, s.EnableSecretsEngine(ctx, "secret", "kv", nil), ErrorCodeValidation)
		wantCode(t, s.EnableSecretsEngine(ctx, "x", "", nil), ErrorCodeValidation)
		wantCode(t, s.EnableAuthMethod(ctx, "x", "", nil), ErrorCodeValidation)
		wantCode(t, s.WritePolicy(ctx, "bad", "{"), ErrorCodeValidation)
		wantCode(t, s.WritePolicy(ctx, "", "x"), ErrorCodeValidation)
		wantCode(t, s.CreateAppRole(ctx, "", nil), ErrorCodeValidation)
		_, err = s.ReadPolicy(ctx, "gone")
		wantCode(t, err, ErrorCodeNotFound)
		_, err = s.ReadRoleID(ctx, "nope", "")
		wantCode(t, err, ErrorCodeNotFound)
		_, err = s.SealStatus(ctx)
		wantCode(t, err, ErrorCodeUnavailable)
		_, err = s.Leader(ctx)
		wantCode(t, err, ErrorCodeUnavailable)
		if auths, err := s.ListAuthMethods(ctx); err != nil || len(auths) != 1 {
			t.Fatalf("auths skip non-mount keys: %v %v", auths, err)
		}
		_, err = s.GenerateSecretID(ctx, "r", nil)
		wantCode(t, err, ErrorCodeNotFound)
		c := newBao(t, newMockBao(t), nil)
		_ = c.Close()
		_, err = c.Sys().SealStatus(ctx)
		wantCode(t, err, ErrorCodeCancelled)
		_, err = c.Sys().Leader(ctx)
		wantCode(t, err, ErrorCodeCancelled)
	})
}

func TestWrapping(t *testing.T) {
	m := newMockBao(t).
		fixture("POST", "/v1/sys/wrapping/wrap", "wrapping.wrap.ok").
		fixture("POST", "/v1/sys/wrapping/lookup", "wrapping.lookupWrapping.ok").
		fixture("POST", "/v1/sys/wrapping/unwrap", "wrapping.unwrap.ok").
		fixture("POST", "/v1/sys/wrapping/unwrap", "wrapping.unwrap.already-used")
	w := newBao(t, m, nil).Wrapping()
	ctx := t.Context()
	info, err := w.Wrap(ctx, map[string]any{"secret": "s", "n": 1}, time.Minute)
	if err != nil || info.Token.IsZero() || info.TTL != time.Minute || info.CreationPath != "sys/wrapping/wrap" || info.CreationTime.IsZero() {
		t.Fatalf("wrap %+v %v", info, err)
	}
	if r := m.last("POST", "/v1/sys/wrapping/wrap"); r.Header.Get("X-Vault-Wrap-Ttl") != "60s" || r.JSON(t)["secret"] != "s" {
		t.Fatalf("wrap request %v", r.Header)
	}
	lk, err := w.LookupWrapping(ctx, "wrap-token-1")
	if err != nil || lk.CreationTTL != time.Minute || lk.CreationPath != "sys/wrapping/wrap" {
		t.Fatalf("lookup %+v %v", lk, err)
	}
	res, err := w.Unwrap(ctx, "wrap-token-1")
	if err != nil || res.Data["secret"] != "wrapped-f43633d7" || res.Auth != nil || res.RequestID == "" {
		t.Fatalf("unwrap %+v %v", res, err)
	}
	if m.last("POST", "/v1/sys/wrapping/unwrap").Header.Get("X-Vault-Token") != "wrap-token-1" {
		t.Fatal("unwrap must authenticate with the wrapping token")
	}
	_, err = w.Unwrap(ctx, "wrap-token-1")
	wantCode(t, err, ErrorCodeValidation)
	if strings.Contains(err.Error(), "wrap-token-1") {
		t.Fatal("token leaked")
	}

	t.Run("errors", func(t *testing.T) {
		m := newMockBao(t).
			fixture("POST", "/v1/sys/wrapping/wrap", "wrapping.wrap.missing-ttl").
			data("POST", "/v1/sys/wrapping/lookup", nil).
			json("POST", "/v1/sys/wrapping/unwrap", 200, map[string]any{"auth": map[string]any{"client_token": "child-token", "lease_duration": 60}})
		w := newBao(t, m, nil).Wrapping()
		_, err := w.Wrap(ctx, nil, time.Minute)
		wantCode(t, err, ErrorCodeValidation)
		_, err = w.Wrap(ctx, nil, 0)
		wantCode(t, err, ErrorCodeValidation)
		_, err = w.Unwrap(ctx, "")
		wantCode(t, err, ErrorCodeValidation)
		_, err = w.LookupWrapping(ctx, "")
		wantCode(t, err, ErrorCodeValidation)
		if res, err := w.Unwrap(ctx, "tok-1"); err != nil || res.Auth == nil || res.Auth.LeaseDuration != time.Minute {
			t.Fatalf("unwrap auth %+v %v", res, err)
		}
		m2 := newMockBao(t).data("POST", "/v1/sys/wrapping/wrap", nil).json("POST", "/v1/sys/wrapping/unwrap", 200, map[string]any{"data": "x"})
		w2 := newBao(t, m2, nil).Wrapping()
		_, err = w2.Wrap(ctx, map[string]any{}, time.Second)
		wantCode(t, err, ErrorCodeUnavailable)
		_, err = w2.Unwrap(ctx, "tok-2")
		wantCode(t, err, ErrorCodeUnavailable)
		_, err = newBao(t, newMockBao(t), nil).Wrapping().LookupWrapping(ctx, "tok-3")
		wantCode(t, err, ErrorCodeNotFound)
	})
}
