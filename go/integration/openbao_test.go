package integration

// Integration tests against the real OpenBao from docker/compose.yml. Every
// public function of the package is called at least once with a round-trip
// assertion. The bootstrap writes /bootstrap/env (GROW_OPENBAO_TOKEN and the
// GROW_OPENBAO_TEST_* fixture names).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	openbao "github.com/grow-codes-packages/openbao/go"
	"github.com/grow-codes-packages/openbao/go/testkit"
)

// setup loads the bootstrap environment and returns a root client.
func setup(t *testing.T) *openbao.Client {
	t.Helper()
	bootstrap := os.Getenv("GROW_BOOTSTRAP_ENV")
	if bootstrap == "" {
		bootstrap = "/bootstrap/env"
	}
	loadBootstrapEnv(t, bootstrap)
	if os.Getenv("GROW_OPENBAO_URL") == "" {
		t.Skip("GROW_OPENBAO_URL is not set; run through docker/compose.yml")
	}
	c, err := openbao.NewClientFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func env(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv("GROW_OPENBAO_TEST_" + name)
	if v == "" {
		t.Fatalf("GROW_OPENBAO_TEST_%s is not set (bootstrap env)", name)
	}
	return v
}

func runID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// result carries a value and an error so calls read get(f()).of(t).
type result[T any] struct {
	v   T
	err error
}

func get[T any](v T, err error) result[T] { return result[T]{v, err} }

// of returns the value or fails the test.
func (r result[T]) of(t *testing.T) T {
	t.Helper()
	if r.err != nil {
		t.Fatal(r.err)
	}
	return r.v
}

func ok(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, err error, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("want %v, got %v", target, err)
	}
}

// eventually retries fn for up to 30 s (newly enabled KV v2 mounts answer
// "Upgrading from non-versioned to versioned data" for a moment).
func eventually(t *testing.T, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := fn()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func TestClientSurface(t *testing.T) {
	c := setup(t)
	ctx := t.Context()
	hs := get(c.Health(ctx)).of(t)
	if !hs.Healthy || hs.Status != "active" {
		t.Fatalf("health %+v", hs)
	}
	if d := get(c.Ping(ctx)).of(t); d <= 0 {
		t.Fatal("ping latency")
	}
	if v := get(c.ServerVersion(ctx)).of(t); v != env(t, "SERVER_VERSION") {
		t.Fatalf("version %q", v)
	}
	if c.Config().URL != os.Getenv("GROW_OPENBAO_URL") || c.Token().IsZero() {
		t.Fatal("config")
	}
	bad := get(openbao.NewClient(openbao.Config{CommonConfig: openbao.CommonConfig{URL: c.Config().URL}, Token: openbao.NewSecret("not-a-real-token")})).of(t)
	_, err := bad.Ping(ctx)
	wantErr(t, err, openbao.ErrAuthentication)
	if strings.Contains(err.Error(), "not-a-real-token") {
		t.Fatal("token leaked into the error")
	}
	// An ordinary call with a bad token: plain "permission denied" 403 → AUTHENTICATION.
	_, err = bad.KVv2("secret").Read(ctx, "sdk/allowed/hello", nil)
	wantErr(t, err, openbao.ErrAuthentication)
	ok(t, bad.Close())
	ok(t, bad.Close())
	unreachable := get(openbao.NewClient(openbao.Config{CommonConfig: openbao.CommonConfig{URL: "http://127.0.0.1:1", ConnectTimeout: time.Second}})).of(t)
	if hs := get(unreachable.Health(ctx)).of(t); hs.Healthy || hs.Status != "unreachable" {
		t.Fatalf("unreachable %+v", hs)
	}
}

func TestSys(t *testing.T) {
	c := setup(t)
	ctx := t.Context()
	s := c.Sys()
	st := get(s.SealStatus(ctx)).of(t)
	if st.Sealed || !st.Initialized || st.StorageType != "raft" {
		t.Fatalf("seal status %+v", st)
	}
	ld := get(s.Leader(ctx)).of(t)
	if !ld.IsSelf || !ld.HAEnabled {
		t.Fatalf("leader %+v", ld)
	}
	if v := get(s.Version(ctx)).of(t); v != st.Version {
		t.Fatalf("version %q vs %q", v, st.Version)
	}
	if hs := get(s.Health(ctx)).of(t); hs.State != "active" || hs.Version != st.Version {
		t.Fatalf("sys health %+v", hs)
	}

	id := runID(t)
	pol := "sdk-go-" + id
	hcl := fmt.Sprintf(`path "secret/data/sdk/go-%s/*" { capabilities = ["read"] }`, id)
	ok(t, s.WritePolicy(ctx, pol, hcl))
	if p := get(s.ReadPolicy(ctx, pol)).of(t); p.Policy != hcl || p.Name != pol {
		t.Fatalf("policy %+v", p)
	}
	if names := get(s.ListPolicies(ctx)).of(t); !slices.Contains(names, pol) || !slices.Contains(names, "default") {
		t.Fatalf("policies %v", names)
	}
	ok(t, s.DeletePolicy(ctx, pol))
	_, err := s.ReadPolicy(ctx, pol)
	wantErr(t, err, openbao.ErrNotFound)
	wantErr(t, s.WritePolicy(ctx, pol, "path {"), openbao.ErrValidation)

	mount := "kv-go-" + id
	ok(t, s.EnableSecretsEngine(ctx, mount, "kv", &openbao.MountOptions{Description: "go sdk", Options: map[string]string{"version": "2"}}))
	mounts := get(s.ListMounts(ctx)).of(t)
	if m := mounts[mount+"/"]; m.Type != "kv" || m.Options["version"] != "2" || m.Description != "go sdk" {
		t.Fatalf("mount %+v", m)
	}
	wantErr(t, s.EnableSecretsEngine(ctx, mount, "kv", nil), openbao.ErrValidation)
	kv := get(c.KV(ctx, mount)).of(t)
	if kv.Version() != 2 {
		t.Fatal("new mount must detect as v2")
	}
	eventually(t, func() error { _, err := kv.Write(ctx, "x", map[string]any{"a": "b"}, nil); return err })
	ok(t, s.DisableSecretsEngine(ctx, mount))
	if _, ok := get(s.ListMounts(ctx)).of(t)[mount+"/"]; ok {
		t.Fatal("mount still listed")
	}

	authPath := "ar-go-" + id
	ok(t, s.EnableAuthMethod(ctx, authPath, "approle", &openbao.MountOptions{Description: "go approle"}))
	if a := get(s.ListAuthMethods(ctx)).of(t)[authPath+"/"]; a.Type != "approle" {
		t.Fatalf("auth method %+v", a)
	}
	ok(t, s.WritePolicy(ctx, pol, hcl))
	defer func() { _ = s.DeletePolicy(ctx, pol) }()
	ok(t, s.CreateAppRole(ctx, "r1", &openbao.AppRoleOptions{Mount: authPath, TokenPolicies: []string{pol}, TokenTTL: time.Hour, SecretIDNumUses: 1}))
	if roles := get(s.ListAppRoles(ctx, authPath)).of(t); !slices.Equal(roles, []string{"r1"}) {
		t.Fatalf("roles %v", roles)
	}
	roleID := get(s.ReadRoleID(ctx, "r1", authPath)).of(t)
	sid := get(s.GenerateSecretID(ctx, "r1", &openbao.SecretIDOptions{Mount: authPath, Metadata: map[string]string{"purpose": "go-sdk"}})).of(t)
	if sid.NumUses != 1 || sid.SecretID.IsZero() {
		t.Fatalf("secret id %+v", sid)
	}
	login := get(openbao.NewClient(openbao.Config{CommonConfig: c.Config().CommonConfig})).of(t)
	defer func() { _ = login.Close() }()
	info := get(login.Auth().Login(ctx, &openbao.AppRoleAuth{RoleID: roleID, SecretID: sid.SecretID, Mount: authPath})).of(t)
	if !slices.Contains(info.Policies, pol) {
		t.Fatalf("login policies %v", info.Policies)
	}
	_, err = login.Auth().Login(ctx, &openbao.AppRoleAuth{RoleID: roleID, SecretID: sid.SecretID, Mount: authPath})
	wantErr(t, err, openbao.ErrAuthentication) // single-use secret id is used up (login 400 → AUTHENTICATION)
	_, err = s.ReadRoleID(ctx, "missing", authPath)
	wantErr(t, err, openbao.ErrNotFound)
	ok(t, s.DeleteAppRole(ctx, "r1", authPath))
	if roles := get(s.ListAppRoles(ctx, authPath)).of(t); len(roles) != 0 {
		t.Fatalf("roles after delete %v", roles)
	}
	ok(t, s.DisableAuthMethod(ctx, authPath))
	if _, ok := get(s.ListAuthMethods(ctx)).of(t)[authPath+"/"]; ok {
		t.Fatal("auth method still listed")
	}
}

func TestAuth(t *testing.T) {
	c := setup(t)
	ctx := t.Context()
	base := c.Config().CommonConfig
	newBare := func() *openbao.Client {
		cl := get(openbao.NewClient(openbao.Config{CommonConfig: base})).of(t)
		t.Cleanup(func() { _ = cl.Close() })
		return cl
	}
	allowed, denied := env(t, "ALLOWED_PATH"), env(t, "DENIED_PATH")
	readAllowed := func(cl *openbao.Client) {
		t.Helper()
		sec := get(cl.KVv2(env(t, "KV2_MOUNT")).Read(ctx, allowed, nil)).of(t)
		if sec.Data["value"] != "world" {
			t.Fatalf("allowed read %v", sec.Data)
		}
		_, err := cl.KVv2(env(t, "KV2_MOUNT")).Read(ctx, denied, nil)
		wantErr(t, err, openbao.ErrPermissionDenied)
	}

	methods := map[string]openbao.AuthMethod{
		"approle":  &openbao.AppRoleAuth{RoleID: env(t, "APPROLE_ROLE_ID"), SecretID: openbao.NewSecret(env(t, "APPROLE_SECRET_ID")), Mount: env(t, "APPROLE_MOUNT")},
		"userpass": &openbao.UserpassAuth{Username: env(t, "USERPASS_USER"), Password: openbao.NewSecret(env(t, "USERPASS_PASSWORD")), Mount: env(t, "USERPASS_MOUNT")},
		"jwt":      &openbao.JWTAuth{Role: env(t, "JWT_ROLE"), JWT: openbao.NewSecret(env(t, "JWT")), Mount: env(t, "JWT_MOUNT")},
	}
	for name, m := range methods {
		t.Run(name, func(t *testing.T) {
			cl := newBare()
			info := get(cl.Auth().Login(ctx, m)).of(t)
			if !slices.Contains(info.Policies, env(t, "POLICY")) || info.ClientToken.IsZero() || cl.Token().Reveal() != info.ClientToken.Reveal() {
				t.Fatalf("login %+v", info)
			}
			readAllowed(cl)
			ti := get(cl.Auth().LookupSelf(ctx)).of(t)
			if ti.Accessor != info.Accessor {
				t.Fatal("lookup-self after login")
			}
		})
	}
	t.Run("convenience constructors", func(t *testing.T) {
		cl := newBare()
		get(cl.Auth().Login(ctx, openbao.NewUserpassAuth(env(t, "USERPASS_USER"), env(t, "USERPASS_PASSWORD")))).of(t)
		get(cl.Auth().Login(ctx, openbao.NewAppRoleAuth(env(t, "APPROLE_ROLE_ID"), env(t, "APPROLE_SECRET_ID")))).of(t)
		get(cl.Auth().Login(ctx, openbao.NewJWTAuth(env(t, "JWT_ROLE"), env(t, "JWT")))).of(t)
		root := get(cl.Auth().Login(ctx, openbao.NewTokenAuth(c.Token().Reveal()))).of(t)
		if !slices.Contains(root.Policies, "root") {
			t.Fatalf("token auth %+v", root)
		}
	})
	t.Run("login errors", func(t *testing.T) {
		cl := newBare()
		_, err := cl.Auth().Login(ctx, openbao.NewJWTAuth(env(t, "JWT_ROLE"), env(t, "JWT_EXPIRED")))
		wantErr(t, err, openbao.ErrAuthentication)
		_, err = cl.Auth().Login(ctx, openbao.NewUserpassAuth(env(t, "USERPASS_USER"), "wrong-password"))
		wantErr(t, err, openbao.ErrAuthentication)
		_, err = cl.Auth().Login(ctx, openbao.NewTokenAuth("not-a-token"))
		wantErr(t, err, openbao.ErrAuthentication)
	})
	t.Run("kubernetes request shape", func(t *testing.T) {
		// No Kubernetes API in the fixture: OpenBao's TokenReview fails, so the
		// login is rejected with 403 (success path: unit tests only).
		path := filepath.Join(t.TempDir(), "token")
		ok(t, os.WriteFile(path, []byte(env(t, "K8S_JWT")), 0o600))
		cl := newBare()
		_, err := cl.Auth().Login(ctx, &openbao.KubernetesAuth{Role: env(t, "K8S_ROLE"), JWTPath: path, Mount: env(t, "K8S_MOUNT")})
		if !errors.Is(err, openbao.ErrAuthentication) && !errors.Is(err, openbao.ErrPermissionDenied) {
			t.Fatalf("kubernetes: %v", err)
		}
		_, err = cl.Auth().Login(ctx, openbao.NewKubernetesAuth(env(t, "K8S_ROLE"), filepath.Join(t.TempDir(), "missing")))
		wantErr(t, err, openbao.ErrConfig)
	})
	t.Run("token lifecycle", func(t *testing.T) {
		id := runID(t)
		tok := get(c.Auth().CreateToken(ctx, &openbao.TokenCreateOptions{
			Policies: []string{env(t, "POLICY")}, TTL: time.Hour, Renewable: openbao.Ptr(true),
			DisplayName: "go-" + id, Meta: map[string]string{"run": id},
		})).of(t)
		cl := newBare()
		cl.SetToken(tok.ClientToken.Reveal())
		ti := get(cl.Auth().LookupSelf(ctx)).of(t)
		if ti.DisplayName != "token-go-"+id || ti.Meta["run"] != id || !ti.Renewable || ti.TTL <= 0 {
			t.Fatalf("lookup %+v", ti)
		}
		renewed := get(cl.Auth().RenewSelf(ctx, 30*time.Minute)).of(t)
		if renewed.LeaseDuration != 30*time.Minute {
			t.Fatalf("renew %s", renewed.LeaseDuration)
		}
		readAllowed(cl)
		ok(t, cl.Auth().RevokeSelf(ctx))
		if !cl.Token().IsZero() {
			t.Fatal("revoke must clear the token")
		}
		cl.SetToken(tok.ClientToken.Reveal())
		_, err := cl.Auth().LookupSelf(ctx)
		wantErr(t, err, openbao.ErrAuthentication)
		orphan := get(c.Auth().CreateToken(ctx, &openbao.TokenCreateOptions{NoParent: true, TTL: time.Minute, Renewable: openbao.Ptr(false)})).of(t)
		if !orphan.Orphan || orphan.Renewable {
			t.Fatalf("orphan %+v", orphan)
		}
		cl.SetToken(orphan.ClientToken.Reveal())
		_, err = cl.Auth().RenewSelf(ctx, time.Minute)
		wantErr(t, err, openbao.ErrValidation)
	})
	t.Run("token renewer", func(t *testing.T) {
		tok := get(c.Auth().CreateToken(ctx, &openbao.TokenCreateOptions{TTL: 3 * time.Second, ExplicitMaxTTL: 5 * time.Second, Renewable: openbao.Ptr(true)})).of(t)
		cl := newBare()
		cl.SetToken(tok.ClientToken.Reveal())
		var mu sync.Mutex
		renews := 0
		expired := make(chan struct{})
		r := get(cl.Auth().StartRenewer(ctx, &openbao.TokenRenewerOptions{
			Increment: 3 * time.Second,
			OnRenew:   func(*openbao.AuthInfo) { mu.Lock(); renews++; mu.Unlock() },
			OnExpire:  func() { close(expired) },
		})).of(t)
		select {
		case <-expired:
		case <-time.After(20 * time.Second):
			t.Fatal("token renewer never reported expiry")
		}
		<-r.Done()
		mu.Lock()
		defer mu.Unlock()
		if renews < 1 {
			t.Fatalf("renews %d", renews)
		}
	})
}

func TestKV(t *testing.T) {
	c := setup(t)
	ctx := t.Context()
	id := runID(t)
	base := "sdk/go-" + id

	if v := get(c.DetectKVVersion(ctx, env(t, "KV2_MOUNT"))).of(t); v != 2 {
		t.Fatalf("kv2 detect %d", v)
	}
	kv1 := get(c.KV(ctx, env(t, "KV1_MOUNT"))).of(t)
	if kv1.Version() != 1 || kv1.Mount() != env(t, "KV1_MOUNT") {
		t.Fatal("kv1 detect")
	}

	t.Run("v2", func(t *testing.T) {
		kv := c.KVv2(env(t, "KV2_MOUNT"))
		p := base + "/alpha"
		md := get(kv.Write(ctx, p, map[string]any{"a": "1", "b": "2"}, &openbao.KVWriteOptions{CAS: openbao.Ptr(0)})).of(t)
		if md.Version != 1 {
			t.Fatalf("v1 %+v", md)
		}
		_, err := kv.Write(ctx, p, map[string]any{"a": "x"}, &openbao.KVWriteOptions{CAS: openbao.Ptr(0)})
		wantErr(t, err, openbao.ErrConflict)
		get(kv.Write(ctx, p, map[string]any{"a": "3", "b": "2"}, &openbao.KVWriteOptions{CAS: openbao.Ptr(1)})).of(t)
		md = get(kv.Patch(ctx, p, map[string]any{"b": nil, "c": "new"}, nil)).of(t)
		if md.Version != 3 {
			t.Fatalf("patch version %d", md.Version)
		}
		sec := get(kv.Read(ctx, p, nil)).of(t)
		if sec.Data["a"] != "3" || sec.Data["c"] != "new" || sec.Data["b"] != nil || sec.Metadata.Version != 3 {
			t.Fatalf("read after patch %+v", sec)
		}
		if old := get(kv.Read(ctx, p, &openbao.KVReadOptions{Version: 1})).of(t); old.Data["a"] != "1" {
			t.Fatalf("version 1 %+v", old.Data)
		}
		ok(t, kv.WriteMetadata(ctx, p, openbao.KVMetadataOptions{MaxVersions: openbao.Ptr(5), CASRequired: openbao.Ptr(false),
			DeleteVersionAfter: openbao.Ptr(720 * time.Hour), CustomMetadata: map[string]string{"owner": "go"}}))
		meta := get(kv.ReadMetadata(ctx, p)).of(t)
		if meta.CurrentVersion != 3 || meta.MaxVersions != 5 || meta.DeleteVersionAfter != 720*time.Hour || meta.CustomMetadata["owner"] != "go" || len(meta.Versions) != 3 {
			t.Fatalf("metadata %+v", meta)
		}
		ok(t, kv.Delete(ctx, p))
		_, err = kv.Read(ctx, p, nil)
		wantErr(t, err, openbao.ErrNotFound)
		ok(t, kv.Undelete(ctx, p, []int{3}))
		get(kv.Read(ctx, p, nil)).of(t)
		ok(t, kv.DeleteVersions(ctx, p, []int{1}))
		_, err = kv.Read(ctx, p, &openbao.KVReadOptions{Version: 1})
		wantErr(t, err, openbao.ErrNotFound)
		ok(t, kv.Destroy(ctx, p, []int{2}))
		if meta := get(kv.ReadMetadata(ctx, p)).of(t); !meta.Versions[2].Destroyed || meta.Versions[1].DeletionTime.IsZero() {
			t.Fatalf("destroy %+v", meta.Versions)
		}
		get(kv.Write(ctx, base+"/beta", map[string]any{"v": "b"}, nil)).of(t)
		get(kv.Write(ctx, base+"/dir/gamma", map[string]any{"v": "g"}, nil)).of(t)
		if keys := get(kv.List(ctx, base)).of(t); !slices.Equal(keys, []string{"alpha", "beta", "dir/"}) {
			t.Fatalf("list %v", keys)
		}
		if keys := get(kv.List(ctx, base+"/none")).of(t); len(keys) != 0 {
			t.Fatal("missing list must be empty")
		}
		for _, k := range []string{"alpha", "beta", "dir/gamma"} {
			ok(t, kv.DeleteMetadata(ctx, base+"/"+k))
		}
		if keys := get(kv.List(ctx, base)).of(t); len(keys) != 0 {
			t.Fatalf("list after deleteMetadata %v", keys)
		}
		_, err = kv.ReadMetadata(ctx, base+"/alpha")
		wantErr(t, err, openbao.ErrNotFound)
	})
	t.Run("v1", func(t *testing.T) {
		kv := c.KVv1(env(t, "KV1_MOUNT"))
		p := base + "/with space"
		md := get(kv.Write(ctx, p, map[string]any{"a": "1", "n": 2}, nil)).of(t)
		if md != nil {
			t.Fatal("v1 write has no metadata")
		}
		if sec := get(kv.Read(ctx, p, nil)).of(t); sec.Data["a"] != "1" || sec.Data["n"] != float64(2) || sec.Metadata != nil {
			t.Fatalf("read %+v", sec)
		}
		if keys := get(kv.List(ctx, base)).of(t); !slices.Equal(keys, []string{"with space"}) {
			t.Fatalf("list %v", keys)
		}
		_, err := kv.Patch(ctx, p, map[string]any{"a": "2"}, nil)
		wantErr(t, err, openbao.ErrUnsupported)
		for _, err := range []error{
			kv.DeleteVersions(ctx, p, []int{1}), kv.Undelete(ctx, p, []int{1}), kv.Destroy(ctx, p, []int{1}),
			kv.WriteMetadata(ctx, p, openbao.KVMetadataOptions{}), kv.DeleteMetadata(ctx, p),
		} {
			wantErr(t, err, openbao.ErrUnsupported)
		}
		_, err = kv.ReadMetadata(ctx, p)
		wantErr(t, err, openbao.ErrUnsupported)
		ok(t, kv.Delete(ctx, p))
		_, err = kv.Read(ctx, p, nil)
		wantErr(t, err, openbao.ErrNotFound)
		ok(t, kv.Delete(ctx, p)) // missing path: 204, no error
	})
}

func TestSecretsProvider(t *testing.T) {
	c := setup(t)
	ctx := t.Context()
	id := runID(t)
	p := c.SecretsWith(openbao.SecretsProviderOptions{Path: "sdk/go-provider-" + id})

	v := get(p.Set(ctx, "alpha", "s3cr3t-"+id, &openbao.SetOptions{Tags: map[string]string{"team": "go"}, Description: "demo"})).of(t)
	if v != "1" {
		t.Fatalf("version %q", v)
	}
	get(p.Set(ctx, "alpha", "s3cr3t-2-"+id, &openbao.SetOptions{CAS: openbao.Ptr(1)})).of(t)
	_, err := p.Set(ctx, "alpha", "x", &openbao.SetOptions{CAS: openbao.Ptr(1)})
	wantErr(t, err, openbao.ErrConflict)
	if got := get(p.Get(ctx, "alpha", &openbao.GetOptions{Version: "1"})).of(t); got.Version() != "1" {
		t.Fatal("versioned get")
	}
	if s, found, err := p.GetString(ctx, "alpha", nil); err != nil || !found || s != "s3cr3t-2-"+id {
		t.Fatalf("getString %q %v", s, err)
	}
	md := get(p.Metadata(ctx, "alpha", nil)).of(t)
	if md.Version != "2" || md.Tags["team"] != "go" || md.Tags["description"] != "demo" || md.Versions != 2 {
		t.Fatalf("metadata %+v", md)
	}
	get(p.Set(ctx, "bin", []byte{0xff, 0x00, 0x10}, nil)).of(t)
	if b := get(p.Get(ctx, "bin", nil)).of(t); string(b.RevealBytes()) != "\xff\x00\x10" {
		t.Fatal("binary round trip")
	}
	get(p.Set(ctx, "cfg", map[string]any{"port": 5432}, nil)).of(t)
	var cfg struct{ Port int }
	if found, err := p.GetJSON(ctx, "cfg", &cfg, nil); err != nil || !found || cfg.Port != 5432 {
		t.Fatalf("json %+v %v", cfg, err)
	}
	get(p.Set(ctx, "num", "42", nil)).of(t)
	get(p.Set(ctx, "flag", "on", nil)).of(t)
	if n, _, err := p.GetNumber(ctx, "num", nil); err != nil || n != 42 {
		t.Fatal("number")
	}
	if b, _, err := p.GetBool(ctx, "flag", nil); err != nil || !b {
		t.Fatal("bool")
	}
	if !get(p.Exists(ctx, "num", nil)).of(t) || get(p.Exists(ctx, "nope", nil)).of(t) {
		t.Fatal("exists")
	}
	if _, err := p.Require(ctx, "nope", nil); !errors.Is(err, openbao.ErrNotFound) {
		t.Fatalf("require %v", err)
	}
	if many := get(p.GetMany(ctx, []string{"num", "flag", "nope"}, nil)).of(t); len(many) != 2 {
		t.Fatalf("getMany %d", len(many))
	}
	if all := get(p.GetAll(ctx, "")).of(t); len(all) != 5 {
		t.Fatalf("getAll %d", len(all))
	}
	list := get(p.List(ctx, "")).of(t)
	names := make([]string, len(list))
	for i, m := range list {
		names[i] = m.Name
	}
	if !slices.Equal(names, []string{"alpha", "bin", "cfg", "flag", "num"}) {
		t.Fatalf("list %v", names)
	}
	prefix := "GROW_GO_" + strings.ToUpper(id) + "_"
	get(p.Set(ctx, "env/db_user", "app-user", nil)).of(t)
	get(p.Set(ctx, "env/db-pass", "app-pass", nil)).of(t)
	set := get(p.LoadEnv(ctx, "env", &openbao.LoadEnvOptions{Prefix: prefix})).of(t)
	if len(set) != 2 || os.Getenv(prefix+"DB_USER") != "app-user" || os.Getenv(prefix+"DB_PASS") != "app-pass" || set[prefix+"DB_PASS"] != "env/db-pass" {
		t.Fatalf("loadEnv %v", set)
	}
	for name := range set {
		_ = os.Unsetenv(name)
	}
	mapped := get(p.LoadEnvMapping(ctx, map[string]string{prefix + "PORT_CFG": "cfg"}, nil)).of(t)
	if len(mapped) != 1 || !strings.Contains(os.Getenv(prefix+"PORT_CFG"), "5432") {
		t.Fatalf("loadEnvMapping %v", mapped)
	}
	_ = os.Unsetenv(prefix + "PORT_CFG")

	// watch sees a change, the cache serves reads
	changed := make(chan string, 4)
	h := p.Watch(ctx, "num", 200*time.Millisecond, func(nv, _ *openbao.SecretValue) {
		if nv != nil {
			s, _ := nv.Reveal()
			changed <- s
		}
	}, nil)
	time.Sleep(400 * time.Millisecond)
	get(p.Set(ctx, "num", "43", nil)).of(t)
	select {
	case s := <-changed:
		if s != "43" {
			t.Fatalf("watch value %q", s)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("watch saw no change")
	}
	h.Stop()
	cache := openbao.NewSecretCache(p, nil)
	if s, _, err := cache.GetString(ctx, "num", nil); err != nil || s != "43" {
		t.Fatalf("cache %q %v", s, err)
	}
	if st := cache.Stats(); st.Misses != 1 {
		t.Fatalf("cache stats %+v", st)
	}

	// deletes
	ok(t, p.Delete(ctx, "alpha", &openbao.DeleteOptions{Versions: []string{"1"}}))
	if got, _ := p.Get(ctx, "alpha", &openbao.GetOptions{Version: "1"}); got != nil {
		t.Fatal("version 1 must be deleted")
	}
	ok(t, p.Delete(ctx, "alpha", nil))
	if get(p.Exists(ctx, "alpha", nil)).of(t) {
		t.Fatal("soft-deleted secret must not exist")
	}
	wantErr(t, p.Delete(ctx, "alpha", nil), openbao.ErrNotFound)
	for _, n := range []string{"alpha", "bin", "cfg", "num", "flag", "env/db_user", "env/db-pass"} {
		ok(t, p.Delete(ctx, n, &openbao.DeleteOptions{Permanent: true}))
	}
	if list := get(p.List(ctx, "")).of(t); len(list) != 0 {
		t.Fatalf("list after permanent delete %v", list)
	}

	t.Run("kv v1 provider", func(t *testing.T) {
		p1 := c.SecretsWith(openbao.SecretsProviderOptions{Mount: env(t, "KV1_MOUNT"), Path: "sdk/go-provider-" + id})
		if v := get(p1.Set(ctx, "one", "1", nil)).of(t); v != "" {
			t.Fatalf("v1 version %q", v)
		}
		if s, _, _ := p1.GetString(ctx, "one", nil); s != "1" {
			t.Fatal("v1 get")
		}
		_, err := p1.Get(ctx, "one", &openbao.GetOptions{Version: "1"})
		wantErr(t, err, openbao.ErrValidation)
		ok(t, p1.Delete(ctx, "one", nil))
		wantErr(t, p1.Delete(ctx, "one", nil), openbao.ErrNotFound)
	})
	t.Run("restricted token detects the mount through the key path", func(t *testing.T) {
		cl := get(openbao.NewClient(openbao.Config{CommonConfig: c.Config().CommonConfig})).of(t)
		defer func() { _ = cl.Close() }()
		get(cl.Auth().Login(ctx, &openbao.AppRoleAuth{RoleID: env(t, "APPROLE_ROLE_ID"), SecretID: openbao.NewSecret(env(t, "APPROLE_SECRET_ID")), Mount: env(t, "APPROLE_MOUNT")})).of(t)
		if s, found, err := cl.Secrets().GetString(ctx, env(t, "ALLOWED_PATH"), nil); err != nil || !found || s != "world" {
			t.Fatalf("restricted get %q %v", s, err)
		}
		_, err := cl.Secrets().Get(ctx, env(t, "DENIED_PATH"), nil)
		wantErr(t, err, openbao.ErrPermissionDenied)
	})
	t.Run("namespace", func(t *testing.T) {
		ns := os.Getenv("GROW_OPENBAO_TEST_NAMESPACE")
		if ns == "" {
			t.Skip("namespaces not available")
		}
		cfg := c.Config()
		cfg.Token = c.Token()
		cfg.Namespace = ns
		cl := get(openbao.NewClient(cfg)).of(t)
		defer func() { _ = cl.Close() }()
		if s, found, err := cl.Secrets().GetString(ctx, "sdk/in-namespace", nil); err != nil || !found || s != "ns-only" {
			t.Fatalf("namespace get %q %v", s, err)
		}
		if got, _ := c.Secrets().Get(ctx, "sdk/in-namespace", nil); got != nil {
			t.Fatal("root namespace must not see the namespaced secret")
		}
	})
}

func TestTransit(t *testing.T) {
	c := setup(t)
	ctx := t.Context()
	tr := c.Transit(env(t, "TRANSIT_MOUNT"))
	name := "go-" + runID(t)

	key := get(tr.CreateKey(ctx, name, "aes256-gcm96", nil)).of(t)
	if key.Name != name || key.Type != "aes256-gcm96" || key.LatestVersion != 1 {
		t.Fatalf("create %+v", key)
	}
	if again := get(tr.CreateKey(ctx, name, "aes256-gcm96", nil)).of(t); again.LatestVersion != 1 {
		t.Fatal("create is idempotent")
	}
	if got := get(tr.ReadKey(ctx, name)).of(t); !got.SupportsEncryption || len(got.Keys) != 1 {
		t.Fatalf("read %+v", got)
	}
	if keys := get(tr.ListKeys(ctx)).of(t); !slices.Contains(keys, name) {
		t.Fatalf("list %v", keys)
	}
	ct := get(tr.Encrypt(ctx, name, []byte("hello go"), nil)).of(t)
	if !strings.HasPrefix(ct.Ciphertext, "vault:v1:") || ct.KeyVersion != 1 {
		t.Fatalf("encrypt %+v", ct)
	}
	if pt := get(tr.Decrypt(ctx, name, ct.Ciphertext, nil)).of(t); string(pt) != "hello go" {
		t.Fatalf("decrypt %q", pt)
	}
	if rot := get(tr.RotateKey(ctx, name)).of(t); rot.LatestVersion != 2 {
		t.Fatal("rotate")
	}
	rw := get(tr.Rewrap(ctx, name, ct.Ciphertext, nil)).of(t)
	if !strings.HasPrefix(rw.Ciphertext, "vault:v2:") {
		t.Fatalf("rewrap %+v", rw)
	}
	if pt := get(tr.Decrypt(ctx, name, rw.Ciphertext, nil)).of(t); string(pt) != "hello go" {
		t.Fatal("decrypt rewrapped")
	}
	cfg := get(tr.UpdateKeyConfig(ctx, name, openbao.TransitKeyConfig{MinDecryptionVersion: openbao.Ptr(2)})).of(t)
	if cfg.MinDecryptionVersion != 2 {
		t.Fatal("config")
	}
	_, err := tr.Decrypt(ctx, name, ct.Ciphertext, nil)
	wantErr(t, err, openbao.ErrValidation) // v1 ciphertext is below min_decryption_version

	res := get(tr.EncryptBatch(ctx, name, []openbao.TransitBatchItem{{Plaintext: []byte("one")}, {Plaintext: []byte("two"), Reference: "r2"}}, nil)).of(t)
	if len(res) != 2 || res[1].Reference != "r2" || res[0].Error != "" {
		t.Fatalf("encrypt batch %+v", res)
	}
	dec := get(tr.DecryptBatch(ctx, name, []openbao.TransitBatchItem{{Ciphertext: res[0].Ciphertext}, {Ciphertext: res[1].Ciphertext}, {Ciphertext: "vault:v2:AAAA"}})).of(t)
	if len(dec) != 3 || string(dec[0].Plaintext) != "one" || string(dec[1].Plaintext) != "two" || dec[2].Error == "" {
		t.Fatalf("decrypt batch %+v", dec)
	}
	dk := get(tr.GenerateDataKey(ctx, name, &openbao.DataKeyOptions{Bits: 256})).of(t)
	if len(dk.Plaintext) != 32 {
		t.Fatal("data key")
	}
	if pt := get(tr.Decrypt(ctx, name, dk.Ciphertext, nil)).of(t); string(pt) != string(dk.Plaintext) {
		t.Fatal("data key ciphertext must decrypt to the plaintext key")
	}
	if wk := get(tr.GenerateDataKey(ctx, name, &openbao.DataKeyOptions{Wrapped: true})).of(t); wk.Plaintext != nil || wk.Ciphertext == "" {
		t.Fatal("wrapped data key")
	}
	mac := get(tr.HMAC(ctx, name, []byte("mac me"), &openbao.HMACOptions{Algorithm: "sha2-256"})).of(t)
	if !get(tr.Verify(ctx, name, []byte("mac me"), mac, &openbao.VerifyOptions{SignOptions: openbao.SignOptions{HashAlgorithm: "sha2-256"}, HMAC: true})).of(t) {
		t.Fatal("hmac verify")
	}
	if get(tr.Verify(ctx, name, []byte("other"), mac, &openbao.VerifyOptions{SignOptions: openbao.SignOptions{HashAlgorithm: "sha2-256"}, HMAC: true})).of(t) {
		t.Fatal("hmac verify must fail for other input")
	}
	signKey := env(t, "TRANSIT_SIGN_KEY")
	sig := get(tr.Sign(ctx, signKey, []byte("sign me"), nil)).of(t)
	if !get(tr.Verify(ctx, signKey, []byte("sign me"), sig.Signature, nil)).of(t) || get(tr.Verify(ctx, signKey, []byte("tampered"), sig.Signature, nil)).of(t) {
		t.Fatal("ed25519 sign/verify")
	}
	rsaKey := env(t, "TRANSIT_RSA_KEY")
	rsig := get(tr.Sign(ctx, rsaKey, []byte("rsa"), &openbao.SignOptions{HashAlgorithm: "sha2-256", SignatureAlgorithm: "pkcs1v15"})).of(t)
	if !get(tr.Verify(ctx, rsaKey, []byte("rsa"), rsig.Signature, &openbao.VerifyOptions{SignOptions: openbao.SignOptions{HashAlgorithm: "sha2-256", SignatureAlgorithm: "pkcs1v15"}})).of(t) {
		t.Fatal("rsa sign/verify")
	}
	_, err = tr.Sign(ctx, name, []byte("x"), nil)
	wantErr(t, err, openbao.ErrValidation)
	if sum := get(tr.Hash(ctx, []byte("abc"), nil)).of(t); sum != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("hash %s", sum)
	}
	if sum := get(tr.Hash(ctx, []byte("abc"), &openbao.HashOptions{Algorithm: "sha2-256", Format: "base64"})).of(t); sum != "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=" {
		t.Fatalf("hash b64 %s", sum)
	}
	if rnd := get(tr.RandomBytes(ctx, 16, &openbao.RandomOptions{Format: "hex"})).of(t); len(rnd) != 32 {
		t.Fatalf("random %q", rnd)
	}
	if rnd := get(tr.RandomBytes(ctx, 16, nil)).of(t); len(rnd) != 24 {
		t.Fatalf("random b64 %q", rnd)
	}
	wantErr(t, tr.DeleteKey(ctx, name), openbao.ErrValidation) // deletion not allowed yet
	get(tr.UpdateKeyConfig(ctx, name, openbao.TransitKeyConfig{DeletionAllowed: openbao.Ptr(true)})).of(t)
	ok(t, tr.DeleteKey(ctx, name))
	_, err = tr.ReadKey(ctx, name)
	wantErr(t, err, openbao.ErrNotFound)
}

func TestDatabaseAndLeases(t *testing.T) {
	c := setup(t)
	ctx := t.Context()
	db := c.Database(env(t, "DB_MOUNT"))
	id := runID(t)
	conn, role := "pg-go-"+id, "ro-go-"+id
	url := fmt.Sprintf("postgresql://{{username}}:{{password}}@%s:%s/%s?sslmode=disable", env(t, "PG_HOST"), env(t, "PG_PORT"), env(t, "PG_DB"))
	ok(t, db.ConfigureConnection(ctx, conn, openbao.DatabaseConnectionConfig{
		PluginName: "postgresql-database-plugin", ConnectionURL: url, Username: env(t, "PG_ADMIN_USER"),
		Password: openbao.NewSecret(env(t, "PG_ADMIN_PASSWORD")), AllowedRoles: []string{role, role + "-short"}, VerifyConnection: openbao.Ptr(true),
	}))
	if got := get(db.ReadConnection(ctx, conn)).of(t); got["plugin_name"] != "postgresql-database-plugin" || got["password"] != nil {
		t.Fatalf("read connection %v", got)
	}
	wantErr(t, db.ConfigureConnection(ctx, conn+"-bad", openbao.DatabaseConnectionConfig{
		PluginName: "postgresql-database-plugin", ConnectionURL: url, Username: env(t, "PG_ADMIN_USER"), Password: openbao.NewSecret("wrong"),
	}), openbao.ErrValidation)
	stmt := []string{`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`, `GRANT SELECT ON public.sdk_probe TO "{{name}}";`}
	ok(t, db.CreateRole(ctx, role, openbao.DatabaseRoleConfig{DBName: conn, CreationStatements: stmt, DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour}))
	if r := get(db.ReadRole(ctx, role)).of(t); r.DefaultTTL != time.Hour || r.MaxTTL != 2*time.Hour || r.DBName != conn {
		t.Fatalf("read role %+v", r)
	}
	lease := get(db.GetCredentials(ctx, role)).of(t)
	if lease.ID == "" || !lease.Renewable || !near(lease.Duration, time.Hour) || lease.Username == "" || lease.Password.IsZero() {
		t.Fatalf("creds %+v", lease)
	}
	lm := c.Leases()
	lk := get(lm.Lookup(ctx, lease.ID)).of(t)
	if lk.ID != lease.ID || !lk.Renewable || lk.TTL <= 0 {
		t.Fatalf("lookup %+v", lk)
	}
	info := get(lm.Renew(ctx, lease.ID, 10*time.Minute)).of(t)
	if !near(info.Duration, 10*time.Minute) || info.Capped() {
		t.Fatalf("renew %+v", info)
	}
	if capped := get(lm.Renew(ctx, lease.ID, 100*time.Hour)).of(t); !capped.Capped() || capped.Duration > 2*time.Hour {
		t.Fatalf("capped renew %+v", capped)
	}
	ok(t, lm.Revoke(ctx, lease.ID))
	_, err := lm.Lookup(ctx, lease.ID)
	wantErr(t, err, openbao.ErrValidation)
	_, err = lm.Renew(ctx, lease.ID, 0)
	wantErr(t, err, openbao.ErrValidation)

	second := get(db.GetCredentials(ctx, role)).of(t)
	ok(t, lm.RevokePrefix(ctx, env(t, "DB_MOUNT")+"/creds/"+role))
	_, err = lm.Lookup(ctx, second.ID)
	wantErr(t, err, openbao.ErrValidation)

	// auto-renew until the max TTL caps the grant, then OnExpire exactly once
	short := role + "-short"
	ok(t, db.CreateRole(ctx, short, openbao.DatabaseRoleConfig{DBName: conn, CreationStatements: stmt, DefaultTTL: 2 * time.Second, MaxTTL: 4 * time.Second}))
	sl := get(db.GetCredentials(ctx, short)).of(t)
	var mu sync.Mutex
	renews, expires := 0, 0
	expired := make(chan struct{})
	ml := lm.Manage(sl, &openbao.ManageOptions{
		Increment: 2 * time.Second,
		OnRenew:   func(*openbao.LeaseInfo) { mu.Lock(); renews++; mu.Unlock() },
		OnExpire: func(*openbao.Lease) {
			mu.Lock()
			expires++
			mu.Unlock()
			close(expired)
		},
	})
	select {
	case <-expired:
	case <-time.After(20 * time.Second):
		t.Fatal("managed lease never expired")
	}
	<-ml.Done()
	mu.Lock()
	if renews < 1 || expires != 1 || ml.Lease().ID != sl.ID {
		t.Fatalf("renews=%d expires=%d", renews, expires)
	}
	mu.Unlock()

	_, err = db.GetCredentials(ctx, "unknown-"+id)
	wantErr(t, err, openbao.ErrValidation)
	ok(t, db.DeleteRole(ctx, short))
	ok(t, db.DeleteRole(ctx, role))
	_, err = db.ReadRole(ctx, role)
	wantErr(t, err, openbao.ErrNotFound)
	ok(t, db.DeleteConnection(ctx, conn))
	if _, err := db.ReadConnection(ctx, conn); !errors.Is(err, openbao.ErrNotFound) {
		t.Fatalf("connection after delete: %v", err)
	}
}

func TestPKI(t *testing.T) {
	c := setup(t)
	ctx := t.Context()
	p := c.PKI(env(t, "PKI_MOUNT"))
	role, domain := env(t, "PKI_ROLE"), env(t, "PKI_DOMAIN")
	id := runID(t)

	cert := get(p.IssueCertificate(ctx, role, "svc-"+id+"."+domain, &openbao.IssueOptions{AltNames: []string{"alt-" + id + "." + domain}, IPSANs: []string{"127.0.0.1"}, TTL: time.Hour})).of(t)
	block, _ := pem.Decode([]byte(cert.Certificate))
	x := get(x509.ParseCertificate(block.Bytes)).of(t)
	if x.Subject.CommonName != "svc-"+id+"."+domain || !slices.Contains(x.DNSNames, "alt-"+id+"."+domain) || cert.PrivateKey.IsZero() {
		t.Fatalf("issued %v %v", x.Subject, x.DNSNames)
	}
	chain := get(p.ReadCAChain(ctx)).of(t)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(chain)) {
		t.Fatal("ca chain is not PEM")
	}
	if _, err := x.Verify(x509.VerifyOptions{Roots: pool, DNSName: "svc-" + id + "." + domain}); err != nil {
		t.Fatalf("chain verify: %v", err)
	}
	key := get(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)).of(t)
	csrDER := get(x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "csr-" + id + "." + domain}}, key)).of(t)
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	signed := get(p.SignCSR(ctx, role, csr, &openbao.IssueOptions{TTL: time.Hour})).of(t)
	sb, _ := pem.Decode([]byte(signed.Certificate))
	sx := get(x509.ParseCertificate(sb.Bytes)).of(t)
	if pub, isEC := sx.PublicKey.(*ecdsa.PublicKey); !isEC || !pub.Equal(&key.PublicKey) || !signed.PrivateKey.IsZero() {
		t.Fatal("signed certificate must carry the CSR key")
	}
	if serials := get(p.ListCertificates(ctx)).of(t); !slices.Contains(serials, cert.SerialNumber) {
		t.Fatalf("list %v", serials)
	}
	if info := get(p.ReadCertificate(ctx, cert.SerialNumber)).of(t); info.Revoked() || info.Certificate == "" {
		t.Fatal("read before revoke")
	}
	rev := get(p.RevokeCertificate(ctx, cert.SerialNumber)).of(t)
	if rev.State != "revoked" || rev.RevocationTime.IsZero() {
		t.Fatalf("revoke %+v", rev)
	}
	if info := get(p.ReadCertificate(ctx, cert.SerialNumber)).of(t); !info.Revoked() {
		t.Fatal("read after revoke")
	}
	_, err := p.IssueCertificate(ctx, role, "evil.example.com", nil)
	wantErr(t, err, openbao.ErrValidation)
	_, err = p.ReadCertificate(ctx, "ff:ff:ff:ff")
	wantErr(t, err, openbao.ErrNotFound)
	_, err = p.RevokeCertificate(ctx, "ff:ff:ff:ff")
	wantErr(t, err, openbao.ErrValidation)
	st := get(p.Tidy(ctx, &openbao.TidyOptions{SafetyBuffer: time.Second, Wait: true})).of(t)
	if st.State != "Finished" {
		t.Fatalf("tidy %+v", st)
	}
	if st := get(p.TidyStatus(ctx)).of(t); st.State != "Finished" {
		t.Fatalf("tidy status %+v", st)
	}
}

func TestWrapping(t *testing.T) {
	c := setup(t)
	ctx := t.Context()
	w := c.Wrapping()
	id := runID(t)
	info := get(w.Wrap(ctx, map[string]any{"secret": "wrapped-" + id, "n": 1}, time.Minute)).of(t)
	if info.TTL != time.Minute || info.CreationPath != "sys/wrapping/wrap" {
		t.Fatalf("wrap %+v", info)
	}
	lk := get(w.LookupWrapping(ctx, info.Token.Reveal())).of(t)
	if lk.CreationTTL != time.Minute || lk.CreationPath != "sys/wrapping/wrap" {
		t.Fatalf("lookup %+v", lk)
	}
	res := get(w.Unwrap(ctx, info.Token.Reveal())).of(t)
	if res.Data["secret"] != "wrapped-"+id || res.Data["n"] != float64(1) {
		t.Fatalf("unwrap %+v", res.Data)
	}
	_, err := w.Unwrap(ctx, info.Token.Reveal())
	wantErr(t, err, openbao.ErrValidation)
	_, err = w.LookupWrapping(ctx, info.Token.Reveal())
	wantErr(t, err, openbao.ErrValidation)
}

func TestTestingInitUnseal(t *testing.T) {
	c := setup(t)
	ctx := t.Context()
	url := env(t, "SHAMIR_URL")
	sc := get(openbao.NewClient(openbao.Config{CommonConfig: openbao.CommonConfig{URL: url}})).of(t)
	defer func() { _ = sc.Close() }()
	initialized := get(testkit.InitStatus(ctx, sc, nil)).of(t)
	if initialized {
		t.Skip("the Shamir instance is already initialised (fresh per compose project)")
	}
	if hs := get(sc.Health(ctx)).of(t); hs.Status != "uninitialized" || hs.Healthy {
		t.Fatalf("before init %+v", hs)
	}
	res := get(testkit.Init(ctx, sc, &testkit.InitOptions{SecretShares: 1, SecretThreshold: 1})).of(t)
	if len(res.Keys) != 1 || res.RootToken.IsZero() {
		t.Fatal("init result")
	}
	_, err := testkit.Init(ctx, sc, nil)
	wantErr(t, err, openbao.ErrValidation)
	if !get(testkit.InitStatus(ctx, sc, nil)).of(t) {
		t.Fatal("init status")
	}
	if hs := get(sc.Health(ctx)).of(t); hs.Status != "sealed" {
		t.Fatalf("after init %+v", hs)
	}
	st := get(sc.Sys().SealStatus(ctx)).of(t)
	if !st.Sealed || st.T != 1 || st.Type != "shamir" {
		t.Fatalf("seal status %+v", st)
	}
	_, err = testkit.Unseal(ctx, sc, "not-a-key", nil)
	wantErr(t, err, openbao.ErrValidation)
	us := get(testkit.Unseal(ctx, sc, res.Keys[0].Reveal(), nil)).of(t)
	if us.Sealed {
		t.Fatal("still sealed")
	}
	if hs := get(testkit.WaitForActive(ctx, sc, 30*time.Second)).of(t); hs.State != "active" {
		t.Fatalf("active %+v", hs)
	}
	sc.SetToken(res.RootToken.Reveal())
	if _, err := sc.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	ok(t, testkit.Seal(ctx, sc, nil))
	if st := get(sc.Sys().SealStatus(ctx)).of(t); !st.Sealed {
		t.Fatal("seal")
	}
	_ = c
}

// near reports whether a lease duration the server computed is within a few seconds of want
// (OpenBao counts from issue time, so a lease can come back as 59m59s instead of 1h).
func near(got, want time.Duration) bool {
	return got <= want && got >= want-5*time.Second
}
