package openbao_test

import (
	"context"
	"errors"
	"fmt"

	"strings"
	"testing"

	openbao "github.com/grow-codes-packages/openbao/go"
	"github.com/grow-codes-packages/openbao/go/testkit"
)

func fakeClient(t *testing.T, f *fakeKV, mutate func(*openbao.Config)) *openbao.Client {
	t.Helper()
	cfg := openbao.Config{CommonConfig: openbao.CommonConfig{URL: f.URL, Retry: &openbao.RetryPolicy{}}, Token: openbao.NewSecret("unit-token")}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := openbao.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestSecretsConformanceUnit runs the shared secrets scenarios against the
// in-memory KV server for both KV versions.
func TestSecretsConformanceUnit(t *testing.T) {
	for _, mount := range []string{"secret", "kv1"} {
		t.Run(mount, func(t *testing.T) {
			f := newFakeKV(t)
			testkit.Run(t, "../conformance/scenarios", testkit.Options{
				Categories:   []string{"secrets"},
				Capabilities: []string{"write", "delete"},
				Factories: testkit.Factories{"secrets": testkit.SecretsFactory(func(context.Context) (openbao.SecretsProvider, error) {
					return fakeClient(t, f, func(c *openbao.Config) { c.KVMount = mount }).Secrets(), nil
				})},
			})
		})
	}
}

func TestKVSecretsProviderV2(t *testing.T) {
	f := newFakeKV(t)
	c := fakeClient(t, f, func(c *openbao.Config) { c.SecretsPath = "apps/demo" })
	p := c.Secrets()
	ctx := t.Context()

	v1, err := p.Set(ctx, "db/password", "pw-1", nil)
	if err != nil || v1 != "1" {
		t.Fatalf("set %q %v", v1, err)
	}
	if _, err := p.Set(ctx, "db/password", "pw-2", &openbao.SetOptions{CAS: openbao.Ptr(1), Tags: map[string]string{"team": "a"}, Description: "db"}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Set(ctx, "db/password", "pw-3", &openbao.SetOptions{CAS: openbao.Ptr(1)}); !errors.Is(err, openbao.ErrConflict) {
		t.Fatalf("cas mismatch: %v", err)
	}
	got, err := p.Get(ctx, "db/password", &openbao.GetOptions{Version: "1"})
	if s, _ := got.Reveal(); err != nil || s != "pw-1" || got.Version() != "1" {
		t.Fatalf("version 1: %v", err)
	}
	if _, err := p.Get(ctx, "db/password", &openbao.GetOptions{Version: "x"}); !errors.Is(err, openbao.ErrValidation) {
		t.Fatalf("bad version: %v", err)
	}
	md, err := p.Metadata(ctx, "db/password", nil)
	if err != nil || md.Version != "2" || md.Tags["team"] != "a" || md.Tags["description"] != "db" || md.Versions != 2 ||
		md.Path != "db" || md.Name != "db/password" || md.Extra["max_versions"] != "0" || md.CreatedAt.IsZero() {
		t.Fatalf("metadata %+v %v", md, err)
	}
	// binary and JSON values
	if _, err := p.Set(ctx, "bin", []byte{0xff, 0x00, 0x01}, nil); err != nil {
		t.Fatal(err)
	}
	if b, err := p.Get(ctx, "bin", nil); err != nil || string(b.RevealBytes()) != "\xff\x00\x01" {
		t.Fatalf("binary %v", err)
	}
	if f.v2["apps/demo/bin"].versions[1].data["encoding"] != "base64" {
		t.Fatal("binary must be stored base64")
	}
	if _, err := p.Set(ctx, "obj", map[string]any{"a": 1}, nil); err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if ok, err := p.GetJSON(ctx, "obj", &obj, nil); !ok || err != nil || obj["a"] != float64(1) {
		t.Fatalf("json %v %v", obj, err)
	}
	// native multi-field secret written by someone else
	kv := c.KVv2("")
	if _, err := kv.Write(ctx, "apps/demo/native", map[string]any{"user": "u", "pass": "p"}, nil); err != nil {
		t.Fatal(err)
	}
	var native map[string]string
	if ok, err := p.GetJSON(ctx, "native", &native, nil); !ok || err != nil || native["user"] != "u" {
		t.Fatalf("native %v %v", native, err)
	}
	if _, err := kv.Write(ctx, "apps/demo/num", map[string]any{"value": 42}, nil); err != nil {
		t.Fatal(err)
	}
	if n, ok, err := p.GetNumber(ctx, "num", nil); !ok || err != nil || n != 42 {
		t.Fatalf("non-string value %v %v", n, err)
	}
	// list skips folders and deleted keys; names are relative to the base path
	if err := p.Delete(ctx, "obj", nil); err != nil {
		t.Fatal(err)
	}
	list, err := p.List(ctx, "")
	if err != nil || len(list) != 3 || list[0].Name != "bin" || list[1].Name != "native" || list[2].Name != "num" {
		t.Fatalf("list %+v %v", list, err)
	}
	if list, err := p.List(ctx, "db"); err != nil || len(list) != 1 || list[0].Name != "db/password" {
		t.Fatalf("list db %+v %v", list, err)
	}
	all, err := p.GetAll(ctx, "db")
	if err != nil || len(all) != 1 || all["db/password"] == nil {
		t.Fatalf("getAll %v %v", all, err)
	}
	// deletes
	if err := p.Delete(ctx, "db/password", &openbao.DeleteOptions{Versions: []string{"1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Get(ctx, "db/password", &openbao.GetOptions{Version: "1"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(ctx, "db/password", &openbao.DeleteOptions{Versions: []string{"x"}}); !errors.Is(err, openbao.ErrValidation) {
		t.Fatalf("bad versions: %v", err)
	}
	if err := p.Delete(ctx, "db/password", &openbao.DeleteOptions{Permanent: true}); err != nil || f.v2["apps/demo/db/password"] != nil {
		t.Fatalf("permanent: %v", err)
	}
	if err := p.Delete(ctx, "db/password", nil); !errors.Is(err, openbao.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := p.Delete(ctx, "obj", nil); !errors.Is(err, openbao.ErrNotFound) {
		t.Fatalf("already soft-deleted: %v", err)
	}
	// per-call path
	if _, err := p.Set(ctx, "k", "v", &openbao.SetOptions{Path: "other"}); err != nil || f.v2["other/k"] == nil {
		t.Fatalf("set path: %v", err)
	}
	if s, ok, err := p.GetString(ctx, "k", &openbao.GetOptions{Path: "other"}); !ok || err != nil || s != "v" {
		t.Fatalf("get path: %v", err)
	}
	if kv, err := p.KV(ctx); err != nil || kv.Version() != 2 {
		t.Fatalf("provider KV %v", err)
	}
	if fmt.Sprint(got) != "SecretValue([REDACTED])" {
		t.Fatal("redaction")
	}
}

func TestKVSecretsProviderV1(t *testing.T) {
	f := newFakeKV(t)
	c := fakeClient(t, f, nil)
	p := c.SecretsWith(openbao.SecretsProviderOptions{Mount: "kv1", ValueField: "secret"})
	ctx := t.Context()
	if v, err := p.Set(ctx, "a/b", "x", nil); err != nil || v != "" || f.v1["a/b"]["secret"] != "x" {
		t.Fatalf("set %q %v %v", v, err, f.v1)
	}
	if got, err := p.Get(ctx, "a/b", nil); err != nil || got.Version() != "" {
		t.Fatalf("get %v", err)
	}
	if _, err := p.Get(ctx, "a/b", &openbao.GetOptions{Version: "1"}); !errors.Is(err, openbao.ErrValidation) {
		t.Fatalf("v1 version: %v", err)
	}
	for _, opts := range []*openbao.SetOptions{{CAS: openbao.Ptr(0)}, {Tags: map[string]string{"a": "b"}}, {Description: "d"}} {
		if _, err := p.Set(ctx, "a/b", "y", opts); !errors.Is(err, openbao.ErrUnsupported) {
			t.Fatalf("v1 set options: %v", err)
		}
	}
	if err := p.Delete(ctx, "a/b", &openbao.DeleteOptions{Versions: []string{"1"}}); !errors.Is(err, openbao.ErrUnsupported) {
		t.Fatalf("v1 delete versions: %v", err)
	}
	md, err := p.Metadata(ctx, "a/b", nil)
	if err != nil || md.Name != "a/b" || md.Path != "a" || md.Version != "" {
		t.Fatalf("metadata %+v %v", md, err)
	}
	list, err := p.List(ctx, "a")
	if err != nil || len(list) != 1 || list[0].Name != "a/b" {
		t.Fatalf("list %+v %v", list, err)
	}
	if err := p.Delete(ctx, "a/b", nil); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(ctx, "a/b", nil); !errors.Is(err, openbao.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	set, err := p.LoadEnv(ctx, "a", nil)
	if err != nil || len(set) != 0 {
		t.Fatalf("loadEnv empty %v %v", set, err)
	}
}

func TestKVSecretsProviderErrors(t *testing.T) {
	f := newFakeKV(t)
	c := fakeClient(t, f, nil)
	p := c.SecretsWith(openbao.SecretsProviderOptions{Mount: "locked"})
	ctx := t.Context()
	checks := []error{}
	_, err := p.Get(ctx, "x", nil)
	checks = append(checks, err)
	_, err = p.List(ctx, "")
	checks = append(checks, err)
	_, err = p.Set(ctx, "x", "y", nil)
	checks = append(checks, err)
	checks = append(checks, p.Delete(ctx, "x", nil))
	_, err = p.Metadata(ctx, "x", nil)
	checks = append(checks, err)
	_, err = p.KV(ctx)
	checks = append(checks, err)
	for i, err := range checks {
		if !errors.Is(err, openbao.ErrPermissionDenied) {
			t.Fatalf("check %d: %v", i, err)
		}
	}
	// errors from the KV calls themselves (closed client)
	c2 := fakeClient(t, f, nil)
	p2 := c2.Secrets()
	if _, err := p2.Set(ctx, "warm", "x", nil); err != nil { // caches the detection
		t.Fatal(err)
	}
	p1 := c2.SecretsWith(openbao.SecretsProviderOptions{Mount: "kv1"})
	if _, err := p1.Set(ctx, "warm", "x", nil); err != nil {
		t.Fatal(err)
	}
	_ = c2.Close()
	for _, prov := range []*openbao.KVSecretsProvider{p2, p1} {
		if _, err := prov.Get(ctx, "x", nil); !errors.Is(err, openbao.ErrCancelled) {
			t.Fatalf("get: %v", err)
		}
		if _, err := prov.List(ctx, ""); !errors.Is(err, openbao.ErrCancelled) {
			t.Fatalf("list: %v", err)
		}
		if _, err := prov.Set(ctx, "x", "y", nil); !errors.Is(err, openbao.ErrCancelled) {
			t.Fatalf("set: %v", err)
		}
		if err := prov.Delete(ctx, "x", nil); !errors.Is(err, openbao.ErrCancelled) {
			t.Fatalf("delete: %v", err)
		}
		if _, err := prov.Metadata(ctx, "x", nil); !errors.Is(err, openbao.ErrCancelled) {
			t.Fatalf("metadata: %v", err)
		}
	}
	// tag write failure after a successful write
	c3 := fakeClient(t, f, nil)
	if _, err := c3.Secrets().Set(ctx, "x", "y", &openbao.SetOptions{Tags: map[string]string{"a": "b"}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprint(c3.Config()), "unit-token") {
		t.Fatal("config leaks the token")
	}
}
