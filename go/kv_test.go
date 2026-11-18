package openbao

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestKVDetect(t *testing.T) {
	m := newMockBao(t).
		fixture("GET", "/v1/sys/internal/ui/mounts/kv1", "mountDetect.kv1").
		fixture("GET", "/v1/sys/internal/ui/mounts/secret", "mountDetect.kv2").
		data("GET", "/v1/sys/internal/ui/mounts/transit", map[string]any{"type": "transit"}).
		fixture("GET", "/v1/sys/internal/ui/mounts/locked", "mountDetect.no-access")
	c := newBao(t, m, nil)
	ctx := t.Context()
	kv, err := c.KV(ctx, "kv1")
	if err != nil || kv.Version() != 1 || kv.Mount() != "kv1" {
		t.Fatalf("kv1 %v %v", kv, err)
	}
	kv, err = c.KV(ctx, "")
	if err != nil || kv.Version() != 2 || kv.Mount() != "secret" {
		t.Fatalf("default %v %v", kv, err)
	}
	if _, err := c.KV(ctx, "secret"); err != nil || m.count("GET", "/v1/sys/internal/ui/mounts/secret") != 1 {
		t.Fatal("detection must be cached per mount")
	}
	if v, err := c.DetectKVVersion(ctx, "secret"); err != nil || v != 2 || m.count("GET", "/v1/sys/internal/ui/mounts/secret") != 2 {
		t.Fatal("DetectKVVersion is not cached")
	}
	_, err = c.KV(ctx, "transit")
	wantCode(t, err, ErrorCodeValidation)
	_, err = c.KV(ctx, "locked")
	wantCode(t, err, ErrorCodePermissionDenied)

	forced := newBao(t, newMockBao(t), func(c *Config) { c.KVVersion = 1 })
	if kv, err := forced.KV(ctx, "anything"); err != nil || kv.Version() != 1 {
		t.Fatal("forced version")
	}
	if c.KVv1("").Mount() != "secret" || c.KVv2("/x/").Mount() != "x" {
		t.Fatal("mounts")
	}
}

func TestKVv2(t *testing.T) {
	const p = "/v1/secret/data/app/alpha"
	m := newMockBao(t).
		fixture("GET", p, "kvV2.read.ok").
		fixture("POST", p, "kvV2.write.cas-ok").
		fixture("PATCH", p, "kvV2.patch.ok").
		noContent("DELETE", p).
		noContent("POST", "/v1/secret/delete/app/alpha").
		noContent("POST", "/v1/secret/undelete/app/alpha").
		noContent("PUT", "/v1/secret/destroy/app/alpha").
		fixture("GET", "/v1/secret/metadata/app", "kvV2.list.ok").
		fixture("GET", "/v1/secret/metadata/app/alpha", "kvV2.readMetadata.ok").
		noContent("POST", "/v1/secret/metadata/app/alpha").
		noContent("DELETE", "/v1/secret/metadata/app/alpha")
	kv := newBao(t, m, nil).KVv2("secret")
	ctx := t.Context()

	sec, err := kv.Read(ctx, "app/alpha", nil)
	if err != nil || sec.Data["a"] != "1" || sec.Metadata.Version != 1 || sec.Metadata.CreatedTime.IsZero() || sec.Metadata.Deleted() {
		t.Fatalf("read %+v %v", sec, err)
	}
	if _, err := kv.Read(ctx, "/app/alpha/", &KVReadOptions{Version: 3}); err != nil || m.last("GET", p).Query != "version=3" {
		t.Fatal("versioned read")
	}
	md, err := kv.Write(ctx, "app/alpha", map[string]any{"v": "x"}, &KVWriteOptions{CAS: Ptr(1)})
	if err != nil || md.Version != 2 {
		t.Fatalf("write %+v %v", md, err)
	}
	if b := m.last("POST", p).JSON(t); b["options"].(map[string]any)["cas"] != float64(1) || b["data"].(map[string]any)["v"] != "x" {
		t.Fatalf("write body %v", b)
	}
	if _, err := kv.Write(ctx, "app/alpha", nil, nil); err != nil {
		t.Fatal(err)
	}
	if b := m.last("POST", p).JSON(t); b["options"] != nil || b["data"] == nil {
		t.Fatalf("write without cas %v", b)
	}
	md, err = kv.Patch(ctx, "app/alpha", map[string]any{"b": nil}, nil)
	if err != nil || md.Version == 0 || m.last("PATCH", p).Header.Get("Content-Type") != "application/merge-patch+json" {
		t.Fatalf("patch %+v %v", md, err)
	}
	if err := kv.Delete(ctx, "app/alpha"); err != nil {
		t.Fatal(err)
	}
	if err := kv.DeleteVersions(ctx, "app/alpha", []int{1}); err != nil || m.last("POST", "/v1/secret/delete/app/alpha").JSON(t)["versions"] == nil {
		t.Fatal("deleteVersions")
	}
	if err := kv.Undelete(ctx, "app/alpha", []int{1, 2}); err != nil {
		t.Fatal(err)
	}
	if err := kv.Destroy(ctx, "app/alpha", []int{1}); err != nil {
		t.Fatal(err)
	}
	wantCode(t, kv.Destroy(ctx, "app/alpha", nil), ErrorCodeValidation)
	keys, err := kv.List(ctx, "app")
	if err != nil || len(keys) != 3 || keys[2] != "dir/" || m.last("GET", "/v1/secret/metadata/app").Query != "list=true" {
		t.Fatalf("list %v %v", keys, err)
	}
	if keys, err := kv.List(ctx, "missing"); err != nil || len(keys) != 0 || keys == nil {
		t.Fatalf("missing list %v %v", keys, err)
	}
	meta, err := kv.ReadMetadata(ctx, "app/alpha")
	if err != nil || meta.CurrentVersion != 3 || meta.MaxVersions != 5 || meta.DeleteVersionAfter != 720*time.Hour ||
		len(meta.Versions) != 3 || meta.Versions[2].Version != 2 || meta.CustomMetadata["owner"] != "sdk" || meta.UpdatedTime.IsZero() {
		t.Fatalf("metadata %+v %v", meta, err)
	}
	err = kv.WriteMetadata(ctx, "app/alpha", KVMetadataOptions{
		MaxVersions: Ptr(5), CASRequired: Ptr(false), DeleteVersionAfter: Ptr(720 * time.Hour), CustomMetadata: map[string]string{"k": "v"},
	})
	b := m.last("POST", "/v1/secret/metadata/app/alpha").JSON(t)
	if err != nil || b["max_versions"] != float64(5) || b["cas_required"] != false || b["delete_version_after"] != "2592000s" || b["custom_metadata"] == nil {
		t.Fatalf("writeMetadata %v %v", b, err)
	}
	if err := kv.DeleteMetadata(ctx, "app/alpha"); err != nil {
		t.Fatal(err)
	}

	t.Run("errors", func(t *testing.T) {
		m := newMockBao(t).
			fixture("GET", p, "kvV2.read.deleted-version").
			fixture("POST", p, "kvV2.write.cas-mismatch").
			fixture("PATCH", p, "kvV2.patch.wrong-content-type").
			fixture("GET", "/v1/secret/metadata/app/alpha", "kvV2.readMetadata.not-found").
			data("GET", "/v1/secret/data/app/empty", map[string]any{"data": nil}).
			data("GET", "/v1/secret/metadata/app/bad", map[string]any{"versions": map[string]any{"x": map[string]any{}}})
		kv := newBao(t, m, nil).KVv2("")
		_, err := kv.Read(t.Context(), "app/alpha", &KVReadOptions{Version: 1})
		wantCode(t, err, ErrorCodeNotFound)
		_, err = kv.Read(t.Context(), "app/empty", nil)
		wantCode(t, err, ErrorCodeNotFound)
		_, err = kv.Write(t.Context(), "app/alpha", map[string]any{"a": "x"}, &KVWriteOptions{CAS: Ptr(0)})
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("cas mismatch: %v", err)
		}
		_, err = kv.Patch(t.Context(), "app/alpha", map[string]any{"a": 1}, nil)
		wantCode(t, err, ErrorCodeValidation)
		_, err = kv.ReadMetadata(t.Context(), "app/alpha")
		wantCode(t, err, ErrorCodeNotFound)
		if md, err := kv.ReadMetadata(t.Context(), "app/bad"); err != nil || len(md.Versions) != 0 {
			t.Fatalf("bad version key: %v", err)
		}
		_, err = kv.Write(t.Context(), "nope", nil, nil)
		wantCode(t, err, ErrorCodeNotFound)
		_, err = kv.Patch(t.Context(), "nope", nil, nil)
		wantCode(t, err, ErrorCodeNotFound)
	})
}

func TestKVv1(t *testing.T) {
	const p = "/v1/kv1/app/alpha"
	m := newMockBao(t).
		fixture("GET", p, "kvV1.read.ok").
		fixture("POST", p, "kvV1.write.ok").
		fixture("DELETE", p, "kvV1.delete.ok").
		fixture("GET", "/v1/kv1/app", "kvV1.list.ok").
		data("GET", "/v1/kv1/app/empty", nil)
	kv := newBao(t, m, nil).KVv1("kv1")
	ctx := t.Context()
	sec, err := kv.Read(ctx, "app/alpha", nil)
	if err != nil || sec.Data["a"] != "1" || sec.Metadata != nil || kv.Version() != 1 || kv.Mount() != "kv1" {
		t.Fatalf("read %+v %v", sec, err)
	}
	if sec, err := kv.Read(ctx, "app/empty", nil); err != nil || sec.Data == nil {
		t.Fatal("empty data")
	}
	if md, err := kv.Write(ctx, "app/alpha", map[string]any{"a": "1"}, nil); err != nil || md != nil {
		t.Fatalf("write %v %v", md, err)
	}
	if _, err := kv.Write(ctx, "app/alpha", nil, &KVWriteOptions{}); err != nil || string(m.last("POST", p).Body) != "{}" {
		t.Fatal("write nil data")
	}
	if err := kv.Delete(ctx, "app/alpha"); err != nil {
		t.Fatal(err)
	}
	if keys, err := kv.List(ctx, "app"); err != nil || len(keys) == 0 {
		t.Fatalf("list %v %v", keys, err)
	}
	_, err = kv.Read(ctx, "app/alpha", &KVReadOptions{Version: 1})
	wantCode(t, err, ErrorCodeUnsupported)
	_, err = kv.Write(ctx, "x", nil, &KVWriteOptions{CAS: Ptr(0)})
	wantCode(t, err, ErrorCodeUnsupported)
	_, err = kv.Patch(ctx, "x", nil, nil)
	wantCode(t, err, ErrorCodeUnsupported)
	_, err = kv.ReadMetadata(ctx, "x")
	wantCode(t, err, ErrorCodeUnsupported)
	for _, err := range []error{
		kv.DeleteVersions(ctx, "x", []int{1}), kv.Undelete(ctx, "x", []int{1}), kv.Destroy(ctx, "x", []int{1}),
		kv.WriteMetadata(ctx, "x", KVMetadataOptions{}), kv.DeleteMetadata(ctx, "x"),
	} {
		wantCode(t, err, ErrorCodeUnsupported)
	}
	if n := len(m.requests()); n != 6 {
		t.Fatalf("v1-only errors must not send requests (%d requests)", n)
	}
	_, err = kv.Read(ctx, "missing", nil)
	wantCode(t, err, ErrorCodeNotFound)

	t.Run("server 405 is UNSUPPORTED", func(t *testing.T) {
		m := newMockBao(t).fixture("PATCH", p, "kvV1.patch.unsupported")
		_, err := newBao(t, m, nil).send(t.Context(), apiRequest{method: http.MethodPatch, path: "kv1/app/alpha", body: map[string]any{}, op: "patch"})
		wantCode(t, err, ErrorCodeUnsupported)
	})
}
