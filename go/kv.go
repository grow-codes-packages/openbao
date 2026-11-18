package openbao

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// KV is the common interface of KVv1 and KVv2. Operations that exist only on
// KV v2 (Patch, DeleteVersions, Undelete, Destroy, ReadMetadata,
// WriteMetadata, DeleteMetadata, CAS and versioned reads) return an
// UNSUPPORTED error on KV v1 without sending a request.
type KV interface {
	// Mount returns the mount path (without slashes).
	Mount() string
	// Version returns 1 or 2.
	Version() int
	// Read returns the secret at path (NOT_FOUND when missing or, on v2, when
	// the requested version is deleted or destroyed).
	Read(ctx context.Context, path string, opts *KVReadOptions) (*KVSecret, error)
	// Write replaces the data at path. On v2 it returns the new version's
	// metadata; on v1 the metadata is nil.
	Write(ctx context.Context, path string, data map[string]any, opts *KVWriteOptions) (*KVVersionMetadata, error)
	// Patch merges data into the latest version (RFC 7386: nil removes a key). v2 only.
	Patch(ctx context.Context, path string, data map[string]any, opts *KVWriteOptions) (*KVVersionMetadata, error)
	// Delete removes path (v2: soft-deletes the latest version). Missing paths are not an error.
	Delete(ctx context.Context, path string) error
	// DeleteVersions soft-deletes the given versions. v2 only.
	DeleteVersions(ctx context.Context, path string, versions []int) error
	// Undelete restores soft-deleted versions. v2 only.
	Undelete(ctx context.Context, path string, versions []int) error
	// Destroy permanently removes the data of the given versions. v2 only.
	Destroy(ctx context.Context, path string, versions []int) error
	// List returns the keys directly under path, sorted; folders end in "/".
	// A missing path gives an empty list.
	List(ctx context.Context, path string) ([]string, error)
	// ReadMetadata returns the metadata of every version. v2 only.
	ReadMetadata(ctx context.Context, path string) (*KVMetadata, error)
	// WriteMetadata changes max versions, CAS requirement, auto-delete and custom metadata. v2 only.
	WriteMetadata(ctx context.Context, path string, opts KVMetadataOptions) error
	// DeleteMetadata removes the key with all versions and metadata. v2 only.
	DeleteMetadata(ctx context.Context, path string) error
}

// KVReadOptions select a version (v2 only; 0 = latest).
type KVReadOptions struct {
	Version int
}

// KVWriteOptions control writes (v2 only).
type KVWriteOptions struct {
	// CAS is the expected current version (0 = create only); nil disables the check.
	// A mismatch is a CONFLICT error.
	CAS *int
}

// KVSecret is the result of KV.Read.
type KVSecret struct {
	Data map[string]any
	// Metadata is the version metadata (nil on KV v1).
	Metadata *KVVersionMetadata
}

// KVVersionMetadata describes one version of a KV v2 secret.
type KVVersionMetadata struct {
	Version        int
	CreatedTime    time.Time
	DeletionTime   time.Time
	Destroyed      bool
	CustomMetadata map[string]string
}

// Deleted reports whether the version is soft-deleted or destroyed.
func (m KVVersionMetadata) Deleted() bool { return m.Destroyed || !m.DeletionTime.IsZero() }

// KVMetadata is the metadata of a KV v2 key (ReadMetadata).
type KVMetadata struct {
	CASRequired        bool
	CreatedTime        time.Time
	UpdatedTime        time.Time
	CurrentVersion     int
	OldestVersion      int
	MaxVersions        int
	DeleteVersionAfter time.Duration
	CustomMetadata     map[string]string
	Versions           map[int]KVVersionMetadata
}

// KVMetadataOptions are the fields WriteMetadata changes; nil fields are left unchanged.
type KVMetadataOptions struct {
	MaxVersions        *int
	CASRequired        *bool
	DeleteVersionAfter *time.Duration
	CustomMetadata     map[string]string
}

// KV returns the KV engine at mount ("" = Config.KVMount), detecting its
// version (Config.KVVersion forces it). Detection uses
// sys/internal/ui/mounts/<mount> and is cached per mount.
func (c *Client) KV(ctx context.Context, mount string) (KV, error) {
	mount = mountOr(mount, c.cfg.kvMount())
	v, err := c.kvVersion(ctx, mount, c.cfg.KVVersion, "")
	if err != nil {
		return nil, err
	}
	if v == 1 {
		return c.KVv1(mount), nil
	}
	return c.KVv2(mount), nil
}

// KVv1 returns the KV version 1 engine at mount ("" = "secret").
func (c *Client) KVv1(mount string) *KVv1 { return &KVv1{c: c, mount: mountOr(mount, DefaultKVMount)} }

// KVv2 returns the KV version 2 engine at mount ("" = "secret").
func (c *Client) KVv2(mount string) *KVv2 { return &KVv2{c: c, mount: mountOr(mount, DefaultKVMount)} }

// DetectKVVersion returns the KV version (1 or 2) of mount without caching.
// A mount that is not a KV engine is a VALIDATION error. A token without
// capabilities on the mount root gets PERMISSION_DENIED; use KVv1/KVv2 or
// Config.KVVersion for such tokens.
func (c *Client) DetectKVVersion(ctx context.Context, mount string) (int, error) {
	return c.detectKVVersion(ctx, mountOr(mount, c.cfg.kvMount()), "")
}

// detectKVVersion asks sys/internal/ui/mounts/<mount>/<path>; a path inside the
// mount lets restricted tokens (capabilities only below the root) detect it.
func (c *Client) detectKVVersion(ctx context.Context, mount, path string) (int, error) {
	var d struct {
		Type    string            `json:"type"`
		Options map[string]string `json:"options"`
	}
	op := "kv.detect " + mount
	if err := c.callData(ctx, apiRequest{method: http.MethodGet, path: "sys/internal/ui/mounts/" + joinPath(mount, path), op: op}, &d); err != nil {
		return 0, err
	}
	if d.Type != "kv" && d.Type != "generic" {
		return 0, ValidationError(op, "mount is not a KV engine (type "+d.Type+")")
	}
	if d.Options["version"] == "2" {
		return 2, nil
	}
	return 1, nil
}

func (c *Client) kvVersion(ctx context.Context, mount string, forced int, path string) (int, error) {
	if forced == 1 || forced == 2 {
		return forced, nil
	}
	c.kvMu.Lock()
	v, ok := c.kvVersions[mount]
	c.kvMu.Unlock()
	if ok {
		return v, nil
	}
	v, err := c.detectKVVersion(ctx, mount, path)
	if err != nil {
		return 0, err
	}
	c.kvMu.Lock()
	c.kvVersions[mount] = v
	c.kvMu.Unlock()
	return v, nil
}

func kvOp(name, mount, path string) string { return "kv." + name + " " + joinPath(mount, path) }

func checkVersions(op string, versions []int) error {
	if len(versions) == 0 {
		return ValidationError(op, "at least one version is required")
	}
	return nil
}

// --- KV v1 ----------------------------------------------------------------

// KVv1 is a KV version 1 (unversioned) engine.
type KVv1 struct {
	c     *Client
	mount string
}

var _ KV = (*KVv1)(nil)

func v1Unsupported(name, mount, path string) error {
	return UnsupportedError(kvOp(name, mount, path), "not available on KV version 1")
}

// Mount implements KV.
func (k *KVv1) Mount() string { return k.mount }

// Version implements KV.
func (k *KVv1) Version() int { return 1 }

// Read implements KV (GET <mount>/<path>).
func (k *KVv1) Read(ctx context.Context, path string, opts *KVReadOptions) (*KVSecret, error) {
	if opts != nil && opts.Version != 0 {
		return nil, v1Unsupported("read", k.mount, path)
	}
	var data map[string]any
	err := k.c.callData(ctx, apiRequest{method: http.MethodGet, path: joinPath(k.mount, path), op: kvOp("read", k.mount, path)}, &data)
	if err != nil {
		return nil, err
	}
	if data == nil {
		data = map[string]any{}
	}
	return &KVSecret{Data: data}, nil
}

// Write implements KV (POST <mount>/<path>, full replace). CAS is UNSUPPORTED.
func (k *KVv1) Write(ctx context.Context, path string, data map[string]any, opts *KVWriteOptions) (*KVVersionMetadata, error) {
	if opts != nil && opts.CAS != nil {
		return nil, v1Unsupported("write", k.mount, path)
	}
	if data == nil {
		data = map[string]any{}
	}
	_, err := k.c.call(ctx, apiRequest{method: http.MethodPost, path: joinPath(k.mount, path), body: data, op: kvOp("write", k.mount, path)})
	return nil, err
}

// Patch implements KV (UNSUPPORTED on v1).
func (k *KVv1) Patch(_ context.Context, path string, _ map[string]any, _ *KVWriteOptions) (*KVVersionMetadata, error) {
	return nil, v1Unsupported("patch", k.mount, path)
}

// Delete implements KV (DELETE <mount>/<path>).
func (k *KVv1) Delete(ctx context.Context, path string) error {
	_, err := k.c.call(ctx, apiRequest{method: http.MethodDelete, path: joinPath(k.mount, path), op: kvOp("delete", k.mount, path)})
	return err
}

// DeleteVersions implements KV (UNSUPPORTED on v1).
func (k *KVv1) DeleteVersions(_ context.Context, path string, _ []int) error {
	return v1Unsupported("deleteVersions", k.mount, path)
}

// Undelete implements KV (UNSUPPORTED on v1).
func (k *KVv1) Undelete(_ context.Context, path string, _ []int) error {
	return v1Unsupported("undelete", k.mount, path)
}

// Destroy implements KV (UNSUPPORTED on v1).
func (k *KVv1) Destroy(_ context.Context, path string, _ []int) error {
	return v1Unsupported("destroy", k.mount, path)
}

// List implements KV (LIST <mount>/<path>).
func (k *KVv1) List(ctx context.Context, path string) ([]string, error) {
	return k.c.list(ctx, joinPath(k.mount, path), kvOp("list", k.mount, path))
}

// ReadMetadata implements KV (UNSUPPORTED on v1).
func (k *KVv1) ReadMetadata(_ context.Context, path string) (*KVMetadata, error) {
	return nil, v1Unsupported("readMetadata", k.mount, path)
}

// WriteMetadata implements KV (UNSUPPORTED on v1).
func (k *KVv1) WriteMetadata(_ context.Context, path string, _ KVMetadataOptions) error {
	return v1Unsupported("writeMetadata", k.mount, path)
}

// DeleteMetadata implements KV (UNSUPPORTED on v1).
func (k *KVv1) DeleteMetadata(_ context.Context, path string) error {
	return v1Unsupported("deleteMetadata", k.mount, path)
}

// --- KV v2 ----------------------------------------------------------------

// KVv2 is a KV version 2 (versioned) engine.
type KVv2 struct {
	c     *Client
	mount string
}

var _ KV = (*KVv2)(nil)

type kvVersionJSON struct {
	Version        int               `json:"version"`
	CreatedTime    flexTime          `json:"created_time"`
	DeletionTime   flexTime          `json:"deletion_time"`
	Destroyed      bool              `json:"destroyed"`
	CustomMetadata map[string]string `json:"custom_metadata"`
}

func (v kvVersionJSON) public() *KVVersionMetadata {
	return &KVVersionMetadata{
		Version: v.Version, CreatedTime: v.CreatedTime.Time, DeletionTime: v.DeletionTime.Time,
		Destroyed: v.Destroyed, CustomMetadata: v.CustomMetadata,
	}
}

// Mount implements KV.
func (k *KVv2) Mount() string { return k.mount }

// Version implements KV.
func (k *KVv2) Version() int { return 2 }

func (k *KVv2) path(kind, path string) string { return joinPath(k.mount, kind, path) }

// Read implements KV (GET <mount>/data/<path>[?version=n]).
func (k *KVv2) Read(ctx context.Context, path string, opts *KVReadOptions) (*KVSecret, error) {
	var q url.Values
	if opts != nil && opts.Version > 0 {
		q = url.Values{"version": {strconv.Itoa(opts.Version)}}
	}
	var d struct {
		Data     map[string]any `json:"data"`
		Metadata kvVersionJSON  `json:"metadata"`
	}
	op := kvOp("read", k.mount, path)
	if err := k.c.callData(ctx, apiRequest{method: http.MethodGet, path: k.path("data", path), query: q, op: op}, &d); err != nil {
		return nil, err
	}
	if d.Data == nil {
		return nil, NotFoundError(op, "version is deleted or destroyed")
	}
	return &KVSecret{Data: d.Data, Metadata: d.Metadata.public()}, nil
}

func casBody(data map[string]any, opts *KVWriteOptions) map[string]any {
	if data == nil {
		data = map[string]any{}
	}
	body := map[string]any{"data": data}
	if opts != nil && opts.CAS != nil {
		body["options"] = map[string]any{"cas": *opts.CAS}
	}
	return body
}

// Write implements KV (POST <mount>/data/<path>).
func (k *KVv2) Write(ctx context.Context, path string, data map[string]any, opts *KVWriteOptions) (*KVVersionMetadata, error) {
	var d kvVersionJSON
	err := k.c.callData(ctx, apiRequest{method: http.MethodPost, path: k.path("data", path), body: casBody(data, opts), op: kvOp("write", k.mount, path)}, &d)
	if err != nil {
		return nil, err
	}
	return d.public(), nil
}

// Patch implements KV (PATCH <mount>/data/<path>, application/merge-patch+json).
func (k *KVv2) Patch(ctx context.Context, path string, data map[string]any, opts *KVWriteOptions) (*KVVersionMetadata, error) {
	var d kvVersionJSON
	err := k.c.callData(ctx, apiRequest{
		method: http.MethodPatch, path: k.path("data", path), body: casBody(data, opts),
		contentType: "application/merge-patch+json", op: kvOp("patch", k.mount, path),
	}, &d)
	if err != nil {
		return nil, err
	}
	return d.public(), nil
}

// Delete implements KV (DELETE <mount>/data/<path>: soft-deletes the latest version).
func (k *KVv2) Delete(ctx context.Context, path string) error {
	_, err := k.c.call(ctx, apiRequest{method: http.MethodDelete, path: k.path("data", path), op: kvOp("delete", k.mount, path)})
	return err
}

func (k *KVv2) versionsCall(ctx context.Context, method, kind, name, path string, versions []int) error {
	op := kvOp(name, k.mount, path)
	if err := checkVersions(op, versions); err != nil {
		return err
	}
	_, err := k.c.call(ctx, apiRequest{method: method, path: k.path(kind, path), body: map[string]any{"versions": versions}, op: op})
	return err
}

// DeleteVersions implements KV (POST <mount>/delete/<path>).
func (k *KVv2) DeleteVersions(ctx context.Context, path string, versions []int) error {
	return k.versionsCall(ctx, http.MethodPost, "delete", "deleteVersions", path, versions)
}

// Undelete implements KV (POST <mount>/undelete/<path>).
func (k *KVv2) Undelete(ctx context.Context, path string, versions []int) error {
	return k.versionsCall(ctx, http.MethodPost, "undelete", "undelete", path, versions)
}

// Destroy implements KV (PUT <mount>/destroy/<path>).
func (k *KVv2) Destroy(ctx context.Context, path string, versions []int) error {
	return k.versionsCall(ctx, http.MethodPut, "destroy", "destroy", path, versions)
}

// List implements KV (LIST <mount>/metadata/<path>).
func (k *KVv2) List(ctx context.Context, path string) ([]string, error) {
	return k.c.list(ctx, k.path("metadata", path), kvOp("list", k.mount, path))
}

// ReadMetadata implements KV (GET <mount>/metadata/<path>).
func (k *KVv2) ReadMetadata(ctx context.Context, path string) (*KVMetadata, error) {
	var d struct {
		CASRequired        bool                     `json:"cas_required"`
		CreatedTime        flexTime                 `json:"created_time"`
		UpdatedTime        flexTime                 `json:"updated_time"`
		CurrentVersion     int                      `json:"current_version"`
		OldestVersion      int                      `json:"oldest_version"`
		MaxVersions        int                      `json:"max_versions"`
		DeleteVersionAfter flexDuration             `json:"delete_version_after"`
		CustomMetadata     map[string]string        `json:"custom_metadata"`
		Versions           map[string]kvVersionJSON `json:"versions"`
	}
	if err := k.c.callData(ctx, apiRequest{method: http.MethodGet, path: k.path("metadata", path), op: kvOp("readMetadata", k.mount, path)}, &d); err != nil {
		return nil, err
	}
	md := &KVMetadata{
		CASRequired: d.CASRequired, CreatedTime: d.CreatedTime.Time, UpdatedTime: d.UpdatedTime.Time,
		CurrentVersion: d.CurrentVersion, OldestVersion: d.OldestVersion, MaxVersions: d.MaxVersions,
		DeleteVersionAfter: d.DeleteVersionAfter.Duration, CustomMetadata: d.CustomMetadata,
		Versions: make(map[int]KVVersionMetadata, len(d.Versions)),
	}
	for key, v := range d.Versions {
		n, err := strconv.Atoi(key)
		if err != nil {
			continue
		}
		v.Version = n
		md.Versions[n] = *v.public()
	}
	return md, nil
}

// WriteMetadata implements KV (POST <mount>/metadata/<path>).
func (k *KVv2) WriteMetadata(ctx context.Context, path string, opts KVMetadataOptions) error {
	body := map[string]any{}
	if opts.MaxVersions != nil {
		body["max_versions"] = *opts.MaxVersions
	}
	if opts.CASRequired != nil {
		body["cas_required"] = *opts.CASRequired
	}
	if opts.DeleteVersionAfter != nil {
		body["delete_version_after"] = durationString(*opts.DeleteVersionAfter)
	}
	if opts.CustomMetadata != nil {
		body["custom_metadata"] = opts.CustomMetadata
	}
	_, err := k.c.call(ctx, apiRequest{method: http.MethodPost, path: k.path("metadata", path), body: body, op: kvOp("writeMetadata", k.mount, path)})
	return err
}

// DeleteMetadata implements KV (DELETE <mount>/metadata/<path>).
func (k *KVv2) DeleteMetadata(ctx context.Context, path string) error {
	_, err := k.c.call(ctx, apiRequest{method: http.MethodDelete, path: k.path("metadata", path), op: kvOp("deleteMetadata", k.mount, path)})
	return err
}

// isNotFound reports a NOT_FOUND error.
func isNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// trimSlashes is strings.Trim(s, "/").
func trimSlashes(s string) string { return strings.Trim(s, "/") }
