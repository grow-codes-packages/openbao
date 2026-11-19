package openbao

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// listConcurrency bounds the per-key metadata reads of List on KV v2.
const listConcurrency = 8

// SecretsProviderOptions configure a KV-backed SecretsProvider. Zero values
// fall back to the client Config (KVMount, SecretsPath, ValueField, KVVersion).
type SecretsProviderOptions struct {
	// Mount is the KV mount (default Config.KVMount, then "secret").
	Mount string
	// Path is the base path inside the mount under which names live.
	Path string
	// ValueField is the data field holding the value (default "value").
	ValueField string
	// KVVersion forces 1 or 2; 0 auto-detects.
	KVVersion int
}

// KVSecretsProvider is the SecretsProvider (SPEC §3) over an OpenBao KV mount.
//
// Model: a secret is one KV path <Path>/<name> (GetOptions.Path or
// SetOptions.Path replace the base path). The value is stored as
// {"value": "<text>"}; bytes that are not valid UTF-8 are stored as
// {"value": "<base64>", "encoding": "base64"}; objects passed to Set are
// JSON-encoded into "value". Reading a path without a "value" field returns
// the whole data map JSON-encoded. Versions are the KV v2 version numbers as
// strings ("" on KV v1). A KV v2 key whose current version is deleted or
// destroyed counts as missing (Get, Metadata, Exists, List).
type KVSecretsProvider struct {
	*BaseSecretsProvider
	prims *kvPrimitives
}

// KV returns the KV engine the provider uses (detecting its version).
func (p *KVSecretsProvider) KV(ctx context.Context) (KV, error) { return p.prims.kv(ctx) }

func newKVSecretsProvider(c *Client, o SecretsProviderOptions) *KVSecretsProvider {
	if o.Mount == "" {
		o.Mount = c.cfg.kvMount()
	}
	if o.Path == "" {
		o.Path = c.cfg.SecretsPath
	}
	if o.ValueField == "" {
		o.ValueField = c.cfg.valueField()
	}
	if o.KVVersion == 0 {
		o.KVVersion = c.cfg.KVVersion
	}
	o.Mount, o.Path = trimSlashes(o.Mount), trimSlashes(o.Path)
	prims := &kvPrimitives{c: c, opts: o}
	return &KVSecretsProvider{BaseSecretsProvider: NewSecretsProvider(prims), prims: prims}
}

type kvPrimitives struct {
	c    *Client
	opts SecretsProviderOptions
}

var _ SecretPrimitives = (*kvPrimitives)(nil)

func (p *kvPrimitives) kv(ctx context.Context) (KV, error) { return p.kvFor(ctx, "") }

// kvFor resolves the engine; path (a key inside the mount) helps restricted
// tokens pass the detection preflight.
func (p *kvPrimitives) kvFor(ctx context.Context, path string) (KV, error) {
	v, err := p.c.kvVersion(ctx, p.opts.Mount, p.opts.KVVersion, path)
	if err != nil {
		return nil, err
	}
	if v == 1 {
		return p.c.KVv1(p.opts.Mount), nil
	}
	return p.c.KVv2(p.opts.Mount), nil
}

// key returns the KV path of name.
func (p *kvPrimitives) key(name, path string) string {
	if path == "" {
		path = p.opts.Path
	}
	return joinPath(path, name)
}

// decode turns KV data into the secret bytes.
func (p *kvPrimitives) decode(op string, data map[string]any) ([]byte, error) {
	raw, ok := data[p.opts.ValueField]
	if !ok {
		b, err := json.Marshal(data)
		if err != nil {
			return nil, ValidationError(op, "data cannot be encoded")
		}
		return b, nil
	}
	s, isString := raw.(string)
	if !isString {
		b, err := json.Marshal(raw)
		if err != nil {
			return nil, ValidationError(op, "value cannot be encoded")
		}
		return b, nil
	}
	if enc, _ := data["encoding"].(string); enc == "base64" {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, ValidationError(op, "value is not valid base64")
		}
		return b, nil
	}
	return []byte(s), nil
}

// FetchSecret implements SecretPrimitives.
func (p *kvPrimitives) FetchSecret(ctx context.Context, name string, opts GetOptions) (*SecretValue, error) {
	key := p.key(name, opts.Path)
	kv, err := p.kvFor(ctx, key)
	if err != nil {
		return nil, err
	}
	op := "secrets.get " + key
	var ro *KVReadOptions
	if opts.Version != "" {
		if kv.Version() == 1 {
			return nil, ValidationError(op, "versions are not available on KV version 1")
		}
		n, err := strconv.Atoi(opts.Version)
		if err != nil || n <= 0 {
			return nil, ValidationError(op, "version must be a positive integer")
		}
		ro = &KVReadOptions{Version: n}
	}
	sec, err := kv.Read(ctx, key, ro)
	if isNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	b, err := p.decode(op, sec.Data)
	if err != nil {
		return nil, err
	}
	version := ""
	if sec.Metadata != nil {
		version = strconv.Itoa(sec.Metadata.Version)
	}
	return NewSecretValue(b, version), nil
}

// ListSecrets implements SecretPrimitives: the secrets directly under path
// (folders skipped), with metadata per key on KV v2 (bounded concurrency).
func (p *kvPrimitives) ListSecrets(ctx context.Context, path string) ([]SecretMetadata, error) {
	kv, err := p.kvFor(ctx, joinPath(p.opts.Path, path))
	if err != nil {
		return nil, err
	}
	keys, err := kv.List(ctx, joinPath(p.opts.Path, path))
	if err != nil {
		return nil, err
	}
	prefix := trimSlashes(path)
	names := make([]string, 0, len(keys))
	for _, k := range keys {
		if !strings.HasSuffix(k, "/") {
			names = append(names, joinPath(prefix, k))
		}
	}
	if kv.Version() == 1 {
		out := make([]SecretMetadata, len(names))
		for i, n := range names {
			out[i] = SecretMetadata{Name: n, Path: prefix, Tags: map[string]string{}, Extra: map[string]string{}}
		}
		return out, nil
	}
	results := make([]*SecretMetadata, len(names))
	errs := make([]error, len(names))
	sem := make(chan struct{}, listConcurrency)
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i], errs[i] = p.FetchMetadata(ctx, n, GetOptions{})
		}()
	}
	wg.Wait()
	out := make([]SecretMetadata, 0, len(names))
	for i := range names {
		if errs[i] != nil {
			return nil, errs[i]
		}
		if results[i] != nil {
			out = append(out, *results[i])
		}
	}
	return out, nil
}

// encode builds the KV data for value bytes.
func (p *kvPrimitives) encode(value []byte) map[string]any {
	if utf8.Valid(value) {
		return map[string]any{p.opts.ValueField: string(value)}
	}
	return map[string]any{p.opts.ValueField: base64.StdEncoding.EncodeToString(value), "encoding": "base64"}
}

// PutSecret implements SecretPrimitives. On KV v2, Tags and Description are
// written to the key's custom metadata ("description" key) after the write.
func (p *kvPrimitives) PutSecret(ctx context.Context, name string, value []byte, opts SetOptions) (string, error) {
	key := p.key(name, opts.Path)
	kv, err := p.kvFor(ctx, key)
	if err != nil {
		return "", err
	}
	op := "secrets.set " + key
	if kv.Version() == 1 {
		if opts.CAS != nil || len(opts.Tags) > 0 || opts.Description != "" {
			return "", UnsupportedError(op, "cas, tags and description need KV version 2")
		}
		_, err := kv.Write(ctx, key, p.encode(value), nil)
		return "", err
	}
	var wo *KVWriteOptions
	if opts.CAS != nil {
		wo = &KVWriteOptions{CAS: opts.CAS}
	}
	md, err := kv.Write(ctx, key, p.encode(value), wo)
	if err != nil {
		return "", err
	}
	if len(opts.Tags) > 0 || opts.Description != "" {
		custom := make(map[string]string, len(opts.Tags)+1)
		for k, v := range opts.Tags {
			custom[k] = v
		}
		if opts.Description != "" {
			custom["description"] = opts.Description
		}
		if err := kv.WriteMetadata(ctx, key, KVMetadataOptions{CustomMetadata: custom}); err != nil {
			return "", err
		}
	}
	return strconv.Itoa(md.Version), nil
}

// RemoveSecret implements SecretPrimitives. KV answers 204 for missing paths,
// so the key is read first to report NOT_FOUND. KV v2: soft-deletes the
// latest version; Versions soft-deletes those versions; Permanent removes the
// key with all versions and metadata.
func (p *kvPrimitives) RemoveSecret(ctx context.Context, name string, opts DeleteOptions) error {
	key := p.key(name, opts.Path)
	kv, err := p.kvFor(ctx, key)
	if err != nil {
		return err
	}
	op := "secrets.delete " + key
	if kv.Version() == 1 {
		if len(opts.Versions) > 0 {
			return UnsupportedError(op, "versions need KV version 2")
		}
		if _, err := kv.Read(ctx, key, nil); err != nil {
			if isNotFound(err) {
				return NotFoundError(op, "not found")
			}
			return err
		}
		return kv.Delete(ctx, key)
	}
	md, err := kv.ReadMetadata(ctx, key)
	if isNotFound(err) {
		return NotFoundError(op, "not found")
	}
	if err != nil {
		return err
	}
	switch {
	case opts.Permanent:
		return kv.DeleteMetadata(ctx, key)
	case len(opts.Versions) > 0:
		versions := make([]int, len(opts.Versions))
		for i, v := range opts.Versions {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return ValidationError(op, "versions must be positive integers")
			}
			versions[i] = n
		}
		return kv.DeleteVersions(ctx, key, versions)
	}
	if currentDeleted(md) {
		return NotFoundError(op, "not found")
	}
	return kv.Delete(ctx, key)
}

func currentDeleted(md *KVMetadata) bool {
	v, ok := md.Versions[md.CurrentVersion]
	return !ok || v.Deleted()
}

// FetchMetadata implements SecretPrimitives.
func (p *kvPrimitives) FetchMetadata(ctx context.Context, name string, opts GetOptions) (*SecretMetadata, error) {
	key := p.key(name, opts.Path)
	kv, err := p.kvFor(ctx, key)
	if err != nil {
		return nil, err
	}
	parent := ""
	if i := strings.LastIndex(trimSlashes(name), "/"); i >= 0 {
		parent = trimSlashes(name)[:i]
	}
	if kv.Version() == 1 {
		if _, err := kv.Read(ctx, key, nil); err != nil {
			if isNotFound(err) {
				return nil, nil
			}
			return nil, err
		}
		return &SecretMetadata{Name: trimSlashes(name), Path: parent, Tags: map[string]string{}, Extra: map[string]string{}}, nil
	}
	md, err := kv.ReadMetadata(ctx, key)
	if isNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if currentDeleted(md) {
		return nil, nil
	}
	tags := map[string]string{}
	for k, v := range md.CustomMetadata {
		tags[k] = v
	}
	return &SecretMetadata{
		Name:      trimSlashes(name),
		Path:      parent,
		Version:   strconv.Itoa(md.CurrentVersion),
		CreatedAt: md.CreatedTime,
		UpdatedAt: md.UpdatedTime,
		Tags:      tags,
		Versions:  len(md.Versions),
		Extra: map[string]string{
			"maxVersions":        strconv.Itoa(md.MaxVersions),
			"casRequired":        strconv.FormatBool(md.CASRequired),
			"deleteVersionAfter": strconv.FormatInt(int64(md.DeleteVersionAfter/time.Second), 10) + "s",
			"oldestVersion":      strconv.Itoa(md.OldestVersion),
		},
	}, nil
}
