package openbao

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"time"
)

// Sys is the system and admin module: health, seal status, leader, version,
// ACL policies, secrets engines, auth methods and AppRole administration.
type Sys struct{ c *Client }

// Health is Client.Health.
func (s *Sys) Health(ctx context.Context) (HealthStatus, error) { return s.c.Health(ctx) }

// Version is Client.ServerVersion.
func (s *Sys) Version(ctx context.Context) (string, error) { return s.c.ServerVersion(ctx) }

// SealStatus is the result of Sys.SealStatus (and of testkit Unseal).
type SealStatus struct {
	// Type is the seal type ("shamir", "static", ...).
	Type        string `json:"type"`
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	// T is the unseal threshold, N the number of shares.
	T        int    `json:"t"`
	N        int    `json:"n"`
	Progress int    `json:"progress"`
	Nonce    string `json:"nonce"`
	Version  string `json:"version"`
	// CommitDate is the build commit date (RFC 3339 text).
	CommitDate       string `json:"commit_date"`
	RecoverySeal     bool   `json:"recovery_seal"`
	RecoverySealType string `json:"recovery_seal_type"`
	StorageType      string `json:"storage_type"`
	ClusterName      string `json:"cluster_name"`
	ClusterID        string `json:"cluster_id"`
}

// SealStatus returns the seal state (GET sys/seal-status, no token needed).
func (s *Sys) SealStatus(ctx context.Context) (*SealStatus, error) {
	res, err := s.c.send(ctx, apiRequest{method: http.MethodGet, path: "sys/seal-status", op: "sys.sealStatus", noAuth: true})
	if err != nil {
		return nil, err
	}
	var st SealStatus
	if err := res.decodeJSON("sys.sealStatus", &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// LeaderStatus is the result of Sys.Leader.
type LeaderStatus struct {
	HAEnabled            bool
	IsSelf               bool
	ActiveTime           time.Time
	LeaderAddress        string
	LeaderClusterAddress string
	RaftCommittedIndex   uint64
	RaftAppliedIndex     uint64
}

// Leader returns the HA leader (GET sys/leader, no token needed).
func (s *Sys) Leader(ctx context.Context) (*LeaderStatus, error) {
	res, err := s.c.send(ctx, apiRequest{method: http.MethodGet, path: "sys/leader", op: "sys.leader", noAuth: true})
	if err != nil {
		return nil, err
	}
	var d struct {
		HAEnabled            bool     `json:"ha_enabled"`
		IsSelf               bool     `json:"is_self"`
		ActiveTime           flexTime `json:"active_time"`
		LeaderAddress        string   `json:"leader_address"`
		LeaderClusterAddress string   `json:"leader_cluster_address"`
		RaftCommittedIndex   uint64   `json:"raft_committed_index"`
		RaftAppliedIndex     uint64   `json:"raft_applied_index"`
	}
	if err := res.decodeJSON("sys.leader", &d); err != nil {
		return nil, err
	}
	return &LeaderStatus{
		HAEnabled: d.HAEnabled, IsSelf: d.IsSelf, ActiveTime: d.ActiveTime.Time, LeaderAddress: d.LeaderAddress,
		LeaderClusterAddress: d.LeaderClusterAddress, RaftCommittedIndex: d.RaftCommittedIndex, RaftAppliedIndex: d.RaftAppliedIndex,
	}, nil
}

// --- policies -------------------------------------------------------------

// Policy is an ACL policy.
type Policy struct {
	Name string
	// Policy is the HCL document.
	Policy string
}

// WritePolicy creates or replaces an ACL policy (invalid HCL is a VALIDATION error).
func (s *Sys) WritePolicy(ctx context.Context, name, policy string) error {
	op := "sys.writePolicy " + name
	if err := requireArg(op, "name", name); err != nil {
		return err
	}
	_, err := s.c.call(ctx, apiRequest{method: http.MethodPut, path: "sys/policies/acl/" + name, body: map[string]any{"policy": policy}, op: op})
	return err
}

// ReadPolicy returns an ACL policy (NOT_FOUND when missing).
func (s *Sys) ReadPolicy(ctx context.Context, name string) (*Policy, error) {
	var d struct {
		Name   string `json:"name"`
		Policy string `json:"policy"`
	}
	if err := s.c.callData(ctx, apiRequest{method: http.MethodGet, path: "sys/policies/acl/" + name, op: "sys.readPolicy " + name}, &d); err != nil {
		return nil, err
	}
	return &Policy{Name: d.Name, Policy: d.Policy}, nil
}

// ListPolicies returns the ACL policy names (including "default" and "root").
func (s *Sys) ListPolicies(ctx context.Context) ([]string, error) {
	return s.c.list(ctx, "sys/policies/acl", "sys.listPolicies")
}

// DeletePolicy removes an ACL policy (missing policies are not an error).
func (s *Sys) DeletePolicy(ctx context.Context, name string) error {
	_, err := s.c.call(ctx, apiRequest{method: http.MethodDelete, path: "sys/policies/acl/" + name, op: "sys.deletePolicy " + name})
	return err
}

// --- mounts and auth methods ---------------------------------------------

// MountInfo describes a secrets engine or auth method mount.
type MountInfo struct {
	Type                 string
	Description          string
	Accessor             string
	Options              map[string]string
	DefaultLeaseTTL      time.Duration
	MaxLeaseTTL          time.Duration
	Local                bool
	SealWrap             bool
	UUID                 string
	RunningPluginVersion string
}

type mountJSON struct {
	Type        string            `json:"type"`
	Description string            `json:"description"`
	Accessor    string            `json:"accessor"`
	Options     map[string]string `json:"options"`
	Config      struct {
		DefaultLeaseTTL flexDuration `json:"default_lease_ttl"`
		MaxLeaseTTL     flexDuration `json:"max_lease_ttl"`
	} `json:"config"`
	Local                bool   `json:"local"`
	SealWrap             bool   `json:"seal_wrap"`
	UUID                 string `json:"uuid"`
	RunningPluginVersion string `json:"running_plugin_version"`
}

func (s *Sys) mounts(ctx context.Context, path, op string) (map[string]MountInfo, error) {
	var raw map[string]json.RawMessage
	if err := s.c.callData(ctx, apiRequest{method: http.MethodGet, path: path, op: op}, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]MountInfo, len(raw))
	for k, v := range raw {
		var m mountJSON
		if json.Unmarshal(v, &m) != nil || m.Type == "" {
			continue
		}
		out[k] = MountInfo{
			Type: m.Type, Description: m.Description, Accessor: m.Accessor, Options: m.Options,
			DefaultLeaseTTL: m.Config.DefaultLeaseTTL.Duration, MaxLeaseTTL: m.Config.MaxLeaseTTL.Duration,
			Local: m.Local, SealWrap: m.SealWrap, UUID: m.UUID, RunningPluginVersion: m.RunningPluginVersion,
		}
	}
	return out, nil
}

// MountOptions configure EnableSecretsEngine and EnableAuthMethod.
type MountOptions struct {
	Description string
	// Options are engine options, e.g. {"version": "2"} for KV v2.
	Options         map[string]string
	DefaultLeaseTTL time.Duration
	MaxLeaseTTL     time.Duration
	Local           bool
	SealWrap        bool
}

func (o *MountOptions) body(kind string) map[string]any {
	body := map[string]any{"type": kind}
	if o == nil {
		return body
	}
	if o.Description != "" {
		body["description"] = o.Description
	}
	if len(o.Options) > 0 {
		body["options"] = o.Options
	}
	cfg := map[string]any{}
	if o.DefaultLeaseTTL > 0 {
		cfg["default_lease_ttl"] = durationString(o.DefaultLeaseTTL)
	}
	if o.MaxLeaseTTL > 0 {
		cfg["max_lease_ttl"] = durationString(o.MaxLeaseTTL)
	}
	if len(cfg) > 0 {
		body["config"] = cfg
	}
	if o.Local {
		body["local"] = true
	}
	if o.SealWrap {
		body["seal_wrap"] = true
	}
	return body
}

// ListMounts returns the secrets engines keyed by path ("secret/").
func (s *Sys) ListMounts(ctx context.Context) (map[string]MountInfo, error) {
	return s.mounts(ctx, "sys/mounts", "sys.listMounts")
}

// EnableSecretsEngine mounts an engine of engineType at path (a used path is a
// VALIDATION error). A new KV v2 mount may answer 400 "Upgrading from
// non-versioned to versioned data" for a moment; retry writes briefly.
func (s *Sys) EnableSecretsEngine(ctx context.Context, path, engineType string, opts *MountOptions) error {
	op := "sys.enableSecretsEngine " + trimSlashes(path)
	if err := requireArg(op, "type", engineType); err != nil {
		return err
	}
	s.c.kvMu.Lock()
	delete(s.c.kvVersions, trimSlashes(path))
	s.c.kvMu.Unlock()
	_, err := s.c.call(ctx, apiRequest{method: http.MethodPost, path: "sys/mounts/" + trimSlashes(path), body: opts.body(engineType), op: op})
	return err
}

// DisableSecretsEngine unmounts the engine at path (all its data is deleted).
func (s *Sys) DisableSecretsEngine(ctx context.Context, path string) error {
	s.c.kvMu.Lock()
	delete(s.c.kvVersions, trimSlashes(path))
	s.c.kvMu.Unlock()
	_, err := s.c.call(ctx, apiRequest{method: http.MethodDelete, path: "sys/mounts/" + trimSlashes(path), op: "sys.disableSecretsEngine " + trimSlashes(path)})
	return err
}

// ListAuthMethods returns the auth methods keyed by path ("approle/").
func (s *Sys) ListAuthMethods(ctx context.Context) (map[string]MountInfo, error) {
	return s.mounts(ctx, "sys/auth", "sys.listAuthMethods")
}

// EnableAuthMethod enables an auth method of methodType at path.
func (s *Sys) EnableAuthMethod(ctx context.Context, path, methodType string, opts *MountOptions) error {
	op := "sys.enableAuthMethod " + trimSlashes(path)
	if err := requireArg(op, "type", methodType); err != nil {
		return err
	}
	_, err := s.c.call(ctx, apiRequest{method: http.MethodPost, path: "sys/auth/" + trimSlashes(path), body: opts.body(methodType), op: op})
	return err
}

// DisableAuthMethod disables the auth method at path.
func (s *Sys) DisableAuthMethod(ctx context.Context, path string) error {
	_, err := s.c.call(ctx, apiRequest{method: http.MethodDelete, path: "sys/auth/" + trimSlashes(path), op: "sys.disableAuthMethod " + trimSlashes(path)})
	return err
}

// --- AppRole admin ----------------------------------------------------------

// AppRoleOptions configure CreateAppRole. Zero values use the server defaults.
type AppRoleOptions struct {
	// Mount is the AppRole auth mount (default "approle").
	Mount           string
	TokenPolicies   []string
	TokenTTL        time.Duration
	TokenMaxTTL     time.Duration
	TokenNumUses    int
	TokenType       string
	SecretIDTTL     time.Duration
	SecretIDNumUses int
	// BindSecretID requires a secret id at login (server default true).
	BindSecretID *bool
}

// CreateAppRole creates or updates an AppRole role (POST auth/<mount>/role/<name>).
func (s *Sys) CreateAppRole(ctx context.Context, name string, opts *AppRoleOptions) error {
	o := AppRoleOptions{}
	if opts != nil {
		o = *opts
	}
	op := "sys.createAppRole " + name
	if err := requireArg(op, "name", name); err != nil {
		return err
	}
	body := map[string]any{}
	if len(o.TokenPolicies) > 0 {
		body["token_policies"] = o.TokenPolicies
	}
	for k, d := range map[string]time.Duration{"token_ttl": o.TokenTTL, "token_max_ttl": o.TokenMaxTTL, "secret_id_ttl": o.SecretIDTTL} {
		if d > 0 {
			body[k] = durationString(d)
		}
	}
	if o.TokenNumUses > 0 {
		body["token_num_uses"] = o.TokenNumUses
	}
	if o.TokenType != "" {
		body["token_type"] = o.TokenType
	}
	if o.SecretIDNumUses > 0 {
		body["secret_id_num_uses"] = o.SecretIDNumUses
	}
	if o.BindSecretID != nil {
		body["bind_secret_id"] = *o.BindSecretID
	}
	_, err := s.c.call(ctx, apiRequest{method: http.MethodPost, path: joinPath("auth", mountOr(o.Mount, "approle"), "role", name), body: body, op: op})
	return err
}

// ListAppRoles returns the AppRole role names on mount ("" = "approle"), sorted.
func (s *Sys) ListAppRoles(ctx context.Context, mount string) ([]string, error) {
	keys, err := s.c.list(ctx, joinPath("auth", mountOr(mount, "approle"), "role"), "sys.listAppRoles")
	sort.Strings(keys)
	return keys, err
}

// DeleteAppRole removes an AppRole role on mount ("" = "approle").
func (s *Sys) DeleteAppRole(ctx context.Context, name, mount string) error {
	_, err := s.c.call(ctx, apiRequest{method: http.MethodDelete, path: joinPath("auth", mountOr(mount, "approle"), "role", name), op: "sys.deleteAppRole " + name})
	return err
}

// ReadRoleID returns the role id of an AppRole role on mount ("" = "approle");
// NOT_FOUND for an unknown role.
func (s *Sys) ReadRoleID(ctx context.Context, name, mount string) (string, error) {
	var d struct {
		RoleID string `json:"role_id"`
	}
	if err := s.c.callData(ctx, apiRequest{method: http.MethodGet, path: joinPath("auth", mountOr(mount, "approle"), "role", name, "role-id"), op: "sys.readRoleId " + name}, &d); err != nil {
		return "", err
	}
	return d.RoleID, nil
}

// SecretIDOptions configure GenerateSecretID.
type SecretIDOptions struct {
	// Mount is the AppRole auth mount (default "approle").
	Mount    string
	Metadata map[string]string
	TTL      time.Duration
	NumUses  int
	CIDRList []string
}

// SecretID is a generated AppRole secret id.
type SecretID struct {
	// SecretID is redacted when printed.
	SecretID Secret
	Accessor string
	TTL      time.Duration
	NumUses  int
}

// GenerateSecretID creates a secret id for an AppRole role (POST auth/<mount>/role/<name>/secret-id).
func (s *Sys) GenerateSecretID(ctx context.Context, name string, opts *SecretIDOptions) (*SecretID, error) {
	o := SecretIDOptions{}
	if opts != nil {
		o = *opts
	}
	op := "sys.generateSecretId " + name
	body := map[string]any{}
	if len(o.Metadata) > 0 {
		b, err := json.Marshal(o.Metadata)
		if err != nil {
			return nil, ValidationError(op, "metadata cannot be encoded")
		}
		body["metadata"] = string(b)
	}
	if o.TTL > 0 {
		body["ttl"] = durationString(o.TTL)
	}
	if o.NumUses > 0 {
		body["num_uses"] = o.NumUses
	}
	if len(o.CIDRList) > 0 {
		body["cidr_list"] = o.CIDRList
	}
	var d struct {
		SecretID string `json:"secret_id"`
		Accessor string `json:"secret_id_accessor"`
		TTL      int64  `json:"secret_id_ttl"`
		NumUses  int    `json:"secret_id_num_uses"`
	}
	if err := s.c.callData(ctx, apiRequest{method: http.MethodPost, path: joinPath("auth", mountOr(o.Mount, "approle"), "role", name, "secret-id"), body: body, op: op}, &d); err != nil {
		return nil, err
	}
	s.c.rememberSecret(d.SecretID, d.Accessor)
	return &SecretID{SecretID: NewSecret(d.SecretID), Accessor: d.Accessor, TTL: seconds(d.TTL), NumUses: d.NumUses}, nil
}
