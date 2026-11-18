package openbao

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client is the OpenBao client. It is safe for concurrent use.
//
// Service modules hang off the client: Auth, KV / KVv1 / KVv2, Secrets
// (SecretsProvider over KV), Transit, Database, LeaseManager, PKI, Sys and
// Wrapping. Close stops every background renewer and watcher.
type Client struct {
	cfg       Config
	transport *httpTransport
	closeOnce sync.Once

	tokenMu sync.RWMutex
	token   string

	kvMu       sync.Mutex
	kvVersions map[string]int

	bgMu    sync.Mutex
	closers []func()
	closed  bool

	modOnce  sync.Once
	auth     *Auth
	sys      *Sys
	wrapping *Wrapping
	leases   *LeaseManager
	secrets  *KVSecretsProvider
}

// NewClient validates cfg and returns a client.
func NewClient(cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.CommonConfig = cfg.withDefaults(DefaultURL)
	t, err := newHTTPTransport(cfg.CommonConfig)
	if err != nil {
		return nil, err
	}
	c := &Client{cfg: cfg, transport: t, kvVersions: map[string]int{}}
	c.SetToken(cfg.Token.Reveal())
	return c, nil
}

// NewClientFromEnv builds a client from the environment (see ConfigFromEnv).
func NewClientFromEnv() (*Client, error) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return NewClient(cfg)
}

// Config returns the effective configuration (the token is the configured
// one, not a token obtained later by a login).
func (c *Client) Config() Config { return c.cfg }

// SetToken replaces the token sent as X-Vault-Token ("" sends none). Logins
// through Auth().Login call it automatically.
func (c *Client) SetToken(token string) {
	c.rememberSecret(token)
	c.tokenMu.Lock()
	c.token = token
	c.tokenMu.Unlock()
}

// Token returns the current token, wrapped so it never prints.
func (c *Client) Token() Secret {
	c.tokenMu.RLock()
	defer c.tokenMu.RUnlock()
	return NewSecret(c.token)
}

func (c *Client) currentToken() string {
	c.tokenMu.RLock()
	defer c.tokenMu.RUnlock()
	return c.token
}

// rememberSecret registers values that must never appear in errors or logs.
func (c *Client) rememberSecret(values ...string) {
	for _, v := range values {
		if len(v) >= 4 {
			c.transport.addSecret(v)
		}
	}
}

func (c *Client) modules() {
	c.modOnce.Do(func() {
		c.auth = &Auth{c: c}
		c.sys = &Sys{c: c}
		c.wrapping = &Wrapping{c: c}
		c.leases = newLeaseManager(c)
		c.secrets = newKVSecretsProvider(c, SecretsProviderOptions{})
		c.onClose(func() { c.leases.Close() })
		c.onClose(func() { _ = c.secrets.Close() })
	})
}

// Auth returns the auth module (logins, token operations, TokenRenewer).
func (c *Client) Auth() *Auth { c.modules(); return c.auth }

// Sys returns the system and admin module (seal status, leader, policies,
// mounts, auth methods, AppRole admin).
func (c *Client) Sys() *Sys { c.modules(); return c.sys }

// Wrapping returns the response-wrapping module.
func (c *Client) Wrapping() *Wrapping { c.modules(); return c.wrapping }

// LeaseManager returns the client's lease manager (renew, revoke, auto-renew).
func (c *Client) LeaseManager() *LeaseManager { c.modules(); return c.leases }

// Secrets returns the SecretsProvider over Config.KVMount / Config.SecretsPath.
// Close of the client stops its watchers.
func (c *Client) Secrets() *KVSecretsProvider { c.modules(); return c.secrets }

// SecretsWith returns a new SecretsProvider with its own mount, base path,
// value field or KV version. Close of the client stops its watchers.
func (c *Client) SecretsWith(opts SecretsProviderOptions) *KVSecretsProvider {
	p := newKVSecretsProvider(c, opts)
	c.onClose(func() { _ = p.Close() })
	return p
}

// onClose registers fn to run on Close (immediately when already closed).
func (c *Client) onClose(fn func()) {
	c.bgMu.Lock()
	if c.closed {
		c.bgMu.Unlock()
		fn()
		return
	}
	c.closers = append(c.closers, fn)
	c.bgMu.Unlock()
}

// Health checks the server without credentials (GET sys/health). It never
// fails for a sealed, standby, uninitialised or unreachable server: Status is
// "active", "standby", "perfstandby", "sealed", "uninitialized", "unhealthy"
// or "unreachable", and Healthy is true only for an active node (HTTP 200).
// It fails only for CANCELLED and CONFIG.
func (c *Client) Health(ctx context.Context) (HealthStatus, error) {
	hs, err := c.transport.checkHealth(ctx, "health", &request{
		Method: http.MethodGet, Path: "/v1/sys/health", Header: c.headers(""), Operation: "health",
	})
	if err != nil || hs.Status == "unreachable" {
		return hs, err
	}
	d := hs.Details
	switch {
	case d["initialized"] == "false":
		hs.Status = "uninitialized"
	case d["sealed"] == "true":
		hs.Status = "sealed"
	case d["performance_standby"] == "true":
		hs.Status = "perfstandby"
	case d["standby"] == "true":
		hs.Status = "standby"
	case d["httpStatus"] == "200":
		hs.Status = "active"
	default:
		hs.Status = "unhealthy"
	}
	hs.Healthy = d["httpStatus"] == "200"
	return hs, nil
}

// Ping makes an authenticated round trip (GET auth/token/lookup-self) and
// returns its latency (AUTHENTICATION error on a missing or invalid token).
func (c *Client) Ping(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	if _, err := c.send(ctx, apiRequest{method: http.MethodGet, path: "auth/token/lookup-self", op: "ping"}); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// ServerVersion returns the server version from sys/health (no token needed;
// it also answers while sealed or uninitialised).
func (c *Client) ServerVersion(ctx context.Context) (string, error) {
	res, err := c.send(ctx, apiRequest{method: http.MethodGet, path: "sys/health", op: "serverVersion", noAuth: true, rawStatus: true})
	if err != nil {
		return "", err
	}
	var body struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(res.Body, &body) == nil && body.Version != "" {
		return body.Version, nil
	}
	if res.Status >= 300 {
		return "", c.statusError("serverVersion", res)
	}
	return "", UnsupportedError("serverVersion", "the server exposes no version")
}

// Close stops every TokenRenewer, managed lease and secrets watcher and
// releases connections. It is idempotent.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.bgMu.Lock()
		c.closed = true
		fns := c.closers
		c.closers = nil
		c.bgMu.Unlock()
		for i := len(fns) - 1; i >= 0; i-- {
			fns[i]()
		}
		c.transport.close()
	})
	return nil
}

// --- request plumbing -----------------------------------------------------

// apiRequest is one OpenBao API call; path is relative to /v1/.
type apiRequest struct {
	method string
	path   string
	query  url.Values
	body   any
	op     string
	// noAuth sends no X-Vault-Token (login endpoints).
	noAuth bool
	// token overrides the client token for this call (unwrap).
	token string
	// wrapTTL asks the server to wrap the response.
	wrapTTL time.Duration
	// contentType sends body JSON-encoded with this content type (merge-patch).
	contentType string
	noRetry     bool
	rawStatus   bool
}

func (c *Client) headers(token string) http.Header {
	h := http.Header{}
	if token != "" {
		h.Set("X-Vault-Token", token)
	}
	if c.cfg.Namespace != "" {
		h.Set("X-Vault-Namespace", strings.Trim(c.cfg.Namespace, "/"))
	}
	return h
}

// send executes r and maps OpenBao-specific error bodies.
func (c *Client) send(ctx context.Context, r apiRequest) (*response, error) {
	token := r.token
	if token == "" && !r.noAuth {
		token = c.currentToken()
	}
	h := c.headers(token)
	if r.wrapTTL > 0 {
		h.Set("X-Vault-Wrap-TTL", durationString(r.wrapTTL))
	}
	req := &request{
		Method: r.method, Path: "/v1/" + strings.TrimPrefix(r.path, "/"), Query: r.query, Header: h,
		Operation: r.op, NoRetry: r.noRetry, RawStatus: r.rawStatus,
	}
	if r.body != nil {
		if r.contentType != "" {
			b, err := jsonMarshal(r.body)
			if err != nil {
				return nil, ValidationError(r.op, "request body cannot be encoded")
			}
			req.Body, req.ContentType = b, r.contentType
		} else {
			req.JSON = r.body
		}
	}
	res, err := c.transport.do(ctx, req)
	if err != nil {
		return nil, mapError(err)
	}
	return res, nil
}

// call executes r and decodes the response envelope (an empty body gives an
// empty envelope).
func (c *Client) call(ctx context.Context, r apiRequest) (*envelope, error) {
	res, err := c.send(ctx, r)
	if err != nil {
		return nil, err
	}
	env := &envelope{status: res.Status}
	if len(strings.TrimSpace(string(res.Body))) == 0 {
		return env, nil
	}
	if err := res.decodeJSON(r.op, env); err != nil {
		return nil, err
	}
	env.op = r.op
	return env, nil
}

// callData executes r and decodes the envelope's data into out.
func (c *Client) callData(ctx context.Context, r apiRequest, out any) error {
	env, err := c.call(ctx, r)
	if err != nil {
		return err
	}
	return env.decodeData(out)
}

// list runs a LIST (GET ?list=true) and returns data.keys; 404 is an empty list.
func (c *Client) list(ctx context.Context, path, op string) ([]string, error) {
	var data struct {
		Keys []string `json:"keys"`
	}
	err := c.callData(ctx, apiRequest{method: http.MethodGet, path: path, query: url.Values{"list": {"true"}}, op: op}, &data)
	if errors.Is(err, ErrNotFound) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	if data.Keys == nil {
		data.Keys = []string{}
	}
	return data.Keys, nil
}

// statusError builds the mapped error for a raw response.
func (c *Client) statusError(op string, res *response) error {
	return mapError(StatusError(op, res.Status, res.RequestID, vendorErrorText(res), c.transport.knownSecrets()))
}

// mapError applies the OpenBao-specific status refinements on top of SPEC §2.1:
//
//   - 403 with the plain "permission denied" body (missing, invalid, expired or
//     revoked token) or a message naming an invalid/missing token is
//     AUTHENTICATION; a policy denial ("1 error occurred: * permission denied")
//     stays PERMISSION_DENIED.
//   - 400 "check-and-set parameter did not match" is CONFLICT.
//   - 405 (operation not supported on this path, e.g. PATCH on KV v1) is UNSUPPORTED.
//   - 501 (server not initialised) is UNAVAILABLE.
func mapError(err error) error {
	var e *Error
	if !errors.As(err, &e) || e.HTTPStatus == 0 {
		return err
	}
	msg := strings.ToLower(e.Message)
	switch e.HTTPStatus {
	case http.StatusForbidden:
		if isAuthFailure(msg) {
			e.Code = ErrorCodeAuthentication
		}
	case http.StatusBadRequest:
		if strings.Contains(msg, "check-and-set parameter did not match") {
			e.Code = ErrorCodeConflict
		}
	case http.StatusMethodNotAllowed:
		e.Code = ErrorCodeUnsupported
	case http.StatusNotImplemented:
		e.Code = ErrorCodeUnavailable
		e.Retryable = true
	}
	return e
}

func isAuthFailure(msg string) bool {
	for _, s := range []string{"invalid token", "token not found", "missing client token", "bad token"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return strings.HasSuffix(msg, "forbidden: permission denied (http 403)") && !strings.Contains(msg, "error occurred")
}
