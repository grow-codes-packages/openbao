package openbao

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultKubernetesJWTPath is the service account token path read by KubernetesAuth.
const DefaultKubernetesJWTPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// AuthInfo is the token returned by a login, a renewal or a token creation.
type AuthInfo struct {
	// ClientToken is the issued token (redacted when printed).
	ClientToken   Secret
	Accessor      string
	Policies      []string
	TokenPolicies []string
	Metadata      map[string]string
	// LeaseDuration is the token TTL (0 = never expires).
	LeaseDuration time.Duration
	Renewable     bool
	EntityID      string
	TokenType     string
	Orphan        bool
	NumUses       int
}

// TokenInfo is the result of LookupSelf (the token id itself is not included).
type TokenInfo struct {
	Accessor       string
	Policies       []string
	TTL            time.Duration
	CreationTTL    time.Duration
	CreationTime   time.Time
	ExpireTime     time.Time
	IssueTime      time.Time
	ExplicitMaxTTL time.Duration
	Renewable      bool
	DisplayName    string
	Meta           map[string]string
	NumUses        int
	Orphan         bool
	Path           string
	Type           string
	EntityID       string
}

// AuthMethod logs in to OpenBao. The built-in methods are TokenAuth,
// AppRoleAuth, KubernetesAuth, JWTAuth and UserpassAuth; custom methods can
// call Auth.LoginWith.
type AuthMethod interface {
	// Login authenticates and returns the issued token; it does not change the
	// client token (Auth.Login does).
	Login(ctx context.Context, a *Auth) (*AuthInfo, error)
}

// Auth is the auth module: logins, token self-operations, token creation and
// the TokenRenewer.
type Auth struct {
	c *Client

	mu     sync.Mutex
	method AuthMethod
	last   *AuthInfo
}

// Login authenticates with method, sets the resulting token on the client and
// returns it. The method is remembered for TokenRenewer re-logins.
func (a *Auth) Login(ctx context.Context, method AuthMethod) (*AuthInfo, error) {
	if method == nil {
		return nil, ValidationError("auth.login", "auth method is required")
	}
	info, err := method.Login(ctx, a)
	if err != nil {
		return nil, err
	}
	a.c.SetToken(info.ClientToken.Reveal())
	a.mu.Lock()
	a.method, a.last = method, info
	a.mu.Unlock()
	return info, nil
}

// LoginWith posts body to auth/<path> without a token and returns the issued
// token (building block for AuthMethod implementations). path is relative to
// auth/, for example "approle/login".
func (a *Auth) LoginWith(ctx context.Context, path string, body map[string]any) (*AuthInfo, error) {
	op := "auth.login " + strings.Trim(path, "/")
	for _, v := range body {
		if s, ok := v.(string); ok {
			a.c.rememberSecret(s)
		}
	}
	env, err := a.c.call(ctx, apiRequest{method: http.MethodPost, path: "auth/" + strings.Trim(path, "/"), body: body, op: op, noAuth: true})
	if err != nil {
		return nil, loginError(err)
	}
	if env.Auth == nil || env.Auth.ClientToken == "" {
		return nil, &Error{Code: ErrorCodeAuthentication, Message: op + ": the response carried no token"}
	}
	a.c.rememberSecret(env.Auth.ClientToken, env.Auth.Accessor)
	return env.Auth.info(), nil
}

// loginError maps 400/401/403 from a login endpoint to AUTHENTICATION: the
// credentials were rejected (DECISIONS §7, the same in every language).
func loginError(err error) error {
	var e *Error
	if errors.As(err, &e) {
		switch e.HTTPStatus {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
			e.Code, e.Retryable = ErrorCodeAuthentication, false
		}
	}
	return err
}

// LookupSelf returns the current token's properties (GET auth/token/lookup-self).
func (a *Auth) LookupSelf(ctx context.Context) (*TokenInfo, error) { return a.lookupSelf(ctx, "") }

// lookupSelf looks up token ("" = the client token).
func (a *Auth) lookupSelf(ctx context.Context, token string) (*TokenInfo, error) {
	var d struct {
		Accessor       string            `json:"accessor"`
		Policies       []string          `json:"policies"`
		TTL            int64             `json:"ttl"`
		CreationTTL    int64             `json:"creation_ttl"`
		CreationTime   flexTime          `json:"creation_time"`
		ExpireTime     flexTime          `json:"expire_time"`
		IssueTime      flexTime          `json:"issue_time"`
		ExplicitMaxTTL int64             `json:"explicit_max_ttl"`
		Renewable      bool              `json:"renewable"`
		DisplayName    string            `json:"display_name"`
		Meta           map[string]string `json:"meta"`
		NumUses        int               `json:"num_uses"`
		Orphan         bool              `json:"orphan"`
		Path           string            `json:"path"`
		Type           string            `json:"type"`
		EntityID       string            `json:"entity_id"`
	}
	if err := a.c.callData(ctx, apiRequest{method: http.MethodGet, path: "auth/token/lookup-self", op: "auth.lookupSelf", token: token}, &d); err != nil {
		return nil, err
	}
	return &TokenInfo{
		Accessor: d.Accessor, Policies: d.Policies, TTL: seconds(d.TTL), CreationTTL: seconds(d.CreationTTL),
		CreationTime: d.CreationTime.Time, ExpireTime: d.ExpireTime.Time, IssueTime: d.IssueTime.Time,
		ExplicitMaxTTL: seconds(d.ExplicitMaxTTL), Renewable: d.Renewable, DisplayName: d.DisplayName,
		Meta: d.Meta, NumUses: d.NumUses, Orphan: d.Orphan, Path: d.Path, Type: d.Type, EntityID: d.EntityID,
	}, nil
}

// RenewSelf renews the current token (POST auth/token/renew-self). increment
// is the requested TTL (0 = the token's default). A non-renewable token is a
// VALIDATION error.
func (a *Auth) RenewSelf(ctx context.Context, increment time.Duration) (*AuthInfo, error) {
	body := map[string]any{}
	if increment > 0 {
		body["increment"] = durationString(increment)
	}
	env, err := a.c.call(ctx, apiRequest{method: http.MethodPost, path: "auth/token/renew-self", body: body, op: "auth.renewSelf"})
	if err != nil {
		return nil, err
	}
	if env.Auth == nil {
		return nil, &Error{Code: ErrorCodeUnavailable, Message: "auth.renewSelf: the response carried no auth data"}
	}
	return env.Auth.info(), nil
}

// RevokeSelf revokes the current token (POST auth/token/revoke-self) and
// clears it from the client.
func (a *Auth) RevokeSelf(ctx context.Context) error {
	if _, err := a.c.call(ctx, apiRequest{method: http.MethodPost, path: "auth/token/revoke-self", op: "auth.revokeSelf"}); err != nil {
		return err
	}
	a.c.SetToken("")
	return nil
}

// TokenCreateOptions configure CreateToken. Zero values use the server defaults.
type TokenCreateOptions struct {
	// Role creates the token against auth/token/create/<role>.
	Role            string
	Policies        []string
	TTL             time.Duration
	ExplicitMaxTTL  time.Duration
	Period          time.Duration
	Renewable       *bool
	DisplayName     string
	Meta            map[string]string
	NumUses         int
	NoParent        bool
	NoDefaultPolicy bool
	// Type is "service" or "batch" ("" = server default).
	Type string
	// EntityAlias is the entity alias to associate with the token (role tokens only).
	EntityAlias string
}

// CreateToken creates a child token (POST auth/token/create). The new token is
// returned, not set on the client.
func (a *Auth) CreateToken(ctx context.Context, opts *TokenCreateOptions) (*AuthInfo, error) {
	o := TokenCreateOptions{}
	if opts != nil {
		o = *opts
	}
	body := map[string]any{}
	if len(o.Policies) > 0 {
		body["policies"] = o.Policies
	}
	setDur := func(k string, d time.Duration) {
		if d > 0 {
			body[k] = durationString(d)
		}
	}
	setDur("ttl", o.TTL)
	setDur("explicit_max_ttl", o.ExplicitMaxTTL)
	setDur("period", o.Period)
	if o.Renewable != nil {
		body["renewable"] = *o.Renewable
	}
	if o.DisplayName != "" {
		body["display_name"] = o.DisplayName
	}
	if len(o.Meta) > 0 {
		body["meta"] = o.Meta
	}
	if o.NumUses > 0 {
		body["num_uses"] = o.NumUses
	}
	if o.NoParent {
		body["no_parent"] = true
	}
	if o.NoDefaultPolicy {
		body["no_default_policy"] = true
	}
	if o.Type != "" {
		body["type"] = o.Type
	}
	if o.EntityAlias != "" {
		body["entity_alias"] = o.EntityAlias
	}
	path := "auth/token/create"
	if o.Role != "" {
		path += "/" + strings.Trim(o.Role, "/")
	}
	env, err := a.c.call(ctx, apiRequest{method: http.MethodPost, path: path, body: body, op: "auth.createToken"})
	if err != nil {
		return nil, err
	}
	if env.Auth == nil {
		return nil, &Error{Code: ErrorCodeUnavailable, Message: "auth.createToken: the response carried no token"}
	}
	a.c.rememberSecret(env.Auth.ClientToken, env.Auth.Accessor)
	return env.Auth.info(), nil
}

func (a *Auth) lastLogin() (AuthMethod, *AuthInfo) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.method, a.last
}

// --- auth methods ---------------------------------------------------------

// TokenAuth uses an existing token. Login sets it on the client and verifies it
// with lookup-self.
type TokenAuth struct {
	Token Secret
}

// NewTokenAuth returns a TokenAuth for token.
func NewTokenAuth(token string) *TokenAuth { return &TokenAuth{Token: NewSecret(token)} }

// Login implements AuthMethod.
func (t *TokenAuth) Login(ctx context.Context, a *Auth) (*AuthInfo, error) {
	if t.Token.IsZero() {
		return nil, ValidationError("auth.token", "token is required")
	}
	a.c.rememberSecret(t.Token.Reveal())
	ti, err := a.lookupSelf(ctx, t.Token.Reveal())
	if err != nil {
		return nil, err
	}
	return &AuthInfo{
		ClientToken: t.Token, Accessor: ti.Accessor, Policies: ti.Policies, TokenPolicies: ti.Policies,
		Metadata: ti.Meta, LeaseDuration: ti.TTL, Renewable: ti.Renewable, EntityID: ti.EntityID,
		TokenType: ti.Type, Orphan: ti.Orphan, NumUses: ti.NumUses,
	}, nil
}

// AppRoleAuth logs in with a role id and secret id (POST auth/<mount>/login).
type AppRoleAuth struct {
	RoleID   string
	SecretID Secret
	// Mount is the auth mount path (default "approle").
	Mount string
}

// NewAppRoleAuth returns an AppRoleAuth on the default "approle" mount.
func NewAppRoleAuth(roleID, secretID string) *AppRoleAuth {
	return &AppRoleAuth{RoleID: roleID, SecretID: NewSecret(secretID)}
}

// Login implements AuthMethod.
func (m *AppRoleAuth) Login(ctx context.Context, a *Auth) (*AuthInfo, error) {
	if err := requireArg("auth.approle", "roleId", m.RoleID); err != nil {
		return nil, err
	}
	body := map[string]any{"role_id": m.RoleID}
	if !m.SecretID.IsZero() {
		body["secret_id"] = m.SecretID.Reveal()
	}
	return a.LoginWith(ctx, mountOr(m.Mount, "approle")+"/login", body)
}

// UserpassAuth logs in with a username and password (POST auth/<mount>/login/<username>).
type UserpassAuth struct {
	Username string
	Password Secret
	// Mount is the auth mount path (default "userpass").
	Mount string
}

// NewUserpassAuth returns a UserpassAuth on the default "userpass" mount.
func NewUserpassAuth(username, password string) *UserpassAuth {
	return &UserpassAuth{Username: username, Password: NewSecret(password)}
}

// Login implements AuthMethod.
func (m *UserpassAuth) Login(ctx context.Context, a *Auth) (*AuthInfo, error) {
	if err := requireArg("auth.userpass", "username", m.Username); err != nil {
		return nil, err
	}
	return a.LoginWith(ctx, mountOr(m.Mount, "userpass")+"/login/"+m.Username, map[string]any{"password": m.Password.Reveal()})
}

// JWTAuth logs in with a signed JWT for a role (POST auth/<mount>/login).
type JWTAuth struct {
	Role string
	JWT  Secret
	// Mount is the auth mount path (default "jwt").
	Mount string
}

// NewJWTAuth returns a JWTAuth on the default "jwt" mount.
func NewJWTAuth(role, jwt string) *JWTAuth { return &JWTAuth{Role: role, JWT: NewSecret(jwt)} }

// Login implements AuthMethod.
func (m *JWTAuth) Login(ctx context.Context, a *Auth) (*AuthInfo, error) {
	if m.JWT.IsZero() {
		return nil, ValidationError("auth.jwt", "jwt is required")
	}
	body := map[string]any{"jwt": m.JWT.Reveal()}
	if m.Role != "" {
		body["role"] = m.Role
	}
	return a.LoginWith(ctx, mountOr(m.Mount, "jwt")+"/login", body)
}

// KubernetesAuth logs in with the pod's service account token (POST
// auth/<mount>/login). The token file is read on every login, so rotated
// tokens are picked up.
type KubernetesAuth struct {
	Role string
	// JWTPath is the service account token file (default DefaultKubernetesJWTPath).
	JWTPath string
	// Mount is the auth mount path (default "kubernetes").
	Mount string
}

// NewKubernetesAuth returns a KubernetesAuth; jwtPath "" uses DefaultKubernetesJWTPath.
func NewKubernetesAuth(role, jwtPath string) *KubernetesAuth {
	return &KubernetesAuth{Role: role, JWTPath: jwtPath}
}

// Login implements AuthMethod.
func (m *KubernetesAuth) Login(ctx context.Context, a *Auth) (*AuthInfo, error) {
	if err := requireArg("auth.kubernetes", "role", m.Role); err != nil {
		return nil, err
	}
	path := m.JWTPath
	if path == "" {
		path = DefaultKubernetesJWTPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ConfigError("kubernetes auth: the service account token file cannot be read")
	}
	jwt := strings.TrimSpace(string(data))
	if jwt == "" {
		return nil, ConfigError("kubernetes auth: the service account token file is empty")
	}
	return a.LoginWith(ctx, mountOr(m.Mount, "kubernetes")+"/login", map[string]any{"role": m.Role, "jwt": jwt})
}
