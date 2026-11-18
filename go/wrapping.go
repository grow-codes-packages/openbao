package openbao

import (
	"context"
	"net/http"
	"time"
)

// Wrapping is the response-wrapping module (single-use wrapping tokens).
type Wrapping struct{ c *Client }

// WrapInfo describes a wrapping token.
type WrapInfo struct {
	// Token is the single-use wrapping token (redacted when printed).
	Token        Secret
	Accessor     string
	TTL          time.Duration
	CreationTime time.Time
	CreationPath string
}

// WrapLookup is the result of LookupWrapping.
type WrapLookup struct {
	CreationPath string
	CreationTime time.Time
	CreationTTL  time.Duration
}

// Wrap stores data in the cubbyhole of a new wrapping token valid for ttl
// (POST sys/wrapping/wrap with X-Vault-Wrap-TTL).
func (w *Wrapping) Wrap(ctx context.Context, data map[string]any, ttl time.Duration) (*WrapInfo, error) {
	op := "wrapping.wrap"
	if ttl <= 0 {
		return nil, ValidationError(op, "ttl must be positive")
	}
	if data == nil {
		data = map[string]any{}
	}
	env, err := w.c.call(ctx, apiRequest{method: http.MethodPost, path: "sys/wrapping/wrap", body: data, wrapTTL: ttl, op: op})
	if err != nil {
		return nil, err
	}
	if env.WrapInfo == nil {
		return nil, &Error{Code: ErrorCodeUnavailable, Message: op + ": the response carried no wrapping token"}
	}
	w.c.rememberSecret(env.WrapInfo.Token, env.WrapInfo.Accessor)
	return env.WrapInfo.info(), nil
}

// Unwrap returns the wrapped response and consumes the token (POST
// sys/wrapping/unwrap authenticated with the wrapping token). It is never
// retried after the request was sent; a used or invalid token is a VALIDATION error.
func (w *Wrapping) Unwrap(ctx context.Context, token string) (*SecretResponse, error) {
	op := "wrapping.unwrap"
	if err := requireArg(op, "token", token); err != nil {
		return nil, err
	}
	w.c.rememberSecret(token)
	env, err := w.c.call(ctx, apiRequest{method: http.MethodPost, path: "sys/wrapping/unwrap", token: token, noRetry: true, op: op})
	if err != nil {
		return nil, err
	}
	if env.Auth != nil {
		w.c.rememberSecret(env.Auth.ClientToken, env.Auth.Accessor)
	}
	return env.secretResponse()
}

// LookupWrapping returns a wrapping token's properties without consuming it
// (POST sys/wrapping/lookup).
func (w *Wrapping) LookupWrapping(ctx context.Context, token string) (*WrapLookup, error) {
	op := "wrapping.lookup"
	if err := requireArg(op, "token", token); err != nil {
		return nil, err
	}
	w.c.rememberSecret(token)
	var d struct {
		CreationPath string   `json:"creation_path"`
		CreationTime flexTime `json:"creation_time"`
		CreationTTL  int64    `json:"creation_ttl"`
	}
	if err := w.c.callData(ctx, apiRequest{method: http.MethodPost, path: "sys/wrapping/lookup", body: map[string]any{"token": token}, op: op}, &d); err != nil {
		return nil, err
	}
	return &WrapLookup{CreationPath: d.CreationPath, CreationTime: d.CreationTime.Time, CreationTTL: seconds(d.CreationTTL)}, nil
}
