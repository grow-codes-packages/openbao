package testkit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	openbao "github.com/grow-codes-packages/openbao/go"
)

// This file holds the OpenBao operator helpers that only tests and fixtures
// need: Init, Unseal, Seal and WaitForActive. They are deliberately not part
// of the openbao package API.

// OperatorOptions configure the operator helpers.
type OperatorOptions struct {
	// HTTPClient sends the requests (default: a client with a 30 s timeout).
	HTTPClient *http.Client
	// Namespace is sent as X-Vault-Namespace when set.
	Namespace string
}

// InitOptions configure Init. With a Shamir seal set SecretShares and
// SecretThreshold; with an auto/static seal set RecoveryShares and
// RecoveryThreshold. All zero means one Shamir share with threshold one.
type InitOptions struct {
	OperatorOptions
	SecretShares      int
	SecretThreshold   int
	RecoveryShares    int
	RecoveryThreshold int
}

// InitResult is the result of Init. Every key and the root token are redacted
// when printed.
type InitResult struct {
	// Keys are the unseal key shares (hex).
	Keys []openbao.Secret
	// KeysBase64 are the same shares in base64.
	KeysBase64 []openbao.Secret
	// RecoveryKeys are the recovery shares (auto/static seal).
	RecoveryKeys []openbao.Secret
	// RootToken is the initial root token.
	RootToken openbao.Secret
}

func secrets(values []string) []openbao.Secret {
	out := make([]openbao.Secret, len(values))
	for i, v := range values {
		out[i] = openbao.NewSecret(v)
	}
	return out
}

// operatorCall sends one request to url+"/v1/"+path and decodes the JSON body into out.
func operatorCall(ctx context.Context, opts OperatorOptions, method, baseURL, path, token string, body, out any) error {
	op := "testing." + path
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return openbao.ValidationError(op, "request body cannot be encoded")
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(baseURL, "/")+"/v1/"+path, reader)
	if err != nil {
		return openbao.ConfigError("url must be an absolute http or https URL")
	}
	req.Header.Set("User-Agent", openbao.UserAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if opts.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", opts.Namespace)
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return openbao.ContextError(op, ctx.Err())
		}
		return openbao.NewError(openbao.ErrorCodeUnavailable, op+": network error", nil)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(data, &e)
		return openbao.StatusError(op, resp.StatusCode, "", strings.Join(e.Errors, "; "), []string{token})
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return openbao.NewError(openbao.ErrorCodeUnavailable, op+": invalid JSON response", nil)
		}
	}
	return nil
}

// Init initialises a fresh server (PUT sys/init). A second call is a
// VALIDATION error ("already initialized").
func Init(ctx context.Context, baseURL string, opts *InitOptions) (*InitResult, error) {
	o := InitOptions{}
	if opts != nil {
		o = *opts
	}
	body := map[string]any{}
	switch {
	case o.RecoveryShares > 0:
		body["recovery_shares"] = o.RecoveryShares
		body["recovery_threshold"] = max(o.RecoveryThreshold, 1)
	default:
		body["secret_shares"] = max(o.SecretShares, 1)
		body["secret_threshold"] = max(o.SecretThreshold, 1)
	}
	var d struct {
		Keys         []string `json:"keys"`
		KeysBase64   []string `json:"keys_base64"`
		RecoveryKeys []string `json:"recovery_keys"`
		RootToken    string   `json:"root_token"`
	}
	if err := operatorCall(ctx, o.OperatorOptions, http.MethodPut, baseURL, "sys/init", "", body, &d); err != nil {
		return nil, err
	}
	return &InitResult{
		Keys: secrets(d.Keys), KeysBase64: secrets(d.KeysBase64), RecoveryKeys: secrets(d.RecoveryKeys),
		RootToken: openbao.NewSecret(d.RootToken),
	}, nil
}

// InitStatus reports whether the server is initialised (GET sys/init).
func InitStatus(ctx context.Context, baseURL string, opts *OperatorOptions) (bool, error) {
	var d struct {
		Initialized bool `json:"initialized"`
	}
	err := operatorCall(ctx, operatorOpts(opts), http.MethodGet, baseURL, "sys/init", "", nil, &d)
	return d.Initialized, err
}

func operatorOpts(opts *OperatorOptions) OperatorOptions {
	if opts == nil {
		return OperatorOptions{}
	}
	return *opts
}

// Unseal submits one unseal key share (hex or base64; PUT sys/unseal) and
// returns the seal status; Sealed is false once the threshold is reached.
// An invalid key is a VALIDATION error.
func Unseal(ctx context.Context, baseURL, key string, opts *OperatorOptions) (*openbao.SealStatus, error) {
	if strings.TrimSpace(key) == "" {
		return nil, openbao.ValidationError("testing.unseal", "key is required")
	}
	var st openbao.SealStatus
	if err := operatorCall(ctx, operatorOpts(opts), http.MethodPut, baseURL, "sys/unseal", "", map[string]any{"key": key}, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Seal seals the server (PUT sys/seal; needs a root/sudo token).
func Seal(ctx context.Context, baseURL, token string, opts *OperatorOptions) error {
	return operatorCall(ctx, operatorOpts(opts), http.MethodPut, baseURL, "sys/seal", token, nil, nil)
}

// WaitForActive polls client.Health until the node is active (HTTP 200) or
// timeout passes (TIMEOUT error). Use it after Unseal: leader election takes
// a moment.
func WaitForActive(ctx context.Context, client *openbao.Client, timeout time.Duration) (openbao.HealthStatus, error) {
	return openbao.PollUntil(ctx, "testing.waitForActive", timeout, 200*time.Millisecond,
		func(ctx context.Context) (openbao.HealthStatus, bool, error) {
			hs, err := client.Health(ctx)
			return hs, err == nil && hs.Healthy, err
		})
}
