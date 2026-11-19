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

// This file holds the OpenBao server lifecycle helpers that only tests and
// fixtures need: InitStatus, Init, Unseal, Seal and WaitForActive (the same
// names and arguments as the testing module of the other four languages).
// They are deliberately not part of the openbao package API. Each takes the
// client whose URL, namespace and token (Seal) it uses.

// OperatorOptions configure the lifecycle helpers.
type OperatorOptions struct {
	// HTTPClient sends the requests (default: a client with a 30 s timeout).
	HTTPClient *http.Client
}

// target returns the base URL and namespace of client.
func target(op string, client *openbao.Client) (string, string, error) {
	if client == nil {
		return "", "", openbao.ConfigError(op + ": client is required")
	}
	cfg := client.Config()
	return cfg.URL, strings.Trim(cfg.Namespace, "/"), nil
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
func operatorCall(ctx context.Context, opts OperatorOptions, method, baseURL, namespace, path, token string, body, out any) error {
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
	if namespace != "" {
		req.Header.Set("X-Vault-Namespace", namespace)
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
func Init(ctx context.Context, client *openbao.Client, opts *InitOptions) (*InitResult, error) {
	baseURL, ns, err := target("testing.init", client)
	if err != nil {
		return nil, err
	}
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
	if err := operatorCall(ctx, o.OperatorOptions, http.MethodPut, baseURL, ns, "sys/init", "", body, &d); err != nil {
		return nil, err
	}
	return &InitResult{
		Keys: secrets(d.Keys), KeysBase64: secrets(d.KeysBase64), RecoveryKeys: secrets(d.RecoveryKeys),
		RootToken: openbao.NewSecret(d.RootToken),
	}, nil
}

// InitStatus reports whether the server is initialised (GET sys/init).
func InitStatus(ctx context.Context, client *openbao.Client, opts *OperatorOptions) (bool, error) {
	baseURL, ns, err := target("testing.initStatus", client)
	if err != nil {
		return false, err
	}
	var d struct {
		Initialized bool `json:"initialized"`
	}
	err = operatorCall(ctx, operatorOpts(opts), http.MethodGet, baseURL, ns, "sys/init", "", nil, &d)
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
func Unseal(ctx context.Context, client *openbao.Client, key string, opts *OperatorOptions) (*openbao.SealStatus, error) {
	baseURL, ns, err := target("testing.unseal", client)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(key) == "" {
		return nil, openbao.ValidationError("testing.unseal", "key is required")
	}
	var st openbao.SealStatus
	if err := operatorCall(ctx, operatorOpts(opts), http.MethodPut, baseURL, ns, "sys/unseal", "", map[string]any{"key": key}, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Seal seals the server (PUT sys/seal) with the client token (needs a
// root/sudo token).
func Seal(ctx context.Context, client *openbao.Client, opts *OperatorOptions) error {
	baseURL, ns, err := target("testing.seal", client)
	if err != nil {
		return err
	}
	return operatorCall(ctx, operatorOpts(opts), http.MethodPut, baseURL, ns, "sys/seal", client.Token().Reveal(), nil, nil)
}

// WaitForActive polls client.Sys().Health until the node is active
// (initialised, unsealed, leader) or timeout passes (TIMEOUT error). Use it
// after Unseal: leader election takes a moment.
func WaitForActive(ctx context.Context, client *openbao.Client, timeout time.Duration) (*openbao.HealthResponse, error) {
	if client == nil {
		return nil, openbao.ConfigError("testing.waitForActive: client is required")
	}
	return openbao.PollUntil(ctx, "testing.waitForActive", timeout, 200*time.Millisecond,
		func(ctx context.Context) (*openbao.HealthResponse, bool, error) {
			h, err := client.Sys().Health(ctx) // retryable errors keep polling
			if err != nil {
				return nil, false, err
			}
			return h, h.State == "active", nil
		})
}
