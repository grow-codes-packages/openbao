package testkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	openbao "github.com/grow-codes-packages/openbao/go"
)

// shamirServer mimics a fresh Shamir-sealed OpenBao (init -> unseal -> active).
func shamirServer(t *testing.T) *httptest.Server {
	t.Helper()
	initialized, sealed := false, true
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		w.Header().Set("Content-Type", "application/json")
		write := func(status int, v any) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(v)
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/sys/init":
			write(200, map[string]any{"initialized": initialized})
		case "PUT /v1/sys/init":
			if initialized {
				write(400, map[string]any{"errors": []string{"Vault is already initialized"}})
				return
			}
			initialized = true
			if body["recovery_shares"] != nil {
				write(200, map[string]any{"recovery_keys": []string{"rk1"}, "root_token": "root-tok-1"})
				return
			}
			write(200, map[string]any{"keys": []string{"aa11"}, "keys_base64": []string{"qhE="}, "root_token": "root-tok-1"})
		case "PUT /v1/sys/unseal":
			if body["key"] != "aa11" {
				write(400, map[string]any{"errors": []string{"'key' must be a valid hex or base64 string"}})
				return
			}
			sealed = false
			write(200, map[string]any{"type": "shamir", "initialized": true, "sealed": false, "t": 1, "n": 1})
		case "PUT /v1/sys/seal":
			if r.Header.Get("X-Vault-Token") != "root-tok-1" {
				write(403, map[string]any{"errors": []string{"permission denied"}})
				return
			}
			sealed = true
			w.WriteHeader(http.StatusNoContent)
		case "GET /v1/sys/health":
			status := 200
			switch {
			case !initialized:
				status = 501
			case sealed:
				status = 503
			}
			write(status, map[string]any{"initialized": initialized, "sealed": sealed, "standby": sealed, "version": "2.7.2"})
		case "GET /v1/sys/bad-json":
			_, _ = w.Write([]byte("{"))
		default:
			write(404, map[string]any{"errors": []string{}})
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestOperator(t *testing.T) {
	ts := shamirServer(t)
	ctx := t.Context()
	if ok, err := InitStatus(ctx, ts.URL, nil); err != nil || ok {
		t.Fatalf("init status %v %v", ok, err)
	}
	c, err := openbao.NewClient(openbao.Config{CommonConfig: openbao.CommonConfig{URL: ts.URL, Retry: &openbao.RetryPolicy{}}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if hs, _ := c.Health(ctx); hs.Status != "uninitialized" {
		t.Fatalf("health before init %+v", hs)
	}
	res, err := Init(ctx, ts.URL, &InitOptions{SecretShares: 1, SecretThreshold: 1, OperatorOptions: OperatorOptions{Namespace: "ns"}})
	if err != nil || len(res.Keys) != 1 || res.Keys[0].Reveal() != "aa11" || res.RootToken.Reveal() != "root-tok-1" || len(res.KeysBase64) != 1 {
		t.Fatalf("init %+v %v", res, err)
	}
	if strings.Contains(fmt.Sprintf("%+v", res), "root-tok-1") || strings.Contains(fmt.Sprintf("%v", res), "aa11") {
		t.Fatal("init result must print redacted")
	}
	if _, err := Init(ctx, ts.URL, nil); !errors.Is(err, openbao.ErrValidation) {
		t.Fatalf("second init: %v", err)
	}
	if hs, _ := c.Health(ctx); hs.Status != "sealed" {
		t.Fatalf("health sealed %+v", hs)
	}
	if _, err := Unseal(ctx, ts.URL, "zz", nil); !errors.Is(err, openbao.ErrValidation) {
		t.Fatalf("bad key: %v", err)
	}
	if _, err := Unseal(ctx, ts.URL, " ", nil); !errors.Is(err, openbao.ErrValidation) {
		t.Fatalf("empty key: %v", err)
	}
	st, err := Unseal(ctx, ts.URL, res.Keys[0].Reveal(), &OperatorOptions{HTTPClient: http.DefaultClient})
	if err != nil || st.Sealed || st.T != 1 {
		t.Fatalf("unseal %+v %v", st, err)
	}
	if hs, err := WaitForActive(ctx, c, 5*time.Second); err != nil || !hs.Healthy || hs.Status != "active" {
		t.Fatalf("active %+v %v", hs, err)
	}
	if err := Seal(ctx, ts.URL, "wrong", nil); !errors.Is(err, openbao.ErrAuthentication) && !errors.Is(err, openbao.ErrPermissionDenied) {
		t.Fatalf("seal wrong token: %v", err)
	}
	if err := Seal(ctx, ts.URL, res.RootToken.Reveal(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := WaitForActive(ctx, c, 300*time.Millisecond); !errors.Is(err, openbao.ErrTimeout) {
		t.Fatalf("sealed never active: %v", err)
	}
	if ok, err := InitStatus(ctx, ts.URL, nil); err != nil || !ok {
		t.Fatal("initialized")
	}

	t.Run("recovery shares and transport errors", func(t *testing.T) {
		ts := shamirServer(t)
		res, err := Init(ctx, ts.URL, &InitOptions{RecoveryShares: 1})
		if err != nil || len(res.RecoveryKeys) != 1 || len(res.Keys) != 0 {
			t.Fatalf("recovery %+v %v", res, err)
		}
		if err := operatorCall(ctx, OperatorOptions{}, "GET", ts.URL, "sys/bad-json", "", nil, &map[string]any{}); !errors.Is(err, openbao.ErrUnavailable) {
			t.Fatalf("bad json: %v", err)
		}
		if err := operatorCall(ctx, OperatorOptions{}, "GET", ts.URL, "sys/x", "", func() {}, nil); !errors.Is(err, openbao.ErrValidation) {
			t.Fatalf("bad body: %v", err)
		}
		if _, err := InitStatus(ctx, "http://bad host", nil); !errors.Is(err, openbao.ErrConfig) {
			t.Fatalf("bad url: %v", err)
		}
		closed := httptest.NewServer(http.NotFoundHandler())
		closed.Close()
		if _, err := InitStatus(ctx, closed.URL, nil); !errors.Is(err, openbao.ErrUnavailable) {
			t.Fatalf("closed: %v", err)
		}
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := InitStatus(cctx, ts.URL, nil); !errors.Is(err, openbao.ErrCancelled) {
			t.Fatalf("cancelled: %v", err)
		}
	})
}
