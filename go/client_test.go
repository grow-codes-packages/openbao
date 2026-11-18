package openbao

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// newTestClient builds a client for url with fast retries; mutate adjusts the config.
func newTestClient(t *testing.T, url string, mutate func(*Config)) *Client {
	t.Helper()
	cfg := Config{CommonConfig: CommonConfig{URL: url, Retry: fastRetry(3)}, Token: NewSecret(testToken)}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestClientConfig(t *testing.T) {
	t.Run("core.config.env-precedence", func(t *testing.T) {
		env := map[string]string{
			EnvPrefix + "URL": "http://grow:1", "BAO_ADDR": "http://bao:2", "VAULT_ADDR": "http://vault:3",
			"VAULT_TOKEN": "vault-token", "VAULT_NAMESPACE": "vault-ns", "VAULT_CACERT": "/vault/ca.pem",
			"VAULT_CLIENT_CERT": "/c.pem", "VAULT_CLIENT_KEY": "/k.pem", "VAULT_SKIP_VERIFY": "true",
		}
		cfg, err := ConfigFromEnvWith(Config{}, env)
		if err != nil || cfg.URL != "http://grow:1" || cfg.Token.Reveal() != "vault-token" || cfg.Namespace != "vault-ns" ||
			cfg.TLS.CACertPath != "/vault/ca.pem" || cfg.TLS.ClientCertPath != "/c.pem" || cfg.TLS.ClientKeyPath != "/k.pem" ||
			!cfg.TLS.InsecureSkipVerify {
			t.Fatalf("env: %v %s", err, cfg)
		}
		env["BAO_TOKEN"], env["BAO_NAMESPACE"], env["BAO_CACERT"] = "bao-token", "bao-ns", "/bao/ca.pem"
		delete(env, EnvPrefix+"URL")
		cfg, _ = ConfigFromEnvWith(Config{}, env)
		if cfg.URL != "http://bao:2" || cfg.Token.Reveal() != "bao-token" || cfg.Namespace != "bao-ns" || cfg.TLS.CACertPath != "/bao/ca.pem" {
			t.Fatalf("BAO_* must beat VAULT_*: %s", cfg)
		}
		env[EnvPrefix+"TOKEN"], env[EnvPrefix+"NAMESPACE"] = "grow-token", "grow-ns"
		env[EnvPrefix+"KV_MOUNT"], env[EnvPrefix+"KV_VERSION"], env[EnvPrefix+"SECRETS_PATH"] = "kv1", "1", "apps/x"
		cfg, _ = ConfigFromEnvWith(Config{}, env)
		if cfg.Token.Reveal() != "grow-token" || cfg.Namespace != "grow-ns" || cfg.KVMount != "kv1" || cfg.KVVersion != 1 || cfg.SecretsPath != "apps/x" {
			t.Fatalf("GROW_* must beat vendor variables: %s", cfg)
		}
		cfg, _ = ConfigFromEnvWith(Config{CommonConfig: CommonConfig{URL: "https://explicit"}, Token: NewSecret("explicit"), Namespace: "e", KVMount: "m", KVVersion: 2, SecretsPath: "p"}, env)
		if cfg.URL != "https://explicit" || cfg.Token.Reveal() != "explicit" || cfg.Namespace != "e" || cfg.KVMount != "m" || cfg.KVVersion != 2 || cfg.SecretsPath != "p" {
			t.Fatal("explicit must win")
		}
		cfg, _ = ConfigFromEnvWith(Config{}, map[string]string{})
		if cfg.URL != DefaultURL || cfg.RequestTimeout != DefaultRequestTimeout || cfg.kvMount() != "secret" || cfg.valueField() != "value" {
			t.Fatalf("defaults: %s", cfg)
		}
		_, err = ConfigFromEnvWith(Config{}, map[string]string{EnvPrefix + "TOTAL_TIMEOUT": "forever-xyz"})
		if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), EnvPrefix+"TOTAL_TIMEOUT") || strings.Contains(err.Error(), "forever-xyz") {
			t.Fatalf("invalid value: %v", err)
		}
		_, err = ConfigFromEnvWith(Config{}, map[string]string{EnvPrefix + "KV_VERSION": "two-xyz"})
		if !errors.Is(err, ErrConfig) || strings.Contains(err.Error(), "two-xyz") {
			t.Fatalf("invalid kv version: %v", err)
		}
		if _, err := ConfigFromEnvWith(Config{}, map[string]string{EnvPrefix + "KV_VERSION": "3"}); !errors.Is(err, ErrConfig) {
			t.Fatalf("kv version 3: %v", err)
		}
		if _, err := ConfigFromEnvWith(Config{}, map[string]string{EnvPrefix + "URL": "ftp://nope"}); !errors.Is(err, ErrConfig) {
			t.Fatalf("invalid url: %v", err)
		}
		if err := (Config{Namespace: "a b"}).Validate(); !errors.Is(err, ErrConfig) {
			t.Fatalf("namespace: %v", err)
		}
		t.Setenv(EnvPrefix+"URL", "http://process-env:9")
		if cfg, err := ConfigFromEnv(); err != nil || cfg.URL != "http://process-env:9" {
			t.Fatalf("process env: %v %s", err, cfg.URL)
		}
	})

	t.Run("core.redaction.config", func(t *testing.T) {
		cfg := Config{
			CommonConfig: CommonConfig{URL: "https://h", Headers: map[string]string{"X-Api-Key": "hdr-xyz"}},
			Token:        NewSecret("tok-xyz"),
		}
		forms := fmt.Sprintf("%v|%+v|%#v|%s", cfg, cfg, cfg, cfg.String())
		if strings.Contains(forms, "tok-xyz") || strings.Contains(forms, "hdr-xyz") || !strings.Contains(forms, "Token:"+Redacted) {
			t.Fatalf("forms: %s", forms)
		}
	})

	t.Run("invalid config", func(t *testing.T) {
		if _, err := NewClient(Config{CommonConfig: CommonConfig{URL: "mailto:x"}}); !errors.Is(err, ErrConfig) {
			t.Fatalf("NewClient: %v", err)
		}
		if _, err := NewClient(Config{CommonConfig: CommonConfig{TLS: TLSConfig{CACertPEM: "bad"}}}); !errors.Is(err, ErrConfig) {
			t.Fatalf("bad TLS: %v", err)
		}
		if _, err := NewClient(Config{KVVersion: -1}); !errors.Is(err, ErrConfig) {
			t.Fatalf("kv version: %v", err)
		}
	})
}

func TestClientHealth(t *testing.T) {
	cases := []struct {
		fixture, status string
		healthy         bool
	}{
		{"health.active", "active", true},
		{"health.sealed", "sealed", false},
		{"health.uninitialized", "uninitialized", false},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			m := newMockBao(t).fixture("GET", "/v1/sys/health", tc.fixture)
			hs, err := newBao(t, m, nil).Health(t.Context())
			if err != nil || hs.Status != tc.status || hs.Healthy != tc.healthy || hs.Details["version"] != "2.7.2" {
				t.Fatalf("%+v %v", hs, err)
			}
			if m.last("GET", "/v1/sys/health").Header.Get("X-Vault-Token") != "" {
				t.Fatal("health must not send the token")
			}
		})
	}
	t.Run("standby and others", func(t *testing.T) {
		m := newMockBao(t).
			json("GET", "/v1/sys/health", 429, map[string]any{"initialized": true, "sealed": false, "standby": true}).
			json("GET", "/v1/sys/health", 473, map[string]any{"initialized": true, "sealed": false, "standby": true, "performance_standby": true}).
			add("GET", "/v1/sys/health", reply{status: 502, body: []byte("bad gateway")})
		c := newBao(t, m, nil)
		for _, want := range []string{"standby", "perfstandby", "unhealthy"} {
			if hs, err := c.Health(t.Context()); err != nil || hs.Status != want || hs.Healthy {
				t.Fatalf("want %s: %+v %v", want, hs, err)
			}
		}
	})
	t.Run("core.health.unreachable", func(t *testing.T) {
		c := newTestClient(t, "http://"+closedAddr(t), func(cfg *Config) { cfg.ConnectTimeout = time.Second })
		if hs, err := c.Health(t.Context()); err != nil || hs.Healthy || hs.Status != "unreachable" {
			t.Fatalf("hs=%+v err=%v", hs, err)
		}
	})
}

func TestClientPingAndVersion(t *testing.T) {
	m := newMockBao(t).fixture("GET", "/v1/auth/token/lookup-self", "ping.lookup-self").fixture("GET", "/v1/sys/health", "health.active")
	c := newBao(t, m, func(c *Config) { c.Namespace = "/team-a/" })
	if d, err := c.Ping(t.Context()); err != nil || d <= 0 {
		t.Fatalf("ping %s %v", d, err)
	}
	r := m.last("GET", "/v1/auth/token/lookup-self")
	if r.Header.Get("X-Vault-Token") != testToken || r.Header.Get("X-Vault-Namespace") != "team-a" || r.Header.Get("Authorization") != "" {
		t.Fatalf("headers %v", r.Header)
	}
	if !strings.HasPrefix(r.Header.Get("User-Agent"), "grow-codes-openbao/") {
		t.Fatalf("core.useragent: %q", r.Header.Get("User-Agent"))
	}
	if v, err := c.ServerVersion(t.Context()); err != nil || v != "2.7.2" {
		t.Fatalf("version %q %v", v, err)
	}
	if v, err := c.Sys().Version(t.Context()); err != nil || v != "2.7.2" {
		t.Fatalf("sys version %q %v", v, err)
	}
	if hs, err := c.Sys().Health(t.Context()); err != nil || !hs.Healthy {
		t.Fatalf("sys health %+v %v", hs, err)
	}

	t.Run("invalid token is AUTHENTICATION", func(t *testing.T) {
		m := newMockBao(t).fixture("GET", "/v1/auth/token/lookup-self", "ping.invalid-token")
		_, err := newBao(t, m, nil).Ping(t.Context())
		wantCode(t, err, ErrorCodeAuthentication)
		if strings.Contains(err.Error(), testToken) {
			t.Fatal("token leaked")
		}
	})
	t.Run("policy denial is PERMISSION_DENIED", func(t *testing.T) {
		m := newMockBao(t).fixture("GET", "/v1/auth/token/lookup-self", "kvV2.read.permission-denied")
		_, err := newBao(t, m, nil).Ping(t.Context())
		wantCode(t, err, ErrorCodePermissionDenied)
	})
	t.Run("version while sealed and errors", func(t *testing.T) {
		m := newMockBao(t).fixture("GET", "/v1/sys/health", "health.sealed")
		if v, err := newBao(t, m, nil).ServerVersion(t.Context()); err != nil || v != "2.7.2" {
			t.Fatalf("sealed version %q %v", v, err)
		}
		m = newMockBao(t).json("GET", "/v1/sys/health", 200, map[string]any{"initialized": true})
		_, err := newBao(t, m, nil).ServerVersion(t.Context())
		wantCode(t, err, ErrorCodeUnsupported)
		m = newMockBao(t).errors("GET", "/v1/sys/health", 500, "boom")
		_, err = newBao(t, m, nil).ServerVersion(t.Context())
		wantCode(t, err, ErrorCodeUnavailable)
		_, err = newBao(t, newMockBao(t), nil).ServerVersion(t.Context())
		wantCode(t, err, ErrorCodeNotFound)
	})
	t.Run("token handling", func(t *testing.T) {
		c := newBao(t, m, func(c *Config) { c.Token = Secret{} })
		if !c.Token().IsZero() {
			t.Fatal("token")
		}
		_, _ = c.Ping(t.Context())
		if m.last("GET", "/v1/auth/token/lookup-self").Header.Get("X-Vault-Token") != "" {
			t.Fatal("no token expected")
		}
		c.SetToken("new-token-1")
		if c.Token().Reveal() != "new-token-1" || fmt.Sprint(c.Token()) != Redacted {
			t.Fatal("SetToken")
		}
		if c.Config().URL != m.URL {
			t.Fatal("Config()")
		}
	})
}

func TestClientErrorMapping(t *testing.T) {
	cases := []struct {
		status int
		msg    string
		code   ErrorCode
	}{
		{400, "check-and-set parameter did not match the current version", ErrorCodeConflict},
		{400, "invalid role or secret ID", ErrorCodeValidation},
		{403, "permission denied", ErrorCodeAuthentication},
		{403, "invalid token", ErrorCodeAuthentication},
		{403, "1 error occurred:\n\t* permission denied\n\n", ErrorCodePermissionDenied},
		{403, "preflight capability check returned 403", ErrorCodePermissionDenied},
		{404, "", ErrorCodeNotFound},
		{405, "1 error occurred:\n\t* unsupported operation\n\n", ErrorCodeUnsupported},
		{415, "PATCH requires Content-Type of application/merge-patch+json", ErrorCodeValidation},
		{501, "Vault is not initialized", ErrorCodeUnavailable},
		{503, "Vault is sealed", ErrorCodeUnavailable},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d %s", tc.status, tc.msg), func(t *testing.T) {
			m := newMockBao(t).errors("GET", "/v1/x", tc.status, tc.msg)
			_, err := newBao(t, m, nil).call(t.Context(), apiRequest{method: "GET", path: "x", op: "test"})
			wantCode(t, err, tc.code)
		})
	}
	if err := mapError(errors.New("plain")); err.Error() != "plain" {
		t.Fatal("non-SDK errors pass through")
	}
}

func TestClientMisc(t *testing.T) {
	t.Run("core.close.idempotent", func(t *testing.T) {
		m := newMockBao(t)
		c := newBao(t, m, nil)
		ran := 0
		c.onClose(func() { ran++ })
		first, second := c.Close(), c.Close()
		if first != nil || second != nil || ran != 1 {
			t.Fatal("close")
		}
		c.onClose(func() { ran++ })
		if ran != 2 {
			t.Fatal("onClose after close runs at once")
		}
		if _, err := c.Ping(t.Context()); !errors.Is(err, ErrCancelled) {
			t.Fatalf("after close: %v", err)
		}
	})
	t.Run("from env", func(t *testing.T) {
		m := newMockBao(t).fixture("GET", "/v1/auth/token/lookup-self", "ping.lookup-self")
		t.Setenv(EnvPrefix+"URL", m.URL)
		t.Setenv(EnvPrefix+"TOKEN", testToken)
		c, err := NewClientFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if _, err := c.Ping(t.Context()); err != nil {
			t.Fatal(err)
		}
		t.Setenv(EnvPrefix+"URL", "mailto:x")
		if _, err := NewClientFromEnv(); !errors.Is(err, ErrConfig) {
			t.Fatalf("bad env: %v", err)
		}
	})
	t.Run("bad JSON and bad data", func(t *testing.T) {
		m := newMockBao(t).add("GET", "/v1/x", reply{status: 200, body: []byte("{not json")}).
			json("GET", "/v1/y", 200, map[string]any{"data": []int{1}})
		c := newBao(t, m, nil)
		_, err := c.call(t.Context(), apiRequest{method: "GET", path: "x", op: "x"})
		wantCode(t, err, ErrorCodeUnavailable)
		var out map[string]any
		wantCode(t, c.callData(t.Context(), apiRequest{method: "GET", path: "y", op: "y"}, &out), ErrorCodeUnavailable)
		_, err = c.send(t.Context(), apiRequest{method: "POST", path: "z", body: func() {}, contentType: "application/merge-patch+json", op: "z"})
		wantCode(t, err, ErrorCodeValidation)
		wantCode(t, c.Wrapping().c.callData(t.Context(), apiRequest{method: "GET", path: "y", op: "y"}, &out), ErrorCodeUnavailable)
		if _, err := c.list(t.Context(), "y", "list"); CodeOf(err) != ErrorCodeUnavailable {
			t.Fatalf("list bad data: %v", err)
		}
	})
	t.Run("helpers", func(t *testing.T) {
		if durationString(1500*time.Millisecond) != "2s" || durationString(time.Minute) != "60s" {
			t.Fatal("durationString")
		}
		if joinPath("/a/", "", "b/c/") != "a/b/c" || mountOr("", "x") != "x" || mountOr("/m/", "x") != "m" {
			t.Fatal("paths")
		}
		if *Ptr(3) != 3 {
			t.Fatal("Ptr")
		}
		var ft flexTime
		for _, in := range []string{`"2026-11-18T20:28:54.7Z"`, `1795033741`, `"1795033741"`, `null`, `""`, `"junk"`} {
			if err := ft.UnmarshalJSON([]byte(in)); err != nil {
				t.Fatal(err)
			}
		}
		var fd flexDuration
		for in, want := range map[string]time.Duration{`3600`: time.Hour, `"720h0m0s"`: 720 * time.Hour, `null`: 0, `"x"`: 0} {
			if err := fd.UnmarshalJSON([]byte(in)); err != nil || fd.Duration != want {
				t.Fatalf("%s: %s", in, fd.Duration)
			}
		}
	})
}
