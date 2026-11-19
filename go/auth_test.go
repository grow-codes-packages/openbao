package openbao

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthLogins(t *testing.T) {
	jwtFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(jwtFile, []byte(" k8s-jwt-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := newMockBao(t).
		fixture("POST", "/v1/auth/approle/login", "appRoleLogin.ok").
		fixture("POST", "/v1/auth/ar2/login", "appRoleLogin.custom-mount").
		fixture("POST", "/v1/auth/userpass/login/sdk-user", "userpassLogin.ok").
		fixture("POST", "/v1/auth/jwt/login", "jwtLogin.ok").
		fixture("POST", "/v1/auth/kubernetes/login", "appRoleLogin.ok").
		fixture("GET", "/v1/auth/token/lookup-self", "lookupSelf.ok")
	c := newBao(t, m, func(c *Config) { c.Token = Secret{} })
	ctx := t.Context()

	cases := []struct {
		name   string
		method AuthMethod
		path   string
		check  func(map[string]any) bool
	}{
		{"approle", NewAppRoleAuth("role-1", "secret-id-1"), "/v1/auth/approle/login",
			func(b map[string]any) bool { return b["role_id"] == "role-1" && b["secret_id"] == "secret-id-1" }},
		{"approle custom mount", &AppRoleAuth{RoleID: "role-2", Mount: "/ar2/"}, "/v1/auth/ar2/login",
			func(b map[string]any) bool { _, has := b["secret_id"]; return b["role_id"] == "role-2" && !has }},
		{"userpass", NewUserpassAuth("sdk-user", "pw-123456"), "/v1/auth/userpass/login/sdk-user",
			func(b map[string]any) bool { return b["password"] == "pw-123456" }},
		{"jwt", NewJWTAuth("sdk-jwt", "jwt-value-1"), "/v1/auth/jwt/login",
			func(b map[string]any) bool { return b["role"] == "sdk-jwt" && b["jwt"] == "jwt-value-1" }},
		{"kubernetes", NewKubernetesAuth("sdk-k8s", jwtFile), "/v1/auth/kubernetes/login",
			func(b map[string]any) bool { return b["role"] == "sdk-k8s" && b["jwt"] == "k8s-jwt-value" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c.SetToken("")
			info, err := c.Auth().Login(ctx, tc.method)
			if err != nil {
				t.Fatal(err)
			}
			r := m.last("POST", tc.path)
			if r.Header.Get("X-Vault-Token") != "" || !tc.check(r.JSON(t)) {
				t.Fatalf("request %s %v", r.Body, r.Header)
			}
			if c.Token().Reveal() != "<redacted>" || info.LeaseDuration <= 0 || len(info.Policies) == 0 || info.TokenType != "service" {
				t.Fatalf("info %+v", info)
			}
			if fmt.Sprintf("%v", info.ClientToken) != Redacted || !strings.Contains(fmt.Sprintf("%+v", info), "ClientToken:"+Redacted) {
				t.Fatal("ClientToken must print redacted")
			}
		})
	}
	t.Run("token auth", func(t *testing.T) {
		info, err := c.Auth().Login(ctx, NewTokenAuth("given-token-1"))
		if err != nil || c.Token().Reveal() != "given-token-1" || info.LeaseDuration != 3599*time.Second || !info.Renewable {
			t.Fatalf("%+v %v", info, err)
		}
		if m.last("GET", "/v1/auth/token/lookup-self").Header.Get("X-Vault-Token") != "given-token-1" {
			t.Fatal("token auth must verify the given token")
		}
		method, last := c.Auth().lastLogin()
		if method == nil || last != info {
			t.Fatal("last login not remembered")
		}
	})
	t.Run("argument errors", func(t *testing.T) {
		for _, method := range []AuthMethod{
			nil, &TokenAuth{}, &AppRoleAuth{}, &UserpassAuth{}, &JWTAuth{Role: "r"}, &KubernetesAuth{},
		} {
			if _, err := c.Auth().Login(ctx, method); !errors.Is(err, ErrValidation) {
				t.Fatalf("%T: %v", method, err)
			}
		}
		if _, err := c.Auth().Login(ctx, NewKubernetesAuth("r", filepath.Join(t.TempDir(), "missing"))); !errors.Is(err, ErrConfig) {
			t.Fatalf("missing jwt file: %v", err)
		}
		empty := filepath.Join(t.TempDir(), "empty")
		_ = os.WriteFile(empty, nil, 0o600)
		if _, err := c.Auth().Login(ctx, NewKubernetesAuth("r", empty)); !errors.Is(err, ErrConfig) {
			t.Fatalf("empty jwt file: %v", err)
		}
		if _, err := c.Auth().Login(ctx, NewKubernetesAuth("r", "")); !errors.Is(err, ErrConfig) {
			t.Fatalf("default jwt path outside a pod: %v", err)
		}
	})
}

func TestAuthLoginErrors(t *testing.T) {
	m := newMockBao(t).
		fixture("POST", "/v1/auth/approle/login", "appRoleLogin.invalid-secret").
		fixture("POST", "/v1/auth/jwt/login", "jwtLogin.expired").
		fixture("POST", "/v1/auth/kubernetes/login", "kubernetesLogin.no-kubernetes-api").
		data("POST", "/v1/auth/userpass/login/u", nil)
	c := newBao(t, m, nil)
	_, err := c.Auth().Login(t.Context(), NewAppRoleAuth("r", "bad-secret-id"))
	wantCode(t, err, ErrorCodeAuthentication)
	if strings.Contains(err.Error(), "bad-secret-id") {
		t.Fatal("secret id leaked")
	}
	_, err = c.Auth().Login(t.Context(), NewJWTAuth("r", "expired-jwt"))
	wantCode(t, err, ErrorCodeAuthentication)
	jwtFile := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(jwtFile, []byte("k8s"), 0o600)
	_, err = c.Auth().Login(t.Context(), NewKubernetesAuth("sdk-k8s", jwtFile))
	wantCode(t, err, ErrorCodeAuthentication)
	_, err = c.Auth().Login(t.Context(), NewUserpassAuth("u", "p"))
	wantCode(t, err, ErrorCodeAuthentication)
	if c.Token().Reveal() != testToken {
		t.Fatal("failed logins must keep the token")
	}
	_, err = c.Auth().Login(t.Context(), NewTokenAuth("bad"))
	wantCode(t, err, ErrorCodeNotFound)
}

func TestAuthTokenOperations(t *testing.T) {
	m := newMockBao(t).
		fixture("GET", "/v1/auth/token/lookup-self", "lookupSelf.ok").
		fixture("POST", "/v1/auth/token/renew-self", "renewSelf.ok").
		noContent("POST", "/v1/auth/token/revoke-self").
		fixture("POST", "/v1/auth/token/create", "createToken.ok").
		fixture("POST", "/v1/auth/token/create/my-role", "createToken.orphan")
	c := newBao(t, m, nil)
	ctx := t.Context()

	ti, err := c.Auth().LookupSelf(ctx)
	if err != nil || ti.DisplayName != "token-sdk-test" || ti.TTL != 3599*time.Second || ti.CreationTTL != time.Hour ||
		ti.CreationTime.IsZero() || ti.ExpireTime.IsZero() || !ti.Renewable || ti.Meta["run"] == "" || ti.Type != "service" {
		t.Fatalf("%+v %v", ti, err)
	}
	info, err := c.Auth().RenewSelf(ctx, 30*time.Minute)
	if err != nil || info.LeaseDuration != 30*time.Minute || m.last("POST", "/v1/auth/token/renew-self").JSON(t)["increment"] != "1800s" {
		t.Fatalf("%+v %v", info, err)
	}
	if _, err := c.Auth().RenewSelf(ctx, 0); err != nil || len(m.last("POST", "/v1/auth/token/renew-self").JSON(t)) != 0 {
		t.Fatal("renew without increment")
	}
	tok, err := c.Auth().CreateToken(ctx, &TokenCreateOptions{
		Policies: []string{"sdk-app"}, TTL: time.Hour, ExplicitMaxTTL: 2 * time.Hour, Period: time.Minute, Renewable: Ptr(true),
		DisplayName: "sdk-test", Meta: map[string]string{"run": "x"}, NumUses: 3, NoParent: true, NoDefaultPolicy: true,
		Type: "service", EntityAlias: "alias",
	})
	if err != nil || tok.ClientToken.IsZero() || tok.LeaseDuration != time.Hour {
		t.Fatalf("%+v %v", tok, err)
	}
	b := m.last("POST", "/v1/auth/token/create").JSON(t)
	if b["ttl"] != "3600s" || b["explicit_max_ttl"] != "7200s" || b["period"] != "60s" || b["renewable"] != true || b["no_parent"] != true ||
		b["no_default_policy"] != true || b["num_uses"] != float64(3) || b["type"] != "service" || b["entity_alias"] != "alias" || b["display_name"] != "sdk-test" {
		t.Fatalf("body %v", b)
	}
	if _, err := c.Auth().CreateToken(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if tok, err := c.Auth().CreateToken(ctx, &TokenCreateOptions{Role: "my-role"}); err != nil || !tok.Orphan {
		t.Fatalf("role token %+v %v", tok, err)
	}
	if err := c.Auth().RevokeSelf(ctx); err != nil || !c.Token().IsZero() {
		t.Fatalf("revoke %v", err)
	}

	t.Run("errors", func(t *testing.T) {
		m := newMockBao(t).
			fixture("POST", "/v1/auth/token/renew-self", "renewSelf.not-renewable").
			fixture("POST", "/v1/auth/token/create", "createToken.permission-denied").
			fixture("GET", "/v1/auth/token/lookup-self", "lookupSelf.revoked").
			errors("POST", "/v1/auth/token/revoke-self", 403, "permission denied")
		c := newBao(t, m, nil)
		_, err := c.Auth().RenewSelf(t.Context(), time.Minute)
		wantCode(t, err, ErrorCodeValidation)
		_, err = c.Auth().CreateToken(t.Context(), nil)
		wantCode(t, err, ErrorCodePermissionDenied)
		_, err = c.Auth().LookupSelf(t.Context())
		wantCode(t, err, ErrorCodeAuthentication)
		wantCode(t, c.Auth().RevokeSelf(t.Context()), ErrorCodeAuthentication)
		if c.Token().IsZero() {
			t.Fatal("failed revoke keeps the token")
		}
		m2 := newMockBao(t).data("POST", "/v1/auth/token/renew-self", nil).data("POST", "/v1/auth/token/create", nil)
		c2 := newBao(t, m2, nil)
		_, err = c2.Auth().RenewSelf(t.Context(), 0)
		wantCode(t, err, ErrorCodeUnavailable)
		_, err = c2.Auth().CreateToken(t.Context(), nil)
		wantCode(t, err, ErrorCodeUnavailable)
		_, err = newBao(t, newMockBao(t), nil).Auth().LoginWith(t.Context(), "x/login", nil)
		wantCode(t, err, ErrorCodeNotFound)
	})
}

func renewAuth(ttl int, renewable bool) map[string]any {
	return map[string]any{"auth": map[string]any{"client_token": "renewed-token", "lease_duration": ttl, "renewable": renewable}}
}

func lookupData(ttl int, renewable bool) map[string]any {
	return map[string]any{"ttl": ttl, "renewable": renewable}
}

func TestTokenRenewer(t *testing.T) {
	t.Run("renews until capped then expires", func(t *testing.T) {
		m := newMockBao(t).data("GET", "/v1/auth/token/lookup-self", lookupData(60, true)).
			json("POST", "/v1/auth/token/renew-self", 200, renewAuth(60, true)).
			json("POST", "/v1/auth/token/renew-self", 200, renewAuth(30, true))
		c := newBao(t, m, nil)
		var renews int
		expired := make(chan struct{})
		r, err := c.Auth().StartRenewer(t.Context(), &TokenRenewerOptions{
			Increment: time.Minute, Clock: newFakeClock(),
			OnRenew:  func(*AuthInfo) { renews++ },
			OnExpire: func() { close(expired) },
		})
		if err != nil {
			t.Fatal(err)
		}
		waitDone(t, r.Done())
		<-expired
		if renews != 2 || m.count("POST", "/v1/auth/token/renew-self") != 2 {
			t.Fatalf("renews %d", renews)
		}
	})
	t.Run("rejected renewal then re-login", func(t *testing.T) {
		m := newMockBao(t).data("GET", "/v1/auth/token/lookup-self", lookupData(60, true)).
			errors("POST", "/v1/auth/token/renew-self", 400, "lease is not renewable").
			fixture("POST", "/v1/auth/approle/login", "appRoleLogin.ok").
			errors("POST", "/v1/auth/approle/login", 400, "invalid role or secret ID")
		c := newBao(t, m, nil)
		var errs, renews int
		expired := false
		r, err := c.Auth().StartRenewer(t.Context(), &TokenRenewerOptions{
			ReLogin: true, Clock: newFakeClock(),
			OnRenew:  func(*AuthInfo) { renews++ },
			OnError:  func(error) { errs++ },
			OnExpire: func() { expired = true },
		})
		if err != nil {
			t.Fatal(err)
		}
		waitDone(t, r.Done())
		if renews != 0 || errs != 1 || !expired {
			t.Fatalf("no login method: renews=%d errs=%d expired=%v", renews, errs, expired)
		}
		if _, err := c.Auth().Login(t.Context(), NewAppRoleAuth("r", "s")); err != nil {
			t.Fatal(err)
		}
		errs, expired = 0, false
		r, _ = c.Auth().StartRenewer(t.Context(), &TokenRenewerOptions{
			ReLogin: true, Clock: newFakeClock(),
			OnRenew:  func(*AuthInfo) { renews++ },
			OnError:  func(error) { errs++ },
			OnExpire: func() { expired = true },
		})
		waitDone(t, r.Done())
		// renew rejected -> re-login fails (second login reply) -> expire
		if errs != 2 || !expired || m.count("POST", "/v1/auth/approle/login") != 2 {
			t.Fatalf("relogin: errs=%d expired=%v logins=%d", errs, expired, m.count("POST", "/v1/auth/approle/login"))
		}
	})
	t.Run("re-login success keeps going", func(t *testing.T) {
		m := newMockBao(t).data("GET", "/v1/auth/token/lookup-self", lookupData(60, false)).
			fixture("POST", "/v1/auth/approle/login", "appRoleLogin.ok").
			fixture("POST", "/v1/auth/approle/login", "appRoleLogin.ok").
			json("POST", "/v1/auth/approle/login", 200, renewAuth(0, false))
		c := newBao(t, m, nil)
		if _, err := c.Auth().Login(t.Context(), NewAppRoleAuth("r", "s")); err != nil {
			t.Fatal(err)
		}
		renewed := make(chan *AuthInfo, 4)
		r, _ := c.Auth().StartRenewer(t.Context(), &TokenRenewerOptions{
			ReLogin: true, Clock: newFakeClock(), OnRenew: func(i *AuthInfo) { renewed <- i },
		})
		// login #2 (renewable, 3600 s) -> renew-self 404 (not configured) is not retryable -> login #3 (never expires)
		<-renewed
		<-renewed
		r.Stop()
		r.Stop()
		waitDone(t, r.Done())
	})
	t.Run("retryable errors until expiry", func(t *testing.T) {
		m := newMockBao(t).data("GET", "/v1/auth/token/lookup-self", lookupData(60, true)).
			errors("POST", "/v1/auth/token/renew-self", 503, "sealed")
		c := newBao(t, m, nil)
		var errs int
		expired := false
		r, _ := c.Auth().StartRenewer(t.Context(), &TokenRenewerOptions{
			Clock: newFakeClock(), OnError: func(error) { errs++ }, OnExpire: func() { expired = true },
		})
		waitDone(t, r.Done())
		if errs < 2 || !expired {
			t.Fatalf("errs=%d expired=%v", errs, expired)
		}
	})
	t.Run("non-expiring token and close", func(t *testing.T) {
		m := newMockBao(t).data("GET", "/v1/auth/token/lookup-self", lookupData(0, false))
		c := newBao(t, m, nil)
		r, err := c.Auth().StartRenewer(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
		waitDone(t, r.Done())
	})
	t.Run("stop while waiting", func(t *testing.T) {
		m := newMockBao(t).data("GET", "/v1/auth/token/lookup-self", lookupData(60, true))
		c := newBao(t, m, nil)
		r, _ := c.Auth().StartRenewer(t.Context(), &TokenRenewerOptions{Clock: blockClock{}})
		r.Stop()
		waitDone(t, r.Done())
		m = newMockBao(t).data("GET", "/v1/auth/token/lookup-self", lookupData(60, false))
		c = newBao(t, m, nil)
		r, _ = c.Auth().StartRenewer(t.Context(), &TokenRenewerOptions{Clock: blockClock{}})
		r.Stop()
		waitDone(t, r.Done())
	})
	t.Run("lookup failure", func(t *testing.T) {
		_, err := newBao(t, newMockBao(t), nil).Auth().StartRenewer(t.Context(), nil)
		wantCode(t, err, ErrorCodeNotFound)
	})
	if renewWait(time.Unix(0, 0), time.Unix(0, 0)) != minRenewWait || clockOr(nil) != SystemClock {
		t.Fatal("renewWait / clockOr")
	}
	if SystemClock.Now().IsZero() {
		t.Fatal("system clock")
	}
	<-SystemClock.After(time.Millisecond)
}
