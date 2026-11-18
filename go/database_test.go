package openbao

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestDatabase(t *testing.T) {
	m := newMockBao(t).
		fixture("POST", "/v1/database/config/pg", "database.configureConnection.ok").
		fixture("GET", "/v1/database/config/pg", "database.readConnection.ok").
		fixture("DELETE", "/v1/database/config/pg", "database.deleteConnection.ok").
		fixture("POST", "/v1/database/roles/ro", "database.createRole.ok").
		fixture("GET", "/v1/database/roles/ro", "database.readRole.ok").
		fixture("DELETE", "/v1/database/roles/ro", "database.deleteRole.ok").
		fixture("GET", "/v1/database/creds/ro", "database.getCredentials.ok").
		fixture("GET", "/v1/database/creds/unknown", "database.getCredentials.unknown-role").
		fixture("POST", "/v1/database/config/bad", "database.configureConnection.bad-credentials")
	c := newBao(t, m, nil)
	db := c.Database("")
	ctx := t.Context()
	if db.Mount() != "database" {
		t.Fatal("mount")
	}
	err := db.ConfigureConnection(ctx, "pg", DatabaseConnectionConfig{
		PluginName: "postgresql-database-plugin", ConnectionURL: "postgresql://{{username}}:{{password}}@pg:5432/app",
		Username: "postgres", Password: NewSecret("pg-admin-pw"), AllowedRoles: []string{"ro"}, VerifyConnection: Ptr(true),
		Extra: map[string]any{"max_open_connections": 4},
	})
	b := m.last("POST", "/v1/database/config/pg").JSON(t)
	if err != nil || b["password"] != "pg-admin-pw" || b["verify_connection"] != true || b["max_open_connections"] != float64(4) || b["plugin_name"] == nil {
		t.Fatalf("configure %v %v", b, err)
	}
	if cfg, err := db.ReadConnection(ctx, "pg"); err != nil || cfg["plugin_name"] == nil {
		t.Fatalf("read connection %v %v", cfg, err)
	}
	err = db.CreateRole(ctx, "ro", DatabaseRoleConfig{
		DBName: "pg", CreationStatements: []string{"CREATE ROLE"}, RevocationStatements: []string{"DROP"},
		RollbackStatements: []string{"RB"}, RenewStatements: []string{"RN"}, DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour,
	})
	b = m.last("POST", "/v1/database/roles/ro").JSON(t)
	if err != nil || b["default_ttl"] != "3600s" || b["max_ttl"] != "7200s" || b["db_name"] != "pg" || b["renew_statements"] == nil {
		t.Fatalf("create role %v %v", b, err)
	}
	role, err := db.ReadRole(ctx, "ro")
	if err != nil || role.DefaultTTL != time.Hour || role.MaxTTL != 2*time.Hour || len(role.CreationStatements) != 2 {
		t.Fatalf("read role %+v %v", role, err)
	}
	lease, err := db.GetCredentials(ctx, "ro")
	if err != nil || !strings.HasPrefix(lease.ID, "database/creds/") || !lease.Renewable || lease.Duration != time.Hour ||
		lease.Username == "" || lease.Password.Reveal() != "<redacted>" || lease.Data["password"] != nil || lease.ExpiresAt().IsZero() {
		t.Fatalf("creds %+v %v", lease, err)
	}
	if strings.Contains(fmt.Sprintf("%+v", lease), "Password:<redacted>") {
		t.Fatal("password must print redacted")
	}
	if (&Lease{}).ExpiresAt() != (time.Time{}) {
		t.Fatal("non-expiring lease")
	}
	if err := db.DeleteRole(ctx, "ro"); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteConnection(ctx, "pg"); err != nil {
		t.Fatal(err)
	}
	_, err = db.GetCredentials(ctx, "unknown")
	wantCode(t, err, ErrorCodeValidation)
	wantCode(t, db.ConfigureConnection(ctx, "bad", DatabaseConnectionConfig{}), ErrorCodeValidation)
	wantCode(t, db.ConfigureConnection(ctx, "", DatabaseConnectionConfig{}), ErrorCodeValidation)
	wantCode(t, db.CreateRole(ctx, "", DatabaseRoleConfig{}), ErrorCodeValidation)
	_, err = db.GetCredentials(ctx, "")
	wantCode(t, err, ErrorCodeValidation)
	_, err = db.ReadRole(ctx, "missing")
	wantCode(t, err, ErrorCodeNotFound)
	m.json("GET", "/v1/database/creds/odd", 200, map[string]any{"data": []int{1}})
	_, err = db.GetCredentials(ctx, "odd")
	wantCode(t, err, ErrorCodeUnavailable)
	_, err = db.GetCredentials(ctx, "missing")
	wantCode(t, err, ErrorCodeNotFound)
}

func TestLeaseManager(t *testing.T) {
	m := newMockBao(t).
		fixture("PUT", "/v1/sys/leases/renew", "leases.renew.ok").
		fixture("PUT", "/v1/sys/leases/revoke", "leases.revoke.ok").
		fixture("PUT", "/v1/sys/leases/lookup", "leases.lookup.ok").
		fixture("PUT", "/v1/sys/leases/revoke-prefix/database/creds/ro", "leases.revokePrefix.ok")
	c := newBao(t, m, nil)
	lm := c.LeaseManager()
	ctx := t.Context()
	info, err := lm.Renew(ctx, "database/creds/ro/abc", 10*time.Minute)
	if err != nil || info.Duration <= 0 || info.ID == "" || info.Capped() || m.last("PUT", "/v1/sys/leases/renew").JSON(t)["increment"] != "600s" {
		t.Fatalf("renew %+v %v", info, err)
	}
	lk, err := lm.Lookup(ctx, "database/creds/ro/abc")
	if err != nil || !strings.HasPrefix(lk.Path, "database/creds/ro") || lk.TTL != 3599*time.Second || lk.ExpireTime.IsZero() || !lk.LastRenewal.IsZero() {
		t.Fatalf("lookup %+v %v", lk, err)
	}
	if err := lm.Revoke(ctx, "database/creds/ro/abc"); err != nil {
		t.Fatal(err)
	}
	if err := lm.RevokePrefix(ctx, "/database/creds/ro/"); err != nil {
		t.Fatal(err)
	}
	_, err = lm.Renew(ctx, "", 0)
	wantCode(t, err, ErrorCodeValidation)
	wantCode(t, lm.Revoke(ctx, ""), ErrorCodeValidation)
	wantCode(t, lm.RevokePrefix(ctx, ""), ErrorCodeValidation)
	_, err = lm.Lookup(ctx, "")
	wantCode(t, err, ErrorCodeValidation)

	t.Run("errors and capping", func(t *testing.T) {
		m := newMockBao(t).
			fixture("PUT", "/v1/sys/leases/renew", "leases.renew.capped").
			fixture("PUT", "/v1/sys/leases/renew", "leases.renew.not-found").
			fixture("PUT", "/v1/sys/leases/lookup", "leases.lookup.revoked")
		lm := newBao(t, m, nil).LeaseManager()
		info, err := lm.Renew(t.Context(), "l1", 100*time.Hour)
		if err != nil || !info.Capped() || info.Duration != 2*time.Hour {
			t.Fatalf("capped %+v %v", info, err)
		}
		_, err = lm.Renew(t.Context(), "l1", 0)
		wantCode(t, err, ErrorCodeValidation)
		_, err = lm.Lookup(t.Context(), "l1")
		wantCode(t, err, ErrorCodeValidation)
		m.json("PUT", "/v1/sys/leases/renew-id", 200, map[string]any{"lease_duration": 5})
	})
}

func leaseReply(ttl int, renewable bool, warnings ...string) map[string]any {
	return map[string]any{"lease_id": "", "renewable": renewable, "lease_duration": ttl, "warnings": warnings}
}

func TestManagedLease(t *testing.T) {
	lease := func(ttl time.Duration, renewable bool) *Lease {
		return &Lease{ID: "database/creds/ro/x", Renewable: renewable, Duration: ttl}
	}
	t.Run("renews until capped then expires once", func(t *testing.T) {
		m := newMockBao(t).
			json("PUT", "/v1/sys/leases/renew", 200, leaseReply(3600, true)).
			json("PUT", "/v1/sys/leases/renew", 200, leaseReply(1800, true, `TTL of "100h" exceeded the effective max_ttl of "2h"; TTL value is capped accordingly`))
		lm := newBao(t, m, nil).LeaseManager()
		var renews, expires int
		ml := lm.Manage(lease(time.Hour, true), &ManageOptions{
			Clock: newFakeClock(), OnRenew: func(*LeaseInfo) { renews++ }, OnExpire: func(*Lease) { expires++ },
		})
		waitDone(t, ml.Done())
		if renews != 2 || expires != 1 || ml.Lease().ID == "" {
			t.Fatalf("renews=%d expires=%d", renews, expires)
		}
	})
	t.Run("increment above grant counts as capped", func(t *testing.T) {
		m := newMockBao(t).json("PUT", "/v1/sys/leases/renew", 200, leaseReply(60, true))
		lm := newBao(t, m, nil).LeaseManager()
		expired := false
		ml := lm.Manage(lease(time.Minute, true), &ManageOptions{Increment: time.Hour, Clock: newFakeClock(), OnExpire: func(*Lease) { expired = true }})
		waitDone(t, ml.Done())
		if !expired || m.count("PUT", "/v1/sys/leases/renew") != 1 {
			t.Fatal("capped by increment")
		}
	})
	t.Run("rejected renewal expires", func(t *testing.T) {
		m := newMockBao(t).errors("PUT", "/v1/sys/leases/renew", 400, "lease not found")
		lm := newBao(t, m, nil).LeaseManager()
		var errs, expires int
		ml := lm.Manage(lease(time.Minute, true), &ManageOptions{Clock: newFakeClock(), OnError: func(error) { errs++ }, OnExpire: func(*Lease) { expires++ }})
		waitDone(t, ml.Done())
		if errs != 1 || expires != 1 {
			t.Fatalf("errs=%d expires=%d", errs, expires)
		}
	})
	t.Run("retryable errors until expiry", func(t *testing.T) {
		m := newMockBao(t).errors("PUT", "/v1/sys/leases/renew", 503, "sealed")
		lm := newBao(t, m, nil).LeaseManager()
		var errs, expires int
		ml := lm.Manage(lease(time.Minute, true), &ManageOptions{Clock: newFakeClock(), OnError: func(error) { errs++ }, OnExpire: func(*Lease) { expires++ }})
		waitDone(t, ml.Done())
		if errs < 2 || expires != 1 {
			t.Fatalf("errs=%d expires=%d", errs, expires)
		}
	})
	t.Run("not renewable waits for expiry", func(t *testing.T) {
		lm := newBao(t, newMockBao(t), nil).LeaseManager()
		expired := false
		l := lease(time.Minute, false)
		l.IssuedAt = time.Now()
		ml := lm.Manage(l, &ManageOptions{Clock: newFakeClock(), OnExpire: func(*Lease) { expired = true }})
		waitDone(t, ml.Done())
		if !expired {
			t.Fatal("expire")
		}
	})
	t.Run("stop, revoke and close", func(t *testing.T) {
		m := newMockBao(t).noContent("PUT", "/v1/sys/leases/revoke")
		c := newBao(t, m, nil)
		lm := c.LeaseManager()
		a := lm.Manage(lease(time.Minute, true), &ManageOptions{Clock: blockClock{}})
		b := lm.Manage(lease(0, false), nil)
		other := &Lease{ID: "other", Renewable: true, Duration: time.Minute}
		d := lm.Manage(other, &ManageOptions{Clock: blockClock{}})
		if err := lm.Revoke(t.Context(), "database/creds/ro/x"); err != nil {
			t.Fatal(err)
		}
		waitDone(t, a.Done())
		waitDone(t, b.Done())
		d.Stop()
		waitDone(t, d.Done())
		e := lm.Manage(other, &ManageOptions{Clock: blockClock{}})
		_ = c.Close()
		waitDone(t, e.Done())
		f := lm.Manage(other, nil)
		waitDone(t, f.Done())
	})
}
