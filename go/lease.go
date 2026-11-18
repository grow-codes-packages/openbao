package openbao

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"
)

// LeaseInfo is the result of LeaseManager.Renew.
type LeaseInfo struct {
	ID        string
	Renewable bool
	// Duration is the granted TTL (capped by the max TTL; see Warnings).
	Duration time.Duration
	Warnings []string
}

// Capped reports whether the server capped the grant at the lease's max TTL.
func (l *LeaseInfo) Capped() bool {
	for _, w := range l.Warnings {
		w = strings.ToLower(w)
		if strings.Contains(w, "capped") || strings.Contains(w, "max_ttl") {
			return true
		}
	}
	return false
}

// LeaseLookup is the result of LeaseManager.Lookup.
type LeaseLookup struct {
	ID          string
	Path        string
	IssueTime   time.Time
	ExpireTime  time.Time
	LastRenewal time.Time
	Renewable   bool
	TTL         time.Duration
}

// LeaseManager renews and revokes leases and keeps managed leases alive in
// the background. Get it with Client.LeaseManager; Close of the client stops
// every managed lease.
type LeaseManager struct {
	c *Client

	mu      sync.Mutex
	managed map[*ManagedLease]struct{}
	closed  bool
}

func newLeaseManager(c *Client) *LeaseManager {
	return &LeaseManager{c: c, managed: map[*ManagedLease]struct{}{}}
}

// Renew renews a lease (PUT sys/leases/renew). increment is the requested TTL
// (0 = the lease default). An unknown or revoked lease is a VALIDATION error.
func (m *LeaseManager) Renew(ctx context.Context, leaseID string, increment time.Duration) (*LeaseInfo, error) {
	op := "lease.renew"
	if err := requireArg(op, "leaseId", leaseID); err != nil {
		return nil, err
	}
	body := map[string]any{"lease_id": leaseID}
	if increment > 0 {
		body["increment"] = durationString(increment)
	}
	env, err := m.c.call(ctx, apiRequest{method: http.MethodPut, path: "sys/leases/renew", body: body, op: op})
	if err != nil {
		return nil, err
	}
	id := env.LeaseID
	if id == "" {
		id = leaseID
	}
	return &LeaseInfo{ID: id, Renewable: env.Renewable, Duration: seconds(env.LeaseDuration), Warnings: env.Warnings}, nil
}

// Revoke revokes a lease (PUT sys/leases/revoke) and stops managing it.
func (m *LeaseManager) Revoke(ctx context.Context, leaseID string) error {
	op := "lease.revoke"
	if err := requireArg(op, "leaseId", leaseID); err != nil {
		return err
	}
	m.stopManaged(leaseID)
	_, err := m.c.call(ctx, apiRequest{method: http.MethodPut, path: "sys/leases/revoke", body: map[string]any{"lease_id": leaseID}, op: op})
	return err
}

// RevokePrefix revokes every lease under prefix (PUT sys/leases/revoke-prefix/<prefix>; needs sudo).
func (m *LeaseManager) RevokePrefix(ctx context.Context, prefix string) error {
	op := "lease.revokePrefix"
	if err := requireArg(op, "prefix", prefix); err != nil {
		return err
	}
	_, err := m.c.call(ctx, apiRequest{method: http.MethodPut, path: "sys/leases/revoke-prefix/" + trimSlashes(prefix), op: op})
	return err
}

// Lookup returns a lease's properties (PUT sys/leases/lookup).
func (m *LeaseManager) Lookup(ctx context.Context, leaseID string) (*LeaseLookup, error) {
	op := "lease.lookup"
	if err := requireArg(op, "leaseId", leaseID); err != nil {
		return nil, err
	}
	var d struct {
		ID          string   `json:"id"`
		Path        string   `json:"path"`
		IssueTime   flexTime `json:"issue_time"`
		ExpireTime  flexTime `json:"expire_time"`
		LastRenewal flexTime `json:"last_renewal"`
		Renewable   bool     `json:"renewable"`
		TTL         int64    `json:"ttl"`
	}
	if err := m.c.callData(ctx, apiRequest{method: http.MethodPut, path: "sys/leases/lookup", body: map[string]any{"lease_id": leaseID}, op: op}, &d); err != nil {
		return nil, err
	}
	return &LeaseLookup{
		ID: d.ID, Path: d.Path, IssueTime: d.IssueTime.Time, ExpireTime: d.ExpireTime.Time,
		LastRenewal: d.LastRenewal.Time, Renewable: d.Renewable, TTL: seconds(d.TTL),
	}, nil
}

// ManageOptions configure automatic renewal of a lease.
type ManageOptions struct {
	// Increment is the TTL requested on every renewal (0 = the lease default).
	Increment time.Duration
	// OnRenew is called after every successful renewal.
	OnRenew func(info *LeaseInfo)
	// OnError receives renewal errors; renewal continues while the lease is valid.
	OnError func(err error)
	// OnExpire is called exactly once when the lease expires (max TTL reached,
	// not renewable, or rejected by the server); management then stops.
	OnExpire func(lease *Lease)
	// Clock replaces the real clock (tests).
	Clock Clock
}

// ManagedLease is a lease renewed in the background (LeaseManager.Manage).
type ManagedLease struct {
	*background
	m     *LeaseManager
	lease *Lease
	opts  ManageOptions
	clock Clock
}

// Lease returns the managed lease.
func (ml *ManagedLease) Lease() *Lease { return ml.lease }

// Manage renews lease at 2/3 of its remaining TTL until the max TTL caps the
// grant, then calls OnExpire once at expiry. Stop the handle, Revoke the
// lease or Close the client to end it.
func (m *LeaseManager) Manage(lease *Lease, opts *ManageOptions) *ManagedLease {
	o := ManageOptions{}
	if opts != nil {
		o = *opts
	}
	ml := &ManagedLease{background: newBackground(), m: m, lease: lease, opts: o, clock: clockOr(o.Clock)}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		close(ml.done)
		return ml
	}
	m.managed[ml] = struct{}{}
	m.mu.Unlock()
	go ml.loop()
	return ml
}

func (m *LeaseManager) stopManaged(leaseID string) {
	m.mu.Lock()
	var hs []*ManagedLease
	for h := range m.managed {
		if h.lease.ID == leaseID {
			hs = append(hs, h)
		}
	}
	m.mu.Unlock()
	for _, h := range hs {
		h.Stop()
	}
}

// Close stops every managed lease (leases are not revoked). It is idempotent.
func (m *LeaseManager) Close() {
	m.mu.Lock()
	m.closed = true
	hs := make([]*ManagedLease, 0, len(m.managed))
	for h := range m.managed {
		hs = append(hs, h)
	}
	m.mu.Unlock()
	for _, h := range hs {
		h.Stop()
	}
}

func (ml *ManagedLease) loop() {
	defer func() {
		ml.m.mu.Lock()
		delete(ml.m.managed, ml)
		ml.m.mu.Unlock()
		close(ml.done)
	}()
	if ml.lease.Duration <= 0 {
		<-ml.ctx.Done()
		return
	}
	issued := ml.lease.IssuedAt
	if issued.IsZero() {
		issued = ml.clock.Now()
	}
	expiry := issued.Add(ml.lease.Duration)
	renewable := ml.lease.Renewable && ml.lease.ID != ""
	for renewable {
		if !ml.sleep(ml.clock, renewWait(ml.clock.Now(), expiry)) {
			return
		}
		info, err := ml.m.Renew(ml.ctx, ml.lease.ID, ml.opts.Increment)
		if err != nil {
			if ml.ctx.Err() != nil {
				return
			}
			if ml.opts.OnError != nil {
				safeCall(func() { ml.opts.OnError(err) })
			}
			if !isRetryable(err) {
				ml.expire()
				return
			}
			if !ml.clock.Now().Before(expiry) {
				break
			}
			continue
		}
		expiry = ml.clock.Now().Add(info.Duration)
		capped := info.Capped() || (ml.opts.Increment > 0 && info.Duration < ml.opts.Increment)
		renewable = info.Renewable && !capped && info.Duration > 0
		if ml.opts.OnRenew != nil {
			safeCall(func() { ml.opts.OnRenew(info) })
		}
	}
	if wait := expiry.Sub(ml.clock.Now()); wait > 0 && !ml.sleep(ml.clock, wait) {
		return
	}
	ml.expire()
}

func (ml *ManagedLease) expire() {
	if ml.opts.OnExpire != nil {
		safeCall(func() { ml.opts.OnExpire(ml.lease) })
	}
}
