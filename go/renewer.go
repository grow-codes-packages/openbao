package openbao

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Clock abstracts time for TokenRenewer and LeaseManager so tests can use a fake.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time                         { return time.Now() }
func (systemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// SystemClock is the real clock.
var SystemClock Clock = systemClock{}

func clockOr(c Clock) Clock {
	if c == nil {
		return SystemClock
	}
	return c
}

// renewFraction is the share of the remaining TTL after which a renewal runs.
const renewFraction = 2.0 / 3.0

// minRenewWait keeps a failing renewal loop from spinning.
const minRenewWait = 100 * time.Millisecond

// renewAt returns how long to wait before renewing a lease that expires at expiry.
func renewWait(now, expiry time.Time) time.Duration {
	d := time.Duration(float64(expiry.Sub(now)) * renewFraction)
	if d < minRenewWait {
		d = minRenewWait
	}
	return d
}

// background is a stoppable goroutine owned by the client.
type background struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func newBackground() *background {
	ctx, cancel := context.WithCancel(context.Background()) //nolint:gosec // cancel is stored and called by Stop
	return &background{ctx: ctx, cancel: cancel, done: make(chan struct{})}
}

// Stop cancels the loop; it returns at once (wait on Done if needed) so it
// is safe to call from callbacks. It is idempotent.
func (b *background) Stop() { b.once.Do(b.cancel) }

// Done is closed when the loop has ended.
func (b *background) Done() <-chan struct{} { return b.done }

// sleep waits for d on clock; false when stopped.
func (b *background) sleep(clock Clock, d time.Duration) bool {
	select {
	case <-b.ctx.Done():
		return false
	case <-clock.After(d):
		return true
	}
}

// TokenRenewerOptions configure a TokenRenewer. Zero values use the defaults.
type TokenRenewerOptions struct {
	// Increment is the TTL requested on every renewal (0 = the token's default).
	Increment time.Duration
	// ReLogin logs in again with the method of the last Auth().Login when the
	// token can no longer be renewed (not renewable, max TTL reached or renewal
	// rejected). Without it, OnExpire is called when the token expires.
	ReLogin bool
	// OnRenew is called after every successful renewal or re-login.
	OnRenew func(info *AuthInfo)
	// OnError receives renewal and re-login errors; the loop keeps going while
	// the token is still valid.
	OnError func(err error)
	// OnExpire is called once when the token expires and cannot be renewed or
	// replaced; the renewer then stops.
	OnExpire func()
	// Clock replaces the real clock (tests).
	Clock Clock
}

// TokenRenewer keeps the client token alive: it renews at 2/3 of the
// remaining TTL, stops renewing when the token is not renewable or the max
// TTL caps the grant, and then re-logs in (ReLogin) or reports OnExpire.
type TokenRenewer struct {
	*background
	a     *Auth
	opts  TokenRenewerOptions
	clock Clock
}

// StartRenewer looks up the current token and starts renewing it in the
// background. Stop the renewer (or Close the client) to end it.
func (a *Auth) StartRenewer(ctx context.Context, opts *TokenRenewerOptions) (*TokenRenewer, error) {
	o := TokenRenewerOptions{}
	if opts != nil {
		o = *opts
	}
	ti, err := a.LookupSelf(ctx)
	if err != nil {
		return nil, err
	}
	r := &TokenRenewer{background: newBackground(), a: a, opts: o, clock: clockOr(o.Clock)}
	a.c.onClose(r.Stop)
	go r.loop(ti.TTL, ti.Renewable)
	return r, nil
}

func (r *TokenRenewer) emitError(err error) {
	if r.opts.OnError != nil {
		safeCall(func() { r.opts.OnError(err) })
	}
}

func (r *TokenRenewer) emitRenew(info *AuthInfo) {
	if r.opts.OnRenew != nil {
		safeCall(func() { r.opts.OnRenew(info) })
	}
}

func (r *TokenRenewer) loop(ttl time.Duration, renewable bool) {
	defer close(r.done)
	if ttl <= 0 {
		<-r.ctx.Done() // the token never expires: nothing to renew
		return
	}
	expiry := r.clock.Now().Add(ttl)
	for {
		if renewable {
			if !r.sleep(r.clock, renewWait(r.clock.Now(), expiry)) {
				return
			}
			info, err := r.a.RenewSelf(r.ctx, r.opts.Increment)
			switch {
			case err == nil:
				expiry = r.clock.Now().Add(info.LeaseDuration)
				capped := r.opts.Increment > 0 && info.LeaseDuration < r.opts.Increment
				renewable = info.Renewable && !capped && info.LeaseDuration > 0
				r.emitRenew(info)
			case r.ctx.Err() != nil:
				return
			default:
				r.emitError(err)
				if !isRetryable(err) {
					renewable = false
				} else if !r.clock.Now().Before(expiry) {
					renewable = false
				}
			}
			continue
		}
		method, _ := r.a.lastLogin()
		if r.opts.ReLogin && method != nil {
			if r.clock.Now().Before(expiry) && !r.sleep(r.clock, renewWait(r.clock.Now(), expiry)) {
				return
			}
			info, err := r.a.Login(r.ctx, method)
			if err == nil {
				expiry = r.clock.Now().Add(info.LeaseDuration)
				renewable = info.Renewable
				r.emitRenew(info)
				if info.LeaseDuration <= 0 {
					<-r.ctx.Done()
					return
				}
				continue
			}
			if r.ctx.Err() != nil {
				return
			}
			r.emitError(err)
			if isRetryable(err) && r.clock.Now().Before(expiry) {
				continue
			}
		}
		if wait := expiry.Sub(r.clock.Now()); wait > 0 && !r.sleep(r.clock, wait) {
			return
		}
		if r.opts.OnExpire != nil {
			safeCall(r.opts.OnExpire)
		}
		return
	}
}

func isRetryable(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Retryable
}
