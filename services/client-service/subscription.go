package clientservice

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buzzmean/neexitlag/core/controlclient"
)

const (
	subscriptionCheckInterval = 6 * time.Hour
	subscriptionRetryInterval = 10 * time.Minute
)

// SubscriptionView is what the GUI shows: a state and dates, nothing else.
// UNKNOWN until the control plane answered; UNMANAGED for installations
// without a code (never limited); ACTIVE or EXPIRED otherwise.
type SubscriptionView struct {
	State      string     `json:"state"`
	PaidUntil  *time.Time `json:"paid_until,omitempty"`
	GraceUntil *time.Time `json:"grace_until,omitempty"`
	CheckedAt  *time.Time `json:"checked_at,omitempty"`
}

// An ended subscription suspends optimization reversibly: identity, certificate
// and activation stay; paying again resumes without a new code or a restart.
// A network failure is never treated as an ended subscription.
type subscriptionRuntime struct {
	mu        sync.Mutex
	view      SubscriptionView
	suspended atomic.Bool
	resume    bool
	once      sync.Once
	wake      chan struct{}
}

func (s *subscriptionRuntime) wakeChannel() chan struct{} {
	s.once.Do(func() { s.wake = make(chan struct{}, 1) })
	return s.wake
}

// subscriptionRecheck asks the watcher for an immediate check, e.g. after the
// relay refused a ticket or when the user returns from paying.
func (c *Controller) subscriptionRecheck() {
	select {
	case c.subscription.wakeChannel() <- struct{}{}:
	default:
	}
}

func (c *Controller) subscriptionStatus() SubscriptionView {
	c.subscription.mu.Lock()
	defer c.subscription.mu.Unlock()
	out := c.subscription.view
	if out.State == "" {
		out.State = "UNKNOWN"
	}
	return out
}

func (c *Controller) handleSubscription(method string) (any, error) {
	if method == "subscription.refresh" {
		c.subscriptionRecheck()
	}
	return c.subscriptionStatus(), nil
}

type subscriptionSource interface {
	SubscriptionStatus(context.Context) (controlclient.SubscriptionStatus, error)
}

func (c *Controller) runSubscription(ctx context.Context, cp subscriptionSource) {
	wake := c.subscription.wakeChannel()
	for {
		checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		st, err := cp.SubscriptionStatus(checkCtx)
		cancel()
		next := subscriptionCheckInterval
		if err == nil {
			c.applySubscription(st, time.Now())
		} else if !errors.Is(err, controlclient.ErrNotSupported) {
			next = subscriptionRetryInterval
		}
		if c.subscription.suspended.Load() {
			next = subscriptionRetryInterval
		}
		timer := time.NewTimer(next)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (c *Controller) applySubscription(st controlclient.SubscriptionStatus, now time.Time) {
	view := SubscriptionView{State: "ACTIVE", PaidUntil: st.PaidUntil, GraceUntil: st.GraceUntil, CheckedAt: &now}
	expired := st.Enforced && !st.Active
	switch {
	case !st.Managed:
		view.State = "UNMANAGED"
	case expired:
		view.State = "EXPIRED"
	}
	c.subscription.mu.Lock()
	c.subscription.view = view
	c.subscription.mu.Unlock()
	if expired && !c.subscription.suspended.Load() {
		c.mu.Lock()
		wasEnabled := c.enabled
		c.mu.Unlock()
		c.subscription.mu.Lock()
		c.subscription.resume = wasEnabled
		c.subscription.mu.Unlock()
		// Block first so no automatic path can re-enable in between.
		c.subscription.suspended.Store(true)
		if wasEnabled {
			_, _ = c.Handle(c.ctx, "optimize", []byte(`{"enabled":false}`))
		} else {
			_ = c.CleanupOwnedBrowserPolicies()
		}
		return
	}
	if !expired && c.subscription.suspended.Load() {
		c.subscription.suspended.Store(false)
		c.subscription.mu.Lock()
		resume := c.subscription.resume
		c.subscription.resume = false
		c.subscription.mu.Unlock()
		_ = c.RestoreBrowserTransport()
		if resume {
			_, _ = c.Handle(c.ctx, "optimize", []byte(`{"enabled":true}`))
		}
	}
}
