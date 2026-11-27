package clientservice

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buzzmean/veliq/core/controlclient"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/routing"
	wp "github.com/buzzmean/veliq/platform/windows"
)

const personalLeaseMaximum = 60 * time.Second

// This opt-in test capability fences new optimization admission. It deliberately
// does not close already pinned user TCP streams or claim legacy-client fencing.
type personalLeaseRuntime struct {
	stage             atomic.Bool
	once              sync.Once
	opMu              sync.Mutex
	mu                sync.Mutex
	source            personalLeaseSource
	known, required   bool
	id                string
	deadline, renewAt time.Time
	generation        uint64
	state             string
	renewing          atomic.Bool
}

type personalLeaseSource interface {
	SubscriptionStatus(context.Context) (controlclient.SubscriptionStatus, error)
	OptimizationLease(context.Context, string, string) (controlclient.OptimizationLease, error)
}

type PersonalLeaseView struct {
	State     string     `json:"state"`
	Required  bool       `json:"required"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (c *Controller) configurePersonalLeaseStage(enabled bool) {
	// The installed manifest selects the test capability before activation and
	// browser recovery. No IPC method can disable it while optimization is active.
	if enabled {
		c.personalLease.stage.Store(true)
	}
}

func (c *Controller) setPersonalLeaseSource(source personalLeaseSource) {
	if !c.personalLease.stage.Load() {
		return
	}
	s := &c.personalLease
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	s.source = source
	s.known = false
	s.id = ""
	s.deadline = time.Time{}
	s.generation++
	s.state = "CHECKING"
	s.mu.Unlock()
}

func (c *Controller) personalLeaseView() *PersonalLeaseView {
	if !c.personalLease.stage.Load() {
		return nil
	}
	s := &c.personalLease
	s.mu.Lock()
	defer s.mu.Unlock()
	view := &PersonalLeaseView{State: s.state, Required: s.required}
	if view.State == "" {
		view.State = "CHECKING"
	}
	if !s.deadline.IsZero() {
		deadline := s.deadline
		view.ExpiresAt = &deadline
	}
	return view
}

func (c *Controller) personalLeaseNetworkAllowed(now time.Time) bool {
	if !c.personalLease.stage.Load() {
		return true
	}
	s := &c.personalLease
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.known && (!s.required || s.id != "" && now.Before(s.deadline))
}

func (c *Controller) personalLeaseOpenError(optimized bool) error {
	if optimized && !c.personalLeaseNetworkAllowed(time.Now()) {
		return errors.New("PERSONAL_LEASE_REQUIRED")
	}
	return nil
}

// Inspect the effective decision, not the fact that discovery found an EXE.
// Healthy DIRECT games, DNS, LAN and unselected OS traffic remain unchanged.
func (c *Controller) personalLeaseGateDecision(d wp.Decision) wp.Decision {
	if !c.personalLease.stage.Load() {
		return d
	}
	if resolve := d.ResolveDomain; resolve != nil {
		d.ResolveDomain = func(domain string) wp.Decision {
			return c.personalLeaseGateDecision(resolve(domain))
		}
	}
	optimized := d.Route.Local() || d.Route.RelayID != "" || d.GameUDP != nil || d.ProbeDirect ||
		d.Policy.Action == flowpolicy.DirectPlus || d.Policy.Action == flowpolicy.Relay || d.Policy.Action == flowpolicy.RelayRequired
	if optimized && !c.personalLeaseNetworkAllowed(time.Now()) {
		d.Block, d.BlockOnFailure = true, true
		d.Route = routing.Route{}
		d.Local, d.GameUDP, d.OpenDeferred, d.ResolveDomain = nil, nil, nil, nil
		d.Deferred, d.ProbeDirect = false, false
		d.Flow.PinnedPolicy = &routing.Policy{Block: true}
		d.Policy = flowpolicy.Result{Action: flowpolicy.Block, Fallback: flowpolicy.FailBlock, Source: "personal_lease_required", Reason: "personal optimization lease is not current"}
	}
	return d
}

func (c *Controller) applyPersonalLeasePolicy(policy controlclient.OptimizationLeasePolicy) {
	if !c.personalLease.stage.Load() {
		return
	}
	s := &c.personalLease
	s.mu.Lock()
	defer s.mu.Unlock()
	// An old server or malformed capabilities cannot silently downgrade an opted
	// in test installation to the legacy offline path.
	if !policy.Supported || policy.Required && (policy.TTLSeconds < 1 || policy.TTLSeconds > 60 || policy.RenewAfterSeconds < 1 || policy.RenewAfterSeconds >= policy.TTLSeconds) {
		s.known = false
		s.state = "UNSUPPORTED"
		return
	}
	s.known, s.required = true, policy.Required
	if !s.required {
		s.state = "NOT_REQUIRED"
	} else if s.id == "" {
		s.state = "REQUIRED"
	}
}

func personalLeaseDeadline(reply controlclient.OptimizationLease, started, now time.Time) (time.Time, error) {
	b, err := hex.DecodeString(reply.LeaseID)
	if err != nil || len(b) != 16 || hex.EncodeToString(b) != reply.LeaseID || !reply.Supported || !reply.Required || !reply.Granted || reply.ExpiresAt == nil || reply.ServerTime.IsZero() {
		return time.Time{}, errors.New("PERSONAL_LEASE_INVALID")
	}
	remaining := reply.ExpiresAt.Sub(reply.ServerTime)
	if remaining <= time.Second || remaining > personalLeaseMaximum {
		return time.Time{}, errors.New("PERSONAL_LEASE_INVALID")
	}
	// Use the monotonic request START, never response receipt or the local wall
	// clock, so network delay cannot extend access beyond server expiration.
	deadline := started.Add(remaining - time.Second)
	if !now.Before(deadline) {
		return time.Time{}, errors.New("PERSONAL_LEASE_EXPIRED")
	}
	return deadline, nil
}

func (c *Controller) ensurePersonalLease(ctx context.Context) error {
	if !c.personalLease.stage.Load() {
		return nil
	}
	s := &c.personalLease
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	cp, generation := s.source, s.generation
	s.mu.Unlock()
	if cp == nil {
		return errors.New("PERSONAL_LEASE_UNAVAILABLE")
	}
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	status, err := cp.SubscriptionStatus(check)
	if err != nil {
		return errors.New("PERSONAL_LEASE_UNAVAILABLE")
	}
	c.applyPersonalLeasePolicy(status.OptimizationLease)
	s.mu.Lock()
	known, required := s.known, s.required
	valid := s.id != "" && time.Now().Before(s.deadline)
	s.mu.Unlock()
	if !known {
		return errors.New("PERSONAL_LEASE_UNSUPPORTED")
	}
	if status.Enforced && !status.Active {
		return controlclient.ErrSubscriptionExpired
	}
	if !required || valid {
		return nil
	}
	started := time.Now()
	reply, err := cp.OptimizationLease(check, "acquire", "")
	if err != nil {
		return errors.New("PERSONAL_LEASE_UNAVAILABLE")
	}
	if !reply.Granted {
		switch reply.Reason {
		case "ACTIVE_ON_OTHER_DEVICE":
			return errors.New("PERSONAL_ACTIVE_ON_OTHER_DEVICE")
		case "SUBSCRIPTION_EXPIRED":
			return controlclient.ErrSubscriptionExpired
		case "LEASE_UNSUPPORTED":
			return errors.New("PERSONAL_LEASE_UNSUPPORTED")
		default:
			return errors.New("PERSONAL_LEASE_DENIED")
		}
	}
	deadline, err := personalLeaseDeadline(reply, started, time.Now())
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.generation != generation {
		return errors.New("PERSONAL_LEASE_CHANGED")
	}
	s.id, s.deadline, s.renewAt, s.state = reply.LeaseID, deadline, time.Now().Add(20*time.Second), "ACTIVE"
	return nil
}

// The caller stops capture and releases the browser authority before relinquishing
// admission. A failed release remains owned until server TTL; there is no takeover.
func (c *Controller) releasePersonalLease(ctx context.Context) {
	if !c.personalLease.stage.Load() {
		return
	}
	s := &c.personalLease
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	cp, id := s.source, s.id
	s.id = ""
	s.deadline = time.Time{}
	s.generation++
	if s.required && s.state != "EXPIRED" {
		s.state = "RELEASED"
	}
	s.mu.Unlock()
	if cp != nil && id != "" {
		bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		_, _ = cp.OptimizationLease(bounded, "release", id)
	}
}

func (c *Controller) renewPersonalLease(ctx context.Context) {
	s := &c.personalLease
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	cp, id, generation := s.source, s.id, s.generation
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		// A failing endpoint must not turn the quarter-second expiry check into
		// an unbounded renewal request loop.
		if s.generation == generation && s.id == id && s.renewAt.Before(time.Now().Add(5*time.Second)) {
			s.renewAt = time.Now().Add(5 * time.Second)
		}
	}()
	if cp == nil || id == "" {
		return
	}
	started := time.Now()
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	reply, err := cp.OptimizationLease(bounded, "renew", id)
	cancel()
	if err != nil {
		return
	}
	deadline, err := personalLeaseDeadline(reply, started, time.Now())
	if err != nil || reply.LeaseID != id {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.generation != generation || s.id != id || !time.Now().Before(s.deadline) {
		return
	}
	s.deadline, s.renewAt, s.state = deadline, time.Now().Add(20*time.Second), "ACTIVE"
}

func (c *Controller) expirePersonalLease(now time.Time) bool {
	s := &c.personalLease
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.id == "" || now.Before(s.deadline) {
		return false
	}
	s.id = ""
	s.generation++ // A late response must never re-open expired admission.
	s.state = "EXPIRED"
	return true
}

func (c *Controller) startPersonalLeaseWorker() {
	if !c.personalLease.stage.Load() {
		return
	}
	c.personalLease.once.Do(func() {
		c.wg.Add(1)
		go func() { defer c.wg.Done(); c.runPersonalLease(c.ctx) }()
	})
}

func (c *Controller) runPersonalLease(ctx context.Context) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if !c.personalLease.stage.Load() {
				continue
			}
			expired := c.expirePersonalLease(now)
			c.mu.Lock()
			enabled := c.enabled
			c.mu.Unlock()
			// Rebinding or an unsupported policy can clear admission without an
			// old lease ID. Never leave already enabled capture running in that gap.
			if expired || enabled && !c.personalLeaseNetworkAllowed(now) {
				_, _ = c.Handle(ctx, "optimize", []byte(`{"enabled":false}`))
				continue
			}
			s := &c.personalLease
			s.mu.Lock()
			due := s.id != "" && !now.Before(s.renewAt)
			s.mu.Unlock()
			if enabled && due && s.renewing.CompareAndSwap(false, true) {
				c.wg.Add(1)
				go func() { defer c.wg.Done(); defer s.renewing.Store(false); c.renewPersonalLease(ctx) }()
			}
		}
	}
}
