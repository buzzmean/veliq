package routing

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// AdaptiveUDP validates sustained DIRECT cadence without parsing media. It can
// transition once to required relay, never back. Previously sent media is not
// replayed; an atomic UDP Send error can retry that unsent datagram on the
// legacy relay. Fleet selection after an active DIRECT failure requires a new flow.
type AdaptiveUDP struct {
	mu                   sync.Mutex
	readMu               sync.Mutex
	current              Datagram
	e                    *Engine
	flow                 Flow
	relay                string
	health               udpCadence
	now                  func() time.Time
	deadline             time.Duration
	transitioned, closed bool
	reason               string
	fleetFailure         error
	fakeSends, fakes     int
}

// udpFakePayload is the zapret/Flowseal default UDP fake: 64 zero bytes. A
// voice server discards it; a stateful middlebox may classify the flow on it.
var udpFakePayload = make([]byte, 64)

// Caller holds mu. Fakes go only on the unconfirmed DIRECT socket, never on
// relay, and never count toward DIRECT health (they expect no reply).
func (d *AdaptiveUDP) sendFakePreludeLocked() {
	if d.transitioned || d.flow.UDPFakePrelude == 0 || d.fakeSends >= int(d.flow.UDPFakeCutoff) {
		return
	}
	d.fakeSends++
	for i := 0; i < int(d.flow.UDPFakePrelude) && i < 12; i++ {
		if d.current.Send(udpFakePayload) != nil {
			return
		}
		d.fakes++
	}
}

type udpHealthKey struct{ Application, Network, Destination string }
type udpHealth struct {
	relay   bool
	expires time.Time
}

func (e *Engine) udpCached(f Flow, now time.Time) bool {
	if f.Network == "" {
		return false
	}
	e.healthMu.Lock()
	defer e.healthMu.Unlock()
	k := udpHealthKey{f.ApplicationID, f.Network, f.Destination.String()}
	v := e.health[k]
	return v.relay && now.Before(v.expires)
}
func (e *Engine) udpObserved(f Flow, relay bool) {
	if f.Network == "" {
		return
	}
	e.healthMu.Lock()
	defer e.healthMu.Unlock()
	now := time.Now()
	for k, v := range e.health {
		if !now.Before(v.expires) {
			delete(e.health, k)
		}
	}
	k := udpHealthKey{f.ApplicationID, f.Network, f.Destination.String()}
	if len(e.health) < 1024 || !e.health[k].expires.IsZero() {
		e.health[k] = udpHealth{relay, now.Add(2 * time.Minute)}
	}
}
func (e *Engine) OpenAdaptiveUDP(ctx context.Context, f Flow, relay string, deadline time.Duration) (*AdaptiveUDP, error) {
	if relay == "" || deadline <= 0 || deadline > 10*time.Second {
		return nil, errors.New("invalid adaptive UDP bound")
	}
	f.Protocol = "udp"
	a := &AdaptiveUDP{e: e, flow: f, relay: relay, deadline: deadline}
	implicit := f.PinnedPolicy != nil && f.PinnedPolicy.ImplicitRelay
	if f.UDPFakePrelude > 0 {
		a.health.lenientReplies = 2
	}
	cached := e.udpCached(f, time.Now())
	f.PinnedPolicy = &Policy{}
	if cached {
		f.PinnedPolicy = &Policy{Route: Route{RelayID: relay}, BlockOnFailure: true, ImplicitRelay: implicit}
		a.transitioned = true
		a.reason = "LEARNED_RECENT_DIRECT_FAILURE"
		a.health.fallback(time.Now(), a.reason)
	}
	d, err := e.OpenUDP(ctx, f)
	if err != nil && !cached {
		f.PinnedPolicy = &Policy{Route: Route{RelayID: relay}, BlockOnFailure: true, ImplicitRelay: implicit}
		d, err = e.OpenUDP(ctx, f)
		a.transitioned = true
		a.reason = "DIRECT_OPEN_FAILED"
		a.health.fallback(time.Now(), a.reason)
		e.udpObserved(f, true)
	}
	if errors.Is(err, ErrFleetPolicy) {
		return nil, err
	}
	if err != nil {
		// A failed required-relay transition remains relay-only and retries future
		// traffic without resetting the direct-health/cache decision.
		if !a.transitioned {
			return nil, err
		}
		retryFlow := f
		d = &recoveringUDP{open: func(ctx context.Context) (Datagram, error) { return e.OpenUDP(ctx, retryFlow) }}
	}
	a.current = d
	return a, nil
}
func (d *AdaptiveUDP) Route() Route {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.transitioned {
		if route, ok := d.e.flowRoute(d.flow); ok {
			return route
		}
		return Route{RelayID: d.relay}
	}
	return Route{}
}
func (d *AdaptiveUDP) Reason() string { d.mu.Lock(); defer d.mu.Unlock(); return d.reason }
func (d *AdaptiveUDP) toRelayLocked(ctx context.Context, reason string) error {
	d.current.Close()
	d.transitioned = true // includes failed required-relay setup; never retry DIRECT
	d.reason = reason
	d.health.fallback(d.clock(), reason)
	d.e.udpObserved(d.flow, true)
	f := d.flow
	implicit := f.PinnedPolicy != nil && f.PinnedPolicy.ImplicitRelay
	f.PinnedPolicy = &Policy{Route: Route{RelayID: d.relay}, BlockOnFailure: true, ImplicitRelay: implicit}
	openCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	next, err := d.e.OpenUDP(WithExistingFlow(openCtx), f)
	if errors.Is(err, ErrFleetPolicy) {
		d.fleetFailure = err
		return err
	}
	if err != nil {
		d.current = &recoveringUDP{open: func(ctx context.Context) (Datagram, error) { return d.e.OpenUDP(ctx, f) }}
		return errors.Join(ErrUDPRecovering, err)
	}
	d.current = next
	return nil
}
func (d *AdaptiveUDP) Send(b []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errors.New("UDP flow closed")
	}
	if err := d.checkHealthLocked(context.Background()); err != nil {
		return err
	}
	d.sendFakePreludeLocked()
	err := d.current.Send(b)
	if err == nil && !d.transitioned {
		d.health.observe(d.clock(), false, len(b))
	}
	if err != nil && !d.transitioned {
		if err = d.toRelayLocked(context.Background(), "DIRECT_SEND_FAILED"); err == nil {
			err = d.current.Send(b)
		}
	}
	return err
}
func (d *AdaptiveUDP) Receive(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.readMu.Lock()
	defer d.readMu.Unlock()
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, errors.New("UDP flow closed")
	}
	if err := d.checkHealthLocked(ctx); err != nil {
		d.mu.Unlock()
		return nil, err
	}
	current := d.current
	monitor := !d.transitioned && !d.health.started.IsZero()
	until := d.clock().Add(udpHealthTick)
	if d.health.stateName() == DirectProbation && !d.health.started.IsZero() {
		bound := d.health.started.Add(d.deadline)
		if bound.Before(until) {
			until = bound
		}
	}
	d.mu.Unlock()
	readCtx := ctx
	cancel := func() {}
	if monitor {
		readCtx, cancel = context.WithDeadline(ctx, until)
	}
	b, err := current.Receive(readCtx)
	cancel()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, errors.New("UDP flow closed")
	}
	if current != d.current {
		return nil, context.DeadlineExceeded
	}
	if err == nil {
		if !d.transitioned {
			d.health.observe(d.clock(), true, len(b))
			// Return this real DIRECT datagram before any subsequent transition.
			confirmed, _ := d.health.check(d.clock(), d.deadline)
			if confirmed {
				d.e.udpObserved(d.flow, false)
			}
		}
		return b, nil
	}
	if ctx.Err() == context.Canceled {
		return nil, err
	}
	var networkError net.Error
	timeout := errors.Is(err, context.DeadlineExceeded) || errors.As(err, &networkError) && networkError.Timeout()
	if d.transitioned {
		if timeout {
			return nil, context.DeadlineExceeded
		}
		return nil, err
	}
	if timeout {
		if err = d.checkHealthLocked(ctx); err != nil {
			return nil, err
		}
		return nil, context.DeadlineExceeded
	}
	if err = d.toRelayLocked(ctx, "DIRECT_RECEIVE_FAILED"); err != nil {
		return nil, err
	}
	return nil, context.DeadlineExceeded
}
func (d *AdaptiveUDP) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return d.current.Close()
}

func (d *AdaptiveUDP) clock() time.Time {
	if d.now != nil {
		return d.now()
	}
	return time.Now()
}
func (d *AdaptiveUDP) Health() UDPHealthEvidence {
	d.mu.Lock()
	defer d.mu.Unlock()
	e := d.health.snapshot(d.clock())
	e.FakePrelude = d.fakes
	return e
}
func (d *AdaptiveUDP) checkHealthLocked(ctx context.Context) error {
	if d.fleetFailure != nil {
		return d.fleetFailure
	}
	if d.transitioned {
		return nil
	}
	confirmed, failure := d.health.check(d.clock(), d.deadline)
	if confirmed {
		d.e.udpObserved(d.flow, false)
	}
	if failure != "" {
		return d.toRelayLocked(ctx, failure)
	}
	return nil
}
