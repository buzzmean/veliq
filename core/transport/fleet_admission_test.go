package transport

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestFleetAdmissionOldAllowedCannotBecomeTokenZeroWarm(t *testing.T) {
	budget := &FleetBudget{}
	budget.SetEnabled(true)
	cfg := DefaultPoolConfig()
	cfg.FleetBudget = budget
	var factories atomic.Int32
	p, err := NewPool(context.Background(), cfg, func(context.Context) (*Client, error) {
		factories.Add(1)
		return nil, errors.New("unexpected fixture factory")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	entered, proceed := make(chan struct{}), make(chan struct{})
	a := NewFleetAdmission(p, nil, time.Now().Add(time.Second), func() bool { close(entered); <-proceed; return true })
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("allowed barrier missing")
	}
	if !a.Snapshot().Priority {
		t.Fatal("constructor did not reserve free-slot priority")
	}
	// No scheduler chance for the worker is needed to protect the last slot.
	var legacy []func()
	for range FleetSessionLimit - 1 {
		release, ok := budget.reserve(fleetSession)
		if !ok {
			t.Fatal("unreserved legacy slot was blocked")
		}
		legacy = append(legacy, release)
	}
	if got := budget.Snapshot().Sessions; got != FleetSessionLimit-1 {
		t.Fatalf("did not fill all unreserved session slots: %d", got)
	}
	if unexpected, ok := budget.reserve(fleetSession); ok {
		unexpected()
		t.Fatal("legacy stole constructor priority")
	}
	for _, release := range legacy {
		release()
	}
	cancelled := make(chan struct{})
	go func() { a.Cancel(); close(cancelled) }()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("client callback held a transport lock")
	}
	budget.SetEnabled(false)
	// A previously checked operation can arrive after Cancel cleared association.
	// Its captured token is mandatory even though ordinary feature-off capacity is free.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if s, err := p.acquireToken(ctx, false, a.token); err == nil {
		p.release(s)
		t.Fatal("stale admission token was accepted")
	}
	cancel()
	close(proceed)
	select {
	case <-a.Done():
	case <-time.After(time.Second):
		t.Fatal("old worker did not stop")
	}
	if factories.Load() != 0 || budget.Snapshot().Sessions != 0 {
		t.Fatal("old allowed result bootstrapped without its token")
	}
}
