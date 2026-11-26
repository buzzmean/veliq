package clientservice

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/transport"
)

func awaitFleetSetup(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("fleet setup barrier not reached")
	}
}

func TestFleetAdmissionPolicyPrecedesBootstrapAndRefreshKeepsPlan(t *testing.T) {
	f := newRelayFleet(func() string { return "network" })
	f.arm("fixture")
	started, cancelled := make(chan struct{}), make(chan struct{})
	var ready atomic.Bool
	cfg := transport.DefaultPoolConfig()
	cfg.FleetBudget = &f.budget
	pool, err := transport.NewPool(context.Background(), cfg, func(ctx context.Context) (*transport.Client, error) {
		ready.Store(f.probeAllowed("FI", "fixture-address", time.Now()))
		close(started)
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	defer f.suspend()
	now := time.Now()
	node := fleetNode{id: "FI", address: "fixture-address", weight: 1, observed: now, pool: pool}
	f.configure(1, now.Add(time.Minute), true, []fleetNode{node}, "")
	awaitFleetSetup(t, started)
	if !ready.Load() {
		t.Fatal("session bootstrap preceded authenticated policy binding")
	}
	f.mu.Lock()
	plan := f.admission
	f.mu.Unlock()
	for i := uint64(2); i < 6; i++ {
		node.observed = time.Now()
		f.configure(i, time.Now().Add(time.Minute), true, []fleetNode{node}, "")
		f.mu.Lock()
		same := f.admission == plan
		f.mu.Unlock()
		if !same {
			t.Fatal("same target refresh replaced admission plan")
		}
	}
	status := f.snapshot(time.Now())
	if status["reason"] == "policy_ready" || status["admission"].(transport.FleetAdmissionSnapshot).State == "READY" {
		t.Fatal("policy parsed was represented as session accepted")
	}
	if got := f.budget.Snapshot(); got.Sessions != 1 {
		t.Fatalf("creating not counted: %+v", got)
	}
	f.configure(6, time.Now().Add(time.Minute), false, nil, "")
	awaitFleetSetup(t, cancelled)
	awaitFleetSetup(t, plan.Done())
}

func TestFleetAdmissionCancelsOnFreshnessNetworkAndCandidateChange(t *testing.T) {
	for _, mode := range []string{"policy-expiry", "load-expiry", "network", "removed", "address"} {
		t.Run(mode, func(t *testing.T) {
			var network atomic.Value
			network.Store("network1")
			f := newRelayFleet(func() string { return network.Load().(string) })
			f.arm("fixture")
			started, cancelled := make(chan struct{}), make(chan struct{})
			cfg := transport.DefaultPoolConfig()
			cfg.FleetBudget = &f.budget
			pool, err := transport.NewPool(context.Background(), cfg, func(ctx context.Context) (*transport.Client, error) {
				close(started)
				<-ctx.Done()
				close(cancelled)
				return nil, ctx.Err()
			})
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			defer f.suspend()
			now := time.Now()
			until := now.Add(time.Minute)
			observed := now
			if mode == "policy-expiry" {
				until = now.Add(250 * time.Millisecond)
			}
			if mode == "load-expiry" {
				observed = now.Add(-fleetLoadTTL + 250*time.Millisecond)
			}
			node := fleetNode{id: "FI", address: "address1", weight: 1, observed: observed, pool: pool}
			f.configure(1, until, true, []fleetNode{node}, "")
			awaitFleetSetup(t, started)
			f.mu.Lock()
			plan := f.admission
			f.mu.Unlock()
			switch mode {
			case "network":
				network.Store("network2")
			case "removed":
				f.configure(2, until, true, nil, "empty")
			case "address":
				node.address = "address2"
				node.pool = nil
				f.configure(2, until, true, []fleetNode{node}, "")
			}
			awaitFleetSetup(t, cancelled)
			awaitFleetSetup(t, plan.Done())
			if plan.Snapshot().Priority {
				t.Fatal("cancel retained slot priority")
			}
		})
	}
}

func TestFleetStatusReadsCannotRestartOrBootstrapAdmission(t *testing.T) {
	f := newRelayFleet(func() string { return "network" })
	f.arm("fixture")
	var calls atomic.Int32
	started := make(chan struct{})
	cfg := transport.DefaultPoolConfig()
	cfg.FleetBudget = &f.budget
	first, err := transport.NewPool(context.Background(), cfg, func(ctx context.Context) (*transport.Client, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := transport.NewPool(context.Background(), cfg, func(context.Context) (*transport.Client, error) { calls.Add(100); return nil, context.Canceled })
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	defer f.suspend()
	now := time.Now()
	f.configure(1, now.Add(time.Minute), true, []fleetNode{{id: "FI", address: "one", weight: 1, observed: now, pool: first}, {id: "NL", address: "two", weight: 1, observed: now, pool: second}}, "")
	awaitFleetSetup(t, started)
	f.mu.Lock()
	plan := f.admission
	f.mu.Unlock()
	plan.Cancel()
	awaitFleetSetup(t, plan.Done())
	for range 100 {
		_ = f.snapshot(time.Now())
	}
	f.mu.Lock()
	unchanged := f.admission == plan
	f.mu.Unlock()
	if !unchanged || calls.Load() != 1 {
		t.Fatal("read-only fleet status changed admission or created sessions", calls.Load())
	}
}
