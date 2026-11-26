package clientservice

import (
	"context"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/transport"
)

func TestFleetPrepublishedPoolReuseTransfersOnlyExactLegacyOwnership(t *testing.T) {
	for _, same := range []bool{true, false} {
		t.Run(map[bool]string{true: "same-address", false: "changed-address"}[same], func(t *testing.T) {
			c := New(context.Background())
			defer c.Close()
			c.fleet.arm("fixture")
			started, cancelled := make(chan struct{}), make(chan struct{})
			cfg := transport.DefaultPoolConfig()
			cfg.FleetBudget = &c.fleet.budget
			managed, err := transport.NewPool(context.Background(), cfg, func(ctx context.Context) (*transport.Client, error) {
				close(started)
				<-ctx.Done()
				close(cancelled)
				return nil, ctx.Err()
			})
			if err != nil {
				t.Fatal(err)
			}
			defer managed.Close()
			warmCtx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			go managed.Warm(warmCtx)
			awaitFleetSetup(t, started)
			s := &remoteState{controller: c, clients: map[string]*transport.Pool{}, addresses: map[string]string{}, fleet: &remoteFleet{pools: map[string]remoteFleetPool{"FI": {pool: managed, address: "127.0.0.1:9443", owned: true}}}}
			defer s.close()
			address := "127.0.0.1:9443"
			if !same {
				address = "127.0.0.1:9444"
			}
			if err = s.apply(context.Background(), security.Config{Relays: []optimizer.RelayCandidate{{ID: "FI", Address: address}}}); err != nil {
				t.Fatal(err)
			}
			if reused := s.clients["FI"] == managed; reused != same {
				t.Fatal("ID/address ownership did not match", reused, same)
			}
			if s.fleet.pools["FI"].owned == same {
				t.Fatal("legacy did not take ownership only for exact same pool")
			}
			if c.fleet.budget.Snapshot().Sessions != 1 {
				t.Fatal("reuse charged a second permit")
			}
			if err = s.applyFleetPolicy(security.FleetPolicy{Version: 1, Enabled: true, ExpiresAt: time.Now().Add(time.Minute)}, time.Now()); err != nil {
				t.Fatal(err)
			}
			if same {
				select {
				case <-cancelled:
					t.Fatal("fleet withdraw closed shared legacy provider")
				default:
				}
				if managed.Snapshot().CreatingSessions != 1 || c.relayPools["FI"] != managed {
					t.Fatal("shared legacy pool was retired")
				}
			} else if c.relayPools["FI"] == managed {
				t.Fatal("address changed legacy still points to retired managed pool")
			}
		})
	}
}
