package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/transport"
)

func TestFleetPoolsShareAdmissionAcrossConcurrentOpenFixtures(t *testing.T) {
	for _, starts := range []int{10, 40, 120} {
		t.Run(fmt.Sprint(starts), func(t *testing.T) {
			budget := &transport.FleetBudget{}
			cfg := transport.DefaultPoolConfig()
			cfg.FleetBudget = budget
			a := newPoolFixture(t, cfg, nil)
			b := newPoolFixture(t, cfg, nil)
			legacy := newPoolFixture(t, cfg, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := a.pool.Warm(ctx); err != nil {
				t.Fatal(err)
			}
			if err := b.pool.Warm(ctx); err != nil {
				t.Fatal(err)
			}
			previous, err := a.pool.OpenTCP(ctx, a.tcp)
			if err != nil {
				t.Fatal(err)
			}
			defer previous.Close()
			budget.SetEnabled(true)
			if err = legacy.pool.Warm(ctx); transport.FailureReason(err) != "fleet_session_capacity" || legacy.issued.Load() != 0 {
				t.Fatalf("legacy Warm bypassed shared session ceiling: %v", err)
			}
			assertTCPEcho(t, previous)

			type outcome struct {
				conn io.Closer
				err  error
			}
			results := make(chan outcome, starts)
			fire := make(chan struct{})
			var opens sync.WaitGroup
			for i := 0; i < starts; i++ {
				opens.Add(1)
				go func() {
					defer opens.Done()
					<-fire
					if i%2 == 0 {
						conn, err := a.pool.OpenFleetTCP(ctx, a.tcp)
						results <- outcome{conn, err}
					} else {
						flow, err := b.pool.OpenDatagram(ctx, b.udp)
						results <- outcome{flow, err}
					}
				}()
			}
			close(fire)
			opens.Wait()
			close(results)
			want := min(starts, transport.FleetApplicationLimit-1)
			var live []io.Closer
			var failures []error
			defer func() {
				for _, conn := range live {
					_ = conn.Close()
				}
			}()
			for r := range results {
				if r.err != nil {
					if !errors.Is(r.err, transport.ErrCapacity) {
						failures = append(failures, r.err)
					}
					continue
				}
				live = append(live, r.conn)
			}
			if len(failures) != 0 || len(live) != want {
				t.Fatalf("admitted %d/%d, unexpected failures %v", len(live), want, failures)
			}
			probe, err := b.pool.OpenProbeDatagram(ctx, b.udp)
			if err != nil {
				t.Fatalf("no reserved probe capacity at %d applications: %v", len(live)+1, err)
			}
			defer probe.Close()
			if _, err := a.pool.OpenProbeDatagram(ctx, a.udp); transport.FailureReason(err) != "fleet_stream_capacity" {
				t.Fatalf("second pool bypassed probe ceiling: %v", err)
			}
			if got := budget.Snapshot(); got.Sessions != 2 || got.Applications != want+1 || got.Probes != 1 || got.Waiting != 0 {
				t.Fatalf("unexpected shared occupancy: %+v", got)
			}
			b.pool.SetDraining(true)
			if _, err := b.pool.OpenFleetDatagram(ctx, b.udp); !errors.Is(err, transport.ErrCapacity) {
				t.Fatalf("draining pool admitted a new flow: %v", err)
			}
			assertTCPEcho(t, previous)
			for _, conn := range live {
				_ = conn.Close()
			}
			_ = probe.Close()
			_ = previous.Close()
			if got := budget.Snapshot(); got.Applications != 0 || got.Probes != 0 || got.Waiting != 0 {
				t.Fatalf("leaked application or probe permits: %+v", got)
			}
			_ = a.pool.Close()
			_ = b.pool.Close()
			if state := budget.Snapshot(); state != (transport.FleetOccupancy{Enabled: true}) {
				t.Fatalf("leaked session permits: %+v", state)
			}
			if err := legacy.pool.Warm(ctx); err != nil {
				t.Fatalf("legacy pool could not reuse released budget: %v", err)
			}
		})
	}
}

func TestFleetPoolCancelledOpenReturnsSharedWaiterAndApplication(t *testing.T) {
	budget := &transport.FleetBudget{}
	budget.SetEnabled(true)
	cfg := transport.DefaultPoolConfig()
	cfg.FleetBudget = budget
	started := make(chan struct{})
	pool, err := transport.NewPool(context.Background(), cfg, func(ctx context.Context) (*transport.Client, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := pool.OpenFleetTCP(ctx, netip.MustParseAddrPort("127.0.0.1:9443"))
		done <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("fixture session creation did not start")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled OPEN: %v", err)
	}
	if got := budget.Snapshot(); got.Applications != 0 || got.Waiting != 0 || got.Probes != 0 {
		t.Fatalf("cancellation leaked client reservations: %+v", got)
	}
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	if got := budget.Snapshot(); got.Sessions != 0 {
		t.Fatalf("session creation permit remained after close: %+v", got)
	}
}
