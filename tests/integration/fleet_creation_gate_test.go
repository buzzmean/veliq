package integration

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/routing"
	"github.com/buzzmean/veliq/core/telemetry"
	"github.com/buzzmean/veliq/core/transport"
)

func TestFleetCreationDenyRejectsLateAuthenticatedFactory(t *testing.T) {
	for _, mode := range []string{"owned", "borrowed", "ownership-transfer"} {
		t.Run(mode, func(t *testing.T) {
			budget := &transport.FleetBudget{}
			budget.SetEnabled(true)
			cfg := transport.DefaultPoolConfig()
			cfg.FleetBudget = budget
			x := newPoolFixture(t, cfg, nil)
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			cancelled := make(chan struct{})
			var authenticated *transport.Client
			x.pool.UpdateFactory(func(ctx context.Context) (*transport.Client, error) {
				client, err := x.factory(ctx)
				if err != nil {
					return nil, err
				}
				authenticated = client
				close(entered)
				<-ctx.Done()
				close(cancelled)
				<-release // A deliberately late result must never publish.
				return client, nil
			}, false)
			x.pool.SetFleetAdmission(true, true, time.Now().Add(2*time.Second), mode != "borrowed")
			result := make(chan error, 1)
			go func() {
				c, err := x.pool.OpenFleetTCP(context.Background(), x.tcp)
				if c != nil {
					c.Close()
				}
				result <- err
			}()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("authenticated factory barrier missing")
			}
			x.pool.SetFleetAdmission(false, false, time.Time{}, mode == "owned")
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				t.Fatal("deny did not cancel pending setup")
			}
			if budget.Snapshot().Sessions != 1 {
				t.Fatal("in-flight creation stopped counting before completion")
			}
			for range 3 {
				if c, err := x.pool.OpenFleetTCP(context.Background(), x.tcp); err == nil {
					c.Close()
					t.Fatal("post-deny open admitted")
				}
				if d, err := x.pool.OpenFleetProbeDatagram(context.Background(), x.udp); err == nil {
					d.Close()
					t.Fatal("post-deny probe admitted")
				}
			}
			releaseOnce.Do(func() { close(release) })
			waitFleetAdmission(t, func() bool { return x.pool.Snapshot().CreatingSessions == 0 })
			select {
			case err := <-result:
				if !errors.Is(err, transport.ErrCapacity) {
					t.Fatal("unexpected rejection", err)
				}
			case <-time.After(time.Second):
				t.Fatal("open did not finish")
			}
			select {
			case <-authenticated.Done():
			default:
				t.Fatal("late authenticated client leaked")
			}
			if x.issued.Load() != 1 || x.pool.HasAdmittingSession() || budget.Snapshot().Sessions != 0 {
				t.Fatal("stale factory published or double-released its permit")
			}
		})
	}
}

func TestFleetCreationDeadlineCancelsSetupWithoutPolicyRefresh(t *testing.T) {
	cfg := transport.DefaultPoolConfig()
	x := newPoolFixture(t, cfg, nil)
	until := time.Now().Add(250 * time.Millisecond)
	entered, expired := make(chan struct{}), make(chan struct{})
	x.pool.UpdateFactory(func(ctx context.Context) (*transport.Client, error) {
		deadline, ok := ctx.Deadline()
		if !ok || deadline.After(until) {
			return nil, errors.New("factory context exceeds policy deadline")
		}
		client, err := x.factory(ctx)
		if err != nil {
			return nil, err
		}
		close(entered)
		<-ctx.Done()
		close(expired)
		return client, nil
	}, false)
	x.pool.SetFleetAdmission(true, true, until, true)
	result := make(chan error, 1)
	go func() { result <- x.pool.Warm(context.Background()) }()
	select {
	case <-entered:
	case err := <-result:
		t.Fatal("factory did not enter", err)
	case <-time.After(time.Second):
		t.Fatal("setup did not start")
	}
	select {
	case <-expired:
	case <-time.After(time.Second):
		t.Fatal("policy expiry did not cancel setup context")
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expired setup published")
		}
	case <-time.After(time.Second):
		t.Fatal("expired warm did not stop")
	}
	if x.pool.HasAdmittingSession() || x.issued.Load() != 1 {
		t.Fatal("expired authentication was retained or retried")
	}
}

func TestFleetProbeReuseSharesLegacyEchoBudget(t *testing.T) {
	budget := &transport.FleetBudget{}
	budget.SetEnabled(true)
	cfg := transport.DefaultPoolConfig()
	cfg.FleetBudget = budget
	x := newPoolFixture(t, cfg, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := x.pool.Warm(ctx); err != nil {
		t.Fatal(err)
	}
	x.pool.SetFleetAdmission(true, false, time.Now().Add(3*time.Second), true)
	for i := 0; i < transport.FleetEchoLimit; i++ {
		open := x.pool.OpenFleetProbeDatagram
		if i%2 == 0 {
			open = x.pool.OpenProbeDatagram
		}
		probe, err := open(ctx, x.udp)
		if err != nil {
			t.Fatal(err)
		}
		if err = probe.Send([]byte("bounded-echo")); err != nil {
			probe.Close()
			t.Fatal(err)
		}
		data, err := probe.Receive(ctx)
		probe.Close()
		if err != nil || string(data) != "bounded-echo" {
			t.Fatal("authenticated pool UDP reuse failed", err)
		}
	}
	for _, open := range []func(context.Context, netip.AddrPort) (routing.Datagram, error){x.pool.OpenProbeDatagram, x.pool.OpenFleetProbeDatagram} {
		probe, err := open(ctx, x.udp)
		if err != nil {
			t.Fatal(err)
		}
		err = probe.Send([]byte("over-budget"))
		probe.Close()
		if !errors.Is(err, transport.ErrCapacity) {
			t.Fatal("probe bypassed the shared rolling echo bound", err)
		}
	}
	if x.issued.Load() != 1 || budget.Snapshot().Sessions != 1 {
		t.Fatal("probe reuse opened another session")
	}
}

func TestFleetProbeDeadSessionIsIsolatedFromHealthyPeer(t *testing.T) {
	budget := &transport.FleetBudget{}
	budget.SetEnabled(true)
	cfg := transport.DefaultPoolConfig()
	cfg.FleetBudget = budget
	cfg.SessionFlows, cfg.ProbeReserve = 2, 1
	x := newPoolFixture(t, cfg, nil)
	x.pool.SetFleetAdmission(true, true, time.Now().Add(3*time.Second), true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	probe, err := x.pool.OpenFleetProbeDatagram(ctx, x.udp)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	peer, err := x.pool.OpenFleetTCP(ctx, x.tcp)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	x.pool.SetFleetAdmission(true, false, time.Now().Add(3*time.Second), true)
	x.mu.Lock()
	victim := x.clients[0]
	x.mu.Unlock()
	victim.Close()
	select {
	case <-victim.Done():
	case <-time.After(time.Second):
		t.Fatal("fixture session did not finish closing")
	}
	if err := probe.Send([]byte("dead-session")); !errors.Is(err, telemetry.ErrIsolatedSession) {
		t.Fatal("fleet probe send lost session isolation", err)
	}
	if _, err := probe.Receive(ctx); !errors.Is(err, telemetry.ErrIsolatedSession) {
		t.Fatal("fleet probe receive lost session isolation", err)
	}
	assertTCPEcho(t, peer)
	if x.issued.Load() != 2 {
		t.Fatal("probe failure dialed a replacement")
	}
}
