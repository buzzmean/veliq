package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/routing"
	"github.com/buzzmean/veliq/core/transport"
)

func waitFleetAdmission(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatal("bounded fleet admission condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func busyFleetDonor(t *testing.T, budget *transport.FleetBudget, renew bool) (*poolFixture, net.Conn, routing.Datagram, net.Conn) {
	t.Helper()
	cfg := transport.DefaultPoolConfig()
	cfg.FleetBudget = budget
	cfg.MaxSessions = 2
	cfg.SessionFlows = 3
	lease := time.Duration(0)
	if renew {
		lease = 3 * time.Second
	}
	x := newRenewingPoolFixture(t, cfg, nil, lease)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a, err := x.pool.OpenTCP(ctx, x.tcp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	u, err := x.pool.OpenDatagram(ctx, x.udp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	b, err := x.pool.OpenTCP(ctx, x.tcp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return x, a, u, b
}

// occupyOtherFleetSlots supplies unrelated, authenticated pools so the old
// handoff cases exercise the shared ceiling rather than a two-session constant.
// No application or probe permits are consumed by these warm sessions.
func occupyOtherFleetSlots(t *testing.T, budget *transport.FleetBudget, slots int) func() {
	t.Helper()
	var pools []*transport.Pool
	closePools := func() {
		for _, p := range pools {
			_ = p.Close()
		}
	}
	t.Cleanup(closePools)
	for range slots {
		cfg := transport.DefaultPoolConfig()
		cfg.FleetBudget = budget
		cfg.MaxSessions = 1
		x := newPoolFixture(t, cfg, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := x.pool.Warm(ctx)
		cancel()
		if err != nil {
			t.Fatal("could not occupy shared session fixture", err)
		}
		pools = append(pools, x.pool)
	}
	return closePools
}

func fleetUDPEcho(t *testing.T, d routing.Datagram) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := d.Send([]byte("pinned-UDP")); err != nil {
		t.Fatal(err)
	}
	data, err := d.Receive(ctx)
	if err != nil || string(data) != "pinned-UDP" {
		t.Fatal("pinned datagram failed", err)
	}
}

func TestFleetSelectiveHandoffPreservesBusyTCPUDPAndRenewal(t *testing.T) {
	budget := &transport.FleetBudget{}
	legacy, tcp, udp, other := busyFleetDonor(t, budget, true)
	closeFillers := occupyOtherFleetSlots(t, budget, transport.FleetSessionLimit-2)
	cfg := transport.DefaultPoolConfig()
	cfg.FleetBudget = budget
	target := newRenewingPoolFixture(t, cfg, nil, 3*time.Second)
	budget.SetEnabled(true)
	plan := transport.NewFleetAdmission(target.pool, []*transport.Pool{legacy.pool}, time.Now().Add(10*time.Second), nil)
	defer plan.Cancel()
	waitFleetAdmission(t, func() bool { return plan.Snapshot().State == "WAITING_EXISTING_LEASES" })
	before := plan.Snapshot()
	if before.ExistingLeases != 2 || before.VictimSession != 1 || !before.Priority {
		t.Fatalf("unsafe victim: %+v", before)
	}
	for range 3 {
		if !plan.Refresh(time.Now().Add(10 * time.Second)) {
			t.Fatal("same policy lost its plan")
		}
		if plan.Snapshot().VictimSession != before.VictimSession {
			t.Fatal("victim moved on refresh")
		}
	}
	assertTCPEcho(t, tcp)
	assertTCPEcho(t, other)
	fleetUDPEcho(t, udp)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	newLegacy, err := legacy.pool.OpenTCP(ctx, legacy.tcp)
	if err != nil {
		t.Fatal("alternative admission lost", err)
	}
	defer newLegacy.Close()
	assertTCPEcho(t, newLegacy)
	waitFleetAdmission(t, func() bool { return legacy.server.Metrics.Renewals.Load() >= 2 })
	assertTCPEcho(t, tcp)
	fleetUDPEcho(t, udp)
	if target.issued.Load() != 0 || budget.Snapshot().Sessions != transport.FleetSessionLimit {
		t.Fatal("busy leases were bypassed")
	}
	stop := make(chan struct{})
	var storm sync.WaitGroup
	for range 4 {
		storm.Add(1)
		go func() {
			defer storm.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				attempt, end := context.WithTimeout(context.Background(), 50*time.Millisecond)
				_ = legacy.pool.Warm(attempt)
				end()
			}
		}()
	}
	tcp.Close()
	udp.Close()
	waitFleetAdmission(t, func() bool { return target.pool.HasAdmittingSession() })
	close(stop)
	storm.Wait()
	if legacy.issued.Load() != 2 || target.issued.Load() != 1 || budget.Snapshot().Sessions != transport.FleetSessionLimit {
		t.Fatalf("priority or shared session ceiling violated: legacy%d target%d %+v", legacy.issued.Load(), target.issued.Load(), budget.Snapshot())
	}
	assertTCPEcho(t, other)
	assertTCPEcho(t, newLegacy)
	managedContext, stopManaged := context.WithTimeout(context.Background(), time.Second)
	defer stopManaged()
	managed, err := target.pool.OpenFleetTCP(managedContext, target.tcp)
	if err != nil {
		t.Fatal(err)
	}
	assertTCPEcho(t, managed)
	managed.Close()
	newLegacy.Close()
	other.Close()
	tcp.Close()
	udp.Close()
	legacy.pool.Close()
	target.pool.Close()
	closeFillers()
	if got := budget.Snapshot(); got != (transport.FleetOccupancy{Enabled: true}) {
		t.Fatalf("release was not exactly once: %+v", got)
	}
}

func TestFleetSelectiveHandoffCancellationRestoresAdmission(t *testing.T) {
	for _, mode := range []string{"cancel", "off", "expiry", "guard", "target-close"} {
		t.Run(mode, func(t *testing.T) {
			budget := &transport.FleetBudget{}
			legacy, tcp, udp, other := busyFleetDonor(t, budget, false)
			occupyOtherFleetSlots(t, budget, transport.FleetSessionLimit-2)
			cfg := transport.DefaultPoolConfig()
			cfg.FleetBudget = budget
			target := newPoolFixture(t, cfg, nil)
			budget.SetEnabled(true)
			var valid atomic.Bool
			valid.Store(true)
			until := time.Now().Add(3 * time.Second)
			if mode == "expiry" {
				until = time.Now().Add(250 * time.Millisecond)
			}
			plan := transport.NewFleetAdmission(target.pool, []*transport.Pool{legacy.pool}, until, valid.Load)
			defer plan.Cancel()
			waitFleetAdmission(t, func() bool { return plan.Snapshot().State == "WAITING_EXISTING_LEASES" })
			switch mode {
			case "cancel":
				plan.Cancel()
			case "off":
				budget.SetEnabled(false)
			case "guard":
				valid.Store(false)
			case "target-close":
				target.pool.Close()
			}
			waitFleetAdmission(t, func() bool {
				select {
				case <-plan.Done():
					return true
				default:
					return false
				}
			})
			for _, s := range legacy.pool.Snapshot().Sessions {
				if s.AdmissionFenced || s.Draining {
					t.Fatal("cancel became permanent drain")
				}
			}
			assertTCPEcho(t, tcp)
			assertTCPEcho(t, other)
			fleetUDPEcho(t, udp)
			if target.issued.Load() != 0 {
				t.Fatal("cancelled policy issued target session")
			}
		})
	}
}

func TestFleetSelectiveHandoffDoesNotFenceSoleUnrelatedPools(t *testing.T) {
	budget := &transport.FleetBudget{}
	cfg := transport.DefaultPoolConfig()
	cfg.FleetBudget = budget
	a := newPoolFixture(t, cfg, nil)
	b := newPoolFixture(t, cfg, nil)
	target := newPoolFixture(t, cfg, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	one, err := a.pool.OpenTCP(ctx, a.tcp)
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	two, err := b.pool.OpenDatagram(ctx, b.udp)
	if err != nil {
		t.Fatal(err)
	}
	defer two.Close()
	occupyOtherFleetSlots(t, budget, transport.FleetSessionLimit-2)
	budget.SetEnabled(true)
	plan := transport.NewFleetAdmission(target.pool, []*transport.Pool{a.pool, b.pool}, time.Now().Add(time.Second), nil)
	defer plan.Cancel()
	time.Sleep(150 * time.Millisecond)
	if got := plan.Snapshot(); got.State != "WAITING_NATURAL_SESSION_RELEASE" || !got.Priority || got.VictimSession != 0 {
		t.Fatalf("sole exact providers were damaged: %+v", got)
	}
	assertTCPEcho(t, one)
	fleetUDPEcho(t, two)
	if target.issued.Load() != 0 || budget.Snapshot().Sessions != transport.FleetSessionLimit {
		t.Fatal("infinite leases were reported as progress")
	}
}

func TestFleetSelectiveHandoffRejectsStaleFactoryAndOldCancel(t *testing.T) {
	budget := &transport.FleetBudget{}
	budget.SetEnabled(true)
	cfg := transport.DefaultPoolConfig()
	cfg.FleetBudget = budget
	target := newPoolFixture(t, cfg, nil)
	started, finish := make(chan struct{}), make(chan struct{})
	target.pool.UpdateFactory(func(ctx context.Context) (*transport.Client, error) {
		c, err := target.factory(ctx)
		if err != nil {
			return nil, err
		}
		close(started)
		<-finish
		return c, nil
	}, false)
	old := transport.NewFleetAdmission(target.pool, nil, time.Now().Add(3*time.Second), nil)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("factory did not authenticate")
	}
	old.Cancel()
	target.pool.UpdateFactory(target.factory, false)
	next := transport.NewFleetAdmission(target.pool, nil, time.Now().Add(3*time.Second), nil)
	defer next.Cancel()
	close(finish)
	old.Cancel()
	waitFleetAdmission(t, func() bool { return target.pool.HasAdmittingSession() })
	if target.issued.Load() != 2 || len(target.pool.Snapshot().Sessions) != 1 || budget.Snapshot().Sessions != 1 {
		t.Fatal("stale factory consumed/published the new plan")
	}
	target.mu.Lock()
	oldClient := target.clients[0]
	target.mu.Unlock()
	select {
	case <-oldClient.Done():
	default:
		t.Fatal("old token published authenticated client")
	}
}

func TestFleetSelectiveHandoffRestoresSoleLegacyAfterAlternativeDies(t *testing.T) {
	for _, mode := range []string{"blocked-target", "failed-target"} {
		t.Run(mode, func(t *testing.T) {
			budget := &transport.FleetBudget{}
			legacy, tcp, udp, _ := busyFleetDonor(t, budget, false)
			occupyOtherFleetSlots(t, budget, transport.FleetSessionLimit-2)
			cfg := transport.DefaultPoolConfig()
			cfg.FleetBudget = budget
			target := newPoolFixture(t, cfg, nil)
			started := make(chan struct{})
			var once sync.Once
			target.pool.UpdateFactory(func(ctx context.Context) (*transport.Client, error) {
				once.Do(func() { close(started) })
				if mode == "blocked-target" {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return nil, errors.New("fixture unavailable")
			}, false)
			budget.SetEnabled(true)
			plan := transport.NewFleetAdmission(target.pool, []*transport.Pool{legacy.pool}, time.Now().Add(3*time.Second), nil)
			defer plan.Cancel()
			waitFleetAdmission(t, func() bool { return plan.Snapshot().VictimSession == 1 })
			legacy.mu.Lock()
			alternative := legacy.clients[1]
			legacy.mu.Unlock()
			alternative.Close()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("freed slot was not offered to target")
			}
			assertTCPEcho(t, tcp)
			fleetUDPEcho(t, udp)
			udp.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := legacy.pool.OpenTCP(ctx, legacy.tcp)
			if err != nil {
				t.Fatal("live sole exact provider remained fenced", err)
			}
			defer conn.Close()
			assertTCPEcho(t, conn)
			for _, s := range legacy.pool.Snapshot().Sessions {
				if s.AdmissionFenced {
					t.Fatal("sole legacy session still fenced")
				}
			}
			if budget.Snapshot().Sessions > transport.FleetSessionLimit {
				t.Fatal("restoration exceeded shared budget")
			}
		})
	}
}

func TestFleetFutureSlotClaimBeatsLegacyNaturalRetirementStorm(t *testing.T) {
	budget := &transport.FleetBudget{}
	cfg := transport.DefaultPoolConfig()
	cfg.FleetBudget = budget
	a := newPoolFixture(t, cfg, nil)
	b := newPoolFixture(t, cfg, nil)
	target := newPoolFixture(t, cfg, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	first, err := a.pool.OpenTCP(ctx, a.tcp)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	other, err := b.pool.OpenTCP(ctx, b.tcp)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	occupyOtherFleetSlots(t, budget, transport.FleetSessionLimit-2)
	budget.SetEnabled(true)
	plan := transport.NewFleetAdmission(target.pool, []*transport.Pool{a.pool, b.pool}, time.Now().Add(3*time.Second), nil)
	defer plan.Cancel()
	waitFleetAdmission(t, func() bool { return plan.Snapshot().State == "WAITING_NATURAL_SESSION_RELEASE" })
	if !plan.Snapshot().Priority || plan.Snapshot().VictimSession != 0 {
		t.Fatal("future slot was not reserved independently of safe fence")
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	// External factory rotation retires only the old endpoint; the application
	// lease still lives until Close. Re-creation must lose to the pending claim.
	a.pool.UpdateFactory(a.factory, true)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				attempt, end := context.WithTimeout(ctx, 50*time.Millisecond)
				_ = a.pool.Warm(attempt)
				end()
			}
		}()
	}
	assertTCPEcho(t, first)
	assertTCPEcho(t, other)
	first.Close()
	waitFleetAdmission(t, func() bool { return target.pool.HasAdmittingSession() })
	close(stop)
	wg.Wait()
	if a.issued.Load() != 1 || target.issued.Load() != 1 || budget.Snapshot().Sessions != transport.FleetSessionLimit {
		t.Fatal("legacy re-creation stole naturally released slot")
	}
	assertTCPEcho(t, other)
}

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
			closeFillers := occupyOtherFleetSlots(t, budget, transport.FleetSessionLimit-2)
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
			if got := budget.Snapshot(); got.Sessions != transport.FleetSessionLimit || got.Applications != want+1 || got.Probes != 1 || got.Waiting != 0 {
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
			closeFillers()
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

// Real QUIC/mTLS regression for hot opt-in with the three occupied legacy
// sessions observed in the field. Increasing the session ceiling does not
// require closing, moving, or fencing any existing TCP/UDP lease.
func TestFleetHotEnableAdmitsManagedAlongsideThreeBusyLegacySessions(t *testing.T) {
	budget := &transport.FleetBudget{}
	cfg := transport.DefaultPoolConfig()
	cfg.FleetBudget = budget
	cfg.MaxSessions = 1
	one := newPoolFixture(t, cfg, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	first, err := one.pool.OpenTCP(ctx, one.tcp)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	legacy, tcp, udp, other := busyFleetDonor(t, budget, false)
	if got := budget.Snapshot(); got.Enabled || got.Sessions != 3 || got.Applications != 4 {
		t.Fatalf("fixture is not the three busy feature-off sessions: %+v", got)
	}
	cfg.MaxSessions = 1
	target := newPoolFixture(t, cfg, nil)
	budget.SetEnabled(true)
	plan := transport.NewFleetAdmission(target.pool, []*transport.Pool{one.pool, legacy.pool}, time.Now().Add(3*time.Second), nil)
	defer plan.Cancel()
	waitFleetAdmission(t, func() bool { return target.pool.HasAdmittingSession() })
	if got := budget.Snapshot(); got.Sessions != 4 || got.Applications != 4 {
		t.Fatalf("new managed session did not coexist with old leases: %+v", got)
	}
	if plan.Snapshot().VictimSession != 0 || one.issued.Load() != 1 || legacy.issued.Load() != 2 || target.issued.Load() != 1 {
		t.Fatal("hot opt-in replaced or fenced an existing session", plan.Snapshot())
	}
	for _, p := range []*transport.Pool{one.pool, legacy.pool} {
		for _, s := range p.Snapshot().Sessions {
			if s.Draining || s.AdmissionFenced {
				t.Fatal("old busy session was drained instead of retained")
			}
		}
	}
	assertTCPEcho(t, first)
	assertTCPEcho(t, tcp)
	assertTCPEcho(t, other)
	fleetUDPEcho(t, udp)
	managed, err := target.pool.OpenFleetTCP(ctx, target.tcp)
	if err != nil {
		t.Fatal("managed application OPEN failed", err)
	}
	defer managed.Close()
	assertTCPEcho(t, managed)
	budget.SetEnabled(false)
	assertTCPEcho(t, first)
	assertTCPEcho(t, tcp)
	assertTCPEcho(t, managed)
	fleetUDPEcho(t, udp)
}

func TestFleetSixRelayPoolsAndTwoExtraSessionsKeepBoundedCeiling(t *testing.T) {
	budget := &transport.FleetBudget{}
	budget.SetEnabled(true)
	cfg := transport.DefaultPoolConfig()
	cfg.FleetBudget = budget
	cfg.MaxSessions = 3
	cfg.SessionFlows = 2
	primary := newPoolFixture(t, cfg, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var busy []net.Conn
	for range 3 {
		c, err := primary.pool.OpenTCP(ctx, primary.tcp)
		if err != nil {
			t.Fatal(err)
		}
		busy = append(busy, c)
		t.Cleanup(func() { c.Close() })
	}
	// Five other relay pools plus three demanded primary sessions exercise
	// six distinct authenticated endpoints and the two spare session slots.
	closeOthers := occupyOtherFleetSlots(t, budget, 5)
	if got := budget.Snapshot(); got.Sessions != 8 {
		t.Fatalf("six-node plus spare-session ceiling changed: %+v", got)
	}
	ninth := newPoolFixture(t, cfg, nil)
	if err := ninth.pool.Warm(ctx); transport.FailureReason(err) != "fleet_session_capacity" || ninth.issued.Load() != 0 {
		t.Fatalf("ninth session reached factory or bypassed client ceiling: %v", err)
	}
	for _, c := range busy {
		assertTCPEcho(t, c)
	}
	closeOthers()
	if err := ninth.pool.Warm(ctx); err != nil || ninth.issued.Load() != 1 {
		t.Fatal("naturally released capacity was not reusable", err)
	}
	for _, c := range busy {
		assertTCPEcho(t, c)
		c.Close()
	}
	primary.pool.Close()
	ninth.pool.Close()
	if got := budget.Snapshot(); got != (transport.FleetOccupancy{Enabled: true}) {
		t.Fatalf("session/application permits were not refunded exactly: %+v", got)
	}
}
