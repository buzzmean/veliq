package clientservice

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/routing"
	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/transport"
)

func primarySelectionFixture(t *testing.T) (*primaryRelayProvider, *primaryFixture, *primaryFixture, *time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 24, 1, 0, 0, 0, time.UTC)
	a, b := &primaryFixture{healthy: true}, &primaryFixture{healthy: true}
	r := newRelayPrimary()
	p := &primaryRelayProvider{primary: a, standby: b, primaryAddress: "146.0.77.98:4433", standbyAddress: "2.56.177.4:4433", runtime: r, now: func() time.Time { return now }}
	r.configure(p, p.primaryAddress, p.standbyAddress)
	t.Cleanup(func() {
		for _, f := range []*primaryFixture{a, b} {
			for _, c := range f.peers {
				c.Close()
			}
		}
	})
	return p, a, b, &now
}
func firstRelay(p *primaryRelayProvider) string { _, id, _, _, _, _ := p.order(); return id }

func TestPrimaryHysteresisRecoveryAndHealthFlap(t *testing.T) {
	p, a, _, now := primarySelectionFixture(t)
	if firstRelay(p) != primaryRelayID {
		t.Fatal("initial primary")
	}
	a.healthy = false
	if firstRelay(p) != "VPS-01" {
		t.Fatal("failure did not select standby")
	}
	a.healthy = true
	*now = now.Add(time.Second)
	if firstRelay(p) != "VPS-01" {
		t.Fatal("returned before confirmation")
	}
	*now = now.Add(29 * time.Second)
	if firstRelay(p) != "VPS-01" {
		t.Fatal("not 30 continuous seconds")
	}
	a.healthy = false
	firstRelay(p)
	a.healthy = true
	*now = now.Add(time.Second)
	firstRelay(p)
	*now = now.Add(30 * time.Second)
	if firstRelay(p) != primaryRelayID {
		t.Fatal("stable primary never recovered")
	}
	s := p.runtime.snapshot()
	if s["selection_switches"] != uint64(2) {
		t.Fatal(s)
	}
}

func TestPrimaryRequiresFreshAuthenticatedRecoveryNotMerelyLiveQUIC(t *testing.T) {
	p, _, _, now := primarySelectionFixture(t)
	q := optimizer.Quality{Health: "unhealthy", ObservedAt: *now, LatestRTT: 60 * time.Millisecond}
	p.quality = func(time.Time) map[string]optimizer.Quality { return map[string]optimizer.Quality{primaryRelayID: q} }
	if firstRelay(p) != "VPS-01" {
		t.Fatal("ignored authenticated path failure")
	}
	// A stale quality sample is not proof of recovery, even with a live session.
	*now = now.Add(2 * time.Minute)
	if firstRelay(p) != "VPS-01" {
		t.Fatal("stale sample recovered primary")
	}
	q = optimizer.Quality{Health: "recovering", ReplyCount: 1, ObservedAt: *now}
	firstRelay(p)
	q = optimizer.Quality{Health: "healthy", ReplyCount: 60, ObservedAt: *now, LatestRTT: 57 * time.Millisecond}
	firstRelay(p)
	*now = now.Add(30 * time.Second)
	if firstRelay(p) != "VPS-01" {
		t.Fatal("one positive quality snapshot repeated for 30s is not sustained recovery")
	}
	q.ObservedAt = *now
	if firstRelay(p) != primaryRelayID {
		t.Fatal("good echo history did not recover")
	}
	rows := p.runtime.snapshot()["connections"].([]primaryUsage)
	for _, r := range rows {
		if r.ID == primaryRelayID && (r.RTTMS != 57 || !r.Healthy) {
			t.Fatal(r)
		}
	}
}

func TestPrimaryOriginCapacityAndIsolatedSessionFailuresDoNotPoisonVPS(t *testing.T) {
	p, a, _, _ := primarySelectionFixture(t)
	for _, reason := range []string{"stream_capacity", "pool_capacity", "admission_timeout", "upstream_dial_timeout", "upstream_connection_refused", "upstream_dial_failed", "open_stream_reset", "open_io_failed", "device_revoked", "authorization_lease_expired"} {
		p.failed(primaryRelayID, a, &transport.OpenError{Reason: reason, Cause: errors.New("private remote text")})
		if firstRelay(p) != primaryRelayID {
			t.Fatalf("healthy peer sessions poisoned by %s", reason)
		}
	}
	s := p.runtime.snapshot()
	for _, r := range s["connections"].([]primaryUsage) {
		if r.ID == primaryRelayID && r.Failures != 10 {
			t.Fatal(r)
		}
	}
	// Even when there are no sessions, admission/caller/origin errors cannot
	// themselves assert a failed whole relay. The pool health drives selection.
	a.healthy = false
	p.failed(primaryRelayID, a, &transport.OpenError{Reason: "pool_capacity"})
	if p.runtime.preferStandby {
		t.Fatal("capacity blacklisted provider")
	}
	a.healthy = true
	if firstRelay(p) != primaryRelayID {
		t.Fatal("capacity hold-down persisted")
	}
}

func TestPrimaryOpenFailureHoldSurvivesConfigRefreshAndDoesNotReplayStream(t *testing.T) {
	p, a, _, now := primarySelectionFixture(t)
	dst := netip.MustParseAddrPort("1.1.1.1:443")
	conn, err := p.OpenTCP(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	a.healthy = false
	a.fail = true
	p.failed(primaryRelayID, a, errors.New("session died"))
	a.healthy = true
	a.fail = false
	replacement := *p
	p.runtime.configure(&replacement, p.primaryAddress, p.standbyAddress)
	*now = now.Add(time.Second)
	if firstRelay(&replacement) != "VPS-01" {
		t.Fatal("config poll erased hold-down")
	}
	// An old provider completion cannot overwrite the replacement's selection.
	firstRelay(p)
	if !p.runtime.preferStandby {
		t.Fatal("stale provider erased state")
	}
	next, err := replacement.OpenTCP(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if a.opens != 1 {
		t.Fatal("retried primary during standby hold", a.opens)
	}
	done := make(chan error, 1)
	go func() { _, e := a.peers[0].Write([]byte("old")); done <- e }()
	b := make([]byte, 3)
	if _, e := conn.Read(b); e != nil || string(b) != "old" {
		t.Fatal("migrated/replayed established stream", e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

func TestStandbyFailureOverridesReturnHoldAndBothUnavailableFailClosedUDP(t *testing.T) {
	p, a, b, _ := primarySelectionFixture(t)
	a.healthy = false
	firstRelay(p)
	a.healthy = true
	b.healthy = false
	if firstRelay(p) != primaryRelayID {
		t.Fatal("dead standby held despite live primary")
	}
	a.healthy = false
	a.fail = true
	b.fail = true
	// Fixture UDP returns no mapping for either node. No DIRECT provider exists.
	d, e := p.OpenDatagram(context.Background(), netip.MustParseAddrPort("1.1.1.1:19295"))
	if e == nil || d != nil {
		t.Fatal("unavailable authenticated providers did not fail closed")
	}
}

// No application data is sent before the provider returns. After return, old
// UDP mappings remain bound to their server just like established TCP streams.
type selectionPacket struct {
	b      []byte
	closed bool
}

func (d *selectionPacket) Send(b []byte) error {
	if d.closed {
		return errors.New("closed")
	}
	d.b = append([]byte(nil), b...)
	return nil
}
func (d *selectionPacket) Receive(context.Context) ([]byte, error) { return d.b, nil }
func (d *selectionPacket) Close() error                            { d.closed = true; return nil }

type selectionPacketPool struct {
	primaryFixture
	flows []*selectionPacket
}

func (f *selectionPacketPool) OpenDatagram(context.Context, netip.AddrPort) (routing.Datagram, error) {
	if f.fail {
		return nil, errors.New("session unavailable")
	}
	d := &selectionPacket{}
	f.flows = append(f.flows, d)
	return d, nil
}
func TestPrimaryUDPNewMappingFailoverPreservesExistingAndCountsOnce(t *testing.T) {
	a, b := &selectionPacketPool{primaryFixture: primaryFixture{healthy: true}}, &selectionPacketPool{primaryFixture: primaryFixture{healthy: true}}
	r := newRelayPrimary()
	p := &primaryRelayProvider{primary: a, standby: b, runtime: r}
	r.configure(p, "primary", "standby")
	dst := netip.MustParseAddrPort("1.1.1.1:19295")
	old, e := p.OpenDatagram(context.Background(), dst)
	if e != nil {
		t.Fatal(e)
	}
	defer old.Close()
	a.healthy = false
	next, e := p.OpenDatagram(context.Background(), dst)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	if len(a.flows) != 1 || len(b.flows) != 1 {
		t.Fatal("mapping replaced or replayed")
	}
	if e = old.Send([]byte("old")); e != nil {
		t.Fatal(e)
	}
	data, e := old.Receive(context.Background())
	if e != nil || string(data) != "old" {
		t.Fatal("old mapping migrated")
	}
	if e = next.Send([]byte("new")); e != nil {
		t.Fatal(e)
	}
	next.Receive(context.Background())
	next.Close()
	next.Close()
	for _, row := range r.snapshot()["connections"].([]primaryUsage) {
		if row.TX != 3 || row.RX != 3 || row.Opens != 1 {
			t.Fatal(row)
		}
		if row.ID == "VPS-01" && row.Active != 0 {
			t.Fatal("double close corrupted live counts", row)
		}
	}
}

func TestStandbyReplacementUsesSignedOwnAudienceNotLogicalAlias(t *testing.T) {
	nodes := []optimizer.RelayCandidate{{ID: primaryRelayID}, {ID: "VPS-TIMEWEB"}, {ID: "VPS-01"}}
	if standbyCandidate(nodes) != "VPS-01" {
		t.Fatal("changed registered preferred standby")
	}
	nodes = nodes[:2]
	if standbyCandidate(nodes) != "VPS-TIMEWEB" {
		t.Fatal("replacement requires installer rebuild")
	}
	if standbyCandidate([]optimizer.RelayCandidate{{ID: primaryRelayID}, {ID: optimizer.Direct}}) != "" {
		t.Fatal("DIRECT cannot be a relay")
	}
	p, a, _, _ := primarySelectionFixture(t)
	p.standbyID = "VPS-TIMEWEB"
	p.runtime.configure(p, p.primaryAddress, "new-address")
	a.healthy = false
	if firstRelay(p) != "VPS-TIMEWEB" {
		t.Fatal("rewrote replacement audience to policy VPS-01")
	}
	if p.runtime.snapshot()["preferred_for_new_opens"] != "VPS-TIMEWEB" {
		t.Fatal("reported logical alias as server")
	}
}

func TestPrimaryRegistryLoadDoesNotUnpublishSignedProvider(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	pool, e := transport.NewPool(context.Background(), transport.DefaultPoolConfig(), func(context.Context) (*transport.Client, error) { return nil, errors.New("not dialed in fixture") })
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	s := &remoteState{controller: c, clients: map[string]*transport.Pool{primaryRelayID: pool}, addresses: map[string]string{primaryRelayID: "146.0.77.98:4433"}}
	if e = s.apply(context.Background(), security.Config{Relays: []optimizer.RelayCandidate{{ID: primaryRelayID, Address: "146.0.77.98:4433", Load: 1}}}); e != nil {
		t.Fatal(e)
	}
	c.relayPrimary.mu.Lock()
	provider := c.relayPrimary.provider
	c.relayPrimary.mu.Unlock()
	if provider == nil || provider.primary != pool {
		t.Fatal("aggregate saturation silently unpublished registered primary")
	}
}
