package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/buzzmean/neexitlag/core/routing"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

type nativeBackendFixture struct {
	hotBackendFixture
	publications int
}

func (b *nativeBackendFixture) Status() wp.CaptureStatus {
	s := b.hotBackendFixture.Status()
	s.Capabilities.Transparent = true
	return s
}

func nativeEdgeFixture(t *testing.T) (*Controller, profiles.Profile, *nativeBackendFixture) {
	t.Helper()
	c := New(context.Background())
	t.Cleanup(c.Close)
	c.BrowserOwnerSID = "owner"
	p := edgeTestProfile()
	p.AppPreset = "edge-sites-pending"
	c.Profiles.Upsert(p)
	b := &nativeBackendFixture{}
	c.Backend = b
	return c, p, b
}
func ownNativeEdge(c *Controller) {
	e := c.edgeLocked()
	e.saved.Owned = []string{"owned-guard"}
	e.saved.GuardPAC = "owned-guard"
	e.active = func(_, v string) bool { return v != "" }
	e.write = func(string, []string, string) error { return nil }
}
func TestNativeFreshPreparesCaptureWithoutPACAndPublishesAUTO(t *testing.T) {
	c, p, b := nativeEdgeFixture(t)
	c.enabled = true
	result, err := edgeCall(c, "browser.native.enable", map[string]string{"profile_id": p.ID})
	if err != nil {
		t.Fatal(err)
	}
	if !b.ready || !nativeBrowserProfile(findNativeEdge(c)) || result.(map[string]any)["compatibility"] != (*nativeBrowserCompatibility)(nil) {
		t.Fatal("native preparation failed", result)
	}
	if c.browser.edge != nil && len(c.browser.edge.saved.Owned) > 0 {
		t.Fatal("fresh activation wrote policy")
	}
}

func TestNativeEdgeEnablePreservesStreamsAndRepairsGuardWithoutNonce(t *testing.T) {
	c, p, b := nativeEdgeFixture(t)
	c.enabled = true
	ownNativeEdge(c)
	result, err := edgeCall(c, "browser.native.enable", map[string]string{"profile_id": p.ID})
	if err != nil {
		t.Fatal(err)
	}
	if !result.(map[string]any)["native"].(bool) || !b.ready {
		t.Fatal(result)
	}
	if len(b.calls) != 0 || b.epoch != 0 {
		t.Fatal("activation reset established connections", b.calls, b.epoch)
	}
	saved := findNativeEdge(c)
	if !nativeBrowserProfile(saved) || saved.AppPreset != "edge-sites" {
		t.Fatal(saved)
	}
	e := c.browser.edge
	if e.server == nil || e.saved.GuardPAC == "" || e.server.Confirmed(p.ID) {
		t.Fatal("missing live guard or fabricated nonce")
	}
	args, err := nativeCompatibilityArguments(saved, e.server.Address())
	if err != nil || !strings.Contains(e.saved.GuardPAC, strings.TrimPrefix(args[1], "--proxy-pac-url=")) {
		t.Fatal("guard did not target live per-origin listener", err)
	}
	first := c.nativeSnapshot().Profiles[0].Activated
	if _, err = edgeCall(c, "browser.native.enable", map[string]string{"profile_id": p.ID}); err != nil {
		t.Fatal(err)
	}
	if c.nativeSnapshot().Profiles[0].Activated != first {
		t.Fatal("idempotent enable reset timing")
	}
	if _, err = edgeCall(c, "edge.confirm", map[string]string{"profile_id": p.ID, "health_url": "http://neexitlag-health.invalid/ready/missing"}); err == nil {
		t.Fatal("missing nonce accepted")
	}
	if e.server == nil || e.saved.GuardPAC == "" || !nativeBrowserProfile(findNativeEdge(c)) {
		t.Fatal("failed confirmation stranded native profile")
	}
}
func TestNativeBackendFailurePreservesPendingAndOwnedPolicy(t *testing.T) {
	c, p, b := nativeEdgeFixture(t)
	c.enabled = true
	ownNativeEdge(c)
	b.fail = true
	if _, err := edgeCall(c, "browser.native.enable", map[string]string{"profile_id": p.ID}); err == nil {
		t.Fatal("capture failure ignored")
	}
	if findNativeEdge(c).BrowserTransport != "" || c.browser.edge.saved.GuardPAC != "owned-guard" {
		t.Fatal("capture failure published native or changed guard")
	}
}
func TestNativeSNIHostOpaqueDNSIPv6AndLegacyIsolation(t *testing.T) {
	c, p, _ := nativeEdgeFixture(t)
	p.Mode = profiles.Auto
	p.BrowserTransport = "native"
	c.Profiles.Upsert(p)
	c.enabled = true
	id := wp.ProcessIdentity{PID: 77, CreationTime: 1, Path: p.Executables[0]}
	tuple := wp.Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:50001"), Destination: netip.MustParseAddrPort("203.0.113.1:443")}
	initial := c.Classify(id, tuple)
	if !initial.Deferred || !initial.NewConnectionsOnly || initial.OpenDeferred == nil {
		t.Fatalf("%+v", initial)
	}
	for _, tt := range []struct {
		host, reason string
		want         flowpolicy.Action
	}{
		{"ordinary.example", "TLS_SNI", flowpolicy.Direct}, {"chatgpt.com", "TLS_SNI", flowpolicy.RelayRequired},
		{"www.google.com", "ECH_OUTER_SNI_ONLY", flowpolicy.Direct}, {"", "CLIENTHELLO_INCOMPLETE", flowpolicy.Direct},
		{"ordinary.example", "HTTP_HOST", flowpolicy.Direct},
	} {
		d := wp.ResolveDeferredDecision(initial, tt.host, tt.reason)
		if d.Policy.Action != tt.want || d.OpenDeferred == nil || !d.NewConnectionsOnly {
			t.Fatalf("%s/%s: %+v", tt.host, tt.reason, d)
		}
		if tt.want == flowpolicy.RelayRequired && (!d.BlockOnFailure || d.Route.RelayID != "VPS-01") {
			t.Fatal("required fail-open", d)
		}
	}
	tuple.Destination = netip.MustParseAddrPort("192.0.2.53:53")
	d := c.Classify(id, tuple)
	if d.Deferred || !d.Route.Direct() || d.OpenDeferred == nil || d.DNSExchange == nil {
		t.Fatal("native DNS broker missing or DNS/53 relayed", d)
	}
	tuple.Destination = netip.MustParseAddrPort("[2001:db8::1]:443")
	d = c.Classify(id, tuple)
	if !d.Block || d.Deferred {
		t.Fatal("unsupported IPv6 leaked", d)
	}
	tuple.Protocol = "udp"
	tuple.Destination = netip.MustParseAddrPort("203.0.113.1:443")
	d = c.Classify(id, tuple)
	if !d.Block || d.Policy.Action != flowpolicy.Block || !d.BlockOnFailure || d.Policy.Source != "browser_native_quic_tcp_fallback" {
		t.Fatal("opaque QUIC fallback not enforced", d)
	}
	id.Path = "unrelated.exe"
	if d = c.Classify(id, tuple); d.Block || !d.Route.Direct() {
		t.Fatal("unrelated process touched")
	}
	p.BrowserTransport = ""
	p.AppPreset = ""
	tuple.Protocol = "tcp"
	id.Path = p.Executables[0]
	c.Profiles.Upsert(p)
	d = c.Classify(id, tuple)
	if d.NewConnectionsOnly || d.OpenDeferred != nil {
		t.Fatal("legacy Edge behavior changed")
	}
}
func TestNativeTimingRequiresBidirectionalPayloadAndBoundsEvidence(t *testing.T) {
	c, _, _ := nativeEdgeFixture(t)
	n := &c.browser.native
	n.activate("edge", false)
	q := browserproxy.Request{Owner: browserproxy.Owner{Profile: "edge"}, Host: "ordinary.example"}
	id, err := n.begin(q, wp.Tuple{})
	if err != nil {
		t.Fatal(err)
	}
	n.opened(id, browserproxy.Plan{}, nil)
	if s := c.nativeSnapshot().Profiles[0]; s.FirstOpenMS < 0 || s.FirstExchangeMS != -1 {
		t.Fatal(s)
	}
	n.bytes(id, 100, 0)
	if c.nativeSnapshot().Profiles[0].FirstExchangeMS != -1 {
		t.Fatal("one-way traffic certified reply")
	}
	n.bytes(id, 0, 25)
	if c.nativeSnapshot().Profiles[0].FirstExchangeMS < 0 {
		t.Fatal("missing real exchange")
	}
	n.closed(id)
	for i := 0; i < 600; i++ {
		id, _ = n.begin(q, wp.Tuple{})
		n.closed(id)
	}
	s := c.nativeSnapshot()
	raw, _ := json.Marshal(s)
	if len(n.records) > 512 || len(raw) > 60*1024 || !s.Truncated || s.Lost == 0 {
		t.Fatal("unbounded/false complete snapshot", len(raw), s.Lost)
	}
	cutoff := n.next
	n.activate("edge", true)
	if c.nativeSnapshot().Profiles[0].AfterFlow != cutoff || c.nativeSnapshot().Profiles[0].FirstExchangeMS != -1 {
		t.Fatal("new optimization epoch not measured")
	}
}
func TestRelayTunnelMinutesActiveCountsAndReleaseOnce(t *testing.T) {
	u := &browserRelayUsage{}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			release := u.openedTunnel("edge", fmt.Sprintf("%d.example", i%2), time.Now())
			u.account("edge", fmt.Sprintf("%d.example", i%2), 10, 20, time.Now())
			release()
			release()
		}(i)
	}
	wg.Wait()
	s := u.snapshot()
	var opened, tx, rx uint64
	for _, m := range s.Minutes {
		opened += m.Opened
		tx += m.Sent
		rx += m.Received
	}
	if s.Active != 0 || s.Opened != 32 || opened != 32 || tx != 320 || rx != 640 || len(s.ActiveOrigins) != 0 {
		t.Fatal(s)
	}
}

func findNativeEdge(c *Controller) profiles.Profile {
	for _, p := range c.Profiles.List() {
		if p.ID == "edge" {
			return p
		}
	}
	return profiles.Profile{}
}

func TestNativeSilentDIRECTClosesOnlyThatFlowNeverReplays(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	fired := make(chan struct{}, 1)
	c := &nativeFirstReplyConn{Conn: a, timeout: 25 * time.Millisecond, stalled: func() { fired <- struct{}{} }}
	defer c.Close()
	read := make(chan error, 1)
	go func() { _, err := io.ReadFull(b, make([]byte, 3)); read <- err }()
	if _, err := c.Write([]byte("TLS")); err != nil {
		t.Fatal(err)
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("silent flow not closed")
	}
	c.fail()
	select {
	case <-fired:
		t.Fatal("failure replayed")
	default:
	}
}
func TestNativeFirstReplyIsProgressButDoesNotClearFailedDomainVerdict(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	fired := make(chan struct{}, 1)
	c := &nativeFirstReplyConn{Conn: a, timeout: 25 * time.Millisecond, stalled: func() { fired <- struct{}{} }}
	defer c.Close()
	go func() { io.ReadFull(b, make([]byte, 1)); b.Write([]byte("x")) }()
	c.Write([]byte("x"))
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-fired:
		t.Fatal("working flow closed")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestNativeNewEpochDoesNotCountOldTCPAsNewActivationSuccess(t *testing.T) {
	c, _, _ := nativeEdgeFixture(t)
	n := &c.browser.native
	n.activate("edge", false)
	id, _ := n.begin(browserproxy.Request{Owner: browserproxy.Owner{Profile: "edge"}}, wp.Tuple{})
	n.mu.Lock()
	clock := n.records[id].Started
	n.mu.Unlock()
	n.activateAt("edge", true, clock)
	n.opened(id, browserproxy.Plan{}, nil)
	n.bytes(id, 10, 10)
	s := c.nativeSnapshot().Profiles[0]
	if s.FirstOpenMS != -1 || s.FirstExchangeMS != -1 {
		t.Fatal("old stream certified new activation", s)
	}
}

func TestNativeCapturePrepareDoesNotHotResetOldPendingBrowserTCP(t *testing.T) {
	c, p, b := nativeEdgeFixture(t)
	ownNativeEdge(c)
	c.enabled = true
	p.Mode = profiles.Auto
	c.Profiles.Upsert(p)
	b.id = wp.ProcessIdentity{PID: 77, CreationTime: 1, Path: p.Executables[0]}
	b.tuple = wp.Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:50001"), Destination: netip.MustParseAddrPort("203.0.113.1:443")}
	if _, err := edgeCall(c, "browser.native.enable", map[string]string{"profile_id": p.ID}); err != nil {
		t.Fatal(err)
	}
	if !b.classified.NewConnectionsOnly {
		t.Fatal("backend start could reset existing browser TCP before publication")
	}
}

func (b *nativeBackendFixture) ReconfigureNewConnections(_ string, publish func() error) error {
	b.publications++
	return publish()
}
func TestNativeIdempotentEnableDoesNotRetireUDPEveryMonitorTick(t *testing.T) {
	c, p, b := nativeEdgeFixture(t)
	c.enabled = true
	ownNativeEdge(c)
	for i := 0; i < 3; i++ {
		if _, err := edgeCall(c, "browser.native.enable", map[string]string{"profile_id": p.ID}); err != nil {
			t.Fatal(err)
		}
	}
	if b.publications != 1 || len(b.calls) != 0 {
		t.Fatal("monitor retired flows", b.publications, b.calls)
	}
}

func TestNativeEdgeStatusSeparatesCaptureFromPACNonceReadiness(t *testing.T) {
	c, p, _ := nativeEdgeFixture(t)
	c.enabled = true
	ownNativeEdge(c)
	if _, err := edgeCall(c, "browser.native.enable", map[string]string{"profile_id": p.ID}); err != nil {
		t.Fatal(err)
	}
	read := func() map[string]any {
		value, err := edgeCall(c, "edge.status", nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(value)
		var got map[string]any
		json.Unmarshal(raw, &got)
		return got
	}
	got := read()
	if findNativeEdge(c).AppPreset != "edge-sites" || got["readiness_state"] != "NATIVE_ARMED_NO_NEW_FLOW" || got["pac_nonce_readiness"] != "NOT_PREPARED" || got["rollback_guard_active"] != false || got["owned_guard_installed"] != true {
		t.Fatal(got, findNativeEdge(c))
	}
	n := &c.browser.native
	id, err := n.begin(browserproxy.Request{Ingress: "PAC_NATIVE_UPSTREAM", Host: "ordinary.example", Owner: browserproxy.Owner{Profile: p.ID}}, policyTuple("tcp", 443))
	if err != nil {
		t.Fatal(err)
	}
	n.opened(id, browserproxy.Plan{}, nil)
	got = read()
	if got["readiness_state"] != "NATIVE_UPSTREAM_OPENED_NO_EXCHANGE" {
		t.Fatal("upstream OPEN without bytes presented as working tunnel", got)
	}
	n.bytes(id, 11, 0)
	got = read()
	if got["readiness_state"] != "NATIVE_UPSTREAM_OPENED_NO_EXCHANGE" {
		t.Fatal("one-way traffic presented as bidirectional tunnel", got)
	}
	n.bytes(id, 0, 21)
	got = read()
	if got["readiness_state"] != "NATIVE_TUNNEL_OBSERVED" || c.browser.edge.server.Confirmed(p.ID) {
		t.Fatal("native observation forged PAC nonce readiness", got)
	}
	timing := c.nativeSnapshot().Profiles[0]
	if timing.Opened != 1 || timing.Sent != 11 || timing.Received != 21 || timing.FirstOpenMS < 0 {
		t.Fatal(timing)
	}
}

type nativePACAdmissionSpy struct {
	nativeBackendFixture
	decision     wp.Decision
	calls        int
	err          error
	invokeWorker bool
}

func (b *nativePACAdmissionSpy) OpenBrowserNativeTCP(ctx context.Context, _ wp.ProcessIdentity, _, _ netip.AddrPort, d wp.Decision) (net.Conn, error) {
	b.calls++
	b.decision = d
	if b.invokeWorker {
		_, _, _ = d.OpenDeferred(ctx, d, "CONNECT_AUTHORITY")
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, b.err
}
func TestNativePACExactDelegationIsBoundedFailClosedAndNotAFalseOpen(t *testing.T) {
	c, p, _ := nativeEdgeFixture(t)
	b := &nativePACAdmissionSpy{err: context.DeadlineExceeded}
	b.ready = true
	c.Backend = b
	q := browserproxy.Request{Ingress: "PAC_CONNECT", Host: "chatgpt.com", Port: 443, Secure: true, Owner: browserproxy.Owner{Profile: p.ID}}
	plan := browserproxy.Plan{Destination: netip.MustParseAddrPort("203.0.113.2:443"), Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: "VPS-01", Fallback: flowpolicy.Required}}
	_, err := c.openNativePAC(context.Background(), q, plan, wp.Decision{Policy: plan.Policy})
	if err != context.DeadlineExceeded || b.calls != 1 {
		t.Fatal(err, b.calls)
	}
	d := b.decision
	if d.Deferred || !d.NewConnectionsOnly || !d.BlockOnFailure || d.ResolveDomain != nil || d.OpenDeferred == nil || d.OriginDomain != "chatgpt.com" {
		t.Fatal(d)
	}
	if len(c.nativeSnapshot().Records) != 0 {
		t.Fatal("failed local delegation manufactured real upstream OPEN")
	}
	b.ready = false
	if _, err = c.openNativePAC(context.Background(), q, plan, d); err == nil || b.calls != 1 {
		t.Fatal("unready capture admitted a SYN", err, b.calls)
	}
}

func TestNativePACWorkerFailureIsNotMisreportedAsKernelConnectTimeout(t *testing.T) {
	c, p, _ := nativeEdgeFixture(t)
	b := &nativePACAdmissionSpy{invokeWorker: true}
	b.ready = true
	c.Backend = b
	q := browserproxy.Request{Host: "chatgpt.com", Owner: browserproxy.Owner{Profile: p.ID}}
	plan := browserproxy.Plan{Destination: netip.MustParseAddrPort("203.0.113.2:443")}
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	_, err := c.openNativePAC(ctx, q, plan, wp.Decision{})
	if err == nil || err.Error() != "NATIVE_PROFILE_CHANGED" || ctx.Err() != nil {
		t.Fatal("real worker error hidden behind timeout", err, ctx.Err())
	}
}

func TestBrowserReservationCollisionIsLocalAndDoesNotPoisonNetworkCache(t *testing.T) {
	err := browserFlowOpenError(fmt.Errorf("wrapped: %w", routing.ErrFlowExists))
	if !errors.Is(err, routing.ErrFlowExists) || nativeFailureCode(err) != "LOCAL_FLOW_RESERVATION_IN_USE" || retryableDirectOpen(err) {
		t.Fatal("local collision misclassified as network", err)
	}
	c := New(context.Background())
	defer c.Close()
	q := browserproxy.Request{Host: "www.youtube.com", Port: 443}
	p := browserproxy.Plan{Destination: netip.MustParseAddrPort("203.0.113.1:443"), Policy: flowpolicy.Result{Action: flowpolicy.Direct}}
	c.observeDirectOpen(profilesResult{profile: profiles.Profile{ID: "chrome"}, network: "n"}, q, p, err, time.Now())
	if c.browser.directTimeouts.Stats().Created != 0 {
		t.Fatal("local collision polluted route cache")
	}
}

func TestNativeBrowserHealthRequiresActualExchangeInsteadOfArmedCapture(t *testing.T) {
	c, p, _ := nativeEdgeFixture(t)
	c.enabled = true
	if _, err := edgeCall(c, "browser.native.enable", map[string]string{"profile_id": p.ID}); err != nil {
		t.Fatal(err)
	}
	if h := c.browserPolicyHealth(); h.EdgeReady {
		t.Fatal("armed capture fabricated browser readiness", h)
	}
	n := &c.browser.native
	n.mu.Lock()
	v := n.profiles[p.ID]
	v.PACUpstream.Exchanges = 1
	v.PACUpstream.Sent = 10
	v.PACUpstream.Received = 10
	n.profiles[p.ID] = v
	n.mu.Unlock()
	if h := c.browserPolicyHealth(); h.EdgeReady {
		t.Fatal("PAC exchange fabricated native readiness", h)
	}
	c.browser.readiness.mu.Lock()
	c.browser.readiness.relay = func() bool { return true }
	c.browser.readiness.mu.Unlock()
	n.mu.Lock()
	v = n.profiles[p.ID]
	v.NativeOnly.Exchanges = 1
	v.NativeOnly.Sent = 10
	v.NativeOnly.Received = 10
	n.profiles[p.ID] = v
	n.mu.Unlock()
	if h := c.browserPolicyHealth(); h.EdgeReady || h.EdgeReason != "AUTHORITY_TRANSPORT_PENDING; RAW_TLS_AUTHENTICATED_RELAY" {
		t.Fatal("raw TLS bytes falsely established authority readiness", h)
	}
	c.enabled = false
	if h := c.browserPolicyHealth(); h.EdgeReady {
		t.Fatal("historic exchange hid OFF", h)
	}
}
