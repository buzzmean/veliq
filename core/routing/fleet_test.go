package routing

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

type fleetRouteFixture struct {
	enabled     bool
	calls       int
	failure     error
	application string
}

func (f *fleetRouteFixture) Enabled() bool { return f.enabled }
func (f *fleetRouteFixture) ManagesFlow(flow Flow) bool {
	return f.application == "" || flow.ApplicationID == f.application
}

func (f *fleetRouteFixture) OpenTCP(context.Context, Flow) (net.Conn, string, error) {
	f.calls++
	if f.failure != nil {
		return nil, "", f.failure
	}
	a, b := net.Pipe()
	_ = b.Close()
	return a, "fleet-a", nil
}

func (f *fleetRouteFixture) OpenDatagram(context.Context, Flow) (Datagram, string, error) {
	f.calls++
	if f.failure != nil {
		return nil, "", f.failure
	}
	return fleetRouteDatagram{}, "fleet-a", nil
}

type fleetRouteDatagram struct{}

func (fleetRouteDatagram) Close() error                            { return nil }
func (fleetRouteDatagram) Send([]byte) error                       { return nil }
func (fleetRouteDatagram) Receive(context.Context) ([]byte, error) { return nil, errors.New("fixture") }

type fleetRouteLegacy struct{ calls int }

func (r *fleetRouteLegacy) OpenTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	r.calls++
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}

func (r *fleetRouteLegacy) OpenDatagram(context.Context, netip.AddrPort) (Datagram, error) {
	r.calls++
	return fleetRouteDatagram{}, nil
}

func TestFleetRoutingThroughEngine(t *testing.T) {
	engine := New(16)
	fleet := &fleetRouteFixture{}
	legacy := &fleetRouteLegacy{}
	engine.SetFleetRelay(fleet)
	engine.SetRelay("legacy", legacy)
	engine.SetExactRelay("legacy", "198.51.100.88:4433", legacy)
	flow := Flow{
		PID: 71, ProcessPath: "fixture.exe", ApplicationID: "fixture",
		Source:       netip.MustParseAddrPort("127.0.0.1:50501"),
		Destination:  netip.MustParseAddrPort("198.51.100.7:443"),
		PinnedPolicy: &Policy{Route: Route{RelayID: "legacy"}, ImplicitRelay: true, BlockOnFailure: true},
	}
	old, err := engine.OpenTCP(context.Background(), flow)
	if err != nil || legacy.calls != 1 || fleet.calls != 0 {
		t.Fatalf("disabled fleet changed routing: legacy=%d fleet=%d err=%v", legacy.calls, fleet.calls, err)
	}
	defer old.Close()
	fleet.enabled = true
	flow.Source = netip.MustParseAddrPort("127.0.0.1:50502")
	if next, err := engine.OpenUDP(context.Background(), flow); next != nil || !errors.Is(err, ErrFleetPolicy) || fleet.calls != 0 {
		t.Fatalf("hot opt-in did not preserve the previous egress: %v / %v", next, err)
	}
	_ = old.Close()
	next, err := engine.OpenUDP(context.Background(), flow)
	if err != nil || fleet.calls != 1 {
		t.Fatalf("UDP did not use fleet: %v", err)
	}
	defer next.Close()
	if replay, err := engine.OpenTCP(WithExistingFlow(context.Background()), flow); replay != nil ||
		!errors.Is(err, ErrFleetPolicy) || fleet.calls != 1 {
		t.Fatalf("first flight replay started another fleet OPEN: %v, %v, %d", replay, err, fleet.calls)
	}
	fleet.failure = errors.New("stale")
	if conn, err := engine.OpenTCP(context.Background(), flow); conn != nil || !errors.Is(err, ErrFleetPolicy) {
		t.Fatalf("stale fleet opened TCP or tried fallback: %v / %v", conn, err)
	}
	flow.Source = netip.MustParseAddrPort("127.0.0.1:50503")
	flow.PinnedPolicy = &Policy{Route: Route{RelayID: "legacy"}, ExactRelay: true, RelayAddress: "198.51.100.88:4433", BlockOnFailure: true}
	explicit, err := engine.OpenTCP(context.Background(), flow)
	if err != nil || legacy.calls != 2 {
		t.Fatalf("exact route was diverted: %v", err)
	}
	defer explicit.Close()
	counts := map[string]int{}
	for _, active := range engine.Snapshot() {
		counts[active.Route.RelayID]++
	}
	if counts["legacy"] != 1 || counts["fleet-a"] != 1 {
		t.Fatalf("actual routes changed or a reservation leaked: %v", counts)
	}
}

func TestScopedFleetLeavesOtherApplicationsOnLegacy(t *testing.T) {
	engine := New(16)
	fleet := &fleetRouteFixture{enabled: true, application: "!v2-fi-canary"}
	legacy := &fleetRouteLegacy{}
	engine.SetFleetRelay(fleet)
	engine.SetRelay("legacy", legacy)
	flow := Flow{PID: 71, ProcessPath: "chatgpt.exe", ApplicationID: "chatgpt-desktop",
		Source: netip.MustParseAddrPort("127.0.0.1:50501"), Destination: netip.MustParseAddrPort("198.51.100.7:443"),
		PinnedPolicy: &Policy{Route: Route{RelayID: "legacy"}, ImplicitRelay: true, BlockOnFailure: true}}
	chat, err := engine.OpenTCP(context.Background(), flow)
	if err != nil || legacy.calls != 1 || fleet.calls != 0 {
		t.Fatalf("legacy app changed route: %v / %d / %d", err, legacy.calls, fleet.calls)
	}
	defer chat.Close()
	flow.ApplicationID = "!v2-fi-canary"
	flow.ProcessPath = "veliq-fi-canary.exe"
	flow.PID = 72
	flow.Source = netip.MustParseAddrPort("127.0.0.1:50502")
	probe, err := engine.OpenTCP(context.Background(), flow)
	if err != nil || fleet.calls != 1 {
		t.Fatalf("scoped canary could not coexist with legacy app: %v / %d", err, fleet.calls)
	}
	defer probe.Close()
	flow.ApplicationID = "chatgpt-desktop"
	flow.ProcessPath = "chatgpt.exe"
	flow.PID = 71
	flow.Source = netip.MustParseAddrPort("127.0.0.1:50503")
	other, err := engine.OpenTCP(context.Background(), flow)
	if err != nil || legacy.calls != 2 || fleet.calls != 1 {
		t.Fatalf("second legacy app flow changed route: %v / %d / %d", err, legacy.calls, fleet.calls)
	}
	defer other.Close()
	flow.ApplicationID = "!v2-fi-canary"
	flow.ProcessPath = "veliq-fi-canary.exe"
	flow.PID = 72
	flow.Source = netip.MustParseAddrPort("127.0.0.1:50504")
	if next, err := engine.OpenTCP(context.Background(), flow); next == nil || err != nil {
		t.Fatalf("additional scoped flow failed: %v", err)
	} else {
		_ = next.Close()
	}
}

func TestScopedFleetWaitsForOldFlowOfSelectedApplication(t *testing.T) {
	engine := New(16)
	fleet := &fleetRouteFixture{application: "!v2-fi-canary"}
	legacy := &fleetRouteLegacy{}
	engine.SetFleetRelay(fleet)
	engine.SetRelay("legacy", legacy)
	flow := Flow{PID: 72, ProcessPath: "veliq-fi-canary.exe", ApplicationID: "!v2-fi-canary",
		Source: netip.MustParseAddrPort("127.0.0.1:50501"), Destination: netip.MustParseAddrPort("198.51.100.7:443"),
		PinnedPolicy: &Policy{Route: Route{RelayID: "legacy"}, ImplicitRelay: true, BlockOnFailure: true}}
	old, err := engine.OpenTCP(context.Background(), flow)
	if err != nil {
		t.Fatal(err)
	}
	fleet.enabled = true
	flow.Source = netip.MustParseAddrPort("127.0.0.1:50502")
	if next, err := engine.OpenTCP(context.Background(), flow); next != nil || !errors.Is(err, ErrFleetPolicy) || fleet.calls != 0 {
		t.Fatalf("selected application changed egress while old flow remained: %v / %d", err, fleet.calls)
	}
	_ = old.Close()
	next, err := engine.OpenTCP(context.Background(), flow)
	if err != nil || fleet.calls != 1 {
		t.Fatalf("selected application could not enter fleet after old flow closed: %v / %d", err, fleet.calls)
	}
	_ = next.Close()
}

func TestFleetAdaptiveUDPWaitsForNewFlowAfterDirectFailure(t *testing.T) {
	engine := New(16)
	fleet := &fleetRouteFixture{enabled: true}
	engine.SetFleetRelay(fleet)
	flow := Flow{PID: 71, ProcessPath: "fixture", ApplicationID: "fixture", Protocol: "udp", Network: "fixture-network",
		Source: netip.MustParseAddrPort("127.0.0.1:50501"), Destination: netip.MustParseAddrPort("198.51.100.7:5000"),
		PinnedPolicy: &Policy{ImplicitRelay: true}}
	active := &AdaptiveUDP{e: engine, flow: flow, current: fleetRouteDatagram{}, relay: "legacy"}
	now := time.Now()
	active.health.observe(now, false, 128)
	if err := active.toRelayLocked(context.Background(), "DIRECT_RECEIVE_FAILED"); !errors.Is(err, ErrFleetPolicy) ||
		fleet.calls != 0 || len(engine.Snapshot()) != 0 {
		t.Fatalf("an active UDP tuple attempted to change egress: %v / %d", err, fleet.calls)
	}
	flow.Source = netip.MustParseAddrPort("127.0.0.1:50502")
	next, err := engine.OpenAdaptiveUDP(context.Background(), flow, "legacy", time.Second)
	if err != nil || fleet.calls != 1 || next.Route().RelayID != "fleet-a" {
		t.Fatalf("new tuple did not use the verified fleet selector: %v / %d", err, fleet.calls)
	}
	_ = next.Close()
}
