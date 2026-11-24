package windowsplatform

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/routing"
)

type delegationRelay struct{ open func() net.Conn }

func (r delegationRelay) OpenTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return r.open(), nil
}
func (delegationRelay) OpenDatagram(context.Context, netip.AddrPort) (routing.Datagram, error) {
	return nil, errors.New("not UDP")
}

func TestPlannedFullCloseReleasesActualEngineTupleBeforeRelayRetry(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// Keep the accepted origin open even if the proxy half-closes its upload.
	// A blocked origin is not obliged to send any FIN or application response.
	accept := make(chan net.Conn, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			accept <- c
		}
	}()
	engine := routing.New(8)
	flow := routing.Flow{Protocol: "tcp", PID: 7, ProcessPath: "chrome.exe", ApplicationID: "chrome", Source: netip.MustParseAddrPort("127.0.0.1:1111"), Destination: listener.Addr().(*net.TCPAddr).AddrPort(), PinnedPolicy: &routing.Policy{}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	direct, err := engine.OpenTCP(ctx, flow)
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	peer := <-accept
	defer peer.Close()
	unrelated := flow
	unrelated.Source = netip.MustParseAddrPort("127.0.0.1:1112")
	other, err := engine.OpenTCP(ctx, unrelated)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	otherPeer := <-accept
	defer otherPeer.Close()
	if _, err = engine.OpenTCP(ctx, flow); !errors.Is(err, routing.ErrFlowExists) {
		t.Fatal("missing baseline reservation", err)
	}
	state := newTCPState(8)
	bound := Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:2222"), Destination: flow.Destination}
	owner := &tcpEntry{}
	entry := state.add(bound, ProcessIdentity{}, Decision{OpenDeferred: func(context.Context, Decision, string) (net.Conn, Decision, error) { return nil, Decision{}, nil }}, "opening", time.Now())
	entry.delegationOwner, entry.upstream, entry.mode = owner, direct, "relay"
	local, app := net.Pipe()
	defer app.Close()
	entry.local = local
	state.closePlannedDelegation(bound, owner)
	if entry.mode != "closed" || !entry.normalTeardown || entry.upstream != nil || entry.local != nil {
		t.Fatal("handoff not synchronously retired")
	}
	if len(engine.Snapshot()) != 1 {
		t.Fatal("target reservation retained or unrelated flow closed", engine.Snapshot())
	}
	engine.SetRelay("VPS-01", delegationRelay{func() net.Conn { a, b := net.Pipe(); t.Cleanup(func() { a.Close(); b.Close() }); return a }})
	next := flow
	next.PinnedPolicy = &routing.Policy{Route: routing.Route{RelayID: "VPS-01"}, BlockOnFailure: true}
	relay, err := engine.OpenTCP(ctx, next)
	if err != nil {
		t.Fatal("cold same-tuple relay OPEN failed", err)
	}
	defer relay.Close()
	state.closePlannedDelegation(bound, owner)
	direct.Close()
	if len(engine.Snapshot()) != 2 {
		t.Fatal("late old close removed relay or unrelated tuple", engine.Snapshot())
	}
	for _, f := range engine.Snapshot() {
		if f.Source == flow.Source && f.Route.RelayID != "VPS-01" {
			t.Fatal("retry leaked DIRECT", f)
		}
	}
}

func TestPlannedCloseDoesNotRetireForeignGenerationOrLegacy(t *testing.T) {
	for _, kind := range []string{"foreign", "legacy", "hot_attach"} {
		t.Run(kind, func(t *testing.T) {
			s := newTCPState(8)
			bound := Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:2222"), Destination: netip.MustParseAddrPort("203.0.113.1:443")}
			owner := &tcpEntry{}
			d := Decision{OpenDeferred: func(context.Context, Decision, string) (net.Conn, Decision, error) { return nil, Decision{}, nil }}
			e := s.add(bound, ProcessIdentity{}, d, "opening", time.Now())
			e.delegationOwner = owner
			e.mode = "relay"
			up, peer := net.Pipe()
			defer up.Close()
			defer peer.Close()
			e.upstream = up
			if kind == "foreign" {
				owner = &tcpEntry{}
			}
			if kind == "legacy" {
				e.decision.OpenDeferred = nil
			}
			if kind == "hot_attach" {
				e.mode = "hot_attach"
			}
			before := e.mode
			s.closePlannedDelegation(bound, owner)
			if e.mode != before || e.upstream != up {
				t.Fatal("unowned mapping changed", kind)
			}
		})
	}
}

func TestReservedLocalSYNMustNotBecomeSelfDirectOnOwnerTableRace(t *testing.T) {
	d := Decision{Route: routing.Route{Kind: routing.DirectPlusRoute}}
	if !delegatedOwnerPending(d, 0, 100, errors.New("TCP owner table pending")) {
		t.Fatal("unverified reserved LOCAL SYN escaped as self DIRECT")
	}
	if !delegatedOwnerPending(d, 200, 100, nil) {
		t.Fatal("foreign owner accepted")
	}
	if delegatedOwnerPending(d, 100, 100, nil) {
		t.Fatal("verified own socket blocked")
	}
	if delegatedOwnerPending(Decision{}, 0, 100, errors.New("unrelated lookup")) {
		t.Fatal("unrelated socket affected")
	}
}
