package routing

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestProtectedUDPReadTimeoutDoesNotReopen(t *testing.T) {
	e := New(8)
	p := &pinnedProvider{d: &pinnedDatagram{}}
	e.SetRelay("relay", p)
	e.SetPolicy("media", Policy{Route: Route{RelayID: "relay"}, BlockOnFailure: true})
	f := Flow{Source: netip.MustParseAddrPort("127.0.0.1:12001"), Destination: netip.MustParseAddrPort("127.0.0.1:19000"), PID: 1, ProcessPath: "media.exe", ApplicationID: "media"}
	d, err := e.OpenUDP(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for i := 0; i < 10; i++ {
		if _, err = d.Receive(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		if err = d.Send([]byte("live")); err != nil {
			t.Fatal(err)
		}
	}
	if p.calls != 1 {
		t.Fatal("harmless read timeout replaced flow", p.calls)
	}
}
func TestAdaptiveFailedRelayOpenRecoversWithoutNewDirectProbation(t *testing.T) {
	e := New(8)
	f := Flow{Source: netip.MustParseAddrPort("127.0.0.1:12002"), Destination: netip.MustParseAddrPort("127.0.0.1:19000"), PID: 1, ProcessPath: "media.exe", ApplicationID: "media", Network: "ISP"}
	// A failed probation has already populated a relay-only cache entry.
	e.udpObserved(f, true)
	d, err := e.OpenAdaptiveUDP(context.Background(), f, "relay", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if d.Route().RelayID != "relay" {
		t.Fatal("restarted direct probation")
	}
	if err = d.Send([]byte("while unavailable")); !errors.Is(err, ErrUDPRecovering) {
		t.Fatal(err)
	}
	p := &pinnedProvider{d: &pinnedDatagram{}}
	e.SetRelay("relay", p)
	time.Sleep(510 * time.Millisecond)
	if err = d.Send([]byte("future datagram")); err != nil {
		t.Fatal(err)
	}
	if d.Route().RelayID != "relay" || !e.udpCached(f, time.Now()) || p.calls != 1 || p.d.sent != 1 {
		t.Fatal("adaptive route/cache changed", d.Route(), p.calls, p.d.sent)
	}
}
