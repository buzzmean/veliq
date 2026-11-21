package routing

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

type pinnedDatagram struct {
	failed bool
	sent   int
}

func (d *pinnedDatagram) Send([]byte) error {
	if d.failed {
		return errors.New("closed")
	}
	d.sent++
	return nil
}
func (d *pinnedDatagram) Receive(context.Context) ([]byte, error) {
	return nil, context.DeadlineExceeded
}
func (d *pinnedDatagram) Close() error { return nil }

type pinnedProvider struct {
	calls int
	d     *pinnedDatagram
}

func (p *pinnedProvider) OpenDatagram(context.Context, netip.AddrPort) (Datagram, error) {
	p.calls++
	return p.d, nil
}
func (p *pinnedProvider) OpenTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("unused")
}
func TestExistingUDPFlowNeverMigratesOnAUTOQualityChange(t *testing.T) {
	engine := New(10)
	a, b := &pinnedProvider{d: &pinnedDatagram{}}, &pinnedProvider{d: &pinnedDatagram{}}
	engine.SetRelay("A", a)
	engine.SetRelay("B", b)
	chosen := "A"
	engine.SetAutoSelector(func(Flow) Policy { return Policy{Route: Route{RelayID: chosen}} })
	engine.SetPolicy("game", Policy{Auto: true})
	flow := Flow{Source: netip.MustParseAddrPort("127.0.0.1:11000"), Destination: netip.MustParseAddrPort("127.0.0.1:40000"), PID: 42, ProcessPath: "game.exe", ApplicationID: "game"}
	first, err := engine.OpenUDP(context.Background(), flow)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	chosen = "B"
	if first.Send([]byte{1}) != nil || a.d.sent != 1 || b.calls != 0 {
		t.Fatal("existing flow moved")
	}
	a.d.failed = true
	if first.Send([]byte{2}) == nil || b.calls != 0 {
		t.Fatal("failure reopened existing flow on another relay")
	}
	flow.Source = netip.MustParseAddrPort("127.0.0.1:11001")
	second, err := engine.OpenUDP(context.Background(), flow)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if b.calls != 1 {
		t.Fatal("new flow did not use new AUTO route")
	}
}
