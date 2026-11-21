package routing

import (
	"context"
	"errors"
	"github.com/buzzmean/neexitlag/tools/echo"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestAdaptiveDirectReplyRemainsDirect(t *testing.T) {
	addr, close, err := echo.UDP()
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	e := New(8)
	f := Flow{Protocol: "udp", PID: 1, ProcessPath: "Discord.exe", ApplicationID: "discord", Source: netip.MustParseAddrPort("127.0.0.1:1200"), Destination: netip.MustParseAddrPort(addr.String())}
	d, err := e.OpenAdaptiveUDP(context.Background(), f, "offline", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err = d.Send([]byte("voice")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	b, err := d.Receive(ctx)
	if err != nil || string(b) != "voice" || !d.Route().Direct() {
		t.Fatal(string(b), err, d.Route())
	}
}
func TestPinnedRequiredTCPAndUDPDoNotUseGlobalDirect(t *testing.T) {
	e := New(4)
	f := Flow{PID: 1, ProcessPath: "ChatGPT.exe", ApplicationID: "openai", Source: netip.MustParseAddrPort("127.0.0.1:1201"), Destination: netip.MustParseAddrPort("127.0.0.1:1"), PinnedPolicy: &Policy{Route: Route{RelayID: "offline"}, BlockOnFailure: true}}
	if _, err := e.OpenUDP(context.Background(), f); err == nil {
		t.Fatal("required UDP fell back")
	}
	if _, err := e.OpenTCP(context.Background(), f); err == nil {
		t.Fatal("required TCP fell back")
	}
	if len(e.Snapshot()) != 0 {
		t.Fatal("failed reservations retained")
	}
}

// This is a local transport regression, not Discord voice/Internet acceptance.
func TestAdaptiveFailureOnlyChangesOneUDPFlow(t *testing.T) {
	drop, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer drop.Close()
	e := New(8)
	f := Flow{PID: 1, ProcessPath: "Discord.exe", ApplicationID: "discord", Source: netip.MustParseAddrPort("127.0.0.1:1202"), Destination: netip.MustParseAddrPort(drop.LocalAddr().String())}
	d, err := e.OpenAdaptiveUDP(context.Background(), f, "offline", 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	other := f
	other.Source = netip.MustParseAddrPort("127.0.0.1:1203")
	other.PinnedPolicy = &Policy{}
	unchanged, err := e.OpenUDP(context.Background(), other)
	if err != nil {
		t.Fatal(err)
	}
	defer unchanged.Close()
	d.Send([]byte("probe"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err = d.Receive(ctx); err == nil {
		t.Fatal("unavailable relay silently used DIRECT")
	}
	all := e.Snapshot()
	if len(all) != 1 || all[0].Source != other.Source || !all[0].Route.Direct() {
		t.Fatal("unrelated flow changed", all)
	}
}
func TestAdaptivePositiveRelayTransitionNeverChangesOtherFlow(t *testing.T) {
	drop, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer drop.Close()
	e := New(8)
	provider := &pinnedProvider{d: &pinnedDatagram{}}
	e.SetRelay("VPS-01", provider)
	f := Flow{PID: 1, ProcessPath: "Discord.exe", ApplicationID: "discord", Source: netip.MustParseAddrPort("127.0.0.1:1210"), Destination: netip.MustParseAddrPort(drop.LocalAddr().String())}
	d, err := e.OpenAdaptiveUDP(context.Background(), f, "VPS-01", 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.Send([]byte("first"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	d.Receive(ctx)
	if d.Route().RelayID != "VPS-01" || provider.calls != 1 {
		t.Fatal("flow did not transition", d.Route(), provider.calls)
	}
	if err = d.Send([]byte("fresh-media")); err != nil || provider.d.sent != 1 {
		t.Fatal("media replay or missing fresh send", err, provider.d.sent)
	}
	if all := e.Snapshot(); len(all) != 1 || all[0].Route.RelayID != "VPS-01" {
		t.Fatal(all)
	}
}
func TestUDPHealthCacheIsNetworkAndApplicationScoped(t *testing.T) {
	e := New(8)
	f := Flow{ApplicationID: "discord", Network: "ISP-a", Destination: netip.MustParseAddrPort("203.0.113.1:19000")}
	e.udpObserved(f, true)
	if !e.udpCached(f, time.Now()) {
		t.Fatal("missing endpoint cache")
	}
	other := f
	other.Network = "ISP-b"
	if e.udpCached(other, time.Now()) {
		t.Fatal("cache crossed network")
	}
	other = f
	other.ApplicationID = "chrome"
	if e.udpCached(other, time.Now()) {
		t.Fatal("cache crossed application")
	}
	if e.udpCached(f, time.Now().Add(3*time.Minute)) {
		t.Fatal("cache did not expire")
	}
}
func TestPinnedDecisionDoesNotRunApplicationAUTOSelectorAgain(t *testing.T) {
	addr, close, err := echo.UDP()
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	e := New(4)
	e.SetPolicy("app", Policy{Auto: true})
	e.SetAutoSelector(func(Flow) Policy { t.Error("pinned decision selected a second time"); return Policy{Block: true} })
	f := Flow{PID: 1, ProcessPath: "app.exe", ApplicationID: "app", Source: netip.MustParseAddrPort("127.0.0.1:1220"), Destination: netip.MustParseAddrPort(addr.String()), PinnedPolicy: &Policy{}}
	d, err := e.OpenUDP(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
}

type socketPollTimeout struct{}

func (socketPollTimeout) Error() string   { return "socket deadline elapsed before context timer" }
func (socketPollTimeout) Timeout() bool   { return true }
func (socketPollTimeout) Temporary() bool { return true }

type pollDatagram struct{ closed bool }

func (p *pollDatagram) Send([]byte) error                       { return nil }
func (p *pollDatagram) Receive(context.Context) ([]byte, error) { return nil, socketPollTimeout{} }
func (p *pollDatagram) Close() error                            { p.closed = true; return nil }
func TestNativeSocketPollTimeoutIsNotDirectFailure(t *testing.T) {
	for _, state := range []string{DirectProbation, DirectConfirmed} {
		current := &pollDatagram{}
		d := &AdaptiveUDP{current: current, health: udpCadence{state: state, started: time.Now()}, deadline: 3 * time.Second}
		_, err := d.Receive(context.Background())
		if !errors.Is(err, context.DeadlineExceeded) || current.closed || d.transitioned || d.Reason() != "" {
			t.Fatal("poll timeout became a routing failure", state, err, d.reason)
		}
	}
}
