package integration

import (
	"bytes"
	"context"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/tools/echo"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestSimultaneousDirectRelayPinning(t *testing.T) {
	r, c, _ := setup(t, 5*time.Second)
	a, close, err := echo.UDP()
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	e := routing.New(10)
	e.SetRelay("lab", c)
	e.SetPolicy("game", routing.Policy{Route: routing.Route{RelayID: "lab"}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f := routing.Flow{Source: netip.MustParseAddrPort("127.0.0.1:30001"), Destination: netip.MustParseAddrPort(a.String()), PID: 123, ProcessPath: "game.exe", ApplicationID: "game"}
	relayFlow, err := e.OpenUDP(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	defer relayFlow.Close()
	f.Source = netip.MustParseAddrPort("127.0.0.1:30002")
	f.PID = 456
	f.ProcessPath = "browser.exe"
	f.ApplicationID = "browser"
	directFlow, err := e.OpenUDP(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	defer directFlow.Close()
	e.SetPolicy("game", routing.Policy{})
	var wg sync.WaitGroup
	for _, d := range []routing.Datagram{relayFlow, directFlow} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if err := d.Send([]byte("flow")); err != nil {
					t.Error(err)
					return
				}
				b, err := d.Receive(ctx)
				if err != nil || string(b) != "flow" {
					t.Errorf("%q %v", b, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if r.Metrics.UDPPackets.Load() != 20 {
		t.Fatalf("relay got %d packets, expected only selected flow", r.Metrics.UDPPackets.Load())
	}
	routes := map[string]string{}
	for _, flow := range e.Snapshot() {
		routes[flow.ApplicationID] = flow.Route.RelayID
	}
	if routes["game"] != "lab" || routes["browser"] != "" {
		t.Fatal("flow pinning", routes)
	}
	f.Source = netip.MustParseAddrPort("127.0.0.1:30003")
	f.PID = 123
	f.ProcessPath = "game.exe"
	f.ApplicationID = "game"
	newFlow, err := e.OpenUDP(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	defer newFlow.Close()
	for _, flow := range e.Snapshot() {
		if flow.Source == f.Source && !flow.Route.Direct() {
			t.Fatal("new policy not applied")
		}
	}
}
func TestConcurrentTCPDirectRelay(t *testing.T) {
	r, c, _ := setup(t, 5*time.Second)
	a, close, err := echo.TCP()
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	e := routing.New(10)
	e.SetRelay("lab", c)
	e.SetPolicy("game", routing.Policy{Route: routing.Route{RelayID: "lab"}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i, app := range []string{"game", "browser"} {
		f := routing.Flow{Source: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(31000+i)), Destination: netip.MustParseAddrPort(a.String()), PID: uint32(i + 1), ProcessPath: app + ".exe", ApplicationID: app}
		conn, err := e.OpenTCP(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		p := bytes.Repeat([]byte(app), 100)
		if _, err = conn.Write(p); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, len(p))
		if _, err = io.ReadFull(conn, b); err != nil || !bytes.Equal(b, p) {
			t.Fatal("TCP echo", err)
		}
	}
	if r.Metrics.TCPConnections.Load() != 1 {
		t.Fatal("browser TCP was relayed")
	}
}

func TestRelayFailureNewFlowFallback(t *testing.T) {
	r, c, _ := setup(t, 5*time.Second)
	a, close, err := echo.UDP()
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	e := routing.New(10)
	e.SetRelay("lab", c)
	e.SetPolicy("game", routing.Policy{Route: routing.Route{RelayID: "lab"}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f := routing.Flow{Source: netip.MustParseAddrPort("127.0.0.1:32001"), Destination: netip.MustParseAddrPort(a.String()), PID: 123, ProcessPath: "game.exe", ApplicationID: "game"}
	old, err := e.OpenUDP(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	r.Close()
	select {
	case <-c.Done():
	case <-ctx.Done():
		t.Fatal("session remained active")
	}
	if _, err = old.Receive(ctx); err == nil {
		t.Fatal("existing relay flow silently migrated")
	}
	f.Source = netip.MustParseAddrPort("127.0.0.1:32002")
	fresh, err := e.OpenUDP(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err = fresh.Send([]byte("fallback")); err != nil {
		t.Fatal(err)
	}
	b, err := fresh.Receive(ctx)
	if err != nil || string(b) != "fallback" {
		t.Fatal("DIRECT fallback failed", err)
	}
	for _, flow := range e.Snapshot() {
		if flow.Source == f.Source && !flow.Route.Direct() {
			t.Fatal("fallback route not recorded")
		}
	}
}
