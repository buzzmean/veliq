package routing

import (
	"context"
	"errors"
	"github.com/buzzmean/neexitlag/tools/echo"
	"net/netip"
	"testing"
	"time"
)

func TestDefaultFallbackAndBlock(t *testing.T) {
	a, close, err := echo.UDP()
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	e := New(1)
	f := Flow{Source: netip.MustParseAddrPort("127.0.0.1:1111"), Destination: netip.MustParseAddrPort(a.String()), PID: 1, ProcessPath: "game.exe", ApplicationID: "game"}
	e.SetPolicy("game", Policy{Route: Route{RelayID: "offline"}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	d, err := e.OpenUDP(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Snapshot()[0].Route.Direct() {
		t.Fatal("no DIRECT fallback")
	}
	if _, err = e.OpenUDP(ctx, f); !errors.Is(err, ErrFlowExists) {
		t.Fatal("duplicate flow")
	}
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	e.SetPolicy("game", Policy{Route: Route{RelayID: "offline"}, BlockOnFailure: true})
	if _, err = e.OpenUDP(ctx, f); err == nil {
		t.Fatal("BLOCK fallback ignored")
	}
	if len(e.Snapshot()) != 0 {
		t.Fatal("failed flow leaked")
	}
}
func TestUnknownProcessDirect(t *testing.T) {
	a, close, err := echo.UDP()
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	e := New(1)
	e.SetPolicy("game", Policy{Route: Route{RelayID: "offline"}, BlockOnFailure: true})
	f := Flow{Source: netip.MustParseAddrPort("127.0.0.1:1112"), Destination: netip.MustParseAddrPort(a.String()), ApplicationID: "game"}
	d, err := e.OpenUDP(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if !e.Snapshot()[0].Route.Direct() {
		t.Fatal("unknown PID optimized")
	}
}
