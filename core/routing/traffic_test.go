package routing

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type accountingRelay struct{}

func (*accountingRelay) OpenTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", dst.String())
}
func (*accountingRelay) OpenDatagram(context.Context, netip.AddrPort) (Datagram, error) {
	return nil, context.Canceled
}
func TestRelayAccountingMetadataLiveContinuityAndNoDirectCounts(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	engine := New(8)
	engine.SetRelay("relay", &accountingRelay{})
	engine.SetPolicy("chrome", Policy{Route: Route{RelayID: "relay"}, BlockOnFailure: true})
	var tx, rx atomic.Uint64
	engine.SetTrafficObserver(func(f Flow, sent, received uint64) {
		_ = engine.Snapshot()
		if f.OriginDomain != "video.googlevideo.com" || f.OriginService != "youtube-media" || f.Route.RelayID != "relay" {
			t.Error("metadata/pinned route lost", f)
		}
		tx.Add(sent)
		rx.Add(received)
	})
	flow := Flow{PID: 42, ProcessPath: "chrome.exe", ApplicationID: "chrome", Source: netip.MustParseAddrPort("127.0.0.1:12345"), Destination: netip.MustParseAddrPort(l.Addr().String()), OriginDomain: "video.googlevideo.com", OriginService: "youtube-media", OriginReason: "LOCAL_NOT_CONFIRMED"}
	for _, direct := range []bool{false, true} {
		if direct {
			flow.PID = 0
			flow.Source = netip.MustParseAddrPort("127.0.0.1:12346")
		}
		c, e := engine.OpenTCP(context.Background(), flow)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		for n := 0; n < 2; n++ {
			if _, e = c.Write([]byte("live")); e != nil {
				t.Fatal(e)
			}
			b := make([]byte, 4)
			if _, e = io.ReadFull(c, b); e != nil || string(b) != "live" {
				t.Fatal(e)
			}
		}
		c.Close()
	}
	if tx.Load() != 8 || rx.Load() != 8 {
		t.Fatal("DIRECT counted or relay lost bytes", tx.Load(), rx.Load())
	}
}
