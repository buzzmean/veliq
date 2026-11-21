package routing

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestHotAttachAbortOnlyTargetFlowAndReleaseAccounting(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	engine := New(4)
	target := netip.MustParseAddrPort(listener.Addr().String())
	open := func(port uint16) net.Conn {
		f := Flow{PID: uint32(port), ApplicationID: "app", ProcessPath: "app.exe", Source: netip.MustParseAddrPort("127.0.0.1:1234"), Destination: target, PinnedPolicy: &Policy{}}
		f.Source = netip.AddrPortFrom(f.Source.Addr(), port)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		c, e := engine.OpenTCP(ctx, f)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	selected := open(12001)
	control := open(12002)
	a, ok := selected.(interface{ Abort() error })
	if !ok {
		t.Fatal("tracked native flow cannot abort")
	}
	if err = a.Abort(); err != nil {
		t.Fatal(err)
	}
	if len(engine.Snapshot()) != 1 {
		t.Fatal("retirement disrupted unrelated flow or leaked accounting")
	}
	control.SetDeadline(time.Now().Add(time.Second))
	if _, err = control.Write([]byte("live")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err = io.ReadFull(control, reply); err != nil || string(reply) != "live" {
		t.Fatal("unrelated socket reset", err)
	}
	selected.Close()
	if len(engine.Snapshot()) != 1 {
		t.Fatal("duplicate close removed unrelated flow")
	}
}
