package routing

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/protocol"
)

func TestOpenLocalUDPUsesOnlyOriginalPeerAndFullDatagrams(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	remote := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	e := New(8)
	// This stale policy would immediately fail or use an unintended provider if
	// a capture caller accidentally used the ordinary unpinned route selector.
	e.SetPolicy("cs2", Policy{Route: Route{RelayID: "old-relay"}, BlockOnFailure: true})
	f := Flow{Protocol: "udp", PID: 42, ProcessPath: "cs2.exe", ApplicationID: "cs2",
		Source: netip.MustParseAddrPort("127.0.0.1:43007"), Destination: remote}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	d, err := e.OpenLocalUDP(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var first []byte
	for _, size := range []int{4, protocol.MaxPayload + 1, 8192, 0} {
		p := bytes.Repeat([]byte{byte(size % 233)}, size)
		if err = d.Send(p); err != nil {
			t.Fatal(err)
		}
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, size+1)
		n, src, err := peer.ReadFromUDP(buf)
		if err != nil || !bytes.Equal(p, buf[:n]) {
			t.Fatal("wrong outbound UDP", n, err)
		}
		if _, err = peer.WriteToUDP(buf[:n], src); err != nil {
			t.Fatal(err)
		}
		reply, err := d.Receive(ctx)
		if err != nil || !bytes.Equal(reply, p) {
			t.Fatal("wrong reply", len(reply), err)
		}
		if first == nil {
			first = reply
		} else if !bytes.Equal(first, []byte{4, 4, 4, 4}) {
			t.Fatal("a subsequent read changed a previously returned payload")
		}
		if size == 0 && reply == nil {
			t.Fatal("empty datagram lost")
		}
	}
	flows := e.Snapshot()
	if len(flows) != 1 || !flows[0].Route.Direct() || flows[0].Destination != remote {
		t.Fatal(flows)
	}
	if err := d.Send(make([]byte, 65508)); err == nil {
		t.Fatal("invalid IPv4 datagram allowed")
	}
	f.PinnedPolicy = &Policy{Block: true}
	if _, err = e.OpenLocalUDP(ctx, f); err == nil {
		t.Fatal("blocked flow admitted")
	}
}
