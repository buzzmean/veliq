//go:build windows

package windowsplatform

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/browserproxy"
	"golang.org/x/net/dns/dnsmessage"
)

func TestBrowserDNSNativeUDPReplyAndBoundedCapacity(t *testing.T) {
	b, _ := captureFixture(t)
	b.dnsSlots = make(chan struct{}, 1)
	name, _ := dnsmessage.NewName("www.youtube.com.")
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 7}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	query, _ := m.Pack()
	m.Response = true
	answer, _ := m.Pack()
	packet := make([]byte, 28+len(query))
	packet[0] = 0x45
	packet[9] = 17
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	copy(packet[12:], []byte{192, 168, 88, 10})
	copy(packet[16:], []byte{8, 8, 8, 8})
	binary.BigEndian.PutUint16(packet[20:], 50100)
	binary.BigEndian.PutUint16(packet[22:], 53)
	binary.BigEndian.PutUint16(packet[24:], uint16(8+len(query)))
	copy(packet[28:], query)
	tuple, _, err := ParseUDP(packet)
	if err != nil {
		t.Fatal(err)
	}
	replies := make(chan []byte, 2)
	b.packetWriter = func(p []byte, _ [80]byte) error { replies <- append([]byte(nil), p...); return nil }
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	d := Decision{DNSExchange: func(context.Context, []byte) ([]byte, error) { close(entered); <-release; return answer, nil }}
	id := ProcessIdentity{PID: 42, CreationTime: 1, Path: `C:\Apps\chrome.exe`}
	b.handleBrowserDNS(nil, id, tuple, packet, query, [80]byte{}, d)
	<-entered
	b.handleBrowserDNS(nil, id, tuple, packet, query, [80]byte{}, d)
	select {
	case p := <-replies:
		replyTuple, wire, e := ParseUDP(p)
		if e != nil || replyTuple.Source != tuple.Destination || replyTuple.Destination != tuple.Source {
			t.Fatal("DNS tuple spoofed", replyTuple, e)
		}
		var fail dnsmessage.Message
		if fail.Unpack(wire) != nil || fail.RCode != dnsmessage.RCodeServerFailure {
			t.Fatal("capacity leaked query", fail)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS capture loop blocked on worker")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case p := <-replies:
		_, wire, e := ParseUDP(p)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = browserproxy.ValidateDNSResponse(query, wire); e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("missing DNS response")
	}
	b.wg.Wait()
	if tuple.Destination != netip.MustParseAddrPort("8.8.8.8:53") {
		t.Fatal(tuple)
	}
}
