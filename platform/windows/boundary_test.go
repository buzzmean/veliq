package windowsplatform

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestPIDReuseAndEndpointDeletion(t *testing.T) {
	a := NewAssociations(1)
	tuple := Tuple{"udp", netip.MustParseAddrPort("10.0.0.1:123"), netip.MustParseAddrPort("1.1.1.1:456")}
	id := ProcessIdentity{PID: 42, Path: "game.exe", CreationTime: 1}
	if !a.Put(Association{id, tuple, 10}) {
		t.Fatal("put")
	}
	if _, ok := a.Get(tuple, id); !ok {
		t.Fatal("lookup")
	}
	reused := id
	reused.CreationTime = 2
	if _, ok := a.Get(tuple, reused); ok {
		t.Fatal("PID reuse accepted")
	}
	a.Delete(tuple, 9)
	if _, ok := a.Get(tuple, id); !ok {
		t.Fatal("stale close removed current endpoint")
	}
	a.Delete(tuple, 10)
	if _, ok := a.Get(tuple, id); ok {
		t.Fatal("close failed")
	}
}
func TestPacketReplyAndFragmentBypass(t *testing.T) {
	p := make([]byte, 31)
	p[0] = 0x45
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], 31)
	copy(p[12:16], []byte{10, 0, 0, 1})
	copy(p[16:20], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(p[20:22], 123)
	binary.BigEndian.PutUint16(p[22:24], 456)
	binary.BigEndian.PutUint16(p[24:26], 11)
	copy(p[28:], "abc")
	tuple, data, e := ParseUDP(p)
	if e != nil || string(data) != "abc" {
		t.Fatal(e)
	}
	reply, e := ReplyUDP(p, []byte("xyz"))
	if e != nil {
		t.Fatal(e)
	}
	reverse, _, e := ParseUDP(reply)
	if e != nil || reverse.Source != tuple.Destination || reverse.Destination != tuple.Source {
		t.Fatal("reply tuple")
	}
	p[6] = 0x20
	if _, _, e = ParseUDP(p); e == nil {
		t.Fatal("fragment captured")
	}
}
