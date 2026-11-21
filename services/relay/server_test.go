package relay

import (
	"net/netip"
	"testing"
)

func TestDefaultEgressPolicy(t *testing.T) {
	s := &Server{}
	for _, a := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "224.0.0.1", "0.0.0.0", "240.0.0.1", "::1", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1", "64:ff9b::a00:1", "2002:a00:1::1", "::ffff:127.0.0.1"} {
		if s.allowed(netip.MustParseAddr(a)) {
			t.Fatalf("allowed special address %s", a)
		}
	}
	for _, a := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !s.allowed(netip.MustParseAddr(a)) {
			t.Fatalf("rejected public address %s", a)
		}
	}
}
