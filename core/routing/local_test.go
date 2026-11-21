package routing

import (
	"net/netip"
	"testing"
)

func TestLocalDestinationCoversLANAndLeavesInternetAlone(t *testing.T) {
	for _, a := range []string{
		"192.168.88.1", "10.0.0.5", "172.16.3.4", "172.31.255.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0",
		"224.0.0.251", "255.255.255.255", "198.18.0.1", "192.0.0.5", "240.0.0.1",
		"::1", "fe80::1", "fc00::1", "ff02::fb", "::ffff:192.168.1.1",
	} {
		if !netip.MustParseAddr(a).IsValid() || !LocalDestination(netip.MustParseAddr(a)) {
			t.Fatalf("%s must be local", a)
		}
	}
	for _, a := range []string{"8.8.8.8", "160.79.104.10", "104.18.39.21", "149.154.167.51", "91.108.56.130", "172.32.0.1", "100.128.0.1", "2606:4700::1111",
		"203.0.113.1", "198.51.100.7", "192.0.2.9"} { // documentation ranges stay ordinary
		if LocalDestination(netip.MustParseAddr(a)) {
			t.Fatalf("%s must not be local", a)
		}
	}
	if !LocalDestination(netip.Addr{}) {
		t.Fatal("an invalid destination must never get a relay path")
	}
}
