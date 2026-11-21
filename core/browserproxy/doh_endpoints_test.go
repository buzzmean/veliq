package browserproxy

import (
	"net/netip"
	"testing"
)

func TestKnownDoHEndpointsExactNamesAddressesAndPorts(t *testing.T) {
	for _, tc := range []struct {
		host, dst string
		want      bool
	}{
		{"dns.google", "142.250.1.1:443", true}, {"cloudflare-dns.com", "1.1.1.1:443", true},
		{"", "8.8.4.4:443", true}, {"", "9.9.9.9:443", true}, {"", "[2606:4700:4700::1111]:443", true},
		{"doh.familyshield.opendns.com", "8.9.10.11:443", true}, {"chromium.dns.nextdns.io", "8.9.10.11:443", true},
		{"dns.google.evil.test", "87.240.137.208:443", false}, {"vk.ru", "87.240.137.208:443", false},
		{"www.google.com", "142.250.1.1:443", false}, {"dns.google", "8.8.8.8:53", false}, {"", "1.1.1.1:80", false},
	} {
		if got := KnownDoHEndpoint(tc.host, netip.MustParseAddrPort(tc.dst)); got != tc.want {
			t.Fatal(tc, got)
		}
	}
}
