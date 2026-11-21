package relay

import (
	"net/netip"
	"testing"
)

// Default (public-only) destination policy must carry the blocked services the
// built-in profiles send through the relay. No port filtering exists in the policy.
func TestPublicOnlyPolicyAllowsTelegramAndBlockedServiceAddresses(t *testing.T) {
	s := &Server{config: Config{}}
	for _, a := range []string{"149.154.160.1", "149.154.167.51", "149.154.175.254", "91.108.4.1", "91.108.56.130", "160.79.104.10", "104.18.39.21"} {
		if !s.allowed(netip.MustParseAddr(a)) {
			t.Fatalf("%s rejected by public-only relay policy", a)
		}
	}
	for _, a := range []string{"10.0.0.5", "192.168.88.1", "127.0.0.1", "169.254.1.1", "100.64.0.1"} {
		if s.allowed(netip.MustParseAddr(a)) {
			t.Fatalf("%s must stay forbidden", a)
		}
	}
	// A controlled-CIDR deployment (the example.env default) restricts to the list.
	s.config.Allow = []netip.Prefix{netip.MustParsePrefix("2.56.177.4/32")}
	if s.allowed(netip.MustParseAddr("149.154.167.51")) {
		t.Fatal("cidrs mode must not allow unlisted destinations")
	}
}
