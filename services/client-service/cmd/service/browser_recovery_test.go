package main

import (
	"context"
	"github.com/buzzmean/veliq/core/browserproxy"
	"net"
	"net/netip"
	"os"
	"testing"
)

// Only a TEST BINARY can select the controlled target resolver. The production
// CLI has no test DNS/dial configuration and always uses the system resolver.
func TestChromeRecoveryChildProcess(t *testing.T) {
	if os.Getenv("NEEXITLAG_TEST_RECOVERY_CHILD") != "1" {
		t.Skip("native Chrome fixture child only")
	}
	err := runBrowserRecoveryWithDial(context.Background(), 0, func(ctx context.Context, q browserproxy.Request) (net.Conn, error) {
		target := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), q.Port)
		return (&net.Dialer{}).DialContext(ctx, "tcp4", target.String())
	})
	if err != nil {
		t.Fatal(err)
	}
}
