package clientservice

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/browserproxy"
	wp "github.com/buzzmean/veliq/platform/windows"
)

func TestNativeBrowserTLSObservesRelayBeforeClientDelivery(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	n := &c.browser.native
	id, err := n.begin(browserproxy.Request{Owner: browserproxy.Owner{Profile: "chrome"}, Host: "web.telegram.org", Ingress: "PAC_NATIVE_UPSTREAM"}, wp.Tuple{Protocol: "tcp", Destination: netip.MustParseAddrPort("149.154.167.40:443")})
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer b.Close()
	conn := newNativeBrowserConn(a, n, id)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	// This read is the actual upstream boundary; no PAC/browser reader is required.
	sent := make(chan error, 1)
	go func() { _, e := b.Write([]byte{21, 3, 3, 0, 2}); sent <- e }()
	h := make([]byte, 5)
	if _, err := io.ReadFull(conn, h); err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	snap := c.nativeSnapshot()
	if len(snap.Records) != 1 || snap.Records[0].TLS == nil || snap.Records[0].TLS.Origin.State != "TLS_HEADER_ONLY" || snap.Records[0].TLS.Origin.Bytes != 5 || snap.Records[0].TLS.Origin.AlertLevel != 0 {
		t.Fatal(snap)
	}
	// Returned slices cannot mutate the live observer.
	snap.Records[0].TLS.Origin.Records[0].Length = 999
	if c.nativeSnapshot().Records[0].TLS.Origin.Records[0].Length != 2 {
		t.Fatal("snapshot alias")
	}
}
