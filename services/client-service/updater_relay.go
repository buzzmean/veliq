package clientservice

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/buzzmean/veliq/core/routing"
)

// relayHTTPClient fetches updates through the VELIQ relay, for networks that
// throttle GitHub release downloads. Integrity does not depend on the path:
// the manifest is signed and the Setup is bound by size and SHA-256.
func (c *Controller) relayHTTPClient() *http.Client {
	exe, _ := os.Executable()
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("UPDATE_RELAY_DNS_FAILED")
		}
		// A reserved loopback tuple keeps the engine's per-flow bookkeeping unique.
		reserved, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		defer reserved.Close()
		policy := &routing.Policy{Route: routing.Route{RelayID: primaryRelayID}, BlockOnFailure: true}
		return c.Engine.OpenTCP(ctx, routing.Flow{Protocol: "tcp", Source: reserved.Addr().(*net.TCPAddr).AddrPort(), Destination: netip.AddrPortFrom(ips[0].Unmap(), uint16(port)), PID: uint32(os.Getpid()), ProcessPath: exe, ApplicationID: "veliq-updater", PinnedPolicy: policy})
	}
	return &http.Client{Timeout: 30 * time.Minute, Transport: &http.Transport{DialContext: dial, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 15 * time.Second}}
}
