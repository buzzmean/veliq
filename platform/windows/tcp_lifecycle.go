package windowsplatform

import (
	"errors"
	"github.com/buzzmean/neexitlag/core/transport"
	"io"
	"net"
)

func tcpPacketDropCause(mode string) string {
	if mode == "closed" {
		return "TCP_TEARDOWN_TAIL"
	}
	return "POLICY_BLOCK"
}

// App-side reset/close and a graceful upstream EOF are normal TCP lifecycle.
// A broken upstream read or write is a transport failure even after prior replies.
func tcpCopyFailure(event string, readErr, writeErr error, stopping bool) string {
	if stopping {
		return ""
	}
	for _, err := range []error{readErr, writeErr} {
		switch transport.AuthorizationEndReason(err) {
		case "authorization_lease_expired":
			return "TCP_AUTHORIZATION_LEASE_EXPIRED"
		case "device_revoked":
			return "TCP_DEVICE_REVOKED"
		}
	}
	if event == "relay" && writeErr != nil {
		return "TCP_RELAY_WRITE_FAILED"
	}
	if event == "reply" && readErr != nil && !errors.Is(readErr, io.EOF) {
		return "TCP_RELAY_READ_FAILED"
	}
	return ""
}
func tcpNormalEnd(event string, readErr, writeErr error) bool {
	return (event == "reply" && errors.Is(readErr, io.EOF)) || (event == "relay" && readErr != nil && !errors.Is(readErr, io.EOF)) || (event == "reply" && writeErr != nil)
}

// Abortive close prevents a pre-policy native proxy send buffer being flushed
// after a route edit. Authenticated stream wrappers keep their existing close.
func abortHotTCP(c net.Conn) {
	if c == nil {
		return
	}
	if a, ok := c.(interface{ Abort() error }); ok {
		_ = a.Abort()
		return
	}
	if a, ok := c.(interface{ SetLinger(int) error }); ok {
		_ = a.SetLinger(0)
	}
	_ = c.Close()
}
