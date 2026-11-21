//go:build !windows

package windowsplatform

import (
	"context"
	"net"
	"net/netip"
)

func LookupTCPPeer(netip.AddrPort, netip.AddrPort) (ProcessIdentity, error) {
	return ProcessIdentity{}, ErrUnavailable
}
func (*WinDivertBackend) OpenBrowserLocalTCP(context.Context, ProcessIdentity, netip.AddrPort, netip.AddrPort, Decision) (net.Conn, error) {
	return nil, ErrUnavailable
}
func (*WinDivertBackend) BrowserTransformApplied(ProcessIdentity, netip.AddrPort, netip.AddrPort) bool {
	return false
}

func ProcessUserSID(ProcessIdentity) (string, error) { return "", ErrUnavailable }

func ChromeProxyPolicyActive(string, string) bool { return false }

func (*WinDivertBackend) OpenBrowserNativeTCP(context.Context, ProcessIdentity, netip.AddrPort, netip.AddrPort, Decision) (net.Conn, error) {
	return nil, ErrUnavailable
}
