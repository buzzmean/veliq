//go:build windows

package windowsplatform

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// dialBoundIPv4 registers the exact source tuple before Go emits a SYN. Never
// bind inside Dialer.Control: Go binds LocalAddr after Control and ConnectEx
// binds again when LocalAddr is nil, so a manual bind fails with WSAEINVAL.
// Reserve an ephemeral port, release it, then let Go perform the ONLY bind on
// the outbound socket. An intervening port collision has no SYN/payload and is
// retried at most twice with a new port; other errors are never retried. Go owns
// the socket, IOCP, cancellation, half-close and all resource cleanup normally.
func dialBoundIPv4(parent context.Context, source netip.Addr, dest netip.AddrPort, bound func(netip.AddrPort) error) (net.Conn, error) {
	return dialBoundIPv4Options(parent, source, dest, bound, false)
}

// TCP_TIMESTAMPS=10 is a documented Winsock per-socket option. Only explicitly
// selected LOCAL catalog sockets request it, before connect; no netsh/global change.
func dialBoundIPv4Options(parent context.Context, source netip.Addr, dest netip.AddrPort, bound func(netip.AddrPort) error, timestamps bool) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if !source.Is4() || !dest.Addr().Is4() {
		return nil, errors.New("bound IPv4 socket required")
	}
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		local, err := reserveIPv4Port(source)
		if err != nil {
			return nil, err
		}
		dialer := net.Dialer{LocalAddr: net.TCPAddrFromAddrPort(local), ControlContext: func(ctx context.Context, network, address string, raw syscall.RawConn) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if timestamps {
				var optionError error
				if e := raw.Control(func(fd uintptr) { optionError = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_TCP, 10, 1) }); e != nil {
					return e
				}
				if optionError != nil {
					return os.NewSyscallError("LOCAL_TCP_TIMESTAMPS_UNAVAILABLE", optionError)
				}
			}
			return bound(local)
		}}
		conn, err := dialer.DialContext(ctx, "tcp4", dest.String())
		if err == nil {
			return conn, nil
		}
		if !errors.Is(err, windows.WSAEADDRINUSE) {
			return nil, err
		}
	}
	return nil, errors.New("bounded upstream source-port collision")
}

// Reserve a port without ever listening or emitting traffic on the interface.
// The raw socket has no pending I/O and is always released with closesocket.
func reserveIPv4Port(source netip.Addr) (netip.AddrPort, error) {
	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		return netip.AddrPort{}, os.NewSyscallError("reserve_socket", err)
	}
	defer windows.Closesocket(fd)
	if err = windows.Bind(fd, &windows.SockaddrInet4{Addr: source.As4()}); err != nil {
		return netip.AddrPort{}, os.NewSyscallError("reserve_bind", err)
	}
	address, err := windows.Getsockname(fd)
	if err != nil {
		return netip.AddrPort{}, os.NewSyscallError("reserve_getsockname", err)
	}
	local, ok := address.(*windows.SockaddrInet4)
	if !ok {
		return netip.AddrPort{}, errors.New("reserved IPv4 tuple unavailable")
	}
	return netip.AddrPortFrom(source, uint16(local.Port)), nil
}
