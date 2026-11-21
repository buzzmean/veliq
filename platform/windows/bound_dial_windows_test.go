//go:build windows

package windowsplatform

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeBoundDialRegistersBeforeSYNAndRetainsSocket(t *testing.T) {
	target, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	var registered atomic.Bool
	accepted := make(chan error, 1)
	go func() {
		c, e := target.AcceptTCP()
		if e != nil {
			accepted <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if !registered.Load() {
			accepted <- errors.New("SYN before delegation registration")
			return
		}
		_, e = io.Copy(c, c)
		accepted <- e
	}()
	var bound netip.AddrPort
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, e := dialBoundIPv4(ctx, netip.MustParseAddr("127.0.0.1"), target.Addr().(*net.TCPAddr).AddrPort(), func(a netip.AddrPort) error { bound = a; registered.Store(true); return nil })
	if e != nil {
		t.Fatal(e)
	}
	if c.LocalAddr().String() != bound.String() {
		t.Fatal("bound tuple changed", c.LocalAddr(), bound)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	for i := 0; i < 3; i++ {
		if _, e = c.Write([]byte("same TCP stream")); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, len("same TCP stream"))
		if _, e = io.ReadFull(c, b); e != nil || string(b) != "same TCP stream" {
			t.Fatal(string(b), e)
		}
	}
	c.Close()
	if e = <-accepted; e != nil {
		t.Fatal(e)
	}
}
func TestNativeBoundDialCancellationAndRegistrationFailure(t *testing.T) {
	target := netip.MustParseAddrPort("127.0.0.1:1")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if c, e := dialBoundIPv4(ctx, target.Addr(), target, func(netip.AddrPort) error { called = true; return nil }); c != nil || !errors.Is(e, context.Canceled) || called {
		t.Fatal(c, e, called)
	}
	sentinel := errors.New("admission denied")
	if c, e := dialBoundIPv4(context.Background(), target.Addr(), target, func(netip.AddrPort) error { return sentinel }); c != nil || !errors.Is(e, sentinel) {
		t.Fatal(c, e)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if c, e := dialBoundIPv4(ctx, target.Addr(), target, func(netip.AddrPort) error { return nil }); c != nil || e == nil {
		t.Fatal(c, e)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("connect ignored cancellation")
	}
}

func TestNativeBoundDialRetriesOnlyPreSYNPortCollision(t *testing.T) {
	target, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	calls := 0
	var occupied *net.TCPListener
	c, e := dialBoundIPv4(context.Background(), netip.MustParseAddr("127.0.0.1"), target.Addr().(*net.TCPAddr).AddrPort(), func(a netip.AddrPort) error {
		calls++
		if calls == 1 {
			occupied, e = net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(a))
			return e
		}
		return nil
	})
	if occupied != nil {
		defer occupied.Close()
	}
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if calls != 2 {
		t.Fatal("collision did not receive one bounded retry", calls)
	}
}

func TestLocalSocketTimestampOptionDoesNotRequireBrowserRestart(t *testing.T) {
	listener, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, e := dialBoundIPv4Options(ctx, netip.MustParseAddr("127.0.0.1"), listener.Addr().(*net.TCPAddr).AddrPort(), func(netip.AddrPort) error { return nil }, true)
	if e != nil {
		t.Fatal("per-socket TCP_TIMESTAMPS unavailable", e)
	}
	defer c.Close()
	raw, e := c.(*net.TCPConn).SyscallConn()
	if e != nil {
		t.Fatal(e)
	}
	enabled := 0
	var optionError error
	if e = raw.Control(func(fd uintptr) {
		enabled, optionError = windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_TCP, 10)
	}); e != nil || optionError != nil || enabled != 1 {
		t.Fatal("per-socket timestamp option not effective", e, optionError, enabled)
	}
}
