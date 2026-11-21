// The lab runs real loopback echo traffic through an ephemeral authenticated relay.
package main

import (
	"context"
	"fmt"
	"github.com/buzzmean/neexitlag/core/transport"
	"github.com/buzzmean/neexitlag/services/relay"
	"github.com/buzzmean/neexitlag/tools/echo"
	"github.com/buzzmean/neexitlag/tools/labcert"
	"io"
	"net/netip"
	"os"
	"time"
)

func run() error {
	s, c, e := labcert.Pair()
	if e != nil {
		return e
	}
	r, e := relay.Listen("127.0.0.1:0", relay.Config{TLS: s, Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	if e != nil {
		return e
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, e := transport.Dial(ctx, r.Addr().String(), c)
	if e != nil {
		return e
	}
	defer client.Close()
	u, cu, e := echo.UDP()
	if e != nil {
		return e
	}
	defer cu()
	t, ct, e := echo.TCP()
	if e != nil {
		return e
	}
	defer ct()
	f, e := client.OpenUDP(ctx, netip.MustParseAddrPort(u.String()))
	if e != nil {
		return e
	}
	defer f.Close()
	start := time.Now()
	if e = f.Send([]byte("udp")); e != nil {
		return e
	}
	b, e := f.Receive(ctx)
	if e != nil {
		return e
	}
	if string(b) != "udp" {
		return fmt.Errorf("UDP mismatch")
	}
	fmt.Printf("UDP E2E PASS RTT=%s\n", time.Since(start))
	tcp, e := client.OpenTCP(ctx, netip.MustParseAddrPort(t.String()))
	if e != nil {
		return e
	}
	defer tcp.Close()
	tcp.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = tcp.Write([]byte("tcp")); e != nil {
		return e
	}
	b = make([]byte, 3)
	if _, e = io.ReadFull(tcp, b); e != nil {
		return e
	}
	if string(b) != "tcp" {
		return fmt.Errorf("TCP mismatch")
	}
	fmt.Println("TCP E2E PASS")
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
