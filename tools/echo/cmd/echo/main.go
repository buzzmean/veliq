package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	addr := flag.String("listen", ":9000", "development UDP/TCP echo listener; keep on isolated lab network")
	flag.Parse()
	udp, e := net.ListenPacket("udp", *addr)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	defer udp.Close()
	tcp, e := net.Listen("tcp", *addr)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	defer tcp.Close()
	go func() {
		b := make([]byte, 1200)
		for {
			n, a, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			udp.WriteTo(b[:n], a)
		}
	}()
	go func() {
		sem := make(chan struct{}, 32)
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			select {
			case sem <- struct{}{}:
				go func() { defer func() { <-sem }(); defer c.Close(); io.Copy(c, c) }()
			default:
				c.Close()
			}
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
