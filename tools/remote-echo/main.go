package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/buzzmean/veliq/internal/e2eprobe"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:40000", "authenticated IPv4 UDP echo")
	tcpListen := flag.String("tcp-listen", "", "optional authenticated TCP echo on the controlled test target")
	token := flag.String("token-file", "", "private echo token")
	metrics := flag.String("metrics", "127.0.0.1:9092", "local metrics/health")
	flag.Parse()
	key, e := e2eprobe.Token(*token)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	addr, e := net.ResolveUDPAddr("udp4", *listen)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	conn, e := net.ListenUDP("udp4", addr)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer conn.Close()
	stats := &e2eprobe.EchoStats{}
	if *tcpListen != "" {
		listener, err := net.Listen("tcp4", *tcpListen)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer listener.Close()
		go func() {
			if err := e2eprobe.ServeTCP(ctx, listener, key, stats); err != nil {
				fmt.Fprintln(os.Stderr, "TCP echo listener failed")
			}
		}()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "neexitlag_echo_accepted_total %d\nneexitlag_echo_rejected_total %d\n", stats.Accepted.Load(), stats.Rejected.Load())
	})
	server := &http.Server{Addr: *metrics, Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	go server.ListenAndServe()
	defer server.Close()
	fmt.Println("Authenticated UDP echo ready; no payload logging.")
	if e = e2eprobe.Serve(ctx, conn, key, stats); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
