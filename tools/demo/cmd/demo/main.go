package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/buzzmean/veliq/tools/demo"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8099", "loopback-only demo HTTP address")
	flag.Parse()
	host, _, e := net.SplitHostPort(*addr)
	if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		fmt.Fprintln(os.Stderr, "demo must bind a loopback IP")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	lab, e := demo.New(ctx)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	defer lab.Close()
	server := &http.Server{Addr: *addr, Handler: lab.Handler(*addr), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		stop, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		server.Shutdown(stop)
	}()
	fmt.Printf("neexitlag local demo: http://%s\nReal loopback traffic; DIRECT path has deterministic delay/loss. No Windows interception.\n", *addr)
	if e = server.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
