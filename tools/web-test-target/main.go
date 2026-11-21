// Controlled destination endpoint for external TCP/HTTPS acceptance.
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/buzzmean/neexitlag/internal/webprobe"
	"github.com/quic-go/quic-go/http3"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("listen", ":40080", "HTTP listen")
	tlsAddr := flag.String("tls-listen", ":40443", "HTTPS listen")
	quicAddr := flag.String("quic-listen", "", "optional HTTP/3 UDP listen, normally same port as HTTPS")
	cert := flag.String("cert", "", "destination certificate PEM")
	key := flag.String("key", "", "destination private key PEM")
	tokenFile := flag.String("token-file", "", "private token file, at least 24 characters")
	flag.Parse()
	raw, e := os.ReadFile(*tokenFile)
	if e != nil {
		fmt.Fprintln(os.Stderr, "read token:", e)
		os.Exit(1)
	}
	token := strings.TrimSpace(string(raw))
	if len(token) < 24 || len(token) > 128 {
		fmt.Fprintln(os.Stderr, "invalid token length")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	servers := []*http.Server{}
	errs := make(chan error, 3)
	handler := webprobe.Handler(token)
	h3 := &http3.Server{Addr: *quicAddr, Handler: handler, MaxHeaderBytes: 8192, IdleTimeout: 10 * time.Second}

	var wg sync.WaitGroup
	if *quicAddr != "" {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- h3.ListenAndServeTLS(*cert, *key) }()
	}
	for _, a := range []struct {
		address string
		tls     bool
	}{{*addr, false}, {*tlsAddr, true}} {
		if a.address == "" {
			continue
		}
		s := &http.Server{Addr: a.address, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if *quicAddr != "" {
				_ = h3.SetQUICHeaders(w.Header())
			}
			handler.ServeHTTP(w, r)
		}), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
		servers = append(servers, s)
		wg.Add(1)
		go func(tls bool) {
			defer wg.Done()
			if tls {
				errs <- s.ListenAndServeTLS(*cert, *key)
			} else {
				errs <- s.ListenAndServe()
			}
		}(a.tls)
	}
	var failure error
	select {
	case <-ctx.Done():
	case failure = <-errs:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if *quicAddr != "" {
		_ = h3.Close()
	}
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
	}
	wg.Wait()
	if failure != nil && failure != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, failure)
		os.Exit(1)
	}
}
