package main

import (
	"context"
	"encoding/pem"
	"github.com/buzzmean/neexitlag/internal/webprobe"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRealHTTPHTTPSH2AndWebSocket(t *testing.T) {
	token := "test-controlled-endpoint-token-123456"
	plain := httptest.NewServer(webprobe.Handler(token))
	defer plain.Close()
	secure := httptest.NewUnstartedServer(webprobe.Handler(token))
	secure.EnableHTTP2 = true
	secure.StartTLS()
	defer secure.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: secure.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	for _, c := range []struct{ url, mode, ca string }{{plain.URL, "http", ""}, {secure.URL, "http", ca}, {secure.URL, "http2", ca}, {secure.URL, "websocket", ca}} {
		t.Run(c.mode+c.url[:5], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			r := probe(ctx, c.url, token, c.ca, c.mode)
			if !r.Success || r.Source != "127.0.0.1" || r.Destination == "" || r.Finished.Before(r.Started) {
				t.Fatalf("%+v", r)
			}
		})
	}
	r := probe(context.Background(), secure.URL, token, "", "http")
	if r.Success {
		t.Fatal("untrusted TLS accepted")
	}
	r = probe(context.Background(), plain.URL, "wrong-token", "", "http")
	if r.Success {
		t.Fatal("unauthorized accepted")
	}
}
