package controlclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/buzzmean/neexitlag/core/optimizer"
	"github.com/buzzmean/neexitlag/core/security"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSignedConfigRealHTTPAndOutage(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	raw, _ := security.Sign("config", "root", key, security.Config{Version: 1, GeneratedAt: now, ExpiresAt: now.Add(time.Hour), RoutingParameters: optimizer.DefaultParameters()})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(raw) }))
	client := &Client{BaseURL: server.URL, Cache: security.NewConfigCache(map[string]ed25519.PublicKey{"root": pub}, "")}
	if _, e := client.Config(context.Background()); e != nil {
		t.Fatal(e)
	}
	server.Close()
	if cfg, e := client.Config(context.Background()); e != nil || cfg.Version != 1 {
		t.Fatal("LKG outage", e)
	}
	client.BaseURL = "http://example.com"
	if _, e := client.Ticket(context.Background(), "FRA"); e == nil {
		t.Fatal("missing device accepted")
	}
}
