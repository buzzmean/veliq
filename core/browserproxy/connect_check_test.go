package browserproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestTransportCheckRealCONNECTTLSHTTPAndFixedTarget(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Error("wrong path")
		}
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer origin.Close()
	target := strings.TrimPrefix(origin.URL, "https://")
	token := strings.Repeat("a", 64)
	proxy, err := Listen(context.Background(), Config{TransportCheck: func() (string, string) { return target, token }, Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (Owner, error) {
		return Owner{}, errors.New("ordinary owner rejected")
	}, Plan: func(context.Context, Request) (Plan, error) {
		t.Error("probe reached application planner")
		return Plan{}, errors.New("no")
	}, Open: func(context.Context, Request, Plan) (net.Conn, error) { return nil, errors.New("no") }})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	cfg := &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}
	if err = ProbeConnect(context.Background(), proxy.Address(), target, token, cfg); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		target, token string
		cfg           *tls.Config
	}{{target, strings.Repeat("b", 64), cfg}, {"127.0.0.1:1", token, cfg}, {target, token, &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "example.com"}}} {
		if err = ProbeConnect(context.Background(), proxy.Address(), test.target, test.token, test.cfg); err == nil {
			t.Fatal("unauthorized or unverified probe accepted")
		}
	}
	if len(proxy.Snapshot().Records) != 0 {
		t.Fatal("self check fabricated browser evidence")
	}
}
