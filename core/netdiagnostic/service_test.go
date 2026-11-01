package netdiagnostic

import (
	"bytes"
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
)

func TestServiceDiagnosisSeparatesLayersWithoutPageOrPlaybackClaims(t *testing.T) {
	for _, tc := range []struct {
		p            browserproxy.ProbeResult
		layer, state string
	}{
		{browserproxy.ProbeResult{Phase: "ORIGIN_DNS", Failure: "DNS_FAILED"}, "DNS", "RESOLUTION_FAILED"},
		{browserproxy.ProbeResult{Phase: "RELAY_OR_TCP_OPEN", Failure: "CONNECTION_FAILED"}, "OPEN", "IO_FAILED"},
		{browserproxy.ProbeResult{Phase: "ORIGIN_TLS", Failure: "TLS_FAILED", Detail: "PEER_RESET"}, "TLS", "RESET_OBSERVED"},
		{browserproxy.ProbeResult{Phase: "ORIGIN_TLS", Failure: "TLS_CERTIFICATE_ERROR"}, "TLS", "CERTIFICATE_REJECTED"},
		{browserproxy.ProbeResult{Phase: "ORIGIN_BODY", Failure: "NETWORK_TIMEOUT", BodyBytes: 17000}, "TRANSFER", "BODY_STALLED_AFTER_PROGRESS"},
		{browserproxy.ProbeResult{Status: 403, BodyBytes: 100000}, "HTTP", "HTTP_DENIED_OR_ERROR"},
		{browserproxy.ProbeResult{Status: 200, BodyBytes: 65536}, "HTTP", "HTTP_CONTROL_ONLY_NOT_BULK"},
		{browserproxy.ProbeResult{Status: 200, BodyBytes: 65537}, "HTTP", "PUBLIC_BODY_TRANSFER_VERIFIED"},
		{browserproxy.ProbeResult{TLSVersion: 0x304}, "TLS", "NO_HTTP_PROOF"},
	} {
		d := DiagnoseProbe(tc.p)
		if d.Layer != tc.layer || d.State != tc.state || d.PageVerified || d.PlaybackVerified {
			t.Fatal(tc.p, d)
		}
	}
	wire := &browserproxy.TLSWireEvidence{}
	wire.Origin.ServerHelloComplete = true
	if d := DiagnoseStream("", 2000, 3000, wire); d.State != "SERVER_HELLO_ONLY" || d.PageVerified {
		t.Fatal(d)
	}
	wire.Origin.ApplicationBytes = 1024 * 1024
	if d := DiagnoseStream("", 5000, 1024*1024, wire); d.State != "ENCRYPTED_TRANSFER_NOT_PAGE_OR_PLAYBACK_PROOF" || d.PlaybackVerified {
		t.Fatal(d)
	}
	if d := DiagnoseStream("CLIENT_INITIATED_CLOSE", 5000, 7000, wire); d.State != "NEUTRAL_CLOSE_NOT_FAILURE" {
		t.Fatal(d)
	}
	wire.Origin.AlertLevel = 2
	if d := DiagnoseStream("CLIENT_INITIATED_CLOSE", 5000, 7000, wire); d.State != "ALERT_OR_INVALID_RECORD" {
		t.Fatal("real alert hidden by close", d)
	}
	if d := DiagnoseHost(HostResult{TCP: "BOUNDED_TIMEOUT"}); d.Layer != "TCP" || d.State != "CONNECT_FAILED" {
		t.Fatal(d)
	}
}

func TestServiceDiagnosisUsesRealVerifiedHTTPBodyAndStall(t *testing.T) {
	stallRelease := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Write(bytes.Repeat([]byte("x"), 70000))
		case "/denied":
			w.WriteHeader(403)
			w.Write([]byte("denied"))
		case "/stall":
			w.Write(bytes.Repeat([]byte("x"), 17000))
			w.(http.Flusher).Flush()
			// Do not complete the chunked response when the client cancels: that
			// races the deadline and models a valid short response, not a stall.
			<-stallRelease
		}
	}))
	defer func() { close(stallRelease); server.Close() }()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	for _, tc := range []struct{ path, state string }{{"/ok", "PUBLIC_BODY_TRANSFER_VERIFIED"}, {"/denied", "HTTP_DENIED_OR_ERROR"}, {"/stall", "BODY_STALLED_AFTER_PROGRESS"}} {
		budget := 3 * time.Second
		if tc.path == "/stall" {
			budget = 300 * time.Millisecond
		}
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		p := browserproxy.ProbeOriginTransfer(ctx, "127.0.0.1", tc.path, roots, func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		})
		cancel()
		d := DiagnoseProbe(p)
		if d.State != tc.state || d.PageVerified || d.PlaybackVerified {
			t.Fatal(tc.path, p, d)
		}
	}
	p := browserproxy.ProbeOriginTransfer(context.Background(), "wrong.example", "/ok", roots, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	})
	if d := DiagnoseProbe(p); d.State != "CERTIFICATE_REJECTED" {
		t.Fatal(p, d)
	}
}
