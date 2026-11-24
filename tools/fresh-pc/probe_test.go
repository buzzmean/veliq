package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/freshpc"
	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/transport"
	"github.com/buzzmean/veliq/internal/e2eprobe"
	"github.com/buzzmean/veliq/services/relay"
)

func TestFreshProbeRealPinnedTLSMTLSTicketTCPUDP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root := t.TempDir()
	pki := filepath.Join(root, "pki")
	if e := freshpc.GenerateCA(pki, "127.0.0.1"); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(filepath.Join(pki, "ca.pem"))
	ca, e := freshpc.ParseCertificate(string(raw))
	if e != nil {
		t.Fatal(e)
	}
	caKey, e := privateKey(filepath.Join(pki, "ca.key"))
	if e != nil {
		t.Fatal(e)
	}
	state := filepath.Join(root, "pc")
	request, e := freshpc.RequestDevice(state, strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	pub, e := freshpc.ValidateRequest(request)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := freshpc.Issue(ca, caKey, pub, "")
	if e != nil {
		t.Fatal(e)
	}
	signerPub, signer, _ := ed25519.GenerateKey(rand.Reader)
	response := freshpc.Response{DeviceID: request.DeviceID, MachineHash: request.MachineHash, CA: string(raw), CASHA256: freshpc.Fingerprint(ca), Certificate: cert, Trust: map[string]string{"vps-1": base64.RawURLEncoding.EncodeToString(signerPub)}, EchoToken: strings.Repeat("x", 32)}
	wire, _ := json.Marshal(response)
	if e = os.WriteFile(filepath.Join(state, "response.json"), wire, 0600); e != nil {
		t.Fatal(e)
	}
	if e = freshpc.Complete(state, request, response, response.CASHA256); e != nil {
		t.Fatal(e)
	}
	pair, e := tls.LoadX509KeyPair(filepath.Join(pki, "server.pem"), filepath.Join(pki, "server.key"))
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	mu := sync.Mutex{}
	nonces := map[string]bool{}
	cp := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Write([]byte(`{"status":"ok"}`))
			return
		}
		if r.URL.Path != "/api/v1/auth" {
			http.NotFound(w, r)
			return
		}
		b, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		var proof security.Proof
		if security.Parse(b, &proof) != nil || proof.DeviceID != request.DeviceID || proof.RelayID != "VPS-01" || proof.Verify(pub, time.Now()) != nil {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if nonces[proof.Nonce] {
			w.WriteHeader(401)
			return
		}
		nonces[proof.Nonce] = true
		id, _ := security.NewID()
		ticket, e := security.Sign("ticket", "vps-1", signer, security.Ticket{ID: id, DeviceID: request.DeviceID, DeviceKey: security.Fingerprint(pub), RelayID: "VPS-01", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)})
		if e != nil {
			t.Error(e)
			w.WriteHeader(500)
			return
		}
		w.Write(ticket)
	}))
	cp.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	cp.StartTLS()
	defer cp.Close()
	st := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, NextProtos: []string{transport.ALPN}}
	server, e := relay.Listen("127.0.0.1:0", relay.Config{TLS: st, TicketVerifier: security.NewTicketVerifier(map[string]ed25519.PublicKey{"vps-1": signerPub}, "VPS-01"), Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	tcp, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer tcp.Close()
	target := tcp.Addr().String()
	udp, e := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(target)))
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	stats := &e2eprobe.EchoStats{}
	go e2eprobe.ServeTCP(ctx, tcp, []byte(response.EchoToken), stats)
	go e2eprobe.Serve(ctx, udp, []byte(response.EchoToken), stats)
	if e = probeEndpoints(state, "127.0.0.1", cp.URL, server.Addr().String(), target); e != nil {
		t.Fatal(e)
	}
	// Same trust/key, wrong relay name: TLS must reject instead of returning a PASS.
	if e = probeEndpoints(state, "127.0.0.2", cp.URL, server.Addr().String(), target); e == nil {
		t.Fatal("wrong TLS identity accepted")
	}
}
