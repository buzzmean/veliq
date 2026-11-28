package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
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
	tcp, udp, e := listenEchoPair(func(address string) (net.Listener, error) { return net.Listen("tcp4", address) })
	if e != nil {
		t.Fatal(e)
	}
	defer tcp.Close()
	target := tcp.Addr().String()
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

// TCP:0 does not prove that the chosen port is available for UDP on Windows.
// Hold both sockets together; retry only actual socket-availability errors.
// This is fixture preparation, never a transport/TLS assertion retry.
func listenEchoPair(listenTCP func(string) (net.Listener, error)) (net.Listener, *net.UDPConn, error) {
	var last error
	for attempt := 0; attempt < 16; attempt++ {
		udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return nil, nil, err
		}
		tcp, err := listenTCP(udp.LocalAddr().String())
		if err == nil {
			return tcp, udp, nil
		}
		udp.Close()
		if !echoPortUnavailable(err) {
			return nil, nil, err
		}
		last = err
	}
	return nil, nil, fmt.Errorf("no paired loopback TCP/UDP echo port after 16 attempts: %w", last)
}

func echoPortUnavailable(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EACCES) {
		return true
	}
	// Winsock errors are not the POSIX-shaped syscall errno constants on Windows.
	var native syscall.Errno
	return runtime.GOOS == "windows" && errors.As(err, &native) && (native == 10013 || native == 10048)
}

func TestFreshProbeEchoPairAvailabilityIsBounded(t *testing.T) {
	availability := []error{syscall.EACCES, syscall.EADDRINUSE}
	if runtime.GOOS == "windows" {
		availability = append(availability, syscall.Errno(10013), syscall.Errno(10048))
	}
	for _, denied := range availability {
		t.Run(denied.Error(), func(t *testing.T) {
			attempts := 0
			tcp, udp, err := listenEchoPair(func(address string) (net.Listener, error) {
				attempts++
				if attempts == 1 {
					return nil, &net.OpError{Op: "listen", Net: "tcp4", Err: denied}
				}
				return net.Listen("tcp4", address)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			defer udp.Close()
			if attempts < 2 || attempts > 16 || tcp.Addr().String() != udp.LocalAddr().String() {
				t.Fatal("unpaired fixture sockets", attempts)
			}
		})
	}
	for _, cause := range []error{syscall.EACCES, errors.New("unexpected fixture error")} {
		attempts := 0
		tcp, udp, err := listenEchoPair(func(string) (net.Listener, error) { attempts++; return nil, cause })
		wanted := 1
		if errors.Is(cause, syscall.EACCES) {
			wanted = 16
		}
		if tcp != nil || udp != nil || !errors.Is(err, cause) || attempts != wanted {
			t.Fatal("error bypassed or retried without bound", attempts, err)
		}
	}
}
