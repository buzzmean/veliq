package windowsplatform

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func http3ProbeCertificate(t *testing.T, host string) (*tls.Config, *x509.CertPool) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{host}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13}), roots
}

// The sole network seam maps the reviewed public endpoint to loopback. The
// connected socket, packet writer, TLS and HTTP/3 implementations are real.
type http3MappedConn struct {
	net.Conn
	logical net.Addr
}

func (c *http3MappedConn) RemoteAddr() net.Addr { return c.logical }

type http3NoWitness struct{ *QUICProbeSocket }

func (*http3NoWitness) Committed() bool { return false }

func TestHTTP3ProbeOwnedSocketAuthenticatedSample(t *testing.T) {
	owner := quicProbeOwner(t)
	for _, mode := range []string{"success", "wrong-ca", "wrong-name", "redirect", "forbidden", "short", "reset", "compressed", "large-headers", "uncommitted", "revoked", "canceled", "deadline", "mismatched-owner"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 1500*time.Millisecond)
				defer stop()
			}
			host := "www.youtube.com"
			certHost := host
			if mode == "wrong-name" {
				certHost = "wrong.youtube.com"
			}
			serverTLS, roots := http3ProbeCertificate(t, certHost)
			if mode == "wrong-ca" {
				roots = x509.NewCertPool()
			}
			var requests, opens atomic.Int64
			var revoked atomic.Bool
			requestErrors := make(chan string, 1)
			server := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				body, bodyErr := io.ReadAll(io.LimitReader(r.Body, 1))
				if r.Method != "GET" || r.URL.Path != "/" || r.URL.RawQuery != "" || r.Host != host || r.ProtoMajor != 3 || r.TLS == nil || r.TLS.ServerName != host || r.TLS.NegotiatedProtocol != "h3" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Accept-Encoding") != "identity" || len(body) != 0 || bodyErr != nil {
					select {
					case requestErrors <- "request escaped credential-free pinned GET contract":
					default:
					}
				}
				switch mode {
				case "redirect":
					w.Header().Set("Location", "https://api.openai.com/private")
					w.WriteHeader(302)
					return
				case "forbidden":
					w.WriteHeader(403)
					return
				case "short":
					w.Write([]byte("short"))
					return
				case "compressed":
					w.Header().Set("Content-Encoding", "gzip")
				case "large-headers":
					w.Header().Set("X-Large", strings.Repeat("x", 16384))
				}
				if mode == "reset" || mode == "revoked" || mode == "canceled" || mode == "deadline" {
					w.Header().Set("Content-Length", "65536")
					w.Write(make([]byte, 1024))
					w.(http.Flusher).Flush()
					switch mode {
					case "reset":
						w.(http3.HTTPStreamer).HTTPStream().CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
						return
					case "revoked":
						revoked.Store(true)
					case "canceled":
						cancel()
					}
					<-r.Context().Done()
					return
				}
				w.Write(make([]byte, 64*1024))
			})}
			listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{Versions: []quic.Version{quic.Version1}, HandshakeIdleTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			served := make(chan error, 1)
			go func() { served <- server.ServeListener(listener) }()
			defer func() { server.Close(); listener.Close(); <-served }()
			scope := quicProbeScopeFixture()
			scope.Source = netip.AddrPort{}
			scope.Owner = owner
			key := browserproxy.HTTP3ProbeKey{Host: host, Endpoint: scope.Destination, PID: owner.PID, Birth: owner.CreationTime, Executable: owner.Path, Network: scope.Network, Profile: scope.Profile, Revision: scope.Revision}
			if mode == "mismatched-owner" {
				key.Birth++
			}
			ownerCurrent := func(p ProcessIdentity) bool { return p == owner && (runtime.GOOS != "windows" || IsCurrent(p)) }
			current := func(s QUICProbeScope) bool {
				return !revoked.Load() && s.Owner == scope.Owner && s.Destination == scope.Destination && s.Network == scope.Network && s.Profile == scope.Profile && s.Revision == scope.Revision
			}
			var socket *QUICProbeSocket
			manager := browserproxy.NewHTTP3ProbeManager()
			defer manager.Close()
			r := manager.Probe(ctx, key, roots, func(k browserproxy.HTTP3ProbeKey) bool { return k == key && !revoked.Load() && ownerCurrent(owner) }, func(ctx context.Context) (browserproxy.HTTP3ProbeSocket, error) {
				opens.Add(1)
				var err error
				socket, err = openQUICProbeSocket(ctx, scope, 6, current, ownerCurrent, func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
					if dst != key.Endpoint {
						return nil, errors.New("unexpected destination")
					}
					conn, err := (&net.Dialer{}).DialContext(ctx, "udp4", listener.Addr().String())
					if err != nil {
						return nil, err
					}
					return &http3MappedConn{Conn: conn, logical: net.UDPAddrFromAddrPort(dst)}, nil
				})
				if err != nil {
					return nil, err
				}
				if mode == "uncommitted" {
					return &http3NoWitness{socket}, nil
				}
				return socket, nil
			})
			want := map[string]string{"success": "HTTP3_AUTHENTICATED_SAMPLE", "wrong-ca": "HTTP3_CERTIFICATE_ERROR", "wrong-name": "HTTP3_CERTIFICATE_ERROR", "redirect": "HTTP3_STATUS_REJECTED", "forbidden": "HTTP3_STATUS_REJECTED", "short": "HTTP3_BODY_INCOMPLETE", "reset": "HTTP3_BODY_INCOMPLETE", "compressed": "HTTP3_ENCODING_REJECTED", "large-headers": "HTTP3_RESPONSE_FAILED", "uncommitted": "HTTP3_TRANSFORM_UNCOMMITTED", "revoked": "HTTP3_SCOPE_CHANGED", "canceled": "HTTP3_CANCELED_OR_TIMEOUT", "deadline": "HTTP3_CANCELED_OR_TIMEOUT", "mismatched-owner": "HTTP3_SOCKET_SCOPE_MISMATCH"}[mode]
			if (r.Outcome != want && !(mode == "reset" && r.Outcome == "HTTP3_RESPONSE_FAILED")) || r.Observed != (mode == "success") {
				t.Fatalf("want %s: %+v", want, r)
			}
			if opens.Load() != 1 || socket == nil || !socket.closed.Load() || socket.Committed() {
				t.Fatal("socket lifecycle/retry escaped")
			}
			if r.ReceivedBytes > browserproxy.HTTP3ProbeReceiveLimit || r.SentBytes > browserproxy.HTTP3ProbeSendLimit || r.ReceivedPackets > browserproxy.HTTP3ProbeReceivePackets || r.SentPackets > browserproxy.HTTP3ProbeSendPackets {
				t.Fatal("budget escaped", r)
			}
			if mode == "wrong-ca" || mode == "wrong-name" || mode == "mismatched-owner" {
				if requests.Load() != 0 {
					t.Fatal("unverified HTTP request")
				}
				if mode != "mismatched-owner" && (!r.TransformCommitted || r.VerifiedTLS) {
					t.Fatal("send witness confused with certificate acceptance", r)
				}
			} else if requests.Load() != 1 {
				t.Fatal("request retry/redirect escaped", requests.Load())
			}
			if mode == "success" && (!r.VerifiedTLS || !r.TransformCommitted || r.BodyBytes != browserproxy.HTTP3ProbeSampleBytes || r.ALPN != "h3" || r.TLSVersion != tls.VersionTLS13) {
				t.Fatal("incomplete success", r)
			}
			e := socket.Evidence()
			if mode == "mismatched-owner" {
				if e.FakePackets != 0 || e.OriginalPackets != 0 {
					t.Fatal("mismatched socket sent data")
				}
			} else if e.FakePackets != 6 || e.OriginalPackets == 0 {
				t.Fatal("missing real packet plan", e)
			}
			select {
			case msg := <-requestErrors:
				t.Fatal(msg)
			default:
			}
			t.Logf("outcome=%s body=%d rx=%d tx=%d packets=%d/%d fake=%d opens=%d requests=%d", r.Outcome, r.BodyBytes, r.ReceivedBytes, r.SentBytes, r.ReceivedPackets, r.SentPackets, e.FakePackets, opens.Load(), requests.Load())
		})
	}
}
