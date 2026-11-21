package browserproxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTransferProbeRequiresActualVerifiedLargeBodyAndBoundsStalls(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	cert := &x509.Certificate{SerialNumber: big.NewInt(111), DNSNames: []string{"www.youtube.com", "i.ytimg.com"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	parsed, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("probe must be credential free GET")
		}
		switch r.URL.Path {
		case "/redirect":
			w.Header().Set("Location", "https://www.youtube.com/")
			w.WriteHeader(301)
		case "/short":
			w.WriteHeader(404)
			w.Write([]byte("no video URL"))
		case "/stall":
			w.Header().Set("Content-Length", "131073")
			w.Write(bytes.Repeat([]byte("x"), 16384))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case "/truncated":
			w.Header().Set("Content-Length", "131073")
			w.Write(bytes.Repeat([]byte("x"), 16384))
		default:
			w.Write(bytes.Repeat([]byte("x"), 200000))
		}
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	open := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	for _, host := range []string{"www.youtube.com", "i.ytimg.com"} {
		p := ProbeOriginTransfer(context.Background(), host, "/", roots, open)
		if p.Failure != "" || p.TLSVersion == 0 || p.BodyBytes != 131073 {
			t.Fatal("not a verified bounded body", host, p)
		}
	}
	p := ProbeOriginTransfer(context.Background(), "wrong.example", "/", roots, open)
	if p.Failure != "TLS_CERTIFICATE_ERROR" {
		t.Fatal("TLS weakened", p)
	}
	p = ProbeOriginTransfer(context.Background(), "www.youtube.com", "/short", roots, open)
	if p.Status != 404 || p.BodyBytes >= 65536 {
		t.Fatal(p)
	}
	p = ProbeOriginTransfer(context.Background(), "www.youtube.com", "/redirect", roots, open)
	if p.Failure != "" || p.Status != 301 || p.BodyBytes != 0 {
		t.Fatal("empty redirect mislabelled as connection failure", p)
	}
	for _, path := range []string{"/stall", "/truncated"} {
		ctx, stop := context.WithTimeout(context.Background(), 150*time.Millisecond)
		p = ProbeOriginTransfer(ctx, "i.ytimg.com", path, roots, open)
		stop()
		if p.Failure == "" || p.BodyBytes > 20000 {
			t.Fatal("16KiB freeze/truncation promoted", path, p)
		}
	}
}
