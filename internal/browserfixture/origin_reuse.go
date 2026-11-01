package browserfixture

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These names never resolve publicly in this fixture. One ephemeral certificate
// deliberately authorizes different policy classes at the same IP and port.
const ReuseLocalHost = "www.youtube.com"
const ReuseSiblingHost = "youtube.com"
const ReuseRequiredHost = "chatgpt.com"
const ReuseFreshRequiredHost = "api.openai.com"

// Distinct TEST-NET addresses prevent an earlier H2 connection from satisfying
// a fresh single-fault/recovery attempt. These names never resolve publicly.
var OutageHosts = [...]string{"outage.openai.com", "ordinary-outage.example", "recovery.openai.com", "ordinary-recovery.example"}
var OutageSteps = [...]string{"outage_required", "outage_direct", "recovery_required", "recovery_direct"}
var OutageAddresses = [...]string{"192.0.2.251", "192.0.2.250", "192.0.2.249", "192.0.2.248"}

type OriginOutcome struct {
	Step     string
	Complete bool
	Error    string
	Millis   int64
}

type OriginRequest struct {
	Connection              uint64
	Host, SNI, Source, Step string
	Protocol                int
	BodyBytes               int
}

type OriginReuse struct {
	Server    *httptest.Server
	RootDER   []byte
	Roots     *x509.CertPool
	Nonce     string
	mu        sync.Mutex
	requests  []OriginRequest
	fresh     []OriginRequest
	outage    []OriginRequest
	outcomes  []OriginOutcome
	bootstrap *OriginRequest
	overflow  bool
}

type reuseConnectionKey struct{}

func NewOriginReuse(t testing.TB) *OriginReuse {
	t.Helper()
	f := &OriginReuse{}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "VELIQ ephemeral origin reuse"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	f.RootDER, err = x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(f.RootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	names := append([]string{ReuseLocalHost, ReuseSiblingHost, ReuseRequiredHost, ReuseFreshRequiredHost}, OutageHosts[:]...)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: names, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	f.Roots = x509.NewCertPool()
	f.Roots.AddCert(ca)
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	f.Nonce = hex.EncodeToString(nonce[:])
	f.Server = httptest.NewUnstartedServer(http.HandlerFunc(f.serveReuse))
	f.Server.EnableHTTP2 = true
	f.Server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: leafKey}}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		// Isolate reuse of an explicitly observed SNI from the separate opaque
		// ECH/GREASE limitation. Verify the browser flag at the actual endpoint.
		for _, extension := range hello.Extensions {
			if extension == 0xfe0d {
				return nil, errors.New("origin reuse precondition: ECH extension must be absent")
			}
		}
		return nil, nil
	}}
	var next atomic.Uint64
	f.Server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, reuseConnectionKey{}, next.Add(1))
	}
	f.Server.StartTLS()
	t.Cleanup(f.Server.Close)
	return f
}

func (f *OriginReuse) Port() uint16 { return uint16(f.Server.Listener.Addr().(*net.TCPAddr).Port) }
func (f *OriginReuse) Destination() netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), f.Port())
}
func (f *OriginReuse) URL(host, path string) string {
	return fmt.Sprintf("https://%s:%d/%s?nonce=%s", host, f.Port(), path, f.Nonce)
}

func (f *OriginReuse) serveReuse(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.Host)
	outageIndex := -1
	for i, name := range OutageHosts {
		if host == name {
			outageIndex = i
		}
	}
	if outageIndex < 0 && host != ReuseLocalHost && host != ReuseSiblingHost && host != ReuseRequiredHost && host != ReuseFreshRequiredHost {
		http.Error(w, "unexpected host", 400)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.URL.Query().Get("nonce") != f.Nonce {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/sequence" {
		w.Header().Set("Content-Type", "text/html")
		body := "<!doctype html><title>ORIGIN_REUSE_READY</title><body>ephemeral fixture</body>"
		record := reuseRequest(r, host, "bootstrap", len(body))
		f.mu.Lock()
		if f.bootstrap != nil {
			f.overflow = true
		} else {
			f.bootstrap = &record
		}
		f.mu.Unlock()
		fmt.Fprint(w, body)
		return
	}
	if r.URL.Path != "/payload" || r.Method != "GET" {
		http.NotFound(w, r)
		return
	}
	step := r.URL.Query().Get("step")
	fresh := host == ReuseFreshRequiredHost && (step == "fresh_required" || step == "fresh_required_again")
	if (outageIndex >= 0 && step != OutageSteps[outageIndex]) || (outageIndex < 0 && !fresh && (host == ReuseFreshRequiredHost || (step != "local" && step != "sibling" && step != "required" && step != "required_again"))) {
		http.Error(w, "bad step", 400)
		return
	}
	body := f.Nonce + ":" + step
	record := reuseRequest(r, host, step, len(body))
	f.mu.Lock()
	if outageIndex >= 0 {
		if len(f.outage) < 16 {
			f.outage = append(f.outage, record)
		} else {
			f.overflow = true
		}
	} else if fresh {
		if len(f.fresh) < 4 {
			f.fresh = append(f.fresh, record)
		} else {
			f.overflow = true
		}
	} else if len(f.requests) < 32 {
		f.requests = append(f.requests, record)
	} else {
		f.overflow = true
	}
	f.mu.Unlock()
	// Record before returning the response: a rejected request has already leaked
	// its authority to this endpoint. Never use an origin 421/403 as route proof.
	fmt.Fprint(w, body)
}

// OutageEvidence includes server requests even when the browser rejected or
// aborted the response. A fetch error alone is never evidence of no leak.
func (f *OriginReuse) OutageEvidence(t testing.TB) ([]OriginRequest, []OriginOutcome) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.overflow {
		t.Fatal("outage evidence overflow")
	}
	return append([]OriginRequest(nil), f.outage...), append([]OriginOutcome(nil), f.outcomes...)
}

// FreshRequests is separate from the four-request coalescing sequence. The
// browser maps this new authority to TEST-NET before launch, preventing reuse
// of the earlier loopback direct connection and requiring real capture/PAC.
func (f *OriginReuse) FreshRequests(t testing.TB) []OriginRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.overflow || len(f.fresh) != 2 {
		t.Fatalf("expected two fresh-authority requests, got %d", len(f.fresh))
	}
	for i, r := range f.fresh {
		step := []string{"fresh_required", "fresh_required_again"}[i]
		if r.Host != ReuseFreshRequiredHost || r.SNI != ReuseFreshRequiredHost || r.Step != step || r.Protocol != 2 || r.Connection == 0 || r.BodyBytes != len(f.Nonce+":"+step) {
			t.Fatal("incomplete fresh-authority H2 evidence")
		}
	}
	return append([]OriginRequest(nil), f.fresh...)
}

func (f *OriginReuse) Requests(t testing.TB) []OriginRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.overflow {
		t.Fatal("origin reuse evidence overflow")
	}
	out := append([]OriginRequest(nil), f.requests...)
	if len(out) != 4 {
		t.Fatalf("expected four sequential browser requests, got %d", len(out))
	}
	hosts := []string{ReuseLocalHost, ReuseSiblingHost, ReuseRequiredHost, ReuseRequiredHost}
	steps := []string{"local", "sibling", "required", "required_again"}
	for i, r := range out {
		if r.Host != hosts[i] || r.Step != steps[i] || r.Protocol != 2 || r.Connection == 0 || r.BodyBytes == 0 {
			t.Fatalf("incomplete H2 request evidence: %+v", out)
		}
	}
	return out
}

func reuseRequest(r *http.Request, host, step string, size int) OriginRequest {
	source, _, _ := net.SplitHostPort(r.RemoteAddr)
	return OriginRequest{Connection: r.Context().Value(reuseConnectionKey{}).(uint64), Host: host, SNI: r.TLS.ServerName, Source: source, Step: step, Protocol: r.ProtoMajor, BodyBytes: size}
}

func (f *OriginReuse) Bootstrap(t testing.TB) OriginRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.overflow || f.bootstrap == nil || f.bootstrap.Protocol != 2 || f.bootstrap.Connection == 0 || f.bootstrap.BodyBytes == 0 {
		t.Fatal("missing unique H2 bootstrap evidence")
	}
	return *f.bootstrap
}
