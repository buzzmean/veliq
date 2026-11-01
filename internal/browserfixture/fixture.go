// Package browserfixture is an isolated acceptance target. It never contacts
// public services or reads deployed credentials; all keys/nonces are ephemeral.
package browserfixture

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var Domains = []string{"chatgpt.com", "www.youtube.com", "ordinary.example", "blocked.example", "vk.com", "music.yandex.ru", "langame.ru", "www.twitch.tv", "web.telegram.org"}

type Fixture struct {
	PoisonTelegramDNS       atomic.Bool
	PoisonedDNSAnswers      atomic.Uint64
	AlternativeDNSQueries   atomic.Uint64
	TelegramProbeRejection  atomic.Bool
	TelegramProbeRejected   atomic.Uint64
	StageReady              func(int, func(string, any) (json.RawMessage, error)) error
	DirectProbe             func(netip.AddrPort) bool
	ExpectedFailures        map[int][]string
	ProtectedDirectAttempts atomic.Uint64
	ECHClientHellos         atomic.Uint64
	HealthURL               string
	BeforeRequests          func() error
	Server                  *httptest.Server
	Roots                   *x509.CertPool
	SPKI, Nonce             string
	Resolver                *net.Resolver
	DNS                     *net.UDPConn
	mu                      sync.Mutex
	Seen                    map[string]int
	Protocols               map[string]int
}

func New() (*Fixture, error) {
	f := &Fixture{Seen: map[string]int{}, Protocols: map[string]int{}}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := &key.PublicKey
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "NeExitLag ephemeral acceptance"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, pub, key)
	if e != nil {
		return nil, e
	}
	ca, _ := x509.ParseCertificate(rootDER)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: append(append([]string(nil), Domains...), "youtube.com", "rr1---sn-test.googlevideo.com", "play.google.com", "vk.ru", "i.ytimg.com", "yt3.ggpht.com"), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, Subject: pkix.Name{CommonName: "controlled acceptance target"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, leaf, ca, pub, key)
	if e != nil {
		return nil, e
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(key)
	cert, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
	if e != nil {
		return nil, e
	}
	parsed, _ := x509.ParseCertificate(der)
	spki := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	f.SPKI = base64.StdEncoding.EncodeToString(spki[:])
	f.Roots = x509.NewCertPool()
	f.Roots.AddCert(ca)
	nonce := make([]byte, 16)
	rand.Read(nonce)
	f.Nonce = hex.EncodeToString(nonce)
	f.Server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.Server.EnableHTTP2 = true
	f.Server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName == "chatgpt.com" {
			peer, _, _ := net.SplitHostPort(hello.Conn.RemoteAddr().String())
			if peer != "127.0.0.2" {
				f.ProtectedDirectAttempts.Add(1)
			}
		}
		if hello.ServerName == "web.telegram.org" && f.PoisonTelegramDNS.Load() {
			peer, _, _ := net.SplitHostPort(hello.Conn.RemoteAddr().String())
			if peer != "127.0.0.2" {
				return nil, errors.New("controlled recovered origin only reachable through relay")
			}
		}
		if hello.ServerName == "web.telegram.org" && f.TelegramProbeRejection.Load() {
			peer, _, _ := net.SplitHostPort(hello.Conn.RemoteAddr().String())
			browserHello := false
			for _, curve := range hello.SupportedCurves {
				n := uint16(curve)
				if n&0x0f0f == 0x0a0a && byte(n>>8) == byte(n) {
					browserHello = true
				}
			}
			if peer != "127.0.0.2" || !browserHello {
				if peer == "127.0.0.2" {
					f.TelegramProbeRejected.Add(1)
				}
				return nil, errors.New("controlled origin rejects local path or non-browser ClientHello")
			}
		}
		if hello.ServerName == "blocked.example" {
			peer, _, _ := net.SplitHostPort(hello.Conn.RemoteAddr().String())
			if peer != "127.0.0.2" {
				return nil, errors.New("isolated ISP impairment: this origin rejects local routes")
			}
		}
		return nil, nil
	}}
	f.Server.Listener = &helloListener{Listener: f.Server.Listener, fixture: f}
	f.Server.StartTLS()
	f.DNS, e = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		f.Server.Close()
		return nil, e
	}
	go f.dns()
	f.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", f.DNS.LocalAddr().String())
	}}
	return f, nil
}
func (f *Fixture) Port() uint16 { return uint16(f.Server.Listener.Addr().(*net.TCPAddr).Port) }
func (f *Fixture) Destination() netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), f.Port())
}
func (f *Fixture) Close() { f.DNS.Close(); f.Server.Close() }
func (f *Fixture) serve(w http.ResponseWriter, r *http.Request) {
	host, _, e := net.SplitHostPort(r.Host)
	if e != nil {
		host = r.Host
	}
	if r.URL.Path == "/dns-query" {
		f.AlternativeDNSQueries.Add(1)
		var question dnsmessage.Message
		wire, e := io.ReadAll(io.LimitReader(r.Body, 513))
		if e != nil || len(wire) > 512 || question.Unpack(wire) != nil || r.Method != "POST" || len(question.Questions) != 1 || question.Questions[0].Name.String() != "web.telegram.org." {
			http.Error(w, "bad DNS question", 400)
			return
		}
		peer, _, _ := net.SplitHostPort(r.RemoteAddr)
		if peer != "127.0.0.2" {
			http.Error(w, "DNS must use authenticated relay", 403)
			return
		}
		reply := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Questions: question.Questions, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}}}}
		response, _ := reply.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(response)
		return
	}
	if r.URL.Path == "/policy-probe" {
		if r.Method != "GET" || r.URL.Query().Get("nonce") != f.Nonce {
			http.Error(w, "bad nonce", 403)
			return
		}
		source, _ := netip.ParseAddrPort(r.RemoteAddr)
		route := "PROXY"
		if f.DirectProbe != nil && f.DirectProbe(source) {
			route = "DIRECT"
		}
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprint(w, f.Nonce+":"+route)
		return
	}
	if host == "chatgpt.com" {
		peer, _, _ := net.SplitHostPort(r.RemoteAddr)
		if peer != "127.0.0.2" {
			http.Error(w, "protected DIRECT source forbidden", http.StatusForbidden)
			return
		}
	}
	f.mu.Lock()
	f.Seen[host]++
	if r.Method != "HEAD" {
		f.Protocols[host] = r.ProtoMajor
	}
	f.mu.Unlock()
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/bootstrap" {
		stage := r.URL.Query().Get("stage")
		if stage == "" {
			stage = "1"
		}
		w.Header().Set("Content-Type", "text/html")
		stageID, _ := strconv.Atoi(stage)
		expected, _ := json.Marshal(f.ExpectedFailures[stageID])
		if string(expected) == "null" {
			expected = []byte("[]")
		}
		fmt.Fprintf(w, `<!doctype html><title>PENDING</title><body><script>const expectedFailures=%s;Promise.all(%s.map(async h=>{let value;try{const r=await fetch('https://'+h+':%d/check?stage=%s',{cache:'no-store'});if(r.status!==200)throw Error('HTTP '+r.status);value=await r.text();}catch(e){if(expectedFailures.includes(h))return;throw Error(h+': '+String(e));}if(expectedFailures.includes(h))throw Error('UNEXPECTED PROTECTED SUCCESS '+h);if(value!==%q)throw Error(h+': wrong nonce');})).then(()=>{document.title='NEEXITLAG_PASS_%s';document.body.textContent='CONTROLLED_HTTPS_OK';}).catch(e=>{document.title='NEEXITLAG_FAIL';document.body.textContent=String(e);});</script>`, expected, string(domainJSON()), f.Port(), stage, f.Nonce, f.Nonce+"_"+stage)
		return
	}
	if r.URL.Path != "/" && r.URL.Path != "/check" {
		http.NotFound(w, r)
		return
	}
	fmt.Fprint(w, f.Nonce)
}
func domainJSON() []byte { b, _ := json.Marshal(Domains); return b }

func (f *Fixture) dns() {
	data := make([]byte, 2048)
	for {
		n, peer, e := f.DNS.ReadFromUDP(data)
		if e != nil {
			return
		}
		var p dnsmessage.Parser
		header, e := p.Start(data[:n])
		if e != nil {
			continue
		}
		questions, e := p.AllQuestions()
		if e != nil {
			continue
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true, RecursionDesired: true})
		b.StartQuestions()
		for _, q := range questions {
			b.Question(q)
		}
		b.StartAnswers()
		for _, q := range questions {
			if q.Type == dnsmessage.TypeA {
				ip := [4]byte{127, 0, 0, 1}
				if f.PoisonTelegramDNS.Load() && q.Name.String() == "web.telegram.org." {
					ip = [4]byte{127, 0, 0, 3}
					f.PoisonedDNSAnswers.Add(1)
				}
				b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, dnsmessage.AResource{A: ip})
			}
		}
		out, e := b.Finish()
		if e == nil {
			f.DNS.WriteToUDP(out, peer)
		}
	}
}
func ChromePath() string {
	if v := os.Getenv("NEEXITLAG_TEST_CHROME"); v != "" {
		return v
	}
	for _, name := range []string{"google-chrome", "chromium", "chrome"} {
		if p, e := exec.LookPath(name); e == nil {
			return p
		}
	}
	for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LOCALAPPDATA")} {
		p := filepath.Join(root, "Google", "Chrome", "Application", "chrome.exe")
		if _, e := os.Stat(p); e == nil {
			return p
		}
	}
	return ""
}

// Count observable ECH/GREASE in actual Chrome TLS handshakes without retaining
// or logging payload. This is a test target, never a production TLS interceptor.
type helloListener struct {
	net.Listener
	fixture *Fixture
}

func (l *helloListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &helloConn{Conn: c, fixture: l.fixture}, nil
}

type helloConn struct {
	net.Conn
	fixture *Fixture
	hello   []byte
	done    bool
}

func (c *helloConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if !c.done && n > 0 {
		if len(c.hello)+n > localstrategy.MaxHelloBytes {
			c.done = true
			c.hello = nil
			return n, err
		}
		c.hello = append(c.hello, p[:n]...)
		if _, reason, complete := localstrategy.InspectHelloStream(c.hello); complete {
			if reason == "ECH_OUTER_SNI_ONLY" {
				c.fixture.ECHClientHellos.Add(1)
			}
			c.done = true
			c.hello = nil
		}
	}
	return n, err
}

// Isolated DoH-shaped fixture over the caller's REAL authenticated relay. Only
// this fixture permits loopback DNS answers; production DoH rejects private IPs.
func (f *Fixture) AlternativeDNS(ctx context.Context, host string, open func(context.Context, netip.AddrPort) (net.Conn, error)) ([]netip.Addr, time.Duration, error) {
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil, 0, err
	}
	msg := dnsmessage.Message{Header: dnsmessage.Header{RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	data, err := msg.Pack()
	if err != nil {
		return nil, 0, err
	}
	tr := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: f.Roots, ServerName: host}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return open(ctx, f.Destination()) }}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+host+":"+strconv.Itoa(int(f.Port()))+"/dns-query", bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	response, err := tr.RoundTrip(req)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || response.StatusCode != 200 {
		return nil, 0, errors.New("fixture DoH failed")
	}
	var answer dnsmessage.Message
	if answer.Unpack(wire) != nil || len(answer.Answers) != 1 {
		return nil, 0, errors.New("fixture DNS invalid")
	}
	a, ok := answer.Answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		return nil, 0, errors.New("fixture DNS A missing")
	}
	return []netip.Addr{netip.AddrFrom4(a.A)}, time.Duration(answer.Answers[0].Header.TTL) * time.Second, nil
}
