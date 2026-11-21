package browserproxy

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func wireDNS(t *testing.T, typ dnsmessage.Type) ([]byte, []byte) {
	t.Helper()
	name, _ := dnsmessage.NewName("www.youtube.com.")
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 175, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: typ, Class: dnsmessage.ClassINET}}}
	query, e := m.Pack()
	if e != nil {
		t.Fatal(e)
	}
	m.Response = true
	m.RecursionAvailable = true
	if typ == dnsmessage.TypeA {
		m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: typ, Class: dnsmessage.ClassINET, TTL: 17}, Body: &dnsmessage.AResource{A: [4]byte{142, 251, 1, 94}}}}
	}
	reply, e := m.Pack()
	if e != nil {
		t.Fatal(e)
	}
	return query, reply
}

func TestBrowserDNSWireDoHVerifiedTLSAndQuestionTypes(t *testing.T) {
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, 64, 65} {
		query, reply := wireDNS(t, typ)
		target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			if binary.BigEndian.Uint16(b) != 0 {
				t.Error("DoH ID not normalized")
			}
			q, e := DNSQuestion(b)
			if e != nil || q.Type != typ {
				t.Error(q, e)
			}
			out := append([]byte(nil), reply...)
			binary.BigEndian.PutUint16(out, 0)
			w.Header().Set("Content-Type", "application/dns-message")
			w.Write(out)
		}))
		roots := x509.NewCertPool()
		roots.AddCert(target.Certificate())
		resolver := &DoHResolver{roots: roots, providers: []dohProvider{{"example.com", netip.MustParseAddrPort("8.8.8.8:443")}}}
		open := func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			if dst.Port() != 443 {
				t.Fatal("raw DNS relayed")
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", target.Listener.Addr().String())
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		answer, err := resolver.ExchangeWire(ctx, query, open)
		cancel()
		if err != nil || binary.BigEndian.Uint16(answer) != 175 {
			t.Fatal(err)
		}
		hints, err := ValidateDNSResponse(query, answer)
		if err != nil {
			t.Fatal(err)
		}
		if typ == dnsmessage.TypeA && (len(hints) != 1 || hints[0].TTL != 17 || hints[0].Name != "www.youtube.com") {
			t.Fatal(hints)
		}
		resolver.roots = x509.NewCertPool()
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		_, err = resolver.ExchangeWire(ctx, query, open)
		cancel()
		if err == nil {
			t.Fatal("untrusted DoH certificate accepted")
		}
		target.Close()
	}
}
func TestBrowserDNSTCPFramingAndUDPTruncation(t *testing.T) {
	query, reply := wireDNS(t, dnsmessage.TypeA)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := NewDNSStream(ctx, func(_ context.Context, b []byte) ([]byte, error) {
		if _, err := DNSQuestion(b); err != nil {
			t.Error(err)
		}
		return reply, nil
	})
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(query)))
		_, err := conn.Write(append(size[:], query...))
		done <- err
	}()
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateDNSResponse(query, body); err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	m.Unpack(reply)
	for len(m.Answers) < 40 {
		m.Answers = append(m.Answers, m.Answers[0])
	}
	large, _ := m.Pack()
	small := DNSDatagramResponse(query, large)
	var truncated dnsmessage.Message
	if truncated.Unpack(small) != nil || !truncated.Truncated || len(small) > 512 {
		t.Fatal("UDP budget not respected")
	}
	if hints, err := ValidateDNSResponse(query, small); err != nil || len(hints) != 0 {
		t.Fatal("undelivered addresses became hints", hints, err)
	}
	cancel()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(size[:]); err == nil {
		t.Fatal("DNS stream survived cancellation")
	}
}
func TestBrowserDNSRejectsMismatchedResponseAndUnboundedCounts(t *testing.T) {
	query, reply := wireDNS(t, dnsmessage.TypeA)
	reply[0] ^= 1
	if _, err := ValidateDNSResponse(query, reply); err == nil {
		t.Fatal("transaction mismatch")
	}
	binary.BigEndian.PutUint16(query[10:12], 65535)
	if _, err := DNSQuestion(query); err == nil {
		t.Fatal("unbounded additional count")
	}
}
