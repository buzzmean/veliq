package browserproxy

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Только локальные TLS-серверы; фиксированные resolver IP не покидают фикстуру.
func wireRecoveryFixture(t *testing.T, handlers ...http.HandlerFunc) (*DoHResolver, DNSOpen, *atomic.Int32) {
	t.Helper()
	r := &DoHResolver{roots: x509.NewCertPool()}
	targets := map[netip.AddrPort]string{}
	for i, h := range handlers {
		s := httptest.NewTLSServer(h)
		t.Cleanup(s.Close)
		r.roots.AddCert(s.Certificate())
		dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, byte(i + 1)}), 443)
		r.providers = append(r.providers, dohProvider{"example.com", dst})
		targets[dst] = s.Listener.Addr().String()
	}
	var opened atomic.Int32
	return r, func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		address, ok := targets[dst]
		if !ok || dst.Port() != 443 {
			return nil, errors.New("unexpected DNS destination")
		}
		opened.Add(1)
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}, &opened
}
func wireResponseHandler(t *testing.T, code dnsmessage.RCode) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, e := io.ReadAll(r.Body)
		if e != nil {
			t.Error(e)
			return
		}
		var m dnsmessage.Message
		if m.Unpack(b) != nil {
			t.Error("invalid query")
			return
		}
		m.Response = true
		m.RCode = code
		if code == dnsmessage.RCodeSuccess {
			q := m.Questions[0]
			switch q.Type {
			case dnsmessage.TypeA:
				m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class, TTL: 17}, Body: &dnsmessage.AResource{A: [4]byte{142, 251, 1, 94}}}}
			case dnsmessage.TypeAAAA:
				m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class, TTL: 17}, Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2607:f8b0::1").As16()}}}
			}
		}
		out, e := m.Pack()
		if e != nil {
			t.Error(e)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	}
}
func TestDNSWireRecoveryNegativeThenHealthy(t *testing.T) {
	for _, code := range []dnsmessage.RCode{dnsmessage.RCodeNameError, dnsmessage.RCodeServerFailure} {
		for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
			t.Run(code.String()+"/"+typ.String(), func(t *testing.T) {
				r, open, calls := wireRecoveryFixture(t, wireResponseHandler(t, code), wireResponseHandler(t, dnsmessage.RCodeSuccess))
				query, _ := wireDNS(t, typ)
				answer, e := r.ExchangeWire(context.Background(), query, open)
				if e != nil || DNSResponseStatus(query, answer) != "DNS_RESPONSE" || calls.Load() != 2 {
					t.Fatalf("second provider did not repair DNS: status=%s calls=%d err=%v", DNSResponseStatus(query, answer), calls.Load(), e)
				}
				hints, e := ValidateDNSResponse(query, answer)
				if e != nil || len(hints) != 1 || hints[0].TTL != 17 || binary.BigEndian.Uint16(answer) != 175 {
					t.Fatal(hints, e)
				}
			})
		}
	}
}
func TestDNSWireRecoveryExistingTransportAndValidationFallback(t *testing.T) {
	for _, kind := range []string{"timeout", "mismatched", "certificate", "invalid"} {
		t.Run(kind, func(t *testing.T) {
			bad := func(w http.ResponseWriter, r *http.Request) {
				if kind == "timeout" {
					io.Copy(io.Discard, r.Body)
					<-r.Context().Done()
					return
				}
				b, _ := io.ReadAll(r.Body)
				var m dnsmessage.Message
				m.Unpack(b)
				m.Response = true
				m.ID = 99
				out, _ := m.Pack()
				if kind == "invalid" {
					out = []byte("invalid DNS")
				}
				w.Header().Set("Content-Type", "application/dns-message")
				w.Write(out)
			}
			r, open, calls := wireRecoveryFixture(t, bad, wireResponseHandler(t, dnsmessage.RCodeSuccess))
			if kind == "certificate" {
				r.providers[0].host = "wrong.example"
			}
			query, _ := wireDNS(t, dnsmessage.TypeA)
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			out, e := r.ExchangeWire(ctx, query, open)
			if e != nil || DNSResponseStatus(query, out) != "DNS_RESPONSE" || calls.Load() != 2 {
				t.Fatal(kind, e, calls.Load())
			}
		})
	}
}
func TestDNSWireRecoveryAllNegativeAndTemporaryFailure(t *testing.T) {
	var healthy atomic.Bool
	second := func(w http.ResponseWriter, r *http.Request) {
		code := dnsmessage.RCodeServerFailure
		if healthy.Load() {
			code = dnsmessage.RCodeSuccess
		}
		wireResponseHandler(t, code)(w, r)
	}
	r, open, calls := wireRecoveryFixture(t, wireResponseHandler(t, dnsmessage.RCodeNameError), second)
	query, _ := wireDNS(t, dnsmessage.TypeA)
	out, e := r.ExchangeWire(context.Background(), query, open)
	if e != nil || DNSResponseStatus(query, out) != "DNS_NXDOMAIN" || calls.Load() != 2 {
		t.Fatalf("first validated negative must survive exhaustion: %v %d %s", e, calls.Load(), DNSResponseStatus(query, out))
	}
	healthy.Store(true)
	out, e = r.ExchangeWire(context.Background(), query, open)
	if e != nil || DNSResponseStatus(query, out) != "DNS_RESPONSE" || calls.Load() != 4 {
		t.Fatal("negative result permanently pinned", e, calls.Load())
	}
}
func TestDNSWireRecoveryCancellationAndDeadline(t *testing.T) {
	query, _ := wireDNS(t, dnsmessage.TypeA)
	r, open, calls := wireRecoveryFixture(t, wireResponseHandler(t, dnsmessage.RCodeSuccess))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := r.ExchangeWire(ctx, query, open); e == nil || calls.Load() != 0 {
		t.Fatal("canceled query was opened", e, calls.Load())
	}
	// Даже caller без deadline не может удержать wire slot бесконечно.
	started := time.Now()
	_, e := r.ExchangeWire(context.Background(), query, func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() })
	if e == nil || time.Since(started) > 2500*time.Millisecond {
		t.Fatal("unbounded provider timeout", e, time.Since(started))
	}
}
func TestDNSWireRecoveryConcurrentIDs(t *testing.T) {
	r, open, _ := wireRecoveryFixture(t, wireResponseHandler(t, dnsmessage.RCodeServerFailure), wireResponseHandler(t, dnsmessage.RCodeSuccess))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(id uint16) {
			defer wg.Done()
			query, _ := wireDNS(t, dnsmessage.TypeA)
			binary.BigEndian.PutUint16(query, id)
			out, e := r.ExchangeWire(context.Background(), query, open)
			if e != nil || len(out) < 2 || binary.BigEndian.Uint16(out) != id || DNSResponseStatus(query, out) != "DNS_RESPONSE" {
				t.Error("concurrent DNS response crossed transaction", id, e)
			}
		}(uint16(i + 1))
	}
	wg.Wait()
}
func TestDNSWireRecoveryNoRetryForValidOtherSemantics(t *testing.T) {
	query, reply := wireDNS(t, dnsmessage.TypeAAAA) // NODATA — нормальный результат, не NXDOMAIN.
	for _, tc := range []struct {
		name      string
		code      dnsmessage.RCode
		truncated bool
	}{{"nodata", 0, false}, {"refused", dnsmessage.RCodeRefused, false}, {"truncated", 0, true}} {
		t.Run(tc.name, func(t *testing.T) {
			var m dnsmessage.Message
			m.Unpack(reply)
			m.ID = 0
			m.RCode = tc.code
			m.Truncated = tc.truncated
			first, _ := m.Pack()
			r, open, calls := wireRecoveryFixture(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/dns-message")
				w.Write(first)
			}, wireResponseHandler(t, dnsmessage.RCodeSuccess))
			out, e := r.ExchangeWire(context.Background(), query, open)
			expected := append([]byte(nil), first...)
			binary.BigEndian.PutUint16(expected, 175)
			if e != nil || calls.Load() != 1 || !bytes.Equal(out, expected) {
				t.Fatal("valid DNS semantics changed", e, calls.Load())
			}
		})
	}
}

func TestDNSWireRecoveryBothUnavailableAndParentCancellation(t *testing.T) {
	query, _ := wireDNS(t, dnsmessage.TypeA)
	r, _, _ := wireRecoveryFixture(t, wireResponseHandler(t, 0), wireResponseHandler(t, 0))
	var calls atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	answer, e := r.ExchangeWire(ctx, query, func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
		calls.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if e == nil || len(answer) != 0 || calls.Load() < 1 || calls.Load() > 2 || time.Since(start) > time.Second {
		t.Fatal("all-provider deadline was not bounded", e, calls.Load(), time.Since(start))
	}
	calls.Store(0)
	answer, e = r.ExchangeWire(context.Background(), query, func(context.Context, netip.AddrPort) (net.Conn, error) {
		calls.Add(1)
		return nil, context.DeadlineExceeded
	})
	if e == nil || len(answer) != 0 || calls.Load() != 2 {
		t.Fatal("both unavailable providers were not exhausted", e, calls.Load())
	}
	// Отмена после валидного NXDOMAIN не разрешает ни доставку, ни новый dial.
	ctx, stop := context.WithCancel(context.Background())
	r, open, calls2 := wireRecoveryFixture(t, func(w http.ResponseWriter, r *http.Request) {
		wireResponseHandler(t, dnsmessage.RCodeNameError)(w, r)
		stop()
	}, wireResponseHandler(t, 0))
	out, e := r.ExchangeWire(ctx, query, open)
	if e == nil || len(out) != 0 || calls2.Load() != 1 {
		t.Fatal("canceled DNS returned stale negative", e, calls2.Load())
	}
}
func TestDNSWireRecoveryPreservesDNSSECServiceRecordsAndAge(t *testing.T) {
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, 64, 65} {
		t.Run(typ.String(), func(t *testing.T) {
			query, _ := wireDNS(t, typ)
			expectedReply := make(chan dnsmessage.Message, 1)
			handler := func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				var m dnsmessage.Message
				m.Unpack(b)
				m.Response = true
				m.AuthenticData = true
				q := m.Questions[0]
				m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: typ, Class: q.Class, TTL: 20}, Body: &dnsmessage.UnknownResource{Type: typ, Data: []byte{0, 1, 0}}}}
				if typ == dnsmessage.TypeA {
					m.Answers[0].Body = &dnsmessage.AResource{A: [4]byte{142, 251, 1, 94}}
				}
				if typ == dnsmessage.TypeAAAA {
					m.Answers[0].Body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2607:f8b0::1").As16()}
				}
				// Opaque RRSIG и EDNS DO сохраняются; это не собственная DNSSEC-валидация.
				m.Authorities = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: 46, Class: q.Class, TTL: 20}, Body: &dnsmessage.UnknownResource{Type: 46, Data: []byte{1, 2, 3, 4}}}}
				m.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 1232, TTL: 0x8000}, Body: &dnsmessage.OPTResource{}}}
				expectedReply <- m
				out, _ := m.Pack()
				w.Header().Set("Age", "3")
				w.Header().Set("Content-Type", "application/dns-message")
				w.Write(out)
			}
			r, open, calls := wireRecoveryFixture(t, wireResponseHandler(t, dnsmessage.RCodeServerFailure), handler)
			out, e := r.ExchangeWire(context.Background(), query, open)
			var got dnsmessage.Message
			if e != nil || got.Unpack(out) != nil || calls.Load() != 2 || !got.AuthenticData || got.ID != 175 || len(got.Answers) != 1 || got.Answers[0].Header.TTL != 17 || got.Authorities[0].Header.TTL != 17 || got.Additionals[0].Header.TTL != 0x8000 {
				t.Fatal("DNSSEC/type/TTL changed", e, got)
			}
			// Сверяем полный ответ с единственными разрешёнными изменениями ID и HTTP Age.
			want := <-expectedReply
			want.ID = 175
			want.Answers[0].Header.TTL = 17
			want.Authorities[0].Header.TTL = 17
			expected, _ := want.Pack()
			if !bytes.Equal(out, expected) {
				t.Fatal("opaque service/DNSSEC records were rewritten")
			}
		})
	}
}
