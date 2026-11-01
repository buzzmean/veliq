package localstrategy

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func http80Fixture(t *testing.T) (*LocalStrategyEngine, *State, Metadata) {
	t.Helper()
	p := Profile{ID: "http80-test", Name: "HTTP fixture", Version: 1, Protocol: "tcp", Ports: []uint16{80}, Application: "chrome.exe", Domains: []string{"www.example.org"}, Strategy: HTTP80HostSplit, Cutoff: 1, Enabled: true}
	e := engine(t, p)
	m := Metadata{Application: `C:\Apps\chrome.exe`, Domain: "www.example.org", Protocol: "tcp", StrategyID: p.ID, Destination: netip.MustParseAddrPort("203.0.113.9:80")}
	st := &State{}
	syn := http80Packet(nil, 999)
	syn[33] = 2
	checksumTransport(syn)
	e.Process(syn, st, m)
	st.ConfirmHandshake(1000, 99)
	return e, st, m
}
func http80Packet(data []byte, seq uint32) []byte {
	p := segment(data, seq)
	binary.BigEndian.PutUint16(p[22:], 80)
	checksumTransport(p)
	return p
}

func TestHTTP80HostRejectsAmbiguousHeaders(t *testing.T) {
	for _, raw := range []string{
		"GET / HTTP/1.1\r\nHost: www.example.org\r\nHost: api.openai.com\r\n\r\n",
		"GET / HTTP/1.1\r\nHost : www.example.org\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: www.example.org:443\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: www.example.org\nHost: other.example\r\n\r\n",
		"GET http://api.openai.com/ HTTP/1.1\r\nHost: www.example.org\r\n\r\n",
		"CONNECT www.example.org:80 HTTP/1.1\r\nHost: www.example.org\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: www.example.org\r\n folded: value\r\n\r\n",
		"GET / HTTP/1.1\r\nX: " + strings.Repeat("x", MaxHTTP80HeaderBytes) + "\r\nHost: www.example.org\r\n\r\n",
	} {
		if host, _, _, _ := HTTP80Host([]byte(raw)); host != "" {
			t.Fatal("ambiguous header accepted")
		}
		if !strings.Contains(raw, "www.example.org:443") {
			if host, reason, complete := InspectHelloStream([]byte(raw)); host != "" || reason == "HTTP_HOST" || !complete {
				t.Fatal("native ingress trusted an ambiguous HTTP authority", reason)
			}
		}
	}
	if host, reason, complete := InspectHelloStream([]byte("GET / HTTP/1.1\r\nHost: www.example.org:8080\r\n\r\n")); host != "www.example.org" || reason != "HTTP_HOST_OTHER_PORT" || !complete {
		t.Fatal("ordinary HTTP nonstandard port regressed")
	}
	request := []byte("POST /upload HTTP/1.1\r\nhOsT:\tWWW.Example.ORG:80 \t\r\nAuthorization: fixture\r\nContent-Length: 4\r\n\r\nbody")
	host, cut, size, complete := HTTP80Host(request)
	if !complete || host != "www.example.org" || request[cut-1] != 'W' || request[cut] != 'W' || !bytes.Equal(request[size:], []byte("body")) {
		t.Fatal(host, cut, size)
	}
	for i := range request {
		request[i] = 0
	}
	if host != "www.example.org" {
		t.Fatal("hostname borrowed request storage")
	}
}

func TestHTTP80SplitAcrossEveryHeaderBoundary(t *testing.T) {
	raw := []byte("POST /upload HTTP/1.1\r\nHost: www.example.org\r\nContent-Length: 4\r\n\r\nbody")
	for split := 1; split < bytes.Index(raw, []byte("\r\n\r\n"))+4; split++ {
		for _, reverse := range []bool{false, true} {
			e, st, m := http80Fixture(t)
			parts := [][]byte{http80Packet(raw[:split], 1000), http80Packet(raw[split:], 1000+uint32(split))}
			if reverse {
				parts[0], parts[1] = parts[1], parts[0]
			}
			b := &HelloBuffer{}
			var result *BufferedResult
			for _, p := range parts {
				accepted, r := e.BufferTCP(p, st, b, m, time.Now())
				if !accepted {
					t.Fatal("HTTP segment rejected", split)
				}
				if r != nil {
					result = r
				}
			}
			if result == nil {
				t.Fatal("header never completed", split)
			}
			assertStream(t, result.Result, raw, 1000)
			if b.Pending() || st.logicalHello != nil || result.Result.Inspection.ReassembledSNI || result.Result.Inspection.Domain != "www.example.org" {
				t.Fatal("HTTP retention or false TLS evidence", split, result.Result.Inspection)
			}
			// An existing packet boundary at Host+1 already provides the cut.
			_, cut, _, _ := HTTP80Host(raw)
			if split != cut && !result.Result.Modified {
				t.Fatal("Host not split", split)
			}
			if later := e.Process(http80Packet(raw, 1000+uint32(len(raw))), st, m); later.Modified {
				t.Fatal("second HTTP request transformed")
			}
		}
	}
}

func TestHTTP80LSOAndScope(t *testing.T) {
	e, st, m := http80Fixture(t)
	raw := []byte("POST / HTTP/1.1\r\nHost: www.example.org\r\nX-Padding: " + strings.Repeat("x", 7000) + "\r\nContent-Length: 12000\r\n\r\n" + strings.Repeat("b", 12000))
	_, r := e.BufferTCP(http80Packet(raw, 1000), st, &HelloBuffer{}, m, time.Now())
	if r == nil || !r.Result.Modified || len(r.Result.Packets) > 64 {
		t.Fatal("bounded LSO HTTP not split")
	}
	assertStream(t, r.Result, raw, 1000)
	for _, mutate := range []func(*Metadata){func(m *Metadata) { m.Application = `C:\Games\game.exe` }, func(m *Metadata) { m.Destination = netip.MustParseAddrPort("203.0.113.9:443") }} {
		e, st, m := http80Fixture(t)
		mutate(&m)
		if r := e.Process(http80Packet(raw, 1000), st, m); r.Modified {
			t.Fatal("HTTP escaped application/port scope")
		}
	}
	e, st, m = http80Fixture(t)
	m.TrustedOrigin = true
	if r := e.Process(http80Packet([]byte("GET / HTTP/1.1\r\nHost: api.openai.com\r\n\r\n"), 1000), st, m); r.Modified {
		t.Fatal("metadata replaced actual Host")
	}
}
