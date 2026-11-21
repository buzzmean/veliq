package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
)

// Deliberately fragment TCP writes across TLS headers and the large key share.
// Real QUIC+mTLS relay is used; no Internet/Telegram site PASS is asserted.
type fragmentedTLSConn struct {
	net.Conn
	wire *browserproxy.TLSWireObserver
}

func (c *fragmentedTLSConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := 73
		if n > len(p) {
			n = len(p)
		}
		k, e := c.Conn.Write(p[:n])
		c.wire.ObserveClient(p[:k])
		total += k
		p = p[k:]
		if e != nil {
			return total, e
		}
		if k == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
func (c *fragmentedTLSConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	c.wire.ObserveOrigin(p[:n])
	return n, e
}
func (c *fragmentedTLSConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}

func TestPACRelayLargeMLKEMClientHelloVerifiedTLSHTTP(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" || r.TLS == nil || r.TLS.ServerName != "example.com" {
			t.Error("original SNI/Host lost")
		}
		io.WriteString(w, "controlled HTTPS origin body")
	}))
	defer target.Close()
	_, client, _ := setup(t, 10*time.Second)
	wire := &browserproxy.TLSWireObserver{}
	s, err := browserproxy.Listen(context.Background(), browserproxy.Config{
		Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (browserproxy.Owner, error) {
			return browserproxy.Owner{Profile: "chrome"}, nil
		},
		Plan: func(context.Context, browserproxy.Request) (browserproxy.Plan, error) {
			return browserproxy.Plan{Enabled: true, Destination: target.Listener.Addr().(*net.TCPAddr).AddrPort(), Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: "VPS-01", Fallback: flowpolicy.Required}}, nil
		},
		Open: func(ctx context.Context, _ browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
			c, e := client.OpenTCP(ctx, p.Destination)
			if e != nil {
				return nil, e
			}
			return &fragmentedTLSConn{Conn: c, wire: wire}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := net.Dial("tcp", s.Address())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	r := bufio.NewReader(c)
	response, err := http.ReadResponse(r, &http.Request{Method: "CONNECT"})
	if err != nil || response.StatusCode != 200 {
		t.Fatal(response, err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	tc := tls.Client(c, &tls.Config{ServerName: "example.com", RootCAs: roots, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{"http/1.1"}})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	response, err = http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(body) != "controlled HTTPS origin body" {
		t.Fatal(response, err, string(body))
	}
	deadline := time.Now().Add(time.Second)
	for {
		rows := s.Snapshot().Records
		if len(rows) == 1 && rows[0].TLS != nil && rows[0].TLS.Origin.Bytes > 0 {
			pac := rows[0].TLS
			actual := wire.Snapshot()
			if pac.Client.ClientHelloBytes < 1000 || actual.Client.ClientHelloBytes != pac.Client.ClientHelloBytes {
				t.Fatal("large hello was not observed intact at both boundaries", pac, actual)
			}
			if !bytes.Equal(wireJSON(t, pac.Client.Records), wireJSON(t, actual.Client.Records)) {
				t.Fatal("record framing changed", pac, actual)
			}
			if rows[0].Plan.Policy.Action != flowpolicy.RelayRequired || rows[0].StallRetried {
				t.Fatal("protected route changed", rows[0])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("missing passive TLS evidence", rows)
		}
		time.Sleep(time.Millisecond)
	}
}

// Record-layer fragmentation plus opaque GREASE/ECH-like extension bytes must
// cross the real relay unchanged. This is byte-preservation, not valid ECH proof.
func TestRelayPreservesOpaqueLargeFragmentedTLSFlight(t *testing.T) {
	_, client, _ := setup(t, 10*time.Second)
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	payload := bytes.Repeat([]byte{0xfa, 0xfa, 0xfe, 0x0d, 0, 0xff}, 1800)
	flight := []byte{}
	for len(payload) > 0 {
		n := 997
		if n > len(payload) {
			n = len(payload)
		}
		flight = append(flight, 22, 3, 3, byte(n>>8), byte(n))
		flight = append(flight, payload[:n]...)
		payload = payload[n:]
	}
	done := make(chan error, 1)
	go func() {
		c, e := origin.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, len(flight))
		_, e = io.ReadFull(c, got)
		if e == nil && !bytes.Equal(got, flight) {
			e = fmt.Errorf("TLS bytes changed")
		}
		if e == nil {
			_, e = c.Write([]byte{21, 3, 3, 0, 2, 2, 40})
		}
		done <- e
	}()
	c, err := client.OpenTCP(context.Background(), origin.Addr().(*net.TCPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	wire := &browserproxy.TLSWireObserver{}
	f := &fragmentedTLSConn{Conn: c, wire: wire}
	if _, e := f.Write(flight); e != nil {
		t.Fatal(e)
	}
	reply := make([]byte, 7)
	if _, e := io.ReadFull(f, reply); e != nil {
		t.Fatal(e)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if s := wire.Snapshot(); s.Origin.State != "TLS_PLAINTEXT_ALERT_COMPLETE" || s.Origin.AlertDescription != 40 || s.Client.Bytes != uint64(len(flight)) {
		t.Fatal(s)
	}
}

func wireJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestPACRelayIncompleteAlertIsNotLostOrReportedAsComplete(t *testing.T) {
	_, client, _ := setup(t, 10*time.Second)
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	hello := append([]byte{22, 3, 1, 8, 0, 1, 0, 7, 252}, bytes.Repeat([]byte{0xfa}, 2044)...)
	done := make(chan error, 1)
	go func() {
		c, e := origin.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, len(hello))
		_, e = io.ReadFull(c, got)
		if e == nil && !bytes.Equal(got, hello) {
			e = fmt.Errorf("hello changed")
		}
		if e == nil {
			_, e = c.Write([]byte{21, 3, 3, 0, 2})
		}
		done <- e
	}()
	wire := &browserproxy.TLSWireObserver{}
	s, err := browserproxy.Listen(context.Background(), browserproxy.Config{
		Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (browserproxy.Owner, error) {
			return browserproxy.Owner{Profile: "chrome"}, nil
		},
		Plan: func(context.Context, browserproxy.Request) (browserproxy.Plan, error) {
			return browserproxy.Plan{Enabled: true, Destination: origin.Addr().(*net.TCPAddr).AddrPort(), Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: "VPS-01", Fallback: flowpolicy.Required}}, nil
		},
		Open: func(ctx context.Context, _ browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
			c, e := client.OpenTCP(ctx, p.Destination)
			if e != nil {
				return nil, e
			}
			return &fragmentedTLSConn{Conn: c, wire: wire}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := net.Dial("tcp", s.Address())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(c, "CONNECT web.telegram.org:443 HTTP/1.1\r\nHost: web.telegram.org:443\r\n\r\n")
	b := bufio.NewReader(c)
	resp, err := http.ReadResponse(b, &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(resp, err)
	}
	if _, err := c.Write(hello); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(b)
	if err != nil || !bytes.Equal(got, []byte{21, 3, 3, 0, 2}) {
		t.Fatal("five-byte origin header lost", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	for {
		rows := s.Snapshot().Records
		if len(rows) == 1 && !rows[0].Active {
			if rows[0].TLS == nil || rows[0].TLS.Origin.State != "TLS_HEADER_ONLY" || rows[0].Received != 5 || wire.Snapshot().Origin.Bytes != 5 {
				t.Fatal(rows)
			}
			break
		}
		if time.Now().After(until) {
			t.Fatal("missing completed TLS evidence", rows)
		}
		time.Sleep(time.Millisecond)
	}
}
