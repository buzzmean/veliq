package windowsplatform

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// Exercise the exact portable pre-read used by the native Windows TCP worker.
// No certificate validation bypass: only capture a generated ClientHello; the
// synthetic peer closes before presenting any certificate/HTTP response.
func TestDeferredLargeMLKEMHelloPreservesAllBytes(t *testing.T) {
	hello := deferredMLKEMHello(t)
	for _, chunk := range []int{97, 7, 1} {
		t.Run(strconv.Itoa(chunk), func(t *testing.T) {
			x, y := net.Pipe()
			defer x.Close()
			defer y.Close()
			x.SetDeadline(time.Now().Add(3 * time.Second))
			sent := make(chan error, 1)
			go func() {
				defer y.Close()
				for p := hello; len(p) > 0; {
					n := chunk
					if n > len(p) {
						n = len(p)
					}
					_, e := y.Write(p[:n])
					if e != nil {
						sent <- e
						return
					}
					p = p[n:]
				}
				sent <- nil
			}()
			prefix, domain, reason := ReadDeferredHello(x)
			tail, err := io.ReadAll(x)
			if err != nil {
				t.Fatal(err)
			}
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(append(prefix, tail...), hello) {
				t.Fatal("native pre-read changed/truncated TLS bytes", len(prefix), len(tail), len(hello))
			}
			if domain != "web.telegram.org" || reason != "REASSEMBLY_COMPLETE" {
				t.Fatal(domain, reason)
			}
		})
	}
}

func deferredMLKEMHello(t *testing.T) []byte {
	t.Helper()
	a, b := net.Pipe()
	a.SetDeadline(time.Now().Add(3 * time.Second))
	b.SetDeadline(time.Now().Add(3 * time.Second))
	tc := tls.Client(a, &tls.Config{ServerName: "web.telegram.org", MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{"h2", "http/1.1"}})
	done := make(chan error, 1)
	go func() { done <- tc.Handshake() }()
	h := make([]byte, 5)
	if _, err := io.ReadFull(b, h); err != nil {
		a.Close()
		b.Close()
		t.Fatal(err)
	}
	payload := make([]byte, int(h[3])<<8|int(h[4]))
	_, err := io.ReadFull(b, payload)
	b.Close()
	a.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("no synthetic TLS handshake may succeed without a certificate")
	}
	hello := append(h, payload...)
	if len(hello) < 1200 {
		t.Fatal("large ML-KEM hello not generated", len(hello))
	}
	return hello
}
