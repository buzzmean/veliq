package netdiagnostic

import (
	"context"
	"crypto/tls"
	"github.com/buzzmean/neexitlag/tools/labcert"
	"net"
	"testing"
	"time"
)

func TestDiagnosticTLSKeepsCertificateValidation(t *testing.T) {
	st, ct, e := labcert.Pair()
	if e != nil {
		t.Fatal(e)
	}
	st.ClientAuth = tls.NoClientCert
	ln, e := tls.Listen("tcp", "127.0.0.1:0", st)
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for j := 0; j < 2; j++ {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(time.Second))
			_ = c.(*tls.Conn).Handshake()
			_ = c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, _ := tlsEndpoint(ctx, ln.Addr().String(), "127.0.0.1", ct.RootCAs)
	if got != "OK" {
		t.Fatal(got)
	}
	got, _ = tlsEndpoint(ctx, ln.Addr().String(), "example.com", ct.RootCAs)
	if got != "CERTIFICATE_REJECTED_RESPONSE_OBSERVED" {
		t.Fatal(got)
	}
	<-done
	if got := ErrorClass(&net.OpError{Err: context.DeadlineExceeded}); got != "BOUNDED_TIMEOUT" {
		t.Fatal(got)
	}
}
