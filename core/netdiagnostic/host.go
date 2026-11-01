package netdiagnostic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"net"
	"net/netip"
	"syscall"
	"time"
)

func ErrorClass(err error) string {
	if err == nil {
		return "OK"
	}
	var cert *tls.CertificateVerificationError
	var ne net.Error
	switch {
	case errors.As(err, &cert):
		return "CERTIFICATE_REJECTED_RESPONSE_OBSERVED"
	case errors.Is(err, syscall.ECONNRESET):
		return "RESET_OBSERVED"
	case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return "BOUNDED_TIMEOUT"
	default:
		return "IO_ERROR"
	}
}

type HostResult struct {
	Diagnosis                                      Diagnosis `json:"diagnosis"`
	Host, Address, TCP, RealTLS, ForeignTLS, Stage string
	TCPMS, RealTLSMS, ForeignTLSMS                 float64
	HTTP                                           browserproxy.ProbeResult
}

func timedTLS(ctx context.Context, ip, sni string, roots *x509.CertPool) (string, float64) {
	return tlsEndpoint(ctx, net.JoinHostPort(ip, "443"), sni, roots)
}
func tlsEndpoint(ctx context.Context, address, sni string, roots *x509.CertPool) (string, float64) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	c, e := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if e != nil {
		return ErrorClass(e), float64(time.Since(start)) / float64(time.Millisecond)
	}
	defer c.Close()
	secure := tls.Client(c, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12, RootCAs: roots})
	e = secure.HandshakeContext(ctx)
	return ErrorClass(e), float64(time.Since(start)) / float64(time.Millisecond)
}
func Host(ctx context.Context, host, ip, path string) (r HostResult) {
	r = HostResult{Host: host, Address: ip, Stage: "UNCLASSIFIED"}
	defer func() { r.Diagnosis = DiagnoseHost(r) }()
	addr, e := netip.ParseAddr(ip)
	if e != nil || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		r.Stage = "PUBLIC_ADDRESS_REQUIRED"
		return r
	}
	start := time.Now()
	attempt, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	c, e := (&net.Dialer{}).DialContext(attempt, "tcp", net.JoinHostPort(ip, "443"))
	cancel()
	r.TCP = ErrorClass(e)
	r.TCPMS = float64(time.Since(start)) / float64(time.Millisecond)
	if e != nil {
		r.Stage = "TCP_CONNECT_FAILED_NO_SYNACK_PROOF"
		return r
	}
	c.Close()
	r.RealTLS, r.RealTLSMS = timedTLS(ctx, ip, host, nil)
	r.ForeignTLS, r.ForeignTLSMS = timedTLS(ctx, ip, "example.com", nil)
	r.Stage = "TLS_FAILURE_UNCLASSIFIED"
	if r.RealTLS == "RESET_OBSERVED" {
		r.Stage = "TLS_RESET_OBSERVED_NOT_DPI_PROOF"
	}
	if r.RealTLS == "BOUNDED_TIMEOUT" {
		r.Stage = "TLS_NO_REPLY_BEFORE_BUDGET"
	}
	if r.RealTLS == "OK" {
		r.HTTP = browserproxy.ProbeOriginTransfer(ctx, host, path, nil, func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
		})
		r.Stage = "HTTP_RESPONSE_NOT_BULK"
		if r.HTTP.BodyBytes > 64*1024 && r.HTTP.Failure == "" {
			r.Stage = "PUBLIC_BULK_OBSERVED_NOT_APPLICATION_PASS"
		} else if r.HTTP.BodyBytes >= 16*1024 && r.HTTP.Failure == "NETWORK_TIMEOUT" {
			r.Stage = "FREEZE_AFTER_BODY_BYTES_NOT_DPI_PROOF"
		} else if r.HTTP.Failure != "" {
			r.Stage = "HTTP_OR_BODY_FAILED"
		}
	}
	return r
}
