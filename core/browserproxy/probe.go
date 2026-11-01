package browserproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

// ProbeResult describes an independent, credential-free origin probe. It never
// proves that a browser page, its scripts or a logged-in application works.
type ProbeResult struct {
	Status     int    `json:"http_status"`
	Bytes      uint64 `json:"received_bytes"`
	Failure    string `json:"failure,omitempty"`
	Phase      string `json:"phase"`
	Detail     string `json:"detail,omitempty"`
	ALPN       string `json:"alpn,omitempty"`
	TLSVersion uint16 `json:"tls_version,omitempty"`
	BodyBytes  uint64 `json:"body_bytes"`
}

// ProbeOrigin retains the original caller contract.
func ProbeOrigin(ctx context.Context, host string, port uint16, secure bool, roots *x509.CertPool, open func(context.Context) (net.Conn, error)) (int, uint64, string) {
	r := ProbeOriginDetailed(ctx, host, port, secure, roots, open)
	return r.Status, r.Bytes, r.Failure
}

type probeCountingConn struct {
	net.Conn
	received atomic.Uint64
}

func (c *probeCountingConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	if n > 0 {
		c.received.Add(uint64(n))
	}
	return n, e
}

func probeError(r ProbeResult, err error) ProbeResult {
	r.Failure = "CONNECTION_FAILED"
	r.Detail = "IO_FAILED"
	var certificate *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	var ne net.Error
	switch {
	case errors.As(err, &certificate):
		r.Failure, r.Detail = "TLS_CERTIFICATE_ERROR", "CERTIFICATE_VERIFICATION"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		r.Failure, r.Detail = "NETWORK_TIMEOUT", "DEADLINE"
	case errors.Is(err, context.Canceled):
		r.Detail = "CANCELED"
	case errors.Is(err, syscall.ECONNRESET):
		r.Detail = "PEER_RESET"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		r.Detail = "PEER_CLOSED"
	case errors.As(err, &record):
		r.Detail = "INVALID_TLS_RECORD"
	default:
		// Finite diagnostics only: never export arbitrary peer-controlled error text.
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "remote error" {
			r.Detail = "REMOTE_TLS_ALERT"
		}
	}
	if r.Phase == "ORIGIN_TLS" && r.Failure == "CONNECTION_FAILED" {
		r.Failure = "TLS_FAILED"
	}
	return r
}

// ProbeOriginDetailed negotiates HTTP/2 or HTTP/1.1 with the ORIGINAL DNS host
// as SNI and certificate name even when open uses a pinned IP over relay QUIC.
// A bounded GET body is required; neither a TCP ACK nor HEAD headers is success.
// Redirects are not followed (a different origin must get its own route plan).
func ProbeOriginDetailed(ctx context.Context, host string, port uint16, secure bool, roots *x509.CertPool, open func(context.Context) (net.Conn, error)) (r ProbeResult) {
	return probeOrigin(ctx, host, port, secure, "/", 32769, 1500*time.Millisecond, roots, open)
}

// ProbeOriginTransfer samples a bounded public GET with verified TLS. It does
// not follow redirects, send credentials, or infer that a video CDN root works.
// BodyBytes (not TLS framing or certificate bytes) must exceed 64KiB at callers.
func ProbeOriginTransfer(ctx context.Context, host, path string, roots *x509.CertPool, open func(context.Context) (net.Conn, error)) ProbeResult {
	if path == "" || path[0] != '/' || len(path) > 256 {
		return ProbeResult{Failure: "INVALID_PROBE_PATH"}
	}
	return probeOrigin(ctx, host, 443, true, path, 128*1024+1, 4*time.Second, roots, open)
}

func probeOrigin(ctx context.Context, host string, port uint16, secure bool, path string, bodyLimit int64, budget time.Duration, roots *x509.CertPool, open func(context.Context) (net.Conn, error)) (r ProbeResult) {
	r = ProbeResult{Phase: "RELAY_OR_TCP_OPEN"}
	conn, err := open(ctx)
	if err != nil {
		return probeError(r, err)
	}
	defer conn.Close()
	deadline := time.Now().Add(budget)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return probeError(r, err)
	}
	// Cancellation must also interrupt a body read, not just the handshake.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	counter := &probeCountingConn{Conn: conn}
	defer func() {
		r.Bytes = counter.received.Load()
		// Cancellation closes the socket concurrently with Read. That Read may
		// return net.ErrClosed instead of a timeout; retain the known context
		// cause instead of exporting a misleading generic I/O failure. Never
		// replace an actual TLS/certificate/HTTP result or a completed response.
		if r.Failure == "CONNECTION_FAILED" && r.Detail == "IO_FAILED" && ctx.Err() != nil {
			r = probeError(r, ctx.Err())
		}
	}()
	var origin net.Conn = counter
	if secure {
		r.Phase = "ORIGIN_TLS"
		tc := tls.Client(counter, &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}})
		if err = tc.HandshakeContext(ctx); err != nil {
			return probeError(r, err)
		}
		state := tc.ConnectionState()
		r.ALPN, r.TLSVersion = state.NegotiatedProtocol, state.Version
		origin = tc
	}
	authority := host
	if (port != 443 && secure) || (port != 80 && !secure) {
		authority = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}
	scheme := "http"
	if secure {
		scheme = "https"
	}
	req, err := http.NewRequestWithContext(ctx, "GET", scheme+"://"+authority+path, nil)
	if err != nil {
		return probeError(r, err)
	}
	req.Header.Set("User-Agent", "VELIQ-Origin-Probe/2")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache")
	tr := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 32768,
		DialContext:    func(context.Context, string, string) (net.Conn, error) { return origin, nil },
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return origin, nil },
	}
	defer tr.CloseIdleConnections()
	r.Phase = "ORIGIN_HTTP"
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return probeError(r, err)
	}
	defer resp.Body.Close()
	r.Status = resp.StatusCode
	r.Phase = "ORIGIN_BODY"
	// Complete small responses; bound sampling of large documents. This is origin
	// availability only, not complete-page acceptance. Truncated declared bodies fail.
	b, err := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
	r.BodyBytes = uint64(len(b))
	r.Bytes = counter.received.Load()
	if err != nil {
		return probeError(r, err)
	}
	if len(b) == 0 && resp.StatusCode != http.StatusNoContent && (resp.StatusCode < 300 || resp.StatusCode >= 400) {
		r.Failure, r.Detail = "CONNECTION_FAILED", "EMPTY_BODY"
		return r
	}
	r.Phase = "ORIGIN_RESPONSE"

	return r
}
