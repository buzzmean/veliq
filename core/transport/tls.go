package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/quic-go/quic-go"
	"os"
	"time"
)

const ALPN = "neexitlag/1"

func TLS(cert, key, ca string, server bool) (*tls.Config, error) {
	pair, e := tls.LoadX509KeyPair(cert, key)
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(ca)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("invalid CA")
	}
	c := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, NextProtos: []string{ALPN}, RootCAs: pool}
	if server {
		c.ClientCAs = pool
		c.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return c, nil
}
func QUICConfig() *quic.Config {
	return &quic.Config{EnableDatagrams: true, Allow0RTT: false, HandshakeIdleTimeout: 3 * time.Second, MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second, MaxIncomingStreams: 64, MaxIncomingUniStreams: -1, InitialStreamReceiveWindow: 64 * 1024, MaxStreamReceiveWindow: 256 * 1024, InitialConnectionReceiveWindow: 256 * 1024, MaxConnectionReceiveWindow: 1024 * 1024}
}

// ClientQUICConfig advertises bounded downstream credit to existing relays.
// The former 256KiB per-stream / 1MiB per-session maxima constrained long RTT
// video transfers even after congestion control had warmed up. These windows
// auto-tune on consumption; they are limits, not eager allocations. Eight pool
// sessions may authorize at most 64MiB of outstanding stream payload per client.
// Server receive windows, stream counts, 0-RTT and authorization are unchanged.
func ClientQUICConfig() *quic.Config {
	c := QUICConfig()
	c.InitialStreamReceiveWindow = 256 * 1024
	c.MaxStreamReceiveWindow = 2 * 1024 * 1024
	c.InitialConnectionReceiveWindow = 1024 * 1024
	c.MaxConnectionReceiveWindow = 8 * 1024 * 1024
	return c
}
