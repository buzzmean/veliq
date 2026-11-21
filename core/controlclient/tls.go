package controlclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"time"
)

// Explicit private CA trust for the remote E2E deployment; never disables TLS verification.
func HTTPSClient(path string) (*http.Client, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return nil, errors.New("invalid control plane CA")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("control plane redirects are disabled") }}, nil
}
