package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

const (
	certRenewBefore   = 10 * 24 * time.Hour
	certRenewInterval = 6 * time.Hour
)

// certRenewer keeps the device certificate fresh. The key never changes; only the
// certificate is replaced, in memory (new handshakes pick it up through
// GetClientCertificate) and atomically on disk so a restart keeps the new one.
type certRenewer struct {
	current atomic.Pointer[tls.Certificate]
	path    string
	roots   *x509.CertPool
	key     ed25519.PrivateKey
	fetch   func(context.Context) (string, error)
}

func (r *certRenewer) clientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if c := r.current.Load(); c != nil {
		return c, nil
	}
	return nil, errors.New("device certificate unavailable")
}

// renewIfNeeded returns true when a new certificate was installed.
func (r *certRenewer) renewIfNeeded(ctx context.Context, now time.Time) (bool, error) {
	cur := r.current.Load()
	if cur == nil || cur.Leaf == nil {
		return false, errors.New("device certificate unavailable")
	}
	if cur.Leaf.NotAfter.Sub(now) > certRenewBefore {
		return false, nil
	}
	text, err := r.fetch(ctx)
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode([]byte(text))
	if block == nil || block.Type != "CERTIFICATE" {
		return false, errors.New("renewal response is not a certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, errors.New("invalid renewed certificate")
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !pub.Equal(r.key.Public()) {
		return false, errors.New("renewed certificate does not match device identity")
	}
	if !leaf.NotAfter.After(cur.Leaf.NotAfter) {
		return false, errors.New("renewed certificate does not extend validity")
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: r.roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return false, errors.New("renewed certificate not issued by the trusted CA")
	}
	if err = writeFileAtomic(r.path, []byte(text)); err != nil {
		return false, err
	}
	r.current.Store(&tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: r.key, Leaf: leaf})
	return true, nil
}

func (r *certRenewer) run(ctx context.Context) {
	t := time.NewTicker(certRenewInterval)
	defer t.Stop()
	for {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		renewed, err := r.renewIfNeeded(cctx, time.Now())
		cancel()
		switch {
		case err != nil:
			slog.Warn("device certificate renewal failed; will retry", "error", err)
		case renewed:
			slog.Info("device certificate renewed", "not_after", r.current.Load().Leaf.NotAfter.UTC().Format(time.RFC3339))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func writeFileAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".device-cert-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}
