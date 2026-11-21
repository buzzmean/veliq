package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return testCA{c, key}
}

func (ca testCA) issue(t *testing.T, pub ed25519.PublicKey, notAfter time.Time) (*x509.Certificate, string) {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return leaf, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCertRenewalInstallsOnlyTrustedExtendedCertificateForSameKey(t *testing.T) {
	ca := newTestCA(t)
	other := newTestCA(t)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	leaf, _ := ca.issue(t, pub, now.Add(5*24*time.Hour)) // inside the renewal window
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	path := filepath.Join(t.TempDir(), "device.pem")
	os.WriteFile(path, []byte("old"), 0600)
	var reply string
	r := &certRenewer{path: path, roots: pool, key: key, fetch: func(context.Context) (string, error) { return reply, nil }}
	r.current.Store(&tls.Certificate{Leaf: leaf, PrivateKey: key})

	for name, mk := range map[string]func() string{
		"foreign key":  func() string { _, p := ca.issue(t, otherPub, now.Add(30*24*time.Hour)); return p },
		"untrusted CA": func() string { _, p := other.issue(t, pub, now.Add(30*24*time.Hour)); return p },
		"no extension": func() string { _, p := ca.issue(t, pub, now.Add(4*24*time.Hour)); return p },
		"not a PEM":    func() string { return "garbage" },
	} {
		reply = mk()
		if ok, err := r.renewIfNeeded(context.Background(), now); ok || err == nil {
			t.Fatalf("%s accepted (ok=%v err=%v)", name, ok, err)
		}
		if b, _ := os.ReadFile(path); string(b) != "old" || r.current.Load().Leaf != leaf {
			t.Fatalf("%s changed state", name)
		}
	}

	newLeaf, good := ca.issue(t, pub, now.Add(30*24*time.Hour))
	reply = good
	if ok, err := r.renewIfNeeded(context.Background(), now); !ok || err != nil {
		t.Fatalf("valid renewal rejected: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != good {
		t.Fatal("certificate not persisted")
	}
	got, err := r.clientCertificate(nil)
	if err != nil || !got.Leaf.NotAfter.Equal(newLeaf.NotAfter) {
		t.Fatal("new certificate not served to new handshakes")
	}
	// Outside the window nothing is requested.
	r.fetch = func(context.Context) (string, error) { return "", errors.New("must not be called") }
	if ok, err := r.renewIfNeeded(context.Background(), now); ok || err != nil {
		t.Fatalf("renewed outside window: %v %v", ok, err)
	}
}
