package controlplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestIssuedClientCertificateBindsKeyUsageAndLifetime(t *testing.T) {
	caPub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, caPub, caKey)
	ca, _ := x509.ParseCertificate(der)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	raw, err := issueClientCertificate(ca, caKey, pub, now)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(raw)
	if !leaf.PublicKey.(ed25519.PublicKey).Equal(pub) || leaf.NotAfter.Sub(now) > ClientCertificateLifetime+time.Second || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("unexpected certificate: %+v", leaf)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
}
