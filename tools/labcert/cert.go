// Package labcert creates ephemeral in-memory identities for local tests only.
package labcert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/buzzmean/veliq/core/transport"
	"math/big"
	"net"
	"time"
)

func Pair() (*tls.Config, *tls.Config, error) {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, nil, e
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "neexitlag ephemeral lab CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if e != nil {
		return nil, nil, e
	}
	root, e := x509.ParseCertificate(der)
	if e != nil {
		return nil, nil, e
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	issue := func(serial int64, usage x509.ExtKeyUsage) (tls.Certificate, error) {
		p, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return tls.Certificate{}, e
		}
		t := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
		b, e := x509.CreateCertificate(rand.Reader, t, root, p, key)
		return tls.Certificate{Certificate: [][]byte{b}, PrivateKey: k}, e
	}
	server, e := issue(2, x509.ExtKeyUsageServerAuth)
	if e != nil {
		return nil, nil, e
	}
	client, e := issue(3, x509.ExtKeyUsageClientAuth)
	if e != nil {
		return nil, nil, e
	}
	s := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{transport.ALPN}, Certificates: []tls.Certificate{server}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	c := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{transport.ALPN}, Certificates: []tls.Certificate{client}, RootCAs: pool}
	return s, c, nil
}
