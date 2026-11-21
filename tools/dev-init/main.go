// dev-init provisions development credentials once; it never prints secret values.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/buzzmean/neexitlag/core/security"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func write(path string, b []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	closeErr := f.Close()
	if e != nil {
		return e
	}
	return closeErr
}
func keyPEM(key ed25519.PrivateKey) ([]byte, error) {
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
func run(control, relay, public, db string) error {
	if _, e := os.Stat(filepath.Join(control, "ready")); e == nil {
		return nil
	}
	pub, caKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "neexitlag development device/relay CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(365 * 24 * time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, caKey)
	if e != nil {
		return e
	}
	caCert, e := x509.ParseCertificate(der)
	if e != nil {
		return e
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	serverPub, serverKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	server := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "relay"}, DNSNames: []string{"relay", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, e := x509.CreateCertificate(rand.Reader, server, caCert, serverPub, caKey)
	if e != nil {
		return e
	}
	issuerPub, issuer, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	trust, _ := json.Marshal(map[string]string{"dev-1": base64.RawURLEncoding.EncodeToString(issuerPub)})
	admin, e := security.NewID()
	if e != nil {
		return e
	}
	heartbeat, e := security.NewID()
	if e != nil {
		return e
	}
	password, e := security.NewID()
	if e != nil {
		return e
	}
	caKeyPEM, e := keyPEM(caKey)
	if e != nil {
		return e
	}
	serverKeyPEM, e := keyPEM(serverKey)
	if e != nil {
		return e
	}
	issuerKeyPEM, e := keyPEM(issuer)
	if e != nil {
		return e
	}
	files := map[string][]byte{filepath.Join(control, "ca.pem"): caPEM, filepath.Join(control, "ca.key"): caKeyPEM, filepath.Join(control, "signing.key"): issuerKeyPEM, filepath.Join(control, "admin.token"): []byte(admin), filepath.Join(control, "heartbeat.token"): []byte(heartbeat), filepath.Join(relay, "heartbeat.token"): []byte(heartbeat), filepath.Join(relay, "ca.pem"): caPEM, filepath.Join(relay, "relay.pem"): pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), filepath.Join(relay, "relay.key"): serverKeyPEM, filepath.Join(relay, "trust.json"): trust, filepath.Join(public, "ca.pem"): caPEM, filepath.Join(public, "trust.json"): trust, filepath.Join(db, "password"): []byte(password)}
	for path, b := range files {
		if e = write(path, b); e != nil {
			return fmt.Errorf("development credential generation failed; refusing to overwrite existing files: %w", e)
		}
	}
	return write(filepath.Join(control, "ready"), []byte("initialized\n"))
}
func main() {
	root := flag.String("dir", ".dev", "development state directory")
	control := flag.String("control-dir", "", "control plane secrets directory")
	relay := flag.String("relay-dir", "", "relay-specific credentials directory")
	public := flag.String("public-dir", "", "public trust directory")
	db := flag.String("database-dir", "", "PostgreSQL secret directory")
	flag.Parse()
	if *control == "" {
		*control = filepath.Join(*root, "control")
	}
	if *relay == "" {
		*relay = filepath.Join(*root, "relay")
	}
	if *public == "" {
		*public = filepath.Join(*root, "public")
	}
	if *db == "" {
		*db = filepath.Join(*root, "postgres")
	}
	if e := run(*control, *relay, *public, *db); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	fmt.Println("Development identities ready; private credentials remain in their scoped directories.")
}
