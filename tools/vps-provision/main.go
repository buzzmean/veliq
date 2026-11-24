// Provisions an explicit VPS identity and scoped private files; never prints key material.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/buzzmean/veliq/core/security"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

func publicIPv4(s string) (netip.Addr, error) {
	ip, e := netip.ParseAddr(s)
	if e != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return netip.Addr{}, errors.New("explicit public VPS IPv4 required")
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15", "240.0.0.0/4"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return netip.Addr{}, errors.New("test/special IP is not a real VPS address")
		}
	}
	return ip, nil
}
func put(root, path string, b []byte) error {
	path = filepath.Join(root, path)
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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
func keyPEM(key ed25519.PrivateKey) []byte {
	b, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})
}
func provision(root, address string) error {
	ip, e := publicIPv4(address)
	if e != nil {
		return e
	}
	return createBundle(root, ip)
}
func createBundle(root string, ip netip.Addr) error {
	var e error
	if _, e = os.Stat(root); !os.IsNotExist(e) {
		return errors.New("output directory must not exist; refusing to replace identities")
	}
	if e = os.MkdirAll(root, 0700); e != nil {
		return e
	}
	now := time.Now()
	pub, caKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "neexitlag private VPS E2E CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(365 * 24 * time.Hour)}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, caKey)
	if e != nil {
		return e
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	serverPub, serverKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	server := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "neexitlag VPS"}, IPAddresses: []net.IP{net.IP(ip.AsSlice()), net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * 24 * time.Hour)}
	serverDER, e := x509.CreateCertificate(rand.Reader, server, caCert, serverPub, caKey)
	if e != nil {
		return e
	}
	signerPub, signer, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	trust, _ := json.Marshal(map[string]string{"vps-1": base64.RawURLEncoding.EncodeToString(signerPub)})
	files := map[string][]byte{"server/ca.pem": caPEM, "server/ca.key": keyPEM(caKey), "server/server.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), "server/server.key": keyPEM(serverKey), "server/signing.key": keyPEM(signer), "server/trust.json": trust, "windows/trust/ca.pem": caPEM, "windows/trust/cp-ca.pem": caPEM, "windows/trust/trust.json": trust}
	for _, name := range []string{"admin.token", "heartbeat.token", "echo.token", "database.password"} {
		v, e := security.NewID()
		if e != nil {
			return e
		}
		files["server/"+name] = []byte(v)
		if name == "admin.token" || name == "echo.token" {
			files["windows/"+name] = []byte(v)
		}
	}
	files["server/control-plane.env"] = []byte("DATABASE_URL=postgres://neexitlag@127.0.0.1:5432/neexitlag?sslmode=disable\n")
	config, _ := json.MarshalIndent(map[string]string{"vps_public_ip": ip.String(), "relay_id": "VPS-01", "relay_address": net.JoinHostPort(ip.String(), "4433"), "echo_target": net.JoinHostPort(ip.String(), "40000"), "control_plane_url": "https://" + net.JoinHostPort(ip.String(), "8443")}, "", "  ")
	files["deployment.json"] = config
	for path, b := range files {
		if e = put(root, path, b); e != nil {
			return e
		}
	}
	if _, _, e = security.LoadOrCreateIdentity(filepath.Join(root, "windows/device/identity.json")); e != nil {
		return e
	}
	return nil
}
func main() {
	ip := flag.String("vps-ip", "", "actual public VPS IPv4, no default")
	out := flag.String("out", "", "new private bundle directory")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "output directory required")
		os.Exit(1)
	}
	if e := provision(*out, *ip); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	fmt.Println("READY FOR VPS: private bundle created; server certificate expires in 30 days. No deployment or acceptance performed.")
}
