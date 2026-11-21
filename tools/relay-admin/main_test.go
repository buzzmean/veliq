package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	cp "github.com/buzzmean/neexitlag/services/control-plane"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestIssueRelayCSRNeverGrantsCAOrClientIdentity(t *testing.T) {
	now := time.Now()
	pub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ephemeral CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(45 * 24 * time.Hour)}
	raw, _ := x509.CreateCertificate(rand.Reader, ca, ca, pub, caKey)
	ca, _ = x509.ParseCertificate(raw)
	nodePub, nodeKey, _ := ed25519.GenerateKey(rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted requested name"}, DNSNames: []string{"not-authorized.example"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}, nodeKey)
	cert, e := issue(ca, caKey, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), netip.MustParseAddr("146.0.77.98"), now)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := pem.Decode([]byte(cert))
	leaf, e := x509.ParseCertificate(p.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	if leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || !leaf.PublicKey.(ed25519.PublicKey).Equal(nodePub) || len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "146.0.77.98" || len(leaf.DNSNames) != 0 || leaf.NotAfter.After(ca.NotAfter) {
		t.Fatal("CSR privilege/SAN/expiry escaped issuer policy")
	}
	if leaf.CheckSignatureFrom(ca) != nil {
		t.Fatal("issuer mismatch")
	}
	csr[len(csr)-1] ^= 1
	if _, e = issue(ca, caKey, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), netip.MustParseAddr("146.0.77.98"), now); e == nil {
		t.Fatal("forged CSR accepted")
	}
}
func TestFleetArgumentsAndCertificateBounds(t *testing.T) {
	for _, id := range []string{"../VPS", "bad;name", "", string(make([]byte, 65))} {
		if safeID(id) {
			t.Fatal("unsafe ID")
		}
	}
	for _, address := range []string{"127.0.0.1:4433", "10.0.0.1:4433", "[::1]:4433", "146.0.77.98:22"} {
		if _, e := addressIP(address); e == nil {
			t.Fatal(address)
		}
	}
	if _, e := addressIP("146.0.77.98:4433"); e != nil {
		t.Fatal(e)
	}
}

func TestRegistryRollbackNeverOverwritesForeignHeartbeatRotation(t *testing.T) {
	j := journal{Heartbeat: "private-fixture"}
	current := cp.FleetRelayState{HeartbeatHash: []byte("another-admin-rotation")}
	if ownedHeartbeat(j, current) {
		t.Fatal("foreign rotation accepted")
	}
	current.HeartbeatHash = nil
	if !ownedHeartbeat(j, current) {
		t.Fatal("owned reservation rejected")
	}
}
