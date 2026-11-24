// Package freshpc exchanges only a CSR/public trust over owner-authenticated SSH.
// Hardware hashes are inventory slots, never authentication credentials.
package freshpc

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/buzzmean/veliq/core/security"
)

type Request struct {
	DeviceID    string `json:"device_id"`
	MachineHash string `json:"machine_hash"`
	CSR         string `json:"csr"`
}
type Response struct {
	DeviceID    string            `json:"device_id"`
	MachineHash string            `json:"machine_hash"`
	CA          string            `json:"ca"`
	CASHA256    string            `json:"ca_sha256"`
	Certificate string            `json:"certificate"`
	Trust       map[string]string `json:"trust"`
	EchoToken   string            `json:"echo_token"`
}

var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func Fingerprint(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return hex.EncodeToString(h[:])
}
func ParseCertificate(raw string) (*x509.Certificate, error) {
	if !strings.HasPrefix(strings.TrimSpace(raw), "-----BEGIN CERTIFICATE-----") {
		return nil, errors.New("single certificate required")
	}
	b, rest := pem.Decode([]byte(raw))
	if b == nil || len(b.Headers) != 0 || b.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("single certificate required")
	}
	return x509.ParseCertificate(b.Bytes)
}
func ValidateRequest(r Request) (ed25519.PublicKey, error) {
	if !idPattern.MatchString(r.DeviceID) || !hashPattern.MatchString(r.MachineHash) || len(r.CSR) > 8192 {
		return nil, errors.New("invalid enrollment request")
	}
	if !strings.HasPrefix(strings.TrimSpace(r.CSR), "-----BEGIN CERTIFICATE REQUEST-----") {
		return nil, errors.New("invalid CSR encoding")
	}
	b, rest := pem.Decode([]byte(r.CSR))
	if b == nil || len(b.Headers) != 0 || b.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid CSR encoding")
	}
	c, e := x509.ParseCertificateRequest(b.Bytes)
	if e != nil || c.CheckSignature() != nil || c.Subject.CommonName != r.DeviceID || len(c.Extensions) != 0 {
		return nil, errors.New("invalid CSR proof or extensions")
	}
	k, ok := c.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("Ed25519 CSR required")
	}
	return k, nil
}
func writeNew(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
func RequestDevice(state, machine string) (Request, error) {
	if !hashPattern.MatchString(machine) {
		return Request{}, errors.New("invalid hardware hash")
	}
	id, key, e := security.LoadOrCreateIdentity(filepath.Join(state, "device", "identity.json"))
	if e != nil {
		return Request{}, e
	}
	path := filepath.Join(state, "request.json")
	if b, e := os.ReadFile(path); e == nil {
		var r Request
		if security.Parse(b, &r) != nil {
			return r, errors.New("invalid saved request")
		}
		pub, e := ValidateRequest(r)
		if e != nil || r.DeviceID != id.ID || r.MachineHash != machine || !pub.Equal(key.Public()) {
			return r, errors.New("saved request identity mismatch")
		}
		return r, nil
	}
	der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: id.ID}}, key)
	if e != nil {
		return Request{}, e
	}
	r := Request{id.ID, machine, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))}
	raw, _ := json.Marshal(r)
	return r, writeNew(path, raw)
}
func ValidateResponse(r Request, reply Response, expected string, now time.Time) error {
	expected = strings.ToLower(strings.ReplaceAll(expected, ":", ""))
	if !hashPattern.MatchString(expected) {
		return errors.New("explicit CA SHA256 pin required")
	}
	ca, e := ParseCertificate(reply.CA)
	if e != nil || Fingerprint(ca) != expected || reply.CASHA256 != expected {
		return errors.New("CA_FINGERPRINT_MISMATCH")
	}
	if !ca.IsCA || ca.CheckSignatureFrom(ca) != nil || now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return errors.New("invalid CA")
	}
	if reply.DeviceID != r.DeviceID || reply.MachineHash != r.MachineHash {
		return errors.New("enrollment response belongs to another request")
	}
	pub, e := ValidateRequest(r)
	if e != nil {
		return e
	}
	cert, e := ParseCertificate(reply.Certificate)
	if e != nil {
		return errors.New("invalid device certificate")
	}
	k, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !k.Equal(pub) || cert.IsCA {
		return errors.New("certificate device key mismatch")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, e = cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return errors.New("device certificate verification failed")
	}
	if len(reply.Trust) == 0 || len(reply.Trust) > 16 || len(strings.TrimSpace(reply.EchoToken)) < 24 || len(reply.EchoToken) > 256 {
		return errors.New("invalid trust/echo response")
	}
	for _, k := range reply.Trust {
		if _, e := security.DecodePublicKey(k); e != nil {
			return errors.New("invalid signing trust")
		}
	}
	return nil
}
func Complete(state string, r Request, reply Response, pin string) error {
	if e := ValidateResponse(r, reply, pin, time.Now()); e != nil {
		return e
	}
	// Validate every input before writing any trusted output; identity never leaves PC.
	saved, e := RequestDevice(state, r.MachineHash)
	if e != nil || saved.DeviceID != r.DeviceID || saved.CSR != r.CSR {
		return errors.New("local request identity mismatch")
	}
	trust := filepath.Join(state, "trust")
	if e := os.MkdirAll(trust, 0700); e != nil {
		return e
	}
	raw, _ := json.Marshal(reply.Trust)
	for name, b := range map[string][]byte{"trust/ca.pem": []byte(reply.CA), "trust/cp-ca.pem": []byte(reply.CA), "trust/trust.json": raw, "device/device.pem": []byte(reply.Certificate), "echo.token": []byte(reply.EchoToken)} {
		path := filepath.Join(state, name)
		if e := os.WriteFile(path+".pending", b, 0600); e != nil {
			return e
		}
		if e := os.Rename(path+".pending", path); e != nil {
			return e
		}
	}
	return nil
}
func KeyPEM(k ed25519.PrivateKey) []byte {
	b, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})
}
func Issue(ca *x509.Certificate, key ed25519.PrivateKey, pub ed25519.PublicKey, serverIP string) (string, error) {
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return "", e
	}
	c := &x509.Certificate{SerialNumber: n, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if serverIP != "" {
		ip := net.ParseIP(serverIP)
		if ip == nil {
			return "", errors.New("invalid server IP")
		}
		c.IPAddresses = []net.IP{ip, net.IPv4(127, 0, 0, 1)}
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if c.NotAfter.After(ca.NotAfter) {
		c.NotAfter = ca.NotAfter
	}
	der, e := x509.CreateCertificate(rand.Reader, c, ca, pub, key)
	if e != nil {
		return "", e
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}
func GenerateCA(directory, ip string) error {
	if _, e := os.Stat(directory); !os.IsNotExist(e) {
		return errors.New("CA staging directory must be new")
	}
	if e := os.Mkdir(directory, 0700); e != nil {
		return e
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return e
	}
	c := &x509.Certificate{Subject: pkix.Name{CommonName: "VELIQ private enrollment CA"}, SerialNumber: n, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, c, c, pub, key)
	if e != nil {
		return e
	}
	ca, _ := x509.ParseCertificate(der)
	serverPub, serverKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	cert, e := Issue(ca, key, serverPub, ip)
	if e != nil {
		return e
	}
	for name, b := range map[string][]byte{"ca.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "ca.key": KeyPEM(key), "server.pem": []byte(cert), "server.key": KeyPEM(serverKey)} {
		if e := writeNew(filepath.Join(directory, name), b); e != nil {
			return e
		}
	}
	return nil
}
