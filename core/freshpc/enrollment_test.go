package freshpc

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (string, Request, Response) {
	t.Helper()
	root := t.TempDir()
	caPath := filepath.Join(root, "ca")
	if e := GenerateCA(caPath, "2.56.177.4"); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(filepath.Join(caPath, "ca.pem"))
	ca, e := ParseCertificate(string(raw))
	if e != nil {
		t.Fatal(e)
	}
	// CA key is only a test fixture; generated client request has a different key.
	// Parse fixture key through PKCS8, exactly like the root server helper.
	keyRaw, _ := os.ReadFile(filepath.Join(caPath, "ca.key"))
	key := parseTestKey(t, keyRaw)
	state := filepath.Join(root, "pc")
	r, e := RequestDevice(state, strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	pub, e := ValidateRequest(r)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := Issue(ca, key, pub, "")
	if e != nil {
		t.Fatal(e)
	}
	trust, _, _ := ed25519.GenerateKey(rand.Reader)
	return state, r, Response{DeviceID: r.DeviceID, MachineHash: r.MachineHash, CA: string(raw), CASHA256: Fingerprint(ca), Certificate: cert, Trust: map[string]string{"vps-1": base64.RawURLEncoding.EncodeToString(trust)}, EchoToken: strings.Repeat("e", 32)}
}
func TestFreshPCPinBeforeTrustAndCSRBinding(t *testing.T) {
	state, r, reply := fixture(t)
	if e := Complete(state, r, reply, strings.Repeat("0", 64)); e == nil {
		t.Fatal("wrong CA pin trusted")
	}
	if _, e := os.Stat(filepath.Join(state, "trust")); !os.IsNotExist(e) {
		t.Fatal("trusted output written before pin validation")
	}
	good := reply
	reply.DeviceID = strings.Repeat("1", 32)
	if ValidateResponse(r, reply, good.CASHA256, time.Now()) == nil {
		t.Fatal("wrong device response accepted")
	}
	reply = good
	reply.MachineHash = strings.Repeat("b", 64)
	if ValidateResponse(r, reply, good.CASHA256, time.Now()) == nil {
		t.Fatal("wrong machine accepted")
	}
	reply = good
	reply.CA += "\nPRIVATE KEY\n"
	if ValidateResponse(r, reply, good.CASHA256, time.Now()) == nil {
		t.Fatal("extra PEM/key data accepted")
	}
	if e := Complete(state, r, good, good.CASHA256); e != nil {
		t.Fatal(e)
	}
	if e := Complete(state, r, good, good.CASHA256); e != nil {
		t.Fatal("retry not idempotent", e)
	}
	again, e := RequestDevice(state, r.MachineHash)
	if e != nil || again != r {
		t.Fatal("retry rotated local key", again, e)
	}
	other, e := RequestDevice(filepath.Join(t.TempDir(), "other"), r.MachineHash)
	if e != nil || other.DeviceID == r.DeviceID {
		t.Fatal("freeze reinstall reused identity", e)
	}
	if e := Complete(state, other, good, good.CASHA256); e == nil {
		t.Fatal("different CSR accepted")
	}
}
func TestFreshPCCSRParsingAndKeysNeverExported(t *testing.T) {
	_, r, _ := fixture(t)
	for _, bad := range []Request{{DeviceID: r.DeviceID, MachineHash: r.MachineHash, CSR: "bad"}, {DeviceID: "id", MachineHash: r.MachineHash, CSR: r.CSR}, {DeviceID: r.DeviceID, MachineHash: "bad", CSR: r.CSR}, {DeviceID: strings.Repeat("0", 32), MachineHash: r.MachineHash, CSR: r.CSR}} {
		if _, e := ValidateRequest(bad); e == nil {
			t.Fatal("bad request accepted")
		}
	}
	pub, e := ValidateRequest(r)
	if e != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatal(e)
	}
	if strings.Contains(r.CSR, "PRIVATE") || strings.Contains(r.CSR, "seed") {
		t.Fatal("secret exported")
	}
	if _, e := RequestDevice(t.TempDir(), "invalid"); e == nil {
		t.Fatal("bad hardware ID accepted")
	}
}

func parseTestKey(t *testing.T, b []byte) ed25519.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(b)
	k, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	return k.(ed25519.PrivateKey)
}

func TestFreshPCRejectsInvalidSignatureWrongKeyServerEKUAndExpiredLeaf(t *testing.T) {
	state, r, reply := fixture(t)
	b, _ := pem.Decode([]byte(r.CSR))
	b.Bytes[len(b.Bytes)-1] ^= 1
	bad := r
	bad.CSR = string(pem.EncodeToMemory(b))
	if _, e := ValidateRequest(bad); e == nil {
		t.Fatal("invalid CSR signature accepted")
	}
	if e := ValidateResponse(r, reply, reply.CASHA256, time.Now().Add(31*24*time.Hour)); e == nil {
		t.Fatal("expired leaf accepted")
	}
	ca, _ := ParseCertificate(reply.CA)
	raw, _ := os.ReadFile(filepath.Join(filepath.Dir(state), "ca", "ca.key"))
	cak := parseTestKey(t, raw)
	pub, _ := ValidateRequest(r)
	server, e := Issue(ca, cak, pub, "2.56.177.4")
	if e != nil {
		t.Fatal(e)
	}
	original := reply.Certificate
	reply.Certificate = server
	if ValidateResponse(r, reply, reply.CASHA256, time.Now()) == nil {
		t.Fatal("server certificate accepted as device")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	reply.Certificate, _ = Issue(ca, cak, other, "")
	if ValidateResponse(r, reply, reply.CASHA256, time.Now()) == nil {
		t.Fatal("different device key accepted")
	}
	reply.Certificate = original
	reply.CA = "junk\n" + reply.CA
	if ValidateResponse(r, reply, reply.CASHA256, time.Now()) == nil {
		t.Fatal("extra CA payload accepted")
	}
}
