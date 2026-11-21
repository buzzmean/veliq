// Root-only server certificate/registry tool. No migration, enrollment, revoke,
// CA rotation, activation-code mutation or client certificate issuance.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/buzzmean/neexitlag/core/optimizer"
	cp "github.com/buzzmean/neexitlag/services/control-plane"
)

const control = "/etc/neexitlag/control"
const journalRoot = "/var/lib/veliq-relay-fleet"

type request struct{ Op, ID, Address, Name, CSR string }
type journal struct {
	Before                                          cp.FleetRelayState
	Address, CSR, Certificate, CA, Heartbeat, Phase string
	Trust                                           map[string]string
}

func safeID(id string) bool { return regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(id) }
func addressIP(address string) (netip.Addr, error) {
	a, e := netip.ParseAddrPort(address)
	if e != nil || (a.Port() != 4433 && a.Port() != 4434) || !a.Addr().Is4() || !a.Addr().IsGlobalUnicast() || a.Addr().IsPrivate() {
		return netip.Addr{}, errors.New("PUBLIC_RELAY_ADDRESS_REQUIRED")
	}
	return a.Addr(), nil
}
func issue(ca *x509.Certificate, key ed25519.PrivateKey, csrPEM string, ip netip.Addr, now time.Time) (string, error) {
	p, _ := pem.Decode([]byte(csrPEM))
	if p == nil || len(csrPEM) > 16384 {
		return "", errors.New("INVALID_CSR")
	}
	csr, e := x509.ParseCertificateRequest(p.Bytes)
	if e != nil || csr.CheckSignature() != nil || csr.PublicKeyAlgorithm != x509.Ed25519 {
		return "", errors.New("INVALID_CSR_SIGNATURE_OR_KEY")
	}
	if !ca.IsCA || now.Before(ca.NotBefore) || !now.Add(24*time.Hour).Before(ca.NotAfter) {
		return "", errors.New("CA_EXPIRED_OR_TOO_SHORT")
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if e != nil {
		return "", e
	}
	serial.Add(serial, big.NewInt(1))
	expires := now.Add(90 * 24 * time.Hour)
	if expires.After(ca.NotAfter) {
		expires = ca.NotAfter
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "VELIQ authenticated relay"}, NotBefore: now.Add(-time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.IP(ip.AsSlice())}}
	b, e := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, key)
	if e != nil {
		return "", e
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})), nil
}
func readKey(path string) (ed25519.PrivateKey, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("KEY_FORMAT")
	}
	v, e := x509.ParsePKCS8PrivateKey(p.Bytes)
	if e != nil {
		return nil, e
	}
	k, ok := v.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("ED25519_REQUIRED")
	}
	return k, nil
}
func atomic(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".fleet-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	f.Chmod(0600)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(name, path)
		if e == nil {
			if dir, de := os.Open(filepath.Dir(path)); de == nil {
				e = dir.Sync()
				dir.Close()
			} else {
				e = de
			}
		}
	}
	return e
}
func rootState() (string, *x509.Certificate, ed25519.PrivateKey, ed25519.PrivateKey, map[string]string, *cp.Store, error) {
	fail := func() (string, *x509.Certificate, ed25519.PrivateKey, ed25519.PrivateKey, map[string]string, *cp.Store, error) {
		return "", nil, nil, nil, nil, nil, errors.New("CONTROL_ROOT_STATE_UNAVAILABLE")
	}
	hostname, _ := os.Hostname()
	if os.Geteuid() != 0 || strings.HasPrefix(strings.ToLower(hostname), "veliq-swe-01") {
		return fail()
	}
	st, e := os.Lstat(control + "/ca.key")
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		return fail()
	}
	caRaw, e := os.ReadFile(control + "/ca.pem")
	if e != nil {
		return fail()
	}
	p, _ := pem.Decode(caRaw)
	if p == nil {
		return fail()
	}
	ca, e := x509.ParseCertificate(p.Bytes)
	if e != nil {
		return fail()
	}
	cak, e := readKey(control + "/ca.key")
	caPub, caOK := ca.PublicKey.(ed25519.PublicKey)
	if e != nil || !caOK || !caPub.Equal(cak.Public()) {
		return fail()
	}
	signer, e := readKey(control + "/signing.key")
	if e != nil {
		return fail()
	}
	var trust map[string]string
	raw, e := os.ReadFile("/etc/neexitlag/relay/trust.json")
	if e != nil || json.Unmarshal(raw, &trust) != nil || trust["vps-1"] != base64.RawURLEncoding.EncodeToString(signer.Public().(ed25519.PublicKey)) {
		return fail()
	}
	env, e := os.ReadFile(control + "/control-plane.env")
	if e != nil {
		return fail()
	}
	database := ""
	for _, line := range strings.Split(string(env), "\n") {
		if strings.HasPrefix(line, "DATABASE_URL=") {
			database = strings.TrimSpace(strings.TrimPrefix(line, "DATABASE_URL="))
		}
	}
	u, e := url.Parse(database)
	if e != nil || u.User == nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return fail()
	}
	pass, e := os.ReadFile(control + "/database.password")
	if e != nil {
		return fail()
	}
	u.User = url.UserPassword(u.User.Username(), strings.TrimSpace(string(pass)))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, e := cp.Open(ctx, u.String())
	if e != nil {
		return fail()
	}
	return string(caRaw), ca, cak, signer, trust, store, nil
}
func ownedHeartbeat(j journal, current cp.FleetRelayState) bool {
	h := sha256.Sum256([]byte(j.Heartbeat))
	return bytes.Equal(current.HeartbeatHash, h[:]) || bytes.Equal(current.HeartbeatHash, j.Before.HeartbeatHash)
}
func run() error {
	var q request
	d := json.NewDecoder(io.LimitReader(os.Stdin, 32769))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || !safeID(q.ID) {
		return errors.New("INVALID_FLEET_REQUEST")
	}
	if q.ID == "VPS-01" && q.Op != "inspect" && q.Op != "rollback" {
		return errors.New("DISTINCT_PRIMARY_TICKET_AUDIENCE_REQUIRED")
	}
	ip, e := addressIP(q.Address)
	if e != nil {
		return e
	}
	if strings.HasSuffix(q.Address, ":4434") && (q.ID != "VPS-LEGACY" || ip.String() != "2.56.177.4") {
		return errors.New("LEGACY_ENDPOINT_ONLY")
	}
	caRaw, ca, cak, signer, trust, store, e := rootState()
	if e != nil {
		return e
	}
	defer store.DB.Close()
	if q.Op == "inspect" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		current, e := store.FleetRelay(ctx, q.ID)
		if e != nil {
			return e
		}
		phase := "not_prepared"
		var j journal
		if b, e := os.ReadFile(filepath.Join(journalRoot, q.ID+".json")); e == nil && json.Unmarshal(b, &j) == nil {
			phase = j.Phase
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"relay": current.Node, "exists": current.Exists, "phase": phase, "heartbeat_healthy": current.Healthy, "heartbeat_at": current.HeartbeatAt, "heartbeat_fresh": current.HeartbeatAt != nil && time.Since(*current.HeartbeatAt) < 60*time.Second})
	}
	if e = os.MkdirAll(journalRoot, 0700); e != nil {
		return e
	}
	info, e := os.Lstat(journalRoot)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("UNSAFE_FLEET_JOURNAL")
	}
	path := filepath.Join(journalRoot, q.ID+".json")
	var j journal
	raw, readErr := os.ReadFile(path)
	if readErr == nil {
		if json.Unmarshal(raw, &j) != nil || j.Address != q.Address {
			return errors.New("FLEET_JOURNAL_ADDRESS_MISMATCH")
		}
	} else if !os.IsNotExist(readErr) {
		return readErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	current, e := store.FleetRelay(ctx, q.ID)
	if e != nil {
		return e
	}
	save := func() error {
		b, e := json.Marshal(j)
		if e != nil {
			return e
		}
		return atomic(path, b)
	}
	switch q.Op {
	case "inspect":
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"relay": current.Node, "exists": current.Exists, "phase": j.Phase, "journal": path, "heartbeat_healthy": current.Healthy, "heartbeat_at": current.HeartbeatAt, "heartbeat_fresh": current.HeartbeatAt != nil && time.Since(*current.HeartbeatAt) < 60*time.Second})
	case "prepare":
		if current.Exists && current.Node.Address != q.Address {
			return errors.New("PRIMARY_ADDRESS_CHANGE_REQUIRES_NEW_AUDIENCE")
		}
		if readErr == nil && j.Phase != "rolled_back" {
			if !current.Exists && !j.Before.Exists && j.Phase == "prepared" {
				pending := cp.FleetRelayState{Exists: true, Node: optimizer.RelayCandidate{ID: q.ID, Address: q.Address, City: q.Name, Load: 1}}
				if e = store.ChangeFleetRelay(ctx, q.ID, "", pending, "vps-1", signer, trust, nil); e != nil {
					return e
				}
				current = pending
			}

			h := sha256.Sum256([]byte(j.Heartbeat))
			if j.Phase == "committed" && (!current.Exists || current.Node.Address != q.Address || string(current.HeartbeatHash) != string(h[:])) {
				return errors.New("COMMITTED_REGISTRY_CHANGED_REVIEW_REQUIRED")
			}
			if j.CSR != q.CSR {
				return errors.New("SERVER_KEY_CHANGED_REVIEW_REQUIRED")
			}
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": j.Phase, "certificate": j.Certificate, "ca": j.CA, "heartbeat": j.Heartbeat, "trust": j.Trust})
		}
		leaf, e := issue(ca, cak, q.CSR, ip, time.Now())
		if e != nil {
			return e
		}
		b := make([]byte, 16)
		if _, e = rand.Read(b); e != nil {
			return e
		}
		hb := fmt.Sprintf("%x", b)
		j = journal{Before: current, Address: q.Address, CSR: q.CSR, Certificate: leaf, CA: caRaw, Heartbeat: hb, Trust: trust, Phase: "prepared"}
		if e = save(); e != nil {
			return e
		}
		if !current.Exists {
			pending := cp.FleetRelayState{Exists: true, Node: optimizer.RelayCandidate{ID: q.ID, Address: q.Address, City: q.Name, Load: 1}}
			if e = store.ChangeFleetRelay(ctx, q.ID, "", pending, "vps-1", signer, trust, current.HeartbeatHash); e != nil {
				return e
			}
		}
		// PRIVATE transport response: caller must capture, never log or echo it.
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": j.Phase, "certificate": j.Certificate, "ca": j.CA, "heartbeat": j.Heartbeat, "trust": j.Trust})
	case "commit":
		if readErr != nil || j.Phase == "rolled_back" {
			return errors.New("PREPARE_REQUIRED")
		}
		if !current.Exists || !ownedHeartbeat(j, current) {
			return errors.New("RELAY_REGISTRY_OWNERSHIP_CHANGED")
		}
		h := sha256.Sum256([]byte(j.Heartbeat))
		next := cp.FleetRelayState{Exists: true, Node: optimizer.RelayCandidate{ID: q.ID, Address: q.Address, City: q.Name}, HeartbeatHash: h[:]}
		if current.Exists && current.Node.Address == q.Address && current.Node.City == q.Name && string(current.HeartbeatHash) == string(h[:]) {
			if j.Phase != "committed" {
				j.Phase = "published"
			}
			if e = save(); e != nil {
				return e
			}
			return json.NewEncoder(os.Stdout).Encode(map[string]string{"phase": j.Phase, "address": q.Address, "journal": path})
		}
		expected := ""
		if current.Exists {
			expected = current.Node.Address
		}
		if current.Exists && expected != j.Before.Node.Address && expected != q.Address {
			return errors.New("RELAY_REGISTRY_CONCURRENT_CHANGE")
		}
		if e = store.ChangeFleetRelay(ctx, q.ID, expected, next, "vps-1", signer, trust, current.HeartbeatHash); e != nil {
			return e
		}
		j.Phase = "published"
		if e = save(); e != nil {
			return e
		}
	case "finalize":
		if readErr != nil || !current.Exists || current.Node.Address != q.Address {
			return errors.New("PUBLICATION_NOT_CONFIRMED")
		}
		j.Phase = "committed"
		if e = save(); e != nil {
			return e
		}
	case "rollback":
		if readErr != nil {
			return errors.New("ROLLBACK_JOURNAL_MISSING")
		}
		if j.Phase == "rolled_back" {
			break
		}
		expected := ""
		if current.Exists {
			if !ownedHeartbeat(j, current) {
				return errors.New("RELAY_REGISTRY_OWNERSHIP_CHANGED")
			}
			expected = current.Node.Address
		}
		if current.Exists && expected != q.Address && expected != j.Before.Node.Address {
			return errors.New("RELAY_REGISTRY_CONCURRENT_CHANGE")
		}
		if e = store.ChangeFleetRelay(ctx, q.ID, expected, j.Before, "vps-1", signer, trust, current.HeartbeatHash); e != nil {
			return e
		}
		j.Phase = "rolled_back"
		if e = save(); e != nil {
			return e
		}
	default:
		return errors.New("UNKNOWN_FLEET_OPERATION")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"phase": j.Phase, "journal": path, "address": q.Address})
}
func main() {
	if e := run(); e != nil {
		code := e.Error()
		if !regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,80}$`).MatchString(code) {
			code = "SAFE_RELAY_ADMIN_FAILED"
		}
		fmt.Fprintln(os.Stderr, code)
		os.Exit(1)
	}
}
