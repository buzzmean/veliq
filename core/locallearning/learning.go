// Package locallearning coordinates advisory LOCAL trials. A signed candidate
// is not routing authorization or a substitute for local TLS/transform proof.
package locallearning

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/buzzmean/veliq/core/security"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const Domain = "local-learning"
const Lease = 90 * time.Second
const CandidateTTL = 10 * time.Minute

type Scope struct {
	Group    string `json:"group"`
	HintOnly bool   `json:"hint_only"`
}
type Command struct {
	Scope     Scope  `json:"scope"`
	Action    string `json:"action"`
	Candidate string `json:"candidate,omitempty"`
	BodyBytes uint64 `json:"body_bytes,omitempty"`
	Flows     uint32 `json:"flows,omitempty"`
	Applied   bool   `json:"applied,omitempty"`
}
type Request struct {
	Command Command        `json:"command"`
	Proof   security.Proof `json:"proof"`
}
type Document struct {
	Version                uint64    `json:"version"`
	Network                string    `json:"network"`
	Scope                  Scope     `json:"scope"`
	Candidate              string    `json:"candidate,omitempty"`
	CandidateUntil         time.Time `json:"candidate_until"`
	Picker                 bool      `json:"picker"`
	State                  string    `json:"state"`
	GeneratedAt, ExpiresAt time.Time
}

func Audience(c Command) string {
	b, _ := json.Marshal(c)
	s := sha256.Sum256(b)
	return Domain + ":" + hex.EncodeToString(s[:])
}
func ValidScope(s Scope) bool {
	if strings.HasPrefix(s.Group, "googlevideo:sn-") || s.Group == "googlevideo:unclassified" {
		if len(s.Group) > 128 {
			return false
		}
		for _, r := range strings.TrimPrefix(s.Group, "googlevideo:") {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
		return true
	}
	if len(s.Group) < 3 || len(s.Group) > 128 || !strings.Contains(s.Group, ".") || strings.HasPrefix(s.Group, ".") || strings.HasSuffix(s.Group, ".") || strings.Contains(s.Group, "..") {
		return false
	}
	if _, err := netip.ParseAddr(s.Group); err == nil {
		return false
	}
	for _, r := range s.Group {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// The CP derives this opaque cohort from its actual peer, never forwarded headers
// or client hardware/network data. No public address/prefix is returned or stored.
func Network(seed []byte, peer netip.Addr) (string, error) {
	if len(seed) < 32 {
		return "", errors.New("LEARNING_COHORT_KEY_REQUIRED")
	}
	peer = peer.Unmap()
	if !peer.IsValid() || !peer.IsGlobalUnicast() || peer.IsPrivate() || peer.IsLoopback() {
		return "", errors.New("LEARNING_PUBLIC_PEER_REQUIRED")
	}
	bits := 24
	if peer.Is6() {
		bits = 48
	}
	prefix := netip.PrefixFrom(peer, bits).Masked()
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte("local-cohort:v1\x00" + prefix.String()))
	return hex.EncodeToString(mac.Sum(nil)), nil
}
func Validate(keys map[string]ed25519.PublicKey, raw []byte, scope Scope, now time.Time) (Document, error) {
	var d Document
	if e := security.Verify(Domain, keys, raw, &d); e != nil {
		return d, e
	}
	_, networkErr := hex.DecodeString(d.Network)
	if d.Scope != scope || !ValidScope(scope) || d.Version == 0 || len(d.Network) != 64 || networkErr != nil || !d.ExpiresAt.After(now) || !d.ExpiresAt.After(d.GeneratedAt) || d.GeneratedAt.After(now.Add(30*time.Second)) || d.ExpiresAt.Sub(d.GeneratedAt) > Lease || d.CandidateUntil.After(d.GeneratedAt.Add(CandidateTTL)) {
		return d, errors.New("LEARNING_DOCUMENT_INVALID_OR_EXPIRED")
	}
	return d, nil
}

type record struct {
	Owner          string
	LeaseUntil     time.Time
	Candidate      string
	CandidateUntil time.Time
	Version        uint64
	Updated        time.Time
}
type Broker struct {
	mu   sync.Mutex
	path string
	rows map[string]record
}

func New(path string) (*Broker, error) {
	b := &Broker{path: path, rows: map[string]record{}}
	if path == "" {
		return b, nil
	}
	info, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return b, nil
	}
	if e != nil || !info.Mode().IsRegular() || info.Size() > 256*1024 {
		return nil, errors.New("LEARNING_STATE_FILE_INVALID")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	if security.Parse(raw, &b.rows) != nil || len(b.rows) > 512 {
		return nil, errors.New("LEARNING_STATE_INVALID")
	}
	return b, nil
}
func (b *Broker) save(rows map[string]record) error {
	if b.path == "" {
		return nil
	}
	raw, e := json.Marshal(rows)
	if e != nil || len(raw) > 256*1024 {
		return errors.New("LEARNING_STATE_LIMIT")
	}
	if e = os.MkdirAll(filepath.Dir(b.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(b.path), ".local-learning-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), b.path)
}
func (b *Broker) Apply(network, owner string, cmd Command, validCandidate func(string) bool, now time.Time) (Document, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(network) != 64 || len(owner) != 64 || !ValidScope(cmd.Scope) {
		return Document{}, errors.New("LEARNING_SCOPE_INVALID")
	}
	key := network + "|" + cmd.Scope.Group
	if cmd.Scope.HintOnly {
		key += "|hint"
	}
	rows := make(map[string]record, len(b.rows))
	for k, v := range b.rows {
		if now.Sub(v.Updated) < 24*time.Hour {
			rows[k] = v
		}
	}
	v, exists := rows[key]
	if !exists && len(rows) >= 512 {
		return Document{}, errors.New("LEARNING_CAPACITY")
	}
	if !now.Before(v.LeaseUntil) {
		v.Owner = owner
		v.LeaseUntil = now.Add(Lease)
	}
	picker := v.Owner == owner
	if picker {
		v.LeaseUntil = now.Add(Lease)
	}
	if !now.Before(v.CandidateUntil) || v.Candidate != "" && !validCandidate(v.Candidate) {
		v.Candidate = ""
		v.CandidateUntil = time.Time{}
	}
	switch cmd.Action {
	case "observe":
	case "report":
		if !picker || !validCandidate(cmd.Candidate) || cmd.BodyBytes <= 64*1024 || !cmd.Applied || cmd.Flows == 0 || strings.HasPrefix(cmd.Scope.Group, "googlevideo:") && cmd.Flows < 3 {
			return Document{}, errors.New("LEARNING_UNQUALIFIED_REPORT")
		}
		v.Candidate = cmd.Candidate
		v.CandidateUntil = now.Add(CandidateTTL)
	case "reject":
		if picker && v.Candidate == cmd.Candidate {
			v.Candidate = ""
			v.CandidateUntil = time.Time{}
		}
	default:
		return Document{}, errors.New("LEARNING_ACTION_INVALID")
	}
	v.Version++
	v.Updated = now
	rows[key] = v
	if e := b.save(rows); e != nil {
		return Document{}, e
	}
	b.rows = rows
	state := "PEER_PICKING"
	if picker {
		state = "PICKER_GRANTED"
	}
	if v.Candidate != "" {
		state = "SHARED_CANDIDATE_REQUIRES_LOCAL_CONFIRMATION"
	}
	return Document{Version: v.Version, Network: network, Scope: cmd.Scope, Candidate: v.Candidate, CandidateUntil: v.CandidateUntil, Picker: picker, State: state, GeneratedAt: now, ExpiresAt: now.Add(Lease)}, nil
}
