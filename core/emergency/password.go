// Package emergency verifies an installation owner's offline emergency password.
// It contains no networking or system mutations.
package emergency

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const Iterations = 600000
const MaxPasswordBytes = 1024
const maxFailures = 5
const lockDuration = 5 * time.Minute

var (
	ErrNotConfigured = errors.New("EMERGENCY_PASSWORD_NOT_CONFIGURED")
	ErrUnavailable = errors.New("EMERGENCY_PASSWORD_UNAVAILABLE")
	ErrPassword = errors.New("EMERGENCY_PASSWORD_INVALID")
	ErrRateLimited = errors.New("EMERGENCY_PASSWORD_RATE_LIMIT")
)

// Record is a verifier, never a recoverable password. Its protected Windows
// registry value is writable only by SYSTEM/administrators and bound to OwnerSID.
type Record struct {
	Version int `json:"version"`
	Algorithm string `json:"algorithm"`
	OwnerSID string `json:"owner_sid"`
	Iterations int `json:"iterations"`
	Salt []byte `json:"salt"`
	Hash []byte `json:"hash"`
}

func Create(password []byte, owner string) (Record, error) {
	if len(password) < 8 || len(password) > MaxPasswordBytes || owner == "" { return Record{}, ErrPassword }
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil { return Record{}, ErrUnavailable }
	return Record{1, "pbkdf2-sha256", owner, Iterations, salt, pbkdf2.Key(password, salt, Iterations, 32, sha256.New)}, nil
}

func Decode(raw []byte, owner string) (Record, error) {
	var r Record
	if len(raw) == 0 || len(raw) > 4096 || owner == "" { return r, ErrUnavailable }
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil { return Record{}, ErrUnavailable }
	var extra any
	if d.Decode(&extra) != io.EOF { return Record{}, ErrUnavailable }
	if r.Version != 1 || r.Algorithm != "pbkdf2-sha256" || r.OwnerSID != owner || r.Iterations != Iterations || len(r.Salt) != 32 || len(r.Hash) != 32 { return Record{}, ErrUnavailable }
	return r, nil
}

// Authenticator serializes expensive checks and bounds guessing. The loader must
// verify registry security on the same opened handle before reading the value.
type Authenticator struct {
	mu sync.Mutex
	owner string
	load func() ([]byte, error)
	now func() time.Time
	failures int
	lockedUntil time.Time
}
func New(owner string, load func() ([]byte, error)) *Authenticator {
	return &Authenticator{owner: owner, load: load, now: time.Now}
}
func (a *Authenticator) record() (Record, error) {
	if a.load == nil { return Record{}, ErrNotConfigured }
	raw, err := a.load()
	defer clear(raw)
	if os.IsNotExist(err) { return Record{}, ErrNotConfigured }
	if err != nil { return Record{}, ErrUnavailable }
	return Decode(raw, a.owner)
}
func (a *Authenticator) Configured() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	r, err := a.record()
	clear(r.Hash)
	return err == nil
}
func (a *Authenticator) Verify(password []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if now.Before(a.lockedUntil) { return ErrRateLimited }
	if !a.lockedUntil.IsZero() { a.failures=0; a.lockedUntil=time.Time{} }
	r, err := a.record()
	if err != nil { return err }
	valid := false
	if len(password)>0 && len(password)<=MaxPasswordBytes {
		key := pbkdf2.Key(password,r.Salt,r.Iterations,32,sha256.New)
		valid=subtle.ConstantTimeCompare(key,r.Hash)==1
		clear(key)
	}
	clear(r.Hash)
	if valid { a.failures=0; return nil }
	a.failures++
	if a.failures>=maxFailures { a.lockedUntil=now.Add(lockDuration) }
	return ErrPassword
}
