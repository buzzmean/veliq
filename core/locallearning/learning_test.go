package locallearning

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"github.com/buzzmean/veliq/core/security"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func hexID(v string) string { s := sha256.Sum256([]byte(v)); return hex.EncodeToString(s[:]) }
func TestFortyPCsOnePickerPersistenceAndSafeReelection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "learning.json")
	b, e := New(path)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	network := hexID("network")
	scope := Scope{Group: "googlevideo:sn-abc"}
	valid := func(s string) bool { return s == "catalog-test" }
	var wg sync.WaitGroup
	var granted atomic.Int32
	winner := make(chan string, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			owner := hexID(string(rune(i)))
			doc, e := b.Apply(network, owner, Command{Scope: scope, Action: "observe"}, valid, now)
			if e != nil {
				t.Error(e)
				return
			}
			if doc.Picker {
				granted.Add(1)
				winner <- owner
			}
		}(i)
	}
	wg.Wait()
	close(winner)
	if granted.Load() != 1 {
		t.Fatal("not one picker", granted.Load())
	}
	owner := <-winner
	b, e = New(path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.Apply(network, owner, Command{Scope: scope, Action: "report", Candidate: "catalog-test", Applied: true, BodyBytes: 100000, Flows: 2}, valid, now); e == nil {
		t.Fatal("two CDN flows accepted")
	}
	doc, e := b.Apply(network, owner, Command{Scope: scope, Action: "report", Candidate: "catalog-test", Applied: true, BodyBytes: 100000, Flows: 3}, valid, now)
	if e != nil || doc.Candidate == "" {
		t.Fatal(doc, e)
	}
	peer := hexID("peer")
	doc, e = b.Apply(network, peer, Command{Scope: scope, Action: "observe"}, valid, now.Add(time.Second))
	if e != nil || doc.Picker || doc.Candidate != "catalog-test" {
		t.Fatal("candidate not shared", doc, e)
	}
	doc, e = b.Apply(network, peer, Command{Scope: scope, Action: "observe"}, valid, now.Add(Lease+time.Second))
	if e != nil || !doc.Picker {
		t.Fatal("picker deadlocks club", doc, e)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "198.51.100.") || strings.Contains(string(raw), "device_id") {
		t.Fatal("personal data in shared state")
	}
	info, _ := os.Stat(path)
	// POSIX mode bits are meaningless on Windows (os.Stat reports 0666); the
	// shared store runs on the Linux control plane, where this check applies.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		t.Fatal("unprotected shared state", info.Mode())
	}
}
func TestCohortUsesCPPeerPrefixAndKeyNotHardware(t *testing.T) {
	seed := []byte(strings.Repeat("s", 32))
	a, e := Network(seed, netip.MustParseAddr("198.51.100.1"))
	if e != nil {
		t.Fatal(e)
	}
	b, _ := Network(seed, netip.MustParseAddr("198.51.100.200"))
	c, _ := Network(seed, netip.MustParseAddr("198.51.101.1"))
	d, _ := Network([]byte(strings.Repeat("x", 32)), netip.MustParseAddr("198.51.100.1"))
	if a != b || a == c || a == d || strings.Contains(a, "198.51") {
		t.Fatal(a, b, c, d)
	}
	if _, e = Network(seed, netip.MustParseAddr("192.168.88.1")); e == nil {
		t.Fatal("untrusted proxy/local network identified as ISP")
	}
}
func TestProofBoundToExactLearningCommandAndSignedScopeTTL(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	cmd := Command{Scope: Scope{Group: "www.youtube.com"}, Action: "observe"}
	p, e := security.NewProof("device", Audience(cmd), key, now)
	if e != nil || p.Verify(pub, now) != nil {
		t.Fatal(e)
	}
	changed := cmd
	changed.Candidate = "injected"
	if Audience(changed) == p.RelayID {
		t.Fatal("unsigned candidate mutation")
	}
	doc := Document{Version: 1, Network: hexID("network"), Scope: cmd.Scope, Picker: true, State: "PICKER_GRANTED", GeneratedAt: now, ExpiresAt: now.Add(Lease)}
	raw, _ := security.Sign(Domain, "k", key, doc)
	keys := map[string]ed25519.PublicKey{"k": pub}
	if _, e = Validate(keys, raw, cmd.Scope, now); e != nil {
		t.Fatal(e)
	}
	if _, e = Validate(keys, raw, Scope{Group: "i.ytimg.com"}, now); e == nil {
		t.Fatal("cross subgroup")
	}
	if _, e = Validate(keys, raw, cmd.Scope, now.Add(Lease)); e == nil {
		t.Fatal("expired")
	}
	wrong, _ := security.Sign("config", "k", key, doc)
	if _, e = Validate(keys, wrong, cmd.Scope, now); e == nil {
		t.Fatal("domain confusion")
	}
}
func TestPersistenceFailureNeverCommitsPickerOrCandidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "parent", "state.json")
	b, e := New(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "parent"), []byte("file"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = b.Apply(hexID("net"), hexID("owner"), Command{Scope: Scope{Group: "www.youtube.com"}, Action: "observe"}, func(string) bool { return true }, time.Now()); e == nil {
		t.Fatal("failed save ignored")
	}
	if len(b.rows) != 0 {
		t.Fatal("partial in-memory lease")
	}
}
