package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"github.com/buzzmean/veliq/core/traffic"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPostgresTrafficRelayTokenBoundSignedCountersAndReplay(t *testing.T) {
	s := codeStore(t)
	ctx := context.Background()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	token := strings.Repeat("t", 32)
	hash := sha256.Sum256([]byte(token))
	if _, e := s.DB.Exec(ctx, "INSERT INTO relay_nodes(id,metadata,heartbeat_token_hash) VALUES('VPS-PRIMARY','{}',$1)", hash[:]); e != nil {
		t.Fatal(e)
	}
	api := &API{Store: s, Settings: Settings{KeyID: "k", SigningKey: key, RelayTrafficFile: filepath.Join(t.TempDir(), "traffic.json")}}
	now := time.Now()
	o := traffic.Observation{Relay: "VPS-PRIMARY", Interface: "eth0", Boot: strings.Repeat("a", 64), BootAt: now, At: now, Counter: 100}
	call := func(method, auth string, obs traffic.Observation) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(obs)
		r := httptest.NewRequest(method, "/api/v1/relays/traffic", bytes.NewReader(raw))
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		w := httptest.NewRecorder()
		api.relayTraffic(w, r)
		return w
	}
	if w := call("POST", strings.Repeat("x", 32), o); w.Code != 401 {
		t.Fatal("unauthenticated counter accepted", w.Code)
	}
	bad := o
	bad.Relay = "VPS-01"
	if w := call("POST", token, bad); w.Code != 401 {
		t.Fatal("cross relay token accepted", w.Code)
	}
	w := call("POST", token, o)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	d, e := traffic.Validate(map[string]ed25519.PublicKey{"k": pub}, w.Body.Bytes(), now)
	if e != nil || len(d.Relays) != 1 || d.Relays[0].Bytes != 100 {
		t.Fatal(d, e)
	}
	if w = call("POST", token, o); w.Code != 200 {
		t.Fatal("lost ACK not idempotent", w.Code)
	}
	w = call("GET", "", o)
	d, e = traffic.Validate(map[string]ed25519.PublicKey{"k": pub}, w.Body.Bytes(), now)
	if e != nil || d.Relays[0].Bytes != 100 {
		t.Fatal("replay inflated NIC tally", d, e)
	}
	if _, e = traffic.Validate(map[string]ed25519.PublicKey{"k": pub}, w.Body.Bytes(), now.Add(10*time.Minute)); e == nil {
		t.Fatal("stale signed report accepted")
	}
}
func TestTrafficUnconfiguredIsUnknownNotZero(t *testing.T) {
	api := &API{}
	w := httptest.NewRecorder()
	api.relayTraffic(w, httptest.NewRequest("GET", "/api/v1/relays/traffic", nil))
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}
