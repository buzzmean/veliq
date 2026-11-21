package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/controlclient"
	"github.com/buzzmean/neexitlag/core/locallearning"
	"github.com/buzzmean/neexitlag/core/security"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestSharedCandidateNeverAuthorizesLOCALWithoutLocalConfirmation(t *testing.T) {
	r := newYoutubeRuntime()
	s := r.shared
	k := youtubeKey{"net", "chrome", "www.youtube.com", 443, false}
	now := time.Now()
	s.configured = true
	s.started = now
	if allowed, _ := s.decision(k, now); allowed {
		t.Fatal("initial coordination bypassed")
	}
	doc := locallearning.Document{Version: 1, Network: strings.Repeat("a", 64), Scope: locallearning.Scope{Group: k.Domain}, State: "PEER_PICKING", GeneratedAt: now, ExpiresAt: now.Add(time.Minute)}
	s.accept(k, doc, now)
	if allowed, _ := s.decision(k, now); allowed {
		t.Fatal("second picker")
	}
	id := r.order[0]
	doc.Version++
	doc.Candidate = id
	doc.CandidateUntil = now.Add(10 * time.Minute)
	s.accept(k, doc, now)
	if allowed, candidate := s.decision(k, now); !allowed || candidate != id {
		t.Fatal("shared candidate ignored")
	}
	if stage, _ := r.choose(k, now); stage != "RELAY" {
		t.Fatal("shared metadata promoted transport without actual proof")
	}
	s.reject(k, id)
	if allowed, _ := s.decision(k, now); allowed {
		t.Fatal("failed candidate retried endlessly by peer")
	}
	older := doc
	older.Version--
	if s.accept(k, older, now) {
		t.Fatal("signed replay rolled back candidate")
	}
	other := k
	other.Network = "other"
	if allowed, _ := s.decision(other, now); allowed {
		t.Fatal("borrowed local-network entry")
	}
}
func TestSharedLearningLegacyCPFallbackAndBoundDeviceProof(t *testing.T) {
	for _, status := range []int{200, 404} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			c, cur, q, p := youtubeFixture(t)
			q.Source = netip.MustParseAddrPort("127.0.0.1:54321")
			k := youtubeScope(cur, q)
			c.browser.youtube.register(k, cur, q, p, time.Now())
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
			signPub, signer, _ := ed25519.GenerateKey(rand.Reader)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req locallearning.Request
				if r.URL.Path != "/api/v1/local/learning" || json.NewDecoder(r.Body).Decode(&req) != nil || req.Proof.RelayID != locallearning.Audience(req.Command) || req.Proof.Verify(pub, time.Now()) != nil {
					t.Error("unbound device proof")
				}
				w.WriteHeader(status)
				if status == 200 {
					now := time.Now()
					raw, _ := security.Sign(locallearning.Domain, "k", signer, locallearning.Document{Version: 1, Network: strings.Repeat("b", 64), Scope: req.Command.Scope, Picker: false, State: "PEER_PICKING", GeneratedAt: now, ExpiresAt: now.Add(time.Minute)})
					w.Write(raw)
				}
			}))
			defer server.Close()
			cp := &controlclient.Client{BaseURL: server.URL, HTTP: server.Client(), DeviceID: "fixture", DeviceKey: key}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); c.runSharedLearning(ctx, cp, map[string]ed25519.PublicKey{"k": signPub}) }()
			defer func() { cancel(); <-done }()
			c.browser.youtube.shared.notify()
			deadline := time.Now().Add(3 * time.Second)
			for c.browser.youtube.shared.snapshot().LastCheck.IsZero() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			view := c.browser.youtube.shared.snapshot()
			if view.LastCheck.IsZero() {
				t.Fatal("no coordination")
			}
			allowed, _ := c.browser.youtube.shared.decision(k, time.Now())
			if (status == 404) != allowed {
				t.Fatal(status, view, allowed)
			}
		})
	}
}

func TestWarmMediaConfirmationPreservesThreeTrialEvidence(t *testing.T) {
	r := newYoutubeRuntime()
	k := youtubeKey{Network: "net", Profile: "chrome", Domain: "googlevideo:sn-abc", Port: 443}
	now := time.Now()
	id := r.order[0]
	r.cache[k] = youtubeLearn{Stage: "LOCAL", Strategy: id, Confirmed: true, Streak: 3, Until: now.Add(youtubeLearnTTL)}
	r.confirmed(k, "LOCAL", id, now.Add(time.Minute))
	r.recordVerification(k, 100000)
	if v := r.cache[k]; v.Streak != 3 || v.VerifiedBytes != 100000 {
		t.Fatal("actual warm flow destroyed shared CDN evidence", v)
	}
	r.failed(k, "LOCAL", id, "MIDSTREAM_STALL", now)
	if v := r.cache[k]; v.Confirmed || v.Streak != 0 {
		t.Fatal("degradation retained proof", v)
	}
}

func TestPublicRecheckCannotRenewExpiredCDNHealth(t *testing.T) {
	r := newYoutubeRuntime()
	k := youtubeKey{Network: "net", Profile: "chrome", Domain: "googlevideo:sn-abc", Port: 443}
	now := time.Now()
	id := r.order[0]
	deadline := now.Add(time.Minute)
	r.cache[k] = youtubeLearn{Stage: "LOCAL", Strategy: id, Confirmed: true, Streak: 3, VerifiedBytes: 100000, Until: deadline}
	r.completeCDNQualification(k, id, now.Add(30*time.Second))
	if v := r.cache[k]; v.Until != deadline || v.Streak != 3 || !v.Confirmed {
		t.Fatal("public probe changed live media deadline", v)
	}
	r.completeCDNQualification(k, id, now.Add(2*time.Minute))
	if v := r.cache[k]; v.Stage != "RELAY" || v.Streak != 0 || v.VerifiedBytes != 0 || v.Confirmed {
		t.Fatal("public body renewed stale CDN authorization", v)
	}
}
