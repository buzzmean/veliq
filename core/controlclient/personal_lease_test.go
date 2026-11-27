package controlclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/security"
)

func TestOptimizationLeaseUsesFreshBoundProofForEveryAction(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	nonces := map[string]bool{}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Proof   security.Proof `json:"proof"`
			Action  string         `json:"action"`
			LeaseID string         `json:"lease_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			t.Error(err)
		}
		expected, err := security.PersonalOptimizationLeaseProofAudience(q.Action, q.LeaseID)
		if err != nil || r.URL.Path != "/api/v1/subscription/optimization-lease" || q.Proof.RelayID != expected || q.Proof.DeviceID != "stage-device" || q.Proof.Verify(pub, time.Now()) != nil {
			t.Error("invalid bound proof")
		}
		if nonces[q.Proof.Nonce] {
			t.Error("proof replay")
		}
		nonces[q.Proof.Nonce] = true
		if q.Action != "acquire" && q.LeaseID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
			t.Error("lease identity missing")
		}
		_, _ = w.Write([]byte(`{"supported":true,"required":true,"granted":true,"lease_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","server_time":"2026-11-27T12:00:00Z","expires_at":"2026-11-27T12:01:00Z"}`))
	}))
	defer s.Close()
	c := &Client{BaseURL: s.URL, HTTP: s.Client(), DeviceID: "stage-device", DeviceKey: key}
	for _, action := range []string{"acquire", "renew", "release"} {
		id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		if action == "acquire" {
			id = ""
		}
		if _, err := c.OptimizationLease(context.Background(), action, id); err != nil {
			t.Fatal(err)
		}
	}
	if len(nonces) != 3 {
		t.Fatal("fresh proofs not emitted")
	}
	if _, err := c.OptimizationLease(context.Background(), "takeover", ""); err == nil {
		t.Fatal("takeover action accepted")
	}
}

func TestOptimizationLeaseConflictPreservesAdmissionReason(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"supported":true,"required":true,"ttl_seconds":60,"renew_after_seconds":20,"granted":false,"server_time":"2026-11-27T12:00:00Z","reason":"ACTIVE_ON_OTHER_DEVICE"}`))
	}))
	defer s.Close()
	c := &Client{BaseURL: s.URL, HTTP: s.Client(), DeviceID: "stage-device", DeviceKey: key}
	reply, err := c.OptimizationLease(context.Background(), "acquire", "")
	if err != nil || reply.Granted || reply.Reason != "ACTIVE_ON_OTHER_DEVICE" {
		t.Fatal("structured conflict lost", reply, err)
	}
	if _, err := c.SubscriptionStatus(context.Background()); err == nil {
		t.Fatal("unrelated endpoint accepted conflict")
	}
}

func TestSubscriptionLeaseStatusAudienceIsExplicitlyNegotiated(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	var audience string
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p security.Proof
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Error(err)
		}
		audience = p.RelayID
		_, _ = w.Write([]byte(`{"managed":false,"enforced":false,"active":true}`))
	}))
	defer s.Close()
	c := &Client{BaseURL: s.URL, HTTP: s.Client(), DeviceID: "stage-device", DeviceKey: key}
	if _, err := c.SubscriptionStatus(context.Background()); err != nil || audience != security.SubscriptionAudience {
		t.Fatal("legacy status wire changed", audience, err)
	}
	c.PersonalOptimizationLeaseStage = true
	if _, err := c.SubscriptionStatus(context.Background()); err != nil || audience != security.SubscriptionPersonalLeaseAudience {
		t.Fatal("modern status did not negotiate", audience, err)
	}
}
