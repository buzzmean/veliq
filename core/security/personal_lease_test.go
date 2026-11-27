package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestPersonalOptimizationLeaseProofCannotChangeActionOrLease(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, tc := range []struct{ action, id, changedAction, changedID string }{
		{"acquire", "", "release", id},
		{"renew", id, "release", id},
		{"renew", id, "renew", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	} {
		audience, err := PersonalOptimizationLeaseProofAudience(tc.action, tc.id)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := NewProof("stage-device", audience, key, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		expected, err := PersonalOptimizationLeaseProofAudience(tc.changedAction, tc.changedID)
		if err != nil {
			t.Fatal(err)
		}
		if proof.RelayID == expected {
			t.Fatal("different lease action has same signed audience")
		}
		proof.RelayID = expected
		if proof.Verify(pub, time.Now()) == nil {
			t.Fatal("tampered lease proof verified")
		}
	}
	for _, tc := range []struct{ action, id string }{{"takeover", id}, {"acquire", id}, {"renew", ""}, {"release", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}} {
		if _, err := PersonalOptimizationLeaseProofAudience(tc.action, tc.id); err == nil {
			t.Fatal("invalid action/lease accepted", tc)
		}
	}
}
