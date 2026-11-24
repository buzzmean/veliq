package controlclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/buzzmean/neexitlag/core/clubhealth"
)

func TestPersistentRequiresDurableMatchingReceipt(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	ack := clubhealth.Receipt{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q clubhealth.PersistentRequest
		if json.NewDecoder(r.Body).Decode(&q) != nil {
			t.Error("request")
			return
		}
		if q.Proof.RelayID != q.Batch.Audience() {
			t.Error("proof not bound to batch")
		}
		json.NewEncoder(w).Encode(ack)
	}))
	defer server.Close()
	c := Client{BaseURL: server.URL, DeviceID: "device", DeviceKey: key, AllowHTTPDevelopment: true}
	b := clubhealth.Batch{Protocol: 1, Events: []clubhealth.Diagnostic{}}
	if _, err := c.ClubHealthPersistent(context.Background(), b); err == nil {
		t.Fatal("old server 200 ACK accepted")
	}
	ack = clubhealth.Receipt{Protocol: 1, Committed: true, Digest: b.Audience()}
	if _, err := c.ClubHealthPersistent(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	ack.Digest = "different"
	if _, err := c.ClubHealthPersistent(context.Background(), b); err == nil {
		t.Fatal("foreign batch ACK accepted")
	}
}
