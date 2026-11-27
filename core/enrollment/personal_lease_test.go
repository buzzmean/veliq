package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPersonalLeaseCapabilityIsSignedAndOldRequestsStayCompatible(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	device, err := NewRequest(strings.Repeat("a", 32), strings.Repeat("b", 64), key)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := NewDeviceLink("device")
	old, err := l.Request("Stage PC", device, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(old)
	if strings.Contains(string(raw), "personal_optimization_lease_v1") {
		t.Fatal("legacy signed payload changed")
	}
	old.PersonalOptimizationLeaseV1 = true
	if _, err := old.Validate(time.Now()); err == nil {
		t.Fatal("unsigned capability was accepted")
	}
	l.PersonalOptimizationLeaseV1 = true
	modern, err := l.Request("Stage PC", device, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !modern.PersonalOptimizationLeaseV1 {
		t.Fatal("capability missing before signing")
	}
	modern.PersonalOptimizationLeaseV1 = false
	if _, err := modern.Validate(time.Now()); err == nil {
		t.Fatal("signed capability downgrade accepted")
	}
}

func TestPersonalLeaseCapabilitySurvivesPrivateLinkStorageAndPoll(t *testing.T) {
	l, _ := NewDeviceLink("device")
	l.PersonalOptimizationLeaseV1 = true
	raw, _ := json.Marshal(l)
	var restored DeviceLink
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	var received DeviceLinkPoll
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/enroll/device/poll" {
			t.Errorf("wrong endpoint %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte(`{"state":"PENDING"}`))
	}))
	defer s.Close()
	if _, err := (Client{URL: s.URL, HTTP: s.Client()}).PollDeviceLink(context.Background(), restored); err != nil {
		t.Fatal(err)
	}
	if !received.PersonalOptimizationLeaseV1 || received.ID != l.ID || received.Secret != l.Secret {
		t.Fatal("stored poll lost capability")
	}
}
