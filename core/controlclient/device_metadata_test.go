package controlclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/deviceinfo"
)

func TestDeviceMetadataCapabilityAndBoundProof(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	supported := false
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if !supported {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(map[string]bool{"supported": true})
			return
		}
		posts++
		var q deviceinfo.Request
		if json.NewDecoder(r.Body).Decode(&q) != nil || q.Proof.RelayID != q.Details.Audience() || q.Proof.Verify(pub, time.Now()) != nil {
			t.Error("Сведения не привязаны к подписи устройства")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"recorded": true})
	}))
	defer server.Close()
	cp := &Client{BaseURL: server.URL, DeviceID: "fixture-device", DeviceKey: key}
	if ok, err := cp.SupportsDeviceMetadata(context.Background()); ok || !errors.Is(err, ErrNotSupported) || posts != 0 {
		t.Fatalf("Старый сервер: %v %v; POST=%d", ok, err, posts)
	}
	supported = true
	if ok, err := cp.SupportsDeviceMetadata(context.Background()); !ok || err != nil {
		t.Fatal("Возможности нового сервера", err)
	}
	if err := cp.DeviceMetadata(context.Background(), deviceinfo.Details{ComputerName: "PC13", Version: "0.3.735"}); err != nil {
		t.Fatal(err)
	}
	if posts != 1 {
		t.Fatal("Повторная отправка сведений")
	}
}
