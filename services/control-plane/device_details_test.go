package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/deviceinfo"
	"github.com/buzzmean/veliq/core/security"
)

func TestDeviceConnectionRequiresFreshEvidence(t *testing.T) {
	now := time.Now()
	fresh := now.Add(-time.Minute)
	old := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	for _, tc := range []struct {
		seen, heartbeat *time.Time
		disabled        bool
		want            string
	}{
		{nil, nil, false, "unknown"}, {&old, nil, false, "unknown"}, {&future, nil, false, "unknown"},
		{&fresh, nil, false, "online"}, {&old, &old, false, "offline"}, {&fresh, &old, false, "online"}, {&fresh, &fresh, true, "disabled"},
	} {
		if got := deviceConnection(tc.seen, tc.heartbeat, tc.disabled, now); got != tc.want {
			t.Fatalf("%+v: %s", tc, got)
		}
	}
}

func TestDeviceDetailsStoredWithReplayAndPayloadProtection(t *testing.T) {
	a, s, _ := accountAPI(t, true)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	id, _ := security.NewID()
	if err := s.Register(context.Background(), Device{ID: id, Name: "VELIQ device", PublicKey: base64.RawURLEncoding.EncodeToString(pub)}); err != nil {
		t.Fatal(err)
	}
	d := deviceinfo.Details{ComputerName: "PC13", Version: "0.3.735"}
	p, err := security.NewProof(id, d.Audience(), key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	q := deviceinfo.Request{Details: d, Proof: p}
	call := func(q deviceinfo.Request) int {
		raw, _ := json.Marshal(q)
		r := httptest.NewRequest("POST", testOrigin+"/api/v1/device/details", bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		return w.Code
	}
	changed := q
	changed.Details.ComputerName = "PC14"
	if got := call(changed); got != 400 {
		t.Fatalf("Изменённое содержимое: %d", got)
	}
	if got := call(q); got != 200 {
		t.Fatalf("Подписанные сведения: %d", got)
	}
	if got := call(q); got != 401 {
		t.Fatalf("Повтор подписи: %d", got)
	}
	var name, version string
	if err = s.DB.QueryRow(context.Background(), "SELECT computer_name,software_version FROM device_details WHERE device_id=$1", id).Scan(&name, &version); err != nil {
		t.Fatal(err)
	}
	if name != "PC13" || version != "0.3.735" {
		t.Fatal("Имя Windows или версия не сохранены")
	}
	if err = s.Revoke(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	p, _ = security.NewProof(id, d.Audience(), key, time.Now())
	q.Proof = p
	if got := call(q); got != 401 {
		t.Fatalf("Отозванное устройство: %d", got)
	}
}

func TestDeviceLabelsStayWithinOwningAccount(t *testing.T) {
	s := codeStore(t)
	ctx := context.Background()
	id, _ := security.NewID()
	other, _ := security.NewID()
	for _, a := range []string{id, other} {
		if _, err := s.DB.Exec(ctx, "INSERT INTO accounts(id,email) VALUES($1,$2)", a, a+"@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	owner := Account{ID: id}
	sub, err := s.CreateSubscription(ctx, owner, Plan{ID: "player", Kind: "player", MaxSeats: 3}, 1)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	device, _ := security.NewID()
	if err = s.Register(ctx, Device{ID: device, Name: "PC13", PublicKey: base64.RawURLEncoding.EncodeToString(pub)}); err != nil {
		t.Fatal(err)
	}
	machine := strings.Repeat("a", 64)
	if _, err = s.DB.Exec(ctx, `INSERT INTO activation_slots(code_id,machine_hash,device_id) SELECT id,$2,$3 FROM activation_codes WHERE subscription_id=$1`, sub, machine, device); err != nil {
		t.Fatal(err)
	}
	if err = s.SetDeviceLabel(ctx, Account{ID: other}, sub, machine[:12], "Чужой ПК"); err == nil {
		t.Fatal("Чужой аккаунт изменил подпись")
	}
	if err = s.SetDeviceLabel(ctx, owner, sub, machine[:12], "Зал1, у окна"); err != nil {
		t.Fatal(err)
	}
	var label string
	if err = s.DB.QueryRow(ctx, "SELECT label FROM account_device_labels WHERE account_id=$1", id).Scan(&label); err != nil || label != "Зал1, у окна" {
		t.Fatalf("Подпись: %q %v", label, err)
	}
	if err = s.SetDeviceLabel(ctx, owner, sub, machine[:12], ""); err != nil {
		t.Fatal(err)
	}
}
