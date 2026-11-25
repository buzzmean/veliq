package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/buzzmean/veliq/core/clubhealth"
	"github.com/buzzmean/veliq/core/security"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPersistentRepeatIngestionMonotonicAndReporter(t *testing.T) {
	a, s, _ := accountAPI(t, true)
	owner, device, key := persistentDeviceFixture(t, s, "PC13")
	b := persistentFixtureBatch("PC13")
	// Впервом запросе — старый клиент без новых полей.
	send := func(batch clubhealth.Batch) (int, clubhealth.Receipt) {
		proof, err := security.NewProof(device, batch.Audience(), key, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(clubhealth.PersistentRequest{Batch: batch, Proof: proof})
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, httptest.NewRequest("POST", clubhealth.PersistentEndpoint, bytes.NewReader(raw)))
		var receipt clubhealth.Receipt
		_ = json.Unmarshal(w.Body.Bytes(), &receipt)
		return w.Code, receipt
	}
	if status, ack := send(b); status != 200 || !ack.Accepts(b) {
		t.Fatalf("старый клиент: %d", status)
	}
	now := b.Events[0].At
	b.Reporter = &clubhealth.Reporter{PC: "PC13", Version: "0.3.800", Source: "new-fixture", Session: b.Events[0].Session, ServicePID: 11}
	b.Events[0].Occurrences = 5
	b.Events[0].LastAt = now.Add(time.Millisecond)
	if status, ack := send(b); status != 200 || !ack.Accepts(b) {
		t.Fatalf("счётчик: %d", status)
	}
	read := func() clubhealth.Diagnostic {
		var raw []byte
		if err := s.DB.QueryRow(context.Background(), "SELECT summary FROM club_health_persistent_events WHERE device_id=$1 AND event_id=$2", device, b.Events[0].ID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var e clubhealth.Diagnostic
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		return e
	}
	if read().Occurrences != 5 {
		t.Fatal("монотонный счётчик не сохранён")
	}
	stale := b
	stale.Events = append([]clubhealth.Diagnostic(nil), b.Events...)
	stale.Events[0].Occurrences = 3
	stale.Events[0].LastAt = now
	if status, ack := send(stale); status != 200 || !ack.Accepts(stale) || read().Occurrences != 5 {
		t.Fatal("старый снимок уменьшил счётчик")
	}
	changed := stale
	changed.Events = append([]clubhealth.Diagnostic(nil), stale.Events...)
	changed.Events[0].NativeCode++
	if status, _ := send(changed); status != 409 || read().NativeCode != b.Events[0].NativeCode {
		t.Fatal("подмена ошибки темжеID")
	}
	changed.Events[0] = b.Events[0]
	changed.Events[0].Occurrences = 6
	changed.Events[0].LastAt = now
	if status, _ := send(changed); status != 409 {
		t.Fatal("противоречивый счётчик принят")
	}
	view, err := s.PersistentDiagnosticsView(context.Background(), owner, "PC13")
	if err != nil || !bytes.Contains(view, []byte("0.3.800")) {
		t.Fatal("backlogподменил версию отправителя", err)
	}
	// Пустойheartbeatтоже сообщает актуальную службу, без выдуманного события.
	b.Events = nil
	if status, ack := send(b); status != 200 || !ack.Accepts(b) {
		t.Fatal("метаданные heartbeat")
	}
}
