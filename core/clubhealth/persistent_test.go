package clubhealth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func diagnosticFixture(n int, now time.Time) Diagnostic {
	return Diagnostic{ID: fmt.Sprintf("%032x", n), At: now, PC: "PC13", Version: "0.3.736", Source: "96c30994", Session: strings.Repeat("b", 32),
		ServicePID: 10, Observer: "FIXTURE", Component: "CONNECTION", State: "failed", Code: "OS_ERROR", NativeCode: 10061}
}
func TestPersistentJournalRestartAckAndRotation(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "journal.json")
	j := LoadJournal(path, "device-A", now)
	e := diagnosticFixture(1, now)
	j.Add(e, now)
	write := func(b []byte) error { return os.WriteFile(path, b, 0600) }
	if err := j.Save(write); err != nil {
		t.Fatal(err)
	}
	restarted := LoadJournal(path, "device-A", now)
	b := restarted.Batch()
	if len(b.Events) != 1 {
		t.Fatal("offline record lost")
	}
	if restarted.Ack(b, Receipt{Protocol: 1, Committed: true, Digest: "wrong"}) {
		t.Fatal("wrong ACK accepted")
	}
	if len(restarted.Batch().Events) != 1 {
		t.Fatal("HTTP success deleted queue")
	}
	if !restarted.Ack(b, Receipt{Protocol: 1, Committed: true, Digest: b.Audience()}) {
		t.Fatal("durable ACK rejected")
	}
	if err := restarted.Save(write); err != nil {
		t.Fatal(err)
	}
	restarted = LoadJournal(path, "device-A", now)
	if len(restarted.Batch().Events) != 0 || len(restarted.Rows) != 1 {
		t.Fatal("ACK must retain local history")
	}
	if restarted.Add(e, now) {
		t.Fatal("duplicate added")
	}
	for n := 2; n < JournalEvents+30; n++ {
		restarted.Add(diagnosticFixture(n, now), now)
	}
	restarted.Trim(now)
	raw, _ := json.Marshal(restarted)
	if len(raw) > JournalBytes || len(restarted.Rows) > JournalEvents || restarted.Lost == 0 {
		t.Fatal("unbounded journal")
	}
	restarted.Trim(now.Add(Retention + time.Second))
	if len(restarted.Rows) != 0 {
		t.Fatal("expired history retained")
	}
}
func TestPersistentJournalRejectsCorruptionAndOtherDevice(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "journal.json")
	j := Journal{Format: 1, Device: "owner-A"}
	j.Add(diagnosticFixture(1, now), now)
	if err := j.Save(func(b []byte) error { return os.WriteFile(path, b, 0600) }); err != nil {
		t.Fatal(err)
	}
	if other := LoadJournal(path, "owner-B", now); len(other.Rows) != 0 || other.Lost == 0 {
		t.Fatal("cross-device history")
	}
	if err := os.WriteFile(path, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if corrupt := LoadJournal(path, "owner-A", now); corrupt.Lost == 0 {
		t.Fatal("corruption hidden")
	}
	if err := j.Save(func([]byte) error { return errors.New("disk full") }); err == nil {
		t.Fatal("disk failure hidden")
	}
}
func TestPersistentRecoveryRequiresPositiveEvidenceAndSurvivesRestart(t *testing.T) {
	now := time.Now()
	j := Journal{Format: 1, Device: "a"}
	e, ok := j.Transitions.Observe("cp", diagnosticFixture(1, now))
	if !ok || e.Incident != e.ID {
		t.Fatal("missing incident")
	}
	if _, ok := j.Transitions.Observe("cp", e); ok {
		t.Fatal("repeated failure")
	}
	unknown := diagnosticFixture(2, now)
	unknown.State = "unknown"
	if v, _ := j.Transitions.Observe("cp", unknown); v.State == "recovered" {
		t.Fatal("silence recovered")
	}
	raw, _ := json.Marshal(j)
	var recovered Journal
	if err := json.Unmarshal(raw, &recovered); err != nil {
		t.Fatal(err)
	}
	ready := diagnosticFixture(3, now)
	ready.State = "ready"
	ready.Code = "DURABLE_ACK"
	v, ok := recovered.Transitions.Observe("cp", ready)
	if !ok || v.State != "recovered" || v.Incident != e.ID {
		t.Fatal("restart lost incident link")
	}
}
func TestPersistentPrivacyAndTypedErrors(t *testing.T) {
	now := time.Now()
	e := diagnosticFixture(1, now)
	e.Code = "https://example.test/?token=secret"
	if e.Valid(now) {
		t.Fatal("URL accepted")
	}
	code, n := ErrorCode(fmt.Errorf("secret password: %w", syscall.Errno(10061)))
	if code != "OS_ERROR" || n != 10061 {
		t.Fatal(code, n)
	}
	code, _ = ErrorCode(errors.New("https://example.test/?token=secret"))
	if strings.Contains(code, "secret") || code != "ERROR_UNCLASSIFIED" {
		t.Fatal("raw error leaked")
	}
}
