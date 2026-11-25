package clubhealth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistentRepeatAckBindsCounterSnapshot(t *testing.T) {
	now := time.Now().UTC()
	first := diagnosticFixture(1, now)
	first.Occurrences = 1
	first.LastAt = now
	j := Journal{Format: 1, Device: "owner"}
	j.Add(first, now)
	sent := j.Batch()
	durable := j.Snapshot()
	next := first
	next.Occurrences = 2
	next.LastAt = now.Add(time.Second)
	if !j.Add(next, now.Add(time.Second)) {
		t.Fatal("второе наблюдение потеряно")
	}
	receipt := Receipt{Protocol: 1, Committed: true, Digest: sent.Audience()}
	if j.Ack(sent, receipt) || len(j.Batch().Events) != 1 {
		t.Fatal("старыйACKподтвердил новый счётчик")
	}
	if durable.Batch().Events[0].Occurrences != 1 {
		t.Fatal("сохранённый снимок изменён в памяти")
	}
	current := j.Batch()
	if !j.Ack(current, Receipt{Protocol: 1, Committed: true, Digest: current.Audience()}) || len(j.Batch().Events) != 0 {
		t.Fatal("точныйACKне подтверждён")
	}
}

func TestPersistentLegacy739BacklogPreservesEveryEventAndLoss(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "journal.json")
	before := Journal{Format: 1, Device: "owner", Lost: 25165}
	for n := 1; n <= JournalEvents; n++ {
		e := diagnosticFixture(n, now)
		e.Version = "0.3.739"
		e.State = "observed"
		e.Component = "OWNER_PROXY"
		e.Operation = "OPEN"
		before.Rows = append(before.Rows, JournalRow{Event: e})
	}
	write := func(raw []byte) error { return os.WriteFile(path, raw, 0600) }
	if err := before.Save(write); err != nil {
		t.Fatal(err)
	}
	migrated := LoadJournal(path, "owner", now)
	if !migrated.PreserveBacklog("0.3.800") || len(migrated.History) != JournalEvents || len(migrated.Rows) != 0 {
		t.Fatal("backlogне сохранён")
	}
	started := diagnosticFixture(10001, now)
	started.Version = "0.3.800"
	started.Component = "SERVICE"
	started.Code = "SERVICE_STARTED"
	started.State = "ready"
	migrated.Add(started, now)
	repeat := diagnosticFixture(10002, now)
	repeat.State = "observed"
	repeat.Occurrences = 100000
	repeat.LastAt = now.Add(time.Second)
	migrated.Add(repeat, now.Add(time.Second))
	migrated.Trim(now.Add(time.Second))
	if migrated.Lost != 25165 {
		t.Fatalf("потери изменились: %d", migrated.Lost)
	}
	if err := migrated.Save(write); err != nil {
		t.Fatal(err)
	}
	after := LoadJournal(path, "owner", now.Add(time.Second))
	if len(after.History) != len(before.Rows) || after.Lost != before.Lost {
		t.Fatal("перезапуск утратил историю")
	}
	for i, row := range before.Rows {
		if after.History[i] != row {
			t.Fatalf("старое событие%dизменено", i)
		}
	}
	b := after.Batch()
	if b.Events[0].ID != started.ID || len(b.Events) != MaxEvents {
		t.Fatal("новые lifecycleиbacklogне доставляются")
	}
	raw, _ := json.Marshal(after)
	if len(raw) > JournalBytes {
		t.Fatal("лимит файла нарушен")
	}
	wrong := LoadJournal(path, "another-owner", now)
	if len(wrong.Rows)+len(wrong.History) != 0 || wrong.Lost == 0 {
		t.Fatal("историядругоговладельца")
	}
}

func TestPersistentLifecycleSurvivesUnrelatedFlood(t *testing.T) {
	now := time.Now().UTC()
	j := Journal{Format: 1, Device: "owner"}
	first := diagnosticFixture(1, now)
	first.Component = "SERVICE"
	first.State = "observed"
	first.Code = "SERVICE_STARTED"
	j.Add(first, now)
	for n := 2; n < JournalEvents+1000; n++ {
		e := diagnosticFixture(n, now)
		e.State = "observed"
		j.Add(e, now)
	}
	if j.Lost == 0 || j.Rows[0].Event.ID != first.ID || j.Batch().Events[0].ID != first.ID {
		t.Fatal("шум вытеснил lifecycle")
	}
}

func TestPersistentRepeatMetadataAndValidation(t *testing.T) {
	now := time.Now().UTC()
	e := diagnosticFixture(1, now)
	e.Occurrences = 1
	e.LastAt = now
	if !e.Valid(now) {
		t.Fatal("первое наблюдение отвергнуто")
	}
	for _, change := range []func(*Diagnostic){func(v *Diagnostic) { v.LastAt = time.Time{} }, func(v *Diagnostic) { v.Occurrences = 0 }, func(v *Diagnostic) { v.LastAt = now.Add(-time.Second) }, func(v *Diagnostic) { v.LastAt = now.Add(time.Second) }} {
		invalid := e
		change(&invalid)
		if invalid.Valid(now) {
			t.Fatal("некорректный диапазон принят")
		}
	}
	next := e
	next.Occurrences = 2
	next.LastAt = now.Add(time.Second)
	if changed, ok := DiagnosticUpdate(e, next); !changed || !ok {
		t.Fatal("обновление счётчика")
	}
	next.NativeCode = 10054
	if _, ok := DiagnosticUpdate(e, next); ok {
		t.Fatal("новый код смешан со старым")
	}
	next = e
	next.PID++
	if _, ok := DiagnosticUpdate(e, next); ok {
		t.Fatal("новый процесс смешан со старым")
	}
}

func TestPersistentWindowsReplayAfterServiceRestartIsNotLoss(t *testing.T) {
	now := time.Now().UTC()
	first := diagnosticFixture(1, now)
	first.State = "observed"
	first.Observer = "WINDOWS_EVENT_LOG"
	first.RecordID = 90
	first.EventID = 36876
	j := Journal{Format: 1, Device: "owner"}
	j.Add(first, now)
	replay := first
	replay.Version = "0.3.800"
	replay.Source = "new-fixture"
	replay.Session = "cccccccccccccccccccccccccccccccc"
	replay.ServicePID++
	if j.Add(replay, now) || j.Lost != 0 || j.Rows[0].Event != first {
		t.Fatalf("повтор записиWindows после смены службы изменил журнал: lost=%d", j.Lost)
	}
	replay.NativeCode++
	if j.Add(replay, now) || j.Rows[0].Event != first {
		t.Fatal("подменены исходные данные записиWindows")
	}
}

func TestPersistentSchannelReplayKeepsOriginalProcessEvidence(t *testing.T) {
	now := time.Now().UTC()
	first := diagnosticFixture(1, now)
	first.Observer = "WINDOWS_EVENT_LOG"
	first.RecordID = 90
	first.EventID = 36876
	first.Component = "TLS"
	first.State = "observed"
	first.PID = 42
	first.App = "steam.exe"
	first.Birth = 123
	first.ProcessVerified = true
	j := Journal{Format: 1, Device: "owner"}
	j.Add(first, now)
	replay := first
	replay.Version = "0.3.800"
	replay.Session = "cccccccccccccccccccccccccccccccc"
	replay.ServicePID++
	replay.App = ""
	replay.Birth = 0
	replay.ProcessVerified = false
	if j.Add(replay, now) || j.Lost != 0 || j.Rows[0].Event != first {
		t.Fatal("выход процесса уничтожил прежнее подтверждение записи")
	}
	contradictory := first
	contradictory.Birth++
	if _, ok := DiagnosticUpdate(first, contradictory); ok {
		t.Fatal("две разные проверенные личности смешаны")
	}
	replay.PID++
	if _, ok := DiagnosticUpdate(first, replay); ok {
		t.Fatal("изменённый сырой PID принят")
	}
}

func TestPersistentCrashAndRecoverySurviveTLSLogFlood(t *testing.T) {
	now := time.Now().UTC()
	j := Journal{Format: 1, Device: "owner"}
	for n := 1; n <= JournalEvents; n++ {
		e := diagnosticFixture(n, now)
		e.State = "observed"
		e.Component = "TLS"
		e.Observer = "WINDOWS_EVENT_LOG"
		e.RecordID = uint64(n)
		j.Add(e, now)
	}
	crash := diagnosticFixture(10001, now)
	crash.State = "observed"
	crash.Component = "WINDOWS"
	crash.Observer = "WINDOWS_EVENT_LOG"
	crash.Code = "BUGCHECK"
	crash.RecordID = 10001
	recovered := diagnosticFixture(10002, now)
	recovered.State = "recovered"
	recovered.Component = "CAPTURE"
	recovered.Code = "CAPTURE_READY"
	j.Add(crash, now)
	j.Add(recovered, now)
	for n := 11000; n < 12000; n++ {
		e := diagnosticFixture(n, now)
		e.State = "observed"
		e.Component = "JOURNAL"
		e.Code = "EVENTS_LOST"
		j.Add(e, now)
	}
	b := j.Batch()
	if len(b.Events) < 2 || b.Events[0].ID != crash.ID || b.Events[1].ID != recovered.ID {
		t.Fatal("TLS/журнал вытеснил аварийные события")
	}
}
