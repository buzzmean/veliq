package clientservice

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/clubhealth"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPersistentProxyRepeatStormPreservesIngress(t *testing.T) {
	d := diagnosticRuntimeFixture()
	c := &Controller{}
	c.diagnostics.Store(d)
	record := browserproxy.Record{Result: "UPSTREAM_OPEN_FAILED", ErrorOperation: "OPEN", ErrorCode: "OS_ERROR", NativeCode: 10061, Owner: browserproxy.Owner{PID: 20, Birth: 30, Exe: "steam.exe"}}
	for range 100000 {
		c.observeProxyDiagnostic(record)
	}
	if d.dropped.Load() != 0 || len(d.input) > 1 {
		t.Fatalf("повторы заполнили очередь: input=%d lost=%d", len(d.input), d.dropped.Load())
	}
	events := d.takeRepeats()
	if len(events) != 1 || events[0].Occurrences != 100000 || events[0].NativeCode != 10061 || events[0].Operation != "OPEN" || events[0].PID != 20 || events[0].Birth != 30 {
		t.Fatalf("неполное объединение: %+v", events)
	}
	d.note("SERVICE", "SERVICE_LIFECYCLE", "observed", "SERVICE_STOP_REQUESTED", 0, "service")
	if len(d.input) != 1 {
		t.Fatal("событие жизненного цикла не получило свободную очередь")
	}
}

func TestPersistentProxyRepeatClassesAreBoundedAndSeparate(t *testing.T) {
	d := diagnosticRuntimeFixture()
	c := &Controller{}
	c.diagnostics.Store(d)
	record := browserproxy.Record{Result: "UPSTREAM_OPEN_FAILED", ErrorOperation: "OPEN", ErrorCode: "OS_ERROR", NativeCode: 10061, Owner: browserproxy.Owner{PID: 20, Birth: 30, Exe: "steam.exe"}}
	c.observeProxyDiagnostic(record)
	record.NativeCode = 10054
	c.observeProxyDiagnostic(record)
	record.Owner.Birth++
	c.observeProxyDiagnostic(record)
	if len(d.takeRepeats()) != 3 {
		t.Fatal("разные коды или поколения процесса смешаны")
	}
	for n := 0; n < 1000; n++ {
		record.Owner.PID = uint32(n + 100)
		c.observeProxyDiagnostic(record)
	}
	if len(d.repeats) > diagnosticRepeatKeys || d.dropped.Load() == 0 || len(d.input) != 0 {
		t.Fatal("таблица не ограничена или потери скрыты")
	}
}

func TestPersistentRepeatConcurrentIngress(t *testing.T) {
	d := diagnosticRuntimeFixture()
	c := &Controller{}
	c.diagnostics.Store(d)
	record := browserproxy.Record{Result: "UPSTREAM_OPEN_FAILED", ErrorOperation: "OPEN", ErrorCode: "OS_ERROR", NativeCode: 10061, Owner: browserproxy.Owner{PID: 20, Birth: 30, Exe: "steam.exe"}}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				c.observeProxyDiagnostic(record)
			}
		}()
	}
	wg.Wait()
	events := d.takeRepeats()
	if len(events) != 1 || events[0].Occurrences != 8000 || d.dropped.Load() != 0 {
		t.Fatal("конкурентные наблюдения потеряны")
	}
}

func TestPersistentRepeatWorkerLegacyBacklogAndDurableSnapshots(t *testing.T) {
	d := diagnosticRuntimeFixture()
	d.base.Version = "0.3.800"
	d.done = make(chan struct{})
	path := filepath.Join(t.TempDir(), "journal.json")
	now := time.Now().UTC()
	old := clubhealth.Journal{Format: 1, Device: "device", Lost: 25165}
	for n := 1; n <= clubhealth.JournalEvents; n++ {
		e := d.base
		e.ID = fmt.Sprintf("%032x", n)
		e.At = now
		e.Version = "0.3.739"
		e.Component = "OWNER_PROXY"
		e.Observer = "PROXY_EXCHANGE"
		e.State = "observed"
		e.Code = "OS_ERROR"
		e.NativeCode = 10061
		old.Rows = append(old.Rows, clubhealth.JournalRow{Event: e})
	}
	raw, _ := json.Marshal(old)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var writes atomic.Int64
	d.write = func(raw []byte) error { writes.Add(1); return os.WriteFile(path, raw, 0600) }
	c := &Controller{}
	c.diagnostics.Store(d)
	record := browserproxy.Record{Result: "UPSTREAM_OPEN_FAILED", ErrorOperation: "OPEN", ErrorCode: "OS_ERROR", NativeCode: 10061, Owner: browserproxy.Owner{PID: 20, Birth: 30, Exe: "steam.exe"}}
	for range 100000 {
		c.observeProxyDiagnostic(record)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.run(ctx, path, "device")
	get := func() clubhealth.Batch {
		reply := make(chan clubhealth.Batch, 1)
		d.uploads <- diagnosticUpload{device: "device", reply: reply}
		select {
		case b := <-reply:
			return b
		case <-time.After(3 * time.Second):
			t.Fatal("worker заблокирован")
			return clubhealth.Batch{}
		}
	}
	b := get()
	found := false
	for _, e := range b.Events {
		if e.Occurrences == 100000 && e.NativeCode == 10061 {
			found = true
		}
	}
	if !found || b.Reporter == nil || b.Reporter.Version != "0.3.800" {
		t.Fatal("сохранённый счётчик/версия не доставляются")
	}
	c.observeProxyDiagnostic(record)
	d.uploads <- diagnosticUpload{device: "device", batch: b, receipt: clubhealth.Receipt{Protocol: 1, Committed: true, Digest: b.Audience()}}
	for range 5 {
		next := get()
		for _, e := range next.Events {
			if e.Occurrences > 100000 {
				t.Fatal("доставлен ещё не сохранённый счётчик")
			}
		}
	}
	d.note("CAPTURE", "CAPTURE_BACKEND", "failed", "CAPTURE_FAILED", 0, "capture")
	d.note("CAPTURE", "CAPTURE_BACKEND", "ready", "CAPTURE_READY", 0, "capture")
	cancel()
	select {
	case <-d.done:
	case <-time.After(3 * time.Second):
		t.Fatal("worker не завершился")
	}
	after := clubhealth.LoadJournal(path, "device", time.Now())
	if after.Lost != 25165 || len(after.History) != len(old.Rows) {
		t.Fatalf("старый журнал повреждён: lost=%d history=%d", after.Lost, len(after.History))
	}
	for i, row := range old.Rows {
		if after.History[i].Event != row.Event {
			t.Fatal("историческое событие изменено")
		}
	}
	count, recovery := uint64(0), false
	for _, row := range after.Rows {
		if row.Event.Occurrences > 0 {
			count = row.Event.Occurrences
		}
		if row.Event.Component == "CAPTURE" && row.Event.State == "recovered" && row.Event.Incident != "" {
			recovery = true
		}
	}
	if count != 100001 || !recovery || writes.Load() != 2 {
		t.Fatalf("счётчик/восстановление/лимит записи: %d %v %d", count, recovery, writes.Load())
	}
}
