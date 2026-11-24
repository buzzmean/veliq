package clientservice

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/clubhealth"
)

func diagnosticRuntimeFixture() *persistentDiagnostics {
	return &persistentDiagnostics{input: make(chan diagnosticInput, clubhealth.InputEvents), uploads: make(chan diagnosticUpload, 1),
		base: clubhealth.Diagnostic{PC: "PC13", Version: "0.3.736", Source: "fixture", Session: strings.Repeat("a", 32), ServicePID: 1}}
}
func TestPersistentWriterCannotBlockIPCProducer(t *testing.T) {
	d := diagnosticRuntimeFixture()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	first := true
	d.write = func([]byte) error {
		if first {
			first = false
			close(entered)
			<-release
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { defer close(done); d.run(ctx, t.TempDir()+"/journal.json", "device") }()
	reply := make(chan clubhealth.Batch, 1)
	d.uploads <- diagnosticUpload{device: "device", reply: reply}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("writer not entered")
	}
	start := time.Now()
	e := d.event("IPC", "SERVICE_HANDLER", "observed", "DEADLINE")
	for range 10000 {
		d.offer(e, "")
	}
	if time.Since(start) > time.Second || d.dropped.Load() == 0 {
		t.Error("producer blocked or overflow hidden")
	}
	close(release)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not finish")
	}
}
func TestPersistentOwnerIPCReadInClubMode(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.clubMode.Store(true)
	d := diagnosticRuntimeFixture()
	d.status.Store(&diagnosticStatus{PC: "PC13", Version: "0.3.736", Storage: "OK"})
	c.diagnostics.Store(d)
	value, err := c.HandleOwnerIPC(context.Background(), "diagnostics.status", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(value)
	if !strings.Contains(string(raw), "PC13") {
		t.Fatal(string(raw))
	}
}
