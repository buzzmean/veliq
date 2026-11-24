package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/clubhealth"
	"github.com/buzzmean/neexitlag/core/transport"
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
func TestPersistentOldFailureCountersAreNotCurrentOutage(t *testing.T) {
	now := time.Now()
	s := transport.PoolSnapshot{SessionFailures: 100, CreationFailures: 100}
	if state, _ := diagnosticRelayHealth([]transport.PoolSnapshot{s}, now); state != "unknown" {
		t.Fatal("stale counters called an outage")
	}
	s.RecentOpens = []transport.PoolOpenEvent{{At: now.Add(-time.Second), FailureReason: "dial"}}
	if state, _ := diagnosticRelayHealth([]transport.PoolSnapshot{s}, now); state != "failed" {
		t.Fatal("fresh failure missing")
	}
	s.HealthySessions = 1
	if state, _ := diagnosticRelayHealth([]transport.PoolSnapshot{s}, now); state != "ready" {
		t.Fatal("authenticated recovery missing")
	}
}

func TestPersistentWindowsReadRetriesAndBoundsMissingHistory(t *testing.T) {
	now := time.Now()
	since := now.Add(-time.Minute)
	err := errors.New("fixture")
	next, gap := diagnosticNextWindow(since, now, err)
	if !next.Equal(since) || !gap {
		t.Fatal("failed query discarded retry window")
	}
	next, gap = diagnosticNextWindow(since.Add(-time.Hour), now, err)
	if !next.Equal(now.Add(-15*time.Minute)) || !gap {
		t.Fatal("failed query has unbounded history")
	}
	next, gap = diagnosticNextWindow(since, now, nil)
	if !next.Equal(now.Add(-time.Second)) || gap {
		t.Fatal("successful query did not advance")
	}
}

func TestPersistentStorageFailureAndRecoveryAreDurableBeforeDelivery(t *testing.T) {
	d := diagnosticRuntimeFixture()
	d.done = make(chan struct{})
	writes := 0
	d.write = func([]byte) error {
		writes++
		if writes == 1 {
			return syscall.Errno(112)
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); <-d.done }()
	go d.run(ctx, t.TempDir()+"/journal.json", "device")
	get := func() clubhealth.Batch {
		reply := make(chan clubhealth.Batch, 1)
		d.uploads <- diagnosticUpload{device: "device", reply: reply}
		select {
		case b := <-reply:
			return b
		case <-time.After(time.Second):
			t.Fatal("worker blocked")
			return clubhealth.Batch{}
		}
	}
	if b := get(); b.Protocol != 0 {
		t.Fatal("failed write allowed upload")
	}
	if b := get(); b.Protocol != 0 {
		t.Fatal("unsaved recovery allowed upload")
	}
	b := get()
	if len(b.Events) != 2 || b.Events[0].NativeCode != 112 || b.Events[0].State != "failed" || b.Events[1].State != "recovered" || b.Events[1].Incident != b.Events[0].ID {
		t.Fatal("storage evidence or incident link lost")
	}
}
