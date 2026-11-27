package clientservice

import (
	"context"
	"encoding/json"
	"github.com/buzzmean/veliq/core/clubhealth"
	"github.com/buzzmean/veliq/core/flightrecorder"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFlightRecorderConfigurationIsSingletonAndBounded(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	dir := t.TempDir()
	c.ConfigurePersistentDiagnostics(Manifest{StateDirectory: dir, DeviceIdentityFile: filepath.Join(dir, "absent.json")})
	first := c.flight.Load()
	if first == nil {
		t.Fatal("not configured before workers")
	}
	c.ConfigurePersistentDiagnostics(Manifest{StateDirectory: dir})
	c.ConfigureFlightRecorder(Manifest{StateDirectory: dir})
	if c.flight.Load() != first {
		t.Fatal("duplicate worker")
	}
	if _, err := c.FlightRecorderContext(context.Background(), 9); err == nil {
		t.Fatal("IPC context limit not enforced")
	}
	if _, err := c.FlightRecorderContext(context.Background(), 0); err == nil {
		t.Fatal("zero limit accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	rows, err := c.FlightRecorderContext(ctx, 8)
	if err != nil || len(rows) > 8 {
		t.Fatal(err, len(rows))
	}
	raw, _ := json.Marshal(rows)
	if len(raw) > 48<<10 {
		t.Fatal("IPC message budget")
	}
}
func TestFlightPromotionKeepsOldWireAndAvoidsRecorderFeedback(t *testing.T) {
	d := diagnosticRuntimeFixture()
	r := flightrecorder.New(flightrecorder.Header{Schema: 1, PC: "PC13", Version: "0.3.814", Source: "fixture", Session: d.base.Session, ServicePID: 1}, nil)
	d.flight.Store(&flightRecorderRuntime{recorder: r})
	e := d.event("PERFORMANCE", "FLIGHT_RECORDER", "observed", "RECORDER_HEARTBEAT")
	e.Operation = (flightrecorder.Summary{}).Encode()
	d.recordFlightFact(e)
	if r.Status().Dropped != 0 {
		t.Fatal("recorder feedback changed accounting")
	}
}
func TestPendingDiagnosticCountPreservesAllQueuesAndACK(t *testing.T) {
	j := clubhealth.Journal{Lost: 714991, Rows: []clubhealth.JournalRow{{Acked: false}, {Acked: true}}, History: []clubhealth.JournalRow{{Acked: true}, {Acked: false}, {Acked: false}}}
	if diagnosticPendingCount(&j) != 3 || j.Lost != 714991 || !j.Rows[1].Acked {
		t.Fatal("count changed durable state")
	}
}
func BenchmarkDiagnosticPendingCount(b *testing.B) {
	j := clubhealth.Journal{Rows: make([]clubhealth.JournalRow, clubhealth.JournalEvents), History: make([]clubhealth.JournalRow, clubhealth.JournalEvents)}
	b.Run("old_append_copy", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			count := 0
			for _, row := range append(append([]clubhealth.JournalRow(nil), j.History...), j.Rows...) {
				if !row.Acked {
					count++
				}
			}
			if count != 2*clubhealth.JournalEvents {
				b.Fatal(count)
			}
		}
	})
	b.Run("separate_queues", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if diagnosticPendingCount(&j) != 2*clubhealth.JournalEvents {
				b.Fatal("count")
			}
		}
	})
}
func BenchmarkFlightRuntimeResourceSampler(b *testing.B) {
	r := newRuntimeResourceSampler()
	r.sample()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := r.sample()
		if !v.GCKnown || v.Goroutines == 0 {
			b.Fatal("unavailable runtime metadata")
		}
	}
}
func TestFlightSegmentFilesRemainBoundedAfterShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := New(ctx)
	dir := t.TempDir()
	c.ConfigurePersistentDiagnostics(Manifest{StateDirectory: dir, DeviceIdentityFile: filepath.Join(dir, "missing.json")})
	f := c.flight.Load()
	cancel()
	c.Close()
	select {
	case <-f.done:
	case <-time.After(time.Second):
		t.Fatal("recorder did not stop")
	}
	names, _ := filepath.Glob(filepath.Join(dir, "flight-v1-*.jsonl"))
	if len(names) == 0 || len(names) > flightrecorder.SegmentCount {
		t.Fatal("segment count", len(names))
	}
	for _, name := range names {
		info, err := os.Stat(name)
		if err != nil || info.Size() > flightrecorder.SegmentBytes {
			t.Fatal("segment size", err)
		}
	}
}
