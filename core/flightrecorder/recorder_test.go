package flightrecorder

import (
	"context"
	"errors"
	"fmt"
	"github.com/buzzmean/veliq/core/clubhealth"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func headerFixture() Header {
	return Header{Schema: 1, PC: "PC13", Version: "0.3.814", Source: "fixture", Session: strings.Repeat("a", 32), ServicePID: 42}
}
func factFixture(n int) clubhealth.Diagnostic {
	return clubhealth.Diagnostic{ID: fmt.Sprintf("%032x", n+1), PC: "PC13", Version: "0.3.814", Source: "fixture", Session: strings.Repeat("a", 32), ServicePID: 42, At: time.Now().UTC(), Observer: "SERVICE_PHASE", Component: "SERVICE", State: "observed", Code: "PHASE_ENTERED"}
}
func resourceFrame(n int) Frame {
	s := sampleFixture()
	s.CPUTimeNS += uint64(n) * 1_000_000
	s.ReadBytes += uint64(n) * 1024
	s.WriteBytes += uint64(n) * 2048
	s.At = time.Now().UTC().Add(-10 * time.Minute).Add(time.Duration(n) * time.Second)
	return Frame{ObservedAt: s.At, ElapsedNS: uint64(time.Duration(n) * time.Second), Resource: s, Runtime: RuntimeSample{GCKnown: true, PauseTotalNS: uint64(n) * 1000}}
}
func memoryStore() (Storage, map[int][]byte) {
	m := map[int][]byte{}
	return Storage{Read: func(i int) ([]byte, error) {
		v, ok := m[i]
		if !ok {
			return nil, os.ErrNotExist
		}
		return append([]byte(nil), v...), nil
	}, Write: func(i int, p []byte) error {
		if len(p) > SegmentBytes {
			panic("unbounded write")
		}
		m[i] = append([]byte(nil), p...)
		return nil
	}}, m
}
func TestRecorderRotatesBoundedSegmentsAndColdReloads(t *testing.T) {
	store, files := memoryStore()
	r := New(headerFixture(), nil)
	for i := 0; i < 2000; i++ {
		f := resourceFrame(i%500 + 1)
		f.ObservedAt = time.Now().UTC().Add(time.Duration(i-2000) * time.Millisecond)
		r.append(f, store)
	}
	r.append(Frame{Marker: "RECORDER_STOPPED", ObservedAt: time.Now().UTC()}, store)
	r.flushAt(store, time.Now(), true)
	r.publish()
	if len(files) > SegmentCount || r.Status().WindowFrames != RingCapacity || r.Status().WindowEvictions == 0 || r.Status().Dropped != 0 {
		t.Fatal(r.Status())
	}
	fresh := New(headerFixture(), nil)
	fresh.load(store, time.Now())
	fresh.publish()
	if fresh.Status().WindowFrames == 0 || fresh.Status().PreviousTailUncertain || fresh.Status().Cause != "UNKNOWN" {
		t.Fatal(fresh.Status())
	}
	rows := fresh.recent(8)
	if len(rows) != 8 || rows[len(rows)-1].Frame.Marker != "RECORDER_STOPPED" {
		t.Fatal("latest cold tail not preserved")
	}
	for _, p := range files {
		if len(p) > SegmentBytes {
			t.Fatal("segment bound")
		}
	}
}
func TestRecorderProducerNeverWaitsForBlockedDurability(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	store := Storage{Write: func(int, []byte) error { once.Do(func() { close(entered) }); <-release; return nil }}
	r := New(headerFixture(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx, store); close(done) }()
	cancel()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("writer not entered")
	}
	started := time.Now()
	for i := 0; i < QueueCapacity*3; i++ {
		r.OfferFact(factFixture(i))
	}
	if time.Since(started) > time.Second || r.Status().Dropped == 0 {
		t.Fatal("producer blocked or loss hidden")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("did not close")
	}
}
func TestRecorderKeepsDurabilityFailuresSeparateFromWindowEviction(t *testing.T) {
	store := Storage{Write: func(int, []byte) error { return errors.New("fixture") }}
	r := New(headerFixture(), nil)
	for i := 0; i < 200; i++ {
		r.append(resourceFrame(i+1), store)
	}
	r.flush(store)
	r.publish()
	s := r.Status()
	if s.WriteFailures == 0 || s.UnpersistedSegments == 0 || s.WriteBytes != 0 || s.WriteAttemptBytes == 0 || s.Dropped != 0 || s.Coverage != "WRITE_FAILED" {
		t.Fatal(s)
	}
}
func TestRecorderTruncatedColdTailIsUnknownNotCrash(t *testing.T) {
	store, files := memoryStore()
	r := New(headerFixture(), nil)
	r.append(resourceFrame(1), store)
	r.flush(store)
	files[0] = append(files[0], []byte(`{"partial":`)...)
	fresh := New(headerFixture(), nil)
	fresh.load(store, time.Now())
	fresh.publish()
	if fresh.Status().CorruptSegments != 1 || fresh.Status().Cause != "UNKNOWN" || fresh.Status().WindowFrames == 0 {
		t.Fatal(fresh.Status())
	}
}
func TestRecorderIncidentPrePostAndGlobalPromotionBudget(t *testing.T) {
	var output []Promotion
	r := New(headerFixture(), func(p Promotion) bool { output = append(output, p); return true })
	store, _ := memoryStore()
	for _, n := range []int{5, 10, 15, 20, 25, 30, 35, 40, 45, 50} {
		r.append(resourceFrame(n), store)
	}
	e := factFixture(1)
	e.State = "failed"
	e.At = resourceFrame(55).Resource.At
	r.append(Frame{ObservedAt: e.At, ElapsedNS: uint64(55 * time.Second), Fact: e}, store)
	for i := 0; i < 100; i++ {
		v := e
		v.ID = fmt.Sprintf("%032x", i+20)
		r.append(Frame{ObservedAt: e.At.Add(time.Second), ElapsedNS: uint64(56 * time.Second), Fact: v}, store)
	}
	for _, n := range []int{60, 65, 70, 75, 80, 85, 90} {
		r.append(resourceFrame(n), store)
	}
	r.publish()
	pre, post := 0, 0
	for _, p := range output {
		if p.Summary.Flags&ContextPre != 0 {
			pre++
		}
		if p.Summary.Flags&ContextPost != 0 {
			post++
		}
		if _, ok := Decode(p.Summary.Encode()); !ok {
			t.Fatal("invalid promoted codec")
		}
	}
	if pre != 4 || post != 4 || len(output) > RemoteBudget || r.Status().RemoteSuppressed < 100 {
		t.Fatal(pre, post, len(output), r.Status())
	}
	// Historical PRE timestamps may never reset the current global budget.
	r.budgetStart = uint64(time.Minute)
	r.budgetUsed = RemoteBudget
	r.promoteSample(resourceFrame(10), ContextPre, e.ID, uint64(65*time.Second))
	if len(output) > RemoteBudget {
		t.Fatal("historical PRE bypassed budget")
	}
}
func TestRecorderWERAndUnknownStateDoNotInventIncidents(t *testing.T) {
	var output []Promotion
	r := New(headerFixture(), func(p Promotion) bool { output = append(output, p); return true })
	store, _ := memoryStore()
	r.append(resourceFrame(5), store)
	before := len(output)
	for _, code := range []string{"LANGAME_CRASH", "SCM_UNAVAILABLE", "PROCESS_EXITED"} {
		e := factFixture(1)
		e.Code, e.Observer, e.Component, e.State = code, "WINDOWS_EVENT_LOG", "LANGAME", "observed"
		e.EventID = 1001
		r.append(Frame{ObservedAt: time.Now().UTC(), ElapsedNS: uint64(10 * time.Second), Fact: e}, store)
	}
	if len(output) != before || r.postRemaining != 0 {
		t.Fatal("ambiguous observation called an incident")
	}
}
func BenchmarkRecorderOfferWithoutDisk(b *testing.B) {
	r := New(headerFixture(), nil)
	e := factFixture(1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.OfferFact(e)
	}
}
func BenchmarkRecorderAppendSteadyState(b *testing.B) {
	r := New(headerFixture(), nil)
	f := resourceFrame(1)
	store := Storage{Write: func(int, []byte) error { return nil }}
	for i := 0; i < RingCapacity; i++ {
		r.append(f, store)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.ElapsedNS++
		r.append(f, store)
	}
}

func TestHistoricalWindowsFaultKeepsAuditWithoutCurrentBeforeAfterAttribution(t *testing.T) {
	var output []Promotion
	r := New(headerFixture(), func(p Promotion) bool { output = append(output, p); return true })
	store, _ := memoryStore()
	r.append(resourceFrame(5), store)
	e := factFixture(10)
	e.At = time.Now().Add(-10 * time.Minute)
	e.Observer = "WINDOWS_EVENT_LOG"
	e.Component = "LANGAME"
	e.Code = "LANGAME_CRASH"
	e.Operation = "APPLICATION_FAULT"
	e.EventID = 1000
	before := len(output)
	r.append(Frame{ObservedAt: time.Now().UTC(), ElapsedNS: uint64(10 * time.Second), Fact: e}, store)
	r.publish()
	if len(output) != before || r.Status().HistoricalIncidents != 1 || r.Status().LastFact.At != e.At {
		t.Fatal("historical fault associated with current resource samples", r.Status())
	}
}

func TestClosingAbortsUnboundedSnapshotAndRejectsEveryLaterOffer(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	store := Storage{Write: func(int, []byte) error { once.Do(func() { close(entered) }); <-release; return nil }}
	r := New(headerFixture(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx, store); close(done) }()
	cancel()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("close flush not entered")
	}
	read := make(chan error, 1)
	go func() { _, err := r.Snapshot(context.Background(), 8); read <- err }()
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("closing snapshot claimed success")
		}
	case <-time.After(time.Second):
		t.Fatal("Background context waited for disk forever")
	}
	for i := 0; i < 100; i++ {
		if r.OfferFact(factFixture(i)) {
			t.Fatal("accepted unprocessable closing tail")
		}
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close not finished")
	}
}

func TestFrameRejectsUnboundedOrMixedMetadata(t *testing.T) {
	for _, change := range []func(*Frame){func(f *Frame) { f.State.CaptureRXBytes = 1 }, func(f *Frame) { f.State.ActivationState = strings.Repeat("SECRET", 1000) }, func(f *Frame) { f.State.Known = 0xffff }, func(f *Frame) { f.Fact = factFixture(1) }} {
		f := resourceFrame(1)
		change(&f)
		if validFrame(f, time.Now()) {
			t.Fatal("malformed or mixed metadata accepted")
		}
	}
}
func BenchmarkRecorderAcceptedOfferAndDequeue(b *testing.B) {
	r := New(headerFixture(), nil)
	e := factFixture(1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !r.OfferFact(e) {
			b.Fatal("accepted workload rejected")
		}
		<-r.input
	}
}

func TestWriteAttemptBudgetSurvivesStormFailureAndColdRestart(t *testing.T) {
	for _, fail := range []bool{false, true} {
		store, files := memoryStore()
		realWrite := store.Write
		attempts := 0
		store.Write = func(slot int, p []byte) error {
			attempts++
			if fail {
				return errors.New("fixture")
			}
			return realWrite(slot, p)
		}
		r := New(headerFixture(), nil)
		for i := 0; i < 2000; i++ {
			r.append(resourceFrame(i%100+1), store)
		}
		if attempts != 1 || r.stats.WriteThrottled == 0 || r.stats.UnpersistedSegments == 0 {
			t.Fatal("sustained storm escaped attempt budget", attempts, r.stats)
		}
		r.flushAt(store, r.lastWriteAttempt.Add(14*time.Second), false)
		if attempts != 1 {
			t.Fatal("failure retry bypassed budget")
		}
		fail = false
		r.append(Frame{Marker: "RECORDER_STOPPED", ObservedAt: time.Now().UTC()}, store)
		r.flushAt(store, time.Now(), true)
		r.flushAt(store, time.Now(), true)
		if attempts != 2 || r.stats.ShutdownWrites != 1 {
			t.Fatal("multiple final budget exemptions", attempts, r.stats.ShutdownWrites)
		}
		for _, raw := range files {
			if len(raw) > SegmentBytes {
				t.Fatal("header gap counters escaped byte budget")
			}
		}
		fresh := New(headerFixture(), nil)
		fresh.load(store, time.Now())
		fresh.publish()
		if fresh.Status().UnpersistedSegments == 0 || fresh.Status().Coverage != "PARTIAL_LOCAL_WINDOW" {
			t.Fatal("cold restart hid skipped middle context", fresh.Status())
		}
	}
}

func BenchmarkRecorderWriteBudgetNormalAndStorm(b *testing.B) {
	for _, normal := range []bool{true, false} {
		name := "storm"
		if normal {
			name = "normal_5s_frames"
		}
		b.Run(name, func(b *testing.B) {
			attempts := 0
			r := New(headerFixture(), nil)
			f := resourceFrame(1)
			store := Storage{Write: func(int, []byte) error { attempts++; return nil }}
			base := time.Now()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				f.ElapsedNS++
				r.append(f, store)
				if normal && i%3 == 2 {
					r.flushAt(store, base.Add(time.Duration(i/3+1)*15*time.Second), false)
				}
			}
			b.ReportMetric(float64(attempts), "write_attempts")
			b.ReportMetric(float64(attempts)/float64(b.N), "writes/frame")
			b.ReportMetric(float64(r.stats.WriteAttemptBytes)/float64(b.N), "requested_B/frame")
		})
	}
}
