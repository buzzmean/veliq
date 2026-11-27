package clientservice

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"runtime/metrics"
	"time"

	"github.com/buzzmean/veliq/core/clubhealth"
	"github.com/buzzmean/veliq/core/flightrecorder"
	wp "github.com/buzzmean/veliq/platform/windows"
)

type flightRecorderRuntime struct {
	recorder *flightrecorder.Recorder
	done     chan struct{}
}

func (c *Controller) ConfigureFlightRecorder(m Manifest) {
	d := c.diagnostics.Load()
	if d == nil || !filepath.IsAbs(m.StateDirectory) || m.StateDirectory == "" || c.flight.Load() != nil {
		return
	}
	ownApp := ""
	if exe, err := os.Executable(); err == nil {
		name := filepath.Base(exe)
		if clubhealth.ValidApp(name) {
			ownApp = name
		}
	}
	h := flightrecorder.Header{Schema: 1, PC: d.base.PC, Version: d.base.Version, Source: d.base.Source, Session: d.base.Session, ServicePID: d.base.ServicePID}
	promote := func(p flightrecorder.Promotion) bool {
		code := "RESOURCE_CONTEXT"
		if p.Summary.Flags&flightrecorder.Heartbeat != 0 {
			code = "RECORDER_HEARTBEAT"
		}
		e := d.event("PERFORMANCE", "FLIGHT_RECORDER", "observed", code)
		e.At, e.Incident, e.Operation = p.At, p.Incident, p.Summary.Encode()
		e.PID, e.Birth = p.PID, p.Birth
		if p.Summary.Flags&flightrecorder.VerifiedProcess != 0 && p.PID == d.base.ServicePID && ownApp != "" {
			e.App, e.ProcessVerified = ownApp, true
		}
		select {
		case d.input <- diagnosticInput{event: e}:
			return true
		default:
			return false
		}
	}
	f := &flightRecorderRuntime{recorder: flightrecorder.New(h, promote), done: make(chan struct{})}
	if !c.flight.CompareAndSwap(nil, f) {
		return
	}
	d.flight.Store(f)
	path := func(slot int) string {
		return filepath.Join(m.StateDirectory, fmt.Sprintf("flight-v1-%02d.jsonl", slot))
	}
	store := flightrecorder.Storage{
		Read: func(slot int) ([]byte, error) {
			p := path(slot)
			before, err := os.Lstat(p)
			if err != nil {
				return nil, err
			}
			if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() > flightrecorder.SegmentBytes {
				return nil, fmt.Errorf("FLIGHT_SEGMENT_INVALID")
			}
			file, err := os.Open(p)
			if err != nil {
				return nil, err
			}
			defer file.Close()
			actual, err := file.Stat()
			if err != nil || !os.SameFile(before, actual) {
				return nil, fmt.Errorf("FLIGHT_SEGMENT_CHANGED")
			}
			return io.ReadAll(io.LimitReader(file, flightrecorder.SegmentBytes+1))
		},
		Write: func(slot int, raw []byte) error { return protectedActivationWrite(path(slot), raw) },
	}
	go func() { defer close(f.done); f.recorder.Run(c.ctx, store) }()
	go c.sampleFlightResources(c.ctx, d, f)
}
func (c *Controller) RecordFlightFact(component, code, state string) {
	d := c.diagnostics.Load()
	if d == nil {
		return
	}
	// Only fixed internal call sites use this method. IPC never supplies labels.
	switch component {
	case "SERVICE", "ACTIVATION", "CAPTURE", "IPC", "NETWORK":
	default:
		return
	}
	switch state {
	case "ready", "failed", "observed", "unknown", "recovered":
	default:
		return
	}
	if !clubhealth.ValidReason(code) {
		return
	}
	observer := "SERVICE_PHASE"
	if component == "ACTIVATION" {
		observer = "ACTIVATION_PHASE"
	}
	e := d.event(component, observer, state, code)
	d.offer(e, "flight-phase:"+component)
}
func (c *Controller) FlightRecorderStatus() flightrecorder.Status {
	if f := c.flight.Load(); f != nil {
		return f.recorder.Status()
	}
	return (*flightrecorder.Recorder)(nil).Status()
}
func (c *Controller) FlightRecorderContext(ctx context.Context, limit int) ([]flightrecorder.Entry, error) {
	if limit < 1 || limit > 8 {
		return nil, fmt.Errorf("FLIGHT_CONTEXT_LIMIT")
	}
	f := c.flight.Load()
	if f == nil {
		return nil, fmt.Errorf("FLIGHT_NOT_CONFIGURED")
	}
	return f.recorder.Snapshot(ctx, limit)
}
func (d *persistentDiagnostics) recordFlightFact(e clubhealth.Diagnostic) {
	if f := d.flight.Load(); f != nil {
		f.recorder.OfferFact(e)
	}
}

type runtimeResourceSampler struct {
	samples []metrics.Sample
	gc      debug.GCStats
}

func newRuntimeResourceSampler() *runtimeResourceSampler {
	names := []string{"/memory/classes/heap/objects:bytes", "/memory/classes/heap/free:bytes", "/memory/classes/heap/released:bytes", "/memory/classes/heap/unused:bytes", "/gc/heap/allocs:bytes", "/sched/goroutines:goroutines"}
	r := &runtimeResourceSampler{samples: make([]metrics.Sample, len(names)), gc: debug.GCStats{Pause: make([]time.Duration, 515), PauseEnd: make([]time.Time, 0, 256)}}
	for i, name := range names {
		r.samples[i].Name = name
	}
	return r
}
func (r *runtimeResourceSampler) sample() flightrecorder.RuntimeSample {
	started := time.Now()
	metrics.Read(r.samples)
	debug.ReadGCStats(&r.gc)
	value := func(i int) uint64 {
		if r.samples[i].Value.Kind() == metrics.KindUint64 {
			return r.samples[i].Value.Uint64()
		}
		return 0
	}
	return flightrecorder.RuntimeSample{GCKnown: true, HeapAllocBytes: value(0), HeapSysBytes: value(0) + value(1) + value(2) + value(3), AllocBytes: value(4), PauseTotalNS: uint64(max(0, r.gc.PauseTotal)), NumGC: uint32(min(uint64(max(0, r.gc.NumGC)), 1<<32-1)), Goroutines: uint32(min(value(5), 1<<32-1)), CostNS: uint64(time.Since(started))}
}
func (c *Controller) sampleFlightResources(ctx context.Context, d *persistentDiagnostics, f *flightRecorderRuntime) {
	sampler := wp.NewResourceSampler(0)
	runtimeSampler := newRuntimeResourceSampler()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		s := sampler.Sample()
		g := runtimeSampler.sample()
		state := c.flightStateSnapshot()
		state.DiagnosticQueue = uint32(len(d.input))
		state.DiagnosticClubQueue = uint32(len(d.clubInputs))
		f.recorder.OfferResource(s, g, state)
		if s.ErrorCode != "" && s.ErrorCode != "OK" && s.ErrorCode != "THROTTLED" {
			d.note("PERFORMANCE", "RESOURCE_SAMPLER", "unknown", s.ErrorCode, s.NativeCode, "resource-sampler")
		}
		timer.Reset(5 * time.Second)
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}
