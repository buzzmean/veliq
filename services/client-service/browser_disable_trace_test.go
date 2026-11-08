package clientservice

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wp "github.com/buzzmean/neexitlag/platform/windows"
)

// Test-only lifecycle evidence. No addresses, browser identities or payloads are
// recorded. Counters are monotonic; a completed pre-disable OPEN is not a new OPEN.
type continuityCall struct {
	Sequence         uint64
	FinishedSequence uint64
	CalledAt         time.Time
	ObservedAt       time.Time
	FinishedAt       time.Time
	Optimizing       bool
	Ready            bool
	InFlight         int
}

type continuityBoundary struct {
	Sequence   uint64
	Stage      string
	At         time.Time
	Optimizing bool
	Ready      bool
	InFlight   int
}

type continuityTrace struct {
	DisableSequence      uint64
	Total                int32
	InFlight             int
	StartedWhileDisabled int
	StartedAfterDisable  int
	Calls                []continuityCall
	Boundaries           []continuityBoundary
}

// Controlled backend seam, NOT WinDivert proof. The Windows test retains real
// owner/SID, registry policy, browser process and HTTP body assertions.
type continuityBackend struct {
	activationCaptureFixture
	controller      *Controller
	nativeCalls     atomic.Int32
	mu              sync.Mutex
	inFlight        int
	calls           []continuityCall
	boundaries      []continuityBoundary
	sequence        uint64 // All entry, completion and boundary events, guarded by mu.
	disableSequence uint64
	clock           func() time.Time // Set before use; nil keeps real diagnostic times.
	dial            func(context.Context, netip.AddrPort) (net.Conn, error)
}

func (b *continuityBackend) now() time.Time {
	if b.clock != nil {
		return b.clock()
	}
	return time.Now()
}

func (b *continuityBackend) Status() wp.CaptureStatus {
	s := b.activationCaptureFixture.Status()
	s.Capabilities.Transparent = true
	return s
}

func (b *continuityBackend) Stop() error {
	err := b.activationCaptureFixture.Stop()
	b.mark("backend_stopped")
	return err
}

func (b *continuityBackend) mark(stage string) {
	b.controller.mu.Lock()
	defer b.controller.mu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	at := b.now()
	b.sequence++
	if stage == "disable_complete" {
		b.disableSequence = b.sequence
	}
	b.boundaries = append(b.boundaries, continuityBoundary{Sequence: b.sequence, Stage: stage, At: at,
		Optimizing: b.controller.enabled && b.controller.settings.Automatic, Ready: b.active.Load(), InFlight: b.inFlight})
}

func (b *continuityBackend) OpenBrowserNativeTCP(ctx context.Context, _ wp.ProcessIdentity, _ netip.AddrPort, dst netip.AddrPort, _ wp.Decision) (net.Conn, error) {
	calledAt := b.now()
	// Same mutex as optimize's enabled=false transition: state attribution cannot
	// race a plain field read. Entries/boundaries lock controller.mu then b.mu;
	// completion/trace lock only b.mu, never the reverse. Sequence is the entry
	// linearization point; timestamps are diagnostic and may be identical.
	b.controller.mu.Lock()
	b.mu.Lock()
	ready := b.active.Load()
	index := len(b.calls)
	b.inFlight++
	b.nativeCalls.Add(1)
	b.sequence++
	b.calls = append(b.calls, continuityCall{Sequence: b.sequence, CalledAt: calledAt, ObservedAt: b.now(),
		Optimizing: b.controller.enabled && b.controller.settings.Automatic, Ready: ready, InFlight: b.inFlight})
	b.mu.Unlock()
	b.controller.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.sequence++
		b.calls[index].FinishedSequence = b.sequence
		b.calls[index].FinishedAt = b.now()
		b.inFlight--
		b.mu.Unlock()
	}()
	if !ready {
		return nil, errors.New("NATIVE_CAPTURE_NOT_READY")
	}
	if b.dial != nil {
		return b.dial(ctx, dst)
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", dst.String())
}

func (b *continuityBackend) trace() continuityTrace {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := continuityTrace{DisableSequence: b.disableSequence, Total: b.nativeCalls.Load(), InFlight: b.inFlight,
		Calls: append([]continuityCall(nil), b.calls...), Boundaries: append([]continuityBoundary(nil), b.boundaries...)}
	for _, call := range b.calls {
		if !call.Optimizing {
			s.StartedWhileDisabled++
		}
		if b.disableSequence != 0 && call.Sequence > b.disableSequence {
			s.StartedAfterDisable++
		}
	}
	return s
}

func TestContinuityMeasurementDoesNotMisclassifyPreDisableOpen(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.Demo, c.enabled = true, true
	entered, release := make(chan struct{}), make(chan struct{})
	// Reproduce the Windows clock collision, including identical monotonic time.
	frozen := time.Now()
	b := &continuityBackend{controller: c, clock: func() time.Time { return frozen }}
	b.active.Store(true)
	c.Backend = b
	app, peer := net.Pipe()
	defer peer.Close()
	b.dial = func(context.Context, netip.AddrPort) (net.Conn, error) { close(entered); <-release; return app, nil }
	oldBaseline := b.nativeCalls.Load()
	done := make(chan error, 1)
	go func() {
		conn, err := b.OpenBrowserNativeTCP(c.ctx, wp.ProcessIdentity{}, netip.AddrPort{}, netip.AddrPort{}, wp.Decision{})
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	<-entered // A legitimate OPEN after the old sample, but before disabling.
	if _, err := c.Handle(context.Background(), "optimize", []byte(`{"enabled":false}`)); err != nil {
		close(release)
		t.Fatal(err)
	}
	b.mark("disable_complete")
	if s := b.trace(); s.Total == oldBaseline || s.InFlight != 1 || s.StartedWhileDisabled != 0 || s.StartedAfterDisable != 0 || s.Calls[0].Sequence >= s.DisableSequence {
		close(release)
		t.Fatal("pre-disable call incorrectly attributed", s)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if s := b.trace(); s.Total != 1 || s.InFlight != 0 || s.StartedWhileDisabled != 0 || s.StartedAfterDisable != 0 || s.Calls[0].FinishedSequence <= s.DisableSequence {
		t.Fatal("completion after disable became a new call", s)
	}
	s := b.trace()
	if s.Calls[0].CalledAt != frozen || s.Calls[0].ObservedAt != frozen || s.Calls[0].FinishedAt != frozen || s.Boundaries[len(s.Boundaries)-1].At != frozen {
		t.Fatal("fixture did not reproduce equal timestamps", s)
	}
	t.Logf("identical timestamps: entry=%d disable=%d finish=%d off_entry=%d after_disable=%d in_flight=%d",
		s.Calls[0].Sequence, s.DisableSequence, s.Calls[0].FinishedSequence, s.StartedWhileDisabled, s.StartedAfterDisable, s.InFlight)
}

func TestContinuityMeasurementDetectsNewDisabledNativeCall(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	frozen := time.Now()
	b := &continuityBackend{controller: c, clock: func() time.Time { return frozen }}
	c.Backend = b
	b.mark("disable_complete")
	if _, err := b.OpenBrowserNativeTCP(c.ctx, wp.ProcessIdentity{}, netip.AddrPort{}, netip.AddrPort{}, wp.Decision{}); err == nil {
		t.Fatal("stopped fixture accepted a connection")
	}
	s := b.trace()
	if s.Total != 1 || s.InFlight != 0 || s.StartedWhileDisabled != 1 || s.StartedAfterDisable != 1 || s.Calls[0].Sequence <= s.DisableSequence || s.Calls[0].CalledAt != s.Boundaries[0].At {
		t.Fatal("actual disabled invocation was hidden", s)
	}
	t.Logf("identical timestamps: disable=%d entry=%d off_entry=%d after_disable=%d",
		s.DisableSequence, s.Calls[0].Sequence, s.StartedWhileDisabled, s.StartedAfterDisable)
}

func TestContinuityMeasurementConcurrentEventSequenceIsUnique(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	b := &continuityBackend{controller: c}
	c.Backend = b
	const calls = 32
	var wg sync.WaitGroup
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = b.OpenBrowserNativeTCP(c.ctx, wp.ProcessIdentity{}, netip.AddrPort{}, netip.AddrPort{}, wp.Decision{})
			b.mark("concurrent_boundary")
			_ = b.trace()
		}()
	}
	wg.Wait()
	s := b.trace()
	if s.Total != calls || s.InFlight != 0 || len(s.Boundaries) != calls || s.StartedWhileDisabled != calls {
		t.Fatal("lost concurrent entry or completion", s)
	}
	seen := make(map[uint64]bool)
	check := func(sequence uint64) {
		t.Helper()
		if sequence == 0 || seen[sequence] {
			t.Fatal("event sequence missing or duplicated", sequence, s)
		}
		seen[sequence] = true
	}
	for _, call := range s.Calls {
		check(call.Sequence)
		check(call.FinishedSequence)
		if call.Sequence >= call.FinishedSequence {
			t.Fatal("completion ordered before entry", call)
		}
	}
	for _, boundary := range s.Boundaries {
		check(boundary.Sequence)
	}
	for sequence := uint64(1); sequence <= 3*calls; sequence++ {
		if !seen[sequence] {
			t.Fatal("gap in event sequence", sequence, s)
		}
	}
}

func TestContinuityMeasurementDetectsDisabledEntryBeforeStopCompletes(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	b := &continuityBackend{controller: c}
	c.Backend = b
	// optimize publishes enabled=false before policy cleanup and Backend.Stop.
	// A native invocation in that interval is still forbidden, even if the
	// backend is ready and disable_complete has not yet been recorded.
	b.active.Store(true)
	app, peer := net.Pipe()
	defer app.Close()
	defer peer.Close()
	b.dial = func(context.Context, netip.AddrPort) (net.Conn, error) { return app, nil }
	if _, err := b.OpenBrowserNativeTCP(c.ctx, wp.ProcessIdentity{}, netip.AddrPort{}, netip.AddrPort{}, wp.Decision{}); err != nil {
		t.Fatal(err)
	}
	if s := b.trace(); s.Total != 1 || s.InFlight != 0 || s.StartedWhileDisabled != 1 || s.StartedAfterDisable != 0 || !s.Calls[0].Ready {
		t.Fatal("disabled entry during stop was hidden", s)
	}
}
