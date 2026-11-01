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
	CalledAt   time.Time
	ObservedAt time.Time
	FinishedAt time.Time
	Optimizing bool
	Ready      bool
	InFlight   int
}

type continuityBoundary struct {
	Stage      string
	At         time.Time
	Optimizing bool
	Ready      bool
	InFlight   int
}

type continuityTrace struct {
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
	controller  *Controller
	nativeCalls atomic.Int32
	mu          sync.Mutex
	inFlight    int
	calls       []continuityCall
	boundaries  []continuityBoundary
	disabledAt  time.Time
	dial        func(context.Context, netip.AddrPort) (net.Conn, error)
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
	at := time.Now()
	if stage == "disable_complete" {
		b.disabledAt = at
	}
	b.boundaries = append(b.boundaries, continuityBoundary{Stage: stage, At: at,
		Optimizing: b.controller.enabled && b.controller.settings.Automatic, Ready: b.active.Load(), InFlight: b.inFlight})
}

func (b *continuityBackend) OpenBrowserNativeTCP(ctx context.Context, _ wp.ProcessIdentity, _ netip.AddrPort, dst netip.AddrPort, _ wp.Decision) (net.Conn, error) {
	calledAt := time.Now()
	// Same mutex as optimize's enabled=false transition: state attribution cannot
	// race a plain field read. Keep physical invocation and observation times.
	b.controller.mu.Lock()
	b.mu.Lock()
	ready := b.active.Load()
	index := len(b.calls)
	b.inFlight++
	b.nativeCalls.Add(1)
	b.calls = append(b.calls, continuityCall{CalledAt: calledAt, ObservedAt: time.Now(),
		Optimizing: b.controller.enabled && b.controller.settings.Automatic, Ready: ready, InFlight: b.inFlight})
	b.mu.Unlock()
	b.controller.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.calls[index].FinishedAt = time.Now()
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
	s := continuityTrace{Total: b.nativeCalls.Load(), InFlight: b.inFlight,
		Calls: append([]continuityCall(nil), b.calls...), Boundaries: append([]continuityBoundary(nil), b.boundaries...)}
	for _, call := range b.calls {
		if !call.Optimizing {
			s.StartedWhileDisabled++
		}
		if !b.disabledAt.IsZero() && !call.CalledAt.Before(b.disabledAt) {
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
	b := &continuityBackend{controller: c}
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
	if s := b.trace(); s.Total == oldBaseline || s.InFlight != 1 || s.StartedWhileDisabled != 0 || s.StartedAfterDisable != 0 {
		close(release)
		t.Fatal("pre-disable call incorrectly attributed", s)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if s := b.trace(); s.Total != 1 || s.InFlight != 0 || s.StartedWhileDisabled != 0 || s.StartedAfterDisable != 0 || s.Calls[0].FinishedAt.Before(s.Boundaries[len(s.Boundaries)-1].At) {
		t.Fatal("completion after disable became a new call", s)
	}
}

func TestContinuityMeasurementDetectsNewDisabledNativeCall(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	b := &continuityBackend{controller: c}
	c.Backend = b
	b.mark("disable_complete")
	if _, err := b.OpenBrowserNativeTCP(c.ctx, wp.ProcessIdentity{}, netip.AddrPort{}, netip.AddrPort{}, wp.Decision{}); err == nil {
		t.Fatal("stopped fixture accepted a connection")
	}
	if s := b.trace(); s.Total != 1 || s.InFlight != 0 || s.StartedWhileDisabled != 1 || s.StartedAfterDisable != 1 {
		t.Fatal("actual disabled invocation was hidden", s)
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
