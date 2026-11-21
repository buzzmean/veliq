package windowsplatform

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTCPAdmissionBurstAndHardBound(t *testing.T) {
	for _, n := range []int{160, 256, tcpOpenPending} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			a := newTCPAdmission()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			gate := make(chan struct{})
			var active, peak atomic.Int32
			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				wg.Add(1)
				if !a.submit(ctx, func(_ time.Duration, err error, release func()) {
					defer wg.Done()
					if err != nil {
						t.Error(err)
						return
					}
					v := active.Add(1)
					for old := peak.Load(); v > old; old = peak.Load() {
						if peak.CompareAndSwap(old, v) {
							break
						}
					}
					<-gate
					active.Add(-1)
					release()
					release() // Idempotent: payload pipe may also defer release.
				}) {
					t.Fatal("normal burst rejected", i)
				}
			}
			if n == tcpOpenPending && a.submit(ctx, func(time.Duration, error, func()) { t.Error("overflow executed") }) {
				t.Fatal("unbounded admission")
			}
			close(gate)
			wg.Wait()
			if peak.Load() > tcpOpenParallel {
				t.Fatal("too many opens", peak.Load())
			}
			if len(a.pending) != 0 {
				t.Fatal("admission leaked")
			}
		})
	}
}

func TestTCPAdmissionCancellationAndReuse(t *testing.T) {
	a := newTCPAdmission()
	// Fill all workers deterministically so no queued work can start.
	if err := a.slots.Acquire(context.Background(), tcpOpenParallel); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	if !a.submit(ctx, func(_ time.Duration, err error, _ func()) { done <- err }) {
		t.Fatal("queue rejected")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancel ignored")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel stuck")
	}
	a.slots.Release(tcpOpenParallel)
	// Completion releases queued reservations, including on cancellation.
	deadline := time.Now().Add(time.Second)
	for len(a.pending) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(a.pending) != 0 {
		t.Fatal("cancelled reservation leaked")
	}
	done2 := make(chan struct{})
	a.submit(context.Background(), func(_ time.Duration, err error, release func()) {
		if err != nil {
			t.Error(err)
		}
		release()
		close(done2)
	})
	<-done2
}

func TestTCPAdmissionDeadline(t *testing.T) {
	a := newTCPAdmission()
	if err := a.slots.Acquire(context.Background(), tcpOpenParallel); err != nil {
		t.Fatal(err)
	}
	defer a.slots.Release(tcpOpenParallel)
	// A caller's shorter deadline must bound queue wait too, independently of
	// the later upstream timeout, and the reservation must be reusable.
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	if !a.submit(ctx, func(_ time.Duration, err error, release func()) { release(); done <- err }) {
		t.Fatal("queue full")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("deadline lost", err)
		}
	case <-time.After(time.Second):
		t.Fatal("unbounded queue wait")
	}
	if len(a.pending) != 0 {
		t.Fatal("expired reservation leaked")
	}
}
