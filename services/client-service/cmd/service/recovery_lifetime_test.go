package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestRecoveryOnlyExitsForExplicitSCMStop(t *testing.T) {
	for _, state := range []string{"RUNNING", "UNKNOWN", "START_PENDING"} {
		if recoveryHostStopped(state) {
			t.Fatal("transient treated as stop", state)
		}
	}
	for _, state := range []string{"STOPPED", "STOP_PENDING", "NOT_INSTALLED"} {
		if !recoveryHostStopped(state) {
			t.Fatal("stop ignored", state)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stopped atomic.Bool
	done := make(chan struct{})
	go func() {
		watchRecoveryHost(ctx, cancel, func() string {
			if stopped.Load() {
				return "STOP_PENDING"
			}
			return "RUNNING"
		}, time.Millisecond)
		close(done)
	}()
	select {
	case <-ctx.Done():
		t.Fatal("live host stopped recovery")
	default:
	}
	stopped.Store(true)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("helper retained listener after SCM stop")
	}
	if ctx.Err() == nil {
		t.Fatal("helper listener context not cancelled")
	}
}
