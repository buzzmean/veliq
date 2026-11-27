package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestStartupGateRejectsUntilReady(t *testing.T) {
	var g startupGate
	calls := 0
	h := g.wrap(func(context.Context, string, json.RawMessage) (any, error) { calls++; return "ok", nil })
	if _, err := h(context.Background(), "optimize", nil); !errors.Is(err, errStarting) || calls != 0 {
		t.Fatalf("handler reachable before ready: err=%v calls=%d", err, calls)
	}
	g.ready.Store(true)
	if v, err := h(context.Background(), "status", nil); err != nil || v != "ok" || calls != 1 {
		t.Fatalf("handler unreachable after ready: %v %v %d", v, err, calls)
	}
}

// Diagnostic reads remain available precisely when initialization gets stuck;
// they still pass through the authenticated pipe and controller guards.
func TestStartupFlightReadsDoNotOpenMutationGate(t *testing.T) {
	var g startupGate
	calls := 0
	h := g.wrap(func(context.Context, string, json.RawMessage) (any, error) { calls++; return "ok", nil })
	for _, method := range []string{"flight.status", "flight.context"} {
		if _, err := h(context.Background(), method, nil); err != nil {
			t.Fatal(method, err)
		}
	}
	for _, method := range []string{"flight.configure", "settings.set", "profile.set", "optimize", "future.mutation"} {
		if _, err := h(context.Background(), method, nil); !errors.Is(err, errStarting) {
			t.Fatal("startup mutation gate changed", method, err)
		}
	}
	if calls != 2 {
		t.Fatal("unexpected handler access", calls)
	}
}
