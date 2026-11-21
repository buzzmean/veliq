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
