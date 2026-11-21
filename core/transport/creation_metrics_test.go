package transport

import (
	"errors"
	"testing"
	"time"
)

func TestCreationMetricsWindowFailuresAndSnapshot(t *testing.T) {
	var m creationTelemetry
	n := time.Unix(1000, 0)
	m.begin(n, "initial_bootstrap")
	m.finish(n.Add(time.Millisecond), n, "initial_bootstrap", &Client{handshakeMS: 3}, nil)
	m.begin(n.Add(time.Second), "session_replacement")
	m.finish(n.Add(time.Second), n, "session_replacement", nil, errors.New("ticket secret must not be retained"))
	s := m.snapshot(n.Add(time.Second))
	if s.Attempts60s != 2 || s.NewSessions60s != 1 || s.MaxConcurrent != 1 || s.Concurrent != 0 || len(s.Recent) != 2 || s.Recent[1].QUICHandshakeMS != -1 {
		t.Fatal(s)
	}
	s.Recent[0].Reason = "changed"
	if m.metrics.Recent[0].Reason != "initial_bootstrap" {
		t.Fatal("alias")
	}
	s = m.snapshot(n.Add(61 * time.Second))
	if s.Attempts60s != 0 || s.NewSessions60s != 0 || s.MaxAttempts60s != 2 || s.MaxNewSessions60s != 1 {
		t.Fatal(s)
	}
}
