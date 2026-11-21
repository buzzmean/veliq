package integration

import (
	"context"
	"github.com/buzzmean/neexitlag/core/transport"
	"testing"
	"time"
)

func TestPoolCreationMeasurementsBootstrapAndRecovery(t *testing.T) {
	x := newPoolFixture(t, transport.DefaultPoolConfig(), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := x.pool.Warm(ctx); e != nil {
		t.Fatal(e)
	}
	s := x.pool.Snapshot().SessionCreationMetrics
	if s.NewSessions60s != 1 || s.Attempts60s != 1 || s.MaxConcurrent != 1 || s.Recent[0].QUICHandshakeMS < 0 || s.Recent[0].FactoryMS < s.Recent[0].QUICHandshakeMS {
		t.Fatal(s)
	}
	x.mu.Lock()
	old := x.clients[0]
	x.mu.Unlock()
	old.Close()
	select {
	case <-old.Done():
	case <-ctx.Done():
		t.Fatal("session close")
	}
	if e := x.pool.Warm(ctx); e != nil {
		t.Fatal(e)
	}
	s = x.pool.Snapshot().SessionCreationMetrics
	if s.NewSessions60s != 2 || s.Attempts60s != 2 || s.MaxConcurrent != 1 || s.Recent[1].Reason != "session_replacement" {
		t.Fatal(s)
	}
	t.Logf("local bootstrap+recovery: %+v", s)
}
