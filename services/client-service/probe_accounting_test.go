package clientservice

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/measurement"
	"github.com/buzzmean/neexitlag/core/optimizer"
	"github.com/buzzmean/neexitlag/core/routing"
)

type silentFlow struct{}

func (silentFlow) Send([]byte) error { return nil }
func (silentFlow) Receive(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (silentFlow) Close() error { return nil }

func TestQualityDiagnosticsExposeProbeAccountingPerRoute(t *testing.T) {
	c := New(context.Background())
	t.Cleanup(c.Close)
	e := measurement.New(measurement.Settings{Samples: 2, Timeout: 20 * time.Millisecond, Spacing: 20 * time.Millisecond, Concurrency: 1, LateWindow: 30 * time.Millisecond})
	c.Measurements = e
	e.Probe(context.Background(), measurement.Candidate{Metadata: optimizer.RelayCandidate{ID: "VPS-01"}, Target: netip.MustParseAddrPort("192.0.2.1:40000"),
		Open: func(context.Context, netip.AddrPort) (routing.Datagram, error) { return silentFlow{}, nil }})
	raw, err := c.Handle(context.Background(), "quality.diagnostics", nil)
	if err != nil {
		t.Fatal(err)
	}
	text, _ := json.Marshal(raw)
	for _, want := range []string{`"probe_accounting"`, `"route_id":"VPS-01"`, `"loss_true_percent":100`, `"no_reply":2`, `"last_5_min"`} {
		if !strings.Contains(string(text), want) {
			t.Fatalf("missing %s in %s", want, text)
		}
	}
}

func TestStatusReportsTheBuildItWasMadeFrom(t *testing.T) {
	c := New(context.Background())
	t.Cleanup(c.Close)
	raw, err := c.Handle(context.Background(), "status", nil)
	if err != nil {
		t.Fatal(err)
	}
	text, _ := json.Marshal(raw)
	if !strings.Contains(string(text), `"build":"`) {
		t.Fatalf("status has no build stamp: %s", text)
	}
}
