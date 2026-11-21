package clientservice

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/buzzmean/neexitlag/core/optimizer"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/telemetry"
	"strings"
	"testing"
	"time"
)

func TestQualityDiagnosticsDoesNotInventRemoteDrops(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	var counters telemetry.Counters
	counters.Attempt(telemetry.TransportQueue)
	counters.Drop(telemetry.TransportQueue)
	c.transportDrops["R"] = counters.Snapshot
	data, err := c.Handle(context.Background(), "quality.diagnostics", nil)
	if err != nil {
		t.Fatal(err)
	}
	report := data.(DropDiagnostics)
	if report.RemoteRelayAvailable || report.Transport["R"]["transport_queue_drops"].Count != 1 || report.ProbeLossScope == "" {
		t.Fatal(report)
	}
}
func TestQualitySnapshotFitsIPCWithLargestProfileStorage(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	now := time.Now()
	for i := 0; i < 128; i++ {
		id := fmt.Sprintf("app-%03d", i)
		if c.Profiles.Upsert(profiles.Profile{ID: id, Name: strings.Repeat("n", 100), Executables: []string{strings.Repeat("p", 80) + ".exe"}, Mode: profiles.Auto}) != nil {
			break
		}
	}
	for i := 0; i < 32; i++ {
		id := fmt.Sprintf("R-%03d", i)
		for j := 0; j < 4; j++ {
			c.Selector.Observe(optimizer.RouteMeasurement{RouteID: id, RTT: 50 * time.Millisecond, Available: true, Samples: 20, Stability: 1, ObservedAt: now.Add(time.Duration(j-3) * time.Second)})
		}
	}
	raw, err := json.Marshal(c.Snapshot())
	if err != nil || len(raw) > 60000 {
		t.Fatal("IPC budget", len(raw), err)
	}
}

func TestTransportFaultVisibleBeforeProbeRoundCompletes(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	generation := c.Selector.RegisterTransport("R")
	c.Selector.ReportTransportFailure("R", generation, "session_closed", time.Now())
	state := c.Snapshot()
	for _, route := range state.Routes {
		if route.ID == "R" {
			if route.Status != "unhealthy" {
				t.Fatal(route)
			}
			if route.Quality == nil {
				t.Fatal("missing quality state")
			}
			return
		}
	}
	t.Fatal("faulted route omitted while probe pending")
}
