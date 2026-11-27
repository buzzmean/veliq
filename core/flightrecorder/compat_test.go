package flightrecorder

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFR1DiagnosticWireCompatibilityFixtures(t *testing.T) {
	cases := []Summary{
		{Flags: KnownCPU | KnownWorkingSet | KnownIO | KnownGC | KnownInterval | VerifiedProcess | ContextPre, SpanMS: 6000, CPUTimeUS: 20000, WorkingSetKiB: 51200, ReadKiB: 2, WriteKiB: 1, GCPauseUS: 55},
		{Flags: Heartbeat | CounterReset},
		{Flags: KnownCPU | KnownWorkingSet | KnownInterval | Saturated | ContextPost, SpanMS: 6000, CPUTimeUS: 1<<32 - 1, WorkingSetKiB: 1<<32 - 1},
		{Flags: KnownWorkingSet | KnownInterval | CounterReset | Heartbeat, SpanMS: 6000, WorkingSetKiB: 51200},
	}
	for i, s := range cases {
		e := factFixture(100 + i)
		e.Observer, e.Component, e.Code, e.Operation = "FLIGHT_RECORDER", "PERFORMANCE", "RESOURCE_CONTEXT", s.Encode()
		e.Incident = fmt.Sprintf("%032x", 1000+i)
		e.At = time.Now().UTC()
		if _, ok := Decode(e.Operation); !ok || !e.Valid(time.Now()) || e.NativeCode != 0 {
			t.Fatal("old wire allowlist incompatible", s)
		}
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if dir := os.Getenv("VELIQ_FLIGHTRECORDER_COMPAT_DIR"); dir != "" {
			if err = os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(dir, fmt.Sprintf("frame-%d.json", i)), raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
