package windowsplatform

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/flightrecorder"
)

func resourceFixtureSampler(frames []flightrecorder.ResourceSample) (*ResourceSampler, *time.Time, *int) {
	at := time.Now()
	calls := 0
	s := &ResourceSampler{pid: 7, interval: 5 * time.Second, now: func() time.Time { return at }, read: func(uint32) flightrecorder.ResourceSample {
		index := min(calls, len(frames)-1)
		calls++
		return frames[index]
	}}
	return s, &at, &calls
}
func resourceFixtureFrame(birth, cpu, read, write uint64) flightrecorder.ResourceSample {
	return flightrecorder.ResourceSample{PID: 7, Birth: birth, Source: "TEST_SOURCE", ErrorCode: "OK", Known: flightrecorder.ResourceCPU | flightrecorder.ResourceIO | flightrecorder.ResourceSystemCPU, CPUTimeNS: cpu, ReadBytes: read, WriteBytes: write, SystemIdleNS: cpu / 2, SystemKernelNS: cpu, SystemUserNS: cpu}
}

func TestResourceSamplerMonotonicDeltasKnownAndThrottle(t *testing.T) {
	s, at, calls := resourceFixtureSampler([]flightrecorder.ResourceSample{resourceFixtureFrame(123, 1000, 50, 70), resourceFixtureFrame(123, 3000, 70, 120)})
	first := s.Observe()
	if first.Delta.Reset != "FIRST_SAMPLE" || first.Delta.Known != 0 || first.Sample.CostNS == 0 {
		t.Fatal(first)
	}
	for range 20 {
		throttled := s.Observe()
		if throttled.Sample.Known != 0 || throttled.Sample.ErrorCode != "THROTTLED" || throttled.Delta.Known != 0 {
			t.Fatal("stale sample relabelled fresh", throttled)
		}
	}
	if *calls != 1 {
		t.Fatal("native reads escaped bound", *calls)
	}
	*at = at.Add(5 * time.Second)
	second := s.Observe()
	if second.Delta.ElapsedNS != uint64(5*time.Second) || second.Delta.CPUTimeNS != 2000 || second.Delta.ReadBytes != 20 || second.Delta.WriteBytes != 50 || second.Delta.SystemBusyBasisPoints != 7500 || second.Delta.Reset != "" {
		t.Fatal(second)
	}
	if second.Delta.Known != first.Sample.Known || *calls != 2 {
		t.Fatal(second, *calls)
	}
	if second.Sample.At.Location() != time.UTC {
		t.Fatal("timestamp not UTC")
	}
}
func TestResourceSamplerPIDBirthReuseAndCounterResetAreExplicit(t *testing.T) {
	for _, which := range []string{"birth", "cpu", "io", "system", "pid", "unavailable", "backward-clock", "zero-clock"} {
		t.Run(which, func(t *testing.T) {
			a, b := resourceFixtureFrame(123, 1000, 50, 70), resourceFixtureFrame(123, 2000, 60, 80)
			switch which {
			case "birth":
				b.Birth = 124
			case "cpu":
				b.CPUTimeNS = 999
			case "io":
				b.WriteBytes = 69
			case "system":
				b.SystemIdleNS = 99999
			case "pid":
				b.PID = 8
			case "unavailable":
				b.Known = 0
				b.Birth = 0
				b.ErrorCode = "ACCESS_DENIED"
			}
			s, at, _ := resourceFixtureSampler([]flightrecorder.ResourceSample{a, b})
			s.Observe()
			*at = at.Add(5 * time.Second)
			if which == "backward-clock" {
				*at = at.Add(-10 * time.Second)
			}
			if which == "zero-clock" {
				s.interval = 0
				*at = at.Add(-5 * time.Second)
			}
			out := s.Observe()
			if out.Delta.Reset == "" {
				t.Fatal("reset silently attributed", which, out)
			}
			if which == "zero-clock" && (out.Delta.Reset != "MONOTONIC_CLOCK_RESET" || out.Delta.ElapsedNS != 0) {
				t.Fatal("zero native interval must remain unknown", out)
			}
			switch which {
			case "birth", "pid", "unavailable", "backward-clock", "zero-clock":
				if out.Delta.Known != 0 {
					t.Fatal("wrong generation/clock attributed", out)
				}
			case "cpu":
				if out.Delta.Known&flightrecorder.ResourceCPU != 0 {
					t.Fatal(out)
				}
			case "io":
				if out.Delta.Known&flightrecorder.ResourceIO != 0 {
					t.Fatal(out)
				}
			case "system":
				if out.Delta.Known&flightrecorder.ResourceSystemCPU != 0 {
					t.Fatal(out)
				}
			}
		})
	}
}
func TestResourceSamplerUnavailableGapDoesNotBecomeZeroCPU(t *testing.T) {
	s, at, _ := resourceFixtureSampler([]flightrecorder.ResourceSample{resourceFixtureFrame(1, 100, 1, 1), {PID: 7, Source: "TEST_SOURCE", ErrorCode: "ACCESS_DENIED"}, resourceFixtureFrame(1, 300, 3, 3), resourceFixtureFrame(1, 400, 4, 4)})
	s.Observe()
	*at = at.Add(5 * time.Second)
	if out := s.Observe(); out.Sample.Known != 0 || out.Sample.ErrorCode != "ACCESS_DENIED" {
		t.Fatal(out)
	}
	*at = at.Add(5 * time.Second)
	if out := s.Observe(); out.Delta.Known != 0 || out.Delta.Reset != "FIRST_SAMPLE" {
		t.Fatal("unknown gap presented as measured interval", out)
	}
	*at = at.Add(5 * time.Second)
	if out := s.Observe(); out.Delta.CPUTimeNS != 100 || out.Delta.ElapsedNS != uint64(5*time.Second) {
		t.Fatal(out)
	}
}
func TestResourceSamplerConcurrentCallsOnlyReadOncePerInterval(t *testing.T) {
	s, _, calls := resourceFixtureSampler([]flightrecorder.ResourceSample{resourceFixtureFrame(1, 1, 1, 1)})
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() { defer wg.Done(); s.Observe() }()
	}
	wg.Wait()
	if *calls != 1 {
		t.Fatal("concurrent read amplification", *calls)
	}
}
func TestResourceSamplerBirthJSONPreservesFullUint64(t *testing.T) {
	frame := resourceFixtureFrame(134402359570643174, 1, 1, 1)
	raw, e := json.Marshal(frame)
	if e != nil || !strings.Contains(string(raw), `"birth":"134402359570643174"`) {
		t.Fatal("birth precision unsafe", string(raw), e)
	}
}
func TestResourceSamplerOwnProcessCountersNoExternalSource(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native resource source unsupported")
	}
	s := NewResourceSampler(0)
	out := s.Observe()
	if out.Sample.PID != uint32(os.Getpid()) || out.Sample.Birth == 0 || out.Sample.Known&flightrecorder.ResourceCPU == 0 || out.Sample.Known&flightrecorder.ResourceWorkingSet == 0 || out.Sample.CostNS == 0 {
		t.Fatal("own process observation absent", out)
	}
	// Native reads only; this force bypasses the scheduled interval in the fixture.
	s.interval = 0
	for range 4 {
		// Windows may return identical monotonic timestamps for adjacent reads.
		// Await a real clock tick instead of inventing an interval or asking the
		// runtime to attribute CPU over zero elapsed time. Both bounds prevent
		// an indefinitely stalled native clock from hanging the fixture.
		deadline := time.Now().Add(time.Second)
		for polls := 0; !s.now().After(s.previous); polls++ {
			if polls >= 1000 || !time.Now().Before(deadline) {
				t.Fatal("native monotonic clock did not advance within the bounded wait")
			}
			time.Sleep(time.Millisecond)
		}
		next := s.Observe()
		if next.Sample.PID != out.Sample.PID || next.Sample.Birth != out.Sample.Birth || next.Sample.CPUTimeNS < out.Sample.CPUTimeNS || next.Delta.Reset != "" || next.Delta.ElapsedNS == 0 || next.Delta.Known&flightrecorder.ResourceCPU == 0 {
			t.Fatal("own monotonic source mismatch", next)
		}
		out = next
	}
	t.Logf("source=%s known=%d sample_cost_ns=%d fps=UNKNOWN", out.Sample.Source, out.Sample.Known, out.Sample.CostNS)
}
func BenchmarkResourceSamplerOwnProcess(b *testing.B) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		b.Skip("unsupported")
	}
	s := NewResourceSampler(0)
	s.interval = 0
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		out := s.Observe()
		if out.Sample.Known&flightrecorder.ResourceCPU == 0 {
			b.Fatal(out.Sample.ErrorCode)
		}
	}
}
func BenchmarkResourceSamplerThrottled(b *testing.B) {
	s := NewResourceSampler(0)
	s.Observe()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		s.Observe()
	}
}
func TestResourceSamplerFinalIdentityQueryFailureIsNotProcessExit(t *testing.T) {
	frame := resourceFixtureFrame(123, 100, 1, 1)
	for _, tc := range []struct {
		name   string
		birth  uint64
		exit   bool
		query  string
		native uint32
		want   string
	}{{"query-failure", 0, false, "RESOURCE_UNAVAILABLE", 6, "RESOURCE_UNAVAILABLE"}, {"access-denied", 0, false, "ACCESS_DENIED", 5, "ACCESS_DENIED"}, {"positive-exit", 123, true, "", 0, "PROCESS_EXITED"}, {"birth-changed", 124, false, "", 0, "PROCESS_GENERATION_CHANGED"}} {
		t.Run(tc.name, func(t *testing.T) {
			out := resourceFinishIdentity(frame, tc.birth, tc.exit, tc.query, tc.native)
			if out.Known != 0 || out.ErrorCode != tc.want || out.NativeCode != tc.native {
				t.Fatal(out)
			}
		})
	}
	if out := resourceFinishIdentity(frame, 123, false, "", 0); out.Known != frame.Known || out.ErrorCode != "OK" {
		t.Fatal(out)
	}
}
