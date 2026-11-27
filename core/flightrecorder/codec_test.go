package flightrecorder

import (
	"strings"
	"testing"
	"time"
)

func sampleFixture() ResourceSample {
	return ResourceSample{At: time.Now().UTC(), PID: 42, Birth: 1234, Source: "FIXTURE", ErrorCode: "OK", Known: ResourceCPU | ResourceWorkingSet | ResourceIO, CPUTimeNS: 1_000_000, WorkingSetBytes: 10 << 20, ReadBytes: 1000, WriteBytes: 2000}
}
func TestSummaryCodecKnownUnknownAndSaturation(t *testing.T) {
	before := sampleFixture()
	after := before
	after.CPUTimeNS += 3_000_000
	after.ReadBytes += 4096
	after.WriteBytes += 2048
	s := Summarize(before, after, RuntimeSample{GCKnown: true}, RuntimeSample{GCKnown: true, PauseTotalNS: 1000}, uint64(5*time.Second))
	if s.CPUTimeUS != 3000 || s.ReadKiB != 4 || s.WriteKiB != 2 || s.SpanMS != 5000 || s.GCPauseUS != 1 {
		t.Fatal(s)
	}
	for _, flags := range []uint16{0, ContextPre, ContextPost, Heartbeat} {
		v := s
		v.Flags |= flags
		raw := v.Encode()
		decoded, ok := Decode(raw)
		if !ok || len(raw) != 62 || decoded != v {
			t.Fatal(raw, decoded)
		}
	}
	unknown := Summary{}
	if v, ok := Decode(unknown.Encode()); !ok || v.Flags != 0 {
		t.Fatal("unknown became measured zero")
	}
	after.CPUTimeNS = 1<<64 - 1
	after.WorkingSetBytes = 1<<64 - 1
	s = Summarize(before, after, RuntimeSample{}, RuntimeSample{}, uint64(5*time.Second))
	if s.Flags&Saturated == 0 || s.Flags&KnownGC != 0 {
		t.Fatal(s)
	}
}
func TestSummaryRejectsNonCanonicalAndInconsistentMetadata(t *testing.T) {
	s := Summary{Flags: KnownCPU | KnownInterval, SpanMS: 5000, CPUTimeUS: 10}
	raw := s.Encode()
	for _, bad := range []string{raw + "_EXTRA", strings.ToLower(raw), "FR2" + raw[3:], strings.Replace(raw, "0001", "ZZZZ", 1), Summary{Flags: 0x8000}.Encode(), Summary{CPUTimeUS: 1}.Encode(), Summary{Flags: CounterReset | KnownCPU, CPUTimeUS: 1}.Encode()} {
		if _, ok := Decode(bad); ok {
			t.Fatalf("accepted %s", bad)
		}
	}
}
func TestSummaryResetAndUnavailableAreNotHealthyZeros(t *testing.T) {
	before := sampleFixture()
	for _, change := range []func(*ResourceSample){func(s *ResourceSample) { s.Birth++ }, func(s *ResourceSample) { s.PID++ }, func(s *ResourceSample) { s.CPUTimeNS-- }, func(s *ResourceSample) { s.ErrorCode = "THROTTLED"; s.Known = 0 }, func(s *ResourceSample) { s.ErrorCode = "ACCESS_DENIED"; s.Known = 0 }, func(s *ResourceSample) { s.Birth = 0 }} {
		after := before
		change(&after)
		s := Summarize(before, after, RuntimeSample{}, RuntimeSample{}, uint64(time.Second))
		if s.Flags&CounterReset == 0 || s.Flags&(KnownCPU|KnownIO|KnownGC) != 0 {
			t.Fatal(s)
		}
		if after.ErrorCode != "OK" && s.Flags&VerifiedProcess != 0 {
			t.Fatal("stale/failed sample called verified")
		}
	}
	after := before
	s := Summarize(before, after, RuntimeSample{}, RuntimeSample{}, uint64(time.Second))
	if s.Flags&KnownCPU == 0 || s.CPUTimeUS != 0 || s.Flags&KnownGC != 0 {
		t.Fatal("real zero or unknown GC misclassified", s)
	}
}
func BenchmarkEncodeSummary(b *testing.B) {
	s := Summary{Flags: KnownCPU | KnownInterval | KnownWorkingSet, SpanMS: 5000, CPUTimeUS: 12500, WorkingSetKiB: 200000}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = s.Encode()
	}
}
