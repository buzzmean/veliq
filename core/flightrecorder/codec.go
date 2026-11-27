package flightrecorder

import (
	"fmt"
	"strconv"
	"strings"
)

// Summary is a bounded measurement, never an attribution of fault or FPS.
// Units are explicit, and zero is a measurement only when its Known flag is set.
type Summary struct {
	Flags         uint16 `json:"flags"`
	SpanMS        uint32 `json:"span_ms"`
	CPUTimeUS     uint32 `json:"cpu_time_us"`
	WorkingSetKiB uint32 `json:"working_set_kib"`
	ReadKiB       uint32 `json:"read_kib"`
	WriteKiB      uint32 `json:"write_kib"`
	GCPauseUS     uint32 `json:"gc_pause_us"`
}

const (
	KnownCPU uint16 = 1 << iota
	KnownWorkingSet
	KnownIO
	KnownGC
	KnownInterval
	VerifiedProcess
	CounterReset
	Saturated
	ContextPre
	ContextPost
	Heartbeat
)
const validFlags = KnownCPU | KnownWorkingSet | KnownIO | KnownGC | KnownInterval | VerifiedProcess | CounterReset | Saturated | ContextPre | ContextPost | Heartbeat

// Encode uses only old762's existing 64-character Operation alphabet. No new
// optional Diagnostic field, signed audience projection or native-code reuse.
func (s Summary) Encode() string {
	return fmt.Sprintf("FR1_%04X_%08X_%08X_%08X_%08X_%08X_%08X", s.Flags, s.SpanMS, s.CPUTimeUS, s.WorkingSetKiB, s.ReadKiB, s.WriteKiB, s.GCPauseUS)
}
func Decode(operation string) (Summary, bool) {
	var s Summary
	if len(operation) != 62 || strings.ToUpper(operation) != operation {
		return s, false
	}
	a := strings.Split(operation, "_")
	if len(a) != 8 || a[0] != "FR1" || len(a[1]) != 4 {
		return s, false
	}
	v, e := strconv.ParseUint(a[1], 16, 16)
	if e != nil || uint16(v)&^validFlags != 0 {
		return s, false
	}
	s.Flags = uint16(v)
	slots := []*uint32{&s.SpanMS, &s.CPUTimeUS, &s.WorkingSetKiB, &s.ReadKiB, &s.WriteKiB, &s.GCPauseUS}
	for i, p := range slots {
		if len(a[i+2]) != 8 {
			return Summary{}, false
		}
		v, e = strconv.ParseUint(a[i+2], 16, 32)
		if e != nil {
			return Summary{}, false
		}
		*p = uint32(v)
	}
	if s.Flags&KnownInterval == 0 && s.SpanMS != 0 || s.Flags&KnownCPU == 0 && s.CPUTimeUS != 0 || s.Flags&KnownWorkingSet == 0 && s.WorkingSetKiB != 0 || s.Flags&KnownIO == 0 && (s.ReadKiB != 0 || s.WriteKiB != 0) || s.Flags&KnownGC == 0 && s.GCPauseUS != 0 {
		return Summary{}, false
	}
	if s.Flags&ContextPre != 0 && s.Flags&ContextPost != 0 || s.Flags&Heartbeat != 0 && s.Flags&(ContextPre|ContextPost) != 0 {
		return Summary{}, false
	}
	if s.Flags&(KnownCPU|KnownIO|KnownGC) != 0 && s.Flags&KnownInterval == 0 {
		return Summary{}, false
	}
	if s.Flags&CounterReset != 0 && (s.Flags&(KnownCPU|KnownIO|KnownGC) != 0) {
		return Summary{}, false
	}
	return s, true
}
func bounded(v uint64, flags *uint16) uint32 {
	if v > 1<<32-1 {
		*flags |= Saturated
		return 1<<32 - 1
	}
	return uint32(v)
}

func Summarize(before, after ResourceSample, previous, current RuntimeSample, spanNS uint64) Summary {
	var s Summary
	if after.Known&ResourceWorkingSet != 0 {
		s.Flags |= KnownWorkingSet
		s.WorkingSetKiB = bounded(after.WorkingSetBytes/1024, &s.Flags)
	}
	if after.PID != 0 && after.Birth != 0 && after.Known != 0 && after.ErrorCode == "OK" {
		s.Flags |= VerifiedProcess
	}
	if spanNS == 0 || before.ErrorCode != "OK" || after.ErrorCode != "OK" || before.Birth == 0 || after.Birth == 0 || before.PID == 0 || before.PID != after.PID || before.Birth != after.Birth || before.Source != after.Source {
		s.Flags |= CounterReset
		return s
	}
	s.Flags |= KnownInterval
	s.SpanMS = bounded(spanNS/1_000_000, &s.Flags)
	if before.Known&after.Known&ResourceCPU != 0 {
		if after.CPUTimeNS < before.CPUTimeNS {
			s.Flags |= CounterReset
		} else {
			s.Flags |= KnownCPU
			s.CPUTimeUS = bounded((after.CPUTimeNS-before.CPUTimeNS)/1000, &s.Flags)
		}
	}
	if before.Known&after.Known&ResourceIO != 0 {
		if after.ReadBytes < before.ReadBytes || after.WriteBytes < before.WriteBytes {
			s.Flags |= CounterReset
		} else {
			s.Flags |= KnownIO
			s.ReadKiB = bounded((after.ReadBytes-before.ReadBytes)/1024, &s.Flags)
			s.WriteKiB = bounded((after.WriteBytes-before.WriteBytes)/1024, &s.Flags)
		}
	}
	if previous.GCKnown && current.GCKnown && current.PauseTotalNS < previous.PauseTotalNS {
		s.Flags |= CounterReset
	} else if previous.GCKnown && current.GCKnown {
		s.Flags |= KnownGC
		s.GCPauseUS = bounded((current.PauseTotalNS-previous.PauseTotalNS)/1000, &s.Flags)
	}
	if s.Flags&CounterReset != 0 {
		s.Flags &^= KnownCPU | KnownIO | KnownGC
		s.CPUTimeUS, s.ReadKiB, s.WriteKiB, s.GCPauseUS = 0, 0, 0, 0
	}
	return s
}
