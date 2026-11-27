package windowsplatform

import (
	"math"
	"os"
	"sync"
	"time"

	"github.com/buzzmean/veliq/core/flightrecorder"
)

// ResourceSampleInterval keeps diagnostic observation out of packet/flow paths.
const ResourceSampleInterval = 5 * time.Second

// ResourceDelta describes counter changes over a monotonic interval. CPUTimeNS /
// ElapsedNS measures CPU cores consumed, not FPS or a percentage of the whole PC.
// Known contains only ResourceCPU, ResourceIO and ResourceSystemCPU bits.
type ResourceDelta struct {
	ElapsedNS             uint64                       `json:"elapsed_ns"`
	CPUTimeNS             uint64                       `json:"cpu_time_ns"`
	ReadBytes             uint64                       `json:"read_bytes"`
	WriteBytes            uint64                       `json:"write_bytes"`
	SystemBusyBasisPoints uint32                       `json:"system_busy_basis_points"`
	Known                 flightrecorder.ResourceKnown `json:"known"`
	Reset                 string                       `json:"reset,omitempty"`
}

type ResourceObservation struct {
	Sample flightrecorder.ResourceSample `json:"sample"`
	Delta  ResourceDelta                 `json:"delta"`
}

// ResourceSampler observes one already-known PID, never discovers applications,
// spawns processes, opens network connections or changes process state. Storage
// is constant-size; a generation change always resets deltas.
type ResourceSampler struct {
	mu        sync.Mutex
	pid       uint32
	read      func(uint32) flightrecorder.ResourceSample
	now       func() time.Time
	interval  time.Duration
	attempted time.Time
	previous  time.Time
	sample    flightrecorder.ResourceSample
	delta     ResourceDelta
}

// NewResourceSampler selects the current process when pid is zero. Windows can
// observe other existing PIDs with query-only handles; other platforms explicitly
// report unsupported observations rather than inventing another process's data.
func NewResourceSampler(pid uint32) *ResourceSampler {
	if pid == 0 {
		pid = uint32(os.Getpid())
	}
	return &ResourceSampler{pid: pid, read: readNativeResources, now: time.Now, interval: ResourceSampleInterval}
}

func (s *ResourceSampler) Sample() flightrecorder.ResourceSample { return s.Observe().Sample }

// Observe returns raw cumulative counters and their deltas atomically. The UTC
// timestamp is for correlation; deltas use private Go monotonic timestamps.
func (s *ResourceSampler) Observe() ResourceObservation {
	started := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	at := s.now()
	if !s.attempted.IsZero() && at.Sub(s.attempted) >= 0 && at.Sub(s.attempted) < s.interval {
		return ResourceObservation{Sample: flightrecorder.ResourceSample{At: at.UTC(), PID: s.pid, Birth: s.sample.Birth, Source: s.sample.Source, ErrorCode: "THROTTLED", CostNS: positiveResourceCost(started)}, Delta: ResourceDelta{Reset: "THROTTLED"}}
	}
	s.attempted = at
	frame := s.read(s.pid)
	frame.At = at.UTC()
	d := ResourceDelta{Reset: "FIRST_SAMPLE"}
	if frame.PID != s.pid || frame.Birth == 0 {
		frame.Known = 0
		if frame.ErrorCode == "" || frame.ErrorCode == "OK" {
			frame.ErrorCode = "RESOURCE_UNAVAILABLE"
		}
		d.Reset = "RESOURCE_UNAVAILABLE"
		s.previous = time.Time{}
	} else if !s.previous.IsZero() {
		elapsed := at.Sub(s.previous)
		switch {
		case frame.Birth != s.sample.Birth:
			d.Reset = "PROCESS_GENERATION_CHANGED"
			frame.ErrorCode = "PROCESS_GENERATION_CHANGED"
		case elapsed <= 0:
			d.Reset = "MONOTONIC_CLOCK_RESET"
		default:
			d = resourceCounterDelta(s.sample, frame, uint64(elapsed))
		}
	}
	frame.CostNS = positiveResourceCost(started)
	if frame.Known != 0 && frame.PID == s.pid && frame.Birth != 0 {
		s.previous = at
	} else {
		s.previous = time.Time{}
	}
	s.sample, s.delta = frame, d
	return ResourceObservation{Sample: frame, Delta: d}
}

func positiveResourceCost(start time.Time) uint64 {
	return uint64(max(1, time.Since(start).Nanoseconds()))
}

// Delta is a copy of the most recent real observation's delta. Prefer Observe
// when concurrent callers need an atomic sample/delta pair.
func (s *ResourceSampler) Delta() ResourceDelta { s.mu.Lock(); defer s.mu.Unlock(); return s.delta }

func resourceCounterDelta(a, b flightrecorder.ResourceSample, elapsed uint64) ResourceDelta {
	d := ResourceDelta{ElapsedNS: elapsed}
	both := a.Known & b.Known
	if both&flightrecorder.ResourceCPU != 0 {
		if b.CPUTimeNS >= a.CPUTimeNS {
			d.CPUTimeNS = b.CPUTimeNS - a.CPUTimeNS
			d.Known |= flightrecorder.ResourceCPU
		} else {
			d.Reset = "COUNTER_REGRESSION"
		}
	}
	if both&flightrecorder.ResourceIO != 0 {
		if b.ReadBytes >= a.ReadBytes && b.WriteBytes >= a.WriteBytes {
			d.ReadBytes = b.ReadBytes - a.ReadBytes
			d.WriteBytes = b.WriteBytes - a.WriteBytes
			d.Known |= flightrecorder.ResourceIO
		} else {
			d.Reset = "COUNTER_REGRESSION"
		}
	}
	if both&flightrecorder.ResourceSystemCPU != 0 {
		if b.SystemIdleNS >= a.SystemIdleNS && b.SystemKernelNS >= a.SystemKernelNS && b.SystemUserNS >= a.SystemUserNS {
			idle, kernel, user := b.SystemIdleNS-a.SystemIdleNS, b.SystemKernelNS-a.SystemKernelNS, b.SystemUserNS-a.SystemUserNS
			// GetSystemTimes kernel includes idle. Guard addition and representation.
			if kernel <= math.MaxUint64-user && kernel+user > 0 && idle <= kernel+user {
				total := kernel + user
				d.SystemBusyBasisPoints = uint32(float64(total-idle) / float64(total) * 10000)
				d.Known |= flightrecorder.ResourceSystemCPU
			} else {
				d.Reset = "COUNTER_REGRESSION"
			}
		} else {
			d.Reset = "COUNTER_REGRESSION"
		}
	}
	return d
}

// resourceFinishIdentity separates observed exit from a failed metadata query.
// A failed query cannot be promoted into evidence that a process terminated.
func resourceFinishIdentity(frame flightrecorder.ResourceSample, birth uint64, exited bool, queryError string, native uint32) flightrecorder.ResourceSample {
	switch {
	case queryError != "":
		frame.Known = 0
		frame.ErrorCode = queryError
		frame.NativeCode = native
	case exited:
		frame.Known = 0
		frame.ErrorCode = "PROCESS_EXITED"
	case birth != frame.Birth:
		frame.Known = 0
		frame.ErrorCode = "PROCESS_GENERATION_CHANGED"
	}
	return frame
}
