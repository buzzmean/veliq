// Package flightrecorder keeps bounded metadata context; it never records
// packets, URLs, command lines, account secrets or a causal verdict.
package flightrecorder

import "time"

type ResourceKnown uint32

const (
	ResourceCPU ResourceKnown = 1 << iota
	ResourceWorkingSet
	ResourcePrivate
	ResourceIO
	ResourceHandles
	ResourceThreads
	ResourceSystemCPU
)

type ResourceSample struct {
	At              time.Time     `json:"at"`
	PID             uint32        `json:"pid"`
	Birth           uint64        `json:"birth,string"`
	Source          string        `json:"source"`
	CPUTimeNS       uint64        `json:"cpu_time_ns"`
	WorkingSetBytes uint64        `json:"working_set_bytes"`
	PrivateBytes    uint64        `json:"private_bytes"`
	ReadBytes       uint64        `json:"read_bytes"`
	WriteBytes      uint64        `json:"write_bytes"`
	Handles         uint32        `json:"handles"`
	Threads         uint32        `json:"threads"`
	SystemIdleNS    uint64        `json:"system_idle_ns"`
	SystemKernelNS  uint64        `json:"system_kernel_ns"`
	SystemUserNS    uint64        `json:"system_user_ns"`
	Known           ResourceKnown `json:"known"`
	CostNS          uint64        `json:"cost_ns"`
	ErrorCode       string        `json:"error_code"`
	NativeCode      uint32        `json:"native_code,omitempty"`
}

type RuntimeSample struct {
	GCKnown        bool   `json:"gc_known"`
	HeapAllocBytes uint64 `json:"heap_alloc_bytes"`
	HeapSysBytes   uint64 `json:"heap_sys_bytes"`
	AllocBytes     uint64 `json:"alloc_bytes"`
	PauseTotalNS   uint64 `json:"pause_total_ns"`
	NumGC          uint32 `json:"num_gc"`
	Goroutines     uint32 `json:"goroutines"`
	CostNS         uint64 `json:"cost_ns"`
}
