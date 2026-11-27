package flightrecorder

import (
	"github.com/buzzmean/veliq/core/clubhealth"
	"time"
)

const (
	QueueCapacity  = 128
	RingCapacity   = 512
	SegmentCount   = 16
	SegmentBytes   = 16 << 10
	MaxLineBytes   = 4096
	MaxHeaderBytes = 1024
	Retention      = 2 * time.Hour
	RemoteBudget   = 12
)

type ContextGaps struct {
	Dropped             uint64 `json:"dropped"`
	UnpersistedSegments uint64 `json:"unpersisted_segments"`
	WriteFailures       uint64 `json:"write_failures"`
	WriteThrottled      uint64 `json:"write_throttled"`
}
type Header struct {
	Gaps       ContextGaps `json:"gaps,omitzero"`
	Schema     int         `json:"schema"`
	PC         string      `json:"pc"`
	Version    string      `json:"version"`
	Source     string      `json:"source"`
	Session    string      `json:"session"`
	ServicePID uint32      `json:"service_pid"`
}
type Frame struct {
	Marker     string                `json:"marker,omitempty"`
	State      RuntimeState          `json:"state,omitzero"`
	Sequence   uint64                `json:"sequence"`
	ObservedAt time.Time             `json:"observed_at"`
	ElapsedNS  uint64                `json:"elapsed_ns"`
	Fact       clubhealth.Diagnostic `json:"fact,omitzero"`
	Resource   ResourceSample        `json:"resource,omitzero"`
	Runtime    RuntimeSample         `json:"runtime,omitzero"`
	Summary    Summary               `json:"summary,omitzero"`
}
type Entry struct {
	Header Header `json:"header"`
	Frame  Frame  `json:"frame"`
}
type Storage struct {
	Read  func(slot int) ([]byte, error)
	Write func(slot int, raw []byte) error
}
type Status struct {
	Schema                int                   `json:"schema"`
	Coverage              string                `json:"coverage"`
	Cause                 string                `json:"cause"`
	StoredFrames          uint64                `json:"stored_frames"`
	Dropped               uint64                `json:"dropped"`
	Invalid               uint64                `json:"invalid"`
	CorruptSegments       uint64                `json:"corrupt_segments"`
	PreviousTailUncertain bool                  `json:"previous_tail_uncertain"`
	WriteAttemptBytes     uint64                `json:"write_attempt_bytes"`
	WriteThrottled        uint64                `json:"write_throttled"`
	ShutdownWrites        uint64                `json:"shutdown_writes"`
	WriteFailures         uint64                `json:"write_failures"`
	UnpersistedSegments   uint64                `json:"unpersisted_segments"`
	PendingBytes          int                   `json:"pending_bytes"`
	WriteBytes            uint64                `json:"write_bytes"`
	WriteNS               uint64                `json:"write_ns"`
	LastDurableAt         time.Time             `json:"last_durable_at,omitzero"`
	RemotePromoted        uint64                `json:"remote_promoted"`
	HistoricalIncidents   uint64                `json:"historical_incidents_without_temporal_context"`
	RemoteSuppressed      uint64                `json:"remote_suppressed"`
	PromotionQueueDropped uint64                `json:"promotion_queue_dropped"`
	PostWindowUntil       time.Time             `json:"post_window_until,omitzero"`
	Closed                bool                  `json:"closed"`
	LastResource          ResourceSample        `json:"last_resource,omitzero"`
	LastSummary           Summary               `json:"last_summary,omitzero"`
	LastState             RuntimeState          `json:"last_state,omitzero"`
	LastFact              clubhealth.Diagnostic `json:"last_fact,omitzero"`
	WindowFrames          int                   `json:"window_frames"`
	OldestObservedAt      time.Time             `json:"oldest_observed_at,omitzero"`
	WindowEvictions       uint64                `json:"window_evictions"`
}

type StateKnown uint16

const (
	StateCapture StateKnown = 1 << iota
	StateAutomatic
	StateActivation
	StateIPC
)

type RuntimeState struct {
	Known               StateKnown `json:"known"`
	CaptureTrafficKnown bool       `json:"capture_traffic_known"`
	CaptureRXBytes      uint64     `json:"capture_rx_bytes"`
	CaptureTXBytes      uint64     `json:"capture_tx_bytes"`
	CaptureEnabled      bool       `json:"capture_enabled"`
	Automatic           bool       `json:"automatic"`
	ActivationState     string     `json:"activation_state"`
	IPCInFlight         uint32     `json:"ipc_in_flight"`
	DiagnosticQueue     uint32     `json:"diagnostic_queue"`
	DiagnosticClubQueue uint32     `json:"diagnostic_club_queue"`
}
type Promotion struct {
	At       time.Time
	Summary  Summary
	Incident string
	PID      uint32
	Birth    uint64
}
