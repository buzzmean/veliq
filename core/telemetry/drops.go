// Package telemetry classifies observable local failures, never inferring wire loss.
package telemetry

import (
	"errors"
	"sync/atomic"
)

// ErrCapacity describes bounded local admission, never remote path quality.
var ErrCapacity = errors.New("local relay capacity exhausted")
var ErrIsolatedSession = errors.New("probe session closed while relay has healthy peers")

type Category int

const (
	CaptureProcessing Category = iota
	CaptureQueue
	WorkerSaturation
	TransportQueue
	Decode
	UnknownFlow
	SocketSend
	ReplyReinjection
	Policy
	CaptureReceiveErrors
	LastCategory
)

var names = []string{"capture_processing_drops", "capture_queue_drops", "worker_saturation_drops", "transport_queue_drops", "quic_decode_drops", "unknown_flow_drops", "relay_socket_send_drops", "reply_reinjection_failures", "policy_drops", "capture_receive_errors"}

type Counters struct {
	values   [LastCategory]atomic.Uint64
	attempts [LastCategory]atomic.Uint64
}
type Metric struct {
	Count     uint64   `json:"count"`
	Attempts  uint64   `json:"attempts"`
	Fraction  *float64 `json:"fraction,omitempty"`
	Available bool     `json:"available"`
	Unit      string   `json:"unit"`
}

func (c *Counters) Attempt(category Category) { c.attempts[category].Add(1) }
func (c *Counters) Drop(category Category)    { c.values[category].Add(1) }
func (c *Counters) Snapshot() map[string]Metric {
	out := map[string]Metric{}
	for i, name := range names {
		m := Metric{Count: c.values[i].Load(), Attempts: c.attempts[i].Load(), Available: true, Unit: "packets"}
		if i == int(CaptureReceiveErrors) {
			m.Unit = "events"
		}
		if m.Attempts > 0 && m.Count <= m.Attempts {
			fraction := float64(m.Count) / float64(m.Attempts)
			m.Fraction = &fraction
		}
		out[name] = m
	}
	return out
}
func (c *Counters) Total() uint64 {
	var n uint64
	for i := Category(0); i < CaptureReceiveErrors; i++ {
		n += c.values[i].Load()
	}
	return n
}

type LocalError struct {
	Category Category
	Cause    error
}

func (e *LocalError) Error() string { return e.Cause.Error() }
func (e *LocalError) Unwrap() error { return e.Cause }
func IsLocal(err error) bool {
	var local *LocalError
	return errors.As(err, &local) || errors.Is(err, ErrCapacity) || errors.Is(err, ErrIsolatedSession)
}

// TryEnqueue counts only a real local overflow; it never creates a network-loss sample.
func (c *Counters) TryEnqueue(queue chan []byte, payload []byte, category Category) bool {
	c.Attempt(category)
	select {
	case queue <- payload:
		return true
	default:
		c.Drop(category)
		return false
	}
}
