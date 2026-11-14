package clientservice

import (
	"context"
	"net/netip"
	"time"

	"github.com/buzzmean/neexitlag/core/routing"
)

// This is session/open evidence, not echo quality or a game-packet delivery claim.
// Only an already configured relay and its configured probe destination are used.
type RelayTransportReadiness struct {
	RelayID   string    `json:"relay_id"`
	Connected bool      `json:"connected"`
	FlowOpen  bool      `json:"flow_open"`
	CheckedAt time.Time `json:"checked_at"`
	Reason    string    `json:"reason,omitempty"`
	OpenError string    `json:"open_error,omitempty"`
}
type acceptanceRelay interface {
	Done() <-chan struct{}
	OpenDatagram(context.Context, netip.AddrPort) (routing.Datagram, error)
}
type acceptanceRelaySource struct {
	session    acceptanceRelay
	target     netip.AddrPort
	generation uint64
	address    string
}

func sessionConnected(session acceptanceRelay) bool {
	if session == nil {
		return false
	}
	if pooled, ok := session.(interface{ Healthy() bool }); ok {
		return pooled.Healthy()
	}
	select {
	case <-session.Done():
		return false
	default:
		return true
	}
}
func (c *Controller) acceptanceReadiness(ctx context.Context, id string) Snapshot {
	evidence := RelayTransportReadiness{RelayID: id, Reason: "relay_session_unavailable"}
	c.mu.Lock()
	source, known := c.acceptanceRelays[id]
	c.mu.Unlock()
	if known && sessionConnected(source.session) {
		evidence.Connected = true
		if !source.target.IsValid() {
			evidence.Reason = "configured_probe_target_unavailable"
		} else {
			attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
			open := source.session.OpenDatagram
			if probe, ok := source.session.(interface {
				OpenProbeDatagram(context.Context, netip.AddrPort) (routing.Datagram, error)
			}); ok {
				open = probe.OpenProbeDatagram
			}
			flow, err := open(attempt, source.target)
			cancel()
			if err != nil {
				evidence.Reason = "relay_flow_open_failed"
				evidence.OpenError = err.Error()
			} else if flow == nil {
				evidence.Reason = "relay_flow_open_unavailable"
			} else {
				closeErr := flow.Close()
				evidence.FlowOpen = closeErr == nil
				evidence.Reason = ""
				if closeErr != nil {
					evidence.Reason = "relay_flow_close_failed"
				}
			}
		}
	}
	// An ACK from a retired session must not certify the current replacement.
	c.mu.Lock()
	current, currentKnown := c.acceptanceRelays[id]
	c.mu.Unlock()
	if known && (!currentKnown || current.generation != source.generation || !sessionConnected(source.session)) {
		evidence.Connected = false
		evidence.FlowOpen = false
		evidence.Reason = "relay_session_closed_or_replaced"
	}
	evidence.CheckedAt = time.Now().UTC()
	snapshot := c.Snapshot()
	snapshot.RelayTransport = &evidence
	return snapshot
}
