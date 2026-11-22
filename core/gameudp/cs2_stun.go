package gameudp

import (
	"net/netip"
	"slices"
	"time"
)

const (
	cs2STUNInitialCutoff = 2
	cs2STUNDataCutoff    = 4
	cs2STUNRepeats       = 6
	cs2STUNFakeTTL       = 8
)

// SetCS2STUNEndpoint configures one endpoint for local-only runs of this engine.
func (e *Engine) SetCS2STUNEndpoint(endpoint netip.AddrPort) {
	e.SetCS2STUNScope(endpoint, nil)
}

// SetCS2STUNScope configures a fixed endpoint or server ports for an exact CS2
// executable. Existing flows cannot start a new first flight.
func (e *Engine) SetCS2STUNScope(endpoint netip.AddrPort, ports []uint16) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stunEndpoint != endpoint || !slices.Equal(e.stunPorts, ports) {
		e.stunEndpoint = endpoint
		e.stunPorts = slices.Clone(ports)
		e.generation++
	}
}

func (e *Engine) openSTUNFlow(k Key, now time.Time) (*Flow, error) {
	state := Evidence{
		Selection: "CS2_STUN_OTHER_ENDPOINT_DIRECT", Stage: Direct,
		Network: k.Network, PID: k.PID, Birth: k.Birth, Application: k.Application,
		Source: k.Source.String(), Destination: k.Destination.String(), Started: now,
		State: "PROBATION", Reason: "SUSTAINED_REPLY_NOT_OBSERVED",
	}
	selection := ""
	switch {
	case k.Destination == e.stunEndpoint:
		selection = "CS2_STUN_ENDPOINT"
	case slices.Contains(e.stunPorts, k.Destination.Port()):
		selection = "CS2_STUN_SERVER_PORT"
	}
	var payload []byte
	if selection != "" {
		var err error
		payload, err = STUNPayload()
		if err != nil {
			return nil, err
		}
		state.Selection = selection
		state.Stage = Local
		state.Variant = Variant{ID: "stun-binding-ttl8-k6-n2-d4", Repeats: cs2STUNRepeats, Cutoff: cs2STUNInitialCutoff, Size: len(payload), First: payload[0]}
		state.FakeTTL = cs2STUNFakeTTL
	}
	e.next++
	state.ID = e.next
	f := &Flow{engine: e, key: k, generation: e.generation, payload: payload, last: now, stunOnly: true, e: state}
	e.flows[state.ID] = f
	return f, nil
}

func isCS2Data(datagram []byte) bool {
	return len(datagram) >= 7 && datagram[0]&0x80 != 0 &&
		!(datagram[0] == 0xff && datagram[1] == 0xff && datagram[2] == 0xff && datagram[3] == 0xff)
}
