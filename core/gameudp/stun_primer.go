package gameudp

import "time"

// SetSTUNAuto enables the bounded first-flight strategy measured in Build 687.
// The service scopes opt-in to an exact game image. Existing flows retain
// their selection, and a mode change cannot restart their packet cutoff.
func (e *Engine) SetSTUNAuto(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stunAuto != enabled {
		e.stunAuto = enabled
		e.generation++
	}
}

func (e *Engine) openSTUN(k Key, now time.Time) (*Flow, error) {
	// A measured direct endpoint wins over the experiment for an unknown peer.
	row := e.learning[endpointKey(k.Network, k.Application, k.Destination.String())]
	if row.Confirmed && row.Stage == Direct && now.Before(row.Expires) {
		return e.addFlow(k, now, Direct, "CONFIRMED_DIRECT_ENDPOINT", Variant{}, nil), nil
	}
	payload, err := STUNPayload()
	if err != nil {
		return nil, err
	}
	v := Variant{ID: "stun-binding-ttl8-k6-n2-d4", Repeats: 6, Cutoff: 2, Size: len(payload), First: payload[0]}
	f := e.addFlow(k, now, Local, "STUN687_FIRST_FLIGHT", v, payload)
	f.stunPrimer, f.e.FakeTTL = true, 8
	return f, nil
}
