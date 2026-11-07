package gameudp

import (
	"errors"
	"fmt"
	"github.com/buzzmean/neexitlag/core/routing"
	"net/netip"
	"time"
)

// Primer is an explicit endpoint-scoped experiment, never an automatic ladder
// candidate. Short TTL applies only to decoys; it is not a guarantee of their
// path or a claim that a particular ISP ignores or accepts them.
type Primer struct {
	Kind       string `json:"kind,omitempty"`
	DataCutoff int    `json:"data_cutoff,omitempty"`
	Endpoint   string `json:"endpoint"`
	TTL        uint8  `json:"ttl"`
	Repeats    int    `json:"repeats"`
	Cutoff     int    `json:"cutoff"`
}

func (p Primer) Validate() error {
	if p.Kind != "" && p.Kind != "quic-initial" && p.Kind != "stun" || p.DataCutoff < 0 || p.DataCutoff > 4 || p.Kind != "stun" && p.DataCutoff != 0 || p.Kind == "stun" && p.Cutoff > 2 {
		return errors.New("GAME_UDP_PRIMER_INVALID")
	}
	d, err := netip.ParseAddrPort(p.Endpoint)
	if err != nil || !d.Addr().Is4() || routing.LocalDestination(d.Addr()) || d.Port() < 1024 || d.String() != p.Endpoint || p.TTL < 1 || p.TTL > 16 || p.Repeats < 1 || p.Repeats > MaxRepeats || p.Cutoff < 1 || p.Cutoff > MaxCutoff {
		return errors.New("GAME_UDP_PRIMER_INVALID")
	}
	return nil
}
func copyPrimer(p *Primer) *Primer {
	if p == nil {
		return nil
	}
	q := *p
	return &q
}
func (e *Engine) SetPrimer(p *Primer) error {
	if p != nil {
		if err := p.Validate(); err != nil {
			return err
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if p != nil && !e.localOnly {
		return errors.New("GAME_UDP_PRIMER_REQUIRES_LOCAL_ONLY")
	}
	if (p == nil) != (e.primer == nil) || p != nil && *p != *e.primer {
		e.generation++
	}
	e.primer = copyPrimer(p)
	return nil
}
func (e *Engine) openPrimer(k Key, now time.Time) (*Flow, error) {
	if !e.localOnly {
		return nil, errors.New("GAME_UDP_PRIMER_REQUIRES_LOCAL_ONLY")
	}
	v := Variant{}
	stage := Direct
	selection := "PRIMER_OTHER_ENDPOINT_DIRECT"
	var payload []byte
	var ttl uint8
	if k.Destination.String() == e.primer.Endpoint {
		var err error
		if e.primer.Kind == "stun" {
			payload, err = STUNPayload()
		} else {
			payload, err = InitialPayload()
		}
		if err != nil {
			return nil, err
		}
		ttl = e.primer.TTL
		v = Variant{ID: fmt.Sprintf("quic-initial-v1-ttl%d-k%d-n%d", ttl, e.primer.Repeats, e.primer.Cutoff), Repeats: e.primer.Repeats, Cutoff: e.primer.Cutoff, Size: len(payload), First: payload[0]}
		if e.primer.Kind == "stun" {
			v.ID = fmt.Sprintf("stun-binding-ttl%d-k%d-n%d-d%d", ttl, e.primer.Repeats, e.primer.Cutoff, e.primer.DataCutoff)
		}
		stage = Local
		selection = "EXPLICIT_ENDPOINT_INITIAL_PRIMER"
	}
	e.next++
	f := &Flow{engine: e, key: k, generation: e.generation, payload: payload, last: now, primer: true, e: Evidence{Selection: selection, Stage: stage, ID: e.next, Network: k.Network, PID: k.PID, Birth: k.Birth, Application: k.Application, Source: k.Source.String(), Destination: k.Destination.String(), Variant: v, FakeTTL: ttl, Started: now, State: "PROBATION", Reason: "SUSTAINED_REPLY_NOT_OBSERVED"}}
	if e.primer.Kind == "stun" && stage == Local {
		f.primerDataCutoff = e.primer.DataCutoff
	}
	e.flows[f.e.ID] = f
	return f, nil
}
