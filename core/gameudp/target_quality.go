package gameudp

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/buzzmean/neexitlag/core/optimizer"
)

const (
	targetQualityWindow  = 45 * time.Second
	targetQualityRounds  = 4
	targetQualitySamples = 20
)

const TargetQualityRelayReason = "RELAY_LOWEST_MEASURED_LOSS"

type TargetSample struct {
	Route      string        `json:"route"`
	Samples    int           `json:"samples"`
	RTT        time.Duration `json:"rtt_ns"`
	RTTP95     time.Duration `json:"rtt_p95_ns"`
	Loss       float64       `json:"loss"`
	ObservedAt time.Time     `json:"observed_at"`
}

type TargetQualityStatus struct {
	Destination netip.AddrPort `json:"destination"`
	State       string         `json:"state"`
	Relay       string         `json:"suggested_relay,omitempty"`
	Samples     []TargetSample `json:"samples,omitempty"`
}

type targetSeries struct {
	network, address string
	endpoint         netip.AddrPort
	rounds           []optimizer.RouteMeasurement
}

// TargetQuality consumes the authenticated configured echo observations. No
// probe is sent to an arbitrary game address, and packet directions alone
// never become RTT or loss measurements.
type TargetQuality struct {
	mu     sync.Mutex
	routes map[string]targetSeries
}

func (q *TargetQuality) HasTarget(network string, target netip.AddrPort) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if network == "" || !target.IsValid() {
		return false
	}
	for _, series := range q.routes {
		if series.network == network && series.endpoint == target {
			return true
		}
	}
	return false
}

func (q *TargetQuality) Observe(m optimizer.RouteMeasurement) {
	if !m.AuthenticatedTarget || m.Network == "" || !m.Target.IsValid() || m.RouteID == "" ||
		m.RouteID != optimizer.Direct && m.RouteAddress == "" {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.routes == nil {
		q.routes = make(map[string]targetSeries)
	}
	series, exists := q.routes[m.RouteID]
	if !exists && len(q.routes) >= 64 {
		for id, other := range q.routes {
			if len(other.rounds) == 0 || m.ObservedAt.Sub(other.rounds[len(other.rounds)-1].ObservedAt) > targetQualityWindow {
				delete(q.routes, id)
			}
		}
		if len(q.routes) >= 64 {
			return
		}
	}
	if series.network != m.Network || series.endpoint != m.Target || series.address != m.RouteAddress {
		series = targetSeries{network: m.Network, endpoint: m.Target, address: m.RouteAddress}
	}
	if n := len(series.rounds); n > 0 {
		if !m.ObservedAt.After(series.rounds[n-1].ObservedAt) {
			return
		}
		if n >= targetQualityRounds {
			series.rounds = series.rounds[1:]
		}
	}
	series.rounds = append(series.rounds, m)
	q.routes[m.RouteID] = series
}

func targetSample(series targetSeries, route string, now time.Time) (TargetSample, bool) {
	if len(series.rounds) < targetQualityRounds {
		return TargetSample{}, false
	}
	var delays []time.Duration
	var sent, missed int
	out := TargetSample{Route: route, ObservedAt: series.rounds[len(series.rounds)-1].ObservedAt}
	for _, round := range series.rounds {
		if round.ObservedAt.After(now) || now.Sub(round.ObservedAt) > targetQualityWindow ||
			round.TransportError != "" || len(round.Probes) == 0 {
			return TargetSample{}, false
		}
		before := len(delays)
		for _, probe := range round.Probes {
			switch {
			case probe.Outcome == optimizer.Reply && probe.RTT > 0:
				delays = append(delays, probe.RTT)
			case probe.Outcome == optimizer.Timeout:
				missed++
			default:
				return TargetSample{}, false
			}
			sent++
		}
		if len(delays) == before {
			return TargetSample{}, false
		}
	}
	if sent < targetQualitySamples || len(delays) < targetQualitySamples/2 {
		return TargetSample{}, false
	}
	sort.Slice(delays, func(i, j int) bool { return delays[i] < delays[j] })
	out.Samples, out.RTT, out.Loss = sent, delays[len(delays)/2], float64(missed)/float64(sent)
	out.RTTP95 = delays[(95*len(delays)+99)/100-1]
	return out, true
}

// Compare ranks configured relays for an exact destination, by loss and then
// tail latency. DIRECT is diagnostic; it may have no replies. A suggestion
// applies only to a new flow whose ladder already selected relay.
func (q *TargetQuality) Compare(network string, target netip.AddrPort, configured map[string]string, now time.Time) TargetQualityStatus {
	out := TargetQualityStatus{Destination: target, State: "UNKNOWN_NO_AUTHENTICATED_EXACT_TARGET"}
	if network == "" || !target.IsValid() {
		return out
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	directSeries := q.routes[optimizer.Direct]
	if directSeries.network == network && directSeries.endpoint == target {
		out.State = "UNKNOWN_INSUFFICIENT_RELAY_SAMPLES"
		if direct, ok := targetSample(directSeries, optimizer.Direct, now); ok {
			out.Samples = append(out.Samples, direct)
		}
	}
	ids := make([]string, 0, len(configured))
	for id, address := range configured {
		if id != optimizer.Direct && address != "" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	best := TargetSample{}
	for _, id := range ids {
		series := q.routes[id]
		if series.network != network || series.endpoint != target || series.address != configured[id] {
			continue
		}
		out.State = "UNKNOWN_INSUFFICIENT_RELAY_SAMPLES"
		row, fresh := targetSample(series, id, now)
		if !fresh {
			continue
		}
		out.Samples = append(out.Samples, row)
		if best.Route == "" || row.Loss < best.Loss || row.Loss == best.Loss && row.RTTP95 < best.RTTP95 {
			best = row
		}
	}
	if best.Route != "" {
		out.Relay, out.State = best.Route, TargetQualityRelayReason
	}
	return out
}
