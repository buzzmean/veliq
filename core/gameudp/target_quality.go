package gameudp

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/buzzmean/neexitlag/core/optimizer"
)

const (
	targetQualityWindow         = 45 * time.Second
	targetQualityRounds         = 4
	targetQualitySamples        = 20
	targetQualityMinimumRTTGain = 2 * time.Millisecond
)

const TargetQualityRelayReason = "RELAY_IMPROVES_RTT_AND_LOSS"

type TargetSample struct {
	Route      string        `json:"route"`
	Samples    int           `json:"samples"`
	RTT        time.Duration `json:"rtt_ns"`
	Loss       float64       `json:"loss"`
	ObservedAt time.Time     `json:"observed_at"`
	roundRTT   [targetQualityRounds]time.Duration
	roundLoss  [targetQualityRounds]int
	roundSent  [targetQualityRounds]int
	roundAt    [targetQualityRounds]time.Time
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
	direct := q.routes[optimizer.Direct]
	return network != "" && direct.network == network && direct.endpoint == target
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

func targetSample(series targetSeries, route, network, address string, endpoint netip.AddrPort, now time.Time) (TargetSample, bool) {
	if series.network != network || series.address != address || series.endpoint != endpoint || len(series.rounds) < targetQualityRounds {
		return TargetSample{}, false
	}
	var delays []time.Duration
	var sent, missed int
	out := TargetSample{Route: route, ObservedAt: series.rounds[len(series.rounds)-1].ObservedAt}
	for i, round := range series.rounds {
		if round.ObservedAt.After(now) || now.Sub(round.ObservedAt) > targetQualityWindow ||
			round.TransportError != "" || len(round.Probes) == 0 {
			return TargetSample{}, false
		}
		out.roundAt[i] = round.ObservedAt
		var roundDelays []time.Duration
		for _, probe := range round.Probes {
			switch {
			case probe.Outcome == optimizer.Reply && probe.RTT > 0:
				delays = append(delays, probe.RTT)
				roundDelays = append(roundDelays, probe.RTT)
			case probe.Outcome == optimizer.Timeout:
				missed++
				out.roundLoss[i]++
			default:
				return TargetSample{}, false
			}
			sent++
			out.roundSent[i]++
		}
		if len(roundDelays) == 0 {
			return TargetSample{}, false
		}
		sort.Slice(roundDelays, func(a, b int) bool { return roundDelays[a] < roundDelays[b] })
		out.roundRTT[i] = roundDelays[len(roundDelays)/2]
	}
	if sent < targetQualitySamples || len(delays) < targetQualitySamples/2 {
		return TargetSample{}, false
	}
	sort.Slice(delays, func(i, j int) bool { return delays[i] < delays[j] })
	out.Samples, out.RTT, out.Loss = sent, delays[len(delays)/2], float64(missed)/float64(sent)
	return out, true
}

func sustainedImprovement(local, relay TargetSample) bool {
	if relay.Samples != local.Samples || relay.RTT+targetQualityMinimumRTTGain > local.RTT ||
		relay.Loss+2/float64(local.Samples) > local.Loss {
		return false
	}
	both := 0
	for i := range local.roundRTT {
		if relay.roundAt[i].Sub(local.roundAt[i]).Abs() > 5*time.Second ||
			relay.roundSent[i] != local.roundSent[i] || relay.roundRTT[i]+targetQualityMinimumRTTGain > local.roundRTT[i] ||
			relay.roundLoss[i] > local.roundLoss[i] {
			return false
		}
		if relay.roundLoss[i] < local.roundLoss[i] {
			both++
		}
	}
	return both >= 2
}

// Compare evaluates configured relay IDs only and ranks the approaches that
// beat the local baseline on both dimensions. The caller still pins the
// existing flow and uses a recommendation only for a new one.
func (q *TargetQuality) Compare(network string, target netip.AddrPort, configured map[string]string, now time.Time) TargetQualityStatus {
	out := TargetQualityStatus{Destination: target, State: "UNKNOWN_NO_AUTHENTICATED_EXACT_TARGET"}
	q.mu.Lock()
	defer q.mu.Unlock()
	directSeries := q.routes[optimizer.Direct]
	if target != directSeries.endpoint || network == "" || network != directSeries.network {
		return out
	}
	out.State = "UNKNOWN_INSUFFICIENT_COMPARABLE_SAMPLES"
	local, ok := targetSample(directSeries, optimizer.Direct, network, "", target, now)
	if !ok {
		return out
	}
	out.Samples = append(out.Samples, local)
	ids := make([]string, 0, len(configured))
	for id := range configured {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	best := TargetSample{}
	for _, id := range ids {
		row, fresh := targetSample(q.routes[id], id, network, configured[id], target, now)
		if !fresh || row.ObservedAt.Sub(local.ObservedAt).Abs() > 10*time.Second {
			continue
		}
		out.Samples = append(out.Samples, row)
		if !sustainedImprovement(local, row) {
			continue
		}
		if best.Route == "" || row.Loss < best.Loss || row.Loss == best.Loss && row.RTT < best.RTT {
			best = row
		}
	}
	if best.Route != "" {
		out.Relay, out.State = best.Route, TargetQualityRelayReason
	} else if len(out.Samples) > 1 {
		out.State = "KEEP_LOCAL_IMPROVEMENT_UNPROVEN"
	}
	return out
}
