package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/buzzmean/veliq/core/measurement"
	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/routing"
	"github.com/buzzmean/veliq/core/transport"
	"github.com/buzzmean/veliq/internal/e2eprobe"
)

type metrics struct {
	Successful, Failed, Attempted int
	FlowFailures                  int `json:"flow_transport_failures"`
	NetworkSamples                int `json:"network_samples"`
	MedianMS, P95MS, JitterMS     *float64
	Loss                          *float64 `json:"packet_loss,omitempty"`
	Score                         *float64 `json:"score,omitempty"`
	Health                        string   `json:"health"`
	ObservedSources               []string `json:"observed_sources"`
	Error                         string   `json:"error,omitempty"`
}
type report struct {
	GeneratedAt       time.Time `json:"generated_at"`
	Relay, Target     string
	InternetEndpoints bool `json:"internet_endpoints"`
	Direct, Relayed   metrics
	Recommended       string
	Smoke             []string `json:"smoke,omitempty"`
	Error             string   `json:"error,omitempty"`
}
type observation struct {
	mu       sync.Mutex
	sources  map[string]bool
	packets  []optimizer.ProbeSample
	attempts int
	errors   []string
}
type recordingDatagram struct {
	routing.Datagram
	record *observation
	key    []byte
}

func (d recordingDatagram) Receive(ctx context.Context) ([]byte, error) {
	b, err := d.Datagram.Receive(ctx)
	if err == nil {
		p, e := e2eprobe.Decode(b, d.key)
		if e == nil && p.Reply && p.Peer.IsValid() {
			d.record.mu.Lock()
			d.record.sources[p.Peer.Addr().String()] = true
			d.record.mu.Unlock()
		}
	}
	return b, err
}
func measuredOpener(open measurement.Opener, record *observation, key []byte) measurement.Opener {
	wrapped := func(ctx context.Context, dst netip.AddrPort) (routing.Datagram, error) {
		d, err := open(ctx, dst)
		if err != nil {
			return nil, err
		}
		return recordingDatagram{d, record, key}, nil
	}
	return e2eprobe.ProbeOpener(wrapped, key)
}
func summarize(record *observation, q optimizer.Quality, load float64) metrics {
	result := metrics{FlowFailures: len(record.errors), Attempted: record.attempts, Health: q.Health, ObservedSources: []string{}}
	var rtts []time.Duration
	var variation, previous time.Duration
	count := 0
	lost := 0
	for _, p := range record.packets {
		switch p.Outcome {
		case optimizer.Reply:
			result.Successful++
			result.NetworkSamples++
			rtts = append(rtts, p.RTT)
			if count > 0 {
				delta := p.RTT - previous
				if delta < 0 {
					delta = -delta
				}
				variation += delta
			}
			previous = p.RTT
			count++
		case optimizer.Timeout:
			lost++
			result.NetworkSamples++
		}
	}
	result.Failed = result.Attempted - result.Successful
	if result.NetworkSamples > 0 {
		v := float64(lost) / float64(result.NetworkSamples)
		result.Loss = &v
	}
	if len(rtts) > 0 {
		sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
		median := float64(rtts[(len(rtts)-1)/2]) / 1e6
		p95 := float64(rtts[int(math.Ceil(.95*float64(len(rtts))))-1]) / 1e6
		result.MedianMS = &median
		result.P95MS = &p95
	}
	if count > 1 {
		jitter := float64(variation) / float64(count-1) / 1e6
		result.JitterMS = &jitter
	}
	if score := optimizer.QualityScore(q, load); !math.IsInf(score, 0) && !math.IsNaN(score) {
		result.Score = &score
	}
	for ip := range record.sources {
		result.ObservedSources = append(result.ObservedSources, ip)
	}
	sort.Strings(result.ObservedSources)
	if len(record.errors) > 0 {
		result.Error = record.errors[len(record.errors)-1]
	}
	if result.Successful == 0 && result.Error == "" {
		result.Error = "timeout: no authenticated UDP replies"
	}
	return result
}
func benchmark(ctx context.Context, o options, relayOpen measurement.Opener, key []byte, load float64) (metrics, metrics, string) {
	selector := optimizer.New(optimizer.DefaultParameters())
	records := map[string]*observation{optimizer.Direct: {sources: map[string]bool{}}, o.relayID: {sources: map[string]bool{}}}
	dst := netip.MustParseAddrPort(o.target)
	for measured := 0; measured < o.count && ctx.Err() == nil; {
		size := min(5, o.count-measured)
		engine := measurement.New(measurement.Settings{Samples: size, Timeout: o.timeout, Spacing: o.interval, Concurrency: 2})
		engine.OnFailure = selector.ReportProbeFailure
		engine.SetCandidates([]measurement.Candidate{
			{Metadata: optimizer.RelayCandidate{ID: optimizer.Direct}, Target: dst, Open: measuredOpener(measurement.OpenDirect, records[optimizer.Direct], key)},
			{Metadata: optimizer.RelayCandidate{ID: o.relayID}, Target: dst, Open: measuredOpener(relayOpen, records[o.relayID], key), Load: load},
		})
		for _, m := range engine.Round(ctx) {
			if m.RouteID == "" {
				continue
			}
			record := records[m.RouteID]
			record.attempts += m.Samples
			record.packets = append(record.packets, m.Probes...)
			if m.TransportError != "" || m.Samples == 0 {
				record.errors = append(record.errors, "relay/flow unavailable: open or transport I/O failed")
			}
			selector.Observe(m)
		}
		measured += size
	}
	now := time.Now()
	qualities := selector.Qualities(now)
	selection := selector.Select(now)
	recommended := "INSUFFICIENT_EVIDENCE"
	// Use the actual optimizer's ranked quality scores. This recommendation is not
	// a claim that its current lifetime/confirmation policy has migrated any flow.
	if len(selection.Ranked) > 0 {
		recommended = selection.Ranked[0].ID
		if recommended == o.relayID {
			recommended = "RELAY"
		}
	}
	return summarize(records[optimizer.Direct], qualities[optimizer.Direct], 0), summarize(records[o.relayID], qualities[o.relayID], load), recommended
}
func run(ctx context.Context, o options) (result report, runErr error) {
	defer func() {
		if runErr != nil {
			result.Error = runErr.Error()
		}
	}()
	result = report{GeneratedAt: time.Now().UTC(), Relay: o.relay, Target: o.target, Recommended: "INSUFFICIENT_EVIDENCE"}
	result.InternetEndpoints = publicEndpoint(o.relay) && publicEndpoint(o.target)
	attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
	auth, err := authenticate(attempt, o)
	cancel()
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	key, err := e2eprobe.Token(o.echoToken)
	if err != nil {
		return result, errors.New("private authenticated echo token missing/invalid")
	}
	attempt, cancel = context.WithTimeout(ctx, o.timeout)
	ticket, err := auth.control.Ticket(attempt, o.relayID)
	cancel()
	if err != nil {
		result.Error = "ticket request rejected or control plane unavailable"
		return result, errors.New(result.Error)
	}
	attempt, cancel = context.WithTimeout(ctx, o.timeout)
	client, err := transport.DialWithTicket(attempt, o.relay, auth.tls, ticket)
	cancel()
	if err != nil {
		result.Error = "relay unavailable or authentication rejected: " + err.Error()
		return result, errors.New(result.Error)
	}
	defer client.Close()
	result.Direct, result.Relayed, result.Recommended = benchmark(ctx, o, client.OpenDatagram, key, auth.load)
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if result.Direct.Successful == 0 || result.Relayed.Successful == 0 {
		result.Error = "timeout/unavailable: one route produced no authenticated UDP replies"
		return result, errors.New(result.Error)
	}
	if o.tcpTarget != "" {
		for _, route := range []string{"DIRECT", "RELAY"} {
			peer, err := tcpProof(ctx, o, client, key, route)
			if err != nil {
				result.Error = route + " TCP timeout/flow failed: " + err.Error()
				return result, errors.New(result.Error)
			}
			result.Smoke = append(result.Smoke, route+" TCP authenticated round trip PASS observed_source="+peer)
		}
	}
	if o.smoke {
		if !result.InternetEndpoints {
			result.Error = "smoke Internet proof requires actual public relay/target endpoints; loopback tests are not Internet acceptance"
			return result, errors.New(result.Error)
		}
		if len(result.Direct.ObservedSources) != 1 || len(result.Relayed.ObservedSources) != 1 || result.Direct.ObservedSources[0] == result.Relayed.ObservedSources[0] {
			result.Error = "DIRECT/RELAY authenticated source distinction not proven"
			return result, errors.New(result.Error)
		}
		result.Smoke = append(result.Smoke, "UDP Internet DIRECT/RELAY authenticated source distinction PASS")
		if err := authSmoke(ctx, o, auth, &result); err != nil {
			result.Error = err.Error()
			return result, err
		}
	}
	return result, nil
}
func publicEndpoint(value string) bool {
	addr, err := netip.ParseAddrPort(value)
	if err != nil {
		return false
	}
	ip := addr.Addr()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15", "240.0.0.0/4"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return true
}
func printReport(r report) {
	for _, item := range []struct {
		name string
		m    metrics
	}{{"DIRECT", r.Direct}, {"RELAY", r.Relayed}} {
		fmt.Println(item.name)
		metric := func(label string, v *float64) {
			if v == nil {
				fmt.Println(label + ": unavailable")
			} else {
				fmt.Printf("%s: %.2f ms\n", label, *v)
			}
		}
		metric("RTT median", item.m.MedianMS)
		metric("RTT p95", item.m.P95MS)
		metric("jitter", item.m.JitterMS)
		if item.m.Loss == nil {
			fmt.Println("packet loss: unavailable")
		} else {
			fmt.Printf("packet loss: %.2f%%\n", 100*(*item.m.Loss))
		}
		fmt.Printf("successful probes: %d; failed probes: %d; attempted: %d; sent network probes: %d\n", item.m.Successful, item.m.Failed, item.m.Attempted, item.m.NetworkSamples)
		fmt.Printf("flow/transport failures: %d\n", item.m.FlowFailures)
		fmt.Printf("optimizer health: %s; observed_sources: %v\n", item.m.Health, item.m.ObservedSources)
		if item.m.Error != "" {
			fmt.Println("error:", item.m.Error)
		}
	}
	fmt.Println("Recommended route:", r.Recommended, "(existing optimizer quality ranking; not a flow migration)")
	for _, check := range r.Smoke {
		fmt.Println(check)
	}
	fmt.Println("Public Internet endpoints:", r.InternetEndpoints, "(requires external smoke evidence; local CI is not Internet validation)")
}
