package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/optimizer"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/security"
	windowsplatform "github.com/buzzmean/neexitlag/platform/windows"
	"log/slog"
	"net/netip"
	"strings"
	"time"
)

func (c *Controller) watchNetwork() {
	// The route fingerprint is cheap and gates AUTO/Chrome freshness; the process
	// and module conflict scan is slow, so it runs on its own cadence and never
	// delays or invalidates the fingerprint.
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.watchConflicts() }()
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		ctx, cancel := context.WithTimeout(c.ctx, 8*time.Second)
		c.mu.Lock()
		routes := append([]netip.Addr{}, c.NetworkHostRoutes...)
		c.mu.Unlock()
		n := windowsplatform.InspectNetwork(ctx, routes)
		cancel()
		if n.Error != "" {
			slog.Warn("network inspection failed; AUTO waits for a fresh fingerprint", "error", n.Error)
		}
		c.mergeConflicts(&n)
		c.network.Store(&n)
		c.Local.Suspend(len(n.Conflicts) > 0)
		c.Learned.Cleanup(time.Now())
		select {
		case <-c.ctx.Done():
			return
		case <-tick.C:
		}
	}
}
func (c *Controller) watchConflicts() {
	tick := time.NewTicker(2 * time.Minute)
	defer tick.Stop()
	for {
		ctx, cancel := context.WithTimeout(c.ctx, 20*time.Second)
		scan := windowsplatform.InspectConflicts(ctx)
		cancel()
		if scan.Error != "" {
			slog.Warn("conflict scan failed; previous conflicts are kept, none are assumed", "error", scan.Error)
		} else {
			c.conflicts.Store(&scan)
			if n := c.network.Load(); n != nil {
				merged := *n
				c.mergeConflicts(&merged)
				c.network.Store(&merged)
			}
			c.Local.Suspend(len(scan.Conflicts) > 0)
		}
		select {
		case <-c.ctx.Done():
			return
		case <-tick.C:
		}
	}
}
func (c *Controller) mergeConflicts(n *windowsplatform.NetworkContext) {
	scan := c.conflicts.Load()
	if scan == nil {
		n.ConflictScan = "conflict scan has not completed; conflicts unknown"
		return
	}
	n.Conflicts = append([]string(nil), scan.Conflicts...)
	n.AntiCheats = append([]string(nil), scan.AntiCheats...)
	n.ConflictsObservedAt = scan.ObservedAt
	if scan.Incomplete {
		n.ConflictScan = "some process modules inaccessible; conflict scan incomplete"
	}
}
func (c *Controller) localKey(app, dest, protocol string) (localstrategy.TargetKey, error) {
	n := c.network.Load()
	if n == nil || n.Error != "" || n.Fingerprint == "" || time.Since(n.ObservedAt) > 45*time.Second {
		return localstrategy.TargetKey{}, errors.New("fresh network fingerprint unavailable")
	}
	return localstrategy.TargetKey{ConfigRevision: c.Local.Revision(), Network: n.Fingerprint, Application: strings.ToLower(strings.ReplaceAll(app, "\\", "/")), Destination: dest, Protocol: protocol, Version: localstrategy.Version}, nil
}
func (c *Controller) applyLocalAuto(id windowsplatform.ProcessIdentity, t windowsplatform.Tuple, d *windowsplatform.Decision) {
	c.mu.Lock()
	automatic := c.settings.Automatic
	c.mu.Unlock()
	if !automatic {
		return
	}
	lookupProtocol := t.Protocol
	quicCandidate := t.Protocol == "udp" && t.Destination.Port() == 443
	if quicCandidate {
		lookupProtocol = "tcp"
	} // TCP proof can authorize scoped fallback, never UDP relay success.
	k, err := c.localKey(id.Path, t.Destination.String(), lookupProtocol)
	if err != nil {
		return
	}
	now := time.Now()
	all := c.Learned.Candidates(k, now)
	var direct, relay optimizer.RouteMeasurement
	for _, v := range all {
		if v.Strategy == "DIRECT" {
			direct = v.Measurement
		}
		if v.Strategy == "RELAY" {
			relay = v.Measurement
		}
	}
	// Failed DIRECT must also remain available to policy (Candidates excludes failures).
	if v, ok := c.Learned.Evidence(k, "DIRECT", now); ok {
		direct = v.Measurement
	}
	winner := localstrategy.Recommend(direct, all, relay, now)
	if winner == "DIRECT" {
		d.Route = routing.Route{}
		return
	}
	if winner == "RELAY" && quicCandidate {
		return
	} // do not borrow TCP success to relay UDP
	if winner == "RELAY" {
		if relay.RouteID != "" && relay.RouteID != optimizer.Direct && relay.RouteID != "controlled-target" {
			d.Route = routing.Route{RelayID: relay.RouteID}
		}
		return
	}
	if winner == "" {
		return
	}
	for _, p := range c.Local.Config().User {
		if p.ID == winner && p.Enabled && (!quicCandidate || p.QuicFallback) {
			d.Route = routing.Route{Kind: routing.DirectPlusRoute}
			d.Local = c.Local
			d.LocalStrategyID = winner
			d.BlockOnFailure = false
			return
		}
	}
}

type localRecord struct {
	ObservedHostname string                          `json:"observed_hostname,omitempty"`
	CaptureMarker    *windowsplatform.EvidenceMarker `json:"capture_marker,omitempty"`
	FlowID           uint64                          `json:"flow_id,omitempty"`
	Source           string                          `json:"source,omitempty"`
	Domain           string                          `json:"domain,omitempty"`

	PID          uint32                     `json:"pid"`
	CreationTime uint64                     `json:"creation_time"`
	Application  string                     `json:"application"`
	Destination  string                     `json:"destination"`
	Protocol     string                     `json:"protocol"`
	Network      string                     `json:"network"`
	Strategy     string                     `json:"strategy"`
	Success      bool                       `json:"success"`
	Measurement  optimizer.RouteMeasurement `json:"measurement"`
}

func (c *Controller) handleLocalEvidence(method string, raw json.RawMessage) (any, error) {
	var v localRecord
	if err := security.Parse(raw, &v); err != nil {
		return nil, err
	}
	k, err := c.localKey(v.Application, v.Destination, v.Protocol)
	if err != nil {
		return nil, err
	}
	if k.Network != v.Network {
		return nil, errors.New("network changed during test; discard evidence")
	}
	if method == "local.record" {
		if v.Strategy == "RELAY" {
			c.mu.Lock()
			_, registered := c.acceptanceRelays[v.Measurement.RouteID]
			c.mu.Unlock()
			if !registered {
				return nil, errors.New("relay evidence must name a configured authenticated relay")
			}
		}

		if v.Strategy != "DIRECT" && v.Strategy != "RELAY" {
			found := false
			for _, p := range c.Local.Config().User {
				if p.ID == v.Strategy && p.Protocol == v.Protocol {
					found = true
					if v.Success && len(p.Actions) > 0 {
						backend, ok := c.Backend.(interface {
							DiagnosticsTarget(uint32, string) windowsplatform.CaptureEvidence
						})
						if !ok || v.PID == 0 || v.CreationTime == 0 {
							return nil, errors.New("successful chain evidence requires captured process identity")
						}
						ev := backend.DiagnosticsTarget(v.PID, v.Destination)
						if v.CaptureMarker != nil {
							scoped, ok := c.Backend.(interface {
								DiagnosticsScoped(windowsplatform.EvidenceQuery) (windowsplatform.CaptureEvidence, error)
							})
							if !ok || v.FlowID == 0 || v.Source == "" || v.Domain == "" {
								return nil, errors.New("successful trial requires scoped source/flow/domain evidence")
							}
							var err error
							ev, err = scoped.DiagnosticsScoped(windowsplatform.EvidenceQuery{PID: v.PID, CreationTime: v.CreationTime, Destination: v.Destination, Source: v.Source, Domain: v.Domain, Since: v.CaptureMarker})
							if err != nil {
								return nil, err
							}
						}
						proved := false
						for _, f := range ev.Flows {
							if (v.CaptureMarker == nil || f.FlowID == v.FlowID && f.Source == v.Source && strings.EqualFold(f.Domain, v.Domain) && f.LocalInspection != nil && f.LocalInspection.Reason == "REASSEMBLY_COMPLETE" && f.LocalInspection.TransformApplied) && f.PID == v.PID && f.CreationTime == v.CreationTime && strings.EqualFold(strings.ReplaceAll(f.Executable, `\`, "/"), strings.ReplaceAll(v.Application, `\`, "/")) && f.Destination == v.Destination && f.Protocol == v.Protocol && f.Strategy == v.Strategy && f.StrategyRevision == c.Local.Revision() && f.Route == "DIRECT_PLUS" && f.Counters.DirectPlus > 0 && f.Counters.DirectPlusBytes > 0 && f.Counters.Relayed == 0 && f.Counters.RelayedBytes == 0 && time.Since(f.LastSeen) < time.Minute {
								proved = true
							}
						}
						if ev.Truncated || !proved {
							return nil, errors.New("no complete real transform evidence for successful chain report")
						}
					}
				}
			}
			if !found {
				return nil, errors.New("strategy version no longer configured")
			}
		}
		if err = c.Learned.Record(k, v.Strategy, v.Measurement, v.Success, time.Now()); err != nil {
			return nil, err
		}
	}
	if method == "local.record" {
		if err = c.recordAutoTrial(v); err != nil {
			return nil, err
		}
	}
	all := c.Learned.Candidates(k, time.Now())
	var d, r optimizer.RouteMeasurement
	if x, ok := c.Learned.Evidence(k, "DIRECT", time.Now()); ok {
		d = x.Measurement
	}
	if x, ok := c.Learned.Evidence(k, "RELAY", time.Now()); ok {
		r = x.Measurement
	}
	return map[string]any{"recommended": localstrategy.Recommend(d, all, r, time.Now()), "evidence": all}, nil
}

// Compare is report-only; cross-process A/B/C tests cannot populate learned
// strategy evidence for an application that did not perform that route's trial.
func compareLocalReports(raw json.RawMessage) (any, error) {
	var q struct {
		Measurements []localRecord `json:"measurements"`
	}
	if err := security.Parse(raw, &q); err != nil {
		return nil, err
	}
	if len(q.Measurements) < 2 || len(q.Measurements) > 6 {
		return nil, errors.New("bounded comparison requires 2..6 measurements")
	}
	now := time.Now()
	var d, r optimizer.RouteMeasurement
	var local []localstrategy.Working
	for _, v := range q.Measurements {
		if now.Sub(v.Measurement.ObservedAt) > 90*time.Second || v.Measurement.ObservedAt.After(now) {
			return nil, errors.New("stale/future comparison")
		}
		switch v.Strategy {
		case "DIRECT":
			d = v.Measurement
		case "RELAY":
			r = v.Measurement
		default:
			if v.Success {
				local = append(local, localstrategy.Working{Strategy: v.Strategy, Measurement: v.Measurement, Expires: now.Add(time.Minute)})
			}
		}
	}
	return map[string]string{"recommended": localstrategy.Recommend(d, local, r, now), "scope": "report only; no cross-exe learning"}, nil
}
