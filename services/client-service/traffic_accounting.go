package clientservice

import (
	"context"
	"crypto/ed25519"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/controlclient"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/traffic"
	"sync"
	"time"
)

// Remote NIC counters are independently signed by the CP, not inferred from
// this PC's session bytes or configured relay address.
type remoteTrafficState struct {
	mu           sync.Mutex
	state, error string
	checked      time.Time
	generated    time.Time
	rows         []traffic.MonthRow
}

func (c *Controller) accountRelayTraffic(f routing.Flow, tx, rx uint64) {
	if browserDPIFinalEnabled() {
		c.browser.dpiField.relayBytes(f, tx, rx)
	}
	service := f.OriginService
	if service == "" {
		service = f.ApplicationID
	}
	subgroup := f.OriginDomain
	if subgroup == "" {
		subgroup = "opaque-application"
	} else {
		subgroup = youtubeSubgroup(subgroup)
	}
	reason := f.OriginReason
	if reason == "" {
		reason = "APPLICATION_PINNED_RELAY"
	}
	c.traffic.Add(traffic.Key{Profile: f.ApplicationID, Service: service, Subgroup: subgroup, Reason: reason, Relay: f.Route.RelayID}, tx, rx, time.Now())
}
func (c *Controller) watchTrafficAccounting() {
	timer := time.NewTicker(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-c.ctx.Done():
			_ = c.traffic.Flush()
			return
		case <-timer.C:
			_ = c.traffic.Flush()
		}
	}
}
func (c *Controller) trafficSnapshot() map[string]any {
	r := &c.remoteTraffic
	r.mu.Lock()
	state, err, checked := r.state, r.error, r.checked
	rows := append([]traffic.MonthRow(nil), r.rows...)
	r.mu.Unlock()
	if !checked.IsZero() && time.Since(checked) > 3*time.Minute {
		state = "SERVER_TRAFFIC_STALE_LAST_KNOWN"
	}
	if state == "" {
		state = "SERVER_TRAFFIC_UNINSTRUMENTED"
	}
	return map[string]any{"client": c.traffic.Snapshot(time.Now()), "server": map[string]any{"state": state, "error": err, "checked": checked, "relays": rows, "scope": "sampled Linux interface TX, includes overhead and non-relay traffic; UTC month estimate, provider reset day and any coverage gaps explicit; never infer unused quota from missing data"}}
}

func (c *Controller) browserTrafficReason(cur profilesResult, q browserproxy.Request, p browserproxy.Plan) string {
	if p.Policy.Source == "browser_secure_dns_relay" {
		return "RESOLVER_BOOTSTRAP"
	}
	if c.browserOriginPolicy(q.Host).Kind == "RELAY" {
		return "IP_GEO_REQUIRED"
	}
	if p.Policy.Source == youtubeLadderSource && p.Policy.Action == flowpolicy.RelayRequired {
		r := c.browser.youtube
		r.mu.Lock()
		v := r.cache[youtubeScope(cur, q)]
		r.mu.Unlock()
		if v.Reason != "" {
			return v.Reason
		}
		return "LOCAL_HEALTH_NOT_CONFIRMED"
	}
	if p.Policy.Source == "rule" {
		return "EXPLICIT_RULE"
	}
	return p.Policy.Source
}
func (c *Controller) runRemoteTraffic(ctx context.Context, cp *controlclient.Client, keys map[string]ed25519.PublicKey) {
	r := &c.remoteTraffic
	poll := func() {
		work, cancel := context.WithTimeout(ctx, 2*time.Second)
		raw, err := cp.RelayTrafficSnapshot(work)
		cancel()
		now := time.Now()
		var d traffic.Document
		if err == nil {
			d, err = traffic.Validate(keys, raw, now)
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		r.checked = now
		if err != nil {
			r.state = "SERVER_TRAFFIC_UNAVAILABLE_OR_UNSIGNED"
			r.error = "TRAFFIC_CP_UNAVAILABLE_OR_REJECTED; unused quota UNKNOWN"
			return
		}
		if d.GeneratedAt.Before(r.generated) {
			r.state = "SERVER_TRAFFIC_ROLLBACK_REJECTED"
			return
		}
		for _, old := range r.rows {
			for _, next := range d.Relays {
				if old.Relay == next.Relay && old.Month == next.Month && next.Bytes < old.Bytes {
					r.state = "SERVER_TRAFFIC_COUNTER_REGRESSION_REVIEW"
					return
				}
			}
		}
		r.rows = d.Relays
		r.generated = d.GeneratedAt
		r.error = ""
		r.state = "SIGNED_SERVER_NIC_TRAFFIC"
		if len(d.Relays) == 0 {
			r.state = "NO_SERVER_COUNTER_REPORTS; USAGE_UNKNOWN"
		}
	}
	poll()
	timer := time.NewTicker(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			poll()
		}
	}
}
