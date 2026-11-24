package clientservice

import (
	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/originpolicy"
	"time"
)

func (c *Controller) browserOriginPolicy(host string) originpolicy.Rule {
	if c.catalog == nil {
		return originpolicy.Floor(host)
	}
	return c.catalog.origin(host)
}
func (c *Controller) localLadderEligible(cur profilesResult, q browserproxy.Request, p browserproxy.Plan) bool {
	if !localBrowserRequestEligible(q, p) {
		return false
	}
	policy := c.browserOriginPolicy(q.Host)
	if policy.Kind == "RELAY" {
		return false
	}
	if policy.Kind == "DPI" {
		return true
	}
	// Ordinary sites remain immediate DIRECT. Only real prior per-origin failure
	// evidence or an independently confirmed LOCAL result engages the same ladder.
	r := c.browser.youtube
	r.mu.Lock()
	v := r.cache[youtubeScope(cur, q)]
	r.mu.Unlock()
	if v.Confirmed && v.Stage == "LOCAL" && time.Now().Before(v.Until) {
		return true
	}
	return c.directAddressFailed(cur, q, p) || p.Policy.Source == "direct_timeout_cache"
}
func localBrowserRequestEligible(q browserproxy.Request, p browserproxy.Plan) bool {
	return !(p.Policy.Action == flowpolicy.RelayRequired && p.Policy.Source == "") && p.Enabled && !q.OriginAmbiguous && q.Secure && q.Port == 443 && browserproxy.ValidPublicDNSName(q.Host) && !protectedBrowserDomain(q.Host) && flowpolicy.KnownBrowserRelayGroup(q.Host) == "" && p.Policy.Source != "rule" && p.Policy.Action != flowpolicy.Block && p.Destination.Addr().Is4() && browserproxy.PublicDNSAddress(p.Destination.Addr())
}
