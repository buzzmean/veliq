package clientservice

import (
	"crypto/sha256"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
)

// Conservative public Google service ranges, NOT an IP->YouTube identity map.
// Membership alone NEVER authorizes relay. Two distinct actual DIRECT failures
// in this browser/network are required. No reverse DNS/ASN network lookup.
var browserGooglePrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"64.233.160.0/19", "142.250.0.0/15", "74.125.0.0/16", "108.177.0.0/17", "172.217.0.0/16", "172.253.0.0/16", "173.194.0.0/16", "209.85.128.0/17", "216.58.192.0/19"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func browserGoogleDestination(dst netip.AddrPort) bool {
	if dst.Port() != 443 {
		return false
	}
	for _, p := range browserGooglePrefixes {
		if p.Contains(dst.Addr().Unmap()) {
			return true
		}
	}
	return false
}

type browserGoogleKey struct{ network, profile string }
type browserGoogleFailure struct {
	first     netip.Addr
	at, until time.Time
	distinct  int
	reason    string
}

func (x *browserDomainIndex) googleFailed(network, profile string, dst netip.AddrPort, reason string, now time.Time) {
	if network == "" || profile == "" || !browserGoogleDestination(dst) {
		return
	}
	if !strings.HasPrefix(reason, "DIRECT_TLS_") && reason != "DIRECT_TCP_OPEN_FAILED" {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.google == nil {
		x.google = map[browserGoogleKey]browserGoogleFailure{}
	}
	for key, v := range x.google {
		if v.until.IsZero() && now.Sub(v.at) > 10*time.Second || !v.until.IsZero() && !now.Before(v.until) {
			delete(x.google, key)
		}
	}
	key := browserGoogleKey{network, profile}
	v, ok := x.google[key]
	if !ok {
		if len(x.google) >= 64 {
			return
		}
		v = browserGoogleFailure{first: dst.Addr().Unmap(), at: now, distinct: 1}
	}
	if v.until.IsZero() && v.first != dst.Addr().Unmap() {
		v.distinct = 2
		v.until = now.Add(2 * time.Minute)
	}
	v.reason = reason
	x.google[key] = v
}
func (x *browserDomainIndex) googleRelay(network, profile string, dst netip.AddrPort, now time.Time) bool {
	if network == "" || !browserGoogleDestination(dst) {
		return false
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	v := x.google[browserGoogleKey{network, profile}]
	active := !v.until.IsZero() && now.Before(v.until)
	if active {
		x.googleHits++
	}
	return active
}
func (c *Controller) recordNativeBrowserFailure(cur profilesResult, q browserproxy.Request, p browserproxy.Plan, opaque bool, reason string, evidence ...browserDomainEvidence) bool {
	c.mu.Lock()
	enabled := c.enabled && c.settings.Automatic
	c.mu.Unlock()
	if !enabled || c.ctx != nil && c.ctx.Err() != nil {
		return false
	}
	if n := c.network.Load(); n != nil && n.Fingerprint != cur.network {
		return false
	}
	c.recordNativeBrowserStall(cur, q, p, opaque)
	if len(evidence) > 0 {
		c.browser.domains.recordOrdinaryGoogleFailure(cur.network, cur.profile.ID, p.Destination, evidence[0], time.Now())
	}
	if opaque {
		c.browser.domains.googleFailed(cur.network, cur.profile.ID, p.Destination, reason, time.Now())
	}
	return true
}

// These are ordinary Google hints, not authorization for a hidden protected
// domain. Any observed protected/shared association takes priority below.
func ordinaryGoogleDomain(host string) bool {
	if !browserproxy.ValidPublicDNSName(host) || restrictiveBrowserDomain(host) {
		return false
	}
	for _, suffix := range []string{"google.com", "gstatic.com", "googleapis.com", "googleusercontent.com"} {
		if flowpolicy.DomainMatches(host, suffix) {
			return true
		}
	}
	return false
}
func ordinaryGoogleEvidence(e browserDomainEvidence) bool {
	if e.Restricted {
		return false
	}
	if !e.Ambiguous && ordinaryGoogleDomain(e.Domain) {
		return true
	}
	if len(e.Candidates) == 0 {
		return false
	}
	for _, host := range e.Candidates {
		if !ordinaryGoogleDomain(host) {
			return false
		}
	}
	return true
}

type browserOrdinaryGoogleKey struct {
	network, profile string
	destination      netip.AddrPort
	hints            [32]byte
}

func ordinaryGoogleKey(network, profile string, dst netip.AddrPort, e browserDomainEvidence) browserOrdinaryGoogleKey {
	hints := append([]string{strings.ToLower(e.Domain)}, e.Candidates...)
	sort.Strings(hints)
	return browserOrdinaryGoogleKey{network, profile, dst, sha256.Sum256([]byte(strings.Join(hints, "\x00")))}
}
func (x *browserDomainIndex) recordOrdinaryGoogleFailure(network, profile string, dst netip.AddrPort, e browserDomainEvidence, now time.Time) {
	if network == "" || profile == "" || !ordinaryGoogleEvidence(e) {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.ordinaryGoogleFailures == nil {
		x.ordinaryGoogleFailures = map[browserOrdinaryGoogleKey]time.Time{}
	}
	for k, until := range x.ordinaryGoogleFailures {
		if !now.Before(until) {
			delete(x.ordinaryGoogleFailures, k)
		}
	}
	key := ordinaryGoogleKey(network, profile, dst, e)
	if _, exists := x.ordinaryGoogleFailures[key]; !exists && len(x.ordinaryGoogleFailures) >= 256 {
		return
	}
	x.ordinaryGoogleFailures[key] = now.Add(2 * time.Minute)
}
func (x *browserDomainIndex) ordinaryGoogleFailed(network, profile string, dst netip.AddrPort, e browserDomainEvidence, now time.Time) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return now.Before(x.ordinaryGoogleFailures[ordinaryGoogleKey(network, profile, dst, e)])
}
