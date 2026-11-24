package clientservice

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
)

type browserDomainEvidence struct {
	YoutubeSubgroup string   `json:"youtube_uniform_subgroup,omitempty"`
	YoutubeOnly     bool     `json:"youtube_only_hint_set,omitempty"`
	Source          string   `json:"source"`
	Domain          string   `json:"domain,omitempty"`
	Outer           string   `json:"outer_sni,omitempty"`
	Candidates      []string `json:"candidates"`
	Restricted      bool     `json:"restricted"`
	Ambiguous       bool     `json:"ambiguous"`
	// DNS/outer metadata is a routing hint, never authenticated inner SNI.
	Confidence string `json:"confidence"`
}
type browserDNSObservation struct {
	name    string
	expires time.Time
}
type browserDNSKey struct {
	network, profile string
	address          netip.Addr
}
type browserDomainIndex struct {
	ordinaryGoogleFailures map[browserOrdinaryGoogleKey]time.Time
	google                 map[browserGoogleKey]browserGoogleFailure
	googleHits             uint64

	owned map[browserDNSKey][]browserDNSObservation

	mu        sync.Mutex
	network   string
	checked   time.Time
	errorCode string
	entries   map[netip.Addr][]browserDNSObservation
	failed    map[string]time.Time
}

func (x *browserDomainIndex) replace(network string, rows []wp.DNSCacheEntry, err error, now time.Time) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.network = network
	x.checked = now
	x.entries = map[netip.Addr][]browserDNSObservation{}
	x.errorCode = ""
	if err != nil {
		x.errorCode = "DNS_CACHE_UNAVAILABLE"
		return
	}
	for i, r := range rows {
		if i >= 256 {
			break
		}
		ip, e := netip.ParseAddr(r.Address)
		if e != nil || !browserproxy.ValidPublicDNSName(r.Name) || r.TTL == 0 {
			continue
		}
		ttl := time.Duration(r.TTL) * time.Second
		if ttl > 5*time.Minute {
			ttl = 5 * time.Minute
		}
		x.entries[ip.Unmap()] = append(x.entries[ip.Unmap()], browserDNSObservation{r.Name, now.Add(ttl)})
	}
}
func restrictiveBrowserDomain(host string) bool {
	return protectedBrowserDomain(host) || flowpolicy.KnownBrowserRelayGroup(host) != "" || youtubeRelayDomain(host)
}
func (x *browserDomainIndex) evidence(network string, destination netip.Addr, outer string, now time.Time) browserDomainEvidence {
	return x.profileEvidence(network, "", destination, outer, now)
}
func (x *browserDomainIndex) profileEvidence(network, profile string, destination netip.Addr, outer string, now time.Time) browserDomainEvidence {
	return x.profileEvidenceFor(network, profile, destination, outer, now, restrictiveBrowserDomain)
}
func (x *browserDomainIndex) profileEvidenceFor(network, profile string, destination netip.Addr, outer string, now time.Time, restrictive func(string) bool) browserDomainEvidence {
	out := browserDomainEvidence{Source: "OPAQUE_UNKNOWN_DIRECT_DEFAULT", Confidence: "UNKNOWN; ECH inner name not observed", Outer: outer, Candidates: []string{}}
	x.mu.Lock()
	defer x.mu.Unlock()
	seen := map[string]bool{}
	if network != "" && network == x.network {
		for _, r := range x.entries[destination.Unmap()] {
			if now.Before(r.expires) {
				seen[r.name] = true
			}
		}
	}
	owned := false
	if network != "" && profile != "" {
		for _, r := range x.owned[browserDNSKey{network, profile, destination.Unmap()}] {
			if now.Before(r.expires) {
				if !owned {
					seen = map[string]bool{}
					owned = true
				}
				seen[r.name] = true
			}
		}
	}
	for name := range seen {
		out.Candidates = append(out.Candidates, name)
	}
	sort.Strings(out.Candidates)
	out.Ambiguous = len(out.Candidates) > 1
	// A protected association can restrict a shared IP but can never authorize
	// DIRECT for it. Never claim that an ambiguous shared IP identifies a site.
	for _, host := range out.Candidates {
		if restrictive(host) {
			out.Restricted = true
		}
	}
	if len(out.Candidates) == 1 {
		out.Domain = out.Candidates[0]
		out.Source = "SYSTEM_DNS_CACHE_TTL_HINT"
		out.Confidence = "OS cache hint; browser/inner ECH not proven"
	}
	if out.Ambiguous {
		out.Source = "SYSTEM_DNS_CACHE_AMBIGUOUS"
	}
	if owned {
		out.Source = "BROWSER_DNS_REPLY_PROFILE_TTL_HINT"
		out.Confidence = "response delivered to this browser profile; shared IP/ECH inner identity not proven"
		if out.Ambiguous {
			out.Source = "BROWSER_DNS_REPLY_AMBIGUOUS"
		}
	}
	// A visible protected outer name may only make policy MORE restrictive.
	// In GREASE flows this also restores TLS-first-flight IP health/recovery.
	if browserproxy.ValidPublicDNSName(outer) && restrictive(outer) {
		out.Restricted = true
		if len(out.Candidates) == 0 || seen[outer] {
			out.Domain = outer
			out.Source = "ECH_PROTECTED_OUTER_HINT"
			out.Confidence = "outer SNI only; inner ECH not proven"
		}
	}
	// A normal Google outer name is a hint only. It must never override a
	// protected DNS association, shared-IP ambiguity or a known DoH endpoint.
	if out.Domain == "" && !out.Restricted && !out.Ambiguous && ordinaryGoogleDomain(outer) {
		out.Domain = outer
		out.Source = "ECH_ORDINARY_GOOGLE_OUTER_HINT"
		out.Confidence = "ordinary outer SNI hint; inner ECH NOT proven"
	}
	out.YoutubeOnly = len(out.Candidates) > 0
	for _, host := range out.Candidates {
		if !youtubeRelayDomain(host) {
			out.YoutubeOnly = false
		}
	}
	if browserproxy.ValidPublicDNSName(outer) && restrictive(outer) && !youtubeRelayDomain(outer) {
		out.YoutubeOnly = false
	}
	if out.YoutubeOnly && len(out.Candidates) > 0 {
		out.YoutubeSubgroup = youtubeSubgroup(out.Candidates[0])
		for _, h := range out.Candidates[1:] {
			if youtubeSubgroup(h) != out.YoutubeSubgroup {
				out.YoutubeSubgroup = ""
				break
			}
		}
	}
	out, _ = youtubeMediaOuterEvidence(out)
	if len(out.Candidates) > 8 {
		out.Candidates = out.Candidates[:8]
	}
	return out
}
func opaqueFailureKey(network, profile string, dst netip.AddrPort) string {
	return network + "|" + profile + "|" + dst.String()
}
func (x *browserDomainIndex) failedDirect(network, profile string, dst netip.AddrPort, now time.Time) {
	if network == "" {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.failed == nil {
		x.failed = map[string]time.Time{}
	}
	for key, until := range x.failed {
		if !now.Before(until) {
			delete(x.failed, key)
		}
	}
	if len(x.failed) >= 256 && x.failed[opaqueFailureKey(network, profile, dst)].IsZero() {
		return
	}
	x.failed[opaqueFailureKey(network, profile, dst)] = now.Add(2 * time.Minute)
}
func (x *browserDomainIndex) directFailed(network, profile string, dst netip.AddrPort, now time.Time) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	until := x.failed[opaqueFailureKey(network, profile, dst)]
	return network != "" && now.Before(until)
}
func (x *browserDomainIndex) snapshot() map[string]any {
	x.mu.Lock()
	defer x.mu.Unlock()
	now := time.Now()
	groups := []map[string]any{}
	activeFailures := 0
	hints := []map[string]any{}
	activeOwned, omittedHints := 0, 0
	for key, rows := range x.owned {
		activeAddress := false
		for _, row := range rows {
			if !now.Before(row.expires) {
				continue
			}
			activeAddress = true
			if len(hints) >= 16 {
				omittedHints++
				continue
			}
			hints = append(hints, map[string]any{"network": key.network, "profile_id": key.profile, "address": key.address.String(), "domain": row.name, "expires": row.expires})
		}
		if activeAddress {
			activeOwned++
		}
	}
	for _, until := range x.failed {
		if now.Before(until) {
			activeFailures++
		}
	}
	for key, v := range x.google {
		if v.until.IsZero() && now.Sub(v.at) > 10*time.Second {
			continue
		}
		if len(groups) >= 16 {
			break
		}
		state := "PROBATION"
		if !v.until.IsZero() {
			if !now.Before(v.until) {
				continue
			}
			state = "RELAY_FIRST"
		}
		groups = append(groups, map[string]any{"network": key.network, "profile_id": key.profile, "family": "GOOGLE_SERVICE_NETWORKS_NOT_DOMAIN_IDENTITY", "state": state, "distinct_failed_addresses": v.distinct, "first_address": v.first.String(), "until": v.until, "last_failure": v.reason})
	}
	return map[string]any{"source": "BROWSER_DNS_RESPONSE_PROFILE_TTL + WINDOWS_SYSTEM_DNS_CACHE; transit DoH encrypted", "opaque_direct_failed_endpoints": activeFailures, "google_failure_groups": groups, "google_failure_group_hits": x.googleHits, "google_group_maximum": 64, "google_group_ttl_seconds": 120, "native_first_tls_reply_budget_ms": 1200, "checked_at": x.checked, "last_error": x.errorCode, "browser_scoped_addresses": activeOwned, "browser_scoped_hints": hints, "browser_scoped_hints_omitted": omittedHints, "addresses": len(x.entries), "maximum_rows": 256, "maximum_ttl_seconds": 300, "refresh_seconds": 10, "unknown_policy": "DIRECT_DEFAULT; hidden protected domain cannot be guaranteed"}
}
func (c *Controller) watchBrowserDomainCache() {
	for {
		network := ""
		if n := c.network.Load(); n != nil && n.Error == "" && time.Since(n.ObservedAt) <= 45*time.Second {
			network = n.Fingerprint
		}
		ctx, cancel := context.WithTimeout(c.ctx, 3*time.Second)
		rows, err := wp.ReadDNSCache(ctx)
		cancel()
		c.browser.domains.replace(network, rows, err, time.Now())
		timer := time.NewTimer(10 * time.Second)
		select {
		case <-c.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (c *Controller) nativeOpaquePlan(p profiles.Profile, t wp.Tuple, network string, e browserDomainEvidence) browserproxy.Plan {
	policy := c.browserFlow(p, wp.ProcessIdentity{}, t, e.Domain, network)
	secureDNS := browserproxy.KnownDoHEndpoint(e.Domain, t.Destination)
	if secureDNS {
		e.Restricted = true
	}
	// Explicit BLOCK remains authoritative. An ordinary DIRECT rule cannot
	// override a known protected association, even on an ambiguous shared IP.
	if r, ok := flowpolicy.Evaluate(p.Rules, flowpolicy.Input{Protocol: t.Protocol, Destination: t.Destination, Domain: e.Domain, Network: network}); ok {
		if !e.Restricted || r.Action == flowpolicy.Block || r.Action == flowpolicy.RelayRequired {
			policy = r
		}
	}
	ordinaryHint := ordinaryGoogleEvidence(e) && !secureDNS
	ordinaryFailed := ordinaryHint && policy.Source != "rule" && c.browser.domains.ordinaryGoogleFailed(network, p.ID, t.Destination, e, time.Now())
	googleFailed := !ordinaryHint && policy.Source != "rule" && c.browser.domains.googleRelay(network, p.ID, t.Destination, time.Now())
	if policy.Action != flowpolicy.Block && (e.Restricted || googleFailed || ordinaryFailed || !ordinaryHint && policy.Source != "rule" && c.browser.domains.directFailed(network, p.ID, t.Destination, time.Now())) {
		relay := p.RelayID
		if relay == "" {
			relay = "VPS-01"
		}
		if policy.Action == flowpolicy.RelayRequired && policy.RelayID != "" {
			relay = policy.RelayID
		}
		policy = flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: relay, Fallback: flowpolicy.Required, Source: "browser_opaque_evidence", Reason: "protected DNS/outer association or observed DIRECT failure; authenticated relay only"}
	}
	if googleFailed && policy.Action == flowpolicy.RelayRequired {
		policy.Source = "browser_opaque_google_failure_cache"
		policy.Reason = "two distinct Google TCP443 DIRECT failures on this network/profile; bounded relay-first, domain not inferred"
	}
	if ordinaryFailed && policy.Action == flowpolicy.RelayRequired {
		policy.Source = "browser_ordinary_google_failure_cache"
		policy.Reason = "actual DIRECT failure for this exact Google hint set/IP on this browser/network; bounded relay, no unrelated SNI failure"
	}
	if ordinaryHint && policy.Action == flowpolicy.Direct && policy.Source != "rule" {
		policy.Source = "browser_ordinary_google_hint_direct"
		policy.Reason = "ordinary Google DNS/outer hint: unrelated IP/family failures do not prove this origin blocked; domain-scoped failure recovery remains enabled"
	}
	if secureDNS && policy.Action != flowpolicy.Block {
		policy.Source = "browser_secure_dns_relay"
		policy.Reason = "known resolver endpoint, no DIRECT Secure DNS bypass"
	}
	return browserproxy.Plan{Enabled: true, Network: network, Destination: t.Destination, Policy: policy, Probe: e.Source, OrdinaryCapacityDirect: !e.Restricted && !secureDNS && policy.Source != "rule"}
}

func (x *browserDomainIndex) observeBrowserDNS(network, profile string, rows []browserproxy.DNSHint, now time.Time) {
	if network == "" || profile == "" {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.owned == nil {
		x.owned = map[browserDNSKey][]browserDNSObservation{}
	}
	for k, rows := range x.owned {
		kept := rows[:0]
		for _, r := range rows {
			if now.Before(r.expires) {
				kept = append(kept, r)
			}
		}
		if len(kept) == 0 {
			delete(x.owned, k)
		} else {
			x.owned[k] = kept
		}
	}
	for i, r := range rows {
		if i >= 128 {
			break
		}
		ip, err := netip.ParseAddr(r.Address)
		if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || !browserproxy.ValidPublicDNSName(r.Name) || r.TTL == 0 {
			continue
		}
		k := browserDNSKey{network, profile, ip.Unmap()}
		if len(x.owned) >= 1024 && len(x.owned[k]) == 0 {
			continue
		}
		ttl := time.Duration(r.TTL) * time.Second
		if ttl > 5*time.Minute {
			ttl = 5 * time.Minute
		}
		values := x.owned[k]
		found := false
		for j := range values {
			if values[j].name == r.Name {
				values[j].expires = now.Add(ttl)
				found = true
			}
		}
		if !found && len(values) < 8 {
			values = append(values, browserDNSObservation{r.Name, now.Add(ttl)})
		}
		x.owned[k] = values
	}
}

// Chrome sends a GREASE ECH extension in ordinary ClientHellos, so a googlevideo
// media name is usually only visible as "outer" SNI. When that name is a classified
// CDN subgroup and every DNS candidate for the IP is a non-protected YouTube name,
// the shared-IP ambiguity carries no other origin: bind the flow to the outer
// subgroup so the YouTube ladder (RELAY until a LOCAL trial proves itself) applies.
// Protected candidates, unclassified hosts and other sites keep the ambiguity.
func youtubeMediaOuterEvidence(e browserDomainEvidence) (browserDomainEvidence, bool) {
	outer := strings.ToLower(strings.TrimSuffix(e.Outer, "."))
	group := youtubeSubgroup(outer)
	if !e.Ambiguous || !browserproxy.ValidPublicDNSName(outer) || !strings.HasPrefix(group, "googlevideo:sn-") || protectedBrowserDomain(outer) {
		return e, false
	}
	listed := false
	for _, host := range e.Candidates {
		if protectedBrowserDomain(host) || !youtubeRelayDomain(host) {
			return e, false
		}
		listed = listed || strings.EqualFold(strings.TrimSuffix(host, "."), outer)
	}
	if !listed {
		return e, false
	}
	e.Domain = outer
	e.Ambiguous = false
	e.YoutubeOnly = true
	e.YoutubeSubgroup = group
	e.Source = "ECH_YOUTUBE_MEDIA_OUTER_IN_DNS_SET"
	e.Confidence = "outer SNI listed in YouTube-only DNS set; inner ECH not proven"
	return e, true
}
