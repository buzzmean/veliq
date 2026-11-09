package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/security"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func (c *Controller) browserDNSKey(q browserproxy.Request, current profilesResult) string {
	k := c.learnKey(current.profile, current.network, "tcp", q.Host, q.Port)
	k.Revision += ":dns:" + current.profile.RelayID
	if q.Secure {
		k.Revision += ":https"
	} else {
		k.Revision += ":http"
	}
	return browserproxy.DNSCacheKey(k)
}
func browserDNSPolicy(current profilesResult) flowpolicy.Result {
	relay := current.profile.RelayID
	if relay == "" {
		relay = "VPS-01"
	}
	return flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: relay, Fallback: flowpolicy.Required, Source: "browser_dns_recovered", Reason: "alternative DNS address authenticated by TLS/HTTP through relay; page success not inferred"}
}

// Shared by initial requests and waiters of the original per-origin planner.
// A successful DNS recovery invalidates the ordinary learner, so waiters must
// consult this independent TTL cache before falling back to an unverified IP.
func (c *Controller) browserDNSCachedPlan(q browserproxy.Request, current profilesResult) (browserproxy.Plan, bool) {
	if current.enabled && current.network != "" && q.Secure {
		if cached, ok := c.browser.dns.Lookup(c.browserDNSKey(q, current), time.Now()); ok && cached.Usable() {
			result := c.browserFlow(current.profile, current.id, wp.Tuple{Protocol: "tcp", Source: q.Source, Destination: cached.Destination}, q.Host, current.network)
			if result.Action != flowpolicy.Block && result.Source != "rule" && result.Action != flowpolicy.DirectPlus {
				return browserproxy.Plan{Network: current.network, Enabled: current.enabled, Policy: browserDNSPolicy(current), Destination: cached.Destination, Probe: cached.ProbeName(), HTTPStatus: cached.Probe.Status, DNSRecovery: &cached}, true
			}
		}
	}
	return browserproxy.Plan{}, false
}

func (c *Controller) recoverBrowserDNS(ctx context.Context, q browserproxy.Request, current profilesResult, plan browserproxy.Plan) (browserproxy.Plan, bool) {
	current = c.captureAutomaticScope(current)
	if !c.automaticScopeCurrent(current) {
		return plan, false
	}
	if !q.Secure || !current.enabled || current.network == "" || !browserproxy.ValidPublicDNSName(q.Host) {
		return plan, false
	}
	// Respect explicit domain policy before even issuing recovery traffic.
	policyDestination := plan.Destination
	if !policyDestination.IsValid() {
		policyDestination = netip.AddrPortFrom(netip.IPv4Unspecified(), q.Port)
	}
	existing := c.browserFlow(current.profile, current.id, wp.Tuple{Protocol: "tcp", Source: q.Source, Destination: policyDestination}, q.Host, current.network)
	if existing.Action == flowpolicy.Block || existing.Action == flowpolicy.DirectPlus || existing.Source == "rule" && existing.Action != flowpolicy.RelayRequired {
		return plan, false
	}
	plan.Policy = browserDNSPolicy(current)
	if existing.Source == "rule" && existing.Action == flowpolicy.RelayRequired {
		plan.Policy = existing
	}
	lookup := c.BrowserAlternativeDNS
	if lookup == nil {
		lookup = browserproxy.NewDoHResolver().Lookup
	}
	var scopeCurrent func() bool
	if automaticApplication(current.profile) {
		scopeCurrent = func() bool { return c.automaticScopeCurrent(current) }
	}
	open := c.automaticScopedOpen(current, c.browserOpenUnobserved)
	result := c.browser.dns.RecoverScoped(ctx, c.browserDNSKey(q, current), q.Host, q.Port, c.BrowserProbeRoots, lookup, func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		candidate := plan
		candidate.Destination = dst
		return open(ctx, q, candidate)
	}, scopeCurrent)
	plan.DNSRecovery = &result
	plan.Trials = append(plan.Trials, result.Trials...)
	if !result.Usable() || !c.automaticScopeCurrent(current) {
		return plan, false
	}
	// Ownership/policy/network must still match after all independent probes.
	after, err := c.browserProfile(q.Owner)
	if err != nil || after.network != current.network || after.enabled != current.enabled || c.browserDNSKey(q, after) != c.browserDNSKey(q, current) {
		return plan, false
	}
	// Remove any longer-lived ordinary learner entry on ALL recovery paths,
	// including system lookup failure. It must not resurrect after DNS TTL expiry.
	learned := c.learnKey(current.profile, current.network, "tcp", q.Host, q.Port)
	if q.Secure {
		learned.Revision += ":https"
	} else {
		learned.Revision += ":http"
	}
	c.browser.learned.Forget(learned)
	plan.Destination = result.Destination
	plan.HTTPStatus = result.Probe.Status
	plan.Probe = result.ProbeName()
	return plan, true
}

// Owner-authenticated IPC only. Fixed GET /, public host/IPs, HTTPS/443, relay-only,
// no credentials/cookies/paths accepted, and no profile/OS/VPS mutation. Evidence
// is a service-origin transport check, never Chrome/capture or whole-site PASS.
func (c *Controller) checkBrowserOrigin(ctx context.Context, raw json.RawMessage) (any, error) {
	var q struct {
		Host       string   `json:"host"`
		Candidates []string `json:"candidates"`
		Relay      string   `json:"relay_id"`
	}
	if err := security.Parse(raw, &q); err != nil {
		return nil, err
	}
	if !browserproxy.ValidPublicDNSName(q.Host) || len(q.Candidates) < 1 || len(q.Candidates) > 3 {
		return nil, errors.New("public DNS hostname and 1..3 public IP candidates required")
	}
	destinations := []netip.AddrPort{}
	seen := map[netip.Addr]bool{}
	for _, value := range q.Candidates {
		ip, err := netip.ParseAddr(value)
		ip = ip.Unmap()
		if err != nil || !browserproxy.PublicDNSAddress(ip) || seen[ip] {
			return nil, errors.New("unique public IPv4 candidates required")
		}
		seen[ip] = true
		destinations = append(destinations, netip.AddrPortFrom(ip, 443))
	}
	if q.Relay == "" {
		q.Relay = "VPS-01"
	}
	if len(q.Relay) > 128 || strings.ContainsAny(q.Relay, "\r\n") {
		return nil, errors.New("invalid relay ID")
	}
	select {
	case c.browser.probes <- struct{}{}:
		defer func() { <-c.browser.probes }()
	default:
		return nil, errors.New("bounded origin check capacity")
	}
	bounded, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	// Reserve a real local tuple only for the engine's diagnostic bookkeeping.
	// It is not represented as a captured Chrome socket or a source-IP observation.
	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer reserved.Close()
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	policy := &routing.Policy{Route: routing.Route{RelayID: q.Relay}, BlockOnFailure: true}
	rows := []map[string]any{}
	for _, dst := range destinations {
		started := time.Now()
		probe, cancel := context.WithTimeout(bounded, 1500*time.Millisecond)
		result := browserproxy.ProbeOriginDetailed(probe, q.Host, 443, true, nil, func(ctx context.Context) (net.Conn, error) {
			return c.Engine.OpenTCP(ctx, routing.Flow{Protocol: "tcp", Source: reserved.Addr().(*net.TCPAddr).AddrPort(), Destination: dst, PID: uint32(os.Getpid()), ProcessPath: exe, ApplicationID: "browser-origin-check", PinnedPolicy: policy})
		})
		cancel()
		rows = append(rows, map[string]any{"destination": dst.String(), "relay_id": q.Relay, "route": "RELAY_REQUIRED", "duration_ms": time.Since(started).Milliseconds(), "origin": result, "origin_verified": result.Failure == "" && result.Status >= 200 && result.Status < 400 && result.Bytes > 0})
	}
	return map[string]any{"scope": "service-origin HTTPS transport; not Chrome or complete-site acceptance", "sni": q.Host, "certificate_verification": true, "candidates": rows}, nil
}
