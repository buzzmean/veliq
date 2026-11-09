package clientservice

import (
	"context"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
)

// One negative IP must not select RELAY before a healthy DNS peer. This branch
// only repairs failed ordinary AUTO origins; known DPI/RELAY floors, explicit
// rules, ambiguous hints, private addresses and configured DIRECT+ stay outside.
func (c *Controller) ordinaryAddressRetry(cur profilesResult, q browserproxy.Request, p browserproxy.Plan) bool {
	reason := ""
	switch {
	case browserproxy.KnownDoHEndpoint(q.Host, p.Destination):
		reason = "DOH_RELAY_RESERVED"
	case !cur.enabled || cur.routingDisabled:
		reason = "OPTIMIZATION_DISABLED"
	case !browserAuto(cur.profile) && !automaticApplication(cur.profile):
		reason = "NOT_BROWSER_AUTO"
	case q.OriginAmbiguous:
		reason = "AMBIGUOUS_DOMAIN_NO_DNS_RETARGET"
	case !q.Secure:
		reason = "NOT_TLS_REQUEST"
	case q.Port != 443:
		reason = "NOT_HTTPS443"
	case !p.Enabled:
		reason = "PLAN_NOT_ENABLED"
	case !p.Destination.Addr().Is4() || !browserproxy.PublicDNSAddress(p.Destination.Addr()):
		reason = "NO_PUBLIC_IPV4_DESTINATION"
	case !localBrowserRequestEligible(q, p):
		reason = "REQUEST_OR_POLICY_SCOPE_EXCLUDED"
	case c.browserOriginPolicy(q.Host).Kind != "":
		reason = "KNOWN_DPI_OR_RELAY_GROUP"
	case p.Policy.Action == flowpolicy.DirectPlus:
		reason = "CONFIGURED_LOCAL_RETAINED"
	}
	if _, explicit := flowpolicy.Evaluate(cur.profile.Rules, flowpolicy.Input{Protocol: "tcp", Destination: p.Destination, Domain: q.Host, Network: cur.network}); explicit {
		reason = "EXPLICIT_RULE_RETAINED"
	}
	failed := c.directAddressFailed(cur, q, p) || p.Policy.Source == "direct_timeout_cache" || p.Policy.Action == flowpolicy.RelayRequired
	if reason != "" {
		if failed && browserproxy.ValidPublicDNSName(q.Host) && c.browserOriginPolicy(q.Host).Kind == "" {
			c.browser.youtube.ordinaryDenied(cur, q, p, reason)
		}
		return false
	}
	if failed {
		return true
	}
	_, cached := c.steerTimedOutOrigin(p, cur, q, time.Now())
	return cached
}

type ordinaryAddressEvidence struct {
	Address, Stage, Result string
	TX, RX                 uint64
	FirstWriteAt           time.Time
}
type ordinaryFlowEvidence struct {
	ID                                         uint64
	Host, Profile, Network, Stage, Reason, DNS string
	Updated                                    time.Time
	Addresses                                  []ordinaryAddressEvidence
}

func (r *youtubeRuntime) ordinaryUpdate(id uint64, update func(*ordinaryFlowEvidence)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.ordinary {
		if r.ordinary[i].ID == id {
			update(&r.ordinary[i])
			r.ordinary[i].Updated = time.Now()
			return
		}
	}
}
func (c *Controller) openOrdinaryAddresses(ctx context.Context, cur profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) (net.Conn, browserproxy.Plan, error) {
	cur = c.captureAutomaticScope(cur)
	if !c.automaticScopeCurrent(cur) {
		return nil, p, errAutomaticScopeChanged
	}
	open = c.automaticScopedOpen(cur, open)
	candidates := []netip.AddrPort{}
	add := func(a netip.AddrPort) {
		if len(candidates) >= 2 || !a.IsValid() || !a.Addr().Is4() || !browserproxy.PublicDNSAddress(a.Addr()) || a.Port() != q.Port {
			return
		}
		for _, old := range candidates {
			if a == old {
				return
			}
		}
		if rule, explicit := flowpolicy.Evaluate(cur.profile.Rules, flowpolicy.Input{Protocol: "tcp", Destination: a, Domain: q.Host, Network: cur.network}); explicit && rule.Action != flowpolicy.Direct {
			return
		}
		candidates = append(candidates, a)
	}
	add(p.Destination)
	for _, a := range p.DirectCandidates {
		add(a)
	}
	for _, a := range p.RelayCandidates {
		add(a)
	}
	dns := "PLANNER_DNS_CANDIDATES"
	if len(candidates) < 2 {
		lookup, stop := context.WithTimeout(ctx, 500*time.Millisecond)
		resolver := c.BrowserResolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		addresses, e := resolver.LookupNetIP(lookup, "ip4", q.Host)
		stop()
		dns = "BOUNDED_SYSTEM_DNS_IPV4"
		if e != nil {
			dns = "SYSTEM_DNS_UNAVAILABLE_NO_INVENTED_ADDRESS"
		}
		for _, a := range addresses {
			add(netip.AddrPortFrom(a.Unmap(), q.Port))
		}
	}
	if ctx.Err() != nil {
		return nil, p, ctx.Err()
	}
	if !c.automaticScopeCurrent(cur) {
		return nil, p, errAutomaticScopeChanged
	}
	// p.Destination was eligible and remains first. No IP/subnet pin is introduced.
	p.DirectCandidates = candidates
	p.Policy = flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailBlock, Source: "ordinary_direct_first", Reason: "Ordinary AUTO: try DNS IPv4 peers before LOCAL/authenticated RELAY; address negatives expire in 10min"}
	p.Probe = "ORDINARY_DIRECT_DNS_FIRST_FLIGHT"
	r := c.browser.youtube
	r.mu.Lock()
	r.ordinarySeq++
	id := r.ordinarySeq
	row := ordinaryFlowEvidence{ID: id, Host: q.Host, Profile: cur.profile.ID, Network: cur.network, DNS: dns, Stage: "DIRECT", Reason: "TRY_DNS_PEERS_BEFORE_LADDER", Updated: time.Now()}
	for _, a := range candidates {
		result := "NOT_TRIED"
		key := c.directTimeoutKey(cur, q, browserproxy.RetargetOrigin(p, a))
		if c.browser.directTimeouts.AddressFailed(key, time.Now()) {
			result = "CACHED_DIRECT_FAILURE_TTL10MIN"
		}
		row.Addresses = append(row.Addresses, ordinaryAddressEvidence{Address: a.String(), Stage: "DIRECT", Result: result})
	}
	r.ordinary = append(r.ordinary, row)
	if len(r.ordinary) > 32 {
		r.ordinary = append([]ordinaryFlowEvidence(nil), r.ordinary[len(r.ordinary)-32:]...)
	}
	r.mu.Unlock()
	observed := func(work context.Context, request browserproxy.Request, actual browserproxy.Plan) (net.Conn, error) {
		stage := "DIRECT"
		if actual.Policy.Action == flowpolicy.DirectPlus {
			stage = "LOCAL"
		}
		if actual.Policy.Action == flowpolicy.RelayRequired {
			stage = "RELAY"
		}
		address := actual.Destination.String()
		conn, e := open(work, request, actual)
		if stage == "DIRECT" {
			r.mu.Lock()
			r.ordinaryDirectAttempts++
			r.mu.Unlock()
		}
		r.ordinaryUpdate(id, func(v *ordinaryFlowEvidence) {
			// Poll deadlines are not failure proof. Only the stepper's recorded
			// negative verdict can label a prior silent first flight as failed.
			for i := range v.Addresses {
				a := &v.Addresses[i]
				if a.Stage != "DIRECT" || (a.Result != "TLS_WAITING_NO_REPLY" && a.Result != "TLS_FIRST_FLIGHT_SILENT") {
					continue
				}
				if ip, err := netip.ParseAddrPort(a.Address); err == nil && c.directAddressFailed(cur, q, browserproxy.RetargetOrigin(p, ip)) {
					a.Result = "TLS_FIRST_FLIGHT_FAILED_NEGATIVE_TTL"
				}
			}
			v.Stage = stage
			v.Reason = "DIRECT_DNS_PEER_SELECTED"
			if stage != "DIRECT" {
				v.Reason = "DIRECT_DNS_CANDIDATES_FAILED_OR_CACHED; " + actual.Probe
			}
			at := -1
			for i := range v.Addresses {
				if v.Addresses[i].Address == address && v.Addresses[i].Stage == stage {
					at = i
					break
				}
			}
			if at < 0 && len(v.Addresses) < 4 {
				v.Addresses = append(v.Addresses, ordinaryAddressEvidence{Address: address, Stage: stage})
				at = len(v.Addresses) - 1
			}
			if at >= 0 {
				v.Addresses[at].Result = "TCP_OPEN_WAITING_TLS"
				if e != nil {
					v.Addresses[at].Result = "TCP_OPEN_FAILED"
				}
			}
		})
		if e != nil {
			return conn, e
		}
		return &ordinaryEvidenceConn{Conn: conn, r: r, id: id, address: address, stage: stage}, nil
	}
	// Reuse the already-tested launcher address stepper unchanged: <=2 IPv4,
	// 900ms first flights/3s budget, per-address TTL, complete ClientHello replay
	// only before ANY origin byte. Riot profile/scope/guards are not modified.
	return c.openRiotPlan(ctx, cur, q, p, observed)
}

type ordinaryEvidenceConn struct {
	net.Conn
	r              *youtubeRuntime
	id             uint64
	address, stage string
	wire           browserproxy.TLSWireObserver
}

func (c *ordinaryEvidenceConn) update(tx, rx uint64, e error) {
	wire := c.wire.Snapshot().Origin
	c.r.ordinaryUpdate(c.id, func(v *ordinaryFlowEvidence) {
		for i := range v.Addresses {
			a := &v.Addresses[i]
			if a.Address != c.address || a.Stage != c.stage {
				continue
			}
			a.TX += tx
			a.RX += rx
			if tx > 0 && a.FirstWriteAt.IsZero() {
				a.FirstWriteAt = time.Now()
			}
			switch {
			case isTCPReset(e):
				a.Result = "REMOTE_RST_NO_REPLAY"
			case wire.AlertLevel != 0:
				a.Result = "TLS_ALERT_NO_REPLAY"
			case wire.State == "NON_TLS_OR_INVALID_HEADER":
				a.Result = "INVALID_TLS_NO_REPLAY"
			case wire.ServerHelloComplete:
				a.Result = "TLS_SERVER_HELLO; NOT_HTTP_PROOF"
			case e == io.EOF && wire.Bytes > 0:
				a.Result = "EOF_AFTER_ORIGIN_BYTES_NO_REPLAY"
			case e == io.EOF:
				a.Result = "EOF_BEFORE_ORIGIN_REPLY"
			case isYoutubeTimeout(e) && a.TX > 0 && wire.Bytes == 0:
				a.Result = "TLS_WAITING_NO_REPLY"
				if !a.FirstWriteAt.IsZero() && time.Since(a.FirstWriteAt) >= 900*time.Millisecond {
					a.Result = "TLS_FIRST_FLIGHT_SILENT"
				}
			case wire.Bytes > 0:
				a.Result = "ORIGIN_BYTES_NO_REPLAY"
			}
		}
	})
}
func (c *ordinaryEvidenceConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	c.update(uint64(n), 0, e)
	return n, e
}
func (c *ordinaryEvidenceConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	c.wire.ObserveOrigin(p[:n])
	c.update(0, uint64(n), e)
	return n, e
}
func (c *ordinaryEvidenceConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return nil
}

func (c *ordinaryEvidenceConn) OriginAttempts() browserproxy.OriginReport {
	if v, ok := c.Conn.(browserproxy.OriginReporter); ok {
		return v.OriginAttempts()
	}
	return browserproxy.OriginReport{Selected: c.address, State: "ORDINARY_" + c.stage}
}

// Metadata only: a rejected route scope must be visible instead of silently
// pretending that a DNS peer was tried. Never loosen ambiguous/protected policy.
func (r *youtubeRuntime) ordinaryDenied(cur profilesResult, q browserproxy.Request, p browserproxy.Plan, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ordinaryDenials++
	r.ordinarySeq++
	r.ordinary = append(r.ordinary, ordinaryFlowEvidence{ID: r.ordinarySeq, Host: q.Host, Profile: cur.profile.ID, Network: cur.network, Stage: string(p.Policy.Action), Reason: reason, DNS: "NO_DNS_RETARGET", Updated: time.Now(), Addresses: []ordinaryAddressEvidence{{Address: p.Destination.String(), Stage: string(p.Policy.Action), Result: "NOT_TRIED; " + reason}}})
	if len(r.ordinary) > 32 {
		r.ordinary = append([]ordinaryFlowEvidence(nil), r.ordinary[len(r.ordinary)-32:]...)
	}
}
