package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/transport"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func nativeBrowserProfile(p profiles.Profile) bool {
	return p.BrowserTransport == "native" && p.Mode == profiles.Auto && p.Trial == nil && (chromeProfile(p) || edgeProfile(p))
}

func (c *Controller) nativeBackendReady() bool {
	if c.Backend == nil {
		return false
	}
	s := c.Backend.Status()
	return s.Ready && s.Capabilities.IPv4 && s.Capabilities.TCP && s.Capabilities.Transparent
}
func (c *Controller) nativeBackendConfigured() bool {
	if c.Backend == nil {
		return false
	}
	s := c.Backend.Status()
	return s.Capabilities.IPv4 && s.Capabilities.TCP && s.Capabilities.Transparent
}

type nativeBrowserProfileStatus struct {
	NativeOnly      nativeIngressMetrics `json:"native_only"`
	PACUpstream     nativeIngressMetrics `json:"pac_native_upstream"`
	Accepted        uint64               `json:"accepted"`
	Opened          uint64               `json:"opened"`
	Failed          uint64               `json:"failed"`
	Sent            uint64               `json:"sent_bytes"`
	Received        uint64               `json:"received_bytes"`
	AfterFlow       uint64               `json:"-"`
	Profile         string               `json:"profile_id"`
	Activated       time.Time            `json:"activated_at"`
	FirstOpened     time.Time            `json:"first_tunnel_opened_at,omitzero"`
	FirstExchange   time.Time            `json:"first_bidirectional_exchange_at,omitzero"`
	FirstOpenMS     int64                `json:"enable_to_first_open_ms"`
	FirstExchangeMS int64                `json:"enable_to_first_exchange_ms"`
}
type nativeBrowserRecord struct {
	planReporter    browserproxy.PlanReporter
	OriginPreflight *browserproxy.DNSRecoveryResult `json:"origin_preflight,omitempty"`
	DomainEvidence  *browserDomainEvidence          `json:"domain_evidence,omitempty"`
	Origin          *browserproxy.OriginReport      `json:"origin_attempts,omitempty"`
	originReporter  browserproxy.OriginReporter
	TLS             *browserproxy.TLSWireEvidence `json:"tls_wire,omitempty"`
	tlsWire         *browserproxy.TLSWireObserver
	Ingress         string             `json:"ingress"`
	ID              uint64             `json:"id"`
	Owner           browserproxy.Owner `json:"owner"`
	Started         time.Time          `json:"started"`
	Domain          string             `json:"domain"`
	Destination     string             `json:"destination"`
	Upstream        string             `json:"upstream_destination"`
	Policy          flowpolicy.Result  `json:"policy"`
	Probe           string             `json:"origin_probe"`
	Result          string             `json:"result"`
	Failure         string             `json:"failure_reason,omitempty"`
	Sent            uint64             `json:"sent_bytes"`
	Received        uint64             `json:"received_bytes"`
	Active          bool               `json:"active"`
}
type nativeBrowserSnapshot struct {
	HTTP80       http80Snapshot  `json:"http80_local"`
	YoutubeLocal youtubeSnapshot `json:"youtube_local_ladder"`
	DNS          map[string]any  `json:"browser_dns"`

	DomainCache        map[string]any               `json:"domain_cache"`
	CaptureIngress     *wp.CaptureIngressSnapshot   `json:"capture_ingress,omitempty"`
	State              string                       `json:"state"`
	Reason             string                       `json:"reason"`
	ConfiguredProfiles int                          `json:"configured_profiles"`
	Guard              string                       `json:"guard"`
	NativeOnlyState    string                       `json:"native_only_state"`
	NativeOnlyAutoMode string                       `json:"native_only_auto_mode"`
	NativeOnly         nativeIngressCounters        `json:"native_only_totals"`
	PACUpstream        nativeIngressCounters        `json:"pac_native_upstream_totals"`
	RelayUsage         relayUsageSnapshot           `json:"relay_usage"`
	Version            int                          `json:"version"`
	Ready              bool                         `json:"capture_ready"`
	Enabled            bool                         `json:"optimizing"`
	ExistingTCP        string                       `json:"existing_tcp"`
	PageVerification   string                       `json:"page_verification"`
	Profiles           []nativeBrowserProfileStatus `json:"profiles"`
	Records            []nativeBrowserRecord        `json:"records"`
	Lost               uint64                       `json:"lost"`
	Truncated          bool                         `json:"truncated"`
}
type nativeBrowserRuntime struct {
	mu         sync.Mutex
	next, lost uint64
	profiles   map[string]nativeBrowserProfileStatus
	records    map[uint64]nativeBrowserRecord
}

func (n *nativeBrowserRuntime) activate(id string, reset bool) { n.activateAt(id, reset, time.Now()) }
func (n *nativeBrowserRuntime) activateAt(id string, reset bool, at time.Time) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.profiles == nil {
		n.profiles = map[string]nativeBrowserProfileStatus{}
	}
	if _, ok := n.profiles[id]; (reset || !ok) && (ok || len(n.profiles) < 128) {
		n.profiles[id] = nativeBrowserProfileStatus{NativeOnly: newIngressMetrics(), PACUpstream: newIngressMetrics(), Profile: id, AfterFlow: n.next, Activated: at, FirstOpenMS: -1, FirstExchangeMS: -1}
	}
}
func (c *Controller) nativeBrowserActivation(enabled, wasEnabled bool, at time.Time) {
	if enabled && !wasEnabled {
		for _, p := range c.Profiles.List() {
			if nativeBrowserProfile(p) {
				c.browser.native.activateAt(p.ID, true, at)
			}
		}
	}
}
func (c *Controller) nativeSnapshot() nativeBrowserSnapshot {
	s := nativeBrowserSnapshot{YoutubeLocal: c.browser.youtube.snapshot(), NativeOnlyState: "NATIVE_ONLY_NOT_OBSERVED", NativeOnlyAutoMode: "AUTOMATIC_NATIVE_NEW_CONNECTIONS_NO_PAC_DEPENDENCY", Version: 1, Ready: c.nativeBackendReady(), ExistingTCP: "PINNED_UNTIL_CLOSED; reload may reuse HTTP/2", PageVerification: "NOT_OBSERVED; bidirectional bytes are not HTTPS/page PASS", Profiles: []nativeBrowserProfileStatus{}, Records: []nativeBrowserRecord{}}
	s.HTTP80 = c.browser.http80.snapshot()
	c.mu.Lock()
	s.Enabled = c.enabled
	c.mu.Unlock()
	s.Guard = "PROCESS_CAPTURE_ONLY; no independent kernel crash guard"
	for _, p := range c.Profiles.List() {
		if nativeBrowserProfile(p) {
			s.ConfiguredProfiles++
		}
	}
	s.State = "PREPARING"
	s.Reason = "NATIVE_CAPTURE_NOT_READY"
	c.mu.Lock()
	automatic := c.settings.Automatic
	c.mu.Unlock()
	switch {
	case !s.Enabled || !automatic:
		s.State = "DISABLED"
		s.Reason = "OPTIMIZATION_DISABLED"
	case !c.activationNetworkAllowed():
		s.Reason = "ACTIVATION_REQUIRED"
	case s.ConfiguredProfiles == 0:
		s.Reason = "BROWSER_PROFILES_PENDING"
	case !s.Ready:
		s.Reason = "NATIVE_CAPTURE_NOT_READY"
	case !c.relayConnected():
		s.Reason = "RELAY_NOT_CONNECTED"
	default:
		s.State = "READY_NEW_CONNECTIONS"
		s.Reason = "NATIVE_CAPTURE_ARMED; PAGE_NOT_VERIFIED"
	}
	if backend, ok := c.Backend.(interface {
		CaptureIngressStatus() wp.CaptureIngressSnapshot
	}); ok {
		v := backend.CaptureIngressStatus()
		s.CaptureIngress = &v
	}
	s.RelayUsage = c.relayUsage().snapshot()
	s.DomainCache = c.browser.domains.snapshot()
	s.DNS = c.browser.dnsWire.snapshot()
	n := &c.browser.native
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, p := range n.profiles {
		s.Profiles = append(s.Profiles, p)
		addIngress(&s.NativeOnly, p.NativeOnly.nativeIngressCounters)
		addIngress(&s.PACUpstream, p.PACUpstream.nativeIngressCounters)
	}
	if s.NativeOnly.Exchanges > 0 {
		s.NativeOnlyState = "NATIVE_ONLY_OBSERVED"
	}
	sort.Slice(s.Profiles, func(i, j int) bool { return s.Profiles[i].Profile < s.Profiles[j].Profile })
	for _, r := range n.records {
		if r.planReporter != nil {
			v := r.planReporter.CurrentPlan()
			r.Policy = v.Policy
			r.Probe = v.Probe
			r.Upstream = v.Destination.String()
		}
		if r.originReporter != nil {
			v := r.originReporter.OriginAttempts()
			r.Origin = &v
			if v.Selected != "" {
				r.Upstream = v.Selected
			}
		}
		if r.tlsWire != nil {
			v := r.tlsWire.Snapshot()
			r.TLS = &v
		}
		s.Records = append(s.Records, r)
	}
	sort.Slice(s.Records, func(i, j int) bool { return s.Records[i].ID > s.Records[j].ID })
	if len(s.Records) > 48 {
		s.Records = s.Records[:48]
		s.Truncated = true
	}
	s.Lost = n.lost
	s.Truncated = s.Truncated || n.lost > 0
	for {
		raw, _ := json.Marshal(s)
		if len(raw) <= 60*1024 {
			break
		}
		switch {
		case len(s.YoutubeLocal.Records) > 0:
			s.YoutubeLocal.Records = s.YoutubeLocal.Records[:len(s.YoutubeLocal.Records)-1]
			s.YoutubeLocal.RecordsOmitted++
		// LOCAL trial admission is only visible in the YouTube cache rows: keep
		// them over the oldest native records, which stay at 16 or more.
		case len(s.Records) > 16:
			s.Records = s.Records[:len(s.Records)-1]
		case len(s.YoutubeLocal.Cache) > 0:
			s.YoutubeLocal.Cache = s.YoutubeLocal.Cache[:len(s.YoutubeLocal.Cache)-1]
			s.YoutubeLocal.CacheOmitted++
		case len(s.Records) > 0:
			s.Records = s.Records[:len(s.Records)-1]
		case len(s.RelayUsage.VideoConnections) > 0:
			s.RelayUsage.VideoConnections = s.RelayUsage.VideoConnections[:len(s.RelayUsage.VideoConnections)-1]
			s.RelayUsage.VideoOmitted++
			s.RelayUsage.Truncated = true
		case len(s.RelayUsage.Minutes) > 0:
			s.RelayUsage.Minutes = s.RelayUsage.Minutes[:len(s.RelayUsage.Minutes)-1]
			s.RelayUsage.Truncated = true
		case len(s.RelayUsage.ActiveOrigins) > 0:
			s.RelayUsage.ActiveOrigins = s.RelayUsage.ActiveOrigins[:len(s.RelayUsage.ActiveOrigins)-1]
			s.RelayUsage.Truncated = true
		case s.CaptureIngress != nil && len(s.CaptureIngress.Records) > 0:
			s.CaptureIngress.Records = s.CaptureIngress.Records[1:]
			s.CaptureIngress.Lost++
		case len(s.Profiles) > 0:
			s.Profiles = s.Profiles[:len(s.Profiles)-1]
		default:
			return s
		}
		s.Truncated = true
	}
	return s
}

func (c *Controller) handleNativeBrowser(ctx context.Context, method string, raw json.RawMessage) (_ any, retErr error) {
	if method == "browser.native.status" {
		return c.nativeSnapshot(), nil
	}
	activationStarted := time.Now()
	var q struct {
		Profile       string `json:"profile_id"`
		Compatibility bool   `json:"compatibility"`
	}
	if err := security.Parse(raw, &q); err != nil {
		return nil, err
	}
	if c.BrowserOwnerSID == "" && !c.Demo {
		return nil, errors.New("NATIVE_OWNER_SID_REQUIRED")
	}
	c.mu.Lock()
	automatic := c.settings.Automatic
	enabled := c.enabled
	c.mu.Unlock()
	if !enabled {
		return nil, errors.New("NATIVE_OPTIMIZATION_DISABLED")
	}
	if !automatic {
		return nil, errors.New("NATIVE_AUTOMATIC_DISABLED")
	}
	var p profiles.Profile
	found := false
	for _, v := range c.Profiles.List() {
		if v.ID == q.Profile {
			p = v
			found = true
			break
		}
	}
	if !found || (!chromeProfile(p) && !edgeProfile(p)) || p.Trial != nil || (p.Mode != profiles.Direct && p.Mode != profiles.Auto) {
		return nil, errors.New("NATIVE_BROWSER_PROFILE_REQUIRED")
	}
	defer func() {
		if edgeProfile(p) {
			c.browser.mu.Lock()
			defer c.browser.mu.Unlock()
			e := c.edgeLocked()
			if retErr != nil {
				e.lastError = "browser.native.enable: " + nativeFailureCode(retErr)
			} else {
				e.lastError = ""
			}
		}
	}()
	if !c.activationNetworkAllowed() {
		return nil, errors.New("ACTIVATION_REQUIRED")
	}
	if err := c.nativeGuardReady(p); err != nil {
		return nil, err
	}
	if c.Backend == nil {
		return nil, errors.New("NATIVE_CAPTURE_NOT_CONFIGURED")
	}
	// Prepare capture before publishing native AUTO. Failure preserves the old
	// profile/PAC; it must never produce a DIRECT authorization for protected data.
	if !c.nativeBackendReady() {
		// Backend recovery must not hot-reset this browser while it still has
		// its legacy/pending profile. Pin only its TCP during prepare; after
		// publication the profile itself supplies NewConnectionsOnly.
		var preparing atomic.Bool
		preparing.Store(true)
		defer preparing.Store(false)
		classify := func(id wp.ProcessIdentity, t wp.Tuple) wp.Decision {
			d := c.Classify(id, t)
			if preparing.Load() && t.Protocol == "tcp" && d.Flow.ApplicationID == p.ID {
				d.NewConnectionsOnly = true
			}
			return d
		}
		if err := c.Backend.Start(c.ctx, classify); err != nil {
			return nil, errors.New("NATIVE_CAPTURE_START_FAILED")
		}
	}
	if !c.nativeBackendReady() {
		return nil, errors.New("NATIVE_CAPTURE_NOT_READY")
	}
	old := p
	p.Mode = profiles.Auto
	p.BrowserTransport = "native"
	if edgeProfile(p) && p.AppPreset == "edge-sites-pending" {
		p.AppPreset = "edge-sites"
	}
	prepareAuto(&p)
	if err := p.Validate(); err != nil {
		return nil, err
	}
	c.browser.native.activateAt(p.ID, false, activationStarted)
	if !reflect.DeepEqual(old, p) {
		publish := func() error {
			// Do not use legacy Reconfigure: it aborts established TCP.
			if err := c.Profiles.Upsert(p); err != nil {
				return err
			}
			c.mu.Lock()
			previous, had := c.localProfiles[p.ID]
			c.localProfiles[p.ID] = p
			c.mu.Unlock()
			c.syncPolicies()
			if err := c.saveProfiles(); err != nil {
				_ = c.Profiles.Upsert(old)
				c.mu.Lock()
				if had {
					c.localProfiles[p.ID] = previous
				} else {
					delete(c.localProfiles, p.ID)
				}
				c.mu.Unlock()
				c.syncPolicies()
				return errors.New("NATIVE_PROFILE_PERSIST_FAILED")
			}

			return nil
		}
		var err error
		if backend, ok := c.Backend.(interface {
			ReconfigureNewConnections(string, func() error) error
		}); ok {
			err = backend.ReconfigureNewConnections(p.ID, publish)
		} else {
			err = publish()
		}
		if err != nil {
			return nil, err
		}
	}
	c.browser.native.activate(p.ID, false)
	compat, err := c.nativeBrowserCompatibility(p, q.Compatibility)
	if err != nil {
		return nil, err
	} // Native fail-closed capture remains armed on PAC repair failure.
	return map[string]any{"native": true, "capture_ready": true, "profile_id": p.ID, "profiles": c.Profiles.List(), "compatibility": compat, "existing_tcp": "PINNED_UNTIL_CLOSED"}, nil
}

func (n *nativeBrowserRuntime) begin(q browserproxy.Request, t wp.Tuple) (uint64, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.records == nil {
		n.records = map[uint64]nativeBrowserRecord{}
	}
	if len(n.records) >= 512 {
		old := uint64(0)
		for id, r := range n.records {
			if !r.Active && (old == 0 || id < old) {
				old = id
			}
		}
		if old == 0 {
			n.lost++
			return 0, errors.New("NATIVE_EVIDENCE_CAPACITY")
		}
		delete(n.records, old)
		n.lost++
	}
	n.next++
	domain := q.Host
	if domain == "" {
		domain = "<opaque>"
	}
	n.records[n.next] = nativeBrowserRecord{Ingress: q.Ingress, ID: n.next, Owner: q.Owner, Started: time.Now(), Domain: domain, Destination: t.Destination.String(), Result: "PLANNING", Active: true}
	p := n.profiles[q.Owner.Profile]
	if p.Profile != "" {
		p.Accepted++
		if path := p.ingress(q.Ingress); path != nil {
			path.Accepted++
		}
		n.profiles[q.Owner.Profile] = p
	}
	return n.next, nil
}
func (n *nativeBrowserRuntime) opened(id uint64, plan browserproxy.Plan, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, ok := n.records[id]
	if !ok {
		return
	}
	r.Policy = plan.Policy
	r.Upstream = plan.Destination.String()
	r.Probe = plan.Probe
	p := n.profiles[r.Owner.Profile]
	if err != nil {
		r.Active = false
		r.Result = "BLOCK"
		r.Failure = nativeFailureCode(err)
		p.Failed++
	} else {
		p.Opened++
		r.Result = "TUNNEL_OPENED"
		if !p.Activated.IsZero() && id > p.AfterFlow && p.FirstOpened.IsZero() {
			p.FirstOpened = time.Now()
			p.FirstOpenMS = p.FirstOpened.Sub(p.Activated).Milliseconds()
		}
	}
	if p.Profile != "" && id > p.AfterFlow {
		if path := p.ingress(r.Ingress); path != nil {
			if err != nil {
				path.Failed++
			} else {
				path.Opened++
				path.Active++
				if path.FirstOpened.IsZero() {
					path.FirstOpened = time.Now()
					path.FirstOpenMS = path.FirstOpened.Sub(p.Activated).Milliseconds()
				}
			}
		}
	}
	if p.Profile != "" {
		n.profiles[r.Owner.Profile] = p
	}
	n.records[id] = r
}
func (n *nativeBrowserRuntime) bytes(id uint64, tx, rx uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, ok := n.records[id]
	if !ok {
		return
	}
	wasExchange := r.Sent > 0 && r.Received > 0
	r.Sent += tx
	r.Received += rx
	p := n.profiles[r.Owner.Profile]
	if p.Profile != "" {
		p.Sent += tx
		p.Received += rx
		if id > p.AfterFlow {
			if path := p.ingress(r.Ingress); path != nil {
				path.Sent += tx
				path.Received += rx
				if !wasExchange && r.Sent > 0 && r.Received > 0 {
					path.Exchanges++
					if path.FirstExchange.IsZero() {
						path.FirstExchange = time.Now()
						path.FirstExchangeMS = path.FirstExchange.Sub(p.Activated).Milliseconds()
					}
				}
			}
		}
		n.profiles[r.Owner.Profile] = p
	}
	if r.Sent > 0 && r.Received > 0 && r.Failure == "" {
		r.Result = "BIDIRECTIONAL_EXCHANGE"
		p := n.profiles[r.Owner.Profile]
		if !p.Activated.IsZero() && id > p.AfterFlow && p.FirstExchange.IsZero() {
			p.FirstExchange = time.Now()
			p.FirstExchangeMS = p.FirstExchange.Sub(p.Activated).Milliseconds()
			n.profiles[r.Owner.Profile] = p
		}
	}
	n.records[id] = r
}
func (n *nativeBrowserRuntime) closed(id uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, ok := n.records[id]
	if ok {
		p := n.profiles[r.Owner.Profile]
		if r.Active && id > p.AfterFlow {
			if path := p.ingress(r.Ingress); path != nil && path.Active > 0 {
				path.Active--
				n.profiles[r.Owner.Profile] = p
			}
		}
		r.Active = false
		n.records[id] = r
	}
}

func (c *Controller) openNativeBrowser(ctx context.Context, p profiles.Profile, id wp.ProcessIdentity, t wp.Tuple, d wp.Decision, reason string) (net.Conn, wp.Decision, error) {
	d.BlockOnFailure = true // Owner/policy errors must not reach the legacy DIRECT fallback.
	// ResolveDomain was evaluated from this flow's actual ClientHello/Host.
	// ECH outer/DNS metadata remains explicitly a hint, not an inner SNI claim.
	if reason == "ECH_OUTER_SNI_ONLY" {
		d.OriginDomain = ""
	}
	if !wp.IsCurrent(id) {
		return nil, d, errors.New("NATIVE_OWNER_EXITED")
	}
	if c.BrowserOwnerSID != "" {
		sid, err := wp.ProcessUserSID(id)
		if err != nil || sid != c.BrowserOwnerSID {
			return nil, d, errors.New("NATIVE_OWNER_SID_MISMATCH")
		}
	}
	q := browserproxy.Request{Ingress: "NATIVE_TCP", Owner: browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: p.ID}, Source: t.Source, Host: d.OriginDomain, Port: t.Destination.Port(), Secure: reason != "HTTP_HOST" && reason != "HTTP_HOST_OTHER_PORT"}
	// Preserve ordinary HTTP on other ports, but never promote a mismatched
	// Host authority on TCP80 using the credential-free port-80 probe.
	q.OriginAmbiguous = q.Port == 80 && reason == "HTTP_HOST_OTHER_PORT"
	current, err := c.browserProfile(q.Owner)
	if err != nil || !current.enabled || !(nativeBrowserProfile(current.profile) || riotAuto(current.profile)) || c.policyRevision(p) != c.policyRevision(current.profile) {
		return nil, d, errors.New("NATIVE_PROFILE_CHANGED")
	}
	n := &c.browser.native
	if riotAuto(current.profile) {
		n = &c.browser.riot
	}
	n.activate(p.ID, false)
	record, err := n.begin(q, t)
	if err != nil {
		return nil, d, err
	}
	opaque := q.Host == ""
	q.HintOnly = opaque
	evidence := browserDomainEvidence{Source: "CLIENTHELLO_SNI_OR_HTTP_HOST", Domain: q.Host, Confidence: "observed on this connection", Candidates: []string{}}
	plan := browserproxy.Plan{Enabled: true, Network: current.network, Destination: t.Destination, Policy: d.Policy}
	secureDNS := browserproxy.KnownDoHEndpoint(q.Host, t.Destination)
	if opaque {
		evidence = c.browser.domains.profileEvidenceFor(current.network, p.ID, t.Destination.Addr(), d.OuterSNI, time.Now(), func(host string) bool { return c.browserOriginPolicy(host).Kind != "" })
		if browserproxy.KnownDoHEndpoint(evidence.Domain, t.Destination) {
			secureDNS = true
			evidence.Restricted = true
			evidence.Source = "KNOWN_DOH_RESOLVER"
			evidence.Confidence = "dedicated resolver address or hostname; encrypted question not observed"
		}
		q.Host = evidence.Domain
		if q.Host == "" && evidence.YoutubeOnly && len(evidence.Candidates) > 0 {
			q.Host = evidence.Candidates[0]
		}
		q.OriginAmbiguous = evidence.Ambiguous && !youtubeSameHintSubgroup(evidence)
		plan = c.nativeOpaquePlan(current.profile, t, current.network, evidence)
		if q.Host != "" {
			if steered, ok := c.steerTimedOutOrigin(plan, current, q, time.Now()); ok {
				plan = steered
			}
		}
		// Metadata may select a stricter relay route; it never enables DIRECT+ on
		// hidden SNI and never replaces an ordinary destination from a DNS hint.
		if plan.Policy.Action == flowpolicy.DirectPlus {
			plan.Policy = flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailOpen, Source: "browser_opaque_direct_default", Reason: "hidden SNI cannot authorize a local transform"}
		}
	} else if secureDNS {
		plan.Probe = "KNOWN_DOH_AUTHENTICATED_RELAY"
	} else {
		plan, err = c.browserPlan(ctx, q)
	}
	n.mu.Lock()
	r := n.records[record]
	r.DomainEvidence = &evidence
	if q.Host != "" {
		r.Domain = q.Host
	}
	n.records[record] = r
	n.mu.Unlock()
	if err == nil && plan.Policy.Action == flowpolicy.DirectPlus {
		// Keep delegation/evidence bound to the original native tuple. No DNS/IP
		// change may splice a configured local transform into a different flow.
		plan.Destination = t.Destination
	}
	if err == nil && !secureDNS && opaque && !youtubeLadderEligible(q, plan) && relayOriginEligible(q, plan) {
		originalPlan := plan
		plan = c.prepareHintedRelayOrigin(ctx, current, q, plan, func(probe context.Context, dst netip.AddrPort) (net.Conn, error) {
			candidate := originalPlan
			candidate.Destination = dst
			return c.browserOpenUnobserved(probe, q, candidate)
		})
		n.mu.Lock()
		r := n.records[record]
		r.OriginPreflight = plan.DNSRecovery
		n.records[record] = r
		n.mu.Unlock()
	}
	var conn net.Conn
	if err == nil {
		if secureDNS {
			conn, err = c.browserOpen(ctx, q, plan)
		} else if opaque {
			conn, plan, err = c.openOpaqueBrowserPlan(ctx, current, q, plan, c.browserOpen)
		} else {
			conn, plan, err = c.browserOpenPlan(ctx, q, plan)
		}
	}
	n.opened(record, plan, err)
	d = applyFlowResult(p, d, plan.Policy, current.network, c.browserLocal(plan.Policy.Strategy))
	d.OriginDomain = q.Host
	d.OriginHintOnly = q.HintOnly
	d.NewConnectionsOnly = true
	if err != nil {
		d.BlockOnFailure = true
		return nil, d, err
	} // No generic native fallback after a planned failure.
	if current.network != "" && !plan.FirstFlightManaged && nativeFirstReplyEligible(q, plan) {
		conn = &nativeFirstReplyConn{Conn: conn, timeout: 1200 * time.Millisecond, failed: func(failure string) {
			if !c.recordNativeBrowserFailure(current, q, plan, opaque, failure, evidence) {
				return
			}
			n.mu.Lock()
			r, ok := n.records[record]
			if ok {
				r.Result = "DIRECT_STALL_NEW_CONNECTION_REQUIRED"
				r.Failure = failure
				n.records[record] = r
			}
			n.mu.Unlock()
		}}
	}
	return newNativeBrowserConn(conn, n, record), d, nil
}

func newNativeBrowserConn(conn net.Conn, n *nativeBrowserRuntime, id uint64) *nativeBrowserConn {
	wire := &browserproxy.TLSWireObserver{}
	n.mu.Lock()
	r := n.records[id]
	r.tlsWire = wire
	if reporter, ok := conn.(browserproxy.PlanReporter); ok {
		r.planReporter = reporter
	}
	if reporter, ok := conn.(browserproxy.OriginReporter); ok {
		r.originReporter = reporter
	}
	n.records[id] = r
	n.mu.Unlock()
	return &nativeBrowserConn{Conn: conn, runtime: n, record: id, wire: wire}
}

type nativeBrowserConn struct {
	wire *browserproxy.TLSWireObserver
	net.Conn
	runtime *nativeBrowserRuntime
	record  uint64
	once    sync.Once
}

func (c *nativeBrowserConn) CurrentTCPPolicy() (flowpolicy.Result, bool) {
	if r, ok := c.Conn.(wp.TCPPolicyReporter); ok {
		return r.CurrentTCPPolicy()
	}
	return flowpolicy.Result{}, false
}
func (c *nativeBrowserConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	if n > 0 {
		if c.wire != nil {
			c.wire.ObserveOrigin(p[:n])
		}
		c.runtime.bytes(c.record, 0, uint64(n))
	}
	return n, e
}
func (c *nativeBrowserConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	if n > 0 {
		if c.wire != nil {
			c.wire.ObserveClient(p[:n])
		}
		c.runtime.bytes(c.record, uint64(n), 0)
	}
	return n, e
}
func (c *nativeBrowserConn) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { c.runtime.closed(c.record) })
	return e
}
func (c *nativeBrowserConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}

func nativeFailureCode(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, errOpaqueGoogleCapacity) {
		return "OPAQUE_GOOGLE_RELAY_ADMISSION_CAPACITY"
	}
	if errors.Is(err, errVideoRelayCapacity) {
		return "GOOGLEVIDEO_RELAY_ADMISSION_CAPACITY"
	}
	switch err.Error() {
	case "NATIVE_OPTIMIZATION_DISABLED", "LOCAL_FLOW_RESERVATION_IN_USE", "NATIVE_OWNED_PAC_GUARD_REQUIRED", "NATIVE_CAPTURE_NOT_READY", "NATIVE_CAPTURE_START_FAILED", "NATIVE_CAPTURE_NOT_CONFIGURED", "NATIVE_PROFILE_PERSIST_FAILED", "NATIVE_OWNER_EXITED", "NATIVE_OWNER_SID_MISMATCH", "NATIVE_PROFILE_CHANGED", "NATIVE_EVIDENCE_CAPACITY", "EDGE_LISTENER_BIND_FAILED", "CHROME_LISTENER_BIND_FAILED", "NATIVE_GUARD_ADDRESS_CHANGED", "EDGE_POLICY_OWNERSHIP_CHANGED":
		return err.Error()
	}
	return transport.FailureReason(err)
}
