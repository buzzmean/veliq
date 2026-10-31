// Package clientservice owns routing, telemetry and privileged commands outside the UI.
package clientservice

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/buzzmean/neexitlag/internal/releaseinfo"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/gameudp"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/measurement"
	"github.com/buzzmean/neexitlag/core/optimizer"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/telemetry"
	"github.com/buzzmean/neexitlag/core/traffic"
	"github.com/buzzmean/neexitlag/core/transport"
	windowsplatform "github.com/buzzmean/neexitlag/platform/windows"
)

type RouteView struct {
	ID          string             `json:"id"`
	RTTMS       float64            `json:"rtt_ms"`
	JitterMS    float64            `json:"jitter_ms"`
	Loss        float64            `json:"loss"`
	FailureRate float64            `json:"failure_rate"`
	Score       *float64           `json:"score,omitempty"`
	Status      string             `json:"status"`
	ObservedAt  time.Time          `json:"observed_at"`
	Quality     *optimizer.Quality `json:"quality,omitempty"`
}
type Settings struct {
	Automatic     bool   `json:"automatic"`
	Failover      string `json:"failover"`
	UpdateChannel string `json:"update_channel"`
	// YouTubeViaRelay lets the stall retry and the timeout cache move YouTube to the relay.
	// Off by default: video traffic is heavy and the VPS plan limits are not confirmed.
	YouTubeViaRelay bool `json:"youtube_via_relay,omitempty"`
}
type Snapshot struct {
	CaptureActive        bool                             `json:"capture_active"`
	CapturePermitted     bool                             `json:"capture_permitted"`
	CaptureBlockedReason string                           `json:"capture_blocked_reason,omitempty"`
	HotAttach            *windowsplatform.HotAttachStatus `json:"hot_attach,omitempty"`
	RelayTransport       *RelayTransportReadiness         `json:"relay_transport,omitempty"`
	Version              string                           `json:"version"`
	// Build is the git commit this binary was built from (plus "+modified" for a dirty tree),
	// so a stale service or checkout is visible instead of guessed.
	Build            string                        `json:"build,omitempty"`
	ServicePID       uint32                        `json:"service_pid"`
	ConnectionReason string                        `json:"connection_reason"`
	RelayConnected   bool                          `json:"relay_connected"`
	BrowserPolicy    BrowserPolicyHealth           `json:"browser_policy"`
	Connected        bool                          `json:"connected"`
	Optimizing       bool                          `json:"optimizing"`
	Demo             bool                          `json:"demo"`
	Backend          windowsplatform.CaptureStatus `json:"backend"`
	Primary          string                        `json:"primary"`
	Secondary        string                        `json:"secondary"`
	Tertiary         string                        `json:"tertiary"`
	Routes           []RouteView                   `json:"routes"`
	Profiles         []profiles.Profile            `json:"profiles"`
	RXBytes          uint64                        `json:"rx_bytes"`
	TXBytes          uint64                        `json:"tx_bytes"`
	History          optimizer.RouteHistory        `json:"history"`
	Flows            []routing.Flow                `json:"flows"`
	Settings         Settings                      `json:"settings"`
	ControlPlane     string                        `json:"control_plane"`
	ActiveApps       []string                      `json:"active_apps"`
}
type Controller struct {
	updater         atomic.Pointer[updater]
	traffic         *traffic.Client
	remoteTraffic   remoteTrafficState
	catalog         *clientCatalog
	clubConfig      atomic.Pointer[clubConfiguration]
	clubProbe       atomic.Pointer[ClubRelayCheck]
	clubMode        atomic.Bool
	games           gameRuntime
	activation      activationRuntime
	subscription    subscriptionRuntime
	remoteDone      chan struct{}
	remoteMu        sync.Mutex
	remoteCancel    context.CancelFunc
	selfExecutable  string
	BrowserOwnerSID string // Existing installation owner; restrict the loopback endpoint to this user.
	// In-process fixture injection only; production uses the system resolver/roots.
	BrowserRecoveryExecutable string                 // In-process fixture only; production authenticates its own installed binary.
	BrowserAlternativeDNS     browserproxy.DNSLookup // In-process fixture only; no IPC/config override.
	BrowserResolver           *net.Resolver
	BrowserProbeRoots         *x509.CertPool
	browser                   *browserRuntime
	activationMu              sync.Mutex
	relayPools                map[string]*transport.Pool
	relayPrimary              *relayPrimaryRuntime
	autoJobs                  map[string]autoLease
	groupBindings             map[uint32]groupBinding
	autoMu                    sync.Mutex
	AutoLearned               *flowpolicy.Learning
	groupMu                   sync.Mutex
	groupAt                   time.Time
	groupAll                  []profiles.Identity
	discovery                 windowsplatform.Discovery
	Learned                   *localstrategy.Cache
	network                   atomic.Pointer[windowsplatform.NetworkContext]
	conflicts                 atomic.Pointer[windowsplatform.ConflictScan]
	// NetworkHostRoutes are extra /32 routes (relay VPS) included in the fingerprint.
	NetworkHostRoutes           []netip.Addr
	Local                       *localstrategy.LocalStrategyEngine
	localMu                     sync.Mutex
	Engine                      *routing.Engine
	Selector                    *optimizer.RouteSelector
	Measurements                *measurement.Engine
	Profiles                    *profiles.Registry
	Backend                     windowsplatform.WindowsCaptureBackend
	Demo                        bool
	ConfigPath, ControlPlaneURL string
	DiagnosticHTTPClient        *http.Client
	TCPDiagnosticTarget         string
	RX, TX                      atomic.Uint64
	mu                          sync.Mutex
	captureStartError           string
	enabled                     bool
	settings                    Settings
	customPath                  string
	recentApps                  map[string]time.Time
	localProfiles               map[string]profiles.Profile
	acceptanceRelays            map[string]acceptanceRelaySource
	transportDrops              map[string]func() map[string]telemetry.Metric
	ctx                         context.Context
	cancel                      context.CancelFunc
	wg                          sync.WaitGroup
	FailRelay                   func(string) error
}

func New(ctx context.Context) *Controller {
	ctx, cancel := context.WithCancel(ctx)
	c := &Controller{traffic: traffic.NewClient(), catalog: newClientCatalog(), relayPrimary: newRelayPrimary(), browser: newBrowserRuntime(), relayPools: map[string]*transport.Pool{}, AutoLearned: flowpolicy.NewLearning(), groupBindings: map[uint32]groupBinding{}, autoJobs: map[string]autoLease{}, discovery: windowsplatform.NewDiscovery(), Local: localstrategy.New(), Learned: localstrategy.NewCache(1024), Engine: routing.New(4096), Selector: optimizer.New(optimizer.DefaultParameters()), Measurements: measurement.New(measurement.Defaults()), Profiles: profiles.New(profiles.Defaults()), recentApps: make(map[string]time.Time), localProfiles: make(map[string]profiles.Profile), acceptanceRelays: make(map[string]acceptanceRelaySource), transportDrops: make(map[string]func() map[string]telemetry.Metric), settings: Settings{Automatic: true, Failover: "DIRECT", UpdateChannel: "stable"}, ctx: ctx, cancel: cancel}
	c.games.items = map[string]*gameEntry{}
	c.games.budget = &gameudp.Budget{}
	c.selfExecutable, _ = os.Executable()
	c.Local.Guard = func(m localstrategy.Metadata) bool {
		if c.autoCandidateQuarantined(m) {
			return false
		}
		k, err := c.localKey(m.Application, m.Destination.String(), m.Protocol)
		return err != nil || !c.Learned.Quarantined(k, m.StrategyID, time.Now())
	}
	c.Selector.SetFlapGuard(optimizer.DefaultFlapGuard())
	c.Measurements.OnFailure = c.Selector.ReportProbeFailure
	c.Engine.SetAutoSelector(func(f routing.Flow) routing.Policy {
		c.mu.Lock()
		automatic := c.settings.Automatic
		c.mu.Unlock()
		if !automatic || !c.applicationAutomaticRelayAllowed(f.ApplicationID) {
			return routing.Policy{}
		}
		selection := c.Selector.Select(time.Now())
		route := func(id string) routing.Route {
			if id == optimizer.Direct {
				return routing.Route{}
			}
			return routing.Route{RelayID: id}
		}
		p := routing.Policy{Route: route(selection.Primary)}
		for _, id := range []string{selection.Secondary, selection.Tertiary} {
			if id != "" {
				p.Backups = append(p.Backups, route(id))
			}
		}
		// Same per-target policy at classification and actual transport open. The
		// engine invokes this under its own lock: no call back into Engine methods.
		d := windowsplatform.Decision{Route: p.Route}
		c.applyLocalAuto(windowsplatform.ProcessIdentity{Path: f.ProcessPath}, windowsplatform.Tuple{Protocol: f.Protocol, Source: f.Source, Destination: f.Destination}, &d)
		p.Route = d.Route
		return p
	})
	c.Engine.SetTrafficObserver(c.accountRelayTraffic)
	c.syncPolicies()
	return c
}
func (c *Controller) syncPolicies() {
	for _, p := range c.Profiles.List() {
		policy := routing.Policy{}
		switch p.Mode {
		case profiles.Auto:
			policy.Auto = automaticRelayAllowed(p)
		case profiles.DirectPlus:
			policy.Route = routing.Route{Kind: routing.DirectPlusRoute}
		case profiles.Manual:
			policy.Route = routing.Route{RelayID: p.RelayID}
		case profiles.Block:
			policy.Block = true
		}
		c.mu.Lock()
		policy.BlockOnFailure = c.settings.Failover == "BLOCK"
		c.mu.Unlock()
		if p.Fallback != "" {
			policy.BlockOnFailure = p.Fallback == flowpolicy.Required || p.Fallback == flowpolicy.FailBlock
		}
		if p.Mode == profiles.Auto && relayFirstPreset(presetFor(p)) {
			policy.Auto = false
			policy.Route = routing.Route{RelayID: p.RelayID}
			if policy.Route.RelayID == "" {
				policy.Route.RelayID = "VPS-01"
			}
			policy.BlockOnFailure = true
		}
		if len(p.Rules) > 0 {
			policy.Auto = false
			policy.Block = true
		} // classified flows supply the exact pinned override
		c.Engine.SetPolicy(p.ID, policy)
	}
}
func (c *Controller) Start() {
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.watchTrafficAccounting() }()
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.watchLocalSelection() }()
	if c.clubMode.Load() {
		c.wg.Add(1)
		go func() { defer c.wg.Done(); c.watchClubStatus() }()
	}
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.watchBrowserDomainCache() }()
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.watchGames() }()
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.maintainSilentBrowserPolicies() }()
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.watchNetwork() }()
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.Measurements.Run(c.ctx, c.Selector.Observe) }()
}
func (c *Controller) Close() {
	if c.browser.readiness.enforced.Load() {
		_ = c.CleanupOwnedBrowserPolicies() // Before listeners, relay workers or capture stop.
	}
	c.cancel()
	c.browser.youtube.stop()
	c.activation.mu.Lock()
	activationDone := c.activation.done
	c.activation.mu.Unlock()
	if activationDone != nil {
		<-activationDone
	}
	c.closeEdge()
	c.browser.mu.Lock()
	bs := c.browser.server
	c.browser.mu.Unlock()
	if bs != nil {
		bs.Close()
	}
	if c.Backend != nil {
		c.Backend.Stop()
	}
	c.wg.Wait()
	_ = c.traffic.Flush()
}
func (c *Controller) SetCustomPath(path string) error {
	c.customPath = path
	c.loadGames()
	if err := c.loadAutoLearning(); err != nil {
		return err
	}
	if err := c.loadLocal(); err != nil {
		return err
	}
	settingsRaw, e := os.ReadFile(filepath.Join(filepath.Dir(path), "settings.json"))
	if e == nil {
		var stored Settings
		if e = security.Parse(settingsRaw, &stored); e != nil {
			return e
		}
		if (stored.Failover != "DIRECT" && stored.Failover != "BLOCK") || (stored.UpdateChannel != "stable" && stored.UpdateChannel != "preview") {
			return errors.New("invalid persisted settings")
		}
		c.mu.Lock()
		c.settings = stored
		c.mu.Unlock()
	} else if !os.IsNotExist(e) {
		return e
	}
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	var all []profiles.Profile
	if e = security.Parse(b, &all); e != nil {
		return e
	}
	dropShadowedBuiltIns(c.Profiles, all)
	for _, p := range all {
		prepareAuto(&p)
		c.mu.Lock()
		c.localProfiles[p.ID] = p
		c.mu.Unlock()
		if e = c.Profiles.Upsert(p); e != nil {
			return e
		}
	}
	c.syncPolicies()
	return nil
}
func (c *Controller) saveProfiles() error {
	if c.customPath == "" {
		return nil
	}
	all := []profiles.Profile{}
	c.mu.Lock()
	for _, p := range c.localProfiles {
		if p.Trial != nil {
			continue
		}
		all = append(all, p)
	}
	c.mu.Unlock()
	raw, e := json.Marshal(all)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(c.customPath), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(c.customPath), ".profiles-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	f.Chmod(0600)
	_, e = f.Write(raw)
	f.Close()
	if e != nil {
		return e
	}
	return os.Rename(name, c.customPath)
}
func (c *Controller) Classify(identity windowsplatform.ProcessIdentity, t windowsplatform.Tuple) windowsplatform.Decision {
	c.mu.Lock()
	enabled := c.enabled
	c.mu.Unlock()
	decision := windowsplatform.Decision{Route: routing.Route{}}
	if windowsplatform.IsPrivateISCSI(t) {
		return decision
	}
	if !enabled || c.selfExecutable != "" && strings.EqualFold(identity.Path, c.selfExecutable) {
		return decision
	}
	if d, ok := c.classifyGameUDP(identity, t); ok {
		return d
	}
	profile, ok := c.matchApplication(identity)
	if !ok {
		return decision
	}
	// Owner-authorized availability contract: no opaque native browser capture
	// while its PAC lane is suspended. Desktop apps and games retain their policy.
	if c.browser.readiness.enforced.Load() && profile.Mode == profiles.Auto && !nativeBrowserProfile(profile) && (chromeProfile(profile) || edgeProfile(profile)) {
		lane := 0
		if edgeProfile(profile) {
			lane = 1
		}
		c.mu.Lock()
		automatic := c.settings.Automatic
		c.mu.Unlock()
		if !c.browser.readiness.laneReady(lane) || !automatic {
			decision.Flow = routing.Flow{Protocol: t.Protocol, Source: t.Source, Destination: t.Destination, PID: identity.PID, ProcessPath: identity.Path, ApplicationID: profile.ID, PinnedPolicy: &routing.Policy{}}
			decision.Revision = c.policyRevision(profile)
			decision.Policy = flowpolicy.Result{Action: flowpolicy.Direct, Source: "browser_policy_suspended", Reason: "owner-authorized DIRECT while browser infrastructure is not ready"}
			return decision
		}
	}
	f := routing.Flow{Protocol: t.Protocol, Source: t.Source, Destination: t.Destination, PID: identity.PID, ProcessPath: identity.Path, ApplicationID: profile.ID}
	decision.Flow = f
	decision.Revision = c.policyRevision(profile)
	if edgeProfile(profile) && !nativeBrowserProfile(profile) && profile.Mode == profiles.Auto && profile.AppPreset == "edge-sites-pending" && !directOnlyFlow(t) {
		decision.Block, decision.BlockOnFailure = true, true
		decision.Policy = flowpolicy.Result{Action: flowpolicy.Block, Source: "edge_activation_pending", Reason: "Edge AUTO awaits CONNECT/PAC activation; no DIRECT authorization"}
		return decision
	}
	// Name resolution (port 53) and local or non-public destinations are never relayed, even
	// for fail-closed profiles: the relay refuses them (relay_destination_denied), so relaying
	// would only block the application. The flow stays attributed to its profile but is
	// pinned DIRECT so the engine ignores the profile's relay policy for it. Browser AUTO
	// profiles keep their own, already verified DNS handling (browserFlow).
	if (profile.Mode == profiles.Auto || profile.Mode == profiles.Manual) && !browserAuto(profile) && directOnlyFlow(t) {
		decision.Flow.PinnedPolicy = &routing.Policy{}
		return decision
	}
	c.mu.Lock()
	decision.BlockOnFailure = c.settings.Failover == "BLOCK"
	c.mu.Unlock()
	switch profile.Mode {
	case profiles.Block:
		decision.Block = true
	case profiles.DirectPlus:
		decision.Route = routing.Route{Kind: routing.DirectPlusRoute}
		decision.Local = c.Local
		decision.LocalStrategyID = profile.LocalStrategyID
		decision.BlockOnFailure = false
	case profiles.Manual:
		decision.Route = routing.Route{RelayID: profile.RelayID}
	case profiles.Auto:
		c.mu.Lock()
		automatic := c.settings.Automatic
		c.mu.Unlock()
		if !automatic {
			decision.Flow.PinnedPolicy = &routing.Policy{}
			decision.Policy = flowpolicy.Result{Action: flowpolicy.Direct, Source: "optimization_disabled", Reason: "automatic optimization disabled"}
			return decision
		}

		if automaticRelayAllowed(profile) {
			primary := c.Selector.Select(time.Now()).Primary
			if primary != optimizer.Direct {
				decision.Route = routing.Route{RelayID: primary}
			}
		}
	}
	if profile.Mode == profiles.Auto && c.Local.HasApplication(identity.Path) {
		decision.Route = routing.Route{}
	}
	if profile.Mode == profiles.Auto {
		c.applyLocalAuto(identity, t, &decision)
		if !automaticRelayAllowed(profile) && !decision.Route.Direct() && !decision.Route.Local() {
			decision.Route = routing.Route{}
		}
	}
	decision = c.scopedDecision(profile, identity, t, decision)
	if n := c.network.Load(); n != nil && len(n.Conflicts) > 0 {
		if decision.BlockOnFailure {
			decision.Block = true
			decision.Deferred = false
			decision.ResolveDomain = nil
			return decision
		}
		return windowsplatform.Decision{Flow: f}
	}
	return decision
}
func (c *Controller) Snapshot() Snapshot {
	selection := c.Selector.Select(time.Now())
	history := c.Selector.History()
	if len(history.Measurements) > 48 {
		history.Measurements = history.Measurements[len(history.Measurements)-48:]
	}
	if len(history.Changes) > 32 {
		history.Changes = history.Changes[len(history.Changes)-32:]
	}
	latest := map[string]optimizer.RouteMeasurement{}
	for _, m := range history.Measurements {
		latest[m.RouteID] = m
	}
	qualities := c.Selector.Qualities(time.Now())
	// Route state must not disappear when display history is truncated, or while
	// a newly failed route has not yet completed its first probe round.
	for id, q := range qualities {
		if _, ok := latest[id]; !ok {
			latest[id] = optimizer.RouteMeasurement{RouteID: id, ObservedAt: q.ObservedAt}
		}
	}
	views := []RouteView{}
	for _, m := range latest {
		view := RouteView{ID: m.RouteID, RTTMS: float64(m.RTT) / float64(time.Millisecond), JitterMS: float64(m.Jitter) / float64(time.Millisecond), Loss: m.Loss, FailureRate: m.FailureRate, Status: "unavailable", ObservedAt: m.ObservedAt}
		if q, ok := qualities[m.RouteID]; ok {
			view.Quality = &q
			view.RTTMS = float64(q.LatestRTT) / float64(time.Millisecond)
			view.Loss = q.Loss
			view.FailureRate = q.FailureRate
			view.JitterMS = float64(q.Jitter) / float64(time.Millisecond)
			view.Status = q.Health
		}
		for _, r := range selection.Ranked {
			if r.ID == m.RouteID {
				score := r.Score
				view.Score = &score
				view.Status = "healthy"
			}
		}
		views = append(views, view)
	}
	sort.Slice(views, func(i, j int) bool { return views[i].ID < views[j].ID })
	backend := windowsplatform.CaptureStatus{Backend: "none", Error: "capture not configured; networking remains DIRECT"}
	if c.Backend != nil {
		backend = c.Backend.Status()
	}
	c.mu.Lock()
	enabled := c.enabled
	settings := c.settings
	controlPlaneURL := c.ControlPlaneURL
	recent := make(map[string]time.Time, len(c.recentApps))
	for id, t := range c.recentApps {
		recent[id] = t
	}
	c.mu.Unlock()
	active := map[string]bool{}
	for id, t := range recent {
		if time.Since(t) < 5*time.Second {
			active[id] = true
		}
	}
	flows := c.Engine.Snapshot()
	for _, f := range flows {
		if !f.Route.Direct() {
			active[f.ApplicationID] = true
		}
	}
	apps := []string{}
	for id := range active {
		apps = append(apps, id)
	}
	sort.Strings(apps)
	if len(history.Measurements) > 32 {
		history.Measurements = history.Measurements[len(history.Measurements)-32:]
	}
	if len(history.Changes) > 32 {
		history.Changes = history.Changes[len(history.Changes)-32:]
	}
	if len(flows) > 16 {
		flows = flows[:16]
	}
	rx, tx := c.RX.Load(), c.TX.Load()
	if b, ok := c.Backend.(interface{ Traffic() (uint64, uint64) }); ok {
		brx, btx := b.Traffic()
		rx += brx
		tx += btx
	}
	snapshot := Snapshot{CaptureActive: backend.Ready, CapturePermitted: c.activationNetworkAllowed(), HotAttach: c.hotAttachStatus(), Version: "0.3.0-dev", Build: buildStamp(), Connected: (c.Demo || backend.Ready) && (controlPlaneURL == "" || c.relayConnected()), Optimizing: enabled && (c.Demo || backend.Ready), Demo: c.Demo, Backend: backend, Primary: selection.Primary, Secondary: selection.Secondary, Tertiary: selection.Tertiary, Routes: views, Profiles: c.Profiles.List(), RXBytes: rx, TXBytes: tx, History: history, Flows: flows, Settings: settings, ControlPlane: controlPlaneURL, ActiveApps: apps}
	snapshot.ServicePID = uint32(os.Getpid())
	snapshot.RelayConnected = c.relayConnected()
	snapshot.ConnectionReason = c.connectionReason(snapshot)
	snapshot.BrowserPolicy = c.browserPolicyHealth()
	// Keep mandatory profile/quality fields; shorten display history to the IPC frame.
	for {
		raw, _ := json.Marshal(snapshot)
		if len(raw) <= 60000 {
			break
		}
		if len(snapshot.History.Measurements) > 0 {
			snapshot.History.Measurements = snapshot.History.Measurements[1:]
			continue
		}
		if len(snapshot.History.Changes) > 0 {
			snapshot.History.Changes = snapshot.History.Changes[1:]
			continue
		}
		if len(snapshot.Flows) > 0 {
			snapshot.Flows = snapshot.Flows[:len(snapshot.Flows)-1]
			continue
		}
		break
	}
	if !snapshot.CapturePermitted {
		snapshot.CaptureBlockedReason = "ACTIVATION_REQUIRED"
	}
	return snapshot
}
func (c *Controller) Handle(ctx context.Context, method string, raw json.RawMessage) (result any, err error) {
	if method == "club.status" {
		return c.clubStatus(), nil
	}
	if (method == "profile.set" || method == "profile.delete" || method == "auto.commit") && c.browserProfileMutation(raw) {
		defer func() { _ = c.CleanupOwnedBrowserPolicies() }()
	}

	if !c.activationNetworkAllowed() {
		if activationNetworkMutation(method) {
			return nil, errors.New("ACTIVATION_REQUIRED")
		}
		if method == "optimize" {
			var v struct {
				Enabled bool `json:"enabled"`
			}
			if e := security.Parse(raw, &v); e != nil {
				return nil, e
			}
			if v.Enabled {
				return nil, errors.New("ACTIVATION_REQUIRED")
			}
			return c.handleOptimize(ctx, raw)
		}
	}

	if isEdgeMutation(method) {
		c.activationMu.Lock()
		defer c.activationMu.Unlock()
		// Include guard-publication failures before/after handleEdge in the same
		// bounded status diagnostic; otherwise a failure before listener was invisible.
		defer func() {
			if err != nil {
				c.browser.mu.Lock()
				e := c.edgeLocked()
				e.lastError = method + ": " + edgeErrorCode(err)
				err = errors.New(e.lastError)
				c.browser.mu.Unlock()
			}
		}()
		if e := c.publishBrowserGuard(true); e != nil {
			return nil, errors.New("EDGE_GUARD_STATE_WRITE_FAILED")
		}
		defer func() {
			if e := c.publishBrowserGuard(false); e != nil && err == nil {
				result, err = nil, errors.New("EDGE_GUARD_STATE_WRITE_FAILED")
			}
		}()
	}
	switch method {
	case "optimize", "profile.set", "profile.delete", "settings.set", "local.set", "local.preset.apply", "auto.commit", "browser.silent.guard", "browser.silent.apply", "browser.prepare", "browser.start", "browser.confirm", "browser.native.enable":
		c.activationMu.Lock()
		defer c.activationMu.Unlock()
		if e := c.publishBrowserGuard(true); e != nil {
			return nil, e
		}
		defer func() {
			if e := c.publishBrowserGuard(false); e != nil && err == nil {
				result = nil
				err = e
			}
		}()
	}
	switch method {
	case "update.status":
		if u := c.updater.Load(); u != nil {
			return u.snapshot(), nil
		}
		return UpdateStatus{State: "NOT_STARTED", Current: BuildSequence}, nil
	case "traffic.status":
		return c.trafficSnapshot(), nil
	case "local.catalog":
		return c.catalog.snapshot(), nil
	case "gameudp.status", "gameudp.set", "pubg.status", "pubg.set":
		return c.handleGameUDP(ctx, method, raw)
	case "activation.status", "activation.set":
		return c.handleActivation(method, raw)
	case "subscription.status", "subscription.refresh":
		return c.handleSubscription(method)
	case "browser.native.attribution":
		return c.nativeBrowserAttribution(), nil
	case "browser.native.firewall":
		return windowsplatform.InspectNativeFirewall(ctx), nil
	case "riot.status":
		return c.riotStatus(), nil
	case "browser.local.probes":
		return c.localProbeSnapshot(), nil
	case "browser.native.enable", "browser.native.status":
		return c.handleNativeBrowser(ctx, method, raw)
	case "edge.silent.apply", "browser.silent.apply", "browser.silent.guard":
		return c.handleBrowserSilent(method, raw)
	case "edge.prepare", "edge.confirm", "edge.policy", "edge.status", "edge.failure":
		return c.handleEdge(method, raw)
	case "browser.origin.check":
		return c.checkBrowserOrigin(ctx, raw)
	case "browser.first-byte", "edge.first-byte":
		return c.browserFirstBytes(method == "edge.first-byte"), nil
	case "browser.start", "browser.prepare", "browser.confirm", "browser.status":
		return c.handleBrowser(method, raw)
	case "local.presets", "local.preset.apply", "local.get", "local.set", "local.metrics", "local.network", "local.record", "local.recommend", "local.compare":
		return c.handleLocal(method, raw)
	case "acceptance.readiness", "relay.primary.status", "relay.pool.diagnostics", "quality.diagnostics":
		return c.handleRelayDiagnostics(ctx, method, raw)
	case "capture.changes.marker", "capture.changes", "capture.marker", "capture.diagnostics":
		return c.handleCapture(ctx, method, raw)
	case "hot_attach.status":
		return c.hotAttachStatus(), nil
	case "status":
		return c.Snapshot(), nil
	case "profiles":
		return c.Profiles.List(), nil
	case "profiles.routing":
		return c.profileRoutingAudit(), nil
	case "processes":
		return listProcesses(raw)
	case "profile.delete":
		return c.handleProfileDelete(ctx, raw)
	case "auto.plan", "auto.commit":
		c.pruneTrials(time.Now())
		return c.handleAuto(method, raw)
	case "profile.set":
		return c.handleProfileSet(ctx, raw)
	case "optimize":
		return c.handleOptimize(ctx, raw)
	case "settings.set":
		return c.handleSettingsSet(ctx, raw)
	case "diagnostics":
		return c.Diagnostics(ctx), nil
	case "demo.fail-relay":
		if !c.Demo || c.FailRelay == nil {
			return nil, errors.New("relay failure control is only available in local demo")
		}
		var v struct {
			ID string `json:"id"`
		}
		if e := security.Parse(raw, &v); e != nil {
			return nil, e
		}
		if e := c.FailRelay(v.ID); e != nil {
			return nil, e
		}
		return c.Snapshot(), nil
	default:
		return nil, fmt.Errorf("unsupported IPC method %q", method)
	}
}

type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func (c *Controller) Diagnostics(ctx context.Context) []Check {
	c.mu.Lock()
	controlPlaneURL, diagnosticHTTP, tcpTarget := c.ControlPlaneURL, c.DiagnosticHTTPClient, c.TCPDiagnosticTarget
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	out := []Check{}
	if c.Backend != nil {
		b := c.Backend.Status()
		tcp, udp, ipv4 := "unavailable", "unavailable", "unavailable"
		if b.Ready && b.Capabilities.TCP {
			tcp = "healthy"
		}
		if b.Ready && b.Capabilities.UDP {
			udp = "healthy"
		}
		if b.Ready && b.Capabilities.IPv4 {
			ipv4 = "healthy"
		}
		out = append(out, Check{"TCP interception", tcp, "backend readiness, not an external TCP proof"}, Check{"UDP interception", udp, "backend readiness"}, Check{"IPv4", ipv4, "capture backend capability"})
	}
	out = append(out, Check{"IPv6", "unsupported", "no IPv6 relay transport: new attributable selected IPv6 packets blocked at NETWORK; existing/unattributed/unsupported traffic fails open"}, Check{"HTTPS through relay", "not configured", "not measured; encrypted TCP alone is not HTTPS evidence"}, Check{"QUIC through relay", "not configured", "not measured; UDP/443 alone is not QUIC evidence"}, Check{"Browser DNS", "not configured", "not attributed: system resolver service traffic stays DIRECT; selected browser DoH follows its socket profile"})
	dnsHost := "localhost"
	if controlPlaneURL == "" {
		out = append(out, Check{"Control Plane", "not configured", "no endpoint configured"})
	} else {
		u, e := url.Parse(controlPlaneURL)
		if e == nil {
			dnsHost = u.Hostname()
		}
		req, e := http.NewRequestWithContext(ctx, "GET", controlPlaneURL+"/healthz", nil)
		status := "unavailable"
		if e == nil {
			client := diagnosticHTTP
			if client == nil {
				client = &http.Client{Timeout: time.Second}
			}
			probe, stop := context.WithTimeout(ctx, time.Second)
			response, e := client.Do(req.WithContext(probe))
			stop()
			if e == nil {
				response.Body.Close()
				if response.StatusCode == 200 {
					status = "healthy"
				}
			}
		}
		out = append(out, Check{"Control Plane", status, "HTTP health request"})
	}
	_, e := net.DefaultResolver.LookupHost(ctx, dnsHost)
	dns := "healthy"
	if e != nil {
		dns = "unavailable"
	}
	out = append(out, Check{"DNS", dns, "resolved configured control host (localhost in standalone demo)"})
	measurements := c.Measurements.Round(ctx)
	udpStatus, relayStatus := "not configured", "not configured"
	for _, m := range measurements {
		if m.RouteID == "" {
			continue
		}
		c.Selector.Observe(m)
		status := "unavailable"
		if m.Available {
			status = "healthy"
		}
		if m.RouteID == optimizer.Direct {
			udpStatus = status
		} else if relayStatus != "healthy" {
			relayStatus = status
		}
	}
	out = append(out, Check{"UDP", udpStatus, "real application-level UDP echo probes"}, Check{"Relay", relayStatus, "authenticated relay UDP echo path"})
	tcpStatus := "not configured"
	if tcpTarget != "" {
		conn, e := (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "tcp", tcpTarget)
		tcpStatus = "unavailable"
		if e == nil {
			conn.Close()
			tcpStatus = "healthy"
		}
	}
	out = append(out, Check{"TCP", tcpStatus, "TCP connect to configured diagnostic target"})
	mtuStatus := "not configured"
	for _, candidate := range c.Measurements.Candidates() {
		if candidate.Metadata.ID != optimizer.Direct {
			continue
		}
		mtuStatus = "unavailable"
		probe, stop := context.WithTimeout(ctx, 500*time.Millisecond)
		flow, e := candidate.Open(probe, candidate.Target)
		if e == nil {
			payload := bytes.Repeat([]byte{0x6e}, 1100)
			if flow.Send(payload) == nil {
				got, e := flow.Receive(probe)
				if e == nil && bytes.Equal(got, payload) {
					mtuStatus = "healthy"
				}
			}
			flow.Close()
		}
		stop()
		break
	}
	out = append(out, Check{"MTU", mtuStatus, "1100-byte echo payload check; not end-to-end Internet PMTU discovery"})
	selection := c.Selector.Select(time.Now())
	for _, route := range selection.Ranked {
		if route.ID == selection.Primary {
			out = append(out, Check{"Latency / Loss", "measured", fmt.Sprintf("RTT %.1f ms, jitter %.1f ms, loss %.1f%%", float64(route.Measurement.RTT)/float64(time.Millisecond), float64(route.Measurement.Jitter)/float64(time.Millisecond), route.Measurement.Loss*100)})
			break
		}
	}
	return out
}
func (c *Controller) RecordTraffic(app string, rx, tx uint64) {
	c.RX.Add(rx)
	c.TX.Add(tx)
	c.mu.Lock()
	if len(c.recentApps) < 128 {
		c.recentApps[app] = time.Now()
	}
	c.mu.Unlock()
}

func (c *Controller) saveSettings() error {
	if c.customPath == "" {
		return nil
	}
	c.mu.Lock()
	raw, e := json.Marshal(c.settings)
	c.mu.Unlock()
	if e != nil {
		return e
	}
	dir := filepath.Dir(c.customPath)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".settings-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	f.Chmod(0600)
	_, e = f.Write(raw)
	f.Close()
	if e != nil {
		return e
	}
	return os.Rename(name, filepath.Join(dir, "settings.json"))
}

// buildStamp names the commit the running binary was built from.
func buildStamp() string {
	info := releaseinfo.Current("client-service", nil, 0, 0)
	if info.Commit == "" {
		return "unknown (built outside a git checkout)"
	}
	stamp := info.Commit
	if len(stamp) > 12 {
		stamp = stamp[:12]
	}
	if info.Modified {
		stamp += "+modified"
	}
	return stamp
}
