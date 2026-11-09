package clientservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/gameudp"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

// Discovery is ephemeral: no registry writes, executable lists to maintain, or
// process-wide relay preference. The backend authenticates PID + creation time.
// A user profile always wins over this default, including explicit DIRECT.
func discoveredApplication(id wp.ProcessIdentity) (profiles.Profile, bool) {
	name := strings.ToLower(strings.ReplaceAll(id.Path, "\\", "/"))
	if id.PID == 0 || id.CreationTime == 0 || len(name) > 2048 || !strings.Contains(name, "/") || !strings.HasSuffix(name, ".exe") {
		return profiles.Profile{}, false
	}
	// Chrome/Edge have an independently authenticated authority lane. Discovery
	// must not invent a legacy browser profile before that lane is activated.
	if path.Base(name) == "chrome.exe" || path.Base(name) == "msedge.exe" {
		return profiles.Profile{}, false
	}
	sum := sha256.Sum256([]byte(name))
	return profiles.Profile{ID: "auto-" + hex.EncodeToString(sum[:12]), Name: path.Base(name), Executables: []string{id.Path}, Mode: profiles.Auto, AppPreset: "automatic-discovery"}, true
}

func automaticApplication(p profiles.Profile) bool {
	for _, exe := range p.Executables {
		base := path.Base(strings.ToLower(strings.ReplaceAll(exe, "\\", "/")))
		// Preserve separately accepted game/local-only and anti-cheat boundaries.
		// Launcher policy must never grant capture of these executables.
		for _, game := range gameudp.Presets() {
			if strings.EqualFold(base, game.Executable) {
				return false
			}
		}
		switch base {
		case "valorant.exe", "valorant-win64-shipping.exe", "league of legends.exe", "vgc.exe", "vgtray.exe", "faceit.exe", "faceitclient.exe", "faceitservice.exe", "beservice.exe", "beservice_x64.exe", "easyanticheat.exe", "easyanticheat_eos.exe":
			return false
		}
	}
	return p.Mode == profiles.Auto && p.Trial == nil && !browserAuto(p) && !riotAuto(p) &&
		(presetFor(p) == "" || p.AppPreset == "automatic-discovery")
}

func (c *Controller) automaticProfile(id wp.ProcessIdentity) (profiles.Profile, bool) {
	if p, ok := c.matchApplication(id); ok {
		return p, true
	}
	return discoveredApplication(id)
}

func (c *Controller) automaticCaptureAllowed() bool {
	n := c.network.Load()
	return n == nil || len(n.Conflicts) == 0
}

func (c *Controller) automaticOwnerProfile(o browserproxy.Owner) (profilesResult, error) {
	id := wp.ProcessIdentity{PID: o.PID, CreationTime: o.Birth, Path: o.Exe}
	if !wp.IsCurrent(id) || strings.EqualFold(id.Path, c.selfExecutable) || !c.automaticCaptureAllowed() {
		return profilesResult{}, errors.New("AUTOMATIC_OWNER_CHANGED")
	}
	p, ok := c.automaticProfile(id)
	if !ok || p.ID != o.Profile || !automaticApplication(p) {
		return profilesResult{}, errors.New("AUTOMATIC_PROFILE_CHANGED")
	}
	network := ""
	if n := c.network.Load(); n != nil && n.Error == "" && time.Since(n.ObservedAt) <= 45*time.Second {
		network = n.Fingerprint
	}
	c.mu.Lock()
	enabled := c.enabled && c.settings.Automatic
	c.mu.Unlock()
	return c.captureAutomaticScope(profilesResult{profile: p, id: id, network: network, enabled: enabled, routingDisabled: !enabled}), nil
}

// Capture before asynchronous OPEN/first-flight work. policyRevision reads live
// settings and LOCAL revisions, so recomputing it from the old profile afterward
// would silently accept a global policy change.
type automaticScopeKey struct{}

var errAutomaticScopeChanged = errors.New("AUTOMATIC_SCOPE_CHANGED")

func (c *Controller) captureAutomaticScope(cur profilesResult) profilesResult {
	if automaticApplication(cur.profile) && cur.automaticRevision == "" {
		cur.automaticRevision = c.policyRevision(cur.profile)
	}
	return cur
}

func (c *Controller) automaticScopeCurrent(cur profilesResult) bool {
	if !automaticApplication(cur.profile) {
		return true // Ordinary browser and Riot retain their own ownership contract.
	}
	if cur.automaticRevision == "" || !cur.enabled || cur.routingDisabled || c.ctx.Err() != nil || !c.automaticCaptureAllowed() {
		return false
	}
	c.mu.Lock()
	enabled := c.enabled && c.settings.Automatic
	c.mu.Unlock()
	if !enabled {
		return false
	}
	network := ""
	if n := c.network.Load(); n != nil && n.Error == "" && time.Since(n.ObservedAt) <= 45*time.Second {
		network = n.Fingerprint
	}
	if network != cur.network {
		return false
	}
	fresh, ok := c.automaticProfile(cur.id)
	return ok && fresh.ID == cur.profile.ID && automaticApplication(fresh) && c.policyRevision(fresh) == cur.automaticRevision
}

// This guard applies only until an upstream OPEN completes and before bounded
// first-flight retries. Established streams stay pinned; no payload is migrated.
func (c *Controller) automaticScopedOpen(cur profilesResult, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
	if !automaticApplication(cur.profile) {
		return open
	}
	return func(ctx context.Context, q browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
		if !c.automaticScopeCurrent(cur) {
			return nil, errAutomaticScopeChanged
		}
		conn, err := open(context.WithValue(ctx, automaticScopeKey{}, cur), q, p)
		if !c.automaticScopeCurrent(cur) {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, errAutomaticScopeChanged
		}
		return conn, err
	}
}

func (c *Controller) openAutomaticApplication(ctx context.Context, p profiles.Profile, id wp.ProcessIdentity, tuple wp.Tuple, d wp.Decision, reason string) (net.Conn, wp.Decision, error) {
	// Once the app's socket has been captured, a planning error must not escape
	// through the backend's legacy unobserved DIRECT fallback.
	d.BlockOnFailure = true
	q := browserproxy.Request{Ingress: "AUTOMATIC_TCP", Owner: browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: p.ID}, Source: tuple.Source, Host: d.OriginDomain, Port: tuple.Destination.Port(), Secure: reason == "REASSEMBLY_COMPLETE" || reason == "SNI_FOUND"}
	if reason == "ECH_OUTER_SNI_ONLY" {
		q.Host, q.HintOnly = "", true
	}
	cur, err := c.automaticOwnerProfile(q.Owner)
	if err != nil || !cur.enabled || c.policyRevision(cur.profile) != c.policyRevision(p) || cur.network != d.Flow.Network {
		return nil, d, errors.New("AUTOMATIC_SCOPE_CHANGED")
	}
	plan := browserproxy.Plan{Enabled: true, Network: cur.network, Destination: tuple.Destination, Policy: d.Policy, Probe: "AUTOMATIC_DIRECT_FIRST"}
	if q.Host == "" && q.Port == 443 && plan.Policy.Source != "rule" {
		plan = stallRetryPlan(cur, plan)
		plan.Policy.Source, plan.Policy.Reason = "automatic_opaque_tls", "TLS443 origin unavailable: authenticated relay, no invented inner SNI or LOCAL transform"
	}
	n := &c.browser.applications
	record, err := n.begin(q, tuple)
	if err != nil {
		return nil, d, err
	}
	revision := cur.automaticRevision
	open := func(work context.Context, request browserproxy.Request, actual browserproxy.Plan) (net.Conn, error) {
		fresh, err := c.automaticOwnerProfile(request.Owner)
		if err != nil || !fresh.enabled || fresh.network != cur.network || c.policyRevision(fresh.profile) != revision {
			return nil, errors.New("AUTOMATIC_SCOPE_CHANGED")
		}
		return c.browserOpen(work, request, actual)
	}
	conn, plan, err := c.openAutomaticPlan(ctx, cur, q, plan, open)
	n.opened(record, plan, err)
	d = applyFlowResult(p, d, plan.Policy, cur.network, c.browserLocal(plan.Policy.Strategy))
	d.BlockOnFailure, d.NewConnectionsOnly = true, true
	if err != nil {
		return nil, d, err
	}
	return newNativeBrowserConn(conn, n, record), d, nil
}

// Reuse the common service ladder rather than treating each new executable as
// another manually configured browser. The destination remains the captured IP;
// DNS peers are considered only after this exact ordinary address has failed.
func (c *Controller) openAutomaticPlan(ctx context.Context, cur profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) (net.Conn, browserproxy.Plan, error) {
	cur = c.captureAutomaticScope(cur)
	if !c.automaticScopeCurrent(cur) {
		return nil, p, errAutomaticScopeChanged
	}
	open = c.automaticScopedOpen(cur, open)
	if !cur.enabled || cur.routingDisabled || !automaticApplication(cur.profile) || directOnlyFlow(wp.Tuple{Protocol: "tcp", Destination: p.Destination}) || !p.Destination.Addr().Is4() {
		return nil, p, errors.New("AUTOMATIC_SCOPE_EXCLUDED")
	}
	if p.Policy.Source == "rule" || p.Policy.Source == "configured_baseline" || p.Policy.Action == flowpolicy.Block {
		conn, err := open(ctx, q, p)
		return conn, p, err
	}
	if q.Host != "" && c.browserOriginPolicy(q.Host).Kind == "RELAY" {
		p.Policy = c.browserFlow(cur.profile, cur.id, wp.Tuple{Protocol: "tcp", Destination: p.Destination}, q.Host, cur.network)
		return c.openBrowserPlan(ctx, cur, q, p, open)
	}
	if p.Policy.Action == flowpolicy.RelayRequired {
		conn, err := open(ctx, q, p)
		return conn, p, err
	}
	if q.Secure && q.Port == 443 && browserproxy.ValidPublicDNSName(q.Host) {
		if c.browserOriginPolicy(q.Host).Kind == "DPI" || c.localLadderEligible(cur, q, p) {
			return c.openBrowserPlan(ctx, cur, q, p, open)
		}
		// Complete ClientHello only, bounded first-flight retry, never HTTP bodies,
		// TLS early data, or a second route after ANY upstream response byte.
		return c.openAutomaticTLS(ctx, cur, q, p, open)
	}
	// Unknown protocols and HTTP get connect-failure recovery only. Silence on
	// an arbitrary established socket is not evidence of DPI or packet loss.
	key := c.directTimeoutKey(cur, q, p)
	key.Host = p.Destination.Addr().String()
	if cur.network == "" || !c.browser.directTimeouts.AddressFailed(key, time.Now()) {
		attempt, stop := context.WithTimeout(ctx, 1500*time.Millisecond)
		conn, err := open(attempt, q, p)
		stop()
		if err == nil || ctx.Err() != nil || !retryableDirectOpen(err) {
			return conn, p, err
		}
		if cur.network != "" && c.automaticScopeCurrent(cur) {
			c.browser.directTimeouts.RecordTimeout(key, time.Now())
		}
	}
	p = stallRetryPlan(cur, p)
	p.Policy.Source, p.Policy.Reason = "automatic_connect_failure", "This network/application/endpoint failed DIRECT connect; authenticated relay before application bytes, negative expires after 10min"
	conn, err := open(ctx, q, p)
	return conn, p, err
}

func (c *Controller) openAutomaticTLS(ctx context.Context, cur profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) (net.Conn, browserproxy.Plan, error) {
	key := c.directTimeoutKey(cur, q, p)
	if cur.network != "" && c.browser.directTimeouts.AddressFailed(key, time.Now()) {
		return c.openOrdinaryAddresses(ctx, cur, q, p, open)
	}
	failed := func(reason string) {
		if cur.network != "" && c.automaticScopeCurrent(cur) && automaticNetworkFailure(reason) {
			c.browser.directTimeouts.RecordTimeout(key, time.Now())
		}
	}
	attempt, stop := context.WithTimeout(ctx, 1500*time.Millisecond)
	conn, err := open(attempt, q, p)
	stop()
	if err != nil {
		if ctx.Err() != nil || !retryableDirectOpen(err) {
			return nil, p, err
		}
		failed("DIRECT_OPEN_FAILED")
		return c.openOrdinaryAddresses(ctx, cur, q, p, open)
	}
	p.FirstFlightManaged = true
	ref := &youtubePlanRef{}
	ref.set(p, conn)
	conn = browserproxy.WatchFirstFlight(c.ctx, conn, 1200*time.Millisecond, func(work context.Context) (net.Conn, error) {
		next, actual, err := c.openOrdinaryAddresses(work, cur, q, p, open)
		if err == nil {
			ref.set(actual, next)
		}
		return next, err
	}, failed)
	return &youtubePlanConn{Conn: conn, ref: ref}, p, nil
}

func automaticNetworkFailure(reason string) bool {
	switch reason {
	case "DIRECT_OPEN_FAILED", "OPEN_FAILED", "ORIGIN_SILENT", "ORIGIN_EOF_NO_BYTES", "ORIGIN_EARLY_WRITE_CLOSED":
		return true
	}
	return false // TLS alerts/partial replies are not a network failure verdict.
}

func (c *Controller) automaticStatus() map[string]any {
	n := &c.browser.applications
	n.mu.Lock()
	rows := make([]nativeBrowserRecord, 0, len(n.records))
	for _, r := range n.records {
		rows = append(rows, snapshotConnectionEvidence(r))
	}
	lost := n.lost
	n.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID > rows[j].ID })
	total := len(rows)
	if len(rows) > 8 {
		rows = rows[:8]
	}
	c.mu.Lock()
	enabled := c.enabled && c.settings.Automatic
	c.mu.Unlock()
	status := map[string]any{"version": 2, "observed_at": time.Now().UTC(), "enabled": enabled, "records": rows, "records_total": total, "records_omitted": total - len(rows), "records_lost": lost,
		"application_verification": "NOT_VERIFIED; TLS records and bytes do not prove service, account or region access",
		"discovery":                "automatic, ephemeral, verified process; explicit profiles retain priority", "scope": "public IPv4 TCP; HTTPS443 first-flight/local ladder; other TCP connect failures only",
		"limits": []string{"unknown UDP is not switched on silence", "native IPv6 transport is not implemented", "encrypted application/region/auth errors are not inspected", "existing flows remain pinned"}}
	// TLS/attempt metadata and long executable paths share the IPC frame budget.
	// Preserve newest records and report every omission, including size trimming.
	for {
		status["records"], status["records_omitted"] = rows, total-len(rows)
		status["records_truncated"] = len(rows) < total || lost > 0
		raw, _ := json.Marshal(status)
		if len(raw) <= 60*1024 || len(rows) == 0 {
			return status
		}
		rows = rows[:len(rows)-1]
	}
}
