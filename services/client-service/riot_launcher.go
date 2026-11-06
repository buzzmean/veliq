package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

func riotAuto(p profiles.Profile) bool {
	return p.AppPreset == "riot-client" && p.Mode == profiles.Auto
}
func riotHost(h string) bool {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	for _, s := range []string{"riotgames.com", "riotcdn.net", "pvp.net"} {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}
func (c *Controller) riotOwnerProfile(o browserproxy.Owner) (profilesResult, error) {
	id := wp.ProcessIdentity{PID: o.PID, CreationTime: o.Birth, Path: o.Exe}
	if !wp.IsCurrent(id) || !profiles.RiotLauncherPath(id.Path) {
		return profilesResult{}, errors.New("RIOT_OWNER_EXITED_OR_PATH_CHANGED")
	}
	p, ok := c.matchApplication(id)
	if !ok || p.ID != o.Profile || !riotAuto(p) {
		return profilesResult{}, errors.New("RIOT_PROFILE_CHANGED")
	}
	c.mu.Lock()
	enabled := c.enabled && c.settings.Automatic
	c.mu.Unlock()
	network := ""
	if n := c.network.Load(); n != nil && n.Error == "" && time.Since(n.ObservedAt) < 45*time.Second {
		network = n.Fingerprint
	}
	return profilesResult{profile: p, id: id, network: network, enabled: enabled, routingDisabled: !enabled}, nil
}

// Reuse the finite first-flight guard: full ClientHello only, never replay after
// ANY origin byte. No subnet verdict is inferred from a single silent endpoint.
func (c *Controller) openRiotPlan(ctx context.Context, cur profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) (net.Conn, browserproxy.Plan, error) {
	ref := &youtubePlanRef{}
	// Every actual OPEN updates the shared reporter, including a later LOCAL ->
	// RELAY zero-origin retry inside the nested common ladder.
	observedOpen := func(work context.Context, request browserproxy.Request, actual browserproxy.Plan) (net.Conn, error) {
		conn, err := open(work, request, actual)
		if err == nil {
			ref.set(actual, conn)
		}
		return conn, err
	}

	addresses := []netip.AddrPort{p.Destination}
	for _, a := range p.DirectCandidates {
		if a != p.Destination && a.IsValid() && a.Addr().Is4() && browserproxy.PublicDNSAddress(a.Addr()) {
			addresses = append(addresses, a)
			break
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	var step func(context.Context, int) (net.Conn, browserproxy.Plan, error)
	step = func(work context.Context, index int) (net.Conn, browserproxy.Plan, error) {
		for index < len(addresses) {
			actual := p
			actual.Destination = addresses[index]
			actual.FirstFlightManaged = true
			key := c.directTimeoutKey(cur, q, actual)
			if cur.network != "" && c.browser.directTimeouts.AddressFailed(key, time.Now()) {
				index++
				continue
			}
			budget := time.Until(deadline)
			if budget > 900*time.Millisecond {
				budget = 900 * time.Millisecond
			}
			if budget <= 0 {
				break
			}
			attempt, cancel := context.WithTimeout(work, budget)
			conn, e := observedOpen(attempt, q, actual)
			cancel()
			nextIndex := index + 1
			failed := func(reason string) {
				if cur.network != "" && (!automaticApplication(cur.profile) || automaticNetworkFailure(reason)) {
					c.browser.directTimeouts.RecordTimeout(key, time.Now())
					c.browser.directTimeouts.SetProbeHost(key, q.Host)
				}
			}
			if e != nil {
				if work.Err() != nil {
					return nil, actual, work.Err()
				}
				if !retryableDirectOpen(e) {
					return nil, actual, e
				}
				failed("OPEN_FAILED")
				index++
				continue
			}
			ref.set(actual, conn)
			conn = browserproxy.WatchFirstFlight(c.ctx, conn, budget, func(next context.Context) (net.Conn, error) { n, _, err := step(next, nextIndex); return n, err }, failed)
			return conn, actual, nil
		}
		// Same scoped catalog, background verified GET, LOCAL cache and negative TTL
		// as browsers. Healthy auth/CDN hosts never enter this branch.
		conn, actual, e := c.openYoutubeLadder(work, cur, q, p, observedOpen)
		if e == nil {
			ref.set(actual, conn)
		}
		return conn, actual, e
	}
	conn, actual, e := step(ctx, 0)
	if e != nil {
		return nil, actual, e
	}
	return &youtubePlanConn{Conn: conn, ref: ref}, actual, nil
}

// Separate accounting: Riot must never count as Chrome/Edge readiness evidence.
func (c *Controller) riotStatus() map[string]any {
	n := &c.browser.riot
	n.mu.Lock()
	rows := []nativeBrowserRecord{}
	for _, r := range n.records {
		if r.planReporter != nil {
			p := r.planReporter.CurrentPlan()
			r.Policy = p.Policy
			r.Upstream = p.Destination.String()
			r.Probe = p.Probe
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID > rows[j].ID })
	if len(rows) > 8 {
		rows = rows[:8]
	}
	n.mu.Unlock()
	stages := []youtubeStage{}
	for _, s := range c.browser.youtube.snapshot().Stages {
		if s.Service == "riot-client" {
			stages = append(stages, s)
		}
	}
	result := map[string]any{"records": rows, "stages": stages, "scope": "Riot launcher TCP443 only; separate from browser readiness; no game/anti-cheat inheritance", "address_policy": "DNS first two IPv4; per-network/profile/host/IP negative TTL10min; no Cloudflare subnet inference; no replay after any origin byte"}
	for {
		raw, _ := json.Marshal(result)
		if len(raw) < 48000 || len(rows) == 0 {
			return result
		}
		rows = rows[:len(rows)-1]
		result["records"] = rows
		result["truncated"] = true
	}
}
