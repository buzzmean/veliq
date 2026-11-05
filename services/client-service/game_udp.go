package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/gameudp"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/security"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

const maxGameProfiles = 8

// Each selected exact executable has an independent ladder. The byte/packet
// budget is shared across the PC. No baseline optimizer policy is changed.
type gameEntry struct {
	ProfileID string
	Name      string
	Path      string
	Enabled   bool
	LocalOnly bool
	AntiCheat string
	Engine    *gameudp.Engine
	persisted uint64
}
type gameRuntime struct {
	mu     sync.Mutex
	items  map[string]*gameEntry
	budget *gameudp.Budget
	error  string
}
type gameDiskEntry struct {
	LocalOnly bool               `json:"local_only,omitempty"`
	ProfileID string             `json:"profile_id"`
	Path      string             `json:"exe"`
	Enabled   bool               `json:"enabled"`
	Learning  []gameudp.Learning `json:"learning"`
}
type gameDisk struct {
	Version int             `json:"version"`
	Games   []gameDiskEntry `json:"games"`
}
type GameUDPStatus struct {
	Profiles []GameProfileStatus   `json:"profiles"`
	Guard    wp.GameUDPGuardStatus `json:"guard"`
	Error    string                `json:"error,omitempty"`
}
type GameProfileStatus struct {
	Activity  string           `json:"activity"`
	Ready     bool             `json:"ready"`
	ProfileID string           `json:"profile_id"`
	Name      string           `json:"name"`
	State     string           `json:"state"`
	Reason    string           `json:"reason"`
	AntiCheat string           `json:"anti_cheat"`
	Engine    gameudp.Snapshot `json:"engine"`
}

func (c *Controller) loadGames() {
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(c.customPath), "game-udp.json"))
	if os.IsNotExist(err) {
		return
	}
	var v gameDisk
	if err != nil || len(raw) > 256*1024 || security.Parse(raw, &v) != nil || v.Version != 2 || len(v.Games) > maxGameProfiles {
		c.games.error = "GAME_UDP_CONFIG_INVALID"
		return
	}
	for _, d := range v.Games {
		if d.ProfileID == "" || !gamePath(d.Path) || c.games.items[d.ProfileID] != nil {
			c.games.error = "GAME_UDP_CONFIG_INVALID"
			return
		}
		e := c.newGameLadder(d.Path)
		e.SetLocalOnly(d.LocalOnly)
		e.Configure(d.Path, d.Enabled)
		// Keep the explicit route restriction even when cached evidence is
		// rejected. Rediscovery must not replace it with the legacy relay ladder.
		c.games.items[d.ProfileID] = &gameEntry{ProfileID: d.ProfileID, Path: d.Path, Enabled: d.Enabled, LocalOnly: d.LocalOnly, Engine: e}
		if err := e.Restore(d.Learning, time.Now()); err != nil {
			c.games.error = "GAME_UDP_CONFIG_INVALID"
		}
	}
}
func (c *Controller) saveGamesLocked() error {
	if c.customPath == "" {
		return nil
	}
	v := gameDisk{Version: 2, Games: []gameDiskEntry{}}
	for _, g := range c.games.items {
		v.Games = append(v.Games, gameDiskEntry{ProfileID: g.ProfileID, Path: g.Path, Enabled: g.Enabled, LocalOnly: g.LocalOnly, Learning: g.Engine.Snapshot().Learning})
	}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > 256*1024 {
		return errors.New("GAME_UDP_CONFIG_LIMIT")
	}
	dir := filepath.Dir(c.customPath)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return errors.New("GAME_UDP_SAVE_FAILED")
	}
	f, err := os.CreateTemp(dir, ".game-udp-*")
	if err != nil {
		return errors.New("GAME_UDP_SAVE_FAILED")
	}
	defer os.Remove(f.Name())
	f.Chmod(0600)
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err == nil {
		err = os.Rename(f.Name(), filepath.Join(dir, "game-udp.json"))
	}
	if err != nil {
		return errors.New("GAME_UDP_SAVE_FAILED")
	}
	return nil
}
func gamePath(path string) bool {
	p := gameudp.Canonical(path)
	return len(p) >= 7 && len(p) <= 2048 && p[1] == ':' && p[2] == '/' && !strings.ContainsAny(p, "\x00\r\n") && strings.HasSuffix(p, ".exe") && !strings.Contains(p, "/../")
}
func gameProfileSafe(p profiles.Profile) bool {
	for _, id := range append([]string{"discord", "steam"}, profiles.BuiltInRelayFirstIDs...) {
		if p.ID == id {
			return false
		}
	}
	if (p.Mode != profiles.Direct && p.Mode != profiles.Auto) || p.Trial != nil || p.Identity != nil || len(p.Rules) > 0 || len(p.BrowserRecoveryRules) > 0 {
		return false
	}
	for _, preset := range gameudp.Presets() {
		if p.AppPreset == "game-udp-"+preset.ID {
			return true
		}
	}
	if p.AppPreset != "" {
		return false
	}
	for _, path := range p.Executables {
		base := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
		base = base[strings.LastIndex(base, "/")+1:]
		switch base {
		case "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "browser.exe", "discord.exe", "chatgpt.exe", "codex.exe", "claude.exe", "telegram.exe", "steam.exe", "veliq-service.exe", "neexitlag-service.exe", "veliq.exe":
			return false
		}
	}
	return true
}
func (c *Controller) registerGame(preset gameudp.Preset, path string) {
	if !gamePath(path) {
		return
	}
	c.games.mu.Lock()
	defer c.games.mu.Unlock()
	p, ok := c.Profiles.Match(wp.ProcessIdentity{PID: 1, CreationTime: 1, Path: path})
	if !ok {
		p = profiles.Profile{ID: preset.ID, Name: preset.Name, Executables: []string{path}, Mode: profiles.Direct, AppPreset: "game-udp-" + preset.ID}
		if err := c.Profiles.Upsert(p); err != nil {
			c.games.error = "GAME_PROFILE_REGISTER_FAILED"
			return
		}
		c.mu.Lock()
		c.localProfiles[p.ID] = p
		c.mu.Unlock()
		if err := c.saveProfiles(); err != nil {
			c.games.error = "GAME_PROFILE_SAVE_FAILED"
			return
		}
	}
	if !gameProfileSafe(p) {
		return
	}
	g := c.games.items[p.ID]
	if g == nil {
		if len(c.games.items) >= maxGameProfiles {
			return
		}
		g = &gameEntry{ProfileID: p.ID, Path: path, Enabled: preset.DefaultEnabled, Engine: c.newGameLadder(path)}
		c.games.items[p.ID] = g
		g.Engine.Configure(path, g.Enabled)
	}
	// Never silently re-enable a user opt-out or move an existing per-path identity.
	if gameudp.Canonical(g.Path) == gameudp.Canonical(path) {
		g.Name = preset.Name
		g.AntiCheat = preset.AntiCheat
	}
}
func (c *Controller) discoverGames() {
	for _, p := range gameudp.Presets() {
		if found := wp.DiscoverSteamGame(c.BrowserOwnerSID, p); found.Path != "" {
			c.registerGame(p, found.Path)
		}
	}
}
func (c *Controller) gameGuard() wp.GameUDPGuardStatus {
	if b, ok := c.Backend.(interface{ GameUDPGuardStatus() wp.GameUDPGuardStatus }); ok {
		return b.GameUDPGuardStatus()
	}
	return wp.GameUDPGuardStatus{Error: "UDP_CONFLICT_DETECTOR_UNAVAILABLE"}
}
func (c *Controller) updateGamesGate() {
	c.mu.Lock()
	enabled, automatic := c.enabled, c.settings.Automatic
	c.mu.Unlock()
	n := c.network.Load()
	guard := c.gameGuard()
	reason := ""
	switch {
	case !c.activationNetworkAllowed():
		reason = "ACTIVATION_REQUIRED"
	case !enabled || !automatic:
		reason = "OPTIMIZATION_DISABLED"
	case c.Backend == nil || !c.Backend.Status().Ready:
		reason = "CAPTURE_NOT_READY"
	case n == nil || n.Error != "" || len(n.Fingerprint) != 64 || time.Since(n.ObservedAt) > 45*time.Second:
		reason = "NETWORK_FINGERPRINT_PENDING"
	case len(n.VPN) > 0:
		reason = "EXTERNAL_VPN_ACTIVE"
	case guard.Error != "":
		reason = guard.Error
	case !guard.Ready:
		reason = "UDP_CONFLICT_CHECK_PENDING"
	case guard.Conflict:
		reason = "FOREIGN_UDP_INTERCEPTOR"
	}
	c.games.mu.Lock()
	defer c.games.mu.Unlock()
	for _, g := range c.games.items {
		r := reason
		if r == "" {
			r = gameAntiCheatReason(g.Path, guard)
		}
		p, ok := c.Profiles.Match(wp.ProcessIdentity{PID: 1, CreationTime: 1, Path: g.Path})
		if !ok || p.ID != g.ProfileID || !gameProfileSafe(p) {
			r = "GAME_PROFILE_OVERRIDDEN_OR_REMOVED"
		}
		if c.games.error != "" {
			r = c.games.error
		}
		if !g.Enabled {
			r = "DISABLED_BY_USER"
		}
		if n != nil {
			g.Engine.SetNetwork(n.Fingerprint)
		} else {
			g.Engine.SetNetwork("")
		}
		g.Engine.SetReason(r)
	}
}
func (c *Controller) watchGames() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	nextDiscovery := time.Time{}
	for {
		now := time.Now()
		if !now.Before(nextDiscovery) {
			c.discoverGames()
			nextDiscovery = now.Add(15 * time.Second)
		}
		c.updateGamesGate()
		c.games.mu.Lock()
		dirty := false
		for _, g := range c.games.items {
			g.Engine.Tick(now)
			if g.persisted != g.Engine.Revision() {
				dirty = true
			}
		}
		if dirty {
			if err := c.saveGamesLocked(); err != nil {
				c.games.error = "GAME_UDP_SAVE_FAILED"
			} else {
				for _, g := range c.games.items {
					g.persisted = g.Engine.Revision()
				}
			}
		}
		c.games.mu.Unlock()
		select {
		case <-c.ctx.Done():
			return
		case <-tick.C:
		}
	}
}
func (c *Controller) classifyGameUDP(id wp.ProcessIdentity, t wp.Tuple) (wp.Decision, bool) {
	// No interception override for TCP, DNS, UDP/443, LAN, disabled/unselected games.
	if !gameudp.Eligible(id.Path, id.Path, t.Protocol, t.Destination) {
		return wp.Decision{}, false
	}
	p, ok := c.matchApplication(id)
	if !ok || !gameProfileSafe(p) {
		return wp.Decision{}, false
	}
	c.games.mu.Lock()
	defer c.games.mu.Unlock()
	g := c.games.items[p.ID]
	if g == nil || !g.Enabled || gameudp.Canonical(g.Path) != gameudp.Canonical(id.Path) {
		return wp.Decision{}, false
	}
	n := c.network.Load()
	if !g.Engine.Ready() || n == nil || len(n.Fingerprint) != 64 || time.Since(n.ObservedAt) > 45*time.Second {
		if g.LocalOnly {
			// A suspended local trial must not fall through to AUTO's learned
			// relay choice. Guards still prohibit decoys; only originals pass.
			return wp.Decision{NewConnectionsOnly: true, Revision: "game-udp-local-only", Group: p.ID,
				Flow:   routing.Flow{PID: id.PID, ProcessPath: id.Path, ApplicationID: p.ID, Protocol: t.Protocol, Source: t.Source, Destination: t.Destination, PinnedPolicy: &routing.Policy{}},
				Policy: flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailOpen, Source: "game_udp_local_only", Reason: "LOCAL_ONLY_TRIAL_UNAVAILABLE_DIRECT"}}, true
		}
		return wp.Decision{}, false
	}
	d := wp.Decision{NewConnectionsOnly: true, Revision: "game-udp-ladder-v2", Group: p.ID, Network: n.Fingerprint, GameUDP: g.Engine, GameRelayID: "VPS-01", Flow: routing.Flow{PID: id.PID, ProcessPath: id.Path, ApplicationID: p.ID, Protocol: t.Protocol, Source: t.Source, Destination: t.Destination, PinnedPolicy: &routing.Policy{}}, Policy: flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailOpen, Source: "game_udp_ladder", Reason: "game route chosen and pinned before first datagram"}}
	if p.RelayID != "" {
		d.GameRelayID = p.RelayID
	}
	return d, true
}
func (c *Controller) gameStatus() GameUDPStatus {
	// Reflect current guard/capture/optimization state without waiting for the tick.
	c.updateGamesGate()
	out := GameUDPStatus{Profiles: []GameProfileStatus{}, Guard: c.gameGuard()}
	c.games.mu.Lock()
	defer c.games.mu.Unlock()
	out.Error = c.games.error
	for _, g := range c.games.items {
		s := g.Engine.Snapshot()
		state := "PENDING"
		activity := "NOT_ARMED"
		if !s.Enabled {
			state = "DISABLED"
		} else if s.Reason == "" {
			state = "READY_NEW_FLOWS"
			activity = "WAITING_NEW_FLOW"
			if s.InitialPolicy == "LOCAL_FIRST_UNCONFIRMED_ENDPOINT" {
				state = "ACTIVE"
			}
			for _, f := range s.Flows {
				if f.Outgoing > 0 && time.Since(f.LastOutgoing) < 5*time.Second {
					state = "ACTIVE"
					activity = "TRAFFIC_OBSERVED"
					if f.Stage == gameudp.Local && f.Fakes > 0 {
						activity = "LOCAL_DECOYS_OBSERVED"
					}
					break
				}
			}
		}
		if len(s.Flows) > 12 {
			s.Flows = s.Flows[:12]
			s.Truncated = true
		}
		reason := s.Reason
		if n := c.network.Load(); n != nil && s.Reason == "" {
			for _, l := range s.Learning {
				if l.Network == n.Fingerprint && l.LocalOnly == s.LocalOnly && (!s.LocalOnly || len(s.Flows) == 0 || l.Endpoint == s.Flows[0].Destination) && l.Exhausted && time.Now().Before(l.Expires) {
					state = "COOLDOWN"
					reason = "GAME_UDP_LADDER_EXHAUSTED"
					if s.LocalOnly {
						reason = "GAME_UDP_LOCAL_ONLY_EXHAUSTED"
					}
					activity = "COOLDOWN"
				}
			}
		}
		name := g.Name
		if name == "" {
			name = g.ProfileID
		}
		out.Profiles = append(out.Profiles, GameProfileStatus{ProfileID: g.ProfileID, Name: name, State: state, Reason: reason, AntiCheat: g.AntiCheat, Engine: s, Ready: s.Enabled && reason == "", Activity: activity})
	}
	sort.Slice(out.Profiles, func(i, j int) bool { return out.Profiles[i].ProfileID < out.Profiles[j].ProfileID })
	// IPC responses must remain within the existing 64 KiB envelope.
	for {
		raw, _ := json.Marshal(out)
		if len(raw) <= 56*1024 {
			break
		}
		trimmed := false
		for i := range out.Profiles {
			f := &out.Profiles[i].Engine
			if len(f.Flows) > 0 {
				f.Flows = f.Flows[:len(f.Flows)-1]
				f.Truncated = true
				trimmed = true
			}
		}
		if !trimmed {
			for i := range out.Profiles {
				e := &out.Profiles[i].Engine
				if len(e.Learning) > 0 {
					e.Learning = e.Learning[:len(e.Learning)-1]
					e.Truncated = true
					trimmed = true
				}
			}
			if !trimmed {
				break
			}
		}
	}
	return out
}
func (c *Controller) handleGameUDP(_ context.Context, method string, raw json.RawMessage) (any, error) {
	if strings.HasSuffix(method, ".status") {
		return c.gameStatus(), nil
	}
	var q struct {
		ProfileID string `json:"profile_id"`
		Enabled   *bool  `json:"enabled"`
		LocalOnly *bool  `json:"local_only"`
	}
	if err := security.Parse(raw, &q); err != nil {
		return nil, err
	}
	if method == "pubg.set" && q.ProfileID == "" {
		q.ProfileID = "pubg"
	}
	if q.Enabled == nil {
		return nil, errors.New("GAME_UDP_ENABLED_REQUIRED")
	}
	var p profiles.Profile
	found := false
	for _, v := range c.Profiles.List() {
		if v.ID == q.ProfileID {
			p = v
			found = true
			break
		}
	}
	if !found || !gameProfileSafe(p) {
		return nil, errors.New("GAME_UDP_SELECT_DIRECT_GAME_PROFILE")
	}
	c.games.mu.Lock()
	g := c.games.items[q.ProfileID]
	if g == nil {
		if len(c.games.items) >= maxGameProfiles || len(p.Executables) != 1 || !gamePath(p.Executables[0]) {
			c.games.mu.Unlock()
			return nil, errors.New("GAME_UDP_EXACT_EXECUTABLE_REQUIRED_OR_CAPACITY")
		}
		g = &gameEntry{ProfileID: p.ID, Name: p.Name, Path: p.Executables[0], Engine: c.newGameLadder(p.Executables[0]), AntiCheat: "runtime compatibility unverified"}
		g.Engine.Configure(g.Path, false)
		c.games.items[p.ID] = g
	}
	if *q.Enabled && gameAntiCheatReason(g.Path, c.gameGuard()) != "" {
		c.games.mu.Unlock()
		return nil, errors.New("GAME_UDP_ANTICHEAT_COMPATIBILITY_UNVERIFIED")
	}
	previous, previousLocalOnly := g.Enabled, g.LocalOnly
	if q.LocalOnly != nil {
		g.LocalOnly = *q.LocalOnly
	}
	g.Enabled = *q.Enabled
	if err := c.saveGamesLocked(); err != nil {
		g.Enabled, g.LocalOnly = previous, previousLocalOnly
		c.games.mu.Unlock()
		return nil, err
	}
	g.Engine.SetLocalOnly(g.LocalOnly)
	g.Engine.Configure(g.Path, g.Enabled)
	c.games.mu.Unlock()
	c.updateGamesGate()
	return c.gameStatus(), nil
}
