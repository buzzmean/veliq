package clientservice

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/security"
	"path"
	"strings"
	"time"
)

type autoLease struct {
	Profile, Network, Application string
	Started, Expires              time.Time
}

func (c *Controller) handleAuto(method string, raw json.RawMessage) (any, error) {
	var q struct {
		Profile string `json:"profile_id"`
		Lease   string `json:"lease"`
	}
	if err := security.Parse(raw, &q); err != nil {
		return nil, err
	}
	c.autoMu.Lock()
	defer c.autoMu.Unlock()
	now := time.Now()
	n := c.network.Load()
	if n == nil || n.Error != "" || n.Fingerprint == "" || now.Sub(n.ObservedAt) > 45*time.Second || len(n.VPN) > 0 || len(n.Conflicts) > 0 {
		return nil, errors.New("fresh VPN-free network required for AUTO measurement")
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
	if !found || p.Mode != profiles.Auto || len(p.Executables) != 1 {
		return nil, errors.New("select an existing AUTO application")
	}
	if method == "auto.commit" {
		lease, ok := c.autoJobs[q.Lease]
		if !ok || !now.Before(lease.Expires) || lease.Profile != p.ID || lease.Network != n.Fingerprint || lease.Application != applicationKey(p) {
			return nil, errors.New("AUTO lease expired, changed network or profile")
		}
		result, ok := c.AutoLearned.LookupSince(c.learnKey(p, n.Fingerprint, "tcp", "www.youtube.com", 443), lease.Started, now)
		if !ok {
			return nil, errors.New("no measured successful target route; AUTO did not invent a winner")
		}
		if result.Action == flowpolicy.DirectPlus {
			p.LocalStrategyID = result.Strategy
			p.AutoNetwork = n.Fingerprint
			p.AutoRevision = c.baselineRevision(p)
			p.AppPreset = "youtube"
		} else {
			p.AutoNetwork = ""
			p.LocalStrategyID = ""
		}
		if err := c.reconfigure(p.ID, func() error {
			if err := c.Profiles.Upsert(p); err != nil {
				return err
			}
			c.mu.Lock()
			c.localProfiles[p.ID] = p
			c.mu.Unlock()
			c.syncPolicies()
			return nil
		}); err != nil {
			return nil, err
		}
		if err := c.saveProfiles(); err != nil {
			return nil, err
		}
		return map[string]any{"status": "measured", "route": result.Action, "source": result.Source}, nil
	}
	if c.hasBaseline(p, n.Fingerprint) && p.LocalStrategyID != "" {
		return map[string]any{"status": "configured_baseline", "needs_trial": false}, nil
	}
	if presetFor(p) == "openai" || presetFor(p) == "openai-web" || presetFor(p) == "discord" {
		return map[string]any{"status": "application_policy", "needs_trial": false}, nil
	}
	exe := path.Base(strings.ToLower(strings.ReplaceAll(p.Executables[0], "\\", "/")))
	if exe != "chrome.exe" && exe != "msedge.exe" {
		return map[string]any{"status": "application_default", "needs_trial": false, "detail": "No safe application-level probe adapter registered"}, nil
	}
	for key, v := range c.autoJobs {
		if !now.Before(v.Expires) {
			delete(c.autoJobs, key)
		} else if v.Application == applicationKey(p) && v.Network == n.Fingerprint {
			return nil, errors.New("AUTO measurement already attempted recently; bounded cooldown")
		}
	}
	if len(c.autoJobs) >= 16 {
		return nil, errors.New("AUTO measurement capacity reached")
	}
	// Never replace profiles of other applications. The existing preset endpoint
	// serializes this read-modify-write and has its own strict bounds.
	b, _ := json.Marshal(map[string]any{"application": p.Executables[0], "preset": "youtube", "quic_fallback": true})
	if _, err := c.handleLocal("local.preset.apply", b); err != nil {
		return nil, err
	}
	if _, ok := c.AutoLearned.Lookup(c.learnKey(p, n.Fingerprint, "tcp", "www.youtube.com", 443), now); ok {
		return map[string]any{"status": "cached", "needs_trial": false}, nil
	}
	candidates := []string{}
	for _, v := range c.Local.Config().User {
		if v.Application == p.Executables[0] && v.Preset == "youtube" && !c.AutoLearned.Quarantined(c.learnKey(p, n.Fingerprint, "tcp", "www.youtube.com", 443), v.ID, now) {
			candidates = append(candidates, v.ID)
		}
	}
	if len(candidates) > 7 {
		return nil, errors.New("finite candidate bound")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(nonce)
	c.autoJobs[id] = autoLease{Profile: p.ID, Network: n.Fingerprint, Application: applicationKey(p), Started: now, Expires: now.Add(10 * time.Minute)}
	return map[string]any{"status": "probe_required", "needs_trial": true, "lease": id, "application": p.Executables[0], "preset": "youtube", "url": "https://www.youtube.com/", "candidates": candidates}, nil
}
