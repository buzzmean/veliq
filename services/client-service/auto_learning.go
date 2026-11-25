package clientservice

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/localstrategy"
	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func applicationKey(p profiles.Profile) string {
	if p.Identity != nil && p.Identity.PackageFamily != "" {
		return strings.ToLower(p.Identity.Root) + "/" + p.Identity.PackageFamily + "/" + p.Identity.RelativePath
	}
	if p.Identity != nil {
		return strings.ToLower(strings.ReplaceAll(p.Identity.Root, "\\", "/")) + "/" + strings.ToLower(p.Identity.Executable)
	}
	if len(p.Executables) > 0 {
		return strings.ToLower(strings.ReplaceAll(p.Executables[0], "\\", "/"))
	}
	return ""
}
func (c *Controller) learnKey(p profiles.Profile, network, protocol, target string, port uint16) flowpolicy.LearnKey {
	// A Discord config update must not invalidate Chrome's evidence.
	local := []any{}
	for _, v := range c.Local.Config().User {
		for _, exe := range p.Executables {
			if strings.EqualFold(strings.ReplaceAll(v.Application, "\\", "/"), strings.ReplaceAll(exe, "\\", "/")) {
				local = append(local, v)
			}
		}
	}
	raw, _ := json.Marshal(struct {
		Rules []flowpolicy.Rule
		Local []any
	}{p.Rules, local})
	h := sha256.Sum256(raw)
	return flowpolicy.LearnKey{Network: network, Application: applicationKey(p), Protocol: protocol, Target: strings.ToLower(target), Port: port, Revision: hex.EncodeToString(h[:])}
}
func (c *Controller) recordAutoTrial(v localRecord) error {
	// Only the existing strictly scoped tester contract may populate this cache.
	// Passive transform/TCP response counters alone are not application success.
	if v.CaptureMarker == nil || v.FlowID == 0 || v.PID == 0 || v.CreationTime == 0 {
		return nil
	}
	target := strings.ToLower(v.Domain)
	if target == "" && v.Success {
		target = strings.ToLower(v.ObservedHostname)
	}
	if target == "" {
		return nil
	}
	backend, ok := c.Backend.(interface {
		DiagnosticsScoped(wp.EvidenceQuery) (wp.CaptureEvidence, error)
	})
	if !ok {
		return errors.New("scoped AUTO proof unavailable")
	}
	ev, err := backend.DiagnosticsScoped(wp.EvidenceQuery{PID: v.PID, CreationTime: v.CreationTime, Source: v.Source, Destination: v.Destination, Since: v.CaptureMarker})
	if err != nil {
		return err
	}
	if ev.Truncated || ev.EvidenceLost {
		return errors.New("incomplete AUTO proof")
	}
	proved := false
	for _, f := range ev.Flows {
		if f.FlowID != v.FlowID || f.CreationTime != v.CreationTime || f.PID != v.PID || !strings.EqualFold(f.Executable, v.Application) || f.Source != v.Source || f.Domain != "" && !strings.EqualFold(f.Domain, target) {
			continue
		}
		if !v.Success {
			proved = f.Counters.DirectPlus > 0 && f.Strategy == v.Strategy
			continue
		}
		switch v.Strategy {
		case "DIRECT":
			proved = f.Route == "DIRECT" && f.Counters.Direct > 0 && f.Counters.DirectPlus == 0 && f.Counters.Relayed == 0
		case "RELAY":
			proved = f.Route == "RELAY" && f.RelayID == v.Measurement.RouteID && f.Counters.RelayedBytes > 0 && f.Counters.ReplyBytes > 0
		default:
			proved = f.Route == "DIRECT_PLUS" && f.Strategy == v.Strategy && f.Counters.DirectPlus > 0 && f.Counters.RelayedBytes == 0 && f.LocalInspection != nil && f.LocalInspection.TransformApplied
		}
	}
	if !proved {
		return errors.New("AUTO result has no exact captured route evidence")
	}
	var p profiles.Profile
	found := false
	for _, candidate := range c.Profiles.List() {
		for _, exe := range candidate.Executables {
			if strings.EqualFold(strings.ReplaceAll(exe, "\\", "/"), strings.ReplaceAll(v.Application, "\\", "/")) {
				p = candidate
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		return nil
	}
	dest, err := netip.ParseAddrPort(v.Destination)
	if err != nil {
		return err
	}
	r := flowpolicy.Result{Action: flowpolicy.Direct, Source: "verified_trial", Fallback: flowpolicy.FailOpen}
	switch v.Strategy {
	case "DIRECT":
	case "RELAY":
		r.Action = flowpolicy.Relay
		r.RelayID = v.Measurement.RouteID
	default:
		r.Action = flowpolicy.DirectPlus
		r.Strategy = v.Strategy
	}
	score := 0.0
	if v.Success {
		score = optimizer.Score(v.Measurement)
	}
	now := time.Now()
	ttl := 15 * time.Minute
	if !v.Success {
		ttl = 5 * time.Minute
	}
	if err = c.AutoLearned.Record(flowpolicy.Learned{Key: c.learnKey(p, v.Network, v.Protocol, target, dest.Port()), Result: r, Success: v.Success, Score: score, Observed: now, Expires: now.Add(ttl)}, now); err != nil {
		return err
	}
	return c.saveAutoLearning()
}
func (c *Controller) saveAutoLearning() error {
	if c.customPath == "" {
		return nil
	}
	c.autoMu.Lock()
	defer c.autoMu.Unlock()
	raw, err := json.Marshal(c.AutoLearned.Snapshot(time.Now()))
	if err != nil {
		return err
	}
	if len(raw) > 1024*1024 {
		return errors.New("learning persistence bound")
	}
	dir := filepath.Dir(c.customPath)
	f, err := os.CreateTemp(dir, ".auto-learning-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	f.Chmod(0600)
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, filepath.Join(dir, "auto-learning.json"))
}
func (c *Controller) loadAutoLearning() error {
	file, err := os.Open(filepath.Join(filepath.Dir(c.customPath), "auto-learning.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return err
	}
	if stat.Size() > 1024*1024 {
		return errors.New("learning persistence bound")
	}
	var all []flowpolicy.Learned
	if err = json.NewDecoder(file).Decode(&all); err != nil {
		return err
	}
	if len(all) > 12288 {
		return errors.New("learning entry bound")
	}
	for _, v := range all {
		if time.Now().Before(v.Expires) {
			if err = c.AutoLearned.Record(v, time.Now()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Controller) baselineRevision(p profiles.Profile) string {
	cfg := c.Local.Config()
	if !cfg.Enabled {
		return ""
	}
	for _, v := range cfg.User {
		if v.ID == p.LocalStrategyID && v.Enabled {
			for _, exe := range p.Executables {
				if strings.EqualFold(strings.ReplaceAll(v.Application, "\\", "/"), strings.ReplaceAll(exe, "\\", "/")) {
					b, _ := json.Marshal(v)
					h := sha256.Sum256(b)
					return hex.EncodeToString(h[:])
				}
			}
		}
	}
	return ""
}
func (c *Controller) hasBaseline(p profiles.Profile, network string) bool {
	return p.AutoNetwork != "" && p.AutoNetwork == network && p.AutoRevision != "" && p.AutoRevision == c.baselineRevision(p)
}

func (c *Controller) autoCandidateQuarantined(m localstrategy.Metadata) bool {
	n := c.network.Load()
	if n == nil || n.Fingerprint == "" || m.Domain == "" {
		return false
	}
	for _, p := range c.Profiles.List() {
		for _, exe := range p.Executables {
			if strings.EqualFold(strings.ReplaceAll(exe, "\\", "/"), strings.ReplaceAll(m.Application, "\\", "/")) {
				if c.AutoLearned.Quarantined(c.learnKey(p, n.Fingerprint, m.Protocol, m.Domain, m.Destination.Port()), m.StrategyID, time.Now()) {
					return true
				}
			}
		}
	}
	return false
}
