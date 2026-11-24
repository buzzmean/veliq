package clientservice

import (
	"encoding/json"
	"errors"
	"github.com/buzzmean/veliq/core/localstrategy"
	"github.com/buzzmean/veliq/core/security"
	"os"
	"path/filepath"
	"strings"
)

func (c *Controller) loadLocal() error {
	b, err := os.ReadFile(filepath.Join(filepath.Dir(c.customPath), "local-strategies.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(b) > 24000 {
		return errors.New("local config too large")
	}
	var v localstrategy.Config
	if err = security.Parse(b, &v); err != nil {
		return err
	}
	return c.Local.Reload(v)
}
func (c *Controller) handleLocal(method string, raw json.RawMessage) (any, error) {
	if method == "local.presets" {
		return localstrategy.Presets(), nil
	}
	if method == "local.preset.apply" {
		var q struct {
			Application  string `json:"application"`
			Preset       string `json:"preset"`
			QuicFallback bool   `json:"quic_fallback"`
		}
		if err := security.Parse(raw, &q); err != nil {
			return nil, err
		}
		entries, selected, err := localstrategy.PresetProfiles(q.Preset, q.Application, q.QuicFallback)
		if err != nil {
			return nil, err
		}
		c.localMu.Lock()
		defer c.localMu.Unlock()
		cfg := c.Local.Config()
		cfg.Enabled = true
		kept := []localstrategy.Profile{}
		for _, p := range cfg.User {
			if p.Preset != q.Preset || !strings.EqualFold(strings.ReplaceAll(p.Application, `\`, "/"), strings.ReplaceAll(q.Application, `\`, "/")) {
				kept = append(kept, p)
			}
		}
		cfg.User = append(kept, entries...)
		saved, err := c.setLocalConfig(cfg)
		if err != nil {
			return nil, err
		}
		return map[string]any{"config": saved, "strategy_id": selected, "preset": q.Preset, "version": localstrategy.PresetVersion}, nil
	}
	if method == "local.compare" {
		return compareLocalReports(raw)
	}
	if method == "local.network" {
		if n := c.network.Load(); n != nil {
			return n, nil
		}
		return nil, errors.New("network inspection pending")
	}
	if method == "local.record" || method == "local.recommend" {
		return c.handleLocalEvidence(method, raw)
	}
	if method == "local.get" {
		return c.Local.Config(), nil
	}
	if method == "local.metrics" {
		return c.Local.Metrics(), nil
	}
	c.localMu.Lock()
	defer c.localMu.Unlock()
	var v localstrategy.Config
	if err := security.Parse(raw, &v); err != nil {
		return nil, err
	}
	return c.setLocalConfig(v)
}
func (c *Controller) setLocalConfig(v localstrategy.Config) (any, error) {
	if len(v.Builtin) > 0 {
		return nil, errors.New("built-in strategies are reserved; use user profiles")
	}
	if err := c.Local.Validate(v); err != nil {
		return nil, err
	}
	if c.customPath != "" {
		dir := filepath.Dir(c.customPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
		f, err := os.CreateTemp(dir, ".local-strategies-*")
		if err != nil {
			return nil, err
		}
		defer os.Remove(f.Name())
		f.Chmod(0600)
		b, _ := json.Marshal(v)
		_, err = f.Write(b)
		if err == nil {
			err = f.Sync()
		}
		ce := f.Close()
		if err != nil {
			return nil, err
		}
		if ce != nil {
			return nil, ce
		}
		if err = os.Rename(f.Name(), filepath.Join(dir, "local-strategies.json")); err != nil {
			return nil, err
		}
	}
	// Keep unmatched application connections intact on local-only config edits.
	next := localstrategy.New()
	if err := next.Reload(v); err != nil {
		return nil, err
	}
	ids := []string{}
	for _, p := range c.Profiles.List() {
		if c.Local.ApplicationRevision(p.Executables) != next.ApplicationRevision(p.Executables) {
			ids = append(ids, p.ID)
		}
	}
	change := func() error { return c.Local.Reload(v) }
	if len(ids) > 0 {
		if err := c.reconfigureApplications(ids, change); err != nil {
			return nil, err
		}
	} else if err := change(); err != nil {
		return nil, err
	}
	return c.Local.Config(), nil
}
