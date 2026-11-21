package clientservice

import (
	"encoding/json"
	"errors"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"os"
	"path/filepath"
)

func (c *Controller) browserGuardFile() string {
	if c.customPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(c.customPath), "browser-recovery-guard.json")
}
func (c *Controller) publishBrowserGuard(deny bool) error {
	path := c.browserGuardFile()
	if path == "" {
		return nil
	}
	c.mu.Lock()
	compatibility := !c.enabled || !c.settings.Automatic
	c.mu.Unlock()
	guard := browserproxy.RecoveryGuard{DirectCompatibility: compatibility && !deny, Version: 1, Deny: deny, Profiles: map[string]browserproxy.RecoveryGuardProfile{}}
	if !deny {
		for _, p := range c.Profiles.List() {
			if (!chromeProfile(p) && !edgeProfile(p)) || p.Trial != nil {
				continue
			}
			entry := browserproxy.RecoveryGuardProfile{Executables: p.Executables, Strict: p.Mode != profiles.Auto && p.Mode != profiles.Direct}
			for _, rule := range append(append([]flowpolicy.Rule{}, p.Rules...), p.BrowserRecoveryRules...) {
				if rule.Action == flowpolicy.Direct {
					continue
				}
				if len(rule.Domains) == 0 {
					entry.Strict = true
				} else {
					entry.Domains = append(entry.Domains, rule.Domains...)
				}
			}
			if len(entry.Domains) > 512 {
				return errors.New("Chrome recovery guard domain capacity")
			}
			guard.Profiles[p.ID] = entry
		}
	}
	raw, err := json.Marshal(guard)
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 || len(guard.Profiles) > 128 {
		return errors.New("Chrome recovery guard capacity")
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".browser-guard-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if c.BrowserOwnerSID != "" {
		if err = wp.AllowOwnerReadFile(name, c.BrowserOwnerSID); err != nil {
			return err
		}
	}
	return os.Rename(name, path)
}
