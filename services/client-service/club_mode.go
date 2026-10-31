package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/buzzmean/neexitlag/internal/clientconfig"
	"os"
	"path/filepath"
	"strings"

	"github.com/buzzmean/neexitlag/core/profiles"
)

// ConfigureClub trusts only the SYSTEM/admin-protected manifest, never owner IPC.
// Called before activation or public pipe startup. Internal controller operations
// retain their normal path; the external pipe has a separate read-only gate.
func (c *Controller) ConfigureClub(m Manifest) error {
	m = clientconfig.Normalize(m)
	if !m.ClubImage {
		return nil
	}
	if len(m.ClubBrowserPaths) > 2 {
		return errors.New("CLUB_BROWSER_PATH_LIMIT")
	}
	for _, file := range m.ClubBrowserPaths {
		name := strings.ToLower(filepath.Base(file))
		id, title := "club-chrome", "Google Chrome"
		if name == "msedge.exe" {
			id, title = "club-edge", "Microsoft Edge"
		} else if name != "chrome.exe" {
			return errors.New("CLUB_BROWSER_PATH_INVALID")
		}
		if !filepath.IsAbs(file) {
			return errors.New("CLUB_BROWSER_PATH_INVALID")
		}
		st, err := os.Stat(file)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !st.Mode().IsRegular() {
			return errors.New("CLUB_BROWSER_PATH_UNAVAILABLE")
		}
		exists := false
		for _, p := range c.Profiles.List() {
			for _, exe := range p.Executables {
				if strings.EqualFold(exe, file) {
					exists = true
					// Explicit administrator opt-out survives. Legacy DIRECT/pending
					// is NOT an opt-out and must not reproduce the fresh AUTO cycle.
					if !p.BrowserAutoDisabled {
						p.Mode = profiles.Auto
						p.BrowserTransport = "native"
						if name == "msedge.exe" {
							p.AppPreset = "edge-sites"
						}
						prepareAuto(&p)
						if err = c.Profiles.Upsert(p); err != nil {
							return err
						}
						c.mu.Lock()
						c.localProfiles[p.ID] = p
						c.mu.Unlock()
					}
				}
			}
		}
		if exists {
			continue
		}
		p := profiles.Profile{ID: id, Name: title, Executables: []string{file}, Mode: profiles.Auto, BrowserTransport: "native", Custom: true}
		if name == "msedge.exe" {
			p.AppPreset = "edge-sites"
		}
		prepareAuto(&p)
		if err = c.Profiles.Upsert(p); err != nil {
			return err
		}
		c.mu.Lock()
		c.localProfiles[p.ID] = p
		c.mu.Unlock()
	}
	c.mu.Lock()
	c.settings.Automatic = true
	c.mu.Unlock()
	if err := c.saveProfiles(); err != nil {
		return err
	}
	if err := c.saveSettings(); err != nil {
		return err
	}
	c.syncPolicies()
	c.clubConfig.Store(&clubConfiguration{manifest: m})
	c.clubMode.Store(true)
	return nil
}

// Read-only allowlist: unknown/future methods fail closed too. A normal owner
// cannot disable club policy by bypassing the GUI. Windows admins control the
// manifest/service and are deliberately outside this boundary.
func clubReadMethod(method string) bool {
	switch method {
	case "riot.status", "browser.local.probes", "traffic.status", "update.status", "local.catalog", "relay.primary.status", "relay.pool.diagnostics", "status", "profiles", "activation.status", "subscription.status", "subscription.refresh", "browser.native.status", "browser.status", "edge.status", "gameudp.status", "club.status", "capture.changes.marker", "capture.changes", "capture.diagnostics":
		return true
	default:
		return false
	}
}
func (c *Controller) HandleOwnerIPC(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	if c.clubMode.Load() && !clubReadMethod(method) {
		return nil, errors.New("CLUB_ADMIN_MANAGED")
	}
	return c.Handle(ctx, method, raw)
}
