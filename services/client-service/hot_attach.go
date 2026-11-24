package clientservice

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
)

// Reconfigure is optional to preserve portable/older backend contracts.
func (c *Controller) reconfigure(app string, change func() error) error {
	if b, ok := c.Backend.(interface {
		Reconfigure(string, func() error) error
	}); ok {
		return b.Reconfigure(app, change)
	}
	return change()
}
func (c *Controller) hotAttachStatus() *wp.HotAttachStatus {
	if b, ok := c.Backend.(interface{ HotAttachStatus() wp.HotAttachStatus }); ok {
		s := b.HotAttachStatus()
		return &s
	}
	return nil
}
func (c *Controller) policyRevision(p profiles.Profile) string {
	// Per-profile content plus matching local strategies only: edits for Discord
	// must not reconnect Chrome. No rolling score/session state enters this stamp.
	c.mu.Lock()
	automatic, failover := c.settings.Automatic, c.settings.Failover
	c.mu.Unlock()
	raw, _ := json.Marshal(struct {
		Profile   profiles.Profile
		Automatic bool
		Failover  string
		Local     string
	}{p, automatic, failover, c.Local.ApplicationRevision(p.Executables)})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:16])
}

func (c *Controller) reconfigureApplications(ids []string, change func() error) error {
	if b, ok := c.Backend.(interface {
		ReconfigureApplications([]string, func() error) error
	}); ok {
		return b.ReconfigureApplications(ids, change)
	}
	return change()
}

// Browser enrollment changes new connections only; existing HTTP/2/TCP stays pinned.
func (c *Controller) reconfigureBrowserNewConnections(app string, change func() error) error {
	if b, ok := c.Backend.(interface {
		ReconfigureNewConnections(string, func() error) error
	}); ok {
		return b.ReconfigureNewConnections(app, change)
	}
	return change()
}
