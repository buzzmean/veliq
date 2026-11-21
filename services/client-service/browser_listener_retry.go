package clientservice

import (
	"errors"
	"github.com/buzzmean/neexitlag/core/browserproxy"
)

// Called under browser.mu. A temporary bind conflict on boot must not leave a
// configured lane permanently pending. Never replace a living listener/flow.
func (c *Controller) ensureBrowserListenerLocked(edge bool) error {
	index := 0
	address := c.browser.address
	server := c.browser.server
	if edge {
		index = 1
		e := c.edgeLocked()
		address = e.saved.Address
		server = e.server
	}
	if server != nil {
		if server.Snapshot().Listening {
			return nil
		}
		return errors.New("CONNECT_LISTENER_STOPPED")
	}
	if address == "" {
		return errors.New("CONNECT_LISTENER_NOT_PREPARED")
	}
	p := &c.browser.readiness
	p.mu.Lock()
	p.listenerAttempts[index]++
	p.mu.Unlock()
	cfg := browserproxy.Config{TransportCheck: c.transportCheckSettings, RequireClientHelloReplay: true, Address: address, Authorize: c.browserOwner, AuthorizeForwarded: c.browserRecoveryOwner, Plan: c.browserPlan, Open: c.browserOpen, OpenPlan: c.browserOpenPlan, TransformApplied: c.browserTransform, OnStall: c.browserStall, OnDirectAnswered: c.browserDirectAnswered}
	if edge {
		cfg.Authorize = c.edgeOwner
		cfg.AuthorizeForwarded = c.edgeRecoveryOwner
	}
	next, err := browserproxy.Listen(c.ctx, cfg)
	if err != nil {
		return errors.New("CONNECT_LISTENER_BIND_FAILED")
	}
	if edge {
		c.edgeLocked().server = next
	} else {
		c.browser.server = next
	}
	return nil
}
