package clientservice

import (
	"context"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"net"
	"time"
)

// Called only after per-socket browser PID/birth/path/SID validation. Never
// use Engine/WinDivert/relay, DNS pins or learned routes while Optimize is off.
func disabledBrowserPlan(p browserproxy.Plan) browserproxy.Plan {
	return browserproxy.Plan{Destination: p.Destination, Network: p.Network,
		Probe: "BROWSER_DISABLED_DIRECT", Policy: flowpolicy.Result{Action: flowpolicy.Direct,
			Fallback: flowpolicy.FailOpen, Source: "optimization_disabled", Reason: "cached PAC compatibility; optimization disabled"}}
}
func openBrowserDirectCompatibility(ctx context.Context, p browserproxy.Plan) (net.Conn, error) {
	return (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", p.Destination.String())
}

// Drop no active TCP connections. A cached-PAC browser keeps the compatibility
// listener alive; after three idle minutes no unnecessary accept socket remains.
func (c *Controller) retireDisabledBrowserListeners(now time.Time, idle time.Duration) {
	c.activationMu.Lock()
	defer c.activationMu.Unlock()
	c.browser.mu.Lock()
	defer c.browser.mu.Unlock()
	c.mu.Lock()
	enabled := c.enabled && c.settings.Automatic
	c.mu.Unlock()
	if enabled {
		return
	}
	if s := c.browser.server; s != nil && s.CloseIfIdle(now, idle) {
		c.browser.server = nil
	}
	if e := c.browser.edge; e != nil && e.server != nil && e.server.CloseIfIdle(now, idle) {
		e.server = nil
	}
}
