package clientservice

import "github.com/buzzmean/veliq/core/browserproxy"

func (c *Controller) browserFirstBytes(edge bool) browserproxy.FirstByteReport {
	c.browser.mu.Lock()
	defer c.browser.mu.Unlock()
	server := c.browser.server
	if edge {
		server = nil
		if c.browser.edge != nil {
			server = c.browser.edge.server
		}
	}
	return server.FirstBytes()
}
