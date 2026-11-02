package clientservice

// Called with browser.mu held. Capture readiness and raw TLS counters never
// establish per-authority ingress. Only the live owner CONNECT lane does.
func (c *Controller) nativeBrowserReadiness(edge bool) string {
	for _, p := range c.Profiles.List() {
		if !nativeBrowserProfile(p) || edgeProfile(p) != edge {
			continue
		}
		c.mu.Lock()
		enabled := c.enabled && c.settings.Automatic
		c.mu.Unlock()
		if !enabled {
			return "NATIVE_DISABLED"
		}
		if !c.nativeBackendReady() {
			return "NATIVE_CAPTURE_NOT_READY"
		}
		if !c.relayConnected() {
			return "NATIVE_RELAY_PENDING"
		}
		// Native-only TLS is the explicitly degraded relay fallback, not proof
		// that encrypted HTTP/2 authorities were isolated by SNI/capture.
		v := c.authorityStatus()
		observed := v.ChromeRequests
		if edge {
			observed = v.EdgeRequests
		}
		if observed > 0 {
			return "AUTHORITY_REQUEST_OBSERVED"
		}
		return "AUTHORITY_TRANSPORT_PENDING"
	}
	return ""
}
