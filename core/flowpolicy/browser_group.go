package flowpolicy

import (
	"github.com/buzzmean/veliq/core/originpolicy"
	"strings"
)

// BrowserRelayGroup is a bounded family hint, not authorization for DIRECT and
// not evidence that the family is blocked. Never match generic Google domains.
func BrowserRelayGroup(host string) string {
	if group := KnownBrowserRelayGroup(host); group != "" {
		return group
	}
	if r := originpolicy.Floor(host); r.Group == "youtube-media" {
		return r.Group
	}

	return ""
}

// DirectTimeoutHost shares failure evidence within an explicit family, while
// ordinary sites remain exact-host scoped. Network/profile/port stay in the key.
func DirectTimeoutHost(host string) string {
	if BrowserRelayGroup(host) == "youtube-media" {
		return "youtube.com"
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// SetProbeHost remembers the actual failed origin, so a healthy unrelated member
// cannot accidentally clear the family verdict at TTL. It creates no verdict.
func (c *DirectTimeoutCache) SetProbeHost(k DirectTimeoutKey, host string) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if len(host) > 253 || BrowserRelayGroup(host) != "youtube-media" || DirectTimeoutHost(host) != k.Host {
		return
	}
	k.Address = ""
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[k]; e != nil {
		e.probeHost = host
	}
}
func (c *DirectTimeoutCache) ProbeHost(k DirectTimeoutKey) string {
	k.Address = ""
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[k]; e != nil {
		return e.probeHost
	}
	return ""
}

// KnownBrowserRelayGroup contains only explicitly approved degraded services.
// Unlike YouTube's learned failure family these routes do not require a failed
// foreground DIRECT trial. Suffix matching includes WebSocket/API subdomains.
func KnownBrowserRelayGroup(host string) string {
	r := originpolicy.Floor(host)
	if r.Kind == "RELAY" && !r.Protected {
		return r.Group
	}
	return ""
}
