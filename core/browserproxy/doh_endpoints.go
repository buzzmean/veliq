package browserproxy

import (
	"net/netip"
	"strings"
)

// Public provider address/hostname facts from Chromium doh_provider_entry.cc,
// snapshot 2026-10-23, SHA256 cd0c73995ebe946154fb44ddbff4237bab378ac8329d52e5561f74b45ee689bf.
// Additional Cloudflare/NextDNS aliases. No templates, preferences or private
// user resolver settings are imported. Never match an entire provider CDN.
var knownDoHAddresses = func() map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	for _, s := range strings.Fields(`185.228.168.10 185.228.169.11 2a0d:2a00:1::1 2a0d:2a00:2::1 185.228.168.168 185.228.169.168 2a0d:2a00:1:: 2a0d:2a00:2:: 185.228.168.9 185.228.169.9 2a0d:2a00:1::2 2a0d:2a00:2::2 1.1.1.1 1.0.0.1 2606:4700:4700::1111 2606:4700:4700::1001 1.1.1.3 1.0.0.3 2606:4700:4700::1113 2606:4700:4700::1003 1.1.1.2 1.0.0.2 2606:4700:4700::1112 2606:4700:4700::1002 75.75.75.75 75.75.76.76 2001:558:feed::1 2001:558:feed::2 68.105.28.11 68.105.28.12 2001:578:3f::30 185.43.135.1 193.17.47.1 2001:148f:fffe::1 2001:148f:ffff::1 86.54.11.1 86.54.11.201 2a13:1001::86:54:11:1 2a13:1001::86:54:11:201 185.222.222.222 45.11.45.11 2a09:: 2a11:: 8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844 2001:4860:4860::64 2001:4860:4860::6464 109.236.119.2 109.236.120.2 2a02:6ca3:0:1::2 2a02:6ca3:0:2::2 208.67.222.222 208.67.220.220 2620:119:35::35 2620:119:53::53 208.67.222.123 208.67.220.123 2620:119:35::123 2620:119:53::123 9.9.9.11 149.112.112.11 2620:fe::11 2620:fe::fe:11 9.9.9.10 149.112.112.10 2620:fe::10 2620:fe::fe:10 9.9.9.9 149.112.112.112 2620:fe::fe 2620:fe::9 212.60.61.246 212.60.63.246 2001:1a88:10:ffff::1 2001:1a88:10:ffff::2 209.18.47.61 209.18.47.62 2001:1998:f00:1::1 2001:1998:f00:2::1`) {
		out[netip.MustParseAddr(s)] = true
	}
	return out
}()
var knownDoHNames = map[string]bool{
	"doh.cleanbrowsing.org":        true,
	"chrome.cloudflare-dns.com":    true,
	"family.cloudflare-dns.com":    true,
	"security.cloudflare-dns.com":  true,
	"doh.xfinity.com":              true,
	"doh.cox.net":                  true,
	"odvr.nic.cz":                  true,
	"protective.joindns4.eu":       true,
	"doh.dns.sb":                   true,
	"dns.google":                   true,
	"dns64.dns.google":             true,
	"public.dns.iij.jp":            true,
	"dns.levonet.sk":               true,
	"chromium.dns.nextdns.io":      true,
	"doh.opendns.com":              true,
	"doh.familyshield.opendns.com": true,
	"dns11.quad9.net":              true,
	"dns10.quad9.net":              true,
	"dns.quad9.net":                true,
	"doh.quickline.ch":             true,
	"doh-01.spectrum.com":          true,
	"doh-02.spectrum.com":          true,
	"cloudflare-dns.com":           true,
	"mozilla.cloudflare-dns.com":   true,
	"dns.google.com":               true,
	"dns.nextdns.io":               true,
	"one.one.one.one":              true,
}

func KnownDoHEndpoint(host string, dst netip.AddrPort) bool {
	if dst.Port() != 443 {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return knownDoHNames[host] || knownDoHAddresses[dst.Addr().Unmap()]
}
