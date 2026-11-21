package routing

import "net/netip"

// localOnly are ranges that exist only inside a LAN, an ISP's internal network or the host
// itself. Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32)
// are deliberately NOT here: they never occur on a real network, and synthetic test traffic
// uses them as stand-ins for ordinary Internet servers.
var localOnly = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("64:ff9b::/96"),
}

// LocalDestination reports whether a is not an Internet destination a remote relay could
// reach on the user's behalf: private (RFC 1918 / ULA), loopback, link-local, multicast,
// broadcast, unspecified, carrier-grade NAT and other internal ranges. Such flows (the
// router, LAN hosts, mDNS, DHCP) belong to the local network and are never relayed.
func LocalDestination(a netip.Addr) bool {
	if !a.IsValid() {
		return true // no usable destination: never invent a relay path for it
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || !a.IsGlobalUnicast() {
		return true
	}
	for _, p := range localOnly {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
