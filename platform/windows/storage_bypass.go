package windowsplatform

import "fmt"

func IsPrivateISCSI(t Tuple) bool {
	// Classifier tuples are canonical outbound tuples, never a reversed reply.
	return t.Protocol == "tcp" && t.Destination.Port() == 3260 && t.Destination.Addr().IsPrivate()
}
func outsidePrivateIPv4Filter(field string) string {
	return fmt.Sprintf("((%s < 10.0.0.0 or %s > 10.255.255.255) and (%s < 172.16.0.0 or %s > 172.31.255.255) and (%s < 192.168.0.0 or %s > 192.168.255.255))", field, field, field, field, field, field)
}

// Network-layer exclusion: diskless storage never enters the redirect queue.
// Match the private STORAGE peer, not the always-private client source address.
func nativeTCPNetworkFilter(port uint16, loopbackFixture bool) string {
	base := fmt.Sprintf("ip and tcp and !impostor and ((outbound and (!loopback or tcp.DstPort == 53)) or (inbound and (!loopback or tcp.DstPort == %d)))", port)
	if loopbackFixture {
		base = "ip and tcp and !impostor"
	}
	// WinDivert 2.2.2 accepts NOT only before a field test, NOT a grouped
	// expression. De Morgan preserves the exact directional/private-peer
	// exclusion without "not (...)" (which fails at the opening parenthesis).
	return base + " and (!outbound or tcp.DstPort != 3260 or " + outsidePrivateIPv4Filter("ip.DstAddr") + ") and (!inbound or tcp.SrcPort != 3260 or " + outsidePrivateIPv4Filter("ip.SrcAddr") + ")"
}
