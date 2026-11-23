package windowsplatform

import "fmt"

const (
	lanGameMQTTPort = 1883
	iscsiPort       = 3260
)

func IsPrivateISCSI(t Tuple) bool {
	return t.Protocol == "tcp" && t.Destination.Port() == iscsiPort && t.Destination.Addr().IsPrivate()
}

// IsPrivateClubInfrastructure takes a canonical outbound tuple. Only a private
// broker or storage peer qualifies, regardless of the client's own address.
func IsPrivateClubInfrastructure(t Tuple) bool {
	port := t.Destination.Port()
	return t.Protocol == "tcp" && (port == lanGameMQTTPort || port == iscsiPort) && t.Destination.Addr().IsPrivate()
}

func outsidePrivateIPv4Filter(field string) string {
	return fmt.Sprintf("((%s < 10.0.0.0 or %s > 10.255.255.255) and (%s < 172.16.0.0 or %s > 172.31.255.255) and (%s < 192.168.0.0 or %s > 192.168.255.255))", field, field, field, field, field, field)
}

// WinDivert 2.2.2 cannot negate a grouped expression. Keep the private peer
// and its service port on the same side of the packet in each direction.
func outsideClubTCPFilter(outsideDst, outsideSrc string) string {
	return fmt.Sprintf("(!outbound or (tcp.DstPort != %d and tcp.DstPort != %d) or %s) and (!inbound or (tcp.SrcPort != %d and tcp.SrcPort != %d) or %s)",
		lanGameMQTTPort, iscsiPort, outsideDst, lanGameMQTTPort, iscsiPort, outsideSrc)
}

func nativeTCPNetworkFilter(port uint16, loopbackFixture bool) string {
	base := fmt.Sprintf("ip and tcp and !impostor and ((outbound and (!loopback or tcp.DstPort == 53)) or (inbound and (!loopback or tcp.DstPort == %d)))", port)
	if loopbackFixture {
		base = "ip and tcp and !impostor"
	}
	// Always guard the wildcard interception listener, even when a physical
	// client uses a broker/storage source port to reach it.
	return fmt.Sprintf("%s and ((inbound and tcp.DstPort == %d) or (%s))", base, port,
		outsideClubTCPFilter(outsidePrivateIPv4Filter("ip.DstAddr"), outsidePrivateIPv4Filter("ip.SrcAddr")))
}

// IPv6 private peers use fc00::/7. UDP keeps its existing capture semantics.
var captureIPv6Filter = "ipv6 and !loopback and !impostor and (udp or (tcp and " +
	outsideClubTCPFilter("(ipv6.DstAddr < fc00:: or ipv6.DstAddr >= fe00::)", "(ipv6.SrcAddr < fc00:: or ipv6.SrcAddr >= fe00::)") + "))"
