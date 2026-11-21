package windowsplatform

const captureFlowFilter = "outbound and !loopback and (udp or tcp)"
const captureReflectFilter = "true"
const gameUDPReplyFilter = "inbound and ip and udp and udp.SrcPort >= 1024 and !loopback and !impostor"

type divertFilterSpec struct {
	name, text string
	layer      uintptr
}

// Keep this inventory tied to the actual openHandle call sites (checked by
// TestServiceWinDivertFilterInventory). The Windows gate compiles every entry
// with the pinned DLL; it never opens a handle or installs/starts a driver.
func serviceWinDivertFilters(port uint16, loopbackFixture bool) []divertFilterSpec {
	return []divertFilterSpec{
		{"captureFlowFilter", captureFlowFilter, 2},
		{"captureUDPFilter", captureUDPFilter, 0},
		{"captureSocketFilter", captureSocketFilter, 3},
		{"captureIPv6Filter", captureIPv6Filter, 0},
		{"captureReflectFilter", captureReflectFilter, 4},
		{"gameUDPReplyFilter", gameUDPReplyFilter, 0},
		{"nativeTCPNetworkFilter", nativeTCPNetworkFilter(port, loopbackFixture), 0},
	}
}
