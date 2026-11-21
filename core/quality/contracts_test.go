package quality

import (
	"net/netip"
	"testing"
)

func TestExistingFlowMetadataDoesNotInventDestinationLoss(t *testing.T) {
	key := DestinationKey{ApplicationID: "game", PID: 42, CreationTime: 10, Protocol: "udp", Destination: netip.MustParseAddrPort("192.0.2.1:27015"), RouteID: "R"}
	if !key.Valid() {
		t.Fatal("valid active-flow key rejected")
	}
	if _, known := (DestinationObservation{Key: key, SentPackets: 100, ReplyPackets: 10}).NetworkLoss(); known {
		t.Fatal("asymmetric UDP inferred loss")
	}
	key.CreationTime = 0
	if key.Valid() {
		t.Fatal("unknown/reused identity accepted")
	}
}
func TestFECIsNotEnabledOrClaimedSupported(t *testing.T) {
	fec := DisabledFEC()
	if fec.Supported || fec.MaximumParity != 0 || fec.MaximumWait != 0 {
		t.Fatal("FEC enabled")
	}
}
