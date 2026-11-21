// Package quality contains destination/FEC contracts. Neither capability is active in v1.
package quality

import (
	"net/netip"
	"time"
)

type DestinationKey struct {
	ApplicationID string
	PID           uint32
	CreationTime  uint64
	Protocol      string
	Destination   netip.AddrPort
	RouteID       string
}

func (k DestinationKey) Valid() bool {
	return k.ApplicationID != "" && k.PID != 0 && k.CreationTime != 0 && (k.Protocol == "udp" || k.Protocol == "tcp") && k.Destination.IsValid() && k.Destination.Port() != 0 && k.RouteID != ""
}

// Observations must come only from existing classified application flows. No
// payload, DNS guessing, arbitrary scanning or fabricated UDP request/reply pairing.
type DestinationObservation struct {
	Key                                                          DestinationKey
	At                                                           time.Time
	SentPackets, ReplyPackets, SentBytes, ReplyBytes, LocalDrops uint64
}

func (o DestinationObservation) NetworkLoss() (float64, bool) { return 0, false } // UDP directions alone cannot establish loss.
type DestinationQualityProvider interface {
	Observe(DestinationObservation)
	KnownQuality(DestinationKey) (DestinationQuality, bool)
}
type DestinationQuality struct {
	RTT, Jitter      time.Duration
	Loss             float64
	LossKnown        bool
	ObservationCount uint64
}

// Future negotiation must explicitly support a new wire version. There is no
// encoder/decoder or parity scheduling in v1, and QUIC DATAGRAM is unretransmitted.
type FECCapability struct {
	Supported     bool
	MaximumParity int
	MaximumWait   time.Duration
}

func DisabledFEC() FECCapability { return FECCapability{} }
